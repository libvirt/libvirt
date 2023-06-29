/*
 * Copyright (C) 2014 Red Hat, Inc.
 * Copyright (C) 2012 Fujitsu Limited.
 *
 * lxc_fuse.c: fuse filesystem support for libvirt lxc
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <fcntl.h>
#include <sys/mount.h>
#include <mntent.h>
#include <unistd.h>

#if WITH_FUSE
# if WITH_FUSE == 3
#  define FUSE_USE_VERSION 31
# else
#  define FUSE_USE_VERSION 26
# endif
# include <fuse.h>
# if FUSE_USE_VERSION >= 31
#  include <fuse_lowlevel.h>
# endif
#endif

#include "lxc_fuse.h"
#include "lxc_cgroup.h"
#include "lxc_conf.h"
#include "virerror.h"
#include "virfile.h"
#include "virbuffer.h"
#include "virutil.h"

#define VIR_FROM_THIS VIR_FROM_LXC

#if WITH_FUSE

struct virLXCFuse {
    virDomainDef *def;
    virThread thread;
    char *mountpoint;
    struct fuse *fuse;
# if FUSE_USE_VERSION < 31
    struct fuse_chan *ch;
# else
    struct fuse_session *sess;
# endif
    virMutex lock;
};

static const char *fuse_meminfo_path = "/meminfo";

static int
lxcProcGetattrImpl(const char *path,
                   struct stat *stbuf)
{
    g_autofree char *mempath = NULL;
    struct stat sb;
    struct fuse_context *context = fuse_get_context();
    virDomainDef *def = (virDomainDef *)context->private_data;

    memset(stbuf, 0, sizeof(struct stat));
    mempath = g_strdup_printf("/proc/%s", path);

    if (STREQ(path, "/")) {
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
    } else if (STREQ(path, fuse_meminfo_path)) {
        if (stat(mempath, &sb) < 0)
            return -errno;

        stbuf->st_uid = def->idmap.uidmap ? def->idmap.uidmap[0].target : 0;
        stbuf->st_gid = def->idmap.gidmap ? def->idmap.gidmap[0].target : 0;
        stbuf->st_mode = sb.st_mode;
        stbuf->st_nlink = 1;
        stbuf->st_blksize = sb.st_blksize;
        stbuf->st_blocks = sb.st_blocks;
        stbuf->st_size = sb.st_size;
        stbuf->st_atime = sb.st_atime;
        stbuf->st_ctime = sb.st_ctime;
        stbuf->st_mtime = sb.st_mtime;
    } else {
        return -ENOENT;
    }

    return 0;
}

# if FUSE_USE_VERSION >= 31
static int
lxcProcGetattr(const char *path,
               struct stat *stbuf,
               struct fuse_file_info *fi G_GNUC_UNUSED)
{
    return lxcProcGetattrImpl(path, stbuf);
}
# else
static int lxcProcGetattr(const char *path, struct stat *stbuf)
{
    return lxcProcGetattrImpl(path, stbuf);
}
# endif

# if FUSE_USE_VERSION >= 31
static int
lxcProcReaddir(const char *path,
               void *buf,
               fuse_fill_dir_t filler,
               off_t offset G_GNUC_UNUSED,
               struct fuse_file_info *fi G_GNUC_UNUSED,
               enum fuse_readdir_flags unused_flags G_GNUC_UNUSED)
{
    if (STRNEQ(path, "/"))
        return -ENOENT;

    filler(buf, ".", NULL, 0, 0);
    filler(buf, "..", NULL, 0, 0);
    filler(buf, fuse_meminfo_path + 1, NULL, 0, 0);

    return 0;
}
# else
static int
lxcProcReaddir(const char *path,
               void *buf,
               fuse_fill_dir_t filler,
               off_t offset G_GNUC_UNUSED,
               struct fuse_file_info *fi G_GNUC_UNUSED)
{
    if (STRNEQ(path, "/"))
        return -ENOENT;

    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);
    filler(buf, fuse_meminfo_path + 1, NULL, 0);

    return 0;
}
# endif

static int
lxcProcOpen(const char *path,
            struct fuse_file_info *fi)
{
    if (STRNEQ(path, fuse_meminfo_path))
        return -ENOENT;

    if ((fi->flags & O_ACCMODE) != O_RDONLY)
        return -EACCES;

    fi->direct_io = 1;
    return 0;
}

static int
lxcProcHostRead(char *path,
                char *buf,
                size_t size,
                off_t offset)
{
    VIR_AUTOCLOSE fd = -1;
    int res;

    fd = open(path, O_RDONLY);
    if (fd == -1)
        return -errno;

    if ((res = pread(fd, buf, size, offset)) < 0)
        res = -errno;

    return res;
}

static int
lxcProcReadMeminfo(char *hostpath,
                   virDomainDef *def,
                   char *buf,
                   size_t size,
                   off_t offset)
{
    int res;
    g_autoptr(FILE) fp = NULL;
    g_autofree char *line = NULL;
    size_t n;
    struct virLXCMeminfo meminfo;
    g_auto(virBuffer) buffer = VIR_BUFFER_INITIALIZER;
    const char *new_meminfo = NULL;

    if (virLXCCgroupGetMeminfo(&meminfo) < 0) {
        virErrorSetErrnoFromLastError();
        return -errno;
    }

    fp = fopen(hostpath, "r");
    if (fp == NULL) {
        virReportSystemError(errno, _("Cannot open %1$s"), hostpath);
        return -errno;
    }

    res = -1;
    while (getline(&line, &n, fp) > 0) {
        char *ptr = strchr(line, ':');
        if (!ptr)
            continue;
        *ptr = '\0';

        if (STREQ(line, "MemTotal") &&
            (virMemoryLimitIsSet(def->mem.hard_limit) ||
             virDomainDefGetMemoryTotal(def))) {
            virBufferAsprintf(&buffer, "MemTotal:       %8llu kB\n",
                              meminfo.memtotal);
        } else if (STREQ(line, "MemFree") &&
                   (virMemoryLimitIsSet(def->mem.hard_limit) ||
                    virDomainDefGetMemoryTotal(def))) {
            virBufferAsprintf(&buffer, "MemFree:        %8llu kB\n",
                              (meminfo.memtotal - meminfo.memusage));
        } else if (STREQ(line, "MemAvailable") &&
                   (virMemoryLimitIsSet(def->mem.hard_limit) ||
                    virDomainDefGetMemoryTotal(def))) {
            /* MemAvailable is actually MemFree + SRReclaimable +
               some other bits, but MemFree is the closest approximation
               we have */
            virBufferAsprintf(&buffer, "MemAvailable:   %8llu kB\n",
                              (meminfo.memtotal - meminfo.memusage));
        } else if (STREQ(line, "Buffers")) {
            virBufferAsprintf(&buffer, "Buffers:        %8d kB\n", 0);
        } else if (STREQ(line, "Cached")) {
            virBufferAsprintf(&buffer, "Cached:         %8llu kB\n",
                              meminfo.cached);
        } else if (STREQ(line, "Active")) {
            virBufferAsprintf(&buffer, "Active:         %8llu kB\n",
                              (meminfo.active_anon + meminfo.active_file));
        } else if (STREQ(line, "Inactive")) {
            virBufferAsprintf(&buffer, "Inactive:       %8llu kB\n",
                              (meminfo.inactive_anon + meminfo.inactive_file));
        } else if (STREQ(line, "Active(anon)")) {
            virBufferAsprintf(&buffer, "Active(anon):   %8llu kB\n",
                              meminfo.active_anon);
        } else if (STREQ(line, "Inactive(anon)")) {
            virBufferAsprintf(&buffer, "Inactive(anon): %8llu kB\n",
                              meminfo.inactive_anon);
        } else if (STREQ(line, "Active(file)")) {
            virBufferAsprintf(&buffer, "Active(file):   %8llu kB\n",
                              meminfo.active_file);
        } else if (STREQ(line, "Inactive(file)")) {
            virBufferAsprintf(&buffer, "Inactive(file): %8llu kB\n",
                              meminfo.inactive_file);
        } else if (STREQ(line, "Unevictable")) {
            virBufferAsprintf(&buffer, "Unevictable:    %8llu kB\n",
                              meminfo.unevictable);
        } else if (STREQ(line, "SwapTotal") &&
                   virMemoryLimitIsSet(def->mem.swap_hard_limit)) {
            virBufferAsprintf(&buffer, "SwapTotal:      %8llu kB\n",
                              (meminfo.swaptotal - meminfo.memtotal));
        } else if (STREQ(line, "SwapFree") &&
                   virMemoryLimitIsSet(def->mem.swap_hard_limit)) {
            virBufferAsprintf(&buffer, "SwapFree:       %8llu kB\n",
                              (meminfo.swaptotal - meminfo.memtotal -
                               meminfo.swapusage + meminfo.memusage));
        } else if (STREQ(line, "Slab")) {
            virBufferAsprintf(&buffer, "Slab:           %8d kB\n", 0);
        } else if (STREQ(line, "SReclaimable")) {
            virBufferAsprintf(&buffer, "SReclaimable:   %8d kB\n", 0);
        } else if (STREQ(line, "SUnreclaim")) {
            virBufferAsprintf(&buffer, "SUnreclaim:     %8d kB\n", 0);
        } else {
            *ptr = ':';
            virBufferAdd(&buffer, line, -1);
        }

    }

    new_meminfo = virBufferCurrentContent(&buffer);
    res = virBufferUse(&buffer);

    if (offset > res)
        return 0;

    res -= offset;

    if (res > size)
        res = size;
    memcpy(buf, new_meminfo + offset, res);

    return res;
}

static int
lxcProcRead(const char *path,
            char *buf,
            size_t size,
            off_t offset,
            struct fuse_file_info *fi G_GNUC_UNUSED)
{
    int res = -ENOENT;
    g_autofree char *hostpath = NULL;
    struct fuse_context *context = NULL;
    virDomainDef *def = NULL;

    hostpath = g_strdup_printf("/proc/%s", path);

    context = fuse_get_context();
    def = (virDomainDef *)context->private_data;

    if (STREQ(path, fuse_meminfo_path)) {
        if ((res = lxcProcReadMeminfo(hostpath, def, buf, size, offset)) < 0)
            res = lxcProcHostRead(hostpath, buf, size, offset);
    }

    return res;
}

static struct fuse_operations lxcProcOper = {
    .getattr = lxcProcGetattr,
    .readdir = lxcProcReaddir,
    .open    = lxcProcOpen,
    .read    = lxcProcRead,
};

static void
lxcFuseDestroy(struct virLXCFuse *fuse)
{
    VIR_LOCK_GUARD lock = virLockGuardLock(&fuse->lock);

# if FUSE_USE_VERSION >= 31
    fuse_unmount(fuse->fuse);
# else
    fuse_unmount(fuse->mountpoint, fuse->ch);
# endif
    g_clear_pointer(&fuse->fuse, fuse_destroy);
}

static void
lxcFuseRun(void *opaque)
{
    struct virLXCFuse *fuse = opaque;

    if (fuse_loop(fuse->fuse) < 0)
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("fuse_loop failed"));

    lxcFuseDestroy(fuse);
}

int
lxcSetupFuse(struct virLXCFuse **f,
             virDomainDef *def)
{
    int ret = -1;
    struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
    g_autofree struct virLXCFuse *fuse = g_new0(virLXCFuse, 1);

    fuse->def = def;

    if (virMutexInit(&fuse->lock) < 0)
        return -1;

    fuse->mountpoint = g_strdup_printf("%s/%s.fuse/", LXC_STATE_DIR, def->name);

    if (g_mkdir_with_parents(fuse->mountpoint, 0777) < 0) {
        virReportSystemError(errno, _("Cannot create %1$s"),
                             fuse->mountpoint);
        goto error;
    }

    /* process name is libvirt_lxc */
    if (fuse_opt_add_arg(&args, "libvirt_lxc") == -1 ||
        fuse_opt_add_arg(&args, "-oallow_other") == -1 ||
        fuse_opt_add_arg(&args, "-ofsname=libvirt") == -1)
        goto error;

# if FUSE_USE_VERSION >= 31
    fuse->fuse = fuse_new(&args, &lxcProcOper, sizeof(lxcProcOper), fuse->def);
    if (fuse->fuse == NULL)
        goto error;

    if (fuse_mount(fuse->fuse, fuse->mountpoint) < 0)
        goto error;

    fuse->sess = fuse_get_session(fuse->fuse);

    if (virSetInherit(fuse_session_fd(fuse->sess), false) < 0) {
        virReportSystemError(errno, "%s",
                             _("Cannot disable close-on-exec flag"));
        goto error;
    }

# else
    fuse->ch = fuse_mount(fuse->mountpoint, &args);
    if (fuse->ch == NULL)
        goto error;

    fuse->fuse = fuse_new(fuse->ch, &args, &lxcProcOper,
                          sizeof(lxcProcOper), fuse->def);
    if (fuse->fuse == NULL) {
        goto error;
    }
# endif

    *f = g_steal_pointer(&fuse);
    ret = 0;
 cleanup:
    fuse_opt_free_args(&args);
    return ret;

 error:
# if FUSE_USE_VERSION < 31
    if (fuse->ch)
        fuse_unmount(fuse->mountpoint, fuse->ch);
# else
    fuse_unmount(fuse->fuse);
    fuse_destroy(fuse->fuse);
# endif
    g_free(fuse->mountpoint);
    virMutexDestroy(&fuse->lock);
    goto cleanup;
}

int
lxcStartFuse(struct virLXCFuse *fuse)
{
    if (virThreadCreateFull(&fuse->thread, false, lxcFuseRun,
                            "lxc-fuse", false, (void *)fuse) < 0) {
        lxcFuseDestroy(fuse);
        return -1;
    }

    return 0;
}

void
lxcFreeFuse(struct virLXCFuse **f)
{
    struct virLXCFuse *fuse = *f;
    /* lxcFuseRun thread create success */
    if (fuse) {
        /* exit fuse_loop, lxcFuseRun thread may try to destroy
         * fuse->fuse at the same time,so add a lock here. */
        VIR_WITH_MUTEX_LOCK_GUARD(&fuse->lock) {
            if (fuse->fuse)
                fuse_exit(fuse->fuse);
        }

        g_free(fuse->mountpoint);
        g_free(*f);
    }
}
#else
int
lxcSetupFuse(struct virLXCFuse **f G_GNUC_UNUSED,
             virDomainDef *def G_GNUC_UNUSED)
{
    return 0;
}

int
lxcStartFuse(struct virLXCFuse *f G_GNUC_UNUSED)
{
    return 0;
}

void
lxcFreeFuse(struct virLXCFuse **f G_GNUC_UNUSED)
{
}
#endif
