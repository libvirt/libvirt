/*
 * Copyright (C) 2012 Fujitsu Limited.
 *
 * lxc_fuse.c: fuse filesystem support for libvirt lxc
 *
 * Authors:
 *  Gao feng <gaofeng at cn.fujitsu.com>
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
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/mount.h>
#include <mntent.h>

#include "lxc_fuse.h"
#include "virterror_internal.h"
#include "logging.h"

#define VIR_FROM_THIS VIR_FROM_LXC

#if HAVE_FUSE

static int lxcProcGetattr(const char *path, struct stat *stbuf)
{
    int res = 0;

    memset(stbuf, 0, sizeof(struct stat));

    if (STREQ(path, "/")) {
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
    } else {
        res = -ENOENT;
    }

    return res;
}

static int lxcProcReaddir(const char *path, void *buf,
                          fuse_fill_dir_t filler,
                          off_t offset ATTRIBUTE_UNUSED,
                          struct fuse_file_info *fi ATTRIBUTE_UNUSED)
{
    if (!STREQ(path, "/"))
        return -ENOENT;

    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);

    return 0;
}

static int lxcProcOpen(const char *path ATTRIBUTE_UNUSED,
                       struct fuse_file_info *fi ATTRIBUTE_UNUSED)
{
    return -ENOENT;
}

static int lxcProcRead(const char *path ATTRIBUTE_UNUSED,
                       char *buf ATTRIBUTE_UNUSED,
                       size_t size ATTRIBUTE_UNUSED,
                       off_t offset ATTRIBUTE_UNUSED,
                       struct fuse_file_info *fi ATTRIBUTE_UNUSED)
{
    return -ENOENT;
}

static struct fuse_operations lxcProcOper = {
    .getattr = lxcProcGetattr,
    .readdir = lxcProcReaddir,
    .open    = lxcProcOpen,
    .read    = lxcProcRead,
};

static void lxcFuseDestroy(virLXCFusePtr fuse)
{
    virMutexLock(&fuse->lock);
    fuse_unmount(fuse->mountpoint, fuse->ch);
    fuse_destroy(fuse->fuse);
    fuse->fuse = NULL;
    virMutexUnlock(&fuse->lock);
}

static void lxcFuseRun(void *opaque)
{
    virLXCFusePtr fuse = opaque;

    if (fuse_loop(fuse->fuse) < 0)
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("fuse_loop failed"));

    lxcFuseDestroy(fuse);
}

int lxcSetupFuse(virLXCFusePtr *f, virDomainDefPtr def)
{
    int ret = -1;
    struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
    virLXCFusePtr fuse = NULL;

    if (VIR_ALLOC(fuse) < 0)
        goto cleanup;

    fuse->def = def;

    if (virMutexInit(&fuse->lock) < 0)
        goto cleanup2;

    if (virAsprintf(&fuse->mountpoint, "%s/%s/", LXC_STATE_DIR,
                    def->name) < 0) {
        virReportOOMError();
        goto cleanup1;
    }

    if (virFileMakePath(fuse->mountpoint) < 0) {
        virReportSystemError(errno, _("Cannot create %s"),
                             fuse->mountpoint);
        goto cleanup1;
    }

    /* process name is libvirt_lxc */
    if (fuse_opt_add_arg(&args, "libvirt_lxc") == -1 ||
        fuse_opt_add_arg(&args, "-odirect_io") == -1 ||
        fuse_opt_add_arg(&args, "-ofsname=libvirt") == -1)
        goto cleanup1;

    fuse->ch = fuse_mount(fuse->mountpoint, &args);
    if (fuse->ch == NULL)
        goto cleanup1;

    fuse->fuse = fuse_new(fuse->ch, &args, &lxcProcOper,
                          sizeof(lxcProcOper), fuse->def);
    if (fuse->fuse == NULL) {
        fuse_unmount(fuse->mountpoint, fuse->ch);
        goto cleanup1;
    }

    if (virThreadCreate(&fuse->thread, true, lxcFuseRun,
                        (void *)fuse) < 0) {
        lxcFuseDestroy(fuse);
        goto cleanup1;
    }

    ret = 0;
cleanup:
    fuse_opt_free_args(&args);
    *f = fuse;
    return ret;
cleanup1:
    VIR_FREE(fuse->mountpoint);
    virMutexDestroy(&fuse->lock);
cleanup2:
    VIR_FREE(fuse);
    goto cleanup;
}

void lxcFreeFuse(virLXCFusePtr *f)
{
    virLXCFusePtr fuse = *f;
    /* lxcFuseRun thread create success */
    if (fuse) {
        /* exit fuse_loop, lxcFuseRun thread may try to destroy
         * fuse->fuse at the same time,so add a lock here. */
        virMutexLock(&fuse->lock);
        if (fuse->fuse)
            fuse_exit(fuse->fuse);
        virMutexUnlock(&fuse->lock);

        virThreadJoin(&fuse->thread);

        VIR_FREE(fuse->mountpoint);
        VIR_FREE(*f);
    }
}
#else
int lxcSetupFuse(virLXCFusePtr *f ATTRIBUTE_UNUSED,
                  virDomainDefPtr def ATTRIBUTE_UNUSED)
{
    return 0;
}

void lxcFreeFuse(virLXCFusePtr *f ATTRIBUTE_UNUSED)
{
}
#endif
