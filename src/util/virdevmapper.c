/*
 * virdevmapper.c: Functions for handling device mapper
 *
 * Copyright (C) 2018 Red Hat, Inc.
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

#include "virdevmapper.h"
#include "internal.h"

#ifdef __linux__
# include <sys/sysmacros.h>
# include <linux/dm-ioctl.h>
# include <sys/ioctl.h>
# include <sys/types.h>
# include <sys/stat.h>
# include <fcntl.h>

# include "virthread.h"
# include "viralloc.h"
# include "virstring.h"
# include "virfile.h"
# include "virlog.h"

# define VIR_FROM_THIS VIR_FROM_STORAGE

VIR_LOG_INIT("util.virdevmapper");

# define PROC_DEVICES "/proc/devices"
# define DM_NAME "device-mapper"
# define DEV_DM_DIR "/dev/" DM_DIR
# define CONTROL_PATH DEV_DM_DIR "/" DM_CONTROL_NODE
# define BUF_SIZE (16 * 1024)

G_STATIC_ASSERT(BUF_SIZE > sizeof(struct dm_ioctl));


static int
virDevMapperGetMajor(unsigned int *major)
{
    g_autofree char *buf = NULL;
    g_auto(GStrv) lines = NULL;
    size_t i;

    if (!virFileExists(CONTROL_PATH))
        return -2;

    if (virFileReadAll(PROC_DEVICES, BUF_SIZE, &buf) < 0)
        return -1;

    lines = g_strsplit(buf, "\n", 0);
    if (!lines)
        return -1;

    for (i = 0; lines[i]; i++) {
        g_autofree char *dev = NULL;
        unsigned int maj;

        if (sscanf(lines[i], "%u %ms\n", &maj, &dev) == 2 &&
            STREQ(dev, DM_NAME)) {
            *major = maj;
            break;
        }
    }

    if (!lines[i]) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to find major for %s"),
                       DM_NAME);
        return -1;
    }

    return 0;
}


static void *
virDMIoctl(int controlFD, int cmd, struct dm_ioctl *dm, char **buf)
{
    size_t bufsize = BUF_SIZE;

 reread:
    *buf = g_new0(char, bufsize);

    dm->version[0] = DM_VERSION_MAJOR;
    dm->version[1] = 0;
    dm->version[2] = 0;
    dm->data_size = bufsize;
    dm->data_start = sizeof(struct dm_ioctl);

    memcpy(*buf, dm, sizeof(struct dm_ioctl));

    if (ioctl(controlFD, cmd, *buf) < 0) {
        VIR_FREE(*buf);
        return NULL;
    }

    memcpy(dm, *buf, sizeof(struct dm_ioctl));

    if (dm->flags & DM_BUFFER_FULL_FLAG) {
        bufsize += BUF_SIZE;
        VIR_FREE(*buf);
        goto reread;
    }

    return *buf + dm->data_start;
}


static int
virDMOpen(void)
{
    VIR_AUTOCLOSE controlFD = -1;
    struct dm_ioctl dm;
    g_autofree char *tmp = NULL;
    int ret;

    memset(&dm, 0, sizeof(dm));

    if ((controlFD = open(CONTROL_PATH, O_RDWR)) < 0) {
        /* We can't talk to devmapper. Produce a warning and let
         * the caller decide what to do next. */
        if (errno == ENOENT) {
            VIR_DEBUG("device mapper not available");
        } else {
            VIR_WARN("unable to open %s: %s",
                     CONTROL_PATH, g_strerror(errno));
        }
        return -2;
    }

    if (!virDMIoctl(controlFD, DM_VERSION, &dm, &tmp)) {
        virReportSystemError(errno, "%s",
                             _("Unable to get device-mapper version"));
        return -1;
    }

    if (dm.version[0] != DM_VERSION_MAJOR) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("Unsupported device-mapper version. Expected %d got %d"),
                       DM_VERSION_MAJOR, dm.version[0]);
        return -1;
    }

    ret = controlFD;
    controlFD = -1;
    return ret;
}


static char *
virDMSanitizepath(const char *path)
{
    g_autofree char *dmDirPath = NULL;
    struct dirent *ent = NULL;
    struct stat sb[2];
    g_autoptr(DIR) dh = NULL;
    const char *p;

    /* If a path is NOT provided then assume it's DM name */
    p = strrchr(path, '/');

    if (!p)
        return g_strdup(path);
    else
        p++;

    /* It's a path. Check if the last component is DM name */
    if (stat(path, &sb[0]) < 0) {
        virReportError(errno,
                       _("Unable to stat %p"),
                       path);
        return NULL;
    }

    dmDirPath = g_strdup_printf(DEV_DM_DIR "/%s", p);

    if (stat(dmDirPath, &sb[1]) == 0 &&
        sb[0].st_rdev == sb[1].st_rdev) {
        return g_strdup(p);
    }

    /* The last component of @path wasn't DM name. Let's check if
     * there's a device under /dev/mapper/ with the same rdev. */
    if (virDirOpen(&dh, DEV_DM_DIR) < 0)
        return NULL;

    while (virDirRead(dh, &ent, DEV_DM_DIR) > 0) {
        g_autofree char *tmp = g_strdup_printf(DEV_DM_DIR "/%s", ent->d_name);

        if (stat(tmp, &sb[1]) == 0 &&
            sb[0].st_rdev == sb[1].st_rdev) {
            return g_steal_pointer(&tmp);
        }
    }

    return NULL;
}


static int
virDevMapperGetTargetsImpl(int controlFD,
                           const char *path,
                           char ***devPaths_ret,
                           unsigned int ttl)
{
    g_autofree char *sanitizedPath = NULL;
    g_autofree char *buf = NULL;
    struct dm_ioctl dm;
    struct dm_target_deps *deps = NULL;
    g_auto(GStrv) devPaths = NULL;
    size_t i;

    memset(&dm, 0, sizeof(dm));
    *devPaths_ret = NULL;

    if (ttl == 0) {
        errno = ELOOP;
        return -1;
    }

    if (!virIsDevMapperDevice(path))
        return 0;

    if (!(sanitizedPath = virDMSanitizepath(path)))
        return 0;

    if (virStrcpy(dm.name, sanitizedPath, DM_NAME_LEN) < 0) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("Resolved device mapper name too long"));
        return -1;
    }

    deps = virDMIoctl(controlFD, DM_TABLE_DEPS, &dm, &buf);
    if (!deps) {
        if (errno == ENXIO)
            return 0;

        virReportSystemError(errno,
                             _("Unable to query dependencies for %s"),
                             path);
        return -1;
    }

    devPaths = g_new0(char *, deps->count + 1);
    for (i = 0; i < deps->count; i++) {
        devPaths[i] = g_strdup_printf("/dev/block/%u:%u",
                                      major(deps->dev[i]),
                                      minor(deps->dev[i]));
    }

    for (i = 0; i < deps->count; i++) {
        g_auto(GStrv) tmpPaths = NULL;

        if (virDevMapperGetTargetsImpl(controlFD, devPaths[i], &tmpPaths, ttl - 1) < 0)
            return -1;

        if (virStringListMerge(&devPaths, &tmpPaths) < 0)
            return -1;
    }

    *devPaths_ret = g_steal_pointer(&devPaths);
    return 0;
}


/**
 * virDevMapperGetTargets:
 * @path: devmapper target
 * @devPaths: returned string list of devices
 *
 * For given @path figure out its targets, and store them in
 * @devPaths array. Note, @devPaths is a string list so it's NULL
 * terminated.
 *
 * If @path is not a devmapper device, @devPaths is set to NULL and
 * success is returned.
 *
 * If @path consists of yet another devmapper targets these are
 * consulted recursively.
 *
 * Returns 0 on success,
 *        -1 otherwise (with errno set, no libvirt error is
 *        reported)
 */
int
virDevMapperGetTargets(const char *path,
                       char ***devPaths)
{
    VIR_AUTOCLOSE controlFD = -1;
    const unsigned int ttl = 32;

    /* Arbitrary limit on recursion level. A devmapper target can
     * consist of devices or yet another targets. If that's the
     * case, we have to stop recursion somewhere. */

    if ((controlFD = virDMOpen()) < 0) {
        if (controlFD == -2) {
            /* The CONTROL_PATH doesn't exist or is unusable.
             * Probably the module isn't loaded, yet. Don't error
             * out, just exit. */
            return 0;
        }

        return -1;
    }

    return virDevMapperGetTargetsImpl(controlFD, path, devPaths, ttl);
}


bool
virIsDevMapperDevice(const char *dev_name)
{
    struct stat buf;
    unsigned int major;

    if (virDevMapperGetMajor(&major) < 0)
        return false;

    if (!stat(dev_name, &buf) &&
        S_ISBLK(buf.st_mode) &&
        major(buf.st_rdev) == major)
        return true;

    return false;
}

#else /* !defined(__linux__)  */

int
virDevMapperGetTargets(const char *path G_GNUC_UNUSED,
                       char ***devPaths G_GNUC_UNUSED)
{
    errno = ENOSYS;
    return -1;
}


bool
virIsDevMapperDevice(const char *dev_name G_GNUC_UNUSED)
{
    return false;
}
#endif /* ! defined(__linux__) */
