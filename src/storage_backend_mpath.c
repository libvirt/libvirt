/*
 * storage_backend_mpath.c: storage backend for multipath handling
 *
 * Copyright (C) 2009-2009 Red Hat, Inc.
 * Copyright (C) 2009-2008 Dave Allan
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Dave Allan <dallan@redhat.com>
 */

#include <config.h>

#include <unistd.h>
#include <stdio.h>
#include <dirent.h>
#include <fcntl.h>

#include <libdevmapper.h>

#include "virterror_internal.h"
#include "storage_conf.h"
#include "storage_backend.h"
#include "memory.h"
#include "logging.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE

static int
virStorageBackendMpathUpdateVolTargetInfo(virConnectPtr conn,
                                          virStorageVolTargetPtr target,
                                          unsigned long long *allocation,
                                          unsigned long long *capacity)
{
    int ret = 0;
    int fd = -1;

    if ((fd = open(target->path, O_RDONLY)) < 0) {
        virReportSystemError(conn, errno,
                             _("cannot open volume '%s'"),
                             target->path);
        ret = -1;
        goto out;
    }

    if (virStorageBackendUpdateVolTargetInfoFD(conn,
                                               target,
                                               fd,
                                               allocation,
                                               capacity) < 0) {

        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                          _("Failed to update volume target info for '%s'"),
                          target->path);

        ret = -1;
        goto out;
    }

    if (virStorageBackendUpdateVolTargetFormatFD(conn,
                                                 target,
                                                 fd) < 0) {
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                          _("Failed to update volume target format for '%s'"),
                          target->path);

        ret = -1;
        goto out;
    }

out:
    if (fd != -1) {
        close(fd);
    }
    return ret;
}


static int
virStorageBackendMpathNewVol(virConnectPtr conn,
                             virStoragePoolObjPtr pool,
                             const int devnum,
                             const char *dev)
{
    virStorageVolDefPtr vol;
    int ret = -1;

    if (VIR_ALLOC(vol) < 0) {
        virReportOOMError(conn);
        goto cleanup;
    }

    vol->type = VIR_STORAGE_VOL_BLOCK;

    if (virAsprintf(&(vol->name), "dm-%u", devnum) < 0) {
        virReportOOMError(conn);
        goto cleanup;
    }

    if (virAsprintf(&vol->target.path, "/dev/%s", dev) < 0) {
        virReportOOMError(conn);
        goto cleanup;
    }

    if (virStorageBackendMpathUpdateVolTargetInfo(conn,
                                                  &vol->target,
                                                  &vol->allocation,
                                                  &vol->capacity) < 0) {

        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              _("Failed to update volume for '%s'"),
                              vol->target.path);
        goto cleanup;
    }

    /* XXX should use logical unit's UUID instead */
    vol->key = strdup(vol->target.path);
    if (vol->key == NULL) {
        virReportOOMError(conn);
        goto cleanup;
    }

    if (VIR_REALLOC_N(pool->volumes.objs,
                      pool->volumes.count + 1) < 0) {
        virReportOOMError(conn);
        goto cleanup;
    }
    pool->volumes.objs[pool->volumes.count++] = vol;
    pool->def->capacity += vol->capacity;
    pool->def->allocation += vol->allocation;
    ret = 0;

cleanup:

    if (ret != 0)
        virStorageVolDefFree(vol);

    return ret;
}


static int
virStorageBackendIsMultipath(const char *devname)
{
    int ret = 0;
    struct dm_task *dmt = NULL;
    void *next = NULL;
    uint64_t start, length;
    char *target_type = NULL;
    char *params = NULL;

    dmt = dm_task_create(DM_DEVICE_TABLE);
    if (dmt == NULL) {
        ret = -1;
        goto out;
    }

    if (dm_task_set_name(dmt, devname) == 0) {
        ret = -1;
        goto out;
    }

    dm_task_no_open_count(dmt);

    if (!dm_task_run(dmt)) {
        ret = -1;
        goto out;
    }

    next = dm_get_next_target(dmt, next, &start, &length,
                              &target_type, &params);

    if (target_type == NULL) {
        ret = -1;
        goto out;
    }

    if (STREQ(target_type, "multipath")) {
        ret = 1;
    }

out:
    if (dmt != NULL) {
        dm_task_destroy(dmt);
    }
    return ret;
}


static int
virStorageBackendGetMinorNumber(const char *devname, uint32_t *minor)
{
    int ret = -1;
    struct dm_task *dmt;
    struct dm_info info;

    if (!(dmt = dm_task_create(DM_DEVICE_INFO))) {
        goto out;
    }

    if (!dm_task_set_name(dmt, devname)) {
        goto out;
    }

    if (!dm_task_run(dmt)) {
        goto out;
    }

    if (!dm_task_get_info(dmt, &info)) {
        goto out;
    }

    *minor = info.minor;
    ret = 0;

out:
    if (dmt != NULL)
        dm_task_destroy(dmt);

    return ret;
}


static int
virStorageBackendCreateVols(virConnectPtr conn,
                            virStoragePoolObjPtr pool,
                            struct dm_names *names)
{
    int retval = 0, is_mpath = 0;
    char *map_device = NULL;
    uint32_t minor = -1;

    do {
        is_mpath = virStorageBackendIsMultipath(names->name);

        if (is_mpath < 0) {
            retval = -1;
            goto out;
        }

        if (is_mpath == 1) {

            if (virAsprintf(&map_device, "mapper/%s", names->name) < 0) {
                virReportOOMError(conn);
                retval = -1;
                goto out;
            }

            if (virStorageBackendGetMinorNumber(names->name, &minor) < 0) {
                retval = -1;
                goto out;
            }

            virStorageBackendMpathNewVol(conn,
                                         pool,
                                         minor,
                                         map_device);

            VIR_FREE(map_device);
        }

        /* Given the way libdevmapper returns its data, I don't see
         * any way to avoid this series of casts. */
        names = (struct dm_names *)(((char *)names) + names->next);

    } while (names->next);

out:
    return retval;
}


static int
virStorageBackendGetMaps(virConnectPtr conn,
                         virStoragePoolObjPtr pool)
{
    int retval = 0;
    struct dm_task *dmt = NULL;
    struct dm_names *names = NULL;

    if (!(dmt = dm_task_create(DM_DEVICE_LIST))) {
        retval = 1;
        goto out;
    }

    dm_task_no_open_count(dmt);

    if (!dm_task_run(dmt)) {
        retval = 1;
        goto out;
    }

    if (!(names = dm_task_get_names(dmt))) {
        retval = 1;
        goto out;
    }

    if (!names->dev) {
        /* No devices found */
        goto out;
    }

    virStorageBackendCreateVols(conn, pool, names);

out:
    if (dmt != NULL) {
        dm_task_destroy (dmt);
    }
    return retval;
}


static int
virStorageBackendMpathRefreshPool(virConnectPtr conn,
                                  virStoragePoolObjPtr pool)
{
    int retval = 0;

    VIR_ERROR(_("in %s"), __func__);

    pool->def->allocation = pool->def->capacity = pool->def->available = 0;

    virFileWaitForDevices(conn);

    virStorageBackendGetMaps(conn, pool);

    return retval;
}


virStorageBackend virStorageBackendMpath = {
    .type = VIR_STORAGE_POOL_MPATH,

    .refreshPool = virStorageBackendMpathRefreshPool,
};
