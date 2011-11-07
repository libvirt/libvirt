/*
 * storage_backend_mpath.c: storage backend for multipath handling
 *
 * Copyright (C) 2009-2011 Red Hat, Inc.
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
#include <fcntl.h>

#include <libdevmapper.h>

#include "virterror_internal.h"
#include "storage_conf.h"
#include "storage_backend.h"
#include "memory.h"
#include "logging.h"
#include "virfile.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE

static int
virStorageBackendMpathUpdateVolTargetInfo(virStorageVolTargetPtr target,
                                          unsigned long long *allocation,
                                          unsigned long long *capacity)
{
    int ret = -1;
    int fdret, fd = -1;

    if ((fdret = virStorageBackendVolOpen(target->path)) < 0)
        goto out;
    fd = fdret;

    if (virStorageBackendUpdateVolTargetInfoFD(target,
                                               fd,
                                               allocation,
                                               capacity) < 0)
        goto out;

    if (virStorageBackendDetectBlockVolFormatFD(target, fd) < 0)
        goto out;

    ret = 0;
out:
    VIR_FORCE_CLOSE(fd);
    return ret;
}


static int
virStorageBackendMpathNewVol(virStoragePoolObjPtr pool,
                             const int devnum,
                             const char *dev)
{
    virStorageVolDefPtr vol;
    int ret = -1;

    if (VIR_ALLOC(vol) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    vol->type = VIR_STORAGE_VOL_BLOCK;

    if (virAsprintf(&(vol->name), "dm-%u", devnum) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if (virAsprintf(&vol->target.path, "/dev/%s", dev) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if (virStorageBackendMpathUpdateVolTargetInfo(&vol->target,
                                                  &vol->allocation,
                                                  &vol->capacity) < 0) {
        goto cleanup;
    }

    /* XXX should use logical unit's UUID instead */
    vol->key = strdup(vol->target.path);
    if (vol->key == NULL) {
        virReportOOMError();
        goto cleanup;
    }

    if (VIR_REALLOC_N(pool->volumes.objs,
                      pool->volumes.count + 1) < 0) {
        virReportOOMError();
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
virStorageBackendIsMultipath(const char *dev_name)
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

    if (dm_task_set_name(dmt, dev_name) == 0) {
        ret = -1;
        goto out;
    }

    dm_task_no_open_count(dmt);

    if (!dm_task_run(dmt)) {
        ret = -1;
        goto out;
    }

    dm_get_next_target(dmt, next, &start, &length, &target_type, &params);

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
virStorageBackendGetMinorNumber(const char *dev_name, uint32_t *minor)
{
    int ret = -1;
    struct dm_task *dmt;
    struct dm_info info;

    if (!(dmt = dm_task_create(DM_DEVICE_INFO))) {
        goto out;
    }

    if (!dm_task_set_name(dmt, dev_name)) {
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
virStorageBackendCreateVols(virStoragePoolObjPtr pool,
                            struct dm_names *names)
{
    int retval = -1, is_mpath = 0;
    char *map_device = NULL;
    uint32_t minor = -1;
    uint32_t next;

    do {
        is_mpath = virStorageBackendIsMultipath(names->name);

        if (is_mpath < 0) {
            goto out;
        }

        if (is_mpath == 1) {

            if (virAsprintf(&map_device, "mapper/%s", names->name) < 0) {
                virReportOOMError();
                goto out;
            }

            if (virStorageBackendGetMinorNumber(names->name, &minor) < 0) {
                virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                                      _("Failed to get %s minor number"),
                                      names->name);
                goto out;
            }

            if (virStorageBackendMpathNewVol(pool, minor, map_device) < 0) {
                goto out;
            }

            VIR_FREE(map_device);
        }

        /* Given the way libdevmapper returns its data, I don't see
         * any way to avoid this series of casts. */
        next = names->next;
        names = (struct dm_names *)(((char *)names) + next);

    } while (next);

    retval = 0;
out:
    return retval;
}


static int
virStorageBackendGetMaps(virStoragePoolObjPtr pool)
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

    virStorageBackendCreateVols(pool, names);

out:
    if (dmt != NULL) {
        dm_task_destroy (dmt);
    }
    return retval;
}

static int
virStorageBackendMpathCheckPool(virConnectPtr conn ATTRIBUTE_UNUSED,
                                virStoragePoolObjPtr pool ATTRIBUTE_UNUSED,
                                bool *isActive)
{
    const char *path = "/dev/mpath";

    *isActive = false;

    if (access(path, F_OK) == 0)
        *isActive = true;

    return 0;
}



static int
virStorageBackendMpathRefreshPool(virConnectPtr conn ATTRIBUTE_UNUSED,
                                  virStoragePoolObjPtr pool)
{
    int retval = 0;

    VIR_DEBUG("conn=%p, pool=%p", conn, pool);

    pool->def->allocation = pool->def->capacity = pool->def->available = 0;

    virFileWaitForDevices();

    virStorageBackendGetMaps(pool);

    return retval;
}


virStorageBackend virStorageBackendMpath = {
    .type = VIR_STORAGE_POOL_MPATH,

    .checkPool = virStorageBackendMpathCheckPool,
    .refreshPool = virStorageBackendMpathRefreshPool,
};
