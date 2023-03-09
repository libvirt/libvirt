/*
 * storage_backend_mpath.c: storage backend for multipath handling
 *
 * Copyright (C) 2009-2014 Red Hat, Inc.
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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#include <unistd.h>
#include <fcntl.h>

#include <libdevmapper.h>

#include "virerror.h"
#include "storage_conf.h"
#include "storage_backend.h"
#include "storage_backend_mpath.h"
#include "viralloc.h"
#include "virlog.h"
#include "virfile.h"
#include "virutil.h"
#include "storage_util.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE

VIR_LOG_INIT("storage.storage_backend_mpath");

static int
virStorageBackendMpathNewVol(virStoragePoolObj *pool,
                             const int devnum,
                             const char *dev)
{
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    g_autoptr(virStorageVolDef) vol = NULL;

    vol = g_new0(virStorageVolDef, 1);

    vol->type = VIR_STORAGE_VOL_BLOCK;

    (vol->name) = g_strdup_printf("dm-%u", devnum);

    vol->target.path = g_strdup_printf("/dev/%s", dev);

    if (virStorageBackendUpdateVolInfo(vol, true,
                                       VIR_STORAGE_VOL_OPEN_DEFAULT, 0) < 0) {
        return -1;
    }

    /* XXX should use logical unit's UUID instead */
    vol->key = g_strdup(vol->target.path);

    if (virStoragePoolObjAddVol(pool, vol) < 0)
        return -1;

    def->capacity += vol->target.capacity;
    def->allocation += vol->target.allocation;
    vol = NULL;

    return 0;
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

    if (STREQ_NULLABLE(target_type, "multipath"))
        ret = 1;

 out:
    if (dmt != NULL)
        dm_task_destroy(dmt);
    return ret;
}


static int
virStorageBackendGetMinorNumber(const char *dev_name, uint32_t *minor)
{
    int ret = -1;
    struct dm_task *dmt;
    struct dm_info info;

    if (!(dmt = dm_task_create(DM_DEVICE_INFO)))
        goto out;

    if (!dm_task_set_name(dmt, dev_name))
        goto out;

    if (!dm_task_run(dmt))
        goto out;

    if (!dm_task_get_info(dmt, &info))
        goto out;

    *minor = info.minor;
    ret = 0;

 out:
    if (dmt != NULL)
        dm_task_destroy(dmt);

    return ret;
}


static int
virStorageBackendCreateVols(virStoragePoolObj *pool,
                            struct dm_names *names)
{
    uint32_t minor = -1;
    uint32_t next;
    g_autofree char *map_device = NULL;

    do {
        int is_mpath = virStorageBackendIsMultipath(names->name);

        if (is_mpath < 0)
            return -1;

        if (is_mpath == 1) {

            map_device = g_strdup_printf("mapper/%s", names->name);

            if (virStorageBackendGetMinorNumber(names->name, &minor) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Failed to get %1$s minor number"),
                               names->name);
                return -1;
            }

            if (virStorageBackendMpathNewVol(pool, minor, map_device) < 0)
                return -1;

            VIR_FREE(map_device);
        }

        /* Given the way libdevmapper returns its data, I don't see
         * any way to avoid this series of casts. */
        VIR_WARNINGS_NO_CAST_ALIGN
        next = names->next;
        names = (struct dm_names *)(((char *)names) + next);
        VIR_WARNINGS_RESET

    } while (next);

    return 0;
}


static int
virStorageBackendGetMaps(virStoragePoolObj *pool)
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
    if (dmt != NULL)
        dm_task_destroy(dmt);
    return retval;
}

static int
virStorageBackendMpathCheckPool(virStoragePoolObj *pool G_GNUC_UNUSED,
                                bool *isActive)
{
    *isActive = virFileExists("/dev/mapper") ||
                virFileExists("/dev/mpath");
    return 0;
}



static int
virStorageBackendMpathRefreshPool(virStoragePoolObj *pool)
{
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);

    VIR_DEBUG("pool=%p", pool);

    def->allocation = def->capacity = def->available = 0;

    virWaitForDevices();

    virStorageBackendGetMaps(pool);

    return 0;
}


virStorageBackend virStorageBackendMpath = {
    .type = VIR_STORAGE_POOL_MPATH,

    .checkPool = virStorageBackendMpathCheckPool,
    .refreshPool = virStorageBackendMpathRefreshPool,
    .uploadVol = virStorageBackendVolUploadLocal,
    .downloadVol = virStorageBackendVolDownloadLocal,
    .wipeVol = virStorageBackendVolWipeLocal,
};


int
virStorageBackendMpathRegister(void)
{
    return virStorageBackendRegister(&virStorageBackendMpath);
}
