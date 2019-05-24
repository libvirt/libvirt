/*
 * storage_backend_zfs.c: storage backend for ZFS handling
 *
 * Copyright (C) 2014 Roman Bogorodskiy
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
 *
 */

#include <config.h>

#include "viralloc.h"
#include "virerror.h"
#include "virfile.h"
#include "storage_backend_zfs.h"
#include "virlog.h"
#include "virstring.h"
#include "storage_util.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE

VIR_LOG_INIT("storage.storage_backend_zfs");

/*
 * Some common flags of zfs and zpool commands we use:
 * -H -- don't print headers and separate fields by tab
 * -p -- show exact numbers instead of human-readable, i.e.
 *       for size, show just a number instead of 2G etc
 */

/**
 * virStorageBackendZFSVolModeNeeded:
 *
 * Checks if it's necessary to specify 'volmode' (i.e. that
 * we're working with BSD ZFS implementation).
 *
 * Returns 1 if 'volmode' is need, 0 if not needed, -1 on error
 */
static int
virStorageBackendZFSVolModeNeeded(void)
{
    int ret = -1, exit_code = -1;
    VIR_AUTOFREE(char *) error = NULL;
    VIR_AUTOPTR(virCommand) cmd = NULL;

    /* 'zfs get' without arguments prints out
     * usage information to stderr, including
     * list of supported options, and exits with
     * exit code 2
     */
    cmd = virCommandNewArgList(ZFS, "get", NULL);
    virCommandAddEnvString(cmd, "LC_ALL=C");
    virCommandSetErrorBuffer(cmd, &error);

    ret = virCommandRun(cmd, &exit_code);
    if ((ret < 0) || (exit_code != 2)) {
        VIR_WARN("Command 'zfs get' either failed "
                 "to run or exited with unexpected status");
        goto cleanup;
    }

    if (strstr(error, " volmode "))
        ret = 1;
    else
        ret = 0;

 cleanup:
    return ret;
}

static int
virStorageBackendZFSCheckPool(virStoragePoolObjPtr pool ATTRIBUTE_UNUSED,
                              bool *isActive)
{
    virStoragePoolDefPtr def = virStoragePoolObjGetDef(pool);
    VIR_AUTOFREE(char *) devpath = NULL;

    if (virAsprintf(&devpath, "/dev/zvol/%s",
                    def->source.name) < 0)
        return -1;
    *isActive = virFileIsDir(devpath);

    return 0;
}

static int
virStorageBackendZFSParseVol(virStoragePoolObjPtr pool,
                             virStorageVolDefPtr vol,
                             const char *volume_string)
{
    int ret = -1;
    size_t count;
    char *vol_name;
    bool is_new_vol = false;
    virStorageVolDefPtr volume = NULL;
    virStoragePoolDefPtr def = virStoragePoolObjGetDef(pool);
    VIR_AUTOSTRINGLIST tokens = NULL;
    VIR_AUTOSTRINGLIST name_tokens = NULL;

    if (!(tokens = virStringSplitCount(volume_string, "\t", 0, &count)))
        return -1;

    if (count != 3)
        goto cleanup;

    if (!(name_tokens = virStringSplit(tokens[0], "/", 2)))
        goto cleanup;

    vol_name = name_tokens[1];

    if (vol == NULL)
        volume = virStorageVolDefFindByName(pool, vol_name);
    else
        volume = vol;

    if (volume == NULL) {
        if (VIR_ALLOC(volume) < 0)
            goto cleanup;

        is_new_vol = true;
        volume->type = VIR_STORAGE_VOL_BLOCK;

        if (VIR_STRDUP(volume->name, vol_name) < 0)
            goto cleanup;
    }

    if (!volume->key && VIR_STRDUP(volume->key, tokens[0]) < 0)
        goto cleanup;

    if (volume->target.path == NULL) {
        if (virAsprintf(&volume->target.path, "%s/%s",
                        def->target.path, volume->name) < 0)
            goto cleanup;
    }

    if (virStrToLong_ull(tokens[1], NULL, 10, &volume->target.capacity) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("malformed volsize reported"));
        goto cleanup;
    }

    if (virStrToLong_ull(tokens[2], NULL, 10, &volume->target.allocation) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("malformed refreservation reported"));
        goto cleanup;
    }

    if (volume->target.allocation < volume->target.capacity)
        volume->target.sparse = true;

    if (is_new_vol && virStoragePoolObjAddVol(pool, volume) < 0)
        goto cleanup;
    volume = NULL;

    ret = 0;
 cleanup:
    if (is_new_vol)
        virStorageVolDefFree(volume);
    return ret;
}

static int
virStorageBackendZFSFindVols(virStoragePoolObjPtr pool,
                             virStorageVolDefPtr vol)
{
    virStoragePoolDefPtr def = virStoragePoolObjGetDef(pool);
    size_t i;
    VIR_AUTOSTRINGLIST lines = NULL;
    VIR_AUTOPTR(virCommand) cmd = NULL;
    VIR_AUTOFREE(char *) volumes_list = NULL;

    /**
     * $ zfs list -Hp -t volume -o name,volsize -r test
     * test/vol1       5368709120
     * test/vol3       1073741824
     * test/vol4       1572864000
     * $
     *
     * Arguments description:
     *  -t volume -- we want to see only volumes
     *  -o name,volsize -- limit output to name and volume size
     *  -r -- we want to see all the childer of our pool
     */
    cmd = virCommandNewArgList(ZFS,
                               "list", "-Hp",
                               "-t", "volume", "-r",
                               "-o", "name,volsize,refreservation",
                               def->source.name,
                               NULL);
    virCommandSetOutputBuffer(cmd, &volumes_list);
    if (virCommandRun(cmd, NULL) < 0)
        return -1;

    if (!(lines = virStringSplit(volumes_list, "\n", 0)))
        return -1;

    for (i = 0; lines[i]; i++) {
        if (STREQ(lines[i], ""))
            continue;

        if (virStorageBackendZFSParseVol(pool, vol, lines[i]) < 0)
            continue;
    }

    return 0;
}

static int
virStorageBackendZFSRefreshPool(virStoragePoolObjPtr pool ATTRIBUTE_UNUSED)
{
    virStoragePoolDefPtr def = virStoragePoolObjGetDef(pool);
    char *zpool_props = NULL;
    size_t i;
    VIR_AUTOPTR(virCommand) cmd = NULL;
    VIR_AUTOSTRINGLIST lines = NULL;
    VIR_AUTOSTRINGLIST tokens = NULL;

    /**
     * $ zpool get -Hp health,size,free,allocated test
     * test    health  ONLINE  -
     * test    size    199715979264    -
     * test    free    198899976704    -
     * test    allocated       816002560       -
     * $
     *
     * Here we just provide a list of properties we want to see
     */
    cmd = virCommandNewArgList(ZPOOL,
                               "get", "-Hp",
                               "health,size,free,allocated",
                               def->source.name,
                               NULL);
    virCommandSetOutputBuffer(cmd, &zpool_props);
    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    if (!(lines = virStringSplit(zpool_props, "\n", 0)))
        goto cleanup;

    for (i = 0; lines[i]; i++) {
        size_t count;
        char *prop_name;

        if (STREQ(lines[i], ""))
            continue;

        virStringListFree(tokens);
        if (!(tokens = virStringSplitCount(lines[i], "\t", 0, &count)))
            goto cleanup;

        if (count != 4)
            continue;

        prop_name = tokens[1];

        if (STREQ(prop_name, "free") || STREQ(prop_name, "size") ||
            STREQ(prop_name, "allocated")) {
            unsigned long long value;
            if (virStrToLong_ull(tokens[2], NULL, 10, &value) < 0)
                goto cleanup;

            if (STREQ(prop_name, "free"))
                def->available = value;
            else if (STREQ(prop_name, "size"))
                def->capacity = value;
            else if (STREQ(prop_name, "allocated"))
                def->allocation = value;
        }
    }

    /* Obtain a list of volumes */
    if (virStorageBackendZFSFindVols(pool, NULL) < 0)
        goto cleanup;

 cleanup:
    VIR_FREE(zpool_props);

    return 0;
}

static int
virStorageBackendZFSCreateVol(virStoragePoolObjPtr pool,
                              virStorageVolDefPtr vol)
{
    virStoragePoolDefPtr def = virStoragePoolObjGetDef(pool);
    int ret = -1;
    int volmode_needed = -1;
    VIR_AUTOPTR(virCommand) cmd = NULL;

    if (vol->target.encryption != NULL) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       "%s", _("storage pool does not support encrypted "
                               "volumes"));
        return -1;
    }

    vol->type = VIR_STORAGE_VOL_BLOCK;

    VIR_FREE(vol->target.path);
    if (virAsprintf(&vol->target.path, "%s/%s",
                    def->target.path, vol->name) < 0)
        return -1;

    if (VIR_STRDUP(vol->key, vol->target.path) < 0)
        goto cleanup;

    volmode_needed = virStorageBackendZFSVolModeNeeded();
    if (volmode_needed < 0)
        goto cleanup;
    /**
     * $ zfs create -o volmode=dev -V 10240K test/volname
     * $ zfs create -o volmode=dev -s -V 10240K test/volname
     * $ zfs create -o volmode=dev -s -o refreservation=1024K -V 10240K test/volname
     *
     * -o volmode=dev -- we want to get volumes exposed as cdev
     *                   devices. If we don't specify that zfs
     *                   will lookup vfs.zfs.vol.mode sysctl value
     * -s -- create a sparse volume
     * -o refreservation -- reserve the specified amount of space
     * -V -- tells to create a volume with the specified size
     */
    cmd = virCommandNewArgList(ZFS, "create", NULL);
    if (volmode_needed)
        virCommandAddArgList(cmd, "-o", "volmode=dev", NULL);
    if (vol->target.capacity != vol->target.allocation) {
        virCommandAddArg(cmd, "-s");
        if (vol->target.allocation > 0) {
            virCommandAddArg(cmd, "-o");
            virCommandAddArgFormat(cmd, "refreservation=%lluK",
                                   VIR_DIV_UP(vol->target.allocation, 1024));
        }
        vol->target.sparse = true;
    }
    virCommandAddArg(cmd, "-V");
    virCommandAddArgFormat(cmd, "%lluK",
                           VIR_DIV_UP(vol->target.capacity, 1024));
    virCommandAddArgFormat(cmd, "%s/%s", def->source.name, vol->name);

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    if (virStorageBackendZFSFindVols(pool, vol) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    return ret;

}

static int
virStorageBackendZFSDeleteVol(virStoragePoolObjPtr pool,
                              virStorageVolDefPtr vol,
                              unsigned int flags)
{
    virStoragePoolDefPtr def = virStoragePoolObjGetDef(pool);
    VIR_AUTOPTR(virCommand) destroy_cmd = NULL;

    virCheckFlags(0, -1);

    destroy_cmd = virCommandNewArgList(ZFS, "destroy", NULL);

    virCommandAddArgFormat(destroy_cmd, "%s/%s",
                           def->source.name, vol->name);

    return virCommandRun(destroy_cmd, NULL);
}

static int
virStorageBackendZFSBuildPool(virStoragePoolObjPtr pool,
                              unsigned int flags)
{
    virStoragePoolDefPtr def = virStoragePoolObjGetDef(pool);
    size_t i;
    VIR_AUTOPTR(virCommand) cmd = NULL;
    int ret = -1;

    virCheckFlags(0, -1);

    if (def->source.ndevice == 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       "%s", _("missing source devices"));
        return -1;
    }

    cmd = virCommandNewArgList(ZPOOL, "create",
                               def->source.name, NULL);

    for (i = 0; i < def->source.ndevice; i++)
        virCommandAddArg(cmd, def->source.devices[i].path);

    virObjectUnlock(pool);
    ret = virCommandRun(cmd, NULL);
    virObjectLock(pool);

    return ret;
}

static int
virStorageBackendZFSDeletePool(virStoragePoolObjPtr pool,
                               unsigned int flags)
{
    virStoragePoolDefPtr def = virStoragePoolObjGetDef(pool);
    VIR_AUTOPTR(virCommand) cmd = NULL;

    virCheckFlags(0, -1);

    cmd = virCommandNewArgList(ZPOOL, "destroy",
                               def->source.name, NULL);

    return virCommandRun(cmd, NULL);
}

virStorageBackend virStorageBackendZFS = {
    .type = VIR_STORAGE_POOL_ZFS,

    .checkPool = virStorageBackendZFSCheckPool,
    .refreshPool = virStorageBackendZFSRefreshPool,
    .createVol = virStorageBackendZFSCreateVol,
    .deleteVol = virStorageBackendZFSDeleteVol,
    .buildPool = virStorageBackendZFSBuildPool,
    .deletePool = virStorageBackendZFSDeletePool,
    .uploadVol = virStorageBackendVolUploadLocal,
    .downloadVol = virStorageBackendVolDownloadLocal,
};


int
virStorageBackendZFSRegister(void)
{
    return virStorageBackendRegister(&virStorageBackendZFS);
}
