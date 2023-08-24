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

#define ZFS "zfs"
#define ZPOOL "zpool"

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
    g_autofree char *error = NULL;
    g_autoptr(virCommand) cmd = NULL;

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
        return ret;
    }

    if (strstr(error, " volmode "))
        return 1;
    else
        return 0;
}

static int
virStorageBackendZFSCheckPool(virStoragePoolObj *pool G_GNUC_UNUSED,
                              bool *isActive)
{
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    g_autoptr(virCommand) cmd = NULL;
    int exit_code = -1;

    /* Check for an existing dataset of type 'filesystem' by the name of our
     * pool->source.name.  */
    cmd = virCommandNewArgList(ZFS,
                               "list", "-H",
                               "-t", "filesystem",
                               "-o", "name",
                               def->source.name,
                               NULL);


    if (virCommandRun(cmd, &exit_code) < 0)
        return -1;

    /* zfs list exits with 0 if the dataset exists, 1 if it doesn't */
    *isActive = exit_code == 0;

    return 0;
}

static int
virStorageBackendZFSParseVol(virStoragePoolObj *pool,
                             virStorageVolDef *vol,
                             const char *volume_string)
{
    int ret = -1;
    char *vol_name;
    bool is_new_vol = false;
    virStorageVolDef *volume = NULL;
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    g_auto(GStrv) tokens = NULL;
    char *tmp;

    if (!(tokens = g_strsplit(volume_string, "\t", 0)))
        return -1;

    if (g_strv_length(tokens) != 3)
        goto cleanup;

    vol_name = tokens[0];
    if ((tmp = strrchr(vol_name, '/')))
        vol_name = tmp + 1;

    if (vol == NULL)
        volume = virStorageVolDefFindByName(pool, vol_name);
    else
        volume = vol;

    if (volume == NULL) {
        volume = g_new0(virStorageVolDef, 1);

        is_new_vol = true;
        volume->type = VIR_STORAGE_VOL_BLOCK;

        volume->name = g_strdup(vol_name);
    }

    if (!volume->key)
        volume->key = g_strdup(tokens[0]);

    if (volume->target.path == NULL) {
        volume->target.path = g_strdup_printf("%s/%s", def->target.path,
                                              volume->name);
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
virStorageBackendZFSFindVols(virStoragePoolObj *pool,
                             virStorageVolDef *vol)
{
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    size_t i;
    g_auto(GStrv) lines = NULL;
    g_autoptr(virCommand) cmd = NULL;
    g_autofree char *volumes_list = NULL;

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

    if (!(lines = g_strsplit(volumes_list, "\n", 0)))
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
virStorageBackendZFSRefreshPool(virStoragePoolObj *pool G_GNUC_UNUSED)
{
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    char *zpool_props = NULL;
    size_t i;
    g_autoptr(virCommand) cmd = NULL;
    g_auto(GStrv) lines = NULL;
    g_autofree char *name = g_strdup(def->source.name);
    char *tmp;

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
    if ((tmp = strchr(name, '/')))
        *tmp = '\0';

    cmd = virCommandNewArgList(ZPOOL,
                               "get", "-Hp",
                               "health,size,free,allocated",
                               name,
                               NULL);
    virCommandSetOutputBuffer(cmd, &zpool_props);
    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    if (!(lines = g_strsplit(zpool_props, "\n", 0)))
        goto cleanup;

    for (i = 0; lines[i]; i++) {
        g_auto(GStrv) tokens = NULL;
        char *prop_name;

        if (STREQ(lines[i], ""))
            continue;

        if (!(tokens = g_strsplit(lines[i], "\t", 0)))
            goto cleanup;

        if (g_strv_length(tokens) != 4)
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
virStorageBackendZFSCreateVol(virStoragePoolObj *pool,
                              virStorageVolDef *vol)
{
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    int volmode_needed = -1;
    g_autoptr(virCommand) cmd = NULL;

    if (vol->target.encryption != NULL) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       "%s", _("storage pool does not support encrypted volumes"));
        return -1;
    }

    vol->type = VIR_STORAGE_VOL_BLOCK;

    VIR_FREE(vol->target.path);
    vol->target.path = g_strdup_printf("%s/%s", def->target.path, vol->name);

    vol->key = g_strdup(vol->target.path);

    volmode_needed = virStorageBackendZFSVolModeNeeded();
    if (volmode_needed < 0)
        return -1;
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
        return -1;

    if (virStorageBackendZFSFindVols(pool, vol) < 0)
        return -1;

    return 0;
}

static int
virStorageBackendZFSDeleteVol(virStoragePoolObj *pool,
                              virStorageVolDef *vol,
                              unsigned int flags)
{
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    g_autoptr(virCommand) destroy_cmd = NULL;

    virCheckFlags(0, -1);

    destroy_cmd = virCommandNewArgList(ZFS, "destroy", NULL);

    virCommandAddArgFormat(destroy_cmd, "%s/%s",
                           def->source.name, vol->name);

    return virCommandRun(destroy_cmd, NULL);
}

static int
virStorageBackendZFSBuildPool(virStoragePoolObj *pool,
                              unsigned int flags)
{
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    size_t i;
    g_autoptr(virCommand) cmd = NULL;
    int ret = -1;
    char *tmp;

    virCheckFlags(0, -1);

    tmp = strstr(def->source.name, "/");
    if (tmp) {
        cmd = virCommandNewArgList(ZFS, "create", "-o", "mountpoint=none",
                                   def->source.name, NULL);
    } else {
        if (def->source.ndevice == 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           "%s", _("missing source devices"));
            return -1;
        }

        cmd = virCommandNewArgList(ZPOOL, "create",
                                   def->source.name, NULL);

        for (i = 0; i < def->source.ndevice; i++)
            virCommandAddArg(cmd, def->source.devices[i].path);
    }

    virObjectUnlock(pool);
    ret = virCommandRun(cmd, NULL);
    virObjectLock(pool);

    return ret;
}

static int
virStorageBackendZFSDeletePool(virStoragePoolObj *pool,
                               unsigned int flags)
{
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    g_autoptr(virCommand) cmd = NULL;
    char *tmp;

    virCheckFlags(0, -1);

    tmp = strstr(def->source.name, "/");
    if (tmp) {
        cmd = virCommandNewArgList(ZFS, "destroy", "-r",
                                   def->source.name, NULL);
    } else {
        cmd = virCommandNewArgList(ZPOOL, "destroy",
                                   def->source.name, NULL);
    }

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
