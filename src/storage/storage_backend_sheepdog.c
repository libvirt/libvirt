/*
 * storage_backend_sheepdog.c: storage backend for Sheepdog handling
 *
 * Copyright (C) 2013-2014 Red Hat, Inc.
 * Copyright (C) 2012 Wido den Hollander
 * Copyright (C) 2012 Frank Spijkerman
 * Copyright (C) 2012 Sebastian Wiedenroth
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
 * Author: Wido den Hollander <wido@widodh.nl>
 *         Frank Spijkerman <frank.spijkerman@avira.com>
 *         Sebastian Wiedenroth <sebastian.wiedenroth@skylime.net>
 */

#include <config.h>

#include "virerror.h"
#include "storage_backend_sheepdog.h"
#include "storage_conf.h"
#include "vircommand.h"
#include "viralloc.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE

static int virStorageBackendSheepdogRefreshVol(virConnectPtr conn,
                                               virStoragePoolObjPtr pool,
                                               virStorageVolDefPtr vol);

void virStorageBackendSheepdogAddHostArg(virCommandPtr cmd,
                                         virStoragePoolObjPtr pool);

int
virStorageBackendSheepdogParseNodeInfo(virStoragePoolDefPtr pool,
                                       char *output)
{
    /* fields:
     * node id/total, size, used, use%, [total vdi size]
     *
     * example output:
     * 0 425814278144 4871131136 420943147008 1%
     * Total 2671562256384 32160083968 2639402172416 1% 75161927680
     */
    char **lines = NULL;
    char **cells = NULL;
    size_t i;
    int ret = -1;

    pool->allocation = pool->capacity = pool->available = 0;

    lines = virStringSplit(output, "\n", 0);
    if (lines == NULL)
        goto cleanup;

    for (i = 0; lines[i]; i++) {
        char *line = lines[i];
        if (line == NULL)
            goto cleanup;

        if (!STRPREFIX(line, "Total "))
            continue;

        virStringStripControlChars(line);
        virTrimSpaces(line, NULL);
        if ((cells = virStringSplit(line, " ", 0)) == NULL)
            continue;

        if (virStringListLength(cells) < 3) {
            goto cleanup;
        }

        if (virStrToLong_ull(cells[1], NULL, 10, &pool->capacity) < 0)
            goto cleanup;

        if (virStrToLong_ull(cells[2], NULL, 10, &pool->allocation) < 0)
            goto cleanup;

        pool->available = pool->capacity - pool->allocation;
        ret = 0;
        break;
    }

 cleanup:
    virStringFreeList(lines);
    virStringFreeList(cells);
    return ret;
}

void
virStorageBackendSheepdogAddHostArg(virCommandPtr cmd,
                                    virStoragePoolObjPtr pool)
{
    const char *address = "localhost";
    int port = 7000;
    if (pool->def->source.nhost > 0) {
        if (pool->def->source.hosts[0].name != NULL)
            address = pool->def->source.hosts[0].name;
        if (pool->def->source.hosts[0].port)
            port = pool->def->source.hosts[0].port;
    }
    virCommandAddArg(cmd, "-a");
    virCommandAddArgFormat(cmd, "%s", address);
    virCommandAddArg(cmd, "-p");
    virCommandAddArgFormat(cmd, "%d", port);
}

static int
virStorageBackendSheepdogAddVolume(virConnectPtr conn ATTRIBUTE_UNUSED,
                                  virStoragePoolObjPtr pool, const char *diskInfo)
{
    virStorageVolDefPtr vol = NULL;

    if (diskInfo == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing disk info when adding volume"));
        goto error;
    }

    if (VIR_ALLOC(vol) < 0 || VIR_STRDUP(vol->name, diskInfo) < 0)
        goto error;

    vol->type = VIR_STORAGE_VOL_NETWORK;

    if (virStorageBackendSheepdogRefreshVol(conn, pool, vol) < 0)
        goto error;

    if (VIR_EXPAND_N(pool->volumes.objs, pool->volumes.count, 1) < 0)
        goto error;

    pool->volumes.objs[pool->volumes.count - 1] = vol;

    return 0;

 error:
    virStorageVolDefFree(vol);
    return -1;
}

static int
virStorageBackendSheepdogRefreshAllVol(virConnectPtr conn ATTRIBUTE_UNUSED,
                                       virStoragePoolObjPtr pool)
{
    int ret = -1;
    char *output = NULL;
    char **lines = NULL;
    char **cells = NULL;
    size_t i;

    virCommandPtr cmd = virCommandNewArgList(SHEEPDOGCLI, "vdi", "list", "-r", NULL);
    virStorageBackendSheepdogAddHostArg(cmd, pool);
    virCommandSetOutputBuffer(cmd, &output);
    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    lines = virStringSplit(output, "\n", 0);
    if (lines == NULL)
        goto cleanup;

    for (i = 0; lines[i]; i++) {
        const char *line = lines[i];
        if (line == NULL)
            break;

        cells = virStringSplit(line, " ", 0);

        if (cells != NULL && virStringListLength(cells) > 2) {
            if (virStorageBackendSheepdogAddVolume(conn, pool, cells[1]) < 0)
                goto cleanup;
        }

        virStringFreeList(cells);
        cells = NULL;
    }

    ret = 0;

 cleanup:
    virCommandFree(cmd);
    virStringFreeList(lines);
    virStringFreeList(cells);
    VIR_FREE(output);
    return ret;
}


static int
virStorageBackendSheepdogRefreshPool(virConnectPtr conn ATTRIBUTE_UNUSED,
                                     virStoragePoolObjPtr pool)
{
    int ret = -1;
    char *output = NULL;
    virCommandPtr cmd;

    cmd = virCommandNewArgList(SHEEPDOGCLI, "node", "info", "-r", NULL);
    virStorageBackendSheepdogAddHostArg(cmd, pool);
    virCommandSetOutputBuffer(cmd, &output);
    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    if (virStorageBackendSheepdogParseNodeInfo(pool->def, output) < 0)
        goto cleanup;

    ret = virStorageBackendSheepdogRefreshAllVol(conn, pool);
 cleanup:
    virCommandFree(cmd);
    VIR_FREE(output);
    return ret;
}


static int
virStorageBackendSheepdogDeleteVol(virConnectPtr conn ATTRIBUTE_UNUSED,
                                   virStoragePoolObjPtr pool,
                                   virStorageVolDefPtr vol,
                                   unsigned int flags)
{

    virCheckFlags(0, -1);

    virCommandPtr cmd = virCommandNewArgList(SHEEPDOGCLI, "vdi", "delete", vol->name, NULL);
    virStorageBackendSheepdogAddHostArg(cmd, pool);
    int ret = virCommandRun(cmd, NULL);

    virCommandFree(cmd);
    return ret;
}


static int
virStorageBackendSheepdogCreateVol(virConnectPtr conn ATTRIBUTE_UNUSED,
                                   virStoragePoolObjPtr pool,
                                   virStorageVolDefPtr vol)
{
    if (vol->target.encryption != NULL) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Sheepdog does not support encrypted volumes"));
        return -1;
    }

    vol->type = VIR_STORAGE_VOL_NETWORK;

    VIR_FREE(vol->key);
    if (virAsprintf(&vol->key, "%s/%s",
                    pool->def->source.name, vol->name) == -1)
        return -1;

    VIR_FREE(vol->target.path);
    if (VIR_STRDUP(vol->target.path, vol->name) < 0)
        return -1;

    return 0;
}


static int
virStorageBackendSheepdogBuildVol(virConnectPtr conn ATTRIBUTE_UNUSED,
                                  virStoragePoolObjPtr pool,
                                  virStorageVolDefPtr vol,
                                  unsigned int flags)
{
    int ret = -1;
    virCommandPtr cmd = NULL;

    virCheckFlags(0, -1);

    if (!vol->target.capacity) {
        virReportError(VIR_ERR_NO_SUPPORT, "%s",
                       _("volume capacity required for this pool"));
        goto cleanup;
    }

    cmd = virCommandNewArgList(SHEEPDOGCLI, "vdi", "create", vol->name, NULL);
    virCommandAddArgFormat(cmd, "%llu", vol->target.capacity);

    if(NULL != vol->target.redundancy)
        virCommandAddArgList(cmd, "-c", vol->target.redundancy, NULL);

    virStorageBackendSheepdogAddHostArg(cmd, pool);
    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virCommandFree(cmd);
    return ret;
}


int
virStorageBackendSheepdogParseVdiList(virStorageVolDefPtr vol,
                                      char *output)
{
    /* fields:
     * current/clone/snapshot, name, id, size, used, shared, creation time, vdi id, redundancy, [tag], size shift
     *
     * example output:
     * s test 1 10 0 0 1336556634 7c2b25 1 tt 22
     * s test 2 10 0 0 1336557203 7c2b26 2 zz 22
     * = 39865 0 21474836480 247463936 1337982976 1447516646 47d187 2  22
     * = test 3 10 0 0 1336557216 7c2b27 3 xx 22
     */
    char **lines = NULL;
    char **cells = NULL;
    size_t i;
    int ret = -1;

    vol->target.allocation = vol->target.capacity = 0;
    vol->target.redundancy = NULL;

    lines = virStringSplit(output, "\n", 0);
    if (lines == NULL)
        goto cleanup;

    for (i = 0; lines[i]; i++) {
        char *line = lines[i];
        if (line == NULL)
            break;

        if (!STRPREFIX(line, "= "))
            continue;

        /* skip = and space */
        if (*(line + 2) != '\0')
            line += 2;
        else
            continue;

        /* skip name */
        while (*line != '\0' && *line != ' ') {
            if (*line == '\\')
                ++line;
            ++line;
        }

        /* skip space */
        if (*(line + 1) != '\0')
            line += 1;
        else
            continue;

        virStringStripControlChars(line);
        virTrimSpaces(line, NULL);
        if ((cells = virStringSplit(line, " ", 0)) == NULL)
            continue;

        if (virStringListLength(cells) < 5)
            continue;

        if ((ret = virStrToLong_ull(cells[1], NULL, 10, &vol->target.capacity)) < 0)
            goto cleanup;

        if ((ret = virStrToLong_ull(cells[2], NULL, 10, &vol->target.allocation)) < 0)
            goto cleanup;

        if ((ret = VIR_STRDUP(vol->target.redundancy, cells[6])) < 0)
            goto cleanup;

        ret = 0;
        break;
    }

 cleanup:
    virStringFreeList(lines);
    virStringFreeList(cells);
    return ret;
}

static int
virStorageBackendSheepdogRefreshVol(virConnectPtr conn ATTRIBUTE_UNUSED,
                                    virStoragePoolObjPtr pool,
                                    virStorageVolDefPtr vol)
{
    int ret;
    char *output = NULL;

    virCommandPtr cmd = virCommandNewArgList(SHEEPDOGCLI, "vdi", "list", vol->name, "-r", NULL);
    virStorageBackendSheepdogAddHostArg(cmd, pool);
    virCommandSetOutputBuffer(cmd, &output);
    ret = virCommandRun(cmd, NULL);

    if (ret < 0)
        goto cleanup;

    if ((ret = virStorageBackendSheepdogParseVdiList(vol, output)) < 0)
        goto cleanup;

    vol->type = VIR_STORAGE_VOL_NETWORK;

    VIR_FREE(vol->key);
    if (virAsprintf(&vol->key, "%s/%s",
                    pool->def->source.name, vol->name) == -1)
        goto cleanup;

    VIR_FREE(vol->target.path);
    ignore_value(VIR_STRDUP(vol->target.path, vol->name));
 cleanup:
    virCommandFree(cmd);
    return ret;
}


static int
virStorageBackendSheepdogResizeVol(virConnectPtr conn ATTRIBUTE_UNUSED,
                                   virStoragePoolObjPtr pool,
                                   virStorageVolDefPtr vol,
                                   unsigned long long capacity,
                                   unsigned int flags)
{

    virCheckFlags(0, -1);

    virCommandPtr cmd = virCommandNewArgList(SHEEPDOGCLI, "vdi", "resize", vol->name, NULL);
    virCommandAddArgFormat(cmd, "%llu", capacity);
    virStorageBackendSheepdogAddHostArg(cmd, pool);
    int ret = virCommandRun(cmd, NULL);

    virCommandFree(cmd);
    return ret;

}



virStorageBackend virStorageBackendSheepdog = {
    .type = VIR_STORAGE_POOL_SHEEPDOG,

    .refreshPool = virStorageBackendSheepdogRefreshPool,
    .createVol = virStorageBackendSheepdogCreateVol,
    .buildVol = virStorageBackendSheepdogBuildVol,
    .refreshVol = virStorageBackendSheepdogRefreshVol,
    .deleteVol = virStorageBackendSheepdogDeleteVol,
    .resizeVol = virStorageBackendSheepdogResizeVol,
};
