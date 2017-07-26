/*
 * virmacmap.c: MAC address <-> Domain name mapping
 *
 * Copyright (C) 2016 Red Hat, Inc.
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
 * Authors:
 *     Michal Privoznik <mprivozn@redhat.com>
 */

#include <config.h>

#include "virmacmap.h"
#include "virobject.h"
#include "virlog.h"
#include "virjson.h"
#include "virfile.h"
#include "virhash.h"
#include "virstring.h"
#include "viralloc.h"

#define VIR_FROM_THIS VIR_FROM_NETWORK

VIR_LOG_INIT("util.virmacmap");

/**
 * VIR_MAC_MAP_FILE_SIZE_MAX:
 *
 * Macro providing the upper limit on the size of mac maps file
 */
#define VIR_MAC_MAP_FILE_SIZE_MAX (32 * 1024 * 1024)

struct virMacMap {
    virObjectLockable parent;

    virHashTablePtr macs;
};


static virClassPtr virMacMapClass;


static int
virMacMapHashFree(void *payload,
                  const void *name ATTRIBUTE_UNUSED,
                  void *opaque ATTRIBUTE_UNUSED)
{
    virStringListFree(payload);
    return 0;
}


static void
virMacMapDispose(void *obj)
{
    virMacMapPtr mgr = obj;
    virHashForEach(mgr->macs, virMacMapHashFree, NULL);
    virHashFree(mgr->macs);
}


static int virMacMapOnceInit(void)
{
    if (!(virMacMapClass = virClassNew(virClassForObjectLockable(),
                                       "virMacMapClass",
                                       sizeof(virMacMap),
                                       virMacMapDispose)))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virMacMap);


static int
virMacMapAddLocked(virMacMapPtr mgr,
                   const char *domain,
                   const char *mac)
{
    int ret = -1;
    char **macsList = NULL;
    char **newMacsList = NULL;

    if ((macsList = virHashLookup(mgr->macs, domain)) &&
        virStringListHasString((const char**) macsList, mac)) {
        ret = 0;
        goto cleanup;
    }

    if (!(newMacsList = virStringListAdd((const char **) macsList, mac)) ||
        virHashUpdateEntry(mgr->macs, domain, newMacsList) < 0)
        goto cleanup;
    newMacsList = NULL;
    virStringListFree(macsList);

    ret = 0;
 cleanup:
    virStringListFree(newMacsList);
    return ret;
}


static int
virMacMapRemoveLocked(virMacMapPtr mgr,
                      const char *domain,
                      const char *mac)
{
    char **macsList = NULL;
    char **newMacsList = NULL;

    if (!(macsList = virHashLookup(mgr->macs, domain)))
        return 0;

    newMacsList = macsList;
    virStringListRemove(&newMacsList, mac);
    if (!newMacsList) {
        virHashSteal(mgr->macs, domain);
    } else {
        if (macsList != newMacsList &&
            virHashUpdateEntry(mgr->macs, domain, newMacsList) < 0)
            return -1;
    }

    return 0;
}


static int
virMacMapLoadFile(virMacMapPtr mgr,
                  const char *file)
{
    char *map_str = NULL;
    virJSONValuePtr map = NULL;
    int map_str_len = 0;
    size_t i;
    int ret = -1;

    if (virFileExists(file) &&
        (map_str_len = virFileReadAll(file,
                                      VIR_MAC_MAP_FILE_SIZE_MAX,
                                      &map_str)) < 0)
        goto cleanup;

    if (map_str_len == 0) {
        ret = 0;
        goto cleanup;
    }

    if (!(map = virJSONValueFromString(map_str))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("invalid json in file: %s"),
                       file);
        goto cleanup;
    }

    if (!virJSONValueIsArray(map)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Malformed file structure: %s"),
                       file);
        goto cleanup;
    }

    for (i = 0; i < virJSONValueArraySize(map); i++) {
        virJSONValuePtr tmp = virJSONValueArrayGet(map, i);
        virJSONValuePtr macs;
        const char *domain;
        size_t j;

        if (!(domain = virJSONValueObjectGetString(tmp, "domain"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Missing domain"));
            goto cleanup;
        }

        if (!(macs = virJSONValueObjectGetArray(tmp, "macs"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Missing macs"));
            goto cleanup;
        }

        for (j = 0; j < virJSONValueArraySize(macs); j++) {
            virJSONValuePtr macJSON = virJSONValueArrayGet(macs, j);
            const char *mac = virJSONValueGetString(macJSON);

            if (virMacMapAddLocked(mgr, domain, mac) < 0)
                goto cleanup;
        }
    }

    ret = 0;
 cleanup:
    VIR_FREE(map_str);
    virJSONValueFree(map);
    return ret;
}


static int
virMACMapHashDumper(void *payload,
                    const void *name,
                    void *data)
{
    virJSONValuePtr obj = NULL;
    virJSONValuePtr arr = NULL;
    const char **macs = payload;
    size_t i;
    int ret = -1;

    if (!(obj = virJSONValueNewObject()) ||
        !(arr = virJSONValueNewArray()))
        goto cleanup;

    for (i = 0; macs[i]; i++) {
        virJSONValuePtr m = virJSONValueNewString(macs[i]);

        if (!m ||
            virJSONValueArrayAppend(arr, m) < 0) {
            virJSONValueFree(m);
            goto cleanup;
        }
    }

    if (virJSONValueObjectAppendString(obj, "domain", name) < 0 ||
        virJSONValueObjectAppend(obj, "macs", arr) < 0)
        goto cleanup;
    arr = NULL;

    if (virJSONValueArrayAppend(data, obj) < 0)
        goto cleanup;
    obj = NULL;

    ret = 0;
 cleanup:
    virJSONValueFree(obj);
    virJSONValueFree(arr);
    return ret;
}


static int
virMacMapDumpStrLocked(virMacMapPtr mgr,
                       char **str)
{
    virJSONValuePtr arr;
    int ret = -1;

    if (!(arr = virJSONValueNewArray()))
        goto cleanup;

    if (virHashForEach(mgr->macs, virMACMapHashDumper, arr) < 0)
        goto cleanup;

    if (!(*str = virJSONValueToString(arr, true)))
        goto cleanup;

    ret = 0;
 cleanup:
    virJSONValueFree(arr);
    return ret;
}


static int
virMacMapWriteFileLocked(virMacMapPtr mgr,
                         const char *file)
{
    char *str;
    int ret = -1;

    if (virMacMapDumpStrLocked(mgr, &str) < 0)
        goto cleanup;

    if (virFileRewriteStr(file, 0644, str) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    VIR_FREE(str);
    return ret;
}


char *
virMacMapFileName(const char *dnsmasqStateDir,
                  const char *bridge)
{
    char *filename;

    ignore_value(virAsprintf(&filename, "%s/%s.macs", dnsmasqStateDir, bridge));

    return filename;
}


#define VIR_MAC_HASH_TABLE_SIZE 10

virMacMapPtr
virMacMapNew(const char *file)
{
    virMacMapPtr mgr;

    if (virMacMapInitialize() < 0)
        return NULL;

    if (!(mgr = virObjectLockableNew(virMacMapClass)))
        return NULL;

    virObjectLock(mgr);
    if (!(mgr->macs = virHashCreate(VIR_MAC_HASH_TABLE_SIZE, NULL)))
        goto error;

    if (file &&
        virMacMapLoadFile(mgr, file) < 0)
        goto error;

    virObjectUnlock(mgr);
    return mgr;

 error:
    virObjectUnlock(mgr);
    virObjectUnref(mgr);
    return NULL;
}


int
virMacMapAdd(virMacMapPtr mgr,
             const char *domain,
             const char *mac)
{
    int ret;

    virObjectLock(mgr);
    ret = virMacMapAddLocked(mgr, domain, mac);
    virObjectUnlock(mgr);
    return ret;
}


int
virMacMapRemove(virMacMapPtr mgr,
                const char *domain,
                const char *mac)
{
    int ret;

    virObjectLock(mgr);
    ret = virMacMapRemoveLocked(mgr, domain, mac);
    virObjectUnlock(mgr);
    return ret;
}


const char *const *
virMacMapLookup(virMacMapPtr mgr,
                const char *domain)
{
    const char *const *ret;

    virObjectLock(mgr);
    ret = virHashLookup(mgr->macs, domain);
    virObjectUnlock(mgr);
    return ret;
}


int
virMacMapWriteFile(virMacMapPtr mgr,
                   const char *filename)
{
    int ret;

    virObjectLock(mgr);
    ret = virMacMapWriteFileLocked(mgr, filename);
    virObjectUnlock(mgr);
    return ret;
}


int
virMacMapDumpStr(virMacMapPtr mgr,
                 char **str)
{
    int ret;

    virObjectLock(mgr);
    ret = virMacMapDumpStrLocked(mgr, str);
    virObjectUnlock(mgr);
    return ret;
}
