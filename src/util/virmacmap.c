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
 */

#include <config.h>

#include "virmacmap.h"
#include "virobject.h"
#include "virlog.h"
#include "virjson.h"
#include "virfile.h"
#include "virhash.h"

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

    GHashTable *macs;
};


static virClass *virMacMapClass;


static void
virMacMapDispose(void *obj)
{
    virMacMap *mgr = obj;
    GHashTableIter htitr;
    void *value;

    g_hash_table_iter_init(&htitr,  mgr->macs);

    while (g_hash_table_iter_next(&htitr, NULL, &value))
        g_slist_free_full(value, g_free);

    g_clear_pointer(&mgr->macs, g_hash_table_unref);
}


static int virMacMapOnceInit(void)
{
    if (!VIR_CLASS_NEW(virMacMap, virClassForObjectLockable()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virMacMap);


static void
virMacMapAddLocked(virMacMap *mgr,
                   const char *domain,
                   const char *mac)
{
    GSList *orig_list;
    GSList *list;
    GSList *next;

    list = orig_list = g_hash_table_lookup(mgr->macs, domain);

    for (next = list; next; next = next->next) {
        if (STREQ((const char *) next->data, mac))
            return;
    }

    list = g_slist_append(list, g_strdup(mac));

    if (list != orig_list)
        g_hash_table_insert(mgr->macs, g_strdup(domain), list);
}


static void
virMacMapRemoveLocked(virMacMap *mgr,
                      const char *domain,
                      const char *mac)
{
    GSList *orig_list;
    GSList *list;
    GSList *next;

    list = orig_list = g_hash_table_lookup(mgr->macs, domain);

    if (!orig_list)
        return;

    for (next = list; next; next = next->next) {
        if (STREQ((const char *) next->data, mac)) {
            list = g_slist_remove_link(list, next);
            g_slist_free_full(next, g_free);
            break;
        }
    }

    if (list != orig_list) {
        if (list)
            g_hash_table_insert(mgr->macs, g_strdup(domain), list);
        else
            g_hash_table_remove(mgr->macs, domain);
    }
}


static int
virMacMapLoadFile(virMacMap *mgr,
                  const char *file)
{
    g_autofree char *map_str = NULL;
    g_autoptr(virJSONValue) map = NULL;
    int map_str_len = 0;
    size_t i;

    if (virFileExists(file) &&
        (map_str_len = virFileReadAll(file,
                                      VIR_MAC_MAP_FILE_SIZE_MAX,
                                      &map_str)) < 0)
        return -1;

    if (map_str_len == 0)
        return 0;

    if (!(map = virJSONValueFromString(map_str))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("invalid json in file: %1$s"),
                       file);
        return -1;
    }

    if (!virJSONValueIsArray(map)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Malformed file structure: %1$s"),
                       file);
        return -1;
    }

    for (i = 0; i < virJSONValueArraySize(map); i++) {
        virJSONValue *tmp = virJSONValueArrayGet(map, i);
        virJSONValue *macs;
        const char *domain;
        size_t j;
        GSList *vals = NULL;

        if (!(domain = virJSONValueObjectGetString(tmp, "domain"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Missing domain"));
            return -1;
        }

        if (!(macs = virJSONValueObjectGetArray(tmp, "macs"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Missing macs"));
            return -1;
        }

        if (g_hash_table_contains(mgr->macs, domain)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("duplicate domain '%1$s'"), domain);
            return -1;

        }

        for (j = 0; j < virJSONValueArraySize(macs); j++) {
            virJSONValue *macJSON = virJSONValueArrayGet(macs, j);

            vals = g_slist_prepend(vals, g_strdup(virJSONValueGetString(macJSON)));
        }

        vals = g_slist_reverse(vals);
        g_hash_table_insert(mgr->macs, g_strdup(domain), vals);
    }

    return 0;
}


static int
virMACMapHashDumper(void *payload,
                    const char *name,
                    void *data)
{
    g_autoptr(virJSONValue) obj = virJSONValueNewObject();
    g_autoptr(virJSONValue) arr = virJSONValueNewArray();
    GSList *macs = payload;
    GSList *next;

    for (next = macs; next; next = next->next) {
        if (virJSONValueArrayAppendString(arr, (const char *) next->data) < 0)
            return -1;
    }

    if (virJSONValueObjectAppendString(obj, "domain", name) < 0 ||
        virJSONValueObjectAppend(obj, "macs", &arr) < 0)
        return -1;

    if (virJSONValueArrayAppend(data, &obj) < 0)
        return -1;

    return 0;
}


static int
virMacMapDumpStrLocked(virMacMap *mgr,
                       char **str)
{
    g_autoptr(virJSONValue) arr = virJSONValueNewArray();

    if (virHashForEachSorted(mgr->macs, virMACMapHashDumper, arr) < 0)
        return -1;

    if (!(*str = virJSONValueToString(arr, true)))
        return -1;

    return 0;
}


static int
virMacMapWriteFileLocked(virMacMap *mgr,
                         const char *file)
{
    g_autofree char *str = NULL;

    if (virMacMapDumpStrLocked(mgr, &str) < 0)
        return -1;

    if (virFileRewriteStr(file, 0644, str) < 0)
        return -1;

    return 0;
}


char *
virMacMapFileName(const char *dnsmasqStateDir,
                  const char *bridge)
{
    return g_strdup_printf("%s/%s.macs", dnsmasqStateDir, bridge);
}


#define VIR_MAC_HASH_TABLE_SIZE 10

virMacMap *
virMacMapNew(const char *file)
{
    virMacMap *mgr;

    if (virMacMapInitialize() < 0)
        return NULL;

    if (!(mgr = virObjectLockableNew(virMacMapClass)))
        return NULL;

    virObjectLock(mgr);

    mgr->macs = virHashNew(NULL);

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
virMacMapAdd(virMacMap *mgr,
             const char *domain,
             const char *mac)
{
    virObjectLock(mgr);
    virMacMapAddLocked(mgr, domain, mac);
    virObjectUnlock(mgr);
    return 0;
}


int
virMacMapRemove(virMacMap *mgr,
                const char *domain,
                const char *mac)
{
    virObjectLock(mgr);
    virMacMapRemoveLocked(mgr, domain, mac);
    virObjectUnlock(mgr);
    return 0;
}


/* note that the returned pointer may be invalidated by other APIs in this module */
GSList *
virMacMapLookup(virMacMap *mgr,
                const char *domain)
{
    GSList *ret;

    virObjectLock(mgr);
    ret = virHashLookup(mgr->macs, domain);
    virObjectUnlock(mgr);
    return ret;
}


int
virMacMapWriteFile(virMacMap *mgr,
                   const char *filename)
{
    int ret;

    virObjectLock(mgr);
    ret = virMacMapWriteFileLocked(mgr, filename);
    virObjectUnlock(mgr);
    return ret;
}


int
virMacMapDumpStr(virMacMap *mgr,
                 char **str)
{
    int ret;

    virObjectLock(mgr);
    ret = virMacMapDumpStrLocked(mgr, str);
    virObjectUnlock(mgr);
    return ret;
}
