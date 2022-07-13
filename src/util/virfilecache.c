/*
 * virfilecache.c: file caching for data
 *
 * Copyright (C) 2017 Red Hat, Inc.
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

#include "internal.h"

#include "virbuffer.h"
#include "vircrypto.h"
#include "virerror.h"
#include "virfile.h"
#include "virfilecache.h"
#include "virhash.h"
#include "virlog.h"
#include "virobject.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.filecache");


struct _virFileCache {
    virObjectLockable parent;

    GHashTable *table;

    char *dir;
    char *suffix;

    void *priv;

    virFileCacheHandlers handlers;
};


static virClass *virFileCacheClass;


static void
virFileCachePrivFree(virFileCache *cache)
{
    if (cache->priv && cache->handlers.privFree)
        cache->handlers.privFree(cache->priv);
}


static void
virFileCacheDispose(void *obj)
{
    virFileCache *cache = obj;

    g_free(cache->dir);
    g_free(cache->suffix);

    g_clear_pointer(&cache->table, g_hash_table_unref);

    virFileCachePrivFree(cache);
}


static int
virFileCacheOnceInit(void)
{
    if (!VIR_CLASS_NEW(virFileCache, virClassForObjectLockable()))
        return -1;

    return 0;
}


VIR_ONCE_GLOBAL_INIT(virFileCache);


static char *
virFileCacheGetFileName(virFileCache *cache,
                        const char *name)
{
    g_autofree char *namehash = NULL;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    if (virCryptoHashString(VIR_CRYPTO_HASH_SHA256, name, &namehash) < 0)
        return NULL;

    if (g_mkdir_with_parents(cache->dir, 0777) < 0) {
        virReportSystemError(errno,
                             _("Unable to create directory '%1$s'"),
                             cache->dir);
        return NULL;
    }

    virBufferAsprintf(&buf, "%s/%s", cache->dir, namehash);

    if (cache->suffix)
        virBufferAsprintf(&buf, ".%s", cache->suffix);

    return virBufferContentAndReset(&buf);
}


static int
virFileCacheLoad(virFileCache *cache,
                 const char *name,
                 void **data)
{
    g_autofree char *file = NULL;
    int ret = -1;
    void *loadData = NULL;
    bool outdated = false;

    *data = NULL;

    if (!(file = virFileCacheGetFileName(cache, name)))
        return ret;

    if (!virFileExists(file)) {
        if (errno == ENOENT) {
            VIR_DEBUG("No cached data '%s' for '%s'", file, name);
            ret = 0;
            goto cleanup;
        }
        virReportSystemError(errno,
                             _("Unable to access cache '%1$s' for '%2$s'"),
                             file, name);
        goto cleanup;
    }

    if (!(loadData = cache->handlers.loadFile(file, name, cache->priv, &outdated))) {
        if (!outdated) {
            VIR_WARN("Failed to load cached data from '%s' for '%s': %s",
                     file, name, virGetLastErrorMessage());
            virResetLastError();
        }
        ret = 0;
        goto cleanup;
    }

    if (!cache->handlers.isValid(loadData, cache->priv)) {
        VIR_DEBUG("Outdated cached capabilities '%s' for '%s'", file, name);
        unlink(file);
        ret = 0;
        goto cleanup;
    }

    VIR_DEBUG("Loaded cached data '%s' for '%s'", file, name);

    ret = 1;
    *data = g_steal_pointer(&loadData);

 cleanup:
    g_clear_pointer(&loadData, g_object_unref);
    return ret;
}


static int
virFileCacheSave(virFileCache *cache,
                 const char *name,
                 void *data)
{
    g_autofree char *file = NULL;

    if (!(file = virFileCacheGetFileName(cache, name)))
        return -1;

    if (cache->handlers.saveFile(data, file, cache->priv) < 0)
        return -1;

    return 0;
}


static void *
virFileCacheNewData(virFileCache *cache,
                    const char *name)
{
    void *data = NULL;
    int rv;

    if ((rv = virFileCacheLoad(cache, name, &data)) < 0)
        return NULL;

    if (rv == 0) {
        if (!(data = cache->handlers.newData(name, cache->priv)))
            return NULL;

        if (virFileCacheSave(cache, name, data) < 0) {
            g_clear_object(&data);
        }
    }

    return data;
}


/**
 * virFileCacheNew:
 * @dir: the cache directory where all the cache files will be stored
 * @suffix: the cache file suffix or NULL if no suffix is required
 * @handlers: filled structure with all required handlers
 *
 * Creates a new cache object which handles caching any data to files
 * stored on a filesystem.
 *
 * Returns new cache object or NULL on error.
 */
virFileCache *
virFileCacheNew(const char *dir,
                const char *suffix,
                virFileCacheHandlers *handlers)
{
    virFileCache *cache;

    if (virFileCacheInitialize() < 0)
        return NULL;

    if (!(cache = virObjectNew(virFileCacheClass)))
        return NULL;

    cache->table = virHashNew(g_object_unref);

    cache->dir = g_strdup(dir);

    cache->suffix = g_strdup(suffix);

    cache->handlers = *handlers;

    return cache;
}


static void
virFileCacheValidate(virFileCache *cache,
                     const char *name,
                     void **data)
{
    if (*data && !cache->handlers.isValid(*data, cache->priv)) {
        VIR_DEBUG("Cached data '%p' no longer valid for '%s'",
                  *data, NULLSTR(name));
        if (name)
            virHashRemoveEntry(cache->table, name);
        *data = NULL;
    }

    if (!*data && name) {
        VIR_DEBUG("Creating data for '%s'", name);
        *data = virFileCacheNewData(cache, name);
        if (*data) {
            VIR_DEBUG("Caching data '%p' for '%s'", *data, name);
            if (virHashAddEntry(cache->table, name, *data) < 0) {
                g_clear_pointer(data, g_object_unref);
            }
        }
    }
}


/**
 * virFileCacheLookup:
 * @cache: existing cache object
 * @name: name of the data stored in a cache
 *
 * Lookup a data specified by name.  This tries to find a file with
 * cached data, if it doesn't exist or is no longer valid new data
 * is created.
 *
 * Returns data object or NULL on error.  The caller is responsible for
 * unrefing the data.
 */
void *
virFileCacheLookup(virFileCache *cache,
                   const char *name)
{
    void *data = NULL;

    virObjectLock(cache);

    data = virHashLookup(cache->table, name);
    virFileCacheValidate(cache, name, &data);

    if (data)
        g_object_ref(data);
    virObjectUnlock(cache);

    return data;
}


/**
 * virFileCacheLookupByFunc:
 * @cache: existing cache object
 * @iter: an iterator to identify the desired data
 * @iterData: extra opaque information passed to the @iter
 *
 * Similar to virFileCacheLookup() except it search by @iter.
 *
 * Returns data object or NULL on error.  The caller is responsible for
 * unrefing the data.
 */
void *
virFileCacheLookupByFunc(virFileCache *cache,
                         virHashSearcher iter,
                         const void *iterData)
{
    void *data = NULL;
    g_autofree char *name = NULL;

    virObjectLock(cache);

    data = virHashSearch(cache->table, iter, iterData, &name);
    virFileCacheValidate(cache, name, &data);

    if (data)
        g_object_ref(data);
    virObjectUnlock(cache);

    return data;
}


/**
 * virFileCacheGetPriv:
 * @cache: existing cache object
 *
 * Returns private data used by @handlers.
 */
void *
virFileCacheGetPriv(virFileCache *cache)
{
    void *priv;

    virObjectLock(cache);

    priv = cache->priv;

    virObjectUnlock(cache);

    return priv;
}


/**
 * virFileCacheSetPriv:
 * @cache: existing cache object
 * @priv: private data to set
 *
 * Sets private data used by @handlers.  If there is already some @priv
 * set, privFree() will be called on the old @priv before setting a new one.
 */
void
virFileCacheSetPriv(virFileCache *cache,
                    void *priv)
{
    virObjectLock(cache);

    virFileCachePrivFree(cache);

    cache->priv = priv;

    virObjectUnlock(cache);
}


/**
 * virFileCacheInsertData:
 * @cache: existing cache object
 * @name: name of the new data
 * @data: the actual data object to store in cache
 *
 * Adds a new data into a cache but doesn't store the data into
 * a file.  This function should be used only by testing code.
 *
 * Returns 0 on success, -1 on error.
 */
int
virFileCacheInsertData(virFileCache *cache,
                       const char *name,
                       void *data)
{
    int ret;

    virObjectLock(cache);

    ret = virHashUpdateEntry(cache->table, name, data);

    virObjectUnlock(cache);

    return ret;
}


/**
 * virFileCacheClear:
 * @cache: existing cache object
 *
 * Drops all entries from the cache. This is useful in tests to clean out
 * previous usage.
 */
void
virFileCacheClear(virFileCache *cache)
{
    virObjectLock(cache);
    virHashRemoveAll(cache->table);
    virObjectUnlock(cache);
}
