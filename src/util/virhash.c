/*
 * virhash.c: chained hash tables
 *
 * Reference: Your favorite introductory book on algorithms
 *
 * Copyright (C) 2005-2014 Red Hat, Inc.
 * Copyright (C) 2000 Bjorn Reese and Daniel Veillard.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE AUTHORS AND
 * CONTRIBUTORS ACCEPT NO RESPONSIBILITY IN ANY CONCEIVABLE MANNER.
 */

#include <config.h>


#include "virerror.h"
#include "virhash.h"
#include "virlog.h"
#include "virhashcode.h"
#include "virrandom.h"
#include "virobject.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.hash");


struct _virHashAtomic {
    virObjectLockable parent;
    virHashTablePtr hash;
};

static virClassPtr virHashAtomicClass;
static void virHashAtomicDispose(void *obj);

static int virHashAtomicOnceInit(void)
{
    if (!VIR_CLASS_NEW(virHashAtomic, virClassForObjectLockable()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virHashAtomic);


/**
 * Our hash function uses a random seed to provide uncertainity from run to run
 * to prevent pre-crafting of colliding hash keys.
 */
static uint32_t virHashTableSeed;

static int virHashTableSeedOnceInit(void)
{
    virHashTableSeed = virRandomBits(32);
    return 0;
}

VIR_ONCE_GLOBAL_INIT(virHashTableSeed);


static unsigned int
virHashTableStringKey(const void *vkey)
{
    const char *key = vkey;

    return virHashCodeGen(key, strlen(key), virHashTableSeed);
}


/**
 * virHashNew:
 * @dataFree: callback to free data
 *
 * Create a new virHashTablePtr.
 *
 * Returns the newly created object.
 */
virHashTablePtr
virHashNew(virHashDataFree dataFree)
{
    ignore_value(virHashTableSeedInitialize());

    return g_hash_table_new_full(virHashTableStringKey, g_str_equal, g_free, dataFree);
}


virHashAtomicPtr
virHashAtomicNew(virHashDataFree dataFree)
{
    virHashAtomicPtr hash;

    if (virHashAtomicInitialize() < 0)
        return NULL;

    if (!(hash = virObjectLockableNew(virHashAtomicClass)))
        return NULL;

    if (!(hash->hash = virHashNew(dataFree))) {
        virObjectUnref(hash);
        return NULL;
    }
    return hash;
}


static void
virHashAtomicDispose(void *obj)
{
    virHashAtomicPtr hash = obj;

    virHashFree(hash->hash);
}


/**
 * virHashFree:
 * @table: the hash table
 *
 * Free the hash @table and its contents. The userdata is
 * deallocated with function provided at creation time.
 */
void
virHashFree(virHashTablePtr table)
{
    if (table == NULL)
        return;

    g_hash_table_unref(table);
}


/**
 * virHashAddEntry:
 * @table: the hash table
 * @name: the name of the userdata
 * @userdata: a pointer to the userdata
 *
 * Add the @userdata to the hash @table. This can later be retrieved
 * by using @name. Duplicate entries generate errors.
 *
 * Returns 0 the addition succeeded and -1 in case of error.
 */
int
virHashAddEntry(virHashTablePtr table, const char *name, void *userdata)
{
    if (!table || !name)
        return -1;

    if (g_hash_table_contains(table, name)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Duplicate hash table key '%s'"), name);
        return -1;
    }

    g_hash_table_insert(table, g_strdup(name), userdata);

    return 0;
}

/**
 * virHashUpdateEntry:
 * @table: the hash table
 * @name: the name of the userdata
 * @userdata: a pointer to the userdata
 *
 * Add the @userdata to the hash @table. This can later be retrieved
 * by using @name. Existing entry for this tuple
 * will be removed and freed with @f if found.
 *
 * Returns 0 the addition succeeded and -1 in case of error.
 */
int
virHashUpdateEntry(virHashTablePtr table, const char *name,
                   void *userdata)
{
    if (!table || !name)
        return -1;

    g_hash_table_insert(table, g_strdup(name), userdata);

    return 0;
}

int
virHashAtomicUpdate(virHashAtomicPtr table,
                    const char *name,
                    void *userdata)
{
    int ret;

    virObjectLock(table);
    ret = virHashUpdateEntry(table->hash, name, userdata);
    virObjectUnlock(table);

    return ret;
}


/**
 * virHashLookup:
 * @table: the hash table
 * @name: the name of the userdata
 *
 * Find the userdata specified by @name
 *
 * Returns a pointer to the userdata
 */
void *
virHashLookup(virHashTablePtr table,
              const char *name)
{
    if (!table || !name)
        return NULL;

    return g_hash_table_lookup(table, name);
}


/**
 * virHashHasEntry:
 * @table: the hash table
 * @name: the name of the userdata
 *
 * Find whether entry specified by @name exists.
 *
 * Returns true if the entry exists and false otherwise
 */
bool
virHashHasEntry(virHashTablePtr table,
                const char *name)
{
    if (!table || !name)
        return false;

    return g_hash_table_contains(table, name);
}


/**
 * virHashSteal:
 * @table: the hash table
 * @name: the name of the userdata
 *
 * Find the userdata specified by @name
 * and remove it from the hash without freeing it.
 *
 * Returns a pointer to the userdata
 */
void *virHashSteal(virHashTablePtr table, const char *name)
{
    g_autofree void *orig_name = NULL;
    void *val = NULL;

    if (!table || !name)
        return NULL;

    /* we can replace this by g_hash_table_steal_extended with glib 2.58 */
    if (!(g_hash_table_lookup_extended(table, name, &orig_name, &val)))
        return NULL;

    g_hash_table_steal(table, name);

    return val;
}

void *
virHashAtomicSteal(virHashAtomicPtr table,
                   const char *name)
{
    void *data;

    virObjectLock(table);
    data = virHashSteal(table->hash, name);
    virObjectUnlock(table);

    return data;
}


/**
 * virHashSize:
 * @table: the hash table
 *
 * Query the number of elements installed in the hash @table.
 *
 * Returns the number of elements in the hash table or
 * -1 in case of error
 */
ssize_t
virHashSize(virHashTablePtr table)
{
    if (table == NULL)
        return -1;

    return g_hash_table_size(table);
}


/**
 * virHashRemoveEntry:
 * @table: the hash table
 * @name: the name of the userdata
 *
 * Find the userdata specified by the @name and remove
 * it from the hash @table. Existing userdata for this tuple will be removed
 * and freed with @f.
 *
 * Returns 0 if the removal succeeded and -1 in case of error or not found.
 */
int
virHashRemoveEntry(virHashTablePtr table,
                   const char *name)
{
    if (!table || !name)
        return -1;

    if (g_hash_table_remove(table, name))
        return 0;

    return -1;
}


/**
 * virHashForEach, virHashForEachSorted, virHashForEachSafe
 * @table: the hash table to process
 * @iter: callback to process each element
 * @opaque: opaque data to pass to the iterator
 *
 * Iterates over every element in the hash table, invoking the 'iter' callback.
 *
 * The elements are iterated in arbitrary order.
 *
 * virHashForEach prohibits @iter from modifying @table
 *
 * virHashForEachSafe allows the callback to remove the current
 * element using virHashRemoveEntry but calling other virHash* functions is
 * prohibited. Note that removing the entry invalidates @key and @payload in
 * the callback.
 *
 * virHashForEachSorted iterates the elements in order by sorted key.
 *
 * virHashForEachSorted and virHashForEachSafe are more computationally
 * expensive than virHashForEach.
 *
 * If @iter fails and returns a negative value, the evaluation is stopped and -1
 * is returned.
 *
 * Returns 0 on success or -1 on failure.
 */
int
virHashForEach(virHashTablePtr table, virHashIterator iter, void *opaque)
{
    GHashTableIter htitr;
    void *key;
    void *value;

    if (!table || !iter)
        return -1;

    g_hash_table_iter_init(&htitr, table);

    while (g_hash_table_iter_next(&htitr, &key, &value)) {
        if (iter(value, key, opaque) < 0)
            return -1;
    }

    return 0;
}


int
virHashForEachSafe(virHashTablePtr table,
                   virHashIterator iter,
                   void *opaque)
{
    g_autofree virHashKeyValuePairPtr items = virHashGetItems(table, NULL, false);
    size_t i;

    if (!items)
        return -1;

    for (i = 0; items[i].key; i++) {
        if (iter((void *)items[i].value, items[i].key, opaque) < 0)
            return -1;
    }

    return 0;
}


int
virHashForEachSorted(virHashTablePtr table,
                     virHashIterator iter,
                     void *opaque)
{
    g_autofree virHashKeyValuePairPtr items = virHashGetItems(table, NULL, true);
    size_t i;

    if (!items)
        return -1;

    for (i = 0; items[i].key; i++) {
        if (iter((void *)items[i].value, items[i].key, opaque) < 0)
            return -1;
    }

    return 0;
}


struct virHashSearcherWrapFuncData {
    virHashSearcher iter;
    const void *opaque;
    const char *name;
};

static gboolean
virHashSearcherWrapFunc(gpointer key,
                        gpointer value,
                        gpointer opaque)
{
    struct virHashSearcherWrapFuncData *data = opaque;

    data->name = key;

    return !!(data->iter(value, key, data->opaque));
}

/**
 * virHashRemoveSet
 * @table: the hash table to process
 * @iter: callback to identify elements for removal
 * @opaque: opaque data to pass to the iterator
 *
 * Iterates over all elements in the hash table, invoking the 'iter'
 * callback. If the callback returns a non-zero value, the element
 * will be removed from the hash table & its payload passed to the
 * data freer callback registered at creation.
 *
 * Returns number of items removed on success, -1 on failure
 */
ssize_t
virHashRemoveSet(virHashTablePtr table,
                 virHashSearcher iter,
                 const void *opaque)
{
    struct virHashSearcherWrapFuncData data = { iter, opaque, NULL };

    if (table == NULL || iter == NULL)
        return -1;

    return g_hash_table_foreach_remove(table, virHashSearcherWrapFunc, &data);
}

/**
 * virHashRemoveAll
 * @table: the hash table to clear
 *
 * Free the hash @table's contents. The userdata is
 * deallocated with the function provided at creation time.
 */
void
virHashRemoveAll(virHashTablePtr table)
{
    if (!table)
        return;

    g_hash_table_remove_all(table);
}

/**
 * virHashSearch:
 * @table: the hash table to search
 * @iter: an iterator to identify the desired element
 * @opaque: extra opaque information passed to the iter
 * @name: the name of found user data, pass NULL to ignore
 *
 * Iterates over the hash table calling the 'iter' callback
 * for each element. The first element for which the iter
 * returns non-zero will be returned by this function.
 * The elements are processed in a undefined order. Caller is
 * responsible for freeing the @name.
 */
void *virHashSearch(virHashTablePtr table,
                    virHashSearcher iter,
                    const void *opaque,
                    char **name)
{
    struct virHashSearcherWrapFuncData data = { iter, opaque, NULL };
    void *ret;

    if (!table || !iter)
        return NULL;

    if (!(ret = g_hash_table_find(table, virHashSearcherWrapFunc, &data)))
        return NULL;

    if (name)
        *name = g_strdup(data.name);

    return ret;
}


static int
virHashGetItemsKeySorter(const void *va,
                         const void *vb)
{
    const virHashKeyValuePair *a = va;
    const virHashKeyValuePair *b = vb;

    return strcmp(a->key, b->key);
}


virHashKeyValuePairPtr
virHashGetItems(virHashTablePtr table,
                size_t *nitems,
                bool sortKeys)
{
    virHashKeyValuePair *items;
    size_t dummy;
    GHashTableIter htitr;
    void *key;
    void *value;
    size_t i = 0;

    if (!nitems)
        nitems = &dummy;

    if (!table)
        return NULL;

    *nitems = g_hash_table_size(table);
    items = g_new0(virHashKeyValuePair, *nitems + 1);

    g_hash_table_iter_init(&htitr, table);

    while (g_hash_table_iter_next(&htitr, &key, &value)) {
        items[i].key = key;
        items[i].value = value;
        i++;
    }

    if (sortKeys)
        qsort(items, *nitems, sizeof(*items), virHashGetItemsKeySorter);

    return items;
}


struct virHashEqualData
{
    bool equal;
    virHashTablePtr table2;
    virHashValueComparator compar;
};

static int virHashEqualSearcher(const void *payload, const char *name,
                                const void *opaque)
{
    struct virHashEqualData *vhed = (void *)opaque;
    const void *value;

    value = virHashLookup(vhed->table2, name);
    if (!value ||
        vhed->compar(value, payload) != 0) {
        /* key is missing in 2nd table or values are different */
        vhed->equal = false;
        /* stop 'iteration' */
        return 1;
    }
    return 0;
}

bool virHashEqual(virHashTablePtr table1,
                  virHashTablePtr table2,
                  virHashValueComparator compar)
{
    struct virHashEqualData data = {
        .equal = true,
        .table2 = table2,
        .compar = compar,
    };

    if (table1 == table2)
        return true;

    if (!table1 || !table2 ||
        virHashSize(table1) != virHashSize(table2))
        return false;

    virHashSearch(table1, virHashEqualSearcher, &data, NULL);

    return data.equal;
}
