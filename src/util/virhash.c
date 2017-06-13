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
 * MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE AUTHORS AND
 * CONTRIBUTORS ACCEPT NO RESPONSIBILITY IN ANY CONCEIVABLE MANNER.
 *
 * Author: Bjorn Reese <bjorn.reese@systematic.dk>
 *         Daniel Veillard <veillard@redhat.com>
 */

#include <config.h>

#include <string.h>
#include <stdlib.h>

#include "virerror.h"
#include "virhash.h"
#include "viralloc.h"
#include "virlog.h"
#include "virhashcode.h"
#include "virrandom.h"
#include "virstring.h"
#include "virobject.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.hash");

#define MAX_HASH_LEN 8

/* #define DEBUG_GROW */

#define virHashIterationError(ret)                                      \
    do {                                                                \
        VIR_ERROR(_("Hash operation not allowed during iteration"));   \
        return ret;                                                     \
    } while (0)

/*
 * A single entry in the hash table
 */
typedef struct _virHashEntry virHashEntry;
typedef virHashEntry *virHashEntryPtr;
struct _virHashEntry {
    struct _virHashEntry *next;
    void *name;
    void *payload;
};

/*
 * The entire hash table
 */
struct _virHashTable {
    virHashEntryPtr *table;
    uint32_t seed;
    size_t size;
    size_t nbElems;
    /* True iff we are iterating over hash entries. */
    bool iterating;
    /* Pointer to the current entry during iteration. */
    virHashEntryPtr current;
    virHashDataFree dataFree;
    virHashKeyCode keyCode;
    virHashKeyEqual keyEqual;
    virHashKeyCopy keyCopy;
    virHashKeyFree keyFree;
};

struct _virHashAtomic {
    virObjectLockable parent;
    virHashTablePtr hash;
};

static virClassPtr virHashAtomicClass;
static void virHashAtomicDispose(void *obj);

static int virHashAtomicOnceInit(void)
{
    virHashAtomicClass = virClassNew(virClassForObjectLockable(),
                                     "virHashAtomic",
                                     sizeof(virHashAtomic),
                                     virHashAtomicDispose);
    if (!virHashAtomicClass)
        return -1;
    else
        return 0;
}
VIR_ONCE_GLOBAL_INIT(virHashAtomic)


static uint32_t virHashStrCode(const void *name, uint32_t seed)
{
    return virHashCodeGen(name, strlen(name), seed);
}

static bool virHashStrEqual(const void *namea, const void *nameb)
{
    return STREQ(namea, nameb);
}

static void *virHashStrCopy(const void *name)
{
    char *ret;
    ignore_value(VIR_STRDUP(ret, name));
    return ret;
}

static void virHashStrFree(void *name)
{
    VIR_FREE(name);
}


void
virHashValueFree(void *value, const void *name ATTRIBUTE_UNUSED)
{
    VIR_FREE(value);
}


static size_t
virHashComputeKey(const virHashTable *table, const void *name)
{
    uint32_t value = table->keyCode(name, table->seed);
    return value % table->size;
}

/**
 * virHashCreateFull:
 * @size: the size of the hash table
 * @dataFree: callback to free data
 * @keyCode: callback to compute hash code
 * @keyEqual: callback to compare hash keys
 * @keyCopy: callback to copy hash keys
 * @keyFree: callback to free keys
 *
 * Create a new virHashTablePtr.
 *
 * Returns the newly created object, or NULL if an error occurred.
 */
virHashTablePtr virHashCreateFull(ssize_t size,
                                  virHashDataFree dataFree,
                                  virHashKeyCode keyCode,
                                  virHashKeyEqual keyEqual,
                                  virHashKeyCopy keyCopy,
                                  virHashKeyFree keyFree)
{
    virHashTablePtr table = NULL;

    if (size <= 0)
        size = 256;

    if (VIR_ALLOC(table) < 0)
        return NULL;

    table->seed = virRandomBits(32);
    table->size = size;
    table->nbElems = 0;
    table->dataFree = dataFree;
    table->keyCode = keyCode;
    table->keyEqual = keyEqual;
    table->keyCopy = keyCopy;
    table->keyFree = keyFree;

    if (VIR_ALLOC_N(table->table, size) < 0) {
        VIR_FREE(table);
        return NULL;
    }

    return table;
}


/**
 * virHashCreate:
 * @size: the size of the hash table
 * @dataFree: callback to free data
 *
 * Create a new virHashTablePtr.
 *
 * Returns the newly created object, or NULL if an error occurred.
 */
virHashTablePtr virHashCreate(ssize_t size, virHashDataFree dataFree)
{
    return virHashCreateFull(size,
                             dataFree,
                             virHashStrCode,
                             virHashStrEqual,
                             virHashStrCopy,
                             virHashStrFree);
}


virHashAtomicPtr
virHashAtomicNew(ssize_t size,
                 virHashDataFree dataFree)
{
    virHashAtomicPtr hash;

    if (virHashAtomicInitialize() < 0)
        return NULL;

    if (!(hash = virObjectLockableNew(virHashAtomicClass)))
        return NULL;

    if (!(hash->hash = virHashCreate(size, dataFree))) {
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
 * virHashGrow:
 * @table: the hash table
 * @size: the new size of the hash table
 *
 * resize the hash table
 *
 * Returns 0 in case of success, -1 in case of failure
 */
static int
virHashGrow(virHashTablePtr table, size_t size)
{
    size_t oldsize, i;
    virHashEntryPtr *oldtable;

#ifdef DEBUG_GROW
    size_t nbElem = 0;
#endif

    if (table == NULL)
        return -1;
    if (size < 8)
        return -1;
    if (size > 8 * 2048)
        return -1;

    oldsize = table->size;
    oldtable = table->table;
    if (oldtable == NULL)
        return -1;

    if (VIR_ALLOC_N(table->table, size) < 0) {
        table->table = oldtable;
        return -1;
    }
    table->size = size;

    for (i = 0; i < oldsize; i++) {
        virHashEntryPtr iter = oldtable[i];
        while (iter) {
            virHashEntryPtr next = iter->next;
            size_t key = virHashComputeKey(table, iter->name);

            iter->next = table->table[key];
            table->table[key] = iter;

#ifdef DEBUG_GROW
            nbElem++;
#endif
            iter = next;
        }
    }

    VIR_FREE(oldtable);

#ifdef DEBUG_GROW
    VIR_DEBUG("virHashGrow : from %d to %d, %ld elems", oldsize,
              size, nbElem);
#endif

    return 0;
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
    size_t i;

    if (table == NULL)
        return;

    for (i = 0; i < table->size; i++) {
        virHashEntryPtr iter = table->table[i];
        while (iter) {
            virHashEntryPtr next = iter->next;

            if (table->dataFree)
                table->dataFree(iter->payload, iter->name);
            if (table->keyFree)
                table->keyFree(iter->name);
            VIR_FREE(iter);
            iter = next;
        }
    }

    VIR_FREE(table->table);
    VIR_FREE(table);
}

static int
virHashAddOrUpdateEntry(virHashTablePtr table, const void *name,
                        void *userdata,
                        bool is_update)
{
    size_t key, len = 0;
    virHashEntryPtr entry;
    void *new_name;

    if ((table == NULL) || (name == NULL))
        return -1;

    if (table->iterating)
        virHashIterationError(-1);

    key = virHashComputeKey(table, name);

    /* Check for duplicate entry */
    for (entry = table->table[key]; entry; entry = entry->next) {
        if (table->keyEqual(entry->name, name)) {
            if (is_update) {
                if (table->dataFree)
                    table->dataFree(entry->payload, entry->name);
                entry->payload = userdata;
                return 0;
            } else {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Duplicate key"));
                return -1;
            }
        }
        len++;
    }

    if (VIR_ALLOC(entry) < 0 || !(new_name = table->keyCopy(name))) {
        VIR_FREE(entry);
        return -1;
    }

    entry->name = new_name;
    entry->payload = userdata;
    entry->next = table->table[key];
    table->table[key] = entry;

    table->nbElems++;

    if (len > MAX_HASH_LEN)
        virHashGrow(table, MAX_HASH_LEN * table->size);

    return 0;
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
virHashAddEntry(virHashTablePtr table, const void *name, void *userdata)
{
    return virHashAddOrUpdateEntry(table, name, userdata, false);
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
virHashUpdateEntry(virHashTablePtr table, const void *name,
                   void *userdata)
{
    return virHashAddOrUpdateEntry(table, name, userdata, true);
}

int
virHashAtomicUpdate(virHashAtomicPtr table,
                    const void *name,
                    void *userdata)
{
    int ret;

    virObjectLock(table);
    ret = virHashAddOrUpdateEntry(table->hash, name, userdata, true);
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
virHashLookup(const virHashTable *table, const void *name)
{
    size_t key;
    virHashEntryPtr entry;

    if (!table || !name)
        return NULL;

    key = virHashComputeKey(table, name);
    for (entry = table->table[key]; entry; entry = entry->next) {
        if (table->keyEqual(entry->name, name))
            return entry->payload;
    }
    return NULL;
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
void *virHashSteal(virHashTablePtr table, const void *name)
{
    void *data = virHashLookup(table, name);
    if (data) {
        virHashDataFree dataFree = table->dataFree;
        table->dataFree = NULL;
        virHashRemoveEntry(table, name);
        table->dataFree = dataFree;
    }
    return data;
}

void *
virHashAtomicSteal(virHashAtomicPtr table,
                   const void *name)
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
virHashSize(const virHashTable *table)
{
    if (table == NULL)
        return -1;
    return table->nbElems;
}

/**
 * virHashTableSize:
 * @table: the hash table
 *
 * Query the size of the hash @table, i.e., number of buckets in the table.
 *
 * Returns the number of keys in the hash table or
 * -1 in case of error
 */
ssize_t
virHashTableSize(const virHashTable *table)
{
    if (table == NULL)
        return -1;
    return table->size;
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
virHashRemoveEntry(virHashTablePtr table, const void *name)
{
    virHashEntryPtr entry;
    virHashEntryPtr *nextptr;

    if (table == NULL || name == NULL)
        return -1;

    nextptr = table->table + virHashComputeKey(table, name);
    for (entry = *nextptr; entry; entry = entry->next) {
        if (table->keyEqual(entry->name, name)) {
            if (table->iterating && table->current != entry)
                virHashIterationError(-1);

            if (table->dataFree)
                table->dataFree(entry->payload, entry->name);
            if (table->keyFree)
                table->keyFree(entry->name);
            *nextptr = entry->next;
            VIR_FREE(entry);
            table->nbElems--;
            return 0;
        }
        nextptr = &entry->next;
    }

    return -1;
}


/**
 * virHashForEach
 * @table: the hash table to process
 * @iter: callback to process each element
 * @data: opaque data to pass to the iterator
 *
 * Iterates over every element in the hash table, invoking the
 * 'iter' callback. The callback is allowed to remove the current element
 * using virHashRemoveEntry but calling other virHash* functions is prohibited.
 * If @iter fails and returns a negative value, the evaluation is stopped and -1
 * is returned.
 *
 * Returns 0 on success or -1 on failure.
 */
int
virHashForEach(virHashTablePtr table, virHashIterator iter, void *data)
{
    size_t i;
    int ret = -1;

    if (table == NULL || iter == NULL)
        return -1;

    if (table->iterating)
        virHashIterationError(-1);

    table->iterating = true;
    table->current = NULL;
    for (i = 0; i < table->size; i++) {
        virHashEntryPtr entry = table->table[i];
        while (entry) {
            virHashEntryPtr next = entry->next;
            table->current = entry;
            ret = iter(entry->payload, entry->name, data);
            table->current = NULL;

            if (ret < 0)
                goto cleanup;

            entry = next;
        }
    }

    ret = 0;
 cleanup:
    table->iterating = false;
    return ret;
}


/**
 * virHashRemoveSet
 * @table: the hash table to process
 * @iter: callback to identify elements for removal
 * @data: opaque data to pass to the iterator
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
                 const void *data)
{
    size_t i, count = 0;

    if (table == NULL || iter == NULL)
        return -1;

    if (table->iterating)
        virHashIterationError(-1);

    table->iterating = true;
    table->current = NULL;
    for (i = 0; i < table->size; i++) {
        virHashEntryPtr *nextptr = table->table + i;

        while (*nextptr) {
            virHashEntryPtr entry = *nextptr;
            if (!iter(entry->payload, entry->name, data)) {
                nextptr = &entry->next;
            } else {
                count++;
                if (table->dataFree)
                    table->dataFree(entry->payload, entry->name);
                if (table->keyFree)
                    table->keyFree(entry->name);
                *nextptr = entry->next;
                VIR_FREE(entry);
                table->nbElems--;
            }
        }
    }
    table->iterating = false;

    return count;
}

static int
_virHashRemoveAllIter(const void *payload ATTRIBUTE_UNUSED,
                      const void *name ATTRIBUTE_UNUSED,
                      const void *data ATTRIBUTE_UNUSED)
{
    return 1;
}

/**
 * virHashRemoveAll
 * @table: the hash table to clear
 *
 * Free the hash @table's contents. The userdata is
 * deallocated with the function provided at creation time.
 *
 * Returns the number of items removed on success, -1 on failure
 */
ssize_t
virHashRemoveAll(virHashTablePtr table)
{
    return virHashRemoveSet(table,
                            _virHashRemoveAllIter,
                            NULL);
}

/**
 * virHashSearch:
 * @table: the hash table to search
 * @iter: an iterator to identify the desired element
 * @data: extra opaque information passed to the iter
 * @name: the name of found user data, pass NULL to ignore
 *
 * Iterates over the hash table calling the 'iter' callback
 * for each element. The first element for which the iter
 * returns non-zero will be returned by this function.
 * The elements are processed in a undefined order. Caller is
 * responsible for freeing the @name.
 */
void *virHashSearch(const virHashTable *ctable,
                    virHashSearcher iter,
                    const void *data,
                    void **name)
{
    size_t i;

    /* Cast away const for internal detection of misuse.  */
    virHashTablePtr table = (virHashTablePtr)ctable;

    if (table == NULL || iter == NULL)
        return NULL;

    if (table->iterating)
        virHashIterationError(NULL);

    table->iterating = true;
    table->current = NULL;
    for (i = 0; i < table->size; i++) {
        virHashEntryPtr entry;
        for (entry = table->table[i]; entry; entry = entry->next) {
            if (iter(entry->payload, entry->name, data)) {
                table->iterating = false;
                if (name)
                    *name = table->keyCopy(entry->name);
                return entry->payload;
            }
        }
    }
    table->iterating = false;

    return NULL;
}

struct getKeysIter
{
    virHashKeyValuePair *sortArray;
    size_t arrayIdx;
};

static int virHashGetKeysIterator(void *payload,
                                  const void *key, void *data)
{
    struct getKeysIter *iter = data;

    iter->sortArray[iter->arrayIdx].key = key;
    iter->sortArray[iter->arrayIdx].value = payload;

    iter->arrayIdx++;
    return 0;
}

typedef int (*qsort_comp)(const void *, const void *);

virHashKeyValuePairPtr virHashGetItems(virHashTablePtr table,
                                       virHashKeyComparator compar)
{
    ssize_t numElems = virHashSize(table);
    struct getKeysIter iter = {
        .arrayIdx = 0,
        .sortArray = NULL,
    };

    if (numElems < 0)
        return NULL;

    if (VIR_ALLOC_N(iter.sortArray, numElems + 1))
        return NULL;

    virHashForEach(table, virHashGetKeysIterator, &iter);

    if (compar)
        qsort(&iter.sortArray[0], numElems, sizeof(iter.sortArray[0]),
              (qsort_comp)compar);

    return iter.sortArray;
}

struct virHashEqualData
{
    bool equal;
    const virHashTable *table2;
    virHashValueComparator compar;
};

static int virHashEqualSearcher(const void *payload, const void *name,
                                const void *data)
{
    struct virHashEqualData *vhed = (void *)data;
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

bool virHashEqual(const virHashTable *table1,
                  const virHashTable *table2,
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
