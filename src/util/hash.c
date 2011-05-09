/*
 * hash.c: chained hash tables for domain and domain/connection deallocations
 *
 * Reference: Your favorite introductory book on algorithms
 *
 * Copyright (C) 2011 Red Hat, Inc.
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
 * Author: breese@users.sourceforge.net
 *         Daniel Veillard <veillard@redhat.com>
 */

#include <config.h>

#include <string.h>
#include <stdlib.h>

#include "virterror_internal.h"
#include "hash.h"
#include "memory.h"
#include "logging.h"

#define VIR_FROM_THIS VIR_FROM_NONE

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
    int size;
    int nbElems;
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

static unsigned long virHashStrCode(const void *name)
{
    const char *str = name;
    unsigned long value = 0L;
    char ch;

    if (str != NULL) {
        value += 30 * (*str);
        while ((ch = *str++) != 0) {
            value =
                value ^ ((value << 5) + (value >> 3) + (unsigned long) ch);
        }
    }
    return value;
}

static bool virHashStrEqual(const void *namea, const void *nameb)
{
    return STREQ(namea, nameb);
}

static void *virHashStrCopy(const void *name)
{
    return strdup(name);
}

static void virHashStrFree(void *name)
{
    VIR_FREE(name);
}


static unsigned long
virHashComputeKey(virHashTablePtr table, const void *name)
{
    unsigned long value = table->keyCode(name);
    return (value % table->size);
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
 * Returns the newly created object, or NULL if an error occured.
 */
virHashTablePtr virHashCreateFull(int size,
                                  virHashDataFree dataFree,
                                  virHashKeyCode keyCode,
                                  virHashKeyEqual keyEqual,
                                  virHashKeyCopy keyCopy,
                                  virHashKeyFree keyFree)
{
    virHashTablePtr table = NULL;

    if (size <= 0)
        size = 256;

    if (VIR_ALLOC(table) < 0) {
        virReportOOMError();
        return NULL;
    }

    table->size = size;
    table->nbElems = 0;
    table->dataFree = dataFree;
    table->keyCode = keyCode;
    table->keyEqual = keyEqual;
    table->keyCopy = keyCopy;
    table->keyFree = keyFree;

    if (VIR_ALLOC_N(table->table, size) < 0) {
        virReportOOMError();
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
virHashTablePtr virHashCreate(int size, virHashDataFree dataFree)
{
    return virHashCreateFull(size,
                             dataFree,
                             virHashStrCode,
                             virHashStrEqual,
                             virHashStrCopy,
                             virHashStrFree);
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
virHashGrow(virHashTablePtr table, int size)
{
    int oldsize, i;
    virHashEntryPtr *oldtable;

#ifdef DEBUG_GROW
    unsigned long nbElem = 0;
#endif

    if (table == NULL)
        return (-1);
    if (size < 8)
        return (-1);
    if (size > 8 * 2048)
        return (-1);

    oldsize = table->size;
    oldtable = table->table;
    if (oldtable == NULL)
        return (-1);

    if (VIR_ALLOC_N(table->table, size) < 0) {
        virReportOOMError();
        table->table = oldtable;
        return (-1);
    }
    table->size = size;

    for (i = 0; i < oldsize; i++) {
        virHashEntryPtr iter = oldtable[i];
        while (iter) {
            virHashEntryPtr next = iter->next;
            unsigned long key = virHashComputeKey(table, iter->name);

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
    VIR_DEBUG("virHashGrow : from %d to %d, %ld elems\n", oldsize,
              size, nbElem);
#endif

    return (0);
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
    int i;

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
    unsigned long key, len = 0;
    virHashEntryPtr entry;
    char *new_name;

    if ((table == NULL) || (name == NULL))
        return (-1);

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
                return -1;
            }
        }
        len++;
    }

    if (VIR_ALLOC(entry) < 0 || !(new_name = table->keyCopy(name))) {
        virReportOOMError();
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

/**
 * virHashLookup:
 * @table: the hash table
 * @name: the name of the userdata
 *
 * Find the userdata specified by @name
 *
 * Returns the a pointer to the userdata
 */
void *
virHashLookup(virHashTablePtr table, const void *name)
{
    unsigned long key;
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
 * Returns the a pointer to the userdata
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


/**
 * virHashSize:
 * @table: the hash table
 *
 * Query the number of elements installed in the hash @table.
 *
 * Returns the number of elements in the hash table or
 * -1 in case of error
 */
int
virHashSize(virHashTablePtr table)
{
    if (table == NULL)
        return (-1);
    return (table->nbElems);
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
int
virHashTableSize(virHashTablePtr table)
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
        return (-1);

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
 *
 * Returns number of items iterated over upon completion, -1 on failure
 */
int virHashForEach(virHashTablePtr table, virHashIterator iter, void *data)
{
    int i, count = 0;

    if (table == NULL || iter == NULL)
        return (-1);

    if (table->iterating)
        virHashIterationError(-1);

    table->iterating = true;
    table->current = NULL;
    for (i = 0 ; i < table->size ; i++) {
        virHashEntryPtr entry = table->table[i];
        while (entry) {
            virHashEntryPtr next = entry->next;

            table->current = entry;
            iter(entry->payload, entry->name, data);
            table->current = NULL;

            count++;
            entry = next;
        }
    }
    table->iterating = false;

    return (count);
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
int virHashRemoveSet(virHashTablePtr table,
                     virHashSearcher iter,
                     const void *data)
{
    int i, count = 0;

    if (table == NULL || iter == NULL)
        return (-1);

    if (table->iterating)
        virHashIterationError(-1);

    table->iterating = true;
    table->current = NULL;
    for (i = 0 ; i < table->size ; i++) {
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

/**
 * virHashSearch:
 * @table: the hash table to search
 * @iter: an iterator to identify the desired element
 * @data: extra opaque information passed to the iter
 *
 * Iterates over the hash table calling the 'iter' callback
 * for each element. The first element for which the iter
 * returns non-zero will be returned by this function.
 * The elements are processed in a undefined order
 */
void *virHashSearch(virHashTablePtr table,
                    virHashSearcher iter,
                    const void *data)
{
    int i;

    if (table == NULL || iter == NULL)
        return (NULL);

    if (table->iterating)
        virHashIterationError(NULL);

    table->iterating = true;
    table->current = NULL;
    for (i = 0 ; i < table->size ; i++) {
        virHashEntryPtr entry;
        for (entry = table->table[i]; entry; entry = entry->next) {
            if (iter(entry->payload, entry->name, data)) {
                table->iterating = false;
                return entry->payload;
            }
        }
    }
    table->iterating = false;

    return NULL;
}
