/*
 * hash.c: chained hash tables for domain and domain/connection deallocations
 *
 * Reference: Your favorite introductory book on algorithms
 *
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

#define MAX_HASH_LEN 8

/* #define DEBUG_GROW */

/*
 * A single entry in the hash table
 */
typedef struct _virHashEntry virHashEntry;
typedef virHashEntry *virHashEntryPtr;
struct _virHashEntry {
    struct _virHashEntry *next;
    char *name;
    void *payload;
    int valid;
};

/*
 * The entire hash table
 */
struct _virHashTable {
    struct _virHashEntry *table;
    int size;
    int nbElems;
};

/*
 * virHashComputeKey:
 * Calculate the hash key
 */
static unsigned long
virHashComputeKey(virHashTablePtr table, const char *name)
{
    unsigned long value = 0L;
    char ch;

    if (name != NULL) {
        value += 30 * (*name);
        while ((ch = *name++) != 0) {
            value =
                value ^ ((value << 5) + (value >> 3) + (unsigned long) ch);
        }
    }
    return (value % table->size);
}

/**
 * virHashCreate:
 * @size: the size of the hash table
 *
 * Create a new virHashTablePtr.
 *
 * Returns the newly created object, or NULL if an error occured.
 */
virHashTablePtr
virHashCreate(int size)
{
    virHashTablePtr table = NULL;

    if (size <= 0)
        size = 256;

    if (VIR_ALLOC(table) < 0)
        return NULL;

    table->size = size;
    table->nbElems = 0;
    if (VIR_ALLOC_N(table->table, size) < 0) {
        VIR_FREE(table);
        return NULL;
    }

    return table;
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
    unsigned long key;
    int oldsize, i;
    virHashEntryPtr iter, next;
    struct _virHashEntry *oldtable;

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
        table->table = oldtable;
        return (-1);
    }
    table->size = size;

    /* If the two loops are merged, there would be situations where
     * a new entry needs to allocated and data copied into it from
     * the main table. So instead, we run through the array twice, first
     * copying all the elements in the main array (where we can't get
     * conflicts) and then the rest, so we only free (and don't allocate)
     */
    for (i = 0; i < oldsize; i++) {
        if (oldtable[i].valid == 0)
            continue;
        key = virHashComputeKey(table, oldtable[i].name);
        memcpy(&(table->table[key]), &(oldtable[i]), sizeof(virHashEntry));
        table->table[key].next = NULL;
    }

    for (i = 0; i < oldsize; i++) {
        iter = oldtable[i].next;
        while (iter) {
            next = iter->next;

            /*
             * put back the entry in the new table
             */

            key = virHashComputeKey(table, iter->name);
            if (table->table[key].valid == 0) {
                memcpy(&(table->table[key]), iter, sizeof(virHashEntry));
                table->table[key].next = NULL;
                VIR_FREE(iter);
            } else {
                iter->next = table->table[key].next;
                table->table[key].next = iter;
            }

#ifdef DEBUG_GROW
            nbElem++;
#endif

            iter = next;
        }
    }

    VIR_FREE(oldtable);

#ifdef DEBUG_GROW
    xmlGenericError(xmlGenericErrorContext,
                    "virHashGrow : from %d to %d, %d elems\n", oldsize,
                    size, nbElem);
#endif

    return (0);
}

/**
 * virHashFree:
 * @table: the hash table
 * @f:  the deallocator function for items in the hash
 *
 * Free the hash @table and its contents. The userdata is
 * deallocated with @f if provided.
 */
void
virHashFree(virHashTablePtr table, virHashDeallocator f)
{
    int i;
    virHashEntryPtr iter;
    virHashEntryPtr next;
    int inside_table = 0;
    int nbElems;

    if (table == NULL)
        return;
    if (table->table) {
        nbElems = table->nbElems;
        for (i = 0; (i < table->size) && (nbElems > 0); i++) {
            iter = &(table->table[i]);
            if (iter->valid == 0)
                continue;
            inside_table = 1;
            while (iter) {
                next = iter->next;
                if ((f != NULL) && (iter->payload != NULL))
                    f(iter->payload, iter->name);
                VIR_FREE(iter->name);
                iter->payload = NULL;
                if (!inside_table)
                    VIR_FREE(iter);
                nbElems--;
                inside_table = 0;
                iter = next;
            }
        }
        VIR_FREE(table->table);
    }
    VIR_FREE(table);
}

/**
 * virHashAddEntry3:
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
    unsigned long key, len = 0;
    virHashEntryPtr entry;
    virHashEntryPtr insert;

    if ((table == NULL) || (name == NULL))
        return (-1);

    /*
     * Check for duplicate and insertion location.
     */
    key = virHashComputeKey(table, name);
    if (table->table[key].valid == 0) {
        insert = NULL;
    } else {
        for (insert = &(table->table[key]); insert->next != NULL;
             insert = insert->next) {
            if (STREQ(insert->name, name))
                return (-1);
            len++;
        }
        if (STREQ(insert->name, name))
            return (-1);
    }

    if (insert == NULL) {
        entry = &(table->table[key]);
    } else {
        if (VIR_ALLOC(entry) < 0)
            return (-1);
    }

    entry->name = strdup(name);
    entry->payload = userdata;
    entry->next = NULL;
    entry->valid = 1;


    if (insert != NULL)
        insert->next = entry;

    table->nbElems++;

    if (len > MAX_HASH_LEN)
        virHashGrow(table, MAX_HASH_LEN * table->size);

    return (0);
}

/**
 * virHashUpdateEntry:
 * @table: the hash table
 * @name: the name of the userdata
 * @userdata: a pointer to the userdata
 * @f: the deallocator function for replaced item (if any)
 *
 * Add the @userdata to the hash @table. This can later be retrieved
 * by using @name. Existing entry for this tuple
 * will be removed and freed with @f if found.
 *
 * Returns 0 the addition succeeded and -1 in case of error.
 */
int
virHashUpdateEntry(virHashTablePtr table, const char *name,
                   void *userdata, virHashDeallocator f)
{
    unsigned long key;
    virHashEntryPtr entry;
    virHashEntryPtr insert;

    if ((table == NULL) || name == NULL)
        return (-1);

    /*
     * Check for duplicate and insertion location.
     */
    key = virHashComputeKey(table, name);
    if (table->table[key].valid == 0) {
        insert = NULL;
    } else {
        for (insert = &(table->table[key]); insert->next != NULL;
             insert = insert->next) {
            if (STREQ(insert->name, name)) {
                if (f)
                    f(insert->payload, insert->name);
                insert->payload = userdata;
                return (0);
            }
        }
        if (STREQ(insert->name, name)) {
            if (f)
                f(insert->payload, insert->name);
            insert->payload = userdata;
            return (0);
        }
    }

    if (insert == NULL) {
        entry = &(table->table[key]);
    } else {
        if (VIR_ALLOC(entry) < 0)
            return (-1);
    }

    entry->name = strdup(name);
    entry->payload = userdata;
    entry->next = NULL;
    entry->valid = 1;
    table->nbElems++;


    if (insert != NULL) {
        insert->next = entry;
    }
    return (0);
}

/**
 * virHashLookup:
 * @table: the hash table
 * @name: the name of the userdata
 *
 * Find the userdata specified by the (@name, @name2, @name3) tuple.
 *
 * Returns the a pointer to the userdata
 */
void *
virHashLookup(virHashTablePtr table, const char *name)
{
    unsigned long key;
    virHashEntryPtr entry;

    if (table == NULL)
        return (NULL);
    if (name == NULL)
        return (NULL);
    key = virHashComputeKey(table, name);
    if (table->table[key].valid == 0)
        return (NULL);
    for (entry = &(table->table[key]); entry != NULL; entry = entry->next) {
        if (STREQ(entry->name, name))
            return (entry->payload);
    }
    return (NULL);
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
 * virHashRemoveEntry:
 * @table: the hash table
 * @name: the name of the userdata
 * @f: the deallocator function for removed item (if any)
 *
 * Find the userdata specified by the @name and remove
 * it from the hash @table. Existing userdata for this tuple will be removed
 * and freed with @f.
 *
 * Returns 0 if the removal succeeded and -1 in case of error or not found.
 */
int
virHashRemoveEntry(virHashTablePtr table, const char *name,
                   virHashDeallocator f)
{
    unsigned long key;
    virHashEntryPtr entry;
    virHashEntryPtr prev = NULL;

    if (table == NULL || name == NULL)
        return (-1);

    key = virHashComputeKey(table, name);
    if (table->table[key].valid == 0) {
        return (-1);
    } else {
        for (entry = &(table->table[key]); entry != NULL;
             entry = entry->next) {
            if (STREQ(entry->name, name)) {
                if ((f != NULL) && (entry->payload != NULL))
                    f(entry->payload, entry->name);
                entry->payload = NULL;
                VIR_FREE(entry->name);
                if (prev) {
                    prev->next = entry->next;
                    VIR_FREE(entry);
                } else {
                    if (entry->next == NULL) {
                        entry->valid = 0;
                    } else {
                        entry = entry->next;
                        memcpy(&(table->table[key]), entry,
                               sizeof(virHashEntry));
                        VIR_FREE(entry);
                    }
                }
                table->nbElems--;
                return (0);
            }
            prev = entry;
        }
        return (-1);
    }
}


/**
 * virHashForEach
 * @table: the hash table to process
 * @iter: callback to process each element
 * @data: opaque data to pass to the iterator
 *
 * Iterates over every element in the hash table, invoking the
 * 'iter' callback. The callback must not call any other virHash*
 * functions, and in particular must not attempt to remove the
 * element.
 *
 * Returns number of items iterated over upon completion, -1 on failure
 */
int virHashForEach(virHashTablePtr table, virHashIterator iter, void *data) {
    int i, count = 0;

    if (table == NULL || iter == NULL)
        return (-1);

    for (i = 0 ; i < table->size ; i++) {
        virHashEntryPtr entry = table->table + i;
        while (entry) {
            if (entry->valid) {
                iter(entry->payload, entry->name, data);
                count++;
            }
            entry = entry->next;
        }
    }
    return (count);
}

/**
 * virHashRemoveSet
 * @table: the hash table to process
 * @iter: callback to identify elements for removal
 * @f: callback to free memory from element payload
 * @data: opaque data to pass to the iterator
 *
 * Iterates over all elements in the hash table, invoking the 'iter'
 * callback. If the callback returns a non-zero value, the element
 * will be removed from the hash table & its payload passed to the
 * callback 'f' for de-allocation.
 *
 * Returns number of items removed on success, -1 on failure
 */
int virHashRemoveSet(virHashTablePtr table, virHashSearcher iter, virHashDeallocator f, const void *data) {
    int i, count = 0;

    if (table == NULL || iter == NULL)
        return (-1);

    for (i = 0 ; i < table->size ; i++) {
        virHashEntryPtr prev = NULL;
        virHashEntryPtr entry = &(table->table[i]);

        while (entry && entry->valid) {
            if (iter(entry->payload, entry->name, data)) {
                count++;
                f(entry->payload, entry->name);
                VIR_FREE(entry->name);
                table->nbElems--;
                if (prev) {
                    prev->next = entry->next;
                    VIR_FREE(entry);
                    entry = prev;
                } else {
                    if (entry->next == NULL) {
                        entry->valid = 0;
                        entry->name = NULL;
                    } else {
                        entry = entry->next;
                        memcpy(&(table->table[i]), entry,
                               sizeof(virHashEntry));
                        VIR_FREE(entry);
                        entry = &(table->table[i]);
                        continue;
                    }
                }
            }
            prev = entry;
            if (entry) {
                entry = entry->next;
            }
        }
    }
    return (count);
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
void *virHashSearch(virHashTablePtr table, virHashSearcher iter, const void *data) {
    int i;

    if (table == NULL || iter == NULL)
        return (NULL);

    for (i = 0 ; i < table->size ; i++) {
        virHashEntryPtr entry = table->table + i;
        while (entry) {
            if (entry->valid) {
                if (iter(entry->payload, entry->name, data))
                    return entry->payload;
            }
            entry = entry->next;
        }
    }
    return (NULL);
}
