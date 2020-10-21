/*
 * Summary: Chained hash tables and domain/connections handling
 * Description: This module implements the hash table and allocation and
 *              deallocation of domains and connections
 *
 * Copyright (C) 2005-2014 Red Hat, Inc.
 * Copyright (C) 2000 Bjorn Reese and Daniel Veillard.
 */

#pragma once

/*
 * The hash table.
 */
typedef struct _virHashTable virHashTable;
typedef virHashTable *virHashTablePtr;

typedef struct _virHashAtomic virHashAtomic;
typedef virHashAtomic *virHashAtomicPtr;

/*
 * function types:
 */

/**
 * virHashDataFree:
 * @payload:  the data in the hash
 *
 * Callback to free data from a hash.
 */
typedef void (*virHashDataFree) (void *payload);

/**
 * virHashIterator:
 * @payload: the data in the hash
 * @name: the hash key
 * @data: user supplied data blob
 *
 * Callback to process a hash entry during iteration
 *
 * Returns -1 to stop the iteration, e.g. in case of an error
 */
typedef int (*virHashIterator) (void *payload, const char *name, void *data);
/**
 * virHashSearcher:
 * @payload: the data in the hash
 * @name: the hash key
 * @data: user supplied data blob
 *
 * Callback to identify hash entry desired
 * Returns 1 if the hash entry is desired, 0 to move
 * to next entry
 */
typedef int (*virHashSearcher) (const void *payload, const char *name,
                                const void *data);

/*
 * Constructor and destructor.
 */
virHashTablePtr virHashNew(virHashDataFree dataFree);
virHashAtomicPtr virHashAtomicNew(virHashDataFree dataFree);
void virHashFree(virHashTablePtr table);
ssize_t virHashSize(const virHashTable *table);

/*
 * Add a new entry to the hash table.
 */
int virHashAddEntry(virHashTablePtr table,
                    const char *name, void *userdata);
int virHashUpdateEntry(virHashTablePtr table,
                       const char *name,
                       void *userdata);
int virHashAtomicUpdate(virHashAtomicPtr table,
                        const char *name,
                        void *userdata);

/*
 * Remove an entry from the hash table.
 */
int virHashRemoveEntry(virHashTablePtr table,
                       const char *name);

/*
 * Remove all entries from the hash table.
 */
void virHashRemoveAll(virHashTablePtr table);

/*
 * Retrieve the userdata.
 */
void *virHashLookup(const virHashTable *table, const char *name);
bool virHashHasEntry(const virHashTable *table, const char *name);

/*
 * Retrieve & remove the userdata.
 */
void *virHashSteal(virHashTablePtr table, const char *name);
void *virHashAtomicSteal(virHashAtomicPtr table,
                         const char *name);

/*
 * Get the hash table's key/value pairs and have them optionally sorted.
 * The returned array contains virHashSize() elements. Additionally,
 * an empty element has been added to the end of the array (with key == NULL)
 * to indicate the end of the array.
 * The key/value pairs are only valid as long as the underlying hash
 * table is not modified, i.e., no keys are removed or inserted, and
 * the hash table is not deleted.
 * The caller must only free the returned array using VIR_FREE().
 * The caller must make copies of all returned keys and values if they are
 * to be used somewhere else.
 */
typedef struct _virHashKeyValuePair virHashKeyValuePair;
typedef virHashKeyValuePair *virHashKeyValuePairPtr;
struct _virHashKeyValuePair {
    const void *key;
    const void *value;
};
typedef int (*virHashKeyComparator)(const virHashKeyValuePair *,
                                    const virHashKeyValuePair *);
virHashKeyValuePairPtr virHashGetItems(virHashTablePtr table,
                                       virHashKeyComparator compar);

/*
 * Compare two tables for equality: the lookup of a key's value in
 * both tables must result in an equivalent value.
 * The caller must pass in a comparator function for comparing the values
 * of two keys.
 */
typedef int (*virHashValueComparator)(const void *value1, const void *value2);
bool virHashEqual(const virHashTable *table1,
                  const virHashTable *table2,
                  virHashValueComparator compar);


/*
 * Iterators
 */
int virHashForEach(virHashTablePtr table, virHashIterator iter, void *data);
ssize_t virHashRemoveSet(virHashTablePtr table, virHashSearcher iter, const void *data);
void *virHashSearch(const virHashTable *table, virHashSearcher iter,
                    const void *data, char **name);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virHashTable, virHashFree);
