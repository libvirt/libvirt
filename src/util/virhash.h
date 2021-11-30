/*
 * Summary: Chained hash tables and domain/connections handling
 * Description: This module implements the hash table and allocation and
 *              deallocation of domains and connections
 *
 * Copyright (C) 2005-2014 Red Hat, Inc.
 * Copyright (C) 2000 Bjorn Reese and Daniel Veillard.
 */

#pragma once

typedef struct _virHashAtomic virHashAtomic;

/*
 * function types:
 */

/**
 * virHashIterator:
 * @payload: the data in the hash
 * @name: the hash key
 * @opaque: user supplied data blob
 *
 * Callback to process a hash entry during iteration
 *
 * Returns -1 to stop the iteration, e.g. in case of an error
 */
typedef int (*virHashIterator) (void *payload, const char *name, void *opaque);
/**
 * virHashSearcher:
 * @payload: the data in the hash
 * @name: the hash key
 * @opaque: user supplied data blob
 *
 * Callback to identify hash entry desired
 * Returns 1 if the hash entry is desired, 0 to move
 * to next entry
 */
typedef int (*virHashSearcher) (const void *payload, const char *name,
                                const void *opaque);

/*
 * Constructor and destructor.
 */
GHashTable *virHashNew(GDestroyNotify dataFree) G_GNUC_WARN_UNUSED_RESULT;
virHashAtomic *virHashAtomicNew(GDestroyNotify dataFree);
ssize_t virHashSize(GHashTable *table);

/*
 * Add a new entry to the hash table.
 */
int virHashAddEntry(GHashTable *table,
                    const char *name, void *userdata);
int virHashUpdateEntry(GHashTable *table,
                       const char *name,
                       void *userdata);
int virHashAtomicUpdate(virHashAtomic *table,
                        const char *name,
                        void *userdata);

/*
 * Remove an entry from the hash table.
 */
int virHashRemoveEntry(GHashTable *table,
                       const char *name);

/*
 * Remove all entries from the hash table.
 */
void virHashRemoveAll(GHashTable *table);

/*
 * Retrieve the userdata.
 */
void *virHashLookup(GHashTable *table, const char *name);
bool virHashHasEntry(GHashTable *table, const char *name);

/*
 * Retrieve & remove the userdata.
 */
void *virHashSteal(GHashTable *table, const char *name);
void *virHashAtomicSteal(virHashAtomic *table,
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
struct _virHashKeyValuePair {
    const void *key;
    const void *value;
};
virHashKeyValuePair *virHashGetItems(GHashTable *table,
                                       size_t *nitems,
                                       bool sortedKeys);

/*
 * Compare two tables for equality: the lookup of a key's value in
 * both tables must result in an equivalent value.
 * The caller must pass in a comparator function for comparing the values
 * of two keys.
 */
typedef int (*virHashValueComparator)(const void *value1, const void *value2);
bool virHashEqual(GHashTable *table1,
                  GHashTable *table2,
                  virHashValueComparator compar);


/*
 * Iterators
 */
int virHashForEach(GHashTable *table, virHashIterator iter, void *opaque);
int virHashForEachSafe(GHashTable *table, virHashIterator iter, void *opaque);
int virHashForEachSorted(GHashTable *table, virHashIterator iter, void *opaque);
ssize_t virHashRemoveSet(GHashTable *table, virHashSearcher iter, const void *opaque);
void *virHashSearch(GHashTable *table, virHashSearcher iter,
                    const void *opaque, char **name);
