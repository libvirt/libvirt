/*
 * Summary: Chained hash tables and domain/connections handling
 * Description: This module implements the hash table and allocation and
 *              deallocation of domains and connections
 *
 * Copy: Copyright (C) 2005, 2011 Red Hat, Inc.
 *
 * Author: Bjorn Reese <bjorn.reese@systematic.dk>
 *         Daniel Veillard <veillard@redhat.com>
 */

#ifndef __VIR_HASH_H__
# define __VIR_HASH_H__

/*
 * The hash table.
 */
typedef struct _virHashTable virHashTable;
typedef virHashTable *virHashTablePtr;

/*
 * function types:
 */

/**
 * virHashDataFree:
 * @payload:  the data in the hash
 * @name:  the name associated
 *
 * Callback to free data from a hash.
 */
typedef void (*virHashDataFree) (void *payload, const void *name);
/**
 * virHashIterator:
 * @payload: the data in the hash
 * @name: the hash key
 * @data: user supplied data blob
 *
 * Callback to process a hash entry during iteration
 */
typedef void (*virHashIterator) (void *payload, const void *name, void *data);
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
typedef int (*virHashSearcher) (const void *payload, const void *name,
                                const void *data);

/**
 * virHashKeyCode:
 * @name: the hash key
 *
 * Compute the hash code corresponding to the key @name
 *
 * Returns the hash code
 */
typedef unsigned long (*virHashKeyCode)(const void *name);
/**
 * virHashKeyEqual:
 * @namea: the first hash key
 * @nameb: the second hash key
 *
 * Compare two hash keys for equality
 *
 * Returns true if the keys are equal, false otherwise
 */
typedef bool (*virHashKeyEqual)(const void *namea, const void *nameb);
/**
 * virHashKeyCopy:
 * @name: the hash key
 *
 * Create a copy of the hash key, duplicating
 * memory allocation where applicable
 *
 * Returns a newly allocated copy of @name
 */
typedef void *(*virHashKeyCopy)(const void *name);
/**
 * virHashKeyFree:
 * @name: the hash key
 *
 * Free any memory associated with the hash
 * key @name
 */
typedef void (*virHashKeyFree)(void *name);

/*
 * Constructor and destructor.
 */
virHashTablePtr virHashCreate(int size,
                              virHashDataFree dataFree);
virHashTablePtr virHashCreateFull(int size,
                                  virHashDataFree dataFree,
                                  virHashKeyCode keyCode,
                                  virHashKeyEqual keyEqual,
                                  virHashKeyCopy keyCopy,
                                  virHashKeyFree keyFree);
void virHashFree(virHashTablePtr table);
int virHashSize(virHashTablePtr table);
int virHashTableSize(virHashTablePtr table);

/*
 * Add a new entry to the hash table.
 */
int virHashAddEntry(virHashTablePtr table,
                    const void *name, void *userdata);
int virHashUpdateEntry(virHashTablePtr table,
                       const void *name,
                       void *userdata);

/*
 * Remove an entry from the hash table.
 */
int virHashRemoveEntry(virHashTablePtr table,
                       const void *name);

/*
 * Retrieve the userdata.
 */
void *virHashLookup(virHashTablePtr table, const void *name);

/*
 * Retrieve & remove the userdata.
 */
void *virHashSteal(virHashTablePtr table, const void *name);

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
typedef int (*virHashKeyComparator)(const virHashKeyValuePairPtr,
                                    const virHashKeyValuePairPtr);
virHashKeyValuePairPtr virHashGetItems(virHashTablePtr table,
                                       virHashKeyComparator compar);

/*
 * Iterators
 */
int virHashForEach(virHashTablePtr table, virHashIterator iter, void *data);
int virHashRemoveSet(virHashTablePtr table, virHashSearcher iter, const void *data);
void *virHashSearch(virHashTablePtr table, virHashSearcher iter, const void *data);

#endif                          /* ! __VIR_HASH_H__ */
