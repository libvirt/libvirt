/*
 * Summary: Chained hash tables and domain/connections handling
 * Description: This module implements the hash table and allocation and
 *              deallocation of domains and connections
 *
 * Copy: Copyright (C) 2005 Red Hat, Inc.
 *
 * Author: Bjorn Reese <bjorn.reese@systematic.dk>
 *         Daniel Veillard <veillard@redhat.com>
 */

#ifndef __VIR_HASH_H__
#define __VIR_HASH_H__

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The hash table.
 */
typedef struct _virHashTable virHashTable;
typedef virHashTable *virHashTablePtr;

/*
 * function types:
 */

/**
 * virHashDeallocator:
 * @payload:  the data in the hash
 * @name:  the name associated
 *
 * Callback to free data from a hash.
 */
typedef void (*virHashDeallocator) (void *payload, const char *name);
/**
 * virHashIterator:
 * @payload: the data in the hash
 * @name: the name associated
 * @data: user supplied data blob
 *
 * Callback to process a hash entry during iteration
 */
typedef void (*virHashIterator) (const void *payload, const char *name, const void *data);
/**
 * virHashSearcher
 * @payload: the data in the hash
 * @name: the name associated
 * @data: user supplied data blob
 *
 * Callback to identify hash entry desired
 * Returns 1 if the hash entry is desired, 0 to move
 * to next entry
 */
typedef int (*virHashSearcher) (const void *payload, const char *name, const void *data);

/*
 * Constructor and destructor.
 */
virHashTablePtr virHashCreate(int size);
void virHashFree(virHashTablePtr table, virHashDeallocator f);
int virHashSize(virHashTablePtr table);

/*
 * Add a new entry to the hash table.
 */
int virHashAddEntry(virHashTablePtr table,
		    const char *name, void *userdata);
int virHashUpdateEntry(virHashTablePtr table,
		       const char *name,
		       void *userdata, virHashDeallocator f);

/*
 * Remove an entry from the hash table.
 */
int virHashRemoveEntry(virHashTablePtr table,
		       const char *name, virHashDeallocator f);

/*
 * Retrieve the userdata.
 */
void *virHashLookup(virHashTablePtr table, const char *name);


/*
 * Iterators
 */
int virHashForEach(virHashTablePtr table, virHashIterator iter, const void *data);
int virHashRemoveSet(virHashTablePtr table, virHashSearcher iter, virHashDeallocator f, const void *data);
void *virHashSearch(virHashTablePtr table, virHashSearcher iter, const void *data);

#ifdef __cplusplus
}
#endif
#endif                          /* ! __VIR_HASH_H__ */
