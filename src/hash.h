/*
 * Summary: Chained hash tables
 * Description: This module implements the hash table support used in 
 * 		various places in the library.
 *
 * Copy: See Copyright for the status of this software.
 *
 * Author: Bjorn Reese <bjorn.reese@systematic.dk>
 */

#ifndef __XEN_HASH_H__
#define __XEN_HASH_H__

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The hash table.
 */
typedef struct _xenHashTable xenHashTable;
typedef xenHashTable *xenHashTablePtr;

/*
 * function types:
 */
/**
 * xenHashDeallocator:
 * @payload:  the data in the hash
 * @name:  the name associated
 *
 * Callback to free data from a hash.
 */
typedef void (*xenHashDeallocator)(void *payload, char *name);

/*
 * Constructor and destructor.
 */
xenHashTablePtr		xenHashCreate	(int size);
void			
			xenHashFree	(xenHashTablePtr table,
					 xenHashDeallocator f);
int			xenHashSize	(xenHashTablePtr table);

/*
 * Add a new entry to the hash table.
 */
int			xenHashAddEntry	(xenHashTablePtr table,
		                         const char *name,
		                         void *userdata);
int			xenHashUpdateEntry(xenHashTablePtr table,
		                         const char *name,
		                         void *userdata,
					 xenHashDeallocator f);

/*
 * Remove an entry from the hash table.
 */
int    			xenHashRemoveEntry(xenHashTablePtr table,
					 const char *name,
					 xenHashDeallocator f);
/*
 * Retrieve the userdata.
 */
void *			xenHashLookup	(xenHashTablePtr table,
					 const char *name);

#ifdef __cplusplus
}
#endif
#endif /* ! __XEN_HASH_H__ */
