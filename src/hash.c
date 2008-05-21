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
#include <libxml/threads.h>
#include "internal.h"
#include "hash.h"
#include "memory.h"

#define MAX_HASH_LEN 8

#define DEBUG(fmt,...) VIR_DEBUG(__FILE__, fmt, __VA_ARGS__)
#define DEBUG0(msg) VIR_DEBUG(__FILE__, "%s", msg)

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

    /*  If the two loops are merged, there would be situations where
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
            inside_table = 0;
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
int virHashForEach(virHashTablePtr table, virHashIterator iter, const void *data) {
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

/************************************************************************
 *									*
 *			Domain and Connections allocations		*
 *									*
 ************************************************************************/

/**
 * virHashError:
 * @conn: the connection if available
 * @error: the error number
 * @info: extra information string
 *
 * Handle an error at the connection level
 */
static void
virHashError(virConnectPtr conn, virErrorNumber error, const char *info)
{
    const char *errmsg;

    if (error == VIR_ERR_OK)
        return;

    errmsg = __virErrorMsg(error, info);
    __virRaiseError(conn, NULL, NULL, VIR_FROM_NONE, error, VIR_ERR_ERROR,
                    errmsg, info, NULL, 0, 0, errmsg, info);
}


/**
 * virDomainFreeName:
 * @domain: a domain object
 *
 * Destroy the domain object, this is just used by the domain hash callback.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
static int
virDomainFreeName(virDomainPtr domain, const char *name ATTRIBUTE_UNUSED)
{
    return (virDomainFree(domain));
}

/**
 * virNetworkFreeName:
 * @network: a network object
 *
 * Destroy the network object, this is just used by the network hash callback.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
static int
virNetworkFreeName(virNetworkPtr network, const char *name ATTRIBUTE_UNUSED)
{
    return (virNetworkFree(network));
}

/**
 * virStoragePoolFreeName:
 * @pool: a pool object
 *
 * Destroy the pool object, this is just used by the pool hash callback.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
static int
virStoragePoolFreeName(virStoragePoolPtr pool, const char *name ATTRIBUTE_UNUSED)
{
    return (virStoragePoolFree(pool));
}

/**
 * virStorageVolFreeName:
 * @vol: a vol object
 *
 * Destroy the vol object, this is just used by the vol hash callback.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
static int
virStorageVolFreeName(virStorageVolPtr vol, const char *name ATTRIBUTE_UNUSED)
{
    return (virStorageVolFree(vol));
}

/**
 * virGetConnect:
 *
 * Allocates a new hypervisor connection structure
 *
 * Returns a new pointer or NULL in case of error.
 */
virConnectPtr
virGetConnect(void) {
    virConnectPtr ret;

    if (VIR_ALLOC(ret) < 0) {
        virHashError(NULL, VIR_ERR_NO_MEMORY, _("allocating connection"));
        goto failed;
    }
    ret->magic = VIR_CONNECT_MAGIC;
    ret->driver = NULL;
    ret->networkDriver = NULL;
    ret->privateData = NULL;
    ret->networkPrivateData = NULL;
    ret->domains = virHashCreate(20);
    if (ret->domains == NULL)
        goto failed;
    ret->networks = virHashCreate(20);
    if (ret->networks == NULL)
        goto failed;
    ret->storagePools = virHashCreate(20);
    if (ret->storagePools == NULL)
        goto failed;
    ret->storageVols = virHashCreate(20);
    if (ret->storageVols == NULL)
        goto failed;

    pthread_mutex_init(&ret->lock, NULL);

    ret->refs = 1;
    return(ret);

failed:
    if (ret != NULL) {
        if (ret->domains != NULL)
            virHashFree(ret->domains, (virHashDeallocator) virDomainFreeName);
        if (ret->networks != NULL)
            virHashFree(ret->networks, (virHashDeallocator) virNetworkFreeName);
        if (ret->storagePools != NULL)
            virHashFree(ret->storagePools, (virHashDeallocator) virStoragePoolFreeName);
        if (ret->storageVols != NULL)
            virHashFree(ret->storageVols, (virHashDeallocator) virStorageVolFreeName);

        pthread_mutex_destroy(&ret->lock);
        VIR_FREE(ret);
    }
    return(NULL);
}

/**
 * virReleaseConnect:
 * @conn: the hypervisor connection to release
 *
 * Unconditionally release all memory associated with a connection.
 * The conn.lock mutex must be held prior to calling this, and will
 * be released prior to this returning. The connection obj must not
 * be used once this method returns.
 */
static void
virReleaseConnect(virConnectPtr conn) {
    DEBUG("release connection %p %s", conn, conn->name);
    if (conn->domains != NULL)
        virHashFree(conn->domains, (virHashDeallocator) virDomainFreeName);
    if (conn->networks != NULL)
        virHashFree(conn->networks, (virHashDeallocator) virNetworkFreeName);
    if (conn->storagePools != NULL)
        virHashFree(conn->storagePools, (virHashDeallocator) virStoragePoolFreeName);
    if (conn->storageVols != NULL)
        virHashFree(conn->storageVols, (virHashDeallocator) virStorageVolFreeName);

    virResetError(&conn->err);
    if (__lastErr.conn == conn)
        __lastErr.conn = NULL;

    VIR_FREE(conn->name);

    pthread_mutex_unlock(&conn->lock);
    pthread_mutex_destroy(&conn->lock);
    VIR_FREE(conn);
}

/**
 * virUnrefConnect:
 * @conn: the hypervisor connection to unreference
 *
 * Unreference the connection. If the use count drops to zero, the structure is
 * actually freed.
 *
 * Returns the reference count or -1 in case of failure.
 */
int
virUnrefConnect(virConnectPtr conn) {
    int refs;

    if ((!VIR_IS_CONNECT(conn))) {
        virHashError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return(-1);
    }
    pthread_mutex_lock(&conn->lock);
    DEBUG("unref connection %p %s %d", conn, conn->name, conn->refs);
    conn->refs--;
    refs = conn->refs;
    if (refs == 0) {
        virReleaseConnect(conn);
        /* Already unlocked mutex */
        return (0);
    }
    pthread_mutex_unlock(&conn->lock);
    return (refs);
}

/**
 * virGetDomain:
 * @conn: the hypervisor connection
 * @name: pointer to the domain name
 * @uuid: pointer to the uuid
 *
 * Lookup if the domain is already registered for that connection,
 * if yes return a new pointer to it, if no allocate a new structure,
 * and register it in the table. In any case a corresponding call to
 * virUnrefDomain() is needed to not leak data.
 *
 * Returns a pointer to the domain, or NULL in case of failure
 */
virDomainPtr
__virGetDomain(virConnectPtr conn, const char *name, const unsigned char *uuid) {
    virDomainPtr ret = NULL;

    if ((!VIR_IS_CONNECT(conn)) || (name == NULL) || (uuid == NULL)) {
        virHashError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return(NULL);
    }
    pthread_mutex_lock(&conn->lock);

    /* TODO search by UUID first as they are better differenciators */

    ret = (virDomainPtr) virHashLookup(conn->domains, name);
    /* TODO check the UUID */
    if (ret == NULL) {
        if (VIR_ALLOC(ret) < 0) {
            virHashError(conn, VIR_ERR_NO_MEMORY, _("allocating domain"));
            goto error;
        }
        ret->name = strdup(name);
        if (ret->name == NULL) {
            virHashError(conn, VIR_ERR_NO_MEMORY, _("allocating domain"));
            goto error;
        }
        ret->magic = VIR_DOMAIN_MAGIC;
        ret->conn = conn;
        ret->id = -1;
        if (uuid != NULL)
            memcpy(&(ret->uuid[0]), uuid, VIR_UUID_BUFLEN);

        if (virHashAddEntry(conn->domains, name, ret) < 0) {
            virHashError(conn, VIR_ERR_INTERNAL_ERROR,
                         _("failed to add domain to connection hash table"));
            goto error;
        }
        conn->refs++;
        DEBUG("New hash entry %p", ret);
    } else {
        DEBUG("Existing hash entry %p: refs now %d", ret, ret->refs+1);
    }
    ret->refs++;
    pthread_mutex_unlock(&conn->lock);
    return(ret);

 error:
    pthread_mutex_unlock(&conn->lock);
    if (ret != NULL) {
        VIR_FREE(ret->name);
        VIR_FREE(ret);
    }
    return(NULL);
}

/**
 * virReleaseDomain:
 * @domain: the domain to release
 *
 * Unconditionally release all memory associated with a domain.
 * The conn.lock mutex must be held prior to calling this, and will
 * be released prior to this returning. The domain obj must not
 * be used once this method returns.
 *
 * It will also unreference the associated connection object,
 * which may also be released if its ref count hits zero.
 */
static void
virReleaseDomain(virDomainPtr domain) {
    virConnectPtr conn = domain->conn;
    DEBUG("release domain %p %s", domain, domain->name);

    /* TODO search by UUID first as they are better differenciators */
    if (virHashRemoveEntry(conn->domains, domain->name, NULL) < 0)
        virHashError(conn, VIR_ERR_INTERNAL_ERROR,
                     _("domain missing from connection hash table"));

    if (conn->err.dom == domain)
        conn->err.dom = NULL;
    if (__lastErr.dom == domain)
        __lastErr.dom = NULL;
    domain->magic = -1;
    domain->id = -1;
    VIR_FREE(domain->name);
    VIR_FREE(domain);

    DEBUG("unref connection %p %s %d", conn, conn->name, conn->refs);
    conn->refs--;
    if (conn->refs == 0) {
        virReleaseConnect(conn);
        /* Already unlocked mutex */
        return;
    }

    pthread_mutex_unlock(&conn->lock);
}


/**
 * virUnrefDomain:
 * @domain: the domain to unreference
 *
 * Unreference the domain. If the use count drops to zero, the structure is
 * actually freed.
 *
 * Returns the reference count or -1 in case of failure.
 */
int
virUnrefDomain(virDomainPtr domain) {
    int refs;

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virHashError(domain->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return(-1);
    }
    pthread_mutex_lock(&domain->conn->lock);
    DEBUG("unref domain %p %s %d", domain, domain->name, domain->refs);
    domain->refs--;
    refs = domain->refs;
    if (refs == 0) {
        virReleaseDomain(domain);
        /* Already unlocked mutex */
        return (0);
    }

    pthread_mutex_unlock(&domain->conn->lock);
    return (refs);
}

/**
 * virGetNetwork:
 * @conn: the hypervisor connection
 * @name: pointer to the network name
 * @uuid: pointer to the uuid
 *
 * Lookup if the network is already registered for that connection,
 * if yes return a new pointer to it, if no allocate a new structure,
 * and register it in the table. In any case a corresponding call to
 * virUnrefNetwork() is needed to not leak data.
 *
 * Returns a pointer to the network, or NULL in case of failure
 */
virNetworkPtr
__virGetNetwork(virConnectPtr conn, const char *name, const unsigned char *uuid) {
    virNetworkPtr ret = NULL;

    if ((!VIR_IS_CONNECT(conn)) || (name == NULL) || (uuid == NULL)) {
        virHashError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return(NULL);
    }
    pthread_mutex_lock(&conn->lock);

    /* TODO search by UUID first as they are better differenciators */

    ret = (virNetworkPtr) virHashLookup(conn->networks, name);
    /* TODO check the UUID */
    if (ret == NULL) {
        if (VIR_ALLOC(ret) < 0) {
            virHashError(conn, VIR_ERR_NO_MEMORY, _("allocating network"));
            goto error;
        }
        ret->name = strdup(name);
        if (ret->name == NULL) {
            virHashError(conn, VIR_ERR_NO_MEMORY, _("allocating network"));
            goto error;
        }
        ret->magic = VIR_NETWORK_MAGIC;
        ret->conn = conn;
        if (uuid != NULL)
            memcpy(&(ret->uuid[0]), uuid, VIR_UUID_BUFLEN);

        if (virHashAddEntry(conn->networks, name, ret) < 0) {
            virHashError(conn, VIR_ERR_INTERNAL_ERROR,
                         _("failed to add network to connection hash table"));
            goto error;
        }
        conn->refs++;
    }
    ret->refs++;
    pthread_mutex_unlock(&conn->lock);
    return(ret);

 error:
    pthread_mutex_unlock(&conn->lock);
    if (ret != NULL) {
        VIR_FREE(ret->name);
        VIR_FREE(ret);
    }
    return(NULL);
}

/**
 * virReleaseNetwork:
 * @network: the network to release
 *
 * Unconditionally release all memory associated with a network.
 * The conn.lock mutex must be held prior to calling this, and will
 * be released prior to this returning. The network obj must not
 * be used once this method returns.
 *
 * It will also unreference the associated connection object,
 * which may also be released if its ref count hits zero.
 */
static void
virReleaseNetwork(virNetworkPtr network) {
    virConnectPtr conn = network->conn;
    DEBUG("release network %p %s", network, network->name);

    /* TODO search by UUID first as they are better differenciators */
    if (virHashRemoveEntry(conn->networks, network->name, NULL) < 0)
        virHashError(conn, VIR_ERR_INTERNAL_ERROR,
                     _("network missing from connection hash table"));

    if (conn->err.net == network)
        conn->err.net = NULL;
    if (__lastErr.net == network)
        __lastErr.net = NULL;

    network->magic = -1;
    VIR_FREE(network->name);
    VIR_FREE(network);

    DEBUG("unref connection %p %s %d", conn, conn->name, conn->refs);
    conn->refs--;
    if (conn->refs == 0) {
        virReleaseConnect(conn);
        /* Already unlocked mutex */
        return;
    }

    pthread_mutex_unlock(&conn->lock);
}


/**
 * virUnrefNetwork:
 * @network: the network to unreference
 *
 * Unreference the network. If the use count drops to zero, the structure is
 * actually freed.
 *
 * Returns the reference count or -1 in case of failure.
 */
int
virUnrefNetwork(virNetworkPtr network) {
    int refs;

    if (!VIR_IS_CONNECTED_NETWORK(network)) {
        virHashError(network->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return(-1);
    }
    pthread_mutex_lock(&network->conn->lock);
    DEBUG("unref network %p %s %d", network, network->name, network->refs);
    network->refs--;
    refs = network->refs;
    if (refs == 0) {
        virReleaseNetwork(network);
        /* Already unlocked mutex */
        return (0);
    }

    pthread_mutex_unlock(&network->conn->lock);
    return (refs);
}


/**
 * virGetStoragePool:
 * @conn: the hypervisor connection
 * @name: pointer to the storage pool name
 * @uuid: pointer to the uuid
 *
 * Lookup if the storage pool is already registered for that connection,
 * if yes return a new pointer to it, if no allocate a new structure,
 * and register it in the table. In any case a corresponding call to
 * virFreeStoragePool() is needed to not leak data.
 *
 * Returns a pointer to the network, or NULL in case of failure
 */
virStoragePoolPtr
__virGetStoragePool(virConnectPtr conn, const char *name, const unsigned char *uuid) {
    virStoragePoolPtr ret = NULL;

    if ((!VIR_IS_CONNECT(conn)) || (name == NULL) || (uuid == NULL)) {
        virHashError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return(NULL);
    }
    pthread_mutex_lock(&conn->lock);

    /* TODO search by UUID first as they are better differenciators */

    ret = (virStoragePoolPtr) virHashLookup(conn->storagePools, name);
    /* TODO check the UUID */
    if (ret == NULL) {
        if (VIR_ALLOC(ret) < 0) {
            virHashError(conn, VIR_ERR_NO_MEMORY, _("allocating storage pool"));
            goto error;
        }
        ret->name = strdup(name);
        if (ret->name == NULL) {
            virHashError(conn, VIR_ERR_NO_MEMORY, _("allocating storage pool"));
            goto error;
        }
        ret->magic = VIR_STORAGE_POOL_MAGIC;
        ret->conn = conn;
        if (uuid != NULL)
            memcpy(&(ret->uuid[0]), uuid, VIR_UUID_BUFLEN);

        if (virHashAddEntry(conn->storagePools, name, ret) < 0) {
            virHashError(conn, VIR_ERR_INTERNAL_ERROR,
                         _("failed to add storage pool to connection hash table"));
            goto error;
        }
        conn->refs++;
    }
    ret->refs++;
    pthread_mutex_unlock(&conn->lock);
    return(ret);

error:
    pthread_mutex_unlock(&conn->lock);
    if (ret != NULL) {
        VIR_FREE(ret->name);
        VIR_FREE(ret);
    }
    return(NULL);
}


/**
 * virReleaseStoragePool:
 * @pool: the pool to release
 *
 * Unconditionally release all memory associated with a pool.
 * The conn.lock mutex must be held prior to calling this, and will
 * be released prior to this returning. The pool obj must not
 * be used once this method returns.
 *
 * It will also unreference the associated connection object,
 * which may also be released if its ref count hits zero.
 */
static void
virReleaseStoragePool(virStoragePoolPtr pool) {
    virConnectPtr conn = pool->conn;
    DEBUG("release pool %p %s", pool, pool->name);

    /* TODO search by UUID first as they are better differenciators */
    if (virHashRemoveEntry(conn->storagePools, pool->name, NULL) < 0)
        virHashError(conn, VIR_ERR_INTERNAL_ERROR,
                     _("pool missing from connection hash table"));

    pool->magic = -1;
    VIR_FREE(pool->name);
    VIR_FREE(pool);

    DEBUG("unref connection %p %s %d", conn, conn->name, conn->refs);
    conn->refs--;
    if (conn->refs == 0) {
        virReleaseConnect(conn);
        /* Already unlocked mutex */
        return;
    }

    pthread_mutex_unlock(&conn->lock);
}


/**
 * virUnrefStoragePool:
 * @pool: the pool to unreference
 *
 * Unreference the pool. If the use count drops to zero, the structure is
 * actually freed.
 *
 * Returns the reference count or -1 in case of failure.
 */
int
virUnrefStoragePool(virStoragePoolPtr pool) {
    int refs;

    if (!VIR_IS_CONNECTED_STORAGE_POOL(pool)) {
        virHashError(pool->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return(-1);
    }
    pthread_mutex_lock(&pool->conn->lock);
    DEBUG("unref pool %p %s %d", pool, pool->name, pool->refs);
    pool->refs--;
    refs = pool->refs;
    if (refs == 0) {
        virReleaseStoragePool(pool);
        /* Already unlocked mutex */
        return (0);
    }

    pthread_mutex_unlock(&pool->conn->lock);
    return (refs);
}


/**
 * virGetStorageVol:
 * @conn: the hypervisor connection
 * @pool: pool owning the volume
 * @name: pointer to the storage vol name
 * @uuid: pointer to the uuid
 *
 * Lookup if the storage vol is already registered for that connection,
 * if yes return a new pointer to it, if no allocate a new structure,
 * and register it in the table. In any case a corresponding call to
 * virFreeStorageVol() is needed to not leak data.
 *
 * Returns a pointer to the storage vol, or NULL in case of failure
 */
virStorageVolPtr
__virGetStorageVol(virConnectPtr conn, const char *pool, const char *name, const char *key) {
    virStorageVolPtr ret = NULL;

    if ((!VIR_IS_CONNECT(conn)) || (name == NULL) || (key == NULL)) {
        virHashError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return(NULL);
    }
    pthread_mutex_lock(&conn->lock);

    ret = (virStorageVolPtr) virHashLookup(conn->storageVols, key);
    if (ret == NULL) {
        if (VIR_ALLOC(ret) < 0) {
            virHashError(conn, VIR_ERR_NO_MEMORY, _("allocating storage vol"));
            goto error;
        }
        ret->pool = strdup(pool);
        if (ret->pool == NULL) {
            virHashError(conn, VIR_ERR_NO_MEMORY, _("allocating storage vol"));
            goto error;
        }
        ret->name = strdup(name);
        if (ret->name == NULL) {
            virHashError(conn, VIR_ERR_NO_MEMORY, _("allocating storage vol"));
            goto error;
        }
        strncpy(ret->key, key, sizeof(ret->key)-1);
        ret->key[sizeof(ret->key)-1] = '\0';
        ret->magic = VIR_STORAGE_VOL_MAGIC;
        ret->conn = conn;

        if (virHashAddEntry(conn->storageVols, key, ret) < 0) {
            virHashError(conn, VIR_ERR_INTERNAL_ERROR,
                         _("failed to add storage vol to connection hash table"));
            goto error;
        }
        conn->refs++;
    }
    ret->refs++;
    pthread_mutex_unlock(&conn->lock);
    return(ret);

error:
    pthread_mutex_unlock(&conn->lock);
    if (ret != NULL) {
        VIR_FREE(ret->name);
        VIR_FREE(ret->pool);
        VIR_FREE(ret);
    }
    return(NULL);
}


/**
 * virReleaseStorageVol:
 * @vol: the vol to release
 *
 * Unconditionally release all memory associated with a vol.
 * The conn.lock mutex must be held prior to calling this, and will
 * be released prior to this returning. The vol obj must not
 * be used once this method returns.
 *
 * It will also unreference the associated connection object,
 * which may also be released if its ref count hits zero.
 */
static void
virReleaseStorageVol(virStorageVolPtr vol) {
    virConnectPtr conn = vol->conn;
    DEBUG("release vol %p %s", vol, vol->name);

    /* TODO search by UUID first as they are better differenciators */
    if (virHashRemoveEntry(conn->storageVols, vol->key, NULL) < 0)
        virHashError(conn, VIR_ERR_INTERNAL_ERROR,
                     _("vol missing from connection hash table"));

    vol->magic = -1;
    VIR_FREE(vol->name);
    VIR_FREE(vol->pool);
    VIR_FREE(vol);

    DEBUG("unref connection %p %s %d", conn, conn->name, conn->refs);
    conn->refs--;
    if (conn->refs == 0) {
        virReleaseConnect(conn);
        /* Already unlocked mutex */
        return;
    }

    pthread_mutex_unlock(&conn->lock);
}


/**
 * virUnrefStorageVol:
 * @vol: the vol to unreference
 *
 * Unreference the vol. If the use count drops to zero, the structure is
 * actually freed.
 *
 * Returns the reference count or -1 in case of failure.
 */
int
virUnrefStorageVol(virStorageVolPtr vol) {
    int refs;

    if (!VIR_IS_CONNECTED_STORAGE_VOL(vol)) {
        virHashError(vol->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return(-1);
    }
    pthread_mutex_lock(&vol->conn->lock);
    DEBUG("unref vol %p %s %d", vol, vol->name, vol->refs);
    vol->refs--;
    refs = vol->refs;
    if (refs == 0) {
        virReleaseStorageVol(vol);
        /* Already unlocked mutex */
        return (0);
    }

    pthread_mutex_unlock(&vol->conn->lock);
    return (refs);
}
