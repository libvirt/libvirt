/*
 * nwfilter_ipaddrmap.c: IP address map for mapping interfaces to their
 *                       detected/expected IP addresses
 *
 * Copyright (C) 2010, 2012 IBM Corp.
 *
 * Author:
 *     Stefan Berger <stefanb@linux.vnet.ibm.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#include "internal.h"

#include "virerror.h"
#include "datatypes.h"
#include "nwfilter_params.h"
#include "nwfilter_ipaddrmap.h"

#define VIR_FROM_THIS VIR_FROM_NWFILTER

static virMutex ipAddressMapLock;
static virNWFilterHashTablePtr ipAddressMap;


/* Add an IP address to the list of IP addresses an interface is
 * known to use. This function feeds the per-interface cache that
 * is used to instantiate filters with variable '$IP'.
 *
 * @ifname: The name of the (tap) interface
 * @addr: An IPv4 address in dotted decimal format that the (tap)
 *        interface is known to use.
 *
 * This function returns 0 on success, -1 otherwise
 */
int
virNWFilterIPAddrMapAddIPAddr(const char *ifname, char *addr)
{
    int ret = -1;
    virNWFilterVarValuePtr val;

    virMutexLock(&ipAddressMapLock);

    val = virHashLookup(ipAddressMap->hashTable, ifname);
    if (!val) {
        val = virNWFilterVarValueCreateSimple(addr);
        if (!val)
            goto cleanup;
        ret = virNWFilterHashTablePut(ipAddressMap, ifname, val, 1);
        goto cleanup;
    } else {
        if (virNWFilterVarValueAddValue(val, addr) < 0)
            goto cleanup;
    }

    ret = 0;

 cleanup:
    virMutexUnlock(&ipAddressMapLock);

    return ret;
}

/* Delete all or a specific IP address from an interface. After this
 * call either all or the given IP address will not be associated
 * with the interface anymore.
 *
 * @ifname: The name of the (tap) interface
 * @addr: An IPv4 address in dotted decimal format that the (tap)
 *        interface is not using anymore; provide NULL to remove all IP
 *        addresses associated with the given interface
 *
 * This function returns the number of IP addresses that are still
 * known to be associated with this interface, in case of an error
 * -1 is returned. Error conditions are:
 * - IP addresses is not known to be associated with the interface
 */
int
virNWFilterIPAddrMapDelIPAddr(const char *ifname, const char *ipaddr)
{
    int ret = -1;
    virNWFilterVarValuePtr val = NULL;

    virMutexLock(&ipAddressMapLock);

    if (ipaddr != NULL) {
        val = virHashLookup(ipAddressMap->hashTable, ifname);
        if (val) {
            if (virNWFilterVarValueGetCardinality(val) == 1 &&
                STREQ(ipaddr,
                      virNWFilterVarValueGetNthValue(val, 0)))
                goto remove_entry;
            virNWFilterVarValueDelValue(val, ipaddr);
            ret = virNWFilterVarValueGetCardinality(val);
        }
    } else {
 remove_entry:
        /* remove whole entry */
        val = virNWFilterHashTableRemoveEntry(ipAddressMap, ifname);
        virNWFilterVarValueFree(val);
        ret = 0;
    }

    virMutexUnlock(&ipAddressMapLock);

    return ret;
}

/* Get the list of IP addresses known to be in use by an interface
 *
 * This function returns NULL in case no IP address is known to be
 * associated with the interface, a virNWFilterVarValuePtr otherwise
 * that then can contain one or multiple entries.
 */
virNWFilterVarValuePtr
virNWFilterIPAddrMapGetIPAddr(const char *ifname)
{
    virNWFilterVarValuePtr res;

    virMutexLock(&ipAddressMapLock);

    res = virHashLookup(ipAddressMap->hashTable, ifname);

    virMutexUnlock(&ipAddressMapLock);

    return res;
}

int
virNWFilterIPAddrMapInit(void)
{
    ipAddressMap = virNWFilterHashTableCreate(0);
    if (!ipAddressMap)
        return -1;

    if (virMutexInit(&ipAddressMapLock) < 0) {
        virNWFilterIPAddrMapShutdown();
        return -1;
    }

    return 0;
}

void
virNWFilterIPAddrMapShutdown(void)
{
    virNWFilterHashTableFree(ipAddressMap);
    ipAddressMap = NULL;
}
