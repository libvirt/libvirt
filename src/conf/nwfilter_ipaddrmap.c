/*
 * nwfilter_ipaddrmap.c: IP address map for mapping interfaces to their
 *                       detected/expected IP addresses
 *
 * Copyright (C) 2010, 2012 IBM Corp.
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

#include "viralloc.h"
#include "virerror.h"
#include "virstring.h"
#include "datatypes.h"
#include "nwfilter_params.h"
#include "nwfilter_ipaddrmap.h"

#define VIR_FROM_THIS VIR_FROM_NWFILTER

static virMutex ipAddressMapLock = VIR_MUTEX_INITIALIZER;
static virHashTablePtr ipAddressMap;


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
    char *addrCopy;
    virNWFilterVarValuePtr val;

    if (VIR_STRDUP(addrCopy, addr) < 0)
        return -1;

    virMutexLock(&ipAddressMapLock);

    val = virHashLookup(ipAddressMap, ifname);
    if (!val) {
        val = virNWFilterVarValueCreateSimple(addrCopy);
        if (!val)
            goto cleanup;
        addrCopy = NULL;
        ret = virHashUpdateEntry(ipAddressMap, ifname, val);
        if (ret < 0)
            virNWFilterVarValueFree(val);
        goto cleanup;
    } else {
        if (virNWFilterVarValueAddValue(val, addrCopy) < 0)
            goto cleanup;
        addrCopy = NULL;
    }

    ret = 0;

 cleanup:
    virMutexUnlock(&ipAddressMapLock);
    VIR_FREE(addrCopy);

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
        val = virHashLookup(ipAddressMap, ifname);
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
        virHashRemoveEntry(ipAddressMap, ifname);
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

    res = virHashLookup(ipAddressMap, ifname);

    virMutexUnlock(&ipAddressMapLock);

    return res;
}

int
virNWFilterIPAddrMapInit(void)
{
    ipAddressMap = virNWFilterHashTableCreate(0);
    if (!ipAddressMap)
        return -1;

    return 0;
}

void
virNWFilterIPAddrMapShutdown(void)
{
    virHashFree(ipAddressMap);
    ipAddressMap = NULL;
}
