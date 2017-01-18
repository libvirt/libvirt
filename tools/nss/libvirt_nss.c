/*
 * libvirt_nss: Name Service Switch plugin
 *
 * The aim is to enable users and applications to translate
 * domain names into IP addresses. However, this is currently
 * available only for those domains which gets their IP addresses
 * from a libvirt managed network.
 *
 * Copyright (C) 2016 Red Hat, Inc.
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
 *
 * Authors:
 *     Michal Privoznik <mprivozn@redhat.com>
 */
#include <config.h>

#include "libvirt_nss.h"

#include <netinet/in.h>
#include <resolv.h>
#include <sys/types.h>
#include <dirent.h>
#include <arpa/inet.h>

#if defined(HAVE_BSD_NSS)
# include <nsswitch.h>
#endif

#include "virlease.h"
#include "viralloc.h"
#include "virfile.h"
#include "virtime.h"
#include "virerror.h"
#include "virstring.h"
#include "virsocketaddr.h"
#include "configmake.h"
#include "virmacmap.h"
#include "virobject.h"

#if 0
# define ERROR(...)                                             \
do {                                                            \
    char ebuf[1024];                                            \
    fprintf(stderr, "ERROR %s:%d : ", __FUNCTION__, __LINE__);  \
    fprintf(stderr, __VA_ARGS__);                               \
    fprintf(stderr, " : %s\n", virStrerror(errno, ebuf, sizeof(ebuf))); \
    fprintf(stderr, "\n");                                      \
} while (0)

# define DEBUG(...)                                             \
do {                                                            \
    fprintf(stderr, "DEBUG %s:%d : ", __FUNCTION__, __LINE__);  \
    fprintf(stderr, __VA_ARGS__);                               \
    fprintf(stderr, "\n");                                      \
} while (0)
#else
# define ERROR(...) do { } while (0)
# define DEBUG(...) do { } while (0)
#endif

#define LEASEDIR LOCALSTATEDIR "/lib/libvirt/dnsmasq/"

#define LIBVIRT_ALIGN(x) (((x) + __SIZEOF_POINTER__ - 1) & ~(__SIZEOF_POINTER__ - 1))
#define FAMILY_ADDRESS_SIZE(family) ((family) == AF_INET6 ? 16 : 4)

typedef struct {
    unsigned char addr[16];
    int af;
} leaseAddress;


static int
appendAddr(leaseAddress **tmpAddress,
           size_t *ntmpAddress,
           virJSONValuePtr lease,
           int af)
{
    int ret = -1;
    const char *ipAddr;
    virSocketAddr sa;
    int family;
    size_t i;

    if (!(ipAddr = virJSONValueObjectGetString(lease, "ip-address"))) {
        ERROR("ip-address field missing for %s", name);
        goto cleanup;
    }

    DEBUG("IP address: %s", ipAddr);

    if (virSocketAddrParse(&sa, ipAddr, AF_UNSPEC) < 0) {
        ERROR("Unable to parse %s", ipAddr);
        goto cleanup;
    }

    family = VIR_SOCKET_ADDR_FAMILY(&sa);
    if (af != AF_UNSPEC && af != family) {
        DEBUG("Skipping address which family is %d, %d requested", family, af);
        ret = 0;
        goto cleanup;
    }

    for (i = 0; i < *ntmpAddress; i++) {
        if (memcmp((*tmpAddress)[i].addr,
                   (family == AF_INET ?
                    (void *) &sa.data.inet4.sin_addr.s_addr :
                    (void *) &sa.data.inet6.sin6_addr.s6_addr),
                   FAMILY_ADDRESS_SIZE(family)) == 0) {
            DEBUG("IP address already in the list");
            ret = 0;
            goto cleanup;
        }
    }

    if (VIR_REALLOC_N_QUIET(*tmpAddress, *ntmpAddress + 1) < 0) {
        ERROR("Out of memory");
        goto cleanup;
    }

    (*tmpAddress)[*ntmpAddress].af = family;
    memcpy((*tmpAddress)[*ntmpAddress].addr,
           (family == AF_INET ?
            (void *) &sa.data.inet4.sin_addr.s_addr :
            (void *) &sa.data.inet6.sin6_addr.s6_addr),
           FAMILY_ADDRESS_SIZE(family));
    (*ntmpAddress)++;
    ret = 0;
 cleanup:
    return ret;
}


static int
findLeaseInJSON(leaseAddress **tmpAddress,
                size_t *ntmpAddress,
                virJSONValuePtr leases_array,
                size_t nleases,
                const char *name,
                const char **macs,
                int af,
                bool *found)
{
    size_t i;
    long long expirytime;
    time_t currtime;
    int ret = -1;

    if ((currtime = time(NULL)) == (time_t) - 1) {
        ERROR("Failed to get current system time");
        goto cleanup;
    }

    for (i = 0; i < nleases; i++) {
        virJSONValuePtr lease = virJSONValueArrayGet(leases_array, i);

        if (!lease) {
            /* This should never happen (TM) */
            ERROR("Unable to get element %zu of %zu", i, nleases);
            goto cleanup;
        }

        if (macs) {
            const char *macAddr;

            macAddr = virJSONValueObjectGetString(lease, "mac-address");
            if (!macAddr)
                continue;

            if (!virStringListHasString(macs, macAddr))
                continue;
        } else {
            const char *lease_name;

            lease_name = virJSONValueObjectGetString(lease, "hostname");

            if (STRNEQ_NULLABLE(name, lease_name))
                continue;
        }

        if (virJSONValueObjectGetNumberLong(lease, "expiry-time", &expirytime) < 0) {
            /* A lease cannot be present without expiry-time */
            ERROR("expiry-time field missing for %s", name);
            goto cleanup;
        }

        /* Do not report expired lease */
        if (expirytime < (long long) currtime) {
            DEBUG("Skipping expired lease for %s", name);
            continue;
        }

        DEBUG("Found record for %s", name);
        *found = true;

        if (appendAddr(tmpAddress, ntmpAddress, lease, af) < 0)
            goto cleanup;
    }

    ret = 0;
 cleanup:
    return ret;
}


/**
 * findLease:
 * @name: domain name to lookup
 * @af: address family
 * @address: all the addresses found for selected @af
 * @naddress: number of elements in @address array
 * @found: whether @name has been found
 * @errnop: errno pointer
 *
 * Lookup @name in libvirt's IP database, parse it and store all
 * addresses found in @address array. Callers can choose which
 * address family (@af) should be returned. Currently only
 * AF_INET (IPv4) and AF_INET6 (IPv6) are supported. As a corner
 * case, AF_UNSPEC may be passed to @af in which case no address
 * filtering is done and addresses from both families are
 * returned.
 *
 * Returns -1 on error
 *          0 on success
 */
static int
findLease(const char *name,
          int af,
          leaseAddress **address,
          size_t *naddress,
          bool *found,
          int *errnop)
{
    DIR *dir = NULL;
    int ret = -1;
    const char *leaseDir = LEASEDIR;
    struct dirent *entry;
    virJSONValuePtr leases_array = NULL;
    ssize_t nleases;
    leaseAddress *tmpAddress = NULL;
    size_t ntmpAddress = 0;
    virMacMapPtr *macmaps = NULL;
    size_t nMacmaps = 0;

    *address = NULL;
    *naddress = 0;
    *found = false;

    if (af != AF_UNSPEC && af != AF_INET && af != AF_INET6) {
        errno = EAFNOSUPPORT;
        goto cleanup;
    }

    if (virDirOpenQuiet(&dir, leaseDir) < 0) {
        ERROR("Failed to open dir '%s'", leaseDir);
        goto cleanup;
    }

    if (!(leases_array = virJSONValueNewArray())) {
        ERROR("Failed to create json array");
        goto cleanup;
    }

    DEBUG("Dir: %s", leaseDir);
    while ((ret = virDirRead(dir, &entry, leaseDir)) > 0) {
        char *path;

        if (virFileHasSuffix(entry->d_name, ".status")) {
            if (!(path = virFileBuildPath(leaseDir, entry->d_name, NULL)))
                goto cleanup;

            DEBUG("Processing %s", path);
            if (virLeaseReadCustomLeaseFile(leases_array, path, NULL, NULL) < 0) {
                ERROR("Unable to parse %s", path);
                VIR_FREE(path);
                goto cleanup;
            }
            VIR_FREE(path);
        } else if (virFileHasSuffix(entry->d_name, ".macs")) {
            if (!(path = virFileBuildPath(leaseDir, entry->d_name, NULL)))
                goto cleanup;

            if (VIR_REALLOC_N_QUIET(macmaps, nMacmaps + 1) < 0) {
                VIR_FREE(path);
                goto cleanup;
            }

            DEBUG("Processing %s", path);
            if (!(macmaps[nMacmaps] = virMacMapNew(path))) {
                ERROR("Unable to parse %s", path);
                VIR_FREE(path);
                goto cleanup;
            }
            nMacmaps++;
            VIR_FREE(path);
        }
    }
    VIR_DIR_CLOSE(dir);

    if ((nleases = virJSONValueArraySize(leases_array)) < 0)
        goto cleanup;
    DEBUG("Read %zd leases", nleases);

#if !defined(LIBVIRT_NSS_GUEST)
    if (findLeaseInJSON(&tmpAddress, &ntmpAddress,
                        leases_array, nleases,
                        name, NULL, af, found) < 0)
        goto cleanup;

#else /* defined(LIBVIRT_NSS_GUEST) */

    size_t i;
    for (i = 0; i < nMacmaps; i++) {
        const char **macs = (const char **) virMacMapLookup(macmaps[i], name);

        if (!macs)
            continue;

        if (findLeaseInJSON(&tmpAddress, &ntmpAddress,
                            leases_array, nleases,
                            name, macs, af, found) < 0)
            goto cleanup;
    }

#endif /* defined(LIBVIRT_NSS_GUEST) */

    *address = tmpAddress;
    *naddress = ntmpAddress;
    tmpAddress = NULL;
    ntmpAddress = 0;

    ret = 0;

 cleanup:
    *errnop = errno;
    VIR_FREE(tmpAddress);
    virJSONValueFree(leases_array);
    VIR_DIR_CLOSE(dir);
    while (nMacmaps)
        virObjectUnref(macmaps[--nMacmaps]);
    VIR_FREE(macmaps);
    return ret;
}


enum nss_status
NSS_NAME(gethostbyname)(const char *name, struct hostent *result,
                        char *buffer, size_t buflen, int *errnop,
                        int *herrnop)
{
    return NSS_NAME(gethostbyname3)(name, AF_INET, result, buffer, buflen,
                                    errnop, herrnop, NULL, NULL);
}

enum nss_status
NSS_NAME(gethostbyname2)(const char *name, int af, struct hostent *result,
                         char *buffer, size_t buflen, int *errnop,
                         int *herrnop)
{
    return NSS_NAME(gethostbyname3)(name, af, result, buffer, buflen,
                                    errnop, herrnop, NULL, NULL);
}

static inline void *
move_and_align(void *buf, size_t len, size_t *idx)
{
    char *buffer = buf;
    size_t move = LIBVIRT_ALIGN(len);

    if (!idx)
        return buffer + move;

    *idx += move;

    return buffer + *idx;
}

enum nss_status
NSS_NAME(gethostbyname3)(const char *name, int af, struct hostent *result,
                         char *buffer, size_t buflen, int *errnop,
                         int *herrnop, int32_t *ttlp, char **canonp)
{
    enum nss_status ret = NSS_STATUS_UNAVAIL;
    char *r_name, **r_aliases, *r_addr, *r_addr_next, **r_addr_list;
    leaseAddress *addr = NULL;
    size_t naddr, i;
    bool found = false;
    size_t nameLen, need, idx = 0;
    int alen;
    int r;

    /* findLease is capable of returning both IPv4 and IPv6.
     * However, this function has no way of telling user back the
     * family per each address returned. Therefore, if @af ==
     * AF_UNSPEC return just one family instead of a mixture of
     * both. Dice picked the former one. */
    if (af == AF_UNSPEC)
        af = AF_INET;

    if ((r = findLease(name, af, &addr, &naddr, &found, errnop)) < 0) {
        /* Error occurred. Return immediately. */
        if (*errnop == EAGAIN) {
            *herrnop = TRY_AGAIN;
            return NSS_STATUS_TRYAGAIN;
        } else {
            *herrnop = NO_RECOVERY;
            return NSS_STATUS_UNAVAIL;
        }
    }

    if (!found) {
        /* NOT found */
        *errnop = ESRCH;
        *herrnop = HOST_NOT_FOUND;
        return NSS_STATUS_NOTFOUND;
    } else if (!naddr) {
        /* Found, but no data */
        *errnop = ENXIO;
        *herrnop = NO_DATA;
        return NSS_STATUS_UNAVAIL;
    }

    /* Found and have data */

    alen = FAMILY_ADDRESS_SIZE(addr[0].af);

    nameLen = strlen(name);
    /* We need space for:
     * a) name
     * b) alias
     * c) addresses
     * d) NULL stem */
    need = LIBVIRT_ALIGN(nameLen + 1) + naddr * LIBVIRT_ALIGN(alen) + (naddr + 2) * sizeof(char*);

    if (buflen < need) {
        *errnop = ENOMEM;
        *herrnop = TRY_AGAIN;
        ret = NSS_STATUS_TRYAGAIN;
        goto cleanup;
    }

    /* First, append name */
    r_name = buffer;
    memcpy(r_name, name, nameLen + 1);

    r_aliases = move_and_align(buffer, nameLen + 1, &idx);

    /* Second, create aliases array */
    r_aliases[0] = NULL;

    /* Third, append address */
    r_addr = move_and_align(buffer, sizeof(char *), &idx);
    r_addr_next = r_addr;
    for (i = 0; i < naddr; i++) {
        memcpy(r_addr_next, addr[i].addr, alen);
        r_addr_next = move_and_align(buffer, alen, &idx);
    }

    r_addr_list = move_and_align(buffer, 0, &idx);
    r_addr_next = r_addr;
    /* Third, append address pointer array */
    for (i = 0; i < naddr; i++) {
        r_addr_list[i] = r_addr_next;
        r_addr_next = move_and_align(r_addr_next, alen, NULL);
    }
    r_addr_list[i] = NULL;
    idx += (naddr + 1) * sizeof(char*);

    /* At this point, idx == need */
    DEBUG("Done idx:%zd need:%zd", idx, need);

    result->h_name = r_name;
    result->h_aliases = r_aliases;
    result->h_addrtype = af;
    result->h_length = alen;
    result->h_addr_list = r_addr_list;

    if (ttlp)
        *ttlp = 0;

    if (canonp)
        *canonp = r_name;

    /* Explicitly reset all error variables */
    *errnop = 0;
    *herrnop = NETDB_SUCCESS;
    h_errno = 0;

    ret = NSS_STATUS_SUCCESS;
 cleanup:
    VIR_FREE(addr);
    return ret;
}

#ifdef HAVE_STRUCT_GAIH_ADDRTUPLE
enum nss_status
NSS_NAME(gethostbyname4)(const char *name, struct gaih_addrtuple **pat,
                         char *buffer, size_t buflen, int *errnop,
                         int *herrnop, int32_t *ttlp)
{
    enum nss_status ret = NSS_STATUS_UNAVAIL;
    leaseAddress *addr = NULL;
    size_t naddr, i;
    bool found = false;
    int r;
    size_t nameLen, need, idx = 0;
    struct gaih_addrtuple *r_tuple, *r_tuple_first = NULL;
    char *r_name;

    if ((r = findLease(name, AF_UNSPEC, &addr, &naddr, &found, errnop)) < 0) {
        /* Error occurred. Return immediately. */
        if (*errnop == EAGAIN) {
            *herrnop = TRY_AGAIN;
            return NSS_STATUS_TRYAGAIN;
        } else {
            *herrnop = NO_RECOVERY;
            return NSS_STATUS_UNAVAIL;
        }
    }

    if (!found) {
        /* NOT found */
        *errnop = ESRCH;
        *herrnop = HOST_NOT_FOUND;
        return NSS_STATUS_NOTFOUND;
    } else if (!naddr) {
        /* Found, but no data */
        *errnop = ENXIO;
        *herrnop = NO_DATA;
        return NSS_STATUS_UNAVAIL;
    }

    /* Found and have data */

    nameLen = strlen(name);
    /* We need space for:
     * a) name
     * b) addresses */
    need = LIBVIRT_ALIGN(nameLen + 1) + naddr * LIBVIRT_ALIGN(sizeof(struct gaih_addrtuple));

    if (buflen < need) {
        *errnop = ENOMEM;
        *herrnop = TRY_AGAIN;
        ret = NSS_STATUS_TRYAGAIN;
        goto cleanup;
    }

    /* First, append name */
    r_name = buffer;
    memcpy(r_name, name, nameLen + 1);

    /* Second, append addresses */
    r_tuple_first = move_and_align(buffer, nameLen + 1, &idx);
    for (i = 0; i < naddr; i++) {
        int family = addr[i].af;

        r_tuple = move_and_align(buffer, 0, &idx);
        if (i == naddr - 1)
            r_tuple->next = NULL;
        else
            r_tuple->next = move_and_align(buffer, sizeof(struct gaih_addrtuple), &idx);
        r_tuple->name = r_name;
        r_tuple->family = family;
        r_tuple->scopeid = 0;
        memcpy(r_tuple->addr, addr[i].addr, FAMILY_ADDRESS_SIZE(family));

    }

    /* At this point, idx == need */
    DEBUG("Done idx:%zd need:%zd", idx, need);

    if (*pat)
        **pat = *r_tuple_first;
    else
        *pat = r_tuple_first;

    if (ttlp)
        *ttlp = 0;

    /* Explicitly reset all error variables */
    *errnop = 0;
    *herrnop = NETDB_SUCCESS;
    ret = NSS_STATUS_SUCCESS;
 cleanup:
    return ret;
}
#endif /* HAVE_STRUCT_GAIH_ADDRTUPLE */

#if defined(HAVE_BSD_NSS)
NSS_METHOD_PROTOTYPE(_nss_compat_getaddrinfo);
NSS_METHOD_PROTOTYPE(_nss_compat_gethostbyname2_r);

ns_mtab methods[] = {
    { NSDB_HOSTS, "getaddrinfo", _nss_compat_getaddrinfo, NULL },
    { NSDB_HOSTS, "gethostbyname", _nss_compat_gethostbyname2_r, NULL },
    { NSDB_HOSTS, "gethostbyname2_r", _nss_compat_gethostbyname2_r, NULL },
};

static void
aiforaf(const char *name, int af, struct addrinfo *pai, struct addrinfo **aip)
{
    int ret;
    struct hostent resolved;
    char buf[1024] = { 0 };
    int err, herr;
    struct addrinfo hints, *res0, *res;
    char **addrList;

    if ((ret = NSS_NAME(gethostbyname2)(name, af, &resolved,
                                        buf, sizeof(buf),
                                        &err, &herr)) != NS_SUCCESS)
        return;

    addrList = resolved.h_addr_list;
    while (*addrList) {
        virSocketAddr sa;
        char *ipAddr = NULL;
        void *address = *addrList;

        memset(&sa, 0, sizeof(sa));
        if (resolved.h_addrtype == AF_INET) {
            virSocketAddrSetIPv4AddrNetOrder(&sa, *((uint32_t *) address));
        } else {
            virSocketAddrSetIPv6AddrNetOrder(&sa, address);
        }

        ipAddr = virSocketAddrFormat(&sa);

        hints = *pai;
        hints.ai_flags = AI_NUMERICHOST;
        hints.ai_family = af;

        if (getaddrinfo(ipAddr, NULL, &hints, &res0)) {
            addrList++;
            continue;
        }

        for (res = res0; res; res = res->ai_next)
            res->ai_flags = pai->ai_flags;

        (*aip)->ai_next = res0;
        while ((*aip)->ai_next)
           *aip = (*aip)->ai_next;

        addrList++;
    }
}

int
_nss_compat_getaddrinfo(void *retval, void *mdata ATTRIBUTE_UNUSED, va_list ap)
{
    struct addrinfo sentinel, *cur, *ai;
    const char *name;

    name  = va_arg(ap, char *);
    ai = va_arg(ap, struct addrinfo *);

    memset(&sentinel, 0, sizeof(sentinel));
    cur = &sentinel;

    if ((ai->ai_family == AF_UNSPEC) || (ai->ai_family == AF_INET6))
        aiforaf(name, AF_INET6, ai, &cur);
    if ((ai->ai_family == AF_UNSPEC) || (ai->ai_family == AF_INET))
        aiforaf(name, AF_INET, ai, &cur);

    if (sentinel.ai_next == NULL) {
        h_errno = HOST_NOT_FOUND;
        return NS_NOTFOUND;
    }
    *((struct addrinfo **)retval) = sentinel.ai_next;

    return NS_SUCCESS;
}

int
_nss_compat_gethostbyname2_r(void *retval, void *mdata ATTRIBUTE_UNUSED, va_list ap)
{
    int ret;

    const char *name;
    int af;
    struct hostent *result;
    char *buffer;
    size_t buflen;
    int *errnop;
    int *herrnop;

    name = va_arg(ap, const char *);
    af = va_arg(ap, int);
    result = va_arg(ap, struct hostent *);
    buffer = va_arg(ap, char *);
    buflen = va_arg(ap, size_t);
    errnop = va_arg(ap, int *);
    herrnop = va_arg(ap, int *);

    ret = NSS_NAME(gethostbyname2)(name, af, result, buffer, buflen, errnop, herrnop);
    *(struct hostent **)retval = (ret == NS_SUCCESS) ? result : NULL;

    return ret;
}

ns_mtab*
nss_module_register(const char *name ATTRIBUTE_UNUSED, unsigned int *size,
                    nss_module_unregister_fn *unregister)
{
    *size = sizeof(methods) / sizeof(methods[0]);
    *unregister = NULL;
    return methods;
}
#endif /* HAVE_BSD_NSS */
