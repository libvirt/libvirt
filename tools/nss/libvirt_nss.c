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

#include <resolv.h>
#include <sys/types.h>
#include <dirent.h>
#include <arpa/inet.h>

#include "virlease.h"
#include "viralloc.h"
#include "virfile.h"
#include "virerror.h"
#include "virstring.h"
#include "virsocketaddr.h"
#include "configmake.h"

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

#define ALIGN(x) (((x) + __SIZEOF_POINTER__ - 1) & ~(__SIZEOF_POINTER__ - 1))
#define FAMILY_ADDRESS_SIZE(family) ((family) == AF_INET6 ? 16 : 4)

typedef struct {
    unsigned char addr[16];
    int af;
} leaseAddress;

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
    ssize_t i, nleases;
    leaseAddress *tmpAddress = NULL;
    size_t ntmpAddress = 0;

    *address = NULL;
    *naddress = 0;
    *found = false;

    if (af != AF_UNSPEC && af != AF_INET && af != AF_INET6) {
        errno = EAFNOSUPPORT;
        goto cleanup;
    }


    if (!(dir = opendir(leaseDir))) {
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

        if (entry->d_name[0] == '.')
            continue;

        if (!virFileHasSuffix(entry->d_name, ".status"))
            continue;

        if (!(path = virFileBuildPath(leaseDir, entry->d_name, NULL)))
            goto cleanup;

        DEBUG("Processing %s", path);

        if (virLeaseReadCustomLeaseFile(leases_array, path, NULL, NULL) < 0) {
            ERROR("Unable to parse %s", path);
            VIR_FREE(path);
            goto cleanup;
        }

        VIR_FREE(path);
    }

    closedir(dir);
    dir = NULL;

    nleases = virJSONValueArraySize(leases_array);
    DEBUG("Read %zd leases", nleases);

    for (i = 0; i < nleases; i++) {
        virJSONValuePtr lease;
        const char *lease_name;
        virSocketAddr sa;
        const char *ipAddr;
        int family;

        lease = virJSONValueArrayGet(leases_array, i);

        if (!lease) {
            /* This should never happen (TM) */
            ERROR("Unable to get element %zd of %zd", i, nleases);
            goto cleanup;
        }

        lease_name = virJSONValueObjectGetString(lease, "hostname");

        if (STRNEQ_NULLABLE(name, lease_name))
            continue;

        DEBUG("Found record for %s", lease_name);
        *found = true;

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
            continue;
        }

        if (VIR_REALLOC_N_QUIET(tmpAddress, ntmpAddress + 1) < 0) {
            ERROR("Out of memory");
            goto cleanup;
        }

        tmpAddress[ntmpAddress].af = family;
        memcpy(tmpAddress[ntmpAddress].addr,
               (family == AF_INET ?
                (void *) &sa.data.inet4.sin_addr.s_addr :
                (void *) &sa.data.inet6.sin6_addr.s6_addr),
               FAMILY_ADDRESS_SIZE(family));
        ntmpAddress++;
    }

    *address = tmpAddress;
    *naddress = ntmpAddress;
    tmpAddress = NULL;
    ntmpAddress = 0;

    ret = 0;

 cleanup:
    *errnop = errno;
    VIR_FREE(tmpAddress);
    virJSONValueFree(leases_array);
    if (dir)
        closedir(dir);
    return ret;
}


enum nss_status
_nss_libvirt_gethostbyname_r(const char *name, struct hostent *result,
                             char *buffer, size_t buflen, int *errnop,
                             int *herrnop)
{
    int af = ((_res.options & RES_USE_INET6) ? AF_INET6 : AF_INET);

    return _nss_libvirt_gethostbyname3_r(name, af, result, buffer, buflen,
                                         errnop, herrnop, NULL, NULL);
}

enum nss_status
_nss_libvirt_gethostbyname2_r(const char *name, int af, struct hostent *result,
                              char *buffer, size_t buflen, int *errnop,
                              int *herrnop)
{
    return _nss_libvirt_gethostbyname3_r(name, af, result, buffer, buflen,
                                         errnop, herrnop, NULL, NULL);
}

static inline void *
move_and_align(void *buf, size_t len, size_t *idx)
{
    char *buffer = buf;
    size_t move = ALIGN(len);

    if (!idx)
        return buffer + move;

    *idx += move;

    return buffer + *idx;
}

enum nss_status
_nss_libvirt_gethostbyname3_r(const char *name, int af, struct hostent *result,
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
    need = ALIGN(nameLen + 1) + naddr * ALIGN(alen) + (naddr + 2) * sizeof(char*);

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

enum nss_status
_nss_libvirt_gethostbyname4_r(const char *name, struct gaih_addrtuple **pat,
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
    need = ALIGN(nameLen + 1) + naddr * ALIGN(sizeof(struct gaih_addrtuple));

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
