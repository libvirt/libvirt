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
 */
#include <config.h>

#include "libvirt_nss.h"

#include <resolv.h>
#include <sys/types.h>
#include <dirent.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <time.h>


#if defined(WITH_BSD_NSS)
# include <nsswitch.h>
#endif

#include "configmake.h"

#include "libvirt_nss_leases.h"

#if defined(LIBVIRT_NSS_GUEST)
# include "libvirt_nss_macs.h"
#endif /* !LIBVIRT_NSS_GUEST */

#define LEASEDIR LOCALSTATEDIR "/lib/libvirt/dnsmasq/"

#define LIBVIRT_ALIGN(x) (((x) + __SIZEOF_POINTER__ - 1) & ~(__SIZEOF_POINTER__ - 1))
#define FAMILY_ADDRESS_SIZE(family) ((family) == AF_INET6 ? 16 : 4)
#define G_N_ELEMENTS(Array) (sizeof(Array) / sizeof(*(Array)))

static int
leaseAddressSorter(const void *a,
                   const void *b)
{
    const leaseAddress *la = a;
    const leaseAddress *lb = b;

    return lb->expirytime - la->expirytime;
}


static void
sortAddr(leaseAddress *tmpAddress,
         size_t ntmpAddress)
{
    if (tmpAddress)
        qsort(tmpAddress, ntmpAddress, sizeof(*tmpAddress), leaseAddressSorter);
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
    char **leaseFiles = NULL;
    size_t nleaseFiles = 0;
    char **macs = NULL;
    size_t nmacs = 0;
    size_t i;
    time_t now;

    *address = NULL;
    *naddress = 0;
    *found = false;

    if (af != AF_UNSPEC && af != AF_INET && af != AF_INET6) {
        errno = EAFNOSUPPORT;
        goto cleanup;
    }

    dir = opendir(leaseDir);
    if (!dir) {
        ERROR("Failed to open dir '%s'", leaseDir);
        goto cleanup;
    }

    DEBUG("Dir: %s", leaseDir);
    while ((entry = readdir(dir)) != NULL) {
        char *path;
        size_t dlen = strlen(entry->d_name);

        if (dlen >= 7 && !strcmp(entry->d_name + dlen - 7, ".status")) {
            char **tmpLease;
            if (asprintf(&path, "%s/%s", leaseDir, entry->d_name) < 0)
                goto cleanup;

            tmpLease = realloc(leaseFiles, sizeof(char *) * (nleaseFiles + 1));
            if (!tmpLease)
                goto cleanup;
            leaseFiles = tmpLease;
            leaseFiles[nleaseFiles++] = path;
#if defined(LIBVIRT_NSS_GUEST)
        } else if (dlen >= 5 && !strcmp(entry->d_name + dlen - 5, ".macs")) {
            if (asprintf(&path, "%s/%s", leaseDir, entry->d_name) < 0)
                goto cleanup;

            DEBUG("Processing %s", path);
            if (findMACs(path, name, &macs, &nmacs) < 0) {
                free(path);
                goto cleanup;
            }
            free(path);
#endif /* LIBVIRT_NSS_GUEST */
        }

        errno = 0;
    }
    closedir(dir);
    dir = NULL;

#if defined(LIBVIRT_NSS_GUEST)
    DEBUG("Finding with %zu macs", nmacs);
    if (!nmacs)
        goto cleanup;
    for (i = 0; i < nmacs; i++)
        DEBUG("  %s", macs[i]);
#endif

    if ((now = time(NULL)) == (time_t)-1) {
        DEBUG("Failed to get time");
        goto cleanup;
    }

    for (i = 0; i < nleaseFiles; i++) {
        if (findLeases(leaseFiles[i],
                       name, macs, nmacs,
                       af, now,
                       address, naddress,
                       found) < 0)
            goto cleanup;
    }

    DEBUG("Found %zu addresses", *naddress);
    sortAddr(*address, *naddress);

    ret = 0;

 cleanup:
    *errnop = errno;
    for (i = 0; i < nleaseFiles; i++)
        free(leaseFiles[i]);
    free(leaseFiles);
    for (i = 0; i < nmacs; i++)
        free(macs[i]);
    free(macs);
    if (ret < 0) {
        free(*address);
        *address = NULL;
        *naddress = 0;
    }
    if (dir)
        closedir(dir);
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
    free(addr);
    return ret;
}

#ifdef WITH_STRUCT_GAIH_ADDRTUPLE
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
    free(addr);
    return ret;
}
#endif /* WITH_STRUCT_GAIH_ADDRTUPLE */

#if defined(WITH_BSD_NSS)
NSS_METHOD_PROTOTYPE(_nss_compat_getaddrinfo);
NSS_METHOD_PROTOTYPE(_nss_compat_gethostbyname2_r);

ns_mtab methods[] = {
    { NSDB_HOSTS, "getaddrinfo", _nss_compat_getaddrinfo, NULL },
    { NSDB_HOSTS, "gethostbyname", _nss_compat_gethostbyname2_r, NULL },
    { NSDB_HOSTS, "gethostbyname2_r", _nss_compat_gethostbyname2_r, NULL },
};

static void
aiforaf(const char *name,
        int af,
        struct addrinfo *pai,
        struct addrinfo **aip)
{
    struct hostent resolved;
    int err;
    char **addrList;

    /* Note: The do-while blocks in this function are used to scope off large
     * stack allocated buffers, which are not needed at the same time */
    do {
        char buf[1024] = { 0 };
        int herr;

        if (NSS_NAME(gethostbyname2)(name, af, &resolved,
                                     buf, sizeof(buf),
                                     &err, &herr) != NS_SUCCESS)
            return;
    } while (false);

    addrList = resolved.h_addr_list;
    while (*addrList) {
        void *address = *addrList;
        char host[NI_MAXHOST];
        struct addrinfo *res0;
        struct addrinfo *res;

        do  {
            union {
                struct sockaddr sa;
                struct sockaddr_in sin;
                struct sockaddr_in6 sin6;
            } sa = { 0 };
            socklen_t salen;

            if (resolved.h_addrtype == AF_INET) {
                sa.sin.sin_family = AF_INET;
                memcpy(&sa.sin.sin_addr.s_addr,
                       address,
                       FAMILY_ADDRESS_SIZE(AF_INET));
                salen = sizeof(sa.sin);
            } else {
                sa.sin6.sin6_family = AF_INET6;
                memcpy(&sa.sin6.sin6_addr.s6_addr,
                       address,
                       FAMILY_ADDRESS_SIZE(AF_INET6));
                salen = sizeof(sa.sin6);
            }

            err = getnameinfo(&sa.sa, salen,
                              host, sizeof(host),
                              NULL, 0,
                              NI_NUMERICHOST | NI_NUMERICSERV);
        } while (false);

        if (err != 0) {
            ERROR("Cannot convert socket address to string: %s",
                  gai_strerror(err));
            continue;
        }

        do {
            struct addrinfo hints;

            hints = *pai;
            hints.ai_flags = AI_NUMERICHOST;
            hints.ai_family = af;

            err = getaddrinfo(host, NULL, &hints, &res0);
        } while (false);

        if (err != 0) {
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
_nss_compat_getaddrinfo(void *retval,
                        void *mdata __attribute__((unused)),
                        va_list ap)
{
    struct addrinfo sentinel = { 0 };
    struct addrinfo *cur = &sentinel;
    struct addrinfo *ai;
    const char *name;

    name  = va_arg(ap, char *);
    ai = va_arg(ap, struct addrinfo *);

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
_nss_compat_gethostbyname2_r(void *retval,
                             void *mdata __attribute__((unused)),
                             va_list ap)
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
nss_module_register(const char *name __attribute__((unused)),
                    unsigned int *size,
                    nss_module_unregister_fn *unregister)
{
    *size = G_N_ELEMENTS(methods);
    *unregister = NULL;
    return methods;
}
#endif /* WITH_BSD_NSS */
