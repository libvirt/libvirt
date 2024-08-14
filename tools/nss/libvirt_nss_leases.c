/*
 * libvirt_nss_leases.c: Name Service Switch plugin lease file parser
 *
 * Copyright (C) 2019 Red Hat, Inc.
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

#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <fcntl.h>

#include <json.h>

#include "libvirt_nss_leases.h"
#include "libvirt_nss.h"


static int
appendAddr(const char *name __attribute__((unused)),
           leaseAddress **tmpAddress,
           size_t *ntmpAddress,
           const char *ipAddr,
           long long expirytime,
           int af)
{
    int family;
    size_t i;
    struct addrinfo hints = {0};
    struct addrinfo *res = NULL;
    union {
        struct sockaddr sa;
        struct sockaddr_in sin;
        struct sockaddr_in6 sin6;
    } sa;
    unsigned char addr[16];
    int err;
    leaseAddress *newAddr;

    DEBUG("IP address: %s", ipAddr);

    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = AI_NUMERICHOST;

    if ((err = getaddrinfo(ipAddr, NULL, &hints, &res)) != 0) {
        ERROR("Cannot parse socket address '%s': %s",
              ipAddr, gai_strerror(err));
        return -1;
    }

    if (!res) {
        ERROR("No resolved address for '%s'", ipAddr);
        return -1;
    }
    family = res->ai_family;
    memcpy(&sa, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);

    if (family == AF_INET) {
        memcpy(addr, &sa.sin.sin_addr, sizeof(sa.sin.sin_addr));
    } else if (family == AF_INET6) {
        memcpy(addr, &sa.sin6.sin6_addr, sizeof(sa.sin6.sin6_addr));
    } else {
        DEBUG("Skipping unexpected family %d", family);
        return 0;
    }

    if (af != AF_UNSPEC && af != family) {
        DEBUG("Skipping address which family is %d, %d requested", family, af);
        return 0;
    }

    for (i = 0; i < *ntmpAddress; i++) {
        if (family == AF_INET) {
            if ((*tmpAddress)[i].af == AF_INET &&
                memcmp((*tmpAddress)[i].addr,
                       &sa.sin.sin_addr,
                       sizeof(sa.sin.sin_addr)) == 0) {
                DEBUG("IP address already in the list");
                return 0;
            }
        } else {
            if ((*tmpAddress)[i].af == AF_INET6 &&
                memcmp((*tmpAddress)[i].addr,
                       &sa.sin6.sin6_addr,
                       sizeof(sa.sin6.sin6_addr)) == 0) {
                DEBUG("IP address already in the list");
                return 0;
            }
        }
    }

    newAddr = realloc(*tmpAddress, sizeof(*newAddr) * (*ntmpAddress + 1));
    if (!newAddr) {
        ERROR("Out of memory");
        return -1;
    }
    *tmpAddress = newAddr;

    (*tmpAddress)[*ntmpAddress].expirytime = expirytime;
    (*tmpAddress)[*ntmpAddress].af = family;
    if (family == AF_INET)
        memcpy((*tmpAddress)[*ntmpAddress].addr,
               &sa.sin.sin_addr,
               sizeof(sa.sin.sin_addr));
    else
        memcpy((*tmpAddress)[*ntmpAddress].addr,
               &sa.sin6.sin6_addr,
               sizeof(sa.sin6.sin6_addr));
    (*ntmpAddress)++;
    return 0;
}


/**
 * findLeaseInJSON
 *
 * @jobj: the json object containing the leases
 * @name: the requested hostname (optional if a MAC address is present)
 * @macs: the array of MAC addresses we're matching (optional if we have a hostname)
 * @nmacs: the size of the MAC array
 * @af: the requested address family
 * @now: current time (to eliminate expired leases)
 * @addrs: the returned matching addresses
 * @naddrs: size of the returned array
 * @found: whether a match was found
 *
 * Returns 0 even if nothing was found
 *        -1 on error
 */
static int
findLeaseInJSON(json_object *jobj,
                const char *name,
                char **macs,
                size_t nmacs,
                int af,
                time_t now,
                leaseAddress **addrs,
                size_t *naddrs,
                bool *found)
{
    size_t i;
    int len;

    if (!json_object_is_type(jobj, json_type_array)) {
        ERROR("parsed JSON does not contain the leases array");
        return -1;
    }

    len = json_object_array_length(jobj);
    for (i = 0; i < len; i++) {
        json_object *lease = NULL;
        json_object *expiry = NULL;
        json_object *ipobj = NULL;
        unsigned long long expiryTime;
        const char *ipaddr;

        lease = json_object_array_get_idx(jobj, i);

        if (macs) {
            const char *macAddr;
            bool match = false;
            json_object *val;
            size_t j;

            val = json_object_object_get(lease, "mac-address");
            if (!val)
                continue;

            macAddr = json_object_get_string(val);
            if (!macAddr)
                continue;

            for (j = 0; j < nmacs; j++) {
                if (strcmp(macs[j], macAddr) == 0) {
                    match = true;
                    break;
                }
            }
            if (!match)
                continue;
        } else {
            const char *leaseName;
            json_object *val;

            val = json_object_object_get(lease, "hostname");
            if (!val)
                continue;

            leaseName = json_object_get_string(val);
            if (!leaseName)
                continue;

            if (strcasecmp(leaseName, name) != 0)
                continue;
        }

        expiry = json_object_object_get(lease, "expiry-time");
        if (!expiry) {
            ERROR("Missing expiry time for %s", name);
            return -1;
        }

        expiryTime = json_object_get_uint64(expiry);
        if (expiryTime > 0 && expiryTime < now) {
            DEBUG("Skipping expired lease for %s", name);
            continue;
        }

        ipobj = json_object_object_get(lease, "ip-address");
        if (!ipobj) {
            DEBUG("Missing IP address for %s", name);
            continue;
        }
        ipaddr = json_object_get_string(ipobj);

        DEBUG("Found record for %s", name);
        *found = true;

        if (appendAddr(name,
                       addrs, naddrs,
                       ipaddr,
                       expiryTime,
                       af) < 0)
            return -1;
    }

    return 0;
}


int
findLeases(const char *file,
           const char *name,
           char **macs,
           size_t nmacs,
           int af,
           time_t now,
           leaseAddress **addrs,
           size_t *naddrs,
           bool *found)
{
    int fd = -1;
    int ret = -1;
    json_object *jobj = NULL;
    json_tokener *tok = NULL;
    enum json_tokener_error jerr;
    int jsonflags = JSON_TOKENER_STRICT | JSON_TOKENER_VALIDATE_UTF8;
    char line[1024];
    ssize_t nreadTotal = 0;
    int rv;

    if ((fd = open(file, O_RDONLY)) < 0) {
        ERROR("Cannot open %s", file);
        goto cleanup;
    }

    tok = json_tokener_new();
    json_tokener_set_flags(tok, jsonflags);

    do {
        rv = read(fd, line, sizeof(line));
        if (rv < 0)
            goto cleanup;
        if (rv == 0)
            break;
        nreadTotal += rv;

        jobj = json_tokener_parse_ex(tok, line, rv);
        jerr = json_tokener_get_error(tok);
    } while (jerr == json_tokener_continue);

    if (jerr == json_tokener_continue) {
        ERROR("Cannot parse %s: incomplete json found", file);
        goto cleanup;
    }

    if (nreadTotal > 0 && jerr != json_tokener_success) {
        ERROR("Cannot parse %s: %s", file, json_tokener_error_desc(jerr));
        goto cleanup;
    }

    ret = findLeaseInJSON(jobj, name, macs, nmacs, af, now,
                          addrs, naddrs, found);

 cleanup:
    json_object_put(jobj);
    json_tokener_free(tok);
    if (ret != 0) {
        free(*addrs);
        *addrs = NULL;
        *naddrs = 0;
    }
    if (fd != -1)
        close(fd);
    return ret;
}
