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

#include <yajl/yajl_gen.h>
#include <yajl/yajl_parse.h>

#include "libvirt_nss_leases.h"
#include "libvirt_nss.h"

enum {
    FIND_LEASES_STATE_START,
    FIND_LEASES_STATE_LIST,
    FIND_LEASES_STATE_ENTRY,
};


typedef struct {
    const char *name;
    char **macs;
    size_t nmacs;
    int state;
    unsigned long long now;
    int af;
    bool *found;
    leaseAddress **addrs;
    size_t *naddrs;

    char *key;
    struct {
        unsigned long long expiry;
        char *ipaddr;
        char *macaddr;
        char *hostname;
    } entry;
} findLeasesParser;


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


static int
findLeasesParserInteger(void *ctx,
                        long long val)
{
    findLeasesParser *parser = ctx;

    DEBUG("Parse int state=%d '%lld' (map key '%s')",
          parser->state, val, NULLSTR(parser->key));
    if (!parser->key)
        return 0;

    if (parser->state == FIND_LEASES_STATE_ENTRY) {
        if (strcmp(parser->key, "expiry-time"))
            return 0;

        parser->entry.expiry = val;
    } else {
        return 0;
    }
    return 1;
}


static int
findLeasesParserString(void *ctx,
                       const unsigned char *stringVal,
                       size_t stringLen)
{
    findLeasesParser *parser = ctx;

    DEBUG("Parse string state=%d '%.*s' (map key '%s')",
          parser->state, (int)stringLen, (const char *)stringVal,
          NULLSTR(parser->key));
    if (!parser->key)
        return 0;

    if (parser->state == FIND_LEASES_STATE_ENTRY) {
        if (!strcmp(parser->key, "ip-address")) {
            if (!(parser->entry.ipaddr = strndup((char *)stringVal, stringLen)))
                return 0;
        } else if (!strcmp(parser->key, "mac-address")) {
            if (!(parser->entry.macaddr = strndup((char *)stringVal, stringLen)))
                return 0;
        } else if (!strcmp(parser->key, "hostname")) {
            if (!(parser->entry.hostname = strndup((char *)stringVal, stringLen)))
                return 0;
        } else {
            return 1;
        }
    } else {
        return 0;
    }
    return 1;
}


static int
findLeasesParserMapKey(void *ctx,
                       const unsigned char *stringVal,
                       size_t stringLen)
{
    findLeasesParser *parser = ctx;

    DEBUG("Parse map key state=%d '%.*s'",
          parser->state, (int)stringLen, (const char *)stringVal);

    free(parser->key);
    if (!(parser->key = strndup((char *)stringVal, stringLen)))
        return 0;

    return 1;
}


static int
findLeasesParserStartMap(void *ctx)
{
    findLeasesParser *parser = ctx;

    DEBUG("Parse start map state=%d", parser->state);

    if (parser->state != FIND_LEASES_STATE_LIST)
        return 0;

    free(parser->key);
    parser->key = NULL;
    parser->state = FIND_LEASES_STATE_ENTRY;

    return 1;
}


static int
findLeasesParserEndMap(void *ctx)
{
    findLeasesParser *parser = ctx;
    size_t i;
    bool found = false;

    DEBUG("Parse end map state=%d", parser->state);

    if (parser->entry.macaddr == NULL)
        return 0;

    if (parser->state != FIND_LEASES_STATE_ENTRY)
        return 0;

    if (parser->nmacs) {
        DEBUG("Check %zu macs", parser->nmacs);
        for (i = 0; i < parser->nmacs && !found; i++) {
            DEBUG("Check mac '%s' vs '%s'", parser->macs[i], NULLSTR(parser->entry.macaddr));
            if (parser->entry.macaddr && !strcmp(parser->macs[i], parser->entry.macaddr))
                found = true;
        }
    } else {
        DEBUG("Check name '%s' vs '%s'", parser->name, NULLSTR(parser->entry.hostname));
        if (parser->entry.hostname && !strcasecmp(parser->name, parser->entry.hostname))
            found = true;
    }
    DEBUG("Found %d", found);
    if (parser->entry.expiry != 0 &&
        parser->entry.expiry < parser->now) {
        DEBUG("Entry expired at %llu vs now %llu",
              parser->entry.expiry, parser->now);
        found = false;
    }
    if (!parser->entry.ipaddr)
        found = false;

    if (found) {
        *parser->found = true;

        if (appendAddr(parser->name,
                       parser->addrs, parser->naddrs,
                       parser->entry.ipaddr,
                       parser->entry.expiry,
                       parser->af) < 0)
            return 0;
    }

    free(parser->entry.macaddr);
    free(parser->entry.ipaddr);
    free(parser->entry.hostname);
    parser->entry.expiry = 0;
    parser->entry.macaddr = NULL;
    parser->entry.ipaddr = NULL;
    parser->entry.hostname = NULL;

    parser->state = FIND_LEASES_STATE_LIST;

    return 1;
}


static int
findLeasesParserStartArray(void *ctx)
{
    findLeasesParser *parser = ctx;

    DEBUG("Parse start array state=%d", parser->state);

    if (parser->state == FIND_LEASES_STATE_START) {
        parser->state = FIND_LEASES_STATE_LIST;
    } else {
        return 0;
    }

    return 1;
}


static int
findLeasesParserEndArray(void *ctx)
{
    findLeasesParser *parser = ctx;

    DEBUG("Parse end array state=%d", parser->state);

    if (parser->state == FIND_LEASES_STATE_LIST)
        parser->state = FIND_LEASES_STATE_START;
    else
        return 0;

    return 1;
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
    const yajl_callbacks parserCallbacks = {
        NULL, /* null */
        NULL, /* bool */
        findLeasesParserInteger,
        NULL, /* double */
        NULL, /* number */
        findLeasesParserString,
        findLeasesParserStartMap,
        findLeasesParserMapKey,
        findLeasesParserEndMap,
        findLeasesParserStartArray,
        findLeasesParserEndArray,
    };
    findLeasesParser parserState = {
        .name = name,
        .macs = macs,
        .nmacs = nmacs,
        .af = af,
        .now = now,
        .found = found,
        .addrs = addrs,
        .naddrs = naddrs,
    };
    yajl_handle parser = NULL;
    char line[1024];
    ssize_t nreadTotal = 0;
    int rv;

    if ((fd = open(file, O_RDONLY)) < 0) {
        ERROR("Cannot open %s", file);
        goto cleanup;
    }

    parser = yajl_alloc(&parserCallbacks, NULL, &parserState);
    if (!parser) {
        ERROR("Unable to create JSON parser");
        goto cleanup;
    }

    while (1) {
        rv = read(fd, line, sizeof(line));
        if (rv < 0)
            goto cleanup;
        if (rv == 0)
            break;
        nreadTotal += rv;

        if (yajl_parse(parser, (const unsigned char *)line, rv)  !=
            yajl_status_ok) {
            unsigned char *err = yajl_get_error(parser, 1,
                                                (const unsigned char*)line, rv);
            ERROR("Parse failed %s", (const char *) err);
            yajl_free_error(parser, err);
            goto cleanup;
        }
    }

    if (nreadTotal > 0 &&
        yajl_complete_parse(parser) != yajl_status_ok) {
        ERROR("Parse failed %s",
              yajl_get_error(parser, 1, NULL, 0));
        goto cleanup;
    }

    ret = 0;

 cleanup:
    if (ret != 0) {
        free(*addrs);
        *addrs = NULL;
        *naddrs = 0;
    }
    if (parser)
        yajl_free(parser);
    free(parserState.entry.ipaddr);
    free(parserState.entry.macaddr);
    free(parserState.entry.hostname);
    free(parserState.key);
    if (fd != -1)
        close(fd);
    return ret;
}
