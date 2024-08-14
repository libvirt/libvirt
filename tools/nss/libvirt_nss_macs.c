/*
 * libvirt_nss_macs.c: Name Service Switch plugin MAC file parser
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
#include <fcntl.h>

#include <json.h>

#include "libvirt_nss_macs.h"
#include "libvirt_nss.h"


/**
 * findMACsFromJSON
 *
 * @jobj: JSON object containing the leases
 * @name: requested hostname
 * @macs: returned array of MAC addresses leased to the hostname
 * @nmacs: size of the returned array
 */
static int
findMACsFromJSON(json_object *jobj,
                 const char *name,
                 char ***macs,
                 size_t *nmacs)
{
    size_t i;
    int len;

    if (!json_object_is_type(jobj, json_type_array)) {
        ERROR("parsed JSON does not contain the leases array");
        return -1;
    }

    len = json_object_array_length(jobj);
    DEBUG("Found an array of length: %zu", len);
    for (i = 0; i < len; i++) {
        json_object *entry = NULL;
        json_object *domain = NULL;
        const char *domainName;
        char **tmpMacs = NULL;
        size_t newmacs = 0;
        json_object *macsArray = NULL;
        size_t j;

        entry = json_object_array_get_idx(jobj, i);
        if (!entry)
            continue;

        DEBUG("Processing item %zu", i);

        domain = json_object_object_get(entry, "domain");
        if (!domain)
            continue;

        domainName = json_object_get_string(domain);
        if (!domainName)
            continue;

        DEBUG("Processing domain %s", domainName);

        if (strcasecmp(domainName, name))
            continue;

        macsArray = json_object_object_get(entry, "macs");
        if (!macsArray)
            continue;

        newmacs = json_object_array_length(macsArray);
        DEBUG("Found %zu MAC addresses", newmacs);

        tmpMacs = realloc(*macs, sizeof(char *) * (*nmacs + newmacs + 1));
        if (!tmpMacs)
            return -1;

        *macs = tmpMacs;

        for (j = 0; j < newmacs; j++) {
            json_object *macobj = NULL;
            char *macstr;

            macobj = json_object_array_get_idx(macsArray, j);
            macstr = strdup(json_object_get_string(macobj));
            if (!macstr)
                return -1;
            (*macs)[(*nmacs)++] = macstr;
        }
    }
    return 0;
}


int
findMACs(const char *file,
         const char *name,
         char ***macs,
         size_t *nmacs)
{
    int fd = -1;
    int ret = -1;
    char line[1024];
    json_object *jobj = NULL;
    json_tokener *tok = NULL;
    enum json_tokener_error jerr;
    int jsonflags = JSON_TOKENER_STRICT | JSON_TOKENER_VALIDATE_UTF8;
    ssize_t nreadTotal = 0;
    int rv;
    size_t i;

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

    ret = findMACsFromJSON(jobj, name, macs, nmacs);

 cleanup:
    json_object_put(jobj);
    json_tokener_free(tok);
    if (ret != 0) {
        for (i = 0; i < *nmacs; i++) {
            char *mac = (*macs)[i];
            free(mac);
        }
        free(*macs);
        *macs = NULL;
        *nmacs = 0;
    }
    if (fd != -1)
        close(fd);
    return ret;
}
