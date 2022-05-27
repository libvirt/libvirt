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

#include <yajl/yajl_gen.h>
#include <yajl/yajl_parse.h>

#include "libvirt_nss_macs.h"
#include "libvirt_nss.h"

enum {
    FIND_MACS_STATE_START,
    FIND_MACS_STATE_LIST,
    FIND_MACS_STATE_ENTRY,
    FIND_MACS_STATE_ENTRY_MACS,
};

typedef struct {
    const char *name;
    char ***macs;
    size_t *nmacs;
    int state;

    char *key;
    struct {
        char *name;
        char **macs;
        size_t nmacs;
    } entry;
} findMACsParser;


static int
findMACsParserString(void *ctx,
                     const unsigned char *stringVal,
                     size_t stringLen)
{
    findMACsParser *parser = ctx;

    DEBUG("Parse string state=%d '%.*s' (map key '%s')",
          parser->state, (int)stringLen, (const char *)stringVal,
          NULLSTR(parser->key));
    if (!parser->key)
        return 0;

    if (parser->state == FIND_MACS_STATE_ENTRY) {
        if (strcmp(parser->key, "domain"))
            return 1;

        free(parser->entry.name);
        if (!(parser->entry.name = strndup((char *)stringVal, stringLen)))
            return 0;
    } else if (parser->state == FIND_MACS_STATE_ENTRY_MACS) {
        char **macs;
        if (strcmp(parser->key, "macs"))
            return 1;

        if (!(macs = realloc(parser->entry.macs,
                             sizeof(char *) * (parser->entry.nmacs + 1))))
            return 0;

        parser->entry.macs = macs;
        if (!(macs[parser->entry.nmacs++] = strndup((char *)stringVal, stringLen)))
            return 0;
    } else {
        return 0;
    }
    return 1;
}


static int
findMACsParserMapKey(void *ctx,
                     const unsigned char *stringVal,
                     size_t stringLen)
{
    findMACsParser *parser = ctx;

    DEBUG("Parse map key state=%d '%.*s'",
          parser->state, (int)stringLen, (const char *)stringVal);

    free(parser->key);
    if (!(parser->key = strndup((char *)stringVal, stringLen)))
        return 0;

    return 1;
}


static int
findMACsParserStartMap(void *ctx)
{
    findMACsParser *parser = ctx;

    DEBUG("Parse start map state=%d", parser->state);

    if (parser->state != FIND_MACS_STATE_LIST)
        return 0;

    free(parser->key);
    parser->key = NULL;
    parser->state = FIND_MACS_STATE_ENTRY;

    return 1;
}


static int
findMACsParserEndMap(void *ctx)
{
    findMACsParser *parser = ctx;
    size_t i;

    DEBUG("Parse end map state=%d", parser->state);

    if (parser->entry.name == NULL)
        return 0;

    if (parser->state != FIND_MACS_STATE_ENTRY)
        return 0;

    if (!strcasecmp(parser->entry.name, parser->name)) {
        char **macs = realloc(*parser->macs,
                              sizeof(char *) * ((*parser->nmacs) + parser->entry.nmacs));
        if (!macs)
            return 0;

        *parser->macs = macs;
        for (i = 0; i < parser->entry.nmacs; i++)
            (*parser->macs)[(*parser->nmacs)++] = parser->entry.macs[i];
    } else {
        for (i = 0; i < parser->entry.nmacs; i++)
            free(parser->entry.macs[i]);
    }
    free(parser->entry.macs);
    parser->entry.macs = NULL;
    parser->entry.nmacs = 0;

    parser->state = FIND_MACS_STATE_LIST;

    return 1;
}


static int
findMACsParserStartArray(void *ctx)
{
    findMACsParser *parser = ctx;

    DEBUG("Parse start array state=%d", parser->state);

    if (parser->state == FIND_MACS_STATE_START)
        parser->state = FIND_MACS_STATE_LIST;
    else if (parser->state == FIND_MACS_STATE_ENTRY)
        parser->state = FIND_MACS_STATE_ENTRY_MACS;
    else
        return 0;

    return 1;
}


static int
findMACsParserEndArray(void *ctx)
{
    findMACsParser *parser = ctx;

    DEBUG("Parse end array state=%d", parser->state);

    if (parser->state == FIND_MACS_STATE_LIST)
        parser->state = FIND_MACS_STATE_START;
    else if (parser->state == FIND_MACS_STATE_ENTRY_MACS)
        parser->state = FIND_MACS_STATE_ENTRY;
    else
        return 0;

    return 1;
}


int
findMACs(const char *file,
         const char *name,
         char ***macs,
         size_t *nmacs)
{
    int fd = -1;
    int ret = -1;
    const yajl_callbacks parserCallbacks = {
        NULL, /* null */
        NULL, /* bool */
        NULL, /* integer */
        NULL, /* double */
        NULL, /* number */
        findMACsParserString,
        findMACsParserStartMap,
        findMACsParserMapKey,
        findMACsParserEndMap,
        findMACsParserStartArray,
        findMACsParserEndArray,
    };
    findMACsParser parserState = {
        .name = name,
        .macs = macs,
        .nmacs = nmacs,
    };
    yajl_handle parser = NULL;
    char line[1024];
    size_t i;
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

        if (yajl_parse(parser, (const unsigned char *)line, rv)  !=
            yajl_status_ok) {
            unsigned char *err = yajl_get_error(parser, 1,
                                                (const unsigned char*)line, rv);
            ERROR("Parse failed %s", (const char *) err);
            yajl_free_error(parser, err);
            goto cleanup;
        }
    }

    if (yajl_complete_parse(parser) != yajl_status_ok) {
        ERROR("Parse failed %s",
              yajl_get_error(parser, 1, NULL, 0));
        goto cleanup;
    }

    ret = 0;

 cleanup:
    if (ret != 0) {
        for (i = 0; i < *nmacs; i++) {
            char *mac = (*macs)[i];
            free(mac);
        }
        free(*macs);
        *macs = NULL;
        *nmacs = 0;
    }
    if (parser)
        yajl_free(parser);
    for (i = 0; i < parserState.entry.nmacs; i++)
        free(parserState.entry.macs[i]);
    free(parserState.entry.macs);
    free(parserState.entry.name);
    free(parserState.key);
    if (fd != -1)
        close(fd);
    return ret;
}
