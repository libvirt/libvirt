/*
 * Copyright (C) 2012 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include <stdlib.h>
#include <signal.h>

#include "testutils.h"
#include "util.h"
#include "virterror_internal.h"
#include "memory.h"
#include "logging.h"

#include "viruri.h"

#define VIR_FROM_THIS VIR_FROM_RPC

struct URIParseData {
    const char *uri;
    const char *scheme;
    const char *server;
    int port;
    const char *path;
    const char *query;
    const char *fragment;
};

static int testURIParse(const void *args)
{
    int ret = -1;
    virURIPtr uri = NULL;
    const struct URIParseData *data = args;
    char *uristr;

    if (!(uri = virURIParse(data->uri))) {
        virReportOOMError();
        goto cleanup;
    }

    if (!(uristr = virURIFormat(uri))) {
        virReportOOMError();
        goto cleanup;
    }

    if (!STREQ(uristr, data->uri)) {
        VIR_DEBUG("URI did not roundtrip, expect '%s', actual '%s'",
                  data->uri, uristr);
        goto cleanup;
    }

    if (!STREQ(uri->scheme, data->scheme)) {
        VIR_DEBUG("Expected scheme '%s', actual '%s'",
                  data->scheme, uri->scheme);
        goto cleanup;
    }

    if (!STREQ(uri->server, data->server)) {
        VIR_DEBUG("Expected server '%s', actual '%s'",
                  data->server, uri->server);
        goto cleanup;
    }

    if (uri->port != data->port) {
        VIR_DEBUG("Expected port '%d', actual '%d'",
                  data->port, uri->port);
        goto cleanup;
    }

    if (!STREQ_NULLABLE(uri->path, data->path)) {
        VIR_DEBUG("Expected path '%s', actual '%s'",
                  data->path, uri->path);
        goto cleanup;
    }

    if (!STREQ_NULLABLE(uri->query, data->query)) {
        VIR_DEBUG("Expected query '%s', actual '%s'",
                  data->query, uri->query);
        goto cleanup;
    }

    if (!STREQ_NULLABLE(uri->fragment, data->fragment)) {
        VIR_DEBUG("Expected fragment '%s', actual '%s'",
                  data->fragment, uri->fragment);
        goto cleanup;
    }

    ret = 0;
cleanup:
    VIR_FREE(uristr);
    xmlFreeURI(uri);
    return ret;
}


static int
mymain(void)
{
    int ret = 0;

    signal(SIGPIPE, SIG_IGN);

#define TEST_PARSE(uri, scheme, server, port, path, query, fragment)    \
    do  {                                                               \
        const struct URIParseData data = {                              \
            uri, scheme, server, port, path, query, fragment            \
        };                                                              \
        if (virtTestRun("Test IPv6 " # uri,  1, testURIParse, &data) < 0) \
            ret = -1;                                                   \
    } while (0)

    TEST_PARSE("test://example.com", "test", "example.com", 0, NULL, NULL, NULL);
    TEST_PARSE("test://example.com:123", "test", "example.com", 123, NULL, NULL, NULL);
    TEST_PARSE("test://example.com:123/system?name=value#foo", "test", "example.com", 123, "/system", "name=value", "foo");
    TEST_PARSE("test://127.0.0.1:123/system", "test", "127.0.0.1", 123, "/system", NULL, NULL);
    TEST_PARSE("test://[::1]:123/system", "test", "::1", 123, "/system", NULL, NULL);
    TEST_PARSE("test://[2001:41c8:1:4fd4::2]:123/system", "test", "2001:41c8:1:4fd4::2", 123, "/system", NULL, NULL);

    return (ret==0 ? EXIT_SUCCESS : EXIT_FAILURE);
}

VIRT_TEST_MAIN(mymain)
