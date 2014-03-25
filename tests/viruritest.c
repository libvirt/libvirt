/*
 * Copyright (C) 2012, 2014 Red Hat, Inc.
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
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include <stdlib.h>
#include <signal.h>

#include "testutils.h"
#include "virerror.h"
#include "viralloc.h"
#include "virlog.h"

#include "viruri.h"

#define VIR_FROM_THIS VIR_FROM_RPC

VIR_LOG_INIT("tests.uritest");

struct URIParseData {
    const char *uri;
    const char *uri_out;
    const char *scheme;
    const char *server;
    int port;
    const char *path;
    const char *query;
    const char *fragment;
    const char *user;
    virURIParamPtr params;
};

static int testURIParse(const void *args)
{
    int ret = -1;
    virURIPtr uri = NULL;
    const struct URIParseData *data = args;
    char *uristr = NULL;
    size_t i;

    if (!(uri = virURIParse(data->uri)))
        goto cleanup;

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

    for (i = 0; data->params && data->params[i].name && i < uri->paramsCount; i++) {
        if (!STREQ_NULLABLE(data->params[i].name, uri->params[i].name)) {
            VIR_DEBUG("Expected param name %zu '%s', actual '%s'",
                      i, data->params[i].name, uri->params[i].name);
            goto cleanup;
        }
        if (!STREQ_NULLABLE(data->params[i].value, uri->params[i].value)) {
            VIR_DEBUG("Expected param value %zu '%s', actual '%s'",
                      i, data->params[i].value, uri->params[i].value);
            goto cleanup;
        }
    }
    if (data->params && data->params[i].name) {
        VIR_DEBUG("Missing parameter %zu %s=%s",
                  i, data->params[i].name, data->params[i].value);
        goto cleanup;
    }
    if (i != uri->paramsCount) {
        VIR_DEBUG("Unexpected parameter %zu %s=%s",
                  i, uri->params[i].name, uri->params[i].value);
        goto cleanup;
    }

    VIR_FREE(uri->query);
    uri->query = virURIFormatParams(uri);

    if (!(uristr = virURIFormat(uri)))
        goto cleanup;

    if (!STREQ(uristr, data->uri_out)) {
        VIR_DEBUG("URI did not roundtrip, expect '%s', actual '%s'",
                  data->uri_out, uristr);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FREE(uristr);
    virURIFree(uri);
    return ret;
}


static int
mymain(void)
{
    int ret = 0;

    signal(SIGPIPE, SIG_IGN);

#define TEST_FULL(uri, uri_out, scheme, server, port, path, query,      \
                  fragment, user, params)                               \
    do  {                                                               \
        const struct URIParseData data = {                              \
            uri, (uri_out) ? (uri_out) : (uri), scheme, server, port,   \
            path, query, fragment, user, params                         \
        };                                                              \
        if (virtTestRun("Test URI " # uri, testURIParse, &data) < 0)    \
            ret = -1;                                                   \
    } while (0)
#define TEST_PARSE(uri, scheme, server, port, path, query, fragment, user, params) \
    TEST_FULL(uri, NULL, scheme, server, port, path, query, fragment, user, params)
#define TEST_PARAMS(query_in, query_out, params)                        \
    TEST_FULL("test://example.com/?" query_in,                          \
              *query_out ? "test://example.com/?" query_out : NULL,     \
              "test", "example.com", 0, "/", query_in, NULL, NULL, params)

    virURIParam params[] = {
        { (char*)"name", (char*)"value", false },
        { NULL, NULL, false },
    };

    TEST_PARSE("test://example.com", "test", "example.com", 0, NULL, NULL, NULL, NULL, NULL);
    TEST_PARSE("test://foo@example.com", "test", "example.com", 0, NULL, NULL, NULL, "foo", NULL);
    TEST_PARSE("test://example.com:123", "test", "example.com", 123, NULL, NULL, NULL, NULL, NULL);
    TEST_PARSE("test://example.com:123/system?name=value#foo", "test", "example.com", 123, "/system", "name=value", "foo", NULL, params);
    TEST_PARSE("test://127.0.0.1:123/system", "test", "127.0.0.1", 123, "/system", NULL, NULL, NULL, NULL);
    TEST_PARSE("test://[::1]:123/system", "test", "::1", 123, "/system", NULL, NULL, NULL, NULL);
    TEST_PARSE("test://[2001:41c8:1:4fd4::2]:123/system", "test", "2001:41c8:1:4fd4::2", 123, "/system", NULL, NULL, NULL, NULL);

    virURIParam params1[] = {
        { (char*)"foo", (char*)"one", false },
        { (char*)"bar", (char*)"two", false },
        { NULL, NULL, false },
    };
    virURIParam params2[] = {
        { (char*)"foo", (char*)"one", false },
        { (char*)"foo", (char*)"two", false },
        { NULL, NULL, false },
    };
#ifdef HAVE_XMLURI_QUERY_RAW
    virURIParam params3[] = {
        { (char*)"foo", (char*)"&one", false },
        { (char*)"bar", (char*)"&two", false },
        { NULL, NULL, false },
    };
#endif
    virURIParam params4[] = {
        { (char*)"foo", (char*)"", false },
        { NULL, NULL, false },
    };
#ifdef HAVE_XMLURI_QUERY_RAW
    virURIParam params5[] = {
        { (char*)"foo", (char*)"one two", false },
        { NULL, NULL, false },
    };
#endif
    virURIParam params6[] = {
        { (char*)"foo", (char*)"one", false },
        { NULL, NULL, false },
    };

    TEST_PARAMS("foo=one&bar=two", "", params1);
    TEST_PARAMS("foo=one&foo=two", "", params2);
    TEST_PARAMS("foo=one&&foo=two", "foo=one&foo=two", params2);
    TEST_PARAMS("foo=one;foo=two", "foo=one&foo=two", params2);
#ifdef HAVE_XMLURI_QUERY_RAW
    TEST_PARAMS("foo=%26one&bar=%26two", "", params3);
#endif
    TEST_PARAMS("foo", "foo=", params4);
    TEST_PARAMS("foo=", "", params4);
    TEST_PARAMS("foo=&", "foo=", params4);
    TEST_PARAMS("foo=&&", "foo=", params4);
#ifdef HAVE_XMLURI_QUERY_RAW
    TEST_PARAMS("foo=one%20two", "", params5);
#endif
    TEST_PARAMS("=bogus&foo=one", "foo=one", params6);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)
