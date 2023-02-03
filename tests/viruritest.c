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
 */

#include <config.h>

#include <signal.h>

#include "testutils.h"
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
    virURIParam *params;
};

static int testURIParse(const void *args)
{
    g_autoptr(virURI) uri = NULL;
    const struct URIParseData *data = args;
    g_autofree char *uristr = NULL;
    size_t i;
    bool fail = false;

    if (!(uri = virURIParse(data->uri)))
        return -1;

    if (STRNEQ(uri->scheme, data->scheme)) {
        VIR_TEST_DEBUG("Expected scheme '%s', actual '%s'",
                       data->scheme, uri->scheme);
        fail = true;
    }

    if (STRNEQ(uri->server, data->server)) {
        VIR_TEST_DEBUG("Expected server '%s', actual '%s'",
                       data->server, uri->server);
        fail = true;
    }

    if (uri->port != data->port) {
        VIR_TEST_DEBUG("Expected port '%d', actual '%d'",
                       data->port, uri->port);
        fail = true;
    }

    if (STRNEQ_NULLABLE(uri->path, data->path)) {
        VIR_TEST_DEBUG("Expected path '%s', actual '%s'",
                       data->path, uri->path);
        fail = true;
    }

    if (STRNEQ_NULLABLE(uri->query, data->query)) {
        VIR_TEST_DEBUG("Expected query '%s', actual '%s'",
                       data->query, uri->query);
        fail = true;
    }

    if (STRNEQ_NULLABLE(uri->fragment, data->fragment)) {
        VIR_TEST_DEBUG("Expected fragment '%s', actual '%s'",
                       data->fragment, uri->fragment);
        fail = true;
    }

    for (i = 0; data->params && data->params[i].name && i < uri->paramsCount; i++) {
        if (STRNEQ_NULLABLE(data->params[i].name, uri->params[i].name)) {
            VIR_TEST_DEBUG("Expected param name %zu '%s', actual '%s'",
                           i, data->params[i].name, uri->params[i].name);
            fail = true;
        }
        if (STRNEQ_NULLABLE(data->params[i].value, uri->params[i].value)) {
            VIR_TEST_DEBUG("Expected param value %zu '%s', actual '%s'",
                           i, data->params[i].value, uri->params[i].value);
            fail = true;
        }
    }
    if (data->params && data->params[i].name) {
        VIR_TEST_DEBUG("Missing parameter %zu %s=%s",
                       i, data->params[i].name, data->params[i].value);
        fail = true;
    }
    if (i != uri->paramsCount) {
        for (; i < uri->paramsCount; i++) {
            VIR_TEST_DEBUG("Unexpected parameter %zu %s=%s",
                           i, uri->params[i].name, uri->params[i].value);
        }
        fail = true;
    }

    VIR_FREE(uri->query);
    uri->query = virURIFormatParams(uri);

    uristr = virURIFormat(uri);

    if (STRNEQ(uristr, data->uri_out)) {
        VIR_TEST_DEBUG("URI did not roundtrip, expect '%s', actual '%s'",
                       data->uri_out, uristr);
        fail = true;
    }

    if (fail)
        return -1;

    return 0;
}


static int
mymain(void)
{
    int ret = 0;

#ifndef WIN32
    signal(SIGPIPE, SIG_IGN);
#endif /* WIN32 */

#define TEST_FULL(uri, uri_out, scheme, server, port, path, query, \
                  fragment, user, params) \
    do  { \
        const struct URIParseData data = { \
            uri, (uri_out) ? (uri_out) : (uri), scheme, server, port, \
            path, query, fragment, user, params \
        }; \
        if (virTestRun("Test URI " # uri, testURIParse, &data) < 0) \
            ret = -1; \
    } while (0)
#define TEST_PARSE(uri, scheme, server, port, path, query, fragment, user, params) \
    TEST_FULL(uri, NULL, scheme, server, port, path, query, fragment, user, params)
#define TEST_PARAMS(query_in, query_out, params) \
    TEST_FULL("test://example.com/?" query_in, \
              *query_out ? "test://example.com/?" query_out : NULL, \
              "test", "example.com", 0, "/", query_in, NULL, NULL, params)

    VIR_WARNINGS_NO_DECLARATION_AFTER_STATEMENT
    virURIParam params[] = {
        { (char*)"name", (char*)"value", false },
        { NULL, NULL, false },
    };

    TEST_PARSE("test://example.com", "test", "example.com", 0, NULL, NULL, NULL, NULL, NULL);
    TEST_PARSE("test://foo@example.com", "test", "example.com", 0, NULL, NULL, NULL, "foo", NULL);
    TEST_PARSE("test://foo:pass@example.com", "test", "example.com", 0, NULL, NULL, NULL, "foo:pass", NULL);
    TEST_PARSE("test://example.com:123", "test", "example.com", 123, NULL, NULL, NULL, NULL, NULL);
    TEST_PARSE("test://example.com:123/system?name=value#foo", "test", "example.com", 123, "/system", "name=value", "foo", NULL, params);
    TEST_PARSE("test://127.0.0.1:123/system", "test", "127.0.0.1", 123, "/system", NULL, NULL, NULL, NULL);
    TEST_PARSE("test://[::1]:123/system", "test", "::1", 123, "/system", NULL, NULL, NULL, NULL);
    TEST_PARSE("test://[2001:41c8:1:4fd4::2]:123/system", "test", "2001:41c8:1:4fd4::2", 123, "/system", NULL, NULL, NULL, NULL);
    TEST_PARSE("gluster+rdma://example.com:1234/gv0/vol.img", "gluster+rdma", "example.com", 1234, "/gv0/vol.img", NULL, NULL, NULL, NULL);

    virURIParam spiceparams[] = {
        { (char *) "tlsSubject", (char *) "C=XX,L=Testtown,O=Test Company,CN=tester.test", false },
        { NULL, NULL, false },
    };
    TEST_FULL("spice://[3ffe::104]:5900/?tlsSubject=C=XX,L=Testtown,O=Test%20Company,CN=tester.test",
              "spice://[3ffe::104]:5900/?tlsSubject=C%3DXX%2CL%3DTesttown%2CO%3DTest%20Company%2CCN%3Dtester.test",
              "spice", "3ffe::104", 5900, "/", "tlsSubject=C=XX,L=Testtown,O=Test%20Company,CN=tester.test", NULL, NULL, spiceparams);

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
    virURIParam params3[] = {
        { (char*)"foo", (char*)"&one", false },
        { (char*)"bar", (char*)"&two", false },
        { NULL, NULL, false },
    };
    virURIParam params4[] = {
        { (char*)"foo", (char*)"", false },
        { NULL, NULL, false },
    };
    virURIParam params5[] = {
        { (char*)"foo", (char*)"one two", false },
        { NULL, NULL, false },
    };
    virURIParam params6[] = {
        { (char*)"foo", (char*)"one", false },
        { NULL, NULL, false },
    };
    VIR_WARNINGS_RESET

    TEST_PARAMS("foo=one&bar=two", "", params1);
    TEST_PARAMS("foo=one&foo=two", "", params2);
    TEST_PARAMS("foo=one&&foo=two", "foo=one&foo=two", params2);
    TEST_PARAMS("foo=one;foo=two", "foo=one&foo=two", params2);
    TEST_PARAMS("foo=%26one&bar=%26two", "", params3);
    TEST_PARAMS("foo", "foo=", params4);
    TEST_PARAMS("foo=", "", params4);
    TEST_PARAMS("foo=&", "foo=", params4);
    TEST_PARAMS("foo=&&", "foo=", params4);
    TEST_PARAMS("foo=one%20two", "", params5);
    TEST_PARAMS("=bogus&foo=one", "foo=one", params6);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
