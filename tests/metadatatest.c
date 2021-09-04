/*
 * Copyright (C) 2013 Red Hat, Inc.
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
 * License along with this library;  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#include "testutils.h"

#include "virerror.h"
#include "virxml.h"

#define VIR_FROM_THIS VIR_FROM_NONE

static const char metadata1[] =
"<derp xmlns:foobar='http://foo.bar/'>\n"
"  <bar>foobar</bar>\n"
"  <foo fooish='blurb'>foofoo</foo>\n"
"  <foobar:baz>zomg</foobar:baz>\n"
"</derp>";


static const char metadata1_ns[] =
"<herp:derp xmlns:foobar='http://foo.bar/' xmlns:herp='http://herp.derp/'>\n"
"  <herp:bar>foobar</herp:bar>\n"
"  <herp:foo fooish='blurb'>foofoo</herp:foo>\n"
"  <foobar:baz>zomg</foobar:baz>\n"
"</herp:derp>";


static const char metadata2[] =
"<foo>\n"
"  <bar>baz</bar>\n"
"</foo>";


static const char metadata2_ns[] =
"<blurb:foo xmlns:blurb='http://herp.derp/'>\n"
"  <blurb:bar>baz</blurb:bar>\n"
"</blurb:foo>";


static char *
getMetadataFromXML(virDomainPtr dom)
{
    g_autoptr(xmlDoc) doc = NULL;
    g_autoptr(xmlXPathContext) ctxt = NULL;
    xmlNodePtr node;

    g_autofree char *xml = NULL;

    if (!(xml = virDomainGetXMLDesc(dom, 0)))
        return NULL;

    if (!(doc = virXMLParseStringCtxt(xml, "(domain_definition)", &ctxt)))
        return NULL;

    if (!(node = virXPathNode("//metadata/*", ctxt)))
        return NULL;

    return virXMLNodeToString(node->doc, node);
}


static void
metadataXMLConvertApostrophe(char *str)
{
    do {
        if (*str == '\"')
            *str = '\'';
    } while ((*++str) != '\0');
}


static bool
verifyMetadata(virDomainPtr dom,
               const char *expectXML,
               const char *expectAPI,
               const char *uri)
{
    g_autofree char *metadataXML = NULL;
    g_autofree char *metadataAPI = NULL;

    if (!expectAPI) {
        if ((metadataAPI = virDomainGetMetadata(dom,
                                                VIR_DOMAIN_METADATA_ELEMENT,
                                                uri, 0))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "expected no metadata in API, but got:\n[%s]",
                           metadataAPI);
            return false;
        }
    } else {
        if (!(metadataAPI = virDomainGetMetadata(dom,
                                                 VIR_DOMAIN_METADATA_ELEMENT,
                                                 uri, 0)))
            return false;

        metadataXMLConvertApostrophe(metadataAPI);

        if (STRNEQ(metadataAPI, expectAPI)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "XML metadata in API doesn't match expected metadata: "
                           "expected:\n[%s]\ngot:\n[%s]",
                           expectAPI, metadataAPI);
            return false;
        }

    }

    if (!expectXML) {
        if ((metadataXML = getMetadataFromXML(dom))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "expected no metadata in XML, but got:\n[%s]",
                           metadataXML);
            return false;
        }
    } else {
        if (!(metadataXML = getMetadataFromXML(dom)))
            return false;

        metadataXMLConvertApostrophe(metadataXML);

        if (STRNEQ(metadataXML, expectXML)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "XML in dump doesn't match expected metadata: "
                           "expected:\n[%s]\ngot:\n[%s]",
                           expectXML, metadataXML);
            return false;
        }
    }

    return true;
}


struct metadataTest {
    virConnectPtr conn;
    virDomainPtr dom;

    const char *data;
    const char *expect;
    int type;
    bool fail;
};


static int
testAssignMetadata(const void *data)
{
    const struct metadataTest *test = data;

    if (virDomainSetMetadata(test->dom, VIR_DOMAIN_METADATA_ELEMENT,
                             metadata1, "herp", "http://herp.derp/", 0) < 0)
        return -1;

    if (!verifyMetadata(test->dom, metadata1_ns, metadata1, "http://herp.derp/"))
        return -1;

    return 0;
}

static int
testRewriteMetadata(const void *data)
{
    const struct metadataTest *test = data;

    if (virDomainSetMetadata(test->dom, VIR_DOMAIN_METADATA_ELEMENT,
                             metadata2, "blurb", "http://herp.derp/", 0) < 0)
        return -1;

    if (!verifyMetadata(test->dom, metadata2_ns, metadata2, "http://herp.derp/"))
        return -1;

    return 0;
}

static int
testEraseMetadata(const void *data)
{
    const struct metadataTest *test = data;

    if (virDomainSetMetadata(test->dom, VIR_DOMAIN_METADATA_ELEMENT,
                             NULL, NULL, "http://herp.derp/", 0) < 0)
        return -1;

    if (!verifyMetadata(test->dom, NULL, NULL, "http://herp.derp/"))
        return -1;

    return 0;
}

static int
testTextMetadata(const void *data)
{
    const struct metadataTest *test = data;
    g_autofree char *actual = NULL;

    if (virDomainSetMetadata(test->dom, test->type, test->data, NULL, NULL, 0) < 0) {
        if (test->fail)
            return 0;
        return -1;
    }

    actual = virDomainGetMetadata(test->dom, test->type, NULL, 0);

    if (STRNEQ_NULLABLE(test->expect, actual)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "expected metadata doesn't match actual: "
                       "expected:'%s'\ngot: '%s'",
                       NULLSTR(test->data), NULLSTR(actual));
        return -1;
    }

    return 0;
}

#define TEST_TEXT_METADATA(INDEX, TYPE, DATA, EXPECT, FAIL) \
    do { \
        test.type = VIR_DOMAIN_METADATA_ ## TYPE; \
        test.data = DATA; \
        test.expect = EXPECT; \
        test.fail = FAIL; \
 \
        if (virTestRun("text metadata: " #TYPE " " INDEX " ", \
                       testTextMetadata, &test) < 0) \
            ret = EXIT_FAILURE; \
    } while (0)

#define TEST_TITLE(INDEX, DATA) \
    TEST_TEXT_METADATA(INDEX, TITLE, DATA, DATA, false)
#define TEST_TITLE_EXPECT(INDEX, DATA, EXPECT) \
    TEST_TEXT_METADATA(INDEX, TITLE, DATA, EXPECT, false)
#define TEST_TITLE_FAIL(INDEX, DATA) \
    TEST_TEXT_METADATA(INDEX, TITLE, DATA, DATA, true)
#define TEST_DESCR(INDEX, DATA) \
    TEST_TEXT_METADATA(INDEX, DESCRIPTION, DATA, DATA, false)
#define TEST_DESCR_EXPECT(INDEX, DATA, EXPECT) \
    TEST_TEXT_METADATA(INDEX, DESCRIPTION, DATA, EXPECT, false)

static int
mymain(void)
{
    struct metadataTest test = { 0 };
    int ret = EXIT_SUCCESS;

    if (!(test.conn = virConnectOpen("test:///default")))
        return EXIT_FAILURE;

    if (!(test.dom = virDomainLookupByName(test.conn, "test"))) {
        virConnectClose(test.conn);
        return EXIT_FAILURE;
    }

    virTestQuiesceLibvirtErrors(false);

    if (virTestRun("Assign metadata ", testAssignMetadata, &test) < 0)
        ret = EXIT_FAILURE;
    if (virTestRun("Rewrite Metadata ", testRewriteMetadata, &test) < 0)
        ret = EXIT_FAILURE;
    if (virTestRun("Erase metadata ", testEraseMetadata, &test) < 0)
        ret = EXIT_FAILURE;

    TEST_TITLE("1", "qwert");
    TEST_TITLE("2", NULL);
    TEST_TITLE("3", "blah");
    TEST_TITLE_FAIL("4", "qwe\nrt");
    TEST_TITLE_EXPECT("5", "", NULL);
    TEST_TITLE_FAIL("6", "qwert\n");
    TEST_TITLE_FAIL("7", "\n");

    TEST_DESCR("1", "qwert\nqwert");
    TEST_DESCR("2", NULL);
    TEST_DESCR("3", "qwert");
    TEST_DESCR("4", "\n");
    TEST_DESCR_EXPECT("5", "", NULL);

    virDomainFree(test.dom);
    virConnectClose(test.conn);

    return ret;
}

VIR_TEST_MAIN(mymain)
