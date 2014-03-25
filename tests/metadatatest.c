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
 *
 * Author: Peter Krempa <pkrempa@redhat.com>
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
    xmlDocPtr doc = NULL;
    xmlXPathContextPtr ctxt = NULL;
    xmlNodePtr node;

    char *xml = NULL;
    char *ret = NULL;

    if (!(xml = virDomainGetXMLDesc(dom, 0)))
        goto cleanup;

    if (!(doc = virXMLParseStringCtxt(xml, "(domain_definition)", &ctxt)))
        goto cleanup;

    if (!(node = virXPathNode("//metadata/*", ctxt)))
        goto cleanup;

    ret = virXMLNodeToString(node->doc, node);

 cleanup:
    VIR_FREE(xml);
    xmlFreeDoc(doc);
    xmlXPathFreeContext(ctxt);

    return ret;
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
    bool ret = false;
    char *metadataXML = NULL;
    char *metadataAPI = NULL;

    if (!expectAPI) {
        if ((metadataAPI = virDomainGetMetadata(dom,
                                                VIR_DOMAIN_METADATA_ELEMENT,
                                                uri, 0))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "expected no metadata in API, but got:\n[%s]",
                           metadataAPI);
            goto cleanup;
        }
    } else {
        if (!(metadataAPI = virDomainGetMetadata(dom,
                                                 VIR_DOMAIN_METADATA_ELEMENT,
                                                 uri, 0)))
            goto cleanup;

        metadataXMLConvertApostrophe(metadataAPI);

        if (STRNEQ(metadataAPI, expectAPI)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "XML metadata in API doesn't match expected metadata: "
                           "expected:\n[%s]\ngot:\n[%s]",
                           expectAPI, metadataAPI);
            goto cleanup;
        }

    }

    if (!expectXML) {
        if ((metadataXML = getMetadataFromXML(dom))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "expected no metadata in XML, but got:\n[%s]",
                           metadataXML);
            goto cleanup;
        }
    } else {
        if (!(metadataXML = getMetadataFromXML(dom)))
            goto cleanup;

        metadataXMLConvertApostrophe(metadataXML);

        if (STRNEQ(metadataXML, expectXML)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "XML in dump doesn't match expected metadata: "
                           "expected:\n[%s]\ngot:\n[%s]",
                           expectXML, metadataXML);
            goto cleanup;
        }
    }

    ret = true;

 cleanup:
    VIR_FREE(metadataXML);
    VIR_FREE(metadataAPI);

    return ret;
}


struct metadataTest {
    virConnectPtr conn;
    virDomainPtr dom;
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
mymain(void)
{
    struct metadataTest test;
    int ret = EXIT_SUCCESS;

    if (!(test.conn = virConnectOpen("test:///default")))
        return EXIT_FAILURE;

    if (!(test.dom = virDomainLookupByName(test.conn, "test"))) {
        virConnectClose(test.conn);
        return EXIT_FAILURE;
    }

    virtTestQuiesceLibvirtErrors(false);

    if (virtTestRun("Assign metadata ", testAssignMetadata, &test) < 0)
        ret = EXIT_FAILURE;
    if (virtTestRun("Rewrite Metadata ", testRewriteMetadata, &test) < 0)
        ret = EXIT_FAILURE;
    if (virtTestRun("Erase metadata ", testEraseMetadata, &test) < 0)
        ret = EXIT_FAILURE;

    virDomainFree(test.dom);
    virConnectClose(test.conn);

    return ret;
}

VIRT_TEST_MAIN(mymain)
