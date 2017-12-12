/*
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

#include <stdlib.h>

#include "testutils.h"
#include "virstoragefile.h"
#include "virstring.h"
#include "virlog.h"
#include "qemu/qemu_block.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("tests.storagetest");

struct testBackingXMLjsonXMLdata {
    int type;
    const char *xml;
};

static int
testBackingXMLjsonXML(const void *args)
{
    const struct testBackingXMLjsonXMLdata *data = args;
    xmlDocPtr xml = NULL;
    xmlXPathContextPtr ctxt = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    virStorageSourcePtr xmlsrc = NULL;
    virStorageSourcePtr jsonsrc = NULL;
    virJSONValuePtr backendprops = NULL;
    virJSONValuePtr wrapper = NULL;
    char *propsstr = NULL;
    char *protocolwrapper = NULL;
    char *actualxml = NULL;
    int ret = -1;

    if (VIR_ALLOC(xmlsrc) < 0)
        return -1;

    xmlsrc->type = data->type;

    if (!(xml = virXMLParseStringCtxt(data->xml, "(test storage source XML)", &ctxt)))
        goto cleanup;

    if (virDomainDiskSourceParse(ctxt->node, ctxt, xmlsrc, 0, NULL) < 0) {
        fprintf(stderr, "failed to parse disk source xml\n");
        goto cleanup;
    }

    if (!(backendprops = qemuBlockStorageSourceGetBackendProps(xmlsrc))) {
        fprintf(stderr, "failed to format disk source json\n");
        goto cleanup;
    }

    if (virJSONValueObjectCreate(&wrapper, "a:file", backendprops, NULL) < 0)
        goto cleanup;

    backendprops = NULL;

    if (!(propsstr = virJSONValueToString(wrapper, false)))
        goto cleanup;

    if (virAsprintf(&protocolwrapper, "json:%s", propsstr) < 0)
        goto cleanup;

    if (!(jsonsrc = virStorageSourceNewFromBackingAbsolute(protocolwrapper))) {
        fprintf(stderr, "failed to parse disk json\n");
        goto cleanup;
    }

    if (virDomainDiskSourceFormat(&buf, jsonsrc, 0, 0, NULL) < 0 ||
        !(actualxml = virBufferContentAndReset(&buf))) {
        fprintf(stderr, "failed to format disk source xml\n");
        goto cleanup;
    }

    if (STRNEQ(actualxml, data->xml)) {
        fprintf(stderr, "\n expected storage source xml:\n'%s'\n"
                        "actual storage source xml:\n%s\n"
                        "intermediate json:\n%s\n",
                        data->xml, actualxml, protocolwrapper);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    virStorageSourceFree(xmlsrc);
    virStorageSourceFree(jsonsrc);
    VIR_FREE(propsstr);
    VIR_FREE(protocolwrapper);
    VIR_FREE(actualxml);
    virJSONValueFree(backendprops);
    virJSONValueFree(wrapper);
    virBufferFreeAndReset(&buf);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);

    return ret;
}


static int
mymain(void)
{
    int ret = 0;
    struct testBackingXMLjsonXMLdata data;

    virTestCounterReset("qemu storage source xml->json->xml ");

#define TEST_JSON_FORMAT(tpe, xmlstr) \
    do { \
        data.type = tpe; \
        data.xml = xmlstr; \
        if (virTestRun(virTestCounterNext(), testBackingXMLjsonXML, &data) < 0) \
            ret = -1; \
    } while (0)

#define TEST_JSON_FORMAT_NET(xmlstr)\
    TEST_JSON_FORMAT(VIR_STORAGE_TYPE_NETWORK, xmlstr)

    TEST_JSON_FORMAT(VIR_STORAGE_TYPE_FILE, "<source file='/path/to/file'/>\n");

    /* type VIR_STORAGE_TYPE_BLOCK is not tested since it parses back to 'file' */
    /* type VIR_STORAGE_TYPE_DIR it is a 'format' driver in qemu */

    TEST_JSON_FORMAT_NET("<source protocol='http' name='file'>\n"
                         "  <host name='example.com' port='80'/>\n"
                         "</source>\n");
    TEST_JSON_FORMAT_NET("<source protocol='https' name='file'>\n"
                         "  <host name='example.com' port='432'/>\n"
                         "</source>\n");
    TEST_JSON_FORMAT_NET("<source protocol='gluster' name='vol/file'>\n"
                         "  <host name='example.com' port='24007'/>\n"
                         "</source>\n");
    TEST_JSON_FORMAT_NET("<source protocol='gluster' name='testvol/img.qcow2'>\n"
                         "  <host name='example.com' port='1234'/>\n"
                         "  <host transport='unix' socket='/path/socket'/>\n"
                         "  <host name='example.com' port='24007'/>\n"
                         "</source>\n");
    TEST_JSON_FORMAT_NET("<source protocol='nbd'>\n"
                         "  <host transport='unix' socket='/path/to/socket'/>\n"
                         "</source>\n");
    TEST_JSON_FORMAT_NET("<source protocol='nbd' name='blah'>\n"
                         "  <host name='example.org' port='6000'/>\n"
                         "</source>\n");
    TEST_JSON_FORMAT_NET("<source protocol='nbd'>\n"
                         "  <host name='example.org' port='6000'/>\n"
                         "</source>\n");
    TEST_JSON_FORMAT_NET("<source protocol='ssh' name='blah'>\n"
                         "  <host name='example.org' port='6000'/>\n"
                         "</source>\n");
    TEST_JSON_FORMAT_NET("<source protocol='rbd' name='libvirt/test'>\n"
                         "  <host name='example.com' port='1234'/>\n"
                         "  <host name='example2.com'/>\n"
                         "  <snapshot name='snapshotname'/>\n"
                         "  <config file='/path/to/conf'/>\n"
                         "</source>\n");
    TEST_JSON_FORMAT_NET("<source protocol='iscsi' name='iqn.2016-12.com.virttest:emulated-iscsi-noauth.target/0'>\n"
                         "  <host name='test.org' port='3260'/>\n"
                         "</source>\n");
    TEST_JSON_FORMAT_NET("<source protocol='iscsi' name='iqn.2016-12.com.virttest:emulated-iscsi-noauth.target/6'>\n"
                         "  <host name='test.org' port='1234'/>\n"
                         "</source>\n");
    TEST_JSON_FORMAT_NET("<source protocol='sheepdog' name='test'>\n"
                         "  <host name='example.com' port='321'/>\n"
                         "</source>\n");
    TEST_JSON_FORMAT_NET("<source protocol='vxhs' name='c6718f6b-0401-441d-a8c3-1f0064d75ee0'>\n"
                         "  <host name='example.com' port='9999'/>\n"
                         "</source>\n");

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
