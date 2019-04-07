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


#include "testutils.h"

#if WITH_YAJL
# include "testutilsqemu.h"
# include "testutilsqemuschema.h"
# include "virstoragefile.h"
# include "virstring.h"
# include "virlog.h"
# include "qemu/qemu_block.h"
# include "qemu/qemu_qapi.h"

# include "qemu/qemu_command.h"

# define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("tests.storagetest");

struct testBackingXMLjsonXMLdata {
    int type;
    const char *xml;
};

static int
testBackingXMLjsonXML(const void *args)
{
    const struct testBackingXMLjsonXMLdata *data = args;
    VIR_AUTOPTR(xmlDoc) xml = NULL;
    VIR_AUTOPTR(xmlXPathContext) ctxt = NULL;
    VIR_AUTOCLEAN(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    VIR_AUTOPTR(virJSONValue) backendprops = NULL;
    VIR_AUTOPTR(virJSONValue) wrapper = NULL;
    VIR_AUTOFREE(char *) propsstr = NULL;
    VIR_AUTOFREE(char *) protocolwrapper = NULL;
    VIR_AUTOFREE(char *) actualxml = NULL;
    VIR_AUTOUNREF(virStorageSourcePtr) xmlsrc = NULL;
    VIR_AUTOUNREF(virStorageSourcePtr) jsonsrc = NULL;

    if (!(xmlsrc = virStorageSourceNew()))
        return -1;

    xmlsrc->type = data->type;

    if (!(xml = virXMLParseStringCtxt(data->xml, "(test storage source XML)", &ctxt)))
        return -1;

    if (virDomainStorageSourceParse(ctxt->node, ctxt, xmlsrc, 0, NULL) < 0) {
        fprintf(stderr, "failed to parse disk source xml\n");
        return -1;
    }

    if (!(backendprops = qemuBlockStorageSourceGetBackendProps(xmlsrc, true))) {
        fprintf(stderr, "failed to format disk source json\n");
        return -1;
    }

    if (virJSONValueObjectCreate(&wrapper, "a:file", &backendprops, NULL) < 0)
        return -1;

    if (!(propsstr = virJSONValueToString(wrapper, false)))
        return -1;

    if (virAsprintf(&protocolwrapper, "json:%s", propsstr) < 0)
        return -1;

    if (!(jsonsrc = virStorageSourceNewFromBackingAbsolute(protocolwrapper))) {
        fprintf(stderr, "failed to parse disk json\n");
        return -1;
    }

    if (virDomainDiskSourceFormat(&buf, jsonsrc, 0, false, 0, NULL) < 0 ||
        !(actualxml = virBufferContentAndReset(&buf))) {
        fprintf(stderr, "failed to format disk source xml\n");
        return -1;
    }

    if (STRNEQ(actualxml, data->xml)) {
        fprintf(stderr, "\n expected storage source xml:\n'%s'\n"
                        "actual storage source xml:\n%s\n"
                        "intermediate json:\n%s\n",
                        data->xml, actualxml, protocolwrapper);
        return -1;
    }

    return 0;
}


struct testQemuDiskXMLToJSONData {
    virQEMUDriverPtr driver;
    virHashTablePtr schema;
    virJSONValuePtr schemaroot;
    const char *name;
    bool fail;

    virJSONValuePtr *props;
    size_t nprops;

    virQEMUCapsPtr qemuCaps;
};


static void
testQemuDiskXMLToPropsClear(struct testQemuDiskXMLToJSONData *data)
{
    size_t i;

    for (i = 0; i < data->nprops; i++)
        virJSONValueFree(data->props[i]);

    data->nprops = 0;
    VIR_FREE(data->props);
}


static int
testQemuDiskXMLToJSONFakeSecrets(virStorageSourcePtr src)
{
    qemuDomainStorageSourcePrivatePtr srcpriv;

    if (!src->privateData &&
        !(src->privateData = qemuDomainStorageSourcePrivateNew()))
        return -1;

    srcpriv = QEMU_DOMAIN_STORAGE_SOURCE_PRIVATE(src);

    if (src->auth) {
        if (VIR_ALLOC(srcpriv->secinfo) < 0)
            return -1;

        srcpriv->secinfo->type = VIR_DOMAIN_SECRET_INFO_TYPE_AES;
        if (VIR_STRDUP(srcpriv->secinfo->s.aes.username, src->auth->username) < 0)
            return -1;

        if (virAsprintf(&srcpriv->secinfo->s.aes.alias, "%s-secalias",
                        NULLSTR(src->nodestorage)) < 0)
            return -1;
    }

    if (src->encryption) {
        if (VIR_ALLOC(srcpriv->encinfo) < 0)
            return -1;

        srcpriv->encinfo->type = VIR_DOMAIN_SECRET_INFO_TYPE_AES;
        if (virAsprintf(&srcpriv->encinfo->s.aes.alias, "%s-encalias",
                        NULLSTR(src->nodeformat)) < 0)
            return -1;
    }

    return 0;
}


static const char *testQemuDiskXMLToJSONPath = abs_srcdir "/qemublocktestdata/xml2json/";

static int
testQemuDiskXMLToProps(const void *opaque)
{
    struct testQemuDiskXMLToJSONData *data = (void *) opaque;
    virDomainDiskDefPtr disk = NULL;
    virStorageSourcePtr n;
    virJSONValuePtr formatProps = NULL;
    virJSONValuePtr storageProps = NULL;
    char *xmlpath = NULL;
    char *xmlstr = NULL;
    int ret = -1;

    if (virAsprintf(&xmlpath, "%s%s.xml",
                    testQemuDiskXMLToJSONPath, data->name) < 0)
        goto cleanup;

    if (virTestLoadFile(xmlpath, &xmlstr) < 0)
        goto cleanup;

    /* qemu stores node names in the status XML portion */
    if (!(disk = virDomainDiskDefParse(xmlstr, NULL, data->driver->xmlopt,
                                       VIR_DOMAIN_DEF_PARSE_STATUS)))
        goto cleanup;

    if (qemuCheckDiskConfig(disk, data->qemuCaps) < 0 ||
        qemuDomainDeviceDefValidateDisk(disk, data->qemuCaps) < 0) {
        VIR_TEST_VERBOSE("invalid configuration for disk\n");
        goto cleanup;
    }

    for (n = disk->src; virStorageSourceIsBacking(n); n = n->backingStore) {
        if (testQemuDiskXMLToJSONFakeSecrets(n) < 0)
            goto cleanup;

        if (qemuDomainValidateStorageSource(n, data->qemuCaps) < 0)
            goto cleanup;

        if (qemuDomainPrepareDiskSourceData(disk, n, NULL, data->qemuCaps) < 0)
            goto cleanup;

        if (!(formatProps = qemuBlockStorageSourceGetBlockdevProps(n)) ||
            !(storageProps = qemuBlockStorageSourceGetBackendProps(n, false))) {
            if (!data->fail) {
                VIR_TEST_VERBOSE("failed to generate qemu blockdev props\n");
                goto cleanup;
            }
        } else if (data->fail) {
            VIR_TEST_VERBOSE("qemu blockdev props should have failed\n");
            goto cleanup;
        }

        if (VIR_APPEND_ELEMENT(data->props, data->nprops, formatProps) < 0 ||
            VIR_APPEND_ELEMENT(data->props, data->nprops, storageProps) < 0)
            goto cleanup;
    }

    ret = 0;

 cleanup:
    virJSONValueFree(formatProps);
    virJSONValueFree(storageProps);
    virDomainDiskDefFree(disk);
    VIR_FREE(xmlpath);
    VIR_FREE(xmlstr);
    return ret;
}


static int
testQemuDiskXMLToPropsValidateSchema(const void *opaque)
{
    struct testQemuDiskXMLToJSONData *data = (void *) opaque;
    virBuffer debug = VIR_BUFFER_INITIALIZER;
    char *propsstr = NULL;
    char *debugmsg = NULL;
    int ret = 0;
    size_t i;

    if (data->fail)
        return EXIT_AM_SKIP;

    for (i = 0; i < data->nprops; i++) {
        if (testQEMUSchemaValidate(data->props[i], data->schemaroot,
                                   data->schema, &debug) < 0) {
            debugmsg = virBufferContentAndReset(&debug);
            propsstr = virJSONValueToString(data->props[i], true);
            VIR_TEST_VERBOSE("json does not conform to QAPI schema");
            VIR_TEST_DEBUG("json:\n%s\ndoes not match schema. Debug output:\n %s",
                           propsstr, NULLSTR(debugmsg));
            VIR_FREE(debugmsg);
            VIR_FREE(propsstr);
            ret = -1;
        }

        virBufferFreeAndReset(&debug);
    }
    return ret;
}


static int
testQemuDiskXMLToPropsValidateFile(const void *opaque)
{
    struct testQemuDiskXMLToJSONData *data = (void *) opaque;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char *jsonpath = NULL;
    char *actual = NULL;
    int ret = -1;
    size_t i;

    if (data->fail)
        return EXIT_AM_SKIP;

    if (virAsprintf(&jsonpath, "%s%s.json",
                    testQemuDiskXMLToJSONPath, data->name) < 0)
        goto cleanup;

    for (i = 0; i < data->nprops; i++) {
        char *jsonstr;

        if (!(jsonstr = virJSONValueToString(data->props[i], true)))
            goto cleanup;

        virBufferAdd(&buf, jsonstr, -1);
        VIR_FREE(jsonstr);
    }

    if (virBufferCheckError(&buf) < 0)
        goto cleanup;

    actual = virBufferContentAndReset(&buf);

    ret = virTestCompareToFile(actual, jsonpath);

 cleanup:
    VIR_FREE(jsonpath);
    VIR_FREE(actual);
    return ret;
}


static int
mymain(void)
{
    int ret = 0;
    virQEMUDriver driver;
    struct testBackingXMLjsonXMLdata xmljsonxmldata;
    struct testQemuDiskXMLToJSONData diskxmljsondata;
    char *capslatest_x86_64 = NULL;
    virQEMUCapsPtr caps_x86_64 = NULL;

    if (qemuTestDriverInit(&driver) < 0)
        return EXIT_FAILURE;

    diskxmljsondata.driver = &driver;

    if (!(capslatest_x86_64 = testQemuGetLatestCapsForArch(abs_srcdir "/qemucapabilitiesdata",
                                                           "x86_64", "xml")))
        return EXIT_FAILURE;

    VIR_TEST_VERBOSE("\nlatest caps x86_64: %s\n", capslatest_x86_64);

    if (!(caps_x86_64 = qemuTestParseCapabilitiesArch(virArchFromString("x86_64"),
                                                      capslatest_x86_64)))
        return EXIT_FAILURE;

    diskxmljsondata.qemuCaps = caps_x86_64;

    virTestCounterReset("qemu storage source xml->json->xml ");

# define TEST_JSON_FORMAT(tpe, xmlstr) \
    do { \
        xmljsonxmldata.type = tpe; \
        xmljsonxmldata.xml = xmlstr; \
        if (virTestRun(virTestCounterNext(), testBackingXMLjsonXML, \
                       &xmljsonxmldata) < 0) \
            ret = -1; \
    } while (0)

# define TEST_JSON_FORMAT_NET(xmlstr) \
    TEST_JSON_FORMAT(VIR_STORAGE_TYPE_NETWORK, xmlstr)

    TEST_JSON_FORMAT(VIR_STORAGE_TYPE_FILE, "<source file='/path/to/file'/>\n");

    /* type VIR_STORAGE_TYPE_BLOCK is not tested since it parses back to 'file' */
    /* type VIR_STORAGE_TYPE_DIR it is a 'format' driver in qemu */

    TEST_JSON_FORMAT_NET("<source protocol='http' name=''>\n"
                         "  <host name='example.com' port='80'/>\n"
                         "</source>\n");
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

# define TEST_DISK_TO_JSON_FULL(nme, fl) \
    do { \
        diskxmljsondata.name = nme; \
        diskxmljsondata.props = NULL; \
        diskxmljsondata.nprops = 0; \
        diskxmljsondata.fail = fl; \
        if (virTestRun("disk xml to props " nme, testQemuDiskXMLToProps, \
                       &diskxmljsondata) < 0) \
            ret = -1; \
        if (virTestRun("disk xml to props validate schema " nme, \
                       testQemuDiskXMLToPropsValidateSchema, &diskxmljsondata) < 0) \
            ret = -1; \
        if (virTestRun("disk xml to props validate file " nme, \
                       testQemuDiskXMLToPropsValidateFile,  &diskxmljsondata) < 0) \
            ret = -1; \
        testQemuDiskXMLToPropsClear(&diskxmljsondata); \
    } while (0)

# define TEST_DISK_TO_JSON(nme) TEST_DISK_TO_JSON_FULL(nme, false)

    if (!(diskxmljsondata.schema = testQEMUSchemaLoad())) {
        ret = -1;
        goto cleanup;
    }

    if (virQEMUQAPISchemaPathGet("blockdev-add/arg-type",
                                 diskxmljsondata.schema,
                                 &diskxmljsondata.schemaroot) < 0 ||
        !diskxmljsondata.schemaroot) {
        VIR_TEST_VERBOSE("failed to find schema entry for blockdev-add\n");
        ret = -1;
        goto cleanup;
    }

    TEST_DISK_TO_JSON_FULL("nodename-long-format", true);
    TEST_DISK_TO_JSON_FULL("nodename-long-protocol", true);

    TEST_DISK_TO_JSON("file-raw-noopts");
    TEST_DISK_TO_JSON("file-bochs-noopts");
    TEST_DISK_TO_JSON("file-cloop-noopts");
    TEST_DISK_TO_JSON("file-dmg-noopts");
    TEST_DISK_TO_JSON("file-ploop-noopts");
    TEST_DISK_TO_JSON("file-vdi-noopts");
    TEST_DISK_TO_JSON("file-vhd-noopts");
    TEST_DISK_TO_JSON("file-vpc-noopts");

    TEST_DISK_TO_JSON("file-backing_basic-noopts");
    TEST_DISK_TO_JSON("dir-fat-readonly");
    TEST_DISK_TO_JSON("dir-fat-floppy");
    TEST_DISK_TO_JSON("file-raw-aio_native");
    TEST_DISK_TO_JSON("file-backing_basic-aio_threads");
    TEST_DISK_TO_JSON("file-raw-luks");
    TEST_DISK_TO_JSON("file-qcow2-backing-chain-noopts");
    TEST_DISK_TO_JSON("file-qcow2-backing-chain-unterminated");
    TEST_DISK_TO_JSON("file-qcow2-backing-chain-encryption");
    TEST_DISK_TO_JSON("network-qcow2-backing-chain-encryption_auth");

    TEST_DISK_TO_JSON("file-backing_basic-unmap");
    TEST_DISK_TO_JSON("file-backing_basic-unmap-detect");
    TEST_DISK_TO_JSON("file-backing_basic-unmap-ignore");
    TEST_DISK_TO_JSON("file-backing_basic-detect");

    TEST_DISK_TO_JSON("file-backing_basic-cache-none");
    TEST_DISK_TO_JSON("file-backing_basic-cache-writethrough");
    TEST_DISK_TO_JSON("file-backing_basic-cache-writeback");
    TEST_DISK_TO_JSON("file-backing_basic-cache-directsync");
    TEST_DISK_TO_JSON("file-backing_basic-cache-unsafe");
    TEST_DISK_TO_JSON("network-qcow2-backing-chain-cache-unsafe");
    TEST_DISK_TO_JSON("dir-fat-cache");
    TEST_DISK_TO_JSON("network-nbd-tls");

    TEST_DISK_TO_JSON("block-raw-noopts");
    TEST_DISK_TO_JSON("block-raw-reservations");

 cleanup:
    virHashFree(diskxmljsondata.schema);
    qemuTestDriverFree(&driver);
    VIR_FREE(capslatest_x86_64);
    virObjectUnref(caps_x86_64);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

#else
static int
mymain(void)
{
    return EXIT_AM_SKIP;
}
#endif

VIR_TEST_MAIN(mymain)
