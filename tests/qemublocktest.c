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

# define LIBVIRT_SNAPSHOT_CONF_PRIV_H_ALLOW
# include "conf/snapshot_conf_priv.h"

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

    if (!(backendprops = qemuBlockStorageSourceGetBackendProps(xmlsrc, true, false,
                                                               false))) {
        fprintf(stderr, "failed to format disk source json\n");
        return -1;
    }

    if (virJSONValueObjectCreate(&wrapper, "a:file", &backendprops, NULL) < 0)
        return -1;

    if (!(propsstr = virJSONValueToString(wrapper, false)))
        return -1;

    if (virAsprintf(&protocolwrapper, "json:%s", propsstr) < 0)
        return -1;

    if (virStorageSourceNewFromBackingAbsolute(protocolwrapper,
                                               &jsonsrc) < 0) {
        fprintf(stderr, "failed to parse disk json\n");
        return -1;
    }

    if (virDomainDiskSourceFormat(&buf, jsonsrc, "source", 0, false, 0,
                                  NULL) < 0 ||
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

    virJSONValuePtr *propssrc;
    size_t npropssrc;

    virQEMUCapsPtr qemuCaps;
};


static void
testQemuDiskXMLToPropsClear(struct testQemuDiskXMLToJSONData *data)
{
    size_t i;

    for (i = 0; i < data->nprops; i++)
        virJSONValueFree(data->props[i]);

    for (i = 0; i < data->npropssrc; i++)
        virJSONValueFree(data->propssrc[i]);

    data->nprops = 0;
    VIR_FREE(data->props);
    data->npropssrc = 0;
    VIR_FREE(data->propssrc);
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
    VIR_AUTOPTR(virJSONValue) storageSrcOnlyProps = NULL;
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
        VIR_TEST_VERBOSE("invalid configuration for disk");
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
            !(storageSrcOnlyProps = qemuBlockStorageSourceGetBackendProps(n, false, true, true)) ||
            !(storageProps = qemuBlockStorageSourceGetBackendProps(n, false, false, true))) {
            if (!data->fail) {
                VIR_TEST_VERBOSE("failed to generate qemu blockdev props");
                goto cleanup;
            }
        } else if (data->fail) {
            VIR_TEST_VERBOSE("qemu blockdev props should have failed");
            goto cleanup;
        }

        if (VIR_APPEND_ELEMENT(data->props, data->nprops, formatProps) < 0 ||
            VIR_APPEND_ELEMENT(data->props, data->nprops, storageProps) < 0 ||
            VIR_APPEND_ELEMENT(data->propssrc, data->npropssrc, storageSrcOnlyProps) < 0)
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

    for (i = 0; i < data->npropssrc; i++) {
        if (testQEMUSchemaValidate(data->propssrc[i], data->schemaroot,
                                   data->schema, &debug) < 0) {
            debugmsg = virBufferContentAndReset(&debug);
            propsstr = virJSONValueToString(data->propssrc[i], true);
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


struct testQemuImageCreateData {
    const char *name;
    const char *backingname;
    virHashTablePtr schema;
    virJSONValuePtr schemaroot;
    virQEMUDriverPtr driver;
    virQEMUCapsPtr qemuCaps;
};

static const char *testQemuImageCreatePath = abs_srcdir "/qemublocktestdata/imagecreate/";

static virStorageSourcePtr
testQemuImageCreateLoadDiskXML(const char *name,
                               virDomainXMLOptionPtr xmlopt)

{
    virDomainSnapshotDiskDefPtr diskdef = NULL;
    VIR_AUTOPTR(xmlDoc) doc = NULL;
    VIR_AUTOPTR(xmlXPathContext) ctxt = NULL;
    xmlNodePtr node;
    VIR_AUTOFREE(char *) xmlpath = NULL;
    virStorageSourcePtr ret = NULL;

    if (virAsprintf(&xmlpath, "%s%s.xml",
                    testQemuImageCreatePath, name) < 0)
        return NULL;

    if (!(doc = virXMLParseFileCtxt(xmlpath, &ctxt)))
        return NULL;

    if (!(node = virXPathNode("//disk", ctxt))) {
        VIR_TEST_VERBOSE("failed to find <source> element\n");
        return NULL;
    }

    if (VIR_ALLOC(diskdef) < 0)
        return NULL;

    if (virDomainSnapshotDiskDefParseXML(node, ctxt, diskdef,
                                         VIR_DOMAIN_DEF_PARSE_STATUS,
                                         xmlopt) == 0)
        VIR_STEAL_PTR(ret, diskdef->src);

    virDomainSnapshotDiskDefFree(diskdef);
    return ret;
}


static int
testQemuImageCreate(const void *opaque)
{
    struct testQemuImageCreateData *data = (void *) opaque;
    VIR_AUTOPTR(virJSONValue) protocolprops = NULL;
    VIR_AUTOPTR(virJSONValue) formatprops = NULL;
    VIR_AUTOUNREF(virStorageSourcePtr) src = NULL;
    VIR_AUTOCLEAN(virBuffer) debug = VIR_BUFFER_INITIALIZER;
    VIR_AUTOCLEAN(virBuffer) actualbuf = VIR_BUFFER_INITIALIZER;
    VIR_AUTOFREE(char *) jsonprotocol = NULL;
    VIR_AUTOFREE(char *) jsonformat = NULL;
    VIR_AUTOFREE(char *) actual = NULL;
    VIR_AUTOFREE(char *) jsonpath = NULL;

    if (!(src = testQemuImageCreateLoadDiskXML(data->name, data->driver->xmlopt)))
        return -1;

    if (data->backingname &&
        !(src->backingStore = testQemuImageCreateLoadDiskXML(data->backingname,
                                                             data->driver->xmlopt)))
        return -1;

    if (testQemuDiskXMLToJSONFakeSecrets(src) < 0)
        return -1;

    /* fake some sizes */
    src->capacity = UINT_MAX * 2ULL;
    src->physical = UINT_MAX + 1ULL;

    if (qemuDomainValidateStorageSource(src, data->qemuCaps) < 0)
        return -1;

    if (qemuBlockStorageSourceCreateGetStorageProps(src, &protocolprops) < 0)
        return -1;

    if (qemuBlockStorageSourceCreateGetFormatProps(src, src->backingStore, &formatprops) < 0)
        return -1;

    if (formatprops) {
        if (!(jsonformat = virJSONValueToString(formatprops, true)))
            return -1;

        if (testQEMUSchemaValidate(formatprops, data->schemaroot, data->schema,
                                   &debug) < 0) {
            VIR_AUTOFREE(char *) debugmsg = virBufferContentAndReset(&debug);
            VIR_TEST_VERBOSE("blockdev-create format json does not conform to QAPI schema");
            VIR_TEST_DEBUG("json:\n%s\ndoes not match schema. Debug output:\n %s",
                           jsonformat, NULLSTR(debugmsg));
            return -1;
        }
        virBufferFreeAndReset(&debug);
    }

    if (protocolprops) {
        if (!(jsonprotocol = virJSONValueToString(protocolprops, true)))
            return -1;

        if (testQEMUSchemaValidate(protocolprops, data->schemaroot, data->schema,
                                   &debug) < 0) {
            VIR_AUTOFREE(char *) debugmsg = virBufferContentAndReset(&debug);
            VIR_TEST_VERBOSE("blockdev-create protocol json does not conform to QAPI schema");
            VIR_TEST_DEBUG("json:\n%s\ndoes not match schema. Debug output:\n %s",
                           jsonprotocol, NULLSTR(debugmsg));
            return -1;
        }
        virBufferFreeAndReset(&debug);
    }

    virBufferStrcat(&actualbuf, "protocol:\n", NULLSTR(jsonprotocol),
                    "\nformat:\n", NULLSTR(jsonformat), NULL);
    virBufferTrim(&actualbuf, "\n", -1);
    virBufferAddLit(&actualbuf, "\n");

    if (virAsprintf(&jsonpath, "%s%s.json",
                    testQemuImageCreatePath, data->name) < 0)
        return -1;

    if (!(actual = virBufferContentAndReset(&actualbuf)))
        return -1;

    return virTestCompareToFile(actual, jsonpath);
}


static int
testQemuDiskXMLToPropsValidateFileSrcOnly(const void *opaque)
{
    struct testQemuDiskXMLToJSONData *data = (void *) opaque;
    VIR_AUTOCLEAN(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    VIR_AUTOFREE(char *) jsonpath = NULL;
    VIR_AUTOFREE(char *) actual = NULL;
    size_t i;

    if (data->fail)
        return EXIT_AM_SKIP;

    if (virAsprintf(&jsonpath, "%s%s-srconly.json",
                    testQemuDiskXMLToJSONPath, data->name) < 0)
        return -1;

    for (i = 0; i < data->npropssrc; i++) {
        VIR_AUTOFREE(char *) jsonstr = NULL;

        if (!(jsonstr = virJSONValueToString(data->propssrc[i], true)))
            return -1;

        virBufferAdd(&buf, jsonstr, -1);
    }

    if (virBufferCheckError(&buf) < 0)
        return -1;

    actual = virBufferContentAndReset(&buf);

    return virTestCompareToFile(actual, jsonpath);
}


static int
mymain(void)
{
    int ret = 0;
    virQEMUDriver driver;
    struct testBackingXMLjsonXMLdata xmljsonxmldata;
    struct testQemuDiskXMLToJSONData diskxmljsondata;
    struct testQemuImageCreateData imagecreatedata;
    char *capslatest_x86_64 = NULL;
    virQEMUCapsPtr caps_x86_64 = NULL;

    if (qemuTestDriverInit(&driver) < 0)
        return EXIT_FAILURE;

    diskxmljsondata.driver = &driver;
    imagecreatedata.driver = &driver;

    if (!(capslatest_x86_64 = testQemuGetLatestCapsForArch("x86_64", "xml")))
        return EXIT_FAILURE;

    VIR_TEST_VERBOSE("\nlatest caps x86_64: %s", capslatest_x86_64);

    if (!(caps_x86_64 = qemuTestParseCapabilitiesArch(virArchFromString("x86_64"),
                                                      capslatest_x86_64)))
        return EXIT_FAILURE;

    diskxmljsondata.qemuCaps = caps_x86_64;
    imagecreatedata.qemuCaps = caps_x86_64;

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
        diskxmljsondata.propssrc = NULL; \
        diskxmljsondata.npropssrc = 0; \
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
        if (virTestRun("disk xml to props source only validate file " nme, \
                       testQemuDiskXMLToPropsValidateFileSrcOnly,  &diskxmljsondata) < 0) \
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
        VIR_TEST_VERBOSE("failed to find schema entry for blockdev-add");
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

# define TEST_IMAGE_CREATE(testname, testbacking) \
    do { \
        imagecreatedata.name = testname; \
        imagecreatedata.backingname = testbacking; \
        if (virTestRun("image create xml to props " testname, testQemuImageCreate, \
                       &imagecreatedata) < 0) \
            ret = -1; \
    } while (0)
    imagecreatedata.schema = diskxmljsondata.schema;
    if (virQEMUQAPISchemaPathGet("blockdev-create/arg-type/options",
                                 imagecreatedata.schema,
                                 &imagecreatedata.schemaroot) < 0 ||
        !imagecreatedata.schemaroot) {
        VIR_TEST_VERBOSE("failed to find schema entry for blockdev-create\n");
        ret = -1;
        goto cleanup;
    }

    TEST_IMAGE_CREATE("raw", NULL);
    TEST_IMAGE_CREATE("raw-nbd", NULL);
    TEST_IMAGE_CREATE("luks-noopts", NULL);
    TEST_IMAGE_CREATE("luks-encopts", NULL);
    TEST_IMAGE_CREATE("qcow2", NULL);
    TEST_IMAGE_CREATE("qcow2-luks-noopts", NULL);
    TEST_IMAGE_CREATE("qcow2-luks-encopts", NULL);
    TEST_IMAGE_CREATE("qcow2-backing-raw", "raw");
    TEST_IMAGE_CREATE("qcow2-backing-raw-nbd", "raw-nbd");
    TEST_IMAGE_CREATE("qcow2-backing-luks", "luks-noopts");
    TEST_IMAGE_CREATE("qcow2-luks-encopts-backing", "qcow2");

    TEST_IMAGE_CREATE("network-gluster-qcow2", NULL);
    TEST_IMAGE_CREATE("network-rbd-qcow2", NULL);
    TEST_IMAGE_CREATE("network-ssh-qcow2", NULL);
    TEST_IMAGE_CREATE("network-sheepdog-qcow2", NULL);

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
