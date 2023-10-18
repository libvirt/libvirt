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


#include "storage_source.h"
#include "testutils.h"
#include "testutilsqemu.h"
#include "testutilsqemuschema.h"
#include "virlog.h"
#include "qemu/qemu_block.h"
#include "qemu/qemu_qapi.h"
#include "qemu/qemu_monitor_json.h"
#include "qemu/qemu_backup.h"
#include "qemu/qemu_checkpoint.h"
#include "qemu/qemu_validate.h"

#define LIBVIRT_SNAPSHOT_CONF_PRIV_H_ALLOW
#include "conf/snapshot_conf_priv.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("tests.storagetest");

struct testBackingXMLjsonXMLdata {
    int type;
    const char *xml;
    bool legacy;
    GHashTable *schema;
    virJSONValue *schemaroot;
};

static int
testBackingXMLjsonXML(const void *args)
{
    const struct testBackingXMLjsonXMLdata *data = args;
    g_autoptr(xmlDoc) xml = NULL;
    g_autoptr(xmlXPathContext) ctxt = NULL;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    g_autoptr(virJSONValue) backendprops = NULL;
    g_autoptr(virJSONValue) wrapper = NULL;
    g_autofree char *propsstr = NULL;
    g_autofree char *protocolwrapper = NULL;
    g_autofree char *actualxml = NULL;
    g_autoptr(virStorageSource) xmlsrc = NULL;
    g_autoptr(virStorageSource) jsonsrc = NULL;
    g_auto(virBuffer) debug = VIR_BUFFER_INITIALIZER;
    unsigned int backendpropsflags = QEMU_BLOCK_STORAGE_SOURCE_BACKEND_PROPS_TARGET_ONLY;


    xmlsrc = virStorageSourceNew();
    xmlsrc->type = data->type;

    if (!(xml = virXMLParseStringCtxt(data->xml, "(test storage source XML)", &ctxt)))
        return -1;

    if (virDomainStorageSourceParse(ctxt->node, ctxt, xmlsrc, 0, NULL) < 0) {
        fprintf(stderr, "failed to parse disk source xml\n");
        return -1;
    }

    if (!(backendprops = qemuBlockStorageSourceGetBackendProps(xmlsrc,
                                                               backendpropsflags))) {
        fprintf(stderr, "failed to format disk source json\n");
        return -1;
    }

    if (testQEMUSchemaValidate(backendprops, data->schemaroot,
                               data->schema, false, &debug) < 0) {
        g_autofree char *debugmsg = virBufferContentAndReset(&debug);
        g_autofree char *debugprops = virJSONValueToString(backendprops, true);

        VIR_TEST_VERBOSE("json does not conform to QAPI schema");
        VIR_TEST_DEBUG("json:\n%s\ndoes not match schema. Debug output:\n %s",
                       debugprops, NULLSTR(debugmsg));
        return -1;
    }

    if (virJSONValueObjectAdd(&wrapper, "a:file", &backendprops, NULL) < 0)
        return -1;

    if (!(propsstr = virJSONValueToString(wrapper, false)))
        return -1;

    protocolwrapper = g_strdup_printf("json:%s", propsstr);

    if (virStorageSourceNewFromBackingAbsolute(protocolwrapper,
                                               &jsonsrc) < 0) {
        fprintf(stderr, "failed to parse disk json\n");
        return -1;
    }

    if (virDomainDiskSourceFormat(&buf, jsonsrc, "source", 0, false, 0,
                                  false, false, NULL) < 0 ||
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

static const char *testJSONtoJSONPath = abs_srcdir "/qemublocktestdata/jsontojson/";

struct testJSONtoJSONData {
    const char *name;
    GHashTable *schema;
    virJSONValue *schemaroot;
};

static int
testJSONtoJSON(const void *args)
{
    const struct testJSONtoJSONData *data = args;
    g_auto(virBuffer) debug = VIR_BUFFER_INITIALIZER;
    g_autoptr(virJSONValue) jsonsrcout = NULL;
    g_autoptr(virStorageSource) src = NULL;
    g_autofree char *actual = NULL;
    g_autofree char *in = NULL;
    g_autofree char *infile = g_strdup_printf("%s%s-in.json", testJSONtoJSONPath,
                                              data->name);
    g_autofree char *outfile = g_strdup_printf("%s%s-out.json", testJSONtoJSONPath,
                                              data->name);

    if (virTestLoadFile(infile, &in) < 0)
        return -1;

    if (virStorageSourceNewFromBackingAbsolute(in, &src) < 0) {
        fprintf(stderr, "failed to parse disk json\n");
        return -1;
    }

    if (!(jsonsrcout = qemuBlockStorageSourceGetBackendProps(src,
                                                             QEMU_BLOCK_STORAGE_SOURCE_BACKEND_PROPS_TARGET_ONLY))) {
        fprintf(stderr, "failed to format disk source json\n");
        return -1;
    }

    if (!(actual = virJSONValueToString(jsonsrcout, true)))
        return -1;

    if (testQEMUSchemaValidate(jsonsrcout, data->schemaroot,
                               data->schema, false, &debug) < 0) {
        g_autofree char *debugmsg = virBufferContentAndReset(&debug);

        VIR_TEST_VERBOSE("json does not conform to QAPI schema");
        VIR_TEST_DEBUG("json:\n%s\ndoes not match schema. Debug output:\n %s",
                       actual, NULLSTR(debugmsg));
        return -1;
    }

    return virTestCompareToFile(actual, outfile);
}


struct testQemuDiskXMLToJSONImageData {
    virJSONValue *formatprops;
    virJSONValue *storageprops;
    virJSONValue *storagepropssrc;
    char *backingstore;
};


struct testQemuDiskXMLToJSONData {
    virQEMUDriver *driver;
    GHashTable *schema;
    virJSONValue *schemaroot;
    const char *name;
    bool fail;

    struct testQemuDiskXMLToJSONImageData *images;
    size_t nimages;

    virQEMUCaps *qemuCaps;
};


static void
testQemuDiskXMLToPropsClear(struct testQemuDiskXMLToJSONData *data)
{
    size_t i;

    for (i = 0; i < data->nimages; i++) {
        virJSONValueFree(data->images[i].formatprops);
        virJSONValueFree(data->images[i].storageprops);
        virJSONValueFree(data->images[i].storagepropssrc);
        g_free(data->images[i].backingstore);
    }
    data->nimages = 0;
    VIR_FREE(data->images);
}


static int
testQemuDiskXMLToJSONFakeSecrets(virStorageSource *src)
{
    qemuDomainStorageSourcePrivate *srcpriv;

    if (!src->privateData &&
        !(src->privateData = qemuDomainStorageSourcePrivateNew()))
        return -1;

    srcpriv = QEMU_DOMAIN_STORAGE_SOURCE_PRIVATE(src);

    if (src->auth) {
        srcpriv->secinfo = g_new0(qemuDomainSecretInfo, 1);

        srcpriv->secinfo->username = g_strdup(src->auth->username);
        srcpriv->secinfo->alias = g_strdup_printf("%s-secalias",
                                                  NULLSTR(qemuBlockStorageSourceGetStorageNodename(src)));
    }

    if (src->encryption) {
        srcpriv->encinfo = g_new0(qemuDomainSecretInfo *, 1);
        srcpriv->encinfo[0] = g_new0(qemuDomainSecretInfo, 1);

        srcpriv->encinfo[0]->alias = g_strdup_printf("%s-encalias",
                                                     qemuBlockStorageSourceGetFormatNodename(src));
        srcpriv->enccount = 1;
    }

    return 0;
}


static const char *testQemuDiskXMLToJSONPath = abs_srcdir "/qemublocktestdata/xml2json/";

static int
testQemuDiskXMLToProps(const void *opaque)
{
    struct testQemuDiskXMLToJSONData *data = (void *) opaque;
    g_autoptr(virDomainDef) vmdef = NULL;
    virDomainDiskDef *disk = NULL;
    virStorageSource *n;
    g_autoptr(virJSONValue) formatProps = NULL;
    g_autoptr(virJSONValue) storageProps = NULL;
    g_autoptr(virJSONValue) storageSrcOnlyProps = NULL;
    g_autofree char *xmlpath = NULL;
    g_autofree char *xmlstr = NULL;

    xmlpath = g_strdup_printf("%s%s.xml", testQemuDiskXMLToJSONPath, data->name);

    if (virTestLoadFile(xmlpath, &xmlstr) < 0)
        return -1;

    /* qemu stores node names in the status XML portion */
    if (!(disk = virDomainDiskDefParse(xmlstr, data->driver->xmlopt,
                                       VIR_DOMAIN_DEF_PARSE_STATUS)))
        return -1;

    if (qemuDomainDeviceDiskDefPostParse(disk, 0) < 0)
        return -1;

    if (!(vmdef = virDomainDefNew(data->driver->xmlopt)))
        return -1;

    virDomainDiskInsert(vmdef, disk);

    if (qemuValidateDomainDeviceDefDisk(disk, vmdef, data->qemuCaps) < 0) {
        VIR_TEST_VERBOSE("invalid configuration for disk");
        return -1;
    }

    for (n = disk->src; virStorageSourceIsBacking(n); n = n->backingStore) {
        g_autofree char *backingstore = NULL;
        unsigned int backendpropsflagsnormal = QEMU_BLOCK_STORAGE_SOURCE_BACKEND_PROPS_AUTO_READONLY;
        unsigned int backendpropsflagstarget = QEMU_BLOCK_STORAGE_SOURCE_BACKEND_PROPS_AUTO_READONLY |
                                               QEMU_BLOCK_STORAGE_SOURCE_BACKEND_PROPS_TARGET_ONLY;

        if (testQemuDiskXMLToJSONFakeSecrets(n) < 0)
            return -1;

        if (qemuDomainValidateStorageSource(n, data->qemuCaps) < 0)
            return -1;

        qemuDomainPrepareDiskSourceData(disk, n);

        if (!(formatProps = qemuBlockStorageSourceGetFormatProps(n, n->backingStore)) ||
            !(storageSrcOnlyProps = qemuBlockStorageSourceGetBackendProps(n, backendpropsflagstarget)) ||
            !(storageProps = qemuBlockStorageSourceGetBackendProps(n, backendpropsflagsnormal)) ||
            !(backingstore = qemuBlockGetBackingStoreString(n, true))) {
            if (!data->fail) {
                VIR_TEST_VERBOSE("failed to generate qemu blockdev props");
                return -1;
            }
        } else if (data->fail) {
            VIR_TEST_VERBOSE("qemu blockdev props should have failed");
            return -1;
        }

        VIR_REALLOC_N(data->images, data->nimages + 1);

        data->images[data->nimages].formatprops = g_steal_pointer(&formatProps);
        data->images[data->nimages].storageprops = g_steal_pointer(&storageProps);
        data->images[data->nimages].storagepropssrc = g_steal_pointer(&storageSrcOnlyProps);
        data->images[data->nimages].backingstore = g_steal_pointer(&backingstore);

        data->nimages++;
    }

    return 0;
}


static int
testQemuDiskXMLToPropsValidateSchema(const void *opaque)
{
    struct testQemuDiskXMLToJSONData *data = (void *) opaque;
    int ret = 0;
    size_t i;

    if (data->fail)
        return EXIT_AM_SKIP;

    for (i = 0; i < data->nimages; i++) {
        g_auto(virBuffer) debug = VIR_BUFFER_INITIALIZER;

        if (testQEMUSchemaValidate(data->images[i].formatprops, data->schemaroot,
                                   data->schema, false, &debug) < 0) {
            g_autofree char *debugmsg = virBufferContentAndReset(&debug);
            g_autofree char *propsstr = virJSONValueToString(data->images[i].formatprops, true);
            VIR_TEST_VERBOSE("json does not conform to QAPI schema");
            VIR_TEST_DEBUG("json:\n%s\ndoes not match schema. Debug output:\n %s",
                           propsstr, NULLSTR(debugmsg));
            ret = -1;
        }

        virBufferFreeAndReset(&debug);

        if (testQEMUSchemaValidate(data->images[i].storageprops, data->schemaroot,
                                   data->schema, false, &debug) < 0) {
            g_autofree char *debugmsg = virBufferContentAndReset(&debug);
            g_autofree char *propsstr = virJSONValueToString(data->images[i].storageprops, true);
            VIR_TEST_VERBOSE("json does not conform to QAPI schema");
            VIR_TEST_DEBUG("json:\n%s\ndoes not match schema. Debug output:\n %s",
                           propsstr, NULLSTR(debugmsg));
            ret = -1;
        }

        virBufferFreeAndReset(&debug);

        if (testQEMUSchemaValidate(data->images[i].storagepropssrc, data->schemaroot,
                                   data->schema, false, &debug) < 0) {
            g_autofree char *debugmsg = virBufferContentAndReset(&debug);
            g_autofree char *propsstr = virJSONValueToString(data->images[i].storagepropssrc, true);
            VIR_TEST_VERBOSE("json does not conform to QAPI schema");
            VIR_TEST_DEBUG("json:\n%s\ndoes not match schema. Debug output:\n %s",
                           propsstr, NULLSTR(debugmsg));
            ret = -1;
        }
    }

    return ret;
}


static int
testQemuDiskXMLToPropsValidateFile(const void *opaque)
{
    struct testQemuDiskXMLToJSONData *data = (void *) opaque;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    g_autofree char *jsonpath = NULL;
    g_autofree char *actual = NULL;
    size_t i;

    if (data->fail)
        return EXIT_AM_SKIP;

    jsonpath = g_strdup_printf("%s%s.json", testQemuDiskXMLToJSONPath, data->name);

    for (i = 0; i < data->nimages; i++) {
        g_autofree char *formatprops = NULL;
        g_autofree char *storageprops = NULL;

        if (!(formatprops = virJSONValueToString(data->images[i].formatprops, true)))
            return -1;

        if (!(storageprops = virJSONValueToString(data->images[i].storageprops, true)))
            return -1;

        virBufferStrcat(&buf, formatprops, storageprops, NULL);
    }

    actual = virBufferContentAndReset(&buf);

    return virTestCompareToFile(actual, jsonpath);
}


static int
testQemuDiskXMLToPropsValidateFileSrcOnly(const void *opaque)
{
    struct testQemuDiskXMLToJSONData *data = (void *) opaque;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    g_autofree char *jsonpath = NULL;
    g_autofree char *actual = NULL;
    size_t i;

    if (data->fail)
        return EXIT_AM_SKIP;

    jsonpath = g_strdup_printf("%s%s-srconly.json", testQemuDiskXMLToJSONPath,
                               data->name);

    for (i = 0; i < data->nimages; i++) {
        g_autofree char *jsonstr = NULL;

        virBufferAddLit(&buf, "(\n");
        virBufferAdjustIndent(&buf, 2);
        virBufferAddLit(&buf, "source only properties:\n");

        if (!(jsonstr = virJSONValueToString(data->images[i].storagepropssrc, true)))
            return -1;

        virBufferAddStr(&buf, jsonstr);

        virBufferAddLit(&buf, "backing store string:\n");
        virBufferAddStr(&buf, data->images[i].backingstore);

        virBufferTrim(&buf, "\n");
        virBufferAdjustIndent(&buf, -2);
        virBufferAddLit(&buf, "\n)\n");
    }

    actual = virBufferContentAndReset(&buf);

    return virTestCompareToFile(actual, jsonpath);
}



struct testQemuImageCreateData {
    const char *name;
    const char *backingname;
    GHashTable *schema;
    virJSONValue *schemaroot;
    virQEMUDriver *driver;
    virQEMUCaps *qemuCaps;
};

static const char *testQemuImageCreatePath = abs_srcdir "/qemublocktestdata/imagecreate/";

static virStorageSource *
testQemuImageCreateLoadDiskXML(const char *name,
                               virDomainXMLOption *xmlopt)

{
    g_autoptr(virDomainDiskDef) disk = NULL;
    g_autofree char *xmlpath = NULL;
    g_autofree char *xmlstr = NULL;

    xmlpath = g_strdup_printf("%s%s.xml", testQemuImageCreatePath, name);

    if (virTestLoadFile(xmlpath, &xmlstr) < 0)
        return NULL;

    /* qemu stores node names in the status XML portion */
    if (!(disk = virDomainDiskDefParse(xmlstr, xmlopt,
                                       VIR_DOMAIN_DEF_PARSE_STATUS)))
        return NULL;

    if (qemuDomainDeviceDiskDefPostParse(disk, 0) < 0)
        return NULL;

    return g_steal_pointer(&disk->src);
}


static int
testQemuImageCreate(const void *opaque)
{
    struct testQemuImageCreateData *data = (void *) opaque;
    g_autoptr(virJSONValue) protocolprops = NULL;
    g_autoptr(virJSONValue) formatprops = NULL;
    g_autoptr(virStorageSource) src = NULL;
    g_auto(virBuffer) debug = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) actualbuf = VIR_BUFFER_INITIALIZER;
    g_autofree char *jsonprotocol = NULL;
    g_autofree char *jsonformat = NULL;
    g_autofree char *actual = NULL;
    g_autofree char *jsonpath = NULL;

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
                                   false, &debug) < 0) {
            g_autofree char *debugmsg = virBufferContentAndReset(&debug);
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
                                   false, &debug) < 0) {
            g_autofree char *debugmsg = virBufferContentAndReset(&debug);
            VIR_TEST_VERBOSE("blockdev-create protocol json does not conform to QAPI schema");
            VIR_TEST_DEBUG("json:\n%s\ndoes not match schema. Debug output:\n %s",
                           jsonprotocol, NULLSTR(debugmsg));
            return -1;
        }
        virBufferFreeAndReset(&debug);
    }

    virBufferStrcat(&actualbuf, "protocol:\n", NULLSTR(jsonprotocol),
                    "\nformat:\n", NULLSTR(jsonformat), NULL);
    virBufferTrim(&actualbuf, "\n");
    virBufferAddLit(&actualbuf, "\n");

    jsonpath = g_strdup_printf("%s%s.json", testQemuImageCreatePath, data->name);

    if (!(actual = virBufferContentAndReset(&actualbuf)))
        return -1;

    return virTestCompareToFile(actual, jsonpath);
}


static const char *bitmapDetectPrefix = "qemublocktestdata/bitmap/";

static void
testQemuDetectBitmapsWorker(GHashTable *nodedata,
                            const char *nodename,
                            virBuffer *buf)
{
    qemuBlockNamedNodeData *data;
    size_t i;

    if (!(data = virHashLookup(nodedata, nodename)))
        return;

    virBufferAsprintf(buf, "%s:\n", nodename);
    if (data->qcow2v2)
        virBufferAddLit(buf, " qcow2 v2\n");
    virBufferAdjustIndent(buf, 1);

    for (i = 0; i < data->nbitmaps; i++) {
        qemuBlockNamedNodeDataBitmap *bitmap = data->bitmaps[i];

        virBufferAsprintf(buf, "%8s: record:%d busy:%d persist:%d inconsist:%d gran:%llu dirty:%llu\n",
                          bitmap->name, bitmap->recording, bitmap->busy,
                          bitmap->persistent, bitmap->inconsistent,
                          bitmap->granularity, bitmap->dirtybytes);
    }

    virBufferAdjustIndent(buf, -1);
}


static int
testQemuDetectBitmaps(const void *opaque)
{
    const char *name = opaque;
    g_autoptr(virJSONValue) nodedatajson = NULL;
    g_autoptr(GHashTable) nodedata = NULL;
    g_autofree char *actual = NULL;
    g_autofree char *expectpath = NULL;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    size_t i;

    expectpath = g_strdup_printf("%s/%s%s.out", abs_srcdir,
                                 bitmapDetectPrefix, name);

    if (!(nodedatajson = virTestLoadFileJSON(bitmapDetectPrefix, name,
                                             ".json", NULL)))
        return -1;

    if (!(nodedata = qemuMonitorJSONBlockGetNamedNodeDataJSON(nodedatajson))) {
        VIR_TEST_VERBOSE("failed to load nodedata JSON");
        return -1;
    }

    /* we detect for the first 30 nodenames for simplicity */
    for (i = 0; i < 30; i++) {
        g_autofree char *nodename = g_strdup_printf("libvirt-%zu-format", i);

        testQemuDetectBitmapsWorker(nodedata, nodename, &buf);
    }

    actual = virBufferContentAndReset(&buf);

    return virTestCompareToFile(actual, expectpath);
}


static void
testQemuBitmapListPrint(const char *title,
                        GSList *next,
                        virBuffer *buf)
{
    if (!next)
        return;

    virBufferAsprintf(buf, "%s\n", title);

    for (; next; next = next->next) {
        virStorageSource *src = next->data;
        virBufferAsprintf(buf, "%s\n", qemuBlockStorageSourceGetFormatNodename(src));
    }
}


static virStorageSource *
testQemuBackupIncrementalBitmapCalculateGetFakeImage(size_t idx)
{
   virStorageSource *ret = virStorageSourceNew();

   ret->id = idx;
   ret->type = VIR_STORAGE_TYPE_FILE;
   ret->format = VIR_STORAGE_FILE_QCOW2;
   ret->path = g_strdup_printf("/image%zu", idx);
   qemuBlockStorageSourceSetStorageNodename(ret, g_strdup_printf("libvirt-%zu-storage", idx));
   qemuBlockStorageSourceSetFormatNodename(ret, g_strdup_printf("libvirt-%zu-format", idx));

   return ret;
}


static virStorageSource *
testQemuBackupIncrementalBitmapCalculateGetFakeChain(void)
{
    virStorageSource *ret;
    virStorageSource *n;
    size_t i;

    n = ret = testQemuBackupIncrementalBitmapCalculateGetFakeImage(1);

    for (i = 2; i < 6; i++) {
        n->backingStore = testQemuBackupIncrementalBitmapCalculateGetFakeImage(i);
        n = n->backingStore;
    }

    return ret;
}


static virStorageSource *
testQemuBitmapGetFakeChainEntry(virStorageSource *src,
                                size_t idx)
{
    virStorageSource *n;

    for (n = src; n; n = n->backingStore) {
        if (n->id == idx)
            return n;
    }

    return NULL;
}


static const char *backupDataPrefix = "qemublocktestdata/backupmerge/";

struct testQemuBackupIncrementalBitmapCalculateData {
    const char *name;
    virStorageSource *chain;
    const char *incremental;
    const char *nodedatafile;
};


static int
testQemuBackupIncrementalBitmapCalculate(const void *opaque)
{
    const struct testQemuBackupIncrementalBitmapCalculateData *data = opaque;
    g_autoptr(virJSONValue) nodedatajson = NULL;
    g_autoptr(GHashTable) nodedata = NULL;
    g_autoptr(virJSONValue) actions = virJSONValueNewArray();
    g_autofree char *expectpath = NULL;
    g_autoptr(virStorageSource) target = NULL;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    expectpath = g_strdup_printf("%s/%s%s-out.json", abs_srcdir,
                                 backupDataPrefix, data->name);

    if (!(nodedatajson = virTestLoadFileJSON(bitmapDetectPrefix, data->nodedatafile,
                                             ".json", NULL)))
        return -1;

    if (!(nodedata = qemuMonitorJSONBlockGetNamedNodeDataJSON(nodedatajson))) {
        VIR_TEST_VERBOSE("failed to load nodedata JSON\n");
        return -1;
    }

    target = virStorageSourceNew();
    qemuBlockStorageSourceSetFormatNodename(target, g_strdup_printf("target_node"));

    if (qemuBackupDiskPrepareOneBitmapsChain(data->chain,
                                             target,
                                             "target-bitmap-name",
                                             data->incremental,
                                             actions,
                                             nodedata) >= 0) {
        if (virJSONValueToBuffer(actions, &buf, true) < 0)
            return -1;
    } else {
        virBufferAddLit(&buf, "NULL\n");
    }

    return virTestCompareToFile(virBufferCurrentContent(&buf), expectpath);
}


static const char *checkpointDeletePrefix = "qemublocktestdata/checkpointdelete/";

struct testQemuCheckpointDeleteData {
    const char *name;
    virStorageSource *chain;
    const char *deletebitmap;
    const char *nodedatafile;
};


static int
testQemuCheckpointDelete(const void *opaque)
{
    const struct testQemuCheckpointDeleteData *data = opaque;
    g_autofree char *actual = NULL;
    g_autofree char *expectpath = NULL;
    g_autoptr(virJSONValue) actions = NULL;
    g_autoptr(virJSONValue) nodedatajson = NULL;
    g_autoptr(GHashTable) nodedata = NULL;
    g_autoptr(GSList) reopenimages = NULL;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    expectpath = g_strdup_printf("%s/%s%s-out.json", abs_srcdir,
                                 checkpointDeletePrefix, data->name);

    if (!(nodedatajson = virTestLoadFileJSON(bitmapDetectPrefix, data->nodedatafile,
                                             ".json", NULL)))
        return -1;

    if (!(nodedata = qemuMonitorJSONBlockGetNamedNodeDataJSON(nodedatajson))) {
        VIR_TEST_VERBOSE("failed to load nodedata JSON\n");
        return -1;
    }

    actions = virJSONValueNewArray();

    if (qemuCheckpointDiscardDiskBitmaps(data->chain,
                                         nodedata,
                                         data->deletebitmap,
                                         actions,
                                         "testdisk",
                                         &reopenimages) >= 0) {
        if (virJSONValueToBuffer(actions, &buf, true) < 0)
            return -1;
    } else {
        virBufferAddLit(&buf, "NULL\n");
    }

    testQemuBitmapListPrint("reopen nodes:", reopenimages, &buf);

    actual = virBufferContentAndReset(&buf);

    return virTestCompareToFile(actual, expectpath);
}


struct testQemuBlockBitmapValidateData {
    const char *name;
    const char *bitmapname;
    virStorageSource *chain;
    bool expect;
};

static int
testQemuBlockBitmapValidate(const void *opaque)
{
    const struct testQemuBlockBitmapValidateData *data = opaque;
    g_autoptr(virJSONValue) nodedatajson = NULL;
    g_autoptr(GHashTable) nodedata = NULL;
    bool actual;

    if (!(nodedatajson = virTestLoadFileJSON(bitmapDetectPrefix, data->name,
                                             ".json", NULL)))
        return -1;

    if (!(nodedata = qemuMonitorJSONBlockGetNamedNodeDataJSON(nodedatajson))) {
        VIR_TEST_VERBOSE("failed to load nodedata JSON\n");
        return -1;
    }

    actual = qemuBlockBitmapChainIsValid(data->chain, data->bitmapname, nodedata);

    if (actual != data->expect) {
        VIR_TEST_VERBOSE("expected rv:'%d' actual rv:'%d'\n", data->expect, actual);
        return -1;
    }

    return 0;
}


static const char *blockcopyPrefix = "qemublocktestdata/bitmapblockcopy/";

struct testQemuBlockBitmapBlockcopyData {
    const char *name;
    bool shallow;
    virStorageSource *chain;
    const char *nodedatafile;
};


static int
testQemuBlockBitmapBlockcopy(const void *opaque)
{
    const struct testQemuBlockBitmapBlockcopyData *data = opaque;
    g_autofree char *actual = NULL;
    g_autofree char *expectpath = NULL;
    g_autoptr(virJSONValue) actions = NULL;
    g_autoptr(virJSONValue) nodedatajson = NULL;
    g_autoptr(GHashTable) nodedata = NULL;
    g_autoptr(virStorageSource) fakemirror = virStorageSourceNew();
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    qemuBlockStorageSourceSetFormatNodename(fakemirror, g_strdup("mirror-format-node"));

    expectpath = g_strdup_printf("%s/%s%s-out.json", abs_srcdir,
                                 blockcopyPrefix, data->name);

    if (!(nodedatajson = virTestLoadFileJSON(bitmapDetectPrefix, data->nodedatafile,
                                             ".json", NULL)))
        return -1;

    if (!(nodedata = qemuMonitorJSONBlockGetNamedNodeDataJSON(nodedatajson))) {
        VIR_TEST_VERBOSE("failed to load nodedata JSON\n");
        return -1;
    }

    if (qemuBlockBitmapsHandleBlockcopy(data->chain, fakemirror, nodedata,
                                        data->shallow, &actions) < 0)
        return -1;


    if (actions &&
        virJSONValueToBuffer(actions, &buf, true) < 0)
        return -1;

    actual = virBufferContentAndReset(&buf);

    return virTestCompareToFile(actual, expectpath);
}

static const char *blockcommitPrefix = "qemublocktestdata/bitmapblockcommit/";

struct testQemuBlockBitmapBlockcommitData {
    const char *name;
    virStorageSource *top;
    virStorageSource *base;
    virStorageSource *chain;
    const char *nodedatafile;
};


static int
testQemuBlockBitmapBlockcommit(const void *opaque)
{
    const struct testQemuBlockBitmapBlockcommitData *data = opaque;

    g_autofree char *actual = NULL;
    g_autofree char *expectpath = NULL;
    g_autoptr(virJSONValue) actionsMerge = NULL;
    g_autoptr(virJSONValue) nodedatajson = NULL;
    g_autoptr(GHashTable) nodedata = NULL;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    bool active = data->top == data->chain;

    expectpath = g_strdup_printf("%s/%s%s", abs_srcdir,
                                 blockcommitPrefix, data->name);

    if (!(nodedatajson = virTestLoadFileJSON(bitmapDetectPrefix, data->nodedatafile,
                                             ".json", NULL)))
        return -1;

    if (!(nodedata = qemuMonitorJSONBlockGetNamedNodeDataJSON(nodedatajson))) {
        VIR_TEST_VERBOSE("failed to load nodedata JSON\n");
        return -1;
    }

    virBufferAddLit(&buf, "merge bitmpas:\n");

    if (qemuBlockBitmapsHandleCommitFinish(data->top, data->base, active, nodedata,
                                           &actionsMerge) < 0)
        return -1;

    if (actionsMerge &&
        virJSONValueToBuffer(actionsMerge, &buf, true) < 0)
        return -1;

    actual = virBufferContentAndReset(&buf);

    return virTestCompareToFile(actual, expectpath);
}


static int
mymain(void)
{
    int ret = 0;
    virQEMUDriver driver;
    struct testBackingXMLjsonXMLdata xmljsonxmldata;
    struct testQemuDiskXMLToJSONData diskxmljsondata;
    struct testJSONtoJSONData jsontojsondata;
    struct testQemuImageCreateData imagecreatedata;
    struct testQemuBackupIncrementalBitmapCalculateData backupbitmapcalcdata;
    struct testQemuCheckpointDeleteData checkpointdeletedata;
    struct testQemuBlockBitmapValidateData blockbitmapvalidatedata;
    struct testQemuBlockBitmapBlockcopyData blockbitmapblockcopydata;
    struct testQemuBlockBitmapBlockcommitData blockbitmapblockcommitdata;
    char *capslatest_x86_64 = NULL;
    g_autoptr(virQEMUCaps) caps_x86_64 = NULL;
    g_autoptr(GHashTable) qmp_schema_x86_64 = NULL;
    virJSONValue *qmp_schemaroot_x86_64_blockdev_add = NULL;
    g_autoptr(virStorageSource) bitmapSourceChain = NULL;

    if (qemuTestDriverInit(&driver) < 0)
        return EXIT_FAILURE;

    bitmapSourceChain = testQemuBackupIncrementalBitmapCalculateGetFakeChain();

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

    if (!(qmp_schema_x86_64 = testQEMUSchemaLoadLatest("x86_64"))) {
        ret = -1;
        goto cleanup;
    }

    if (virQEMUQAPISchemaPathGet("blockdev-add/arg-type",
                                 qmp_schema_x86_64,
                                 &qmp_schemaroot_x86_64_blockdev_add) < 0 ||
        !qmp_schemaroot_x86_64_blockdev_add) {
        VIR_TEST_VERBOSE("failed to find schema entry for blockdev-add");
        ret = -1;
        goto cleanup;
    }

    virTestCounterReset("qemu storage source xml->json->xml ");

#define TEST_JSON_FORMAT(tpe, xmlstr) \
    do { \
        xmljsonxmldata.type = tpe; \
        xmljsonxmldata.xml = xmlstr; \
        if (virTestRun(virTestCounterNext(), testBackingXMLjsonXML, \
                       &xmljsonxmldata) < 0) \
            ret = -1; \
    } while (0)

#define TEST_JSON_FORMAT_NET(xmlstr) \
    TEST_JSON_FORMAT(VIR_STORAGE_TYPE_NETWORK, xmlstr)

    xmljsonxmldata.schema = qmp_schema_x86_64;
    xmljsonxmldata.schemaroot = qmp_schemaroot_x86_64_blockdev_add;

    TEST_JSON_FORMAT(VIR_STORAGE_TYPE_FILE, "<source file='/path/to/file'/>\n");

    /* type VIR_STORAGE_TYPE_BLOCK is not tested since it parses back to 'file' */
    /* type VIR_STORAGE_TYPE_DIR it is a 'format' driver in qemu */

    TEST_JSON_FORMAT(VIR_STORAGE_TYPE_NVME,
                     "<source type='pci' namespace='1'>\n"
                     "  <address domain='0x0000' bus='0x01' slot='0x00' function='0x0'/>\n"
                     "</source>\n");

    TEST_JSON_FORMAT_NET("<source protocol='http' name=''>\n"
                         "  <host name='example.com' port='80'/>\n"
                         "</source>\n");
    TEST_JSON_FORMAT_NET("<source protocol='http' name='file'>\n"
                         "  <host name='example.com' port='80'/>\n"
                         "</source>\n");
    TEST_JSON_FORMAT_NET("<source protocol='https' name='file'>\n"
                         "  <host name='example.com' port='432'/>\n"
                         "</source>\n");
    TEST_JSON_FORMAT_NET("<source protocol='https' name='file'>\n"
                         "  <host name='example.com' port='432'/>\n"
                         "  <ssl verify='no'/>\n"
                         "  <readahead size='1024'/>\n"
                         "  <timeout seconds='1337'/>\n"
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

#define TEST_DISK_TO_JSON_FULL(nme, fl) \
    do { \
        diskxmljsondata.name = nme; \
        diskxmljsondata.images = NULL; \
        diskxmljsondata.nimages = 0; \
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

#define TEST_DISK_TO_JSON(nme) TEST_DISK_TO_JSON_FULL(nme, false)

    diskxmljsondata.schema = qmp_schema_x86_64;
    diskxmljsondata.schemaroot = qmp_schemaroot_x86_64_blockdev_add;

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
    TEST_DISK_TO_JSON("file-backing_basic-aio_io_uring");
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
    TEST_DISK_TO_JSON("network-http-noopts");
    TEST_DISK_TO_JSON("network-http-curlopts");

    TEST_DISK_TO_JSON("block-raw-noopts");
    TEST_DISK_TO_JSON("block-raw-reservations");

    TEST_DISK_TO_JSON("nvme-raw-noopts");

#define TEST_JSON_TO_JSON(nme) \
    do { \
        jsontojsondata.name = nme; \
        if (virTestRun("JSON to JSON " nme, testJSONtoJSON, \
                       &jsontojsondata) < 0) \
            ret = -1; \
    } while (0)

    jsontojsondata.schema = qmp_schema_x86_64;
    jsontojsondata.schemaroot = qmp_schemaroot_x86_64_blockdev_add;

    TEST_JSON_TO_JSON("curl-libguestfs");
    TEST_JSON_TO_JSON("ssh-passthrough-libguestfs");

#define TEST_IMAGE_CREATE(testname, testbacking) \
    do { \
        imagecreatedata.name = testname; \
        imagecreatedata.backingname = testbacking; \
        if (virTestRun("image create xml to props " testname, testQemuImageCreate, \
                       &imagecreatedata) < 0) \
            ret = -1; \
    } while (0)

    imagecreatedata.schema = qmp_schema_x86_64;

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
    TEST_IMAGE_CREATE("qcow2-backing-qcow2luks", "qcow2-luks-noopts");
    TEST_IMAGE_CREATE("qcow2-luks-encopts-backing", "qcow2");
    TEST_IMAGE_CREATE("qcow2-backing-raw-slice", "raw-slice");
    TEST_IMAGE_CREATE("qcow2-backing-qcow2-slice", "qcow2-slice");

    TEST_IMAGE_CREATE("network-gluster-qcow2", NULL);
    TEST_IMAGE_CREATE("network-rbd-qcow2", NULL);
    TEST_IMAGE_CREATE("network-ssh-qcow2", NULL);

#define TEST_BITMAP_DETECT(testname) \
    do { \
        if (virTestRun("bitmap detect " testname, \
                       testQemuDetectBitmaps, testname) < 0) \
            ret = -1; \
    } while (0)

    TEST_BITMAP_DETECT("empty");

    TEST_BITMAP_DETECT("basic");
    TEST_BITMAP_DETECT("snapshots");
    TEST_BITMAP_DETECT("synthetic");

#define TEST_BACKUP_BITMAP_CALCULATE(testname, source, incrbackup, named) \
    do { \
        backupbitmapcalcdata.name = testname; \
        backupbitmapcalcdata.chain = source; \
        backupbitmapcalcdata.incremental = incrbackup; \
        backupbitmapcalcdata.nodedatafile = named; \
        if (virTestRun("incremental backup bitmap " testname, \
                       testQemuBackupIncrementalBitmapCalculate, \
                       &backupbitmapcalcdata) < 0) \
            ret = -1; \
    } while (0)

    TEST_BACKUP_BITMAP_CALCULATE("empty", bitmapSourceChain, "a", "empty");

    TEST_BACKUP_BITMAP_CALCULATE("basic-flat", bitmapSourceChain, "current", "basic");
    TEST_BACKUP_BITMAP_CALCULATE("basic-intermediate", bitmapSourceChain, "d", "basic");
    TEST_BACKUP_BITMAP_CALCULATE("basic-deep", bitmapSourceChain, "a", "basic");

    TEST_BACKUP_BITMAP_CALCULATE("snapshots-flat", bitmapSourceChain, "current", "snapshots");
    TEST_BACKUP_BITMAP_CALCULATE("snapshots-intermediate", bitmapSourceChain, "d", "snapshots");
    TEST_BACKUP_BITMAP_CALCULATE("snapshots-deep", bitmapSourceChain, "a", "snapshots");

#define TEST_CHECKPOINT_DELETE(testname, delbmp, named) \
    do { \
        checkpointdeletedata.name = testname; \
        checkpointdeletedata.chain = bitmapSourceChain; \
        checkpointdeletedata.deletebitmap = delbmp; \
        checkpointdeletedata.nodedatafile = named; \
        if (virTestRun("checkpoint delete " testname, \
                       testQemuCheckpointDelete, &checkpointdeletedata) < 0) \
        ret = -1; \
    } while (0)

    TEST_CHECKPOINT_DELETE("empty", "a", "empty");

    TEST_CHECKPOINT_DELETE("basic-noparent", "a", "basic");
    TEST_CHECKPOINT_DELETE("basic-intermediate1", "b", "basic");
    TEST_CHECKPOINT_DELETE("basic-intermediate2", "c", "basic");
    TEST_CHECKPOINT_DELETE("basic-intermediate3", "d", "basic");
    TEST_CHECKPOINT_DELETE("basic-current", "current", "basic");

    TEST_CHECKPOINT_DELETE("snapshots-noparent", "a", "snapshots");
    TEST_CHECKPOINT_DELETE("snapshots-intermediate1", "b", "snapshots");
    TEST_CHECKPOINT_DELETE("snapshots-intermediate2", "c", "snapshots");
    TEST_CHECKPOINT_DELETE("snapshots-intermediate3", "d", "snapshots");
    TEST_CHECKPOINT_DELETE("snapshots-current", "current", "snapshots");

    TEST_CHECKPOINT_DELETE("synthetic-noparent", "a", "synthetic");
    TEST_CHECKPOINT_DELETE("synthetic-intermediate1", "b", "synthetic");
    TEST_CHECKPOINT_DELETE("synthetic-intermediate2", "c", "synthetic");
    TEST_CHECKPOINT_DELETE("synthetic-intermediate3", "d", "synthetic");
    TEST_CHECKPOINT_DELETE("synthetic-current", "current", "synthetic");

#define TEST_BITMAP_VALIDATE(testname, bitmap, rc) \
    do { \
        blockbitmapvalidatedata.name = testname; \
        blockbitmapvalidatedata.chain = bitmapSourceChain; \
        blockbitmapvalidatedata.bitmapname = bitmap; \
        blockbitmapvalidatedata.expect = rc; \
        if (virTestRun("bitmap validate " testname " " bitmap, \
                       testQemuBlockBitmapValidate, \
                       &blockbitmapvalidatedata) < 0) \
            ret = -1; \
    } while (0)

    TEST_BITMAP_VALIDATE("empty", "a", false);

    TEST_BITMAP_VALIDATE("basic", "a", true);
    TEST_BITMAP_VALIDATE("basic", "b", true);
    TEST_BITMAP_VALIDATE("basic", "c", true);
    TEST_BITMAP_VALIDATE("basic", "d", true);
    TEST_BITMAP_VALIDATE("basic", "current", true);

    TEST_BITMAP_VALIDATE("snapshots", "a", true);
    TEST_BITMAP_VALIDATE("snapshots", "b", true);
    TEST_BITMAP_VALIDATE("snapshots", "c", true);
    TEST_BITMAP_VALIDATE("snapshots", "d", true);
    TEST_BITMAP_VALIDATE("snapshots", "current", true);

    TEST_BITMAP_VALIDATE("synthetic", "a", false);
    TEST_BITMAP_VALIDATE("synthetic", "b", false);
    TEST_BITMAP_VALIDATE("synthetic", "c", false);
    TEST_BITMAP_VALIDATE("synthetic", "d", false);
    TEST_BITMAP_VALIDATE("synthetic", "current", false);
    TEST_BITMAP_VALIDATE("synthetic", "top-ok", true);
    TEST_BITMAP_VALIDATE("synthetic", "top-inactive", false);
    TEST_BITMAP_VALIDATE("synthetic", "top-transient", false);
    TEST_BITMAP_VALIDATE("synthetic", "top-inactive-transient", false);

#define TEST_BITMAP_BLOCKCOPY(testname, shllw, ndf) \
    do { \
        blockbitmapblockcopydata.name = testname; \
        blockbitmapblockcopydata.shallow = shllw; \
        blockbitmapblockcopydata.nodedatafile = ndf; \
        blockbitmapblockcopydata.chain = bitmapSourceChain;\
        if (virTestRun("bitmap block copy " testname, \
                       testQemuBlockBitmapBlockcopy, \
                       &blockbitmapblockcopydata) < 0) \
            ret = -1; \
    } while (0)

    TEST_BITMAP_BLOCKCOPY("empty-shallow", true, "empty");
    TEST_BITMAP_BLOCKCOPY("empty-deep", false, "empty");

    TEST_BITMAP_BLOCKCOPY("basic-shallow", true, "basic");
    TEST_BITMAP_BLOCKCOPY("basic-deep", false, "basic");

    TEST_BITMAP_BLOCKCOPY("snapshots-shallow", true, "snapshots");
    TEST_BITMAP_BLOCKCOPY("snapshots-deep", false, "snapshots");

#define TEST_BITMAP_BLOCKCOMMIT(testname, topimg, baseimg, ndf) \
    do {\
        blockbitmapblockcommitdata.name = testname; \
        blockbitmapblockcommitdata.chain = bitmapSourceChain; \
        blockbitmapblockcommitdata.top = testQemuBitmapGetFakeChainEntry(bitmapSourceChain, topimg); \
        blockbitmapblockcommitdata.base = testQemuBitmapGetFakeChainEntry(bitmapSourceChain, baseimg); \
        blockbitmapblockcommitdata.nodedatafile = ndf; \
        if (virTestRun("bitmap block commit " testname, \
                       testQemuBlockBitmapBlockcommit, \
                       &blockbitmapblockcommitdata) < 0) \
        ret = -1; \
    } while (0)

    TEST_BITMAP_BLOCKCOMMIT("empty", 1, 2, "empty");

    TEST_BITMAP_BLOCKCOMMIT("basic-1-2", 1, 2, "basic");
    TEST_BITMAP_BLOCKCOMMIT("basic-1-3", 1, 3, "basic");
    TEST_BITMAP_BLOCKCOMMIT("basic-2-3", 2, 3, "basic");

    TEST_BITMAP_BLOCKCOMMIT("snapshots-1-2", 1, 2, "snapshots");
    TEST_BITMAP_BLOCKCOMMIT("snapshots-1-3", 1, 3, "snapshots");
    TEST_BITMAP_BLOCKCOMMIT("snapshots-1-4", 1, 4, "snapshots");
    TEST_BITMAP_BLOCKCOMMIT("snapshots-1-5", 1, 5, "snapshots");

    TEST_BITMAP_BLOCKCOMMIT("snapshots-2-3", 2, 3, "snapshots");
    TEST_BITMAP_BLOCKCOMMIT("snapshots-2-4", 2, 4, "snapshots");
    TEST_BITMAP_BLOCKCOMMIT("snapshots-2-5", 2, 5, "snapshots");

    TEST_BITMAP_BLOCKCOMMIT("snapshots-3-4", 3, 4, "snapshots");
    TEST_BITMAP_BLOCKCOMMIT("snapshots-3-5", 3, 5, "snapshots");

    TEST_BITMAP_BLOCKCOMMIT("snapshots-4-5", 4, 5, "snapshots");

 cleanup:
    qemuTestDriverFree(&driver);
    VIR_FREE(capslatest_x86_64);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
