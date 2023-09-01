#include <config.h>

#include <unistd.h>

#include <sys/types.h>
#include <fcntl.h>

#include "testutils.h"
#include "internal.h"
#include "conf/backup_conf.h"

#define VIR_FROM_THIS VIR_FROM_NONE

static virCaps *caps;
static virDomainXMLOption *xmlopt;

struct testInfo {
    const char *name;
    int different;
    bool active_only;
    testCompareDomXML2XMLResult expectResult;
};

static int
testCompareXMLToXMLHelper(const void *data)
{
    const struct testInfo *info = data;
    g_autofree char *xml_in = NULL;
    g_autofree char *xml_out = NULL;
    int ret = -1;

    xml_in = g_strdup_printf("%s/genericxml2xmlindata/%s.xml",
                             abs_srcdir, info->name);
    xml_out = g_strdup_printf("%s/genericxml2xmloutdata/%s.xml",
                              abs_srcdir, info->name);

    ret = testCompareDomXML2XMLFiles(caps, xmlopt, xml_in,
                                     info->different ? xml_out : xml_in,
                                     info->active_only, 0,
                                     info->expectResult);
    return ret;
}


struct testCompareBackupXMLData {
    const char *testname;
    bool internal;
};


static virDomainDiskDef *
testCompareBackupXMLGetFakeDomdisk(const char *dst)
{
    virDomainDiskDef *domdisk = NULL;

    if (!(domdisk = virDomainDiskDefNew(NULL)))
        abort();

    domdisk->dst = g_strdup(dst);
    domdisk->src->type = VIR_STORAGE_TYPE_FILE;
    domdisk->src->format = VIR_STORAGE_FILE_QCOW2;
    domdisk->src->path = g_strdup_printf("/fake/%s.qcow2", dst);

    return domdisk;
}


static int
testCompareBackupXML(const void *opaque)
{
    const struct testCompareBackupXMLData *data = opaque;
    const char *testname = data->testname;
    g_autofree char *xml_in = NULL;
    g_autofree char *file_in = NULL;
    g_autofree char *file_out = NULL;
    g_autoptr(virDomainBackupDef) backup = NULL;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    g_autofree char *actual = NULL;
    unsigned int parseFlags = 0;
    g_autoptr(virDomainDef) fakedef = NULL;
    size_t i;

    if (data->internal)
        parseFlags |= VIR_DOMAIN_BACKUP_PARSE_INTERNAL;

    file_in = g_strdup_printf("%s/domainbackupxml2xmlin/%s.xml",
                              abs_srcdir, testname);
    file_out = g_strdup_printf("%s/domainbackupxml2xmlout/%s.xml",
                               abs_srcdir, testname);

    if (virFileReadAll(file_in, 1024 * 64, &xml_in) < 0)
        return -1;

    if (!(backup = virDomainBackupDefParseString(xml_in, xmlopt, parseFlags))) {
        VIR_TEST_VERBOSE("failed to parse backup def '%s'", file_in);
        return -1;
    }

    /* create a fake definition and fill it with disks */
    if (!(fakedef = virDomainDefNew(xmlopt)))
        return -1;

    fakedef->ndisks = backup->ndisks + 1;
    fakedef->disks = g_new0(virDomainDiskDef *, fakedef->ndisks);

    for (i = 0; i < backup->ndisks; i++)
        fakedef->disks[i] = testCompareBackupXMLGetFakeDomdisk(backup->disks[i].name);

    fakedef->disks[fakedef->ndisks -1 ] = testCompareBackupXMLGetFakeDomdisk("vdextradisk");

    if (virDomainBackupAlignDisks(backup, fakedef, "SUFFIX") < 0) {
        VIR_TEST_VERBOSE("failed to align backup def '%s'", file_in);
        return -1;
    }

    if (virDomainBackupDefFormat(&buf, backup, data->internal, NULL) < 0) {
        VIR_TEST_VERBOSE("failed to format backup def '%s'", file_in);
        return -1;
    }

    actual = virBufferContentAndReset(&buf);

    return virTestCompareToFile(actual, file_out);
}


static int
mymain(void)
{
    int ret = 0;

    if (!(caps = virTestGenericCapsInit()))
        return EXIT_FAILURE;

    if (!(xmlopt = virTestGenericDomainXMLConfInit()))
        return EXIT_FAILURE;

#define DO_TEST_FULL(name, is_different, active, expectResult) \
    do { \
        const struct testInfo info = {name, is_different, active, \
                                      expectResult}; \
        if (virTestRun("GENERIC XML-2-XML " name, \
                       testCompareXMLToXMLHelper, &info) < 0) \
            ret = -1; \
    } while (0)

#define DO_TEST(name) \
    DO_TEST_FULL(name, 0, true, TEST_COMPARE_DOM_XML2XML_RESULT_SUCCESS)

#define DO_TEST_DIFFERENT(name) \
    DO_TEST_FULL(name, 1, true, TEST_COMPARE_DOM_XML2XML_RESULT_SUCCESS)

#define DO_TEST_FAIL_ACTIVE(name) \
    DO_TEST_FULL(name, 0, true, TEST_COMPARE_DOM_XML2XML_RESULT_FAIL_PARSE)

#define DO_TEST_FAIL_INACTIVE(name) \
    DO_TEST_FULL(name, 0, false, TEST_COMPARE_DOM_XML2XML_RESULT_FAIL_PARSE)

    DO_TEST_DIFFERENT("disk-virtio");
    DO_TEST_DIFFERENT("disk-hyperv-physical");
    DO_TEST_DIFFERENT("disk-hyperv-virtual");

    DO_TEST_DIFFERENT("graphics-vnc-minimal");
    DO_TEST_DIFFERENT("graphics-vnc-manual-port");
    DO_TEST_DIFFERENT("graphics-vnc-socket");
    DO_TEST_DIFFERENT("graphics-vnc-socket-listen");
    DO_TEST_DIFFERENT("graphics-listen-back-compat");
    DO_TEST_FAIL_ACTIVE("graphics-listen-back-compat-mismatch");
    DO_TEST_DIFFERENT("graphics-vnc-listen-attr-only");
    DO_TEST_DIFFERENT("graphics-vnc-listen-element-minimal");
    DO_TEST_DIFFERENT("graphics-vnc-listen-element-with-address");
    DO_TEST_DIFFERENT("graphics-vnc-socket-attr-listen-address");
    DO_TEST_DIFFERENT("graphics-vnc-socket-attr-listen-socket");
    DO_TEST_FAIL_ACTIVE("graphics-vnc-socket-attr-listen-socket-mismatch");
    DO_TEST("graphics-vnc-autoport-no");
    DO_TEST_FAIL_INACTIVE("graphics-listen-network-invalid");

    DO_TEST_FAIL_ACTIVE("name-slash-fail");

    DO_TEST("perf");

    DO_TEST("vcpus-individual");
    DO_TEST("disk-network-http");

    DO_TEST("cpu-cache-emulate");
    DO_TEST("cpu-cache-passthrough");
    DO_TEST("cpu-cache-disable");

    DO_TEST("network-interface-mac-check");
    DO_TEST_DIFFERENT("network-interface-mac-clear");

    DO_TEST_DIFFERENT("chardev-tcp");
    DO_TEST_FAIL_ACTIVE("chardev-tcp-missing-host");
    DO_TEST_FAIL_ACTIVE("chardev-tcp-missing-service");
    DO_TEST_FAIL_ACTIVE("chardev-tcp-multiple-source");
    DO_TEST_DIFFERENT("chardev-udp");
    DO_TEST_FAIL_ACTIVE("chardev-udp-missing-connect-service");
    DO_TEST_FAIL_ACTIVE("chardev-udp-multiple-source");
    DO_TEST_DIFFERENT("chardev-unix");
    DO_TEST_FAIL_ACTIVE("chardev-unix-smartcard-missing-path");
    DO_TEST_FAIL_ACTIVE("chardev-unix-redirdev-missing-path");
    DO_TEST_FAIL_ACTIVE("chardev-unix-rng-missing-path");
    DO_TEST_DIFFERENT("chardev-reconnect");
    DO_TEST_FAIL_ACTIVE("chardev-reconnect-missing-timeout");
    DO_TEST_FAIL_ACTIVE("chardev-reconnect-invalid-mode");

    DO_TEST("cachetune-small");
    DO_TEST("cachetune-cdp");
    DO_TEST("cachetune");
    DO_TEST_DIFFERENT("cachetune-extra-tunes");
    DO_TEST_FAIL_INACTIVE("cachetune-colliding-allocs");
    DO_TEST_FAIL_INACTIVE("cachetune-colliding-tunes");
    DO_TEST_FAIL_INACTIVE("cachetune-colliding-types");
    DO_TEST_FAIL_INACTIVE("cachetune-colliding-monitor");
    DO_TEST_DIFFERENT("memorytune");
    DO_TEST_FAIL_INACTIVE("memorytune-colliding-allocs");
    DO_TEST_FAIL_INACTIVE("memorytune-colliding-cachetune");

    DO_TEST("tseg");

    DO_TEST("launch-security-sev");
    DO_TEST("launch-security-s390-pv");

    DO_TEST_DIFFERENT("cputune");
    DO_TEST("device-backenddomain");

    DO_TEST("fibrechannel-appid");

#define DO_TEST_BACKUP_FULL(name, intrnl) \
    do { \
        const struct testCompareBackupXMLData data = { .testname = name, \
                                                       .internal = intrnl }; \
        if (virTestRun("QEMU BACKUP XML-2-XML " name, testCompareBackupXML, &data) < 0) \
          ret = -1; \
    } while (false)

#define DO_TEST_BACKUP(name) \
    DO_TEST_BACKUP_FULL(name, false)

    DO_TEST_BACKUP("empty");
    DO_TEST_BACKUP("backup-pull");
    DO_TEST_BACKUP("backup-pull-seclabel");
    DO_TEST_BACKUP("backup-pull-encrypted");
    DO_TEST_BACKUP("backup-push");
    DO_TEST_BACKUP("backup-push-seclabel");
    DO_TEST_BACKUP("backup-push-encrypted");

    DO_TEST_BACKUP_FULL("backup-pull-internal-invalid", true);

    DO_TEST("cpu-phys-bits-emulate");
    DO_TEST("cpu-phys-bits-passthrough");

    DO_TEST("iothreadids");

    virObjectUnref(caps);
    virObjectUnref(xmlopt);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN_PRELOAD(mymain,
                      VIR_TEST_MOCK("virrandom"))
