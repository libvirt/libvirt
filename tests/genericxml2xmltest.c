#include <config.h>

#include <unistd.h>

#include <sys/types.h>
#include <fcntl.h>

#include "testutils.h"
#include "internal.h"
#include "virstring.h"
#include "conf/backup_conf.h"

#define VIR_FROM_THIS VIR_FROM_NONE

static virCapsPtr caps;
static virDomainXMLOptionPtr xmlopt;

struct testInfo {
    const char *name;
    int different;
    bool inactive_only;
    testCompareDomXML2XMLResult expectResult;
};

static int
testCompareXMLToXMLHelper(const void *data)
{
    const struct testInfo *info = data;
    char *xml_in = NULL;
    char *xml_out = NULL;
    int ret = -1;

    xml_in = g_strdup_printf("%s/genericxml2xmlindata/%s.xml",
                             abs_srcdir, info->name);
    xml_out = g_strdup_printf("%s/genericxml2xmloutdata/%s.xml",
                              abs_srcdir, info->name);

    ret = testCompareDomXML2XMLFiles(caps, xmlopt, xml_in,
                                     info->different ? xml_out : xml_in,
                                     !info->inactive_only, 0,
                                     info->expectResult);
    VIR_FREE(xml_in);
    VIR_FREE(xml_out);
    return ret;
}


struct testCompareBackupXMLData {
    const char *testname;
    bool internal;
};


static virDomainDiskDefPtr
testCompareBackupXMLGetFakeDomdisk(const char *dst)
{
    virDomainDiskDefPtr domdisk = NULL;

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
    if (!(fakedef = virDomainDefNew()))
        return -1;

    fakedef->ndisks = backup->ndisks + 1;
    fakedef->disks = g_new0(virDomainDiskDefPtr, fakedef->ndisks);

    for (i = 0; i < backup->ndisks; i++)
        fakedef->disks[i] = testCompareBackupXMLGetFakeDomdisk(backup->disks[i].name);

    fakedef->disks[fakedef->ndisks -1 ] = testCompareBackupXMLGetFakeDomdisk("vdextradisk");

    if (virDomainBackupAlignDisks(backup, fakedef, "SUFFIX") < 0) {
        VIR_TEST_VERBOSE("failed to align backup def '%s'", file_in);
        return -1;
    }

    if (virDomainBackupDefFormat(&buf, backup, data->internal) < 0) {
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

#define DO_TEST_FULL(name, is_different, inactive, expectResult) \
    do { \
        const struct testInfo info = {name, is_different, inactive, \
                                      expectResult}; \
        if (virTestRun("GENERIC XML-2-XML " name, \
                       testCompareXMLToXMLHelper, &info) < 0) \
            ret = -1; \
    } while (0)

#define DO_TEST(name) \
    DO_TEST_FULL(name, 0, false, TEST_COMPARE_DOM_XML2XML_RESULT_SUCCESS)

#define DO_TEST_DIFFERENT(name) \
    DO_TEST_FULL(name, 1, false, TEST_COMPARE_DOM_XML2XML_RESULT_SUCCESS)

    DO_TEST_DIFFERENT("disk-virtio");
    DO_TEST_DIFFERENT("disk-hyperv-physical");
    DO_TEST_DIFFERENT("disk-hyperv-virtual");

    DO_TEST_DIFFERENT("graphics-vnc-minimal");
    DO_TEST_DIFFERENT("graphics-vnc-manual-port");
    DO_TEST_DIFFERENT("graphics-vnc-socket");
    DO_TEST_DIFFERENT("graphics-vnc-socket-listen");
    DO_TEST_DIFFERENT("graphics-listen-back-compat");
    DO_TEST_FULL("graphics-listen-back-compat-mismatch", 0, false,
        TEST_COMPARE_DOM_XML2XML_RESULT_FAIL_PARSE);
    DO_TEST_DIFFERENT("graphics-vnc-listen-attr-only");
    DO_TEST_DIFFERENT("graphics-vnc-listen-element-minimal");
    DO_TEST_DIFFERENT("graphics-vnc-listen-element-with-address");
    DO_TEST_DIFFERENT("graphics-vnc-socket-attr-listen-address");
    DO_TEST_DIFFERENT("graphics-vnc-socket-attr-listen-socket");
    DO_TEST_FULL("graphics-vnc-socket-attr-listen-socket-mismatch", 0, false,
        TEST_COMPARE_DOM_XML2XML_RESULT_FAIL_PARSE);
    DO_TEST("graphics-vnc-autoport-no");

    DO_TEST_FULL("name-slash-fail", 0, false,
        TEST_COMPARE_DOM_XML2XML_RESULT_FAIL_PARSE);

    DO_TEST("perf");

    DO_TEST("vcpus-individual");
    DO_TEST("disk-network-http");

    DO_TEST("cpu-cache-emulate");
    DO_TEST("cpu-cache-passthrough");
    DO_TEST("cpu-cache-disable");

    DO_TEST("network-interface-mac-check");

    DO_TEST_DIFFERENT("chardev-tcp");
    DO_TEST_FULL("chardev-tcp-missing-host", 0, false,
                 TEST_COMPARE_DOM_XML2XML_RESULT_FAIL_PARSE);
    DO_TEST_FULL("chardev-tcp-missing-service", 0, false,
                 TEST_COMPARE_DOM_XML2XML_RESULT_FAIL_PARSE);
    DO_TEST_FULL("chardev-tcp-multiple-source", 0, false,
                 TEST_COMPARE_DOM_XML2XML_RESULT_FAIL_PARSE);
    DO_TEST_DIFFERENT("chardev-udp");
    DO_TEST_FULL("chardev-udp-missing-connect-service", 0, false,
                 TEST_COMPARE_DOM_XML2XML_RESULT_FAIL_PARSE);
    DO_TEST_FULL("chardev-udp-multiple-source", 0, false,
                 TEST_COMPARE_DOM_XML2XML_RESULT_FAIL_PARSE);
    DO_TEST_DIFFERENT("chardev-unix");
    DO_TEST_FULL("chardev-unix-smartcard-missing-path", 0, false,
                 TEST_COMPARE_DOM_XML2XML_RESULT_FAIL_PARSE);
    DO_TEST_FULL("chardev-unix-redirdev-missing-path", 0, false,
                 TEST_COMPARE_DOM_XML2XML_RESULT_FAIL_PARSE);
    DO_TEST_FULL("chardev-unix-rng-missing-path", 0, false,
                 TEST_COMPARE_DOM_XML2XML_RESULT_FAIL_PARSE);
    DO_TEST_DIFFERENT("chardev-reconnect");
    DO_TEST_FULL("chardev-reconnect-missing-timeout", 0, false,
                 TEST_COMPARE_DOM_XML2XML_RESULT_FAIL_PARSE);
    DO_TEST_FULL("chardev-reconnect-invalid-mode", 0, false,
                 TEST_COMPARE_DOM_XML2XML_RESULT_FAIL_PARSE);

    DO_TEST("cachetune-small");
    DO_TEST("cachetune-cdp");
    DO_TEST_DIFFERENT("cachetune");
    DO_TEST_DIFFERENT("cachetune-extra-tunes");
    DO_TEST_FULL("cachetune-colliding-allocs", false, true,
                 TEST_COMPARE_DOM_XML2XML_RESULT_FAIL_PARSE);
    DO_TEST_FULL("cachetune-colliding-tunes", false, true,
                 TEST_COMPARE_DOM_XML2XML_RESULT_FAIL_PARSE);
    DO_TEST_FULL("cachetune-colliding-types", false, true,
                 TEST_COMPARE_DOM_XML2XML_RESULT_FAIL_PARSE);
    DO_TEST_FULL("cachetune-colliding-monitor", false, true,
                 TEST_COMPARE_DOM_XML2XML_RESULT_FAIL_PARSE);
    DO_TEST_DIFFERENT("memorytune");
    DO_TEST_FULL("memorytune-colliding-allocs", false, true,
                 TEST_COMPARE_DOM_XML2XML_RESULT_FAIL_PARSE);
    DO_TEST_FULL("memorytune-colliding-cachetune", false, true,
                 TEST_COMPARE_DOM_XML2XML_RESULT_FAIL_PARSE);

    DO_TEST("tseg");

    DO_TEST("launch-security-sev");

    DO_TEST_DIFFERENT("cputune");
    DO_TEST("device-backenddomain");

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


    virObjectUnref(caps);
    virObjectUnref(xmlopt);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
