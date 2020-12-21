#include <config.h>

#include "testutils.h"

#ifdef WITH_VMX

# include <unistd.h>

# include "internal.h"
# include "viralloc.h"
# include "vmx/vmx.h"
# include "virstring.h"

# define VIR_FROM_THIS VIR_FROM_VMWARE

static virCapsPtr caps;
static virDomainXMLOptionPtr xmlopt;
static virVMXContext ctx;


static void
testCapsInit(void)
{
    virCapsGuestPtr guest = NULL;

    caps = virCapabilitiesNew(VIR_ARCH_I686, true, true);

    if (caps == NULL)
        return;

    virCapabilitiesAddHostMigrateTransport(caps, "vpxmigr");

    /* i686 guest */
    guest =
      virCapabilitiesAddGuest(caps, VIR_DOMAIN_OSTYPE_HVM,
                              VIR_ARCH_I686,
                              NULL, NULL, 0, NULL);

    if (guest == NULL)
        goto failure;

    if (virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_VMWARE, NULL, NULL, 0,
                                      NULL) == NULL) {
        goto failure;
    }

    /* x86_64 guest */
    guest =
      virCapabilitiesAddGuest(caps, VIR_DOMAIN_OSTYPE_HVM,
                              VIR_ARCH_X86_64,
                              NULL, NULL, 0, NULL);

    if (guest == NULL)
        goto failure;

    if (virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_VMWARE, NULL, NULL, 0,
                                      NULL) == NULL) {
        goto failure;
    }

    return;

 failure:
    virObjectUnref(caps);
    caps = NULL;
}

static int
testCompareFiles(const char *vmx, const char *xml, bool should_fail_parse)
{
    int ret = -1;
    char *vmxData = NULL;
    char *formatted = NULL;
    virDomainDefPtr def = NULL;

    if (virTestLoadFile(vmx, &vmxData) < 0)
        return -1;

    def = virVMXParseConfig(&ctx, xmlopt, caps, vmxData);
    if (should_fail_parse) {
        if (!def)
            ret = 0;
        else
            VIR_TEST_DEBUG("passed instead of expected failure");
        goto cleanup;
    }
    if (!def)
        goto cleanup;

    if (!virDomainDefCheckABIStability(def, def, xmlopt)) {
        fprintf(stderr, "ABI stability check failed on %s", vmx);
        goto cleanup;
    }

    if (!(formatted = virDomainDefFormat(def, xmlopt,
                                         VIR_DOMAIN_DEF_FORMAT_SECURE)))
        goto cleanup;

    if (virTestCompareToFile(formatted, xml) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    VIR_FREE(vmxData);
    VIR_FREE(formatted);
    virDomainDefFree(def);

    return ret;
}

struct testInfo {
    const char *input;
    const char *output;
    bool should_fail;
};

static int
testCompareHelper(const void *data)
{
    int ret = -1;
    const struct testInfo *info = data;
    char *vmx = NULL;
    char *xml = NULL;

    vmx = g_strdup_printf("%s/vmx2xmldata/vmx2xml-%s.vmx", abs_srcdir,
                          info->input);
    xml = g_strdup_printf("%s/vmx2xmldata/vmx2xml-%s.xml", abs_srcdir,
                          info->output);

    ret = testCompareFiles(vmx, xml, info->should_fail);

    VIR_FREE(vmx);
    VIR_FREE(xml);

    return ret;
}

static int
testParseVMXFileName(const char *fileName,
                     void *opaque G_GNUC_UNUSED,
                     char **src,
                     bool allow_missing)
{
    g_autofree char *copyOfFileName = NULL;
    char *tmp = NULL;
    char *saveptr = NULL;
    char *datastoreName = NULL;
    char *directoryAndFileName = NULL;

    *src = NULL;

    if (STRPREFIX(fileName, "/vmfs/volumes/")) {
        /* Found absolute path referencing a file inside a datastore */
        copyOfFileName = g_strdup(fileName);

        /* Expected format: '/vmfs/volumes/<datastore>/<path>' */
        if ((tmp = STRSKIP(copyOfFileName, "/vmfs/volumes/")) == NULL ||
            (datastoreName = strtok_r(tmp, "/", &saveptr)) == NULL ||
            (directoryAndFileName = strtok_r(NULL, "", &saveptr)) == NULL) {
            return -1;
        }

        if (STREQ(datastoreName, "missing") ||
            STRPREFIX(directoryAndFileName, "missing")) {
            if (allow_missing)
                return 0;

            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "Referenced missing file '%s'", fileName);
            return -1;
        }

        *src = g_strdup_printf("[%s] %s", datastoreName, directoryAndFileName);
    } else if (STRPREFIX(fileName, "/")) {
        /* Found absolute path referencing a file outside a datastore */
        *src = g_strdup(fileName);
    } else if (strchr(fileName, '/') != NULL) {
        /* Found relative path, this is not supported */
        return -1;
    } else {
        /* Found single file name referencing a file inside a datastore */
        *src = g_strdup_printf("[datastore] directory/%s", fileName);
    }

    return 0;
}

static int
mymain(void)
{
    int ret = 0;

# define DO_TEST_FULL(_in, _out, _should_fail) \
        do { \
            struct testInfo info = { _in, _out, _should_fail }; \
            virResetLastError(); \
            if (virTestRun("VMware VMX-2-XML "_in" -> "_out, \
                           testCompareHelper, &info) < 0) { \
                ret = -1; \
            } \
        } while (0)

# define DO_TEST(_in, _out) DO_TEST_FULL(_in, _out, false)
# define DO_TEST_FAIL(_in, _out) DO_TEST_FULL(_in, _out, true)

    testCapsInit();

    if (caps == NULL)
        return EXIT_FAILURE;

    if (!(xmlopt = virVMXDomainXMLConfInit(caps)))
        return EXIT_FAILURE;

    ctx.opaque = NULL;
    ctx.parseFileName = testParseVMXFileName;
    ctx.formatFileName = NULL;
    ctx.autodetectSCSIControllerModel = NULL;
    ctx.datacenterPath = NULL;

    DO_TEST("case-insensitive-1", "case-insensitive-1");
    DO_TEST("case-insensitive-2", "case-insensitive-2");

    DO_TEST("minimal", "minimal");
    DO_TEST("minimal-64bit", "minimal-64bit");

    DO_TEST("graphics-vnc", "graphics-vnc");

    DO_TEST("scsi-driver", "scsi-driver");
    DO_TEST("scsi-writethrough", "scsi-writethrough");

    DO_TEST("harddisk-scsi-file", "harddisk-scsi-file");
    DO_TEST("harddisk-ide-file", "harddisk-ide-file");
    DO_TEST("harddisk-transient", "harddisk-transient");

    DO_TEST("cdrom-scsi-file", "cdrom-scsi-file");
    DO_TEST("cdrom-scsi-empty", "cdrom-scsi-empty");
    DO_TEST("cdrom-scsi-device", "cdrom-scsi-device");
    DO_TEST("cdrom-scsi-raw-device", "cdrom-scsi-raw-device");
    DO_TEST("cdrom-scsi-raw-auto-detect", "cdrom-scsi-raw-auto-detect");
    DO_TEST("cdrom-scsi-passthru", "cdrom-scsi-passthru");
    DO_TEST("cdrom-ide-file", "cdrom-ide-file");
    DO_TEST("cdrom-ide-empty", "cdrom-ide-empty");
    DO_TEST("cdrom-ide-empty-2", "cdrom-ide-empty-2");
    DO_TEST("cdrom-ide-device", "cdrom-ide-device");
    DO_TEST("cdrom-ide-raw-device", "cdrom-ide-raw-device");
    DO_TEST("cdrom-ide-raw-auto-detect", "cdrom-ide-raw-auto-detect");
    DO_TEST("cdrom-ide-raw-auto-detect", "cdrom-ide-raw-auto-detect");

    DO_TEST("cdrom-ide-file-missing-datastore", "cdrom-ide-empty");
    DO_TEST("cdrom-ide-file-missing-file", "cdrom-ide-empty");

    DO_TEST_FAIL("harddisk-ide-file-missing-datastore", "harddisk-ide-file");
    DO_TEST_FAIL("harddisk-scsi-file-missing-file", "harddisk-scsi-file");

    DO_TEST("floppy-file", "floppy-file");
    DO_TEST("floppy-device", "floppy-device");

    DO_TEST("sharedfolder", "sharedfolder");

    DO_TEST("ethernet-e1000", "ethernet-e1000");
    DO_TEST("ethernet-vmxnet2", "ethernet-vmxnet2");

    DO_TEST("ethernet-custom", "ethernet-custom");
    DO_TEST("ethernet-bridged", "ethernet-bridged");
    DO_TEST("ethernet-nat", "ethernet-nat");

    DO_TEST("ethernet-generated", "ethernet-generated");
    DO_TEST("ethernet-static", "ethernet-static");
    DO_TEST("ethernet-vpx", "ethernet-vpx");
    DO_TEST("ethernet-other", "ethernet-other");

    DO_TEST("serial-file", "serial-file");
    DO_TEST("serial-device", "serial-device");
    DO_TEST("serial-pipe-client-app", "serial-pipe");
    DO_TEST("serial-pipe-server-vm", "serial-pipe");
    DO_TEST("serial-pipe-client-app", "serial-pipe");
    DO_TEST("serial-pipe-server-vm", "serial-pipe");
    DO_TEST("serial-network-server", "serial-network-server");
    DO_TEST("serial-network-client", "serial-network-client");

    DO_TEST("parallel-file", "parallel-file");
    DO_TEST("parallel-device", "parallel-device");

    DO_TEST("esx-in-the-wild-1", "esx-in-the-wild-1");
    DO_TEST("esx-in-the-wild-2", "esx-in-the-wild-2");
    DO_TEST("esx-in-the-wild-3", "esx-in-the-wild-3");
    DO_TEST("esx-in-the-wild-4", "esx-in-the-wild-4");
    DO_TEST("esx-in-the-wild-5", "esx-in-the-wild-5");
    DO_TEST("esx-in-the-wild-6", "esx-in-the-wild-6");
    DO_TEST("esx-in-the-wild-7", "esx-in-the-wild-7");
    DO_TEST("esx-in-the-wild-8", "esx-in-the-wild-8");
    DO_TEST("esx-in-the-wild-9", "esx-in-the-wild-9");
    DO_TEST("esx-in-the-wild-10", "esx-in-the-wild-10");

    DO_TEST("gsx-in-the-wild-1", "gsx-in-the-wild-1");
    DO_TEST("gsx-in-the-wild-2", "gsx-in-the-wild-2");
    DO_TEST("gsx-in-the-wild-3", "gsx-in-the-wild-3");
    DO_TEST("gsx-in-the-wild-4", "gsx-in-the-wild-4");

    DO_TEST("ws-in-the-wild-1", "ws-in-the-wild-1");
    DO_TEST("ws-in-the-wild-2", "ws-in-the-wild-2");

    DO_TEST("fusion-in-the-wild-1", "fusion-in-the-wild-1");

    DO_TEST("annotation", "annotation");

    DO_TEST("smbios", "smbios");

    DO_TEST("svga", "svga");

    DO_TEST("firmware-efi", "firmware-efi");

    ctx.datacenterPath = "folder1/folder2/datacenter1";

    DO_TEST("datacenterpath", "datacenterpath");

    virObjectUnref(caps);
    virObjectUnref(xmlopt);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)

#else

int main(void)
{
    return EXIT_AM_SKIP;
}

#endif /* WITH_VMX */
