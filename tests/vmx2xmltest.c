#include <config.h>

#include "testutils.h"

#ifdef WITH_VMX

# include <unistd.h>

# include "internal.h"
# include "vmx/vmx.h"

# define VIR_FROM_THIS VIR_FROM_VMWARE

static virCaps *caps;
static virDomainXMLOption *xmlopt;
static virVMXContext ctx;


static void
testCapsInit(void)
{
    virCapsGuest *guest = NULL;

    caps = virCapabilitiesNew(VIR_ARCH_I686, true, true);

    if (caps == NULL)
        return;

    virCapabilitiesAddHostMigrateTransport(caps, "vpxmigr");

    /* i686 guest */
    guest = virCapabilitiesAddGuest(caps, VIR_DOMAIN_OSTYPE_HVM,
                                    VIR_ARCH_I686,
                                    NULL, NULL, 0, NULL);

    virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_VMWARE,
                                  NULL, NULL, 0, NULL);

    /* x86_64 guest */
    guest = virCapabilitiesAddGuest(caps, VIR_DOMAIN_OSTYPE_HVM,
                                    VIR_ARCH_X86_64,
                                    NULL, NULL, 0, NULL);

    virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_VMWARE,
                                  NULL, NULL, 0, NULL);
}

static int
testCompareFiles(const char *vmx, const char *xml, bool should_fail_parse)
{
    g_autofree char *vmxData = NULL;
    g_autofree char *formatted = NULL;
    g_autoptr(virDomainDef) def = NULL;

    if (virTestLoadFile(vmx, &vmxData) < 0)
        return -1;

    def = virVMXParseConfig(&ctx, xmlopt, caps, vmxData);
    if (should_fail_parse) {
        if (!def)
            return 0;

        VIR_TEST_DEBUG("passed instead of expected failure");
        return -1;
    }
    if (!def)
        return -1;

    if (!virDomainDefCheckABIStability(def, def, xmlopt)) {
        fprintf(stderr, "ABI stability check failed on %s", vmx);
        return -1;
    }

    if (!(formatted = virDomainDefFormat(def, xmlopt,
                                         VIR_DOMAIN_DEF_FORMAT_SECURE)))
        return -1;

    if (virTestCompareToFile(formatted, xml) < 0)
        return -1;

    return 0;
}

struct testInfo {
    const char *file;
    bool should_fail;
};

static int
testCompareHelper(const void *data)
{
    int ret = -1;
    const struct testInfo *info = data;
    g_autofree char *vmx = NULL;
    g_autofree char *xml = NULL;

    vmx = g_strdup_printf("%s/vmx2xmldata/%s.vmx", abs_srcdir,
                          info->file);
    xml = g_strdup_printf("%s/vmx2xmldata/%s.xml", abs_srcdir,
                          info->file);

    ret = testCompareFiles(vmx, xml, info->should_fail);

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

# define DO_TEST_FULL(file, should_fail) \
        do { \
            struct testInfo info = { file, should_fail }; \
            virResetLastError(); \
            if (virTestRun("VMware VMX-2-XML " file, \
                           testCompareHelper, &info) < 0) { \
                ret = -1; \
            } \
        } while (0)

# define DO_TEST(file) DO_TEST_FULL(file, false)
# define DO_TEST_FAIL(file) DO_TEST_FULL(file, true)

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

    DO_TEST("case-insensitive-1");
    DO_TEST("case-insensitive-2");

    DO_TEST("minimal");
    DO_TEST("minimal-64bit");

    DO_TEST("graphics-vnc");

    DO_TEST("scsi-driver");
    DO_TEST("scsi-writethrough");

    DO_TEST("harddisk-scsi-file");
    DO_TEST("harddisk-ide-file");
    DO_TEST("harddisk-transient");

    DO_TEST("cdrom-scsi-file");
    DO_TEST("cdrom-scsi-empty");
    DO_TEST("cdrom-scsi-device");
    DO_TEST("cdrom-scsi-raw-device");
    DO_TEST("cdrom-scsi-raw-auto-detect");
    DO_TEST("cdrom-scsi-passthru");
    DO_TEST("cdrom-ide-file");
    DO_TEST("cdrom-ide-empty");
    DO_TEST("cdrom-ide-empty-2");
    DO_TEST("cdrom-ide-device");
    DO_TEST("cdrom-ide-raw-device");
    DO_TEST("cdrom-ide-raw-auto-detect");

    DO_TEST("cdrom-ide-file-missing-datastore");
    DO_TEST("cdrom-ide-file-missing-file");

    DO_TEST_FAIL("harddisk-ide-file-missing-datastore");
    DO_TEST_FAIL("harddisk-scsi-file-missing-file");

    DO_TEST("floppy-file");
    DO_TEST("floppy-device");

    DO_TEST("sharedfolder");

    DO_TEST("ethernet-e1000");
    DO_TEST("ethernet-vmxnet2");

    DO_TEST("ethernet-custom");
    DO_TEST("ethernet-bridged");
    DO_TEST("ethernet-nat");

    DO_TEST("ethernet-generated");
    DO_TEST("ethernet-static");
    DO_TEST("ethernet-vpx");
    DO_TEST("ethernet-other");
    DO_TEST("ethernet-null");
    DO_TEST("ethernet-vds");

    DO_TEST("serial-file");
    DO_TEST("serial-device");
    DO_TEST("serial-pipe-client-app");
    DO_TEST("serial-pipe-client-vm");
    DO_TEST("serial-pipe-server-app");
    DO_TEST("serial-pipe-server-vm");
    DO_TEST("serial-network-server");
    DO_TEST("serial-network-client");

    DO_TEST("parallel-file");
    DO_TEST("parallel-device");

    DO_TEST("esx-in-the-wild-1");
    DO_TEST("esx-in-the-wild-2");
    DO_TEST("esx-in-the-wild-3");
    DO_TEST("esx-in-the-wild-4");
    DO_TEST("esx-in-the-wild-5");
    DO_TEST("esx-in-the-wild-6");
    DO_TEST("esx-in-the-wild-7");
    DO_TEST("esx-in-the-wild-8");
    DO_TEST("esx-in-the-wild-9");
    DO_TEST("esx-in-the-wild-10");
    DO_TEST("esx-in-the-wild-11");

    DO_TEST("gsx-in-the-wild-1");
    DO_TEST("gsx-in-the-wild-2");
    DO_TEST("gsx-in-the-wild-3");
    DO_TEST("gsx-in-the-wild-4");

    DO_TEST("ws-in-the-wild-1");
    DO_TEST("ws-in-the-wild-2");

    DO_TEST("fusion-in-the-wild-1");

    DO_TEST("annotation");

    DO_TEST("smbios");

    DO_TEST("svga");

    DO_TEST("firmware-efi");

    ctx.datacenterPath = "folder1/folder2/datacenter1";

    DO_TEST("datacenterpath");

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
