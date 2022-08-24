#include <config.h>

#include "testutils.h"

#ifdef WITH_VMX

# include <unistd.h>

# include "internal.h"
# include "viralloc.h"
# include "vmx/vmx.h"

# define VIR_FROM_THIS VIR_FROM_VMWARE

static virCaps *caps;
static virVMXContext ctx;
static virDomainXMLOption *xmlopt;


static void
testCapsInit(void)
{
    virCapsGuest *guest = NULL;

    caps = virCapabilitiesNew(VIR_ARCH_I686, true, true);

    if (caps == NULL)
        return;

    virCapabilitiesAddHostMigrateTransport(caps, "esx");


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
testCompareFiles(const char *xml, const char *vmx, int virtualHW_version)
{
    g_autofree char *formatted = NULL;
    g_autoptr(virDomainDef) def = NULL;

    def = virDomainDefParseFile(xml, xmlopt, NULL,
                                VIR_DOMAIN_DEF_PARSE_INACTIVE);

    if (def == NULL)
        return -1;

    if (!virDomainDefCheckABIStability(def, def, xmlopt)) {
        fprintf(stderr, "ABI stability check failed on %s", xml);
        return -1;
    }

    formatted = virVMXFormatConfig(&ctx, xmlopt, def, virtualHW_version);
    if (formatted == NULL)
        return -1;

    if (virTestCompareToFile(formatted, vmx) < 0)
        return -1;

    return 0;
}

struct testInfo {
    const char *input;
    const char *output;
    int virtualHW_version;
};

static int
testCompareHelper(const void *data)
{
    int result = -1;
    const struct testInfo *info = data;
    g_autofree char *xml = NULL;
    g_autofree char *vmx = NULL;

    xml = g_strdup_printf("%s/xml2vmxdata/xml2vmx-%s.xml", abs_srcdir,
                          info->input);
    vmx = g_strdup_printf("%s/xml2vmxdata/xml2vmx-%s.vmx", abs_srcdir,
                          info->output);

    result = testCompareFiles(xml, vmx, info->virtualHW_version);

    return result;
}

static int
testAutodetectSCSIControllerModel(virDomainDiskDef *def G_GNUC_UNUSED,
                                  int *model, void *opaque G_GNUC_UNUSED)
{
    *model = VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LSILOGIC;

    return 0;
}

static char *
testFormatVMXFileName(const char *src, void *opaque G_GNUC_UNUSED)
{
    bool success = false;
    g_autofree char *copyOfDatastorePath = NULL;
    char *tmp = NULL;
    char *saveptr = NULL;
    char *datastoreName = NULL;
    char *directoryAndFileName = NULL;
    char *absolutePath = NULL;

    if (STRPREFIX(src, "[")) {
        /* Found potential datastore path */
        copyOfDatastorePath = g_strdup(src);

        /* Expected format: '[<datastore>] <path>' where <path> is optional */
        if ((tmp = STRSKIP(copyOfDatastorePath, "[")) == NULL || *tmp == ']' ||
            (datastoreName = strtok_r(tmp, "]", &saveptr)) == NULL) {
            goto cleanup;
        }

        directoryAndFileName = strtok_r(NULL, "", &saveptr);

        if (directoryAndFileName == NULL) {
            directoryAndFileName = (char *)"";
        } else {
            directoryAndFileName += strspn(directoryAndFileName, " ");
        }

        absolutePath = g_strdup_printf("/vmfs/volumes/%s/%s", datastoreName,
                                       directoryAndFileName);
    } else if (STRPREFIX(src, "/")) {
        /* Found absolute path */
        absolutePath = g_strdup(src);
    } else {
        /* Found relative path, this is not supported */
        goto cleanup;
    }

    success = true;

 cleanup:
    if (! success)
        VIR_FREE(absolutePath);

    return absolutePath;
}

static int
mymain(void)
{
    int result = 0;

# define DO_TEST(_in, _out, _version) \
        do { \
            struct testInfo info = { _in, _out, _version }; \
            virResetLastError(); \
            if (virTestRun("VMware XML-2-VMX "_in" -> "_out, \
                           testCompareHelper, &info) < 0) { \
                result = -1; \
            } \
        } while (0)

    testCapsInit();

    if (caps == NULL)
        return EXIT_FAILURE;

    if (!(xmlopt = virVMXDomainXMLConfInit(caps)))
        return EXIT_FAILURE;

    ctx.opaque = NULL;
    ctx.parseFileName = NULL;
    ctx.formatFileName = testFormatVMXFileName;
    ctx.autodetectSCSIControllerModel = testAutodetectSCSIControllerModel;
    ctx.datacenterPath = NULL;

    DO_TEST("minimal", "minimal", 4);
    DO_TEST("minimal-64bit", "minimal-64bit", 4);

    DO_TEST("graphics-vnc", "graphics-vnc", 4);

    DO_TEST("scsi-driver", "scsi-driver", 4);
    DO_TEST("scsi-writethrough", "scsi-writethrough", 4);

    DO_TEST("harddisk-scsi-file", "harddisk-scsi-file", 4);
    DO_TEST("harddisk-ide-file", "harddisk-ide-file", 4);

    DO_TEST("cdrom-scsi-file", "cdrom-scsi-file", 4);
    DO_TEST("cdrom-scsi-empty", "cdrom-scsi-empty", 4);
    DO_TEST("cdrom-scsi-device", "cdrom-scsi-device", 4);
    DO_TEST("cdrom-scsi-raw-device", "cdrom-scsi-raw-device", 4);
    DO_TEST("cdrom-scsi-raw-auto-detect", "cdrom-scsi-raw-auto-detect", 4);
    DO_TEST("cdrom-scsi-passthru", "cdrom-scsi-passthru", 4);
    DO_TEST("cdrom-ide-file", "cdrom-ide-file", 4);
    DO_TEST("cdrom-ide-empty", "cdrom-ide-empty", 4);
    DO_TEST("cdrom-ide-device", "cdrom-ide-device", 4);
    DO_TEST("cdrom-ide-raw-device", "cdrom-ide-raw-device", 4);
    DO_TEST("cdrom-ide-raw-auto-detect", "cdrom-ide-raw-auto-detect", 4);

    DO_TEST("floppy-file", "floppy-file", 4);
    DO_TEST("floppy-device", "floppy-device", 4);

    DO_TEST("sharedfolder", "sharedfolder", 4);

    DO_TEST("ethernet-e1000", "ethernet-e1000", 4);
    DO_TEST("ethernet-vmxnet2", "ethernet-vmxnet2", 4);

    DO_TEST("ethernet-custom", "ethernet-custom", 4);
    DO_TEST("ethernet-bridged", "ethernet-bridged", 4);
    DO_TEST("ethernet-nat", "ethernet-nat", 4);

    DO_TEST("ethernet-generated", "ethernet-generated", 4);
    DO_TEST("ethernet-static", "ethernet-static", 4);
    DO_TEST("ethernet-vpx", "ethernet-vpx", 4);
    DO_TEST("ethernet-other", "ethernet-other", 4);
    DO_TEST("ethernet-mac-type", "ethernet-mac-type", 4);

    DO_TEST("ethernet-null", "ethernet-null", 4);
    DO_TEST("ethernet-vds", "ethernet-vds", 4);

    DO_TEST("serial-file", "serial-file", 4);
    DO_TEST("serial-device", "serial-device", 4);
    DO_TEST("serial-pipe", "serial-pipe", 4);
    DO_TEST("serial-network-server", "serial-network-server", 7);
    DO_TEST("serial-network-client", "serial-network-client", 7);

    DO_TEST("parallel-file", "parallel-file", 4);
    DO_TEST("parallel-device", "parallel-device", 4);

    DO_TEST("esx-in-the-wild-1", "esx-in-the-wild-1", 4);
    DO_TEST("esx-in-the-wild-2", "esx-in-the-wild-2", 4);
    DO_TEST("esx-in-the-wild-3", "esx-in-the-wild-3", 4);
    DO_TEST("esx-in-the-wild-4", "esx-in-the-wild-4", 4);
    DO_TEST("esx-in-the-wild-5", "esx-in-the-wild-5", 4);
    DO_TEST("esx-in-the-wild-6", "esx-in-the-wild-6", 4);
    DO_TEST("esx-in-the-wild-7", "esx-in-the-wild-7", 4);
    DO_TEST("esx-in-the-wild-9", "esx-in-the-wild-9", 10);

    DO_TEST("gsx-in-the-wild-1", "gsx-in-the-wild-1", 4);
    DO_TEST("gsx-in-the-wild-2", "gsx-in-the-wild-2", 4);
    DO_TEST("gsx-in-the-wild-3", "gsx-in-the-wild-3", 4);
    DO_TEST("gsx-in-the-wild-4", "gsx-in-the-wild-4", 4);

    DO_TEST("ws-in-the-wild-1", "ws-in-the-wild-1", 8);
    DO_TEST("ws-in-the-wild-2", "ws-in-the-wild-2", 8);

    DO_TEST("fusion-in-the-wild-1", "fusion-in-the-wild-1", 9);

    DO_TEST("annotation", "annotation", 4);

    DO_TEST("smbios", "smbios", 4);

    DO_TEST("svga", "svga", 4);

    DO_TEST("firmware-efi", "firmware-efi", 4);

    DO_TEST("datacenterpath", "datacenterpath", 4);

    virObjectUnref(caps);
    virObjectUnref(xmlopt);

    return result == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)

#else

int main(void)
{
    return EXIT_AM_SKIP;
}

#endif /* WITH_VMX */
