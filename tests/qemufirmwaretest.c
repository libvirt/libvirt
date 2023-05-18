#include <config.h>

#include <inttypes.h>

#include "testutils.h"
#include "virfilewrapper.h"
#include "qemu/qemu_firmware.h"
#include "configmake.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

/* A very basic test. Parse given JSON firmware description into
 * an internal structure, format it back and compare with the
 * contents of the file (minus some keys that are not parsed).
 */
static int
testParseFormatFW(const void *opaque)
{
    const char *filename = opaque;
    g_autofree char *inpath = NULL;
    g_autofree char *outpath = NULL;
    g_autoptr(qemuFirmware) fw = NULL;
    g_autoptr(virJSONValue) json = NULL;
    g_autofree char *expected = NULL;
    g_autofree char *actual = NULL;
    g_autofree char *buf = NULL;

    inpath = g_strdup_printf("%s/qemufirmwaredata/%s", abs_srcdir, filename);
    outpath = g_strdup_printf("%s/qemufirmwaredata/out/%s", abs_srcdir, filename);

    if (!(fw = qemuFirmwareParse(inpath)))
        return -1;

    if (virFileExists(outpath)) {
        if (virFileReadAll(outpath,
                           1024 * 1024, /* 1MiB */
                           &buf) < 0)
            return -1;
    } else {
        if (virFileReadAll(inpath,
                           1024 * 1024, /* 1MiB */
                           &buf) < 0)
            return -1;
    }

    if (!(json = virJSONValueFromString(buf)))
        return -1;

    /* Description and tags are not parsed. */
    if (virJSONValueObjectRemoveKey(json, "description", NULL) < 0 ||
        virJSONValueObjectRemoveKey(json, "tags", NULL) < 0)
        return -1;

    if (!(expected = virJSONValueToString(json, true)))
        return -1;

    if (!(actual = qemuFirmwareFormat(fw)))
        return -1;

    return virTestCompareToString(expected, actual);
}


static int
testFWPrecedence(const void *opaque G_GNUC_UNUSED)
{
    g_autofree char *fakehome = NULL;
    g_auto(GStrv) fwList = NULL;
    const char *expected[] = {
        SYSCONFDIR "/qemu/firmware/20-bios.json",
        PREFIX "/share/qemu/firmware/30-edk2-ovmf-4m-qcow2-x64-sb-enrolled.json",
        PREFIX "/share/qemu/firmware/31-edk2-ovmf-2m-raw-x64-sb-enrolled.json",
        PREFIX "/share/qemu/firmware/40-edk2-ovmf-4m-qcow2-x64-sb.json",
        PREFIX "/share/qemu/firmware/41-edk2-ovmf-2m-raw-x64-sb.json",
        PREFIX "/share/qemu/firmware/50-edk2-aarch64-qcow2.json",
        PREFIX "/share/qemu/firmware/50-edk2-ovmf-4m-qcow2-x64-nosb.json",
        PREFIX "/share/qemu/firmware/50-edk2-ovmf-x64-microvm.json",
        PREFIX "/share/qemu/firmware/51-edk2-aarch64-raw.json",
        PREFIX "/share/qemu/firmware/51-edk2-ovmf-2m-raw-x64-nosb.json",
        PREFIX "/share/qemu/firmware/52-edk2-aarch64-verbose-qcow2.json",
        PREFIX "/share/qemu/firmware/53-edk2-aarch64-verbose-raw.json",
        SYSCONFDIR "/qemu/firmware/59-combined.json",
        PREFIX "/share/qemu/firmware/60-edk2-ovmf-x64-amdsev.json",
        PREFIX "/share/qemu/firmware/60-edk2-ovmf-x64-inteltdx.json",
        PREFIX "/share/qemu/firmware/90-combined.json",
        PREFIX "/share/qemu/firmware/91-bios.json",
        NULL
    };
    const char **e;
    GStrv f;

    fakehome = g_strdup(abs_srcdir "/qemufirmwaredata/home/user/.config");

    g_setenv("XDG_CONFIG_HOME", fakehome, TRUE);

    if (qemuFirmwareFetchConfigs(&fwList, false) < 0)
        return -1;

    if (!fwList) {
        fprintf(stderr, "Expected a non-NULL result, but got a NULL result\n");
        return -1;
    }

    for (e = expected, f = fwList; *f || *e;) {
        if (STRNEQ_NULLABLE(*f, *e)) {
            fprintf(stderr,
                    "Unexpected path. Expected %s got %s \n",
                    NULLSTR(*e), NULLSTR(*f));
            return -1;
        }

        if (*f)
            f++;
        if (*e)
            e++;
    }

    return 0;
}


struct supportedData {
    const char *machine;
    virArch arch;
    bool secure;
    const char *fwlist;
    unsigned int *interfaces;
    size_t ninterfaces;
};


static int
testSupportedFW(const void *opaque)
{
    const struct supportedData *data = opaque;
    uint64_t actualInterfaces;
    uint64_t expectedInterfaces = 0;
    bool actualSecure;
    virFirmware **expFWs = NULL;
    size_t nexpFWs = 0;
    virFirmware **actFWs = NULL;
    size_t nactFWs = 0;
    size_t i;
    int ret = -1;

    for (i = 0; i < data->ninterfaces; i++)
        expectedInterfaces |= 1ULL << data->interfaces[i];

    if (virFirmwareParseList(data->fwlist, &expFWs, &nexpFWs) < 0) {
        fprintf(stderr, "Unable to parse list of expected FW paths\n");
        return -1;
    }

    /* virFirmwareParseList() expects to see pairs of paths: ${FW}:${NVRAM}.
     * Well, some images don't have a NVRAM store. In that case NULL was passed:
     * ${FW}:NULL. Now iterate over expected firmwares and fix this. */
    for (i = 0; i < nexpFWs; i++) {
        virFirmware *tmp = expFWs[i];

        if (STREQ(tmp->nvram, "NULL"))
            VIR_FREE(tmp->nvram);
    }

    if (qemuFirmwareGetSupported(data->machine, data->arch, false,
                                 &actualInterfaces, &actualSecure, &actFWs, &nactFWs) < 0) {
        fprintf(stderr, "Unable to get list of supported interfaces\n");
        goto cleanup;
    }

    if (actualInterfaces != expectedInterfaces) {
        fprintf(stderr,
                "Mismatch in supported interfaces. "
                "Expected 0x%" PRIx64 " got 0x%" PRIx64 "\n",
                expectedInterfaces, actualInterfaces);
        goto cleanup;
    }

    if (actualSecure != data->secure) {
        fprintf(stderr,
                "Mismatch in SMM requirement/support. "
                "Expected %d got %d\n",
                data->secure, actualSecure);
        goto cleanup;
    }

    for (i = 0; i < nactFWs; i++) {
        virFirmware *actFW = actFWs[i];
        virFirmware *expFW = NULL;

        if (i >= nexpFWs) {
            fprintf(stderr, "Unexpected FW image: %s NVRAM: %s\n",
                    actFW->name, NULLSTR(actFW->nvram));
            goto cleanup;
        }

        expFW = expFWs[i];

        if (STRNEQ(actFW->name, expFW->name) ||
            STRNEQ_NULLABLE(actFW->nvram, expFW->nvram)) {
            fprintf(stderr, "Unexpected FW image: %s NVRAM: %s\n"
                    "Expected: %s NVRAM: %s\n",
                    actFW->name, NULLSTR(actFW->nvram),
                    expFW->name, NULLSTR(expFW->nvram));
            goto cleanup;
        }
    }

    if (i < nexpFWs) {
        fprintf(stderr, "Expected FW image: %s NVRAM: %s got nothing\n",
                expFWs[i]->name, NULLSTR(expFWs[i]->nvram));
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virFirmwareFreeList(actFWs, nactFWs);
    virFirmwareFreeList(expFWs, nexpFWs);
    return ret;
}


static int
mymain(void)
{
    int ret = 0;

    virFileWrapperAddPrefix(SYSCONFDIR "/qemu/firmware",
                            abs_srcdir "/qemufirmwaredata/etc/qemu/firmware");
    virFileWrapperAddPrefix(PREFIX "/share/qemu/firmware",
                            abs_srcdir "/qemufirmwaredata/usr/share/qemu/firmware");
    virFileWrapperAddPrefix("/home/user/.config/qemu/firmware",
                            abs_srcdir "/qemufirmwaredata/home/user/.config/qemu/firmware");

#define DO_PARSE_TEST(filename) \
    do { \
        if (virTestRun("QEMU FW " filename, \
                       testParseFormatFW, filename) < 0) \
            ret = -1; \
    } while (0)

    DO_PARSE_TEST("usr/share/qemu/firmware/30-edk2-ovmf-4m-qcow2-x64-sb-enrolled.json");
    DO_PARSE_TEST("usr/share/qemu/firmware/31-edk2-ovmf-2m-raw-x64-sb-enrolled.json");
    DO_PARSE_TEST("usr/share/qemu/firmware/40-edk2-ovmf-4m-qcow2-x64-sb.json");
    DO_PARSE_TEST("usr/share/qemu/firmware/41-edk2-ovmf-2m-raw-x64-sb.json");
    DO_PARSE_TEST("usr/share/qemu/firmware/50-edk2-aarch64-qcow2.json");
    DO_PARSE_TEST("usr/share/qemu/firmware/50-edk2-ovmf-4m-qcow2-x64-nosb.json");
    DO_PARSE_TEST("usr/share/qemu/firmware/50-edk2-ovmf-x64-microvm.json");
    DO_PARSE_TEST("usr/share/qemu/firmware/51-edk2-aarch64-raw.json");
    DO_PARSE_TEST("usr/share/qemu/firmware/51-edk2-ovmf-2m-raw-x64-nosb.json");
    DO_PARSE_TEST("usr/share/qemu/firmware/52-edk2-aarch64-verbose-qcow2.json");
    DO_PARSE_TEST("usr/share/qemu/firmware/53-edk2-aarch64-verbose-raw.json");
    DO_PARSE_TEST("usr/share/qemu/firmware/60-edk2-ovmf-x64-amdsev.json");
    DO_PARSE_TEST("usr/share/qemu/firmware/60-edk2-ovmf-x64-inteltdx.json");
    DO_PARSE_TEST("usr/share/qemu/firmware/90-combined.json");
    DO_PARSE_TEST("usr/share/qemu/firmware/91-bios.json");

    if (virTestRun("QEMU FW precedence test", testFWPrecedence, NULL) < 0)
        ret = -1;

    /* The @fwlist contains pairs of ${FW}:${NVRAM}. If there's
     * no NVRAM expected pass literal "NULL" and test fixes that
     * later. */
#define DO_SUPPORTED_TEST(machine, arch, secure, fwlist, ...) \
    do { \
        unsigned int interfaces[] = {__VA_ARGS__}; \
        struct supportedData data = {machine, arch, secure, fwlist, \
                                     interfaces, G_N_ELEMENTS(interfaces)}; \
        if (virTestRun("QEMU FW SUPPORTED " machine " " #arch, \
                       testSupportedFW, &data) < 0) \
            ret = -1; \
    } while (0)

    DO_SUPPORTED_TEST("pc-i440fx-3.1", VIR_ARCH_X86_64, false,
                      "/usr/share/seabios/bios-256k.bin:NULL:"
                      "/usr/share/edk2/ovmf/OVMF_CODE_4M.qcow2:/usr/share/edk2/ovmf/OVMF_VARS_4M.qcow2:"
                      "/usr/share/edk2/ovmf/OVMF_CODE.fd:/usr/share/edk2/ovmf/OVMF_VARS.fd",
                      VIR_DOMAIN_OS_DEF_FIRMWARE_BIOS,
                      VIR_DOMAIN_OS_DEF_FIRMWARE_EFI);
    DO_SUPPORTED_TEST("pc-i440fx-3.1", VIR_ARCH_I686, false,
                      "/usr/share/seabios/bios-256k.bin:NULL",
                      VIR_DOMAIN_OS_DEF_FIRMWARE_BIOS);
    DO_SUPPORTED_TEST("pc-q35-3.1", VIR_ARCH_X86_64, true,
                      "/usr/share/seabios/bios-256k.bin:NULL:"
                      "/usr/share/edk2/ovmf/OVMF_CODE_4M.secboot.qcow2:/usr/share/edk2/ovmf/OVMF_VARS_4M.secboot.qcow2:"
                      "/usr/share/edk2/ovmf/OVMF_CODE.secboot.fd:/usr/share/edk2/ovmf/OVMF_VARS.secboot.fd:"
                      "/usr/share/edk2/ovmf/OVMF_CODE_4M.secboot.qcow2:/usr/share/edk2/ovmf/OVMF_VARS_4M.qcow2:"
                      "/usr/share/edk2/ovmf/OVMF_CODE.secboot.fd:/usr/share/edk2/ovmf/OVMF_VARS.fd:"
                      "/usr/share/edk2/ovmf/OVMF_CODE_4M.qcow2:/usr/share/edk2/ovmf/OVMF_VARS_4M.qcow2:"
                      "/usr/share/edk2/ovmf/OVMF_CODE.fd:/usr/share/edk2/ovmf/OVMF_VARS.fd:"
                      "/usr/share/edk2/ovmf/OVMF.secboot.fd:NULL:"
                      "/usr/share/edk2/ovmf/OVMF.amdsev.fd:NULL:"
                      "/usr/share/edk2/ovmf/OVMF.inteltdx.fd:NULL",
                      VIR_DOMAIN_OS_DEF_FIRMWARE_BIOS,
                      VIR_DOMAIN_OS_DEF_FIRMWARE_EFI);
    DO_SUPPORTED_TEST("pc-q35-3.1", VIR_ARCH_I686, false,
                      "/usr/share/seabios/bios-256k.bin:NULL",
                      VIR_DOMAIN_OS_DEF_FIRMWARE_BIOS);
    DO_SUPPORTED_TEST("microvm", VIR_ARCH_X86_64, false,
                      "/usr/share/edk2/ovmf/MICROVM.fd:NULL",
                      VIR_DOMAIN_OS_DEF_FIRMWARE_EFI);
    DO_SUPPORTED_TEST("virt-3.1", VIR_ARCH_AARCH64, false,
                      "/usr/share/edk2/aarch64/QEMU_EFI-silent-pflash.qcow2:/usr/share/edk2/aarch64/vars-template-pflash.qcow2:"
                      "/usr/share/edk2/aarch64/QEMU_EFI-silent-pflash.raw:/usr/share/edk2/aarch64/vars-template-pflash.raw:"
                      "/usr/share/edk2/aarch64/QEMU_EFI-pflash.qcow2:/usr/share/edk2/aarch64/vars-template-pflash.qcow2:"
                      "/usr/share/edk2/aarch64/QEMU_EFI-pflash.raw:/usr/share/edk2/aarch64/vars-template-pflash.raw",
                      VIR_DOMAIN_OS_DEF_FIRMWARE_EFI);

    virFileWrapperClearPrefixes();

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}


VIR_TEST_MAIN(mymain)
