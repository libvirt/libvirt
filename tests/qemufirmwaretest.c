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
    g_autofree char *path = NULL;
    g_autoptr(qemuFirmware) fw = NULL;
    g_autofree char *buf = NULL;
    g_autoptr(virJSONValue) json = NULL;
    g_autofree char *expected = NULL;
    g_autofree char *actual = NULL;

    if (virAsprintf(&path, "%s/qemufirmwaredata/%s",
                    abs_srcdir, filename) < 0)
        return -1;

    if (!(fw = qemuFirmwareParse(path)))
        return -1;

    if (virFileReadAll(path,
                       1024 * 1024, /* 1MiB */
                       &buf) < 0)
        return -1;

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
    VIR_AUTOSTRINGLIST fwList = NULL;
    size_t nfwList;
    size_t i;
    const char *expected[] = {
        PREFIX "/share/qemu/firmware/40-bios.json",
        SYSCONFDIR "/qemu/firmware/40-ovmf-sb-keys.json",
        PREFIX "/share/qemu/firmware/50-ovmf-sb-keys.json",
        PREFIX "/share/qemu/firmware/61-ovmf.json",
        PREFIX "/share/qemu/firmware/70-aavmf.json",
    };
    const size_t nexpected = G_N_ELEMENTS(expected);

    if (VIR_STRDUP(fakehome, abs_srcdir "/qemufirmwaredata/home/user/.config") < 0)
        return -1;

    setenv("XDG_CONFIG_HOME", fakehome, 1);

    if (qemuFirmwareFetchConfigs(&fwList, false) < 0)
        return -1;

    if (!fwList) {
        fprintf(stderr, "Expected a non-NULL result, but got a NULL result\n");
        return -1;
    }

    nfwList = virStringListLength((const char **)fwList);

    for (i = 0; i < MAX(nfwList, nexpected); i++) {
        const char *e = i < nexpected ? expected[i] : NULL;
        const char *f = i < nfwList ? fwList[i] : NULL;

        if (STRNEQ_NULLABLE(e, f)) {
            fprintf(stderr,
                    "Unexpected path (i=%zu). Expected %s got %s \n",
                    i, NULLSTR(e), NULLSTR(f));
            return -1;
        }
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
    virFirmwarePtr *expFWs = NULL;
    size_t nexpFWs = 0;
    virFirmwarePtr *actFWs = NULL;
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
        virFirmwarePtr tmp = expFWs[i];

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
        virFirmwarePtr actFW = actFWs[i];
        virFirmwarePtr expFW = NULL;

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

    DO_PARSE_TEST("usr/share/qemu/firmware/40-bios.json");
    DO_PARSE_TEST("usr/share/qemu/firmware/50-ovmf-sb-keys.json");
    DO_PARSE_TEST("usr/share/qemu/firmware/60-ovmf-sb.json");
    DO_PARSE_TEST("usr/share/qemu/firmware/61-ovmf.json");
    DO_PARSE_TEST("usr/share/qemu/firmware/70-aavmf.json");

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
                      "/usr/share/OVMF/OVMF_CODE.fd:/usr/share/OVMF/OVMF_VARS.fd",
                      VIR_DOMAIN_OS_DEF_FIRMWARE_BIOS,
                      VIR_DOMAIN_OS_DEF_FIRMWARE_EFI);
    DO_SUPPORTED_TEST("pc-i440fx-3.1", VIR_ARCH_I686, false,
                      "/usr/share/seabios/bios-256k.bin:NULL",
                      VIR_DOMAIN_OS_DEF_FIRMWARE_BIOS);
    DO_SUPPORTED_TEST("pc-q35-3.1", VIR_ARCH_X86_64, true,
                      "/usr/share/seabios/bios-256k.bin:NULL:"
                      "/usr/share/OVMF/OVMF_CODE.secboot.fd:/usr/share/OVMF/OVMF_VARS.secboot.fd:"
                      "/usr/share/OVMF/OVMF_CODE.fd:/usr/share/OVMF/OVMF_VARS.fd",
                      VIR_DOMAIN_OS_DEF_FIRMWARE_BIOS,
                      VIR_DOMAIN_OS_DEF_FIRMWARE_EFI);
    DO_SUPPORTED_TEST("pc-q35-3.1", VIR_ARCH_I686, false,
                      "/usr/share/seabios/bios-256k.bin:NULL",
                      VIR_DOMAIN_OS_DEF_FIRMWARE_BIOS);
    DO_SUPPORTED_TEST("virt-3.1", VIR_ARCH_AARCH64, false,
                      "/usr/share/AAVMF/AAVMF_CODE.fd:/usr/share/AAVMF/AAVMF_VARS.fd",
                      VIR_DOMAIN_OS_DEF_FIRMWARE_EFI);

    virFileWrapperClearPrefixes();

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}


VIR_TEST_MAIN(mymain)
