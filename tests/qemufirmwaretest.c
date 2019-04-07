#include <config.h>

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
    VIR_AUTOFREE(char *) path = NULL;
    VIR_AUTOPTR(qemuFirmware) fw = NULL;
    VIR_AUTOFREE(char *) buf = NULL;
    VIR_AUTOPTR(virJSONValue) json = NULL;
    VIR_AUTOFREE(char *) expected = NULL;
    VIR_AUTOFREE(char *) actual = NULL;

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
testFWPrecedence(const void *opaque ATTRIBUTE_UNUSED)
{
    VIR_AUTOFREE(char *) fakehome = NULL;
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
    const size_t nexpected = ARRAY_CARDINALITY(expected);

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

    virFileWrapperClearPrefixes();

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}


VIR_TEST_MAIN(mymain)
