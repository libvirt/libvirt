#include <config.h>

#include "testutils.h"
#include "qemu/qemu_firmware.h"

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
mymain(void)
{
    int ret = 0;

#define DO_PARSE_TEST(filename) \
    do { \
        if (virTestRun("QEMU FW " filename, \
                       testParseFormatFW, filename) < 0) \
            ret = -1; \
    } while (0)

    DO_PARSE_TEST("bios.json");
    DO_PARSE_TEST("ovmf-sb-keys.json");
    DO_PARSE_TEST("ovmf-sb.json");
    DO_PARSE_TEST("ovmf.json");
    DO_PARSE_TEST("aavmf.json");

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}


VIR_TEST_MAIN(mymain)
