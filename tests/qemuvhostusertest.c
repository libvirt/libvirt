#include <config.h>

#include <inttypes.h>

#include "testutils.h"
#include "virfilewrapper.h"
#include "qemu/qemu_vhost_user.h"
#include "configmake.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

/* A very basic test. Parse given JSON vhostuser description into
 * an internal structure, format it back and compare with the
 * contents of the file (minus some keys that are not parsed).
 */
static int
testParseFormatVU(const void *opaque)
{
    const char *filename = opaque;
    g_autofree char *path = NULL;
    VIR_AUTOPTR(qemuVhostUser) vu = NULL;
    g_autofree char *buf = NULL;
    VIR_AUTOPTR(virJSONValue) json = NULL;
    g_autofree char *expected = NULL;
    g_autofree char *actual = NULL;

    if (virAsprintf(&path, "%s/qemuvhostuserdata/%s",
                    abs_srcdir, filename) < 0)
        return -1;

    if (!(vu = qemuVhostUserParse(path)))
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

    if (!(actual = qemuVhostUserFormat(vu)))
        return -1;

    return virTestCompareToString(expected, actual);
}


static int
testVUPrecedence(const void *opaque G_GNUC_UNUSED)
{
    g_autofree char *fakehome = NULL;
    VIR_AUTOSTRINGLIST vuList = NULL;
    size_t nvuList;
    size_t i;
    const char *expected[] = {
        PREFIX "/share/qemu/vhost-user/30-gpu.json",
        SYSCONFDIR "/qemu/vhost-user/40-gpu.json",
        PREFIX "/share/qemu/vhost-user/60-gpu.json",
    };
    const size_t nexpected = G_N_ELEMENTS(expected);

    if (VIR_STRDUP(fakehome, abs_srcdir "/qemuvhostuserdata/home/user/.config") < 0)
        return -1;

    setenv("XDG_CONFIG_HOME", fakehome, 1);

    if (qemuVhostUserFetchConfigs(&vuList, false) < 0)
        return -1;

    if (!vuList) {
        fprintf(stderr, "Expected a non-NULL result, but got a NULL result\n");
        return -1;
    }

    nvuList = virStringListLength((const char **)vuList);

    for (i = 0; i < MAX(nvuList, nexpected); i++) {
        const char *e = i < nexpected ? expected[i] : NULL;
        const char *f = i < nvuList ? vuList[i] : NULL;

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

    virFileWrapperAddPrefix(SYSCONFDIR "/qemu/vhost-user",
                            abs_srcdir "/qemuvhostuserdata/etc/qemu/vhost-user");
    virFileWrapperAddPrefix(PREFIX "/share/qemu/vhost-user",
                            abs_srcdir "/qemuvhostuserdata/usr/share/qemu/vhost-user");
    virFileWrapperAddPrefix("/home/user/.config/qemu/vhost-user",
                            abs_srcdir "/qemuvhostuserdata/home/user/.config/qemu/vhost-user");

#define DO_PARSE_TEST(filename) \
    do { \
        if (virTestRun("QEMU vhost-user " filename, \
                       testParseFormatVU, filename) < 0) \
            ret = -1; \
    } while (0)

    DO_PARSE_TEST("usr/share/qemu/vhost-user/50-gpu.json");

    if (virTestRun("QEMU vhost-user precedence test", testVUPrecedence, NULL) < 0)
        ret = -1;

    virFileWrapperClearPrefixes();

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}


VIR_TEST_MAIN(mymain)
