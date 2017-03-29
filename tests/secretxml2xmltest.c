#include <config.h>

#include <stdlib.h>

#include "internal.h"
#include "testutils.h"
#include "secret_conf.h"

#define VIR_FROM_THIS VIR_FROM_NONE

static int
testCompareXMLToXMLFiles(const char *inxml, const char *outxml)
{
    char *actual = NULL;
    int ret = -1;
    virSecretDefPtr secret = NULL;

    if (!(secret = virSecretDefParseFile(inxml)))
        goto fail;

    if (!(actual = virSecretDefFormat(secret)))
        goto fail;

    if (virTestCompareToFile(actual, outxml) < 0)
        goto fail;

    ret = 0;

 fail:
    VIR_FREE(actual);
    virSecretDefFree(secret);
    return ret;
}

struct testInfo {
    const char *name;
    bool different;
};

static int
testCompareXMLToXMLHelper(const void *data)
{
    int result = -1;
    char *inxml = NULL;
    char *outxml = NULL;
    const struct testInfo *info = data;

    if (virAsprintf(&inxml, "%s/secretxml2xmlin/%s.xml",
                    abs_srcdir, info->name) < 0 ||
        virAsprintf(&outxml, "%s/secretxml2xml%s/%s.xml",
                    abs_srcdir,
                    info->different ? "out" : "in",
                    info->name) < 0) {
        goto cleanup;
    }

    result = testCompareXMLToXMLFiles(inxml, outxml);

 cleanup:
    VIR_FREE(inxml);
    VIR_FREE(outxml);

    return result;
}

static int
mymain(void)
{
    int ret = 0;

#define DO_TEST(name)                                           \
    do {                                                        \
        const struct testInfo info = {name, false};             \
        if (virTestRun("Secret XML->XML " name,                 \
                       testCompareXMLToXMLHelper, &info) < 0)   \
            ret = -1;                                           \
    } while (0)

    DO_TEST("ephemeral-usage-volume");
    DO_TEST("usage-volume");
    DO_TEST("usage-ceph");
    DO_TEST("usage-iscsi");
    DO_TEST("usage-tls");

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
