#include <config.h>


#include "internal.h"
#include "testutils.h"
#include "secret_conf.h"

#define VIR_FROM_THIS VIR_FROM_NONE

static int
testCompareXMLToXMLFiles(const char *inxml, const char *outxml)
{
    g_autofree char *actual = NULL;
    g_autoptr(virSecretDef) secret = NULL;

    if (!(secret = virSecretDefParse(NULL, inxml, 0)))
        return -1;

    if (!(actual = virSecretDefFormat(secret)))
        return -1;

    if (virTestCompareToFile(actual, outxml) < 0)
        return -1;

    return 0;
}

struct testInfo {
    const char *name;
    bool different;
};

static int
testCompareXMLToXMLHelper(const void *data)
{
    int result = -1;
    g_autofree char *inxml = NULL;
    g_autofree char *outxml = NULL;
    const struct testInfo *info = data;

    inxml = g_strdup_printf("%s/secretxml2xmlin/%s.xml", abs_srcdir, info->name);
    outxml = g_strdup_printf("%s/secretxml2xml%s/%s.xml",
                             abs_srcdir,
                             info->different ? "out" : "in",
                             info->name);

    result = testCompareXMLToXMLFiles(inxml, outxml);

    return result;
}

static int
mymain(void)
{
    int ret = 0;

#define DO_TEST(name) \
    do { \
        const struct testInfo info = {name, false}; \
        if (virTestRun("Secret XML->XML " name, \
                       testCompareXMLToXMLHelper, &info) < 0) \
            ret = -1; \
    } while (0)

    DO_TEST("ephemeral-usage-volume");
    DO_TEST("usage-volume");
    DO_TEST("usage-ceph");
    DO_TEST("usage-ceph-space");
    DO_TEST("usage-iscsi");
    DO_TEST("usage-tls");
    DO_TEST("usage-vtpm");

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
