#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <fcntl.h>

#include "internal.h"
#include "testutils.h"
#include "network_conf.h"
#include "testutilsqemu.h"

static int
testCompareXMLToXMLFiles(const char *inxml, const char *outxml,
                         unsigned int flags)
{
    char *inXmlData = NULL;
    char *outXmlData = NULL;
    char *actual = NULL;
    int ret = -1;
    virNetworkDefPtr dev = NULL;

    if (virtTestLoadFile(inxml, &inXmlData) < 0)
        goto fail;
    if (virtTestLoadFile(outxml, &outXmlData) < 0)
        goto fail;

    if (!(dev = virNetworkDefParseString(inXmlData)))
        goto fail;

    if (!(actual = virNetworkDefFormat(dev, flags)))
        goto fail;

    if (STRNEQ(outXmlData, actual)) {
        virtTestDifference(stderr, outXmlData, actual);
        goto fail;
    }

    ret = 0;

 fail:
    VIR_FREE(inXmlData);
    VIR_FREE(outXmlData);
    VIR_FREE(actual);
    virNetworkDefFree(dev);
    return ret;
}

struct testInfo {
    const char *name;
    unsigned int flags;
};

static int
testCompareXMLToXMLHelper(const void *data)
{
    const struct testInfo *info = data;
    int result = -1;
    char *inxml = NULL;
    char *outxml = NULL;

    if (virAsprintf(&inxml, "%s/networkxml2xmlin/%s.xml",
                    abs_srcdir, info->name) < 0 ||
        virAsprintf(&outxml, "%s/networkxml2xmlout/%s.xml",
                    abs_srcdir, info->name) < 0) {
        goto cleanup;
    }

    result = testCompareXMLToXMLFiles(inxml, outxml, info->flags);

cleanup:
    VIR_FREE(inxml);
    VIR_FREE(outxml);

    return result;
}

static int
mymain(void)
{
    int ret = 0;

#define DO_TEST_FULL(name, flags)                                       \
    do {                                                                \
        const struct testInfo info = {name, flags};                     \
        if (virtTestRun("Network XML-2-XML " name,                      \
                        1, testCompareXMLToXMLHelper, &info) < 0)       \
            ret = -1;                                                   \
    } while (0)
#define DO_TEST(name) DO_TEST_FULL(name, 0)

    DO_TEST("isolated-network");
    DO_TEST("routed-network");
    DO_TEST("nat-network");
    DO_TEST("netboot-network");
    DO_TEST("netboot-proxy-network");
    DO_TEST("nat-network-dns-txt-record");
    DO_TEST("nat-network-dns-hosts");
    DO_TEST("8021Qbh-net");
    DO_TEST("direct-net");
    DO_TEST("host-bridge-net");
    DO_TEST("vepa-net");
    DO_TEST("bandwidth-network");
    DO_TEST_FULL("passthrough-pf", VIR_NETWORK_XML_INACTIVE);

    return ret==0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)
