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
testCompareXMLToXMLFiles(const char *inxml, const char *outxml)
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

    if (!(actual = virNetworkDefFormat(dev)))
        goto fail;

    if (STRNEQ(outXmlData, actual)) {
        virtTestDifference(stderr, outXmlData, actual);
        goto fail;
    }

    ret = 0;

 fail:
    free(inXmlData);
    free(outXmlData);
    free(actual);
    virNetworkDefFree(dev);
    return ret;
}

static int
testCompareXMLToXMLHelper(const void *data)
{
    int result = -1;
    char *inxml = NULL;
    char *outxml = NULL;

    if (virAsprintf(&inxml, "%s/networkxml2xmlin/%s.xml",
                    abs_srcdir, (const char*)data) < 0 ||
        virAsprintf(&outxml, "%s/networkxml2xmlout/%s.xml",
                    abs_srcdir, (const char*)data) < 0) {
        goto cleanup;
    }

    result = testCompareXMLToXMLFiles(inxml, outxml);

cleanup:
    free(inxml);
    free(outxml);

    return result;
}

static int
mymain(void)
{
    int ret = 0;

#define DO_TEST(name) \
    if (virtTestRun("Network XML-2-XML " name, \
                    1, testCompareXMLToXMLHelper, (name)) < 0) \
        ret = -1

    DO_TEST("isolated-network");
    DO_TEST("routed-network");
    DO_TEST("nat-network");
    DO_TEST("netboot-network");
    DO_TEST("netboot-proxy-network");
    DO_TEST("nat-network-dns-txt-record");
    DO_TEST("nat-network-dns-hosts");

    return (ret==0 ? EXIT_SUCCESS : EXIT_FAILURE);
}

VIRT_TEST_MAIN(mymain)
