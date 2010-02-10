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

static char *progname;
static char *abs_srcdir;

#define MAX_FILE 4096


static int testCompareXMLToXMLFiles(const char *inxml, const char *outxml) {
    char inXmlData[MAX_FILE];
    char *inXmlPtr = &(inXmlData[0]);
    char outXmlData[MAX_FILE];
    char *outXmlPtr = &(outXmlData[0]);
    char *actual = NULL;
    int ret = -1;
    virNetworkDefPtr dev = NULL;

    if (virtTestLoadFile(inxml, &inXmlPtr, MAX_FILE) < 0)
        goto fail;
    if (virtTestLoadFile(outxml, &outXmlPtr, MAX_FILE) < 0)
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
    free(actual);
    virNetworkDefFree(dev);
    return ret;
}

static int testCompareXMLToXMLHelper(const void *data) {
    char inxml[PATH_MAX];
    char outxml[PATH_MAX];
    snprintf(inxml, PATH_MAX, "%s/networkxml2xmlin/%s.xml",
             abs_srcdir, (const char*)data);
    snprintf(outxml, PATH_MAX, "%s/networkxml2xmlout/%s.xml",
             abs_srcdir, (const char*)data);
    return testCompareXMLToXMLFiles(inxml, outxml);
}


static int
mymain(int argc, char **argv)
{
    int ret = 0;
    char cwd[PATH_MAX];

    progname = argv[0];

    if (argc > 1) {
        fprintf(stderr, "Usage: %s\n", progname);
        return (EXIT_FAILURE);
    }

    abs_srcdir = getenv("abs_srcdir");
    if (!abs_srcdir)
        abs_srcdir = getcwd(cwd, sizeof(cwd));

#define DO_TEST(name) \
    if (virtTestRun("Network XML-2-XML " name, \
                    1, testCompareXMLToXMLHelper, (name)) < 0) \
        ret = -1

    DO_TEST("isolated-network");
    DO_TEST("routed-network");
    DO_TEST("nat-network");
    DO_TEST("netboot-network");
    DO_TEST("netboot-proxy-network");

    return (ret==0 ? EXIT_SUCCESS : EXIT_FAILURE);
}

VIRT_TEST_MAIN(mymain)
