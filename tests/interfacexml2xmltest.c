#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <fcntl.h>

#include "internal.h"
#include "testutils.h"
#include "interface_conf.h"
#include "testutilsqemu.h"

static char *progname;
static char *abs_srcdir;

#define MAX_FILE 4096


static int testCompareXMLToXMLFiles(const char *xml) {
    char xmlData[MAX_FILE];
    char *xmlPtr = &(xmlData[0]);
    char *actual = NULL;
    int ret = -1;
    virInterfaceDefPtr dev = NULL;

    if (virtTestLoadFile(xml, &xmlPtr, MAX_FILE) < 0)
        goto fail;

    if (!(dev = virInterfaceDefParseString(NULL, xmlData)))
        goto fail;

    if (!(actual = virInterfaceDefFormat(NULL, dev)))
        goto fail;

    if (STRNEQ(xmlData, actual)) {
        virtTestDifference(stderr, xmlData, actual);
        goto fail;
    }

    ret = 0;

 fail:
    if (ret != 0)
        fprintf(stderr, "expected: -------\n%s", actual);
    free(actual);
    virInterfaceDefFree(dev);
    return ret;
}

static int testCompareXMLToXMLHelper(const void *data) {
    char xml[PATH_MAX];
    snprintf(xml, PATH_MAX, "%s/interfaceschemadata/%s.xml",
             abs_srcdir, (const char*)data);
    return testCompareXMLToXMLFiles(xml);
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
    if (virtTestRun("Node device XML-2-XML " name, \
                    1, testCompareXMLToXMLHelper, (name)) < 0) \
        ret = -1

    DO_TEST("ethernet-dhcp");
    DO_TEST("ethernet-static");
    DO_TEST("ethernet-static-no-prefix");
    DO_TEST("bridge");
    DO_TEST("bridge42");
    DO_TEST("bridge-vlan");
    DO_TEST("bridge-no-address");
    DO_TEST("vlan");
    DO_TEST("bond");
    DO_TEST("bond-arp");

    return (ret==0 ? EXIT_SUCCESS : EXIT_FAILURE);
}

VIRT_TEST_MAIN(mymain)
