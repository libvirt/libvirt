#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <fcntl.h>

#include "internal.h"
#include "testutils.h"
#include "storage_conf.h"
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
    virStoragePoolDefPtr dev = NULL;

    if (virtTestLoadFile(inxml, &inXmlPtr, MAX_FILE) < 0)
        goto fail;
    if (virtTestLoadFile(outxml, &outXmlPtr, MAX_FILE) < 0)
        goto fail;

    if (!(dev = virStoragePoolDefParseString(inXmlData)))
        goto fail;

    if (!(actual = virStoragePoolDefFormat(dev)))
        goto fail;

    if (STRNEQ(outXmlData, actual)) {
        virtTestDifference(stderr, outXmlData, actual);
        goto fail;
    }

    ret = 0;

 fail:
    free(actual);
    virStoragePoolDefFree(dev);
    return ret;
}

static int testCompareXMLToXMLHelper(const void *data) {
    char inxml[PATH_MAX];
    char outxml[PATH_MAX];
    snprintf(inxml, PATH_MAX, "%s/storagepoolxml2xmlin/%s.xml",
             abs_srcdir, (const char*)data);
    snprintf(outxml, PATH_MAX, "%s/storagepoolxml2xmlout/%s.xml",
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
    if (virtTestRun("Storage Pool XML-2-XML " name, \
                    1, testCompareXMLToXMLHelper, (name)) < 0) \
        ret = -1

    DO_TEST("pool-dir");
    DO_TEST("pool-fs");
    DO_TEST("pool-logical");
    DO_TEST("pool-logical-create");
    DO_TEST("pool-disk");
    DO_TEST("pool-iscsi");
    DO_TEST("pool-iscsi-auth");
    DO_TEST("pool-netfs");
    DO_TEST("pool-scsi");
    DO_TEST("pool-mpath");
    DO_TEST("pool-iscsi-multiiqn");

    return (ret==0 ? EXIT_SUCCESS : EXIT_FAILURE);
}

VIRT_TEST_MAIN(mymain)
