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


static int testCompareXMLToXMLFiles(const char *poolxml,
                                    const char *inxml,
                                    const char *outxml) {
    char poolXmlData[MAX_FILE];
    char *poolXmlPtr = &(poolXmlData[0]);
    char inXmlData[MAX_FILE];
    char *inXmlPtr = &(inXmlData[0]);
    char outXmlData[MAX_FILE];
    char *outXmlPtr = &(outXmlData[0]);
    char *actual = NULL;
    int ret = -1;
    virStoragePoolDefPtr pool = NULL;
    virStorageVolDefPtr dev = NULL;

    if (virtTestLoadFile(poolxml, &poolXmlPtr, MAX_FILE) < 0)
        goto fail;
    if (virtTestLoadFile(inxml, &inXmlPtr, MAX_FILE) < 0)
        goto fail;
    if (virtTestLoadFile(outxml, &outXmlPtr, MAX_FILE) < 0)
        goto fail;

    if (!(pool = virStoragePoolDefParseString(poolXmlData)))
        goto fail;

    if (!(dev = virStorageVolDefParseString(pool, inXmlData)))
        goto fail;

    if (!(actual = virStorageVolDefFormat(pool, dev)))
        goto fail;

    if (STRNEQ(outXmlData, actual)) {
        virtTestDifference(stderr, outXmlData, actual);
        goto fail;
    }

    ret = 0;

 fail:
    free(actual);
    virStoragePoolDefFree(pool);
    virStorageVolDefFree(dev);
    return ret;
}

struct testInfo {
    const char *pool;
    const char *name;
};

static int testCompareXMLToXMLHelper(const void *data) {
    char poolxml[PATH_MAX];
    char inxml[PATH_MAX];
    char outxml[PATH_MAX];
    const struct testInfo *info = data;

    snprintf(poolxml, PATH_MAX, "%s/storagepoolxml2xmlin/%s.xml",
             abs_srcdir, (const char*)info->pool);
    snprintf(inxml, PATH_MAX, "%s/storagevolxml2xmlin/%s.xml",
             abs_srcdir, (const char*)info->name);
    snprintf(outxml, PATH_MAX, "%s/storagevolxml2xmlout/%s.xml",
             abs_srcdir, (const char*)info->name);
    return testCompareXMLToXMLFiles(poolxml, inxml, outxml);
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

#define DO_TEST(pool, name) \
    do {                    \
        struct testInfo info = { pool, name };             \
        if (virtTestRun("Storage Vol XML-2-XML " name, \
                        1, testCompareXMLToXMLHelper, &info) < 0) \
            ret = -1;   \
       }    \
    while(0);

    DO_TEST("pool-dir", "vol-file");
    DO_TEST("pool-dir", "vol-file-backing");
    DO_TEST("pool-dir", "vol-qcow2");
    DO_TEST("pool-disk", "vol-partition");
    DO_TEST("pool-logical", "vol-logical");
    DO_TEST("pool-logical", "vol-logical-backing");

    return (ret==0 ? EXIT_SUCCESS : EXIT_FAILURE);
}

VIRT_TEST_MAIN(mymain)
