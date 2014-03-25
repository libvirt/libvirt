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
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NONE

static int
testCompareXMLToXMLFiles(const char *poolxml, const char *inxml,
                         const char *outxml)
{
    char *poolXmlData = NULL;
    char *inXmlData = NULL;
    char *outXmlData = NULL;
    char *actual = NULL;
    int ret = -1;
    virStoragePoolDefPtr pool = NULL;
    virStorageVolDefPtr dev = NULL;

    if (virtTestLoadFile(poolxml, &poolXmlData) < 0)
        goto fail;
    if (virtTestLoadFile(inxml, &inXmlData) < 0)
        goto fail;
    if (virtTestLoadFile(outxml, &outXmlData) < 0)
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
    VIR_FREE(poolXmlData);
    VIR_FREE(inXmlData);
    VIR_FREE(outXmlData);
    VIR_FREE(actual);
    virStoragePoolDefFree(pool);
    virStorageVolDefFree(dev);
    return ret;
}

struct testInfo {
    const char *pool;
    const char *name;
};

static int
testCompareXMLToXMLHelper(const void *data)
{
    int result = -1;
    const struct testInfo *info = data;
    char *poolxml = NULL;
    char *inxml = NULL;
    char *outxml = NULL;

    if (virAsprintf(&poolxml, "%s/storagepoolxml2xmlin/%s.xml",
                    abs_srcdir, info->pool) < 0 ||
        virAsprintf(&inxml, "%s/storagevolxml2xmlin/%s.xml",
                    abs_srcdir, info->name) < 0 ||
        virAsprintf(&outxml, "%s/storagevolxml2xmlout/%s.xml",
                    abs_srcdir, info->name) < 0) {
        goto cleanup;
    }

    result = testCompareXMLToXMLFiles(poolxml, inxml, outxml);

 cleanup:
    VIR_FREE(poolxml);
    VIR_FREE(inxml);
    VIR_FREE(outxml);

    return result;
}


static int
mymain(void)
{
    int ret = 0;

#define DO_TEST(pool, name)                                     \
    do {                                                        \
        struct testInfo info = { pool, name };                  \
        if (virtTestRun("Storage Vol XML-2-XML " name,          \
                        testCompareXMLToXMLHelper, &info) < 0)  \
            ret = -1;                                           \
    }                                                           \
    while (0);

    DO_TEST("pool-dir", "vol-file");
    DO_TEST("pool-dir", "vol-file-naming");
    DO_TEST("pool-dir", "vol-file-backing");
    DO_TEST("pool-dir", "vol-qcow2");
    DO_TEST("pool-dir", "vol-qcow2-1.1");
    DO_TEST("pool-dir", "vol-qcow2-lazy");
    DO_TEST("pool-dir", "vol-qcow2-0.10-lazy");
    DO_TEST("pool-dir", "vol-qcow2-nobacking");
    DO_TEST("pool-disk", "vol-partition");
    DO_TEST("pool-logical", "vol-logical");
    DO_TEST("pool-logical", "vol-logical-backing");
    DO_TEST("pool-sheepdog", "vol-sheepdog");
    DO_TEST("pool-gluster", "vol-gluster-dir");

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)
