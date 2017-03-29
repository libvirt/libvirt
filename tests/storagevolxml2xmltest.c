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
                         const char *outxml, unsigned int flags)
{
    char *actual = NULL;
    int ret = -1;
    virStoragePoolDefPtr pool = NULL;
    virStorageVolDefPtr dev = NULL;

    if (!(pool = virStoragePoolDefParseFile(poolxml)))
        goto fail;

    if (!(dev = virStorageVolDefParseFile(pool, inxml, flags)))
        goto fail;

    if (!(actual = virStorageVolDefFormat(pool, dev)))
        goto fail;

    if (virTestCompareToFile(actual, outxml) < 0)
        goto fail;

    ret = 0;

 fail:
    VIR_FREE(actual);
    virStoragePoolDefFree(pool);
    virStorageVolDefFree(dev);
    return ret;
}

struct testInfo {
    const char *pool;
    const char *name;
    unsigned int flags;
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

    result = testCompareXMLToXMLFiles(poolxml, inxml, outxml, info->flags);

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

#define DO_TEST_FULL(pool, name, flags)                         \
    do {                                                        \
        struct testInfo info = { pool, name, flags };           \
        if (virTestRun("Storage Vol XML-2-XML " name,           \
                       testCompareXMLToXMLHelper, &info) < 0)   \
            ret = -1;                                           \
    }                                                           \
    while (0);

#define DO_TEST(pool, name) DO_TEST_FULL(pool, name, 0)

    DO_TEST("pool-dir", "vol-file");
    DO_TEST("pool-dir", "vol-file-naming");
    DO_TEST("pool-dir", "vol-file-backing");
    DO_TEST("pool-dir", "vol-file-iso");
    DO_TEST("pool-dir", "vol-qcow2");
    DO_TEST("pool-dir", "vol-qcow2-1.1");
    DO_TEST("pool-dir", "vol-qcow2-lazy");
    DO_TEST("pool-dir", "vol-qcow2-0.10-lazy");
    DO_TEST("pool-dir", "vol-qcow2-nobacking");
    DO_TEST("pool-dir", "vol-luks");
    DO_TEST("pool-dir", "vol-luks-cipher");
    DO_TEST("pool-disk", "vol-partition");
    DO_TEST("pool-logical", "vol-logical");
    DO_TEST("pool-logical", "vol-logical-backing");
    DO_TEST("pool-sheepdog", "vol-sheepdog");
    DO_TEST("pool-gluster", "vol-gluster-dir");
    DO_TEST("pool-gluster", "vol-gluster-dir-neg-uid");
    DO_TEST_FULL("pool-dir", "vol-qcow2-nocapacity",
                 VIR_VOL_XML_PARSE_NO_CAPACITY);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
