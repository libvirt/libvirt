#include <config.h>

#include <unistd.h>

#include <sys/types.h>
#include <fcntl.h>

#include "internal.h"
#include "testutils.h"
#include "storage_conf.h"

#define VIR_FROM_THIS VIR_FROM_NONE

static int
testCompareXMLToXMLFiles(const char *poolxml, const char *inxml,
                         const char *outxml, unsigned int flags)
{
    g_autofree char *actual = NULL;
    g_autoptr(virStoragePoolDef) pool = NULL;
    g_autoptr(virStorageVolDef) dev = NULL;

    if (!(pool = virStoragePoolDefParse(NULL, poolxml, 0)))
        return -1;

    if (!(dev = virStorageVolDefParse(pool, NULL, inxml, flags)))
        return -1;

    if (!(actual = virStorageVolDefFormat(pool, dev)))
        return -1;

    if (virTestCompareToFile(actual, outxml) < 0)
        return -1;

    return 0;
}

struct testInfo {
    const char *pool;
    const char *name;
    unsigned int flags;
};

static int
testCompareXMLToXMLHelper(const void *data)
{
    const struct testInfo *info = data;
    g_autofree char *poolxml = NULL;
    g_autofree char *inxml = NULL;
    g_autofree char *outxml = NULL;

    poolxml = g_strdup_printf("%s/storagepoolxml2xmlin/%s.xml",
                              abs_srcdir, info->pool);
    inxml = g_strdup_printf("%s/storagevolxml2xmlin/%s.xml",
                            abs_srcdir, info->name);
    outxml = g_strdup_printf("%s/storagevolxml2xmlout/%s.xml",
                             abs_srcdir, info->name);

    return testCompareXMLToXMLFiles(poolxml, inxml, outxml, info->flags);
}


static int
mymain(void)
{
    int ret = 0;

#define DO_TEST_FULL(pool, name, flags) \
    do { \
        struct testInfo info = { pool, name, flags }; \
        if (virTestRun("Storage Vol XML-2-XML " name, \
                       testCompareXMLToXMLHelper, &info) < 0) \
            ret = -1; \
    } \
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
    DO_TEST("pool-dir", "vol-qcow2-encryption");
    DO_TEST("pool-dir", "vol-qcow2-luks");
    DO_TEST("pool-dir", "vol-qcow2-clusterSize");
    DO_TEST("pool-dir", "vol-luks");
    DO_TEST("pool-dir", "vol-luks-cipher");
    DO_TEST("pool-disk", "vol-partition");
    DO_TEST("pool-logical", "vol-logical");
    DO_TEST("pool-logical", "vol-logical-backing");
    DO_TEST("pool-gluster", "vol-gluster-dir");
    DO_TEST("pool-gluster", "vol-gluster-dir-neg-uid");
    DO_TEST_FULL("pool-dir", "vol-qcow2-nocapacity",
                 VIR_VOL_XML_PARSE_NO_CAPACITY);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
