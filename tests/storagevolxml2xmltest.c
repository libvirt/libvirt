#include <config.h>

#include <unistd.h>

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
    VIR_AUTOFREE(char *) actual = NULL;
    VIR_AUTOPTR(virStoragePoolDef) pool = NULL;
    VIR_AUTOPTR(virStorageVolDef) dev = NULL;

    if (!(pool = virStoragePoolDefParseFile(poolxml)))
        return -1;

    if (!(dev = virStorageVolDefParseFile(pool, inxml, flags)))
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
    VIR_AUTOFREE(char *) poolxml = NULL;
    VIR_AUTOFREE(char *) inxml = NULL;
    VIR_AUTOFREE(char *) outxml = NULL;

    if (virAsprintf(&poolxml, "%s/storagepoolxml2xmlin/%s.xml",
                    abs_srcdir, info->pool) < 0 ||
        virAsprintf(&inxml, "%s/storagevolxml2xmlin/%s.xml",
                    abs_srcdir, info->name) < 0 ||
        virAsprintf(&outxml, "%s/storagevolxml2xmlout/%s.xml",
                    abs_srcdir, info->name) < 0)
        return -1;

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
