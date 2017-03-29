#include <config.h>

#include "internal.h"
#include "testutils.h"
#include "datatypes.h"
#include "storage/storage_util.h"
#include "testutilsqemu.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NONE

const char create_tool[] = "qemu-img";

/* createVol sets this on volume creation */
static void
testSetVolumeType(virStorageVolDefPtr vol,
                  virStoragePoolDefPtr pool)
{
    if (!vol || !pool)
        return;

    switch (pool->type) {
    case VIR_STORAGE_POOL_DIR:
    case VIR_STORAGE_POOL_FS:
    case VIR_STORAGE_POOL_NETFS:
        vol->type = VIR_STORAGE_VOL_FILE;
        return;

    case VIR_STORAGE_POOL_LOGICAL:
        vol->type = VIR_STORAGE_VOL_BLOCK;
        return;
    }
}

static int
testCompareXMLToArgvFiles(bool shouldFail,
                          const char *poolxml,
                          const char *volxml,
                          const char *inputpoolxml,
                          const char *inputvolxml,
                          const char *cmdline,
                          unsigned int flags,
                          int imgformat,
                          unsigned long parse_flags)
{
    char *actualCmdline = NULL;
    int ret = -1;

    virCommandPtr cmd = NULL;
    virConnectPtr conn;

    virStorageVolDefPtr vol = NULL, inputvol = NULL;
    virStoragePoolDefPtr pool = NULL;
    virStoragePoolDefPtr inputpool = NULL;
    virStoragePoolObj poolobj = {.def = NULL };


    if (!(conn = virGetConnect()))
        goto cleanup;

    if (!(pool = virStoragePoolDefParseFile(poolxml)))
        goto cleanup;

    poolobj.def = pool;

    if (inputpoolxml) {
        if (!(inputpool = virStoragePoolDefParseFile(inputpoolxml)))
            goto cleanup;
    }

    if (inputvolxml)
        parse_flags |= VIR_VOL_XML_PARSE_NO_CAPACITY;

    if (!(vol = virStorageVolDefParseFile(pool, volxml, parse_flags)))
        goto cleanup;

    if (inputvolxml &&
        !(inputvol = virStorageVolDefParseFile(inputpool, inputvolxml, 0)))
        goto cleanup;

    testSetVolumeType(vol, pool);
    testSetVolumeType(inputvol, inputpool);

    cmd = virStorageBackendCreateQemuImgCmdFromVol(conn, &poolobj, vol,
                                                   inputvol, flags,
                                                   create_tool, imgformat,
                                                   NULL);
    if (!cmd) {
        if (shouldFail) {
            virResetLastError();
            ret = 0;
        }
        goto cleanup;
    }

    if (!(actualCmdline = virCommandToString(cmd)))
        goto cleanup;

    if (virTestCompareToFile(actualCmdline, cmdline) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virStoragePoolDefFree(pool);
    virStoragePoolDefFree(inputpool);
    virStorageVolDefFree(vol);
    virStorageVolDefFree(inputvol);
    virCommandFree(cmd);
    VIR_FREE(actualCmdline);
    virObjectUnref(conn);
    return ret;
}

struct testInfo {
    bool shouldFail;
    const char *pool;
    const char *vol;
    const char *inputpool;
    const char *inputvol;
    const char *cmdline;
    unsigned int flags;
    int imgformat;
    unsigned long parseflags;
};

static int
testCompareXMLToArgvHelper(const void *data)
{
    int result = -1;
    const struct testInfo *info = data;
    char *poolxml = NULL;
    char *inputpoolxml = NULL;
    char *volxml = NULL;
    char *inputvolxml = NULL;
    char *cmdline = NULL;

    if (info->inputvol &&
        virAsprintf(&inputvolxml, "%s/storagevolxml2xmlin/%s.xml",
                    abs_srcdir, info->inputvol) < 0)
        goto cleanup;
    if (info->inputpool &&
        virAsprintf(&inputpoolxml, "%s/storagepoolxml2xmlin/%s.xml",
                    abs_srcdir, info->inputpool) < 0)
        goto cleanup;
    if (virAsprintf(&poolxml, "%s/storagepoolxml2xmlin/%s.xml",
                    abs_srcdir, info->pool) < 0 ||
        virAsprintf(&volxml, "%s/storagevolxml2xmlin/%s.xml",
                    abs_srcdir, info->vol) < 0) {
        goto cleanup;
    }
    if (virAsprintf(&cmdline, "%s/storagevolxml2argvdata/%s.argv",
                    abs_srcdir, info->cmdline) < 0 && !info->shouldFail)
        goto cleanup;

    result = testCompareXMLToArgvFiles(info->shouldFail, poolxml, volxml,
                                       inputpoolxml, inputvolxml,
                                       cmdline, info->flags,
                                       info->imgformat, info->parseflags);

 cleanup:
    VIR_FREE(poolxml);
    VIR_FREE(volxml);
    VIR_FREE(inputvolxml);
    VIR_FREE(inputpoolxml);
    VIR_FREE(cmdline);

    return result;
}

enum {
    FMT_OPTIONS = 0,
    FMT_COMPAT,
};



static int
mymain(void)
{
    int ret = 0;
    unsigned int flags = VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA;

#define DO_TEST_FULL(shouldFail, parseflags, pool, vol, inputpool, inputvol, \
                     cmdline, flags, imgformat)                              \
    do {                                                                     \
        struct testInfo info = { shouldFail, pool, vol, inputpool, inputvol, \
                                 cmdline, flags, imgformat, parseflags };    \
        if (virTestRun("Storage Vol XML-2-argv " cmdline,                    \
                       testCompareXMLToArgvHelper, &info) < 0)               \
            ret = -1;                                                        \
       }                                                                     \
    while (0);

#define DO_TEST(pool, ...)                                                 \
    DO_TEST_FULL(false, 0, pool, __VA_ARGS__)

#define DO_TEST_FAIL(pool, ...)                                            \
    DO_TEST_FULL(true, 0, pool, __VA_ARGS__)

    DO_TEST("pool-dir", "vol-qcow2",
            NULL, NULL,
            "qcow2", 0, FMT_OPTIONS);
    DO_TEST_FAIL("pool-dir", "vol-qcow2",
                 NULL, NULL,
                 "qcow2-prealloc", flags, FMT_OPTIONS);
    DO_TEST("pool-dir", "vol-qcow2-nobacking",
            NULL, NULL,
            "qcow2-nobacking-prealloc", flags, FMT_OPTIONS);
    DO_TEST("pool-dir", "vol-qcow2-nobacking",
            "pool-dir", "vol-file",
            "qcow2-nobacking-convert-prealloc", flags, FMT_OPTIONS);
    DO_TEST_FAIL("pool-dir", "vol-qcow2",
                 "pool-dir", "vol-file",
                 "qcow2-convert-nobacking", 0, FMT_OPTIONS);
    DO_TEST_FAIL("pool-dir", "vol-qcow2",
                 "pool-dir", "vol-file",
                 "qcow2-convert-prealloc", flags, FMT_OPTIONS);
    DO_TEST("pool-dir", "vol-qcow2-lazy",
            NULL, NULL,
            "qcow2-lazy", 0, FMT_OPTIONS);
    DO_TEST("pool-dir", "vol-qcow2-1.1",
            NULL, NULL,
            "qcow2-1.1", 0, FMT_OPTIONS);
    DO_TEST_FAIL("pool-dir", "vol-qcow2-0.10-lazy",
                 NULL, NULL,
                 "qcow2-0.10-lazy", 0, FMT_OPTIONS);
    DO_TEST("pool-dir", "vol-qcow2-nobacking",
            "pool-logical", "vol-logical",
            "qcow2-from-logical", 0, FMT_OPTIONS);
    DO_TEST("pool-logical", "vol-logical",
            "pool-dir", "vol-qcow2-nobacking",
            "logical-from-qcow2", 0, FMT_OPTIONS);

    DO_TEST("pool-dir", "vol-qcow2",
            NULL, NULL,
            "qcow2-compat", 0, FMT_COMPAT);
    DO_TEST("pool-dir", "vol-qcow2-nobacking",
            NULL, NULL,
            "qcow2-nobacking-prealloc-compat", flags, FMT_COMPAT);
    DO_TEST("pool-dir", "vol-qcow2-nobacking",
            "pool-dir", "vol-file",
            "qcow2-nobacking-convert-prealloc-compat", flags, FMT_COMPAT);
    DO_TEST("pool-dir", "vol-qcow2-lazy",
            NULL, NULL,
            "qcow2-lazy", 0, FMT_COMPAT);
    DO_TEST("pool-dir", "vol-qcow2-1.1",
            NULL, NULL,
            "qcow2-1.1", 0, FMT_COMPAT);
    DO_TEST_FAIL("pool-dir", "vol-qcow2-0.10-lazy",
                 NULL, NULL,
                 "qcow2-0.10-lazy", 0, FMT_COMPAT);
    DO_TEST("pool-dir", "vol-qcow2-nobacking",
            "pool-logical", "vol-logical",
            "qcow2-from-logical-compat", 0, FMT_COMPAT);
    DO_TEST("pool-logical", "vol-logical",
            "pool-dir", "vol-qcow2-nobacking",
            "logical-from-qcow2", 0, FMT_COMPAT);
    DO_TEST("pool-dir", "vol-qcow2-nocow",
            NULL, NULL,
            "qcow2-nocow", 0, FMT_OPTIONS);
    DO_TEST("pool-dir", "vol-qcow2-nocow",
            NULL, NULL,
            "qcow2-nocow-compat", 0, FMT_COMPAT);
    DO_TEST("pool-dir", "vol-qcow2-nocapacity",
            "pool-dir", "vol-file",
            "qcow2-nocapacity-convert-prealloc", flags, FMT_OPTIONS);
    DO_TEST("pool-dir", "vol-qcow2-zerocapacity",
            NULL, NULL,
            "qcow2-zerocapacity", 0, FMT_COMPAT);
    DO_TEST_FULL(false, VIR_VOL_XML_PARSE_OPT_CAPACITY,
                 "pool-dir", "vol-qcow2-nocapacity-backing", NULL, NULL,
                 "qcow2-nocapacity", 0, FMT_OPTIONS);

    DO_TEST("pool-dir", "vol-file-iso",
            NULL, NULL,
            "iso", 0, FMT_OPTIONS);
    DO_TEST("pool-dir", "vol-file",
            "pool-dir", "vol-file-iso",
            "iso-input", 0, FMT_OPTIONS);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
