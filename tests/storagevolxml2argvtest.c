#include <config.h>

#include "internal.h"
#include "testutils.h"
#include "datatypes.h"
#include "storage/storage_backend.h"
#include "testutilsqemu.h"
#include "virstring.h"

const char create_tool[] = "qemu-img";

static int
testCompareXMLToArgvFiles(bool shouldFail,
                          const char *poolxml,
                          const char *volxml,
                          const char *inputvolxml,
                          const char *cmdline,
                          unsigned int flags,
                          int imgformat)
{
    char *volXmlData = NULL;
    char *poolXmlData = NULL;
    char *inputvolXmlData = NULL;
    char *expectedCmdline = NULL;
    char *actualCmdline = NULL;
    int ret = -1;

    int len;

    virCommandPtr cmd = NULL;
    virConnectPtr conn;

    virStorageVolDefPtr vol = NULL, inputvol = NULL;
    virStoragePoolDefPtr pool = NULL;
    virStoragePoolObj poolobj = {.def = NULL };


    if (!(conn = virGetConnect()))
        goto cleanup;

    if (virtTestLoadFile(poolxml, &poolXmlData) < 0)
        goto cleanup;
    if (virtTestLoadFile(volxml, &volXmlData) < 0)
        goto cleanup;
    if (inputvolxml &&
        virtTestLoadFile(inputvolxml, &inputvolXmlData) < 0)
        goto cleanup;

    if (!(pool = virStoragePoolDefParseString(poolXmlData)))
        goto cleanup;

    poolobj.def = pool;

    if (!(vol = virStorageVolDefParseString(pool, volXmlData)))
        goto cleanup;

    if (inputvolxml &&
        !(inputvol = virStorageVolDefParseString(pool, inputvolXmlData)))
        goto cleanup;

    cmd = virStorageBackendCreateQemuImgCmd(conn, &poolobj, vol, inputvol,
                                            flags, create_tool, imgformat);
    if (!cmd) {
        if (shouldFail) {
            virResetLastError();
            ret = 0;
        }
        goto cleanup;
    }

    if (!(actualCmdline = virCommandToString(cmd)))
        goto cleanup;

    len = virtTestLoadFile(cmdline, &expectedCmdline);
    if (len < 0)
        goto cleanup;
    if (len && expectedCmdline[len-1] == '\n')
        expectedCmdline[len-1] = '\0';

    if (STRNEQ_NULLABLE(expectedCmdline, actualCmdline)) {
        virtTestDifference(stderr, expectedCmdline, actualCmdline);
        goto cleanup;
    }

    ret = 0;

cleanup:
    virStoragePoolDefFree(pool);
    virStorageVolDefFree(vol);
    virStorageVolDefFree(inputvol);
    virCommandFree(cmd);
    VIR_FREE(actualCmdline);
    VIR_FREE(expectedCmdline);
    VIR_FREE(poolXmlData);
    VIR_FREE(volXmlData);
    VIR_FREE(inputvolXmlData);
    virObjectUnref(conn);
    return ret;
}

struct testInfo {
    bool shouldFail;
    const char *pool;
    const char *vol;
    const char *inputvol;
    const char *cmdline;
    unsigned int flags;
    int imgformat;
};

static int
testCompareXMLToArgvHelper(const void *data)
{
    int result = -1;
    const struct testInfo *info = data;
    char *poolxml = NULL;
    char *volxml = NULL;
    char *inputvolxml = NULL;
    char *cmdline = NULL;

    if (info->inputvol &&
        virAsprintf(&inputvolxml, "%s/storagevolxml2argvdata/%s.xml",
                    abs_srcdir, info->inputvol) < 0)
        goto cleanup;
    if (virAsprintf(&poolxml, "%s/storagevolxml2argvdata/%s.xml",
                    abs_srcdir, info->pool) < 0 ||
        virAsprintf(&volxml, "%s/storagevolxml2argvdata/%s.xml",
                    abs_srcdir, info->vol) < 0) {
        goto cleanup;
    }
    if (virAsprintf(&cmdline, "%s/storagevolxml2argvdata/%s.argv",
                    abs_srcdir, info->cmdline) < 0 && !info->shouldFail)
        goto cleanup;

    result = testCompareXMLToArgvFiles(info->shouldFail, poolxml, volxml,
                                       inputvolxml, cmdline, info->flags,
                                       info->imgformat);

cleanup:
    VIR_FREE(poolxml);
    VIR_FREE(volxml);
    VIR_FREE(inputvolxml);
    VIR_FREE(cmdline);

    return result;
}

enum {
    FMT_NONE = 0,
    FMT_FLAG,
    FMT_OPTIONS,
};



static int
mymain(void)
{
    int ret = 0;
    unsigned int flags = VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA;

#define DO_TEST(shouldFail, pool, vol, inputvol, cmdline, flags, imgformat) \
    do {                    \
        struct testInfo info = { shouldFail, pool, vol, inputvol, cmdline, \
                                 flags, imgformat }; \
        if (virtTestRun("Storage Vol XML-2-argv " cmdline, \
                        1, testCompareXMLToArgvHelper, &info) < 0) \
            ret = -1;   \
       }    \
    while (0);

    DO_TEST(false, "pool-dir", "vol-qcow2", NULL, "qcow2", 0, FMT_OPTIONS);
    DO_TEST(true, "pool-dir", "vol-qcow2", NULL, "qcow2-prealloc", flags,
            FMT_OPTIONS);
    DO_TEST(false, "pool-dir", "vol-qcow2-nobacking", NULL,
            "qcow2-nobacking-prealloc", flags, FMT_OPTIONS);
    DO_TEST(false, "pool-dir", "vol-qcow2-nobacking", "vol-file",
            "qcow2-nobacking-convert-prealloc", flags, FMT_OPTIONS);
    DO_TEST(true, "pool-dir", "vol-qcow2", "vol-file",
            "qcow2-convert-prealloc", flags, FMT_OPTIONS);
    DO_TEST(false, "pool-dir", "vol-qcow2", NULL, "qcow2-flag", 0, FMT_FLAG);
    DO_TEST(false, "pool-dir", "vol-qcow2-nobacking", NULL,
            "qcow2-nobacking-flag", 0, FMT_FLAG);
    DO_TEST(false, "pool-dir", "vol-qcow2-nobacking", "vol-file",
            "qcow2-nobacking-convert-flag", 0, FMT_FLAG);
    DO_TEST(false, "pool-dir", "vol-qcow2", NULL, "qcow2-none", 0, FMT_NONE);
    DO_TEST(false, "pool-dir", "vol-qcow2-nobacking", NULL,
            "qcow2-nobacking-none", 0, FMT_NONE);
    DO_TEST(false, "pool-dir", "vol-qcow2-nobacking", "vol-file",
            "qcow2-nobacking-convert-none", 0, FMT_NONE);
    DO_TEST(false, "pool-dir", "vol-qcow2-lazy", NULL, "qcow2-lazy", 0,
            FMT_OPTIONS);
    DO_TEST(false, "pool-dir", "vol-qcow2-1.1", NULL, "qcow2-1.1", 0,
            FMT_OPTIONS);
    DO_TEST(true, "pool-dir", "vol-qcow2-0.10-lazy", NULL, "qcow2-0.10-lazy", 0,
            FMT_OPTIONS);

    return ret==0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)
