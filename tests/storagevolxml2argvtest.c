#include <config.h>

#include "internal.h"
#include "testutils.h"
#include "storage/storage_util.h"

#define VIR_FROM_THIS VIR_FROM_NONE

const char create_tool[] = "qemu-img";

/* createVol sets this on volume creation */
static void
testSetVolumeType(virStorageVolDef *vol,
                  virStoragePoolDef *pool)
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
                          unsigned long parse_flags)
{
    virStorageVolEncryptConvertStep convertStep = VIR_STORAGE_VOL_ENCRYPT_NONE;
    int ret = -1;
    virStoragePoolDef *def = NULL;
    virStoragePoolObj *obj = NULL;
    g_autofree char *actualCmdline = NULL;
    g_autoptr(virStorageVolDef) vol = NULL;
    g_autoptr(virStorageVolDef) inputvol = NULL;
    g_autoptr(virStoragePoolDef) inputpool = NULL;

    if (!(def = virStoragePoolDefParse(NULL, poolxml, 0)))
        goto cleanup;

    if (!(obj = virStoragePoolObjNew())) {
        virStoragePoolDefFree(def);
        goto cleanup;
    }
    virStoragePoolObjSetDef(obj, def);

    if (inputpoolxml) {
        if (!(inputpool = virStoragePoolDefParse(NULL, inputpoolxml, 0)))
            goto cleanup;
    }

    if (inputvolxml)
        parse_flags |= VIR_VOL_XML_PARSE_NO_CAPACITY;

    if (!(vol = virStorageVolDefParse(def, NULL, volxml, parse_flags)))
        goto cleanup;

    if (inputvolxml &&
        !(inputvol = virStorageVolDefParse(inputpool, NULL, inputvolxml, 0)))
        goto cleanup;

    testSetVolumeType(vol, def);
    testSetVolumeType(inputvol, inputpool);

    /* Using an input file for encryption requires a multi-step process
     * to create an image of the same size as the inputvol and then to
     * convert the inputvol afterwards. Since we only care about the
     * command line we have to copy code from storageBackendCreateQemuImg
     * and adjust it for the test needs. */
    if (inputvol && (vol->target.encryption || inputvol->target.encryption))
        convertStep = VIR_STORAGE_VOL_ENCRYPT_CREATE;

    do {
        g_autoptr(virCommand) cmd = NULL;

        cmd = virStorageBackendCreateQemuImgCmdFromVol(obj, vol,
                                                       inputvol, flags,
                                                       create_tool,
                                                       "/path/to/secretFile",
                                                       "/path/to/inputSecretFile",
                                                       convertStep);
        if (!cmd) {
            if (shouldFail) {
                virResetLastError();
                ret = 0;
            }
            goto cleanup;
        }

        if (convertStep != VIR_STORAGE_VOL_ENCRYPT_CONVERT) {
            if (!(actualCmdline = virCommandToString(cmd, true)))
                goto cleanup;
        } else {
            char *createCmdline = actualCmdline;
            g_autofree char *cvtCmdline = NULL;

            if (!(cvtCmdline = virCommandToString(cmd, true)))
                goto cleanup;

            actualCmdline = g_strdup_printf("%s\n%s", createCmdline, cvtCmdline);

            VIR_FREE(createCmdline);
        }

        if (convertStep == VIR_STORAGE_VOL_ENCRYPT_NONE)
            convertStep = VIR_STORAGE_VOL_ENCRYPT_DONE;
        else if (convertStep == VIR_STORAGE_VOL_ENCRYPT_CREATE)
            convertStep = VIR_STORAGE_VOL_ENCRYPT_CONVERT;
        else if (convertStep == VIR_STORAGE_VOL_ENCRYPT_CONVERT)
            convertStep = VIR_STORAGE_VOL_ENCRYPT_DONE;

    } while (convertStep != VIR_STORAGE_VOL_ENCRYPT_DONE);

    if (virTestCompareToFileFull(actualCmdline, cmdline, false) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virStoragePoolObjEndAPI(&obj);
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
    unsigned long parseflags;
};

static int
testCompareXMLToArgvHelper(const void *data)
{
    const struct testInfo *info = data;
    g_autofree char *poolxml = NULL;
    g_autofree char *inputpoolxml = NULL;
    g_autofree char *volxml = NULL;
    g_autofree char *inputvolxml = NULL;
    g_autofree char *cmdline = NULL;

    if (info->inputvol)
        inputvolxml = g_strdup_printf("%s/storagevolxml2xmlin/%s.xml",
                                      abs_srcdir, info->inputvol);
    if (info->inputpool)
        inputpoolxml = g_strdup_printf("%s/storagepoolxml2xmlin/%s.xml",
                                       abs_srcdir, info->inputpool);
    poolxml = g_strdup_printf("%s/storagepoolxml2xmlin/%s.xml",
                              abs_srcdir, info->pool);
    volxml = g_strdup_printf("%s/storagevolxml2xmlin/%s.xml",
                             abs_srcdir, info->vol);
    cmdline = g_strdup_printf("%s/storagevolxml2argvdata/%s.argv",
                              abs_srcdir, info->cmdline);

    return testCompareXMLToArgvFiles(info->shouldFail, poolxml, volxml,
                                     inputpoolxml, inputvolxml,
                                     cmdline, info->flags,
                                     info->parseflags);
}


static int
mymain(void)
{
    int ret = 0;
    unsigned int flags = VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA;

#define DO_TEST_FULL(shouldFail, parseflags, pool, vol, inputpool, inputvol, \
                     cmdline, flags) \
    do { \
        struct testInfo info = { shouldFail, pool, vol, inputpool, inputvol, \
                                 cmdline, flags, parseflags }; \
        if (virTestRun("Storage Vol XML-2-argv " cmdline, \
                       testCompareXMLToArgvHelper, &info) < 0) \
            ret = -1; \
       } \
    while (0);

#define DO_TEST(pool, ...) \
    DO_TEST_FULL(false, 0, pool, __VA_ARGS__)

#define DO_TEST_FAIL(pool, ...) \
    DO_TEST_FULL(true, 0, pool, __VA_ARGS__)

    DO_TEST("pool-dir", "vol-qcow2",
            NULL, NULL,
            "qcow2-compat", 0);
    DO_TEST("pool-dir", "vol-qcow2-nobacking",
            NULL, NULL,
            "qcow2-nobacking-prealloc-compat", flags);
    DO_TEST("pool-dir", "vol-qcow2-nobacking",
            "pool-dir", "vol-file",
            "qcow2-nobacking-convert-prealloc-compat", flags);
    DO_TEST("pool-dir", "vol-qcow2-lazy",
            NULL, NULL,
            "qcow2-lazy", 0);
    DO_TEST("pool-dir", "vol-qcow2-1.1",
            NULL, NULL,
            "qcow2-1.1", 0);
    DO_TEST_FAIL("pool-dir", "vol-qcow2-0.10-lazy",
                 NULL, NULL,
                 "qcow2-0.10-lazy", 0);
    DO_TEST("pool-dir", "vol-qcow2-nobacking",
            "pool-logical", "vol-logical",
            "qcow2-from-logical-compat", 0);
    DO_TEST("pool-logical", "vol-logical",
            "pool-dir", "vol-qcow2-nobacking",
            "logical-from-qcow2", 0);
    DO_TEST("pool-dir", "vol-qcow2-nocow",
            NULL, NULL,
            "qcow2-nocow-compat", 0);
    DO_TEST("pool-dir", "vol-qcow2-nocapacity",
            "pool-dir", "vol-file",
            "qcow2-nocapacity-convert-prealloc", flags);
    DO_TEST("pool-dir", "vol-qcow2-zerocapacity",
            NULL, NULL,
            "qcow2-zerocapacity", 0);
    DO_TEST_FULL(false, VIR_VOL_XML_PARSE_OPT_CAPACITY,
                 "pool-dir", "vol-qcow2-nocapacity-backing", NULL, NULL,
                 "qcow2-nocapacity", 0);

    DO_TEST("pool-dir", "vol-qcow2-clusterSize",
            NULL, NULL,
            "qcow2-clusterSize", 0);

    DO_TEST("pool-dir", "vol-file-iso",
            NULL, NULL,
            "iso", 0);
    DO_TEST("pool-dir", "vol-file",
            "pool-dir", "vol-file-iso",
            "iso-input", 0);

    DO_TEST_FAIL("pool-dir", "vol-qcow2-encryption",
                 NULL, NULL,
                 "qcow2-encryption", 0);

    DO_TEST("pool-dir", "vol-luks",
            NULL, NULL,
            "luks", 0);
    DO_TEST("pool-dir", "vol-luks-cipher",
            NULL, NULL,
            "luks-cipher", 0);
    DO_TEST("pool-dir", "vol-qcow2-luks",
            NULL, NULL,
            "qcow2-luks", 0);

    DO_TEST("pool-dir", "vol-luks-convert",
            "pool-dir", "vol-file",
            "luks-convert", 0);

    DO_TEST("pool-dir", "vol-luks-convert",
            "pool-dir", "vol-file-qcow2",
            "luks-convert-qcow2", 0);

    DO_TEST("pool-dir", "vol-luks",
            "pool-dir", "vol-luks-convert",
            "luks-convert-encrypt", 0);

    DO_TEST("pool-dir", "vol-file",
            "pool-dir", "vol-luks-convert",
            "luks-convert-encrypt2fileraw", 0);

    DO_TEST("pool-dir", "vol-file-qcow2",
            "pool-dir", "vol-luks-convert",
            "luks-convert-encrypt2fileqcow2", 0);

    DO_TEST("pool-dir", "vol-qcow2-luks",
            "pool-dir", "vol-qcow2-luks-convert",
            "qcow2-luks-convert-encrypt", 0);

    DO_TEST("pool-dir", "vol-file",
            "pool-dir", "vol-qcow2-luks-convert",
            "qcow2-luks-convert-encrypt2fileraw", 0);

    DO_TEST("pool-dir", "vol-file-qcow2",
            "pool-dir", "vol-qcow2-luks-convert",
            "qcow2-luks-convert-encrypt2fileqcow2", 0);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
