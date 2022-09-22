#include <config.h>

#include "internal.h"
#include "testutils.h"
#include "storage/storage_util.h"

#define VIR_FROM_THIS VIR_FROM_NONE

#ifndef MOUNT
# define MOUNT "/usr/bin/mount"
#endif

#ifndef VGCHANGE
# define VGCHANGE "/usr/sbin/vgchange"
#endif

static int
testCompareXMLToArgvFiles(bool shouldFail,
                          const char *poolxml,
                          const char *cmdline)
{
    int ret = -1;
    virStoragePoolDef *def = NULL;
    virStoragePoolObj *pool = NULL;
    const char *defTypeStr;
    g_autofree char *actualCmdline = NULL;
    g_autofree char *src = NULL;
    g_autoptr(virCommand) cmd = NULL;

    if (!(def = virStoragePoolDefParse(NULL, poolxml, 0)))
        goto cleanup;
    defTypeStr = virStoragePoolTypeToString(def->type);

    switch ((virStoragePoolType)def->type) {
    case VIR_STORAGE_POOL_FS:
    case VIR_STORAGE_POOL_NETFS:
        if (!(pool = virStoragePoolObjNew())) {
            VIR_TEST_DEBUG("pool type '%s' alloc pool obj fails", defTypeStr);
            goto cleanup;
        }
        virStoragePoolObjSetDef(pool, def);

        if (!(src = virStorageBackendFileSystemGetPoolSource(pool))) {
            VIR_TEST_DEBUG("pool type '%s' has no pool source", defTypeStr);
            def = NULL;
            goto cleanup;
        }

        cmd = virStorageBackendFileSystemMountCmd(MOUNT, def, src);
        def = NULL;
        break;

    case VIR_STORAGE_POOL_LOGICAL:
        cmd = virStorageBackendLogicalChangeCmd(VGCHANGE, def, true);
        break;

    case VIR_STORAGE_POOL_DIR:
    case VIR_STORAGE_POOL_DISK:
    case VIR_STORAGE_POOL_ISCSI:
    case VIR_STORAGE_POOL_ISCSI_DIRECT:
    case VIR_STORAGE_POOL_SCSI:
    case VIR_STORAGE_POOL_MPATH:
    case VIR_STORAGE_POOL_RBD:
    case VIR_STORAGE_POOL_SHEEPDOG:
    case VIR_STORAGE_POOL_GLUSTER:
    case VIR_STORAGE_POOL_ZFS:
    case VIR_STORAGE_POOL_VSTORAGE:
    case VIR_STORAGE_POOL_LAST:
    default:
        VIR_TEST_DEBUG("pool type '%s' has no xml2argv test", defTypeStr);
        goto cleanup;
    };

    if (!(actualCmdline = virCommandToStringFull(cmd, true, true))) {
        VIR_TEST_DEBUG("pool type '%s' failed to get commandline", defTypeStr);
        goto cleanup;
    }

    if (virTestCompareToFileFull(actualCmdline, cmdline, false) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virStoragePoolDefFree(def);
    virStoragePoolObjEndAPI(&pool);
    if (shouldFail) {
        virResetLastError();
        ret = 0;
    }
    return ret;
}

struct testInfo {
    bool shouldFail;
    const char *pool;
    const char *platformSuffix;
};

static int
testCompareXMLToArgvHelper(const void *data)
{
    const struct testInfo *info = data;
    g_autofree char *poolxml = NULL;
    g_autofree char *cmdline = NULL;

    poolxml = g_strdup_printf("%s/storagepoolxml2xmlin/%s.xml", abs_srcdir,
                              info->pool);

    cmdline = g_strdup_printf("%s/storagepoolxml2argvdata/%s%s.argv",
                              abs_srcdir, info->pool, info->platformSuffix);

    return testCompareXMLToArgvFiles(info->shouldFail, poolxml, cmdline);
}


static int
mymain(void)
{
    int ret = 0;
#ifdef __linux__
    const char *platform = "-linux";
#elif defined(__FreeBSD__)
    const char *platform = "-freebsd";
#else
    const char *platform = "";
#endif

#define DO_TEST_FULL(shouldFail, pool, platformSuffix) \
    do { \
        struct testInfo info = { shouldFail, pool, platformSuffix }; \
        if (virTestRun("Storage Pool XML-2-argv " pool, \
                       testCompareXMLToArgvHelper, &info) < 0) \
            ret = -1; \
       } \
    while (0);

#define DO_TEST(pool, ...) \
    DO_TEST_FULL(false, pool, "")

#define DO_TEST_FAIL(pool, ...) \
    DO_TEST_FULL(true, pool, "")

#define DO_TEST_PLATFORM(pool, ...) \
    DO_TEST_FULL(false, pool, platform)

    if (storageRegisterAll() < 0)
       return EXIT_FAILURE;

    DO_TEST_FAIL("pool-dir");
    DO_TEST_FAIL("pool-dir-naming");
    DO_TEST("pool-logical");
    DO_TEST("pool-logical-nopath");
    DO_TEST("pool-logical-create");
    DO_TEST("pool-logical-noname");
    DO_TEST_FAIL("pool-disk");
    DO_TEST_FAIL("pool-disk-device-nopartsep");
    DO_TEST_FAIL("pool-iscsi");
    DO_TEST_FAIL("pool-iscsi-auth");

    DO_TEST_PLATFORM("pool-fs");
    DO_TEST_PLATFORM("pool-netfs");
    DO_TEST_PLATFORM("pool-netfs-auto");
    DO_TEST_PLATFORM("pool-netfs-protocol-ver");
#if WITH_STORAGE_FS
    DO_TEST_PLATFORM("pool-netfs-ns-mountopts");
#endif
    DO_TEST_PLATFORM("pool-netfs-gluster");
    DO_TEST_PLATFORM("pool-netfs-cifs");

    DO_TEST_FAIL("pool-scsi");
    DO_TEST_FAIL("pool-scsi-type-scsi-host");
    DO_TEST_FAIL("pool-scsi-type-fc-host");
    DO_TEST_FAIL("pool-scsi-type-fc-host-managed");
    DO_TEST_FAIL("pool-mpath");
    DO_TEST_FAIL("pool-iscsi-multiiqn");
    DO_TEST_FAIL("pool-iscsi-vendor-product");
    DO_TEST_FAIL("pool-gluster");
    DO_TEST_FAIL("pool-gluster-sub");
    DO_TEST_FAIL("pool-scsi-type-scsi-host-stable");
    DO_TEST_FAIL("pool-zfs");
    DO_TEST_FAIL("pool-zfs-sourcedev");
    DO_TEST_FAIL("pool-rbd");
    DO_TEST_FAIL("pool-vstorage");
    DO_TEST_FAIL("pool-iscsi-direct-auth");
    DO_TEST_FAIL("pool-iscsi-direct");

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
