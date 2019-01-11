#include <config.h>

#include "internal.h"
#include "testutils.h"
#include "datatypes.h"
#include "storage/storage_util.h"
#include "testutilsqemu.h"
#include "virstring.h"

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
    VIR_AUTOFREE(char *) actualCmdline = NULL;
    VIR_AUTOFREE(char *) src = NULL;
    int ret = -1;
    virCommandPtr cmd = NULL;
    virStoragePoolDefPtr def = NULL;
    virStoragePoolObjPtr pool = NULL;

    if (!(def = virStoragePoolDefParseFile(poolxml)))
        goto cleanup;

    switch ((virStoragePoolType)def->type) {
    case VIR_STORAGE_POOL_FS:
    case VIR_STORAGE_POOL_NETFS:
        if (!(pool = virStoragePoolObjNew())) {
            VIR_TEST_DEBUG("pool type %d alloc pool obj fails\n", def->type);
            virStoragePoolDefFree(def);
            goto cleanup;
        }
        virStoragePoolObjSetDef(pool, def);

        if (!(src = virStorageBackendFileSystemGetPoolSource(pool))) {
            VIR_TEST_DEBUG("pool type %d has no pool source\n", def->type);
            goto cleanup;
        }

        cmd = virStorageBackendFileSystemMountCmd(MOUNT, def, src);
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
        VIR_TEST_DEBUG("pool type %d has no xml2argv test\n", def->type);
        goto cleanup;
    };

    if (!(actualCmdline = virCommandToString(cmd, false))) {
        VIR_TEST_DEBUG("pool type %d failed to get commandline\n", def->type);
        goto cleanup;
    }

    virTestClearCommandPath(actualCmdline);
    if (virTestCompareToFile(actualCmdline, cmdline) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virCommandFree(cmd);
    VIR_FREE(actualCmdline);
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
    bool linuxOut;
    bool freebsdOut;
};

static int
testCompareXMLToArgvHelper(const void *data)
{
    int result = -1;
    const struct testInfo *info = data;
    char *poolxml = NULL;
    char *cmdline = NULL;

    if (virAsprintf(&poolxml, "%s/storagepoolxml2xmlin/%s.xml",
                    abs_srcdir, info->pool) < 0)
        goto cleanup;

    if (info->linuxOut) {
        if (virAsprintf(&cmdline, "%s/storagepoolxml2argvdata/%s-linux.argv",
                        abs_srcdir, info->pool) < 0 && !info->shouldFail)
            goto cleanup;
    } else if (info->freebsdOut) {
        if (virAsprintf(&cmdline, "%s/storagepoolxml2argvdata/%s-freebsd.argv",
                        abs_srcdir, info->pool) < 0 && !info->shouldFail)
            goto cleanup;
    } else {
        if (virAsprintf(&cmdline, "%s/storagepoolxml2argvdata/%s.argv",
                        abs_srcdir, info->pool) < 0 && !info->shouldFail)
            goto cleanup;
    }

    result = testCompareXMLToArgvFiles(info->shouldFail, poolxml, cmdline);

 cleanup:
    VIR_FREE(poolxml);
    VIR_FREE(cmdline);

    return result;
}


static int
mymain(void)
{
    int ret = 0;

#define DO_TEST_FULL(shouldFail, pool, linuxOut, freebsdOut) \
    do { \
        struct testInfo info = { shouldFail, pool, linuxOut, freebsdOut }; \
        if (virTestRun("Storage Pool XML-2-argv " pool, \
                       testCompareXMLToArgvHelper, &info) < 0) \
            ret = -1; \
       } \
    while (0);

#define DO_TEST(pool, ...) \
    DO_TEST_FULL(false, pool, false, false)

#define DO_TEST_FAIL(pool, ...) \
    DO_TEST_FULL(true, pool, false, false)

#define DO_TEST_LINUX(pool, ...) \
    DO_TEST_FULL(false, pool, true, false)

#define DO_TEST_FREEBSD(pool, ...) \
    DO_TEST_FULL(false, pool, false, true)

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
#ifdef __linux__
    DO_TEST_LINUX("pool-fs");
    DO_TEST_LINUX("pool-netfs");
    DO_TEST_LINUX("pool-netfs-auto");
    DO_TEST_LINUX("pool-netfs-gluster");
    DO_TEST_LINUX("pool-netfs-cifs");
#elif defined(__FreeBSD__)
    DO_TEST_FREEBSD("pool-fs");
    DO_TEST_FREEBSD("pool-netfs");
    DO_TEST_FREEBSD("pool-netfs-auto");
    DO_TEST_FREEBSD("pool-netfs-gluster");
    DO_TEST_FREEBSD("pool-netfs-cifs");
#else
    DO_TEST("pool-fs");
    DO_TEST("pool-netfs");
    DO_TEST("pool-netfs-auto");
    DO_TEST("pool-netfs-gluster");
    DO_TEST("pool-netfs-cifs");
#endif
    DO_TEST_FAIL("pool-scsi");
    DO_TEST_FAIL("pool-scsi-type-scsi-host");
    DO_TEST_FAIL("pool-scsi-type-fc-host");
    DO_TEST_FAIL("pool-scsi-type-fc-host-managed");
    DO_TEST_FAIL("pool-mpath");
    DO_TEST_FAIL("pool-iscsi-multiiqn");
    DO_TEST_FAIL("pool-iscsi-vendor-product");
    DO_TEST_FAIL("pool-sheepdog");
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
