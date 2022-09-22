#include <config.h>

#include <unistd.h>

#include <sys/types.h>
#include <fcntl.h>

#include "internal.h"
#include "testutils.h"
#include "storage_conf.h"

#include "storage/storage_util.h"

#define VIR_FROM_THIS VIR_FROM_NONE

static int
testCompareXMLToXMLFiles(const char *inxml, const char *outxml)
{
    g_autofree char *actual = NULL;
    g_autoptr(virStoragePoolDef) dev = NULL;

    if (!(dev = virStoragePoolDefParse(NULL, inxml, 0)))
        return -1;

    if (!(actual = virStoragePoolDefFormat(dev)))
        return -1;

    if (virTestCompareToFile(actual, outxml) < 0)
        return -1;

    return 0;
}

static int
testCompareXMLToXMLHelper(const void *data)
{
    g_autofree char *inxml = NULL;
    g_autofree char *outxml = NULL;

    inxml = g_strdup_printf("%s/storagepoolxml2xmlin/%s.xml",
                            abs_srcdir, (const char*)data);
    outxml = g_strdup_printf("%s/storagepoolxml2xmlout/%s.xml",
                             abs_srcdir, (const char*)data);

    return testCompareXMLToXMLFiles(inxml, outxml);
}

static int
mymain(void)
{
    int ret = 0;

#define DO_TEST(name) \
    if (virTestRun("Storage Pool XML-2-XML " name, \
                   testCompareXMLToXMLHelper, (name)) < 0) \
        ret = -1

    if (storageRegisterAll() < 0)
       return EXIT_FAILURE;

    DO_TEST("pool-dir");
    DO_TEST("pool-dir-naming");
    DO_TEST("pool-dir-cow");
    DO_TEST("pool-fs");
    DO_TEST("pool-logical");
    DO_TEST("pool-logical-nopath");
    DO_TEST("pool-logical-create");
    DO_TEST("pool-logical-noname");
    DO_TEST("pool-disk");
    DO_TEST("pool-disk-device-nopartsep");
    DO_TEST("pool-iscsi");
    DO_TEST("pool-iscsi-auth");
    DO_TEST("pool-netfs");
    DO_TEST("pool-netfs-slash");
    DO_TEST("pool-netfs-auto");
    DO_TEST("pool-netfs-protocol-ver");
    DO_TEST("pool-netfs-gluster");
    DO_TEST("pool-netfs-cifs");
#ifdef WITH_STORAGE_FS
    DO_TEST("pool-netfs-ns-mountopts");
#endif
    DO_TEST("pool-scsi");
    DO_TEST("pool-scsi-type-scsi-host");
    DO_TEST("pool-scsi-type-fc-host");
    DO_TEST("pool-scsi-type-fc-host-managed");
    DO_TEST("pool-mpath");
    DO_TEST("pool-iscsi-multiiqn");
    DO_TEST("pool-iscsi-vendor-product");
    DO_TEST("pool-gluster");
    DO_TEST("pool-gluster-sub");
    DO_TEST("pool-scsi-type-scsi-host-stable");
    DO_TEST("pool-zfs");
    DO_TEST("pool-zfs-sourcedev");
    DO_TEST("pool-rbd");
#ifdef WITH_STORAGE_RBD
    DO_TEST("pool-rbd-ipv6");
    DO_TEST("pool-rbd-refresh-volume-allocation");
    DO_TEST("pool-rbd-ns-configopts");
#endif
    DO_TEST("pool-vstorage");
    DO_TEST("pool-iscsi-direct-auth");
    DO_TEST("pool-iscsi-direct");

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
