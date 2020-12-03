#include <config.h>

#include <unistd.h>

#include <sys/types.h>
#include <fcntl.h>

#include "internal.h"
#include "testutils.h"
#include "node_device_conf.h"
#include "testutilsqemu.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NONE

static int
testCompareXMLToXMLFiles(const char *xml)
{
    char *xmlData = NULL;
    char *actual = NULL;
    int ret = -1;
    virNodeDeviceDefPtr dev = NULL;
    virNodeDevCapsDefPtr caps;

    if (virTestLoadFile(xml, &xmlData) < 0)
        goto fail;

    if (!(dev = virNodeDeviceDefParseString(xmlData, EXISTING_DEVICE, NULL)))
        goto fail;

    /* Calculate some things that are not read in */
    for (caps = dev->caps; caps; caps = caps->next) {
        virNodeDevCapDataPtr data = &caps->data;

        if (caps->data.type == VIR_NODE_DEV_CAP_STORAGE) {
            if (data->storage.flags & VIR_NODE_DEV_CAP_STORAGE_REMOVABLE) {
                if (data->storage.flags &
                    VIR_NODE_DEV_CAP_STORAGE_REMOVABLE_MEDIA_AVAILABLE) {
                    data->storage.logical_block_size = 2048;
                    data->storage.num_blocks =
                        data->storage.removable_media_size /
                        data->storage.logical_block_size;
                }
            } else {
                data->storage.logical_block_size = 512;
                data->storage.num_blocks = data->storage.size /
                                           data->storage.logical_block_size;
            }
        }
    }

    if (!(actual = virNodeDeviceDefFormat(dev)))
        goto fail;

    if (STRNEQ(xmlData, actual)) {
        virTestDifferenceFull(stderr, xmlData, xml, actual, NULL);
        goto fail;
    }

    ret = 0;

 fail:
    VIR_FREE(xmlData);
    VIR_FREE(actual);
    virNodeDeviceDefFree(dev);
    return ret;
}

static int
testCompareXMLToXMLHelper(const void *data)
{
    int result = -1;
    char *xml = NULL;

    xml = g_strdup_printf("%s/nodedevschemadata/%s.xml", abs_srcdir,
                          (const char *)data);

    result = testCompareXMLToXMLFiles(xml);

    VIR_FREE(xml);
    return result;
}


static int
mymain(void)
{
    int ret = 0;

#define DO_TEST(name) \
    if (virTestRun("Node device XML-2-XML " name, \
                   testCompareXMLToXMLHelper, (name)) < 0) \
        ret = -1

    DO_TEST("computer");
    DO_TEST("DVD_GCC_4247N");
    DO_TEST("DVD_with_media");
    DO_TEST("net_00_13_02_b9_f9_d3");
    DO_TEST("net_00_15_58_2f_e9_55");
    DO_TEST("pci_1002_71c4");
    DO_TEST("pci_8086_10c9_sriov_pf");
    DO_TEST("pci_8086_27c5_scsi_host_0");
    DO_TEST("pci_8086_27c5_scsi_host_0_unique_id");
    DO_TEST("pci_8086_27c5_scsi_host_scsi_device_lun0");
    DO_TEST("pci_8086_27c5_scsi_host_scsi_host");
    DO_TEST("pci_8086_27c5_scsi_host");
    DO_TEST("storage_serial_SATA_HTS721010G9SA00_MPCZ12Y0GNGWSE");
    DO_TEST("storage_serial_3600c0ff000d7a2a5d463ff4902000000");
    DO_TEST("usb_device_1d6b_1_0000_00_1d_0_if0");
    DO_TEST("usb_device_1d6b_1_0000_00_1d_0");
    DO_TEST("pci_8086_4238_pcie_wireless");
    DO_TEST("pci_8086_0c0c_snd_hda_intel");
    DO_TEST("pci_0000_00_02_0_header_type");
    DO_TEST("pci_0000_00_1c_0_header_type");
    DO_TEST("scsi_target0_0_0");
    DO_TEST("scsi_target1_0_0");
    DO_TEST("pci_0000_02_10_7_sriov");
    DO_TEST("pci_0000_02_10_7_sriov_vfs");
    DO_TEST("pci_0000_02_10_7_sriov_zero_vfs_max_count");
    DO_TEST("pci_0000_02_10_7_sriov_pf_vfs_all");
    DO_TEST("pci_0000_02_10_7_sriov_pf_vfs_all_header_type");
    DO_TEST("drm_renderD129");
    DO_TEST("pci_0000_02_10_7_mdev_types");
    DO_TEST("mdev_3627463d_b7f0_4fea_b468_f1da537d301b");
    DO_TEST("ccw_0_0_ffff");
    DO_TEST("css_0_0_ffff");
    DO_TEST("css_0_0_fffe_mdev_types");
    DO_TEST("ap_card07");
    DO_TEST("ap_07_0038");
    DO_TEST("ap_matrix");
    DO_TEST("ap_matrix_mdev_types");
    DO_TEST("mdev_ee0b88c4_f554_4dc1_809d_b2a01e8e48ad");

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
