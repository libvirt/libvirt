#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

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

    if (virtTestLoadFile(xml, &xmlData) < 0)
        goto fail;

    if (!(dev = virNodeDeviceDefParseString(xmlData, EXISTING_DEVICE, NULL)))
        goto fail;

    if (!(actual = virNodeDeviceDefFormat(dev)))
        goto fail;

    if (STRNEQ(xmlData, actual)) {
        virtTestDifference(stderr, xmlData, actual);
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

    if (virAsprintf(&xml, "%s/nodedevschemadata/%s.xml",
                    abs_srcdir, (const char*)data) < 0)
        return -1;

    result = testCompareXMLToXMLFiles(xml);

    VIR_FREE(xml);
    return result;
}


static int
mymain(void)
{
    int ret = 0;

#define DO_TEST(name)                                           \
    if (virtTestRun("Node device XML-2-XML " name,              \
                    testCompareXMLToXMLHelper, (name)) < 0)     \
        ret = -1

    DO_TEST("computer");
    DO_TEST("DVD_GCC_4247N");
    DO_TEST("DVD_with_media");
    DO_TEST("net_00_13_02_b9_f9_d3");
    DO_TEST("net_00_15_58_2f_e9_55");
    DO_TEST("pci_1002_71c4");
    DO_TEST("pci_8086_10c9_sriov_pf");
    DO_TEST("pci_8086_27c5_scsi_host_0");
    DO_TEST("pci_8086_27c5_scsi_host_scsi_device_lun0");
    DO_TEST("pci_8086_27c5_scsi_host_scsi_host");
    DO_TEST("pci_8086_27c5_scsi_host");
    DO_TEST("storage_serial_SATA_HTS721010G9SA00_MPCZ12Y0GNGWSE");
    DO_TEST("usb_device_1d6b_1_0000_00_1d_0_if0");
    DO_TEST("usb_device_1d6b_1_0000_00_1d_0");

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)
