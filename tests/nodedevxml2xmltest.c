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

static char *progname;
static char *abs_srcdir;

#define MAX_FILE 4096


static int testCompareXMLToXMLFiles(const char *xml) {
    char xmlData[MAX_FILE];
    char *xmlPtr = &(xmlData[0]);
    char *actual = NULL;
    int ret = -1;
    virNodeDeviceDefPtr dev = NULL;

    if (virtTestLoadFile(xml, &xmlPtr, MAX_FILE) < 0)
        goto fail;

    if (!(dev = virNodeDeviceDefParseString(NULL, xmlData)))
        goto fail;

    if (!(actual = virNodeDeviceDefFormat(NULL, dev)))
        goto fail;

    if (STRNEQ(xmlData, actual)) {
        virtTestDifference(stderr, xmlData, actual);
        goto fail;
    }

    ret = 0;

 fail:
    free(actual);
    virNodeDeviceDefFree(dev);
    return ret;
}

static int testCompareXMLToXMLHelper(const void *data) {
    char xml[PATH_MAX];
    snprintf(xml, PATH_MAX, "%s/nodedevschemadata/%s.xml",
             abs_srcdir, (const char*)data);
    return testCompareXMLToXMLFiles(xml);
}


static int
mymain(int argc, char **argv)
{
    int ret = 0;
    char cwd[PATH_MAX];

    progname = argv[0];

    if (argc > 1) {
        fprintf(stderr, "Usage: %s\n", progname);
        return (EXIT_FAILURE);
    }

    abs_srcdir = getenv("abs_srcdir");
    if (!abs_srcdir)
        abs_srcdir = getcwd(cwd, sizeof(cwd));

#define DO_TEST(name) \
    if (virtTestRun("Node device XML-2-XML " name, \
                    1, testCompareXMLToXMLHelper, (name)) < 0) \
        ret = -1

    DO_TEST("computer");
    DO_TEST("DVD_GCC_4247N");
    DO_TEST("net_00_13_02_b9_f9_d3");
    DO_TEST("net_00_15_58_2f_e9_55");
    DO_TEST("pci_1002_71c4");
    DO_TEST("pci_8086_27c5_scsi_host_0");
    DO_TEST("pci_8086_27c5_scsi_host_scsi_device_lun0");
    DO_TEST("pci_8086_27c5_scsi_host_scsi_host");
    DO_TEST("pci_8086_27c5_scsi_host");
    DO_TEST("storage_serial_SATA_HTS721010G9SA00_MPCZ12Y0GNGWSE");
    DO_TEST("usb_device_1d6b_1_0000_00_1d_0_if0");
    DO_TEST("usb_device_1d6b_1_0000_00_1d_0");

    return (ret==0 ? EXIT_SUCCESS : EXIT_FAILURE);
}

VIRT_TEST_MAIN(mymain)
