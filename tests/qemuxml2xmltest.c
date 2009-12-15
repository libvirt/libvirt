#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <fcntl.h>

#ifdef WITH_QEMU

#include "internal.h"
#include "testutils.h"
#include "qemu/qemu_conf.h"
#include "testutilsqemu.h"

static char *progname;
static char *abs_srcdir;
static struct qemud_driver driver;

#define MAX_FILE 4096


static int testCompareXMLToXMLFiles(const char *xml) {
    char xmlData[MAX_FILE];
    char *xmlPtr = &(xmlData[0]);
    char *actual = NULL;
    int ret = -1;
    virDomainDefPtr vmdef = NULL;

    if (virtTestLoadFile(xml, &xmlPtr, MAX_FILE) < 0)
        goto fail;

    if (!(vmdef = virDomainDefParseString(NULL, driver.caps, xmlData,
                                          VIR_DOMAIN_XML_INACTIVE)))
        goto fail;

    if (!(actual = virDomainDefFormat(NULL, vmdef, 0)))
        goto fail;

    if (STRNEQ(xmlData, actual)) {
        virtTestDifference(stderr, xmlData, actual);
        goto fail;
    }

    ret = 0;

 fail:
    free(actual);
    virDomainDefFree(vmdef);
    return ret;
}

static int testCompareXMLToXMLHelper(const void *data) {
    char xml[PATH_MAX];
    snprintf(xml, PATH_MAX, "%s/qemuxml2argvdata/qemuxml2argv-%s.xml",
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

    if ((driver.caps = testQemuCapsInit()) == NULL)
        return (EXIT_FAILURE);

#define DO_TEST(name) \
    if (virtTestRun("QEMU XML-2-XML " name, \
                    1, testCompareXMLToXMLHelper, (name)) < 0) \
        ret = -1

    DO_TEST("minimal");
    DO_TEST("boot-cdrom");
    DO_TEST("boot-network");
    DO_TEST("boot-floppy");
    DO_TEST("bootloader");
    DO_TEST("clock-utc");
    DO_TEST("clock-localtime");
    DO_TEST("hugepages");
    DO_TEST("disk-cdrom");
    DO_TEST("disk-floppy");
    DO_TEST("disk-many");
    DO_TEST("disk-xenvbd");
    DO_TEST("disk-usb");
    DO_TEST("floppy-drive-fat");
    DO_TEST("disk-drive-fat");
    DO_TEST("disk-drive-fmt-qcow");
    DO_TEST("disk-drive-cache-v1-wt");
    DO_TEST("disk-drive-cache-v1-wb");
    DO_TEST("disk-drive-cache-v1-none");
    DO_TEST("graphics-vnc");
    DO_TEST("graphics-vnc-sasl");
    DO_TEST("graphics-vnc-tls");
    DO_TEST("graphics-sdl");
    DO_TEST("graphics-sdl-fullscreen");
    DO_TEST("input-usbmouse");
    DO_TEST("input-usbtablet");
    DO_TEST("input-xen");
    DO_TEST("misc-acpi");
    DO_TEST("misc-no-reboot");
    DO_TEST("net-user");
    DO_TEST("net-virtio");
    DO_TEST("net-eth");
    DO_TEST("net-eth-ifname");
    DO_TEST("sound");

    DO_TEST("serial-vc");
    DO_TEST("serial-pty");
    DO_TEST("serial-dev");
    DO_TEST("serial-file");
    DO_TEST("serial-unix");
    DO_TEST("serial-tcp");
    DO_TEST("serial-udp");
    DO_TEST("serial-tcp-telnet");
    DO_TEST("serial-many");
    DO_TEST("parallel-tcp");
    DO_TEST("console-compat");
    DO_TEST("channel-guestfwd");

    DO_TEST("hostdev-usb-product");
    DO_TEST("hostdev-usb-address");
    DO_TEST("hostdev-pci-address");

    virCapabilitiesFree(driver.caps);

    return (ret==0 ? EXIT_SUCCESS : EXIT_FAILURE);
}

VIRT_TEST_MAIN(mymain)

#else

int main (void) { exit (EXIT_AM_SKIP); }

#endif /* WITH_QEMU */
