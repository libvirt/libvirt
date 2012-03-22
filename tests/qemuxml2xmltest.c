#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <fcntl.h>

#ifdef WITH_QEMU

# include "internal.h"
# include "testutils.h"
# include "qemu/qemu_conf.h"
# include "qemu/qemu_domain.h"
# include "testutilsqemu.h"

static struct qemud_driver driver;

static int
testCompareXMLToXMLFiles(const char *inxml, const char *outxml, bool live)
{
    char *inXmlData = NULL;
    char *outXmlData = NULL;
    char *actual = NULL;
    int ret = -1;
    virDomainDefPtr def = NULL;

    if (virtTestLoadFile(inxml, &inXmlData) < 0)
        goto fail;
    if (virtTestLoadFile(outxml, &outXmlData) < 0)
        goto fail;

    if (!(def = virDomainDefParseString(driver.caps, inXmlData,
                                        QEMU_EXPECTED_VIRT_TYPES,
                                        live ? 0 : VIR_DOMAIN_XML_INACTIVE)))
        goto fail;

    if (!(actual = virDomainDefFormat(def, VIR_DOMAIN_XML_SECURE)))
        goto fail;

    if (STRNEQ(outXmlData, actual)) {
        virtTestDifference(stderr, outXmlData, actual);
        goto fail;
    }

    ret = 0;
 fail:
    VIR_FREE(inXmlData);
    VIR_FREE(outXmlData);
    VIR_FREE(actual);
    virDomainDefFree(def);
    return ret;
}

struct testInfo {
    const char *name;
    int different;
    bool inactive_only;
};

static int
testCompareXMLToXMLHelper(const void *data)
{
    const struct testInfo *info = data;
    char *xml_in = NULL;
    char *xml_out = NULL;
    int ret = -1;

    if (virAsprintf(&xml_in, "%s/qemuxml2argvdata/qemuxml2argv-%s.xml",
                    abs_srcdir, info->name) < 0 ||
        virAsprintf(&xml_out, "%s/qemuxml2xmloutdata/qemuxml2xmlout-%s.xml",
                    abs_srcdir, info->name) < 0)
        goto cleanup;

    if (info->different) {
        ret = testCompareXMLToXMLFiles(xml_in, xml_out, false);
    } else {
        ret = testCompareXMLToXMLFiles(xml_in, xml_in, false);
    }
    if (!info->inactive_only) {
        if (info->different) {
            ret = testCompareXMLToXMLFiles(xml_in, xml_out, true);
        } else {
            ret = testCompareXMLToXMLFiles(xml_in, xml_in, true);
        }
    }

cleanup:
    VIR_FREE(xml_in);
    VIR_FREE(xml_out);
    return ret;
}


static int
mymain(void)
{
    int ret = 0;

    if ((driver.caps = testQemuCapsInit()) == NULL)
        return EXIT_FAILURE;

# define DO_TEST_FULL(name, is_different, inactive)                     \
    do {                                                                \
        const struct testInfo info = {name, is_different, inactive};    \
        if (virtTestRun("QEMU XML-2-XML " name,                         \
                        1, testCompareXMLToXMLHelper, &info) < 0)       \
            ret = -1;                                                   \
    } while (0)

# define DO_TEST(name) \
    DO_TEST_FULL(name, 0, false)

# define DO_TEST_DIFFERENT(name) \
    DO_TEST_FULL(name, 1, false)

    /* Unset or set all envvars here that are copied in qemudBuildCommandLine
     * using ADD_ENV_COPY, otherwise these tests may fail due to unexpected
     * values for these envvars */
    setenv("PATH", "/bin", 1);

    DO_TEST("minimal");
    DO_TEST("boot-cdrom");
    DO_TEST("boot-network");
    DO_TEST("boot-floppy");
    DO_TEST("boot-multi");
    DO_TEST("boot-menu-disable");
    DO_TEST("boot-order");
    DO_TEST("bootloader");
    DO_TEST("clock-utc");
    DO_TEST("clock-localtime");
    DO_TEST("cpu-kvmclock");
    DO_TEST("cpu-host-kvmclock");
    DO_TEST("kvmclock");
    DO_TEST("hugepages");
    DO_TEST("disk-aio");
    DO_TEST("disk-cdrom");
    DO_TEST("disk-floppy");
    DO_TEST("disk-many");
    DO_TEST("disk-xenvbd");
    DO_TEST("disk-usb");
    DO_TEST("disk-virtio");
    DO_TEST("floppy-drive-fat");
    DO_TEST("disk-drive-fat");
    DO_TEST("disk-drive-fmt-qcow");
    DO_TEST("disk-drive-cache-v1-wt");
    DO_TEST("disk-drive-cache-v1-wb");
    DO_TEST("disk-drive-cache-v1-none");
    DO_TEST("disk-scsi-device");
    DO_TEST("disk-scsi-vscsi");
    DO_TEST("disk-scsi-virtio-scsi");
    DO_TEST("graphics-listen-network");
    DO_TEST("graphics-vnc");
    DO_TEST("graphics-vnc-sasl");
    DO_TEST("graphics-vnc-tls");
    DO_TEST("graphics-sdl");
    DO_TEST("graphics-sdl-fullscreen");
    DO_TEST("graphics-spice");
    DO_TEST("graphics-spice-compression");
    DO_TEST("graphics-spice-qxl-vga");
    DO_TEST("input-usbmouse");
    DO_TEST("input-usbtablet");
    DO_TEST("input-xen");
    DO_TEST("misc-acpi");
    DO_TEST("misc-no-reboot");
    DO_TEST("net-user");
    DO_TEST("net-virtio");
    DO_TEST("net-virtio-device");
    DO_TEST("net-eth");
    DO_TEST("net-eth-ifname");
    DO_TEST("net-virtio-network-portgroup");
    DO_TEST("net-hostdev");
    DO_TEST("sound");
    DO_TEST("net-bandwidth");

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
    DO_TEST("console-virtio-many");
    DO_TEST("channel-guestfwd");
    DO_TEST("channel-virtio");

    DO_TEST("hostdev-usb-address");
    DO_TEST("hostdev-pci-address");
    DO_TEST("pci-rom");

    DO_TEST("encrypted-disk");
    DO_TEST_DIFFERENT("memtune");
    DO_TEST("blkiotune");
    DO_TEST("blkiotune-device");
    DO_TEST("cputune");

    DO_TEST("smp");
    DO_TEST("lease");
    DO_TEST("event_idx");
    DO_TEST("virtio-lun");

    DO_TEST("usb-redir");
    DO_TEST("blkdeviotune");

    DO_TEST_FULL("seclabel-dynamic-baselabel", false, true);
    DO_TEST_FULL("seclabel-dynamic-override", false, true);
    DO_TEST("seclabel-static");
    DO_TEST("seclabel-none");

    /* These tests generate different XML */
    DO_TEST_DIFFERENT("balloon-device-auto");
    DO_TEST_DIFFERENT("channel-virtio-auto");
    DO_TEST_DIFFERENT("console-compat-auto");
    DO_TEST_DIFFERENT("disk-scsi-device-auto");
    DO_TEST_DIFFERENT("console-virtio");
    DO_TEST_DIFFERENT("serial-target-port-auto");
    DO_TEST_DIFFERENT("graphics-listen-network2");
    DO_TEST_DIFFERENT("graphics-spice-timeout");

    DO_TEST_DIFFERENT("metadata");

    virCapabilitiesFree(driver.caps);

    return ret==0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)

#else
# include "testutils.h"

int
main(void)
{
    return EXIT_AM_SKIP;
}

#endif /* WITH_QEMU */
