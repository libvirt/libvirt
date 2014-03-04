#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <fcntl.h>

#include "testutils.h"

#ifdef WITH_QEMU

# include "internal.h"
# include "qemu/qemu_conf.h"
# include "qemu/qemu_domain.h"
# include "testutilsqemu.h"
# include "virstring.h"

# define VIR_FROM_THIS VIR_FROM_NONE

static virQEMUDriver driver;

static int
testCompareXMLToXMLFiles(const char *inxml, const char *outxml, bool live)
{
    char *inXmlData = NULL;
    char *outXmlData = NULL;
    char *actual = NULL;
    int ret = -1;
    virDomainDefPtr def = NULL;
    unsigned int flags = live ? 0 : VIR_DOMAIN_XML_INACTIVE;

    if (virtTestLoadFile(inxml, &inXmlData) < 0)
        goto fail;
    if (virtTestLoadFile(outxml, &outXmlData) < 0)
        goto fail;

    if (!(def = virDomainDefParseString(inXmlData, driver.caps, driver.xmlopt,
                                        QEMU_EXPECTED_VIRT_TYPES, flags)))
        goto fail;

    if (!virDomainDefCheckABIStability(def, def)) {
        fprintf(stderr, "ABI stability check failed on %s", inxml);
        goto fail;
    }

    if (!(actual = virDomainDefFormat(def, VIR_DOMAIN_XML_SECURE | flags)))
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

enum {
    WHEN_INACTIVE = 1,
    WHEN_ACTIVE = 2,
    WHEN_EITHER = 3,
};

struct testInfo {
    const char *name;
    bool different;
    int when;
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

    if ((info->when & WHEN_INACTIVE) &&
        testCompareXMLToXMLFiles(xml_in,
                                 info->different ? xml_out : xml_in,
                                 false) < 0)
        goto cleanup;

    if ((info->when & WHEN_ACTIVE) &&
        testCompareXMLToXMLFiles(xml_in,
                                 info->different ? xml_out : xml_in,
                                 true) < 0)
        goto cleanup;

    ret = 0;

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

    if (!(driver.xmlopt = virQEMUDriverCreateXMLConf(&driver)))
        return EXIT_FAILURE;

# define DO_TEST_FULL(name, is_different, when)                         \
    do {                                                                \
        const struct testInfo info = {name, is_different, when};        \
        if (virtTestRun("QEMU XML-2-XML " name,                         \
                        testCompareXMLToXMLHelper, &info) < 0)          \
            ret = -1;                                                   \
    } while (0)

# define DO_TEST(name) \
    DO_TEST_FULL(name, false, WHEN_EITHER)

# define DO_TEST_DIFFERENT(name) \
    DO_TEST_FULL(name, true, WHEN_EITHER)

    /* Unset or set all envvars here that are copied in qemudBuildCommandLine
     * using ADD_ENV_COPY, otherwise these tests may fail due to unexpected
     * values for these envvars */
    setenv("PATH", "/bin", 1);

    DO_TEST("minimal");
    DO_TEST("machine-core-on");
    DO_TEST("machine-core-off");
    DO_TEST("boot-cdrom");
    DO_TEST("boot-network");
    DO_TEST("boot-floppy");
    DO_TEST("boot-multi");
    DO_TEST("boot-menu-disable");
    DO_TEST("boot-order");
    DO_TEST("bootloader");

    DO_TEST("reboot-timeout-enabled");
    DO_TEST("reboot-timeout-disabled");

    DO_TEST("clock-utc");
    DO_TEST("clock-localtime");
    DO_TEST("cpu-kvmclock");
    DO_TEST("cpu-host-kvmclock");
    DO_TEST("clock-catchup");
    DO_TEST("kvmclock");
    DO_TEST("clock-timer-hyperv-rtc");

    DO_TEST("cpu-eoi-disabled");
    DO_TEST("cpu-eoi-enabled");
    DO_TEST("eoi-disabled");
    DO_TEST("eoi-enabled");
    DO_TEST("pv-spinlock-disabled");
    DO_TEST("pv-spinlock-enabled");

    DO_TEST("hyperv");
    DO_TEST("hyperv-off");

    DO_TEST("hugepages");
    DO_TEST("nosharepages");
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
    DO_TEST("disk-drive-network-nbd");
    DO_TEST("disk-drive-network-nbd-export");
    DO_TEST("disk-drive-network-nbd-ipv6");
    DO_TEST("disk-drive-network-nbd-ipv6-export");
    DO_TEST("disk-drive-network-nbd-unix");
    DO_TEST("disk-drive-network-iscsi");
    DO_TEST("disk-drive-network-iscsi-auth");
    DO_TEST("disk-scsi-device");
    DO_TEST("disk-scsi-vscsi");
    DO_TEST("disk-scsi-virtio-scsi");
    DO_TEST("disk-virtio-scsi-num_queues");
    DO_TEST("disk-scsi-megasas");
    DO_TEST_FULL("disk-mirror", false, WHEN_ACTIVE);
    DO_TEST_FULL("disk-mirror", true, WHEN_INACTIVE);
    DO_TEST("graphics-listen-network");
    DO_TEST("graphics-vnc");
    DO_TEST("graphics-vnc-websocket");
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
    DO_TEST("misc-disable-s3");
    DO_TEST("misc-disable-suspends");
    DO_TEST("misc-enable-s4");
    DO_TEST("misc-no-reboot");
    DO_TEST("net-user");
    DO_TEST("net-virtio");
    DO_TEST("net-virtio-device");
    DO_TEST("net-eth");
    DO_TEST("net-eth-ifname");
    DO_TEST("net-virtio-network-portgroup");
    DO_TEST("net-hostdev");
    DO_TEST("net-hostdev-vfio");
    DO_TEST("net-openvswitch");
    DO_TEST("sound");
    DO_TEST("sound-device");
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
    DO_TEST("serial-spiceport");
    DO_TEST("serial-spiceport-nospice");
    DO_TEST("parallel-tcp");
    DO_TEST("console-compat");
    DO_TEST("console-virtio-many");
    DO_TEST("channel-guestfwd");
    DO_TEST("channel-virtio");

    DO_TEST("hostdev-usb-address");
    DO_TEST("hostdev-pci-address");
    DO_TEST("hostdev-vfio");
    DO_TEST("pci-rom");

    DO_TEST("encrypted-disk");
    DO_TEST_DIFFERENT("memtune");
    DO_TEST_DIFFERENT("memtune-unlimited");
    DO_TEST("blkiotune");
    DO_TEST("blkiotune-device");
    DO_TEST("cputune");
    DO_TEST("cputune-zero-shares");

    DO_TEST("smp");
    DO_TEST("lease");
    DO_TEST("event_idx");
    DO_TEST("vhost_queues");
    DO_TEST("virtio-lun");

    DO_TEST("usb-redir");
    DO_TEST("blkdeviotune");

    DO_TEST_FULL("seclabel-dynamic-baselabel", false, WHEN_INACTIVE);
    DO_TEST_FULL("seclabel-dynamic-override", false, WHEN_INACTIVE);
    DO_TEST_FULL("seclabel-dynamic-labelskip", true, WHEN_INACTIVE);
    DO_TEST_FULL("seclabel-dynamic-relabel", false, WHEN_INACTIVE);
    DO_TEST("seclabel-static");
    DO_TEST_FULL("seclabel-static-labelskip", false, WHEN_ACTIVE);
    DO_TEST("seclabel-none");
    DO_TEST("numad-static-vcpu-no-numatune");
    DO_TEST("disk-scsi-lun-passthrough-sgio");

    DO_TEST("disk-scsi-disk-vpd");
    DO_TEST("disk-source-pool");
    DO_TEST("disk-source-pool-mode");

    DO_TEST("disk-drive-discard");

    DO_TEST("virtio-rng-random");
    DO_TEST("virtio-rng-egd");

    DO_TEST("pseries-nvram");

    /* These tests generate different XML */
    DO_TEST_DIFFERENT("balloon-device-auto");
    DO_TEST_DIFFERENT("channel-virtio-auto");
    DO_TEST_DIFFERENT("console-compat-auto");
    DO_TEST_DIFFERENT("disk-scsi-device-auto");
    DO_TEST_DIFFERENT("console-virtio");
    DO_TEST_DIFFERENT("serial-target-port-auto");
    DO_TEST_DIFFERENT("graphics-listen-network2");
    DO_TEST_DIFFERENT("graphics-spice-timeout");
    DO_TEST_DIFFERENT("numad-auto-vcpu-no-numatune");
    DO_TEST_DIFFERENT("numad-auto-memory-vcpu-no-cpuset-and-placement");
    DO_TEST_DIFFERENT("numad-auto-memory-vcpu-cpuset");
    DO_TEST_DIFFERENT("usb-ich9-ehci-addr");

    DO_TEST_DIFFERENT("metadata");

    DO_TEST("tpm-passthrough");
    DO_TEST("pci-bridge");
    DO_TEST_DIFFERENT("pci-bridge-many-disks");
    DO_TEST_DIFFERENT("pci-autoadd-addr");
    DO_TEST_DIFFERENT("pci-autoadd-idx");
    DO_TEST_DIFFERENT("pcie-root");
    DO_TEST_DIFFERENT("q35");

    DO_TEST("hostdev-scsi-lsi");
    DO_TEST("hostdev-scsi-virtio-scsi");
    DO_TEST("hostdev-scsi-readonly");

    DO_TEST("disk-copy_on_read");
    DO_TEST("hostdev-scsi-shareable");
    DO_TEST("hostdev-scsi-sgio");

    DO_TEST_DIFFERENT("hostdev-scsi-autogen-address");

    DO_TEST_DIFFERENT("s390-defaultconsole");

    DO_TEST("pcihole64");
    DO_TEST_DIFFERENT("pcihole64-gib");
    DO_TEST("pcihole64-none");
    DO_TEST("pcihole64-q35");

    DO_TEST("panic");

    virObjectUnref(driver.caps);
    virObjectUnref(driver.xmlopt);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)

#else

int
main(void)
{
    return EXIT_AM_SKIP;
}

#endif /* WITH_QEMU */
