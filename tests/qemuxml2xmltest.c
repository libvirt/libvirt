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

enum {
    WHEN_INACTIVE = 1,
    WHEN_ACTIVE = 2,
    WHEN_BOTH = 3,
};

struct testInfo {
    char *inName;
    char *outActiveName;
    char *outInactiveName;

    virQEMUCapsPtr qemuCaps;
};

static int
qemuXML2XMLPreFormatCallback(virDomainDefPtr def, const void *opaque)
{
    const struct testInfo *info = opaque;

    if (qemuDomainAssignAddresses(def, info->qemuCaps, NULL))
        return -1;

    return 0;
}

static int
testXML2XMLActive(const void *opaque)
{
    const struct testInfo *info = opaque;

    return testCompareDomXML2XMLFiles(driver.caps, driver.xmlopt,
                                      info->inName, info->outActiveName, true,
                                      qemuXML2XMLPreFormatCallback, opaque, 0);
}


static int
testXML2XMLInactive(const void *opaque)
{
    const struct testInfo *info = opaque;

    return testCompareDomXML2XMLFiles(driver.caps, driver.xmlopt, info->inName,
                                      info->outInactiveName, false,
                                      qemuXML2XMLPreFormatCallback, opaque, 0);
}


static const char testStatusXMLPrefix[] =
"<domstatus state='running' reason='booted' pid='3803518'>\n"
"  <taint flag='high-privileges'/>\n"
"  <monitor path='/var/lib/libvirt/qemu/test.monitor' json='1' type='unix'/>\n"
"  <vcpus>\n"
"    <vcpu pid='3803519'/>\n"
"  </vcpus>\n"
"  <qemuCaps>\n"
"    <flag name='vnet-hdr'/>\n"
"    <flag name='qxl.vgamem_mb'/>\n"
"    <flag name='qxl-vga.vgamem_mb'/>\n"
"    <flag name='pc-dimm'/>\n"
"  </qemuCaps>\n"
"  <devices>\n"
"    <device alias='balloon0'/>\n"
"    <device alias='video0'/>\n"
"    <device alias='serial0'/>\n"
"    <device alias='net0'/>\n"
"    <device alias='usb'/>\n"
"  </devices>\n"
"  <numad nodeset='0-2'/>\n";

static const char testStatusXMLSuffix[] =
"</domstatus>\n";


static int
testCompareStatusXMLToXMLFiles(const void *opaque)
{
    const struct testInfo *data = opaque;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    xmlDocPtr xml = NULL;
    virDomainObjPtr obj = NULL;
    char *expect = NULL;
    char *actual = NULL;
    char *source = NULL;
    char *inFile = NULL, *outActiveFile = NULL;
    int ret = -1;
    int keepBlanksDefault = xmlKeepBlanksDefault(0);

    if (virtTestLoadFile(data->inName, &inFile) < 0)
        goto cleanup;
    if (virtTestLoadFile(data->outActiveName, &outActiveFile) < 0)
        goto cleanup;

    /* construct faked source status XML */
    virBufferAdd(&buf, testStatusXMLPrefix, -1);
    virBufferAdjustIndent(&buf, 2);
    virBufferAddStr(&buf, inFile);
    virBufferAdjustIndent(&buf, -2);
    virBufferAdd(&buf, testStatusXMLSuffix, -1);

    if (!(source = virBufferContentAndReset(&buf))) {
        VIR_TEST_DEBUG("Failed to create the source XML");
        goto cleanup;
    }

    /* construct the expect string */
    virBufferAdd(&buf, testStatusXMLPrefix, -1);
    virBufferAdjustIndent(&buf, 2);
    virBufferAddStr(&buf, outActiveFile);
    virBufferAdjustIndent(&buf, -2);
    virBufferAdd(&buf, testStatusXMLSuffix, -1);

    if (!(expect = virBufferContentAndReset(&buf))) {
        VIR_TEST_DEBUG("Failed to create the expect XML");
        goto cleanup;
    }

    /* parse the fake source status XML */
    if (!(xml = virXMLParseString(source, "(domain_status_test_XML)")) ||
        !(obj = virDomainObjParseNode(xml, xmlDocGetRootElement(xml),
                                      driver.caps, driver.xmlopt,
                                      VIR_DOMAIN_DEF_PARSE_STATUS |
                                      VIR_DOMAIN_DEF_PARSE_ACTUAL_NET |
                                      VIR_DOMAIN_DEF_PARSE_PCI_ORIG_STATES))) {
        VIR_TEST_DEBUG("Failed to parse domain status XML:\n%s", source);
        goto cleanup;
    }

    if (qemuDomainAssignAddresses(obj->def, data->qemuCaps, NULL))
        goto cleanup;

    /* format it back */
    if (!(actual = virDomainObjFormat(driver.xmlopt, obj, NULL,
                                      VIR_DOMAIN_DEF_FORMAT_SECURE))) {
        VIR_TEST_DEBUG("Failed to format domain status XML");
        goto cleanup;
    }

    if (STRNEQ(actual, expect)) {
        /* For status test we don't want to regenerate output to not
         * add the status data.*/
        virtTestDifferenceFullNoRegenerate(stderr,
                                           expect, data->outActiveName,
                                           actual, data->inName);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    xmlKeepBlanksDefault(keepBlanksDefault);
    xmlFreeDoc(xml);
    virObjectUnref(obj);
    VIR_FREE(expect);
    VIR_FREE(actual);
    VIR_FREE(source);
    VIR_FREE(inFile);
    VIR_FREE(outActiveFile);
    return ret;
}


static void
testInfoFree(struct testInfo *info)
{
    VIR_FREE(info->inName);
    VIR_FREE(info->outActiveName);
    VIR_FREE(info->outInactiveName);

    virObjectUnref(info->qemuCaps);
}


static int
testInfoSet(struct testInfo *info,
            const char *name,
            int when)
{
    if (!(info->qemuCaps = virQEMUCapsNew()))
        goto error;

    virQEMUCapsSetList(info->qemuCaps,
                       QEMU_CAPS_DEVICE,
                       QEMU_CAPS_LAST);

    if (qemuTestCapsCacheInsert(driver.qemuCapsCache, name,
                                info->qemuCaps) < 0)
        goto error;

    if (virAsprintf(&info->inName, "%s/qemuxml2argvdata/qemuxml2argv-%s.xml",
                    abs_srcdir, name) < 0)
        goto error;

    if (when & WHEN_INACTIVE) {
        if (virAsprintf(&info->outInactiveName,
                        "%s/qemuxml2xmloutdata/qemuxml2xmlout-%s-inactive.xml",
                        abs_srcdir, name) < 0)
            goto error;

        if (!virFileExists(info->outInactiveName)) {
            VIR_FREE(info->outInactiveName);

            if (virAsprintf(&info->outInactiveName,
                            "%s/qemuxml2xmloutdata/qemuxml2xmlout-%s.xml",
                            abs_srcdir, name) < 0)
                goto error;
        }
    }

    if (when & WHEN_ACTIVE) {
        if (virAsprintf(&info->outActiveName,
                        "%s/qemuxml2xmloutdata/qemuxml2xmlout-%s-active.xml",
                        abs_srcdir, name) < 0)
            goto error;

        if (!virFileExists(info->outActiveName)) {
            VIR_FREE(info->outActiveName);

            if (virAsprintf(&info->outActiveName,
                            "%s/qemuxml2xmloutdata/qemuxml2xmlout-%s.xml",
                            abs_srcdir, name) < 0)
                goto error;
        }
    }

    return 0;

 error:
    testInfoFree(info);
    return -1;
}


static int
mymain(void)
{
    int ret = 0;
    struct testInfo info;

    if (qemuTestDriverInit(&driver) < 0)
        return EXIT_FAILURE;

    /* TODO: test with format probing disabled too */
    driver.config->allowDiskFormatProbing = true;

# define DO_TEST_FULL(name, when, ...)                                        \
    do {                                                                       \
        if (testInfoSet(&info, name, when) < 0) {                             \
            VIR_TEST_DEBUG("Failed to generate test data for '%s'", name);    \
            return -1;                                                         \
        }                                                                      \
        virQEMUCapsSetList(info.qemuCaps, __VA_ARGS__, QEMU_CAPS_LAST);        \
                                                                               \
        if (info.outInactiveName) {                                            \
            if (virtTestRun("QEMU XML-2-XML-inactive " name,                   \
                            testXML2XMLInactive, &info) < 0)                   \
                ret = -1;                                                      \
        }                                                                      \
                                                                               \
        if (info.outActiveName) {                                              \
            if (virtTestRun("QEMU XML-2-XML-active " name,                     \
                            testXML2XMLActive, &info) < 0)                     \
                ret = -1;                                                      \
                                                                               \
            if (virtTestRun("QEMU XML-2-XML-status " name,                     \
                            testCompareStatusXMLToXMLFiles, &info) < 0)        \
                ret = -1;                                                      \
        }                                                                      \
        testInfoFree(&info);                                                   \
    } while (0)

# define NONE QEMU_CAPS_LAST

# define DO_TEST(name) \
    DO_TEST_FULL(name, WHEN_BOTH, NONE)



    /* Unset or set all envvars here that are copied in qemudBuildCommandLine
     * using ADD_ENV_COPY, otherwise these tests may fail due to unexpected
     * values for these envvars */
    setenv("PATH", "/bin", 1);

    DO_TEST("minimal");
    DO_TEST("machine-core-on");
    DO_TEST("machine-core-off");
    DO_TEST("default-kvm-host-arch");
    DO_TEST("default-qemu-host-arch");
    DO_TEST("boot-cdrom");
    DO_TEST("boot-network");
    DO_TEST("boot-floppy");
    DO_TEST("boot-multi");
    DO_TEST("boot-menu-enable-with-timeout");
    DO_TEST("boot-menu-disable");
    DO_TEST("boot-menu-disable-with-timeout");
    DO_TEST("boot-order");

    DO_TEST("reboot-timeout-enabled");
    DO_TEST("reboot-timeout-disabled");

    DO_TEST("clock-utc");
    DO_TEST("clock-localtime");
    DO_TEST("cpu-empty");
    DO_TEST("cpu-kvmclock");
    DO_TEST("cpu-host-kvmclock");
    DO_TEST("cpu-host-passthrough-features");
    DO_TEST("cpu-host-model-features");
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
    DO_TEST("hyperv-panic");

    DO_TEST("kvm-features");
    DO_TEST("kvm-features-off");

    DO_TEST("pmu-feature");
    DO_TEST("pmu-feature-off");

    DO_TEST("hugepages");
    DO_TEST("hugepages-pages");
    DO_TEST("hugepages-pages2");
    DO_TEST("hugepages-pages3");
    DO_TEST("hugepages-shared");
    DO_TEST("nosharepages");
    DO_TEST("restore-v2");
    DO_TEST("migrate");
    DO_TEST("qemu-ns-no-env");
    DO_TEST("disk-aio");
    DO_TEST("disk-cdrom");
    DO_TEST("disk-cdrom-empty");
    DO_TEST("disk-floppy");
    DO_TEST("disk-many");
    DO_TEST("disk-xenvbd");
    DO_TEST("disk-usb-device");
    DO_TEST("disk-virtio");
    DO_TEST("floppy-drive-fat");
    DO_TEST("disk-drive-boot-disk");
    DO_TEST("disk-drive-boot-cdrom");
    DO_TEST("disk-drive-error-policy-stop");
    DO_TEST("disk-drive-error-policy-enospace");
    DO_TEST("disk-drive-error-policy-wreport-rignore");
    DO_TEST("disk-drive-fat");
    DO_TEST("disk-drive-fmt-qcow");
    DO_TEST("disk-drive-copy-on-read");
    DO_TEST("disk-drive-cache-v2-wt");
    DO_TEST("disk-drive-cache-v2-wb");
    DO_TEST("disk-drive-cache-v2-none");
    DO_TEST("disk-drive-cache-directsync");
    DO_TEST("disk-drive-cache-unsafe");
    DO_TEST("disk-drive-network-nbd");
    DO_TEST("disk-drive-network-nbd-export");
    DO_TEST("disk-drive-network-nbd-ipv6");
    DO_TEST("disk-drive-network-nbd-ipv6-export");
    DO_TEST("disk-drive-network-nbd-unix");
    DO_TEST("disk-drive-network-iscsi");
    DO_TEST("disk-drive-network-iscsi-auth");
    DO_TEST("disk-drive-network-gluster");
    DO_TEST("disk-drive-network-rbd");
    DO_TEST("disk-drive-network-rbd-auth");
    DO_TEST("disk-drive-network-rbd-ipv6");
    DO_TEST("disk-drive-network-rbd-ceph-env");
    DO_TEST("disk-drive-network-sheepdog");
    DO_TEST_FULL("disk-scsi-device", WHEN_ACTIVE,
                 QEMU_CAPS_NODEFCONFIG,
                 QEMU_CAPS_SCSI_LSI);
    DO_TEST("disk-scsi-vscsi");
    DO_TEST_FULL("disk-scsi-virtio-scsi", WHEN_ACTIVE,
                 QEMU_CAPS_NODEFCONFIG,
                 QEMU_CAPS_VIRTIO_SCSI);
    DO_TEST_FULL("disk-virtio-scsi-num_queues", WHEN_ACTIVE,
                 QEMU_CAPS_NODEFCONFIG,
                 QEMU_CAPS_VIRTIO_SCSI);
    DO_TEST_FULL("disk-virtio-scsi-cmd_per_lun", WHEN_ACTIVE,
                 QEMU_CAPS_NODEFCONFIG,
                 QEMU_CAPS_VIRTIO_SCSI);
    DO_TEST_FULL("disk-virtio-scsi-max_sectors", WHEN_ACTIVE,
                 QEMU_CAPS_NODEFCONFIG,
                 QEMU_CAPS_VIRTIO_SCSI);
    DO_TEST_FULL("disk-virtio-scsi-ioeventfd", WHEN_ACTIVE,
                 QEMU_CAPS_NODEFCONFIG,
                 QEMU_CAPS_VIRTIO_SCSI);
    DO_TEST_FULL("disk-scsi-megasas", WHEN_ACTIVE,
                 QEMU_CAPS_NODEFCONFIG,
                 QEMU_CAPS_SCSI_MEGASAS);
    DO_TEST_FULL("disk-scsi-mptsas1068", WHEN_ACTIVE,
                 QEMU_CAPS_NODEFCONFIG,
                 QEMU_CAPS_SCSI_MPTSAS1068,
                 QEMU_CAPS_SCSI_DISK_WWN);
    DO_TEST("disk-mirror-old");
    DO_TEST_FULL("disk-mirror", WHEN_ACTIVE, NONE);
    DO_TEST_FULL("disk-mirror", WHEN_INACTIVE, NONE);
    DO_TEST_FULL("disk-active-commit", WHEN_ACTIVE, NONE);
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
    DO_TEST("nographics-vga");
    DO_TEST("input-usbmouse");
    DO_TEST("input-usbtablet");
    DO_TEST("misc-acpi");
    DO_TEST("misc-disable-s3");
    DO_TEST("misc-disable-suspends");
    DO_TEST("misc-enable-s4");
    DO_TEST("misc-no-reboot");
    DO_TEST("misc-uuid");
    DO_TEST("net-vhostuser");
    DO_TEST("net-user");
    DO_TEST("net-virtio");
    DO_TEST("net-virtio-device");
    DO_TEST("net-virtio-disable-offloads");
    DO_TEST("net-eth");
    DO_TEST("net-eth-ifname");
    DO_TEST("net-virtio-network-portgroup");
    DO_TEST("net-hostdev");
    DO_TEST("net-hostdev-vfio");
    DO_TEST("net-midonet");
    DO_TEST("net-openvswitch");
    DO_TEST("sound");
    DO_TEST("sound-device");
    DO_TEST("watchdog");
    DO_TEST("net-bandwidth");
    DO_TEST("net-bandwidth2");

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
    DO_TEST("console-compat2");
    DO_TEST("console-virtio-many");
    DO_TEST("channel-guestfwd");
    DO_TEST("channel-virtio");
    DO_TEST("channel-virtio-state");

    DO_TEST("hostdev-usb-address");
    DO_TEST("hostdev-pci-address");
    DO_TEST("hostdev-vfio");
    DO_TEST("pci-rom");
    DO_TEST("pci-serial-dev-chardev");

    DO_TEST("encrypted-disk");
    DO_TEST("memtune");
    DO_TEST("memtune-unlimited");
    DO_TEST("blkiotune");
    DO_TEST("blkiotune-device");
    DO_TEST("cputune");
    DO_TEST("cputune-zero-shares");
    DO_TEST("cputune-iothreadsched");
    DO_TEST("cputune-iothreadsched-zeropriority");
    DO_TEST("cputune-numatune");
    DO_TEST_FULL("vcpu-placement-static", WHEN_ACTIVE,
                 QEMU_CAPS_DEVICE_PCI_BRIDGE);

    DO_TEST("smp");
    DO_TEST("iothreads");
    DO_TEST("iothreads-ids");
    DO_TEST("iothreads-ids-partial");
    DO_TEST("cputune-iothreads");
    DO_TEST("iothreads-disk");
    DO_TEST_FULL("iothreads-disk-virtio-ccw", WHEN_ACTIVE,
                 QEMU_CAPS_VIRTIO_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST("lease");
    DO_TEST("event_idx");
    DO_TEST("vhost_queues");
    DO_TEST("interface-driver");
    DO_TEST("interface-server");
    DO_TEST("virtio-lun");

    DO_TEST("usb-redir");
    DO_TEST("usb-redir-filter");
    DO_TEST("usb-redir-filter-version");
    DO_TEST("blkdeviotune");
    DO_TEST("controller-usb-order");

    DO_TEST_FULL("seclabel-dynamic-baselabel", WHEN_INACTIVE, NONE);
    DO_TEST_FULL("seclabel-dynamic-override", WHEN_INACTIVE, NONE);
    DO_TEST_FULL("seclabel-dynamic-labelskip", WHEN_INACTIVE, NONE);
    DO_TEST_FULL("seclabel-dynamic-relabel", WHEN_INACTIVE, NONE);
    DO_TEST("seclabel-static");
    DO_TEST_FULL("seclabel-static-labelskip", WHEN_ACTIVE, NONE);
    DO_TEST("seclabel-none");
    DO_TEST("seclabel-dac-none");
    DO_TEST("seclabel-dynamic-none");
    DO_TEST("seclabel-device-multiple");
    DO_TEST_FULL("seclabel-dynamic-none-relabel", WHEN_INACTIVE, NONE);
    DO_TEST("numad-static-vcpu-no-numatune");

    DO_TEST_FULL("disk-scsi-lun-passthrough-sgio", WHEN_ACTIVE,
                 QEMU_CAPS_NODEFCONFIG,
                 QEMU_CAPS_SCSI_CD, QEMU_CAPS_SCSI_LSI, QEMU_CAPS_VIRTIO_SCSI,
                 QEMU_CAPS_SCSI_DISK_WWN);
    DO_TEST_FULL("disk-scsi-disk-vpd", WHEN_ACTIVE,
                 QEMU_CAPS_NODEFCONFIG,
                 QEMU_CAPS_SCSI_CD, QEMU_CAPS_SCSI_LSI, QEMU_CAPS_VIRTIO_SCSI,
                 QEMU_CAPS_SCSI_DISK_WWN);
    DO_TEST("disk-source-pool");
    DO_TEST("disk-source-pool-mode");

    DO_TEST("disk-drive-discard");

    DO_TEST("virtio-rng-random");
    DO_TEST("virtio-rng-egd");

    DO_TEST("pseries-nvram");
    DO_TEST("pseries-panic-missing");
    DO_TEST("pseries-panic-no-address");

    DO_TEST("balloon-device-auto");
    DO_TEST("balloon-device-period");
    DO_TEST("channel-virtio-auto");
    DO_TEST("console-compat-auto");
    DO_TEST_FULL("disk-scsi-device-auto", WHEN_ACTIVE,
                 QEMU_CAPS_NODEFCONFIG,
                 QEMU_CAPS_SCSI_LSI);
    DO_TEST("console-virtio");
    DO_TEST("serial-target-port-auto");
    DO_TEST("graphics-listen-network2");
    DO_TEST("graphics-spice-timeout");
    DO_TEST("numad-auto-vcpu-no-numatune");
    DO_TEST("numad-auto-memory-vcpu-no-cpuset-and-placement");
    DO_TEST("numad-auto-memory-vcpu-cpuset");
    DO_TEST("usb-ich9-ehci-addr");
    DO_TEST("disk-copy_on_read");
    DO_TEST("tpm-passthrough");

    DO_TEST("metadata");
    DO_TEST("metadata-duplicate");

    DO_TEST_FULL("pci-bridge", WHEN_ACTIVE,
                 QEMU_CAPS_DEVICE_PCI_BRIDGE);
    DO_TEST_FULL("pci-bridge-many-disks", WHEN_ACTIVE,
                 QEMU_CAPS_DEVICE_PCI_BRIDGE);
    DO_TEST_FULL("pci-autoadd-addr", WHEN_ACTIVE,
                 QEMU_CAPS_DEVICE_PCI_BRIDGE);
    DO_TEST_FULL("pci-autoadd-idx", WHEN_ACTIVE,
                 QEMU_CAPS_DEVICE_PCI_BRIDGE);

    DO_TEST_FULL("q35", WHEN_ACTIVE,
                 QEMU_CAPS_DEVICE_PCI_BRIDGE,
                 QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
                 QEMU_CAPS_ICH9_AHCI,
                 QEMU_CAPS_PCI_MULTIFUNCTION, QEMU_CAPS_ICH9_USB_EHCI1,
                 QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
                 QEMU_CAPS_VGA_QXL, QEMU_CAPS_DEVICE_QXL);
    DO_TEST_FULL("q35-usb2", WHEN_ACTIVE,
                 QEMU_CAPS_DEVICE_PCI_BRIDGE,
                 QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
                 QEMU_CAPS_ICH9_AHCI,
                 QEMU_CAPS_PCI_MULTIFUNCTION, QEMU_CAPS_ICH9_USB_EHCI1,
                 QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
                 QEMU_CAPS_VGA_QXL, QEMU_CAPS_DEVICE_QXL);
    DO_TEST_FULL("q35-usb2-multi", WHEN_ACTIVE,
                 QEMU_CAPS_DEVICE_PCI_BRIDGE,
                 QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
                 QEMU_CAPS_ICH9_AHCI,
                 QEMU_CAPS_PCI_MULTIFUNCTION, QEMU_CAPS_ICH9_USB_EHCI1,
                 QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
                 QEMU_CAPS_VGA_QXL, QEMU_CAPS_DEVICE_QXL);
    DO_TEST_FULL("q35-usb2-reorder", WHEN_ACTIVE,
                 QEMU_CAPS_DEVICE_PCI_BRIDGE,
                 QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
                 QEMU_CAPS_ICH9_AHCI,
                 QEMU_CAPS_PCI_MULTIFUNCTION, QEMU_CAPS_ICH9_USB_EHCI1,
                 QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
                 QEMU_CAPS_VGA_QXL, QEMU_CAPS_DEVICE_QXL);

    DO_TEST_FULL("pcie-root", WHEN_ACTIVE,
                 QEMU_CAPS_DEVICE_PCI_BRIDGE,
                 QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
                 QEMU_CAPS_DEVICE_IOH3420,
                 QEMU_CAPS_ICH9_AHCI,
                 QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
                 QEMU_CAPS_VGA_QXL, QEMU_CAPS_DEVICE_QXL);
    DO_TEST_FULL("pcie-root-port", WHEN_ACTIVE,
                 QEMU_CAPS_DEVICE_PCI_BRIDGE,
                 QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
                 QEMU_CAPS_DEVICE_IOH3420,
                 QEMU_CAPS_ICH9_AHCI,
                 QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
                 QEMU_CAPS_VGA_QXL, QEMU_CAPS_DEVICE_QXL);
    DO_TEST_FULL("pcie-switch-upstream-port", WHEN_ACTIVE,
                 QEMU_CAPS_DEVICE_PCI_BRIDGE,
                 QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
                 QEMU_CAPS_DEVICE_IOH3420,
                 QEMU_CAPS_ICH9_AHCI,
                 QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
                 QEMU_CAPS_VGA_QXL, QEMU_CAPS_DEVICE_QXL);
    DO_TEST_FULL("pcie-switch-downstream-port", WHEN_ACTIVE,
                 QEMU_CAPS_DEVICE_PCI_BRIDGE,
                 QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
                 QEMU_CAPS_DEVICE_IOH3420,
                 QEMU_CAPS_ICH9_AHCI,
                 QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
                 QEMU_CAPS_VGA_QXL, QEMU_CAPS_DEVICE_QXL);


    DO_TEST_FULL("hostdev-scsi-lsi", WHEN_ACTIVE,
                 QEMU_CAPS_VIRTIO_SCSI, QEMU_CAPS_SCSI_LSI,
                 QEMU_CAPS_DEVICE_SCSI_GENERIC);
    DO_TEST_FULL("hostdev-scsi-virtio-scsi", WHEN_ACTIVE,
                 QEMU_CAPS_VIRTIO_SCSI, QEMU_CAPS_SCSI_LSI,
                 QEMU_CAPS_DEVICE_SCSI_GENERIC);
    DO_TEST_FULL("hostdev-scsi-readonly", WHEN_ACTIVE,
                 QEMU_CAPS_VIRTIO_SCSI, QEMU_CAPS_SCSI_LSI,
                 QEMU_CAPS_DEVICE_SCSI_GENERIC);

    DO_TEST_FULL("hostdev-scsi-shareable", WHEN_ACTIVE,
                 QEMU_CAPS_VIRTIO_SCSI, QEMU_CAPS_SCSI_LSI,
                 QEMU_CAPS_DEVICE_SCSI_GENERIC);
    DO_TEST_FULL("hostdev-scsi-sgio", WHEN_ACTIVE,
                 QEMU_CAPS_VIRTIO_SCSI, QEMU_CAPS_SCSI_LSI,
                 QEMU_CAPS_DEVICE_SCSI_GENERIC);
    DO_TEST_FULL("hostdev-scsi-rawio", WHEN_ACTIVE,
                 QEMU_CAPS_VIRTIO_SCSI, QEMU_CAPS_SCSI_LSI,
                 QEMU_CAPS_DEVICE_SCSI_GENERIC);

    DO_TEST_FULL("hostdev-scsi-autogen-address", WHEN_ACTIVE,
                 QEMU_CAPS_VIRTIO_SCSI, QEMU_CAPS_SCSI_LSI,
                 QEMU_CAPS_DEVICE_SCSI_GENERIC);
    DO_TEST_FULL("hostdev-scsi-large-unit", WHEN_ACTIVE,
                 QEMU_CAPS_VIRTIO_SCSI, QEMU_CAPS_SCSI_LSI,
                 QEMU_CAPS_DEVICE_SCSI_GENERIC);

    DO_TEST_FULL("hostdev-scsi-lsi-iscsi", WHEN_ACTIVE,
                 QEMU_CAPS_VIRTIO_SCSI, QEMU_CAPS_SCSI_LSI,
                 QEMU_CAPS_DEVICE_SCSI_GENERIC);
    DO_TEST_FULL("hostdev-scsi-lsi-iscsi-auth", WHEN_ACTIVE,
                 QEMU_CAPS_VIRTIO_SCSI, QEMU_CAPS_SCSI_LSI,
                 QEMU_CAPS_DEVICE_SCSI_GENERIC);
    DO_TEST_FULL("hostdev-scsi-virtio-iscsi", WHEN_ACTIVE,
                 QEMU_CAPS_VIRTIO_SCSI, QEMU_CAPS_SCSI_LSI,
                 QEMU_CAPS_DEVICE_SCSI_GENERIC);
    DO_TEST_FULL("hostdev-scsi-virtio-iscsi-auth", WHEN_ACTIVE,
                 QEMU_CAPS_VIRTIO_SCSI, QEMU_CAPS_SCSI_LSI,
                 QEMU_CAPS_DEVICE_SCSI_GENERIC);

    DO_TEST_FULL("s390-defaultconsole", WHEN_ACTIVE,
                 QEMU_CAPS_VIRTIO_CCW, QEMU_CAPS_VIRTIO_S390);

    DO_TEST("pcihole64");
    DO_TEST("pcihole64-gib");
    DO_TEST("pcihole64-none");
    DO_TEST_FULL("pcihole64-q35", WHEN_ACTIVE,
                 QEMU_CAPS_DEVICE_PCI_BRIDGE,
                 QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
                 QEMU_CAPS_ICH9_AHCI,
                 QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
                 QEMU_CAPS_VGA_QXL, QEMU_CAPS_DEVICE_QXL,
                 QEMU_CAPS_Q35_PCI_HOLE64_SIZE);

    DO_TEST("panic");
    DO_TEST("panic-isa");
    DO_TEST("panic-pseries");
    DO_TEST("panic-double");
    DO_TEST("panic-no-address");

    DO_TEST("disk-backing-chains");

    DO_TEST("chardev-label");

    DO_TEST("cpu-numa1");
    DO_TEST("cpu-numa2");
    DO_TEST("cpu-numa-no-memory-element");
    DO_TEST("cpu-numa-disordered");
    DO_TEST("cpu-numa-disjoint");
    DO_TEST("cpu-numa-memshared");

    DO_TEST("numatune-auto-prefer");
    DO_TEST("numatune-memnode");
    DO_TEST("numatune-memnode-no-memory");

    DO_TEST("bios-nvram");
    DO_TEST("bios-nvram-os-interleave");

    DO_TEST("tap-vhost");
    DO_TEST("tap-vhost-incorrect");
    DO_TEST("shmem");
    DO_TEST("smbios");
    DO_TEST("smbios-multiple-type2");

    DO_TEST_FULL("aarch64-aavmf-virtio-mmio", WHEN_ACTIVE,
            QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_DTB,
            QEMU_CAPS_DEVICE_VIRTIO_MMIO,
            QEMU_CAPS_DEVICE_VIRTIO_RNG, QEMU_CAPS_OBJECT_RNG_RANDOM);
    DO_TEST_FULL("aarch64-virtio-pci-default", WHEN_ACTIVE,
            QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_DTB,
            QEMU_CAPS_DEVICE_VIRTIO_MMIO,
            QEMU_CAPS_DEVICE_VIRTIO_RNG, QEMU_CAPS_OBJECT_RNG_RANDOM,
            QEMU_CAPS_OBJECT_GPEX, QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE, QEMU_CAPS_VIRTIO_SCSI);
    DO_TEST_FULL("aarch64-virtio-pci-manual-addresses", WHEN_ACTIVE,
            QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_DTB,
            QEMU_CAPS_DEVICE_VIRTIO_MMIO,
            QEMU_CAPS_DEVICE_VIRTIO_RNG, QEMU_CAPS_OBJECT_RNG_RANDOM,
            QEMU_CAPS_OBJECT_GPEX, QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE, QEMU_CAPS_VIRTIO_SCSI);

    DO_TEST("aarch64-gic-none");
    DO_TEST("aarch64-gic-default");
    DO_TEST("aarch64-gic-v2");
    DO_TEST("aarch64-gic-v3");
    DO_TEST("aarch64-gic-host");

    DO_TEST("memory-hotplug");
    DO_TEST("memory-hotplug-nonuma");
    DO_TEST("memory-hotplug-dimm");
    DO_TEST("net-udp");

    DO_TEST("video-virtio-gpu-device");
    DO_TEST("video-virtio-gpu-virgl");
    DO_TEST("virtio-input");
    DO_TEST("virtio-input-passthrough");

    qemuTestDriverFree(&driver);

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
