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
# include "qemu/qemu_domain_address.h"
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

    virBitmapPtr activeVcpus;

    virQEMUCapsPtr qemuCaps;
};

static int
qemuXML2XMLActivePreFormatCallback(virDomainDefPtr def,
                                   const void *opaque)
{
    struct testInfo *info = (struct testInfo *) opaque;

    /* store vCPU bitmap so that the status XML can be created faithfully */
    if (!info->activeVcpus)
        info->activeVcpus = virDomainDefGetOnlineVcpumap(def);

    return 0;
}

static int
testXML2XMLActive(const void *opaque)
{
    const struct testInfo *info = opaque;

    return testCompareDomXML2XMLFiles(driver.caps, driver.xmlopt,
                                      info->inName, info->outActiveName, true,
                                      qemuXML2XMLActivePreFormatCallback,
                                      opaque, 0,
                                      TEST_COMPARE_DOM_XML2XML_RESULT_SUCCESS);
}


static int
testXML2XMLInactive(const void *opaque)
{
    const struct testInfo *info = opaque;

    return testCompareDomXML2XMLFiles(driver.caps, driver.xmlopt, info->inName,
                                      info->outInactiveName, false,
                                      NULL, opaque, 0,
                                      TEST_COMPARE_DOM_XML2XML_RESULT_SUCCESS);
}


static const char testStatusXMLPrefixHeader[] =
"<domstatus state='running' reason='booted' pid='3803518'>\n"
"  <taint flag='high-privileges'/>\n"
"  <monitor path='/var/lib/libvirt/qemu/test.monitor' json='1' type='unix'/>\n";

static const char testStatusXMLPrefixFooter[] =
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
"  <numad nodeset='0-2'/>\n"
"  <libDir path='/tmp'/>\n"
"  <channelTargetDir path='/tmp/channel'/>\n";

static const char testStatusXMLSuffix[] =
"</domstatus>\n";


static void
testGetStatuXMLPrefixVcpus(virBufferPtr buf,
                           const struct testInfo *data)
{
    ssize_t vcpuid = -1;

    virBufferAddLit(buf, "<vcpus>\n");
    virBufferAdjustIndent(buf, 2);

    /* Make sure we can format the fake vcpu list. The test will fail regardles. */
    if (data->activeVcpus) {
        while ((vcpuid = virBitmapNextSetBit(data->activeVcpus, vcpuid)) >= 0)
            virBufferAsprintf(buf, "<vcpu id='%zd' pid='%zd'/>\n",
                              vcpuid, vcpuid + 3803519);
    }

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</vcpus>\n");
}


static char *
testGetStatusXMLPrefix(const struct testInfo *data)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virBufferAdd(&buf, testStatusXMLPrefixHeader, -1);
    virBufferAdjustIndent(&buf, 2);

    testGetStatuXMLPrefixVcpus(&buf, data);

    virBufferAdjustIndent(&buf, -2);
    virBufferAdd(&buf, testStatusXMLPrefixFooter, -1);

    return virBufferContentAndReset(&buf);
}


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
    char *header = NULL;
    char *inFile = NULL, *outActiveFile = NULL;
    int ret = -1;
    int keepBlanksDefault = xmlKeepBlanksDefault(0);

    if (virTestLoadFile(data->inName, &inFile) < 0)
        goto cleanup;
    if (virTestLoadFile(data->outActiveName, &outActiveFile) < 0)
        goto cleanup;

    if (!(header = testGetStatusXMLPrefix(data)))
        goto cleanup;

    /* construct faked source status XML */
    virBufferAdd(&buf, header, -1);
    virBufferAdjustIndent(&buf, 2);
    virBufferAddStr(&buf, inFile);
    virBufferAdjustIndent(&buf, -2);
    virBufferAdd(&buf, testStatusXMLSuffix, -1);

    if (!(source = virBufferContentAndReset(&buf))) {
        VIR_TEST_DEBUG("Failed to create the source XML");
        goto cleanup;
    }

    /* construct the expect string */
    virBufferAdd(&buf, header, -1);
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

    /* format it back */
    if (!(actual = virDomainObjFormat(driver.xmlopt, obj, NULL,
                                      VIR_DOMAIN_DEF_FORMAT_SECURE))) {
        VIR_TEST_DEBUG("Failed to format domain status XML");
        goto cleanup;
    }

    if (STRNEQ(actual, expect)) {
        /* For status test we don't want to regenerate output to not
         * add the status data.*/
        virTestDifferenceFullNoRegenerate(stderr,
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
    VIR_FREE(header);
    VIR_FREE(outActiveFile);
    return ret;
}


static void
testInfoFree(struct testInfo *info)
{
    VIR_FREE(info->inName);
    VIR_FREE(info->outActiveName);
    VIR_FREE(info->outInactiveName);

    virBitmapFree(info->activeVcpus);
    info->activeVcpus = NULL;

    virObjectUnref(info->qemuCaps);
}


static int
testInfoSet(struct testInfo *info,
            const char *name,
            int when,
            int gic)
{
    if (!(info->qemuCaps = virQEMUCapsNew()))
        goto error;

    virQEMUCapsSetList(info->qemuCaps,
                       QEMU_CAPS_LAST);

    if (testQemuCapsSetGIC(info->qemuCaps, gic) < 0)
        goto error;

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
    virQEMUDriverConfigPtr cfg = NULL;

    memset(&info, 0, sizeof(info));

    if (qemuTestDriverInit(&driver) < 0)
        return EXIT_FAILURE;

    cfg = virQEMUDriverGetConfig(&driver);

    /* TODO: test with format probing disabled too */
    driver.config->allowDiskFormatProbing = true;

# define DO_TEST_FULL(name, when, gic, ...)                                    \
    do {                                                                       \
        if (testInfoSet(&info, name, when, gic) < 0) {                         \
            VIR_TEST_DEBUG("Failed to generate test data for '%s'", name);     \
            return -1;                                                         \
        }                                                                      \
        virQEMUCapsSetList(info.qemuCaps, __VA_ARGS__, QEMU_CAPS_LAST);        \
                                                                               \
        if (info.outInactiveName) {                                            \
            if (virTestRun("QEMU XML-2-XML-inactive " name,                    \
                            testXML2XMLInactive, &info) < 0)                   \
                ret = -1;                                                      \
        }                                                                      \
                                                                               \
        if (info.outActiveName) {                                              \
            if (virTestRun("QEMU XML-2-XML-active " name,                      \
                            testXML2XMLActive, &info) < 0)                     \
                ret = -1;                                                      \
                                                                               \
            if (virTestRun("QEMU XML-2-XML-status " name,                      \
                            testCompareStatusXMLToXMLFiles, &info) < 0)        \
                ret = -1;                                                      \
        }                                                                      \
        testInfoFree(&info);                                                   \
    } while (0)

# define NONE QEMU_CAPS_LAST

# define DO_TEST(name, ...) \
    DO_TEST_FULL(name, WHEN_BOTH, GIC_NONE, __VA_ARGS__)



    /* Unset or set all envvars here that are copied in qemudBuildCommandLine
     * using ADD_ENV_COPY, otherwise these tests may fail due to unexpected
     * values for these envvars */
    setenv("PATH", "/bin", 1);

    DO_TEST("minimal", NONE);
    DO_TEST("machine-core-on", NONE);
    DO_TEST("machine-core-off", NONE);
    DO_TEST("default-kvm-host-arch", NONE);
    DO_TEST("default-qemu-host-arch", NONE);
    DO_TEST("boot-cdrom", NONE);
    DO_TEST("boot-network", NONE);
    DO_TEST("boot-floppy", NONE);
    DO_TEST("boot-floppy-q35",
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI);
    DO_TEST("bootindex-floppy-q35",
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI, QEMU_CAPS_BOOT_MENU,
            QEMU_CAPS_BOOTINDEX);
    DO_TEST("boot-multi", NONE);
    DO_TEST("boot-menu-enable-with-timeout", NONE);
    DO_TEST("boot-menu-disable", NONE);
    DO_TEST("boot-menu-disable-with-timeout", NONE);
    DO_TEST("boot-order", NONE);

    DO_TEST("reboot-timeout-enabled", NONE);
    DO_TEST("reboot-timeout-disabled", NONE);

    DO_TEST("clock-utc", NONE);
    DO_TEST("clock-localtime", NONE);
    DO_TEST("cpu-empty", NONE);
    DO_TEST("cpu-kvmclock", NONE);
    DO_TEST("cpu-host-kvmclock", NONE);
    DO_TEST("cpu-host-passthrough-features", NONE);
    DO_TEST("cpu-host-model-features", NONE);
    DO_TEST("clock-catchup", NONE);
    DO_TEST("kvmclock", NONE);
    DO_TEST("clock-timer-hyperv-rtc", NONE);

    DO_TEST("cpu-eoi-disabled", NONE);
    DO_TEST("cpu-eoi-enabled", NONE);
    DO_TEST("eoi-disabled", NONE);
    DO_TEST("eoi-enabled", NONE);
    DO_TEST("pv-spinlock-disabled", NONE);
    DO_TEST("pv-spinlock-enabled", NONE);

    DO_TEST("hyperv", NONE);
    DO_TEST("hyperv-off", NONE);
    DO_TEST("hyperv-panic", NONE);

    DO_TEST("kvm-features", NONE);
    DO_TEST("kvm-features-off", NONE);

    DO_TEST("pmu-feature", NONE);
    DO_TEST("pmu-feature-off", NONE);

    DO_TEST("hugepages", NONE);
    DO_TEST("hugepages-pages", NONE);
    DO_TEST("hugepages-pages2", NONE);
    DO_TEST("hugepages-pages3", NONE);
    DO_TEST("hugepages-shared", NONE);
    DO_TEST("nosharepages", NONE);
    DO_TEST("restore-v2", NONE);
    DO_TEST("migrate", NONE);
    DO_TEST("qemu-ns-no-env", NONE);
    DO_TEST("disk-aio", NONE);
    DO_TEST("disk-cdrom", NONE);
    DO_TEST("disk-cdrom-empty", NONE);
    DO_TEST("disk-floppy", NONE);
    DO_TEST("disk-many", NONE);
    DO_TEST("disk-usb-device", NONE);
    DO_TEST("disk-virtio", NONE);
    DO_TEST("floppy-drive-fat", NONE);
    DO_TEST("disk-drive-boot-disk", NONE);
    DO_TEST("disk-drive-boot-cdrom", NONE);
    DO_TEST("disk-drive-error-policy-stop", NONE);
    DO_TEST("disk-drive-error-policy-enospace", NONE);
    DO_TEST("disk-drive-error-policy-wreport-rignore", NONE);
    DO_TEST("disk-drive-fmt-qcow", NONE);
    DO_TEST("disk-drive-copy-on-read", NONE);
    DO_TEST("disk-drive-cache-v2-wt", NONE);
    DO_TEST("disk-drive-cache-v2-wb", NONE);
    DO_TEST("disk-drive-cache-v2-none", NONE);
    DO_TEST("disk-drive-cache-directsync", NONE);
    DO_TEST("disk-drive-cache-unsafe", NONE);
    DO_TEST("disk-drive-network-nbd", NONE);
    DO_TEST("disk-drive-network-nbd-export", NONE);
    DO_TEST("disk-drive-network-nbd-ipv6", NONE);
    DO_TEST("disk-drive-network-nbd-ipv6-export", NONE);
    DO_TEST("disk-drive-network-nbd-unix", NONE);
    DO_TEST("disk-drive-network-iscsi", NONE);
    DO_TEST("disk-drive-network-iscsi-auth", NONE);
    DO_TEST("disk-drive-network-gluster", NONE);
    DO_TEST("disk-drive-network-rbd", NONE);
    DO_TEST("disk-drive-network-rbd-auth", NONE);
    DO_TEST("disk-drive-network-rbd-ipv6", NONE);
    DO_TEST("disk-drive-network-rbd-ceph-env", NONE);
    DO_TEST("disk-drive-network-sheepdog", NONE);
    DO_TEST("disk-scsi-device",
            QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_SCSI_LSI);
    DO_TEST("disk-scsi-vscsi", NONE);
    DO_TEST("disk-scsi-virtio-scsi",
            QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_VIRTIO_SCSI);
    DO_TEST("disk-virtio-scsi-num_queues",
            QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_VIRTIO_SCSI);
    DO_TEST("disk-virtio-scsi-cmd_per_lun",
            QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_VIRTIO_SCSI);
    DO_TEST("disk-virtio-scsi-max_sectors",
            QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_VIRTIO_SCSI);
    DO_TEST("disk-virtio-scsi-ioeventfd",
            QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_VIRTIO_SCSI);
    DO_TEST("disk-scsi-megasas",
            QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_SCSI_MEGASAS);
    DO_TEST("disk-scsi-mptsas1068",
            QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_SCSI_MPTSAS1068,
            QEMU_CAPS_SCSI_DISK_WWN);
    DO_TEST("disk-mirror-old", NONE);
    DO_TEST("disk-mirror", NONE);
    DO_TEST_FULL("disk-active-commit", WHEN_ACTIVE, GIC_NONE, NONE);
    DO_TEST("graphics-listen-network", NONE);
    DO_TEST("graphics-vnc", NONE);
    DO_TEST("graphics-vnc-websocket", NONE);
    DO_TEST("graphics-vnc-sasl", NONE);
    DO_TEST("graphics-vnc-tls", NONE);
    DO_TEST("graphics-vnc-no-listen-attr", NONE);
    DO_TEST("graphics-vnc-remove-generated-socket", NONE);
    cfg->vncAutoUnixSocket = true;
    DO_TEST("graphics-vnc-auto-socket-cfg", NONE);
    cfg->vncAutoUnixSocket = false;
    DO_TEST("graphics-vnc-socket", NONE);
    DO_TEST("graphics-vnc-auto-socket", NONE);

    DO_TEST("graphics-sdl", NONE);
    DO_TEST("graphics-sdl-fullscreen", NONE);
    DO_TEST("graphics-spice", NONE);
    DO_TEST("graphics-spice-compression", NONE);
    DO_TEST("graphics-spice-qxl-vga", NONE);
    DO_TEST("graphics-spice-socket", NONE);
    DO_TEST("graphics-spice-auto-socket", NONE);
    cfg->spiceAutoUnixSocket = true;
    DO_TEST("graphics-spice-auto-socket-cfg", NONE);
    cfg->spiceAutoUnixSocket = false;

    DO_TEST("nographics-vga",
            QEMU_CAPS_DISPLAY);
    DO_TEST("input-usbmouse", NONE);
    DO_TEST("input-usbtablet", NONE);
    DO_TEST("misc-acpi", NONE);
    DO_TEST("misc-disable-s3", NONE);
    DO_TEST("misc-disable-suspends", NONE);
    DO_TEST("misc-enable-s4", NONE);
    DO_TEST("misc-no-reboot", NONE);
    DO_TEST("misc-uuid", NONE);
    DO_TEST("net-vhostuser", NONE);
    DO_TEST("net-user", NONE);
    DO_TEST("net-virtio", NONE);
    DO_TEST("net-virtio-device", NONE);
    DO_TEST("net-virtio-disable-offloads", NONE);
    DO_TEST("net-eth", NONE);
    DO_TEST("net-eth-ifname", NONE);
    DO_TEST("net-eth-hostip", NONE);
    DO_TEST("net-virtio-network-portgroup", NONE);
    DO_TEST("net-virtio-rxqueuesize", NONE);
    DO_TEST("net-hostdev", NONE);
    DO_TEST("net-hostdev-vfio", NONE);
    DO_TEST("net-midonet", NONE);
    DO_TEST("net-openvswitch", NONE);
    DO_TEST("sound", NONE);
    DO_TEST("sound-device", NONE);
    DO_TEST("watchdog", NONE);
    DO_TEST("net-bandwidth", NONE);
    DO_TEST("net-bandwidth2", NONE);
    DO_TEST("net-mtu", NONE);

    DO_TEST("serial-vc", NONE);
    DO_TEST("serial-pty", NONE);
    DO_TEST("serial-dev", NONE);
    DO_TEST("serial-file", NONE);
    DO_TEST("serial-unix", NONE);
    DO_TEST("serial-tcp", NONE);
    DO_TEST("serial-udp", NONE);
    DO_TEST("serial-tcp-telnet", NONE);
    DO_TEST("serial-tcp-tlsx509-chardev", NONE);
    DO_TEST("serial-tcp-tlsx509-chardev-notls", NONE);
    DO_TEST("serial-many", NONE);
    DO_TEST("serial-spiceport", NONE);
    DO_TEST("serial-spiceport-nospice", NONE);
    DO_TEST("parallel-tcp", NONE);
    DO_TEST("console-compat", NONE);
    DO_TEST("console-compat2", NONE);
    DO_TEST("console-virtio-many", NONE);
    DO_TEST("channel-guestfwd", NONE);
    DO_TEST("channel-virtio", NONE);
    DO_TEST("channel-virtio-state", NONE);

    DO_TEST("hostdev-usb-address", NONE);
    DO_TEST("hostdev-pci-address", NONE);
    DO_TEST("hostdev-vfio", NONE);
    DO_TEST("pci-rom", NONE);
    DO_TEST("pci-serial-dev-chardev", NONE);

    DO_TEST("encrypted-disk", NONE);
    DO_TEST("encrypted-disk-usage", NONE);
    DO_TEST("luks-disks", NONE);
    DO_TEST("memtune", NONE);
    DO_TEST("memtune-unlimited", NONE);
    DO_TEST("blkiotune", NONE);
    DO_TEST("blkiotune-device", NONE);
    DO_TEST("cputune", NONE);
    DO_TEST("cputune-zero-shares", NONE);
    DO_TEST("cputune-iothreadsched", NONE);
    DO_TEST("cputune-iothreadsched-zeropriority", NONE);
    DO_TEST("cputune-numatune", NONE);
    DO_TEST("vcpu-placement-static",
            QEMU_CAPS_KVM,
            QEMU_CAPS_OBJECT_IOTHREAD);

    DO_TEST("smp", NONE);
    DO_TEST("iothreads", NONE);
    DO_TEST("iothreads-ids", NONE);
    DO_TEST("iothreads-ids-partial", NONE);
    DO_TEST("cputune-iothreads", NONE);
    DO_TEST("iothreads-disk", NONE);
    DO_TEST("iothreads-disk-virtio-ccw",
            QEMU_CAPS_VIRTIO_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST("iothreads-virtio-scsi-pci",
            QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_VIRTIO_SCSI);
    DO_TEST("iothreads-virtio-scsi-ccw",
            QEMU_CAPS_VIRTIO_SCSI, QEMU_CAPS_VIRTIO_CCW,
            QEMU_CAPS_VIRTIO_S390);
    DO_TEST("lease", NONE);
    DO_TEST("event_idx", NONE);
    DO_TEST("vhost_queues", NONE);
    DO_TEST("interface-driver", NONE);
    DO_TEST("interface-server", NONE);
    DO_TEST("virtio-lun", NONE);

    DO_TEST("usb-none", NONE);
    DO_TEST("usb-controller", NONE);
    DO_TEST("usb-piix3-controller",
            QEMU_CAPS_PIIX3_USB_UHCI);
    DO_TEST("usb-controller-default-q35",
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_PCI_OHCI,
            QEMU_CAPS_PIIX3_USB_UHCI,
            QEMU_CAPS_NEC_USB_XHCI);
    DO_TEST("usb-controller-explicit-q35",
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_PCI_OHCI,
            QEMU_CAPS_PIIX3_USB_UHCI,
            QEMU_CAPS_NEC_USB_XHCI);
    DO_TEST("ppc64-usb-controller",
            QEMU_CAPS_PCI_OHCI);
    DO_TEST("ppc64-usb-controller-legacy",
            QEMU_CAPS_PIIX3_USB_UHCI);
    DO_TEST("usb-port-missing", NONE);
    DO_TEST("usb-redir", NONE);
    DO_TEST("usb-redir-filter", NONE);
    DO_TEST("usb-redir-filter-version", NONE);
    DO_TEST("blkdeviotune", NONE);
    DO_TEST("blkdeviotune-max", NONE);
    DO_TEST("blkdeviotune-group-num", NONE);
    DO_TEST("blkdeviotune-max-length", NONE);
    DO_TEST("controller-usb-order", NONE);

    DO_TEST_FULL("seclabel-dynamic-baselabel", WHEN_INACTIVE, GIC_NONE, NONE);
    DO_TEST_FULL("seclabel-dynamic-override", WHEN_INACTIVE, GIC_NONE, NONE);
    DO_TEST_FULL("seclabel-dynamic-labelskip", WHEN_INACTIVE, GIC_NONE, NONE);
    DO_TEST_FULL("seclabel-dynamic-relabel", WHEN_INACTIVE, GIC_NONE, NONE);
    DO_TEST("seclabel-static", NONE);
    DO_TEST_FULL("seclabel-static-labelskip", WHEN_ACTIVE, GIC_NONE, NONE);
    DO_TEST("seclabel-none", NONE);
    DO_TEST("seclabel-dac-none", NONE);
    DO_TEST("seclabel-dynamic-none", NONE);
    DO_TEST("seclabel-device-multiple", NONE);
    DO_TEST_FULL("seclabel-dynamic-none-relabel", WHEN_INACTIVE, GIC_NONE, NONE);
    DO_TEST("numad-static-vcpu-no-numatune", NONE);

    DO_TEST("disk-scsi-lun-passthrough-sgio",
            QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_SCSI_CD, QEMU_CAPS_SCSI_LSI,
            QEMU_CAPS_VIRTIO_SCSI, QEMU_CAPS_SCSI_DISK_WWN);
    DO_TEST("disk-scsi-disk-vpd",
            QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_SCSI_CD, QEMU_CAPS_SCSI_LSI,
            QEMU_CAPS_VIRTIO_SCSI, QEMU_CAPS_SCSI_DISK_WWN);
    DO_TEST("disk-source-pool", NONE);
    DO_TEST("disk-source-pool-mode", NONE);

    DO_TEST("disk-drive-discard", NONE);
    DO_TEST("disk-drive-detect-zeroes", NONE);

    DO_TEST("virtio-rng-random", NONE);
    DO_TEST("virtio-rng-egd", NONE);

    DO_TEST("pseries-nvram", NONE);
    DO_TEST("pseries-panic-missing", NONE);
    DO_TEST("pseries-panic-no-address", NONE);

    DO_TEST("balloon-device-auto", NONE);
    DO_TEST("balloon-device-period", NONE);
    DO_TEST("channel-virtio-auto", NONE);
    DO_TEST("console-compat-auto", NONE);
    DO_TEST("disk-scsi-device-auto",
            QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_SCSI_LSI);
    DO_TEST("console-virtio", NONE);
    DO_TEST("serial-target-port-auto", NONE);
    DO_TEST("graphics-listen-network2", NONE);
    DO_TEST("graphics-spice-timeout", NONE);
    DO_TEST("numad-auto-vcpu-no-numatune", NONE);
    DO_TEST("numad-auto-memory-vcpu-no-cpuset-and-placement", NONE);
    DO_TEST("numad-auto-memory-vcpu-cpuset", NONE);
    DO_TEST("usb-ich9-ehci-addr", NONE);
    DO_TEST("disk-copy_on_read", NONE);
    DO_TEST("tpm-passthrough", NONE);

    DO_TEST("metadata", NONE);
    DO_TEST("metadata-duplicate", NONE);

    DO_TEST("pci-bridge",
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_VNC,
            QEMU_CAPS_DEVICE_CIRRUS_VGA);
    DO_TEST("pci-many",
            QEMU_CAPS_DEVICE_CIRRUS_VGA);
    DO_TEST("pci-bridge-many-disks",
            QEMU_CAPS_DEVICE_PCI_BRIDGE);
    DO_TEST("pci-autoadd-addr",
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_CIRRUS_VGA);
    DO_TEST("pci-autoadd-idx",
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_CIRRUS_VGA);
    DO_TEST("pci-autofill-addr", NONE);

    DO_TEST("q35",
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_PCI_MULTIFUNCTION,
            QEMU_CAPS_ICH9_USB_EHCI1,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_DEVICE_QXL);
    DO_TEST("q35-usb2",
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_PCI_MULTIFUNCTION,
            QEMU_CAPS_ICH9_USB_EHCI1,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_DEVICE_QXL);
    DO_TEST("q35-usb2-multi",
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_PCI_MULTIFUNCTION,
            QEMU_CAPS_ICH9_USB_EHCI1,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_DEVICE_QXL);
    DO_TEST("q35-usb2-reorder",
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_PCI_MULTIFUNCTION,
            QEMU_CAPS_ICH9_USB_EHCI1,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_DEVICE_QXL);
    DO_TEST("q35-pcie",
            QEMU_CAPS_VIRTIO_PCI_DISABLE_LEGACY,
            QEMU_CAPS_DEVICE_VIRTIO_RNG,
            QEMU_CAPS_OBJECT_RNG_RANDOM,
            QEMU_CAPS_NETDEV,
            QEMU_CAPS_DEVICE_VIRTIO_NET,
            QEMU_CAPS_DEVICE_VIRTIO_GPU,
            QEMU_CAPS_VIRTIO_GPU_VIRGL,
            QEMU_CAPS_VIRTIO_KEYBOARD,
            QEMU_CAPS_VIRTIO_MOUSE,
            QEMU_CAPS_VIRTIO_TABLET,
            QEMU_CAPS_VIRTIO_INPUT_HOST,
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_FSDEV,
            QEMU_CAPS_FSDEV_WRITEOUT,
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_PCI_MULTIFUNCTION,
            QEMU_CAPS_ICH9_USB_EHCI1,
            QEMU_CAPS_NEC_USB_XHCI,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY);
    /* same XML as q35-pcie, but don't set
       QEMU_CAPS_VIRTIO_PCI_DISABLE_LEGACY */
    DO_TEST("q35-virtio-pci",
            QEMU_CAPS_DEVICE_VIRTIO_RNG,
            QEMU_CAPS_OBJECT_RNG_RANDOM,
            QEMU_CAPS_NETDEV,
            QEMU_CAPS_DEVICE_VIRTIO_NET,
            QEMU_CAPS_DEVICE_VIRTIO_GPU,
            QEMU_CAPS_VIRTIO_GPU_VIRGL,
            QEMU_CAPS_VIRTIO_KEYBOARD,
            QEMU_CAPS_VIRTIO_MOUSE,
            QEMU_CAPS_VIRTIO_TABLET,
            QEMU_CAPS_VIRTIO_INPUT_HOST,
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_FSDEV,
            QEMU_CAPS_FSDEV_WRITEOUT,
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_PCI_MULTIFUNCTION,
            QEMU_CAPS_ICH9_USB_EHCI1,
            QEMU_CAPS_NEC_USB_XHCI,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY);
    /* same as q35-pcie, but all PCI controllers are added automatically */
    DO_TEST("q35-pcie-autoadd",
            QEMU_CAPS_VIRTIO_PCI_DISABLE_LEGACY,
            QEMU_CAPS_DEVICE_VIRTIO_RNG,
            QEMU_CAPS_OBJECT_RNG_RANDOM,
            QEMU_CAPS_NETDEV,
            QEMU_CAPS_DEVICE_VIRTIO_NET,
            QEMU_CAPS_DEVICE_VIRTIO_GPU,
            QEMU_CAPS_VIRTIO_GPU_VIRGL,
            QEMU_CAPS_VIRTIO_KEYBOARD,
            QEMU_CAPS_VIRTIO_MOUSE,
            QEMU_CAPS_VIRTIO_TABLET,
            QEMU_CAPS_VIRTIO_INPUT_HOST,
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_FSDEV,
            QEMU_CAPS_FSDEV_WRITEOUT,
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_PCI_MULTIFUNCTION,
            QEMU_CAPS_ICH9_USB_EHCI1,
            QEMU_CAPS_NEC_USB_XHCI,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY);
    DO_TEST("q35-default-devices-only",
            QEMU_CAPS_VIRTIO_PCI_DISABLE_LEGACY,
            QEMU_CAPS_DEVICE_VIRTIO_RNG,
            QEMU_CAPS_OBJECT_RNG_RANDOM,
            QEMU_CAPS_NETDEV,
            QEMU_CAPS_DEVICE_VIRTIO_NET,
            QEMU_CAPS_DEVICE_VIRTIO_GPU,
            QEMU_CAPS_VIRTIO_GPU_VIRGL,
            QEMU_CAPS_VIRTIO_KEYBOARD,
            QEMU_CAPS_VIRTIO_MOUSE,
            QEMU_CAPS_VIRTIO_TABLET,
            QEMU_CAPS_VIRTIO_INPUT_HOST,
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_FSDEV,
            QEMU_CAPS_FSDEV_WRITEOUT,
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_PCI_MULTIFUNCTION,
            QEMU_CAPS_ICH9_USB_EHCI1,
            QEMU_CAPS_NEC_USB_XHCI,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY);
    DO_TEST("q35-multifunction",
            QEMU_CAPS_VIRTIO_PCI_DISABLE_LEGACY,
            QEMU_CAPS_DEVICE_VIRTIO_RNG,
            QEMU_CAPS_OBJECT_RNG_RANDOM,
            QEMU_CAPS_NETDEV,
            QEMU_CAPS_DEVICE_VIRTIO_NET,
            QEMU_CAPS_DEVICE_VIRTIO_GPU,
            QEMU_CAPS_VIRTIO_GPU_VIRGL,
            QEMU_CAPS_VIRTIO_KEYBOARD,
            QEMU_CAPS_VIRTIO_MOUSE,
            QEMU_CAPS_VIRTIO_TABLET,
            QEMU_CAPS_VIRTIO_INPUT_HOST,
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_FSDEV,
            QEMU_CAPS_FSDEV_WRITEOUT,
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_PCI_MULTIFUNCTION,
            QEMU_CAPS_ICH9_USB_EHCI1,
            QEMU_CAPS_NEC_USB_XHCI,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY);
    DO_TEST("q35-virt-manager-basic",
            QEMU_CAPS_KVM,
            QEMU_CAPS_RTC,
            QEMU_CAPS_NO_KVM_PIT,
            QEMU_CAPS_ICH9_DISABLE_S3,
            QEMU_CAPS_ICH9_DISABLE_S4,
            QEMU_CAPS_VIRTIO_PCI_DISABLE_LEGACY,
            QEMU_CAPS_DEVICE_VIRTIO_RNG,
            QEMU_CAPS_OBJECT_RNG_RANDOM,
            QEMU_CAPS_NETDEV,
            QEMU_CAPS_DEVICE_VIRTIO_NET,
            QEMU_CAPS_DEVICE_VIRTIO_GPU,
            QEMU_CAPS_VIRTIO_GPU_VIRGL,
            QEMU_CAPS_VIRTIO_KEYBOARD,
            QEMU_CAPS_VIRTIO_MOUSE,
            QEMU_CAPS_VIRTIO_TABLET,
            QEMU_CAPS_VIRTIO_INPUT_HOST,
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_FSDEV,
            QEMU_CAPS_FSDEV_WRITEOUT,
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_PCI_MULTIFUNCTION,
            QEMU_CAPS_ICH9_USB_EHCI1,
            QEMU_CAPS_NEC_USB_XHCI,
            QEMU_CAPS_DEVICE_ICH9_INTEL_HDA,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_SPICE,
            QEMU_CAPS_CHARDEV_SPICEVMC,
            QEMU_CAPS_DEVICE_QXL,
            QEMU_CAPS_HDA_DUPLEX,
            QEMU_CAPS_USB_REDIR);
    DO_TEST("pcie-root",
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_DEVICE_QXL);
    DO_TEST("pcie-root-port",
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_PCI_MULTIFUNCTION,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_DEVICE_QXL);
    DO_TEST("pcie-switch-upstream-port",
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_DEVICE_X3130_UPSTREAM,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_PCI_MULTIFUNCTION,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_DEVICE_QXL);
    DO_TEST("pcie-switch-downstream-port",
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_DEVICE_X3130_UPSTREAM,
            QEMU_CAPS_DEVICE_XIO3130_DOWNSTREAM,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_DEVICE_QXL);
    DO_TEST("pci-expander-bus",
            QEMU_CAPS_DEVICE_PXB);
    DO_TEST("pcie-expander-bus",
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_DEVICE_X3130_UPSTREAM,
            QEMU_CAPS_DEVICE_XIO3130_DOWNSTREAM,
            QEMU_CAPS_DEVICE_PXB_PCIE);
    DO_TEST("autoindex",
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_DEVICE_X3130_UPSTREAM,
            QEMU_CAPS_DEVICE_XIO3130_DOWNSTREAM,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_PCI_MULTIFUNCTION,
            QEMU_CAPS_ICH9_USB_EHCI1,
            QEMU_CAPS_NEC_USB_XHCI);
    /* Make sure the user can always override libvirt's default device
     * placement policy by providing an explicit PCI address */
    DO_TEST("q35-pci-force-address",
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_HDA_DUPLEX);

    DO_TEST("hostdev-scsi-vhost-scsi-ccw",
            QEMU_CAPS_VIRTIO_SCSI, QEMU_CAPS_DEVICE_VHOST_SCSI,
            QEMU_CAPS_DEVICE_SCSI_GENERIC, QEMU_CAPS_VIRTIO_CCW);
    DO_TEST("hostdev-scsi-vhost-scsi-pci",
            QEMU_CAPS_VIRTIO_SCSI, QEMU_CAPS_DEVICE_VHOST_SCSI,
            QEMU_CAPS_DEVICE_SCSI_GENERIC);
    DO_TEST("hostdev-scsi-lsi",
            QEMU_CAPS_VIRTIO_SCSI, QEMU_CAPS_SCSI_LSI,
            QEMU_CAPS_DEVICE_SCSI_GENERIC);
    DO_TEST("hostdev-scsi-virtio-scsi",
            QEMU_CAPS_VIRTIO_SCSI, QEMU_CAPS_SCSI_LSI,
            QEMU_CAPS_DEVICE_SCSI_GENERIC);
    DO_TEST("hostdev-scsi-readonly",
            QEMU_CAPS_VIRTIO_SCSI, QEMU_CAPS_SCSI_LSI,
            QEMU_CAPS_DEVICE_SCSI_GENERIC);

    DO_TEST("hostdev-scsi-shareable",
            QEMU_CAPS_VIRTIO_SCSI, QEMU_CAPS_SCSI_LSI,
            QEMU_CAPS_DEVICE_SCSI_GENERIC);
    DO_TEST("hostdev-scsi-sgio",
            QEMU_CAPS_VIRTIO_SCSI, QEMU_CAPS_SCSI_LSI,
            QEMU_CAPS_DEVICE_SCSI_GENERIC);
    DO_TEST("hostdev-scsi-rawio",
            QEMU_CAPS_VIRTIO_SCSI, QEMU_CAPS_SCSI_LSI,
            QEMU_CAPS_DEVICE_SCSI_GENERIC);

    DO_TEST("hostdev-scsi-autogen-address",
            QEMU_CAPS_VIRTIO_SCSI, QEMU_CAPS_SCSI_LSI,
            QEMU_CAPS_DEVICE_SCSI_GENERIC);
    DO_TEST("hostdev-scsi-large-unit",
            QEMU_CAPS_VIRTIO_SCSI, QEMU_CAPS_SCSI_LSI,
            QEMU_CAPS_DEVICE_SCSI_GENERIC);

    DO_TEST("hostdev-scsi-lsi-iscsi",
            QEMU_CAPS_VIRTIO_SCSI, QEMU_CAPS_SCSI_LSI,
            QEMU_CAPS_DEVICE_SCSI_GENERIC);
    DO_TEST("hostdev-scsi-lsi-iscsi-auth",
            QEMU_CAPS_VIRTIO_SCSI, QEMU_CAPS_SCSI_LSI,
            QEMU_CAPS_DEVICE_SCSI_GENERIC);
    DO_TEST("hostdev-scsi-virtio-iscsi",
            QEMU_CAPS_VIRTIO_SCSI, QEMU_CAPS_SCSI_LSI,
            QEMU_CAPS_DEVICE_SCSI_GENERIC);
    DO_TEST("hostdev-scsi-virtio-iscsi-auth",
            QEMU_CAPS_VIRTIO_SCSI, QEMU_CAPS_SCSI_LSI,
            QEMU_CAPS_DEVICE_SCSI_GENERIC);

    DO_TEST("s390-defaultconsole",
            QEMU_CAPS_VIRTIO_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST("s390-panic",
            QEMU_CAPS_VIRTIO_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST("s390-panic-missing",
            QEMU_CAPS_VIRTIO_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST("s390-panic-no-address",
            QEMU_CAPS_VIRTIO_CCW, QEMU_CAPS_VIRTIO_S390);

    DO_TEST("pcihole64", NONE);
    DO_TEST("pcihole64-gib", NONE);
    DO_TEST("pcihole64-none", NONE);
    DO_TEST("pcihole64-q35",
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_DEVICE_QXL,
            QEMU_CAPS_Q35_PCI_HOLE64_SIZE);

    DO_TEST("panic", NONE);
    DO_TEST("panic-isa", NONE);
    DO_TEST("panic-pseries", NONE);
    DO_TEST("panic-double", NONE);
    DO_TEST("panic-no-address", NONE);

    DO_TEST("disk-backing-chains", NONE);

    DO_TEST("chardev-label", NONE);

    DO_TEST("cpu-numa1", NONE);
    DO_TEST("cpu-numa2", NONE);
    DO_TEST("cpu-numa-no-memory-element", NONE);
    DO_TEST("cpu-numa-disordered", NONE);
    DO_TEST("cpu-numa-disjoint", NONE);
    DO_TEST("cpu-numa-memshared", NONE);

    DO_TEST("numatune-auto-prefer", NONE);
    DO_TEST("numatune-memnode", NONE);
    DO_TEST("numatune-memnode-no-memory", NONE);

    DO_TEST("bios-nvram", NONE);
    DO_TEST("bios-nvram-os-interleave", NONE);

    DO_TEST("tap-vhost", NONE);
    DO_TEST("tap-vhost-incorrect", NONE);
    DO_TEST("shmem", NONE);
    DO_TEST("shmem-plain-doorbell", NONE);
    DO_TEST("smbios", NONE);
    DO_TEST("smbios-multiple-type2", NONE);

    DO_TEST("aarch64-aavmf-virtio-mmio",
            QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_DTB,
            QEMU_CAPS_DEVICE_VIRTIO_MMIO,
            QEMU_CAPS_DEVICE_VIRTIO_RNG, QEMU_CAPS_OBJECT_RNG_RANDOM);
    DO_TEST("aarch64-virtio-pci-default",
            QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_DTB,
            QEMU_CAPS_VIRTIO_PCI_DISABLE_LEGACY,
            QEMU_CAPS_DEVICE_VIRTIO_MMIO,
            QEMU_CAPS_DEVICE_VIRTIO_RNG, QEMU_CAPS_OBJECT_RNG_RANDOM,
            QEMU_CAPS_OBJECT_GPEX, QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_PCI_MULTIFUNCTION,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_VIRTIO_SCSI);
    DO_TEST("aarch64-virtio-pci-manual-addresses",
            QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_DTB,
            QEMU_CAPS_DEVICE_VIRTIO_MMIO,
            QEMU_CAPS_DEVICE_VIRTIO_RNG, QEMU_CAPS_OBJECT_RNG_RANDOM,
            QEMU_CAPS_OBJECT_GPEX, QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_PCI_MULTIFUNCTION,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_VIRTIO_SCSI);
    DO_TEST("aarch64-video-virtio-gpu-pci",
            QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_OBJECT_GPEX,
            QEMU_CAPS_DEVICE_PCI_BRIDGE, QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_PCI_MULTIFUNCTION, QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_DEVICE_VIRTIO_GPU, QEMU_CAPS_BOOTINDEX);

    DO_TEST_FULL("aarch64-gic-none", WHEN_BOTH, GIC_NONE, NONE);
    DO_TEST_FULL("aarch64-gic-none-v2", WHEN_BOTH, GIC_V2, NONE);
    DO_TEST_FULL("aarch64-gic-none-v3", WHEN_BOTH, GIC_V3, NONE);
    DO_TEST_FULL("aarch64-gic-none-both", WHEN_BOTH, GIC_BOTH, NONE);
    DO_TEST_FULL("aarch64-gic-default", WHEN_BOTH, GIC_NONE, NONE);
    DO_TEST_FULL("aarch64-gic-default", WHEN_BOTH, GIC_V2, NONE);
    DO_TEST_FULL("aarch64-gic-default", WHEN_BOTH, GIC_V3, NONE);
    DO_TEST_FULL("aarch64-gic-default", WHEN_BOTH, GIC_BOTH, NONE);
    DO_TEST_FULL("aarch64-gic-v2", WHEN_BOTH, GIC_NONE, NONE);
    DO_TEST_FULL("aarch64-gic-v2", WHEN_BOTH, GIC_V2, NONE);
    DO_TEST_FULL("aarch64-gic-v2", WHEN_BOTH, GIC_V3, NONE);
    DO_TEST_FULL("aarch64-gic-v2", WHEN_BOTH, GIC_BOTH, NONE);
    DO_TEST_FULL("aarch64-gic-v3", WHEN_BOTH, GIC_NONE, NONE);
    DO_TEST_FULL("aarch64-gic-v3", WHEN_BOTH, GIC_V2, NONE);
    DO_TEST_FULL("aarch64-gic-v3", WHEN_BOTH, GIC_V3, NONE);
    DO_TEST_FULL("aarch64-gic-v3", WHEN_BOTH, GIC_BOTH, NONE);
    DO_TEST_FULL("aarch64-gic-host", WHEN_BOTH, GIC_NONE, NONE);
    DO_TEST_FULL("aarch64-gic-host", WHEN_BOTH, GIC_V2, NONE);
    DO_TEST_FULL("aarch64-gic-host", WHEN_BOTH, GIC_V3, NONE);
    DO_TEST_FULL("aarch64-gic-host", WHEN_BOTH, GIC_BOTH, NONE);

    DO_TEST("memory-hotplug", NONE);
    DO_TEST("memory-hotplug-nonuma", NONE);
    DO_TEST("memory-hotplug-dimm", NONE);
    DO_TEST("memory-hotplug-nvdimm", NONE);
    DO_TEST("net-udp", NONE);

    DO_TEST("video-virtio-gpu-device", NONE);
    DO_TEST("video-virtio-gpu-virgl", NONE);
    DO_TEST("video-virtio-gpu-spice-gl", NONE);
    DO_TEST("virtio-input", NONE);
    DO_TEST("virtio-input-passthrough", NONE);

    DO_TEST("memorybacking-set", NONE);
    DO_TEST("memorybacking-unset", NONE);

    virObjectUnref(cfg);

    DO_TEST("acpi-table", NONE);

    DO_TEST("video-device-pciaddr-default",
            QEMU_CAPS_KVM,
            QEMU_CAPS_VNC,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_DEVICE_QXL);
    DO_TEST("video-qxl-heads", NONE);
    DO_TEST("video-qxl-noheads", NONE);
    DO_TEST("video-virtio-gpu-secondary", NONE);

    DO_TEST("intel-iommu",
            QEMU_CAPS_DEVICE_INTEL_IOMMU);
    DO_TEST("intel-iommu-machine",
            QEMU_CAPS_MACHINE_OPT,
            QEMU_CAPS_MACHINE_IOMMU);

    qemuTestDriverFree(&driver);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN_PRELOAD(mymain, abs_builddir "/.libs/qemuxml2xmlmock.so")

#else

int
main(void)
{
    return EXIT_AM_SKIP;
}

#endif /* WITH_QEMU */
