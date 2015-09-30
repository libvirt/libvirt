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
    char *inFile;

    char *outActiveName;
    char *outActiveFile;

    char *outInactiveName;
    char *outInactiveFile;
};

static int
testXML2XMLHelper(const char *inxml,
                  const char *inXmlData,
                  const char *outxml,
                  const char *outXmlData,
                  bool live)
{
    char *actual = NULL;
    int ret = -1;
    virDomainDefPtr def = NULL;
    unsigned int parse_flags = live ? 0 : VIR_DOMAIN_DEF_PARSE_INACTIVE;
    unsigned int format_flags = VIR_DOMAIN_DEF_FORMAT_SECURE;
    if (!live)
        format_flags |= VIR_DOMAIN_DEF_FORMAT_INACTIVE;

    if (!(def = virDomainDefParseString(inXmlData, driver.caps, driver.xmlopt,
                                        parse_flags)))
        goto fail;

    if (!virDomainDefCheckABIStability(def, def)) {
        fprintf(stderr, "ABI stability check failed on %s", inxml);
        goto fail;
    }

    if (!(actual = virDomainDefFormat(def, format_flags)))
        goto fail;

    if (STRNEQ(outXmlData, actual)) {
        virtTestDifferenceFull(stderr, outXmlData, outxml, actual, inxml);
        goto fail;
    }

    ret = 0;

 fail:
    VIR_FREE(actual);
    virDomainDefFree(def);
    return ret;
}


static int
testXML2XMLActive(const void *opaque)
{
    const struct testInfo *info = opaque;

    return testXML2XMLHelper(info->inName,
                             info->inFile,
                             info->outActiveName,
                             info->outActiveFile,
                             true);
}


static int
testXML2XMLInactive(const void *opaque)
{
    const struct testInfo *info = opaque;

    return testXML2XMLHelper(info->inName,
                             info->inFile,
                             info->outInactiveName,
                             info->outInactiveFile,
                             false);
}


static const char testStatusXMLPrefix[] =
"<domstatus state='running' reason='booted' pid='3803518'>\n"
"  <taint flag='high-privileges'/>\n"
"  <monitor path='/var/lib/libvirt/qemu/test.monitor' json='1' type='unix'/>\n"
"  <vcpus>\n"
"    <vcpu pid='3803519'/>\n"
"  </vcpus>\n"
"  <qemuCaps>\n"
"    <flag name='vnc-colon'/>\n"
"    <flag name='no-reboot'/>\n"
"    <flag name='drive'/>\n"
"    <flag name='name'/>\n"
"    <flag name='uuid'/>\n"
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
    int ret = -1;
    int keepBlanksDefault = xmlKeepBlanksDefault(0);

    /* construct faked source status XML */
    virBufferAdd(&buf, testStatusXMLPrefix, -1);
    virBufferAdjustIndent(&buf, 2);
    virBufferAddStr(&buf, data->inFile);
    virBufferAdjustIndent(&buf, -2);
    virBufferAdd(&buf, testStatusXMLSuffix, -1);

    if (!(source = virBufferContentAndReset(&buf))) {
        fprintf(stderr, "Failed to create the source XML");
        goto cleanup;
    }

    /* construct the expect string */
    virBufferAdd(&buf, testStatusXMLPrefix, -1);
    virBufferAdjustIndent(&buf, 2);
    virBufferAddStr(&buf, data->outActiveFile);
    virBufferAdjustIndent(&buf, -2);
    virBufferAdd(&buf, testStatusXMLSuffix, -1);

    if (!(expect = virBufferContentAndReset(&buf))) {
        fprintf(stderr, "Failed to create the expect XML");
        goto cleanup;
    }

    /* parse the fake source status XML */
    if (!(xml = virXMLParseString(source, "(domain_status_test_XML)")) ||
        !(obj = virDomainObjParseNode(xml, xmlDocGetRootElement(xml),
                                      driver.caps, driver.xmlopt,
                                      VIR_DOMAIN_DEF_PARSE_STATUS |
                                      VIR_DOMAIN_DEF_PARSE_ACTUAL_NET |
                                      VIR_DOMAIN_DEF_PARSE_PCI_ORIG_STATES))) {
        fprintf(stderr, "Failed to parse domain status XML:\n%s", source);
        goto cleanup;
    }

    /* format it back */
    if (!(actual = virDomainObjFormat(driver.xmlopt, obj,
                                      VIR_DOMAIN_DEF_FORMAT_SECURE))) {
        fprintf(stderr, "Failed to format domain status XML");
        goto cleanup;
    }

    if (STRNEQ(actual, expect)) {
        virtTestDifferenceFull(stderr,
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
    return ret;
}


static void
testInfoFree(struct testInfo *info)
{
    VIR_FREE(info->inName);
    VIR_FREE(info->inFile);

    VIR_FREE(info->outActiveName);
    VIR_FREE(info->outActiveFile);

    VIR_FREE(info->outInactiveName);
    VIR_FREE(info->outInactiveFile);
}


static int
testInfoSet(struct testInfo *info,
            const char *name,
            bool different,
            int when)
{
    if (virAsprintf(&info->inName, "%s/qemuxml2argvdata/qemuxml2argv-%s.xml",
                    abs_srcdir, name) < 0)
        goto error;

    if (virtTestLoadFile(info->inName, &info->inFile) < 0)
        goto error;

    if (when & WHEN_INACTIVE) {
        if (different) {
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
        } else {
            if (VIR_STRDUP(info->outInactiveName, info->inName) < 0)
                goto error;
        }

        if (virtTestLoadFile(info->outInactiveName, &info->outInactiveFile) < 0)
            goto error;
    }

    if (when & WHEN_ACTIVE) {
        if (different) {
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
        } else {
            if (VIR_STRDUP(info->outActiveName, info->inName) < 0)
                goto error;
        }

        if (virtTestLoadFile(info->outActiveName, &info->outActiveFile) < 0)
            goto error;
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

# define DO_TEST_FULL(name, is_different, when)                                \
    do {                                                                       \
        if (testInfoSet(&info, name, is_different, when) < 0) {                \
            fprintf(stderr, "Failed to generate test data for '%s'", name);    \
            return -1;                                                         \
        }                                                                      \
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

# define DO_TEST(name) \
    DO_TEST_FULL(name, false, WHEN_BOTH)

# define DO_TEST_DIFFERENT(name) \
    DO_TEST_FULL(name, true, WHEN_BOTH)

    /* Unset or set all envvars here that are copied in qemudBuildCommandLine
     * using ADD_ENV_COPY, otherwise these tests may fail due to unexpected
     * values for these envvars */
    setenv("PATH", "/bin", 1);

    DO_TEST("minimal");
    DO_TEST("machine-core-on");
    DO_TEST("machine-core-off");
    DO_TEST_DIFFERENT("default-kvm-host-arch");
    DO_TEST_DIFFERENT("default-qemu-host-arch");
    DO_TEST("boot-cdrom");
    DO_TEST("boot-network");
    DO_TEST("boot-floppy");
    DO_TEST("boot-multi");
    DO_TEST("boot-menu-enable-with-timeout");
    DO_TEST("boot-menu-disable");
    DO_TEST_DIFFERENT("boot-menu-disable-with-timeout");
    DO_TEST("boot-order");

    DO_TEST("reboot-timeout-enabled");
    DO_TEST("reboot-timeout-disabled");

    DO_TEST("clock-utc");
    DO_TEST("clock-localtime");
    DO_TEST_DIFFERENT("cpu-empty");
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

    DO_TEST("kvm-features");
    DO_TEST("kvm-features-off");

    DO_TEST_DIFFERENT("pmu-feature");
    DO_TEST("pmu-feature-off");

    DO_TEST("hugepages");
    DO_TEST("hugepages-pages");
    DO_TEST("hugepages-pages2");
    DO_TEST("hugepages-pages3");
    DO_TEST("hugepages-shared");
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
    DO_TEST("disk-drive-copy-on-read");
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
    DO_TEST("disk-virtio-scsi-cmd_per_lun");
    DO_TEST("disk-virtio-scsi-max_sectors");
    DO_TEST("disk-virtio-scsi-ioeventfd");
    DO_TEST("disk-scsi-megasas");
    DO_TEST_DIFFERENT("disk-mirror-old");
    DO_TEST_FULL("disk-mirror", false, WHEN_ACTIVE);
    DO_TEST_FULL("disk-mirror", true, WHEN_INACTIVE);
    DO_TEST_FULL("disk-active-commit", false, WHEN_ACTIVE);
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
    DO_TEST("misc-acpi");
    DO_TEST("misc-disable-s3");
    DO_TEST("misc-disable-suspends");
    DO_TEST("misc-enable-s4");
    DO_TEST("misc-no-reboot");
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
    DO_TEST_DIFFERENT("console-compat2");
    DO_TEST("console-virtio-many");
    DO_TEST("channel-guestfwd");
    DO_TEST("channel-virtio");
    DO_TEST_DIFFERENT("channel-virtio-state");

    DO_TEST("hostdev-usb-address");
    DO_TEST("hostdev-pci-address");
    DO_TEST("hostdev-vfio");
    DO_TEST("pci-rom");
    DO_TEST("pci-serial-dev-chardev");

    DO_TEST("encrypted-disk");
    DO_TEST_DIFFERENT("memtune");
    DO_TEST_DIFFERENT("memtune-unlimited");
    DO_TEST("blkiotune");
    DO_TEST("blkiotune-device");
    DO_TEST("cputune");
    DO_TEST("cputune-zero-shares");
    DO_TEST_DIFFERENT("cputune-iothreadsched");
    DO_TEST("cputune-iothreadsched-zeropriority");
    DO_TEST("cputune-numatune");
    DO_TEST("vcpu-placement-static");

    DO_TEST("smp");
    DO_TEST("iothreads");
    DO_TEST("iothreads-ids");
    DO_TEST("iothreads-ids-partial");
    DO_TEST_DIFFERENT("cputune-iothreads");
    DO_TEST("iothreads-disk");
    DO_TEST("iothreads-disk-virtio-ccw");
    DO_TEST("lease");
    DO_TEST("event_idx");
    DO_TEST("vhost_queues");
    DO_TEST("interface-driver");
    DO_TEST("interface-server");
    DO_TEST("virtio-lun");

    DO_TEST("usb-redir");
    DO_TEST_DIFFERENT("usb-redir-filter");
    DO_TEST_DIFFERENT("usb-redir-filter-version");
    DO_TEST("blkdeviotune");

    DO_TEST_FULL("seclabel-dynamic-baselabel", false, WHEN_INACTIVE);
    DO_TEST_FULL("seclabel-dynamic-override", false, WHEN_INACTIVE);
    DO_TEST_FULL("seclabel-dynamic-labelskip", true, WHEN_INACTIVE);
    DO_TEST_FULL("seclabel-dynamic-relabel", true, WHEN_INACTIVE);
    DO_TEST("seclabel-static");
    DO_TEST_FULL("seclabel-static-labelskip", false, WHEN_ACTIVE);
    DO_TEST_DIFFERENT("seclabel-none");
    DO_TEST("seclabel-dac-none");
    DO_TEST("seclabel-dynamic-none");
    DO_TEST("seclabel-device-multiple");
    DO_TEST_FULL("seclabel-dynamic-none-relabel", true, WHEN_INACTIVE);
    DO_TEST("numad-static-vcpu-no-numatune");
    DO_TEST("disk-scsi-lun-passthrough-sgio");

    DO_TEST("disk-scsi-disk-vpd");
    DO_TEST_DIFFERENT("disk-source-pool");
    DO_TEST("disk-source-pool-mode");

    DO_TEST_DIFFERENT("disk-drive-discard");

    DO_TEST("virtio-rng-random");
    DO_TEST("virtio-rng-egd");

    DO_TEST("pseries-nvram");
    DO_TEST_DIFFERENT("pseries-panic-missing");
    DO_TEST("pseries-panic-no-address");

    /* These tests generate different XML */
    DO_TEST_DIFFERENT("balloon-device-auto");
    DO_TEST_DIFFERENT("balloon-device-period");
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
    DO_TEST_DIFFERENT("metadata-duplicate");

    DO_TEST("tpm-passthrough");
    DO_TEST("pci-bridge");
    DO_TEST_DIFFERENT("pci-bridge-many-disks");
    DO_TEST_DIFFERENT("pci-autoadd-addr");
    DO_TEST_DIFFERENT("pci-autoadd-idx");
    DO_TEST_DIFFERENT("pcie-root");
    DO_TEST_DIFFERENT("q35");
    DO_TEST("pcie-root-port");
    DO_TEST("pcie-root-port-too-many");
    DO_TEST("pcie-switch-upstream-port");
    DO_TEST("pcie-switch-downstream-port");

    DO_TEST("hostdev-scsi-lsi");
    DO_TEST("hostdev-scsi-virtio-scsi");
    DO_TEST("hostdev-scsi-readonly");

    DO_TEST("disk-copy_on_read");
    DO_TEST("hostdev-scsi-shareable");
    DO_TEST("hostdev-scsi-sgio");
    DO_TEST("hostdev-scsi-rawio");

    DO_TEST_DIFFERENT("hostdev-scsi-autogen-address");
    DO_TEST("hostdev-scsi-large-unit");

    DO_TEST("hostdev-scsi-lsi-iscsi");
    DO_TEST("hostdev-scsi-lsi-iscsi-auth");
    DO_TEST("hostdev-scsi-virtio-iscsi");
    DO_TEST("hostdev-scsi-virtio-iscsi-auth");

    DO_TEST_DIFFERENT("s390-defaultconsole");

    DO_TEST("pcihole64");
    DO_TEST_DIFFERENT("pcihole64-gib");
    DO_TEST("pcihole64-none");
    DO_TEST("pcihole64-q35");

    DO_TEST("panic");
    DO_TEST("panic-no-address");

    DO_TEST_DIFFERENT("disk-backing-chains");

    DO_TEST("chardev-label");

    DO_TEST_DIFFERENT("cpu-numa1");
    DO_TEST_DIFFERENT("cpu-numa2");
    DO_TEST_DIFFERENT("cpu-numa-no-memory-element");
    DO_TEST_DIFFERENT("cpu-numa-disordered");
    DO_TEST("cpu-numa-disjoint");
    DO_TEST("cpu-numa-memshared");

    DO_TEST_DIFFERENT("numatune-auto-prefer");
    DO_TEST_DIFFERENT("numatune-memnode");
    DO_TEST("numatune-memnode-no-memory");

    DO_TEST("bios-nvram");
    DO_TEST_DIFFERENT("bios-nvram-os-interleave");

    DO_TEST("tap-vhost");
    DO_TEST_DIFFERENT("tap-vhost-incorrect");
    DO_TEST("shmem");
    DO_TEST("smbios");
    DO_TEST("smbios-multiple-type2");
    DO_TEST("aarch64-aavmf-virtio-mmio");

    DO_TEST("aarch64-gic");
    DO_TEST("aarch64-gicv3");

    DO_TEST("memory-hotplug");
    DO_TEST("memory-hotplug-nonuma");
    DO_TEST("memory-hotplug-dimm");
    DO_TEST("net-udp");

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
