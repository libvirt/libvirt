#include <config.h>

#include <unistd.h>

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


static int
testXML2XMLActive(const void *opaque)
{
    const struct testQemuInfo *info = opaque;

    return testCompareDomXML2XMLFiles(driver.caps, driver.xmlopt,
                                      info->infile, info->outfile, true, 0,
                                      TEST_COMPARE_DOM_XML2XML_RESULT_SUCCESS);
}


static int
testXML2XMLInactive(const void *opaque)
{
    const struct testQemuInfo *info = opaque;

    return testCompareDomXML2XMLFiles(driver.caps, driver.xmlopt,
                                      info->infile, info->outfile, false, 0,
                                      TEST_COMPARE_DOM_XML2XML_RESULT_SUCCESS);
}


static int
testCompareStatusXMLToXMLFiles(const void *opaque)
{
    const struct testQemuInfo *data = opaque;
    virDomainObjPtr obj = NULL;
    char *actual = NULL;
    int ret = -1;

    if (!(obj = virDomainObjParseFile(data->infile, driver.caps, driver.xmlopt,
                                      VIR_DOMAIN_DEF_PARSE_STATUS |
                                      VIR_DOMAIN_DEF_PARSE_ACTUAL_NET |
                                      VIR_DOMAIN_DEF_PARSE_PCI_ORIG_STATES |
                                      VIR_DOMAIN_DEF_PARSE_SKIP_VALIDATE |
                                      VIR_DOMAIN_DEF_PARSE_ALLOW_POST_PARSE_FAIL))) {
        VIR_TEST_DEBUG("\nfailed to parse '%s'\n", data->infile);
        goto cleanup;
    }

    if (!(actual = virDomainObjFormat(driver.xmlopt, obj, NULL,
                                      VIR_DOMAIN_DEF_FORMAT_SECURE |
                                      VIR_DOMAIN_DEF_FORMAT_STATUS |
                                      VIR_DOMAIN_DEF_FORMAT_ACTUAL_NET |
                                      VIR_DOMAIN_DEF_FORMAT_PCI_ORIG_STATES |
                                      VIR_DOMAIN_DEF_FORMAT_CLOCK_ADJUST))) {
        VIR_TEST_DEBUG("\nfailed to format back '%s'\n", data->infile);
        goto cleanup;
    }

    if (virTestCompareToFile(actual, data->outfile) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virDomainObjEndAPI(&obj);
    VIR_FREE(actual);
    return ret;
}


static int
testInfoSetPaths(struct testQemuInfo *info,
                 const char *suffix,
                 int when)
{
    VIR_FREE(info->infile);
    VIR_FREE(info->outfile);

    if (virAsprintf(&info->infile, "%s/qemuxml2argvdata/%s.xml",
                    abs_srcdir, info->name) < 0)
        goto error;

    if (virAsprintf(&info->outfile,
                    "%s/qemuxml2xmloutdata/%s-%s%s.xml",
                    abs_srcdir, info->name,
                    when == WHEN_ACTIVE ? "active" : "inactive",
                    suffix) < 0)
        goto error;

    if (!virFileExists(info->outfile)) {
        VIR_FREE(info->outfile);

        if (virAsprintf(&info->outfile,
                        "%s/qemuxml2xmloutdata/%s%s.xml",
                        abs_srcdir, info->name, suffix) < 0)
            goto error;
    }

    return 0;

 error:
    testQemuInfoClear(info);
    return -1;
}


static const char *statusPath = abs_srcdir "/qemustatusxml2xmldata/";

static int
testInfoSetStatusPaths(struct testQemuInfo *info)
{
    if (virAsprintf(&info->infile, "%s%s-in.xml", statusPath, info->name) < 0 ||
        virAsprintf(&info->outfile, "%s%s-out.xml", statusPath, info->name) < 0)
        goto error;

    return 0;

 error:
    testQemuInfoClear(info);
    return -1;
}


# define FAKEROOTDIRTEMPLATE abs_builddir "/fakerootdir-XXXXXX"

static int
mymain(void)
{
    int ret = 0;
    char *fakerootdir;
    virQEMUDriverConfigPtr cfg = NULL;
    virHashTablePtr capslatest = NULL;

    capslatest = testQemuGetLatestCaps();
    if (!capslatest)
        return EXIT_FAILURE;

    if (VIR_STRDUP_QUIET(fakerootdir, FAKEROOTDIRTEMPLATE) < 0) {
        fprintf(stderr, "Out of memory\n");
        abort();
    }

    if (!mkdtemp(fakerootdir)) {
        fprintf(stderr, "Cannot create fakerootdir");
        abort();
    }

    setenv("LIBVIRT_FAKE_ROOT_DIR", fakerootdir, 1);

    if (qemuTestDriverInit(&driver) < 0)
        return EXIT_FAILURE;

    cfg = virQEMUDriverGetConfig(&driver);

# define DO_TEST_INTERNAL(_name, suffix, when, ...) \
    do { \
        static struct testQemuInfo info = { \
            .name = _name, \
        }; \
        if (testQemuInfoSetArgs(&info, capslatest, \
                                __VA_ARGS__, \
                                ARG_END) < 0 || \
            qemuTestCapsCacheInsert(driver.qemuCapsCache, info.qemuCaps) < 0) { \
            VIR_TEST_DEBUG("Failed to generate test data for '%s'", _name); \
            return -1; \
        } \
 \
        if (when & WHEN_INACTIVE) { \
            if (testInfoSetPaths(&info, suffix, WHEN_INACTIVE) < 0) { \
                VIR_TEST_DEBUG("Failed to generate inactive paths for '%s'", _name); \
                return -1; \
            } \
            if (virTestRun("QEMU XML-2-XML-inactive " _name, \
                            testXML2XMLInactive, &info) < 0) \
                ret = -1; \
        } \
 \
        if (when & WHEN_ACTIVE) { \
            if (testInfoSetPaths(&info, suffix, WHEN_ACTIVE) < 0) { \
                VIR_TEST_DEBUG("Failed to generate active paths for '%s'", _name); \
                return -1; \
            } \
            if (virTestRun("QEMU XML-2-XML-active " _name, \
                            testXML2XMLActive, &info) < 0) \
                ret = -1; \
        } \
        testQemuInfoClear(&info); \
    } while (0)

# define DO_TEST_CAPS_INTERNAL(name, arch, ver, ...) \
    DO_TEST_INTERNAL(name, "." arch "-" ver, WHEN_BOTH, \
                     ARG_CAPS_ARCH, arch, \
                     ARG_CAPS_VER, ver, \
                     __VA_ARGS__)

# define DO_TEST_CAPS_ARCH_LATEST_FULL(name, arch, ...) \
    DO_TEST_CAPS_INTERNAL(name, arch, "latest", __VA_ARGS__)

# define DO_TEST_CAPS_ARCH_LATEST(name, arch) \
    DO_TEST_CAPS_ARCH_LATEST_FULL(name, arch, ARG_END)

# define DO_TEST_CAPS_ARCH_VER(name, arch, ver) \
    DO_TEST_CAPS_INTERNAL(name, arch, ver, ARG_END)

# define DO_TEST_CAPS_LATEST(name) \
    DO_TEST_CAPS_ARCH_LATEST(name, "x86_64")

# define DO_TEST_CAPS_VER(name, ver) \
    DO_TEST_CAPS_ARCH_VER(name, "x86_64", ver)

# define DO_TEST_FULL(name, when, ...) \
    DO_TEST_INTERNAL(name, "", when, __VA_ARGS__)

# define DO_TEST(name, ...) \
    DO_TEST_FULL(name, WHEN_BOTH, \
                 ARG_QEMU_CAPS, __VA_ARGS__, QEMU_CAPS_LAST)

# define NONE QEMU_CAPS_LAST

    /* Unset or set all envvars here that are copied in qemudBuildCommandLine
     * using ADD_ENV_COPY, otherwise these tests may fail due to unexpected
     * values for these envvars */
    setenv("PATH", "/bin", 1);

    DO_TEST("minimal", NONE);
    DO_TEST_CAPS_LATEST("genid");
    DO_TEST_CAPS_LATEST("genid-auto");
    DO_TEST("machine-core-on", NONE);
    DO_TEST("machine-core-off", NONE);
    DO_TEST("machine-loadparm-multiple-disks-nets-s390", NONE);
    DO_TEST("default-kvm-host-arch", NONE);
    DO_TEST("default-qemu-host-arch", NONE);
    DO_TEST("boot-cdrom", NONE);
    DO_TEST("boot-network", NONE);
    DO_TEST("boot-floppy", NONE);
    DO_TEST("boot-floppy-q35",
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI);
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

    DO_TEST("pages-discard", NONE);
    DO_TEST("pages-discard-hugepages", NONE);
    DO_TEST("pages-dimm-discard", NONE);
    DO_TEST("hugepages-default", NONE);
    DO_TEST("hugepages-default-2M", NONE);
    DO_TEST("hugepages-default-system-size", NONE);
    DO_TEST("hugepages-nodeset", NONE);
    DO_TEST("hugepages-numa-default-2M", NONE);
    DO_TEST("hugepages-numa-default-dimm", NONE);
    DO_TEST("hugepages-numa-nodeset", NONE);
    DO_TEST("hugepages-numa-nodeset-part", NONE);
    DO_TEST("hugepages-shared", NONE);
    DO_TEST("hugepages-memaccess", NONE);
    DO_TEST("hugepages-memaccess2", NONE);
    DO_TEST("hugepages-nvdimm", NONE);
    DO_TEST("nosharepages", NONE);
    DO_TEST("restore-v2", NONE);
    DO_TEST("migrate", NONE);
    DO_TEST("qemu-ns-no-env", NONE);
    DO_TEST("disk-aio", NONE);
    DO_TEST("disk-cdrom", NONE);
    DO_TEST("disk-cdrom-bus-other", NONE);
    DO_TEST("disk-floppy", NONE);
    DO_TEST("disk-usb-device", NONE);
    DO_TEST("disk-virtio", NONE);
    DO_TEST("floppy-drive-fat", NONE);
    DO_TEST("disk-virtio-queues", QEMU_CAPS_VIRTIO_BLK_NUM_QUEUES);
    DO_TEST("disk-boot-disk", NONE);
    DO_TEST("disk-boot-cdrom", NONE);
    DO_TEST("disk-error-policy", NONE);
    DO_TEST("disk-fmt-qcow", NONE);
    DO_TEST("disk-cache", QEMU_CAPS_SCSI_LSI);
    DO_TEST("disk-network-nbd", NONE);
    DO_TEST("disk-network-iscsi", QEMU_CAPS_VIRTIO_SCSI);
    DO_TEST("disk-network-gluster", NONE);
    DO_TEST("disk-network-rbd", NONE);
    DO_TEST("disk-network-source-auth", NONE);
    DO_TEST("disk-network-sheepdog", NONE);
    DO_TEST("disk-network-vxhs", NONE);
    DO_TEST("disk-network-tlsx509", NONE);
    DO_TEST("disk-scsi", QEMU_CAPS_SCSI_LSI, QEMU_CAPS_SCSI_MEGASAS,
            QEMU_CAPS_SCSI_MPTSAS1068, QEMU_CAPS_SCSI_DISK_WWN);
    DO_TEST("disk-virtio-scsi-reservations",
            QEMU_CAPS_VIRTIO_SCSI, QEMU_CAPS_PR_MANAGER_HELPER);
    DO_TEST("controller-virtio-scsi", QEMU_CAPS_VIRTIO_SCSI);
    DO_TEST("disk-virtio-s390-zpci",
            QEMU_CAPS_DEVICE_ZPCI,
            QEMU_CAPS_CCW);
    DO_TEST("disk-mirror-old", NONE);
    DO_TEST("disk-mirror", NONE);
    DO_TEST("disk-active-commit", NONE);
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
    DO_TEST("graphics-vnc-egl-headless",
            QEMU_CAPS_EGL_HEADLESS);

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
    DO_TEST("graphics-spice-egl-headless",
            QEMU_CAPS_EGL_HEADLESS);

    DO_TEST("graphics-egl-headless-rendernode",
            QEMU_CAPS_EGL_HEADLESS,
            QEMU_CAPS_EGL_HEADLESS_RENDERNODE);

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
    DO_TEST("net-user-addr", NONE);
    DO_TEST("net-virtio", NONE);
    DO_TEST("net-virtio-device", NONE);
    DO_TEST("net-virtio-disable-offloads", NONE);
    DO_TEST("net-eth", NONE);
    DO_TEST("net-eth-ifname", NONE);
    DO_TEST("net-eth-hostip", NONE);
    DO_TEST("net-virtio-network-portgroup", NONE);
    DO_TEST("net-virtio-rxtxqueuesize", NONE);
    DO_TEST("net-hostdev", NONE);
    DO_TEST("net-hostdev-bootorder", NONE);
    DO_TEST("net-hostdev-vfio", NONE);
    DO_TEST("net-midonet", NONE);
    DO_TEST("net-openvswitch", NONE);
    DO_TEST("sound", NONE);
    DO_TEST("sound-device", NONE);
    DO_TEST("watchdog", NONE);
    DO_TEST("net-bandwidth", NONE);
    DO_TEST("net-bandwidth2", NONE);
    DO_TEST("net-mtu", NONE);
    DO_TEST("net-coalesce", NONE);
    DO_TEST("net-many-models", NONE);

    DO_TEST("serial-tcp-tlsx509-chardev", NONE);
    DO_TEST("serial-tcp-tlsx509-chardev-notls", NONE);
    DO_TEST("serial-spiceport", NONE);
    DO_TEST("serial-spiceport-nospice", NONE);
    DO_TEST("console-compat", NONE);
    DO_TEST("console-compat2", NONE);
    DO_TEST("console-virtio-many", NONE);
    DO_TEST("channel-guestfwd", NONE);
    DO_TEST("channel-virtio", NONE);
    DO_TEST("channel-virtio-state", NONE);

    DO_TEST("channel-unix-source-path", NONE);

    DO_TEST("hostdev-usb-address", NONE);
    DO_TEST("hostdev-pci-address", NONE);
    DO_TEST("hostdev-vfio", NONE);
    DO_TEST("hostdev-vfio-zpci",
            QEMU_CAPS_DEVICE_ZPCI,
            QEMU_CAPS_CCW);
    DO_TEST("hostdev-vfio-zpci-multidomain-many",
            QEMU_CAPS_DEVICE_VFIO_PCI,
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_ZPCI);
    DO_TEST("hostdev-vfio-zpci-autogenerate",
            QEMU_CAPS_DEVICE_VFIO_PCI,
            QEMU_CAPS_DEVICE_ZPCI);
    DO_TEST("hostdev-vfio-zpci-boundaries",
            QEMU_CAPS_DEVICE_VFIO_PCI,
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_ZPCI);
    DO_TEST("hostdev-mdev-precreated", NONE);
    DO_TEST("hostdev-mdev-display", QEMU_CAPS_VFIO_PCI_DISPLAY);
    DO_TEST("pci-rom", NONE);
    DO_TEST("pci-rom-disabled", NONE);
    DO_TEST("pci-rom-disabled-invalid", NONE);
    DO_TEST("pci-serial-dev-chardev", NONE);

    DO_TEST("encrypted-disk", QEMU_CAPS_QCOW2_LUKS);
    DO_TEST("encrypted-disk-usage", QEMU_CAPS_QCOW2_LUKS);
    DO_TEST("luks-disks", NONE);
    DO_TEST("luks-disks-source", NONE);
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
            QEMU_CAPS_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST("iothreads-virtio-scsi-pci",
            QEMU_CAPS_VIRTIO_SCSI);
    DO_TEST("iothreads-virtio-scsi-ccw",
            QEMU_CAPS_VIRTIO_SCSI, QEMU_CAPS_CCW,
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
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
            QEMU_CAPS_PCI_OHCI);
    DO_TEST("ppc64-usb-controller-legacy",
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
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

    DO_TEST_FULL("seclabel-dynamic-baselabel", WHEN_INACTIVE,
                 ARG_QEMU_CAPS, NONE);
    DO_TEST_FULL("seclabel-dynamic-override", WHEN_INACTIVE,
                 ARG_QEMU_CAPS, NONE);
    DO_TEST_FULL("seclabel-dynamic-labelskip", WHEN_INACTIVE,
                 ARG_QEMU_CAPS, NONE);
    DO_TEST_FULL("seclabel-dynamic-relabel", WHEN_INACTIVE,
                 ARG_QEMU_CAPS, NONE);
    DO_TEST("seclabel-static", NONE);
    DO_TEST("seclabel-static-labelskip", NONE);
    DO_TEST("seclabel-none", NONE);
    DO_TEST("seclabel-dac-none", NONE);
    DO_TEST("seclabel-dynamic-none", NONE);
    DO_TEST("seclabel-device-multiple", NONE);
    DO_TEST_FULL("seclabel-dynamic-none-relabel", WHEN_INACTIVE,
                 ARG_QEMU_CAPS, NONE);
    DO_TEST("numad-static-vcpu-no-numatune", NONE);

    DO_TEST("disk-scsi-lun-passthrough-sgio",
            QEMU_CAPS_SCSI_LSI, QEMU_CAPS_VIRTIO_SCSI, QEMU_CAPS_SCSI_DISK_WWN);
    DO_TEST("disk-scsi-disk-vpd",
            QEMU_CAPS_SCSI_LSI, QEMU_CAPS_VIRTIO_SCSI, QEMU_CAPS_SCSI_DISK_WWN);
    DO_TEST("disk-source-pool", NONE);
    DO_TEST("disk-source-pool-mode", NONE);

    DO_TEST("disk-discard", NONE);
    DO_TEST("disk-detect-zeroes", NONE);

    DO_TEST("disk-serial", NONE);

    DO_TEST("virtio-rng-random",
            QEMU_CAPS_DEVICE_VIRTIO_RNG);
    DO_TEST("virtio-rng-egd",
            QEMU_CAPS_DEVICE_VIRTIO_RNG);

    DO_TEST("pseries-nvram",
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE);
    DO_TEST("pseries-panic-missing",
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE);
    DO_TEST("pseries-panic-no-address",
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE);

    DO_TEST("pseries-phb-simple",
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE);
    DO_TEST("pseries-phb-default-missing",
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE);
    DO_TEST("pseries-phb-numa-node",
            QEMU_CAPS_NUMA,
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
            QEMU_CAPS_SPAPR_PCI_HOST_BRIDGE_NUMA_NODE);

    DO_TEST("pseries-many-devices",
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
            QEMU_CAPS_VIRTIO_SCSI);
    DO_TEST("pseries-many-buses-1",
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
            QEMU_CAPS_VIRTIO_SCSI);
    DO_TEST("pseries-many-buses-2",
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
            QEMU_CAPS_VIRTIO_SCSI);
    DO_TEST("pseries-hostdevs-1",
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_DEVICE_VFIO_PCI);
    DO_TEST("pseries-hostdevs-2",
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_DEVICE_VFIO_PCI);
    DO_TEST("pseries-hostdevs-3",
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_DEVICE_VFIO_PCI);

    DO_TEST("pseries-features",
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
            QEMU_CAPS_MACHINE_PSERIES_CAP_HPT_MAX_PAGE_SIZE,
            QEMU_CAPS_MACHINE_PSERIES_CAP_HTM,
            QEMU_CAPS_MACHINE_PSERIES_CAP_NESTED_HV,
            QEMU_CAPS_MACHINE_PSERIES_RESIZE_HPT);

    DO_TEST("pseries-serial-native",
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
            QEMU_CAPS_DEVICE_SPAPR_VTY);
    DO_TEST("pseries-serial+console-native",
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
            QEMU_CAPS_DEVICE_SPAPR_VTY);
    DO_TEST("pseries-serial-compat",
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
            QEMU_CAPS_DEVICE_SPAPR_VTY);
    DO_TEST("pseries-serial-pci",
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
            QEMU_CAPS_DEVICE_PCI_SERIAL);
    DO_TEST("pseries-serial-usb",
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
            QEMU_CAPS_DEVICE_QEMU_XHCI,
            QEMU_CAPS_DEVICE_USB_SERIAL);
    DO_TEST("pseries-console-native",
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
            QEMU_CAPS_DEVICE_SPAPR_VTY);
    DO_TEST("pseries-console-virtio",
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE);

    DO_TEST("mach-virt-serial-native", NONE);
    DO_TEST("mach-virt-serial+console-native", NONE);
    DO_TEST("mach-virt-serial-compat", NONE);
    DO_TEST("mach-virt-serial-pci",
            QEMU_CAPS_OBJECT_GPEX,
            QEMU_CAPS_DEVICE_PCIE_ROOT_PORT,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_PCI_SERIAL);
    DO_TEST("mach-virt-serial-usb",
            QEMU_CAPS_OBJECT_GPEX,
            QEMU_CAPS_DEVICE_PCIE_ROOT_PORT,
            QEMU_CAPS_DEVICE_QEMU_XHCI,
            QEMU_CAPS_DEVICE_USB_SERIAL);
    DO_TEST("mach-virt-console-native",
            QEMU_CAPS_DEVICE_PL011);
    DO_TEST("mach-virt-console-virtio",
            QEMU_CAPS_DEVICE_VIRTIO_MMIO);

    DO_TEST("balloon-device-auto", NONE);
    DO_TEST("balloon-device-period", NONE);
    DO_TEST("channel-virtio-auto", NONE);
    DO_TEST("console-compat-auto", NONE);
    DO_TEST("disk-scsi-device-auto",
            QEMU_CAPS_SCSI_LSI);
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
    DO_TEST("tpm-passthrough-crb", NONE);
    DO_TEST("tpm-emulator", NONE);

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
            QEMU_CAPS_ICH9_USB_EHCI1,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_DEVICE_QXL);
    DO_TEST("q35-usb2",
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_ICH9_USB_EHCI1,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_DEVICE_QXL);
    DO_TEST("q35-usb2-multi",
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_ICH9_USB_EHCI1,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_DEVICE_QXL);
    DO_TEST("q35-usb2-reorder",
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_ICH9_USB_EHCI1,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_DEVICE_QXL);
    DO_TEST("q35-pcie",
            QEMU_CAPS_VIRTIO_PCI_DISABLE_LEGACY,
            QEMU_CAPS_DEVICE_VIRTIO_RNG,
            QEMU_CAPS_OBJECT_RNG_RANDOM,
            QEMU_CAPS_DEVICE_VIRTIO_NET,
            QEMU_CAPS_DEVICE_VIRTIO_GPU,
            QEMU_CAPS_VIRTIO_GPU_VIRGL,
            QEMU_CAPS_VIRTIO_KEYBOARD,
            QEMU_CAPS_VIRTIO_MOUSE,
            QEMU_CAPS_VIRTIO_TABLET,
            QEMU_CAPS_VIRTIO_INPUT_HOST,
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_ICH9_USB_EHCI1,
            QEMU_CAPS_NEC_USB_XHCI,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY);
    /* same XML as q35-pcie, but don't set
       QEMU_CAPS_VIRTIO_PCI_DISABLE_LEGACY */
    DO_TEST("q35-virtio-pci",
            QEMU_CAPS_DEVICE_VIRTIO_RNG,
            QEMU_CAPS_OBJECT_RNG_RANDOM,
            QEMU_CAPS_DEVICE_VIRTIO_NET,
            QEMU_CAPS_DEVICE_VIRTIO_GPU,
            QEMU_CAPS_VIRTIO_GPU_VIRGL,
            QEMU_CAPS_VIRTIO_KEYBOARD,
            QEMU_CAPS_VIRTIO_MOUSE,
            QEMU_CAPS_VIRTIO_TABLET,
            QEMU_CAPS_VIRTIO_INPUT_HOST,
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_ICH9_USB_EHCI1,
            QEMU_CAPS_NEC_USB_XHCI,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY);
    /* same as q35-pcie, but all PCI controllers are added automatically */
    DO_TEST("q35-pcie-autoadd",
            QEMU_CAPS_VIRTIO_PCI_DISABLE_LEGACY,
            QEMU_CAPS_DEVICE_VIRTIO_RNG,
            QEMU_CAPS_OBJECT_RNG_RANDOM,
            QEMU_CAPS_DEVICE_VIRTIO_NET,
            QEMU_CAPS_DEVICE_VIRTIO_GPU,
            QEMU_CAPS_VIRTIO_GPU_VIRGL,
            QEMU_CAPS_VIRTIO_KEYBOARD,
            QEMU_CAPS_VIRTIO_MOUSE,
            QEMU_CAPS_VIRTIO_TABLET,
            QEMU_CAPS_VIRTIO_INPUT_HOST,
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_ICH9_USB_EHCI1,
            QEMU_CAPS_NEC_USB_XHCI,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY);
    DO_TEST("q35-default-devices-only",
            QEMU_CAPS_VIRTIO_PCI_DISABLE_LEGACY,
            QEMU_CAPS_DEVICE_VIRTIO_RNG,
            QEMU_CAPS_OBJECT_RNG_RANDOM,
            QEMU_CAPS_DEVICE_VIRTIO_NET,
            QEMU_CAPS_DEVICE_VIRTIO_GPU,
            QEMU_CAPS_VIRTIO_GPU_VIRGL,
            QEMU_CAPS_VIRTIO_KEYBOARD,
            QEMU_CAPS_VIRTIO_MOUSE,
            QEMU_CAPS_VIRTIO_TABLET,
            QEMU_CAPS_VIRTIO_INPUT_HOST,
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_ICH9_USB_EHCI1,
            QEMU_CAPS_NEC_USB_XHCI,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY);
    DO_TEST("q35-multifunction",
            QEMU_CAPS_VIRTIO_PCI_DISABLE_LEGACY,
            QEMU_CAPS_DEVICE_VIRTIO_RNG,
            QEMU_CAPS_OBJECT_RNG_RANDOM,
            QEMU_CAPS_DEVICE_VIRTIO_NET,
            QEMU_CAPS_DEVICE_VIRTIO_GPU,
            QEMU_CAPS_VIRTIO_GPU_VIRGL,
            QEMU_CAPS_VIRTIO_KEYBOARD,
            QEMU_CAPS_VIRTIO_MOUSE,
            QEMU_CAPS_VIRTIO_TABLET,
            QEMU_CAPS_VIRTIO_INPUT_HOST,
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_ICH9_USB_EHCI1,
            QEMU_CAPS_NEC_USB_XHCI,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY);
    DO_TEST("q35-virt-manager-basic",
            QEMU_CAPS_KVM,
            QEMU_CAPS_ICH9_DISABLE_S3,
            QEMU_CAPS_ICH9_DISABLE_S4,
            QEMU_CAPS_VIRTIO_PCI_DISABLE_LEGACY,
            QEMU_CAPS_DEVICE_VIRTIO_RNG,
            QEMU_CAPS_OBJECT_RNG_RANDOM,
            QEMU_CAPS_DEVICE_VIRTIO_NET,
            QEMU_CAPS_DEVICE_VIRTIO_GPU,
            QEMU_CAPS_VIRTIO_GPU_VIRGL,
            QEMU_CAPS_VIRTIO_KEYBOARD,
            QEMU_CAPS_VIRTIO_MOUSE,
            QEMU_CAPS_VIRTIO_TABLET,
            QEMU_CAPS_VIRTIO_INPUT_HOST,
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_ICH9_USB_EHCI1,
            QEMU_CAPS_NEC_USB_XHCI,
            QEMU_CAPS_DEVICE_ICH9_INTEL_HDA,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_SPICE,
            QEMU_CAPS_DEVICE_QXL,
            QEMU_CAPS_HDA_DUPLEX,
            QEMU_CAPS_USB_REDIR);
    DO_TEST("pcie-root",
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_DEVICE_QXL);

    /* Test automatic and manual setting of pcie-root-port attributes */
    DO_TEST("pcie-root-port",
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_DEVICE_QXL);

    /* Make sure the default model for PCIe Root Ports is picked correctly
     * based on QEMU binary capabilities. We use x86/q35 for the test, but
     * any PCIe machine type (such as aarch64/virt) will behave the same */
    DO_TEST("pcie-root-port-model-generic",
            QEMU_CAPS_DEVICE_PCIE_ROOT_PORT,
            QEMU_CAPS_DEVICE_IOH3420);
    DO_TEST("pcie-root-port-model-ioh3420",
            QEMU_CAPS_DEVICE_IOH3420);

    DO_TEST("pcie-switch-upstream-port",
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_DEVICE_X3130_UPSTREAM,
            QEMU_CAPS_ICH9_AHCI,
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
            QEMU_CAPS_CCW);
    DO_TEST("hostdev-scsi-vhost-scsi-pci",
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_DEVICE_VHOST_SCSI);
    DO_TEST("hostdev-scsi-vhost-scsi-pcie",
            QEMU_CAPS_KVM,
            QEMU_CAPS_VIRTIO_SCSI, QEMU_CAPS_DEVICE_VHOST_SCSI,
            QEMU_CAPS_DEVICE_PCIE_ROOT_PORT,
            QEMU_CAPS_VIRTIO_PCI_DISABLE_LEGACY);
    DO_TEST("hostdev-scsi-lsi",
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_SCSI_LSI);
    DO_TEST("hostdev-scsi-virtio-scsi",
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_SCSI_LSI);
    DO_TEST("hostdev-scsi-readonly",
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_SCSI_LSI);

    DO_TEST("hostdev-scsi-shareable",
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_SCSI_LSI);
    DO_TEST("hostdev-scsi-sgio",
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_SCSI_LSI);
    DO_TEST("hostdev-scsi-rawio",
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_SCSI_LSI);

    DO_TEST("hostdev-scsi-autogen-address",
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_SCSI_LSI);
    DO_TEST("hostdev-scsi-large-unit",
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_SCSI_LSI);

    DO_TEST("hostdev-scsi-lsi-iscsi",
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_SCSI_LSI);
    DO_TEST("hostdev-scsi-lsi-iscsi-auth",
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_SCSI_LSI);
    DO_TEST("hostdev-scsi-virtio-iscsi",
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_SCSI_LSI);
    DO_TEST("hostdev-scsi-virtio-iscsi-auth",
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_SCSI_LSI);

    DO_TEST("hostdev-subsys-mdev-vfio-ccw",
            QEMU_CAPS_CCW,
            QEMU_CAPS_CCW_CSSID_UNRESTRICTED,
            QEMU_CAPS_DEVICE_VFIO_CCW);

    DO_TEST("s390-defaultconsole",
            QEMU_CAPS_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST("s390-panic",
            QEMU_CAPS_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST("s390-panic-missing",
            QEMU_CAPS_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST("s390-panic-no-address",
            QEMU_CAPS_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST("s390-serial",
            QEMU_CAPS_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST("s390-serial-2",
            QEMU_CAPS_CCW, QEMU_CAPS_VIRTIO_S390);
    DO_TEST("s390-serial-console",
            QEMU_CAPS_CCW, QEMU_CAPS_VIRTIO_S390);

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
    DO_TEST("panic-pseries",
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE);
    DO_TEST("panic-double", NONE);
    DO_TEST("panic-no-address", NONE);

    DO_TEST("disk-backing-chains", NONE);
    DO_TEST("disk-backing-chains-index", NONE);
    DO_TEST("disk-backing-chains-noindex", NONE);

    DO_TEST("chardev-label",
            QEMU_CAPS_DEVICE_VIRTIO_RNG);

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

    DO_TEST_CAPS_LATEST("os-firmware-bios");
    DO_TEST_CAPS_LATEST("os-firmware-efi");
    DO_TEST_CAPS_LATEST("os-firmware-efi-secboot");

    DO_TEST("aarch64-aavmf-virtio-mmio",
            QEMU_CAPS_DEVICE_VIRTIO_MMIO,
            QEMU_CAPS_DEVICE_VIRTIO_RNG, QEMU_CAPS_OBJECT_RNG_RANDOM);
    DO_TEST_CAPS_ARCH_LATEST("aarch64-os-firmware-efi", "aarch64");
    DO_TEST("aarch64-virtio-pci-default",
            QEMU_CAPS_VIRTIO_PCI_DISABLE_LEGACY,
            QEMU_CAPS_DEVICE_VIRTIO_MMIO,
            QEMU_CAPS_DEVICE_VIRTIO_RNG, QEMU_CAPS_OBJECT_RNG_RANDOM,
            QEMU_CAPS_OBJECT_GPEX, QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_VIRTIO_SCSI);
    DO_TEST("aarch64-virtio-pci-manual-addresses",
            QEMU_CAPS_DEVICE_VIRTIO_MMIO,
            QEMU_CAPS_DEVICE_VIRTIO_RNG, QEMU_CAPS_OBJECT_RNG_RANDOM,
            QEMU_CAPS_OBJECT_GPEX, QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_VIRTIO_SCSI);
    DO_TEST("aarch64-video-virtio-gpu-pci",
            QEMU_CAPS_OBJECT_GPEX,
            QEMU_CAPS_DEVICE_PCI_BRIDGE, QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_DEVICE_VIRTIO_GPU);
    DO_TEST("aarch64-pci-serial",
            QEMU_CAPS_DEVICE_PCI_SERIAL,
            QEMU_CAPS_CHARDEV_LOGFILE,
            QEMU_CAPS_OBJECT_GPEX,
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_PCIE_ROOT_PORT);
    DO_TEST("aarch64-traditional-pci",
            QEMU_CAPS_OBJECT_GPEX,
            QEMU_CAPS_DEVICE_PCIE_ROOT_PORT,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_PCIE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_PCI_SERIAL);
    DO_TEST("aarch64-video-default",
            QEMU_CAPS_OBJECT_GPEX,
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_DEVICE_VIRTIO_GPU,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_VNC);

    DO_TEST_FULL("aarch64-gic-none", WHEN_BOTH,
                 ARG_GIC, GIC_NONE,
                 ARG_QEMU_CAPS, NONE);
    DO_TEST_FULL("aarch64-gic-none-v2", WHEN_BOTH,
                 ARG_GIC, GIC_V2,
                 ARG_QEMU_CAPS, NONE);
    DO_TEST_FULL("aarch64-gic-none-v3", WHEN_BOTH,
                 ARG_GIC, GIC_V3,
                 ARG_QEMU_CAPS, NONE);
    DO_TEST_FULL("aarch64-gic-none-both", WHEN_BOTH,
                 ARG_GIC, GIC_BOTH,
                 ARG_QEMU_CAPS, NONE);
    DO_TEST_FULL("aarch64-gic-none-tcg", WHEN_BOTH,
                 ARG_GIC, GIC_BOTH,
                 ARG_QEMU_CAPS, NONE);
    DO_TEST_FULL("aarch64-gic-default", WHEN_BOTH,
                 ARG_GIC, GIC_NONE,
                 ARG_QEMU_CAPS, NONE);
    DO_TEST_FULL("aarch64-gic-default-v2", WHEN_BOTH,
                 ARG_GIC, GIC_V2,
                 ARG_QEMU_CAPS, NONE);
    DO_TEST_FULL("aarch64-gic-default-v3", WHEN_BOTH,
                 ARG_GIC, GIC_V3,
                 ARG_QEMU_CAPS, NONE);
    DO_TEST_FULL("aarch64-gic-default-both", WHEN_BOTH,
                 ARG_GIC, GIC_BOTH,
                 ARG_QEMU_CAPS, NONE);
    DO_TEST_FULL("aarch64-gic-v2", WHEN_BOTH,
                 ARG_GIC, GIC_NONE,
                 ARG_QEMU_CAPS, NONE);
    DO_TEST_FULL("aarch64-gic-v2", WHEN_BOTH,
                 ARG_GIC, GIC_V2,
                 ARG_QEMU_CAPS, NONE);
    DO_TEST_FULL("aarch64-gic-v2", WHEN_BOTH,
                 ARG_GIC, GIC_V3,
                 ARG_QEMU_CAPS, NONE);
    DO_TEST_FULL("aarch64-gic-v2", WHEN_BOTH,
                 ARG_GIC, GIC_BOTH,
                 ARG_QEMU_CAPS, NONE);
    DO_TEST_FULL("aarch64-gic-v3", WHEN_BOTH,
                 ARG_GIC, GIC_NONE,
                 ARG_QEMU_CAPS, NONE);
    DO_TEST_FULL("aarch64-gic-v3", WHEN_BOTH,
                 ARG_GIC, GIC_V2,
                 ARG_QEMU_CAPS, NONE);
    DO_TEST_FULL("aarch64-gic-v3", WHEN_BOTH,
                 ARG_GIC, GIC_V3,
                 ARG_QEMU_CAPS, NONE);
    DO_TEST_FULL("aarch64-gic-v3", WHEN_BOTH,
                 ARG_GIC, GIC_BOTH,
                 ARG_QEMU_CAPS, NONE);
    DO_TEST_FULL("aarch64-gic-host", WHEN_BOTH,
                 ARG_GIC, GIC_NONE,
                 ARG_QEMU_CAPS, NONE);
    DO_TEST_FULL("aarch64-gic-host", WHEN_BOTH,
                 ARG_GIC, GIC_V2,
                 ARG_QEMU_CAPS, NONE);
    DO_TEST_FULL("aarch64-gic-host", WHEN_BOTH,
                 ARG_GIC, GIC_V3,
                 ARG_QEMU_CAPS, NONE);
    DO_TEST_FULL("aarch64-gic-host", WHEN_BOTH,
                 ARG_GIC, GIC_BOTH,
                 ARG_QEMU_CAPS, NONE);

    DO_TEST("memory-hotplug", NONE);
    DO_TEST("memory-hotplug-nonuma", NONE);
    DO_TEST("memory-hotplug-dimm", NONE);
    DO_TEST("memory-hotplug-nvdimm", NONE);
    DO_TEST("memory-hotplug-nvdimm-access", NONE);
    DO_TEST("memory-hotplug-nvdimm-label", NONE);
    DO_TEST("memory-hotplug-nvdimm-align", NONE);
    DO_TEST("memory-hotplug-nvdimm-pmem", NONE);
    DO_TEST("memory-hotplug-nvdimm-readonly", NONE);
    DO_TEST("net-udp", NONE);

    DO_TEST("video-virtio-gpu-device", NONE);
    DO_TEST("video-virtio-gpu-virgl", NONE);
    DO_TEST("video-virtio-gpu-spice-gl", NONE);
    DO_TEST("video-virtio-gpu-sdl-gl", NONE);

    DO_TEST("virtio-input",
            QEMU_CAPS_VIRTIO_KEYBOARD,
            QEMU_CAPS_VIRTIO_MOUSE,
            QEMU_CAPS_VIRTIO_TABLET);
    DO_TEST("virtio-input-passthrough",
            QEMU_CAPS_VIRTIO_INPUT_HOST);

    DO_TEST("memorybacking-set", NONE);
    DO_TEST("memorybacking-unset", NONE);

    DO_TEST("virtio-options",
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_VIRTIO_KEYBOARD,
            QEMU_CAPS_VIRTIO_MOUSE,
            QEMU_CAPS_VIRTIO_TABLET,
            QEMU_CAPS_VIRTIO_INPUT_HOST,
            QEMU_CAPS_DEVICE_VIRTIO_GPU,
            QEMU_CAPS_VIRTIO_GPU_VIRGL,
            QEMU_CAPS_DEVICE_VIRTIO_RNG,
            QEMU_CAPS_OBJECT_RNG_RANDOM,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_VIRTIO_PCI_IOMMU_PLATFORM,
            QEMU_CAPS_VIRTIO_PCI_ATS);

    DO_TEST("fd-memory-numa-topology", QEMU_CAPS_OBJECT_MEMORY_FILE,
            QEMU_CAPS_KVM);
    DO_TEST("fd-memory-numa-topology2", QEMU_CAPS_OBJECT_MEMORY_FILE,
            QEMU_CAPS_KVM);
    DO_TEST("fd-memory-numa-topology3", QEMU_CAPS_OBJECT_MEMORY_FILE,
            QEMU_CAPS_KVM);

    DO_TEST("fd-memory-no-numa-topology", QEMU_CAPS_OBJECT_MEMORY_FILE,
            QEMU_CAPS_KVM);

    DO_TEST("memfd-memory-numa",
            QEMU_CAPS_OBJECT_MEMORY_MEMFD,
            QEMU_CAPS_OBJECT_MEMORY_MEMFD_HUGETLB);
    DO_TEST("memfd-memory-default-hugepage",
            QEMU_CAPS_OBJECT_MEMORY_MEMFD,
            QEMU_CAPS_OBJECT_MEMORY_MEMFD_HUGETLB);

    DO_TEST("acpi-table", NONE);

    DO_TEST("video-device-pciaddr-default",
            QEMU_CAPS_KVM,
            QEMU_CAPS_VNC,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_DEVICE_QXL);
    DO_TEST("video-qxl-heads", NONE);
    DO_TEST("video-qxl-noheads", NONE);
    DO_TEST("video-virtio-gpu-secondary", NONE);
    DO_TEST("video-virtio-gpu-ccw",
            QEMU_CAPS_CCW,
            QEMU_CAPS_DEVICE_VIRTIO_GPU,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_VIRTIO_GPU_MAX_OUTPUTS,
            QEMU_CAPS_VNC,
            QEMU_CAPS_DEVICE_VIRTIO_GPU_CCW);
    DO_TEST("video-virtio-gpu-ccw-auto",
            QEMU_CAPS_CCW,
            QEMU_CAPS_DEVICE_VIRTIO_GPU,
            QEMU_CAPS_DEVICE_VIDEO_PRIMARY,
            QEMU_CAPS_VIRTIO_GPU_MAX_OUTPUTS,
            QEMU_CAPS_VNC,
            QEMU_CAPS_DEVICE_VIRTIO_GPU_CCW);
    DO_TEST("video-none-device", NONE);

    DO_TEST_CAPS_LATEST("intel-iommu");
    DO_TEST_CAPS_VER("intel-iommu", "2.6.0");
    DO_TEST_CAPS_LATEST("intel-iommu-caching-mode");
    DO_TEST_CAPS_LATEST("intel-iommu-eim");
    DO_TEST_CAPS_LATEST("intel-iommu-device-iotlb");
    DO_TEST_CAPS_ARCH_LATEST("iommu-smmuv3", "aarch64");

    DO_TEST("cpu-check-none", NONE);
    DO_TEST("cpu-check-partial", NONE);
    DO_TEST("cpu-check-full", NONE);
    DO_TEST("cpu-check-default-none", NONE);
    DO_TEST("cpu-check-default-none2", NONE);
    DO_TEST("cpu-check-default-partial", NONE);
    DO_TEST("cpu-check-default-partial2", NONE);
    DO_TEST("vmcoreinfo", NONE);

    DO_TEST("smartcard-host", NONE);
    DO_TEST("smartcard-host-certificates", NONE);
    DO_TEST("smartcard-host-certificates-database", NONE);
    DO_TEST("smartcard-passthrough-tcp", NONE);
    DO_TEST("smartcard-passthrough-spicevmc", NONE);
    DO_TEST("smartcard-controller", NONE);

    DO_TEST("pseries-cpu-compat-power9",
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE);
    DO_TEST("pseries-cpu-compat",
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE);
    DO_TEST("pseries-cpu-exact",
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE);

    DO_TEST("user-aliases", QEMU_CAPS_QCOW2_LUKS);
    DO_TEST("input-virtio-ccw",
            QEMU_CAPS_CCW,
            QEMU_CAPS_VIRTIO_KEYBOARD,
            QEMU_CAPS_VIRTIO_MOUSE,
            QEMU_CAPS_VIRTIO_TABLET,
            QEMU_CAPS_DEVICE_VIRTIO_KEYBOARD_CCW,
            QEMU_CAPS_DEVICE_VIRTIO_MOUSE_CCW,
            QEMU_CAPS_DEVICE_VIRTIO_TABLET_CCW);

    DO_TEST("tseg-explicit-size",
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_MACHINE_SMM_OPT,
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_MCH_EXTENDED_TSEG_MBYTES);

# define DO_TEST_STATUS(_name) \
    do { \
        static struct testQemuInfo info = { \
            .name = _name, \
        }; \
        if (testQemuInfoSetArgs(&info, capslatest, \
                                ARG_QEMU_CAPS, QEMU_CAPS_LAST, \
                                ARG_END) < 0 || \
            qemuTestCapsCacheInsert(driver.qemuCapsCache, info.qemuCaps) < 0 || \
            testInfoSetStatusPaths(&info) < 0) { \
            VIR_TEST_DEBUG("Failed to generate status test data for '%s'", _name); \
            return -1; \
        } \
\
        if (virTestRun("QEMU status XML-2-XML " _name, \
                       testCompareStatusXMLToXMLFiles, &info) < 0) \
            ret = -1; \
\
        testQemuInfoClear(&info); \
    } while (0)


    DO_TEST_STATUS("blockjob-mirror");
    DO_TEST_STATUS("vcpus-multi");
    DO_TEST_STATUS("modern");
    DO_TEST_STATUS("migration-out-nbd");
    DO_TEST_STATUS("migration-in-params");
    DO_TEST_STATUS("migration-out-params");
    DO_TEST_STATUS("migration-out-nbd-tls");
    DO_TEST_STATUS("disk-secinfo-upgrade");

    DO_TEST("vhost-vsock", QEMU_CAPS_DEVICE_VHOST_VSOCK);
    DO_TEST("vhost-vsock-auto", QEMU_CAPS_DEVICE_VHOST_VSOCK);
    DO_TEST("vhost-vsock-ccw", QEMU_CAPS_DEVICE_VHOST_VSOCK,
            QEMU_CAPS_CCW);
    DO_TEST("vhost-vsock-ccw-auto", QEMU_CAPS_DEVICE_VHOST_VSOCK,
            QEMU_CAPS_CCW);

    DO_TEST("riscv64-virt",
            QEMU_CAPS_DEVICE_VIRTIO_MMIO);
    DO_TEST("riscv64-virt-pci",
            QEMU_CAPS_OBJECT_GPEX);

    DO_TEST_CAPS_LATEST("virtio-transitional");
    DO_TEST_CAPS_LATEST("virtio-non-transitional");

    /* Simple headless guests for various architectures */
    DO_TEST_CAPS_ARCH_LATEST("aarch64-virt-headless", "aarch64");
    DO_TEST_CAPS_ARCH_LATEST("ppc64-pseries-headless", "ppc64");
    DO_TEST_CAPS_ARCH_LATEST("riscv64-virt-headless", "riscv64");
    DO_TEST_CAPS_ARCH_LATEST("s390x-ccw-headless", "s390x");
    DO_TEST_CAPS_ARCH_LATEST("x86_64-pc-headless", "x86_64");
    DO_TEST_CAPS_ARCH_LATEST("x86_64-q35-headless", "x86_64");

    /* Simple guests with graphics for various architectures */
    DO_TEST_CAPS_ARCH_LATEST("aarch64-virt-graphics", "aarch64");
    DO_TEST_CAPS_ARCH_LATEST("ppc64-pseries-graphics", "ppc64");
    DO_TEST_CAPS_ARCH_LATEST("riscv64-virt-graphics", "riscv64");
    DO_TEST_CAPS_ARCH_LATEST("s390x-ccw-graphics", "s390x");
    DO_TEST_CAPS_ARCH_LATEST("x86_64-pc-graphics", "x86_64");
    DO_TEST_CAPS_ARCH_LATEST("x86_64-q35-graphics", "x86_64");

    if (getenv("LIBVIRT_SKIP_CLEANUP") == NULL)
        virFileDeleteTree(fakerootdir);

    virHashFree(capslatest);
    qemuTestDriverFree(&driver);
    VIR_FREE(fakerootdir);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN_PRELOAD(mymain,
                      abs_builddir "/.libs/virpcimock.so",
                      abs_builddir "/.libs/virrandommock.so",
                      abs_builddir "/.libs/virdeterministichashmock.so")

#else

int
main(void)
{
    return EXIT_AM_SKIP;
}

#endif /* WITH_QEMU */
