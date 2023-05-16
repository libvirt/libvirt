#include <config.h>

#include <unistd.h>

#include <sys/types.h>
#include <fcntl.h>

#include "testutils.h"

#include "internal.h"
#include "testutilsqemu.h"
#include "virfilewrapper.h"
#include "configmake.h"

#define LIBVIRT_QEMU_CAPSPRIV_H_ALLOW
#include "qemu/qemu_capspriv.h"

#define VIR_FROM_THIS VIR_FROM_NONE

static virQEMUDriver driver;

enum {
    WHEN_INACTIVE = 1,
    WHEN_ACTIVE = 2,
    WHEN_BOTH = 3,
};


static int
testXML2XMLCommon(const struct testQemuInfo *info)
{
    if (testQemuInfoInitArgs((struct testQemuInfo *) info) < 0)
        return -1;

    virFileCacheClear(driver.qemuCapsCache);

    if (qemuTestCapsCacheInsert(driver.qemuCapsCache, info->qemuCaps) < 0)
        return -1;

    return 0;
}


static int
testXML2XMLActive(const void *opaque)
{
    const struct testQemuInfo *info = opaque;

    if (testXML2XMLCommon(info) < 0 ||
        testCompareDomXML2XMLFiles(driver.caps, driver.xmlopt,
                                   info->infile, info->outfile, true,
                                   info->parseFlags,
                                   TEST_COMPARE_DOM_XML2XML_RESULT_SUCCESS) < 0) {
        return -1;
    }

    return 0;
}


static int
testXML2XMLInactive(const void *opaque)
{
    const struct testQemuInfo *info = opaque;

    if (testXML2XMLCommon(info) < 0 ||
        testCompareDomXML2XMLFiles(driver.caps, driver.xmlopt,
                                   info->infile, info->outfile, false,
                                   info->parseFlags,
                                   TEST_COMPARE_DOM_XML2XML_RESULT_SUCCESS) < 0) {
        return -1;
    }

    return 0;
}


static void
testInfoSetPaths(struct testQemuInfo *info,
                 const char *suffix,
                 int when)
{
    VIR_FREE(info->infile);
    VIR_FREE(info->outfile);

    info->infile = g_strdup_printf("%s/qemuxml2argvdata/%s.xml", abs_srcdir,
                                   info->name);

    info->outfile = g_strdup_printf("%s/qemuxml2xmloutdata/%s-%s%s.xml",
                                    abs_srcdir, info->name,
                                    when == WHEN_ACTIVE ? "active" : "inactive", suffix);

    if (!virFileExists(info->outfile)) {
        VIR_FREE(info->outfile);

        info->outfile = g_strdup_printf("%s/qemuxml2xmloutdata/%s%s.xml",
                                        abs_srcdir, info->name, suffix);
    }
}


static int
mymain(void)
{
    int ret = 0;
    g_autoptr(virQEMUDriverConfig) cfg = NULL;
    g_autoptr(GHashTable) capslatest = testQemuGetLatestCaps();
    g_autoptr(GHashTable) capscache = virHashNew(virObjectUnref);
    g_autoptr(virConnect) conn = NULL;
    struct testQemuConf testConf = { .capslatest = capslatest,
                                     .capscache = capscache,
                                     .qapiSchemaCache = NULL };

    if (!capslatest)
        return EXIT_FAILURE;

    /* Required for tpm-emulator tests
     */
    virFileWrapperAddPrefix(SYSCONFDIR "/qemu/firmware",
                            abs_srcdir "/qemufirmwaredata/etc/qemu/firmware");
    virFileWrapperAddPrefix(PREFIX "/share/qemu/firmware",
                            abs_srcdir "/qemufirmwaredata/usr/share/qemu/firmware");
    virFileWrapperAddPrefix("/home/user/.config/qemu/firmware",
                            abs_srcdir "/qemufirmwaredata/home/user/.config/qemu/firmware");

    if (qemuTestDriverInit(&driver) < 0)
        return EXIT_FAILURE;

    cfg = virQEMUDriverGetConfig(&driver);

    if (!(conn = virGetConnect()))
        goto cleanup;

    virSetConnectInterface(conn);
    virSetConnectNetwork(conn);
    virSetConnectNWFilter(conn);
    virSetConnectNodeDev(conn);
    virSetConnectSecret(conn);
    virSetConnectStorage(conn);

#define DO_TEST_FULL(_name, suffix, when, ...) \
    do { \
        static struct testQemuInfo info = { \
            .name = _name, \
        }; \
        testQemuInfoSetArgs(&info, &testConf, __VA_ARGS__); \
 \
        if (when & WHEN_INACTIVE) { \
            testInfoSetPaths(&info, suffix, WHEN_INACTIVE); \
            virTestRunLog(&ret, "QEMU XML-2-XML-inactive " _name, testXML2XMLInactive, &info); \
        } \
 \
        if (when & WHEN_ACTIVE) { \
            testInfoSetPaths(&info, suffix, WHEN_ACTIVE); \
            virTestRunLog(&ret, "QEMU XML-2-XML-active " _name, testXML2XMLActive, &info); \
        } \
        testQemuInfoClear(&info); \
    } while (0)

#define DO_TEST_CAPS_INTERNAL(name, arch, ver, ...) \
    DO_TEST_FULL(name, "." arch "-" ver, WHEN_BOTH, \
                 ARG_CAPS_ARCH, arch, \
                 ARG_CAPS_VER, ver, \
                 __VA_ARGS__, \
                 ARG_END)

#define DO_TEST_CAPS_ARCH_LATEST_FULL(name, arch, ...) \
    DO_TEST_CAPS_INTERNAL(name, arch, "latest", __VA_ARGS__)

#define DO_TEST_CAPS_ARCH_VER_FULL(name, arch, ver, ...) \
    DO_TEST_CAPS_INTERNAL(name, arch, ver, __VA_ARGS__)

#define DO_TEST_CAPS_ARCH_LATEST(name, arch) \
    DO_TEST_CAPS_ARCH_LATEST_FULL(name, arch, ARG_END)

#define DO_TEST_CAPS_ARCH_LATEST_ABI_UPDATE(name, arch) \
    DO_TEST_CAPS_ARCH_LATEST_FULL(name, arch, \
                                  ARG_PARSEFLAGS, VIR_DOMAIN_DEF_PARSE_ABI_UPDATE, \
                                  ARG_END)

#define DO_TEST_CAPS_ARCH_VER(name, arch, ver) \
    DO_TEST_CAPS_ARCH_VER_FULL(name, arch, ver, ARG_END)

#define DO_TEST_CAPS_LATEST(name) \
    DO_TEST_CAPS_ARCH_LATEST(name, "x86_64")

#define DO_TEST_CAPS_VER(name, ver) \
    DO_TEST_CAPS_ARCH_VER(name, "x86_64", ver)

#define DO_TEST(name, ...) \
    DO_TEST_FULL(name, "", WHEN_BOTH, \
                 ARG_QEMU_CAPS, __VA_ARGS__, QEMU_CAPS_LAST, ARG_END)
#define DO_TEST_NOCAPS(name) \
    DO_TEST_FULL(name, "", WHEN_BOTH, ARG_END)

    /* Unset or set all envvars here that are copied in qemudBuildCommandLine
     * using ADD_ENV_COPY, otherwise these tests may fail due to unexpected
     * values for these envvars */
    g_setenv("PATH", "/bin", TRUE);
    g_unsetenv("QEMU_AUDIO_DRV");
    g_unsetenv("SDL_AUDIODRIVER");

    DO_TEST_NOCAPS("minimal");
    DO_TEST_CAPS_LATEST("genid");
    DO_TEST_CAPS_LATEST("genid-auto");
    DO_TEST_NOCAPS("machine-core-on");
    DO_TEST_NOCAPS("machine-core-off");
    DO_TEST_CAPS_LATEST("machine-smm-on");
    DO_TEST_CAPS_LATEST("machine-smm-off");
    DO_TEST_CAPS_ARCH_LATEST("machine-loadparm-hostdev", "s390x");
    DO_TEST_CAPS_ARCH_LATEST("machine-loadparm-multiple-disks-nets-s390", "s390x");
    DO_TEST_NOCAPS("default-kvm-host-arch");
    DO_TEST_NOCAPS("default-qemu-host-arch");
    DO_TEST_NOCAPS("boot-cdrom");
    DO_TEST_NOCAPS("boot-network");
    DO_TEST_NOCAPS("boot-floppy");
    DO_TEST("boot-floppy-q35",
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI);
    DO_TEST_NOCAPS("boot-multi");
    DO_TEST_NOCAPS("boot-menu-enable-with-timeout");
    DO_TEST_NOCAPS("boot-menu-disable");
    DO_TEST_NOCAPS("boot-menu-disable-with-timeout");
    DO_TEST_NOCAPS("boot-order");

    DO_TEST_NOCAPS("reboot-timeout-enabled");
    DO_TEST_NOCAPS("reboot-timeout-disabled");

    DO_TEST_NOCAPS("clock-utc");
    DO_TEST_NOCAPS("clock-localtime");
    DO_TEST_NOCAPS("cpu-empty");
    DO_TEST_NOCAPS("cpu-kvmclock");
    DO_TEST_NOCAPS("cpu-host-kvmclock");
    DO_TEST_NOCAPS("cpu-host-passthrough-features");
    DO_TEST_NOCAPS("cpu-host-model-features");
    DO_TEST_NOCAPS("cpu-host-model-vendor");
    DO_TEST("clock-catchup", QEMU_CAPS_KVM_PIT_TICK_POLICY);
    DO_TEST_NOCAPS("kvmclock");
    DO_TEST_NOCAPS("clock-timer-hyperv-rtc");
    DO_TEST_CAPS_ARCH_LATEST("clock-timer-armvtimer", "aarch64");
    DO_TEST_NOCAPS("clock-realtime");
    DO_TEST_CAPS_LATEST("clock-absolute");

    DO_TEST_NOCAPS("cpu-eoi-disabled");
    DO_TEST_NOCAPS("cpu-eoi-enabled");
    DO_TEST_NOCAPS("eoi-disabled");
    DO_TEST_NOCAPS("eoi-enabled");
    DO_TEST_NOCAPS("pv-spinlock-disabled");
    DO_TEST_NOCAPS("pv-spinlock-enabled");

    DO_TEST_NOCAPS("hyperv");
    DO_TEST_NOCAPS("hyperv-off");
    DO_TEST_NOCAPS("hyperv-panic");
    DO_TEST_NOCAPS("hyperv-passthrough");
    DO_TEST_NOCAPS("hyperv-stimer-direct");

    DO_TEST_NOCAPS("kvm-features");
    DO_TEST_NOCAPS("kvm-features-off");

    DO_TEST_NOCAPS("pmu-feature");
    DO_TEST_NOCAPS("pmu-feature-off");

    DO_TEST_NOCAPS("pages-discard");
    DO_TEST_CAPS_LATEST("pages-discard-hugepages");
    DO_TEST_CAPS_LATEST("pages-dimm-discard");
    DO_TEST_CAPS_LATEST("hugepages-default");
    DO_TEST_CAPS_LATEST("hugepages-default-2M");
    DO_TEST_CAPS_LATEST("hugepages-default-system-size");
    DO_TEST_CAPS_LATEST("hugepages-nodeset");
    DO_TEST_CAPS_LATEST("hugepages-numa-default-2M");
    DO_TEST_CAPS_LATEST("hugepages-numa-default-dimm");
    DO_TEST_CAPS_LATEST("hugepages-numa-nodeset");
    DO_TEST_CAPS_LATEST("hugepages-numa-nodeset-part");
    DO_TEST_CAPS_LATEST("hugepages-shared");
    DO_TEST_CAPS_LATEST("hugepages-memaccess");
    DO_TEST_CAPS_LATEST("hugepages-memaccess2");
    DO_TEST_CAPS_LATEST("hugepages-memaccess3");
    DO_TEST_CAPS_LATEST("hugepages-nvdimm");
    DO_TEST_NOCAPS("nosharepages");
    DO_TEST_NOCAPS("restore-v2");
    DO_TEST_NOCAPS("migrate");
    DO_TEST_NOCAPS("qemu-ns-no-env");
    DO_TEST_CAPS_LATEST("qemu-ns");
    DO_TEST_NOCAPS("disk-aio");
    DO_TEST_CAPS_LATEST("disk-aio-io_uring");
    DO_TEST_NOCAPS("disk-cdrom");
    DO_TEST_CAPS_LATEST("disk-cdrom-empty-network-invalid");
    DO_TEST_CAPS_LATEST("disk-cdrom-network");
    DO_TEST("disk-cdrom-bus-other", QEMU_CAPS_DEVICE_USB_STORAGE);
    DO_TEST_NOCAPS("disk-floppy");
    DO_TEST("disk-usb-device", QEMU_CAPS_DEVICE_USB_STORAGE);
    DO_TEST_NOCAPS("disk-virtio");
    DO_TEST_NOCAPS("floppy-drive-fat");
    DO_TEST_CAPS_LATEST("disk-virtio-queues");
    DO_TEST_NOCAPS("disk-boot-disk");
    DO_TEST_NOCAPS("disk-boot-cdrom");
    DO_TEST_NOCAPS("disk-error-policy");
    DO_TEST_CAPS_LATEST("disk-transient");
    DO_TEST_NOCAPS("disk-fmt-qcow");
    DO_TEST_CAPS_LATEST("disk-cache");
    DO_TEST_CAPS_LATEST("disk-metadata-cache");
    DO_TEST_NOCAPS("disk-network-nbd");
    DO_TEST("disk-network-iscsi", QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_SCSI_BLOCK);
    DO_TEST_NOCAPS("disk-network-gluster");
    DO_TEST_NOCAPS("disk-network-rbd");
    DO_TEST_CAPS_LATEST("disk-network-rbd-encryption");
    DO_TEST_CAPS_LATEST("disk-network-rbd-encryption-layering");
    DO_TEST_CAPS_LATEST("disk-network-rbd-encryption-luks-any");
    DO_TEST_NOCAPS("disk-network-source-auth");
    DO_TEST_NOCAPS("disk-network-sheepdog");
    DO_TEST_NOCAPS("disk-network-vxhs");
    DO_TEST_CAPS_LATEST("disk-network-nfs");
    DO_TEST_NOCAPS("disk-network-tlsx509-nbd");
    DO_TEST_CAPS_LATEST("disk-network-tlsx509-nbd-hostname");
    DO_TEST_NOCAPS("disk-network-tlsx509-vxhs");
    DO_TEST_CAPS_LATEST("disk-nvme");
    DO_TEST_CAPS_LATEST("disk-vhostuser");
    DO_TEST_CAPS_LATEST("disk-sata-device");
    DO_TEST_CAPS_LATEST("disk-scsi");
    DO_TEST("disk-virtio-scsi-reservations",
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_PR_MANAGER_HELPER,
            QEMU_CAPS_SCSI_BLOCK);
    DO_TEST("controller-virtio-scsi", QEMU_CAPS_VIRTIO_SCSI);
    DO_TEST_CAPS_ARCH_LATEST("disk-virtio-s390-zpci", "s390x");
    DO_TEST_NOCAPS("disk-mirror-old");
    DO_TEST_NOCAPS("disk-mirror");
    DO_TEST_NOCAPS("disk-active-commit");
    DO_TEST("graphics-listen-network",
            QEMU_CAPS_DEVICE_CIRRUS_VGA,
            QEMU_CAPS_VNC);
    DO_TEST("graphics-vnc",
            QEMU_CAPS_DEVICE_CIRRUS_VGA,
            QEMU_CAPS_VNC);
    DO_TEST("graphics-vnc-websocket",
            QEMU_CAPS_DEVICE_CIRRUS_VGA,
            QEMU_CAPS_VNC);
    DO_TEST("graphics-vnc-sasl",
            QEMU_CAPS_DEVICE_CIRRUS_VGA,
            QEMU_CAPS_VNC);
    DO_TEST("graphics-vnc-tls",
            QEMU_CAPS_DEVICE_CIRRUS_VGA,
            QEMU_CAPS_VNC);
    DO_TEST("graphics-vnc-no-listen-attr",
            QEMU_CAPS_DEVICE_CIRRUS_VGA,
            QEMU_CAPS_VNC);
    DO_TEST("graphics-vnc-remove-generated-socket",
            QEMU_CAPS_DEVICE_CIRRUS_VGA,
            QEMU_CAPS_VNC);
    cfg->vncAutoUnixSocket = true;
    DO_TEST("graphics-vnc-auto-socket-cfg",
            QEMU_CAPS_DEVICE_CIRRUS_VGA,
            QEMU_CAPS_VNC);
    cfg->vncAutoUnixSocket = false;
    DO_TEST("graphics-vnc-socket",
            QEMU_CAPS_DEVICE_CIRRUS_VGA,
            QEMU_CAPS_VNC);
    DO_TEST("graphics-vnc-auto-socket",
            QEMU_CAPS_DEVICE_CIRRUS_VGA,
            QEMU_CAPS_VNC);
    DO_TEST("graphics-vnc-egl-headless",
            QEMU_CAPS_DEVICE_CIRRUS_VGA,
            QEMU_CAPS_VNC,
            QEMU_CAPS_EGL_HEADLESS);

    DO_TEST("graphics-dbus",
            QEMU_CAPS_DEVICE_CIRRUS_VGA,
            QEMU_CAPS_DISPLAY_DBUS);
    DO_TEST("graphics-dbus-address",
            QEMU_CAPS_DEVICE_CIRRUS_VGA,
            QEMU_CAPS_DISPLAY_DBUS);
    DO_TEST("graphics-dbus-p2p",
            QEMU_CAPS_DEVICE_CIRRUS_VGA,
            QEMU_CAPS_DISPLAY_DBUS);
    DO_TEST("graphics-dbus-audio",
            QEMU_CAPS_DEVICE_CIRRUS_VGA,
            QEMU_CAPS_DISPLAY_DBUS);
    DO_TEST("graphics-dbus-chardev",
            QEMU_CAPS_DEVICE_CIRRUS_VGA,
            QEMU_CAPS_DISPLAY_DBUS);

    DO_TEST_CAPS_ARCH_LATEST("default-video-type-aarch64", "aarch64");
    DO_TEST_CAPS_ARCH_LATEST("default-video-type-ppc64", "ppc64");
    DO_TEST_CAPS_ARCH_LATEST("default-video-type-riscv64", "riscv64");
    DO_TEST_CAPS_ARCH_LATEST("default-video-type-s390x", "s390x");
    DO_TEST("default-video-type-x86_64-caps-test-0",
            QEMU_CAPS_DEVICE_VGA,
            QEMU_CAPS_SPICE);
    DO_TEST("default-video-type-x86_64-caps-test-1",
            QEMU_CAPS_DEVICE_CIRRUS_VGA,
            QEMU_CAPS_SPICE);

    DO_TEST("graphics-sdl", QEMU_CAPS_DEVICE_VGA, QEMU_CAPS_SDL);
    DO_TEST("graphics-sdl-fullscreen", QEMU_CAPS_DEVICE_CIRRUS_VGA, QEMU_CAPS_SDL);

    cfg->spiceTLS = true;
    DO_TEST_CAPS_LATEST("graphics-spice");
    DO_TEST_CAPS_LATEST("graphics-spice-compression");
    DO_TEST_CAPS_LATEST("graphics-spice-qxl-vga");
    DO_TEST_CAPS_LATEST("graphics-spice-socket");
    DO_TEST_CAPS_LATEST("graphics-spice-auto-socket");
    cfg->spiceAutoUnixSocket = true;
    DO_TEST_CAPS_LATEST("graphics-spice-auto-socket-cfg");
    cfg->spiceAutoUnixSocket = false;
    cfg->spiceTLS = false;
    DO_TEST_CAPS_LATEST("graphics-spice-egl-headless");
    DO_TEST_CAPS_LATEST("graphics-spice-timeout");

    DO_TEST("graphics-egl-headless-rendernode",
            QEMU_CAPS_DEVICE_CIRRUS_VGA,
            QEMU_CAPS_EGL_HEADLESS_RENDERNODE,
            QEMU_CAPS_EGL_HEADLESS);

    DO_TEST_NOCAPS("input-usbmouse");
    DO_TEST_NOCAPS("input-usbtablet");
    DO_TEST_NOCAPS("misc-acpi");
    DO_TEST("misc-disable-s3", QEMU_CAPS_PIIX_DISABLE_S3);
    DO_TEST_CAPS_LATEST("pc-i440fx-acpi-root-hotplug-disable");
    DO_TEST_CAPS_LATEST("pc-i440fx-acpi-root-hotplug-enable");
    DO_TEST("misc-disable-suspends",
            QEMU_CAPS_PIIX_DISABLE_S3,
            QEMU_CAPS_PIIX_DISABLE_S4);
    DO_TEST("misc-enable-s4", QEMU_CAPS_PIIX_DISABLE_S4);
    DO_TEST_NOCAPS("misc-no-reboot");
    DO_TEST_NOCAPS("misc-uuid");
    DO_TEST_NOCAPS("net-vhostuser");
    DO_TEST_NOCAPS("net-user");
    DO_TEST_NOCAPS("net-user-addr");
    DO_TEST_CAPS_LATEST("net-user-passt");
    DO_TEST_NOCAPS("net-virtio");
    DO_TEST_NOCAPS("net-virtio-device");
    DO_TEST_NOCAPS("net-virtio-disable-offloads");
    DO_TEST_NOCAPS("net-eth");
    DO_TEST_NOCAPS("net-eth-ifname");
    DO_TEST_NOCAPS("net-eth-hostip");
    DO_TEST_NOCAPS("net-eth-unmanaged-tap");
    DO_TEST_NOCAPS("net-virtio-network-portgroup");
    DO_TEST_NOCAPS("net-virtio-rxtxqueuesize");
    DO_TEST("net-virtio-teaming",
            QEMU_CAPS_DEVICE_VFIO_PCI);
    DO_TEST("net-virtio-teaming-network",
            QEMU_CAPS_DEVICE_VFIO_PCI);
    DO_TEST("net-virtio-teaming-hostdev",
            QEMU_CAPS_DEVICE_VFIO_PCI);
    DO_TEST_CAPS_LATEST("net-isolated-port");
    DO_TEST_NOCAPS("net-hostdev");
    DO_TEST_NOCAPS("net-hostdev-bootorder");
    DO_TEST("net-hostdev-vfio", QEMU_CAPS_DEVICE_VFIO_PCI);
    DO_TEST_NOCAPS("net-midonet");
    DO_TEST_NOCAPS("net-openvswitch");
    DO_TEST_CAPS_LATEST("sound-device");
    DO_TEST_NOCAPS("watchdog");
    DO_TEST_CAPS_LATEST("watchdog-q35-multiple");
    DO_TEST("net-bandwidth", QEMU_CAPS_DEVICE_VGA, QEMU_CAPS_VNC);
    DO_TEST("net-bandwidth2", QEMU_CAPS_DEVICE_VGA, QEMU_CAPS_VNC);
    DO_TEST_NOCAPS("net-mtu");
    DO_TEST_NOCAPS("net-coalesce");
    DO_TEST_NOCAPS("net-many-models");
    DO_TEST("net-vdpa", QEMU_CAPS_NETDEV_VHOST_VDPA);
    DO_TEST("net-vdpa-multiqueue", QEMU_CAPS_NETDEV_VHOST_VDPA);
    DO_TEST_CAPS_LATEST("net-virtio-rss");

    DO_TEST_NOCAPS("serial-tcp-tlsx509-chardev");
    DO_TEST_NOCAPS("serial-tcp-tlsx509-chardev-notls");

    cfg->spiceTLS = true;
    DO_TEST("serial-spiceport",
            QEMU_CAPS_DEVICE_QXL,
            QEMU_CAPS_SPICE);
    cfg->spiceTLS = false;

    DO_TEST_NOCAPS("serial-debugcon");
    DO_TEST_NOCAPS("console-compat");
    DO_TEST_NOCAPS("console-compat2");
    DO_TEST_NOCAPS("console-virtio-many");
    DO_TEST_NOCAPS("channel-guestfwd");
    DO_TEST_NOCAPS("channel-virtio");
    DO_TEST_NOCAPS("channel-virtio-state");

    DO_TEST_NOCAPS("channel-unix-source-path");

    DO_TEST_CAPS_LATEST("hostdev-usb-address");
    DO_TEST_CAPS_LATEST("hostdev-pci-address");
    DO_TEST("hostdev-pci-address-unassigned", QEMU_CAPS_DEVICE_VFIO_PCI);
    DO_TEST("hostdev-pci-multifunction", QEMU_CAPS_DEVICE_VFIO_PCI);
    DO_TEST("hostdev-vfio", QEMU_CAPS_DEVICE_VFIO_PCI);
    DO_TEST_CAPS_ARCH_LATEST("hostdev-vfio-zpci", "s390x");
    DO_TEST_CAPS_ARCH_LATEST("hostdev-vfio-zpci-multidomain-many", "s390x");
    DO_TEST_CAPS_ARCH_LATEST("hostdev-vfio-zpci-autogenerate", "s390x");
    DO_TEST_CAPS_ARCH_LATEST("hostdev-vfio-zpci-autogenerate-uids", "s390x");
    DO_TEST_CAPS_ARCH_LATEST("hostdev-vfio-zpci-autogenerate-fids", "s390x");
    DO_TEST_CAPS_ARCH_LATEST("hostdev-vfio-zpci-boundaries", "s390x");
    DO_TEST_CAPS_ARCH_LATEST("hostdev-vfio-zpci-ccw-memballoon", "s390x");
    DO_TEST("hostdev-mdev-precreated", QEMU_CAPS_DEVICE_VFIO_PCI);
    DO_TEST("hostdev-mdev-display",
            QEMU_CAPS_DEVICE_QXL,
            QEMU_CAPS_VFIO_PCI_DISPLAY,
            QEMU_CAPS_DEVICE_VFIO_PCI,
            QEMU_CAPS_VNC);
    DO_TEST_CAPS_LATEST("hostdev-mdev-display-ramfb");
    DO_TEST_NOCAPS("pci-rom");
    DO_TEST_NOCAPS("pci-rom-disabled");
    DO_TEST_NOCAPS("pci-rom-disabled-invalid");
    DO_TEST_NOCAPS("pci-serial-dev-chardev");

    DO_TEST_CAPS_LATEST("disk-slices");
    DO_TEST_CAPS_LATEST("disk-rotation");

    DO_TEST_CAPS_LATEST("encrypted-disk");
    DO_TEST_CAPS_LATEST("encrypted-disk-usage");
    DO_TEST_CAPS_LATEST("luks-disks");
    DO_TEST_CAPS_LATEST("luks-disks-source");
    DO_TEST_CAPS_LATEST("luks-disks-source-qcow2");
    DO_TEST_NOCAPS("memtune");
    DO_TEST_NOCAPS("memtune-unlimited");
    DO_TEST_NOCAPS("blkiotune");
    DO_TEST_NOCAPS("blkiotune-device");
    DO_TEST_CAPS_LATEST("cputune");
    DO_TEST_CAPS_LATEST("cputune-zero-shares");
    DO_TEST_CAPS_LATEST("cputune-numatune");
    DO_TEST_CAPS_LATEST("vcpu-placement-static");
    DO_TEST_CAPS_LATEST("cputune-cpuset-big-id");
    DO_TEST_CAPS_LATEST("numavcpus-topology-mismatch");

    DO_TEST_NOCAPS("smp");
    DO_TEST_CAPS_LATEST("iothreads-ids");
    DO_TEST_CAPS_LATEST("iothreads-ids-pool-sizes");
    DO_TEST_CAPS_LATEST("iothreads-ids-partial");
    DO_TEST_CAPS_LATEST("iothreads-disk");
    DO_TEST_CAPS_ARCH_LATEST("iothreads-disk-virtio-ccw", "s390x");
    DO_TEST_CAPS_LATEST("iothreads-virtio-scsi-pci");
    DO_TEST_CAPS_ARCH_LATEST("iothreads-virtio-scsi-ccw", "s390x");
    DO_TEST_NOCAPS("lease");
    DO_TEST_NOCAPS("event_idx");
    DO_TEST_NOCAPS("vhost_queues");
    DO_TEST_NOCAPS("interface-driver");
    DO_TEST_NOCAPS("net-server");
    DO_TEST_NOCAPS("virtio-lun");

    DO_TEST_NOCAPS("usb-none");
    DO_TEST_NOCAPS("usb-controller");
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
    DO_TEST_CAPS_ARCH_LATEST("ppc64-usb-controller", "ppc64");
    DO_TEST_CAPS_ARCH_LATEST("ppc64-usb-controller-legacy", "ppc64");
    DO_TEST("usb-port-missing", QEMU_CAPS_USB_HUB);
    DO_TEST("usb-redir", QEMU_CAPS_USB_REDIR,
            QEMU_CAPS_SPICE,
            QEMU_CAPS_DEVICE_CIRRUS_VGA);
    DO_TEST("usb-redir-filter",
            QEMU_CAPS_USB_REDIR,
            QEMU_CAPS_USB_REDIR_FILTER,
            QEMU_CAPS_SPICE,
            QEMU_CAPS_DEVICE_CIRRUS_VGA);
    DO_TEST("usb-redir-filter-version",
            QEMU_CAPS_USB_REDIR,
            QEMU_CAPS_USB_REDIR_FILTER,
            QEMU_CAPS_SPICE,
            QEMU_CAPS_DEVICE_CIRRUS_VGA);
    DO_TEST_CAPS_LATEST("blkdeviotune");
    DO_TEST_CAPS_LATEST("blkdeviotune-max");
    DO_TEST_CAPS_LATEST("blkdeviotune-group-num");
    DO_TEST_CAPS_LATEST("blkdeviotune-max-length");
    DO_TEST_CAPS_LATEST("controller-usb-order");
    DO_TEST_CAPS_ARCH_LATEST("ppc64-tpmproxy-single", "ppc64");
    DO_TEST_CAPS_ARCH_LATEST("ppc64-tpmproxy-with-tpm", "ppc64");

    DO_TEST_FULL("seclabel-dynamic-baselabel", "", WHEN_INACTIVE, ARG_END);
    DO_TEST_FULL("seclabel-dynamic-override", "", WHEN_INACTIVE, ARG_END);
    DO_TEST_FULL("seclabel-dynamic-labelskip", "", WHEN_INACTIVE, ARG_END);
    DO_TEST_FULL("seclabel-dynamic-relabel", "", WHEN_INACTIVE, ARG_END);
    DO_TEST_NOCAPS("seclabel-static");
    DO_TEST_NOCAPS("seclabel-static-labelskip");
    DO_TEST_NOCAPS("seclabel-none");
    DO_TEST_NOCAPS("seclabel-dac-none");
    DO_TEST_NOCAPS("seclabel-dynamic-none");
    DO_TEST_NOCAPS("seclabel-device-multiple");
    DO_TEST_FULL("seclabel-dynamic-none-relabel", "", WHEN_INACTIVE,
                 ARG_QEMU_CAPS, QEMU_CAPS_DEVICE_CIRRUS_VGA,
                 QEMU_CAPS_SPICE, QEMU_CAPS_LAST,
                 ARG_END);
    DO_TEST_NOCAPS("numad-static-vcpu-no-numatune");

    DO_TEST("disk-scsi-disk-vpd",
            QEMU_CAPS_SCSI_LSI, QEMU_CAPS_VIRTIO_SCSI, QEMU_CAPS_SCSI_DISK_WWN);
    DO_TEST_NOCAPS("disk-source-pool");
    DO_TEST_NOCAPS("disk-source-pool-mode");

    DO_TEST_CAPS_LATEST("disk-discard");
    DO_TEST_CAPS_LATEST("disk-detect-zeroes");

    DO_TEST_NOCAPS("disk-serial");

    DO_TEST_CAPS_ARCH_LATEST("disk-arm-virtio-sd", "aarch64");

    DO_TEST("virtio-rng-random",
            QEMU_CAPS_DEVICE_VIRTIO_RNG,
            QEMU_CAPS_OBJECT_RNG_RANDOM);
    DO_TEST("virtio-rng-egd",
            QEMU_CAPS_DEVICE_VIRTIO_RNG,
            QEMU_CAPS_OBJECT_RNG_EGD);
    DO_TEST_CAPS_LATEST("virtio-rng-builtin");

    DO_TEST_CAPS_ARCH_LATEST("pseries-nvram", "ppc64");
    DO_TEST_CAPS_ARCH_LATEST("pseries-panic-missing", "ppc64");
    DO_TEST_CAPS_ARCH_LATEST("pseries-panic-no-address", "ppc64");

    DO_TEST_CAPS_ARCH_LATEST("pseries-phb-simple", "ppc64");
    DO_TEST_CAPS_ARCH_LATEST("pseries-phb-default-missing", "ppc64");
    DO_TEST_CAPS_ARCH_LATEST("pseries-phb-numa-node", "ppc64");

    DO_TEST_CAPS_ARCH_LATEST("pseries-many-devices", "ppc64");
    DO_TEST_CAPS_ARCH_LATEST("pseries-many-buses-1", "ppc64");
    DO_TEST_CAPS_ARCH_LATEST("pseries-many-buses-2", "ppc64");
    DO_TEST_CAPS_ARCH_LATEST("pseries-hostdevs-1", "ppc64");
    DO_TEST_CAPS_ARCH_LATEST("pseries-hostdevs-2", "ppc64");
    DO_TEST_CAPS_ARCH_LATEST("pseries-hostdevs-3", "ppc64");

    DO_TEST_CAPS_ARCH_LATEST("pseries-features", "ppc64");

    DO_TEST_CAPS_ARCH_LATEST("pseries-serial-native", "ppc64");
    DO_TEST_CAPS_ARCH_LATEST("pseries-serial+console-native", "ppc64");
    DO_TEST_CAPS_ARCH_LATEST("pseries-serial-compat", "ppc64");
    DO_TEST_CAPS_ARCH_LATEST("pseries-serial-pci", "ppc64");
    DO_TEST_CAPS_ARCH_LATEST("pseries-serial-usb", "ppc64");
    DO_TEST_CAPS_ARCH_LATEST("pseries-console-native", "ppc64");
    DO_TEST_CAPS_ARCH_LATEST("pseries-console-virtio", "ppc64");

    DO_TEST_CAPS_ARCH_LATEST("mach-virt-serial-native", "aarch64");
    DO_TEST_CAPS_ARCH_LATEST("mach-virt-serial+console-native", "aarch64");
    DO_TEST_CAPS_ARCH_LATEST("mach-virt-serial-compat", "aarch64");
    DO_TEST_CAPS_ARCH_LATEST("mach-virt-serial-pci", "aarch64");
    DO_TEST_CAPS_ARCH_LATEST("mach-virt-serial-usb", "aarch64");
    DO_TEST_CAPS_ARCH_LATEST("mach-virt-console-native", "aarch64");
    DO_TEST_CAPS_ARCH_LATEST("mach-virt-console-virtio", "aarch64");

    DO_TEST_NOCAPS("balloon-device-auto");
    DO_TEST_NOCAPS("balloon-device-period");
    DO_TEST_NOCAPS("channel-virtio-auto");
    DO_TEST_NOCAPS("console-compat-auto");
    DO_TEST("disk-scsi-device-auto",
            QEMU_CAPS_SCSI_LSI);
    DO_TEST_NOCAPS("console-virtio");
    DO_TEST_NOCAPS("serial-target-port-auto");
    DO_TEST("graphics-listen-network2",
            QEMU_CAPS_DEVICE_CIRRUS_VGA,
            QEMU_CAPS_VNC);
    DO_TEST_NOCAPS("numad-auto-vcpu-no-numatune");
    DO_TEST_NOCAPS("numad-auto-memory-vcpu-no-cpuset-and-placement");
    DO_TEST_NOCAPS("numad-auto-memory-vcpu-cpuset");
    DO_TEST_NOCAPS("usb-ich9-ehci-addr");
    DO_TEST_NOCAPS("disk-copy_on_read");
    DO_TEST_CAPS_LATEST("tpm-passthrough");
    DO_TEST_CAPS_LATEST("tpm-passthrough-crb");
    DO_TEST_CAPS_LATEST("tpm-emulator");
    DO_TEST_CAPS_ARCH_LATEST("tpm-emulator-spapr", "ppc64");
    DO_TEST_CAPS_LATEST("tpm-emulator-tpm2");
    DO_TEST_CAPS_LATEST("tpm-emulator-tpm2-enc");
    DO_TEST_CAPS_LATEST("tpm-emulator-tpm2-pstate");
    DO_TEST_CAPS_ARCH_LATEST("aarch64-tpm", "aarch64");
    DO_TEST_CAPS_LATEST("tpm-external");

    DO_TEST_NOCAPS("metadata");
    DO_TEST_NOCAPS("metadata-duplicate");

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
    DO_TEST("pci-autofill-addr", QEMU_CAPS_DEVICE_CIRRUS_VGA);

    DO_TEST("q35",
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_ICH9_USB_EHCI1,
            QEMU_CAPS_DEVICE_QXL);
    DO_TEST("q35-usb2",
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_ICH9_USB_EHCI1,
            QEMU_CAPS_DEVICE_QXL);
    DO_TEST("q35-usb2-multi",
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_ICH9_USB_EHCI1,
            QEMU_CAPS_DEVICE_QXL);
    DO_TEST("q35-usb2-reorder",
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_ICH9_USB_EHCI1,
            QEMU_CAPS_DEVICE_QXL);
    DO_TEST_CAPS_LATEST("q35-pcie");
    /* same as q35-pcie, but all PCI controllers are added automatically */
    DO_TEST_CAPS_LATEST("q35-pcie-autoadd");
    DO_TEST_CAPS_LATEST("q35-default-devices-only");
    DO_TEST_CAPS_LATEST("q35-multifunction");
    DO_TEST_CAPS_LATEST("q35-virt-manager-basic");
    DO_TEST("pcie-root",
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_DEVICE_QXL);

    /* Test automatic and manual setting of pcie-root-port attributes */
    DO_TEST("pcie-root-port",
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_DEVICE_QXL);

    /* Make sure the default model for PCIe Root Ports is picked correctly
     * based on QEMU binary capabilities. We use x86/q35 for the test, but
     * any PCIe machine type (such as aarch64/virt) will behave the same */
    DO_TEST("pcie-root-port-model-generic",
            QEMU_CAPS_DEVICE_PCIE_ROOT_PORT,
            QEMU_CAPS_DEVICE_IOH3420);
    DO_TEST("pcie-root-port-model-ioh3420",
            QEMU_CAPS_DEVICE_IOH3420);
    DO_TEST_CAPS_LATEST("pcie-root-port-nohotplug");
    DO_TEST("pcie-switch-upstream-port",
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_DEVICE_X3130_UPSTREAM,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_DEVICE_QXL);
    DO_TEST("pcie-switch-downstream-port",
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_DEVICE_X3130_UPSTREAM,
            QEMU_CAPS_DEVICE_XIO3130_DOWNSTREAM,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_DEVICE_QXL);
    DO_TEST("pci-expander-bus",
            QEMU_CAPS_DEVICE_PXB);
    DO_TEST("pcie-expander-bus",
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_DEVICE_X3130_UPSTREAM,
            QEMU_CAPS_DEVICE_XIO3130_DOWNSTREAM,
            QEMU_CAPS_DEVICE_PXB_PCIE);
    DO_TEST_CAPS_ARCH_LATEST("pcie-expander-bus-aarch64", "aarch64");
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

    DO_TEST_CAPS_ARCH_LATEST("hostdev-scsi-vhost-scsi-ccw", "s390x");
    DO_TEST("hostdev-scsi-vhost-scsi-pci",
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_DEVICE_VHOST_SCSI);
    DO_TEST_CAPS_LATEST("hostdev-scsi-vhost-scsi-pcie");
    DO_TEST("hostdev-scsi-lsi",
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_SCSI_LSI);
    DO_TEST("hostdev-scsi-virtio-scsi",
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_SCSI_LSI);

    DO_TEST("hostdev-scsi-shareable",
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_SCSI_LSI);

    DO_TEST("hostdev-scsi-autogen-address",
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_SCSI_LSI);
    DO_TEST("hostdev-scsi-large-unit",
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_SCSI_LSI);

    DO_TEST_CAPS_ARCH_LATEST("hostdev-subsys-mdev-vfio-ccw", "s390x");
    DO_TEST_CAPS_ARCH_LATEST("hostdev-subsys-mdev-vfio-ccw-boot", "s390x");
    DO_TEST_CAPS_ARCH_LATEST("hostdev-subsys-mdev-vfio-ap", "s390x");

    DO_TEST_CAPS_ARCH_LATEST("s390-defaultconsole", "s390x");
    DO_TEST_CAPS_ARCH_LATEST("s390-panic", "s390x");
    DO_TEST_CAPS_ARCH_LATEST("s390-panic-missing", "s390x");
    DO_TEST_CAPS_ARCH_LATEST("s390-panic-no-address", "s390x");
    DO_TEST_CAPS_ARCH_LATEST("s390-serial", "s390x");
    DO_TEST_CAPS_ARCH_LATEST("s390-serial-2", "s390x");
    DO_TEST_CAPS_ARCH_LATEST("s390-serial-console", "s390x");

    DO_TEST_NOCAPS("pcihole64");
    DO_TEST_NOCAPS("pcihole64-gib");
    DO_TEST("pcihole64-q35",
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_DEVICE_QXL);

    DO_TEST("panic", QEMU_CAPS_DEVICE_PANIC);
    DO_TEST("panic-double", QEMU_CAPS_DEVICE_PANIC);
    DO_TEST("panic-no-address", QEMU_CAPS_DEVICE_PANIC);
    DO_TEST_CAPS_ARCH_LATEST("panic-pseries", "ppc64");

    DO_TEST_CAPS_LATEST("pvpanic-pci-x86_64");
    DO_TEST_CAPS_ARCH_LATEST("pvpanic-pci-aarch64", "aarch64");
    DO_TEST_CAPS_ARCH_LATEST("pvpanic-pci-no-address-aarch64", "aarch64");

    DO_TEST_NOCAPS("disk-backing-chains-index");
    DO_TEST_NOCAPS("disk-backing-chains-noindex");

    DO_TEST_CAPS_LATEST("disk-source-fd");

    DO_TEST_CAPS_LATEST("disk-network-http");

    DO_TEST("chardev-label",
            QEMU_CAPS_DEVICE_VIRTIO_RNG,
            QEMU_CAPS_OBJECT_RNG_EGD);

    DO_TEST_NOCAPS("cpu-numa1");
    DO_TEST_NOCAPS("cpu-numa2");
    DO_TEST_NOCAPS("cpu-numa-no-memory-element");
    DO_TEST_NOCAPS("cpu-numa-disordered");
    DO_TEST_NOCAPS("cpu-numa-disjoint");
    DO_TEST_NOCAPS("cpu-numa-memshared");

    DO_TEST_NOCAPS("numatune-auto-prefer");
    DO_TEST_NOCAPS("numatune-memnode");
    DO_TEST_NOCAPS("numatune-memnode-no-memory");
    DO_TEST_NOCAPS("numatune-distances");
    DO_TEST_NOCAPS("numatune-no-vcpu");
    DO_TEST("numatune-hmat", QEMU_CAPS_NUMA_HMAT);
    DO_TEST_CAPS_LATEST("numatune-hmat-none");
    DO_TEST_CAPS_LATEST("numatune-memnode-restrictive-mode");

    DO_TEST_CAPS_LATEST("firmware-manual-bios");
    DO_TEST_CAPS_LATEST("firmware-manual-bios-stateless");
    DO_TEST_CAPS_LATEST("firmware-manual-efi");
    DO_TEST_CAPS_LATEST("firmware-manual-efi-features");
    DO_TEST_CAPS_LATEST("firmware-manual-efi-rw");
    DO_TEST_CAPS_LATEST("firmware-manual-efi-rw-implicit");
    DO_TEST_CAPS_LATEST("firmware-manual-efi-loader-secure");
    DO_TEST_CAPS_LATEST("firmware-manual-efi-secboot");
    DO_TEST_CAPS_LATEST("firmware-manual-efi-no-enrolled-keys");
    DO_TEST_CAPS_LATEST("firmware-manual-efi-no-secboot");
    DO_TEST_CAPS_LATEST("firmware-manual-efi-stateless");
    DO_TEST_CAPS_LATEST("firmware-manual-efi-nvram-template");
    DO_TEST_CAPS_LATEST("firmware-manual-efi-nvram-network-iscsi");
    DO_TEST_CAPS_LATEST("firmware-manual-efi-nvram-network-nbd");
    DO_TEST_CAPS_LATEST("firmware-manual-efi-nvram-file");

    DO_TEST_CAPS_ARCH_LATEST("firmware-manual-efi-acpi-aarch64", "aarch64");
    DO_TEST_CAPS_LATEST("firmware-manual-efi-acpi-q35");
    DO_TEST_CAPS_ARCH_LATEST("firmware-manual-efi-noacpi-aarch64", "aarch64");
    DO_TEST_CAPS_LATEST("firmware-manual-noefi-acpi-q35");
    DO_TEST_CAPS_ARCH_LATEST("firmware-manual-noefi-noacpi-aarch64", "aarch64");
    DO_TEST_CAPS_LATEST("firmware-manual-noefi-noacpi-q35");

    DO_TEST_CAPS_LATEST("firmware-auto-bios");
    DO_TEST_CAPS_LATEST("firmware-auto-bios-stateless");
    DO_TEST_CAPS_LATEST("firmware-auto-efi");
    DO_TEST_CAPS_LATEST("firmware-auto-efi-stateless");
    DO_TEST_CAPS_LATEST("firmware-auto-efi-nvram");
    DO_TEST_CAPS_LATEST("firmware-auto-efi-loader-secure");
    DO_TEST_CAPS_LATEST("firmware-auto-efi-loader-insecure");
    DO_TEST_CAPS_LATEST("firmware-auto-efi-loader-path");
    DO_TEST_CAPS_LATEST("firmware-auto-efi-loader-path-nonstandard");
    DO_TEST_CAPS_LATEST("firmware-auto-efi-secboot");
    DO_TEST_CAPS_LATEST("firmware-auto-efi-no-secboot");
    DO_TEST_CAPS_LATEST("firmware-auto-efi-enrolled-keys");
    DO_TEST_CAPS_LATEST("firmware-auto-efi-no-enrolled-keys");
    DO_TEST_CAPS_LATEST("firmware-auto-efi-smm-off");
    DO_TEST_CAPS_ARCH_LATEST("firmware-auto-efi-aarch64", "aarch64");
    DO_TEST_CAPS_ARCH_LATEST_ABI_UPDATE("firmware-auto-efi-abi-update-aarch64", "aarch64");
    DO_TEST_CAPS_LATEST("firmware-auto-efi-nvram-file");
    DO_TEST_CAPS_LATEST("firmware-auto-efi-nvram-network-nbd");
    DO_TEST_CAPS_LATEST("firmware-auto-efi-nvram-network-iscsi");

    DO_TEST_CAPS_LATEST("firmware-auto-efi-format-loader-qcow2");
    DO_TEST_CAPS_LATEST("firmware-auto-efi-format-nvram-qcow2");
    DO_TEST_CAPS_LATEST("firmware-auto-efi-format-nvram-qcow2-path");
    DO_TEST_CAPS_LATEST("firmware-auto-efi-format-nvram-qcow2-network-nbd");
    DO_TEST_CAPS_ARCH_LATEST("firmware-auto-efi-format-loader-raw", "aarch64");

    DO_TEST_NOCAPS("tap-vhost");
    DO_TEST_NOCAPS("tap-vhost-incorrect");
    DO_TEST("shmem", QEMU_CAPS_DEVICE_IVSHMEM);
    DO_TEST("shmem-plain-doorbell",
            QEMU_CAPS_DEVICE_IVSHMEM_PLAIN, QEMU_CAPS_DEVICE_IVSHMEM_DOORBELL);
    DO_TEST_NOCAPS("smbios");
    DO_TEST_NOCAPS("smbios-multiple-type2");
    DO_TEST_NOCAPS("smbios-type-fwcfg");

    DO_TEST_CAPS_ARCH_LATEST("aarch64-aavmf-virtio-mmio", "aarch64");
    DO_TEST_CAPS_ARCH_LATEST("aarch64-virtio-pci-default", "aarch64");
    DO_TEST_CAPS_ARCH_LATEST("aarch64-virtio-pci-manual-addresses", "aarch64");
    DO_TEST_CAPS_ARCH_LATEST("aarch64-video-virtio-gpu-pci", "aarch64");
    DO_TEST_CAPS_ARCH_LATEST("aarch64-pci-serial", "aarch64");
    DO_TEST_CAPS_ARCH_LATEST("aarch64-traditional-pci", "aarch64");
    DO_TEST_CAPS_ARCH_LATEST("aarch64-video-default", "aarch64");

    DO_TEST_FULL("aarch64-gic-none", ".aarch64-latest", WHEN_BOTH,
                 ARG_CAPS_ARCH, "aarch64", ARG_CAPS_VER, "latest",
                 ARG_GIC, GIC_NONE, ARG_END);
    DO_TEST_FULL("aarch64-gic-none-v2", ".aarch64-latest", WHEN_BOTH,
                 ARG_CAPS_ARCH, "aarch64", ARG_CAPS_VER, "latest",
                 ARG_GIC, GIC_V2, ARG_END);
    DO_TEST_FULL("aarch64-gic-none-v3", ".aarch64-latest", WHEN_BOTH,
                 ARG_CAPS_ARCH, "aarch64", ARG_CAPS_VER, "latest",
                 ARG_GIC, GIC_V3, ARG_END);
    DO_TEST_FULL("aarch64-gic-none-both", ".aarch64-latest", WHEN_BOTH,
                 ARG_CAPS_ARCH, "aarch64", ARG_CAPS_VER, "latest",
                 ARG_GIC, GIC_BOTH, ARG_END);
    DO_TEST_FULL("aarch64-gic-none-tcg", ".aarch64-latest", WHEN_BOTH,
                 ARG_CAPS_ARCH, "aarch64", ARG_CAPS_VER, "latest",
                 ARG_GIC, GIC_BOTH, ARG_END);
    DO_TEST_FULL("aarch64-gic-default", ".aarch64-latest", WHEN_BOTH,
                 ARG_CAPS_ARCH, "aarch64", ARG_CAPS_VER, "latest",
                 ARG_GIC, GIC_NONE, ARG_END);
    DO_TEST_FULL("aarch64-gic-default-v2", ".aarch64-latest", WHEN_BOTH,
                 ARG_CAPS_ARCH, "aarch64", ARG_CAPS_VER, "latest",
                 ARG_GIC, GIC_V2, ARG_END);
    DO_TEST_FULL("aarch64-gic-default-v3", ".aarch64-latest", WHEN_BOTH,
                 ARG_CAPS_ARCH, "aarch64", ARG_CAPS_VER, "latest",
                 ARG_GIC, GIC_V3, ARG_END);
    DO_TEST_FULL("aarch64-gic-default-both", ".aarch64-latest", WHEN_BOTH,
                 ARG_CAPS_ARCH, "aarch64", ARG_CAPS_VER, "latest",
                 ARG_GIC, GIC_BOTH, ARG_END);
    DO_TEST_FULL("aarch64-gic-v2", ".aarch64-latest", WHEN_BOTH,
                 ARG_CAPS_ARCH, "aarch64", ARG_CAPS_VER, "latest",
                 ARG_GIC, GIC_NONE, ARG_END);
    DO_TEST_FULL("aarch64-gic-v2", ".aarch64-latest", WHEN_BOTH,
                 ARG_CAPS_ARCH, "aarch64", ARG_CAPS_VER, "latest",
                 ARG_GIC, GIC_V2, ARG_END);
    DO_TEST_FULL("aarch64-gic-v2", ".aarch64-latest", WHEN_BOTH,
                 ARG_CAPS_ARCH, "aarch64", ARG_CAPS_VER, "latest",
                 ARG_GIC, GIC_V3, ARG_END);
    DO_TEST_FULL("aarch64-gic-v2", ".aarch64-latest", WHEN_BOTH,
                 ARG_CAPS_ARCH, "aarch64", ARG_CAPS_VER, "latest",
                 ARG_GIC, GIC_BOTH, ARG_END);
    DO_TEST_FULL("aarch64-gic-v3", ".aarch64-latest", WHEN_BOTH,
                 ARG_CAPS_ARCH, "aarch64", ARG_CAPS_VER, "latest",
                 ARG_GIC, GIC_NONE, ARG_END);
    DO_TEST_FULL("aarch64-gic-v3", ".aarch64-latest", WHEN_BOTH,
                 ARG_CAPS_ARCH, "aarch64", ARG_CAPS_VER, "latest",
                 ARG_GIC, GIC_V2, ARG_END);
    DO_TEST_FULL("aarch64-gic-v3", ".aarch64-latest", WHEN_BOTH,
                 ARG_CAPS_ARCH, "aarch64", ARG_CAPS_VER, "latest",
                 ARG_GIC, GIC_V3, ARG_END);
    DO_TEST_FULL("aarch64-gic-v3", ".aarch64-latest", WHEN_BOTH,
                 ARG_CAPS_ARCH, "aarch64", ARG_CAPS_VER, "latest",
                 ARG_GIC, GIC_BOTH, ARG_END);
    DO_TEST_FULL("aarch64-gic-host", ".aarch64-latest", WHEN_BOTH,
                 ARG_CAPS_ARCH, "aarch64", ARG_CAPS_VER, "latest",
                 ARG_GIC, GIC_NONE, ARG_END);
    DO_TEST_FULL("aarch64-gic-host", ".aarch64-latest", WHEN_BOTH,
                 ARG_CAPS_ARCH, "aarch64", ARG_CAPS_VER, "latest",
                 ARG_GIC, GIC_V2, ARG_END);
    DO_TEST_FULL("aarch64-gic-host", ".aarch64-latest", WHEN_BOTH,
                 ARG_CAPS_ARCH, "aarch64", ARG_CAPS_VER, "latest",
                 ARG_GIC, GIC_V3, ARG_END);
    DO_TEST_FULL("aarch64-gic-host", ".aarch64-latest", WHEN_BOTH,
                 ARG_CAPS_ARCH, "aarch64", ARG_CAPS_VER, "latest",
                 ARG_GIC, GIC_BOTH, ARG_END);

    /* SVE aarch64 CPU features work on modern QEMU */
    DO_TEST_CAPS_ARCH_LATEST("aarch64-features-sve", "aarch64");

    DO_TEST_CAPS_ARCH_LATEST("aarch64-usb-controller", "aarch64");

    DO_TEST_CAPS_ARCH_LATEST("memory-hotplug-ppc64-nonuma", "ppc64");
    DO_TEST_FULL("memory-hotplug-ppc64-nonuma-abi-update", "", WHEN_BOTH,
                 ARG_PARSEFLAGS, VIR_DOMAIN_DEF_PARSE_ABI_UPDATE,
                 ARG_CAPS_ARCH, "ppc64", ARG_CAPS_VER, "latest", ARG_END);
    DO_TEST_NOCAPS("memory-hotplug");
    DO_TEST("memory-hotplug-dimm", QEMU_CAPS_DEVICE_PC_DIMM);
    DO_TEST_CAPS_LATEST("memory-hotplug-dimm-addr");
    DO_TEST("memory-hotplug-nvdimm", QEMU_CAPS_DEVICE_NVDIMM);
    DO_TEST("memory-hotplug-nvdimm-access", QEMU_CAPS_DEVICE_NVDIMM);
    DO_TEST("memory-hotplug-nvdimm-label", QEMU_CAPS_DEVICE_NVDIMM);
    DO_TEST("memory-hotplug-nvdimm-align", QEMU_CAPS_DEVICE_NVDIMM);
    DO_TEST("memory-hotplug-nvdimm-pmem", QEMU_CAPS_DEVICE_NVDIMM);
    DO_TEST("memory-hotplug-nvdimm-readonly", QEMU_CAPS_DEVICE_NVDIMM,
                                              QEMU_CAPS_DEVICE_NVDIMM_UNARMED);
    DO_TEST_CAPS_ARCH_LATEST("memory-hotplug-nvdimm-ppc64", "ppc64");
    DO_TEST_FULL("memory-hotplug-nvdimm-ppc64-abi-update", "", WHEN_BOTH,
                 ARG_PARSEFLAGS, VIR_DOMAIN_DEF_PARSE_ABI_UPDATE,
                 ARG_CAPS_ARCH, "ppc64", ARG_CAPS_VER, "latest", ARG_END);
    DO_TEST_CAPS_LATEST("memory-hotplug-virtio-pmem");
    DO_TEST_CAPS_LATEST("memory-hotplug-virtio-mem");

    DO_TEST_NOCAPS("net-udp");

    DO_TEST("video-virtio-gpu-device", QEMU_CAPS_DEVICE_VIRTIO_GPU);
    DO_TEST("video-virtio-gpu-virgl",
            QEMU_CAPS_DEVICE_VIRTIO_GPU,
            QEMU_CAPS_VIRTIO_GPU_VIRGL);
    DO_TEST("video-virtio-gpu-spice-gl",
            QEMU_CAPS_DEVICE_VIRTIO_GPU,
            QEMU_CAPS_VIRTIO_GPU_VIRGL,
            QEMU_CAPS_SPICE,
            QEMU_CAPS_SPICE_GL,
            QEMU_CAPS_SPICE_RENDERNODE);
    DO_TEST("video-virtio-gpu-sdl-gl",
            QEMU_CAPS_DEVICE_VIRTIO_GPU,
            QEMU_CAPS_VIRTIO_GPU_VIRGL,
            QEMU_CAPS_SDL);

    DO_TEST("virtio-input",
            QEMU_CAPS_VIRTIO_KEYBOARD,
            QEMU_CAPS_VIRTIO_MOUSE,
            QEMU_CAPS_VIRTIO_TABLET);
    DO_TEST("virtio-input-passthrough",
            QEMU_CAPS_VIRTIO_INPUT_HOST);

    DO_TEST_CAPS_LATEST("input-linux");

    DO_TEST_NOCAPS("memorybacking-set");
    DO_TEST_NOCAPS("memorybacking-unset");

    DO_TEST_CAPS_LATEST("virtio-options");

    DO_TEST("fd-memory-numa-topology", QEMU_CAPS_KVM);
    DO_TEST("fd-memory-numa-topology2", QEMU_CAPS_KVM);
    DO_TEST("fd-memory-numa-topology3", QEMU_CAPS_KVM);
    DO_TEST_CAPS_LATEST("fd-memory-numa-topology4");

    DO_TEST("fd-memory-no-numa-topology", QEMU_CAPS_KVM);

    DO_TEST_CAPS_LATEST("memfd-memory-numa");
    DO_TEST_CAPS_LATEST("memfd-memory-default-hugepage");

    DO_TEST_NOCAPS("acpi-table");

    DO_TEST("video-device-pciaddr-default",
            QEMU_CAPS_KVM,
            QEMU_CAPS_VNC,
            QEMU_CAPS_DEVICE_QXL);
    DO_TEST("video-qxl-heads", QEMU_CAPS_DEVICE_QXL);
    DO_TEST("video-qxl-noheads", QEMU_CAPS_DEVICE_QXL);
    DO_TEST("video-qxl-resolution", QEMU_CAPS_DEVICE_QXL);
    DO_TEST("video-virtio-gpu-secondary", QEMU_CAPS_DEVICE_VIRTIO_GPU);
    DO_TEST_CAPS_ARCH_LATEST("video-virtio-gpu-ccw", "s390x");
    DO_TEST_CAPS_ARCH_LATEST("video-virtio-gpu-ccw-auto", "s390x");
    DO_TEST("video-none-device", QEMU_CAPS_VNC);
    DO_TEST_CAPS_LATEST("video-virtio-vga-gpu-gl");
    DO_TEST_CAPS_LATEST("video-virtio-blob-on");
    DO_TEST_CAPS_LATEST("video-virtio-blob-off");

    DO_TEST_CAPS_LATEST("intel-iommu");
    DO_TEST_CAPS_LATEST("intel-iommu-caching-mode");
    DO_TEST_CAPS_LATEST("intel-iommu-eim");
    DO_TEST_CAPS_LATEST("intel-iommu-device-iotlb");
    DO_TEST_CAPS_LATEST("intel-iommu-aw-bits");
    DO_TEST_CAPS_ARCH_LATEST("iommu-smmuv3", "aarch64");
    DO_TEST_CAPS_LATEST("virtio-iommu-x86_64");
    DO_TEST_CAPS_ARCH_LATEST("virtio-iommu-aarch64", "aarch64");

    DO_TEST_NOCAPS("cpu-check-none");
    DO_TEST_NOCAPS("cpu-check-partial");
    DO_TEST_NOCAPS("cpu-check-full");
    DO_TEST_NOCAPS("cpu-check-default-none");
    DO_TEST_NOCAPS("cpu-check-default-none2");
    DO_TEST_NOCAPS("cpu-check-default-partial");
    DO_TEST_NOCAPS("cpu-check-default-partial2");
    DO_TEST("vmcoreinfo", QEMU_CAPS_DEVICE_VMCOREINFO);

    DO_TEST("smartcard-host", QEMU_CAPS_CCID_EMULATED);
    DO_TEST("smartcard-host-certificates", QEMU_CAPS_CCID_EMULATED);
    DO_TEST("smartcard-host-certificates-database",
            QEMU_CAPS_CCID_EMULATED);
    DO_TEST("smartcard-passthrough-tcp", QEMU_CAPS_CCID_PASSTHRU);
    DO_TEST("smartcard-passthrough-spicevmc",
            QEMU_CAPS_CCID_PASSTHRU,
            QEMU_CAPS_SPICE,
            QEMU_CAPS_DEVICE_CIRRUS_VGA);
    DO_TEST("smartcard-controller", QEMU_CAPS_CCID_EMULATED);

    DO_TEST_CAPS_ARCH_LATEST("pseries-cpu-compat-power9", "ppc64");
    DO_TEST_CAPS_ARCH_LATEST("pseries-cpu-compat-power10", "ppc64");
    DO_TEST_CAPS_ARCH_LATEST("pseries-cpu-compat", "ppc64");
    DO_TEST_CAPS_ARCH_LATEST("pseries-cpu-exact", "ppc64");

    DO_TEST_CAPS_LATEST("user-aliases");
    DO_TEST_CAPS_ARCH_LATEST("input-virtio-ccw", "s390x");

    DO_TEST_CAPS_LATEST("tseg-explicit-size");

    DO_TEST_CAPS_LATEST("vhost-vsock");
    DO_TEST_CAPS_LATEST("vhost-vsock-auto");
    DO_TEST_CAPS_ARCH_LATEST("vhost-vsock-ccw", "s390x");
    DO_TEST_CAPS_ARCH_LATEST("vhost-vsock-ccw-auto", "s390x");
    DO_TEST_CAPS_ARCH_LATEST("vhost-vsock-ccw-iommu", "s390x");


    DO_TEST_CAPS_LATEST("vhost-user-fs-fd-memory");
    DO_TEST_CAPS_LATEST("vhost-user-fs-hugepages");
    DO_TEST_CAPS_LATEST("vhost-user-fs-sock");

    DO_TEST_CAPS_ARCH_LATEST("riscv64-virt", "riscv64");
    DO_TEST_CAPS_ARCH_LATEST("riscv64-virt-pci", "riscv64");

    DO_TEST_CAPS_LATEST("x86-kvm-32-on-64");

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

    DO_TEST_CAPS_LATEST("cpu-Icelake-Server-pconfig");

    DO_TEST_CAPS_ARCH_LATEST("aarch64-default-cpu-kvm-virt-4.2", "aarch64");
    DO_TEST_CAPS_ARCH_LATEST("aarch64-default-cpu-tcg-virt-4.2", "aarch64");
    DO_TEST_CAPS_ARCH_LATEST("ppc64-default-cpu-kvm-pseries-2.7", "ppc64");
    DO_TEST_CAPS_ARCH_LATEST("ppc64-default-cpu-tcg-pseries-2.7", "ppc64");
    DO_TEST_CAPS_ARCH_LATEST("ppc64-default-cpu-kvm-pseries-3.1", "ppc64");
    DO_TEST_CAPS_ARCH_LATEST("ppc64-default-cpu-tcg-pseries-3.1", "ppc64");
    DO_TEST_CAPS_ARCH_LATEST("ppc64-default-cpu-kvm-pseries-4.2", "ppc64");
    DO_TEST_CAPS_ARCH_LATEST("ppc64-default-cpu-tcg-pseries-4.2", "ppc64");
    DO_TEST_CAPS_ARCH_LATEST("s390-default-cpu-kvm-ccw-virtio-2.7", "s390x");
    DO_TEST_CAPS_ARCH_LATEST("s390-default-cpu-tcg-ccw-virtio-2.7", "s390x");
    DO_TEST_CAPS_ARCH_LATEST("s390-default-cpu-kvm-ccw-virtio-4.2", "s390x");
    DO_TEST_CAPS_ARCH_LATEST("s390-default-cpu-tcg-ccw-virtio-4.2", "s390x");
    DO_TEST_CAPS_ARCH_LATEST("x86_64-default-cpu-kvm-pc-4.2", "x86_64");
    DO_TEST_CAPS_ARCH_LATEST("x86_64-default-cpu-tcg-pc-4.2", "x86_64");
    DO_TEST_CAPS_ARCH_LATEST("x86_64-default-cpu-kvm-q35-4.2", "x86_64");
    DO_TEST_CAPS_ARCH_LATEST("x86_64-default-cpu-tcg-q35-4.2", "x86_64");
    DO_TEST_CAPS_ARCH_LATEST("x86_64-default-cpu-tcg-features", "x86_64");

    DO_TEST_CAPS_LATEST("virtio-9p-multidevs");
    DO_TEST_CAPS_LATEST("virtio-9p-createmode");
    DO_TEST_NOCAPS("downscript");

    /* Simplest possible <audio>, all supported with ENV */
    DO_TEST_CAPS_LATEST("audio-none-minimal");
    DO_TEST_CAPS_LATEST("audio-alsa-minimal");
    DO_TEST_CAPS_LATEST("audio-coreaudio-minimal");
    DO_TEST_CAPS_LATEST("audio-oss-minimal");
    DO_TEST_CAPS_LATEST("audio-pulseaudio-minimal");
    DO_TEST_CAPS_LATEST("audio-sdl-minimal");
    DO_TEST_CAPS_LATEST("audio-spice-minimal");
    DO_TEST_CAPS_LATEST("audio-file-minimal");

    /* Best <audio> still compat with old ENV */
    DO_TEST_CAPS_LATEST("audio-none-best");
    DO_TEST_CAPS_LATEST("audio-alsa-best");
    DO_TEST_CAPS_LATEST("audio-coreaudio-best");
    DO_TEST_CAPS_LATEST("audio-oss-best");
    DO_TEST_CAPS_LATEST("audio-pulseaudio-best");
    DO_TEST_CAPS_LATEST("audio-sdl-best");
    DO_TEST_CAPS_LATEST("audio-spice-best");
    DO_TEST_CAPS_LATEST("audio-file-best");

    /* Full <audio> only compat with new QEMU -audiodev args */
    DO_TEST_CAPS_LATEST("audio-none-full");
    DO_TEST_CAPS_LATEST("audio-alsa-full");
    DO_TEST_CAPS_LATEST("audio-coreaudio-full");
    DO_TEST_CAPS_LATEST("audio-jack-full");
    DO_TEST_CAPS_LATEST("audio-oss-full");
    DO_TEST_CAPS_LATEST("audio-pulseaudio-full");
    DO_TEST_CAPS_LATEST("audio-sdl-full");
    DO_TEST_CAPS_LATEST("audio-spice-full");
    DO_TEST_CAPS_LATEST("audio-file-full");

    DO_TEST_CAPS_LATEST("audio-many-backends");

    /* Validate auto-creation of <audio> for legacy compat */
    g_setenv("QEMU_AUDIO_DRV", "sdl", TRUE);
    g_setenv("SDL_AUDIODRIVER", "esd", TRUE);
    DO_TEST_CAPS_LATEST("audio-default-sdl");
    g_unsetenv("QEMU_AUDIO_DRV");
    g_unsetenv("SDL_AUDIODRIVER");

    g_setenv("QEMU_AUDIO_DRV", "alsa", TRUE);
    driver.config->vncAllowHostAudio = true;
    DO_TEST_CAPS_LATEST("audio-default-vnc");
    driver.config->vncAllowHostAudio = false;
    g_unsetenv("QEMU_AUDIO_DRV");

    DO_TEST_CAPS_LATEST("audio-default-spice");

    g_setenv("QEMU_AUDIO_DRV", "alsa", TRUE);
    driver.config->nogfxAllowHostAudio = true;
    DO_TEST_CAPS_LATEST("audio-default-nographics");
    driver.config->nogfxAllowHostAudio = false;
    g_unsetenv("QEMU_AUDIO_DRV");

    DO_TEST_CAPS_LATEST("devices-acpi-index");

    DO_TEST_CAPS_ARCH_LATEST_FULL("hvf-x86_64-q35-headless", "x86_64", ARG_CAPS_VARIANT, "+hvf", ARG_END);
    DO_TEST_CAPS_ARCH_LATEST_FULL("hvf-aarch64-virt-headless", "aarch64", ARG_CAPS_VARIANT, "+hvf", ARG_END);

    DO_TEST_CAPS_LATEST("channel-qemu-vdagent");
    DO_TEST_CAPS_LATEST("channel-qemu-vdagent-features");

    DO_TEST_CAPS_VER("sgx-epc", "7.0.0");

    DO_TEST_CAPS_LATEST("crypto-builtin");

    DO_TEST_CAPS_LATEST("cpu-phys-bits-limit");
    DO_TEST_CAPS_LATEST("cpu-phys-bits-emulate-bare");

 cleanup:
    qemuTestDriverFree(&driver);
    virFileWrapperClearPrefixes();

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN_PRELOAD(mymain,
                      VIR_TEST_MOCK("virpci"),
                      VIR_TEST_MOCK("virrandom"),
                      VIR_TEST_MOCK("domaincaps"))
