#include <config.h>

#include <unistd.h>

#include <sys/types.h>
#include <fcntl.h>

#include "testutils.h"

#include "internal.h"
#include "qemu/qemu_domain_address.h"
#include "qemu/qemu_domain.h"
#include "testutilsqemu.h"
#include "virstring.h"
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
    if (!(info->flags & FLAG_REAL_CAPS)) {
        virQEMUCapsInitQMPBasicArch(info->qemuCaps);
        if (qemuTestCapsCacheInsert(driver.qemuCapsCache, info->qemuCaps) < 0)
            return -1;
    }

    return 0;
}


static int
testXML2XMLActive(const void *opaque)
{
    const struct testQemuInfo *info = opaque;

    if (testXML2XMLCommon(info) < 0)
        return -1;

    return testCompareDomXML2XMLFiles(driver.caps, driver.xmlopt,
                                      info->infile, info->outfile, true,
                                      info->parseFlags,
                                      TEST_COMPARE_DOM_XML2XML_RESULT_SUCCESS);
}


static int
testXML2XMLInactive(const void *opaque)
{
    const struct testQemuInfo *info = opaque;

    if (testXML2XMLCommon(info) < 0)
        return -1;

    return testCompareDomXML2XMLFiles(driver.caps, driver.xmlopt,
                                      info->infile, info->outfile, false,
                                      info->parseFlags,
                                      TEST_COMPARE_DOM_XML2XML_RESULT_SUCCESS);
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


#define FAKEROOTDIRTEMPLATE abs_builddir "/fakerootdir-XXXXXX"

static int
mymain(void)
{
    int ret = 0;
    g_autofree char *fakerootdir = NULL;
    g_autoptr(virQEMUDriverConfig) cfg = NULL;
    g_autoptr(GHashTable) capslatest = NULL;
    g_autoptr(GHashTable) capscache = virHashNew(virObjectFreeHashData);
    g_autoptr(virConnect) conn = NULL;

    capslatest = testQemuGetLatestCaps();
    if (!capslatest)
        return EXIT_FAILURE;

    fakerootdir = g_strdup(FAKEROOTDIRTEMPLATE);

    if (!g_mkdtemp(fakerootdir)) {
        fprintf(stderr, "Cannot create fakerootdir");
        abort();
    }

    g_setenv("LIBVIRT_FAKE_ROOT_DIR", fakerootdir, TRUE);

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
    driver.privileged = true;

    if (!(conn = virGetConnect()))
        goto cleanup;

    virSetConnectInterface(conn);
    virSetConnectNetwork(conn);
    virSetConnectNWFilter(conn);
    virSetConnectNodeDev(conn);
    virSetConnectSecret(conn);
    virSetConnectStorage(conn);

#define DO_TEST_INTERNAL(_name, suffix, when, ...) \
    do { \
        static struct testQemuInfo info = { \
            .name = _name, \
        }; \
        if (testQemuInfoSetArgs(&info, capscache, capslatest, \
                                __VA_ARGS__, \
                                ARG_END) < 0 || \
            qemuTestCapsCacheInsert(driver.qemuCapsCache, info.qemuCaps) < 0) { \
            VIR_TEST_DEBUG("Failed to generate test data for '%s'", _name); \
            ret = -1; \
        } \
 \
        if (when & WHEN_INACTIVE) { \
            testInfoSetPaths(&info, suffix, WHEN_INACTIVE); \
            if (virTestRun("QEMU XML-2-XML-inactive " _name, \
                            testXML2XMLInactive, &info) < 0) \
                ret = -1; \
        } \
 \
        if (when & WHEN_ACTIVE) { \
            testInfoSetPaths(&info, suffix, WHEN_ACTIVE); \
            if (virTestRun("QEMU XML-2-XML-active " _name, \
                            testXML2XMLActive, &info) < 0) \
                ret = -1; \
        } \
        testQemuInfoClear(&info); \
    } while (0)

#define DO_TEST_CAPS_INTERNAL(name, arch, ver, ...) \
    DO_TEST_INTERNAL(name, "." arch "-" ver, WHEN_BOTH, \
                     ARG_CAPS_ARCH, arch, \
                     ARG_CAPS_VER, ver, \
                     __VA_ARGS__)

#define DO_TEST_CAPS_ARCH_LATEST_FULL(name, arch, ...) \
    DO_TEST_CAPS_INTERNAL(name, arch, "latest", __VA_ARGS__)

#define DO_TEST_CAPS_ARCH_VER_FULL(name, arch, ver, ...) \
    DO_TEST_CAPS_INTERNAL(name, arch, ver, __VA_ARGS__)

#define DO_TEST_CAPS_ARCH_LATEST(name, arch) \
    DO_TEST_CAPS_ARCH_LATEST_FULL(name, arch, ARG_END)

#define DO_TEST_CAPS_ARCH_VER(name, arch, ver) \
    DO_TEST_CAPS_ARCH_VER_FULL(name, arch, ver, ARG_END)

#define DO_TEST_CAPS_LATEST(name) \
    DO_TEST_CAPS_ARCH_LATEST(name, "x86_64")

#define DO_TEST_CAPS_VER(name, ver) \
    DO_TEST_CAPS_ARCH_VER(name, "x86_64", ver)

#define DO_TEST_FULL(name, when, ...) \
    DO_TEST_INTERNAL(name, "", when, __VA_ARGS__)

#define DO_TEST(name, ...) \
    DO_TEST_FULL(name, WHEN_BOTH, \
                 ARG_QEMU_CAPS, __VA_ARGS__, QEMU_CAPS_LAST)

#define NONE QEMU_CAPS_LAST

    /* Unset or set all envvars here that are copied in qemudBuildCommandLine
     * using ADD_ENV_COPY, otherwise these tests may fail due to unexpected
     * values for these envvars */
    g_setenv("PATH", "/bin", TRUE);
    g_unsetenv("QEMU_AUDIO_DRV");
    g_unsetenv("SDL_AUDIODRIVER");

    DO_TEST("minimal", NONE);
    DO_TEST_CAPS_LATEST("genid");
    DO_TEST_CAPS_LATEST("genid-auto");
    DO_TEST("machine-core-on", NONE);
    DO_TEST("machine-core-off", NONE);
    DO_TEST("machine-loadparm-multiple-disks-nets-s390", QEMU_CAPS_CCW);
    DO_TEST("default-kvm-host-arch", NONE);
    DO_TEST("default-qemu-host-arch", NONE);
    DO_TEST("boot-cdrom", NONE);
    DO_TEST("boot-network", NONE);
    DO_TEST("boot-floppy", NONE);
    DO_TEST("boot-floppy-q35",
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI);
    DO_TEST("boot-multi", NONE);
    DO_TEST("boot-menu-enable-with-timeout", QEMU_CAPS_SPLASH_TIMEOUT);
    DO_TEST("boot-menu-disable", NONE);
    DO_TEST("boot-menu-disable-with-timeout", NONE);
    DO_TEST("boot-order", NONE);

    DO_TEST("reboot-timeout-enabled", QEMU_CAPS_REBOOT_TIMEOUT);
    DO_TEST("reboot-timeout-disabled", QEMU_CAPS_REBOOT_TIMEOUT);

    DO_TEST("clock-utc", NONE);
    DO_TEST("clock-localtime", NONE);
    DO_TEST("cpu-empty", NONE);
    DO_TEST("cpu-kvmclock", NONE);
    DO_TEST("cpu-host-kvmclock", NONE);
    DO_TEST("cpu-host-passthrough-features", NONE);
    DO_TEST("cpu-host-model-features", NONE);
    DO_TEST("cpu-host-model-vendor", NONE);
    DO_TEST("clock-catchup", QEMU_CAPS_KVM_PIT_TICK_POLICY);
    DO_TEST("kvmclock", NONE);
    DO_TEST("clock-timer-hyperv-rtc", NONE);
    DO_TEST_CAPS_ARCH_LATEST("clock-timer-armvtimer", "aarch64");
    DO_TEST("clock-realtime", NONE);

    DO_TEST("cpu-eoi-disabled", NONE);
    DO_TEST("cpu-eoi-enabled", NONE);
    DO_TEST("eoi-disabled", NONE);
    DO_TEST("eoi-enabled", NONE);
    DO_TEST("pv-spinlock-disabled", NONE);
    DO_TEST("pv-spinlock-enabled", NONE);

    DO_TEST("hyperv", NONE);
    DO_TEST("hyperv-off", NONE);
    DO_TEST("hyperv-panic", NONE);
    DO_TEST("hyperv-stimer-direct", NONE);

    DO_TEST("kvm-features", NONE);
    DO_TEST("kvm-features-off", NONE);

    DO_TEST("pmu-feature", NONE);
    DO_TEST("pmu-feature-off", NONE);

    DO_TEST("pages-discard", NONE);
    DO_TEST("pages-discard-hugepages", QEMU_CAPS_OBJECT_MEMORY_FILE);
    DO_TEST("pages-dimm-discard", QEMU_CAPS_DEVICE_PC_DIMM);
    DO_TEST("hugepages-default", QEMU_CAPS_OBJECT_MEMORY_FILE);
    DO_TEST("hugepages-default-2M", QEMU_CAPS_OBJECT_MEMORY_FILE);
    DO_TEST("hugepages-default-system-size", QEMU_CAPS_OBJECT_MEMORY_FILE);
    DO_TEST("hugepages-nodeset", QEMU_CAPS_OBJECT_MEMORY_FILE);
    DO_TEST("hugepages-numa-default-2M", QEMU_CAPS_OBJECT_MEMORY_FILE);
    DO_TEST("hugepages-numa-default-dimm", QEMU_CAPS_DEVICE_PC_DIMM,
            QEMU_CAPS_OBJECT_MEMORY_FILE);
    DO_TEST("hugepages-numa-nodeset", QEMU_CAPS_OBJECT_MEMORY_FILE);
    DO_TEST("hugepages-numa-nodeset-part", QEMU_CAPS_OBJECT_MEMORY_FILE);
    DO_TEST("hugepages-shared", QEMU_CAPS_OBJECT_MEMORY_FILE);
    DO_TEST("hugepages-memaccess", QEMU_CAPS_DEVICE_PC_DIMM,
            QEMU_CAPS_OBJECT_MEMORY_FILE);
    DO_TEST("hugepages-memaccess2", QEMU_CAPS_DEVICE_PC_DIMM,
            QEMU_CAPS_OBJECT_MEMORY_FILE);
    DO_TEST("hugepages-nvdimm", QEMU_CAPS_DEVICE_NVDIMM,
            QEMU_CAPS_OBJECT_MEMORY_FILE);
    DO_TEST("nosharepages", NONE);
    DO_TEST("restore-v2", NONE);
    DO_TEST("migrate", NONE);
    DO_TEST("qemu-ns-no-env", NONE);
    DO_TEST_CAPS_LATEST("qemu-ns");
    DO_TEST("disk-aio", NONE);
    DO_TEST_CAPS_LATEST("disk-aio-io_uring");
    DO_TEST("disk-cdrom", NONE);
    DO_TEST_CAPS_LATEST("disk-cdrom-empty-network-invalid");
    DO_TEST("disk-cdrom-bus-other", QEMU_CAPS_DEVICE_USB_STORAGE);
    DO_TEST("disk-floppy", NONE);
    DO_TEST("disk-usb-device", QEMU_CAPS_DEVICE_USB_STORAGE);
    DO_TEST("disk-virtio", NONE);
    DO_TEST("floppy-drive-fat", NONE);
    DO_TEST("disk-virtio-queues", QEMU_CAPS_VIRTIO_BLK_NUM_QUEUES);
    DO_TEST("disk-boot-disk", NONE);
    DO_TEST("disk-boot-cdrom", NONE);
    DO_TEST("disk-error-policy", NONE);
    DO_TEST_CAPS_LATEST("disk-transient");
    DO_TEST("disk-fmt-qcow", NONE);
    DO_TEST_CAPS_VER("disk-cache", "2.12.0");
    DO_TEST_CAPS_LATEST("disk-cache");
    DO_TEST_CAPS_LATEST("disk-metadata-cache");
    DO_TEST("disk-network-nbd", NONE);
    DO_TEST("disk-network-iscsi", QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_SCSI_BLOCK);
    DO_TEST("disk-network-gluster", NONE);
    DO_TEST("disk-network-rbd", NONE);
    DO_TEST("disk-network-source-auth", NONE);
    DO_TEST("disk-network-sheepdog", NONE);
    DO_TEST("disk-network-vxhs", NONE);
    DO_TEST_CAPS_LATEST("disk-network-nfs");
    DO_TEST("disk-network-tlsx509-nbd", NONE);
    DO_TEST("disk-network-tlsx509-vxhs", NONE);
    DO_TEST("disk-nvme", QEMU_CAPS_VIRTIO_SCSI, QEMU_CAPS_QCOW2_LUKS);
    DO_TEST_CAPS_LATEST("disk-vhostuser");
    DO_TEST_CAPS_LATEST("disk-scsi");
    DO_TEST("disk-virtio-scsi-reservations",
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_PR_MANAGER_HELPER,
            QEMU_CAPS_SCSI_BLOCK);
    DO_TEST("controller-virtio-scsi", QEMU_CAPS_VIRTIO_SCSI);
    DO_TEST("disk-virtio-s390-zpci",
            QEMU_CAPS_DEVICE_ZPCI,
            QEMU_CAPS_CCW);
    DO_TEST("disk-mirror-old", NONE);
    DO_TEST("disk-mirror", NONE);
    DO_TEST("disk-active-commit", NONE);
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
    DO_TEST("graphics-spice",
            QEMU_CAPS_DEVICE_QXL,
            QEMU_CAPS_SPICE,
            QEMU_CAPS_SPICE_FILE_XFER_DISABLE);
    DO_TEST("graphics-spice-compression",
            QEMU_CAPS_DEVICE_QXL,
            QEMU_CAPS_SPICE);
    DO_TEST("graphics-spice-qxl-vga",
            QEMU_CAPS_DEVICE_QXL,
            QEMU_CAPS_SPICE);
    DO_TEST("graphics-spice-socket",
            QEMU_CAPS_DEVICE_CIRRUS_VGA,
            QEMU_CAPS_SPICE,
            QEMU_CAPS_SPICE_UNIX);
    DO_TEST("graphics-spice-auto-socket",
            QEMU_CAPS_DEVICE_CIRRUS_VGA,
            QEMU_CAPS_SPICE,
            QEMU_CAPS_SPICE_UNIX);
    cfg->spiceAutoUnixSocket = true;
    DO_TEST("graphics-spice-auto-socket-cfg",
            QEMU_CAPS_DEVICE_CIRRUS_VGA,
            QEMU_CAPS_SPICE);
    cfg->spiceAutoUnixSocket = false;
    cfg->spiceTLS = false;
    DO_TEST("graphics-spice-egl-headless",
            QEMU_CAPS_DEVICE_QXL,
            QEMU_CAPS_SPICE,
            QEMU_CAPS_EGL_HEADLESS);

    DO_TEST("graphics-egl-headless-rendernode",
            QEMU_CAPS_DEVICE_CIRRUS_VGA,
            QEMU_CAPS_EGL_HEADLESS_RENDERNODE,
            QEMU_CAPS_EGL_HEADLESS);

    DO_TEST("input-usbmouse", NONE);
    DO_TEST("input-usbtablet", NONE);
    DO_TEST("misc-acpi", NONE);
    DO_TEST("misc-disable-s3", QEMU_CAPS_PIIX_DISABLE_S3);
    DO_TEST("misc-disable-suspends",
            QEMU_CAPS_PIIX_DISABLE_S3,
            QEMU_CAPS_PIIX_DISABLE_S4);
    DO_TEST("misc-enable-s4", QEMU_CAPS_PIIX_DISABLE_S4);
    DO_TEST("misc-no-reboot", NONE);
    DO_TEST("misc-uuid", NONE);
    DO_TEST("net-vhostuser", NONE);
    DO_TEST("net-user", NONE);
    DO_TEST("net-user-addr", NONE);
    DO_TEST("net-virtio", NONE);
    DO_TEST("net-virtio-device", QEMU_CAPS_VIRTIO_TX_ALG);
    DO_TEST("net-virtio-disable-offloads", NONE);
    DO_TEST("net-eth", NONE);
    DO_TEST("net-eth-ifname", NONE);
    DO_TEST("net-eth-hostip", NONE);
    DO_TEST("net-eth-unmanaged-tap", NONE);
    DO_TEST("net-virtio-network-portgroup", NONE);
    DO_TEST("net-virtio-rxtxqueuesize",
            QEMU_CAPS_VIRTIO_NET_RX_QUEUE_SIZE,
            QEMU_CAPS_VIRTIO_NET_TX_QUEUE_SIZE);
    DO_TEST("net-virtio-teaming",
            QEMU_CAPS_VIRTIO_NET_FAILOVER,
            QEMU_CAPS_DEVICE_VFIO_PCI);
    DO_TEST("net-virtio-teaming-network",
            QEMU_CAPS_VIRTIO_NET_FAILOVER,
            QEMU_CAPS_DEVICE_VFIO_PCI);
    DO_TEST("net-virtio-teaming-hostdev",
            QEMU_CAPS_VIRTIO_NET_FAILOVER,
            QEMU_CAPS_DEVICE_VFIO_PCI);
    DO_TEST_CAPS_LATEST("net-isolated-port");
    DO_TEST("net-hostdev", NONE);
    DO_TEST("net-hostdev-bootorder", NONE);
    DO_TEST("net-hostdev-vfio", QEMU_CAPS_DEVICE_VFIO_PCI);
    DO_TEST("net-midonet", NONE);
    DO_TEST("net-openvswitch", NONE);
    DO_TEST("sound", NONE);
    DO_TEST("sound-device",
            QEMU_CAPS_DEVICE_ICH9_INTEL_HDA,
            QEMU_CAPS_OBJECT_USB_AUDIO,
            QEMU_CAPS_HDA_MICRO,
            QEMU_CAPS_HDA_DUPLEX,
            QEMU_CAPS_HDA_OUTPUT);
    DO_TEST("watchdog", NONE);
    DO_TEST("net-bandwidth", QEMU_CAPS_DEVICE_VGA, QEMU_CAPS_VNC);
    DO_TEST("net-bandwidth2", QEMU_CAPS_DEVICE_VGA, QEMU_CAPS_VNC);
    DO_TEST("net-mtu", QEMU_CAPS_VIRTIO_NET_HOST_MTU);
    DO_TEST("net-coalesce", NONE);
    DO_TEST("net-many-models", NONE);
    DO_TEST("net-vdpa", QEMU_CAPS_NETDEV_VHOST_VDPA);

    DO_TEST("serial-tcp-tlsx509-chardev", NONE);
    DO_TEST("serial-tcp-tlsx509-chardev-notls", NONE);

    cfg->spiceTLS = true;
    DO_TEST("serial-spiceport",
            QEMU_CAPS_DEVICE_QXL,
            QEMU_CAPS_SPICE);
    cfg->spiceTLS = false;

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
    DO_TEST("hostdev-pci-address-unassigned", QEMU_CAPS_DEVICE_VFIO_PCI);
    DO_TEST("hostdev-pci-multifunction", QEMU_CAPS_DEVICE_VFIO_PCI);
    DO_TEST("hostdev-vfio", QEMU_CAPS_DEVICE_VFIO_PCI);
    DO_TEST("hostdev-vfio-zpci",
            QEMU_CAPS_DEVICE_VFIO_PCI,
            QEMU_CAPS_DEVICE_ZPCI,
            QEMU_CAPS_CCW);
    DO_TEST("hostdev-vfio-zpci-multidomain-many",
            QEMU_CAPS_DEVICE_VFIO_PCI,
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_ZPCI);
    DO_TEST("hostdev-vfio-zpci-autogenerate",
            QEMU_CAPS_DEVICE_VFIO_PCI,
            QEMU_CAPS_DEVICE_ZPCI);
    DO_TEST("hostdev-vfio-zpci-autogenerate-uids",
            QEMU_CAPS_DEVICE_VFIO_PCI,
            QEMU_CAPS_DEVICE_ZPCI);
    DO_TEST("hostdev-vfio-zpci-autogenerate-fids",
            QEMU_CAPS_DEVICE_VFIO_PCI,
            QEMU_CAPS_DEVICE_ZPCI);
    DO_TEST("hostdev-vfio-zpci-boundaries",
            QEMU_CAPS_DEVICE_VFIO_PCI,
            QEMU_CAPS_DEVICE_PCI_BRIDGE,
            QEMU_CAPS_DEVICE_ZPCI);
    DO_TEST("hostdev-vfio-zpci-ccw-memballoon",
            QEMU_CAPS_CCW,
            QEMU_CAPS_DEVICE_VFIO_PCI,
            QEMU_CAPS_DEVICE_ZPCI);
    DO_TEST("hostdev-mdev-precreated", QEMU_CAPS_DEVICE_VFIO_PCI);
    DO_TEST("hostdev-mdev-display",
            QEMU_CAPS_DEVICE_QXL,
            QEMU_CAPS_VFIO_PCI_DISPLAY,
            QEMU_CAPS_DEVICE_VFIO_PCI,
            QEMU_CAPS_VNC);
    DO_TEST_CAPS_LATEST("hostdev-mdev-display-ramfb");
    DO_TEST("pci-rom", NONE);
    DO_TEST("pci-rom-disabled", NONE);
    DO_TEST("pci-rom-disabled-invalid", NONE);
    DO_TEST("pci-serial-dev-chardev", NONE);

    DO_TEST_CAPS_LATEST("disk-slices");
    DO_TEST_CAPS_LATEST("disk-rotation");

    DO_TEST("encrypted-disk", QEMU_CAPS_QCOW2_LUKS);
    DO_TEST("encrypted-disk-usage", QEMU_CAPS_QCOW2_LUKS);
    DO_TEST("luks-disks", NONE);
    DO_TEST("luks-disks-source", NONE);
    DO_TEST_CAPS_LATEST("luks-disks-source-qcow2");
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
    DO_TEST_CAPS_LATEST("cputune-cpuset-big-id");
    DO_TEST_CAPS_LATEST("numavcpus-topology-mismatch");

    DO_TEST("smp", NONE);
    DO_TEST("iothreads", NONE);
    DO_TEST("iothreads-ids", NONE);
    DO_TEST("iothreads-ids-partial", NONE);
    DO_TEST("cputune-iothreads", NONE);
    DO_TEST("iothreads-disk", NONE);
    DO_TEST("iothreads-disk-virtio-ccw", QEMU_CAPS_CCW);
    DO_TEST("iothreads-virtio-scsi-pci",
            QEMU_CAPS_VIRTIO_SCSI);
    DO_TEST("iothreads-virtio-scsi-ccw",
            QEMU_CAPS_VIRTIO_SCSI, QEMU_CAPS_CCW);
    DO_TEST("lease", NONE);
    DO_TEST("event_idx", NONE);
    DO_TEST("vhost_queues", NONE);
    DO_TEST("interface-driver", NONE);
    DO_TEST("interface-server", QEMU_CAPS_DEVICE_CIRRUS_VGA,
            QEMU_CAPS_OBJECT_MEMORY_FILE,
            QEMU_CAPS_PIIX_DISABLE_S3,
            QEMU_CAPS_PIIX_DISABLE_S4,
            QEMU_CAPS_VNC);
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
    DO_TEST("usb-port-missing", QEMU_CAPS_USB_HUB);
    DO_TEST("usb-redir", QEMU_CAPS_USB_REDIR);
    DO_TEST("usb-redir-filter",
            QEMU_CAPS_USB_REDIR,
            QEMU_CAPS_USB_REDIR_FILTER);
    DO_TEST("usb-redir-filter-version",
            QEMU_CAPS_USB_REDIR,
            QEMU_CAPS_USB_REDIR_FILTER);
    DO_TEST_CAPS_LATEST("blkdeviotune");
    DO_TEST_CAPS_LATEST("blkdeviotune-max");
    DO_TEST_CAPS_LATEST("blkdeviotune-group-num");
    DO_TEST_CAPS_LATEST("blkdeviotune-max-length");
    DO_TEST("controller-usb-order",
            QEMU_CAPS_PIIX_DISABLE_S3,
            QEMU_CAPS_PIIX_DISABLE_S4);
    DO_TEST_CAPS_ARCH_LATEST("ppc64-tpmproxy-single", "ppc64");
    DO_TEST_CAPS_ARCH_LATEST("ppc64-tpmproxy-with-tpm", "ppc64");

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
                 ARG_QEMU_CAPS, QEMU_CAPS_DEVICE_CIRRUS_VGA,
                 QEMU_CAPS_OBJECT_MEMORY_FILE,
                 QEMU_CAPS_SPICE, NONE);
    DO_TEST("numad-static-vcpu-no-numatune", NONE);

    DO_TEST("disk-scsi-lun-passthrough-sgio",
            QEMU_CAPS_SCSI_LSI,
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_SCSI_DISK_WWN,
            QEMU_CAPS_SCSI_BLOCK);
    DO_TEST("disk-scsi-disk-vpd",
            QEMU_CAPS_SCSI_LSI, QEMU_CAPS_VIRTIO_SCSI, QEMU_CAPS_SCSI_DISK_WWN);
    DO_TEST("disk-source-pool", NONE);
    DO_TEST("disk-source-pool-mode", NONE);

    DO_TEST_CAPS_LATEST("disk-discard");
    DO_TEST_CAPS_LATEST("disk-detect-zeroes");

    DO_TEST("disk-serial", NONE);

    DO_TEST_CAPS_ARCH_LATEST("disk-arm-virtio-sd", "aarch64");

    DO_TEST("virtio-rng-random",
            QEMU_CAPS_DEVICE_VIRTIO_RNG,
            QEMU_CAPS_OBJECT_RNG_RANDOM);
    DO_TEST("virtio-rng-egd",
            QEMU_CAPS_DEVICE_VIRTIO_RNG,
            QEMU_CAPS_OBJECT_RNG_EGD);
    DO_TEST_CAPS_LATEST("virtio-rng-builtin");

    DO_TEST("pseries-nvram",
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
            QEMU_CAPS_DEVICE_NVRAM);
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
            QEMU_CAPS_SPAPR_PCI_HOST_BRIDGE_NUMA_NODE,
            QEMU_CAPS_OBJECT_MEMORY_FILE);

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
            QEMU_CAPS_MACHINE_PSERIES_CAP_CCF_ASSIST,
            QEMU_CAPS_MACHINE_PSERIES_RESIZE_HPT,
            QEMU_CAPS_MACHINE_PSERIES_CAP_CFPC,
            QEMU_CAPS_MACHINE_PSERIES_CAP_SBBC,
            QEMU_CAPS_MACHINE_PSERIES_CAP_IBS);

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
    DO_TEST("graphics-listen-network2",
            QEMU_CAPS_DEVICE_CIRRUS_VGA,
            QEMU_CAPS_VNC);
    DO_TEST("graphics-spice-timeout",
            QEMU_CAPS_DEVICE_VGA,
            QEMU_CAPS_SPICE);
    DO_TEST("numad-auto-vcpu-no-numatune", NONE);
    DO_TEST("numad-auto-memory-vcpu-no-cpuset-and-placement", NONE);
    DO_TEST("numad-auto-memory-vcpu-cpuset", NONE);
    DO_TEST("usb-ich9-ehci-addr", NONE);
    DO_TEST("disk-copy_on_read", QEMU_CAPS_VIRTIO_TX_ALG);
    DO_TEST_CAPS_LATEST("tpm-passthrough");
    DO_TEST_CAPS_LATEST("tpm-passthrough-crb");
    DO_TEST_CAPS_LATEST("tpm-emulator");
    DO_TEST_CAPS_LATEST("tpm-emulator-tpm2");
    DO_TEST_CAPS_LATEST("tpm-emulator-tpm2-enc");
    DO_TEST_CAPS_LATEST("tpm-emulator-tpm2-pstate");

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
            QEMU_CAPS_NEC_USB_XHCI);
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
            QEMU_CAPS_NEC_USB_XHCI);
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
            QEMU_CAPS_NEC_USB_XHCI);
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
            QEMU_CAPS_NEC_USB_XHCI);
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
            QEMU_CAPS_NEC_USB_XHCI);
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
            QEMU_CAPS_SPICE,
            QEMU_CAPS_DEVICE_QXL,
            QEMU_CAPS_HDA_DUPLEX,
            QEMU_CAPS_USB_REDIR,
            QEMU_CAPS_MACHINE_VMPORT_OPT);
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

    DO_TEST("hostdev-subsys-mdev-vfio-ccw",
            QEMU_CAPS_CCW,
            QEMU_CAPS_CCW_CSSID_UNRESTRICTED,
            QEMU_CAPS_DEVICE_VFIO_CCW);
    DO_TEST_CAPS_ARCH_LATEST("hostdev-subsys-mdev-vfio-ccw-boot",
                             "s390x");
    DO_TEST("hostdev-subsys-mdev-vfio-ap",
            QEMU_CAPS_CCW,
            QEMU_CAPS_CCW_CSSID_UNRESTRICTED,
            QEMU_CAPS_DEVICE_VFIO_AP);

    DO_TEST_CAPS_ARCH_LATEST("s390-defaultconsole", "s390x");
    DO_TEST("s390-panic", QEMU_CAPS_CCW);
    DO_TEST("s390-panic-missing", QEMU_CAPS_CCW);
    DO_TEST("s390-panic-no-address", QEMU_CAPS_CCW);
    DO_TEST("s390-serial", QEMU_CAPS_CCW);
    DO_TEST("s390-serial-2", QEMU_CAPS_CCW);
    DO_TEST("s390-serial-console", QEMU_CAPS_CCW);

    DO_TEST("pcihole64", QEMU_CAPS_I440FX_PCI_HOLE64_SIZE);
    DO_TEST("pcihole64-gib", QEMU_CAPS_I440FX_PCI_HOLE64_SIZE);
    DO_TEST("pcihole64-none", QEMU_CAPS_I440FX_PCI_HOLE64_SIZE);
    DO_TEST("pcihole64-q35",
            QEMU_CAPS_DEVICE_IOH3420,
            QEMU_CAPS_ICH9_AHCI,
            QEMU_CAPS_DEVICE_QXL,
            QEMU_CAPS_Q35_PCI_HOLE64_SIZE);

    DO_TEST("panic", QEMU_CAPS_DEVICE_PANIC);
    DO_TEST("panic-isa", QEMU_CAPS_DEVICE_PANIC);
    DO_TEST("panic-pseries",
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE);
    DO_TEST("panic-double", QEMU_CAPS_DEVICE_PANIC);
    DO_TEST("panic-no-address", QEMU_CAPS_DEVICE_PANIC);

    DO_TEST("disk-backing-chains", NONE);
    DO_TEST("disk-backing-chains-index", NONE);
    DO_TEST("disk-backing-chains-noindex", NONE);

    DO_TEST_CAPS_LATEST("disk-network-http");

    DO_TEST("chardev-label",
            QEMU_CAPS_DEVICE_VIRTIO_RNG,
            QEMU_CAPS_OBJECT_RNG_EGD);

    DO_TEST("cpu-numa1", NONE);
    DO_TEST("cpu-numa2", NONE);
    DO_TEST("cpu-numa-no-memory-element", NONE);
    DO_TEST("cpu-numa-disordered", NONE);
    DO_TEST("cpu-numa-disjoint", QEMU_CAPS_NUMA);
    DO_TEST("cpu-numa-memshared", QEMU_CAPS_OBJECT_MEMORY_FILE);

    DO_TEST("numatune-auto-prefer", NONE);
    DO_TEST("numatune-memnode", QEMU_CAPS_NUMA, QEMU_CAPS_OBJECT_MEMORY_FILE);
    DO_TEST("numatune-memnode-no-memory", QEMU_CAPS_OBJECT_MEMORY_FILE);
    DO_TEST("numatune-distances", QEMU_CAPS_NUMA);
    DO_TEST("numatune-no-vcpu", QEMU_CAPS_NUMA);
    DO_TEST("numatune-hmat", QEMU_CAPS_NUMA_HMAT, QEMU_CAPS_OBJECT_MEMORY_RAM);
    DO_TEST_CAPS_LATEST("numatune-memnode-restrictive-mode");

    DO_TEST("bios-nvram", NONE);
    DO_TEST("bios-nvram-os-interleave", NONE);

    DO_TEST("tap-vhost", NONE);
    DO_TEST("tap-vhost-incorrect", NONE);
    DO_TEST("shmem", QEMU_CAPS_DEVICE_IVSHMEM);
    DO_TEST("shmem-plain-doorbell",
            QEMU_CAPS_DEVICE_IVSHMEM_PLAIN, QEMU_CAPS_DEVICE_IVSHMEM_DOORBELL);
    DO_TEST("smbios", NONE);
    DO_TEST("smbios-multiple-type2", NONE);
    DO_TEST("smbios-type-fwcfg", QEMU_CAPS_FW_CFG);

    DO_TEST_CAPS_LATEST("os-firmware-bios");
    DO_TEST_CAPS_LATEST("os-firmware-efi");
    DO_TEST_CAPS_LATEST("os-firmware-efi-secboot");
    DO_TEST_CAPS_LATEST("os-firmware-efi-no-enrolled-keys");

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

    /* SVE aarch64 CPU features work on modern QEMU */
    DO_TEST_CAPS_ARCH_LATEST("aarch64-features-sve", "aarch64");

    DO_TEST("memory-hotplug-ppc64-nonuma", QEMU_CAPS_KVM, QEMU_CAPS_DEVICE_PC_DIMM, QEMU_CAPS_NUMA,
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
            QEMU_CAPS_OBJECT_MEMORY_RAM, QEMU_CAPS_OBJECT_MEMORY_FILE);
    DO_TEST_FULL("memory-hotplug-ppc64-nonuma-abi-update", WHEN_BOTH,
                 ARG_PARSEFLAGS, VIR_DOMAIN_DEF_PARSE_ABI_UPDATE,
                 ARG_QEMU_CAPS,
                 QEMU_CAPS_KVM, QEMU_CAPS_DEVICE_PC_DIMM,
                 QEMU_CAPS_NUMA, QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
                 QEMU_CAPS_OBJECT_MEMORY_RAM,
                 QEMU_CAPS_OBJECT_MEMORY_FILE, QEMU_CAPS_LAST);
    DO_TEST("memory-hotplug", NONE);
    DO_TEST("memory-hotplug-dimm", QEMU_CAPS_DEVICE_PC_DIMM);
    DO_TEST("memory-hotplug-nvdimm", QEMU_CAPS_DEVICE_NVDIMM);
    DO_TEST("memory-hotplug-nvdimm-access", QEMU_CAPS_DEVICE_NVDIMM);
    DO_TEST("memory-hotplug-nvdimm-label", QEMU_CAPS_DEVICE_NVDIMM);
    DO_TEST("memory-hotplug-nvdimm-align", QEMU_CAPS_DEVICE_NVDIMM);
    DO_TEST("memory-hotplug-nvdimm-pmem", QEMU_CAPS_DEVICE_NVDIMM);
    DO_TEST("memory-hotplug-nvdimm-readonly", QEMU_CAPS_DEVICE_NVDIMM,
                                              QEMU_CAPS_DEVICE_NVDIMM_UNARMED);
    DO_TEST("memory-hotplug-nvdimm-ppc64", QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
                                           QEMU_CAPS_OBJECT_MEMORY_FILE,
                                           QEMU_CAPS_DEVICE_NVDIMM);
    DO_TEST_FULL("memory-hotplug-nvdimm-ppc64-abi-update", WHEN_BOTH,
                 ARG_PARSEFLAGS, VIR_DOMAIN_DEF_PARSE_ABI_UPDATE,
                 ARG_QEMU_CAPS,
                 QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE,
                 QEMU_CAPS_OBJECT_MEMORY_FILE,
                 QEMU_CAPS_DEVICE_NVDIMM,
                 QEMU_CAPS_LAST);
    DO_TEST_CAPS_LATEST("memory-hotplug-virtio-pmem");

    DO_TEST("net-udp", NONE);

    DO_TEST("video-virtio-gpu-device", QEMU_CAPS_DEVICE_VIRTIO_GPU);
    DO_TEST("video-virtio-gpu-virgl",
            QEMU_CAPS_DEVICE_VIRTIO_GPU,
            QEMU_CAPS_VIRTIO_GPU_VIRGL);
    DO_TEST("video-virtio-gpu-spice-gl",
            QEMU_CAPS_DEVICE_VIRTIO_GPU,
            QEMU_CAPS_VIRTIO_GPU_VIRGL,
            QEMU_CAPS_SPICE,
            QEMU_CAPS_SPICE_FILE_XFER_DISABLE,
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

    DO_TEST("memorybacking-set", NONE);
    DO_TEST("memorybacking-unset", NONE);

    DO_TEST_CAPS_LATEST("virtio-options");

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
            QEMU_CAPS_OBJECT_MEMORY_MEMFD_HUGETLB,
            QEMU_CAPS_OBJECT_MEMORY_FILE);
    DO_TEST("memfd-memory-default-hugepage",
            QEMU_CAPS_OBJECT_MEMORY_MEMFD,
            QEMU_CAPS_OBJECT_MEMORY_MEMFD_HUGETLB,
            QEMU_CAPS_OBJECT_MEMORY_FILE);

    DO_TEST("acpi-table", NONE);

    DO_TEST("video-device-pciaddr-default",
            QEMU_CAPS_KVM,
            QEMU_CAPS_VNC,
            QEMU_CAPS_DEVICE_QXL);
    DO_TEST("video-qxl-heads", QEMU_CAPS_DEVICE_QXL);
    DO_TEST("video-qxl-noheads", QEMU_CAPS_DEVICE_QXL);
    DO_TEST("video-qxl-resolution", QEMU_CAPS_DEVICE_QXL);
    DO_TEST("video-virtio-gpu-secondary", QEMU_CAPS_DEVICE_VIRTIO_GPU);
    DO_TEST("video-virtio-gpu-ccw",
            QEMU_CAPS_CCW,
            QEMU_CAPS_DEVICE_VIRTIO_GPU,
            QEMU_CAPS_VIRTIO_GPU_MAX_OUTPUTS,
            QEMU_CAPS_VNC,
            QEMU_CAPS_DEVICE_VIRTIO_GPU_CCW);
    DO_TEST("video-virtio-gpu-ccw-auto",
            QEMU_CAPS_CCW,
            QEMU_CAPS_DEVICE_VIRTIO_GPU,
            QEMU_CAPS_VIRTIO_GPU_MAX_OUTPUTS,
            QEMU_CAPS_VNC,
            QEMU_CAPS_DEVICE_VIRTIO_GPU_CCW);
    DO_TEST("video-none-device", QEMU_CAPS_VNC);
    DO_TEST_CAPS_LATEST("video-virtio-vga-gpu-gl");

    DO_TEST_CAPS_LATEST("intel-iommu");
    DO_TEST_CAPS_LATEST("intel-iommu-caching-mode");
    DO_TEST_CAPS_LATEST("intel-iommu-eim");
    DO_TEST_CAPS_LATEST("intel-iommu-device-iotlb");
    DO_TEST_CAPS_LATEST("intel-iommu-aw-bits");
    DO_TEST_CAPS_ARCH_LATEST("iommu-smmuv3", "aarch64");

    DO_TEST("cpu-check-none", NONE);
    DO_TEST("cpu-check-partial", NONE);
    DO_TEST("cpu-check-full", NONE);
    DO_TEST("cpu-check-default-none", NONE);
    DO_TEST("cpu-check-default-none2", NONE);
    DO_TEST("cpu-check-default-partial", NONE);
    DO_TEST("cpu-check-default-partial2", NONE);
    DO_TEST("vmcoreinfo", QEMU_CAPS_DEVICE_VMCOREINFO);

    DO_TEST("smartcard-host", QEMU_CAPS_CCID_EMULATED);
    DO_TEST("smartcard-host-certificates", QEMU_CAPS_CCID_EMULATED);
    DO_TEST("smartcard-host-certificates-database",
            QEMU_CAPS_CCID_EMULATED);
    DO_TEST("smartcard-passthrough-tcp", QEMU_CAPS_CCID_PASSTHRU);
    DO_TEST("smartcard-passthrough-spicevmc", QEMU_CAPS_CCID_PASSTHRU);
    DO_TEST("smartcard-controller", QEMU_CAPS_CCID_EMULATED);

    DO_TEST("pseries-cpu-compat-power9",
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE);
    DO_TEST("pseries-cpu-compat",
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE);
    DO_TEST("pseries-cpu-exact",
            QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE);

    DO_TEST("user-aliases",
            QEMU_CAPS_DEVICE_CIRRUS_VGA,
            QEMU_CAPS_QCOW2_LUKS,
            QEMU_CAPS_OBJECT_MEMORY_FILE,
            QEMU_CAPS_PIIX_DISABLE_S3,
            QEMU_CAPS_PIIX_DISABLE_S4,
            QEMU_CAPS_VNC,
            QEMU_CAPS_CCID_EMULATED);
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
            QEMU_CAPS_VIRTIO_SCSI,
            QEMU_CAPS_MCH_EXTENDED_TSEG_MBYTES);

    DO_TEST("vhost-vsock", QEMU_CAPS_DEVICE_VHOST_VSOCK);
    DO_TEST("vhost-vsock-auto", QEMU_CAPS_DEVICE_VHOST_VSOCK);
    DO_TEST("vhost-vsock-ccw", QEMU_CAPS_DEVICE_VHOST_VSOCK,
            QEMU_CAPS_CCW);
    DO_TEST("vhost-vsock-ccw-auto", QEMU_CAPS_DEVICE_VHOST_VSOCK,
            QEMU_CAPS_CCW);
    DO_TEST_CAPS_ARCH_LATEST("vhost-vsock-ccw-iommu", "s390x");


    DO_TEST_CAPS_LATEST("vhost-user-fs-fd-memory");
    DO_TEST_CAPS_LATEST("vhost-user-fs-hugepages");
    DO_TEST_CAPS_LATEST("vhost-user-fs-sock");

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

    DO_TEST_CAPS_VER("cpu-Icelake-Server-pconfig", "3.1.0");
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

    DO_TEST_CAPS_LATEST("virtio-9p-multidevs");
    DO_TEST_CAPS_LATEST("virtio-9p-createmode");
    DO_TEST("downscript", NONE);

    /* Simplest possible <audio>, all supported with ENV */
    DO_TEST("audio-none-minimal", NONE);
    DO_TEST("audio-alsa-minimal", NONE);
    DO_TEST("audio-coreaudio-minimal", NONE);
    DO_TEST("audio-oss-minimal", NONE);
    DO_TEST("audio-pulseaudio-minimal", NONE);
    DO_TEST("audio-sdl-minimal", NONE);
    DO_TEST("audio-spice-minimal", NONE);
    DO_TEST("audio-file-minimal", NONE);

    /* Best <audio> still compat with old ENV */
    DO_TEST("audio-none-best", NONE);
    DO_TEST("audio-alsa-best", NONE);
    DO_TEST("audio-coreaudio-best", NONE);
    DO_TEST("audio-oss-best", NONE);
    DO_TEST("audio-pulseaudio-best", NONE);
    DO_TEST("audio-sdl-best", NONE);
    DO_TEST("audio-spice-best", NONE);
    DO_TEST("audio-file-best", NONE);

    /* Full <audio> only compat with new QEMU -audiodev args */
    DO_TEST("audio-none-full", QEMU_CAPS_AUDIODEV);
    DO_TEST("audio-alsa-full", QEMU_CAPS_AUDIODEV);
    DO_TEST("audio-coreaudio-full", QEMU_CAPS_AUDIODEV);
    DO_TEST("audio-jack-full", QEMU_CAPS_AUDIODEV);
    DO_TEST("audio-oss-full", QEMU_CAPS_AUDIODEV);
    DO_TEST("audio-pulseaudio-full", QEMU_CAPS_AUDIODEV);
    DO_TEST("audio-sdl-full", QEMU_CAPS_AUDIODEV);
    DO_TEST("audio-spice-full", QEMU_CAPS_AUDIODEV);
    DO_TEST("audio-file-full", QEMU_CAPS_AUDIODEV);

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

 cleanup:
    if (getenv("LIBVIRT_SKIP_CLEANUP") == NULL)
        virFileDeleteTree(fakerootdir);

    qemuTestDriverFree(&driver);
    virFileWrapperClearPrefixes();

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN_PRELOAD(mymain,
                      VIR_TEST_MOCK("virpci"),
                      VIR_TEST_MOCK("virrandom"),
                      VIR_TEST_MOCK("domaincaps"))
