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

    if (info->flags & FLAG_SKIP_CONFIG_ACTIVE)
        return EXIT_AM_SKIP;

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


/**
 * testInfoSetPaths:
 * @info: test info structure to populate
 * @suffix: suffix used to create output file name e.g. ".x86-64_latest"
 * @statesuffix: suffix to create output file name based on tested state ("active" | "inactive")
 *
 * This function populates @info with the correct input and output file paths.
 *
 * The output file is chosen based on whether a version with @statesuffix exists.
 * If yes, it's used, if no the @statesuffix is omitted and it's expected that
 * both the "active" and "inactive" versions are the same.
 */
static void
testInfoSetPaths(struct testQemuInfo *info,
                 const char *suffix,
                 const char *statesuffix)
{
    VIR_FREE(info->infile);
    VIR_FREE(info->outfile);

    info->infile = g_strdup_printf("%s/qemuxml2argvdata/%s.xml", abs_srcdir,
                                   info->name);

    info->outfile = g_strdup_printf("%s/qemuxml2xmloutdata/%s-%s%s.xml",
                                    abs_srcdir, info->name,
                                    statesuffix, suffix);

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

#define DO_TEST_CAPS_INTERNAL(_name, arch, ver, ...) \
    do { \
        static struct testQemuInfo info = { \
            .name = _name, \
        }; \
        testQemuInfoSetArgs(&info, &testConf, \
                            ARG_CAPS_ARCH, arch, \
                            ARG_CAPS_VER, ver, \
                            __VA_ARGS__, ARG_END); \
 \
        testInfoSetPaths(&info, "." arch "-" ver, "inactive"); \
        virTestRunLog(&ret, "QEMU XML-2-XML-inactive " _name, testXML2XMLInactive, &info); \
 \
        testInfoSetPaths(&info, "." arch "-" ver, "active"); \
        virTestRunLog(&ret, "QEMU XML-2-XML-active " _name, testXML2XMLActive, &info); \
        testQemuInfoClear(&info); \
    } while (0)

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

#define DO_TEST_CAPS_LATEST_ABI_UPDATE(name) \
    DO_TEST_CAPS_ARCH_LATEST_ABI_UPDATE(name, "x86_64")

#define DO_TEST_CAPS_VER(name, ver) \
    DO_TEST_CAPS_ARCH_VER(name, "x86_64", ver)

    /* Unset or set all envvars here that are copied in qemudBuildCommandLine
     * using ADD_ENV_COPY, otherwise these tests may fail due to unexpected
     * values for these envvars */
    g_setenv("PATH", "/bin", TRUE);
    g_unsetenv("QEMU_AUDIO_DRV");
    g_unsetenv("SDL_AUDIODRIVER");

    DO_TEST_CAPS_LATEST("minimal");
    DO_TEST_CAPS_LATEST("genid");
    DO_TEST_CAPS_LATEST("genid-auto");
    DO_TEST_CAPS_LATEST("machine-core-on");
    DO_TEST_CAPS_LATEST("machine-core-off");
    DO_TEST_CAPS_LATEST("machine-smm-on");
    DO_TEST_CAPS_LATEST("machine-smm-off");
    DO_TEST_CAPS_ARCH_LATEST("machine-loadparm-hostdev", "s390x");
    DO_TEST_CAPS_ARCH_LATEST("machine-loadparm-multiple-disks-nets-s390", "s390x");
    DO_TEST_CAPS_LATEST("default-kvm-host-arch");
    DO_TEST_CAPS_LATEST("default-qemu-host-arch");
    DO_TEST_CAPS_LATEST("boot-cdrom");
    DO_TEST_CAPS_LATEST("boot-network");
    DO_TEST_CAPS_LATEST("boot-floppy");
    DO_TEST_CAPS_LATEST("boot-floppy-q35");
    DO_TEST_CAPS_LATEST("boot-multi");
    DO_TEST_CAPS_LATEST("boot-menu-enable-with-timeout");
    DO_TEST_CAPS_LATEST("boot-menu-disable");
    DO_TEST_CAPS_LATEST("boot-menu-disable-with-timeout");
    DO_TEST_CAPS_LATEST("boot-order");

    DO_TEST_CAPS_LATEST("reboot-timeout-enabled");
    DO_TEST_CAPS_LATEST("reboot-timeout-disabled");

    DO_TEST_CAPS_LATEST("clock-utc");
    DO_TEST_CAPS_LATEST("clock-localtime");
    DO_TEST_CAPS_LATEST("cpu-empty");
    DO_TEST_CAPS_LATEST("cpu-kvmclock");
    DO_TEST_CAPS_LATEST("cpu-host-kvmclock");
    DO_TEST_CAPS_LATEST("cpu-host-passthrough-features");
    DO_TEST_CAPS_LATEST("cpu-host-model-features");
    DO_TEST_CAPS_LATEST("cpu-host-model-vendor");
    DO_TEST_CAPS_LATEST("clock-catchup");
    DO_TEST_CAPS_LATEST("kvmclock");
    DO_TEST_CAPS_LATEST("clock-timer-hyperv-rtc");
    DO_TEST_CAPS_ARCH_LATEST("clock-timer-armvtimer", "aarch64");
    DO_TEST_CAPS_LATEST("clock-realtime");
    DO_TEST_CAPS_LATEST("clock-absolute");

    DO_TEST_CAPS_LATEST("cpu-eoi-disabled");
    DO_TEST_CAPS_LATEST("cpu-eoi-enabled");
    DO_TEST_CAPS_LATEST("eoi-disabled");
    DO_TEST_CAPS_LATEST("eoi-enabled");
    DO_TEST_CAPS_LATEST("pv-spinlock-disabled");
    DO_TEST_CAPS_LATEST("pv-spinlock-enabled");

    DO_TEST_CAPS_LATEST("hyperv");
    DO_TEST_CAPS_LATEST("hyperv-off");
    DO_TEST_CAPS_LATEST("hyperv-panic");
    DO_TEST_CAPS_LATEST("hyperv-passthrough");
    DO_TEST_CAPS_LATEST("hyperv-stimer-direct");

    DO_TEST_CAPS_LATEST("kvm-features");
    DO_TEST_CAPS_LATEST("kvm-features-off");

    DO_TEST_CAPS_LATEST("pmu-feature");
    DO_TEST_CAPS_LATEST("pmu-feature-off");

    DO_TEST_CAPS_LATEST("pages-discard");
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
    DO_TEST_CAPS_LATEST("nosharepages");
    DO_TEST_CAPS_LATEST("restore-v2");
    DO_TEST_CAPS_LATEST("migrate");
    DO_TEST_CAPS_LATEST("qemu-ns-no-env");
    DO_TEST_CAPS_LATEST("qemu-ns");
    DO_TEST_CAPS_LATEST("disk-aio");
    DO_TEST_CAPS_LATEST("disk-aio-io_uring");
    DO_TEST_CAPS_LATEST("disk-cdrom");
    /* The 'disk-cdrom-empty-network-invalid' test case uses separate
     * '-active'/'-inactive' output files to work around 'virschematest'
     * thinking the output file is invalid XML */
    DO_TEST_CAPS_LATEST("disk-cdrom-empty-network-invalid");
    DO_TEST_CAPS_LATEST("disk-cdrom-network");
    DO_TEST_CAPS_LATEST("disk-cdrom-bus-other");
    DO_TEST_CAPS_LATEST("disk-floppy");
    DO_TEST_CAPS_LATEST("disk-usb-device");
    DO_TEST_CAPS_LATEST("disk-virtio");
    DO_TEST_CAPS_LATEST("disk-blockio");
    DO_TEST_CAPS_LATEST("floppy-drive-fat");
    DO_TEST_CAPS_LATEST("disk-virtio-queues");
    DO_TEST_CAPS_LATEST("disk-boot-disk");
    DO_TEST_CAPS_LATEST("disk-boot-cdrom");
    DO_TEST_CAPS_LATEST("disk-error-policy");
    DO_TEST_CAPS_LATEST("disk-transient");
    DO_TEST_CAPS_LATEST("disk-fmt-qcow");
    DO_TEST_CAPS_LATEST("disk-cache");
    DO_TEST_CAPS_LATEST("disk-metadata-cache");
    DO_TEST_CAPS_LATEST("disk-network-nbd");
    DO_TEST_CAPS_LATEST("disk-network-iscsi");
    DO_TEST_CAPS_LATEST("disk-network-gluster");
    DO_TEST_CAPS_LATEST("disk-network-rbd");
    DO_TEST_CAPS_LATEST("disk-network-rbd-encryption");
    DO_TEST_CAPS_LATEST("disk-network-rbd-encryption-layering");
    DO_TEST_CAPS_LATEST("disk-network-rbd-encryption-luks-any");
    DO_TEST_CAPS_LATEST("disk-network-source-auth");
    DO_TEST_CAPS_LATEST("disk-network-sheepdog");
    DO_TEST_CAPS_VER("disk-network-vxhs", "5.0.0");
    DO_TEST_CAPS_LATEST("disk-network-nfs");
    DO_TEST_CAPS_LATEST("disk-network-tlsx509-nbd");
    DO_TEST_CAPS_LATEST("disk-network-tlsx509-nbd-hostname");
    DO_TEST_CAPS_VER("disk-network-tlsx509-vxhs", "5.0.0");
    DO_TEST_CAPS_LATEST("disk-nvme");
    DO_TEST_CAPS_LATEST("disk-vhostuser");
    DO_TEST_CAPS_LATEST("disk-sata-device");
    DO_TEST_CAPS_LATEST("disk-scsi");
    DO_TEST_CAPS_LATEST("disk-virtio-scsi-reservations");
    DO_TEST_CAPS_LATEST("controller-virtio-scsi");
    DO_TEST_CAPS_ARCH_LATEST("disk-virtio-s390-zpci", "s390x");
    DO_TEST_CAPS_LATEST("disk-mirror-old");
    DO_TEST_CAPS_LATEST("disk-mirror");
    DO_TEST_CAPS_LATEST("disk-active-commit");
    DO_TEST_CAPS_LATEST("graphics-listen-network");
    DO_TEST_CAPS_LATEST("graphics-vnc");
    DO_TEST_CAPS_LATEST("graphics-vnc-websocket");
    DO_TEST_CAPS_LATEST("graphics-vnc-sasl");
    DO_TEST_CAPS_LATEST("graphics-vnc-tls");
    DO_TEST_CAPS_LATEST("graphics-vnc-no-listen-attr");
    DO_TEST_CAPS_LATEST("graphics-vnc-remove-generated-socket");
    cfg->vncAutoUnixSocket = true;
    DO_TEST_CAPS_LATEST("graphics-vnc-auto-socket-cfg");
    cfg->vncAutoUnixSocket = false;
    DO_TEST_CAPS_LATEST("graphics-vnc-socket");
    DO_TEST_CAPS_LATEST("graphics-vnc-auto-socket");
    DO_TEST_CAPS_LATEST("graphics-vnc-egl-headless");

    DO_TEST_CAPS_LATEST("graphics-dbus");
    DO_TEST_CAPS_LATEST("graphics-dbus-address");
    DO_TEST_CAPS_LATEST("graphics-dbus-p2p");
    DO_TEST_CAPS_LATEST("graphics-dbus-audio");
    DO_TEST_CAPS_LATEST("graphics-dbus-chardev");

    DO_TEST_CAPS_ARCH_LATEST("default-video-type-aarch64", "aarch64");
    DO_TEST_CAPS_ARCH_LATEST("default-video-type-ppc64", "ppc64");
    DO_TEST_CAPS_ARCH_LATEST("default-video-type-riscv64", "riscv64");
    DO_TEST_CAPS_ARCH_LATEST("default-video-type-s390x", "s390x");
    DO_TEST_CAPS_LATEST("default-video-type-x86_64");

    DO_TEST_CAPS_LATEST("graphics-sdl");
    DO_TEST_CAPS_LATEST("graphics-sdl-fullscreen");

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

    DO_TEST_CAPS_LATEST("graphics-egl-headless-rendernode");

    DO_TEST_CAPS_LATEST("input-usbmouse");
    DO_TEST_CAPS_LATEST("input-usbtablet");
    DO_TEST_CAPS_LATEST("misc-acpi");
    DO_TEST_CAPS_LATEST("misc-disable-s3");
    DO_TEST_CAPS_LATEST("pc-i440fx-acpi-root-hotplug-disable");
    DO_TEST_CAPS_LATEST("pc-i440fx-acpi-root-hotplug-enable");
    DO_TEST_CAPS_LATEST("misc-disable-suspends");
    DO_TEST_CAPS_LATEST("misc-enable-s4");
    DO_TEST_CAPS_LATEST("misc-no-reboot");
    DO_TEST_CAPS_LATEST("misc-uuid");
    DO_TEST_CAPS_LATEST("net-vhostuser");
    DO_TEST_CAPS_LATEST("net-user");
    DO_TEST_CAPS_LATEST("net-user-addr");
    DO_TEST_CAPS_LATEST("net-user-passt");
    DO_TEST_CAPS_LATEST("net-virtio");
    DO_TEST_CAPS_LATEST("net-virtio-device");
    DO_TEST_CAPS_LATEST("net-virtio-disable-offloads");
    DO_TEST_CAPS_LATEST("net-eth");
    DO_TEST_CAPS_LATEST("net-eth-ifname");
    DO_TEST_CAPS_LATEST("net-eth-hostip");
    DO_TEST_CAPS_LATEST("net-eth-unmanaged-tap");
    DO_TEST_CAPS_LATEST("net-virtio-network-portgroup");
    DO_TEST_CAPS_LATEST("net-virtio-rxtxqueuesize");
    DO_TEST_CAPS_LATEST("net-virtio-teaming");
    DO_TEST_CAPS_LATEST("net-virtio-teaming-network");
    DO_TEST_CAPS_LATEST("net-virtio-teaming-hostdev");
    DO_TEST_CAPS_LATEST("net-isolated-port");
    DO_TEST_CAPS_LATEST("net-hostdev");
    DO_TEST_CAPS_LATEST("net-hostdev-bootorder");
    DO_TEST_CAPS_LATEST("net-hostdev-vfio");
    DO_TEST_CAPS_LATEST("net-midonet");
    DO_TEST_CAPS_LATEST("net-openvswitch");
    DO_TEST_CAPS_LATEST("sound-device");
    DO_TEST_CAPS_LATEST("watchdog");
    DO_TEST_CAPS_LATEST("watchdog-q35-multiple");
    DO_TEST_CAPS_LATEST("net-bandwidth");
    DO_TEST_CAPS_LATEST("net-bandwidth2");
    DO_TEST_CAPS_LATEST("net-mtu");
    DO_TEST_CAPS_LATEST("net-coalesce");
    DO_TEST_CAPS_LATEST("net-many-models");
    DO_TEST_CAPS_LATEST("net-vdpa");
    DO_TEST_CAPS_LATEST("net-vdpa-multiqueue");
    DO_TEST_CAPS_LATEST("net-virtio-rss");

    DO_TEST_CAPS_LATEST("serial-tcp-tlsx509-chardev");
    DO_TEST_CAPS_LATEST("serial-tcp-tlsx509-chardev-notls");

    cfg->spiceTLS = true;
    DO_TEST_CAPS_LATEST("serial-spiceport");
    cfg->spiceTLS = false;

    DO_TEST_CAPS_LATEST("serial-debugcon");
    DO_TEST_CAPS_LATEST("console-compat");
    DO_TEST_CAPS_LATEST("console-compat2");
    DO_TEST_CAPS_LATEST("console-virtio-many");
    DO_TEST_CAPS_LATEST("channel-guestfwd");
    DO_TEST_CAPS_LATEST("channel-virtio");
    DO_TEST_CAPS_LATEST("channel-virtio-state");

    DO_TEST_CAPS_LATEST("channel-unix-source-path");

    DO_TEST_CAPS_LATEST("hostdev-usb-address");
    DO_TEST_CAPS_LATEST("hostdev-pci-address");
    DO_TEST_CAPS_LATEST("hostdev-pci-address-unassigned");
    DO_TEST_CAPS_LATEST("hostdev-pci-multifunction");
    DO_TEST_CAPS_LATEST("hostdev-vfio");
    DO_TEST_CAPS_ARCH_LATEST("hostdev-vfio-zpci", "s390x");
    DO_TEST_CAPS_ARCH_LATEST("hostdev-vfio-zpci-multidomain-many", "s390x");
    DO_TEST_CAPS_ARCH_LATEST("hostdev-vfio-zpci-autogenerate", "s390x");
    DO_TEST_CAPS_ARCH_LATEST("hostdev-vfio-zpci-autogenerate-uids", "s390x");
    DO_TEST_CAPS_ARCH_LATEST("hostdev-vfio-zpci-autogenerate-fids", "s390x");
    DO_TEST_CAPS_ARCH_LATEST("hostdev-vfio-zpci-boundaries", "s390x");
    DO_TEST_CAPS_ARCH_LATEST("hostdev-vfio-zpci-ccw-memballoon", "s390x");
    DO_TEST_CAPS_LATEST("hostdev-mdev-precreated");
    DO_TEST_CAPS_LATEST("hostdev-mdev-display");
    DO_TEST_CAPS_LATEST("hostdev-mdev-display-ramfb");
    DO_TEST_CAPS_LATEST("pci-rom");
    DO_TEST_CAPS_LATEST("pci-rom-disabled");
    DO_TEST_CAPS_LATEST("pci-rom-disabled-invalid");
    DO_TEST_CAPS_LATEST("pci-serial-dev-chardev");

    DO_TEST_CAPS_LATEST("disk-slices");
    DO_TEST_CAPS_LATEST("disk-rotation");

    DO_TEST_CAPS_LATEST("encrypted-disk");
    DO_TEST_CAPS_LATEST("encrypted-disk-usage");
    DO_TEST_CAPS_LATEST("luks-disks");
    DO_TEST_CAPS_LATEST("luks-disks-source");
    DO_TEST_CAPS_LATEST("luks-disks-source-qcow2");
    DO_TEST_CAPS_LATEST("memtune");
    DO_TEST_CAPS_LATEST("memtune-unlimited");
    DO_TEST_CAPS_LATEST("blkiotune");
    DO_TEST_CAPS_LATEST("blkiotune-device");
    DO_TEST_CAPS_LATEST("cputune");
    DO_TEST_CAPS_LATEST("cputune-zero-shares");
    DO_TEST_CAPS_LATEST("cputune-numatune");
    DO_TEST_CAPS_LATEST("vcpu-placement-static");
    DO_TEST_CAPS_LATEST("cputune-cpuset-big-id");
    DO_TEST_CAPS_LATEST("numavcpus-topology-mismatch");

    DO_TEST_CAPS_LATEST("iothreads-ids");
    DO_TEST_CAPS_LATEST("iothreads-ids-pool-sizes");
    DO_TEST_CAPS_LATEST("iothreads-ids-partial");
    DO_TEST_CAPS_LATEST("iothreads-disk");
    DO_TEST_CAPS_ARCH_LATEST("iothreads-disk-virtio-ccw", "s390x");
    DO_TEST_CAPS_LATEST("iothreads-virtio-scsi-pci");
    DO_TEST_CAPS_ARCH_LATEST("iothreads-virtio-scsi-ccw", "s390x");
    DO_TEST_CAPS_LATEST("lease");
    DO_TEST_CAPS_LATEST("event_idx");
    DO_TEST_CAPS_LATEST("vhost_queues");
    DO_TEST_CAPS_LATEST("interface-driver");
    DO_TEST_CAPS_LATEST("net-server");
    DO_TEST_CAPS_LATEST("virtio-lun");

    DO_TEST_CAPS_LATEST("usb-none");
    DO_TEST_CAPS_LATEST("usb-controller-implicit-isapc");
    DO_TEST_CAPS_LATEST("usb-controller-implicit-i440fx");
    DO_TEST_CAPS_LATEST("usb-controller-implicit-q35");
    DO_TEST_CAPS_LATEST("usb-controller-default-i440fx");
    DO_TEST_CAPS_LATEST("usb-controller-default-q35");
    DO_TEST_CAPS_LATEST("usb-controller-piix3");
    DO_TEST_CAPS_LATEST("usb-controller-ich9-ehci-addr");
    DO_TEST_CAPS_LATEST("usb-controller-nec-xhci");
    DO_TEST_CAPS_ARCH_LATEST_FULL("usb-controller-default-unavailable-i440fx", "x86_64",
                                  ARG_QEMU_CAPS_DEL, QEMU_CAPS_PIIX3_USB_UHCI, QEMU_CAPS_LAST);
    DO_TEST_CAPS_ARCH_LATEST("ppc64-usb-controller", "ppc64");
    DO_TEST_CAPS_ARCH_LATEST("ppc64-usb-controller-legacy", "ppc64");
    DO_TEST_CAPS_LATEST("usb-port-missing");
    DO_TEST_CAPS_LATEST("usb-redir");
    DO_TEST_CAPS_LATEST("usb-redir-filter");
    DO_TEST_CAPS_LATEST("usb-redir-filter-version");
    DO_TEST_CAPS_LATEST("blkdeviotune");
    DO_TEST_CAPS_LATEST("blkdeviotune-max");
    DO_TEST_CAPS_LATEST("blkdeviotune-group-num");
    DO_TEST_CAPS_LATEST("blkdeviotune-max-length");
    DO_TEST_CAPS_LATEST("controller-usb-order");
    DO_TEST_CAPS_ARCH_LATEST("ppc64-tpmproxy-single", "ppc64");
    DO_TEST_CAPS_ARCH_LATEST("ppc64-tpmproxy-with-tpm", "ppc64");

    DO_TEST_CAPS_ARCH_LATEST_FULL("seclabel-dynamic-baselabel", "x86_64", ARG_FLAGS, FLAG_SKIP_CONFIG_ACTIVE, ARG_END);
    DO_TEST_CAPS_ARCH_LATEST_FULL("seclabel-dynamic-override", "x86_64", ARG_FLAGS, FLAG_SKIP_CONFIG_ACTIVE, ARG_END);
    DO_TEST_CAPS_ARCH_LATEST_FULL("seclabel-dynamic-labelskip", "x86_64", ARG_FLAGS, FLAG_SKIP_CONFIG_ACTIVE, ARG_END);
    DO_TEST_CAPS_ARCH_LATEST_FULL("seclabel-dynamic-relabel", "x86_64", ARG_FLAGS, FLAG_SKIP_CONFIG_ACTIVE, ARG_END);
    DO_TEST_CAPS_LATEST("seclabel-static");
    DO_TEST_CAPS_LATEST("seclabel-static-labelskip");
    DO_TEST_CAPS_LATEST("seclabel-none");
    DO_TEST_CAPS_LATEST("seclabel-dac-none");
    DO_TEST_CAPS_LATEST("seclabel-dynamic-none");
    DO_TEST_CAPS_LATEST("seclabel-device-multiple");
    DO_TEST_CAPS_ARCH_LATEST_FULL("seclabel-dynamic-none-relabel", "x86_64", ARG_FLAGS, FLAG_SKIP_CONFIG_ACTIVE, ARG_END);
    DO_TEST_CAPS_LATEST("numad-static-vcpu-no-numatune");

    DO_TEST_CAPS_LATEST("disk-scsi-disk-vpd");
    DO_TEST_CAPS_LATEST("disk-source-pool");
    DO_TEST_CAPS_LATEST("disk-source-pool-mode");

    DO_TEST_CAPS_LATEST("disk-discard");
    DO_TEST_CAPS_LATEST("disk-detect-zeroes");
    DO_TEST_CAPS_LATEST("disk-discard_no_unref");

    DO_TEST_CAPS_LATEST("disk-serial");

    DO_TEST_CAPS_ARCH_LATEST("disk-arm-virtio-sd", "aarch64");

    DO_TEST_CAPS_LATEST("virtio-rng-random");
    DO_TEST_CAPS_LATEST("virtio-rng-egd");
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

    DO_TEST_CAPS_LATEST("balloon-device-auto");
    DO_TEST_CAPS_LATEST("balloon-device-period");
    DO_TEST_CAPS_LATEST("channel-virtio-auto");
    DO_TEST_CAPS_LATEST("console-compat-auto");
    DO_TEST_CAPS_LATEST("disk-scsi-device-auto");
    DO_TEST_CAPS_LATEST("console-virtio");
    DO_TEST_CAPS_LATEST("serial-target-port-auto");
    DO_TEST_CAPS_LATEST("graphics-listen-network2");
    DO_TEST_CAPS_LATEST("numad-auto-vcpu-no-numatune");
    DO_TEST_CAPS_LATEST("numad-auto-memory-vcpu-no-cpuset-and-placement");
    DO_TEST_CAPS_LATEST("numad-auto-memory-vcpu-cpuset");
    DO_TEST_CAPS_LATEST("disk-copy_on_read");
    DO_TEST_CAPS_LATEST("tpm-passthrough");
    DO_TEST_CAPS_LATEST("tpm-passthrough-crb");
    DO_TEST_CAPS_LATEST("tpm-emulator");
    DO_TEST_CAPS_ARCH_LATEST("tpm-emulator-spapr", "ppc64");
    DO_TEST_CAPS_LATEST("tpm-emulator-tpm2");
    DO_TEST_CAPS_LATEST("tpm-emulator-tpm2-enc");
    DO_TEST_CAPS_LATEST("tpm-emulator-tpm2-pstate");
    DO_TEST_CAPS_ARCH_LATEST("aarch64-tpm", "aarch64");
    DO_TEST_CAPS_LATEST("tpm-external");

    DO_TEST_CAPS_LATEST("metadata");
    DO_TEST_CAPS_LATEST("metadata-duplicate");

    DO_TEST_CAPS_LATEST("pci-bridge");
    DO_TEST_CAPS_LATEST("pci-many");
    DO_TEST_CAPS_LATEST("pci-bridge-many-disks");
    DO_TEST_CAPS_LATEST("pci-autoadd-addr");
    DO_TEST_CAPS_LATEST("pci-autoadd-idx");
    DO_TEST_CAPS_LATEST("pci-autofill-addr");

    DO_TEST_CAPS_LATEST("q35");
    DO_TEST_CAPS_LATEST("q35-usb2");
    DO_TEST_CAPS_LATEST("q35-usb2-multi");
    DO_TEST_CAPS_LATEST("q35-usb2-reorder");
    DO_TEST_CAPS_LATEST("q35-pcie");
    /* same as q35-pcie, but all PCI controllers are added automatically */
    DO_TEST_CAPS_LATEST("q35-pcie-autoadd");
    DO_TEST_CAPS_LATEST("q35-default-devices-only");
    DO_TEST_CAPS_LATEST("q35-multifunction");
    DO_TEST_CAPS_LATEST("q35-virt-manager-basic");
    DO_TEST_CAPS_LATEST("pcie-root");

    /* Test automatic and manual setting of pcie-root-port attributes */
    DO_TEST_CAPS_LATEST("pcie-root-port");

    /* Make sure the default model for PCIe Root Ports is picked correctly
     * based on QEMU binary capabilities. We use x86/q35 for the test, but
     * any PCIe machine type (such as aarch64/virt) will behave the same */
    DO_TEST_CAPS_LATEST("pcie-root-port-model-generic");
    DO_TEST_CAPS_LATEST("pcie-root-port-model-ioh3420");
    DO_TEST_CAPS_LATEST("pcie-root-port-nohotplug");
    DO_TEST_CAPS_LATEST("pcie-switch-upstream-port");
    DO_TEST_CAPS_LATEST("pcie-switch-downstream-port");
    DO_TEST_CAPS_LATEST("pci-expander-bus");
    DO_TEST_CAPS_LATEST("pcie-expander-bus");
    DO_TEST_CAPS_ARCH_LATEST("pcie-expander-bus-aarch64", "aarch64");
    DO_TEST_CAPS_LATEST("autoindex");
    /* Make sure the user can always override libvirt's default device
     * placement policy by providing an explicit PCI address */
    DO_TEST_CAPS_LATEST("q35-pci-force-address");

    DO_TEST_CAPS_ARCH_LATEST("hostdev-scsi-vhost-scsi-ccw", "s390x");
    DO_TEST_CAPS_LATEST("hostdev-scsi-vhost-scsi-pci");
    DO_TEST_CAPS_LATEST("hostdev-scsi-vhost-scsi-pcie");
    DO_TEST_CAPS_LATEST("hostdev-scsi-lsi");
    DO_TEST_CAPS_LATEST("hostdev-scsi-virtio-scsi");

    DO_TEST_CAPS_LATEST("hostdev-scsi-shareable");

    DO_TEST_CAPS_LATEST("hostdev-scsi-autogen-address");
    DO_TEST_CAPS_LATEST("hostdev-scsi-large-unit");

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

    DO_TEST_CAPS_LATEST("pcihole64");
    DO_TEST_CAPS_LATEST("pcihole64-gib");
    DO_TEST_CAPS_LATEST("pcihole64-q35");

    DO_TEST_CAPS_LATEST("panic");
    DO_TEST_CAPS_LATEST("panic-double");
    DO_TEST_CAPS_LATEST("panic-no-address");
    DO_TEST_CAPS_ARCH_LATEST("panic-pseries", "ppc64");

    DO_TEST_CAPS_LATEST("pvpanic-pci-x86_64");
    DO_TEST_CAPS_ARCH_LATEST("pvpanic-pci-aarch64", "aarch64");
    DO_TEST_CAPS_ARCH_LATEST("pvpanic-pci-no-address-aarch64", "aarch64");

    DO_TEST_CAPS_LATEST("disk-backing-chains-index");
    DO_TEST_CAPS_LATEST("disk-backing-chains-noindex");

    DO_TEST_CAPS_LATEST("disk-source-fd");

    DO_TEST_CAPS_LATEST("disk-network-http");

    DO_TEST_CAPS_LATEST("chardev-label");

    DO_TEST_CAPS_LATEST("cpu-numa1");
    DO_TEST_CAPS_LATEST("cpu-numa2");
    DO_TEST_CAPS_LATEST("cpu-numa-no-memory-element");
    DO_TEST_CAPS_LATEST("cpu-numa-disordered");
    DO_TEST_CAPS_LATEST("cpu-numa-disjoint");
    DO_TEST_CAPS_LATEST("cpu-numa-memshared");

    DO_TEST_CAPS_LATEST("numatune-auto-prefer");
    DO_TEST_CAPS_LATEST("numatune-memnode");
    DO_TEST_CAPS_LATEST("numatune-memnode-no-memory");
    DO_TEST_CAPS_LATEST("numatune-distances");
    DO_TEST_CAPS_LATEST("numatune-no-vcpu");
    DO_TEST_CAPS_LATEST("numatune-hmat");
    DO_TEST_CAPS_LATEST("numatune-hmat-none");
    DO_TEST_CAPS_LATEST("numatune-memnode-restrictive-mode");

    DO_TEST_CAPS_LATEST("firmware-manual-bios");
    DO_TEST_CAPS_LATEST("firmware-manual-bios-stateless");
    DO_TEST_CAPS_LATEST("firmware-manual-efi");
    DO_TEST_CAPS_LATEST("firmware-manual-efi-features");
    DO_TEST_CAPS_LATEST("firmware-manual-efi-rw");
    DO_TEST_CAPS_LATEST("firmware-manual-efi-rw-legacy-paths");
    DO_TEST_CAPS_LATEST("firmware-manual-efi-rw-modern-paths");
    DO_TEST_CAPS_LATEST("firmware-manual-efi-rw-implicit");
    DO_TEST_CAPS_LATEST("firmware-manual-efi-loader-secure");
    DO_TEST_CAPS_LATEST("firmware-manual-efi-loader-path-nonstandard");
    DO_TEST_CAPS_LATEST("firmware-manual-efi-secboot");
    DO_TEST_CAPS_LATEST("firmware-manual-efi-no-enrolled-keys");
    DO_TEST_CAPS_LATEST("firmware-manual-efi-no-secboot");
    DO_TEST_CAPS_LATEST("firmware-manual-efi-stateless");
    DO_TEST_CAPS_LATEST("firmware-manual-efi-nvram-template");
    DO_TEST_CAPS_LATEST("firmware-manual-efi-nvram-template-nonstandard");
    DO_TEST_CAPS_LATEST("firmware-manual-efi-nvram-network-iscsi");
    DO_TEST_CAPS_LATEST("firmware-manual-efi-nvram-network-nbd");
    DO_TEST_CAPS_LATEST("firmware-manual-efi-nvram-file");

    DO_TEST_CAPS_ARCH_LATEST("firmware-manual-efi-acpi-aarch64", "aarch64");
    DO_TEST_CAPS_LATEST("firmware-manual-efi-acpi-q35");
    DO_TEST_CAPS_ARCH_LATEST("firmware-manual-efi-noacpi-aarch64", "aarch64");
    DO_TEST_CAPS_LATEST("firmware-manual-noefi-acpi-q35");
    DO_TEST_CAPS_ARCH_LATEST("firmware-manual-noefi-noacpi-aarch64", "aarch64");
    DO_TEST_CAPS_LATEST("firmware-manual-noefi-noacpi-q35");

    /* Ensure that legacy firmware paths keep working */
    DO_TEST_CAPS_LATEST("firmware-manual-efi-secboot-legacy-paths");
    DO_TEST_CAPS_LATEST("firmware-manual-efi-no-enrolled-keys-legacy-paths");
    DO_TEST_CAPS_LATEST("firmware-manual-efi-no-secboot-legacy-paths");
    DO_TEST_CAPS_ARCH_LATEST("firmware-manual-efi-aarch64-legacy-paths", "aarch64");

    DO_TEST_CAPS_LATEST("firmware-auto-bios");
    DO_TEST_CAPS_LATEST("firmware-auto-bios-stateless");
    DO_TEST_CAPS_LATEST("firmware-auto-efi");
    DO_TEST_CAPS_LATEST_ABI_UPDATE("firmware-auto-efi-abi-update");
    DO_TEST_CAPS_LATEST("firmware-auto-efi-stateless");
    DO_TEST_CAPS_LATEST("firmware-auto-efi-rw");
    DO_TEST_CAPS_LATEST("firmware-auto-efi-loader-secure");
    DO_TEST_CAPS_LATEST_ABI_UPDATE("firmware-auto-efi-loader-secure-abi-update");
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
    DO_TEST_CAPS_LATEST("firmware-auto-efi-nvram-path");
    DO_TEST_CAPS_LATEST("firmware-auto-efi-nvram-template");
    DO_TEST_CAPS_LATEST("firmware-auto-efi-nvram-template-nonstandard");
    DO_TEST_CAPS_LATEST("firmware-auto-efi-nvram-file");
    DO_TEST_CAPS_LATEST("firmware-auto-efi-nvram-network-nbd");
    DO_TEST_CAPS_LATEST("firmware-auto-efi-nvram-network-iscsi");

    DO_TEST_CAPS_LATEST("firmware-auto-efi-format-loader-qcow2");
    DO_TEST_CAPS_LATEST("firmware-auto-efi-format-loader-qcow2-nvram-path");
    DO_TEST_CAPS_LATEST("firmware-auto-efi-format-nvram-qcow2");
    DO_TEST_CAPS_LATEST("firmware-auto-efi-format-nvram-qcow2-path");
    DO_TEST_CAPS_LATEST("firmware-auto-efi-format-nvram-qcow2-network-nbd");
    DO_TEST_CAPS_ARCH_LATEST("firmware-auto-efi-format-loader-raw", "aarch64");
    DO_TEST_CAPS_ARCH_LATEST_ABI_UPDATE("firmware-auto-efi-format-loader-raw-abi-update", "aarch64");

    DO_TEST_CAPS_LATEST("tap-vhost");
    DO_TEST_CAPS_LATEST("tap-vhost-incorrect");
    DO_TEST_CAPS_LATEST("shmem-plain-doorbell");
    DO_TEST_CAPS_LATEST("smbios");
    DO_TEST_CAPS_LATEST("smbios-multiple-type2");
    DO_TEST_CAPS_LATEST("smbios-type-fwcfg");

    DO_TEST_CAPS_ARCH_LATEST("aarch64-aavmf-virtio-mmio", "aarch64");
    DO_TEST_CAPS_ARCH_LATEST("aarch64-virtio-pci-default", "aarch64");
    DO_TEST_CAPS_ARCH_LATEST("aarch64-virtio-pci-manual-addresses", "aarch64");
    DO_TEST_CAPS_ARCH_LATEST("aarch64-video-virtio-gpu-pci", "aarch64");
    DO_TEST_CAPS_ARCH_LATEST("aarch64-pci-serial", "aarch64");
    DO_TEST_CAPS_ARCH_LATEST("aarch64-traditional-pci", "aarch64");
    DO_TEST_CAPS_ARCH_LATEST("aarch64-video-default", "aarch64");

    DO_TEST_CAPS_ARCH_LATEST_FULL("aarch64-gic-none", "aarch64", ARG_GIC, GIC_NONE, ARG_END);
    DO_TEST_CAPS_ARCH_LATEST_FULL("aarch64-gic-none-v2", "aarch64", ARG_GIC, GIC_V2, ARG_END);
    DO_TEST_CAPS_ARCH_LATEST_FULL("aarch64-gic-none-v3", "aarch64", ARG_GIC, GIC_V3, ARG_END);
    DO_TEST_CAPS_ARCH_LATEST_FULL("aarch64-gic-none-both", "aarch64", ARG_GIC, GIC_BOTH, ARG_END);
    DO_TEST_CAPS_ARCH_LATEST_FULL("aarch64-gic-none-tcg", "aarch64", ARG_GIC, GIC_BOTH, ARG_END);
    DO_TEST_CAPS_ARCH_LATEST_FULL("aarch64-gic-default", "aarch64", ARG_GIC, GIC_NONE, ARG_END);
    DO_TEST_CAPS_ARCH_LATEST_FULL("aarch64-gic-default-v2", "aarch64", ARG_GIC, GIC_V2, ARG_END);
    DO_TEST_CAPS_ARCH_LATEST_FULL("aarch64-gic-default-v3", "aarch64", ARG_GIC, GIC_V3, ARG_END);
    DO_TEST_CAPS_ARCH_LATEST_FULL("aarch64-gic-default-both", "aarch64", ARG_GIC, GIC_BOTH, ARG_END);
    DO_TEST_CAPS_ARCH_LATEST_FULL("aarch64-gic-v2", "aarch64", ARG_GIC, GIC_NONE, ARG_END);
    DO_TEST_CAPS_ARCH_LATEST_FULL("aarch64-gic-v2", "aarch64", ARG_GIC, GIC_V2, ARG_END);
    DO_TEST_CAPS_ARCH_LATEST_FULL("aarch64-gic-v2", "aarch64", ARG_GIC, GIC_V3, ARG_END);
    DO_TEST_CAPS_ARCH_LATEST_FULL("aarch64-gic-v2", "aarch64", ARG_GIC, GIC_BOTH, ARG_END);
    DO_TEST_CAPS_ARCH_LATEST_FULL("aarch64-gic-v3", "aarch64", ARG_GIC, GIC_NONE, ARG_END);
    DO_TEST_CAPS_ARCH_LATEST_FULL("aarch64-gic-v3", "aarch64", ARG_GIC, GIC_V2, ARG_END);
    DO_TEST_CAPS_ARCH_LATEST_FULL("aarch64-gic-v3", "aarch64", ARG_GIC, GIC_V3, ARG_END);
    DO_TEST_CAPS_ARCH_LATEST_FULL("aarch64-gic-v3", "aarch64", ARG_GIC, GIC_BOTH, ARG_END);
    DO_TEST_CAPS_ARCH_LATEST_FULL("aarch64-gic-host", "aarch64", ARG_GIC, GIC_NONE, ARG_END);
    DO_TEST_CAPS_ARCH_LATEST_FULL("aarch64-gic-host", "aarch64", ARG_GIC, GIC_V2, ARG_END);
    DO_TEST_CAPS_ARCH_LATEST_FULL("aarch64-gic-host", "aarch64", ARG_GIC, GIC_V3, ARG_END);
    DO_TEST_CAPS_ARCH_LATEST_FULL("aarch64-gic-host", "aarch64", ARG_GIC, GIC_BOTH, ARG_END);

    /* SVE aarch64 CPU features work on modern QEMU */
    DO_TEST_CAPS_ARCH_LATEST("aarch64-features-sve", "aarch64");

    DO_TEST_CAPS_ARCH_LATEST("aarch64-usb-controller", "aarch64");

    DO_TEST_CAPS_ARCH_LATEST("memory-hotplug-ppc64-nonuma", "ppc64");
    DO_TEST_CAPS_ARCH_LATEST_ABI_UPDATE("memory-hotplug-ppc64-nonuma-abi-update", "ppc64");
    DO_TEST_CAPS_LATEST("memory-hotplug");
    DO_TEST_CAPS_LATEST("memory-hotplug-dimm");
    DO_TEST_CAPS_LATEST("memory-hotplug-dimm-addr");
    DO_TEST_CAPS_LATEST("memory-hotplug-nvdimm");
    DO_TEST_CAPS_LATEST("memory-hotplug-nvdimm-access");
    DO_TEST_CAPS_LATEST("memory-hotplug-nvdimm-label");
    DO_TEST_CAPS_LATEST("memory-hotplug-nvdimm-align");
    DO_TEST_CAPS_LATEST("memory-hotplug-nvdimm-pmem");
    DO_TEST_CAPS_LATEST("memory-hotplug-nvdimm-readonly");
    DO_TEST_CAPS_ARCH_LATEST("memory-hotplug-nvdimm-ppc64", "ppc64");
    DO_TEST_CAPS_ARCH_LATEST_ABI_UPDATE("memory-hotplug-nvdimm-ppc64-abi-update", "ppc64");
    DO_TEST_CAPS_LATEST("memory-hotplug-virtio-pmem");
    DO_TEST_CAPS_LATEST("memory-hotplug-virtio-mem");
    DO_TEST_CAPS_LATEST("memory-hotplug-multiple");

    DO_TEST_CAPS_LATEST("net-udp");

    DO_TEST_CAPS_LATEST("video-virtio-gpu-device");
    DO_TEST_CAPS_LATEST("video-virtio-gpu-virgl");
    DO_TEST_CAPS_LATEST("video-virtio-gpu-spice-gl");
    DO_TEST_CAPS_LATEST("video-virtio-gpu-sdl-gl");

    DO_TEST_CAPS_LATEST("virtio-input");
    DO_TEST_CAPS_LATEST("virtio-input-passthrough");

    DO_TEST_CAPS_LATEST("input-linux");

    DO_TEST_CAPS_LATEST("memorybacking-set");
    DO_TEST_CAPS_LATEST("memorybacking-unset");

    DO_TEST_CAPS_LATEST("virtio-options");

    DO_TEST_CAPS_LATEST("fd-memory-numa-topology");
    DO_TEST_CAPS_LATEST("fd-memory-numa-topology2");
    DO_TEST_CAPS_LATEST("fd-memory-numa-topology3");
    DO_TEST_CAPS_LATEST("fd-memory-numa-topology4");

    DO_TEST_CAPS_LATEST("fd-memory-no-numa-topology");

    DO_TEST_CAPS_LATEST("memfd-memory-numa");
    DO_TEST_CAPS_LATEST("memfd-memory-default-hugepage");

    DO_TEST_CAPS_LATEST("acpi-table");

    DO_TEST_CAPS_LATEST("video-device-pciaddr-default");
    DO_TEST_CAPS_LATEST("video-qxl-heads");
    DO_TEST_CAPS_LATEST("video-qxl-noheads");
    DO_TEST_CAPS_LATEST("video-qxl-resolution");
    DO_TEST_CAPS_LATEST("video-virtio-gpu-secondary");
    DO_TEST_CAPS_ARCH_LATEST("video-virtio-gpu-ccw", "s390x");
    DO_TEST_CAPS_ARCH_LATEST("video-virtio-gpu-ccw-auto", "s390x");
    DO_TEST_CAPS_LATEST("video-none-device");
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

    DO_TEST_CAPS_LATEST("cpu-check-none");
    DO_TEST_CAPS_LATEST("cpu-check-partial");
    DO_TEST_CAPS_LATEST("cpu-check-full");
    DO_TEST_CAPS_LATEST("cpu-check-default-none");
    DO_TEST_CAPS_LATEST("cpu-check-default-none2");
    DO_TEST_CAPS_LATEST("cpu-check-default-partial");
    DO_TEST_CAPS_LATEST("cpu-check-default-partial2");
    DO_TEST_CAPS_LATEST("vmcoreinfo");

    DO_TEST_CAPS_LATEST("smartcard-host");
    DO_TEST_CAPS_LATEST("smartcard-host-certificates");
    DO_TEST_CAPS_LATEST("smartcard-host-certificates-database");
    DO_TEST_CAPS_LATEST("smartcard-passthrough-tcp");
    DO_TEST_CAPS_LATEST("smartcard-passthrough-spicevmc");
    DO_TEST_CAPS_LATEST("smartcard-controller");

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
    DO_TEST_CAPS_LATEST("downscript");

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

    DO_TEST_CAPS_LATEST("async-teardown");
    DO_TEST_CAPS_ARCH_LATEST("s390-async-teardown", "s390x");
    DO_TEST_CAPS_ARCH_LATEST("s390-async-teardown-no-attrib", "s390x");
    DO_TEST_CAPS_ARCH_LATEST("s390-async-teardown-disabled", "s390x");
    DO_TEST_CAPS_ARCH_VER("s390-async-teardown-disabled", "s390x", "6.0.0");

 cleanup:
    qemuTestDriverFree(&driver);
    virFileWrapperClearPrefixes();

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN_PRELOAD(mymain,
                      VIR_TEST_MOCK("virpci"),
                      VIR_TEST_MOCK("virrandom"),
                      VIR_TEST_MOCK("domaincaps"))
