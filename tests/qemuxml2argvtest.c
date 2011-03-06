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
# include "qemu/qemu_capabilities.h"
# include "qemu/qemu_command.h"
# include "datatypes.h"
# include "cpu/cpu_map.h"

# include "testutilsqemu.h"

static char *progname;
static char *abs_srcdir;
static const char *abs_top_srcdir;
static struct qemud_driver driver;

# define MAX_FILE 4096

static int testCompareXMLToArgvFiles(const char *xml,
                                     const char *cmdline,
                                     virBitmapPtr extraFlags,
                                     const char *migrateFrom,
                                     int migrateFd,
                                     bool expectError) {
    char argvData[MAX_FILE];
    char *expectargv = &(argvData[0]);
    int len;
    char *actualargv = NULL;
    int ret = -1;
    virDomainDefPtr vmdef = NULL;
    virDomainChrSourceDef monitor_chr;
    virConnectPtr conn;
    char *log = NULL;
    char *emulator = NULL;
    virCommandPtr cmd = NULL;

    if (!(conn = virGetConnect()))
        goto fail;

    len = virtTestLoadFile(cmdline, &expectargv, MAX_FILE);
    if (len < 0)
        goto fail;
    if (len && expectargv[len - 1] == '\n')
        expectargv[len - 1] = '\0';

    if (!(vmdef = virDomainDefParseFile(driver.caps, xml,
                                        VIR_DOMAIN_XML_INACTIVE)))
        goto fail;

    /*
     * For test purposes, we may want to fake emulator's output by providing
     * our own script instead of a real emulator. For this to work we need to
     * specify a relative path in <emulator/> element, which, however, is not
     * allowed by RelaxNG schema for domain XML. To work around it we add an
     * extra '/' at the beginning of relative emulator path so that it looks
     * like, e.g., "/./qemu.sh" or "/../emulator/qemu.sh" instead of
     * "./qemu.sh" or "../emulator/qemu.sh" respectively. The following code
     * detects such paths, strips the extra '/' and makes the path absolute.
     */
    if (vmdef->emulator && STRPREFIX(vmdef->emulator, "/.")) {
        if (!(emulator = strdup(vmdef->emulator + 1)))
            goto fail;
        free(vmdef->emulator);
        vmdef->emulator = NULL;
        if (virAsprintf(&vmdef->emulator, "%s/qemuxml2argvdata/%s",
                        abs_srcdir, emulator) < 0)
            goto fail;
    }

    if (qemuCapsGet(extraFlags, QEMU_CAPS_DOMID))
        vmdef->id = 6;
    else
        vmdef->id = -1;

    memset(&monitor_chr, 0, sizeof(monitor_chr));
    monitor_chr.type = VIR_DOMAIN_CHR_TYPE_UNIX;
    monitor_chr.data.nix.path = (char *)"/tmp/test-monitor";
    monitor_chr.data.nix.listen = true;

    qemuCapsSetList(extraFlags,
                    QEMU_CAPS_VNC_COLON,
                    QEMU_CAPS_NO_REBOOT,
                    QEMU_CAPS_LAST);

    if (qemudCanonicalizeMachine(&driver, vmdef) < 0)
        goto fail;

    if (qemuCapsGet(extraFlags, QEMU_CAPS_DEVICE)) {
        qemuDomainPCIAddressSetPtr pciaddrs;
        if (!(pciaddrs = qemuDomainPCIAddressSetCreate(vmdef)))
            goto fail;

        if (qemuAssignDevicePCISlots(vmdef, pciaddrs) < 0)
            goto fail;

        qemuDomainPCIAddressSetFree(pciaddrs);
    }


    free(virtTestLogContentAndReset());
    virResetLastError();

    /* We do not call qemuCapsExtractVersionInfo() before calling
     * qemuBuildCommandLine(), so we should set QEMU_CAPS_PCI_MULTIBUS for
     * x86_64 and i686 architectures here.
     */
    if (STREQLEN(vmdef->os.arch, "x86_64", 6) ||
        STREQLEN(vmdef->os.arch, "i686", 4)) {
        qemuCapsSet(extraFlags, QEMU_CAPS_PCI_MULTIBUS);
    }

    if (!(cmd = qemuBuildCommandLine(conn, &driver,
                                     vmdef, &monitor_chr, false, extraFlags,
                                     migrateFrom, migrateFd, NULL,
                                     VIR_VM_OP_CREATE)))
        goto fail;

    if (!!virGetLastError() != expectError) {
        if (virTestGetDebug() && (log = virtTestLogContentAndReset()))
            fprintf(stderr, "\n%s", log);
        goto fail;
    }

    if (expectError) {
        /* need to suppress the errors */
        virResetLastError();
    }

    if (!(actualargv = virCommandToString(cmd)))
        goto fail;

    if (emulator) {
        /* Skip the abs_srcdir portion of replacement emulator.  */
        char *start_skip = strstr(actualargv, abs_srcdir);
        char *end_skip = strstr(actualargv, emulator);
        if (!start_skip || !end_skip)
            goto fail;
        memmove(start_skip, end_skip, strlen(end_skip) + 1);
    }

    if (STRNEQ(expectargv, actualargv)) {
        virtTestDifference(stderr, expectargv, actualargv);
        goto fail;
    }

    ret = 0;

 fail:
    free(log);
    free(emulator);
    free(actualargv);
    virCommandFree(cmd);
    virDomainDefFree(vmdef);
    virUnrefConnect(conn);
    return ret;
}


struct testInfo {
    const char *name;
    virBitmapPtr extraFlags;
    const char *migrateFrom;
    int migrateFd;
    bool expectError;
};

static int testCompareXMLToArgvHelper(const void *data) {
    const struct testInfo *info = data;
    char xml[PATH_MAX];
    char args[PATH_MAX];
    snprintf(xml, PATH_MAX, "%s/qemuxml2argvdata/qemuxml2argv-%s.xml",
             abs_srcdir, info->name);
    snprintf(args, PATH_MAX, "%s/qemuxml2argvdata/qemuxml2argv-%s.args",
             abs_srcdir, info->name);
    return testCompareXMLToArgvFiles(xml, args, info->extraFlags,
                                     info->migrateFrom, info->migrateFd,
                                     info->expectError);
}



static int
mymain(int argc, char **argv)
{
    int ret = 0;
    char cwd[PATH_MAX];
    char map[PATH_MAX];

    progname = argv[0];

    if (argc > 1) {
        fprintf(stderr, "Usage: %s\n", progname);
        return (EXIT_FAILURE);
    }

    abs_srcdir = getenv("abs_srcdir");
    if (!abs_srcdir)
        abs_srcdir = getcwd(cwd, sizeof(cwd));

    abs_top_srcdir = getenv("abs_top_srcdir");
    if (!abs_top_srcdir)
        abs_top_srcdir = "..";

    if ((driver.caps = testQemuCapsInit()) == NULL)
        return EXIT_FAILURE;
    if ((driver.stateDir = strdup("/nowhere")) == NULL)
        return EXIT_FAILURE;
    if ((driver.hugetlbfs_mount = strdup("/dev/hugepages")) == NULL)
        return EXIT_FAILURE;
    if ((driver.hugepage_path = strdup("/dev/hugepages/libvirt/qemu")) == NULL)
        return EXIT_FAILURE;
    driver.spiceTLS = 1;
    if (!(driver.spiceTLSx509certdir = strdup("/etc/pki/libvirt-spice")))
        return EXIT_FAILURE;
    if (!(driver.spicePassword = strdup("123456")))
        return EXIT_FAILURE;

    snprintf(map, PATH_MAX, "%s/src/cpu/cpu_map.xml", abs_top_srcdir);
    if (cpuMapOverride(map) < 0)
        return EXIT_FAILURE;

# define DO_TEST_FULL(name, migrateFrom, migrateFd, expectError, ...)   \
    do {                                                                \
        struct testInfo info = {                                        \
            name, NULL, migrateFrom, migrateFd, expectError             \
        };                                                              \
        if (!(info.extraFlags = qemuCapsNew()))                         \
            return EXIT_FAILURE;                                        \
        qemuCapsSetList(info.extraFlags, __VA_ARGS__, QEMU_CAPS_LAST);  \
        if (virtTestRun("QEMU XML-2-ARGV " name,                        \
                        1, testCompareXMLToArgvHelper, &info) < 0)      \
            ret = -1;                                                   \
        qemuCapsFree(info.extraFlags);                                  \
    } while (0)

# define DO_TEST(name, expectError, ...)                                \
    DO_TEST_FULL(name, NULL, -1, expectError, __VA_ARGS__)

# define NONE QEMU_CAPS_LAST

    /* Unset or set all envvars here that are copied in qemudBuildCommandLine
     * using ADD_ENV_COPY, otherwise these tests may fail due to unexpected
     * values for these envvars */
    setenv("PATH", "/bin", 1);
    setenv("USER", "test", 1);
    setenv("LOGNAME", "test", 1);
    setenv("HOME", "/home/test", 1);
    unsetenv("TMPDIR");
    unsetenv("LD_PRELOAD");
    unsetenv("LD_LIBRARY_PATH");
    unsetenv("QEMU_AUDIO_DRV");
    unsetenv("SDL_AUDIODRIVER");

    DO_TEST("minimal", false, QEMU_CAPS_NAME);
    DO_TEST("machine-aliases1", false, NONE);
    DO_TEST("machine-aliases2", true, NONE);
    DO_TEST("boot-cdrom", false, NONE);
    DO_TEST("boot-network", false, NONE);
    DO_TEST("boot-floppy", false, NONE);
    DO_TEST("boot-multi", false, QEMU_CAPS_BOOT_MENU);
    DO_TEST("boot-menu-disable", false, QEMU_CAPS_BOOT_MENU);
    DO_TEST("boot-order", false,
            QEMU_CAPS_BOOTINDEX, QEMU_CAPS_DRIVE, QEMU_CAPS_DEVICE);
    DO_TEST("bootloader", true, QEMU_CAPS_DOMID);
    DO_TEST("clock-utc", false, NONE);
    DO_TEST("clock-localtime", false, NONE);
    /*
     * Can't be enabled since the absolute timestamp changes every time
    DO_TEST("clock-variable", false, QEMU_CAPS_RTC);
    */
    DO_TEST("clock-france", false, QEMU_CAPS_RTC);

    DO_TEST("hugepages", false, QEMU_CAPS_MEM_PATH);
    DO_TEST("disk-cdrom", false, NONE);
    DO_TEST("disk-cdrom-empty", false, QEMU_CAPS_DRIVE);
    DO_TEST("disk-floppy", false, NONE);
    DO_TEST("disk-many", false, NONE);
    DO_TEST("disk-virtio", false, QEMU_CAPS_DRIVE, QEMU_CAPS_DRIVE_BOOT);
    DO_TEST("disk-xenvbd", false, QEMU_CAPS_DRIVE, QEMU_CAPS_DRIVE_BOOT);
    DO_TEST("disk-drive-boot-disk", false,
            QEMU_CAPS_DRIVE, QEMU_CAPS_DRIVE_BOOT);
    DO_TEST("disk-drive-boot-cdrom", false,
            QEMU_CAPS_DRIVE, QEMU_CAPS_DRIVE_BOOT);
    DO_TEST("floppy-drive-fat", false,
            QEMU_CAPS_DRIVE, QEMU_CAPS_DRIVE_BOOT, QEMU_CAPS_DRIVE_FORMAT);
    DO_TEST("disk-drive-fat", false,
            QEMU_CAPS_DRIVE, QEMU_CAPS_DRIVE_BOOT, QEMU_CAPS_DRIVE_FORMAT);
    DO_TEST("disk-drive-readonly-disk", false,
            QEMU_CAPS_DRIVE, QEMU_CAPS_DRIVE_READONLY,
            QEMU_CAPS_DEVICE, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("disk-drive-readonly-no-device", false,
            QEMU_CAPS_DRIVE, QEMU_CAPS_DRIVE_READONLY, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("disk-drive-fmt-qcow", false,
            QEMU_CAPS_DRIVE, QEMU_CAPS_DRIVE_BOOT, QEMU_CAPS_DRIVE_FORMAT);
    DO_TEST("disk-drive-shared", false,
            QEMU_CAPS_DRIVE, QEMU_CAPS_DRIVE_FORMAT, QEMU_CAPS_DRIVE_SERIAL);
    DO_TEST("disk-drive-cache-v1-wt", false,
            QEMU_CAPS_DRIVE, QEMU_CAPS_DRIVE_FORMAT);
    DO_TEST("disk-drive-cache-v1-wb", false,
            QEMU_CAPS_DRIVE, QEMU_CAPS_DRIVE_FORMAT);
    DO_TEST("disk-drive-cache-v1-none", false,
            QEMU_CAPS_DRIVE, QEMU_CAPS_DRIVE_FORMAT);
    DO_TEST("disk-drive-error-policy-stop", false,
            QEMU_CAPS_DRIVE, QEMU_CAPS_MONITOR_JSON, QEMU_CAPS_DRIVE_FORMAT);
    DO_TEST("disk-drive-cache-v2-wt", false,
            QEMU_CAPS_DRIVE, QEMU_CAPS_DRIVE_CACHE_V2, QEMU_CAPS_DRIVE_FORMAT);
    DO_TEST("disk-drive-cache-v2-wb", false,
            QEMU_CAPS_DRIVE, QEMU_CAPS_DRIVE_CACHE_V2, QEMU_CAPS_DRIVE_FORMAT);
    DO_TEST("disk-drive-cache-v2-none", false,
            QEMU_CAPS_DRIVE, QEMU_CAPS_DRIVE_CACHE_V2, QEMU_CAPS_DRIVE_FORMAT);
    DO_TEST("disk-drive-network-nbd", false,
            QEMU_CAPS_DRIVE, QEMU_CAPS_DRIVE_FORMAT);
    DO_TEST("disk-drive-network-rbd", false,
            QEMU_CAPS_DRIVE, QEMU_CAPS_DRIVE_FORMAT);
    DO_TEST("disk-drive-network-sheepdog", false,
            QEMU_CAPS_DRIVE, QEMU_CAPS_DRIVE_FORMAT);
    DO_TEST("disk-usb", false, NONE);
    DO_TEST("disk-usb-device", false,
            QEMU_CAPS_DRIVE, QEMU_CAPS_DEVICE, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("disk-scsi-device", false,
            QEMU_CAPS_DRIVE, QEMU_CAPS_DEVICE, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("disk-scsi-device-auto", false,
            QEMU_CAPS_DRIVE, QEMU_CAPS_DEVICE, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("disk-aio", false,
            QEMU_CAPS_DRIVE, QEMU_CAPS_DRIVE_AIO,
            QEMU_CAPS_DRIVE_CACHE_V2, QEMU_CAPS_DRIVE_FORMAT);
    DO_TEST("graphics-vnc", false, NONE);
    DO_TEST("graphics-vnc-socket", false, NONE);

    driver.vncSASL = 1;
    driver.vncSASLdir = strdup("/root/.sasl2");
    DO_TEST("graphics-vnc-sasl", false, QEMU_CAPS_VGA);
    driver.vncTLS = 1;
    driver.vncTLSx509verify = 1;
    driver.vncTLSx509certdir = strdup("/etc/pki/tls/qemu");
    DO_TEST("graphics-vnc-tls", false, NONE);
    driver.vncSASL = driver.vncTLSx509verify = driver.vncTLS = 0;
    free(driver.vncSASLdir);
    free(driver.vncTLSx509certdir);
    driver.vncSASLdir = driver.vncTLSx509certdir = NULL;

    DO_TEST("graphics-sdl", false, NONE);
    DO_TEST("graphics-sdl-fullscreen", false, NONE);
    DO_TEST("nographics", false, QEMU_CAPS_VGA);
    DO_TEST("nographics-vga", false,
            QEMU_CAPS_VGA, QEMU_CAPS_VGA_NONE);
    DO_TEST("graphics-spice", false,
            QEMU_CAPS_VGA, QEMU_CAPS_VGA_QXL,
            QEMU_CAPS_DEVICE, QEMU_CAPS_SPICE);
    DO_TEST("graphics-spice-qxl-vga", false,
            QEMU_CAPS_VGA, QEMU_CAPS_VGA_QXL,
            QEMU_CAPS_DEVICE, QEMU_CAPS_SPICE,
            QEMU_CAPS_DEVICE_QXL_VGA);

    DO_TEST("input-usbmouse", false, NONE);
    DO_TEST("input-usbtablet", false, NONE);
    DO_TEST("input-xen", true, QEMU_CAPS_DOMID);
    DO_TEST("misc-acpi", false, NONE);
    DO_TEST("misc-no-reboot", false, NONE);
    DO_TEST("misc-uuid", false, QEMU_CAPS_NAME, QEMU_CAPS_UUID);
    DO_TEST("net-user", false, NONE);
    DO_TEST("net-virtio", false, NONE);
    DO_TEST("net-virtio-device", false,
            QEMU_CAPS_DEVICE, QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_VIRTIO_TX_ALG);
    DO_TEST("net-virtio-netdev", false,
            QEMU_CAPS_DEVICE, QEMU_CAPS_NETDEV, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("net-eth", false, NONE);
    DO_TEST("net-eth-ifname", false, NONE);
    DO_TEST("net-eth-names", false, QEMU_CAPS_NET_NAME);

    DO_TEST("serial-vc", false, NONE);
    DO_TEST("serial-pty", false, NONE);
    DO_TEST("serial-dev", false, NONE);
    DO_TEST("serial-file", false, NONE);
    DO_TEST("serial-unix", false, NONE);
    DO_TEST("serial-tcp", false, NONE);
    DO_TEST("serial-udp", false, NONE);
    DO_TEST("serial-tcp-telnet", false, NONE);
    DO_TEST("serial-many", false, NONE);
    DO_TEST("parallel-tcp", false, NONE);
    DO_TEST("console-compat", false, NONE);
    DO_TEST("console-compat-auto", false, NONE);

    DO_TEST("serial-vc-chardev", false,
            QEMU_CAPS_CHARDEV, QEMU_CAPS_DEVICE, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("serial-pty-chardev", false,
            QEMU_CAPS_CHARDEV, QEMU_CAPS_DEVICE, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("serial-dev-chardev", false,
            QEMU_CAPS_CHARDEV, QEMU_CAPS_DEVICE, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("serial-file-chardev", false,
            QEMU_CAPS_CHARDEV, QEMU_CAPS_DEVICE, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("serial-unix-chardev", false,
            QEMU_CAPS_CHARDEV, QEMU_CAPS_DEVICE, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("serial-tcp-chardev", false,
            QEMU_CAPS_CHARDEV, QEMU_CAPS_DEVICE, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("serial-udp-chardev", false,
            QEMU_CAPS_CHARDEV, QEMU_CAPS_DEVICE, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("serial-tcp-telnet-chardev", false,
            QEMU_CAPS_CHARDEV, QEMU_CAPS_DEVICE, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("serial-many-chardev", false,
            QEMU_CAPS_CHARDEV, QEMU_CAPS_DEVICE, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("parallel-tcp-chardev", false,
            QEMU_CAPS_CHARDEV, QEMU_CAPS_DEVICE, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("console-compat-chardev", false,
            QEMU_CAPS_CHARDEV, QEMU_CAPS_DEVICE, QEMU_CAPS_NODEFCONFIG);

    DO_TEST("channel-guestfwd", false,
            QEMU_CAPS_CHARDEV, QEMU_CAPS_DEVICE, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("channel-virtio", false,
            QEMU_CAPS_DEVICE, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("channel-virtio-auto", false,
            QEMU_CAPS_DEVICE, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("console-virtio", false,
            QEMU_CAPS_DEVICE, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("channel-spicevmc", false,
            QEMU_CAPS_DEVICE, QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_SPICE, QEMU_CAPS_CHARDEV_SPICEVMC);
    DO_TEST("channel-spicevmc-old", false,
            QEMU_CAPS_DEVICE, QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_SPICE, QEMU_CAPS_DEVICE_SPICEVMC);

    DO_TEST("smartcard-host", false,
            QEMU_CAPS_CHARDEV, QEMU_CAPS_DEVICE,
            QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_CCID_EMULATED);
    DO_TEST("smartcard-host-certificates", false,
            QEMU_CAPS_CHARDEV, QEMU_CAPS_DEVICE,
            QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_CCID_EMULATED);
    DO_TEST("smartcard-passthrough-tcp", false,
            QEMU_CAPS_CHARDEV, QEMU_CAPS_DEVICE,
            QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_CCID_PASSTHRU);
    DO_TEST("smartcard-passthrough-spicevmc", false,
            QEMU_CAPS_CHARDEV, QEMU_CAPS_DEVICE, QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_CCID_PASSTHRU, QEMU_CAPS_CHARDEV_SPICEVMC);
    DO_TEST("smartcard-controller", false,
            QEMU_CAPS_CHARDEV, QEMU_CAPS_DEVICE,
            QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_CCID_EMULATED);

    DO_TEST("smbios", false, QEMU_CAPS_SMBIOS_TYPE);

    DO_TEST("watchdog", false, NONE);
    DO_TEST("watchdog-device", false, QEMU_CAPS_DEVICE, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("watchdog-dump", false, NONE);
    DO_TEST("balloon-device", false, QEMU_CAPS_DEVICE, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("balloon-device-auto", false,
            QEMU_CAPS_DEVICE, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("sound", false, NONE);
    DO_TEST("sound-device", false,
            QEMU_CAPS_DEVICE, QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_HDA_DUPLEX);
    DO_TEST("fs9p", false,
            QEMU_CAPS_DEVICE, QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_FSDEV);

    DO_TEST("hostdev-usb-address", false, NONE);
    DO_TEST("hostdev-usb-address-device", false,
            QEMU_CAPS_DEVICE, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("hostdev-pci-address", false, QEMU_CAPS_PCIDEVICE);
    DO_TEST("hostdev-pci-address-device", false,
            QEMU_CAPS_PCIDEVICE, QEMU_CAPS_DEVICE, QEMU_CAPS_NODEFCONFIG);

    DO_TEST_FULL("restore-v1", "stdio", 7, false,
            QEMU_CAPS_MIGRATE_KVM_STDIO);
    DO_TEST_FULL("restore-v2", "stdio", 7, false,
            QEMU_CAPS_MIGRATE_QEMU_EXEC);
    DO_TEST_FULL("restore-v2", "exec:cat", 7, false,
            QEMU_CAPS_MIGRATE_QEMU_EXEC);
    DO_TEST_FULL("restore-v2-fd", "stdio", 7, false,
            QEMU_CAPS_MIGRATE_QEMU_FD);
    DO_TEST_FULL("restore-v2-fd", "fd:7", 7, false,
            QEMU_CAPS_MIGRATE_QEMU_FD);
    DO_TEST_FULL("migrate", "tcp:10.0.0.1:5000", -1, false,
            QEMU_CAPS_MIGRATE_QEMU_TCP);

    DO_TEST("qemu-ns", false, NONE);

    DO_TEST("smp", false, QEMU_CAPS_SMP_TOPOLOGY);

    DO_TEST("cpu-topology1", false, QEMU_CAPS_SMP_TOPOLOGY);
    DO_TEST("cpu-topology2", false, QEMU_CAPS_SMP_TOPOLOGY);
    DO_TEST("cpu-topology3", false, NONE);
    DO_TEST("cpu-minimum1", false, NONE);
    DO_TEST("cpu-minimum2", false, NONE);
    DO_TEST("cpu-exact1", false, NONE);
    DO_TEST("cpu-exact2", false, NONE);
    DO_TEST("cpu-strict1", false, NONE);

    DO_TEST("memtune", false, QEMU_CAPS_NAME);
    DO_TEST("blkiotune", false, QEMU_CAPS_NAME);

    free(driver.stateDir);
    virCapabilitiesFree(driver.caps);

    return(ret==0 ? EXIT_SUCCESS : EXIT_FAILURE);
}

VIRT_TEST_MAIN(mymain)

#else

int main (void) { return (77); /* means 'test skipped' for automake */ }

#endif /* WITH_QEMU */
