#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>

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
                                     unsigned long long extraFlags,
                                     const char *migrateFrom,
                                     int migrateFd,
                                     bool expectError) {
    char argvData[MAX_FILE];
    char *expectargv = &(argvData[0]);
    int len;
    char *actualargv = NULL;
    int ret = -1;
    unsigned long long flags;
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

    if (extraFlags & QEMUD_CMD_FLAG_DOMID)
        vmdef->id = 6;
    else
        vmdef->id = -1;

    memset(&monitor_chr, 0, sizeof(monitor_chr));
    monitor_chr.type = VIR_DOMAIN_CHR_TYPE_UNIX;
    monitor_chr.data.nix.path = (char *)"/tmp/test-monitor";
    monitor_chr.data.nix.listen = true;

    flags = QEMUD_CMD_FLAG_VNC_COLON |
        QEMUD_CMD_FLAG_NO_REBOOT |
        extraFlags;

    if (qemudCanonicalizeMachine(&driver, vmdef) < 0)
        goto fail;

    if (flags & QEMUD_CMD_FLAG_DEVICE) {
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
     * qemuBuildCommandLine(), so we should set QEMUD_CMD_FLAG_PCI_MULTIBUS for
     * x86_64 and i686 architectures here.
     */
    if (STREQLEN(vmdef->os.arch, "x86_64", 6) ||
        STREQLEN(vmdef->os.arch, "i686", 4)) {
        flags |= QEMUD_CMD_FLAG_PCI_MULTIBUS;
    }

    if (!(cmd = qemuBuildCommandLine(conn, &driver,
                                     vmdef, &monitor_chr, false, flags,
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
    unsigned long long extraFlags;
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

# define DO_TEST_FULL(name, extraFlags, migrateFrom, migrateFd, expectError) \
    do {                                                                \
        const struct testInfo info = {                                  \
            name, extraFlags, migrateFrom, migrateFd, expectError       \
        };                                                              \
        if (virtTestRun("QEMU XML-2-ARGV " name,                        \
                        1, testCompareXMLToArgvHelper, &info) < 0)      \
            ret = -1;                                                   \
    } while (0)

# define DO_TEST(name, extraFlags, expectError)                         \
    DO_TEST_FULL(name, extraFlags, NULL, -1, expectError)

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

    DO_TEST("minimal", QEMUD_CMD_FLAG_NAME, false);
    DO_TEST("machine-aliases1", 0, false);
    DO_TEST("machine-aliases2", 0, true);
    DO_TEST("boot-cdrom", 0, false);
    DO_TEST("boot-network", 0, false);
    DO_TEST("boot-floppy", 0, false);
    DO_TEST("boot-multi", QEMUD_CMD_FLAG_BOOT_MENU, false);
    DO_TEST("boot-menu-disable", QEMUD_CMD_FLAG_BOOT_MENU, false);
    DO_TEST("boot-order", QEMUD_CMD_FLAG_BOOTINDEX |
            QEMUD_CMD_FLAG_DRIVE | QEMUD_CMD_FLAG_DEVICE, false);
    DO_TEST("bootloader", QEMUD_CMD_FLAG_DOMID, true);
    DO_TEST("clock-utc", 0, false);
    DO_TEST("clock-localtime", 0, false);
    /*
     * Can't be enabled since the absolute timestamp changes every time
    DO_TEST("clock-variable", QEMUD_CMD_FLAG_RTC, false);
    */
    DO_TEST("clock-france", QEMUD_CMD_FLAG_RTC, false);

    DO_TEST("hugepages", QEMUD_CMD_FLAG_MEM_PATH, false);
    DO_TEST("disk-cdrom", 0, false);
    DO_TEST("disk-cdrom-empty", QEMUD_CMD_FLAG_DRIVE, false);
    DO_TEST("disk-floppy", 0, false);
    DO_TEST("disk-many", 0, false);
    DO_TEST("disk-virtio", QEMUD_CMD_FLAG_DRIVE |
            QEMUD_CMD_FLAG_DRIVE_BOOT, false);
    DO_TEST("disk-xenvbd", QEMUD_CMD_FLAG_DRIVE |
            QEMUD_CMD_FLAG_DRIVE_BOOT, false);
    DO_TEST("disk-drive-boot-disk", QEMUD_CMD_FLAG_DRIVE |
            QEMUD_CMD_FLAG_DRIVE_BOOT, false);
    DO_TEST("disk-drive-boot-cdrom", QEMUD_CMD_FLAG_DRIVE |
            QEMUD_CMD_FLAG_DRIVE_BOOT, false);
    DO_TEST("floppy-drive-fat", QEMUD_CMD_FLAG_DRIVE |
            QEMUD_CMD_FLAG_DRIVE_BOOT | QEMUD_CMD_FLAG_DRIVE_FORMAT, false);
    DO_TEST("disk-drive-fat", QEMUD_CMD_FLAG_DRIVE |
            QEMUD_CMD_FLAG_DRIVE_BOOT | QEMUD_CMD_FLAG_DRIVE_FORMAT, false);
    DO_TEST("disk-drive-readonly-disk", QEMUD_CMD_FLAG_DRIVE |
            QEMUD_CMD_FLAG_DRIVE_READONLY | QEMUD_CMD_FLAG_DEVICE |
            QEMUD_CMD_FLAG_NODEFCONFIG, false);
    DO_TEST("disk-drive-readonly-no-device", QEMUD_CMD_FLAG_DRIVE |
            QEMUD_CMD_FLAG_DRIVE_READONLY | QEMUD_CMD_FLAG_NODEFCONFIG, false);
    DO_TEST("disk-drive-fmt-qcow", QEMUD_CMD_FLAG_DRIVE |
            QEMUD_CMD_FLAG_DRIVE_BOOT | QEMUD_CMD_FLAG_DRIVE_FORMAT, false);
    DO_TEST("disk-drive-shared", QEMUD_CMD_FLAG_DRIVE |
            QEMUD_CMD_FLAG_DRIVE_FORMAT | QEMUD_CMD_FLAG_DRIVE_SERIAL, false);
    DO_TEST("disk-drive-cache-v1-wt", QEMUD_CMD_FLAG_DRIVE |
            QEMUD_CMD_FLAG_DRIVE_FORMAT, false);
    DO_TEST("disk-drive-cache-v1-wb", QEMUD_CMD_FLAG_DRIVE |
            QEMUD_CMD_FLAG_DRIVE_FORMAT, false);
    DO_TEST("disk-drive-cache-v1-none", QEMUD_CMD_FLAG_DRIVE |
            QEMUD_CMD_FLAG_DRIVE_FORMAT, false);
    DO_TEST("disk-drive-error-policy-stop", QEMUD_CMD_FLAG_DRIVE |
            QEMUD_CMD_FLAG_MONITOR_JSON |
            QEMUD_CMD_FLAG_DRIVE_FORMAT, false);
    DO_TEST("disk-drive-cache-v2-wt", QEMUD_CMD_FLAG_DRIVE |
            QEMUD_CMD_FLAG_DRIVE_CACHE_V2 | QEMUD_CMD_FLAG_DRIVE_FORMAT, false);
    DO_TEST("disk-drive-cache-v2-wb", QEMUD_CMD_FLAG_DRIVE |
            QEMUD_CMD_FLAG_DRIVE_CACHE_V2 | QEMUD_CMD_FLAG_DRIVE_FORMAT, false);
    DO_TEST("disk-drive-cache-v2-none", QEMUD_CMD_FLAG_DRIVE |
            QEMUD_CMD_FLAG_DRIVE_CACHE_V2 | QEMUD_CMD_FLAG_DRIVE_FORMAT, false);
    DO_TEST("disk-drive-network-nbd", QEMUD_CMD_FLAG_DRIVE |
            QEMUD_CMD_FLAG_DRIVE_FORMAT, false);
    DO_TEST("disk-drive-network-rbd", QEMUD_CMD_FLAG_DRIVE |
            QEMUD_CMD_FLAG_DRIVE_FORMAT, false);
    DO_TEST("disk-drive-network-sheepdog", QEMUD_CMD_FLAG_DRIVE |
            QEMUD_CMD_FLAG_DRIVE_FORMAT, false);
    DO_TEST("disk-usb", 0, false);
    DO_TEST("disk-usb-device", QEMUD_CMD_FLAG_DRIVE |
            QEMUD_CMD_FLAG_DEVICE | QEMUD_CMD_FLAG_NODEFCONFIG, false);
    DO_TEST("disk-scsi-device", QEMUD_CMD_FLAG_DRIVE |
            QEMUD_CMD_FLAG_DEVICE | QEMUD_CMD_FLAG_NODEFCONFIG, false);
    DO_TEST("disk-scsi-device-auto", QEMUD_CMD_FLAG_DRIVE |
            QEMUD_CMD_FLAG_DEVICE | QEMUD_CMD_FLAG_NODEFCONFIG, false);
    DO_TEST("disk-aio", QEMUD_CMD_FLAG_DRIVE | QEMUD_CMD_FLAG_DRIVE_AIO |
            QEMUD_CMD_FLAG_DRIVE_CACHE_V2 | QEMUD_CMD_FLAG_DRIVE_FORMAT, false);
    DO_TEST("graphics-vnc", 0, false);
    DO_TEST("graphics-vnc-socket", 0, false);

    driver.vncSASL = 1;
    driver.vncSASLdir = strdup("/root/.sasl2");
    DO_TEST("graphics-vnc-sasl", QEMUD_CMD_FLAG_VGA, false);
    driver.vncTLS = 1;
    driver.vncTLSx509verify = 1;
    driver.vncTLSx509certdir = strdup("/etc/pki/tls/qemu");
    DO_TEST("graphics-vnc-tls", 0, false);
    driver.vncSASL = driver.vncTLSx509verify = driver.vncTLS = 0;
    free(driver.vncSASLdir);
    free(driver.vncTLSx509certdir);
    driver.vncSASLdir = driver.vncTLSx509certdir = NULL;

    DO_TEST("graphics-sdl", 0, false);
    DO_TEST("graphics-sdl-fullscreen", 0, false);
    DO_TEST("nographics", QEMUD_CMD_FLAG_VGA, false);
    DO_TEST("nographics-vga", QEMUD_CMD_FLAG_VGA |
                              QEMUD_CMD_FLAG_VGA_NONE, false);
    DO_TEST("graphics-spice",
            QEMUD_CMD_FLAG_VGA | QEMUD_CMD_FLAG_VGA_QXL |
            QEMUD_CMD_FLAG_DEVICE | QEMUD_CMD_FLAG_SPICE, false);

    DO_TEST("input-usbmouse", 0, false);
    DO_TEST("input-usbtablet", 0, false);
    DO_TEST("input-xen", QEMUD_CMD_FLAG_DOMID, true);
    DO_TEST("misc-acpi", 0, false);
    DO_TEST("misc-no-reboot", 0, false);
    DO_TEST("misc-uuid", QEMUD_CMD_FLAG_NAME |
            QEMUD_CMD_FLAG_UUID, false);
    DO_TEST("net-user", 0, false);
    DO_TEST("net-virtio", 0, false);
    DO_TEST("net-virtio-device", QEMUD_CMD_FLAG_DEVICE |
            QEMUD_CMD_FLAG_NODEFCONFIG, false);
    DO_TEST("net-virtio-netdev", QEMUD_CMD_FLAG_DEVICE |
            QEMUD_CMD_FLAG_NETDEV | QEMUD_CMD_FLAG_NODEFCONFIG, false);
    DO_TEST("net-eth", 0, false);
    DO_TEST("net-eth-ifname", 0, false);
    DO_TEST("net-eth-names", QEMUD_CMD_FLAG_NET_NAME, false);

    DO_TEST("serial-vc", 0, false);
    DO_TEST("serial-pty", 0, false);
    DO_TEST("serial-dev", 0, false);
    DO_TEST("serial-file", 0, false);
    DO_TEST("serial-unix", 0, false);
    DO_TEST("serial-tcp", 0, false);
    DO_TEST("serial-udp", 0, false);
    DO_TEST("serial-tcp-telnet", 0, false);
    DO_TEST("serial-many", 0, false);
    DO_TEST("parallel-tcp", 0, false);
    DO_TEST("console-compat", 0, false);
    DO_TEST("console-compat-auto", 0, false);

    DO_TEST("serial-vc-chardev", QEMUD_CMD_FLAG_CHARDEV|QEMUD_CMD_FLAG_DEVICE |
            QEMUD_CMD_FLAG_NODEFCONFIG, false);
    DO_TEST("serial-pty-chardev", QEMUD_CMD_FLAG_CHARDEV|QEMUD_CMD_FLAG_DEVICE |
            QEMUD_CMD_FLAG_NODEFCONFIG, false);
    DO_TEST("serial-dev-chardev", QEMUD_CMD_FLAG_CHARDEV|QEMUD_CMD_FLAG_DEVICE |
            QEMUD_CMD_FLAG_NODEFCONFIG, false);
    DO_TEST("serial-file-chardev", QEMUD_CMD_FLAG_CHARDEV|QEMUD_CMD_FLAG_DEVICE |
            QEMUD_CMD_FLAG_NODEFCONFIG, false);
    DO_TEST("serial-unix-chardev", QEMUD_CMD_FLAG_CHARDEV|QEMUD_CMD_FLAG_DEVICE |
            QEMUD_CMD_FLAG_NODEFCONFIG, false);
    DO_TEST("serial-tcp-chardev", QEMUD_CMD_FLAG_CHARDEV|QEMUD_CMD_FLAG_DEVICE |
            QEMUD_CMD_FLAG_NODEFCONFIG, false);
    DO_TEST("serial-udp-chardev", QEMUD_CMD_FLAG_CHARDEV|QEMUD_CMD_FLAG_DEVICE |
            QEMUD_CMD_FLAG_NODEFCONFIG, false);
    DO_TEST("serial-tcp-telnet-chardev", QEMUD_CMD_FLAG_CHARDEV|QEMUD_CMD_FLAG_DEVICE |
            QEMUD_CMD_FLAG_NODEFCONFIG, false);
    DO_TEST("serial-many-chardev", QEMUD_CMD_FLAG_CHARDEV|QEMUD_CMD_FLAG_DEVICE |
            QEMUD_CMD_FLAG_NODEFCONFIG, false);
    DO_TEST("parallel-tcp-chardev", QEMUD_CMD_FLAG_CHARDEV|QEMUD_CMD_FLAG_DEVICE |
            QEMUD_CMD_FLAG_NODEFCONFIG, false);
    DO_TEST("console-compat-chardev", QEMUD_CMD_FLAG_CHARDEV|QEMUD_CMD_FLAG_DEVICE |
            QEMUD_CMD_FLAG_NODEFCONFIG, false);

    DO_TEST("channel-guestfwd", QEMUD_CMD_FLAG_CHARDEV|QEMUD_CMD_FLAG_DEVICE |
            QEMUD_CMD_FLAG_NODEFCONFIG, false);
    DO_TEST("channel-virtio", QEMUD_CMD_FLAG_DEVICE |
            QEMUD_CMD_FLAG_NODEFCONFIG, false);
    DO_TEST("channel-virtio-auto", QEMUD_CMD_FLAG_DEVICE |
            QEMUD_CMD_FLAG_NODEFCONFIG, false);
    DO_TEST("console-virtio", QEMUD_CMD_FLAG_DEVICE |
            QEMUD_CMD_FLAG_NODEFCONFIG, false);
    DO_TEST("channel-spicevmc", QEMUD_CMD_FLAG_DEVICE |
            QEMUD_CMD_FLAG_NODEFCONFIG | QEMUD_CMD_FLAG_SPICE |
            QEMUD_CMD_FLAG_CHARDEV_SPICEVMC, false);
    DO_TEST("channel-spicevmc-old", QEMUD_CMD_FLAG_DEVICE |
            QEMUD_CMD_FLAG_NODEFCONFIG | QEMUD_CMD_FLAG_SPICE |
            QEMUD_CMD_FLAG_DEVICE_SPICEVMC, false);

    DO_TEST("smartcard-host",
            QEMUD_CMD_FLAG_CHARDEV | QEMUD_CMD_FLAG_DEVICE |
            QEMUD_CMD_FLAG_NODEFCONFIG | QEMUD_CMD_FLAG_CCID_EMULATED, false);
    DO_TEST("smartcard-host-certificates",
            QEMUD_CMD_FLAG_CHARDEV | QEMUD_CMD_FLAG_DEVICE |
            QEMUD_CMD_FLAG_NODEFCONFIG | QEMUD_CMD_FLAG_CCID_EMULATED, false);
    DO_TEST("smartcard-passthrough-tcp",
            QEMUD_CMD_FLAG_CHARDEV | QEMUD_CMD_FLAG_DEVICE |
            QEMUD_CMD_FLAG_NODEFCONFIG | QEMUD_CMD_FLAG_CCID_PASSTHRU, false);
    DO_TEST("smartcard-passthrough-spicevmc",
            QEMUD_CMD_FLAG_CHARDEV | QEMUD_CMD_FLAG_DEVICE |
            QEMUD_CMD_FLAG_NODEFCONFIG | QEMUD_CMD_FLAG_CCID_PASSTHRU |
            QEMUD_CMD_FLAG_CHARDEV_SPICEVMC, false);
    DO_TEST("smartcard-controller",
            QEMUD_CMD_FLAG_CHARDEV | QEMUD_CMD_FLAG_DEVICE |
            QEMUD_CMD_FLAG_NODEFCONFIG | QEMUD_CMD_FLAG_CCID_EMULATED, false);

    DO_TEST("smbios", QEMUD_CMD_FLAG_SMBIOS_TYPE, false);

    DO_TEST("watchdog", 0, false);
    DO_TEST("watchdog-device", QEMUD_CMD_FLAG_DEVICE |
            QEMUD_CMD_FLAG_NODEFCONFIG, false);
    DO_TEST("watchdog-dump", 0, false);
    DO_TEST("balloon-device", QEMUD_CMD_FLAG_DEVICE |
            QEMUD_CMD_FLAG_NODEFCONFIG, false);
    DO_TEST("balloon-device-auto", QEMUD_CMD_FLAG_DEVICE |
            QEMUD_CMD_FLAG_NODEFCONFIG, false);
    DO_TEST("sound", 0, false);
    DO_TEST("sound-device", QEMUD_CMD_FLAG_DEVICE |
            QEMUD_CMD_FLAG_NODEFCONFIG | QEMUD_CMD_FLAG_HDA_DUPLEX, false);
    DO_TEST("fs9p", QEMUD_CMD_FLAG_DEVICE |
            QEMUD_CMD_FLAG_NODEFCONFIG | QEMUD_CMD_FLAG_FSDEV, false);

    DO_TEST("hostdev-usb-address", 0, false);
    DO_TEST("hostdev-usb-address-device", QEMUD_CMD_FLAG_DEVICE |
            QEMUD_CMD_FLAG_NODEFCONFIG, false);
    DO_TEST("hostdev-pci-address", QEMUD_CMD_FLAG_PCIDEVICE, false);
    DO_TEST("hostdev-pci-address-device", QEMUD_CMD_FLAG_PCIDEVICE |
            QEMUD_CMD_FLAG_DEVICE | QEMUD_CMD_FLAG_NODEFCONFIG, false);

    DO_TEST_FULL("restore-v1", QEMUD_CMD_FLAG_MIGRATE_KVM_STDIO, "stdio", 7,
                 false);
    DO_TEST_FULL("restore-v2", QEMUD_CMD_FLAG_MIGRATE_QEMU_EXEC, "stdio", 7,
                 false);
    DO_TEST_FULL("restore-v2", QEMUD_CMD_FLAG_MIGRATE_QEMU_EXEC, "exec:cat", 7,
                 false);
    DO_TEST_FULL("restore-v2-fd", QEMUD_CMD_FLAG_MIGRATE_QEMU_FD, "stdio", 7,
                 false);
    DO_TEST_FULL("restore-v2-fd", QEMUD_CMD_FLAG_MIGRATE_QEMU_FD, "fd:7", 7,
                 false);
    DO_TEST_FULL("migrate", QEMUD_CMD_FLAG_MIGRATE_QEMU_TCP,
                 "tcp:10.0.0.1:5000", -1, false);

    DO_TEST("qemu-ns", 0, false);

    DO_TEST("smp", QEMUD_CMD_FLAG_SMP_TOPOLOGY, false);

    DO_TEST("cpu-topology1", QEMUD_CMD_FLAG_SMP_TOPOLOGY, false);
    DO_TEST("cpu-topology2", QEMUD_CMD_FLAG_SMP_TOPOLOGY, false);
    DO_TEST("cpu-topology3", 0, false);
    DO_TEST("cpu-minimum1", 0, false);
    DO_TEST("cpu-minimum2", 0, false);
    DO_TEST("cpu-exact1", 0, false);
    DO_TEST("cpu-exact2", 0, false);
    DO_TEST("cpu-strict1", 0, false);

    DO_TEST("memtune", QEMUD_CMD_FLAG_NAME, false);
    DO_TEST("blkiotune", QEMUD_CMD_FLAG_NAME, false);

    free(driver.stateDir);
    virCapabilitiesFree(driver.caps);

    return(ret==0 ? EXIT_SUCCESS : EXIT_FAILURE);
}

VIRT_TEST_MAIN(mymain)

#else

int main (void) { return (77); /* means 'test skipped' for automake */ }

#endif /* WITH_QEMU */
