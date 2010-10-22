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
# include "qemu/qemu_conf.h"
# include "datatypes.h"

# include "testutilsqemu.h"

static char *progname;
static char *abs_srcdir;
static struct qemud_driver driver;

# define MAX_FILE 4096

static int testCompareXMLToArgvFiles(const char *xml,
                                     const char *cmd,
                                     unsigned long long extraFlags,
                                     const char *migrateFrom,
                                     bool expectError) {
    char argvData[MAX_FILE];
    char *expectargv = &(argvData[0]);
    char *actualargv = NULL;
    const char **argv = NULL;
    const char **qenv = NULL;
    const char **tmp = NULL;
    int ret = -1, len;
    unsigned long long flags;
    virDomainDefPtr vmdef = NULL;
    virDomainChrDef monitor_chr;
    virConnectPtr conn;
    char *log = NULL;

    if (!(conn = virGetConnect()))
        goto fail;

    if (virtTestLoadFile(cmd, &expectargv, MAX_FILE) < 0)
        goto fail;

    if (!(vmdef = virDomainDefParseFile(driver.caps, xml,
                                        VIR_DOMAIN_XML_INACTIVE)))
        goto fail;

    if (extraFlags & QEMUD_CMD_FLAG_DOMID)
        vmdef->id = 6;
    else
        vmdef->id = -1;

    memset(&monitor_chr, 0, sizeof(monitor_chr));
    monitor_chr.type = VIR_DOMAIN_CHR_TYPE_UNIX;
    monitor_chr.data.nix.path = (char *)"/tmp/test-monitor";
    monitor_chr.data.nix.listen = 1;
    if (!(monitor_chr.info.alias = strdup("monitor")))
        goto fail;

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

    if (qemudBuildCommandLine(conn, &driver,
                              vmdef, &monitor_chr, 0, flags,
                              &argv, &qenv,
                              NULL, NULL, migrateFrom, NULL) < 0)
        goto fail;

    if ((log = virtTestLogContentAndReset()) == NULL)
        goto fail;

    if (!!strstr(log, ": error :") != expectError) {
        if (virTestGetDebug())
            fprintf(stderr, "\n%s", log);
        goto fail;
    }

    if (expectError) {
        /* need to suppress the errors */
        virResetLastError();
    }

    len = 1; /* for trailing newline */
    tmp = qenv;
    while (*tmp) {
        len += strlen(*tmp) + 1;
        tmp++;
    }

    tmp = argv;
    while (*tmp) {
        len += strlen(*tmp) + 1;
        tmp++;
    }
    if ((actualargv = malloc(sizeof(*actualargv)*len)) == NULL)
        goto fail;
    actualargv[0] = '\0';
    tmp = qenv;
    while (*tmp) {
        if (actualargv[0])
            strcat(actualargv, " ");
        strcat(actualargv, *tmp);
        tmp++;
    }
    tmp = argv;
    while (*tmp) {
        if (actualargv[0])
            strcat(actualargv, " ");
        strcat(actualargv, *tmp);
        tmp++;
    }
    strcat(actualargv, "\n");

    if (STRNEQ(expectargv, actualargv)) {
        virtTestDifference(stderr, expectargv, actualargv);
        goto fail;
    }

    ret = 0;

 fail:
    free(log);
    free(actualargv);
    if (argv) {
        tmp = argv;
        while (*tmp) {
            free(*(char**)tmp);
            tmp++;
        }
        free(argv);
    }
    if (qenv) {
        tmp = qenv;
        while (*tmp) {
            free(*(char**)tmp);
            tmp++;
        }
        free(qenv);
    }
    virDomainDefFree(vmdef);
    virUnrefConnect(conn);
    return ret;
}


struct testInfo {
    const char *name;
    unsigned long long extraFlags;
    const char *migrateFrom;
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
                                     info->migrateFrom, info->expectError);
}



static int
mymain(int argc, char **argv)
{
    int ret = 0;
    char cwd[PATH_MAX];

    progname = argv[0];

    if (argc > 1) {
        fprintf(stderr, "Usage: %s\n", progname);
        return (EXIT_FAILURE);
    }

    abs_srcdir = getenv("abs_srcdir");
    if (!abs_srcdir)
        abs_srcdir = getcwd(cwd, sizeof(cwd));

    if ((driver.caps = testQemuCapsInit()) == NULL)
        return EXIT_FAILURE;
    if ((driver.stateDir = strdup("/nowhere")) == NULL)
        return EXIT_FAILURE;
    if ((driver.hugetlbfs_mount = strdup("/dev/hugepages")) == NULL)
        return EXIT_FAILURE;
    if ((driver.hugepage_path = strdup("/dev/hugepages/libvirt/qemu")) == NULL)
        return EXIT_FAILURE;

# define DO_TEST_FULL(name, extraFlags, migrateFrom, expectError)       \
    do {                                                                \
        const struct testInfo info = {                                  \
            name, extraFlags, migrateFrom, expectError                  \
        };                                                              \
        if (virtTestRun("QEMU XML-2-ARGV " name,                        \
                        1, testCompareXMLToArgvHelper, &info) < 0)      \
            ret = -1;                                                   \
    } while (0)

# define DO_TEST(name, extraFlags, expectError)                         \
        DO_TEST_FULL(name, extraFlags, NULL, expectError)

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
    DO_TEST("disk-usb", 0, false);
    DO_TEST("disk-usb-device", QEMUD_CMD_FLAG_DRIVE |
            QEMUD_CMD_FLAG_DEVICE | QEMUD_CMD_FLAG_NODEFCONFIG, false);
    DO_TEST("disk-scsi-device", QEMUD_CMD_FLAG_DRIVE |
            QEMUD_CMD_FLAG_DEVICE | QEMUD_CMD_FLAG_NODEFCONFIG, false);
    DO_TEST("disk-scsi-device-auto", QEMUD_CMD_FLAG_DRIVE |
            QEMUD_CMD_FLAG_DEVICE | QEMUD_CMD_FLAG_NODEFCONFIG, false);
    DO_TEST("graphics-vnc", 0, false);

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
    DO_TEST("nographics-vga", QEMUD_CMD_FLAG_VGA, false);
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

    DO_TEST("watchdog", 0, false);
    DO_TEST("watchdog-device", QEMUD_CMD_FLAG_DEVICE |
            QEMUD_CMD_FLAG_NODEFCONFIG, false);
    DO_TEST("balloon-device", QEMUD_CMD_FLAG_DEVICE |
            QEMUD_CMD_FLAG_NODEFCONFIG, false);
    DO_TEST("balloon-device-auto", QEMUD_CMD_FLAG_DEVICE |
            QEMUD_CMD_FLAG_NODEFCONFIG, false);
    DO_TEST("sound", 0, false);
    DO_TEST("sound-device", QEMUD_CMD_FLAG_DEVICE |
            QEMUD_CMD_FLAG_NODEFCONFIG, false);
    DO_TEST("fs9p", QEMUD_CMD_FLAG_DEVICE |
            QEMUD_CMD_FLAG_NODEFCONFIG | QEMUD_CMD_FLAG_FSDEV, false);

    DO_TEST("hostdev-usb-address", 0, false);
    DO_TEST("hostdev-usb-address-device", QEMUD_CMD_FLAG_DEVICE |
            QEMUD_CMD_FLAG_NODEFCONFIG, false);
    DO_TEST("hostdev-pci-address", QEMUD_CMD_FLAG_PCIDEVICE, false);
    DO_TEST("hostdev-pci-address-device", QEMUD_CMD_FLAG_PCIDEVICE |
            QEMUD_CMD_FLAG_DEVICE | QEMUD_CMD_FLAG_NODEFCONFIG, false);

    DO_TEST_FULL("restore-v1", QEMUD_CMD_FLAG_MIGRATE_KVM_STDIO, "stdio", false);
    DO_TEST_FULL("restore-v2", QEMUD_CMD_FLAG_MIGRATE_QEMU_EXEC, "stdio", false);
    DO_TEST_FULL("restore-v2", QEMUD_CMD_FLAG_MIGRATE_QEMU_EXEC, "exec:cat", false);
    DO_TEST_FULL("migrate", QEMUD_CMD_FLAG_MIGRATE_QEMU_TCP, "tcp:10.0.0.1:5000", false);

    DO_TEST("qemu-ns", 0, false);

    DO_TEST("smp", QEMUD_CMD_FLAG_SMP_TOPOLOGY, false);

    free(driver.stateDir);
    virCapabilitiesFree(driver.caps);

    return(ret==0 ? EXIT_SUCCESS : EXIT_FAILURE);
}

VIRT_TEST_MAIN(mymain)

#else

int main (void) { return (77); /* means 'test skipped' for automake */ }

#endif /* WITH_QEMU */
