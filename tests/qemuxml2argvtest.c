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
# include "util/memory.h"
# include "qemu/qemu_capabilities.h"
# include "qemu/qemu_command.h"
# include "qemu/qemu_domain.h"
# include "datatypes.h"
# include "cpu/cpu_map.h"

# include "testutilsqemu.h"

static const char *abs_top_srcdir;
static struct qemud_driver driver;

static unsigned char *
fakeSecretGetValue(virSecretPtr obj ATTRIBUTE_UNUSED,
                   size_t *value_size,
                   unsigned int fakeflags ATTRIBUTE_UNUSED,
                   unsigned int internalFlags ATTRIBUTE_UNUSED)
{
    char *secret = strdup("AQCVn5hO6HzFAhAAq0NCv8jtJcIcE+HOBlMQ1A");
    *value_size = strlen(secret);
    return (unsigned char *) secret;
}

static virSecretPtr
fakeSecretLookupByUsage(virConnectPtr conn,
                        int usageType ATTRIBUTE_UNUSED,
                        const char *usageID)
{
    virSecretPtr ret = NULL;
    int err;
    if (STRNEQ(usageID, "mycluster_myname"))
        return NULL;
    err = VIR_ALLOC(ret);
    if (err < 0)
        return NULL;
    ret->magic = VIR_SECRET_MAGIC;
    ret->refs = 1;
    ret->usageID = strdup(usageID);
    if (!ret->usageID)
        return NULL;
    ret->conn = conn;
    conn->refs++;
    return ret;
}

static int
fakeSecretClose(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    return 0;
}

static virSecretDriver fakeSecretDriver = {
    .name = "fake_secret",
    .open = NULL,
    .close = fakeSecretClose,
    .numOfSecrets = NULL,
    .listSecrets = NULL,
    .lookupByUUID = NULL,
    .lookupByUsage = fakeSecretLookupByUsage,
    .defineXML = NULL,
    .getXMLDesc = NULL,
    .setValue = NULL,
    .getValue = fakeSecretGetValue,
    .undefine = NULL,
};

static int testCompareXMLToArgvFiles(const char *xml,
                                     const char *cmdline,
                                     virBitmapPtr extraFlags,
                                     const char *migrateFrom,
                                     int migrateFd,
                                     bool json,
                                     bool expectError,
                                     bool expectFailure)
{
    char *expectargv = NULL;
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
        goto out;
    conn->secretDriver = &fakeSecretDriver;

    if (!(vmdef = virDomainDefParseFile(driver.caps, xml,
                                        QEMU_EXPECTED_VIRT_TYPES,
                                        VIR_DOMAIN_XML_INACTIVE)))
        goto out;

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
            goto out;
        VIR_FREE(vmdef->emulator);
        vmdef->emulator = NULL;
        if (virAsprintf(&vmdef->emulator, "%s/qemuxml2argvdata/%s",
                        abs_srcdir, emulator) < 0)
            goto out;
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
                    QEMU_CAPS_NO_ACPI,
                    QEMU_CAPS_LAST);

    if (qemudCanonicalizeMachine(&driver, vmdef) < 0)
        goto out;

    if (qemuCapsGet(extraFlags, QEMU_CAPS_DEVICE)) {
        qemuDomainPCIAddressSetPtr pciaddrs;

        if (qemuDomainAssignSpaprVIOAddresses(vmdef)) {
            if (expectError)
                goto ok;
            goto out;
        }

        if (!(pciaddrs = qemuDomainPCIAddressSetCreate(vmdef)))
            goto out;

        if (qemuAssignDevicePCISlots(vmdef, pciaddrs) < 0)
            goto out;

        qemuDomainPCIAddressSetFree(pciaddrs);
    }

    log = virtTestLogContentAndReset();
    VIR_FREE(log);
    virResetLastError();

    /* We do not call qemuCapsExtractVersionInfo() before calling
     * qemuBuildCommandLine(), so we should set QEMU_CAPS_PCI_MULTIBUS for
     * x86_64 and i686 architectures here.
     */
    if (STREQLEN(vmdef->os.arch, "x86_64", 6) ||
        STREQLEN(vmdef->os.arch, "i686", 4)) {
        qemuCapsSet(extraFlags, QEMU_CAPS_PCI_MULTIBUS);
    }

    if (qemuAssignDeviceAliases(vmdef, extraFlags) < 0)
        goto out;

    if (!(cmd = qemuBuildCommandLine(conn, &driver,
                                     vmdef, &monitor_chr, json, extraFlags,
                                     migrateFrom, migrateFd, NULL,
                                     VIR_NETDEV_VPORT_PROFILE_OP_NO_OP))) {
        if (expectFailure) {
            ret = 0;
            virResetLastError();
        }
        goto out;
    } else if (expectFailure) {
        if (virTestGetDebug())
            fprintf(stderr, "qemuBuildCommandLine should have failed\n");
        goto out;
    }

    if (!!virGetLastError() != expectError) {
        if (virTestGetDebug() && (log = virtTestLogContentAndReset()))
            fprintf(stderr, "\n%s", log);
        goto out;
    }

    if (!(actualargv = virCommandToString(cmd)))
        goto out;

    if (emulator) {
        /* Skip the abs_srcdir portion of replacement emulator.  */
        char *start_skip = strstr(actualargv, abs_srcdir);
        char *end_skip = strstr(actualargv, emulator);
        if (!start_skip || !end_skip)
            goto out;
        memmove(start_skip, end_skip, strlen(end_skip) + 1);
    }

    len = virtTestLoadFile(cmdline, &expectargv);
    if (len < 0)
        goto out;
    if (len && expectargv[len - 1] == '\n')
        expectargv[len - 1] = '\0';

    if (STRNEQ(expectargv, actualargv)) {
        virtTestDifference(stderr, expectargv, actualargv);
        goto out;
    }

 ok:
    if (expectError) {
        /* need to suppress the errors */
        virResetLastError();
    }

    ret = 0;

out:
    VIR_FREE(log);
    VIR_FREE(emulator);
    VIR_FREE(expectargv);
    VIR_FREE(actualargv);
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
    bool expectFailure;
};

static int
testCompareXMLToArgvHelper(const void *data)
{
    int result = -1;
    const struct testInfo *info = data;
    char *xml = NULL;
    char *args = NULL;

    if (virAsprintf(&xml, "%s/qemuxml2argvdata/qemuxml2argv-%s.xml",
                    abs_srcdir, info->name) < 0 ||
        virAsprintf(&args, "%s/qemuxml2argvdata/qemuxml2argv-%s.args",
                    abs_srcdir, info->name) < 0)
        goto cleanup;

    result = testCompareXMLToArgvFiles(xml, args, info->extraFlags,
                                       info->migrateFrom, info->migrateFd,
                                       qemuCapsGet(info->extraFlags,
                                                   QEMU_CAPS_MONITOR_JSON),
                                       info->expectError,
                                       info->expectFailure);

cleanup:
    VIR_FREE(xml);
    VIR_FREE(args);
    return result;
}



static int
mymain(void)
{
    int ret = 0;
    char *map = NULL;

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
    if (virAsprintf(&map, "%s/src/cpu/cpu_map.xml", abs_top_srcdir) < 0 ||
        cpuMapOverride(map) < 0) {
        VIR_FREE(map);
        return EXIT_FAILURE;
    }

# define DO_TEST_FULL(name, migrateFrom, migrateFd,                     \
                      expectError, expectFailure, ...)                  \
    do {                                                                \
        struct testInfo info = {                                        \
            name, NULL, migrateFrom, migrateFd,                         \
            expectError, expectFailure                                  \
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
    DO_TEST_FULL(name, NULL, -1, expectError, false, __VA_ARGS__)

# define DO_TEST_FAILURE(name, ...)                                     \
    DO_TEST_FULL(name, NULL, -1, false, true, __VA_ARGS__)

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
    DO_TEST("boot-menu-enable", false,
            QEMU_CAPS_BOOT_MENU, QEMU_CAPS_DEVICE, QEMU_CAPS_DRIVE);
    DO_TEST("boot-menu-enable", false,
            QEMU_CAPS_BOOT_MENU, QEMU_CAPS_DEVICE, QEMU_CAPS_DRIVE,
            QEMU_CAPS_BOOTINDEX);
    DO_TEST("boot-menu-disable", false, QEMU_CAPS_BOOT_MENU);
    DO_TEST("boot-menu-disable-drive", false,
            QEMU_CAPS_BOOT_MENU, QEMU_CAPS_DEVICE, QEMU_CAPS_DRIVE);
    DO_TEST("boot-menu-disable-drive-bootindex", false,
            QEMU_CAPS_BOOT_MENU, QEMU_CAPS_DEVICE, QEMU_CAPS_DRIVE,
            QEMU_CAPS_BOOTINDEX);
    DO_TEST("boot-order", false,
            QEMU_CAPS_BOOTINDEX, QEMU_CAPS_DRIVE, QEMU_CAPS_DEVICE,
            QEMU_CAPS_VIRTIO_BLK_SCSI, QEMU_CAPS_VIRTIO_BLK_SG_IO);
    DO_TEST("boot-complex", false,
            QEMU_CAPS_DEVICE, QEMU_CAPS_DRIVE, QEMU_CAPS_DRIVE_BOOT,
            QEMU_CAPS_VIRTIO_BLK_SCSI, QEMU_CAPS_VIRTIO_BLK_SG_IO);
    DO_TEST("boot-complex-bootindex", false,
            QEMU_CAPS_DEVICE, QEMU_CAPS_DRIVE, QEMU_CAPS_DRIVE_BOOT,
            QEMU_CAPS_BOOTINDEX,
            QEMU_CAPS_VIRTIO_BLK_SCSI, QEMU_CAPS_VIRTIO_BLK_SG_IO);
    DO_TEST("bootloader", true, QEMU_CAPS_DOMID);
    DO_TEST("bios", false, QEMU_CAPS_DEVICE, QEMU_CAPS_SGA);
    DO_TEST("clock-utc", false, NONE);
    DO_TEST("clock-localtime", false, NONE);
    /*
     * Can't be enabled since the absolute timestamp changes every time
    DO_TEST("clock-variable", false, QEMU_CAPS_RTC);
    */
    DO_TEST("clock-france", false, QEMU_CAPS_RTC);
    DO_TEST("cpu-kvmclock", false, QEMU_CAPS_ENABLE_KVM);
    DO_TEST("cpu-host-kvmclock", false, QEMU_CAPS_ENABLE_KVM, QEMU_CAPS_CPU_HOST);
    DO_TEST("kvmclock", false, QEMU_CAPS_KVM);

    DO_TEST("hugepages", false, QEMU_CAPS_MEM_PATH);
    DO_TEST("disk-cdrom", false, NONE);
    DO_TEST("disk-cdrom-empty", false, QEMU_CAPS_DRIVE);
    DO_TEST("disk-cdrom-tray", false,
            QEMU_CAPS_DRIVE, QEMU_CAPS_DEVICE, QEMU_CAPS_VIRTIO_TX_ALG);
    DO_TEST("disk-cdrom-tray-no-device-cap", false, NONE);
    DO_TEST("disk-floppy", false, NONE);
    DO_TEST("disk-floppy-tray-no-device-cap", false, NONE);
    DO_TEST("disk-floppy-tray", false,
            QEMU_CAPS_DRIVE, QEMU_CAPS_DEVICE);
    DO_TEST("disk-many", false, NONE);
    DO_TEST("disk-virtio", false, QEMU_CAPS_DRIVE, QEMU_CAPS_DRIVE_BOOT);
    DO_TEST("disk-order", false,
            QEMU_CAPS_DRIVE, QEMU_CAPS_DEVICE, QEMU_CAPS_DRIVE_BOOT,
            QEMU_CAPS_VIRTIO_BLK_SCSI, QEMU_CAPS_VIRTIO_BLK_SG_IO);
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
    DO_TEST("disk-drive-error-policy-enospace", false,
            QEMU_CAPS_DRIVE, QEMU_CAPS_MONITOR_JSON, QEMU_CAPS_DRIVE_FORMAT);
    DO_TEST("disk-drive-error-policy-wreport-rignore", false,
            QEMU_CAPS_DRIVE, QEMU_CAPS_MONITOR_JSON, QEMU_CAPS_DRIVE_FORMAT);
    DO_TEST("disk-drive-cache-v2-wt", false,
            QEMU_CAPS_DRIVE, QEMU_CAPS_DRIVE_CACHE_V2, QEMU_CAPS_DRIVE_FORMAT);
    DO_TEST("disk-drive-cache-v2-wb", false,
            QEMU_CAPS_DRIVE, QEMU_CAPS_DRIVE_CACHE_V2, QEMU_CAPS_DRIVE_FORMAT);
    DO_TEST("disk-drive-cache-v2-none", false,
            QEMU_CAPS_DRIVE, QEMU_CAPS_DRIVE_CACHE_V2, QEMU_CAPS_DRIVE_FORMAT);
    DO_TEST("disk-drive-cache-directsync", false,
            QEMU_CAPS_DRIVE, QEMU_CAPS_DRIVE_CACHE_V2,
            QEMU_CAPS_DRIVE_CACHE_DIRECTSYNC, QEMU_CAPS_DRIVE_FORMAT);
    DO_TEST("disk-drive-cache-unsafe", false,
            QEMU_CAPS_DRIVE, QEMU_CAPS_DRIVE_CACHE_V2,
            QEMU_CAPS_DRIVE_CACHE_UNSAFE, QEMU_CAPS_DRIVE_FORMAT);
    DO_TEST("disk-drive-network-nbd", false,
            QEMU_CAPS_DRIVE, QEMU_CAPS_DRIVE_FORMAT);
    DO_TEST("disk-drive-network-rbd", false,
            QEMU_CAPS_DRIVE, QEMU_CAPS_DRIVE_FORMAT);
    DO_TEST("disk-drive-network-sheepdog", false,
            QEMU_CAPS_DRIVE, QEMU_CAPS_DRIVE_FORMAT);
    DO_TEST("disk-drive-network-rbd-auth", false,
            QEMU_CAPS_DRIVE, QEMU_CAPS_DRIVE_FORMAT);
    DO_TEST("disk-drive-no-boot", false,
            QEMU_CAPS_DRIVE, QEMU_CAPS_DEVICE, QEMU_CAPS_BOOTINDEX);
    DO_TEST("disk-usb", false, NONE);
    DO_TEST("disk-usb-device", false,
            QEMU_CAPS_DRIVE, QEMU_CAPS_DEVICE, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("disk-scsi-device", false,
            QEMU_CAPS_DRIVE, QEMU_CAPS_DEVICE, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("disk-scsi-device-auto", false,
            QEMU_CAPS_DRIVE, QEMU_CAPS_DEVICE, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("disk-scsi-vscsi", false,
            QEMU_CAPS_DRIVE, QEMU_CAPS_DEVICE, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("disk-scsi-virtio-scsi", false,
            QEMU_CAPS_DRIVE, QEMU_CAPS_DEVICE, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("disk-sata-device", false,
            QEMU_CAPS_DRIVE, QEMU_CAPS_DEVICE,
            QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_ICH9_AHCI);
    DO_TEST("disk-aio", false,
            QEMU_CAPS_DRIVE, QEMU_CAPS_DRIVE_AIO,
            QEMU_CAPS_DRIVE_CACHE_V2, QEMU_CAPS_DRIVE_FORMAT);
    DO_TEST("disk-ioeventfd", false,
            QEMU_CAPS_DRIVE, QEMU_CAPS_VIRTIO_IOEVENTFD,
            QEMU_CAPS_VIRTIO_TX_ALG, QEMU_CAPS_DEVICE,
            QEMU_CAPS_VIRTIO_BLK_SCSI, QEMU_CAPS_VIRTIO_BLK_SG_IO);
    DO_TEST("disk-copy_on_read", false,
            QEMU_CAPS_DRIVE, QEMU_CAPS_DRIVE_COPY_ON_READ,
            QEMU_CAPS_VIRTIO_TX_ALG, QEMU_CAPS_DEVICE,
            QEMU_CAPS_VIRTIO_BLK_SCSI, QEMU_CAPS_VIRTIO_BLK_SG_IO);
    DO_TEST("disk-snapshot", false,
            QEMU_CAPS_DRIVE, QEMU_CAPS_DRIVE_CACHE_V2, QEMU_CAPS_DRIVE_FORMAT);
    DO_TEST("event_idx", false,
            QEMU_CAPS_DRIVE,
            QEMU_CAPS_VIRTIO_BLK_EVENT_IDX,
            QEMU_CAPS_VIRTIO_NET_EVENT_IDX,
            QEMU_CAPS_DEVICE,
            QEMU_CAPS_VIRTIO_BLK_SCSI, QEMU_CAPS_VIRTIO_BLK_SG_IO);
    DO_TEST("virtio-lun", false,
            QEMU_CAPS_DRIVE,
            QEMU_CAPS_DEVICE,
            QEMU_CAPS_VIRTIO_BLK_SCSI, QEMU_CAPS_VIRTIO_BLK_SG_IO);
    DO_TEST("disk-scsi-lun-passthrough", false,
            QEMU_CAPS_DRIVE,
            QEMU_CAPS_DEVICE,
            QEMU_CAPS_SCSI_BLOCK, QEMU_CAPS_VIRTIO_BLK_SG_IO);

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
    VIR_FREE(driver.vncSASLdir);
    VIR_FREE(driver.vncTLSx509certdir);
    driver.vncSASLdir = driver.vncTLSx509certdir = NULL;

    DO_TEST("graphics-sdl", false, NONE);
    DO_TEST("graphics-sdl-fullscreen", false, NONE);
    DO_TEST("nographics", false, QEMU_CAPS_VGA);
    DO_TEST("nographics-vga", false,
            QEMU_CAPS_VGA, QEMU_CAPS_VGA_NONE);
    DO_TEST("graphics-spice", false,
            QEMU_CAPS_VGA, QEMU_CAPS_VGA_QXL,
            QEMU_CAPS_DEVICE, QEMU_CAPS_SPICE);
    DO_TEST("graphics-spice-agentmouse", false,
            QEMU_CAPS_VGA, QEMU_CAPS_VGA_QXL,
            QEMU_CAPS_DEVICE, QEMU_CAPS_SPICE,
            QEMU_CAPS_CHARDEV_SPICEVMC,
            QEMU_CAPS_NODEFCONFIG);
    DO_TEST("graphics-spice-compression", false,
            QEMU_CAPS_VGA, QEMU_CAPS_VGA_QXL,
            QEMU_CAPS_DEVICE, QEMU_CAPS_SPICE);
    DO_TEST("graphics-spice-timeout", false,
            QEMU_CAPS_DRIVE,
            QEMU_CAPS_VGA, QEMU_CAPS_VGA_QXL,
            QEMU_CAPS_DEVICE, QEMU_CAPS_SPICE,
            QEMU_CAPS_DEVICE_QXL_VGA);
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
    DO_TEST("net-client", false, NONE);
    DO_TEST("net-server", false, NONE);
    DO_TEST("net-mcast", false, NONE);
    DO_TEST("net-hostdev", false,
            QEMU_CAPS_PCIDEVICE, QEMU_CAPS_DEVICE, QEMU_CAPS_NODEFCONFIG);

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
            QEMU_CAPS_DEVICE, QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("channel-virtio-auto", false,
            QEMU_CAPS_DEVICE, QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("console-virtio", false,
            QEMU_CAPS_DEVICE, QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("console-virtio-many", false,
            QEMU_CAPS_DEVICE, QEMU_CAPS_CHARDEV, QEMU_CAPS_NODEFCONFIG);
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

    DO_TEST("usb-controller", false,
            QEMU_CAPS_CHARDEV, QEMU_CAPS_DEVICE,
            QEMU_CAPS_NODEFCONFIG);
    DO_TEST("usb-piix3-controller", false,
            QEMU_CAPS_CHARDEV, QEMU_CAPS_DEVICE, QEMU_CAPS_PIIX3_USB_UHCI,
            QEMU_CAPS_PCI_MULTIFUNCTION, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("usb-ich9-ehci-addr", false,
            QEMU_CAPS_CHARDEV, QEMU_CAPS_DEVICE, QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_PCI_MULTIFUNCTION, QEMU_CAPS_ICH9_USB_EHCI1);
    DO_TEST("input-usbmouse-addr", false,
            QEMU_CAPS_DEVICE, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("usb-ich9-companion", false,
            QEMU_CAPS_CHARDEV, QEMU_CAPS_DEVICE, QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_PCI_MULTIFUNCTION, QEMU_CAPS_ICH9_USB_EHCI1);
    DO_TEST("usb-hub", false,
            QEMU_CAPS_CHARDEV, QEMU_CAPS_DEVICE, QEMU_CAPS_USB_HUB,
            QEMU_CAPS_NODEFCONFIG);
    DO_TEST("usb-ports", false,
            QEMU_CAPS_CHARDEV, QEMU_CAPS_DEVICE, QEMU_CAPS_USB_HUB,
            QEMU_CAPS_NODEFCONFIG);
    DO_TEST("usb-redir", false,
            QEMU_CAPS_CHARDEV, QEMU_CAPS_DEVICE, QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_PCI_MULTIFUNCTION, QEMU_CAPS_USB_HUB,
            QEMU_CAPS_ICH9_USB_EHCI1, QEMU_CAPS_USB_REDIR,
            QEMU_CAPS_SPICE, QEMU_CAPS_CHARDEV_SPICEVMC);
    DO_TEST("usb1-usb2", false,
            QEMU_CAPS_CHARDEV, QEMU_CAPS_DEVICE, QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_PCI_MULTIFUNCTION, QEMU_CAPS_PIIX3_USB_UHCI,
            QEMU_CAPS_USB_HUB, QEMU_CAPS_ICH9_USB_EHCI1);

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
            QEMU_CAPS_DEVICE, QEMU_CAPS_NODEFCONFIG, QEMU_CAPS_FSDEV,
            QEMU_CAPS_FSDEV_WRITEOUT);

    DO_TEST("hostdev-usb-address", false, NONE);
    DO_TEST("hostdev-usb-address-device", false,
            QEMU_CAPS_DEVICE, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("hostdev-pci-address", false, QEMU_CAPS_PCIDEVICE);
    DO_TEST("hostdev-pci-address-device", false,
            QEMU_CAPS_PCIDEVICE, QEMU_CAPS_DEVICE, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("pci-rom", false,
            QEMU_CAPS_PCIDEVICE, QEMU_CAPS_DEVICE, QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_PCI_ROMBAR);

    DO_TEST_FULL("restore-v1", "stdio", 7, false, false,
            QEMU_CAPS_MIGRATE_KVM_STDIO);
    DO_TEST_FULL("restore-v2", "stdio", 7, false, false,
            QEMU_CAPS_MIGRATE_QEMU_EXEC);
    DO_TEST_FULL("restore-v2", "exec:cat", 7, false, false,
            QEMU_CAPS_MIGRATE_QEMU_EXEC);
    DO_TEST_FULL("restore-v2-fd", "stdio", 7, false, false,
            QEMU_CAPS_MIGRATE_QEMU_FD);
    DO_TEST_FULL("restore-v2-fd", "fd:7", 7, false, false,
            QEMU_CAPS_MIGRATE_QEMU_FD);
    DO_TEST_FULL("migrate", "tcp:10.0.0.1:5000", -1, false, false,
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
    DO_TEST("cpu-exact2-nofallback", false, NONE);
    DO_TEST("cpu-fallback", false, NONE);
    DO_TEST_FAILURE("cpu-nofallback", NONE);
    DO_TEST("cpu-strict1", false, NONE);
    DO_TEST("cpu-numa1", false, NONE);
    DO_TEST("cpu-numa2", false, QEMU_CAPS_SMP_TOPOLOGY);
    DO_TEST("cpu-host-model", false, NONE);
    DO_TEST("cpu-host-model-fallback", false, NONE);
    DO_TEST_FAILURE("cpu-host-model-nofallback", NONE);
    DO_TEST("cpu-host-passthrough", false, QEMU_CAPS_KVM, QEMU_CAPS_CPU_HOST);
    DO_TEST_FAILURE("cpu-host-passthrough", NONE);
    DO_TEST_FAILURE("cpu-qemu-host-passthrough",
                    QEMU_CAPS_KVM, QEMU_CAPS_CPU_HOST);

    DO_TEST("memtune", false, QEMU_CAPS_NAME);
    DO_TEST("blkiotune", false, QEMU_CAPS_NAME);
    DO_TEST("blkiotune-device", false, QEMU_CAPS_NAME);
    DO_TEST("cputune", false, QEMU_CAPS_NAME);
    DO_TEST("numatune-memory", false, NONE);
    DO_TEST("blkdeviotune", false, QEMU_CAPS_NAME, QEMU_CAPS_DEVICE,
            QEMU_CAPS_DRIVE, QEMU_CAPS_DRIVE_IOTUNE);

    DO_TEST("multifunction-pci-device", false,
            QEMU_CAPS_DRIVE, QEMU_CAPS_DEVICE, QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_PCI_MULTIFUNCTION);

    DO_TEST("monitor-json", false, QEMU_CAPS_DEVICE,
            QEMU_CAPS_CHARDEV, QEMU_CAPS_MONITOR_JSON, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("no-shutdown", false, QEMU_CAPS_DEVICE,
            QEMU_CAPS_CHARDEV, QEMU_CAPS_MONITOR_JSON, QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_NO_SHUTDOWN);

    DO_TEST("seclabel-dynamic", false, QEMU_CAPS_NAME);
    DO_TEST("seclabel-dynamic-baselabel", false, QEMU_CAPS_NAME);
    DO_TEST("seclabel-dynamic-override", false, QEMU_CAPS_NAME);
    DO_TEST("seclabel-static", false, QEMU_CAPS_NAME);
    DO_TEST("seclabel-static-relabel", false, QEMU_CAPS_NAME);
    DO_TEST("seclabel-none", false, QEMU_CAPS_NAME);

    DO_TEST("pseries-basic", false,
            QEMU_CAPS_CHARDEV, QEMU_CAPS_DEVICE, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("pseries-vio", false, QEMU_CAPS_DRIVE,
            QEMU_CAPS_CHARDEV, QEMU_CAPS_DEVICE, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("pseries-vio-user-assigned", false, QEMU_CAPS_DRIVE,
            QEMU_CAPS_CHARDEV, QEMU_CAPS_DEVICE, QEMU_CAPS_NODEFCONFIG);
    DO_TEST("pseries-vio-address-clash", true, QEMU_CAPS_DRIVE,
            QEMU_CAPS_CHARDEV, QEMU_CAPS_DEVICE, QEMU_CAPS_NODEFCONFIG);

    VIR_FREE(driver.stateDir);
    virCapabilitiesFree(driver.caps);
    VIR_FREE(map);

    return ret==0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)

#else
# include "testutils.h"

int main(void)
{
    return EXIT_AM_SKIP;
}

#endif /* WITH_QEMU */
