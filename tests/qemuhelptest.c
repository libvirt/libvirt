#include <config.h>

#ifdef WITH_QEMU

# include <stdio.h>
# include <stdlib.h>

# include "testutils.h"
# include "qemu/qemu_capabilities.h"
# include "memory.h"

struct testInfo {
    const char *name;
    virBitmapPtr flags;
    unsigned int version;
    unsigned int is_kvm;
    unsigned int kvm_version;
};

static void printMismatchedFlags(virBitmapPtr got,
                                 virBitmapPtr expect)
{
    int i;

    for (i = 0 ; i < QEMU_CAPS_LAST ; i++) {
        bool gotFlag = qemuCapsGet(got, i);
        bool expectFlag = qemuCapsGet(expect, i);
        if (gotFlag && !expectFlag)
            fprintf(stderr, "Extra flag %i\n", i);
        if (!gotFlag && expectFlag)
            fprintf(stderr, "Missing flag %i\n", i);
    }
}

static int testHelpStrParsing(const void *data)
{
    const struct testInfo *info = data;
    char *path = NULL;
    char *help = NULL;
    unsigned int version, is_kvm, kvm_version;
    virBitmapPtr flags = NULL;
    int ret = -1;
    char *got = NULL;
    char *expected = NULL;

    if (virAsprintf(&path, "%s/qemuhelpdata/%s", abs_srcdir, info->name) < 0)
        return -1;

    if (virtTestLoadFile(path, &help) < 0)
        goto cleanup;

    if (!(flags = qemuCapsNew()))
        goto cleanup;

    if (qemuCapsParseHelpStr("QEMU", help, flags,
                             &version, &is_kvm, &kvm_version) == -1)
        goto cleanup;

    if (qemuCapsGet(info->flags, QEMU_CAPS_DEVICE)) {
        VIR_FREE(path);
        VIR_FREE(help);
        if (virAsprintf(&path, "%s/qemuhelpdata/%s-device", abs_srcdir,
                        info->name) < 0)
            goto cleanup;

        if (virtTestLoadFile(path, &help) < 0)
            goto cleanup;

        if (qemuCapsParseDeviceStr(help, flags) < 0)
            goto cleanup;
    }

    got = virBitmapString(flags);
    expected = virBitmapString(info->flags);
    if (!got || !expected)
        goto cleanup;

    if (STRNEQ(got, expected)) {
        fprintf(stderr,
                "Computed flags do not match: got %s, expected %s\n",
                got, expected);

        if (getenv("VIR_TEST_DEBUG"))
            printMismatchedFlags(flags, info->flags);

        goto cleanup;
    }

    if (version != info->version) {
        fprintf(stderr, "Parsed versions do not match: got %u, expected %u\n",
                version, info->version);
        goto cleanup;
    }

    if (is_kvm != info->is_kvm) {
        fprintf(stderr,
                "Parsed is_kvm flag does not match: got %u, expected %u\n",
                is_kvm, info->is_kvm);
        goto cleanup;
    }

    if (kvm_version != info->kvm_version) {
        fprintf(stderr,
                "Parsed KVM versions do not match: got %u, expected %u\n",
                kvm_version, info->kvm_version);
        goto cleanup;
    }

    ret = 0;
cleanup:
    VIR_FREE(path);
    VIR_FREE(help);
    qemuCapsFree(flags);
    VIR_FREE(got);
    VIR_FREE(expected);
    return ret;
}

static int
mymain(void)
{
    int ret = 0;

# define DO_TEST(name, version, is_kvm, kvm_version, ...)                   \
    do {                                                                    \
        struct testInfo info = {                                            \
            name, NULL, version, is_kvm, kvm_version                        \
        };                                                                  \
        if (!(info.flags = qemuCapsNew()))                                  \
            return EXIT_FAILURE;                                            \
        qemuCapsSetList(info.flags, __VA_ARGS__, QEMU_CAPS_LAST);           \
        if (virtTestRun("QEMU Help String Parsing " name,                   \
                        1, testHelpStrParsing, &info) < 0)                  \
            ret = -1;                                                       \
        qemuCapsFree(info.flags);                                           \
    } while (0)

    DO_TEST("qemu-0.9.1", 9001, 0, 0,
            QEMU_CAPS_KQEMU,
            QEMU_CAPS_VNC_COLON,
            QEMU_CAPS_NO_REBOOT,
            QEMU_CAPS_DRIVE,
            QEMU_CAPS_NAME);
    DO_TEST("kvm-74", 9001, 1, 74,
            QEMU_CAPS_VNC_COLON,
            QEMU_CAPS_NO_REBOOT,
            QEMU_CAPS_DRIVE,
            QEMU_CAPS_DRIVE_BOOT,
            QEMU_CAPS_NAME,
            QEMU_CAPS_VNET_HDR,
            QEMU_CAPS_MIGRATE_KVM_STDIO,
            QEMU_CAPS_KVM,
            QEMU_CAPS_DRIVE_FORMAT,
            QEMU_CAPS_MEM_PATH,
            QEMU_CAPS_TDF);
    DO_TEST("kvm-83-rhel56", 9001, 1, 83,
            QEMU_CAPS_VNC_COLON,
            QEMU_CAPS_NO_REBOOT,
            QEMU_CAPS_DRIVE,
            QEMU_CAPS_DRIVE_BOOT,
            QEMU_CAPS_NAME,
            QEMU_CAPS_UUID,
            QEMU_CAPS_VNET_HDR,
            QEMU_CAPS_MIGRATE_QEMU_TCP,
            QEMU_CAPS_MIGRATE_QEMU_EXEC,
            QEMU_CAPS_DRIVE_CACHE_V2,
            QEMU_CAPS_KVM,
            QEMU_CAPS_DRIVE_FORMAT,
            QEMU_CAPS_DRIVE_SERIAL,
            QEMU_CAPS_VGA,
            QEMU_CAPS_PCIDEVICE,
            QEMU_CAPS_MEM_PATH,
            QEMU_CAPS_BALLOON,
            QEMU_CAPS_RTC_TD_HACK,
            QEMU_CAPS_NO_HPET,
            QEMU_CAPS_NO_KVM_PIT,
            QEMU_CAPS_TDF,
            QEMU_CAPS_DRIVE_READONLY,
            QEMU_CAPS_SMBIOS_TYPE,
            QEMU_CAPS_SPICE);
    DO_TEST("qemu-0.10.5", 10005, 0, 0,
            QEMU_CAPS_KQEMU,
            QEMU_CAPS_VNC_COLON,
            QEMU_CAPS_NO_REBOOT,
            QEMU_CAPS_DRIVE,
            QEMU_CAPS_NAME,
            QEMU_CAPS_UUID,
            QEMU_CAPS_MIGRATE_QEMU_TCP,
            QEMU_CAPS_MIGRATE_QEMU_EXEC,
            QEMU_CAPS_DRIVE_CACHE_V2,
            QEMU_CAPS_DRIVE_FORMAT,
            QEMU_CAPS_DRIVE_SERIAL,
            QEMU_CAPS_VGA,
            QEMU_CAPS_0_10,
            QEMU_CAPS_ENABLE_KVM,
            QEMU_CAPS_SDL,
            QEMU_CAPS_RTC_TD_HACK,
            QEMU_CAPS_NO_HPET,
            QEMU_CAPS_VGA_NONE);
    DO_TEST("qemu-kvm-0.10.5", 10005, 1, 0,
            QEMU_CAPS_VNC_COLON,
            QEMU_CAPS_NO_REBOOT,
            QEMU_CAPS_DRIVE,
            QEMU_CAPS_DRIVE_BOOT,
            QEMU_CAPS_NAME,
            QEMU_CAPS_UUID,
            QEMU_CAPS_VNET_HDR,
            QEMU_CAPS_MIGRATE_QEMU_TCP,
            QEMU_CAPS_MIGRATE_QEMU_EXEC,
            QEMU_CAPS_DRIVE_CACHE_V2,
            QEMU_CAPS_KVM,
            QEMU_CAPS_DRIVE_FORMAT,
            QEMU_CAPS_DRIVE_SERIAL,
            QEMU_CAPS_VGA,
            QEMU_CAPS_0_10,
            QEMU_CAPS_PCIDEVICE,
            QEMU_CAPS_MEM_PATH,
            QEMU_CAPS_SDL,
            QEMU_CAPS_RTC_TD_HACK,
            QEMU_CAPS_NO_HPET,
            QEMU_CAPS_NO_KVM_PIT,
            QEMU_CAPS_TDF,
            QEMU_CAPS_NESTING,
            QEMU_CAPS_VGA_NONE);
    DO_TEST("kvm-86", 10050, 1, 0,
            QEMU_CAPS_VNC_COLON,
            QEMU_CAPS_NO_REBOOT,
            QEMU_CAPS_DRIVE,
            QEMU_CAPS_DRIVE_BOOT,
            QEMU_CAPS_NAME,
            QEMU_CAPS_UUID,
            QEMU_CAPS_VNET_HDR,
            QEMU_CAPS_MIGRATE_QEMU_TCP,
            QEMU_CAPS_MIGRATE_QEMU_EXEC,
            QEMU_CAPS_DRIVE_CACHE_V2,
            QEMU_CAPS_KVM,
            QEMU_CAPS_DRIVE_FORMAT,
            QEMU_CAPS_DRIVE_SERIAL,
            QEMU_CAPS_VGA,
            QEMU_CAPS_0_10,
            QEMU_CAPS_PCIDEVICE,
            QEMU_CAPS_SDL,
            QEMU_CAPS_RTC_TD_HACK,
            QEMU_CAPS_NO_HPET,
            QEMU_CAPS_NO_KVM_PIT,
            QEMU_CAPS_TDF,
            QEMU_CAPS_NESTING,
            QEMU_CAPS_SMBIOS_TYPE,
            QEMU_CAPS_VGA_NONE);
    DO_TEST("qemu-kvm-0.11.0-rc2", 10092, 1, 0,
            QEMU_CAPS_VNC_COLON,
            QEMU_CAPS_NO_REBOOT,
            QEMU_CAPS_DRIVE,
            QEMU_CAPS_DRIVE_BOOT,
            QEMU_CAPS_NAME,
            QEMU_CAPS_UUID,
            QEMU_CAPS_VNET_HDR,
            QEMU_CAPS_MIGRATE_QEMU_TCP,
            QEMU_CAPS_MIGRATE_QEMU_EXEC,
            QEMU_CAPS_DRIVE_CACHE_V2,
            QEMU_CAPS_KVM,
            QEMU_CAPS_DRIVE_FORMAT,
            QEMU_CAPS_DRIVE_SERIAL,
            QEMU_CAPS_VGA,
            QEMU_CAPS_0_10,
            QEMU_CAPS_PCIDEVICE,
            QEMU_CAPS_MEM_PATH,
            QEMU_CAPS_ENABLE_KVM,
            QEMU_CAPS_BALLOON,
            QEMU_CAPS_SDL,
            QEMU_CAPS_RTC_TD_HACK,
            QEMU_CAPS_NO_HPET,
            QEMU_CAPS_NO_KVM_PIT,
            QEMU_CAPS_TDF,
            QEMU_CAPS_BOOT_MENU,
            QEMU_CAPS_NESTING,
            QEMU_CAPS_NAME_PROCESS,
            QEMU_CAPS_SMBIOS_TYPE,
            QEMU_CAPS_VGA_NONE);
    DO_TEST("qemu-0.12.1", 12001, 0, 0,
            QEMU_CAPS_VNC_COLON,
            QEMU_CAPS_NO_REBOOT,
            QEMU_CAPS_DRIVE,
            QEMU_CAPS_NAME,
            QEMU_CAPS_UUID,
            QEMU_CAPS_MIGRATE_QEMU_TCP,
            QEMU_CAPS_MIGRATE_QEMU_EXEC,
            QEMU_CAPS_DRIVE_CACHE_V2,
            QEMU_CAPS_DRIVE_FORMAT,
            QEMU_CAPS_DRIVE_SERIAL,
            QEMU_CAPS_DRIVE_READONLY,
            QEMU_CAPS_VGA,
            QEMU_CAPS_0_10,
            QEMU_CAPS_ENABLE_KVM,
            QEMU_CAPS_SDL,
            QEMU_CAPS_XEN_DOMID,
            QEMU_CAPS_MIGRATE_QEMU_UNIX,
            QEMU_CAPS_CHARDEV,
            QEMU_CAPS_BALLOON,
            QEMU_CAPS_DEVICE,
            QEMU_CAPS_SMP_TOPOLOGY,
            QEMU_CAPS_RTC,
            QEMU_CAPS_NO_HPET,
            QEMU_CAPS_BOOT_MENU,
            QEMU_CAPS_NAME_PROCESS,
            QEMU_CAPS_SMBIOS_TYPE,
            QEMU_CAPS_VGA_NONE,
            QEMU_CAPS_MIGRATE_QEMU_FD,
            QEMU_CAPS_DRIVE_AIO);
    DO_TEST("qemu-kvm-0.12.1.2-rhel60", 12001, 1, 0,
            QEMU_CAPS_VNC_COLON,
            QEMU_CAPS_NO_REBOOT,
            QEMU_CAPS_DRIVE,
            QEMU_CAPS_DRIVE_BOOT,
            QEMU_CAPS_NAME,
            QEMU_CAPS_UUID,
            QEMU_CAPS_VNET_HDR,
            QEMU_CAPS_MIGRATE_QEMU_TCP,
            QEMU_CAPS_MIGRATE_QEMU_EXEC,
            QEMU_CAPS_DRIVE_CACHE_V2,
            QEMU_CAPS_KVM,
            QEMU_CAPS_DRIVE_FORMAT,
            QEMU_CAPS_DRIVE_SERIAL,
            QEMU_CAPS_DRIVE_READONLY,
            QEMU_CAPS_VGA,
            QEMU_CAPS_0_10,
            QEMU_CAPS_PCIDEVICE,
            QEMU_CAPS_MEM_PATH,
            QEMU_CAPS_MIGRATE_QEMU_UNIX,
            QEMU_CAPS_CHARDEV,
            QEMU_CAPS_ENABLE_KVM,
            QEMU_CAPS_BALLOON,
            QEMU_CAPS_DEVICE,
            QEMU_CAPS_SMP_TOPOLOGY,
            QEMU_CAPS_RTC,
            QEMU_CAPS_VNET_HOST,
            QEMU_CAPS_NO_KVM_PIT,
            QEMU_CAPS_TDF,
            QEMU_CAPS_PCI_CONFIGFD,
            QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_BOOT_MENU,
            QEMU_CAPS_NESTING,
            QEMU_CAPS_NAME_PROCESS,
            QEMU_CAPS_SMBIOS_TYPE,
            QEMU_CAPS_VGA_QXL,
            QEMU_CAPS_SPICE,
            QEMU_CAPS_VGA_NONE,
            QEMU_CAPS_MIGRATE_QEMU_FD,
            QEMU_CAPS_DRIVE_AIO,
            QEMU_CAPS_DEVICE_SPICEVMC);
    DO_TEST("qemu-kvm-0.12.3", 12003, 1, 0,
            QEMU_CAPS_VNC_COLON,
            QEMU_CAPS_NO_REBOOT,
            QEMU_CAPS_DRIVE,
            QEMU_CAPS_DRIVE_BOOT,
            QEMU_CAPS_NAME,
            QEMU_CAPS_UUID,
            QEMU_CAPS_VNET_HDR,
            QEMU_CAPS_MIGRATE_QEMU_TCP,
            QEMU_CAPS_MIGRATE_QEMU_EXEC,
            QEMU_CAPS_DRIVE_CACHE_V2,
            QEMU_CAPS_KVM,
            QEMU_CAPS_DRIVE_FORMAT,
            QEMU_CAPS_DRIVE_SERIAL,
            QEMU_CAPS_DRIVE_READONLY,
            QEMU_CAPS_VGA,
            QEMU_CAPS_0_10,
            QEMU_CAPS_PCIDEVICE,
            QEMU_CAPS_MEM_PATH,
            QEMU_CAPS_SDL,
            QEMU_CAPS_MIGRATE_QEMU_UNIX,
            QEMU_CAPS_CHARDEV,
            QEMU_CAPS_BALLOON,
            QEMU_CAPS_DEVICE,
            QEMU_CAPS_SMP_TOPOLOGY,
            QEMU_CAPS_RTC,
            QEMU_CAPS_VNET_HOST,
            QEMU_CAPS_NO_HPET,
            QEMU_CAPS_NO_KVM_PIT,
            QEMU_CAPS_TDF,
            QEMU_CAPS_BOOT_MENU,
            QEMU_CAPS_NESTING,
            QEMU_CAPS_NAME_PROCESS,
            QEMU_CAPS_SMBIOS_TYPE,
            QEMU_CAPS_VGA_NONE,
            QEMU_CAPS_MIGRATE_QEMU_FD,
            QEMU_CAPS_DRIVE_AIO);
    DO_TEST("qemu-kvm-0.13.0", 13000, 1, 0,
            QEMU_CAPS_VNC_COLON,
            QEMU_CAPS_NO_REBOOT,
            QEMU_CAPS_DRIVE,
            QEMU_CAPS_DRIVE_BOOT,
            QEMU_CAPS_NAME,
            QEMU_CAPS_UUID,
            QEMU_CAPS_VNET_HDR,
            QEMU_CAPS_MIGRATE_QEMU_TCP,
            QEMU_CAPS_MIGRATE_QEMU_EXEC,
            QEMU_CAPS_DRIVE_CACHE_V2,
            QEMU_CAPS_KVM,
            QEMU_CAPS_DRIVE_FORMAT,
            QEMU_CAPS_DRIVE_SERIAL,
            QEMU_CAPS_XEN_DOMID,
            QEMU_CAPS_DRIVE_READONLY,
            QEMU_CAPS_VGA,
            QEMU_CAPS_0_10,
            QEMU_CAPS_PCIDEVICE,
            QEMU_CAPS_MEM_PATH,
            QEMU_CAPS_SDL,
            QEMU_CAPS_MIGRATE_QEMU_UNIX,
            QEMU_CAPS_CHARDEV,
            QEMU_CAPS_ENABLE_KVM,
            QEMU_CAPS_MONITOR_JSON,
            QEMU_CAPS_BALLOON,
            QEMU_CAPS_DEVICE,
            QEMU_CAPS_SMP_TOPOLOGY,
            QEMU_CAPS_NETDEV,
            QEMU_CAPS_RTC,
            QEMU_CAPS_VNET_HOST,
            QEMU_CAPS_NO_HPET,
            QEMU_CAPS_NO_KVM_PIT,
            QEMU_CAPS_TDF,
            QEMU_CAPS_PCI_CONFIGFD,
            QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_BOOT_MENU,
            QEMU_CAPS_FSDEV,
            QEMU_CAPS_NESTING,
            QEMU_CAPS_NAME_PROCESS,
            QEMU_CAPS_SMBIOS_TYPE,
            QEMU_CAPS_SPICE,
            QEMU_CAPS_VGA_NONE,
            QEMU_CAPS_MIGRATE_QEMU_FD,
            QEMU_CAPS_DRIVE_AIO,
            QEMU_CAPS_DEVICE_SPICEVMC);
    DO_TEST("qemu-kvm-0.12.1.2-rhel61", 12001, 1, 0,
            QEMU_CAPS_VNC_COLON,
            QEMU_CAPS_NO_REBOOT,
            QEMU_CAPS_DRIVE,
            QEMU_CAPS_NAME,
            QEMU_CAPS_UUID,
            QEMU_CAPS_VNET_HDR,
            QEMU_CAPS_MIGRATE_QEMU_TCP,
            QEMU_CAPS_MIGRATE_QEMU_EXEC,
            QEMU_CAPS_DRIVE_CACHE_V2,
            QEMU_CAPS_KVM,
            QEMU_CAPS_DRIVE_FORMAT,
            QEMU_CAPS_DRIVE_SERIAL,
            QEMU_CAPS_DRIVE_READONLY,
            QEMU_CAPS_VGA,
            QEMU_CAPS_0_10,
            QEMU_CAPS_PCIDEVICE,
            QEMU_CAPS_MEM_PATH,
            QEMU_CAPS_MIGRATE_QEMU_UNIX,
            QEMU_CAPS_CHARDEV,
            QEMU_CAPS_ENABLE_KVM,
            QEMU_CAPS_BALLOON,
            QEMU_CAPS_DEVICE,
            QEMU_CAPS_SMP_TOPOLOGY,
            QEMU_CAPS_RTC,
            QEMU_CAPS_VNET_HOST,
            QEMU_CAPS_NO_KVM_PIT,
            QEMU_CAPS_TDF,
            QEMU_CAPS_PCI_CONFIGFD,
            QEMU_CAPS_NODEFCONFIG,
            QEMU_CAPS_BOOT_MENU,
            QEMU_CAPS_NESTING,
            QEMU_CAPS_NAME_PROCESS,
            QEMU_CAPS_SMBIOS_TYPE,
            QEMU_CAPS_VGA_QXL,
            QEMU_CAPS_SPICE,
            QEMU_CAPS_VGA_NONE,
            QEMU_CAPS_MIGRATE_QEMU_FD,
            QEMU_CAPS_HDA_DUPLEX,
            QEMU_CAPS_DRIVE_AIO,
            QEMU_CAPS_CCID_PASSTHRU,
            QEMU_CAPS_CHARDEV_SPICEVMC,
            QEMU_CAPS_DEVICE_QXL_VGA,
            QEMU_CAPS_VIRTIO_TX_ALG);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)

#else

int main (void) { return (77); /* means 'test skipped' for automake */ }

#endif /* WITH_QEMU */
