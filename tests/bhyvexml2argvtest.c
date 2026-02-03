#include <config.h>

#include "testutils.h"

#ifdef WITH_BHYVE

# include "datatypes.h"

# include "bhyve/bhyve_capabilities.h"
# include "bhyve/bhyve_conf.h"
# include "bhyve/bhyve_domain.h"
# include "bhyve/bhyve_utils.h"
# include "bhyve/bhyve_command.h"
# include "bhyve/bhyve_process.h"

# define VIR_FROM_THIS VIR_FROM_BHYVE

static bhyveConn driver;

typedef enum {
    FLAG_EXPECT_FAILURE         = 1 << 0,
    FLAG_EXPECT_PARSE_ERROR     = 1 << 1,
    FLAG_EXPECT_PREPARE_ERROR   = 1 << 2,
} virBhyveXMLToArgvTestFlags;

static int testCompareXMLToArgvFiles(const char *xml,
                                     const char *cmdline,
                                     const char *ldcmdline,
                                     const char *dmcmdline,
                                     unsigned int flags)
{
    g_autofree char *actualargv = NULL;
    g_autofree char *actualld = NULL;
    g_autofree char *actualdm = NULL;
    g_autoptr(virDomainObj) vm = NULL;
    g_autoptr(virCommand) cmd = NULL;
    g_autoptr(virCommand) ldcmd = NULL;
    g_autoptr(virConnect) conn = NULL;
    int ret = -1;

    if (!(conn = virGetConnect()))
        goto out;

    if (!(vm = virDomainObjNew(driver.xmlopt)))
        return -1;

    if (!(vm->def = virDomainDefParseFile(xml, driver.xmlopt,
                                          NULL, VIR_DOMAIN_DEF_PARSE_INACTIVE))) {
        if (flags & FLAG_EXPECT_PARSE_ERROR) {
            ret = 0;
        } else if (flags & FLAG_EXPECT_FAILURE) {
            ret = 0;
            VIR_TEST_DEBUG("Got expected error: %s",
                    virGetLastErrorMessage());
            virResetLastError();
        }

        goto out;
    }

    conn->privateData = &driver;

    if (bhyveProcessPrepareDomain(&driver, vm, 0) < 0) {
        if (flags & FLAG_EXPECT_PREPARE_ERROR) {
            ret = 0;
            VIR_TEST_DEBUG("Got expected error: %s",
                    virGetLastErrorMessage());
        }
        goto out;
    }

    cmd = virBhyveProcessBuildBhyveCmd(&driver, vm->def, false);
    if (vm->def->os.loader)
        ldcmd = virCommandNew("dummy");
    else
        ldcmd = virBhyveProcessBuildLoadCmd(&driver, vm->def, "<device.map>",
                                            &actualdm);

    if ((cmd == NULL) || (ldcmd == NULL)) {
        if (flags & FLAG_EXPECT_FAILURE) {
            ret = 0;
            VIR_TEST_DEBUG("Got expected error: %s",
                    virGetLastErrorMessage());
            virResetLastError();
        }
        goto out;
    }

    if (!(actualargv = virCommandToStringFull(cmd, true, true)))
        goto out;

    if (actualdm != NULL)
        virTrimSpaces(actualdm, NULL);

    if (!(actualld = virCommandToStringFull(ldcmd, true, true)))
        goto out;

    if (virTestCompareToFileFull(actualargv, cmdline, false) < 0)
        goto out;

    if (virTestCompareToFileFull(actualld, ldcmdline, false) < 0)
        goto out;

    if (virFileExists(dmcmdline) || actualdm) {
        if (virTestCompareToFile(actualdm, dmcmdline) < 0)
            goto out;
    }

    ret = 0;

 out:
    if (vm && vm->def &&
        vm->def->ngraphics == 1 &&
        vm->def->graphics[0]->type == VIR_DOMAIN_GRAPHICS_TYPE_VNC)
        virPortAllocatorRelease(vm->def->graphics[0]->data.vnc.port);

    return ret;
}

struct testInfo {
    const char *name;
    unsigned int flags;
};

static int
testCompareXMLToArgvHelper(const void *data)
{
    const struct testInfo *info = data;
    g_autofree char *xml = NULL;
    g_autofree char *args = NULL;
    g_autofree char *ldargs = NULL;
    g_autofree char *dmargs = NULL;
    const char *arch = virArchToString(virArchFromHost());

    xml = g_strdup_printf("%s/bhyvexml2argvdata/%s/bhyvexml2argv-%s.xml",
                          abs_srcdir, arch, info->name);
    args = g_strdup_printf("%s/bhyvexml2argvdata/%s/bhyvexml2argv-%s.args",
                           abs_srcdir, arch, info->name);
    ldargs = g_strdup_printf("%s/bhyvexml2argvdata/%s/bhyvexml2argv-%s.ldargs",
                             abs_srcdir, arch, info->name);
    dmargs = g_strdup_printf("%s/bhyvexml2argvdata/%s/bhyvexml2argv-%s.devmap",
                             abs_srcdir, arch, info->name);

    return testCompareXMLToArgvFiles(xml, args, ldargs, dmargs, info->flags);
}

static int
mymain(void)
{
    int ret = 0;
    g_autofree char *fakefirmwaredir = g_strdup("fakefirmwaredir");
    g_autofree char *fakenvramdir = g_strdup("fakenvramdir");
    g_autofree char *fakefirmwareemptydir = g_strdup("fakefirmwareemptydir");

    if ((driver.caps = virBhyveCapsBuild()) == NULL)
        return EXIT_FAILURE;

    if ((driver.xmlopt = virBhyveDriverCreateXMLConf(&driver)) == NULL)
        return EXIT_FAILURE;

    if (!(driver.remotePorts = virPortAllocatorRangeNew("display", 5900, 65535)))
        return EXIT_FAILURE;

    if (!(driver.config = virBhyveDriverConfigNew()))
        return EXIT_FAILURE;

    VIR_FREE(driver.config->firmwareDir);
    VIR_FREE(driver.config->nvramDir);
    driver.config->firmwareDir = g_steal_pointer(&fakefirmwaredir);
    driver.config->nvramDir = g_steal_pointer(&fakenvramdir);
    driver.config->bhyveloadTimeout = 0;
    driver.config->bhyveloadTimeoutKill = 0;

# define DO_TEST_FULL(name, flags) \
    do { \
        static struct testInfo info = { \
            name, (flags) \
        }; \
        if (virTestRun("BHYVE XML-2-ARGV " name, \
                       testCompareXMLToArgvHelper, &info) < 0) \
            ret = -1; \
    } while (0)

# define DO_TEST(name) \
    DO_TEST_FULL(name, 0)

# define DO_TEST_FAILURE(name) \
    DO_TEST_FULL(name, FLAG_EXPECT_FAILURE)

# define DO_TEST_PARSE_ERROR(name) \
    DO_TEST_FULL(name, FLAG_EXPECT_PARSE_ERROR)

# define DO_TEST_PREPARE_ERROR(name) \
    DO_TEST_FULL(name, FLAG_EXPECT_PREPARE_ERROR)

    driver.grubcaps = BHYVE_GRUB_CAP_CONSDEV;
    driver.bhyvecaps = BHYVE_CAP_RTC_UTC | BHYVE_CAP_AHCI32SLOT | \
                       BHYVE_CAP_NET_E1000 | BHYVE_CAP_LPC_BOOTROM | \
                       BHYVE_CAP_FBUF | BHYVE_CAP_XHCI | \
                       BHYVE_CAP_CPUTOPOLOGY | BHYVE_CAP_SOUND_HDA | \
                       BHYVE_CAP_VNC_PASSWORD | BHYVE_CAP_VIRTIO_9P | \
                       BHYVE_CAP_NVME;

    DO_TEST("base");
    DO_TEST("wired");
    DO_TEST("acpiapic");
    DO_TEST("disk-cdrom");
    DO_TEST("disk-virtio");
    DO_TEST("macaddr");
    DO_TEST("serial");
    DO_TEST("console");
    DO_TEST("console-master-slave-not-specified");
    DO_TEST("grub-defaults");
    DO_TEST("grub-bootorder");
    DO_TEST("grub-bootorder2");
    DO_TEST("bhyveload-bootorder");
    DO_TEST("bhyveload-bootorder1");
    DO_TEST_FAILURE("bhyveload-bootorder2");
    DO_TEST("bhyveload-bootorder3");
    DO_TEST("bhyveload-explicitargs");
    DO_TEST_FAILURE("bhyveload-bootorder4");
    DO_TEST_PARSE_ERROR("bhyveload-bootorder5");
    DO_TEST("custom-loader");
    DO_TEST("disk-cdrom-grub");
    DO_TEST("serial-grub");
    DO_TEST("localtime");
    DO_TEST("net-e1000");
    DO_TEST("passthru");
    DO_TEST("passthru-multiple-devs");
    DO_TEST("uefi");
    DO_TEST("uefi-nvram");
    DO_TEST("uefi-nvram-template-set");
    DO_TEST("uefi-nvram-template-and-source-set");
    DO_TEST("vnc");
    DO_TEST("vnc-vgaconf-on");
    DO_TEST("vnc-vgaconf-off");
    DO_TEST("vnc-vgaconf-io");
    DO_TEST("vnc-autoport");
    DO_TEST("vnc-resolution");
    DO_TEST("vnc-password");
    DO_TEST("vnc-wait");
    DO_TEST("vnc-wait-no");
    DO_TEST_FAILURE("vnc-password-comma");
    DO_TEST("cputopology");
    DO_TEST_FAILURE("cputopology-nvcpu-mismatch");
    DO_TEST("commandline");
    DO_TEST("msrs");
    DO_TEST("sound");
    DO_TEST("isa-controller");
    DO_TEST_FAILURE("isa-multiple-controllers");
    DO_TEST("firmware-efi");
    driver.config->firmwareDir = fakefirmwareemptydir;
    DO_TEST_PREPARE_ERROR("firmware-efi");
    DO_TEST("fs-9p");
    DO_TEST("fs-9p-readonly");
    DO_TEST_FAILURE("fs-9p-unsupported-type");
    DO_TEST_FAILURE("fs-9p-unsupported-driver");
    DO_TEST_FAILURE("fs-9p-unsupported-accessmode");
    driver.bhyvecaps &= ~BHYVE_CAP_VIRTIO_9P;
    DO_TEST_FAILURE("fs-9p");
    DO_TEST("virtio-rnd");
    DO_TEST_FAILURE("virtio-rnd-backend-random-non-default-file");
    DO_TEST_FAILURE("virtio-rnd-backend-builtin");
    DO_TEST_FAILURE("virtio-rnd-transitional");
    driver.bhyvecaps &= ~BHYVE_CAP_VIRTIO_RND;
    DO_TEST_FAILURE("virtio-rnd");
    DO_TEST("serial-tcp");
    DO_TEST("4-consoles");
    DO_TEST_FAILURE("serial-invalid-port");
    DO_TEST("nvme");
    DO_TEST("2-nvme-2-controllers");
    DO_TEST_FAILURE("2-nvme-same-controller");
    DO_TEST("sata-rotation-rate");
    DO_TEST_FAILURE("disk-virtio-rotation-rate");
    DO_TEST_FAILURE("disk-virtio-queue-opts");
    DO_TEST("slirp");
    DO_TEST("slirp-mac-addr");
    DO_TEST_FAILURE("slirp-ip");
    DO_TEST("virtio-scsi");

    /* Address allocation tests */
    DO_TEST("addr-single-sata-disk");
    DO_TEST("addr-multiple-sata-disks");
    DO_TEST("addr-more-than-32-sata-disks");
    DO_TEST("addr-single-virtio-disk");
    DO_TEST("addr-multiple-virtio-disks");
    DO_TEST("addr-isa-controller-on-slot-1");
    DO_TEST("addr-isa-controller-on-slot-31");
    DO_TEST("addr-non-isa-controller-on-slot-1");

    /* The same without 32 devs per controller support */
    driver.bhyvecaps ^= BHYVE_CAP_AHCI32SLOT;
    DO_TEST("addr-no32devs-single-sata-disk");
    DO_TEST("addr-no32devs-multiple-sata-disks");
    DO_TEST_FAILURE("addr-no32devs-more-than-32-sata-disks");

    /* USB xhci tablet */
    DO_TEST("input-xhci-tablet");
    DO_TEST_FAILURE("xhci-multiple-controllers");
    DO_TEST_FAILURE("xhci-no-devs");
    DO_TEST_FAILURE("xhci-multiple-devs");
    driver.bhyvecaps ^= BHYVE_CAP_XHCI;
    DO_TEST_FAILURE("input-xhci-tablet");

    driver.grubcaps = 0;

    DO_TEST("serial-grub-nocons");

    driver.bhyvecaps &= ~BHYVE_CAP_NET_E1000;

    DO_TEST_FAILURE("net-e1000");

    driver.bhyvecaps &= ~BHYVE_CAP_LPC_BOOTROM;
    DO_TEST_FAILURE("uefi");

    driver.bhyvecaps &= ~BHYVE_CAP_FBUF;
    DO_TEST_FAILURE("vnc");

    driver.bhyvecaps &= ~BHYVE_CAP_CPUTOPOLOGY;
    DO_TEST_FAILURE("cputopology");

    driver.bhyvecaps &= ~BHYVE_CAP_SOUND_HDA;
    DO_TEST_FAILURE("sound");

    driver.bhyvecaps &= ~BHYVE_CAP_VNC_PASSWORD;
    DO_TEST_FAILURE("vnc-password");

    driver.bhyvecaps &= ~BHYVE_CAP_NVME;
    DO_TEST_FAILURE("nvme");

    driver.config->bhyveloadTimeout = 300;
    driver.config->bhyveloadTimeoutKill = 20;
    DO_TEST("bhyveload-timeout");

    /* arm64 tests */
    virObjectUnref(driver.caps);
    virTestSetHostArch(VIR_ARCH_AARCH64);
    driver.caps = virBhyveCapsBuild();
    /* bhyve does not support UTC clock on ARM */
    driver.bhyvecaps ^= BHYVE_CAP_RTC_UTC;

    DO_TEST("base");
    DO_TEST("console");
    DO_TEST("bootloader");

    virObjectUnref(driver.caps);
    virObjectUnref(driver.xmlopt);
    virPortAllocatorRangeFree(driver.remotePorts);
    virObjectUnref(driver.config);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN_PRELOAD(mymain, VIR_TEST_MOCK("bhyvexml2argv"))

#else

int main(void)
{
    return EXIT_AM_SKIP;
}

#endif /* WITH_BHYVE */
