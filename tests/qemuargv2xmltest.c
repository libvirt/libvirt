#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <fcntl.h>

#include "testutils.h"

#ifdef WITH_QEMU

# include "internal.h"
# include "qemu/qemu_parse_command.h"
# include "testutilsqemu.h"
# include "virstring.h"

# define VIR_FROM_THIS VIR_FROM_NONE

static virQEMUDriver driver;

static int testSanitizeDef(virDomainDefPtr vmdef)
{
    size_t i = 0;
    int ret = -1;

    /* Remove UUID randomness */
    if (virUUIDParse("c7a5fdbd-edaf-9455-926a-d65c16db1809", vmdef->uuid) < 0)
        goto fail;

    /* qemuargv2xml doesn't know what to set for a secret usage/uuid,
     * so hardcode usage='qemuargv2xml_usage' to appead the schema checker */
    for (i = 0; i < vmdef->ndisks; i++) {
        virDomainDiskDefPtr disk = vmdef->disks[i];

        if (disk->src->auth) {
            disk->src->auth->seclookupdef.type = VIR_SECRET_LOOKUP_TYPE_USAGE;
            if (VIR_STRDUP(disk->src->auth->seclookupdef.u.usage,
                          "qemuargv2xml_usage") < 0)
                goto fail;
        }
    }

    ret = 0;
 fail:
    return ret;
}

typedef enum {
    FLAG_EXPECT_WARNING     = 1 << 0,
} virQemuXML2ArgvTestFlags;

static int testCompareXMLToArgvFiles(const char *xmlfile,
                                     const char *cmdfile,
                                     virQemuXML2ArgvTestFlags flags)
{
    char *actualxml = NULL;
    char *cmd = NULL;
    char *log = NULL;
    int ret = -1;
    virDomainDefPtr vmdef = NULL;

    if (virTestLoadFile(cmdfile, &cmd) < 0)
        goto fail;

    if (!(vmdef = qemuParseCommandLineString(driver.caps, driver.xmlopt,
                                             cmd, NULL, NULL, NULL)))
        goto fail;

    if (!virTestOOMActive()) {
        if ((log = virTestLogContentAndReset()) == NULL)
            goto fail;
        if (flags & FLAG_EXPECT_WARNING) {
            if (*log) {
                VIR_TEST_DEBUG("Got expected warning from "
                            "qemuParseCommandLineString:\n%s",
                            log);
            } else {
                VIR_TEST_DEBUG("qemuParseCommandLineString "
                        "should have logged a warning\n");
                goto fail;
            }
        } else { /* didn't expect a warning */
            if (*log) {
                VIR_TEST_DEBUG("Got unexpected warning from "
                            "qemuParseCommandLineString:\n%s",
                            log);
                goto fail;
            }
        }
    }

    if (testSanitizeDef(vmdef) < 0)
        goto fail;

    if (!virDomainDefCheckABIStability(vmdef, vmdef)) {
        VIR_TEST_DEBUG("ABI stability check failed on %s", xmlfile);
        goto fail;
    }

    if (!(actualxml = virDomainDefFormat(vmdef, driver.caps, 0)))
        goto fail;

    if (virTestCompareToFile(actualxml, xmlfile) < 0)
        goto fail;

    ret = 0;

 fail:
    VIR_FREE(actualxml);
    VIR_FREE(cmd);
    VIR_FREE(log);
    virDomainDefFree(vmdef);
    return ret;
}


struct testInfo {
    const char *name;
    unsigned int flags;
};

static int
testCompareXMLToArgvHelper(const void *data)
{
    int result = -1;
    const struct testInfo *info = data;
    char *xml = NULL;
    char *args = NULL;

    if (virAsprintf(&xml, "%s/qemuargv2xmldata/qemuargv2xml-%s.xml",
                    abs_srcdir, info->name) < 0 ||
        virAsprintf(&args, "%s/qemuargv2xmldata/qemuargv2xml-%s.args",
                    abs_srcdir, info->name) < 0)
        goto cleanup;

    result = testCompareXMLToArgvFiles(xml, args, info->flags);

 cleanup:
    VIR_FREE(xml);
    VIR_FREE(args);
    return result;
}



static int
mymain(void)
{
    int ret = 0;

    if (qemuTestDriverInit(&driver) < 0)
        return EXIT_FAILURE;


# define DO_TEST_FULL(name, flags)                                      \
    do {                                                                \
        const struct testInfo info = { name, (flags) };                 \
        if (virTestRun("QEMU ARGV-2-XML " name,                         \
                       testCompareXMLToArgvHelper, &info) < 0)          \
            ret = -1;                                                   \
    } while (0)

# define DO_TEST(name)                                                  \
        DO_TEST_FULL(name, 0)

    setenv("PATH", "/bin", 1);
    setenv("USER", "test", 1);
    setenv("LOGNAME", "test", 1);
    setenv("HOME", "/home/test", 1);
    unsetenv("TMPDIR");
    unsetenv("LD_PRELOAD");
    unsetenv("LD_LIBRARY_PATH");

    /* Can't roundtrip vcpu  cpuset attribute */
    /*DO_TEST("minimal", QEMU_CAPS_NAME);*/
    DO_TEST("machine-core-on");
    DO_TEST("machine-core-off");
    DO_TEST("boot-cdrom");
    DO_TEST("boot-network");
    DO_TEST("boot-floppy");
    DO_TEST("kvmclock");
    /* This needs <emulator>./qemu.sh</emulator> which doesn't work here.  */
    /*DO_TEST("cpu-kvmclock");*/

    DO_TEST("reboot-timeout-enabled");
    DO_TEST("reboot-timeout-disabled");

    DO_TEST("clock-utc");
    DO_TEST("clock-localtime");
    DO_TEST("disk-cdrom");
    DO_TEST("disk-cdrom-empty");
    DO_TEST("disk-floppy");
    DO_TEST("disk-many");
    DO_TEST("disk-virtio");
    DO_TEST("disk-drive-boot-disk");
    DO_TEST("disk-drive-boot-cdrom");
    DO_TEST("disk-drive-fmt-qcow");
    DO_TEST("disk-drive-error-policy-stop");
    DO_TEST("disk-drive-error-policy-enospace");
    DO_TEST("disk-drive-error-policy-wreport-rignore");
    DO_TEST("disk-drive-cache-v2-wt");
    DO_TEST("disk-drive-cache-v2-wb");
    DO_TEST("disk-drive-cache-v2-none");
    DO_TEST("disk-drive-cache-directsync");
    DO_TEST("disk-drive-cache-unsafe");
    DO_TEST("disk-drive-network-nbd");
    DO_TEST("disk-drive-network-nbd-export");
    DO_TEST("disk-drive-network-nbd-ipv6");
    DO_TEST("disk-drive-network-nbd-ipv6-export");
    DO_TEST("disk-drive-network-nbd-unix");
    DO_TEST("disk-drive-network-iscsi");
    DO_TEST("disk-drive-network-iscsi-auth");
    DO_TEST("disk-drive-network-gluster");
    DO_TEST("disk-drive-network-rbd");
    DO_TEST("disk-drive-network-rbd-auth");
    DO_TEST("disk-drive-network-rbd-ipv6");
    /* older format using CEPH_ARGS env var */
    DO_TEST("disk-drive-network-rbd-ceph-env");
    DO_TEST("disk-drive-network-sheepdog");
    DO_TEST("disk-usb");
    DO_TEST("graphics-vnc");
    DO_TEST("graphics-vnc-socket");
    DO_TEST("graphics-vnc-websocket");
    DO_TEST("graphics-vnc-policy");

    DO_TEST("graphics-vnc-sasl");
    DO_TEST("graphics-vnc-tls");

    DO_TEST("graphics-sdl");
    DO_TEST("graphics-sdl-fullscreen");
    DO_TEST("nographics-vga");
    DO_TEST("nographics-vga-display");
    DO_TEST("input-usbmouse");
    DO_TEST("input-usbtablet");
    DO_TEST("misc-acpi");
    DO_TEST("misc-disable-s3");
    DO_TEST("misc-disable-suspends");
    DO_TEST("misc-enable-s4");
    DO_TEST("misc-no-reboot");
    DO_TEST("misc-uuid");
    DO_TEST("net-user");
    DO_TEST("net-virtio");
    DO_TEST("net-eth");
    DO_TEST("net-eth-ifname");

    DO_TEST("serial-vc");
    DO_TEST("serial-pty");
    DO_TEST("serial-dev");
    DO_TEST("serial-file");
    DO_TEST("serial-unix");
    DO_TEST("serial-tcp");
    DO_TEST("serial-udp");
    DO_TEST("serial-tcp-telnet");
    DO_TEST("serial-many");
    DO_TEST("parallel-tcp");
    DO_TEST("console-compat");
    DO_TEST("sound");
    DO_TEST("watchdog");

    DO_TEST("hostdev-usb-address");

    DO_TEST("hostdev-pci-address");

    DO_TEST("mem-scale");
    DO_TEST("smp");

    DO_TEST("hyperv");
    DO_TEST("hyperv-panic");

    DO_TEST("kvm-features");

    DO_TEST("pseries-nvram");
    DO_TEST("pseries-disk");

    DO_TEST("nosharepages");

    DO_TEST("restore-v2");
    DO_TEST("migrate");

    DO_TEST_FULL("qemu-ns-no-env", FLAG_EXPECT_WARNING);

    DO_TEST("machine-aeskeywrap-on-argv");
    DO_TEST("machine-aeskeywrap-off-argv");
    DO_TEST("machine-deakeywrap-on-argv");
    DO_TEST("machine-deakeywrap-off-argv");
    DO_TEST("machine-keywrap-none-argv");

    qemuTestDriverFree(&driver);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)

#else

int
main(void)
{
    return EXIT_AM_SKIP;
}

#endif /* WITH_QEMU */
