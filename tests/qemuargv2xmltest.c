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

# include "testutilsqemu.h"

static char *progname;
static char *abs_srcdir;
static struct qemud_driver driver;

# define MAX_FILE 4096

static int blankProblemElements(char *data)
{
    if (virtTestClearLineRegex("<name>[[:alnum:]]+</name>", data) < 0 ||
        virtTestClearLineRegex("<uuid>([[:alnum:]]|-)+</uuid>", data) < 0 ||
        virtTestClearLineRegex("<memory>[[:digit:]]+</memory>", data) < 0 ||
        virtTestClearLineRegex("<currentMemory>[[:digit:]]+</currentMemory>", data) < 0 ||
        virtTestClearLineRegex("<readonly/>", data) < 0 ||
        virtTestClearLineRegex("<sharable/>", data) < 0)
        return -1;
    return 0;
}

static int testCompareXMLToArgvFiles(const char *xml,
                                     const char *cmdfile,
                                     bool expect_warning) {
    char xmlData[MAX_FILE];
    char cmdData[MAX_FILE];
    char *expectxml = &(xmlData[0]);
    char *actualxml = NULL;
    char *cmd = &(cmdData[0]);
    int ret = -1;
    virDomainDefPtr vmdef = NULL;
    char *log;

    if (virtTestLoadFile(cmdfile, &cmd, MAX_FILE) < 0)
        goto fail;
    if (virtTestLoadFile(xml, &expectxml, MAX_FILE) < 0)
        goto fail;

    if (!(vmdef = qemuParseCommandLineString(driver.caps, cmd)))
        goto fail;

    if ((log = virtTestLogContentAndReset()) == NULL)
        goto fail;
    if ((*log != '\0') != expect_warning) {
        free(log);
        goto fail;
    }
    free(log);

    if (!(actualxml = virDomainDefFormat(vmdef, 0)))
        goto fail;

    if (blankProblemElements(expectxml) < 0 ||
        blankProblemElements(actualxml) < 0)
        goto fail;

    if (STRNEQ(expectxml, actualxml)) {
        virtTestDifference(stderr, expectxml, actualxml);
        goto fail;
    }

    ret = 0;

 fail:
    free(actualxml);
    virDomainDefFree(vmdef);
    return ret;
}


struct testInfo {
    const char *name;
    unsigned long long extraFlags;
    const char *migrateFrom;
};

static int testCompareXMLToArgvHelper(const void *data) {
    const struct testInfo *info = data;
    char xml[PATH_MAX];
    char args[PATH_MAX];
    snprintf(xml, PATH_MAX, "%s/qemuxml2argvdata/qemuxml2argv-%s.xml",
             abs_srcdir, info->name);
    snprintf(args, PATH_MAX, "%s/qemuxml2argvdata/qemuxml2argv-%s.args",
             abs_srcdir, info->name);
    return testCompareXMLToArgvFiles(xml, args, !!info->extraFlags);
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
    if((driver.stateDir = strdup("/nowhere")) == NULL)
        return EXIT_FAILURE;

# define DO_TEST_FULL(name, extraFlags, migrateFrom)                     \
    do {                                                                \
        const struct testInfo info = { name, extraFlags, migrateFrom }; \
        if (virtTestRun("QEMU ARGV-2-XML " name,                        \
                        1, testCompareXMLToArgvHelper, &info) < 0)      \
            ret = -1;                                                   \
    } while (0)

# define DO_TEST(name)                                                  \
        DO_TEST_FULL(name, 0, NULL)

    setenv("PATH", "/bin", 1);
    setenv("USER", "test", 1);
    setenv("LOGNAME", "test", 1);
    setenv("HOME", "/home/test", 1);
    unsetenv("TMPDIR");
    unsetenv("LD_PRELOAD");
    unsetenv("LD_LIBRARY_PATH");

    /* Can't roundtrip vcpu  cpuset attribute */
    /*DO_TEST("minimal", QEMUD_CMD_FLAG_NAME);*/
    DO_TEST("boot-cdrom");
    DO_TEST("boot-network");
    DO_TEST("boot-floppy");
    /* Can't roundtrip xenner arch */
    /*DO_TEST("bootloader");*/
    DO_TEST("clock-utc");
    DO_TEST("clock-localtime");
    DO_TEST("disk-cdrom");
    DO_TEST("disk-cdrom-empty");
    DO_TEST("disk-floppy");
    DO_TEST("disk-many");
    DO_TEST("disk-virtio");
    DO_TEST("disk-xenvbd");
    DO_TEST("disk-drive-boot-disk");
    DO_TEST("disk-drive-boot-cdrom");
    DO_TEST("disk-drive-fmt-qcow");
    /* Can't roundtrip  shareable+cache mode option */
    /*DO_TEST("disk-drive-shared");*/
    /* Can't roundtrip v1 writethrough option */
    /*DO_TEST("disk-drive-cache-v1-wt");*/
    DO_TEST("disk-drive-cache-v1-wb");
    DO_TEST("disk-drive-cache-v1-none");
    DO_TEST("disk-drive-error-policy-stop");
    DO_TEST("disk-drive-error-policy-enospace");
    DO_TEST("disk-drive-cache-v2-wt");
    DO_TEST("disk-drive-cache-v2-wb");
    DO_TEST("disk-drive-cache-v2-none");
    DO_TEST("disk-usb");
    DO_TEST("graphics-vnc");

    driver.vncSASL = 1;
    driver.vncSASLdir = strdup("/root/.sasl2");
    DO_TEST("graphics-vnc-sasl");
    driver.vncTLS = 1;
    driver.vncTLSx509verify = 1;
    driver.vncTLSx509certdir = strdup("/etc/pki/tls/qemu");
    DO_TEST("graphics-vnc-tls");
    driver.vncSASL = driver.vncTLSx509verify = driver.vncTLS = 0;
    free(driver.vncSASLdir);
    free(driver.vncTLSx509certdir);
    driver.vncSASLdir = driver.vncTLSx509certdir = NULL;

    DO_TEST("graphics-sdl");
    DO_TEST("graphics-sdl-fullscreen");
    DO_TEST("nographics-vga");
    DO_TEST("input-usbmouse");
    DO_TEST("input-usbtablet");
    /* Can't rountrip xenner arch */
    /*DO_TEST("input-xen");*/
    DO_TEST("misc-acpi");
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

    DO_TEST("smp");

    DO_TEST_FULL("restore-v1", 0, "stdio");
    DO_TEST_FULL("restore-v2", 0, "stdio");
    DO_TEST_FULL("restore-v2", 0, "exec:cat");
    DO_TEST_FULL("migrate", 0, "tcp:10.0.0.1:5000");

    DO_TEST_FULL("qemu-ns-no-env", 1, NULL);

    free(driver.stateDir);
    virCapabilitiesFree(driver.caps);

    return(ret==0 ? EXIT_SUCCESS : EXIT_FAILURE);
}

VIRT_TEST_MAIN(mymain)

#else

int main (void) { return (EXIT_AM_SKIP); }

#endif /* WITH_QEMU */
