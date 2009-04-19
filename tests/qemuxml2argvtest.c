#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <fcntl.h>

#ifdef WITH_QEMU

#include "internal.h"
#include "testutils.h"
#include "qemu_conf.h"

#include "testutilsqemu.h"

static char *progname;
static char *abs_srcdir;
static struct qemud_driver driver;

#define MAX_FILE 4096

static int testCompareXMLToArgvFiles(const char *xml,
                                     const char *cmd,
                                     int extraFlags,
                                     const char *migrateFrom) {
    char argvData[MAX_FILE];
    char *expectargv = &(argvData[0]);
    char *actualargv = NULL;
    const char **argv = NULL;
    const char **qenv = NULL;
    const char **tmp = NULL;
    int ret = -1, len, flags;
    virDomainDefPtr vmdef = NULL;

    if (virtTestLoadFile(cmd, &expectargv, MAX_FILE) < 0)
        goto fail;

    if (!(vmdef = virDomainDefParseFile(NULL, driver.caps, xml,
                                        VIR_DOMAIN_XML_INACTIVE)))
        goto fail;

    if (extraFlags & QEMUD_CMD_FLAG_DOMID)
        vmdef->id = 6;
    else
        vmdef->id = -1;

    flags = QEMUD_CMD_FLAG_VNC_COLON |
        QEMUD_CMD_FLAG_NO_REBOOT |
        extraFlags;

    if (qemudBuildCommandLine(NULL, &driver,
                              vmdef, flags, &argv, &qenv,
                              NULL, NULL, migrateFrom) < 0)
        goto fail;

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
    actualargv = malloc(sizeof(*actualargv)*len);
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
    return ret;
}


struct testInfo {
    const char *name;
    int extraFlags;
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
    return testCompareXMLToArgvFiles(xml, args, info->extraFlags, info->migrateFrom);
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

#define DO_TEST_FULL(name, extraFlags, migrateFrom)                     \
    do {                                                                \
        const struct testInfo info = { name, extraFlags, migrateFrom }; \
        if (virtTestRun("QEMU XML-2-ARGV " name,                        \
                        1, testCompareXMLToArgvHelper, &info) < 0)      \
            ret = -1;                                                   \
    } while (0)

#define DO_TEST(name, extraFlags)                       \
        DO_TEST_FULL(name, extraFlags, NULL)

    setenv("PATH", "/bin", 1);
    setenv("USER", "test", 1);
    setenv("LOGNAME", "test", 1);
    setenv("HOME", "/home/test", 1);
    unsetenv("TMPDIR");
    unsetenv("LD_PRELOAD");
    unsetenv("LD_LIBRARY_PATH");

    DO_TEST("minimal", QEMUD_CMD_FLAG_NAME);
    DO_TEST("boot-cdrom", 0);
    DO_TEST("boot-network", 0);
    DO_TEST("boot-floppy", 0);
    DO_TEST("bootloader", 0);
    DO_TEST("clock-utc", 0);
    DO_TEST("clock-localtime", 0);
    DO_TEST("disk-cdrom", 0);
    DO_TEST("disk-cdrom-empty", QEMUD_CMD_FLAG_DRIVE);
    DO_TEST("disk-floppy", 0);
    DO_TEST("disk-many", 0);
    DO_TEST("disk-virtio", QEMUD_CMD_FLAG_DRIVE |
            QEMUD_CMD_FLAG_DRIVE_BOOT);
    DO_TEST("disk-xenvbd", QEMUD_CMD_FLAG_DRIVE |
            QEMUD_CMD_FLAG_DRIVE_BOOT);
    DO_TEST("disk-drive-boot-disk", QEMUD_CMD_FLAG_DRIVE |
            QEMUD_CMD_FLAG_DRIVE_BOOT);
    DO_TEST("disk-drive-boot-cdrom", QEMUD_CMD_FLAG_DRIVE |
            QEMUD_CMD_FLAG_DRIVE_BOOT);
    DO_TEST("disk-drive-fmt-qcow", QEMUD_CMD_FLAG_DRIVE |
            QEMUD_CMD_FLAG_DRIVE_BOOT);
    DO_TEST("disk-drive-shared", QEMUD_CMD_FLAG_DRIVE);
    DO_TEST("disk-drive-cache-v1-wt", QEMUD_CMD_FLAG_DRIVE);
    DO_TEST("disk-drive-cache-v1-wb", QEMUD_CMD_FLAG_DRIVE);
    DO_TEST("disk-drive-cache-v1-none", QEMUD_CMD_FLAG_DRIVE);
    DO_TEST("disk-drive-cache-v2-wt", QEMUD_CMD_FLAG_DRIVE |
            QEMUD_CMD_FLAG_DRIVE_CACHE_V2);
    DO_TEST("disk-drive-cache-v2-wb", QEMUD_CMD_FLAG_DRIVE |
            QEMUD_CMD_FLAG_DRIVE_CACHE_V2);
    DO_TEST("disk-drive-cache-v2-none", QEMUD_CMD_FLAG_DRIVE |
            QEMUD_CMD_FLAG_DRIVE_CACHE_V2);
    DO_TEST("disk-usb", 0);
    DO_TEST("graphics-vnc", 0);

    driver.vncSASL = 1;
    driver.vncSASLdir = strdup("/root/.sasl2");
    DO_TEST("graphics-vnc-sasl", 0);
    driver.vncTLS = 1;
    driver.vncTLSx509verify = 1;
    driver.vncTLSx509certdir = strdup("/etc/pki/tls/qemu");
    DO_TEST("graphics-vnc-tls", 0);
    driver.vncSASL = driver.vncTLSx509verify = driver.vncTLS = 0;
    free(driver.vncSASLdir);
    free(driver.vncTLSx509certdir);
    driver.vncSASLdir = driver.vncTLSx509certdir = NULL;

    DO_TEST("graphics-sdl", 0);
    DO_TEST("graphics-sdl-fullscreen", 0);
    DO_TEST("input-usbmouse", 0);
    DO_TEST("input-usbtablet", 0);
    DO_TEST("input-xen", 0);
    DO_TEST("misc-acpi", 0);
    DO_TEST("misc-no-reboot", 0);
    DO_TEST("misc-uuid", QEMUD_CMD_FLAG_NAME |
        QEMUD_CMD_FLAG_UUID | QEMUD_CMD_FLAG_DOMID);
    DO_TEST("net-user", 0);
    DO_TEST("net-virtio", 0);
    DO_TEST("net-eth", 0);
    DO_TEST("net-eth-ifname", 0);

    DO_TEST("serial-vc", 0);
    DO_TEST("serial-pty", 0);
    DO_TEST("serial-dev", 0);
    DO_TEST("serial-file", 0);
    DO_TEST("serial-unix", 0);
    DO_TEST("serial-tcp", 0);
    DO_TEST("serial-udp", 0);
    DO_TEST("serial-tcp-telnet", 0);
    DO_TEST("serial-many", 0);
    DO_TEST("parallel-tcp", 0);
    DO_TEST("console-compat", 0);
    DO_TEST("sound", 0);

    DO_TEST("hostdev-usb-product", 0);
    DO_TEST("hostdev-usb-address", 0);

    DO_TEST("hostdev-pci-address", 0);

    DO_TEST_FULL("restore-v1", QEMUD_CMD_FLAG_MIGRATE_KVM_STDIO, "stdio");
    DO_TEST_FULL("restore-v2", QEMUD_CMD_FLAG_MIGRATE_QEMU_EXEC, "stdio");
    DO_TEST_FULL("restore-v2", QEMUD_CMD_FLAG_MIGRATE_QEMU_EXEC, "exec:cat");
    DO_TEST_FULL("migrate", QEMUD_CMD_FLAG_MIGRATE_QEMU_TCP, "tcp:10.0.0.1:5000");

    virCapabilitiesFree(driver.caps);

    return(ret==0 ? EXIT_SUCCESS : EXIT_FAILURE);
}

VIRT_TEST_MAIN(mymain)

#else

int main (void) { return (77); /* means 'test skipped' for automake */ }

#endif /* WITH_QEMU */
