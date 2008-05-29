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

static int testCompareXMLToArgvFiles(const char *xml, const char *cmd, int extraFlags) {
    char xmlData[MAX_FILE];
    char argvData[MAX_FILE];
    char *xmlPtr = &(xmlData[0]);
    char *expectargv = &(argvData[0]);
    char *actualargv = NULL;
    char **argv = NULL;
    char **tmp = NULL;
    int ret = -1, len;
    struct qemud_vm_def *vmdef = NULL;
    struct qemud_vm vm;

    if (virtTestLoadFile(xml, &xmlPtr, MAX_FILE) < 0)
        goto fail;

    if (virtTestLoadFile(cmd, &expectargv, MAX_FILE) < 0)
        goto fail;

    if (!(vmdef = qemudParseVMDef(NULL, &driver, xmlData, "test")))
        goto fail;

    memset(&vm, 0, sizeof vm);
    vm.def = vmdef;
    vm.pid = -1;
    vm.id = -1;
    vm.qemuVersion = 0 * 1000 * 100 + (8 * 1000) + 1;
    vm.qemuCmdFlags = QEMUD_CMD_FLAG_VNC_COLON |
        QEMUD_CMD_FLAG_NO_REBOOT;
    vm.qemuCmdFlags |= extraFlags;
    vm.migrateFrom[0] = '\0';

    vmdef->vncActivePort = vmdef->vncPort;

    if (qemudBuildCommandLine(NULL, &driver, &vm, &argv) < 0)
        goto fail;

    tmp = argv;
    len = 0;
    while (*tmp) {
        len += strlen(*tmp) + 1;
        tmp++;
    }
    actualargv = malloc(sizeof(*actualargv)*len);
    actualargv[0] = '\0';
    tmp = argv;
    len = 0;
    while (*tmp) {
        if (actualargv[0])
            strcat(actualargv, " ");
        strcat(actualargv, *tmp);
        tmp++;
    }

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
            free(*tmp);
            tmp++;
        }
        free(argv);
    }
    if (vmdef)
        qemudFreeVMDef(vmdef);
    return ret;
}


struct testInfo {
    const char *name;
    int extraFlags;
};

static int testCompareXMLToArgvHelper(const void *data) {
    const struct testInfo *info = data;
    char xml[PATH_MAX];
    char args[PATH_MAX];
    snprintf(xml, PATH_MAX, "%s/qemuxml2argvdata/qemuxml2argv-%s.xml",
             abs_srcdir, info->name);
    snprintf(args, PATH_MAX, "%s/qemuxml2argvdata/qemuxml2argv-%s.args",
             abs_srcdir, info->name);
    return testCompareXMLToArgvFiles(xml, args, info->extraFlags);
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

#define DO_TEST(name, extraFlags)                                       \
    do {                                                                \
        struct testInfo info = { name, extraFlags };                    \
        if (virtTestRun("QEMU XML-2-ARGV " name,                        \
                        1, testCompareXMLToArgvHelper, &info) < 0)      \
            ret = -1;                                                   \
    } while (0)

    DO_TEST("minimal", QEMUD_CMD_FLAG_NAME);
    DO_TEST("boot-cdrom", 0);
    DO_TEST("boot-network", 0);
    DO_TEST("boot-floppy", 0);
    DO_TEST("bootloader", 0);
    DO_TEST("clock-utc", 0);
    DO_TEST("clock-localtime", 0);
    DO_TEST("disk-cdrom", 0);
    DO_TEST("disk-floppy", 0);
    DO_TEST("disk-many", 0);
    DO_TEST("disk-virtio", QEMUD_CMD_FLAG_DRIVE |
            QEMUD_CMD_FLAG_DRIVE_BOOT);
    DO_TEST("disk-xenvbd", QEMUD_CMD_FLAG_DRIVE |
            QEMUD_CMD_FLAG_DRIVE_BOOT);
    DO_TEST("graphics-vnc", 0);
    DO_TEST("graphics-sdl", 0);
    DO_TEST("input-usbmouse", 0);
    DO_TEST("input-usbtablet", 0);
    DO_TEST("input-xen", 0);
    DO_TEST("misc-acpi", 0);
    DO_TEST("misc-no-reboot", 0);
    DO_TEST("net-user", 0);
    DO_TEST("net-virtio", 0);

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

    virCapabilitiesFree(driver.caps);

    return(ret==0 ? EXIT_SUCCESS : EXIT_FAILURE);
}

VIRT_TEST_MAIN(mymain)

#else

int main (void) { return (77); /* means 'test skipped' for automake */ }

#endif /* WITH_QEMU */
