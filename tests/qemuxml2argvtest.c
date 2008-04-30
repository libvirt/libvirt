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

static char *progname;
static char *abs_srcdir;
static struct qemud_driver driver;

#define MAX_FILE 4096

static int testCompareXMLToArgvFiles(const char *xml, const char *cmd) {
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

    vm.def = vmdef;
    vm.pid = -1;
    vm.id = -1;
    vm.qemuVersion = 0 * 1000 * 100 + (8 * 1000) + 1;
    vm.qemuCmdFlags = QEMUD_CMD_FLAG_VNC_COLON |
        QEMUD_CMD_FLAG_NO_REBOOT;
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


static int testCompareXMLToArgvHelper(const void *data) {
    char xml[PATH_MAX];
    char args[PATH_MAX];
    snprintf(xml, PATH_MAX, "%s/qemuxml2argvdata/qemuxml2argv-%s.xml",
             abs_srcdir, (const char*)data);
    snprintf(args, PATH_MAX, "%s/qemuxml2argvdata/qemuxml2argv-%s.args",
             abs_srcdir, (const char*)data);
    return testCompareXMLToArgvFiles(xml, args);
}



int
main(int argc, char **argv)
{
    int ret = 0;
    char cwd[PATH_MAX];

    progname = argv[0];

    if (argc > 1) {
        fprintf(stderr, "Usage: %s\n", progname);
        exit(EXIT_FAILURE);
    }

    abs_srcdir = getenv("abs_srcdir");
    if (!abs_srcdir)
        abs_srcdir = getcwd(cwd, sizeof(cwd));

    driver.caps = qemudCapsInit();

#define DO_TEST(name) \
    if (virtTestRun("QEMU XML-2-ARGV " name, \
                    1, testCompareXMLToArgvHelper, (name)) < 0) \
        ret = -1

    DO_TEST("minimal");
    DO_TEST("boot-cdrom");
    DO_TEST("boot-network");
    DO_TEST("boot-floppy");
    DO_TEST("clock-utc");
    DO_TEST("clock-localtime");
    DO_TEST("disk-cdrom");
    DO_TEST("disk-floppy");
    DO_TEST("disk-many");
    DO_TEST("graphics-vnc");
    DO_TEST("graphics-sdl");
    DO_TEST("input-usbmouse");
    DO_TEST("input-usbtablet");
    DO_TEST("misc-acpi");
    DO_TEST("misc-no-reboot");
    DO_TEST("net-user");
    DO_TEST("net-virtio");

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

    virCapabilitiesFree(driver.caps);

    exit(ret==0 ? EXIT_SUCCESS : EXIT_FAILURE);
}

#else

int main (void) { exit (77); /* means 'test skipped' for automake */ }

#endif /* WITH_QEMU */
