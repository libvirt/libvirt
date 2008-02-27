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
static char *abs_top_srcdir;
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

    if (strcmp(expectargv, actualargv)) {
        if (getenv("DEBUG_TESTS")) {
            printf("Expect %4d '%s'\n", (int)strlen(expectargv), expectargv);
            printf("Actual %4d '%s'\n", (int)strlen(actualargv), actualargv);
        }
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
    snprintf(xml, PATH_MAX, "%s/tests/qemuxml2argvdata/qemuxml2argv-%s.xml",
             abs_top_srcdir, (const char*)data);
    snprintf(args, PATH_MAX, "%s/tests/qemuxml2argvdata/qemuxml2argv-%s.args",
             abs_top_srcdir, (const char*)data);
    return testCompareXMLToArgvFiles(xml, args);
}



int
main(int argc, char **argv)
{
    int ret = 0;

    progname = argv[0];

    if (argc > 1) {
        fprintf(stderr, "Usage: %s\n", progname);
        exit(EXIT_FAILURE);
    }

    abs_top_srcdir = getenv("abs_top_srcdir");
    if (!abs_top_srcdir)
      return 1;

    driver.caps = qemudCapsInit();

    if (virtTestRun("QEMU XML-2-ARGV minimal",
                    1, testCompareXMLToArgvHelper, "minimal") < 0)
        ret = -1;

    if (virtTestRun("QEMU XML-2-ARGV Boot CDROM",
                    1, testCompareXMLToArgvHelper, "boot-cdrom") < 0)
        ret = -1;

    if (virtTestRun("QEMU XML-2-ARGV Boot Network",
                    1, testCompareXMLToArgvHelper, "boot-network") < 0)
        ret = -1;

    if (virtTestRun("QEMU XML-2-ARGV Boot Floppy",
                    1, testCompareXMLToArgvHelper, "boot-floppy") < 0)
        ret = -1;

    if (virtTestRun("QEMU XML-2-ARGV Clock UTC",
                    1, testCompareXMLToArgvHelper, "clock-utc") < 0)
        ret = -1;

    if (virtTestRun("QEMU XML-2-ARGV Clock Localtime",
                    1, testCompareXMLToArgvHelper, "clock-localtime") < 0)
        ret = -1;

    if (virtTestRun("QEMU XML-2-ARGV Disk CDROM",
                    1, testCompareXMLToArgvHelper, "disk-cdrom") < 0)
        ret = -1;

    if (virtTestRun("QEMU XML-2-ARGV Disk Floppy",
                    1, testCompareXMLToArgvHelper, "disk-floppy") < 0)
        ret = -1;

    if (virtTestRun("QEMU XML-2-ARGV Disk Many",
                    1, testCompareXMLToArgvHelper, "disk-many") < 0)
        ret = -1;

    if (virtTestRun("QEMU XML-2-ARGV Graphics VNC",
                    1, testCompareXMLToArgvHelper, "graphics-vnc") < 0)
        ret = -1;

    if (virtTestRun("QEMU XML-2-ARGV Graphics SDL",
                    1, testCompareXMLToArgvHelper, "graphics-sdl") < 0)
        ret = -1;

    if (virtTestRun("QEMU XML-2-ARGV Input USB Mouse",
                    1, testCompareXMLToArgvHelper, "input-usbmouse") < 0)
        ret = -1;

    if (virtTestRun("QEMU XML-2-ARGV Input USB Tablet",
                    1, testCompareXMLToArgvHelper, "input-usbtablet") < 0)
        ret = -1;

    if (virtTestRun("QEMU XML-2-ARGV Misc ACPI",
                    1, testCompareXMLToArgvHelper, "misc-acpi") < 0)
        ret = -1;

    if (virtTestRun("QEMU XML-2-ARGV Misc No Reboot",
                    1, testCompareXMLToArgvHelper, "misc-no-reboot") < 0)
        ret = -1;

    if (virtTestRun("QEMU XML-2-ARGV Net User",
                    1, testCompareXMLToArgvHelper, "net-user") < 0)
        ret = -1;


    virCapabilitiesFree(driver.caps);

    exit(ret==0 ? EXIT_SUCCESS : EXIT_FAILURE);
}

#else

int main (void) { exit (77); /* means 'test skipped' for automake */ }

#endif /* WITH_QEMU */

/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
