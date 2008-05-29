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


static int testCompareXMLToXMLFiles(const char *xml) {
    char xmlData[MAX_FILE];
    char *xmlPtr = &(xmlData[0]);
    char *actual = NULL;
    int ret = -1;
    struct qemud_vm_def *vmdef = NULL;
    struct qemud_vm vm;

    if (virtTestLoadFile(xml, &xmlPtr, MAX_FILE) < 0)
        goto fail;

    if (!(vmdef = qemudParseVMDef(NULL, &driver, xmlData, "test")))
        goto fail;

    vm.def = vmdef;
    vm.pid = -1;
    vm.id = -1;
    vm.qemuVersion = 0 * 1000 * 100 + (8 * 1000) + 1;
    vm.qemuCmdFlags = QEMUD_CMD_FLAG_VNC_COLON |
        QEMUD_CMD_FLAG_NO_REBOOT;

    vmdef->vncActivePort = vmdef->vncPort;

    if (!(actual = qemudGenerateXML(NULL, &driver, &vm, vmdef, 0)))
        goto fail;

    if (STRNEQ(xmlData, actual)) {
        virtTestDifference(stderr, xmlData, actual);
        goto fail;
    }

    ret = 0;

 fail:
    free(actual);
    if (vmdef)
        qemudFreeVMDef(vmdef);
    return ret;
}

static int testCompareXMLToXMLHelper(const void *data) {
    char xml[PATH_MAX];
    snprintf(xml, PATH_MAX, "%s/qemuxml2argvdata/qemuxml2argv-%s.xml",
             abs_srcdir, (const char*)data);
    return testCompareXMLToXMLFiles(xml);
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
        return (EXIT_FAILURE);

#define DO_TEST(name) \
    if (virtTestRun("QEMU XML-2-XML " name, \
                    1, testCompareXMLToXMLHelper, (name)) < 0) \
        ret = -1

    DO_TEST("minimal");
    DO_TEST("boot-cdrom");
    DO_TEST("boot-network");
    DO_TEST("boot-floppy");
    DO_TEST("bootloader");
    DO_TEST("clock-utc");
    DO_TEST("clock-localtime");
    DO_TEST("disk-cdrom");
    DO_TEST("disk-floppy");
    DO_TEST("disk-many");
    DO_TEST("disk-xenvbd");
    DO_TEST("graphics-vnc");
    DO_TEST("graphics-sdl");
    DO_TEST("input-usbmouse");
    DO_TEST("input-usbtablet");
    DO_TEST("input-xen");
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

    return (ret==0 ? EXIT_SUCCESS : EXIT_FAILURE);
}

VIRT_TEST_MAIN(mymain)

#else

int main (void) { exit (77); /* means 'test skipped' to automake */ }

#endif /* WITH_QEMU */
