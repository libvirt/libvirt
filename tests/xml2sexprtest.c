#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

#include "internal.h"
#include "xen/xend_internal.h"
#include "xen/xen_driver.h"
#include "xenconfig/xen_sxpr.h"
#include "testutils.h"
#include "testutilsxen.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NONE

static virCapsPtr caps;
static virDomainXMLOptionPtr xmlopt;

static int
testCompareFiles(const char *xml, const char *sexpr)
{
  char *gotsexpr = NULL;
  int ret = -1;
  virDomainDefPtr def = NULL;

  if (!(def = virDomainDefParseFile(xml, caps, xmlopt, NULL,
                                    VIR_DOMAIN_DEF_PARSE_INACTIVE)))
      goto fail;

  if (!virDomainDefCheckABIStability(def, def, xmlopt)) {
      fprintf(stderr, "ABI stability check failed on %s", xml);
      goto fail;
  }

  if (!(gotsexpr = xenFormatSxpr(NULL, def)))
      goto fail;

  if (virTestCompareToFile(gotsexpr, sexpr) < 0)
      goto fail;

  ret = 0;

 fail:
  VIR_FREE(gotsexpr);
  virDomainDefFree(def);

  return ret;
}

struct testInfo {
    const char *input;
    const char *output;
    const char *name;
};

static int
testCompareHelper(const void *data)
{
    int result = -1;
    const struct testInfo *info = data;
    char *xml = NULL;
    char *args = NULL;

    if (virAsprintf(&xml, "%s/xml2sexprdata/xml2sexpr-%s.xml",
                    abs_srcdir, info->input) < 0 ||
        virAsprintf(&args, "%s/xml2sexprdata/xml2sexpr-%s.sexpr",
                    abs_srcdir, info->output) < 0) {
        goto cleanup;
    }

    result = testCompareFiles(xml, args);

 cleanup:
    VIR_FREE(xml);
    VIR_FREE(args);

    return result;
}

static int
mymain(void)
{
    int ret = 0;

#define DO_TEST(in, out, name)                                         \
    do {                                                               \
        struct testInfo info = { in, out, name };                      \
        virResetLastError();                                           \
        if (virTestRun("Xen XML-2-SEXPR " in " -> " out,               \
                       testCompareHelper, &info) < 0)                  \
            ret = -1;                                                  \
    } while (0)

    if (!(caps = testXenCapsInit()))
        return EXIT_FAILURE;

    if (!(xmlopt = xenDomainXMLConfInit()))
        return EXIT_FAILURE;

    DO_TEST("pv", "pv", "pvtest");
    DO_TEST("fv", "fv", "fvtest");
    DO_TEST("pv", "pv", "pvtest");
    DO_TEST("fv", "fv-v2", "fvtest");
    DO_TEST("fv-vncunused", "fv-vncunused", "fvtest");
    DO_TEST("pv-vfb-new", "pv-vfb-new", "pvtest");
    DO_TEST("pv-vfb-new-auto", "pv-vfb-new-auto", "pvtest");
    DO_TEST("pv-bootloader", "pv-bootloader", "pvtest");
    DO_TEST("pv-bootloader-cmdline", "pv-bootloader-cmdline", "pvtest");
    DO_TEST("pv-vcpus", "pv-vcpus", "pvtest");

    DO_TEST("disk-file", "disk-file", "pvtest");
    DO_TEST("disk-block", "disk-block", "pvtest");
    DO_TEST("disk-block-shareable", "disk-block-shareable", "pvtest");
    DO_TEST("disk-drv-loop", "disk-drv-loop", "pvtest");
    DO_TEST("disk-drv-blkback", "disk-drv-blkback", "pvtest");
    DO_TEST("disk-drv-blktap", "disk-drv-blktap", "pvtest");
    DO_TEST("disk-drv-blktap-raw", "disk-drv-blktap-raw", "pvtest");
    DO_TEST("disk-drv-blktap-qcow", "disk-drv-blktap-qcow", "pvtest");
    DO_TEST("disk-drv-blktap2", "disk-drv-blktap2", "pvtest");
    DO_TEST("disk-drv-blktap2-raw", "disk-drv-blktap2-raw", "pvtest");

    DO_TEST("curmem", "curmem", "rhel5");
    DO_TEST("net-routed", "net-routed", "pvtest");
    DO_TEST("net-bridged", "net-bridged", "pvtest");
    DO_TEST("net-e1000", "net-e1000", "pvtest");
    DO_TEST("bridge-ipaddr", "bridge-ipaddr", "pvtest");
    DO_TEST("no-source-cdrom", "no-source-cdrom", "test");
    DO_TEST("pv-localtime", "pv-localtime", "pvtest");
    DO_TEST("pci-devs", "pci-devs", "pvtest");

    DO_TEST("fv-utc", "fv-utc", "fvtest");
    DO_TEST("fv-localtime", "fv-localtime", "fvtest");
    DO_TEST("fv-usbmouse", "fv-usbmouse", "fvtest");
    DO_TEST("fv-usbmouse", "fv-usbmouse", "fvtest");
    DO_TEST("fv-kernel", "fv-kernel", "fvtest");
    DO_TEST("fv-force-hpet", "fv-force-hpet", "fvtest");
    DO_TEST("fv-force-nohpet", "fv-force-nohpet", "fvtest");

    DO_TEST("fv-serial-null", "fv-serial-null", "fvtest");
    DO_TEST("fv-serial-file", "fv-serial-file", "fvtest");
    DO_TEST("fv-serial-dev-2-ports", "fv-serial-dev-2-ports", "fvtest");
    DO_TEST("fv-serial-dev-2nd-port", "fv-serial-dev-2nd-port", "fvtest");
    DO_TEST("fv-serial-stdio", "fv-serial-stdio", "fvtest");
    DO_TEST("fv-serial-pty", "fv-serial-pty", "fvtest");
    DO_TEST("fv-serial-pipe", "fv-serial-pipe", "fvtest");
    DO_TEST("fv-serial-tcp", "fv-serial-tcp", "fvtest");
    DO_TEST("fv-serial-udp", "fv-serial-udp", "fvtest");
    DO_TEST("fv-serial-tcp-telnet", "fv-serial-tcp-telnet", "fvtest");
    DO_TEST("fv-serial-unix", "fv-serial-unix", "fvtest");
    DO_TEST("fv-parallel-tcp", "fv-parallel-tcp", "fvtest");

    DO_TEST("fv-sound", "fv-sound", "fvtest");

    DO_TEST("fv-net-netfront", "fv-net-netfront", "fvtest");
    DO_TEST("fv-net-rate", "fv-net-rate", "fvtest");

    DO_TEST("boot-grub", "boot-grub", "fvtest");
    DO_TEST("escape", "escape", "fvtest");

    virObjectUnref(caps);
    virObjectUnref(xmlopt);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
