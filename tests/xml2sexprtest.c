
#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

#include "internal.h"
#include "xen/xend_internal.h"
#include "xenxs/xen_sxpr.h"
#include "testutils.h"
#include "testutilsxen.h"

static virCapsPtr caps;

static int
testCompareFiles(const char *xml, const char *sexpr, int xendConfigVersion)
{
  char *xmlData = NULL;
  char *sexprData = NULL;
  char *gotsexpr = NULL;
  int ret = -1;
  virDomainDefPtr def = NULL;

  if (virtTestLoadFile(xml, &xmlData) < 0)
      goto fail;

  if (virtTestLoadFile(sexpr, &sexprData) < 0)
      goto fail;

  if (!(def = virDomainDefParseString(caps, xmlData, 1 << VIR_DOMAIN_VIRT_XEN,
                                      VIR_DOMAIN_XML_INACTIVE)))
      goto fail;

  if (!(gotsexpr = xenFormatSxpr(NULL, def, xendConfigVersion)))
      goto fail;

  if (STRNEQ(sexprData, gotsexpr)) {
      virtTestDifference(stderr, sexprData, gotsexpr);
      goto fail;
  }

  ret = 0;

 fail:
  VIR_FREE(xmlData);
  VIR_FREE(sexprData);
  VIR_FREE(gotsexpr);
  virDomainDefFree(def);

  return ret;
}

struct testInfo {
    const char *input;
    const char *output;
    const char *name;
    int version;
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

    result = testCompareFiles(xml, args, info->version);

cleanup:
    VIR_FREE(xml);
    VIR_FREE(args);

    return result;
}

static int
mymain(void)
{
    int ret = 0;

#define DO_TEST(in, out, name, version)                                \
    do {                                                               \
        struct testInfo info = { in, out, name, version };             \
        virResetLastError();                                           \
        if (virtTestRun("Xen XML-2-SEXPR " in " -> " out,              \
                        1, testCompareHelper, &info) < 0)     \
            ret = -1;                                                  \
    } while (0)

    if (!(caps = testXenCapsInit()))
        return EXIT_FAILURE;

    DO_TEST("pv", "pv", "pvtest", 1);
    DO_TEST("fv", "fv", "fvtest", 1);
    DO_TEST("pv", "pv", "pvtest", 2);
    DO_TEST("fv", "fv-v2", "fvtest", 2);
    DO_TEST("fv-vncunused", "fv-vncunused", "fvtest", 2);
#ifdef WITH_RHEL5_API
    /* RHEL-5 Xen doesn't support the old style vnc configuration */
    DO_TEST("pv-vfb-orig", "pv-vfb-new", "pvtest", 2);
#else
    DO_TEST("pv-vfb-orig", "pv-vfb-orig", "pvtest", 2);
#endif
    DO_TEST("pv-vfb-new", "pv-vfb-new", "pvtest", 3);
    DO_TEST("pv-vfb-new-auto", "pv-vfb-new-auto", "pvtest", 3);
    DO_TEST("pv-bootloader", "pv-bootloader", "pvtest", 1);
    DO_TEST("pv-bootloader-cmdline", "pv-bootloader-cmdline", "pvtest", 1);
    DO_TEST("pv-vcpus", "pv-vcpus", "pvtest", 1);

    DO_TEST("disk-file", "disk-file", "pvtest", 2);
    DO_TEST("disk-block", "disk-block", "pvtest", 2);
    DO_TEST("disk-block-shareable", "disk-block-shareable", "pvtest", 2);
    DO_TEST("disk-drv-loop", "disk-drv-loop", "pvtest", 2);
    DO_TEST("disk-drv-blkback", "disk-drv-blkback", "pvtest", 2);
    DO_TEST("disk-drv-blktap", "disk-drv-blktap", "pvtest", 2);
    DO_TEST("disk-drv-blktap-raw", "disk-drv-blktap-raw", "pvtest", 2);
    DO_TEST("disk-drv-blktap-qcow", "disk-drv-blktap-qcow", "pvtest", 2);
    DO_TEST("disk-drv-blktap2", "disk-drv-blktap2", "pvtest", 2);
    DO_TEST("disk-drv-blktap2-raw", "disk-drv-blktap2-raw", "pvtest", 2);

    DO_TEST("curmem", "curmem", "rhel5", 2);
    DO_TEST("net-routed", "net-routed", "pvtest", 2);
    DO_TEST("net-bridged", "net-bridged", "pvtest", 2);
    DO_TEST("net-e1000", "net-e1000", "pvtest", 2);
    DO_TEST("bridge-ipaddr", "bridge-ipaddr", "pvtest", 2);
    DO_TEST("no-source-cdrom", "no-source-cdrom", "test", 2);
    DO_TEST("pv-localtime", "pv-localtime", "pvtest", 1);
    DO_TEST("pci-devs", "pci-devs", "pvtest", 2);

    DO_TEST("fv-utc", "fv-utc", "fvtest", 1);
    DO_TEST("fv-localtime", "fv-localtime", "fvtest", 1);
    DO_TEST("fv-usbmouse", "fv-usbmouse", "fvtest", 1);
    DO_TEST("fv-usbmouse", "fv-usbmouse", "fvtest", 1);
    DO_TEST("fv-kernel", "fv-kernel", "fvtest", 1);
    DO_TEST("fv-force-hpet", "fv-force-hpet", "fvtest", 1);
    DO_TEST("fv-force-nohpet", "fv-force-nohpet", "fvtest", 1);

    DO_TEST("fv-serial-null", "fv-serial-null", "fvtest", 1);
    DO_TEST("fv-serial-file", "fv-serial-file", "fvtest", 1);
    DO_TEST("fv-serial-dev-2-ports", "fv-serial-dev-2-ports", "fvtest", 1);
    DO_TEST("fv-serial-dev-2nd-port", "fv-serial-dev-2nd-port", "fvtest", 1);
    DO_TEST("fv-serial-stdio", "fv-serial-stdio", "fvtest", 1);
    DO_TEST("fv-serial-pty", "fv-serial-pty", "fvtest", 1);
    DO_TEST("fv-serial-pipe", "fv-serial-pipe", "fvtest", 1);
    DO_TEST("fv-serial-tcp", "fv-serial-tcp", "fvtest", 1);
    DO_TEST("fv-serial-udp", "fv-serial-udp", "fvtest", 1);
    DO_TEST("fv-serial-tcp-telnet", "fv-serial-tcp-telnet", "fvtest", 1);
    DO_TEST("fv-serial-unix", "fv-serial-unix", "fvtest", 1);
    DO_TEST("fv-parallel-tcp", "fv-parallel-tcp", "fvtest", 1);

    DO_TEST("fv-sound", "fv-sound", "fvtest", 1);

    DO_TEST("fv-net-ioemu", "fv-net-ioemu", "fvtest", 1);
    DO_TEST("fv-net-netfront", "fv-net-netfront", "fvtest", 1);

    DO_TEST("boot-grub", "boot-grub", "fvtest", 1);
    DO_TEST("escape", "escape", "fvtest", 1);

    virCapabilitiesFree(caps);

    return ret==0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)
