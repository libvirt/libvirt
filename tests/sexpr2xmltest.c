#include <config.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "internal.h"
#include "virxml.h"
#include "datatypes.h"
#include "xen/xen_driver.h"
#include "xen/xend_internal.h"
#include "xenxs/xen_sxpr.h"
#include "testutils.h"
#include "testutilsxen.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NONE

static virCapsPtr caps;

static int
testCompareFiles(const char *xml, const char *sexpr, int xendConfigVersion)
{
  char *xmlData = NULL;
  char *sexprData = NULL;
  char *gotxml = NULL;
  int id;
  char * tty;
  int vncport;
  int ret = -1;
  virDomainDefPtr def = NULL;
  virConnectPtr conn;
  struct _xenUnifiedPrivate priv;


  conn = virGetConnect();
  if (!conn) goto fail;

  if (virtTestLoadFile(xml, &xmlData) < 0)
      goto fail;

  if (virtTestLoadFile(sexpr, &sexprData) < 0)
      goto fail;

  memset(&priv, 0, sizeof(priv));
  /* Many puppies died to bring you this code. */
  priv.xendConfigVersion = xendConfigVersion;
  priv.caps = caps;
  conn->privateData = &priv;
  if (virMutexInit(&priv.lock) < 0)
      goto fail;

  if (xenGetDomIdFromSxprString(sexprData, xendConfigVersion, &id) < 0)
      goto fail;
  xenUnifiedLock(&priv);
  tty = xenStoreDomainGetConsolePath(conn, id);
  vncport = xenStoreDomainGetVNCPort(conn, id);
  xenUnifiedUnlock(&priv);

  if (!(def = xenParseSxprString(sexprData, xendConfigVersion, tty, vncport)))
      goto fail;

  if (!virDomainDefCheckABIStability(def, def)) {
      fprintf(stderr, "ABI stability check failed on %s", xml);
      goto fail;
  }

  if (!(gotxml = virDomainDefFormat(def, 0)))
      goto fail;

  if (STRNEQ(xmlData, gotxml)) {
      virtTestDifference(stderr, xmlData, gotxml);
      goto fail;
  }

  ret = 0;

 fail:
  VIR_FREE(xmlData);
  VIR_FREE(sexprData);
  VIR_FREE(gotxml);
  virDomainDefFree(def);
  virObjectUnref(conn);

  return ret;
}

struct testInfo {
    const char *input;
    const char *output;
    int version;
};

static int
testCompareHelper(const void *data)
{
    int result = -1;
    const struct testInfo *info = data;
    char *xml = NULL;
    char *args = NULL;

    if (virAsprintf(&xml, "%s/sexpr2xmldata/sexpr2xml-%s.xml",
                    abs_srcdir, info->input) < 0 ||
        virAsprintf(&args, "%s/sexpr2xmldata/sexpr2xml-%s.sexpr",
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

    if (!(caps = testXenCapsInit()))
        return EXIT_FAILURE;

#define DO_TEST(in, out, version)                                      \
    do {                                                               \
        struct testInfo info = { in, out, version };                   \
        virResetLastError();                                           \
        if (virtTestRun("Xen SEXPR-2-XML " in " -> " out,              \
                        testCompareHelper, &info) < 0)                 \
            ret = -1;                                                  \
    } while (0)

    DO_TEST("pv", "pv", 1);
    DO_TEST("fv", "fv", 1);
    DO_TEST("pv", "pv", 2);
    DO_TEST("fv-v2", "fv-v2", 2);
    DO_TEST("pv-vfb-orig", "pv-vfb-orig", 2);
    DO_TEST("pv-vfb-new", "pv-vfb-new", 3);
    DO_TEST("pv-vfb-new-vncdisplay", "pv-vfb-new-vncdisplay", 3);
    DO_TEST("pv-vfb-type-crash", "pv-vfb-type-crash", 3);
    DO_TEST("fv-autoport", "fv-autoport", 3);
    DO_TEST("pv-bootloader", "pv-bootloader", 1);
    DO_TEST("pv-bootloader-cmdline", "pv-bootloader-cmdline", 1);
    DO_TEST("pv-vcpus", "pv-vcpus", 1);

    DO_TEST("disk-file", "disk-file", 2);
    DO_TEST("disk-block", "disk-block", 2);
    DO_TEST("disk-block-shareable", "disk-block-shareable", 2);
    DO_TEST("disk-drv-blktap-raw", "disk-drv-blktap-raw", 2);
    DO_TEST("disk-drv-blktap-qcow", "disk-drv-blktap-qcow", 2);
    DO_TEST("disk-drv-blktap2-raw", "disk-drv-blktap2-raw", 2);

    DO_TEST("curmem", "curmem", 2);
    DO_TEST("net-routed", "net-routed", 2);
    DO_TEST("net-bridged", "net-bridged", 2);
    DO_TEST("net-e1000", "net-e1000", 2);
    DO_TEST("bridge-ipaddr", "bridge-ipaddr", 3);
    DO_TEST("no-source-cdrom", "no-source-cdrom", 2);
    DO_TEST("pv-localtime", "pv-localtime", 2);
    DO_TEST("pci-devs", "pci-devs", 2);

    DO_TEST("fv-utc", "fv-utc", 1);
    DO_TEST("fv-localtime", "fv-localtime", 1);
    DO_TEST("fv-usbmouse", "fv-usbmouse", 1);
    DO_TEST("fv-usbtablet", "fv-usbtablet", 1);
    DO_TEST("fv-kernel", "fv-kernel", 1);
    DO_TEST("fv-force-hpet", "fv-force-hpet", 1);
    DO_TEST("fv-force-nohpet", "fv-force-nohpet", 1);

    DO_TEST("fv-serial-null", "fv-serial-null", 1);
    DO_TEST("fv-serial-file", "fv-serial-file", 1);
    DO_TEST("fv-serial-dev-2-ports", "fv-serial-dev-2-ports", 1);
    DO_TEST("fv-serial-dev-2nd-port", "fv-serial-dev-2nd-port", 1);
    DO_TEST("fv-serial-stdio", "fv-serial-stdio", 1);
    DO_TEST("fv-serial-pty", "fv-serial-pty", 1);
    DO_TEST("fv-serial-pipe", "fv-serial-pipe", 1);
    DO_TEST("fv-serial-tcp", "fv-serial-tcp", 1);
    DO_TEST("fv-serial-udp", "fv-serial-udp", 1);
    DO_TEST("fv-serial-tcp-telnet", "fv-serial-tcp-telnet", 1);
    DO_TEST("fv-serial-unix", "fv-serial-unix", 1);
    DO_TEST("fv-parallel-tcp", "fv-parallel-tcp", 1);

    DO_TEST("fv-sound", "fv-sound", 1);
    DO_TEST("fv-sound-all", "fv-sound-all", 1);

    DO_TEST("fv-net-ioemu", "fv-net-ioemu", 1);
    DO_TEST("fv-net-netfront", "fv-net-netfront", 1);

    DO_TEST("fv-empty-kernel", "fv-empty-kernel", 1);

    DO_TEST("boot-grub", "boot-grub", 1);

    virObjectUnref(caps);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)
