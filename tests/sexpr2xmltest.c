#include <config.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "internal.h"
#include "virxml.h"
#include "datatypes.h"
#include "xen/xen_driver.h"
#include "xen/xend_internal.h"
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

  if (virTestLoadFile(sexpr, &sexprData) < 0)
      goto fail;

  memset(&priv, 0, sizeof(priv));
  /* Many puppies died to bring you this code. */
  priv.caps = caps;
  conn->privateData = &priv;
  if (virMutexInit(&priv.lock) < 0)
      goto fail;

  if (xenGetDomIdFromSxprString(sexprData, &id) < 0)
      goto fail;
  xenUnifiedLock(&priv);
  tty = xenStoreDomainGetConsolePath(conn, id);
  vncport = xenStoreDomainGetVNCPort(conn, id);
  xenUnifiedUnlock(&priv);

  if (!(def = xenParseSxprString(sexprData,
                                 tty, vncport, caps, xmlopt)))
      goto fail;

  if (!virDomainDefCheckABIStability(def, def, xmlopt)) {
      fprintf(stderr, "ABI stability check failed on %s", xml);
      goto fail;
  }

  if (!(gotxml = virDomainDefFormat(def, caps, 0)))
      goto fail;

  if (virTestCompareToFile(gotxml, xml) < 0)
      goto fail;

  ret = 0;

 fail:
  VIR_FREE(sexprData);
  VIR_FREE(gotxml);
  virDomainDefFree(def);
  virObjectUnref(conn);

  return ret;
}

struct testInfo {
    const char *input;
    const char *output;
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

    if (!(caps = testXenCapsInit()))
        return EXIT_FAILURE;

    if (!(xmlopt = xenDomainXMLConfInit())) {
        virObjectUnref(caps);
        return EXIT_FAILURE;
    }

#define DO_TEST(in, out)                                               \
    do {                                                               \
        struct testInfo info = { in, out };                            \
        virResetLastError();                                           \
        if (virTestRun("Xen SEXPR-2-XML " in " -> " out,               \
                       testCompareHelper, &info) < 0)                  \
            ret = -1;                                                  \
    } while (0)

    DO_TEST("pv", "pv");
    DO_TEST("fv", "fv");
    DO_TEST("pv", "pv");
    DO_TEST("fv-v2", "fv-v2");
    DO_TEST("pv-vfb-new", "pv-vfb-new");
    DO_TEST("pv-vfb-new-vncdisplay", "pv-vfb-new-vncdisplay");
    DO_TEST("pv-vfb-type-crash", "pv-vfb-type-crash");
    DO_TEST("fv-autoport", "fv-autoport");
    DO_TEST("pv-bootloader", "pv-bootloader");
    DO_TEST("pv-bootloader-cmdline", "pv-bootloader-cmdline");
    DO_TEST("pv-vcpus", "pv-vcpus");

    DO_TEST("disk-file", "disk-file");
    DO_TEST("disk-block", "disk-block");
    DO_TEST("disk-block-shareable", "disk-block-shareable");
    DO_TEST("disk-drv-blktap-raw", "disk-drv-blktap-raw");
    DO_TEST("disk-drv-blktap-qcow", "disk-drv-blktap-qcow");
    DO_TEST("disk-drv-blktap2-raw", "disk-drv-blktap2-raw");

    DO_TEST("curmem", "curmem");
    DO_TEST("net-routed", "net-routed");
    DO_TEST("net-bridged", "net-bridged");
    DO_TEST("net-e1000", "net-e1000");
    DO_TEST("bridge-ipaddr", "bridge-ipaddr");
    DO_TEST("no-source-cdrom", "no-source-cdrom");
    DO_TEST("pv-localtime", "pv-localtime");
    DO_TEST("pci-devs", "pci-devs");

    DO_TEST("fv-utc", "fv-utc");
    DO_TEST("fv-localtime", "fv-localtime");
    DO_TEST("fv-usbmouse", "fv-usbmouse");
    DO_TEST("fv-usbtablet", "fv-usbtablet");
    DO_TEST("fv-kernel", "fv-kernel");
    DO_TEST("fv-force-hpet", "fv-force-hpet");
    DO_TEST("fv-force-nohpet", "fv-force-nohpet");

    DO_TEST("fv-serial-null", "fv-serial-null");
    DO_TEST("fv-serial-file", "fv-serial-file");
    DO_TEST("fv-serial-dev-2-ports", "fv-serial-dev-2-ports");
    DO_TEST("fv-serial-dev-2nd-port", "fv-serial-dev-2nd-port");
    DO_TEST("fv-serial-stdio", "fv-serial-stdio");
    DO_TEST("fv-serial-pty", "fv-serial-pty");
    DO_TEST("fv-serial-pipe", "fv-serial-pipe");
    DO_TEST("fv-serial-tcp", "fv-serial-tcp");
    DO_TEST("fv-serial-udp", "fv-serial-udp");
    DO_TEST("fv-serial-tcp-telnet", "fv-serial-tcp-telnet");
    DO_TEST("fv-serial-unix", "fv-serial-unix");
    DO_TEST("fv-parallel-tcp", "fv-parallel-tcp");

    DO_TEST("fv-sound", "fv-sound");
    DO_TEST("fv-sound-all", "fv-sound-all");

    DO_TEST("fv-net-netfront", "fv-net-netfront");

    DO_TEST("fv-empty-kernel", "fv-empty-kernel");

    DO_TEST("boot-grub", "boot-grub");

    DO_TEST("vif-rate", "vif-rate");

    virObjectUnref(caps);
    virObjectUnref(xmlopt);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
