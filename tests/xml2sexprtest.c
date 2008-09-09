
#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

#if WITH_XEN

#include "internal.h"
#include "xend_internal.h"
#include "testutils.h"
#include "testutilsxen.h"

static char *progname;
static char *abs_srcdir;
static virCapsPtr caps;

#define MAX_FILE 4096

static int testCompareFiles(const char *xml, const char *sexpr,
                            int xendConfigVersion) {
  char xmlData[MAX_FILE];
  char sexprData[MAX_FILE];
  char *gotsexpr = NULL;
  char *xmlPtr = &(xmlData[0]);
  char *sexprPtr = &(sexprData[0]);
  int ret = -1;
  virDomainDefPtr def = NULL;

  if (virtTestLoadFile(xml, &xmlPtr, MAX_FILE) < 0)
      goto fail;

  if (virtTestLoadFile(sexpr, &sexprPtr, MAX_FILE) < 0)
      goto fail;

  if (!(def = virDomainDefParseString(NULL, caps, xmlData)))
      goto fail;

  if (!(gotsexpr = xenDaemonFormatSxpr(NULL, def, xendConfigVersion)))
      goto fail;

  if (STRNEQ(sexprData, gotsexpr)) {
      virtTestDifference(stderr, sexprData, gotsexpr);
      goto fail;
  }

  ret = 0;

 fail:
  virDomainDefFree(def);
  free(gotsexpr);

  return ret;
}

struct testInfo {
    const char *input;
    const char *output;
    const char *name;
    int version;
};

static int testCompareHelper(const void *data) {
    const struct testInfo *info = data;
    char xml[PATH_MAX];
    char args[PATH_MAX];
    snprintf(xml, PATH_MAX, "%s/xml2sexprdata/xml2sexpr-%s.xml",
             abs_srcdir, info->input);
    snprintf(args, PATH_MAX, "%s/xml2sexprdata/xml2sexpr-%s.sexpr",
             abs_srcdir, info->output);
    return testCompareFiles(xml, args, info->version);
}


static int
mymain(int argc, char **argv)
{
    int ret = 0;
    char cwd[PATH_MAX];

    progname = argv[0];

    abs_srcdir = getenv("abs_srcdir");
    if (!abs_srcdir)
        abs_srcdir = getcwd(cwd, sizeof(cwd));

    if (argc > 1) {
        fprintf(stderr, "Usage: %s\n", progname);
        return(EXIT_FAILURE);
    }

#define DO_TEST(in, out, name, version)                                \
    do {                                                               \
        struct testInfo info = { in, out, name, version };             \
        if (virtTestRun("Xen XML-2-SEXPR " in " -> " out,              \
                        1, testCompareHelper, &info) < 0)     \
            ret = -1;                                                  \
    } while (0)

    if (!(caps = testXenCapsInit()))
        return(EXIT_FAILURE);

    DO_TEST("pv", "pv", "pvtest", 1);
    DO_TEST("fv", "fv", "fvtest", 1);
    DO_TEST("pv", "pv", "pvtest", 2);
    DO_TEST("fv", "fv-v2", "fvtest", 2);
    DO_TEST("fv-vncunused", "fv-vncunused", "fvtest", 2);
    DO_TEST("pv-vfb-orig", "pv-vfb-orig", "pvtest", 2);
    DO_TEST("pv-vfb-new", "pv-vfb-new", "pvtest", 3);
    DO_TEST("pv-vfb-new-auto", "pv-vfb-new-auto", "pvtest", 3);
    DO_TEST("pv-bootloader", "pv-bootloader", "pvtest", 1);

    DO_TEST("disk-file", "disk-file", "pvtest", 2);
    DO_TEST("disk-block", "disk-block", "pvtest", 2);
    DO_TEST("disk-block-shareable", "disk-block-shareable", "pvtest", 2);
    DO_TEST("disk-drv-loop", "disk-drv-loop", "pvtest", 2);
    DO_TEST("disk-drv-blkback", "disk-drv-blkback", "pvtest", 2);
    DO_TEST("disk-drv-blktap", "disk-drv-blktap", "pvtest", 2);
    DO_TEST("disk-drv-blktap-raw", "disk-drv-blktap-raw", "pvtest", 2);
    DO_TEST("disk-drv-blktap-qcow", "disk-drv-blktap-qcow", "pvtest", 2);

    DO_TEST("curmem", "curmem", "rhel5", 2);
    DO_TEST("net-routed", "net-routed", "pvtest", 2);
    DO_TEST("net-bridged", "net-bridged", "pvtest", 2);
    DO_TEST("net-e1000", "net-e1000", "pvtest", 2);
    DO_TEST("no-source-cdrom", "no-source-cdrom", "test", 2);

    DO_TEST("fv-utc", "fv-utc", "fvtest", 1);
    DO_TEST("fv-localtime", "fv-localtime", "fvtest", 1);
    DO_TEST("fv-usbmouse", "fv-usbmouse", "fvtest", 1);
    DO_TEST("fv-usbmouse", "fv-usbmouse", "fvtest", 1);
    DO_TEST("fv-kernel", "fv-kernel", "fvtest", 1);

    DO_TEST("fv-serial-null", "fv-serial-null", "fvtest", 1);
    DO_TEST("fv-serial-file", "fv-serial-file", "fvtest", 1);
    DO_TEST("fv-serial-stdio", "fv-serial-stdio", "fvtest", 1);
    DO_TEST("fv-serial-pty", "fv-serial-pty", "fvtest", 1);
    DO_TEST("fv-serial-pipe", "fv-serial-pipe", "fvtest", 1);
    DO_TEST("fv-serial-tcp", "fv-serial-tcp", "fvtest", 1);
    DO_TEST("fv-serial-udp", "fv-serial-udp", "fvtest", 1);
    DO_TEST("fv-serial-tcp-telnet", "fv-serial-tcp-telnet", "fvtest", 1);
    DO_TEST("fv-serial-unix", "fv-serial-unix", "fvtest", 1);
    DO_TEST("fv-parallel-tcp", "fv-parallel-tcp", "fvtest", 1);

    DO_TEST("fv-sound", "fv-sound", "fvtest", 1);

    virCapabilitiesFree(caps);

    return(ret==0 ? EXIT_SUCCESS : EXIT_FAILURE);
}

VIRT_TEST_MAIN(mymain)

#else /* WITH_XEN */

int main (void) { exit (77); /* means 'test skipped' for automake */ }

#endif /* ! WITH_XEN */
