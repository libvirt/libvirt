
#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <fcntl.h>

#if WITH_XEN

#include "internal.h"
#include "xml.h"
#include "testutils.h"

static char *progname;
static char *abs_top_srcdir;

#define MAX_FILE 4096

static int testCompareFiles(const char *xml_rel, const char *sexpr_rel,
                            const char *name, int xendConfigVersion) {
  char xmlData[MAX_FILE];
  char sexprData[MAX_FILE];
  char *gotname = NULL;
  char *gotsexpr = NULL;
  char *xmlPtr = &(xmlData[0]);
  char *sexprPtr = &(sexprData[0]);
  int ret = -1;
  char xml[PATH_MAX];
  char sexpr[PATH_MAX];

  snprintf(xml, sizeof xml - 1, "%s/tests/%s", abs_top_srcdir, xml_rel);
  snprintf(sexpr, sizeof sexpr - 1, "%s/tests/%s", abs_top_srcdir, sexpr_rel);

  if (virtTestLoadFile(xml, &xmlPtr, MAX_FILE) < 0)
    goto fail;

  if (virtTestLoadFile(sexpr, &sexprPtr, MAX_FILE) < 0)
    goto fail;

  if (!(gotsexpr = virDomainParseXMLDesc(NULL, xmlData, &gotname, xendConfigVersion)))
    goto fail;

  if (strcmp(sexprData, gotsexpr)) {
      if (getenv("DEBUG_TESTS")) {
	printf("Expect %d '%s'\n", (int)strlen(sexprData), sexprData);
	printf("Actual %d '%s'\n", (int)strlen(gotsexpr), gotsexpr);
      }
      goto fail;
  }

  if (strcmp(name, gotname)) {
      printf("Got wrong name: expected %s, got %s\n", name, gotname);
      goto fail;
  }

  ret = 0;

 fail:

  free(gotname);
  free(gotsexpr);

  return ret;
}

static int testComparePVversion1(const void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("xml2sexprdata/xml2sexpr-pv.xml",
			  "xml2sexprdata/xml2sexpr-pv.sexpr",
			  "pvtest",
			  1);
}

static int testCompareFVversion1(const void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("xml2sexprdata/xml2sexpr-fv.xml",
			  "xml2sexprdata/xml2sexpr-fv.sexpr",
			  "fvtest",
			  1);
}

static int testComparePVversion2(const void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("xml2sexprdata/xml2sexpr-pv.xml",
			  "xml2sexprdata/xml2sexpr-pv.sexpr",
			  "pvtest",
			  2);
}

static int testCompareFVversion2(const void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("xml2sexprdata/xml2sexpr-fv.xml",
			  "xml2sexprdata/xml2sexpr-fv-v2.sexpr",
			  "fvtest",
			  2);
}

static int testCompareFVversion2VNC(const void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("xml2sexprdata/xml2sexpr-fv-vncunused.xml",
			  "xml2sexprdata/xml2sexpr-fv-vncunused.sexpr",
			  "fvtest",
			  2);
}

static int testComparePVOrigVFB(const void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("xml2sexprdata/xml2sexpr-pv-vfb-orig.xml",
                          "xml2sexprdata/xml2sexpr-pv-vfb-orig.sexpr",
			  "pvtest",
                          2);
}


static int testComparePVNewVFB(const void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("xml2sexprdata/xml2sexpr-pv-vfb-new.xml",
                          "xml2sexprdata/xml2sexpr-pv-vfb-new.sexpr",
			  "pvtest",
                          3);
}

static int testComparePVBootloader(const void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("xml2sexprdata/xml2sexpr-pv-bootloader.xml",
			  "xml2sexprdata/xml2sexpr-pv-bootloader.sexpr",
			  "pvtest",
			  1);
}

static int testCompareDiskFile(const void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("xml2sexprdata/xml2sexpr-disk-file.xml",
			  "xml2sexprdata/xml2sexpr-disk-file.sexpr",
			  "pvtest",
			  2);
}

static int testCompareDiskBlock(const void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("xml2sexprdata/xml2sexpr-disk-block.xml",
			  "xml2sexprdata/xml2sexpr-disk-block.sexpr",
			  "pvtest",
			  2);
}

static int testCompareDiskShareable(const void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("xml2sexprdata/xml2sexpr-disk-block-shareable.xml",
			  "xml2sexprdata/xml2sexpr-disk-block-shareable.sexpr",
			  "pvtest",
			  2);
}

static int testCompareDiskDrvLoop(const void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("xml2sexprdata/xml2sexpr-disk-drv-loop.xml",
			  "xml2sexprdata/xml2sexpr-disk-drv-loop.sexpr",
			  "pvtest",
			  2);
}

static int testCompareDiskDrvBlkback(const void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("xml2sexprdata/xml2sexpr-disk-drv-blkback.xml",
			  "xml2sexprdata/xml2sexpr-disk-drv-blkback.sexpr",
			  "pvtest",
			  2);
}

static int testCompareDiskDrvBlktap(const void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("xml2sexprdata/xml2sexpr-disk-drv-blktap.xml",
			  "xml2sexprdata/xml2sexpr-disk-drv-blktap.sexpr",
			  "pvtest",
			  2);
}

static int testCompareDiskDrvBlktapQcow(const void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("xml2sexprdata/xml2sexpr-disk-drv-blktap-qcow.xml",
			  "xml2sexprdata/xml2sexpr-disk-drv-blktap-qcow.sexpr",
			  "pvtest",
			  2);
}

static int testCompareDiskDrvBlktapRaw(const void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("xml2sexprdata/xml2sexpr-disk-drv-blktap-raw.xml",
			  "xml2sexprdata/xml2sexpr-disk-drv-blktap-raw.sexpr",
			  "pvtest",
			  2);
}

static int testCompareMemoryResize(const void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("xml2sexprdata/xml2sexpr-curmem.xml",
			  "xml2sexprdata/xml2sexpr-curmem.sexpr",
			  "rhel5",
			  2);
}

static int testCompareNetRouted(const void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("xml2sexprdata/xml2sexpr-net-routed.xml",
			  "xml2sexprdata/xml2sexpr-net-routed.sexpr",
			  "pvtest",
			  2);
}

static int testCompareNetBridged(const void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("xml2sexprdata/xml2sexpr-net-bridged.xml",
			  "xml2sexprdata/xml2sexpr-net-bridged.sexpr",
			  "pvtest",
			  2);
}

static int testCompareNoSourceCDRom(const void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("xml2sexprdata/xml2sexpr-no-source-cdrom.xml",
			  "xml2sexprdata/xml2sexpr-no-source-cdrom.sexpr",
			  "test",
			  2);
}

static int testCompareFVclockUTC(const void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("xml2sexprdata/xml2sexpr-fv-utc.xml",
			  "xml2sexprdata/xml2sexpr-fv-utc.sexpr",
			  "fvtest",
			  1);
}

static int testCompareFVclockLocaltime(const void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("xml2sexprdata/xml2sexpr-fv-localtime.xml",
			  "xml2sexprdata/xml2sexpr-fv-localtime.sexpr",
			  "fvtest",
			  1);
}


static int testCompareFVInputUSBMouse(const void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("xml2sexprdata/xml2sexpr-fv-usbmouse.xml",
			  "xml2sexprdata/xml2sexpr-fv-usbmouse.sexpr",
			  "fvtest",
			  1);
}

static int testCompareFVInputUSBTablet(const void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("xml2sexprdata/xml2sexpr-fv-usbtablet.xml",
			  "xml2sexprdata/xml2sexpr-fv-usbtablet.sexpr",
			  "fvtest",
			  1);
}

static int testCompareFVKernel(const void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("xml2sexprdata/xml2sexpr-fv-kernel.xml",
			  "xml2sexprdata/xml2sexpr-fv-kernel.sexpr",
			  "fvtest",
			  1);
}



int
main(int argc, char **argv)
{
    int ret = 0;

    progname = argv[0];

    abs_top_srcdir = getenv("abs_top_srcdir");
    if (!abs_top_srcdir) {
        fprintf(stderr, "missing enviroment variable abs_top_srcdir\n");
	exit(EXIT_FAILURE);
    }


    if (argc > 1) {
	fprintf(stderr, "Usage: %s\n", progname);
	exit(EXIT_FAILURE);
    }

    if (virtTestRun("XML-2-SEXPR PV config (format 1)",
		    1, testComparePVversion1, NULL) != 0)
	ret = -1;

    if (virtTestRun("XML-2-SEXPR FV config (format 1)",
		    1, testCompareFVversion1, NULL) != 0)
	ret = -1;

    if (virtTestRun("XML-2-SEXPR PV config (format 2)",
		    1, testComparePVversion2, NULL) != 0)
	ret = -1;

    if (virtTestRun("XML-2-SEXPR FV config (format 2)",
		    1, testCompareFVversion2, NULL) != 0)
	ret = -1;

    if (virtTestRun("XML-2-SEXPR FV config (format 2, VNC unused)",
		    1, testCompareFVversion2VNC, NULL) != 0)
	ret = -1;

    if (virtTestRun("XML-2-SEXPR PV config (Orig VFB)",
                    1, testComparePVOrigVFB, NULL) != 0)
        ret = -1;

    if (virtTestRun("XML-2-SEXPR PV config (New VFB)",
                    1, testComparePVNewVFB, NULL) != 0)
        ret = -1;

    if (virtTestRun("XML-2-SEXPR PV config with bootloader",
		    1, testComparePVBootloader, NULL) != 0)
	ret = -1;

    if (virtTestRun("XML-2-SEXPR Disk File",
		    1, testCompareDiskFile, NULL) != 0)
	ret = -1;

    if (virtTestRun("XML-2-SEXPR Disk Block",
		    1, testCompareDiskBlock, NULL) != 0)
	ret = -1;

    if (virtTestRun("XML-2-SEXPR Disk Shareable",
		    1, testCompareDiskShareable, NULL) != 0)
	ret = -1;

    if (virtTestRun("XML-2-SEXPR Disk Drv Loop",
		    1, testCompareDiskDrvLoop, NULL) != 0)
	ret = -1;

    if (virtTestRun("XML-2-SEXPR Disk Drv Blkback",
		    1, testCompareDiskDrvBlkback, NULL) != 0)
	ret = -1;

    if (virtTestRun("XML-2-SEXPR Disk Drv Blktap",
		    1, testCompareDiskDrvBlktap, NULL) != 0)
	ret = -1;

    if (virtTestRun("XML-2-SEXPR Disk Drv Blktap QCow",
		    1, testCompareDiskDrvBlktapQcow, NULL) != 0)
	ret = -1;

    if (virtTestRun("XML-2-SEXPR Disk Drv Blktap Raw",
		    1, testCompareDiskDrvBlktapRaw, NULL) != 0)
	ret = -1;

    if (virtTestRun("XML-2-SEXPR Memory Resize",
		    1, testCompareMemoryResize, NULL) != 0)
	ret = -1;

    if (virtTestRun("XML-2-SEXPR Net Routed",
		    1, testCompareNetRouted, NULL) != 0)
	ret = -1;

    if (virtTestRun("XML-2-SEXPR Net Bridged",
		    1, testCompareNetBridged, NULL) != 0)
	ret = -1;

    if (virtTestRun("XML-2-SEXPR No Source CDRom",
		    1, testCompareNoSourceCDRom, NULL) != 0)
	ret = -1;

    if (virtTestRun("XML-2-SEXPR FV usb mouse)",
		    1, testCompareFVInputUSBMouse, NULL) != 0)
	ret = -1;
    if (virtTestRun("XML-2-SEXPR FV usb tablet)",
		    1, testCompareFVInputUSBTablet, NULL) != 0)
	ret = -1;

    if (virtTestRun("XML-2-SEXPR clock UTC",
		    1, testCompareFVclockUTC, NULL) != 0)
	ret = -1;

    if (virtTestRun("XML-2-SEXPR clock Localtime",
		    1, testCompareFVclockLocaltime, NULL) != 0)
	ret = -1;

    if (virtTestRun("XML-2-SEXPR FV kernel",
		    1, testCompareFVKernel, NULL) != 0)
	ret = -1;

    exit(ret==0 ? EXIT_SUCCESS : EXIT_FAILURE);
}

#else /* WITH_XEN */

int main (void) { exit (77); /* means 'test skipped' for automake */ }

#endif /* ! WITH_XEN */
