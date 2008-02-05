#include <config.h>

#include <stdio.h>
#include <string.h>

#ifdef WITH_XEN

#include "internal.h"
#include "xml.h"
#include "xend_internal.h"
#include "testutils.h"

static char *progname;
static char *abs_top_srcdir;

#define MAX_FILE 4096

static int testCompareFiles(const char *xml_rel, const char *sexpr_rel,
                            int xendConfigVersion) {
  char xmlData[MAX_FILE];
  char sexprData[MAX_FILE];
  char *gotxml = NULL;
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

  if (!(gotxml = xend_parse_domain_sexp(NULL, sexprData, xendConfigVersion)))
    goto fail;

  if (strcmp(xmlData, gotxml)) {
    if (getenv("DEBUG_TESTS")) {
        printf("In test file %s -> %s:\n", sexpr, xml);
        printf("Expect %d '%s'\n", (int)strlen(xmlData), xmlData);
        printf("Actual %d '%s'\n", (int)strlen(gotxml), gotxml);
    }
    goto fail;
  }

  ret = 0;

 fail:
  free(gotxml);

  return ret;
}

static int testComparePVversion1(const void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("sexpr2xmldata/sexpr2xml-pv.xml",
			  "sexpr2xmldata/sexpr2xml-pv.sexpr",
			  1);
}

static int testCompareFVversion1(const void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("sexpr2xmldata/sexpr2xml-fv.xml",
			  "sexpr2xmldata/sexpr2xml-fv.sexpr",
			  1);
}

static int testComparePVversion2(const void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("sexpr2xmldata/sexpr2xml-pv.xml",
			  "sexpr2xmldata/sexpr2xml-pv.sexpr",
			  2);
}

static int testComparePVOrigVFB(const void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("sexpr2xmldata/sexpr2xml-pv-vfb-orig.xml",
                          "sexpr2xmldata/sexpr2xml-pv-vfb-orig.sexpr",
                          2);
}


static int testComparePVNewVFB(const void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("sexpr2xmldata/sexpr2xml-pv-vfb-new.xml",
                          "sexpr2xmldata/sexpr2xml-pv-vfb-new.sexpr",
                          3);
}


static int testCompareFVversion2(const void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("sexpr2xmldata/sexpr2xml-fv-v2.xml",
			  "sexpr2xmldata/sexpr2xml-fv-v2.sexpr",
			  2);
}

static int testComparePVBootloader(const void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("sexpr2xmldata/sexpr2xml-pv-bootloader.xml",
			  "sexpr2xmldata/sexpr2xml-pv-bootloader.sexpr",
			  2);
}

static int testCompareDiskFile(const void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("sexpr2xmldata/sexpr2xml-disk-file.xml",
			  "sexpr2xmldata/sexpr2xml-disk-file.sexpr",
			  1);
}

static int testCompareDiskBlock(const void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("sexpr2xmldata/sexpr2xml-disk-block.xml",
			  "sexpr2xmldata/sexpr2xml-disk-block.sexpr",
			  1);
}

static int testCompareDiskShareable(const void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("sexpr2xmldata/sexpr2xml-disk-block-shareable.xml",
			  "sexpr2xmldata/sexpr2xml-disk-block-shareable.sexpr",
			  1);
}

static int testCompareDiskDrvBlktapQcow(const void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("sexpr2xmldata/sexpr2xml-disk-drv-blktap-qcow.xml",
			  "sexpr2xmldata/sexpr2xml-disk-drv-blktap-qcow.sexpr",
			  1);
}

static int testCompareDiskDrvBlktapRaw(const void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("sexpr2xmldata/sexpr2xml-disk-drv-blktap-raw.xml",
			  "sexpr2xmldata/sexpr2xml-disk-drv-blktap-raw.sexpr",
			  1);
}

static int testCompareResizedMemory(const void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("sexpr2xmldata/sexpr2xml-curmem.xml",
			  "sexpr2xmldata/sexpr2xml-curmem.sexpr",
			  1);
}


static int testCompareNetRouted(const void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("sexpr2xmldata/sexpr2xml-net-routed.xml",
			  "sexpr2xmldata/sexpr2xml-net-routed.sexpr",
			  1);
}

static int testCompareNetBridged(const void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("sexpr2xmldata/sexpr2xml-net-bridged.xml",
			  "sexpr2xmldata/sexpr2xml-net-bridged.sexpr",
			  1);
}

static int testCompareNoSourceCDRom(const void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("sexpr2xmldata/sexpr2xml-no-source-cdrom.xml",
			  "sexpr2xmldata/sexpr2xml-no-source-cdrom.sexpr",
			  1);
}

static int testCompareFVInputUSBMouse(const void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("sexpr2xmldata/sexpr2xml-fv-usbmouse.xml",
			  "sexpr2xmldata/sexpr2xml-fv-usbmouse.sexpr",
			  1);
}

static int testCompareFVInputUSBTablet(const void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("sexpr2xmldata/sexpr2xml-fv-usbtablet.xml",
			  "sexpr2xmldata/sexpr2xml-fv-usbtablet.sexpr",
			  1);
}

static int testCompareFVclockUTC(const void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("sexpr2xmldata/sexpr2xml-fv-utc.xml",
			  "sexpr2xmldata/sexpr2xml-fv-utc.sexpr",
			  1);
}

static int testCompareFVclockLocaltime(const void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("sexpr2xmldata/sexpr2xml-fv-localtime.xml",
			  "sexpr2xmldata/sexpr2xml-fv-localtime.sexpr",
			  1);
}

static int testCompareFVKernel(const void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("sexpr2xmldata/sexpr2xml-fv-kernel.xml",
			  "sexpr2xmldata/sexpr2xml-fv-kernel.sexpr",
			  1);
}

static int testCompareFVLegacyVFB(const void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("sexpr2xmldata/sexpr2xml-fv-legacy-vfb.xml",
			  "sexpr2xmldata/sexpr2xml-fv-legacy-vfb.sexpr",
			  4);
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
    if (!abs_top_srcdir) {
        fprintf(stderr, "missing enviroment variable abs_top_srcdir\n");
	exit(EXIT_FAILURE);
    }

    if (virtTestRun("SEXPR-2-XML PV config (version 1)",
		    1, testComparePVversion1, NULL) != 0)
	ret = -1;

    if (virtTestRun("SEXPR-2-XML FV config (version 1)",
		    1, testCompareFVversion1, NULL) != 0)
	ret = -1;

    if (virtTestRun("SEXPR-2-XML PV config (version 2)",
		    1, testComparePVversion2, NULL) != 0)
	ret = -1;

    if (virtTestRun("SEXPR-2-XML PV config (Orig VFB)",
                    1, testComparePVOrigVFB, NULL) != 0)
        ret = -1;

    if (virtTestRun("SEXPR-2-XML PV config (New VFB)",
                    1, testComparePVNewVFB, NULL) != 0)
        ret = -1;

    if (virtTestRun("SEXPR-2-XML FV config (version 2)",
		    1, testCompareFVversion2, NULL) != 0)
	ret = -1;

    if (virtTestRun("SEXPR-2-XML PV config bootloader",
		    1, testComparePVBootloader, NULL) != 0)
	ret = -1;

    if (virtTestRun("SEXPR-2-XML Disk File config",
		    1, testCompareDiskFile, NULL) != 0)
	ret = -1;

    if (virtTestRun("SEXPR-2-XML Disk Block config",
		    1, testCompareDiskBlock, NULL) != 0)
	ret = -1;

    if (virtTestRun("SEXPR-2-XML Disk Block shareable",
		    1, testCompareDiskShareable, NULL) != 0)
	ret = -1;

    if (virtTestRun("SEXPR-2-XML Disk Driver blktap qcow config",
		    1, testCompareDiskDrvBlktapQcow, NULL) != 0)
	ret = -1;

    if (virtTestRun("SEXPR-2-XML Disk Driver blktap raw config",
		    1, testCompareDiskDrvBlktapRaw, NULL) != 0)
	ret = -1;

    if (virtTestRun("SEXPR-2-XML Resized memory config",
		    1, testCompareResizedMemory, NULL) != 0)
	ret = -1;

    if (virtTestRun("SEXPR-2-XML net routed",
		    1, testCompareNetRouted, NULL) != 0)
	ret = -1;

    if (virtTestRun("SEXPR-2-XML net bridged",
		    1, testCompareNetBridged, NULL) != 0)
	ret = -1;

    if (virtTestRun("SEXPR-2-XML no source CDRom",
		    1, testCompareNoSourceCDRom, NULL) != 0)
	ret = -1;

    if (virtTestRun("SEXPR-2-XML USB Mouse",
		    1, testCompareFVInputUSBMouse, NULL) != 0)
	ret = -1;
    if (virtTestRun("SEXPR-2-XML USB Tablet",
		    1, testCompareFVInputUSBTablet, NULL) != 0)
	ret = -1;

    if (virtTestRun("SEXPR-2-XML clock UTC",
		    1, testCompareFVclockUTC, NULL) != 0)
	ret = -1;

    if (virtTestRun("SEXPR-2-XML clock Localtime",
		    1, testCompareFVclockLocaltime, NULL) != 0)
	ret = -1;

    if (virtTestRun("SEXPR-2-XML FV kernel",
		    1, testCompareFVKernel, NULL) != 0)
	ret = -1;

    if (virtTestRun("SEXPR-2-XML FV legacy VFB",
		    1, testCompareFVLegacyVFB, NULL) != 0)
	ret = -1;

    exit(ret==0 ? EXIT_SUCCESS : EXIT_FAILURE);
}
#else /* WITHOUT_XEN */
int
main(void)
{
    fprintf(stderr, "libvirt compiled without Xen support\n");
    return(0);
}
#endif /* WITH_XEN */
/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
