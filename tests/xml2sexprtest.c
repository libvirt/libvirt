#include <stdio.h>
#include <string.h>

#include "xml.h"
#include "testutils.h"
#include "internal.h"

static char *progname;

#define MAX_FILE 4096

static int testCompareFiles(const char *xml, const char *sexpr, const char *name, int xendConfigVersion) {
  char xmlData[MAX_FILE];
  char sexprData[MAX_FILE];
  char *gotname = NULL;
  char *gotsexpr = NULL;
  char *xmlPtr = &(xmlData[0]);
  char *sexprPtr = &(sexprData[0]);
  int ret = -1;

  if (virtTestLoadFile(xml, &xmlPtr, MAX_FILE) < 0)
    goto fail;

  if (virtTestLoadFile(sexpr, &sexprPtr, MAX_FILE) < 0)
    goto fail;

  if (!(gotsexpr = virDomainParseXMLDesc(xmlData, &gotname, xendConfigVersion)))
    goto fail;

  if (getenv("DEBUG_TESTS")) {
      printf("Expect %d '%s'\n", (int)strlen(sexprData), sexprData);
      printf("Actual %d '%s'\n", (int)strlen(gotsexpr), gotsexpr);
  }
  if (strcmp(sexprData, gotsexpr))
    goto fail;

  if (strcmp(name, gotname))
    goto fail;

  ret = 0;

 fail:

  free(gotname);
  free(gotsexpr);

  return ret;
}

static int testComparePVversion1(void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("xml2sexprdata/xml2sexpr-pv.xml",
			  "xml2sexprdata/xml2sexpr-pv.sexpr",
			  "pvtest",
			  1);
}

static int testCompareFVversion1(void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("xml2sexprdata/xml2sexpr-fv.xml",
			  "xml2sexprdata/xml2sexpr-fv.sexpr",
			  "fvtest",
			  1);
}

static int testComparePVversion2(void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("xml2sexprdata/xml2sexpr-pv.xml",
			  "xml2sexprdata/xml2sexpr-pv.sexpr",
			  "pvtest",
			  2);
}

static int testCompareFVversion2(void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("xml2sexprdata/xml2sexpr-fv.xml",
			  "xml2sexprdata/xml2sexpr-fv-v2.sexpr",
			  "fvtest",
			  2);
}

static int testCompareFVversion2VNC(void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("xml2sexprdata/xml2sexpr-fv-vncunused.xml",
			  "xml2sexprdata/xml2sexpr-fv-vncunused.sexpr",
			  "fvtest",
			  2);
}

static int testCompareDiskFile(void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("xml2sexprdata/xml2sexpr-disk-file.xml",
			  "xml2sexprdata/xml2sexpr-disk-file.sexpr",
			  "pvtest",
			  2);
}

static int testCompareDiskBlock(void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("xml2sexprdata/xml2sexpr-disk-block.xml",
			  "xml2sexprdata/xml2sexpr-disk-block.sexpr",
			  "pvtest",
			  2);
}

static int testCompareDiskDrvLoop(void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("xml2sexprdata/xml2sexpr-disk-drv-loop.xml",
			  "xml2sexprdata/xml2sexpr-disk-drv-loop.sexpr",
			  "pvtest",
			  2);
}

static int testCompareDiskDrvBlkback(void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("xml2sexprdata/xml2sexpr-disk-drv-blkback.xml",
			  "xml2sexprdata/xml2sexpr-disk-drv-blkback.sexpr",
			  "pvtest",
			  2);
}

static int testCompareDiskDrvBlktap(void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("xml2sexprdata/xml2sexpr-disk-drv-blktap.xml",
			  "xml2sexprdata/xml2sexpr-disk-drv-blktap.sexpr",
			  "pvtest",
			  2);
}

static int testCompareDiskDrvBlktapQcow(void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("xml2sexprdata/xml2sexpr-disk-drv-blktap-qcow.xml",
			  "xml2sexprdata/xml2sexpr-disk-drv-blktap-qcow.sexpr",
			  "pvtest",
			  2);
}

static int testCompareDiskDrvBlktapRaw(void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("xml2sexprdata/xml2sexpr-disk-drv-blktap-raw.xml",
			  "xml2sexprdata/xml2sexpr-disk-drv-blktap-raw.sexpr",
			  "pvtest",
			  2);
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

    if (virtTestRun("XML-2-SEXPR Disk File",
		    1, testCompareDiskFile, NULL) != 0)
	ret = -1;

    if (virtTestRun("XML-2-SEXPR Disk Block",
		    1, testCompareDiskBlock, NULL) != 0)
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


    exit(ret==0 ? EXIT_SUCCESS : EXIT_FAILURE);
}
