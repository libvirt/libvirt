#include <stdio.h>
#include <string.h>

#include "xml.h"
#include "xend_internal.h"
#include "testutils.h"
#include "internal.h"

static char *progname;

#define MAX_FILE 4096

static int testCompareFiles(const char *xml, const char *sexpr, int xendConfigVersion) {
  char xmlData[MAX_FILE];
  char sexprData[MAX_FILE];
  char *gotxml = NULL;
  char *xmlPtr = &(xmlData[0]);
  char *sexprPtr = &(sexprData[0]);
  int ret = -1;

  if (virtTestLoadFile(xml, &xmlPtr, MAX_FILE) < 0)
    goto fail;

  if (virtTestLoadFile(sexpr, &sexprPtr, MAX_FILE) < 0)
    goto fail;

  if (!(gotxml = xend_parse_domain_sexp(NULL, sexprData, xendConfigVersion)))
    goto fail;

  if (getenv("DEBUG_TESTS")) {
      printf("Expect %d '%s'\n", (int)strlen(xmlData), xmlData);
      printf("Actual %d '%s'\n", (int)strlen(gotxml), gotxml);
  }
  if (strcmp(xmlData, gotxml))
    goto fail;

  ret = 0;

 fail:
  free(gotxml);

  return ret;
}

static int testComparePVversion1(void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("sexpr2xmldata/sexpr2xml-pv.xml",
			  "sexpr2xmldata/sexpr2xml-pv.sexpr",
			  1);
}

static int testCompareFVversion1(void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("sexpr2xmldata/sexpr2xml-fv.xml",
			  "sexpr2xmldata/sexpr2xml-fv.sexpr",
			  1);
}

static int testComparePVversion2(void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("sexpr2xmldata/sexpr2xml-pv.xml",
			  "sexpr2xmldata/sexpr2xml-pv.sexpr",
			  2);
}

static int testCompareFVversion2(void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("sexpr2xmldata/sexpr2xml-fv-v2.xml",
			  "sexpr2xmldata/sexpr2xml-fv-v2.sexpr",
			  2);
}

static int testCompareDiskFile(void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("sexpr2xmldata/sexpr2xml-disk-file.xml",
			  "sexpr2xmldata/sexpr2xml-disk-file.sexpr",
			  1);
}

static int testCompareDiskBlock(void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("sexpr2xmldata/sexpr2xml-disk-block.xml",
			  "sexpr2xmldata/sexpr2xml-disk-block.sexpr",
			  1);
}

static int testCompareDiskDrvBlktapQcow(void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("sexpr2xmldata/sexpr2xml-disk-drv-blktap-qcow.xml",
			  "sexpr2xmldata/sexpr2xml-disk-drv-blktap-qcow.sexpr",
			  1);
}

static int testCompareDiskDrvBlktapRaw(void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("sexpr2xmldata/sexpr2xml-disk-drv-blktap-raw.xml",
			  "sexpr2xmldata/sexpr2xml-disk-drv-blktap-raw.sexpr",
			  1);
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

    if (virtTestRun("SEXPR-2-XML PV config (version 1)",
		    1, testComparePVversion1, NULL) != 0)
	ret = -1;

    if (virtTestRun("SEXPR-2-XML FV config (version 1)",
		    1, testCompareFVversion1, NULL) != 0)
	ret = -1;

    if (virtTestRun("SEXPR-2-XML PV config (version 2)",
		    1, testComparePVversion2, NULL) != 0)
	ret = -1;

    if (virtTestRun("SEXPR-2-XML FV config  (version 2)",
		    1, testCompareFVversion2, NULL) != 0)
	ret = -1;

    if (virtTestRun("SEXPR-2-XML Disk File config",
		    1, testCompareDiskFile, NULL) != 0)
	ret = -1;

    if (virtTestRun("SEXPR-2-XML Disk Block config",
		    1, testCompareDiskBlock, NULL) != 0)
	ret = -1;

    if (virtTestRun("SEXPR-2-XML Disk Driver blktap qcow config",
		    1, testCompareDiskDrvBlktapQcow, NULL) != 0)
	ret = -1;

    if (virtTestRun("SEXPR-2-XML Disk Driver blktap raw config",
		    1, testCompareDiskDrvBlktapRaw, NULL) != 0)
	ret = -1;

    exit(ret==0 ? EXIT_SUCCESS : EXIT_FAILURE);
}
