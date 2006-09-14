
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

  if (virtTestLoadFile(xml, &xmlPtr, MAX_FILE) < 0)
    return -1;

  if (virtTestLoadFile(sexpr, &sexprPtr, MAX_FILE) < 0)
    return -1;

  if (!(gotsexpr = virDomainParseXMLDesc(xmlData, &gotname, xendConfigVersion))) 
    return -1;

  if (getenv("DEBUG_TESTS")) {
      printf("Expect %d '%s'\n", (int)strlen(sexprData), sexprData);
      printf("Actual %d '%s'\n", (int)strlen(gotsexpr), gotsexpr);
  }
  if (strcmp(sexprData, gotsexpr))
    return -1;

  if (strcmp(name, gotname))
    return -1;

  return 0;
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

    exit(ret==0 ? EXIT_SUCCESS : EXIT_FAILURE);
}
