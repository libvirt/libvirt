
#include <stdio.h>
#include <string.h>

#include "xml.h"
#include "testutils.h"
#include "internal.h"

static char *progname;

#define MAX_FILE 4096

static int testCompareFiles(const char *xml, const char *sexpr, const char *name) {
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

  if (!(gotsexpr = virDomainParseXMLDesc(xmlData, &gotname))) 
    return -1;

  if (getenv("DEBUG_TESTS")) {
      printf("In  %d '%s'\n", strlen(sexprData), sexprData);
      printf("Out %d '%s'\n", strlen(gotsexpr), gotsexpr);
  }
  if (strcmp(sexprData, gotsexpr))
    return -1;

  if (strcmp(name, gotname))
    return -1;

  return 0;
}

static int testComparePV(void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("xml2sexpr-pv.xml",
			  "xml2sexpr-pv.sexpr",
			  "pvtest");
}

static int testCompareFV(void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("xml2sexpr-fv.xml",
			  "xml2sexpr-fv.sexpr",
			  "fvtest");
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
    
    if (virtTestRun("XML-2-SEXPR PV config", 
		    1, testComparePV, NULL) != 0)
        ret = -1;

    if (virtTestRun("XML-2-SEXPR FV config", 
		    1, testCompareFV, NULL) != 0)
        ret = -1;

    exit(ret==0 ? EXIT_SUCCESS : EXIT_FAILURE);
}
