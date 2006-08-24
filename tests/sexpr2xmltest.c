
#include <stdio.h>
#include <string.h>

#include "xml.h"
#include "xend_internal.h"
#include "testutils.h"
#include "internal.h"

static char *progname;

#define MAX_FILE 4096

static int testCompareFiles(const char *xml, const char *sexpr) {
  char xmlData[MAX_FILE];
  char sexprData[MAX_FILE];
  char *gotxml = NULL;
  char *xmlPtr = &(xmlData[0]);
  char *sexprPtr = &(sexprData[0]);

  if (virtTestLoadFile(xml, &xmlPtr, MAX_FILE) < 0)
    return -1;

  if (virtTestLoadFile(sexpr, &sexprPtr, MAX_FILE) < 0)
    return -1;

  if (!(gotxml = xend_parse_domain_sexp(NULL, sexprData)))
    return -1;

  if (getenv("DEBUG_TESTS")) {
      printf("In  %d '%s'\n", strlen(xmlData), xmlData);
      printf("Out %d '%s'\n", strlen(gotxml), gotxml);
  }
  if (strcmp(xmlData, gotxml))
    return -1;

  return 0;
}

static int testComparePV(void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("sexpr2xml-pv.xml",
			  "sexpr2xml-pv.sexpr");
}

static int testCompareFV(void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("sexpr2xml-fv.xml",
			  "sexpr2xml-fv.sexpr");
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
    
    if (virtTestRun("SEXPR-2-XML PV config", 
		    1, testComparePV, NULL) != 0)
        ret = -1;

    if (virtTestRun("SEXPR-2-XML FV config", 
		    1, testCompareFV, NULL) != 0)
        ret = -1;

    exit(ret==0 ? EXIT_SUCCESS : EXIT_FAILURE);
}
