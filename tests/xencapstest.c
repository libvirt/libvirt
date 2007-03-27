#include <stdio.h>
#include <string.h>

#include "xml.h"
#include "testutils.h"
#include "internal.h"
#include "xen_internal.h"

static char *progname;

#define MAX_FILE 4096

static int testCompareFiles(const char *hostmachine,
			    const char *xml,
			    const char *cpuinfo,
			    const char *capabilities) {
  char xmlData[MAX_FILE];
  char *expectxml = &(xmlData[0]);
  char *actualxml = NULL;
  FILE *fp1 = NULL, *fp2 = NULL;

  int ret = -1;

  if (virtTestLoadFile(xml, &expectxml, MAX_FILE) < 0)
    goto fail;

  if (!(fp1 = fopen(cpuinfo, "r")))
    goto fail;

  if (!(fp2 = fopen(capabilities, "r")))
    goto fail;

  if (!(actualxml = xenHypervisorMakeCapabilitiesXML(NULL, hostmachine, fp1, fp2)))
    goto fail;

  if (getenv("DEBUG_TESTS")) {
    printf("Expect %d '%s'\n", (int)strlen(expectxml), expectxml);
    printf("Actual %d '%s'\n", (int)strlen(actualxml), actualxml);
  }
  if (strcmp(expectxml, actualxml))
    goto fail;

  ret = 0;

 fail:

  if (actualxml)
    free(actualxml);
  if (fp1)
    fclose(fp1);
  if (fp2)
    fclose(fp2);

  return ret;
}

static int testXeni686(void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("i686",
			  "xencapsdata/xen-i686.xml",
			  "xencapsdata/xen-i686.cpuinfo",
			  "xencapsdata/xen-i686.caps");
}

static int testXeni686PAE(void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("i686",
			  "xencapsdata/xen-i686-pae.xml",
			  "xencapsdata/xen-i686-pae.cpuinfo",
			  "xencapsdata/xen-i686-pae.caps");
}

static int testXeni686PAEHVM(void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("i686",
			  "xencapsdata/xen-i686-pae-hvm.xml",
			  "xencapsdata/xen-i686-pae-hvm.cpuinfo",
			  "xencapsdata/xen-i686-pae-hvm.caps");
}

/* No PAE + HVM is non-sensical - all VMX capable
   CPUs have PAE */
/*
static int testXeni686HVM(void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("i686",
			  "xencapsdata/xen-i686-hvm.xml",
			  "xencapsdata/xen-i686.cpuinfo",
			  "xencapsdata/xen-i686-hvm.caps");
}
*/

static int testXenx86_64(void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("x86_64",
			  "xencapsdata/xen-x86_64.xml",
			  "xencapsdata/xen-x86_64.cpuinfo",
			  "xencapsdata/xen-x86_64.caps");
}
static int testXenx86_64HVM(void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("x86_64",
			  "xencapsdata/xen-x86_64-hvm.xml",
			  "xencapsdata/xen-x86_64-hvm.cpuinfo",
			  "xencapsdata/xen-x86_64-hvm.caps");
}

static int testXenia64(void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("ia64",
			  "xencapsdata/xen-ia64.xml",
			  "xencapsdata/xen-ia64.cpuinfo",
			  "xencapsdata/xen-ia64.caps");
}
static int testXenia64BE(void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("ia64",
			  "xencapsdata/xen-ia64-be.xml",
			  "xencapsdata/xen-ia64-be.cpuinfo",
			  "xencapsdata/xen-ia64-be.caps");
}

static int testXenia64HVM(void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("ia64",
			  "xencapsdata/xen-ia64-hvm.xml",
			  "xencapsdata/xen-ia64-hvm.cpuinfo",
			  "xencapsdata/xen-ia64-hvm.caps");
}
static int testXenia64BEHVM(void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("ia64",
			  "xencapsdata/xen-ia64-be-hvm.xml",
			  "xencapsdata/xen-ia64-be-hvm.cpuinfo",
			  "xencapsdata/xen-ia64-be-hvm.caps");
}

static int testXenppc64(void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("ppc64",
			  "xencapsdata/xen-ppc64.xml",
			  "xencapsdata/xen-ppc64.cpuinfo",
			  "xencapsdata/xen-ppc64.caps");
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

    virInitialize();

    if (virtTestRun("Capabilities for i686, no PAE, no HVM",
		    1, testXeni686, NULL) != 0)
	ret = -1;

    if (virtTestRun("Capabilities for i686, PAE, no HVM",
		    1, testXeni686PAE, NULL) != 0)
	ret = -1;

    /* No PAE + HVM is non-sensical - all VMX capable
       CPUs have PAE */
    /*if (virtTestRun("Capabilities for i686, no PAE, HVM",
		    1, testXeni686HVM, NULL) != 0)
	ret = -1;
    */

    if (virtTestRun("Capabilities for i686, PAE, HVM",
		    1, testXeni686PAEHVM, NULL) != 0)
	ret = -1;

    if (virtTestRun("Capabilities for x86_64, no HVM",
		    1, testXenx86_64, NULL) != 0)
	ret = -1;

    if (virtTestRun("Capabilities for x86_64, HVM",
		    1, testXenx86_64HVM, NULL) != 0)
	ret = -1;

    if (virtTestRun("Capabilities for ia64, no HVM, LE",
		    1, testXenia64, NULL) != 0)
	ret = -1;

    if (virtTestRun("Capabilities for ia64, HVM, LE",
		    1, testXenia64HVM, NULL) != 0)
	ret = -1;

    if (virtTestRun("Capabilities for ia64, no HVM, BE",
		    1, testXenia64BE, NULL) != 0)
	ret = -1;

    if (virtTestRun("Capabilities for ia64, HVM, BE",
		    1, testXenia64BEHVM, NULL) != 0)
	ret = -1;

    if (virtTestRun("Capabilities for ppc64",
		    1, testXenppc64, NULL) != 0)
	ret = -1;


    exit(ret==0 ? EXIT_SUCCESS : EXIT_FAILURE);
}
