
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>

#include "xml.h"
#include "testutils.h"
#include "internal.h"

static char *progname;
#define MAX_FILE 4096

static int testFilterLine(char *buffer,
			  const char *toRemove) {
  char *start;
  char *end;

  if (!(start = strstr(buffer, toRemove)))
    return -1;

  if (!(end = strstr(start+1, "\n"))) {
    *start = '\0';
  } else {
    memmove(start, end, strlen(end)+1);
  }
  return 0;
}

static int testCompareOutput(const char *expect, const char *filter, const char *const argv[]) {
  char expectData[MAX_FILE];
  char actualData[MAX_FILE];
  char *expectPtr = &(expectData[0]);
  char *actualPtr = &(actualData[0]);

  if (virtTestLoadFile(expect, &expectPtr, MAX_FILE) < 0)
    return -1;

  if (virtTestCaptureProgramOutput(argv, &actualPtr, MAX_FILE) < 0)
    return -1;

  if (filter)
    if (testFilterLine(actualData, filter) < 0)
      return -1;

  if (getenv("DEBUG_TESTS")) {
      printf("Expect %d '%s'\n", (int)strlen(expectData), expectData);
      printf("Actual %d '%s'\n", (int)strlen(actualData), actualData);
  }
  if (strcmp(expectData, actualData))
    return -1;

  return 0;
}


#define VIRSH_DEFAULT     "../src/virsh", \
    "--connect", \
    "test:///default"

static char *custom_uri;

#define VIRSH_CUSTOM     "../src/virsh", \
    "--connect", \
    custom_uri



static int testCompareListDefault(const void *data ATTRIBUTE_UNUSED) {
  const char *const argv[] = {
    VIRSH_DEFAULT,
    "list",
    NULL
  };
  return testCompareOutput("virshdata/list-default.txt",
			   NULL,
			   argv);
}

static int testCompareListCustom(const void *data ATTRIBUTE_UNUSED) {
  const char *const argv[] = {
    VIRSH_CUSTOM,
    "list",
    NULL
  };
  return testCompareOutput("virshdata/list-custom.txt",
			   NULL,
			   argv);
}


static int testCompareNodeinfoDefault(const void *data ATTRIBUTE_UNUSED) {
  const char *const argv[] = {
    VIRSH_DEFAULT,
    "nodeinfo",
    NULL
  };
  return testCompareOutput("virshdata/nodeinfo-default.txt",
			   NULL,
			   argv);
}

static int testCompareNodeinfoCustom(const void *data ATTRIBUTE_UNUSED) {
  const char *const argv[] = {
    VIRSH_CUSTOM,
    "nodeinfo",
    NULL
  };
  return testCompareOutput("virshdata/nodeinfo-custom.txt",
			   NULL,
			   argv);
}

static int testCompareDominfoByID(const void *data ATTRIBUTE_UNUSED) {
  const char *const argv[] = {
    VIRSH_CUSTOM,
    "dominfo",
    "2",
    NULL
  };
  return testCompareOutput("virshdata/dominfo-fc4.txt",
			   "\nCPU time:",
			   argv);
}


static int testCompareDominfoByUUID(const void *data ATTRIBUTE_UNUSED) {
  const char *const argv[] = {
    VIRSH_CUSTOM,
    "dominfo",
    "ef861801-45b9-11cb-88e3-afbfe5370493",
    NULL
  };
  return testCompareOutput("virshdata/dominfo-fc4.txt",
			   "\nCPU time:",
			   argv);
}


static int testCompareDominfoByName(const void *data ATTRIBUTE_UNUSED) {
  const char *const argv[] = {
    VIRSH_CUSTOM,
    "dominfo",
    "fc4",
    NULL
  };
  return testCompareOutput("virshdata/dominfo-fc4.txt",
			   "\nCPU time:",
			   argv);
}


static int testCompareDomuuidByID(const void *data ATTRIBUTE_UNUSED) {
  const char *const argv[] = {
    VIRSH_CUSTOM,
    "domuuid",
    "2",
    NULL
  };
  return testCompareOutput("virshdata/domuuid-fc4.txt",
			   NULL,
			   argv);
}

static int testCompareDomuuidByName(const void *data ATTRIBUTE_UNUSED) {
  const char *const argv[] = {
    VIRSH_CUSTOM,
    "domuuid",
    "fc4",
    NULL
  };
  return testCompareOutput("virshdata/domuuid-fc4.txt",
			   NULL,
			   argv);
}

static int testCompareDomidByName(const void *data ATTRIBUTE_UNUSED) {
  const char *const argv[] = {
    VIRSH_CUSTOM,
    "domid",
    "fc4",
    NULL
  };
  return testCompareOutput("virshdata/domid-fc4.txt",
			   NULL,
			   argv);
}


static int testCompareDomidByUUID(const void *data ATTRIBUTE_UNUSED) {
  const char *const argv[] = {
    VIRSH_CUSTOM,
    "domid",
    "ef861801-45b9-11cb-88e3-afbfe5370493",
    NULL
  };
  return testCompareOutput("virshdata/domid-fc4.txt",
			   NULL,
			   argv);
}


static int testCompareDomnameByID(const void *data ATTRIBUTE_UNUSED) {
  const char *const argv[] = {
    VIRSH_CUSTOM,
    "domname",
    "2",
    NULL
  };
  return testCompareOutput("virshdata/domname-fc4.txt",
			   NULL,
			   argv);
}


static int testCompareDomnameByUUID(const void *data ATTRIBUTE_UNUSED) {
  const char *const argv[] = {
    VIRSH_CUSTOM,
    "domname",
    "ef861801-45b9-11cb-88e3-afbfe5370493",
    NULL
  };
  return testCompareOutput("virshdata/domname-fc4.txt",
			   NULL,
			   argv);
}

static int testCompareDomstateByID(const void *data ATTRIBUTE_UNUSED) {
  const char *const argv[] = {
    VIRSH_CUSTOM,
    "domstate",
    "2",
    NULL
  };
  return testCompareOutput("virshdata/domstate-fc4.txt",
			   NULL,
			   argv);
}


static int testCompareDomstateByUUID(const void *data ATTRIBUTE_UNUSED) {
  const char *const argv[] = {
    VIRSH_CUSTOM,
    "domstate",
    "ef861801-45b9-11cb-88e3-afbfe5370493",
    NULL
  };
  return testCompareOutput("virshdata/domstate-fc4.txt",
			   NULL,
			   argv);
}

static int testCompareDomstateByName(const void *data ATTRIBUTE_UNUSED) {
  const char *const argv[] = {
    VIRSH_CUSTOM,
    "domstate",
    "fc4",
    NULL
  };
  return testCompareOutput("virshdata/domstate-fc4.txt",
			   NULL,
			   argv);
}



int
main(int argc, char **argv)
{
    int ret = 0;
    char cwd[PATH_MAX];
    char buffer[PATH_MAX];

    if (!getcwd(cwd, PATH_MAX-1))
      return 1;

    snprintf(buffer, PATH_MAX-1, "test://%s/../docs/testnode.xml", cwd);
    buffer[PATH_MAX-1] = '\0';
    progname = argv[0];
    custom_uri = buffer;
    
    if (argc > 1) {
        fprintf(stderr, "Usage: %s\n", progname); 
        exit(EXIT_FAILURE);
    }
    
    if (virtTestRun("virsh list (default)",
		    1, testCompareListDefault, NULL) != 0)
        ret = -1;

    if (virtTestRun("virsh list (custom)",
		    1, testCompareListCustom, NULL) != 0)
        ret = -1;

    if (virtTestRun("virsh nodeinfo (default)",
		    1, testCompareNodeinfoDefault, NULL) != 0)
        ret = -1;

    if (virtTestRun("virsh nodeinfo (custom)",
		    1, testCompareNodeinfoCustom, NULL) != 0)
        ret = -1;

    if (virtTestRun("virsh dominfo (by id)",
		    1, testCompareDominfoByID, NULL) != 0)
        ret = -1;

    if (virtTestRun("virsh dominfo (by uuid)",
		    1, testCompareDominfoByUUID, NULL) != 0)
        ret = -1;

    if (virtTestRun("virsh dominfo (by name)",
		    1, testCompareDominfoByName, NULL) != 0)
        ret = -1;

    if (virtTestRun("virsh domid (by name)",
		    1, testCompareDomidByName, NULL) != 0)
        ret = -1;

    if (virtTestRun("virsh domid (by uuid)",
		    1, testCompareDomidByUUID, NULL) != 0)
        ret = -1;

    if (virtTestRun("virsh domuuid (by id)",
		    1, testCompareDomuuidByID, NULL) != 0)
        ret = -1;

    if (virtTestRun("virsh domuuid (by name)",
		    1, testCompareDomuuidByName, NULL) != 0)
        ret = -1;

    if (virtTestRun("virsh domname (by id)",
		    1, testCompareDomnameByID, NULL) != 0)
        ret = -1;

    if (virtTestRun("virsh domname (by uuid)",
		    1, testCompareDomnameByUUID, NULL) != 0)
        ret = -1;

    if (virtTestRun("virsh domstate (by id)",
		    1, testCompareDomstateByID, NULL) != 0)
        ret = -1;

    if (virtTestRun("virsh domstate (by uuid)",
		    1, testCompareDomstateByUUID, NULL) != 0)
        ret = -1;

    if (virtTestRun("virsh domstate (by name)",
		    1, testCompareDomstateByName, NULL) != 0)
        ret = -1;

    exit(ret==0 ? EXIT_SUCCESS : EXIT_FAILURE);
}
