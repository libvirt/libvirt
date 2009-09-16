#include <config.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "internal.h"
#include "xml.h"
#include "testutils.h"

static char *progname;
static char *abs_srcdir;
#define MAX_FILE 4096

#define DOM_UUID "ef861801-45b9-11cb-88e3-afbfe5370493"

static const char *dominfo_fc4 = "\
Id:             2\n\
Name:           fc4\n\
UUID:           " DOM_UUID "\n\
OS Type:        linux\n\
State:          running\n\
CPU(s):         1\n\
Max memory:     261072 kB\n\
Used memory:    131072 kB\n\
Autostart:      disable\n\
\n";
static const char *domuuid_fc4 = DOM_UUID "\n\n";
static const char *domid_fc4 = "2\n\n";
static const char *domname_fc4 = "fc4\n\n";
static const char *domstate_fc4 = "running\n\n";

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

static int testCompareOutputLit(const char *expectData,
                                const char *filter, const char *const argv[]) {
  char actualData[MAX_FILE];
  char *actualPtr = &(actualData[0]);

  if (virtTestCaptureProgramOutput(argv, &actualPtr, MAX_FILE) < 0)
    return -1;

  if (filter)
    if (testFilterLine(actualData, filter) < 0)
      return -1;

  if (STRNEQ(expectData, actualData)) {
      virtTestDifference(stderr, expectData, actualData);
      return -1;
  }

  return 0;
}

#if unused
static int testCompareOutput(const char *expect_rel, const char *filter,
                             const char *const argv[]) {
  char expectData[MAX_FILE];
  char *expectPtr = &(expectData[0]);
  char expect[PATH_MAX];

  snprintf(expect, sizeof expect - 1, "%s/%s", abs_srcdir, expect_rel);

  if (virtTestLoadFile(expect, &expectPtr, MAX_FILE) < 0)
    return -1;

  return testCompareOutputLit(expectData, filter, argv);
}
#endif

#define VIRSH_DEFAULT     "../tools/virsh", \
    "--connect", \
    "test:///default"

static char *custom_uri;

#define VIRSH_CUSTOM     "../tools/virsh", \
    "--connect", \
    custom_uri

static int testCompareListDefault(const void *data ATTRIBUTE_UNUSED) {
  const char *const argv[] = { VIRSH_DEFAULT, "list", NULL };
  const char *exp = "\
 Id Name                 State\n\
----------------------------------\n\
  1 test                 running\n\
\n";
  return testCompareOutputLit(exp, NULL, argv);
}

static int testCompareListCustom(const void *data ATTRIBUTE_UNUSED) {
  const char *const argv[] = { VIRSH_CUSTOM, "list", NULL };
  const char *exp = "\
 Id Name                 State\n\
----------------------------------\n\
  1 fv0                  running\n\
  2 fc4                  running\n\
\n";
  return testCompareOutputLit(exp, NULL, argv);
}

static int testCompareNodeinfoDefault(const void *data ATTRIBUTE_UNUSED) {
  const char *const argv[] = { VIRSH_DEFAULT, "nodeinfo", NULL };
  const char *exp = "\
CPU model:           i686\n\
CPU(s):              16\n\
CPU frequency:       1400 MHz\n\
CPU socket(s):       2\n\
Core(s) per socket:  2\n\
Thread(s) per core:  2\n\
NUMA cell(s):        2\n\
Memory size:         3145728 kB\n\
\n";
  return testCompareOutputLit(exp, NULL, argv);
}

static int testCompareNodeinfoCustom(const void *data ATTRIBUTE_UNUSED) {
  const char *const argv[] = {
    VIRSH_CUSTOM,
    "nodeinfo",
    NULL
  };
  const char *exp = "\
CPU model:           i986\n\
CPU(s):              50\n\
CPU frequency:       6000 MHz\n\
CPU socket(s):       4\n\
Core(s) per socket:  4\n\
Thread(s) per core:  2\n\
NUMA cell(s):        4\n\
Memory size:         8192000 kB\n\
\n";
  return testCompareOutputLit(exp, NULL, argv);
}

static int testCompareDominfoByID(const void *data ATTRIBUTE_UNUSED) {
  const char *const argv[] = { VIRSH_CUSTOM, "dominfo", "2", NULL };
  const char *exp = dominfo_fc4;
  return testCompareOutputLit(exp, "\nCPU time:", argv);
}

static int testCompareDominfoByUUID(const void *data ATTRIBUTE_UNUSED) {
  const char *const argv[] = { VIRSH_CUSTOM, "dominfo", DOM_UUID, NULL };
  const char *exp = dominfo_fc4;
  return testCompareOutputLit(exp, "\nCPU time:", argv);
}

static int testCompareDominfoByName(const void *data ATTRIBUTE_UNUSED) {
  const char *const argv[] = { VIRSH_CUSTOM, "dominfo", "fc4", NULL };
  const char *exp = dominfo_fc4;
  return testCompareOutputLit(exp, "\nCPU time:", argv);
}

static int testCompareDomuuidByID(const void *data ATTRIBUTE_UNUSED) {
  const char *const argv[] = { VIRSH_CUSTOM, "domuuid", "2", NULL };
  const char *exp = domuuid_fc4;
  return testCompareOutputLit(exp, NULL, argv);
}

static int testCompareDomuuidByName(const void *data ATTRIBUTE_UNUSED) {
  const char *const argv[] = { VIRSH_CUSTOM, "domuuid", "fc4", NULL };
  const char *exp = domuuid_fc4;
  return testCompareOutputLit(exp, NULL, argv);
}

static int testCompareDomidByName(const void *data ATTRIBUTE_UNUSED) {
  const char *const argv[] = { VIRSH_CUSTOM, "domid", "fc4", NULL };
  const char *exp = domid_fc4;
  return testCompareOutputLit(exp, NULL, argv);
}

static int testCompareDomidByUUID(const void *data ATTRIBUTE_UNUSED) {
  const char *const argv[] = { VIRSH_CUSTOM, "domid", DOM_UUID, NULL };
  const char *exp = domid_fc4;
  return testCompareOutputLit(exp, NULL, argv);
}

static int testCompareDomnameByID(const void *data ATTRIBUTE_UNUSED) {
  const char *const argv[] = { VIRSH_CUSTOM, "domname", "2", NULL };
  const char *exp = domname_fc4;
  return testCompareOutputLit(exp, NULL, argv);
}

static int testCompareDomnameByUUID(const void *data ATTRIBUTE_UNUSED) {
  const char *const argv[] = { VIRSH_CUSTOM, "domname", DOM_UUID, NULL };
  const char *exp = domname_fc4;
  return testCompareOutputLit(exp, NULL, argv);
}

static int testCompareDomstateByID(const void *data ATTRIBUTE_UNUSED) {
  const char *const argv[] = { VIRSH_CUSTOM, "domstate", "2", NULL };
  const char *exp = domstate_fc4;
  return testCompareOutputLit(exp, NULL, argv);
}

static int testCompareDomstateByUUID(const void *data ATTRIBUTE_UNUSED) {
  const char *const argv[] = { VIRSH_CUSTOM, "domstate", DOM_UUID, NULL };
  const char *exp = domstate_fc4;
  return testCompareOutputLit(exp, NULL, argv);
}

static int testCompareDomstateByName(const void *data ATTRIBUTE_UNUSED) {
  const char *const argv[] = { VIRSH_CUSTOM, "domstate", "fc4", NULL };
  const char *exp = domstate_fc4;
  return testCompareOutputLit(exp, NULL, argv);
}

static int
mymain(int argc, char **argv)
{
    int ret = 0;
    char buffer[PATH_MAX];
    char cwd[PATH_MAX];

    abs_srcdir = getenv("abs_srcdir");
    if (!abs_srcdir)
        abs_srcdir = getcwd(cwd, sizeof(cwd));

#ifdef WIN32
    exit (77); /* means 'test skipped' for automake */
#endif

    snprintf(buffer, PATH_MAX-1, "test://%s/../examples/xml/test/testnode.xml", abs_srcdir);
    buffer[PATH_MAX-1] = '\0';
    progname = argv[0];
    custom_uri = buffer;

    if (argc > 1) {
        fprintf(stderr, "Usage: %s\n", progname);
        return(EXIT_FAILURE);
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

    return(ret==0 ? EXIT_SUCCESS : EXIT_FAILURE);
}

VIRT_TEST_MAIN(mymain)
