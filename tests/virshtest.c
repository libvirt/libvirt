#include <config.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "internal.h"
#include "virxml.h"
#include "testutils.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NONE

#ifdef WIN32

int
main(void)
{
    return EXIT_AM_SKIP;
}

#else

# define DOM_UUID "ef861801-45b9-11cb-88e3-afbfe5370493"

static const char *dominfo_fc4 = "\
Id:             2\n\
Name:           fc4\n\
UUID:           " DOM_UUID "\n\
OS Type:        linux\n\
State:          running\n\
CPU(s):         1\n\
Max memory:     261072 KiB\n\
Used memory:    131072 KiB\n\
Persistent:     yes\n\
Autostart:      disable\n\
Managed save:   no\n\
\n";
static const char *domuuid_fc4 = DOM_UUID "\n\n";
static const char *domid_fc4 = "2\n\n";
static const char *domname_fc4 = "fc4\n\n";
static const char *domstate_fc4 = "running\n\n";

static int testFilterLine(char *buffer,
                          const char *toRemove)
{
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

static int
testCompareOutputLit(const char *expectData,
                     const char *filter, const char *const argv[])
{
    int result = -1;
    char *actualData = NULL;

    if (virTestCaptureProgramOutput(argv, &actualData, 4096) < 0)
        goto cleanup;

    if (filter && testFilterLine(actualData, filter) < 0)
        goto cleanup;

    if (STRNEQ(expectData, actualData)) {
        virTestDifference(stderr, expectData, actualData);
        goto cleanup;
    }

    result = 0;

 cleanup:
    VIR_FREE(actualData);

    return result;
}

# define VIRSH_DEFAULT     "../tools/virsh", \
    "--connect", \
    "test:///default"

static char *custom_uri;

# define VIRSH_CUSTOM     "../tools/virsh", \
    "--connect", \
    custom_uri

static int testCompareListDefault(const void *data ATTRIBUTE_UNUSED)
{
  const char *const argv[] = { VIRSH_DEFAULT, "list", NULL };
  const char *exp = "\
 Id    Name                           State\n\
----------------------------------------------------\n\
 1     test                           running\n\
\n";
  return testCompareOutputLit(exp, NULL, argv);
}

static int testCompareListCustom(const void *data ATTRIBUTE_UNUSED)
{
  const char *const argv[] = { VIRSH_CUSTOM, "list", NULL };
  const char *exp = "\
 Id    Name                           State\n\
----------------------------------------------------\n\
 1     fv0                            running\n\
 2     fc4                            running\n\
\n";
  return testCompareOutputLit(exp, NULL, argv);
}

static int testCompareNodeinfoDefault(const void *data ATTRIBUTE_UNUSED)
{
  const char *const argv[] = { VIRSH_DEFAULT, "nodeinfo", NULL };
  const char *exp = "\
CPU model:           i686\n\
CPU(s):              16\n\
CPU frequency:       1400 MHz\n\
CPU socket(s):       2\n\
Core(s) per socket:  2\n\
Thread(s) per core:  2\n\
NUMA cell(s):        2\n\
Memory size:         3145728 KiB\n\
\n";
  return testCompareOutputLit(exp, NULL, argv);
}

static int testCompareNodeinfoCustom(const void *data ATTRIBUTE_UNUSED)
{
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
Memory size:         8192000 KiB\n\
\n";
  return testCompareOutputLit(exp, NULL, argv);
}

static int testCompareDominfoByID(const void *data ATTRIBUTE_UNUSED)
{
  const char *const argv[] = { VIRSH_CUSTOM, "dominfo", "2", NULL };
  const char *exp = dominfo_fc4;
  return testCompareOutputLit(exp, "\nCPU time:", argv);
}

static int testCompareDominfoByUUID(const void *data ATTRIBUTE_UNUSED)
{
  const char *const argv[] = { VIRSH_CUSTOM, "dominfo", DOM_UUID, NULL };
  const char *exp = dominfo_fc4;
  return testCompareOutputLit(exp, "\nCPU time:", argv);
}

static int testCompareDominfoByName(const void *data ATTRIBUTE_UNUSED)
{
  const char *const argv[] = { VIRSH_CUSTOM, "dominfo", "fc4", NULL };
  const char *exp = dominfo_fc4;
  return testCompareOutputLit(exp, "\nCPU time:", argv);
}

static int testCompareDomuuidByID(const void *data ATTRIBUTE_UNUSED)
{
  const char *const argv[] = { VIRSH_CUSTOM, "domuuid", "2", NULL };
  const char *exp = domuuid_fc4;
  return testCompareOutputLit(exp, NULL, argv);
}

static int testCompareDomuuidByName(const void *data ATTRIBUTE_UNUSED)
{
  const char *const argv[] = { VIRSH_CUSTOM, "domuuid", "fc4", NULL };
  const char *exp = domuuid_fc4;
  return testCompareOutputLit(exp, NULL, argv);
}

static int testCompareDomidByName(const void *data ATTRIBUTE_UNUSED)
{
  const char *const argv[] = { VIRSH_CUSTOM, "domid", "fc4", NULL };
  const char *exp = domid_fc4;
  return testCompareOutputLit(exp, NULL, argv);
}

static int testCompareDomidByUUID(const void *data ATTRIBUTE_UNUSED)
{
  const char *const argv[] = { VIRSH_CUSTOM, "domid", DOM_UUID, NULL };
  const char *exp = domid_fc4;
  return testCompareOutputLit(exp, NULL, argv);
}

static int testCompareDomnameByID(const void *data ATTRIBUTE_UNUSED)
{
  const char *const argv[] = { VIRSH_CUSTOM, "domname", "2", NULL };
  const char *exp = domname_fc4;
  return testCompareOutputLit(exp, NULL, argv);
}

static int testCompareDomnameByUUID(const void *data ATTRIBUTE_UNUSED)
{
  const char *const argv[] = { VIRSH_CUSTOM, "domname", DOM_UUID, NULL };
  const char *exp = domname_fc4;
  return testCompareOutputLit(exp, NULL, argv);
}

static int testCompareDomstateByID(const void *data ATTRIBUTE_UNUSED)
{
  const char *const argv[] = { VIRSH_CUSTOM, "domstate", "2", NULL };
  const char *exp = domstate_fc4;
  return testCompareOutputLit(exp, NULL, argv);
}

static int testCompareDomstateByUUID(const void *data ATTRIBUTE_UNUSED)
{
  const char *const argv[] = { VIRSH_CUSTOM, "domstate", DOM_UUID, NULL };
  const char *exp = domstate_fc4;
  return testCompareOutputLit(exp, NULL, argv);
}

static int testCompareDomstateByName(const void *data ATTRIBUTE_UNUSED)
{
  const char *const argv[] = { VIRSH_CUSTOM, "domstate", "fc4", NULL };
  const char *exp = domstate_fc4;
  return testCompareOutputLit(exp, NULL, argv);
}

struct testInfo {
    const char *const *argv;
    const char *result;
};

static int testCompareEcho(const void *data)
{
    const struct testInfo *info = data;
    return testCompareOutputLit(info->result, NULL, info->argv);
}


static int
mymain(void)
{
    int ret = 0;

    if (virAsprintf(&custom_uri, "test://%s/../examples/xml/test/testnode.xml",
                    abs_srcdir) < 0)
        return EXIT_FAILURE;

    if (virTestRun("virsh list (default)",
                   testCompareListDefault, NULL) != 0)
        ret = -1;

    if (virTestRun("virsh list (custom)",
                   testCompareListCustom, NULL) != 0)
        ret = -1;

    if (virTestRun("virsh nodeinfo (default)",
                   testCompareNodeinfoDefault, NULL) != 0)
        ret = -1;

    if (virTestRun("virsh nodeinfo (custom)",
                   testCompareNodeinfoCustom, NULL) != 0)
        ret = -1;

    if (virTestRun("virsh dominfo (by id)",
                   testCompareDominfoByID, NULL) != 0)
        ret = -1;

    if (virTestRun("virsh dominfo (by uuid)",
                   testCompareDominfoByUUID, NULL) != 0)
        ret = -1;

    if (virTestRun("virsh dominfo (by name)",
                   testCompareDominfoByName, NULL) != 0)
        ret = -1;

    if (virTestRun("virsh domid (by name)",
                   testCompareDomidByName, NULL) != 0)
        ret = -1;

    if (virTestRun("virsh domid (by uuid)",
                   testCompareDomidByUUID, NULL) != 0)
        ret = -1;

    if (virTestRun("virsh domuuid (by id)",
                   testCompareDomuuidByID, NULL) != 0)
        ret = -1;

    if (virTestRun("virsh domuuid (by name)",
                   testCompareDomuuidByName, NULL) != 0)
        ret = -1;

    if (virTestRun("virsh domname (by id)",
                   testCompareDomnameByID, NULL) != 0)
        ret = -1;

    if (virTestRun("virsh domname (by uuid)",
                   testCompareDomnameByUUID, NULL) != 0)
        ret = -1;

    if (virTestRun("virsh domstate (by id)",
                   testCompareDomstateByID, NULL) != 0)
        ret = -1;

    if (virTestRun("virsh domstate (by uuid)",
                   testCompareDomstateByUUID, NULL) != 0)
        ret = -1;

    if (virTestRun("virsh domstate (by name)",
                   testCompareDomstateByName, NULL) != 0)
        ret = -1;

    /* It's a bit awkward listing result before argument, but that's a
     * limitation of C99 vararg macros.  */
# define DO_TEST(i, result, ...)                                        \
    do {                                                                \
        const char *myargv[] = { VIRSH_DEFAULT, __VA_ARGS__, NULL };    \
        const struct testInfo info = { myargv, result };                \
        if (virTestRun("virsh echo " #i,                                \
                       testCompareEcho, &info) < 0)                     \
            ret = -1;                                                   \
    } while (0)

    /* Arg parsing quote removal tests.  */
    DO_TEST(0, "\n",
            "echo");
    DO_TEST(1, "a\n",
            "echo", "a");
    DO_TEST(2, "a b\n",
            "echo", "a", "b");
    DO_TEST(3, "a b\n",
            "echo a \t b");
    DO_TEST(4, "a \t b\n",
            "echo \"a \t b\"");
    DO_TEST(5, "a \t b\n",
            "echo 'a \t b'");
    DO_TEST(6, "a \t b\n",
            "echo a\\ \\\t\\ b");
    DO_TEST(7, "\n\n",
            "echo ; echo");
    DO_TEST(8, "a\nb\n",
            ";echo a; ; echo b;");
    DO_TEST(9, "' \" \\;echo\ta\n",
            "echo", "'", "\"", "\\;echo\ta");
    DO_TEST(10, "' \" ;echo a\n",
            "echo \\' \\\" \\;echo\ta");
    DO_TEST(11, "' \" \\\na\n",
            "echo \\' \\\" \\\\;echo\ta");
    DO_TEST(12, "' \" \\\\\n",
            "echo  \"'\"  '\"'  '\\'\"\\\\\"");

    /* Tests of echo flags.  */
    DO_TEST(13, "a A 0 + * ; . ' \" / ? =   \n < > &\n",
            "echo", "a", "A", "0", "+", "*", ";", ".", "'", "\"", "/", "?",
            "=", " ", "\n", "<", ">", "&");
    DO_TEST(14, "a A 0 + '*' ';' . ''\\''' '\"' / '?' = ' ' '\n' '<' '>' '&'\n",
            "echo", "--shell", "a", "A", "0", "+", "*", ";", ".", "'", "\"",
            "/", "?", "=", " ", "\n", "<", ">", "&");
    DO_TEST(15, "a A 0 + * ; . &apos; &quot; / ? =   \n &lt; &gt; &amp;\n",
            "echo", "--xml", "a", "A", "0", "+", "*", ";", ".", "'", "\"",
            "/", "?", "=", " ", "\n", "<", ">", "&");
    DO_TEST(16, "a A 0 + '*' ';' . '&apos;' '&quot;' / '?' = ' ' '\n' '&lt;'"
            " '&gt;' '&amp;'\n",
            "echo", "--shell", "--xml", "a", "A", "0", "+", "*", ";", ".", "'",
            "\"", "/", "?", "=", " ", "\n", "<", ">", "&");
    DO_TEST(17, "\n",
            "echo", "");
    DO_TEST(18, "''\n",
            "echo", "--shell", "");
    DO_TEST(19, "\n",
            "echo", "--xml", "");
    DO_TEST(20, "''\n",
            "echo", "--xml", "--shell", "");
    DO_TEST(21, "\n",
            "echo ''");
    DO_TEST(22, "''\n",
            "echo --shell \"\"");
    DO_TEST(23, "\n",
            "echo --xml ''");
    DO_TEST(24, "''\n",
            "echo --xml --shell \"\"''");

    /* Tests of -- handling.  */
    DO_TEST(25, "a\n",
            "--", "echo", "--shell", "a");
    DO_TEST(26, "a\n",
            "--", "echo", "a", "--shell");
    DO_TEST(27, "a --shell\n",
            "--", "echo", "--", "a", "--shell");
    DO_TEST(28, "-- --shell a\n",
            "echo", "--", "--", "--shell", "a");
    DO_TEST(29, "a\n",
            "echo --s\\h'e'\"l\"l -- a");
    DO_TEST(30, "--shell a\n",
            "echo \t '-'\"-\" \t --shell \t a");

    /* Tests of alias handling.  */
    DO_TEST(31, "hello\n", "echo", "--string", "hello");
    DO_TEST(32, "hello\n", "echo --string hello");
    DO_TEST(33, "hello\n", "echo", "--str", "hello");
    DO_TEST(34, "hello\n", "echo --str hello");
    DO_TEST(35, "hello\n", "echo --hi");

# undef DO_TEST

    VIR_FREE(custom_uri);
    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)

#endif /* WIN32 */
