#include <config.h>

#include <unistd.h>

#include "internal.h"
#include "testutils.h"
#include "vircommand.h"

#define VIR_FROM_THIS VIR_FROM_NONE

#ifdef WIN32

int
main(void)
{
    return EXIT_AM_SKIP;
}

#else

# define DOM_FC4_UUID "ef861801-45b9-11cb-88e3-afbfe5370493"
# define DOM_FC5_UUID "08721f99-3d1d-4aec-96eb-97803297bb36"
# define SECURITY_LABEL "libvirt-test (enforcing)"
# define FC4_MESSAGES "tainted: network configuration using opaque shell scripts"
# define FC5_MESSAGES "tainted: running with undesirable elevated privileges\n\
                tainted: network configuration using opaque shell scripts\n\
                tainted: use of host cdrom passthrough\n\
                tainted: custom device tree blob used\n\
                tainted: use of deprecated configuration settings\n\
                deprecated configuration: CPU model Deprecated-Test"
# define GET_BLKIO_PARAMETER "/dev/hda,700"
# define SET_BLKIO_PARAMETER "/dev/hda,1000"
# define EQUAL "="

static const char *dominfo_fc4 = "\
Id:             2\n\
Name:           fc4\n\
UUID:           " DOM_FC4_UUID "\n\
OS Type:        linux\n\
State:          running\n\
CPU(s):         1\n\
Max memory:     261072 KiB\n\
Used memory:    131072 KiB\n\
Persistent:     yes\n\
Autostart:      disable\n\
Managed save:   no\n\
Security model: testSecurity\n\
Security DOI:   \n\
Security label: " SECURITY_LABEL "\n\
Messages:       " FC4_MESSAGES "\n\
\n";
static const char *domuuid_fc4 = DOM_FC4_UUID "\n\n";
static const char *domid_fc4 = "2\n\n";
static const char *domname_fc4 = "fc4\n\n";
static const char *domstate_fc4 = "running\n\n";
static const char *dominfo_fc5 = "\
Id:             3\n\
Name:           fc5\n\
UUID:           " DOM_FC5_UUID "\n\
OS Type:        linux\n\
State:          running\n\
CPU(s):         4\n\
Max memory:     2097152 KiB\n\
Used memory:    2097152 KiB\n\
Persistent:     yes\n\
Autostart:      disable\n\
Managed save:   no\n\
Security model: testSecurity\n\
Security DOI:   \n\
Security label: " SECURITY_LABEL "\n\
Messages:       " FC5_MESSAGES "\n\
\n";

static const char *get_blkio_parameters = "\
weight         : 800\n\
device_weight  : " GET_BLKIO_PARAMETER "\n\
device_read_iops_sec: " GET_BLKIO_PARAMETER "\n\
device_write_iops_sec: " GET_BLKIO_PARAMETER "\n\
device_read_bytes_sec: " GET_BLKIO_PARAMETER "\n\
device_write_bytes_sec: " GET_BLKIO_PARAMETER "\n\
\n";

static const char *set_blkio_parameters = "\
\n\
weight         : 500\n\
device_weight  : " SET_BLKIO_PARAMETER "\n\
device_read_iops_sec: " SET_BLKIO_PARAMETER "\n\
device_write_iops_sec: " SET_BLKIO_PARAMETER "\n\
device_read_bytes_sec: " SET_BLKIO_PARAMETER "\n\
device_write_bytes_sec: " SET_BLKIO_PARAMETER "\n\
\n";

static void testFilterLine(char *buffer,
                           const char *toRemove)
{
    char *start;

    while ((start = strstr(buffer, toRemove))) {
        char *end;

        if (!(end = strstr(start+1, "\n"))) {
            *start = '\0';
        } else {
            memmove(start, end, strlen(end)+1);
        }
    }
}

static int
testCompareOutputLit(const char *expectFile,
                     const char *expectData,
                     const char *filter,
                     const char *const argv[])
{
    g_autofree char *actual = NULL;
    const char *empty = "";
    g_autoptr(virCommand) cmd = NULL;
    int exitstatus = 0;

    cmd = virCommandNewArgs(argv);

    virCommandAddEnvString(cmd, "LANG=C");
    virCommandSetInputBuffer(cmd, empty);
    virCommandSetOutputBuffer(cmd, &actual);
    virCommandSetErrorBuffer(cmd, &actual);

    if (virCommandRun(cmd, &exitstatus) < 0)
        return -1;

    if (exitstatus != 0) {
        g_autofree char *tmp = g_steal_pointer(&actual);

        actual = g_strdup_printf("%s\n## Exit code: %d\n", tmp, exitstatus);
    }

    if (filter)
        testFilterLine(actual, filter);

    if (expectData) {
        if (virTestCompareToString(expectData, actual) < 0)
            return -1;
    }

    if (expectFile) {
        if (virTestCompareToFileFull(actual, expectFile, false) < 0)
            return -1;
    }

    return 0;
}

# define VIRSH_DEFAULT abs_top_builddir "/tools/virsh", \
    "--connect", \
    "test:///default"

static char *custom_uri;

# define VIRSH_CUSTOM  abs_top_builddir "/tools/virsh", \
    "--connect", \
    custom_uri

static int testCompareListDefault(const void *data)
{
    const char *const argv[] = { VIRSH_DEFAULT, "list", NULL };
    const char *exp = "\
 Id   Name   State\n\
----------------------\n\
 1    test   running\n\
\n";
    return testCompareOutputLit((const char *) data, exp, NULL, argv);
}

static int testCompareListCustom(const void *data)
{
    const char *const argv[] = { VIRSH_CUSTOM, "list", NULL };
    const char *exp = "\
 Id   Name   State\n\
----------------------\n\
 1    fv0    running\n\
 2    fc4    running\n\
 3    fc5    running\n\
\n";
    return testCompareOutputLit((const char *) data, exp, NULL, argv);
}

static int testCompareNodeinfoDefault(const void *data)
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
    return testCompareOutputLit((const char *) data, exp, NULL, argv);
}

static int testCompareNodeinfoCustom(const void *data)
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
    return testCompareOutputLit((const char *) data, exp, NULL, argv);
}

static int testCompareDominfoByID(const void *data)
{
    const char *const argv[] = { VIRSH_CUSTOM, "dominfo", "2", NULL };
    const char *exp = dominfo_fc4;
    return testCompareOutputLit((const char *) data, exp, "\nCPU time:", argv);
}

static int testCompareDominfoByUUID(const void *data)
{
    const char *const argv[] = { VIRSH_CUSTOM, "dominfo", DOM_FC4_UUID, NULL };
    const char *exp = dominfo_fc4;
    return testCompareOutputLit((const char *) data, exp, "\nCPU time:", argv);
}

static int testCompareDominfoByName(const void *data)
{
    const char *const argv[] = { VIRSH_CUSTOM, "dominfo", "fc4", NULL };
    const char *exp = dominfo_fc4;
    return testCompareOutputLit((const char *) data, exp, "\nCPU time:", argv);
}

static int testCompareTaintedDominfoByName(const void *data)
{
    const char *const argv[] = { VIRSH_CUSTOM, "dominfo", "fc5", NULL };
    const char *exp = dominfo_fc5;
    return testCompareOutputLit((const char *) data, exp, "\nCPU time:", argv);
}

static int testCompareDomuuidByID(const void *data)
{
    const char *const argv[] = { VIRSH_CUSTOM, "domuuid", "2", NULL };
    const char *exp = domuuid_fc4;
    return testCompareOutputLit((const char *) data, exp, NULL, argv);
}

static int testCompareDomuuidByName(const void *data)
{
    const char *const argv[] = { VIRSH_CUSTOM, "domuuid", "fc4", NULL };
    const char *exp = domuuid_fc4;
    return testCompareOutputLit((const char *) data, exp, NULL, argv);
}

static int testCompareDomidByName(const void *data)
{
    const char *const argv[] = { VIRSH_CUSTOM, "domid", "fc4", NULL };
    const char *exp = domid_fc4;
    return testCompareOutputLit((const char *) data, exp, NULL, argv);
}

static int testCompareDomidByUUID(const void *data)
{
    const char *const argv[] = { VIRSH_CUSTOM, "domid", DOM_FC4_UUID, NULL };
    const char *exp = domid_fc4;
    return testCompareOutputLit((const char *) data, exp, NULL, argv);
}

static int testCompareDomnameByID(const void *data)
{
    const char *const argv[] = { VIRSH_CUSTOM, "domname", "2", NULL };
    const char *exp = domname_fc4;
    return testCompareOutputLit((const char *) data, exp, NULL, argv);
}

static int testCompareDomnameByUUID(const void *data)
{
    const char *const argv[] = { VIRSH_CUSTOM, "domname", DOM_FC4_UUID, NULL };
    const char *exp = domname_fc4;
    return testCompareOutputLit((const char *) data, exp, NULL, argv);
}

static int testCompareDomstateByID(const void *data)
{
    const char *const argv[] = { VIRSH_CUSTOM, "domstate", "2", NULL };
    const char *exp = domstate_fc4;
    return testCompareOutputLit((const char *) data, exp, NULL, argv);
}

static int testCompareDomstateByUUID(const void *data)
{
    const char *const argv[] = { VIRSH_CUSTOM, "domstate", DOM_FC4_UUID, NULL };
    const char *exp = domstate_fc4;
    return testCompareOutputLit((const char *) data, exp, NULL, argv);
}

static int testCompareDomstateByName(const void *data)
{
    const char *const argv[] = { VIRSH_CUSTOM, "domstate", "fc4", NULL };
    const char *exp = domstate_fc4;
    return testCompareOutputLit((const char *) data, exp, NULL, argv);
}

static int testCompareDomControlInfoByName(const void *data)
{
    const char *const argv[] = { VIRSH_CUSTOM, "domcontrol", "fc4", NULL };
    const char *exp = "ok\n\n";
    return testCompareOutputLit((const char *) data, exp, NULL, argv);
}

static int testCompareGetBlkioParameters(const void *data)
{
    const char *const argv[] = { VIRSH_CUSTOM, "blkiotune", "fv0", NULL };
    const char *exp = get_blkio_parameters;
    return testCompareOutputLit((const char *) data, exp, NULL, argv);
}

static int testCompareSetBlkioParameters(const void *data)
{
    const char *const argv[] = { VIRSH_CUSTOM, "blkiotune fv0\
                                 --weight 500\
                                 --device-weights\
                                 " SET_BLKIO_PARAMETER "\
                                 --device-read-iops-sec\
                                 " SET_BLKIO_PARAMETER "\
                                 --device-write-iops-sec\
                                 " SET_BLKIO_PARAMETER "\
                                 --device-read-bytes-sec\
                                 " SET_BLKIO_PARAMETER "\
                                 --device-write-bytes-sec\
                                 " SET_BLKIO_PARAMETER ";\
                                 blkiotune fv0", NULL };
    const char *exp = set_blkio_parameters;
    return testCompareOutputLit((const char *) data, exp, NULL, argv);
}

static int testIOThreadAdd(const void *data)
{
    const char *const argv[] = { VIRSH_CUSTOM, "iothreadinfo --domain fc4;\
                                 iothreadadd --domain fc4 --id 6;\
                                 iothreadinfo --domain fc4", NULL};
    const char *exp = "\
 IOThread ID   CPU Affinity\n\
-----------------------------\n\
 2             0\n\
 4             0\n\
\n\
\n\
 IOThread ID   CPU Affinity\n\
-----------------------------\n\
 2             0\n\
 4             0\n\
 6             0\n\
\n";
    return testCompareOutputLit((const char *) data, exp, NULL, argv);
}

static int testIOThreadDel(const void *data)
{
    const char *const argv[] = { VIRSH_CUSTOM, "iothreadinfo --domain fc4;\
                                 iothreaddel --domain fc4 --id 2;\
                                 iothreadinfo --domain fc4", NULL};
    const char *exp = "\
 IOThread ID   CPU Affinity\n\
-----------------------------\n\
 2             0\n\
 4             0\n\
\n\
\n\
 IOThread ID   CPU Affinity\n\
-----------------------------\n\
 4             0\n\
\n";
    return testCompareOutputLit((const char *) data, exp, NULL, argv);
}

static int testIOThreadSet(const void *data)
{
    const char *const argv[] = { VIRSH_CUSTOM, "domstats --domain fc4;\
                                 iothreadset --domain fc4\
                                 --id 2 --poll-max-ns 100\
                                 --poll-shrink 10 --poll-grow 10;\
                                 domstats --domain fc4", NULL};
    const char *exp = "\
Domain: 'fc4'\n\
  state.state" EQUAL "1\n\
  state.reason" EQUAL "0\n\
  iothread.count" EQUAL "2\n\
  iothread.2.poll-max-ns" EQUAL "32768\n\
  iothread.2.poll-grow" EQUAL "0\n\
  iothread.2.poll-shrink" EQUAL "0\n\
  iothread.4.poll-max-ns" EQUAL "32768\n\
  iothread.4.poll-grow" EQUAL "0\n\
  iothread.4.poll-shrink" EQUAL "0\n\n\
\n\
Domain: 'fc4'\n\
  state.state" EQUAL "1\n\
  state.reason" EQUAL "0\n\
  iothread.count" EQUAL "2\n\
  iothread.2.poll-max-ns" EQUAL "100\n\
  iothread.2.poll-grow" EQUAL "10\n\
  iothread.2.poll-shrink" EQUAL "10\n\
  iothread.4.poll-max-ns" EQUAL "32768\n\
  iothread.4.poll-grow" EQUAL "0\n\
  iothread.4.poll-shrink" EQUAL "0\n\n";
    return testCompareOutputLit((const char *) data, exp, NULL, argv);
}

static int testIOThreadPin(const void *data)
{
    const char *const argv[] = { VIRSH_CUSTOM,
                                 "iothreadadd --domain fc5 --id 2;\
                                 iothreadinfo --domain fc5;\
                                 iothreadpin --domain fc5 --iothread 2\
                                 --cpulist 0;\
                                 iothreadinfo --domain fc5", NULL};
    const char *exp = "\n\
 IOThread ID   CPU Affinity\n\
-----------------------------\n\
 2             0-3\n\
\n\
\n\
 IOThread ID   CPU Affinity\n\
-----------------------------\n\
 2             0\n\
\n";
    return testCompareOutputLit((const char *) data, exp, NULL, argv);
}

struct testInfo {
    const char *testname; /* used to generate output filename */
    const char *filter;
    const char *const *argv;
};

static int testCompare(const void *data)
{
    const struct testInfo *info = data;
    g_autofree char *outfile = NULL;

    if (info->testname) {
        outfile = g_strdup_printf("%s/virshtestdata/%s.out",
                                  abs_srcdir, info->testname);
    }

    return testCompareOutputLit(outfile, NULL, info->filter, info->argv);
}


static int
mymain(void)
{
    int ret = 0;

    custom_uri = g_strdup_printf("test://%s/../examples/xml/test/testnode.xml",
                                 abs_srcdir);

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

    if (virTestRun("virsh dominfo (by name, more tainted messages)",
                   testCompareTaintedDominfoByName, NULL) != 0)
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

    if (virTestRun("virsh domcontrol (by name)",
                   testCompareDomControlInfoByName, NULL) != 0)
        ret = -1;

    if (virTestRun("virsh blkiotune (get parameters)",
                   testCompareGetBlkioParameters, NULL) != 0)
        ret = -1;

    if (virTestRun("virsh blkiotune (set parameters)",
                   testCompareSetBlkioParameters, NULL) != 0)
        ret = -1;

    if (virTestRun("virsh iothreadadd",
                   testIOThreadAdd, NULL) != 0)
        ret = -1;

    if (virTestRun("virsh iothreaddel",
                   testIOThreadDel, NULL) != 0)
        ret = -1;

    if (virTestRun("virsh iothreadset",
                   testIOThreadSet, NULL) != 0)
        ret = -1;

    if (virTestRun("virsh iothreadpin",
                   testIOThreadPin, NULL) != 0)
        ret = -1;

# define DO_TEST_SCRIPT(testname_, testfilter, ...) \
    { \
        const char *testname = testname_; \
        g_autofree char *infile = g_strdup_printf("%s/virshtestdata/%s.in", \
                                                  abs_srcdir, testname); \
        const char *myargv[] = { __VA_ARGS__, NULL, NULL }; \
        const char **tmp = myargv; \
        const struct testInfo info = { testname, testfilter, myargv }; \
        g_autofree char *scriptarg = NULL; \
        if (virFileReadAll(infile, 256 * 1024, &scriptarg) < 0) { \
            fprintf(stderr, "\nfailed to load '%s'\n", infile); \
            ret = -1; \
        } \
        while (*tmp) \
            tmp++; \
        *tmp = scriptarg; \
        if (virTestRun(testname, testCompare, &info) < 0) \
            ret = -1; \
    } while (0);

# define DO_TEST_FULL(testname_, filter, ...) \
    do { \
        const char *testname = testname_; \
        const char *myargv[] = { __VA_ARGS__, NULL }; \
        const struct testInfo info = { testname, NULL, myargv }; \
        if (virTestRun(testname, testCompare, &info) < 0) \
            ret = -1; \
    } while (0)

    /* automatically numbered test invocation */
# define DO_TEST(...) \
    DO_TEST_FULL(virTestCounterNext(), NULL, VIRSH_DEFAULT, __VA_ARGS__);


    /* Arg parsing quote removal tests.  */
    virTestCounterReset("echo-quote-removal-");
    DO_TEST("echo a \t b");
    DO_TEST("echo \"a \t b\"");
    DO_TEST("echo 'a \t b'");
    DO_TEST("echo a\\ \\\t\\ b");
    DO_TEST("echo", "'", "\"", "\\;echo\ta");
    DO_TEST("echo \\' \\\" \\;echo\ta");
    DO_TEST("echo \\' \\\" \\\\;echo\ta");
    DO_TEST("echo  \"'\"  '\"'  '\\'\"\\\\\"");

    /* Tests of echo flags.  */
    DO_TEST_SCRIPT("echo-escaping", NULL, VIRSH_DEFAULT);

    virTestCounterReset("echo-escaping-");
    DO_TEST("echo", "a", "A", "0", "+", "*", ";", ".", "'", "\"", "/", "?", "=", " ", "\n", "<", ">", "&");
    DO_TEST("echo", "--shell", "a", "A", "0", "+", "*", ";", ".", "'", "\"", "/", "?", "=", " ", "\n", "<", ">", "&");
    DO_TEST("echo", "--xml", "a", "A", "0", "+", "*", ";", ".", "'", "\"", "/", "?", "=", " ", "\n", "<", ">", "&");

    /* Tests of -- handling.  */
    virTestCounterReset("dash-dash-argument-");
    DO_TEST("--", "echo", "--shell", "a");
    DO_TEST("--", "echo", "a", "--shell");
    DO_TEST("--", "echo", "--", "a", "--shell");
    DO_TEST("echo", "--", "--", "--shell", "a");
    DO_TEST("echo --s\\h'e'\"l\"l -- a");
    DO_TEST("echo \t '-'\"-\" \t --shell \t a");

    /* Tests of alias handling.  */
    DO_TEST_SCRIPT("echo-alias", NULL, VIRSH_DEFAULT);
    DO_TEST_FULL("echo-alias-argv", NULL, VIRSH_DEFAULT, "echo", "--str", "hello");

    /* Tests of multiple commands.  */
    virTestCounterReset("multiple-commands-");
    DO_TEST(" echo a; echo b;");
    DO_TEST("\necho a\n echo b\n");
    DO_TEST("ec\\\nho a\n echo \\\n b;");
    DO_TEST("\"ec\\\nho\" a\n echo \"\\\n b\";");
    DO_TEST("ec\\\nho a\n echo '\\\n b';");
    DO_TEST("echo a # b");
    DO_TEST("echo a #b\necho c");
    DO_TEST("echo a # b\\\necho c");
    DO_TEST("echo a '#' b");
    DO_TEST("echo a \\# b");
    DO_TEST("#unbalanced; 'quotes\"\necho a # b");
    DO_TEST("\\# ignored;echo a\n'#also' ignored");

    /* test of splitting in vshStringToArray */
    DO_TEST_SCRIPT("echo-split", NULL, VIRSH_DEFAULT, "-q");
# undef DO_TEST

    VIR_FREE(custom_uri);
    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)

#endif /* WIN32 */
