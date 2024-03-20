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

# define EQUAL "="

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

    DO_TEST_SCRIPT("info-default", NULL, VIRSH_DEFAULT);
    DO_TEST_SCRIPT("info-custom", NULL, VIRSH_CUSTOM);
    DO_TEST_SCRIPT("domain-id", "\nCPU time:", VIRSH_CUSTOM);
    DO_TEST_SCRIPT("blkiotune", NULL, VIRSH_CUSTOM);

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
