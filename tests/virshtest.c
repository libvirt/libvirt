#include <config.h>

#include <unistd.h>
#include <fcntl.h>

#include "internal.h"
#include "testutils.h"
#include "vircommand.h"

#include "util/virthread.h"

#define VIR_FROM_THIS VIR_FROM_NONE

#ifdef WIN32

int
main(void)
{
    return EXIT_AM_SKIP;
}

#else

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
                     const char *filter,
                     const char *const *env,
                     const char *const argv[])
{
    g_autofree char *actual = NULL;
    const char *empty = "";
    g_autoptr(virCommand) cmd = NULL;
    int exitstatus = 0;

    cmd = virCommandNewArgs(argv);

    virCommandAddEnvString(cmd, "LANG=C");

    while (env && *env) {
        virCommandAddEnvString(cmd, *env);
        env++;
    }

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

    if (virTestCompareToFileFull(actual, expectFile, false) < 0)
        return -1;

    return 0;
}

# define VIRSH_DEFAULT abs_top_builddir "/tools/virsh", \
    "--connect", \
    "test:///default"

static char *custom_uri;

# define VIRSH_CUSTOM  abs_top_builddir "/tools/virsh", \
    "--connect", \
    custom_uri

struct testInfo {
    const char *testname; /* used to generate output filename */
    const char *filter;
    const char *const *argv;
    bool expensive;
    const char *const *env; /* extra environment variables to pass */
    bool forbid_root;
    bool need_readline;
};

static int testCompare(const void *data)
{
    const struct testInfo *info = data;
    g_autofree char *outfile = NULL;

    if (info->expensive && virTestGetExpensive() == 0)
        return EXIT_AM_SKIP;

    if (info->forbid_root && geteuid() == 0)
        return EXIT_AM_SKIP;

# ifndef WITH_READLINE
    if (info->need_readline)
        return EXIT_AM_SKIP;
# endif

    if (info->testname) {
        outfile = g_strdup_printf("%s/virshtestdata/%s.out",
                                  abs_srcdir, info->testname);
    }

    return testCompareOutputLit(outfile, info->filter, info->env, info->argv);
}


static void
testPipeFeeder(void *opaque)
{
    /* feed more than observed buffer size which was historically 128k in the
     * test this was adapted from */
    size_t emptyspace = 140 * 1024;
    const char *pipepath = opaque;
    const char *xml =
        "<domain type='test' id='2'>\n"
        "  <name>t2</name>\n"
        "  <uuid>004b96e1-2d78-c30f-5aa5-000000000000</uuid>\n"
        "  <memory>8388608</memory>\n"
        "  <vcpu>2</vcpu>\n"
        "  <os>\n"
        "    <type>xen</type>\n"
        "  </os>\n"
        "</domain>\n";
    size_t xmlsize = strlen(xml);
    g_autofree char *doc = g_new0(char, emptyspace + xmlsize + 1);
    VIR_AUTOCLOSE fd = -1;

    if ((fd = open(pipepath, O_WRONLY)) < 0) {
        fprintf(stderr, "\nfailed to open pipe '%s': %s\n", pipepath, g_strerror(errno));
        return;
    }

    memset(doc, ' ', emptyspace);
    g_assert(virStrcpy(doc + emptyspace, xml, xmlsize + 1) == 0);

    if (safewrite(fd, doc, emptyspace + xmlsize) < 0) {
        fprintf(stderr, "\nfailed to write to pipe '%s': %s\n", pipepath, g_strerror(errno));
        return;
    }
}


static int
testVirshPipe(const void *data G_GNUC_UNUSED)
{
    char tmpdir[] = "/tmp/libvirt_virshtest_XXXXXXX";
    g_autofree char *pipepath = NULL;
    virThread feeder;
    bool join = false;
    g_autofree char *cmdstr = NULL;
    const char *argv[] = { VIRSH_DEFAULT, NULL, NULL };
    int ret = -1;

    if (!g_mkdtemp(tmpdir)) {
        fprintf(stderr, "\nfailed to create temporary directory\n");
        return -1;
    }

    pipepath = g_strdup_printf("%s/pipe", tmpdir);


    cmdstr = g_strdup_printf("define %s ; list --all", pipepath);
    argv[3] = cmdstr;

    if (mkfifo(pipepath, 0600) < 0) {
        fprintf(stderr, "\nfailed to create pipe '%s': %s\n", pipepath, g_strerror(errno));
        goto cleanup;
    }

    if (virThreadCreate(&feeder, true, testPipeFeeder, pipepath) < 0)
        goto cleanup;

    join = true;

    if (testCompareOutputLit(abs_srcdir "/virshtestdata/read-big-pipe.out",
                             "/tmp/libvirt_virshtest", NULL, argv) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    if (join)
        virThreadJoin(&feeder);
    unlink(pipepath);
    rmdir(tmpdir);

    return ret;
}


static int
mymain(void)
{
    int ret = 0;
    bool need_readline = false;

    custom_uri = g_strdup_printf("test://%s/../examples/xml/test/testnode.xml",
                                 abs_srcdir);

# define DO_TEST_SCRIPT_FULL(testname_, expensive, testfilter, ...) \
    { \
        const char *testname = testname_; \
        g_autofree char *infile = g_strdup_printf("%s/virshtestdata/%s.in", \
                                                  abs_srcdir, testname); \
        const char *myargv[] = { __VA_ARGS__, NULL, NULL }; \
        const char **tmp = myargv; \
        const struct testInfo info = { testname, testfilter, myargv, expensive, NULL, false, need_readline}; \
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

# define DO_TEST_SCRIPT(testname_, testfilter, ...) \
    DO_TEST_SCRIPT_FULL(testname_, false, testfilter, __VA_ARGS__);

    DO_TEST_SCRIPT("info-default", NULL, VIRSH_DEFAULT);
    DO_TEST_SCRIPT("info-custom", NULL, VIRSH_CUSTOM);
    DO_TEST_SCRIPT("domain-id", "\nCPU time:", VIRSH_CUSTOM);
    DO_TEST_SCRIPT("blkiotune", NULL, VIRSH_CUSTOM);
    DO_TEST_SCRIPT("iothreads", NULL, VIRSH_CUSTOM);

# define DO_TEST_INFO(infostruct) \
    if (virTestRun((infostruct)->testname, testCompare, (infostruct)) < 0) \
        ret = -1;

# define DO_TEST_FULL(testname, filter, ...) \
    do { \
        const char *myargv[] = { __VA_ARGS__, NULL }; \
        const struct testInfo info = { testname, NULL, myargv, false, NULL, false, need_readline }; \
        DO_TEST_INFO(&info); \
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

    /* test of the --help option handling */
    DO_TEST_SCRIPT("help-option", NULL, VIRSH_DEFAULT, "-q");

    /* test of splitting in vshStringToArray */
    DO_TEST_SCRIPT("echo-split", NULL, VIRSH_DEFAULT, "-q");

    /* comprehensive coverage of argument assignment */
    DO_TEST_SCRIPT("argument-assignment", NULL, VIRSH_DEFAULT, "-k0", "-d0");
    DO_TEST_SCRIPT("snapshot-create-args", NULL, VIRSH_DEFAULT, "-q");
    DO_TEST_SCRIPT("numeric-parsing", NULL, VIRSH_DEFAULT);
    /* The 'numeric-parsing-event' invokes virsh event with a 1 second timeout,
     * thus is marked expensive */
    DO_TEST_SCRIPT_FULL("numeric-parsing-event", true, NULL, VIRSH_DEFAULT);
    DO_TEST_SCRIPT("attach-disk", NULL, VIRSH_DEFAULT);
    DO_TEST_SCRIPT("vcpupin", NULL, VIRSH_DEFAULT);
    DO_TEST_SCRIPT("lifecycle", "\nCPU time:", VIRSH_CUSTOM);

    DO_TEST_FULL("domain-id-overflow", NULL, VIRSH_CUSTOM, "-q", "domname", "4294967298");
    DO_TEST_FULL("schedinfo-invalid-argument", NULL, VIRSH_DEFAULT, "schedinfo", "1", "--set", "j=k");
    DO_TEST_FULL("pool-define-as", NULL, VIRSH_DEFAULT, "-q",
                 "pool-define-as", "--print-xml", "P", "dir", "src-host",
                 "/src/path", "/src/dev", "S", "/target-path");

    DO_TEST_SCRIPT("snapshot", "<creationTime", VIRSH_DEFAULT);
    DO_TEST_FULL("snapshot-redefine", NULL, VIRSH_DEFAULT,
                 "cd " abs_srcdir "/virshtestdata ;"
                 "echo 'Redefine must be in topological order; this will fail' ;"
                 "snapshot-create test --redefine snapshot-s2.xml --validate ;"
                 "echo 'correct order' ;"
                 "snapshot-create test --redefine snapshot-s3.xml --validate ;"
                 "snapshot-create test --redefine snapshot-s2.xml --current --validate ;"
                 "snapshot-info test --current");

    DO_TEST_SCRIPT("checkpoint", "<creationTime", VIRSH_DEFAULT);
    DO_TEST_FULL("checkpoint-redefine", NULL, VIRSH_DEFAULT,
                 "cd " abs_srcdir "/virshtestdata ;"
                 "echo 'Redefine must be in topological order; this will fail' ;"
                 "checkpoint-create test --redefine checkpoint-c2.xml ;"
                 "echo 'correct order' ;"
                 "checkpoint-create test --redefine checkpoint-c3.xml ;"
                 "checkpoint-create test --redefine checkpoint-c2.xml ;"
                 "checkpoint-info test c2");

    DO_TEST_SCRIPT("script-friendly-options", NULL, VIRSH_CUSTOM);

    /* completion doesn't work on non-readline builds */
    need_readline = true;

    DO_TEST_FULL("completion-command", NULL, VIRSH_CUSTOM,
                 "complete", "--", "ech");
    DO_TEST_FULL("completion-command-complete", NULL, VIRSH_CUSTOM,
                 "complete", "--", "echo");
    DO_TEST_FULL("completion-args", NULL, VIRSH_CUSTOM,
                 "complete", "--", "echo", "");
    DO_TEST_FULL("completion-arg-partial", NULL, VIRSH_CUSTOM,
                 "complete", "--", "echo", "--xm", "--s");
    DO_TEST_FULL("completion-arg-full-bool", NULL, VIRSH_CUSTOM,
                 "complete", "--", "echo", "--nonexistant-arg", "--xml");
    DO_TEST_FULL("completion-arg-full-bool-next", NULL, VIRSH_CUSTOM,
                 "complete", "--", "echo", "--nonexistant-arg", "--xml", "");
    DO_TEST_FULL("completion-arg-full-string", NULL, VIRSH_CUSTOM,
                 "complete", "--", "echo", "--nonexistant-arg", "--prefix");
    DO_TEST_FULL("completion-arg-full-string-next", NULL, VIRSH_CUSTOM,
                 "complete", "--", "echo", "--nonexistant-arg", "--prefix", "");
    DO_TEST_FULL("completion-arg-full-argv", NULL, VIRSH_CUSTOM,
                 "complete", "--", "domstats", "--domain");
    DO_TEST_FULL("completion-arg-full-argv-next", NULL, VIRSH_DEFAULT,
                 "complete", "--", "domstats", "--domain", "");
    DO_TEST_FULL("completion-argv-multiple", NULL, VIRSH_CUSTOM,
                 "complete", "--", "domstats", "--domain", "fc", "--domain", "fv");
    DO_TEST_FULL("completion-argv-multiple-next", NULL, VIRSH_CUSTOM,
                 "complete", "--", "domstats", "--domain", "fv", "--domain", "fc", "");
    DO_TEST_FULL("completion-argv-multiple-positional", NULL, VIRSH_CUSTOM,
                 "complete", "--", "domstats", "--domain", "fc", "fv");
    DO_TEST_FULL("completion-argv-multiple-positional-next", NULL, VIRSH_CUSTOM,
                 "complete", "--", "domstats", "--domain", "fc", "fv", "");
    DO_TEST_FULL("completion-arg-positional-empty", NULL, VIRSH_CUSTOM,
                 "complete", "--", "domstate", "");
    DO_TEST_FULL("completion-arg-positional-partial", NULL, VIRSH_CUSTOM,
                 "complete", "--", "domstate", "fv");
    DO_TEST_FULL("completion-arg-positional-partial-next", NULL, VIRSH_CUSTOM,
                 "complete", "--", "domstate", "fv", "");

    DO_TEST_SCRIPT("completion", NULL, VIRSH_DEFAULT);

    need_readline = false;

    if (virTestRun("read-big-pipe", testVirshPipe, NULL) < 0)
        ret = -1;

    /* Test precedence of URI lookup in virsh:
     *
     * Precedence is the following (lowest priority first):
     *
     * 1) if run as root, 'uri_default' from /etc/libvirtd/libvirt.conf,
     * otherwise qemu:///session.  There is no way to mock this file for
     * virsh/libvirt.so and the user may have set anything in there that
     * would spoil the test, so we don't test this
     *
     * 2) 'uri_default' from $XDG_CONFIG_HOME/libvirt/libvirt.conf
     *
     * 3) LIBVIRT_DEFAULT_URI
     *
     * 4) VIRSH_DEFAULT_CONNECT_URI
     *
     * 5) parameter -c (--connect)
     *
     * There are two pre-prepared directories in tests/virshtestdata/ serving
     * as mock XDG_CONFIG_HOME containing the test configs.
     */
    {
        const char *uriTest = "uri; connect; uri";
        const char *myargv_noconnect[] = { abs_top_builddir "/tools/virsh", uriTest, NULL };
        const char *xdgDirBad = "XDG_CONFIG_HOME=" abs_srcdir "/virshtestdata/uriprecedence-xdg/bad/";
        struct testInfo info = { NULL, NULL, myargv_noconnect, false, NULL, false, false };

        /* test 1 - default from config */
        {
            const char *myenv[] = {
                "XDG_CONFIG_HOME=" abs_srcdir "/virshtestdata/uriprecedence-xdg/good/",
                NULL,
            };

            info.testname = "uriprecedence-xdg-config";
            info.env = myenv;
            info.forbid_root = true;

            DO_TEST_INFO(&info);
        }

        /* all other tests don't care */
        info.forbid_root = false;

        /* test 2 - LIBVIRT_DEFAULT_URI env variable */
        {
            const char *myenv[] = {
                xdgDirBad,
                "LIBVIRT_DEFAULT_URI=test:///default?good_uri",
                NULL,
            };

            info.testname = "uriprecedence-LIBVIRT_DEFAULT_URI";
            info.env = myenv;

            DO_TEST_INFO(&info);
        }

        /* test 3 - VIRSH_DEFAULT_CONNECT_URI env variable */
        {
            const char *myenv[] = {
                xdgDirBad,
                "LIBVIRT_DEFAULT_URI=test:///default?bad_uri",
                "VIRSH_DEFAULT_CONNECT_URI=test:///default?good_uri",
                NULL,
            };

            info.testname = "uriprecedence-VIRSH_DEFAULT_CONNECT_URI";
            info.env = myenv;

            DO_TEST_INFO(&info);
        }

        /* test 3 - --connect parameter */
        {
            const char *myenv[] = {
                xdgDirBad,
                "LIBVIRT_DEFAULT_URI=test:///default?bad_uri",
                "VIRSH_DEFAULT_CONNECT_URI=test:///default?bad_uri",
                NULL,
            };

            const char *myargv[] = {
                 abs_top_builddir "/tools/virsh",
                 "--connect", "test:///default?good_uri",
                 uriTest,
                 NULL,
            };

            info.testname = "uriprecedence-param";
            info.env = myenv;
            info.argv = myargv;

            DO_TEST_INFO(&info);
        }
    }

    VIR_FREE(custom_uri);
    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)

#endif /* WIN32 */
