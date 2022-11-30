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
    g_autofree char *actualData = NULL;
    const char *empty = "";
    g_autoptr(virCommand) cmd = NULL;
    g_autofree char *errbuf = NULL;

    cmd = virCommandNewArgs(argv);

    virCommandAddEnvString(cmd, "LANG=C");
    virCommandSetInputBuffer(cmd, empty);
    virCommandSetOutputBuffer(cmd, &actualData);
    virCommandSetErrorBuffer(cmd, &errbuf);

    if (virCommandRun(cmd, NULL) < 0)
        return -1;

    if (STRNEQ(errbuf, "")) {
        fprintf(stderr, "Command reported error: %s", errbuf);
        return -1;
    }

    if (filter && testFilterLine(actualData, filter) < 0)
        return -1;

    if (virTestCompareToString(expectData, actualData) < 0) {
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

static int testCompareListDefault(const void *data G_GNUC_UNUSED)
{
    const char *const argv[] = { VIRSH_DEFAULT, "list", NULL };
    const char *exp = "\
 Id   Name   State\n\
----------------------\n\
 1    test   running\n\
\n";
    return testCompareOutputLit(exp, NULL, argv);
}

static int testCompareListCustom(const void *data G_GNUC_UNUSED)
{
    const char *const argv[] = { VIRSH_CUSTOM, "list", NULL };
    const char *exp = "\
 Id   Name   State\n\
----------------------\n\
 1    fv0    running\n\
 2    fc4    running\n\
 3    fc5    running\n\
\n";
    return testCompareOutputLit(exp, NULL, argv);
}

static int testCompareNodeinfoDefault(const void *data G_GNUC_UNUSED)
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

static int testCompareNodeinfoCustom(const void *data G_GNUC_UNUSED)
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

static int testCompareDominfoByID(const void *data G_GNUC_UNUSED)
{
    const char *const argv[] = { VIRSH_CUSTOM, "dominfo", "2", NULL };
    const char *exp = dominfo_fc4;
    return testCompareOutputLit(exp, "\nCPU time:", argv);
}

static int testCompareDominfoByUUID(const void *data G_GNUC_UNUSED)
{
    const char *const argv[] = { VIRSH_CUSTOM, "dominfo", DOM_FC4_UUID, NULL };
    const char *exp = dominfo_fc4;
    return testCompareOutputLit(exp, "\nCPU time:", argv);
}

static int testCompareDominfoByName(const void *data G_GNUC_UNUSED)
{
    const char *const argv[] = { VIRSH_CUSTOM, "dominfo", "fc4", NULL };
    const char *exp = dominfo_fc4;
    return testCompareOutputLit(exp, "\nCPU time:", argv);
}

static int testCompareTaintedDominfoByName(const void *data G_GNUC_UNUSED)
{
    const char *const argv[] = { VIRSH_CUSTOM, "dominfo", "fc5", NULL };
    const char *exp = dominfo_fc5;
    return testCompareOutputLit(exp, "\nCPU time:", argv);
}

static int testCompareDomuuidByID(const void *data G_GNUC_UNUSED)
{
    const char *const argv[] = { VIRSH_CUSTOM, "domuuid", "2", NULL };
    const char *exp = domuuid_fc4;
    return testCompareOutputLit(exp, NULL, argv);
}

static int testCompareDomuuidByName(const void *data G_GNUC_UNUSED)
{
    const char *const argv[] = { VIRSH_CUSTOM, "domuuid", "fc4", NULL };
    const char *exp = domuuid_fc4;
    return testCompareOutputLit(exp, NULL, argv);
}

static int testCompareDomidByName(const void *data G_GNUC_UNUSED)
{
    const char *const argv[] = { VIRSH_CUSTOM, "domid", "fc4", NULL };
    const char *exp = domid_fc4;
    return testCompareOutputLit(exp, NULL, argv);
}

static int testCompareDomidByUUID(const void *data G_GNUC_UNUSED)
{
    const char *const argv[] = { VIRSH_CUSTOM, "domid", DOM_FC4_UUID, NULL };
    const char *exp = domid_fc4;
    return testCompareOutputLit(exp, NULL, argv);
}

static int testCompareDomnameByID(const void *data G_GNUC_UNUSED)
{
    const char *const argv[] = { VIRSH_CUSTOM, "domname", "2", NULL };
    const char *exp = domname_fc4;
    return testCompareOutputLit(exp, NULL, argv);
}

static int testCompareDomnameByUUID(const void *data G_GNUC_UNUSED)
{
    const char *const argv[] = { VIRSH_CUSTOM, "domname", DOM_FC4_UUID, NULL };
    const char *exp = domname_fc4;
    return testCompareOutputLit(exp, NULL, argv);
}

static int testCompareDomstateByID(const void *data G_GNUC_UNUSED)
{
    const char *const argv[] = { VIRSH_CUSTOM, "domstate", "2", NULL };
    const char *exp = domstate_fc4;
    return testCompareOutputLit(exp, NULL, argv);
}

static int testCompareDomstateByUUID(const void *data G_GNUC_UNUSED)
{
    const char *const argv[] = { VIRSH_CUSTOM, "domstate", DOM_FC4_UUID, NULL };
    const char *exp = domstate_fc4;
    return testCompareOutputLit(exp, NULL, argv);
}

static int testCompareDomstateByName(const void *data G_GNUC_UNUSED)
{
    const char *const argv[] = { VIRSH_CUSTOM, "domstate", "fc4", NULL };
    const char *exp = domstate_fc4;
    return testCompareOutputLit(exp, NULL, argv);
}

static int testCompareDomControlInfoByName(const void *data G_GNUC_UNUSED)
{
    const char *const argv[] = { VIRSH_CUSTOM, "domcontrol", "fc4", NULL };
    const char *exp = "ok\n\n";
    return testCompareOutputLit(exp, NULL, argv);
}

static int testCompareGetBlkioParameters(const void *data G_GNUC_UNUSED)
{
    const char *const argv[] = { VIRSH_CUSTOM, "blkiotune", "fv0", NULL };
    const char *exp = get_blkio_parameters;
    return testCompareOutputLit(exp, NULL, argv);
}

static int testCompareSetBlkioParameters(const void *data G_GNUC_UNUSED)
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
    return testCompareOutputLit(exp, NULL, argv);
}

static int testIOThreadAdd(const void *data G_GNUC_UNUSED)
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
    return testCompareOutputLit(exp, NULL, argv);
}

static int testIOThreadDel(const void *data G_GNUC_UNUSED)
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
    return testCompareOutputLit(exp, NULL, argv);
}

static int testIOThreadSet(const void *data G_GNUC_UNUSED)
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
    return testCompareOutputLit(exp, NULL, argv);
}

static int testIOThreadPin(const void *data G_GNUC_UNUSED)
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

    /* It's a bit awkward listing result before argument, but that's a
     * limitation of C99 vararg macros.  */
# define DO_TEST(i, result, ...) \
    do { \
        const char *myargv[] = { VIRSH_DEFAULT, __VA_ARGS__, NULL }; \
        const struct testInfo info = { myargv, result }; \
        if (virTestRun("virsh echo " #i, \
                       testCompareEcho, &info) < 0) \
            ret = -1; \
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
    DO_TEST(16, "a A 0 + '*' ';' . ''\\''' '\"' / '?' = ' ' '\n' '<' '>' '&'\n",
            "echo", "--shell", "a", "A", "0", "+", "*", ";", ".", "\'",
            "\"", "/", "?", "=", " ", "\n", "<", ">", "&");
    DO_TEST(17, "\n",
            "echo", "");
    DO_TEST(18, "''\n",
            "echo", "--shell", "");
    DO_TEST(19, "\n",
            "echo", "--xml", "");
    DO_TEST(20, "''\n",
            "echo", "--shell", "");
    DO_TEST(21, "\n",
            "echo ''");
    DO_TEST(22, "''\n",
            "echo --shell \"\"");
    DO_TEST(23, "\n",
            "echo --xml ''");
    DO_TEST(24, "''\n",
            "echo --shell \"\"''");

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

    /* Tests of multiple commands.  */
    DO_TEST(36, "a\nb\n", " echo a; echo b;");
    DO_TEST(37, "a\nb\n", "\necho a\n echo b\n");
    DO_TEST(38, "a\nb\n", "ec\\\nho a\n echo \\\n b;");
    DO_TEST(39, "a\n b\n", "\"ec\\\nho\" a\n echo \"\\\n b\";");
    DO_TEST(40, "a\n\\\n b\n", "ec\\\nho a\n echo '\\\n b';");
    DO_TEST(41, "a\n", "echo a # b");
    DO_TEST(42, "a\nc\n", "echo a #b\necho c");
    DO_TEST(43, "a\nc\n", "echo a # b\\\necho c");
    DO_TEST(44, "a # b\n", "echo a '#' b");
    DO_TEST(45, "a # b\n", "echo a \\# b");
    DO_TEST(46, "a\n", "#unbalanced; 'quotes\"\necho a # b");
    DO_TEST(47, "a\n", "\\# ignored;echo a\n'#also' ignored");

    /* test of splitting in vshStringToArray */
    DO_TEST(48, "a\nb,c,\nd,,e,,\nf,,,e\n",
            "-q", "echo", "--split", "a,b,,c,,,d,,,,e,,,,,f,,,,,,e");
    DO_TEST(49, "\na\nb,c,\nd,,e,,\nf,,,e\n\n",
            "-q", "echo", "--split", ",a,b,,c,,,d,,,,e,,,,,f,,,,,,e,");
    DO_TEST(50, ",a\nb,c,\nd,,e,,\nf,,,e,\n",
            "-q", "echo", "--split", ",,a,b,,c,,,d,,,,e,,,,,f,,,,,,e,,");
    DO_TEST(51, ",\na\nb,c,\nd,,e,,\nf,,,e,\n\n",
            "-q", "echo", "--split", ",,,a,b,,c,,,d,,,,e,,,,,f,,,,,,e,,,");
    DO_TEST(52, ",,a\nb,c,\nd,,e,,\nf,,,e,,\n",
            "-q", "echo", "--split", ",,,,a,b,,c,,,d,,,,e,,,,,f,,,,,,e,,,,");
# undef DO_TEST

    VIR_FREE(custom_uri);
    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)

#endif /* WIN32 */
