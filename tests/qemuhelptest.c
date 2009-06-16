#include <config.h>

#ifdef WITH_QEMU

#include <stdio.h>
#include <stdlib.h>

#include "testutils.h"
#include "qemu_conf.h"

#define MAX_HELP_OUTPUT_SIZE 1024*64

struct testInfo {
    const char *name;
    unsigned flags;
    unsigned version;
    unsigned is_kvm;
    unsigned kvm_version;
};

static char *progname;
static char *abs_srcdir;

static int testHelpStrParsing(const void *data)
{
    const struct testInfo *info = data;
    char path[PATH_MAX];
    char helpStr[MAX_HELP_OUTPUT_SIZE];
    char *help = &(helpStr[0]);
    unsigned flags, version, is_kvm, kvm_version;

    snprintf(path, PATH_MAX, "%s/qemuhelpdata/%s", abs_srcdir, info->name);

    if (virtTestLoadFile(path, &help, MAX_HELP_OUTPUT_SIZE) < 0)
        return -1;

    if (qemudParseHelpStr(help, &flags, &version, &is_kvm, &kvm_version) == -1)
        return -1;

    if (flags != info->flags) {
        fprintf(stderr, "Computed flags do not match: got 0x%x, expected 0x%x\n",
                flags, info->flags);
        return -1;
    }

    if (version != info->version) {
        fprintf(stderr, "Parsed versions do not match: got %u, expected %u\n",
                version, info->version);
        return -1;
    }

    if (is_kvm != info->is_kvm) {
        fprintf(stderr, "Parsed is_kvm flag does not match: got %u, expected %u\n",
                is_kvm, info->is_kvm);
        return -1;
    }

    if (kvm_version != kvm_version) {
        fprintf(stderr, "Parsed KVM versions do not match: got %u, expected %u\n",
                version, kvm_version);
        return -1;
    }

    return 0;
}

static int
mymain(int argc, char **argv)
{
    int ret = 0;
    char cwd[PATH_MAX];

    progname = argv[0];

    if (argc > 1) {
        fprintf(stderr, "Usage: %s\n", progname);
        return (EXIT_FAILURE);
    }

    abs_srcdir = getenv("abs_srcdir");
    if (!abs_srcdir)
        abs_srcdir = getcwd(cwd, sizeof(cwd));

#define DO_TEST(name, flags, version, is_kvm, kvm_version)                          \
    do {                                                                            \
        const struct testInfo info = { name, flags, version, is_kvm, kvm_version }; \
        if (virtTestRun("QEMU Help String Parsing " name,                           \
                        1, testHelpStrParsing, &info) < 0)                          \
            ret = -1;                                                               \
    } while (0)

    DO_TEST("qemu-0.9.1",      0x002f, 9001,  0,  0);
    DO_TEST("kvm-74",          0x633e, 9001,  1, 74);
    DO_TEST("qemu-0.10.5",     0x5c6f, 10005, 0,  0);
    DO_TEST("qemu-kvm-0.10.5", 0x7d7e, 10005, 1,  0);
    DO_TEST("kvm-86",          0x7d7e, 10050, 1,  0);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)

#else

int main (void) { return (77); /* means 'test skipped' for automake */ }

#endif /* WITH_QEMU */
