#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "testutils.h"
#include "internal.h"
#include "nodeinfo.h"
#include "util.h"
#include "files.h"

#ifndef __linux__

static int
mymain(int argc ATTRIBUTE_UNUSED, char **argv ATTRIBUTE_UNUSED)
{
    exit (EXIT_AM_SKIP);
}

#else

static char *progname;
static char *abs_srcdir;

# define MAX_FILE 4096

extern int linuxNodeInfoCPUPopulate(FILE *cpuinfo, virNodeInfoPtr nodeinfo);

static int linuxTestCompareFiles(const char *cpuinfofile, const char *outputfile) {
    char actualData[MAX_FILE];
    char expectData[MAX_FILE];
    char *expect = &expectData[0];
    virNodeInfo nodeinfo;
    FILE *cpuinfo;

    if (virtTestLoadFile(outputfile, &expect, MAX_FILE) < 0)
        return -1;

    cpuinfo = fopen(cpuinfofile, "r");
    if (!cpuinfo)
        return -1;

    memset(&nodeinfo, 0, sizeof(nodeinfo));
    if (linuxNodeInfoCPUPopulate(cpuinfo, &nodeinfo) < 0) {
        if (virTestGetDebug()) {
            virErrorPtr error = virSaveLastError();
            if (error && error->code != VIR_ERR_OK)
                fprintf(stderr, "\n%s\n", error->message);
            virFreeError(error);
        }
        VIR_FORCE_FCLOSE(cpuinfo);
        return -1;
    }
    VIR_FORCE_FCLOSE(cpuinfo);

    /* 'nodes' is filled using libnuma.so from current machine
     * topology, which makes it unsuitable for the test suite
     * so blank it to a predictable value */
    nodeinfo.nodes = 1;

    snprintf(actualData, MAX_FILE,
             "CPUs: %u, MHz: %u, Nodes: %u, Cores: %u\n",
             nodeinfo.cpus, nodeinfo.mhz, nodeinfo.nodes, nodeinfo.cores);

    if (STRNEQ(actualData, expectData)) {
        if (getenv("DEBUG_TESTS")) {
            printf("Expect %d '%s'\n", (int)strlen(expectData), expectData);
            printf("Actual %d '%s'\n", (int)strlen(actualData), actualData);
        }
        return -1;
    }

    return 0;
}


static int linuxTestNodeInfo(const void *data) {
    char cpuinfo[PATH_MAX];
    char output[PATH_MAX];
    snprintf(cpuinfo, PATH_MAX, "%s/nodeinfodata/linux-%s.cpuinfo",
             abs_srcdir, (const char*)data);
    snprintf(output, PATH_MAX, "%s/nodeinfodata/linux-%s.txt",
             abs_srcdir, (const char*)data);
    return linuxTestCompareFiles(cpuinfo, output);
}


static int
mymain(int argc, char **argv)
{
    int ret = 0;
    int i;
    const char *nodeData[] = {
        "nodeinfo-1",
        "nodeinfo-2",
        "nodeinfo-3",
        "nodeinfo-4",
        "nodeinfo-5",
        "nodeinfo-6",
    };
    char cwd[PATH_MAX];

    abs_srcdir = getenv("abs_srcdir");
    if (!abs_srcdir)
        abs_srcdir = getcwd(cwd, sizeof(cwd));

    progname = argv[0];

    if (argc > 1) {
        fprintf(stderr, "Usage: %s\n", progname);
        return(EXIT_FAILURE);
    }

    if (virInitialize() < 0)
        return EXIT_FAILURE;

    for (i = 0 ; i < ARRAY_CARDINALITY(nodeData); i++)
      if (virtTestRun(nodeData[i], 1, linuxTestNodeInfo, nodeData[i]) != 0)
        ret = -1;

    return(ret==0 ? EXIT_SUCCESS : EXIT_FAILURE);
}

#endif /* __linux__ */

VIRT_TEST_MAIN(mymain)
