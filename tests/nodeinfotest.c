#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "testutils.h"
#include "internal.h"
#include "nodeinfo.h"

static char *progname;
static char *abs_top_srcdir;

#define MAX_FILE 4096

#ifdef __linux__

extern int linuxNodeInfoCPUPopulate(virConnectPtr conn, FILE *cpuinfo, virNodeInfoPtr nodeinfo);

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
    if (linuxNodeInfoCPUPopulate(NULL, cpuinfo, &nodeinfo) < 0) {
        fclose(cpuinfo);
        return -1;
    }
    fclose(cpuinfo);

    snprintf(actualData, MAX_FILE,
             "CPUs: %u, MHz: %u, Nodes: %u, Sockets: %u, Cores: %u, Threads: %u\n",
             nodeinfo.cpus, nodeinfo.mhz, nodeinfo.nodes, nodeinfo.sockets,
             nodeinfo.cores, nodeinfo.threads);

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
    snprintf(cpuinfo, PATH_MAX, "%s/tests/nodeinfodata/linux-%s.cpuinfo",
             abs_top_srcdir, (const char*)data);
    snprintf(output, PATH_MAX, "%s/tests/nodeinfodata/linux-%s.txt",
             abs_top_srcdir, (const char*)data);
    return linuxTestCompareFiles(cpuinfo, output);
}
#endif


int
main(int argc, char **argv)
{
    int ret = 0;
#ifdef __linux__
    int i;
    const char *nodeData[] = {
        "nodeinfo-1",
        "nodeinfo-2",
        "nodeinfo-3",
        "nodeinfo-4",
        "nodeinfo-5",
        "nodeinfo-6",
    };

    abs_top_srcdir = getenv("abs_top_srcdir");
    if (!abs_top_srcdir)
      return EXIT_FAILURE;

    progname = argv[0];

    if (argc > 1) {
        fprintf(stderr, "Usage: %s\n", progname);
        exit(EXIT_FAILURE);
    }

    virInitialize();

    for (i = 0 ; i < (sizeof(nodeData)/sizeof(nodeData[0])) ; i++)
      if (virtTestRun(nodeData[i], 1, linuxTestNodeInfo, nodeData[i]) != 0)
	ret = -1;
#endif

    exit(ret==0 ? EXIT_SUCCESS : EXIT_FAILURE);
}

/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
