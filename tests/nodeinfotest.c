#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "testutils.h"
#include "internal.h"
#include "nodeinfo.h"
#include "util.h"
#include "virfile.h"

#if ! (defined __linux__  &&  (defined(__x86_64__) || \
                               defined(__amd64__)  || \
                               defined(__i386__)))

int
main(void)
{
    return EXIT_AM_SKIP;
}

#else

extern int linuxNodeInfoCPUPopulate(FILE *cpuinfo, virNodeInfoPtr nodeinfo,
                                    bool need_hyperthreads);

static int
linuxTestCompareFiles(const char *cpuinfofile, const char *outputfile)
{
    int ret = -1;
    char *actualData = NULL;
    char *expectData = NULL;
    virNodeInfo nodeinfo;
    FILE *cpuinfo;

    if (virtTestLoadFile(outputfile, &expectData) < 0)
        goto fail;

    cpuinfo = fopen(cpuinfofile, "r");
    if (!cpuinfo)
        goto fail;

    memset(&nodeinfo, 0, sizeof(nodeinfo));
    if (linuxNodeInfoCPUPopulate(cpuinfo, &nodeinfo, false) < 0) {
        if (virTestGetDebug()) {
            virErrorPtr error = virSaveLastError();
            if (error && error->code != VIR_ERR_OK)
                fprintf(stderr, "\n%s\n", error->message);
            virFreeError(error);
        }
        VIR_FORCE_FCLOSE(cpuinfo);
        goto fail;
    }
    VIR_FORCE_FCLOSE(cpuinfo);

    /* 'nodes' is filled using libnuma.so from current machine
     * topology, which makes it unsuitable for the test suite
     * so blank it to a predictable value */
    nodeinfo.nodes = 1;

    if (virAsprintf(&actualData, "CPUs: %u, MHz: %u, Nodes: %u, Cores: %u\n",
                    nodeinfo.cpus, nodeinfo.mhz, nodeinfo.nodes,
                    nodeinfo.cores) < 0)
        goto fail;

    if (STRNEQ(actualData, expectData)) {
        if (getenv("DEBUG_TESTS")) {
            printf("Expect %d '%s'\n", (int)strlen(expectData), expectData);
            printf("Actual %d '%s'\n", (int)strlen(actualData), actualData);
        }
        goto fail;
    }

    ret = 0;

fail:
    free(expectData);
    free(actualData);
    return ret;
}


static int
linuxTestNodeInfo(const void *data)
{
    int result = -1;
    char *cpuinfo = NULL;
    char *output = NULL;

    if (virAsprintf(&cpuinfo, "%s/nodeinfodata/linux-%s.cpuinfo",
                    abs_srcdir, (const char*)data) < 0 ||
        virAsprintf(&output, "%s/nodeinfodata/linux-%s.txt",
                    abs_srcdir, (const char*)data) < 0) {
        goto cleanup;
    }

    result = linuxTestCompareFiles(cpuinfo, output);

cleanup:
    free(cpuinfo);
    free(output);

    return result;
}


static int
mymain(void)
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

    if (virInitialize() < 0)
        return EXIT_FAILURE;

    for (i = 0 ; i < ARRAY_CARDINALITY(nodeData); i++)
      if (virtTestRun(nodeData[i], 1, linuxTestNodeInfo, nodeData[i]) != 0)
        ret = -1;

    return(ret==0 ? EXIT_SUCCESS : EXIT_FAILURE);
}

VIRT_TEST_MAIN(mymain)

#endif /* __linux__ */
