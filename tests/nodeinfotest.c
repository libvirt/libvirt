#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "testutils.h"
#include "internal.h"
#include "nodeinfo.h"
#include "virfile.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NONE

#if ! (defined __linux__  &&  (defined(__x86_64__) || \
                               defined(__amd64__)  || \
                               defined(__i386__)  || \
                               defined(__powerpc__)  || \
                               defined(__powerpc64__)))

int
main(void)
{
    return EXIT_AM_SKIP;
}

#else

extern int linuxNodeInfoCPUPopulate(FILE *cpuinfo,
                                    char *sysfs_dir,
                                    virNodeInfoPtr nodeinfo);

static int
linuxTestCompareFiles(const char *cpuinfofile,
                      char *sysfs_dir,
                      const char *outputfile)
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
    if (linuxNodeInfoCPUPopulate(cpuinfo, sysfs_dir, &nodeinfo) < 0) {
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

    if (virAsprintf(&actualData,
                    "CPUs: %u/%u, MHz: %u, Nodes: %u, Sockets: %u, "
                    "Cores: %u, Threads: %u\n",
                    nodeinfo.cpus, VIR_NODEINFO_MAXCPUS(nodeinfo),
                    nodeinfo.mhz, nodeinfo.nodes, nodeinfo.sockets,
                    nodeinfo.cores, nodeinfo.threads) < 0)
        goto fail;

    if (STRNEQ(actualData, expectData)) {
        virtTestDifference(stderr, expectData, actualData);
        goto fail;
    }

    ret = 0;

fail:
    VIR_FREE(expectData);
    VIR_FREE(actualData);
    return ret;
}


static int
linuxTestNodeInfo(const void *data)
{
    int result = -1;
    char *cpuinfo = NULL;
    char *sysfs_dir = NULL;
    char *output = NULL;
    const char *test = data;
    const char *arch = "x86";

# if defined(__powerpc__) || \
     defined(__powerpc64__)
    arch = "ppc";
# endif

    if (virAsprintf(&sysfs_dir, "%s/nodeinfodata/linux-%s",
                    abs_srcdir, test) < 0 ||
        virAsprintf(&cpuinfo, "%s/nodeinfodata/linux-%s-%s.cpuinfo",
                    abs_srcdir, arch, test) < 0 ||
        virAsprintf(&output, "%s/nodeinfodata/linux-%s-%s.expected",
                    abs_srcdir, arch, test) < 0) {
        goto cleanup;
    }

    result = linuxTestCompareFiles(cpuinfo, sysfs_dir, output);

cleanup:
    VIR_FREE(cpuinfo);
    VIR_FREE(output);
    VIR_FREE(sysfs_dir);

    return result;
}


static int
mymain(void)
{
    int ret = 0;
    size_t i;
    const char *nodeData[] = {
        "test1",
# if !(defined(__powerpc__) ||                  \
       defined(__powerpc64__))
        "test2",
        "test3",
        "test4",
        "test5",
        "test6",
        "test7",
        "test8",
# endif
    };

    if (virInitialize() < 0)
        return EXIT_FAILURE;

    for (i = 0; i < ARRAY_CARDINALITY(nodeData); i++)
      if (virtTestRun(nodeData[i], 1, linuxTestNodeInfo, nodeData[i]) != 0)
        ret = -1;

    return ret==0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)

#endif /* __linux__ */
