#include <config.h>

#include <unistd.h>

#include "testutils.h"
#include "internal.h"
#define LIBVIRT_VIRHOSTCPUPRIV_H_ALLOW
#include "virhostcpupriv.h"
#include "virfile.h"
#include "virstring.h"
#include "virfilewrapper.h"

#define VIR_FROM_THIS VIR_FROM_NONE

#define SYSFS_SYSTEM_PATH "/sys/devices/system"

#if !(defined __linux__)

int
main(void)
{
    return EXIT_AM_SKIP;
}

#else

static int
linuxTestCompareFiles(const char *cpuinfofile,
                      virArch arch,
                      const char *outputfile)
{
    int ret = -1;
    char *actualData = NULL;
    virNodeInfo nodeinfo;
    FILE *cpuinfo;

    cpuinfo = fopen(cpuinfofile, "r");
    if (!cpuinfo) {
        fprintf(stderr, "unable to open: %s : %s\n",
                cpuinfofile, strerror(errno));
        goto fail;
    }

    memset(&nodeinfo, 0, sizeof(nodeinfo));
    if (virHostCPUGetInfoPopulateLinux(cpuinfo, arch,
                                       &nodeinfo.cpus, &nodeinfo.mhz,
                                       &nodeinfo.nodes, &nodeinfo.sockets,
                                       &nodeinfo.cores, &nodeinfo.threads) < 0) {
        if (virTestGetDebug()) {
            if (virGetLastErrorCode())
                VIR_TEST_DEBUG("\n%s\n", virGetLastErrorMessage());
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

    if (virTestCompareToFile(actualData, outputfile) < 0)
        goto fail;

    ret = 0;

 fail:
    VIR_FREE(actualData);
    return ret;
}


static int
linuxCPUStatsToBuf(virBufferPtr buf,
                   int cpu,
                   virNodeCPUStatsPtr param,
                   size_t nparams)
{
    size_t i = 0;
    unsigned long long tick_to_nsec;
    long long sc_clk_tck;

    if ((sc_clk_tck = sysconf(_SC_CLK_TCK)) < 0) {
        fprintf(stderr, "sysconf(_SC_CLK_TCK) fails : %s\n",
                strerror(errno));
        return -1;
    }
    tick_to_nsec = (1000ull * 1000ull * 1000ull) / sc_clk_tck;

    if (cpu < 0)
        virBufferAddLit(buf, "cpu:\n");
    else
        virBufferAsprintf(buf, "cpu%d:\n", cpu);

    for (i = 0; i < nparams; i++)
        virBufferAsprintf(buf, "%s: %llu\n", param[i].field,
                          param[i].value / tick_to_nsec);

    virBufferAddChar(buf, '\n');
    return 0;
}

static int
linuxCPUStatsCompareFiles(const char *cpustatfile,
                          size_t ncpus,
                          const char *outfile)
{
    int ret = -1;
    char *actualData = NULL;
    FILE *cpustat = NULL;
    virNodeCPUStatsPtr params = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    size_t i;
    int nparams = 0;

    if (!(cpustat = fopen(cpustatfile, "r"))) {
        virReportSystemError(errno, "failed to open '%s': ", cpustatfile);
        goto fail;
    }

    if (virHostCPUGetStatsLinux(NULL, 0, NULL, &nparams) < 0)
        goto fail;

    if (VIR_ALLOC_N(params, nparams) < 0)
        goto fail;

    if (virHostCPUGetStatsLinux(cpustat, VIR_NODE_CPU_STATS_ALL_CPUS, params,
                                &nparams) < 0)
        goto fail;

    if (linuxCPUStatsToBuf(&buf, VIR_NODE_CPU_STATS_ALL_CPUS,
                           params, nparams) < 0)
        goto fail;

    for (i = 0; i < ncpus; i++) {
        if (virHostCPUGetStatsLinux(cpustat, i, params, &nparams) < 0)
            goto fail;
        if (linuxCPUStatsToBuf(&buf, i, params, nparams) < 0)
            goto fail;
    }

    if (!(actualData = virBufferContentAndReset(&buf))) {
        virReportOOMError();
        goto fail;
    }

    if (virTestCompareToFile(actualData, outfile) < 0)
        goto fail;

    ret = 0;

 fail:
    virBufferFreeAndReset(&buf);
    VIR_FORCE_FCLOSE(cpustat);
    VIR_FREE(actualData);
    VIR_FREE(params);
    return ret;
}


struct linuxTestHostCPUData {
    const char *testName;
    virArch arch;
};

static int
linuxTestHostCPU(const void *opaque)
{
    int result = -1;
    char *cpuinfo = NULL;
    char *sysfs_prefix = NULL;
    char *output = NULL;
    struct linuxTestHostCPUData *data = (struct linuxTestHostCPUData *) opaque;
    const char *archStr = virArchToString(data->arch);

    if (virAsprintf(&sysfs_prefix, "%s/virhostcpudata/linux-%s",
                    abs_srcdir, data->testName) < 0 ||
        virAsprintf(&cpuinfo, "%s/virhostcpudata/linux-%s-%s.cpuinfo",
                    abs_srcdir, archStr, data->testName) < 0 ||
        virAsprintf(&output, "%s/virhostcpudata/linux-%s-%s.expected",
                    abs_srcdir, archStr, data->testName) < 0) {
        goto cleanup;
    }

    virFileWrapperAddPrefix(SYSFS_SYSTEM_PATH, sysfs_prefix);
    result = linuxTestCompareFiles(cpuinfo, data->arch, output);
    virFileWrapperRemovePrefix(SYSFS_SYSTEM_PATH);

 cleanup:
    VIR_FREE(cpuinfo);
    VIR_FREE(output);
    VIR_FREE(sysfs_prefix);

    return result;
}

struct nodeCPUStatsData {
    const char *name;
    int ncpus;
};

static int
linuxTestNodeCPUStats(const void *data)
{
    const struct nodeCPUStatsData *testData = data;
    int result = -1;
    char *cpustatfile = NULL;
    char *outfile = NULL;

    if (virAsprintf(&cpustatfile, "%s/virhostcpudata/linux-cpustat-%s.stat",
                    abs_srcdir, testData->name) < 0 ||
        virAsprintf(&outfile, "%s/virhostcpudata/linux-cpustat-%s.out",
                    abs_srcdir, testData->name) < 0)
        goto fail;

    result = linuxCPUStatsCompareFiles(cpustatfile,
                                       testData->ncpus,
                                       outfile);
 fail:
    VIR_FREE(cpustatfile);
    VIR_FREE(outfile);
    return result;
}


static int
mymain(void)
{
    int ret = 0;
    size_t i;
    const struct linuxTestHostCPUData nodeData[] = {
        {"test1", VIR_ARCH_X86_64},
        {"test1", VIR_ARCH_PPC},
        {"test2", VIR_ARCH_X86_64},
        {"test3", VIR_ARCH_X86_64},
        {"test4", VIR_ARCH_X86_64},
        {"test5", VIR_ARCH_X86_64},
        {"test6", VIR_ARCH_X86_64},
        {"test7", VIR_ARCH_X86_64},
        {"test8", VIR_ARCH_X86_64},
        {"raspberrypi", VIR_ARCH_ARMV6L},
        {"f21-mustang", VIR_ARCH_AARCH64},
        {"rhelsa-3.19.0-mustang", VIR_ARCH_AARCH64},
        {"rhel74-moonshot", VIR_ARCH_AARCH64},
        {"high-ids", VIR_ARCH_AARCH64},
        {"deconf-cpus", VIR_ARCH_PPC64},
        /* subcores, default configuration */
        {"subcores1", VIR_ARCH_PPC64},
        /* subcores, some of the cores are offline */
        {"subcores2", VIR_ARCH_PPC64},
        /* subcores, invalid configuration */
        {"subcores3", VIR_ARCH_PPC64},
        {"with-frequency", VIR_ARCH_S390X},
    };

    if (virInitialize() < 0)
        return EXIT_FAILURE;

    for (i = 0; i < ARRAY_CARDINALITY(nodeData); i++)
        if (virTestRun(nodeData[i].testName, linuxTestHostCPU, &nodeData[i]) != 0)
            ret = -1;

# define DO_TEST_CPU_STATS(name, ncpus) \
    do { \
        static struct nodeCPUStatsData data = { name, ncpus }; \
        if (virTestRun("CPU stats " name, linuxTestNodeCPUStats, &data) < 0) \
            ret = -1; \
    } while (0)

    DO_TEST_CPU_STATS("24cpu", 24);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN_PRELOAD(mymain, abs_builddir "/.libs/virhostcpumock.so")

#endif /* __linux__ */
