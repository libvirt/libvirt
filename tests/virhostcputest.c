#include <config.h>

#include <unistd.h>
#include <fcntl.h>

#include "testutils.h"
#include "internal.h"
#define LIBVIRT_VIRHOSTCPUPRIV_H_ALLOW
#include "virhostcpupriv.h"
#include "virfile.h"
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
    g_autofree char *actualData = NULL;
    virNodeInfo nodeinfo = { 0 };
    g_autoptr(FILE) cpuinfo = NULL;

    cpuinfo = fopen(cpuinfofile, "r");
    if (!cpuinfo) {
        fprintf(stderr, "unable to open: %s : %s\n",
                cpuinfofile, g_strerror(errno));
        return -1;
    }

    if (virHostCPUGetInfoPopulateLinux(cpuinfo, arch,
                                       &nodeinfo.cpus, &nodeinfo.mhz,
                                       &nodeinfo.nodes, &nodeinfo.sockets,
                                       &nodeinfo.cores, &nodeinfo.threads) < 0) {
        if (virTestGetDebug()) {
            if (virGetLastErrorCode())
                VIR_TEST_DEBUG("\n%s", virGetLastErrorMessage());
        }
        return -1;
    }

    actualData = g_strdup_printf("CPUs: %u/%u, MHz: %u, Nodes: %u, Sockets: %u, "
                                 "Cores: %u, Threads: %u\n",
                                 nodeinfo.cpus, VIR_NODEINFO_MAXCPUS(nodeinfo),
                                 nodeinfo.mhz, nodeinfo.nodes, nodeinfo.sockets,
                                 nodeinfo.cores, nodeinfo.threads);

    if (virTestCompareToFile(actualData, outputfile) < 0)
        return -1;

    return 0;
}


static int
linuxCPUStatsToBuf(virBuffer *buf,
                   int cpu,
                   virNodeCPUStatsPtr param,
                   size_t nparams)
{
    size_t i = 0;
    unsigned long long tick_to_nsec;
    long long sc_clk_tck;

    if ((sc_clk_tck = sysconf(_SC_CLK_TCK)) < 0) {
        fprintf(stderr, "sysconf(_SC_CLK_TCK) fails : %s\n",
                g_strerror(errno));
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
    g_autofree char *actualData = NULL;
    g_autoptr(FILE) cpustat = NULL;
    virNodeCPUStatsPtr params = NULL;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    size_t i;
    int nparams = 0;

    if (!(cpustat = fopen(cpustatfile, "r"))) {
        virReportSystemError(errno, "failed to open '%s': ", cpustatfile);
        goto fail;
    }

    if (virHostCPUGetStatsLinux(NULL, 0, NULL, &nparams) < 0)
        goto fail;

    params = g_new0(virNodeCPUStats, nparams);

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

    actualData = virBufferContentAndReset(&buf);

    if (virTestCompareToFile(actualData, outfile) < 0)
        goto fail;

    ret = 0;

 fail:
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
    g_autofree char *cpuinfo = NULL;
    g_autofree char *sysfs_prefix = NULL;
    g_autofree char *output = NULL;
    struct linuxTestHostCPUData *data = (struct linuxTestHostCPUData *) opaque;
    const char *archStr = virArchToString(data->arch);

    sysfs_prefix = g_strdup_printf("%s/virhostcpudata/linux-%s",
                                   abs_srcdir, data->testName);
    cpuinfo = g_strdup_printf("%s/virhostcpudata/linux-%s-%s.cpuinfo",
                              abs_srcdir, archStr, data->testName);
    output = g_strdup_printf("%s/virhostcpudata/linux-%s-%s.expected",
                             abs_srcdir, archStr, data->testName);

    virFileWrapperAddPrefix(SYSFS_SYSTEM_PATH, sysfs_prefix);
    result = linuxTestCompareFiles(cpuinfo, data->arch, output);
    virFileWrapperRemovePrefix(SYSFS_SYSTEM_PATH);

    return result;
}


static int
hostCPUSignature(const void *opaque)
{
    const struct linuxTestHostCPUData *data = opaque;
    const char *arch = virArchToString(data->arch);
    g_autofree char *cpuinfo = NULL;
    g_autofree char *expected = NULL;
    g_autofree char *signature = NULL;
    g_autoptr(FILE) f = NULL;

    cpuinfo = g_strdup_printf("%s/virhostcpudata/linux-%s-%s.cpuinfo",
                              abs_srcdir, arch, data->testName);
    expected = g_strdup_printf("%s/virhostcpudata/linux-%s-%s.signature",
                               abs_srcdir, arch, data->testName);

    if (!(f = fopen(cpuinfo, "r"))) {
        virReportSystemError(errno,
                             "Failed to open cpuinfo file '%s'", cpuinfo);
        return -1;
    }

    if (virHostCPUReadSignature(data->arch, f, &signature) < 0)
        return -1;

    if (!signature && !virFileExists(expected))
        return 0;

    return virTestCompareToFile(signature, expected);
}


struct nodeCPUStatsData {
    const char *name;
    int ncpus;
    bool shouldFail;
};

static int
linuxTestNodeCPUStats(const void *data)
{
    const struct nodeCPUStatsData *testData = data;
    int result = -1;
    g_autofree char *cpustatfile = NULL;
    g_autofree g_autofree char *outfile = NULL;

    cpustatfile = g_strdup_printf("%s/virhostcpudata/linux-cpustat-%s.stat",
                                  abs_srcdir, testData->name);
    outfile = g_strdup_printf("%s/virhostcpudata/linux-cpustat-%s.out",
                              abs_srcdir, testData->name);

    result = linuxCPUStatsCompareFiles(cpustatfile,
                                       testData->ncpus,
                                       outfile);
    if (result < 0) {
        if (testData->shouldFail) {
            /* Expected error */
            result = 0;
        }
    } else {
        if (testData->shouldFail) {
            fprintf(stderr, "Expected a failure, got success");
            result = -1;
        }
    }

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
        {"with-die", VIR_ARCH_X86_64},
    };

    if (virInitialize() < 0)
        return EXIT_FAILURE;

    for (i = 0; i < G_N_ELEMENTS(nodeData); i++) {
        g_autofree char *sigTest = NULL;

        if (virTestRun(nodeData[i].testName, linuxTestHostCPU, &nodeData[i]) != 0)
            ret = -1;

        sigTest = g_strdup_printf("%s CPU signature", nodeData[i].testName);
        if (virTestRun(sigTest, hostCPUSignature, &nodeData[i]) != 0)
            ret = -1;
    }

# define DO_TEST_CPU_STATS(name, ncpus, shouldFail) \
    do { \
        static struct nodeCPUStatsData data = { name, ncpus, shouldFail}; \
        if (virTestRun("CPU stats " name, linuxTestNodeCPUStats, &data) < 0) \
            ret = -1; \
    } while (0)

    DO_TEST_CPU_STATS("24cpu", 24, false);
    DO_TEST_CPU_STATS("24cpu", 25, true);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN_PRELOAD(mymain, VIR_TEST_MOCK("virhostcpu"))

#endif /* __linux__ */
