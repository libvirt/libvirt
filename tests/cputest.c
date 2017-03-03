/*
 * cputest.c: Test the libvirtd internal CPU APIs
 *
 * Copyright (C) 2010-2014 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Author: Jiri Denemark <jdenemar@redhat.com>
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <fcntl.h>

#include "internal.h"
#include "virxml.h"
#include "viralloc.h"
#include "virbuffer.h"
#include "testutils.h"
#include "cpu_conf.h"
#include "cpu/cpu.h"
#include "cpu/cpu_map.h"
#include "virstring.h"

#if WITH_QEMU && WITH_YAJL
# include "testutilsqemu.h"
# include "qemumonitortestutils.h"
# define __QEMU_CAPSRIV_H_ALLOW__
# include "qemu/qemu_capspriv.h"
# undef __QEMU_CAPSRIV_H_ALLOW__
#endif

#define VIR_FROM_THIS VIR_FROM_CPU

enum cpuTestBoolWithError {
    FAIL    = -1,
    NO      = 0,
    YES     = 1
};


struct data {
    virArch arch;
    const char *host;
    const char *name;
    const char **models;
    const char *modelsName;
    unsigned int nmodels;
    unsigned int flags;
    int result;
};

#if WITH_QEMU && WITH_YAJL
static virQEMUDriver driver;
#endif


static virCPUDefPtr
cpuTestLoadXML(virArch arch, const char *name)
{
    char *xml = NULL;
    xmlDocPtr doc = NULL;
    xmlXPathContextPtr ctxt = NULL;
    virCPUDefPtr cpu = NULL;

    if (virAsprintf(&xml, "%s/cputestdata/%s-%s.xml",
                    abs_srcdir, virArchToString(arch), name) < 0)
        goto cleanup;

    if (!(doc = virXMLParseFileCtxt(xml, &ctxt)))
        goto cleanup;

    cpu = virCPUDefParseXML(ctxt->node, ctxt, VIR_CPU_TYPE_AUTO);

 cleanup:
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(doc);
    VIR_FREE(xml);
    return cpu;
}


static virCPUDefPtr *
cpuTestLoadMultiXML(virArch arch,
                    const char *name,
                    unsigned int *count)
{
    char *xml = NULL;
    xmlDocPtr doc = NULL;
    xmlXPathContextPtr ctxt = NULL;
    xmlNodePtr *nodes = NULL;
    virCPUDefPtr *cpus = NULL;
    int n;
    size_t i;

    if (virAsprintf(&xml, "%s/cputestdata/%s-%s.xml",
                    abs_srcdir, virArchToString(arch), name) < 0)
        goto cleanup;

    if (!(doc = virXMLParseFileCtxt(xml, &ctxt)))
        goto cleanup;

    n = virXPathNodeSet("/cpuTest/cpu", ctxt, &nodes);
    if (n <= 0 || (VIR_ALLOC_N(cpus, n) < 0)) {
        fprintf(stderr, "\nNo /cpuTest/cpu elements found in %s\n", xml);
        goto cleanup;
    }

    for (i = 0; i < n; i++) {
        ctxt->node = nodes[i];
        cpus[i] = virCPUDefParseXML(nodes[i], ctxt, VIR_CPU_TYPE_HOST);
        if (!cpus[i])
            goto cleanup_cpus;
    }

    *count = n;

 cleanup:
    VIR_FREE(xml);
    VIR_FREE(nodes);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(doc);
    return cpus;

 cleanup_cpus:
    for (i = 0; i < n; i++)
        virCPUDefFree(cpus[i]);
    VIR_FREE(cpus);
    goto cleanup;
}


static int
cpuTestCompareXML(virArch arch,
                  virCPUDef *cpu,
                  const char *name,
                  bool updateCPU)
{
    char *xml = NULL;
    char *actual = NULL;
    int ret = -1;

    if (virAsprintf(&xml, "%s/cputestdata/%s-%s.xml",
                    abs_srcdir, virArchToString(arch), name) < 0)
        goto cleanup;

    if (!(actual = virCPUDefFormat(cpu, NULL, updateCPU)))
        goto cleanup;

    if (virTestCompareToFile(actual, xml) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    VIR_FREE(xml);
    VIR_FREE(actual);
    return ret;
}


static const char *
cpuTestCompResStr(virCPUCompareResult result)
{
    switch (result) {
    case VIR_CPU_COMPARE_ERROR:         return "ERROR";
    case VIR_CPU_COMPARE_INCOMPATIBLE:  return "INCOMPATIBLE";
    case VIR_CPU_COMPARE_IDENTICAL:     return "IDENTICAL";
    case VIR_CPU_COMPARE_SUPERSET:      return "SUPERSET";
    case VIR_CPU_COMPARE_LAST:          break;
    }

    return "unknown";
}


static const char *
cpuTestBoolWithErrorStr(enum cpuTestBoolWithError result)
{
    switch (result) {
    case FAIL:  return "FAIL";
    case NO:    return "NO";
    case YES:   return "YES";
    }

    return "unknown";
}


static int
cpuTestCompare(const void *arg)
{
    const struct data *data = arg;
    int ret = -1;
    virCPUDefPtr host = NULL;
    virCPUDefPtr cpu = NULL;
    virCPUCompareResult result;

    if (!(host = cpuTestLoadXML(data->arch, data->host)) ||
        !(cpu = cpuTestLoadXML(data->arch, data->name)))
        goto cleanup;

    result = virCPUCompare(host->arch, host, cpu, false);
    if (data->result == VIR_CPU_COMPARE_ERROR)
        virResetLastError();

    if (data->result != result) {
        VIR_TEST_VERBOSE("\nExpected result %s, got %s\n",
                    cpuTestCompResStr(data->result),
                    cpuTestCompResStr(result));
        /* Pad to line up with test name ... in virTestRun */
        VIR_TEST_VERBOSE("%74s", "... ");
        goto cleanup;
    }

    ret = 0;

 cleanup:
    virCPUDefFree(host);
    virCPUDefFree(cpu);
    return ret;
}


static int
cpuTestGuestCPU(const void *arg)
{
    const struct data *data = arg;
    int ret = -2;
    virCPUDefPtr host = NULL;
    virCPUDefPtr cpu = NULL;
    virCPUCompareResult cmpResult;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char *result = NULL;

    if (!(host = cpuTestLoadXML(data->arch, data->host)) ||
        !(cpu = cpuTestLoadXML(data->arch, data->name)))
        goto cleanup;

    if (virCPUConvertLegacy(host->arch, cpu) < 0)
        goto cleanup;

    cmpResult = virCPUCompare(host->arch, host, cpu, false);
    if (cmpResult == VIR_CPU_COMPARE_ERROR ||
        cmpResult == VIR_CPU_COMPARE_INCOMPATIBLE) {
        ret = -1;
        goto cleanup;
    }

    if (virCPUUpdate(host->arch, cpu, host) < 0 ||
        virCPUTranslate(host->arch, cpu, data->models, data->nmodels) < 0) {
        ret = -1;
        goto cleanup;
    }

    virBufferAsprintf(&buf, "%s+%s", data->host, data->name);
    if (data->nmodels)
        virBufferAsprintf(&buf, ",%s", data->modelsName);
    virBufferAddLit(&buf, "-result");

    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        goto cleanup;
    }
    result = virBufferContentAndReset(&buf);

    if (cpuTestCompareXML(data->arch, cpu, result, false) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    VIR_FREE(result);
    virCPUDefFree(host);
    virCPUDefFree(cpu);

    if (ret == data->result) {
        /* We got the result we expected, whether it was
         * a success or a failure */
        virResetLastError();
        ret = 0;
    } else {
        VIR_TEST_VERBOSE("\nExpected result %d, got %d\n",
                         data->result, ret);
        /* Pad to line up with test name ... in virTestRun */
        VIR_TEST_VERBOSE("%74s", "... ");
        ret = -1;
    }

    return ret;
}


static int
cpuTestBaseline(const void *arg)
{
    const struct data *data = arg;
    int ret = -1;
    virCPUDefPtr *cpus = NULL;
    virCPUDefPtr baseline = NULL;
    unsigned int ncpus = 0;
    char *result = NULL;
    const char *suffix;
    size_t i;

    if (!(cpus = cpuTestLoadMultiXML(data->arch, data->name, &ncpus)))
        goto cleanup;

    baseline = cpuBaseline(cpus, ncpus, NULL, 0, data->flags);
    if (data->result < 0) {
        virResetLastError();
        if (!baseline) {
            ret = 0;
        } else {
            VIR_TEST_VERBOSE("\n%-70s... ",
                    "cpuBaseline was expected to fail but it succeeded");
        }
        goto cleanup;
    }
    if (!baseline)
        goto cleanup;

    if (data->flags & VIR_CONNECT_BASELINE_CPU_EXPAND_FEATURES)
        suffix = "expanded";
    else if (data->flags & VIR_CONNECT_BASELINE_CPU_MIGRATABLE)
        suffix = "migratable";
    else
        suffix = "result";
    if (virAsprintf(&result, "%s-%s", data->name, suffix) < 0)
        goto cleanup;

    if (cpuTestCompareXML(data->arch, baseline, result, false) < 0)
        goto cleanup;

    for (i = 0; i < ncpus; i++) {
        virCPUCompareResult cmp;

        cmp = virCPUCompare(cpus[i]->arch, cpus[i], baseline, false);
        if (cmp != VIR_CPU_COMPARE_SUPERSET &&
            cmp != VIR_CPU_COMPARE_IDENTICAL) {
            VIR_TEST_VERBOSE("\nbaseline CPU is incompatible with CPU %zu\n",
                             i);
            VIR_TEST_VERBOSE("%74s", "... ");
            ret = -1;
            goto cleanup;
        }
    }

    ret = 0;

 cleanup:
    if (cpus) {
        for (i = 0; i < ncpus; i++)
            virCPUDefFree(cpus[i]);
        VIR_FREE(cpus);
    }
    virCPUDefFree(baseline);
    VIR_FREE(result);
    return ret;
}


static int
cpuTestUpdate(const void *arg)
{
    const struct data *data = arg;
    int ret = -1;
    virCPUDefPtr host = NULL;
    virCPUDefPtr cpu = NULL;
    char *result = NULL;

    if (!(host = cpuTestLoadXML(data->arch, data->host)) ||
        !(cpu = cpuTestLoadXML(data->arch, data->name)))
        goto cleanup;

    if (virCPUUpdate(host->arch, cpu, host) < 0)
        goto cleanup;

    if (virAsprintf(&result, "%s+%s", data->host, data->name) < 0)
        goto cleanup;

    ret = cpuTestCompareXML(data->arch, cpu, result, true);

 cleanup:
    virCPUDefFree(host);
    virCPUDefFree(cpu);
    VIR_FREE(result);
    return ret;
}


static int
cpuTestHasFeature(const void *arg)
{
    const struct data *data = arg;
    int ret = -1;
    virCPUDefPtr host = NULL;
    virCPUDataPtr hostData = NULL;
    int result;

    if (!(host = cpuTestLoadXML(data->arch, data->host)))
        goto cleanup;

    if (cpuEncode(host->arch, host, NULL, &hostData,
                  NULL, NULL, NULL, NULL) < 0)
        goto cleanup;

    result = virCPUCheckFeature(host->arch, host, data->name);

    if (data->result == result)
        result = virCPUDataCheckFeature(hostData, data->name);

    if (data->result == -1)
        virResetLastError();

    if (data->result != result) {
        VIR_TEST_VERBOSE("\nExpected result %s, got %s\n",
            cpuTestBoolWithErrorStr(data->result),
            cpuTestBoolWithErrorStr(result));
        /* Pad to line up with test name ... in virTestRun */
        VIR_TEST_VERBOSE("%74s", "... ");
        goto cleanup;
    }

    ret = 0;

 cleanup:
    virCPUDataFree(hostData);
    virCPUDefFree(host);
    return ret;
}


static int
cpuTestCPUID(bool guest, const void *arg)
{
    const struct data *data = arg;
    int ret = -1;
    virCPUDataPtr hostData = NULL;
    char *hostFile = NULL;
    char *host = NULL;
    virCPUDefPtr cpu = NULL;
    char *result = NULL;

    if (virAsprintf(&hostFile, "%s/cputestdata/%s-cpuid-%s.xml",
                    abs_srcdir, virArchToString(data->arch), data->host) < 0)
        goto cleanup;

    if (virTestLoadFile(hostFile, &host) < 0 ||
        !(hostData = virCPUDataParse(host)))
        goto cleanup;

    if (VIR_ALLOC(cpu) < 0)
        goto cleanup;

    cpu->arch = hostData->arch;
    if (guest) {
        cpu->type = VIR_CPU_TYPE_GUEST;
        cpu->match = VIR_CPU_MATCH_EXACT;
        cpu->fallback = VIR_CPU_FALLBACK_FORBID;
    } else {
        cpu->type = VIR_CPU_TYPE_HOST;
    }

    if (cpuDecode(cpu, hostData, NULL, 0, NULL) < 0)
        goto cleanup;

    if (virAsprintf(&result, "cpuid-%s-%s",
                    data->host,
                    guest ? "guest" : "host") < 0)
        goto cleanup;

    ret = cpuTestCompareXML(data->arch, cpu, result, false);

 cleanup:
    VIR_FREE(hostFile);
    VIR_FREE(host);
    virCPUDataFree(hostData);
    virCPUDefFree(cpu);
    VIR_FREE(result);
    return ret;
}


static int
cpuTestHostCPUID(const void *arg)
{
    return cpuTestCPUID(false, arg);
}


static int
cpuTestGuestCPUID(const void *arg)
{
    return cpuTestCPUID(true, arg);
}


#if WITH_QEMU && WITH_YAJL
static int
cpuTestJSONCPUID(const void *arg)
{
    const struct data *data = arg;
    qemuMonitorCPUModelInfoPtr model = NULL;
    virQEMUCapsPtr qemuCaps = NULL;
    virCPUDefPtr cpu = NULL;
    qemuMonitorTestPtr testMon = NULL;
    char *json = NULL;
    char *result = NULL;
    int ret = -1;

    if (virAsprintf(&json, "%s/cputestdata/%s-cpuid-%s.json",
                    abs_srcdir, virArchToString(data->arch), data->host) < 0 ||
        virAsprintf(&result, "cpuid-%s-json", data->host) < 0)
        goto cleanup;

    if (!(testMon = qemuMonitorTestNewFromFile(json, driver.xmlopt, true)))
        goto cleanup;

    if (qemuMonitorGetCPUModelExpansion(qemuMonitorTestGetMonitor(testMon),
                                        QEMU_MONITOR_CPU_MODEL_EXPANSION_STATIC,
                                        "host", &model) < 0)
        goto cleanup;

    if (!(qemuCaps = virQEMUCapsNew()))
        goto cleanup;

    virQEMUCapsSetArch(qemuCaps, data->arch);
    virQEMUCapsSetCPUModelInfo(qemuCaps, VIR_DOMAIN_VIRT_KVM, model);
    model = NULL;

    if (VIR_ALLOC(cpu) < 0)
        goto cleanup;

    cpu->arch = data->arch;
    cpu->type = VIR_CPU_TYPE_GUEST;
    cpu->match = VIR_CPU_MATCH_EXACT;
    cpu->fallback = VIR_CPU_FALLBACK_FORBID;

    if (virQEMUCapsInitCPUModel(qemuCaps, VIR_DOMAIN_VIRT_KVM, cpu) != 0)
        goto cleanup;

    ret = cpuTestCompareXML(data->arch, cpu, result, false);

 cleanup:
    qemuMonitorCPUModelInfoFree(model);
    virObjectUnref(qemuCaps);
    qemuMonitorTestFree(testMon);
    virCPUDefFree(cpu);
    VIR_FREE(result);
    VIR_FREE(json);
    return ret;
}
#endif


static const char *model486[]   = { "486" };
static const char *nomodel[]    = { "nomodel" };
static const char *models[]     = { "qemu64", "core2duo", "Nehalem" };
static const char *haswell[]    = { "SandyBridge", "Haswell" };
static const char *ppc_models[] = { "POWER6", "POWER7", "POWER8" };

static int
mymain(void)
{
    int ret = 0;

#if WITH_QEMU && WITH_YAJL
    if (qemuTestDriverInit(&driver) < 0)
        return EXIT_FAILURE;

    virEventRegisterDefaultImpl();
#endif

#define DO_TEST(arch, api, name, host, cpu,                             \
                models, nmodels, flags, result)                         \
    do {                                                                \
        struct data data = {                                            \
            arch, host, cpu, models,                                    \
            models == NULL ? NULL : #models,                            \
            nmodels, flags, result                                      \
        };                                                              \
        char *testLabel;                                                \
        char *tmp;                                                      \
                                                                        \
        tmp = virTestLogContentAndReset();                              \
        VIR_FREE(tmp);                                                  \
                                                                        \
        if (virAsprintf(&testLabel, "%s(%s): %s",                       \
                        #api, virArchToString(arch), name) < 0) {       \
            ret = -1;                                                   \
            break;                                                      \
        }                                                               \
                                                                        \
        if (virTestRun(testLabel, api, &data) < 0) {                    \
            if (virTestGetDebug()) {                                    \
                char *log;                                              \
                if ((log = virTestLogContentAndReset()) &&              \
                     strlen(log) > 0)                                   \
                    VIR_TEST_DEBUG("\n%s\n", log);                      \
                VIR_FREE(log);                                          \
            }                                                           \
            ret = -1;                                                   \
        }                                                               \
                                                                        \
        VIR_FREE(testLabel);                                            \
    } while (0)

#define DO_TEST_COMPARE(arch, host, cpu, result)                        \
    DO_TEST(arch, cpuTestCompare,                                       \
            host "/" cpu " (" #result ")",                              \
            host, cpu, NULL, 0, 0, result)

#define DO_TEST_UPDATE_ONLY(arch, host, cpu)                            \
    DO_TEST(arch, cpuTestUpdate,                                        \
            cpu " on " host,                                            \
            host, cpu, NULL, 0, 0, 0)

#define DO_TEST_UPDATE(arch, host, cpu, result)                         \
    do {                                                                \
        DO_TEST_UPDATE_ONLY(arch, host, cpu);                           \
        DO_TEST_COMPARE(arch, host, host "+" cpu, result);              \
    } while (0)

#define DO_TEST_BASELINE(arch, name, flags, result)                     \
    do {                                                                \
        const char *suffix = "";                                        \
        char *label;                                                    \
        if ((flags) & VIR_CONNECT_BASELINE_CPU_EXPAND_FEATURES)         \
            suffix = " (expanded)";                                     \
        if ((flags) & VIR_CONNECT_BASELINE_CPU_MIGRATABLE)              \
            suffix = " (migratable)";                                   \
        if (virAsprintf(&label, "%s%s", name, suffix) < 0) {            \
            ret = -1;                                                   \
        } else {                                                        \
            DO_TEST(arch, cpuTestBaseline, label, NULL,                 \
                    "baseline-" name, NULL, 0, flags, result);          \
        }                                                               \
        VIR_FREE(label);                                                \
    } while (0)

#define DO_TEST_HASFEATURE(arch, host, feature, result)                 \
    DO_TEST(arch, cpuTestHasFeature,                                    \
            host "/" feature " (" #result ")",                          \
            host, feature, NULL, 0, 0, result)

#define DO_TEST_GUESTCPU(arch, host, cpu, models, result)               \
    DO_TEST(arch, cpuTestGuestCPU,                                      \
            host "/" cpu " (" #models ")",                              \
            host, cpu, models,                                          \
            models == NULL ? 0 : sizeof(models) / sizeof(char *),       \
            0, result)

#if WITH_QEMU && WITH_YAJL
# define DO_TEST_CPUID_JSON(arch, host, json)                           \
    do {                                                                \
        if (json) {                                                     \
            DO_TEST(arch, cpuTestJSONCPUID, host, host,                 \
                    NULL, NULL, 0, 0, 0);                               \
        }                                                               \
    } while (0)
#else
# define DO_TEST_CPUID_JSON(arch, host, json)
#endif

#define DO_TEST_CPUID(arch, host, json)                                 \
    do {                                                                \
        DO_TEST(arch, cpuTestHostCPUID, host, host,                     \
                NULL, NULL, 0, 0, 0);                                   \
        DO_TEST(arch, cpuTestGuestCPUID, host, host,                    \
                NULL, NULL, 0, 0, 0);                                   \
        DO_TEST_CPUID_JSON(arch, host, json);                           \
    } while (0)

    /* host to host comparison */
    DO_TEST_COMPARE(VIR_ARCH_X86_64, "host", "host", VIR_CPU_COMPARE_IDENTICAL);
    DO_TEST_COMPARE(VIR_ARCH_X86_64, "host", "host-better", VIR_CPU_COMPARE_INCOMPATIBLE);
    DO_TEST_COMPARE(VIR_ARCH_X86_64, "host", "host-worse", VIR_CPU_COMPARE_SUPERSET);
    DO_TEST_COMPARE(VIR_ARCH_X86_64, "host", "host-amd-fake", VIR_CPU_COMPARE_INCOMPATIBLE);
    DO_TEST_COMPARE(VIR_ARCH_X86_64, "host", "host-incomp-arch", VIR_CPU_COMPARE_INCOMPATIBLE);
    DO_TEST_COMPARE(VIR_ARCH_X86_64, "host", "host-no-vendor", VIR_CPU_COMPARE_IDENTICAL);
    DO_TEST_COMPARE(VIR_ARCH_X86_64, "host-no-vendor", "host", VIR_CPU_COMPARE_INCOMPATIBLE);

    DO_TEST_COMPARE(VIR_ARCH_PPC64, "host", "host", VIR_CPU_COMPARE_IDENTICAL);
    DO_TEST_COMPARE(VIR_ARCH_PPC64, "host", "host-better", VIR_CPU_COMPARE_INCOMPATIBLE);
    DO_TEST_COMPARE(VIR_ARCH_PPC64, "host", "host-worse", VIR_CPU_COMPARE_INCOMPATIBLE);
    DO_TEST_COMPARE(VIR_ARCH_PPC64, "host", "host-incomp-arch", VIR_CPU_COMPARE_INCOMPATIBLE);
    DO_TEST_COMPARE(VIR_ARCH_PPC64, "host", "host-no-vendor", VIR_CPU_COMPARE_IDENTICAL);
    DO_TEST_COMPARE(VIR_ARCH_PPC64, "host-no-vendor", "host", VIR_CPU_COMPARE_INCOMPATIBLE);

    /* guest to host comparison */
    DO_TEST_COMPARE(VIR_ARCH_X86_64, "host", "bogus-model", VIR_CPU_COMPARE_ERROR);
    DO_TEST_COMPARE(VIR_ARCH_X86_64, "host", "bogus-feature", VIR_CPU_COMPARE_ERROR);
    DO_TEST_COMPARE(VIR_ARCH_X86_64, "host", "min", VIR_CPU_COMPARE_SUPERSET);
    DO_TEST_COMPARE(VIR_ARCH_X86_64, "host", "pentium3", VIR_CPU_COMPARE_SUPERSET);
    DO_TEST_COMPARE(VIR_ARCH_X86_64, "host", "exact", VIR_CPU_COMPARE_SUPERSET);
    DO_TEST_COMPARE(VIR_ARCH_X86_64, "host", "exact-forbid", VIR_CPU_COMPARE_INCOMPATIBLE);
    DO_TEST_COMPARE(VIR_ARCH_X86_64, "host", "exact-forbid-extra", VIR_CPU_COMPARE_SUPERSET);
    DO_TEST_COMPARE(VIR_ARCH_X86_64, "host", "exact-disable", VIR_CPU_COMPARE_SUPERSET);
    DO_TEST_COMPARE(VIR_ARCH_X86_64, "host", "exact-disable2", VIR_CPU_COMPARE_SUPERSET);
    DO_TEST_COMPARE(VIR_ARCH_X86_64, "host", "exact-disable-extra", VIR_CPU_COMPARE_SUPERSET);
    DO_TEST_COMPARE(VIR_ARCH_X86_64, "host", "exact-require", VIR_CPU_COMPARE_SUPERSET);
    DO_TEST_COMPARE(VIR_ARCH_X86_64, "host", "exact-require-extra", VIR_CPU_COMPARE_INCOMPATIBLE);
    DO_TEST_COMPARE(VIR_ARCH_X86_64, "host", "exact-force", VIR_CPU_COMPARE_SUPERSET);
    DO_TEST_COMPARE(VIR_ARCH_X86_64, "host", "strict", VIR_CPU_COMPARE_INCOMPATIBLE);
    DO_TEST_COMPARE(VIR_ARCH_X86_64, "host", "strict-full", VIR_CPU_COMPARE_IDENTICAL);
    DO_TEST_COMPARE(VIR_ARCH_X86_64, "host", "strict-disable", VIR_CPU_COMPARE_IDENTICAL);
    DO_TEST_COMPARE(VIR_ARCH_X86_64, "host", "strict-force-extra", VIR_CPU_COMPARE_IDENTICAL);
    DO_TEST_COMPARE(VIR_ARCH_X86_64, "host", "guest", VIR_CPU_COMPARE_SUPERSET);
    DO_TEST_COMPARE(VIR_ARCH_X86_64, "host", "pentium3-amd", VIR_CPU_COMPARE_INCOMPATIBLE);
    DO_TEST_COMPARE(VIR_ARCH_X86_64, "host-amd", "pentium3-amd", VIR_CPU_COMPARE_SUPERSET);
    DO_TEST_COMPARE(VIR_ARCH_X86_64, "host-worse", "penryn-force", VIR_CPU_COMPARE_IDENTICAL);
    DO_TEST_COMPARE(VIR_ARCH_X86_64, "host-SandyBridge", "exact-force-Haswell", VIR_CPU_COMPARE_IDENTICAL);

    DO_TEST_COMPARE(VIR_ARCH_PPC64, "host", "guest-strict", VIR_CPU_COMPARE_IDENTICAL);
    DO_TEST_COMPARE(VIR_ARCH_PPC64, "host", "guest-exact", VIR_CPU_COMPARE_INCOMPATIBLE);
    DO_TEST_COMPARE(VIR_ARCH_PPC64, "host", "guest-legacy", VIR_CPU_COMPARE_IDENTICAL);
    DO_TEST_COMPARE(VIR_ARCH_PPC64, "host", "guest-legacy-incompatible", VIR_CPU_COMPARE_INCOMPATIBLE);
    DO_TEST_COMPARE(VIR_ARCH_PPC64, "host", "guest-legacy-invalid", VIR_CPU_COMPARE_ERROR);
    DO_TEST_COMPARE(VIR_ARCH_PPC64, "host", "guest-compat-none", VIR_CPU_COMPARE_IDENTICAL);
    DO_TEST_COMPARE(VIR_ARCH_PPC64, "host", "guest-compat-valid", VIR_CPU_COMPARE_IDENTICAL);
    DO_TEST_COMPARE(VIR_ARCH_PPC64, "host", "guest-compat-invalid", VIR_CPU_COMPARE_ERROR);
    DO_TEST_COMPARE(VIR_ARCH_PPC64, "host", "guest-compat-incompatible", VIR_CPU_COMPARE_INCOMPATIBLE);

    /* guest updates for migration
     * automatically compares host CPU with the result */
    DO_TEST_UPDATE(VIR_ARCH_X86_64, "host", "min", VIR_CPU_COMPARE_IDENTICAL);
    DO_TEST_UPDATE(VIR_ARCH_X86_64, "host", "pentium3", VIR_CPU_COMPARE_IDENTICAL);
    DO_TEST_UPDATE(VIR_ARCH_X86_64, "host", "guest", VIR_CPU_COMPARE_SUPERSET);
    DO_TEST_UPDATE(VIR_ARCH_X86_64, "host", "host-model", VIR_CPU_COMPARE_IDENTICAL);
    DO_TEST_UPDATE(VIR_ARCH_X86_64, "host", "host-model-nofallback", VIR_CPU_COMPARE_IDENTICAL);
    DO_TEST_UPDATE(VIR_ARCH_X86_64, "host-invtsc", "host-model", VIR_CPU_COMPARE_SUPERSET);
    DO_TEST_UPDATE_ONLY(VIR_ARCH_X86_64, "host", "host-passthrough");
    DO_TEST_UPDATE_ONLY(VIR_ARCH_X86_64, "host", "host-passthrough-features");

    DO_TEST_UPDATE(VIR_ARCH_PPC64, "host", "guest", VIR_CPU_COMPARE_IDENTICAL);
    DO_TEST_UPDATE(VIR_ARCH_PPC64, "host", "guest-nofallback", VIR_CPU_COMPARE_INCOMPATIBLE);
    DO_TEST_UPDATE(VIR_ARCH_PPC64, "host", "guest-legacy", VIR_CPU_COMPARE_IDENTICAL);
    DO_TEST_UPDATE(VIR_ARCH_PPC64, "host", "guest-legacy-incompatible", VIR_CPU_COMPARE_INCOMPATIBLE);
    DO_TEST_UPDATE(VIR_ARCH_PPC64, "host", "guest-legacy-invalid", VIR_CPU_COMPARE_ERROR);
    DO_TEST_UPDATE(VIR_ARCH_PPC64, "host", "guest-compat-none", VIR_CPU_COMPARE_IDENTICAL);
    DO_TEST_UPDATE(VIR_ARCH_PPC64, "host", "guest-compat-valid", VIR_CPU_COMPARE_IDENTICAL);
    DO_TEST_UPDATE(VIR_ARCH_PPC64, "host", "guest-compat-invalid", VIR_CPU_COMPARE_ERROR);
    DO_TEST_UPDATE(VIR_ARCH_PPC64, "host", "guest-compat-incompatible", VIR_CPU_COMPARE_INCOMPATIBLE);

    /* computing baseline CPUs */
    DO_TEST_BASELINE(VIR_ARCH_X86_64, "incompatible-vendors", 0, -1);
    DO_TEST_BASELINE(VIR_ARCH_X86_64, "no-vendor", 0, 0);
    DO_TEST_BASELINE(VIR_ARCH_X86_64, "some-vendors", 0, 0);
    DO_TEST_BASELINE(VIR_ARCH_X86_64, "1", 0, 0);
    DO_TEST_BASELINE(VIR_ARCH_X86_64, "2", 0, 0);
    DO_TEST_BASELINE(VIR_ARCH_X86_64, "3", 0, 0);
    DO_TEST_BASELINE(VIR_ARCH_X86_64, "3", VIR_CONNECT_BASELINE_CPU_EXPAND_FEATURES, 0);
    DO_TEST_BASELINE(VIR_ARCH_X86_64, "4", 0, 0);
    DO_TEST_BASELINE(VIR_ARCH_X86_64, "4", VIR_CONNECT_BASELINE_CPU_EXPAND_FEATURES, 0);
    DO_TEST_BASELINE(VIR_ARCH_X86_64, "5", 0, 0);
    DO_TEST_BASELINE(VIR_ARCH_X86_64, "5", VIR_CONNECT_BASELINE_CPU_EXPAND_FEATURES, 0);
    DO_TEST_BASELINE(VIR_ARCH_X86_64, "6", 0, 0);
    DO_TEST_BASELINE(VIR_ARCH_X86_64, "6", VIR_CONNECT_BASELINE_CPU_MIGRATABLE, 0);
    DO_TEST_BASELINE(VIR_ARCH_X86_64, "7", 0, 0);
    DO_TEST_BASELINE(VIR_ARCH_X86_64, "8", 0, 0);

    DO_TEST_BASELINE(VIR_ARCH_PPC64, "incompatible-vendors", 0, -1);
    DO_TEST_BASELINE(VIR_ARCH_PPC64, "no-vendor", 0, 0);
    DO_TEST_BASELINE(VIR_ARCH_PPC64, "incompatible-models", 0, -1);
    DO_TEST_BASELINE(VIR_ARCH_PPC64, "same-model", 0, 0);
    DO_TEST_BASELINE(VIR_ARCH_PPC64, "legacy", 0, -1);

    /* CPU features */
    DO_TEST_HASFEATURE(VIR_ARCH_X86_64, "host", "vmx", YES);
    DO_TEST_HASFEATURE(VIR_ARCH_X86_64, "host", "lm", YES);
    DO_TEST_HASFEATURE(VIR_ARCH_X86_64, "host", "sse4.1", YES);
    DO_TEST_HASFEATURE(VIR_ARCH_X86_64, "host", "3dnowext", NO);
    DO_TEST_HASFEATURE(VIR_ARCH_X86_64, "host", "skinit", NO);
    DO_TEST_HASFEATURE(VIR_ARCH_X86_64, "host", "foo", FAIL);

    /* computing guest data and decoding the data into a guest CPU XML */
    DO_TEST_GUESTCPU(VIR_ARCH_X86_64, "host", "guest", NULL, 0);
    DO_TEST_GUESTCPU(VIR_ARCH_X86_64, "host-better", "pentium3", NULL, 0);
    DO_TEST_GUESTCPU(VIR_ARCH_X86_64, "host-worse", "guest", NULL, 0);
    DO_TEST_GUESTCPU(VIR_ARCH_X86_64, "host", "strict-force-extra", NULL, 0);
    DO_TEST_GUESTCPU(VIR_ARCH_X86_64, "host", "penryn-force", NULL, 0);
    DO_TEST_GUESTCPU(VIR_ARCH_X86_64, "host", "guest", model486, 0);
    DO_TEST_GUESTCPU(VIR_ARCH_X86_64, "host", "guest", models, 0);
    DO_TEST_GUESTCPU(VIR_ARCH_X86_64, "host", "guest", nomodel, -1);
    DO_TEST_GUESTCPU(VIR_ARCH_X86_64, "host", "guest-nofallback", models, -1);
    DO_TEST_GUESTCPU(VIR_ARCH_X86_64, "host", "host+host-model", models, 0);
    DO_TEST_GUESTCPU(VIR_ARCH_X86_64, "host", "host+host-model-nofallback", models, -1);
    DO_TEST_GUESTCPU(VIR_ARCH_X86_64, "host-Haswell-noTSX", "Haswell", haswell, 0);
    DO_TEST_GUESTCPU(VIR_ARCH_X86_64, "host-Haswell-noTSX", "Haswell-noTSX", haswell, 0);
    DO_TEST_GUESTCPU(VIR_ARCH_X86_64, "host-Haswell-noTSX", "Haswell-noTSX-nofallback", haswell, -1);
    DO_TEST_GUESTCPU(VIR_ARCH_X86_64, "host-Haswell-noTSX", "Haswell-noTSX", NULL, 0);

    DO_TEST_GUESTCPU(VIR_ARCH_PPC64, "host", "guest", ppc_models, 0);
    DO_TEST_GUESTCPU(VIR_ARCH_PPC64, "host", "guest-nofallback", ppc_models, -1);
    DO_TEST_GUESTCPU(VIR_ARCH_PPC64, "host", "guest-legacy", ppc_models, 0);
    DO_TEST_GUESTCPU(VIR_ARCH_PPC64, "host", "guest-legacy-incompatible", ppc_models, -1);
    DO_TEST_GUESTCPU(VIR_ARCH_PPC64, "host", "guest-legacy-invalid", ppc_models, -1);

    DO_TEST_CPUID(VIR_ARCH_X86_64, "A10-5800K", true);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Atom-D510", false);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Atom-N450", false);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Core-i5-2500", true);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Core-i5-2540M", true);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Core-i5-4670T", true);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Core-i5-6600", true);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Core-i7-2600", true);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Core-i7-3520M", false);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Core-i7-3740QM", true);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Core-i7-3770", true);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Core-i7-4600U", true);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Core-i7-4510U", true);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Core-i7-5600U", true);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Core2-E6850", true);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Core2-Q9500", false);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "FX-8150", false);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Opteron-1352", false);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Opteron-2350", true);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Opteron-6234", true);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Opteron-6282", false);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Pentium-P6100", false);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Phenom-B95", true);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Xeon-5110", false);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Xeon-E3-1245", true);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Xeon-E5-2630", true);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Xeon-E5-2650", true);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Xeon-E7-4820", true);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Xeon-E7-8890", false);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Xeon-W3520", true);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Xeon-X5460", false);

#if WITH_QEMU && WITH_YAJL
    qemuTestDriverFree(&driver);
#endif

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)
