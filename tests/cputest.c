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
 */

#include <config.h>

#include <unistd.h>

#include <sys/types.h>
#include <fcntl.h>

#include "internal.h"
#include "virxml.h"
#include "viralloc.h"
#include "virbuffer.h"
#include "testutils.h"
#include "cpu_conf.h"
#include "cpu/cpu.h"
#include "cpu/cpu_x86.h"
#include "cpu/cpu_map.h"
#include "virstring.h"

#if WITH_QEMU && WITH_YAJL
# include "testutilsqemu.h"
# include "qemumonitortestutils.h"
# define LIBVIRT_QEMU_CAPSPRIV_H_ALLOW
# include "qemu/qemu_capspriv.h"
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
    virDomainCapsCPUModelsPtr models;
    const char *modelsName;
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

    virCPUDefParseXML(ctxt, NULL, VIR_CPU_TYPE_AUTO, &cpu);

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
        if (virCPUDefParseXML(ctxt, NULL, VIR_CPU_TYPE_HOST, &cpus[i]) < 0)
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
                  const char *name)
{
    char *xml = NULL;
    char *actual = NULL;
    int ret = -1;

    if (virAsprintf(&xml, "%s/cputestdata/%s-%s.xml",
                    abs_srcdir, virArchToString(arch), name) < 0)
        goto cleanup;

    if (!(actual = virCPUDefFormat(cpu, NULL)))
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
        VIR_TEST_VERBOSE("\nExpected result %s, got %s",
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
        virCPUTranslate(host->arch, cpu, data->models) < 0) {
        ret = -1;
        goto cleanup;
    }

    virBufferAsprintf(&buf, "%s+%s", data->host, data->name);
    if (data->modelsName)
        virBufferAsprintf(&buf, ",%s", data->modelsName);
    virBufferAddLit(&buf, "-result");

    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        goto cleanup;
    }
    result = virBufferContentAndReset(&buf);

    if (cpuTestCompareXML(data->arch, cpu, result) < 0)
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
        VIR_TEST_VERBOSE("\nExpected result %d, got %d",
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

    baseline = virCPUBaseline(data->arch, cpus, ncpus, NULL, NULL,
                              !!(data->flags & VIR_CONNECT_BASELINE_CPU_MIGRATABLE));

    if (baseline &&
        (data->flags & VIR_CONNECT_BASELINE_CPU_EXPAND_FEATURES) &&
        virCPUExpandFeatures(data->arch, baseline) < 0) {
        virCPUDefFree(baseline);
        baseline = NULL;
    }

    if (data->result < 0) {
        virResetLastError();
        if (!baseline) {
            ret = 0;
        } else {
            VIR_TEST_VERBOSE("\n%-70s... ",
                    "virCPUBaseline was expected to fail but it succeeded");
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

    if (cpuTestCompareXML(data->arch, baseline, result) < 0)
        goto cleanup;

    for (i = 0; i < ncpus; i++) {
        virCPUCompareResult cmp;

        cmp = virCPUCompare(cpus[i]->arch, cpus[i], baseline, false);
        if (cmp != VIR_CPU_COMPARE_SUPERSET &&
            cmp != VIR_CPU_COMPARE_IDENTICAL) {
            VIR_TEST_VERBOSE("\nbaseline CPU is incompatible with CPU %zu",
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
    virCPUDefPtr migHost = NULL;
    virCPUDefPtr cpu = NULL;
    char *result = NULL;

    if (!(host = cpuTestLoadXML(data->arch, data->host)) ||
        !(cpu = cpuTestLoadXML(data->arch, data->name)))
        goto cleanup;

    if (!(migHost = virCPUCopyMigratable(data->arch, host)))
        goto cleanup;

    if (virCPUUpdate(host->arch, cpu, migHost) < 0)
        goto cleanup;

    if (virAsprintf(&result, "%s+%s", data->host, data->name) < 0)
        goto cleanup;

    ret = cpuTestCompareXML(data->arch, cpu, result);

 cleanup:
    virCPUDefFree(host);
    virCPUDefFree(cpu);
    virCPUDefFree(migHost);
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
        VIR_TEST_VERBOSE("\nExpected result %s, got %s",
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


typedef enum {
    /* No JSON data from QEMU. */
    JSON_NONE,
    /* Only a reply from query-cpu-model-expansion QMP command. */
    JSON_HOST,
    /* Replies from both query-cpu-model-expansion and query-cpu-definitions
     * QMP commands.
     */
    JSON_MODELS,
    /* Same as JSON_MODELS, but the reply from query-cpu-definitions has to
     * be parsed for providing the correct result. This happens when the
     * CPU model detected by libvirt has non-empty unavailable-features array
     * in query-cpu-definitions reply or when the CPU model detected from CPUID
     * differs from the one we get from QEMU and we need to translate them for
     * comparison. Such tests require QEMU driver to be enabled.
     */
    JSON_MODELS_REQUIRED,
} cpuTestCPUIDJson;

#if WITH_QEMU && WITH_YAJL
static virQEMUCapsPtr
cpuTestMakeQEMUCaps(const struct data *data)
{
    virQEMUCapsPtr qemuCaps = NULL;
    qemuMonitorTestPtr testMon = NULL;
    qemuMonitorCPUModelInfoPtr model = NULL;
    char *json = NULL;

    if (virAsprintf(&json, "%s/cputestdata/%s-cpuid-%s.json",
                    abs_srcdir, virArchToString(data->arch), data->host) < 0)
        goto error;

    if (!(testMon = qemuMonitorTestNewFromFile(json, driver.xmlopt, true)))
        goto error;

    if (qemuMonitorGetCPUModelExpansion(qemuMonitorTestGetMonitor(testMon),
                                        QEMU_MONITOR_CPU_MODEL_EXPANSION_STATIC,
                                        "host", true, &model) < 0)
        goto error;

    if (!(qemuCaps = virQEMUCapsNew()))
        goto error;

    virQEMUCapsSet(qemuCaps, QEMU_CAPS_KVM);
    if (data->flags == JSON_MODELS ||
        data->flags == JSON_MODELS_REQUIRED)
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_QUERY_CPU_DEFINITIONS);

    virQEMUCapsSetArch(qemuCaps, data->arch);
    virQEMUCapsSetCPUModelInfo(qemuCaps, VIR_DOMAIN_VIRT_KVM, model);
    model = NULL;

    if (virQEMUCapsProbeQMPCPUDefinitions(qemuCaps,
                                          qemuMonitorTestGetMonitor(testMon),
                                          false) < 0)
        goto error;

 cleanup:
    qemuMonitorCPUModelInfoFree(model);
    qemuMonitorTestFree(testMon);
    VIR_FREE(json);

    return qemuCaps;

 error:
    virObjectUnref(qemuCaps);
    qemuCaps = NULL;
    goto cleanup;
}


static int
cpuTestGetCPUModels(const struct data *data,
                    virDomainCapsCPUModelsPtr *models)
{
    virQEMUCapsPtr qemuCaps;

    *models = NULL;

    if (data->flags != JSON_MODELS &&
        data->flags != JSON_MODELS_REQUIRED)
        return 0;

    if (!(qemuCaps = cpuTestMakeQEMUCaps(data)))
        return -1;

    *models = virQEMUCapsGetCPUDefinitions(qemuCaps, VIR_DOMAIN_VIRT_KVM);
    virObjectRef(*models);

    virObjectUnref(qemuCaps);

    return 0;
}

#else /* if WITH_QEMU && WITH_YAJL */

static int
cpuTestGetCPUModels(const struct data *data,
                    virDomainCapsCPUModelsPtr *models)
{
    *models = NULL;

    if (data->flags == JSON_MODELS_REQUIRED)
        return EXIT_AM_SKIP;

    return 0;
}

#endif


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
    virDomainCapsCPUModelsPtr models = NULL;

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

    if (guest) {
        int rc;

        rc = cpuTestGetCPUModels(data, &models);
        if (rc != 0) {
            ret = rc;
            goto cleanup;
        }
    }

    if (cpuDecode(cpu, hostData, models) < 0)
        goto cleanup;

    if (virAsprintf(&result, "cpuid-%s-%s",
                    data->host,
                    guest ? "guest" : "host") < 0)
        goto cleanup;

    ret = cpuTestCompareXML(data->arch, cpu, result);

 cleanup:
    VIR_FREE(hostFile);
    VIR_FREE(host);
    virCPUDataFree(hostData);
    virCPUDefFree(cpu);
    VIR_FREE(result);
    virObjectUnref(models);
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


static int
cpuTestCompareSignature(const struct data *data,
                        virCPUDataPtr hostData)
{
    VIR_AUTOFREE(char *) result = NULL;
    VIR_AUTOFREE(char *) sigStr = NULL;
    unsigned long signature;
    unsigned int family;
    unsigned int model;
    unsigned int stepping;

    signature = virCPUx86DataGetSignature(hostData, &family, &model, &stepping);

    if (virAsprintf(&result, "%s/cputestdata/%s-cpuid-%s.sig",
                    abs_srcdir, virArchToString(data->arch), data->host) < 0)
        return -1;

    if (virAsprintf(&sigStr,
                    "%1$06lx\n"
                    "family:   %2$3u (0x%2$02x)\n"
                    "model:    %3$3u (0x%3$02x)\n"
                    "stepping: %4$3u (0x%4$02x)\n",
                    signature, family, model, stepping) < 0)
        return -1;

    return virTestCompareToFile(sigStr, result);
}


static int
cpuTestCPUIDSignature(const void *arg)
{
    const struct data *data = arg;
    virCPUDataPtr hostData = NULL;
    char *hostFile = NULL;
    char *host = NULL;
    int ret = -1;

    if (virAsprintf(&hostFile, "%s/cputestdata/%s-cpuid-%s.xml",
                    abs_srcdir, virArchToString(data->arch), data->host) < 0)
        goto cleanup;

    if (virTestLoadFile(hostFile, &host) < 0 ||
        !(hostData = virCPUDataParse(host)))
        goto cleanup;

    ret = cpuTestCompareSignature(data, hostData);

 cleanup:
    virCPUDataFree(hostData);
    VIR_FREE(hostFile);
    VIR_FREE(host);
    return ret;
}


static int
cpuTestUpdateLiveCompare(virArch arch,
                         virCPUDefPtr actual,
                         virCPUDefPtr expected)
{
    size_t i, j;
    int ret = 0;

    if (virCPUExpandFeatures(arch, actual) < 0 ||
        virCPUExpandFeatures(arch, expected) < 0)
        return -1;

    if (STRNEQ(actual->model, expected->model)) {
        VIR_TEST_VERBOSE("Actual CPU model '%s', expected '%s'",
                         actual->model, expected->model);
        return -1;
    }

    i = j = 0;
    while (i < actual->nfeatures || j < expected->nfeatures) {
        virCPUFeatureDefPtr featAct = NULL;
        virCPUFeatureDefPtr featExp = NULL;
        int cmp;

        if (i < actual->nfeatures)
            featAct = actual->features + i;

        if (j < expected->nfeatures)
            featExp = expected->features + j;

        /*
         * Act < Exp => cmp < 0 (missing entry in Exp)
         * Act = Exp => cmp = 0
         * Act > Exp => cmp > 0 (missing entry in Act)
         *
         * NULL > name for any name != NULL
         */
        if (featAct && featExp)
            cmp = strcmp(featAct->name, featExp->name);
        else
            cmp = featExp ? 1 : -1;

        if (cmp <= 0)
            i++;
        if (cmp >= 0)
            j++;

        /* Possible combinations of cmp, featAct->policy, and featExp->policy:
         *  cmp     Act     Exp     result
         * ---------------------------------
         *   0      dis     dis      ok
         *   0      dis     req     missing
         *   0      req     dis     extra
         *   0      req     req      ok
         * ---------------------------------
         *   -      dis      X       ok     # ignoring extra disabled features
         *   -      req      X      extra
         * ---------------------------------
         *   +       X      dis     extra
         *   +       X      req     missing
         */
        if ((cmp == 0 &&
             featAct->policy == VIR_CPU_FEATURE_DISABLE &&
             featExp->policy == VIR_CPU_FEATURE_REQUIRE) ||
            (cmp > 0 &&
             featExp->policy == VIR_CPU_FEATURE_REQUIRE)) {
            VIR_TEST_VERBOSE("Actual CPU lacks feature '%s'",
                             featExp->name);
            ret = -1;
            continue;
        }

        if ((cmp == 0 &&
             featAct->policy == VIR_CPU_FEATURE_REQUIRE &&
             featExp->policy == VIR_CPU_FEATURE_DISABLE) ||
            (cmp < 0 &&
             featAct->policy == VIR_CPU_FEATURE_REQUIRE) ||
            (cmp > 0 &&
             featExp->policy == VIR_CPU_FEATURE_DISABLE)) {
            VIR_TEST_VERBOSE("Actual CPU has extra feature '%s'",
                             cmp <= 0 ? featAct->name : featExp->name);
            ret = -1;
        }
    }

    return ret;
}


static int
cpuTestUpdateLive(const void *arg)
{
    const struct data *data = arg;
    char *cpuFile = NULL;
    virCPUDefPtr cpu = NULL;
    char *enabledFile = NULL;
    char *enabled = NULL;
    virCPUDataPtr enabledData = NULL;
    char *disabledFile = NULL;
    char *disabled = NULL;
    virCPUDataPtr disabledData = NULL;
    char *expectedFile = NULL;
    virCPUDefPtr expected = NULL;
    virDomainCapsCPUModelsPtr hvModels = NULL;
    virDomainCapsCPUModelsPtr models = NULL;
    int ret = -1;

    if (virAsprintf(&cpuFile, "cpuid-%s-guest", data->host) < 0 ||
        !(cpu = cpuTestLoadXML(data->arch, cpuFile)))
        goto cleanup;

    if (virAsprintf(&enabledFile, "%s/cputestdata/%s-cpuid-%s-enabled.xml",
                    abs_srcdir, virArchToString(data->arch), data->host) < 0 ||
        virTestLoadFile(enabledFile, &enabled) < 0 ||
        !(enabledData = virCPUDataParse(enabled)))
        goto cleanup;

    if (virAsprintf(&disabledFile, "%s/cputestdata/%s-cpuid-%s-disabled.xml",
                    abs_srcdir, virArchToString(data->arch), data->host) < 0 ||
        virTestLoadFile(disabledFile, &disabled) < 0 ||
        !(disabledData = virCPUDataParse(disabled)))
        goto cleanup;

    if (virAsprintf(&expectedFile, "cpuid-%s-json", data->host) < 0 ||
        !(expected = cpuTestLoadXML(data->arch, expectedFile)))
        goto cleanup;

    /* In case the host CPU signature does not exactly match any CPU model from
     * cpu_map.xml, the CPU model we detect from CPUID may differ from the one
     * we compute by asking QEMU. Since this test expands both CPU models and
     * compares their features, we can try to translate the 'actual' CPU to
     * use the CPU model from 'expected'.
     */
    if (STRNEQ(cpu->model, expected->model)) {
        virDomainCapsCPUModelPtr hvModel;
        char **blockers = NULL;
        virDomainCapsCPUUsable usable = VIR_DOMCAPS_CPU_USABLE_UNKNOWN;
        int rc;

        if (!(models = virDomainCapsCPUModelsNew(0)))
            goto cleanup;

        rc = cpuTestGetCPUModels(data, &hvModels);
        if (rc != 0) {
            ret = rc;
            goto cleanup;
        }

        hvModel = virDomainCapsCPUModelsGet(hvModels, expected->model);

        if (hvModel) {
            blockers = hvModel->blockers;
            usable = hvModel->usable;
        }

        if (virDomainCapsCPUModelsAdd(models, expected->model, -1,
                                      usable, blockers) < 0)
            goto cleanup;

        cpu->fallback = VIR_CPU_FALLBACK_ALLOW;
        ignore_value(virCPUTranslate(data->arch, cpu, models));
        cpu->fallback = VIR_CPU_FALLBACK_FORBID;
    }

    if (virCPUUpdateLive(data->arch, cpu, enabledData, disabledData) < 0)
        goto cleanup;

    ret = cpuTestUpdateLiveCompare(data->arch, cpu, expected);

 cleanup:
    VIR_FREE(cpuFile);
    virCPUDefFree(cpu);
    VIR_FREE(enabledFile);
    VIR_FREE(enabled);
    virCPUDataFree(enabledData);
    VIR_FREE(disabledFile);
    VIR_FREE(disabled);
    virCPUDataFree(disabledData);
    VIR_FREE(expectedFile);
    virCPUDefFree(expected);
    virObjectUnref(hvModels);
    virObjectUnref(models);
    return ret;
}


#if WITH_QEMU && WITH_YAJL
static int
cpuTestJSONCPUID(const void *arg)
{
    const struct data *data = arg;
    virQEMUCapsPtr qemuCaps = NULL;
    virCPUDefPtr cpu = NULL;
    char *result = NULL;
    int ret = -1;

    if (virAsprintf(&result, "cpuid-%s-json", data->host) < 0)
        goto cleanup;

    if (!(qemuCaps = cpuTestMakeQEMUCaps(data)))
        goto cleanup;

    if (VIR_ALLOC(cpu) < 0)
        goto cleanup;

    cpu->arch = data->arch;
    cpu->type = VIR_CPU_TYPE_GUEST;
    cpu->match = VIR_CPU_MATCH_EXACT;
    cpu->fallback = VIR_CPU_FALLBACK_FORBID;

    if (virQEMUCapsInitCPUModel(qemuCaps, VIR_DOMAIN_VIRT_KVM, cpu, false) != 0)
        goto cleanup;

    ret = cpuTestCompareXML(data->arch, cpu, result);

 cleanup:
    virObjectUnref(qemuCaps);
    virCPUDefFree(cpu);
    VIR_FREE(result);
    return ret;
}


static int
cpuTestJSONSignature(const void *arg)
{
    const struct data *data = arg;
    virQEMUCapsPtr qemuCaps = NULL;
    virCPUDataPtr hostData = NULL;
    qemuMonitorCPUModelInfoPtr modelInfo;
    int ret = -1;

    if (!(qemuCaps = cpuTestMakeQEMUCaps(data)))
        goto cleanup;

    modelInfo = virQEMUCapsGetCPUModelInfo(qemuCaps, VIR_DOMAIN_VIRT_KVM);
    if (!(hostData = virQEMUCapsGetCPUModelX86Data(qemuCaps, modelInfo, false)))
        goto cleanup;

    ret = cpuTestCompareSignature(data, hostData);

 cleanup:
    virObjectUnref(qemuCaps);
    virCPUDataFree(hostData);
    return ret;
}
#endif


static const char *model486_list[]   = { "486", NULL };
static const char *nomodel_list[]    = { "nomodel", NULL };
static const char *models_list[]     = { "qemu64", "core2duo", "Nehalem", NULL };
static const char *haswell_list[]    = { "SandyBridge", "Haswell", NULL };
static const char *ppc_models_list[] = { "POWER6", "POWER7", "POWER8", NULL };

static virDomainCapsCPUModelsPtr
cpuTestInitModels(const char **list)
{
    virDomainCapsCPUModelsPtr cpus;
    const char **model;

    if (!(cpus = virDomainCapsCPUModelsNew(0)))
        return NULL;

    for (model = list; *model; model++) {
        if (virDomainCapsCPUModelsAdd(cpus, *model, -1,
                                      VIR_DOMCAPS_CPU_USABLE_UNKNOWN, NULL) < 0)
            goto error;
    }

    return cpus;

 error:
    virObjectUnref(cpus);
    return NULL;
}


static int
mymain(void)
{
    virDomainCapsCPUModelsPtr model486 = NULL;
    virDomainCapsCPUModelsPtr nomodel = NULL;
    virDomainCapsCPUModelsPtr models = NULL;
    virDomainCapsCPUModelsPtr haswell = NULL;
    virDomainCapsCPUModelsPtr ppc_models = NULL;
    int ret = 0;

#if WITH_QEMU && WITH_YAJL
    if (qemuTestDriverInit(&driver) < 0)
        return EXIT_FAILURE;

    virEventRegisterDefaultImpl();
#endif

    if (!(model486 = cpuTestInitModels(model486_list)) ||
        !(nomodel = cpuTestInitModels(nomodel_list)) ||
        !(models = cpuTestInitModels(models_list)) ||
        !(haswell = cpuTestInitModels(haswell_list)) ||
        !(ppc_models = cpuTestInitModels(ppc_models_list))) {
        ret = -1;
        goto cleanup;
    }

#define DO_TEST(arch, api, name, host, cpu, \
                models, flags, result) \
    do { \
        struct data data = { \
            arch, host, cpu, models, \
            models == NULL ? NULL : #models, \
            flags, result \
        }; \
        char *testLabel; \
        char *tmp; \
 \
        tmp = virTestLogContentAndReset(); \
        VIR_FREE(tmp); \
 \
        if (virAsprintf(&testLabel, "%s(%s): %s", \
                        #api, virArchToString(arch), name) < 0) { \
            ret = -1; \
            break; \
        } \
 \
        if (virTestRun(testLabel, api, &data) < 0) { \
            if (virTestGetDebug()) { \
                char *log; \
                if ((log = virTestLogContentAndReset()) && \
                     strlen(log) > 0) \
                    VIR_TEST_DEBUG("\n%s", log); \
                VIR_FREE(log); \
            } \
            ret = -1; \
        } \
 \
        VIR_FREE(testLabel); \
    } while (0)

#define DO_TEST_COMPARE(arch, host, cpu, result) \
    DO_TEST(arch, cpuTestCompare, \
            host "/" cpu " (" #result ")", \
            host, cpu, NULL, 0, result)

#define DO_TEST_UPDATE_ONLY(arch, host, cpu) \
    DO_TEST(arch, cpuTestUpdate, \
            cpu " on " host, \
            host, cpu, NULL, 0, 0)

#define DO_TEST_UPDATE(arch, host, cpu, result) \
    do { \
        DO_TEST_UPDATE_ONLY(arch, host, cpu); \
        DO_TEST_COMPARE(arch, host, host "+" cpu, result); \
    } while (0)

#define DO_TEST_BASELINE(arch, name, flags, result) \
    do { \
        const char *suffix = ""; \
        char *label; \
        if ((flags) & VIR_CONNECT_BASELINE_CPU_EXPAND_FEATURES) \
            suffix = " (expanded)"; \
        if ((flags) & VIR_CONNECT_BASELINE_CPU_MIGRATABLE) \
            suffix = " (migratable)"; \
        if (virAsprintf(&label, "%s%s", name, suffix) < 0) { \
            ret = -1; \
        } else { \
            DO_TEST(arch, cpuTestBaseline, label, NULL, \
                    "baseline-" name, NULL, flags, result); \
        } \
        VIR_FREE(label); \
    } while (0)

#define DO_TEST_HASFEATURE(arch, host, feature, result) \
    DO_TEST(arch, cpuTestHasFeature, \
            host "/" feature " (" #result ")", \
            host, feature, NULL, 0, result)

#define DO_TEST_GUESTCPU(arch, host, cpu, models, result) \
    DO_TEST(arch, cpuTestGuestCPU, \
            host "/" cpu " (" #models ")", \
            host, cpu, models, 0, result)

#if WITH_QEMU && WITH_YAJL
# define DO_TEST_JSON(arch, host, json) \
    do { \
        if (json == JSON_MODELS) { \
            DO_TEST(arch, cpuTestGuestCPUID, host, host, \
                    NULL, NULL, 0, 0); \
        } \
        if (json != JSON_NONE) { \
            DO_TEST(arch, cpuTestJSONCPUID, host, host, \
                    NULL, NULL, json, 0); \
            DO_TEST(arch, cpuTestJSONSignature, host, host, \
                    NULL, NULL, 0, 0); \
        } \
    } while (0)
#else
# define DO_TEST_JSON(arch, host, json)
#endif

#define DO_TEST_CPUID(arch, host, json) \
    do { \
        DO_TEST(arch, cpuTestHostCPUID, host, host, \
                NULL, NULL, 0, 0); \
        DO_TEST(arch, cpuTestGuestCPUID, host, host, \
                NULL, NULL, json, 0); \
        DO_TEST(arch, cpuTestCPUIDSignature, host, host, \
                NULL, NULL, 0, 0); \
        DO_TEST_JSON(arch, host, json); \
        if (json != JSON_NONE) { \
            DO_TEST(arch, cpuTestUpdateLive, host, host, \
                    NULL, NULL, json, 0); \
        } \
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

    DO_TEST_CPUID(VIR_ARCH_X86_64, "A10-5800K", JSON_HOST);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Atom-D510", JSON_NONE);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Atom-N450", JSON_NONE);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Core-i5-650", JSON_MODELS_REQUIRED);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Core-i5-2500", JSON_HOST);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Core-i5-2540M", JSON_MODELS);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Core-i5-4670T", JSON_HOST);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Core-i5-6600", JSON_HOST);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Core-i7-2600", JSON_HOST);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Core-i7-2600-xsaveopt", JSON_MODELS_REQUIRED);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Core-i7-3520M", JSON_NONE);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Core-i7-3740QM", JSON_HOST);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Core-i7-3770", JSON_HOST);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Core-i7-4600U", JSON_HOST);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Core-i7-4510U", JSON_HOST);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Core-i7-5600U", JSON_HOST);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Core-i7-5600U-arat", JSON_HOST);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Core-i7-5600U-ibrs", JSON_HOST);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Core-i7-7600U", JSON_MODELS);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Core-i7-7700", JSON_MODELS);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Core-i7-8700", JSON_MODELS);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Core2-E6850", JSON_HOST);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Core2-Q9500", JSON_NONE);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "EPYC-7601-32-Core", JSON_HOST);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "EPYC-7601-32-Core-ibpb", JSON_MODELS_REQUIRED);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "FX-8150", JSON_NONE);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Opteron-1352", JSON_NONE);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Opteron-2350", JSON_HOST);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Opteron-6234", JSON_HOST);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Opteron-6282", JSON_NONE);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Pentium-P6100", JSON_NONE);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Phenom-B95", JSON_HOST);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Ryzen-7-1800X-Eight-Core", JSON_HOST);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Xeon-5110", JSON_NONE);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Xeon-E3-1225-v5", JSON_MODELS);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Xeon-E3-1245-v5", JSON_MODELS);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Xeon-E5-2609-v3", JSON_MODELS);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Xeon-E5-2623-v4", JSON_MODELS);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Xeon-E5-2630-v3", JSON_HOST);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Xeon-E5-2630-v4", JSON_MODELS);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Xeon-E5-2650", JSON_MODELS);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Xeon-E5-2650-v3", JSON_HOST);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Xeon-E5-2650-v4", JSON_MODELS);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Xeon-E7-4820", JSON_HOST);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Xeon-E7-4830", JSON_MODELS_REQUIRED);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Xeon-E7-8890-v3", JSON_MODELS);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Xeon-E7540", JSON_MODELS);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Xeon-Gold-5115", JSON_MODELS);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Xeon-Gold-6148", JSON_HOST);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Xeon-Platinum-8268", JSON_HOST);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Xeon-W3520", JSON_HOST);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Xeon-X5460", JSON_NONE);

 cleanup:
#if WITH_QEMU && WITH_YAJL
    qemuTestDriverFree(&driver);
#endif

    virObjectUnref(model486);
    virObjectUnref(nomodel);
    virObjectUnref(models);
    virObjectUnref(haswell);
    virObjectUnref(ppc_models);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
