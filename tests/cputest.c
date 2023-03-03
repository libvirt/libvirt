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

#if WITH_QEMU
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
    virDomainCapsCPUModels *models;
    const char *modelsName;
    const char **cpus;
    int ncpus;
    unsigned int flags;
    int result;
};

#if WITH_QEMU
static virQEMUDriver driver;
#endif


static virCPUDef *
cpuTestLoadXML(virArch arch, const char *name)
{
    g_autofree char *xml = NULL;
    g_autoptr(xmlDoc) doc = NULL;
    g_autoptr(xmlXPathContext) ctxt = NULL;
    virCPUDef *cpu = NULL;

    xml = g_strdup_printf("%s/cputestdata/%s-%s.xml", abs_srcdir,
                          virArchToString(arch), name);

    if (!(doc = virXMLParseFileCtxt(xml, &ctxt)))
        return NULL;

    virCPUDefParseXML(ctxt, NULL, VIR_CPU_TYPE_AUTO, &cpu, false);

    return cpu;
}


static virCPUDef **
cpuTestLoadMultiXML(virArch arch,
                    const char *name,
                    unsigned int *count)
{
    g_autofree char *xml = NULL;
    g_autoptr(xmlDoc) doc = NULL;
    g_autoptr(xmlXPathContext) ctxt = NULL;
    g_autofree xmlNodePtr *nodes = NULL;
    virCPUDef **cpus = NULL;
    int n;
    size_t i;

    xml = g_strdup_printf("%s/cputestdata/%s-%s.xml", abs_srcdir,
                          virArchToString(arch), name);

    if (!(doc = virXMLParseFileCtxt(xml, &ctxt)))
        return NULL;

    n = virXPathNodeSet("/cpuTest/cpu", ctxt, &nodes);
    if (n <= 0) {
        fprintf(stderr, "\nNo /cpuTest/cpu elements found in %s\n", xml);
        return NULL;
    }

    cpus = g_new0(virCPUDef *, n);

    for (i = 0; i < n; i++) {
        ctxt->node = nodes[i];
        if (virCPUDefParseXML(ctxt, NULL, VIR_CPU_TYPE_HOST, &cpus[i],
                              false) < 0)
            goto error;
    }

    *count = n;

    return cpus;

 error:
    for (i = 0; i < n; i++)
        virCPUDefFree(cpus[i]);
    VIR_FREE(cpus);
    return NULL;
}


static int
cpuTestCompareXML(virArch arch,
                  virCPUDef *cpu,
                  const char *name)
{
    g_autofree char *xml = NULL;
    g_autofree char *actual = NULL;

    xml = g_strdup_printf("%s/cputestdata/%s-%s.xml", abs_srcdir,
                          virArchToString(arch), name);

    if (!(actual = virCPUDefFormat(cpu, NULL)))
        return -1;

    if (virTestCompareToFile(actual, xml) < 0)
        return -1;

    return 0;
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
    g_autoptr(virCPUDef) host = NULL;
    g_autoptr(virCPUDef) cpu = NULL;
    virCPUCompareResult result;

    if (!(host = cpuTestLoadXML(data->arch, data->host)) ||
        !(cpu = cpuTestLoadXML(data->arch, data->name)))
        return -1;

    result = virCPUCompare(host->arch, host, cpu, false);
    if (data->result == VIR_CPU_COMPARE_ERROR)
        virResetLastError();

    if (data->result != result) {
        VIR_TEST_VERBOSE("\nExpected result %s, got %s",
                    cpuTestCompResStr(data->result),
                    cpuTestCompResStr(result));
        /* Pad to line up with test name ... in virTestRun */
        VIR_TEST_VERBOSE("%74s", "... ");
        return -1;
    }

    return 0;
}


static int
cpuTestGuestCPU(const void *arg)
{
    const struct data *data = arg;
    int ret = -2;
    g_autoptr(virCPUDef) host = NULL;
    g_autoptr(virCPUDef) cpu = NULL;
    virCPUCompareResult cmpResult;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    g_autofree char *result = NULL;

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

    result = virBufferContentAndReset(&buf);

    if (cpuTestCompareXML(data->arch, cpu, result) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
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
    virCPUDef **cpus = NULL;
    virCPUDef *baseline = NULL;
    unsigned int ncpus = 0;
    g_autofree char *result = NULL;
    const char *suffix;
    size_t i;

    if (!(cpus = cpuTestLoadMultiXML(data->arch, data->name, &ncpus)))
        goto cleanup;

    baseline = virCPUBaseline(data->arch, cpus, ncpus, NULL, NULL,
                              !!(data->flags & VIR_CONNECT_BASELINE_CPU_MIGRATABLE));

    if (baseline &&
        (data->flags & VIR_CONNECT_BASELINE_CPU_EXPAND_FEATURES) &&
        virCPUExpandFeatures(data->arch, baseline) < 0) {
        g_clear_pointer(&baseline, virCPUDefFree);
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
    result = g_strdup_printf("%s-%s", data->name, suffix);

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
    return ret;
}


static int
cpuTestUpdate(const void *arg)
{
    const struct data *data = arg;
    g_autoptr(virCPUDef) host = NULL;
    g_autoptr(virCPUDef) migHost = NULL;
    g_autoptr(virCPUDef) cpu = NULL;
    g_autofree char *result = NULL;

    if (!(host = cpuTestLoadXML(data->arch, data->host)) ||
        !(cpu = cpuTestLoadXML(data->arch, data->name)))
        return -1;

    if (!(migHost = virCPUCopyMigratable(data->arch, host)))
        return -1;

    if (virCPUUpdate(host->arch, cpu, migHost) < 0)
        return -1;

    result = g_strdup_printf("%s+%s", data->host, data->name);

    return cpuTestCompareXML(data->arch, cpu, result);
}


static int
cpuTestHasFeature(const void *arg)
{
    const struct data *data = arg;
    g_autoptr(virCPUDef) host = NULL;
    g_autoptr(virCPUData) hostData = NULL;
    int result;

    if (!(host = cpuTestLoadXML(data->arch, data->host)))
        return -1;

    if (cpuEncode(host->arch, host, NULL, &hostData,
                  NULL, NULL, NULL, NULL) < 0)
        return -1;

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
        return -1;
    }

    return 0;
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

#if WITH_QEMU
static virQEMUCaps *
cpuTestMakeQEMUCaps(const struct data *data)
{
    g_autoptr(virQEMUCaps) qemuCaps = NULL;
    g_autoptr(qemuMonitorTest) testMon = NULL;
    g_autoptr(qemuMonitorCPUModelInfo) model = NULL;
    g_autoptr(virCPUDef) cpu = NULL;
    bool fail_no_props = true;
    g_autofree char *json = NULL;

    json = g_strdup_printf("%s/cputestdata/%s-cpuid-%s.json", abs_srcdir,
                           virArchToString(data->arch), data->host);

    if (!(testMon = qemuMonitorTestNewFromFile(json, driver.xmlopt, true)))
        return NULL;

    qemuMonitorTestAllowUnusedCommands(testMon);

    cpu = virCPUDefNew();

    cpu->model = g_strdup("host");

    if (ARCH_IS_S390(data->arch))
        fail_no_props = false;

    if (qemuMonitorGetCPUModelExpansion(qemuMonitorTestGetMonitor(testMon),
                                        QEMU_MONITOR_CPU_MODEL_EXPANSION_STATIC,
                                        cpu, true, false, fail_no_props, &model) < 0)
        return NULL;

    qemuCaps = virQEMUCapsNew();

    virQEMUCapsSet(qemuCaps, QEMU_CAPS_KVM);
    if (data->flags == JSON_MODELS ||
        data->flags == JSON_MODELS_REQUIRED)
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_QUERY_CPU_DEFINITIONS);

    virQEMUCapsSetArch(qemuCaps, data->arch);
    virQEMUCapsSetCPUModelInfo(qemuCaps, VIR_DOMAIN_VIRT_KVM, model);
    model = NULL;

    if (virQEMUCapsProbeCPUDefinitionsTest(qemuCaps,
                                           qemuMonitorTestGetMonitor(testMon)) < 0)
        return NULL;

    return g_steal_pointer(&qemuCaps);
}


static int
cpuTestGetCPUModels(const struct data *data,
                    virDomainCapsCPUModels **models)
{
    g_autoptr(virQEMUCaps) qemuCaps = NULL;

    *models = NULL;

    if (data->flags != JSON_MODELS &&
        data->flags != JSON_MODELS_REQUIRED)
        return 0;

    if (!(qemuCaps = cpuTestMakeQEMUCaps(data)))
        return -1;

    *models = virQEMUCapsGetCPUModels(qemuCaps, VIR_DOMAIN_VIRT_KVM, NULL, NULL);

    return 0;
}

#else /* if WITH_QEMU */

static int
cpuTestGetCPUModels(const struct data *data,
                    virDomainCapsCPUModels **models)
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
    g_autoptr(virCPUData) hostData = NULL;
    g_autofree char *hostFile = NULL;
    g_autofree char *host = NULL;
    g_autoptr(virCPUDef) cpu = NULL;
    g_autofree char *result = NULL;
    g_autoptr(virDomainCapsCPUModels) models = NULL;

    hostFile = g_strdup_printf("%s/cputestdata/%s-cpuid-%s.xml", abs_srcdir,
                               virArchToString(data->arch), data->host);

    if (virTestLoadFile(hostFile, &host) < 0 ||
        !(hostData = virCPUDataParse(host)))
        return -1;

    cpu = virCPUDefNew();
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
        if (rc != 0)
            return rc;
    }

    if (cpuDecode(cpu, hostData, models) < 0)
        return -1;

    result = g_strdup_printf("cpuid-%s-%s", data->host, guest ? "guest" : "host");

    return cpuTestCompareXML(data->arch, cpu, result);
}


static int
cpuTestCPUIDBaseline(const void *arg)
{
    const struct data *data = arg;
    int ret = -1;
    virCPUDef **cpus = NULL;
    virCPUDef *baseline = NULL;
    g_autofree char *result = NULL;
    size_t i;

    cpus = g_new0(virCPUDef *, data->ncpus);
    for (i = 0; i < data->ncpus; i++) {
        g_autofree char *name = NULL;

        name = g_strdup_printf("cpuid-%s-json", data->cpus[i]);
        if (!(cpus[i] = cpuTestLoadXML(data->arch, name)))
            goto cleanup;
    }

    baseline = virCPUBaseline(data->arch, cpus, data->ncpus, NULL, NULL, false);
    if (!baseline)
        goto cleanup;

    result = g_strdup_printf("cpuid-baseline-%s", data->name);

    if (cpuTestCompareXML(data->arch, baseline, result) < 0)
        goto cleanup;

    for (i = 0; i < data->ncpus; i++) {
        virCPUCompareResult cmp;

        cmp = virCPUCompare(data->arch, cpus[i], baseline, false);
        if (cmp != VIR_CPU_COMPARE_SUPERSET &&
            cmp != VIR_CPU_COMPARE_IDENTICAL) {
            VIR_TEST_VERBOSE("\nbaseline CPU is incompatible with CPU %zu", i);
            VIR_TEST_VERBOSE("%74s", "... ");
            ret = -1;
            goto cleanup;
        }
    }

    ret = 0;

 cleanup:
    if (cpus) {
        for (i = 0; i < data->ncpus; i++)
            virCPUDefFree(cpus[i]);
        VIR_FREE(cpus);
    }
    virCPUDefFree(baseline);
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
                        virCPUData *hostData)
{
    g_autofree char *result = NULL;
    g_autofree char *sigStr = NULL;
    unsigned long signature;
    unsigned int family;
    unsigned int model;
    unsigned int stepping;

    signature = virCPUx86DataGetSignature(hostData, &family, &model, &stepping);

    result = g_strdup_printf("%s/cputestdata/%s-cpuid-%s.sig", abs_srcdir,
                             virArchToString(data->arch), data->host);

    sigStr = g_strdup_printf("%1$06lx\n" "family:   %2$3u (0x%2$02x)\n"
                             "model:    %3$3u (0x%3$02x)\n" "stepping: %4$3u (0x%4$02x)\n",
                             signature, family, model, stepping);

    return virTestCompareToFile(sigStr, result);
}


static int
cpuTestCPUIDSignature(const void *arg)
{
    const struct data *data = arg;
    g_autoptr(virCPUData) hostData = NULL;
    g_autofree char *hostFile = NULL;
    g_autofree char *host = NULL;

    hostFile = g_strdup_printf("%s/cputestdata/%s-cpuid-%s.xml", abs_srcdir,
                               virArchToString(data->arch), data->host);

    if (virTestLoadFile(hostFile, &host) < 0 ||
        !(hostData = virCPUDataParse(host)))
        return -1;

    return cpuTestCompareSignature(data, hostData);
}


static int
cpuTestUpdateLiveCompare(virArch arch,
                         virCPUDef *actual,
                         virCPUDef *expected)
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
        virCPUFeatureDef *featAct = NULL;
        virCPUFeatureDef *featExp = NULL;
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
            (cmp < 0 && featAct &&
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
    g_autofree char *cpuFile = NULL;
    g_autoptr(virCPUDef) cpu = NULL;
    g_autofree char *enabledFile = NULL;
    g_autofree char *enabled = NULL;
    g_autoptr(virCPUData) enabledData = NULL;
    g_autofree char *disabledFile = NULL;
    g_autofree char *disabled = NULL;
    g_autoptr(virCPUData) disabledData = NULL;
    g_autofree char *expectedFile = NULL;
    g_autoptr(virCPUDef) expected = NULL;
    g_autoptr(virDomainCapsCPUModels) hvModels = NULL;
    g_autoptr(virDomainCapsCPUModels) models = NULL;

    cpuFile = g_strdup_printf("cpuid-%s-guest", data->host);
    if (!(cpu = cpuTestLoadXML(data->arch, cpuFile)))
        return -1;

    enabledFile = g_strdup_printf("%s/cputestdata/%s-cpuid-%s-enabled.xml",
                                  abs_srcdir, virArchToString(data->arch), data->host);
    if (virTestLoadFile(enabledFile, &enabled) < 0 ||
        !(enabledData = virCPUDataParse(enabled)))
        return -1;

    disabledFile = g_strdup_printf("%s/cputestdata/%s-cpuid-%s-disabled.xml",
                                   abs_srcdir, virArchToString(data->arch), data->host);
    if (virTestLoadFile(disabledFile, &disabled) < 0 ||
        !(disabledData = virCPUDataParse(disabled)))
        return -1;

    expectedFile = g_strdup_printf("cpuid-%s-json", data->host);
    if (!(expected = cpuTestLoadXML(data->arch, expectedFile)))
        return -1;

    /* In case the host CPU signature does not exactly match any CPU model in
     * src/cpu_map, the CPU model we detect from CPUID may differ from the one
     * we compute by asking QEMU. Since this test expands both CPU models and
     * compares their features, we can try to translate the 'actual' CPU to
     * use the CPU model from 'expected'.
     */
    if (STRNEQ(cpu->model, expected->model)) {
        virDomainCapsCPUModel *hvModel;
        char **blockers = NULL;
        virDomainCapsCPUUsable usable = VIR_DOMCAPS_CPU_USABLE_UNKNOWN;
        int rc;

        if (!(models = virDomainCapsCPUModelsNew(0)))
            return -1;

        rc = cpuTestGetCPUModels(data, &hvModels);
        if (rc != 0)
            return rc;

        hvModel = virDomainCapsCPUModelsGet(hvModels, expected->model);

        if (hvModel) {
            blockers = hvModel->blockers;
            usable = hvModel->usable;
        }

        virDomainCapsCPUModelsAdd(models, expected->model,
                                  usable, blockers, false, expected->vendor);

        cpu->fallback = VIR_CPU_FALLBACK_ALLOW;
        ignore_value(virCPUTranslate(data->arch, cpu, models));
        cpu->fallback = VIR_CPU_FALLBACK_FORBID;
    }

    if (virCPUUpdateLive(data->arch, cpu, enabledData, disabledData) < 0)
        return -1;

    return cpuTestUpdateLiveCompare(data->arch, cpu, expected);
}


#if WITH_QEMU
static int
cpuTestJSONCPUID(const void *arg)
{
    const struct data *data = arg;
    g_autoptr(virQEMUCaps) qemuCaps = NULL;
    g_autoptr(virCPUDef) cpu = NULL;
    g_autofree char *result = NULL;

    result = g_strdup_printf("cpuid-%s-json", data->host);

    if (!(qemuCaps = cpuTestMakeQEMUCaps(data)))
        return -1;

    cpu = virCPUDefNew();
    cpu->arch = data->arch;
    cpu->type = VIR_CPU_TYPE_GUEST;
    cpu->match = VIR_CPU_MATCH_EXACT;
    cpu->fallback = VIR_CPU_FALLBACK_FORBID;

    if (virQEMUCapsInitCPUModel(qemuCaps, VIR_DOMAIN_VIRT_KVM, cpu, false) != 0)
        return -1;

    return cpuTestCompareXML(data->arch, cpu, result);
}


static int
cpuTestJSONSignature(const void *arg)
{
    const struct data *data = arg;
    g_autoptr(virQEMUCaps) qemuCaps = NULL;
    g_autoptr(virCPUData) hostData = NULL;
    qemuMonitorCPUModelInfo *modelInfo;

    if (!(qemuCaps = cpuTestMakeQEMUCaps(data)))
        return -1;

    modelInfo = virQEMUCapsGetCPUModelInfo(qemuCaps, VIR_DOMAIN_VIRT_KVM);
    if (!(hostData = virQEMUCapsGetCPUModelX86Data(qemuCaps, modelInfo, false)))
        return -1;

    return cpuTestCompareSignature(data, hostData);
}
#endif


static const char *model486_list[]   = { "486", NULL };
static const char *nomodel_list[]    = { "nomodel", NULL };
static const char *models_list[]     = { "qemu64", "core2duo", "Nehalem", NULL };
static const char *haswell_list[]    = { "SandyBridge", "Haswell", NULL };
static const char *ppc_models_list[] = { "POWER6", "POWER7", "POWER8", NULL };

static virDomainCapsCPUModels *
cpuTestInitModels(const char **list)
{
    virDomainCapsCPUModels *cpus;
    const char **model;

    if (!(cpus = virDomainCapsCPUModelsNew(0)))
        return NULL;

    for (model = list; *model; model++) {
        virDomainCapsCPUModelsAdd(cpus, *model,
                                  VIR_DOMCAPS_CPU_USABLE_UNKNOWN,
                                  NULL, false, NULL);
    }

    return cpus;
}


static int
mymain(void)
{
    virDomainCapsCPUModels *model486 = NULL;
    virDomainCapsCPUModels *nomodel = NULL;
    virDomainCapsCPUModels *models = NULL;
    virDomainCapsCPUModels *haswell = NULL;
    virDomainCapsCPUModels *ppc_models = NULL;
    int ret = 0;

#if WITH_QEMU
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

#define DO_TEST(arch, api, name, host, cpu, cpus, ncpus, \
                models, flags, result) \
    do { \
        struct data data = { \
            arch, host, cpu, models, \
            models == NULL ? NULL : #models, \
            cpus, ncpus, flags, result \
        }; \
        g_autofree char *testLabel = NULL; \
 \
        testLabel = g_strdup_printf("%s(%s): %s", #api, \
                                    virArchToString(arch), name); \
 \
        virTestRunLog(&ret, testLabel, api, &data); \
    } while (0)

#define DO_TEST_COMPARE(arch, host, cpu, result) \
    DO_TEST(arch, cpuTestCompare, \
            host "/" cpu " (" #result ")", \
            host, cpu, NULL, 0, NULL, 0, result)

#define DO_TEST_UPDATE_ONLY(arch, host, cpu) \
    DO_TEST(arch, cpuTestUpdate, \
            cpu " on " host, \
            host, cpu, NULL, 0, NULL, 0, 0)

#define DO_TEST_UPDATE(arch, host, cpu, result) \
    do { \
        DO_TEST_UPDATE_ONLY(arch, host, cpu); \
        DO_TEST_COMPARE(arch, host, host "+" cpu, result); \
    } while (0)

#define DO_TEST_BASELINE(arch, name, flags, result) \
    do { \
        const char *suffix = ""; \
        g_autofree char *label = NULL; \
        if ((flags) & VIR_CONNECT_BASELINE_CPU_EXPAND_FEATURES) \
            suffix = " (expanded)"; \
        if ((flags) & VIR_CONNECT_BASELINE_CPU_MIGRATABLE) \
            suffix = " (migratable)"; \
        label = g_strdup_printf("%s%s", name, suffix); \
        DO_TEST(arch, cpuTestBaseline, label, NULL, \
                "baseline-" name, NULL, 0, NULL, flags, result); \
    } while (0)

#define DO_TEST_HASFEATURE(arch, host, feature, result) \
    DO_TEST(arch, cpuTestHasFeature, \
            host "/" feature " (" #result ")", \
            host, feature, NULL, 0, NULL, 0, result)

#define DO_TEST_GUESTCPU(arch, host, cpu, models, result) \
    DO_TEST(arch, cpuTestGuestCPU, \
            host "/" cpu " (" #models ")", \
            host, cpu, NULL, 0, models, 0, result)

#if WITH_QEMU
# define DO_TEST_JSON(arch, host, json) \
    do { \
        if (json == JSON_MODELS) { \
            DO_TEST(arch, cpuTestGuestCPUID, host, host, \
                    NULL, NULL, 0, NULL, 0, 0); \
        } \
        if (json != JSON_NONE) { \
            DO_TEST(arch, cpuTestJSONCPUID, host, host, \
                    NULL, NULL, 0, NULL, json, 0); \
            DO_TEST(arch, cpuTestJSONSignature, host, host, \
                    NULL, NULL, 0, NULL, 0, 0); \
        } \
    } while (0)
#else
# define DO_TEST_JSON(arch, host, json)
#endif

#define DO_TEST_CPUID(arch, host, json) \
    do { \
        DO_TEST(arch, cpuTestHostCPUID, host, host, \
                NULL, NULL, 0, NULL, 0, 0); \
        DO_TEST(arch, cpuTestGuestCPUID, host, host, \
                NULL, NULL, 0, NULL, json, 0); \
        DO_TEST(arch, cpuTestCPUIDSignature, host, host, \
                NULL, NULL, 0, NULL, 0, 0); \
        DO_TEST_JSON(arch, host, json); \
        if (json != JSON_NONE) { \
            DO_TEST(arch, cpuTestUpdateLive, host, host, \
                    NULL, NULL, 0, NULL, json, 0); \
        } \
    } while (0)

#define DO_TEST_CPUID_BASELINE(arch, label, cpu1, cpu2) \
    do { \
        const char *cpus[] = {cpu1, cpu2}; \
        DO_TEST(arch, cpuTestCPUIDBaseline, \
                label " (" cpu1 ", " cpu2 ")", \
                NULL, label, cpus, 2, NULL, 0, 0); \
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
    DO_TEST_COMPARE(VIR_ARCH_PPC64, "host", "guest-legacy-bad", VIR_CPU_COMPARE_ERROR);
    DO_TEST_COMPARE(VIR_ARCH_PPC64, "host", "guest-compat-none", VIR_CPU_COMPARE_IDENTICAL);
    DO_TEST_COMPARE(VIR_ARCH_PPC64, "host", "guest-compat-valid", VIR_CPU_COMPARE_IDENTICAL);
    DO_TEST_COMPARE(VIR_ARCH_PPC64, "host", "guest-compat-bad", VIR_CPU_COMPARE_ERROR);
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
    DO_TEST_UPDATE(VIR_ARCH_PPC64, "host", "guest-legacy-bad", VIR_CPU_COMPARE_ERROR);
    DO_TEST_UPDATE(VIR_ARCH_PPC64, "host", "guest-compat-none", VIR_CPU_COMPARE_IDENTICAL);
    DO_TEST_UPDATE(VIR_ARCH_PPC64, "host", "guest-compat-valid", VIR_CPU_COMPARE_IDENTICAL);
    DO_TEST_UPDATE(VIR_ARCH_PPC64, "host", "guest-compat-bad", VIR_CPU_COMPARE_ERROR);
    DO_TEST_UPDATE(VIR_ARCH_PPC64, "host", "guest-compat-incompatible", VIR_CPU_COMPARE_INCOMPATIBLE);

    /* computing baseline CPUs */
    DO_TEST_BASELINE(VIR_ARCH_X86_64, "incompatible-vendors", 0, -1);
    DO_TEST_BASELINE(VIR_ARCH_X86_64, "no-vendor", 0, 0);
    DO_TEST_BASELINE(VIR_ARCH_X86_64, "some-vendors", 0, 0);
    DO_TEST_BASELINE(VIR_ARCH_X86_64, "simple", 0, 0);
    DO_TEST_BASELINE(VIR_ARCH_X86_64, "simple", VIR_CONNECT_BASELINE_CPU_EXPAND_FEATURES, 0);
    DO_TEST_BASELINE(VIR_ARCH_X86_64, "features", 0, 0);
    DO_TEST_BASELINE(VIR_ARCH_X86_64, "features", VIR_CONNECT_BASELINE_CPU_EXPAND_FEATURES, 0);
    DO_TEST_BASELINE(VIR_ARCH_X86_64, "Westmere+Nehalem", 0, 0);
    DO_TEST_BASELINE(VIR_ARCH_X86_64, "Westmere+Nehalem", VIR_CONNECT_BASELINE_CPU_MIGRATABLE, 0);

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
    DO_TEST_GUESTCPU(VIR_ARCH_PPC64, "host", "guest-legacy-bad", ppc_models, -1);

    DO_TEST_CPUID(VIR_ARCH_X86_64, "A10-5800K", JSON_HOST);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Atom-D510", JSON_NONE);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Atom-N450", JSON_NONE);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Atom-P5362", JSON_MODELS_REQUIRED);
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
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Core-i7-8550U", JSON_MODELS);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Core-i7-8700", JSON_MODELS);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Core2-E6850", JSON_HOST);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Core2-Q9500", JSON_NONE);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Hygon-C86-7185-32-core", JSON_HOST);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "EPYC-7601-32-Core", JSON_HOST);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "EPYC-7601-32-Core-ibpb", JSON_MODELS_REQUIRED);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "EPYC-7502-32-Core", JSON_MODELS);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "FX-8150", JSON_NONE);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Opteron-1352", JSON_NONE);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Opteron-2350", JSON_HOST);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Opteron-6234", JSON_HOST);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Opteron-6282", JSON_NONE);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Pentium-P6100", JSON_NONE);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Phenom-B95", JSON_HOST);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Ryzen-7-1800X-Eight-Core", JSON_HOST);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Ryzen-9-3900X-12-Core", JSON_MODELS);
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
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Xeon-Gold-6130", JSON_MODELS);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Xeon-Gold-6148", JSON_HOST);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Xeon-Platinum-8268", JSON_HOST);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Xeon-Platinum-9242", JSON_MODELS);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Xeon-W3520", JSON_HOST);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Xeon-X5460", JSON_NONE);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Ice-Lake-Server", JSON_MODELS);
    DO_TEST_CPUID(VIR_ARCH_X86_64, "Cooperlake", JSON_MODELS);

    DO_TEST_CPUID_BASELINE(VIR_ARCH_X86_64, "Ryzen+Rome",
                           "Ryzen-7-1800X-Eight-Core", "Ryzen-9-3900X-12-Core");
    DO_TEST_CPUID_BASELINE(VIR_ARCH_X86_64, "EPYC+Rome",
                           "EPYC-7601-32-Core", "EPYC-7502-32-Core");
    DO_TEST_CPUID_BASELINE(VIR_ARCH_X86_64, "Haswell-noTSX-IBRS+Skylake",
                           "Xeon-E5-2609-v3", "Xeon-Gold-6148");
    DO_TEST_CPUID_BASELINE(VIR_ARCH_X86_64, "Haswell-noTSX-IBRS+Skylake-IBRS",
                           "Xeon-E5-2609-v3", "Xeon-Gold-6130");
    DO_TEST_CPUID_BASELINE(VIR_ARCH_X86_64, "Broadwell-IBRS+Cascadelake",
                           "Xeon-E5-2623-v4", "Xeon-Platinum-8268");
    DO_TEST_CPUID_BASELINE(VIR_ARCH_X86_64, "Cascadelake+Skylake-IBRS",
                           "Xeon-Platinum-8268", "Xeon-Gold-6130");
    DO_TEST_CPUID_BASELINE(VIR_ARCH_X86_64, "Cascadelake+Skylake",
                           "Xeon-Platinum-9242", "Xeon-Gold-6148");
    DO_TEST_CPUID_BASELINE(VIR_ARCH_X86_64, "Cascadelake+Icelake",
                           "Xeon-Platinum-9242", "Ice-Lake-Server");
    DO_TEST_CPUID_BASELINE(VIR_ARCH_X86_64, "Cooperlake+Icelake",
                           "Cooperlake", "Ice-Lake-Server");
    DO_TEST_CPUID_BASELINE(VIR_ARCH_X86_64, "Cooperlake+Cascadelake",
                           "Cooperlake", "Xeon-Platinum-9242");
    DO_TEST_CPUID_BASELINE(VIR_ARCH_X86_64, "Skylake-Client+Server",
                           "Core-i5-6600", "Xeon-Gold-6148");
    DO_TEST_CPUID_BASELINE(VIR_ARCH_X86_64, "Haswell-noTSX-IBRS+Broadwell",
                           "Xeon-E5-2609-v3", "Xeon-E5-2650-v4");
    DO_TEST_CPUID_BASELINE(VIR_ARCH_X86_64, "Haswell+Skylake",
                           "Xeon-E7-8890-v3", "Xeon-Gold-5115");
 cleanup:
#if WITH_QEMU
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
