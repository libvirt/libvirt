/*
 * cputest.c: Test the libvirtd internal CPU APIs
 *
 * Copyright (C) 2010-2013 Red Hat, Inc.
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

static const char *abs_top_srcdir;

#define VIR_FROM_THIS VIR_FROM_CPU

enum cpuTestBoolWithError {
    FAIL    = -1,
    NO      = 0,
    YES     = 1
};

enum api {
    API_COMPARE,
    API_GUEST_DATA,
    API_BASELINE,
    API_UPDATE,
    API_HAS_FEATURE
};

static const char *apis[] = {
    "compare",
    "guest data",
    "baseline",
    "update",
    "has feature"
};

struct data {
    const char *arch;
    enum api api;
    const char *host;
    const char *name;
    const char **models;
    const char *modelsName;
    unsigned int nmodels;
    const char *preferred;
    unsigned int flags;
    int result;
};


static virCPUDefPtr
cpuTestLoadXML(const char *arch, const char *name)
{
    char *xml = NULL;
    xmlDocPtr doc = NULL;
    xmlXPathContextPtr ctxt = NULL;
    virCPUDefPtr cpu = NULL;

    if (virAsprintf(&xml, "%s/cputestdata/%s-%s.xml", abs_srcdir, arch, name) < 0)
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
cpuTestLoadMultiXML(const char *arch,
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

    if (virAsprintf(&xml, "%s/cputestdata/%s-%s.xml", abs_srcdir, arch, name) < 0)
        goto cleanup;

    if (!(doc = virXMLParseFileCtxt(xml, &ctxt)))
        goto cleanup;

    n = virXPathNodeSet("/cpuTest/cpu", ctxt, &nodes);
    if (n <= 0 || (VIR_ALLOC_N(cpus, n) < 0))
        goto cleanup;

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
cpuTestCompareXML(const char *arch,
                  virCPUDef *cpu,
                  const char *name,
                  unsigned int flags)
{
    char *xml = NULL;
    char *expected = NULL;
    char *actual = NULL;
    int ret = -1;

    if (virAsprintf(&xml, "%s/cputestdata/%s-%s.xml",
                    abs_srcdir, arch, name) < 0)
        goto cleanup;

    if (virtTestLoadFile(xml, &expected) < 0)
        goto cleanup;

    if (!(actual = virCPUDefFormat(cpu, flags)))
        goto cleanup;

    if (STRNEQ(expected, actual)) {
        if (virTestGetVerbose())
            fprintf(stderr, "\nCompared to %s-%s.xml", arch, name);
        virtTestDifference(stderr, expected, actual);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(xml);
    VIR_FREE(expected);
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

    result = cpuCompare(host, cpu);
    if (data->result == VIR_CPU_COMPARE_ERROR)
        virResetLastError();

    if (data->result != result) {
        if (virTestGetVerbose()) {
            fprintf(stderr, "\nExpected result %s, got %s\n",
                    cpuTestCompResStr(data->result),
                    cpuTestCompResStr(result));
            /* Pad to line up with test name ... in virTestRun */
            fprintf(stderr, "%74s", "... ");
        }
        goto cleanup;
    }

    ret = 0;

 cleanup:
    virCPUDefFree(host);
    virCPUDefFree(cpu);
    return ret;
}


static int
cpuTestGuestData(const void *arg)
{
    const struct data *data = arg;
    int ret = -1;
    virCPUDefPtr host = NULL;
    virCPUDefPtr cpu = NULL;
    virCPUDefPtr guest = NULL;
    virCPUDataPtr guestData = NULL;
    virCPUCompareResult cmpResult;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char *result = NULL;

    if (!(host = cpuTestLoadXML(data->arch, data->host)) ||
        !(cpu = cpuTestLoadXML(data->arch, data->name)))
        goto cleanup;

    cmpResult = cpuGuestData(host, cpu, &guestData, NULL);
    if (cmpResult == VIR_CPU_COMPARE_ERROR ||
        cmpResult == VIR_CPU_COMPARE_INCOMPATIBLE)
        goto cleanup;

    if (VIR_ALLOC(guest) < 0)
        goto cleanup;

    guest->arch = host->arch;
    guest->type = VIR_CPU_TYPE_GUEST;
    guest->match = VIR_CPU_MATCH_EXACT;
    guest->fallback = cpu->fallback;
    if (cpuDecode(guest, guestData, data->models,
                  data->nmodels, data->preferred) < 0) {
        if (data->result < 0) {
            virResetLastError();
            ret = 0;
        }
        goto cleanup;
    }

    virBufferAsprintf(&buf, "%s+%s", data->host, data->name);
    if (data->nmodels)
        virBufferAsprintf(&buf, ",%s", data->modelsName);
    if (data->preferred)
        virBufferAsprintf(&buf, ",%s", data->preferred);
    virBufferAddLit(&buf, "-result");

    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        goto cleanup;
    }
    result = virBufferContentAndReset(&buf);

    ret = cpuTestCompareXML(data->arch, guest, result, 0);

 cleanup:
    VIR_FREE(result);
    cpuDataFree(guestData);
    virCPUDefFree(host);
    virCPUDefFree(cpu);
    virCPUDefFree(guest);
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
        if (!baseline)
            ret = 0;
        else if (virTestGetVerbose()) {
            fprintf(stderr, "\n%-70s... ",
                    "cpuBaseline was expected to fail but it succeeded");
        }
        goto cleanup;
    }
    if (!baseline)
        goto cleanup;

    if (data->flags & VIR_CONNECT_BASELINE_CPU_EXPAND_FEATURES)
        suffix = "expanded";
    else
        suffix = "result";
    if (virAsprintf(&result, "%s-%s", data->name, suffix) < 0)
        goto cleanup;

    if (cpuTestCompareXML(data->arch, baseline, result, 0) < 0)
        goto cleanup;

    for (i = 0; i < ncpus; i++) {
        virCPUCompareResult cmp;

        cmp = cpuCompare(cpus[i], baseline);
        if (cmp != VIR_CPU_COMPARE_SUPERSET &&
            cmp != VIR_CPU_COMPARE_IDENTICAL) {
            if (virTestGetVerbose()) {
                fprintf(stderr,
                        "\nbaseline CPU is incompatible with CPU %zu\n", i);
                fprintf(stderr, "%74s", "... ");
            }
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

    if (cpuUpdate(cpu, host) < 0)
        goto cleanup;

    if (virAsprintf(&result, "%s+%s", data->host, data->name) < 0)
        goto cleanup;

    ret = cpuTestCompareXML(data->arch, cpu, result,
                            VIR_DOMAIN_XML_UPDATE_CPU);

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

    result = cpuHasFeature(hostData, data->name);
    if (data->result == -1)
        virResetLastError();

    if (data->result != result) {
        if (virTestGetVerbose()) {
            fprintf(stderr, "\nExpected result %s, got %s\n",
                    cpuTestBoolWithErrorStr(data->result),
                    cpuTestBoolWithErrorStr(result));
            /* Pad to line up with test name ... in virTestRun */
            fprintf(stderr, "%74s", "... ");
        }
        goto cleanup;
    }

    ret = 0;

 cleanup:
    cpuDataFree(hostData);
    virCPUDefFree(host);
    return ret;
}


static int (*cpuTest[])(const void *) = {
    cpuTestCompare,
    cpuTestGuestData,
    cpuTestBaseline,
    cpuTestUpdate,
    cpuTestHasFeature
};


static int
cpuTestRun(const char *name, const struct data *data)
{
    char *label = NULL;
    char *tmp;

    if (virAsprintf(&label, "CPU %s(%s): %s", apis[data->api], data->arch, name) < 0)
        return -1;

    tmp = virtTestLogContentAndReset();
    VIR_FREE(tmp);

    if (virtTestRun(label, cpuTest[data->api], data) < 0) {
        if (virTestGetDebug()) {
            char *log;
            if ((log = virtTestLogContentAndReset()) &&
                 strlen(log) > 0)
                fprintf(stderr, "\n%s\n", log);
            VIR_FREE(log);
        }

        VIR_FREE(label);
        return -1;
    }

    VIR_FREE(label);
    return 0;
}


static const char *model486[]   = { "486" };
static const char *nomodel[]    = { "nomodel" };
static const char *models[]     = { "qemu64", "core2duo", "Nehalem" };
static const char *ppc_models[]     = { "POWER7", "POWER7_v2.1", "POWER8_v1.0"};

static int
mymain(void)
{
    int ret = 0;
    char *map = NULL;

    abs_top_srcdir = getenv("abs_top_srcdir");
    if (!abs_top_srcdir)
        abs_top_srcdir = abs_srcdir "/..";

    if (virAsprintf(&map, "%s/src/cpu/cpu_map.xml", abs_top_srcdir) < 0 ||
        cpuMapOverride(map) < 0) {
        VIR_FREE(map);
        return EXIT_FAILURE;
    }

#define DO_TEST(arch, api, name, host, cpu,                             \
                models, nmodels, preferred, flags, result)              \
    do {                                                                \
        static struct data data = {                                     \
            arch, api, host, cpu, models,                               \
            models == NULL ? NULL : #models,                            \
            nmodels, preferred, flags, result                           \
        };                                                              \
        if (cpuTestRun(name, &data) < 0)                                \
            ret = -1;                                                   \
    } while (0)

#define DO_TEST_COMPARE(arch, host, cpu, result)                        \
    DO_TEST(arch, API_COMPARE,                                          \
            host "/" cpu " (" #result ")",                              \
            host, cpu, NULL, 0, NULL, 0, result)

#define DO_TEST_UPDATE(arch, host, cpu, result)                         \
    do {                                                                \
        DO_TEST(arch, API_UPDATE,                                       \
                cpu " on " host,                                        \
                host, cpu, NULL, 0, NULL, 0, 0);                        \
        DO_TEST_COMPARE(arch, host, host "+" cpu, result);              \
    } while (0)

#define DO_TEST_BASELINE(arch, name, flags, result)                     \
    do {                                                                \
        const char *suffix = "";                                        \
        char *label;                                                    \
        if ((flags) & VIR_CONNECT_BASELINE_CPU_EXPAND_FEATURES)         \
            suffix = " (expanded)";                                     \
        if (virAsprintf(&label, "%s%s", name, suffix) < 0) {            \
            ret = -1;                                                   \
        } else {                                                        \
            DO_TEST(arch, API_BASELINE, label, NULL, "baseline-" name,  \
                    NULL, 0, NULL, flags, result);                      \
        }                                                               \
        VIR_FREE(label);                                                \
    } while (0)

#define DO_TEST_HASFEATURE(arch, host, feature, result)                 \
    DO_TEST(arch, API_HAS_FEATURE,                                      \
            host "/" feature " (" #result ")",                          \
            host, feature, NULL, 0, NULL, 0, result)

#define DO_TEST_GUESTDATA(arch, host, cpu, models, preferred, result)   \
    DO_TEST(arch, API_GUEST_DATA,                                       \
            host "/" cpu " (" #models ", pref=" #preferred ")",         \
            host, cpu, models,                                          \
            models == NULL ? 0 : sizeof(models) / sizeof(char *),       \
            preferred, 0, result)

    /* host to host comparison */
    DO_TEST_COMPARE("x86", "host", "host", VIR_CPU_COMPARE_IDENTICAL);
    DO_TEST_COMPARE("x86", "host", "host-better", VIR_CPU_COMPARE_INCOMPATIBLE);
    DO_TEST_COMPARE("x86", "host", "host-worse", VIR_CPU_COMPARE_SUPERSET);
    DO_TEST_COMPARE("x86", "host", "host-amd-fake", VIR_CPU_COMPARE_INCOMPATIBLE);
    DO_TEST_COMPARE("x86", "host", "host-incomp-arch", VIR_CPU_COMPARE_INCOMPATIBLE);
    DO_TEST_COMPARE("x86", "host", "host-no-vendor", VIR_CPU_COMPARE_IDENTICAL);
    DO_TEST_COMPARE("x86", "host-no-vendor", "host", VIR_CPU_COMPARE_INCOMPATIBLE);

    /* guest to host comparison */
    DO_TEST_COMPARE("x86", "host", "bogus-model", VIR_CPU_COMPARE_ERROR);
    DO_TEST_COMPARE("x86", "host", "bogus-feature", VIR_CPU_COMPARE_ERROR);
    DO_TEST_COMPARE("x86", "host", "min", VIR_CPU_COMPARE_SUPERSET);
    DO_TEST_COMPARE("x86", "host", "pentium3", VIR_CPU_COMPARE_SUPERSET);
    DO_TEST_COMPARE("x86", "host", "exact", VIR_CPU_COMPARE_SUPERSET);
    DO_TEST_COMPARE("x86", "host", "exact-forbid", VIR_CPU_COMPARE_INCOMPATIBLE);
    DO_TEST_COMPARE("x86", "host", "exact-forbid-extra", VIR_CPU_COMPARE_SUPERSET);
    DO_TEST_COMPARE("x86", "host", "exact-disable", VIR_CPU_COMPARE_SUPERSET);
    DO_TEST_COMPARE("x86", "host", "exact-disable2", VIR_CPU_COMPARE_SUPERSET);
    DO_TEST_COMPARE("x86", "host", "exact-disable-extra", VIR_CPU_COMPARE_SUPERSET);
    DO_TEST_COMPARE("x86", "host", "exact-require", VIR_CPU_COMPARE_SUPERSET);
    DO_TEST_COMPARE("x86", "host", "exact-require-extra", VIR_CPU_COMPARE_INCOMPATIBLE);
    DO_TEST_COMPARE("x86", "host", "exact-force", VIR_CPU_COMPARE_SUPERSET);
    DO_TEST_COMPARE("x86", "host", "strict", VIR_CPU_COMPARE_INCOMPATIBLE);
    DO_TEST_COMPARE("x86", "host", "strict-full", VIR_CPU_COMPARE_IDENTICAL);
    DO_TEST_COMPARE("x86", "host", "strict-disable", VIR_CPU_COMPARE_IDENTICAL);
    DO_TEST_COMPARE("x86", "host", "strict-force-extra", VIR_CPU_COMPARE_IDENTICAL);
    DO_TEST_COMPARE("x86", "host", "guest", VIR_CPU_COMPARE_SUPERSET);
    DO_TEST_COMPARE("x86", "host", "pentium3-amd", VIR_CPU_COMPARE_INCOMPATIBLE);
    DO_TEST_COMPARE("x86", "host-amd", "pentium3-amd", VIR_CPU_COMPARE_SUPERSET);
    DO_TEST_COMPARE("x86", "host-worse", "nehalem-force", VIR_CPU_COMPARE_IDENTICAL);
    DO_TEST_COMPARE("x86", "host-SandyBridge", "exact-force-Haswell", VIR_CPU_COMPARE_IDENTICAL);

    DO_TEST_COMPARE("ppc64", "host", "strict", VIR_CPU_COMPARE_IDENTICAL);
    DO_TEST_COMPARE("ppc64", "host", "exact", VIR_CPU_COMPARE_INCOMPATIBLE);

    /* guest updates for migration
     * automatically compares host CPU with the result */
    DO_TEST_UPDATE("x86", "host", "min", VIR_CPU_COMPARE_IDENTICAL);
    DO_TEST_UPDATE("x86", "host", "pentium3", VIR_CPU_COMPARE_IDENTICAL);
    DO_TEST_UPDATE("x86", "host", "guest", VIR_CPU_COMPARE_SUPERSET);
    DO_TEST_UPDATE("x86", "host", "host-model", VIR_CPU_COMPARE_IDENTICAL);
    DO_TEST_UPDATE("x86", "host", "host-model-nofallback", VIR_CPU_COMPARE_IDENTICAL);
    DO_TEST_UPDATE("x86", "host", "host-passthrough", VIR_CPU_COMPARE_IDENTICAL);

    /* computing baseline CPUs */
    DO_TEST_BASELINE("x86", "incompatible-vendors", 0, -1);
    DO_TEST_BASELINE("x86", "no-vendor", 0, 0);
    DO_TEST_BASELINE("x86", "some-vendors", 0, 0);
    DO_TEST_BASELINE("x86", "1", 0, 0);
    DO_TEST_BASELINE("x86", "2", 0, 0);
    DO_TEST_BASELINE("x86", "3", 0, 0);
    DO_TEST_BASELINE("x86", "3", VIR_CONNECT_BASELINE_CPU_EXPAND_FEATURES, 0);
    DO_TEST_BASELINE("x86", "4", 0, 0);
    DO_TEST_BASELINE("x86", "4", VIR_CONNECT_BASELINE_CPU_EXPAND_FEATURES, 0);
    DO_TEST_BASELINE("x86", "5", 0, 0);
    DO_TEST_BASELINE("x86", "5", VIR_CONNECT_BASELINE_CPU_EXPAND_FEATURES, 0);

    DO_TEST_BASELINE("ppc64", "incompatible-vendors", 0, -1);
    DO_TEST_BASELINE("ppc64", "no-vendor", 0, 0);
    /* CPU features */
    DO_TEST_HASFEATURE("x86", "host", "vmx", YES);
    DO_TEST_HASFEATURE("x86", "host", "lm", YES);
    DO_TEST_HASFEATURE("x86", "host", "sse4.1", YES);
    DO_TEST_HASFEATURE("x86", "host", "3dnowext", NO);
    DO_TEST_HASFEATURE("x86", "host", "skinit", NO);
    DO_TEST_HASFEATURE("x86", "host", "foo", FAIL);

    /* computing guest data and decoding the data into a guest CPU XML */
    DO_TEST_GUESTDATA("x86", "host", "guest", NULL, NULL, 0);
    DO_TEST_GUESTDATA("x86", "host-better", "pentium3", NULL, NULL, 0);
    DO_TEST_GUESTDATA("x86", "host-better", "pentium3", NULL, "pentium3", 0);
    DO_TEST_GUESTDATA("x86", "host-better", "pentium3", NULL, "core2duo", 0);
    DO_TEST_GUESTDATA("x86", "host-worse", "guest", NULL, NULL, 0);
    DO_TEST_GUESTDATA("x86", "host", "strict-force-extra", NULL, NULL, 0);
    DO_TEST_GUESTDATA("x86", "host", "nehalem-force", NULL, NULL, 0);
    DO_TEST_GUESTDATA("x86", "host", "guest", model486, NULL, 0);
    DO_TEST_GUESTDATA("x86", "host", "guest", models, NULL, 0);
    DO_TEST_GUESTDATA("x86", "host", "guest", models, "Penryn", 0);
    DO_TEST_GUESTDATA("x86", "host", "guest", models, "qemu64", 0);
    DO_TEST_GUESTDATA("x86", "host", "guest", nomodel, NULL, -1);
    DO_TEST_GUESTDATA("x86", "host", "guest-nofallback", models, "Penryn", -1);
    DO_TEST_GUESTDATA("x86", "host", "host+host-model", models, "Penryn", 0);
    DO_TEST_GUESTDATA("x86", "host", "host+host-model-nofallback",
                      models, "Penryn", -1);

    DO_TEST_GUESTDATA("ppc64", "host", "guest", ppc_models, NULL, 0);
    DO_TEST_GUESTDATA("ppc64", "host", "guest-nofallback", ppc_models, "POWER7_v2.1", -1);

    VIR_FREE(map);
    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)
