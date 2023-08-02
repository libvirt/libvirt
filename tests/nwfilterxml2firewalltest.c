/*
 * nwfilterxml2firewalltest.c: Test iptables rule generation
 *
 * Copyright (C) 2014 Red Hat, Inc.
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
 */

#include <config.h>

#if defined (__linux__)

# include "testutils.h"
# include "nwfilter/nwfilter_ebiptables_driver.h"
# include "virbuffer.h"

# define LIBVIRT_VIRCOMMANDPRIV_H_ALLOW
# include "vircommandpriv.h"

# define VIR_FROM_THIS VIR_FROM_NONE

# ifdef __linux__
#  define RULESTYPE "linux"
# else
#  error "test case not ported to this platform"
# endif

typedef struct _virNWFilterInst virNWFilterInst;
struct _virNWFilterInst {
    virNWFilterDef **filters;
    size_t nfilters;
    virNWFilterRuleInst **rules;
    size_t nrules;
};

/*
 * Some sets of rules that will be common to all test files,
 * so we don't bother including them in the test data files
 * as that would just bloat them
 */

static const char *commonRules[] = {
    /* Dropping ebtables rules */
    "ebtables \\\n--concurrent \\\n-t nat \\\n-D PREROUTING \\\n-i vnet0 \\\n-j libvirt-J-vnet0\n"
    "ebtables \\\n--concurrent \\\n-t nat \\\n-D POSTROUTING \\\n-o vnet0 \\\n-j libvirt-P-vnet0\n"
    "ebtables \\\n--concurrent \\\n-t nat \\\n-L libvirt-J-vnet0\n"
    "ebtables \\\n--concurrent \\\n-t nat \\\n-L libvirt-P-vnet0\n"
    "ebtables \\\n--concurrent \\\n-t nat \\\n-F libvirt-J-vnet0\n"
    "ebtables \\\n--concurrent \\\n-t nat \\\n-X libvirt-J-vnet0\n"
    "ebtables \\\n--concurrent \\\n-t nat \\\n-F libvirt-P-vnet0\n"
    "ebtables \\\n--concurrent \\\n-t nat \\\n-X libvirt-P-vnet0\n",

    /* Creating ebtables chains */
    "ebtables \\\n--concurrent \\\n-t nat \\\n-N libvirt-J-vnet0\n"
    "ebtables \\\n--concurrent \\\n-t nat \\\n-N libvirt-P-vnet0\n",

    /* Dropping iptables rules */
    "iptables \\\n-w \\\n-D libvirt-out \\\n-m physdev \\\n--physdev-is-bridged \\\n--physdev-out vnet0 \\\n-g FP-vnet0\n"
    "iptables \\\n-w \\\n-D libvirt-out \\\n-m physdev \\\n--physdev-out vnet0 \\\n-g FP-vnet0\n"
    "iptables \\\n-w \\\n-D libvirt-in \\\n-m physdev \\\n--physdev-in vnet0 \\\n-g FJ-vnet0\n"
    "iptables \\\n-w \\\n-D libvirt-host-in \\\n-m physdev \\\n--physdev-in vnet0 \\\n-g HJ-vnet0\n"
    "iptables \\\n-w \\\n-F FP-vnet0\n"
    "iptables \\\n-w \\\n-X FP-vnet0\n"
    "iptables \\\n-w \\\n-F FJ-vnet0\n"
    "iptables \\\n-w \\\n-X FJ-vnet0\n"
    "iptables \\\n-w \\\n-F HJ-vnet0\n"
    "iptables \\\n-w \\\n-X HJ-vnet0\n",

    /* Creating iptables chains */
    "iptables \\\n-w \\\n-N libvirt-in\n"
    "iptables \\\n-w \\\n-N libvirt-out\n"
    "iptables \\\n-w \\\n-N libvirt-in-post\n"
    "iptables \\\n-w \\\n-N libvirt-host-in\n"
    "iptables \\\n-w \\\n-D FORWARD \\\n-j libvirt-in\n"
    "iptables \\\n-w \\\n-D FORWARD \\\n-j libvirt-out\n"
    "iptables \\\n-w \\\n-D FORWARD \\\n-j libvirt-in-post\n"
    "iptables \\\n-w \\\n-D INPUT \\\n-j libvirt-host-in\n"
    "iptables \\\n-w \\\n-I FORWARD 1 \\\n-j libvirt-in\n"
    "iptables \\\n-w \\\n-I FORWARD 2 \\\n-j libvirt-out\n"
    "iptables \\\n-w \\\n-I FORWARD 3 \\\n-j libvirt-in-post\n"
    "iptables \\\n-w \\\n-I INPUT 1 \\\n-j libvirt-host-in\n"
    "iptables \\\n-w \\\n-N FP-vnet0\n"
    "iptables \\\n-w \\\n-N FJ-vnet0\n"
    "iptables \\\n-w \\\n-N HJ-vnet0\n"
    "iptables \\\n-w \\\n-A libvirt-out \\\n-m physdev \\\n--physdev-is-bridged \\\n--physdev-out vnet0 \\\n-g FP-vnet0\n"
    "iptables \\\n-w \\\n-A libvirt-in \\\n-m physdev \\\n--physdev-in vnet0 \\\n-g FJ-vnet0\n"
    "iptables \\\n-w \\\n-A libvirt-host-in \\\n-m physdev \\\n--physdev-in vnet0 \\\n-g HJ-vnet0\n"
    "iptables \\\n-w \\\n-D libvirt-in-post \\\n-m physdev \\\n--physdev-in vnet0 \\\n-j ACCEPT\n"
    "iptables \\\n-w \\\n-A libvirt-in-post \\\n-m physdev \\\n--physdev-in vnet0 \\\n-j ACCEPT\n",

    /* Dropping ip6tables rules */
    "ip6tables \\\n-w \\\n-D libvirt-out \\\n-m physdev \\\n--physdev-is-bridged \\\n--physdev-out vnet0 \\\n-g FP-vnet0\n"
    "ip6tables \\\n-w \\\n-D libvirt-out \\\n-m physdev \\\n--physdev-out vnet0 \\\n-g FP-vnet0\n"
    "ip6tables \\\n-w \\\n-D libvirt-in \\\n-m physdev \\\n--physdev-in vnet0 \\\n-g FJ-vnet0\n"
    "ip6tables \\\n-w \\\n-D libvirt-host-in \\\n-m physdev \\\n--physdev-in vnet0 \\\n-g HJ-vnet0\n"
    "ip6tables \\\n-w \\\n-F FP-vnet0\n"
    "ip6tables \\\n-w \\\n-X FP-vnet0\n"
    "ip6tables \\\n-w \\\n-F FJ-vnet0\n"
    "ip6tables \\\n-w \\\n-X FJ-vnet0\n"
    "ip6tables \\\n-w \\\n-F HJ-vnet0\n"
    "ip6tables \\\n-w \\\n-X HJ-vnet0\n",

    /* Creating ip6tables chains */
    "ip6tables \\\n-w \\\n-N libvirt-in\n"
    "ip6tables \\\n-w \\\n-N libvirt-out\n"
    "ip6tables \\\n-w \\\n-N libvirt-in-post\n"
    "ip6tables \\\n-w \\\n-N libvirt-host-in\n"
    "ip6tables \\\n-w \\\n-D FORWARD \\\n-j libvirt-in\n"
    "ip6tables \\\n-w \\\n-D FORWARD \\\n-j libvirt-out\n"
    "ip6tables \\\n-w \\\n-D FORWARD \\\n-j libvirt-in-post\n"
    "ip6tables \\\n-w \\\n-D INPUT \\\n-j libvirt-host-in\n"
    "ip6tables \\\n-w \\\n-I FORWARD 1 \\\n-j libvirt-in\n"
    "ip6tables \\\n-w \\\n-I FORWARD 2 \\\n-j libvirt-out\n"
    "ip6tables \\\n-w \\\n-I FORWARD 3 \\\n-j libvirt-in-post\n"
    "ip6tables \\\n-w \\\n-I INPUT 1 \\\n-j libvirt-host-in\n"
    "ip6tables \\\n-w \\\n-N FP-vnet0\n"
    "ip6tables \\\n-w \\\n-N FJ-vnet0\n"
    "ip6tables \\\n-w \\\n-N HJ-vnet0\n"
    "ip6tables \\\n-w \\\n-A libvirt-out \\\n-m physdev \\\n--physdev-is-bridged \\\n--physdev-out vnet0 \\\n-g FP-vnet0\n"
    "ip6tables \\\n-w \\\n-A libvirt-in \\\n-m physdev \\\n--physdev-in vnet0 \\\n-g FJ-vnet0\n"
    "ip6tables \\\n-w \\\n-A libvirt-host-in \\\n-m physdev \\\n--physdev-in vnet0 \\\n-g HJ-vnet0\n"
    "ip6tables \\\n-w \\\n-D libvirt-in-post \\\n-m physdev \\\n--physdev-in vnet0 \\\n-j ACCEPT\n"
    "ip6tables \\\n-w \\\n-A libvirt-in-post \\\n-m physdev \\\n--physdev-in vnet0 \\\n-j ACCEPT\n",

    /* Inserting ebtables rules */
    "ebtables \\\n--concurrent \\\n-t nat \\\n-A PREROUTING \\\n-i vnet0 \\\n-j libvirt-J-vnet0\n"
    "ebtables \\\n--concurrent \\\n-t nat \\\n-A POSTROUTING \\\n-o vnet0 \\\n-j libvirt-P-vnet0\n",
};


static GHashTable *
virNWFilterCreateVarsFrom(GHashTable *vars1,
                          GHashTable *vars2)
{
    g_autoptr(GHashTable) res = virHashNew(virNWFilterVarValueHashFree);

    if (virNWFilterHashTablePutAll(vars1, res) < 0)
        return NULL;

    if (virNWFilterHashTablePutAll(vars2, res) < 0)
        return NULL;

    return g_steal_pointer(&res);
}


static void
virNWFilterRuleInstFree(virNWFilterRuleInst *inst)
{
    if (!inst)
        return;

    g_clear_pointer(&inst->vars, g_hash_table_unref);
    g_free(inst);
}


static void
virNWFilterInstReset(virNWFilterInst *inst)
{
    size_t i;

    for (i = 0; i < inst->nfilters; i++)
        virNWFilterDefFree(inst->filters[i]);
    VIR_FREE(inst->filters);
    inst->nfilters = 0;

    for (i = 0; i < inst->nrules; i++)
        virNWFilterRuleInstFree(inst->rules[i]);
    VIR_FREE(inst->rules);
    inst->nrules = 0;
}


static int
virNWFilterDefToInst(const char *xml,
                     GHashTable *vars,
                     virNWFilterInst *inst);

static int
virNWFilterRuleDefToRuleInst(virNWFilterDef *def,
                             virNWFilterRuleDef *rule,
                             GHashTable *vars,
                             virNWFilterInst *inst)
{
    virNWFilterRuleInst *ruleinst;
    int ret = -1;

    ruleinst = g_new0(virNWFilterRuleInst, 1);

    ruleinst->chainSuffix = def->chainsuffix;
    ruleinst->chainPriority = def->chainPriority;
    ruleinst->def = rule;
    ruleinst->priority = rule->priority;
    ruleinst->vars = virHashNew(virNWFilterVarValueHashFree);

    if (virNWFilterHashTablePutAll(vars, ruleinst->vars) < 0)
        goto cleanup;

    VIR_APPEND_ELEMENT(inst->rules, inst->nrules, ruleinst);

    ret = 0;
 cleanup:
    virNWFilterRuleInstFree(ruleinst);
    return ret;
}


static int
virNWFilterIncludeDefToRuleInst(virNWFilterIncludeDef *inc,
                                GHashTable *vars,
                                virNWFilterInst *inst)
{
    g_autoptr(GHashTable) tmpvars = NULL;
    int ret = -1;
    g_autofree char *xml = NULL;

    xml = g_strdup_printf("%s/nwfilterxml2firewalldata/%s.xml", abs_srcdir,
                          inc->filterref);

    /* create a temporary hashmap for depth-first tree traversal */
    if (!(tmpvars = virNWFilterCreateVarsFrom(inc->params,
                                              vars)))
        goto cleanup;

    if (virNWFilterDefToInst(xml,
                             tmpvars,
                             inst) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    if (ret < 0)
        virNWFilterInstReset(inst);
    return ret;
}

static int
virNWFilterDefToInst(const char *xml,
                     GHashTable *vars,
                     virNWFilterInst *inst)
{
    size_t i;
    int ret = -1;
    virNWFilterDef *def = virNWFilterDefParse(NULL, xml, 0);

    if (!def)
        return -1;

    VIR_APPEND_ELEMENT_COPY(inst->filters, inst->nfilters, def);

    for (i = 0; i < def->nentries; i++) {
        if (def->filterEntries[i]->rule) {
            if (virNWFilterRuleDefToRuleInst(def,
                                             def->filterEntries[i]->rule,
                                             vars,
                                             inst) < 0)
                goto cleanup;
        } else if (def->filterEntries[i]->include) {
            if (virNWFilterIncludeDefToRuleInst(def->filterEntries[i]->include,
                                                vars,
                                                inst) < 0)
                goto cleanup;
        }
    }

    ret = 0;
 cleanup:
    if (ret < 0)
        virNWFilterInstReset(inst);
    return ret;
}


static void testRemoveCommonRules(char *rules)
{
    size_t i;
    char *offset = rules;

    for (i = 0; i < G_N_ELEMENTS(commonRules); i++) {
        char *tmp = strstr(offset, commonRules[i]);
        size_t len = strlen(commonRules[i]);
        if (tmp) {
            memmove(tmp, tmp + len, (strlen(tmp) + 1) - len);
            offset = tmp;
        }
    }
}


static int testSetOneParameter(GHashTable *vars,
                               const char *name,
                               const char *value)
{
    virNWFilterVarValue *val;

    if ((val = virHashLookup(vars, name)) == NULL) {
        val = virNWFilterVarValueCreateSimpleCopyValue(value);
        if (!val)
            return -1;
        if (virHashUpdateEntry(vars, name, val) < 0) {
            virNWFilterVarValueFree(val);
            return -1;
        }
    } else {
        if (virNWFilterVarValueAddValueCopy(val, value) < 0)
            return -1;
    }

    return 0;
}

static int testSetDefaultParameters(GHashTable *vars)
{
    if (testSetOneParameter(vars, "IPSETNAME", "tck_test") < 0 ||
        testSetOneParameter(vars, "A", "1.1.1.1") ||
        testSetOneParameter(vars, "A", "2.2.2.2") ||
        testSetOneParameter(vars, "A", "3.3.3.3") ||
        testSetOneParameter(vars, "A", "3.3.3.3") ||
        testSetOneParameter(vars, "B", "80") ||
        testSetOneParameter(vars, "B", "90") ||
        testSetOneParameter(vars, "B", "80") ||
        testSetOneParameter(vars, "B", "80") ||
        testSetOneParameter(vars, "C", "1080") ||
        testSetOneParameter(vars, "C", "1090") ||
        testSetOneParameter(vars, "C", "1100") ||
        testSetOneParameter(vars, "C", "1110"))
        return -1;
    return 0;
}

static int testCompareXMLToArgvFiles(const char *xml,
                                     const char *cmdline)
{
    g_autofree char *actualargv = NULL;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    g_autoptr(GHashTable) vars = virHashNew(virNWFilterVarValueHashFree);
    virNWFilterInst inst = { 0 };
    int ret = -1;
    g_autoptr(virCommandDryRunToken) dryRunToken = virCommandDryRunTokenNew();

    virCommandSetDryRun(dryRunToken, &buf, true, true, NULL, NULL);

    if (testSetDefaultParameters(vars) < 0)
        goto cleanup;

    if (virNWFilterDefToInst(xml,
                             vars,
                             &inst) < 0)
        goto cleanup;

    if (ebiptables_driver.applyNewRules("vnet0", inst.rules, inst.nrules) < 0)
        goto cleanup;

    actualargv = virBufferContentAndReset(&buf);

    testRemoveCommonRules(actualargv);

    if (virTestCompareToFileFull(actualargv, cmdline, false) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virNWFilterInstReset(&inst);
    return ret;
}

struct testInfo {
    const char *name;
};


static int
testCompareXMLToIPTablesHelper(const void *data)
{
    int result = -1;
    const struct testInfo *info = data;
    g_autofree char *xml = NULL;
    g_autofree char *args = NULL;

    xml = g_strdup_printf("%s/nwfilterxml2firewalldata/%s.xml",
                          abs_srcdir, info->name);
    args = g_strdup_printf("%s/nwfilterxml2firewalldata/%s-%s.args",
                           abs_srcdir, info->name, RULESTYPE);

    result = testCompareXMLToArgvFiles(xml, args);

    return result;
}


static int
mymain(void)
{
    int ret = 0;

# define DO_TEST(name) \
    do { \
        static struct testInfo info = { \
            name, \
        }; \
        if (virTestRun("NWFilter XML-2-firewall " name, \
                       testCompareXMLToIPTablesHelper, &info) < 0) \
            ret = -1; \
    } while (0)

    DO_TEST("ah");
    DO_TEST("ah-ipv6");
    DO_TEST("all");
    DO_TEST("all-ipv6");
    DO_TEST("arp");
    DO_TEST("comment");
    DO_TEST("conntrack");
    DO_TEST("esp");
    DO_TEST("esp-ipv6");
    DO_TEST("example-1");
    DO_TEST("example-2");
    DO_TEST("hex-data");
    DO_TEST("icmp-direction2");
    DO_TEST("icmp-direction3");
    DO_TEST("icmp-direction");
    DO_TEST("icmp");
    DO_TEST("icmpv6");
    DO_TEST("igmp");
    DO_TEST("ip");
    DO_TEST("ipset");
    DO_TEST("ipt-no-macspoof");
    DO_TEST("ipv6");
    DO_TEST("iter1");
    DO_TEST("iter2");
    DO_TEST("iter3");
    DO_TEST("mac");
    DO_TEST("rarp");
    DO_TEST("sctp");
    DO_TEST("sctp-ipv6");
    DO_TEST("stp");
    DO_TEST("target2");
    DO_TEST("target");
    DO_TEST("tcp");
    DO_TEST("tcp-ipv6");
    DO_TEST("udp");
    DO_TEST("udp-ipv6");
    DO_TEST("udplite");
    DO_TEST("udplite-ipv6");
    DO_TEST("vlan");

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN_PRELOAD(mymain, VIR_TEST_MOCK("virfirewall"))

#else /* ! defined (__linux__) */

int main(void)
{
    return EXIT_AM_SKIP;
}

#endif /* ! defined (__linux__) */
