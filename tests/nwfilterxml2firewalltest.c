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

# define __VIR_FIREWALL_PRIV_H_ALLOW__
# include "virfirewallpriv.h"

# define __VIR_COMMAND_PRIV_H_ALLOW__
# include "vircommandpriv.h"

# define VIR_FROM_THIS VIR_FROM_NONE

static const char *abs_top_srcdir;

# ifdef __linux__
#  define RULESTYPE "linux"
# else
#  error "test case not ported to this platform"
# endif

typedef struct _virNWFilterInst virNWFilterInst;
typedef virNWFilterInst *virNWFilterInstPtr;
struct _virNWFilterInst {
    virNWFilterDefPtr *filters;
    size_t nfilters;
    virNWFilterRuleInstPtr *rules;
    size_t nrules;
};

/*
 * Some sets of rules that will be common to all test files,
 * so we don't bother including them in the test data files
 * as that would just bloat them
 */

static const char *commonRules[] = {
    /* Dropping ebtables rules */
    "ebtables -t nat -D PREROUTING -i vnet0 -j libvirt-J-vnet0\n"
    "ebtables -t nat -D POSTROUTING -o vnet0 -j libvirt-P-vnet0\n"
    "ebtables -t nat -L libvirt-J-vnet0\n"
    "ebtables -t nat -L libvirt-P-vnet0\n"
    "ebtables -t nat -F libvirt-J-vnet0\n"
    "ebtables -t nat -X libvirt-J-vnet0\n"
    "ebtables -t nat -F libvirt-P-vnet0\n"
    "ebtables -t nat -X libvirt-P-vnet0\n",

    /* Creating ebtables chains */
    "ebtables -t nat -N libvirt-J-vnet0\n"
    "ebtables -t nat -N libvirt-P-vnet0\n",

    /* Dropping iptables rules */
    "iptables -D libvirt-out -m physdev --physdev-is-bridged --physdev-out vnet0 -g FP-vnet0\n"
    "iptables -D libvirt-out -m physdev --physdev-out vnet0 -g FP-vnet0\n"
    "iptables -D libvirt-in -m physdev --physdev-in vnet0 -g FJ-vnet0\n"
    "iptables -D libvirt-host-in -m physdev --physdev-in vnet0 -g HJ-vnet0\n"
    "iptables -F FP-vnet0\n"
    "iptables -X FP-vnet0\n"
    "iptables -F FJ-vnet0\n"
    "iptables -X FJ-vnet0\n"
    "iptables -F HJ-vnet0\n"
    "iptables -X HJ-vnet0\n",

    /* Creating iptables chains */
    "iptables -N libvirt-in\n"
    "iptables -N libvirt-out\n"
    "iptables -N libvirt-in-post\n"
    "iptables -N libvirt-host-in\n"
    "iptables -D FORWARD -j libvirt-in\n"
    "iptables -D FORWARD -j libvirt-out\n"
    "iptables -D FORWARD -j libvirt-in-post\n"
    "iptables -D INPUT -j libvirt-host-in\n"
    "iptables -I FORWARD 1 -j libvirt-in\n"
    "iptables -I FORWARD 2 -j libvirt-out\n"
    "iptables -I FORWARD 3 -j libvirt-in-post\n"
    "iptables -I INPUT 1 -j libvirt-host-in\n"
    "iptables -N FP-vnet0\n"
    "iptables -N FJ-vnet0\n"
    "iptables -N HJ-vnet0\n"
    "iptables -A libvirt-out -m physdev --physdev-is-bridged --physdev-out vnet0 -g FP-vnet0\n"
    "iptables -A libvirt-in -m physdev --physdev-in vnet0 -g FJ-vnet0\n"
    "iptables -A libvirt-host-in -m physdev --physdev-in vnet0 -g HJ-vnet0\n"
    "iptables -D libvirt-in-post -m physdev --physdev-in vnet0 -j ACCEPT\n"
    "iptables -A libvirt-in-post -m physdev --physdev-in vnet0 -j ACCEPT\n",

    /* Dropping ip6tables rules */
    "ip6tables -D libvirt-out -m physdev --physdev-is-bridged --physdev-out vnet0 -g FP-vnet0\n"
    "ip6tables -D libvirt-out -m physdev --physdev-out vnet0 -g FP-vnet0\n"
    "ip6tables -D libvirt-in -m physdev --physdev-in vnet0 -g FJ-vnet0\n"
    "ip6tables -D libvirt-host-in -m physdev --physdev-in vnet0 -g HJ-vnet0\n"
    "ip6tables -F FP-vnet0\n"
    "ip6tables -X FP-vnet0\n"
    "ip6tables -F FJ-vnet0\n"
    "ip6tables -X FJ-vnet0\n"
    "ip6tables -F HJ-vnet0\n"
    "ip6tables -X HJ-vnet0\n",

    /* Creating ip6tables chains */
    "ip6tables -N libvirt-in\n"
    "ip6tables -N libvirt-out\n"
    "ip6tables -N libvirt-in-post\n"
    "ip6tables -N libvirt-host-in\n"
    "ip6tables -D FORWARD -j libvirt-in\n"
    "ip6tables -D FORWARD -j libvirt-out\n"
    "ip6tables -D FORWARD -j libvirt-in-post\n"
    "ip6tables -D INPUT -j libvirt-host-in\n"
    "ip6tables -I FORWARD 1 -j libvirt-in\n"
    "ip6tables -I FORWARD 2 -j libvirt-out\n"
    "ip6tables -I FORWARD 3 -j libvirt-in-post\n"
    "ip6tables -I INPUT 1 -j libvirt-host-in\n"
    "ip6tables -N FP-vnet0\n"
    "ip6tables -N FJ-vnet0\n"
    "ip6tables -N HJ-vnet0\n"
    "ip6tables -A libvirt-out -m physdev --physdev-is-bridged --physdev-out vnet0 -g FP-vnet0\n"
    "ip6tables -A libvirt-in -m physdev --physdev-in vnet0 -g FJ-vnet0\n"
    "ip6tables -A libvirt-host-in -m physdev --physdev-in vnet0 -g HJ-vnet0\n"
    "ip6tables -D libvirt-in-post -m physdev --physdev-in vnet0 -j ACCEPT\n"
    "ip6tables -A libvirt-in-post -m physdev --physdev-in vnet0 -j ACCEPT\n",

    /* Inserting ebtables rules */
    "ebtables -t nat -A PREROUTING -i vnet0 -j libvirt-J-vnet0\n"
    "ebtables -t nat -A POSTROUTING -o vnet0 -j libvirt-P-vnet0\n",
};


static virNWFilterHashTablePtr
virNWFilterCreateVarsFrom(virNWFilterHashTablePtr vars1,
                          virNWFilterHashTablePtr vars2)
{
    virNWFilterHashTablePtr res = virNWFilterHashTableCreate(0);
    if (!res)
        return NULL;

    if (virNWFilterHashTablePutAll(vars1, res) < 0)
        goto err_exit;

    if (virNWFilterHashTablePutAll(vars2, res) < 0)
        goto err_exit;

    return res;

 err_exit:
    virNWFilterHashTableFree(res);
    return NULL;
}


static void
virNWFilterRuleInstFree(virNWFilterRuleInstPtr inst)
{
    if (!inst)
        return;

    virNWFilterHashTableFree(inst->vars);
    VIR_FREE(inst);
}


static void
virNWFilterInstReset(virNWFilterInstPtr inst)
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
                     virNWFilterHashTablePtr vars,
                     virNWFilterInstPtr inst);

static int
virNWFilterRuleDefToRuleInst(virNWFilterDefPtr def,
                             virNWFilterRuleDefPtr rule,
                             virNWFilterHashTablePtr vars,
                             virNWFilterInstPtr inst)
{
    virNWFilterRuleInstPtr ruleinst;
    int ret = -1;

    if (VIR_ALLOC(ruleinst) < 0)
        goto cleanup;

    ruleinst->chainSuffix = def->chainsuffix;
    ruleinst->chainPriority = def->chainPriority;
    ruleinst->def = rule;
    ruleinst->priority = rule->priority;
    if (!(ruleinst->vars = virNWFilterHashTableCreate(0)))
        goto cleanup;
    if (virNWFilterHashTablePutAll(vars, ruleinst->vars) < 0)
        goto cleanup;

    if (VIR_APPEND_ELEMENT(inst->rules,
                           inst->nrules,
                           ruleinst) < 0)
        goto cleanup;
    ruleinst = NULL;

    ret = 0;
 cleanup:
    virNWFilterRuleInstFree(ruleinst);
    return ret;
}


static int
virNWFilterIncludeDefToRuleInst(virNWFilterIncludeDefPtr inc,
                                virNWFilterHashTablePtr vars,
                                virNWFilterInstPtr inst)
{
    virNWFilterHashTablePtr tmpvars = NULL;
    int ret = -1;
    char *xml;

    if (virAsprintf(&xml, "%s/nwfilterxml2firewalldata/%s.xml",
                    abs_srcdir, inc->filterref) < 0)
        return -1;

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
    virNWFilterHashTableFree(tmpvars);
    VIR_FREE(xml);
    return ret;
}

static int
virNWFilterDefToInst(const char *xml,
                     virNWFilterHashTablePtr vars,
                     virNWFilterInstPtr inst)
{
    size_t i;
    int ret = -1;
    virNWFilterDefPtr def = virNWFilterDefParseFile(xml);

    if (!def)
        return -1;

    if (VIR_APPEND_ELEMENT_COPY(inst->filters,
                                inst->nfilters,
                                def) < 0) {
        virNWFilterDefFree(def);
        goto cleanup;
    }

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

    for (i = 0; i < ARRAY_CARDINALITY(commonRules); i++) {
        char *tmp = strstr(offset, commonRules[i]);
        size_t len = strlen(commonRules[i]);
        if (tmp) {
            memmove(tmp, tmp + len, (strlen(tmp) + 1) - len);
            offset = tmp;
        }
    }
}


static int testSetOneParameter(virNWFilterHashTablePtr vars,
                               const char *name,
                               const char *value)
{
    int ret = -1;
    virNWFilterVarValuePtr val;

    if ((val = virHashLookup(vars->hashTable, name)) == NULL) {
        val = virNWFilterVarValueCreateSimpleCopyValue(value);
        if (!val)
            goto cleanup;
        if (virNWFilterHashTablePut(vars, name, val) < 0) {
            virNWFilterVarValueFree(val);
            goto cleanup;
        }
    } else {
        if (virNWFilterVarValueAddValueCopy(val, value) < 0)
            goto cleanup;
    }
    ret = 0;
 cleanup:
    return ret;
}

static int testSetDefaultParameters(virNWFilterHashTablePtr vars)
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
    char *actualargv = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    virNWFilterHashTablePtr vars = virNWFilterHashTableCreate(0);
    virNWFilterInst inst;
    int ret = -1;

    memset(&inst, 0, sizeof(inst));

    virCommandSetDryRun(&buf, NULL, NULL);

    if (!vars)
        goto cleanup;

    if (testSetDefaultParameters(vars) < 0)
        goto cleanup;

    if (virNWFilterDefToInst(xml,
                             vars,
                             &inst) < 0)
        goto cleanup;

    if (ebiptables_driver.applyNewRules("vnet0", inst.rules, inst.nrules) < 0)
        goto cleanup;

    if (virBufferError(&buf))
        goto cleanup;

    actualargv = virBufferContentAndReset(&buf);
    virTestClearCommandPath(actualargv);
    virCommandSetDryRun(NULL, NULL, NULL);

    testRemoveCommonRules(actualargv);

    if (virTestCompareToFile(actualargv, cmdline) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virBufferFreeAndReset(&buf);
    VIR_FREE(actualargv);
    virNWFilterInstReset(&inst);
    virNWFilterHashTableFree(vars);
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
    char *xml = NULL;
    char *args = NULL;

    if (virAsprintf(&xml, "%s/nwfilterxml2firewalldata/%s.xml",
                    abs_srcdir, info->name) < 0 ||
        virAsprintf(&args, "%s/nwfilterxml2firewalldata/%s-%s.args",
                    abs_srcdir, info->name, RULESTYPE) < 0)
        goto cleanup;

    result = testCompareXMLToArgvFiles(xml, args);

 cleanup:
    VIR_FREE(xml);
    VIR_FREE(args);
    return result;
}


static int
mymain(void)
{
    int ret = 0;

    abs_top_srcdir = getenv("abs_top_srcdir");
    if (!abs_top_srcdir)
        abs_top_srcdir = abs_srcdir "/..";

# define DO_TEST(name)                                                  \
    do {                                                                \
        static struct testInfo info = {                                 \
            name,                                                       \
        };                                                              \
        if (virTestRun("NWFilter XML-2-firewall " name,                 \
                       testCompareXMLToIPTablesHelper, &info) < 0)      \
            ret = -1;                                                   \
    } while (0)

    virFirewallSetLockOverride(true);

    if (virFirewallSetBackend(VIR_FIREWALL_BACKEND_DIRECT) < 0) {
        ret = -1;
        goto cleanup;
    }

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

 cleanup:
    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)

#else /* ! defined (__linux__) */

int main(void)
{
    return EXIT_AM_SKIP;
}

#endif /* ! defined (__linux__) */
