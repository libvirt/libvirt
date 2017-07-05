/*
 * nwfilter_gentech_driver.c: generic technology driver
 *
 * Copyright (C) 2011-2014 Red Hat, Inc.
 * Copyright (C) 2010 IBM Corp.
 * Copyright (C) 2010 Stefan Berger
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
 * Author: Stefan Berger <stefanb@us.ibm.com>
 */

#include <config.h>

#include "internal.h"

#include "viralloc.h"
#include "virlog.h"
#include "domain_conf.h"
#include "virerror.h"
#include "nwfilter_gentech_driver.h"
#include "nwfilter_ebiptables_driver.h"
#include "nwfilter_dhcpsnoop.h"
#include "nwfilter_ipaddrmap.h"
#include "nwfilter_learnipaddr.h"
#include "virnetdev.h"
#include "datatypes.h"
#include "virsocketaddr.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NWFILTER

VIR_LOG_INIT("nwfilter.nwfilter_gentech_driver");

#define NWFILTER_STD_VAR_MAC NWFILTER_VARNAME_MAC
#define NWFILTER_STD_VAR_IP  NWFILTER_VARNAME_IP

#define NWFILTER_DFLT_LEARN  "any"

static int _virNWFilterTeardownFilter(const char *ifname);


static virNWFilterTechDriverPtr filter_tech_drivers[] = {
    &ebiptables_driver,
    NULL
};

/* Serializes instantiation of filters. This is necessary
 * to avoid lock ordering deadlocks. eg __virNWFilterInstantiateFilter
 * will hold a lock on a virNWFilterObjPtr. This in turn invokes
 * virNWFilterInstantiate which invokes virNWFilterDetermineMissingVarsRec
 * which invokes virNWFilterObjListFindByName. This iterates over every single
 * virNWFilterObjPtr in the list. So if 2 threads try to instantiate a
 * filter in parallel, they'll both hold 1 lock at the top level in
 * __virNWFilterInstantiateFilter which will cause the other thread
 * to deadlock in virNWFilterObjListFindByName.
 *
 * XXX better long term solution is to make virNWFilterObjList use a
 * hash table as is done for virDomainObjList. You can then get
 * lockless lookup of objects by name.
 */
static virMutex updateMutex;

int virNWFilterTechDriversInit(bool privileged)
{
    size_t i = 0;
    VIR_DEBUG("Initializing NWFilter technology drivers");
    if (virMutexInitRecursive(&updateMutex) < 0)
        return -1;

    while (filter_tech_drivers[i]) {
        if (!(filter_tech_drivers[i]->flags & TECHDRV_FLAG_INITIALIZED))
            filter_tech_drivers[i]->init(privileged);
        i++;
    }
    return 0;
}


void virNWFilterTechDriversShutdown(void)
{
    size_t i = 0;
    while (filter_tech_drivers[i]) {
        if ((filter_tech_drivers[i]->flags & TECHDRV_FLAG_INITIALIZED))
            filter_tech_drivers[i]->shutdown();
        i++;
    }
    virMutexDestroy(&updateMutex);
}


virNWFilterTechDriverPtr
virNWFilterTechDriverForName(const char *name)
{
    size_t i = 0;
    while (filter_tech_drivers[i]) {
        if (STREQ(filter_tech_drivers[i]->name, name)) {
            if ((filter_tech_drivers[i]->flags & TECHDRV_FLAG_INITIALIZED) == 0)
                break;
            return filter_tech_drivers[i];
        }
        i++;
    }
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


/**
 * virNWFilterVarHashmapAddStdValues:
 * @tables: pointer to hash tabel to add values to
 * @macaddr: The string of the MAC address to add to the hash table,
 *    may be NULL
 * @ipaddr: The string of the IP address to add to the hash table;
 *    may be NULL
 *
 * Returns 0 in case of success, -1 in case an error happened with
 * error having been reported.
 *
 * Adds a couple of standard keys (MAC, IP) to the hash table.
 */
static int
virNWFilterVarHashmapAddStdValues(virNWFilterHashTablePtr table,
                                  char *macaddr,
                                  const virNWFilterVarValue *ipaddr)
{
    virNWFilterVarValue *val;

    if (macaddr) {
        val = virNWFilterVarValueCreateSimple(macaddr);
        if (!val)
            return -1;

        if (virHashAddEntry(table->hashTable,
                            NWFILTER_STD_VAR_MAC,
                            val) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("Could not add variable 'MAC' to hashmap"));
            return -1;
        }
    }

    if (ipaddr) {
        val = virNWFilterVarValueCopy(ipaddr);
        if (!val)
            return -1;

        if (virHashAddEntry(table->hashTable,
                            NWFILTER_STD_VAR_IP,
                            val) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("Could not add variable 'IP' to hashmap"));
            return -1;
        }
    }

    return 0;
}


/**
 * virNWFilterCreateVarHashmap:
 * @macaddr: pointer to string containing formatted MAC address of interface
 * @ipaddr: pointer to string containing formatted IP address used by
 *          VM on this interface; may be NULL
 *
 * Create a hashmap used for evaluating the firewall rules. Initializes
 * it with the standard variable 'MAC' and 'IP' if provided.
 *
 * Returns pointer to hashmap, NULL if an error occurred.
 */
virNWFilterHashTablePtr
virNWFilterCreateVarHashmap(char *macaddr,
                            const virNWFilterVarValue *ipaddr)
{
    virNWFilterHashTablePtr table = virNWFilterHashTableCreate(0);
    if (!table)
        return NULL;

    if (virNWFilterVarHashmapAddStdValues(table, macaddr, ipaddr) < 0) {
        virNWFilterHashTableFree(table);
        return NULL;
    }
    return table;
}


/**
 * Convert a virNWFilterHashTable into a string of comma-separated
 * variable names.
 */
struct printString
{
    virBuffer buf;
    const char *separator;
    bool reportMAC;
    bool reportIP;
};


static int
printString(void *payload ATTRIBUTE_UNUSED, const void *name, void *data)
{
    struct printString *ps = data;

    if ((STREQ((char *)name, NWFILTER_STD_VAR_IP) && !ps->reportIP) ||
        (STREQ((char *)name, NWFILTER_STD_VAR_MAC) && !ps->reportMAC))
        return 0;

    if (virBufferUse(&ps->buf) && ps->separator)
        virBufferAdd(&ps->buf, ps->separator, -1);

    virBufferAdd(&ps->buf, name, -1);
    return 0;
}

/**
 * virNWFilterPrintVars
 *
 * @var: hash table containing variables
 * @separator: separator to use between variable names, i.e., ", "
 * @reportMAC: whether to report the 'MAC' variable
 * @reportIP : whether to report the IP variable
 *
 * Returns a string of comma separated variable names
 */
static char *
virNWFilterPrintVars(virHashTablePtr vars,
                     const char *separator,
                     bool reportMAC,
                     bool reportIP)
{
    struct printString ps = {
        .buf       = VIR_BUFFER_INITIALIZER,
        .separator = separator,
        .reportMAC = reportMAC,
        .reportIP  = reportIP,
    };

    virHashForEach(vars, printString, &ps);

    if (virBufferCheckError(&ps.buf) < 0)
        return NULL;
    return virBufferContentAndReset(&ps.buf);
}


/**
 * virNWFilterCreateVarsFrom:
 * @vars1: pointer to hash table
 * @vars2: pointer to hash table
 *
 * Returns pointer to new hashtable or NULL in case of error with
 * error already reported.
 *
 * Creates a new hash table with contents of var1 and var2 added where
 * contents of var2 will overwrite those of var1.
 */
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


typedef struct _virNWFilterInst virNWFilterInst;
typedef virNWFilterInst *virNWFilterInstPtr;
struct _virNWFilterInst {
    virNWFilterObjPtr *filters;
    size_t nfilters;
    virNWFilterRuleInstPtr *rules;
    size_t nrules;
};


static void
virNWFilterInstReset(virNWFilterInstPtr inst)
{
    size_t i;

    for (i = 0; i < inst->nfilters; i++)
        virNWFilterObjUnlock(inst->filters[i]);
    VIR_FREE(inst->filters);
    inst->nfilters = 0;

    for (i = 0; i < inst->nrules; i++)
        virNWFilterRuleInstFree(inst->rules[i]);
    VIR_FREE(inst->rules);
}



static int
virNWFilterDefToInst(virNWFilterDriverStatePtr driver,
                     virNWFilterDefPtr def,
                     virNWFilterHashTablePtr vars,
                     enum instCase useNewFilter,
                     bool *foundNewFilter,
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
    inst = NULL;

    ret = 0;
 cleanup:
    virNWFilterRuleInstFree(ruleinst);
    return ret;
}


static int
virNWFilterIncludeDefToRuleInst(virNWFilterDriverStatePtr driver,
                                virNWFilterIncludeDefPtr inc,
                                virNWFilterHashTablePtr vars,
                                enum instCase useNewFilter,
                                bool *foundNewFilter,
                                virNWFilterInstPtr inst)
{
    virNWFilterObjPtr obj;
    virNWFilterHashTablePtr tmpvars = NULL;
    virNWFilterDefPtr childdef;
    virNWFilterDefPtr newChilddef;
    int ret = -1;

    VIR_DEBUG("Instantiating filter %s", inc->filterref);
    obj = virNWFilterObjListFindByName(driver->nwfilters,
                                       inc->filterref);
    if (!obj) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("referenced filter '%s' is missing"),
                       inc->filterref);
        goto cleanup;
    }
    if (virNWFilterObjWantRemoved(obj)) {
        virReportError(VIR_ERR_NO_NWFILTER,
                       _("Filter '%s' is in use."),
                       inc->filterref);
        goto cleanup;
    }

    /* create a temporary hashmap for depth-first tree traversal */
    if (!(tmpvars = virNWFilterCreateVarsFrom(inc->params,
                                              vars)))
        goto cleanup;

    childdef = virNWFilterObjGetDef(obj);

    switch (useNewFilter) {
    case INSTANTIATE_FOLLOW_NEWFILTER:
        newChilddef = virNWFilterObjGetNewDef(obj);
        if (newChilddef) {
            childdef = newChilddef;
            *foundNewFilter = true;
        }
        break;
    case INSTANTIATE_ALWAYS:
        break;
    }

    if (VIR_APPEND_ELEMENT(inst->filters,
                           inst->nfilters,
                           obj) < 0)
        goto cleanup;
    obj = NULL;

    if (virNWFilterDefToInst(driver,
                             childdef,
                             tmpvars,
                             useNewFilter,
                             foundNewFilter,
                             inst) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    if (ret < 0)
        virNWFilterInstReset(inst);
    virNWFilterHashTableFree(tmpvars);
    if (obj)
        virNWFilterObjUnlock(obj);
    return ret;
}


/**
 * virNWFilterDefToInst:
 * @driver: the driver state pointer
 * @def: The filter to instantiate
 * @vars: A map holding variable names and values used for instantiating
 *  the filter and its subfilters.
 * @useNewFilter: instruct whether to use a newDef pointer rather than a
 *  def ptr which is useful during a filter update
 * @foundNewFilter: pointer to int indivating whether a newDef pointer was
 *  ever used; variable expected to be initialized to 0 by caller
 * @rulesout: array to be filled with rule instance
 * @nrulesout: counter to be filled with number of rule instances
 *
 * Recursively expand a nested filter into a flat list of rule instances,
 * in a depth-first traversal of the tree.
 *
 * Returns 0 on success, -1 on error
 */
static int
virNWFilterDefToInst(virNWFilterDriverStatePtr driver,
                     virNWFilterDefPtr def,
                     virNWFilterHashTablePtr vars,
                     enum instCase useNewFilter,
                     bool *foundNewFilter,
                     virNWFilterInstPtr inst)
{
    size_t i;
    int ret = -1;

    for (i = 0; i < def->nentries; i++) {
        if (def->filterEntries[i]->rule) {
            if (virNWFilterRuleDefToRuleInst(def,
                                             def->filterEntries[i]->rule,
                                             vars,
                                             inst) < 0)
                goto cleanup;
        } else if (def->filterEntries[i]->include) {
            if (virNWFilterIncludeDefToRuleInst(driver,
                                                def->filterEntries[i]->include,
                                                vars,
                                                useNewFilter, foundNewFilter,
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


static int
virNWFilterDetermineMissingVarsRec(virNWFilterDefPtr filter,
                                   virNWFilterHashTablePtr vars,
                                   virNWFilterHashTablePtr missing_vars,
                                   int useNewFilter,
                                   virNWFilterDriverStatePtr driver)
{
    virNWFilterObjPtr obj;
    int rc = 0;
    size_t i, j;
    virNWFilterDefPtr next_filter;
    virNWFilterDefPtr newNext_filter;
    virNWFilterVarValuePtr val;

    for (i = 0; i < filter->nentries; i++) {
        virNWFilterRuleDefPtr    rule = filter->filterEntries[i]->rule;
        virNWFilterIncludeDefPtr inc  = filter->filterEntries[i]->include;
        if (rule) {
            /* check all variables of this rule */
            for (j = 0; j < rule->nVarAccess; j++) {
                if (!virNWFilterVarAccessIsAvailable(rule->varAccess[j],
                                                     vars)) {
                    char *varAccess;
                    virBuffer buf = VIR_BUFFER_INITIALIZER;

                    virNWFilterVarAccessPrint(rule->varAccess[j], &buf);
                    if (virBufferError(&buf)) {
                        virReportOOMError();
                        rc = -1;
                        break;
                    }

                    val = virNWFilterVarValueCreateSimpleCopyValue("1");
                    if (!val) {
                        virBufferFreeAndReset(&buf);
                        rc = -1;
                        break;
                    }

                    varAccess = virBufferContentAndReset(&buf);
                    virNWFilterHashTablePut(missing_vars, varAccess,
                                            val);
                    VIR_FREE(varAccess);
                }
            }
            if (rc)
                break;
        } else if (inc) {
            VIR_DEBUG("Following filter %s", inc->filterref);
            obj = virNWFilterObjListFindByName(driver->nwfilters, inc->filterref);
            if (obj) {

                if (virNWFilterObjWantRemoved(obj)) {
                    virReportError(VIR_ERR_NO_NWFILTER,
                                   _("Filter '%s' is in use."),
                                   inc->filterref);
                    rc = -1;
                    virNWFilterObjUnlock(obj);
                    break;
                }

                /* create a temporary hashmap for depth-first tree traversal */
                virNWFilterHashTablePtr tmpvars =
                                      virNWFilterCreateVarsFrom(inc->params,
                                                                vars);
                if (!tmpvars) {
                    rc = -1;
                    virNWFilterObjUnlock(obj);
                    break;
                }

                next_filter = virNWFilterObjGetDef(obj);

                switch (useNewFilter) {
                case INSTANTIATE_FOLLOW_NEWFILTER:
                    newNext_filter = virNWFilterObjGetNewDef(obj);
                    if (newNext_filter)
                        next_filter = newNext_filter;
                    break;
                case INSTANTIATE_ALWAYS:
                    break;
                }

                rc = virNWFilterDetermineMissingVarsRec(next_filter,
                                                        tmpvars,
                                                        missing_vars,
                                                        useNewFilter,
                                                        driver);

                virNWFilterHashTableFree(tmpvars);

                virNWFilterObjUnlock(obj);
                if (rc < 0)
                    break;
            } else {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("referenced filter '%s' is missing"),
                               inc->filterref);
                rc = -1;
                break;
            }
        }
    }
    return rc;
}


/**
 * virNWFilterInstantiate:
 * @vmuuid: The UUID of the VM
 * @techdriver: The driver to use for instantiation
 * @filter: The filter to instantiate
 * @ifname: The name of the interface to apply the rules to
 * @vars: A map holding variable names and values used for instantiating
 *  the filter and its subfilters.
 * @forceWithPendingReq: Ignore the check whether a pending learn request
 *  is active; 'true' only when the rules are applied late
 *
 * Returns 0 on success, a value otherwise.
 *
 * Instantiate a filter by instantiating the filter itself along with
 * all its subfilters in a depth-first traversal of the tree of referenced
 * filters. The name of the interface to which the rules belong must be
 * provided. Apply the values of variables as needed.
 *
 * Call this function while holding the NWFilter filter update lock
 */
static int
virNWFilterInstantiate(const unsigned char *vmuuid ATTRIBUTE_UNUSED,
                       virNWFilterTechDriverPtr techdriver,
                       virNWFilterDefPtr filter,
                       const char *ifname,
                       int ifindex,
                       const char *linkdev,
                       virNWFilterHashTablePtr vars,
                       enum instCase useNewFilter, bool *foundNewFilter,
                       bool teardownOld,
                       const virMacAddr *macaddr,
                       virNWFilterDriverStatePtr driver,
                       bool forceWithPendingReq)
{
    int rc;
    virNWFilterInst inst;
    bool instantiate = true;
    char *buf;
    virNWFilterVarValuePtr lv;
    const char *learning;
    bool reportIP = false;

    virNWFilterHashTablePtr missing_vars = virNWFilterHashTableCreate(0);

    memset(&inst, 0, sizeof(inst));

    if (!missing_vars) {
        rc = -1;
        goto err_exit;
    }

    rc = virNWFilterDetermineMissingVarsRec(filter,
                                            vars,
                                            missing_vars,
                                            useNewFilter,
                                            driver);
    if (rc < 0)
        goto err_exit;

    lv = virHashLookup(vars->hashTable, NWFILTER_VARNAME_CTRL_IP_LEARNING);
    if (lv)
        learning = virNWFilterVarValueGetNthValue(lv, 0);
    else
        learning = NULL;

    if (learning == NULL)
        learning = NWFILTER_DFLT_LEARN;

    if (virHashSize(missing_vars->hashTable) == 1) {
        if (virHashLookup(missing_vars->hashTable,
                          NWFILTER_STD_VAR_IP) != NULL) {
            if (STRCASEEQ(learning, "none")) {        /* no learning */
                reportIP = true;
                goto err_unresolvable_vars;
            }
            if (STRCASEEQ(learning, "dhcp")) {
                rc = virNWFilterDHCPSnoopReq(techdriver, ifname, linkdev,
                                             vmuuid, macaddr,
                                             filter->name, vars, driver);
                goto err_exit;
            } else if (STRCASEEQ(learning, "any")) {
                if (virNWFilterLookupLearnReq(ifindex) == NULL) {
                    rc = virNWFilterLearnIPAddress(techdriver,
                                                   ifname,
                                                   ifindex,
                                                   linkdev,
                                                   macaddr,
                                                   filter->name,
                                                   vars, driver,
                                                   DETECT_DHCP|DETECT_STATIC);
                }
                goto err_exit;
            } else {
                rc = -1;
                virReportError(VIR_ERR_PARSE_FAILED,
                               _("filter '%s' "
                                 "learning value '%s' invalid."),
                               filter->name, learning);
                goto err_exit;
            }
        } else {
            goto err_unresolvable_vars;
        }
    } else if (virHashSize(missing_vars->hashTable) > 1) {
        goto err_unresolvable_vars;
    } else if (!forceWithPendingReq &&
               virNWFilterLookupLearnReq(ifindex) != NULL) {
        goto err_exit;
    }

    rc = virNWFilterDefToInst(driver,
                              filter,
                              vars,
                              useNewFilter, foundNewFilter,
                              &inst);

    if (rc < 0)
        goto err_exit;

    switch (useNewFilter) {
    case INSTANTIATE_FOLLOW_NEWFILTER:
        instantiate = *foundNewFilter;
        break;
    case INSTANTIATE_ALWAYS:
        instantiate = true;
        break;
    }

    if (instantiate) {
        if (virNWFilterLockIface(ifname) < 0)
            goto err_exit;

        rc = techdriver->applyNewRules(ifname, inst.rules, inst.nrules);

        if (teardownOld && rc == 0)
            techdriver->tearOldRules(ifname);

        if (rc == 0 && (virNetDevValidateConfig(ifname, NULL, ifindex) <= 0)) {
            virResetLastError();
            /* interface changed/disppeared */
            techdriver->allTeardown(ifname);
            rc = -1;
        }

        virNWFilterUnlockIface(ifname);
    }

 err_exit:
    virNWFilterInstReset(&inst);
    virNWFilterHashTableFree(missing_vars);

    return rc;

 err_unresolvable_vars:

    buf = virNWFilterPrintVars(missing_vars->hashTable, ", ", false, reportIP);
    if (buf) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Cannot instantiate filter due to unresolvable "
                         "variables or unavailable list elements: %s"), buf);
        VIR_FREE(buf);
    }

    rc = -1;
    goto err_exit;
}


/*
 * Call this function while holding the NWFilter filter update lock
 */
static int
__virNWFilterInstantiateFilter(virNWFilterDriverStatePtr driver,
                               const unsigned char *vmuuid,
                               bool teardownOld,
                               const char *ifname,
                               int ifindex,
                               const char *linkdev,
                               const virMacAddr *macaddr,
                               const char *filtername,
                               virNWFilterHashTablePtr filterparams,
                               enum instCase useNewFilter,
                               bool forceWithPendingReq,
                               bool *foundNewFilter)
{
    int rc;
    const char *drvname = EBIPTABLES_DRIVER_ID;
    virNWFilterTechDriverPtr techdriver;
    virNWFilterObjPtr obj;
    virNWFilterHashTablePtr vars, vars1;
    virNWFilterDefPtr filter;
    virNWFilterDefPtr newFilter;
    char vmmacaddr[VIR_MAC_STRING_BUFLEN] = {0};
    char *str_macaddr = NULL;
    virNWFilterVarValuePtr ipaddr;
    char *str_ipaddr = NULL;

    techdriver = virNWFilterTechDriverForName(drvname);

    if (!techdriver) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not get access to ACL tech "
                         "driver '%s'"),
                       drvname);
        return -1;
    }

    VIR_DEBUG("filter name: %s", filtername);

    obj = virNWFilterObjListFindByName(driver->nwfilters, filtername);
    if (!obj) {
        virReportError(VIR_ERR_NO_NWFILTER,
                       _("Could not find filter '%s'"),
                       filtername);
        return -1;
    }

    if (virNWFilterObjWantRemoved(obj)) {
        virReportError(VIR_ERR_NO_NWFILTER,
                       _("Filter '%s' is in use."),
                       filtername);
        rc = -1;
        goto err_exit;
    }

    virMacAddrFormat(macaddr, vmmacaddr);
    if (VIR_STRDUP(str_macaddr, vmmacaddr) < 0) {
        rc = -1;
        goto err_exit;
    }

    ipaddr = virNWFilterIPAddrMapGetIPAddr(ifname);

    vars1 = virNWFilterCreateVarHashmap(str_macaddr, ipaddr);
    if (!vars1) {
        rc = -1;
        goto err_exit;
    }

    str_macaddr = NULL;
    str_ipaddr = NULL;

    vars = virNWFilterCreateVarsFrom(vars1,
                                     filterparams);
    if (!vars) {
        rc = -1;
        goto err_exit_vars1;
    }

    filter = virNWFilterObjGetDef(obj);

    switch (useNewFilter) {
    case INSTANTIATE_FOLLOW_NEWFILTER:
        newFilter = virNWFilterObjGetNewDef(obj);
        if (newFilter) {
            filter = newFilter;
            *foundNewFilter = true;
        }
        break;

    case INSTANTIATE_ALWAYS:
        break;
    }

    rc = virNWFilterInstantiate(vmuuid,
                                techdriver,
                                filter,
                                ifname,
                                ifindex,
                                linkdev,
                                vars,
                                useNewFilter, foundNewFilter,
                                teardownOld,
                                macaddr,
                                driver,
                                forceWithPendingReq);

    virNWFilterHashTableFree(vars);

 err_exit_vars1:
    virNWFilterHashTableFree(vars1);

 err_exit:
    virNWFilterObjUnlock(obj);

    VIR_FREE(str_ipaddr);
    VIR_FREE(str_macaddr);

    return rc;
}


static int
_virNWFilterInstantiateFilter(virNWFilterDriverStatePtr driver,
                              const unsigned char *vmuuid,
                              const virDomainNetDef *net,
                              bool teardownOld,
                              enum instCase useNewFilter,
                              bool *foundNewFilter)
{
    const char *linkdev = (net->type == VIR_DOMAIN_NET_TYPE_DIRECT)
                          ? net->data.direct.linkdev
                          : NULL;
    int ifindex;
    int rc;

    virMutexLock(&updateMutex);

    /* after grabbing the filter update lock check for the interface; if
       it's not there anymore its filters will be or are being removed
       (while holding the lock) and we don't want to build new ones */
    if (virNetDevExists(net->ifname) != 1 ||
        virNetDevGetIndex(net->ifname, &ifindex) < 0) {
        /* interfaces / VMs can disappear during filter instantiation;
           don't mark it as an error */
        virResetLastError();
        rc = 0;
        goto cleanup;
    }

    rc = __virNWFilterInstantiateFilter(driver,
                                        vmuuid,
                                        teardownOld,
                                        net->ifname,
                                        ifindex,
                                        linkdev,
                                        &net->mac,
                                        net->filter,
                                        net->filterparams,
                                        useNewFilter,
                                        false,
                                        foundNewFilter);

 cleanup:
    virMutexUnlock(&updateMutex);

    return rc;
}


int
virNWFilterInstantiateFilterLate(virNWFilterDriverStatePtr driver,
                                 const unsigned char *vmuuid,
                                 const char *ifname,
                                 int ifindex,
                                 const char *linkdev,
                                 const virMacAddr *macaddr,
                                 const char *filtername,
                                 virNWFilterHashTablePtr filterparams)
{
    int rc;
    bool foundNewFilter = false;

    virNWFilterReadLockFilterUpdates();
    virMutexLock(&updateMutex);

    rc = __virNWFilterInstantiateFilter(driver,
                                        vmuuid,
                                        true,
                                        ifname,
                                        ifindex,
                                        linkdev,
                                        macaddr,
                                        filtername,
                                        filterparams,
                                        INSTANTIATE_ALWAYS,
                                        true,
                                        &foundNewFilter);
    if (rc < 0) {
        /* something went wrong... 'DOWN' the interface */
        if ((virNetDevValidateConfig(ifname, NULL, ifindex) <= 0) ||
            (virNetDevSetOnline(ifname, false) < 0)) {
            virResetLastError();
            /* assuming interface disappeared... */
            _virNWFilterTeardownFilter(ifname);
        }
    }

    virNWFilterUnlockFilterUpdates();
    virMutexUnlock(&updateMutex);

    return rc;
}


int
virNWFilterInstantiateFilter(virNWFilterDriverStatePtr driver,
                             const unsigned char *vmuuid,
                             const virDomainNetDef *net)
{
    bool foundNewFilter = false;

    return _virNWFilterInstantiateFilter(driver, vmuuid, net,
                                         1,
                                         INSTANTIATE_ALWAYS,
                                         &foundNewFilter);
}


int
virNWFilterUpdateInstantiateFilter(virNWFilterDriverStatePtr driver,
                                   const unsigned char *vmuuid,
                                   const virDomainNetDef *net,
                                   bool *skipIface)
{
    bool foundNewFilter = false;

    int rc = _virNWFilterInstantiateFilter(driver, vmuuid, net,
                                           0,
                                           INSTANTIATE_FOLLOW_NEWFILTER,
                                           &foundNewFilter);

    *skipIface = !foundNewFilter;
    return rc;
}

static int
virNWFilterRollbackUpdateFilter(const virDomainNetDef *net)
{
    const char *drvname = EBIPTABLES_DRIVER_ID;
    int ifindex;
    virNWFilterTechDriverPtr techdriver;

    techdriver = virNWFilterTechDriverForName(drvname);
    if (!techdriver) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not get access to ACL tech "
                         "driver '%s'"),
                       drvname);
        return -1;
    }

    /* don't tear anything while the address is being learned */
    if (virNetDevGetIndex(net->ifname, &ifindex) < 0)
        virResetLastError();
    else if (virNWFilterLookupLearnReq(ifindex) != NULL)
        return 0;

    return techdriver->tearNewRules(net->ifname);
}


static int
virNWFilterTearOldFilter(virDomainNetDefPtr net)
{
    const char *drvname = EBIPTABLES_DRIVER_ID;
    int ifindex;
    virNWFilterTechDriverPtr techdriver;

    techdriver = virNWFilterTechDriverForName(drvname);
    if (!techdriver) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not get access to ACL tech "
                         "driver '%s'"),
                       drvname);
        return -1;
    }

    /* don't tear anything while the address is being learned */
    if (virNetDevGetIndex(net->ifname, &ifindex) < 0)
        virResetLastError();
    else if (virNWFilterLookupLearnReq(ifindex) != NULL)
        return 0;

    return techdriver->tearOldRules(net->ifname);
}


static int
_virNWFilterTeardownFilter(const char *ifname)
{
    const char *drvname = EBIPTABLES_DRIVER_ID;
    virNWFilterTechDriverPtr techdriver;
    techdriver = virNWFilterTechDriverForName(drvname);

    if (!techdriver) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not get access to ACL tech "
                         "driver '%s'"),
                       drvname);
        return -1;
    }

    virNWFilterDHCPSnoopEnd(ifname);

    virNWFilterTerminateLearnReq(ifname);

    if (virNWFilterLockIface(ifname) < 0)
        return -1;

    techdriver->allTeardown(ifname);

    virNWFilterIPAddrMapDelIPAddr(ifname, NULL);

    virNWFilterUnlockIface(ifname);

    return 0;
}


int
virNWFilterTeardownFilter(const virDomainNetDef *net)
{
    int ret;
    virMutexLock(&updateMutex);
    ret = _virNWFilterTeardownFilter(net->ifname);
    virMutexUnlock(&updateMutex);
    return ret;
}


int
virNWFilterDomainFWUpdateCB(virDomainObjPtr obj,
                            void *data)
{
    virDomainDefPtr vm = obj->def;
    struct domUpdateCBStruct *cb = data;
    size_t i;
    bool skipIface;
    int ret = 0;

    virObjectLock(obj);

    if (virDomainObjIsActive(obj)) {
        for (i = 0; i < vm->nnets; i++) {
            virDomainNetDefPtr net = vm->nets[i];
            if ((net->filter) && (net->ifname)) {
                switch (cb->step) {
                case STEP_APPLY_NEW:
                    ret = virNWFilterUpdateInstantiateFilter(cb->opaque,
                                                             vm->uuid,
                                                             net,
                                                             &skipIface);
                    if (ret == 0 && skipIface) {
                        /* filter tree unchanged -- no update needed */
                        ret = virHashAddEntry(cb->skipInterfaces,
                                              net->ifname,
                                              (void *)~0);
                    }
                    break;

                case STEP_TEAR_NEW:
                    if (!virHashLookup(cb->skipInterfaces, net->ifname))
                        ret = virNWFilterRollbackUpdateFilter(net);
                    break;

                case STEP_TEAR_OLD:
                    if (!virHashLookup(cb->skipInterfaces, net->ifname))
                        ret = virNWFilterTearOldFilter(net);
                    break;

                case STEP_APPLY_CURRENT:
                    ret = virNWFilterInstantiateFilter(cb->opaque,
                                                       vm->uuid,
                                                       net);
                    if (ret)
                        virReportError(VIR_ERR_INTERNAL_ERROR,
                                       _("Failure while applying current filter on "
                                         "VM %s"), vm->name);
                    break;
                }
                if (ret)
                    break;
            }
        }
    }

    virObjectUnlock(obj);
    return ret;
}
