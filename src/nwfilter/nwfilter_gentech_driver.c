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
 * to avoid lock ordering deadlocks. eg virNWFilterInstantiateFilterUpdate
 * will hold a lock on a virNWFilterObjPtr. This in turn invokes
 * virNWFilterDoInstantiate which invokes virNWFilterDetermineMissingVarsRec
 * which invokes virNWFilterObjListFindInstantiateFilter. This iterates over
 * every single virNWFilterObjPtr in the list. So if 2 threads try to
 * instantiate a filter in parallel, they'll both hold 1 lock at the top level
 * in virNWFilterInstantiateFilterUpdate which will cause the other thread
 * to deadlock in virNWFilterObjListFindInstantiateFilter.
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

    virHashFree(inst->vars);
    VIR_FREE(inst);
}


/**
 * Convert a virHashTable into a string of comma-separated
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
printString(void *payload G_GNUC_UNUSED, const void *name, void *data)
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
static virHashTablePtr
virNWFilterCreateVarsFrom(virHashTablePtr vars1,
                          virHashTablePtr vars2)
{
    virHashTablePtr res = virNWFilterHashTableCreate(0);
    if (!res)
        return NULL;

    if (virNWFilterHashTablePutAll(vars1, res) < 0)
        goto err_exit;

    if (virNWFilterHashTablePutAll(vars2, res) < 0)
        goto err_exit;

    return res;

 err_exit:
    virHashFree(res);
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
                     virHashTablePtr vars,
                     enum instCase useNewFilter,
                     bool *foundNewFilter,
                     virNWFilterInstPtr inst);

static int
virNWFilterRuleDefToRuleInst(virNWFilterDefPtr def,
                             virNWFilterRuleDefPtr rule,
                             virHashTablePtr vars,
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

    ret = 0;
 cleanup:
    virNWFilterRuleInstFree(ruleinst);
    return ret;
}


static int
virNWFilterIncludeDefToRuleInst(virNWFilterDriverStatePtr driver,
                                virNWFilterIncludeDefPtr inc,
                                virHashTablePtr vars,
                                enum instCase useNewFilter,
                                bool *foundNewFilter,
                                virNWFilterInstPtr inst)
{
    virNWFilterObjPtr obj;
    virHashTablePtr tmpvars = NULL;
    virNWFilterDefPtr childdef;
    virNWFilterDefPtr newChilddef;
    int ret = -1;

    VIR_DEBUG("Instantiating filter %s", inc->filterref);
    if (!(obj = virNWFilterObjListFindInstantiateFilter(driver->nwfilters,
                                                        inc->filterref)))
        goto cleanup;

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
    virHashFree(tmpvars);
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
                     virHashTablePtr vars,
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
                                   virHashTablePtr vars,
                                   virHashTablePtr missing_vars,
                                   int useNewFilter,
                                   virNWFilterDriverStatePtr driver)
{
    virNWFilterObjPtr obj;
    int rc = 0;
    size_t i, j;
    virNWFilterDefPtr next_filter;
    virNWFilterDefPtr newNext_filter;
    virNWFilterVarValuePtr val;
    virHashTablePtr tmpvars;

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
                        return -1;
                    }

                    val = virNWFilterVarValueCreateSimpleCopyValue("1");
                    if (!val) {
                        virBufferFreeAndReset(&buf);
                        return -1;
                    }

                    varAccess = virBufferContentAndReset(&buf);
                    rc = virHashUpdateEntry(missing_vars, varAccess, val);
                    VIR_FREE(varAccess);
                    if (rc < 0) {
                        virNWFilterVarValueFree(val);
                        return -1;
                    }
                }
            }
        } else if (inc) {
            VIR_DEBUG("Following filter %s", inc->filterref);
            if (!(obj = virNWFilterObjListFindInstantiateFilter(driver->nwfilters,
                                                                inc->filterref)))
                return -1;

            /* create a temporary hashmap for depth-first tree traversal */
            if (!(tmpvars = virNWFilterCreateVarsFrom(inc->params, vars))) {
                virNWFilterObjUnlock(obj);
                return -1;
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

            virHashFree(tmpvars);

            virNWFilterObjUnlock(obj);
            if (rc < 0)
                return -1;
        }
    }
    return 0;
}


/**
 * virNWFilterDoInstantiate:
 * @techdriver: The driver to use for instantiation
 * @binding: description of port to bind the filter to
 * @filter: The filter to instantiate
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
virNWFilterDoInstantiate(virNWFilterTechDriverPtr techdriver,
                         virNWFilterBindingDefPtr binding,
                         virNWFilterDefPtr filter,
                         int ifindex,
                         enum instCase useNewFilter,
                         bool *foundNewFilter,
                         bool teardownOld,
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

    virHashTablePtr missing_vars = virNWFilterHashTableCreate(0);

    memset(&inst, 0, sizeof(inst));

    if (!missing_vars) {
        rc = -1;
        goto err_exit;
    }

    rc = virNWFilterDetermineMissingVarsRec(filter,
                                            binding->filterparams,
                                            missing_vars,
                                            useNewFilter,
                                            driver);
    if (rc < 0)
        goto err_exit;

    lv = virHashLookup(binding->filterparams, NWFILTER_VARNAME_CTRL_IP_LEARNING);
    if (lv)
        learning = virNWFilterVarValueGetNthValue(lv, 0);
    else
        learning = NULL;

    if (learning == NULL)
        learning = NWFILTER_DFLT_LEARN;

    if (virHashSize(missing_vars) == 1) {
        if (virHashLookup(missing_vars,
                          NWFILTER_STD_VAR_IP) != NULL) {
            if (STRCASEEQ(learning, "none")) {        /* no learning */
                reportIP = true;
                goto err_unresolvable_vars;
            }
            if (STRCASEEQ(learning, "dhcp")) {
                rc = virNWFilterDHCPSnoopReq(techdriver,
                                             binding,
                                             driver);
                goto err_exit;
            } else if (STRCASEEQ(learning, "any")) {
                if (!virNWFilterHasLearnReq(ifindex)) {
                    rc = virNWFilterLearnIPAddress(techdriver,
                                                   binding,
                                                   ifindex,
                                                   driver,
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
    } else if (virHashSize(missing_vars) > 1) {
        goto err_unresolvable_vars;
    } else if (!forceWithPendingReq &&
               virNWFilterHasLearnReq(ifindex)) {
        goto err_exit;
    }

    rc = virNWFilterDefToInst(driver,
                              filter,
                              binding->filterparams,
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
        if (virNWFilterLockIface(binding->portdevname) < 0)
            goto err_exit;

        rc = techdriver->applyNewRules(binding->portdevname, inst.rules, inst.nrules);

        if (teardownOld && rc == 0)
            techdriver->tearOldRules(binding->portdevname);

        if (rc == 0 && (virNetDevValidateConfig(binding->portdevname, NULL, ifindex) <= 0)) {
            virResetLastError();
            /* interface changed/disappeared */
            techdriver->allTeardown(binding->portdevname);
            rc = -1;
        }

        virNWFilterUnlockIface(binding->portdevname);
    }

 err_exit:
    virNWFilterInstReset(&inst);
    virHashFree(missing_vars);

    return rc;

 err_unresolvable_vars:

    buf = virNWFilterPrintVars(missing_vars, ", ", false, reportIP);
    if (buf) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Cannot instantiate filter due to unresolvable "
                         "variables or unavailable list elements: %s"), buf);
        VIR_FREE(buf);
    }

    rc = -1;
    goto err_exit;
}


static int
virNWFilterVarHashmapAddStdValue(virHashTablePtr table,
                                 const char *var,
                                 const char *value)
{
    virNWFilterVarValue *val;

    if (virHashLookup(table, var))
        return 0;

    if (!(val = virNWFilterVarValueCreateSimpleCopyValue(value)))
        return -1;

    if (virHashAddEntry(table, var, val) < 0) {
        virNWFilterVarValueFree(val);
        return -1;
    }

    return 0;
}


/*
 * Call this function while holding the NWFilter filter update lock
 */
static int
virNWFilterInstantiateFilterUpdate(virNWFilterDriverStatePtr driver,
                                   bool teardownOld,
                                   virNWFilterBindingDefPtr binding,
                                   int ifindex,
                                   enum instCase useNewFilter,
                                   bool forceWithPendingReq,
                                   bool *foundNewFilter)
{
    int rc = -1;
    const char *drvname = EBIPTABLES_DRIVER_ID;
    virNWFilterTechDriverPtr techdriver;
    virNWFilterObjPtr obj;
    virNWFilterDefPtr filter;
    virNWFilterDefPtr newFilter;
    char vmmacaddr[VIR_MAC_STRING_BUFLEN] = {0};
    virNWFilterVarValuePtr ipaddr;

    techdriver = virNWFilterTechDriverForName(drvname);

    if (!techdriver) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not get access to ACL tech "
                         "driver '%s'"),
                       drvname);
        return -1;
    }

    VIR_DEBUG("filter name: %s", binding->filter);

    if (!(obj = virNWFilterObjListFindInstantiateFilter(driver->nwfilters,
                                                        binding->filter)))
        return -1;

    virMacAddrFormat(&binding->mac, vmmacaddr);
    if (virNWFilterVarHashmapAddStdValue(binding->filterparams,
                                         NWFILTER_STD_VAR_MAC,
                                         vmmacaddr) < 0)
        goto err_exit;

    ipaddr = virNWFilterIPAddrMapGetIPAddr(binding->portdevname);
    if (ipaddr &&
        virNWFilterVarHashmapAddStdValue(binding->filterparams,
                                         NWFILTER_STD_VAR_IP,
                                         virNWFilterVarValueGetSimple(ipaddr)) < 0)
        goto err_exit;


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

    rc = virNWFilterDoInstantiate(techdriver, binding, filter,
                                  ifindex, useNewFilter, foundNewFilter,
                                  teardownOld, driver,
                                  forceWithPendingReq);

 err_exit:
    virNWFilterObjUnlock(obj);

    return rc;
}


static int
virNWFilterInstantiateFilterInternal(virNWFilterDriverStatePtr driver,
                                     virNWFilterBindingDefPtr binding,
                                     bool teardownOld,
                                     enum instCase useNewFilter,
                                     bool *foundNewFilter)
{
    int ifindex;
    int rc;

    virMutexLock(&updateMutex);

    /* after grabbing the filter update lock check for the interface; if
       it's not there anymore its filters will be or are being removed
       (while holding the lock) and we don't want to build new ones */
    if (virNetDevExists(binding->portdevname) != 1 ||
        virNetDevGetIndex(binding->portdevname, &ifindex) < 0) {
        /* interfaces / VMs can disappear during filter instantiation;
           don't mark it as an error */
        virResetLastError();
        rc = 0;
        goto cleanup;
    }

    rc = virNWFilterInstantiateFilterUpdate(driver, teardownOld,
                                            binding,
                                            ifindex,
                                            useNewFilter,
                                            false, foundNewFilter);

 cleanup:
    virMutexUnlock(&updateMutex);

    return rc;
}


int
virNWFilterInstantiateFilterLate(virNWFilterDriverStatePtr driver,
                                 virNWFilterBindingDefPtr binding,
                                 int ifindex)
{
    int rc;
    bool foundNewFilter = false;

    virNWFilterReadLockFilterUpdates();
    virMutexLock(&updateMutex);

    rc = virNWFilterInstantiateFilterUpdate(driver, true,
                                            binding, ifindex,
                                            INSTANTIATE_ALWAYS, true,
                                            &foundNewFilter);
    if (rc < 0) {
        /* something went wrong... 'DOWN' the interface */
        if ((virNetDevValidateConfig(binding->portdevname, NULL, ifindex) <= 0) ||
            (virNetDevSetOnline(binding->portdevname, false) < 0)) {
            virResetLastError();
            /* assuming interface disappeared... */
            _virNWFilterTeardownFilter(binding->portdevname);
        }
    }

    virNWFilterUnlockFilterUpdates();
    virMutexUnlock(&updateMutex);

    return rc;
}


int
virNWFilterInstantiateFilter(virNWFilterDriverStatePtr driver,
                             virNWFilterBindingDefPtr binding)
{
    bool foundNewFilter = false;

    return virNWFilterInstantiateFilterInternal(driver, binding,
                                                1,
                                                INSTANTIATE_ALWAYS,
                                                &foundNewFilter);
}


int
virNWFilterUpdateInstantiateFilter(virNWFilterDriverStatePtr driver,
                                   virNWFilterBindingDefPtr binding,
                                   bool *skipIface)
{
    bool foundNewFilter = false;

    int rc = virNWFilterInstantiateFilterInternal(driver, binding,
                                                  0,
                                                  INSTANTIATE_FOLLOW_NEWFILTER,
                                                  &foundNewFilter);

    *skipIface = !foundNewFilter;
    return rc;
}

static int
virNWFilterRollbackUpdateFilter(virNWFilterBindingDefPtr binding)
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
    if (virNetDevGetIndex(binding->portdevname, &ifindex) < 0)
        virResetLastError();
    else if (virNWFilterHasLearnReq(ifindex))
        return 0;

    return techdriver->tearNewRules(binding->portdevname);
}


static int
virNWFilterTearOldFilter(virNWFilterBindingDefPtr binding)
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
    if (virNetDevGetIndex(binding->portdevname, &ifindex) < 0)
        virResetLastError();
    else if (virNWFilterHasLearnReq(ifindex))
        return 0;

    return techdriver->tearOldRules(binding->portdevname);
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
virNWFilterTeardownFilter(virNWFilterBindingDefPtr binding)
{
    int ret;
    virMutexLock(&updateMutex);
    ret = _virNWFilterTeardownFilter(binding->portdevname);
    virMutexUnlock(&updateMutex);
    return ret;
}

enum {
    STEP_APPLY_NEW,
    STEP_ROLLBACK,
    STEP_SWITCH,
    STEP_APPLY_CURRENT,
};

static int
virNWFilterBuildOne(virNWFilterDriverStatePtr driver,
                    virNWFilterBindingDefPtr binding,
                    virHashTablePtr skipInterfaces,
                    int step)
{
    bool skipIface;
    int ret = 0;
    VIR_DEBUG("Building filter for portdev=%s step=%d", binding->portdevname, step);

    switch (step) {
    case STEP_APPLY_NEW:
        ret = virNWFilterUpdateInstantiateFilter(driver,
                                                 binding,
                                                 &skipIface);
        if (ret == 0 && skipIface) {
            /* filter tree unchanged -- no update needed */
            ret = virHashAddEntry(skipInterfaces,
                                  binding->portdevname,
                                  (void *)~0);
        }
        break;

    case STEP_ROLLBACK:
        if (!virHashLookup(skipInterfaces, binding->portdevname))
            ret = virNWFilterRollbackUpdateFilter(binding);
        break;

    case STEP_SWITCH:
        if (!virHashLookup(skipInterfaces, binding->portdevname))
            ret = virNWFilterTearOldFilter(binding);
        break;

    case STEP_APPLY_CURRENT:
        ret = virNWFilterInstantiateFilter(driver,
                                           binding);
        break;
    }

    return ret;
}


struct virNWFilterBuildData {
    virNWFilterDriverStatePtr driver;
    virHashTablePtr skipInterfaces;
    int step;
};

static int
virNWFilterBuildIter(virNWFilterBindingObjPtr binding, void *opaque)
{
    struct virNWFilterBuildData *data = opaque;
    virNWFilterBindingDefPtr def = virNWFilterBindingObjGetDef(binding);

    return virNWFilterBuildOne(data->driver, def,
                               data->skipInterfaces, data->step);
}

int
virNWFilterBuildAll(virNWFilterDriverStatePtr driver,
                    bool newFilters)
{
    struct virNWFilterBuildData data = {
        .driver = driver,
    };
    int ret = 0;

    VIR_DEBUG("Build all filters newFilters=%d", newFilters);

    if (newFilters) {
        if (!(data.skipInterfaces = virHashCreate(0, NULL)))
            return -1;

        data.step = STEP_APPLY_NEW;
        if (virNWFilterBindingObjListForEach(driver->bindings,
                                             virNWFilterBuildIter,
                                             &data) < 0)
            ret = -1;

        if (ret == -1) {
            data.step = STEP_ROLLBACK;
            virNWFilterBindingObjListForEach(driver->bindings,
                                             virNWFilterBuildIter,
                                             &data);
        } else  {
            data.step = STEP_SWITCH;
            virNWFilterBindingObjListForEach(driver->bindings,
                                             virNWFilterBuildIter,
                                             &data);
        }

        virHashFree(data.skipInterfaces);
    } else {
        data.step = STEP_APPLY_CURRENT;
        if (virNWFilterBindingObjListForEach(driver->bindings,
                                             virNWFilterBuildIter,
                                             &data) < 0)
            ret = -1;
    }
    return ret;
}
