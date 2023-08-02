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
#include "virerror.h"
#include "nwfilter_gentech_driver.h"
#include "nwfilter_ebiptables_driver.h"
#include "nwfilter_dhcpsnoop.h"
#include "nwfilter_ipaddrmap.h"
#include "nwfilter_learnipaddr.h"
#include "virnetdev.h"

#define VIR_FROM_THIS VIR_FROM_NWFILTER

VIR_LOG_INIT("nwfilter.nwfilter_gentech_driver");

#define NWFILTER_STD_VAR_MAC NWFILTER_VARNAME_MAC
#define NWFILTER_STD_VAR_IP  NWFILTER_VARNAME_IP

#define NWFILTER_DFLT_LEARN  "any"

static int _virNWFilterTeardownFilter(const char *ifname);


static virNWFilterTechDriver *filter_tech_drivers[] = {
    &ebiptables_driver,
    NULL
};

int virNWFilterTechDriversInit(bool privileged)
{
    size_t i = 0;
    VIR_DEBUG("Initializing NWFilter technology drivers");
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
}


static virNWFilterTechDriver *
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
virNWFilterRuleInstFree(virNWFilterRuleInst *inst)
{
    if (!inst)
        return;

    g_clear_pointer(&inst->vars, g_hash_table_unref);
    g_free(inst);
}


/**
 * Convert a GHashTable into a string of comma-separated
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
printString(void *payload G_GNUC_UNUSED, const char *name, void *data)
{
    struct printString *ps = data;

    if ((STREQ(name, NWFILTER_STD_VAR_IP) && !ps->reportIP) ||
        (STREQ(name, NWFILTER_STD_VAR_MAC) && !ps->reportMAC))
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
virNWFilterPrintVars(GHashTable *vars,
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


typedef struct _virNWFilterInst virNWFilterInst;
struct _virNWFilterInst {
    virNWFilterObj **filters;
    size_t nfilters;
    virNWFilterRuleInst **rules;
    size_t nrules;
};


static void
virNWFilterInstReset(virNWFilterInst *inst)
{
    size_t i;

    for (i = 0; i < inst->nfilters; i++)
        virNWFilterObjUnlock(inst->filters[i]);
    g_free(inst->filters);
    inst->nfilters = 0;

    for (i = 0; i < inst->nrules; i++)
        virNWFilterRuleInstFree(inst->rules[i]);
    g_free(inst->rules);
    inst->nrules = 0;
}



static int
virNWFilterDefToInst(virNWFilterDriverState *driver,
                     virNWFilterDef *def,
                     GHashTable *vars,
                     enum instCase useNewFilter,
                     bool *foundNewFilter,
                     virNWFilterInst *inst);

static int
virNWFilterRuleDefToRuleInst(virNWFilterDef *def,
                             virNWFilterRuleDef *rule,
                             GHashTable *vars,
                             virNWFilterInst *inst)
{
    g_autoptr(GHashTable) tmpvars = virHashNew(virNWFilterVarValueHashFree);
    virNWFilterRuleInst *ruleinst;

    if (virNWFilterHashTablePutAll(vars, tmpvars) < 0)
        return -1;

    ruleinst = g_new0(virNWFilterRuleInst, 1);

    ruleinst->chainSuffix = def->chainsuffix;
    ruleinst->chainPriority = def->chainPriority;
    ruleinst->def = rule;
    ruleinst->priority = rule->priority;
    ruleinst->vars = g_steal_pointer(&tmpvars);

    VIR_APPEND_ELEMENT(inst->rules, inst->nrules, ruleinst);

    return 0;
}


static int
virNWFilterIncludeDefToRuleInst(virNWFilterDriverState *driver,
                                virNWFilterIncludeDef *inc,
                                GHashTable *vars,
                                enum instCase useNewFilter,
                                bool *foundNewFilter,
                                virNWFilterInst *inst)
{
    virNWFilterObj *obj;
    g_autoptr(GHashTable) tmpvars = NULL;
    virNWFilterDef *childdef;
    virNWFilterDef *newChilddef;

    VIR_DEBUG("Instantiating filter %s", inc->filterref);

    /* create a temporary hashmap for depth-first tree traversal */
    if (!(tmpvars = virNWFilterCreateVarsFrom(inc->params, vars)))
        return -1;

    /* 'obj' is always appended to 'inst->filters' thus we don't unlock it */
    if (!(obj = virNWFilterObjListFindInstantiateFilter(driver->nwfilters,
                                                        inc->filterref)))
        return -1;

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

    VIR_APPEND_ELEMENT(inst->filters, inst->nfilters, obj);

    if (virNWFilterDefToInst(driver,
                             childdef,
                             tmpvars,
                             useNewFilter,
                             foundNewFilter,
                             inst) < 0) {
        virNWFilterInstReset(inst);
        return -1;
    }

    return 0;
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
virNWFilterDefToInst(virNWFilterDriverState *driver,
                     virNWFilterDef *def,
                     GHashTable *vars,
                     enum instCase useNewFilter,
                     bool *foundNewFilter,
                     virNWFilterInst *inst)
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
virNWFilterDetermineMissingVarsRec(virNWFilterDef *filter,
                                   GHashTable *vars,
                                   GHashTable *missing_vars,
                                   int useNewFilter,
                                   virNWFilterDriverState *driver)
{
    virNWFilterObj *obj;
    int rc = 0;
    size_t i, j;
    virNWFilterDef *next_filter;
    virNWFilterDef *newNext_filter;
    virNWFilterVarValue *val;

    for (i = 0; i < filter->nentries; i++) {
        virNWFilterRuleDef *   rule = filter->filterEntries[i]->rule;
        virNWFilterIncludeDef *inc  = filter->filterEntries[i]->include;
        if (rule) {
            /* check all variables of this rule */
            for (j = 0; j < rule->nVarAccess; j++) {
                if (!virNWFilterVarAccessIsAvailable(rule->varAccess[j],
                                                     vars)) {
                    g_autofree char *varAccess = NULL;
                    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

                    virNWFilterVarAccessPrint(rule->varAccess[j], &buf);

                    if (!(val = virNWFilterVarValueCreateSimpleCopyValue("1")))
                        return -1;

                    varAccess = virBufferContentAndReset(&buf);
                    rc = virHashUpdateEntry(missing_vars, varAccess, val);
                    if (rc < 0) {
                        virNWFilterVarValueFree(val);
                        return -1;
                    }
                }
            }
        } else if (inc) {
            g_autoptr(GHashTable) tmpvars = NULL;

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
virNWFilterDoInstantiate(virNWFilterTechDriver *techdriver,
                         virNWFilterBindingDef *binding,
                         virNWFilterDef *filter,
                         int ifindex,
                         enum instCase useNewFilter,
                         bool *foundNewFilter,
                         bool teardownOld,
                         virNWFilterDriverState *driver,
                         bool forceWithPendingReq)
{
    int rc;
    virNWFilterInst inst = { 0 };
    bool instantiate = true;
    g_autofree char *buf = NULL;
    virNWFilterVarValue *lv;
    const char *learning;
    bool reportIP = false;
    g_autoptr(GHashTable) missing_vars = virHashNew(virNWFilterVarValueHashFree);

    rc = virNWFilterDetermineMissingVarsRec(filter,
                                            binding->filterparams,
                                            missing_vars,
                                            useNewFilter,
                                            driver);
    if (rc < 0)
        goto error;

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
                goto error;
            } else if (STRCASEEQ(learning, "any")) {
                if (!virNWFilterHasLearnReq(ifindex)) {
                    rc = virNWFilterLearnIPAddress(techdriver,
                                                   binding,
                                                   ifindex,
                                                   driver,
                                                   DETECT_DHCP|DETECT_STATIC);
                }
                goto error;
            } else {
                rc = -1;
                virReportError(VIR_ERR_PARSE_FAILED,
                               _("filter '%1$s' learning value '%2$s' invalid."),
                               filter->name, learning);
                goto error;
            }
        } else {
            goto err_unresolvable_vars;
        }
    } else if (virHashSize(missing_vars) > 1) {
        goto err_unresolvable_vars;
    } else if (!forceWithPendingReq &&
               virNWFilterHasLearnReq(ifindex)) {
        goto error;
    }

    rc = virNWFilterDefToInst(driver,
                              filter,
                              binding->filterparams,
                              useNewFilter, foundNewFilter,
                              &inst);

    if (rc < 0)
        goto error;

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
            goto error;

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

 error:
    virNWFilterInstReset(&inst);

    return rc;

 err_unresolvable_vars:

    buf = virNWFilterPrintVars(missing_vars, ", ", false, reportIP);
    if (buf) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Cannot instantiate filter due to unresolvable variables or unavailable list elements: %1$s"),
                       buf);
    }

    rc = -1;
    goto error;
}


static int
virNWFilterVarHashmapAddStdValue(GHashTable *table,
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
virNWFilterInstantiateFilterUpdate(virNWFilterDriverState *driver,
                                   bool teardownOld,
                                   virNWFilterBindingDef *binding,
                                   int ifindex,
                                   enum instCase useNewFilter,
                                   bool forceWithPendingReq,
                                   bool *foundNewFilter)
{
    int rc = -1;
    const char *drvname = EBIPTABLES_DRIVER_ID;
    virNWFilterTechDriver *techdriver;
    virNWFilterObj *obj;
    virNWFilterDef *filter;
    virNWFilterDef *newFilter;
    char vmmacaddr[VIR_MAC_STRING_BUFLEN] = {0};
    virNWFilterVarValue *ipaddr;

    techdriver = virNWFilterTechDriverForName(drvname);

    if (!techdriver) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not get access to ACL tech driver '%1$s'"),
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
        goto error;

    ipaddr = virNWFilterIPAddrMapGetIPAddr(binding->portdevname);
    if (ipaddr &&
        virNWFilterVarHashmapAddStdValue(binding->filterparams,
                                         NWFILTER_STD_VAR_IP,
                                         virNWFilterVarValueGetSimple(ipaddr)) < 0)
        goto error;


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

 error:
    virNWFilterObjUnlock(obj);

    return rc;
}


static int
virNWFilterInstantiateFilterInternal(virNWFilterDriverState *driver,
                                     virNWFilterBindingDef *binding,
                                     bool teardownOld,
                                     enum instCase useNewFilter,
                                     bool *foundNewFilter)
{
    int ifindex;

    /* after grabbing the filter update lock check for the interface; if
       it's not there anymore its filters will be or are being removed
       (while holding the lock) and we don't want to build new ones */
    if (virNetDevExists(binding->portdevname) != 1 ||
        virNetDevGetIndex(binding->portdevname, &ifindex) < 0) {
        /* interfaces / VMs can disappear during filter instantiation;
           don't mark it as an error */
        virResetLastError();
        return 0;
    }

    return virNWFilterInstantiateFilterUpdate(driver, teardownOld,
                                              binding,
                                              ifindex,
                                              useNewFilter,
                                              false, foundNewFilter);
}


int
virNWFilterInstantiateFilterLate(virNWFilterDriverState *driver,
                                 virNWFilterBindingDef *binding,
                                 int ifindex)
{
    int rc = 0;
    bool foundNewFilter = false;
    VIR_LOCK_GUARD lock = virLockGuardLock(&driver->updateLock);

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

    return rc;
}


int
virNWFilterInstantiateFilter(virNWFilterDriverState *driver,
                             virNWFilterBindingDef *binding)
{
    bool foundNewFilter = false;

    return virNWFilterInstantiateFilterInternal(driver, binding,
                                                1,
                                                INSTANTIATE_ALWAYS,
                                                &foundNewFilter);
}


static int
virNWFilterUpdateInstantiateFilter(virNWFilterDriverState *driver,
                                   virNWFilterBindingDef *binding,
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
virNWFilterRollbackUpdateFilter(virNWFilterBindingDef *binding)
{
    const char *drvname = EBIPTABLES_DRIVER_ID;
    int ifindex;
    virNWFilterTechDriver *techdriver;

    techdriver = virNWFilterTechDriverForName(drvname);
    if (!techdriver) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not get access to ACL tech driver '%1$s'"),
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
virNWFilterTearOldFilter(virNWFilterBindingDef *binding)
{
    const char *drvname = EBIPTABLES_DRIVER_ID;
    int ifindex;
    virNWFilterTechDriver *techdriver;

    techdriver = virNWFilterTechDriverForName(drvname);
    if (!techdriver) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not get access to ACL tech driver '%1$s'"),
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
    virNWFilterTechDriver *techdriver;
    techdriver = virNWFilterTechDriverForName(drvname);

    if (!techdriver) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not get access to ACL tech driver '%1$s'"),
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
virNWFilterTeardownFilter(virNWFilterBindingDef *binding)
{
    return _virNWFilterTeardownFilter(binding->portdevname);
}

enum {
    STEP_APPLY_NEW,
    STEP_ROLLBACK,
    STEP_SWITCH,
    STEP_APPLY_CURRENT,
};

static int
virNWFilterBuildOne(virNWFilterDriverState *driver,
                    virNWFilterBindingDef *binding,
                    GHashTable *skipInterfaces,
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
    virNWFilterDriverState *driver;
    GHashTable *skipInterfaces;
    int step;
};

static int
virNWFilterBuildIter(virNWFilterBindingObj *binding, void *opaque)
{
    struct virNWFilterBuildData *data = opaque;
    virNWFilterBindingDef *def = virNWFilterBindingObjGetDef(binding);

    return virNWFilterBuildOne(data->driver, def,
                               data->skipInterfaces, data->step);
}

int
virNWFilterBuildAll(virNWFilterDriverState *driver,
                    bool newFilters)
{
    struct virNWFilterBuildData data = {
        .driver = driver,
    };
    int ret = 0;

    VIR_DEBUG("Build all filters newFilters=%d", newFilters);

    if (newFilters) {
        g_autoptr(GHashTable) skipInterfaces = virHashNew(NULL);
        data.skipInterfaces = skipInterfaces;

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
    } else {
        data.step = STEP_APPLY_CURRENT;
        if (virNWFilterBindingObjListForEach(driver->bindings,
                                             virNWFilterBuildIter,
                                             &data) < 0)
            ret = -1;
    }
    return ret;
}
