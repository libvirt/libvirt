/*
 * nwfilter_gentech_driver.c: generic technology driver
 *
 * Copyright (C) 2011, 2013 Red Hat, Inc.
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
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NWFILTER


#define NWFILTER_STD_VAR_MAC NWFILTER_VARNAME_MAC
#define NWFILTER_STD_VAR_IP  NWFILTER_VARNAME_IP

#define NWFILTER_DFLT_LEARN  "any"

static int _virNWFilterTeardownFilter(const char *ifname);


static virNWFilterTechDriverPtr filter_tech_drivers[] = {
    &ebiptables_driver,
    NULL
};


void virNWFilterTechDriversInit(bool privileged) {
    size_t i = 0;
    VIR_DEBUG("Initializing NWFilter technology drivers");
    while (filter_tech_drivers[i]) {
        if (!(filter_tech_drivers[i]->flags & TECHDRV_FLAG_INITIALIZED))
            filter_tech_drivers[i]->init(privileged);
        i++;
    }
}


void virNWFilterTechDriversShutdown(void) {
    size_t i = 0;
    while (filter_tech_drivers[i]) {
        if ((filter_tech_drivers[i]->flags & TECHDRV_FLAG_INITIALIZED))
            filter_tech_drivers[i]->shutdown();
        i++;
    }
}


virNWFilterTechDriverPtr
virNWFilterTechDriverForName(const char *name) {
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


/**
 * virNWFilterRuleInstAddData:
 * @res : pointer to virNWFilterRuleInst object collecting the instantiation
 *        data of a single firewall rule.
 * @data : the opaque data that the driver wants to add
 *
 * Add instantiation data to a firewall rule. An instantiated firewall
 * rule may hold multiple data structure representing its instantiation
 * data. This may for example be the case if a rule has been defined
 * for bidirectional traffic and data needs to be added to the incoming
 * and outgoing chains.
 *
 * Returns 0 in case of success, -1 in case of an error.
 */
int
virNWFilterRuleInstAddData(virNWFilterRuleInstPtr res,
                           void *data)
{
    if (VIR_REALLOC_N(res->data, res->ndata+1) < 0)
        return -1;
    res->data[res->ndata++] = data;
    return 0;
}


static void
virNWFilterRuleInstFree(virNWFilterRuleInstPtr inst)
{
    size_t i;
    if (!inst)
        return;

    for (i = 0; i < inst->ndata; i++)
        inst->techdriver->freeRuleInstance(inst->data[i]);

    VIR_FREE(inst->data);
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


static void
printString(void *payload ATTRIBUTE_UNUSED, const void *name, void *data)
{
    struct printString *ps = data;

    if ((STREQ((char *)name, NWFILTER_STD_VAR_IP) && !ps->reportIP) ||
        (STREQ((char *)name, NWFILTER_STD_VAR_MAC) && !ps->reportMAC))
        return;

    if (virBufferUse(&ps->buf) && ps->separator)
        virBufferAdd(&ps->buf, ps->separator, -1);

    virBufferAdd(&ps->buf, name, -1);
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

     if (virBufferError(&ps.buf)) {
         virBufferFreeAndReset(&ps.buf);
         virReportOOMError();
         return NULL;
     }
     return virBufferContentAndReset(&ps.buf);
}


/**
 * virNWFilterRuleInstantiate:
 * @techdriver: the driver to use for instantiation
 * @filter: The filter the rule is part of
 * @rule : The rule that is to be instantiated
 * @ifname: The name of the interface
 * @vars: map containing variable names and value used for instantiation
 *
 * Returns virNWFilterRuleInst object on success, NULL on error with
 * error reported.
 *
 * Instantiate a single rule. Return a pointer to virNWFilterRuleInst
 * object that will hold an array of driver-specific data resulting
 * from the instantiation. Returns NULL on error with error reported.
 */
static virNWFilterRuleInstPtr
virNWFilterRuleInstantiate(virNWFilterTechDriverPtr techdriver,
                           enum virDomainNetType nettype,
                           virNWFilterDefPtr filter,
                           virNWFilterRuleDefPtr rule,
                           const char *ifname,
                           virNWFilterHashTablePtr vars)
{
    int rc;
    size_t i;
    virNWFilterRuleInstPtr ret;

    if (VIR_ALLOC(ret) < 0)
        return NULL;

    ret->techdriver = techdriver;

    rc = techdriver->createRuleInstance(nettype, filter,
                                        rule, ifname, vars, ret);

    if (rc) {
        for (i = 0; i < ret->ndata; i++)
            techdriver->freeRuleInstance(ret->data[i]);
        VIR_FREE(ret);
        ret = NULL;
    }

    return ret;
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


/**
 * _virNWFilterInstantiateRec:
 * @techdriver: The driver to use for instantiation
 * @filter: The filter to instantiate
 * @ifname: The name of the interface to apply the rules to
 * @vars: A map holding variable names and values used for instantiating
 *  the filter and its subfilters.
 * @nEntries: number of virNWFilterInst objects collected
 * @insts: pointer to array for virNWFilterIns object pointers
 * @useNewFilter: instruct whether to use a newDef pointer rather than a
 *  def ptr which is useful during a filter update
 * @foundNewFilter: pointer to int indivating whether a newDef pointer was
 *  ever used; variable expected to be initialized to 0 by caller
 *
 * Returns 0 on success, a value otherwise.
 *
 * Recursively instantiate a filter by instantiating the given filter along
 * with all its subfilters in a depth-first traversal of the tree of
 * referenced filters. The name of the interface to which the rules belong
 * must be provided. Apply the values of variables as needed. Terminate with
 * error when a referenced filter is missing or a variable could not be
 * resolved -- among other reasons.
 */
static int
_virNWFilterInstantiateRec(virNWFilterTechDriverPtr techdriver,
                           enum virDomainNetType nettype,
                           virNWFilterDefPtr filter,
                           const char *ifname,
                           virNWFilterHashTablePtr vars,
                           int *nEntries,
                           virNWFilterRuleInstPtr **insts,
                           enum instCase useNewFilter, bool *foundNewFilter,
                           virNWFilterDriverStatePtr driver)
{
    virNWFilterObjPtr obj;
    int rc = 0;
    size_t i;
    virNWFilterRuleInstPtr inst;
    virNWFilterDefPtr next_filter;

    for (i = 0; i < filter->nentries; i++) {
        virNWFilterRuleDefPtr    rule = filter->filterEntries[i]->rule;
        virNWFilterIncludeDefPtr inc  = filter->filterEntries[i]->include;
        if (rule) {
            inst = virNWFilterRuleInstantiate(techdriver,
                                              nettype,
                                              filter,
                                              rule,
                                              ifname,
                                              vars);
            if (!inst) {
                rc = -1;
                break;
            }

            if (VIR_REALLOC_N(*insts, (*nEntries)+1) < 0) {
                rc = -1;
                break;
            }

            (*insts)[(*nEntries)++] = inst;

        } else if (inc) {
            VIR_DEBUG("Instantiating filter %s", inc->filterref);
            obj = virNWFilterObjFindByName(&driver->nwfilters, inc->filterref);
            if (obj) {

                if (obj->wantRemoved) {
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

                next_filter = obj->def;

                switch (useNewFilter) {
                case INSTANTIATE_FOLLOW_NEWFILTER:
                    if (obj->newDef) {
                        next_filter = obj->newDef;
                        *foundNewFilter = true;
                    }
                break;
                case INSTANTIATE_ALWAYS:
                break;
                }

                rc = _virNWFilterInstantiateRec(techdriver,
                                                nettype,
                                                next_filter,
                                                ifname,
                                                tmpvars,
                                                nEntries, insts,
                                                useNewFilter,
                                                foundNewFilter,
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
                                            val, 1);
                    VIR_FREE(varAccess);
                }
            }
            if (rc)
                break;
        } else if (inc) {
            VIR_DEBUG("Following filter %s\n", inc->filterref);
            obj = virNWFilterObjFindByName(&driver->nwfilters, inc->filterref);
            if (obj) {

                if (obj->wantRemoved) {
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

                next_filter = obj->def;

                switch (useNewFilter) {
                case INSTANTIATE_FOLLOW_NEWFILTER:
                    if (obj->newDef) {
                        next_filter = obj->newDef;
                    }
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


static int
virNWFilterRuleInstancesToArray(int nEntries,
                                virNWFilterRuleInstPtr *insts,
                                void ***ptrs,
                                int *nptrs)
{
    size_t i, j;

    *nptrs = 0;

    for (j = 0; j < nEntries; j++)
        (*nptrs) += insts[j]->ndata;

    if ((*nptrs) == 0)
        return 0;

    if (VIR_ALLOC_N((*ptrs), (*nptrs)) < 0)
        return -1;

    (*nptrs) = 0;

    for (j = 0; j < nEntries; j++)
        for (i = 0; i < insts[j]->ndata; i++)
            (*ptrs)[(*nptrs)++] = insts[j]->data[i];

    return 0;
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
                       enum virDomainNetType nettype,
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
    size_t j;
    int nptrs;
    int nEntries = 0;
    virNWFilterRuleInstPtr *insts = NULL;
    void **ptrs = NULL;
    bool instantiate = true;
    char *buf;
    virNWFilterVarValuePtr lv;
    const char *learning;
    bool reportIP = false;

    virNWFilterHashTablePtr missing_vars = virNWFilterHashTableCreate(0);
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
                                             nettype, vmuuid, macaddr,
                                             filter->name, vars, driver);
                goto err_exit;
            } else if (STRCASEEQ(learning, "any")) {
                if (virNWFilterLookupLearnReq(ifindex) == NULL) {
                    rc = virNWFilterLearnIPAddress(techdriver,
                                                   ifname,
                                                   ifindex,
                                                   linkdev,
                                                   nettype, macaddr,
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
            }
        } else
             goto err_unresolvable_vars;
    } else if (virHashSize(missing_vars->hashTable) > 1) {
        goto err_unresolvable_vars;
    } else if (!forceWithPendingReq &&
               virNWFilterLookupLearnReq(ifindex) != NULL) {
        goto err_exit;
    }

    rc = _virNWFilterInstantiateRec(techdriver,
                                    nettype,
                                    filter,
                                    ifname,
                                    vars,
                                    &nEntries, &insts,
                                    useNewFilter, foundNewFilter,
                                    driver);

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

        rc = virNWFilterRuleInstancesToArray(nEntries, insts,
                                             &ptrs, &nptrs);
        if (rc < 0)
            goto err_exit;

        if (virNWFilterLockIface(ifname) < 0)
            goto err_exit;

        rc = techdriver->applyNewRules(ifname, nptrs, ptrs);

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

    for (j = 0; j < nEntries; j++)
        virNWFilterRuleInstFree(insts[j]);

    VIR_FREE(insts);
    VIR_FREE(ptrs);

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
                               enum virDomainNetType nettype,
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

    obj = virNWFilterObjFindByName(&driver->nwfilters, filtername);
    if (!obj) {
        virReportError(VIR_ERR_NO_NWFILTER,
                       _("Could not find filter '%s'"),
                       filtername);
        return -1;
    }

    if (obj->wantRemoved) {
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

    filter = obj->def;

    switch (useNewFilter) {
    case INSTANTIATE_FOLLOW_NEWFILTER:
        if (obj->newDef) {
            filter = obj->newDef;
            *foundNewFilter = true;
        }
    break;

    case INSTANTIATE_ALWAYS:
    break;
    }

    rc = virNWFilterInstantiate(vmuuid,
                                techdriver,
                                nettype,
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

    virNWFilterLockFilterUpdates();

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
                                        net->type,
                                        &net->mac,
                                        net->filter,
                                        net->filterparams,
                                        useNewFilter,
                                        false,
                                        foundNewFilter);

cleanup:
    virNWFilterUnlockFilterUpdates();

    return rc;
}


int
virNWFilterInstantiateFilterLate(virNWFilterDriverStatePtr driver,
                                 const unsigned char *vmuuid,
                                 const char *ifname,
                                 int ifindex,
                                 const char *linkdev,
                                 enum virDomainNetType nettype,
                                 const virMacAddr *macaddr,
                                 const char *filtername,
                                 virNWFilterHashTablePtr filterparams)
{
    int rc;
    bool foundNewFilter = false;

    virNWFilterLockFilterUpdates();

    rc = __virNWFilterInstantiateFilter(driver,
                                        vmuuid,
                                        true,
                                        ifname,
                                        ifindex,
                                        linkdev,
                                        nettype,
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
    return _virNWFilterTeardownFilter(net->ifname);
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
                    if (!virHashLookup(cb->skipInterfaces, net->ifname)) {
                        ret = virNWFilterRollbackUpdateFilter(net);
                    }
                    break;

                case STEP_TEAR_OLD:
                    if (!virHashLookup(cb->skipInterfaces, net->ifname)) {
                        ret = virNWFilterTearOldFilter(net);
                    }
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
