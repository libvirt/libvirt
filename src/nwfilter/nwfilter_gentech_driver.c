/*
 * nwfilter_gentech_driver.c: generic technology driver
 *
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Stefan Berger <stefanb@us.ibm.com>
 */

#include <config.h>

#include <stdint.h>

#include "internal.h"

#include "memory.h"
#include "logging.h"
#include "datatypes.h"
#include "domain_conf.h"
#include "virterror_internal.h"
#include "nwfilter_gentech_driver.h"
#include "nwfilter_ebiptables_driver.h"


#define VIR_FROM_THIS VIR_FROM_NWFILTER


#define NWFILTER_STD_VAR_MAC "MAC"


static virNWFilterTechDriverPtr filter_tech_drivers[] = {
    &ebiptables_driver,
    NULL
};


virNWFilterTechDriverPtr
virNWFilterTechDriverForName(const char *name) {
    int i = 0;
    while (filter_tech_drivers[i]) {
       if (STREQ(filter_tech_drivers[i]->name, name))
           return filter_tech_drivers[i];
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
 * Returns 0 in case of success, 1 in case of an error with the error
 * message attached to the virConnect object.
 */
int
virNWFilterRuleInstAddData(virNWFilterRuleInstPtr res,
                           void *data)
{
    if (VIR_REALLOC_N(res->data, res->ndata+1) < 0) {
        virReportOOMError();
        return 1;
    }
    res->data[res->ndata++] = data;
    return 0;
}


static void
virNWFilterRuleInstFree(virNWFilterRuleInstPtr inst)
{
    int i;
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
 *
 * Returns 0 in case of success, 1 in case an error happened with
 * error having been reported.
 *
 * Adds a couple of standard keys (MAC, IP) to the hash table.
 */
static int
virNWFilterVarHashmapAddStdValues(virNWFilterHashTablePtr table,
                                  char *macaddr)
{
    if (macaddr) {
        if (virHashAddEntry(table->hashTable,
                            NWFILTER_STD_VAR_MAC,
                            macaddr) < 0) {
            virNWFilterReportError(VIR_ERR_INTERNAL_ERROR,
                                   "%s", _("Could not add variable 'MAC' to hashmap"));
            return 1;
        }
    }

    return 0;
}


/**
 * virNWFilterCreateVarHashmap:
 * @macaddr: pointer to string containing formatted MAC address of interface
 *
 * Create a hashmap used for evaluating the firewall rules. Initializes
 * it with the standard variable 'MAC'.
 *
 * Returns pointer to hashmap, NULL if an error occcurred and error message
 * is attached to the virConnect object.
 */
virNWFilterHashTablePtr
virNWFilterCreateVarHashmap(char *macaddr) {
    virNWFilterHashTablePtr table = virNWFilterHashTableCreate(0);
    if (!table) {
        virReportOOMError();
        return NULL;
    }

    if (virNWFilterVarHashmapAddStdValues(table, macaddr)) {
        virNWFilterHashTableFree(table);
        return NULL;
    }
    return table;
}


/**
 * virNWFilterRuleInstantiate:
 * @conn: pointer to virConnect object
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
virNWFilterRuleInstantiate(virConnectPtr conn,
                           virNWFilterTechDriverPtr techdriver,
                           enum virDomainNetType nettype,
                           virNWFilterDefPtr filter,
                           virNWFilterRuleDefPtr rule,
                           const char *ifname,
                           virNWFilterHashTablePtr vars)
{
    int rc;
    int i;
    virNWFilterRuleInstPtr ret;

    if (VIR_ALLOC(ret) < 0) {
        virReportOOMError();
        return NULL;
    }

    ret->techdriver = techdriver;

    rc = techdriver->createRuleInstance(conn, nettype, filter,
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
    if (!res) {
        virReportOOMError();
        return NULL;
    }

    if (virNWFilterHashTablePutAll(vars1, res))
        goto err_exit;

    if (virNWFilterHashTablePutAll(vars2, res))
        goto err_exit;

    return res;

err_exit:
    virNWFilterHashTableFree(res);
    return NULL;
}


/**
 * _virNWFilterPoolInstantiateRec:
 * @conn: pointer to virConnect object
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
_virNWFilterInstantiateRec(virConnectPtr conn,
                           virNWFilterTechDriverPtr techdriver,
                           enum virDomainNetType nettype,
                           virNWFilterDefPtr filter,
                           const char *ifname,
                           virNWFilterHashTablePtr vars,
                           int *nEntries,
                           virNWFilterRuleInstPtr **insts,
                           enum instCase useNewFilter, int *foundNewFilter)
{
    virNWFilterDriverStatePtr driver = conn->nwfilterPrivateData;
    virNWFilterPoolObjPtr obj;
    int rc = 0;
    int i;
    virNWFilterRuleInstPtr inst;
    virNWFilterDefPtr next_filter;

    for (i = 0; i < filter->nentries; i++) {
        virNWFilterRuleDefPtr    rule = filter->filterEntries[i]->rule;
        virNWFilterIncludeDefPtr inc  = filter->filterEntries[i]->include;
        if (rule) {
            inst = virNWFilterRuleInstantiate(conn,
                                              techdriver,
                                              nettype,
                                              filter,
                                              rule,
                                              ifname,
                                              vars);
            if (!inst) {
                rc = 1;
                break;
            }

            if (VIR_REALLOC_N(*insts, (*nEntries)+1) < 0) {
                virReportOOMError();
                rc = 1;
                break;
            }

            (*insts)[(*nEntries)++] = inst;

        } else if (inc) {
            VIR_DEBUG("Instantiating filter %s", inc->filterref);
            obj = virNWFilterPoolObjFindByName(&driver->pools,
                                               inc->filterref);
            if (obj) {

                if (obj->wantRemoved) {
                    virNWFilterReportError(VIR_ERR_NO_NWFILTER,
                                           _("Filter '%s' is in use."),
                                           inc->filterref);
                    rc = 1;
                    virNWFilterPoolObjUnlock(obj);
                    break;
                }

                // create a temporary hashmap for depth-first tree traversal
                virNWFilterHashTablePtr tmpvars =
                                      virNWFilterCreateVarsFrom(inc->params,
                                                                vars);
                if (!tmpvars) {
                    virReportOOMError();
                    rc = 1;
                    virNWFilterPoolObjUnlock(obj);
                    break;
                }

                next_filter = obj->def;

                switch (useNewFilter) {
                case INSTANTIATE_FOLLOW_NEWFILTER:
                    if (obj->newDef) {
                        next_filter = obj->newDef;
                        *foundNewFilter = 1;
                    }
                break;
                case INSTANTIATE_ALWAYS:
                break;
                }

                rc = _virNWFilterInstantiateRec(conn,
                                                techdriver,
                                                nettype,
                                                next_filter,
                                                ifname,
                                                tmpvars,
                                                nEntries, insts,
                                                useNewFilter,
                                                foundNewFilter);

                virNWFilterHashTableFree(tmpvars);

                virNWFilterPoolObjUnlock(obj);
                if (rc)
                    break;
            } else {
                virNWFilterReportError(VIR_ERR_INTERNAL_ERROR,
                                       _("referenced filter '%s' is missing"),
                                       inc->filterref);
                rc = 1;
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
    int i,j;

    *nptrs = 0;

    for (j = 0; j < nEntries; j++)
        (*nptrs) += insts[j]->ndata;

    if ((*nptrs) == 0)
        return 0;

    if (VIR_ALLOC_N((*ptrs), (*nptrs)) < 0) {
        virReportOOMError();
        return 1;
    }

    (*nptrs) = 0;

    for (j = 0; j < nEntries; j++)
        for (i = 0; i < insts[j]->ndata; i++)
            (*ptrs)[(*nptrs)++] = insts[j]->data[i];

    return 0;
}


/**
 * virNWFilterInstantiate:
 * @conn: pointer to virConnect object
 * @techdriver: The driver to use for instantiation
 * @filter: The filter to instantiate
 * @ifname: The name of the interface to apply the rules to
 * @vars: A map holding variable names and values used for instantiating
 *  the filter and its subfilters.
 *
 * Returns 0 on success, a value otherwise.
 *
 * Instantiate a filter by instantiating the filter itself along with
 * all its subfilters in a depth-first traversal of the tree of referenced
 * filters. The name of the interface to which the rules belong must be
 * provided. Apply the values of variables as needed.
 */
static int
virNWFilterInstantiate(virConnectPtr conn,
                       virNWFilterTechDriverPtr techdriver,
                       enum virDomainNetType nettype,
                       virNWFilterDefPtr filter,
                       const char *ifname,
                       virNWFilterHashTablePtr vars,
                       enum instCase useNewFilter, int *foundNewFilter,
                       bool teardownOld)
{
    int rc;
    int j, nptrs;
    int nEntries = 0;
    virNWFilterRuleInstPtr *insts = NULL;
    void **ptrs = NULL;
    int instantiate = 1;

    rc = _virNWFilterInstantiateRec(conn,
                                    techdriver,
                                    nettype,
                                    filter,
                                    ifname,
                                    vars,
                                    &nEntries, &insts,
                                    useNewFilter, foundNewFilter);

    if (rc)
        goto err_exit;

    switch (useNewFilter) {
    case INSTANTIATE_FOLLOW_NEWFILTER:
        instantiate = *foundNewFilter;
    break;
    case INSTANTIATE_ALWAYS:
        instantiate = 1;
    break;
    }

    if (instantiate) {

        rc = virNWFilterRuleInstancesToArray(nEntries, insts,
                                             &ptrs, &nptrs);
        if (rc)
            goto err_exit;

        rc = techdriver->applyNewRules(conn, ifname, nptrs, ptrs);

        if (teardownOld && rc == 0)
            techdriver->tearOldRules(conn, ifname);

        VIR_FREE(ptrs);
    }

err_exit:

    for (j = 0; j < nEntries; j++)
        virNWFilterRuleInstFree(insts[j]);

    VIR_FREE(insts);

    return rc;
}


static int
_virNWFilterInstantiateFilter(virConnectPtr conn,
                              const virDomainNetDefPtr net,
                              bool teardownOld,
                              enum instCase useNewFilter)
{
    int rc;
    const char *drvname = EBIPTABLES_DRIVER_ID;
    virNWFilterDriverStatePtr driver = conn->nwfilterPrivateData;
    virNWFilterTechDriverPtr techdriver;
    virNWFilterPoolObjPtr obj;
    virNWFilterHashTablePtr vars, vars1;
    virNWFilterDefPtr filter;
    char vmmacaddr[VIR_MAC_STRING_BUFLEN] = {0};
    int foundNewFilter = 0;
    char *str_macaddr = NULL;

    techdriver = virNWFilterTechDriverForName(drvname);

    if (!techdriver) {
        virNWFilterReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Could not get access to ACL tech "
                               "driver '%s'"),
                               drvname);
        return 1;
    }

    VIR_DEBUG("filter name: %s", net->filter);

    obj = virNWFilterPoolObjFindByName(&driver->pools, net->filter);
    if (!obj) {
        virNWFilterReportError(VIR_ERR_NO_NWFILTER,
                               _("Could not find filter '%s'"),
                               net->filter);
        return 1;
    }

    if (obj->wantRemoved) {
        virNWFilterReportError(VIR_ERR_NO_NWFILTER,
                               _("Filter '%s' is in use."),
                               net->filter);
        rc = 1;
        goto err_exit;
    }

    virFormatMacAddr(net->mac, vmmacaddr);
    str_macaddr = strdup(vmmacaddr);
    if (!str_macaddr) {
        virReportOOMError();
        rc = 1;
        goto err_exit;
    }

    vars1 = virNWFilterCreateVarHashmap(str_macaddr);
    if (!vars1) {
        rc = 1;
        goto err_exit;
    }

    str_macaddr = NULL;

    vars = virNWFilterCreateVarsFrom(vars1,
                                     net->filterparams);
    if (!vars) {
        rc = 1;
        goto err_exit_vars1;
    }

    filter = obj->def;

    switch (useNewFilter) {
    case INSTANTIATE_FOLLOW_NEWFILTER:
        if (obj->newDef) {
            filter = obj->newDef;
            foundNewFilter = 1;
        }
    break;

    case INSTANTIATE_ALWAYS:
    break;
    }

    rc = virNWFilterInstantiate(conn,
                                techdriver,
                                net->type,
                                filter,
                                net->ifname,
                                vars,
                                useNewFilter, &foundNewFilter,
                                teardownOld);

    virNWFilterHashTableFree(vars);

err_exit_vars1:
    virNWFilterHashTableFree(vars1);

err_exit:

    virNWFilterPoolObjUnlock(obj);

    VIR_FREE(str_macaddr);

    return rc;
}


int
virNWFilterInstantiateFilter(virConnectPtr conn,
                             const virDomainNetDefPtr net)
{
    return _virNWFilterInstantiateFilter(conn, net,
                                         1,
                                         INSTANTIATE_ALWAYS);
}


int
virNWFilterUpdateInstantiateFilter(virConnectPtr conn,
                                   const virDomainNetDefPtr net)
{
    return _virNWFilterInstantiateFilter(conn, net,
                                         0,
                                         INSTANTIATE_FOLLOW_NEWFILTER);
}

int virNWFilterRollbackUpdateFilter(virConnectPtr conn,
                                    const virDomainNetDefPtr net)
{
    const char *drvname = EBIPTABLES_DRIVER_ID;
    virNWFilterTechDriverPtr techdriver;
    techdriver = virNWFilterTechDriverForName(drvname);
    if (!techdriver) {
        virNWFilterReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Could not get access to ACL tech "
                               "driver '%s'"),
                               drvname);
        return 1;
    }

    return techdriver->tearNewRules(conn, net->ifname);
}


int
virNWFilterTearOldFilter(virConnectPtr conn,
                         virDomainNetDefPtr net)
{
    const char *drvname = EBIPTABLES_DRIVER_ID;
    virNWFilterTechDriverPtr techdriver;
    techdriver = virNWFilterTechDriverForName(drvname);
    if (!techdriver) {
        virNWFilterReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Could not get access to ACL tech "
                               "driver '%s'"),
                               drvname);
        return 1;
    }

    return techdriver->tearOldRules(conn, net->ifname);
}


int
virNWFilterTeardownFilter(const virDomainNetDefPtr net)
{
    const char *drvname = EBIPTABLES_DRIVER_ID;
    virNWFilterTechDriverPtr techdriver;
    techdriver = virNWFilterTechDriverForName(drvname);

    if (!techdriver) {
        virNWFilterReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Could not get access to ACL tech "
                               "driver '%s'"),
                               drvname);
        return 1;
    }

    techdriver->allTeardown(net->ifname);

    return 0;
}


void
virNWFilterDomainFWUpdateCB(void *payload,
                            const char *name ATTRIBUTE_UNUSED,
                            void *data)
{
    virDomainObjPtr obj = payload;
    virDomainDefPtr vm = obj->def;
    struct domUpdateCBStruct *cb = data;
    int i;

    virDomainObjLock(obj);

    if (virDomainObjIsActive(obj)) {
        for (i = 0; i < vm->nnets; i++) {
            virDomainNetDefPtr net = vm->nets[i];
            if ((net->filter) && (net->ifname)) {
                switch (cb->step) {
                case STEP_APPLY_NEW:
                    cb->err = virNWFilterUpdateInstantiateFilter(cb->conn,
                                                                 net);
                    break;

                case STEP_TEAR_NEW:
                    cb->err = virNWFilterRollbackUpdateFilter(cb->conn, net);
                    break;

                case STEP_TEAR_OLD:
                    cb->err = virNWFilterTearOldFilter(cb->conn, net);
                    break;
                }
                if (cb->err)
                    break;
            }
        }
    }

    virDomainObjUnlock(obj);
}
