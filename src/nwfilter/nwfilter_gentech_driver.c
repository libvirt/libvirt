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
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>

#include "internal.h"

#include "memory.h"
#include "logging.h"
#include "datatypes.h"
#include "domain_conf.h"
#include "virterror_internal.h"
#include "nwfilter_gentech_driver.h"
#include "nwfilter_ebiptables_driver.h"
#include "nwfilter_learnipaddr.h"


#define VIR_FROM_THIS VIR_FROM_NWFILTER


#define NWFILTER_STD_VAR_MAC "MAC"
#define NWFILTER_STD_VAR_IP  "IP"

static int _virNWFilterTeardownFilter(const char *ifname);


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
 * @ipaddr: The string of the IP address to add to the hash table;
 *    may be NULL
 *
 * Returns 0 in case of success, 1 in case an error happened with
 * error having been reported.
 *
 * Adds a couple of standard keys (MAC, IP) to the hash table.
 */
static int
virNWFilterVarHashmapAddStdValues(virNWFilterHashTablePtr table,
                                  char *macaddr,
                                  char *ipaddr)
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

    if (ipaddr) {
        if (virHashAddEntry(table->hashTable,
                            NWFILTER_STD_VAR_IP,
                            ipaddr) < 0) {
            virNWFilterReportError(VIR_ERR_INTERNAL_ERROR,
                                   "%s", _("Could not add variable 'IP' to hashmap"));
            return 1;
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
 * Returns pointer to hashmap, NULL if an error occcurred and error message
 * is attached to the virConnect object.
 */
virNWFilterHashTablePtr
virNWFilterCreateVarHashmap(char *macaddr, char *ipaddr) {
    virNWFilterHashTablePtr table = virNWFilterHashTableCreate(0);
    if (!table) {
        virReportOOMError();
        return NULL;
    }

    if (virNWFilterVarHashmapAddStdValues(table, macaddr, ipaddr)) {
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
                           enum instCase useNewFilter, int *foundNewFilter,
                           virNWFilterDriverStatePtr driver)
{
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
                                                foundNewFilter,
                                                driver);

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
virNWFilterDetermineMissingVarsRec(virConnectPtr conn,
                                   virNWFilterDefPtr filter,
                                   virNWFilterHashTablePtr vars,
                                   virNWFilterHashTablePtr missing_vars,
                                   int useNewFilter,
                                   virNWFilterDriverStatePtr driver)
{
    virNWFilterPoolObjPtr obj;
    int rc = 0;
    int i, j;
    virNWFilterDefPtr next_filter;

    for (i = 0; i < filter->nentries; i++) {
        virNWFilterRuleDefPtr    rule = filter->filterEntries[i]->rule;
        virNWFilterIncludeDefPtr inc  = filter->filterEntries[i]->include;
        if (rule) {
            // check all variables of this rule
            for (j = 0; j < rule->nvars; j++) {
                if (!virHashLookup(vars->hashTable, rule->vars[j])) {
                    virNWFilterHashTablePut(missing_vars, rule->vars[j],
                                            strdup("1"), 1);
                }
            }
        } else if (inc) {
            VIR_DEBUG("Following filter %s\n", inc->filterref);
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
                    }
                break;
                case INSTANTIATE_ALWAYS:
                break;
                }

                rc = virNWFilterDetermineMissingVarsRec(conn,
                                                        next_filter,
                                                        tmpvars,
                                                        missing_vars,
                                                        useNewFilter,
                                                        driver);

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
                       const char *linkdev,
                       virNWFilterHashTablePtr vars,
                       enum instCase useNewFilter, int *foundNewFilter,
                       bool teardownOld,
                       const unsigned char *macaddr,
                       virNWFilterDriverStatePtr driver)
{
    int rc;
    int j, nptrs;
    int nEntries = 0;
    virNWFilterRuleInstPtr *insts = NULL;
    void **ptrs = NULL;
    int instantiate = 1;

    virNWFilterLockFilterUpdates();

    virNWFilterHashTablePtr missing_vars = virNWFilterHashTableCreate(0);
    if (!missing_vars) {
        virReportOOMError();
        rc = 1;
        goto err_exit;
    }

    rc = virNWFilterDetermineMissingVarsRec(conn,
                                            filter,
                                            vars,
                                            missing_vars,
                                            useNewFilter,
                                            driver);
    if (rc)
        goto err_exit;

    if (virHashSize(missing_vars->hashTable) == 1) {
        if (virHashLookup(missing_vars->hashTable,
                          NWFILTER_STD_VAR_IP) != NULL) {
            if (virNWFilterLookupLearnReq(ifname) == NULL) {
                rc = virNWFilterLearnIPAddress(ifname,
                                               linkdev,
                                               nettype, macaddr,
                                               filter->name,
                                               vars, driver,
                                               DETECT_DHCP|DETECT_STATIC);
            }
            goto err_exit;
        }
        rc = 1;
        goto err_exit;
    } else if (virHashSize(missing_vars->hashTable) > 1) {
        rc = 1;
        goto err_exit;
    }

    rc = _virNWFilterInstantiateRec(conn,
                                    techdriver,
                                    nettype,
                                    filter,
                                    ifname,
                                    vars,
                                    &nEntries, &insts,
                                    useNewFilter, foundNewFilter,
                                    driver);

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

    virNWFilterUnlockFilterUpdates();

    for (j = 0; j < nEntries; j++)
        virNWFilterRuleInstFree(insts[j]);

    VIR_FREE(insts);

    virNWFilterHashTableFree(missing_vars);

    return rc;
}


static int
__virNWFilterInstantiateFilter(virConnectPtr conn,
                               bool teardownOld,
                               const char *ifname,
                               const char *linkdev,
                               enum virDomainNetType nettype,
                               const unsigned char *macaddr,
                               const char *filtername,
                               virNWFilterHashTablePtr filterparams,
                               enum instCase useNewFilter,
                               virNWFilterDriverStatePtr driver)
{
    int rc;
    const char *drvname = EBIPTABLES_DRIVER_ID;
    virNWFilterTechDriverPtr techdriver;
    virNWFilterPoolObjPtr obj;
    virNWFilterHashTablePtr vars, vars1;
    virNWFilterDefPtr filter;
    char vmmacaddr[VIR_MAC_STRING_BUFLEN] = {0};
    int foundNewFilter = 0;
    char *str_macaddr = NULL;
    const char *ipaddr;
    char *str_ipaddr = NULL;

    techdriver = virNWFilterTechDriverForName(drvname);

    if (!techdriver) {
        virNWFilterReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Could not get access to ACL tech "
                               "driver '%s'"),
                               drvname);
        return 1;
    }

    VIR_DEBUG("filter name: %s", filtername);

    obj = virNWFilterPoolObjFindByName(&driver->pools, filtername);
    if (!obj) {
        virNWFilterReportError(VIR_ERR_NO_NWFILTER,
                               _("Could not find filter '%s'"),
                               filtername);
        return 1;
    }

    if (obj->wantRemoved) {
        virNWFilterReportError(VIR_ERR_NO_NWFILTER,
                               _("Filter '%s' is in use."),
                               filtername);
        rc = 1;
        goto err_exit;
    }

    virFormatMacAddr(macaddr, vmmacaddr);
    str_macaddr = strdup(vmmacaddr);
    if (!str_macaddr) {
        virReportOOMError();
        rc = 1;
        goto err_exit;
    }

    ipaddr = virNWFilterGetIpAddrForIfname(ifname);
    if (ipaddr) {
        str_ipaddr = strdup(ipaddr);
        if (!str_ipaddr) {
            virReportOOMError();
            rc = 1;
            goto err_exit;
        }
    }

    vars1 = virNWFilterCreateVarHashmap(str_macaddr, str_ipaddr);
    if (!vars1) {
        rc = 1;
        goto err_exit;
    }

    str_macaddr = NULL;
    str_ipaddr = NULL;

    vars = virNWFilterCreateVarsFrom(vars1,
                                     filterparams);
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
                                nettype,
                                filter,
                                ifname,
                                linkdev,
                                vars,
                                useNewFilter, &foundNewFilter,
                                teardownOld,
                                macaddr,
                                driver);

    virNWFilterHashTableFree(vars);

err_exit_vars1:
    virNWFilterHashTableFree(vars1);

err_exit:
    virNWFilterPoolObjUnlock(obj);

    VIR_FREE(str_ipaddr);
    VIR_FREE(str_macaddr);

    return rc;
}


static int
_virNWFilterInstantiateFilter(virConnectPtr conn,
                              const virDomainNetDefPtr net,
                              bool teardownOld,
                              enum instCase useNewFilter)
{
    const char *linkdev = (net->type == VIR_DOMAIN_NET_TYPE_DIRECT)
                          ? net->data.direct.linkdev
                          : NULL;
    return __virNWFilterInstantiateFilter(conn,
                                          teardownOld,
                                          net->ifname,
                                          linkdev,
                                          net->type,
                                          net->mac,
                                          net->filter,
                                          net->filterparams,
                                          useNewFilter,
                                          conn->nwfilterPrivateData);
}


// FIXME: move chgIfFlags, ifUp, checkIf into common file & share w/ macvtap.c

/*
 * chgIfFlags: Change flags on an interface
 * @ifname : name of the interface
 * @flagclear : the flags to clear
 * @flagset : the flags to set
 *
 * The new flags of the interface will be calculated as
 * flagmask = (~0 ^ flagclear)
 * newflags = (curflags & flagmask) | flagset;
 *
 * Returns 0 on success, errno on failure.
 */
static int chgIfFlags(const char *ifname, short flagclear, short flagset) {
    struct ifreq ifr;
    int rc = 0;
    int flags;
    short flagmask = (~0 ^ flagclear);
    int fd = socket(PF_PACKET, SOCK_DGRAM, 0);

    if (fd < 0)
        return errno;

    if (virStrncpy(ifr.ifr_name,
                   ifname, strlen(ifname), sizeof(ifr.ifr_name)) == NULL) {
        rc = ENODEV;
        goto err_exit;
    }

    if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
        rc = errno;
        goto err_exit;
    }

    flags = (ifr.ifr_flags & flagmask) | flagset;

    if (ifr.ifr_flags != flags) {
        ifr.ifr_flags = flags;

        if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0)
            rc = errno;
    }

err_exit:
    close(fd);
    return rc;
}

/*
 * ifUp
 * @name: name of the interface
 * @up: 1 for up, 0 for down
 *
 * Function to control if an interface is activated (up, 1) or not (down, 0)
 *
 * Returns 0 in case of success or an errno code in case of failure.
 */
static int
ifUp(const char *name, int up)
{
    return chgIfFlags(name,
                      (up) ? 0      : IFF_UP,
                      (up) ? IFF_UP : 0);
}


/**
 * checkIf
 *
 * @ifname: Name of the interface
 * @macaddr: expected MAC address of the interface
 *
 * FIXME: the interface's index is another good parameter to check
 *
 * Determine whether a given interface is still available. If so,
 * it must have the given MAC address.
 *
 * Returns an error code ENODEV in case the interface does not exist
 * anymore or its MAC address is different, 0 otherwise.
 */
int
checkIf(const char *ifname, const unsigned char *macaddr)
{
    struct ifreq ifr;
    int fd = socket(PF_PACKET, SOCK_DGRAM, 0);
    int rc = 0;

    if (fd < 0)
        return errno;

    if (virStrncpy(ifr.ifr_name,
                   ifname, strlen(ifname), sizeof(ifr.ifr_name)) == NULL) {
        rc = ENODEV;
        goto err_exit;
    }

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        rc = errno;
        goto err_exit;
    }

    if (memcmp(&ifr.ifr_hwaddr.sa_data, macaddr, 6) != 0)
        rc = ENODEV;

 err_exit:
    close(fd);
    return rc;
}


int
virNWFilterInstantiateFilterLate(virConnectPtr conn,
                                 const char *ifname,
                                 const char *linkdev,
                                 enum virDomainNetType nettype,
                                 const unsigned char *macaddr,
                                 const char *filtername,
                                 virNWFilterHashTablePtr filterparams,
                                 virNWFilterDriverStatePtr driver)
{
    int rc;
    rc = __virNWFilterInstantiateFilter(conn,
                                        1,
                                        ifname,
                                        linkdev,
                                        nettype,
                                        macaddr,
                                        filtername,
                                        filterparams,
                                        INSTANTIATE_ALWAYS,
                                        driver);
    if (rc) {
        //something went wrong... 'DOWN' the interface
        if (ifUp(ifname ,0)) {
            // assuming interface disappeared...
            _virNWFilterTeardownFilter(ifname);
        }
    }
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


static int
_virNWFilterTeardownFilter(const char *ifname)
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
    techdriver->allTeardown(ifname);

    virNWFilterDelIpAddrForIfname(ifname);

    return 0;
}


int
virNWFilterTeardownFilter(const virDomainNetDefPtr net)
{
    return _virNWFilterTeardownFilter(net->ifname);
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
