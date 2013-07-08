/*
 * interface_driver.c: backend driver methods to handle physical
 *                     interface configuration using the netcf library.
 *
 * Copyright (C) 2006-2012 Red Hat, Inc.
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
 * Author: Laine Stump <laine@redhat.com>
 */

#include <config.h>

#include <netcf.h>

#include "virerror.h"
#include "datatypes.h"
#include "interface_driver.h"
#include "interface_conf.h"
#include "viralloc.h"
#include "virlog.h"
#include "virstring.h"
#include "viraccessapicheck.h"

#define VIR_FROM_THIS VIR_FROM_INTERFACE

/* Main driver state */
struct interface_driver
{
    virMutex lock;
    struct netcf *netcf;
};


static void interfaceDriverLock(struct interface_driver *driver)
{
    virMutexLock(&driver->lock);
}

static void interfaceDriverUnlock(struct interface_driver *driver)
{
    virMutexUnlock(&driver->lock);
}

/*
 * Get a minimal virInterfaceDef containing enough metadata
 * for access control checks to be performed. Currently
 * this implies existance of name and mac address attributes
 */
static virInterfaceDef * ATTRIBUTE_NONNULL(1)
netcfGetMinimalDefForDevice(struct netcf_if *iface)
{
    virInterfaceDef *def;

    /* Allocate our interface definition structure */
    if (VIR_ALLOC(def) < 0)
        return NULL;

    if (VIR_STRDUP(def->name, ncf_if_name(iface)) < 0)
        goto cleanup;

    if (VIR_STRDUP(def->mac, ncf_if_mac_string(iface)) < 0)
        goto cleanup;

    return def;

cleanup:
    virInterfaceDefFree(def);
    return NULL;
}


static int netcf_to_vir_err(int netcf_errcode)
{
    switch (netcf_errcode)
    {
        case NETCF_NOERROR:
            /* no error, everything ok */
            return VIR_ERR_OK;
        case NETCF_EINTERNAL:
            /* internal error, aka bug */
            return VIR_ERR_INTERNAL_ERROR;
        case NETCF_EOTHER:
            /* other error, copout for being more specific */
            return VIR_ERR_INTERNAL_ERROR;
        case NETCF_ENOMEM:
            /*
             * allocation failed return VIR ERR NO MEMORY
             * though it should not be used now.
             */
            return 2;
        case NETCF_EXMLPARSER:
            /* XML parser choked */
            return VIR_ERR_XML_ERROR;
        case NETCF_EXMLINVALID:
            /* XML invalid in some form */
            return VIR_ERR_XML_ERROR;
        case NETCF_ENOENT:
            /* Required entry in a tree is missing */
            return VIR_ERR_INTERNAL_ERROR;
        case NETCF_EEXEC:
            /* external program execution failed or returned non-0 */
            return VIR_ERR_INTERNAL_ERROR;
#ifdef NETCF_EINVALIDOP
        case NETCF_EINVALIDOP:
            /* attempted operation is invalid while the system is in the current state. */
            return VIR_ERR_OPERATION_INVALID;
#endif
        default:
            return VIR_ERR_INTERNAL_ERROR;
    }
}

static struct netcf_if *interfaceDriverGetNetcfIF(struct netcf *ncf, virInterfacePtr ifinfo)
{
    /* 1) caller already has lock,
     * 2) caller cleans up iface on return
     */
    struct netcf_if *iface = ncf_lookup_by_name(ncf, ifinfo->name);
    if (!iface) {
        const char *errmsg, *details;
        int errcode = ncf_error(ncf, &errmsg, &details);
        if (errcode != NETCF_NOERROR) {
            virReportError(netcf_to_vir_err(errcode),
                           _("couldn't find interface named '%s': %s%s%s"),
                           ifinfo->name, errmsg, details ? " - " : "",
                           details ? details : "");
        } else {
            virReportError(VIR_ERR_NO_INTERFACE,
                           _("couldn't find interface named '%s'"),
                           ifinfo->name);
        }
    }
    return iface;
}

static virDrvOpenStatus netcfInterfaceOpen(virConnectPtr conn,
                                           virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                                           unsigned int flags)
{
    struct interface_driver *driverState;

    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    if (VIR_ALLOC(driverState) < 0)
        goto alloc_error;

    /* initialize non-0 stuff in driverState */
    if (virMutexInit(&driverState->lock) < 0)
    {
        /* what error to report? */
        goto mutex_error;
    }

    /* open netcf */
    if (ncf_init(&driverState->netcf, NULL) != 0)
    {
        /* what error to report? */
        goto netcf_error;
    }

    conn->interfacePrivateData = driverState;
    return VIR_DRV_OPEN_SUCCESS;

netcf_error:
    if (driverState->netcf)
    {
        ncf_close(driverState->netcf);
    }
    virMutexDestroy(&driverState->lock);
mutex_error:
    VIR_FREE(driverState);
alloc_error:
    return VIR_DRV_OPEN_ERROR;
}

static int netcfInterfaceClose(virConnectPtr conn)
{

    if (conn->interfacePrivateData != NULL)
    {
        struct interface_driver *driver = conn->interfacePrivateData;

        /* close netcf instance */
        ncf_close(driver->netcf);
        /* destroy lock */
        virMutexDestroy(&driver->lock);
        /* free driver state */
        VIR_FREE(driver);
    }
    conn->interfacePrivateData = NULL;
    return 0;
}

static int netcfConnectNumOfInterfacesImpl(virConnectPtr conn,
                                           int status,
                                           virInterfaceObjListFilter filter)
{
    struct interface_driver *driver = conn->interfacePrivateData;
    int count;
    int want = 0;
    int ret = -1;
    size_t i;
    char **names = NULL;

    /* List all interfaces, in case we might support new filter flags
     * beyond active|inactive in future.
     */
    count = ncf_num_of_interfaces(driver->netcf, status);
    if (count < 0) {
        const char *errmsg, *details;
        int errcode = ncf_error(driver->netcf, &errmsg, &details);
        virReportError(netcf_to_vir_err(errcode),
                       _("failed to get number of host interfaces: %s%s%s"),
                       errmsg, details ? " - " : "",
                       details ? details : "");
        goto cleanup;
    }

    if (count == 0) {
        ret = 0;
        goto cleanup;
    }

    if (VIR_ALLOC_N(names, count) < 0)
        goto cleanup;

    if ((count = ncf_list_interfaces(driver->netcf, count, names, status)) < 0) {
        const char *errmsg, *details;
        int errcode = ncf_error(driver->netcf, &errmsg, &details);
        virReportError(netcf_to_vir_err(errcode),
                       _("failed to list host interfaces: %s%s%s"),
                       errmsg, details ? " - " : "",
                       details ? details : "");
        goto cleanup;
    }

    for (i = 0; i < count; i++) {
        virInterfaceDefPtr def;
        struct netcf_if *iface;

        iface = ncf_lookup_by_name(driver->netcf, names[i]);
        if (!iface) {
            const char *errmsg, *details;
            int errcode = ncf_error(driver->netcf, &errmsg, &details);
            if (errcode != NETCF_NOERROR) {
                virReportError(netcf_to_vir_err(errcode),
                               _("couldn't find interface named '%s': %s%s%s"),
                               names[i], errmsg,
                               details ? " - " : "", details ? details : "");
                goto cleanup;
            } else {
                /* Ignore the NETCF_NOERROR, as the interface is very likely
                 * deleted by other management apps (e.g. virt-manager).
                 */
                VIR_WARN("couldn't find interface named '%s', might be "
                         "deleted by other process", names[i]);
                continue;
            }
        }

        if (!(def = netcfGetMinimalDefForDevice(iface))) {
            ncf_if_free(iface);
            goto cleanup;
        }
        ncf_if_free(iface);

        if (!filter(conn, def)) {
            virInterfaceDefFree(def);
            continue;
        }
        virInterfaceDefFree(def);

        want++;
    }

    ret = want;

cleanup:
    if (names && count > 0)
        for (i = 0; i < count; i++)
            VIR_FREE(names[i]);
    VIR_FREE(names);
    return ret;
}


static int netcfConnectListInterfacesImpl(virConnectPtr conn,
                                          int status,
                                          char **const names, int nnames,
                                          virInterfaceObjListFilter filter)
{
    struct interface_driver *driver = conn->interfacePrivateData;
    int count = 0;
    int want = 0;
    int ret = -1;
    size_t i;
    char **allnames = NULL;

    count = ncf_num_of_interfaces(driver->netcf, status);
    if (count < 0) {
        const char *errmsg, *details;
        int errcode = ncf_error(driver->netcf, &errmsg, &details);
        virReportError(netcf_to_vir_err(errcode),
                       _("failed to get number of host interfaces: %s%s%s"),
                       errmsg, details ? " - " : "",
                       details ? details : "");
        goto cleanup;
    }

    if (count == 0) {
        ret = 0;
        goto cleanup;
    }

    if (VIR_ALLOC_N(allnames, count) < 0)
        goto cleanup;

    if ((count = ncf_list_interfaces(driver->netcf, count, allnames, status)) < 0) {
        const char *errmsg, *details;
        int errcode = ncf_error(driver->netcf, &errmsg, &details);
        virReportError(netcf_to_vir_err(errcode),
                       _("failed to list host interfaces: %s%s%s"),
                       errmsg, details ? " - " : "",
                       details ? details : "");
        goto cleanup;
    }

    if (count == 0) {
        ret = 0;
        goto cleanup;
    }

    for (i = 0; i < count && want < nnames; i++) {
        virInterfaceDefPtr def;
        struct netcf_if *iface;

        iface = ncf_lookup_by_name(driver->netcf, allnames[i]);
        if (!iface) {
            const char *errmsg, *details;
            int errcode = ncf_error(driver->netcf, &errmsg, &details);
            if (errcode != NETCF_NOERROR) {
                virReportError(netcf_to_vir_err(errcode),
                               _("couldn't find interface named '%s': %s%s%s"),
                               allnames[i], errmsg,
                               details ? " - " : "", details ? details : "");
                goto cleanup;
            } else {
                /* Ignore the NETCF_NOERROR, as the interface is very likely
                 * deleted by other management apps (e.g. virt-manager).
                 */
                VIR_WARN("couldn't find interface named '%s', might be "
                         "deleted by other process", allnames[i]);
                continue;
            }
        }

        if (!(def = netcfGetMinimalDefForDevice(iface))) {
            ncf_if_free(iface);
            goto cleanup;
        }
        ncf_if_free(iface);

        if (!filter(conn, def)) {
            virInterfaceDefFree(def);
            continue;
        }
        virInterfaceDefFree(def);

        names[want++] = allnames[i];
        allnames[i] = NULL;
    }

    ret = want;

cleanup:
    if (allnames && count > 0)
        for (i = 0; i < count; i++)
            VIR_FREE(allnames[i]);
    VIR_FREE(allnames);
    if (ret < 0) {
        for (i = 0; i < nnames; i++)
            VIR_FREE(names[i]);
    }
    return ret;
}


static int netcfConnectNumOfInterfaces(virConnectPtr conn)
{
    int count;
    struct interface_driver *driver = conn->interfacePrivateData;

    if (virConnectNumOfInterfacesEnsureACL(conn) < 0)
        return -1;

    interfaceDriverLock(driver);
    count = netcfConnectNumOfInterfacesImpl(conn,
                                            NETCF_IFACE_ACTIVE,
                                            virConnectNumOfInterfacesCheckACL);
    interfaceDriverUnlock(driver);
    return count;
}

static int netcfConnectListInterfaces(virConnectPtr conn, char **const names, int nnames)
{
    struct interface_driver *driver = conn->interfacePrivateData;
    int count;

    if (virConnectListInterfacesEnsureACL(conn) < 0)
        return -1;

    interfaceDriverLock(driver);
    count = netcfConnectListInterfacesImpl(conn,
                                           NETCF_IFACE_ACTIVE,
                                           names, nnames,
                                           virConnectListInterfacesCheckACL);
    interfaceDriverUnlock(driver);
    return count;

}

static int netcfConnectNumOfDefinedInterfaces(virConnectPtr conn)
{
    int count;
    struct interface_driver *driver = conn->interfacePrivateData;

    if (virConnectNumOfDefinedInterfacesEnsureACL(conn) < 0)
        return -1;

    interfaceDriverLock(driver);
    count = netcfConnectNumOfInterfacesImpl(conn,
                                            NETCF_IFACE_INACTIVE,
                                            virConnectNumOfDefinedInterfacesCheckACL);
    interfaceDriverUnlock(driver);
    return count;
}

static int netcfConnectListDefinedInterfaces(virConnectPtr conn, char **const names, int nnames)
{
    struct interface_driver *driver = conn->interfacePrivateData;
    int count;

    if (virConnectListDefinedInterfacesEnsureACL(conn) < 0)
        return -1;

    interfaceDriverLock(driver);
    count = netcfConnectListInterfacesImpl(conn,
                                           NETCF_IFACE_INACTIVE,
                                           names, nnames,
                                           virConnectListDefinedInterfacesCheckACL);
    interfaceDriverUnlock(driver);
    return count;

}

#define MATCH(FLAG) (flags & (FLAG))
static int
netcfConnectListAllInterfaces(virConnectPtr conn,
                              virInterfacePtr **ifaces,
                              unsigned int flags)
{
    struct interface_driver *driver = conn->interfacePrivateData;
    int count;
    size_t i;
    struct netcf_if *iface = NULL;
    virInterfacePtr *tmp_iface_objs = NULL;
    virInterfacePtr iface_obj = NULL;
    unsigned int status;
    int niface_objs = 0;
    int ret = -1;
    char **names = NULL;

    virCheckFlags(VIR_CONNECT_LIST_INTERFACES_FILTERS_ACTIVE, -1);

    if (virConnectListAllInterfacesEnsureACL(conn) < 0)
        return -1;

    interfaceDriverLock(driver);

    /* List all interfaces, in case of we might support new filter flags
     * except active|inactive in future.
     */
    count = ncf_num_of_interfaces(driver->netcf, NETCF_IFACE_ACTIVE |
                                  NETCF_IFACE_INACTIVE);
    if (count < 0) {
        const char *errmsg, *details;
        int errcode = ncf_error(driver->netcf, &errmsg, &details);
        virReportError(netcf_to_vir_err(errcode),
                       _("failed to get number of host interfaces: %s%s%s"),
                       errmsg, details ? " - " : "",
                       details ? details : "");
        goto cleanup;
    }

    if (count == 0) {
        ret = 0;
        goto cleanup;
    }

    if (VIR_ALLOC_N(names, count) < 0)
        goto cleanup;

    if ((count = ncf_list_interfaces(driver->netcf, count, names,
                                     NETCF_IFACE_ACTIVE |
                                     NETCF_IFACE_INACTIVE)) < 0) {
        const char *errmsg, *details;
        int errcode = ncf_error(driver->netcf, &errmsg, &details);
        virReportError(netcf_to_vir_err(errcode),
                       _("failed to list host interfaces: %s%s%s"),
                       errmsg, details ? " - " : "",
                       details ? details : "");
        goto cleanup;
    }

    if (ifaces && VIR_ALLOC_N(tmp_iface_objs, count + 1) < 0)
        goto cleanup;

    for (i = 0; i < count; i++) {
        virInterfaceDefPtr def;
        iface = ncf_lookup_by_name(driver->netcf, names[i]);
        if (!iface) {
            const char *errmsg, *details;
            int errcode = ncf_error(driver->netcf, &errmsg, &details);
            if (errcode != NETCF_NOERROR) {
                virReportError(netcf_to_vir_err(errcode),
                               _("couldn't find interface named '%s': %s%s%s"),
                               names[i], errmsg,
                               details ? " - " : "", details ? details : "");
                goto cleanup;
            } else {
                /* Ignore the NETCF_NOERROR, as the interface is very likely
                 * deleted by other management apps (e.g. virt-manager).
                 */
                VIR_WARN("couldn't find interface named '%s', might be "
                         "deleted by other process", names[i]);
                continue;
            }
        }

        if (ncf_if_status(iface, &status) < 0) {
            const char *errmsg, *details;
            int errcode = ncf_error(driver->netcf, &errmsg, &details);
            virReportError(netcf_to_vir_err(errcode),
                           _("failed to get status of interface %s: %s%s%s"),
                           names[i], errmsg, details ? " - " : "",
                           details ? details : "");
            goto cleanup;
        }

        if (!(def = netcfGetMinimalDefForDevice(iface)))
            goto cleanup;

        if (!virConnectListAllInterfacesCheckACL(conn, def)) {
            ncf_if_free(iface);
            iface = NULL;
            virInterfaceDefFree(def);
            continue;
        }
        virInterfaceDefFree(def);

        /* XXX: Filter the result, need to be split once new filter flags
         * except active|inactive are supported.
         */
        if (MATCH(VIR_CONNECT_LIST_INTERFACES_FILTERS_ACTIVE) &&
            !((MATCH(VIR_CONNECT_LIST_INTERFACES_ACTIVE) &&
               (status & NETCF_IFACE_ACTIVE)) ||
              (MATCH(VIR_CONNECT_LIST_INTERFACES_INACTIVE) &&
               (status & NETCF_IFACE_INACTIVE)))) {
            ncf_if_free(iface);
            iface = NULL;
            continue;
        }

        if (ifaces) {
            iface_obj = virGetInterface(conn, ncf_if_name(iface),
                                        ncf_if_mac_string(iface));
            tmp_iface_objs[niface_objs++] = iface_obj;
        }

        ncf_if_free(iface);
        iface = NULL;
    }

    if (tmp_iface_objs) {
        /* trim the array to the final size */
        ignore_value(VIR_REALLOC_N(tmp_iface_objs, niface_objs + 1));
        *ifaces = tmp_iface_objs;
        tmp_iface_objs = NULL;
    }

    ret = niface_objs;

cleanup:
    ncf_if_free(iface);

    if (names && count > 0)
        for (i = 0; i < count; i++)
            VIR_FREE(names[i]);
    VIR_FREE(names);

    if (tmp_iface_objs) {
        for (i = 0; i < niface_objs; i++) {
            if (tmp_iface_objs[i])
                virInterfaceFree(tmp_iface_objs[i]);
        }
        VIR_FREE(tmp_iface_objs);
    }

    interfaceDriverUnlock(driver);
    return ret;
}


static virInterfacePtr netcfInterfaceLookupByName(virConnectPtr conn,
                                                  const char *name)
{
    struct interface_driver *driver = conn->interfacePrivateData;
    struct netcf_if *iface;
    virInterfacePtr ret = NULL;
    virInterfaceDefPtr def = NULL;

    interfaceDriverLock(driver);
    iface = ncf_lookup_by_name(driver->netcf, name);
    if (!iface) {
        const char *errmsg, *details;
        int errcode = ncf_error(driver->netcf, &errmsg, &details);
        if (errcode != NETCF_NOERROR) {
            virReportError(netcf_to_vir_err(errcode),
                           _("couldn't find interface named '%s': %s%s%s"),
                           name, errmsg,
                           details ? " - " : "", details ? details : "");
        } else {
            virReportError(VIR_ERR_NO_INTERFACE,
                           _("couldn't find interface named '%s'"), name);
        }
        goto cleanup;
    }

    if (!(def = netcfGetMinimalDefForDevice(iface)))
        goto cleanup;

    if (virInterfaceLookupByNameEnsureACL(conn, def) < 0)
       goto cleanup;

    ret = virGetInterface(conn, ncf_if_name(iface), ncf_if_mac_string(iface));

cleanup:
    ncf_if_free(iface);
    virInterfaceDefFree(def);
    interfaceDriverUnlock(driver);
    return ret;
}

static virInterfacePtr netcfInterfaceLookupByMACString(virConnectPtr conn,
                                                       const char *macstr)
{
    struct interface_driver *driver = conn->interfacePrivateData;
    struct netcf_if *iface;
    int niface;
    virInterfacePtr ret = NULL;
    virInterfaceDefPtr def = NULL;

    interfaceDriverLock(driver);
    niface = ncf_lookup_by_mac_string(driver->netcf, macstr, 1, &iface);

    if (niface < 0) {
        const char *errmsg, *details;
        int errcode = ncf_error(driver->netcf, &errmsg, &details);
        virReportError(netcf_to_vir_err(errcode),
                       _("couldn't find interface with MAC address '%s': %s%s%s"),
                       macstr, errmsg, details ? " - " : "",
                       details ? details : "");
        goto cleanup;
    }
    if (niface == 0) {
        virReportError(VIR_ERR_NO_INTERFACE,
                       _("couldn't find interface with MAC address '%s'"),
                       macstr);
        goto cleanup;
    }
    if (niface > 1) {
        virReportError(VIR_ERR_MULTIPLE_INTERFACES,
                       "%s", _("multiple interfaces with matching MAC address"));
        goto cleanup;
    }


    if (!(def = netcfGetMinimalDefForDevice(iface)))
        goto cleanup;

    if (virInterfaceLookupByMACStringEnsureACL(conn, def) < 0)
       goto cleanup;

    ret = virGetInterface(conn, ncf_if_name(iface), ncf_if_mac_string(iface));

cleanup:
    ncf_if_free(iface);
    virInterfaceDefFree(def);
    interfaceDriverUnlock(driver);
    return ret;
}

static char *netcfInterfaceGetXMLDesc(virInterfacePtr ifinfo,
                                      unsigned int flags)
{
    struct interface_driver *driver = ifinfo->conn->interfacePrivateData;
    struct netcf_if *iface = NULL;
    char *xmlstr = NULL;
    virInterfaceDefPtr ifacedef = NULL;
    char *ret = NULL;

    virCheckFlags(VIR_INTERFACE_XML_INACTIVE, NULL);

    interfaceDriverLock(driver);

    iface = interfaceDriverGetNetcfIF(driver->netcf, ifinfo);
    if (!iface) {
        /* helper already reported error */
        goto cleanup;
    }

    if ((flags & VIR_INTERFACE_XML_INACTIVE)) {
        xmlstr = ncf_if_xml_desc(iface);
    } else {
        xmlstr = ncf_if_xml_state(iface);
    }
    if (!xmlstr) {
        const char *errmsg, *details;
        int errcode = ncf_error(driver->netcf, &errmsg, &details);
        virReportError(netcf_to_vir_err(errcode),
                       _("could not get interface XML description: %s%s%s"),
                       errmsg, details ? " - " : "",
                       details ? details : "");
        goto cleanup;
    }

    ifacedef = virInterfaceDefParseString(xmlstr);
    if (!ifacedef) {
        /* error was already reported */
        goto cleanup;
    }

    if (virInterfaceGetXMLDescEnsureACL(ifinfo->conn, ifacedef) < 0)
        goto cleanup;

    ret = virInterfaceDefFormat(ifacedef);
    if (!ret) {
        /* error was already reported */
        goto cleanup;
    }

cleanup:
    ncf_if_free(iface);
    VIR_FREE(xmlstr);
    virInterfaceDefFree(ifacedef);
    interfaceDriverUnlock(driver);
    return ret;
}

static virInterfacePtr netcfInterfaceDefineXML(virConnectPtr conn,
                                               const char *xml,
                                               unsigned int flags)
{
    struct interface_driver *driver = conn->interfacePrivateData;
    struct netcf_if *iface = NULL;
    char *xmlstr = NULL;
    virInterfaceDefPtr ifacedef = NULL;
    virInterfacePtr ret = NULL;

    virCheckFlags(0, NULL);

    interfaceDriverLock(driver);

    ifacedef = virInterfaceDefParseString(xml);
    if (!ifacedef) {
        /* error was already reported */
        goto cleanup;
    }

    if (virInterfaceDefineXMLEnsureACL(conn, ifacedef) < 0)
        goto cleanup;

    xmlstr = virInterfaceDefFormat(ifacedef);
    if (!xmlstr) {
        /* error was already reported */
        goto cleanup;
    }

    iface = ncf_define(driver->netcf, xmlstr);
    if (!iface) {
        const char *errmsg, *details;
        int errcode = ncf_error(driver->netcf, &errmsg, &details);
        virReportError(netcf_to_vir_err(errcode),
                       _("could not get interface XML description: %s%s%s"),
                       errmsg, details ? " - " : "",
                       details ? details : "");
        goto cleanup;
    }

    ret = virGetInterface(conn, ncf_if_name(iface), ncf_if_mac_string(iface));

cleanup:
    ncf_if_free(iface);
    VIR_FREE(xmlstr);
    virInterfaceDefFree(ifacedef);
    interfaceDriverUnlock(driver);
    return ret;
}

static int netcfInterfaceUndefine(virInterfacePtr ifinfo) {
    struct interface_driver *driver = ifinfo->conn->interfacePrivateData;
    struct netcf_if *iface = NULL;
    virInterfaceDefPtr def = NULL;
    int ret = -1;

    interfaceDriverLock(driver);

    iface = interfaceDriverGetNetcfIF(driver->netcf, ifinfo);
    if (!iface) {
        /* helper already reported error */
        goto cleanup;
    }


    if (!(def = netcfGetMinimalDefForDevice(iface)))
        goto cleanup;

    if (virInterfaceUndefineEnsureACL(ifinfo->conn, def) < 0)
       goto cleanup;

    ret = ncf_if_undefine(iface);
    if (ret < 0) {
        const char *errmsg, *details;
        int errcode = ncf_error(driver->netcf, &errmsg, &details);
        virReportError(netcf_to_vir_err(errcode),
                       _("failed to undefine interface %s: %s%s%s"),
                       ifinfo->name, errmsg, details ? " - " : "",
                       details ? details : "");
        goto cleanup;
    }

cleanup:
    ncf_if_free(iface);
    virInterfaceDefFree(def);
    interfaceDriverUnlock(driver);
    return ret;
}

static int netcfInterfaceCreate(virInterfacePtr ifinfo,
                                unsigned int flags)
{
    struct interface_driver *driver = ifinfo->conn->interfacePrivateData;
    struct netcf_if *iface = NULL;
    virInterfaceDefPtr def = NULL;
    int ret = -1;

    virCheckFlags(0, -1);

    interfaceDriverLock(driver);

    iface = interfaceDriverGetNetcfIF(driver->netcf, ifinfo);
    if (!iface) {
        /* helper already reported error */
        goto cleanup;
    }


    if (!(def = netcfGetMinimalDefForDevice(iface)))
        goto cleanup;

    if (virInterfaceCreateEnsureACL(ifinfo->conn, def) < 0)
       goto cleanup;

    ret = ncf_if_up(iface);
    if (ret < 0) {
        const char *errmsg, *details;
        int errcode = ncf_error(driver->netcf, &errmsg, &details);
        virReportError(netcf_to_vir_err(errcode),
                       _("failed to create (start) interface %s: %s%s%s"),
                       ifinfo->name, errmsg, details ? " - " : "",
                       details ? details : "");
        goto cleanup;
    }

cleanup:
    ncf_if_free(iface);
    virInterfaceDefFree(def);
    interfaceDriverUnlock(driver);
    return ret;
}

static int netcfInterfaceDestroy(virInterfacePtr ifinfo,
                                 unsigned int flags)
{
    struct interface_driver *driver = ifinfo->conn->interfacePrivateData;
    struct netcf_if *iface = NULL;
    virInterfaceDefPtr def = NULL;
    int ret = -1;

    virCheckFlags(0, -1);

    interfaceDriverLock(driver);

    iface = interfaceDriverGetNetcfIF(driver->netcf, ifinfo);
    if (!iface) {
        /* helper already reported error */
        goto cleanup;
    }


    if (!(def = netcfGetMinimalDefForDevice(iface)))
        goto cleanup;

    if (virInterfaceDestroyEnsureACL(ifinfo->conn, def) < 0)
       goto cleanup;

    ret = ncf_if_down(iface);
    if (ret < 0) {
        const char *errmsg, *details;
        int errcode = ncf_error(driver->netcf, &errmsg, &details);
        virReportError(netcf_to_vir_err(errcode),
                       _("failed to destroy (stop) interface %s: %s%s%s"),
                       ifinfo->name, errmsg, details ? " - " : "",
                       details ? details : "");
        goto cleanup;
    }

cleanup:
    ncf_if_free(iface);
    virInterfaceDefFree(def);
    interfaceDriverUnlock(driver);
    return ret;
}

static int netcfInterfaceIsActive(virInterfacePtr ifinfo)
{
    struct interface_driver *driver = ifinfo->conn->interfacePrivateData;
    struct netcf_if *iface = NULL;
    unsigned int flags = 0;
    virInterfaceDefPtr def = NULL;
    int ret = -1;

    interfaceDriverLock(driver);

    iface = interfaceDriverGetNetcfIF(driver->netcf, ifinfo);
    if (!iface) {
        /* helper already reported error */
        goto cleanup;
    }


    if (!(def = netcfGetMinimalDefForDevice(iface)))
        goto cleanup;

    if (virInterfaceIsActiveEnsureACL(ifinfo->conn, def) < 0)
       goto cleanup;

    if (ncf_if_status(iface, &flags) < 0) {
        const char *errmsg, *details;
        int errcode = ncf_error(driver->netcf, &errmsg, &details);
        virReportError(netcf_to_vir_err(errcode),
                       _("failed to get status of interface %s: %s%s%s"),
                       ifinfo->name, errmsg, details ? " - " : "",
                       details ? details : "");
        goto cleanup;
    }

    ret = flags & NETCF_IFACE_ACTIVE ? 1 : 0;

cleanup:
    ncf_if_free(iface);
    virInterfaceDefFree(def);
    interfaceDriverUnlock(driver);
    return ret;
}

#ifdef HAVE_NETCF_TRANSACTIONS
static int netcfInterfaceChangeBegin(virConnectPtr conn, unsigned int flags)
{
    struct interface_driver *driver = conn->interfacePrivateData;
    int ret;

    virCheckFlags(0, -1); /* currently flags must be 0 */

    if (virInterfaceChangeBeginEnsureACL(conn) < 0)
        return -1;

    interfaceDriverLock(driver);

    ret = ncf_change_begin(driver->netcf, 0);
    if (ret < 0) {
        const char *errmsg, *details;
        int errcode = ncf_error(driver->netcf, &errmsg, &details);
        virReportError(netcf_to_vir_err(errcode),
                       _("failed to begin transaction: %s%s%s"),
                       errmsg, details ? " - " : "",
                       details ? details : "");
    }

    interfaceDriverUnlock(driver);
    return ret;
}

static int netcfInterfaceChangeCommit(virConnectPtr conn, unsigned int flags)
{
    struct interface_driver *driver = conn->interfacePrivateData;
    int ret;

    virCheckFlags(0, -1); /* currently flags must be 0 */

    if (virInterfaceChangeCommitEnsureACL(conn) < 0)
        return -1;

    interfaceDriverLock(driver);

    ret = ncf_change_commit(driver->netcf, 0);
    if (ret < 0) {
        const char *errmsg, *details;
        int errcode = ncf_error(driver->netcf, &errmsg, &details);
        virReportError(netcf_to_vir_err(errcode),
                       _("failed to commit transaction: %s%s%s"),
                       errmsg, details ? " - " : "",
                       details ? details : "");
    }

    interfaceDriverUnlock(driver);
    return ret;
}

static int netcfInterfaceChangeRollback(virConnectPtr conn, unsigned int flags)
{
    struct interface_driver *driver = conn->interfacePrivateData;
    int ret;

    virCheckFlags(0, -1); /* currently flags must be 0 */

    if (virInterfaceChangeRollbackEnsureACL(conn) < 0)
        return -1;

    interfaceDriverLock(driver);

    ret = ncf_change_rollback(driver->netcf, 0);
    if (ret < 0) {
        const char *errmsg, *details;
        int errcode = ncf_error(driver->netcf, &errmsg, &details);
        virReportError(netcf_to_vir_err(errcode),
                       _("failed to rollback transaction: %s%s%s"),
                       errmsg, details ? " - " : "",
                       details ? details : "");
    }

    interfaceDriverUnlock(driver);
    return ret;
}
#endif /* HAVE_NETCF_TRANSACTIONS */

static virInterfaceDriver interfaceDriver = {
    "netcf",
    .interfaceOpen = netcfInterfaceOpen, /* 0.7.0 */
    .interfaceClose = netcfInterfaceClose, /* 0.7.0 */
    .connectNumOfInterfaces = netcfConnectNumOfInterfaces, /* 0.7.0 */
    .connectListInterfaces = netcfConnectListInterfaces, /* 0.7.0 */
    .connectNumOfDefinedInterfaces = netcfConnectNumOfDefinedInterfaces, /* 0.7.0 */
    .connectListDefinedInterfaces = netcfConnectListDefinedInterfaces, /* 0.7.0 */
    .connectListAllInterfaces = netcfConnectListAllInterfaces, /* 0.10.2 */
    .interfaceLookupByName = netcfInterfaceLookupByName, /* 0.7.0 */
    .interfaceLookupByMACString = netcfInterfaceLookupByMACString, /* 0.7.0 */
    .interfaceGetXMLDesc = netcfInterfaceGetXMLDesc, /* 0.7.0 */
    .interfaceDefineXML = netcfInterfaceDefineXML, /* 0.7.0 */
    .interfaceUndefine = netcfInterfaceUndefine, /* 0.7.0 */
    .interfaceCreate = netcfInterfaceCreate, /* 0.7.0 */
    .interfaceDestroy = netcfInterfaceDestroy, /* 0.7.0 */
    .interfaceIsActive = netcfInterfaceIsActive, /* 0.7.3 */
#ifdef HAVE_NETCF_TRANSACTIONS
    .interfaceChangeBegin = netcfInterfaceChangeBegin, /* 0.9.2 */
    .interfaceChangeCommit = netcfInterfaceChangeCommit, /* 0.9.2 */
    .interfaceChangeRollback = netcfInterfaceChangeRollback, /* 0.9.2 */
#endif /* HAVE_NETCF_TRANSACTIONS */
};

int netcfIfaceRegister(void) {
    if (virRegisterInterfaceDriver(&interfaceDriver) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to register netcf interface driver"));
        return -1;
    }
    return 0;
}
