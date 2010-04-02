/*
 * interface_driver.c: backend driver methods to handle physical
 *                     interface configuration using the netcf library.
 *
 * Copyright (C) 2006-2010 Red Hat, Inc.
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
 * Author: Laine Stump <laine@redhat.com>
 */

#include <config.h>

#include <netcf.h>

#include "virterror_internal.h"
#include "datatypes.h"
#include "netcf_driver.h"
#include "interface_conf.h"
#include "memory.h"

#define VIR_FROM_THIS VIR_FROM_INTERFACE

#define interfaceReportError(code, ...)                               \
    virReportErrorHelper(NULL, VIR_FROM_THIS, code, __FILE__,         \
                         __FUNCTION__, __LINE__, __VA_ARGS__)

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
            return(2);
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
            interfaceReportError(netcf_to_vir_err(errcode),
                                 "couldn't find interface named '%s' (netcf: %s - %s)",
                                ifinfo->name, errmsg, details ? details : "");
        } else {
            interfaceReportError(VIR_ERR_NO_INTERFACE,
                                 "couldn't find interface named '%s'", ifinfo->name);
        }
    }
    return iface;
}

static virDrvOpenStatus interfaceOpenInterface(virConnectPtr conn,
                                               virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                                               int flags ATTRIBUTE_UNUSED)
{
    struct interface_driver *driverState;

    if (VIR_ALLOC(driverState) < 0)
    {
        virReportOOMError();
        goto alloc_error;
    }

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
    virMutexDestroy (&driverState->lock);
mutex_error:
    VIR_FREE(driverState);
alloc_error:
    return VIR_DRV_OPEN_ERROR;
}

static int interfaceCloseInterface(virConnectPtr conn)
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

static int interfaceNumOfInterfaces(virConnectPtr conn)
{
    int count;
    struct interface_driver *driver = conn->interfacePrivateData;

    interfaceDriverLock(driver);
    count = ncf_num_of_interfaces(driver->netcf, NETCF_IFACE_ACTIVE);
    if (count < 0) {
        const char *errmsg, *details;
        int errcode = ncf_error(driver->netcf, &errmsg, &details);
        interfaceReportError(netcf_to_vir_err(errcode),
                             "%s (netcf: %s - %s)",
                             _("failed to get number of interfaces on host"),
                            errmsg, details ? details : "");
    }

    interfaceDriverUnlock(driver);
    return count;
}

static int interfaceListInterfaces(virConnectPtr conn, char **const names, int nnames)
{
    struct interface_driver *driver = conn->interfacePrivateData;
    int count;

    interfaceDriverLock(driver);

    count = ncf_list_interfaces(driver->netcf, nnames, names, NETCF_IFACE_ACTIVE);
    if (count < 0) {
        const char *errmsg, *details;
        int errcode = ncf_error(driver->netcf, &errmsg, &details);
        interfaceReportError(netcf_to_vir_err(errcode),
                             "%s (netcf: %s - %s)",
                             _("failed to list host interfaces"),
                            errmsg, details ? details : "");
    }

    interfaceDriverUnlock(driver);
    return count;

}

static int interfaceNumOfDefinedInterfaces(virConnectPtr conn)
{
    int count;
    struct interface_driver *driver = conn->interfacePrivateData;

    interfaceDriverLock(driver);
    count = ncf_num_of_interfaces(driver->netcf, NETCF_IFACE_INACTIVE);
    if (count < 0) {
        const char *errmsg, *details;
        int errcode = ncf_error(driver->netcf, &errmsg, &details);
        interfaceReportError(netcf_to_vir_err(errcode),
                             "%s (netcf: %s - %s)",
                             _("failed to get number of defined interfaces on host"),
                            errmsg, details ? details : "");
    }

    interfaceDriverUnlock(driver);
    return count;
}

static int interfaceListDefinedInterfaces(virConnectPtr conn, char **const names, int nnames)
{
    struct interface_driver *driver = conn->interfacePrivateData;
    int count;

    interfaceDriverLock(driver);

    count = ncf_list_interfaces(driver->netcf, nnames, names, NETCF_IFACE_INACTIVE);
    if (count < 0) {
        const char *errmsg, *details;
        int errcode = ncf_error(driver->netcf, &errmsg, &details);
        interfaceReportError(netcf_to_vir_err(errcode),
                             "%s (netcf: %s - %s)",
                             _("failed to list host defined interfaces"),
                            errmsg, details ? details : "");
    }

    interfaceDriverUnlock(driver);
    return count;

}

static virInterfacePtr interfaceLookupByName(virConnectPtr conn,
                                             const char *name)
{
    struct interface_driver *driver = conn->interfacePrivateData;
    struct netcf_if *iface;
    virInterfacePtr ret = NULL;

    interfaceDriverLock(driver);
    iface = ncf_lookup_by_name(driver->netcf, name);
    if (!iface) {
        const char *errmsg, *details;
        int errcode = ncf_error(driver->netcf, &errmsg, &details);
        if (errcode != NETCF_NOERROR) {
            interfaceReportError(netcf_to_vir_err(errcode),
                                 "couldn't find interface named '%s' (netcf: %s - %s)",
                                 name, errmsg, details ? details : "");
        } else {
            interfaceReportError(VIR_ERR_NO_INTERFACE,
                                 "couldn't find interface named '%s'", name);
        }
        goto cleanup;
    }

    ret = virGetInterface(conn, ncf_if_name(iface), ncf_if_mac_string(iface));

cleanup:
    ncf_if_free(iface);
    interfaceDriverUnlock(driver);
    return ret;
}

static virInterfacePtr interfaceLookupByMACString(virConnectPtr conn,
                                                  const char *macstr)
{
    struct interface_driver *driver = conn->interfacePrivateData;
    struct netcf_if *iface;
    int niface;
    virInterfacePtr ret = NULL;

    interfaceDriverLock(driver);
    niface = ncf_lookup_by_mac_string(driver->netcf, macstr, 1, &iface);

    if (niface < 0) {
        const char *errmsg, *details;
        int errcode = ncf_error(driver->netcf, &errmsg, &details);
        interfaceReportError(netcf_to_vir_err(errcode),
                             "couldn't find interface with MAC address '%s' (netcf: %s - %s)",
                             macstr, errmsg, details ? details : "");
        goto cleanup;
    }
    if (niface == 0) {
        interfaceReportError(VIR_ERR_NO_INTERFACE,
                             "couldn't find interface with MAC address '%s'",
                             macstr);
        goto cleanup;
    }
    if (niface > 1) {
        interfaceReportError(VIR_ERR_MULTIPLE_INTERFACES,
                             "%s", _("multiple interfaces with matching MAC address"));
        goto cleanup;
    }

    ret = virGetInterface(conn, ncf_if_name(iface), ncf_if_mac_string(iface));

cleanup:
    ncf_if_free(iface);
    interfaceDriverUnlock(driver);
    return ret;
}

static char *interfaceGetXMLDesc(virInterfacePtr ifinfo,
                                 unsigned int flags)
{
    struct interface_driver *driver = ifinfo->conn->interfacePrivateData;
    struct netcf_if *iface = NULL;
    char *xmlstr = NULL;
    virInterfaceDefPtr ifacedef = NULL;
    char *ret = NULL;

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
        interfaceReportError(netcf_to_vir_err(errcode),
                             "could not get interface XML description (netcf: %s - %s)",
                            errmsg, details ? details : "");
        goto cleanup;
    }

    ifacedef = virInterfaceDefParseString(xmlstr);
    if (!ifacedef) {
        /* error was already reported */
        goto cleanup;
    }

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

static virInterfacePtr interfaceDefineXML(virConnectPtr conn,
                                          const char *xml,
                                          unsigned int flags ATTRIBUTE_UNUSED)
{
    struct interface_driver *driver = conn->interfacePrivateData;
    struct netcf_if *iface = NULL;
    char *xmlstr = NULL;
    virInterfaceDefPtr ifacedef = NULL;
    virInterfacePtr ret = NULL;

    interfaceDriverLock(driver);

    ifacedef = virInterfaceDefParseString(xml);
    if (!ifacedef) {
        /* error was already reported */
        goto cleanup;
    }

    xmlstr = virInterfaceDefFormat(ifacedef);
    if (!xmlstr) {
        /* error was already reported */
        goto cleanup;
    }

    iface = ncf_define(driver->netcf, xmlstr);
    if (!iface) {
        const char *errmsg, *details;
        int errcode = ncf_error(driver->netcf, &errmsg, &details);
        interfaceReportError(netcf_to_vir_err(errcode),
                             "could not get interface XML description (netcf: %s - %s)",
                            errmsg, details ? details : "");
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

static int interfaceUndefine(virInterfacePtr ifinfo) {
    struct interface_driver *driver = ifinfo->conn->interfacePrivateData;
    struct netcf_if *iface = NULL;
    int ret = -1;

    interfaceDriverLock(driver);

    iface = interfaceDriverGetNetcfIF(driver->netcf, ifinfo);
    if (!iface) {
        /* helper already reported error */
        goto cleanup;
    }

    ret = ncf_if_undefine(iface);
    if (ret < 0) {
        const char *errmsg, *details;
        int errcode = ncf_error(driver->netcf, &errmsg, &details);
        interfaceReportError(netcf_to_vir_err(errcode),
                             "failed to undefine interface %s (netcf: %s - %s)",
                             ifinfo->name, errmsg, details ? details : "");
        goto cleanup;
    }

cleanup:
    ncf_if_free(iface);
    interfaceDriverUnlock(driver);
    return ret;
}

static int interfaceCreate(virInterfacePtr ifinfo,
                           unsigned int flags ATTRIBUTE_UNUSED)
{
    struct interface_driver *driver = ifinfo->conn->interfacePrivateData;
    struct netcf_if *iface = NULL;
    int ret = -1;

    interfaceDriverLock(driver);

    iface = interfaceDriverGetNetcfIF(driver->netcf, ifinfo);
    if (!iface) {
        /* helper already reported error */
        goto cleanup;
    }

    ret = ncf_if_up(iface);
    if (ret < 0) {
        const char *errmsg, *details;
        int errcode = ncf_error(driver->netcf, &errmsg, &details);
        interfaceReportError(netcf_to_vir_err(errcode),
                             "failed to create (start) interface %s (netcf: %s - %s)",
                             ifinfo->name, errmsg, details ? details : "");
        goto cleanup;
    }

cleanup:
    ncf_if_free(iface);
    interfaceDriverUnlock(driver);
    return ret;
}

static int interfaceDestroy(virInterfacePtr ifinfo,
                            unsigned int flags ATTRIBUTE_UNUSED)
{
    struct interface_driver *driver = ifinfo->conn->interfacePrivateData;
    struct netcf_if *iface = NULL;
    int ret = -1;

    interfaceDriverLock(driver);

    iface = interfaceDriverGetNetcfIF(driver->netcf, ifinfo);
    if (!iface) {
        /* helper already reported error */
        goto cleanup;
    }

    ret = ncf_if_down(iface);
    if (ret < 0) {
        const char *errmsg, *details;
        int errcode = ncf_error(driver->netcf, &errmsg, &details);
        interfaceReportError(netcf_to_vir_err(errcode),
                             "failed to destroy (stop) interface %s (netcf: %s - %s)",
                             ifinfo->name, errmsg, details ? details : "");
        goto cleanup;
    }

cleanup:
    ncf_if_free(iface);
    interfaceDriverUnlock(driver);
    return ret;
}

static virInterfaceDriver interfaceDriver = {
    "Interface",
    interfaceOpenInterface,          /* open */
    interfaceCloseInterface,         /* close */
    interfaceNumOfInterfaces,        /* numOfInterfaces */
    interfaceListInterfaces,         /* listInterfaces */
    interfaceNumOfDefinedInterfaces, /* numOfInterfaces */
    interfaceListDefinedInterfaces,  /* listInterfaces */
    interfaceLookupByName,           /* interfaceLookupByName */
    interfaceLookupByMACString,      /* interfaceLookupByMACSTring */
    interfaceGetXMLDesc,             /* interfaceGetXMLDesc */
    interfaceDefineXML,              /* interfaceDefineXML */
    interfaceUndefine,               /* interfaceUndefine */
    interfaceCreate,                 /* interfaceCreate */
    interfaceDestroy,                /* interfaceDestroy */
    NULL,                            /* interfaceIsActive */
};

int interfaceRegister(void) {
    virRegisterInterfaceDriver(&interfaceDriver);
    return 0;
}
