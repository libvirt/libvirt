/*
 * hyperv_driver.c: core driver functions for managing Microsoft Hyper-V hosts
 *
 * Copyright (C) 2011-2013 Matthias Bolte <matthias.bolte@googlemail.com>
 * Copyright (C) 2009 Michael Sievers <msievers83@googlemail.com>
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

#include "internal.h"
#include "datatypes.h"
#include "virdomainobjlist.h"
#include "virauth.h"
#include "viralloc.h"
#include "virlog.h"
#include "viruuid.h"
#include "virutil.h"
#include "hyperv_driver.h"
#include "hyperv_private.h"
#include "hyperv_util.h"
#include "hyperv_wmi.h"
#include "virstring.h"
#include "virkeycode.h"
#include "domain_conf.h"

#define VIR_FROM_THIS VIR_FROM_HYPERV

VIR_LOG_INIT("hyperv.hyperv_driver");

/*
 * WMI utility functions
 *
 * wrapper functions for commonly-accessed WMI objects and interfaces.
 */

/**
 * hypervGetWmiClass:
 * @type: the type of the class being retrieved from WMI
 * @class: double pointer where the class data will be stored
 *
 * Retrieve one or more classes from WMI.
 *
 * The following variables must exist in the caller:
 *   1. hypervPrivate *priv
 *   2. virBuffer query
 */
#define hypervGetWmiClass(type, class) \
    hypervGetWmiClassList(priv, type ## _WmiInfo, &query, (hypervObject **)class)

static int
hypervGetProcessorsByName(hypervPrivate *priv, const char *name,
                          Win32_Processor **processorList)
{
    g_auto(virBuffer) query = VIR_BUFFER_INITIALIZER;
    virBufferEscapeSQL(&query,
                       "ASSOCIATORS OF {Win32_ComputerSystem.Name=\"%s\"} "
                       "WHERE AssocClass = Win32_ComputerSystemProcessor "
                       "ResultClass = Win32_Processor",
                       name);

    if (hypervGetWmiClass(Win32_Processor, processorList) < 0)
        return -1;

    if (!processorList) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not look up processor(s) on '%s'"),
                       name);
        return -1;
    }

    return 0;
}


static int
hypervGetActiveVirtualSystemList(hypervPrivate *priv,
                                 Msvm_ComputerSystem **computerSystemList)
{
    g_auto(virBuffer) query = { g_string_new(MSVM_COMPUTERSYSTEM_WQL_SELECT
                                             "WHERE " MSVM_COMPUTERSYSTEM_WQL_VIRTUAL
                                             "AND " MSVM_COMPUTERSYSTEM_WQL_ACTIVE), 0 };

    if (hypervGetWmiClass(Msvm_ComputerSystem, computerSystemList) < 0)
        return -1;

    if (!*computerSystemList) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not look up active virtual machines"));
        return -1;
    }

    return 0;
}


/* gets all the vms including the ones that are marked inactive. */
static int
hypervGetInactiveVirtualSystemList(hypervPrivate *priv,
                                   Msvm_ComputerSystem **computerSystemList)
{
    g_auto(virBuffer) query = { g_string_new(MSVM_COMPUTERSYSTEM_WQL_SELECT
                                             "WHERE " MSVM_COMPUTERSYSTEM_WQL_VIRTUAL
                                             "AND " MSVM_COMPUTERSYSTEM_WQL_INACTIVE), 0 };

    if (hypervGetWmiClass(Msvm_ComputerSystem, computerSystemList) < 0)
        return -1;

    if (!*computerSystemList) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not look up inactive virtual machines"));
        return -1;
    }

    return 0;
}


static int
hypervGetPhysicalSystemList(hypervPrivate *priv,
                            Win32_ComputerSystem **computerSystemList)
{
    g_auto(virBuffer) query = { g_string_new(WIN32_COMPUTERSYSTEM_WQL_SELECT), 0 };

    if (hypervGetWmiClass(Win32_ComputerSystem, computerSystemList) < 0)
        return -1;

    if (!*computerSystemList) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not look up Win32_ComputerSystem"));
        return -1;
    }

    return 0;
}


static int
hypervGetVirtualSystemByID(hypervPrivate *priv, int id,
                           Msvm_ComputerSystem **computerSystemList)
{
    g_auto(virBuffer) query = VIR_BUFFER_INITIALIZER;
    virBufferAsprintf(&query,
                      MSVM_COMPUTERSYSTEM_WQL_SELECT
                      "WHERE " MSVM_COMPUTERSYSTEM_WQL_VIRTUAL
                      "AND ProcessID = %d",
                      id);

    if (hypervGetWmiClass(Msvm_ComputerSystem, computerSystemList) < 0)
        return -1;

    if (*computerSystemList == NULL) {
        virReportError(VIR_ERR_NO_DOMAIN, _("No domain with ID %d"), id);
        return -1;
    }

    return 0;
}


static int
hypervGetVirtualSystemByUUID(hypervPrivate *priv, const char *uuid,
                             Msvm_ComputerSystem **computerSystemList)
{
    g_auto(virBuffer) query = VIR_BUFFER_INITIALIZER;
    virBufferEscapeSQL(&query,
                       MSVM_COMPUTERSYSTEM_WQL_SELECT
                       "WHERE " MSVM_COMPUTERSYSTEM_WQL_VIRTUAL
                       "AND Name = \"%s\"",
                       uuid);

    if (hypervGetWmiClass(Msvm_ComputerSystem, computerSystemList) < 0)
        return -1;

    if (*computerSystemList == NULL) {
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("No domain with UUID %s"), uuid);
        return -1;
    }

    return 0;
}


static int
hypervGetVirtualSystemByName(hypervPrivate *priv, const char *name,
                             Msvm_ComputerSystem **computerSystemList)
{
    g_auto(virBuffer) query = VIR_BUFFER_INITIALIZER;
    virBufferEscapeSQL(&query,
                       MSVM_COMPUTERSYSTEM_WQL_SELECT
                       "WHERE " MSVM_COMPUTERSYSTEM_WQL_VIRTUAL
                       "AND ElementName = \"%s\"",
                       name);

    if (hypervGetWmiClass(Msvm_ComputerSystem, computerSystemList) < 0)
        return -1;

    if (*computerSystemList == NULL) {
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("No domain with name %s"), name);
        return -1;
    }

    return 0;
}


static int
hypervGetVSSDFromUUID(hypervPrivate *priv, const char *uuid,
                      Msvm_VirtualSystemSettingData **data)
{
    g_auto(virBuffer) query = VIR_BUFFER_INITIALIZER;
    virBufferEscapeSQL(&query,
                       "ASSOCIATORS OF {Msvm_ComputerSystem.CreationClassName=\"Msvm_ComputerSystem\",Name=\"%s\"} "
                       "WHERE AssocClass = Msvm_SettingsDefineState "
                       "ResultClass = Msvm_VirtualSystemSettingData",
                       uuid);

    if (hypervGetWmiClass(Msvm_VirtualSystemSettingData, data) < 0)
        return -1;

    if (!*data) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not look up virtual system setting data with UUID '%s'"),
                       uuid);
        return -1;
    }

    return 0;
}


static int
hypervGetProcSDByVSSDInstanceId(hypervPrivate *priv, const char *id,
                                Msvm_ProcessorSettingData **data)
{
    g_auto(virBuffer) query = VIR_BUFFER_INITIALIZER;
    virBufferEscapeSQL(&query,
                       "ASSOCIATORS OF {Msvm_VirtualSystemSettingData.InstanceID=\"%s\"} "
                       "WHERE AssocClass = Msvm_VirtualSystemSettingDataComponent "
                       "ResultClass = Msvm_ProcessorSettingData",
                       id);

    if (hypervGetWmiClass(Msvm_ProcessorSettingData, data) < 0)
        return -1;

    if (!*data) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not look up processor setting data with virtual system instance ID '%s'"),
                       id);
        return -1;
    }

    return 0;
}


static int
hypervGetMemSDByVSSDInstanceId(hypervPrivate *priv, const char *id,
                               Msvm_MemorySettingData **data)
{
    g_auto(virBuffer) query = VIR_BUFFER_INITIALIZER;
    virBufferEscapeSQL(&query,
                       "ASSOCIATORS OF {Msvm_VirtualSystemSettingData.InstanceID=\"%s\"} "
                       "WHERE AssocClass = Msvm_VirtualSystemSettingDataComponent "
                       "ResultClass = Msvm_MemorySettingData",
                       id);

    if (hypervGetWmiClass(Msvm_MemorySettingData, data) < 0)
        return -1;

    if (!*data) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not look up memory setting data with virtual system instance ID '%s'"),
                       id);
        return -1;
    }

    return 0;
}


static int
hypervRequestStateChange(virDomainPtr domain, int state)
{
    int result = -1;
    hypervPrivate *priv = domain->conn->privateData;
    Msvm_ComputerSystem *computerSystem = NULL;

    if (hypervMsvmComputerSystemFromDomain(domain, &computerSystem) < 0)
        goto cleanup;

    if (computerSystem->data.common->EnabledState != MSVM_COMPUTERSYSTEM_ENABLEDSTATE_ENABLED) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s", _("Domain is not active"));
        goto cleanup;
    }

    result = hypervInvokeMsvmComputerSystemRequestStateChange(domain, state);

 cleanup:
    hypervFreeObject(priv, (hypervObject *)computerSystem);

    return result;
}


/*
 * API-specific utility functions
 */

static int
hypervParseVersionString(const char *str, unsigned int *major,
                         unsigned int *minor, unsigned int *micro)
{
    char *suffix = NULL;

    if (virStrToLong_ui(str, &suffix, 10, major) < 0)
        return -1;

    if (virStrToLong_ui(suffix + 1, &suffix, 10, minor) < 0)
        return -1;

    if (virStrToLong_ui(suffix + 1, NULL, 10, micro) < 0)
        return -1;

    return 0;
}


static int
hypervLookupHostSystemBiosUuid(hypervPrivate *priv, unsigned char *uuid)
{
    Win32_ComputerSystemProduct *computerSystem = NULL;
    g_auto(virBuffer) query = VIR_BUFFER_INITIALIZER;
    int result = -1;

    virBufferAddLit(&query, WIN32_COMPUTERSYSTEMPRODUCT_WQL_SELECT);
    if (hypervGetWmiClass(Win32_ComputerSystemProduct, &computerSystem) < 0)
        goto cleanup;

    if (virUUIDParse(computerSystem->data.common->UUID, uuid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not parse UUID from string '%s'"),
                       computerSystem->data.common->UUID);
        goto cleanup;
    }
    result = 0;

 cleanup:
    hypervFreeObject(priv, (hypervObject *) computerSystem);

    return result;
}


static virCapsPtr
hypervCapsInit(hypervPrivate *priv)
{
    virCapsPtr caps = NULL;
    virCapsGuestPtr guest = NULL;

    caps = virCapabilitiesNew(VIR_ARCH_X86_64, 1, 1);

    if (!caps)
        return NULL;

    if (hypervLookupHostSystemBiosUuid(priv, caps->host.host_uuid) < 0)
        goto error;

    /* i686 caps */
    guest = virCapabilitiesAddGuest(caps, VIR_DOMAIN_OSTYPE_HVM, VIR_ARCH_I686,
                                    NULL, NULL, 0, NULL);
    if (!guest)
        goto error;

    if (!virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_HYPERV, NULL, NULL, 0, NULL))
        goto error;

    /* x86_64 caps */
    guest = virCapabilitiesAddGuest(caps, VIR_DOMAIN_OSTYPE_HVM, VIR_ARCH_X86_64,
                                    NULL, NULL, 0, NULL);
    if (!guest)
        goto error;

    if (!virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_HYPERV, NULL, NULL, 0, NULL))
        goto error;

    return caps;

 error:
    virObjectUnref(caps);
    return NULL;
}

/*
 * Driver functions
 */

static void
hypervFreePrivate(hypervPrivate **priv)
{
    if (priv == NULL || *priv == NULL)
        return;

    if ((*priv)->client != NULL)
        wsmc_release((*priv)->client);

    if ((*priv)->caps)
        virObjectUnref((*priv)->caps);

    hypervFreeParsedUri(&(*priv)->parsedUri);
    VIR_FREE(*priv);
}


static int
hypervInitConnection(virConnectPtr conn, hypervPrivate *priv,
                     char *username, char *password)
{
    g_auto(virBuffer) query = VIR_BUFFER_INITIALIZER;
    hypervWqlQuery wqlQuery = HYPERV_WQL_QUERY_INITIALIZER;
    hypervObject *computerSystem = NULL;
    int ret = -1;

    /* Initialize the openwsman connection */
    priv->client = wsmc_create(conn->uri->server, conn->uri->port, "/wsman",
                               priv->parsedUri->transport, username, password);

    if (priv->client == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not create openwsman client"));
        goto cleanup;
    }

    if (wsmc_transport_init(priv->client, NULL) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not initialize openwsman transport"));
        goto cleanup;
    }

    /* FIXME: Currently only basic authentication is supported  */
    wsman_transport_set_auth_method(priv->client, "basic");

    wqlQuery.info = Msvm_ComputerSystem_WmiInfo;
    wqlQuery.query = &query;

    virBufferAddLit(&query, MSVM_COMPUTERSYSTEM_WQL_SELECT);
    virBufferAddLit(&query, "WHERE ");
    virBufferAddLit(&query, MSVM_COMPUTERSYSTEM_WQL_PHYSICAL);

    /* try query using V2 namespace (for Hyper-V 2012+) */
    priv->wmiVersion = HYPERV_WMI_VERSION_V2;

    if (hypervEnumAndPull(priv, &wqlQuery, &computerSystem) < 0) {
        /* rebuild query because hypervEnumAndPull consumes it */
        virBufferAddLit(&query, MSVM_COMPUTERSYSTEM_WQL_SELECT);
        virBufferAddLit(&query, "WHERE ");
        virBufferAddLit(&query, MSVM_COMPUTERSYSTEM_WQL_PHYSICAL);

        /* fall back to V1 namespace (for Hyper-V 2008) */
        priv->wmiVersion = HYPERV_WMI_VERSION_V1;

        if (hypervEnumAndPull(priv, &wqlQuery, &computerSystem) < 0)
            goto cleanup;
    }

    ret = 0;

 cleanup:
    hypervFreeObject(priv, computerSystem);

    return ret;
}


static virDrvOpenStatus
hypervConnectOpen(virConnectPtr conn, virConnectAuthPtr auth,
                  virConfPtr conf G_GNUC_UNUSED,
                  unsigned int flags)
{
    virDrvOpenStatus result = VIR_DRV_OPEN_ERROR;
    hypervPrivate *priv = NULL;
    char *username = NULL;
    char *password = NULL;

    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    /* Allocate per-connection private data */
    priv = g_new0(hypervPrivate, 1);

    if (hypervParseUri(&priv->parsedUri, conn->uri) < 0)
        goto cleanup;

    /* Set the port dependent on the transport protocol if no port is
     * specified. This allows us to rely on the port parameter being
     * correctly set when building URIs later on, without the need to
     * distinguish between the situations port == 0 and port != 0 */
    if (conn->uri->port == 0) {
        if (STRCASEEQ(priv->parsedUri->transport, "https")) {
            conn->uri->port = 5986;
        } else {
            conn->uri->port = 5985;
        }
    }

    /* Request credentials */
    if (conn->uri->user != NULL) {
        username = g_strdup(conn->uri->user);
    } else {
        if (!(username = virAuthGetUsername(conn, auth, "hyperv",
                                            "administrator",
                                            conn->uri->server)))
            goto cleanup;
    }

    if (!(password = virAuthGetPassword(conn, auth, "hyperv", username,
                                        conn->uri->server)))
        goto cleanup;

    if (hypervInitConnection(conn, priv, username, password) < 0)
        goto cleanup;

    /* set up capabilities */
    priv->caps = hypervCapsInit(priv);
    if (!priv->caps)
        goto cleanup;

    conn->privateData = priv;
    priv = NULL;
    result = VIR_DRV_OPEN_SUCCESS;

 cleanup:
    hypervFreePrivate(&priv);
    VIR_FREE(username);
    VIR_FREE(password);

    return result;
}


static int
hypervConnectClose(virConnectPtr conn)
{
    hypervPrivate *priv = conn->privateData;

    hypervFreePrivate(&priv);

    conn->privateData = NULL;

    return 0;
}


static const char *
hypervConnectGetType(virConnectPtr conn G_GNUC_UNUSED)
{
    return "Hyper-V";
}


static int
hypervConnectGetVersion(virConnectPtr conn, unsigned long *version)
{
    int result = -1;
    hypervPrivate *priv = conn->privateData;
    Win32_OperatingSystem *os = NULL;
    g_auto(virBuffer) query = { g_string_new(WIN32_OPERATINGSYSTEM_WQL_SELECT), 0 };
    unsigned int major, minor, micro;

    if (hypervGetWmiClass(Win32_OperatingSystem, &os) < 0)
        goto cleanup;

    if (!os) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not get version information for host %s"),
                       conn->uri->server);
        goto cleanup;
    }

    if (hypervParseVersionString(os->data.common->Version,
                                 &major, &minor, &micro) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not parse version from '%s'"),
                       os->data.common->Version);
        goto cleanup;
    }

    /*
     * Pack the version into an unsigned long while retaining all the digits.
     *
     * Since Microsoft's build numbers are almost always over 1000, this driver
     * needs to pack the value differently compared to the format defined by
     * virConnectGetVersion().
     *
     * This results in `virsh version` producing unexpected output.
     *
     * For example...
     * 2008:      6.0.6001     =>   600.6.1
     * 2008 R2:   6.1.7600     =>   601.7.600
     * 2012:      6.2.9200     =>   602.9.200
     * 2012 R2:   6.3.9600     =>   603.9.600
     * 2016:      10.0.14393   =>   1000.14.393
     * 2019:      10.0.17763   =>   1000.17.763
     */
    if (major > 99 || minor > 99 || micro > 999999) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not produce packed version number from '%s'"),
                       os->data.common->Version);
        goto cleanup;
    }

    *version = major * 100000000 + minor * 1000000 + micro;

    result = 0;

 cleanup:
    hypervFreeObject(priv, (hypervObject *) os);

    return result;
}


static char *
hypervConnectGetHostname(virConnectPtr conn)
{
    char *hostname = NULL;
    hypervPrivate *priv = conn->privateData;
    Win32_ComputerSystem *computerSystem = NULL;

    if (hypervGetPhysicalSystemList(priv, &computerSystem) < 0)
        goto cleanup;

    hostname = g_strdup(computerSystem->data.common->DNSHostName);

 cleanup:
    hypervFreeObject(priv, (hypervObject *)computerSystem);

    return hostname;
}


static char*
hypervConnectGetCapabilities(virConnectPtr conn)
{
    hypervPrivate *priv = conn->privateData;

    return virCapabilitiesFormatXML(priv->caps);
}


static int
hypervConnectGetMaxVcpus(virConnectPtr conn, const char *type G_GNUC_UNUSED)
{
    int result = -1;
    hypervPrivate *priv = conn->privateData;
    g_auto(virBuffer) query = VIR_BUFFER_INITIALIZER;
    Msvm_ProcessorSettingData *processorSettingData = NULL;

    /* Get max processors definition */
    virBufferAddLit(&query,
                    MSVM_PROCESSORSETTINGDATA_WQL_SELECT
                    "WHERE InstanceID LIKE 'Microsoft:Definition%Maximum'");

    if (hypervGetWmiClass(Msvm_ProcessorSettingData, &processorSettingData) < 0)
        goto cleanup;

    if (!processorSettingData) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not get maximum definition of Msvm_ProcessorSettingData for host %s"),
                       conn->uri->server);
        goto cleanup;
    }

    result = processorSettingData->data.common->VirtualQuantity;

 cleanup:
    hypervFreeObject(priv, (hypervObject *) processorSettingData);

    return result;
}


static int
hypervNodeGetInfo(virConnectPtr conn, virNodeInfoPtr info)
{
    int result = -1;
    hypervPrivate *priv = conn->privateData;
    Win32_ComputerSystem *computerSystem = NULL;
    Win32_Processor *processorList = NULL;
    Win32_Processor *processor = NULL;
    char *tmp;

    memset(info, 0, sizeof(*info));

    if (hypervGetPhysicalSystemList(priv, &computerSystem) < 0)
        goto cleanup;

    if (hypervGetProcessorsByName(priv, computerSystem->data.common->Name,
                                  &processorList) < 0) {
        goto cleanup;
    }

    /* Strip the string to fit more relevant information in 32 chars */
    tmp = processorList->data.common->Name;

    while (*tmp != '\0') {
        if (STRPREFIX(tmp, "  ")) {
            memmove(tmp, tmp + 1, strlen(tmp + 1) + 1);
            continue;
        } else if (STRPREFIX(tmp, "(R)") || STRPREFIX(tmp, "(C)")) {
            memmove(tmp, tmp + 3, strlen(tmp + 3) + 1);
            continue;
        } else if (STRPREFIX(tmp, "(TM)")) {
            memmove(tmp, tmp + 4, strlen(tmp + 4) + 1);
            continue;
        } else if (STRPREFIX(tmp, " @ ")) {
            /* Remove " @ X.YZGHz" from the end. */
            *tmp = '\0';
            break;
        }

        ++tmp;
    }

    /* Fill struct */
    if (virStrcpyStatic(info->model, processorList->data.common->Name) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("CPU model %s too long for destination"),
                       processorList->data.common->Name);
        goto cleanup;
    }

    info->memory = computerSystem->data.common->TotalPhysicalMemory / 1024; /* byte to kilobyte */
    info->mhz = processorList->data.common->MaxClockSpeed;
    info->nodes = 1;
    info->sockets = 0;

    for (processor = processorList; processor != NULL;
         processor = processor->next) {
        ++info->sockets;
    }

    info->cores = processorList->data.common->NumberOfCores;
    info->threads = processorList->data.common->NumberOfLogicalProcessors / info->cores;
    info->cpus = info->sockets * info->cores;

    result = 0;

 cleanup:
    hypervFreeObject(priv, (hypervObject *)computerSystem);
    hypervFreeObject(priv, (hypervObject *)processorList);

    return result;
}


static int
hypervConnectListDomains(virConnectPtr conn, int *ids, int maxids)
{
    bool success = false;
    hypervPrivate *priv = conn->privateData;
    Msvm_ComputerSystem *computerSystemList = NULL;
    Msvm_ComputerSystem *computerSystem = NULL;
    int count = 0;

    if (maxids == 0)
        return 0;

    if (hypervGetActiveVirtualSystemList(priv, &computerSystemList) < 0)
        goto cleanup;

    for (computerSystem = computerSystemList; computerSystem != NULL;
         computerSystem = computerSystem->next) {
        ids[count++] = computerSystem->data.common->ProcessID;

        if (count >= maxids)
            break;
    }

    success = true;

 cleanup:
    hypervFreeObject(priv, (hypervObject *)computerSystemList);

    return success ? count : -1;
}


static int
hypervConnectNumOfDomains(virConnectPtr conn)
{
    bool success = false;
    hypervPrivate *priv = conn->privateData;
    Msvm_ComputerSystem *computerSystemList = NULL;
    Msvm_ComputerSystem *computerSystem = NULL;
    int count = 0;

    if (hypervGetActiveVirtualSystemList(priv, &computerSystemList) < 0)
        goto cleanup;

    for (computerSystem = computerSystemList; computerSystem != NULL;
         computerSystem = computerSystem->next) {
        ++count;
    }

    success = true;

 cleanup:
    hypervFreeObject(priv, (hypervObject *)computerSystemList);

    return success ? count : -1;
}


static virDomainPtr
hypervDomainLookupByID(virConnectPtr conn, int id)
{
    virDomainPtr domain = NULL;
    hypervPrivate *priv = conn->privateData;
    Msvm_ComputerSystem *computerSystem = NULL;

    if (hypervGetVirtualSystemByID(priv, id, &computerSystem) < 0)
        goto cleanup;

    hypervMsvmComputerSystemToDomain(conn, computerSystem, &domain);

 cleanup:
    hypervFreeObject(priv, (hypervObject *)computerSystem);

    return domain;
}


static virDomainPtr
hypervDomainLookupByUUID(virConnectPtr conn, const unsigned char *uuid)
{
    virDomainPtr domain = NULL;
    hypervPrivate *priv = conn->privateData;
    char uuid_string[VIR_UUID_STRING_BUFLEN];
    Msvm_ComputerSystem *computerSystem = NULL;

    virUUIDFormat(uuid, uuid_string);

    if (hypervGetVirtualSystemByUUID(priv, uuid_string, &computerSystem) < 0)
        goto cleanup;

    hypervMsvmComputerSystemToDomain(conn, computerSystem, &domain);

 cleanup:
    hypervFreeObject(priv, (hypervObject *)computerSystem);

    return domain;
}


static virDomainPtr
hypervDomainLookupByName(virConnectPtr conn, const char *name)
{
    virDomainPtr domain = NULL;
    hypervPrivate *priv = conn->privateData;
    Msvm_ComputerSystem *computerSystem = NULL;

    if (hypervGetVirtualSystemByName(priv, name, &computerSystem) < 0)
        goto cleanup;

    hypervMsvmComputerSystemToDomain(conn, computerSystem, &domain);

 cleanup:
    hypervFreeObject(priv, (hypervObject *)computerSystem);

    return domain;
}


static int
hypervDomainSuspend(virDomainPtr domain)
{
    hypervPrivate *priv = domain->conn->privateData;
    int requestedState = -1;

    switch (priv->wmiVersion) {
    case HYPERV_WMI_VERSION_V1:
        requestedState = MSVM_COMPUTERSYSTEM_REQUESTEDSTATE_PAUSED;
        break;
    case HYPERV_WMI_VERSION_V2:
        requestedState = MSVM_COMPUTERSYSTEM_REQUESTEDSTATE_QUIESCE;
        break;
    }

    return hypervRequestStateChange(domain, requestedState);
}


static int
hypervDomainResume(virDomainPtr domain)
{
    int result = -1;
    hypervPrivate *priv = domain->conn->privateData;
    Msvm_ComputerSystem *computerSystem = NULL;
    int expectedState = -1;

    switch (priv->wmiVersion) {
    case HYPERV_WMI_VERSION_V1:
        expectedState = MSVM_COMPUTERSYSTEM_ENABLEDSTATE_PAUSED;
        break;
    case HYPERV_WMI_VERSION_V2:
        expectedState = MSVM_COMPUTERSYSTEM_REQUESTEDSTATE_QUIESCE;
        break;
    }

    if (hypervMsvmComputerSystemFromDomain(domain, &computerSystem) < 0)
        return -1;

    if (computerSystem->data.common->EnabledState != expectedState) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Domain is not paused"));
        goto cleanup;
    }

    result = hypervInvokeMsvmComputerSystemRequestStateChange(domain,
                                                              MSVM_COMPUTERSYSTEM_REQUESTEDSTATE_ENABLED);

 cleanup:
    hypervFreeObject(priv, (hypervObject *)computerSystem);

    return result;
}


static int
hypervDomainShutdownFlags(virDomainPtr domain, unsigned int flags)
{
    int result = -1;
    hypervPrivate *priv = domain->conn->privateData;
    Msvm_ComputerSystem *computerSystem = NULL;
    Msvm_ShutdownComponent *shutdown = NULL;
    bool in_transition = false;
    char uuid[VIR_UUID_STRING_BUFLEN];
    g_auto(virBuffer) query = VIR_BUFFER_INITIALIZER;
    g_autoptr(hypervInvokeParamsList) params = NULL;
    g_autofree char *selector = NULL;

    virCheckFlags(0, -1);

    virUUIDFormat(domain->uuid, uuid);

    if (hypervMsvmComputerSystemFromDomain(domain, &computerSystem) < 0)
        goto cleanup;

    if (!hypervIsMsvmComputerSystemActive(computerSystem, &in_transition) ||
        in_transition) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Domain is not active or in state transition"));
        goto cleanup;
    }

    virBufferEscapeSQL(&query, MSVM_SHUTDOWNCOMPONENT_WQL_SELECT "WHERE SystemName = '%s'", uuid);

    if (hypervGetWmiClass(Msvm_ShutdownComponent, &shutdown) < 0 ||
        !shutdown) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("Could not get Msvm_ShutdownComponent for domain with UUID '%s'"),
                       uuid);
        goto cleanup;
    }

    selector = g_strdup_printf("CreationClassName=\"Msvm_ShutdownComponent\"&DeviceID=\"%s\"&"
                               "SystemCreationClassName=\"Msvm_ComputerSystem\"&SystemName=\"%s\"",
                               shutdown->data.common->DeviceID, uuid);

    params = hypervCreateInvokeParamsList(priv, "InitiateShutdown", selector,
                                          Msvm_ShutdownComponent_WmiInfo);
    if (!params)
        goto cleanup;

    hypervAddSimpleParam(params, "Force", "False");

    /* "Reason" is not translated because the Hyper-V administrator may not
     * know the libvirt user's language. They may not know English, either,
     * but this makes it consistent, at least. */
    hypervAddSimpleParam(params, "Reason", "Planned shutdown via libvirt");

    if (hypervInvokeMethod(priv, &params, NULL) < 0)
        goto cleanup;

    result = 0;

 cleanup:
    hypervFreeObject(priv, (hypervObject *) computerSystem);
    hypervFreeObject(priv, (hypervObject *) shutdown);

    return result;
}


static int
hypervDomainShutdown(virDomainPtr domain)
{
    return hypervDomainShutdownFlags(domain, 0);
}


static int
hypervDomainReboot(virDomainPtr domain, unsigned int flags)
{
    virCheckFlags(0, -1);
    return hypervRequestStateChange(domain, MSVM_COMPUTERSYSTEM_REQUESTEDSTATE_REBOOT);
}


static int
hypervDomainReset(virDomainPtr domain, unsigned int flags)
{
    virCheckFlags(0, -1);
    return hypervRequestStateChange(domain, MSVM_COMPUTERSYSTEM_REQUESTEDSTATE_RESET);
}


static int
hypervDomainDestroyFlags(virDomainPtr domain, unsigned int flags)
{
    int result = -1;
    hypervPrivate *priv = domain->conn->privateData;
    Msvm_ComputerSystem *computerSystem = NULL;
    bool in_transition = false;

    virCheckFlags(0, -1);

    if (hypervMsvmComputerSystemFromDomain(domain, &computerSystem) < 0)
        goto cleanup;

    if (!hypervIsMsvmComputerSystemActive(computerSystem, &in_transition) ||
        in_transition) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Domain is not active or is in state transition"));
        goto cleanup;
    }

    result = hypervInvokeMsvmComputerSystemRequestStateChange(domain,
                                                              MSVM_COMPUTERSYSTEM_REQUESTEDSTATE_DISABLED);

 cleanup:
    hypervFreeObject(priv, (hypervObject *)computerSystem);

    return result;
}


static int
hypervDomainDestroy(virDomainPtr domain)
{
    return hypervDomainDestroyFlags(domain, 0);
}


static char *
hypervDomainGetOSType(virDomainPtr domain G_GNUC_UNUSED)
{
    char *osType;

    osType = g_strdup("hvm");
    return osType;
}


static int
hypervDomainGetInfo(virDomainPtr domain, virDomainInfoPtr info)
{
    int result = -1;
    hypervPrivate *priv = domain->conn->privateData;
    char uuid_string[VIR_UUID_STRING_BUFLEN];
    Msvm_ComputerSystem *computerSystem = NULL;
    Msvm_VirtualSystemSettingData *virtualSystemSettingData = NULL;
    Msvm_ProcessorSettingData *processorSettingData = NULL;
    Msvm_MemorySettingData *memorySettingData = NULL;

    memset(info, 0, sizeof(*info));

    virUUIDFormat(domain->uuid, uuid_string);

    /* Get Msvm_ComputerSystem */
    if (hypervMsvmComputerSystemFromDomain(domain, &computerSystem) < 0)
        goto cleanup;

    if (hypervGetVSSDFromUUID(priv, uuid_string,
                              &virtualSystemSettingData) < 0) {
        goto cleanup;
    }

    if (hypervGetProcSDByVSSDInstanceId(priv,
                                        virtualSystemSettingData->data.common->InstanceID,
                                        &processorSettingData) < 0) {
        goto cleanup;
    }

    if (hypervGetMemSDByVSSDInstanceId(priv,
                                       virtualSystemSettingData->data.common->InstanceID,
                                       &memorySettingData) < 0) {
        goto cleanup;
    }

    /* Fill struct */
    info->state = hypervMsvmComputerSystemEnabledStateToDomainState(computerSystem);
    info->maxMem = memorySettingData->data.common->Limit * 1024; /* megabyte to kilobyte */
    info->memory = memorySettingData->data.common->VirtualQuantity * 1024; /* megabyte to kilobyte */
    info->nrVirtCpu = processorSettingData->data.common->VirtualQuantity;
    info->cpuTime = 0;

    result = 0;

 cleanup:
    hypervFreeObject(priv, (hypervObject *)computerSystem);
    hypervFreeObject(priv, (hypervObject *)virtualSystemSettingData);
    hypervFreeObject(priv, (hypervObject *)processorSettingData);
    hypervFreeObject(priv, (hypervObject *)memorySettingData);

    return result;
}


static int
hypervDomainGetState(virDomainPtr domain, int *state, int *reason,
                     unsigned int flags)
{
    int result = -1;
    hypervPrivate *priv = domain->conn->privateData;
    Msvm_ComputerSystem *computerSystem = NULL;

    virCheckFlags(0, -1);

    if (hypervMsvmComputerSystemFromDomain(domain, &computerSystem) < 0)
        goto cleanup;

    *state = hypervMsvmComputerSystemEnabledStateToDomainState(computerSystem);

    if (reason != NULL)
        *reason = 0;

    result = 0;

 cleanup:
    hypervFreeObject(priv, (hypervObject *)computerSystem);

    return result;
}


static char *
hypervDomainGetXMLDesc(virDomainPtr domain, unsigned int flags)
{
    char *xml = NULL;
    hypervPrivate *priv = domain->conn->privateData;
    virDomainDefPtr def = NULL;
    char uuid_string[VIR_UUID_STRING_BUFLEN];
    Msvm_ComputerSystem *computerSystem = NULL;
    Msvm_VirtualSystemSettingData *virtualSystemSettingData = NULL;
    Msvm_ProcessorSettingData *processorSettingData = NULL;
    Msvm_MemorySettingData *memorySettingData = NULL;

    virCheckFlags(VIR_DOMAIN_XML_COMMON_FLAGS, NULL);

    if (!(def = virDomainDefNew()))
        goto cleanup;

    virUUIDFormat(domain->uuid, uuid_string);

    /* Get Msvm_ComputerSystem */
    if (hypervMsvmComputerSystemFromDomain(domain, &computerSystem) < 0)
        goto cleanup;

    if (hypervGetVSSDFromUUID(priv, uuid_string,
                              &virtualSystemSettingData) < 0) {
        goto cleanup;
    }

    if (hypervGetProcSDByVSSDInstanceId(priv,
                                        virtualSystemSettingData->data.common->InstanceID,
                                        &processorSettingData) < 0) {
        goto cleanup;
    }

    if (hypervGetMemSDByVSSDInstanceId(priv,
                                       virtualSystemSettingData->data.common->InstanceID,
                                       &memorySettingData) < 0) {
        goto cleanup;
    }

    /* Fill struct */
    def->virtType = VIR_DOMAIN_VIRT_HYPERV;

    if (hypervIsMsvmComputerSystemActive(computerSystem, NULL)) {
        def->id = computerSystem->data.common->ProcessID;
    } else {
        def->id = -1;
    }

    if (virUUIDParse(computerSystem->data.common->Name, def->uuid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not parse UUID from string '%s'"),
                       computerSystem->data.common->Name);
        return NULL;
    }

    def->name = g_strdup(computerSystem->data.common->ElementName);

    if (priv->wmiVersion == HYPERV_WMI_VERSION_V1) {
        def->description = g_strdup(virtualSystemSettingData->data.v1->Notes);
    } else if (priv->wmiVersion == HYPERV_WMI_VERSION_V2 &&
               virtualSystemSettingData->data.v2->Notes.data != NULL) {
        char **notes = (char **)virtualSystemSettingData->data.v2->Notes.data;
        g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
        size_t i = 0;

        /* in practice Notes has 1 element */
        for (i = 0; i < virtualSystemSettingData->data.v2->Notes.count; i++) {
            /* but if there's more than 1, separate by double new line */
            if (virBufferUse(&buf) > 0)
                virBufferAddLit(&buf, "\n\n");

            virBufferAdd(&buf, *notes, -1);
            notes++;
        }

        def->description = virBufferContentAndReset(&buf);
    }

    /* mebibytes to kibibytes */
    def->mem.max_memory = memorySettingData->data.common->Limit * 1024;
    def->mem.cur_balloon = memorySettingData->data.common->VirtualQuantity * 1024;
    virDomainDefSetMemoryTotal(def, memorySettingData->data.common->VirtualQuantity * 1024);

    if (virDomainDefSetVcpusMax(def,
                                processorSettingData->data.common->VirtualQuantity,
                                NULL) < 0)
        goto cleanup;

    if (virDomainDefSetVcpus(def,
                             processorSettingData->data.common->VirtualQuantity) < 0)
        goto cleanup;

    def->os.type = VIR_DOMAIN_OSTYPE_HVM;

    /* FIXME: devices section is totally missing */

    /* XXX xmlopts must be non-NULL */
    xml = virDomainDefFormat(def, NULL,
                             virDomainDefFormatConvertXMLFlags(flags));

 cleanup:
    virDomainDefFree(def);
    hypervFreeObject(priv, (hypervObject *)computerSystem);
    hypervFreeObject(priv, (hypervObject *)virtualSystemSettingData);
    hypervFreeObject(priv, (hypervObject *)processorSettingData);
    hypervFreeObject(priv, (hypervObject *)memorySettingData);

    return xml;
}


static int
hypervConnectListDefinedDomains(virConnectPtr conn, char **const names, int maxnames)
{
    bool success = false;
    hypervPrivate *priv = conn->privateData;
    Msvm_ComputerSystem *computerSystemList = NULL;
    Msvm_ComputerSystem *computerSystem = NULL;
    int count = 0;
    size_t i;

    if (maxnames == 0)
        return 0;

    if (hypervGetInactiveVirtualSystemList(priv, &computerSystemList) < 0)
        goto cleanup;

    for (computerSystem = computerSystemList; computerSystem != NULL;
         computerSystem = computerSystem->next) {
        names[count] = g_strdup(computerSystem->data.common->ElementName);

        ++count;

        if (count >= maxnames)
            break;
    }

    success = true;

 cleanup:
    if (!success) {
        for (i = 0; i < count; ++i)
            VIR_FREE(names[i]);

        count = -1;
    }

    hypervFreeObject(priv, (hypervObject *)computerSystemList);

    return count;
}


static int
hypervConnectNumOfDefinedDomains(virConnectPtr conn)
{
    bool success = false;
    hypervPrivate *priv = conn->privateData;
    Msvm_ComputerSystem *computerSystemList = NULL;
    Msvm_ComputerSystem *computerSystem = NULL;
    int count = 0;

    if (hypervGetInactiveVirtualSystemList(priv, &computerSystemList) < 0)
        goto cleanup;

    for (computerSystem = computerSystemList; computerSystem != NULL;
         computerSystem = computerSystem->next) {
        ++count;
    }

    success = true;

 cleanup:
    hypervFreeObject(priv, (hypervObject *)computerSystemList);

    return success ? count : -1;
}


static int
hypervDomainCreateWithFlags(virDomainPtr domain, unsigned int flags)
{
    int result = -1;
    hypervPrivate *priv = domain->conn->privateData;
    Msvm_ComputerSystem *computerSystem = NULL;

    virCheckFlags(0, -1);

    if (hypervMsvmComputerSystemFromDomain(domain, &computerSystem) < 0)
        goto cleanup;

    if (hypervIsMsvmComputerSystemActive(computerSystem, NULL)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Domain is already active or is in state transition"));
        goto cleanup;
    }

    result = hypervInvokeMsvmComputerSystemRequestStateChange(domain,
                                                              MSVM_COMPUTERSYSTEM_REQUESTEDSTATE_ENABLED);

 cleanup:
    hypervFreeObject(priv, (hypervObject *)computerSystem);

    return result;
}


static int
hypervDomainCreate(virDomainPtr domain)
{
    return hypervDomainCreateWithFlags(domain, 0);
}


static int
hypervDomainGetAutostart(virDomainPtr domain, int *autostart)
{
    int result = -1;
    char uuid_string[VIR_UUID_STRING_BUFLEN];
    hypervPrivate *priv = domain->conn->privateData;
    g_auto(virBuffer) query = VIR_BUFFER_INITIALIZER;
    Msvm_VirtualSystemGlobalSettingData *vsgsd = NULL;
    Msvm_VirtualSystemSettingData *vssd = NULL;

    virUUIDFormat(domain->uuid, uuid_string);

    if (priv->wmiVersion == HYPERV_WMI_VERSION_V1) {
        virBufferEscapeSQL(&query,
                           MSVM_VIRTUALSYSTEMGLOBALSETTINGDATA_WQL_SELECT
                           "WHERE SystemName = \"%s\"", uuid_string);

        if (hypervGetWmiClass(Msvm_VirtualSystemGlobalSettingData, &vsgsd) < 0)
            goto cleanup;

        *autostart = vsgsd->data.common->AutomaticStartupAction == 2;
        result = 0;
    } else {
        if (hypervGetVSSDFromUUID(priv, uuid_string, &vssd) < 0)
            goto cleanup;

        *autostart = vssd->data.v2->AutomaticStartupAction == 4;
        result = 0;
    }

 cleanup:
    hypervFreeObject(priv, (hypervObject *) vsgsd);
    hypervFreeObject(priv, (hypervObject *) vssd);

    return result;
}


static int
hypervDomainSetAutostart(virDomainPtr domain, int autostart)
{
    int result = -1;
    char uuid_string[VIR_UUID_STRING_BUFLEN];
    hypervPrivate *priv = domain->conn->privateData;
    Msvm_VirtualSystemSettingData *vssd = NULL;
    g_autoptr(hypervInvokeParamsList) params = NULL;
    g_auto(virBuffer) eprQuery = VIR_BUFFER_INITIALIZER;
    g_autoptr(virHashTable) autostartParam = NULL;
    const char *methodName = NULL;
    hypervWmiClassInfoListPtr embeddedParamClass = NULL;
    const char *enabledValue = NULL, *disabledValue = NULL;
    const char *embeddedParamName = NULL;

    switch (priv->wmiVersion) {
    case HYPERV_WMI_VERSION_V1:
        methodName = "ModifyVirtualSystem";
        embeddedParamClass = Msvm_VirtualSystemGlobalSettingData_WmiInfo;
        enabledValue = "2";
        disabledValue = "0";
        embeddedParamName = "SystemSettingData";
        break;
    case HYPERV_WMI_VERSION_V2:
        methodName = "ModifySystemSettings";
        embeddedParamClass = Msvm_VirtualSystemSettingData_WmiInfo;
        enabledValue = "4";
        disabledValue = "2";
        embeddedParamName = "SystemSettings";
        break;
    }

    virUUIDFormat(domain->uuid, uuid_string);

    if (hypervGetVSSDFromUUID(priv, uuid_string, &vssd) < 0)
        goto cleanup;

    params = hypervCreateInvokeParamsList(priv, methodName,
                                          MSVM_VIRTUALSYSTEMMANAGEMENTSERVICE_SELECTOR,
                                          Msvm_VirtualSystemManagementService_WmiInfo);

    if (!params)
        goto cleanup;

    if (priv->wmiVersion == HYPERV_WMI_VERSION_V1) {
        virBufferEscapeSQL(&eprQuery,
                           MSVM_COMPUTERSYSTEM_WQL_SELECT "WHERE Name = '%s'",
                           uuid_string);

        if (hypervAddEprParam(params, "ComputerSystem", priv, &eprQuery,
                              Msvm_ComputerSystem_WmiInfo) < 0)
            goto cleanup;
    }

    autostartParam = hypervCreateEmbeddedParam(priv, embeddedParamClass);

    if (hypervSetEmbeddedProperty(autostartParam, "AutomaticStartupAction",
                                  autostart ? enabledValue : disabledValue) < 0)
        goto cleanup;

    if (hypervSetEmbeddedProperty(autostartParam, "InstanceID",
                                  vssd->data.common->InstanceID) < 0)
        goto cleanup;

    if (hypervAddEmbeddedParam(params, priv, embeddedParamName,
                               &autostartParam, embeddedParamClass) < 0)
        goto cleanup;

    if (hypervInvokeMethod(priv, &params, NULL) < 0)
        goto cleanup;

    result = 0;

 cleanup:
    hypervFreeObject(priv, (hypervObject *)vssd);

    return result;
}


static unsigned long long
hypervNodeGetFreeMemory(virConnectPtr conn)
{
    unsigned long long freeMemoryBytes = 0;
    hypervPrivate *priv = conn->privateData;
    Win32_OperatingSystem *operatingSystem = NULL;
    g_auto(virBuffer) query = { g_string_new(WIN32_OPERATINGSYSTEM_WQL_SELECT), 0 };

    if (hypervGetWmiClass(Win32_OperatingSystem, &operatingSystem) < 0)
        return 0;

    if (!operatingSystem) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not get free memory for host %s"),
                       conn->uri->server);
        return 0;
    }

    freeMemoryBytes = operatingSystem->data.common->FreePhysicalMemory * 1024;

    hypervFreeObject(priv, (hypervObject *)operatingSystem);

    return freeMemoryBytes;
}


static int
hypervConnectIsEncrypted(virConnectPtr conn)
{
    hypervPrivate *priv = conn->privateData;

    if (STRCASEEQ(priv->parsedUri->transport, "https")) {
        return 1;
    } else {
        return 0;
    }
}


static int
hypervConnectIsSecure(virConnectPtr conn)
{
    hypervPrivate *priv = conn->privateData;

    if (STRCASEEQ(priv->parsedUri->transport, "https")) {
        return 1;
    } else {
        return 0;
    }
}


static int
hypervConnectIsAlive(virConnectPtr conn)
{
    hypervPrivate *priv = conn->privateData;

    /* XXX we should be able to do something better than this is simple, safe,
     * and good enough for now. In worst case, the function will return true
     * even though the connection is not alive.
     */
    if (priv->client)
        return 1;
    else
        return 0;
}


static int
hypervDomainIsActive(virDomainPtr domain)
{
    int result = -1;
    hypervPrivate *priv = domain->conn->privateData;
    Msvm_ComputerSystem *computerSystem = NULL;

    if (hypervMsvmComputerSystemFromDomain(domain, &computerSystem) < 0)
        goto cleanup;

    result = hypervIsMsvmComputerSystemActive(computerSystem, NULL) ? 1 : 0;

 cleanup:
    hypervFreeObject(priv, (hypervObject *)computerSystem);

    return result;
}


static int
hypervDomainIsPersistent(virDomainPtr domain G_GNUC_UNUSED)
{
    /* Hyper-V has no concept of transient domains, so all of them are persistent */
    return 1;
}


static int
hypervDomainIsUpdated(virDomainPtr domain G_GNUC_UNUSED)
{
    return 0;
}


static int
hypervDomainManagedSave(virDomainPtr domain, unsigned int flags)
{
    int result = -1;
    hypervPrivate *priv = domain->conn->privateData;
    Msvm_ComputerSystem *computerSystem = NULL;
    bool in_transition = false;
    int requestedState = -1;

    virCheckFlags(0, -1);

    switch (priv->wmiVersion) {
    case HYPERV_WMI_VERSION_V1:
        requestedState = MSVM_COMPUTERSYSTEM_REQUESTEDSTATE_SUSPENDED;
        break;
    case HYPERV_WMI_VERSION_V2:
        requestedState = MSVM_COMPUTERSYSTEM_REQUESTEDSTATE_OFFLINE;
        break;
    }

    if (hypervMsvmComputerSystemFromDomain(domain, &computerSystem) < 0)
        goto cleanup;

    if (!hypervIsMsvmComputerSystemActive(computerSystem, &in_transition) ||
        in_transition) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Domain is not active or is in state transition"));
        goto cleanup;
    }

    result = hypervInvokeMsvmComputerSystemRequestStateChange(domain, requestedState);

 cleanup:
    hypervFreeObject(priv, (hypervObject *)computerSystem);

    return result;
}


static int
hypervDomainHasManagedSaveImage(virDomainPtr domain, unsigned int flags)
{
    int result = -1;
    hypervPrivate *priv = domain->conn->privateData;
    Msvm_ComputerSystem *computerSystem = NULL;

    virCheckFlags(0, -1);

    if (hypervMsvmComputerSystemFromDomain(domain, &computerSystem) < 0)
        goto cleanup;

    result = computerSystem->data.common->EnabledState ==
             MSVM_COMPUTERSYSTEM_ENABLEDSTATE_SUSPENDED ? 1 : 0;

 cleanup:
    hypervFreeObject(priv, (hypervObject *)computerSystem);

    return result;
}


static int
hypervDomainManagedSaveRemove(virDomainPtr domain, unsigned int flags)
{
    int result = -1;
    hypervPrivate *priv = domain->conn->privateData;
    Msvm_ComputerSystem *computerSystem = NULL;

    virCheckFlags(0, -1);

    if (hypervMsvmComputerSystemFromDomain(domain, &computerSystem) < 0)
        goto cleanup;

    if (computerSystem->data.common->EnabledState !=
        MSVM_COMPUTERSYSTEM_ENABLEDSTATE_SUSPENDED) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Domain has no managed save image"));
        goto cleanup;
    }

    result = hypervInvokeMsvmComputerSystemRequestStateChange(domain,
                                                              MSVM_COMPUTERSYSTEM_REQUESTEDSTATE_DISABLED);

 cleanup:
    hypervFreeObject(priv, (hypervObject *)computerSystem);

    return result;
}


#define MATCH(FLAG) (flags & (FLAG))
static int
hypervConnectListAllDomains(virConnectPtr conn,
                            virDomainPtr **domains,
                            unsigned int flags)
{
    hypervPrivate *priv = conn->privateData;
    g_auto(virBuffer) query = VIR_BUFFER_INITIALIZER;
    Msvm_ComputerSystem *computerSystemList = NULL;
    Msvm_ComputerSystem *computerSystem = NULL;
    size_t ndoms;
    virDomainPtr domain;
    virDomainPtr *doms = NULL;
    int count = 0;
    int ret = -1;
    size_t i;

    virCheckFlags(VIR_CONNECT_LIST_DOMAINS_FILTERS_ALL, -1);

    /* check for filter combinations that return no results:
     * persistent: all hyperv guests are persistent
     * snapshot: the driver does not support snapshot management
     * autostart: the driver does not support autostarting guests
     */
    if ((MATCH(VIR_CONNECT_LIST_DOMAINS_TRANSIENT) &&
         !MATCH(VIR_CONNECT_LIST_DOMAINS_PERSISTENT)) ||
        (MATCH(VIR_CONNECT_LIST_DOMAINS_AUTOSTART) &&
         !MATCH(VIR_CONNECT_LIST_DOMAINS_NO_AUTOSTART)) ||
        (MATCH(VIR_CONNECT_LIST_DOMAINS_HAS_SNAPSHOT) &&
         !MATCH(VIR_CONNECT_LIST_DOMAINS_NO_SNAPSHOT))) {
        if (domains)
            *domains = g_new0(virDomainPtr, 1);

        ret = 0;
        goto cleanup;
    }

    virBufferAddLit(&query, MSVM_COMPUTERSYSTEM_WQL_SELECT);
    virBufferAddLit(&query, "where ");
    virBufferAddLit(&query, MSVM_COMPUTERSYSTEM_WQL_VIRTUAL);

    /* construct query with filter depending on flags */
    if (!(MATCH(VIR_CONNECT_LIST_DOMAINS_ACTIVE) &&
          MATCH(VIR_CONNECT_LIST_DOMAINS_INACTIVE))) {
        if (MATCH(VIR_CONNECT_LIST_DOMAINS_ACTIVE)) {
            virBufferAddLit(&query, "and ");
            virBufferAddLit(&query, MSVM_COMPUTERSYSTEM_WQL_ACTIVE);
        }

        if (MATCH(VIR_CONNECT_LIST_DOMAINS_INACTIVE)) {
            virBufferAddLit(&query, "and ");
            virBufferAddLit(&query, MSVM_COMPUTERSYSTEM_WQL_INACTIVE);
        }
    }

    if (hypervGetWmiClass(Msvm_ComputerSystem, &computerSystemList) < 0)
        goto cleanup;

    if (domains) {
        doms = g_new0(virDomainPtr, 1);
        ndoms = 1;
    }

    for (computerSystem = computerSystemList; computerSystem != NULL;
         computerSystem = computerSystem->next) {

        /* filter by domain state */
        if (MATCH(VIR_CONNECT_LIST_DOMAINS_FILTERS_STATE)) {
            int st = hypervMsvmComputerSystemEnabledStateToDomainState(computerSystem);
            if (!((MATCH(VIR_CONNECT_LIST_DOMAINS_RUNNING) &&
                   st == VIR_DOMAIN_RUNNING) ||
                  (MATCH(VIR_CONNECT_LIST_DOMAINS_PAUSED) &&
                   st == VIR_DOMAIN_PAUSED) ||
                  (MATCH(VIR_CONNECT_LIST_DOMAINS_SHUTOFF) &&
                   st == VIR_DOMAIN_SHUTOFF) ||
                  (MATCH(VIR_CONNECT_LIST_DOMAINS_OTHER) &&
                   (st != VIR_DOMAIN_RUNNING &&
                    st != VIR_DOMAIN_PAUSED &&
                    st != VIR_DOMAIN_SHUTOFF))))
                continue;
        }

        /* managed save filter */
        if (MATCH(VIR_CONNECT_LIST_DOMAINS_FILTERS_MANAGEDSAVE)) {
            bool mansave = computerSystem->data.common->EnabledState ==
                           MSVM_COMPUTERSYSTEM_ENABLEDSTATE_SUSPENDED;

            if (!((MATCH(VIR_CONNECT_LIST_DOMAINS_MANAGEDSAVE) && mansave) ||
                  (MATCH(VIR_CONNECT_LIST_DOMAINS_NO_MANAGEDSAVE) && !mansave)))
                continue;
        }

        if (!doms) {
            count++;
            continue;
        }

        if (VIR_RESIZE_N(doms, ndoms, count, 2) < 0)
            goto cleanup;

        domain = NULL;

        if (hypervMsvmComputerSystemToDomain(conn, computerSystem,
                                             &domain) < 0)
            goto cleanup;

        doms[count++] = domain;
    }

    if (doms)
        *domains = doms;
    doms = NULL;
    ret = count;

 cleanup:
    if (doms) {
        for (i = 0; i < count; ++i)
            virObjectUnref(doms[i]);

        VIR_FREE(doms);
    }

    hypervFreeObject(priv, (hypervObject *)computerSystemList);

    return ret;
}
#undef MATCH


static int
hypervDomainSendKey(virDomainPtr domain, unsigned int codeset,
                    unsigned int holdtime, unsigned int *keycodes, int nkeycodes,
                    unsigned int flags)
{
    int result = -1;
    size_t i = 0;
    int keycode = 0;
    int *translatedKeycodes = NULL;
    hypervPrivate *priv = domain->conn->privateData;
    char uuid_string[VIR_UUID_STRING_BUFLEN];
    char *selector = NULL;
    Msvm_ComputerSystem *computerSystem = NULL;
    Msvm_Keyboard *keyboard = NULL;
    g_auto(virBuffer) query = VIR_BUFFER_INITIALIZER;
    g_autoptr(hypervInvokeParamsList) params = NULL;
    char keycodeStr[VIR_INT64_STR_BUFLEN];

    virCheckFlags(0, -1);

    virUUIDFormat(domain->uuid, uuid_string);

    if (hypervMsvmComputerSystemFromDomain(domain, &computerSystem) < 0)
        goto cleanup;

    virBufferEscapeSQL(&query,
                       "associators of "
                       "{Msvm_ComputerSystem.CreationClassName=\"Msvm_ComputerSystem\","
                       "Name=\"%s\"} "
                       "where ResultClass = Msvm_Keyboard",
                       uuid_string);

    if (hypervGetWmiClass(Msvm_Keyboard, &keyboard) < 0)
        goto cleanup;

    translatedKeycodes = g_new0(int, nkeycodes);

    /* translate keycodes to win32 and generate keyup scancodes. */
    for (i = 0; i < nkeycodes; i++) {
        if (codeset != VIR_KEYCODE_SET_WIN32) {
            keycode = virKeycodeValueTranslate(codeset,
                                               VIR_KEYCODE_SET_WIN32,
                                               keycodes[i]);

            if (keycode < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Could not translate keycode"));
                goto cleanup;
            }
            translatedKeycodes[i] = keycode;
        }
    }

    selector = g_strdup_printf("CreationClassName=Msvm_Keyboard&DeviceID=%s&"
                               "SystemCreationClassName=Msvm_ComputerSystem&"
                               "SystemName=%s", keyboard->data.common->DeviceID, uuid_string);

    /* press the keys */
    for (i = 0; i < nkeycodes; i++) {
        g_snprintf(keycodeStr, sizeof(keycodeStr), "%d", translatedKeycodes[i]);

        params = hypervCreateInvokeParamsList(priv, "PressKey", selector,
                                              Msvm_Keyboard_WmiInfo);

        if (!params)
            goto cleanup;

        if (hypervAddSimpleParam(params, "keyCode", keycodeStr) < 0)
            goto cleanup;

        if (hypervInvokeMethod(priv, &params, NULL) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, _("Could not press key %d"),
                           translatedKeycodes[i]);
            goto cleanup;
        }
    }

    /* simulate holdtime by sleeping */
    if (holdtime > 0)
        g_usleep(holdtime * 1000);

    /* release the keys */
    for (i = 0; i < nkeycodes; i++) {
        g_snprintf(keycodeStr, sizeof(keycodeStr), "%d", translatedKeycodes[i]);
        params = hypervCreateInvokeParamsList(priv, "ReleaseKey", selector,
                                              Msvm_Keyboard_WmiInfo);

        if (!params)
            goto cleanup;

        if (hypervAddSimpleParam(params, "keyCode", keycodeStr) < 0)
            goto cleanup;

        if (hypervInvokeMethod(priv, &params, NULL) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Could not release key %s"), keycodeStr);
            goto cleanup;
        }
    }

    result = 0;

 cleanup:
    VIR_FREE(translatedKeycodes);
    VIR_FREE(selector);
    hypervFreeObject(priv, (hypervObject *)keyboard);
    hypervFreeObject(priv, (hypervObject *)computerSystem);
    return result;
}


static int
hypervDomainSetMemoryFlags(virDomainPtr domain, unsigned long memory,
                           unsigned int flags)
{
    int result = -1;
    char uuid_string[VIR_UUID_STRING_BUFLEN];
    hypervPrivate *priv = domain->conn->privateData;
    char *memory_str = NULL;
    g_autoptr(hypervInvokeParamsList) params = NULL;
    unsigned long memory_mb = VIR_ROUND_UP(VIR_DIV_UP(memory, 1024), 2);
    Msvm_VirtualSystemSettingData *vssd = NULL;
    Msvm_MemorySettingData *memsd = NULL;
    g_auto(virBuffer) eprQuery = VIR_BUFFER_INITIALIZER;
    g_autoptr(virHashTable) memResource = NULL;

    virCheckFlags(0, -1);

    memory_str = g_strdup_printf("%lu", memory_mb);

    virUUIDFormat(domain->uuid, uuid_string);

    if (hypervGetMsvmVirtualSystemSettingDataFromUUID(priv, uuid_string, &vssd) < 0)
        goto cleanup;

    if (hypervGetMsvmMemorySettingDataFromVSSD(priv, vssd->data.common->InstanceID,
                                               &memsd) < 0)
        goto cleanup;

    if (priv->wmiVersion == HYPERV_WMI_VERSION_V1) {
        params = hypervCreateInvokeParamsList(priv, "ModifyVirtualSystemResources",
                                              MSVM_VIRTUALSYSTEMMANAGEMENTSERVICE_SELECTOR,
                                              Msvm_VirtualSystemManagementService_WmiInfo);

        if (!params)
            goto cleanup;

        virBufferAddLit(&eprQuery, MSVM_COMPUTERSYSTEM_WQL_SELECT);
        virBufferEscapeSQL(&eprQuery, "where Name = \"%s\"", uuid_string);

        if (hypervAddEprParam(params, "ComputerSystem", priv, &eprQuery,
                              Msvm_ComputerSystem_WmiInfo) < 0)
            goto cleanup;
    } else if (priv->wmiVersion == HYPERV_WMI_VERSION_V2) {
        params = hypervCreateInvokeParamsList(priv, "ModifyResourceSettings",
                                              MSVM_VIRTUALSYSTEMMANAGEMENTSERVICE_SELECTOR,
                                              Msvm_VirtualSystemManagementService_WmiInfo);

        if (!params)
            goto cleanup;
    }

    memResource = hypervCreateEmbeddedParam(priv, Msvm_MemorySettingData_WmiInfo);
    if (!memResource)
        goto cleanup;

    if (hypervSetEmbeddedProperty(memResource, "VirtualQuantity", memory_str) < 0)
        goto cleanup;

    if (hypervSetEmbeddedProperty(memResource, "InstanceID",
                                  memsd->data.common->InstanceID) < 0) {
        goto cleanup;
    }

    if (priv->wmiVersion == HYPERV_WMI_VERSION_V1) {
        if (hypervAddEmbeddedParam(params, priv, "ResourceSettingData",
                                   &memResource, Msvm_MemorySettingData_WmiInfo) < 0) {
            goto cleanup;
        }

    } else if (priv->wmiVersion == HYPERV_WMI_VERSION_V2) {
        if (hypervAddEmbeddedParam(params, priv, "ResourceSettings",
                                   &memResource, Msvm_MemorySettingData_WmiInfo) < 0) {
            hypervFreeEmbeddedParam(memResource);
            goto cleanup;
        }
    }

    if (hypervInvokeMethod(priv, &params, NULL) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Could not set memory"));
        goto cleanup;
    }

    result = 0;

 cleanup:
    VIR_FREE(memory_str);
    hypervFreeObject(priv, (hypervObject *)vssd);
    hypervFreeObject(priv, (hypervObject *)memsd);

    return result;
}


static int
hypervDomainSetMemory(virDomainPtr domain, unsigned long memory)
{
    return hypervDomainSetMemoryFlags(domain, memory, 0);
}


static virHypervisorDriver hypervHypervisorDriver = {
    .name = "Hyper-V",
    .connectOpen = hypervConnectOpen, /* 0.9.5 */
    .connectClose = hypervConnectClose, /* 0.9.5 */
    .connectGetType = hypervConnectGetType, /* 0.9.5 */
    .connectGetVersion = hypervConnectGetVersion, /* 6.9.0 */
    .connectGetHostname = hypervConnectGetHostname, /* 0.9.5 */
    .connectGetMaxVcpus = hypervConnectGetMaxVcpus, /* 6.9.0 */
    .nodeGetInfo = hypervNodeGetInfo, /* 0.9.5 */
    .connectGetCapabilities = hypervConnectGetCapabilities, /* 6.9.0 */
    .connectListDomains = hypervConnectListDomains, /* 0.9.5 */
    .connectNumOfDomains = hypervConnectNumOfDomains, /* 0.9.5 */
    .connectListAllDomains = hypervConnectListAllDomains, /* 0.10.2 */
    .domainLookupByID = hypervDomainLookupByID, /* 0.9.5 */
    .domainLookupByUUID = hypervDomainLookupByUUID, /* 0.9.5 */
    .domainLookupByName = hypervDomainLookupByName, /* 0.9.5 */
    .domainSuspend = hypervDomainSuspend, /* 0.9.5 */
    .domainResume = hypervDomainResume, /* 0.9.5 */
    .domainShutdown = hypervDomainShutdown, /* 6.9.0 */
    .domainShutdownFlags = hypervDomainShutdownFlags, /* 6.9.0 */
    .domainReboot = hypervDomainReboot, /* 6.9.0 */
    .domainReset = hypervDomainReset, /* 6.9.0 */
    .domainDestroy = hypervDomainDestroy, /* 0.9.5 */
    .domainDestroyFlags = hypervDomainDestroyFlags, /* 0.9.5 */
    .domainGetOSType = hypervDomainGetOSType, /* 0.9.5 */
    .domainGetInfo = hypervDomainGetInfo, /* 0.9.5 */
    .domainGetState = hypervDomainGetState, /* 0.9.5 */
    .domainGetXMLDesc = hypervDomainGetXMLDesc, /* 0.9.5 */
    .connectListDefinedDomains = hypervConnectListDefinedDomains, /* 0.9.5 */
    .connectNumOfDefinedDomains = hypervConnectNumOfDefinedDomains, /* 0.9.5 */
    .domainCreate = hypervDomainCreate, /* 0.9.5 */
    .domainCreateWithFlags = hypervDomainCreateWithFlags, /* 0.9.5 */
    .domainGetAutostart = hypervDomainGetAutostart, /* 6.9.0 */
    .domainSetAutostart = hypervDomainSetAutostart, /* 6.9.0 */
    .nodeGetFreeMemory = hypervNodeGetFreeMemory, /* 6.9.0 */
    .connectIsEncrypted = hypervConnectIsEncrypted, /* 0.9.5 */
    .connectIsSecure = hypervConnectIsSecure, /* 0.9.5 */
    .domainIsActive = hypervDomainIsActive, /* 0.9.5 */
    .domainIsPersistent = hypervDomainIsPersistent, /* 0.9.5 */
    .domainIsUpdated = hypervDomainIsUpdated, /* 0.9.5 */
    .domainManagedSave = hypervDomainManagedSave, /* 0.9.5 */
    .domainHasManagedSaveImage = hypervDomainHasManagedSaveImage, /* 0.9.5 */
    .domainManagedSaveRemove = hypervDomainManagedSaveRemove, /* 0.9.5 */
    .domainSendKey = hypervDomainSendKey, /* 3.6.0 */
    .domainSetMemory = hypervDomainSetMemory, /* 3.6.0 */
    .domainSetMemoryFlags = hypervDomainSetMemoryFlags, /* 3.6.0 */
    .connectIsAlive = hypervConnectIsAlive, /* 0.9.8 */
};


static void
hypervDebugHandler(const char *message, debug_level_e level,
                   void *user_data G_GNUC_UNUSED)
{
    switch (level) {
    case DEBUG_LEVEL_ERROR:
    case DEBUG_LEVEL_CRITICAL:
    case DEBUG_LEVEL_ALWAYS:
        VIR_ERROR(_("openwsman: %s"), message);
        break;

    case DEBUG_LEVEL_WARNING:
        VIR_WARN("openwsman: %s", message);
        break;

    case DEBUG_LEVEL_MESSAGE:
        VIR_INFO("openwsman: %s", message);
        break;

    case DEBUG_LEVEL_INFO:
        VIR_INFO("openwsman: %s", message);
        break;

    case DEBUG_LEVEL_DEBUG:
        VIR_DEBUG("openwsman: %s", message);
        break;

    case DEBUG_LEVEL_NONE:
    default:
        /* Ignore the rest */
        break;
    }
}


static virConnectDriver hypervConnectDriver = {
    .remoteOnly = true,
    .uriSchemes = (const char *[]){ "hyperv", NULL },
    .hypervisorDriver = &hypervHypervisorDriver,
};

int
hypervRegister(void)
{
    /* Forward openwsman errors and warnings to libvirt's logging */
    debug_add_handler(hypervDebugHandler, DEBUG_LEVEL_WARNING, NULL);

    return virRegisterConnectDriver(&hypervConnectDriver,
                                    false);
}
