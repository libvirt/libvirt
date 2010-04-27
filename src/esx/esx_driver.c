
/*
 * esx_driver.c: core driver functions for managing VMware ESX hosts
 *
 * Copyright (C) 2010 Red Hat, Inc.
 * Copyright (C) 2009-2010 Matthias Bolte <matthias.bolte@googlemail.com>
 * Copyright (C) 2009 Maximilian Wilhelm <max@rfc2324.org>
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
 */

#include <config.h>

#include <netdb.h>

#include "internal.h"
#include "domain_conf.h"
#include "authhelper.h"
#include "util.h"
#include "memory.h"
#include "logging.h"
#include "uuid.h"
#include "esx_driver.h"
#include "esx_interface_driver.h"
#include "esx_network_driver.h"
#include "esx_storage_driver.h"
#include "esx_device_monitor.h"
#include "esx_secret_driver.h"
#include "esx_nwfilter_driver.h"
#include "esx_private.h"
#include "esx_vi.h"
#include "esx_vi_methods.h"
#include "esx_util.h"
#include "esx_vmx.h"

#define VIR_FROM_THIS VIR_FROM_ESX

static int esxDomainGetMaxVcpus(virDomainPtr domain);



static esxVI_Boolean
esxSupportsLongMode(esxPrivate *priv)
{
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *hostSystem = NULL;
    esxVI_DynamicProperty *dynamicProperty = NULL;
    esxVI_HostCpuIdInfo *hostCpuIdInfoList = NULL;
    esxVI_HostCpuIdInfo *hostCpuIdInfo = NULL;
    esxVI_ParsedHostCpuIdInfo parsedHostCpuIdInfo;
    char edxLongModeBit = '?';

    if (priv->supportsLongMode != esxVI_Boolean_Undefined) {
        return priv->supportsLongMode;
    }

    if (esxVI_EnsureSession(priv->host) < 0) {
        goto failure;
    }

    if (esxVI_String_AppendValueToList(&propertyNameList,
                                       "hardware.cpuFeature") < 0 ||
        esxVI_LookupObjectContentByType(priv->host, priv->host->hostFolder,
                                        "HostSystem", propertyNameList,
                                        esxVI_Boolean_True, &hostSystem) < 0) {
        goto failure;
    }

    if (hostSystem == NULL) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                  _("Could not retrieve the HostSystem object"));
        goto failure;
    }

    for (dynamicProperty = hostSystem->propSet; dynamicProperty != NULL;
         dynamicProperty = dynamicProperty->_next) {
        if (STREQ(dynamicProperty->name, "hardware.cpuFeature")) {
            if (esxVI_HostCpuIdInfo_CastListFromAnyType
                  (dynamicProperty->val, &hostCpuIdInfoList) < 0) {
                goto failure;
            }

            for (hostCpuIdInfo = hostCpuIdInfoList; hostCpuIdInfo != NULL;
                 hostCpuIdInfo = hostCpuIdInfo->_next) {
                if (hostCpuIdInfo->level->value == -2147483647) { /* 0x80000001 */
                    if (esxVI_ParseHostCpuIdInfo(&parsedHostCpuIdInfo,
                                                 hostCpuIdInfo) < 0) {
                        goto failure;
                    }

                    edxLongModeBit = parsedHostCpuIdInfo.edx[29];

                    if (edxLongModeBit == '1') {
                        priv->supportsLongMode = esxVI_Boolean_True;
                    } else if (edxLongModeBit == '0') {
                        priv->supportsLongMode = esxVI_Boolean_False;
                    } else {
                        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                                  _("Bit 29 (Long Mode) of HostSystem property "
                                    "'hardware.cpuFeature[].edx' with value '%s' "
                                    "has unexpected value '%c', expecting '0' "
                                    "or '1'"), hostCpuIdInfo->edx, edxLongModeBit);
                        goto failure;
                    }

                    break;
                }
            }

            break;
        } else {
            VIR_WARN("Unexpected '%s' property", dynamicProperty->name);
        }
    }

  cleanup:
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&hostSystem);
    esxVI_HostCpuIdInfo_Free(&hostCpuIdInfoList);

    return priv->supportsLongMode;

  failure:
    priv->supportsLongMode = esxVI_Boolean_Undefined;

    goto cleanup;
}



static virCapsPtr
esxCapsInit(esxPrivate *priv)
{
    esxVI_Boolean supportsLongMode = esxSupportsLongMode(priv);
    virCapsPtr caps = NULL;
    virCapsGuestPtr guest = NULL;

    if (supportsLongMode == esxVI_Boolean_Undefined) {
        return NULL;
    }

    if (supportsLongMode == esxVI_Boolean_True) {
        caps = virCapabilitiesNew("x86_64", 1, 1);
    } else {
        caps = virCapabilitiesNew("i686", 1, 1);
    }

    if (caps == NULL) {
        virReportOOMError();
        return NULL;
    }

    virCapabilitiesSetMacPrefix(caps, (unsigned char[]){ 0x00, 0x0c, 0x29 });
    virCapabilitiesAddHostMigrateTransport(caps, "esx");

    /* i686 */
    guest = virCapabilitiesAddGuest(caps, "hvm", "i686", 32, NULL, NULL, 0,
                                    NULL);

    if (guest == NULL) {
        goto failure;
    }

    /*
     * FIXME: Maybe distinguish betwen ESX and GSX here, see
     * esxVMX_ParseConfig() and VIR_DOMAIN_VIRT_VMWARE
     */
    if (virCapabilitiesAddGuestDomain(guest, "vmware", NULL, NULL, 0,
                                      NULL) == NULL) {
        goto failure;
    }

    /* x86_64 */
    if (supportsLongMode == esxVI_Boolean_True) {
        guest = virCapabilitiesAddGuest(caps, "hvm", "x86_64", 64, NULL, NULL,
                                        0, NULL);

        if (guest == NULL) {
            goto failure;
        }

        /*
         * FIXME: Maybe distinguish betwen ESX and GSX here, see
         * esxVMX_ParseConfig() and VIR_DOMAIN_VIRT_VMWARE
         */
        if (virCapabilitiesAddGuestDomain(guest, "vmware", NULL, NULL, 0,
                                          NULL) == NULL) {
            goto failure;
        }
    }

    return caps;

  failure:
    virCapabilitiesFree(caps);

    return NULL;
}



/*
 * URI format: {esx|gsx}://[<user>@]<server>[:<port>]/[<query parameter> ...]
 *
 * If no port is specified the default port is set dependent on the scheme and
 * transport parameter:
 * - esx+http  80
 * - esx+https 443
 * - gsx+http  8222
 * - gsx+https 8333
 *
 * Optional query parameters:
 * - transport={http|https}
 * - vcenter={<vcenter>|*}
 * - no_verify={0|1}
 * - auto_answer={0|1}
 *
 * If no transport parameter is specified https is used.
 *
 * The vcenter parameter is only necessary for migration, because the vCenter
 * server is in charge to initiate a migration between two ESX hosts. The
 * vcenter parameter can be set to an explicity hostname or to *. If set to *,
 * the driver will check if the ESX host is managed by a vCenter and connect to
 * it. If the ESX host is not managed by a vCenter an error is reported.
 *
 * If the no_verify parameter is set to 1, this disables libcurl client checks
 * of the server's certificate. The default value it 0.
 *
 * If the auto_answer parameter is set to 1, the driver will respond to all
 * virtual machine questions with the default answer, otherwise virtual machine
 * questions will be reported as errors. The default value it 0.
 */
static virDrvOpenStatus
esxOpen(virConnectPtr conn, virConnectAuthPtr auth, int flags ATTRIBUTE_UNUSED)
{
    virDrvOpenStatus result = VIR_DRV_OPEN_SUCCESS;
    esxPrivate *priv = NULL;
    char hostIpAddress[NI_MAXHOST] = "";
    char vCenterIpAddress[NI_MAXHOST] = "";
    char *url = NULL;
    char *vCenter = NULL;
    int noVerify = 0; // boolean
    int autoAnswer = 0; // boolean
    char *username = NULL;
    char *password = NULL;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *hostSystem = NULL;
    esxVI_DynamicProperty *dynamicProperty = NULL;

    /* Decline if the URI is NULL or the scheme is neither 'esx' nor 'gsx' */
    if (conn->uri == NULL || conn->uri->scheme == NULL ||
        (STRCASENEQ(conn->uri->scheme, "esx") &&
         STRCASENEQ(conn->uri->scheme, "gsx"))) {
        return VIR_DRV_OPEN_DECLINED;
    }

    /* Decline URIs without server part, or missing auth */
    if (conn->uri->server == NULL || auth == NULL || auth->cb == NULL) {
        return VIR_DRV_OPEN_DECLINED;
    }

    if (conn->uri->path != NULL && STRNEQ(conn->uri->path, "") &&
        STRNEQ(conn->uri->path, "/")) {
        VIR_WARN("Ignoring unexpected path '%s' in URI", conn->uri->path);
    }

    /* Allocate per-connection private data */
    if (VIR_ALLOC(priv) < 0) {
        virReportOOMError();
        goto failure;
    }

    priv->maxVcpus = -1;
    priv->supportsVMotion = esxVI_Boolean_Undefined;
    priv->supportsLongMode = esxVI_Boolean_Undefined;
    priv->autoAnswer = esxVI_Boolean_False;
    priv->usedCpuTimeCounterId = -1;

    if (esxUtil_ParseQuery(conn->uri, &priv->transport, &vCenter, &noVerify,
                           &autoAnswer) < 0) {
        goto failure;
    }

    if (autoAnswer) {
        priv->autoAnswer = esxVI_Boolean_True;
    }

    /*
     * Set the port dependent on the transport protocol if no port is
     * specified. This allows us to rely on the port parameter being
     * correctly set when building URIs later on, without the need to
     * distinguish between the situations port == 0 and port != 0
     */
    if (conn->uri->port == 0) {
        if (STRCASEEQ(conn->uri->scheme, "esx")) {
            if (STRCASEEQ(priv->transport, "https")) {
                conn->uri->port = 443;
            } else {
                conn->uri->port = 80;
            }
        } else { /* GSX */
            if (STRCASEEQ(priv->transport, "https")) {
                conn->uri->port = 8333;
            } else {
                conn->uri->port = 8222;
            }
        }
    }

    /* Login to host */
    if (esxUtil_ResolveHostname(conn->uri->server, hostIpAddress,
                                NI_MAXHOST) < 0) {
        goto failure;
    }

    if (virAsprintf(&url, "%s://%s:%d/sdk", priv->transport,
                    conn->uri->server, conn->uri->port) < 0) {
        virReportOOMError();
        goto failure;
    }

    if (conn->uri->user != NULL) {
        username = strdup(conn->uri->user);

        if (username == NULL) {
            virReportOOMError();
            goto failure;
        }
    } else {
        username = virRequestUsername(auth, "root", conn->uri->server);

        if (username == NULL) {
            ESX_ERROR(VIR_ERR_AUTH_FAILED, "%s", _("Username request failed"));
            goto failure;
        }
    }

    if (esxVI_Context_Alloc(&priv->host) < 0) {
        goto failure;
    }

    password = virRequestPassword(auth, username, conn->uri->server);

    if (password == NULL) {
        ESX_ERROR(VIR_ERR_AUTH_FAILED, "%s", _("Password request failed"));
        goto failure;
    }

    if (esxVI_Context_Connect(priv->host, url, hostIpAddress, username,
                              password, noVerify) < 0) {
        goto failure;
    }

    if (STRCASEEQ(conn->uri->scheme, "esx")) {
        if (priv->host->productVersion != esxVI_ProductVersion_ESX35 &&
            priv->host->productVersion != esxVI_ProductVersion_ESX40) {
            ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                      _("%s is neither an ESX 3.5 host nor an ESX 4.0 host"),
                      conn->uri->server);
            goto failure;
        }
    } else { /* GSX */
        if (priv->host->productVersion != esxVI_ProductVersion_GSX20) {
            ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                      _("%s isn't a GSX 2.0 host"), conn->uri->server);
            goto failure;
        }
    }

    /* Query the host for maintenance mode and vCenter IP address */
    if (esxVI_String_AppendValueListToList(&propertyNameList,
                                           "runtime.inMaintenanceMode\0"
                                           "summary.managementServerIp\0") < 0 ||
        esxVI_LookupHostSystemByIp(priv->host, hostIpAddress, propertyNameList,
                                   &hostSystem) < 0) {
        goto failure;
    }

    /* Warn if host is in maintenance mode */
    for (dynamicProperty = hostSystem->propSet; dynamicProperty != NULL;
         dynamicProperty = dynamicProperty->_next) {
        if (STREQ(dynamicProperty->name, "runtime.inMaintenanceMode")) {
            if (esxVI_AnyType_ExpectType(dynamicProperty->val,
                                         esxVI_Type_Boolean) < 0) {
                goto failure;
            }

            if (dynamicProperty->val->boolean == esxVI_Boolean_True) {
                VIR_WARN0("The server is in maintenance mode");
            }

            break;
        }
    }

    /* Login to vCenter */
    if (vCenter != NULL) {
        VIR_FREE(url);
        VIR_FREE(password);
        VIR_FREE(username);

        /* If a vCenter is specified resolve the hostname */
        if (STRNEQ(vCenter, "*") &&
            esxUtil_ResolveHostname(vCenter, vCenterIpAddress,
                                    NI_MAXHOST) < 0) {
            goto failure;
        }

        /* Lookup the vCenter from the ESX host */
        for (dynamicProperty = hostSystem->propSet; dynamicProperty != NULL;
             dynamicProperty = dynamicProperty->_next) {
            if (STREQ(dynamicProperty->name, "summary.managementServerIp")) {
                if (esxVI_AnyType_ExpectType(dynamicProperty->val,
                                             esxVI_Type_String) < 0) {
                    goto failure;
                }

                /* Get the vCenter IP address or verify the specified one */
                if (STREQ(vCenter, "*")) {
                    VIR_FREE(vCenter);

                    vCenter = strdup(dynamicProperty->val->string);

                    if (vCenter == NULL) {
                        virReportOOMError();
                        goto failure;
                    }

                    if (virStrcpyStatic(vCenterIpAddress,
                                        dynamicProperty->val->string) == NULL) {
                        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                                  _("vCenter IP address %s too big for "
                                    "destination"),
                                  dynamicProperty->val->string);
                        goto failure;
                    }
                } else if (STRNEQ(vCenterIpAddress,
                           dynamicProperty->val->string)) {
                    ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                              _("This host is managed by a vCenter with IP "
                                "address %s, but a mismachting vCenter '%s' "
                                "(%s) has been specified"),
                              dynamicProperty->val->string, vCenter,
                              vCenterIpAddress);
                    goto failure;
                }

                break;
            }
        }

        if (STREQ(vCenter, "*")) {
            ESX_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                      _("This host is not managed by a vCenter"));
            goto failure;
        }

        if (virAsprintf(&url, "%s://%s/sdk", priv->transport,
                        vCenter) < 0) {
            virReportOOMError();
            goto failure;
        }

        if (esxVI_Context_Alloc(&priv->vCenter) < 0) {
            goto failure;
        }

        username = virRequestUsername(auth, "administrator", vCenter);

        if (username == NULL) {
            ESX_ERROR(VIR_ERR_AUTH_FAILED, "%s", _("Username request failed"));
            goto failure;
        }

        password = virRequestPassword(auth, username, vCenter);

        if (password == NULL) {
            ESX_ERROR(VIR_ERR_AUTH_FAILED, "%s", _("Password request failed"));
            goto failure;
        }

        if (esxVI_Context_Connect(priv->vCenter, url, vCenterIpAddress,
                                  username, password, noVerify) < 0) {
            goto failure;
        }

        if (priv->vCenter->productVersion != esxVI_ProductVersion_VPX25 &&
            priv->vCenter->productVersion != esxVI_ProductVersion_VPX40) {
            ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                      _("%s is neither a vCenter 2.5 server nor a vCenter "
                        "4.0 server"), conn->uri->server);
            goto failure;
        }
    }

    conn->privateData = priv;

    /* Setup capabilities */
    priv->caps = esxCapsInit(priv);

    if (priv->caps == NULL) {
        goto failure;
    }

  cleanup:
    VIR_FREE(url);
    VIR_FREE(vCenter);
    VIR_FREE(password);
    VIR_FREE(username);
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&hostSystem);

    return result;

  failure:
    if (priv != NULL) {
        esxVI_Context_Free(&priv->host);
        esxVI_Context_Free(&priv->vCenter);

        virCapabilitiesFree(priv->caps);

        VIR_FREE(priv->transport);
        VIR_FREE(priv);
    }

    result = VIR_DRV_OPEN_ERROR;

    goto cleanup;
}



static int
esxClose(virConnectPtr conn)
{
    esxPrivate *priv = conn->privateData;
    int result = 0;

    if (esxVI_EnsureSession(priv->host) < 0 ||
        esxVI_Logout(priv->host) < 0) {
        result = -1;
    }

    esxVI_Context_Free(&priv->host);

    if (priv->vCenter != NULL) {
        if (esxVI_EnsureSession(priv->vCenter) < 0 ||
            esxVI_Logout(priv->vCenter) < 0) {
            result = -1;
        }

        esxVI_Context_Free(&priv->vCenter);
    }

    virCapabilitiesFree(priv->caps);

    VIR_FREE(priv->transport);
    VIR_FREE(priv);

    conn->privateData = NULL;

    return result;
}



static esxVI_Boolean
esxSupportsVMotion(esxPrivate *priv)
{
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *hostSystem = NULL;
    esxVI_DynamicProperty *dynamicProperty = NULL;

    if (priv->supportsVMotion != esxVI_Boolean_Undefined) {
        return priv->supportsVMotion;
    }

    if (esxVI_EnsureSession(priv->host) < 0) {
        goto failure;
    }

    if (esxVI_String_AppendValueToList(&propertyNameList,
                                       "capability.vmotionSupported") < 0 ||
        esxVI_LookupObjectContentByType(priv->host, priv->host->hostFolder,
                                        "HostSystem", propertyNameList,
                                        esxVI_Boolean_True, &hostSystem) < 0) {
        goto failure;
    }

    if (hostSystem == NULL) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                  _("Could not retrieve the HostSystem object"));
        goto failure;
    }

    for (dynamicProperty = hostSystem->propSet; dynamicProperty != NULL;
         dynamicProperty = dynamicProperty->_next) {
        if (STREQ(dynamicProperty->name, "capability.vmotionSupported")) {
            if (esxVI_AnyType_ExpectType(dynamicProperty->val,
                                         esxVI_Type_Boolean) < 0) {
                goto failure;
            }

            priv->supportsVMotion = dynamicProperty->val->boolean;
            break;
        } else {
            VIR_WARN("Unexpected '%s' property", dynamicProperty->name);
        }
    }

  cleanup:
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&hostSystem);

    return priv->supportsVMotion;

  failure:
    priv->supportsVMotion = esxVI_Boolean_Undefined;

    goto cleanup;
}



static int
esxSupportsFeature(virConnectPtr conn, int feature)
{
    esxPrivate *priv = conn->privateData;
    esxVI_Boolean supportsVMotion = esxVI_Boolean_Undefined;

    switch (feature) {
      case VIR_DRV_FEATURE_MIGRATION_V1:
        supportsVMotion = esxSupportsVMotion(priv);

        if (supportsVMotion == esxVI_Boolean_Undefined) {
            return -1;
        }

        /* Migration is only possible via a vCenter and if VMotion is enabled */
        return priv->vCenter != NULL &&
               supportsVMotion == esxVI_Boolean_True ? 1 : 0;

      default:
        return 0;
    }
}



static const char *
esxGetType(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    return "ESX";
}



static int
esxGetVersion(virConnectPtr conn, unsigned long *version)
{
    esxPrivate *priv = conn->privateData;

    if (virParseVersionString(priv->host->service->about->version,
                              version) < 0) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  _("Could not parse version number from '%s'"),
                  priv->host->service->about->version);

        return -1;
    }

    return 0;
}



static char *
esxGetHostname(virConnectPtr conn)
{
    esxPrivate *priv = conn->privateData;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *hostSystem = NULL;
    esxVI_DynamicProperty *dynamicProperty = NULL;
    const char *hostName = NULL;
    const char *domainName = NULL;
    char *complete = NULL;

    if (esxVI_EnsureSession(priv->host) < 0) {
        goto failure;
    }

    if (esxVI_String_AppendValueListToList
          (&propertyNameList,
           "config.network.dnsConfig.hostName\0"
           "config.network.dnsConfig.domainName\0") < 0 ||
        esxVI_LookupObjectContentByType(priv->host, priv->host->hostFolder,
                                        "HostSystem", propertyNameList,
                                        esxVI_Boolean_True, &hostSystem) < 0) {
        goto failure;
    }

    if (hostSystem == NULL) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                  _("Could not retrieve the HostSystem object"));
        goto failure;
    }

    for (dynamicProperty = hostSystem->propSet; dynamicProperty != NULL;
         dynamicProperty = dynamicProperty->_next) {
        if (STREQ(dynamicProperty->name,
                  "config.network.dnsConfig.hostName")) {
            if (esxVI_AnyType_ExpectType(dynamicProperty->val,
                                         esxVI_Type_String) < 0) {
                goto failure;
            }

            hostName = dynamicProperty->val->string;
        } else if (STREQ(dynamicProperty->name,
                         "config.network.dnsConfig.domainName")) {
            if (esxVI_AnyType_ExpectType(dynamicProperty->val,
                                         esxVI_Type_String) < 0) {
                goto failure;
            }

            domainName = dynamicProperty->val->string;
        } else {
            VIR_WARN("Unexpected '%s' property", dynamicProperty->name);
        }
    }

    if (hostName == NULL || strlen(hostName) < 1) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                  _("Missing or empty 'hostName' property"));
        goto failure;
    }

    if (domainName == NULL || strlen(domainName) < 1) {
        complete = strdup(hostName);

        if (complete == NULL) {
            virReportOOMError();
            goto failure;
        }
    } else {
        if (virAsprintf(&complete, "%s.%s", hostName, domainName) < 0) {
            virReportOOMError();
            goto failure;
        }
    }

  cleanup:
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&hostSystem);

    return complete;

  failure:
    VIR_FREE(complete);

    goto cleanup;
}



static int
esxNodeGetInfo(virConnectPtr conn, virNodeInfoPtr nodeinfo)
{
    int result = 0;
    esxPrivate *priv = conn->privateData;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *hostSystem = NULL;
    esxVI_DynamicProperty *dynamicProperty = NULL;
    int64_t cpuInfo_hz = 0;
    int16_t cpuInfo_numCpuCores = 0;
    int16_t cpuInfo_numCpuPackages = 0;
    int16_t cpuInfo_numCpuThreads = 0;
    int64_t memorySize = 0;
    int32_t numaInfo_numNodes = 0;
    char *ptr = NULL;

    memset(nodeinfo, 0, sizeof(virNodeInfo));

    if (esxVI_EnsureSession(priv->host) < 0) {
        goto failure;
    }

    if (esxVI_String_AppendValueListToList(&propertyNameList,
                                           "hardware.cpuInfo.hz\0"
                                           "hardware.cpuInfo.numCpuCores\0"
                                           "hardware.cpuInfo.numCpuPackages\0"
                                           "hardware.cpuInfo.numCpuThreads\0"
                                           "hardware.memorySize\0"
                                           "hardware.numaInfo.numNodes\0"
                                           "summary.hardware.cpuModel\0") < 0 ||
        esxVI_LookupObjectContentByType(priv->host, priv->host->hostFolder,
                                        "HostSystem", propertyNameList,
                                        esxVI_Boolean_True, &hostSystem) < 0) {
        goto failure;
    }

    if (hostSystem == NULL) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                  _("Could not retrieve the HostSystem object"));
        goto failure;
    }

    for (dynamicProperty = hostSystem->propSet; dynamicProperty != NULL;
         dynamicProperty = dynamicProperty->_next) {
        if (STREQ(dynamicProperty->name, "hardware.cpuInfo.hz")) {
            if (esxVI_AnyType_ExpectType(dynamicProperty->val,
                                         esxVI_Type_Long) < 0) {
                goto failure;
            }

            cpuInfo_hz = dynamicProperty->val->int64;
        } else if (STREQ(dynamicProperty->name,
                         "hardware.cpuInfo.numCpuCores")) {
            if (esxVI_AnyType_ExpectType(dynamicProperty->val,
                                         esxVI_Type_Short) < 0) {
                goto failure;
            }

            cpuInfo_numCpuCores = dynamicProperty->val->int16;
        } else if (STREQ(dynamicProperty->name,
                         "hardware.cpuInfo.numCpuPackages")) {
            if (esxVI_AnyType_ExpectType(dynamicProperty->val,
                                         esxVI_Type_Short) < 0) {
                goto failure;
            }

            cpuInfo_numCpuPackages = dynamicProperty->val->int16;
        } else if (STREQ(dynamicProperty->name,
                         "hardware.cpuInfo.numCpuThreads")) {
            if (esxVI_AnyType_ExpectType(dynamicProperty->val,
                                         esxVI_Type_Short) < 0) {
                goto failure;
            }

            cpuInfo_numCpuThreads = dynamicProperty->val->int16;
        } else if (STREQ(dynamicProperty->name, "hardware.memorySize")) {
            if (esxVI_AnyType_ExpectType(dynamicProperty->val,
                                         esxVI_Type_Long) < 0) {
                goto failure;
            }

            memorySize = dynamicProperty->val->int64;
        } else if (STREQ(dynamicProperty->name,
                         "hardware.numaInfo.numNodes")) {
            if (esxVI_AnyType_ExpectType(dynamicProperty->val,
                                         esxVI_Type_Int) < 0) {
                goto failure;
            }

            numaInfo_numNodes = dynamicProperty->val->int32;
        } else if (STREQ(dynamicProperty->name,
                         "summary.hardware.cpuModel")) {
            if (esxVI_AnyType_ExpectType(dynamicProperty->val,
                                         esxVI_Type_String) < 0) {
                goto failure;
            }

            ptr = dynamicProperty->val->string;

            /* Strip the string to fit more relevant information in 32 chars */
            while (*ptr != '\0') {
                if (STRPREFIX(ptr, "  ")) {
                    memmove(ptr, ptr + 1, strlen(ptr + 1) + 1);
                    continue;
                } else if (STRPREFIX(ptr, "(R)") || STRPREFIX(ptr, "(C)")) {
                    memmove(ptr, ptr + 3, strlen(ptr + 3) + 1);
                    continue;
                } else if (STRPREFIX(ptr, "(TM)")) {
                    memmove(ptr, ptr + 4, strlen(ptr + 4) + 1);
                    continue;
                }

                ++ptr;
            }

            if (virStrncpy(nodeinfo->model, dynamicProperty->val->string,
                           sizeof(nodeinfo->model) - 1,
                           sizeof(nodeinfo->model)) == NULL) {
                ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                          _("CPU Model %s too long for destination"),
                          dynamicProperty->val->string);
                goto failure;
            }
        } else {
            VIR_WARN("Unexpected '%s' property", dynamicProperty->name);
        }
    }

    nodeinfo->memory = memorySize / 1024; /* Scale from bytes to kilobytes */
    nodeinfo->cpus = cpuInfo_numCpuCores;
    nodeinfo->mhz = cpuInfo_hz / (1000 * 1000); /* Scale from hz to mhz */
    nodeinfo->nodes = numaInfo_numNodes;
    nodeinfo->sockets = cpuInfo_numCpuPackages;
    nodeinfo->cores = cpuInfo_numCpuPackages > 0
                        ? cpuInfo_numCpuCores / cpuInfo_numCpuPackages
                        : 0;
    nodeinfo->threads = cpuInfo_numCpuCores > 0
                          ? cpuInfo_numCpuThreads / cpuInfo_numCpuCores
                          : 0;

  cleanup:
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&hostSystem);

    return result;

  failure:
    result = -1;

    goto cleanup;
}



static char *
esxGetCapabilities(virConnectPtr conn)
{
    esxPrivate *priv = conn->privateData;
    char *xml = virCapabilitiesFormatXML(priv->caps);

    if (xml == NULL) {
        virReportOOMError();
        return NULL;
    }

    return xml;
}



static int
esxListDomains(virConnectPtr conn, int *ids, int maxids)
{
    esxPrivate *priv = conn->privateData;
    esxVI_ObjectContent *virtualMachineList = NULL;
    esxVI_ObjectContent *virtualMachine = NULL;
    esxVI_String *propertyNameList = NULL;
    esxVI_VirtualMachinePowerState powerState;
    int count = 0;

    if (ids == NULL || maxids < 0) {
        ESX_ERROR(VIR_ERR_INVALID_ARG, "%s", _("Invalid argument"));
        return -1;
    }

    if (maxids == 0) {
        return 0;
    }

    if (esxVI_EnsureSession(priv->host) < 0) {
        goto failure;
    }

    if (esxVI_String_AppendValueToList(&propertyNameList,
                                       "runtime.powerState") < 0 ||
        esxVI_LookupObjectContentByType(priv->host, priv->host->vmFolder,
                                        "VirtualMachine", propertyNameList,
                                        esxVI_Boolean_True,
                                        &virtualMachineList) < 0) {
        goto failure;
    }

    for (virtualMachine = virtualMachineList; virtualMachine != NULL;
         virtualMachine = virtualMachine->_next) {
        if (esxVI_GetVirtualMachinePowerState(virtualMachine,
                                              &powerState) < 0) {
            goto failure;
        }

        if (powerState != esxVI_VirtualMachinePowerState_PoweredOn) {
            continue;
        }

        if (esxUtil_ParseVirtualMachineIDString(virtualMachine->obj->value,
                                                &ids[count]) < 0 ||
            ids[count] <= 0) {
            ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                      _("Failed to parse positive integer from '%s'"),
                      virtualMachine->obj->value);
            goto failure;
        }

        count++;

        if (count >= maxids) {
            break;
        }
    }

  cleanup:
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&virtualMachineList);

    return count;

  failure:
    count = -1;

    goto cleanup;
}



static int
esxNumberOfDomains(virConnectPtr conn)
{
    esxPrivate *priv = conn->privateData;

    if (esxVI_EnsureSession(priv->host) < 0) {
        return -1;
    }

    return esxVI_LookupNumberOfDomainsByPowerState
             (priv->host, esxVI_VirtualMachinePowerState_PoweredOn,
              esxVI_Boolean_False);
}



static virDomainPtr
esxDomainLookupByID(virConnectPtr conn, int id)
{
    esxPrivate *priv = conn->privateData;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *virtualMachineList = NULL;
    esxVI_ObjectContent *virtualMachine = NULL;
    esxVI_VirtualMachinePowerState powerState;
    int id_candidate = -1;
    char *name_candidate = NULL;
    unsigned char uuid_candidate[VIR_UUID_BUFLEN];
    virDomainPtr domain = NULL;

    if (esxVI_EnsureSession(priv->host) < 0) {
        goto failure;
    }

    if (esxVI_String_AppendValueListToList(&propertyNameList,
                                           "configStatus\0"
                                           "name\0"
                                           "runtime.powerState\0"
                                           "config.uuid\0") < 0 ||
        esxVI_LookupObjectContentByType(priv->host, priv->host->vmFolder,
                                        "VirtualMachine", propertyNameList,
                                        esxVI_Boolean_True,
                                        &virtualMachineList) < 0) {
        goto failure;
    }

    for (virtualMachine = virtualMachineList; virtualMachine != NULL;
         virtualMachine = virtualMachine->_next) {
        if (esxVI_GetVirtualMachinePowerState(virtualMachine,
                                              &powerState) < 0) {
            goto failure;
        }

        /* Only running/suspended domains have an ID != -1 */
        if (powerState == esxVI_VirtualMachinePowerState_PoweredOff) {
            continue;
        }

        VIR_FREE(name_candidate);

        if (esxVI_GetVirtualMachineIdentity(virtualMachine,
                                            &id_candidate, &name_candidate,
                                            uuid_candidate) < 0) {
            goto failure;
        }

        if (id != id_candidate) {
            continue;
        }

        domain = virGetDomain(conn, name_candidate, uuid_candidate);

        if (domain == NULL) {
            goto failure;
        }

        domain->id = id;

        break;
    }

    if (domain == NULL) {
        ESX_ERROR(VIR_ERR_NO_DOMAIN, _("No domain with ID %d"), id);
    }

  cleanup:
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&virtualMachineList);
    VIR_FREE(name_candidate);

    return domain;

  failure:
    domain = NULL;

    goto cleanup;
}



static virDomainPtr
esxDomainLookupByUUID(virConnectPtr conn, const unsigned char *uuid)
{
    esxPrivate *priv = conn->privateData;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *virtualMachine = NULL;
    esxVI_VirtualMachinePowerState powerState;
    int id = -1;
    char *name = NULL;
    virDomainPtr domain = NULL;

    if (esxVI_EnsureSession(priv->host) < 0) {
        goto failure;
    }

    if (esxVI_String_AppendValueListToList(&propertyNameList,
                                           "name\0"
                                           "runtime.powerState\0") < 0 ||
        esxVI_LookupVirtualMachineByUuid(priv->host, uuid, propertyNameList,
                                         &virtualMachine,
                                         esxVI_Occurrence_RequiredItem) < 0 ||
        esxVI_GetVirtualMachineIdentity(virtualMachine, &id, &name, NULL) < 0 ||
        esxVI_GetVirtualMachinePowerState(virtualMachine, &powerState) < 0) {
        goto failure;
    }

    domain = virGetDomain(conn, name, uuid);

    if (domain == NULL) {
        goto failure;
    }

    /* Only running/suspended virtual machines have an ID != -1 */
    if (powerState != esxVI_VirtualMachinePowerState_PoweredOff) {
        domain->id = id;
    } else {
        domain->id = -1;
    }

  cleanup:
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&virtualMachine);
    VIR_FREE(name);

    return domain;

  failure:
    domain = NULL;

    goto cleanup;
}



static virDomainPtr
esxDomainLookupByName(virConnectPtr conn, const char *name)
{
    esxPrivate *priv = conn->privateData;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *virtualMachine = NULL;
    esxVI_VirtualMachinePowerState powerState;
    int id = -1;
    unsigned char uuid[VIR_UUID_BUFLEN];
    virDomainPtr domain = NULL;

    if (esxVI_EnsureSession(priv->host) < 0) {
        goto failure;
    }

    if (esxVI_String_AppendValueListToList(&propertyNameList,
                                           "configStatus\0"
                                           "runtime.powerState\0"
                                           "config.uuid\0") < 0 ||
        esxVI_LookupVirtualMachineByName(priv->host, name, propertyNameList,
                                         &virtualMachine,
                                         esxVI_Occurrence_OptionalItem) < 0) {
        goto failure;
    }

    if (virtualMachine == NULL) {
        ESX_ERROR(VIR_ERR_NO_DOMAIN, _("No domain with name '%s'"), name);
        goto failure;
    }


    if (esxVI_GetVirtualMachineIdentity(virtualMachine, &id, NULL, uuid) < 0) {
        goto failure;
    }

    if (esxVI_GetVirtualMachinePowerState(virtualMachine,
                                          &powerState) < 0) {
        goto failure;
    }

    domain = virGetDomain(conn, name, uuid);

    if (domain == NULL) {
        goto failure;
    }

    /* Only running/suspended virtual machines have an ID != -1 */
    if (powerState != esxVI_VirtualMachinePowerState_PoweredOff) {
        domain->id = id;
    } else {
        domain->id = -1;
    }

  cleanup:
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&virtualMachine);

    return domain;

  failure:
    domain = NULL;

    goto cleanup;
}



static int
esxDomainSuspend(virDomainPtr domain)
{
    int result = 0;
    esxPrivate *priv = domain->conn->privateData;
    esxVI_ObjectContent *virtualMachine = NULL;
    esxVI_String *propertyNameList = NULL;
    esxVI_VirtualMachinePowerState powerState;
    esxVI_ManagedObjectReference *task = NULL;
    esxVI_TaskInfoState taskInfoState;

    if (esxVI_EnsureSession(priv->host) < 0) {
        goto failure;
    }

    if (esxVI_String_AppendValueToList(&propertyNameList,
                                       "runtime.powerState") < 0 ||
        esxVI_LookupVirtualMachineByUuidAndPrepareForTask
          (priv->host, domain->uuid, propertyNameList, &virtualMachine,
           priv->autoAnswer) < 0 ||
        esxVI_GetVirtualMachinePowerState(virtualMachine, &powerState) < 0) {
        goto failure;
    }

    if (powerState != esxVI_VirtualMachinePowerState_PoweredOn) {
        ESX_ERROR(VIR_ERR_OPERATION_INVALID, "%s",
                  _("Domain is not powered on"));
        goto failure;
    }

    if (esxVI_SuspendVM_Task(priv->host, virtualMachine->obj, &task) < 0 ||
        esxVI_WaitForTaskCompletion(priv->host, task, domain->uuid,
                                    priv->autoAnswer, &taskInfoState) < 0) {
        goto failure;
    }

    if (taskInfoState != esxVI_TaskInfoState_Success) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Could not suspend domain"));
        goto failure;
    }

  cleanup:
    esxVI_ObjectContent_Free(&virtualMachine);
    esxVI_String_Free(&propertyNameList);
    esxVI_ManagedObjectReference_Free(&task);

    return result;

  failure:
    result = -1;

    goto cleanup;
}



static int
esxDomainResume(virDomainPtr domain)
{
    int result = 0;
    esxPrivate *priv = domain->conn->privateData;
    esxVI_ObjectContent *virtualMachine = NULL;
    esxVI_String *propertyNameList = NULL;
    esxVI_VirtualMachinePowerState powerState;
    esxVI_ManagedObjectReference *task = NULL;
    esxVI_TaskInfoState taskInfoState;

    if (esxVI_EnsureSession(priv->host) < 0) {
        goto failure;
    }

    if (esxVI_String_AppendValueToList(&propertyNameList,
                                       "runtime.powerState") < 0 ||
        esxVI_LookupVirtualMachineByUuidAndPrepareForTask
          (priv->host, domain->uuid, propertyNameList, &virtualMachine,
           priv->autoAnswer) < 0 ||
        esxVI_GetVirtualMachinePowerState(virtualMachine, &powerState) < 0) {
        goto failure;
    }

    if (powerState != esxVI_VirtualMachinePowerState_Suspended) {
        ESX_ERROR(VIR_ERR_OPERATION_INVALID, "%s", _("Domain is not suspended"));
        goto failure;
    }

    if (esxVI_PowerOnVM_Task(priv->host, virtualMachine->obj, NULL,
                             &task) < 0 ||
        esxVI_WaitForTaskCompletion(priv->host, task, domain->uuid,
                                    priv->autoAnswer, &taskInfoState) < 0) {
        goto failure;
    }

    if (taskInfoState != esxVI_TaskInfoState_Success) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Could not resume domain"));
        goto failure;
    }

  cleanup:
    esxVI_ObjectContent_Free(&virtualMachine);
    esxVI_String_Free(&propertyNameList);
    esxVI_ManagedObjectReference_Free(&task);

    return result;

  failure:
    result = -1;

    goto cleanup;
}



static int
esxDomainShutdown(virDomainPtr domain)
{
    int result = 0;
    esxPrivate *priv = domain->conn->privateData;
    esxVI_ObjectContent *virtualMachine = NULL;
    esxVI_String *propertyNameList = NULL;
    esxVI_VirtualMachinePowerState powerState;

    if (esxVI_EnsureSession(priv->host) < 0) {
        goto failure;
    }

    if (esxVI_String_AppendValueToList(&propertyNameList,
                                       "runtime.powerState") < 0 ||
        esxVI_LookupVirtualMachineByUuid(priv->host, domain->uuid,
                                         propertyNameList, &virtualMachine,
                                         esxVI_Occurrence_RequiredItem) < 0 ||
        esxVI_GetVirtualMachinePowerState(virtualMachine, &powerState) < 0) {
        goto failure;
    }

    if (powerState != esxVI_VirtualMachinePowerState_PoweredOn) {
        ESX_ERROR(VIR_ERR_OPERATION_INVALID, "%s",
                  _("Domain is not powered on"));
        goto failure;
    }

    if (esxVI_ShutdownGuest(priv->host, virtualMachine->obj) < 0) {
        goto failure;
    }

  cleanup:
    esxVI_ObjectContent_Free(&virtualMachine);
    esxVI_String_Free(&propertyNameList);

    return result;

  failure:
    result = -1;

    goto cleanup;
}



static int
esxDomainReboot(virDomainPtr domain, unsigned int flags ATTRIBUTE_UNUSED)
{
    int result = 0;
    esxPrivate *priv = domain->conn->privateData;
    esxVI_ObjectContent *virtualMachine = NULL;
    esxVI_String *propertyNameList = NULL;
    esxVI_VirtualMachinePowerState powerState;

    if (esxVI_EnsureSession(priv->host) < 0) {
        goto failure;
    }

    if (esxVI_String_AppendValueToList(&propertyNameList,
                                       "runtime.powerState") < 0 ||
        esxVI_LookupVirtualMachineByUuid(priv->host, domain->uuid,
                                         propertyNameList, &virtualMachine,
                                         esxVI_Occurrence_RequiredItem) < 0 ||
        esxVI_GetVirtualMachinePowerState(virtualMachine, &powerState) < 0) {
        goto failure;
    }

    if (powerState != esxVI_VirtualMachinePowerState_PoweredOn) {
        ESX_ERROR(VIR_ERR_OPERATION_INVALID, "%s",
                  _("Domain is not powered on"));
        goto failure;
    }

    if (esxVI_RebootGuest(priv->host, virtualMachine->obj) < 0) {
        goto failure;
    }

  cleanup:
    esxVI_ObjectContent_Free(&virtualMachine);
    esxVI_String_Free(&propertyNameList);

    return result;

  failure:
    result = -1;

    goto cleanup;
}



static int
esxDomainDestroy(virDomainPtr domain)
{
    int result = 0;
    esxPrivate *priv = domain->conn->privateData;
    esxVI_Context *ctx = NULL;
    esxVI_ObjectContent *virtualMachine = NULL;
    esxVI_String *propertyNameList = NULL;
    esxVI_VirtualMachinePowerState powerState;
    esxVI_ManagedObjectReference *task = NULL;
    esxVI_TaskInfoState taskInfoState;

    if (priv->vCenter != NULL) {
        ctx = priv->vCenter;
    } else {
        ctx = priv->host;
    }

    if (esxVI_EnsureSession(ctx) < 0) {
        goto failure;
    }

    if (esxVI_String_AppendValueToList(&propertyNameList,
                                       "runtime.powerState") < 0 ||
        esxVI_LookupVirtualMachineByUuidAndPrepareForTask
          (ctx, domain->uuid, propertyNameList, &virtualMachine,
           priv->autoAnswer) < 0 ||
        esxVI_GetVirtualMachinePowerState(virtualMachine, &powerState) < 0) {
        goto failure;
    }

    if (powerState != esxVI_VirtualMachinePowerState_PoweredOn) {
        ESX_ERROR(VIR_ERR_OPERATION_INVALID, "%s",
                  _("Domain is not powered on"));
        goto failure;
    }

    if (esxVI_PowerOffVM_Task(ctx, virtualMachine->obj, &task) < 0 ||
        esxVI_WaitForTaskCompletion(ctx, task, domain->uuid, priv->autoAnswer,
                                    &taskInfoState) < 0) {
        goto failure;
    }

    if (taskInfoState != esxVI_TaskInfoState_Success) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Could not destroy domain"));
        goto failure;
    }

  cleanup:
    esxVI_ObjectContent_Free(&virtualMachine);
    esxVI_String_Free(&propertyNameList);
    esxVI_ManagedObjectReference_Free(&task);

    return result;

  failure:
    result = -1;

    goto cleanup;
}



static char *
esxDomainGetOSType(virDomainPtr domain ATTRIBUTE_UNUSED)
{
    char *osType = strdup("hvm");

    if (osType == NULL) {
        virReportOOMError();
        return NULL;
    }

    return osType;
}



static unsigned long
esxDomainGetMaxMemory(virDomainPtr domain)
{
    esxPrivate *priv = domain->conn->privateData;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *virtualMachine = NULL;
    esxVI_DynamicProperty *dynamicProperty = NULL;
    unsigned long memoryMB = 0;

    if (esxVI_EnsureSession(priv->host) < 0) {
        goto failure;
    }

    if (esxVI_String_AppendValueToList(&propertyNameList,
                                       "config.hardware.memoryMB") < 0 ||
        esxVI_LookupVirtualMachineByUuid(priv->host, domain->uuid,
                                         propertyNameList, &virtualMachine,
                                         esxVI_Occurrence_RequiredItem) < 0) {
        goto failure;
    }

    for (dynamicProperty = virtualMachine->propSet; dynamicProperty != NULL;
         dynamicProperty = dynamicProperty->_next) {
        if (STREQ(dynamicProperty->name, "config.hardware.memoryMB")) {
            if (esxVI_AnyType_ExpectType(dynamicProperty->val,
                                         esxVI_Type_Int) < 0) {
                goto failure;
            }

            if (dynamicProperty->val->int32 < 0) {
                ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                          _("Got invalid memory size %d"),
                          dynamicProperty->val->int32);
            } else {
                memoryMB = dynamicProperty->val->int32;
            }

            break;
        } else {
            VIR_WARN("Unexpected '%s' property", dynamicProperty->name);
        }
    }

  cleanup:
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&virtualMachine);

    return memoryMB * 1024; /* Scale from megabyte to kilobyte */

  failure:
    memoryMB = 0;

    goto cleanup;
}



static int
esxDomainSetMaxMemory(virDomainPtr domain, unsigned long memory)
{
    int result = 0;
    esxPrivate *priv = domain->conn->privateData;
    esxVI_ObjectContent *virtualMachine = NULL;
    esxVI_VirtualMachineConfigSpec *spec = NULL;
    esxVI_ManagedObjectReference *task = NULL;
    esxVI_TaskInfoState taskInfoState;

    if (esxVI_EnsureSession(priv->host) < 0) {
        goto failure;
    }

    if (esxVI_LookupVirtualMachineByUuidAndPrepareForTask
          (priv->host, domain->uuid, NULL, &virtualMachine,
           priv->autoAnswer) < 0 ||
        esxVI_VirtualMachineConfigSpec_Alloc(&spec) < 0 ||
        esxVI_Long_Alloc(&spec->memoryMB) < 0) {
        goto failure;
    }

    spec->memoryMB->value =
      memory / 1024; /* Scale from kilobytes to megabytes */

    if (esxVI_ReconfigVM_Task(priv->host, virtualMachine->obj, spec,
                              &task) < 0 ||
        esxVI_WaitForTaskCompletion(priv->host, task, domain->uuid,
                                    priv->autoAnswer, &taskInfoState) < 0) {
        goto failure;
    }

    if (taskInfoState != esxVI_TaskInfoState_Success) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  _("Could not set max-memory to %lu kilobytes"), memory);
        goto failure;
    }

  cleanup:
    esxVI_ObjectContent_Free(&virtualMachine);
    esxVI_VirtualMachineConfigSpec_Free(&spec);
    esxVI_ManagedObjectReference_Free(&task);

    return result;

  failure:
    result = -1;

    goto cleanup;
}



static int
esxDomainSetMemory(virDomainPtr domain, unsigned long memory)
{
    int result = 0;
    esxPrivate *priv = domain->conn->privateData;
    esxVI_ObjectContent *virtualMachine = NULL;
    esxVI_VirtualMachineConfigSpec *spec = NULL;
    esxVI_ManagedObjectReference *task = NULL;
    esxVI_TaskInfoState taskInfoState;

    if (esxVI_EnsureSession(priv->host) < 0) {
        goto failure;
    }

    if (esxVI_LookupVirtualMachineByUuidAndPrepareForTask
          (priv->host, domain->uuid, NULL, &virtualMachine,
           priv->autoAnswer) < 0 ||
        esxVI_VirtualMachineConfigSpec_Alloc(&spec) < 0 ||
        esxVI_ResourceAllocationInfo_Alloc(&spec->memoryAllocation) < 0 ||
        esxVI_Long_Alloc(&spec->memoryAllocation->limit) < 0) {
        goto failure;
    }

    spec->memoryAllocation->limit->value =
      memory / 1024; /* Scale from kilobytes to megabytes */

    if (esxVI_ReconfigVM_Task(priv->host, virtualMachine->obj, spec,
                              &task) < 0 ||
        esxVI_WaitForTaskCompletion(priv->host, task, domain->uuid,
                                    priv->autoAnswer, &taskInfoState) < 0) {
        goto failure;
    }

    if (taskInfoState != esxVI_TaskInfoState_Success) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  _("Could not set memory to %lu kilobytes"), memory);
        goto failure;
    }

  cleanup:
    esxVI_ObjectContent_Free(&virtualMachine);
    esxVI_VirtualMachineConfigSpec_Free(&spec);
    esxVI_ManagedObjectReference_Free(&task);

    return result;

  failure:
    result = -1;

    goto cleanup;
}



static int
esxDomainGetInfo(virDomainPtr domain, virDomainInfoPtr info)
{
    int result = 0;
    esxPrivate *priv = domain->conn->privateData;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *virtualMachine = NULL;
    esxVI_DynamicProperty *dynamicProperty = NULL;
    esxVI_VirtualMachinePowerState powerState;
    int64_t memory_limit = -1;
    esxVI_PerfMetricId *perfMetricId = NULL;
    esxVI_PerfMetricId *perfMetricIdList = NULL;
    esxVI_Int *counterId = NULL;
    esxVI_Int *counterIdList = NULL;
    esxVI_PerfCounterInfo *perfCounterInfo = NULL;
    esxVI_PerfCounterInfo *perfCounterInfoList = NULL;
    esxVI_PerfQuerySpec *querySpec = NULL;
    esxVI_PerfEntityMetricBase *perfEntityMetricBase = NULL;
    esxVI_PerfEntityMetricBase *perfEntityMetricBaseList = NULL;
    esxVI_PerfEntityMetric *perfEntityMetric = NULL;
    esxVI_PerfMetricIntSeries *perfMetricIntSeries = NULL;
    esxVI_Long *value = NULL;

    if (esxVI_EnsureSession(priv->host) < 0) {
        goto failure;
    }

    if (esxVI_String_AppendValueListToList(&propertyNameList,
                                           "runtime.powerState\0"
                                           "config.hardware.memoryMB\0"
                                           "config.hardware.numCPU\0"
                                           "config.memoryAllocation.limit\0") < 0 ||
        esxVI_LookupVirtualMachineByUuid(priv->host, domain->uuid,
                                         propertyNameList, &virtualMachine,
                                         esxVI_Occurrence_RequiredItem) < 0) {
        goto failure;
    }

    info->state = VIR_DOMAIN_NOSTATE;
    info->maxMem = 0;
    info->memory = 0;
    info->nrVirtCpu = 0;
    info->cpuTime = 0; /* FIXME */

    for (dynamicProperty = virtualMachine->propSet; dynamicProperty != NULL;
         dynamicProperty = dynamicProperty->_next) {
        if (STREQ(dynamicProperty->name, "runtime.powerState")) {
            if (esxVI_VirtualMachinePowerState_CastFromAnyType
                  (dynamicProperty->val, &powerState) < 0) {
                goto failure;
            }

            info->state = esxVI_VirtualMachinePowerState_ConvertToLibvirt
                            (powerState);
        } else if (STREQ(dynamicProperty->name, "config.hardware.memoryMB")) {
            if (esxVI_AnyType_ExpectType(dynamicProperty->val,
                                         esxVI_Type_Int) < 0) {
                goto failure;
            }

            info->maxMem = dynamicProperty->val->int32 * 1024; /* Scale from megabyte to kilobyte */
        } else if (STREQ(dynamicProperty->name, "config.hardware.numCPU")) {
            if (esxVI_AnyType_ExpectType(dynamicProperty->val,
                                         esxVI_Type_Int) < 0) {
                goto failure;
            }

            info->nrVirtCpu = dynamicProperty->val->int32;
        } else if (STREQ(dynamicProperty->name,
                         "config.memoryAllocation.limit")) {
            if (esxVI_AnyType_ExpectType(dynamicProperty->val,
                                         esxVI_Type_Long) < 0) {
                goto failure;
            }

            memory_limit = dynamicProperty->val->int64;

            if (memory_limit > 0) {
                memory_limit *= 1024; /* Scale from megabyte to kilobyte */
            }
        } else {
            VIR_WARN("Unexpected '%s' property", dynamicProperty->name);
        }
    }

    /* memory_limit < 0 means no memory limit is set */
    info->memory = memory_limit < 0 ? info->maxMem : memory_limit;

    /* Verify the cached 'used CPU time' performance counter ID */
    if (info->state == VIR_DOMAIN_RUNNING && priv->usedCpuTimeCounterId >= 0) {
        if (esxVI_Int_Alloc(&counterId) < 0) {
            goto failure;
        }

        counterId->value = priv->usedCpuTimeCounterId;

        if (esxVI_Int_AppendToList(&counterIdList, counterId) < 0) {
            goto failure;
        }

        if (esxVI_QueryPerfCounter(priv->host, counterIdList,
                                   &perfCounterInfo) < 0) {
            goto failure;
        }

        if (STRNEQ(perfCounterInfo->groupInfo->key, "cpu") ||
            STRNEQ(perfCounterInfo->nameInfo->key, "used") ||
            STRNEQ(perfCounterInfo->unitInfo->key, "millisecond")) {
            VIR_DEBUG("Cached usedCpuTimeCounterId %d is invalid",
                      priv->usedCpuTimeCounterId);

            priv->usedCpuTimeCounterId = -1;
        }

        esxVI_Int_Free(&counterIdList);
        esxVI_PerfCounterInfo_Free(&perfCounterInfo);
    }

    /*
     * Query the PerformanceManager for the 'used CPU time' performance
     * counter ID and cache it, if it's not already cached.
     */
    if (info->state == VIR_DOMAIN_RUNNING && priv->usedCpuTimeCounterId < 0) {
        if (esxVI_QueryAvailablePerfMetric(priv->host, virtualMachine->obj,
                                           NULL, NULL, NULL,
                                           &perfMetricIdList) < 0) {
            goto failure;
        }

        for (perfMetricId = perfMetricIdList; perfMetricId != NULL;
             perfMetricId = perfMetricId->_next) {
            VIR_DEBUG("perfMetricId counterId %d, instance '%s'",
                      perfMetricId->counterId->value, perfMetricId->instance);

            counterId = NULL;

            if (esxVI_Int_DeepCopy(&counterId, perfMetricId->counterId) < 0 ||
                esxVI_Int_AppendToList(&counterIdList, counterId) < 0) {
                goto failure;
            }
        }

        if (esxVI_QueryPerfCounter(priv->host, counterIdList,
                                   &perfCounterInfoList) < 0) {
            goto failure;
        }

        for (perfCounterInfo = perfCounterInfoList; perfCounterInfo != NULL;
             perfCounterInfo = perfCounterInfo->_next) {
            VIR_DEBUG("perfCounterInfo key %d, nameInfo '%s', groupInfo '%s', "
                      "unitInfo '%s', rollupType %d, statsType %d",
                      perfCounterInfo->key->value,
                      perfCounterInfo->nameInfo->key,
                      perfCounterInfo->groupInfo->key,
                      perfCounterInfo->unitInfo->key,
                      perfCounterInfo->rollupType,
                      perfCounterInfo->statsType);

            if (STREQ(perfCounterInfo->groupInfo->key, "cpu") &&
                STREQ(perfCounterInfo->nameInfo->key, "used") &&
                STREQ(perfCounterInfo->unitInfo->key, "millisecond")) {
                priv->usedCpuTimeCounterId = perfCounterInfo->key->value;
                break;
            }
        }

        if (priv->usedCpuTimeCounterId < 0) {
            VIR_WARN0("Could not find 'used CPU time' performance counter");
        }
    }

    /*
     * Query the PerformanceManager for the 'used CPU time' performance
     * counter value.
     */
    if (info->state == VIR_DOMAIN_RUNNING && priv->usedCpuTimeCounterId >= 0) {
        VIR_DEBUG("usedCpuTimeCounterId %d BEGIN", priv->usedCpuTimeCounterId);

        if (esxVI_PerfQuerySpec_Alloc(&querySpec) < 0 ||
            esxVI_Int_Alloc(&querySpec->maxSample) < 0 ||
            esxVI_PerfMetricId_Alloc(&querySpec->metricId) < 0 ||
            esxVI_Int_Alloc(&querySpec->metricId->counterId) < 0) {
            goto failure;
        }

        querySpec->entity = virtualMachine->obj;
        querySpec->maxSample->value = 1;
        querySpec->metricId->counterId->value = priv->usedCpuTimeCounterId;
        querySpec->metricId->instance = (char *)"";
        querySpec->format = (char *)"normal";

        if (esxVI_QueryPerf(priv->host, querySpec,
                            &perfEntityMetricBaseList) < 0) {
            querySpec->entity = NULL;
            querySpec->metricId->instance = NULL;
            querySpec->format = NULL;
            goto failure;
        }

        for (perfEntityMetricBase = perfEntityMetricBaseList;
             perfEntityMetricBase != NULL;
             perfEntityMetricBase = perfEntityMetricBase->_next) {
            VIR_DEBUG0("perfEntityMetric ...");

            perfEntityMetric =
              esxVI_PerfEntityMetric_DynamicCast(perfEntityMetricBase);

            if (perfMetricIntSeries == NULL) {
                VIR_ERROR0("QueryPerf returned object with unexpected type");
            }

            perfMetricIntSeries =
              esxVI_PerfMetricIntSeries_DynamicCast(perfEntityMetric->value);

            if (perfMetricIntSeries == NULL) {
                VIR_ERROR0("QueryPerf returned object with unexpected type");
            }

            for (; perfMetricIntSeries != NULL;
                 perfMetricIntSeries = perfMetricIntSeries->_next) {
                VIR_DEBUG0("perfMetricIntSeries ...");

                for (value = perfMetricIntSeries->value;
                     value != NULL;
                     value = value->_next) {
                    VIR_DEBUG("value %lld", (long long int)value->value);
                }
            }
        }

        querySpec->entity = NULL;
        querySpec->metricId->instance = NULL;
        querySpec->format = NULL;

        VIR_DEBUG("usedCpuTimeCounterId %d END", priv->usedCpuTimeCounterId);
    }

  cleanup:
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&virtualMachine);
    esxVI_PerfMetricId_Free(&perfMetricIdList);
    esxVI_Int_Free(&counterIdList);
    esxVI_PerfCounterInfo_Free(&perfCounterInfoList);
    esxVI_PerfQuerySpec_Free(&querySpec);
    esxVI_PerfEntityMetricBase_Free(&perfEntityMetricBaseList);

    return result;

  failure:
    result = -1;

    goto cleanup;
}



static int
esxDomainSetVcpus(virDomainPtr domain, unsigned int nvcpus)
{
    int result = 0;
    esxPrivate *priv = domain->conn->privateData;
    int maxVcpus;
    esxVI_ObjectContent *virtualMachine = NULL;
    esxVI_VirtualMachineConfigSpec *spec = NULL;
    esxVI_ManagedObjectReference *task = NULL;
    esxVI_TaskInfoState taskInfoState;

    if (nvcpus < 1) {
        ESX_ERROR(VIR_ERR_INVALID_ARG, "%s",
                  _("Requested number of virtual CPUs must at least be 1"));
        goto failure;
    }

    if (esxVI_EnsureSession(priv->host) < 0) {
        goto failure;
    }

    maxVcpus = esxDomainGetMaxVcpus(domain);

    if (maxVcpus < 0) {
        goto failure;
    }

    if (nvcpus > maxVcpus) {
        ESX_ERROR(VIR_ERR_INVALID_ARG,
                  _("Requested number of virtual CPUs is greater than max "
                    "allowable number of virtual CPUs for the domain: %d > %d"),
                  nvcpus, maxVcpus);
        goto failure;
    }

    if (esxVI_LookupVirtualMachineByUuidAndPrepareForTask
          (priv->host, domain->uuid, NULL, &virtualMachine,
           priv->autoAnswer) < 0 ||
        esxVI_VirtualMachineConfigSpec_Alloc(&spec) < 0 ||
        esxVI_Int_Alloc(&spec->numCPUs) < 0) {
        goto failure;
    }

    spec->numCPUs->value = nvcpus;

    if (esxVI_ReconfigVM_Task(priv->host, virtualMachine->obj, spec,
                              &task) < 0 ||
        esxVI_WaitForTaskCompletion(priv->host, task, domain->uuid,
                                    priv->autoAnswer, &taskInfoState) < 0) {
        goto failure;
    }

    if (taskInfoState != esxVI_TaskInfoState_Success) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  _("Could not set number of virtual CPUs to %d"), nvcpus);
        goto failure;
    }

  cleanup:
    esxVI_ObjectContent_Free(&virtualMachine);
    esxVI_VirtualMachineConfigSpec_Free(&spec);
    esxVI_ManagedObjectReference_Free(&task);

    return result;

  failure:
    result = -1;

    goto cleanup;
}



static int
esxDomainGetMaxVcpus(virDomainPtr domain)
{
    esxPrivate *priv = domain->conn->privateData;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *hostSystem = NULL;
    esxVI_DynamicProperty *dynamicProperty = NULL;

    if (priv->maxVcpus > 0) {
        return priv->maxVcpus;
    }

    if (esxVI_EnsureSession(priv->host) < 0) {
        goto failure;
    }

    if (esxVI_String_AppendValueToList(&propertyNameList,
                                       "capability.maxSupportedVcpus") < 0 ||
        esxVI_LookupObjectContentByType(priv->host, priv->host->hostFolder,
                                        "HostSystem", propertyNameList,
                                        esxVI_Boolean_True, &hostSystem) < 0) {
        goto failure;
    }

    if (hostSystem == NULL) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                  _("Could not retrieve the HostSystem object"));
        goto failure;
    }

    for (dynamicProperty = hostSystem->propSet; dynamicProperty != NULL;
         dynamicProperty = dynamicProperty->_next) {
        if (STREQ(dynamicProperty->name, "capability.maxSupportedVcpus")) {
            if (esxVI_AnyType_ExpectType(dynamicProperty->val,
                                         esxVI_Type_Int) < 0) {
                goto failure;
            }

            priv->maxVcpus = dynamicProperty->val->int32;
            break;
        } else {
            VIR_WARN("Unexpected '%s' property", dynamicProperty->name);
        }
    }

  cleanup:
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&hostSystem);

    return priv->maxVcpus;

  failure:
    priv->maxVcpus = -1;

    goto cleanup;
}



static char *
esxDomainDumpXML(virDomainPtr domain, int flags)
{
    esxPrivate *priv = domain->conn->privateData;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *virtualMachine = NULL;
    esxVI_DynamicProperty *dynamicProperty = NULL;
    const char *vmPathName = NULL;
    char *datastoreName = NULL;
    char *directoryName = NULL;
    char *fileName = NULL;
    virBuffer buffer = VIR_BUFFER_INITIALIZER;
    char *url = NULL;
    char *vmx = NULL;
    virDomainDefPtr def = NULL;
    char *xml = NULL;

    if (esxVI_EnsureSession(priv->host) < 0) {
        goto failure;
    }

    if (esxVI_String_AppendValueToList(&propertyNameList,
                                       "config.files.vmPathName") < 0 ||
        esxVI_LookupVirtualMachineByUuid(priv->host, domain->uuid,
                                         propertyNameList, &virtualMachine,
                                         esxVI_Occurrence_RequiredItem) < 0) {
        goto failure;
    }

    for (dynamicProperty = virtualMachine->propSet; dynamicProperty != NULL;
         dynamicProperty = dynamicProperty->_next) {
        if (STREQ(dynamicProperty->name, "config.files.vmPathName")) {
            if (esxVI_AnyType_ExpectType(dynamicProperty->val,
                                         esxVI_Type_String) < 0) {
                goto failure;
            }

            vmPathName = dynamicProperty->val->string;
            break;
        }
    }

    if (esxUtil_ParseDatastoreRelatedPath(vmPathName, &datastoreName,
                                          &directoryName, &fileName) < 0) {
        goto failure;
    }

    virBufferVSprintf(&buffer, "%s://%s:%d/folder/", priv->transport,
                      domain->conn->uri->server, domain->conn->uri->port);

    if (directoryName != NULL) {
        virBufferURIEncodeString(&buffer, directoryName);
        virBufferAddChar(&buffer, '/');
    }

    virBufferURIEncodeString(&buffer, fileName);
    virBufferAddLit(&buffer, "?dcPath=");
    virBufferURIEncodeString(&buffer, priv->host->datacenter->value);
    virBufferAddLit(&buffer, "&dsName=");
    virBufferURIEncodeString(&buffer, datastoreName);

    if (virBufferError(&buffer)) {
        virReportOOMError();
        goto failure;
    }

    url = virBufferContentAndReset(&buffer);

    if (esxVI_Context_DownloadFile(priv->host, url, &vmx) < 0) {
        goto failure;
    }

    def = esxVMX_ParseConfig(priv->host, vmx, datastoreName, directoryName,
                             priv->host->productVersion);

    if (def != NULL) {
        xml = virDomainDefFormat(def, flags);
    }

  cleanup:
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&virtualMachine);
    VIR_FREE(datastoreName);
    VIR_FREE(directoryName);
    VIR_FREE(fileName);
    VIR_FREE(url);
    VIR_FREE(vmx);
    virDomainDefFree(def);

    return xml;

  failure:
    virBufferFreeAndReset(&buffer);
    VIR_FREE(xml);

    goto cleanup;
}



static char *
esxDomainXMLFromNative(virConnectPtr conn, const char *nativeFormat,
                       const char *nativeConfig,
                       unsigned int flags ATTRIBUTE_UNUSED)
{
    esxPrivate *priv = conn->privateData;
    virDomainDefPtr def = NULL;
    char *xml = NULL;

    if (STRNEQ(nativeFormat, "vmware-vmx")) {
        ESX_ERROR(VIR_ERR_INVALID_ARG,
                  _("Unsupported config format '%s'"), nativeFormat);
        return NULL;
    }

    def = esxVMX_ParseConfig(priv->host, nativeConfig, "?", "?",
                             priv->host->productVersion);

    if (def != NULL) {
        xml = virDomainDefFormat(def, VIR_DOMAIN_XML_INACTIVE);
    }

    virDomainDefFree(def);

    return xml;
}



static char *
esxDomainXMLToNative(virConnectPtr conn, const char *nativeFormat,
                     const char *domainXml,
                     unsigned int flags ATTRIBUTE_UNUSED)
{
    esxPrivate *priv = conn->privateData;
    virDomainDefPtr def = NULL;
    char *vmx = NULL;

    if (STRNEQ(nativeFormat, "vmware-vmx")) {
        ESX_ERROR(VIR_ERR_INVALID_ARG,
                  _("Unsupported config format '%s'"), nativeFormat);
        return NULL;
    }

    def = virDomainDefParseString(priv->caps, domainXml, 0);

    if (def == NULL) {
        return NULL;
    }

    vmx = esxVMX_FormatConfig(priv->host, def, priv->host->productVersion);

    virDomainDefFree(def);

    return vmx;
}



static int
esxListDefinedDomains(virConnectPtr conn, char **const names, int maxnames)
{
    esxPrivate *priv = conn->privateData;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *virtualMachineList = NULL;
    esxVI_ObjectContent *virtualMachine = NULL;
    esxVI_DynamicProperty *dynamicProperty = NULL;
    esxVI_VirtualMachinePowerState powerState;
    int count = 0;
    int i;

    if (names == NULL || maxnames < 0) {
        ESX_ERROR(VIR_ERR_INVALID_ARG, "%s", _("Invalid argument"));
        return -1;
    }

    if (maxnames == 0) {
        return 0;
    }

    if (esxVI_EnsureSession(priv->host) < 0) {
        goto failure;
    }

    if (esxVI_String_AppendValueListToList(&propertyNameList,
                                           "name\0"
                                           "runtime.powerState\0") < 0 ||
        esxVI_LookupObjectContentByType(priv->host, priv->host->vmFolder,
                                        "VirtualMachine", propertyNameList,
                                        esxVI_Boolean_True,
                                        &virtualMachineList) < 0) {
        goto failure;
    }

    for (virtualMachine = virtualMachineList; virtualMachine != NULL;
         virtualMachine = virtualMachine->_next) {
        if (esxVI_GetVirtualMachinePowerState(virtualMachine,
                                              &powerState) < 0) {
            goto failure;
        }

        if (powerState == esxVI_VirtualMachinePowerState_PoweredOn) {
            continue;
        }

        for (dynamicProperty = virtualMachine->propSet;
             dynamicProperty != NULL;
             dynamicProperty = dynamicProperty->_next) {
            if (STREQ(dynamicProperty->name, "name")) {
                if (esxVI_AnyType_ExpectType(dynamicProperty->val,
                                             esxVI_Type_String) < 0) {
                    goto failure;
                }

                names[count] = strdup(dynamicProperty->val->string);

                if (names[count] == NULL) {
                    virReportOOMError();
                    goto failure;
                }

                count++;
                break;
            }
        }

        if (count >= maxnames) {
            break;
        }
    }

  cleanup:
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&virtualMachineList);

    return count;

  failure:
    for (i = 0; i < count; ++i) {
        VIR_FREE(names[i]);
    }

    count = -1;

    goto cleanup;
}



static int
esxNumberOfDefinedDomains(virConnectPtr conn)
{
    esxPrivate *priv = conn->privateData;

    if (esxVI_EnsureSession(priv->host) < 0) {
        return -1;
    }

    return esxVI_LookupNumberOfDomainsByPowerState
             (priv->host, esxVI_VirtualMachinePowerState_PoweredOn,
              esxVI_Boolean_True);
}



static int
esxDomainCreate(virDomainPtr domain)
{
    int result = 0;
    esxPrivate *priv = domain->conn->privateData;
    esxVI_ObjectContent *virtualMachine = NULL;
    esxVI_String *propertyNameList = NULL;
    esxVI_VirtualMachinePowerState powerState;
    esxVI_ManagedObjectReference *task = NULL;
    esxVI_TaskInfoState taskInfoState;

    if (esxVI_EnsureSession(priv->host) < 0) {
        goto failure;
    }

    if (esxVI_String_AppendValueToList(&propertyNameList,
                                       "runtime.powerState") < 0 ||
        esxVI_LookupVirtualMachineByUuidAndPrepareForTask
          (priv->host, domain->uuid, propertyNameList, &virtualMachine,
           priv->autoAnswer) < 0 ||
        esxVI_GetVirtualMachinePowerState(virtualMachine,
                                          &powerState) < 0) {
        goto failure;
    }

    if (powerState != esxVI_VirtualMachinePowerState_PoweredOff) {
        ESX_ERROR(VIR_ERR_OPERATION_INVALID, "%s",
                  _("Domain is not powered off"));
        goto failure;
    }

    if (esxVI_PowerOnVM_Task(priv->host, virtualMachine->obj, NULL,
                             &task) < 0 ||
        esxVI_WaitForTaskCompletion(priv->host, task, domain->uuid,
                                    priv->autoAnswer, &taskInfoState) < 0) {
        goto failure;
    }

    if (taskInfoState != esxVI_TaskInfoState_Success) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Could not start domain"));
        goto failure;
    }

  cleanup:
    esxVI_ObjectContent_Free(&virtualMachine);
    esxVI_String_Free(&propertyNameList);
    esxVI_ManagedObjectReference_Free(&task);

    return result;

  failure:
    result = -1;

    goto cleanup;
}



static virDomainPtr
esxDomainDefineXML(virConnectPtr conn, const char *xml ATTRIBUTE_UNUSED)
{
    esxPrivate *priv = conn->privateData;
    virDomainDefPtr def = NULL;
    char *vmx = NULL;
    int i;
    virDomainDiskDefPtr disk = NULL;
    esxVI_ObjectContent *virtualMachine = NULL;
    char *datastoreName = NULL;
    char *directoryName = NULL;
    char *fileName = NULL;
    virBuffer buffer = VIR_BUFFER_INITIALIZER;
    char *url = NULL;
    char *datastoreRelatedPath = NULL;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *hostSystem = NULL;
    esxVI_ManagedObjectReference *resourcePool = NULL;
    esxVI_ManagedObjectReference *task = NULL;
    esxVI_TaskInfoState taskInfoState;
    virDomainPtr domain = NULL;

    if (esxVI_EnsureSession(priv->host) < 0) {
        goto failure;
    }

    /* Parse domain XML */
    def = virDomainDefParseString(priv->caps, xml,
                                  VIR_DOMAIN_XML_INACTIVE);

    if (def == NULL) {
        goto failure;
    }

    /* Check if an existing domain should be edited */
    if (esxVI_LookupVirtualMachineByUuid(priv->host, def->uuid, NULL,
                                         &virtualMachine,
                                         esxVI_Occurrence_OptionalItem) < 0) {
        goto failure;
    }

    if (virtualMachine != NULL) {
        /* FIXME */
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                  _("Domain already exists, editing existing domains is not "
                    "supported yet"));
        goto failure;
    }

    /* Build VMX from domain XML */
    vmx = esxVMX_FormatConfig(priv->host, def, priv->host->productVersion);

    if (vmx == NULL) {
        goto failure;
    }

    /*
     * Build VMX datastore URL. Use the source of the first file-based harddisk
     * to deduce the datastore and path for the VMX file. Don't just use the
     * first disk, because it may be CDROM disk and ISO images are normaly not
     * located in the virtual machine's directory. This approach to deduce the
     * datastore isn't perfect but should work in the majority of cases.
     */
    if (def->ndisks < 1) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                  _("Domain XML doesn't contain any disks, cannot deduce "
                    "datastore and path for VMX file"));
        goto failure;
    }

    for (i = 0; i < def->ndisks; ++i) {
        if (def->disks[i]->device == VIR_DOMAIN_DISK_DEVICE_DISK &&
            def->disks[i]->type == VIR_DOMAIN_DISK_TYPE_FILE) {
            disk = def->disks[i];
            break;
        }
    }

    if (disk == NULL) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                  _("Domain XML doesn't contain any file-based harddisks, "
                    "cannot deduce datastore and path for VMX file"));
        goto failure;
    }

    if (disk->src == NULL) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                  _("First file-based harddisk has no source, cannot deduce "
                    "datastore and path for VMX file"));
        goto failure;
    }

    if (esxUtil_ParseDatastoreRelatedPath(disk->src, &datastoreName,
                                          &directoryName, &fileName) < 0) {
        goto failure;
    }

    if (! virFileHasSuffix(fileName, ".vmdk")) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  _("Expecting source '%s' of first file-based harddisk to "
                    "be a VMDK image"), disk->src);
        goto failure;
    }

    virBufferVSprintf(&buffer, "%s://%s:%d/folder/", priv->transport,
                      conn->uri->server, conn->uri->port);

    if (directoryName != NULL) {
        virBufferURIEncodeString(&buffer, directoryName);
        virBufferAddChar(&buffer, '/');
    }

    virBufferURIEncodeString(&buffer, def->name);
    virBufferAddLit(&buffer, ".vmx?dcPath=");
    virBufferURIEncodeString(&buffer, priv->host->datacenter->value);
    virBufferAddLit(&buffer, "&dsName=");
    virBufferURIEncodeString(&buffer, datastoreName);

    if (virBufferError(&buffer)) {
        virReportOOMError();
        goto failure;
    }

    url = virBufferContentAndReset(&buffer);

    if (directoryName != NULL) {
        if (virAsprintf(&datastoreRelatedPath, "[%s] %s/%s.vmx", datastoreName,
                        directoryName, def->name) < 0) {
            virReportOOMError();
            goto failure;
        }
    } else {
        if (virAsprintf(&datastoreRelatedPath, "[%s] %s.vmx", datastoreName,
                        def->name) < 0) {
            virReportOOMError();
            goto failure;
        }
    }

    /* Get resource pool */
    if (esxVI_String_AppendValueToList(&propertyNameList, "parent") < 0 ||
        esxVI_LookupHostSystemByIp(priv->host, priv->host->ipAddress,
                                   propertyNameList, &hostSystem) < 0) {
        goto failure;
    }

    if (esxVI_LookupResourcePoolByHostSystem(priv->host, hostSystem,
                                             &resourcePool) < 0) {
        goto failure;
    }

    /* Check, if VMX file already exists */
    /* FIXME */

    /* Upload VMX file */
    if (esxVI_Context_UploadFile(priv->host, url, vmx) < 0) {
        goto failure;
    }

    /* Register the domain */
    if (esxVI_RegisterVM_Task(priv->host, priv->host->vmFolder,
                              datastoreRelatedPath, NULL, esxVI_Boolean_False,
                              resourcePool, hostSystem->obj, &task) < 0 ||
        esxVI_WaitForTaskCompletion(priv->host, task, def->uuid,
                                    priv->autoAnswer, &taskInfoState) < 0) {
        goto failure;
    }

    if (taskInfoState != esxVI_TaskInfoState_Success) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Could not define domain"));
        goto failure;
    }

    domain = virGetDomain(conn, def->name, def->uuid);

    if (domain != NULL) {
        domain->id = -1;
    }

    /* FIXME: Add proper rollback in case of an error */

  cleanup:
    virDomainDefFree(def);
    VIR_FREE(vmx);
    VIR_FREE(datastoreName);
    VIR_FREE(directoryName);
    VIR_FREE(fileName);
    VIR_FREE(url);
    VIR_FREE(datastoreRelatedPath);
    esxVI_ObjectContent_Free(&virtualMachine);
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&hostSystem);
    esxVI_ManagedObjectReference_Free(&resourcePool);
    esxVI_ManagedObjectReference_Free(&task);

    return domain;

  failure:
    virBufferFreeAndReset(&buffer);

    domain = NULL;

    goto cleanup;
}



static int
esxDomainUndefine(virDomainPtr domain)
{
    int result = 0;
    esxPrivate *priv = domain->conn->privateData;
    esxVI_Context *ctx = NULL;
    esxVI_ObjectContent *virtualMachine = NULL;
    esxVI_String *propertyNameList = NULL;
    esxVI_VirtualMachinePowerState powerState;

    if (priv->vCenter != NULL) {
        ctx = priv->vCenter;
    } else {
        ctx = priv->host;
    }

    if (esxVI_EnsureSession(ctx) < 0) {
        goto failure;
    }

    if (esxVI_String_AppendValueToList(&propertyNameList,
                                       "runtime.powerState") < 0 ||
        esxVI_LookupVirtualMachineByUuid(ctx, domain->uuid, propertyNameList,
                                         &virtualMachine,
                                         esxVI_Occurrence_RequiredItem) < 0 ||
        esxVI_GetVirtualMachinePowerState(virtualMachine, &powerState) < 0) {
        goto failure;
    }

    if (powerState != esxVI_VirtualMachinePowerState_Suspended &&
        powerState != esxVI_VirtualMachinePowerState_PoweredOff) {
        ESX_ERROR(VIR_ERR_OPERATION_INVALID, "%s",
                  _("Domain is not suspended or powered off"));
        goto failure;
    }

    if (esxVI_UnregisterVM(ctx, virtualMachine->obj) < 0) {
        goto failure;
    }

  cleanup:
    esxVI_ObjectContent_Free(&virtualMachine);
    esxVI_String_Free(&propertyNameList);

    return result;

  failure:
    result = -1;

    goto cleanup;
}



/*
 * The scheduler interface exposes basically the CPU ResourceAllocationInfo:
 *
 * - http://www.vmware.com/support/developer/vc-sdk/visdk25pubs/ReferenceGuide/vim.ResourceAllocationInfo.html
 * - http://www.vmware.com/support/developer/vc-sdk/visdk25pubs/ReferenceGuide/vim.SharesInfo.html
 * - http://www.vmware.com/support/developer/vc-sdk/visdk25pubs/ReferenceGuide/vim.SharesInfo.Level.html
 *
 *
 * Available parameters:
 *
 * - reservation (VIR_DOMAIN_SCHED_FIELD_LLONG >= 0, in megaherz)
 *
 *   The amount of CPU resource that is guaranteed to be available to the domain.
 *
 *
 * - limit (VIR_DOMAIN_SCHED_FIELD_LLONG >= 0, or -1, in megaherz)
 *
 *   The CPU utilization of the domain will be limited to this value, even if
 *   more CPU resources are available. If the limit is set to -1, the CPU
 *   utilization of the domain is unlimited. If the limit is not set to -1, it
 *   must be greater than or equal to the reservation.
 *
 *
 * - shares (VIR_DOMAIN_SCHED_FIELD_INT >= 0, or in {-1, -2, -3}, no unit)
 *
 *   Shares are used to determine relative CPU allocation between domains. In
 *   general, a domain with more shares gets proportionally more of the CPU
 *   resource. The special values -1, -2 and -3 represent the predefined
 *   SharesLevel 'low', 'normal' and 'high'.
 */
static char *
esxDomainGetSchedulerType(virDomainPtr domain ATTRIBUTE_UNUSED, int *nparams)
{
    char *type = strdup("allocation");

    if (type == NULL) {
        virReportOOMError();
        return NULL;
    }

    *nparams = 3; /* reservation, limit, shares */

    return type;
}



static int
esxDomainGetSchedulerParameters(virDomainPtr domain,
                                virSchedParameterPtr params, int *nparams)
{
    int result = 0;
    esxPrivate *priv = domain->conn->privateData;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *virtualMachine = NULL;
    esxVI_DynamicProperty *dynamicProperty = NULL;
    esxVI_SharesInfo *sharesInfo = NULL;
    unsigned int mask = 0;
    int i = 0;

    if (*nparams < 3) {
        ESX_ERROR(VIR_ERR_INVALID_ARG, "%s",
                  _("Parameter array must have space for 3 items"));
        goto failure;
    }

    if (esxVI_EnsureSession(priv->host) < 0) {
        goto failure;
    }

    if (esxVI_String_AppendValueListToList(&propertyNameList,
                                           "config.cpuAllocation.reservation\0"
                                           "config.cpuAllocation.limit\0"
                                           "config.cpuAllocation.shares\0") < 0 ||
        esxVI_LookupVirtualMachineByUuid(priv->host, domain->uuid,
                                         propertyNameList, &virtualMachine,
                                         esxVI_Occurrence_RequiredItem) < 0) {
        goto failure;
    }

    for (dynamicProperty = virtualMachine->propSet;
         dynamicProperty != NULL && mask != 7 && i < 3;
         dynamicProperty = dynamicProperty->_next) {
        if (STREQ(dynamicProperty->name, "config.cpuAllocation.reservation") &&
            ! (mask & (1 << 0))) {
            snprintf (params[i].field, VIR_DOMAIN_SCHED_FIELD_LENGTH, "%s",
                      "reservation");

            params[i].type = VIR_DOMAIN_SCHED_FIELD_LLONG;

            if (esxVI_AnyType_ExpectType(dynamicProperty->val,
                                         esxVI_Type_Long) < 0) {
                goto failure;
            }

            params[i].value.l = dynamicProperty->val->int64;
            mask |= 1 << 0;
            ++i;
        } else if (STREQ(dynamicProperty->name,
                         "config.cpuAllocation.limit") &&
                   ! (mask & (1 << 1))) {
            snprintf (params[i].field, VIR_DOMAIN_SCHED_FIELD_LENGTH, "%s",
                      "limit");

            params[i].type = VIR_DOMAIN_SCHED_FIELD_LLONG;

            if (esxVI_AnyType_ExpectType(dynamicProperty->val,
                                         esxVI_Type_Long) < 0) {
                goto failure;
            }

            params[i].value.l = dynamicProperty->val->int64;
            mask |= 1 << 1;
            ++i;
        } else if (STREQ(dynamicProperty->name,
                         "config.cpuAllocation.shares") &&
                   ! (mask & (1 << 2))) {
            snprintf (params[i].field, VIR_DOMAIN_SCHED_FIELD_LENGTH, "%s",
                      "shares");

            params[i].type = VIR_DOMAIN_SCHED_FIELD_INT;

            if (esxVI_SharesInfo_CastFromAnyType(dynamicProperty->val,
                                                 &sharesInfo) < 0) {
                goto failure;
            }

            switch (sharesInfo->level) {
              case esxVI_SharesLevel_Custom:
                params[i].value.i = sharesInfo->shares->value;
                break;

              case esxVI_SharesLevel_Low:
                params[i].value.i = -1;
                break;

              case esxVI_SharesLevel_Normal:
                params[i].value.i = -2;
                break;

              case esxVI_SharesLevel_High:
                params[i].value.i = -3;
                break;

              default:
                ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                          _("Shares level has unknown value %d"),
                          (int)sharesInfo->level);
                goto failure;
            }

            esxVI_SharesInfo_Free(&sharesInfo);

            mask |= 1 << 2;
            ++i;
        } else {
            VIR_WARN("Unexpected '%s' property", dynamicProperty->name);
        }
    }

    *nparams = i;

  cleanup:
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&virtualMachine);

    return result;

  failure:
    result = -1;

    goto cleanup;
}



static int
esxDomainSetSchedulerParameters(virDomainPtr domain,
                                virSchedParameterPtr params, int nparams)
{
    int result = 0;
    esxPrivate *priv = domain->conn->privateData;
    esxVI_ObjectContent *virtualMachine = NULL;
    esxVI_VirtualMachineConfigSpec *spec = NULL;
    esxVI_SharesInfo *sharesInfo = NULL;
    esxVI_ManagedObjectReference *task = NULL;
    esxVI_TaskInfoState taskInfoState;
    int i;

    if (esxVI_EnsureSession(priv->host) < 0) {
        goto failure;
    }

    if (esxVI_LookupVirtualMachineByUuidAndPrepareForTask
          (priv->host, domain->uuid, NULL, &virtualMachine,
           priv->autoAnswer) < 0 ||
        esxVI_VirtualMachineConfigSpec_Alloc(&spec) < 0 ||
        esxVI_ResourceAllocationInfo_Alloc(&spec->cpuAllocation) < 0) {
        goto failure;
    }

    for (i = 0; i < nparams; ++i) {
        if (STREQ (params[i].field, "reservation") &&
            params[i].type == VIR_DOMAIN_SCHED_FIELD_LLONG) {
            if (esxVI_Long_Alloc(&spec->cpuAllocation->reservation) < 0) {
                goto failure;
            }

            if (params[i].value.l < 0) {
                ESX_ERROR(VIR_ERR_INVALID_ARG,
                          _("Could not set reservation to %lld MHz, expecting "
                            "positive value"), params[i].value.l);
                goto failure;
            }

            spec->cpuAllocation->reservation->value = params[i].value.l;
        } else if (STREQ (params[i].field, "limit") &&
                   params[i].type == VIR_DOMAIN_SCHED_FIELD_LLONG) {
            if (esxVI_Long_Alloc(&spec->cpuAllocation->limit) < 0) {
                goto failure;
            }

            if (params[i].value.l < -1) {
                ESX_ERROR(VIR_ERR_INVALID_ARG,
                          _("Could not set limit to %lld MHz, expecting "
                            "positive value or -1 (unlimited)"),
                          params[i].value.l);
                goto failure;
            }

            spec->cpuAllocation->limit->value = params[i].value.l;
        } else if (STREQ (params[i].field, "shares") &&
                   params[i].type == VIR_DOMAIN_SCHED_FIELD_INT) {
            if (esxVI_SharesInfo_Alloc(&sharesInfo) < 0 ||
                esxVI_Int_Alloc(&sharesInfo->shares) < 0) {
                goto failure;
            }

            spec->cpuAllocation->shares = sharesInfo;

            if (params[i].value.i >= 0) {
                spec->cpuAllocation->shares->level = esxVI_SharesLevel_Custom;
                spec->cpuAllocation->shares->shares->value = params[i].value.i;
            } else {
                switch (params[i].value.i) {
                  case -1:
                    spec->cpuAllocation->shares->level = esxVI_SharesLevel_Low;
                    spec->cpuAllocation->shares->shares->value = -1;
                    break;

                  case -2:
                    spec->cpuAllocation->shares->level =
                      esxVI_SharesLevel_Normal;
                    spec->cpuAllocation->shares->shares->value = -1;
                    break;

                  case -3:
                    spec->cpuAllocation->shares->level =
                      esxVI_SharesLevel_High;
                    spec->cpuAllocation->shares->shares->value = -1;
                    break;

                  default:
                    ESX_ERROR(VIR_ERR_INVALID_ARG,
                              _("Could not set shares to %d, expecting positive "
                                "value or -1 (low), -2 (normal) or -3 (high)"),
                              params[i].value.i);
                    goto failure;
                }
            }
        } else {
            ESX_ERROR(VIR_ERR_INVALID_ARG, _("Unknown field '%s'"),
                      params[i].field);
            goto failure;
        }
    }

    if (esxVI_ReconfigVM_Task(priv->host, virtualMachine->obj, spec,
                              &task) < 0 ||
        esxVI_WaitForTaskCompletion(priv->host, task, domain->uuid,
                                    priv->autoAnswer, &taskInfoState) < 0) {
        goto failure;
    }

    if (taskInfoState != esxVI_TaskInfoState_Success) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                  _("Could not change scheduler parameters"));
        goto failure;
    }

  cleanup:
    esxVI_ObjectContent_Free(&virtualMachine);
    esxVI_VirtualMachineConfigSpec_Free(&spec);
    esxVI_ManagedObjectReference_Free(&task);

    return result;

  failure:
    result = -1;

    goto cleanup;
}



static int
esxDomainMigratePrepare(virConnectPtr dconn,
                        char **cookie ATTRIBUTE_UNUSED,
                        int *cookielen ATTRIBUTE_UNUSED,
                        const char *uri_in, char **uri_out,
                        unsigned long flags ATTRIBUTE_UNUSED,
                        const char *dname ATTRIBUTE_UNUSED,
                        unsigned long resource ATTRIBUTE_UNUSED)
{
    int result = 0;
    char *transport = NULL;

    if (uri_in == NULL) {
        if (esxUtil_ParseQuery(dconn->uri, &transport, NULL, NULL, NULL) < 0) {
            return -1;
        }

        if (virAsprintf(uri_out, "%s://%s:%d/sdk", transport,
                        dconn->uri->server, dconn->uri->port) < 0) {
            virReportOOMError();
            goto failure;
        }
    }

  cleanup:
    VIR_FREE(transport);

    return result;

  failure:
    result = -1;

    goto cleanup;
}



static int
esxDomainMigratePerform(virDomainPtr domain,
                        const char *cookie ATTRIBUTE_UNUSED,
                        int cookielen ATTRIBUTE_UNUSED,
                        const char *uri,
                        unsigned long flags ATTRIBUTE_UNUSED,
                        const char *dname,
                        unsigned long bandwidth ATTRIBUTE_UNUSED)
{
    int result = 0;
    esxPrivate *priv = domain->conn->privateData;
    xmlURIPtr xmlUri = NULL;
    char hostIpAddress[NI_MAXHOST] = "";
    esxVI_ObjectContent *virtualMachine = NULL;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *hostSystem = NULL;
    esxVI_ManagedObjectReference *resourcePool = NULL;
    esxVI_Event *eventList = NULL;
    esxVI_ManagedObjectReference *task = NULL;
    esxVI_TaskInfoState taskInfoState;

    if (priv->vCenter == NULL) {
        ESX_ERROR(VIR_ERR_INVALID_ARG, "%s",
                  _("Migration not possible without a vCenter"));
        goto failure;
    }

    if (dname != NULL) {
        ESX_ERROR(VIR_ERR_INVALID_ARG, "%s",
                  _("Renaming domains on migration not supported"));
        goto failure;
    }

    if (esxVI_EnsureSession(priv->vCenter) < 0) {
        goto failure;
    }

    /* Parse the destination URI and resolve the hostname */
    xmlUri = xmlParseURI(uri);

    if (xmlUri == NULL) {
        virReportOOMError();
        goto failure;
    }

    if (esxUtil_ResolveHostname(xmlUri->server, hostIpAddress,
                                NI_MAXHOST) < 0) {
        goto failure;
    }

    /* Lookup VirtualMachine, HostSystem and ResourcePool */
    if (esxVI_LookupVirtualMachineByUuidAndPrepareForTask
          (priv->vCenter, domain->uuid, NULL, &virtualMachine,
           priv->autoAnswer) < 0 ||
        esxVI_String_AppendValueToList(&propertyNameList, "parent") < 0 ||
        esxVI_LookupHostSystemByIp(priv->vCenter, hostIpAddress,
                                   propertyNameList, &hostSystem) < 0) {
        goto failure;
    }

    if (esxVI_LookupResourcePoolByHostSystem(priv->vCenter, hostSystem,
                                             &resourcePool) < 0) {
        goto failure;
    }

    /* Validate the purposed migration */
    if (esxVI_ValidateMigration(priv->vCenter, virtualMachine->obj,
                                esxVI_VirtualMachinePowerState_Undefined,
                                NULL, resourcePool, hostSystem->obj,
                                &eventList) < 0) {
        goto failure;
    }

    if (eventList != NULL) {
        /*
         * FIXME: Need to report the complete list of events. Limit reporting
         *        to the first event for now.
         */
        if (eventList->fullFormattedMessage != NULL) {
            ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                      _("Could not migrate domain, validation reported a "
                        "problem: %s"), eventList->fullFormattedMessage);
        } else {
            ESX_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                      _("Could not migrate domain, validation reported a "
                        "problem"));
        }

        goto failure;
    }

    /* Perform the purposed migration */
    if (esxVI_MigrateVM_Task(priv->vCenter, virtualMachine->obj, resourcePool,
                             hostSystem->obj,
                             esxVI_VirtualMachineMovePriority_DefaultPriority,
                             esxVI_VirtualMachinePowerState_Undefined,
                             &task) < 0 ||
        esxVI_WaitForTaskCompletion(priv->vCenter, task, domain->uuid,
                                    priv->autoAnswer, &taskInfoState) < 0) {
        goto failure;
    }

    if (taskInfoState != esxVI_TaskInfoState_Success) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                  _("Could not migrate domain, migration task finished with "
                    "an error"));
        goto failure;
    }

  cleanup:
    xmlFreeURI(xmlUri);
    esxVI_ObjectContent_Free(&virtualMachine);
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&hostSystem);
    esxVI_ManagedObjectReference_Free(&resourcePool);
    esxVI_Event_Free(&eventList);
    esxVI_ManagedObjectReference_Free(&task);

    return result;

  failure:
    result = -1;

    goto cleanup;
}



static virDomainPtr
esxDomainMigrateFinish(virConnectPtr dconn, const char *dname,
                       const char *cookie ATTRIBUTE_UNUSED,
                       int cookielen ATTRIBUTE_UNUSED,
                       const char *uri ATTRIBUTE_UNUSED,
                       unsigned long flags ATTRIBUTE_UNUSED)
{
    return esxDomainLookupByName(dconn, dname);
}



static unsigned long long
esxNodeGetFreeMemory(virConnectPtr conn)
{
    unsigned long long result = 0;
    esxPrivate *priv = conn->privateData;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *hostSystem = NULL;
    esxVI_ManagedObjectReference *managedObjectReference = NULL;
    esxVI_ObjectContent *resourcePool = NULL;
    esxVI_DynamicProperty *dynamicProperty = NULL;
    esxVI_ResourcePoolResourceUsage *resourcePoolResourceUsage = NULL;

    if (esxVI_EnsureSession(priv->host) < 0) {
        goto failure;
    }

    /* Lookup host system with its resource pool */
    if (esxVI_String_AppendValueToList(&propertyNameList, "parent") < 0 ||
        esxVI_LookupHostSystemByIp(priv->host, priv->host->ipAddress,
                                   propertyNameList, &hostSystem) < 0) {
        goto failure;
    }

    if (esxVI_LookupResourcePoolByHostSystem(priv->host, hostSystem,
                                             &managedObjectReference) < 0) {
        goto failure;
    }

    esxVI_String_Free(&propertyNameList);

    /* Get memory usage of resource pool */
    if (esxVI_String_AppendValueToList(&propertyNameList,
                                       "runtime.memory") < 0 ||
        esxVI_LookupObjectContentByType(priv->host, managedObjectReference,
                                        "ResourcePool", propertyNameList,
                                        esxVI_Boolean_False,
                                        &resourcePool) < 0) {
        goto failure;
    }

    for (dynamicProperty = resourcePool->propSet; dynamicProperty != NULL;
         dynamicProperty = dynamicProperty->_next) {
        if (STREQ(dynamicProperty->name, "runtime.memory")) {
            if (esxVI_ResourcePoolResourceUsage_CastFromAnyType
                  (dynamicProperty->val, &resourcePoolResourceUsage) < 0) {
                goto failure;
            }

            break;
        } else {
            VIR_WARN("Unexpected '%s' property", dynamicProperty->name);
        }
    }

    if (resourcePoolResourceUsage == NULL) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                  _("Could not retrieve memory usage of resource pool"));
        goto failure;
    }

    result = resourcePoolResourceUsage->unreservedForVm->value;

  cleanup:
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&hostSystem);
    esxVI_ManagedObjectReference_Free(&managedObjectReference);
    esxVI_ObjectContent_Free(&resourcePool);
    esxVI_ResourcePoolResourceUsage_Free(&resourcePoolResourceUsage);

    return result;

  failure:
    result = 0;

    goto cleanup;
}



static int
esxIsEncrypted(virConnectPtr conn)
{
    esxPrivate *priv = conn->privateData;

    if (STRCASEEQ(priv->transport, "https")) {
        return 1;
    } else {
        return 0;
    }
}



static int
esxIsSecure(virConnectPtr conn)
{
    esxPrivate *priv = conn->privateData;

    if (STRCASEEQ(priv->transport, "https")) {
        return 1;
    } else {
        return 0;
    }
}



static int
esxDomainIsActive(virDomainPtr domain)
{
    int result = 0;
    esxPrivate *priv = domain->conn->privateData;
    esxVI_ObjectContent *virtualMachine = NULL;
    esxVI_String *propertyNameList = NULL;
    esxVI_VirtualMachinePowerState powerState;

    if (esxVI_EnsureSession(priv->host) < 0) {
        goto failure;
    }

    if (esxVI_String_AppendValueToList(&propertyNameList,
                                       "runtime.powerState") < 0 ||
        esxVI_LookupVirtualMachineByUuid(priv->host, domain->uuid,
                                         propertyNameList, &virtualMachine,
                                         esxVI_Occurrence_RequiredItem) < 0 ||
        esxVI_GetVirtualMachinePowerState(virtualMachine, &powerState) < 0) {
        goto failure;
    }

    if (powerState != esxVI_VirtualMachinePowerState_PoweredOff) {
        result = 1;
    } else {
        result = 0;
    }

  cleanup:
    esxVI_ObjectContent_Free(&virtualMachine);
    esxVI_String_Free(&propertyNameList);

    return result;

  failure:
    result = -1;

    goto cleanup;
}



static int
esxDomainIsPersistent(virDomainPtr domain ATTRIBUTE_UNUSED)
{
    /* ESX has no concept of transient domains, so all of them are persistent */
    return 1;
}



static virDomainSnapshotPtr
esxDomainSnapshotCreateXML(virDomainPtr domain, const char *xmlDesc,
                           unsigned int flags)
{
    esxPrivate *priv = domain->conn->privateData;
    virDomainSnapshotDefPtr def = NULL;
    esxVI_ObjectContent *virtualMachine = NULL;
    esxVI_VirtualMachineSnapshotTree *rootSnapshotList = NULL;
    esxVI_VirtualMachineSnapshotTree *snapshotTree = NULL;
    esxVI_VirtualMachineSnapshotTree *snapshotTreeParent = NULL;
    esxVI_ManagedObjectReference *task = NULL;
    esxVI_TaskInfoState taskInfoState;
    virDomainSnapshotPtr snapshot = NULL;

    virCheckFlags(0, NULL);

    if (esxVI_EnsureSession(priv->host) < 0) {
        goto failure;
    }

    def = virDomainSnapshotDefParseString(xmlDesc, 1);

    if (def == NULL) {
        goto failure;
    }

    if (esxVI_LookupVirtualMachineByUuidAndPrepareForTask
          (priv->host, domain->uuid, NULL, &virtualMachine,
           priv->autoAnswer) < 0 ||
        esxVI_LookupRootSnapshotTreeList(priv->host, domain->uuid,
                                         &rootSnapshotList) < 0 ||
        esxVI_GetSnapshotTreeByName(rootSnapshotList, def->name,
                                    &snapshotTree, &snapshotTreeParent,
                                    esxVI_Occurrence_OptionalItem) < 0) {
        goto failure;
    }

    if (snapshotTree != NULL) {
        ESX_ERROR(VIR_ERR_OPERATION_INVALID,
                  _("Snapshot '%s' already exists"), def->name);
        goto failure;
    }

    if (esxVI_CreateSnapshot_Task(priv->host, virtualMachine->obj,
                                  def->name, def->description,
                                  esxVI_Boolean_True,
                                  esxVI_Boolean_False, &task) < 0 ||
        esxVI_WaitForTaskCompletion(priv->host, task, domain->uuid,
                                    priv->autoAnswer, &taskInfoState) < 0) {
        goto failure;
    }

    if (taskInfoState != esxVI_TaskInfoState_Success) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Could not create snapshot"));
        goto failure;
    }

    snapshot = virGetDomainSnapshot(domain, def->name);

  cleanup:
    virDomainSnapshotDefFree(def);
    esxVI_ObjectContent_Free(&virtualMachine);
    esxVI_VirtualMachineSnapshotTree_Free(&rootSnapshotList);
    esxVI_ManagedObjectReference_Free(&task);

    return snapshot;

  failure:
    domain = NULL;

    goto cleanup;
}



static char *
esxDomainSnapshotDumpXML(virDomainSnapshotPtr snapshot,
                         unsigned int flags)
{
    esxPrivate *priv = snapshot->domain->conn->privateData;
    esxVI_VirtualMachineSnapshotTree *rootSnapshotList = NULL;
    esxVI_VirtualMachineSnapshotTree *snapshotTree = NULL;
    esxVI_VirtualMachineSnapshotTree *snapshotTreeParent = NULL;
    virDomainSnapshotDef def;
    char uuid_string[VIR_UUID_STRING_BUFLEN] = "";
    char *xml = NULL;

    virCheckFlags(0, NULL);

    memset(&def, 0, sizeof (virDomainSnapshotDef));

    if (esxVI_EnsureSession(priv->host) < 0) {
        goto failure;
    }

    if (esxVI_LookupRootSnapshotTreeList(priv->host, snapshot->domain->uuid,
                                         &rootSnapshotList) < 0 ||
        esxVI_GetSnapshotTreeByName(rootSnapshotList, snapshot->name,
                                    &snapshotTree, &snapshotTreeParent,
                                    esxVI_Occurrence_RequiredItem) < 0) {
        goto failure;
    }

    def.name = snapshot->name;
    def.description = snapshotTree->description;
    def.parent = snapshotTreeParent != NULL ? snapshotTreeParent->name : NULL;

    if (esxVI_DateTime_ConvertToCalendarTime(snapshotTree->createTime,
                                             &def.creationTime) < 0) {
        goto failure;
    }

    def.state = esxVI_VirtualMachinePowerState_ConvertToLibvirt
                  (snapshotTree->state);

    virUUIDFormat(snapshot->domain->uuid, uuid_string);

    xml = virDomainSnapshotDefFormat(uuid_string, &def, 0);

  cleanup:
    esxVI_VirtualMachineSnapshotTree_Free(&rootSnapshotList);

    return xml;

  failure:
    VIR_FREE(xml);

    goto cleanup;
}



static int
esxDomainSnapshotNum(virDomainPtr domain, unsigned int flags)
{
    int result = 0;
    esxPrivate *priv = domain->conn->privateData;
    esxVI_VirtualMachineSnapshotTree *rootSnapshotTreeList = NULL;

    virCheckFlags(0, -1);

    if (esxVI_EnsureSession(priv->host) < 0) {
        goto failure;
    }

    if (esxVI_LookupRootSnapshotTreeList(priv->host, domain->uuid,
                                         &rootSnapshotTreeList) < 0) {
        goto failure;
    }

    result = esxVI_GetNumberOfSnapshotTrees(rootSnapshotTreeList);

  cleanup:
    esxVI_VirtualMachineSnapshotTree_Free(&rootSnapshotTreeList);

    return result;

  failure:
    result = -1;

    goto cleanup;
}



static int
esxDomainSnapshotListNames(virDomainPtr domain, char **names, int nameslen,
                           unsigned int flags)
{
    int result = 0;
    esxPrivate *priv = domain->conn->privateData;
    esxVI_VirtualMachineSnapshotTree *rootSnapshotTreeList = NULL;

    virCheckFlags(0, -1);

    if (names == NULL || nameslen < 0) {
        ESX_ERROR(VIR_ERR_INVALID_ARG, "%s", _("Invalid argument"));
        return -1;
    }

    if (nameslen == 0) {
        return 0;
    }

    if (esxVI_EnsureSession(priv->host) < 0) {
        goto failure;
    }

    if (esxVI_LookupRootSnapshotTreeList(priv->host, domain->uuid,
                                         &rootSnapshotTreeList) < 0) {
        goto failure;
    }

    result = esxVI_GetSnapshotTreeNames(rootSnapshotTreeList, names, nameslen);

  cleanup:
    esxVI_VirtualMachineSnapshotTree_Free(&rootSnapshotTreeList);

    return result;

  failure:
    result = -1;

    goto cleanup;
}



static virDomainSnapshotPtr
esxDomainSnapshotLookupByName(virDomainPtr domain, const char *name,
                              unsigned int flags)
{
    esxPrivate *priv = domain->conn->privateData;
    esxVI_VirtualMachineSnapshotTree *rootSnapshotTreeList = NULL;
    esxVI_VirtualMachineSnapshotTree *snapshotTree = NULL;
    esxVI_VirtualMachineSnapshotTree *snapshotTreeParent = NULL;
    virDomainSnapshotPtr snapshot = NULL;

    virCheckFlags(0, NULL);

    if (esxVI_EnsureSession(priv->host) < 0) {
        goto cleanup;
    }

    if (esxVI_LookupRootSnapshotTreeList(priv->host, domain->uuid,
                                         &rootSnapshotTreeList) < 0 ||
        esxVI_GetSnapshotTreeByName(rootSnapshotTreeList, name, &snapshotTree,
                                    &snapshotTreeParent,
                                    esxVI_Occurrence_RequiredItem) < 0) {
        goto cleanup;
    }

    snapshot = virGetDomainSnapshot(domain, name);

  cleanup:
    esxVI_VirtualMachineSnapshotTree_Free(&rootSnapshotTreeList);

    return snapshot;
}



static int
esxDomainHasCurrentSnapshot(virDomainPtr domain, unsigned int flags)
{
    int result = 0;
    esxPrivate *priv = domain->conn->privateData;
    esxVI_VirtualMachineSnapshotTree *currentSnapshotTree = NULL;

    virCheckFlags(0, -1);

    if (esxVI_EnsureSession(priv->host) < 0) {
        goto failure;
    }

    if (esxVI_LookupCurrentSnapshotTree(priv->host, domain->uuid,
                                        &currentSnapshotTree,
                                        esxVI_Occurrence_OptionalItem) < 0) {
        goto failure;
    }

    if (currentSnapshotTree != NULL) {
        result = 1;
    }

  cleanup:
    esxVI_VirtualMachineSnapshotTree_Free(&currentSnapshotTree);

    return result;

  failure:
    result = -1;

    goto cleanup;
}



static virDomainSnapshotPtr
esxDomainSnapshotCurrent(virDomainPtr domain, unsigned int flags)
{
    virDomainSnapshotPtr snapshot = NULL;
    esxPrivate *priv = domain->conn->privateData;
    esxVI_VirtualMachineSnapshotTree *currentSnapshotTree = NULL;

    virCheckFlags(0, NULL);

    if (esxVI_EnsureSession(priv->host) < 0) {
        goto cleanup;
    }

    if (esxVI_LookupCurrentSnapshotTree(priv->host, domain->uuid,
                                        &currentSnapshotTree,
                                        esxVI_Occurrence_RequiredItem) < 0) {
        goto cleanup;
    }

    snapshot = virGetDomainSnapshot(domain, currentSnapshotTree->name);

  cleanup:
    esxVI_VirtualMachineSnapshotTree_Free(&currentSnapshotTree);

    return snapshot;
}



static int
esxDomainRevertToSnapshot(virDomainSnapshotPtr snapshot, unsigned int flags)
{
    int result = 0;
    esxPrivate *priv = snapshot->domain->conn->privateData;
    esxVI_VirtualMachineSnapshotTree *rootSnapshotList = NULL;
    esxVI_VirtualMachineSnapshotTree *snapshotTree = NULL;
    esxVI_VirtualMachineSnapshotTree *snapshotTreeParent = NULL;
    esxVI_ManagedObjectReference *task = NULL;
    esxVI_TaskInfoState taskInfoState;

    virCheckFlags(0, -1);

    if (esxVI_EnsureSession(priv->host) < 0) {
        goto failure;
    }

    if (esxVI_LookupRootSnapshotTreeList(priv->host, snapshot->domain->uuid,
                                         &rootSnapshotList) < 0 ||
        esxVI_GetSnapshotTreeByName(rootSnapshotList, snapshot->name,
                                    &snapshotTree, &snapshotTreeParent,
                                    esxVI_Occurrence_RequiredItem) < 0) {
        goto failure;
    }

    if (esxVI_RevertToSnapshot_Task(priv->host, snapshotTree->snapshot, NULL,
                                    &task) < 0 ||
        esxVI_WaitForTaskCompletion(priv->host, task, snapshot->domain->uuid,
                                    priv->autoAnswer, &taskInfoState) < 0) {
        goto failure;
    }

    if (taskInfoState != esxVI_TaskInfoState_Success) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  _("Could not revert to snapshot '%s'"), snapshot->name);
        goto failure;
    }

  cleanup:
    esxVI_VirtualMachineSnapshotTree_Free(&rootSnapshotList);
    esxVI_ManagedObjectReference_Free(&task);

    return result;

  failure:
    result = -1;

    goto cleanup;
}



static int
esxDomainSnapshotDelete(virDomainSnapshotPtr snapshot, unsigned int flags)
{
    int result = 0;
    esxPrivate *priv = snapshot->domain->conn->privateData;
    esxVI_VirtualMachineSnapshotTree *rootSnapshotList = NULL;
    esxVI_VirtualMachineSnapshotTree *snapshotTree = NULL;
    esxVI_VirtualMachineSnapshotTree *snapshotTreeParent = NULL;
    esxVI_Boolean removeChildren = esxVI_Boolean_False;
    esxVI_ManagedObjectReference *task = NULL;
    esxVI_TaskInfoState taskInfoState;

    virCheckFlags(VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN, -1);

    if (esxVI_EnsureSession(priv->host) < 0) {
        goto failure;
    }

    if (flags & VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN) {
        removeChildren = esxVI_Boolean_True;
    }

    if (esxVI_LookupRootSnapshotTreeList(priv->host, snapshot->domain->uuid,
                                         &rootSnapshotList) < 0 ||
        esxVI_GetSnapshotTreeByName(rootSnapshotList, snapshot->name,
                                    &snapshotTree, &snapshotTreeParent,
                                    esxVI_Occurrence_RequiredItem) < 0) {
        goto failure;
    }

    if (esxVI_RemoveSnapshot_Task(priv->host, snapshotTree->snapshot,
                                  removeChildren, &task) < 0 ||
        esxVI_WaitForTaskCompletion(priv->host, task, snapshot->domain->uuid,
                                    priv->autoAnswer, &taskInfoState) < 0) {
        goto failure;
    }

    if (taskInfoState != esxVI_TaskInfoState_Success) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  _("Could not delete snapshot '%s'"), snapshot->name);
        goto failure;
    }

  cleanup:
    esxVI_VirtualMachineSnapshotTree_Free(&rootSnapshotList);
    esxVI_ManagedObjectReference_Free(&task);

    return result;

  failure:
    result = -1;

    goto cleanup;
}



static virDriver esxDriver = {
    VIR_DRV_ESX,
    "ESX",
    esxOpen,                         /* open */
    esxClose,                        /* close */
    esxSupportsFeature,              /* supports_feature */
    esxGetType,                      /* type */
    esxGetVersion,                   /* version */
    NULL,                            /* libvirtVersion (impl. in libvirt.c) */
    esxGetHostname,                  /* hostname */
    NULL,                            /* getMaxVcpus */
    esxNodeGetInfo,                  /* nodeGetInfo */
    esxGetCapabilities,              /* getCapabilities */
    esxListDomains,                  /* listDomains */
    esxNumberOfDomains,              /* numOfDomains */
    NULL,                            /* domainCreateXML */
    esxDomainLookupByID,             /* domainLookupByID */
    esxDomainLookupByUUID,           /* domainLookupByUUID */
    esxDomainLookupByName,           /* domainLookupByName */
    esxDomainSuspend,                /* domainSuspend */
    esxDomainResume,                 /* domainResume */
    esxDomainShutdown,               /* domainShutdown */
    esxDomainReboot,                 /* domainReboot */
    esxDomainDestroy,                /* domainDestroy */
    esxDomainGetOSType,              /* domainGetOSType */
    esxDomainGetMaxMemory,           /* domainGetMaxMemory */
    esxDomainSetMaxMemory,           /* domainSetMaxMemory */
    esxDomainSetMemory,              /* domainSetMemory */
    esxDomainGetInfo,                /* domainGetInfo */
    NULL,                            /* domainSave */
    NULL,                            /* domainRestore */
    NULL,                            /* domainCoreDump */
    esxDomainSetVcpus,               /* domainSetVcpus */
    NULL,                            /* domainPinVcpu */
    NULL,                            /* domainGetVcpus */
    esxDomainGetMaxVcpus,            /* domainGetMaxVcpus */
    NULL,                            /* domainGetSecurityLabel */
    NULL,                            /* nodeGetSecurityModel */
    esxDomainDumpXML,                /* domainDumpXML */
    esxDomainXMLFromNative,          /* domainXMLFromNative */
    esxDomainXMLToNative,            /* domainXMLToNative */
    esxListDefinedDomains,           /* listDefinedDomains */
    esxNumberOfDefinedDomains,       /* numOfDefinedDomains */
    esxDomainCreate,                 /* domainCreate */
    esxDomainDefineXML,              /* domainDefineXML */
    esxDomainUndefine,               /* domainUndefine */
    NULL,                            /* domainAttachDevice */
    NULL,                            /* domainAttachDeviceFlags */
    NULL,                            /* domainDetachDevice */
    NULL,                            /* domainDetachDeviceFlags */
    NULL,                            /* domainUpdateDeviceFlags */
    NULL,                            /* domainGetAutostart */
    NULL,                            /* domainSetAutostart */
    esxDomainGetSchedulerType,       /* domainGetSchedulerType */
    esxDomainGetSchedulerParameters, /* domainGetSchedulerParameters */
    esxDomainSetSchedulerParameters, /* domainSetSchedulerParameters */
    esxDomainMigratePrepare,         /* domainMigratePrepare */
    esxDomainMigratePerform,         /* domainMigratePerform */
    esxDomainMigrateFinish,          /* domainMigrateFinish */
    NULL,                            /* domainBlockStats */
    NULL,                            /* domainInterfaceStats */
    NULL,                            /* domainMemoryStats */
    NULL,                            /* domainBlockPeek */
    NULL,                            /* domainMemoryPeek */
    NULL,                            /* domainGetBlockInfo */
    NULL,                            /* nodeGetCellsFreeMemory */
    esxNodeGetFreeMemory,            /* nodeGetFreeMemory */
    NULL,                            /* domainEventRegister */
    NULL,                            /* domainEventDeregister */
    NULL,                            /* domainMigratePrepare2 */
    NULL,                            /* domainMigrateFinish2 */
    NULL,                            /* nodeDeviceDettach */
    NULL,                            /* nodeDeviceReAttach */
    NULL,                            /* nodeDeviceReset */
    NULL,                            /* domainMigratePrepareTunnel */
    esxIsEncrypted,                  /* isEncrypted */
    esxIsSecure,                     /* isSecure */
    esxDomainIsActive,               /* domainIsActive */
    esxDomainIsPersistent,           /* domainIsPersistent */
    NULL,                            /* cpuCompare */
    NULL,                            /* cpuBaseline */
    NULL,                            /* domainGetJobInfo */
    NULL,                            /* domainAbortJob */
    NULL,                            /* domainMigrateSetMaxDowntime */
    NULL,                            /* domainEventRegisterAny */
    NULL,                            /* domainEventDeregisterAny */
    NULL,                            /* domainManagedSave */
    NULL,                            /* domainHasManagedSaveImage */
    NULL,                            /* domainManagedSaveRemove */
    esxDomainSnapshotCreateXML,      /* domainSnapshotCreateXML */
    esxDomainSnapshotDumpXML,        /* domainSnapshotDumpXML */
    esxDomainSnapshotNum,            /* domainSnapshotNum */
    esxDomainSnapshotListNames,      /* domainSnapshotListNames */
    esxDomainSnapshotLookupByName,   /* domainSnapshotLookupByName */
    esxDomainHasCurrentSnapshot,     /* domainHasCurrentSnapshot */
    esxDomainSnapshotCurrent,        /* domainSnapshotCurrent */
    esxDomainRevertToSnapshot,       /* domainRevertToSnapshot */
    esxDomainSnapshotDelete,         /* domainSnapshotDelete */
};



int
esxRegister(void)
{
    if (virRegisterDriver(&esxDriver) < 0 ||
        esxInterfaceRegister() < 0 ||
        esxNetworkRegister() < 0 ||
        esxStorageRegister() < 0 ||
        esxDeviceRegister() < 0 ||
        esxSecretRegister() < 0 ||
        esxNWFilterRegister() < 0) {
        return -1;
    }

    return 0;
}
