/*
 * esx_driver.c: core driver functions for managing VMware ESX hosts
 *
 * Copyright (C) 2010-2015 Red Hat, Inc.
 * Copyright (C) 2009-2014 Matthias Bolte <matthias.bolte@googlemail.com>
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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 */

#include <config.h>

#include "internal.h"
#include "virdomainobjlist.h"
#include "snapshot_conf.h"
#include "virauth.h"
#include "viralloc.h"
#include "virfile.h"
#include "virlog.h"
#include "viruuid.h"
#include "vmx.h"
#include "virtypedparam.h"
#include "esx_driver.h"
#include "esx_interface_driver.h"
#include "esx_network_driver.h"
#include "esx_storage_driver.h"
#include "esx_private.h"
#include "esx_vi.h"
#include "esx_vi_methods.h"
#include "esx_util.h"
#include "esx_stream.h"
#include "virstring.h"
#include "viruri.h"

#define VIR_FROM_THIS VIR_FROM_ESX

VIR_LOG_INIT("esx.esx_driver");

static int esxDomainGetMaxVcpus(virDomainPtr domain);

typedef struct _esxVMX_Data esxVMX_Data;

struct _esxVMX_Data {
    esxVI_Context *ctx;
    char *datastorePathWithoutFileName;
};



static void
esxFreePrivate(esxPrivate **priv)
{
    if (!priv || !(*priv))
        return;

    esxVI_Context_Free(&(*priv)->host);
    esxVI_Context_Free(&(*priv)->vCenter);
    esxUtil_FreeParsedUri(&(*priv)->parsedUri);
    virObjectUnref((*priv)->caps);
    virObjectUnref((*priv)->xmlopt);
    VIR_FREE(*priv);
}



/*
 * Parse a file name from a .vmx file and convert it to datastore path format
 * if possible. A .vmx file can contain file names in various formats:
 *
 * - A single name referencing a file in the same directory as the .vmx file:
 *
 *     test1.vmdk
 *
 * - An absolute file name referencing a file in a datastore that is mounted at
 *   /vmfs/volumes/<datastore>:
 *
 *     /vmfs/volumes/b24b7a78-9d82b4f5/test1/test1.vmdk
 *     /vmfs/volumes/datastore1/test1/test1.vmdk
 *
 *   The actual mount directory is /vmfs/volumes/b24b7a78-9d82b4f5, the second
 *   form is a symlink to it using the datastore name. This is the typical
 *   setup on an ESX(i) server.
 *
 * - With GSX installed on Windows there are also Windows style file names
 *   including UNC file names:
 *
 *     C:\Virtual Machines\test1\test1.vmdk
 *     \\nas1\storage1\test1\test1.vmdk
 *
 * - There might also be absolute file names referencing files outside of a
 *   datastore:
 *
 *     /usr/lib/vmware/isoimages/linux.iso
 *
 *   Such file names are left as is and are not converted to datastore path
 *   format because this is not possible.
 *
 * The datastore path format typically looks like this:
 *
 *  [datastore1] test1/test1.vmdk
 *
 * Firstly this functions checks if the given file name contains a separator.
 * If it doesn't then the referenced file is in the same directory as the .vmx
 * file. The datastore name and directory of the .vmx file are passed to this
 * function via the opaque parameter by the caller of virVMXParseConfig.
 *
 * Otherwise query for all known datastores and their mount directories. Then
 * try to find a datastore with a mount directory that is a prefix to the given
 * file name. This mechanism covers the Windows style file names too.
 *
 * The symlinks using the datastore name (/vmfs/volumes/datastore1) are an
 * exception and need special handling. Parse the datastore name and use it
 * to lookup the datastore by name to verify that it exists.
 */
static char *
esxParseVMXFileName(const char *fileName, void *opaque)
{
    char *result = NULL;
    esxVMX_Data *data = opaque;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *datastoreList = NULL;
    esxVI_ObjectContent *datastore = NULL;
    esxVI_DatastoreHostMount *hostMount = NULL;
    char *datastoreName;
    char *tmp;
    char *saveptr;
    char *strippedFileName = NULL;
    char *copyOfFileName = NULL;
    char *directoryAndFileName;

    if (!strchr(fileName, '/') && !strchr(fileName, '\\')) {
        /* Plain file name, use same directory as for the .vmx file */
        if (virAsprintf(&result, "%s/%s",
                        data->datastorePathWithoutFileName, fileName) < 0)
            goto cleanup;
    } else {
        if (esxVI_String_AppendValueToList(&propertyNameList,
                                           "summary.name") < 0 ||
            esxVI_LookupDatastoreList(data->ctx, propertyNameList,
                                      &datastoreList) < 0) {
            return NULL;
        }

        /* Search for datastore by mount path */
        for (datastore = datastoreList; datastore;
             datastore = datastore->_next) {
            esxVI_DatastoreHostMount_Free(&hostMount);
            datastoreName = NULL;

            if (esxVI_LookupDatastoreHostMount(data->ctx, datastore->obj,
                                               &hostMount,
                                               esxVI_Occurrence_RequiredItem) < 0 ||
                esxVI_GetStringValue(datastore, "summary.name", &datastoreName,
                                     esxVI_Occurrence_RequiredItem) < 0) {
                goto cleanup;
            }

            tmp = (char *)STRSKIP(fileName, hostMount->mountInfo->path);

            if (!tmp)
                continue;

            /* Found a match. Strip leading separators */
            while (*tmp == '/' || *tmp == '\\')
                ++tmp;

            if (VIR_STRDUP(strippedFileName, tmp) < 0)
                goto cleanup;

            tmp = strippedFileName;

            /* Convert \ to / */
            while (*tmp != '\0') {
                if (*tmp == '\\')
                    *tmp = '/';

                ++tmp;
            }

            if (virAsprintf(&result, "[%s] %s", datastoreName,
                            strippedFileName) < 0)
                goto cleanup;

            break;
        }

        /* Fallback to direct datastore name match */
        if (!result && STRPREFIX(fileName, "/vmfs/volumes/")) {
            if (VIR_STRDUP(copyOfFileName, fileName) < 0)
                goto cleanup;

            /* Expected format: '/vmfs/volumes/<datastore>/<path>' */
            if (!(tmp = STRSKIP(copyOfFileName, "/vmfs/volumes/")) ||
                !(datastoreName = strtok_r(tmp, "/", &saveptr))    ||
                !(directoryAndFileName = strtok_r(NULL, "", &saveptr))) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("File name '%s' doesn't have expected format "
                                 "'/vmfs/volumes/<datastore>/<path>'"), fileName);
                goto cleanup;
            }

            esxVI_ObjectContent_Free(&datastoreList);

            if (esxVI_LookupDatastoreByName(data->ctx, datastoreName,
                                            NULL, &datastoreList,
                                            esxVI_Occurrence_OptionalItem) < 0) {
                goto cleanup;
            }

            if (!datastoreList) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("File name '%s' refers to non-existing datastore '%s'"),
                               fileName, datastoreName);
                goto cleanup;
            }

            if (virAsprintf(&result, "[%s] %s", datastoreName,
                            directoryAndFileName) < 0)
                goto cleanup;
        }

        /* If it's an absolute path outside of a datastore just use it as is */
        if (!result && *fileName == '/') {
            /* FIXME: need to deal with Windows paths here too */
            if (VIR_STRDUP(result, fileName) < 0)
                goto cleanup;
        }

        if (!result) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Could not handle file name '%s'"), fileName);
            goto cleanup;
        }
    }

 cleanup:
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&datastoreList);
    esxVI_DatastoreHostMount_Free(&hostMount);
    VIR_FREE(strippedFileName);
    VIR_FREE(copyOfFileName);

    return result;
}



/*
 * This function does the inverse of esxParseVMXFileName. It takes a file name
 * in datastore path format or in absolute format and converts it to a file
 * name that can be used in a .vmx file.
 *
 * The datastore path format and the formats found in a .vmx file are described
 * in the documentation of esxParseVMXFileName.
 *
 * Firstly parse the datastore path. Then use the datastore name to lookup the
 * datastore and its mount path. Finally concatenate the mount path, directory
 * and file name to an absolute path and return it. Detect the separator type
 * based on the mount path.
 */
static char *
esxFormatVMXFileName(const char *fileName, void *opaque)
{
    bool success = false;
    char *result = NULL;
    esxVMX_Data *data = opaque;
    char *datastoreName = NULL;
    char *directoryAndFileName = NULL;
    esxVI_ObjectContent *datastore = NULL;
    esxVI_DatastoreHostMount *hostMount = NULL;
    char separator = '/';
    virBuffer buffer = VIR_BUFFER_INITIALIZER;
    char *tmp;
    size_t length;

    if (*fileName == '[') {
        /* Parse datastore path and lookup datastore */
        if (esxUtil_ParseDatastorePath(fileName, &datastoreName, NULL,
                                       &directoryAndFileName) < 0) {
            goto cleanup;
        }

        if (esxVI_LookupDatastoreByName(data->ctx, datastoreName, NULL, &datastore,
                                        esxVI_Occurrence_RequiredItem) < 0 ||
            esxVI_LookupDatastoreHostMount(data->ctx, datastore->obj,
                                           &hostMount,
                                           esxVI_Occurrence_RequiredItem) < 0) {
            goto cleanup;
        }

        /* Detect separator type */
        if (strchr(hostMount->mountInfo->path, '\\'))
            separator = '\\';

        /* Strip trailing separators */
        length = strlen(hostMount->mountInfo->path);

        while (length > 0 && hostMount->mountInfo->path[length - 1] == separator)
            --length;

        /* Format as <mount>[/<directory>]/<file>, convert / to \ when necessary */
        virBufferAdd(&buffer, hostMount->mountInfo->path, length);

        if (separator != '/') {
            tmp = directoryAndFileName;

            while (*tmp != '\0') {
                if (*tmp == '/')
                    *tmp = separator;

                ++tmp;
            }
        }

        virBufferAddChar(&buffer, separator);
        virBufferAdd(&buffer, directoryAndFileName, -1);

        if (virBufferCheckError(&buffer) < 0)
            goto cleanup;

        result = virBufferContentAndReset(&buffer);
    } else if (*fileName == '/') {
        /* FIXME: need to deal with Windows paths here too */
        if (VIR_STRDUP(result, fileName) < 0)
            goto cleanup;
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not handle file name '%s'"), fileName);
        goto cleanup;
    }

    /* FIXME: Check if referenced path/file really exists */

    success = true;

 cleanup:
    if (! success) {
        virBufferFreeAndReset(&buffer);
        VIR_FREE(result);
    }

    VIR_FREE(datastoreName);
    VIR_FREE(directoryAndFileName);
    esxVI_ObjectContent_Free(&datastore);
    esxVI_DatastoreHostMount_Free(&hostMount);

    return result;
}



static int
esxAutodetectSCSIControllerModel(virDomainDiskDefPtr def, int *model,
                                 void *opaque)
{
    int result = -1;
    esxVMX_Data *data = opaque;
    esxVI_FileInfo *fileInfo = NULL;
    esxVI_VmDiskFileInfo *vmDiskFileInfo = NULL;
    const char *src = virDomainDiskGetSource(def);

    if (def->device != VIR_DOMAIN_DISK_DEVICE_DISK ||
        def->bus != VIR_DOMAIN_DISK_BUS_SCSI ||
        virDomainDiskGetType(def) != VIR_STORAGE_TYPE_FILE ||
        !src || !STRPREFIX(src, "[")) {
        /*
         * This isn't a file-based SCSI disk device with a datastore related
         * source path => do nothing.
         */
        return 0;
    }

    if (esxVI_LookupFileInfoByDatastorePath(data->ctx, src,
                                            false, &fileInfo,
                                            esxVI_Occurrence_RequiredItem) < 0) {
        goto cleanup;
    }

    vmDiskFileInfo = esxVI_VmDiskFileInfo_DynamicCast(fileInfo);

    if (!vmDiskFileInfo || !vmDiskFileInfo->controllerType) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not lookup controller model for '%s'"), src);
        goto cleanup;
    }

    if (STRCASEEQ(vmDiskFileInfo->controllerType,
                  "VirtualBusLogicController")) {
        *model = VIR_DOMAIN_CONTROLLER_MODEL_SCSI_BUSLOGIC;
    } else if (STRCASEEQ(vmDiskFileInfo->controllerType,
                         "VirtualLsiLogicController")) {
        *model = VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LSILOGIC;
    } else if (STRCASEEQ(vmDiskFileInfo->controllerType,
                         "VirtualLsiLogicSASController")) {
        *model = VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LSISAS1068;
    } else if (STRCASEEQ(vmDiskFileInfo->controllerType,
                         "ParaVirtualSCSIController")) {
        *model = VIR_DOMAIN_CONTROLLER_MODEL_SCSI_VMPVSCSI;
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Found unexpected controller model '%s' for disk '%s'"),
                       vmDiskFileInfo->controllerType, src);
        goto cleanup;
    }

    result = 0;

 cleanup:
    esxVI_FileInfo_Free(&fileInfo);

    return result;
}



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

    if (priv->supportsLongMode != esxVI_Boolean_Undefined)
        return priv->supportsLongMode;

    if (esxVI_EnsureSession(priv->primary) < 0)
        return esxVI_Boolean_Undefined;

    if (esxVI_String_AppendValueToList(&propertyNameList,
                                       "hardware.cpuFeature") < 0 ||
        esxVI_LookupHostSystemProperties(priv->primary, propertyNameList,
                                         &hostSystem) < 0) {
        goto cleanup;
    }

    for (dynamicProperty = hostSystem->propSet; dynamicProperty;
         dynamicProperty = dynamicProperty->_next) {
        if (STREQ(dynamicProperty->name, "hardware.cpuFeature")) {
            if (esxVI_HostCpuIdInfo_CastListFromAnyType
                  (dynamicProperty->val, &hostCpuIdInfoList) < 0) {
                goto cleanup;
            }

            for (hostCpuIdInfo = hostCpuIdInfoList; hostCpuIdInfo;
                 hostCpuIdInfo = hostCpuIdInfo->_next) {
                if (hostCpuIdInfo->level->value == -2147483647) { /* 0x80000001 */
                    if (esxVI_ParseHostCpuIdInfo(&parsedHostCpuIdInfo,
                                                 hostCpuIdInfo) < 0) {
                        goto cleanup;
                    }

                    edxLongModeBit = parsedHostCpuIdInfo.edx[29];

                    if (edxLongModeBit == '1') {
                        priv->supportsLongMode = esxVI_Boolean_True;
                    } else if (edxLongModeBit == '0') {
                        priv->supportsLongMode = esxVI_Boolean_False;
                    } else {
                        virReportError(VIR_ERR_INTERNAL_ERROR,
                                       _("Bit 29 (Long Mode) of HostSystem property "
                                         "'hardware.cpuFeature[].edx' with value '%s' "
                                         "has unexpected value '%c', expecting '0' "
                                         "or '1'"), hostCpuIdInfo->edx, edxLongModeBit);
                        goto cleanup;
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
    /*
     * If we goto cleanup in case of an error then priv->supportsLongMode
     * is still esxVI_Boolean_Undefined, therefore we don't need to set it.
     */
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&hostSystem);
    esxVI_HostCpuIdInfo_Free(&hostCpuIdInfoList);

    return priv->supportsLongMode;
}



static int
esxLookupHostSystemBiosUuid(esxPrivate *priv, unsigned char *uuid)
{
    int result = -1;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *hostSystem = NULL;
    char *uuid_string = NULL;

    if (esxVI_EnsureSession(priv->primary) < 0)
        return -1;

    if (esxVI_String_AppendValueToList(&propertyNameList,
                                       "hardware.systemInfo.uuid") < 0 ||
        esxVI_LookupHostSystemProperties(priv->primary, propertyNameList,
                                         &hostSystem) < 0 ||
        esxVI_GetStringValue(hostSystem, "hardware.systemInfo.uuid",
                             &uuid_string, esxVI_Occurrence_RequiredItem) < 0) {
        goto cleanup;
    }

    if (strlen(uuid_string) > 0) {
        if (virUUIDParse(uuid_string, uuid) < 0) {
            VIR_WARN("Could not parse host UUID from string '%s'", uuid_string);

            /* HostSystem has an invalid UUID, ignore it */
            memset(uuid, 0, VIR_UUID_BUFLEN);
        }
    } else {
        /* HostSystem has an empty UUID */
        memset(uuid, 0, VIR_UUID_BUFLEN);
    }

    result = 0;

 cleanup:
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&hostSystem);

    return result;
}


static virCapsPtr
esxCapsInit(esxPrivate *priv)
{
    esxVI_Boolean supportsLongMode = esxSupportsLongMode(priv);
    virCapsPtr caps = NULL;
    virCapsGuestPtr guest = NULL;

    if (supportsLongMode == esxVI_Boolean_Undefined)
        return NULL;

    if (supportsLongMode == esxVI_Boolean_True) {
        caps = virCapabilitiesNew(VIR_ARCH_X86_64, true, true);
    } else {
        caps = virCapabilitiesNew(VIR_ARCH_I686, true, true);
    }

    if (!caps)
        return NULL;

    virCapabilitiesAddHostMigrateTransport(caps, "vpxmigr");


    if (esxLookupHostSystemBiosUuid(priv, caps->host.host_uuid) < 0)
        goto failure;

    /* i686 */
    guest = virCapabilitiesAddGuest(caps, VIR_DOMAIN_OSTYPE_HVM,
                                    VIR_ARCH_I686,
                                    NULL, NULL, 0,
                                    NULL);

    if (!guest)
        goto failure;

    if (!virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_VMWARE, NULL, NULL, 0, NULL))
        goto failure;

    /* x86_64 */
    if (supportsLongMode == esxVI_Boolean_True) {
        guest = virCapabilitiesAddGuest(caps, VIR_DOMAIN_OSTYPE_HVM,
                                        VIR_ARCH_X86_64,
                                        NULL, NULL,
                                        0, NULL);

        if (!guest)
            goto failure;

        if (!virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_VMWARE, NULL, NULL, 0, NULL))
            goto failure;
    }

    return caps;

 failure:
    virObjectUnref(caps);

    return NULL;
}



static int
esxConnectToHost(esxPrivate *priv,
                 virConnectPtr conn,
                 virConnectAuthPtr auth,
                 char **vCenterIPAddress)
{
    int result = -1;
    char ipAddress[NI_MAXHOST] = "";
    char *username = NULL;
    char *password = NULL;
    char *url = NULL;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *hostSystem = NULL;
    esxVI_Boolean inMaintenanceMode = esxVI_Boolean_Undefined;
    esxVI_ProductLine expectedProductLine = STRCASEEQ(conn->uri->scheme, "esx")
        ? esxVI_ProductLine_ESX
        : esxVI_ProductLine_GSX;

    if (!vCenterIPAddress || *vCenterIPAddress) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (esxUtil_ResolveHostname(conn->uri->server, ipAddress, NI_MAXHOST) < 0)
        return -1;

    if (conn->uri->user) {
        if (VIR_STRDUP(username, conn->uri->user) < 0)
            goto cleanup;
    } else {
        username = virAuthGetUsername(conn, auth, "esx", "root", conn->uri->server);

        if (!username) {
            virReportError(VIR_ERR_AUTH_FAILED, "%s", _("Username request failed"));
            goto cleanup;
        }
    }

    password = virAuthGetPassword(conn, auth, "esx", username, conn->uri->server);

    if (!password) {
        virReportError(VIR_ERR_AUTH_FAILED, "%s", _("Password request failed"));
        goto cleanup;
    }

    if (virAsprintf(&url, "%s://%s:%d/sdk", priv->parsedUri->transport,
                    conn->uri->server, conn->uri->port) < 0)
        goto cleanup;

    if (esxVI_Context_Alloc(&priv->host) < 0 ||
        esxVI_Context_Connect(priv->host, url, ipAddress, username, password,
                              priv->parsedUri) < 0 ||
        esxVI_Context_LookupManagedObjects(priv->host) < 0) {
        goto cleanup;
    }

    if (priv->host->productLine != expectedProductLine) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Expecting '%s' to be a %s host but found a %s host"),
                       conn->uri->server,
                       esxVI_ProductLineToDisplayName(expectedProductLine),
                       esxVI_ProductLineToDisplayName(priv->host->productLine));
        goto cleanup;
    }

    /* Query the host for maintenance mode and vCenter IP address */
    if (esxVI_String_AppendValueListToList(&propertyNameList,
                                           "runtime.inMaintenanceMode\0"
                                           "summary.managementServerIp\0") < 0 ||
        esxVI_LookupHostSystemProperties(priv->host, propertyNameList,
                                         &hostSystem) < 0 ||
        esxVI_GetBoolean(hostSystem, "runtime.inMaintenanceMode",
                         &inMaintenanceMode,
                         esxVI_Occurrence_RequiredItem) < 0 ||
        esxVI_GetStringValue(hostSystem, "summary.managementServerIp",
                             vCenterIPAddress,
                             esxVI_Occurrence_OptionalItem) < 0) {
        goto cleanup;
    }

    /* Warn if host is in maintenance mode */
    if (inMaintenanceMode == esxVI_Boolean_True)
        VIR_WARN("The server is in maintenance mode");

    if (VIR_STRDUP(*vCenterIPAddress, *vCenterIPAddress) < 0)
        goto cleanup;

    result = 0;

 cleanup:
    VIR_FREE(username);
    VIR_FREE(password);
    VIR_FREE(url);
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&hostSystem);

    return result;
}



static int
esxConnectToVCenter(esxPrivate *priv,
                    virConnectPtr conn,
                    virConnectAuthPtr auth,
                    const char *hostname,
                    const char *hostSystemIPAddress)
{
    int result = -1;
    char ipAddress[NI_MAXHOST] = "";
    char *username = NULL;
    char *password = NULL;
    char *url = NULL;

    if (!hostSystemIPAddress &&
        (!priv->parsedUri->path || STREQ(priv->parsedUri->path, "/"))) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Path has to specify the datacenter and compute resource"));
        return -1;
    }

    if (esxUtil_ResolveHostname(hostname, ipAddress, NI_MAXHOST) < 0)
        return -1;

    if (conn->uri->user) {
        if (VIR_STRDUP(username, conn->uri->user) < 0)
            goto cleanup;
    } else {
        username = virAuthGetUsername(conn, auth, "esx", "administrator", hostname);

        if (!username) {
            virReportError(VIR_ERR_AUTH_FAILED, "%s", _("Username request failed"));
            goto cleanup;
        }
    }

    password = virAuthGetPassword(conn, auth, "esx", username, hostname);

    if (!password) {
        virReportError(VIR_ERR_AUTH_FAILED, "%s", _("Password request failed"));
        goto cleanup;
    }

    if (virAsprintf(&url, "%s://%s:%d/sdk", priv->parsedUri->transport,
                    hostname, conn->uri->port) < 0)
        goto cleanup;

    if (esxVI_Context_Alloc(&priv->vCenter) < 0 ||
        esxVI_Context_Connect(priv->vCenter, url, ipAddress, username,
                              password, priv->parsedUri) < 0) {
        goto cleanup;
    }

    if (priv->vCenter->productLine != esxVI_ProductLine_VPX) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Expecting '%s' to be a %s host but found a %s host"),
                       hostname,
                       esxVI_ProductLineToDisplayName(esxVI_ProductLine_VPX),
                       esxVI_ProductLineToDisplayName(priv->vCenter->productLine));
        goto cleanup;
    }

    if (hostSystemIPAddress) {
        if (esxVI_Context_LookupManagedObjectsByHostSystemIp
              (priv->vCenter, hostSystemIPAddress) < 0) {
            goto cleanup;
        }
    } else {
        if (esxVI_Context_LookupManagedObjectsByPath(priv->vCenter,
                                                     priv->parsedUri->path) < 0) {
            goto cleanup;
        }
    }

    result = 0;

 cleanup:
    VIR_FREE(username);
    VIR_FREE(password);
    VIR_FREE(url);

    return result;
}



/*
 * URI format: {vpx|esx|gsx}://[<username>@]<hostname>[:<port>]/[<path>][?<query parameter>...]
 *             <path> = [<folder>/...]<datacenter>/[<folder>/...]<computeresource>[/<hostsystem>]
 *
 * If no port is specified the default port is set dependent on the scheme and
 * transport parameter:
 * - vpx+http  80
 * - vpx+https 443
 * - esx+http  80
 * - esx+https 443
 * - gsx+http  8222
 * - gsx+https 8333
 *
 * For a vpx:// connection <path> references a host managed by the vCenter.
 * In case the host is part of a cluster then <computeresource> is the cluster
 * name. Otherwise <computeresource> and <hostsystem> are equal and the later
 * can be omitted. As datacenters and computeresources can be organized in
 * folders those have to be included in <path>.
 *
 * Optional query parameters:
 * - transport={http|https}
 * - vcenter={<vcenter>|*}             only useful for an esx:// connection
 * - no_verify={0|1}
 * - auto_answer={0|1}
 * - proxy=[{http|socks|socks4|socks4a|socks5}://]<hostname>[:<port>]
 *
 * If no transport parameter is specified https is used.
 *
 * The vcenter parameter is only necessary for migration, because the vCenter
 * server is in charge to initiate a migration between two ESX hosts. The
 * vcenter parameter can be set to an explicitly hostname or to *. If set to *,
 * the driver will check if the ESX host is managed by a vCenter and connect to
 * it. If the ESX host is not managed by a vCenter an error is reported.
 *
 * If the no_verify parameter is set to 1, this disables libcurl client checks
 * of the server's certificate. The default value is 0.
 *
 * If the auto_answer parameter is set to 1, the driver will respond to all
 * virtual machine questions with the default answer, otherwise virtual machine
 * questions will be reported as errors. The default value is 0.
 *
 * The proxy parameter allows to specify a proxy for to be used by libcurl.
 * The default for the optional <type> part is http and socks is synonymous for
 * socks5. The optional <port> part allows to override the default port 1080.
 */
static virDrvOpenStatus
esxConnectOpen(virConnectPtr conn, virConnectAuthPtr auth,
               virConfPtr conf ATTRIBUTE_UNUSED,
               unsigned int flags)
{
    virDrvOpenStatus result = VIR_DRV_OPEN_ERROR;
    char *plus;
    esxPrivate *priv = NULL;
    char *potentialVCenterIPAddress = NULL;
    char vCenterIPAddress[NI_MAXHOST] = "";

    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    /* Decline if the URI is NULL or the scheme is NULL */
    if (!conn->uri || !conn->uri->scheme)
        return VIR_DRV_OPEN_DECLINED;

    /* Decline if the scheme is not one of {vpx|esx|gsx} */
    plus = strchr(conn->uri->scheme, '+');

    if (!plus) {
        if (STRCASENEQ(conn->uri->scheme, "vpx") &&
            STRCASENEQ(conn->uri->scheme, "esx") &&
            STRCASENEQ(conn->uri->scheme, "gsx")) {
            return VIR_DRV_OPEN_DECLINED;
        }
    } else {
        if (plus - conn->uri->scheme != 3 ||
            (STRCASENEQLEN(conn->uri->scheme, "vpx", 3) &&
             STRCASENEQLEN(conn->uri->scheme, "esx", 3) &&
             STRCASENEQLEN(conn->uri->scheme, "gsx", 3))) {
            return VIR_DRV_OPEN_DECLINED;
        }

        virReportError(VIR_ERR_INVALID_ARG,
                       _("Transport '%s' in URI scheme is not supported, try again "
                         "without the transport part"), plus + 1);
        return VIR_DRV_OPEN_ERROR;
    }

    if (STRCASENEQ(conn->uri->scheme, "vpx") &&
        conn->uri->path && STRNEQ(conn->uri->path, "/")) {
        VIR_WARN("Ignoring unexpected path '%s' for non-vpx scheme '%s'",
                 conn->uri->path, conn->uri->scheme);
    }

    /* Require server part */
    if (!conn->uri->server) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("URI is missing the server part"));
        return VIR_DRV_OPEN_ERROR;
    }

    /* Require auth */
    if (!auth || !auth->cb) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Missing or invalid auth pointer"));
        return VIR_DRV_OPEN_ERROR;
    }

    /* Allocate per-connection private data */
    if (VIR_ALLOC(priv) < 0)
        goto cleanup;

    if (esxUtil_ParseUri(&priv->parsedUri, conn->uri) < 0)
        goto cleanup;

    priv->maxVcpus = -1;
    priv->supportsVMotion = esxVI_Boolean_Undefined;
    priv->supportsLongMode = esxVI_Boolean_Undefined;
    priv->supportsScreenshot = esxVI_Boolean_Undefined;
    priv->usedCpuTimeCounterId = -1;

    /*
     * Set the port dependent on the transport protocol if no port is
     * specified. This allows us to rely on the port parameter being
     * correctly set when building URIs later on, without the need to
     * distinguish between the situations port == 0 and port != 0
     */
    if (conn->uri->port == 0) {
        if (STRCASEEQ(conn->uri->scheme, "vpx") ||
            STRCASEEQ(conn->uri->scheme, "esx")) {
            if (STRCASEEQ(priv->parsedUri->transport, "https")) {
                conn->uri->port = 443;
            } else {
                conn->uri->port = 80;
            }
        } else { /* GSX */
            if (STRCASEEQ(priv->parsedUri->transport, "https")) {
                conn->uri->port = 8333;
            } else {
                conn->uri->port = 8222;
            }
        }
    }

    if (STRCASEEQ(conn->uri->scheme, "esx") ||
        STRCASEEQ(conn->uri->scheme, "gsx")) {
        /* Connect to host */
        if (esxConnectToHost(priv, conn, auth,
                             &potentialVCenterIPAddress) < 0) {
            goto cleanup;
        }

        /* Connect to vCenter */
        if (priv->parsedUri->vCenter) {
            if (STREQ(priv->parsedUri->vCenter, "*")) {
                if (!potentialVCenterIPAddress) {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("This host is not managed by a vCenter"));
                    goto cleanup;
                }

                if (!virStrcpyStatic(vCenterIPAddress,
                                     potentialVCenterIPAddress)) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("vCenter IP address %s too big for destination"),
                                   potentialVCenterIPAddress);
                    goto cleanup;
                }
            } else {
                if (esxUtil_ResolveHostname(priv->parsedUri->vCenter,
                                            vCenterIPAddress, NI_MAXHOST) < 0) {
                    goto cleanup;
                }

                if (potentialVCenterIPAddress &&
                    STRNEQ(vCenterIPAddress, potentialVCenterIPAddress)) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("This host is managed by a vCenter with IP "
                                     "address %s, but a mismatching vCenter '%s' "
                                     "(%s) has been specified"),
                                   potentialVCenterIPAddress, priv->parsedUri->vCenter,
                                   vCenterIPAddress);
                    goto cleanup;
                }
            }

            if (esxConnectToVCenter(priv, conn, auth,
                                    vCenterIPAddress,
                                    priv->host->ipAddress) < 0) {
                goto cleanup;
            }
        }

        priv->primary = priv->host;
    } else { /* VPX */
        /* Connect to vCenter */
        if (esxConnectToVCenter(priv, conn, auth,
                                conn->uri->server,
                                NULL) < 0) {
            goto cleanup;
        }

        priv->primary = priv->vCenter;
    }

    /* Setup capabilities */
    priv->caps = esxCapsInit(priv);

    if (!priv->caps)
        goto cleanup;

    if (!(priv->xmlopt = virVMXDomainXMLConfInit()))
        goto cleanup;

    conn->privateData = priv;
    priv = NULL;
    result = VIR_DRV_OPEN_SUCCESS;

 cleanup:
    esxFreePrivate(&priv);
    VIR_FREE(potentialVCenterIPAddress);

    return result;
}



static int
esxConnectClose(virConnectPtr conn)
{
    esxPrivate *priv = conn->privateData;
    int result = 0;

    if (priv->host) {
        if (esxVI_EnsureSession(priv->host) < 0 ||
            esxVI_Logout(priv->host) < 0) {
            result = -1;
        }
    }

    if (priv->vCenter) {
        if (esxVI_EnsureSession(priv->vCenter) < 0 ||
            esxVI_Logout(priv->vCenter) < 0) {
            result = -1;
        }
    }

    esxFreePrivate(&priv);

    conn->privateData = NULL;

    return result;
}



static esxVI_Boolean
esxSupportsVMotion(esxPrivate *priv)
{
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *hostSystem = NULL;

    if (priv->supportsVMotion != esxVI_Boolean_Undefined)
        return priv->supportsVMotion;

    if (esxVI_EnsureSession(priv->primary) < 0)
        return esxVI_Boolean_Undefined;

    if (esxVI_String_AppendValueToList(&propertyNameList,
                                       "capability.vmotionSupported") < 0 ||
        esxVI_LookupHostSystemProperties(priv->primary, propertyNameList,
                                         &hostSystem) < 0 ||
        esxVI_GetBoolean(hostSystem, "capability.vmotionSupported",
                         &priv->supportsVMotion,
                         esxVI_Occurrence_RequiredItem) < 0) {
        goto cleanup;
    }

 cleanup:
    /*
     * If we goto cleanup in case of an error then priv->supportsVMotion is
     * still esxVI_Boolean_Undefined, therefore we don't need to set it.
     */
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&hostSystem);

    return priv->supportsVMotion;
}



static esxVI_Boolean
esxSupportsScreenshot(esxPrivate *priv)
{
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *hostSystem = NULL;

    if (priv->supportsScreenshot != esxVI_Boolean_Undefined)
        return priv->supportsScreenshot;

    if (esxVI_EnsureSession(priv->primary) < 0)
        return esxVI_Boolean_Undefined;

    if (esxVI_String_AppendValueToList(&propertyNameList,
                                       "capability.screenshotSupported") < 0 ||
        esxVI_LookupHostSystemProperties(priv->primary, propertyNameList,
                                         &hostSystem) < 0 ||
        esxVI_GetBoolean(hostSystem, "capability.screenshotSupported",
                         &priv->supportsScreenshot,
                         esxVI_Occurrence_RequiredItem) < 0)
        goto cleanup;

 cleanup:
    /*
     * If we goto cleanup in case of an error then priv->supportsScreenshot is
     * still esxVI_Boolean_Undefined, therefore we don't need to set it.
     */
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&hostSystem);

    return priv->supportsScreenshot;
}



static int
esxConnectSupportsFeature(virConnectPtr conn, int feature)
{
    esxPrivate *priv = conn->privateData;
    esxVI_Boolean supportsVMotion = esxVI_Boolean_Undefined;

    switch (feature) {
      case VIR_DRV_FEATURE_MIGRATION_V1:
        supportsVMotion = esxSupportsVMotion(priv);

        if (supportsVMotion == esxVI_Boolean_Undefined)
            return -1;

        /* Migration is only possible via a vCenter and if VMotion is enabled */
        return priv->vCenter &&
               supportsVMotion == esxVI_Boolean_True ? 1 : 0;

      default:
        return 0;
    }
}



static const char *
esxConnectGetType(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    return "ESX";
}



static int
esxConnectGetVersion(virConnectPtr conn, unsigned long *version)
{
    esxPrivate *priv = conn->privateData;

    *version = priv->primary->productVersion;

    return 0;
}



static char *
esxConnectGetHostname(virConnectPtr conn)
{
    esxPrivate *priv = conn->privateData;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *hostSystem = NULL;
    esxVI_DynamicProperty *dynamicProperty = NULL;
    const char *hostName = NULL;
    const char *domainName = NULL;
    char *complete = NULL;

    if (esxVI_EnsureSession(priv->primary) < 0)
        return NULL;

    if (esxVI_String_AppendValueListToList
          (&propertyNameList,
           "config.network.dnsConfig.hostName\0"
           "config.network.dnsConfig.domainName\0") < 0 ||
        esxVI_LookupHostSystemProperties(priv->primary, propertyNameList,
                                         &hostSystem) < 0) {
        goto cleanup;
    }

    for (dynamicProperty = hostSystem->propSet; dynamicProperty;
         dynamicProperty = dynamicProperty->_next) {
        if (STREQ(dynamicProperty->name,
                  "config.network.dnsConfig.hostName")) {
            if (esxVI_AnyType_ExpectType(dynamicProperty->val,
                                         esxVI_Type_String) < 0) {
                goto cleanup;
            }

            hostName = dynamicProperty->val->string;
        } else if (STREQ(dynamicProperty->name,
                         "config.network.dnsConfig.domainName")) {
            if (esxVI_AnyType_ExpectType(dynamicProperty->val,
                                         esxVI_Type_String) < 0) {
                goto cleanup;
            }

            domainName = dynamicProperty->val->string;
        } else {
            VIR_WARN("Unexpected '%s' property", dynamicProperty->name);
        }
    }

    if (!hostName || strlen(hostName) < 1) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing or empty 'hostName' property"));
        goto cleanup;
    }

    if (!domainName || strlen(domainName) < 1) {
        if (VIR_STRDUP(complete, hostName) < 0)
            goto cleanup;
    } else {
        if (virAsprintf(&complete, "%s.%s", hostName, domainName) < 0)
            goto cleanup;
    }

 cleanup:
    /*
     * If we goto cleanup in case of an error then complete is still NULL,
     * either VIR_STRDUP returned -1 or virAsprintf failed. When virAsprintf
     * fails it guarantees setting complete to NULL
     */
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&hostSystem);

    return complete;
}



static int
esxNodeGetInfo(virConnectPtr conn, virNodeInfoPtr nodeinfo)
{
    int result = -1;
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

    memset(nodeinfo, 0, sizeof(*nodeinfo));

    if (esxVI_EnsureSession(priv->primary) < 0)
        return -1;

    if (esxVI_String_AppendValueListToList(&propertyNameList,
                                           "hardware.cpuInfo.hz\0"
                                           "hardware.cpuInfo.numCpuCores\0"
                                           "hardware.cpuInfo.numCpuPackages\0"
                                           "hardware.cpuInfo.numCpuThreads\0"
                                           "hardware.memorySize\0"
                                           "hardware.numaInfo.numNodes\0"
                                           "summary.hardware.cpuModel\0") < 0 ||
        esxVI_LookupHostSystemProperties(priv->primary, propertyNameList,
                                         &hostSystem) < 0) {
        goto cleanup;
    }

    for (dynamicProperty = hostSystem->propSet; dynamicProperty;
         dynamicProperty = dynamicProperty->_next) {
        if (STREQ(dynamicProperty->name, "hardware.cpuInfo.hz")) {
            if (esxVI_AnyType_ExpectType(dynamicProperty->val,
                                         esxVI_Type_Long) < 0) {
                goto cleanup;
            }

            cpuInfo_hz = dynamicProperty->val->int64;
        } else if (STREQ(dynamicProperty->name,
                         "hardware.cpuInfo.numCpuCores")) {
            if (esxVI_AnyType_ExpectType(dynamicProperty->val,
                                         esxVI_Type_Short) < 0) {
                goto cleanup;
            }

            cpuInfo_numCpuCores = dynamicProperty->val->int16;
        } else if (STREQ(dynamicProperty->name,
                         "hardware.cpuInfo.numCpuPackages")) {
            if (esxVI_AnyType_ExpectType(dynamicProperty->val,
                                         esxVI_Type_Short) < 0) {
                goto cleanup;
            }

            cpuInfo_numCpuPackages = dynamicProperty->val->int16;
        } else if (STREQ(dynamicProperty->name,
                         "hardware.cpuInfo.numCpuThreads")) {
            if (esxVI_AnyType_ExpectType(dynamicProperty->val,
                                         esxVI_Type_Short) < 0) {
                goto cleanup;
            }

            cpuInfo_numCpuThreads = dynamicProperty->val->int16;
        } else if (STREQ(dynamicProperty->name, "hardware.memorySize")) {
            if (esxVI_AnyType_ExpectType(dynamicProperty->val,
                                         esxVI_Type_Long) < 0) {
                goto cleanup;
            }

            memorySize = dynamicProperty->val->int64;
        } else if (STREQ(dynamicProperty->name,
                         "hardware.numaInfo.numNodes")) {
            if (esxVI_AnyType_ExpectType(dynamicProperty->val,
                                         esxVI_Type_Int) < 0) {
                goto cleanup;
            }

            numaInfo_numNodes = dynamicProperty->val->int32;
        } else if (STREQ(dynamicProperty->name,
                         "summary.hardware.cpuModel")) {
            if (esxVI_AnyType_ExpectType(dynamicProperty->val,
                                         esxVI_Type_String) < 0) {
                goto cleanup;
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

            if (!virStrncpy(nodeinfo->model, dynamicProperty->val->string,
                            sizeof(nodeinfo->model) - 1,
                            sizeof(nodeinfo->model))) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("CPU Model %s too long for destination"),
                               dynamicProperty->val->string);
                goto cleanup;
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

    result = 0;

 cleanup:
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&hostSystem);

    return result;
}



static char *
esxConnectGetCapabilities(virConnectPtr conn)
{
    esxPrivate *priv = conn->privateData;

    return virCapabilitiesFormatXML(priv->caps);
}



static int
esxConnectListDomains(virConnectPtr conn, int *ids, int maxids)
{
    bool success = false;
    esxPrivate *priv = conn->privateData;
    esxVI_ObjectContent *virtualMachineList = NULL;
    esxVI_ObjectContent *virtualMachine = NULL;
    esxVI_String *propertyNameList = NULL;
    esxVI_VirtualMachinePowerState powerState;
    int count = 0;

    if (maxids == 0)
        return 0;

    if (esxVI_EnsureSession(priv->primary) < 0)
        return -1;

    if (esxVI_String_AppendValueToList(&propertyNameList,
                                       "runtime.powerState") < 0 ||
        esxVI_LookupVirtualMachineList(priv->primary, propertyNameList,
                                       &virtualMachineList) < 0) {
        goto cleanup;
    }

    for (virtualMachine = virtualMachineList; virtualMachine;
         virtualMachine = virtualMachine->_next) {
        if (esxVI_GetVirtualMachinePowerState(virtualMachine,
                                              &powerState) < 0) {
            goto cleanup;
        }

        if (powerState != esxVI_VirtualMachinePowerState_PoweredOn)
            continue;

        if (esxUtil_ParseVirtualMachineIDString(virtualMachine->obj->value,
                                                &ids[count]) < 0 ||
            ids[count] <= 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to parse positive integer from '%s'"),
                           virtualMachine->obj->value);
            goto cleanup;
        }

        count++;

        if (count >= maxids)
            break;
    }

    success = true;

 cleanup:
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&virtualMachineList);

    return success ? count : -1;
}



static int
esxConnectNumOfDomains(virConnectPtr conn)
{
    esxPrivate *priv = conn->privateData;

    if (esxVI_EnsureSession(priv->primary) < 0)
        return -1;

    return esxVI_LookupNumberOfDomainsByPowerState
             (priv->primary, esxVI_VirtualMachinePowerState_PoweredOn, false);
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

    if (esxVI_EnsureSession(priv->primary) < 0)
        return NULL;

    if (esxVI_String_AppendValueListToList(&propertyNameList,
                                           "configStatus\0"
                                           "name\0"
                                           "runtime.powerState\0"
                                           "config.uuid\0") < 0 ||
        esxVI_LookupVirtualMachineList(priv->primary, propertyNameList,
                                       &virtualMachineList) < 0) {
        goto cleanup;
    }

    for (virtualMachine = virtualMachineList; virtualMachine;
         virtualMachine = virtualMachine->_next) {
        if (esxVI_GetVirtualMachinePowerState(virtualMachine,
                                              &powerState) < 0) {
            goto cleanup;
        }

        /* Only running/suspended domains have an ID != -1 */
        if (powerState == esxVI_VirtualMachinePowerState_PoweredOff)
            continue;

        VIR_FREE(name_candidate);

        if (esxVI_GetVirtualMachineIdentity(virtualMachine,
                                            &id_candidate, &name_candidate,
                                            uuid_candidate) < 0) {
            goto cleanup;
        }

        if (id != id_candidate)
            continue;

        domain = virGetDomain(conn, name_candidate, uuid_candidate, id);

        if (!domain)
            goto cleanup;

        break;
    }

    if (!domain)
        virReportError(VIR_ERR_NO_DOMAIN, _("No domain with ID %d"), id);

 cleanup:
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&virtualMachineList);
    VIR_FREE(name_candidate);

    return domain;
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

    if (esxVI_EnsureSession(priv->primary) < 0)
        return NULL;

    if (esxVI_String_AppendValueListToList(&propertyNameList,
                                           "name\0"
                                           "runtime.powerState\0") < 0 ||
        esxVI_LookupVirtualMachineByUuid(priv->primary, uuid, propertyNameList,
                                         &virtualMachine,
                                         esxVI_Occurrence_RequiredItem) < 0 ||
        esxVI_GetVirtualMachineIdentity(virtualMachine, &id, &name, NULL) < 0 ||
        esxVI_GetVirtualMachinePowerState(virtualMachine, &powerState) < 0) {
        goto cleanup;
    }

    /* Only running/suspended virtual machines have an ID != -1 */
    if (powerState == esxVI_VirtualMachinePowerState_PoweredOff)
        id = -1;

    domain = virGetDomain(conn, name, uuid, id);

 cleanup:
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&virtualMachine);
    VIR_FREE(name);

    return domain;
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

    if (esxVI_EnsureSession(priv->primary) < 0)
        return NULL;

    if (esxVI_String_AppendValueListToList(&propertyNameList,
                                           "configStatus\0"
                                           "runtime.powerState\0"
                                           "config.uuid\0") < 0 ||
        esxVI_LookupVirtualMachineByName(priv->primary, name, propertyNameList,
                                         &virtualMachine,
                                         esxVI_Occurrence_OptionalItem) < 0) {
        goto cleanup;
    }

    if (!virtualMachine) {
        virReportError(VIR_ERR_NO_DOMAIN, _("No domain with name '%s'"), name);
        goto cleanup;
    }

    if (esxVI_GetVirtualMachineIdentity(virtualMachine, &id, NULL, uuid) < 0 ||
        esxVI_GetVirtualMachinePowerState(virtualMachine, &powerState) < 0) {
        goto cleanup;
    }

    /* Only running/suspended virtual machines have an ID != -1 */
    if (powerState == esxVI_VirtualMachinePowerState_PoweredOff)
        id = -1;

    domain = virGetDomain(conn, name, uuid, id);

 cleanup:
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&virtualMachine);

    return domain;
}



static int
esxDomainSuspend(virDomainPtr domain)
{
    int result = -1;
    esxPrivate *priv = domain->conn->privateData;
    esxVI_ObjectContent *virtualMachine = NULL;
    esxVI_String *propertyNameList = NULL;
    esxVI_VirtualMachinePowerState powerState;
    esxVI_ManagedObjectReference *task = NULL;
    esxVI_TaskInfoState taskInfoState;
    char *taskInfoErrorMessage = NULL;

    if (esxVI_EnsureSession(priv->primary) < 0)
        return -1;

    if (esxVI_String_AppendValueToList(&propertyNameList,
                                       "runtime.powerState") < 0 ||
        esxVI_LookupVirtualMachineByUuidAndPrepareForTask
          (priv->primary, domain->uuid, propertyNameList, &virtualMachine,
           priv->parsedUri->autoAnswer) < 0 ||
        esxVI_GetVirtualMachinePowerState(virtualMachine, &powerState) < 0) {
        goto cleanup;
    }

    if (powerState != esxVI_VirtualMachinePowerState_PoweredOn) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Domain is not powered on"));
        goto cleanup;
    }

    if (esxVI_SuspendVM_Task(priv->primary, virtualMachine->obj, &task) < 0 ||
        esxVI_WaitForTaskCompletion(priv->primary, task, domain->uuid,
                                    esxVI_Occurrence_RequiredItem,
                                    priv->parsedUri->autoAnswer, &taskInfoState,
                                    &taskInfoErrorMessage) < 0) {
        goto cleanup;
    }

    if (taskInfoState != esxVI_TaskInfoState_Success) {
        virReportError(VIR_ERR_INTERNAL_ERROR, _("Could not suspend domain: %s"),
                       taskInfoErrorMessage);
        goto cleanup;
    }

    result = 0;

 cleanup:
    esxVI_ObjectContent_Free(&virtualMachine);
    esxVI_String_Free(&propertyNameList);
    esxVI_ManagedObjectReference_Free(&task);
    VIR_FREE(taskInfoErrorMessage);

    return result;
}



static int
esxDomainResume(virDomainPtr domain)
{
    int result = -1;
    esxPrivate *priv = domain->conn->privateData;
    esxVI_ObjectContent *virtualMachine = NULL;
    esxVI_String *propertyNameList = NULL;
    esxVI_VirtualMachinePowerState powerState;
    esxVI_ManagedObjectReference *task = NULL;
    esxVI_TaskInfoState taskInfoState;
    char *taskInfoErrorMessage = NULL;

    if (esxVI_EnsureSession(priv->primary) < 0)
        return -1;

    if (esxVI_String_AppendValueToList(&propertyNameList,
                                       "runtime.powerState") < 0 ||
        esxVI_LookupVirtualMachineByUuidAndPrepareForTask
          (priv->primary, domain->uuid, propertyNameList, &virtualMachine,
           priv->parsedUri->autoAnswer) < 0 ||
        esxVI_GetVirtualMachinePowerState(virtualMachine, &powerState) < 0) {
        goto cleanup;
    }

    if (powerState != esxVI_VirtualMachinePowerState_Suspended) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s", _("Domain is not suspended"));
        goto cleanup;
    }

    if (esxVI_PowerOnVM_Task(priv->primary, virtualMachine->obj, NULL,
                             &task) < 0 ||
        esxVI_WaitForTaskCompletion(priv->primary, task, domain->uuid,
                                    esxVI_Occurrence_RequiredItem,
                                    priv->parsedUri->autoAnswer, &taskInfoState,
                                    &taskInfoErrorMessage) < 0) {
        goto cleanup;
    }

    if (taskInfoState != esxVI_TaskInfoState_Success) {
        virReportError(VIR_ERR_INTERNAL_ERROR, _("Could not resume domain: %s"),
                       taskInfoErrorMessage);
        goto cleanup;
    }

    result = 0;

 cleanup:
    esxVI_ObjectContent_Free(&virtualMachine);
    esxVI_String_Free(&propertyNameList);
    esxVI_ManagedObjectReference_Free(&task);
    VIR_FREE(taskInfoErrorMessage);

    return result;
}



static int
esxDomainShutdownFlags(virDomainPtr domain, unsigned int flags)
{
    int result = -1;
    esxPrivate *priv = domain->conn->privateData;
    esxVI_ObjectContent *virtualMachine = NULL;
    esxVI_String *propertyNameList = NULL;
    esxVI_VirtualMachinePowerState powerState;

    virCheckFlags(0, -1);

    if (esxVI_EnsureSession(priv->primary) < 0)
        return -1;

    if (esxVI_String_AppendValueToList(&propertyNameList,
                                       "runtime.powerState") < 0 ||
        esxVI_LookupVirtualMachineByUuid(priv->primary, domain->uuid,
                                         propertyNameList, &virtualMachine,
                                         esxVI_Occurrence_RequiredItem) < 0 ||
        esxVI_GetVirtualMachinePowerState(virtualMachine, &powerState) < 0) {
        goto cleanup;
    }

    if (powerState != esxVI_VirtualMachinePowerState_PoweredOn) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Domain is not powered on"));
        goto cleanup;
    }

    if (esxVI_ShutdownGuest(priv->primary, virtualMachine->obj) < 0)
        goto cleanup;

    result = 0;

 cleanup:
    esxVI_ObjectContent_Free(&virtualMachine);
    esxVI_String_Free(&propertyNameList);

    return result;
}


static int
esxDomainShutdown(virDomainPtr domain)
{
    return esxDomainShutdownFlags(domain, 0);
}


static int
esxDomainReboot(virDomainPtr domain, unsigned int flags)
{
    int result = -1;
    esxPrivate *priv = domain->conn->privateData;
    esxVI_ObjectContent *virtualMachine = NULL;
    esxVI_String *propertyNameList = NULL;
    esxVI_VirtualMachinePowerState powerState;

    virCheckFlags(0, -1);

    if (esxVI_EnsureSession(priv->primary) < 0)
        return -1;

    if (esxVI_String_AppendValueToList(&propertyNameList,
                                       "runtime.powerState") < 0 ||
        esxVI_LookupVirtualMachineByUuid(priv->primary, domain->uuid,
                                         propertyNameList, &virtualMachine,
                                         esxVI_Occurrence_RequiredItem) < 0 ||
        esxVI_GetVirtualMachinePowerState(virtualMachine, &powerState) < 0) {
        goto cleanup;
    }

    if (powerState != esxVI_VirtualMachinePowerState_PoweredOn) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Domain is not powered on"));
        goto cleanup;
    }

    if (esxVI_RebootGuest(priv->primary, virtualMachine->obj) < 0)
        goto cleanup;

    result = 0;

 cleanup:
    esxVI_ObjectContent_Free(&virtualMachine);
    esxVI_String_Free(&propertyNameList);

    return result;
}



static int
esxDomainDestroyFlags(virDomainPtr domain,
                      unsigned int flags)
{
    int result = -1;
    esxPrivate *priv = domain->conn->privateData;
    esxVI_Context *ctx = NULL;
    esxVI_ObjectContent *virtualMachine = NULL;
    esxVI_String *propertyNameList = NULL;
    esxVI_VirtualMachinePowerState powerState;
    esxVI_ManagedObjectReference *task = NULL;
    esxVI_TaskInfoState taskInfoState;
    char *taskInfoErrorMessage = NULL;

    virCheckFlags(0, -1);

    if (priv->vCenter) {
        ctx = priv->vCenter;
    } else {
        ctx = priv->host;
    }

    if (esxVI_EnsureSession(ctx) < 0)
        return -1;

    if (esxVI_String_AppendValueToList(&propertyNameList,
                                       "runtime.powerState") < 0 ||
        esxVI_LookupVirtualMachineByUuidAndPrepareForTask
          (ctx, domain->uuid, propertyNameList, &virtualMachine,
           priv->parsedUri->autoAnswer) < 0 ||
        esxVI_GetVirtualMachinePowerState(virtualMachine, &powerState) < 0) {
        goto cleanup;
    }

    if (powerState != esxVI_VirtualMachinePowerState_PoweredOn) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Domain is not powered on"));
        goto cleanup;
    }

    if (esxVI_PowerOffVM_Task(ctx, virtualMachine->obj, &task) < 0 ||
        esxVI_WaitForTaskCompletion(ctx, task, domain->uuid,
                                    esxVI_Occurrence_RequiredItem,
                                    priv->parsedUri->autoAnswer, &taskInfoState,
                                    &taskInfoErrorMessage) < 0) {
        goto cleanup;
    }

    if (taskInfoState != esxVI_TaskInfoState_Success) {
        virReportError(VIR_ERR_INTERNAL_ERROR, _("Could not destroy domain: %s"),
                       taskInfoErrorMessage);
        goto cleanup;
    }

    domain->id = -1;
    result = 0;

 cleanup:
    esxVI_ObjectContent_Free(&virtualMachine);
    esxVI_String_Free(&propertyNameList);
    esxVI_ManagedObjectReference_Free(&task);
    VIR_FREE(taskInfoErrorMessage);

    return result;
}


static int
esxDomainDestroy(virDomainPtr dom)
{
    return esxDomainDestroyFlags(dom, 0);
}


static char *
esxDomainGetOSType(virDomainPtr domain ATTRIBUTE_UNUSED)
{
    char *osType;

    ignore_value(VIR_STRDUP(osType, "hvm"));
    return osType;
}



static unsigned long long
esxDomainGetMaxMemory(virDomainPtr domain)
{
    esxPrivate *priv = domain->conn->privateData;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *virtualMachine = NULL;
    esxVI_DynamicProperty *dynamicProperty = NULL;
    unsigned long memoryMB = 0;

    if (esxVI_EnsureSession(priv->primary) < 0)
        return 0;

    if (esxVI_String_AppendValueToList(&propertyNameList,
                                       "config.hardware.memoryMB") < 0 ||
        esxVI_LookupVirtualMachineByUuid(priv->primary, domain->uuid,
                                         propertyNameList, &virtualMachine,
                                         esxVI_Occurrence_RequiredItem) < 0) {
        goto cleanup;
    }

    for (dynamicProperty = virtualMachine->propSet; dynamicProperty;
         dynamicProperty = dynamicProperty->_next) {
        if (STREQ(dynamicProperty->name, "config.hardware.memoryMB")) {
            if (esxVI_AnyType_ExpectType(dynamicProperty->val,
                                         esxVI_Type_Int) < 0) {
                goto cleanup;
            }

            if (dynamicProperty->val->int32 < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
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
}



static int
esxDomainSetMaxMemory(virDomainPtr domain, unsigned long memory)
{
    int result = -1;
    esxPrivate *priv = domain->conn->privateData;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *virtualMachine = NULL;
    esxVI_VirtualMachinePowerState powerState;
    esxVI_VirtualMachineConfigSpec *spec = NULL;
    esxVI_ManagedObjectReference *task = NULL;
    esxVI_TaskInfoState taskInfoState;
    char *taskInfoErrorMessage = NULL;

    if (esxVI_EnsureSession(priv->primary) < 0)
        return -1;

    if (esxVI_String_AppendValueToList(&propertyNameList,
                                       "runtime.powerState") < 0 ||
        esxVI_LookupVirtualMachineByUuidAndPrepareForTask
          (priv->primary, domain->uuid, propertyNameList, &virtualMachine,
           priv->parsedUri->autoAnswer) < 0 ||
        esxVI_GetVirtualMachinePowerState(virtualMachine, &powerState) < 0) {
        goto cleanup;
    }

    if (powerState != esxVI_VirtualMachinePowerState_PoweredOff) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Domain is not powered off"));
        goto cleanup;
    }

    if (esxVI_VirtualMachineConfigSpec_Alloc(&spec) < 0 ||
        esxVI_Long_Alloc(&spec->memoryMB) < 0) {
        goto cleanup;
    }

    /* max-memory must be a multiple of 4096 kilobyte */
    spec->memoryMB->value =
      VIR_DIV_UP(memory, 4096) * 4; /* Scale from kilobytes to megabytes */

    if (esxVI_ReconfigVM_Task(priv->primary, virtualMachine->obj, spec,
                              &task) < 0 ||
        esxVI_WaitForTaskCompletion(priv->primary, task, domain->uuid,
                                    esxVI_Occurrence_RequiredItem,
                                    priv->parsedUri->autoAnswer, &taskInfoState,
                                    &taskInfoErrorMessage) < 0) {
        goto cleanup;
    }

    if (taskInfoState != esxVI_TaskInfoState_Success) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not set max-memory to %lu kilobytes: %s"), memory,
                       taskInfoErrorMessage);
        goto cleanup;
    }

    result = 0;

 cleanup:
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&virtualMachine);
    esxVI_VirtualMachineConfigSpec_Free(&spec);
    esxVI_ManagedObjectReference_Free(&task);
    VIR_FREE(taskInfoErrorMessage);

    return result;
}



static int
esxDomainSetMemory(virDomainPtr domain, unsigned long memory)
{
    int result = -1;
    esxPrivate *priv = domain->conn->privateData;
    esxVI_ObjectContent *virtualMachine = NULL;
    esxVI_VirtualMachineConfigSpec *spec = NULL;
    esxVI_ManagedObjectReference *task = NULL;
    esxVI_TaskInfoState taskInfoState;
    char *taskInfoErrorMessage = NULL;

    if (esxVI_EnsureSession(priv->primary) < 0)
        return -1;

    if (esxVI_LookupVirtualMachineByUuidAndPrepareForTask
          (priv->primary, domain->uuid, NULL, &virtualMachine,
           priv->parsedUri->autoAnswer) < 0 ||
        esxVI_VirtualMachineConfigSpec_Alloc(&spec) < 0 ||
        esxVI_ResourceAllocationInfo_Alloc(&spec->memoryAllocation) < 0 ||
        esxVI_Long_Alloc(&spec->memoryAllocation->limit) < 0) {
        goto cleanup;
    }

    spec->memoryAllocation->limit->value =
      VIR_DIV_UP(memory, 1024); /* Scale from kilobytes to megabytes */

    if (esxVI_ReconfigVM_Task(priv->primary, virtualMachine->obj, spec,
                              &task) < 0 ||
        esxVI_WaitForTaskCompletion(priv->primary, task, domain->uuid,
                                    esxVI_Occurrence_RequiredItem,
                                    priv->parsedUri->autoAnswer, &taskInfoState,
                                    &taskInfoErrorMessage) < 0) {
        goto cleanup;
    }

    if (taskInfoState != esxVI_TaskInfoState_Success) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not set memory to %lu kilobytes: %s"), memory,
                       taskInfoErrorMessage);
        goto cleanup;
    }

    result = 0;

 cleanup:
    esxVI_ObjectContent_Free(&virtualMachine);
    esxVI_VirtualMachineConfigSpec_Free(&spec);
    esxVI_ManagedObjectReference_Free(&task);
    VIR_FREE(taskInfoErrorMessage);

    return result;
}



/*
 * libvirt exposed virtual CPU usage in absolute time, ESX doesn't provide this
 * information in this format. It exposes it in 20 seconds slots, but it's hard
 * to get a reliable absolute time from this. Therefore, disable the code that
 * queries the performance counters here for now, but keep it as example for how
 * to query a selected performance counter for its values.
 */
#define ESX_QUERY_FOR_USED_CPU_TIME 0

static int
esxDomainGetInfo(virDomainPtr domain, virDomainInfoPtr info)
{
    int result = -1;
    esxPrivate *priv = domain->conn->privateData;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *virtualMachine = NULL;
    esxVI_DynamicProperty *dynamicProperty = NULL;
    esxVI_VirtualMachinePowerState powerState;
    int64_t memory_limit = -1;
#if ESX_QUERY_FOR_USED_CPU_TIME
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
#endif

    memset(info, 0, sizeof(*info));

    if (esxVI_EnsureSession(priv->primary) < 0)
        return -1;

    if (esxVI_String_AppendValueListToList(&propertyNameList,
                                           "runtime.powerState\0"
                                           "config.hardware.memoryMB\0"
                                           "config.hardware.numCPU\0"
                                           "config.memoryAllocation.limit\0") < 0 ||
        esxVI_LookupVirtualMachineByUuid(priv->primary, domain->uuid,
                                         propertyNameList, &virtualMachine,
                                         esxVI_Occurrence_RequiredItem) < 0) {
        goto cleanup;
    }

    info->state = VIR_DOMAIN_NOSTATE;

    for (dynamicProperty = virtualMachine->propSet; dynamicProperty;
         dynamicProperty = dynamicProperty->_next) {
        if (STREQ(dynamicProperty->name, "runtime.powerState")) {
            if (esxVI_VirtualMachinePowerState_CastFromAnyType
                  (dynamicProperty->val, &powerState) < 0) {
                goto cleanup;
            }

            info->state = esxVI_VirtualMachinePowerState_ConvertToLibvirt
                            (powerState);
        } else if (STREQ(dynamicProperty->name, "config.hardware.memoryMB")) {
            if (esxVI_AnyType_ExpectType(dynamicProperty->val,
                                         esxVI_Type_Int) < 0) {
                goto cleanup;
            }

            info->maxMem = dynamicProperty->val->int32 * 1024; /* Scale from megabyte to kilobyte */
        } else if (STREQ(dynamicProperty->name, "config.hardware.numCPU")) {
            if (esxVI_AnyType_ExpectType(dynamicProperty->val,
                                         esxVI_Type_Int) < 0) {
                goto cleanup;
            }

            info->nrVirtCpu = dynamicProperty->val->int32;
        } else if (STREQ(dynamicProperty->name,
                         "config.memoryAllocation.limit")) {
            if (esxVI_AnyType_ExpectType(dynamicProperty->val,
                                         esxVI_Type_Long) < 0) {
                goto cleanup;
            }

            memory_limit = dynamicProperty->val->int64;

            if (memory_limit > 0)
                memory_limit *= 1024; /* Scale from megabyte to kilobyte */
        } else {
            VIR_WARN("Unexpected '%s' property", dynamicProperty->name);
        }
    }

    /* memory_limit < 0 means no memory limit is set */
    info->memory = memory_limit < 0 ? info->maxMem : memory_limit;

#if ESX_QUERY_FOR_USED_CPU_TIME
    /* Verify the cached 'used CPU time' performance counter ID */
    /* FIXME: Currently no host for a vpx:// connection */
    if (priv->host) {
        if (info->state == VIR_DOMAIN_RUNNING && priv->usedCpuTimeCounterId >= 0) {
            if (esxVI_Int_Alloc(&counterId) < 0)
                goto cleanup;

            counterId->value = priv->usedCpuTimeCounterId;

            if (esxVI_Int_AppendToList(&counterIdList, counterId) < 0)
                goto cleanup;

            if (esxVI_QueryPerfCounter(priv->host, counterIdList,
                                       &perfCounterInfo) < 0) {
                goto cleanup;
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
                goto cleanup;
            }

            for (perfMetricId = perfMetricIdList; perfMetricId;
                 perfMetricId = perfMetricId->_next) {
                VIR_DEBUG("perfMetricId counterId %d, instance '%s'",
                          perfMetricId->counterId->value, perfMetricId->instance);

                counterId = NULL;

                if (esxVI_Int_DeepCopy(&counterId, perfMetricId->counterId) < 0 ||
                    esxVI_Int_AppendToList(&counterIdList, counterId) < 0) {
                    goto cleanup;
                }
            }

            if (esxVI_QueryPerfCounter(priv->host, counterIdList,
                                       &perfCounterInfoList) < 0) {
                goto cleanup;
            }

            for (perfCounterInfo = perfCounterInfoList; perfCounterInfo;
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

            if (priv->usedCpuTimeCounterId < 0)
                VIR_WARN("Could not find 'used CPU time' performance counter");
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
                goto cleanup;
            }

            querySpec->entity = virtualMachine->obj;
            querySpec->maxSample->value = 1;
            querySpec->metricId->counterId->value = priv->usedCpuTimeCounterId;
            querySpec->metricId->instance = (char *)"";
            querySpec->format = (char *)"normal";

            if (esxVI_QueryPerf(priv->host, querySpec,
                                &perfEntityMetricBaseList) < 0) {
                goto cleanup;
            }

            for (perfEntityMetricBase = perfEntityMetricBaseList;
                 perfEntityMetricBase;
                 perfEntityMetricBase = perfEntityMetricBase->_next) {
                VIR_DEBUG("perfEntityMetric ...");

                perfEntityMetric =
                  esxVI_PerfEntityMetric_DynamicCast(perfEntityMetricBase);

                if (!perfEntityMetric) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("QueryPerf returned object with unexpected type '%s'"),
                                   esxVI_Type_ToString(perfEntityMetricBase->_type));
                    goto cleanup;
                }

                perfMetricIntSeries =
                  esxVI_PerfMetricIntSeries_DynamicCast(perfEntityMetric->value);

                if (!perfMetricIntSeries) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("QueryPerf returned object with unexpected type '%s'"),
                                   esxVI_Type_ToString(perfEntityMetric->value->_type));
                    goto cleanup;
                }

                for (; perfMetricIntSeries;
                     perfMetricIntSeries = perfMetricIntSeries->_next) {
                    VIR_DEBUG("perfMetricIntSeries ...");

                    for (value = perfMetricIntSeries->value;
                         value;
                         value = value->_next) {
                        VIR_DEBUG("value %lld", (long long int)value->value);
                    }
                }
            }

            VIR_DEBUG("usedCpuTimeCounterId %d END", priv->usedCpuTimeCounterId);

            /*
             * FIXME: Cannot map between relative used-cpu-time and absolute
             *        info->cpuTime
             */
        }
    }
#endif

    result = 0;

 cleanup:
#if ESX_QUERY_FOR_USED_CPU_TIME
    /*
     * Remove values owned by data structures to prevent them from being freed
     * by the call to esxVI_PerfQuerySpec_Free().
     */
    if (querySpec) {
        querySpec->entity = NULL;
        querySpec->format = NULL;

        if (querySpec->metricId)
            querySpec->metricId->instance = NULL;
    }
#endif

    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&virtualMachine);
#if ESX_QUERY_FOR_USED_CPU_TIME
    esxVI_PerfMetricId_Free(&perfMetricIdList);
    esxVI_Int_Free(&counterIdList);
    esxVI_PerfCounterInfo_Free(&perfCounterInfoList);
    esxVI_PerfQuerySpec_Free(&querySpec);
    esxVI_PerfEntityMetricBase_Free(&perfEntityMetricBaseList);
#endif

    return result;
}



static int
esxDomainGetState(virDomainPtr domain,
                  int *state,
                  int *reason,
                  unsigned int flags)
{
    int result = -1;
    esxPrivate *priv = domain->conn->privateData;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *virtualMachine = NULL;
    esxVI_VirtualMachinePowerState powerState;

    virCheckFlags(0, -1);

    if (esxVI_EnsureSession(priv->primary) < 0)
        return -1;

    if (esxVI_String_AppendValueToList(&propertyNameList,
                                       "runtime.powerState") < 0 ||
        esxVI_LookupVirtualMachineByUuid(priv->primary, domain->uuid,
                                         propertyNameList, &virtualMachine,
                                         esxVI_Occurrence_RequiredItem) < 0 ||
        esxVI_GetVirtualMachinePowerState(virtualMachine, &powerState) < 0) {
        goto cleanup;
    }

    *state = esxVI_VirtualMachinePowerState_ConvertToLibvirt(powerState);

    if (reason)
        *reason = 0;

    result = 0;

 cleanup:
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&virtualMachine);

    return result;
}



static char *
esxDomainScreenshot(virDomainPtr domain, virStreamPtr stream,
                    unsigned int screen, unsigned int flags)
{
    char *mimeType = NULL;
    esxPrivate *priv = domain->conn->privateData;
    esxVI_Boolean supportsScreenshot = esxVI_Boolean_Undefined;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *virtualMachine = NULL;
    esxVI_VirtualMachinePowerState powerState;
    virBuffer buffer = VIR_BUFFER_INITIALIZER;
    char *url = NULL;

    virCheckFlags(0, NULL);

    if (screen != 0) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Screen cannot be selected"));
        return NULL;
    }

    supportsScreenshot = esxSupportsScreenshot(priv);

    if (supportsScreenshot == esxVI_Boolean_Undefined)
        return NULL;

    if (supportsScreenshot != esxVI_Boolean_True) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("Screenshot feature is unsupported"));
        return NULL;
    }

    if (esxVI_EnsureSession(priv->primary) < 0)
        return NULL;

    if (esxVI_String_AppendValueToList(&propertyNameList,
                                       "runtime.powerState") < 0 ||
        esxVI_LookupVirtualMachineByUuid(priv->primary, domain->uuid,
                                         propertyNameList, &virtualMachine,
                                         esxVI_Occurrence_RequiredItem) < 0 ||
        esxVI_GetVirtualMachinePowerState(virtualMachine, &powerState) < 0)
        goto cleanup;

    if (powerState != esxVI_VirtualMachinePowerState_PoweredOn) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Domain is not powered on"));
        goto cleanup;
    }

    /* Build URL */
    virBufferAsprintf(&buffer, "%s://%s:%d/screen?id=", priv->parsedUri->transport,
                      domain->conn->uri->server, domain->conn->uri->port);
    virBufferURIEncodeString(&buffer, virtualMachine->obj->value);

    if (virBufferCheckError(&buffer))
        goto cleanup;

    url = virBufferContentAndReset(&buffer);

    if (VIR_STRDUP(mimeType, "image/png") < 0)
        goto cleanup;

    if (esxStreamOpenDownload(stream, priv, url, 0, 0) < 0) {
        VIR_FREE(mimeType);
        goto cleanup;
    }

 cleanup:
    virBufferFreeAndReset(&buffer);

    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&virtualMachine);

    return mimeType;
}



static int
esxDomainSetVcpusFlags(virDomainPtr domain, unsigned int nvcpus,
                       unsigned int flags)
{
    int result = -1;
    esxPrivate *priv = domain->conn->privateData;
    int maxVcpus;
    esxVI_ObjectContent *virtualMachine = NULL;
    esxVI_VirtualMachineConfigSpec *spec = NULL;
    esxVI_ManagedObjectReference *task = NULL;
    esxVI_TaskInfoState taskInfoState;
    char *taskInfoErrorMessage = NULL;

    if (flags != VIR_DOMAIN_AFFECT_LIVE) {
        virReportError(VIR_ERR_INVALID_ARG, _("unsupported flags: (0x%x)"), flags);
        return -1;
    }

    if (nvcpus < 1) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Requested number of virtual CPUs must at least be 1"));
        return -1;
    }

    if (esxVI_EnsureSession(priv->primary) < 0)
        return -1;

    maxVcpus = esxDomainGetMaxVcpus(domain);

    if (maxVcpus < 0)
        return -1;

    if (nvcpus > maxVcpus) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Requested number of virtual CPUs is greater than max "
                         "allowable number of virtual CPUs for the domain: %d > %d"),
                       nvcpus, maxVcpus);
        return -1;
    }

    if (esxVI_LookupVirtualMachineByUuidAndPrepareForTask
          (priv->primary, domain->uuid, NULL, &virtualMachine,
           priv->parsedUri->autoAnswer) < 0 ||
        esxVI_VirtualMachineConfigSpec_Alloc(&spec) < 0 ||
        esxVI_Int_Alloc(&spec->numCPUs) < 0) {
        goto cleanup;
    }

    spec->numCPUs->value = nvcpus;

    if (esxVI_ReconfigVM_Task(priv->primary, virtualMachine->obj, spec,
                              &task) < 0 ||
        esxVI_WaitForTaskCompletion(priv->primary, task, domain->uuid,
                                    esxVI_Occurrence_RequiredItem,
                                    priv->parsedUri->autoAnswer, &taskInfoState,
                                    &taskInfoErrorMessage) < 0) {
        goto cleanup;
    }

    if (taskInfoState != esxVI_TaskInfoState_Success) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not set number of virtual CPUs to %d: %s"), nvcpus,
                       taskInfoErrorMessage);
        goto cleanup;
    }

    result = 0;

 cleanup:
    esxVI_ObjectContent_Free(&virtualMachine);
    esxVI_VirtualMachineConfigSpec_Free(&spec);
    esxVI_ManagedObjectReference_Free(&task);
    VIR_FREE(taskInfoErrorMessage);

    return result;
}



static int
esxDomainSetVcpus(virDomainPtr domain, unsigned int nvcpus)
{
    return esxDomainSetVcpusFlags(domain, nvcpus, VIR_DOMAIN_AFFECT_LIVE);
}



static int
esxDomainGetVcpusFlags(virDomainPtr domain, unsigned int flags)
{
    esxPrivate *priv = domain->conn->privateData;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *hostSystem = NULL;
    esxVI_DynamicProperty *dynamicProperty = NULL;

    if (flags != (VIR_DOMAIN_AFFECT_LIVE | VIR_DOMAIN_VCPU_MAXIMUM)) {
        virReportError(VIR_ERR_INVALID_ARG, _("unsupported flags: (0x%x)"), flags);
        return -1;
    }

    if (priv->maxVcpus > 0)
        return priv->maxVcpus;

    priv->maxVcpus = -1;

    if (esxVI_EnsureSession(priv->primary) < 0)
        return -1;

    if (esxVI_String_AppendValueToList(&propertyNameList,
                                       "capability.maxSupportedVcpus") < 0 ||
        esxVI_LookupHostSystemProperties(priv->primary, propertyNameList,
                                         &hostSystem) < 0) {
        goto cleanup;
    }

    for (dynamicProperty = hostSystem->propSet; dynamicProperty;
         dynamicProperty = dynamicProperty->_next) {
        if (STREQ(dynamicProperty->name, "capability.maxSupportedVcpus")) {
            if (esxVI_AnyType_ExpectType(dynamicProperty->val,
                                         esxVI_Type_Int) < 0) {
                goto cleanup;
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
}



static int
esxDomainGetMaxVcpus(virDomainPtr domain)
{
    return esxDomainGetVcpusFlags(domain, (VIR_DOMAIN_AFFECT_LIVE |
                                           VIR_DOMAIN_VCPU_MAXIMUM));
}



static char *
esxDomainGetXMLDesc(virDomainPtr domain, unsigned int flags)
{
    esxPrivate *priv = domain->conn->privateData;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *virtualMachine = NULL;
    esxVI_VirtualMachinePowerState powerState;
    int id;
    char *vmPathName = NULL;
    char *datastoreName = NULL;
    char *directoryName = NULL;
    char *directoryAndFileName = NULL;
    virBuffer buffer = VIR_BUFFER_INITIALIZER;
    char *url = NULL;
    char *vmx = NULL;
    virVMXContext ctx;
    esxVMX_Data data;
    virDomainDefPtr def = NULL;
    char *xml = NULL;

    /* Flags checked by virDomainDefFormat */

    memset(&data, 0, sizeof(data));

    if (esxVI_EnsureSession(priv->primary) < 0)
        return NULL;

    if (esxVI_String_AppendValueListToList(&propertyNameList,
                                           "config.files.vmPathName\0"
                                           "runtime.powerState\0") < 0 ||
        esxVI_LookupVirtualMachineByUuid(priv->primary, domain->uuid,
                                         propertyNameList, &virtualMachine,
                                         esxVI_Occurrence_RequiredItem) < 0 ||
        esxVI_GetVirtualMachinePowerState(virtualMachine, &powerState) < 0 ||
        esxVI_GetVirtualMachineIdentity(virtualMachine, &id, NULL, NULL) < 0 ||
        esxVI_GetStringValue(virtualMachine, "config.files.vmPathName",
                             &vmPathName, esxVI_Occurrence_RequiredItem) < 0) {
        goto cleanup;
    }

    if (esxUtil_ParseDatastorePath(vmPathName, &datastoreName, &directoryName,
                                   &directoryAndFileName) < 0) {
        goto cleanup;
    }

    virBufferAsprintf(&buffer, "%s://%s:%d/folder/", priv->parsedUri->transport,
                      domain->conn->uri->server, domain->conn->uri->port);
    virBufferURIEncodeString(&buffer, directoryAndFileName);
    virBufferAddLit(&buffer, "?dcPath=");
    virBufferURIEncodeString(&buffer, priv->primary->datacenterPath);
    virBufferAddLit(&buffer, "&dsName=");
    virBufferURIEncodeString(&buffer, datastoreName);

    if (virBufferCheckError(&buffer) < 0)
        goto cleanup;

    url = virBufferContentAndReset(&buffer);

    if (esxVI_CURL_Download(priv->primary->curl, url, &vmx, 0, NULL) < 0)
        goto cleanup;

    data.ctx = priv->primary;

    if (!directoryName) {
        if (virAsprintf(&data.datastorePathWithoutFileName, "[%s]",
                        datastoreName) < 0)
            goto cleanup;
    } else {
        if (virAsprintf(&data.datastorePathWithoutFileName, "[%s] %s",
                        datastoreName, directoryName) < 0)
            goto cleanup;
    }

    ctx.opaque = &data;
    ctx.parseFileName = esxParseVMXFileName;
    ctx.formatFileName = NULL;
    ctx.autodetectSCSIControllerModel = NULL;
    ctx.datacenterPath = priv->primary->datacenterPath;

    def = virVMXParseConfig(&ctx, priv->xmlopt, priv->caps, vmx);

    if (def) {
        if (powerState != esxVI_VirtualMachinePowerState_PoweredOff)
            def->id = id;

        xml = virDomainDefFormat(def, priv->caps,
                                 virDomainDefFormatConvertXMLFlags(flags));
    }

 cleanup:
    if (!url)
        virBufferFreeAndReset(&buffer);

    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&virtualMachine);
    VIR_FREE(datastoreName);
    VIR_FREE(directoryName);
    VIR_FREE(directoryAndFileName);
    VIR_FREE(url);
    VIR_FREE(data.datastorePathWithoutFileName);
    VIR_FREE(vmx);
    virDomainDefFree(def);

    return xml;
}



static char *
esxConnectDomainXMLFromNative(virConnectPtr conn, const char *nativeFormat,
                              const char *nativeConfig,
                              unsigned int flags)
{
    esxPrivate *priv = conn->privateData;
    virVMXContext ctx;
    esxVMX_Data data;
    virDomainDefPtr def = NULL;
    char *xml = NULL;

    virCheckFlags(0, NULL);

    memset(&data, 0, sizeof(data));

    if (STRNEQ(nativeFormat, "vmware-vmx")) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Unsupported config format '%s'"), nativeFormat);
        return NULL;
    }

    data.ctx = priv->primary;
    data.datastorePathWithoutFileName = (char *)"[?] ?";

    ctx.opaque = &data;
    ctx.parseFileName = esxParseVMXFileName;
    ctx.formatFileName = NULL;
    ctx.autodetectSCSIControllerModel = NULL;
    ctx.datacenterPath = NULL;

    def = virVMXParseConfig(&ctx, priv->xmlopt, priv->caps, nativeConfig);

    if (def)
        xml = virDomainDefFormat(def, priv->caps,
                                 VIR_DOMAIN_DEF_FORMAT_INACTIVE);

    virDomainDefFree(def);

    return xml;
}



static char *
esxConnectDomainXMLToNative(virConnectPtr conn, const char *nativeFormat,
                            const char *domainXml,
                            unsigned int flags)
{
    esxPrivate *priv = conn->privateData;
    int virtualHW_version;
    virVMXContext ctx;
    esxVMX_Data data;
    virDomainDefPtr def = NULL;
    char *vmx = NULL;

    virCheckFlags(0, NULL);

    memset(&data, 0, sizeof(data));

    if (STRNEQ(nativeFormat, "vmware-vmx")) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Unsupported config format '%s'"), nativeFormat);
        return NULL;
    }

    virtualHW_version = esxVI_ProductVersionToDefaultVirtualHWVersion
                          (priv->primary->productLine, priv->primary->productVersion);

    if (virtualHW_version < 0)
        return NULL;

    def = virDomainDefParseString(domainXml, priv->caps, priv->xmlopt,
                                  NULL, VIR_DOMAIN_DEF_PARSE_INACTIVE);

    if (!def)
        return NULL;

    data.ctx = priv->primary;
    data.datastorePathWithoutFileName = NULL;

    ctx.opaque = &data;
    ctx.parseFileName = NULL;
    ctx.formatFileName = esxFormatVMXFileName;
    ctx.autodetectSCSIControllerModel = esxAutodetectSCSIControllerModel;
    ctx.datacenterPath = NULL;

    vmx = virVMXFormatConfig(&ctx, priv->xmlopt, def, virtualHW_version);

    virDomainDefFree(def);

    return vmx;
}



static int
esxConnectListDefinedDomains(virConnectPtr conn, char **const names, int maxnames)
{
    bool success = false;
    esxPrivate *priv = conn->privateData;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *virtualMachineList = NULL;
    esxVI_ObjectContent *virtualMachine = NULL;
    esxVI_VirtualMachinePowerState powerState;
    int count = 0;
    size_t i;

    if (maxnames == 0)
        return 0;

    if (esxVI_EnsureSession(priv->primary) < 0)
        return -1;

    if (esxVI_String_AppendValueListToList(&propertyNameList,
                                           "name\0"
                                           "runtime.powerState\0") < 0 ||
        esxVI_LookupVirtualMachineList(priv->primary, propertyNameList,
                                       &virtualMachineList) < 0) {
        goto cleanup;
    }

    for (virtualMachine = virtualMachineList; virtualMachine;
         virtualMachine = virtualMachine->_next) {
        if (esxVI_GetVirtualMachinePowerState(virtualMachine,
                                              &powerState) < 0) {
            goto cleanup;
        }

        if (powerState == esxVI_VirtualMachinePowerState_PoweredOn)
            continue;

        names[count] = NULL;

        if (esxVI_GetVirtualMachineIdentity(virtualMachine, NULL, &names[count],
                                            NULL) < 0) {
            goto cleanup;
        }

        ++count;

        if (count >= maxnames)
            break;
    }

    success = true;

 cleanup:
    if (! success) {
        for (i = 0; i < count; ++i)
            VIR_FREE(names[i]);

        count = -1;
    }

    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&virtualMachineList);

    return count;
}



static int
esxConnectNumOfDefinedDomains(virConnectPtr conn)
{
    esxPrivate *priv = conn->privateData;

    if (esxVI_EnsureSession(priv->primary) < 0)
        return -1;

    return esxVI_LookupNumberOfDomainsByPowerState
             (priv->primary, esxVI_VirtualMachinePowerState_PoweredOn, true);
}



static int
esxDomainCreateWithFlags(virDomainPtr domain, unsigned int flags)
{
    int result = -1;
    esxPrivate *priv = domain->conn->privateData;
    esxVI_ObjectContent *virtualMachine = NULL;
    esxVI_String *propertyNameList = NULL;
    esxVI_VirtualMachinePowerState powerState;
    int id = -1;
    esxVI_ManagedObjectReference *task = NULL;
    esxVI_TaskInfoState taskInfoState;
    char *taskInfoErrorMessage = NULL;

    virCheckFlags(0, -1);

    if (esxVI_EnsureSession(priv->primary) < 0)
        return -1;

    if (esxVI_String_AppendValueToList(&propertyNameList,
                                       "runtime.powerState") < 0 ||
        esxVI_LookupVirtualMachineByUuidAndPrepareForTask
          (priv->primary, domain->uuid, propertyNameList, &virtualMachine,
           priv->parsedUri->autoAnswer) < 0 ||
        esxVI_GetVirtualMachinePowerState(virtualMachine, &powerState) < 0 ||
        esxVI_GetVirtualMachineIdentity(virtualMachine, &id, NULL, NULL) < 0) {
        goto cleanup;
    }

    if (powerState != esxVI_VirtualMachinePowerState_PoweredOff) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Domain is not powered off"));
        goto cleanup;
    }

    if (esxVI_PowerOnVM_Task(priv->primary, virtualMachine->obj, NULL,
                             &task) < 0 ||
        esxVI_WaitForTaskCompletion(priv->primary, task, domain->uuid,
                                    esxVI_Occurrence_RequiredItem,
                                    priv->parsedUri->autoAnswer, &taskInfoState,
                                    &taskInfoErrorMessage) < 0) {
        goto cleanup;
    }

    if (taskInfoState != esxVI_TaskInfoState_Success) {
        virReportError(VIR_ERR_INTERNAL_ERROR, _("Could not start domain: %s"),
                       taskInfoErrorMessage);
        goto cleanup;
    }

    domain->id = id;
    result = 0;

 cleanup:
    esxVI_ObjectContent_Free(&virtualMachine);
    esxVI_String_Free(&propertyNameList);
    esxVI_ManagedObjectReference_Free(&task);
    VIR_FREE(taskInfoErrorMessage);

    return result;
}



static int
esxDomainCreate(virDomainPtr domain)
{
    return esxDomainCreateWithFlags(domain, 0);
}



static virDomainPtr
esxDomainDefineXMLFlags(virConnectPtr conn, const char *xml, unsigned int flags)
{
    esxPrivate *priv = conn->privateData;
    virDomainDefPtr def = NULL;
    char *vmx = NULL;
    size_t i;
    virDomainDiskDefPtr disk = NULL;
    esxVI_ObjectContent *virtualMachine = NULL;
    int virtualHW_version;
    virVMXContext ctx;
    esxVMX_Data data;
    char *datastoreName = NULL;
    char *directoryName = NULL;
    char *escapedName = NULL;
    virBuffer buffer = VIR_BUFFER_INITIALIZER;
    char *url = NULL;
    char *datastoreRelatedPath = NULL;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *hostSystem = NULL;
    esxVI_ManagedObjectReference *resourcePool = NULL;
    esxVI_ManagedObjectReference *task = NULL;
    esxVI_TaskInfoState taskInfoState;
    char *taskInfoErrorMessage = NULL;
    virDomainPtr domain = NULL;
    const char *src;
    unsigned int parse_flags = VIR_DOMAIN_DEF_PARSE_INACTIVE;

    virCheckFlags(VIR_DOMAIN_DEFINE_VALIDATE, NULL);

    if (flags & VIR_DOMAIN_DEFINE_VALIDATE)
        parse_flags |= VIR_DOMAIN_DEF_PARSE_VALIDATE_SCHEMA;

    memset(&data, 0, sizeof(data));

    if (esxVI_EnsureSession(priv->primary) < 0)
        return NULL;

    /* Parse domain XML */
    def = virDomainDefParseString(xml, priv->caps, priv->xmlopt,
                                  NULL, parse_flags);

    if (!def)
        return NULL;

    if (virXMLCheckIllegalChars("name", def->name, "\n") < 0)
        goto cleanup;

    /* Check if an existing domain should be edited */
    if (esxVI_LookupVirtualMachineByUuid(priv->primary, def->uuid, NULL,
                                         &virtualMachine,
                                         esxVI_Occurrence_OptionalItem) < 0) {
        goto cleanup;
    }

    if (!virtualMachine &&
        esxVI_LookupVirtualMachineByName(priv->primary, def->name, NULL,
                                         &virtualMachine,
                                         esxVI_Occurrence_OptionalItem) < 0) {
        goto cleanup;
    }

    if (virtualMachine) {
        /* FIXME */
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Domain already exists, editing existing domains is not "
                         "supported yet"));
        goto cleanup;
    }

    /* Build VMX from domain XML */
    virtualHW_version = esxVI_ProductVersionToDefaultVirtualHWVersion
                          (priv->primary->productLine, priv->primary->productVersion);

    if (virtualHW_version < 0)
        goto cleanup;

    data.ctx = priv->primary;
    data.datastorePathWithoutFileName = NULL;

    ctx.opaque = &data;
    ctx.parseFileName = NULL;
    ctx.formatFileName = esxFormatVMXFileName;
    ctx.autodetectSCSIControllerModel = esxAutodetectSCSIControllerModel;
    ctx.datacenterPath = NULL;

    vmx = virVMXFormatConfig(&ctx, priv->xmlopt, def, virtualHW_version);

    if (!vmx)
        goto cleanup;

    /*
     * Build VMX datastore URL. Use the source of the first file-based harddisk
     * to deduce the datastore and path for the VMX file. Don't just use the
     * first disk, because it may be CDROM disk and ISO images are normally not
     * located in the virtual machine's directory. This approach to deduce the
     * datastore isn't perfect but should work in the majority of cases.
     */
    if (def->ndisks < 1) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Domain XML doesn't contain any disks, cannot deduce "
                         "datastore and path for VMX file"));
        goto cleanup;
    }

    for (i = 0; i < def->ndisks; ++i) {
        if (def->disks[i]->device == VIR_DOMAIN_DISK_DEVICE_DISK &&
            virDomainDiskGetType(def->disks[i]) == VIR_STORAGE_TYPE_FILE) {
            disk = def->disks[i];
            break;
        }
    }

    if (!disk) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Domain XML doesn't contain any file-based harddisks, "
                         "cannot deduce datastore and path for VMX file"));
        goto cleanup;
    }

    src = virDomainDiskGetSource(disk);
    if (!src) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("First file-based harddisk has no source, cannot deduce "
                         "datastore and path for VMX file"));
        goto cleanup;
    }

    if (esxUtil_ParseDatastorePath(src, &datastoreName, &directoryName,
                                   NULL) < 0) {
        goto cleanup;
    }

    if (! virFileHasSuffix(src, ".vmdk")) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Expecting source '%s' of first file-based harddisk to "
                         "be a VMDK image"), src);
        goto cleanup;
    }

    virBufferAsprintf(&buffer, "%s://%s:%d/folder/", priv->parsedUri->transport,
                      conn->uri->server, conn->uri->port);

    if (directoryName) {
        virBufferURIEncodeString(&buffer, directoryName);
        virBufferAddChar(&buffer, '/');
    }

    escapedName = esxUtil_EscapeDatastoreItem(def->name);

    if (!escapedName)
        goto cleanup;

    virBufferURIEncodeString(&buffer, escapedName);
    virBufferAddLit(&buffer, ".vmx?dcPath=");
    virBufferURIEncodeString(&buffer, priv->primary->datacenterPath);
    virBufferAddLit(&buffer, "&dsName=");
    virBufferURIEncodeString(&buffer, datastoreName);

    if (virBufferCheckError(&buffer) < 0)
        goto cleanup;

    url = virBufferContentAndReset(&buffer);

    /* Check, if VMX file already exists */
    /* FIXME */

    /* Upload VMX file */
    VIR_DEBUG("Uploading .vmx config, url='%s' vmx='%s'", url, vmx);

    if (esxVI_CURL_Upload(priv->primary->curl, url, vmx) < 0)
        goto cleanup;

    /* Register the domain */
    if (directoryName) {
        if (virAsprintf(&datastoreRelatedPath, "[%s] %s/%s.vmx", datastoreName,
                        directoryName, escapedName) < 0)
            goto cleanup;
    } else {
        if (virAsprintf(&datastoreRelatedPath, "[%s] %s.vmx", datastoreName,
                        escapedName) < 0)
            goto cleanup;
    }

    if (esxVI_RegisterVM_Task(priv->primary, priv->primary->datacenter->vmFolder,
                              datastoreRelatedPath, NULL, esxVI_Boolean_False,
                              priv->primary->computeResource->resourcePool,
                              priv->primary->hostSystem->_reference,
                              &task) < 0 ||
        esxVI_WaitForTaskCompletion(priv->primary, task, def->uuid,
                                    esxVI_Occurrence_OptionalItem,
                                    priv->parsedUri->autoAnswer, &taskInfoState,
                                    &taskInfoErrorMessage) < 0) {
        goto cleanup;
    }

    if (taskInfoState != esxVI_TaskInfoState_Success) {
        virReportError(VIR_ERR_INTERNAL_ERROR, _("Could not define domain: %s"),
                       taskInfoErrorMessage);
        goto cleanup;
    }

    domain = virGetDomain(conn, def->name, def->uuid, -1);

    /* FIXME: Add proper rollback in case of an error */

 cleanup:
    if (!url)
        virBufferFreeAndReset(&buffer);

    virDomainDefFree(def);
    VIR_FREE(vmx);
    VIR_FREE(datastoreName);
    VIR_FREE(directoryName);
    VIR_FREE(escapedName);
    VIR_FREE(url);
    VIR_FREE(datastoreRelatedPath);
    esxVI_ObjectContent_Free(&virtualMachine);
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&hostSystem);
    esxVI_ManagedObjectReference_Free(&resourcePool);
    esxVI_ManagedObjectReference_Free(&task);
    VIR_FREE(taskInfoErrorMessage);

    return domain;
}

static virDomainPtr
esxDomainDefineXML(virConnectPtr conn, const char *xml)
{
    return esxDomainDefineXMLFlags(conn, xml, 0);
}

static int
esxDomainUndefineFlags(virDomainPtr domain,
                       unsigned int flags)
{
    int result = -1;
    esxPrivate *priv = domain->conn->privateData;
    esxVI_Context *ctx = NULL;
    esxVI_ObjectContent *virtualMachine = NULL;
    esxVI_String *propertyNameList = NULL;
    esxVI_VirtualMachinePowerState powerState;

    /* No managed save, so we explicitly reject
     * VIR_DOMAIN_UNDEFINE_MANAGED_SAVE.  No snapshot metadata for
     * ESX, so we can trivially ignore that flag.  */
    virCheckFlags(VIR_DOMAIN_UNDEFINE_SNAPSHOTS_METADATA, -1);

    if (priv->vCenter) {
        ctx = priv->vCenter;
    } else {
        ctx = priv->host;
    }

    if (esxVI_EnsureSession(ctx) < 0)
        return -1;

    if (esxVI_String_AppendValueToList(&propertyNameList,
                                       "runtime.powerState") < 0 ||
        esxVI_LookupVirtualMachineByUuid(ctx, domain->uuid, propertyNameList,
                                         &virtualMachine,
                                         esxVI_Occurrence_RequiredItem) < 0 ||
        esxVI_GetVirtualMachinePowerState(virtualMachine, &powerState) < 0) {
        goto cleanup;
    }

    if (powerState != esxVI_VirtualMachinePowerState_Suspended &&
        powerState != esxVI_VirtualMachinePowerState_PoweredOff) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Domain is not suspended or powered off"));
        goto cleanup;
    }

    if (esxVI_UnregisterVM(ctx, virtualMachine->obj) < 0)
        goto cleanup;

    result = 0;

 cleanup:
    esxVI_ObjectContent_Free(&virtualMachine);
    esxVI_String_Free(&propertyNameList);

    return result;
}


static int
esxDomainUndefine(virDomainPtr domain)
{
    return esxDomainUndefineFlags(domain, 0);
}

static int
esxDomainGetAutostart(virDomainPtr domain, int *autostart)
{
    int result = -1;
    esxPrivate *priv = domain->conn->privateData;
    esxVI_AutoStartDefaults *defaults = NULL;
    esxVI_String *propertyNameList = NULL;
    esxVI_AutoStartPowerInfo *powerInfo = NULL;
    esxVI_AutoStartPowerInfo *powerInfoList = NULL;
    esxVI_ObjectContent *virtualMachine = NULL;

    *autostart = 0;

    if (esxVI_EnsureSession(priv->primary) < 0)
        return -1;

    /* Check general autostart config */
    if (esxVI_LookupAutoStartDefaults(priv->primary, &defaults) < 0)
        goto cleanup;

    if (defaults->enabled != esxVI_Boolean_True) {
        /* Autostart is disabled in general, exit early here */
        result = 0;
        goto cleanup;
    }

    /* Check specific autostart config */
    if (esxVI_LookupAutoStartPowerInfoList(priv->primary, &powerInfoList) < 0)
        goto cleanup;

    if (!powerInfoList) {
        /* powerInfo list is empty, exit early here */
        result = 0;
        goto cleanup;
    }

    if (esxVI_LookupVirtualMachineByUuid(priv->primary, domain->uuid,
                                         NULL, &virtualMachine,
                                         esxVI_Occurrence_RequiredItem) < 0) {
        goto cleanup;
    }

    for (powerInfo = powerInfoList; powerInfo;
         powerInfo = powerInfo->_next) {
        if (STREQ(powerInfo->key->value, virtualMachine->obj->value)) {
            if (STRCASEEQ(powerInfo->startAction, "powerOn"))
                *autostart = 1;

            break;
        }
    }

    result = 0;

 cleanup:
    esxVI_String_Free(&propertyNameList);
    esxVI_AutoStartDefaults_Free(&defaults);
    esxVI_AutoStartPowerInfo_Free(&powerInfoList);
    esxVI_ObjectContent_Free(&virtualMachine);

    return result;
}



static int
esxDomainSetAutostart(virDomainPtr domain, int autostart)
{
    int result = -1;
    esxPrivate *priv = domain->conn->privateData;
    esxVI_ObjectContent *virtualMachine = NULL;
    esxVI_HostAutoStartManagerConfig *spec = NULL;
    esxVI_AutoStartDefaults *defaults = NULL;
    esxVI_AutoStartPowerInfo *powerInfoList = NULL;
    esxVI_AutoStartPowerInfo *powerInfo = NULL;
    esxVI_AutoStartPowerInfo *newPowerInfo = NULL;

    if (esxVI_EnsureSession(priv->primary) < 0)
        return -1;

    if (esxVI_LookupVirtualMachineByUuid(priv->primary, domain->uuid,
                                         NULL, &virtualMachine,
                                         esxVI_Occurrence_RequiredItem) < 0 ||
        esxVI_HostAutoStartManagerConfig_Alloc(&spec) < 0) {
        goto cleanup;
    }

    if (autostart) {
        /*
         * There is a general autostart option that affects the autostart
         * behavior of all domains. If it's disabled then no domain does
         * autostart. If it's enabled then the autostart behavior depends on
         * the per-domain autostart config.
         */
        if (esxVI_LookupAutoStartDefaults(priv->primary, &defaults) < 0)
            goto cleanup;

        if (defaults->enabled != esxVI_Boolean_True) {
            /*
             * Autostart is disabled in general. Check if no other domain is
             * in the list of autostarted domains, so it's safe to enable the
             * general autostart option without affecting the autostart
             * behavior of other domains.
             */
            if (esxVI_LookupAutoStartPowerInfoList(priv->primary,
                                                   &powerInfoList) < 0) {
                goto cleanup;
            }

            for (powerInfo = powerInfoList; powerInfo;
                 powerInfo = powerInfo->_next) {
                if (STRNEQ(powerInfo->key->value, virtualMachine->obj->value)) {
                    virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                                   _("Cannot enable general autostart option "
                                     "without affecting other domains"));
                    goto cleanup;
                }
            }

            /* Enable autostart in general */
            if (esxVI_AutoStartDefaults_Alloc(&spec->defaults) < 0)
                goto cleanup;

            spec->defaults->enabled = esxVI_Boolean_True;
        }
    }

    if (esxVI_AutoStartPowerInfo_Alloc(&newPowerInfo) < 0 ||
        esxVI_Int_Alloc(&newPowerInfo->startOrder) < 0 ||
        esxVI_Int_Alloc(&newPowerInfo->startDelay) < 0 ||
        esxVI_Int_Alloc(&newPowerInfo->stopDelay) < 0) {
        goto cleanup;
    }

    newPowerInfo->key = virtualMachine->obj;
    newPowerInfo->startOrder->value = -1; /* no specific start order */
    newPowerInfo->startDelay->value = -1; /* use system default */
    newPowerInfo->waitForHeartbeat = esxVI_AutoStartWaitHeartbeatSetting_SystemDefault;
    newPowerInfo->startAction = autostart ? (char *)"powerOn" : (char *)"none";
    newPowerInfo->stopDelay->value = -1; /* use system default */
    newPowerInfo->stopAction = (char *)"none";

    if (esxVI_AutoStartPowerInfo_AppendToList(&spec->powerInfo,
                                              newPowerInfo) < 0) {
        goto cleanup;
    }

    newPowerInfo = NULL;

    if (esxVI_ReconfigureAutostart
          (priv->primary,
           priv->primary->hostSystem->configManager->autoStartManager,
           spec) < 0) {
        goto cleanup;
    }

    result = 0;

 cleanup:
    if (newPowerInfo) {
        newPowerInfo->key = NULL;
        newPowerInfo->startAction = NULL;
        newPowerInfo->stopAction = NULL;
    }

    esxVI_ObjectContent_Free(&virtualMachine);
    esxVI_HostAutoStartManagerConfig_Free(&spec);
    esxVI_AutoStartDefaults_Free(&defaults);
    esxVI_AutoStartPowerInfo_Free(&powerInfoList);

    esxVI_AutoStartPowerInfo_Free(&newPowerInfo);

    return result;
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
 * - reservation (VIR_TYPED_PARAM_LLONG >= 0, in megaherz)
 *
 *   The amount of CPU resource that is guaranteed to be available to the domain.
 *
 *
 * - limit (VIR_TYPED_PARAM_LLONG >= 0, or -1, in megaherz)
 *
 *   The CPU utilization of the domain will be limited to this value, even if
 *   more CPU resources are available. If the limit is set to -1, the CPU
 *   utilization of the domain is unlimited. If the limit is not set to -1, it
 *   must be greater than or equal to the reservation.
 *
 *
 * - shares (VIR_TYPED_PARAM_INT >= 0, or in {-1, -2, -3}, no unit)
 *
 *   Shares are used to determine relative CPU allocation between domains. In
 *   general, a domain with more shares gets proportionally more of the CPU
 *   resource. The special values -1, -2 and -3 represent the predefined
 *   SharesLevel 'low', 'normal' and 'high'.
 */
static char *
esxDomainGetSchedulerType(virDomainPtr domain ATTRIBUTE_UNUSED, int *nparams)
{
    char *type;

    if (VIR_STRDUP(type, "allocation") < 0)
        return NULL;

    if (nparams)
        *nparams = 3; /* reservation, limit, shares */

    return type;
}



static int
esxDomainGetSchedulerParametersFlags(virDomainPtr domain,
                                     virTypedParameterPtr params, int *nparams,
                                     unsigned int flags)
{
    int result = -1;
    esxPrivate *priv = domain->conn->privateData;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *virtualMachine = NULL;
    esxVI_DynamicProperty *dynamicProperty = NULL;
    esxVI_SharesInfo *sharesInfo = NULL;
    unsigned int mask = 0;
    size_t i = 0;

    virCheckFlags(0, -1);

    if (esxVI_EnsureSession(priv->primary) < 0)
        return -1;

    if (esxVI_String_AppendValueListToList(&propertyNameList,
                                           "config.cpuAllocation.reservation\0"
                                           "config.cpuAllocation.limit\0"
                                           "config.cpuAllocation.shares\0") < 0 ||
        esxVI_LookupVirtualMachineByUuid(priv->primary, domain->uuid,
                                         propertyNameList, &virtualMachine,
                                         esxVI_Occurrence_RequiredItem) < 0) {
        goto cleanup;
    }

    for (dynamicProperty = virtualMachine->propSet;
         dynamicProperty && mask != 7 && i < 3 && i < *nparams;
         dynamicProperty = dynamicProperty->_next) {
        if (STREQ(dynamicProperty->name, "config.cpuAllocation.reservation") &&
            ! (mask & (1 << 0))) {
            if (esxVI_AnyType_ExpectType(dynamicProperty->val,
                                         esxVI_Type_Long) < 0) {
                goto cleanup;
            }
            if (virTypedParameterAssign(&params[i],
                                        VIR_DOMAIN_SCHEDULER_RESERVATION,
                                        VIR_TYPED_PARAM_LLONG,
                                        dynamicProperty->val->int64) < 0)
                goto cleanup;
            mask |= 1 << 0;
            ++i;
        } else if (STREQ(dynamicProperty->name,
                         "config.cpuAllocation.limit") &&
                   ! (mask & (1 << 1))) {
            if (esxVI_AnyType_ExpectType(dynamicProperty->val,
                                         esxVI_Type_Long) < 0) {
                goto cleanup;
            }
            if (virTypedParameterAssign(&params[i],
                                        VIR_DOMAIN_SCHEDULER_LIMIT,
                                        VIR_TYPED_PARAM_LLONG,
                                        dynamicProperty->val->int64) < 0)
                goto cleanup;
            mask |= 1 << 1;
            ++i;
        } else if (STREQ(dynamicProperty->name,
                         "config.cpuAllocation.shares") &&
                   ! (mask & (1 << 2))) {
            if (virTypedParameterAssign(&params[i],
                                        VIR_DOMAIN_SCHEDULER_SHARES,
                                        VIR_TYPED_PARAM_INT, 0) < 0)
                goto cleanup;
            if (esxVI_SharesInfo_CastFromAnyType(dynamicProperty->val,
                                                 &sharesInfo) < 0) {
                goto cleanup;
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
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Shares level has unknown value %d"),
                               (int)sharesInfo->level);
                esxVI_SharesInfo_Free(&sharesInfo);
                goto cleanup;
            }

            esxVI_SharesInfo_Free(&sharesInfo);

            mask |= 1 << 2;
            ++i;
        } else {
            VIR_WARN("Unexpected '%s' property", dynamicProperty->name);
        }
    }

    *nparams = i;
    result = 0;

 cleanup:
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&virtualMachine);

    return result;
}

static int
esxDomainGetSchedulerParameters(virDomainPtr domain,
                                virTypedParameterPtr params, int *nparams)
{
    return esxDomainGetSchedulerParametersFlags(domain, params, nparams, 0);
}


static int
esxDomainSetSchedulerParametersFlags(virDomainPtr domain,
                                     virTypedParameterPtr params, int nparams,
                                     unsigned int flags)
{
    int result = -1;
    esxPrivate *priv = domain->conn->privateData;
    esxVI_ObjectContent *virtualMachine = NULL;
    esxVI_VirtualMachineConfigSpec *spec = NULL;
    esxVI_SharesInfo *sharesInfo = NULL;
    esxVI_ManagedObjectReference *task = NULL;
    esxVI_TaskInfoState taskInfoState;
    char *taskInfoErrorMessage = NULL;
    size_t i;

    virCheckFlags(0, -1);
    if (virTypedParamsValidate(params, nparams,
                               VIR_DOMAIN_SCHEDULER_RESERVATION,
                               VIR_TYPED_PARAM_LLONG,
                               VIR_DOMAIN_SCHEDULER_LIMIT,
                               VIR_TYPED_PARAM_LLONG,
                               VIR_DOMAIN_SCHEDULER_SHARES,
                               VIR_TYPED_PARAM_INT,
                               NULL) < 0)
        return -1;

    if (esxVI_EnsureSession(priv->primary) < 0)
        return -1;

    if (esxVI_LookupVirtualMachineByUuidAndPrepareForTask
          (priv->primary, domain->uuid, NULL, &virtualMachine,
           priv->parsedUri->autoAnswer) < 0 ||
        esxVI_VirtualMachineConfigSpec_Alloc(&spec) < 0 ||
        esxVI_ResourceAllocationInfo_Alloc(&spec->cpuAllocation) < 0) {
        goto cleanup;
    }

    for (i = 0; i < nparams; ++i) {
        if (STREQ(params[i].field, VIR_DOMAIN_SCHEDULER_RESERVATION)) {
            if (esxVI_Long_Alloc(&spec->cpuAllocation->reservation) < 0)
                goto cleanup;

            if (params[i].value.l < 0) {
                virReportError(VIR_ERR_INVALID_ARG,
                               _("Could not set reservation to %lld MHz, expecting "
                                 "positive value"), params[i].value.l);
                goto cleanup;
            }

            spec->cpuAllocation->reservation->value = params[i].value.l;
        } else if (STREQ(params[i].field, VIR_DOMAIN_SCHEDULER_LIMIT)) {
            if (esxVI_Long_Alloc(&spec->cpuAllocation->limit) < 0)
                goto cleanup;

            if (params[i].value.l < -1) {
                virReportError(VIR_ERR_INVALID_ARG,
                               _("Could not set limit to %lld MHz, expecting "
                                 "positive value or -1 (unlimited)"),
                               params[i].value.l);
                goto cleanup;
            }

            spec->cpuAllocation->limit->value = params[i].value.l;
        } else if (STREQ(params[i].field, VIR_DOMAIN_SCHEDULER_SHARES)) {
            if (esxVI_SharesInfo_Alloc(&sharesInfo) < 0 ||
                esxVI_Int_Alloc(&sharesInfo->shares) < 0) {
                goto cleanup;
            }

            spec->cpuAllocation->shares = sharesInfo;
            sharesInfo = NULL;

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
                    virReportError(VIR_ERR_INVALID_ARG,
                                   _("Could not set shares to %d, expecting positive "
                                     "value or -1 (low), -2 (normal) or -3 (high)"),
                                   params[i].value.i);
                    goto cleanup;
                }
            }
        }
    }

    if (esxVI_ReconfigVM_Task(priv->primary, virtualMachine->obj, spec,
                              &task) < 0 ||
        esxVI_WaitForTaskCompletion(priv->primary, task, domain->uuid,
                                    esxVI_Occurrence_RequiredItem,
                                    priv->parsedUri->autoAnswer, &taskInfoState,
                                    &taskInfoErrorMessage) < 0) {
        goto cleanup;
    }

    if (taskInfoState != esxVI_TaskInfoState_Success) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not change scheduler parameters: %s"),
                       taskInfoErrorMessage);
        goto cleanup;
    }

    result = 0;

 cleanup:
    esxVI_SharesInfo_Free(&sharesInfo);
    esxVI_ObjectContent_Free(&virtualMachine);
    esxVI_VirtualMachineConfigSpec_Free(&spec);
    esxVI_ManagedObjectReference_Free(&task);
    VIR_FREE(taskInfoErrorMessage);

    return result;
}

static int
esxDomainSetSchedulerParameters(virDomainPtr domain,
                                virTypedParameterPtr params, int nparams)
{
    return esxDomainSetSchedulerParametersFlags(domain, params, nparams, 0);
}

/* The subset of migration flags we are able to support.  */
#define ESX_MIGRATION_FLAGS                     \
    (VIR_MIGRATE_PERSIST_DEST |                 \
     VIR_MIGRATE_UNDEFINE_SOURCE |              \
     VIR_MIGRATE_LIVE |                         \
     VIR_MIGRATE_PAUSED)

static int
esxDomainMigratePrepare(virConnectPtr dconn,
                        char **cookie ATTRIBUTE_UNUSED,
                        int *cookielen ATTRIBUTE_UNUSED,
                        const char *uri_in ATTRIBUTE_UNUSED,
                        char **uri_out,
                        unsigned long flags,
                        const char *dname ATTRIBUTE_UNUSED,
                        unsigned long resource ATTRIBUTE_UNUSED)
{
    esxPrivate *priv = dconn->privateData;

    virCheckFlags(ESX_MIGRATION_FLAGS, -1);

    if (!uri_in) {
        if (virAsprintf(uri_out, "vpxmigr://%s/%s/%s",
                        priv->vCenter->ipAddress,
                        priv->vCenter->computeResource->resourcePool->value,
                        priv->vCenter->hostSystem->_reference->value) < 0)
            return -1;
    }

    return 0;
}



static int
esxDomainMigratePerform(virDomainPtr domain,
                        const char *cookie ATTRIBUTE_UNUSED,
                        int cookielen ATTRIBUTE_UNUSED,
                        const char *uri,
                        unsigned long flags,
                        const char *dname,
                        unsigned long bandwidth ATTRIBUTE_UNUSED)
{
    int result = -1;
    esxPrivate *priv = domain->conn->privateData;
    virURIPtr parsedUri = NULL;
    char *saveptr;
    char *path_resourcePool;
    char *path_hostSystem;
    esxVI_ObjectContent *virtualMachine = NULL;
    esxVI_ManagedObjectReference resourcePool;
    esxVI_ManagedObjectReference hostSystem;
    esxVI_Event *eventList = NULL;
    esxVI_ManagedObjectReference *task = NULL;
    esxVI_TaskInfoState taskInfoState;
    char *taskInfoErrorMessage = NULL;

    virCheckFlags(ESX_MIGRATION_FLAGS, -1);

    if (!priv->vCenter) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Migration not possible without a vCenter"));
        return -1;
    }

    if (dname) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Renaming domains on migration not supported"));
        return -1;
    }

    if (esxVI_EnsureSession(priv->vCenter) < 0)
        return -1;

    /* Parse migration URI */
    if (!(parsedUri = virURIParse(uri)))
        return -1;

    if (!parsedUri->scheme || STRCASENEQ(parsedUri->scheme, "vpxmigr")) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Only vpxmigr:// migration URIs are supported"));
        goto cleanup;
    }

    if (STRCASENEQ(priv->vCenter->ipAddress, parsedUri->server)) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Migration source and destination have to refer to "
                         "the same vCenter"));
        goto cleanup;
    }

    path_resourcePool = strtok_r(parsedUri->path, "/", &saveptr);
    path_hostSystem = strtok_r(NULL, "", &saveptr);

    if (!path_resourcePool || !path_hostSystem) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Migration URI has to specify resource pool and host system"));
        goto cleanup;
    }

    resourcePool._next = NULL;
    resourcePool._type = esxVI_Type_ManagedObjectReference;
    resourcePool.type = (char *)"ResourcePool";
    resourcePool.value = path_resourcePool;

    hostSystem._next = NULL;
    hostSystem._type = esxVI_Type_ManagedObjectReference;
    hostSystem.type = (char *)"HostSystem";
    hostSystem.value = path_hostSystem;

    /* Lookup VirtualMachine */
    if (esxVI_LookupVirtualMachineByUuidAndPrepareForTask
          (priv->vCenter, domain->uuid, NULL, &virtualMachine,
           priv->parsedUri->autoAnswer) < 0) {
        goto cleanup;
    }

    /* Validate the purposed migration */
    if (esxVI_ValidateMigration(priv->vCenter, virtualMachine->obj,
                                esxVI_VirtualMachinePowerState_Undefined, NULL,
                                &resourcePool, &hostSystem, &eventList) < 0) {
        goto cleanup;
    }

    if (eventList) {
        /*
         * FIXME: Need to report the complete list of events. Limit reporting
         *        to the first event for now.
         */
        if (eventList->fullFormattedMessage) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Could not migrate domain, validation reported a "
                             "problem: %s"), eventList->fullFormattedMessage);
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Could not migrate domain, validation reported a "
                             "problem"));
        }

        goto cleanup;
    }

    /* Perform the purposed migration */
    if (esxVI_MigrateVM_Task(priv->vCenter, virtualMachine->obj,
                             &resourcePool, &hostSystem,
                             esxVI_VirtualMachineMovePriority_DefaultPriority,
                             esxVI_VirtualMachinePowerState_Undefined,
                             &task) < 0 ||
        esxVI_WaitForTaskCompletion(priv->vCenter, task, domain->uuid,
                                    esxVI_Occurrence_RequiredItem,
                                    priv->parsedUri->autoAnswer, &taskInfoState,
                                    &taskInfoErrorMessage) < 0) {
        goto cleanup;
    }

    if (taskInfoState != esxVI_TaskInfoState_Success) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not migrate domain, migration task finished with "
                         "an error: %s"),
                       taskInfoErrorMessage);
        goto cleanup;
    }

    result = 0;

 cleanup:
    virURIFree(parsedUri);
    esxVI_ObjectContent_Free(&virtualMachine);
    esxVI_Event_Free(&eventList);
    esxVI_ManagedObjectReference_Free(&task);
    VIR_FREE(taskInfoErrorMessage);

    return result;
}



static virDomainPtr
esxDomainMigrateFinish(virConnectPtr dconn, const char *dname,
                       const char *cookie ATTRIBUTE_UNUSED,
                       int cookielen ATTRIBUTE_UNUSED,
                       const char *uri ATTRIBUTE_UNUSED,
                       unsigned long flags)
{
    virCheckFlags(ESX_MIGRATION_FLAGS, NULL);

    return esxDomainLookupByName(dconn, dname);
}



static unsigned long long
esxNodeGetFreeMemory(virConnectPtr conn)
{
    unsigned long long result = 0;
    unsigned long long usageBytes = 0;
    esxPrivate *priv = conn->privateData;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *hostSystem = NULL;
    esxVI_Int *memoryUsage = NULL;
    esxVI_Long *memorySize = NULL;

    if (esxVI_EnsureSession(priv->primary) < 0)
        return 0;

    /* Get memory usage of host system */
    if (esxVI_String_AppendValueListToList(&propertyNameList,
                                           "summary.quickStats.overallMemoryUsage\0"
                                           "hardware.memorySize\0") < 0 ||
        esxVI_LookupHostSystemProperties(priv->primary, propertyNameList,
                                         &hostSystem) < 0 ||
        esxVI_GetInt(hostSystem, "summary.quickStats.overallMemoryUsage",
                      &memoryUsage, esxVI_Occurrence_RequiredItem) < 0 ||
        esxVI_GetLong(hostSystem, "hardware.memorySize", &memorySize,
                      esxVI_Occurrence_RequiredItem) < 0) {
        goto cleanup;
    }

    usageBytes = (unsigned long long) (memoryUsage->value) * 1048576;
    result = memorySize->value - usageBytes;

 cleanup:
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&hostSystem);
    esxVI_Int_Free(&memoryUsage);
    esxVI_Long_Free(&memorySize);

    return result;
}



static int
esxConnectIsEncrypted(virConnectPtr conn)
{
    esxPrivate *priv = conn->privateData;

    if (STRCASEEQ(priv->parsedUri->transport, "https")) {
        return 1;
    } else {
        return 0;
    }
}



static int
esxConnectIsSecure(virConnectPtr conn)
{
    esxPrivate *priv = conn->privateData;

    if (STRCASEEQ(priv->parsedUri->transport, "https")) {
        return 1;
    } else {
        return 0;
    }
}



static int
esxConnectIsAlive(virConnectPtr conn)
{
    esxPrivate *priv = conn->privateData;

    /* XXX we should be able to do something better than this but this is
     * simple, safe, and good enough for now. In worst case, the function will
     * return true even though the connection is not alive.
     */
    if (priv->primary)
        return 1;
    else
        return 0;
}



static int
esxDomainIsActive(virDomainPtr domain)
{
    int result = -1;
    esxPrivate *priv = domain->conn->privateData;
    esxVI_ObjectContent *virtualMachine = NULL;
    esxVI_String *propertyNameList = NULL;
    esxVI_VirtualMachinePowerState powerState;

    if (esxVI_EnsureSession(priv->primary) < 0)
        return -1;

    if (esxVI_String_AppendValueToList(&propertyNameList,
                                       "runtime.powerState") < 0 ||
        esxVI_LookupVirtualMachineByUuid(priv->primary, domain->uuid,
                                         propertyNameList, &virtualMachine,
                                         esxVI_Occurrence_RequiredItem) < 0 ||
        esxVI_GetVirtualMachinePowerState(virtualMachine, &powerState) < 0) {
        goto cleanup;
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
}



static int
esxDomainIsPersistent(virDomainPtr domain)
{
    /* ESX has no concept of transient domains, so all of them are
     * persistent.  However, we do want to check for existence. */
    int result = -1;
    esxPrivate *priv = domain->conn->privateData;
    esxVI_ObjectContent *virtualMachine = NULL;

    if (esxVI_EnsureSession(priv->primary) < 0)
        return -1;

    if (esxVI_LookupVirtualMachineByUuid(priv->primary, domain->uuid,
                                         NULL, &virtualMachine,
                                         esxVI_Occurrence_RequiredItem) < 0)
        goto cleanup;

    result = 1;

 cleanup:
    esxVI_ObjectContent_Free(&virtualMachine);

    return result;
}



static int
esxDomainIsUpdated(virDomainPtr domain ATTRIBUTE_UNUSED)
{
    /* ESX domains never have a persistent state that differs from
     * current state.  However, we do want to check for existence.  */
    int result = -1;
    esxPrivate *priv = domain->conn->privateData;
    esxVI_ObjectContent *virtualMachine = NULL;

    if (esxVI_EnsureSession(priv->primary) < 0)
        return -1;

    if (esxVI_LookupVirtualMachineByUuid(priv->primary, domain->uuid,
                                         NULL, &virtualMachine,
                                         esxVI_Occurrence_RequiredItem) < 0)
        goto cleanup;

    result = 0;

 cleanup:
    esxVI_ObjectContent_Free(&virtualMachine);

    return result;
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
    esxVI_ManagedObjectReference *task = NULL;
    esxVI_TaskInfoState taskInfoState;
    char *taskInfoErrorMessage = NULL;
    virDomainSnapshotPtr snapshot = NULL;
    bool diskOnly = (flags & VIR_DOMAIN_SNAPSHOT_CREATE_DISK_ONLY) != 0;
    bool quiesce = (flags & VIR_DOMAIN_SNAPSHOT_CREATE_QUIESCE) != 0;

    /* ESX supports disk-only and quiesced snapshots; libvirt tracks no
     * snapshot metadata so supporting that flag is trivial.  */
    virCheckFlags(VIR_DOMAIN_SNAPSHOT_CREATE_DISK_ONLY |
                  VIR_DOMAIN_SNAPSHOT_CREATE_QUIESCE |
                  VIR_DOMAIN_SNAPSHOT_CREATE_NO_METADATA, NULL);

    if (esxVI_EnsureSession(priv->primary) < 0)
        return NULL;

    def = virDomainSnapshotDefParseString(xmlDesc, priv->caps,
                                          priv->xmlopt, 0);

    if (!def)
        return NULL;

    if (def->ndisks) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("disk snapshots not supported yet"));
        return NULL;
    }

    if (esxVI_LookupVirtualMachineByUuidAndPrepareForTask
          (priv->primary, domain->uuid, NULL, &virtualMachine,
           priv->parsedUri->autoAnswer) < 0 ||
        esxVI_LookupRootSnapshotTreeList(priv->primary, domain->uuid,
                                         &rootSnapshotList) < 0 ||
        esxVI_GetSnapshotTreeByName(rootSnapshotList, def->name,
                                    &snapshotTree, NULL,
                                    esxVI_Occurrence_OptionalItem) < 0) {
        goto cleanup;
    }

    if (snapshotTree) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("Snapshot '%s' already exists"), def->name);
        goto cleanup;
    }

    if (esxVI_CreateSnapshot_Task(priv->primary, virtualMachine->obj,
                                  def->name, def->description,
                                  diskOnly ? esxVI_Boolean_False : esxVI_Boolean_True,
                                  quiesce ? esxVI_Boolean_True : esxVI_Boolean_False,
                                  &task) < 0 ||
        esxVI_WaitForTaskCompletion(priv->primary, task, domain->uuid,
                                    esxVI_Occurrence_RequiredItem,
                                    priv->parsedUri->autoAnswer, &taskInfoState,
                                    &taskInfoErrorMessage) < 0) {
        goto cleanup;
    }

    if (taskInfoState != esxVI_TaskInfoState_Success) {
        virReportError(VIR_ERR_INTERNAL_ERROR, _("Could not create snapshot: %s"),
                       taskInfoErrorMessage);
        goto cleanup;
    }

    snapshot = virGetDomainSnapshot(domain, def->name);

 cleanup:
    virDomainSnapshotDefFree(def);
    esxVI_ObjectContent_Free(&virtualMachine);
    esxVI_VirtualMachineSnapshotTree_Free(&rootSnapshotList);
    esxVI_ManagedObjectReference_Free(&task);
    VIR_FREE(taskInfoErrorMessage);

    return snapshot;
}



static char *
esxDomainSnapshotGetXMLDesc(virDomainSnapshotPtr snapshot,
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

    memset(&def, 0, sizeof(def));

    if (esxVI_EnsureSession(priv->primary) < 0)
        return NULL;

    if (esxVI_LookupRootSnapshotTreeList(priv->primary, snapshot->domain->uuid,
                                         &rootSnapshotList) < 0 ||
        esxVI_GetSnapshotTreeByName(rootSnapshotList, snapshot->name,
                                    &snapshotTree, &snapshotTreeParent,
                                    esxVI_Occurrence_RequiredItem) < 0) {
        goto cleanup;
    }

    def.name = snapshot->name;
    def.description = snapshotTree->description;
    def.parent = snapshotTreeParent ? snapshotTreeParent->name : NULL;

    if (esxVI_DateTime_ConvertToCalendarTime(snapshotTree->createTime,
                                             &def.creationTime) < 0) {
        goto cleanup;
    }

    def.state = esxVI_VirtualMachinePowerState_ConvertToLibvirt
                  (snapshotTree->state);

    virUUIDFormat(snapshot->domain->uuid, uuid_string);

    xml = virDomainSnapshotDefFormat(uuid_string, &def, priv->caps,
                                     virDomainDefFormatConvertXMLFlags(flags),
                                     0);

 cleanup:
    esxVI_VirtualMachineSnapshotTree_Free(&rootSnapshotList);

    return xml;
}



static int
esxDomainSnapshotNum(virDomainPtr domain, unsigned int flags)
{
    int count;
    esxPrivate *priv = domain->conn->privateData;
    esxVI_VirtualMachineSnapshotTree *rootSnapshotTreeList = NULL;
    bool recurse;
    bool leaves;

    virCheckFlags(VIR_DOMAIN_SNAPSHOT_LIST_ROOTS |
                  VIR_DOMAIN_SNAPSHOT_LIST_METADATA |
                  VIR_DOMAIN_SNAPSHOT_LIST_LEAVES, -1);

    recurse = (flags & VIR_DOMAIN_SNAPSHOT_LIST_ROOTS) == 0;
    leaves = (flags & VIR_DOMAIN_SNAPSHOT_LIST_LEAVES) != 0;

    if (esxVI_EnsureSession(priv->primary) < 0)
        return -1;

    /* ESX snapshots do not require libvirt to maintain any metadata.  */
    if (flags & VIR_DOMAIN_SNAPSHOT_LIST_METADATA)
        return 0;

    if (esxVI_LookupRootSnapshotTreeList(priv->primary, domain->uuid,
                                         &rootSnapshotTreeList) < 0) {
        return -1;
    }

    count = esxVI_GetNumberOfSnapshotTrees(rootSnapshotTreeList, recurse,
                                           leaves);

    esxVI_VirtualMachineSnapshotTree_Free(&rootSnapshotTreeList);

    return count;
}



static int
esxDomainSnapshotListNames(virDomainPtr domain, char **names, int nameslen,
                           unsigned int flags)
{
    int result;
    esxPrivate *priv = domain->conn->privateData;
    esxVI_VirtualMachineSnapshotTree *rootSnapshotTreeList = NULL;
    bool recurse;
    bool leaves;

    virCheckFlags(VIR_DOMAIN_SNAPSHOT_LIST_ROOTS |
                  VIR_DOMAIN_SNAPSHOT_LIST_METADATA |
                  VIR_DOMAIN_SNAPSHOT_LIST_LEAVES, -1);

    recurse = (flags & VIR_DOMAIN_SNAPSHOT_LIST_ROOTS) == 0;
    leaves = (flags & VIR_DOMAIN_SNAPSHOT_LIST_LEAVES) != 0;

    if (!names || nameslen < 0) {
        virReportError(VIR_ERR_INVALID_ARG, "%s", _("Invalid argument"));
        return -1;
    }

    if (nameslen == 0 || (flags & VIR_DOMAIN_SNAPSHOT_LIST_METADATA))
        return 0;

    if (esxVI_EnsureSession(priv->primary) < 0)
        return -1;

    if (esxVI_LookupRootSnapshotTreeList(priv->primary, domain->uuid,
                                         &rootSnapshotTreeList) < 0) {
        return -1;
    }

    result = esxVI_GetSnapshotTreeNames(rootSnapshotTreeList, names, nameslen,
                                        recurse, leaves);

    esxVI_VirtualMachineSnapshotTree_Free(&rootSnapshotTreeList);

    return result;
}



static int
esxDomainSnapshotNumChildren(virDomainSnapshotPtr snapshot, unsigned int flags)
{
    int count = -1;
    esxPrivate *priv = snapshot->domain->conn->privateData;
    esxVI_VirtualMachineSnapshotTree *rootSnapshotTreeList = NULL;
    esxVI_VirtualMachineSnapshotTree *snapshotTree = NULL;
    bool recurse;
    bool leaves;

    virCheckFlags(VIR_DOMAIN_SNAPSHOT_LIST_DESCENDANTS |
                  VIR_DOMAIN_SNAPSHOT_LIST_METADATA |
                  VIR_DOMAIN_SNAPSHOT_LIST_LEAVES, -1);

    recurse = (flags & VIR_DOMAIN_SNAPSHOT_LIST_DESCENDANTS) != 0;
    leaves = (flags & VIR_DOMAIN_SNAPSHOT_LIST_LEAVES) != 0;

    if (esxVI_EnsureSession(priv->primary) < 0)
        return -1;

    if (esxVI_LookupRootSnapshotTreeList(priv->primary, snapshot->domain->uuid,
                                         &rootSnapshotTreeList) < 0 ||
        esxVI_GetSnapshotTreeByName(rootSnapshotTreeList, snapshot->name,
                                    &snapshotTree, NULL,
                                    esxVI_Occurrence_RequiredItem) < 0) {
        goto cleanup;
    }

    /* ESX snapshots do not require libvirt to maintain any metadata.  */
    if (flags & VIR_DOMAIN_SNAPSHOT_LIST_METADATA) {
        count = 0;
        goto cleanup;
    }

    count = esxVI_GetNumberOfSnapshotTrees(snapshotTree->childSnapshotList,
                                           recurse, leaves);

 cleanup:
    esxVI_VirtualMachineSnapshotTree_Free(&rootSnapshotTreeList);

    return count;
}



static int
esxDomainSnapshotListChildrenNames(virDomainSnapshotPtr snapshot,
                                   char **names, int nameslen,
                                   unsigned int flags)
{
    int result = -1;
    esxPrivate *priv = snapshot->domain->conn->privateData;
    esxVI_VirtualMachineSnapshotTree *rootSnapshotTreeList = NULL;
    esxVI_VirtualMachineSnapshotTree *snapshotTree = NULL;
    bool recurse;
    bool leaves;

    virCheckFlags(VIR_DOMAIN_SNAPSHOT_LIST_DESCENDANTS |
                  VIR_DOMAIN_SNAPSHOT_LIST_METADATA |
                  VIR_DOMAIN_SNAPSHOT_LIST_LEAVES, -1);

    recurse = (flags & VIR_DOMAIN_SNAPSHOT_LIST_DESCENDANTS) != 0;
    leaves = (flags & VIR_DOMAIN_SNAPSHOT_LIST_LEAVES) != 0;

    if (!names || nameslen < 0) {
        virReportError(VIR_ERR_INVALID_ARG, "%s", _("Invalid argument"));
        return -1;
    }

    if (nameslen == 0)
        return 0;

    if (esxVI_EnsureSession(priv->primary) < 0)
        return -1;

    if (esxVI_LookupRootSnapshotTreeList(priv->primary, snapshot->domain->uuid,
                                         &rootSnapshotTreeList) < 0 ||
        esxVI_GetSnapshotTreeByName(rootSnapshotTreeList, snapshot->name,
                                    &snapshotTree, NULL,
                                    esxVI_Occurrence_RequiredItem) < 0) {
        goto cleanup;
    }

    /* ESX snapshots do not require libvirt to maintain any metadata.  */
    if (flags & VIR_DOMAIN_SNAPSHOT_LIST_METADATA) {
        result = 0;
        goto cleanup;
    }

    result = esxVI_GetSnapshotTreeNames(snapshotTree->childSnapshotList,
                                        names, nameslen, recurse, leaves);

 cleanup:
    esxVI_VirtualMachineSnapshotTree_Free(&rootSnapshotTreeList);

    return result;
}



static virDomainSnapshotPtr
esxDomainSnapshotLookupByName(virDomainPtr domain, const char *name,
                              unsigned int flags)
{
    esxPrivate *priv = domain->conn->privateData;
    esxVI_VirtualMachineSnapshotTree *rootSnapshotTreeList = NULL;
    esxVI_VirtualMachineSnapshotTree *snapshotTree = NULL;
    virDomainSnapshotPtr snapshot = NULL;

    virCheckFlags(0, NULL);

    if (esxVI_EnsureSession(priv->primary) < 0)
        return NULL;

    if (esxVI_LookupRootSnapshotTreeList(priv->primary, domain->uuid,
                                         &rootSnapshotTreeList) < 0 ||
        esxVI_GetSnapshotTreeByName(rootSnapshotTreeList, name, &snapshotTree,
                                    NULL,
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
    esxPrivate *priv = domain->conn->privateData;
    esxVI_VirtualMachineSnapshotTree *currentSnapshotTree = NULL;

    virCheckFlags(0, -1);

    if (esxVI_EnsureSession(priv->primary) < 0)
        return -1;

    if (esxVI_LookupCurrentSnapshotTree(priv->primary, domain->uuid,
                                        &currentSnapshotTree,
                                        esxVI_Occurrence_OptionalItem) < 0) {
        return -1;
    }

    if (currentSnapshotTree) {
        esxVI_VirtualMachineSnapshotTree_Free(&currentSnapshotTree);
        return 1;
    }

    return 0;
}



static virDomainSnapshotPtr
esxDomainSnapshotGetParent(virDomainSnapshotPtr snapshot, unsigned int flags)
{
    esxPrivate *priv = snapshot->domain->conn->privateData;
    esxVI_VirtualMachineSnapshotTree *rootSnapshotList = NULL;
    esxVI_VirtualMachineSnapshotTree *snapshotTree = NULL;
    esxVI_VirtualMachineSnapshotTree *snapshotTreeParent = NULL;
    virDomainSnapshotPtr parent = NULL;

    virCheckFlags(0, NULL);

    if (esxVI_EnsureSession(priv->primary) < 0)
        return NULL;

    if (esxVI_LookupRootSnapshotTreeList(priv->primary, snapshot->domain->uuid,
                                         &rootSnapshotList) < 0 ||
        esxVI_GetSnapshotTreeByName(rootSnapshotList, snapshot->name,
                                    &snapshotTree, &snapshotTreeParent,
                                    esxVI_Occurrence_RequiredItem) < 0) {
        goto cleanup;
    }

    if (!snapshotTreeParent) {
        virReportError(VIR_ERR_NO_DOMAIN_SNAPSHOT,
                       _("snapshot '%s' does not have a parent"),
                       snapshotTree->name);
        goto cleanup;
    }

    parent = virGetDomainSnapshot(snapshot->domain, snapshotTreeParent->name);

 cleanup:
    esxVI_VirtualMachineSnapshotTree_Free(&rootSnapshotList);

    return parent;
}



static virDomainSnapshotPtr
esxDomainSnapshotCurrent(virDomainPtr domain, unsigned int flags)
{
    esxPrivate *priv = domain->conn->privateData;
    esxVI_VirtualMachineSnapshotTree *currentSnapshotTree = NULL;
    virDomainSnapshotPtr snapshot = NULL;

    virCheckFlags(0, NULL);

    if (esxVI_EnsureSession(priv->primary) < 0)
        return NULL;

    if (esxVI_LookupCurrentSnapshotTree(priv->primary, domain->uuid,
                                        &currentSnapshotTree,
                                        esxVI_Occurrence_RequiredItem) < 0) {
        return NULL;
    }

    snapshot = virGetDomainSnapshot(domain, currentSnapshotTree->name);

    esxVI_VirtualMachineSnapshotTree_Free(&currentSnapshotTree);

    return snapshot;
}


static int
esxDomainSnapshotIsCurrent(virDomainSnapshotPtr snapshot, unsigned int flags)
{
    esxPrivate *priv = snapshot->domain->conn->privateData;
    esxVI_VirtualMachineSnapshotTree *currentSnapshotTree = NULL;
    esxVI_VirtualMachineSnapshotTree *rootSnapshotList = NULL;
    esxVI_VirtualMachineSnapshotTree *snapshotTree = NULL;
    int ret = -1;

    virCheckFlags(0, -1);

    if (esxVI_EnsureSession(priv->primary) < 0)
        return -1;

    /* Check that snapshot exists.  */
    if (esxVI_LookupRootSnapshotTreeList(priv->primary, snapshot->domain->uuid,
                                         &rootSnapshotList) < 0 ||
        esxVI_GetSnapshotTreeByName(rootSnapshotList, snapshot->name,
                                    &snapshotTree, NULL,
                                    esxVI_Occurrence_RequiredItem) < 0) {
        goto cleanup;
    }

    if (esxVI_LookupCurrentSnapshotTree(priv->primary, snapshot->domain->uuid,
                                        &currentSnapshotTree,
                                        esxVI_Occurrence_RequiredItem) < 0) {
        goto cleanup;
    }

    ret = STREQ(snapshot->name, currentSnapshotTree->name);

 cleanup:
    esxVI_VirtualMachineSnapshotTree_Free(&currentSnapshotTree);
    esxVI_VirtualMachineSnapshotTree_Free(&rootSnapshotList);
    return ret;
}


static int
esxDomainSnapshotHasMetadata(virDomainSnapshotPtr snapshot, unsigned int flags)
{
    esxPrivate *priv = snapshot->domain->conn->privateData;
    esxVI_VirtualMachineSnapshotTree *rootSnapshotList = NULL;
    esxVI_VirtualMachineSnapshotTree *snapshotTree = NULL;
    int ret = -1;

    virCheckFlags(0, -1);

    if (esxVI_EnsureSession(priv->primary) < 0)
        return -1;

    /* Check that snapshot exists.  If so, there is no metadata.  */
    if (esxVI_LookupRootSnapshotTreeList(priv->primary, snapshot->domain->uuid,
                                         &rootSnapshotList) < 0 ||
        esxVI_GetSnapshotTreeByName(rootSnapshotList, snapshot->name,
                                    &snapshotTree, NULL,
                                    esxVI_Occurrence_RequiredItem) < 0) {
        goto cleanup;
    }

    ret = 0;

 cleanup:
    esxVI_VirtualMachineSnapshotTree_Free(&rootSnapshotList);
    return ret;
}


static int
esxDomainRevertToSnapshot(virDomainSnapshotPtr snapshot, unsigned int flags)
{
    int result = -1;
    esxPrivate *priv = snapshot->domain->conn->privateData;
    esxVI_VirtualMachineSnapshotTree *rootSnapshotList = NULL;
    esxVI_VirtualMachineSnapshotTree *snapshotTree = NULL;
    esxVI_ManagedObjectReference *task = NULL;
    esxVI_TaskInfoState taskInfoState;
    char *taskInfoErrorMessage = NULL;

    virCheckFlags(0, -1);

    if (esxVI_EnsureSession(priv->primary) < 0)
        return -1;

    if (esxVI_LookupRootSnapshotTreeList(priv->primary, snapshot->domain->uuid,
                                         &rootSnapshotList) < 0 ||
        esxVI_GetSnapshotTreeByName(rootSnapshotList, snapshot->name,
                                    &snapshotTree, NULL,
                                    esxVI_Occurrence_RequiredItem) < 0) {
        goto cleanup;
    }

    if (esxVI_RevertToSnapshot_Task(priv->primary, snapshotTree->snapshot, NULL,
                                    esxVI_Boolean_Undefined, &task) < 0 ||
        esxVI_WaitForTaskCompletion(priv->primary, task, snapshot->domain->uuid,
                                    esxVI_Occurrence_RequiredItem,
                                    priv->parsedUri->autoAnswer, &taskInfoState,
                                    &taskInfoErrorMessage) < 0) {
        goto cleanup;
    }

    if (taskInfoState != esxVI_TaskInfoState_Success) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not revert to snapshot '%s': %s"), snapshot->name,
                       taskInfoErrorMessage);
        goto cleanup;
    }

    result = 0;

 cleanup:
    esxVI_VirtualMachineSnapshotTree_Free(&rootSnapshotList);
    esxVI_ManagedObjectReference_Free(&task);
    VIR_FREE(taskInfoErrorMessage);

    return result;
}



static int
esxDomainSnapshotDelete(virDomainSnapshotPtr snapshot, unsigned int flags)
{
    int result = -1;
    esxPrivate *priv = snapshot->domain->conn->privateData;
    esxVI_VirtualMachineSnapshotTree *rootSnapshotList = NULL;
    esxVI_VirtualMachineSnapshotTree *snapshotTree = NULL;
    esxVI_Boolean removeChildren = esxVI_Boolean_False;
    esxVI_ManagedObjectReference *task = NULL;
    esxVI_TaskInfoState taskInfoState;
    char *taskInfoErrorMessage = NULL;

    virCheckFlags(VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN |
                  VIR_DOMAIN_SNAPSHOT_DELETE_METADATA_ONLY, -1);

    if (esxVI_EnsureSession(priv->primary) < 0)
        return -1;

    if (flags & VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN)
        removeChildren = esxVI_Boolean_True;

    if (esxVI_LookupRootSnapshotTreeList(priv->primary, snapshot->domain->uuid,
                                         &rootSnapshotList) < 0 ||
        esxVI_GetSnapshotTreeByName(rootSnapshotList, snapshot->name,
                                    &snapshotTree, NULL,
                                    esxVI_Occurrence_RequiredItem) < 0) {
        goto cleanup;
    }

    /* ESX snapshots do not require any libvirt metadata, making this
     * flag trivial once we know we have a valid snapshot.  */
    if (flags & VIR_DOMAIN_SNAPSHOT_DELETE_METADATA_ONLY) {
        result = 0;
        goto cleanup;
    }

    if (esxVI_RemoveSnapshot_Task(priv->primary, snapshotTree->snapshot,
                                  removeChildren, &task) < 0 ||
        esxVI_WaitForTaskCompletion(priv->primary, task, snapshot->domain->uuid,
                                    esxVI_Occurrence_RequiredItem,
                                    priv->parsedUri->autoAnswer, &taskInfoState,
                                    &taskInfoErrorMessage) < 0) {
        goto cleanup;
    }

    if (taskInfoState != esxVI_TaskInfoState_Success) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not delete snapshot '%s': %s"), snapshot->name,
                       taskInfoErrorMessage);
        goto cleanup;
    }

    result = 0;

 cleanup:
    esxVI_VirtualMachineSnapshotTree_Free(&rootSnapshotList);
    esxVI_ManagedObjectReference_Free(&task);
    VIR_FREE(taskInfoErrorMessage);

    return result;
}



static int
esxDomainSetMemoryParameters(virDomainPtr domain, virTypedParameterPtr params,
                             int nparams, unsigned int flags)
{
    int result = -1;
    esxPrivate *priv = domain->conn->privateData;
    esxVI_ObjectContent *virtualMachine = NULL;
    esxVI_VirtualMachineConfigSpec *spec = NULL;
    esxVI_ManagedObjectReference *task = NULL;
    esxVI_TaskInfoState taskInfoState;
    char *taskInfoErrorMessage = NULL;
    size_t i;

    virCheckFlags(0, -1);
    if (virTypedParamsValidate(params, nparams,
                               VIR_DOMAIN_MEMORY_MIN_GUARANTEE,
                               VIR_TYPED_PARAM_ULLONG,
                               NULL) < 0)
        return -1;

    if (esxVI_EnsureSession(priv->primary) < 0)
        return -1;

    if (esxVI_LookupVirtualMachineByUuidAndPrepareForTask
          (priv->primary, domain->uuid, NULL, &virtualMachine,
           priv->parsedUri->autoAnswer) < 0 ||
        esxVI_VirtualMachineConfigSpec_Alloc(&spec) < 0 ||
        esxVI_ResourceAllocationInfo_Alloc(&spec->memoryAllocation) < 0) {
        goto cleanup;
    }

    for (i = 0; i < nparams; ++i) {
        if (STREQ(params[i].field, VIR_DOMAIN_MEMORY_MIN_GUARANTEE)) {
            if (esxVI_Long_Alloc(&spec->memoryAllocation->reservation) < 0)
                goto cleanup;

            spec->memoryAllocation->reservation->value =
              VIR_DIV_UP(params[i].value.ul, 1024); /* Scale from kilobytes to megabytes */
        }
    }

    if (esxVI_ReconfigVM_Task(priv->primary, virtualMachine->obj, spec,
                              &task) < 0 ||
        esxVI_WaitForTaskCompletion(priv->primary, task, domain->uuid,
                                    esxVI_Occurrence_RequiredItem,
                                    priv->parsedUri->autoAnswer, &taskInfoState,
                                    &taskInfoErrorMessage) < 0) {
        goto cleanup;
    }

    if (taskInfoState != esxVI_TaskInfoState_Success) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not change memory parameters: %s"),
                       taskInfoErrorMessage);
        goto cleanup;
    }

    result = 0;

 cleanup:
    esxVI_ObjectContent_Free(&virtualMachine);
    esxVI_VirtualMachineConfigSpec_Free(&spec);
    esxVI_ManagedObjectReference_Free(&task);
    VIR_FREE(taskInfoErrorMessage);

    return result;
}



static int
esxDomainGetMemoryParameters(virDomainPtr domain, virTypedParameterPtr params,
                             int *nparams, unsigned int flags)
{
    int result = -1;
    esxPrivate *priv = domain->conn->privateData;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *virtualMachine = NULL;
    esxVI_Long *reservation = NULL;

    virCheckFlags(0, -1);

    if (*nparams == 0) {
        *nparams = 1; /* min_guarantee */
        return 0;
    }

    if (esxVI_EnsureSession(priv->primary) < 0)
        return -1;

    if (esxVI_String_AppendValueToList
          (&propertyNameList, "config.memoryAllocation.reservation") < 0 ||
        esxVI_LookupVirtualMachineByUuid(priv->primary, domain->uuid,
                                         propertyNameList, &virtualMachine,
                                         esxVI_Occurrence_RequiredItem) < 0 ||
        esxVI_GetLong(virtualMachine, "config.memoryAllocation.reservation",
                      &reservation, esxVI_Occurrence_RequiredItem) < 0) {
        goto cleanup;
    }

    /* Scale from megabytes to kilobytes */
    if (virTypedParameterAssign(params, VIR_DOMAIN_MEMORY_MIN_GUARANTEE,
                                VIR_TYPED_PARAM_ULLONG,
                                reservation->value * 1024) < 0)
        goto cleanup;

    *nparams = 1;
    result = 0;

 cleanup:
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&virtualMachine);
    esxVI_Long_Free(&reservation);

    return result;
}

#define MATCH(FLAG) (flags & (FLAG))
static int
esxConnectListAllDomains(virConnectPtr conn,
                         virDomainPtr **domains,
                         unsigned int flags)
{
    int ret = -1;
    esxPrivate *priv = conn->privateData;
    bool needIdentity;
    bool needPowerState;
    virDomainPtr dom;
    virDomainPtr *doms = NULL;
    size_t ndoms = 0;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *virtualMachineList = NULL;
    esxVI_ObjectContent *virtualMachine = NULL;
    esxVI_AutoStartDefaults *autoStartDefaults = NULL;
    esxVI_VirtualMachinePowerState powerState;
    esxVI_AutoStartPowerInfo *powerInfoList = NULL;
    esxVI_AutoStartPowerInfo *powerInfo = NULL;
    esxVI_VirtualMachineSnapshotTree *rootSnapshotTreeList = NULL;
    char *name = NULL;
    int id;
    unsigned char uuid[VIR_UUID_BUFLEN];
    int count = 0;
    bool autostart;
    int state;
    esxVI_DynamicProperty *dynamicProperty = NULL;

    virCheckFlags(VIR_CONNECT_LIST_DOMAINS_FILTERS_ALL, -1);

    /* check for flags that would produce empty output lists:
     * - persistence: all esx machines are persistent
     * - managed save: esx doesn't support managed save
     */
    if ((MATCH(VIR_CONNECT_LIST_DOMAINS_TRANSIENT) &&
         !MATCH(VIR_CONNECT_LIST_DOMAINS_PERSISTENT)) ||
        (MATCH(VIR_CONNECT_LIST_DOMAINS_MANAGEDSAVE) &&
         !MATCH(VIR_CONNECT_LIST_DOMAINS_NO_MANAGEDSAVE))) {
        if (domains &&
            VIR_ALLOC_N(*domains, 1) < 0)
            goto cleanup;

        ret = 0;
        goto cleanup;
    }

    if (esxVI_EnsureSession(priv->primary) < 0)
        return -1;

    /* check system default autostart value */
    if (MATCH(VIR_CONNECT_LIST_DOMAINS_FILTERS_AUTOSTART)) {
        if (esxVI_LookupAutoStartDefaults(priv->primary,
                                          &autoStartDefaults) < 0) {
            goto cleanup;
        }

        if (autoStartDefaults->enabled == esxVI_Boolean_True) {
            if (esxVI_LookupAutoStartPowerInfoList(priv->primary,
                                                   &powerInfoList) < 0) {
                goto cleanup;
            }
        }
    }

    needIdentity = MATCH(VIR_CONNECT_LIST_DOMAINS_FILTERS_SNAPSHOT) ||
                   domains;

    if (needIdentity) {
        /* Request required data for esxVI_GetVirtualMachineIdentity */
        if (esxVI_String_AppendValueListToList(&propertyNameList,
                                               "configStatus\0"
                                               "name\0"
                                               "config.uuid\0") < 0) {
            goto cleanup;
        }
    }

    needPowerState = MATCH(VIR_CONNECT_LIST_DOMAINS_FILTERS_ACTIVE) ||
                     MATCH(VIR_CONNECT_LIST_DOMAINS_FILTERS_STATE) ||
                     domains;

    if (needPowerState) {
        if (esxVI_String_AppendValueToList(&propertyNameList,
                                           "runtime.powerState") < 0) {
            goto cleanup;
        }
    }

    if (MATCH(VIR_CONNECT_LIST_DOMAINS_FILTERS_SNAPSHOT)) {
        if (esxVI_String_AppendValueToList(&propertyNameList,
                                           "snapshot.rootSnapshotList") < 0) {
            goto cleanup;
        }
    }

    if (esxVI_LookupVirtualMachineList(priv->primary, propertyNameList,
                                       &virtualMachineList) < 0)
        goto cleanup;

    if (domains) {
        if (VIR_ALLOC_N(doms, 1) < 0)
            goto cleanup;
        ndoms = 1;
    }

    for (virtualMachine = virtualMachineList; virtualMachine;
         virtualMachine = virtualMachine->_next) {
        if (needIdentity) {
            VIR_FREE(name);

            if (esxVI_GetVirtualMachineIdentity(virtualMachine, &id,
                                                &name, uuid) < 0) {
                goto cleanup;
            }
        }

        if (needPowerState) {
            if (esxVI_GetVirtualMachinePowerState(virtualMachine,
                                                  &powerState) < 0) {
                goto cleanup;
            }
        }

        /* filter by active state */
        if (MATCH(VIR_CONNECT_LIST_DOMAINS_FILTERS_ACTIVE) &&
            !((MATCH(VIR_CONNECT_LIST_DOMAINS_ACTIVE) &&
               powerState != esxVI_VirtualMachinePowerState_PoweredOff) ||
              (MATCH(VIR_CONNECT_LIST_DOMAINS_INACTIVE) &&
               powerState == esxVI_VirtualMachinePowerState_PoweredOff)))
            continue;

        /* filter by snapshot existence */
        if (MATCH(VIR_CONNECT_LIST_DOMAINS_FILTERS_SNAPSHOT)) {

            esxVI_VirtualMachineSnapshotTree_Free(&rootSnapshotTreeList);

            for (dynamicProperty = virtualMachine->propSet; dynamicProperty;
                dynamicProperty = dynamicProperty->_next) {
                if (STREQ(dynamicProperty->name, "snapshot.rootSnapshotList")) {
                    if (esxVI_VirtualMachineSnapshotTree_CastListFromAnyType
                        (dynamicProperty->val, &rootSnapshotTreeList) < 0) {
                        goto cleanup;
                    }

                    break;
                }
            }

            if (!((MATCH(VIR_CONNECT_LIST_DOMAINS_HAS_SNAPSHOT) &&
                   rootSnapshotTreeList) ||
                  (MATCH(VIR_CONNECT_LIST_DOMAINS_NO_SNAPSHOT) &&
                   !rootSnapshotTreeList)))
                continue;
        }

        /* filter by autostart */
        if (MATCH(VIR_CONNECT_LIST_DOMAINS_FILTERS_AUTOSTART)) {
            autostart = false;

            if (autoStartDefaults->enabled == esxVI_Boolean_True) {
                for (powerInfo = powerInfoList; powerInfo;
                     powerInfo = powerInfo->_next) {
                    if (STREQ(powerInfo->key->value, virtualMachine->obj->value)) {
                        if (STRCASEEQ(powerInfo->startAction, "powerOn"))
                            autostart = true;

                        break;
                    }
                }
            }

            if (!((MATCH(VIR_CONNECT_LIST_DOMAINS_AUTOSTART) &&
                   autostart) ||
                  (MATCH(VIR_CONNECT_LIST_DOMAINS_NO_AUTOSTART) &&
                   !autostart)))
                continue;
        }

        /* filter by domain state */
        if (MATCH(VIR_CONNECT_LIST_DOMAINS_FILTERS_STATE)) {
            state = esxVI_VirtualMachinePowerState_ConvertToLibvirt(powerState);

            if (!((MATCH(VIR_CONNECT_LIST_DOMAINS_RUNNING) &&
                   state == VIR_DOMAIN_RUNNING) ||
                  (MATCH(VIR_CONNECT_LIST_DOMAINS_PAUSED) &&
                   state == VIR_DOMAIN_PAUSED) ||
                  (MATCH(VIR_CONNECT_LIST_DOMAINS_SHUTOFF) &&
                   state == VIR_DOMAIN_SHUTOFF) ||
                  (MATCH(VIR_CONNECT_LIST_DOMAINS_OTHER) &&
                   (state != VIR_DOMAIN_RUNNING &&
                    state != VIR_DOMAIN_PAUSED &&
                    state != VIR_DOMAIN_SHUTOFF))))
                continue;
        }

        /* just count the machines */
        if (!doms) {
            count++;
            continue;
        }

        if (VIR_RESIZE_N(doms, ndoms, count, 2) < 0)
            goto cleanup;

        /* Only running/suspended virtual machines have an ID != -1 */
        if (powerState == esxVI_VirtualMachinePowerState_PoweredOff)
            id = -1;

        if (!(dom = virGetDomain(conn, name, uuid, id)))
            goto cleanup;

        doms[count++] = dom;
    }

    if (doms)
        *domains = doms;
    doms = NULL;
    ret = count;

 cleanup:
    if (doms) {
        for (id = 0; id < count; id++)
            virObjectUnref(doms[id]);

        VIR_FREE(doms);
    }

    VIR_FREE(name);
    esxVI_AutoStartDefaults_Free(&autoStartDefaults);
    esxVI_AutoStartPowerInfo_Free(&powerInfoList);
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&virtualMachineList);
    esxVI_VirtualMachineSnapshotTree_Free(&rootSnapshotTreeList);

    return ret;
}
#undef MATCH

static int
esxDomainHasManagedSaveImage(virDomainPtr domain, unsigned int flags)
{
    int result = -1;
    esxPrivate *priv = domain->conn->privateData;
    esxVI_ManagedObjectReference *managedObjectReference = NULL;
    char uuid_string[VIR_UUID_STRING_BUFLEN] = "";

    virCheckFlags(0, -1);

    if (esxVI_EnsureSession(priv->primary) < 0)
        return -1;

    virUUIDFormat(domain->uuid, uuid_string);

    if (esxVI_FindByUuid(priv->primary, priv->primary->datacenter->_reference,
                         uuid_string, esxVI_Boolean_True,
                         esxVI_Boolean_Undefined,
                         &managedObjectReference) < 0) {
        return -1;
    }

    if (!managedObjectReference) {
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("Could not find domain with UUID '%s'"),
                       uuid_string);
        goto cleanup;
    }

    result = 0;

 cleanup:
    esxVI_ManagedObjectReference_Free(&managedObjectReference);
    return result;
}


static virHypervisorDriver esxHypervisorDriver = {
    .name = "ESX",
    .connectOpen = esxConnectOpen, /* 0.7.0 */
    .connectClose = esxConnectClose, /* 0.7.0 */
    .connectSupportsFeature = esxConnectSupportsFeature, /* 0.7.0 */
    .connectGetType = esxConnectGetType, /* 0.7.0 */
    .connectGetVersion = esxConnectGetVersion, /* 0.7.0 */
    .connectGetHostname = esxConnectGetHostname, /* 0.7.0 */
    .nodeGetInfo = esxNodeGetInfo, /* 0.7.0 */
    .connectGetCapabilities = esxConnectGetCapabilities, /* 0.7.1 */
    .connectListDomains = esxConnectListDomains, /* 0.7.0 */
    .connectNumOfDomains = esxConnectNumOfDomains, /* 0.7.0 */
    .connectListAllDomains = esxConnectListAllDomains, /* 0.10.2 */
    .domainLookupByID = esxDomainLookupByID, /* 0.7.0 */
    .domainLookupByUUID = esxDomainLookupByUUID, /* 0.7.0 */
    .domainLookupByName = esxDomainLookupByName, /* 0.7.0 */
    .domainSuspend = esxDomainSuspend, /* 0.7.0 */
    .domainResume = esxDomainResume, /* 0.7.0 */
    .domainShutdown = esxDomainShutdown, /* 0.7.0 */
    .domainShutdownFlags = esxDomainShutdownFlags, /* 0.9.10 */
    .domainReboot = esxDomainReboot, /* 0.7.0 */
    .domainDestroy = esxDomainDestroy, /* 0.7.0 */
    .domainDestroyFlags = esxDomainDestroyFlags, /* 0.9.4 */
    .domainGetOSType = esxDomainGetOSType, /* 0.7.0 */
    .domainGetMaxMemory = esxDomainGetMaxMemory, /* 0.7.0 */
    .domainSetMaxMemory = esxDomainSetMaxMemory, /* 0.7.0 */
    .domainSetMemory = esxDomainSetMemory, /* 0.7.0 */
    .domainSetMemoryParameters = esxDomainSetMemoryParameters, /* 0.8.6 */
    .domainGetMemoryParameters = esxDomainGetMemoryParameters, /* 0.8.6 */
    .domainGetInfo = esxDomainGetInfo, /* 0.7.0 */
    .domainGetState = esxDomainGetState, /* 0.9.2 */
    .domainScreenshot = esxDomainScreenshot, /* 1.2.10 */
    .domainSetVcpus = esxDomainSetVcpus, /* 0.7.0 */
    .domainSetVcpusFlags = esxDomainSetVcpusFlags, /* 0.8.5 */
    .domainGetVcpusFlags = esxDomainGetVcpusFlags, /* 0.8.5 */
    .domainGetMaxVcpus = esxDomainGetMaxVcpus, /* 0.7.0 */
    .domainGetXMLDesc = esxDomainGetXMLDesc, /* 0.7.0 */
    .connectDomainXMLFromNative = esxConnectDomainXMLFromNative, /* 0.7.0 */
    .connectDomainXMLToNative = esxConnectDomainXMLToNative, /* 0.7.2 */
    .connectListDefinedDomains = esxConnectListDefinedDomains, /* 0.7.0 */
    .connectNumOfDefinedDomains = esxConnectNumOfDefinedDomains, /* 0.7.0 */
    .domainCreate = esxDomainCreate, /* 0.7.0 */
    .domainCreateWithFlags = esxDomainCreateWithFlags, /* 0.8.2 */
    .domainDefineXML = esxDomainDefineXML, /* 0.7.2 */
    .domainDefineXMLFlags = esxDomainDefineXMLFlags, /* 1.2.12 */
    .domainUndefine = esxDomainUndefine, /* 0.7.1 */
    .domainUndefineFlags = esxDomainUndefineFlags, /* 0.9.4 */
    .domainGetAutostart = esxDomainGetAutostart, /* 0.9.0 */
    .domainSetAutostart = esxDomainSetAutostart, /* 0.9.0 */
    .domainGetSchedulerType = esxDomainGetSchedulerType, /* 0.7.0 */
    .domainGetSchedulerParameters = esxDomainGetSchedulerParameters, /* 0.7.0 */
    .domainGetSchedulerParametersFlags = esxDomainGetSchedulerParametersFlags, /* 0.9.2 */
    .domainSetSchedulerParameters = esxDomainSetSchedulerParameters, /* 0.7.0 */
    .domainSetSchedulerParametersFlags = esxDomainSetSchedulerParametersFlags, /* 0.9.2 */
    .domainMigratePrepare = esxDomainMigratePrepare, /* 0.7.0 */
    .domainMigratePerform = esxDomainMigratePerform, /* 0.7.0 */
    .domainMigrateFinish = esxDomainMigrateFinish, /* 0.7.0 */
    .nodeGetFreeMemory = esxNodeGetFreeMemory, /* 0.7.2 */
    .connectIsEncrypted = esxConnectIsEncrypted, /* 0.7.3 */
    .connectIsSecure = esxConnectIsSecure, /* 0.7.3 */
    .domainIsActive = esxDomainIsActive, /* 0.7.3 */
    .domainIsPersistent = esxDomainIsPersistent, /* 0.7.3 */
    .domainIsUpdated = esxDomainIsUpdated, /* 0.8.6 */
    .domainSnapshotCreateXML = esxDomainSnapshotCreateXML, /* 0.8.0 */
    .domainSnapshotGetXMLDesc = esxDomainSnapshotGetXMLDesc, /* 0.8.0 */
    .domainSnapshotNum = esxDomainSnapshotNum, /* 0.8.0 */
    .domainSnapshotListNames = esxDomainSnapshotListNames, /* 0.8.0 */
    .domainSnapshotNumChildren = esxDomainSnapshotNumChildren, /* 0.9.7 */
    .domainSnapshotListChildrenNames = esxDomainSnapshotListChildrenNames, /* 0.9.7 */
    .domainSnapshotLookupByName = esxDomainSnapshotLookupByName, /* 0.8.0 */
    .domainHasCurrentSnapshot = esxDomainHasCurrentSnapshot, /* 0.8.0 */
    .domainSnapshotGetParent = esxDomainSnapshotGetParent, /* 0.9.7 */
    .domainSnapshotCurrent = esxDomainSnapshotCurrent, /* 0.8.0 */
    .domainRevertToSnapshot = esxDomainRevertToSnapshot, /* 0.8.0 */
    .domainSnapshotIsCurrent = esxDomainSnapshotIsCurrent, /* 0.9.13 */
    .domainSnapshotHasMetadata = esxDomainSnapshotHasMetadata, /* 0.9.13 */
    .domainSnapshotDelete = esxDomainSnapshotDelete, /* 0.8.0 */
    .connectIsAlive = esxConnectIsAlive, /* 0.9.8 */
    .domainHasManagedSaveImage = esxDomainHasManagedSaveImage, /* 1.2.13 */
};


static virConnectDriver esxConnectDriver = {
    .hypervisorDriver = &esxHypervisorDriver,
    .interfaceDriver = &esxInterfaceDriver,
    .networkDriver = &esxNetworkDriver,
    .storageDriver = &esxStorageDriver,
};

int
esxRegister(void)
{
    return virRegisterConnectDriver(&esxConnectDriver,
                                    false);
}
