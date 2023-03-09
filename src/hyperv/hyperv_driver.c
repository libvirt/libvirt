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

#include <fcntl.h>

#include "internal.h"
#include "datatypes.h"
#include "virdomainobjlist.h"
#include "virauth.h"
#include "viralloc.h"
#include "virlog.h"
#include "viruuid.h"
#include "virutil.h"
#include "hyperv_driver.h"
#include "hyperv_network_driver.h"
#include "hyperv_private.h"
#include "hyperv_util.h"
#include "hyperv_wmi.h"
#include "virstring.h"
#include "virkeycode.h"
#include "domain_conf.h"
#include "virfdstream.h"
#include "virfile.h"

#define VIR_FROM_THIS VIR_FROM_HYPERV

VIR_LOG_INIT("hyperv.hyperv_driver");

/*
 * WMI utility functions
 *
 * wrapper functions for commonly-accessed WMI objects and interfaces.
 */

static int
hypervGetProcessorsByName(hypervPrivate *priv, const char *name,
                          Win32_Processor **processorList)
{
    g_auto(virBuffer) query = VIR_BUFFER_INITIALIZER;
    virBufferEscapeSQL(&query,
                       "ASSOCIATORS OF {Win32_ComputerSystem.Name='%s'} "
                       "WHERE AssocClass = Win32_ComputerSystemProcessor "
                       "ResultClass = Win32_Processor",
                       name);

    if (hypervGetWmiClass(Win32_Processor, processorList) < 0)
        return -1;

    if (!processorList) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not look up processor(s) on '%1$s'"),
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
        virReportError(VIR_ERR_NO_DOMAIN, _("No domain with ID %1$d"), id);
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
                       "AND ElementName = '%s'",
                       name);

    if (hypervGetWmiClass(Msvm_ComputerSystem, computerSystemList) < 0)
        return -1;

    if (*computerSystemList == NULL) {
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("No domain with name %1$s"), name);
        return -1;
    }

    return 0;
}


static int
hypervGetOperatingSystem(hypervPrivate *priv, Win32_OperatingSystem **operatingSystem)
{
    g_auto(virBuffer) query = { g_string_new(WIN32_OPERATINGSYSTEM_WQL_SELECT), 0 };

    if (hypervGetWmiClass(Win32_OperatingSystem, operatingSystem) < 0)
        return -1;

    return 0;
}


static int
hypervRequestStateChange(virDomainPtr domain, int state)
{
    g_autoptr(Msvm_ComputerSystem) computerSystem = NULL;

    if (hypervMsvmComputerSystemFromDomain(domain, &computerSystem) < 0)
        return -1;

    if (computerSystem->data->EnabledState != MSVM_COMPUTERSYSTEM_ENABLEDSTATE_ENABLED) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s", _("Domain is not active"));
        return -1;
    }

    return hypervInvokeMsvmComputerSystemRequestStateChange(domain, state);
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
    g_autoptr(Win32_ComputerSystemProduct) computerSystem = NULL;
    g_auto(virBuffer) query = { g_string_new(WIN32_COMPUTERSYSTEMPRODUCT_WQL_SELECT), 0 };

    if (hypervGetWmiClass(Win32_ComputerSystemProduct, &computerSystem) < 0)
        return -1;

    if (virUUIDParse(computerSystem->data->UUID, uuid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not parse UUID from string '%1$s'"),
                       computerSystem->data->UUID);
        return -1;
    }

    return 0;
}


static virCaps *
hypervCapsInit(hypervPrivate *priv)
{
    g_autoptr(virCaps) caps = NULL;
    virCapsGuest *guest = NULL;

    caps = virCapabilitiesNew(VIR_ARCH_X86_64, 1, 1);

    if (!caps)
        return NULL;

    if (hypervLookupHostSystemBiosUuid(priv, caps->host.host_uuid) < 0)
        return NULL;

    /* i686 caps */
    guest = virCapabilitiesAddGuest(caps, VIR_DOMAIN_OSTYPE_HVM, VIR_ARCH_I686,
                                    NULL, NULL, 0, NULL);

    virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_HYPERV,
                                  NULL, NULL, 0, NULL);

    /* x86_64 caps */
    guest = virCapabilitiesAddGuest(caps, VIR_DOMAIN_OSTYPE_HVM, VIR_ARCH_X86_64,
                                    NULL, NULL, 0, NULL);

    virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_HYPERV,
                                  NULL, NULL, 0, NULL);

    return g_steal_pointer(&caps);
}


static int
hypervGetVideoResolution(hypervPrivate *priv,
                         char *vm_uuid,
                         int *xRes,
                         int *yRes,
                         bool fallback)
{
    g_auto(virBuffer) query = VIR_BUFFER_INITIALIZER;
    g_autoptr(Msvm_S3DisplayController) s3Display = NULL;
    g_autoptr(Msvm_SyntheticDisplayController) synthetic = NULL;
    g_autoptr(Msvm_VideoHead) heads = NULL;
    const char *wmiClass = NULL;
    char *deviceId = NULL;
    g_autofree char *enabledStateString = NULL;

    if (fallback) {
        wmiClass = "Msvm_S3DisplayController";

        virBufferEscapeSQL(&query,
                           MSVM_S3DISPLAYCONTROLLER_WQL_SELECT "WHERE SystemName = '%s'",
                           vm_uuid);

        if (hypervGetWmiClass(Msvm_S3DisplayController, &s3Display) < 0 || !s3Display)
            return -1;

        deviceId = s3Display->data->DeviceID;
    } else {
        wmiClass = "Msvm_SyntheticDisplayController";

        virBufferEscapeSQL(&query,
                           MSVM_SYNTHETICDISPLAYCONTROLLER_WQL_SELECT "WHERE SystemName = '%s'",
                           vm_uuid);

        if (hypervGetWmiClass(Msvm_SyntheticDisplayController, &synthetic) < 0 || !synthetic)
            return -1;

        deviceId = synthetic->data->DeviceID;
    }

    virBufferFreeAndReset(&query);

    virBufferAsprintf(&query,
                      "ASSOCIATORS OF {%s."
                      "CreationClassName='%s',"
                      "DeviceID='%s',"
                      "SystemCreationClassName='Msvm_ComputerSystem',"
                      "SystemName='%s'"
                      "} WHERE AssocClass = Msvm_VideoHeadOnController "
                      "ResultClass = Msvm_VideoHead",
                      wmiClass, wmiClass, deviceId, vm_uuid);

    if (hypervGetWmiClass(Msvm_VideoHead, &heads) < 0)
        return -1;

    enabledStateString = g_strdup_printf("%d", CIM_ENABLEDLOGICALELEMENT_ENABLEDSTATE_ENABLED);
    if (heads && STREQ(heads->data->EnabledState, enabledStateString)) {
        *xRes = heads->data->CurrentHorizontalResolution;
        *yRes = heads->data->CurrentVerticalResolution;

        return 0;
    }

    return -1;
}


/*
 * Virtual device functions
 */
static int
hypervGetDeviceParentRasdFromDeviceId(const char *parentDeviceId,
                                      Msvm_ResourceAllocationSettingData *list,
                                      Msvm_ResourceAllocationSettingData **out)
{
    Msvm_ResourceAllocationSettingData *entry = list;
    *out = NULL;

    while (entry) {
        g_autofree char *escapedDeviceId = virStringReplace(entry->data->InstanceID, "\\", "\\\\");
        g_autofree char *expectedSuffix = g_strdup_printf("%s\"", escapedDeviceId);

        if (g_str_has_suffix(parentDeviceId, expectedSuffix)) {
            *out = entry;
            break;
        }

        entry = entry->next;
    }

    if (*out)
        return 0;

    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("Failed to locate parent device with ID '%1$s'"),
                   parentDeviceId);

    return -1;
}


static char *
hypervGetInstanceIDFromXMLResponse(WsXmlDocH response)
{
    WsXmlNodeH envelope = NULL;
    char *instanceId = NULL;

    envelope = ws_xml_get_soap_envelope(response);
    if (!envelope) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid XML response"));
        return NULL;
    }

    instanceId = ws_xml_get_xpath_value(response, (char *)"//w:Selector[@Name='InstanceID']");

    if (!instanceId) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not find selectors in method response"));
        return NULL;
    }

    return instanceId;
}


static int
hypervDomainCreateSCSIController(virDomainPtr domain, virDomainControllerDef *def)
{
    g_autoptr(GHashTable) scsiResource = NULL;
    g_autofree char *resourceType = NULL;

    if (def->model != VIR_DOMAIN_CONTROLLER_MODEL_SCSI_DEFAULT &&
        def->model != VIR_DOMAIN_CONTROLLER_MODEL_SCSI_AUTO) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unsupported SCSI controller model '%1$d'"), def->model);
        return -1;
    }

    if (def->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unsupported SCSI controller address type '%1$d'"), def->info.type);
        return -1;
    }

    resourceType = g_strdup_printf("%d", MSVM_RASD_RESOURCETYPE_PARALLEL_SCSI_HBA);

    VIR_DEBUG("Attaching SCSI Controller");

    /* prepare embedded param */
    scsiResource = hypervCreateEmbeddedParam(Msvm_ResourceAllocationSettingData_WmiInfo);
    if (!scsiResource)
        return -1;

    if (hypervSetEmbeddedProperty(scsiResource, "ResourceType", resourceType) < 0)
        return -1;

    if (hypervSetEmbeddedProperty(scsiResource, "ResourceSubType",
                                  "Microsoft:Hyper-V:Synthetic SCSI Controller") < 0)
        return -1;

    /* perform the settings change */
    if (hypervMsvmVSMSAddResourceSettings(domain, &scsiResource,
                                          Msvm_ResourceAllocationSettingData_WmiInfo, NULL) < 0)
        return -1;

    return 0;
}


static int
hypervDomainAddVirtualDiskParent(virDomainPtr domain,
                                 virDomainDiskDef *disk,
                                 Msvm_ResourceAllocationSettingData *controller,
                                 const char *hostname,
                                 WsXmlDocH *response)
{
    g_autoptr(GHashTable) controllerResource = NULL;
    g_autofree char *parentInstanceIDEscaped = NULL;
    g_autofree char *parent__PATH = NULL;
    g_autofree char *addressString = g_strdup_printf("%u", disk->info.addr.drive.unit);
    g_autofree char *resourceType = NULL;

    resourceType = g_strdup_printf("%d", MSVM_RASD_RESOURCETYPE_DISK_DRIVE);

    controllerResource = hypervCreateEmbeddedParam(Msvm_ResourceAllocationSettingData_WmiInfo);
    if (!controllerResource)
        return -1;

    parentInstanceIDEscaped = virStringReplace(controller->data->InstanceID, "\\", "\\\\");
    parent__PATH = g_strdup_printf("\\\\%s\\Root\\Virtualization\\V2:"
                                   "Msvm_ResourceAllocationSettingData.InstanceID=\"%s\"",
                                   hostname, parentInstanceIDEscaped);

    if (hypervSetEmbeddedProperty(controllerResource, "Parent", parent__PATH) < 0)
        return -1;

    if (hypervSetEmbeddedProperty(controllerResource, "AddressOnParent", addressString) < 0)
        return -1;

    if (hypervSetEmbeddedProperty(controllerResource, "ResourceType", resourceType) < 0)
        return -1;

    if (hypervSetEmbeddedProperty(controllerResource, "ResourceSubType",
                                  "Microsoft:Hyper-V:Synthetic Disk Drive") < 0)
        return -1;

    if (hypervMsvmVSMSAddResourceSettings(domain, &controllerResource,
                                          Msvm_ResourceAllocationSettingData_WmiInfo,
                                          response) < 0)
        return -1;

    return 0;
}


static int
hypervDomainAddVirtualHardDisk(virDomainPtr domain,
                               virDomainDiskDef *disk,
                               const char *hostname,
                               char *parentInstanceID)
{
    g_autoptr(GHashTable) volumeResource = NULL;
    g_autofree char *vhdInstanceIdEscaped = NULL;
    g_autofree char *vhd__PATH = NULL;
    g_autofree char *resourceType = NULL;

    resourceType = g_strdup_printf("%d", MSVM_RASD_RESOURCETYPE_LOGICAL_DISK);

    volumeResource = hypervCreateEmbeddedParam(Msvm_ResourceAllocationSettingData_WmiInfo);
    if (!volumeResource)
        return -1;

    vhdInstanceIdEscaped = virStringReplace(parentInstanceID, "\\", "\\\\");
    vhd__PATH = g_strdup_printf("\\\\%s\\Root\\Virtualization\\V2:"
                                "Msvm_ResourceAllocationSettingData.InstanceID=\"%s\"",
                                hostname, vhdInstanceIdEscaped);

    if (hypervSetEmbeddedProperty(volumeResource, "Parent", vhd__PATH) < 0)
        return -1;

    if (hypervSetEmbeddedProperty(volumeResource, "HostResource", disk->src->path) < 0)
        return -1;

    if (hypervSetEmbeddedProperty(volumeResource, "ResourceType", resourceType) < 0)
        return -1;

    if (hypervSetEmbeddedProperty(volumeResource, "ResourceSubType",
                                  "Microsoft:Hyper-V:Virtual Hard Disk") < 0)
        return -1;

    if (hypervMsvmVSMSAddResourceSettings(domain, &volumeResource,
                                          Msvm_ResourceAllocationSettingData_WmiInfo,
                                          NULL) < 0)
        return -1;

    return 0;
}


static int
hypervDomainAttachVirtualDisk(virDomainPtr domain,
                              virDomainDiskDef *disk,
                              Msvm_ResourceAllocationSettingData *controller,
                              const char *hostname)
{
    g_autofree char *parentInstanceID = NULL;
    g_auto(WsXmlDocH) response = NULL;

    VIR_DEBUG("Now attaching disk image '%s' with address %d to bus %d of type %d",
              disk->src->path, disk->info.addr.drive.unit, disk->info.addr.drive.controller, disk->bus);

    if (hypervDomainAddVirtualDiskParent(domain, disk, controller, hostname, &response) < 0)
        return -1;

    if (!response) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Could not add virtual disk parent"));
        return -1;
    }

    parentInstanceID = hypervGetInstanceIDFromXMLResponse(response);
    if (!parentInstanceID)
        return -1;

    if (hypervDomainAddVirtualHardDisk(domain, disk, hostname, parentInstanceID) < 0)
        return -1;

    return 0;
}


static int
hypervDomainAttachPhysicalDisk(virDomainPtr domain,
                               virDomainDiskDef *disk,
                               Msvm_ResourceAllocationSettingData *controller,
                               const char *hostname)
{
    hypervPrivate *priv = domain->conn->privateData;
    g_autofree char *hostResource = NULL;
    g_autofree char *controller__PATH = NULL;
    g_auto(GStrv) matches = NULL;
    ssize_t found = 0;
    g_auto(virBuffer) query = VIR_BUFFER_INITIALIZER;
    g_autoptr(Msvm_ResourceAllocationSettingData) diskdefault = NULL;
    g_autofree char *controllerInstanceIdEscaped = NULL;
    g_autoptr(GHashTable) diskResource = NULL;
    g_autofree char *addressString = g_strdup_printf("%u", disk->info.addr.drive.unit);
    g_autofree char *resourceType = NULL;

    resourceType = g_strdup_printf("%d", MSVM_RASD_RESOURCETYPE_DISK_DRIVE);

    if (strstr(disk->src->path, "NODRIVE")) {
        /* Hyper-V doesn't let you define LUNs with no connection */
        VIR_DEBUG("Skipping empty LUN '%s' with address %d on bus %d of type %d",
                  disk->src->path, disk->info.addr.drive.unit,
                  disk->info.addr.drive.controller, disk->bus);
        return 0;
    }

    VIR_DEBUG("Now attaching LUN '%s' with address %d to bus %d of type %d",
              disk->src->path, disk->info.addr.drive.unit,
              disk->info.addr.drive.controller, disk->bus);

    /* prepare HostResource */

    /* get Msvm_DiskDrive root device ID */
    virBufferAddLit(&query,
                    MSVM_RESOURCEALLOCATIONSETTINGDATA_WQL_SELECT
                    "WHERE ResourceSubType = 'Microsoft:Hyper-V:Physical Disk Drive' "
                    "AND InstanceID LIKE '%%Default%%'");

    if (hypervGetWmiClass(Msvm_ResourceAllocationSettingData, &diskdefault) < 0)
        return -1;

    if (!diskdefault) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not retrieve default Msvm_DiskDrive object"));
        return -1;
    }

    found = virStringSearch(diskdefault->data->InstanceID,
                            "([a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12})",
                            1, &matches);

    if (found < 1) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not get Msvm_DiskDrive default InstanceID"));
        return -1;
    }

    hostResource = g_strdup_printf("\\\\%s\\Root\\Virtualization\\V2:"
                                   "Msvm_DiskDrive.CreationClassName=\"Msvm_DiskDrive\","
                                   "DeviceID=\"Microsoft:%s\\\\%s\","
                                   "SystemCreationClassName=\"Msvm_ComputerSystem\","
                                   "SystemName=\"%s\"",
                                   hostname, matches[0], disk->src->path, hostname);

    /* create embedded param */
    diskResource = hypervCreateEmbeddedParam(Msvm_ResourceAllocationSettingData_WmiInfo);
    if (!diskResource)
        return -1;

    controllerInstanceIdEscaped = virStringReplace(controller->data->InstanceID, "\\", "\\\\");
    controller__PATH = g_strdup_printf("\\\\%s\\Root\\Virtualization\\V2:"
                                       "Msvm_ResourceAllocationSettingData.InstanceID=\"%s\"",
                                       hostname, controllerInstanceIdEscaped);

    if (hypervSetEmbeddedProperty(diskResource, "Parent", controller__PATH) < 0)
        return -1;

    if (hypervSetEmbeddedProperty(diskResource, "AddressOnParent", addressString) < 0)
        return -1;

    if (hypervSetEmbeddedProperty(diskResource, "ResourceType", resourceType) < 0)
        return -1;

    if (hypervSetEmbeddedProperty(diskResource, "ResourceSubType",
                                  "Microsoft:Hyper-V:Physical Disk Drive") < 0)
        return -1;

    if (hypervSetEmbeddedProperty(diskResource, "HostResource", hostResource) < 0)
        return -1;

    if (hypervMsvmVSMSAddResourceSettings(domain, &diskResource,
                                          Msvm_ResourceAllocationSettingData_WmiInfo,
                                          NULL) < 0)
        return -1;

    return 0;
}


static int
hypervDomainAddOpticalDrive(virDomainPtr domain,
                            virDomainDiskDef *disk,
                            Msvm_ResourceAllocationSettingData *controller,
                            const char *hostname,
                            WsXmlDocH *response)
{
    g_autoptr(GHashTable) driveResource = NULL;
    g_autofree char *parentInstanceIDEscaped = NULL;
    g_autofree char *parent__PATH = NULL;
    g_autofree char *addressString = g_strdup_printf("%u", disk->info.addr.drive.unit);
    g_autofree char *resourceType = NULL;

    resourceType = g_strdup_printf("%d", MSVM_RASD_RESOURCETYPE_DVD_DRIVE);

    driveResource = hypervCreateEmbeddedParam(Msvm_ResourceAllocationSettingData_WmiInfo);
    if (!driveResource)
        return -1;

    parentInstanceIDEscaped = virStringReplace(controller->data->InstanceID, "\\", "\\\\");
    parent__PATH = g_strdup_printf("\\\\%s\\Root\\Virtualization\\V2:"
                                   "Msvm_ResourceAllocationSettingData.InstanceID=\"%s\"",
                                   hostname, parentInstanceIDEscaped);

    if (hypervSetEmbeddedProperty(driveResource, "Parent", parent__PATH) < 0)
        return -1;

    if (hypervSetEmbeddedProperty(driveResource, "AddressOnParent", addressString) < 0)
        return -1;

    if (hypervSetEmbeddedProperty(driveResource, "ResourceType", resourceType) < 0)
        return -1;

    if (hypervSetEmbeddedProperty(driveResource, "ResourceSubType",
                                  "Microsoft:Hyper-V:Synthetic DVD Drive") < 0)
        return -1;

    if (hypervMsvmVSMSAddResourceSettings(domain, &driveResource,
                                          Msvm_ResourceAllocationSettingData_WmiInfo, response) < 0)
        return -1;

    return 0;
}


static int
hypervDomainAddOpticalDisk(virDomainPtr domain,
                           virDomainDiskDef *disk,
                           const char *hostname,
                           char *driveInstanceID)
{
    g_autoptr(GHashTable) volumeResource = NULL;
    g_autofree char *vhdInstanceIdEscaped = NULL;
    g_autofree char *vhd__PATH = NULL;
    g_autofree char *resourceType = NULL;

    resourceType = g_strdup_printf("%d", MSVM_RASD_RESOURCETYPE_LOGICAL_DISK);

    volumeResource = hypervCreateEmbeddedParam(Msvm_ResourceAllocationSettingData_WmiInfo);
    if (!volumeResource)
        return -1;

    vhdInstanceIdEscaped = virStringReplace(driveInstanceID, "\\", "\\\\");
    vhd__PATH = g_strdup_printf("\\\\%s\\Root\\Virtualization\\V2:"
                                "Msvm_ResourceAllocationSettingData.InstanceID=\"%s\"",
                                hostname, vhdInstanceIdEscaped);

    if (hypervSetEmbeddedProperty(volumeResource, "Parent", vhd__PATH) < 0)
        return -1;

    if (hypervSetEmbeddedProperty(volumeResource, "HostResource", disk->src->path) < 0)
        return -1;

    if (hypervSetEmbeddedProperty(volumeResource, "ResourceType", resourceType) < 0)
        return -1;

    if (hypervSetEmbeddedProperty(volumeResource, "ResourceSubType",
                                  "Microsoft:Hyper-V:Virtual CD/DVD Disk") < 0)
        return -1;

    if (hypervMsvmVSMSAddResourceSettings(domain, &volumeResource,
                                          Msvm_ResourceAllocationSettingData_WmiInfo, NULL) < 0)
        return -1;

    return 0;
}


static int
hypervDomainAttachCDROM(virDomainPtr domain,
                        virDomainDiskDef *disk,
                        Msvm_ResourceAllocationSettingData *controller,
                        const char *hostname)
{
    g_auto(WsXmlDocH) response = NULL;
    g_autofree char *driveInstanceID = NULL;

    VIR_DEBUG("Now attaching CD/DVD '%s' with address %d to bus %d of type %d",
              disk->src->path, disk->info.addr.drive.unit,
              disk->info.addr.drive.controller, disk->bus);

    if (hypervDomainAddOpticalDrive(domain, disk, controller, hostname, &response) < 0)
        return -1;

    driveInstanceID = hypervGetInstanceIDFromXMLResponse(response);
    if (!driveInstanceID)
        return -1;

    if (hypervDomainAddOpticalDisk(domain, disk, hostname, driveInstanceID) < 0)
        return -1;

    return 0;
}


static int
hypervDomainAttachFloppy(virDomainPtr domain,
                         virDomainDiskDef *disk,
                         Msvm_ResourceAllocationSettingData *driveSettings,
                         const char *hostname)
{
    g_autoptr(GHashTable) volumeResource = NULL;
    g_autofree char *vhdInstanceIdEscaped = NULL;
    g_autofree char *vfd__PATH = NULL;
    g_autofree char *resourceType = NULL;

    resourceType = g_strdup_printf("%d", MSVM_RASD_RESOURCETYPE_LOGICAL_DISK);

    volumeResource = hypervCreateEmbeddedParam(Msvm_ResourceAllocationSettingData_WmiInfo);
    if (!volumeResource)
        return -1;

    vhdInstanceIdEscaped = virStringReplace(driveSettings->data->InstanceID, "\\", "\\\\");
    vfd__PATH = g_strdup_printf("\\\\%s\\Root\\Virtualization\\V2:"
                                "Msvm_ResourceAllocationSettingData.InstanceID=\"%s\"",
                                hostname, vhdInstanceIdEscaped);

    if (hypervSetEmbeddedProperty(volumeResource, "Parent", vfd__PATH) < 0)
        return -1;

    if (hypervSetEmbeddedProperty(volumeResource, "HostResource", disk->src->path) < 0)
        return -1;

    if (hypervSetEmbeddedProperty(volumeResource, "ResourceType", resourceType) < 0)
        return -1;

    if (hypervSetEmbeddedProperty(volumeResource, "ResourceSubType",
                                  "Microsoft:Hyper-V:Virtual Floppy Disk") < 0)
        return -1;

    if (hypervMsvmVSMSAddResourceSettings(domain, &volumeResource,
                                          Msvm_ResourceAllocationSettingData_WmiInfo,
                                          NULL) < 0)
        return -1;

    return 0;
}


static int
hypervDomainAttachStorageVolume(virDomainPtr domain,
                                virDomainDiskDef *disk,
                                Msvm_ResourceAllocationSettingData *controller,
                                const char *hostname)
{
    if (disk->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Unsupported disk address type"));
        return -1;
    }

    switch (disk->device) {
    case VIR_DOMAIN_DISK_DEVICE_DISK:
        if (disk->src->type == VIR_STORAGE_TYPE_FILE)
            return hypervDomainAttachVirtualDisk(domain, disk, controller, hostname);
        else if (disk->src->type == VIR_STORAGE_TYPE_BLOCK)
            return hypervDomainAttachPhysicalDisk(domain, disk, controller, hostname);
        else
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Unsupported disk type"));
        break;
    case VIR_DOMAIN_DISK_DEVICE_CDROM:
        return hypervDomainAttachCDROM(domain, disk, controller, hostname);
    case VIR_DOMAIN_DISK_DEVICE_FLOPPY:
        return hypervDomainAttachFloppy(domain, disk, controller, hostname);
    case VIR_DOMAIN_DISK_DEVICE_LUN:
    case VIR_DOMAIN_DISK_DEVICE_LAST:
    default:
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Unsupported disk bus"));
        break;
    }

    return -1;
}


static int
hypervDomainAttachStorage(virDomainPtr domain, virDomainDef *def, const char *hostname)
{
    hypervPrivate *priv = domain->conn->privateData;
    size_t i = 0;
    char uuid_string[VIR_UUID_STRING_BUFLEN];
    int num_scsi_controllers = 0;
    int ctrlr_idx = -1;
    g_autoptr(Msvm_VirtualSystemSettingData) vssd = NULL;
    g_autoptr(Msvm_ResourceAllocationSettingData) rasd = NULL;
    Msvm_ResourceAllocationSettingData *entry = NULL;
    Msvm_ResourceAllocationSettingData *ideChannels[HYPERV_MAX_IDE_CHANNELS];
    Msvm_ResourceAllocationSettingData *scsiControllers[HYPERV_MAX_SCSI_CONTROLLERS];
    Msvm_ResourceAllocationSettingData *floppySettings = NULL;

    /* start with attaching scsi controllers */
    for (i = 0; i < def->ncontrollers; i++) {
        if (def->controllers[i]->type != VIR_DOMAIN_CONTROLLER_TYPE_SCSI)
            continue;

        if (hypervDomainCreateSCSIController(domain, def->controllers[i]) < 0)
            return -1;
    }

    virUUIDFormat(domain->uuid, uuid_string);

    /* filter through all the rasd entries and isolate our controllers */
    if (hypervGetMsvmVirtualSystemSettingDataFromUUID(priv, uuid_string, &vssd) < 0)
        return -1;

    if (hypervGetResourceAllocationSD(priv, vssd->data->InstanceID, &rasd) < 0)
        return -1;

    entry = rasd;
    while (entry) {
        if (entry->data->ResourceType == MSVM_RASD_RESOURCETYPE_IDE_CONTROLLER)
            ideChannels[entry->data->Address[0] - '0'] = entry;
        else if (entry->data->ResourceType == MSVM_RASD_RESOURCETYPE_PARALLEL_SCSI_HBA)
            scsiControllers[num_scsi_controllers++] = entry;
        else if (entry->data->ResourceType == MSVM_RASD_RESOURCETYPE_DISKETTE_DRIVE)
            floppySettings = entry;

        entry = entry->next;
    }

    /* now we loop through and attach all the disks */
    for (i = 0; i < def->ndisks; i++) {
        switch (def->disks[i]->bus) {
        case VIR_DOMAIN_DISK_BUS_IDE:
            ctrlr_idx = def->disks[i]->info.addr.drive.bus;
            if (hypervDomainAttachStorageVolume(domain, def->disks[i],
                                                ideChannels[ctrlr_idx], hostname) < 0) {
                return -1;
            }
            break;
        case VIR_DOMAIN_DISK_BUS_SCSI:
            ctrlr_idx = def->disks[i]->info.addr.drive.controller;
            if (hypervDomainAttachStorageVolume(domain, def->disks[i],
                                                scsiControllers[ctrlr_idx], hostname) < 0) {
                return -1;
            }
            break;
        case VIR_DOMAIN_DISK_BUS_FDC:
            if (hypervDomainAttachFloppy(domain, def->disks[i], floppySettings, hostname) < 0)
                return -1;
            break;
        case VIR_DOMAIN_DISK_BUS_NONE:
        case VIR_DOMAIN_DISK_BUS_VIRTIO:
        case VIR_DOMAIN_DISK_BUS_XEN:
        case VIR_DOMAIN_DISK_BUS_USB:
        case VIR_DOMAIN_DISK_BUS_UML:
        case VIR_DOMAIN_DISK_BUS_SATA:
        case VIR_DOMAIN_DISK_BUS_SD:
        case VIR_DOMAIN_DISK_BUS_LAST:
        default:
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Unsupported controller type"));
            return -1;
        }
    }

    return 0;
}


static int
hypervDomainAttachSerial(virDomainPtr domain, virDomainChrDef *serial)
{
    char uuid_string[VIR_UUID_STRING_BUFLEN];
    hypervPrivate *priv = domain->conn->privateData;
    g_autofree char *com_string = g_strdup_printf("COM %d", serial->target.port);
    g_autoptr(Msvm_VirtualSystemSettingData) vssd = NULL;
    g_autoptr(Msvm_ResourceAllocationSettingData) rasd = NULL;
    g_autoptr(Msvm_SerialPortSettingData) spsd = NULL;
    hypervWmiClassInfo *classInfo = NULL;
    Msvm_ResourceAllocationSettingData *current = NULL;
    Msvm_ResourceAllocationSettingData *entry = NULL;
    g_autoptr(GHashTable) serialResource = NULL;
    const char *connectionValue = NULL;
    g_autofree const char *resourceType = NULL;

    virUUIDFormat(domain->uuid, uuid_string);

    if (hypervGetMsvmVirtualSystemSettingDataFromUUID(priv, uuid_string, &vssd) < 0)
        return -1;

    if (g_str_has_prefix(priv->version, "6.")) {
        if (hypervGetResourceAllocationSD(priv, vssd->data->InstanceID, &rasd) < 0)
            return -1;

        current = rasd;
        classInfo = Msvm_ResourceAllocationSettingData_WmiInfo;
    } else {
        if (hypervGetSerialPortSD(priv, vssd->data->InstanceID, &spsd) < 0)
            return -1;

        current = (Msvm_ResourceAllocationSettingData *)spsd;
        classInfo = Msvm_SerialPortSettingData_WmiInfo;
    }

    while (current) {
        if (current->data->ResourceType == MSVM_RASD_RESOURCETYPE_SERIAL_PORT &&
            STREQ(current->data->ElementName, com_string)) {
            /* found our com port */
            entry = current;
            break;
        }
        current = current->next;
    }

    if (!entry)
        return -1;

    if (STRNEQ(serial->source->data.file.path, "-1"))
        connectionValue = serial->source->data.file.path;
    else
        connectionValue = "";

    resourceType = g_strdup_printf("%d", entry->data->ResourceType);

    serialResource = hypervCreateEmbeddedParam(classInfo);
    if (!serialResource)
        return -1;

    if (hypervSetEmbeddedProperty(serialResource, "Connection", connectionValue) < 0)
        return -1;

    if (hypervSetEmbeddedProperty(serialResource, "InstanceID", entry->data->InstanceID) < 0)
        return -1;

    if (hypervSetEmbeddedProperty(serialResource, "ResourceType", resourceType) < 0)
        return -1;

    if (hypervSetEmbeddedProperty(serialResource, "ResourceSubType",
                                  entry->data->ResourceSubType) < 0)
        return -1;

    if (hypervMsvmVSMSModifyResourceSettings(priv, &serialResource, classInfo) < 0)
        return -1;

    return 0;
}


static int
hypervDomainAttachSyntheticEthernetAdapter(virDomainPtr domain,
                                           virDomainNetDef *net,
                                           char *hostname)
{
    hypervPrivate *priv = domain->conn->privateData;
    g_autofree char *portResourceType = NULL;
    unsigned char vsiGuid[VIR_UUID_BUFLEN];
    char guidString[VIR_UUID_STRING_BUFLEN];
    g_autofree char *virtualSystemIdentifiers = NULL;
    char macString[VIR_MAC_STRING_BUFLEN];
    g_autofree char *macAddressNoColons = NULL;
    g_autoptr(GHashTable) portResource = NULL;
    g_auto(WsXmlDocH) sepsdResponse = NULL;
    g_auto(virBuffer) query = VIR_BUFFER_INITIALIZER;
    g_autoptr(Msvm_VirtualEthernetSwitch) vSwitch = NULL;
    g_autofree char *enabledState = NULL;
    g_autofree char *switch__PATH = NULL;
    g_autofree char *sepsd__PATH = NULL;
    g_autofree char *sepsdInstanceID = NULL;
    g_autofree char *sepsdInstanceEscaped = NULL;
    g_autofree char *connectionResourceType = NULL;
    g_autoptr(GHashTable) connectionResource = NULL;

    /*
     * Step 1: Create the Msvm_SyntheticEthernetPortSettingData object
     * that holds half the settings for the new adapter we are creating
     */
    portResourceType = g_strdup_printf("%d", MSVM_RASD_RESOURCETYPE_ETHERNET_ADAPTER);

    if (virUUIDGenerate(vsiGuid) < 0)
        return -1;

    virUUIDFormat(vsiGuid, guidString);
    virtualSystemIdentifiers = g_strdup_printf("{%s}", guidString);

    virMacAddrFormat(&net->mac, macString);
    macAddressNoColons = virStringReplace(macString, ":", "");

    /* prepare embedded param */
    portResource = hypervCreateEmbeddedParam(Msvm_SyntheticEthernetPortSettingData_WmiInfo);
    if (!portResource)
        return -1;

    if (hypervSetEmbeddedProperty(portResource, "ResourceType", portResourceType) < 0)
        return -1;

    if (hypervSetEmbeddedProperty(portResource, "ResourceSubType",
                                  "Microsoft:Hyper-V:Synthetic Ethernet Port") < 0)
        return -1;

    if (hypervSetEmbeddedProperty(portResource,
                                  "VirtualSystemIdentifiers", virtualSystemIdentifiers) < 0)
        return -1;

    if (hypervSetEmbeddedProperty(portResource, "Address", macAddressNoColons) < 0)
        return -1;

    if (hypervSetEmbeddedProperty(portResource, "StaticMacAddress", "true") < 0)
        return -1;

    if (hypervMsvmVSMSAddResourceSettings(domain, &portResource,
                                          Msvm_SyntheticEthernetPortSettingData_WmiInfo,
                                          &sepsdResponse) < 0)
        return -1;

    /*
     * Step 2: Get the Msvm_VirtualEthernetSwitch object
     */
    virBufferAsprintf(&query,
                      MSVM_VIRTUALETHERNETSWITCH_WQL_SELECT "WHERE Name='%s'",
                      net->data.bridge.brname);

    if (hypervGetWmiClass(Msvm_VirtualEthernetSwitch, &vSwitch) < 0)
        return -1;

    if (!vSwitch)
        return -1;

    /*
     * Step 3: Create the Msvm_EthernetPortAllocationSettingData object that
     * holds the other half of the network configuration
     */
    enabledState = g_strdup_printf("%d", MSVM_ETHERNETPORTALLOCATIONSETTINGDATA_ENABLEDSTATE_ENABLED);

    /* build the two __PATH variables */
    switch__PATH = g_strdup_printf("\\\\%s\\Root\\Virtualization\\V2:"
                                   "Msvm_VirtualEthernetSwitch.CreationClassName=\"Msvm_VirtualEthernetSwitch\","
                                   "Name=\"%s\"",
                                   hostname, vSwitch->data->Name);

    /* Get the sepsd instance ID out of the XML response */
    sepsdInstanceID = hypervGetInstanceIDFromXMLResponse(sepsdResponse);
    sepsdInstanceEscaped = virStringReplace(sepsdInstanceID, "\\", "\\\\");
    sepsd__PATH = g_strdup_printf("\\\\%s\\root\\virtualization\\v2:"
                                  "Msvm_SyntheticEthernetPortSettingData.InstanceID=\"%s\"",
                                  hostname, sepsdInstanceEscaped);

    connectionResourceType = g_strdup_printf("%d", MSVM_RASD_RESOURCETYPE_ETHERNET_CONNECTION);

    connectionResource = hypervCreateEmbeddedParam(Msvm_EthernetPortAllocationSettingData_WmiInfo);
    if (!connectionResource)
        return -1;

    if (hypervSetEmbeddedProperty(connectionResource, "EnabledState", enabledState) < 0)
        return -1;

    if (hypervSetEmbeddedProperty(connectionResource, "HostResource", switch__PATH) < 0)
        return -1;

    if (hypervSetEmbeddedProperty(connectionResource, "Parent", sepsd__PATH) < 0)
        return -1;

    if (hypervSetEmbeddedProperty(connectionResource, "ResourceType", connectionResourceType) < 0)
        return -1;

    if (hypervSetEmbeddedProperty(connectionResource,
                                  "ResourceSubType", "Microsoft:Hyper-V:Ethernet Connection") < 0)
        return -1;

    if (hypervMsvmVSMSAddResourceSettings(domain, &connectionResource,
                                          Msvm_EthernetPortAllocationSettingData_WmiInfo, NULL) < 0)
        return -1;

    return 0;
}


/*
 * Functions for deserializing device entries
 */
static int
hypervDomainDefAppendController(virDomainDef *def,
                                int idx,
                                virDomainControllerType controllerType)
{
    virDomainControllerDef *controller = NULL;

    if (!(controller = virDomainControllerDefNew(controllerType)))
        return -1;

    controller->idx = idx;

    VIR_APPEND_ELEMENT(def->controllers, def->ncontrollers, controller);

    return 0;
}


static int
hypervDomainDefAppendIDEController(virDomainDef *def)
{
    return hypervDomainDefAppendController(def, 0, VIR_DOMAIN_CONTROLLER_TYPE_IDE);
}


static int
hypervDomainDefAppendSCSIController(virDomainDef *def, int idx)
{
    return hypervDomainDefAppendController(def, idx, VIR_DOMAIN_CONTROLLER_TYPE_SCSI);
}


static int
hypervDomainDefAppendDisk(virDomainDef *def,
                          virDomainDiskDef *disk,
                          virDomainDiskBus busType,
                          int diskNameOffset,
                          const char *diskNamePrefix,
                          int maxControllers,
                          Msvm_ResourceAllocationSettingData **controllers,
                          Msvm_ResourceAllocationSettingData *diskParent,
                          Msvm_ResourceAllocationSettingData *diskController)
{
    size_t i = 0;
    int ctrlr_idx = -1;
    int addr = -1;

    if (virStrToLong_i(diskParent->data->AddressOnParent, NULL, 10, &addr) < 0)
        return -1;

    if (addr < 0)
        return -1;

    /* Find controller index */
    for (i = 0; i < maxControllers; i++) {
        if (diskController == controllers[i]) {
            ctrlr_idx = i;
            break;
        }
    }

    if (ctrlr_idx < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Could not find controller for disk!"));
        return -1;
    }

    disk->bus = busType;
    disk->dst = virIndexToDiskName(ctrlr_idx * diskNameOffset + addr, diskNamePrefix);
    if (busType == VIR_DOMAIN_DISK_BUS_IDE) {
        disk->info.addr.drive.controller = 0;
        disk->info.addr.drive.bus = ctrlr_idx;
    } else {
        disk->info.addr.drive.controller = ctrlr_idx;
        disk->info.addr.drive.bus = 0;
    }
    disk->info.addr.drive.target = 0;
    disk->info.addr.drive.unit = addr;

    VIR_APPEND_ELEMENT(def->disks, def->ndisks, disk);

    return 0;
}


static int
hypervDomainDefParseFloppyStorageExtent(virDomainDef *def, virDomainDiskDef *disk)
{
    disk->bus = VIR_DOMAIN_DISK_BUS_FDC;
    disk->dst = g_strdup("fda");

    VIR_APPEND_ELEMENT(def->disks, def->ndisks, disk);

    return 0;
}


static int
hypervDomainDefParseVirtualExtent(hypervPrivate *priv,
                                  virDomainDef *def,
                                  Msvm_StorageAllocationSettingData *disk_entry,
                                  Msvm_ResourceAllocationSettingData *rasd,
                                  Msvm_ResourceAllocationSettingData **ideChannels,
                                  Msvm_ResourceAllocationSettingData **scsiControllers)
{
    Msvm_ResourceAllocationSettingData *diskParent = NULL;
    Msvm_ResourceAllocationSettingData *controller = NULL;
    virDomainDiskDef *disk = NULL;
    int result = -1;

    if (disk_entry->data->HostResource.count < 1)
        goto cleanup;

    if (!(disk = virDomainDiskDefNew(priv->xmlopt))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Could not allocate disk definition"));
        goto cleanup;
    }

    /* get disk associated with storage extent */
    if (hypervGetDeviceParentRasdFromDeviceId(disk_entry->data->Parent, rasd, &diskParent) < 0)
        goto cleanup;

    /* get associated controller */
    if (hypervGetDeviceParentRasdFromDeviceId(diskParent->data->Parent, rasd, &controller) < 0)
        goto cleanup;

    /* common fields first */
    disk->src->type = VIR_STORAGE_TYPE_FILE;
    disk->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE;

    /* note if it's a CDROM disk */
    if (STREQ(disk_entry->data->ResourceSubType, "Microsoft:Hyper-V:Virtual CD/DVD Disk"))
        disk->device = VIR_DOMAIN_DISK_DEVICE_CDROM;
    else
        disk->device = VIR_DOMAIN_DISK_DEVICE_DISK;

    /* copy in the source path */
    virDomainDiskSetSource(disk, *(char **)disk_entry->data->HostResource.data);

    /* controller-specific fields */
    if (controller->data->ResourceType == MSVM_RASD_RESOURCETYPE_PARALLEL_SCSI_HBA) {
        if (hypervDomainDefAppendDisk(def, disk, VIR_DOMAIN_DISK_BUS_SCSI,
                                      64, "sd", HYPERV_MAX_SCSI_CONTROLLERS,
                                      scsiControllers, diskParent, controller) < 0) {
            goto cleanup;
        }
    } else if (controller->data->ResourceType == MSVM_RASD_RESOURCETYPE_IDE_CONTROLLER) {
        if (hypervDomainDefAppendDisk(def, disk, VIR_DOMAIN_DISK_BUS_IDE,
                                      2, "hd", HYPERV_MAX_IDE_CHANNELS,
                                      ideChannels, diskParent, controller) < 0) {
            goto cleanup;
        }
    } else if (controller->data->ResourceType == MSVM_RASD_RESOURCETYPE_OTHER &&
               diskParent->data->ResourceType == MSVM_RASD_RESOURCETYPE_DISKETTE_DRIVE) {
        if (hypervDomainDefParseFloppyStorageExtent(def, disk) < 0)
            goto cleanup;
        disk->device = VIR_DOMAIN_DISK_DEVICE_FLOPPY;
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unrecognized controller type %1$d"),
                       controller->data->ResourceType);
        goto cleanup;
    }

    result = 0;

 cleanup:
    if (result != 0 && disk)
        virDomainDiskDefFree(disk);

    return result;
}


static int
hypervDomainDefParsePhysicalDisk(hypervPrivate *priv,
                                 virDomainDef *def,
                                 Msvm_ResourceAllocationSettingData *entry,
                                 Msvm_ResourceAllocationSettingData *rasd,
                                 Msvm_ResourceAllocationSettingData **ideChannels,
                                 Msvm_ResourceAllocationSettingData **scsiControllers)
{
    int result = -1;
    Msvm_ResourceAllocationSettingData *controller = NULL;
    g_autoptr(Msvm_DiskDrive) diskdrive = NULL;
    virDomainDiskDef *disk = NULL;
    char **hostResource = entry->data->HostResource.data;
    g_autofree char *hostEscaped = NULL;
    g_autofree char *driveNumberStr = NULL;
    g_auto(virBuffer) query = VIR_BUFFER_INITIALIZER;
    int addr = -1, ctrlr_idx = -1;
    size_t i = 0;

    if (virStrToLong_i(entry->data->AddressOnParent, NULL, 10, &addr) < 0)
        return -1;

    if (addr < 0)
        return -1;

    if (hypervGetDeviceParentRasdFromDeviceId(entry->data->Parent, rasd, &controller) < 0)
        goto cleanup;

    /* create disk definition */
    if (!(disk = virDomainDiskDefNew(priv->xmlopt))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Could not allocate disk def"));
        goto cleanup;
    }

    /* Query Msvm_DiskDrive for the DriveNumber */
    hostEscaped = virStringReplace(*hostResource, "\\\"", "\"");
    hostEscaped = virStringReplace(hostEscaped, "\\", "\\\\");

    /* quotes must be preserved, so virBufferEscapeSQL can't be used */
    virBufferAsprintf(&query,
                      MSVM_DISKDRIVE_WQL_SELECT "WHERE __PATH='%s'",
                      hostEscaped);

    if (hypervGetWmiClass(Msvm_DiskDrive, &diskdrive) < 0)
        goto cleanup;

    if (!diskdrive) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Could not find Msvm_DiskDrive object"));
        goto cleanup;
    }

    driveNumberStr = g_strdup_printf("%u", diskdrive->data->DriveNumber);
    virDomainDiskSetSource(disk, driveNumberStr);

    if (controller->data->ResourceType == MSVM_RASD_RESOURCETYPE_PARALLEL_SCSI_HBA) {
        for (i = 0; i < HYPERV_MAX_SCSI_CONTROLLERS; i++) {
            if (controller == scsiControllers[i]) {
                ctrlr_idx = i;
                break;
            }
        }
        disk->bus = VIR_DOMAIN_DISK_BUS_SCSI;
        disk->dst = virIndexToDiskName(ctrlr_idx * 64 + addr, "sd");
        disk->info.addr.drive.unit = addr;
        disk->info.addr.drive.controller = ctrlr_idx;
        disk->info.addr.drive.bus = 0;
    } else if (controller->data->ResourceType == MSVM_RASD_RESOURCETYPE_IDE_CONTROLLER) {
        for (i = 0; i < HYPERV_MAX_IDE_CHANNELS; i++) {
            if (controller == ideChannels[i]) {
                ctrlr_idx = i;
                break;
            }
        }
        disk->bus = VIR_DOMAIN_DISK_BUS_IDE;
        disk->dst = virIndexToDiskName(ctrlr_idx * 4 + addr, "hd");
        disk->info.addr.drive.unit = addr;
        disk->info.addr.drive.controller = 0;
        disk->info.addr.drive.bus = ctrlr_idx;
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid controller type for LUN"));
        goto cleanup;
    }

    disk->info.addr.drive.target = 0;
    virDomainDiskSetType(disk, VIR_STORAGE_TYPE_BLOCK);
    disk->device = VIR_DOMAIN_DISK_DEVICE_DISK;

    disk->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE;

    VIR_APPEND_ELEMENT(def->disks, def->ndisks, disk);

    result = 0;

 cleanup:
    if (result != 0 && disk)
        virDomainDiskDefFree(disk);

    return result;
}


static int
hypervDomainDefParseStorage(hypervPrivate *priv,
                            virDomainDef *def,
                            Msvm_ResourceAllocationSettingData *rasd,
                            Msvm_StorageAllocationSettingData *sasd)
{
    Msvm_ResourceAllocationSettingData *entry = rasd;
    Msvm_StorageAllocationSettingData *disk_entry = sasd;
    Msvm_ResourceAllocationSettingData *ideChannels[HYPERV_MAX_IDE_CHANNELS];
    Msvm_ResourceAllocationSettingData *scsiControllers[HYPERV_MAX_SCSI_CONTROLLERS];
    bool hasIdeController = false;
    int channel = -1;
    int scsi_idx = 0;

    /* first pass: populate storage controllers */
    while (entry) {
        if (entry->data->ResourceType == MSVM_RASD_RESOURCETYPE_IDE_CONTROLLER) {
            channel = entry->data->Address[0] - '0';
            ideChannels[channel] = entry;
            if (!hasIdeController) {
                /* Hyper-V represents its PIIX4 controller's two channels as separate objects. */
                if (hypervDomainDefAppendIDEController(def) < 0) {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Could not add IDE controller"));
                    return -1;
                }
                hasIdeController = true;
            }
        } else if (entry->data->ResourceType == MSVM_RASD_RESOURCETYPE_PARALLEL_SCSI_HBA) {
            scsiControllers[scsi_idx++] = entry;
            if (hypervDomainDefAppendSCSIController(def, scsi_idx - 1) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Could not parse SCSI controller"));
                return -1;
            }
        }

        entry = entry->next;
    }

    /* second pass: populate physical disks */
    entry = rasd;
    while (entry) {
        if (entry->data->ResourceType == MSVM_RASD_RESOURCETYPE_DISK_DRIVE &&
            entry->data->HostResource.count > 0) {
            char **hostResource = entry->data->HostResource.data;

            if (strstr(*hostResource, "NODRIVE")) {
                /* Hyper-V doesn't let you define LUNs with no connection */
                VIR_DEBUG("Skipping empty LUN '%s'", *hostResource);
                entry = entry->next;
                continue;
            }

            if (hypervDomainDefParsePhysicalDisk(priv, def, entry, rasd,
                                                 ideChannels, scsiControllers) < 0)
                return -1;
        }

        entry = entry->next;
    }

    /* third pass: populate virtual disks */
    while (disk_entry) {
        if (hypervDomainDefParseVirtualExtent(priv, def, disk_entry, rasd,
                                              ideChannels, scsiControllers) < 0)
            return -1;

        disk_entry = disk_entry->next;
    }

    return 0;
}


static int
hypervDomainDefParseSerial(virDomainDef *def, Msvm_ResourceAllocationSettingData *rasd)
{
    for (; rasd; rasd = rasd->next) {
        int port_num = 0;
        char **conn = NULL;
        const char *srcPath = NULL;
        virDomainChrDef *serial = NULL;

        if (rasd->data->ResourceType != MSVM_RASD_RESOURCETYPE_SERIAL_PORT)
            continue;

        /* get port number */
        port_num = rasd->data->ElementName[4] - '0';
        if (port_num < 1) {
            continue;
        }

        serial = virDomainChrDefNew(NULL);

        serial->deviceType = VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL;
        serial->source->type = VIR_DOMAIN_CHR_TYPE_PIPE;
        serial->target.port = port_num;

        /* set up source */
        if (rasd->data->Connection.count < 1) {
            srcPath = "-1";
        } else {
            conn = rasd->data->Connection.data;
            if (!*conn)
                srcPath = "-1";
            else
                srcPath = *conn;
        }

        serial->source->data.file.path = g_strdup(srcPath);

        VIR_APPEND_ELEMENT(def->serials, def->nserials, serial);
    }

    return 0;
}


static int
hypervDomainDefParseEthernetAdapter(virDomainDef *def,
                                    Msvm_EthernetPortAllocationSettingData *net,
                                    hypervPrivate *priv)
{
    g_autoptr(virDomainNetDef) ndef = g_new0(virDomainNetDef, 1);
    g_autoptr(Msvm_SyntheticEthernetPortSettingData) sepsd = NULL;
    g_autoptr(Msvm_VirtualEthernetSwitch) vSwitch = NULL;
    char **switchConnection = NULL;
    g_autofree char *switchConnectionEscaped = NULL;
    char *sepsdPATH = NULL;
    g_autofree char *sepsdEscaped = NULL;
    g_auto(virBuffer) query = VIR_BUFFER_INITIALIZER;

    VIR_DEBUG("Parsing ethernet adapter '%s'", net->data->InstanceID);

    ndef->type = VIR_DOMAIN_NET_TYPE_BRIDGE;

    /*
     * If there's no switch port connection or the EnabledState is disabled,
     * then the adapter isn't hooked up to anything and we don't have to
     * do anything more.
     */
    switchConnection = net->data->HostResource.data;
    if (net->data->HostResource.count < 1 || !*switchConnection ||
        net->data->EnabledState == MSVM_ETHERNETPORTALLOCATIONSETTINGDATA_ENABLEDSTATE_DISABLED) {
        VIR_DEBUG("Adapter not connected to switch");
        return 0;
    }

    /*
     * Now we retrieve the associated Msvm_SyntheticEthernetPortSettingData and
     * Msvm_VirtualEthernetSwitch objects and use them to build the XML definition.
     */

    /* begin by getting the Msvm_SyntheticEthernetPortSettingData object */
    sepsdPATH = net->data->Parent;
    sepsdEscaped = virStringReplace(sepsdPATH, "\\", "\\\\");
    virBufferAsprintf(&query,
                      MSVM_SYNTHETICETHERNETPORTSETTINGDATA_WQL_SELECT "WHERE __PATH = '%s'",
                      sepsdEscaped);

    if (hypervGetWmiClass(Msvm_SyntheticEthernetPortSettingData, &sepsd) < 0)
        return -1;

    if (!sepsd) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Could not retrieve NIC settings"));
        return -1;
    }

    /* set mac address */
    if (virMacAddrParseHex(sepsd->data->Address, &ndef->mac) < 0)
        return -1;

    /* now we get the Msvm_VirtualEthernetSwitch */
    virBufferFreeAndReset(&query);
    switchConnectionEscaped = virStringReplace(*switchConnection, "\\", "\\\\");
    virBufferAsprintf(&query,
                      MSVM_VIRTUALETHERNETSWITCH_WQL_SELECT "WHERE __PATH = '%s'",
                      switchConnectionEscaped);

    if (hypervGetWmiClass(Msvm_VirtualEthernetSwitch, &vSwitch) < 0)
        return -1;

    if (!vSwitch) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Could not retrieve virtual switch"));
        return -1;
    }

    /* get bridge name */
    ndef->data.bridge.brname = g_strdup(vSwitch->data->Name);

    VIR_APPEND_ELEMENT(def->nets, def->nnets, ndef);

    return 0;
}

static int
hypervDomainDefParseEthernet(virDomainPtr domain,
                             virDomainDef *def,
                             Msvm_EthernetPortAllocationSettingData *nets)
{
    Msvm_EthernetPortAllocationSettingData *entry = nets;
    hypervPrivate *priv = domain->conn->privateData;

    while (entry) {
        if (hypervDomainDefParseEthernetAdapter(def, entry, priv) < 0)
            return -1;

        entry = entry->next;
    }

    return 0;
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

    if ((*priv)->xmlopt)
        virObjectUnref((*priv)->xmlopt);

    if ((*priv)->version)
        g_free((*priv)->version);

    hypervFreeParsedUri(&(*priv)->parsedUri);
    VIR_FREE(*priv);
}


static int
hypervInitConnection(virConnectPtr conn, hypervPrivate *priv,
                     char *username, char *password)
{
    /* Initialize the openwsman connection */
    priv->client = wsmc_create(conn->uri->server, conn->uri->port, "/wsman",
                               priv->parsedUri->transport, username, password);

    if (priv->client == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not create openwsman client"));
        return -1;
    }

    if (wsmc_transport_init(priv->client, NULL) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not initialize openwsman transport"));
        return -1;
    }

    /* FIXME: Currently only basic authentication is supported  */
    wsman_transport_set_auth_method(priv->client, "basic");

    return 0;
}


virDomainDefParserConfig hypervDomainDefParserConfig;

static virDrvOpenStatus
hypervConnectOpen(virConnectPtr conn, virConnectAuthPtr auth,
                  virConf *conf G_GNUC_UNUSED,
                  unsigned int flags)
{
    virDrvOpenStatus result = VIR_DRV_OPEN_ERROR;
    hypervPrivate *priv = NULL;
    g_autofree char *username = NULL;
    g_autofree char *password = NULL;
    g_autoptr(Win32_OperatingSystem) os = NULL;

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

    /* init xmlopt for domain XML */
    priv->xmlopt = virDomainXMLOptionNew(&hypervDomainDefParserConfig, NULL, NULL, NULL, NULL, NULL);

    if (hypervGetOperatingSystem(priv, &os) < 0)
        goto cleanup;

    if (!os) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not get version information for host %1$s"),
                       conn->uri->server);
        goto cleanup;
    }

    priv->version = g_strdup(os->data->Version);

    conn->privateData = g_steal_pointer(&priv);
    result = VIR_DRV_OPEN_SUCCESS;

 cleanup:
    hypervFreePrivate(&priv);

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
    hypervPrivate *priv = conn->privateData;
    unsigned int major, minor, micro;

    if (hypervParseVersionString(priv->version, &major, &minor, &micro) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not parse version from '%1$s'"),
                       priv->version);
        return -1;
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
                       _("Could not produce packed version number from '%1$s'"),
                       priv->version);
        return -1;
    }

    *version = major * 100000000 + minor * 1000000 + micro;

    return 0;
}


static char *
hypervConnectGetHostname(virConnectPtr conn)
{
    g_autoptr(Win32_ComputerSystem) computerSystem = NULL;

    if (hypervGetPhysicalSystemList((hypervPrivate *)conn->privateData, &computerSystem) < 0)
        return NULL;

    return g_strdup(computerSystem->data->DNSHostName);
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
    hypervPrivate *priv = conn->privateData;
    g_auto(virBuffer) query = VIR_BUFFER_INITIALIZER;
    g_autoptr(Msvm_ProcessorSettingData) processorSettingData = NULL;

    /* Get max processors definition */
    virBufferAddLit(&query,
                    MSVM_PROCESSORSETTINGDATA_WQL_SELECT
                    "WHERE InstanceID LIKE 'Microsoft:Definition%Maximum'");

    if (hypervGetWmiClass(Msvm_ProcessorSettingData, &processorSettingData) < 0)
        return -1;

    if (!processorSettingData) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not get maximum definition of Msvm_ProcessorSettingData for host %1$s"),
                       conn->uri->server);
        return -1;
    }

    return processorSettingData->data->VirtualQuantity;
}


static int
hypervNodeGetInfo(virConnectPtr conn, virNodeInfoPtr info)
{
    hypervPrivate *priv = conn->privateData;
    g_autoptr(Win32_ComputerSystem) computerSystem = NULL;
    g_autoptr(Win32_Processor) processorList = NULL;
    Win32_Processor *processor = NULL;
    char *tmp;

    memset(info, 0, sizeof(*info));

    if (hypervGetPhysicalSystemList(priv, &computerSystem) < 0)
        return -1;

    if (hypervGetProcessorsByName(priv, computerSystem->data->Name, &processorList) < 0) {
        return -1;
    }

    /* Strip the string to fit more relevant information in 32 chars */
    tmp = processorList->data->Name;

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
    if (virStrcpyStatic(info->model, processorList->data->Name) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("CPU model %1$s too long for destination"),
                       processorList->data->Name);
        return -1;
    }

    info->memory = computerSystem->data->TotalPhysicalMemory / 1024; /* byte to kilobyte */
    info->mhz = processorList->data->MaxClockSpeed;
    info->nodes = 1;
    info->sockets = 0;

    for (processor = processorList; processor != NULL;
         processor = processor->next) {
        ++info->sockets;
    }

    info->cores = processorList->data->NumberOfCores;
    info->threads = processorList->data->NumberOfLogicalProcessors / info->cores;
    info->cpus = info->sockets * info->cores;

    return 0;
}


static int
hypervConnectListDomains(virConnectPtr conn, int *ids, int maxids)
{
    hypervPrivate *priv = conn->privateData;
    g_autoptr(Msvm_ComputerSystem) computerSystemList = NULL;
    Msvm_ComputerSystem *computerSystem = NULL;
    int count = 0;

    if (maxids == 0)
        return 0;

    if (hypervGetActiveVirtualSystemList(priv, &computerSystemList) < 0)
        return -1;

    for (computerSystem = computerSystemList; computerSystem != NULL;
         computerSystem = computerSystem->next) {
        ids[count++] = computerSystem->data->ProcessID;

        if (count >= maxids)
            break;
    }

    return count;
}


static int
hypervConnectNumOfDomains(virConnectPtr conn)
{
    hypervPrivate *priv = conn->privateData;
    g_autoptr(Msvm_ComputerSystem) computerSystemList = NULL;
    Msvm_ComputerSystem *computerSystem = NULL;
    int count = 0;

    if (hypervGetActiveVirtualSystemList(priv, &computerSystemList) < 0)
        return -1;

    for (computerSystem = computerSystemList; computerSystem != NULL;
         computerSystem = computerSystem->next) {
        ++count;
    }

    return count;
}


static virDomainPtr
hypervDomainLookupByID(virConnectPtr conn, int id)
{
    virDomainPtr domain = NULL;
    hypervPrivate *priv = conn->privateData;
    g_autoptr(Msvm_ComputerSystem) computerSystem = NULL;

    if (hypervGetVirtualSystemByID(priv, id, &computerSystem) < 0)
        return NULL;

    hypervMsvmComputerSystemToDomain(conn, computerSystem, &domain);

    return domain;
}


static virDomainPtr
hypervDomainLookupByUUID(virConnectPtr conn, const unsigned char *uuid)
{
    virDomainPtr domain = NULL;
    hypervPrivate *priv = conn->privateData;
    char uuid_string[VIR_UUID_STRING_BUFLEN];
    g_autoptr(Msvm_ComputerSystem) computerSystem = NULL;

    virUUIDFormat(uuid, uuid_string);

    if (hypervMsvmComputerSystemFromUUID(priv, uuid_string, &computerSystem) < 0)
        return NULL;

    hypervMsvmComputerSystemToDomain(conn, computerSystem, &domain);

    return domain;
}


static virDomainPtr
hypervDomainLookupByName(virConnectPtr conn, const char *name)
{
    virDomainPtr domain = NULL;
    hypervPrivate *priv = conn->privateData;
    g_autoptr(Msvm_ComputerSystem) computerSystem = NULL;

    if (hypervGetVirtualSystemByName(priv, name, &computerSystem) < 0)
        return NULL;

    if (computerSystem->next) {
        virReportError(VIR_ERR_MULTIPLE_DOMAINS,
                       _("Multiple domains exist with the name '%1$s': repeat the request using a UUID"),
                       name);
        return NULL;
    }

    hypervMsvmComputerSystemToDomain(conn, computerSystem, &domain);

    return domain;
}


static int
hypervDomainSuspend(virDomainPtr domain)
{
    return hypervRequestStateChange(domain, MSVM_COMPUTERSYSTEM_REQUESTEDSTATE_QUIESCE);
}


static int
hypervDomainResume(virDomainPtr domain)
{
    g_autoptr(Msvm_ComputerSystem) computerSystem = NULL;

    if (hypervMsvmComputerSystemFromDomain(domain, &computerSystem) < 0)
        return -1;

    if (computerSystem->data->EnabledState != MSVM_COMPUTERSYSTEM_REQUESTEDSTATE_QUIESCE) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Domain is not paused"));
        return -1;
    }

    return hypervInvokeMsvmComputerSystemRequestStateChange(domain,
                                                            MSVM_COMPUTERSYSTEM_REQUESTEDSTATE_ENABLED);
}


static int
hypervDomainShutdownFlags(virDomainPtr domain, unsigned int flags)
{
    hypervPrivate *priv = domain->conn->privateData;
    g_autoptr(Msvm_ComputerSystem) computerSystem = NULL;
    g_autoptr(Msvm_ShutdownComponent) shutdown = NULL;
    bool in_transition = false;
    char uuid[VIR_UUID_STRING_BUFLEN];
    g_auto(virBuffer) query = VIR_BUFFER_INITIALIZER;
    g_autoptr(hypervInvokeParamsList) params = NULL;
    g_autofree char *selector = NULL;

    virCheckFlags(0, -1);

    virUUIDFormat(domain->uuid, uuid);

    if (hypervMsvmComputerSystemFromDomain(domain, &computerSystem) < 0)
        return -1;

    if (!hypervIsMsvmComputerSystemActive(computerSystem, &in_transition) ||
        in_transition) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Domain is not active or in state transition"));
        return -1;
    }

    virBufferEscapeSQL(&query, MSVM_SHUTDOWNCOMPONENT_WQL_SELECT "WHERE SystemName = '%s'", uuid);

    if (hypervGetWmiClass(Msvm_ShutdownComponent, &shutdown) < 0 ||
        !shutdown) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("Could not get Msvm_ShutdownComponent for domain with UUID '%1$s'"),
                       uuid);
        return -1;
    }

    selector = g_strdup_printf("CreationClassName=\"Msvm_ShutdownComponent\"&DeviceID=\"%s\"&"
                               "SystemCreationClassName=\"Msvm_ComputerSystem\"&SystemName=\"%s\"",
                               shutdown->data->DeviceID, uuid);

    params = hypervCreateInvokeParamsList("InitiateShutdown", selector,
                                          Msvm_ShutdownComponent_WmiInfo);
    if (!params)
        return -1;

    hypervAddSimpleParam(params, "Force", "False");

    /* "Reason" is not translated because the Hyper-V administrator may not
     * know the libvirt user's language. They may not know English, either,
     * but this makes it consistent, at least. */
    hypervAddSimpleParam(params, "Reason", "Planned shutdown via libvirt");

    if (hypervInvokeMethod(priv, &params, NULL) < 0)
        return -1;

    return 0;
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
    g_autoptr(Msvm_ComputerSystem) computerSystem = NULL;
    bool in_transition = false;

    virCheckFlags(0, -1);

    if (hypervMsvmComputerSystemFromDomain(domain, &computerSystem) < 0)
        return -1;

    if (!hypervIsMsvmComputerSystemActive(computerSystem, &in_transition) ||
        in_transition) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Domain is not active or is in state transition"));
        return -1;
    }

    return hypervInvokeMsvmComputerSystemRequestStateChange(domain,
                                                            MSVM_COMPUTERSYSTEM_REQUESTEDSTATE_DISABLED);
}


static int
hypervDomainDestroy(virDomainPtr domain)
{
    return hypervDomainDestroyFlags(domain, 0);
}


static char *
hypervDomainGetOSType(virDomainPtr domain G_GNUC_UNUSED)
{
    return g_strdup("hvm");
}


static unsigned long long
hypervDomainGetMaxMemory(virDomainPtr domain)
{
    char uuid_string[VIR_UUID_STRING_BUFLEN];
    hypervPrivate *priv = domain->conn->privateData;
    g_autoptr(Msvm_VirtualSystemSettingData) vssd = NULL;
    g_autoptr(Msvm_MemorySettingData) mem_sd = NULL;

    virUUIDFormat(domain->uuid, uuid_string);

    if (hypervGetMsvmVirtualSystemSettingDataFromUUID(priv, uuid_string, &vssd) < 0)
        return 0;

    if (hypervGetMemorySD(priv, vssd->data->InstanceID, &mem_sd) < 0)
        return 0;

    return mem_sd->data->Limit * 1024;
}


static int
hypervDomainSetMemoryProperty(virDomainPtr domain,
                              unsigned long memory,
                              const char* propertyName)
{
    char uuid_string[VIR_UUID_STRING_BUFLEN];
    hypervPrivate *priv = domain->conn->privateData;
    g_autoptr(Msvm_VirtualSystemSettingData) vssd = NULL;
    g_autoptr(Msvm_MemorySettingData) memsd = NULL;
    g_autoptr(GHashTable) memResource = NULL;
    g_autofree char *memory_str = g_strdup_printf("%lu", VIR_ROUND_UP(VIR_DIV_UP(memory, 1024), 2));

    virUUIDFormat(domain->uuid, uuid_string);

    if (hypervGetMsvmVirtualSystemSettingDataFromUUID(priv, uuid_string, &vssd) < 0)
        return -1;

    if (hypervGetMemorySD(priv, vssd->data->InstanceID, &memsd) < 0)
        return -1;

    memResource = hypervCreateEmbeddedParam(Msvm_MemorySettingData_WmiInfo);
    if (!memResource)
        return -1;

    if (hypervSetEmbeddedProperty(memResource, propertyName, memory_str) < 0)
        return -1;

    if (hypervSetEmbeddedProperty(memResource, "InstanceID", memsd->data->InstanceID) < 0)
        return -1;

    if (hypervMsvmVSMSModifyResourceSettings(priv, &memResource,
                                             Msvm_MemorySettingData_WmiInfo) < 0)
        return -1;

    return 0;
}


static int
hypervDomainSetMaxMemory(virDomainPtr domain, unsigned long memory)
{
    return hypervDomainSetMemoryProperty(domain, memory, "Limit");
}


static int
hypervDomainSetMemoryFlags(virDomainPtr domain, unsigned long memory, unsigned int flags)
{
    virCheckFlags(0, -1);
    return hypervDomainSetMemoryProperty(domain, memory, "VirtualQuantity");
}


static int
hypervDomainSetMemory(virDomainPtr domain, unsigned long memory)
{
    return hypervDomainSetMemoryFlags(domain, memory, 0);
}


static int
hypervDomainGetInfo(virDomainPtr domain, virDomainInfoPtr info)
{
    hypervPrivate *priv = domain->conn->privateData;
    char uuid_string[VIR_UUID_STRING_BUFLEN];
    g_autoptr(Msvm_ComputerSystem) computerSystem = NULL;
    g_autoptr(Msvm_VirtualSystemSettingData) virtualSystemSettingData = NULL;
    g_autoptr(Msvm_ProcessorSettingData) processorSettingData = NULL;
    g_autoptr(Msvm_MemorySettingData) memorySettingData = NULL;

    memset(info, 0, sizeof(*info));

    virUUIDFormat(domain->uuid, uuid_string);

    /* Get Msvm_ComputerSystem */
    if (hypervMsvmComputerSystemFromDomain(domain, &computerSystem) < 0)
        return -1;

    if (hypervGetMsvmVirtualSystemSettingDataFromUUID(priv, uuid_string,
                                                      &virtualSystemSettingData) < 0)
        return -1;

    if (hypervGetProcessorSD(priv,
                             virtualSystemSettingData->data->InstanceID,
                             &processorSettingData) < 0)
        return -1;

    if (hypervGetMemorySD(priv,
                          virtualSystemSettingData->data->InstanceID,
                          &memorySettingData) < 0)
        return -1;

    /* Fill struct */
    info->state = hypervMsvmComputerSystemEnabledStateToDomainState(computerSystem);
    info->maxMem = memorySettingData->data->Limit * 1024; /* megabyte to kilobyte */
    info->memory = memorySettingData->data->VirtualQuantity * 1024; /* megabyte to kilobyte */
    info->nrVirtCpu = processorSettingData->data->VirtualQuantity;
    info->cpuTime = 0;

    return 0;
}


static int
hypervDomainGetState(virDomainPtr domain, int *state, int *reason,
                     unsigned int flags)
{
    g_autoptr(Msvm_ComputerSystem) computerSystem = NULL;

    virCheckFlags(0, -1);

    if (hypervMsvmComputerSystemFromDomain(domain, &computerSystem) < 0)
        return -1;

    *state = hypervMsvmComputerSystemEnabledStateToDomainState(computerSystem);

    if (reason != NULL)
        *reason = 0;

    return 0;
}


static char *
hypervDomainScreenshot(virDomainPtr domain,
                       virStreamPtr stream,
                       unsigned int screen G_GNUC_UNUSED,
                       unsigned int flags)
{
    char uuid_string[VIR_UUID_STRING_BUFLEN];
    hypervPrivate *priv = domain->conn->privateData;
    g_auto(virBuffer) query = VIR_BUFFER_INITIALIZER;
    g_autoptr(hypervInvokeParamsList) params = NULL;
    g_auto(WsXmlDocH) ret_doc = NULL;
    int xRes = 640;
    int yRes = 480;
    g_autofree char *width = NULL;
    g_autofree char *height = NULL;
    g_autofree char *imageDataText = NULL;
    g_autofree unsigned char *imageDataBuffer = NULL;
    size_t imageDataBufferSize;
    const char *temporaryDirectory = NULL;
    g_autofree char *temporaryFile = NULL;
    g_autofree uint8_t *ppmBuffer = NULL;
    char *result = NULL;
    const char *xpath = "/s:Envelope/s:Body/p:GetVirtualSystemThumbnailImage_OUTPUT/p:ImageData";
    int pixelCount;
    int pixelByteCount;
    size_t i = 0;
    int fd = -1;
    bool unlinkTemporaryFile = false;

    virCheckFlags(0, NULL);

    virUUIDFormat(domain->uuid, uuid_string);

    /* Hyper-V Generation 1 VMs use two video heads:
     *  - S3DisplayController is used for early boot screens.
     *  - SyntheticDisplayController takes over when the guest OS initializes its video driver.
     *
     * This attempts to get the resolution from the SyntheticDisplayController first.
     * If that fails, it falls back to S3DisplayController. */
    if (hypervGetVideoResolution(priv, uuid_string, &xRes, &yRes, false) < 0) {
        if (hypervGetVideoResolution(priv, uuid_string, &xRes, &yRes, true) < 0)
            goto cleanup;
    }

    /* prepare params */
    params = hypervCreateInvokeParamsList("GetVirtualSystemThumbnailImage",
                                          MSVM_VIRTUALSYSTEMMANAGEMENTSERVICE_SELECTOR,
                                          Msvm_VirtualSystemManagementService_WmiInfo);
    if (!params)
        goto cleanup;

    width = g_strdup_printf("%d", xRes);
    hypervAddSimpleParam(params, "WidthPixels", width);

    height = g_strdup_printf("%d", yRes);
    hypervAddSimpleParam(params, "HeightPixels", height);

    virBufferAsprintf(&query,
                      "ASSOCIATORS OF "
                      "{Msvm_ComputerSystem.CreationClassName='Msvm_ComputerSystem',Name='%s'} "
                      "WHERE ResultClass = Msvm_VirtualSystemSettingData",
                      uuid_string);
    hypervAddEprParam(params, "TargetSystem", &query, Msvm_VirtualSystemSettingData_WmiInfo);

    /* capture and parse the screenshot */
    if (hypervInvokeMethod(priv, &params, &ret_doc) < 0)
        goto cleanup;

    if (!ws_xml_get_soap_envelope(ret_doc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Could not retrieve screenshot"));
        goto cleanup;
    }

    imageDataText = ws_xml_get_xpath_value(ret_doc, (char *)xpath);

    if (!imageDataText) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Failed to retrieve image data"));
        goto cleanup;
    }

    imageDataBuffer = g_base64_decode(imageDataText, &imageDataBufferSize);

    pixelCount = imageDataBufferSize / 2;
    pixelByteCount = pixelCount * 3;

    ppmBuffer = g_new0(uint8_t, pixelByteCount);

    /* convert rgb565 to rgb888 */
    for (i = 0; i < pixelCount; i++) {
        const uint16_t pixel = imageDataBuffer[i * 2] + (imageDataBuffer[i * 2 + 1] << 8);
        const uint16_t redMask = 0xF800;
        const uint16_t greenMask = 0x7E0;
        const uint16_t blueMask = 0x1F;
        const uint8_t redFive = (pixel & redMask) >> 11;
        const uint8_t greenSix = (pixel & greenMask) >> 5;
        const uint8_t blueFive = pixel & blueMask;
        ppmBuffer[i * 3] = (redFive * 527 + 23) >> 6;
        ppmBuffer[i * 3 + 1] = (greenSix * 259 + 33) >> 6;
        ppmBuffer[i * 3 + 2] = (blueFive * 527 + 23) >> 6;
    }

    temporaryDirectory = getenv("TMPDIR");
    if (!temporaryDirectory)
        temporaryDirectory = "/tmp";
    temporaryFile = g_strdup_printf("%s/libvirt.hyperv.screendump.XXXXXX", temporaryDirectory);
    if ((fd = g_mkstemp_full(temporaryFile, O_RDWR | O_CLOEXEC, S_IRUSR | S_IWUSR)) == -1) {
        virReportSystemError(errno, _("g_mkstemp(\"%1$s\") failed"), temporaryFile);
        goto cleanup;
    }
    unlinkTemporaryFile = true;

    /* write image data */
    dprintf(fd, "P6\n%d %d\n255\n", xRes, yRes);
    if (safewrite(fd, ppmBuffer, pixelByteCount) != pixelByteCount) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Failed to write pixel data"));
        goto cleanup;
    }

    if (VIR_CLOSE(fd) < 0)
        virReportSystemError(errno, "%s", _("failed to close screenshot file"));

    if (virFDStreamOpenFile(stream, temporaryFile, 0, 0, O_RDONLY) < 0)
        goto cleanup;

    result = g_strdup("image/x-portable-pixmap");

 cleanup:
    VIR_FORCE_CLOSE(fd);
    if (unlinkTemporaryFile)
        unlink(temporaryFile);

    return result;
}


static int
hypervDomainSetVcpusFlags(virDomainPtr domain,
                          unsigned int nvcpus,
                          unsigned int flags)
{
    char uuid_string[VIR_UUID_STRING_BUFLEN];
    hypervPrivate *priv = domain->conn->privateData;
    g_autoptr(Msvm_VirtualSystemSettingData) vssd = NULL;
    g_autoptr(Msvm_ProcessorSettingData) proc_sd = NULL;
    g_autoptr(GHashTable) vcpuResource = NULL;
    g_autofree char *nvcpus_str = g_strdup_printf("%u", nvcpus);

    virCheckFlags(0, -1);

    virUUIDFormat(domain->uuid, uuid_string);

    if (hypervGetMsvmVirtualSystemSettingDataFromUUID(priv, uuid_string, &vssd) < 0)
        return -1;

    if (hypervGetProcessorSD(priv, vssd->data->InstanceID, &proc_sd) < 0)
        return -1;

    vcpuResource = hypervCreateEmbeddedParam(Msvm_ProcessorSettingData_WmiInfo);
    if (!vcpuResource)
        return -1;

    if (hypervSetEmbeddedProperty(vcpuResource, "VirtualQuantity", nvcpus_str) < 0)
        return -1;

    if (hypervSetEmbeddedProperty(vcpuResource, "InstanceID", proc_sd->data->InstanceID) < 0)
        return -1;

    if (hypervMsvmVSMSModifyResourceSettings(priv, &vcpuResource,
                                             Msvm_ProcessorSettingData_WmiInfo) < 0)
        return -1;

    return 0;
}


static int
hypervDomainSetVcpus(virDomainPtr domain, unsigned int nvcpus)
{
    return hypervDomainSetVcpusFlags(domain, nvcpus, 0);
}


static int
hypervDomainGetVcpusFlags(virDomainPtr domain, unsigned int flags)
{
    char uuid_string[VIR_UUID_STRING_BUFLEN];
    hypervPrivate *priv = domain->conn->privateData;
    g_autoptr(Msvm_ComputerSystem) computerSystem = NULL;
    g_autoptr(Msvm_ProcessorSettingData) proc_sd = NULL;
    g_autoptr(Msvm_VirtualSystemSettingData) vssd = NULL;

    virCheckFlags(VIR_DOMAIN_VCPU_LIVE |
                  VIR_DOMAIN_VCPU_CONFIG |
                  VIR_DOMAIN_VCPU_MAXIMUM, -1);

    virUUIDFormat(domain->uuid, uuid_string);

    /* Start by getting the Msvm_ComputerSystem */
    if (hypervMsvmComputerSystemFromDomain(domain, &computerSystem) < 0)
        return -1;

    /* Check @flags to see if we are to query a running domain, and fail
     * if that domain is not running */
    if (flags & VIR_DOMAIN_VCPU_LIVE &&
        computerSystem->data->EnabledState != MSVM_COMPUTERSYSTEM_ENABLEDSTATE_ENABLED) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s", _("Domain is not active"));
        return -1;
    }

    /* Check @flags to see if we are to return the maximum vCPU limit */
    if (flags & VIR_DOMAIN_VCPU_MAXIMUM)
        return hypervConnectGetMaxVcpus(domain->conn, NULL);

    if (hypervGetMsvmVirtualSystemSettingDataFromUUID(priv, uuid_string, &vssd) < 0)
        return -1;

    if (hypervGetProcessorSD(priv, vssd->data->InstanceID, &proc_sd) < 0)
        return -1;

    return proc_sd->data->VirtualQuantity;
}


static int
hypervDomainGetVcpus(virDomainPtr domain,
                     virVcpuInfoPtr info,
                     int maxinfo,
                     unsigned char *cpumaps,
                     int maplen)
{
    int count = 0;
    int vcpu_number;
    hypervPrivate *priv = domain->conn->privateData;
    g_autoptr(Win32_PerfRawData_HvStats_HyperVHypervisorVirtualProcessor) vproc = NULL;

    /* Hyper-V does not allow setting CPU affinity: all cores will be used */
    if (cpumaps && maplen > 0)
        memset(cpumaps, 0xFF, maxinfo * maplen);

    for (vcpu_number = 0; vcpu_number < maxinfo; vcpu_number++) {
        g_auto(virBuffer) query = VIR_BUFFER_INITIALIZER;

        /* Name format: <domain_name>:Hv VP <vCPU_number> */
        g_autofree char *vcpu_name = g_strdup_printf("%s:Hv VP %d", domain->name, vcpu_number);

        /* try to free objects from previous iteration */
        hypervFreeObject((hypervObject *)vproc);
        vproc = NULL;

        /* get the info */
        virBufferEscapeSQL(&query,
                           WIN32_PERFRAWDATA_HVSTATS_HYPERVHYPERVISORVIRTUALPROCESSOR_WQL_SELECT
                           "WHERE Name = '%s'",
                           vcpu_name);

        if (hypervGetWmiClass(Win32_PerfRawData_HvStats_HyperVHypervisorVirtualProcessor, &vproc) < 0)
            continue;

        /* fill structure info */
        info[vcpu_number].number = vcpu_number;
        if (vproc) {
            info[vcpu_number].state = VIR_VCPU_RUNNING;
            info[vcpu_number].cpuTime = vproc->data->PercentTotalRunTime * 100;
            info[vcpu_number].cpu = VIR_VCPU_INFO_CPU_UNAVAILABLE;
        } else {
            info[vcpu_number].state = VIR_VCPU_OFFLINE;
            info[vcpu_number].cpuTime = 0LLU;
            info[vcpu_number].cpu = VIR_VCPU_INFO_CPU_OFFLINE;
        }
        count++;
    }

    return count;
}


static char *
hypervDomainGetXMLDesc(virDomainPtr domain, unsigned int flags)
{
    hypervPrivate *priv = domain->conn->privateData;
    g_autoptr(virDomainDef) def = NULL;
    char uuid_string[VIR_UUID_STRING_BUFLEN];
    g_autoptr(Msvm_ComputerSystem) computerSystem = NULL;
    g_autoptr(Msvm_VirtualSystemSettingData) virtualSystemSettingData = NULL;
    g_autoptr(Msvm_ProcessorSettingData) processorSettingData = NULL;
    g_autoptr(Msvm_MemorySettingData) memorySettingData = NULL;
    g_autoptr(Msvm_ResourceAllocationSettingData) rasd = NULL;
    g_autoptr(Msvm_StorageAllocationSettingData) sasd = NULL;
    g_autoptr(Msvm_SerialPortSettingData) spsd = NULL;
    Msvm_ResourceAllocationSettingData *serialDevices = NULL;
    g_autoptr(Msvm_EthernetPortAllocationSettingData) nets = NULL;

    virCheckFlags(VIR_DOMAIN_XML_COMMON_FLAGS, NULL);

    if (!(def = virDomainDefNew(priv->xmlopt)))
        return NULL;

    virUUIDFormat(domain->uuid, uuid_string);

    /* Get Msvm_ComputerSystem */
    if (hypervMsvmComputerSystemFromDomain(domain, &computerSystem) < 0)
        return NULL;

    if (hypervGetMsvmVirtualSystemSettingDataFromUUID(priv, uuid_string,
                                                      &virtualSystemSettingData) < 0)
        return NULL;

    if (hypervGetProcessorSD(priv,
                             virtualSystemSettingData->data->InstanceID,
                             &processorSettingData) < 0)
        return NULL;

    if (hypervGetMemorySD(priv,
                          virtualSystemSettingData->data->InstanceID,
                          &memorySettingData) < 0)
        return NULL;

    if (hypervGetResourceAllocationSD(priv,
                                      virtualSystemSettingData->data->InstanceID,
                                      &rasd) < 0) {
        return NULL;
    }

    if (hypervGetStorageAllocationSD(priv,
                                     virtualSystemSettingData->data->InstanceID,
                                     &sasd) < 0) {
        return NULL;
    }

    if (hypervGetSerialPortSD(priv, virtualSystemSettingData->data->InstanceID, &spsd) < 0)
        return NULL;

    if (hypervGetEthernetPortAllocationSD(priv,
                                          virtualSystemSettingData->data->InstanceID, &nets) < 0)
        return NULL;

    /* Fill struct */
    def->virtType = VIR_DOMAIN_VIRT_HYPERV;

    if (hypervIsMsvmComputerSystemActive(computerSystem, NULL)) {
        def->id = computerSystem->data->ProcessID;
    } else {
        def->id = -1;
    }

    if (virUUIDParse(computerSystem->data->Name, def->uuid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not parse UUID from string '%1$s'"),
                       computerSystem->data->Name);
        return NULL;
    }

    def->name = g_strdup(computerSystem->data->ElementName);

    if (virtualSystemSettingData->data->Notes.data) {
        char **notes = (char **)virtualSystemSettingData->data->Notes.data;
        g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
        size_t i = 0;

        /* in practice Notes has 1 element */
        for (i = 0; i < virtualSystemSettingData->data->Notes.count; i++) {
            /* but if there's more than 1, separate by double new line */
            if (virBufferUse(&buf) > 0)
                virBufferAddLit(&buf, "\n\n");

            virBufferAdd(&buf, *notes, -1);
            notes++;
        }

        def->description = virBufferContentAndReset(&buf);
    }

    /* mebibytes to kibibytes */
    def->mem.max_memory = memorySettingData->data->Limit * 1024;
    def->mem.cur_balloon = memorySettingData->data->VirtualQuantity * 1024;
    virDomainDefSetMemoryTotal(def, memorySettingData->data->VirtualQuantity * 1024);

    if (virDomainDefSetVcpusMax(def, processorSettingData->data->VirtualQuantity, NULL) < 0)
        return NULL;

    if (virDomainDefSetVcpus(def, processorSettingData->data->VirtualQuantity) < 0)
        return NULL;

    def->os.type = VIR_DOMAIN_OSTYPE_HVM;

    /* Allocate space for all potential devices */

    /* 256 scsi drives + 4 ide drives */
    def->disks = g_new0(virDomainDiskDef *,
                        HYPERV_MAX_SCSI_CONTROLLERS * HYPERV_MAX_DRIVES_PER_SCSI_CONTROLLER +
                        HYPERV_MAX_IDE_CHANNELS * HYPERV_MAX_DRIVES_PER_IDE_CHANNEL);
    def->ndisks = 0;

    /* 1 ide & 4 scsi controllers */
    def->controllers = g_new0(virDomainControllerDef *, 5);
    def->ncontrollers = 0;

    /* 8 synthetic + 4 legacy NICs */
    def->nets = g_new0(virDomainNetDef *, 12);
    def->nnets = 0;

    if (hypervDomainDefParseStorage(priv, def, rasd, sasd) < 0)
        return NULL;

    if (g_str_has_prefix(priv->version, "6."))
        serialDevices = rasd;
    else
        serialDevices = (Msvm_ResourceAllocationSettingData *)spsd;

    if (hypervDomainDefParseSerial(def, serialDevices) < 0)
        return NULL;

    if (hypervDomainDefParseEthernet(domain, def, nets) < 0)
        return NULL;

    /* XXX xmlopts must be non-NULL */
    return virDomainDefFormat(def, NULL, virDomainDefFormatConvertXMLFlags(flags));
}


static int
hypervConnectListDefinedDomains(virConnectPtr conn, char **const names, int maxnames)
{
    bool success = false;
    hypervPrivate *priv = conn->privateData;
    g_autoptr(Msvm_ComputerSystem) computerSystemList = NULL;
    Msvm_ComputerSystem *computerSystem = NULL;
    int count = 0;
    size_t i;

    if (maxnames == 0)
        return 0;

    if (hypervGetInactiveVirtualSystemList(priv, &computerSystemList) < 0)
        goto cleanup;

    for (computerSystem = computerSystemList; computerSystem != NULL;
         computerSystem = computerSystem->next) {
        names[count] = g_strdup(computerSystem->data->ElementName);

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

    return count;
}


static int
hypervConnectNumOfDefinedDomains(virConnectPtr conn)
{
    hypervPrivate *priv = conn->privateData;
    g_autoptr(Msvm_ComputerSystem) computerSystemList = NULL;
    Msvm_ComputerSystem *computerSystem = NULL;
    int count = 0;

    if (hypervGetInactiveVirtualSystemList(priv, &computerSystemList) < 0)
        return -1;

    for (computerSystem = computerSystemList; computerSystem != NULL;
         computerSystem = computerSystem->next) {
        ++count;
    }

    return count;
}


static int
hypervDomainCreateWithFlags(virDomainPtr domain, unsigned int flags)
{
    g_autoptr(Msvm_ComputerSystem) computerSystem = NULL;

    virCheckFlags(0, -1);

    if (hypervMsvmComputerSystemFromDomain(domain, &computerSystem) < 0)
        return -1;

    if (hypervIsMsvmComputerSystemActive(computerSystem, NULL)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Domain is already active or is in state transition"));
        return -1;
    }

    return hypervInvokeMsvmComputerSystemRequestStateChange(domain,
                                                            MSVM_COMPUTERSYSTEM_REQUESTEDSTATE_ENABLED);
}


static int
hypervDomainCreate(virDomainPtr domain)
{
    return hypervDomainCreateWithFlags(domain, 0);
}


static int
hypervDomainUndefineFlags(virDomainPtr domain, unsigned int flags)
{
    char uuid_string[VIR_UUID_STRING_BUFLEN];
    hypervPrivate *priv = domain->conn->privateData;
    g_autoptr(hypervInvokeParamsList) params = NULL;
    g_auto(virBuffer) eprQuery = VIR_BUFFER_INITIALIZER;

    virCheckFlags(0, -1);

    virUUIDFormat(domain->uuid, uuid_string);

    /* prepare params */
    params = hypervCreateInvokeParamsList("DestroySystem",
                                          MSVM_VIRTUALSYSTEMMANAGEMENTSERVICE_SELECTOR,
                                          Msvm_VirtualSystemManagementService_WmiInfo);

    if (!params)
        return -1;

    virBufferEscapeSQL(&eprQuery, MSVM_COMPUTERSYSTEM_WQL_SELECT "WHERE Name = '%s'", uuid_string);

    if (hypervAddEprParam(params, "AffectedSystem", &eprQuery, Msvm_ComputerSystem_WmiInfo) < 0)
        return -1;

    /* actually destroy the VM */
    if (hypervInvokeMethod(priv, &params, NULL) < 0)
        return -1;

    return 0;
}


static int
hypervDomainUndefine(virDomainPtr domain)
{
    return hypervDomainUndefineFlags(domain, 0);
}


static virDomainPtr
hypervDomainDefineXML(virConnectPtr conn, const char *xml)
{
    hypervPrivate *priv = conn->privateData;
    g_autofree char *hostname = hypervConnectGetHostname(conn);
    g_autoptr(virDomainDef) def = NULL;
    virDomainPtr domain = NULL;
    g_autoptr(hypervInvokeParamsList) params = NULL;
    g_autoptr(GHashTable) defineSystemParam = NULL;
    size_t i = 0;

    /* parse xml */
    def = virDomainDefParseString(xml, priv->xmlopt, NULL,
                                  1 << VIR_DOMAIN_VIRT_HYPERV | VIR_DOMAIN_XML_INACTIVE);

    if (!def)
        goto error;

    /* abort if a domain with this UUID already exists */
    if ((domain = hypervDomainLookupByUUID(conn, def->uuid))) {
        char uuid_string[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(domain->uuid, uuid_string);
        virReportError(VIR_ERR_DOM_EXIST, _("Domain already exists with UUID '%1$s'"), uuid_string);

        // Don't use the 'exit' label, since we don't want to delete the existing domain.
        virObjectUnref(domain);
        return NULL;
    }

    /* prepare params: only set the VM's name for now */
    params = hypervCreateInvokeParamsList("DefineSystem",
                                          MSVM_VIRTUALSYSTEMMANAGEMENTSERVICE_SELECTOR,
                                          Msvm_VirtualSystemManagementService_WmiInfo);

    if (!params)
        goto error;

    defineSystemParam = hypervCreateEmbeddedParam(Msvm_VirtualSystemSettingData_WmiInfo);

    if (hypervSetEmbeddedProperty(defineSystemParam, "ElementName", def->name) < 0)
        goto error;

    if (hypervAddEmbeddedParam(params, "SystemSettings",
                               &defineSystemParam, Msvm_VirtualSystemSettingData_WmiInfo) < 0)
        goto error;

    /* create the VM */
    if (hypervInvokeMethod(priv, &params, NULL) < 0)
        goto error;

    /* populate a domain ptr so that we can edit it */
    domain = hypervDomainLookupByName(conn, def->name);

    /* set domain vcpus */
    if (def->vcpus && hypervDomainSetVcpus(domain, def->maxvcpus) < 0)
        goto error;

    /* set VM maximum memory */
    if (def->mem.max_memory > 0 && hypervDomainSetMaxMemory(domain, def->mem.max_memory) < 0)
        goto error;

    /* set VM memory */
    if (def->mem.cur_balloon > 0 && hypervDomainSetMemory(domain, def->mem.cur_balloon) < 0)
        goto error;

    /* attach all storage */
    if (hypervDomainAttachStorage(domain, def, hostname) < 0)
        goto error;

    /* Attach serials */
    for (i = 0; i < def->nserials; i++) {
        if (hypervDomainAttachSerial(domain, def->serials[i]) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, _("Could not attach serial port %1$zu"), i);
            goto error;
        }
    }

    /* Attach networks */
    for (i = 0; i < def->nnets; i++) {
        if (hypervDomainAttachSyntheticEthernetAdapter(domain, def->nets[i], hostname) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, _("Could not attach network %1$zu"), i);
            goto error;
        }
    }

    return domain;

 error:
    VIR_DEBUG("Domain creation failed, rolling back");
    if (domain)
        hypervDomainUndefine(domain);

    return NULL;
}


static int
hypervDomainAttachDeviceFlags(virDomainPtr domain, const char *xml, unsigned int flags)
{
    hypervPrivate *priv = domain->conn->privateData;
    g_autoptr(virDomainDef) def = NULL;
    g_autoptr(virDomainDeviceDef) dev = NULL;
    g_autoptr(Win32_ComputerSystem) host = NULL;
    char *hostname = NULL;
    char uuid_string[VIR_UUID_STRING_BUFLEN];
    Msvm_ResourceAllocationSettingData *controller = NULL;
    g_autoptr(Msvm_ResourceAllocationSettingData) rasd = NULL;
    Msvm_ResourceAllocationSettingData *entry = NULL;
    g_autoptr(Msvm_VirtualSystemSettingData) vssd = NULL;
    int num_scsi = 0;

    virCheckFlags(0, -1);

    virUUIDFormat(domain->uuid, uuid_string);

    /* get domain definition */
    if (!(def = virDomainDefNew(priv->xmlopt)))
        return -1;

    /* get domain device definition */
    dev = virDomainDeviceDefParse(xml, def, priv->xmlopt, NULL, VIR_DOMAIN_DEF_PARSE_INACTIVE);
    if (!dev)
        return -1;

    /* get the host computer system */
    if (hypervGetPhysicalSystemList(priv, &host) < 0)
        return -1;

    hostname = host->data->Name;

    switch (dev->type) {
    case VIR_DOMAIN_DEVICE_DISK:
        /* get our controller */
        if (hypervGetMsvmVirtualSystemSettingDataFromUUID(priv, uuid_string, &vssd) < 0)
            return -1;

        if (hypervGetResourceAllocationSD(priv, vssd->data->InstanceID, &rasd) < 0)
            return -1;

        entry = rasd;
        switch (dev->data.disk->bus) {
        case VIR_DOMAIN_DISK_BUS_IDE:
            while (entry) {
                if (entry->data->ResourceType == MSVM_RASD_RESOURCETYPE_IDE_CONTROLLER &&
                    (entry->data->Address[0] - '0') == dev->data.disk->info.addr.drive.controller) {
                    controller = entry;
                    break;
                }
                entry = entry->next;
            }
            if (!entry)
                return -1;
            break;
        case VIR_DOMAIN_DISK_BUS_SCSI:
            while (entry) {
                if (entry->data->ResourceType == MSVM_RASD_RESOURCETYPE_PARALLEL_SCSI_HBA &&
                    num_scsi++ == dev->data.disk->info.addr.drive.controller) {
                    controller = entry;
                    break;
                }
                entry = entry->next;
            }
            if (!entry)
                return -1;
            break;
        case VIR_DOMAIN_DISK_BUS_FDC:
            while (entry) {
                if (entry->data->ResourceType == MSVM_RASD_RESOURCETYPE_DISKETTE_DRIVE) {
                    controller = entry;
                    break;
                }
                entry = entry->next;
            }
            if (!entry)
                return -1;
            break;
        case VIR_DOMAIN_DISK_BUS_NONE:
        case VIR_DOMAIN_DISK_BUS_VIRTIO:
        case VIR_DOMAIN_DISK_BUS_XEN:
        case VIR_DOMAIN_DISK_BUS_USB:
        case VIR_DOMAIN_DISK_BUS_UML:
        case VIR_DOMAIN_DISK_BUS_SATA:
        case VIR_DOMAIN_DISK_BUS_SD:
        case VIR_DOMAIN_DISK_BUS_LAST:
        default:
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid disk bus in definition"));
            return -1;
        }

        if (hypervDomainAttachStorageVolume(domain, dev->data.disk, controller, hostname) < 0)
            return -1;
        break;
    case VIR_DOMAIN_DEVICE_CHR:
        if (hypervDomainAttachSerial(domain, dev->data.chr) < 0)
            return -1;
        break;
    case VIR_DOMAIN_DEVICE_NET:
        if (hypervDomainAttachSyntheticEthernetAdapter(domain, dev->data.net, hostname) < 0)
            return -1;
        break;

    case VIR_DOMAIN_DEVICE_LEASE:
    case VIR_DOMAIN_DEVICE_FS:
    case VIR_DOMAIN_DEVICE_INPUT:
    case VIR_DOMAIN_DEVICE_SOUND:
    case VIR_DOMAIN_DEVICE_VIDEO:
    case VIR_DOMAIN_DEVICE_HOSTDEV:
    case VIR_DOMAIN_DEVICE_WATCHDOG:
    case VIR_DOMAIN_DEVICE_CONTROLLER:
    case VIR_DOMAIN_DEVICE_GRAPHICS:
    case VIR_DOMAIN_DEVICE_HUB:
    case VIR_DOMAIN_DEVICE_REDIRDEV:
    case VIR_DOMAIN_DEVICE_NONE:
    case VIR_DOMAIN_DEVICE_SMARTCARD:
    case VIR_DOMAIN_DEVICE_MEMBALLOON:
    case VIR_DOMAIN_DEVICE_NVRAM:
    case VIR_DOMAIN_DEVICE_LAST:
    case VIR_DOMAIN_DEVICE_RNG:
    case VIR_DOMAIN_DEVICE_TPM:
    case VIR_DOMAIN_DEVICE_PANIC:
    case VIR_DOMAIN_DEVICE_SHMEM:
    case VIR_DOMAIN_DEVICE_MEMORY:
    case VIR_DOMAIN_DEVICE_IOMMU:
    case VIR_DOMAIN_DEVICE_VSOCK:
    case VIR_DOMAIN_DEVICE_AUDIO:
    case VIR_DOMAIN_DEVICE_CRYPTO:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Attaching devices of type %1$d is not implemented"), dev->type);
        return -1;
    }

    return 0;
}


static int
hypervDomainAttachDevice(virDomainPtr domain, const char *xml)
{
    return hypervDomainAttachDeviceFlags(domain, xml, 0);
}


static int
hypervDomainGetAutostart(virDomainPtr domain, int *autostart)
{
    char uuid_string[VIR_UUID_STRING_BUFLEN];
    hypervPrivate *priv = domain->conn->privateData;
    g_autoptr(Msvm_VirtualSystemSettingData) vssd = NULL;

    virUUIDFormat(domain->uuid, uuid_string);

    if (hypervGetMsvmVirtualSystemSettingDataFromUUID(priv, uuid_string, &vssd) < 0)
        return -1;

    *autostart = vssd->data->AutomaticStartupAction == 4;

    return 0;
}


static int
hypervDomainSetAutostart(virDomainPtr domain, int autostart)
{
    char uuid_string[VIR_UUID_STRING_BUFLEN];
    hypervPrivate *priv = domain->conn->privateData;
    g_autoptr(Msvm_VirtualSystemSettingData) vssd = NULL;
    g_autoptr(hypervInvokeParamsList) params = NULL;
    g_autoptr(GHashTable) autostartParam = NULL;

    virUUIDFormat(domain->uuid, uuid_string);

    if (hypervGetMsvmVirtualSystemSettingDataFromUUID(priv, uuid_string, &vssd) < 0)
        return -1;

    params = hypervCreateInvokeParamsList("ModifySystemSettings",
                                          MSVM_VIRTUALSYSTEMMANAGEMENTSERVICE_SELECTOR,
                                          Msvm_VirtualSystemManagementService_WmiInfo);

    if (!params)
        return -1;

    autostartParam = hypervCreateEmbeddedParam(Msvm_VirtualSystemSettingData_WmiInfo);

    if (hypervSetEmbeddedProperty(autostartParam, "AutomaticStartupAction",
                                  autostart ? "4" : "2") < 0)
        return -1;

    if (hypervSetEmbeddedProperty(autostartParam, "InstanceID", vssd->data->InstanceID) < 0)
        return -1;

    if (hypervAddEmbeddedParam(params, "SystemSettings",
                               &autostartParam, Msvm_VirtualSystemSettingData_WmiInfo) < 0)
        return -1;

    if (hypervInvokeMethod(priv, &params, NULL) < 0)
        return -1;

    return 0;
}


static char *
hypervDomainGetSchedulerType(virDomainPtr domain G_GNUC_UNUSED, int *nparams)
{
    if (nparams)
        *nparams = 3; /* reservation, limit, weight */

    return g_strdup("allocation");
}


static int
hypervDomainGetSchedulerParametersFlags(virDomainPtr domain,
                                        virTypedParameterPtr params,
                                        int *nparams, unsigned int flags)
{
    hypervPrivate *priv = domain->conn->privateData;
    g_autoptr(Msvm_ComputerSystem) computerSystem = NULL;
    g_autoptr(Msvm_VirtualSystemSettingData) vssd = NULL;
    g_autoptr(Msvm_ProcessorSettingData) proc_sd = NULL;
    char uuid_string[VIR_UUID_STRING_BUFLEN];
    int saved_nparams = 0;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE | VIR_DOMAIN_AFFECT_CONFIG, -1);

    if (hypervMsvmComputerSystemFromDomain(domain, &computerSystem) < 0)
        return -1;

    /* get info from host */
    virUUIDFormat(domain->uuid, uuid_string);

    if (hypervGetMsvmVirtualSystemSettingDataFromUUID(priv, uuid_string, &vssd) < 0)
        return -1;

    if (hypervGetProcessorSD(priv, vssd->data->InstanceID, &proc_sd) < 0)
        return -1;

    /* parse it all out */
    if (virTypedParameterAssign(&params[0], VIR_DOMAIN_SCHEDULER_LIMIT,
                                VIR_TYPED_PARAM_LLONG, proc_sd->data->Limit) < 0)
        return -1;
    saved_nparams++;

    if (*nparams > saved_nparams) {
        if (virTypedParameterAssign(&params[1], VIR_DOMAIN_SCHEDULER_RESERVATION,
                                    VIR_TYPED_PARAM_LLONG, proc_sd->data->Reservation) < 0)
            return -1;
        saved_nparams++;
    }

    if (*nparams > saved_nparams) {
        if (virTypedParameterAssign(&params[2], VIR_DOMAIN_SCHEDULER_WEIGHT,
                                    VIR_TYPED_PARAM_UINT, proc_sd->data->Weight) < 0)
            return -1;
        saved_nparams++;
    }

    *nparams = saved_nparams;

    return 0;
}


static int
hypervDomainGetSchedulerParameters(virDomainPtr domain,
                                   virTypedParameterPtr params,
                                   int *nparams)
{
    return hypervDomainGetSchedulerParametersFlags(domain, params, nparams,
                                                   VIR_DOMAIN_AFFECT_CURRENT);
}


static unsigned long long
hypervNodeGetFreeMemory(virConnectPtr conn)
{
    hypervPrivate *priv = conn->privateData;
    g_autoptr(Win32_OperatingSystem) operatingSystem = NULL;

    if (hypervGetOperatingSystem(priv, &operatingSystem) < 0)
        return 0;

    if (!operatingSystem) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not get free memory for host %1$s"),
                       conn->uri->server);
        return 0;
    }

    return operatingSystem->data->FreePhysicalMemory * 1024;
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
    g_autoptr(Msvm_ComputerSystem) computerSystem = NULL;

    if (hypervMsvmComputerSystemFromDomain(domain, &computerSystem) < 0)
        return -1;

    return hypervIsMsvmComputerSystemActive(computerSystem, NULL) ? 1 : 0;
}


static int
hypervDomainGetMaxVcpus(virDomainPtr dom)
{
    if (hypervDomainIsActive(dom))
        return hypervDomainGetVcpusFlags(dom, (VIR_DOMAIN_VCPU_LIVE | VIR_DOMAIN_VCPU_MAXIMUM));
    else
        return hypervConnectGetMaxVcpus(dom->conn, NULL);
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
    g_autoptr(Msvm_ComputerSystem) computerSystem = NULL;
    bool in_transition = false;

    virCheckFlags(0, -1);

    if (hypervMsvmComputerSystemFromDomain(domain, &computerSystem) < 0)
        return -1;

    if (!hypervIsMsvmComputerSystemActive(computerSystem, &in_transition) ||
        in_transition) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Domain is not active or is in state transition"));
        return -1;
    }

    return hypervInvokeMsvmComputerSystemRequestStateChange(domain, MSVM_COMPUTERSYSTEM_REQUESTEDSTATE_OFFLINE);
}


static int
hypervDomainHasManagedSaveImage(virDomainPtr domain, unsigned int flags)
{
    g_autoptr(Msvm_ComputerSystem) computerSystem = NULL;

    virCheckFlags(0, -1);

    if (hypervMsvmComputerSystemFromDomain(domain, &computerSystem) < 0)
        return -1;

    return computerSystem->data->EnabledState == MSVM_COMPUTERSYSTEM_ENABLEDSTATE_SUSPENDED ? 1 : 0;
}


static int
hypervDomainManagedSaveRemove(virDomainPtr domain, unsigned int flags)
{
    g_autoptr(Msvm_ComputerSystem) computerSystem = NULL;

    virCheckFlags(0, -1);

    if (hypervMsvmComputerSystemFromDomain(domain, &computerSystem) < 0)
        return -1;

    if (computerSystem->data->EnabledState != MSVM_COMPUTERSYSTEM_ENABLEDSTATE_SUSPENDED) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Domain has no managed save image"));
        return -1;
    }

    return hypervInvokeMsvmComputerSystemRequestStateChange(domain,
                                                            MSVM_COMPUTERSYSTEM_REQUESTEDSTATE_DISABLED);
}


#define MATCH(FLAG) (flags & (FLAG))
static int
hypervConnectListAllDomains(virConnectPtr conn,
                            virDomainPtr **domains,
                            unsigned int flags)
{
    hypervPrivate *priv = conn->privateData;
    g_auto(virBuffer) query = VIR_BUFFER_INITIALIZER;
    g_autoptr(Msvm_ComputerSystem) computerSystemList = NULL;
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

    virBufferAddLit(&query,
                    MSVM_COMPUTERSYSTEM_WQL_SELECT
                    "WHERE " MSVM_COMPUTERSYSTEM_WQL_VIRTUAL);

    /* construct query with filter depending on flags */
    if (!(MATCH(VIR_CONNECT_LIST_DOMAINS_ACTIVE) &&
          MATCH(VIR_CONNECT_LIST_DOMAINS_INACTIVE))) {
        if (MATCH(VIR_CONNECT_LIST_DOMAINS_ACTIVE)) {
            virBufferAddLit(&query, "AND " MSVM_COMPUTERSYSTEM_WQL_ACTIVE);
        }

        if (MATCH(VIR_CONNECT_LIST_DOMAINS_INACTIVE)) {
            virBufferAddLit(&query, "AND " MSVM_COMPUTERSYSTEM_WQL_INACTIVE);
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
            bool mansave = computerSystem->data->EnabledState ==
                           MSVM_COMPUTERSYSTEM_ENABLEDSTATE_SUSPENDED;

            if (!((MATCH(VIR_CONNECT_LIST_DOMAINS_MANAGEDSAVE) && mansave) ||
                  (MATCH(VIR_CONNECT_LIST_DOMAINS_NO_MANAGEDSAVE) && !mansave)))
                continue;
        }

        if (!doms) {
            count++;
            continue;
        }

        VIR_RESIZE_N(doms, ndoms, count, 2);

        domain = NULL;

        if (hypervMsvmComputerSystemToDomain(conn, computerSystem,
                                             &domain) < 0)
            goto cleanup;

        doms[count++] = domain;
    }

    if (doms)
        *domains = g_steal_pointer(&doms);
    ret = count;

 cleanup:
    if (doms) {
        for (i = 0; i < count; ++i)
            virObjectUnref(doms[i]);

        VIR_FREE(doms);
    }

    return ret;
}
#undef MATCH


static int
hypervDomainSendKey(virDomainPtr domain, unsigned int codeset,
                    unsigned int holdtime, unsigned int *keycodes, int nkeycodes,
                    unsigned int flags)
{
    size_t i = 0;
    int keycode = 0;
    g_autofree int *translatedKeycodes = NULL;
    hypervPrivate *priv = domain->conn->privateData;
    char uuid_string[VIR_UUID_STRING_BUFLEN];
    g_autofree char *selector = NULL;
    g_autoptr(Msvm_ComputerSystem) computerSystem = NULL;
    g_autoptr(Msvm_Keyboard) keyboard = NULL;
    g_auto(virBuffer) query = VIR_BUFFER_INITIALIZER;
    g_autoptr(hypervInvokeParamsList) params = NULL;
    char keycodeStr[VIR_INT64_STR_BUFLEN];

    virCheckFlags(0, -1);

    virUUIDFormat(domain->uuid, uuid_string);

    if (hypervMsvmComputerSystemFromDomain(domain, &computerSystem) < 0)
        return -1;

    virBufferEscapeSQL(&query,
                       "ASSOCIATORS OF {Msvm_ComputerSystem.CreationClassName='Msvm_ComputerSystem',Name='%s'} "
                       "WHERE ResultClass = Msvm_Keyboard",
                       uuid_string);

    if (hypervGetWmiClass(Msvm_Keyboard, &keyboard) < 0)
        return -1;

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
                return -1;
            }
            translatedKeycodes[i] = keycode;
        }
    }

    selector = g_strdup_printf("CreationClassName=Msvm_Keyboard&DeviceID=%s&"
                               "SystemCreationClassName=Msvm_ComputerSystem&"
                               "SystemName=%s", keyboard->data->DeviceID, uuid_string);

    /* press the keys */
    for (i = 0; i < nkeycodes; i++) {
        g_snprintf(keycodeStr, sizeof(keycodeStr), "%d", translatedKeycodes[i]);

        params = hypervCreateInvokeParamsList("PressKey", selector,
                                              Msvm_Keyboard_WmiInfo);

        if (!params)
            return -1;

        if (hypervAddSimpleParam(params, "keyCode", keycodeStr) < 0)
            return -1;

        if (hypervInvokeMethod(priv, &params, NULL) < 0)
            return -1;
    }

    /* simulate holdtime by sleeping */
    if (holdtime > 0)
        g_usleep(holdtime * 1000);

    /* release the keys */
    for (i = 0; i < nkeycodes; i++) {
        g_snprintf(keycodeStr, sizeof(keycodeStr), "%d", translatedKeycodes[i]);
        params = hypervCreateInvokeParamsList("ReleaseKey", selector,
                                              Msvm_Keyboard_WmiInfo);

        if (!params)
            return -1;

        if (hypervAddSimpleParam(params, "keyCode", keycodeStr) < 0)
            return -1;

        if (hypervInvokeMethod(priv, &params, NULL) < 0)
            return -1;
    }

    return 0;
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
    .domainGetMaxMemory = hypervDomainGetMaxMemory, /* 6.10.0 */
    .domainSetMaxMemory = hypervDomainSetMaxMemory, /* 6.10.0 */
    .domainSetMemory = hypervDomainSetMemory, /* 3.6.0 */
    .domainSetMemoryFlags = hypervDomainSetMemoryFlags, /* 3.6.0 */
    .domainGetInfo = hypervDomainGetInfo, /* 0.9.5 */
    .domainGetState = hypervDomainGetState, /* 0.9.5 */
    .domainScreenshot = hypervDomainScreenshot, /* 7.1.0 */
    .domainSetVcpus = hypervDomainSetVcpus, /* 6.10.0 */
    .domainSetVcpusFlags = hypervDomainSetVcpusFlags, /* 6.10.0 */
    .domainGetVcpusFlags = hypervDomainGetVcpusFlags, /* 6.10.0 */
    .domainGetVcpus = hypervDomainGetVcpus, /* 6.10.0 */
    .domainGetMaxVcpus = hypervDomainGetMaxVcpus, /* 6.10.0 */
    .domainGetXMLDesc = hypervDomainGetXMLDesc, /* 0.9.5 */
    .connectListDefinedDomains = hypervConnectListDefinedDomains, /* 0.9.5 */
    .connectNumOfDefinedDomains = hypervConnectNumOfDefinedDomains, /* 0.9.5 */
    .domainCreate = hypervDomainCreate, /* 0.9.5 */
    .domainCreateWithFlags = hypervDomainCreateWithFlags, /* 0.9.5 */
    .domainDefineXML = hypervDomainDefineXML, /* 7.1.0 */
    .domainUndefine = hypervDomainUndefine, /* 7.1.0 */
    .domainUndefineFlags = hypervDomainUndefineFlags, /* 7.1.0 */
    .domainAttachDevice = hypervDomainAttachDevice, /* 7.1.0 */
    .domainAttachDeviceFlags = hypervDomainAttachDeviceFlags, /* 7.1.0 */
    .domainGetAutostart = hypervDomainGetAutostart, /* 6.9.0 */
    .domainSetAutostart = hypervDomainSetAutostart, /* 6.9.0 */
    .domainGetSchedulerType = hypervDomainGetSchedulerType, /* 6.10.0 */
    .domainGetSchedulerParameters = hypervDomainGetSchedulerParameters, /* 6.10.0 */
    .domainGetSchedulerParametersFlags = hypervDomainGetSchedulerParametersFlags, /* 6.10.0 */
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
    .connectIsAlive = hypervConnectIsAlive, /* 0.9.8 */
};


virDomainDefParserConfig hypervDomainDefParserConfig = {
    .features = VIR_DOMAIN_DEF_FEATURE_MEMORY_HOTPLUG,
};


static void
hypervDebugHandler(const char *message, debug_level_e level,
                   void *user_data G_GNUC_UNUSED)
{
    switch (level) {
    case DEBUG_LEVEL_ERROR:
    case DEBUG_LEVEL_CRITICAL:
    case DEBUG_LEVEL_ALWAYS:
        VIR_ERROR(_("openwsman: %1$s"), message);
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
    .networkDriver = &hypervNetworkDriver,
};

int
hypervRegister(void)
{
    /* Forward openwsman errors and warnings to libvirt's logging */
    debug_add_handler(hypervDebugHandler, DEBUG_LEVEL_WARNING, NULL);

    return virRegisterConnectDriver(&hypervConnectDriver,
                                    false);
}
