/*
 * esx_vi.h: client for the VMware VI API 2.5 to manage ESX hosts
 *
 * Copyright (C) 2011 Red Hat, Inc.
 * Copyright (C) 2009-2012 Matthias Bolte <matthias.bolte@googlemail.com>
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

#ifndef __ESX_VI_H__
# define __ESX_VI_H__

# include <libxml/tree.h>
# include <libxml/xpath.h>
# include <curl/curl.h>

# include "internal.h"
# include "virerror.h"
# include "datatypes.h"
# include "esx_vi_types.h"
# include "esx_util.h"


# define ESX_VI__SOAP__REQUEST_HEADER                                         \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"                            \
    "<soapenv:Envelope\n"                                                     \
    " xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\"\n"          \
    " xmlns:soapenc=\"http://schemas.xmlsoap.org/soap/encoding/\"\n"          \
    " xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\n"              \
    " xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\">\n"                      \
    "<soapenv:Body>\n"



# define ESX_VI__SOAP__REQUEST_FOOTER                                         \
    "</soapenv:Body>\n"                                                       \
    "</soapenv:Envelope>"



# define ESV_VI__XML_TAG__OPEN(_buffer, _element, _type)                      \
    do {                                                                      \
        virBufferAddLit(_buffer, "<");                                        \
        virBufferAdd(_buffer, _element, -1);                                  \
        virBufferAddLit(_buffer, " xmlns=\"urn:vim25\" xsi:type=\"");         \
        virBufferAdd(_buffer, _type, -1);                                     \
        virBufferAddLit(_buffer, "\">");                                      \
    } while (0)



# define ESV_VI__XML_TAG__CLOSE(_buffer, _element)                            \
    do {                                                                      \
        virBufferAddLit(_buffer, "</");                                       \
        virBufferAdd(_buffer, _element, -1);                                  \
        virBufferAddLit(_buffer, ">");                                        \
    } while (0)



typedef enum _esxVI_APIVersion esxVI_APIVersion;
typedef enum _esxVI_ProductVersion esxVI_ProductVersion;
typedef enum _esxVI_Occurrence esxVI_Occurrence;
typedef struct _esxVI_ParsedHostCpuIdInfo esxVI_ParsedHostCpuIdInfo;
typedef struct _esxVI_CURL esxVI_CURL;
typedef struct _esxVI_SharedCURL esxVI_SharedCURL;
typedef struct _esxVI_MultiCURL esxVI_MultiCURL;
typedef struct _esxVI_Context esxVI_Context;
typedef struct _esxVI_Response esxVI_Response;
typedef struct _esxVI_Enumeration esxVI_Enumeration;
typedef struct _esxVI_EnumerationValue esxVI_EnumerationValue;
typedef struct _esxVI_List esxVI_List;



enum _esxVI_APIVersion {
    esxVI_APIVersion_Undefined = 0,
    esxVI_APIVersion_Unknown,
    esxVI_APIVersion_25,
    esxVI_APIVersion_40,
    esxVI_APIVersion_41,
    esxVI_APIVersion_4x, /* > 4.1 */
    esxVI_APIVersion_50,
    esxVI_APIVersion_51,
    esxVI_APIVersion_5x  /* > 5.1 */
};

/*
 * AAAABBBB: where AAAA0000 is the product and BBBB the version. this format
 * allows simple bitmask testing for a product independent of the version
 */
enum _esxVI_ProductVersion {
    esxVI_ProductVersion_Undefined = 0,

    esxVI_ProductVersion_GSX   = (1 << 0) << 16,
    esxVI_ProductVersion_GSX20 = esxVI_ProductVersion_GSX | 1,

    esxVI_ProductVersion_ESX   = (1 << 1) << 16,
    esxVI_ProductVersion_ESX35 = esxVI_ProductVersion_ESX | 1,
    esxVI_ProductVersion_ESX40 = esxVI_ProductVersion_ESX | 2,
    esxVI_ProductVersion_ESX41 = esxVI_ProductVersion_ESX | 3,
    esxVI_ProductVersion_ESX4x = esxVI_ProductVersion_ESX | 4, /* > 4.1 */
    esxVI_ProductVersion_ESX50 = esxVI_ProductVersion_ESX | 5,
    esxVI_ProductVersion_ESX51 = esxVI_ProductVersion_ESX | 6,
    esxVI_ProductVersion_ESX5x = esxVI_ProductVersion_ESX | 7, /* > 5.1 */

    esxVI_ProductVersion_VPX   = (1 << 2) << 16,
    esxVI_ProductVersion_VPX25 = esxVI_ProductVersion_VPX | 1,
    esxVI_ProductVersion_VPX40 = esxVI_ProductVersion_VPX | 2,
    esxVI_ProductVersion_VPX41 = esxVI_ProductVersion_VPX | 3,
    esxVI_ProductVersion_VPX4x = esxVI_ProductVersion_VPX | 4, /* > 4.1 */
    esxVI_ProductVersion_VPX50 = esxVI_ProductVersion_VPX | 5,
    esxVI_ProductVersion_VPX51 = esxVI_ProductVersion_VPX | 6,
    esxVI_ProductVersion_VPX5x = esxVI_ProductVersion_VPX | 7  /* > 5.1 */
};

enum _esxVI_Occurrence {
    esxVI_Occurrence_Undefined = 0,
    esxVI_Occurrence_RequiredItem,
    esxVI_Occurrence_RequiredList,
    esxVI_Occurrence_OptionalItem,
    esxVI_Occurrence_OptionalList,
    esxVI_Occurrence_None
};

struct _esxVI_ParsedHostCpuIdInfo {
    int level;
    char eax[32];
    char ebx[32];
    char ecx[32];
    char edx[32];
};



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * CURL
 */

struct _esxVI_CURL {
    CURL *handle;
    virMutex lock;
    struct curl_slist *headers;
    char error[CURL_ERROR_SIZE];
    esxVI_SharedCURL *shared;
    esxVI_MultiCURL *multi;
};

int esxVI_CURL_Alloc(esxVI_CURL **curl);
void esxVI_CURL_Free(esxVI_CURL **curl);
int esxVI_CURL_Connect(esxVI_CURL *curl, esxUtil_ParsedUri *parsedUri);
int esxVI_CURL_Download(esxVI_CURL *curl, const char *url, char **content,
                        unsigned long long offset, unsigned long long *length);
int esxVI_CURL_Upload(esxVI_CURL *curl, const char *url, const char *content);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * SharedCURL
 */

struct _esxVI_SharedCURL {
    CURLSH *handle;
    virMutex locks[3]; /* share, cookie, dns */
    size_t count;
};

int esxVI_SharedCURL_Alloc(esxVI_SharedCURL **shared);
void esxVI_SharedCURL_Free(esxVI_SharedCURL **shared);
int esxVI_SharedCURL_Add(esxVI_SharedCURL *shared, esxVI_CURL *curl);
int esxVI_SharedCURL_Remove(esxVI_SharedCURL *shared, esxVI_CURL *curl);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * MultiCURL
 */

struct _esxVI_MultiCURL {
    CURLM *handle;
    size_t count;
};

int esxVI_MultiCURL_Alloc(esxVI_MultiCURL **multi);
void esxVI_MultiCURL_Free(esxVI_MultiCURL **multi);
int esxVI_MultiCURL_Add(esxVI_MultiCURL *multi, esxVI_CURL *curl);
int esxVI_MultiCURL_Remove(esxVI_MultiCURL *multi, esxVI_CURL *curl);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Context
 */

struct _esxVI_Context {
    /* All members are used read-only after esxVI_Context_Connect ... */
    esxVI_CURL *curl;
    char *url;
    char *ipAddress;
    char *username;
    char *password;
    esxVI_ServiceContent *service;
    esxVI_APIVersion apiVersion;
    esxVI_ProductVersion productVersion;
    esxVI_UserSession *session; /* ... except the session ... */
    virMutexPtr sessionLock; /* ... that is protected by this mutex */
    esxVI_Datacenter *datacenter;
    char *datacenterPath; /* including folders */
    esxVI_ComputeResource *computeResource;
    char *computeResourcePath; /* including folders */
    esxVI_HostSystem *hostSystem;
    char *hostSystemName;
    esxVI_SelectionSpec *selectSet_folderToChildEntity;
    esxVI_SelectionSpec *selectSet_hostSystemToParent;
    esxVI_SelectionSpec *selectSet_hostSystemToVm;
    esxVI_SelectionSpec *selectSet_hostSystemToDatastore;
    esxVI_SelectionSpec *selectSet_computeResourceToHost;
    esxVI_SelectionSpec *selectSet_computeResourceToParentToParent;
    esxVI_SelectionSpec *selectSet_datacenterToNetwork;
    bool hasQueryVirtualDiskUuid;
    bool hasSessionIsActive;
};

int esxVI_Context_Alloc(esxVI_Context **ctx);
void esxVI_Context_Free(esxVI_Context **ctx);
int esxVI_Context_Connect(esxVI_Context *ctx, const char *ipAddress,
                          const char *url, const char *username,
                          const char *password, esxUtil_ParsedUri *parsedUri);
int esxVI_Context_LookupManagedObjects(esxVI_Context *ctx);
int esxVI_Context_LookupManagedObjectsByPath(esxVI_Context *ctx, const char *path);
int esxVI_Context_LookupManagedObjectsByHostSystemIp(esxVI_Context *ctx,
                                                     const char *hostSystemIpAddress);
int esxVI_Context_Execute(esxVI_Context *ctx, const char *methodName,
                          const char *request, esxVI_Response **response,
                          esxVI_Occurrence occurrence);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Response
 */

struct _esxVI_Response {
    int responseCode;                                 /* required */
    char *content;                                    /* required */
    xmlDocPtr document;                               /* optional */
    xmlNodePtr node;                                  /* optional, list */
};

int esxVI_Response_Alloc(esxVI_Response **response);
void esxVI_Response_Free(esxVI_Response **response);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Enumeration
 */

struct _esxVI_EnumerationValue {
    const char *name;
    int value;
};

struct _esxVI_Enumeration {
    esxVI_Type type;
    esxVI_EnumerationValue values[10];
};

int esxVI_Enumeration_CastFromAnyType(const esxVI_Enumeration *enumeration,
                                      esxVI_AnyType *anyType, int *value);
int esxVI_Enumeration_Serialize(const esxVI_Enumeration *enumeration,
                                int value, const char *element,
                                virBufferPtr output);
int esxVI_Enumeration_Deserialize(const esxVI_Enumeration *enumeration,
                                  xmlNodePtr node, int *value);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * List
 */

struct _esxVI_List {
    esxVI_List *_next;
};

typedef int (*esxVI_List_FreeFunc) (esxVI_List **item);
typedef int (*esxVI_List_DeepCopyFunc) (esxVI_List **dest, esxVI_List *src);
typedef int (*esxVI_List_CastFromAnyTypeFunc) (esxVI_AnyType *anyType,
                                               esxVI_List **item);
typedef int (*esxVI_List_SerializeFunc) (esxVI_List *item, const char *element,
                                         virBufferPtr output);
typedef int (*esxVI_List_DeserializeFunc) (xmlNodePtr node, esxVI_List **item);

int esxVI_List_Append(esxVI_List **list, esxVI_List *item);
int esxVI_List_DeepCopy(esxVI_List **destList, esxVI_List *srcList,
                        esxVI_List_DeepCopyFunc deepCopyFunc,
                        esxVI_List_FreeFunc freeFunc);
int esxVI_List_CastFromAnyType(esxVI_AnyType *anyType, esxVI_List **list,
                               esxVI_List_CastFromAnyTypeFunc castFromAnyTypeFunc,
                               esxVI_List_FreeFunc freeFunc);
int esxVI_List_Serialize(esxVI_List *list, const char *element,
                         virBufferPtr output,
                         esxVI_List_SerializeFunc serializeFunc);
int esxVI_List_Deserialize(xmlNodePtr node, esxVI_List **list,
                           esxVI_List_DeserializeFunc deserializeFunc,
                           esxVI_List_FreeFunc freeFunc);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Utility and Convenience Functions
 *
 * Function naming scheme:
 *  - 'lookup' functions query the ESX or vCenter for information
 *  - 'get' functions get information from a local object
 */

int esxVI_BuildSelectSet
      (esxVI_SelectionSpec **selectSet, const char *name,
       const char *type, const char *path, const char *selectSetNames);

int esxVI_BuildSelectSetCollection(esxVI_Context *ctx);

int esxVI_EnsureSession(esxVI_Context *ctx);

int esxVI_LookupObjectContentByType(esxVI_Context *ctx,
                                    esxVI_ManagedObjectReference *root,
                                    const char *type,
                                    esxVI_String *propertyNameList,
                                    esxVI_ObjectContent **objectContentList,
                                    esxVI_Occurrence occurrence);

int esxVI_GetManagedEntityStatus
      (esxVI_ObjectContent *objectContent, const char *propertyName,
       esxVI_ManagedEntityStatus *managedEntityStatus);

int esxVI_GetVirtualMachinePowerState
      (esxVI_ObjectContent *virtualMachine,
       esxVI_VirtualMachinePowerState *powerState);

int esxVI_GetVirtualMachineQuestionInfo
      (esxVI_ObjectContent *virtualMachine,
       esxVI_VirtualMachineQuestionInfo **questionInfo);

int esxVI_GetBoolean(esxVI_ObjectContent *objectContent,
                     const char *propertyName,
                     esxVI_Boolean *value, esxVI_Occurrence occurrence);

int esxVI_GetLong(esxVI_ObjectContent *objectContent, const char *propertyName,
                  esxVI_Long **value, esxVI_Occurrence occurrence);

int esxVI_GetStringValue(esxVI_ObjectContent *objectContent,
                         const char *propertyName,
                         char **value, esxVI_Occurrence occurrence);

int esxVI_GetManagedObjectReference(esxVI_ObjectContent *objectContent,
                                    const char *propertyName,
                                    esxVI_ManagedObjectReference **value,
                                    esxVI_Occurrence occurrence);

int esxVI_LookupNumberOfDomainsByPowerState
      (esxVI_Context *ctx, esxVI_VirtualMachinePowerState powerState,
       bool inverse);

int esxVI_GetVirtualMachineIdentity(esxVI_ObjectContent *virtualMachine,
                                    int *id, char **name, unsigned char *uuid);

int esxVI_GetNumberOfSnapshotTrees
      (esxVI_VirtualMachineSnapshotTree *snapshotTreeList,
       bool recurse, bool leaves);

int esxVI_GetSnapshotTreeNames
      (esxVI_VirtualMachineSnapshotTree *snapshotTreeList, char **names,
       int nameslen, bool recurse, bool leaves);

int esxVI_GetSnapshotTreeByName
      (esxVI_VirtualMachineSnapshotTree *snapshotTreeList, const char *name,
       esxVI_VirtualMachineSnapshotTree **snapshotTree,
       esxVI_VirtualMachineSnapshotTree **snapshotTreeParent,
       esxVI_Occurrence occurrence);

int esxVI_GetSnapshotTreeBySnapshot
      (esxVI_VirtualMachineSnapshotTree *snapshotTreeList,
       esxVI_ManagedObjectReference *snapshot,
       esxVI_VirtualMachineSnapshotTree **snapshotTree);

int esxVI_LookupHostSystemProperties(esxVI_Context *ctx,
                                     esxVI_String *propertyNameList,
                                     esxVI_ObjectContent **hostSystem);

int esxVI_LookupVirtualMachineList(esxVI_Context *ctx,
                                   esxVI_String *propertyNameList,
                                   esxVI_ObjectContent **virtualMachineList);

int esxVI_LookupVirtualMachineByUuid(esxVI_Context *ctx,
                                     const unsigned char *uuid,
                                     esxVI_String *propertyNameList,
                                     esxVI_ObjectContent **virtualMachine,
                                     esxVI_Occurrence occurrence);

int esxVI_LookupVirtualMachineByName(esxVI_Context *ctx, const char *name,
                                     esxVI_String *propertyNameList,
                                     esxVI_ObjectContent **virtualMachine,
                                     esxVI_Occurrence occurrence);

int esxVI_LookupVirtualMachineByUuidAndPrepareForTask
      (esxVI_Context *ctx, const unsigned char *uuid,
       esxVI_String *propertyNameList, esxVI_ObjectContent **virtualMachine,
       bool autoAnswer);

int esxVI_LookupDatastoreList(esxVI_Context *ctx, esxVI_String *propertyNameList,
                              esxVI_ObjectContent **datastoreList);

int esxVI_LookupDatastoreByName(esxVI_Context *ctx, const char *name,
                                esxVI_String *propertyNameList,
                                esxVI_ObjectContent **datastore,
                                esxVI_Occurrence occurrence);

int esxVI_LookupDatastoreByAbsolutePath(esxVI_Context *ctx,
                                        const char *absolutePath,
                                        esxVI_String *propertyNameList,
                                        esxVI_ObjectContent **datastore,
                                        esxVI_Occurrence occurrence);

int esxVI_LookupDatastoreHostMount(esxVI_Context *ctx,
                                   esxVI_ManagedObjectReference *datastore,
                                   esxVI_DatastoreHostMount **hostMount,
                                   esxVI_Occurrence occurrence);

int esxVI_LookupTaskInfoByTask(esxVI_Context *ctx,
                               esxVI_ManagedObjectReference *task,
                               esxVI_TaskInfo **taskInfo);

int esxVI_LookupPendingTaskInfoListByVirtualMachine
      (esxVI_Context *ctx, esxVI_ObjectContent *virtualMachine,
       esxVI_TaskInfo **pendingTaskInfoList);

int esxVI_LookupAndHandleVirtualMachineQuestion(esxVI_Context *ctx,
                                                const unsigned char *uuid,
                                                esxVI_Occurrence occurrence,
                                                bool autoAnswer, bool *blocked);

int esxVI_LookupRootSnapshotTreeList
      (esxVI_Context *ctx, const unsigned char *virtualMachineUuid,
       esxVI_VirtualMachineSnapshotTree **rootSnapshotTreeList);

int esxVI_LookupCurrentSnapshotTree
      (esxVI_Context *ctx, const unsigned char *virtualMachineUuid,
       esxVI_VirtualMachineSnapshotTree **currentSnapshotTree,
       esxVI_Occurrence occurrence);

int esxVI_LookupFileInfoByDatastorePath(esxVI_Context *ctx,
                                        const char *datastorePath,
                                        bool lookupFolder,
                                        esxVI_FileInfo **fileInfo,
                                        esxVI_Occurrence occurrence);

int esxVI_LookupDatastoreContentByDatastoreName
      (esxVI_Context *ctx, const char *datastoreName,
       esxVI_HostDatastoreBrowserSearchResults **searchResultsList);

int esxVI_LookupStorageVolumeKeyByDatastorePath(esxVI_Context *ctx,
                                                const char *datastorePath,
                                                char **key);

int esxVI_LookupAutoStartDefaults(esxVI_Context *ctx,
                                  esxVI_AutoStartDefaults **defaults);

int esxVI_LookupAutoStartPowerInfoList(esxVI_Context *ctx,
                                       esxVI_AutoStartPowerInfo **powerInfoList);

int esxVI_LookupPhysicalNicList(esxVI_Context *ctx,
                                esxVI_PhysicalNic **physicalNicList);

int esxVI_LookupPhysicalNicByName(esxVI_Context *ctx, const char *name,
                                  esxVI_PhysicalNic **physicalNic,
                                  esxVI_Occurrence occurrence);

int esxVI_LookupPhysicalNicByMACAddress(esxVI_Context *ctx, const char *mac,
                                        esxVI_PhysicalNic **physicalNic,
                                        esxVI_Occurrence occurrence);

int esxVI_LookupHostVirtualSwitchList
      (esxVI_Context *ctx, esxVI_HostVirtualSwitch **hostVirtualSwitchList);

int esxVI_LookupHostVirtualSwitchByName(esxVI_Context *ctx, const char *name,
                                        esxVI_HostVirtualSwitch **hostVirtualSwitch,
                                        esxVI_Occurrence occurrence);

int esxVI_LookupHostPortGroupList(esxVI_Context *ctx,
                                  esxVI_HostPortGroup **hostPortGroupList);

int esxVI_LookupNetworkList(esxVI_Context *ctx, esxVI_String *propertyNameList,
                            esxVI_ObjectContent **networkList);

int esxVI_HandleVirtualMachineQuestion
      (esxVI_Context *ctx, esxVI_ManagedObjectReference *virtualMachine,
       esxVI_VirtualMachineQuestionInfo *questionInfo, bool autoAnswer,
       bool *blocked);

int esxVI_WaitForTaskCompletion(esxVI_Context *ctx,
                                esxVI_ManagedObjectReference *task,
                                const unsigned char *virtualMachineUuid,
                                esxVI_Occurrence virtualMachineOccurrence,
                                bool autoAnswer,
                                esxVI_TaskInfoState *finalState,
                                char **errorMessage);

int esxVI_ParseHostCpuIdInfo(esxVI_ParsedHostCpuIdInfo *parsedHostCpuIdInfo,
                             esxVI_HostCpuIdInfo *hostCpuIdInfo);

int esxVI_ProductVersionToDefaultVirtualHWVersion
      (esxVI_ProductVersion productVersion);

int esxVI_LookupHostInternetScsiHbaStaticTargetByName
      (esxVI_Context *ctx, const char *name,
       esxVI_HostInternetScsiHbaStaticTarget **target,
       esxVI_Occurrence occurrence);

int esxVI_LookupHostInternetScsiHba
      (esxVI_Context *ctx, esxVI_HostInternetScsiHba **hostInternetScsiHba);

int esxVI_LookupScsiLunList(esxVI_Context *ctx, esxVI_ScsiLun **scsiLunList);

int esxVI_LookupHostScsiTopologyLunListByTargetName
      (esxVI_Context *ctx, const char *name,
       esxVI_HostScsiTopologyLun **hostScsiTopologyLunList);

int esxVI_LookupStoragePoolNameByScsiLunKey(esxVI_Context *ctx, const char *key,
                                            char **poolName);

# include "esx_vi.generated.h"

#endif /* __ESX_VI_H__ */
