
/*
 * esx_vi.h: client for the VMware VI API 2.5 to manage ESX hosts
 *
 * Copyright (C) 2009 Matthias Bolte <matthias.bolte@googlemail.com>
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

#ifndef __ESX_VI_H__
#define __ESX_VI_H__

#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <curl/curl.h>

#include "internal.h"
#include "datatypes.h"
#include "esx_vi_types.h"

typedef enum _esxVI_APIVersion esxVI_APIVersion;
typedef enum _esxVI_ProductVersion esxVI_ProductVersion;
typedef enum _esxVI_Occurrence esxVI_Occurrence;
typedef struct _esxVI_Context esxVI_Context;
typedef struct _esxVI_Response esxVI_Response;
typedef struct _esxVI_Enumeration esxVI_Enumeration;
typedef struct _esxVI_EnumerationValue esxVI_EnumerationValue;
typedef struct _esxVI_List esxVI_List;



enum _esxVI_APIVersion {
    esxVI_APIVersion_Undefined = 0,
    esxVI_APIVersion_Unknown,
    esxVI_APIVersion_25,
    esxVI_APIVersion_40
};

enum _esxVI_ProductVersion {
    esxVI_ProductVersion_Undefined = 0,
    esxVI_ProductVersion_GSX20,
    esxVI_ProductVersion_ESX35,
    esxVI_ProductVersion_ESX40,
    esxVI_ProductVersion_VPX25,
    esxVI_ProductVersion_VPX40
};

enum _esxVI_Occurrence {
    esxVI_Occurrence_Undefined = 0,
    esxVI_Occurrence_RequiredItem,
    esxVI_Occurrence_OptionalItem,
    esxVI_Occurrence_List,
    esxVI_Occurrence_None
};



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Context
 */

struct _esxVI_Context {
    char *url;
    char *ipAddress;
    CURL *curl_handle;
    struct curl_slist *curl_headers;
    virMutex curl_lock;
    char *username;
    char *password;
    esxVI_ServiceContent *service;
    esxVI_APIVersion apiVersion;
    esxVI_ProductVersion productVersion;
    esxVI_UserSession *session;
    esxVI_ManagedObjectReference *datacenter;
    esxVI_ManagedObjectReference *vmFolder;
    esxVI_ManagedObjectReference *hostFolder;
    esxVI_SelectionSpec *fullTraversalSpecList;
};

int esxVI_Context_Alloc(virConnectPtr conn, esxVI_Context **ctx);
void esxVI_Context_Free(esxVI_Context **ctx);
int esxVI_Context_Connect(virConnectPtr conn, esxVI_Context *ctx,
                          const char *ipAddress, const char *url,
                          const char *username, const char *password,
                          int noVerify);
int esxVI_Context_DownloadFile(virConnectPtr conn, esxVI_Context *ctx,
                               const char *url, char **content);
int esxVI_Context_UploadFile(virConnectPtr conn, esxVI_Context *ctx,
                             const char *url, const char *content);
int esxVI_Context_Execute(virConnectPtr conn, esxVI_Context *ctx,
                          const char *methodName, const char *request,
                          esxVI_Response **response, esxVI_Occurrence occurrence);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Response
 */

struct _esxVI_Response {
    int responseCode;                                 /* required */
    char *content;                                    /* required */
    xmlDocPtr document;                               /* optional */
    xmlNodePtr node;                                  /* optional, list */
};

int esxVI_Response_Alloc(virConnectPtr conn, esxVI_Response **response);
void esxVI_Response_Free(esxVI_Response **response);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Enumeration
 */

struct _esxVI_EnumerationValue {
    const char *name;
    int value;
};

struct _esxVI_Enumeration {
    const char *type;
    esxVI_EnumerationValue values[10];
};

int esxVI_Enumeration_CastFromAnyType(virConnectPtr conn,
                                      const esxVI_Enumeration *enumeration,
                                      esxVI_AnyType *anyType, int *value);
int esxVI_Enumeration_Serialize(virConnectPtr conn,
                                const esxVI_Enumeration *enumeration,
                                int value, const char *element,
                                virBufferPtr output, esxVI_Boolean required);
int esxVI_Enumeration_Deserialize(virConnectPtr conn,
                                  const esxVI_Enumeration *enumeration,
                                  xmlNodePtr node, int *value);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * List
 */

struct _esxVI_List {
    esxVI_List *_next;
};

typedef int (*esxVI_List_FreeFunc) (esxVI_List **item);
typedef int (*esxVI_List_DeepCopyFunc) (virConnectPtr conn, esxVI_List **dest,
                                        esxVI_List *src);
typedef int (*esxVI_List_CastFromAnyTypeFunc) (virConnectPtr conn,
                                               esxVI_AnyType *anyType,
                                               esxVI_List **item);
typedef int (*esxVI_List_SerializeFunc) (virConnectPtr conn, esxVI_List *item,
                                         const char *element,
                                         virBufferPtr output,
                                         esxVI_Boolean required);
typedef int (*esxVI_List_DeserializeFunc) (virConnectPtr conn, xmlNodePtr node,
                                           esxVI_List **item);

int esxVI_List_Append(virConnectPtr conn, esxVI_List **list, esxVI_List *item);
int esxVI_List_DeepCopy(virConnectPtr conn, esxVI_List **destList,
                        esxVI_List *srcList,
                        esxVI_List_DeepCopyFunc deepCopyFunc,
                        esxVI_List_FreeFunc freeFunc);
int esxVI_List_CastFromAnyType(virConnectPtr conn, esxVI_AnyType *anyType,
                               esxVI_List **list,
                               esxVI_List_CastFromAnyTypeFunc castFromAnyTypeFunc,
                               esxVI_List_FreeFunc freeFunc);
int esxVI_List_Serialize(virConnectPtr conn, esxVI_List *list,
                         const char *element, virBufferPtr output,
                         esxVI_Boolean required,
                         esxVI_List_SerializeFunc serializeFunc);
int esxVI_List_Deserialize(virConnectPtr conn, xmlNodePtr node,
                           esxVI_List **list,
                           esxVI_List_DeserializeFunc deserializeFunc,
                           esxVI_List_FreeFunc freeFunc);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Utility and Convenience Functions
 *
 * Function naming scheme:
 *  - 'lookup' functions query the ESX or vCenter for information
 *  - 'get' functions get information from a local object
 */

int esxVI_Alloc(virConnectPtr conn, void **ptrptr, size_t size);

int esxVI_CheckSerializationNecessity(virConnectPtr conn, const char *element,
                                      esxVI_Boolean required);

int esxVI_BuildFullTraversalSpecItem
      (virConnectPtr conn, esxVI_SelectionSpec **fullTraversalSpecList,
       const char *name, const char *type, const char *path,
       const char *selectSetNames);

int esxVI_BuildFullTraversalSpecList
      (virConnectPtr conn, esxVI_SelectionSpec **fullTraversalSpecList);

int esxVI_EnsureSession(virConnectPtr conn, esxVI_Context *ctx);

int esxVI_LookupObjectContentByType(virConnectPtr conn, esxVI_Context *ctx,
                                    esxVI_ManagedObjectReference *root,
                                    const char *type,
                                    esxVI_String *propertyNameList,
                                    esxVI_Boolean recurse,
                                    esxVI_ObjectContent **objectContentList);

int esxVI_GetManagedEntityStatus
      (virConnectPtr conn, esxVI_ObjectContent *objectContent,
       const char *propertyName,
       esxVI_ManagedEntityStatus *managedEntityStatus);

int esxVI_GetVirtualMachinePowerState
      (virConnectPtr conn, esxVI_ObjectContent *virtualMachine,
       esxVI_VirtualMachinePowerState *powerState);

int esxVI_GetVirtualMachineQuestionInfo
      (virConnectPtr conn, esxVI_ObjectContent *virtualMachine,
       esxVI_VirtualMachineQuestionInfo **questionInfo);

int esxVI_LookupNumberOfDomainsByPowerState
      (virConnectPtr conn, esxVI_Context *ctx,
       esxVI_VirtualMachinePowerState powerState, esxVI_Boolean inverse);

int esxVI_GetVirtualMachineIdentity(virConnectPtr conn,
                                    esxVI_ObjectContent *virtualMachine,
                                    int *id, char **name, unsigned char *uuid);

int esxVI_LookupResourcePoolByHostSystem
      (virConnectPtr conn, esxVI_Context *ctx, esxVI_ObjectContent *hostSystem,
       esxVI_ManagedObjectReference **resourcePool);

int esxVI_LookupHostSystemByIp(virConnectPtr conn, esxVI_Context *ctx,
                               const char *ipAddress,
                               esxVI_String *propertyNameList,
                               esxVI_ObjectContent **hostSystem);

int esxVI_LookupVirtualMachineByUuid(virConnectPtr conn, esxVI_Context *ctx,
                                     const unsigned char *uuid,
                                     esxVI_String *propertyNameList,
                                     esxVI_ObjectContent **virtualMachine,
                                     esxVI_Occurrence occurrence);

int esxVI_LookupVirtualMachineByUuidAndPrepareForTask
      (virConnectPtr conn, esxVI_Context *ctx, const unsigned char *uuid,
       esxVI_String *propertyNameList, esxVI_ObjectContent **virtualMachine,
       esxVI_Boolean autoAnswer);

int esxVI_LookupDatastoreByName(virConnectPtr conn, esxVI_Context *ctx,
                                const char *name,
                                esxVI_String *propertyNameList,
                                esxVI_ObjectContent **datastore,
                                esxVI_Occurrence occurrence);

int esxVI_LookupTaskInfoByTask(virConnectPtr conn, esxVI_Context *ctx,
                               esxVI_ManagedObjectReference *task,
                               esxVI_TaskInfo **taskInfo);

int esxVI_LookupPendingTaskInfoListByVirtualMachine
      (virConnectPtr conn, esxVI_Context *ctx,
       esxVI_ObjectContent *virtualMachine,
       esxVI_TaskInfo **pendingTaskInfoList);

int esxVI_LookupAndHandleVirtualMachineQuestion(virConnectPtr conn,
                                                esxVI_Context *ctx,
                                                const unsigned char *uuid,
                                                esxVI_Boolean autoAnswer);

int esxVI_StartVirtualMachineTask(virConnectPtr conn, esxVI_Context *ctx,
                                  const char *name, const char *request,
                                  esxVI_ManagedObjectReference **task);

int esxVI_StartSimpleVirtualMachineTask
      (virConnectPtr conn, esxVI_Context *ctx, const char *name,
       esxVI_ManagedObjectReference *virtualMachine,
       esxVI_ManagedObjectReference **task);

int esxVI_SimpleVirtualMachineMethod
      (virConnectPtr conn, esxVI_Context *ctx, const char *name,
       esxVI_ManagedObjectReference *virtualMachine);

int esxVI_HandleVirtualMachineQuestion
      (virConnectPtr conn, esxVI_Context *ctx,
       esxVI_ManagedObjectReference *virtualMachine,
       esxVI_VirtualMachineQuestionInfo *questionInfo,
       esxVI_Boolean autoAnswer);

int esxVI_WaitForTaskCompletion(virConnectPtr conn, esxVI_Context *ctx,
                                esxVI_ManagedObjectReference *task,
                                const unsigned char *virtualMachineUuid,
                                esxVI_Boolean autoAnswer,
                                esxVI_TaskInfoState *finalState);

#endif /* __ESX_VI_H__ */
