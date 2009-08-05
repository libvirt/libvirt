
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
typedef struct _esxVI_Context esxVI_Context;
typedef struct _esxVI_RemoteResponse esxVI_RemoteResponse;
typedef struct _esxVI_RemoteRequest esxVI_RemoteRequest;
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



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Context
 */

struct _esxVI_Context {
    char *url;
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
                          const char *url, const char *username,
                          const char *password, int noVerify);
int esxVI_Context_Download(virConnectPtr conn, esxVI_Context *ctx,
                           const char *url, char **content);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * RemoteRequest
 */

struct _esxVI_RemoteRequest {
    char *request;                                    /* required */
    char *xpathExpression;                            /* optional */
};

int esxVI_RemoteRequest_Alloc(virConnectPtr conn,
                              esxVI_RemoteRequest **remoteRequest);
void esxVI_RemoteRequest_Free(esxVI_RemoteRequest **remoteRequest);
int esxVI_RemoteRequest_Execute(virConnectPtr conn, esxVI_Context *ctx,
                                esxVI_RemoteRequest *remoteRequest,
                                esxVI_RemoteResponse **remoteResponse);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * RemoteResponse
 */

struct _esxVI_RemoteResponse {
    long response_code;                               /* required */
    char *response;                                   /* required */
    xmlDocPtr document;                               /* optional */
    xmlXPathContextPtr xpathContext;                  /* optional */
    xmlXPathObjectPtr xpathObject;                    /* optional */
};

typedef int (*esxVI_RemoteResponse_DeserializeFunc) (virConnectPtr conn,
                                                     xmlNodePtr node,
                                                     void **item);
typedef int (*esxVI_RemoteResponse_DeserializeListFunc) (virConnectPtr conn,
                                                         xmlNodePtr node,
                                                         esxVI_List **list);

int esxVI_RemoteResponse_Alloc(virConnectPtr conn,
                               esxVI_RemoteResponse **remoteResponse);
void esxVI_RemoteResponse_Free(esxVI_RemoteResponse **remoteResponse);
int esxVI_RemoteResponse_DeserializeXPathObject
      (virConnectPtr conn, esxVI_RemoteResponse *remoteResponse,
       esxVI_RemoteResponse_DeserializeFunc deserializeFunc, void **item);
int esxVI_RemoteResponse_DeserializeXPathObjectList
      (virConnectPtr conn, esxVI_RemoteResponse *remoteResponse,
       esxVI_RemoteResponse_DeserializeListFunc deserializeListFunc,
       esxVI_List **list);
int esxVI_RemoteResponse_DeserializeXPathObjectAsManagedObjectReference
    (virConnectPtr conn, esxVI_RemoteResponse *remoteResponse,
     esxVI_ManagedObjectReference **managedObjectReference,
     const char *expectedType);



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
                                      esxVI_AnyType *anyType, int *boolean);
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
 */

int
esxVI_Alloc(virConnectPtr conn, void **ptrptr, size_t size);

int
esxVI_CheckSerializationNecessity(virConnectPtr conn, const char *element,
                                  esxVI_Boolean required);

int esxVI_BuildFullTraversalSpecItem
      (virConnectPtr conn, esxVI_SelectionSpec **fullTraversalSpecList,
       const char *name, const char *type, const char *path,
       const char *selectSetNames);
int esxVI_BuildFullTraversalSpecList
      (virConnectPtr conn, esxVI_SelectionSpec **fullTraversalSpecList);

int esxVI_EnsureSession(virConnectPtr conn, esxVI_Context *ctx);

int esxVI_GetObjectContent(virConnectPtr conn, esxVI_Context *ctx,
                           esxVI_ManagedObjectReference *root,
                           const char *type, esxVI_String *propertyNameList,
                           esxVI_Boolean recurse,
                           esxVI_ObjectContent **objectContentList);

int esxVI_GetVirtualMachinePowerState
      (virConnectPtr conn, esxVI_ObjectContent *virtualMachine,
       esxVI_VirtualMachinePowerState *powerState);

int esxVI_GetNumberOfDomainsByPowerState
      (virConnectPtr conn, esxVI_Context *ctx,
       esxVI_VirtualMachinePowerState powerState, esxVI_Boolean inverse);

int esxVI_GetVirtualMachineIdentity(virConnectPtr conn,
                                    esxVI_ObjectContent *virtualMachine,
                                    int *id, char **name, unsigned char *uuid);

int esxVI_LookupHostSystemByIp(virConnectPtr conn, esxVI_Context *ctx,
                               const char *ip, esxVI_String *propertyNameList,
                               esxVI_ObjectContent **hostSystem);

int esxVI_LookupVirtualMachineByUuid(virConnectPtr conn, esxVI_Context *ctx,
                                     const unsigned char *uuid,
                                     esxVI_String *propertyNameList,
                                     esxVI_ObjectContent **virtualMachine);

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

int esxVI_WaitForTaskCompletion(virConnectPtr conn, esxVI_Context *ctx,
                                esxVI_ManagedObjectReference *task,
                                esxVI_TaskInfoState *finalState);

#endif /* __ESX_VI_H__ */
