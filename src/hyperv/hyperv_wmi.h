/*
 * hyperv_wmi.h: general WMI over WSMAN related functions and structures for
 *               managing Microsoft Hyper-V hosts
 *
 * Copyright (C) 2011 Matthias Bolte <matthias.bolte@googlemail.com>
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

#pragma once

#include "virbuffer.h"
#include "hyperv_private.h"
#include "hyperv_wmi_classes.h"
#include "virhash.h"


#define HYPERV_WQL_QUERY_INITIALIZER { NULL, NULL }

#define HYPERV_DEFAULT_PARAM_COUNT 5

#define MSVM_VIRTUALSYSTEMMANAGEMENTSERVICE_SELECTOR \
    "CreationClassName=Msvm_VirtualSystemManagementService"

int hypervVerifyResponse(WsManClient *client, WsXmlDocH response,
                         const char *detail);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Object
 */

typedef struct _hypervObject hypervObject;
struct _hypervObject {
    XML_TYPE_PTR data; /* Unserialized data from wsman response */
    hypervWmiClassInfo *info; /* The info used to make wsman request */
    hypervObject *next;
    hypervPrivate *priv;
};

typedef struct _hypervWqlQuery hypervWqlQuery;
struct _hypervWqlQuery {
    virBuffer *query;
    hypervWmiClassInfo *info;
};

int hypervEnumAndPull(hypervPrivate *priv, hypervWqlQuery *wqlQuery,
                      hypervObject **list);

void hypervFreeObject(void *object);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(hypervObject, hypervFreeObject);


/*
 * Invoke
 */

typedef enum {
    HYPERV_SIMPLE_PARAM,
    HYPERV_EPR_PARAM,
    HYPERV_EMBEDDED_PARAM
} hypervStorageType;

struct _hypervSimpleParam {
    const char *name;
    const char *value;
};
typedef struct _hypervSimpleParam hypervSimpleParam;

struct _hypervEprParam {
    const char *name;
    virBuffer *query;
    hypervWmiClassInfo *info; /* info of the object this param represents */
};
typedef struct _hypervEprParam hypervEprParam;

struct _hypervEmbeddedParam {
    const char *name;
    GHashTable *table;
    hypervWmiClassInfo *info; /* info of the object this param represents */
};
typedef struct _hypervEmbeddedParam hypervEmbeddedParam;

struct _hypervParam {
    hypervStorageType type;
    union {
        hypervSimpleParam simple;
        hypervEprParam epr;
        hypervEmbeddedParam embedded;
    };
};
typedef struct _hypervParam hypervParam;

struct _hypervInvokeParamsList {
    const char *method;
    const char *ns;
    const char *resourceUri;
    const char *selector;
    hypervParam *params;
    size_t nbParams;
    size_t nbAvailParams;
};
typedef struct _hypervInvokeParamsList hypervInvokeParamsList;


hypervInvokeParamsList *hypervCreateInvokeParamsList(const char *method,
                                                       const char *selector,
                                                       hypervWmiClassInfo *obj);

void hypervFreeInvokeParams(hypervInvokeParamsList *params);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(hypervInvokeParamsList, hypervFreeInvokeParams);

int hypervAddSimpleParam(hypervInvokeParamsList *params, const char *name,
                         const char *value);

int hypervAddEprParam(hypervInvokeParamsList *params,
                      const char *name,
                      virBuffer *query,
                      hypervWmiClassInfo *eprInfo);

GHashTable *hypervCreateEmbeddedParam(hypervWmiClassInfo *info);

int hypervSetEmbeddedProperty(GHashTable *table,
                              const char *name,
                              const char *value);

int hypervAddEmbeddedParam(hypervInvokeParamsList *params,
                           const char *name,
                           GHashTable **table,
                           hypervWmiClassInfo *info);

void hypervFreeEmbeddedParam(GHashTable *p);

int hypervInvokeMethod(hypervPrivate *priv,
                       hypervInvokeParamsList **paramsPtr,
                       WsXmlDocH *res);

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * CIM/Msvm_ReturnCode
 */

enum _CIM_ReturnCode {
    CIM_RETURNCODE_COMPLETED_WITH_NO_ERROR = 0,
    CIM_RETURNCODE_NOT_SUPPORTED = 1,
    CIM_RETURNCODE_UNKNOWN_ERROR = 2,
    CIM_RETURNCODE_CANNOT_COMPLETE_WITHIN_TIMEOUT_PERIOD = 3,
    CIM_RETURNCODE_FAILED = 4,
    CIM_RETURNCODE_INVALID_PARAMETER = 5,
    CIM_RETURNCODE_IN_USE = 6,
    CIM_RETURNCODE_TRANSITION_STARTED = 4096,
    CIM_RETURNCODE_INVALID_STATE_TRANSITION = 4097,
    CIM_RETURNCODE_TIMEOUT_PARAMETER_NOT_SUPPORTED = 4098,
    CIM_RETURNCODE_BUSY = 4099,
};

enum _Msvm_ReturnCode {
    MSVM_RETURNCODE_FAILED = 32768,
    MSVM_RETURNCODE_ACCESS_DENIED = 32769,
    MSVM_RETURNCODE_NOT_SUPPORTED = 32770,
    MSVM_RETURNCODE_STATUS_IS_UNKNOWN = 32771,
    MSVM_RETURNCODE_TIMEOUT = 32772,
    MSVM_RETURNCODE_INVALID_PARAMETER = 32773,
    MSVM_RETURNCODE_SYSTEM_IS_IN_USE = 32774,
    MSVM_RETURNCODE_INVALID_STATE_FOR_THIS_OPERATION = 32775,
    MSVM_RETURNCODE_INCORRECT_DATA_TYPE = 32776,
    MSVM_RETURNCODE_SYSTEM_IS_NOT_AVAILABLE = 32777,
    MSVM_RETURNCODE_OUT_OF_MEMORY = 32778,
};

const char *hypervReturnCodeToString(int returnCode);



int hypervGetWmiClassList(hypervPrivate *priv,
                          hypervWmiClassInfo *wmiInfo,
                          virBuffer *query,
                          hypervObject **wmiClass);

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

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Msvm_ComputerSystem
 */

int hypervInvokeMsvmComputerSystemRequestStateChange(virDomainPtr domain,
                                                     int requestedState);

int hypervMsvmComputerSystemEnabledStateToDomainState(Msvm_ComputerSystem *computerSystem);

bool hypervIsMsvmComputerSystemActive(Msvm_ComputerSystem *computerSystem,
                                      bool *in_transition);

int hypervMsvmComputerSystemToDomain(virConnectPtr conn,
                                     Msvm_ComputerSystem *computerSystem,
                                     virDomainPtr *domain);

int hypervMsvmComputerSystemFromUUID(hypervPrivate *priv, const char *uuid,
                                     Msvm_ComputerSystem **computerSystem);

int hypervMsvmComputerSystemFromDomain(virDomainPtr domain,
                                       Msvm_ComputerSystem **computerSystem);

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Generic "Get WMI class list" helpers
 */

int hypervGetMsvmVirtualSystemSettingDataFromUUID(hypervPrivate *priv,
                                                  const char *uuid_string,
                                                  Msvm_VirtualSystemSettingData **list);

int hypervGetResourceAllocationSD(hypervPrivate *priv,
                                  const char *id,
                                  Msvm_ResourceAllocationSettingData **data);

int hypervGetProcessorSD(hypervPrivate *priv,
                         const char *id,
                         Msvm_ProcessorSettingData **data);

int hypervGetMemorySD(hypervPrivate *priv,
                      const char *vssd_instanceid,
                      Msvm_MemorySettingData **list);

int hypervGetStorageAllocationSD(hypervPrivate *priv,
                                 const char *id,
                                 Msvm_StorageAllocationSettingData **data);

int hypervGetSerialPortSD(hypervPrivate *priv,
                          const char *id,
                          Msvm_SerialPortSettingData **data);

int hypervGetSyntheticEthernetPortSD(hypervPrivate *priv,
                                     const char *id,
                                     Msvm_SyntheticEthernetPortSettingData **data);

int hypervGetEthernetPortAllocationSD(hypervPrivate *priv,
                                      const char *id,
                                      Msvm_EthernetPortAllocationSettingData **data);

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Msvm_VirtualSystemManagementService
 */

int hypervMsvmVSMSAddResourceSettings(virDomainPtr domain,
                                      GHashTable **resourceSettingsPtr,
                                      hypervWmiClassInfo *wmiInfo,
                                      WsXmlDocH *response);

int hypervMsvmVSMSModifyResourceSettings(hypervPrivate *priv,
                                         GHashTable **resourceSettingsPtr,
                                         hypervWmiClassInfo *wmiInfo);
