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

#ifndef __HYPERV_WMI_H__
# define __HYPERV_WMI_H__

# include "virbuffer.h"
# include "hyperv_private.h"
# include "hyperv_wmi_classes.h"
# include "openwsman.h"
# include "virhash.h"


# define HYPERV_WQL_QUERY_INITIALIZER { NULL, NULL }

# define HYPERV_DEFAULT_PARAM_COUNT 5

int hypervVerifyResponse(WsManClient *client, WsXmlDocH response,
                         const char *detail);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Object
 */

typedef struct _hypervObject hypervObject;
struct _hypervObject {
    /* Unserialized data from wsman response. The member called "common" has
     * properties that are the same type and name for all "versions" of given
     * WMI class. This means that calling code does not have to make any
     * conditional checks based on which version was returned as long as it
     * only needs to read common values. The alignment of structs is ensured
     * by the generator.
     */
    union {
        XML_TYPE_PTR common;
        XML_TYPE_PTR v1;
        XML_TYPE_PTR v2;
    } data;
    /* The info used to make wsman request */
    hypervWmiClassInfoPtr info;
    hypervObject *next;
};

typedef struct _hypervWqlQuery hypervWqlQuery;
typedef hypervWqlQuery *hypervWqlQueryPtr;
struct _hypervWqlQuery {
    virBufferPtr query;
    hypervWmiClassInfoListPtr info;
};

int hypervEnumAndPull(hypervPrivate *priv, hypervWqlQueryPtr wqlQuery,
                      hypervObject **list);

void hypervFreeObject(hypervPrivate *priv, hypervObject *object);


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
    virBufferPtr query;
    hypervWmiClassInfoPtr info; /* info of the object this param represents */
};
typedef struct _hypervEprParam hypervEprParam;

struct _hypervEmbeddedParam {
    const char *name;
    virHashTablePtr table;
    hypervWmiClassInfoPtr info; /* info of the object this param represents */
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
typedef hypervParam *hypervParamPtr;

struct _hypervInvokeParamsList {
    const char *method;
    const char *ns;
    const char *resourceUri;
    const char *selector;
    hypervParamPtr params;
    size_t nbParams;
    size_t nbAvailParams;
};
typedef struct _hypervInvokeParamsList hypervInvokeParamsList;
typedef hypervInvokeParamsList *hypervInvokeParamsListPtr;


hypervInvokeParamsListPtr hypervCreateInvokeParamsList(hypervPrivate *priv,
        const char *method, const char *selector, hypervWmiClassInfoListPtr obj);

void hypervFreeInvokeParams(hypervInvokeParamsListPtr params);

int hypervAddSimpleParam(hypervInvokeParamsListPtr params, const char *name,
        const char *value);

int hypervAddEprParam(hypervInvokeParamsListPtr params, const char *name,
        hypervPrivate *priv, virBufferPtr query,
        hypervWmiClassInfoListPtr eprInfo);

virHashTablePtr hypervCreateEmbeddedParam(hypervPrivate *priv,
        hypervWmiClassInfoListPtr info);

int hypervSetEmbeddedProperty(virHashTablePtr table, const char *name,
        char *value);

int hypervAddEmbeddedParam(hypervInvokeParamsListPtr params, hypervPrivate *priv,
        const char *name, virHashTablePtr table, hypervWmiClassInfoListPtr info);

void hypervFreeEmbeddedParam(virHashTablePtr p);

int hypervInvokeMethod(hypervPrivate *priv, hypervInvokeParamsListPtr params,
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



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Generic "Get WMI class list" helpers
 */

int hypervGetMsvmComputerSystemList(hypervPrivate *priv, virBufferPtr query,
                                    Msvm_ComputerSystem **list);

int hypervGetMsvmConcreteJobList(hypervPrivate *priv, virBufferPtr query,
                                 Msvm_ConcreteJob **list);

int hypervGetWin32ComputerSystemList(hypervPrivate *priv, virBufferPtr query,
                                     Win32_ComputerSystem **list);

int hypervGetWin32ProcessorList(hypervPrivate *priv, virBufferPtr query,
                                    Win32_Processor **list);

int hypervGetMsvmVirtualSystemSettingDataList(hypervPrivate *priv,
                                              virBufferPtr query,
                                              Msvm_VirtualSystemSettingData **list);

int hypervGetMsvmProcessorSettingDataList(hypervPrivate *priv,
                                          virBufferPtr query,
                                          Msvm_ProcessorSettingData **list);

int hypervGetMsvmMemorySettingDataList(hypervPrivate *priv, virBufferPtr query,
                                       Msvm_MemorySettingData **list);

int hypervGetMsvmKeyboardList(hypervPrivate *priv, virBufferPtr query,
                                       Msvm_Keyboard **list);

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Msvm_ComputerSystem
 */

int hypervInvokeMsvmComputerSystemRequestStateChange(virDomainPtr domain,
                                                     int requestedState);

int hypervMsvmComputerSystemEnabledStateToDomainState
      (Msvm_ComputerSystem *computerSystem);

bool hypervIsMsvmComputerSystemActive(Msvm_ComputerSystem *computerSystem,
                                      bool *in_transition);

int hypervMsvmComputerSystemToDomain(virConnectPtr conn,
                                     Msvm_ComputerSystem *computerSystem,
                                     virDomainPtr *domain);

int hypervMsvmComputerSystemFromDomain(virDomainPtr domain,
                                       Msvm_ComputerSystem **computerSystem);

#endif /* __HYPERV_WMI_H__ */
