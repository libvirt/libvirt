
/*
 * esx_vi_types.h: client for the VMware VI API 2.5 to manage ESX hosts
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

#ifndef __ESX_VI_TYPES_H__
#define __ESX_VI_TYPES_H__

#include "buf.h"



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * XSI
 */

typedef enum _esxVI_Type esxVI_Type;



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * XSD
 */

typedef enum _esxVI_Boolean esxVI_Boolean;
typedef struct _esxVI_AnyType esxVI_AnyType;
typedef struct _esxVI_String esxVI_String;
typedef struct _esxVI_Int esxVI_Int;
typedef struct _esxVI_Long esxVI_Long;
typedef struct _esxVI_DateTime esxVI_DateTime;



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Enums
 */

typedef enum _esxVI_ManagedEntityStatus esxVI_ManagedEntityStatus;
typedef enum _esxVI_ObjectUpdateKind esxVI_ObjectUpdateKind;
typedef enum _esxVI_PerfSummaryType esxVI_PerfSummaryType;
typedef enum _esxVI_PerfStatsType esxVI_PerfStatsType;
typedef enum _esxVI_PropertyChangeOp esxVI_PropertyChangeOp;
typedef enum _esxVI_SharesLevel esxVI_SharesLevel;
typedef enum _esxVI_TaskInfoState esxVI_TaskInfoState;
typedef enum _esxVI_VirtualMachineMovePriority esxVI_VirtualMachineMovePriority;
typedef enum _esxVI_VirtualMachinePowerState esxVI_VirtualMachinePowerState;



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Types
 */

typedef struct _esxVI_Fault esxVI_Fault;
typedef struct _esxVI_ManagedObjectReference esxVI_ManagedObjectReference;
typedef struct _esxVI_DynamicProperty esxVI_DynamicProperty;
typedef struct _esxVI_HostCpuIdInfo esxVI_HostCpuIdInfo;
typedef struct _esxVI_SelectionSpec esxVI_SelectionSpec;
typedef struct _esxVI_TraversalSpec esxVI_TraversalSpec;
typedef struct _esxVI_ObjectSpec esxVI_ObjectSpec;
typedef struct _esxVI_PropertyChange esxVI_PropertyChange;
typedef struct _esxVI_PropertySpec esxVI_PropertySpec;
typedef struct _esxVI_PropertyFilterSpec esxVI_PropertyFilterSpec;
typedef struct _esxVI_ObjectContent esxVI_ObjectContent;
typedef struct _esxVI_ObjectUpdate esxVI_ObjectUpdate;
typedef struct _esxVI_PropertyFilterUpdate esxVI_PropertyFilterUpdate;
typedef struct _esxVI_AboutInfo esxVI_AboutInfo;
typedef struct _esxVI_ServiceContent esxVI_ServiceContent;
typedef struct _esxVI_UpdateSet esxVI_UpdateSet;
typedef struct _esxVI_SharesInfo esxVI_SharesInfo;
typedef struct _esxVI_ResourceAllocationInfo esxVI_ResourceAllocationInfo;
typedef struct _esxVI_ResourcePoolResourceUsage esxVI_ResourcePoolResourceUsage;
typedef struct _esxVI_VirtualMachineConfigSpec esxVI_VirtualMachineConfigSpec;
typedef struct _esxVI_Event esxVI_Event;
typedef struct _esxVI_UserSession esxVI_UserSession;
typedef struct _esxVI_ElementDescription esxVI_ElementDescription;
typedef struct _esxVI_PerfMetricId esxVI_PerfMetricId;
typedef struct _esxVI_PerfCounterInfo esxVI_PerfCounterInfo;
typedef struct _esxVI_PerfQuerySpec esxVI_PerfQuerySpec;
typedef struct _esxVI_PerfSampleInfo esxVI_PerfSampleInfo;
typedef struct _esxVI_PerfMetricIntSeries esxVI_PerfMetricIntSeries;
typedef struct _esxVI_PerfEntityMetric esxVI_PerfEntityMetric;



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * XSI: Type
 */

enum _esxVI_Type {
    esxVI_Type_Undefined = 0,
    esxVI_Type_Boolean,
    esxVI_Type_String,
    esxVI_Type_Short,
    esxVI_Type_Int,
    esxVI_Type_Long,
    esxVI_Type_Other,
};

const char *esxVI_Type_Name(esxVI_Type type);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * XSD: Boolean
 */

enum _esxVI_Boolean {
    esxVI_Boolean_Undefined = 0,
    esxVI_Boolean_True,
    esxVI_Boolean_False,
};

int esxVI_Boolean_Serialize(virConnectPtr conn, esxVI_Boolean boolean,
                            const char *element, virBufferPtr output,
                            esxVI_Boolean required);
int esxVI_Boolean_Deserialize(virConnectPtr conn, xmlNodePtr node,
                              esxVI_Boolean *boolean);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * XSD: AnyType
 */

struct _esxVI_AnyType {
    xmlNodePtr _node;                                      /* required */

    esxVI_Type type;                                       /* required */
    char *other;                                           /* required */
    char *value;                                           /* required */
    union {
        esxVI_Boolean boolean;                             /* optional */
        char *string;                                      /* optional */
        int16_t int16;                                     /* optional */
        int32_t int32;                                     /* optional */
        int64_t int64;                                     /* optional */
    };
};

int esxVI_AnyType_Alloc(virConnectPtr conn, esxVI_AnyType **anyType);
void esxVI_AnyType_Free(esxVI_AnyType **anyType);
int esxVI_AnyType_ExpectType(virConnectPtr conn, esxVI_AnyType *anyType,
                             esxVI_Type type);
int esxVI_AnyType_DeepCopy(virConnectPtr conn, esxVI_AnyType **dest,
                           esxVI_AnyType *src);
int esxVI_AnyType_Deserialize(virConnectPtr conn, xmlNodePtr node,
                              esxVI_AnyType **anyType);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * XSD: String
 */

struct _esxVI_String {
    esxVI_String *_next;                                   /* optional */

    char *value;                                           /* required */
};

int esxVI_String_Alloc(virConnectPtr conn, esxVI_String **string);
void esxVI_String_Free(esxVI_String **stringList);
int esxVI_String_AppendToList(virConnectPtr conn, esxVI_String **stringList,
                              esxVI_String *string);
int esxVI_String_AppendValueToList(virConnectPtr conn,
                                   esxVI_String **stringList,
                                   const char *value);
int esxVI_String_AppendValueListToList(virConnectPtr conn,
                                       esxVI_String **stringList,
                                       const char *valueList);
int esxVI_String_DeepCopy(virConnectPtr conn, esxVI_String **dest,
                          esxVI_String *src);
int esxVI_String_DeepCopyList(virConnectPtr conn, esxVI_String **destList,
                              esxVI_String *srcList);
int esxVI_String_DeepCopyValue(virConnectPtr conn, char **dest,
                               const char *src);
int esxVI_String_Serialize(virConnectPtr conn, esxVI_String *string,
                           const char *element, virBufferPtr output,
                           esxVI_Boolean required);
int esxVI_String_SerializeList(virConnectPtr conn, esxVI_String *stringList,
                               const char *element, virBufferPtr output,
                               esxVI_Boolean required);
int esxVI_String_SerializeValue(virConnectPtr conn, const char *value,
                                const char *element, virBufferPtr output,
                                esxVI_Boolean required);
int esxVI_String_Deserialize(virConnectPtr conn, xmlNodePtr node,
                             esxVI_String **string);
int esxVI_String_DeserializeList(virConnectPtr conn, xmlNodePtr node,
                                 esxVI_String **stringList);
int esxVI_String_DeserializeValue(virConnectPtr conn, xmlNodePtr node,
                                  char **value);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * XSD: Int
 */

struct _esxVI_Int {
    esxVI_Int *_next;                                      /* optional */

    int32_t value;                                         /* required */
};

int esxVI_Int_Alloc(virConnectPtr conn, esxVI_Int **number);
void esxVI_Int_Free(esxVI_Int **numberList);
int esxVI_Int_AppendToList(virConnectPtr conn, esxVI_Int **numberList,
                           esxVI_Int *number);
int esxVI_Int_DeepCopy(virConnectPtr conn, esxVI_Int **dest, esxVI_Int *src);
int esxVI_Int_Serialize(virConnectPtr conn, esxVI_Int *number,
                        const char *element, virBufferPtr output,
                        esxVI_Boolean required);
int esxVI_Int_SerializeList(virConnectPtr conn, esxVI_Int *numberList,
                            const char *element, virBufferPtr output,
                            esxVI_Boolean required);
int esxVI_Int_Deserialize(virConnectPtr conn, xmlNodePtr node,
                          esxVI_Int **number);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * XSD: Long
 */

struct _esxVI_Long {
    esxVI_Long *_next;                                     /* optional */

    int64_t value;                                         /* required */
};

int esxVI_Long_Alloc(virConnectPtr conn, esxVI_Long **number);
void esxVI_Long_Free(esxVI_Long **numberList);
int esxVI_Long_AppendToList(virConnectPtr conn, esxVI_Long **numberList,
                            esxVI_Long *number);
int esxVI_Long_Serialize(virConnectPtr conn, esxVI_Long *number,
                         const char *element, virBufferPtr output,
                         esxVI_Boolean required);
int esxVI_Long_SerializeList(virConnectPtr conn, esxVI_Long *numberList,
                             const char *element, virBufferPtr output,
                             esxVI_Boolean required);
int esxVI_Long_Deserialize(virConnectPtr conn, xmlNodePtr node,
                           esxVI_Long **number);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * XSD: DateTime
 */

struct _esxVI_DateTime {
    char *value;                                           /* required */
};

int esxVI_DateTime_Alloc(virConnectPtr conn, esxVI_DateTime **dateTime);
void esxVI_DateTime_Free(esxVI_DateTime **dateTime);
int esxVI_DateTime_Serialize(virConnectPtr conn, esxVI_DateTime *dateTime,
                             const char *element, virBufferPtr output,
                             esxVI_Boolean required);
int esxVI_DateTime_Deserialize(virConnectPtr conn, xmlNodePtr node,
                               esxVI_DateTime **dateTime);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Enum: ManagedEntityStatus
 */

enum _esxVI_ManagedEntityStatus {
    esxVI_ManagedEntityStatus_Undefined = 0,
    esxVI_ManagedEntityStatus_Gray,
    esxVI_ManagedEntityStatus_Green,
    esxVI_ManagedEntityStatus_Yellow,
    esxVI_ManagedEntityStatus_Red,
};

int esxVI_ManagedEntityStatus_CastFromAnyType
      (virConnectPtr conn, esxVI_AnyType *anyType,
       esxVI_ManagedEntityStatus *managedEntityStatus);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Enum: ObjectUpdateKind
 */

enum _esxVI_ObjectUpdateKind {
    esxVI_ObjectUpdateKind_Undefined = 0,
    esxVI_ObjectUpdateKind_Enter,
    esxVI_ObjectUpdateKind_Leave,
    esxVI_ObjectUpdateKind_Modify,
};

int esxVI_ObjectUpdateKind_Deserialize
      (virConnectPtr conn, xmlNodePtr node,
       esxVI_ObjectUpdateKind *objectUpdateKind);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Enum: PerfSummaryType
 */

enum _esxVI_PerfSummaryType {
    esxVI_PerfSummaryType_Undefined = 0,
    esxVI_PerfSummaryType_Average,
    esxVI_PerfSummaryType_Latest,
    esxVI_PerfSummaryType_Maximum,
    esxVI_PerfSummaryType_Minimum,
    esxVI_PerfSummaryType_None,
    esxVI_PerfSummaryType_Summation,
};

int esxVI_PerfSummaryType_Deserialize(virConnectPtr conn, xmlNodePtr node,
                                      esxVI_PerfSummaryType *perfSummaryType);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Enum: PerfStatsType
 */

enum _esxVI_PerfStatsType {
    esxVI_PerfStatsType_Undefined = 0,
    esxVI_PerfStatsType_Absolute,
    esxVI_PerfStatsType_Delta,
    esxVI_PerfStatsType_Rate,
};

int esxVI_PerfStatsType_Deserialize(virConnectPtr conn, xmlNodePtr node,
                                    esxVI_PerfStatsType *perfStatsType);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Enum: PropertyChangeOp
 */

enum _esxVI_PropertyChangeOp {
    esxVI_PropertyChangeOp_Undefined = 0,
    esxVI_PropertyChangeOp_Add,
    esxVI_PropertyChangeOp_Remove,
    esxVI_PropertyChangeOp_Assign,
    esxVI_PropertyChangeOp_IndirectRemove,
};

int esxVI_PropertyChangeOp_Deserialize
      (virConnectPtr conn, xmlNodePtr node,
       esxVI_PropertyChangeOp *propertyChangeOp);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Enum: SharesLevel
 */

enum _esxVI_SharesLevel {
    esxVI_SharesLevel_Undefined = 0,
    esxVI_SharesLevel_Custom,
    esxVI_SharesLevel_High,
    esxVI_SharesLevel_Low,
    esxVI_SharesLevel_Normal,
};

int esxVI_SharesLevel_Serialize(virConnectPtr conn,
                                esxVI_SharesLevel sharesLevel,
                                const char *element, virBufferPtr output,
                                esxVI_Boolean required);
int esxVI_SharesLevel_Deserialize(virConnectPtr conn, xmlNodePtr node,
                                  esxVI_SharesLevel *sharesLevel);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Enum: TaskInfoState
 */

enum _esxVI_TaskInfoState {
    esxVI_TaskInfoState_Undefined = 0,
    esxVI_TaskInfoState_Error,
    esxVI_TaskInfoState_Queued,
    esxVI_TaskInfoState_Running,
    esxVI_TaskInfoState_Success,
};

int esxVI_TaskInfoState_CastFromAnyType(virConnectPtr conn,
                                        esxVI_AnyType *anyType,
                                        esxVI_TaskInfoState *taskInfoState);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Enum: VirtualMachineMovePriority
 */

enum _esxVI_VirtualMachineMovePriority {
    esxVI_VirtualMachineMovePriority_Undefined = 0,
    esxVI_VirtualMachineMovePriority_LowPriority,
    esxVI_VirtualMachineMovePriority_HighPriority,
    esxVI_VirtualMachineMovePriority_DefaultPriority,
};

int esxVI_VirtualMachineMovePriority_Serialize
      (virConnectPtr conn,
       esxVI_VirtualMachineMovePriority virtualMachineMovePriority,
       const char *element, virBufferPtr output, esxVI_Boolean required);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Enum: VirtualMachinePowerState
 */

enum _esxVI_VirtualMachinePowerState {
    esxVI_VirtualMachinePowerState_Undefined = 0,
    esxVI_VirtualMachinePowerState_PoweredOff,
    esxVI_VirtualMachinePowerState_PoweredOn,
    esxVI_VirtualMachinePowerState_Suspended,
};

int esxVI_VirtualMachinePowerState_CastFromAnyType
      (virConnectPtr conn, esxVI_AnyType *anyType,
       esxVI_VirtualMachinePowerState *virtualMachinePowerState);
int esxVI_VirtualMachinePowerState_Serialize
      (virConnectPtr conn,
       esxVI_VirtualMachinePowerState virtualMachinePowerState,
       const char *element, virBufferPtr output, esxVI_Boolean required);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Type: Fault
 */

struct _esxVI_Fault {
    char *faultcode;                                       /* required */
    char *faultstring;                                     /* required */
};

int esxVI_Fault_Alloc(virConnectPtr conn, esxVI_Fault **fault);
void esxVI_Fault_Free(esxVI_Fault **fault);
int esxVI_Fault_Deserialize(virConnectPtr conn, xmlNodePtr node,
                            esxVI_Fault **fault);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Type: ManagedObjectReference
 */

struct _esxVI_ManagedObjectReference {
    esxVI_ManagedObjectReference *_next;                   /* optional */

    char *type;                                            /* required */
    char *value;                                           /* required */
};

int esxVI_ManagedObjectReference_Alloc
      (virConnectPtr conn,
       esxVI_ManagedObjectReference **managedObjectReference);
void esxVI_ManagedObjectReference_Free
       (esxVI_ManagedObjectReference **managedObjectReferenceList);
int esxVI_ManagedObjectReference_DeepCopy(virConnectPtr conn,
                                          esxVI_ManagedObjectReference **dest,
                                          esxVI_ManagedObjectReference *src);
int esxVI_ManagedObjectReference_CastFromAnyType(virConnectPtr conn,
                                                 esxVI_AnyType *anyType,
                                                 esxVI_ManagedObjectReference
                                                 **managedObjectReference,
                                                 const char *expectedType);
int esxVI_ManagedObjectReference_Serialize
      (virConnectPtr conn,
       esxVI_ManagedObjectReference *managedObjectReference,
       const char *element, virBufferPtr output, esxVI_Boolean required);
int esxVI_ManagedObjectReference_SerializeList
      (virConnectPtr conn,
       esxVI_ManagedObjectReference *managedObjectReference,
       const char *element, virBufferPtr output, esxVI_Boolean required);
int esxVI_ManagedObjectReference_Deserialize
      (virConnectPtr conn, xmlNodePtr node,
       esxVI_ManagedObjectReference **managedObjectReference,
       const char *expectedType);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Type: DynamicProperty
 */

struct _esxVI_DynamicProperty {
    esxVI_DynamicProperty *_next;                          /* optional */

    char *name;                                            /* required */
    esxVI_AnyType *val;                                    /* required */
};

int esxVI_DynamicProperty_Alloc(virConnectPtr conn,
                                esxVI_DynamicProperty **dynamicProperty);
void esxVI_DynamicProperty_Free
       (esxVI_DynamicProperty **dynamicPropertyList);
int esxVI_DynamicProperty_DeepCopy(virConnectPtr conn,
                                   esxVI_DynamicProperty **dest,
                                   esxVI_DynamicProperty *src);
int esxVI_DynamicProperty_DeepCopyList(virConnectPtr conn,
                                       esxVI_DynamicProperty **destList,
                                       esxVI_DynamicProperty *srcList);
int esxVI_DynamicProperty_AppendToList
      (virConnectPtr conn, esxVI_DynamicProperty **dynamicPropertyList,
       esxVI_DynamicProperty *dynamicProperty);
int esxVI_DynamicProperty_Deserialize(virConnectPtr conn, xmlNodePtr node,
                                      esxVI_DynamicProperty **dynamicProperty);
int esxVI_DynamicProperty_DeserializeList
      (virConnectPtr conn, xmlNodePtr node,
       esxVI_DynamicProperty **dynamicPropertyList);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Type: HostCpuIdInfo
 */

struct _esxVI_HostCpuIdInfo {
    esxVI_HostCpuIdInfo *_next;                            /* optional */

    esxVI_Int *level;                                      /* required */
    char *vendor;                                          /* optional */
    char *eax;                                             /* optional */
    char *ebx;                                             /* optional */
    char *ecx;                                             /* optional */
    char *edx;                                             /* optional */
};

int esxVI_HostCpuIdInfo_Alloc(virConnectPtr conn,
                              esxVI_HostCpuIdInfo **hostCpuIdInfo);
void esxVI_HostCpuIdInfo_Free(esxVI_HostCpuIdInfo **hostCpuIdInfoList);
int esxVI_HostCpuIdInfo_CastFromAnyType(virConnectPtr conn,
                                        esxVI_AnyType *anyType,
                                        esxVI_HostCpuIdInfo **hostCpuIdInfo);
int esxVI_HostCpuIdInfo_CastListFromAnyType
      (virConnectPtr conn, esxVI_AnyType *anyType,
       esxVI_HostCpuIdInfo **hostCpuIdInfoList);
int esxVI_HostCpuIdInfo_Deserialize(virConnectPtr conn, xmlNodePtr node,
                                    esxVI_HostCpuIdInfo **hostCpuIdInfo);
int esxVI_HostCpuIdInfo_DeserializeList
      (virConnectPtr conn, xmlNodePtr node,
       esxVI_HostCpuIdInfo **hostCpuIdInfoList);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Type: SelectionSpec
 */

struct _esxVI_SelectionSpec {
    esxVI_SelectionSpec *_next;                            /* optional */
    esxVI_TraversalSpec *_super;                           /* optional */

    char *name;                                            /* optional */
};

int esxVI_SelectionSpec_Alloc(virConnectPtr conn,
                              esxVI_SelectionSpec **selectionSpec);
void esxVI_SelectionSpec_Free(esxVI_SelectionSpec **selectionSpecList);
int esxVI_SelectionSpec_AppendToList(virConnectPtr conn,
                                     esxVI_SelectionSpec **selectionSpecList,
                                     esxVI_SelectionSpec *selectionSpec);
int esxVI_SelectionSpec_Serialize(virConnectPtr conn,
                                  esxVI_SelectionSpec *selectionSpec,
                                  const char *element, virBufferPtr output,
                                  esxVI_Boolean required);
int esxVI_SelectionSpec_SerializeList(virConnectPtr conn,
                                      esxVI_SelectionSpec *selectionSpecList,
                                      const char *element, virBufferPtr output,
                                      esxVI_Boolean required);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Type: TraversalSpec extends SelectionSpec
 */

struct _esxVI_TraversalSpec {
    esxVI_SelectionSpec *_base;                            /* required */

    char *type;                                            /* required */
    char *path;                                            /* required */
    esxVI_Boolean skip;                                    /* optional */
    esxVI_SelectionSpec *selectSet;                        /* optional, list */
};

int esxVI_TraversalSpec_Alloc(virConnectPtr conn,
                              esxVI_TraversalSpec **traversalSpec);
void esxVI_TraversalSpec_Free(esxVI_TraversalSpec **traversalSpec);
int esxVI_TraversalSpec_Serialize(virConnectPtr conn,
                                  esxVI_TraversalSpec *traversalSpec,
                                  const char *element, virBufferPtr output,
                                  esxVI_Boolean required);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Type: ObjectSpec
 */

struct _esxVI_ObjectSpec {
    esxVI_ObjectSpec *_next;                               /* optional */

    esxVI_ManagedObjectReference *obj;                     /* required */
    esxVI_Boolean skip;                                    /* optional */
    esxVI_SelectionSpec *selectSet;                        /* optional, list */
};

int esxVI_ObjectSpec_Alloc(virConnectPtr conn, esxVI_ObjectSpec **objectSpec);
void esxVI_ObjectSpec_Free(esxVI_ObjectSpec **objectSpecList);
int esxVI_ObjectSpec_AppendToList(virConnectPtr conn,
                                  esxVI_ObjectSpec **objectSpecList,
                                  esxVI_ObjectSpec *objectSpec);
int esxVI_ObjectSpec_Serialize(virConnectPtr conn,
                               esxVI_ObjectSpec *objectSpec,
                               const char *element, virBufferPtr output,
                               esxVI_Boolean required);
int esxVI_ObjectSpec_SerializeList(virConnectPtr conn,
                                   esxVI_ObjectSpec *objectSpecList,
                                   const char *element, virBufferPtr output,
                                   esxVI_Boolean required);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Type: PropertyChange
 */

struct _esxVI_PropertyChange {
    esxVI_PropertyChange *_next;                           /* optional */

    char *name;                                            /* required */
    esxVI_PropertyChangeOp op;                             /* required */
    esxVI_AnyType *val;                                    /* optional */
};

int esxVI_PropertyChange_Alloc(virConnectPtr conn,
                               esxVI_PropertyChange **propertyChange);
void esxVI_PropertyChange_Free(esxVI_PropertyChange **propertyChangeList);
int esxVI_PropertyChange_AppendToList
      (virConnectPtr conn, esxVI_PropertyChange **propertyChangeList,
       esxVI_PropertyChange *propertyChange);
int esxVI_PropertyChange_Deserialize(virConnectPtr conn, xmlNodePtr node,
                                     esxVI_PropertyChange **propertyChange);
int esxVI_PropertyChange_DeserializeList
      (virConnectPtr conn, xmlNodePtr node,
       esxVI_PropertyChange **propertyChangeList);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Type: PropertySpec
 */

struct _esxVI_PropertySpec {
    esxVI_PropertySpec *_next;                             /* optional */

    char *type;                                            /* required */
    esxVI_Boolean all;                                     /* optional */
    esxVI_String *pathSet;                                 /* optional, list */
};

int esxVI_PropertySpec_Alloc(virConnectPtr conn,
                             esxVI_PropertySpec **propertySpec);
void esxVI_PropertySpec_Free(esxVI_PropertySpec **propertySpecList);
int esxVI_PropertySpec_AppendToList(virConnectPtr conn,
                                    esxVI_PropertySpec **propertySpecList,
                                    esxVI_PropertySpec *propertySpec);
int esxVI_PropertySpec_Serialize(virConnectPtr conn,
                                 esxVI_PropertySpec *propertySpec,
                                 const char *element, virBufferPtr output,
                                 esxVI_Boolean required);
int esxVI_PropertySpec_SerializeList(virConnectPtr conn,
                                     esxVI_PropertySpec *propertySpecList,
                                     const char *element, virBufferPtr output,
                                     esxVI_Boolean required);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Type: PropertyFilterSpec
 */

struct _esxVI_PropertyFilterSpec {
    esxVI_PropertyFilterSpec *_next;                       /* optional */

    esxVI_PropertySpec *propSet;                           /* required, list */
    esxVI_ObjectSpec *objectSet;                           /* required, list */
};

int esxVI_PropertyFilterSpec_Alloc
      (virConnectPtr conn, esxVI_PropertyFilterSpec **propertyFilterSpec);
void esxVI_PropertyFilterSpec_Free
       (esxVI_PropertyFilterSpec **propertyFilterSpecList);
int esxVI_PropertyFilterSpec_AppendToList
      (virConnectPtr conn, esxVI_PropertyFilterSpec **propertyFilterSpecList,
       esxVI_PropertyFilterSpec *propertyFilterSpec);
int esxVI_PropertyFilterSpec_Serialize
      (virConnectPtr conn, esxVI_PropertyFilterSpec *propertyFilterSpec,
       const char *element, virBufferPtr output, esxVI_Boolean required);
int esxVI_PropertyFilterSpec_SerializeList
      (virConnectPtr conn, esxVI_PropertyFilterSpec *propertyFilterSpecList,
       const char *element, virBufferPtr output, esxVI_Boolean required);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Type: ObjectContent
 */

struct _esxVI_ObjectContent {
    esxVI_ObjectContent *_next;                            /* optional */

    esxVI_ManagedObjectReference *obj;                     /* required */
    esxVI_DynamicProperty *propSet;                        /* optional, list */
    /*esxVI_MissingProperty *missingSet; *//* optional, list *//* FIXME */
};

int esxVI_ObjectContent_Alloc(virConnectPtr conn,
                              esxVI_ObjectContent **objectContent);
void esxVI_ObjectContent_Free(esxVI_ObjectContent **objectContentList);
int esxVI_ObjectContent_AppendToList(virConnectPtr conn,
                                     esxVI_ObjectContent **objectContentList,
                                     esxVI_ObjectContent *objectContent);
int esxVI_ObjectContent_DeepCopy(virConnectPtr conn,
                                 esxVI_ObjectContent **dest,
                                 esxVI_ObjectContent *src);
int esxVI_ObjectContent_Deserialize(virConnectPtr conn, xmlNodePtr node,
                                    esxVI_ObjectContent **objectContent);
int esxVI_ObjectContent_DeserializeList
      (virConnectPtr conn, xmlNodePtr node,
       esxVI_ObjectContent **objectContentList);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Type: ObjectUpdate
 */

struct _esxVI_ObjectUpdate {
    esxVI_ObjectUpdate *_next;                             /* optional */

    esxVI_ObjectUpdateKind kind;                           /* required */
    esxVI_ManagedObjectReference *obj;                     /* required */
    esxVI_PropertyChange *changeSet;                       /* optional, list */
    /*esxVI_MissingProperty *missingSet; *//* optional, list *//* FIXME */
};

int esxVI_ObjectUpdate_Alloc(virConnectPtr conn,
                             esxVI_ObjectUpdate **objectUpdate);
void esxVI_ObjectUpdate_Free(esxVI_ObjectUpdate **objectUpdateList);
int esxVI_ObjectUpdate_AppendToList(virConnectPtr conn,
                                    esxVI_ObjectUpdate **objectUpdateList,
                                    esxVI_ObjectUpdate *objectUpdate);
int esxVI_ObjectUpdate_Deserialize(virConnectPtr conn, xmlNodePtr node,
                                   esxVI_ObjectUpdate **objectUpdate);
int esxVI_ObjectUpdate_DeserializeList(virConnectPtr conn, xmlNodePtr node,
                                       esxVI_ObjectUpdate **objectUpdateList);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Type: PropertyFilterUpdate
 */

struct _esxVI_PropertyFilterUpdate {
    esxVI_PropertyFilterUpdate *_next;                     /* optional */

    esxVI_ManagedObjectReference *filter;                  /* required */
    esxVI_ObjectUpdate *objectSet;                         /* optional, list */
    /*esxVI_MissingProperty *missingSet; *//* optional, list *//* FIXME */
};

int esxVI_PropertyFilterUpdate_Alloc
      (virConnectPtr conn,
       esxVI_PropertyFilterUpdate **propertyFilterUpdate);
void esxVI_PropertyFilterUpdate_Free
       (esxVI_PropertyFilterUpdate **propertyFilterUpdateList);
int esxVI_PropertyFilterUpdate_AppendToList
      (virConnectPtr conn,
       esxVI_PropertyFilterUpdate **propertyFilterUpdateList,
       esxVI_PropertyFilterUpdate *propertyFilterUpdate);
int esxVI_PropertyFilterUpdate_Deserialize
      (virConnectPtr conn, xmlNodePtr node,
       esxVI_PropertyFilterUpdate **propertyFilterUpdate);
int esxVI_PropertyFilterUpdate_DeserializeList
      (virConnectPtr conn, xmlNodePtr node,
       esxVI_PropertyFilterUpdate **propertyFilterUpdateList);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Type: AboutInfo
 */

struct _esxVI_AboutInfo {
    char *name;                                            /* required */
    char *fullName;                                        /* required */
    char *vendor;                                          /* required */
    char *version;                                         /* required */
    char *build;                                           /* required */
    char *localeVersion;                                   /* optional */
    char *localeBuild;                                     /* optional */
    char *osType;                                          /* required */
    char *productLineId;                                   /* required */
    char *apiType;                                         /* required */
    char *apiVersion;                                      /* required */
};

int esxVI_AboutInfo_Alloc(virConnectPtr conn, esxVI_AboutInfo **aboutInfo);
void esxVI_AboutInfo_Free(esxVI_AboutInfo **aboutInfo);
int esxVI_AboutInfo_Deserialize(virConnectPtr conn, xmlNodePtr node,
                                esxVI_AboutInfo **aboutInfo);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Type: ServiceContent
 */

struct _esxVI_ServiceContent {
    esxVI_ManagedObjectReference *rootFolder;              /* required */
    esxVI_ManagedObjectReference *propertyCollector;       /* required */
    esxVI_ManagedObjectReference *viewManager;             /* optional */
    esxVI_AboutInfo *about;                                /* required */
    esxVI_ManagedObjectReference *setting;                 /* optional */
    esxVI_ManagedObjectReference *userDirectory;           /* optional */
    esxVI_ManagedObjectReference *sessionManager;          /* optional */
    esxVI_ManagedObjectReference *authorizationManager;    /* optional */
    esxVI_ManagedObjectReference *perfManager;             /* optional */
    esxVI_ManagedObjectReference *scheduledTaskManager;    /* optional */
    esxVI_ManagedObjectReference *alarmManager;            /* optional */
    esxVI_ManagedObjectReference *eventManager;            /* optional */
    esxVI_ManagedObjectReference *taskManager;             /* optional */
    esxVI_ManagedObjectReference *extensionManager;        /* optional */
    esxVI_ManagedObjectReference *customizationSpecManager; /* optional */
    esxVI_ManagedObjectReference *customFieldsManager;     /* optional */
    esxVI_ManagedObjectReference *accountManager;          /* optional */
    esxVI_ManagedObjectReference *diagnosticManager;       /* optional */
    esxVI_ManagedObjectReference *licenseManager;          /* optional */
    esxVI_ManagedObjectReference *searchIndex;             /* optional */
    esxVI_ManagedObjectReference *fileManager;             /* optional */
    esxVI_ManagedObjectReference *virtualDiskManager;      /* optional */
    esxVI_ManagedObjectReference *virtualizationManager;   /* optional */
};

int esxVI_ServiceContent_Alloc(virConnectPtr conn,
                               esxVI_ServiceContent **serviceContent);
void esxVI_ServiceContent_Free(esxVI_ServiceContent **serviceContent);
int esxVI_ServiceContent_Deserialize(virConnectPtr conn, xmlNodePtr node,
                                     esxVI_ServiceContent **serviceContent);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Type: UpdateSet
 */

struct _esxVI_UpdateSet {
    char *version;                                         /* required */
    esxVI_PropertyFilterUpdate *filterSet;                 /* optional, list */
};

int esxVI_UpdateSet_Alloc(virConnectPtr conn, esxVI_UpdateSet **updateSet);
void esxVI_UpdateSet_Free(esxVI_UpdateSet **updateSet);
int esxVI_UpdateSet_Deserialize(virConnectPtr conn, xmlNodePtr node,
                                esxVI_UpdateSet **updateSet);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Type: SharesInfo
 */

struct _esxVI_SharesInfo {
    esxVI_Int *shares;                                     /* required */
    esxVI_SharesLevel level;                               /* required */
};

int esxVI_SharesInfo_Alloc(virConnectPtr conn, esxVI_SharesInfo **sharesInfo);
void esxVI_SharesInfo_Free(esxVI_SharesInfo **sharesInfo);
int esxVI_SharesInfo_CastFromAnyType(virConnectPtr conn,
                                     esxVI_AnyType *anyType,
                                     esxVI_SharesInfo **sharesInfo);
int esxVI_SharesInfo_Deserialize(virConnectPtr conn, xmlNodePtr node,
                                 esxVI_SharesInfo **sharesInfo);
int esxVI_SharesInfo_Serialize(virConnectPtr conn,
                               esxVI_SharesInfo *sharesInfo,
                               const char *element, virBufferPtr output,
                               esxVI_Boolean required);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Type: ResourceAllocationInfo
 */

struct _esxVI_ResourceAllocationInfo {
    esxVI_Long *reservation;                               /* optional */
    esxVI_Boolean expandableReservation;                   /* optional */
    esxVI_Long *limit;                                     /* optional */
    esxVI_SharesInfo *shares;                              /* optional */
    esxVI_Long *overheadLimit;                             /* optional */
};

int esxVI_ResourceAllocationInfo_Alloc
      (virConnectPtr conn,
       esxVI_ResourceAllocationInfo **resourceAllocationInfo);
void esxVI_ResourceAllocationInfo_Free
       (esxVI_ResourceAllocationInfo **resourceAllocationInfo);
int esxVI_ResourceAllocationInfo_Serialize
      (virConnectPtr conn, esxVI_ResourceAllocationInfo *resourceAllocationInfo,
       const char *element, virBufferPtr output, esxVI_Boolean required);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Type: ResourcePoolResourceUsage
 */

struct _esxVI_ResourcePoolResourceUsage {
    esxVI_Long *reservationUsed;                           /* required */
    esxVI_Long *reservationUsedForVm;                      /* required */
    esxVI_Long *unreservedForPool;                         /* required */
    esxVI_Long *unreservedForVm;                           /* required */
    esxVI_Long *overallUsage;                              /* required */
    esxVI_Long *maxUsage;                                  /* required */
};

int esxVI_ResourcePoolResourceUsage_Alloc
      (virConnectPtr conn,
       esxVI_ResourcePoolResourceUsage **resourcePoolResourceUsage);
void esxVI_ResourcePoolResourceUsage_Free
       (esxVI_ResourcePoolResourceUsage **resourcePoolResourceUsage);
int esxVI_ResourcePoolResourceUsage_CastFromAnyType
      (virConnectPtr conn, esxVI_AnyType *anyType,
       esxVI_ResourcePoolResourceUsage **resourcePoolResourceUsage);
int esxVI_ResourcePoolResourceUsage_Deserialize
      (virConnectPtr conn, xmlNodePtr node,
       esxVI_ResourcePoolResourceUsage **resourcePoolResourceUsage);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Type: VirtualMachineConfigSpec
 */

/* FIXME: implement the rest */
struct _esxVI_VirtualMachineConfigSpec {
    char *changeVersion;                                   /* optional */
    char *name;                                            /* optional */
    char *version;                                         /* optional */
    char *uuid;                                            /* optional */
    esxVI_Long *npivNodeWorldWideName;                     /* optional, list */
    esxVI_Long *npivPortWorldWideName;                     /* optional, list */
    char *npivWorldWideNameType;                           /* optional */
    char *npivWorldWideNameOp;                             /* optional */
    char *locationId;                                      /* optional */
    char *guestId;                                         /* optional */
    char *alternateGuestName;                              /* optional */
    char *annotation;                                      /* optional */
    //esxVI_VirtualMachineFileInfo *files; /* optional */
    //esxVI_ToolsConfigInfo *tools; /* optional */
    //esxVI_VirtualMachineFlagInfo *flags; /* optional */
    //esxVI_VirtualMachineConsolePreferences *consolePreferences; /* optional */
    //esxVI_VirtualMachineDefaultPowerOpInfo *powerOpInfo; /* optional */
    esxVI_Int *numCPUs;                                    /* optional */
    esxVI_Long *memoryMB;                                  /* optional */
    //esxVI_VirtualDeviceConfigSpec *deviceChange; /* optional, list */
    esxVI_ResourceAllocationInfo *cpuAllocation;           /* optional */
    esxVI_ResourceAllocationInfo *memoryAllocation;        /* optional */
    //esxVI_VirtualMachineAffinityInfo *cpuAffinity; /* optional */
    //esxVI_VirtualMachineAffinityInfo *memoryAffinity; /* optional */
    //esxVI_VirtualMachineNetworkShaperInfo *networkShaper; /* optional */
    //esxVI_VirtualMachineCpuIdInfoSpec *cpuFeatureMask; /* optional, list */
    //esxVI_OptionValue *extraConfig; /* optional, list */
    char *swapPlacement;                                   /* optional */
    //esxVI_VirtualMachineBootOptions *bootOptions; /* optional */
};

int esxVI_VirtualMachineConfigSpec_Alloc
      (virConnectPtr conn,
       esxVI_VirtualMachineConfigSpec **virtualMachineConfigSpec);
void esxVI_VirtualMachineConfigSpec_Free
       (esxVI_VirtualMachineConfigSpec **virtualMachineConfigSpec);
int esxVI_VirtualMachineConfigSpec_Serialize
      (virConnectPtr conn,
       esxVI_VirtualMachineConfigSpec *virtualMachineConfigSpec,
       const char *element, virBufferPtr output, esxVI_Boolean required);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Type: Event
 */

/* FIXME: implement the rest */
struct _esxVI_Event {
    esxVI_Event *_next;                                    /* optional */

    esxVI_Int *key;                                        /* required */
    esxVI_Int *chainId;                                    /* required */
    esxVI_DateTime *createdTime;                           /* required */
    char *userName;                                        /* required */
    //??? datacenter;                                      /* optional */
    //??? computeResource;                                 /* optional */
    //??? host;                                            /* optional */
    //??? vm;                                              /* optional */
    char *fullFormattedMessage;                            /* optional */
};

int esxVI_Event_Alloc(virConnectPtr conn, esxVI_Event **event);
void esxVI_Event_Free(esxVI_Event **eventList);
int esxVI_Event_Deserialize(virConnectPtr conn, xmlNodePtr node,
                            esxVI_Event **event);
int esxVI_Event_DeserializeList(virConnectPtr conn, xmlNodePtr node,
                                esxVI_Event **eventList);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Type: UserSession
 */

struct _esxVI_UserSession {
    char *key;                                             /* required */
    char *userName;                                        /* required */
    char *fullName;                                        /* required */
    esxVI_DateTime *loginTime;                             /* required */
    esxVI_DateTime *lastActiveTime;                        /* required */
    char *locale;                                          /* required */
    char *messageLocale;                                   /* required */
};

int esxVI_UserSession_Alloc(virConnectPtr conn,
                            esxVI_UserSession **userSession);
void esxVI_UserSession_Free(esxVI_UserSession **userSession);
int esxVI_UserSession_CastFromAnyType(virConnectPtr conn,
                                      esxVI_AnyType *anyType,
                                      esxVI_UserSession **userSession);
int esxVI_UserSession_Deserialize(virConnectPtr conn, xmlNodePtr node,
                                  esxVI_UserSession **userSession);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Type: ElementDescription extends Description
 *
 *          In contrast to SelectionSpec and TraversalSpec just merge
 *          Description into ElementDescription for simplicity, because
 *          only ElementDescription is used.
 */

struct _esxVI_ElementDescription {
    esxVI_ElementDescription *_next;                       /* optional */

    /* Description */
    char *label;                                           /* required */
    char *summary;                                         /* required */

    /* ElementDescription */
    char *key;                                             /* required */
};

int esxVI_ElementDescription_Alloc
      (virConnectPtr conn, esxVI_ElementDescription **elementDescription);
void esxVI_ElementDescription_Free
       (esxVI_ElementDescription **elementDescription);
int esxVI_ElementDescription_Deserialize
      (virConnectPtr conn, xmlNodePtr node,
       esxVI_ElementDescription **elementDescription);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Type: PerfMetricId
 */

struct _esxVI_PerfMetricId {
    esxVI_PerfMetricId *_next;                             /* optional */

    esxVI_Int *counterId;                                  /* required */
    char *instance;                                        /* required */
};

int esxVI_PerfMetricId_Alloc(virConnectPtr conn,
                             esxVI_PerfMetricId **perfMetricId);
void esxVI_PerfMetricId_Free(esxVI_PerfMetricId **perfMetricId);
int esxVI_PerfMetricId_Serialize(virConnectPtr conn,
                                 esxVI_PerfMetricId *perfMetricId,
                                 const char *element, virBufferPtr output,
                                 esxVI_Boolean required);
int esxVI_PerfMetricId_SerializeList(virConnectPtr conn,
                                     esxVI_PerfMetricId *perfMetricIdList,
                                     const char *element, virBufferPtr output,
                                     esxVI_Boolean required);
int esxVI_PerfMetricId_Deserialize(virConnectPtr conn, xmlNodePtr node,
                                   esxVI_PerfMetricId **perfMetricId);
int esxVI_PerfMetricId_DeserializeList(virConnectPtr conn, xmlNodePtr node,
                                       esxVI_PerfMetricId **perfMetricIdList);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Type: PerfCounterInfo
 */

struct _esxVI_PerfCounterInfo {
    esxVI_PerfCounterInfo *_next;                          /* optional */

    esxVI_Int *key;                                        /* required */
    esxVI_ElementDescription *nameInfo;                    /* required */
    esxVI_ElementDescription *groupInfo;                   /* required */
    esxVI_ElementDescription *unitInfo;                    /* required */
    esxVI_PerfSummaryType rollupType;                      /* required */
    esxVI_PerfStatsType statsType;                         /* required */
    esxVI_Int *level;                                      /* optional */
    esxVI_Int *associatedCounterId;                        /* optional, list */
};

int esxVI_PerfCounterInfo_Alloc(virConnectPtr conn,
                                esxVI_PerfCounterInfo **perfCounterInfo);
void esxVI_PerfCounterInfo_Free(esxVI_PerfCounterInfo **perfCounterInfo);
int esxVI_PerfCounterInfo_Deserialize(virConnectPtr conn, xmlNodePtr node,
                                      esxVI_PerfCounterInfo **perfCounterInfo);
int esxVI_PerfCounterInfo_DeserializeList
      (virConnectPtr conn, xmlNodePtr node,
       esxVI_PerfCounterInfo **perfCounterInfoList);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Type: PerfQuerySpec
 */

struct _esxVI_PerfQuerySpec {
    esxVI_PerfQuerySpec *_next;                            /* optional */

    esxVI_ManagedObjectReference *entity;                  /* required */
    esxVI_DateTime *startTime;                             /* optional */
    esxVI_DateTime *endTime;                               /* optional */
    esxVI_Int *maxSample;                                  /* optional */
    esxVI_PerfMetricId *metricId;                          /* optional, list */
    esxVI_Int *intervalId;                                 /* optional */
    char *format;                                          /* optional */ // FIXME: see PerfFormat
};

int esxVI_PerfQuerySpec_Alloc(virConnectPtr conn,
                              esxVI_PerfQuerySpec **perfQuerySpec);
void esxVI_PerfQuerySpec_Free(esxVI_PerfQuerySpec **perfQuerySpec);
int esxVI_PerfQuerySpec_Serialize(virConnectPtr conn,
                                  esxVI_PerfQuerySpec *perfQuerySpec,
                                  const char *element, virBufferPtr output,
                                  esxVI_Boolean required);
int esxVI_PerfQuerySpec_SerializeList(virConnectPtr conn,
                                      esxVI_PerfQuerySpec *perfQuerySpecList,
                                      const char *element, virBufferPtr output,
                                      esxVI_Boolean required);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Type: PerfSampleInfo
 */

struct _esxVI_PerfSampleInfo {
    esxVI_PerfSampleInfo *_next;                           /* optional */

    esxVI_DateTime *timestamp;                             /* required */
    esxVI_Int *interval;                                   /* required */
};

int esxVI_PerfSampleInfo_Alloc(virConnectPtr conn,
                               esxVI_PerfSampleInfo **perfSampleInfo);
void esxVI_PerfSampleInfo_Free(esxVI_PerfSampleInfo **perfSampleInfo);
int esxVI_PerfSampleInfo_AppendToList(virConnectPtr conn,
                                      esxVI_PerfSampleInfo **perfSampleInfoList,
                                      esxVI_PerfSampleInfo *perfSampleInfo);
int esxVI_PerfSampleInfo_Deserialize(virConnectPtr conn, xmlNodePtr node,
                                     esxVI_PerfSampleInfo **perfSampleInfo);
int esxVI_PerfSampleInfo_DeserializeList
      (virConnectPtr conn, xmlNodePtr node,
       esxVI_PerfSampleInfo **perfSampleInfoList);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Type: PerfMetricIntSeries extends PerfMetricSeries
 *
 *          In contrast to SelectionSpec and TraversalSpec just merge
 *          PerfMetricSeries into PerfMetricIntSeries for simplicity, because
 *          only PerfMetricIntSeries is used and the other type inheriting
 *          PerfMetricSeries (PerfMetricSeriesCSV) is not used.
 */

struct _esxVI_PerfMetricIntSeries {
    esxVI_PerfMetricIntSeries *_next;                      /* optional */

    /* PerfMetricSeries */
    esxVI_PerfMetricId *id;                                /* required */

    /* PerfMetricIntSeries */
    esxVI_Long *value;                                     /* optional, list */
};

int esxVI_PerfMetricIntSeries_Alloc
      (virConnectPtr conn, esxVI_PerfMetricIntSeries **perfMetricIntSeries);
void esxVI_PerfMetricIntSeries_Free
       (esxVI_PerfMetricIntSeries **perfMetricIntSeries);
int esxVI_PerfMetricIntSeries_AppendToList
      (virConnectPtr conn, esxVI_PerfMetricIntSeries **perfMetricIntSeriesList,
       esxVI_PerfMetricIntSeries *perfMetricIntSeries);
int esxVI_PerfMetricIntSeries_Deserialize
      (virConnectPtr conn, xmlNodePtr node,
       esxVI_PerfMetricIntSeries **perfMetricIntSeries);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Type: PerfEntityMetric extends PerfEntityMetricBase
 *
 *          In contrast to SelectionSpec and TraversalSpec just merge
 *          PerfEntityMetricBase into PerfEntityMetric for simplicity, because
 *          only PerfEntityMetric is used and the other type inheriting
 *          PerfEntityMetric (PerfEntityMetricCSV) is not used.
 *
 *          Also use PerfMetricIntSeries instead of the correct base type
 *          PerfMetricSeries for the value property, because only
 *          PerfMetricIntSeries is used.
 */

struct _esxVI_PerfEntityMetric {
    esxVI_PerfEntityMetric *_next;                         /* optional */

    /* PerfEntityMetricBase */
    esxVI_ManagedObjectReference *entity;                  /* required */

    /* PerfEntityMetric */
    esxVI_PerfSampleInfo *sampleInfo;                      /* optional, list */
    esxVI_PerfMetricIntSeries *value;                      /* optional, list */
};

int esxVI_PerfEntityMetric_Alloc(virConnectPtr conn,
                                 esxVI_PerfEntityMetric **perfEntityMetric);
void esxVI_PerfEntityMetric_Free
       (esxVI_PerfEntityMetric **perfEntityMetric);
int esxVI_PerfEntityMetric_Deserialize
      (virConnectPtr conn, xmlNodePtr node,
       esxVI_PerfEntityMetric **perfEntityMetric);
int esxVI_PerfEntityMetric_DeserializeList
      (virConnectPtr conn, xmlNodePtr node,
       esxVI_PerfEntityMetric **perfEntityMetricList);

#endif /* __ESX_VI_TYPES_H__ */
