/*
 * esx_vi_types.h: client for the VMware VI API 2.5 to manage ESX hosts
 *
 * Copyright (C) 2009-2011 Matthias Bolte <matthias.bolte@googlemail.com>
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

#ifndef __ESX_VI_TYPES_H__
# define __ESX_VI_TYPES_H__

# include "virbuffer.h"

typedef enum _esxVI_Type esxVI_Type;
typedef struct _esxVI_Object esxVI_Object;
typedef struct _esxVI_ManagedObject esxVI_ManagedObject;



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * XSD
 */

typedef enum _esxVI_Boolean esxVI_Boolean;
typedef struct _esxVI_AnyType esxVI_AnyType;
typedef struct _esxVI_String esxVI_String;
typedef struct _esxVI_Byte esxVI_Byte;
typedef struct _esxVI_Int esxVI_Int;
typedef struct _esxVI_Long esxVI_Long;
typedef struct _esxVI_DateTime esxVI_DateTime;



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * SOAP
 */

typedef struct _esxVI_Fault esxVI_Fault;



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Objects
 */

typedef struct _esxVI_MethodFault esxVI_MethodFault;
typedef struct _esxVI_ManagedObjectReference esxVI_ManagedObjectReference;
typedef struct _esxVI_Event esxVI_Event;

# include "esx_vi_types.generated.typedef"



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Type
 */

enum _esxVI_Type {
    esxVI_Type_Undefined = 0,
    esxVI_Type_Boolean,
    esxVI_Type_AnyType,
    esxVI_Type_String,
    esxVI_Type_Byte,
    esxVI_Type_Short,
    esxVI_Type_Int,
    esxVI_Type_Long,
    esxVI_Type_DateTime,
    esxVI_Type_Fault,
    esxVI_Type_MethodFault,
    esxVI_Type_ManagedObjectReference,
    esxVI_Type_Event,

# include "esx_vi_types.generated.typeenum"

    esxVI_Type_Other,
};

const char *esxVI_Type_ToString(esxVI_Type type);
esxVI_Type esxVI_Type_FromString(const char *type);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Object extends List
 */

struct _esxVI_Object {
    esxVI_Object *_next;                                   /* optional */
    esxVI_Type _type;                                      /* required */
};



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * ManagedObject extends Object
 */

struct _esxVI_ManagedObject {
    esxVI_ManagedObject *_next;                            /* optional */
    esxVI_Type _type;                                      /* required */
    esxVI_ManagedObjectReference *_reference;              /* required */
};



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * XSD: Boolean
 */

enum _esxVI_Boolean {
    esxVI_Boolean_Undefined = 0,
    esxVI_Boolean_True,
    esxVI_Boolean_False,
};

int esxVI_Boolean_Serialize(esxVI_Boolean boolean_, const char *element,
                            virBufferPtr output);
int esxVI_Boolean_Deserialize(xmlNodePtr node, esxVI_Boolean *boolean_);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * XSD: AnyType
 */

struct _esxVI_AnyType {
    esxVI_AnyType *_unused;                                /* optional */
    esxVI_Type _type; /* = esxVI_Type_AnyType */           /* required */

    xmlNodePtr node;                                       /* required */
    esxVI_Type type;                                       /* required */
    char *other;                                           /* required */
    char *value;                                           /* required */
    union {
        esxVI_Boolean boolean;                             /* optional */
        char *string;                                      /* optional */
        int8_t int8;                                       /* optional */
        int16_t int16;                                     /* optional */
        int32_t int32;                                     /* optional */
        int64_t int64;                                     /* optional */
    };
};

int esxVI_AnyType_Alloc(esxVI_AnyType **anyType);
void esxVI_AnyType_Free(esxVI_AnyType **anyType);
const char *esxVI_AnyType_TypeToString(esxVI_AnyType *anyType);
int esxVI_AnyType_ExpectType(esxVI_AnyType *anyType, esxVI_Type type);
int esxVI_AnyType_DeepCopy(esxVI_AnyType **dest, esxVI_AnyType *src);
int esxVI_AnyType_Deserialize(xmlNodePtr node, esxVI_AnyType **anyType);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * XSD: String
 */

struct _esxVI_String {
    esxVI_String *_next;                                   /* optional */
    esxVI_Type _type;                                      /* required */

    char *value;                                           /* required */
};

int esxVI_String_Alloc(esxVI_String **string);
void esxVI_String_Free(esxVI_String **stringList);
int esxVI_String_Validate(esxVI_String *string);
bool esxVI_String_ListContainsValue(esxVI_String *stringList, const char *value);
int esxVI_String_AppendToList(esxVI_String **stringList, esxVI_String *string);
int esxVI_String_AppendValueToList(esxVI_String **stringList,
                                   const char *value);
int esxVI_String_AppendValueListToList(esxVI_String **stringList,
                                       const char *valueList);
int esxVI_String_DeepCopy(esxVI_String **dest, esxVI_String *src);
int esxVI_String_DeepCopyList(esxVI_String **destList, esxVI_String *srcList);
int esxVI_String_DeepCopyValue(char **dest, const char *src);
int esxVI_String_CastFromAnyType(esxVI_AnyType *anyType, esxVI_String **string);
int esxVI_String_CastValueFromAnyType(esxVI_AnyType *anyType, char **string);
int esxVI_String_Serialize(esxVI_String *string, const char *element,
                           virBufferPtr output);
int esxVI_String_SerializeList(esxVI_String *stringList, const char *element,
                               virBufferPtr output);
int esxVI_String_SerializeValue(const char *value, const char *element,
                                virBufferPtr output);
int esxVI_String_Deserialize(xmlNodePtr node, esxVI_String **string);
int esxVI_String_DeserializeList(xmlNodePtr node, esxVI_String **stringList);
int esxVI_String_DeserializeValue(xmlNodePtr node, char **value);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * XSD: Byte
 */

struct _esxVI_Byte {
    esxVI_Byte *_next;                                     /* optional */
    esxVI_Type _type;                                      /* required */

    int8_t value;                                          /* required */
};

int esxVI_Byte_Alloc(esxVI_Byte **number);
void esxVI_Byte_Free(esxVI_Byte **numberList);
int esxVI_Byte_Validate(esxVI_Byte *number);
int esxVI_Byte_AppendToList(esxVI_Byte **numberList, esxVI_Byte *number);
int esxVI_Byte_DeepCopy(esxVI_Byte **dest, esxVI_Byte *src);
int esxVI_Byte_DeepCopyList(esxVI_Byte **destList, esxVI_Byte *srcList);
int esxVI_Byte_Serialize(esxVI_Byte *number, const char *element,
                         virBufferPtr output);
int esxVI_Byte_SerializeList(esxVI_Byte *numberList, const char *element,
                             virBufferPtr output);
int esxVI_Byte_Deserialize(xmlNodePtr node, esxVI_Byte **number);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * XSD: Int
 */

struct _esxVI_Int {
    esxVI_Int *_next;                                      /* optional */
    esxVI_Type _type;                                      /* required */

    int32_t value;                                         /* required */
};

int esxVI_Int_Alloc(esxVI_Int **number);
void esxVI_Int_Free(esxVI_Int **numberList);
int esxVI_Int_Validate(esxVI_Int *number);
int esxVI_Int_AppendToList(esxVI_Int **numberList, esxVI_Int *number);
int esxVI_Int_DeepCopy(esxVI_Int **dest, esxVI_Int *src);
int esxVI_Int_Serialize(esxVI_Int *number, const char *element,
                        virBufferPtr output);
int esxVI_Int_SerializeList(esxVI_Int *numberList, const char *element,
                            virBufferPtr output);
int esxVI_Int_Deserialize(xmlNodePtr node, esxVI_Int **number);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * XSD: Long
 */

struct _esxVI_Long {
    esxVI_Long *_next;                                     /* optional */
    esxVI_Type _type;                                      /* required */

    int64_t value;                                         /* required */
};

int esxVI_Long_Alloc(esxVI_Long **number);
void esxVI_Long_Free(esxVI_Long **numberList);
int esxVI_Long_Validate(esxVI_Long *number);
int esxVI_Long_AppendToList(esxVI_Long **numberList, esxVI_Long *number);
int esxVI_Long_DeepCopy(esxVI_Long **dest, esxVI_Long *src);
int esxVI_Long_CastFromAnyType(esxVI_AnyType *anyType, esxVI_Long **number);
int esxVI_Long_Serialize(esxVI_Long *number, const char *element,
                         virBufferPtr output);
int esxVI_Long_SerializeList(esxVI_Long *numberList, const char *element,
                             virBufferPtr output);
int esxVI_Long_Deserialize(xmlNodePtr node, esxVI_Long **number);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * XSD: DateTime
 */

struct _esxVI_DateTime {
    esxVI_DateTime *_unused;                               /* optional */
    esxVI_Type _type;                                      /* required */

    char *value;                                           /* required */
};

int esxVI_DateTime_Alloc(esxVI_DateTime **dateTime);
void esxVI_DateTime_Free(esxVI_DateTime **dateTime);
int esxVI_DateTime_Validate(esxVI_DateTime *dateTime);
int esxVI_DateTime_DeepCopy(esxVI_DateTime **dest, esxVI_DateTime *src);
int esxVI_DateTime_Serialize(esxVI_DateTime *dateTime, const char *element,
                             virBufferPtr output);
int esxVI_DateTime_Deserialize(xmlNodePtr node, esxVI_DateTime **dateTime);
int esxVI_DateTime_ConvertToCalendarTime(esxVI_DateTime *dateTime,
                                         long long *secondsSinceEpoch);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * SOAP: Fault
 */

struct _esxVI_Fault {
    esxVI_Fault *_unused;                                  /* optional */
    esxVI_Type _type;                                      /* required */

    char *faultcode;                                       /* required */
    char *faultstring;                                     /* required */
};

int esxVI_Fault_Alloc(esxVI_Fault **fault);
void esxVI_Fault_Free(esxVI_Fault **fault);
int esxVI_Fault_Validate(esxVI_Fault *fault);
int esxVI_Fault_Deserialize(xmlNodePtr node, esxVI_Fault **fault);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Object: MethodFault
 */

/*
 * FIXME: This is just a minimal implementation of the MethodFault type.
 *        A complete implementation would require to implement dozens of
 *        extending types too.
 */
struct _esxVI_MethodFault {
    esxVI_MethodFault *_unused;                            /* optional */
    esxVI_Type _type;                                      /* required */

    char *_actualType;                                     /* required */
};

int esxVI_MethodFault_Alloc(esxVI_MethodFault **methodfault);
void esxVI_MethodFault_Free(esxVI_MethodFault **methodFault);
int esxVI_MethodFault_Deserialize(xmlNodePtr node,
                                  esxVI_MethodFault **methodFault);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Object: ManagedObjectReference
 */

struct _esxVI_ManagedObjectReference {
    esxVI_ManagedObjectReference *_next;                   /* optional */
    esxVI_Type _type;                                      /* required */

    char *type;                                            /* required */
    char *value;                                           /* required */
};

int esxVI_ManagedObjectReference_Alloc
      (esxVI_ManagedObjectReference **managedObjectReference);
void esxVI_ManagedObjectReference_Free
       (esxVI_ManagedObjectReference **managedObjectReferenceList);
int esxVI_ManagedObjectReference_DeepCopy(esxVI_ManagedObjectReference **dest,
                                          esxVI_ManagedObjectReference *src);
int esxVI_ManagedObjectReference_AppendToList
      (esxVI_ManagedObjectReference **managedObjectReferenceList,
       esxVI_ManagedObjectReference *managedObjectReference);
int esxVI_ManagedObjectReference_CastFromAnyType
      (esxVI_AnyType *anyType,
       esxVI_ManagedObjectReference **managedObjectReference);
int esxVI_ManagedObjectReference_CastListFromAnyType
      (esxVI_AnyType *anyType,
       esxVI_ManagedObjectReference **managedObjectReferenceList);
int esxVI_ManagedObjectReference_Serialize
      (esxVI_ManagedObjectReference *managedObjectReference,
       const char *element, virBufferPtr output);
int esxVI_ManagedObjectReference_SerializeList
      (esxVI_ManagedObjectReference *managedObjectReference,
       const char *element, virBufferPtr output);
int esxVI_ManagedObjectReference_Deserialize
      (xmlNodePtr node, esxVI_ManagedObjectReference **managedObjectReference);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Type: Event
 */

struct _esxVI_Event {
    esxVI_Event *_next;                                    /* optional */
    esxVI_Type _type;                                      /* required */
    char *_actualType;                                     /* required */

    esxVI_Int *key;                                        /* required */
    esxVI_Int *chainId;                                    /* required */
    esxVI_DateTime *createdTime;                           /* required */
    char *userName;                                        /* required */
    /* FIXME: datacenter is currently ignored */
    /* FIXME: computeResource is currently ignored */
    /* FIXME: host is currently ignored */
    esxVI_VmEventArgument *vm;                             /* optional */
    char *fullFormattedMessage;                            /* optional */
};

int esxVI_Event_Alloc(esxVI_Event **item);
void esxVI_Event_Free(esxVI_Event **item);
int esxVI_Event_Validate(esxVI_Event *item);
int esxVI_Event_AppendToList(esxVI_Event **list, esxVI_Event *item);
int esxVI_Event_CastFromAnyType(esxVI_AnyType *anyType, esxVI_Event **item);
int esxVI_Event_CastListFromAnyType(esxVI_AnyType *anyType, esxVI_Event **list);
int esxVI_Event_Deserialize(xmlNodePtr node, esxVI_Event **item);
int esxVI_Event_DeserializeList(xmlNodePtr node, esxVI_Event **list);



# include "esx_vi_types.generated.h"



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Enum: VirtualMachinePowerState (Additions)
 */

int esxVI_VirtualMachinePowerState_ConvertToLibvirt
      (esxVI_VirtualMachinePowerState powerState);

#endif /* __ESX_VI_TYPES_H__ */
