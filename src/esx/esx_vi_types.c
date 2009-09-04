
/*
 * esx_vi_types.c: client for the VMware VI API 2.5 to manage ESX hosts
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

#include <config.h>

#include <libxml/parser.h>
#include <libxml/xpathInternals.h>

#include "buf.h"
#include "datatypes.h"
#include "memory.h"
#include "logging.h"
#include "util.h"
#include "virterror_internal.h"
#include "esx_vi.h"
#include "esx_vi_types.h"

#define VIR_FROM_THIS VIR_FROM_ESX

#define ESX_VI_ERROR(conn, code, fmt...)                                      \
    virReportErrorHelper(conn, VIR_FROM_ESX, code, __FILE__, __FUNCTION__,    \
                         __LINE__, fmt)



#define ESV_VI__XML_TAG__OPEN(_buffer, _element, _type)                       \
    do {                                                                      \
        virBufferAddLit(_buffer, "<");                                        \
        virBufferAdd(_buffer, _element, -1);                                  \
        virBufferAddLit(_buffer, " xmlns=\"urn:vim25\" xsi:type=\"");         \
        virBufferAdd(_buffer, _type, -1);                                     \
        virBufferAddLit(_buffer, "\">");                                      \
    } while (0)



#define ESV_VI__XML_TAG__CLOSE(_buffer, _element)                             \
    do {                                                                      \
        virBufferAddLit(_buffer, "</");                                       \
        virBufferAdd(_buffer, _element, -1);                                  \
        virBufferAddLit(_buffer, ">");                                        \
    } while (0)



#define ESX_VI__TEMPLATE__ALLOC(_type)                                        \
    int                                                                       \
    esxVI_##_type##_Alloc(virConnectPtr conn, esxVI_##_type **ptrptr)         \
    {                                                                         \
        return esxVI_Alloc(conn, (void **)ptrptr, sizeof (esxVI_##_type));    \
    }



#define ESX_VI__TEMPLATE__FREE(_type, _body)                                  \
    void                                                                      \
    esxVI_##_type##_Free(esxVI_##_type **ptrptr)                              \
    {                                                                         \
        esxVI_##_type *item = NULL;                                           \
                                                                              \
        if (ptrptr == NULL || *ptrptr == NULL) {                              \
            return;                                                           \
        }                                                                     \
                                                                              \
        item = *ptrptr;                                                       \
                                                                              \
        _body                                                                 \
                                                                              \
        VIR_FREE(*ptrptr);                                                    \
    }



#define ESX_VI__TEMPLATE__LIST__APPEND(_type)                                 \
    int                                                                       \
    esxVI_##_type##_AppendToList(virConnectPtr conn, esxVI_##_type **list,    \
                                 esxVI_##_type *item)                         \
    {                                                                         \
        return esxVI_List_Append(conn, (esxVI_List **)list,                   \
                                 (esxVI_List *)item);                         \
    }



#define ESX_VI__TEMPLATE__LIST__DEEP_COPY(_type)                              \
    int                                                                       \
    esxVI_##_type##_DeepCopyList(virConnectPtr conn,                          \
                                 esxVI_##_type **destList,                    \
                                 esxVI_##_type *srcList)                      \
    {                                                                         \
        return esxVI_List_DeepCopy                                            \
                 (conn, (esxVI_List **)destList, (esxVI_List *)srcList,       \
                  (esxVI_List_DeepCopyFunc)esxVI_##_type##_DeepCopy,          \
                  (esxVI_List_FreeFunc)esxVI_##_type##_Free);                 \
    }



#define ESX_VI__TEMPLATE__LIST__SERIALIZE(_type)                              \
    int                                                                       \
    esxVI_##_type##_SerializeList(virConnectPtr conn, esxVI_##_type *list,    \
                                  const char* element, virBufferPtr output,   \
                                  esxVI_Boolean required)                     \
    {                                                                         \
        return esxVI_List_Serialize(conn, (esxVI_List *)list,                 \
                                    element, output, required,                \
                                    (esxVI_List_SerializeFunc)                \
                                      esxVI_##_type##_Serialize);             \
    }



#define ESX_VI__TEMPLATE__LIST__DESERIALIZE(_type)                            \
    int                                                                       \
    esxVI_##_type##_DeserializeList(virConnectPtr conn, xmlNodePtr node,      \
                                    esxVI_##_type **list)                     \
    {                                                                         \
        return esxVI_List_Deserialize                                         \
                 (conn, node, (esxVI_List **)list,                            \
                  (esxVI_List_DeserializeFunc)esxVI_##_type##_Deserialize,    \
                  (esxVI_List_FreeFunc)esxVI_##_type##_Free);                 \
    }



#define ESX_VI__TEMPLATE__CAST_FROM_ANY_TYPE(_type)                           \
    int                                                                       \
    esxVI_##_type##_CastFromAnyType(virConnectPtr conn,                       \
                                    esxVI_AnyType *anyType,                   \
                                    esxVI_##_type **ptrptr)                   \
    {                                                                         \
        if (anyType == NULL || ptrptr == NULL || *ptrptr != NULL) {           \
            ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR, "Invalid argument");   \
            return -1;                                                        \
        }                                                                     \
                                                                              \
        if (STRNEQ(anyType->other, #_type)) {                                 \
            ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR,                        \
                         "Expecting type '%s' but found '%s'",                \
                         #_type, anyType->other);                             \
            return -1;                                                        \
        }                                                                     \
                                                                              \
        return esxVI_##_type##_Deserialize(conn, anyType->_node, ptrptr);     \
    }



#define ESX_VI__TEMPLATE__SERIALIZE_EXTRA(_type, _type_string, _serialize)    \
    int                                                                       \
    esxVI_##_type##_Serialize(virConnectPtr conn,                             \
                              esxVI_##_type *item,                            \
                              const char *element, virBufferPtr output,       \
                              esxVI_Boolean required)                         \
    {                                                                         \
        if (element == NULL || output == NULL ) {                             \
            ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR, "Invalid argument");   \
            return -1;                                                        \
        }                                                                     \
                                                                              \
        if (item == NULL) {                                                   \
            return esxVI_CheckSerializationNecessity(conn, element,           \
                                                     required);               \
        }                                                                     \
                                                                              \
        ESV_VI__XML_TAG__OPEN(output, element, _type_string);                 \
                                                                              \
        _serialize                                                            \
                                                                              \
        ESV_VI__XML_TAG__CLOSE(output, element);                              \
                                                                              \
        return 0;                                                             \
    }



#define ESX_VI__TEMPLATE__SERIALIZE(_type, _serialize)                        \
    ESX_VI__TEMPLATE__SERIALIZE_EXTRA(_type, #_type, _serialize)



#define ESX_VI__TEMPLATE__DESERIALIZE(_type, _deserialize, _require)          \
    int                                                                       \
    esxVI_##_type##_Deserialize(virConnectPtr conn, xmlNodePtr node,          \
                                esxVI_##_type **ptrptr)                       \
    {                                                                         \
        xmlNodePtr childNode = NULL;                                          \
                                                                              \
        if (ptrptr == NULL || *ptrptr != NULL) {                              \
            ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR, "Invalid argument");   \
            return -1;                                                        \
        }                                                                     \
                                                                              \
        if (esxVI_##_type##_Alloc(conn, ptrptr) < 0) {                        \
            return -1;                                                        \
        }                                                                     \
                                                                              \
        for (childNode = node->xmlChildrenNode; childNode != NULL;            \
             childNode = childNode->next) {                                   \
            if (childNode->type != XML_ELEMENT_NODE) {                        \
                ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR,                    \
                             "Wrong XML element type %d", childNode->type);   \
                goto failure;                                                 \
            }                                                                 \
                                                                              \
            _deserialize                                                      \
                                                                              \
            VIR_WARN("Unexpected '%s' property", childNode->name);            \
        }                                                                     \
                                                                              \
        _require                                                              \
                                                                              \
        return 0;                                                             \
                                                                              \
      failure:                                                                \
        esxVI_##_type##_Free(ptrptr);                                         \
                                                                              \
        return -1;                                                            \
    }



#define ESX_VI__TEMPLATE__DESERIALIZE_NUMBER(_type, _xsdType, _min, _max)     \
    int                                                                       \
    esxVI_##_type##_Deserialize(virConnectPtr conn, xmlNodePtr node,          \
                                esxVI_##_type **number)                       \
    {                                                                         \
        int result = 0;                                                       \
        char *string;                                                         \
        long long value;                                                      \
                                                                              \
        if (number == NULL || *number != NULL) {                              \
            ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR, "Invalid argument");   \
            return -1;                                                        \
        }                                                                     \
                                                                              \
        if (esxVI_##_type##_Alloc(conn, number) < 0) {                        \
            return -1;                                                        \
        }                                                                     \
                                                                              \
        string = (char *)xmlNodeListGetString(node->doc,                      \
                                              node->xmlChildrenNode, 1);      \
                                                                              \
        if (string == NULL) {                                                 \
            ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR,                        \
                         "XML node doesn't contain text, expecting an "       \
                         _xsdType" value");                                   \
            goto failure;                                                     \
        }                                                                     \
                                                                              \
        if (virStrToLong_ll(string, NULL, 10, &value) < 0) {                  \
            ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR,                        \
                         "Unknown value '%s' for "_xsdType, string);          \
            goto failure;                                                     \
        }                                                                     \
                                                                              \
        if (value < (_min) || value > (_max)) {                               \
            ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR,                        \
                         "Value '%s' is not representable as "_xsdType,       \
                         (const char *) string);                              \
            goto failure;                                                     \
        }                                                                     \
                                                                              \
        (*number)->value = value;                                             \
                                                                              \
      cleanup:                                                                \
        VIR_FREE(string);                                                     \
                                                                              \
        return result;                                                        \
                                                                              \
      failure:                                                                \
        esxVI_##_type##_Free(number);                                         \
                                                                              \
        result = -1;                                                          \
                                                                              \
        goto cleanup;                                                         \
    }



#define ESX_VI__TEMPLATE__PROPERTY__SERIALIZE(_type, _name, _required)        \
    if (esxVI_##_type##_Serialize(conn, item->_name, #_name, output,          \
                                  esxVI_Boolean_##_required) < 0) {           \
        return -1;                                                            \
    }



#define ESX_VI__TEMPLATE__PROPERTY__SERIALIZE_VALUE(_type, _name, _required)  \
    if (esxVI_##_type##_SerializeValue(conn, item->_name, #_name, output,     \
                                       esxVI_Boolean_##_required) < 0) {      \
        return -1;                                                            \
    }



#define ESX_VI__TEMPLATE__PROPERTY__SERIALIZE_LIST(_type, _name, _required)   \
    if (esxVI_##_type##_SerializeList(conn, item->_name, #_name, output,      \
                                      esxVI_Boolean_##_required) < 0) {       \
        return -1;                                                            \
    }



#define ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE(_type, _name)                 \
    if (xmlStrEqual(childNode->name, BAD_CAST #_name)) {                      \
        if (esxVI_##_type##_Deserialize(conn, childNode,                      \
                                        &(*ptrptr)->_name) < 0) {             \
            goto failure;                                                     \
        }                                                                     \
                                                                              \
        continue;                                                             \
    }



#define ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_VALUE(_type, _name)           \
    if (xmlStrEqual(childNode->name, BAD_CAST #_name)) {                      \
        if (esxVI_##_type##_DeserializeValue(conn, childNode,                 \
                                             &(*ptrptr)->_name) < 0) {        \
            goto failure;                                                     \
        }                                                                     \
                                                                              \
        continue;                                                             \
    }



#define ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_EXPECTED(_type, _expected,    \
                                                        _name)                \
    if (xmlStrEqual(childNode->name, BAD_CAST #_name)) {                      \
        if (esxVI_##_type##_Deserialize(conn, childNode, &(*ptrptr)->_name,   \
                                        _expected) < 0) {                     \
            goto failure;                                                     \
        }                                                                     \
                                                                              \
        continue;                                                             \
    }



#define ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_NOOP(_name)                   \
    if (xmlStrEqual(childNode->name, BAD_CAST #_name)) {                      \
        continue;                                                             \
    }



#define ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_LIST(_type, _name)            \
    if (xmlStrEqual(childNode->name, BAD_CAST #_name)) {                      \
        esxVI_##_type *_name##Item = NULL;                                    \
                                                                              \
        if (esxVI_##_type##_Deserialize(conn, childNode, &_name##Item) < 0) { \
            goto failure;                                                     \
        }                                                                     \
                                                                              \
        if (esxVI_##_type##_AppendToList(conn, &(*ptrptr)->_name,             \
                                         _name##Item) < 0) {                  \
            esxVI_##_type##_Free(&_name##Item);                               \
            goto failure;                                                     \
        }                                                                     \
                                                                              \
        continue;                                                             \
    }



/*
 * A required property must be != 0 (NULL for pointers, "undefined" == 0 for
 * enumeration values).
 */
#define ESX_VI__TEMPLATE__PROPERTY__REQUIRED(_name)                           \
    if ((*ptrptr)->_name == 0) {                                              \
        ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR,                            \
                     "Missing required '%s' property", #_name);               \
        goto failure;                                                         \
    }



#define ESX_VI__TEMPLATE__ENUMERATION__CAST_FROM_ANY_TYPE(_type)              \
    int                                                                       \
    esxVI_##_type##_CastFromAnyType(virConnectPtr conn,                       \
                                    esxVI_AnyType *anyType,                   \
                                    esxVI_##_type *value)                     \
    {                                                                         \
        return esxVI_Enumeration_CastFromAnyType                              \
                 (conn, &_esxVI_##_type##_Enumeration, anyType,               \
                  (int *)value);                                              \
    }



#define ESX_VI__TEMPLATE__ENUMERATION__SERIALIZE(_type)                       \
    int                                                                       \
    esxVI_##_type##_Serialize(virConnectPtr conn, esxVI_##_type value,        \
                              const char *element, virBufferPtr output,       \
                              esxVI_Boolean required)                         \
    {                                                                         \
        return esxVI_Enumeration_Serialize(conn,                              \
                                           &_esxVI_##_type##_Enumeration,     \
                                           value, element, output,            \
                                           required);                         \
    }



#define ESX_VI__TEMPLATE__ENUMERATION__DESERIALIZE(_type)                     \
    int                                                                       \
    esxVI_##_type##_Deserialize(virConnectPtr conn, xmlNodePtr node,          \
                                esxVI_##_type *value)                         \
    {                                                                         \
        return esxVI_Enumeration_Deserialize(conn,                            \
                                             &_esxVI_##_type##_Enumeration,   \
                                             node, (int *)value);             \
    }



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * XSI: Type
 */

const char *
esxVI_Type_Name(esxVI_Type type)
{
    switch (type) {
      case esxVI_Type_Undefined:
        return "undefined";

      case esxVI_Type_Boolean:
        return "xsd:boolean";

      case esxVI_Type_String:
        return "xsd:string";

      case esxVI_Type_Short:
        return "xsd:short";

      case esxVI_Type_Int:
        return "xsd:int";

      case esxVI_Type_Long:
        return "xsd:long";

      case esxVI_Type_Other:
        return "other";

      default:
        return "unknown";
    }
}



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * XSD: Boolean
 */

static const esxVI_Enumeration _esxVI_Boolean_Enumeration = {
    "xsd:boolean", {
        { "true", esxVI_Boolean_True },
        { "false", esxVI_Boolean_False },
        { NULL, -1 },
    },
};

/* esxVI_Boolean_Serialize */
ESX_VI__TEMPLATE__ENUMERATION__SERIALIZE(Boolean);

/* esxVI_Boolean_Deserialize */
ESX_VI__TEMPLATE__ENUMERATION__DESERIALIZE(Boolean);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * XSD: AnyType
 */

/* esxVI_AnyType_Alloc */
ESX_VI__TEMPLATE__ALLOC(AnyType);

/* esxVI_AnyType_Free */
ESX_VI__TEMPLATE__FREE(AnyType,
{
    xmlFreeNode(item->_node);
    VIR_FREE(item->other);
    VIR_FREE(item->value);
});

int
esxVI_AnyType_ExpectType(virConnectPtr conn, esxVI_AnyType *anyType,
                         esxVI_Type type)
{
    if (anyType->type != type) {
        ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                     "Expecting type '%s' but found '%s'",
                     esxVI_Type_Name(type),
                     anyType->type != esxVI_Type_Other
                       ? esxVI_Type_Name(anyType->type)
                       : anyType->other);
        return -1;
    }

    return 0;
}

int
esxVI_AnyType_DeepCopy(virConnectPtr conn, esxVI_AnyType **dest,
                       esxVI_AnyType *src)
{
    if (dest == NULL || *dest != NULL) {
        ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR, "Invalid argument");
        return -1;
    }

    if (src == NULL) {
        return 0;
    }

    if (esxVI_AnyType_Alloc(conn, dest) < 0) {
        goto failure;
    }

    (*dest)->_node = xmlCopyNode(src->_node, 1);

    if ((*dest)->_node == NULL) {
        ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                     "Could not copy an XML node");
        goto failure;
    }

    (*dest)->type = src->type;

    if (esxVI_String_DeepCopyValue(conn, &(*dest)->other, src->other) < 0 ||
        esxVI_String_DeepCopyValue(conn, &(*dest)->value, src->value) < 0) {
        goto failure;
    }

    switch (src->type) {
      case esxVI_Type_Boolean:
        (*dest)->boolean = src->boolean;
        break;

      case esxVI_Type_String:
        (*dest)->string = (*dest)->value;
        break;

      case esxVI_Type_Short:
        (*dest)->int16 = src->int16;
        break;

      case esxVI_Type_Int:
        (*dest)->int32 = src->int32;
        break;

      case esxVI_Type_Long:
        (*dest)->int64 = src->int64;
        break;

      default:
        break;
    }

    return 0;

  failure:
    esxVI_AnyType_Free(dest);

    return -1;
}

int
esxVI_AnyType_Deserialize(virConnectPtr conn, xmlNodePtr node,
                          esxVI_AnyType **anyType)
{
    long long number;

    if (anyType == NULL || *anyType != NULL) {
        ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR, "Invalid argument");
        return -1;
    }

    if (esxVI_AnyType_Alloc(conn, anyType) < 0) {
        return -1;
    }

    (*anyType)->_node = xmlCopyNode(node, 1);

    if ((*anyType)->_node == NULL) {
        ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                     "Could not copy an XML node");
        goto failure;
    }

    (*anyType)->other =
      (char *)xmlGetNsProp
                (node, BAD_CAST "type",
                 BAD_CAST "http://www.w3.org/2001/XMLSchema-instance");

    if ((*anyType)->other == NULL) {
        ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR, "Missing 'type' property");
        goto failure;
    }

    (*anyType)->value =
      (char *)xmlNodeListGetString(node->doc, node->xmlChildrenNode, 1);

    if ((*anyType)->value == NULL) {
        (*anyType)->value = strdup("");

        if ((*anyType)->value == NULL) {
            virReportOOMError(conn);
            goto failure;
        }
    }

    #define _DESERIALIZE_NUMBER(_type, _xsdType, _name, _min, _max)           \
        do {                                                                  \
            if (virStrToLong_ll((*anyType)->value, NULL, 10, &number) < 0) {  \
                ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR,                    \
                             "Unknown value '%s' for "_xsdType,               \
                             (*anyType)->value);                              \
                goto failure;                                                 \
            }                                                                 \
                                                                              \
            if (number < (_min) || number > (_max)) {                         \
                ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR,                    \
                             "Value '%s' is out of "_xsdType" range",         \
                             (*anyType)->value);                              \
                goto failure;                                                 \
            }                                                                 \
                                                                              \
            (*anyType)->type = esxVI_Type_##_type;                            \
            (*anyType)->_name = number;                                       \
        } while (0)

    if (STREQ((*anyType)->other, "xsd:boolean")) {
        (*anyType)->type = esxVI_Type_Boolean;

        if (STREQ((*anyType)->value, "true")) {
            (*anyType)->boolean = esxVI_Boolean_True;
        } else if (STREQ((*anyType)->value, "false")) {
            (*anyType)->boolean = esxVI_Boolean_False;
        } else {
            ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                         "Unknown value '%s' for xsd:boolean",
                         (*anyType)->value);
            goto failure;
        }
    } else if (STREQ((*anyType)->other, "xsd:string")) {
        (*anyType)->type = esxVI_Type_String;
        (*anyType)->string = (*anyType)->value;
    } else if (STREQ((*anyType)->other, "xsd:short")) {
        _DESERIALIZE_NUMBER(Short, "xsd:short", int16, INT16_MIN, INT16_MAX);
    } else if (STREQ((*anyType)->other, "xsd:int")) {
        _DESERIALIZE_NUMBER(Int, "xsd:int", int32, INT32_MIN, INT32_MAX);
    } else if (STREQ((*anyType)->other, "xsd:long")) {
        _DESERIALIZE_NUMBER(Long, "xsd:long", int64, INT64_MIN, INT64_MAX);
    }

    #undef _DESERIALIZE_NUMBER

    return 0;

  failure:
    esxVI_AnyType_Free(anyType);

    return -1;
}



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * XSD: String
 */

/* esxVI_String_Alloc */
ESX_VI__TEMPLATE__ALLOC(String);

/* esxVI_String_Free */
ESX_VI__TEMPLATE__FREE(String,
{
    esxVI_String_Free(&item->_next);

    VIR_FREE(item->value);
});

/* esxVI_String_AppendToList */
ESX_VI__TEMPLATE__LIST__APPEND(String);

int
esxVI_String_AppendValueToList(virConnectPtr conn,
                               esxVI_String **stringList, const char *value)
{
    esxVI_String *string = NULL;

    if (esxVI_String_Alloc(conn, &string) < 0) {
        goto failure;
    }

    string->value = strdup(value);

    if (string->value == NULL) {
        virReportOOMError(conn);
        goto failure;
    }

    if (esxVI_String_AppendToList(conn, stringList, string) < 0) {
        goto failure;
    }

    return 0;

  failure:
    esxVI_String_Free(&string);

    return -1;
}

int
esxVI_String_AppendValueListToList(virConnectPtr conn,
                                   esxVI_String **stringList,
                                   const char *valueList)
{
    esxVI_String *stringListToAppend = NULL;
    const char *value = valueList;

    while (value != NULL && *value != '\0') {
        if (esxVI_String_AppendValueToList(conn, &stringListToAppend,
                                           value) < 0) {
            goto failure;
        }

        value += strlen(value) + 1;
    }

    if (esxVI_String_AppendToList(conn, stringList, stringListToAppend) < 0) {
        goto failure;
    }

    return 0;

  failure:
    esxVI_String_Free(&stringListToAppend);

    return -1;
}

int
esxVI_String_DeepCopy(virConnectPtr conn, esxVI_String **dest,
                      esxVI_String *src)
{
    if (dest == NULL || *dest != NULL) {
        ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR, "Invalid argument");
        return -1;
    }

    if (src == NULL) {
        return 0;
    }

    if (esxVI_String_Alloc(conn, dest) < 0 ||
        esxVI_String_DeepCopyValue(conn, &(*dest)->value, src->value)) {
        goto failure;
    }

    return 0;

  failure:
    esxVI_String_Free(dest);

    return -1;
}

/* esxVI_String_DeepCopyList */
ESX_VI__TEMPLATE__LIST__DEEP_COPY(String);

int
esxVI_String_DeepCopyValue(virConnectPtr conn, char **dest, const char *src)
{
    if (dest == NULL || *dest != NULL) {
        ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR, "Invalid argument");
        return -1;
    }

    if (src == NULL) {
        return 0;
    }

    *dest = strdup(src);

    if (*dest == NULL) {
        virReportOOMError(conn);
        return -1;
    }

    return 0;
}

int
esxVI_String_Serialize(virConnectPtr conn, esxVI_String *string,
                       const char *element, virBufferPtr output,
                       esxVI_Boolean required)
{
    return esxVI_String_SerializeValue(conn,
                                       string != NULL ? string->value : NULL,
                                       element, output, required);
}

/* esxVI_String_SerializeList */
ESX_VI__TEMPLATE__LIST__SERIALIZE(String);

int
esxVI_String_SerializeValue(virConnectPtr conn, const char *value,
                            const char *element, virBufferPtr output,
                            esxVI_Boolean required)
{
    if (element == NULL || output == NULL) {
        ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR, "Invalid argument");
        return -1;
    }

    if (value == NULL) {
        return esxVI_CheckSerializationNecessity(conn, element, required);
    }

    ESV_VI__XML_TAG__OPEN(output, element, "xsd:string");

    virBufferAdd(output, value, -1);

    ESV_VI__XML_TAG__CLOSE(output, element);

    return 0;
}

int
esxVI_String_Deserialize(virConnectPtr conn, xmlNodePtr node,
                         esxVI_String **string)
{
    if (string == NULL || *string != NULL) {
        ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR, "Invalid argument");
        return -1;
    }

    if (esxVI_String_Alloc(conn, string) < 0) {
        return -1;
    }

    (*string)->value =
      (char *)xmlNodeListGetString(node->doc, node->xmlChildrenNode, 1);

    if ((*string)->value == NULL) {
        (*string)->value = strdup("");

        if ((*string)->value == NULL) {
            virReportOOMError(conn);
            goto failure;
        }
    }

    return 0;

  failure:
    esxVI_String_Free(string);

    return -1;
}

/* esxVI_String_DeserializeList */
ESX_VI__TEMPLATE__LIST__DESERIALIZE(String);

int
esxVI_String_DeserializeValue(virConnectPtr conn, xmlNodePtr node,
                              char **value)
{
    if (value == NULL || *value != NULL) {
        ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR, "Invalid argument");
        return -1;
    }

    *value = (char *)xmlNodeListGetString(node->doc, node->xmlChildrenNode, 1);

    if (*value == NULL) {
        *value = strdup("");

        if (*value == NULL) {
            virReportOOMError(conn);
            return -1;
        }
    }

    return 0;
}



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * XSD: Int
 */

/* esxVI_Int_Alloc */
ESX_VI__TEMPLATE__ALLOC(Int);

/* esxVI_Int_Free */
ESX_VI__TEMPLATE__FREE(Int,
{
    esxVI_Int_Free(&item->_next);
});

/* esxVI_Int_AppendToList */
ESX_VI__TEMPLATE__LIST__APPEND(Int);

int
esxVI_Int_DeepCopy(virConnectPtr conn, esxVI_Int **dest, esxVI_Int *src)
{
    if (dest == NULL || *dest != NULL) {
        ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR, "Invalid argument");
        return -1;
    }

    if (src == NULL) {
        return 0;
    }

    if (esxVI_Int_Alloc(conn, dest) < 0) {
        goto failure;
    }

    (*dest)->value = src->value;

    return 0;

  failure:
    esxVI_Int_Free(dest);

    return -1;
}

/* esxVI_Int_Serialize */
ESX_VI__TEMPLATE__SERIALIZE_EXTRA(Int, "xsd:int",
{
    virBufferVSprintf(output, "%d", (int)item->value);
});

/* esxVI_Int_SerializeList */
ESX_VI__TEMPLATE__LIST__SERIALIZE(Int);

/* esxVI_Int_Deserialize */
ESX_VI__TEMPLATE__DESERIALIZE_NUMBER(Int, "xsd:int", INT32_MIN, INT32_MAX);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * XSD: Long
 */

/* esxVI_Long_Alloc */
ESX_VI__TEMPLATE__ALLOC(Long);

/* esxVI_Long_Free */
ESX_VI__TEMPLATE__FREE(Long,
{
    esxVI_Long_Free(&item->_next);
});

/* esxVI_Long_AppendToList */
ESX_VI__TEMPLATE__LIST__APPEND(Long);

/* esxVI_Long_Serialize */
ESX_VI__TEMPLATE__SERIALIZE_EXTRA(Long, "xsd:long",
{
    virBufferVSprintf(output, "%lld", (long long int)item->value);
});

/* esxVI_Long_SerializeList */
ESX_VI__TEMPLATE__LIST__SERIALIZE(Long);


/* esxVI_Long_Deserialize */
ESX_VI__TEMPLATE__DESERIALIZE_NUMBER(Long, "xsd:long", INT64_MIN, INT64_MAX);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * XSD: DateTime
 */

/* esxVI_DateTime_Alloc */
ESX_VI__TEMPLATE__ALLOC(DateTime);

/* esxVI_DateTime_Free */
ESX_VI__TEMPLATE__FREE(DateTime,
{
    VIR_FREE(item->value);
});

/* esxVI_DateTime_Serialize */
ESX_VI__TEMPLATE__SERIALIZE_EXTRA(DateTime, "xsd:dateTime",
{
    virBufferAdd(output, item->value, -1);
});

int
esxVI_DateTime_Deserialize(virConnectPtr conn, xmlNodePtr node,
                           esxVI_DateTime **dateTime)
{
    if (dateTime == NULL || *dateTime != NULL) {
        ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR, "Invalid argument");
        return -1;
    }

    if (esxVI_DateTime_Alloc(conn, dateTime) < 0) {
        return -1;
    }

    (*dateTime)->value =
      (char *)xmlNodeListGetString(node->doc, node->xmlChildrenNode, 1);

    if ((*dateTime)->value == NULL) {
        ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                     "XML node doesn't contain text, expecting an "
                     "xsd:dateTime value");
        goto failure;
    }

    return 0;

  failure:
    esxVI_DateTime_Free(dateTime);

    return -1;
}



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Enum: ManagedEntityStatus
 */

static const esxVI_Enumeration _esxVI_ManagedEntityStatus_Enumeration = {
    "ManagedEntityStatus", {
        { "gray", esxVI_ManagedEntityStatus_Gray },
        { "green", esxVI_ManagedEntityStatus_Green },
        { "yellow", esxVI_ManagedEntityStatus_Yellow },
        { "red", esxVI_ManagedEntityStatus_Red },
        { NULL, -1 },
    },
};

/* esxVI_ManagedEntityStatus_CastFromAnyType */
ESX_VI__TEMPLATE__ENUMERATION__CAST_FROM_ANY_TYPE(ManagedEntityStatus);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Enum: ObjectUpdateKind
 */

static const esxVI_Enumeration _esxVI_ObjectUpdateKind_Enumeration = {
    "ObjectUpdateKind", {
        { "enter", esxVI_ObjectUpdateKind_Enter },
        { "leave", esxVI_ObjectUpdateKind_Leave },
        { "modify", esxVI_ObjectUpdateKind_Modify },
        { NULL, -1 },
    },
};

/* esxVI_ObjectUpdateKind_Deserialize */
ESX_VI__TEMPLATE__ENUMERATION__DESERIALIZE(ObjectUpdateKind);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Enum: PerfSummaryType
 */

static const esxVI_Enumeration _esxVI_PerfSummaryType_Enumeration = {
    "PerfSummaryType", {
        { "average", esxVI_PerfSummaryType_Average },
        { "latest", esxVI_PerfSummaryType_Latest },
        { "maximum", esxVI_PerfSummaryType_Maximum },
        { "minimum", esxVI_PerfSummaryType_Minimum },
        { "none", esxVI_PerfSummaryType_None },
        { "summation", esxVI_PerfSummaryType_Summation },
        { NULL, -1 },
    },
};

/* esxVI_PerfSummaryType_Deserialize */
ESX_VI__TEMPLATE__ENUMERATION__DESERIALIZE(PerfSummaryType);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Enum: PerfStatsType
 */

static const esxVI_Enumeration _esxVI_PerfStatsType_Enumeration = {
    "PerfStatsType", {
        { "absolute", esxVI_PerfStatsType_Absolute },
        { "delta", esxVI_PerfStatsType_Delta },
        { "rate", esxVI_PerfStatsType_Rate },
        { NULL, -1 },
    },
};

/* esxVI_PerfStatsType_Deserialize */
ESX_VI__TEMPLATE__ENUMERATION__DESERIALIZE(PerfStatsType);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Enum: PropertyChangeOp
 */

static const esxVI_Enumeration _esxVI_PropertyChangeOp_Enumeration = {
    "PropertyChangeOp", {
        { "add", esxVI_PropertyChangeOp_Add },
        { "remove", esxVI_PropertyChangeOp_Remove },
        { "assign", esxVI_PropertyChangeOp_Assign },
        { "indirectRemove", esxVI_PropertyChangeOp_IndirectRemove },
        { NULL, -1 },
    },
};

/* esxVI_PropertyChangeOp_Deserialize */
ESX_VI__TEMPLATE__ENUMERATION__DESERIALIZE(PropertyChangeOp);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Enum: SharesLevel
 */

static const esxVI_Enumeration _esxVI_SharesLevel_Enumeration = {
    "SharesLevel", {
        { "custom", esxVI_SharesLevel_Custom },
        { "high", esxVI_SharesLevel_High },
        { "low", esxVI_SharesLevel_Low },
        { "normal", esxVI_SharesLevel_Normal },
        { NULL, -1 },
    },
};

/* esxVI_SharesLevel_Serialize */
ESX_VI__TEMPLATE__ENUMERATION__SERIALIZE(SharesLevel);

/* esxVI_SharesLevel_Deserialize */
ESX_VI__TEMPLATE__ENUMERATION__DESERIALIZE(SharesLevel);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Enum: TaskInfoState
 */

static const esxVI_Enumeration _esxVI_TaskInfoState_Enumeration = {
    "TaskInfoState", {
        { "error", esxVI_TaskInfoState_Error },
        { "queued", esxVI_TaskInfoState_Queued },
        { "running", esxVI_TaskInfoState_Running },
        { "success", esxVI_TaskInfoState_Success },
        { NULL, -1 },
    },
};

/* esxVI_TaskInfoState_CastFromAnyType */
ESX_VI__TEMPLATE__ENUMERATION__CAST_FROM_ANY_TYPE(TaskInfoState);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Enum: VirtualMachineMovePriority
 */

static const esxVI_Enumeration _esxVI_VirtualMachineMovePriority_Enumeration = {
    "VirtualMachineMovePriority", {
        { "lowPriority", esxVI_VirtualMachineMovePriority_LowPriority },
        { "highPriority", esxVI_VirtualMachineMovePriority_HighPriority },
        { "defaultPriority", esxVI_VirtualMachineMovePriority_DefaultPriority },
        { NULL, -1 },
    },
};

/* esxVI_VirtualMachineMovePriority_Serialize */
ESX_VI__TEMPLATE__ENUMERATION__SERIALIZE(VirtualMachineMovePriority);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Enum: VirtualMachinePowerState
 */

static const esxVI_Enumeration _esxVI_VirtualMachinePowerState_Enumeration = {
    "VirtualMachinePowerState", {
        { "poweredOff", esxVI_VirtualMachinePowerState_PoweredOff },
        { "poweredOn", esxVI_VirtualMachinePowerState_PoweredOn },
        { "suspended", esxVI_VirtualMachinePowerState_Suspended },
        { NULL, -1 },
    },
};

/* esxVI_VirtualMachinePowerState_CastFromAnyType */
ESX_VI__TEMPLATE__ENUMERATION__CAST_FROM_ANY_TYPE(VirtualMachinePowerState);

/* esxVI_VirtualMachinePowerState_Serialize */
ESX_VI__TEMPLATE__ENUMERATION__SERIALIZE(VirtualMachinePowerState);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Type: Fault
 */

/* esxVI_Fault_Alloc */
ESX_VI__TEMPLATE__ALLOC(Fault);

/* esxVI_Fault_Free */
ESX_VI__TEMPLATE__FREE(Fault,
{
    VIR_FREE(item->faultcode);
    VIR_FREE(item->faultstring);
});

/* esxVI_Fault_Deserialize */
ESX_VI__TEMPLATE__DESERIALIZE(Fault,
{
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_VALUE(String, faultcode);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_VALUE(String, faultstring);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_NOOP(detail); /* FIXME */
},
{
    ESX_VI__TEMPLATE__PROPERTY__REQUIRED(faultcode);
    ESX_VI__TEMPLATE__PROPERTY__REQUIRED(faultstring);
});



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Type: ManagedObjectReference
 */

/* esxVI_ManagedObjectReference_Alloc */
ESX_VI__TEMPLATE__ALLOC(ManagedObjectReference);

/* esxVI_ManagedObjectReference_Free */
ESX_VI__TEMPLATE__FREE(ManagedObjectReference,
{
    esxVI_ManagedObjectReference_Free(&item->_next);

    VIR_FREE(item->type);
    VIR_FREE(item->value);
});

int
esxVI_ManagedObjectReference_DeepCopy(virConnectPtr conn,
                                      esxVI_ManagedObjectReference **dest,
                                      esxVI_ManagedObjectReference *src)
{
    if (dest == NULL || *dest != NULL) {
        ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR, "Invalid argument");
        return -1;
    }

    if (src == NULL) {
        return 0;
    }

    if (esxVI_ManagedObjectReference_Alloc(conn, dest) < 0 ||
        esxVI_String_DeepCopyValue(conn, &(*dest)->type, src->type) < 0 ||
        esxVI_String_DeepCopyValue(conn, &(*dest)->value, src->value) < 0) {
        goto failure;
    }

    return 0;

  failure:
    esxVI_ManagedObjectReference_Free(dest);

    return -1;
}

int
esxVI_ManagedObjectReference_CastFromAnyType
  (virConnectPtr conn, esxVI_AnyType *anyType,
   esxVI_ManagedObjectReference **managedObjectReference,
   const char *expectedType)
{
    if (anyType == NULL || managedObjectReference == NULL ||
        *managedObjectReference != NULL) {
        ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR, "Invalid argument");
        return -1;
    }

    if (STRNEQ(anyType->other, "ManagedObjectReference")) {
        ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                     "Expecting type 'ManagedObjectReference' but found '%s'",
                     anyType->other);
        return -1;
    }

    return esxVI_ManagedObjectReference_Deserialize(conn, anyType->_node,
                                                    managedObjectReference,
                                                    expectedType);
}

int
esxVI_ManagedObjectReference_Serialize
  (virConnectPtr conn, esxVI_ManagedObjectReference *managedObjectReference,
   const char *element, virBufferPtr output, esxVI_Boolean required)
{
    if (element == NULL || output == NULL) {
        ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR, "Invalid argument");
        return -1;
    }

    if (managedObjectReference == NULL) {
        return esxVI_CheckSerializationNecessity(conn, element, required);
    }

    virBufferAddLit(output, "<");
    virBufferAdd(output, element, -1);
    virBufferVSprintf(output,
                      " xmlns=\"urn:vim25\" "
                      "xsi:type=\"ManagedObjectReference\" type=\"%s\">",
                      managedObjectReference->type);

    virBufferAdd(output, managedObjectReference->value, -1);

    ESV_VI__XML_TAG__CLOSE(output, element);

    return 0;
}

/* esxVI_ManagedObjectReference_SerializeList */
ESX_VI__TEMPLATE__LIST__SERIALIZE(ManagedObjectReference);

int
esxVI_ManagedObjectReference_Deserialize
  (virConnectPtr conn, xmlNodePtr node,
   esxVI_ManagedObjectReference **managedObjectReference,
   const char *expectedType)
{
    if (managedObjectReference == NULL || *managedObjectReference != NULL) {
        ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR, "Invalid argument");
        return -1;
    }

    if (esxVI_ManagedObjectReference_Alloc(conn, managedObjectReference) < 0) {
        return -1;
    }

    (*managedObjectReference)->type =
      (char *)xmlGetNoNsProp(node, BAD_CAST "type");

    if ((*managedObjectReference)->type == NULL) {
        ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR, "Missing 'type' property");
        goto failure;
    }

    if (expectedType != NULL &&
        !STREQ(expectedType, (*managedObjectReference)->type)) {
        ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                     "Expected type '%s' but found '%s'", expectedType,
                     (*managedObjectReference)->type);
        goto failure;
    }

    if (esxVI_String_DeserializeValue(conn, node,
                                      &(*managedObjectReference)->value) < 0) {
        goto failure;
    }

    return 0;

  failure:
    esxVI_ManagedObjectReference_Free(managedObjectReference);

    return -1;
}



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Type: DynamicProperty
 */

/* esxVI_DynamicProperty_Alloc */
ESX_VI__TEMPLATE__ALLOC(DynamicProperty);

/* esxVI_DynamicProperty_Free */
ESX_VI__TEMPLATE__FREE(DynamicProperty,
{
    esxVI_DynamicProperty_Free(&item->_next);

    VIR_FREE(item->name);
    esxVI_AnyType_Free(&item->val);
});

int
esxVI_DynamicProperty_DeepCopy(virConnectPtr conn,
                               esxVI_DynamicProperty **dest,
                               esxVI_DynamicProperty *src)
{
    if (dest == NULL || *dest != NULL) {
        ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR, "Invalid argument");
        return -1;
    }

    if (src == NULL) {
        return 0;
    }

    if (esxVI_DynamicProperty_Alloc(conn, dest) < 0 ||
        esxVI_String_DeepCopyValue(conn, &(*dest)->name, src->name) < 0 ||
        esxVI_AnyType_DeepCopy(conn, &(*dest)->val, src->val) < 0) {
        goto failure;
    }

    return 0;

  failure:
    esxVI_DynamicProperty_Free(dest);

    return -1;
}

/* esxVI_DynamicProperty_DeepCopyList */
ESX_VI__TEMPLATE__LIST__DEEP_COPY(DynamicProperty);

/* esxVI_DynamicProperty_AppendToList */
ESX_VI__TEMPLATE__LIST__APPEND(DynamicProperty);

/* esxVI_DynamicProperty_Deserialize */
ESX_VI__TEMPLATE__DESERIALIZE(DynamicProperty,
{
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_VALUE(String, name);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE(AnyType, val);
},
{
    ESX_VI__TEMPLATE__PROPERTY__REQUIRED(name);
    ESX_VI__TEMPLATE__PROPERTY__REQUIRED(val);
});

/* esxVI_DynamicProperty_DeserializeList */
ESX_VI__TEMPLATE__LIST__DESERIALIZE(DynamicProperty);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Type: SelectionSpec
 */

/* esxVI_SelectionSpec_Alloc */
ESX_VI__TEMPLATE__ALLOC(SelectionSpec);

void
esxVI_SelectionSpec_Free(esxVI_SelectionSpec **selectionSpec)
{
    esxVI_SelectionSpec *local = NULL;

    if (selectionSpec == NULL || *selectionSpec == NULL) {
        return;
    }

    esxVI_SelectionSpec_Free(&(*selectionSpec)->_next);

    if ((*selectionSpec)->_super != NULL) {
        /*
         * Explicitly set this pointer to NULL here, otherwise this is will
         * result in a dangling pointer. The actual memory of this object is
         * freed by a call from the esxVI_TraversalSpec_Free function to the
         * esxVI_SelectionSpec_Free function with the base pointer.
         *
         * Use a local copy of the pointer and set the reference to NULL,
         * otherwise Valgrind complains about invalid writes.
         */
        local = *selectionSpec;
        *selectionSpec = NULL;

        esxVI_TraversalSpec_Free(&local->_super);
    } else {
        VIR_FREE((*selectionSpec)->name);

        VIR_FREE(*selectionSpec);
    }
}

/* esxVI_SelectionSpec_AppendToList */
ESX_VI__TEMPLATE__LIST__APPEND(SelectionSpec);

int
esxVI_SelectionSpec_Serialize(virConnectPtr conn,
                              esxVI_SelectionSpec *selectionSpec,
                              const char *element, virBufferPtr output,
                              esxVI_Boolean required)
{
    if (element == NULL || output == NULL) {
        ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR, "Invalid argument");
        return -1;
    }

    if (selectionSpec == NULL) {
        return esxVI_CheckSerializationNecessity(conn, element, required);
    }

    if (selectionSpec->_super != NULL) {
        return esxVI_TraversalSpec_Serialize(conn, selectionSpec->_super,
                                             element, output, required);
    }

    ESV_VI__XML_TAG__OPEN(output, element, "SelectionSpec");

    if (esxVI_String_SerializeValue(conn, selectionSpec->name, "name", output,
                                    esxVI_Boolean_False) < 0) {
        return -1;
    }

    ESV_VI__XML_TAG__CLOSE(output, element);

    return 0;
}

/* esxVI_SelectionSpec_SerializeList */
ESX_VI__TEMPLATE__LIST__SERIALIZE(SelectionSpec);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Type: TraversalSpec extends SelectionSpec
 */

int
esxVI_TraversalSpec_Alloc(virConnectPtr conn,
                          esxVI_TraversalSpec **traversalSpec)
{
    if (esxVI_Alloc(conn, (void **)traversalSpec,
                    sizeof (esxVI_TraversalSpec)) < 0) {
        return -1;
    }

    if (esxVI_SelectionSpec_Alloc(conn, &(*traversalSpec)->_base) < 0) {
        esxVI_TraversalSpec_Free(traversalSpec);
        return -1;
    }

    (*traversalSpec)->_base->_super = *traversalSpec;

    return 0;
}

void
esxVI_TraversalSpec_Free(esxVI_TraversalSpec **traversalSpec)
{
    esxVI_TraversalSpec *local = NULL;

    if (traversalSpec == NULL || *traversalSpec == NULL) {
        return;
    }

    /*
     * Need to store the traversalSpec pointer in a local variable here,
     * because it is possible that the traversalSpec pointer and the _super
     * pointer represent the same location in memory, e.g. if
     * esxVI_SelectionSpec_Free calls esxVI_TraversalSpec_Free with the _super
     * pointer as argument. Setting the _super pointer to NULL sets the
     * traversalSpec pointer also to NULL, because we're working on a reference
     * to this pointer here.
     *
     * Also use a local copy of the pointer and set the reference to NULL,
     * otherwise Valgrind complains about invalid writes.
     */
    local = *traversalSpec;
    *traversalSpec = NULL;

    /*
     * Setting the _super pointer to NULL here is important, otherwise
     * esxVI_SelectionSpec_Free would call esxVI_TraversalSpec_Free again,
     * resulting in both functions calling each other trying to free the
     * _base/_super object until a stackoverflow occurs.
     */
    local->_base->_super = NULL;

    esxVI_SelectionSpec_Free(&local->_base);
    VIR_FREE(local->type);
    VIR_FREE(local->path);
    esxVI_SelectionSpec_Free(&local->selectSet);

    VIR_FREE(local);
}

/* esxVI_TraversalSpec_Serialize */
ESX_VI__TEMPLATE__SERIALIZE(TraversalSpec,
{
    if (esxVI_String_SerializeValue(conn, item->_base->name, "name", output,
                                    esxVI_Boolean_False) < 0) {
        return -1;
    }

    ESX_VI__TEMPLATE__PROPERTY__SERIALIZE_VALUE(String, type, True);
    ESX_VI__TEMPLATE__PROPERTY__SERIALIZE_VALUE(String, path, True);
    ESX_VI__TEMPLATE__PROPERTY__SERIALIZE(Boolean, skip, False);
    ESX_VI__TEMPLATE__PROPERTY__SERIALIZE_LIST(SelectionSpec, selectSet, False);
});



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Type: ObjectSpec
 */

/* esxVI_ObjectSpec_Alloc */
ESX_VI__TEMPLATE__ALLOC(ObjectSpec);

/* esxVI_ObjectSpec_Free */
ESX_VI__TEMPLATE__FREE(ObjectSpec,
{
    esxVI_ObjectSpec_Free(&item->_next);

    esxVI_ManagedObjectReference_Free(&item->obj);
    esxVI_SelectionSpec_Free(&item->selectSet);
});

/* esxVI_ObjectSpec_AppendToList */
ESX_VI__TEMPLATE__LIST__APPEND(ObjectSpec);

/* esxVI_ObjectSpec_Serialize */
ESX_VI__TEMPLATE__SERIALIZE(ObjectSpec,
{
    ESX_VI__TEMPLATE__PROPERTY__SERIALIZE(ManagedObjectReference, obj, True);
    ESX_VI__TEMPLATE__PROPERTY__SERIALIZE(Boolean, skip, False);
    ESX_VI__TEMPLATE__PROPERTY__SERIALIZE_LIST(SelectionSpec, selectSet, False);
});

/* esxVI_ObjectSpec_SerializeList */
ESX_VI__TEMPLATE__LIST__SERIALIZE(ObjectSpec);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Type: PropertyChange
 */

/* esxVI_PropertyChange_Alloc */
ESX_VI__TEMPLATE__ALLOC(PropertyChange);

/* esxVI_PropertyChange_Free */
ESX_VI__TEMPLATE__FREE(PropertyChange,
{
    esxVI_PropertyChange_Free(&item->_next);

    VIR_FREE(item->name);
    esxVI_AnyType_Free(&item->val);
});

/* esxVI_PropertyChange_AppendToList */
ESX_VI__TEMPLATE__LIST__APPEND(PropertyChange);

/* esxVI_PropertyChange_Deserialize */
ESX_VI__TEMPLATE__DESERIALIZE(PropertyChange,
{
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_VALUE(String, name);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE(PropertyChangeOp, op);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE(AnyType, val);
},
{
    ESX_VI__TEMPLATE__PROPERTY__REQUIRED(name);
    ESX_VI__TEMPLATE__PROPERTY__REQUIRED(op);
});

/* esxVI_PropertyChange_DeserializeList */
ESX_VI__TEMPLATE__LIST__DESERIALIZE(PropertyChange);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Type: PropertySpec
 */

/* esxVI_PropertySpec_Alloc */
ESX_VI__TEMPLATE__ALLOC(PropertySpec);

/* esxVI_PropertySpec_Free */
ESX_VI__TEMPLATE__FREE(PropertySpec,
{
    esxVI_PropertySpec_Free(&item->_next);

    VIR_FREE(item->type);
    esxVI_String_Free(&item->pathSet);
});

/* esxVI_PropertySpec_AppendToList */
ESX_VI__TEMPLATE__LIST__APPEND(PropertySpec);

/* esxVI_PropertySpec_Serialize */
ESX_VI__TEMPLATE__SERIALIZE(PropertySpec,
{
    ESX_VI__TEMPLATE__PROPERTY__SERIALIZE_VALUE(String, type, True);
    ESX_VI__TEMPLATE__PROPERTY__SERIALIZE(Boolean, all, False);
    ESX_VI__TEMPLATE__PROPERTY__SERIALIZE_LIST(String, pathSet, False);
});

/* esxVI_PropertySpec_SerializeList */
ESX_VI__TEMPLATE__LIST__SERIALIZE(PropertySpec);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Type: PropertyFilterSpec
 */

/* esxVI_PropertyFilterSpec_Alloc */
ESX_VI__TEMPLATE__ALLOC(PropertyFilterSpec);

/* esxVI_PropertyFilterSpec_Free */
ESX_VI__TEMPLATE__FREE(PropertyFilterSpec,
{
    esxVI_PropertyFilterSpec_Free(&item->_next);

    esxVI_PropertySpec_Free(&item->propSet);
    esxVI_ObjectSpec_Free(&item->objectSet);
});

/* esxVI_PropertyFilterSpec_AppendToList */
ESX_VI__TEMPLATE__LIST__APPEND(PropertyFilterSpec);

/* esxVI_PropertyFilterSpec_Serialize */
ESX_VI__TEMPLATE__SERIALIZE(PropertyFilterSpec,
{
    ESX_VI__TEMPLATE__PROPERTY__SERIALIZE_LIST(PropertySpec, propSet, True);
    ESX_VI__TEMPLATE__PROPERTY__SERIALIZE_LIST(ObjectSpec, objectSet, True);
});

/* esxVI_PropertyFilterSpec_SerializeList */
ESX_VI__TEMPLATE__LIST__SERIALIZE(PropertyFilterSpec);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Type: ObjectContent
 */

/* esxVI_ObjectContent_Alloc */
ESX_VI__TEMPLATE__ALLOC(ObjectContent);

/* esxVI_ObjectContent_Free */
ESX_VI__TEMPLATE__FREE(ObjectContent,
{
    esxVI_ObjectContent_Free(&item->_next);

    esxVI_ManagedObjectReference_Free(&item->obj);
    esxVI_DynamicProperty_Free(&item->propSet);
    /*esxVI_MissingProperty_Free(&item->missingSet);*//* FIXME */
});

/* esxVI_ObjectContent_AppendToList */
ESX_VI__TEMPLATE__LIST__APPEND(ObjectContent);

int
esxVI_ObjectContent_DeepCopy(virConnectPtr conn,
                             esxVI_ObjectContent **dest,
                             esxVI_ObjectContent *src)
{
    if (dest == NULL || *dest != NULL) {
        ESX_VI_ERROR(conn, VIR_ERR_INTERNAL_ERROR, "Invalid argument");
        return -1;
    }

    if (src == NULL) {
        return 0;
    }

    if (esxVI_ObjectContent_Alloc(conn, dest) < 0 ||
        esxVI_ManagedObjectReference_DeepCopy(conn, &(*dest)->obj,
                                              src->obj) < 0 ||
        esxVI_DynamicProperty_DeepCopyList(conn, &(*dest)->propSet,
                                           src->propSet) < 0) {
        goto failure;
    }

#if 0 /* FIXME */
    if (esxVI_MissingProperty_DeepCopyList(&(*dest)->missingSet,
                                           src->missingSet) < 0) {
        goto failure;
    }
#endif

    return 0;

  failure:
    esxVI_ObjectContent_Free(dest);

    return -1;
}

/* esxVI_ObjectContent_Deserialize */
ESX_VI__TEMPLATE__DESERIALIZE(ObjectContent,
{
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_EXPECTED(ManagedObjectReference,
                                                     NULL, obj);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_LIST(DynamicProperty, propSet);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_NOOP(missingSet); /* FIXME */
},
{
    ESX_VI__TEMPLATE__PROPERTY__REQUIRED(obj);
});

/* esxVI_ObjectContent_DeserializeList */
ESX_VI__TEMPLATE__LIST__DESERIALIZE(ObjectContent);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Type: ObjectUpdate
 */

/* esxVI_ObjectUpdate_Alloc */
ESX_VI__TEMPLATE__ALLOC(ObjectUpdate);

/* esxVI_ObjectUpdate_Free */
ESX_VI__TEMPLATE__FREE(ObjectUpdate,
{
    esxVI_ObjectUpdate_Free(&item->_next);

    esxVI_ManagedObjectReference_Free(&item->obj);
    esxVI_PropertyChange_Free(&item->changeSet);
    /*esxVI_MissingProperty_Free(&item->missingSet);*//* FIXME */
});

/* esxVI_ObjectUpdate_AppendToList */
ESX_VI__TEMPLATE__LIST__APPEND(ObjectUpdate);

/* esxVI_ObjectUpdate_Deserialize */
ESX_VI__TEMPLATE__DESERIALIZE(ObjectUpdate,
{
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE(ObjectUpdateKind, kind);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_EXPECTED(ManagedObjectReference,
                                                     NULL, obj);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_LIST(PropertyChange, changeSet);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_NOOP(missingSet); /* FIXME */
},
{
    ESX_VI__TEMPLATE__PROPERTY__REQUIRED(kind);
    ESX_VI__TEMPLATE__PROPERTY__REQUIRED(obj);
});

/* esxVI_ObjectUpdate_DeserializeList */
ESX_VI__TEMPLATE__LIST__DESERIALIZE(ObjectUpdate);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Type: PropertyFilterUpdate
 */

/* esxVI_PropertyFilterUpdate_Alloc */
ESX_VI__TEMPLATE__ALLOC(PropertyFilterUpdate);

/* esxVI_PropertyFilterUpdate_Free */
ESX_VI__TEMPLATE__FREE(PropertyFilterUpdate,
{
    esxVI_PropertyFilterUpdate_Free(&item->_next);

    esxVI_ManagedObjectReference_Free(&item->filter);
    esxVI_ObjectUpdate_Free(&item->objectSet);
    /*esxVI_MissingProperty_Free(&item->missingSet);*//* FIXME */
});

/* esxVI_PropertyFilterUpdate_AppendToList */
ESX_VI__TEMPLATE__LIST__APPEND(PropertyFilterUpdate);

/* esxVI_PropertyFilterUpdate_Deserialize */
ESX_VI__TEMPLATE__DESERIALIZE(PropertyFilterUpdate,
{
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_EXPECTED(ManagedObjectReference,
                                                     NULL, filter);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_LIST(ObjectUpdate, objectSet);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_NOOP(missingSet); /* FIXME */
},
{
    ESX_VI__TEMPLATE__PROPERTY__REQUIRED(filter);
});

/* esxVI_PropertyFilterUpdate_DeserializeList */
ESX_VI__TEMPLATE__LIST__DESERIALIZE(PropertyFilterUpdate);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Type: AboutInfo
 */

/* esxVI_AboutInfo_Alloc */
ESX_VI__TEMPLATE__ALLOC(AboutInfo);

/* esxVI_AboutInfo_Free */
ESX_VI__TEMPLATE__FREE(AboutInfo,
{
    VIR_FREE(item->name);
    VIR_FREE(item->fullName);
    VIR_FREE(item->vendor);
    VIR_FREE(item->version);
    VIR_FREE(item->build);
    VIR_FREE(item->localeVersion);
    VIR_FREE(item->localeBuild);
    VIR_FREE(item->osType);
    VIR_FREE(item->productLineId);
    VIR_FREE(item->apiType);
    VIR_FREE(item->apiVersion);
});

/* esxVI_AboutInfo_Deserialize */
ESX_VI__TEMPLATE__DESERIALIZE(AboutInfo,
{
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_VALUE(String, name);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_VALUE(String, fullName);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_VALUE(String, vendor);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_VALUE(String, version);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_VALUE(String, build);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_VALUE(String, localeVersion);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_VALUE(String, localeBuild);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_VALUE(String, osType);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_VALUE(String, productLineId);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_VALUE(String, apiType);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_VALUE(String, apiVersion);
},
{
    ESX_VI__TEMPLATE__PROPERTY__REQUIRED(name);
    ESX_VI__TEMPLATE__PROPERTY__REQUIRED(fullName);
    ESX_VI__TEMPLATE__PROPERTY__REQUIRED(vendor);
    ESX_VI__TEMPLATE__PROPERTY__REQUIRED(version);
    ESX_VI__TEMPLATE__PROPERTY__REQUIRED(build);
    ESX_VI__TEMPLATE__PROPERTY__REQUIRED(localeVersion);
    ESX_VI__TEMPLATE__PROPERTY__REQUIRED(localeBuild);
    ESX_VI__TEMPLATE__PROPERTY__REQUIRED(osType);
    ESX_VI__TEMPLATE__PROPERTY__REQUIRED(productLineId);
    ESX_VI__TEMPLATE__PROPERTY__REQUIRED(apiType);
    ESX_VI__TEMPLATE__PROPERTY__REQUIRED(apiVersion);
});



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Type: ServiceContent
 */

/* esxVI_ServiceContent_Alloc */
ESX_VI__TEMPLATE__ALLOC(ServiceContent);

/* esxVI_ServiceContent_Free */
ESX_VI__TEMPLATE__FREE(ServiceContent,
{
    esxVI_ManagedObjectReference_Free(&item->rootFolder);
    esxVI_ManagedObjectReference_Free(&item->propertyCollector);
    esxVI_ManagedObjectReference_Free(&item->viewManager);
    esxVI_AboutInfo_Free(&item->about);
    esxVI_ManagedObjectReference_Free(&item->setting);
    esxVI_ManagedObjectReference_Free(&item->userDirectory);
    esxVI_ManagedObjectReference_Free(&item->sessionManager);
    esxVI_ManagedObjectReference_Free(&item->authorizationManager);
    esxVI_ManagedObjectReference_Free(&item->perfManager);
    esxVI_ManagedObjectReference_Free(&item->scheduledTaskManager);
    esxVI_ManagedObjectReference_Free(&item->alarmManager);
    esxVI_ManagedObjectReference_Free(&item->eventManager);
    esxVI_ManagedObjectReference_Free(&item->taskManager);
    esxVI_ManagedObjectReference_Free(&item->extensionManager);
    esxVI_ManagedObjectReference_Free(&item->customizationSpecManager);
    esxVI_ManagedObjectReference_Free(&item->customFieldsManager);
    esxVI_ManagedObjectReference_Free(&item->accountManager);
    esxVI_ManagedObjectReference_Free(&item->diagnosticManager);
    esxVI_ManagedObjectReference_Free(&item->licenseManager);
    esxVI_ManagedObjectReference_Free(&item->searchIndex);
    esxVI_ManagedObjectReference_Free(&item->fileManager);
    esxVI_ManagedObjectReference_Free(&item->virtualDiskManager);
    esxVI_ManagedObjectReference_Free(&item->virtualizationManager);
});

/* esxVI_ServiceContent_Deserialize */
ESX_VI__TEMPLATE__DESERIALIZE(ServiceContent,
{
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_EXPECTED(ManagedObjectReference,
                                                     "Folder", rootFolder);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_EXPECTED(ManagedObjectReference,
                                                    "PropertyCollector",
                                                     propertyCollector);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_EXPECTED(ManagedObjectReference,
                                                     "ViewManager",
                                                     viewManager);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE(AboutInfo, about);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_EXPECTED(ManagedObjectReference,
                                                     "OptionManager", setting);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_EXPECTED(ManagedObjectReference,
                                                     "UserDirectory",
                                                     userDirectory);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_EXPECTED(ManagedObjectReference,
                                                     "SessionManager",
                                                     sessionManager);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_EXPECTED(ManagedObjectReference,
                                                     "AuthorizationManager",
                                                     authorizationManager);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_EXPECTED(ManagedObjectReference,
                                                     "PerformanceManager",
                                                     perfManager);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_EXPECTED(ManagedObjectReference,
                                                     "ScheduledTaskManager",
                                                     scheduledTaskManager);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_EXPECTED(ManagedObjectReference,
                                                     "AlarmManager",
                                                     alarmManager);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_EXPECTED(ManagedObjectReference,
                                                     "EventManager",
                                                     eventManager);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_EXPECTED(ManagedObjectReference,
                                                     "TaskManager",
                                                     taskManager);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_EXPECTED(ManagedObjectReference,
                                                     "ExtensionManager",
                                                     extensionManager);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_EXPECTED(ManagedObjectReference,
                                                     "CustomizationSpecManager",
                                                     customizationSpecManager);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_EXPECTED(ManagedObjectReference,
                                                     "CustomFieldsManager",
                                                     customFieldsManager);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_EXPECTED(ManagedObjectReference,
                                                     "HostLocalAccountManager",
                                                     accountManager);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_EXPECTED(ManagedObjectReference,
                                                     "DiagnosticManager",
                                                     diagnosticManager);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_EXPECTED(ManagedObjectReference,
                                                     "LicenseManager",
                                                     licenseManager);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_EXPECTED(ManagedObjectReference,
                                                     "SearchIndex",
                                                     searchIndex);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_EXPECTED(ManagedObjectReference,
                                                     "FileManager",
                                                     fileManager);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_EXPECTED(ManagedObjectReference,
                                                     "VirtualDiskManager",
                                                     virtualDiskManager);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_EXPECTED(ManagedObjectReference,
                                                     "VirtualizationManager",
                                                     virtualizationManager);
},
{
    ESX_VI__TEMPLATE__PROPERTY__REQUIRED(rootFolder);
    ESX_VI__TEMPLATE__PROPERTY__REQUIRED(propertyCollector);
    ESX_VI__TEMPLATE__PROPERTY__REQUIRED(about);
});



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Type: UpdateSet
 */

/* esxVI_UpdateSet_Alloc */
ESX_VI__TEMPLATE__ALLOC(UpdateSet);

/* esxVI_UpdateSet_Free */
ESX_VI__TEMPLATE__FREE(UpdateSet,
{
    VIR_FREE(item->version);
    esxVI_PropertyFilterUpdate_Free(&item->filterSet);
});

/* esxVI_UpdateSet_Deserialize */
ESX_VI__TEMPLATE__DESERIALIZE(UpdateSet,
{
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_VALUE(String, version);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_LIST(PropertyFilterUpdate,
                                                 filterSet);
},
{
    ESX_VI__TEMPLATE__PROPERTY__REQUIRED(version);
});



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Type: SharesInfo
 */

/* esxVI_SharesInfo_Alloc */
ESX_VI__TEMPLATE__ALLOC(SharesInfo);

/* esxVI_SharesInfo_Free */
ESX_VI__TEMPLATE__FREE(SharesInfo,
{
    esxVI_Int_Free(&item->shares);
});

/* esxVI_SharesInfo_CastFromAnyType */
ESX_VI__TEMPLATE__CAST_FROM_ANY_TYPE(SharesInfo);

/* esxVI_SharesInfo_Deserialize */
ESX_VI__TEMPLATE__DESERIALIZE(SharesInfo,
{
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE(Int, shares);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE(SharesLevel, level);
},
{
    ESX_VI__TEMPLATE__PROPERTY__REQUIRED(shares);
    ESX_VI__TEMPLATE__PROPERTY__REQUIRED(level);
});

/* esxVI_SharesInfo_Serialize */
ESX_VI__TEMPLATE__SERIALIZE(SharesInfo,
{
    ESX_VI__TEMPLATE__PROPERTY__SERIALIZE(Int, shares, True);
    ESX_VI__TEMPLATE__PROPERTY__SERIALIZE(SharesLevel, level, True);
});



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Type: ResourceAllocationInfo
 */

/* esxVI_ResourceAllocationInfo_Alloc */
ESX_VI__TEMPLATE__ALLOC(ResourceAllocationInfo);

/* esxVI_ResourceAllocationInfo_Free */
ESX_VI__TEMPLATE__FREE(ResourceAllocationInfo,
{
    esxVI_Long_Free(&item->reservation);
    esxVI_Long_Free(&item->limit);
    esxVI_SharesInfo_Free(&item->shares);
    esxVI_Long_Free(&item->overheadLimit);
});

/* esxVI_ResourceAllocationInfo_Serialize */
ESX_VI__TEMPLATE__SERIALIZE(ResourceAllocationInfo,
{
    ESX_VI__TEMPLATE__PROPERTY__SERIALIZE(Long, reservation, False);
    ESX_VI__TEMPLATE__PROPERTY__SERIALIZE(Boolean, expandableReservation,
                                          False);
    ESX_VI__TEMPLATE__PROPERTY__SERIALIZE(Long, limit, False);
    ESX_VI__TEMPLATE__PROPERTY__SERIALIZE(SharesInfo, shares, False);
    ESX_VI__TEMPLATE__PROPERTY__SERIALIZE(Long, overheadLimit, False);
});



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Type: VirtualMachineConfigSpec
 */

/* esxVI_VirtualMachineConfigSpec_Alloc */
ESX_VI__TEMPLATE__ALLOC(VirtualMachineConfigSpec);

/* esxVI_VirtualMachineConfigSpec_Free */
ESX_VI__TEMPLATE__FREE(VirtualMachineConfigSpec,
{
    VIR_FREE(item->changeVersion);
    VIR_FREE(item->name);
    VIR_FREE(item->version);
    VIR_FREE(item->uuid);
    esxVI_Long_Free(&item->npivNodeWorldWideName);
    esxVI_Long_Free(&item->npivPortWorldWideName);
    VIR_FREE(item->npivWorldWideNameType);
    VIR_FREE(item->npivWorldWideNameOp);
    VIR_FREE(item->locationId);
    VIR_FREE(item->guestId);
    VIR_FREE(item->alternateGuestName);
    VIR_FREE(item->annotation);
    /* FIXME: implement missing */
    esxVI_Int_Free(&item->numCPUs);
    esxVI_Long_Free(&item->memoryMB);
    /* FIXME: implement missing */
    esxVI_ResourceAllocationInfo_Free(&item->cpuAllocation);
    esxVI_ResourceAllocationInfo_Free(&item->memoryAllocation);
    /* FIXME: implement missing */
    VIR_FREE(item->swapPlacement);
    /* FIXME: implement missing */
});

/* esxVI_VirtualMachineConfigSpec_Serialize */
ESX_VI__TEMPLATE__SERIALIZE(VirtualMachineConfigSpec,
{
    ESX_VI__TEMPLATE__PROPERTY__SERIALIZE_VALUE(String, changeVersion, False);
    ESX_VI__TEMPLATE__PROPERTY__SERIALIZE_VALUE(String, name, False);
    ESX_VI__TEMPLATE__PROPERTY__SERIALIZE_VALUE(String, version, False);
    ESX_VI__TEMPLATE__PROPERTY__SERIALIZE_VALUE(String, uuid, False);
    ESX_VI__TEMPLATE__PROPERTY__SERIALIZE_LIST(Long, npivNodeWorldWideName,
                                               False);
    ESX_VI__TEMPLATE__PROPERTY__SERIALIZE_LIST(Long, npivPortWorldWideName,
                                               False);
    ESX_VI__TEMPLATE__PROPERTY__SERIALIZE_VALUE(String, npivWorldWideNameType,
                                                False);
    ESX_VI__TEMPLATE__PROPERTY__SERIALIZE_VALUE(String, npivWorldWideNameOp,
                                                False);
    ESX_VI__TEMPLATE__PROPERTY__SERIALIZE_VALUE(String, locationId, False);
    ESX_VI__TEMPLATE__PROPERTY__SERIALIZE_VALUE(String, guestId, False);
    ESX_VI__TEMPLATE__PROPERTY__SERIALIZE_VALUE(String, alternateGuestName,
                                                False);
    ESX_VI__TEMPLATE__PROPERTY__SERIALIZE_VALUE(String, annotation, False);
    /* FIXME: implement missing */
    ESX_VI__TEMPLATE__PROPERTY__SERIALIZE(Int, numCPUs, False);
    ESX_VI__TEMPLATE__PROPERTY__SERIALIZE(Long, memoryMB, False);
    /* FIXME: implement missing */
    ESX_VI__TEMPLATE__PROPERTY__SERIALIZE(ResourceAllocationInfo,
                                          cpuAllocation, False);
    ESX_VI__TEMPLATE__PROPERTY__SERIALIZE(ResourceAllocationInfo,
                                          memoryAllocation, False);
    /* FIXME: implement missing */
    ESX_VI__TEMPLATE__PROPERTY__SERIALIZE_VALUE(String, swapPlacement, False);
    /* FIXME: implement missing */
});



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Type: Event
 */

/* esxVI_Event_Alloc */
ESX_VI__TEMPLATE__ALLOC(Event);

/* esxVI_Event_Free */
ESX_VI__TEMPLATE__FREE(Event,
{
    esxVI_Event_Free(&item->_next);

    /* FIXME: implement the rest */
    esxVI_Int_Free(&item->key);
    esxVI_Int_Free(&item->chainId);
    esxVI_DateTime_Free(&item->createdTime);
    VIR_FREE(item->userName);
    VIR_FREE(item->fullFormattedMessage);
});

/* esxVI_Event_Deserialize */
ESX_VI__TEMPLATE__DESERIALIZE(Event,
{
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE(Int, key);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE(Int, chainId);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE(DateTime, createdTime);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_VALUE(String, userName);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_NOOP(datacenter); /* FIXME */
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_NOOP(computeResource); /* FIXME */
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_NOOP(host); /* FIXME */
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_NOOP(vm); /* FIXME */
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_VALUE(String, fullFormattedMessage);
},
{
    ESX_VI__TEMPLATE__PROPERTY__REQUIRED(key);
    ESX_VI__TEMPLATE__PROPERTY__REQUIRED(chainId);
    ESX_VI__TEMPLATE__PROPERTY__REQUIRED(createdTime);
    ESX_VI__TEMPLATE__PROPERTY__REQUIRED(userName);
});

/* esxVI_Event_DeserializeList */
ESX_VI__TEMPLATE__LIST__DESERIALIZE(Event);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Type: UserSession
 */

/* esxVI_UserSession_Alloc */
ESX_VI__TEMPLATE__ALLOC(UserSession);

/* esxVI_UserSession_Free */
ESX_VI__TEMPLATE__FREE(UserSession,
{
    VIR_FREE(item->key);
    VIR_FREE(item->userName);
    VIR_FREE(item->fullName);
    esxVI_DateTime_Free(&item->loginTime);
    esxVI_DateTime_Free(&item->lastActiveTime);
    VIR_FREE(item->locale);
    VIR_FREE(item->messageLocale);
});

/* esxVI_UserSession_CastFromAnyType */
ESX_VI__TEMPLATE__CAST_FROM_ANY_TYPE(UserSession);

/* esxVI_UserSession_Deserialize */
ESX_VI__TEMPLATE__DESERIALIZE(UserSession,
{
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_VALUE(String, key);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_VALUE(String, userName);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_VALUE(String, fullName);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE(DateTime, loginTime);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE(DateTime, lastActiveTime);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_VALUE(String, locale);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_VALUE(String, messageLocale);
},
{
    ESX_VI__TEMPLATE__PROPERTY__REQUIRED(key);
    ESX_VI__TEMPLATE__PROPERTY__REQUIRED(userName);
    ESX_VI__TEMPLATE__PROPERTY__REQUIRED(fullName);
    ESX_VI__TEMPLATE__PROPERTY__REQUIRED(loginTime);
    ESX_VI__TEMPLATE__PROPERTY__REQUIRED(lastActiveTime);
    ESX_VI__TEMPLATE__PROPERTY__REQUIRED(locale);
    ESX_VI__TEMPLATE__PROPERTY__REQUIRED(messageLocale);
});



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Type: ElementDescription extends Description
 *
 *          In contrast to SelectionSpec and TraversalSpec just merge
 *          Description into ElementDescription for simplicity, because
 *          only ElementDescription is used.
 */

/* esxVI_ElementDescription_Alloc */
ESX_VI__TEMPLATE__ALLOC(ElementDescription);

/* esxVI_ElementDescription_Free */
ESX_VI__TEMPLATE__FREE(ElementDescription,
{
    esxVI_ElementDescription_Free(&item->_next);

    VIR_FREE(item->label);
    VIR_FREE(item->summary);
    VIR_FREE(item->key);
});

/* esxVI_ElementDescription_Deserialize */
ESX_VI__TEMPLATE__DESERIALIZE(ElementDescription,
{
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_VALUE(String, label);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_VALUE(String, summary);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_VALUE(String, key);
},
{
    ESX_VI__TEMPLATE__PROPERTY__REQUIRED(label);
    ESX_VI__TEMPLATE__PROPERTY__REQUIRED(summary);
    ESX_VI__TEMPLATE__PROPERTY__REQUIRED(key);
});



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Type: PerfMetricId
 */

/* esxVI_PerfMetricId_Alloc */
ESX_VI__TEMPLATE__ALLOC(PerfMetricId);

/* esxVI_PerfMetricId_Free */
ESX_VI__TEMPLATE__FREE(PerfMetricId,
{
    esxVI_PerfMetricId_Free(&item->_next);

    esxVI_Int_Free(&item->counterId);
    VIR_FREE(item->instance);
});

/* esxVI_PerfMetricId_Serialize */
ESX_VI__TEMPLATE__SERIALIZE(PerfMetricId,
{
    ESX_VI__TEMPLATE__PROPERTY__SERIALIZE(Int, counterId, True);
    ESX_VI__TEMPLATE__PROPERTY__SERIALIZE_VALUE(String, instance, True);
});

/* esxVI_PerfMetricId_SerializeList */
ESX_VI__TEMPLATE__LIST__SERIALIZE(PerfMetricId);

/* esxVI_PerfMetricId_Deserialize */
ESX_VI__TEMPLATE__DESERIALIZE(PerfMetricId,
{
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE(Int, counterId);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_VALUE(String, instance);
},
{
    ESX_VI__TEMPLATE__PROPERTY__REQUIRED(counterId);
    ESX_VI__TEMPLATE__PROPERTY__REQUIRED(instance);
});

/* esxVI_PerfMetricId_DeserializeList */
ESX_VI__TEMPLATE__LIST__DESERIALIZE(PerfMetricId);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Type: PerfCounterInfo
 */

/* esxVI_PerfCounterInfo_Alloc */
ESX_VI__TEMPLATE__ALLOC(PerfCounterInfo);

/* esxVI_PerfCounterInfo_Free */
ESX_VI__TEMPLATE__FREE(PerfCounterInfo,
{
    esxVI_PerfCounterInfo_Free(&item->_next);

    esxVI_Int_Free(&item->key);
    esxVI_ElementDescription_Free(&item->nameInfo);
    esxVI_ElementDescription_Free(&item->groupInfo);
    esxVI_ElementDescription_Free(&item->unitInfo);
    esxVI_Int_Free(&item->level);
    esxVI_Int_Free(&item->associatedCounterId);
});

/* esxVI_PerfCounterInfo_Deserialize */
ESX_VI__TEMPLATE__DESERIALIZE(PerfCounterInfo,
{
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE(Int, key);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE(ElementDescription, nameInfo);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE(ElementDescription, groupInfo);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE(ElementDescription, unitInfo);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE(PerfSummaryType, rollupType);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE(PerfStatsType, statsType);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE(Int, level);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_LIST(Int, associatedCounterId);
},
{
    ESX_VI__TEMPLATE__PROPERTY__REQUIRED(key);
    ESX_VI__TEMPLATE__PROPERTY__REQUIRED(nameInfo);
    ESX_VI__TEMPLATE__PROPERTY__REQUIRED(groupInfo);
    ESX_VI__TEMPLATE__PROPERTY__REQUIRED(unitInfo);
    ESX_VI__TEMPLATE__PROPERTY__REQUIRED(rollupType);
    ESX_VI__TEMPLATE__PROPERTY__REQUIRED(statsType);
});

/* esxVI_PerfCounterInfo_DeserializeList */
ESX_VI__TEMPLATE__LIST__DESERIALIZE(PerfCounterInfo);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Type: PerfQuerySpec
 */

/* esxVI_PerfQuerySpec_Alloc */
ESX_VI__TEMPLATE__ALLOC(PerfQuerySpec);

/* esxVI_PerfQuerySpec_Free */
ESX_VI__TEMPLATE__FREE(PerfQuerySpec,
{
    esxVI_PerfQuerySpec_Free(&item->_next);

    esxVI_ManagedObjectReference_Free(&item->entity);
    esxVI_DateTime_Free(&item->startTime);
    esxVI_DateTime_Free(&item->endTime);
    esxVI_Int_Free(&item->maxSample);
    esxVI_PerfMetricId_Free(&item->metricId);
    esxVI_Int_Free(&item->intervalId);
    VIR_FREE(item->format);
});

/* esxVI_PerfQuerySpec_Serialize */
ESX_VI__TEMPLATE__SERIALIZE(PerfQuerySpec,
{
    ESX_VI__TEMPLATE__PROPERTY__SERIALIZE(ManagedObjectReference, entity, True);
    ESX_VI__TEMPLATE__PROPERTY__SERIALIZE(DateTime, startTime, False);
    ESX_VI__TEMPLATE__PROPERTY__SERIALIZE(DateTime, endTime, False);
    ESX_VI__TEMPLATE__PROPERTY__SERIALIZE(Int, maxSample, False);
    ESX_VI__TEMPLATE__PROPERTY__SERIALIZE_LIST(PerfMetricId, metricId, False);
    ESX_VI__TEMPLATE__PROPERTY__SERIALIZE(Int, intervalId, False);
    ESX_VI__TEMPLATE__PROPERTY__SERIALIZE_VALUE(String, format, False);
});

/* esxVI_PerfQuerySpec_SerializeList */
ESX_VI__TEMPLATE__LIST__SERIALIZE(PerfQuerySpec);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Type: PerfSampleInfo
 */

/* esxVI_PerfSampleInfo_Alloc */
ESX_VI__TEMPLATE__ALLOC(PerfSampleInfo);

/* esxVI_PerfSampleInfo_Free */
ESX_VI__TEMPLATE__FREE(PerfSampleInfo,
{
    esxVI_PerfSampleInfo_Free(&item->_next);

    esxVI_DateTime_Free(&item->timestamp);
    esxVI_Int_Free(&item->interval);
});

/* esxVI_PerfSampleInfo_AppendToList */
ESX_VI__TEMPLATE__LIST__APPEND(PerfSampleInfo);

/* esxVI_PerfSampleInfo_Deserialize */
ESX_VI__TEMPLATE__DESERIALIZE(PerfSampleInfo,
{
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE(DateTime, timestamp);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE(Int, interval);
},
{
    ESX_VI__TEMPLATE__PROPERTY__REQUIRED(timestamp);
    ESX_VI__TEMPLATE__PROPERTY__REQUIRED(interval);
});

/* esxVI_PerfSampleInfo_DeserializeList */
ESX_VI__TEMPLATE__LIST__DESERIALIZE(PerfSampleInfo);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Type: PerfMetricIntSeries extends PerfMetricSeries
 *
 *          In contrast to SelectionSpec and TraversalSpec just merge
 *          PerfMetricSeries into PerfMetricIntSeries for simplicity, because
 *          only PerfMetricIntSeries is used and the other type inheriting
 *          PerfMetricSeries (PerfMetricSeriesCSV) is not used.
 */

/* esxVI_PerfMetricIntSeries_Alloc */
ESX_VI__TEMPLATE__ALLOC(PerfMetricIntSeries);

/* esxVI_PerfMetricIntSeries_Free */
ESX_VI__TEMPLATE__FREE(PerfMetricIntSeries,
{
    esxVI_PerfMetricIntSeries_Free(&item->_next);

    esxVI_PerfMetricId_Free(&item->id);
    esxVI_Long_Free(&item->value);
});

/* esxVI_PerfMetricIntSeries_AppendToList */
ESX_VI__TEMPLATE__LIST__APPEND(PerfMetricIntSeries);

/* esxVI_PerfMetricIntSeries_Deserialize */
ESX_VI__TEMPLATE__DESERIALIZE(PerfMetricIntSeries,
{
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE(PerfMetricId, id);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_LIST(Long, value);
},
{
    ESX_VI__TEMPLATE__PROPERTY__REQUIRED(id);
});



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

/* esxVI_PerfEntityMetric_Alloc */
ESX_VI__TEMPLATE__ALLOC(PerfEntityMetric);

/* esxVI_PerfEntityMetric_Free */
ESX_VI__TEMPLATE__FREE(PerfEntityMetric,
{
    esxVI_PerfEntityMetric_Free(&item->_next);

    esxVI_ManagedObjectReference_Free(&item->entity);
    esxVI_PerfSampleInfo_Free(&item->sampleInfo);
    esxVI_PerfMetricIntSeries_Free(&item->value);
});

/* esxVI_PerfEntityMetric_Deserialize */
ESX_VI__TEMPLATE__DESERIALIZE(PerfEntityMetric,
{
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_EXPECTED(ManagedObjectReference,
                                                     NULL, entity);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_LIST(PerfSampleInfo, sampleInfo);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_LIST(PerfMetricIntSeries, value);
},
{
    ESX_VI__TEMPLATE__PROPERTY__REQUIRED(entity);
});

/* esxVI_PerfEntityMetric_DeserializeList */
ESX_VI__TEMPLATE__LIST__DESERIALIZE(PerfEntityMetric);
