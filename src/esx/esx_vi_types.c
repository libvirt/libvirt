
/*
 * esx_vi_types.c: client for the VMware VI API 2.5 to manage ESX hosts
 *
 * Copyright (C) 2010 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 */

#include <config.h>

#include <stdint.h>
#include <libxml/parser.h>
#include <libxml/xpathInternals.h>

#include "buf.h"
#include "datatypes.h"
#include "memory.h"
#include "logging.h"
#include "util.h"
#include "esx_vi.h"
#include "esx_vi_types.h"

#define VIR_FROM_THIS VIR_FROM_ESX



#define ESX_VI__TEMPLATE__ALLOC(__type)                                       \
    int                                                                       \
    esxVI_##__type##_Alloc(esxVI_##__type **ptrptr)                           \
    {                                                                         \
        if (esxVI_Alloc((void **)ptrptr, sizeof(esxVI_##__type)) < 0) {       \
            return -1;                                                        \
        }                                                                     \
                                                                              \
        (*ptrptr)->_type = esxVI_Type_##__type;                               \
                                                                              \
        return 0;                                                             \
    }



#define ESX_VI__TEMPLATE__FREE(_type, _body)                                  \
    void                                                                      \
    esxVI_##_type##_Free(esxVI_##_type **ptrptr)                              \
    {                                                                         \
        esxVI_##_type *item ATTRIBUTE_UNUSED;                                 \
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



#define ESX_VI__TEMPLATE__VALIDATE(__type, _require)                          \
    int                                                                       \
    esxVI_##__type##_Validate(esxVI_##__type *item)                           \
    {                                                                         \
        const char *typeName = esxVI_Type_ToString(esxVI_Type_##__type);      \
                                                                              \
        if (item->_type <= esxVI_Type_Undefined ||                            \
            item->_type >= esxVI_Type_Other) {                                \
            ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,                              \
                         _("%s object has invalid dynamic type"), typeName);  \
            return -1;                                                        \
        }                                                                     \
                                                                              \
        _require                                                              \
                                                                              \
        return 0;                                                             \
    }



#define ESX_VI__TEMPLATE__DEEP_COPY(_type, _deep_copy)                        \
    int                                                                       \
    esxVI_##_type##_DeepCopy(esxVI_##_type **dest, esxVI_##_type *src)        \
    {                                                                         \
        if (dest == NULL || *dest != NULL) {                                  \
            ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",                        \
                         _("Invalid argument"));                              \
            return -1;                                                        \
        }                                                                     \
                                                                              \
        if (src == NULL) {                                                    \
            return 0;                                                         \
        }                                                                     \
                                                                              \
        if (esxVI_##_type##_Alloc(dest) < 0) {                                \
            goto failure;                                                     \
        }                                                                     \
                                                                              \
        _deep_copy                                                            \
                                                                              \
        return 0;                                                             \
                                                                              \
      failure:                                                                \
        esxVI_##_type##_Free(dest);                                           \
                                                                              \
        return -1;                                                            \
    }



#define ESX_VI__TEMPLATE__LIST__APPEND(_type)                                 \
    int                                                                       \
    esxVI_##_type##_AppendToList(esxVI_##_type **list,  esxVI_##_type *item)  \
    {                                                                         \
        return esxVI_List_Append((esxVI_List **)list, (esxVI_List *)item);    \
    }



#define ESX_VI__TEMPLATE__LIST__DEEP_COPY(_type)                              \
    int                                                                       \
    esxVI_##_type##_DeepCopyList(esxVI_##_type **destList,                    \
                                 esxVI_##_type *srcList)                      \
    {                                                                         \
        return esxVI_List_DeepCopy                                            \
                 ((esxVI_List **)destList, (esxVI_List *)srcList,             \
                  (esxVI_List_DeepCopyFunc)esxVI_##_type##_DeepCopy,          \
                  (esxVI_List_FreeFunc)esxVI_##_type##_Free);                 \
    }



#define ESX_VI__TEMPLATE__LIST__CAST_FROM_ANY_TYPE(_type)                     \
    int                                                                       \
    esxVI_##_type##_CastListFromAnyType(esxVI_AnyType *anyType,               \
                                        esxVI_##_type **list)                 \
    {                                                                         \
        return esxVI_List_CastFromAnyType                                     \
                 (anyType, (esxVI_List **)list,                               \
                  (esxVI_List_CastFromAnyTypeFunc)                            \
                    esxVI_##_type##_CastFromAnyType,                          \
                  (esxVI_List_FreeFunc)esxVI_##_type##_Free);                 \
    }



#define ESX_VI__TEMPLATE__LIST__SERIALIZE(_type)                              \
    int                                                                       \
    esxVI_##_type##_SerializeList(esxVI_##_type *list, const char *element,   \
                                  virBufferPtr output)                        \
    {                                                                         \
        return esxVI_List_Serialize((esxVI_List *)list, element, output,      \
                                    (esxVI_List_SerializeFunc)                \
                                      esxVI_##_type##_Serialize);             \
    }



#define ESX_VI__TEMPLATE__LIST__DESERIALIZE(_type)                            \
    int                                                                       \
    esxVI_##_type##_DeserializeList(xmlNodePtr node, esxVI_##_type **list)    \
    {                                                                         \
        return esxVI_List_Deserialize                                         \
                 (node, (esxVI_List **)list,                                  \
                  (esxVI_List_DeserializeFunc)esxVI_##_type##_Deserialize,    \
                  (esxVI_List_FreeFunc)esxVI_##_type##_Free);                 \
    }



#define ESX_VI__TEMPLATE__CAST_FROM_ANY_TYPE_EXTRA(_type, _dest_type, _extra, \
                                                   _dest_extra)               \
    int                                                                       \
    esxVI_##_type##_Cast##_dest_extra##FromAnyType(esxVI_AnyType *anyType,    \
                                                   _dest_type **ptrptr)       \
    {                                                                         \
        _dest_type *item ATTRIBUTE_UNUSED;                                    \
                                                                              \
        if (anyType == NULL || ptrptr == NULL || *ptrptr != NULL) {           \
            ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",                        \
                         _("Invalid argument"));                              \
            return -1;                                                        \
        }                                                                     \
                                                                              \
        item = *ptrptr;                                                       \
                                                                              \
        _extra                                                                \
                                                                              \
        return esxVI_##_type##_Deserialize##_dest_extra(anyType->node,        \
                                                        ptrptr);              \
    }



#define ESX_VI__TEMPLATE__CAST_FROM_ANY_TYPE(_type)                           \
    ESX_VI__TEMPLATE__CAST_FROM_ANY_TYPE_EXTRA(_type, esxVI_##_type,          \
    {                                                                         \
        if (anyType->type != esxVI_Type_##_type) {                            \
            ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,                              \
                         _("Call to %s for unexpected type '%s'"),            \
                         __FUNCTION__, anyType->other);                       \
            return -1;                                                        \
        }                                                                     \
    }, /* nothing */)



#define ESX_VI__TEMPLATE__CAST_VALUE_FROM_ANY_TYPE(_type, _value_type)        \
    ESX_VI__TEMPLATE__CAST_FROM_ANY_TYPE_EXTRA(_type, _value_type,            \
    {                                                                         \
        if (anyType->type != esxVI_Type_##_type) {                            \
            ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,                              \
                         _("Call to %s for unexpected type '%s'"),            \
                         __FUNCTION__, anyType->other);                       \
            return -1;                                                        \
        }                                                                     \
    }, Value)



#define ESX_VI__TEMPLATE__SERIALIZE_EXTRA(_type, _extra, _serialize)          \
    int                                                                       \
    esxVI_##_type##_Serialize(esxVI_##_type *item,                            \
                              const char *element, virBufferPtr output)       \
    {                                                                         \
        if (element == NULL || output == NULL ) {                             \
            ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",                        \
                         _("Invalid argument"));                              \
            return -1;                                                        \
        }                                                                     \
                                                                              \
        if (item == NULL) {                                                   \
            return 0;                                                         \
        }                                                                     \
                                                                              \
        _extra                                                                \
                                                                              \
        if (esxVI_##_type##_Validate(item) < 0) {                             \
            return -1;                                                        \
        }                                                                     \
                                                                              \
        ESV_VI__XML_TAG__OPEN(output, element,                                \
                              esxVI_Type_ToString(esxVI_Type_##_type));       \
                                                                              \
        _serialize                                                            \
                                                                              \
        ESV_VI__XML_TAG__CLOSE(output, element);                              \
                                                                              \
        return 0;                                                             \
    }



#define ESX_VI__TEMPLATE__SERIALIZE(_type, _serialize)                        \
    ESX_VI__TEMPLATE__SERIALIZE_EXTRA(_type, /* nothing */, _serialize)



#define ESX_VI__TEMPLATE__DESERIALIZE_EXTRA(_type, _extra1, _extra2,          \
                                            _deserialize)                     \
    int                                                                       \
    esxVI_##_type##_Deserialize(xmlNodePtr node, esxVI_##_type **ptrptr)      \
    {                                                                         \
        xmlNodePtr childNode = NULL;                                          \
                                                                              \
        _extra1                                                               \
                                                                              \
        if (ptrptr == NULL || *ptrptr != NULL) {                              \
            ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",                        \
                         _("Invalid argument"));                              \
            return -1;                                                        \
        }                                                                     \
                                                                              \
        if (esxVI_##_type##_Alloc(ptrptr) < 0) {                              \
            return -1;                                                        \
        }                                                                     \
                                                                              \
        _extra2                                                               \
                                                                              \
        for (childNode = node->children; childNode != NULL;                   \
             childNode = childNode->next) {                                   \
            if (childNode->type != XML_ELEMENT_NODE) {                        \
                ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,                          \
                             _("Wrong XML element type %d"), childNode->type);\
                goto failure;                                                 \
            }                                                                 \
                                                                              \
            _deserialize                                                      \
                                                                              \
            VIR_WARN("Unexpected '%s' property", childNode->name);            \
        }                                                                     \
                                                                              \
        if (esxVI_##_type##_Validate(*ptrptr) < 0) {                          \
            goto failure;                                                     \
        }                                                                     \
                                                                              \
        return 0;                                                             \
                                                                              \
      failure:                                                                \
        esxVI_##_type##_Free(ptrptr);                                         \
                                                                              \
        return -1;                                                            \
    }



#define ESX_VI__TEMPLATE__DESERIALIZE(_type, _deserialize)                    \
    ESX_VI__TEMPLATE__DESERIALIZE_EXTRA(_type, /* nothing */, /* nothing */,  \
                                        _deserialize)



#define ESX_VI__TEMPLATE__DESERIALIZE_NUMBER(_type, _xsdType, _min, _max)     \
    int                                                                       \
    esxVI_##_type##_Deserialize(xmlNodePtr node, esxVI_##_type **number)      \
    {                                                                         \
        int result = -1;                                                      \
        char *string;                                                         \
        long long value;                                                      \
                                                                              \
        if (number == NULL || *number != NULL) {                              \
            ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",                        \
                         _("Invalid argument"));                              \
            return -1;                                                        \
        }                                                                     \
                                                                              \
        if (esxVI_##_type##_Alloc(number) < 0) {                              \
            return -1;                                                        \
        }                                                                     \
                                                                              \
        string = (char *)xmlNodeListGetString(node->doc, node->children, 1);  \
                                                                              \
        if (string == NULL) {                                                 \
            ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,                              \
                         _("XML node doesn't contain text, expecting an %s "  \
                           "value"), _xsdType);                               \
            goto cleanup;                                                     \
        }                                                                     \
                                                                              \
        if (virStrToLong_ll(string, NULL, 10, &value) < 0) {                  \
            ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,                              \
                         _("Unknown value '%s' for %s"), string, _xsdType);   \
            goto cleanup;                                                     \
        }                                                                     \
                                                                              \
        if (((_min) != INT64_MIN && value < (_min))                           \
            || ((_max) != INT64_MAX && value > (_max))) {                     \
            ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,                              \
                         _("Value '%s' is not representable as %s"),          \
                         string, _xsdType);                                   \
            goto cleanup;                                                     \
        }                                                                     \
                                                                              \
        (*number)->value = value;                                             \
                                                                              \
        result = 0;                                                           \
                                                                              \
      cleanup:                                                                \
        if (result < 0) {                                                     \
            esxVI_##_type##_Free(number);                                     \
        }                                                                     \
                                                                              \
        VIR_FREE(string);                                                     \
                                                                              \
        return result;                                                        \
    }



/*
 * Macros for property handling to be used as part of other macros
 */

#define ESX_VI__TEMPLATE__PROPERTY__DEEP_COPY(_type, _name)                   \
    if (esxVI_##_type##_DeepCopy(&(*dest)->_name, src->_name) < 0) {          \
        goto failure;                                                         \
    }



#define ESX_VI__TEMPLATE__PROPERTY__DEEP_COPY_LIST(_type, _name)              \
    if (esxVI_##_type##_DeepCopyList(&(*dest)->_name, src->_name) < 0) {      \
        goto failure;                                                         \
    }



#define ESX_VI__TEMPLATE__PROPERTY__DEEP_COPY_VALUE(_type, _name)             \
    if (esxVI_##_type##_DeepCopyValue(&(*dest)->_name, src->_name) < 0) {     \
        goto failure;                                                         \
    }



#define ESX_VI__TEMPLATE__PROPERTY__SERIALIZE(_type, _name)                   \
    if (esxVI_##_type##_Serialize(item->_name, #_name, output) < 0) {         \
        return -1;                                                            \
    }



#define ESX_VI__TEMPLATE__PROPERTY__SERIALIZE_VALUE(_type, _name)             \
    if (esxVI_##_type##_SerializeValue(item->_name, #_name, output) < 0) {    \
        return -1;                                                            \
    }



#define ESX_VI__TEMPLATE__PROPERTY__SERIALIZE_LIST(_type, _name)              \
    if (esxVI_##_type##_SerializeList(item->_name, #_name, output) < 0) {     \
        return -1;                                                            \
    }



#define ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE(_type, _name)                 \
    if (xmlStrEqual(childNode->name, BAD_CAST #_name)) {                      \
        if (esxVI_##_type##_Deserialize(childNode, &(*ptrptr)->_name) < 0) {  \
            goto failure;                                                     \
        }                                                                     \
                                                                              \
        continue;                                                             \
    }



#define ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_IGNORE(_name)                 \
    if (xmlStrEqual(childNode->name, BAD_CAST #_name)) {                      \
        continue;                                                             \
    }



#define ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_VALUE(_type, _name)           \
    if (xmlStrEqual(childNode->name, BAD_CAST #_name)) {                      \
        if (esxVI_##_type##_DeserializeValue(childNode,                       \
                                             &(*ptrptr)->_name) < 0) {        \
            goto failure;                                                     \
        }                                                                     \
                                                                              \
        continue;                                                             \
    }



#define ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_LIST(_type, _name)            \
    if (xmlStrEqual(childNode->name, BAD_CAST #_name)) {                      \
        esxVI_##_type *_name##Item = NULL;                                    \
                                                                              \
        if (esxVI_##_type##_Deserialize(childNode, &_name##Item) < 0) {       \
            goto failure;                                                     \
        }                                                                     \
                                                                              \
        if (esxVI_##_type##_AppendToList(&(*ptrptr)->_name,                   \
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
 *
 * To be used as part of ESX_VI__TEMPLATE__VALIDATE.
 */
#define ESX_VI__TEMPLATE__PROPERTY__REQUIRE(_name)                            \
    if (item->_name == 0) {                                                   \
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,                                  \
                     _("%s object is missing the required '%s' property"),    \
                     typeName, #_name);                                       \
        return -1;                                                            \
    }



/*
 * Macros to implement enumerations
 */

#define ESX_VI__TEMPLATE__ENUMERATION__CAST_FROM_ANY_TYPE(_type)              \
    int                                                                       \
    esxVI_##_type##_CastFromAnyType(esxVI_AnyType *anyType,                   \
                                    esxVI_##_type *value)                     \
    {                                                                         \
        return esxVI_Enumeration_CastFromAnyType                              \
                 (&_esxVI_##_type##_Enumeration, anyType, (int *)value);      \
    }



#define ESX_VI__TEMPLATE__ENUMERATION__SERIALIZE(_type)                       \
    int                                                                       \
    esxVI_##_type##_Serialize(esxVI_##_type value, const char *element,       \
                              virBufferPtr output)                            \
    {                                                                         \
        return esxVI_Enumeration_Serialize(&_esxVI_##_type##_Enumeration,     \
                                           value, element, output);           \
    }



#define ESX_VI__TEMPLATE__ENUMERATION__DESERIALIZE(_type)                     \
    int                                                                       \
    esxVI_##_type##_Deserialize(xmlNodePtr node, esxVI_##_type *value)        \
    {                                                                         \
        return esxVI_Enumeration_Deserialize(&_esxVI_##_type##_Enumeration,   \
                                             node, (int *)value);             \
    }



/*
 * Macros to implement dynamic dispatched functions
 */

#define ESX_VI__TEMPLATE__DISPATCH(_actual_type, __type, _dispatch,           \
                                   _error_return)                             \
    switch (_actual_type) {                                                   \
      _dispatch                                                               \
                                                                              \
      case esxVI_Type_##__type:                                               \
        break;                                                                \
                                                                              \
      default:                                                                \
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,                                  \
                     _("Call to %s for unexpected type '%s'"), __FUNCTION__,  \
                     esxVI_Type_ToString(_actual_type));                      \
        return _error_return;                                                 \
    }



#define ESX_VI__TEMPLATE__DISPATCH__FREE(_type)                               \
    case esxVI_Type_##_type:                                                  \
      esxVI_##_type##_Free((esxVI_##_type **)ptrptr);                         \
      return;



#define ESX_VI__TEMPLATE__DISPATCH__DEEP_COPY(_type)                          \
    case esxVI_Type_##_type:                                                  \
      return esxVI_##_type##_DeepCopy((esxVI_##_type **)dst,                  \
                                      (esxVI_##_type *)src);



#define ESX_VI__TEMPLATE__DISPATCH__CAST_FROM_ANY_TYPE(_type)                 \
    case esxVI_Type_##_type:                                                  \
      return esxVI_##_type##_Deserialize(anyType->node,                       \
                                         (esxVI_##_type **)ptrptr);



#define ESX_VI__TEMPLATE__DISPATCH__SERIALIZE(_type)                          \
    case esxVI_Type_##_type:                                                  \
      return esxVI_##_type##_Serialize((esxVI_##_type *)item, element,        \
                                       output);



#define ESX_VI__TEMPLATE__DISPATCH__DESERIALIZE(_type)                        \
    case esxVI_Type_##_type:                                                  \
      return esxVI_##_type##_Deserialize(node, (esxVI_##_type **)ptrptr);



#define ESX_VI__TEMPLATE__DYNAMIC_FREE(__type, _dispatch, _body)              \
    ESX_VI__TEMPLATE__FREE(__type,                                            \
      ESX_VI__TEMPLATE__DISPATCH(item->_type, __type, _dispatch,              \
                                 /* nothing */)                               \
      _body)



#define ESX_VI__TEMPLATE__DYNAMIC_CAST__ACCEPT(__type)                        \
    if (((esxVI_Object *)item)->_type == esxVI_Type_##__type) {               \
        return item;                                                          \
    }



#define ESX_VI__TEMPLATE__DYNAMIC_CAST(__type, _accept)                       \
    esxVI_##__type *                                                          \
    esxVI_##__type##_DynamicCast(void *item)                                  \
    {                                                                         \
        if (item == NULL) {                                                   \
            ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",                        \
                         _("Invalid argument"));                              \
            return NULL;                                                      \
        }                                                                     \
                                                                              \
        ESX_VI__TEMPLATE__DYNAMIC_CAST__ACCEPT(__type)                        \
                                                                              \
        _accept                                                               \
                                                                              \
        return NULL;                                                          \
    }



#define ESX_VI__TEMPLATE__DYNAMIC_CAST_FROM_ANY_TYPE(__type, _dispatch)       \
    ESX_VI__TEMPLATE__CAST_FROM_ANY_TYPE_EXTRA(__type, esxVI_##__type,        \
      ESX_VI__TEMPLATE__DISPATCH(anyType->type, __type, _dispatch, -1),       \
      /* nothing */)



#define ESX_VI__TEMPLATE__DYNAMIC_SERIALIZE(__type, _dispatch, _serialize)    \
    ESX_VI__TEMPLATE__SERIALIZE_EXTRA(__type,                                 \
      ESX_VI__TEMPLATE__DISPATCH(item->_type, __type, _dispatch, -1),         \
      _serialize)



#define ESX_VI__TEMPLATE__DYNAMIC_DESERIALIZE(__type, _dispatch,              \
                                              _deserialize)                   \
    ESX_VI__TEMPLATE__DESERIALIZE_EXTRA(__type,                               \
      esxVI_Type type = esxVI_Type_Undefined;                                 \
                                                                              \
      if (esxVI_GetActualObjectType(node, esxVI_Type_##__type, &type) < 0) {  \
          return -1;                                                          \
      }                                                                       \
                                                                              \
      switch (type) {                                                         \
        _dispatch                                                             \
                                                                              \
        case esxVI_Type_##__type:                                             \
          break;                                                              \
                                                                              \
        default:                                                              \
          ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,                                \
                       _("Call to %s for unexpected type '%s'"),              \
                       __FUNCTION__, esxVI_Type_ToString(type));              \
          return -1;                                                          \
      },                                                                      \
      /* nothing */,                                                          \
      _deserialize)



static int
esxVI_GetActualObjectType(xmlNodePtr node, esxVI_Type baseType,
                          esxVI_Type *actualType)
{
    int result = -1;
    char *type = NULL;

    if (actualType == NULL || *actualType != esxVI_Type_Undefined) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    type = (char *)xmlGetNsProp
                     (node, BAD_CAST "type",
                      BAD_CAST "http://www.w3.org/2001/XMLSchema-instance");

    if (type == NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                     _("%s is missing 'type' property"),
                     esxVI_Type_ToString(baseType));
        return -1;
    }

    *actualType = esxVI_Type_FromString(type);

    if (*actualType == esxVI_Type_Undefined) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                     _("Unknown value '%s' for %s 'type' property"),
                     type, esxVI_Type_ToString(baseType));
        goto cleanup;
    }

    result = 0;

  cleanup:
    VIR_FREE(type);

    return result;
}



/*
 * Macros to implement managed objects
 */

#define ESX_VI__TEMPLATE__PROPERTY__MANAGED_REQUIRE(_name)                    \
    /* FIXME: This results in O(n^2) runtime in case of missing required, but \
     * unselected properties. */                                              \
    if (item->_name == 0 &&                                                   \
        esxVI_String_ListContainsValue(selectedPropertyNameList, #_name)) {   \
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,                                  \
                     _("%s object is missing the required '%s' property"),    \
                     typeName, #_name);                                       \
        return -1;                                                            \
    }



#define ESX_VI__TEMPLATE__MANAGED_VALIDATE(__type, _require)                  \
    int                                                                       \
    esxVI_##__type##_Validate(esxVI_##__type *item,                           \
                              esxVI_String *selectedPropertyNameList)         \
    {                                                                         \
        const char *typeName = esxVI_Type_ToString(esxVI_Type_##__type);      \
                                                                              \
        if (item->_type <= esxVI_Type_Undefined ||                            \
            item->_type >= esxVI_Type_Other) {                                \
            ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,                              \
                         _("%s object has invalid dynamic type"), typeName);  \
            return -1;                                                        \
        }                                                                     \
                                                                              \
        _require                                                              \
                                                                              \
        return 0;                                                             \
    }



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * XSI: Type
 */

const char *
esxVI_Type_ToString(esxVI_Type type)
{
    switch (type) {
      default:
      case esxVI_Type_Undefined:
        return "<undefined>";

      case esxVI_Type_Boolean:
        return "xsd:boolean";

      case esxVI_Type_AnyType:
        return "xsd:anyType";

      case esxVI_Type_String:
        return "xsd:string";

      case esxVI_Type_Short:
        return "xsd:short";

      case esxVI_Type_Int:
        return "xsd:int";

      case esxVI_Type_Long:
        return "xsd:long";

      case esxVI_Type_DateTime:
        return "xsd:dateTime";

      case esxVI_Type_Fault:
        return "Fault";

      case esxVI_Type_MethodFault:
        return "MethodFault";

      case esxVI_Type_ManagedObjectReference:
        return "ManagedObjectReference";

      case esxVI_Type_Event:
        return "Event";

#include "esx_vi_types.generated.typetostring"

      case esxVI_Type_Other:
        return "<other>";
    }
}

esxVI_Type
esxVI_Type_FromString(const char *type)
{
    if (type == NULL || STREQ(type, "<undefined>")) {
        return esxVI_Type_Undefined;
    } else if (STREQ(type, "xsd:boolean")) {
        return esxVI_Type_Boolean;
    } else if (STREQ(type, "xsd:anyType")) {
        return esxVI_Type_AnyType;
    } else if (STREQ(type, "xsd:string")) {
        return esxVI_Type_String;
    } else if (STREQ(type, "xsd:short")) {
        return esxVI_Type_Short;
    } else if (STREQ(type, "xsd:int")) {
        return esxVI_Type_Int;
    } else if (STREQ(type, "xsd:long")) {
        return esxVI_Type_Long;
    } else if (STREQ(type, "xsd:dateTime")) {
        return esxVI_Type_DateTime;
    } else if (STREQ(type, "Fault")) {
        return esxVI_Type_Fault;
    } else if (STREQ(type, "MethodFault")) {
        return esxVI_Type_MethodFault;
    } else if (STREQ(type, "ManagedObjectReference")) {
        return esxVI_Type_ManagedObjectReference;
    } else if (STREQ(type, "Event")) {
        return esxVI_Type_Event;
    }

#include "esx_vi_types.generated.typefromstring"

    else {
        return esxVI_Type_Other;
    }
}


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * XSD: Boolean
 */

static const esxVI_Enumeration _esxVI_Boolean_Enumeration = {
    esxVI_Type_Boolean, {
        { "true", esxVI_Boolean_True },
        { "false", esxVI_Boolean_False },
        { NULL, -1 },
    },
};

/* esxVI_Boolean_Serialize */
ESX_VI__TEMPLATE__ENUMERATION__SERIALIZE(Boolean)

/* esxVI_Boolean_Deserialize */
ESX_VI__TEMPLATE__ENUMERATION__DESERIALIZE(Boolean)



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * XSD: AnyType
 */

/* esxVI_AnyType_Alloc */
ESX_VI__TEMPLATE__ALLOC(AnyType)

/* esxVI_AnyType_Free */
ESX_VI__TEMPLATE__FREE(AnyType,
{
    xmlFreeNode(item->node);
    VIR_FREE(item->other);
    VIR_FREE(item->value);
})

int
esxVI_AnyType_ExpectType(esxVI_AnyType *anyType, esxVI_Type type)
{
    if (anyType->type != type) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                     _("Expecting type '%s' but found '%s'"),
                     esxVI_Type_ToString(type),
                     anyType->type != esxVI_Type_Other
                       ? esxVI_Type_ToString(anyType->type)
                       : anyType->other);
        return -1;
    }

    return 0;
}

int
esxVI_AnyType_DeepCopy(esxVI_AnyType **dest, esxVI_AnyType *src)
{
    if (dest == NULL || *dest != NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (src == NULL) {
        return 0;
    }

    if (esxVI_AnyType_Alloc(dest) < 0) {
        goto failure;
    }

    (*dest)->_type = src->_type;
    (*dest)->node = xmlCopyNode(src->node, 1);

    if ((*dest)->node == NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                     _("Could not copy an XML node"));
        goto failure;
    }

    (*dest)->type = src->type;

    if (esxVI_String_DeepCopyValue(&(*dest)->other, src->other) < 0 ||
        esxVI_String_DeepCopyValue(&(*dest)->value, src->value) < 0) {
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
esxVI_AnyType_Deserialize(xmlNodePtr node, esxVI_AnyType **anyType)
{
    long long int number;

    if (anyType == NULL || *anyType != NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (esxVI_AnyType_Alloc(anyType) < 0) {
        return -1;
    }

    (*anyType)->node = xmlCopyNode(node, 1);

    if ((*anyType)->node == NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                     _("Could not copy an XML node"));
        goto failure;
    }

    (*anyType)->other =
      (char *)xmlGetNsProp
                (node, BAD_CAST "type",
                 BAD_CAST "http://www.w3.org/2001/XMLSchema-instance");

    if ((*anyType)->other == NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                     _("AnyType is missing 'type' property"));
        goto failure;
    }

    (*anyType)->type = esxVI_Type_FromString((*anyType)->other);

    if ((*anyType)->type == esxVI_Type_Undefined) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                     _("Unknown value '%s' for AnyType 'type' property"),
                     (*anyType)->other);
        goto failure;
    }

    (*anyType)->value =
      (char *)xmlNodeListGetString(node->doc, node->children, 1);

    if ((*anyType)->value == NULL) {
        (*anyType)->value = strdup("");

        if ((*anyType)->value == NULL) {
            virReportOOMError();
            goto failure;
        }
    }

#define _DESERIALIZE_NUMBER(_type, _xsdType, _name, _min, _max)               \
        do {                                                                  \
            if (virStrToLong_ll((*anyType)->value, NULL, 10, &number) < 0) {  \
                ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,                          \
                             _("Unknown value '%s' for %s"),                  \
                             (*anyType)->value, _xsdType);                    \
                goto failure;                                                 \
            }                                                                 \
                                                                              \
            if (((_min) != INT64_MIN && number < (_min))                      \
                || ((_max) != INT64_MAX && number > (_max))) {                \
                ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,                          \
                             _("Value '%s' is out of %s range"),              \
                             (*anyType)->value, _xsdType);                    \
                goto failure;                                                 \
            }                                                                 \
                                                                              \
            (*anyType)->_name = number;                                       \
        } while (0)

    switch ((*anyType)->type) {
      case esxVI_Type_Boolean:
        if (STREQ((*anyType)->value, "true")) {
            (*anyType)->boolean = esxVI_Boolean_True;
        } else if (STREQ((*anyType)->value, "false")) {
            (*anyType)->boolean = esxVI_Boolean_False;
        } else {
            ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                         _("Unknown value '%s' for xsd:boolean"),
                         (*anyType)->value);
            goto failure;
        }

        break;

      case esxVI_Type_String:
        (*anyType)->string = (*anyType)->value;
        break;

      case esxVI_Type_Short:
        _DESERIALIZE_NUMBER(Short, "xsd:short", int16, INT16_MIN, INT16_MAX);
        break;

      case esxVI_Type_Int:
        _DESERIALIZE_NUMBER(Int, "xsd:int", int32, INT32_MIN, INT32_MAX);
        break;

      case esxVI_Type_Long:
        _DESERIALIZE_NUMBER(Long, "xsd:long", int64, INT64_MIN, INT64_MAX);
        break;

      default:
        break;
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
ESX_VI__TEMPLATE__ALLOC(String)

/* esxVI_String_Free */
ESX_VI__TEMPLATE__FREE(String,
{
    esxVI_String_Free(&item->_next);

    VIR_FREE(item->value);
})

/* esxVI_String_Validate */
ESX_VI__TEMPLATE__VALIDATE(String,
{
    ESX_VI__TEMPLATE__PROPERTY__REQUIRE(value)
})

bool
esxVI_String_ListContainsValue(esxVI_String *stringList, const char *value)
{
    esxVI_String *string;

    for (string = stringList; string != NULL; string = string->_next) {
        if (STREQ(string->value, value)) {
            return true;
        }
    }

    return false;
}

/* esxVI_String_AppendToList */
ESX_VI__TEMPLATE__LIST__APPEND(String)

int
esxVI_String_AppendValueToList(esxVI_String **stringList, const char *value)
{
    esxVI_String *string = NULL;

    if (esxVI_String_Alloc(&string) < 0) {
        return -1;
    }

    string->value = strdup(value);

    if (string->value == NULL) {
        virReportOOMError();
        goto failure;
    }

    if (esxVI_String_AppendToList(stringList, string) < 0) {
        goto failure;
    }

    return 0;

  failure:
    esxVI_String_Free(&string);

    return -1;
}

int
esxVI_String_AppendValueListToList(esxVI_String **stringList,
                                   const char *valueList)
{
    esxVI_String *stringListToAppend = NULL;
    const char *value = valueList;

    while (value != NULL && *value != '\0') {
        if (esxVI_String_AppendValueToList(&stringListToAppend, value) < 0) {
            goto failure;
        }

        value += strlen(value) + 1;
    }

    if (esxVI_String_AppendToList(stringList, stringListToAppend) < 0) {
        goto failure;
    }

    return 0;

  failure:
    esxVI_String_Free(&stringListToAppend);

    return -1;
}

/* esxVI_String_DeepCopy */
ESX_VI__TEMPLATE__DEEP_COPY(String,
{
    ESX_VI__TEMPLATE__PROPERTY__DEEP_COPY_VALUE(String, value)
})

/* esxVI_String_DeepCopyList */
ESX_VI__TEMPLATE__LIST__DEEP_COPY(String)

int
esxVI_String_DeepCopyValue(char **dest, const char *src)
{
    if (dest == NULL || *dest != NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (src == NULL) {
        return 0;
    }

    *dest = strdup(src);

    if (*dest == NULL) {
        virReportOOMError();
        return -1;
    }

    return 0;
}

/* esxVI_String_CastFromAnyType */
ESX_VI__TEMPLATE__CAST_FROM_ANY_TYPE(String)

/* esxVI_String_CastValueFromAnyType */
ESX_VI__TEMPLATE__CAST_VALUE_FROM_ANY_TYPE(String, char)

int
esxVI_String_Serialize(esxVI_String *string, const char *element,
                       virBufferPtr output)
{
    return esxVI_String_SerializeValue(string != NULL ? string->value : NULL,
                                       element, output);
}

/* esxVI_String_SerializeList */
ESX_VI__TEMPLATE__LIST__SERIALIZE(String)

int
esxVI_String_SerializeValue(const char *value, const char *element,
                            virBufferPtr output)
{
    if (element == NULL || output == NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (value == NULL) {
        return 0;
    }

    ESV_VI__XML_TAG__OPEN(output, element, "xsd:string");

    virBufferAdd(output, value, -1);

    ESV_VI__XML_TAG__CLOSE(output, element);

    return 0;
}

/* esxVI_String_Deserialize */
ESX_VI__TEMPLATE__DESERIALIZE(String,
{
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_VALUE(String, value)
})

/* esxVI_String_DeserializeList */
ESX_VI__TEMPLATE__LIST__DESERIALIZE(String)

int
esxVI_String_DeserializeValue(xmlNodePtr node, char **value)
{
    if (value == NULL || *value != NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    *value = (char *)xmlNodeListGetString(node->doc, node->children, 1);

    if (*value == NULL) {
        *value = strdup("");

        if (*value == NULL) {
            virReportOOMError();
            return -1;
        }
    }

    return 0;
}



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * XSD: Int
 */

/* esxVI_Int_Alloc */
ESX_VI__TEMPLATE__ALLOC(Int)

/* esxVI_Int_Free */
ESX_VI__TEMPLATE__FREE(Int,
{
    esxVI_Int_Free(&item->_next);
})

/* esxVI_Int_Validate */
ESX_VI__TEMPLATE__VALIDATE(Int,
{
})

/* esxVI_Int_AppendToList */
ESX_VI__TEMPLATE__LIST__APPEND(Int)

/* esxVI_Int_DeepCopy */
ESX_VI__TEMPLATE__DEEP_COPY(Int,
{
    (*dest)->value = src->value;
})

/* esxVI_Int_Serialize */
ESX_VI__TEMPLATE__SERIALIZE(Int,
{
    virBufferAsprintf(output, "%d", (int)item->value);
})

/* esxVI_Int_SerializeList */
ESX_VI__TEMPLATE__LIST__SERIALIZE(Int)

/* esxVI_Int_Deserialize */
ESX_VI__TEMPLATE__DESERIALIZE_NUMBER(Int, "xsd:int", INT32_MIN, INT32_MAX)



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * XSD: Long
 */

/* esxVI_Long_Alloc */
ESX_VI__TEMPLATE__ALLOC(Long)

/* esxVI_Long_Free */
ESX_VI__TEMPLATE__FREE(Long,
{
    esxVI_Long_Free(&item->_next);
})

/* esxVI_Long_Validate */
ESX_VI__TEMPLATE__VALIDATE(Long,
{
})

/* esxVI_Long_AppendToList */
ESX_VI__TEMPLATE__LIST__APPEND(Long)

/* esxVI_Long_CastFromAnyType */
ESX_VI__TEMPLATE__CAST_FROM_ANY_TYPE(Long)

/* esxVI_Long_Serialize */
ESX_VI__TEMPLATE__SERIALIZE(Long,
{
    virBufferAsprintf(output, "%lld", (long long int)item->value);
})

/* esxVI_Long_SerializeList */
ESX_VI__TEMPLATE__LIST__SERIALIZE(Long)

/* esxVI_Long_Deserialize */
ESX_VI__TEMPLATE__DESERIALIZE_NUMBER(Long, "xsd:long", INT64_MIN, INT64_MAX)



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * XSD: DateTime
 */

/* esxVI_DateTime_Alloc */
ESX_VI__TEMPLATE__ALLOC(DateTime)

/* esxVI_DateTime_Free */
ESX_VI__TEMPLATE__FREE(DateTime,
{
    VIR_FREE(item->value);
})

/* esxVI_DateTime_Validate */
ESX_VI__TEMPLATE__VALIDATE(DateTime,
{
    ESX_VI__TEMPLATE__PROPERTY__REQUIRE(value);
})

/* esxVI_DateTime_DeepCopy */
ESX_VI__TEMPLATE__DEEP_COPY(DateTime,
{
    ESX_VI__TEMPLATE__PROPERTY__DEEP_COPY_VALUE(String, value)
})

/* esxVI_DateTime_Serialize */
ESX_VI__TEMPLATE__SERIALIZE(DateTime,
{
    virBufferAdd(output, item->value, -1);
})

int
esxVI_DateTime_Deserialize(xmlNodePtr node, esxVI_DateTime **dateTime)
{
    if (dateTime == NULL || *dateTime != NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (esxVI_DateTime_Alloc(dateTime) < 0) {
        return -1;
    }

    (*dateTime)->value =
      (char *)xmlNodeListGetString(node->doc, node->children, 1);

    if ((*dateTime)->value == NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                     _("XML node doesn't contain text, expecting an "
                       "xsd:dateTime value"));
        goto failure;
    }

    return 0;

  failure:
    esxVI_DateTime_Free(dateTime);

    return -1;
}

int
esxVI_DateTime_ConvertToCalendarTime(esxVI_DateTime *dateTime,
                                     long long *secondsSinceEpoch)
{
    char value[64] = "";
    char *tmp;
    struct tm tm;
    int milliseconds;
    char sign;
    int tz_hours;
    int tz_minutes;
    int tz_offset = 0;

    if (dateTime == NULL || secondsSinceEpoch == NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (virStrcpyStatic(value, dateTime->value) == NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                     _("xsd:dateTime value '%s' too long for destination"),
                     dateTime->value);
        return -1;
    }

    /*
     * expected format: [-]CCYY-MM-DDTHH:MM:SS[.ssssss][((+|-)HH:MM|Z)]
     * typical example: 2010-04-05T12:13:55.316789+02:00
     *
     * see http://www.w3.org/TR/xmlschema-2/#dateTime
     *
     * map negative years to 0, since the base for time_t is the year 1970.
     */
    if (*value == '-') {
        *secondsSinceEpoch = 0;
        return 0;
    }

    tmp = strptime(value, "%Y-%m-%dT%H:%M:%S", &tm);

    if (tmp == NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                     _("xsd:dateTime value '%s' has unexpected format"),
                     dateTime->value);
        return -1;
    }

    if (*tmp != '\0') {
        /* skip .ssssss part if present */
        if (*tmp == '.' &&
            virStrToLong_i(tmp + 1, &tmp, 10, &milliseconds) < 0) {
            ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                         _("xsd:dateTime value '%s' has unexpected format"),
                         dateTime->value);
            return -1;
        }

        /* parse timezone offset if present. if missing assume UTC */
        if (*tmp == '+' || *tmp == '-') {
            sign = *tmp;

            if (virStrToLong_i(tmp + 1, &tmp, 10, &tz_hours) < 0 ||
                *tmp != ':' ||
                virStrToLong_i(tmp + 1, NULL, 10, &tz_minutes) < 0) {
                ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                             _("xsd:dateTime value '%s' has unexpected format"),
                             dateTime->value);
                return -1;
            }

            tz_offset = tz_hours * 60 * 60 + tz_minutes * 60;

            if (sign == '-') {
                tz_offset = -tz_offset;
            }
        } else if (STREQ(tmp, "Z")) {
            /* Z refers to UTC. tz_offset is already initialized to zero */
        } else {
            ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                         _("xsd:dateTime value '%s' has unexpected format"),
                         dateTime->value);
            return -1;
        }
    }

    /*
     * xsd:dateTime represents local time relative to the optional timezone
     * given as offset. pretend the local time is in UTC and use timegm in
     * order to avoid interference with the timezone to this computer.
     * apply timezone correction afterwards, because it's simpler than
     * handling all the possible over- and underflows when trying to apply
     * it to the tm struct.
     */
    *secondsSinceEpoch = timegm(&tm) - tz_offset;

    return 0;
}



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * SOAP: Fault
 */

/* esxVI_Fault_Alloc */
ESX_VI__TEMPLATE__ALLOC(Fault);

/* esxVI_Fault_Free */
ESX_VI__TEMPLATE__FREE(Fault,
{
    VIR_FREE(item->faultcode);
    VIR_FREE(item->faultstring);
})

/* esxVI_Fault_Validate */
ESX_VI__TEMPLATE__VALIDATE(Fault,
{
    ESX_VI__TEMPLATE__PROPERTY__REQUIRE(faultcode);
    ESX_VI__TEMPLATE__PROPERTY__REQUIRE(faultstring);
})

/* esxVI_Fault_Deserialize */
ESX_VI__TEMPLATE__DESERIALIZE(Fault,
{
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_VALUE(String, faultcode);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_VALUE(String, faultstring);
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_IGNORE(detail); /* FIXME */
})



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Object: MethodFault
 */

/* esxVI_MethodFault_Alloc */
ESX_VI__TEMPLATE__ALLOC(MethodFault);

/* esxVI_MethodFault_Free */
ESX_VI__TEMPLATE__FREE(MethodFault,
{
    VIR_FREE(item->_actualType);
})

int
esxVI_MethodFault_Deserialize(xmlNodePtr node, esxVI_MethodFault **methodFault)
{
    if (methodFault == NULL || *methodFault != NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (esxVI_MethodFault_Alloc(methodFault) < 0) {
        return -1;
    }

    (*methodFault)->_actualType =
      (char *)xmlGetNsProp(node, BAD_CAST "type",
                           BAD_CAST "http://www.w3.org/2001/XMLSchema-instance");

    if ((*methodFault)->_actualType == NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                     _("MethodFault is missing 'type' property"));
        goto failure;
    }

    return 0;

  failure:
    esxVI_MethodFault_Free(methodFault);

    return -1;
}



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Object: ManagedObjectReference
 */

/* esxVI_ManagedObjectReference_Alloc */
ESX_VI__TEMPLATE__ALLOC(ManagedObjectReference)

/* esxVI_ManagedObjectReference_Free */
ESX_VI__TEMPLATE__FREE(ManagedObjectReference,
{
    esxVI_ManagedObjectReference_Free(&item->_next);

    VIR_FREE(item->type);
    VIR_FREE(item->value);
})

/* esxVI_ManagedObjectReference_DeepCopy */
ESX_VI__TEMPLATE__DEEP_COPY(ManagedObjectReference,
{
    ESX_VI__TEMPLATE__PROPERTY__DEEP_COPY_VALUE(String, type)
    ESX_VI__TEMPLATE__PROPERTY__DEEP_COPY_VALUE(String, value)
})

/* esxVI_ManagedObjectReference_AppendToList */
ESX_VI__TEMPLATE__LIST__APPEND(ManagedObjectReference)

/* esxVI_ManagedObjectReference_CastFromAnyType */
ESX_VI__TEMPLATE__CAST_FROM_ANY_TYPE(ManagedObjectReference)

/* esxVI_ManagedObjectReference_CastListFromAnyType */
ESX_VI__TEMPLATE__LIST__CAST_FROM_ANY_TYPE(ManagedObjectReference)

int
esxVI_ManagedObjectReference_Serialize
  (esxVI_ManagedObjectReference *managedObjectReference,
   const char *element, virBufferPtr output)
{
    if (element == NULL || output == NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (managedObjectReference == NULL) {
        return 0;
    }

    virBufferAddLit(output, "<");
    virBufferAdd(output, element, -1);
    virBufferAsprintf(output,
                      " xmlns=\"urn:vim25\" "
                      "xsi:type=\"ManagedObjectReference\" type=\"%s\">",
                      managedObjectReference->type);

    virBufferAdd(output, managedObjectReference->value, -1);

    ESV_VI__XML_TAG__CLOSE(output, element);

    return 0;
}

/* esxVI_ManagedObjectReference_SerializeList */
ESX_VI__TEMPLATE__LIST__SERIALIZE(ManagedObjectReference)

int
esxVI_ManagedObjectReference_Deserialize
  (xmlNodePtr node, esxVI_ManagedObjectReference **managedObjectReference)
{
    if (managedObjectReference == NULL || *managedObjectReference != NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (esxVI_ManagedObjectReference_Alloc(managedObjectReference) < 0) {
        return -1;
    }

    (*managedObjectReference)->type =
      (char *)xmlGetNoNsProp(node, BAD_CAST "type");

    if ((*managedObjectReference)->type == NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                     _("ManagedObjectReference is missing 'type' property"));
        goto failure;
    }

    if (esxVI_String_DeserializeValue(node,
                                      &(*managedObjectReference)->value) < 0) {
        goto failure;
    }

    return 0;

  failure:
    esxVI_ManagedObjectReference_Free(managedObjectReference);

    return -1;
}



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Type: Event
 */

/* esxVI_Event_Alloc */
ESX_VI__TEMPLATE__ALLOC(Event)

/* esxVI_Event_Free */
ESX_VI__TEMPLATE__FREE(Event,
{
    esxVI_Event_Free(&item->_next);
    VIR_FREE(item->_actualType);

    esxVI_Int_Free(&item->key);
    esxVI_Int_Free(&item->chainId);
    esxVI_DateTime_Free(&item->createdTime);
    VIR_FREE(item->userName);
    /* FIXME: datacenter is currently ignored */
    /* FIXME: computeResource is currently ignored */
    /* FIXME: host is currently ignored */
    esxVI_VmEventArgument_Free(&item->vm);
    VIR_FREE(item->fullFormattedMessage);
})

/* esxVI_Event_Validate */
ESX_VI__TEMPLATE__VALIDATE(Event,
{
    ESX_VI__TEMPLATE__PROPERTY__REQUIRE(key)
    ESX_VI__TEMPLATE__PROPERTY__REQUIRE(chainId)
    ESX_VI__TEMPLATE__PROPERTY__REQUIRE(createdTime)
    ESX_VI__TEMPLATE__PROPERTY__REQUIRE(userName)
    /* FIXME: datacenter is currently ignored */
    /* FIXME: computeResource is currently ignored */
    /* FIXME: host is currently ignored */
})

/* esxVI_Event_AppendToList */
ESX_VI__TEMPLATE__LIST__APPEND(Event)

/* esxVI_Event_CastFromAnyType */
ESX_VI__TEMPLATE__DYNAMIC_CAST_FROM_ANY_TYPE(Event,
{
      case esxVI_Type_Other:
        /* Just accept everything here */
        break;
})

/* esxVI_Event_CastListFromAnyType */
ESX_VI__TEMPLATE__LIST__CAST_FROM_ANY_TYPE(Event)

/* esxVI_Event_Deserialize */
ESX_VI__TEMPLATE__DESERIALIZE_EXTRA(Event, /* nothing */,
{
    (*ptrptr)->_actualType =
      (char *)xmlGetNsProp(node, BAD_CAST "type",
                           BAD_CAST "http://www.w3.org/2001/XMLSchema-instance");

    if ((*ptrptr)->_actualType == NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                     _("%s is missing 'type' property"),
                     esxVI_Type_ToString((*ptrptr)->_type));
        goto failure;
    }
},
{
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE(Int, key)
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE(Int, chainId)
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE(DateTime, createdTime)
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_VALUE(String, userName)
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_IGNORE(datacenter) /* FIXME */
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_IGNORE(computeResource) /* FIXME */
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_IGNORE(host) /* FIXME */
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE(VmEventArgument, vm)
    ESX_VI__TEMPLATE__PROPERTY__DESERIALIZE_VALUE(String, fullFormattedMessage)

    /* Don't warn about unexpected properties */
    continue;
})

/* esxVI_Event_DeserializeList */
ESX_VI__TEMPLATE__LIST__DESERIALIZE(Event)



#include "esx_vi_types.generated.c"



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Enum: VirtualMachinePowerState (Additions)
 */

int
esxVI_VirtualMachinePowerState_ConvertToLibvirt
  (esxVI_VirtualMachinePowerState powerState)
{
    switch (powerState) {
      case esxVI_VirtualMachinePowerState_PoweredOff:
        return VIR_DOMAIN_SHUTOFF;

      case esxVI_VirtualMachinePowerState_PoweredOn:
        return VIR_DOMAIN_RUNNING;

      case esxVI_VirtualMachinePowerState_Suspended:
        return VIR_DOMAIN_PAUSED;

      default:
        return VIR_DOMAIN_NOSTATE;
    }
}
