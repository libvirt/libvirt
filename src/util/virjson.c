/*
 * virjson.c: JSON object parsing/formatting
 *
 * Copyright (C) 2009-2010, 2012-2015 Red Hat, Inc.
 * Copyright (C) 2009 Daniel P. Berrange
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

#include "virjson.h"
#include "virerror.h"
#include "virlog.h"
#include "virstring.h"
#include "virutil.h"

/* XXX fixme */
#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.json");

typedef struct _virJSONObject virJSONObject;
typedef virJSONObject *virJSONObjectPtr;

typedef struct _virJSONObjectPair virJSONObjectPair;
typedef virJSONObjectPair *virJSONObjectPairPtr;

typedef struct _virJSONArray virJSONArray;
typedef virJSONArray *virJSONArrayPtr;


struct _virJSONObjectPair {
    char *key;
    virJSONValuePtr value;
};

struct _virJSONObject {
    size_t npairs;
    virJSONObjectPairPtr pairs;
};

struct _virJSONArray {
    size_t nvalues;
    virJSONValuePtr *values;
};

struct _virJSONValue {
    int type; /* enum virJSONType */

    union {
        virJSONObject object;
        virJSONArray array;
        char *string;
        char *number; /* int/float/etc format is context defined so we can't parse it here :-( */
        int boolean;
    } data;
};


virJSONType
virJSONValueGetType(const virJSONValue *value)
{
    return value->type;
}


/**
 * virJSONValueObjectAddVArgs:
 * @obj: JSON object to add the values to
 * @args: a key-value argument pairs, terminated by NULL
 *
 * Adds the key-value pairs supplied as variable argument list to @obj.
 *
 * Keys look like   s:name  the first letter is a type code:
 * Explanation of type codes:
 * s: string value, must be non-null
 * S: string value, omitted if null
 *
 * i: signed integer value
 * j: signed integer value, error if negative
 * z: signed integer value, omitted if zero
 * y: signed integer value, omitted if zero, error if negative
 *
 * I: signed long integer value
 * J: signed long integer value, error if negative
 * Z: signed long integer value, omitted if zero
 * Y: signed long integer value, omitted if zero, error if negative
 *
 * u: unsigned integer value
 * p: unsigned integer value, omitted if zero
 *
 * U: unsigned long integer value (see below for quirks)
 * P: unsigned long integer value, omitted if zero
 *
 * b: boolean value
 * B: boolean value, omitted if false
 *
 * d: double precision floating point number
 * n: json null value
 *
 * The following two cases take a pointer to a pointer to a virJSONValuePtr. The
 * pointer is cleared when the virJSONValuePtr is stolen into the object.
 * a: json object, must be non-NULL
 * A: json object, omitted if NULL
 *
 * m: a bitmap represented as a JSON array, must be non-NULL
 * M: a bitmap represented as a JSON array, omitted if NULL
 *
 * The value corresponds to the selected type.
 *
 * Returns -1 on error. 1 on success, if at least one key:pair was valid 0
 * in case of no error but nothing was filled.
 */
int
virJSONValueObjectAddVArgs(virJSONValuePtr obj,
                           va_list args)
{
    char type;
    char *key;
    int ret = -1;
    int rc;

    while ((key = va_arg(args, char *)) != NULL) {

        if (strlen(key) < 3) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("argument key '%s' is too short, missing type prefix"),
                           key);
            goto cleanup;
        }

        type = key[0];
        key += 2;

        /* This doesn't support maps, but no command uses those.  */
        switch (type) {
        case 'S':
        case 's': {
            char *val = va_arg(args, char *);
            if (!val) {
                if (type == 'S')
                    continue;

                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("argument key '%s' must not have null value"),
                               key);
                goto cleanup;
            }
            rc = virJSONValueObjectAppendString(obj, key, val);
        }   break;

        case 'z':
        case 'y':
        case 'j':
        case 'i': {
            int val = va_arg(args, int);

            if (val < 0 && (type == 'j' || type == 'y')) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("argument key '%s' must not be negative"),
                               key);
                goto cleanup;
            }

            if (!val && (type == 'z' || type == 'y'))
                continue;

            rc = virJSONValueObjectAppendNumberInt(obj, key, val);
        }   break;

        case 'p':
        case 'u': {
            unsigned int val = va_arg(args, unsigned int);

            if (!val && type == 'p')
                continue;

            rc = virJSONValueObjectAppendNumberUint(obj, key, val);
        }   break;

        case 'Z':
        case 'Y':
        case 'J':
        case 'I': {
            long long val = va_arg(args, long long);

            if (val < 0 && (type == 'J' || type == 'Y')) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("argument key '%s' must not be negative"),
                               key);
                goto cleanup;
            }

            if (!val && (type == 'Z' || type == 'Y'))
                continue;

            rc = virJSONValueObjectAppendNumberLong(obj, key, val);
        }   break;

        case 'P':
        case 'U': {
            /* qemu silently truncates numbers larger than LLONG_MAX,
             * so passing the full range of unsigned 64 bit integers
             * is not safe here.  Pass them as signed 64 bit integers
             * instead.
             */
            long long val = va_arg(args, long long);

            if (!val && type == 'P')
                continue;

            rc = virJSONValueObjectAppendNumberLong(obj, key, val);
        }   break;

        case 'd': {
            double val = va_arg(args, double);
            rc = virJSONValueObjectAppendNumberDouble(obj, key, val);
        }   break;

        case 'B':
        case 'b': {
            int val = va_arg(args, int);

            if (!val && type == 'B')
                continue;

            rc = virJSONValueObjectAppendBoolean(obj, key, val);
        }   break;

        case 'n': {
            rc = virJSONValueObjectAppendNull(obj, key);
        }   break;

        case 'A':
        case 'a': {
            virJSONValuePtr *val = va_arg(args, virJSONValuePtr *);

            if (!(*val)) {
                if (type == 'A')
                    continue;

                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("argument key '%s' must not have null value"),
                               key);
                goto cleanup;
            }

            if ((rc = virJSONValueObjectAppend(obj, key, *val)) == 0)
                *val = NULL;
        }   break;

        case 'M':
        case 'm': {
            virBitmapPtr map = va_arg(args, virBitmapPtr);
            virJSONValuePtr jsonMap;

            if (!map) {
                if (type == 'M')
                    continue;

                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("argument key '%s' must not have null value"),
                               key);
                goto cleanup;
            }

            if (!(jsonMap = virJSONValueNewArrayFromBitmap(map)))
                goto cleanup;

            if ((rc = virJSONValueObjectAppend(obj, key, jsonMap)) < 0)
                virJSONValueFree(jsonMap);
        } break;

        default:
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unsupported data type '%c' for arg '%s'"), type, key - 2);
            goto cleanup;
        }

        if (rc < 0)
            goto cleanup;
    }

    /* verify that we added at least one key-value pair */
    if (virJSONValueObjectKeysNumber(obj) == 0) {
        ret = 0;
        goto cleanup;
    }

    ret = 1;

 cleanup:
    return ret;
}


int
virJSONValueObjectAdd(virJSONValuePtr obj, ...)
{
    va_list args;
    int ret;

    va_start(args, obj);
    ret = virJSONValueObjectAddVArgs(obj, args);
    va_end(args);

    return ret;
}


int
virJSONValueObjectCreateVArgs(virJSONValuePtr *obj,
                              va_list args)
{
    int ret;

    if (!(*obj = virJSONValueNewObject()))
        return -1;

    /* free the object on error, or if no value objects were added */
    if ((ret = virJSONValueObjectAddVArgs(*obj, args)) <= 0) {
        virJSONValueFree(*obj);
        *obj = NULL;
    }

    return ret;
}


int
virJSONValueObjectCreate(virJSONValuePtr *obj, ...)
{
    va_list args;
    int ret;

    va_start(args, obj);
    ret = virJSONValueObjectCreateVArgs(obj, args);
    va_end(args);

    return ret;
}


void
virJSONValueFree(virJSONValuePtr value)
{
    size_t i;
    if (!value)
        return;

    switch ((virJSONType) value->type) {
    case VIR_JSON_TYPE_OBJECT:
        for (i = 0; i < value->data.object.npairs; i++) {
            VIR_FREE(value->data.object.pairs[i].key);
            virJSONValueFree(value->data.object.pairs[i].value);
        }
        VIR_FREE(value->data.object.pairs);
        break;
    case VIR_JSON_TYPE_ARRAY:
        for (i = 0; i < value->data.array.nvalues; i++)
            virJSONValueFree(value->data.array.values[i]);
        VIR_FREE(value->data.array.values);
        break;
    case VIR_JSON_TYPE_STRING:
        VIR_FREE(value->data.string);
        break;
    case VIR_JSON_TYPE_NUMBER:
        VIR_FREE(value->data.number);
        break;
    case VIR_JSON_TYPE_BOOLEAN:
    case VIR_JSON_TYPE_NULL:
        break;
    }

    VIR_FREE(value);
}


void
virJSONValueHashFree(void *opaque,
                     const void *name ATTRIBUTE_UNUSED)
{
    virJSONValueFree(opaque);
}


virJSONValuePtr
virJSONValueNewString(const char *data)
{
    virJSONValuePtr val;

    if (!data)
        return virJSONValueNewNull();

    if (VIR_ALLOC(val) < 0)
        return NULL;

    val->type = VIR_JSON_TYPE_STRING;
    if (VIR_STRDUP(val->data.string, data) < 0) {
        VIR_FREE(val);
        return NULL;
    }

    return val;
}


static virJSONValuePtr
virJSONValueNewNumber(const char *data)
{
    virJSONValuePtr val;

    if (VIR_ALLOC(val) < 0)
        return NULL;

    val->type = VIR_JSON_TYPE_NUMBER;
    if (VIR_STRDUP(val->data.number, data) < 0) {
        VIR_FREE(val);
        return NULL;
    }

    return val;
}


virJSONValuePtr
virJSONValueNewNumberInt(int data)
{
    VIR_AUTOFREE(char *) str = NULL;
    if (virAsprintf(&str, "%i", data) < 0)
        return NULL;
    return virJSONValueNewNumber(str);
}


virJSONValuePtr
virJSONValueNewNumberUint(unsigned int data)
{
    VIR_AUTOFREE(char *) str = NULL;
    if (virAsprintf(&str, "%u", data) < 0)
        return NULL;
    return virJSONValueNewNumber(str);
}


virJSONValuePtr
virJSONValueNewNumberLong(long long data)
{
    VIR_AUTOFREE(char *) str = NULL;
    if (virAsprintf(&str, "%lld", data) < 0)
        return NULL;
    return virJSONValueNewNumber(str);
}


virJSONValuePtr
virJSONValueNewNumberUlong(unsigned long long data)
{
    VIR_AUTOFREE(char *) str = NULL;
    if (virAsprintf(&str, "%llu", data) < 0)
        return NULL;
    return virJSONValueNewNumber(str);
}


virJSONValuePtr
virJSONValueNewNumberDouble(double data)
{
    VIR_AUTOFREE(char *) str = NULL;
    if (virDoubleToStr(&str, data) < 0)
        return NULL;
    return virJSONValueNewNumber(str);
}


virJSONValuePtr
virJSONValueNewBoolean(int boolean_)
{
    virJSONValuePtr val;

    if (VIR_ALLOC(val) < 0)
        return NULL;

    val->type = VIR_JSON_TYPE_BOOLEAN;
    val->data.boolean = boolean_;

    return val;
}


virJSONValuePtr
virJSONValueNewNull(void)
{
    virJSONValuePtr val;

    if (VIR_ALLOC(val) < 0)
        return NULL;

    val->type = VIR_JSON_TYPE_NULL;

    return val;
}


virJSONValuePtr
virJSONValueNewArray(void)
{
    virJSONValuePtr val;

    if (VIR_ALLOC(val) < 0)
        return NULL;

    val->type = VIR_JSON_TYPE_ARRAY;

    return val;
}


virJSONValuePtr
virJSONValueNewObject(void)
{
    virJSONValuePtr val;

    if (VIR_ALLOC(val) < 0)
        return NULL;

    val->type = VIR_JSON_TYPE_OBJECT;

    return val;
}


int
virJSONValueObjectAppend(virJSONValuePtr object,
                         const char *key,
                         virJSONValuePtr value)
{
    char *newkey;

    if (object->type != VIR_JSON_TYPE_OBJECT)
        return -1;

    if (virJSONValueObjectHasKey(object, key))
        return -1;

    if (VIR_STRDUP(newkey, key) < 0)
        return -1;

    if (VIR_REALLOC_N(object->data.object.pairs,
                      object->data.object.npairs + 1) < 0) {
        VIR_FREE(newkey);
        return -1;
    }

    object->data.object.pairs[object->data.object.npairs].key = newkey;
    object->data.object.pairs[object->data.object.npairs].value = value;
    object->data.object.npairs++;

    return 0;
}


int
virJSONValueObjectAppendString(virJSONValuePtr object,
                               const char *key,
                               const char *value)
{
    virJSONValuePtr jvalue = virJSONValueNewString(value);
    if (!jvalue)
        return -1;
    if (virJSONValueObjectAppend(object, key, jvalue) < 0) {
        virJSONValueFree(jvalue);
        return -1;
    }
    return 0;
}


int
virJSONValueObjectAppendNumberInt(virJSONValuePtr object,
                                  const char *key,
                                  int number)
{
    virJSONValuePtr jvalue = virJSONValueNewNumberInt(number);
    if (!jvalue)
        return -1;
    if (virJSONValueObjectAppend(object, key, jvalue) < 0) {
        virJSONValueFree(jvalue);
        return -1;
    }
    return 0;
}


int
virJSONValueObjectAppendNumberUint(virJSONValuePtr object,
                                   const char *key,
                                   unsigned int number)
{
    virJSONValuePtr jvalue = virJSONValueNewNumberUint(number);
    if (!jvalue)
        return -1;
    if (virJSONValueObjectAppend(object, key, jvalue) < 0) {
        virJSONValueFree(jvalue);
        return -1;
    }
    return 0;
}


int
virJSONValueObjectAppendNumberLong(virJSONValuePtr object,
                                   const char *key,
                                   long long number)
{
    virJSONValuePtr jvalue = virJSONValueNewNumberLong(number);
    if (!jvalue)
        return -1;
    if (virJSONValueObjectAppend(object, key, jvalue) < 0) {
        virJSONValueFree(jvalue);
        return -1;
    }
    return 0;
}


int
virJSONValueObjectAppendNumberUlong(virJSONValuePtr object,
                                    const char *key,
                                    unsigned long long number)
{
    virJSONValuePtr jvalue = virJSONValueNewNumberUlong(number);
    if (!jvalue)
        return -1;
    if (virJSONValueObjectAppend(object, key, jvalue) < 0) {
        virJSONValueFree(jvalue);
        return -1;
    }
    return 0;
}


int
virJSONValueObjectAppendNumberDouble(virJSONValuePtr object,
                                     const char *key,
                                     double number)
{
    virJSONValuePtr jvalue = virJSONValueNewNumberDouble(number);
    if (!jvalue)
        return -1;
    if (virJSONValueObjectAppend(object, key, jvalue) < 0) {
        virJSONValueFree(jvalue);
        return -1;
    }
    return 0;
}


int
virJSONValueObjectAppendBoolean(virJSONValuePtr object,
                                const char *key,
                                int boolean_)
{
    virJSONValuePtr jvalue = virJSONValueNewBoolean(boolean_);
    if (!jvalue)
        return -1;
    if (virJSONValueObjectAppend(object, key, jvalue) < 0) {
        virJSONValueFree(jvalue);
        return -1;
    }
    return 0;
}


int
virJSONValueObjectAppendNull(virJSONValuePtr object,
                             const char *key)
{
    virJSONValuePtr jvalue = virJSONValueNewNull();
    if (!jvalue)
        return -1;
    if (virJSONValueObjectAppend(object, key, jvalue) < 0) {
        virJSONValueFree(jvalue);
        return -1;
    }
    return 0;
}


int
virJSONValueArrayAppend(virJSONValuePtr array,
                        virJSONValuePtr value)
{
    if (array->type != VIR_JSON_TYPE_ARRAY)
        return -1;

    if (VIR_REALLOC_N(array->data.array.values,
                      array->data.array.nvalues + 1) < 0)
        return -1;

    array->data.array.values[array->data.array.nvalues] = value;
    array->data.array.nvalues++;

    return 0;
}


int
virJSONValueObjectHasKey(virJSONValuePtr object,
                         const char *key)
{
    size_t i;

    if (object->type != VIR_JSON_TYPE_OBJECT)
        return -1;

    for (i = 0; i < object->data.object.npairs; i++) {
        if (STREQ(object->data.object.pairs[i].key, key))
            return 1;
    }

    return 0;
}


virJSONValuePtr
virJSONValueObjectGet(virJSONValuePtr object,
                      const char *key)
{
    size_t i;

    if (object->type != VIR_JSON_TYPE_OBJECT)
        return NULL;

    for (i = 0; i < object->data.object.npairs; i++) {
        if (STREQ(object->data.object.pairs[i].key, key))
            return object->data.object.pairs[i].value;
    }

    return NULL;
}


static virJSONValuePtr
virJSONValueObjectSteal(virJSONValuePtr object,
                        const char *key)
{
    size_t i;
    virJSONValuePtr obj = NULL;

    if (object->type != VIR_JSON_TYPE_OBJECT)
        return NULL;

    for (i = 0; i < object->data.object.npairs; i++) {
        if (STREQ(object->data.object.pairs[i].key, key)) {
            VIR_STEAL_PTR(obj, object->data.object.pairs[i].value);
            VIR_FREE(object->data.object.pairs[i].key);
            VIR_DELETE_ELEMENT(object->data.object.pairs, i,
                               object->data.object.npairs);
            break;
        }
    }

    return obj;
}


/* Return the value associated with KEY within OBJECT, but return NULL
 * if the key is missing or if value is not the correct TYPE.  */
virJSONValuePtr
virJSONValueObjectGetByType(virJSONValuePtr object,
                            const char *key,
                            virJSONType type)
{
    virJSONValuePtr value = virJSONValueObjectGet(object, key);

    if (value && value->type == type)
        return value;
    return NULL;
}


/* Steal the value associated with KEY within OBJECT, but return NULL
 * if the key is missing or if value is not the correct TYPE.  */
static virJSONValuePtr
virJSONValueObjectStealByType(virJSONValuePtr object,
                              const char *key,
                              virJSONType type)
{
    virJSONValuePtr value = virJSONValueObjectSteal(object, key);

    if (value && value->type == type)
        return value;
    return NULL;
}


int
virJSONValueObjectKeysNumber(virJSONValuePtr object)
{
    if (object->type != VIR_JSON_TYPE_OBJECT)
        return -1;

    return object->data.object.npairs;
}


const char *
virJSONValueObjectGetKey(virJSONValuePtr object,
                         unsigned int n)
{
    if (object->type != VIR_JSON_TYPE_OBJECT)
        return NULL;

    if (n >= object->data.object.npairs)
        return NULL;

    return object->data.object.pairs[n].key;
}


/* Remove the key-value pair tied to @key out of @object.  If @value is
 * not NULL, the dropped value object is returned instead of freed.
 * Returns 1 on success, 0 if no key was found, and -1 on error.  */
int
virJSONValueObjectRemoveKey(virJSONValuePtr object,
                            const char *key,
                            virJSONValuePtr *value)
{
    size_t i;

    if (value)
        *value = NULL;

    if (object->type != VIR_JSON_TYPE_OBJECT)
        return -1;

    for (i = 0; i < object->data.object.npairs; i++) {
        if (STREQ(object->data.object.pairs[i].key, key)) {
            if (value) {
                *value = object->data.object.pairs[i].value;
                object->data.object.pairs[i].value = NULL;
            }
            VIR_FREE(object->data.object.pairs[i].key);
            virJSONValueFree(object->data.object.pairs[i].value);
            VIR_DELETE_ELEMENT(object->data.object.pairs, i,
                               object->data.object.npairs);
            return 1;
        }
    }

    return 0;
}


virJSONValuePtr
virJSONValueObjectGetValue(virJSONValuePtr object,
                           unsigned int n)
{
    if (object->type != VIR_JSON_TYPE_OBJECT)
        return NULL;

    if (n >= object->data.object.npairs)
        return NULL;

    return object->data.object.pairs[n].value;
}


bool
virJSONValueIsObject(virJSONValuePtr object)
{
    if (object)
        return object->type == VIR_JSON_TYPE_OBJECT;
    else
        return false;
}


bool
virJSONValueIsArray(virJSONValuePtr array)
{
    return array->type == VIR_JSON_TYPE_ARRAY;
}


size_t
virJSONValueArraySize(const virJSONValue *array)
{
    return array->data.array.nvalues;
}


virJSONValuePtr
virJSONValueArrayGet(virJSONValuePtr array,
                     unsigned int element)
{
    if (array->type != VIR_JSON_TYPE_ARRAY)
        return NULL;

    if (element >= array->data.array.nvalues)
        return NULL;

    return array->data.array.values[element];
}


virJSONValuePtr
virJSONValueArraySteal(virJSONValuePtr array,
                       unsigned int element)
{
    virJSONValuePtr ret = NULL;

    if (array->type != VIR_JSON_TYPE_ARRAY)
        return NULL;

    if (element >= array->data.array.nvalues)
        return NULL;

    ret = array->data.array.values[element];

    VIR_DELETE_ELEMENT(array->data.array.values,
                       element,
                       array->data.array.nvalues);

    return ret;
}


/**
 * virJSONValueArrayForeachSteal:
 * @array: array to iterate
 * @cb: callback called on every member of the array
 * @opaque: custom data for the callback
 *
 * Iterates members of the array and calls the callback on every single member.
 * The return codes of the callback are interpreted as follows:
 *  0: callback claims ownership of the array element and is responsible for
 *     freeing it
 *  1: callback doesn't claim ownership of the element
 * -1: callback doesn't claim ownership of the element and iteration does not
 *     continue
 *
 * Returns 0 if all members were iterated and/or stolen by the callback; -1
 * on callback failure or if the JSON value object is not an array.
 * The rest of the members stay in possession of the array and it's condensed.
 */
int
virJSONValueArrayForeachSteal(virJSONValuePtr array,
                              virJSONArrayIteratorFunc cb,
                              void *opaque)
{
    size_t i;
    size_t j = 0;
    int ret = 0;
    int rc;

    if (array->type != VIR_JSON_TYPE_ARRAY)
        return -1;

    for (i = 0; i < array->data.array.nvalues; i++) {
        if ((rc = cb(i, array->data.array.values[i], opaque)) < 0) {
            ret = -1;
            break;
        }

        if (rc == 0)
            array->data.array.values[i] = NULL;
    }

    /* condense the remaining entries at the beginning */
    for (i = 0; i < array->data.array.nvalues; i++) {
        if (!array->data.array.values[i])
            continue;

        array->data.array.values[j++] = array->data.array.values[i];
    }

    array->data.array.nvalues = j;

    return ret;
}


const char *
virJSONValueGetString(virJSONValuePtr string)
{
    if (string->type != VIR_JSON_TYPE_STRING)
        return NULL;

    return string->data.string;
}


const char *
virJSONValueGetNumberString(virJSONValuePtr number)
{
    if (number->type != VIR_JSON_TYPE_NUMBER)
        return NULL;

    return number->data.number;
}


int
virJSONValueGetNumberInt(virJSONValuePtr number,
                         int *value)
{
    if (number->type != VIR_JSON_TYPE_NUMBER)
        return -1;

    return virStrToLong_i(number->data.number, NULL, 10, value);
}


int
virJSONValueGetNumberUint(virJSONValuePtr number,
                          unsigned int *value)
{
    if (number->type != VIR_JSON_TYPE_NUMBER)
        return -1;

    return virStrToLong_ui(number->data.number, NULL, 10, value);
}


int
virJSONValueGetNumberLong(virJSONValuePtr number,
                          long long *value)
{
    if (number->type != VIR_JSON_TYPE_NUMBER)
        return -1;

    return virStrToLong_ll(number->data.number, NULL, 10, value);
}


int
virJSONValueGetNumberUlong(virJSONValuePtr number,
                           unsigned long long *value)
{
    if (number->type != VIR_JSON_TYPE_NUMBER)
        return -1;

    return virStrToLong_ull(number->data.number, NULL, 10, value);
}


int
virJSONValueGetNumberDouble(virJSONValuePtr number,
                            double *value)
{
    if (number->type != VIR_JSON_TYPE_NUMBER)
        return -1;

    return virStrToDouble(number->data.number, NULL, value);
}


int
virJSONValueGetBoolean(virJSONValuePtr val,
                       bool *value)
{
    if (val->type != VIR_JSON_TYPE_BOOLEAN)
        return -1;

    *value = val->data.boolean;
    return 0;
}


/**
 * virJSONValueGetArrayAsBitmap:
 * @val: JSON array to convert to bitmap
 * @bitmap: New bitmap is allocated filled and returned via this argument
 *
 * Attempts a conversion of a JSON array to a bitmap. The members of the array
 * must be non-negative integers for the conversion to succeed. This function
 * does not report libvirt errors so that it can be used to probe that the
 * array can be represented as a bitmap.
 *
 * Returns 0 on success and fills @bitmap; -1 on error and  @bitmap is set to
 * NULL.
 */
int
virJSONValueGetArrayAsBitmap(const virJSONValue *val,
                             virBitmapPtr *bitmap)
{
    virJSONValuePtr elem;
    size_t i;
    VIR_AUTOFREE(unsigned long long *) elems = NULL;
    unsigned long long maxelem = 0;

    *bitmap = NULL;

    if (val->type != VIR_JSON_TYPE_ARRAY)
        return -1;

    if (VIR_ALLOC_N_QUIET(elems, val->data.array.nvalues) < 0)
        return -1;

    /* first pass converts array members to numbers and finds the maximum */
    for (i = 0; i < val->data.array.nvalues; i++) {
        elem = val->data.array.values[i];

        if (elem->type != VIR_JSON_TYPE_NUMBER ||
            virStrToLong_ullp(elem->data.number, NULL, 10, &elems[i]) < 0)
            return -1;

        if (elems[i] > maxelem)
            maxelem = elems[i];
    }

    if (!(*bitmap = virBitmapNewQuiet(maxelem + 1)))
        return -1;

    /* second pass sets the correct bits in the map */
    for (i = 0; i < val->data.array.nvalues; i++)
        ignore_value(virBitmapSetBit(*bitmap, elems[i]));

    return 0;
}


virJSONValuePtr
virJSONValueNewArrayFromBitmap(virBitmapPtr bitmap)
{
    virJSONValuePtr ret;
    ssize_t pos = -1;

    if (!(ret = virJSONValueNewArray()))
        return NULL;

    if (!bitmap)
        return ret;

    while ((pos = virBitmapNextSetBit(bitmap, pos)) > -1) {
        virJSONValuePtr newelem;

        if (!(newelem = virJSONValueNewNumberLong(pos)) ||
            virJSONValueArrayAppend(ret, newelem) < 0) {
            virJSONValueFree(newelem);
            goto error;
        }
    }

    return ret;

 error:
    virJSONValueFree(ret);
    return NULL;
}


bool
virJSONValueIsNull(virJSONValuePtr val)
{
    return val->type == VIR_JSON_TYPE_NULL;
}


const char *
virJSONValueObjectGetString(virJSONValuePtr object,
                            const char *key)
{
    virJSONValuePtr val = virJSONValueObjectGet(object, key);

    if (!val)
        return NULL;

    return virJSONValueGetString(val);
}


/**
 * virJSONValueObjectGetStringOrNumber:
 * @object: JSON value object
 * @key: name of the property in @object to get
 *
 * Gets a property named @key from the JSON object @object. The value may be
 * a number or a string and is returned as a string. In cases when the property
 * is not present or is not a string or number NULL is returned.
 */
const char *
virJSONValueObjectGetStringOrNumber(virJSONValuePtr object,
                                    const char *key)
{
    virJSONValuePtr val = virJSONValueObjectGet(object, key);

    if (!val)
        return NULL;

    if (val->type == VIR_JSON_TYPE_STRING)
        return val->data.string;
    else if (val->type == VIR_JSON_TYPE_NUMBER)
        return val->data.number;

    return NULL;
}


int
virJSONValueObjectGetNumberInt(virJSONValuePtr object,
                               const char *key,
                               int *value)
{
    virJSONValuePtr val = virJSONValueObjectGet(object, key);

    if (!val)
        return -1;

    return virJSONValueGetNumberInt(val, value);
}


int
virJSONValueObjectGetNumberUint(virJSONValuePtr object,
                                const char *key,
                                unsigned int *value)
{
    virJSONValuePtr val = virJSONValueObjectGet(object, key);

    if (!val)
        return -1;

    return virJSONValueGetNumberUint(val, value);
}


int
virJSONValueObjectGetNumberLong(virJSONValuePtr object,
                                const char *key,
                                long long *value)
{
    virJSONValuePtr val = virJSONValueObjectGet(object, key);

    if (!val)
        return -1;

    return virJSONValueGetNumberLong(val, value);
}


int
virJSONValueObjectGetNumberUlong(virJSONValuePtr object,
                                 const char *key,
                                 unsigned long long *value)
{
    virJSONValuePtr val = virJSONValueObjectGet(object, key);

    if (!val)
        return -1;

    return virJSONValueGetNumberUlong(val, value);
}


int
virJSONValueObjectGetNumberDouble(virJSONValuePtr object,
                                  const char *key,
                                  double *value)
{
    virJSONValuePtr val = virJSONValueObjectGet(object, key);

    if (!val)
        return -1;

    return virJSONValueGetNumberDouble(val, value);
}


int
virJSONValueObjectGetBoolean(virJSONValuePtr object,
                             const char *key,
                             bool *value)
{
    virJSONValuePtr val = virJSONValueObjectGet(object, key);

    if (!val)
        return -1;

    return virJSONValueGetBoolean(val, value);
}


virJSONValuePtr
virJSONValueObjectGetObject(virJSONValuePtr object, const char *key)
{
    return virJSONValueObjectGetByType(object, key, VIR_JSON_TYPE_OBJECT);
}


virJSONValuePtr
virJSONValueObjectGetArray(virJSONValuePtr object, const char *key)
{
    return virJSONValueObjectGetByType(object, key, VIR_JSON_TYPE_ARRAY);
}


virJSONValuePtr
virJSONValueObjectStealArray(virJSONValuePtr object, const char *key)
{
    return virJSONValueObjectStealByType(object, key, VIR_JSON_TYPE_ARRAY);
}


virJSONValuePtr
virJSONValueObjectStealObject(virJSONValuePtr object,
                              const char *key)
{
    return virJSONValueObjectStealByType(object, key, VIR_JSON_TYPE_OBJECT);
}


int
virJSONValueObjectIsNull(virJSONValuePtr object,
                         const char *key)
{
    virJSONValuePtr val = virJSONValueObjectGet(object, key);

    if (!val)
        return -1;

    return virJSONValueIsNull(val);
}


/**
 * virJSONValueObjectForeachKeyValue:
 * @object: JSON object to iterate
 * @cb: callback to call on key-value pairs contained in the object
 * @opaque: generic data for the callback
 *
 * Iterates all key=value pairs in @object. Iteration breaks if @cb returns
 * negative value.
 *
 * Returns 0 if all elements were iterated, -2 if @cb returned negative value
 * during iteration and -1 on generic errors.
 */
int
virJSONValueObjectForeachKeyValue(virJSONValuePtr object,
                                  virJSONValueObjectIteratorFunc cb,
                                  void *opaque)
{
    size_t i;

    if (object->type != VIR_JSON_TYPE_OBJECT)
        return -1;

    for (i = 0; i < object->data.object.npairs; i++) {
        virJSONObjectPairPtr elem = object->data.object.pairs + i;

        if (cb(elem->key, elem->value, opaque) < 0)
            return -2;
    }

    return 0;
}


virJSONValuePtr
virJSONValueCopy(const virJSONValue *in)
{
    size_t i;
    virJSONValuePtr out = NULL;

    if (!in)
        return NULL;

    switch ((virJSONType) in->type) {
    case VIR_JSON_TYPE_OBJECT:
        out = virJSONValueNewObject();
        if (!out)
            return NULL;
        for (i = 0; i < in->data.object.npairs; i++) {
            virJSONValuePtr val = NULL;
            if (!(val = virJSONValueCopy(in->data.object.pairs[i].value)))
                goto error;
            if (virJSONValueObjectAppend(out, in->data.object.pairs[i].key,
                                         val) < 0) {
                virJSONValueFree(val);
                goto error;
            }
        }
        break;
    case VIR_JSON_TYPE_ARRAY:
        out = virJSONValueNewArray();
        if (!out)
            return NULL;
        for (i = 0; i < in->data.array.nvalues; i++) {
            virJSONValuePtr val = NULL;
            if (!(val = virJSONValueCopy(in->data.array.values[i])))
                goto error;
            if (virJSONValueArrayAppend(out, val) < 0) {
                virJSONValueFree(val);
                goto error;
            }
        }
        break;

    /* No need to error out in the following cases */
    case VIR_JSON_TYPE_STRING:
        out = virJSONValueNewString(in->data.string);
        break;
    case VIR_JSON_TYPE_NUMBER:
        out = virJSONValueNewNumber(in->data.number);
        break;
    case VIR_JSON_TYPE_BOOLEAN:
        out = virJSONValueNewBoolean(in->data.boolean);
        break;
    case VIR_JSON_TYPE_NULL:
        out = virJSONValueNewNull();
        break;
    }

    return out;

 error:
    virJSONValueFree(out);
    return NULL;
}


#if WITH_JANSSON

# include "virjsoncompat.h"

static virJSONValuePtr
virJSONValueFromJansson(json_t *json)
{
    virJSONValuePtr ret = NULL;
    const char *key;
    json_t *cur;
    size_t i;

    switch (json_typeof(json)) {
    case JSON_OBJECT:
        ret = virJSONValueNewObject();
        if (!ret)
            goto error;

        json_object_foreach(json, key, cur) {
            virJSONValuePtr val = virJSONValueFromJansson(cur);
            if (!val)
                goto error;

            if (virJSONValueObjectAppend(ret, key, val) < 0) {
                virJSONValueFree(val);
                goto error;
            }
        }

        break;

    case JSON_ARRAY:
        ret = virJSONValueNewArray();
        if (!ret)
            goto error;

        json_array_foreach(json, i, cur) {
            virJSONValuePtr val = virJSONValueFromJansson(cur);
            if (!val)
                goto error;

            if (virJSONValueArrayAppend(ret, val) < 0) {
                virJSONValueFree(val);
                goto error;
            }
        }
        break;

    case JSON_STRING:
        ret = virJSONValueNewString(json_string_value(json));
        break;

    case JSON_INTEGER:
        ret = virJSONValueNewNumberLong(json_integer_value(json));
        break;

    case JSON_REAL:
        ret = virJSONValueNewNumberDouble(json_real_value(json));
        break;

    case JSON_TRUE:
        ret = virJSONValueNewBoolean(true);
        break;

    case JSON_FALSE:
        ret = virJSONValueNewBoolean(false);
        break;

    case JSON_NULL:
        ret = virJSONValueNewNull();
        break;
    }

    return ret;

 error:
    virJSONValueFree(ret);
    return NULL;
}

virJSONValuePtr
virJSONValueFromString(const char *jsonstring)
{
    virJSONValuePtr ret = NULL;
    json_t *json;
    json_error_t error;
    size_t flags = JSON_REJECT_DUPLICATES |
                   JSON_DECODE_ANY;

    if (virJSONInitialize() < 0)
        return NULL;

    if (!(json = json_loads(jsonstring, flags, &error))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to parse JSON %d:%d: %s"),
                       error.line, error.column, error.text);
        return NULL;
    }

    ret = virJSONValueFromJansson(json);
    json_decref(json);
    return ret;
}


static json_t *
virJSONValueToJansson(virJSONValuePtr object)
{
    json_t *ret = NULL;
    size_t i;

    switch ((virJSONType)object->type) {
    case VIR_JSON_TYPE_OBJECT:
        ret = json_object();
        if (!ret)
            goto no_memory;
        for (i = 0; i < object->data.object.npairs; i++) {
            virJSONObjectPairPtr cur = object->data.object.pairs + i;
            json_t *val = virJSONValueToJansson(cur->value);

            if (!val)
                goto error;
            if (json_object_set_new(ret, cur->key, val) < 0) {
                json_decref(val);
                goto no_memory;
            }
        }
        break;

    case VIR_JSON_TYPE_ARRAY:
        ret = json_array();
        if (!ret)
            goto no_memory;
        for (i = 0; i < object->data.array.nvalues; i++) {
            virJSONValuePtr cur = object->data.array.values[i];
            json_t *val = virJSONValueToJansson(cur);

            if (!val)
                goto error;
            if (json_array_append_new(ret, val) < 0) {
                json_decref(val);
                goto no_memory;
            }
        }
        break;

    case VIR_JSON_TYPE_STRING:
        ret = json_string(object->data.string);
        break;

    case VIR_JSON_TYPE_NUMBER: {
        long long ll_val;
        double d_val;
        if (virStrToLong_ll(object->data.number, NULL, 10, &ll_val) < 0) {
            if (virStrToDouble(object->data.number, NULL, &d_val) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("JSON value is not a number"));
                return NULL;
            }
            ret = json_real(d_val);
        } else {
            ret = json_integer(ll_val);
        }
    }
        break;

    case VIR_JSON_TYPE_BOOLEAN:
        ret = json_boolean(object->data.boolean);
        break;

    case VIR_JSON_TYPE_NULL:
        ret = json_null();
        break;

    default:
        virReportEnumRangeError(virJSONType, object->type);
        goto error;
    }
    if (!ret)
        goto no_memory;
    return ret;

 no_memory:
    virReportOOMError();
 error:
    json_decref(ret);
    return NULL;
}


char *
virJSONValueToString(virJSONValuePtr object,
                     bool pretty)
{
    size_t flags = JSON_ENCODE_ANY;
    json_t *json;
    char *str = NULL;

    if (virJSONInitialize() < 0)
        return NULL;

    if (pretty)
        flags |= JSON_INDENT(2);
    else
        flags |= JSON_COMPACT;

    json = virJSONValueToJansson(object);
    if (!json)
        return NULL;

    str = json_dumps(json, flags);
    if (!str)
        virReportOOMError();
    json_decref(json);
    return str;
}


#else
virJSONValuePtr
virJSONValueFromString(const char *jsonstring ATTRIBUTE_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("No JSON parser implementation is available"));
    return NULL;
}


char *
virJSONValueToString(virJSONValuePtr object ATTRIBUTE_UNUSED,
                     bool pretty ATTRIBUTE_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("No JSON parser implementation is available"));
    return NULL;
}
#endif


/**
 * virJSONStringReformat:
 * @jsonstr: string to reformat
 * @pretty: use the pretty formatter
 *
 * Reformats a JSON string by passing it to the parser and then to the
 * formatter. If @pretty is true the JSON is formatted for human eye
 * compatibility.
 *
 * Returns the reformatted JSON string on success; NULL and a libvirt error on
 * failure.
 */
char *
virJSONStringReformat(const char *jsonstr,
                      bool pretty)
{
    VIR_AUTOPTR(virJSONValue) json = NULL;

    if (!(json = virJSONValueFromString(jsonstr)))
        return NULL;

    return virJSONValueToString(json, pretty);
}


static int
virJSONValueObjectDeflattenWorker(const char *key,
                                  virJSONValuePtr value,
                                  void *opaque)
{
    virJSONValuePtr retobj = opaque;
    virJSONValuePtr newval = NULL;
    virJSONValuePtr existobj;
    char **tokens = NULL;
    size_t ntokens = 0;
    int ret = -1;

    /* non-nested keys only need to be copied */
    if (!strchr(key, '.')) {

        if (virJSONValueIsObject(value))
            newval = virJSONValueObjectDeflatten(value);
        else
            newval = virJSONValueCopy(value);

        if (!newval)
            return -1;

        if (virJSONValueObjectHasKey(retobj, key)) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("can't deflatten colliding key '%s'"), key);
            goto cleanup;
        }

        if (virJSONValueObjectAppend(retobj, key, newval) < 0)
            goto cleanup;

        return 0;
    }

    if (!(tokens = virStringSplitCount(key, ".", 2, &ntokens)))
        goto cleanup;

    if (ntokens != 2) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("invalid nested value key '%s'"), key);
        goto cleanup;
    }

    if (!(existobj = virJSONValueObjectGet(retobj, tokens[0]))) {
        if (!(existobj = virJSONValueNewObject()))
            goto cleanup;

        if (virJSONValueObjectAppend(retobj, tokens[0], existobj) < 0)
            goto cleanup;

    } else {
        if (!virJSONValueIsObject(existobj)) {
            virReportError(VIR_ERR_INVALID_ARG, "%s",
                           _("mixing nested objects and values is forbidden in "
                             "JSON deflattening"));
            goto cleanup;
        }
    }

    ret = virJSONValueObjectDeflattenWorker(tokens[1], value, existobj);

 cleanup:
    virStringListFreeCount(tokens, ntokens);
    virJSONValueFree(newval);

    return ret;
}


/**
 * virJSONValueObjectDeflatten:
 *
 * In some cases it's possible to nest JSON objects by prefixing object members
 * with the parent object name followed by the dot and then the attribute name
 * rather than directly using a nested value object (e.g qemu's JSON
 * pseudo-protocol in backing file definition).
 *
 * This function will attempt to reverse the process and provide a nested json
 * hierarchy so that the parsers can be kept simple and we still can use the
 * weird syntax some users might use.
 */
virJSONValuePtr
virJSONValueObjectDeflatten(virJSONValuePtr json)
{
    VIR_AUTOPTR(virJSONValue) deflattened = NULL;
    virJSONValuePtr ret = NULL;

    if (!(deflattened = virJSONValueNewObject()))
        return NULL;

    if (virJSONValueObjectForeachKeyValue(json,
                                          virJSONValueObjectDeflattenWorker,
                                          deflattened) < 0)
        return NULL;

    VIR_STEAL_PTR(ret, deflattened);

    return ret;
}
