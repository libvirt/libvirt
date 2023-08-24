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
#include "viralloc.h"
#include "virerror.h"
#include "virlog.h"
#include "virstring.h"
#include "virbuffer.h"
#include "virenum.h"
#include "virbitmap.h"

#if WITH_YAJL
# include <yajl/yajl_gen.h>
# include <yajl/yajl_parse.h>

#endif

/* XXX fixme */
#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.json");

typedef struct _virJSONObject virJSONObject;

typedef struct _virJSONObjectPair virJSONObjectPair;

typedef struct _virJSONArray virJSONArray;


struct _virJSONObjectPair {
    char *key;
    virJSONValue *value;
};

struct _virJSONObject {
    size_t npairs;
    virJSONObjectPair *pairs;
};

struct _virJSONArray {
    size_t nvalues;
    virJSONValue **values;
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


typedef struct _virJSONParserState virJSONParserState;
struct _virJSONParserState {
    virJSONValue *value;
    char *key;
};

typedef struct _virJSONParser virJSONParser;
struct _virJSONParser {
    virJSONValue *head;
    virJSONParserState *state;
    size_t nstate;
    int wrap;
};


virJSONType
virJSONValueGetType(const virJSONValue *value)
{
    return value->type;
}


/**
 * virJSONValueObjectAddVArgs:
 * @objptr: pointer to a pointer to a JSON object to add the values to
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
 * k: signed integer value, omitted if negative
 * z: signed integer value, omitted if zero
 * y: signed integer value, omitted if zero, error if negative
 *
 * I: signed long integer value
 * J: signed long integer value, error if negative
 * K: signed long integer value, omitted if negative
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
 * T: boolean value specified by a virTristate(Bool|Switch) value, omitted on
 * the _ABSENT value
 *
 * d: double precision floating point number
 * n: json null value
 *
 * The following two cases take a pointer to a pointer to a virJSONValue *. The
 * pointer is cleared when the virJSONValue *is stolen into the object.
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
virJSONValueObjectAddVArgs(virJSONValue **objptr,
                           va_list args)
{
    g_autoptr(virJSONValue) newobj = NULL;
    virJSONValue *obj = *objptr;
    char type;
    char *key;
    int rc;

    if (obj == NULL)
        newobj = obj = virJSONValueNewObject();

    while ((key = va_arg(args, char *)) != NULL) {

        if (strlen(key) < 3 || key[1] != ':') {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("argument key '%1$s' is too short or malformed"),
                           key);
            return -1;
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
                               _("argument key '%1$s' must not have null value"),
                               key);
                return -1;
            }
            rc = virJSONValueObjectAppendString(obj, key, val);
        }   break;

        case 'z':
        case 'y':
        case 'k':
        case 'j':
        case 'i': {
            int val = va_arg(args, int);

            if (val < 0 && (type == 'j' || type == 'y')) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("argument key '%1$s' must not be negative"),
                               key);
                return -1;
            }

            if (!val && (type == 'z' || type == 'y'))
                continue;

            if (val < 0 && type == 'k')
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
        case 'K':
        case 'J':
        case 'I': {
            long long val = va_arg(args, long long);

            if (val < 0 && (type == 'J' || type == 'Y')) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("argument key '%1$s' must not be negative"),
                               key);
                return -1;
            }

            if (!val && (type == 'Z' || type == 'Y'))
                continue;

            if (val < 0 && type == 'K')
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

        case 'T':
        case 'B':
        case 'b': {
            int val = va_arg(args, int);

            if (!val && type == 'B')
                continue;

            if (type == 'T') {
                if (val == VIR_TRISTATE_BOOL_ABSENT)
                    continue;

                if (val == VIR_TRISTATE_BOOL_NO)
                    val = 0;
                else
                    val = 1;
            }

            rc = virJSONValueObjectAppendBoolean(obj, key, val);
        }   break;

        case 'n': {
            rc = virJSONValueObjectAppendNull(obj, key);
        }   break;

        case 'A':
        case 'a': {
            virJSONValue **val = va_arg(args, virJSONValue **);

            if (!(*val)) {
                if (type == 'A')
                    continue;

                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("argument key '%1$s' must not have null value"),
                               key);
                return -1;
            }

            rc = virJSONValueObjectAppend(obj, key, val);
        }   break;

        case 'M':
        case 'm': {
            virBitmap *map = va_arg(args, virBitmap *);
            g_autoptr(virJSONValue) jsonMap = virJSONValueNewArray();
            ssize_t pos = -1;

            if (!map) {
                if (type == 'M')
                    continue;

                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("argument key '%1$s' must not have null value"),
                               key);
                return -1;
            }

            while ((pos = virBitmapNextSetBit(map, pos)) > -1) {
                g_autoptr(virJSONValue) newelem = virJSONValueNewNumberLong(pos);

                if (virJSONValueArrayAppend(jsonMap, &newelem) < 0)
                    return -1;
            }

            if ((rc = virJSONValueObjectAppend(obj, key, &jsonMap)) < 0)
                return -1;
        } break;

        default:
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unsupported data type '%1$c' for arg '%2$s'"), type, key - 2);
            return -1;
        }

        if (rc < 0)
            return -1;
    }

    /* verify that we added at least one key-value pair */
    if (virJSONValueObjectKeysNumber(obj) == 0)
        return 0;

    if (newobj)
        *objptr = g_steal_pointer(&newobj);

    return 1;
}


int
virJSONValueObjectAdd(virJSONValue **objptr, ...)
{
    va_list args;
    int ret;

    va_start(args, objptr);
    ret = virJSONValueObjectAddVArgs(objptr, args);
    va_end(args);

    return ret;
}


void
virJSONValueFree(virJSONValue *value)
{
    size_t i;
    if (!value)
        return;

    switch ((virJSONType) value->type) {
    case VIR_JSON_TYPE_OBJECT:
        for (i = 0; i < value->data.object.npairs; i++) {
            g_free(value->data.object.pairs[i].key);
            virJSONValueFree(value->data.object.pairs[i].value);
        }
        g_free(value->data.object.pairs);
        break;
    case VIR_JSON_TYPE_ARRAY:
        for (i = 0; i < value->data.array.nvalues; i++)
            virJSONValueFree(value->data.array.values[i]);
        g_free(value->data.array.values);
        break;
    case VIR_JSON_TYPE_STRING:
        g_free(value->data.string);
        break;
    case VIR_JSON_TYPE_NUMBER:
        g_free(value->data.number);
        break;
    case VIR_JSON_TYPE_BOOLEAN:
    case VIR_JSON_TYPE_NULL:
        break;
    }

    g_free(value);
}


void
virJSONValueHashFree(void *opaque)
{
    virJSONValueFree(opaque);
}


virJSONValue *
virJSONValueNewString(char *data)
{
    virJSONValue *val;

    if (!data)
        return virJSONValueNewNull();

    val = g_new0(virJSONValue, 1);

    val->type = VIR_JSON_TYPE_STRING;
    val->data.string = data;

    return val;
}


/**
 * virJSONValueNewNumber:
 * @data: string representing the number
 *
 * Creates a new virJSONValue of VIR_JSON_TYPE_NUMBER type. Note that this
 * function takes ownership of @data.
 */
static virJSONValue *
virJSONValueNewNumber(char *data)
{
    virJSONValue *val;

    val = g_new0(virJSONValue, 1);

    val->type = VIR_JSON_TYPE_NUMBER;
    val->data.number = data;

    return val;
}


virJSONValue *
virJSONValueNewNumberInt(int data)
{
    return virJSONValueNewNumber(g_strdup_printf("%i", data));
}


virJSONValue *
virJSONValueNewNumberUint(unsigned int data)
{
    return virJSONValueNewNumber(g_strdup_printf("%u", data));
}


virJSONValue *
virJSONValueNewNumberLong(long long data)
{
    return virJSONValueNewNumber(g_strdup_printf("%lld", data));
}


virJSONValue *
virJSONValueNewNumberUlong(unsigned long long data)
{
    return virJSONValueNewNumber(g_strdup_printf("%llu", data));
}


virJSONValue *
virJSONValueNewNumberDouble(double data)
{
    char *str = NULL;
    if (virDoubleToStr(&str, data) < 0)
        return NULL;
    return virJSONValueNewNumber(str);
}


virJSONValue *
virJSONValueNewBoolean(int boolean_)
{
    virJSONValue *val;

    val = g_new0(virJSONValue, 1);

    val->type = VIR_JSON_TYPE_BOOLEAN;
    val->data.boolean = boolean_;

    return val;
}


virJSONValue *
virJSONValueNewNull(void)
{
    virJSONValue *val;

    val = g_new0(virJSONValue, 1);

    val->type = VIR_JSON_TYPE_NULL;

    return val;
}


virJSONValue *
virJSONValueNewArray(void)
{
    virJSONValue *val = g_new0(virJSONValue, 1);

    val->type = VIR_JSON_TYPE_ARRAY;

    return val;
}


virJSONValue *
virJSONValueNewObject(void)
{
    virJSONValue *val = g_new0(virJSONValue, 1);

    val->type = VIR_JSON_TYPE_OBJECT;

    return val;
}


static int
virJSONValueObjectInsert(virJSONValue *object,
                         const char *key,
                         virJSONValue **value,
                         bool prepend)
{
    virJSONObjectPair pair = { NULL, *value };
    int ret = -1;

    if (object->type != VIR_JSON_TYPE_OBJECT) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("expecting JSON object"));
        return -1;
    }

    if (virJSONValueObjectHasKey(object, key)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, _("duplicate key '%1$s'"), key);
        return -1;
    }

    pair.key = g_strdup(key);

    if (prepend) {
        ret = VIR_INSERT_ELEMENT(object->data.object.pairs, 0,
                                 object->data.object.npairs, pair);
    } else {
        VIR_APPEND_ELEMENT(object->data.object.pairs,
                           object->data.object.npairs, pair);
        ret = 0;
    }

    if (ret == 0)
        *value = NULL;

    VIR_FREE(pair.key);
    return ret;
}


int
virJSONValueObjectAppend(virJSONValue *object,
                         const char *key,
                         virJSONValue **value)
{
    return virJSONValueObjectInsert(object, key, value, false);
}


static int
virJSONValueObjectInsertString(virJSONValue *object,
                               const char *key,
                               const char *value,
                               bool prepend)
{
    g_autoptr(virJSONValue) jvalue = virJSONValueNewString(g_strdup(value));

    return virJSONValueObjectInsert(object, key, &jvalue, prepend);
}


int
virJSONValueObjectAppendString(virJSONValue *object,
                               const char *key,
                               const char *value)
{
    return virJSONValueObjectInsertString(object, key, value, false);
}


int
virJSONValueObjectPrependString(virJSONValue *object,
                                const char *key,
                                const char *value)
{
    return virJSONValueObjectInsertString(object, key, value, true);
}


int
virJSONValueObjectAppendNumberInt(virJSONValue *object,
                                  const char *key,
                                  int number)
{
    g_autoptr(virJSONValue) jvalue = virJSONValueNewNumberInt(number);

    if (virJSONValueObjectAppend(object, key, &jvalue) < 0)
        return -1;

    return 0;
}


int
virJSONValueObjectAppendNumberUint(virJSONValue *object,
                                   const char *key,
                                   unsigned int number)
{
    g_autoptr(virJSONValue) jvalue = virJSONValueNewNumberUint(number);

    if (virJSONValueObjectAppend(object, key, &jvalue) < 0)
        return -1;

    return 0;
}


int
virJSONValueObjectAppendNumberLong(virJSONValue *object,
                                   const char *key,
                                   long long number)
{
    g_autoptr(virJSONValue) jvalue = virJSONValueNewNumberLong(number);

    if (virJSONValueObjectAppend(object, key, &jvalue) < 0)
        return -1;

    return 0;
}


int
virJSONValueObjectAppendNumberUlong(virJSONValue *object,
                                    const char *key,
                                    unsigned long long number)
{
    g_autoptr(virJSONValue) jvalue = virJSONValueNewNumberUlong(number);

    if (virJSONValueObjectAppend(object, key, &jvalue) < 0)
        return -1;

    return 0;
}


int
virJSONValueObjectAppendNumberDouble(virJSONValue *object,
                                     const char *key,
                                     double number)
{
    g_autoptr(virJSONValue) jvalue = virJSONValueNewNumberDouble(number);

    /* virJSONValueNewNumberDouble may return NULL if locale setting fails */
    if (!jvalue)
        return -1;

    if (virJSONValueObjectAppend(object, key, &jvalue) < 0)
        return -1;

    return 0;
}


int
virJSONValueObjectAppendBoolean(virJSONValue *object,
                                const char *key,
                                int boolean_)
{
    g_autoptr(virJSONValue) jvalue = virJSONValueNewBoolean(boolean_);

    if (virJSONValueObjectAppend(object, key, &jvalue) < 0)
        return -1;

    return 0;
}


int
virJSONValueObjectAppendNull(virJSONValue *object,
                             const char *key)
{
    g_autoptr(virJSONValue) jvalue = virJSONValueNewNull();

    if (virJSONValueObjectAppend(object, key, &jvalue) < 0)
        return -1;

    return 0;
}


int
virJSONValueArrayAppend(virJSONValue *array,
                        virJSONValue **value)
{
    if (array->type != VIR_JSON_TYPE_ARRAY) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("expecting JSON array"));
        return -1;
    }

    VIR_REALLOC_N(array->data.array.values, array->data.array.nvalues + 1);

    array->data.array.values[array->data.array.nvalues] = g_steal_pointer(value);
    array->data.array.nvalues++;

    return 0;
}


int
virJSONValueArrayAppendString(virJSONValue *object,
                              const char *value)
{
    g_autoptr(virJSONValue) jvalue = virJSONValueNewString(g_strdup(value));

    if (virJSONValueArrayAppend(object, &jvalue) < 0)
        return -1;

    return 0;
}


/**
 * virJSONValueArrayConcat:
 * @a: JSON value array (destination)
 * @c: JSON value array (source)
 *
 * Merges the members of @c array into @a. The values are stolen from @c.
 */
int
virJSONValueArrayConcat(virJSONValue *a,
                        virJSONValue *c)
{
    size_t i;

    if (a->type != VIR_JSON_TYPE_ARRAY ||
        c->type != VIR_JSON_TYPE_ARRAY) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("expecting JSON array"));
        return -1;
    }

    a->data.array.values = g_renew(virJSONValue *, a->data.array.values,
                                   a->data.array.nvalues + c->data.array.nvalues);

    for (i = 0; i < c->data.array.nvalues; i++)
        a->data.array.values[a->data.array.nvalues++] = g_steal_pointer(&c->data.array.values[i]);

    c->data.array.nvalues = 0;

    return 0;
}


bool
virJSONValueObjectHasKey(virJSONValue *object,
                         const char *key)
{
    size_t i;

    if (object->type != VIR_JSON_TYPE_OBJECT)
        return false;

    for (i = 0; i < object->data.object.npairs; i++) {
        if (STREQ(object->data.object.pairs[i].key, key))
            return true;
    }

    return false;
}


virJSONValue *
virJSONValueObjectGet(virJSONValue *object,
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


/* Return the value associated with KEY within OBJECT, but return NULL
 * if the key is missing or if value is not the correct TYPE.  */
virJSONValue *
virJSONValueObjectGetByType(virJSONValue *object,
                            const char *key,
                            virJSONType type)
{
    virJSONValue *value = virJSONValueObjectGet(object, key);

    if (value && value->type == type)
        return value;
    return NULL;
}


/* Steal the value associated with KEY within OBJECT, but return NULL
 * if the key is missing or if value is not the correct TYPE.  */
static virJSONValue *
virJSONValueObjectStealByType(virJSONValue *object,
                              const char *key,
                              virJSONType type)
{
    virJSONValue *value;

    if (virJSONValueObjectRemoveKey(object, key, &value) <= 0)
        return NULL;

    if (value && value->type == type)
        return value;
    return NULL;
}


int
virJSONValueObjectKeysNumber(virJSONValue *object)
{
    if (object->type != VIR_JSON_TYPE_OBJECT)
        return -1;

    return object->data.object.npairs;
}


const char *
virJSONValueObjectGetKey(virJSONValue *object,
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
virJSONValueObjectRemoveKey(virJSONValue *object,
                            const char *key,
                            virJSONValue **value)
{
    size_t i;

    if (value)
        *value = NULL;

    if (object->type != VIR_JSON_TYPE_OBJECT)
        return -1;

    for (i = 0; i < object->data.object.npairs; i++) {
        if (STREQ(object->data.object.pairs[i].key, key)) {
            if (value) {
                *value = g_steal_pointer(&object->data.object.pairs[i].value);
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


virJSONValue *
virJSONValueObjectGetValue(virJSONValue *object,
                           unsigned int n)
{
    if (object->type != VIR_JSON_TYPE_OBJECT)
        return NULL;

    if (n >= object->data.object.npairs)
        return NULL;

    return object->data.object.pairs[n].value;
}


bool
virJSONValueIsObject(virJSONValue *object)
{
    if (object)
        return object->type == VIR_JSON_TYPE_OBJECT;
    else
        return false;
}


bool
virJSONValueIsArray(virJSONValue *array)
{
    return array->type == VIR_JSON_TYPE_ARRAY;
}


size_t
virJSONValueArraySize(const virJSONValue *array)
{
    return array->data.array.nvalues;
}


virJSONValue *
virJSONValueArrayGet(virJSONValue *array,
                     unsigned int element)
{
    if (array->type != VIR_JSON_TYPE_ARRAY)
        return NULL;

    if (element >= array->data.array.nvalues)
        return NULL;

    return array->data.array.values[element];
}


virJSONValue *
virJSONValueArraySteal(virJSONValue *array,
                       unsigned int element)
{
    virJSONValue *ret = NULL;

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
virJSONValueArrayForeachSteal(virJSONValue *array,
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
virJSONValueGetString(virJSONValue *string)
{
    if (string->type != VIR_JSON_TYPE_STRING)
        return NULL;

    return string->data.string;
}


const char *
virJSONValueGetNumberString(virJSONValue *number)
{
    if (number->type != VIR_JSON_TYPE_NUMBER)
        return NULL;

    return number->data.number;
}


int
virJSONValueGetNumberInt(virJSONValue *number,
                         int *value)
{
    if (number->type != VIR_JSON_TYPE_NUMBER)
        return -1;

    return virStrToLong_i(number->data.number, NULL, 10, value);
}


int
virJSONValueGetNumberUint(virJSONValue *number,
                          unsigned int *value)
{
    if (number->type != VIR_JSON_TYPE_NUMBER)
        return -1;

    return virStrToLong_ui(number->data.number, NULL, 10, value);
}


int
virJSONValueGetNumberLong(virJSONValue *number,
                          long long *value)
{
    if (number->type != VIR_JSON_TYPE_NUMBER)
        return -1;

    return virStrToLong_ll(number->data.number, NULL, 10, value);
}


int
virJSONValueGetNumberUlong(virJSONValue *number,
                           unsigned long long *value)
{
    if (number->type != VIR_JSON_TYPE_NUMBER)
        return -1;

    return virStrToLong_ull(number->data.number, NULL, 10, value);
}


int
virJSONValueGetNumberDouble(virJSONValue *number,
                            double *value)
{
    if (number->type != VIR_JSON_TYPE_NUMBER)
        return -1;

    return virStrToDouble(number->data.number, NULL, value);
}


int
virJSONValueGetBoolean(virJSONValue *val,
                       bool *value)
{
    if (val->type != VIR_JSON_TYPE_BOOLEAN)
        return -1;

    *value = val->data.boolean;
    return 0;
}


const char *
virJSONValueObjectGetString(virJSONValue *object,
                            const char *key)
{
    virJSONValue *val = virJSONValueObjectGet(object, key);

    if (!val)
        return NULL;

    return virJSONValueGetString(val);
}


void
virJSONValueObjectReplaceValue(virJSONValue *object,
                               const char *key,
                               virJSONValue **newval)
{
    size_t i;

    if (object->type != VIR_JSON_TYPE_OBJECT ||
        !*newval)
        return;

    for (i = 0; i < object->data.object.npairs; i++) {
        if (STREQ(object->data.object.pairs[i].key, key)) {
            virJSONValueFree(object->data.object.pairs[i].value);
            object->data.object.pairs[i].value = g_steal_pointer(newval);
        }
    }
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
virJSONValueObjectGetStringOrNumber(virJSONValue *object,
                                    const char *key)
{
    virJSONValue *val = virJSONValueObjectGet(object, key);

    if (!val)
        return NULL;

    if (val->type == VIR_JSON_TYPE_STRING)
        return val->data.string;
    else if (val->type == VIR_JSON_TYPE_NUMBER)
        return val->data.number;

    return NULL;
}


int
virJSONValueObjectGetNumberInt(virJSONValue *object,
                               const char *key,
                               int *value)
{
    virJSONValue *val = virJSONValueObjectGet(object, key);

    if (!val)
        return -1;

    return virJSONValueGetNumberInt(val, value);
}


int
virJSONValueObjectGetNumberUint(virJSONValue *object,
                                const char *key,
                                unsigned int *value)
{
    virJSONValue *val = virJSONValueObjectGet(object, key);

    if (!val)
        return -1;

    return virJSONValueGetNumberUint(val, value);
}


int
virJSONValueObjectGetNumberLong(virJSONValue *object,
                                const char *key,
                                long long *value)
{
    virJSONValue *val = virJSONValueObjectGet(object, key);

    if (!val)
        return -1;

    return virJSONValueGetNumberLong(val, value);
}


int
virJSONValueObjectGetNumberUlong(virJSONValue *object,
                                 const char *key,
                                 unsigned long long *value)
{
    virJSONValue *val = virJSONValueObjectGet(object, key);

    if (!val)
        return -1;

    return virJSONValueGetNumberUlong(val, value);
}


int
virJSONValueObjectGetNumberDouble(virJSONValue *object,
                                  const char *key,
                                  double *value)
{
    virJSONValue *val = virJSONValueObjectGet(object, key);

    if (!val)
        return -1;

    return virJSONValueGetNumberDouble(val, value);
}


int
virJSONValueObjectGetBoolean(virJSONValue *object,
                             const char *key,
                             bool *value)
{
    virJSONValue *val = virJSONValueObjectGet(object, key);

    if (!val)
        return -1;

    return virJSONValueGetBoolean(val, value);
}


virJSONValue *
virJSONValueObjectGetObject(virJSONValue *object, const char *key)
{
    return virJSONValueObjectGetByType(object, key, VIR_JSON_TYPE_OBJECT);
}


virJSONValue *
virJSONValueObjectGetArray(virJSONValue *object, const char *key)
{
    return virJSONValueObjectGetByType(object, key, VIR_JSON_TYPE_ARRAY);
}


virJSONValue *
virJSONValueObjectStealArray(virJSONValue *object, const char *key)
{
    return virJSONValueObjectStealByType(object, key, VIR_JSON_TYPE_ARRAY);
}


virJSONValue *
virJSONValueObjectStealObject(virJSONValue *object,
                              const char *key)
{
    return virJSONValueObjectStealByType(object, key, VIR_JSON_TYPE_OBJECT);
}


/**
 * virJSONValueArrayToStringList:
 * @data: a JSON array containing strings to convert
 *
 * Converts @data a JSON array containing strings to a NULL-terminated string
 * list. @data must be a JSON array. In case @data is doesn't contain only
 * strings an error is reported.
 */
char **
virJSONValueArrayToStringList(virJSONValue *data)
{
    size_t n = virJSONValueArraySize(data);
    g_auto(GStrv) ret = g_new0(char *, n + 1);
    size_t i;

    for (i = 0; i < n; i++) {
        virJSONValue *child = virJSONValueArrayGet(data, i);

        if (!child ||
            !(ret[i] = g_strdup(virJSONValueGetString(child)))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("JSON string array contains non-string element"));
            return NULL;
        }
    }

    return g_steal_pointer(&ret);
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
virJSONValueObjectForeachKeyValue(virJSONValue *object,
                                  virJSONValueObjectIteratorFunc cb,
                                  void *opaque)
{
    size_t i;

    if (object->type != VIR_JSON_TYPE_OBJECT)
        return -1;

    for (i = 0; i < object->data.object.npairs; i++) {
        virJSONObjectPair *elem = object->data.object.pairs + i;

        if (cb(elem->key, elem->value, opaque) < 0)
            return -2;
    }

    return 0;
}


virJSONValue *
virJSONValueCopy(const virJSONValue *in)
{
    size_t i;
    virJSONValue *out = NULL;

    if (!in)
        return NULL;

    switch ((virJSONType) in->type) {
    case VIR_JSON_TYPE_OBJECT:
        out = virJSONValueNewObject();

        out->data.object.pairs = g_new0(virJSONObjectPair, in->data.object.npairs);
        out->data.object.npairs = in->data.object.npairs;

        for (i = 0; i < in->data.object.npairs; i++) {
            out->data.object.pairs[i].key = g_strdup(in->data.object.pairs[i].key);
            out->data.object.pairs[i].value = virJSONValueCopy(in->data.object.pairs[i].value);
        }
        break;
    case VIR_JSON_TYPE_ARRAY:
        out = virJSONValueNewArray();

        out->data.array.values = g_new0(virJSONValue *, in->data.array.nvalues);
        out->data.array.nvalues = in->data.array.nvalues;

        for (i = 0; i < in->data.array.nvalues; i++) {
            out->data.array.values[i] = virJSONValueCopy(in->data.array.values[i]);
        }
        break;

    /* No need to error out in the following cases */
    case VIR_JSON_TYPE_STRING:
        out = virJSONValueNewString(g_strdup(in->data.string));
        break;
    case VIR_JSON_TYPE_NUMBER:
        out = virJSONValueNewNumber(g_strdup(in->data.number));
        break;
    case VIR_JSON_TYPE_BOOLEAN:
        out = virJSONValueNewBoolean(in->data.boolean);
        break;
    case VIR_JSON_TYPE_NULL:
        out = virJSONValueNewNull();
        break;
    }

    return out;
}


#if WITH_YAJL
static int
virJSONParserInsertValue(virJSONParser *parser,
                         virJSONValue **value)
{
    if (!parser->head) {
        parser->head = g_steal_pointer(value);
    } else {
        virJSONParserState *state;
        if (!parser->nstate) {
            VIR_DEBUG("got a value to insert without a container");
            return -1;
        }

        state = &parser->state[parser->nstate-1];

        switch (state->value->type) {
        case VIR_JSON_TYPE_OBJECT: {
            if (!state->key) {
                VIR_DEBUG("missing key when inserting object value");
                return -1;
            }

            if (virJSONValueObjectAppend(state->value,
                                         state->key,
                                         value) < 0)
                return -1;

            VIR_FREE(state->key);
        }   break;

        case VIR_JSON_TYPE_ARRAY: {
            if (state->key) {
                VIR_DEBUG("unexpected key when inserting array value");
                return -1;
            }

            if (virJSONValueArrayAppend(state->value,
                                        value) < 0)
                return -1;
        }   break;

        default:
            VIR_DEBUG("unexpected value type, not a container");
            return -1;
        }
    }

    return 0;
}


static int
virJSONParserHandleNull(void *ctx)
{
    virJSONParser *parser = ctx;
    g_autoptr(virJSONValue) value = virJSONValueNewNull();

    VIR_DEBUG("parser=%p", parser);

    if (virJSONParserInsertValue(parser, &value) < 0)
        return 0;

    return 1;
}


static int
virJSONParserHandleBoolean(void *ctx,
                           int boolean_)
{
    virJSONParser *parser = ctx;
    g_autoptr(virJSONValue) value = virJSONValueNewBoolean(boolean_);

    VIR_DEBUG("parser=%p boolean=%d", parser, boolean_);

    if (virJSONParserInsertValue(parser, &value) < 0)
        return 0;

    return 1;
}


static int
virJSONParserHandleNumber(void *ctx,
                          const char *s,
                          size_t l)
{
    virJSONParser *parser = ctx;
    g_autoptr(virJSONValue) value = virJSONValueNewNumber(g_strndup(s, l));

    VIR_DEBUG("parser=%p str=%s", parser, value->data.number);

    if (virJSONParserInsertValue(parser, &value) < 0)
        return 0;

    return 1;
}


static int
virJSONParserHandleString(void *ctx,
                          const unsigned char *stringVal,
                          size_t stringLen)
{
    virJSONParser *parser = ctx;
    g_autoptr(virJSONValue) value = virJSONValueNewString(g_strndup((const char *)stringVal, stringLen));

    VIR_DEBUG("parser=%p str=%p", parser, (const char *)stringVal);

    if (virJSONParserInsertValue(parser, &value) < 0)
        return 0;

    return 1;
}


static int
virJSONParserHandleMapKey(void *ctx,
                          const unsigned char *stringVal,
                          size_t stringLen)
{
    virJSONParser *parser = ctx;
    virJSONParserState *state;

    VIR_DEBUG("parser=%p key=%p", parser, (const char *)stringVal);

    if (!parser->nstate)
        return 0;

    state = &parser->state[parser->nstate-1];
    if (state->key)
        return 0;
    state->key = g_strndup((const char *)stringVal, stringLen);
    return 1;
}


static int
virJSONParserHandleStartMap(void *ctx)
{
    virJSONParser *parser = ctx;
    g_autoptr(virJSONValue) value = virJSONValueNewObject();
    virJSONValue *tmp = value;

    VIR_DEBUG("parser=%p", parser);

    if (virJSONParserInsertValue(parser, &value) < 0)
        return 0;

    VIR_REALLOC_N(parser->state, parser->nstate + 1);

    parser->state[parser->nstate].value = tmp;
    parser->state[parser->nstate].key = NULL;
    parser->nstate++;

    return 1;
}


static int
virJSONParserHandleEndMap(void *ctx)
{
    virJSONParser *parser = ctx;
    virJSONParserState *state;

    VIR_DEBUG("parser=%p", parser);

    if (!parser->nstate)
        return 0;

    state = &(parser->state[parser->nstate-1]);
    if (state->key) {
        VIR_FREE(state->key);
        return 0;
    }

    VIR_DELETE_ELEMENT(parser->state, parser->nstate - 1, parser->nstate);

    return 1;
}


static int
virJSONParserHandleStartArray(void *ctx)
{
    virJSONParser *parser = ctx;
    g_autoptr(virJSONValue) value = virJSONValueNewArray();
    virJSONValue *tmp = value;

    VIR_DEBUG("parser=%p", parser);

    if (virJSONParserInsertValue(parser, &value) < 0)
        return 0;

    VIR_REALLOC_N(parser->state, parser->nstate + 1);

    parser->state[parser->nstate].value = tmp;
    parser->state[parser->nstate].key = NULL;
    parser->nstate++;

    return 1;
}


static int
virJSONParserHandleEndArray(void *ctx)
{
    virJSONParser *parser = ctx;
    virJSONParserState *state;

    VIR_DEBUG("parser=%p", parser);

    if (!(parser->nstate - parser->wrap))
        return 0;

    state = &(parser->state[parser->nstate-1]);
    if (state->key) {
        VIR_FREE(state->key);
        return 0;
    }

    VIR_DELETE_ELEMENT(parser->state, parser->nstate - 1, parser->nstate);

    return 1;
}


static const yajl_callbacks parserCallbacks = {
    virJSONParserHandleNull,
    virJSONParserHandleBoolean,
    NULL,
    NULL,
    virJSONParserHandleNumber,
    virJSONParserHandleString,
    virJSONParserHandleStartMap,
    virJSONParserHandleMapKey,
    virJSONParserHandleEndMap,
    virJSONParserHandleStartArray,
    virJSONParserHandleEndArray
};


/* XXX add an incremental streaming parser - yajl trivially supports it */
virJSONValue *
virJSONValueFromString(const char *jsonstring)
{
    yajl_handle hand;
    virJSONParser parser = { NULL, NULL, 0, 0 };
    virJSONValue *ret = NULL;
    int rc;
    size_t len = strlen(jsonstring);

    VIR_DEBUG("string=%s", jsonstring);

    hand = yajl_alloc(&parserCallbacks, NULL, &parser);
    if (!hand) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to create JSON parser"));
        return NULL;
    }

    /* Yajl 2 is nice enough to default to rejecting trailing garbage. */
    rc = yajl_parse(hand, (const unsigned char *)jsonstring, len);
    if (rc != yajl_status_ok ||
        yajl_complete_parse(hand) != yajl_status_ok) {
        unsigned char *errstr = yajl_get_error(hand, 1,
                                               (const unsigned char*)jsonstring,
                                               strlen(jsonstring));

        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot parse json %1$s: %2$s"),
                       jsonstring, (const char*) errstr);
        yajl_free_error(hand, errstr);
        virJSONValueFree(parser.head);
        goto cleanup;
    }

    if (parser.nstate != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot parse json %1$s: unterminated string/map/array"),
                       jsonstring);
        virJSONValueFree(parser.head);
    } else {
        ret = parser.head;
    }

 cleanup:
    yajl_free(hand);

    if (parser.nstate) {
        size_t i;
        for (i = 0; i < parser.nstate; i++)
            VIR_FREE(parser.state[i].key);
        VIR_FREE(parser.state);
    }

    VIR_DEBUG("result=%p", ret);

    return ret;
}


static int
virJSONValueToStringOne(virJSONValue *object,
                        yajl_gen g)
{
    size_t i;

    VIR_DEBUG("object=%p type=%d gen=%p", object, object->type, g);

    switch (object->type) {
    case VIR_JSON_TYPE_OBJECT:
        if (yajl_gen_map_open(g) != yajl_gen_status_ok)
            return -1;
        for (i = 0; i < object->data.object.npairs; i++) {
            if (yajl_gen_string(g,
                                (unsigned char *)object->data.object.pairs[i].key,
                                strlen(object->data.object.pairs[i].key))
                != yajl_gen_status_ok)
                return -1;
            if (virJSONValueToStringOne(object->data.object.pairs[i].value, g) < 0)
                return -1;
        }
        if (yajl_gen_map_close(g) != yajl_gen_status_ok)
            return -1;
        break;
    case VIR_JSON_TYPE_ARRAY:
        if (yajl_gen_array_open(g) != yajl_gen_status_ok)
            return -1;
        for (i = 0; i < object->data.array.nvalues; i++) {
            if (virJSONValueToStringOne(object->data.array.values[i], g) < 0)
                return -1;
        }
        if (yajl_gen_array_close(g) != yajl_gen_status_ok)
            return -1;
        break;

    case VIR_JSON_TYPE_STRING:
        if (yajl_gen_string(g, (unsigned char *)object->data.string,
                            strlen(object->data.string)) != yajl_gen_status_ok)
            return -1;
        break;

    case VIR_JSON_TYPE_NUMBER:
        if (yajl_gen_number(g, object->data.number,
                            strlen(object->data.number)) != yajl_gen_status_ok)
            return -1;
        break;

    case VIR_JSON_TYPE_BOOLEAN:
        if (yajl_gen_bool(g, object->data.boolean) != yajl_gen_status_ok)
            return -1;
        break;

    case VIR_JSON_TYPE_NULL:
        if (yajl_gen_null(g) != yajl_gen_status_ok)
            return -1;
        break;

    default:
        return -1;
    }

    return 0;
}


int
virJSONValueToBuffer(virJSONValue *object,
                     virBuffer *buf,
                     bool pretty)
{
    yajl_gen g;
    const unsigned char *str;
    size_t len;
    int ret = -1;

    VIR_DEBUG("object=%p", object);

    g = yajl_gen_alloc(NULL);
    if (!g) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to create JSON formatter"));
        goto cleanup;
    }
    yajl_gen_config(g, yajl_gen_beautify, pretty ? 1 : 0);
    yajl_gen_config(g, yajl_gen_indent_string, pretty ? "  " : " ");
    yajl_gen_config(g, yajl_gen_validate_utf8, 1);

    if (virJSONValueToStringOne(object, g) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to convert virJSONValue to yajl data"));
        goto cleanup;
    }

    if (yajl_gen_get_buf(g, &str, &len) != yajl_gen_status_ok) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                      _("failed to format JSON"));
        goto cleanup;
    }

    virBufferAdd(buf, (const char *) str, len);
    ret = 0;

 cleanup:
    yajl_gen_free(g);

    return ret;
}


#else
virJSONValue *
virJSONValueFromString(const char *jsonstring G_GNUC_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("No JSON parser implementation is available"));
    return NULL;
}


int
virJSONValueToBuffer(virJSONValue *object G_GNUC_UNUSED,
                     virBuffer *buf G_GNUC_UNUSED,
                     bool pretty G_GNUC_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("No JSON parser implementation is available"));
    return -1;
}
#endif


char *
virJSONValueToString(virJSONValue *object,
                     bool pretty)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    if (virJSONValueToBuffer(object, &buf, pretty) < 0)
        return NULL;

    return virBufferContentAndReset(&buf);
}


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
    g_autoptr(virJSONValue) json = NULL;

    if (!(json = virJSONValueFromString(jsonstr)))
        return NULL;

    return virJSONValueToString(json, pretty);
}


static virJSONValue *
virJSONValueObjectDeflattenKeys(virJSONValue *json);


static int
virJSONValueObjectDeflattenWorker(const char *key,
                                  virJSONValue *value,
                                  void *opaque)
{
    virJSONValue *retobj = opaque;
    g_autoptr(virJSONValue) newval = NULL;
    virJSONValue *existobj;
    g_auto(GStrv) tokens = NULL;

    /* non-nested keys only need to be copied */
    if (!strchr(key, '.')) {

        if (virJSONValueIsObject(value))
            newval = virJSONValueObjectDeflattenKeys(value);
        else
            newval = virJSONValueCopy(value);

        if (!newval)
            return -1;

        if (virJSONValueObjectHasKey(retobj, key)) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("can't deflatten colliding key '%1$s'"), key);
            return -1;
        }

        if (virJSONValueObjectAppend(retobj, key, &newval) < 0)
            return -1;

        return 0;
    }

    if (!(tokens = g_strsplit(key, ".", 2)))
        return -1;

    if (!tokens[0] || !tokens[1]) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("invalid nested value key '%1$s'"), key);
        return -1;
    }

    if (!(existobj = virJSONValueObjectGet(retobj, tokens[0]))) {
        virJSONValue *newobj = virJSONValueNewObject();
        existobj = newobj;

        if (virJSONValueObjectAppend(retobj, tokens[0], &newobj) < 0)
            return -1;

    } else {
        if (!virJSONValueIsObject(existobj)) {
            virReportError(VIR_ERR_INVALID_ARG, "%s",
                           _("mixing nested objects and values is forbidden in JSON deflattening"));
            return -1;
        }
    }

    return virJSONValueObjectDeflattenWorker(tokens[1], value, existobj);
}


static virJSONValue *
virJSONValueObjectDeflattenKeys(virJSONValue *json)
{
    g_autoptr(virJSONValue) deflattened = virJSONValueNewObject();

    if (virJSONValueObjectForeachKeyValue(json,
                                          virJSONValueObjectDeflattenWorker,
                                          deflattened) < 0)
        return NULL;

    return g_steal_pointer(&deflattened);
}


/**
 * virJSONValueObjectDeflattenArrays:
 *
 * Reconstruct JSON arrays from objects which only have sequential numeric
 * keys starting from 0.
 */
static void
virJSONValueObjectDeflattenArrays(virJSONValue *json)
{
    g_autofree virJSONValue **arraymembers = NULL;
    virJSONObject *obj;
    size_t i;

    if (!json ||
        json->type != VIR_JSON_TYPE_OBJECT)
        return;

    obj = &json->data.object;

    arraymembers = g_new0(virJSONValue *, obj->npairs);

    for (i = 0; i < obj->npairs; i++)
        virJSONValueObjectDeflattenArrays(obj->pairs[i].value);

    for (i = 0; i < obj->npairs; i++) {
        virJSONObjectPair *pair = obj->pairs + i;
        unsigned int keynum;

        if (virStrToLong_uip(pair->key, NULL, 10, &keynum) < 0)
            return;

        if (keynum >= obj->npairs)
            return;

        if (arraymembers[keynum])
            return;

        arraymembers[keynum] = pair->value;
    }

    for (i = 0; i < obj->npairs; i++)
        g_free(obj->pairs[i].key);

    g_free(json->data.object.pairs);

    i = obj->npairs;
    json->type = VIR_JSON_TYPE_ARRAY;
    json->data.array.nvalues = i;
    json->data.array.values = g_steal_pointer(&arraymembers);
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
virJSONValue *
virJSONValueObjectDeflatten(virJSONValue *json)
{
    virJSONValue *deflattened;

    if (!(deflattened = virJSONValueObjectDeflattenKeys(json)))
        return NULL;

    virJSONValueObjectDeflattenArrays(deflattened);

    return deflattened;
}
