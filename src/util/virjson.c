/*
 * virjson.c: JSON object parsing/formatting
 *
 * Copyright (C) 2009-2010, 2012-2013 Red Hat, Inc.
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
#include "virutil.h"

#if WITH_YAJL
# include <yajl/yajl_gen.h>
# include <yajl/yajl_parse.h>

# ifdef WITH_YAJL2
#  define yajl_size_t size_t
# else
#  define yajl_size_t unsigned int
# endif

#endif

/* XXX fixme */
#define VIR_FROM_THIS VIR_FROM_NONE


typedef struct _virJSONParserState virJSONParserState;
typedef virJSONParserState *virJSONParserStatePtr;
struct _virJSONParserState {
    virJSONValuePtr value;
    char *key;
};

typedef struct _virJSONParser virJSONParser;
typedef virJSONParser *virJSONParserPtr;
struct _virJSONParser {
    virJSONValuePtr head;
    virJSONParserStatePtr state;
    unsigned int nstate;
};


void virJSONValueFree(virJSONValuePtr value)
{
    size_t i;
    if (!value || value->protect)
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


virJSONValuePtr virJSONValueNewString(const char *data)
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

virJSONValuePtr virJSONValueNewStringLen(const char *data, size_t length)
{
    virJSONValuePtr val;

    if (!data)
        return virJSONValueNewNull();

    if (VIR_ALLOC(val) < 0)
        return NULL;

    val->type = VIR_JSON_TYPE_STRING;
    if (VIR_STRNDUP(val->data.string, data, length) < 0) {
        VIR_FREE(val);
        return NULL;
    }

    return val;
}

static virJSONValuePtr virJSONValueNewNumber(const char *data)
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

virJSONValuePtr virJSONValueNewNumberInt(int data)
{
    virJSONValuePtr val = NULL;
    char *str;
    if (virAsprintf(&str, "%i", data) < 0)
        return NULL;
    val = virJSONValueNewNumber(str);
    VIR_FREE(str);
    return val;
}


virJSONValuePtr virJSONValueNewNumberUint(unsigned int data)
{
    virJSONValuePtr val = NULL;
    char *str;
    if (virAsprintf(&str, "%u", data) < 0)
        return NULL;
    val = virJSONValueNewNumber(str);
    VIR_FREE(str);
    return val;
}


virJSONValuePtr virJSONValueNewNumberLong(long long data)
{
    virJSONValuePtr val = NULL;
    char *str;
    if (virAsprintf(&str, "%lld", data) < 0)
        return NULL;
    val = virJSONValueNewNumber(str);
    VIR_FREE(str);
    return val;
}


virJSONValuePtr virJSONValueNewNumberUlong(unsigned long long data)
{
    virJSONValuePtr val = NULL;
    char *str;
    if (virAsprintf(&str, "%llu", data) < 0)
        return NULL;
    val = virJSONValueNewNumber(str);
    VIR_FREE(str);
    return val;
}


virJSONValuePtr virJSONValueNewNumberDouble(double data)
{
    virJSONValuePtr val = NULL;
    char *str;
    if (virDoubleToStr(&str, data) < 0)
        return NULL;
    val = virJSONValueNewNumber(str);
    VIR_FREE(str);
    return val;
}


virJSONValuePtr virJSONValueNewBoolean(int boolean_)
{
    virJSONValuePtr val;

    if (VIR_ALLOC(val) < 0)
        return NULL;

    val->type = VIR_JSON_TYPE_BOOLEAN;
    val->data.boolean = boolean_;

    return val;
}

virJSONValuePtr virJSONValueNewNull(void)
{
    virJSONValuePtr val;

    if (VIR_ALLOC(val) < 0)
        return NULL;

    val->type = VIR_JSON_TYPE_NULL;

    return val;
}

virJSONValuePtr virJSONValueNewArray(void)
{
    virJSONValuePtr val;

    if (VIR_ALLOC(val) < 0)
        return NULL;

    val->type = VIR_JSON_TYPE_ARRAY;

    return val;
}

virJSONValuePtr virJSONValueNewObject(void)
{
    virJSONValuePtr val;

    if (VIR_ALLOC(val) < 0)
        return NULL;

    val->type = VIR_JSON_TYPE_OBJECT;

    return val;
}

int virJSONValueObjectAppend(virJSONValuePtr object, const char *key, virJSONValuePtr value)
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


int virJSONValueObjectAppendString(virJSONValuePtr object, const char *key, const char *value)
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

int virJSONValueObjectAppendNumberInt(virJSONValuePtr object, const char *key, int number)
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


int virJSONValueObjectAppendNumberUint(virJSONValuePtr object, const char *key, unsigned int number)
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

int virJSONValueObjectAppendNumberLong(virJSONValuePtr object, const char *key, long long number)
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

int virJSONValueObjectAppendNumberUlong(virJSONValuePtr object, const char *key, unsigned long long number)
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

int virJSONValueObjectAppendNumberDouble(virJSONValuePtr object, const char *key, double number)
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

int virJSONValueObjectAppendBoolean(virJSONValuePtr object, const char *key, int boolean_)
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

int virJSONValueObjectAppendNull(virJSONValuePtr object, const char *key)
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


int virJSONValueArrayAppend(virJSONValuePtr array, virJSONValuePtr value)
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

int virJSONValueObjectHasKey(virJSONValuePtr object, const char *key)
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

virJSONValuePtr virJSONValueObjectGet(virJSONValuePtr object, const char *key)
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

int virJSONValueObjectKeysNumber(virJSONValuePtr object)
{
    if (object->type != VIR_JSON_TYPE_OBJECT)
        return -1;

    return object->data.object.npairs;
}

const char *virJSONValueObjectGetKey(virJSONValuePtr object, unsigned int n)
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
virJSONValueObjectRemoveKey(virJSONValuePtr object, const char *key,
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

virJSONValuePtr virJSONValueObjectGetValue(virJSONValuePtr object, unsigned int n)
{
    if (object->type != VIR_JSON_TYPE_OBJECT)
        return NULL;

    if (n >= object->data.object.npairs)
        return NULL;

    return object->data.object.pairs[n].value;
}

int virJSONValueArraySize(virJSONValuePtr array)
{
    if (array->type != VIR_JSON_TYPE_ARRAY)
        return -1;

    return array->data.array.nvalues;
}


virJSONValuePtr virJSONValueArrayGet(virJSONValuePtr array, unsigned int element)
{
    if (array->type != VIR_JSON_TYPE_ARRAY)
        return NULL;

    if (element >= array->data.array.nvalues)
        return NULL;

    return array->data.array.values[element];
}

const char *virJSONValueGetString(virJSONValuePtr string)
{
    if (string->type != VIR_JSON_TYPE_STRING)
        return NULL;

    return string->data.string;
}


int virJSONValueGetNumberInt(virJSONValuePtr number, int *value)
{
    if (number->type != VIR_JSON_TYPE_NUMBER)
        return -1;

    return virStrToLong_i(number->data.number, NULL, 10, value);
}

int virJSONValueGetNumberUint(virJSONValuePtr number, unsigned int *value)
{
    if (number->type != VIR_JSON_TYPE_NUMBER)
        return -1;

    return virStrToLong_ui(number->data.number, NULL, 10, value);
}

int virJSONValueGetNumberLong(virJSONValuePtr number, long long *value)
{
    if (number->type != VIR_JSON_TYPE_NUMBER)
        return -1;

    return virStrToLong_ll(number->data.number, NULL, 10, value);
}

int virJSONValueGetNumberUlong(virJSONValuePtr number, unsigned long long *value)
{
    if (number->type != VIR_JSON_TYPE_NUMBER)
        return -1;

    return virStrToLong_ull(number->data.number, NULL, 10, value);
}

int virJSONValueGetNumberDouble(virJSONValuePtr number, double *value)
{
    if (number->type != VIR_JSON_TYPE_NUMBER)
        return -1;

    return virStrToDouble(number->data.number, NULL, value);
}


int virJSONValueGetBoolean(virJSONValuePtr val, bool *value)
{
    if (val->type != VIR_JSON_TYPE_BOOLEAN)
        return -1;

    *value = val->data.boolean;
    return 0;
}


int virJSONValueIsNull(virJSONValuePtr val)
{
    if (val->type != VIR_JSON_TYPE_NULL)
        return 0;

    return 1;
}


const char *virJSONValueObjectGetString(virJSONValuePtr object, const char *key)
{
    virJSONValuePtr val;
    if (object->type != VIR_JSON_TYPE_OBJECT)
        return NULL;

    val = virJSONValueObjectGet(object, key);
    if (!val)
        return NULL;

    return virJSONValueGetString(val);
}


int virJSONValueObjectGetNumberInt(virJSONValuePtr object, const char *key, int *value)
{
    virJSONValuePtr val;
    if (object->type != VIR_JSON_TYPE_OBJECT)
        return -1;

    val = virJSONValueObjectGet(object, key);
    if (!val)
        return -1;

    return virJSONValueGetNumberInt(val, value);
}


int virJSONValueObjectGetNumberUint(virJSONValuePtr object, const char *key, unsigned int *value)
{
    virJSONValuePtr val;
    if (object->type != VIR_JSON_TYPE_OBJECT)
        return -1;

    val = virJSONValueObjectGet(object, key);
    if (!val)
        return -1;

    return virJSONValueGetNumberUint(val, value);
}


int virJSONValueObjectGetNumberLong(virJSONValuePtr object, const char *key, long long *value)
{
    virJSONValuePtr val;
    if (object->type != VIR_JSON_TYPE_OBJECT)
        return -1;

    val = virJSONValueObjectGet(object, key);
    if (!val)
        return -1;

    return virJSONValueGetNumberLong(val, value);
}


int virJSONValueObjectGetNumberUlong(virJSONValuePtr object, const char *key, unsigned long long *value)
{
    virJSONValuePtr val;
    if (object->type != VIR_JSON_TYPE_OBJECT)
        return -1;

    val = virJSONValueObjectGet(object, key);
    if (!val)
        return -1;

    return virJSONValueGetNumberUlong(val, value);
}


int virJSONValueObjectGetNumberDouble(virJSONValuePtr object, const char *key, double *value)
{
    virJSONValuePtr val;
    if (object->type != VIR_JSON_TYPE_OBJECT)
        return -1;

    val = virJSONValueObjectGet(object, key);
    if (!val)
        return -1;

    return virJSONValueGetNumberDouble(val, value);
}


int virJSONValueObjectGetBoolean(virJSONValuePtr object, const char *key, bool *value)
{
    virJSONValuePtr val;
    if (object->type != VIR_JSON_TYPE_OBJECT)
        return -1;

    val = virJSONValueObjectGet(object, key);
    if (!val)
        return -1;

    return virJSONValueGetBoolean(val, value);
}


int virJSONValueObjectIsNull(virJSONValuePtr object, const char *key)
{
    virJSONValuePtr val;
    if (object->type != VIR_JSON_TYPE_OBJECT)
        return -1;

    val = virJSONValueObjectGet(object, key);
    if (!val)
        return -1;

    return virJSONValueIsNull(val);
}


#if WITH_YAJL
static int virJSONParserInsertValue(virJSONParserPtr parser,
                                    virJSONValuePtr value)
{
    if (!parser->head) {
        parser->head = value;
    } else {
        virJSONParserStatePtr state;
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

static int virJSONParserHandleNull(void *ctx)
{
    virJSONParserPtr parser = ctx;
    virJSONValuePtr value = virJSONValueNewNull();

    VIR_DEBUG("parser=%p", parser);

    if (!value)
        return 0;

    if (virJSONParserInsertValue(parser, value) < 0) {
        virJSONValueFree(value);
        return 0;
    }

    return 1;
}

static int virJSONParserHandleBoolean(void *ctx, int boolean_)
{
    virJSONParserPtr parser = ctx;
    virJSONValuePtr value = virJSONValueNewBoolean(boolean_);

    VIR_DEBUG("parser=%p boolean=%d", parser, boolean_);

    if (!value)
        return 0;

    if (virJSONParserInsertValue(parser, value) < 0) {
        virJSONValueFree(value);
        return 0;
    }

    return 1;
}

static int virJSONParserHandleNumber(void *ctx,
                                     const char *s,
                                     yajl_size_t l)
{
    virJSONParserPtr parser = ctx;
    char *str;
    virJSONValuePtr value;

    if (VIR_STRNDUP(str, s, l) < 0)
        return -1;
    value = virJSONValueNewNumber(str);
    VIR_FREE(str);

    VIR_DEBUG("parser=%p str=%s", parser, str);

    if (!value)
        return 0;

    if (virJSONParserInsertValue(parser, value) < 0) {
        virJSONValueFree(value);
        return 0;
    }

    return 1;
}

static int virJSONParserHandleString(void *ctx,
                                     const unsigned char *stringVal,
                                     yajl_size_t stringLen)
{
    virJSONParserPtr parser = ctx;
    virJSONValuePtr value = virJSONValueNewStringLen((const char *)stringVal,
                                                     stringLen);

    VIR_DEBUG("parser=%p str=%p", parser, (const char *)stringVal);

    if (!value)
        return 0;

    if (virJSONParserInsertValue(parser, value) < 0) {
        virJSONValueFree(value);
        return 0;
    }

    return 1;
}

static int virJSONParserHandleMapKey(void *ctx,
                                     const unsigned char *stringVal,
                                     yajl_size_t stringLen)
{
    virJSONParserPtr parser = ctx;
    virJSONParserStatePtr state;

    VIR_DEBUG("parser=%p key=%p", parser, (const char *)stringVal);

    if (!parser->nstate)
        return 0;

    state = &parser->state[parser->nstate-1];
    if (state->key)
        return 0;
    if (VIR_STRNDUP(state->key, (const char *)stringVal, stringLen) < 0)
        return 0;
    return 1;
}

static int virJSONParserHandleStartMap(void *ctx)
{
    virJSONParserPtr parser = ctx;
    virJSONValuePtr value = virJSONValueNewObject();

    VIR_DEBUG("parser=%p", parser);

    if (!value)
        return 0;

    if (virJSONParserInsertValue(parser, value) < 0) {
        virJSONValueFree(value);
        return 0;
    }

    if (VIR_REALLOC_N(parser->state,
                      parser->nstate + 1) < 0) {
        return 0;
    }

    parser->state[parser->nstate].value = value;
    parser->state[parser->nstate].key = NULL;
    parser->nstate++;

    return 1;
}


static int virJSONParserHandleEndMap(void *ctx)
{
    virJSONParserPtr parser = ctx;
    virJSONParserStatePtr state;

    VIR_DEBUG("parser=%p", parser);

    if (!parser->nstate)
        return 0;

    state = &(parser->state[parser->nstate-1]);
    if (state->key) {
        VIR_FREE(state->key);
        return 0;
    }

    if (VIR_REALLOC_N(parser->state,
                      parser->nstate - 1) < 0)
        return 0;
    parser->nstate--;

    return 1;
}

static int virJSONParserHandleStartArray(void *ctx)
{
    virJSONParserPtr parser = ctx;
    virJSONValuePtr value = virJSONValueNewArray();

    VIR_DEBUG("parser=%p", parser);

    if (!value)
        return 0;

    if (virJSONParserInsertValue(parser, value) < 0) {
        virJSONValueFree(value);
        return 0;
    }

    if (VIR_REALLOC_N(parser->state,
                      parser->nstate + 1) < 0)
        return 0;

    parser->state[parser->nstate].value = value;
    parser->state[parser->nstate].key = NULL;
    parser->nstate++;

    return 1;
}

static int virJSONParserHandleEndArray(void *ctx)
{
    virJSONParserPtr parser = ctx;
    virJSONParserStatePtr state;

    VIR_DEBUG("parser=%p", parser);

    if (!parser->nstate)
        return 0;

    state = &(parser->state[parser->nstate-1]);
    if (state->key) {
        VIR_FREE(state->key);
        return 0;
    }

    if (VIR_REALLOC_N(parser->state,
                      parser->nstate - 1) < 0)
        return 0;
    parser->nstate--;

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
virJSONValuePtr virJSONValueFromString(const char *jsonstring)
{
    yajl_handle hand;
    virJSONParser parser = { NULL, NULL, 0 };
    virJSONValuePtr ret = NULL;
# ifndef WITH_YAJL2
    yajl_parser_config cfg = { 1, 1 };
# endif

    VIR_DEBUG("string=%s", jsonstring);

# ifdef WITH_YAJL2
    hand = yajl_alloc(&parserCallbacks, NULL, &parser);
    if (hand) {
        yajl_config(hand, yajl_allow_comments, 1);
        yajl_config(hand, yajl_dont_validate_strings, 0);
    }
# else
    hand = yajl_alloc(&parserCallbacks, &cfg, NULL, &parser);
# endif
    if (!hand) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to create JSON parser"));
        goto cleanup;
    }

    if (yajl_parse(hand,
                   (const unsigned char *)jsonstring,
                   strlen(jsonstring)) != yajl_status_ok) {
        unsigned char *errstr = yajl_get_error(hand, 1,
                                               (const unsigned char*)jsonstring,
                                               strlen(jsonstring));

        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot parse json %s: %s"),
                       jsonstring, (const char*) errstr);
        VIR_FREE(errstr);
        virJSONValueFree(parser.head);
        goto cleanup;
    }

    if (parser.nstate != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot parse json %s: unterminated string/map/array"),
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

    VIR_DEBUG("result=%p", parser.head);

    return ret;
}


static int virJSONValueToStringOne(virJSONValuePtr object,
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

char *virJSONValueToString(virJSONValuePtr object,
                           bool pretty)
{
    yajl_gen g;
    const unsigned char *str;
    char *ret = NULL;
    yajl_size_t len;
# ifndef WITH_YAJL2
    yajl_gen_config conf = { pretty ? 1 : 0, pretty ? "    " : " "};
# endif

    VIR_DEBUG("object=%p", object);

# ifdef WITH_YAJL2
    g = yajl_gen_alloc(NULL);
    if (g) {
        yajl_gen_config(g, yajl_gen_beautify, pretty ? 1 : 0);
        yajl_gen_config(g, yajl_gen_indent_string, pretty ? "    " : " ");
        yajl_gen_config(g, yajl_gen_validate_utf8, 1);
    }
# else
    g = yajl_gen_alloc(&conf, NULL);
# endif
    if (!g) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to create JSON formatter"));
        goto cleanup;
    }

    if (virJSONValueToStringOne(object, g) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if (yajl_gen_get_buf(g, &str, &len) != yajl_gen_status_ok) {
        virReportOOMError();
        goto cleanup;
    }

    ignore_value(VIR_STRDUP(ret, (const char *)str));

cleanup:
    yajl_gen_free(g);

    VIR_DEBUG("result=%s", NULLSTR(ret));

    return ret;
}


#else
virJSONValuePtr virJSONValueFromString(const char *jsonstring ATTRIBUTE_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("No JSON parser implementation is available"));
    return NULL;
}
char *virJSONValueToString(virJSONValuePtr object ATTRIBUTE_UNUSED,
                           bool pretty ATTRIBUTE_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("No JSON parser implementation is available"));
    return NULL;
}
#endif
