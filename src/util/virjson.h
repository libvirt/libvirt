/*
 * virjson.h: JSON object parsing/formatting
 *
 * Copyright (C) 2009, 2012-2015 Red Hat, Inc.
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

#pragma once

#include "internal.h"
#include "virbitmap.h"
#include "virbuffer.h"
#include "virautoclean.h"

#include <stdarg.h>


typedef enum {
    VIR_JSON_TYPE_OBJECT,
    VIR_JSON_TYPE_ARRAY,
    VIR_JSON_TYPE_STRING,
    VIR_JSON_TYPE_NUMBER,
    VIR_JSON_TYPE_BOOLEAN,
    VIR_JSON_TYPE_NULL,
} virJSONType;

typedef struct _virJSONValue virJSONValue;
typedef virJSONValue *virJSONValuePtr;

void virJSONValueFree(virJSONValuePtr value);
void virJSONValueHashFree(void *opaque, const void *name);

virJSONType virJSONValueGetType(const virJSONValue *value);

int virJSONValueObjectCreate(virJSONValuePtr *obj, ...)
    ATTRIBUTE_NONNULL(1) G_GNUC_NULL_TERMINATED;
int virJSONValueObjectCreateVArgs(virJSONValuePtr *obj, va_list args)
    ATTRIBUTE_NONNULL(1);
int virJSONValueObjectAdd(virJSONValuePtr obj, ...)
    ATTRIBUTE_NONNULL(1) G_GNUC_NULL_TERMINATED;
int virJSONValueObjectAddVArgs(virJSONValuePtr obj, va_list args)
    ATTRIBUTE_NONNULL(1);


virJSONValuePtr virJSONValueNewString(const char *data);
virJSONValuePtr virJSONValueNewStringLen(const char *data, size_t length);
virJSONValuePtr virJSONValueNewNumberInt(int data);
virJSONValuePtr virJSONValueNewNumberUint(unsigned int data);
virJSONValuePtr virJSONValueNewNumberLong(long long data);
virJSONValuePtr virJSONValueNewNumberUlong(unsigned long long data);
virJSONValuePtr virJSONValueNewNumberDouble(double data);
virJSONValuePtr virJSONValueNewBoolean(int boolean);
virJSONValuePtr virJSONValueNewNull(void);
virJSONValuePtr virJSONValueNewArray(void);
virJSONValuePtr virJSONValueNewObject(void);
virJSONValuePtr virJSONValueNewArrayFromBitmap(virBitmapPtr bitmap);

int virJSONValueObjectAppend(virJSONValuePtr object, const char *key, virJSONValuePtr value);
int virJSONValueArrayAppend(virJSONValuePtr object, virJSONValuePtr value);

int virJSONValueObjectHasKey(virJSONValuePtr object, const char *key);
virJSONValuePtr virJSONValueObjectGet(virJSONValuePtr object, const char *key);
virJSONValuePtr virJSONValueObjectGetByType(virJSONValuePtr object,
                                            const char *key, virJSONType type);

bool virJSONValueIsObject(virJSONValuePtr object);

bool virJSONValueIsArray(virJSONValuePtr array);
size_t virJSONValueArraySize(const virJSONValue *array);
virJSONValuePtr virJSONValueArrayGet(virJSONValuePtr object, unsigned int element);
virJSONValuePtr virJSONValueArraySteal(virJSONValuePtr object, unsigned int element);
typedef int (*virJSONArrayIteratorFunc)(size_t pos,
                                        virJSONValuePtr item,
                                        void *opaque);
int virJSONValueArrayForeachSteal(virJSONValuePtr array,
                                  virJSONArrayIteratorFunc cb,
                                  void *opaque);

int virJSONValueObjectKeysNumber(virJSONValuePtr object);
const char *virJSONValueObjectGetKey(virJSONValuePtr object, unsigned int n);
virJSONValuePtr virJSONValueObjectGetValue(virJSONValuePtr object, unsigned int n);

const char *virJSONValueGetString(virJSONValuePtr object);
const char *virJSONValueGetNumberString(virJSONValuePtr number);
int virJSONValueGetNumberInt(virJSONValuePtr object, int *value);
int virJSONValueGetNumberUint(virJSONValuePtr object, unsigned int *value);
int virJSONValueGetNumberLong(virJSONValuePtr object, long long *value);
int virJSONValueGetNumberUlong(virJSONValuePtr object, unsigned long long *value);
int virJSONValueGetNumberDouble(virJSONValuePtr object, double *value);
int virJSONValueGetBoolean(virJSONValuePtr object, bool *value);
int virJSONValueGetArrayAsBitmap(const virJSONValue *val, virBitmapPtr *bitmap)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);
bool virJSONValueIsNull(virJSONValuePtr object);
virJSONValuePtr virJSONValueObjectGetObject(virJSONValuePtr object,
                                            const char *key);
virJSONValuePtr virJSONValueObjectGetArray(virJSONValuePtr object,
                                           const char *key);
virJSONValuePtr virJSONValueObjectStealArray(virJSONValuePtr object,
                                             const char *key);
virJSONValuePtr virJSONValueObjectStealObject(virJSONValuePtr object,
                                              const char *key);

const char *virJSONValueObjectGetString(virJSONValuePtr object, const char *key);
const char *virJSONValueObjectGetStringOrNumber(virJSONValuePtr object, const char *key);
int virJSONValueObjectGetNumberInt(virJSONValuePtr object, const char *key, int *value);
int virJSONValueObjectGetNumberUint(virJSONValuePtr object, const char *key, unsigned int *value);
int virJSONValueObjectGetNumberLong(virJSONValuePtr object, const char *key, long long *value);
int virJSONValueObjectGetNumberUlong(virJSONValuePtr object, const char *key, unsigned long long *value);
int virJSONValueObjectGetNumberDouble(virJSONValuePtr object, const char *key, double *value);
int virJSONValueObjectGetBoolean(virJSONValuePtr object, const char *key, bool *value);
int virJSONValueObjectIsNull(virJSONValuePtr object, const char *key);

int virJSONValueObjectAppendString(virJSONValuePtr object, const char *key, const char *value);
int virJSONValueObjectPrependString(virJSONValuePtr object, const char *key, const char *value);
int virJSONValueObjectAppendNumberInt(virJSONValuePtr object, const char *key, int number);
int virJSONValueObjectAppendNumberUint(virJSONValuePtr object, const char *key, unsigned int number);
int virJSONValueObjectAppendNumberLong(virJSONValuePtr object, const char *key, long long number);
int virJSONValueObjectAppendNumberUlong(virJSONValuePtr object, const char *key, unsigned long long number);
int virJSONValueObjectAppendNumberDouble(virJSONValuePtr object, const char *key, double number);
int virJSONValueObjectAppendBoolean(virJSONValuePtr object, const char *key, int boolean);
int virJSONValueObjectAppendNull(virJSONValuePtr object, const char *key);

int virJSONValueObjectRemoveKey(virJSONValuePtr object, const char *key,
                                virJSONValuePtr *value)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int virJSONValueArrayAppendString(virJSONValuePtr object, const char *value);

virJSONValuePtr virJSONValueFromString(const char *jsonstring);
char *virJSONValueToString(virJSONValuePtr object,
                           bool pretty);
int virJSONValueToBuffer(virJSONValuePtr object,
                         virBufferPtr buf,
                         bool pretty)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) G_GNUC_WARN_UNUSED_RESULT;

typedef int (*virJSONValueObjectIteratorFunc)(const char *key,
                                              virJSONValuePtr value,
                                              void *opaque);

int virJSONValueObjectForeachKeyValue(virJSONValuePtr object,
                                      virJSONValueObjectIteratorFunc cb,
                                      void *opaque);

virJSONValuePtr virJSONValueCopy(const virJSONValue *in);

char *virJSONStringReformat(const char *jsonstr, bool pretty);

virJSONValuePtr virJSONValueObjectDeflatten(virJSONValuePtr json);

VIR_DEFINE_AUTOPTR_FUNC(virJSONValue, virJSONValueFree);
