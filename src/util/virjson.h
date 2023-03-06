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
#include "virbuffer.h"

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

void
virJSONValueFree(virJSONValue *value);
void
virJSONValueHashFree(void *opaque);

virJSONType
virJSONValueGetType(const virJSONValue *value);

int
virJSONValueObjectAdd(virJSONValue **obj, ...)
    ATTRIBUTE_NONNULL(1) G_GNUC_NULL_TERMINATED;
int
virJSONValueObjectAddVArgs(virJSONValue **objptr,
                           va_list args)
    ATTRIBUTE_NONNULL(1);


virJSONValue *
virJSONValueNewString(char *data);
virJSONValue *
virJSONValueNewNumberInt(int data);
virJSONValue *
virJSONValueNewNumberUint(unsigned int data);
virJSONValue *
virJSONValueNewNumberLong(long long data);
virJSONValue *
virJSONValueNewNumberUlong(unsigned long long data);
virJSONValue *
virJSONValueNewNumberDouble(double data);
virJSONValue *
virJSONValueNewBoolean(int boolean);
virJSONValue *
virJSONValueNewNull(void);
virJSONValue *
virJSONValueNewArray(void);
virJSONValue *
virJSONValueNewObject(void);

int
virJSONValueObjectAppend(virJSONValue *object,
                         const char *key,
                         virJSONValue **value);
int
virJSONValueArrayAppend(virJSONValue *object,
                        virJSONValue **value);
int
virJSONValueArrayConcat(virJSONValue *a,
                        virJSONValue *c);

bool
virJSONValueObjectHasKey(virJSONValue *object,
                         const char *key);
virJSONValue *
virJSONValueObjectGet(virJSONValue *object,
                      const char *key);
virJSONValue *
virJSONValueObjectGetByType(virJSONValue *object,
                            const char *key,
                            virJSONType type);

bool
virJSONValueIsObject(virJSONValue *object);

bool
virJSONValueIsArray(virJSONValue *array);
size_t
virJSONValueArraySize(const virJSONValue *array);
virJSONValue *
virJSONValueArrayGet(virJSONValue *object,
                     unsigned int element);
virJSONValue *
virJSONValueArraySteal(virJSONValue *object,
                       unsigned int element);

typedef int (*virJSONArrayIteratorFunc)(size_t pos,
                                        virJSONValue *item,
                                        void *opaque);

int
virJSONValueArrayForeachSteal(virJSONValue *array,
                              virJSONArrayIteratorFunc cb,
                              void *opaque);

int
virJSONValueObjectKeysNumber(virJSONValue *object);
const char *
virJSONValueObjectGetKey(virJSONValue *object,
                         unsigned int n);
virJSONValue *
virJSONValueObjectGetValue(virJSONValue *object,
                           unsigned int n);

const char *
virJSONValueGetString(virJSONValue *object);
const char *
virJSONValueGetNumberString(virJSONValue *number);
int
virJSONValueGetNumberInt(virJSONValue *object,
                         int *value);
int
virJSONValueGetNumberUint(virJSONValue *object,
                          unsigned int *value);
int
virJSONValueGetNumberLong(virJSONValue *object,
                          long long *value);
int
virJSONValueGetNumberUlong(virJSONValue *object,
                           unsigned long long *value);
int
virJSONValueGetNumberDouble(virJSONValue *object,
                            double *value);
int
virJSONValueGetBoolean(virJSONValue *object,
                       bool *value);

virJSONValue *
virJSONValueObjectGetObject(virJSONValue *object,
                            const char *key);
virJSONValue *
virJSONValueObjectGetArray(virJSONValue *object,
                           const char *key);
virJSONValue *
virJSONValueObjectStealArray(virJSONValue *object,
                             const char *key);
virJSONValue *
virJSONValueObjectStealObject(virJSONValue *object,
                              const char *key);
const char *
virJSONValueObjectGetString(virJSONValue *object,
                            const char *key);
char **
virJSONValueArrayToStringList(virJSONValue *data);
const char *
virJSONValueObjectGetStringOrNumber(virJSONValue *object,
                                    const char *key);
int
virJSONValueObjectGetNumberInt(virJSONValue *object,
                               const char *key,
                               int *value);
int
virJSONValueObjectGetNumberUint(virJSONValue *object,
                                const char *key,
                                unsigned int *value);
int
virJSONValueObjectGetNumberLong(virJSONValue *object,
                                const char *key,
                                long long *value);
int
virJSONValueObjectGetNumberUlong(virJSONValue *object,
                                 const char *key,
                                 unsigned long long *value);
int
virJSONValueObjectGetNumberDouble(virJSONValue *object,
                                  const char *key,
                                  double *value);
int
virJSONValueObjectGetBoolean(virJSONValue *object,
                             const char *key,
                             bool *value);

int
virJSONValueObjectAppendString(virJSONValue *object,
                               const char *key,
                               const char *value);
int
virJSONValueObjectPrependString(virJSONValue *object,
                                const char *key,
                                const char *value);
int
virJSONValueObjectAppendNumberInt(virJSONValue *object,
                                  const char *key,
                                  int number);
int
virJSONValueObjectAppendNumberUint(virJSONValue *object,
                                   const char *key,
                                   unsigned int number);
int
virJSONValueObjectAppendNumberLong(virJSONValue *object,
                                   const char *key,
                                   long long number);
int
virJSONValueObjectAppendNumberUlong(virJSONValue *object,
                                    const char *key,
                                    unsigned long long number);
int
virJSONValueObjectAppendNumberDouble(virJSONValue *object,
                                     const char *key,
                                     double number);
int
virJSONValueObjectAppendBoolean(virJSONValue *object,
                                const char *key,
                                int boolean);
int
virJSONValueObjectAppendNull(virJSONValue *object,
                             const char *key);

int
virJSONValueObjectRemoveKey(virJSONValue *object,
                            const char *key,
                            virJSONValue **value)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

void
virJSONValueObjectReplaceValue(virJSONValue *object,
                               const char *key,
                               virJSONValue **newval)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);

int
virJSONValueArrayAppendString(virJSONValue *object,
                              const char *value);

virJSONValue *
virJSONValueFromString(const char *jsonstring);
char *
virJSONValueToString(virJSONValue *object,
                     bool pretty);
int
virJSONValueToBuffer(virJSONValue *object,
                     virBuffer *buf,
                     bool pretty)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) G_GNUC_WARN_UNUSED_RESULT;

typedef int (*virJSONValueObjectIteratorFunc)(const char *key,
                                              virJSONValue *value,
                                              void *opaque);

int
virJSONValueObjectForeachKeyValue(virJSONValue *object,
                                  virJSONValueObjectIteratorFunc cb,
                                  void *opaque);

virJSONValue *
virJSONValueCopy(const virJSONValue *in);

char *
virJSONStringReformat(const char *jsonstr,
                      bool pretty);

virJSONValue *
virJSONValueObjectDeflatten(virJSONValue *json);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virJSONValue, virJSONValueFree);
