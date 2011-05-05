/*
 * json.h: JSON object parsing/formatting
 *
 * Copyright (C) 2009 Daniel P. Berrange
 * Copyright (C) 2009 Red Hat, Inc.
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


#ifndef __VIR_JSON_H_
# define __VIR_JSON_H_

# include "internal.h"


enum {
    VIR_JSON_TYPE_OBJECT,
    VIR_JSON_TYPE_ARRAY,
    VIR_JSON_TYPE_STRING,
    VIR_JSON_TYPE_NUMBER,
    VIR_JSON_TYPE_BOOLEAN,
    VIR_JSON_TYPE_NULL,
};

typedef struct _virJSONValue virJSONValue;
typedef virJSONValue *virJSONValuePtr;

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
    unsigned int npairs;
    virJSONObjectPairPtr pairs;
};

struct _virJSONArray {
    unsigned int nvalues;
    virJSONValuePtr *values;
};

struct _virJSONValue {
    int type;

    union {
        virJSONObject object;
        virJSONArray array;
        char *string;
        char *number; /* int/float/etc format is context defined so we can't parse it here :-( */
        int boolean;
    } data;
};

void virJSONValueFree(virJSONValuePtr value);

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

int virJSONValueObjectAppend(virJSONValuePtr object, const char *key, virJSONValuePtr value);
int virJSONValueArrayAppend(virJSONValuePtr object, virJSONValuePtr value);

int virJSONValueObjectHasKey(virJSONValuePtr object, const char *key);
virJSONValuePtr virJSONValueObjectGet(virJSONValuePtr object, const char *key);

int virJSONValueArraySize(virJSONValuePtr object);
virJSONValuePtr virJSONValueArrayGet(virJSONValuePtr object, unsigned int element);

const char *virJSONValueGetString(virJSONValuePtr object);
int virJSONValueGetNumberInt(virJSONValuePtr object, int *value);
int virJSONValueGetNumberUint(virJSONValuePtr object, unsigned int *value);
int virJSONValueGetNumberLong(virJSONValuePtr object, long long *value);
int virJSONValueGetNumberUlong(virJSONValuePtr object, unsigned long long *value);
int virJSONValueGetNumberDouble(virJSONValuePtr object, double *value);
int virJSONValueGetBoolean(virJSONValuePtr object, bool *value);
int virJSONValueIsNull(virJSONValuePtr object);

const char *virJSONValueObjectGetString(virJSONValuePtr object, const char *key);
int virJSONValueObjectGetNumberInt(virJSONValuePtr object, const char *key, int *value);
int virJSONValueObjectGetNumberUint(virJSONValuePtr object, const char *key, unsigned int *value);
int virJSONValueObjectGetNumberLong(virJSONValuePtr object, const char *key, long long *value);
int virJSONValueObjectGetNumberUlong(virJSONValuePtr object, const char *key, unsigned long long *value);
int virJSONValueObjectGetNumberDouble(virJSONValuePtr object, const char *key, double *value);
int virJSONValueObjectGetBoolean(virJSONValuePtr object, const char *key, bool *value);
int virJSONValueObjectIsNull(virJSONValuePtr object, const char *key);

int virJSONValueObjectAppendString(virJSONValuePtr object, const char *key, const char *value);
int virJSONValueObjectAppendNumberInt(virJSONValuePtr object, const char *key, int number);
int virJSONValueObjectAppendNumberUint(virJSONValuePtr object, const char *key, unsigned int number);
int virJSONValueObjectAppendNumberLong(virJSONValuePtr object, const char *key, long long number);
int virJSONValueObjectAppendNumberUlong(virJSONValuePtr object, const char *key, unsigned long long number);
int virJSONValueObjectAppendNumberDouble(virJSONValuePtr object, const char *key, double number);
int virJSONValueObjectAppendBoolean(virJSONValuePtr object, const char *key, int boolean);
int virJSONValueObjectAppendNull(virJSONValuePtr object, const char *key);

virJSONValuePtr virJSONValueFromString(const char *jsonstring);
char *virJSONValueToString(virJSONValuePtr object);

#endif /* __VIR_JSON_H_ */
