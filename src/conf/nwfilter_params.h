/*
 * nwfilter_params.h: parsing and data maintenance of filter parameters
 *
 * Copyright (C) 2011-2013 Red Hat, Inc.
 * Copyright (C) 2010 IBM Corporation
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
 */

#ifndef LIBVIRT_NWFILTER_PARAMS_H
# define LIBVIRT_NWFILTER_PARAMS_H

# include "virhash.h"
# include "virbuffer.h"
# include "virmacaddr.h"
# include "virxml.h"

typedef enum {
    NWFILTER_VALUE_TYPE_SIMPLE,
    NWFILTER_VALUE_TYPE_ARRAY,

    NWFILTER_VALUE_TYPE_LAST
} virNWFilterVarValueType;

typedef struct _virNWFilterVarValue virNWFilterVarValue;
typedef virNWFilterVarValue *virNWFilterVarValuePtr;
struct _virNWFilterVarValue {
    virNWFilterVarValueType valType;
    union {
        struct {
            char *value;
        } simple;
        struct {
            char **values;
            size_t nValues;
        } array;
    } u;
};

virNWFilterVarValuePtr virNWFilterVarValueCreateSimple(char *);
virNWFilterVarValuePtr virNWFilterVarValueCreateSimpleCopyValue(const char *);
virNWFilterVarValuePtr virNWFilterVarValueCopy(const virNWFilterVarValue *);
void virNWFilterVarValueFree(virNWFilterVarValuePtr val);
const char *virNWFilterVarValueGetSimple(const virNWFilterVarValue *val);
const char *virNWFilterVarValueGetNthValue(const virNWFilterVarValue *val,
                                           unsigned int idx);
unsigned int virNWFilterVarValueGetCardinality(const virNWFilterVarValue *);
bool virNWFilterVarValueEqual(const virNWFilterVarValue *a,
                              const virNWFilterVarValue *b);
int virNWFilterVarValueAddValue(virNWFilterVarValuePtr val, char *value);
int virNWFilterVarValueAddValueCopy(virNWFilterVarValuePtr val, const char *value);
int virNWFilterVarValueDelValue(virNWFilterVarValuePtr val, const char *value);

virHashTablePtr virNWFilterParseParamAttributes(xmlNodePtr cur);
int virNWFilterFormatParamAttributes(virBufferPtr buf,
                                     virHashTablePtr table,
                                     const char *filterref);

virHashTablePtr virNWFilterHashTableCreate(int n);
int virNWFilterHashTablePutAll(virHashTablePtr src,
                               virHashTablePtr dest);
bool virNWFilterHashTableEqual(virHashTablePtr a,
                               virHashTablePtr b);

# define VALID_VARNAME \
  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"

# define VALID_VARVALUE \
  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:"

# define NWFILTER_VARNAME_IP "IP"
# define NWFILTER_VARNAME_MAC "MAC"
# define NWFILTER_VARNAME_CTRL_IP_LEARNING "CTRL_IP_LEARNING"
# define NWFILTER_VARNAME_DHCPSERVER "DHCPSERVER"

typedef enum {
    VIR_NWFILTER_VAR_ACCESS_ELEMENT = 0,
    VIR_NWFILTER_VAR_ACCESS_ITERATOR = 1,

    VIR_NWFILTER_VAR_ACCESS_LAST,
} virNWFilterVarAccessType;

typedef struct _virNWFilterVarAccess virNWFilterVarAccess;
typedef virNWFilterVarAccess *virNWFilterVarAccessPtr;
struct  _virNWFilterVarAccess {
    virNWFilterVarAccessType accessType;
    union {
        struct {
            unsigned int idx;
            unsigned int intIterId;
        } index;
        unsigned int iterId;
    } u;
    char *varName;
};

# define VIR_NWFILTER_MAX_ITERID   1000

void virNWFilterVarAccessFree(virNWFilterVarAccessPtr varAccess);
bool virNWFilterVarAccessEqual(const virNWFilterVarAccess *a,
                               const virNWFilterVarAccess *b);
virNWFilterVarAccessPtr virNWFilterVarAccessParse(const char *varAccess);
void virNWFilterVarAccessPrint(virNWFilterVarAccessPtr vap,
                               virBufferPtr buf);
const char *virNWFilterVarAccessGetVarName(const virNWFilterVarAccess *vap);
virNWFilterVarAccessType virNWFilterVarAccessGetType(
                                           const virNWFilterVarAccess *vap);
unsigned int virNWFilterVarAccessGetIterId(const virNWFilterVarAccess *vap);
unsigned int virNWFilterVarAccessGetIndex(const virNWFilterVarAccess *vap);
bool virNWFilterVarAccessIsAvailable(const virNWFilterVarAccess *vap,
                                     const virHashTable *hash);

typedef struct _virNWFilterVarCombIterEntry virNWFilterVarCombIterEntry;
typedef virNWFilterVarCombIterEntry *virNWFilterVarCombIterEntryPtr;
struct _virNWFilterVarCombIterEntry {
    unsigned int iterId;
    const char **varNames;
    size_t nVarNames;
    unsigned int maxValue;
    unsigned int curValue;
    unsigned int minValue;
};

typedef struct _virNWFilterVarCombIter virNWFilterVarCombIter;
typedef virNWFilterVarCombIter *virNWFilterVarCombIterPtr;
struct _virNWFilterVarCombIter {
    virHashTablePtr hashTable;
    size_t nIter;
    virNWFilterVarCombIterEntry iter[0];
};
virNWFilterVarCombIterPtr virNWFilterVarCombIterCreate(
                             virHashTablePtr hash,
                             virNWFilterVarAccessPtr *vars,
                             size_t nVars);

void virNWFilterVarCombIterFree(virNWFilterVarCombIterPtr ci);
virNWFilterVarCombIterPtr virNWFilterVarCombIterNext(
                                virNWFilterVarCombIterPtr ci);
const char *virNWFilterVarCombIterGetVarValue(virNWFilterVarCombIterPtr ci,
                                              const virNWFilterVarAccess *);


#endif /* LIBVIRT_NWFILTER_PARAMS_H */
