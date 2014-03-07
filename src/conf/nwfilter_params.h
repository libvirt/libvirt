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
 *
 * Author: Stefan Berger <stefanb@us.ibm.com>
 */
#ifndef NWFILTER_PARAMS_H
# define NWFILTER_PARAMS_H

# include "virhash.h"
# include "virbuffer.h"
# include "virmacaddr.h"

enum virNWFilterVarValueType {
    NWFILTER_VALUE_TYPE_SIMPLE,
    NWFILTER_VALUE_TYPE_ARRAY,

    NWFILTER_VALUE_TYPE_LAST
};

typedef struct _virNWFilterVarValue virNWFilterVarValue;
typedef virNWFilterVarValue *virNWFilterVarValuePtr;
struct _virNWFilterVarValue {
    enum virNWFilterVarValueType valType;
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
int virNWFilterVarValueDelValue(virNWFilterVarValuePtr val, const char *value);

typedef struct _virNWFilterHashTable virNWFilterHashTable;
typedef virNWFilterHashTable *virNWFilterHashTablePtr;
struct _virNWFilterHashTable {
    virHashTablePtr hashTable;

    size_t nNames;
    char **names;
};


virNWFilterHashTablePtr virNWFilterParseParamAttributes(xmlNodePtr cur);
int virNWFilterFormatParamAttributes(virBufferPtr buf,
                                     virNWFilterHashTablePtr table,
                                     const char *filterref);

virNWFilterHashTablePtr virNWFilterHashTableCreate(int n);
void virNWFilterHashTableFree(virNWFilterHashTablePtr table);
int virNWFilterHashTablePut(virNWFilterHashTablePtr table,
                            const char *name,
                            virNWFilterVarValuePtr val,
                            int freeName);
void *virNWFilterHashTableRemoveEntry(virNWFilterHashTablePtr table,
                                      const char *name);
int virNWFilterHashTablePutAll(virNWFilterHashTablePtr src,
                               virNWFilterHashTablePtr dest);
bool virNWFilterHashTableEqual(virNWFilterHashTablePtr a,
                               virNWFilterHashTablePtr b);

# define VALID_VARNAME \
  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"

# define VALID_VARVALUE \
  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:"

# define NWFILTER_VARNAME_IP "IP"
# define NWFILTER_VARNAME_MAC "MAC"
# define NWFILTER_VARNAME_CTRL_IP_LEARNING "CTRL_IP_LEARNING"
# define NWFILTER_VARNAME_DHCPSERVER "DHCPSERVER"

enum virNWFilterVarAccessType {
    VIR_NWFILTER_VAR_ACCESS_ELEMENT = 0,
    VIR_NWFILTER_VAR_ACCESS_ITERATOR = 1,

    VIR_NWFILTER_VAR_ACCESS_LAST,
};

typedef struct _virNWFilterVarAccess virNWFilterVarAccess;
typedef virNWFilterVarAccess *virNWFilterVarAccessPtr;
struct  _virNWFilterVarAccess {
    enum virNWFilterVarAccessType accessType;
    union {
        struct {
            unsigned int index;
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
enum virNWFilterVarAccessType virNWFilterVarAccessGetType(
                                           const virNWFilterVarAccess *vap);
unsigned int virNWFilterVarAccessGetIterId(const virNWFilterVarAccess *vap);
unsigned int virNWFilterVarAccessGetIndex(const virNWFilterVarAccess *vap);
bool virNWFilterVarAccessIsAvailable(const virNWFilterVarAccess *vap,
                                     const virNWFilterHashTable *hash);

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
    virNWFilterHashTablePtr hashTable;
    size_t nIter;
    virNWFilterVarCombIterEntry iter[0];
};
virNWFilterVarCombIterPtr virNWFilterVarCombIterCreate(
                             virNWFilterHashTablePtr hash,
                             virNWFilterVarAccessPtr *vars,
                             size_t nVars);

void virNWFilterVarCombIterFree(virNWFilterVarCombIterPtr ci);
virNWFilterVarCombIterPtr virNWFilterVarCombIterNext(
                                virNWFilterVarCombIterPtr ci);
const char *virNWFilterVarCombIterGetVarValue(virNWFilterVarCombIterPtr ci,
                                              const virNWFilterVarAccess *);


#endif /* NWFILTER_PARAMS_H */
