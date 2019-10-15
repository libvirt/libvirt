/*
 * virconf.h: parser for a subset of the Python encoded Xen configuration files
 *
 * Copyright (C) 2006, 2007 Red Hat, Inc.
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

#pragma once

#include "virutil.h"
#include "virenum.h"
#include "virautoclean.h"

/**
 * virConfType:
 * one of the possible type for a value from the configuration file
 *
 * TODO: we probably need a float too.
 */
typedef enum {
    VIR_CONF_NONE = 0,      /* undefined */
    VIR_CONF_LLONG,         /* a long long int */
    VIR_CONF_ULLONG,        /* an unsigned long long int */
    VIR_CONF_STRING,        /* a string */
    VIR_CONF_LIST,          /* a list */
    VIR_CONF_LAST,          /* sentinel */
} virConfType;

VIR_ENUM_DECL(virConf);

typedef enum {
    VIR_CONF_FLAG_VMX_FORMAT = 1,  /* allow ':', '.' and '-' in names for compatibility
                                      with VMware VMX configuration file, but restrict
                                      allowed value types to string only */
    VIR_CONF_FLAG_LXC_FORMAT = 2,  /* allow '.' in names for compatibility with LXC
                                      configuration file, restricts allowed value types
                                      to string only and don't expect quotes for values */
} virConfFlags;

/**
 * virConfValue:
 * a value from the configuration file
 */
typedef struct _virConfValue virConfValue;
typedef virConfValue *virConfValuePtr;

struct _virConfValue {
    virConfType type;           /* the virConfType */
    virConfValuePtr next;       /* next element if in a list */
    long long  l;               /* very long integer */
    char *str;                  /* pointer to 0 terminated string */
    virConfValuePtr list;       /* list of a list */
};

/**
 * virConfPtr:
 * a pointer to a parsed configuration file
 */
typedef struct _virConf virConf;
typedef virConf *virConfPtr;

typedef int (*virConfWalkCallback)(const char* name,
                                   virConfValuePtr value,
                                   void *opaque);

virConfPtr virConfNew(void);
virConfPtr virConfReadFile(const char *filename, unsigned int flags);
virConfPtr virConfReadString(const char *memory,
                             unsigned int flags);
int virConfFree(virConfPtr conf);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(virConf, virConfFree);
void virConfFreeValue(virConfValuePtr val);
virConfValuePtr virConfGetValue(virConfPtr conf,
                                const char *setting);

virConfType virConfGetValueType(virConfPtr conf,
                                const char *setting);
int virConfGetValueString(virConfPtr conf,
                          const char *setting,
                          char **value);
int virConfGetValueStringList(virConfPtr conf,
                              const char *setting,
                              bool compatString,
                              char ***values);
int virConfGetValueBool(virConfPtr conf,
                        const char *setting,
                        bool *value);
int virConfGetValueInt(virConfPtr conf,
                       const char *setting,
                       int *value);
int virConfGetValueUInt(virConfPtr conf,
                        const char *setting,
                        unsigned int *value);
int virConfGetValueSizeT(virConfPtr conf,
                         const char *setting,
                         size_t *value);
int virConfGetValueSSizeT(virConfPtr conf,
                          const char *setting,
                          ssize_t *value);
int virConfGetValueLLong(virConfPtr conf,
                        const char *setting,
                        long long *value);
int virConfGetValueULLong(virConfPtr conf,
                          const char *setting,
                          unsigned long long *value);

int virConfSetValue(virConfPtr conf,
                    const char *setting,
                    virConfValuePtr value);
int virConfWalk(virConfPtr conf,
                virConfWalkCallback callback,
                void *opaque);
int virConfWriteFile(const char *filename,
                     virConfPtr conf);
int virConfWriteMem(char *memory,
                    int *len,
                    virConfPtr conf);
int virConfLoadConfig(virConfPtr *conf, const char *name);
