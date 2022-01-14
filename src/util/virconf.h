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

#include "virenum.h"

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
struct _virConfValue {
    virConfType type;           /* the virConfType */
    virConfValue *next;       /* next element if in a list */
    long long  l;               /* very long integer */
    char *str;                  /* pointer to 0 terminated string */
    virConfValue *list;       /* list of a list */
};

/**
 * virConf *:
 * a pointer to a parsed configuration file
 */
typedef struct _virConf virConf;

typedef int (*virConfWalkCallback)(const char* name,
                                   virConfValue *value,
                                   void *opaque);

virConf *virConfNew(void);
virConf *virConfReadFile(const char *filename, unsigned int flags);
virConf *virConfReadString(const char *memory,
                             unsigned int flags);
int virConfFree(virConf *conf);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(virConf, virConfFree);
void virConfFreeValue(virConfValue *val);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(virConfValue, virConfFreeValue);
virConfValue *virConfGetValue(virConf *conf,
                                const char *setting);

virConfType virConfGetValueType(virConf *conf,
                                const char *setting);
int virConfGetValueString(virConf *conf,
                          const char *setting,
                          char **value);
int virConfGetValueStringList(virConf *conf,
                              const char *setting,
                              bool compatString,
                              char ***values);
int virConfGetValueBool(virConf *conf,
                        const char *setting,
                        bool *value);
int virConfGetValueInt(virConf *conf,
                       const char *setting,
                       int *value);
int virConfGetValueUInt(virConf *conf,
                        const char *setting,
                        unsigned int *value);
int virConfGetValueSizeT(virConf *conf,
                         const char *setting,
                         size_t *value);
int virConfGetValueSSizeT(virConf *conf,
                          const char *setting,
                          ssize_t *value);
int virConfGetValueLLong(virConf *conf,
                        const char *setting,
                        long long *value);
int virConfGetValueULLong(virConf *conf,
                          const char *setting,
                          unsigned long long *value);

int virConfSetValue(virConf *conf,
                    const char *setting,
                    virConfValue **value);
int virConfWalk(virConf *conf,
                virConfWalkCallback callback,
                void *opaque);
int virConfWriteFile(const char *filename,
                     virConf *conf);
int virConfWriteMem(char *memory,
                    int *len,
                    virConf *conf);
int virConfLoadConfig(virConf **conf, const char *name);
