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
 *
 * Daniel Veillard <veillard@redhat.com>
 */

#ifndef __VIR_CONF_H__
# define __VIR_CONF_H__

# include "virutil.h"

/**
 * virConfType:
 * one of the possible type for a value from the configuration file
 *
 * TODO: we probably need a float too.
 */
typedef enum {
    VIR_CONF_NONE = 0,      /* undefined */
    VIR_CONF_LONG,          /* a long int */
    VIR_CONF_ULONG,         /* an unsigned long int */
    VIR_CONF_STRING,        /* a string */
    VIR_CONF_LIST,          /* a list */
    VIR_CONF_LAST,          /* sentinel */
} virConfType;

VIR_ENUM_DECL(virConf)

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
    virConfType type;		/* the virConfType */
    virConfValuePtr next;	/* next element if in a list */
    long  l;			/* long integer */
    char *str;			/* pointer to 0 terminated string */
    virConfValuePtr list;	/* list of a list */
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
virConfPtr virConfReadMem(const char *memory,
                          int len, unsigned int flags);
int virConfFree(virConfPtr conf);
void virConfFreeValue(virConfValuePtr val);
virConfValuePtr virConfGetValue(virConfPtr conf,
                                const char *setting);
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

#endif /* __VIR_CONF_H__ */
