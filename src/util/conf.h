/**
 * conf.h: parser for a subset of the Python encoded Xen configuration files
 *
 * Copyright (C) 2006, 2007 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Daniel Veillard <veillard@redhat.com>
 */

#ifndef __VIR_CONF_H__
# define __VIR_CONF_H__

/**
 * virConfType:
 * one of the possible type for a value from the configuration file
 *
 * TODO: we probably need a float too.
 */
typedef enum {
    VIR_CONF_NONE = 0,		/* undefined */
    VIR_CONF_LONG = 1,		/* a long int */
    VIR_CONF_STRING = 2,	/* a string */
    VIR_CONF_LIST = 3		/* a list */
} virConfType;

typedef enum {
    VIR_CONF_FLAG_VMX_FORMAT = 1,  /* allow ':', '.' and '-' in names for compatibility
                                      with VMware VMX configuration file, but restrict
                                      allowed value types to string only */
} virConfFlags;

static inline const char *
virConfTypeName (virConfType t)
{
    switch (t) {
    case VIR_CONF_LONG:
        return "long";
    case VIR_CONF_STRING:
        return "string";
    case VIR_CONF_LIST:
        return "list";
    default:
        return "*unexpected*";
    }
}

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

virConfPtr      virConfNew             (void);
virConfPtr	virConfReadFile	(const char *filename, unsigned int flags);
virConfPtr	virConfReadMem		(const char *memory,
                                         int len, unsigned int flags);
int		virConfFree		(virConfPtr conf);
void            virConfFreeValue      (virConfValuePtr val);

virConfValuePtr	virConfGetValue	(virConfPtr conf,
                                         const char *setting);
int             virConfSetValue        (virConfPtr conf,
                                         const char *setting,
                                         virConfValuePtr value);
int		virConfWriteFile	(const char *filename,
                                         virConfPtr conf);
int		virConfWriteMem	(char *memory,
                                         int *len,
                                         virConfPtr conf);

#endif /* __VIR_CONF_H__ */
