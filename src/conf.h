/**
 * conf.h: parser for a subset of the Python encoded Xen configuration files
 *
 * Copyright (C) 2006 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Daniel Veillard <veillard@redhat.com>
 */

#ifndef __VIR_CONF_H__
#define __VIR_CONF_H__

#ifdef __cplusplus
extern "C" {
#endif

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

virConfPtr	virConfReadFile		(const char *filename);
virConfPtr	virConfReadMem		(const char *memory,
					 int len);
int		virConfFree		(virConfPtr conf);

virConfValuePtr	virConfGetValue		(virConfPtr conf,
					 const char *setting);
int		virConfWriteFile	(const char *filename,
					 virConfPtr conf);
int		virConfWriteMem		(char *memory,
					 int *len,
					 virConfPtr conf);

#ifdef __cplusplus
}
#endif
#endif /* __VIR_CONF_H__ */
