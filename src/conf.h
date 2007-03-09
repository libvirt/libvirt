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

virConfPtr      __virConfNew             (void);
virConfPtr	__virConfReadFile	(const char *filename);
virConfPtr	__virConfReadMem		(const char *memory,
					 int len);
int		__virConfFree		(virConfPtr conf);

virConfValuePtr	__virConfGetValue	(virConfPtr conf,
					 const char *setting);
int             __virConfSetValue        (virConfPtr conf,
					 const char *setting,
					 virConfValuePtr value);
int		__virConfWriteFile	(const char *filename,
					 virConfPtr conf);
int		__virConfWriteMem	(char *memory,
					 int *len,
					 virConfPtr conf);

#define virConfNew() (__virConfNew())
#define virConfReadFile(f) (__virConfReadFile((f)))
#define virConfReadMem(m,l) (__virConfReadMem((m),(l)))
#define virConfFree(c) (__virConfFree((c)))
#define virConfGetValue(c,s) (__virConfGetValue((c),(s)))
#define virConfSetValue(c,s,v) (__virConfSetValue((c),(s),(v)))
#define virConfWriteFile(f,c) (__virConfWriteFile((f),(c)))
#define virConfWriteMem(m,l,c) (__virConfWriteMem((m),(l),(c)))

#ifdef __cplusplus
}
#endif
#endif /* __VIR_CONF_H__ */
