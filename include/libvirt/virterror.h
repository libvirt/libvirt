/*
 * virterror.h:
 * Summary: error handling interfaces for the libvirt library
 * Description: Provides the interfaces of the libvirt library to handle
 *              errors raised while using the library.
 *
 * Copy:  Copyright (C) 2006, 2010-2012 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Author: Daniel Veillard <veillard@redhat.com>
 */

#ifndef __VIR_VIRERR_H__
# define __VIR_VIRERR_H__

# include <libvirt/libvirt.h>

# ifdef __cplusplus
extern "C" {
# endif

/**
 * virErrorLevel:
 *
 * Indicates the level of an error
 */
typedef enum {
    VIR_ERR_NONE = 0,
    VIR_ERR_WARNING = 1,	/* A simple warning */
    VIR_ERR_ERROR = 2		/* An error */
} virErrorLevel;

/**
 * virErrorDomain:
 *
 * Indicates where an error may have come from.  This should remain
 * stable, with all additions placed at the end since libvirt 0.1.0.
 */
typedef enum {
    VIR_FROM_NONE = 0,
    VIR_FROM_XEN = 1,		/* Error at Xen hypervisor layer */
    VIR_FROM_XEND = 2,		/* Error at connection with xend daemon */
    VIR_FROM_XENSTORE = 3,	/* Error at connection with xen store */
    VIR_FROM_SEXPR = 4,		/* Error in the S-Expression code */
    VIR_FROM_XML = 5,		/* Error in the XML code */
    VIR_FROM_DOM = 6,		/* Error when operating on a domain */
    VIR_FROM_RPC = 7,		/* Error in the XML-RPC code */
    VIR_FROM_PROXY = 8,		/* Error in the proxy code; unused since
                                   0.8.6 */
    VIR_FROM_CONF = 9,		/* Error in the configuration file handling */
    VIR_FROM_QEMU = 10,		/* Error at the QEMU daemon */
    VIR_FROM_NET = 11,		/* Error when operating on a network */
    VIR_FROM_TEST = 12,		/* Error from test driver */
    VIR_FROM_REMOTE = 13,	/* Error from remote driver */
    VIR_FROM_OPENVZ = 14,	/* Error from OpenVZ driver */
    VIR_FROM_XENXM = 15,	/* Error at Xen XM layer */
    VIR_FROM_STATS_LINUX = 16,	/* Error in the Linux Stats code */
    VIR_FROM_LXC = 17,		/* Error from Linux Container driver */
    VIR_FROM_STORAGE = 18,	/* Error from storage driver */
    VIR_FROM_NETWORK = 19,	/* Error from network config */
    VIR_FROM_DOMAIN = 20,	/* Error from domain config */
    VIR_FROM_UML = 21,		/* Error at the UML driver */
    VIR_FROM_NODEDEV = 22,	/* Error from node device monitor */
    VIR_FROM_XEN_INOTIFY = 23,	/* Error from xen inotify layer */
    VIR_FROM_SECURITY = 24,	/* Error from security framework */
    VIR_FROM_VBOX = 25,		/* Error from VirtualBox driver */
    VIR_FROM_INTERFACE = 26,	/* Error when operating on an interface */
    VIR_FROM_ONE = 27,		/* The OpenNebula driver no longer exists.
                                   Retained for ABI/API compat only */
    VIR_FROM_ESX = 28,		/* Error from ESX driver */
    VIR_FROM_PHYP = 29,		/* Error from IBM power hypervisor */
    VIR_FROM_SECRET = 30,	/* Error from secret storage */
    VIR_FROM_CPU = 31,		/* Error from CPU driver */
    VIR_FROM_XENAPI = 32,	/* Error from XenAPI */
    VIR_FROM_NWFILTER = 33,	/* Error from network filter driver */
    VIR_FROM_HOOK = 34,		/* Error from Synchronous hooks */
    VIR_FROM_DOMAIN_SNAPSHOT = 35,/* Error from domain snapshot */
    VIR_FROM_AUDIT = 36,	/* Error from auditing subsystem */
    VIR_FROM_SYSINFO = 37,	/* Error from sysinfo/SMBIOS */
    VIR_FROM_STREAMS = 38,	/* Error from I/O streams */
    VIR_FROM_VMWARE = 39,	/* Error from VMware driver */
    VIR_FROM_EVENT = 40,	/* Error from event loop impl */
    VIR_FROM_LIBXL = 41,	/* Error from libxenlight driver */
    VIR_FROM_LOCKING = 42,	/* Error from lock manager */
    VIR_FROM_HYPERV = 43,	/* Error from Hyper-V driver */
    VIR_FROM_CAPABILITIES = 44, /* Error from capabilities */
    VIR_FROM_URI = 45,          /* Error from URI handling */
    VIR_FROM_AUTH = 46,         /* Error from auth handling */
} virErrorDomain;


/**
 * virError:
 *
 * A libvirt Error instance.
 *
 * The conn, dom and net fields should be used with extreme care.
 * Reference counts are not incremented so the underlying objects
 * may be deleted without notice after the error has been delivered.
 */

typedef struct _virError virError;
typedef virError *virErrorPtr;
struct _virError {
    int		code;	/* The error code, a virErrorNumber */
    int		domain;	/* What part of the library raised this error */
    char       *message;/* human-readable informative error message */
    virErrorLevel level;/* how consequent is the error */
    virConnectPtr conn VIR_DEPRECATED; /* connection if available, deprecated
                                          see note above */
    virDomainPtr dom VIR_DEPRECATED; /* domain if available, deprecated
                                        see note above */
    char       *str1;	/* extra string information */
    char       *str2;	/* extra string information */
    char       *str3;	/* extra string information */
    int		int1;	/* extra number information */
    int		int2;	/* extra number information */
    virNetworkPtr net VIR_DEPRECATED; /* network if available, deprecated
                                         see note above */
};

/**
 * virErrorNumber:
 *
 * The full list of errors the library can generate
 *
 * This list should remain stable, with all additions placed at the
 * end since libvirt 0.1.0.  There is one exception: values added
 * between libvirt 0.7.1 and libvirt 0.7.7 (VIR_WAR_NO_SECRET through
 * VIR_ERR_MIGRATE_PERSIST_FAILED) were inadvertently relocated by
 * four positions in 0.8.0.  If you suspect version mismatch between a
 * server and client, then you can decipher values as follows:
 *
 * switch (err.code) {
 * case 60:
 *     // no way to tell VIR_WAR_NO_SECRET apart from VIR_WAR_NO_NWFILTER,
 *     // but both are very similar warnings
 *     break;
 * case 61: case 62: case 63:
 *     if (err.domain != VIR_FROM_NWFILTER)
 *         err.code += 4;
 *     break;
 * case 64:
 *     if (err.domain == VIR_FROM_QEMU)
 *         err.code += 4;
 *     break;
 * case 65:
 *     if (err.domain == VIR_FROM_XEN)
 *         err.code += 4;
 *     break;
 * default:
 * }
 */
typedef enum {
    VIR_ERR_OK = 0,
    VIR_ERR_INTERNAL_ERROR = 1,		/* internal error */
    VIR_ERR_NO_MEMORY = 2,		/* memory allocation failure */
    VIR_ERR_NO_SUPPORT = 3,		/* no support for this function */
    VIR_ERR_UNKNOWN_HOST = 4,		/* could not resolve hostname */
    VIR_ERR_NO_CONNECT = 5,		/* can't connect to hypervisor */
    VIR_ERR_INVALID_CONN = 6,		/* invalid connection object */
    VIR_ERR_INVALID_DOMAIN = 7,		/* invalid domain object */
    VIR_ERR_INVALID_ARG = 8,		/* invalid function argument */
    VIR_ERR_OPERATION_FAILED = 9,	/* a command to hypervisor failed */
    VIR_ERR_GET_FAILED = 10,		/* a HTTP GET command to failed */
    VIR_ERR_POST_FAILED = 11,		/* a HTTP POST command to failed */
    VIR_ERR_HTTP_ERROR = 12,		/* unexpected HTTP error code */
    VIR_ERR_SEXPR_SERIAL = 13,		/* failure to serialize an S-Expr */
    VIR_ERR_NO_XEN = 14,		/* could not open Xen hypervisor
                                           control */
    VIR_ERR_XEN_CALL = 15,		/* failure doing an hypervisor call */
    VIR_ERR_OS_TYPE = 16,		/* unknown OS type */
    VIR_ERR_NO_KERNEL = 17,		/* missing kernel information */
    VIR_ERR_NO_ROOT = 18,		/* missing root device information */
    VIR_ERR_NO_SOURCE = 19,		/* missing source device information */
    VIR_ERR_NO_TARGET = 20,		/* missing target device information */
    VIR_ERR_NO_NAME = 21,		/* missing domain name information */
    VIR_ERR_NO_OS = 22,			/* missing domain OS information */
    VIR_ERR_NO_DEVICE = 23,		/* missing domain devices information */
    VIR_ERR_NO_XENSTORE = 24,		/* could not open Xen Store control */
    VIR_ERR_DRIVER_FULL = 25,		/* too many drivers registered */
    VIR_ERR_CALL_FAILED = 26,		/* not supported by the drivers
                                           (DEPRECATED) */
    VIR_ERR_XML_ERROR = 27,		/* an XML description is not well
                                           formed or broken */
    VIR_ERR_DOM_EXIST = 28,		/* the domain already exist */
    VIR_ERR_OPERATION_DENIED = 29,	/* operation forbidden on read-only
                                           connections */
    VIR_ERR_OPEN_FAILED = 30,		/* failed to open a conf file */
    VIR_ERR_READ_FAILED = 31,		/* failed to read a conf file */
    VIR_ERR_PARSE_FAILED = 32,		/* failed to parse a conf file */
    VIR_ERR_CONF_SYNTAX = 33,		/* failed to parse the syntax of a
                                           conf file */
    VIR_ERR_WRITE_FAILED = 34,		/* failed to write a conf file */
    VIR_ERR_XML_DETAIL = 35,		/* detail of an XML error */
    VIR_ERR_INVALID_NETWORK = 36,	/* invalid network object */
    VIR_ERR_NETWORK_EXIST = 37,		/* the network already exist */
    VIR_ERR_SYSTEM_ERROR = 38,		/* general system call failure */
    VIR_ERR_RPC = 39,			/* some sort of RPC error */
    VIR_ERR_GNUTLS_ERROR = 40,		/* error from a GNUTLS call */
    VIR_WAR_NO_NETWORK = 41,		/* failed to start network */
    VIR_ERR_NO_DOMAIN = 42,		/* domain not found or unexpectedly
                                           disappeared */
    VIR_ERR_NO_NETWORK = 43,		/* network not found */
    VIR_ERR_INVALID_MAC = 44,		/* invalid MAC address */
    VIR_ERR_AUTH_FAILED = 45,		/* authentication failed */
    VIR_ERR_INVALID_STORAGE_POOL = 46,	/* invalid storage pool object */
    VIR_ERR_INVALID_STORAGE_VOL = 47,	/* invalid storage vol object */
    VIR_WAR_NO_STORAGE = 48,		/* failed to start storage */
    VIR_ERR_NO_STORAGE_POOL = 49,	/* storage pool not found */
    VIR_ERR_NO_STORAGE_VOL = 50,	/* storage volume not found */
    VIR_WAR_NO_NODE = 51,		/* failed to start node driver */
    VIR_ERR_INVALID_NODE_DEVICE = 52,	/* invalid node device object */
    VIR_ERR_NO_NODE_DEVICE = 53,	/* node device not found */
    VIR_ERR_NO_SECURITY_MODEL = 54,	/* security model not found */
    VIR_ERR_OPERATION_INVALID = 55,	/* operation is not applicable at this
                                           time */
    VIR_WAR_NO_INTERFACE = 56,		/* failed to start interface driver */
    VIR_ERR_NO_INTERFACE = 57,		/* interface driver not running */
    VIR_ERR_INVALID_INTERFACE = 58,	/* invalid interface object */
    VIR_ERR_MULTIPLE_INTERFACES = 59,	/* more than one matching interface
                                           found */
    VIR_WAR_NO_NWFILTER = 60,		/* failed to start nwfilter driver */
    VIR_ERR_INVALID_NWFILTER = 61,	/* invalid nwfilter object */
    VIR_ERR_NO_NWFILTER = 62,		/* nw filter pool not found */
    VIR_ERR_BUILD_FIREWALL = 63,	/* nw filter pool not found */
    VIR_WAR_NO_SECRET = 64,		/* failed to start secret storage */
    VIR_ERR_INVALID_SECRET = 65,	/* invalid secret */
    VIR_ERR_NO_SECRET = 66,		/* secret not found */
    VIR_ERR_CONFIG_UNSUPPORTED = 67,	/* unsupported configuration
                                           construct */
    VIR_ERR_OPERATION_TIMEOUT = 68,	/* timeout occurred during operation */
    VIR_ERR_MIGRATE_PERSIST_FAILED = 69,/* a migration worked, but making the
                                           VM persist on the dest host failed */
    VIR_ERR_HOOK_SCRIPT_FAILED = 70,	/* a synchronous hook script failed */
    VIR_ERR_INVALID_DOMAIN_SNAPSHOT = 71,/* invalid domain snapshot */
    VIR_ERR_NO_DOMAIN_SNAPSHOT = 72,	/* domain snapshot not found */
    VIR_ERR_INVALID_STREAM = 73,	/* stream pointer not valid */
    VIR_ERR_ARGUMENT_UNSUPPORTED = 74,	/* valid API use but unsupported by
                                           the given driver */
    VIR_ERR_STORAGE_PROBE_FAILED = 75,	/* storage pool probe failed */
    VIR_ERR_STORAGE_POOL_BUILT = 76,	/* storage pool already built */
    VIR_ERR_SNAPSHOT_REVERT_RISKY = 77,	/* force was not requested for a
                                           risky domain snapshot revert */
    VIR_ERR_OPERATION_ABORTED = 78,     /* operation on a domain was
                                           canceled/aborted by user */
    VIR_ERR_AUTH_CANCELLED = 79,        /* authentication cancelled */
    VIR_ERR_NO_DOMAIN_METADATA = 80,    /* The metadata is not present */
    VIR_ERR_MIGRATE_UNSAFE = 81,        /* Migration is not safe */
    VIR_ERR_OVERFLOW = 82,              /* integer overflow */
} virErrorNumber;

/**
 * virErrorFunc:
 * @userData:  user provided data for the error callback
 * @error:  the error being raised.
 *
 * Signature of a function to use when there is an error raised by the library.
 */
typedef void (*virErrorFunc) (void *userData, virErrorPtr error);

/*
 * Errors can be handled as asynchronous callbacks or after the routine
 * failed. They can also be handled globally at the library level, or
 * at the connection level (which then has priority).
 */

virErrorPtr		virGetLastError		(void);
virErrorPtr		virSaveLastError	(void);
void			virResetLastError	(void);
void			virResetError		(virErrorPtr err);
void			virFreeError		(virErrorPtr err);

virErrorPtr		virConnGetLastError	(virConnectPtr conn);
void			virConnResetLastError	(virConnectPtr conn);
int			virCopyLastError	(virErrorPtr to);

void			virDefaultErrorFunc	(virErrorPtr err);
void			virSetErrorFunc		(void *userData,
                                                 virErrorFunc handler);
void			virConnSetErrorFunc	(virConnectPtr conn,
                                                 void *userData,
                                                 virErrorFunc handler);
int			virConnCopyLastError	(virConnectPtr conn,
                                                 virErrorPtr to);
# ifdef __cplusplus
}
# endif

#endif /* __VIR_VIRERR_H__ */
