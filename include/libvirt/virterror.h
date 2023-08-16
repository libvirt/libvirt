/*
 * virterror.h: Error handling interfaces for the libvirt library
 * Summary: error handling interfaces for the libvirt library
 * Description: Provides the interfaces of the libvirt library to handle
 *              errors raised while using the library.
 *
 * Copyright (C) 2006-2019 Red Hat, Inc.
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

#ifndef LIBVIRT_VIRTERROR_H
# define LIBVIRT_VIRTERROR_H

# include <libvirt/libvirt.h>

# ifdef __cplusplus
extern "C" {
# endif

/**
 * virErrorLevel:
 *
 * Indicates the level of an error
 *
 * Since: 0.1.0
 */
typedef enum {
    VIR_ERR_NONE = 0, /* (Since: 0.1.0) */
    VIR_ERR_WARNING = 1,        /* A simple warning (Since: 0.1.0) */
    VIR_ERR_ERROR = 2           /* An error (Since: 0.1.0) */
} virErrorLevel;

/**
 * virErrorDomain:
 *
 * Indicates where an error may have come from.  This should remain
 * stable, with all additions placed at the end since libvirt 0.1.0.
 *
 * Since: 0.1.0
 */
typedef enum {
    VIR_FROM_NONE = 0,          /* (Since: 0.1.0) */
    VIR_FROM_XEN = 1,           /* Error at Xen hypervisor layer (Since: 0.1.0) */
    VIR_FROM_XEND = 2,          /* Error at connection with xend daemon (Since: 0.1.0) */
    VIR_FROM_XENSTORE = 3,      /* Error at connection with xen store (Since: 0.1.0) */
    VIR_FROM_SEXPR = 4,         /* Error in the S-Expression code (Since: 0.1.0) */

    VIR_FROM_XML = 5,           /* Error in the XML code (Since: 0.1.0) */
    VIR_FROM_DOM = 6,           /* Error when operating on a domain (Since: 0.1.0) */
    VIR_FROM_RPC = 7,           /* Error in the XML-RPC code (Since: 0.1.1) */
    VIR_FROM_PROXY = 8,         /* Error in the proxy code; unused since
                                   0.8.6 (Since: 0.1.3) */
    VIR_FROM_CONF = 9,          /* Error in the configuration file handling (Since: 0.1.6) */

    VIR_FROM_QEMU = 10,         /* Error at the QEMU daemon (Since: 0.2.0) */
    VIR_FROM_NET = 11,          /* Error when operating on a network (Since: 0.2.0) */
    VIR_FROM_TEST = 12,         /* Error from test driver (Since: 0.2.3) */
    VIR_FROM_REMOTE = 13,       /* Error from remote driver (Since: 0.2.3) */
    VIR_FROM_OPENVZ = 14,       /* Error from OpenVZ driver (Since: 0.3.1) */

    VIR_FROM_XENXM = 15,        /* Error at Xen XM layer (Since: 0.4.1) */
    VIR_FROM_STATS_LINUX = 16,  /* Error in the Linux Stats code (Since: 0.4.1) */
    VIR_FROM_LXC = 17,          /* Error from Linux Container driver (Since: 0.4.2) */
    VIR_FROM_STORAGE = 18,      /* Error from storage driver (Since: 0.4.1) */
    VIR_FROM_NETWORK = 19,      /* Error from network config (Since: 0.4.6) */

    VIR_FROM_DOMAIN = 20,       /* Error from domain config (Since: 0.4.6) */
    VIR_FROM_UML = 21,          /* Error at the UML driver; unused since 5.0.0 (Since: 0.5.0) */
    VIR_FROM_NODEDEV = 22,      /* Error from node device monitor (Since: 0.5.0) */
    VIR_FROM_XEN_INOTIFY = 23,  /* Error from xen inotify layer (Since: 0.5.0) */
    VIR_FROM_SECURITY = 24,     /* Error from security framework (Since: 0.6.1) */

    VIR_FROM_VBOX = 25,         /* Error from VirtualBox driver (Since: 0.6.3) */
    VIR_FROM_INTERFACE = 26,    /* Error when operating on an interface (Since: 0.6.4) */
    VIR_FROM_ONE = 27,          /* The OpenNebula driver no longer exists.
                                   Retained for ABI/API compat only (Since: 0.6.4) */
    VIR_FROM_ESX = 28,          /* Error from ESX driver (Since: 0.7.0) */
    VIR_FROM_PHYP = 29,         /* Error from the phyp driver, unused since 6.0.0 (Since: 0.7.0) */

    VIR_FROM_SECRET = 30,       /* Error from secret storage (Since: 0.7.1) */
    VIR_FROM_CPU = 31,          /* Error from CPU driver (Since: 0.7.5) */
    VIR_FROM_XENAPI = 32,       /* Error from XenAPI (Since: 0.8.0) */
    VIR_FROM_NWFILTER = 33,     /* Error from network filter driver (Since: 0.8.0) */
    VIR_FROM_HOOK = 34,         /* Error from Synchronous hooks (Since: 0.8.0) */

    VIR_FROM_DOMAIN_SNAPSHOT = 35,/* Error from domain snapshot (Since: 0.8.0) */
    VIR_FROM_AUDIT = 36,        /* Error from auditing subsystem (Since: 0.8.5) */
    VIR_FROM_SYSINFO = 37,      /* Error from sysinfo/SMBIOS (Since: 0.8.6) */
    VIR_FROM_STREAMS = 38,      /* Error from I/O streams (Since: 0.8.6) */
    VIR_FROM_VMWARE = 39,       /* Error from VMware driver (Since: 0.8.7) */

    VIR_FROM_EVENT = 40,        /* Error from event loop impl (Since: 0.9.0) */
    VIR_FROM_LIBXL = 41,        /* Error from libxenlight driver (Since: 0.9.0) */
    VIR_FROM_LOCKING = 42,      /* Error from lock manager (Since: 0.9.2) */
    VIR_FROM_HYPERV = 43,       /* Error from Hyper-V driver (Since: 0.9.5) */
    VIR_FROM_CAPABILITIES = 44, /* Error from capabilities (Since: 0.9.8) */

    VIR_FROM_URI = 45,          /* Error from URI handling (Since: 0.9.11) */
    VIR_FROM_AUTH = 46,         /* Error from auth handling (Since: 0.9.11) */
    VIR_FROM_DBUS = 47,         /* Error from DBus (Since: 0.9.12) */
    VIR_FROM_PARALLELS = 48,    /* Error from Parallels (Since: 0.10.0) */
    VIR_FROM_DEVICE = 49,       /* Error from Device (Since: 0.10.0) */

    VIR_FROM_SSH = 50,          /* Error from libssh2 connection transport (Since: 0.10.0) */
    VIR_FROM_LOCKSPACE = 51,    /* Error from lockspace (Since: 1.0.0) */
    VIR_FROM_INITCTL = 52,      /* Error from initctl device communication (Since: 1.0.1) */
    VIR_FROM_IDENTITY = 53,     /* Error from identity code (Since: 1.0.4) */
    VIR_FROM_CGROUP = 54,       /* Error from cgroups (Since: 1.0.5) */

    VIR_FROM_ACCESS = 55,       /* Error from access control manager (Since: 1.1.0) */
    VIR_FROM_SYSTEMD = 56,      /* Error from systemd code (Since: 1.1.1) */
    VIR_FROM_BHYVE = 57,        /* Error from bhyve driver (Since: 1.2.2) */
    VIR_FROM_CRYPTO = 58,       /* Error from crypto code (Since: 1.2.3) */
    VIR_FROM_FIREWALL = 59,     /* Error from firewall (Since: 1.2.4) */

    VIR_FROM_POLKIT = 60,       /* Error from polkit code (Since: 1.2.9) */
    VIR_FROM_THREAD = 61,       /* Error from thread utils (Since: 1.2.14) */
    VIR_FROM_ADMIN = 62,        /* Error from admin backend (Since: 1.2.17) */
    VIR_FROM_LOGGING = 63,      /* Error from log manager (Since: 1.3.0) */
    VIR_FROM_XENXL = 64,        /* Error from Xen xl config code (Since: 1.3.2) */

    VIR_FROM_PERF = 65,         /* Error from perf (Since: 1.3.3) */
    VIR_FROM_LIBSSH = 66,       /* Error from libssh connection transport (Since: 2.5.0) */
    VIR_FROM_RESCTRL = 67,      /* Error from resource control (Since: 3.7.0) */
    VIR_FROM_FIREWALLD = 68,    /* Error from firewalld (Since: 5.1.0) */
    VIR_FROM_DOMAIN_CHECKPOINT = 69, /* Error from domain checkpoint (Since: 5.2.0) */

    VIR_FROM_TPM = 70,          /* Error from TPM (Since: 5.6.0) */
    VIR_FROM_BPF = 71,          /* Error from BPF code (Since: 5.10.0) */
    VIR_FROM_CH = 72,           /* Error from Cloud-Hypervisor driver (Since: 7.5.0) */

# ifdef VIR_ENUM_SENTINELS
    VIR_ERR_DOMAIN_LAST /* (Since: 0.9.13) */
# endif
} virErrorDomain;


/**
 * virError:
 *
 * A libvirt Error instance.
 *
 * The conn, dom and net fields should be used with extreme care.
 * Reference counts are not incremented so the underlying objects
 * may be deleted without notice after the error has been delivered.
 *
 * Since: 0.1.0
 */
typedef struct _virError virError;

/**
 * virErrorPtr:
 *
 * Since: 0.1.0
 */
typedef virError *virErrorPtr;
struct _virError {
    int         code;   /* The error code, a virErrorNumber */
    int         domain; /* What part of the library raised this error */
    char       *message;/* human-readable informative error message */
    virErrorLevel level;/* how consequent is the error */
    virConnectPtr conn VIR_DEPRECATED; /* connection if available, deprecated
                                          see note above */
    virDomainPtr dom VIR_DEPRECATED; /* domain if available, deprecated
                                        see note above */
    char       *str1;   /* extra string information */
    char       *str2;   /* extra string information */
    char       *str3;   /* extra string information */
    int         int1;   /* extra number information */
    int         int2;   /* extra number information */
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
 *
 * Since: 0.1.0
 */
typedef enum {
    VIR_ERR_OK = 0, /* (Since: 0.1.0) */
    VIR_ERR_INTERNAL_ERROR = 1,         /* internal error (Since: 0.1.0) */
    VIR_ERR_NO_MEMORY = 2,              /* memory allocation failure (Since: 0.1.0) */
    VIR_ERR_NO_SUPPORT = 3,             /* no support for this function (Since: 0.1.0) */
    VIR_ERR_UNKNOWN_HOST = 4,           /* could not resolve hostname (Since: 0.1.0) */
    VIR_ERR_NO_CONNECT = 5,             /* can't connect to hypervisor (Since: 0.1.0) */
    VIR_ERR_INVALID_CONN = 6,           /* invalid connection object (Since: 0.1.0) */
    VIR_ERR_INVALID_DOMAIN = 7,         /* invalid domain object (Since: 0.1.0) */
    VIR_ERR_INVALID_ARG = 8,            /* invalid function argument (Since: 0.1.0) */
    VIR_ERR_OPERATION_FAILED = 9,       /* a command to hypervisor failed (Since: 0.1.0) */
    VIR_ERR_GET_FAILED = 10,            /* a HTTP GET command to failed (Since: 0.1.0) */
    VIR_ERR_POST_FAILED = 11,           /* a HTTP POST command to failed (Since: 0.1.0) */
    VIR_ERR_HTTP_ERROR = 12,            /* unexpected HTTP error code (Since: 0.1.0) */
    VIR_ERR_SEXPR_SERIAL = 13,          /* failure to serialize an S-Expr (Since: 0.1.0) */
    VIR_ERR_NO_XEN = 14,                /* could not open Xen hypervisor
                                           control (Since: 0.1.0) */
    VIR_ERR_XEN_CALL = 15,              /* failure doing an hypervisor call (Since: 0.1.0) */
    VIR_ERR_OS_TYPE = 16,               /* unknown OS type (Since: 0.1.0) */
    VIR_ERR_NO_KERNEL = 17,             /* missing kernel information (Since: 0.1.0) */
    VIR_ERR_NO_ROOT = 18,               /* missing root device information (Since: 0.1.0) */
    VIR_ERR_NO_SOURCE = 19,             /* missing source device information (Since: 0.1.0) */
    VIR_ERR_NO_TARGET = 20,             /* missing target device information (Since: 0.1.0) */
    VIR_ERR_NO_NAME = 21,               /* missing domain name information (Since: 0.1.0) */
    VIR_ERR_NO_OS = 22,                 /* missing domain OS information (Since: 0.1.0) */
    VIR_ERR_NO_DEVICE = 23,             /* missing domain devices information (Since: 0.1.0) */
    VIR_ERR_NO_XENSTORE = 24,           /* could not open Xen Store control (Since: 0.1.0) */
    VIR_ERR_DRIVER_FULL = 25,           /* too many drivers registered (Since: 0.1.0) */
    VIR_ERR_CALL_FAILED = 26,           /* not supported by the drivers
                                           (DEPRECATED) (Since: 0.1.0) */
    VIR_ERR_XML_ERROR = 27,             /* an XML description is not well
                                           formed or broken (Since: 0.1.1) */
    VIR_ERR_DOM_EXIST = 28,             /* the domain already exist (Since: 0.1.1) */
    VIR_ERR_OPERATION_DENIED = 29,      /* operation forbidden on read-only
                                           connections (Since: 0.1.4) */
    VIR_ERR_OPEN_FAILED = 30,           /* failed to open a conf file (Since: 0.1.6) */
    VIR_ERR_READ_FAILED = 31,           /* failed to read a conf file (Since: 0.1.6) */
    VIR_ERR_PARSE_FAILED = 32,          /* failed to parse a conf file (Since: 0.1.6) */
    VIR_ERR_CONF_SYNTAX = 33,           /* failed to parse the syntax of a
                                           conf file (Since: 0.1.6) */
    VIR_ERR_WRITE_FAILED = 34,          /* failed to write a conf file (Since: 0.1.6) */
    VIR_ERR_XML_DETAIL = 35,            /* detail of an XML error (Since: 0.1.9) */
    VIR_ERR_INVALID_NETWORK = 36,       /* invalid network object (Since: 0.2.0) */
    VIR_ERR_NETWORK_EXIST = 37,         /* the network already exist (Since: 0.2.0) */
    VIR_ERR_SYSTEM_ERROR = 38,          /* general system call failure (Since: 0.2.1) */
    VIR_ERR_RPC = 39,                   /* some sort of RPC error (Since: 0.2.3) */
    VIR_ERR_GNUTLS_ERROR = 40,          /* error from a GNUTLS call (Since: 0.2.3) */
    VIR_WAR_NO_NETWORK = 41,            /* failed to start network (Since: 0.2.3) */
    VIR_ERR_NO_DOMAIN = 42,             /* domain not found or unexpectedly
                                           disappeared (Since: 0.3.0) */
    VIR_ERR_NO_NETWORK = 43,            /* network not found (Since: 0.3.0) */
    VIR_ERR_INVALID_MAC = 44,           /* invalid MAC address (Since: 0.3.1) */
    VIR_ERR_AUTH_FAILED = 45,           /* authentication failed (Since: 0.4.1) */
    VIR_ERR_INVALID_STORAGE_POOL = 46,  /* invalid storage pool object (Since: 0.4.1) */
    VIR_ERR_INVALID_STORAGE_VOL = 47,   /* invalid storage vol object (Since: 0.4.1) */
    VIR_WAR_NO_STORAGE = 48,            /* failed to start storage (Since: 0.4.1) */
    VIR_ERR_NO_STORAGE_POOL = 49,       /* storage pool not found (Since: 0.4.1) */
    VIR_ERR_NO_STORAGE_VOL = 50,        /* storage volume not found (Since: 0.4.1) */
    VIR_WAR_NO_NODE = 51,               /* failed to start node driver (Since: 0.5.0) */
    VIR_ERR_INVALID_NODE_DEVICE = 52,   /* invalid node device object (Since: 0.5.0) */
    VIR_ERR_NO_NODE_DEVICE = 53,        /* node device not found (Since: 0.5.0) */
    VIR_ERR_NO_SECURITY_MODEL = 54,     /* security model not found (Since: 0.6.1) */
    VIR_ERR_OPERATION_INVALID = 55,     /* operation is not applicable at this
                                           time (Since: 0.6.4) */
    VIR_WAR_NO_INTERFACE = 56,          /* failed to start interface driver (Since: 0.6.4) */
    VIR_ERR_NO_INTERFACE = 57,          /* interface driver not running (Since: 0.6.4) */
    VIR_ERR_INVALID_INTERFACE = 58,     /* invalid interface object (Since: 0.6.4) */
    VIR_ERR_MULTIPLE_INTERFACES = 59,   /* more than one matching interface
                                           found (Since: 0.7.0) */
    VIR_WAR_NO_NWFILTER = 60,           /* failed to start nwfilter driver (Since: 0.8.0) */
    VIR_ERR_INVALID_NWFILTER = 61,      /* invalid nwfilter object (Since: 0.8.0) */
    VIR_ERR_NO_NWFILTER = 62,           /* nw filter pool not found (Since: 0.8.0) */
    VIR_ERR_BUILD_FIREWALL = 63,        /* nw filter pool not found (Since: 0.8.0) */
    VIR_WAR_NO_SECRET = 64,             /* failed to start secret storage (Since: 0.7.1) */
    VIR_ERR_INVALID_SECRET = 65,        /* invalid secret (Since: 0.7.1) */
    VIR_ERR_NO_SECRET = 66,             /* secret not found (Since: 0.7.1) */
    VIR_ERR_CONFIG_UNSUPPORTED = 67,    /* unsupported configuration
                                           construct (Since: 0.7.3) */
    VIR_ERR_OPERATION_TIMEOUT = 68,     /* timeout occurred during operation (Since: 0.7.3) */
    VIR_ERR_MIGRATE_PERSIST_FAILED = 69,/* a migration worked, but making the
                                           VM persist on the dest host failed (Since: 0.7.3) */
    VIR_ERR_HOOK_SCRIPT_FAILED = 70,    /* a synchronous hook script failed (Since: 0.8.0) */
    VIR_ERR_INVALID_DOMAIN_SNAPSHOT = 71,/* invalid domain snapshot (Since: 0.8.0) */
    VIR_ERR_NO_DOMAIN_SNAPSHOT = 72,    /* domain snapshot not found (Since: 0.8.0) */
    VIR_ERR_INVALID_STREAM = 73,        /* stream pointer not valid (Since: 0.9.0) */
    VIR_ERR_ARGUMENT_UNSUPPORTED = 74,  /* valid API use but unsupported by
                                           the given driver (Since: 0.9.4) */
    VIR_ERR_STORAGE_PROBE_FAILED = 75,  /* storage pool probe failed (Since: 0.9.5) */
    VIR_ERR_STORAGE_POOL_BUILT = 76,    /* storage pool already built (Since: 0.9.5) */
    VIR_ERR_SNAPSHOT_REVERT_RISKY = 77, /* force was not requested for a
                                           risky domain snapshot revert (Since: 0.9.7) */
    VIR_ERR_OPERATION_ABORTED = 78,     /* operation on a domain was
                                           canceled/aborted by user (Since: 0.9.9) */
    VIR_ERR_AUTH_CANCELLED = 79,        /* authentication cancelled (Since: 0.9.10) */
    VIR_ERR_NO_DOMAIN_METADATA = 80,    /* The metadata is not present (Since: 0.9.10) */
    VIR_ERR_MIGRATE_UNSAFE = 81,        /* Migration is not safe (Since: 0.9.11) */
    VIR_ERR_OVERFLOW = 82,              /* integer overflow (Since: 0.9.11) */
    VIR_ERR_BLOCK_COPY_ACTIVE = 83,     /* action prevented by block copy job (Since: 0.9.12) */
    VIR_ERR_OPERATION_UNSUPPORTED = 84, /* The requested operation is not
                                           supported (Since: 0.10.0) */
    VIR_ERR_SSH = 85,                   /* error in ssh transport driver (Since: 0.10.0) */
    VIR_ERR_AGENT_UNRESPONSIVE = 86,    /* guest agent is unresponsive,
                                           not running or not usable (Since: 0.10.0) */
    VIR_ERR_RESOURCE_BUSY = 87,         /* resource is already in use (Since: 1.0.0) */
    VIR_ERR_ACCESS_DENIED = 88,         /* operation on the object/resource
                                           was denied (Since: 1.1.0) */
    VIR_ERR_DBUS_SERVICE = 89,          /* error from a dbus service (Since: 1.1.1) */
    VIR_ERR_STORAGE_VOL_EXIST = 90,     /* the storage vol already exists (Since: 1.1.4) */
    VIR_ERR_CPU_INCOMPATIBLE = 91,      /* given CPU is incompatible with host CPU (Since: 1.2.6) */
    VIR_ERR_XML_INVALID_SCHEMA = 92,    /* XML document doesn't validate against schema (Since: 1.2.12) */
    VIR_ERR_MIGRATE_FINISH_OK = 93,     /* Finish API succeeded but it is expected to return NULL (Since: 1.2.18) */
    VIR_ERR_AUTH_UNAVAILABLE = 94,      /* authentication unavailable (Since: 1.3.3) */
    VIR_ERR_NO_SERVER = 95,             /* Server was not found (Since: 1.3.3) */
    VIR_ERR_NO_CLIENT = 96,             /* Client was not found (Since: 1.3.5) */
    VIR_ERR_AGENT_UNSYNCED = 97,        /* guest agent replies with wrong id
                                           to guest-sync command (DEPRECATED) (Since: 2.3.0) */
    VIR_ERR_LIBSSH = 98,                /* error in libssh transport driver (Since: 2.5.0) */
    VIR_ERR_DEVICE_MISSING = 99,        /* fail to find the desired device (Since: 4.1.0) */
    VIR_ERR_INVALID_NWFILTER_BINDING = 100,  /* invalid nwfilter binding (Since: 4.5.0) */
    VIR_ERR_NO_NWFILTER_BINDING = 101,  /* no nwfilter binding (Since: 4.5.0) */
    VIR_ERR_INVALID_DOMAIN_CHECKPOINT = 102, /* invalid domain checkpoint (Since: 5.2.0) */
    VIR_ERR_NO_DOMAIN_CHECKPOINT = 103, /* domain checkpoint not found (Since: 5.2.0) */
    VIR_ERR_NO_DOMAIN_BACKUP = 104,     /* domain backup job id not found (Since: 5.2.0) */
    VIR_ERR_INVALID_NETWORK_PORT = 105, /* invalid network port object (Since: 5.5.0) */
    VIR_ERR_NETWORK_PORT_EXIST = 106,   /* the network port already exist (Since: 5.5.0) */
    VIR_ERR_NO_NETWORK_PORT = 107,      /* network port not found (Since: 5.5.0) */
    VIR_ERR_NO_HOSTNAME = 108,          /* no domain's hostname found (Since: 6.1.0) */
    VIR_ERR_CHECKPOINT_INCONSISTENT = 109, /* checkpoint can't be used (Since: 6.10.0) */
    VIR_ERR_MULTIPLE_DOMAINS = 110,     /* more than one matching domain found (Since: 7.1.0) */
    VIR_ERR_NO_NETWORK_METADATA = 111,  /* Network metadata is not present (Since: 9.7.0) */

# ifdef VIR_ENUM_SENTINELS
    VIR_ERR_NUMBER_LAST /* (Since: 5.0.0) */
# endif
} virErrorNumber;

/**
 * virErrorFunc:
 * @userData:  user provided data for the error callback
 * @error:  the error being raised.
 *
 * Signature of a function to use when there is an error raised by the library.
 *
 * Since: 0.1.0
 */
typedef void (*virErrorFunc) (void *userData, virErrorPtr error);

/*
 * Errors can be handled as asynchronous callbacks or after the routine
 * failed. They can also be handled globally at the library level, or
 * at the connection level (which then has priority).
 */

virErrorPtr             virGetLastError         (void);
virErrorPtr             virSaveLastError        (void);
void                    virResetLastError       (void);
void                    virResetError           (virErrorPtr err);
void                    virFreeError            (virErrorPtr err);

int                     virGetLastErrorCode     (void);
int                     virGetLastErrorDomain   (void);
const char *            virGetLastErrorMessage  (void);

virErrorPtr             virConnGetLastError     (virConnectPtr conn);
void                    virConnResetLastError   (virConnectPtr conn);
int                     virCopyLastError        (virErrorPtr to);

void                    virDefaultErrorFunc     (virErrorPtr err);
void                    virSetErrorFunc         (void *userData,
                                                 virErrorFunc handler);
void                    virConnSetErrorFunc     (virConnectPtr conn,
                                                 void *userData,
                                                 virErrorFunc handler);
int                     virConnCopyLastError    (virConnectPtr conn,
                                                 virErrorPtr to);
# ifdef __cplusplus
}
# endif

#endif /* LIBVIRT_VIRTERROR_H */
