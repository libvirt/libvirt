/*
 * libvirt-domain.h
 * Summary: APIs for management of domains
 * Description: Provides APIs for the management of domains
 *
 * Copyright (C) 2006-2015 Red Hat, Inc.
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

#ifndef LIBVIRT_DOMAIN_H
# define LIBVIRT_DOMAIN_H

# ifndef __VIR_LIBVIRT_H_INCLUDES__
#  error "Don't include this file directly, only use libvirt/libvirt.h"
# endif


/**
 * virDomain:
 *
 * a virDomain is a private structure representing a domain.
 *
 * Since: 0.0.1
 */
typedef struct _virDomain virDomain;

/**
 * virDomainPtr:
 *
 * a virDomainPtr is pointer to a virDomain private structure, this is the
 * type used to reference a domain in the API.
 *
 * Since: 0.0.1
 */
typedef virDomain *virDomainPtr;

/**
 * virDomainState:
 *
 * A domain may be in different states at a given point in time
 *
 * Since: 0.0.1
 */
typedef enum {
    VIR_DOMAIN_NOSTATE = 0,     /* no state (Since: 0.0.1) */
    VIR_DOMAIN_RUNNING = 1,     /* the domain is running (Since: 0.0.1) */
    VIR_DOMAIN_BLOCKED = 2,     /* the domain is blocked on resource (Since: 0.0.1) */
    VIR_DOMAIN_PAUSED  = 3,     /* the domain is paused by user (Since: 0.0.1) */
    VIR_DOMAIN_SHUTDOWN= 4,     /* the domain is being shut down (Since: 0.0.1) */
    VIR_DOMAIN_SHUTOFF = 5,     /* the domain is shut off (Since: 0.0.1) */
    VIR_DOMAIN_CRASHED = 6,     /* the domain is crashed (Since: 0.0.2) */
    VIR_DOMAIN_PMSUSPENDED = 7, /* the domain is suspended by guest
                                   power management (Since: 0.9.11) */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_LAST
    /*
     * NB: this enum value will increase over time as new states are
     * added to the libvirt API. It reflects the last state supported
     * by this version of the libvirt API.
     *
     * Since: 0.9.5
     */
# endif
} virDomainState;

/**
 * virDomainNostateReason:
 *
 * Since: 0.9.2
 */
typedef enum {
    VIR_DOMAIN_NOSTATE_UNKNOWN = 0, /* (Since: 0.9.2) */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_NOSTATE_LAST /* (Since: 0.9.10) */
# endif
} virDomainNostateReason;

/**
 * virDomainRunningReason:
 *
 * Since: 0.9.2
 */
typedef enum {
    VIR_DOMAIN_RUNNING_UNKNOWN = 0,         /* (Since: 0.9.2) */
    VIR_DOMAIN_RUNNING_BOOTED = 1,          /* normal startup from boot (Since: 0.9.2) */
    VIR_DOMAIN_RUNNING_MIGRATED = 2,        /* migrated from another host (Since: 0.9.2) */
    VIR_DOMAIN_RUNNING_RESTORED = 3,        /* restored from a state file (Since: 0.9.2) */
    VIR_DOMAIN_RUNNING_FROM_SNAPSHOT = 4,   /* restored from snapshot (Since: 0.9.2) */
    VIR_DOMAIN_RUNNING_UNPAUSED = 5,        /* returned from paused state (Since: 0.9.2) */
    VIR_DOMAIN_RUNNING_MIGRATION_CANCELED = 6,  /* returned from migration (Since: 0.9.2) */
    VIR_DOMAIN_RUNNING_SAVE_CANCELED = 7,   /* returned from failed save process (Since: 0.9.2) */
    VIR_DOMAIN_RUNNING_WAKEUP = 8,          /* returned from pmsuspended due to
                                               wakeup event (Since: 0.9.11) */
    VIR_DOMAIN_RUNNING_CRASHED = 9,         /* resumed from crashed (Since: 1.1.1) */
    VIR_DOMAIN_RUNNING_POSTCOPY = 10,       /* running in post-copy migration mode (Since: 1.3.3) */
    VIR_DOMAIN_RUNNING_POSTCOPY_FAILED = 11, /* running in failed post-copy migration (Since: 8.5.0) */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_RUNNING_LAST /* (Since: 0.9.10) */
# endif
} virDomainRunningReason;

/**
 * virDomainBlockedReason:
 *
 * Since: 0.9.2
 */
typedef enum {
    VIR_DOMAIN_BLOCKED_UNKNOWN = 0,     /* the reason is unknown (Since: 0.9.2) */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_BLOCKED_LAST /* (Since: 0.9.10) */
# endif
} virDomainBlockedReason;

/**
 * virDomainPausedReason:
 *
 * Since: 0.9.2
 */
typedef enum {
    VIR_DOMAIN_PAUSED_UNKNOWN = 0,      /* the reason is unknown (Since: 0.9.2) */
    VIR_DOMAIN_PAUSED_USER = 1,         /* paused on user request (Since: 0.9.2) */
    VIR_DOMAIN_PAUSED_MIGRATION = 2,    /* paused for offline migration (Since: 0.9.2) */
    VIR_DOMAIN_PAUSED_SAVE = 3,         /* paused for save (Since: 0.9.2) */
    VIR_DOMAIN_PAUSED_DUMP = 4,         /* paused for offline core dump (Since: 0.9.2) */
    VIR_DOMAIN_PAUSED_IOERROR = 5,      /* paused due to a disk I/O error (Since: 0.9.2) */
    VIR_DOMAIN_PAUSED_WATCHDOG = 6,     /* paused due to a watchdog event (Since: 0.9.2) */
    VIR_DOMAIN_PAUSED_FROM_SNAPSHOT = 7, /* paused after restoring from snapshot (Since: 0.9.2) */
    VIR_DOMAIN_PAUSED_SHUTTING_DOWN = 8, /* paused during shutdown process (Since: 0.9.5) */
    VIR_DOMAIN_PAUSED_SNAPSHOT = 9,      /* paused while creating a snapshot (Since: 1.0.1) */
    VIR_DOMAIN_PAUSED_CRASHED = 10,     /* paused due to a guest crash (Since: 1.1.1) */
    VIR_DOMAIN_PAUSED_STARTING_UP = 11, /* the domain is being started (Since: 1.2.14) */
    VIR_DOMAIN_PAUSED_POSTCOPY = 12,    /* paused for post-copy migration (Since: 1.3.3) */
    VIR_DOMAIN_PAUSED_POSTCOPY_FAILED = 13, /* paused after failed post-copy (Since: 1.3.3) */
    VIR_DOMAIN_PAUSED_API_ERROR = 14,   /* Some APIs (e.g., migration, snapshot) internally need to suspend a domain. This paused state reason is used when resume operation at the end of such API fails. (Since: 9.2.0) */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_PAUSED_LAST /* (Since: 0.9.10) */
# endif
} virDomainPausedReason;

/**
 * virDomainShutdownReason:
 *
 * Since: 0.9.2
 */
typedef enum {
    VIR_DOMAIN_SHUTDOWN_UNKNOWN = 0,    /* the reason is unknown (Since: 0.9.2) */
    VIR_DOMAIN_SHUTDOWN_USER = 1,       /* shutting down on user request (Since: 0.9.2) */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_SHUTDOWN_LAST /* (Since: 0.9.10) */
# endif
} virDomainShutdownReason;

/**
 * virDomainShutoffReason:
 *
 * Since: 0.9.2
 */
typedef enum {
    VIR_DOMAIN_SHUTOFF_UNKNOWN = 0,     /* the reason is unknown (Since: 0.9.2) */
    VIR_DOMAIN_SHUTOFF_SHUTDOWN = 1,    /* normal shutdown (Since: 0.9.2) */
    VIR_DOMAIN_SHUTOFF_DESTROYED = 2,   /* forced poweroff (Since: 0.9.2) */
    VIR_DOMAIN_SHUTOFF_CRASHED = 3,     /* domain crashed (Since: 0.9.2) */
    VIR_DOMAIN_SHUTOFF_MIGRATED = 4,    /* migrated to another host (Since: 0.9.2) */
    VIR_DOMAIN_SHUTOFF_SAVED = 5,       /* saved to a file (Since: 0.9.2) */
    VIR_DOMAIN_SHUTOFF_FAILED = 6,      /* domain failed to start (Since: 0.9.2) */
    VIR_DOMAIN_SHUTOFF_FROM_SNAPSHOT = 7, /* restored from a snapshot which was
                                           * taken while domain was shutoff (Since: 0.9.2) */
    VIR_DOMAIN_SHUTOFF_DAEMON = 8,      /* daemon decides to kill domain
                                           during reconnection processing (Since: 4.10.0) */
# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_SHUTOFF_LAST /* (Since: 0.9.10) */
# endif
} virDomainShutoffReason;

/**
 * virDomainCrashedReason:
 *
 * Since: 0.9.2
 */
typedef enum {
    VIR_DOMAIN_CRASHED_UNKNOWN = 0,     /* crashed for unknown reason (Since: 0.9.2) */
    VIR_DOMAIN_CRASHED_PANICKED = 1,    /* domain panicked (Since: 1.1.1) */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_CRASHED_LAST /* (Since: 0.9.10) */
# endif
} virDomainCrashedReason;

/**
 * virDomainPMSuspendedReason:
 *
 * Since: 0.9.11
 */
typedef enum {
    VIR_DOMAIN_PMSUSPENDED_UNKNOWN = 0, /* (Since: 0.9.11) */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_PMSUSPENDED_LAST /* (Since: 0.9.11) */
# endif
} virDomainPMSuspendedReason;

/**
 * virDomainPMSuspendedDiskReason:
 *
 * Since: 1.0.0
 */
typedef enum {
    VIR_DOMAIN_PMSUSPENDED_DISK_UNKNOWN = 0, /* (Since: 1.0.0) */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_PMSUSPENDED_DISK_LAST /* (Since: 1.0.0) */
# endif
} virDomainPMSuspendedDiskReason;

/**
 * virDomainControlState:
 *
 * Current state of a control interface to the domain.
 *
 * Since: 0.9.3
 */
typedef enum {
    VIR_DOMAIN_CONTROL_OK = 0,       /* operational, ready to accept commands (Since: 0.9.3) */
    VIR_DOMAIN_CONTROL_JOB = 1,      /* background job is running (can be
                                        monitored by virDomainGetJobInfo); only
                                        limited set of commands may be allowed (Since: 0.9.3) */
    VIR_DOMAIN_CONTROL_OCCUPIED = 2, /* occupied by a running command (Since: 0.9.3) */
    VIR_DOMAIN_CONTROL_ERROR = 3,    /* unusable, domain cannot be fully
                                        operated, possible reason is provided
                                        in the details field (Since: 0.9.3) */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_CONTROL_LAST /* (Since: 0.9.10) */
# endif
} virDomainControlState;

/**
 * virDomainControlErrorReason:
 *
 * Reason for the error state.
 *
 * Since: 1.2.14
 */
typedef enum {
    VIR_DOMAIN_CONTROL_ERROR_REASON_NONE = 0,     /* server didn't provide a
                                                     reason (Since: 1.2.14) */
    VIR_DOMAIN_CONTROL_ERROR_REASON_UNKNOWN = 1,  /* unknown reason for the
                                                     error (Since: 1.2.14) */
    VIR_DOMAIN_CONTROL_ERROR_REASON_MONITOR = 2,  /* monitor connection is
                                                     broken (Since: 1.2.14) */
    VIR_DOMAIN_CONTROL_ERROR_REASON_INTERNAL = 3, /* error caused due to
                                                     internal failure in libvirt (Since: 1.2.14)
                                                  */
# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_CONTROL_ERROR_REASON_LAST /* (Since: 1.2.14) */
# endif
} virDomainControlErrorReason;

/**
 * virDomainControlInfo:
 *
 * Structure filled in by virDomainGetControlInfo and providing details about
 * current state of control interface to a domain.
 *
 * Since: 0.9.3
 */
typedef struct _virDomainControlInfo virDomainControlInfo;
struct _virDomainControlInfo {
    unsigned int state;     /* control state, one of virDomainControlState */
    unsigned int details;   /* state details, currently 0 except for ERROR
                               state (one of virDomainControlErrorReason) */
    unsigned long long stateTime; /* for how long (in msec) control interface
                                     has been in current state (except for OK
                                     and ERROR states) */
};

/**
 * virDomainControlInfoPtr:
 *
 * Pointer to virDomainControlInfo structure.
 *
 * Since: 0.9.3
 */
typedef virDomainControlInfo *virDomainControlInfoPtr;

/**
 * virDomainModificationImpact:
 *
 * Several modification APIs take flags to determine whether a change
 * to the domain affects just the running instance, just the
 * persistent definition, or both at the same time.  The counterpart
 * query APIs also take the same flags to determine whether to query
 * the running instance or persistent definition, although both cannot
 * be queried at once.
 *
 * The use of VIR_DOMAIN_AFFECT_CURRENT will resolve to either
 * VIR_DOMAIN_AFFECT_LIVE or VIR_DOMAIN_AFFECT_CONFIG according to
 * current domain state. VIR_DOMAIN_AFFECT_LIVE requires a running
 * domain, and VIR_DOMAIN_AFFECT_CONFIG requires a persistent domain
 * (whether or not it is running).
 *
 * These enums should not conflict with those of virTypedParameterFlags.
 *
 * Since: 0.9.2
 */
typedef enum {
    VIR_DOMAIN_AFFECT_CURRENT = 0,      /* Affect current domain state. (Since: 0.9.2)  */
    VIR_DOMAIN_AFFECT_LIVE    = 1 << 0, /* Affect running domain state. (Since: 0.9.2)  */
    VIR_DOMAIN_AFFECT_CONFIG  = 1 << 1, /* Affect persistent domain state. (Since: 0.9.2) */
    /* 1 << 2 is reserved for virTypedParameterFlags */
} virDomainModificationImpact;

/**
 * virDomainInfo:
 *
 * a virDomainInfo is a structure filled by virDomainGetInfo() and extracting
 * runtime information for a given active Domain
 *
 * Since: 0.0.1
 */
typedef struct _virDomainInfo virDomainInfo;

struct _virDomainInfo {
    unsigned char state;        /* the running state, one of virDomainState */
    unsigned long maxMem;       /* the maximum memory in KBytes allowed */
    unsigned long memory;       /* the memory in KBytes used by the domain */
    unsigned short nrVirtCpu;   /* the number of virtual CPUs for the domain */
    unsigned long long cpuTime; /* the CPU time used in nanoseconds */
};

/**
 * virDomainInfoPtr:
 *
 * a virDomainInfoPtr is a pointer to a virDomainInfo structure.
 *
 * Since: 0.0.1
 */
typedef virDomainInfo *virDomainInfoPtr;

/**
 * virDomainCreateFlags:
 *
 * Flags OR'ed together to provide specific behaviour when creating a
 * Domain.
 *
 * Since: 0.0.1
 */
typedef enum {
    VIR_DOMAIN_NONE               = 0,      /* Default behavior (Since: 0.0.1) */
    VIR_DOMAIN_START_PAUSED       = 1 << 0, /* Launch guest in paused state (Since: 0.8.2) */
    VIR_DOMAIN_START_AUTODESTROY  = 1 << 1, /* Automatically kill guest when virConnectPtr is closed (Since: 0.9.3) */
    VIR_DOMAIN_START_BYPASS_CACHE = 1 << 2, /* Avoid file system cache pollution (Since: 0.9.4) */
    VIR_DOMAIN_START_FORCE_BOOT   = 1 << 3, /* Boot, discarding any managed save (Since: 0.9.5) */
    VIR_DOMAIN_START_VALIDATE     = 1 << 4, /* Validate the XML document against schema (Since: 1.2.12) */
    VIR_DOMAIN_START_RESET_NVRAM  = 1 << 5, /* Re-initialize NVRAM from template (Since: 8.1.0) */
} virDomainCreateFlags;


/* Management of scheduler parameters */

/**
 * VIR_DOMAIN_SCHEDULER_CPU_SHARES:
 *
 * Macro represents proportional weight of the scheduler used on the
 * host cpu, when using the posix scheduler, as a ullong.
 *
 * Since: 0.9.7
 */
# define VIR_DOMAIN_SCHEDULER_CPU_SHARES "cpu_shares"

/**
 * VIR_DOMAIN_SCHEDULER_GLOBAL_PERIOD:
 *
 * Macro represents the enforcement period for a quota, in microseconds,
 * for whole domain, when using the posix scheduler, as a ullong.
 *
 * Since: 1.3.3
 */
# define VIR_DOMAIN_SCHEDULER_GLOBAL_PERIOD "global_period"

/**
 * VIR_DOMAIN_SCHEDULER_GLOBAL_QUOTA:
 *
 * Macro represents the maximum bandwidth to be used within a period for
 * whole domain, when using the posix scheduler, as an llong.
 *
 * Since: 1.3.3
 */
# define VIR_DOMAIN_SCHEDULER_GLOBAL_QUOTA "global_quota"

/**
 * VIR_DOMAIN_SCHEDULER_VCPU_PERIOD:
 *
 * Macro represents the enforcement period for a quota, in microseconds,
 * for vcpus only, when using the posix scheduler, as a ullong.
 *
 * Since: 0.9.7
 */
# define VIR_DOMAIN_SCHEDULER_VCPU_PERIOD "vcpu_period"

/**
 * VIR_DOMAIN_SCHEDULER_VCPU_QUOTA:
 *
 * Macro represents the maximum bandwidth to be used within a period for
 * vcpus only, when using the posix scheduler, as an llong.
 *
 * Since: 0.9.7
 */
# define VIR_DOMAIN_SCHEDULER_VCPU_QUOTA "vcpu_quota"

/**
 * VIR_DOMAIN_SCHEDULER_EMULATOR_PERIOD:
 *
 * Macro represents the enforcement period for a quota in microseconds,
 * when using the posix scheduler, for all emulator activity not tied to
 * vcpus, as a ullong.
 *
 * Since: 0.10.0
 */
# define VIR_DOMAIN_SCHEDULER_EMULATOR_PERIOD "emulator_period"

/**
 * VIR_DOMAIN_SCHEDULER_EMULATOR_QUOTA:
 *
 * Macro represents the maximum bandwidth to be used within a period for
 * all emulator activity not tied to vcpus, when using the posix scheduler,
 * as an llong.
 *
 * Since: 0.10.0
 */
# define VIR_DOMAIN_SCHEDULER_EMULATOR_QUOTA "emulator_quota"

/**
 * VIR_DOMAIN_SCHEDULER_IOTHREAD_PERIOD:
 *
 * Macro represents the enforcement period for a quota, in microseconds,
 * for IOThreads only, when using the posix scheduler, as a ullong.
 *
 * Since: 2.2.0
 */
# define VIR_DOMAIN_SCHEDULER_IOTHREAD_PERIOD "iothread_period"

/**
 * VIR_DOMAIN_SCHEDULER_IOTHREAD_QUOTA:
 *
 * Macro represents the maximum bandwidth to be used within a period for
 * IOThreads only, when using the posix scheduler, as an llong.
 *
 * Since: 2.2.0
 */
# define VIR_DOMAIN_SCHEDULER_IOTHREAD_QUOTA "iothread_quota"

/**
 * VIR_DOMAIN_SCHEDULER_WEIGHT:
 *
 * Macro represents the relative weight,  when using the credit
 * scheduler, as a uint.
 *
 * Since: 0.9.7
 */
# define VIR_DOMAIN_SCHEDULER_WEIGHT "weight"

/**
 * VIR_DOMAIN_SCHEDULER_CAP:
 *
 * Macro represents the maximum scheduler cap, when using the credit
 * scheduler, as a uint.
 *
 * Since: 0.9.7
 */
# define VIR_DOMAIN_SCHEDULER_CAP "cap"

/**
 * VIR_DOMAIN_SCHEDULER_RESERVATION:
 *
 * Macro represents the scheduler reservation value, when using the
 * allocation scheduler, as an llong.
 *
 * Since: 0.9.7
 */
# define VIR_DOMAIN_SCHEDULER_RESERVATION "reservation"

/**
 * VIR_DOMAIN_SCHEDULER_LIMIT:
 *
 * Macro represents the scheduler limit value, when using the
 * allocation scheduler, as an llong.
 *
 * Since: 0.9.7
 */
# define VIR_DOMAIN_SCHEDULER_LIMIT "limit"

/**
 * VIR_DOMAIN_SCHEDULER_SHARES:
 *
 * Macro represents the scheduler shares value, when using the
 * allocation scheduler, as an int.
 *
 * Since: 0.9.7
 */
# define VIR_DOMAIN_SCHEDULER_SHARES "shares"

/*
 * Fetch scheduler parameters, caller allocates 'params' field of size 'nparams'
 */
int     virDomainGetSchedulerParameters (virDomainPtr domain,
                                         virTypedParameterPtr params,
                                         int *nparams);
int     virDomainGetSchedulerParametersFlags (virDomainPtr domain,
                                              virTypedParameterPtr params,
                                              int *nparams,
                                              unsigned int flags);

/*
 * Change scheduler parameters
 */
int     virDomainSetSchedulerParameters (virDomainPtr domain,
                                         virTypedParameterPtr params,
                                         int nparams);
int     virDomainSetSchedulerParametersFlags (virDomainPtr domain,
                                              virTypedParameterPtr params,
                                              int nparams,
                                              unsigned int flags);

/**
 * virDomainBlockStatsStruct:
 *
 * Block device stats for virDomainBlockStats.
 *
 * Hypervisors may return a field set to ((long long)-1) which indicates
 * that the hypervisor does not support that statistic.
 *
 * NB. Here 'long long' means 64 bit integer.
 *
 * Since: 0.3.3
 */
typedef struct _virDomainBlockStats virDomainBlockStatsStruct;

struct _virDomainBlockStats {
    long long rd_req; /* number of read requests */
    long long rd_bytes; /* number of read bytes */
    long long wr_req; /* number of write requests */
    long long wr_bytes; /* number of written bytes */
    long long errs;   /* In Xen this returns the mysterious 'oo_req'. */
};

/**
 * virDomainBlockStatsPtr:
 *
 * A pointer to a virDomainBlockStats structure
 *
 * Since: 0.3.2
 */
typedef virDomainBlockStatsStruct *virDomainBlockStatsPtr;


/**
 * VIR_DOMAIN_BLOCK_STATS_FIELD_LENGTH:
 *
 * Macro providing the field length of parameter names when using
 * virDomainBlockStatsFlags().
 *
 * Since: 0.9.5
 */
# define VIR_DOMAIN_BLOCK_STATS_FIELD_LENGTH VIR_TYPED_PARAM_FIELD_LENGTH

/**
 * VIR_DOMAIN_BLOCK_STATS_READ_BYTES:
 *
 * Macro represents the total number of read bytes of the
 * block device, as an llong.
 *
 * Since: 0.9.5
 */
# define VIR_DOMAIN_BLOCK_STATS_READ_BYTES "rd_bytes"

/**
 * VIR_DOMAIN_BLOCK_STATS_READ_REQ:
 *
 * Macro represents the total read requests of the
 * block device, as an llong.
 *
 * Since: 0.9.5
 */
# define VIR_DOMAIN_BLOCK_STATS_READ_REQ "rd_operations"

/**
 * VIR_DOMAIN_BLOCK_STATS_READ_TOTAL_TIMES:
 *
 * Macro represents the total time spend on cache reads in
 * nano-seconds of the block device, as an llong.
 *
 * Since: 0.9.5
 */
# define VIR_DOMAIN_BLOCK_STATS_READ_TOTAL_TIMES "rd_total_times"

/**
 * VIR_DOMAIN_BLOCK_STATS_WRITE_BYTES:
 *
 * Macro represents the total number of write bytes of the
 * block device, as an llong.
 *
 * Since: 0.9.5
 */
# define VIR_DOMAIN_BLOCK_STATS_WRITE_BYTES "wr_bytes"

/**
 * VIR_DOMAIN_BLOCK_STATS_WRITE_REQ:
 *
 * Macro represents the total write requests of the
 * block device, as an llong.
 *
 * Since: 0.9.5
 */
# define VIR_DOMAIN_BLOCK_STATS_WRITE_REQ "wr_operations"

/**
 * VIR_DOMAIN_BLOCK_STATS_WRITE_TOTAL_TIMES:
 *
 * Macro represents the total time spend on cache writes in
 * nano-seconds of the block device, as an llong.
 *
 * Since: 0.9.5
 */
# define VIR_DOMAIN_BLOCK_STATS_WRITE_TOTAL_TIMES "wr_total_times"

/**
 * VIR_DOMAIN_BLOCK_STATS_FLUSH_REQ:
 *
 * Macro represents the total flush requests of the
 * block device, as an llong.
 *
 * Since: 0.9.5
 */
# define VIR_DOMAIN_BLOCK_STATS_FLUSH_REQ "flush_operations"

/**
 * VIR_DOMAIN_BLOCK_STATS_FLUSH_TOTAL_TIMES:
 *
 * Macro represents the total time spend on cache flushing in
 * nano-seconds of the block device, as an llong.
 *
 * Since: 0.9.5
 */
# define VIR_DOMAIN_BLOCK_STATS_FLUSH_TOTAL_TIMES "flush_total_times"

/**
 * VIR_DOMAIN_BLOCK_STATS_ERRS:
 *
 * In Xen this returns the mysterious 'oo_req', as an llong.
 *
 * Since: 0.9.5
 */
# define VIR_DOMAIN_BLOCK_STATS_ERRS "errs"

/**
 * virDomainInterfaceStatsStruct:
 *
 * Network interface stats for virDomainInterfaceStats.
 *
 * Hypervisors may return a field set to ((long long)-1) which indicates
 * that the hypervisor does not support that statistic.
 *
 * NB. Here 'long long' means 64 bit integer.
 *
 * Since: 0.3.3
 */
typedef struct _virDomainInterfaceStats virDomainInterfaceStatsStruct;

struct _virDomainInterfaceStats {
    long long rx_bytes;
    long long rx_packets;
    long long rx_errs;
    long long rx_drop;
    long long tx_bytes;
    long long tx_packets;
    long long tx_errs;
    long long tx_drop;
};

/**
 * virDomainInterfaceStatsPtr:
 *
 * A pointer to a virDomainInterfaceStats structure
 *
 * Since: 0.3.2
 */
typedef virDomainInterfaceStatsStruct *virDomainInterfaceStatsPtr;

/**
 * virDomainMemoryStatTags:
 *
 * These represent values from inside of the guest (e.g. the same value would
 * be read from '/proc/meminfo' and/or other files from inside the guest).
 *
 * Since: 0.7.5
 */
typedef enum {
    /* The total amount of data read from swap space (in kB). (Since: 0.7.5) */
    VIR_DOMAIN_MEMORY_STAT_SWAP_IN         = 0,
    /* The total amount of memory written out to swap space (in kB). (Since: 0.7.5) */
    VIR_DOMAIN_MEMORY_STAT_SWAP_OUT        = 1,

    /*
     * Page faults occur when a process makes a valid access to virtual memory
     * that is not available.  When servicing the page fault, if disk IO is
     * required, it is considered a major fault.  If not, it is a minor fault.
     * These are expressed as the number of faults that have occurred.
     *
     * Since: 0.7.5
     */
    VIR_DOMAIN_MEMORY_STAT_MAJOR_FAULT     = 2,

    /*
     * Since: 0.7.5
     */
    VIR_DOMAIN_MEMORY_STAT_MINOR_FAULT     = 3,

    /*
     * The amount of memory left completely unused by the system.  Memory that
     * is available but used for reclaimable caches should NOT be reported as
     * free.  This value is expressed in kB.
     *
     * Since: 0.7.5
     */
    VIR_DOMAIN_MEMORY_STAT_UNUSED          = 4,

    /*
     * The total amount of usable memory as seen by the domain.  This value
     * may be less than the amount of memory assigned to the domain if a
     * balloon driver is in use or if the guest OS does not initialize all
     * assigned pages.  This value is expressed in kB.
     *
     * Since: 0.7.5
     */
    VIR_DOMAIN_MEMORY_STAT_AVAILABLE       = 5,

    /*
     * Current balloon value (in KB).
     *
     * Since: 0.9.3
     */
    VIR_DOMAIN_MEMORY_STAT_ACTUAL_BALLOON  = 6,

    /* Resident Set Size of the process running the domain. This value
     * is in kB
     *
     * Since: 0.9.10
     */
    VIR_DOMAIN_MEMORY_STAT_RSS             = 7,

    /*
     * How much the balloon can be inflated without pushing the guest system
     * to swap, corresponds to 'Available' in /proc/meminfo
     *
     * Since: 2.1.0
     */
    VIR_DOMAIN_MEMORY_STAT_USABLE          = 8,

    /*
     * Timestamp of the last update of statistics, in seconds.
     *
     * Since: 2.1.0
     */
    VIR_DOMAIN_MEMORY_STAT_LAST_UPDATE     = 9,

    /*
     * The amount of memory, that can be quickly reclaimed without
     * additional I/O (in kB). Typically these pages are used for caching files
     * from disk.
     *
     * Since: 4.6.0
     */
    VIR_DOMAIN_MEMORY_STAT_DISK_CACHES     = 10,

    /*
     * The number of successful huge page allocations from inside the domain via
     * virtio balloon.
     *
     * Since: 5.4.0
     */
    VIR_DOMAIN_MEMORY_STAT_HUGETLB_PGALLOC    = 11,

    /*
     * The number of failed huge page allocations from inside the domain via
     * virtio balloon.
     *
     * Since: 5.4.0
     */
    VIR_DOMAIN_MEMORY_STAT_HUGETLB_PGFAIL    = 12,

    /*
     * The number of statistics supported by this version of the interface.
     * To add new statistics, add them to the enum and increase this value.
     *
     * Since: 0.7.5
     */
    VIR_DOMAIN_MEMORY_STAT_NR              = 13,

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_MEMORY_STAT_LAST = VIR_DOMAIN_MEMORY_STAT_NR /* (Since: 0.9.10) */
# endif
} virDomainMemoryStatTags;

/**
 * virDomainMemoryStatStruct:
 *
 * Since: 0.7.5
 */
typedef struct _virDomainMemoryStat virDomainMemoryStatStruct;

struct _virDomainMemoryStat {
    int tag;
    unsigned long long val;
};

/**
 * virDomainMemoryStatPtr:
 *
 * Since: 0.7.5
 */
typedef virDomainMemoryStatStruct *virDomainMemoryStatPtr;


/**
 * virDomainCoreDumpFlags:
 *
 * Domain core dump flags.
 *
 * Since: 0.7.5
 */
typedef enum {
    VIR_DUMP_CRASH        = (1 << 0), /* crash after dump (Since: 0.7.5) */
    VIR_DUMP_LIVE         = (1 << 1), /* live dump (Since: 0.7.5) */
    VIR_DUMP_BYPASS_CACHE = (1 << 2), /* avoid file system cache pollution (Since: 0.9.4) */
    VIR_DUMP_RESET        = (1 << 3), /* reset domain after dump finishes (Since: 0.9.7) */
    VIR_DUMP_MEMORY_ONLY  = (1 << 4), /* use dump-guest-memory (Since: 0.9.13) */
} virDomainCoreDumpFlags;

/**
 * virDomainCoreDumpFormat:
 *
 * Values for specifying different formats of domain core dumps.
 *
 * Since: 1.2.3
 */
typedef enum {
    VIR_DOMAIN_CORE_DUMP_FORMAT_RAW,          /* dump guest memory in raw format (Since: 1.2.3) */
    VIR_DOMAIN_CORE_DUMP_FORMAT_KDUMP_ZLIB,   /* kdump-compressed format, with
                                               * zlib compression (Since: 1.2.3) */
    VIR_DOMAIN_CORE_DUMP_FORMAT_KDUMP_LZO,    /* kdump-compressed format, with
                                               * lzo compression (Since: 1.2.3) */
    VIR_DOMAIN_CORE_DUMP_FORMAT_KDUMP_SNAPPY, /* kdump-compressed format, with
                                               * snappy compression (Since: 1.2.3) */
    VIR_DOMAIN_CORE_DUMP_FORMAT_WIN_DMP,      /* Windows full crashdump format (Since: 7.4.0) */
# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_CORE_DUMP_FORMAT_LAST
    /*
     * NB: this enum value will increase over time as new formats are
     * added to the libvirt API. It reflects the last format supported
     * by this version of the libvirt API.
     *
     * Since: 1.2.3
     */
# endif
} virDomainCoreDumpFormat;

/**
 * virDomainMigrateFlags:
 *
 * Domain migration flags.
 *
 * Since: 0.3.2
 */
typedef enum {
    /* Do not pause the domain during migration. The domain's memory will
     * be transferred to the destination host while the domain is running.
     * The migration may never converge if the domain is changing its memory
     * faster then it can be transferred. The domain can be manually paused
     * anytime during migration using virDomainSuspend.
     *
     * Since: 0.3.2
     */
    VIR_MIGRATE_LIVE = (1 << 0),

    /* Tell the source libvirtd to connect directly to the destination host.
     * Without this flag the client (e.g., virsh) connects to both hosts and
     * controls the migration process. In peer-to-peer mode, the source
     * libvirtd controls the migration by calling the destination daemon
     * directly.
     *
     * Since: 0.7.2
     */
    VIR_MIGRATE_PEER2PEER = (1 << 1),

    /* Tunnel migration data over libvirtd connection. Without this flag the
     * source hypervisor sends migration data directly to the destination
     * hypervisor. This flag can only be used when VIR_MIGRATE_PEER2PEER is
     * set as well.
     *
     * Note the less-common spelling that we're stuck with:
     * VIR_MIGRATE_TUNNELLED should be VIR_MIGRATE_TUNNELED.
     *
     * Since: 0.7.2
     */
    VIR_MIGRATE_TUNNELLED = (1 << 2),

    /* Define the domain as persistent on the destination host after successful
     * migration. If the domain was persistent on the source host and
     * VIR_MIGRATE_UNDEFINE_SOURCE is not used, it will end up persistent on
     * both hosts.
     *
     * Since: 0.7.3
     */
    VIR_MIGRATE_PERSIST_DEST = (1 << 3),

    /* Undefine the domain on the source host once migration successfully
     * finishes.
     *
     * Since: 0.7.3
     */
    VIR_MIGRATE_UNDEFINE_SOURCE = (1 << 4),

    /* Leave the domain suspended on the destination host. virDomainResume (on
     * the virDomainPtr returned by the migration API) has to be called
     * explicitly to resume domain's virtual CPUs.
     *
     * Since: 0.7.5
     */
    VIR_MIGRATE_PAUSED = (1 << 5),

    /* Migrate full disk images in addition to domain's memory. By default
     * only non-shared non-readonly disk images are transferred. The
     * VIR_MIGRATE_PARAM_MIGRATE_DISKS parameter can be used to specify which
     * disks should be migrated.
     *
     * This flag and VIR_MIGRATE_NON_SHARED_INC are mutually exclusive.
     *
     * Since: 0.8.2
     */
    VIR_MIGRATE_NON_SHARED_DISK = (1 << 6),

    /* Migrate disk images in addition to domain's memory. This is similar to
     * VIR_MIGRATE_NON_SHARED_DISK, but only the top level of each disk's
     * backing chain is copied. That is, the rest of the backing chain is
     * expected to be present on the destination and to be exactly the same as
     * on the source host.
     *
     * This flag and VIR_MIGRATE_NON_SHARED_DISK are mutually exclusive.
     *
     * Since: 0.8.2
     */
    VIR_MIGRATE_NON_SHARED_INC = (1 << 7),

    /* Protect against domain configuration changes during the migration
     * process. This flag is used automatically when both sides support it.
     * Explicitly setting this flag will cause migration to fail if either the
     * source or the destination does not support it.
     *
     * Since: 0.9.4
     */
    VIR_MIGRATE_CHANGE_PROTECTION = (1 << 8),

    /* Force migration even if it is considered unsafe. In some cases libvirt
     * may refuse to migrate the domain because doing so may lead to potential
     * problems such as data corruption, and thus the migration is considered
     * unsafe. For a QEMU domain this may happen if the domain uses disks
     * without explicitly setting cache mode to "none". Migrating such domains
     * is unsafe unless the disk images are stored on coherent clustered
     * filesystem, such as GFS2 or GPFS.
     *
     * Since: 0.9.11
     */
    VIR_MIGRATE_UNSAFE = (1 << 9),

    /* Migrate a domain definition without starting the domain on the
     * destination and without stopping it on the source host. Offline
     * migration requires VIR_MIGRATE_PERSIST_DEST to be set.
     *
     * Offline migration may not copy disk storage or any other file based
     * storage (such as UEFI variables).
     *
     * Since: 1.0.1
     */
    VIR_MIGRATE_OFFLINE = (1 << 10),

    /* Compress migration data. The compression methods can be specified using
     * VIR_MIGRATE_PARAM_COMPRESSION. A hypervisor default method will be used
     * if this parameter is omitted. Individual compression methods can be
     * tuned via their specific VIR_MIGRATE_PARAM_COMPRESSION_* parameters.
     *
     * Since: 1.0.3
     */
    VIR_MIGRATE_COMPRESSED = (1 << 11),

    /* Cancel migration if a soft error (such as I/O error) happens during
     * migration.
     *
     * Since: 1.1.0
     */
    VIR_MIGRATE_ABORT_ON_ERROR = (1 << 12),

    /* Enable algorithms that ensure a live migration will eventually converge.
     * This usually means the domain will be slowed down to make sure it does
     * not change its memory faster than a hypervisor can transfer the changed
     * memory to the destination host. VIR_MIGRATE_PARAM_AUTO_CONVERGE_*
     * parameters can be used to tune the algorithm.
     *
     * Since: 1.2.3
     */
    VIR_MIGRATE_AUTO_CONVERGE = (1 << 13),

    /* This flag can be used with RDMA migration (i.e., when
     * VIR_MIGRATE_PARAM_URI starts with "rdma://") to tell the hypervisor
     * to pin all domain's memory at once before migration starts rather then
     * letting it pin memory pages as needed. This means that all memory pages
     * belonging to the domain will be locked in host's memory and the host
     * will not be allowed to swap them out.
     *
     * For QEMU/KVM this requires hard_limit memory tuning element (in the
     * domain XML) to be used and set to the maximum memory configured for the
     * domain plus any memory consumed by the QEMU process itself. Beware of
     * setting the memory limit too high (and thus allowing the domain to lock
     * most of the host's memory). Doing so may be dangerous to both the
     * domain and the host itself since the host's kernel may run out of
     * memory.
     *
     * Since: 1.2.9
     */
    VIR_MIGRATE_RDMA_PIN_ALL = (1 << 14),

    /* Setting the VIR_MIGRATE_POSTCOPY flag tells libvirt to enable post-copy
     * migration. However, the migration will start normally and
     * virDomainMigrateStartPostCopy needs to be called to switch it into the
     * post-copy mode. See virDomainMigrateStartPostCopy for more details.
     *
     * Since: 1.3.3
     */
    VIR_MIGRATE_POSTCOPY = (1 << 15),

    /* Setting the VIR_MIGRATE_TLS flag will cause the migration to attempt
     * to use the TLS environment configured by the hypervisor in order to
     * perform the migration. If incorrectly configured on either source or
     * destination, the migration will fail.
     *
     * Since: 3.2.0
     */
    VIR_MIGRATE_TLS = (1 << 16),

    /* Send memory pages to the destination host through several network
     * connections. See VIR_MIGRATE_PARAM_PARALLEL_* parameters for
     * configuring the parallel migration.
     *
     * Since: 5.2.0
     */
    VIR_MIGRATE_PARALLEL = (1 << 17),

     /* Force the guest writes which happen when copying disk images for
      * non-shared storage migration to be synchronously written to the
      * destination. This ensures the storage migration converges for VMs
      * doing heavy I/O on fast local storage and slow mirror.
      *
      * Requires one of VIR_MIGRATE_NON_SHARED_DISK, VIR_MIGRATE_NON_SHARED_INC
      * to be present as well.
      *
      * Since: 8.0.0
      */
    VIR_MIGRATE_NON_SHARED_SYNCHRONOUS_WRITES = (1 << 18),

    /* Resume migration which failed in post-copy phase.
     *
     * Since: 8.5.0
     */
    VIR_MIGRATE_POSTCOPY_RESUME = (1 << 19),

    /* Use zero-copy mechanism for migrating memory pages. For QEMU/KVM this
     * means QEMU will be temporarily allowed to lock all guest pages in host's
     * memory, although only those that are queued for transfer will be locked
     * at the same time.
     *
     * Since: 8.5.0
     */
    VIR_MIGRATE_ZEROCOPY = (1 << 20),
} virDomainMigrateFlags;


/**
 * VIR_MIGRATE_PARAM_URI:
 *
 * virDomainMigrate* params field: URI to use for initiating domain migration
 * as VIR_TYPED_PARAM_STRING. It takes a hypervisor specific format. The
 * uri_transports element of the hypervisor capabilities XML includes details
 * of the supported URI schemes. When omitted libvirt will auto-generate
 * suitable default URI. It is typically only necessary to specify this URI if
 * the destination host has multiple interfaces and a specific interface is
 * required to transmit migration data.
 *
 * This field may not be used when VIR_MIGRATE_TUNNELLED flag is set.
 *
 * Since: 1.1.0
 */
# define VIR_MIGRATE_PARAM_URI               "migrate_uri"

/**
 * VIR_MIGRATE_PARAM_DEST_NAME:
 *
 * virDomainMigrate* params field: the name to be used for the domain on the
 * destination host as VIR_TYPED_PARAM_STRING. Omitting this parameter keeps
 * the domain name the same. This field is only allowed to be used with
 * hypervisors that support domain renaming during migration.
 *
 * Since: 1.1.0
 */
# define VIR_MIGRATE_PARAM_DEST_NAME         "destination_name"

/**
 * VIR_MIGRATE_PARAM_DEST_XML:
 *
 * virDomainMigrate* params field: the new configuration to be used for the
 * domain on the destination host as VIR_TYPED_PARAM_STRING. The configuration
 * must include an identical set of virtual devices, to ensure a stable guest
 * ABI across migration. Only parameters related to host side configuration
 * can be changed in the XML. Hypervisors which support this field will forbid
 * migration if the provided XML would cause a change in the guest ABI. This
 * field cannot be used to rename the domain during migration (use
 * VIR_MIGRATE_PARAM_DEST_NAME field for that purpose). Domain name in the
 * destination XML must match the original domain name.
 *
 * Omitting this parameter keeps the original domain configuration. Using this
 * field with hypervisors that do not support changing domain configuration
 * during migration will result in a failure.
 *
 * Since: 1.1.0
 */
# define VIR_MIGRATE_PARAM_DEST_XML          "destination_xml"

/**
 * VIR_MIGRATE_PARAM_PERSIST_XML:
 *
 * virDomainMigrate* params field: the new persistent configuration to be used
 * for the domain on the destination host as VIR_TYPED_PARAM_STRING.
 * This field cannot be used to rename the domain during migration (use
 * VIR_MIGRATE_PARAM_DEST_NAME field for that purpose). Domain name in the
 * destination XML must match the original domain name.
 *
 * Omitting this parameter keeps the original domain persistent configuration.
 * Using this field with hypervisors that do not support changing domain
 * configuration during migration will result in a failure.
 *
 * Since: 1.3.4
 */
# define VIR_MIGRATE_PARAM_PERSIST_XML  "persistent_xml"

/**
 * VIR_MIGRATE_PARAM_BANDWIDTH:
 *
 * virDomainMigrate* params field: the maximum bandwidth (in MiB/s) that will
 * be used for migration as VIR_TYPED_PARAM_ULLONG. If set to 0 or omitted,
 * libvirt will choose a suitable default. Some hypervisors do not support this
 * feature and will return an error if this field is used and is not 0.
 *
 * Since: 1.1.0
 */
# define VIR_MIGRATE_PARAM_BANDWIDTH         "bandwidth"

/**
 * VIR_MIGRATE_PARAM_BANDWIDTH_POSTCOPY:
 *
 * virDomainMigrate* params field: the maximum bandwidth (in MiB/s) that will
 * be used for post-copy phase of a migration as VIR_TYPED_PARAM_ULLONG. If set
 * to 0 or omitted, post-copy migration speed will not be limited.
 *
 * Since: 5.1.0
 */
# define VIR_MIGRATE_PARAM_BANDWIDTH_POSTCOPY "bandwidth.postcopy"

/**
 * VIR_MIGRATE_PARAM_GRAPHICS_URI:
 *
 * virDomainMigrate* params field: URI to use for migrating client's connection
 * to domain's graphical console as VIR_TYPED_PARAM_STRING. If specified, the
 * client will be asked to automatically reconnect using these parameters
 * instead of the automatically computed ones. This can be useful if, e.g., the
 * client does not have a direct access to the network virtualization hosts are
 * connected to and needs to connect through a proxy. The URI is formed as
 * follows:
 *
 *      protocol://hostname[:port]/[?parameters]
 *
 * where protocol is either "spice" or "vnc" and parameters is a list of
 * protocol specific parameters separated by '&'. Currently recognized
 * parameters are "tlsPort" and "tlsSubject". For example,
 *
 *      spice://target.host.com:1234/?tlsPort=4567
 *
 * Since: 1.1.0
 */
# define VIR_MIGRATE_PARAM_GRAPHICS_URI      "graphics_uri"

/**
 * VIR_MIGRATE_PARAM_LISTEN_ADDRESS:
 *
 * virDomainMigrate* params field: The listen address that hypervisor on the
 * destination side should bind to for incoming migration. Both IPv4 and IPv6
 * addresses are accepted as well as hostnames (the resolving is done on
 * destination). Some hypervisors do not support this feature and will return
 * an error if this field is used.
 *
 * Since: 1.1.4
 */
# define VIR_MIGRATE_PARAM_LISTEN_ADDRESS    "listen_address"

/**
 * VIR_MIGRATE_PARAM_MIGRATE_DISKS:
 *
 * virDomainMigrate* params multiple field: The multiple values that list
 * the block devices to be migrated. At the moment this is only supported
 * by the QEMU driver but not for the tunnelled migration.
 *
 * Since: 1.2.17
 */
# define VIR_MIGRATE_PARAM_MIGRATE_DISKS    "migrate_disks"

/**
 * VIR_MIGRATE_PARAM_DISKS_PORT:
 *
 * virDomainMigrate* params field: port that destination server should use
 * for incoming disks migration. Type is VIR_TYPED_PARAM_INT. If set to 0 or
 * omitted, libvirt will choose a suitable default. At the moment this is only
 * supported by the QEMU driver.
 *
 * Since: 1.3.3
 */
# define VIR_MIGRATE_PARAM_DISKS_PORT    "disks_port"

/**
 * VIR_MIGRATE_PARAM_DISKS_URI:
 *
 * virDomainMigrate* params field: URI used for incoming disks migration. Type
 * is VIR_TYPED_PARAM_STRING. Only schemes "tcp" and "unix" are accepted. TCP
 * URI can currently only provide a server and port to listen on (and connect
 * to), UNIX URI may only provide a path component for a UNIX socket. This is
 * currently only supported by the QEMU driver.  UNIX URI is only usable if the
 * management application makes sure that socket created with this name on the
 * destination will be reachable from the source under the same exact path.
 *
 * Since: 6.8.0
 */
# define VIR_MIGRATE_PARAM_DISKS_URI    "disks_uri"

/**
 * VIR_MIGRATE_PARAM_COMPRESSION:
 *
 * virDomainMigrate* params multiple field: name of the method used to
 * compress migration traffic. Supported compression methods: xbzrle, mt,
 * zlib, zstd. The parameter may be specified multiple times if more than
 * one method should be used. Not all combinations of compression methods
 * and migration options may be allowed. Parallel migration of QEMU domains
 * is only compatible with either zlib or zstd method.
 *
 * Since: 1.3.4
 */
# define VIR_MIGRATE_PARAM_COMPRESSION    "compression"

/**
 * VIR_MIGRATE_PARAM_COMPRESSION_MT_LEVEL:
 *
 * virDomainMigrate* params field: the level of compression for multithread
 * compression as VIR_TYPED_PARAM_INT. Accepted values are in range 0-9.
 * 0 is no compression, 1 is maximum speed and 9 is maximum compression.
 *
 * Since: 1.3.4
 */
# define VIR_MIGRATE_PARAM_COMPRESSION_MT_LEVEL    "compression.mt.level"

/**
 * VIR_MIGRATE_PARAM_COMPRESSION_MT_THREADS:
 *
 * virDomainMigrate* params field: the number of compression threads for
 * multithread compression as VIR_TYPED_PARAM_INT.
 *
 * Since: 1.3.4
 */
# define VIR_MIGRATE_PARAM_COMPRESSION_MT_THREADS "compression.mt.threads"

/**
 * VIR_MIGRATE_PARAM_COMPRESSION_MT_DTHREADS:
 *
 * virDomainMigrate* params field: the number of decompression threads for
 * multithread compression as VIR_TYPED_PARAM_INT.
 *
 * Since: 1.3.4
 */
# define VIR_MIGRATE_PARAM_COMPRESSION_MT_DTHREADS "compression.mt.dthreads"

/**
 * VIR_MIGRATE_PARAM_COMPRESSION_XBZRLE_CACHE:
 *
 * virDomainMigrate* params field: the size of page cache for xbzrle
 * compression as VIR_TYPED_PARAM_ULLONG.
 *
 * Since: 1.3.4
 */
# define VIR_MIGRATE_PARAM_COMPRESSION_XBZRLE_CACHE "compression.xbzrle.cache"

/**
 * VIR_MIGRATE_PARAM_COMPRESSION_ZLIB_LEVEL:
 *
 * virDomainMigrate* params field: the level of compression for zlib as
 * VIR_TYPED_PARAM_INT. Accepted values are in range 0-9. 0 is no compression,
 * 1 is maximum speed and 9 is maximum compression.
 *
 * Since: 9.4.0
 */
# define VIR_MIGRATE_PARAM_COMPRESSION_ZLIB_LEVEL      "compression.zlib.level"

/**
 * VIR_MIGRATE_PARAM_COMPRESSION_ZSTD_LEVEL:
 *
 * virDomainMigrate* params field: the level of compression for zstd as
 * VIR_TYPED_PARAM_INT. Accepted values are in range 0-20. 0 is no compression,
 * 1 is maximum speed and 20 is maximum compression.
 *
 * Since: 9.4.0
 */
# define VIR_MIGRATE_PARAM_COMPRESSION_ZSTD_LEVEL      "compression.zstd.level"

/**
 * VIR_MIGRATE_PARAM_AUTO_CONVERGE_INITIAL:
 *
 * virDomainMigrate* params field: the initial percentage guest CPUs are
 * throttled to when auto-convergence decides migration is not converging.
 * As VIR_TYPED_PARAM_INT.
 *
 * Since: 2.0.0
 */
# define VIR_MIGRATE_PARAM_AUTO_CONVERGE_INITIAL    "auto_converge.initial"

/**
 * VIR_MIGRATE_PARAM_AUTO_CONVERGE_INCREMENT:
 *
 * virDomainMigrate* params field: the increment added to
 * VIR_MIGRATE_PARAM_AUTO_CONVERGE_INITIAL whenever the hypervisor decides
 * the current rate is not enough to ensure convergence of the migration.
 * As VIR_TYPED_PARAM_INT.
 *
 * Since: 2.0.0
 */
# define VIR_MIGRATE_PARAM_AUTO_CONVERGE_INCREMENT  "auto_converge.increment"

/**
 * VIR_MIGRATE_PARAM_PARALLEL_CONNECTIONS:
 *
 * virDomainMigrate* params field: number of connections used during parallel
 * migration. As VIR_TYPED_PARAM_INT.
 *
 * Since: 5.2.0
 */
# define VIR_MIGRATE_PARAM_PARALLEL_CONNECTIONS     "parallel.connections"

/**
 * VIR_MIGRATE_PARAM_TLS_DESTINATION:
 *
 * virDomainMigrate* params field: override the destination host name used for
 * TLS verification. As VIR_TYPED_PARAM_STRING.
 *
 * Normally the TLS certificate from the destination host must match the host's
 * name for TLS verification to succeed. When the certificate does not match
 * the destination hostname and the expected certificate's hostname is known,
 * this parameter can be used to pass this expected hostname when starting
 * the migration.
 *
 * Since: 6.0.0
 */
# define VIR_MIGRATE_PARAM_TLS_DESTINATION          "tls.destination"

/* Domain migration. */
virDomainPtr virDomainMigrate (virDomainPtr domain, virConnectPtr dconn,
                               unsigned long flags, const char *dname,
                               const char *uri, unsigned long bandwidth);
virDomainPtr virDomainMigrate2(virDomainPtr domain, virConnectPtr dconn,
                               const char *dxml,
                               unsigned long flags, const char *dname,
                               const char *uri, unsigned long bandwidth);
virDomainPtr virDomainMigrate3(virDomainPtr domain,
                               virConnectPtr dconn,
                               virTypedParameterPtr params,
                               unsigned int nparams,
                               unsigned int flags);

int virDomainMigrateToURI (virDomainPtr domain, const char *duri,
                           unsigned long flags, const char *dname,
                           unsigned long bandwidth);

int virDomainMigrateToURI2(virDomainPtr domain,
                           const char *dconnuri,
                           const char *miguri,
                           const char *dxml,
                           unsigned long flags,
                           const char *dname,
                           unsigned long bandwidth);
int virDomainMigrateToURI3(virDomainPtr domain,
                           const char *dconnuri,
                           virTypedParameterPtr params,
                           unsigned int nparams,
                           unsigned int flags);

int virDomainMigrateGetMaxDowntime(virDomainPtr domain,
                                   unsigned long long *downtime,
                                   unsigned int flags);

int virDomainMigrateSetMaxDowntime (virDomainPtr domain,
                                    unsigned long long downtime,
                                    unsigned int flags);

int virDomainMigrateGetCompressionCache(virDomainPtr domain,
                                        unsigned long long *cacheSize,
                                        unsigned int flags);
int virDomainMigrateSetCompressionCache(virDomainPtr domain,
                                        unsigned long long cacheSize,
                                        unsigned int flags);

/**
 * virDomainMigrateMaxSpeedFlags:
 *
 * Domain migration speed flags.
 *
 * Since: 5.1.0
 */
typedef enum {
    /* Set or get maximum speed of post-copy migration. (Since: 5.1.0) */
    VIR_DOMAIN_MIGRATE_MAX_SPEED_POSTCOPY = (1 << 0),
} virDomainMigrateMaxSpeedFlags;

int virDomainMigrateSetMaxSpeed(virDomainPtr domain,
                                unsigned long bandwidth,
                                unsigned int flags);

int virDomainMigrateGetMaxSpeed(virDomainPtr domain,
                                unsigned long *bandwidth,
                                unsigned int flags);

int virDomainMigrateStartPostCopy(virDomainPtr domain,
                                  unsigned int flags);

char * virConnectGetDomainCapabilities(virConnectPtr conn,
                                       const char *emulatorbin,
                                       const char *arch,
                                       const char *machine,
                                       const char *virttype,
                                       unsigned int flags);

/*
 * Gather list of running domains
 */
int                     virConnectListDomains   (virConnectPtr conn,
                                                 int *ids,
                                                 int maxids);

/*
 * Number of domains
 */
int                     virConnectNumOfDomains  (virConnectPtr conn);


/*
 * Get connection from domain.
 */
virConnectPtr           virDomainGetConnect     (virDomainPtr domain);

/*
 * Domain creation and destruction
 */

virDomainPtr            virDomainCreateXML      (virConnectPtr conn,
                                                 const char *xmlDesc,
                                                 unsigned int flags);
virDomainPtr            virDomainCreateXMLWithFiles(virConnectPtr conn,
                                                    const char *xmlDesc,
                                                    unsigned int nfiles,
                                                    int *files,
                                                    unsigned int flags);
virDomainPtr            virDomainLookupByName   (virConnectPtr conn,
                                                 const char *name);
virDomainPtr            virDomainLookupByID     (virConnectPtr conn,
                                                 int id);
virDomainPtr            virDomainLookupByUUID   (virConnectPtr conn,
                                                 const unsigned char *uuid);
virDomainPtr            virDomainLookupByUUIDString     (virConnectPtr conn,
                                                         const char *uuid);

/**
 * virDomainShutdownFlagValues:
 *
 * Since: 0.9.10
 */
typedef enum {
    VIR_DOMAIN_SHUTDOWN_DEFAULT        = 0,        /* hypervisor choice (Since: 0.9.10) */
    VIR_DOMAIN_SHUTDOWN_ACPI_POWER_BTN = (1 << 0), /* Send ACPI event (Since: 0.9.10) */
    VIR_DOMAIN_SHUTDOWN_GUEST_AGENT    = (1 << 1), /* Use guest agent (Since: 0.9.10) */
    VIR_DOMAIN_SHUTDOWN_INITCTL        = (1 << 2), /* Use initctl (Since: 1.0.1) */
    VIR_DOMAIN_SHUTDOWN_SIGNAL         = (1 << 3), /* Send a signal (Since: 1.0.1) */
    VIR_DOMAIN_SHUTDOWN_PARAVIRT       = (1 << 4), /* Use paravirt guest control (Since: 1.2.5) */
} virDomainShutdownFlagValues;

int                     virDomainShutdown       (virDomainPtr domain);
int                     virDomainShutdownFlags  (virDomainPtr domain,
                                                 unsigned int flags);

/**
 * virDomainRebootFlagValues:
 *
 * Since: 0.9.10
 */
typedef enum {
    VIR_DOMAIN_REBOOT_DEFAULT        = 0,        /* hypervisor choice (Since: 0.9.10) */
    VIR_DOMAIN_REBOOT_ACPI_POWER_BTN = (1 << 0), /* Send ACPI event (Since: 0.9.10) */
    VIR_DOMAIN_REBOOT_GUEST_AGENT    = (1 << 1), /* Use guest agent (Since: 0.9.10) */
    VIR_DOMAIN_REBOOT_INITCTL        = (1 << 2), /* Use initctl (Since: 1.0.1) */
    VIR_DOMAIN_REBOOT_SIGNAL         = (1 << 3), /* Send a signal (Since: 1.0.1) */
    VIR_DOMAIN_REBOOT_PARAVIRT       = (1 << 4), /* Use paravirt guest control (Since: 1.2.5) */
} virDomainRebootFlagValues;

int                     virDomainReboot         (virDomainPtr domain,
                                                 unsigned int flags);
int                     virDomainReset          (virDomainPtr domain,
                                                 unsigned int flags);

int                     virDomainDestroy        (virDomainPtr domain);

/**
 * virDomainDestroyFlagsValues:
 *
 * Flags used to provide specific behaviour to the
 * virDomainDestroyFlags() function
 *
 * Since: 0.9.4
 */
typedef enum {
    VIR_DOMAIN_DESTROY_DEFAULT   = 0,      /* Default behavior - could lead to data loss!! (Since: 0.9.10) */
    VIR_DOMAIN_DESTROY_GRACEFUL  = 1 << 0, /* only SIGTERM, no SIGKILL (Since: 0.9.10) */
    VIR_DOMAIN_DESTROY_REMOVE_LOGS = 1 << 1, /* remove VM logs on destroy (Since: 8.3.0) */
} virDomainDestroyFlagsValues;

int                     virDomainDestroyFlags   (virDomainPtr domain,
                                                 unsigned int flags);
int                     virDomainRef            (virDomainPtr domain);
int                     virDomainFree           (virDomainPtr domain);

/*
 * Domain suspend/resume
 */
int                     virDomainSuspend        (virDomainPtr domain);
int                     virDomainResume         (virDomainPtr domain);
int                     virDomainPMSuspendForDuration (virDomainPtr domain,
                                                       unsigned int target,
                                                       unsigned long long duration,
                                                       unsigned int flags);
int                     virDomainPMWakeup       (virDomainPtr domain,
                                                 unsigned int flags);
/*
 * Domain save/restore
 */

/**
 * virDomainSaveRestoreFlags:
 *
 * Flags for use in virDomainSaveFlags(), virDomainManagedSave(),
 * virDomainSaveParams(), virDomainRestoreParams(),
 * virDomainRestoreFlags(), and virDomainSaveImageDefineXML().  Not all
 * flags apply to all these functions.
 *
 * Since: 0.9.4
 */
typedef enum {
    VIR_DOMAIN_SAVE_BYPASS_CACHE = 1 << 0, /* Avoid file system cache pollution (Since: 0.9.4) */
    VIR_DOMAIN_SAVE_RUNNING      = 1 << 1, /* Favor running over paused (Since: 0.9.5) */
    VIR_DOMAIN_SAVE_PAUSED       = 1 << 2, /* Favor paused over running (Since: 0.9.5) */
    VIR_DOMAIN_SAVE_RESET_NVRAM  = 1 << 3, /* Re-initialize NVRAM from template (Since: 8.1.0) */
} virDomainSaveRestoreFlags;

int                     virDomainSave           (virDomainPtr domain,
                                                 const char *to);
int                     virDomainSaveFlags      (virDomainPtr domain,
                                                 const char *to,
                                                 const char *dxml,
                                                 unsigned int flags);
int                     virDomainSaveParams     (virDomainPtr domain,
                                                 virTypedParameterPtr params,
                                                 int nparams,
                                                 unsigned int flags);
int                     virDomainRestore        (virConnectPtr conn,
                                                 const char *from);
int                     virDomainRestoreFlags   (virConnectPtr conn,
                                                 const char *from,
                                                 const char *dxml,
                                                 unsigned int flags);
int                     virDomainRestoreParams  (virConnectPtr conn,
                                                 virTypedParameterPtr params,
                                                 int nparams,
                                                 unsigned int flags);

/**
 * VIR_DOMAIN_SAVE_PARAM_FILE:
 *
 * the parameter used to specify the savestate file to save to or restore from.
 *
 * Since: 8.4.0
 */
# define VIR_DOMAIN_SAVE_PARAM_FILE             "file"

/**
 * VIR_DOMAIN_SAVE_PARAM_DXML:
 *
 * an optional parameter used to adjust guest xml on restore.
 * If the hypervisor supports it, it can be used to alter
 * host-specific portions of the domain XML that will be used when
 * restoring an image.  For example, it is possible to alter the
 * device while the domain is stopped.
 *
 * Since: 8.4.0
 */
# define VIR_DOMAIN_SAVE_PARAM_DXML             "dxml"

/* See below for virDomainSaveImageXMLFlags */
char *          virDomainSaveImageGetXMLDesc    (virConnectPtr conn,
                                                 const char *file,
                                                 unsigned int flags);
int             virDomainSaveImageDefineXML     (virConnectPtr conn,
                                                 const char *file,
                                                 const char *dxml,
                                                 unsigned int flags);

/*
 * Managed domain save
 */
int                    virDomainManagedSave     (virDomainPtr dom,
                                                 unsigned int flags);
int                    virDomainHasManagedSaveImage(virDomainPtr dom,
                                                    unsigned int flags);
int                    virDomainManagedSaveRemove(virDomainPtr dom,
                                                  unsigned int flags);
char *                 virDomainManagedSaveGetXMLDesc(virDomainPtr domain,
                                                      unsigned int flags);
int                    virDomainManagedSaveDefineXML(virDomainPtr domain,
                                                     const char *dxml,
                                                     unsigned int flags);


/*
 * Domain core dump
 */
int                     virDomainCoreDump       (virDomainPtr domain,
                                                 const char *to,
                                                 unsigned int flags);

/*
 * Domain core dump with format specified
 */
int                 virDomainCoreDumpWithFormat (virDomainPtr domain,
                                                 const char *to,
                                                 unsigned int dumpformat,
                                                 unsigned int flags);

/*
 * Screenshot of current domain console
 */
char *                  virDomainScreenshot     (virDomainPtr domain,
                                                 virStreamPtr stream,
                                                 unsigned int screen,
                                                 unsigned int flags);

/*
 * Domain runtime information, and collecting CPU statistics
 */

int                     virDomainGetInfo        (virDomainPtr domain,
                                                 virDomainInfoPtr info);
int                     virDomainGetState       (virDomainPtr domain,
                                                 int *state,
                                                 int *reason,
                                                 unsigned int flags);

/**
 * VIR_DOMAIN_CPU_STATS_CPUTIME:
 * cpu usage (sum of both vcpu and hypervisor usage) in nanoseconds,
 * as a ullong
 *
 * Since: 0.9.10
 */
# define VIR_DOMAIN_CPU_STATS_CPUTIME "cpu_time"

/**
 * VIR_DOMAIN_CPU_STATS_USERTIME:
 * cpu time charged to user instructions in nanoseconds, as a ullong
 *
 * Since: 0.9.11
 */
# define VIR_DOMAIN_CPU_STATS_USERTIME "user_time"

/**
 * VIR_DOMAIN_CPU_STATS_SYSTEMTIME:
 * cpu time charged to system instructions in nanoseconds, as a ullong
 *
 * Since: 0.9.11
 */
# define VIR_DOMAIN_CPU_STATS_SYSTEMTIME "system_time"

/**
 * VIR_DOMAIN_CPU_STATS_VCPUTIME:
 * vcpu usage in nanoseconds (cpu_time excluding hypervisor time),
 * as a ullong
 *
 * Since: 0.9.13
 */
# define VIR_DOMAIN_CPU_STATS_VCPUTIME "vcpu_time"

int virDomainGetCPUStats(virDomainPtr domain,
                         virTypedParameterPtr params,
                         unsigned int nparams,
                         int start_cpu,
                         unsigned int ncpus,
                         unsigned int flags);

int                     virDomainGetControlInfo (virDomainPtr domain,
                                                 virDomainControlInfoPtr info,
                                                 unsigned int flags);

/*
 * Return scheduler type in effect 'sedf', 'credit', 'linux'
 */
char *                  virDomainGetSchedulerType(virDomainPtr domain,
                                                  int *nparams);


/* Manage blkio parameters.  */

/**
 * VIR_DOMAIN_BLKIO_WEIGHT:
 *
 * Macro for the Blkio tunable weight: it represents the io weight
 * the guest can use, as a uint.
 *
 * Since: 0.9.0
 */
# define VIR_DOMAIN_BLKIO_WEIGHT "weight"

/**
 * VIR_DOMAIN_BLKIO_DEVICE_WEIGHT:
 *
 * Macro for the blkio tunable weight_device: it represents the
 * per-device weight, as a string.  The string is parsed as a
 * series of /path/to/device,weight elements, separated by ','.
 *
 * Since: 0.9.8
 */
# define VIR_DOMAIN_BLKIO_DEVICE_WEIGHT "device_weight"

/**
 * VIR_DOMAIN_BLKIO_DEVICE_READ_IOPS:
 *
 * Macro for the blkio tunable throttle.read_iops_device: it represents
 * the number of reading the block device per second, as a string. The
 * string is parsed as a series of /path/to/device, read_iops elements,
 * separated by ','.
 *
 * Since: 1.2.2
 */
# define VIR_DOMAIN_BLKIO_DEVICE_READ_IOPS "device_read_iops_sec"


/**
 * VIR_DOMAIN_BLKIO_DEVICE_WRITE_IOPS:
 *
 * Macro for the blkio tunable throttle.write_iops_device: it represents
 * the number of writing the block device per second, as a string. The
 * string is parsed as a series of /path/to/device, write_iops elements,
 * separated by ','.
 *
 * Since: 1.2.2
 */
# define VIR_DOMAIN_BLKIO_DEVICE_WRITE_IOPS "device_write_iops_sec"


/**
 * VIR_DOMAIN_BLKIO_DEVICE_READ_BPS:
 *
 * Macro for the blkio tunable throttle.read_iops_device: it represents
 * the bytes of reading the block device per second, as a string. The
 * string is parsed as a series of /path/to/device, read_bps elements,
 * separated by ','.
 *
 * Since: 1.2.2
 */
# define VIR_DOMAIN_BLKIO_DEVICE_READ_BPS "device_read_bytes_sec"


/**
 * VIR_DOMAIN_BLKIO_DEVICE_WRITE_BPS:
 *
 * Macro for the blkio tunable throttle.read_iops_device: it represents
 * the number of reading the block device per second, as a string. The
 * string is parsed as a series of /path/to/device, write_bps elements,
 * separated by ','.
 *
 * Since: 1.2.2
 */
# define VIR_DOMAIN_BLKIO_DEVICE_WRITE_BPS "device_write_bytes_sec"


/* Set Blkio tunables for the domain */
int     virDomainSetBlkioParameters(virDomainPtr domain,
                                    virTypedParameterPtr params,
                                    int nparams, unsigned int flags);
int     virDomainGetBlkioParameters(virDomainPtr domain,
                                    virTypedParameterPtr params,
                                    int *nparams, unsigned int flags);

/* Manage memory parameters. */

/**
 * VIR_DOMAIN_MEMORY_PARAM_UNLIMITED:
 *
 * Macro providing the virMemoryParameter value that indicates "unlimited"
 *
 * Since: 0.8.8
 */
# define VIR_DOMAIN_MEMORY_PARAM_UNLIMITED 9007199254740991LL /* = INT64_MAX >> 10 */

/**
 * VIR_DOMAIN_MEMORY_HARD_LIMIT:
 *
 * Macro for the memory tunable hard_limit: it represents the maximum memory
 * the guest can use, as a ullong.
 *
 * Since: 0.8.5
 */
# define VIR_DOMAIN_MEMORY_HARD_LIMIT "hard_limit"

/**
 * VIR_DOMAIN_MEMORY_SOFT_LIMIT:
 *
 * Macro for the memory tunable soft_limit: it represents the memory upper
 * limit enforced during memory contention, as a ullong.
 *
 * Since: 0.8.5
 */
# define VIR_DOMAIN_MEMORY_SOFT_LIMIT "soft_limit"

/**
 * VIR_DOMAIN_MEMORY_MIN_GUARANTEE:
 *
 * Macro for the memory tunable min_guarantee: it represents the minimum
 * memory guaranteed to be reserved for the guest, as a ullong.
 *
 * Since: 0.8.5
 */
# define VIR_DOMAIN_MEMORY_MIN_GUARANTEE "min_guarantee"

/**
 * VIR_DOMAIN_MEMORY_SWAP_HARD_LIMIT:
 *
 * Macro for the swap tunable swap_hard_limit: it represents the maximum swap
 * plus memory the guest can use, as a ullong. This limit has to be more than
 * VIR_DOMAIN_MEMORY_HARD_LIMIT.
 *
 * Since: 0.8.5
 */
# define VIR_DOMAIN_MEMORY_SWAP_HARD_LIMIT "swap_hard_limit"

/* Set memory tunables for the domain */
int     virDomainSetMemoryParameters(virDomainPtr domain,
                                     virTypedParameterPtr params,
                                     int nparams, unsigned int flags);
int     virDomainGetMemoryParameters(virDomainPtr domain,
                                     virTypedParameterPtr params,
                                     int *nparams, unsigned int flags);

/**
 * virDomainMemoryModFlags:
 *
 * Memory size modification flags.
 *
 * Since: 0.9.0
 */
typedef enum {
    VIR_DOMAIN_MEM_CURRENT = VIR_DOMAIN_AFFECT_CURRENT, /* See virDomainModificationImpact (Since: 0.9.1) */
    VIR_DOMAIN_MEM_LIVE    = VIR_DOMAIN_AFFECT_LIVE, /* See virDomainModificationImpact (Since: 0.9.0) */
    VIR_DOMAIN_MEM_CONFIG  = VIR_DOMAIN_AFFECT_CONFIG, /* See virDomainModificationImpact (Since: 0.9.0) */

    VIR_DOMAIN_MEM_MAXIMUM = (1 << 2), /* affect Max rather than current (Since: 0.9.1) */
} virDomainMemoryModFlags;


/* Manage numa parameters */

/**
 * virDomainNumatuneMemMode:
 * Representation of the various modes in the <numatune> element of
 * a domain.
 *
 * Since: 0.9.9
 */
typedef enum {
    VIR_DOMAIN_NUMATUNE_MEM_STRICT      = 0, /* (Since: 0.9.9) */
    VIR_DOMAIN_NUMATUNE_MEM_PREFERRED   = 1, /* (Since: 0.9.9) */
    VIR_DOMAIN_NUMATUNE_MEM_INTERLEAVE  = 2, /* (Since: 0.9.9) */
    VIR_DOMAIN_NUMATUNE_MEM_RESTRICTIVE = 3, /* (Since: 7.3.0) */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_NUMATUNE_MEM_LAST /* This constant is subject to change (Since: 0.9.9) */
# endif
} virDomainNumatuneMemMode;

/**
 * VIR_DOMAIN_NUMA_NODESET:
 *
 * Macro for typed parameter name that lists the numa nodeset of a
 * domain, as a string.
 *
 * Since: 0.9.9
 */
# define VIR_DOMAIN_NUMA_NODESET "numa_nodeset"

/**
 * VIR_DOMAIN_NUMA_MODE:
 *
 * Macro for typed parameter name that lists the numa mode of a domain,
 * as an int containing a virDomainNumatuneMemMode value.
 *
 * Since: 0.9.9
 */
# define VIR_DOMAIN_NUMA_MODE "numa_mode"

int     virDomainSetNumaParameters(virDomainPtr domain,
                                   virTypedParameterPtr params,
                                   int nparams, unsigned int flags);
int     virDomainGetNumaParameters(virDomainPtr domain,
                                   virTypedParameterPtr params,
                                   int *nparams, unsigned int flags);

/*
 * Dynamic control of domains
 */
const char *            virDomainGetName        (virDomainPtr domain);
unsigned int            virDomainGetID          (virDomainPtr domain);
int                     virDomainGetUUID        (virDomainPtr domain,
                                                 unsigned char *uuid);
int                     virDomainGetUUIDString  (virDomainPtr domain,
                                                 char *buf);
char *                  virDomainGetOSType      (virDomainPtr domain);
unsigned long           virDomainGetMaxMemory   (virDomainPtr domain);
int                     virDomainSetMaxMemory   (virDomainPtr domain,
                                                 unsigned long memory);
int                     virDomainSetMemory      (virDomainPtr domain,
                                                 unsigned long memory);
int                     virDomainSetMemoryFlags (virDomainPtr domain,
                                                 unsigned long memory,
                                                 unsigned int flags);
int                     virDomainSetMemoryStatsPeriod (virDomainPtr domain,
                                                       int period,
                                                       unsigned int flags);
int                     virDomainGetMaxVcpus    (virDomainPtr domain);
int                     virDomainGetSecurityLabel (virDomainPtr domain,
                                                   virSecurityLabelPtr seclabel);
/**
 * virDomainGetHostnameFlags:
 *
 * Since: 6.1.0
 */
typedef enum {
    VIR_DOMAIN_GET_HOSTNAME_LEASE = (1 << 0), /* Parse DHCP lease file (Since: 6.1.0) */
    VIR_DOMAIN_GET_HOSTNAME_AGENT = (1 << 1), /* Query qemu guest agent (Since: 6.1.0) */
} virDomainGetHostnameFlags;

char *                  virDomainGetHostname    (virDomainPtr domain,
                                                 unsigned int flags);
int                     virDomainGetSecurityLabelList (virDomainPtr domain,
                                                       virSecurityLabelPtr* seclabels);

/**
 * virDomainMetadataType:
 *
 * Since: 0.9.10
 */
typedef enum {
    VIR_DOMAIN_METADATA_DESCRIPTION = 0, /* Operate on <description> (Since: 0.9.10) */
    VIR_DOMAIN_METADATA_TITLE       = 1, /* Operate on <title> (Since: 0.9.10) */
    VIR_DOMAIN_METADATA_ELEMENT     = 2, /* Operate on <metadata> (Since: 0.9.10) */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_METADATA_LAST /* (Since: 0.9.10) */
# endif
} virDomainMetadataType;

int
virDomainSetMetadata(virDomainPtr domain,
                     int type,
                     const char *metadata,
                     const char *key,
                     const char *uri,
                     unsigned int flags);

char *
virDomainGetMetadata(virDomainPtr domain,
                     int type,
                     const char *uri,
                     unsigned int flags);

/*
 * XML domain description
 */

/**
 * virDomainXMLFlags:
 *
 * Flags available for virDomainGetXMLDesc
 *
 * Since: 0.3.3
 */
typedef enum {
    VIR_DOMAIN_XML_SECURE       = (1 << 0), /* dump security sensitive information too (Since: 0.3.3) */
    VIR_DOMAIN_XML_INACTIVE     = (1 << 1), /* dump inactive domain information (Since: 0.3.3) */
    VIR_DOMAIN_XML_UPDATE_CPU   = (1 << 2), /* update guest CPU requirements according to host CPU (Since: 0.8.0) */
    VIR_DOMAIN_XML_MIGRATABLE   = (1 << 3), /* dump XML suitable for migration (Since: 1.0.0) */
} virDomainXMLFlags;

/**
 * virDomainSaveImageXMLFlags:
 *
 * Since: 5.1.0
 */
typedef enum {
    VIR_DOMAIN_SAVE_IMAGE_XML_SECURE         = VIR_DOMAIN_XML_SECURE, /* dump security sensitive information too (Since: 5.1.0) */
} virDomainSaveImageXMLFlags;

char *                  virDomainGetXMLDesc     (virDomainPtr domain,
                                                 unsigned int flags);


char *                  virConnectDomainXMLFromNative(virConnectPtr conn,
                                                      const char *nativeFormat,
                                                      const char *nativeConfig,
                                                      unsigned int flags);
char *                  virConnectDomainXMLToNative(virConnectPtr conn,
                                                    const char *nativeFormat,
                                                    const char *domainXml,
                                                    unsigned int flags);

int                     virDomainBlockStats     (virDomainPtr dom,
                                                 const char *disk,
                                                 virDomainBlockStatsPtr stats,
                                                 size_t size);
int                     virDomainBlockStatsFlags (virDomainPtr dom,
                                                  const char *disk,
                                                  virTypedParameterPtr params,
                                                  int *nparams,
                                                  unsigned int flags);
int                     virDomainInterfaceStats (virDomainPtr dom,
                                                 const char *device,
                                                 virDomainInterfaceStatsPtr stats,
                                                 size_t size);

/* Management of interface parameters */

/**
 * VIR_DOMAIN_BANDWIDTH_IN_AVERAGE:
 *
 * Macro represents the inbound average of NIC bandwidth, as a uint.
 *
 * Since: 0.9.9
 */
# define VIR_DOMAIN_BANDWIDTH_IN_AVERAGE "inbound.average"

/**
 * VIR_DOMAIN_BANDWIDTH_IN_PEAK:
 *
 * Macro represents the inbound peak of NIC bandwidth, as a uint.
 *
 * Since: 0.9.9
 */
# define VIR_DOMAIN_BANDWIDTH_IN_PEAK "inbound.peak"

/**
 * VIR_DOMAIN_BANDWIDTH_IN_BURST:
 *
 * Macro represents the inbound burst of NIC bandwidth, as a uint.
 *
 * Since: 0.9.9
 */
# define VIR_DOMAIN_BANDWIDTH_IN_BURST "inbound.burst"

/**
 * VIR_DOMAIN_BANDWIDTH_IN_FLOOR:
 *
 * Macro represents the inbound floor of NIC bandwidth, as a uint.
 *
 * Since: 1.2.19
 */
# define VIR_DOMAIN_BANDWIDTH_IN_FLOOR "inbound.floor"

/**
 * VIR_DOMAIN_BANDWIDTH_OUT_AVERAGE:
 *
 * Macro represents the outbound average of NIC bandwidth, as a uint.
 *
 * Since: 0.9.9
 */
# define VIR_DOMAIN_BANDWIDTH_OUT_AVERAGE "outbound.average"

/**
 * VIR_DOMAIN_BANDWIDTH_OUT_PEAK:
 *
 * Macro represents the outbound peak of NIC bandwidth, as a uint.
 *
 * Since: 0.9.9
 */
# define VIR_DOMAIN_BANDWIDTH_OUT_PEAK "outbound.peak"

/**
 * VIR_DOMAIN_BANDWIDTH_OUT_BURST:
 *
 * Macro represents the outbound burst of NIC bandwidth, as a uint.
 *
 * Since: 0.9.9
 */
# define VIR_DOMAIN_BANDWIDTH_OUT_BURST "outbound.burst"

int                     virDomainSetInterfaceParameters (virDomainPtr dom,
                                                         const char *device,
                                                         virTypedParameterPtr params,
                                                         int nparams, unsigned int flags);
int                     virDomainGetInterfaceParameters (virDomainPtr dom,
                                                         const char *device,
                                                         virTypedParameterPtr params,
                                                         int *nparams, unsigned int flags);

/* Management of domain block devices */

int                     virDomainBlockPeek (virDomainPtr dom,
                                            const char *disk,
                                            unsigned long long offset,
                                            size_t size,
                                            void *buffer,
                                            unsigned int flags);

/**
 * virDomainBlockResizeFlags:
 *
 * Flags available for virDomainBlockResize().
 *
 * Since: 0.9.11
 */
typedef enum {
    VIR_DOMAIN_BLOCK_RESIZE_BYTES = 1 << 0, /* size in bytes instead of KiB (Since: 0.9.11) */
} virDomainBlockResizeFlags;

int                     virDomainBlockResize (virDomainPtr dom,
                                              const char *disk,
                                              unsigned long long size,
                                              unsigned int flags);

/** virDomainBlockInfo:
 *
 * This struct provides information about the size of a block device
 * backing store.
 *
 * Examples:
 *
 *  - Fully allocated raw file in filesystem:
 *       * capacity, allocation, physical: All the same
 *
 *  - Sparse raw file in filesystem:
 *       * capacity, size: logical size of the file
 *       * allocation: disk space occupied by file
 *
 *  - qcow2 file in filesystem
 *       * capacity: logical size from qcow2 header
 *       * allocation: disk space occupied by file
 *       * physical: reported size of qcow2 file
 *
 *  - qcow2 file in a block device
 *       * capacity: logical size from qcow2 header
 *       * allocation: highest qcow extent written for an active domain
 *       * physical: size of the block device container
 *
 * Since: 0.8.1
 */
typedef struct _virDomainBlockInfo virDomainBlockInfo;

/**
 * virDomainBlockInfoPtr:
 *
 * Since: 0.8.1
 */
typedef virDomainBlockInfo *virDomainBlockInfoPtr;
struct _virDomainBlockInfo {
    unsigned long long capacity;   /* logical size in bytes of the
                                    * image (how much storage the
                                    * guest will see) */
    unsigned long long allocation; /* host storage in bytes occupied
                                    * by the image (such as highest
                                    * allocated extent if there are no
                                    * holes, similar to 'du') */
    unsigned long long physical;   /* host physical size in bytes of
                                    * the image container (last
                                    * offset, similar to 'ls') */
};

int                     virDomainGetBlockInfo(virDomainPtr dom,
                                              const char *disk,
                                              virDomainBlockInfoPtr info,
                                              unsigned int flags);

/* Management of domain memory */

int                     virDomainMemoryStats (virDomainPtr dom,
                                              virDomainMemoryStatPtr stats,
                                              unsigned int nr_stats,
                                              unsigned int flags);

/**
 * virDomainMemoryFlags:
 *
 * Memory peeking flags.
 *
 * Since: 0.4.4
 */
typedef enum {
    VIR_MEMORY_VIRTUAL            = 1 << 0, /* addresses are virtual addresses (Since: 0.4.4) */
    VIR_MEMORY_PHYSICAL           = 1 << 1, /* addresses are physical addresses (Since: 0.7.0) */
} virDomainMemoryFlags;

int                     virDomainMemoryPeek (virDomainPtr dom,
                                             unsigned long long start,
                                             size_t size,
                                             void *buffer,
                                             unsigned int flags);

/**
 * virDomainDefineFlags:
 *
 * Since: 1.2.12
 */
typedef enum {
    VIR_DOMAIN_DEFINE_VALIDATE = (1 << 0), /* Validate the XML document against schema (Since: 1.2.12) */
} virDomainDefineFlags;

/*
 * defined but not running domains
 */
virDomainPtr            virDomainDefineXML      (virConnectPtr conn,
                                                 const char *xml);

virDomainPtr            virDomainDefineXMLFlags (virConnectPtr conn,
                                                 const char *xml,
                                                 unsigned int flags);
int                     virDomainUndefine       (virDomainPtr domain);

/**
 * virDomainUndefineFlagsValues:
 *
 * Since: 0.9.4
 */
typedef enum {
    VIR_DOMAIN_UNDEFINE_MANAGED_SAVE       = (1 << 0), /* Also remove any
                                                          managed save (Since: 0.9.4) */
    VIR_DOMAIN_UNDEFINE_SNAPSHOTS_METADATA = (1 << 1), /* If last use of domain,
                                                          then also remove any
                                                          snapshot metadata (Since: 0.9.5) */
    VIR_DOMAIN_UNDEFINE_NVRAM              = (1 << 2), /* Also remove any
                                                          nvram file (Since: 1.2.9) */
    VIR_DOMAIN_UNDEFINE_KEEP_NVRAM         = (1 << 3), /* Keep nvram file (Since: 2.3.0) */
    VIR_DOMAIN_UNDEFINE_CHECKPOINTS_METADATA = (1 << 4), /* If last use of domain,
                                                            then also remove any
                                                            checkpoint metadata (Since: 5.6.0) */
    VIR_DOMAIN_UNDEFINE_TPM                = (1 << 5), /* Also remove any
                                                          TPM state (Since: 8.9.0) */
    VIR_DOMAIN_UNDEFINE_KEEP_TPM           = (1 << 6), /* Keep TPM state (Since: 8.9.0) */
    /* Future undefine control flags should come here. */
} virDomainUndefineFlagsValues;


int                     virDomainUndefineFlags   (virDomainPtr domain,
                                                  unsigned int flags);
int                     virConnectNumOfDefinedDomains  (virConnectPtr conn);
int                     virConnectListDefinedDomains (virConnectPtr conn,
                                                      char **const names,
                                                      int maxnames);
/**
 * virConnectListAllDomainsFlags:
 *
 * Flags used to tune which domains are listed by virConnectListAllDomains().
 * Note that these flags come in groups; if all bits from a group are 0,
 * then that group is not used to filter results.
 *
 * Since: 0.9.13
 */
typedef enum {
    VIR_CONNECT_LIST_DOMAINS_ACTIVE         = 1 << 0, /* (Since: 0.9.13) */
    VIR_CONNECT_LIST_DOMAINS_INACTIVE       = 1 << 1, /* (Since: 0.9.13) */

    VIR_CONNECT_LIST_DOMAINS_PERSISTENT     = 1 << 2, /* (Since: 0.9.13) */
    VIR_CONNECT_LIST_DOMAINS_TRANSIENT      = 1 << 3, /* (Since: 0.9.13) */

    VIR_CONNECT_LIST_DOMAINS_RUNNING        = 1 << 4, /* (Since: 0.9.13) */
    VIR_CONNECT_LIST_DOMAINS_PAUSED         = 1 << 5, /* (Since: 0.9.13) */
    VIR_CONNECT_LIST_DOMAINS_SHUTOFF        = 1 << 6, /* (Since: 0.9.13) */
    VIR_CONNECT_LIST_DOMAINS_OTHER          = 1 << 7, /* (Since: 0.9.13) */

    VIR_CONNECT_LIST_DOMAINS_MANAGEDSAVE    = 1 << 8, /* (Since: 0.9.13) */
    VIR_CONNECT_LIST_DOMAINS_NO_MANAGEDSAVE = 1 << 9, /* (Since: 0.9.13) */

    VIR_CONNECT_LIST_DOMAINS_AUTOSTART      = 1 << 10, /* (Since: 0.9.13) */
    VIR_CONNECT_LIST_DOMAINS_NO_AUTOSTART   = 1 << 11, /* (Since: 0.9.13) */

    VIR_CONNECT_LIST_DOMAINS_HAS_SNAPSHOT   = 1 << 12, /* (Since: 0.9.13) */
    VIR_CONNECT_LIST_DOMAINS_NO_SNAPSHOT    = 1 << 13, /* (Since: 0.9.13) */

    VIR_CONNECT_LIST_DOMAINS_HAS_CHECKPOINT = 1 << 14, /* (Since: 5.6.0) */
    VIR_CONNECT_LIST_DOMAINS_NO_CHECKPOINT  = 1 << 15, /* (Since: 5.6.0) */
} virConnectListAllDomainsFlags;

int                     virConnectListAllDomains (virConnectPtr conn,
                                                  virDomainPtr **domains,
                                                  unsigned int flags);
int                     virDomainCreate         (virDomainPtr domain);
int                     virDomainCreateWithFlags (virDomainPtr domain,
                                                  unsigned int flags);

int                     virDomainCreateWithFiles (virDomainPtr domain,
                                                  unsigned int nfiles,
                                                  int *files,
                                                  unsigned int flags);

int                     virDomainGetAutostart   (virDomainPtr domain,
                                                 int *autostart);
int                     virDomainSetAutostart   (virDomainPtr domain,
                                                 int autostart);

/**
 * virVcpuState:
 *
 * structure for information about a virtual CPU in a domain.
 *
 * Since: 0.1.4
 */
typedef enum {
    VIR_VCPU_OFFLINE    = 0,    /* the virtual CPU is offline (Since: 0.1.4) */
    VIR_VCPU_RUNNING    = 1,    /* the virtual CPU is running (Since: 0.1.4) */
    VIR_VCPU_BLOCKED    = 2,    /* the virtual CPU is blocked on resource (Since: 0.1.4) */

# ifdef VIR_ENUM_SENTINELS
    VIR_VCPU_LAST /* (Since: 0.9.10) */
# endif
} virVcpuState;

/**
 * virVcpuHostCpuState:
 *
 * Since: 6.10.0
 */
typedef enum {
    VIR_VCPU_INFO_CPU_OFFLINE     = -1, /* the vCPU is offline (Since: 6.10.0) */
    VIR_VCPU_INFO_CPU_UNAVAILABLE = -2, /* the hypervisor does not expose real CPU information (Since: 6.10.0) */
} virVcpuHostCpuState;

/**
 * virVcpuInfo:
 *
 * Since: 0.1.4
 */
typedef struct _virVcpuInfo virVcpuInfo;
struct _virVcpuInfo {
    unsigned int number;        /* virtual CPU number */
    int state;                  /* value from virVcpuState */
    unsigned long long cpuTime; /* CPU time used, in nanoseconds */
    int cpu;                    /* real CPU number, or one of the values from virVcpuHostCpuState */
};

/**
 * virVcpuInfoPtr:
 *
 * Since: 0.1.4
 */
typedef virVcpuInfo *virVcpuInfoPtr;

/**
 * virDomainVcpuFlags:
 *
 * Flags for controlling virtual CPU hot-plugging.
 *
 * Since: 0.8.5
 */
typedef enum {
    VIR_DOMAIN_VCPU_CURRENT = VIR_DOMAIN_AFFECT_CURRENT, /* See virDomainModificationImpact (Since: 0.9.4) */
    VIR_DOMAIN_VCPU_LIVE    = VIR_DOMAIN_AFFECT_LIVE, /* See virDomainModificationImpact (Since: 0.8.5) */
    VIR_DOMAIN_VCPU_CONFIG  = VIR_DOMAIN_AFFECT_CONFIG, /* See virDomainModificationImpact (Since: 0.8.5) */

    VIR_DOMAIN_VCPU_MAXIMUM = (1 << 2), /* Max rather than current count (Since: 0.8.5) */
    VIR_DOMAIN_VCPU_GUEST   = (1 << 3), /* Modify state of the cpu in the guest (Since: 1.1.0) */
    VIR_DOMAIN_VCPU_HOTPLUGGABLE = (1 << 4), /* Make vcpus added hot(un)pluggable (Since: 2.4.0) */
} virDomainVcpuFlags;

int                     virDomainSetVcpus       (virDomainPtr domain,
                                                 unsigned int nvcpus);
int                     virDomainSetVcpusFlags  (virDomainPtr domain,
                                                 unsigned int nvcpus,
                                                 unsigned int flags);
int                     virDomainGetVcpusFlags  (virDomainPtr domain,
                                                 unsigned int flags);

int                     virDomainPinVcpu        (virDomainPtr domain,
                                                 unsigned int vcpu,
                                                 unsigned char *cpumap,
                                                 int maplen);
int                     virDomainPinVcpuFlags   (virDomainPtr domain,
                                                 unsigned int vcpu,
                                                 unsigned char *cpumap,
                                                 int maplen,
                                                 unsigned int flags);

int                     virDomainGetVcpuPinInfo (virDomainPtr domain,
                                                 int ncpumaps,
                                                 unsigned char *cpumaps,
                                                 int maplen,
                                                 unsigned int flags);

int                     virDomainPinEmulator   (virDomainPtr domain,
                                                unsigned char *cpumap,
                                                int maplen,
                                                unsigned int flags);

int                     virDomainGetEmulatorPinInfo (virDomainPtr domain,
                                                     unsigned char *cpumaps,
                                                     int maplen,
                                                     unsigned int flags);

/**
 * virDomainIOThreadInfo:
 *
 * The data structure for information about all IOThreads in a domain
 *
 * Since: 1.2.14
 */
typedef struct _virDomainIOThreadInfo virDomainIOThreadInfo;


/**
 * virDomainIOThreadInfoPtr:
 *
 * Since: 1.2.14
 */
typedef virDomainIOThreadInfo *virDomainIOThreadInfoPtr;
struct _virDomainIOThreadInfo {
    unsigned int iothread_id;          /* IOThread ID */
    unsigned char *cpumap;             /* CPU map for thread. A pointer to an */
                                       /* array of real CPUs (in 8-bit bytes) */
    int cpumaplen;                     /* cpumap size */
};

void                 virDomainIOThreadInfoFree(virDomainIOThreadInfoPtr info);

int                  virDomainGetIOThreadInfo(virDomainPtr domain,
                                               virDomainIOThreadInfoPtr **info,
                                               unsigned int flags);
int                  virDomainPinIOThread(virDomainPtr domain,
                                          unsigned int iothread_id,
                                          unsigned char *cpumap,
                                          int maplen,
                                          unsigned int flags);
int                  virDomainAddIOThread(virDomainPtr domain,
                                          unsigned int iothread_id,
                                          unsigned int flags);
int                  virDomainDelIOThread(virDomainPtr domain,
                                          unsigned int iothread_id,
                                          unsigned int flags);

/* IOThread set parameters */

/**
 * VIR_DOMAIN_IOTHREAD_POLL_MAX_NS:
 *
 * The maximum polling time that can be used by polling algorithm in ns.
 * The polling time starts at 0 (zero) and is the time spent by the guest
 * to process IOThread data before returning the CPU to the host. The
 * polling time will be dynamically modified over time based on the
 * poll_grow and poll_shrink parameters provided. A value set too large
 * will cause more CPU time to be allocated the guest. A value set too
 * small will not provide enough cycles for the guest to process data.
 * Accepted type is VIR_TYPED_PARAM_ULLONG.
 *
 * Since: 4.10.0
 */
# define VIR_DOMAIN_IOTHREAD_POLL_MAX_NS "poll_max_ns"

/**
 * VIR_DOMAIN_IOTHREAD_POLL_GROW:
 *
 * This provides a value for the dynamic polling adjustment algorithm to
 * use to grow its polling interval up to the poll_max_ns value. A value
 * of 0 (zero) allows the hypervisor to choose its own value. The algorithm
 * to use for adjustment is hypervisor specific.
 * Accepted type is VIR_TYPED_PARAM_UINT or since 9.3.0 VIR_TYPED_PARAM_ULLONG.
 *
 * Since: 4.10.0
 */
# define VIR_DOMAIN_IOTHREAD_POLL_GROW "poll_grow"

/**
 * VIR_DOMAIN_IOTHREAD_POLL_SHRINK:
 *
 * This provides a value for the dynamic polling adjustment algorithm to
 * use to shrink its polling interval when the polling interval exceeds
 * the poll_max_ns value. A value of 0 (zero) allows the hypervisor to
 * choose its own value. The algorithm to use for adjustment is hypervisor
 * specific.
 * Accepted type is VIR_TYPED_PARAM_UINT or since 9.3.0 VIR_TYPED_PARAM_ULLONG.
 *
 * Since: 4.10.0
 */
# define VIR_DOMAIN_IOTHREAD_POLL_SHRINK "poll_shrink"

/**
 * VIR_DOMAIN_IOTHREAD_THREAD_POOL_MIN:
 *
 * Sets the lower bound for thread pool size. A value of -1 disables this bound
 * leaving hypervisor use its default value, though this value is not accepted
 * for running domains. Accepted type is VIR_TYPED_PARAM_INT.
 *
 * Since: 8.5.0
 */
# define VIR_DOMAIN_IOTHREAD_THREAD_POOL_MIN "thread_pool_min"

/**
 * VIR_DOMAIN_IOTHREAD_THREAD_POOL_MAX:
 *
 * Sets the upper bound for thread pool size. A value of -1 disables this bound
 * leaving hypervisor use its default value, though this value is not accepted
 * for running domains. Since the upper band has to be equal to or greater than
 * lower bound value of 0 is not accepted. Accepted type is
 * VIR_TYPED_PARAM_INT.
 *
 * Since: 8.5.0
 */
# define VIR_DOMAIN_IOTHREAD_THREAD_POOL_MAX "thread_pool_max"

int                  virDomainSetIOThreadParams(virDomainPtr domain,
                                                unsigned int iothread_id,
                                                virTypedParameterPtr params,
                                                int nparams,
                                                unsigned int flags);


/**
 * VIR_USE_CPU:
 * @cpumap: pointer to a bit map of real CPUs (in 8-bit bytes) (IN/OUT)
 * @cpu: the physical CPU number
 *
 * This macro is to be used in conjunction with virDomainPinVcpu() API.
 * It sets the bit (CPU usable) of the related cpu in cpumap.
 *
 * Since: 0.1.4
 */
# define VIR_USE_CPU(cpumap, cpu) ((cpumap)[(cpu) / 8] |= (1 << ((cpu) % 8)))

/**
 * VIR_UNUSE_CPU:
 * @cpumap: pointer to a bit map of real CPUs (in 8-bit bytes) (IN/OUT)
 * @cpu: the physical CPU number
 *
 * This macro is to be used in conjunction with virDomainPinVcpu() API.
 * It resets the bit (CPU not usable) of the related cpu in cpumap.
 *
 * Since: 0.1.4
 */
# define VIR_UNUSE_CPU(cpumap, cpu) ((cpumap)[(cpu) / 8] &= ~(1 << ((cpu) % 8)))

/**
 * VIR_CPU_USED:
 * @cpumap: pointer to a bit map of real CPUs (in 8-bit bytes) (IN)
 * @cpu: the physical CPU number
 *
 * This macro can be used in conjunction with virNodeGetCPUMap() API.
 * It returns non-zero if the bit of the related CPU is set.
 *
 * Since: 1.0.0
 */
# define VIR_CPU_USED(cpumap, cpu) ((cpumap)[(cpu) / 8] & (1 << ((cpu) % 8)))

/**
 * VIR_CPU_MAPLEN:
 * @cpu: number of physical CPUs
 *
 * This macro is to be used in conjunction with virDomainPinVcpu() API.
 * It returns the length (in bytes) required to store the complete
 * CPU map between a single virtual & all physical CPUs of a domain.
 *
 * Since: 0.1.4
 */
# define VIR_CPU_MAPLEN(cpu) (((cpu) + 7) / 8)


int                     virDomainGetVcpus       (virDomainPtr domain,
                                                 virVcpuInfoPtr info,
                                                 int maxinfo,
                                                 unsigned char *cpumaps,
                                                 int maplen);

/**
 * VIR_CPU_USABLE:
 * @cpumaps: pointer to an array of cpumap (in 8-bit bytes) (IN)
 * @maplen: the length (in bytes) of one cpumap
 * @vcpu: the virtual CPU number
 * @cpu: the physical CPU number
 *
 * This macro is to be used in conjunction with virDomainGetVcpus() API.
 * VIR_CPU_USABLE macro returns a non-zero value (true) if the cpu
 * is usable by the vcpu, and 0 otherwise.
 *
 * Since: 0.1.4
 */
# define VIR_CPU_USABLE(cpumaps, maplen, vcpu, cpu) \
    VIR_CPU_USED(VIR_GET_CPUMAP(cpumaps, maplen, vcpu), cpu)

/**
 * VIR_COPY_CPUMAP:
 * @cpumaps: pointer to an array of cpumap (in 8-bit bytes) (IN)
 * @maplen: the length (in bytes) of one cpumap
 * @vcpu: the virtual CPU number
 * @cpumap: pointer to a cpumap (in 8-bit bytes) (OUT)
 *      This cpumap must be previously allocated by the caller
 *      (ie: malloc(maplen))
 *
 * This macro is to be used in conjunction with virDomainGetVcpus() and
 * virDomainPinVcpu() APIs. VIR_COPY_CPUMAP macro extracts the cpumap of
 * the specified vcpu from cpumaps array and copies it into cpumap to be used
 * later by virDomainPinVcpu() API.
 *
 * Since: 0.1.4
 */
# define VIR_COPY_CPUMAP(cpumaps, maplen, vcpu, cpumap) \
    memcpy(cpumap, VIR_GET_CPUMAP(cpumaps, maplen, vcpu), maplen)


/**
 * VIR_GET_CPUMAP:
 * @cpumaps: pointer to an array of cpumap (in 8-bit bytes) (IN)
 * @maplen: the length (in bytes) of one cpumap
 * @vcpu: the virtual CPU number
 *
 * This macro is to be used in conjunction with virDomainGetVcpus() and
 * virDomainPinVcpu() APIs. VIR_GET_CPUMAP macro returns a pointer to the
 * cpumap of the specified vcpu from cpumaps array.
 *
 * Since: 0.1.4
 */
# define VIR_GET_CPUMAP(cpumaps, maplen, vcpu) (&((cpumaps)[(vcpu) * (maplen)]))


/**
 * virDomainDeviceModifyFlags:
 *
 * Since: 0.7.7
 */
typedef enum {
    VIR_DOMAIN_DEVICE_MODIFY_CURRENT = VIR_DOMAIN_AFFECT_CURRENT, /* See virDomainModificationImpact (Since: 0.7.7) */
    VIR_DOMAIN_DEVICE_MODIFY_LIVE    = VIR_DOMAIN_AFFECT_LIVE, /* See virDomainModificationImpact (Since: 0.7.7) */
    VIR_DOMAIN_DEVICE_MODIFY_CONFIG  = VIR_DOMAIN_AFFECT_CONFIG, /* See virDomainModificationImpact (Since: 0.7.7) */

    VIR_DOMAIN_DEVICE_MODIFY_FORCE = (1 << 2), /* Forcibly modify device (ex. force eject a cdrom) (Since: 0.8.6) */
} virDomainDeviceModifyFlags;

int virDomainAttachDevice(virDomainPtr domain, const char *xml);
int virDomainDetachDevice(virDomainPtr domain, const char *xml);

int virDomainAttachDeviceFlags(virDomainPtr domain,
                               const char *xml, unsigned int flags);
int virDomainDetachDeviceFlags(virDomainPtr domain,
                               const char *xml, unsigned int flags);
int virDomainUpdateDeviceFlags(virDomainPtr domain,
                               const char *xml, unsigned int flags);

int virDomainDetachDeviceAlias(virDomainPtr domain,
                               const char *alias, unsigned int flags);

/**
 * virDomainStatsRecord:
 *
 * Since: 1.2.8
 */
typedef struct _virDomainStatsRecord virDomainStatsRecord;

/**
 * virDomainStatsRecordPtr:
 *
 * Since: 1.2.8
 */
typedef virDomainStatsRecord *virDomainStatsRecordPtr;
struct _virDomainStatsRecord {
    virDomainPtr dom;
    virTypedParameterPtr params;
    int nparams;
};

/**
 * virDomainStatsTypes:
 *
 * Since: 1.2.8
 */
typedef enum {
    VIR_DOMAIN_STATS_STATE = (1 << 0), /* return domain state (Since: 1.2.8) */
    VIR_DOMAIN_STATS_CPU_TOTAL = (1 << 1), /* return domain CPU info (Since: 1.2.9) */
    VIR_DOMAIN_STATS_BALLOON = (1 << 2), /* return domain balloon info (Since: 1.2.9) */
    VIR_DOMAIN_STATS_VCPU = (1 << 3), /* return domain virtual CPU info (Since: 1.2.9) */
    VIR_DOMAIN_STATS_INTERFACE = (1 << 4), /* return domain interfaces info (Since: 1.2.9) */
    VIR_DOMAIN_STATS_BLOCK = (1 << 5), /* return domain block info (Since: 1.2.9) */
    VIR_DOMAIN_STATS_PERF = (1 << 6), /* return domain perf event info (Since: 1.3.3) */
    VIR_DOMAIN_STATS_IOTHREAD = (1 << 7), /* return iothread poll info (Since: 4.10.0) */
    VIR_DOMAIN_STATS_MEMORY = (1 << 8), /* return domain memory info (Since: 6.0.0) */
    VIR_DOMAIN_STATS_DIRTYRATE = (1 << 9), /* return domain dirty rate info (Since: 7.2.0) */
    VIR_DOMAIN_STATS_VM = (1 << 10), /* return vm info (Since: 8.9.0) */
} virDomainStatsTypes;

/**
 * virConnectGetAllDomainStatsFlags:
 *
 * Since: 1.2.8
 */
typedef enum {
    VIR_CONNECT_GET_ALL_DOMAINS_STATS_ACTIVE = VIR_CONNECT_LIST_DOMAINS_ACTIVE, /* (Since: 1.2.8) */
    VIR_CONNECT_GET_ALL_DOMAINS_STATS_INACTIVE = VIR_CONNECT_LIST_DOMAINS_INACTIVE, /* (Since: 1.2.8) */

    VIR_CONNECT_GET_ALL_DOMAINS_STATS_PERSISTENT = VIR_CONNECT_LIST_DOMAINS_PERSISTENT, /* (Since: 1.2.8) */
    VIR_CONNECT_GET_ALL_DOMAINS_STATS_TRANSIENT = VIR_CONNECT_LIST_DOMAINS_TRANSIENT, /* (Since: 1.2.8) */

    VIR_CONNECT_GET_ALL_DOMAINS_STATS_RUNNING = VIR_CONNECT_LIST_DOMAINS_RUNNING, /* (Since: 1.2.8) */
    VIR_CONNECT_GET_ALL_DOMAINS_STATS_PAUSED = VIR_CONNECT_LIST_DOMAINS_PAUSED, /* (Since: 1.2.8) */
    VIR_CONNECT_GET_ALL_DOMAINS_STATS_SHUTOFF = VIR_CONNECT_LIST_DOMAINS_SHUTOFF, /* (Since: 1.2.8) */
    VIR_CONNECT_GET_ALL_DOMAINS_STATS_OTHER = VIR_CONNECT_LIST_DOMAINS_OTHER, /* (Since: 1.2.8) */

    VIR_CONNECT_GET_ALL_DOMAINS_STATS_NOWAIT = 1 << 29, /* report statistics that can be obtained
                                                           immediately without any blocking (Since: 4.5.0) */
    VIR_CONNECT_GET_ALL_DOMAINS_STATS_BACKING = 1 << 30, /* include backing chain for block stats (Since: 1.2.12) */
    VIR_CONNECT_GET_ALL_DOMAINS_STATS_ENFORCE_STATS = 1U << 31, /* enforce requested stats (Since: 1.2.8) */
} virConnectGetAllDomainStatsFlags;

int virConnectGetAllDomainStats(virConnectPtr conn,
                                unsigned int stats,
                                virDomainStatsRecordPtr **retStats,
                                unsigned int flags);

int virDomainListGetStats(virDomainPtr *doms,
                          unsigned int stats,
                          virDomainStatsRecordPtr **retStats,
                          unsigned int flags);

void virDomainStatsRecordListFree(virDomainStatsRecordPtr *stats);

/*
 * Perf Event API
 */

/**
 * VIR_PERF_PARAM_CMT:
 *
 * Macro for typed parameter name that represents CMT perf event
 * which can be used to measure the usage of cache (bytes) by
 * applications running on the platform. It corresponds to the
 * "perf.cmt" field in the *Stats APIs.
 *
 * Since: 1.3.3
 */
# define VIR_PERF_PARAM_CMT "cmt"

/**
 * VIR_PERF_PARAM_MBMT:
 *
 * Macro for typed parameter name that represents MBMT perf event
 * which can be used to monitor total system bandwidth (bytes/s)
 * from one level of cache to another. It corresponds to the
 * "perf.mbmt" field in the *Stats APIs.
 *
 * Since: 1.3.5
 */
# define VIR_PERF_PARAM_MBMT "mbmt"

/**
 * VIR_PERF_PARAM_MBML:
 *
 * Macro for typed parameter name that represents MBML perf event
 * which can be used to monitor the amount of data (bytes/s) sent
 * through the memory controller on the socket. It corresponds to
 * the "perf.mbml" field in the *Stats APIs.
 *
 * Since: 1.3.5
 */
# define VIR_PERF_PARAM_MBML "mbml"

/**
 * VIR_PERF_PARAM_CACHE_MISSES:
 *
 * Macro for typed parameter name that represents cache_misses perf
 * event which can be used to measure the count of cache misses by
 * applications running on the platform. It corresponds to the
 * "perf.cache_misses" field in the *Stats APIs.
 *
 * Since: 2.3.0
 */
# define VIR_PERF_PARAM_CACHE_MISSES "cache_misses"

/**
 * VIR_PERF_PARAM_CACHE_REFERENCES:
 *
 * Macro for typed parameter name that represents cache_references
 * perf event which can be used to measure the count of cache hits
 * by applications running on the platform. It corresponds to the
 * "perf.cache_references" field in the *Stats APIs.
 *
 * Since: 2.3.0
 */
# define VIR_PERF_PARAM_CACHE_REFERENCES "cache_references"

/**
 * VIR_PERF_PARAM_INSTRUCTIONS:
 *
 * Macro for typed parameter name that represents instructions perf
 * event which can be used to measure the count of instructions
 * by applications running on the platform. It corresponds to the
 * "perf.instructions" field in the *Stats APIs.
 *
 * Since: 2.3.0
 */
# define VIR_PERF_PARAM_INSTRUCTIONS "instructions"

/**
 * VIR_PERF_PARAM_CPU_CYCLES:
 *
 * Macro for typed parameter name that represents cpu_cycles perf event
 * describing the total/elapsed cpu cycles. This can be used to measure
 * how many cpu cycles one instruction needs.
 * It corresponds to the "perf.cpu_cycles" field in the *Stats APIs.
 *
 * Since: 2.3.0
 */
# define VIR_PERF_PARAM_CPU_CYCLES "cpu_cycles"

/**
 * VIR_PERF_PARAM_BRANCH_INSTRUCTIONS:
 *
 * Macro for typed parameter name that represents branch_instructions
 * perf event which can be used to measure the count of branch instructions
 * by applications running on the platform. It corresponds to the
 * "perf.branch_instructions" field in the *Stats APIs.
 *
 * Since: 3.0.0
 */
# define VIR_PERF_PARAM_BRANCH_INSTRUCTIONS "branch_instructions"

/**
 * VIR_PERF_PARAM_BRANCH_MISSES:
 *
 * Macro for typed parameter name that represents branch_misses
 * perf event which can be used to measure the count of branch misses
 * by applications running on the platform. It corresponds to the
 * "perf.branch_misses" field in the *Stats APIs.
 *
 * Since: 3.0.0
 */
# define VIR_PERF_PARAM_BRANCH_MISSES "branch_misses"

/**
 * VIR_PERF_PARAM_BUS_CYCLES:
 *
 * Macro for typed parameter name that represents bus_cycles
 * perf event which can be used to measure the count of bus cycles
 * by applications running on the platform. It corresponds to the
 * "perf.bus_cycles" field in the *Stats APIs.
 *
 * Since: 3.0.0
 */
# define VIR_PERF_PARAM_BUS_CYCLES "bus_cycles"

/**
 * VIR_PERF_PARAM_STALLED_CYCLES_FRONTEND:
 *
 * Macro for typed parameter name that represents stalled_cycles_frontend
 * perf event which can be used to measure the count of stalled cpu cycles
 * in the frontend of the instruction processor pipeline by applications
 * running on the platform. It corresponds to the
 * "perf.stalled_cycles_frontend" field in the *Stats APIs.
 *
 * Since: 3.0.0
 */
# define VIR_PERF_PARAM_STALLED_CYCLES_FRONTEND "stalled_cycles_frontend"

/**
 * VIR_PERF_PARAM_STALLED_CYCLES_BACKEND:
 *
 * Macro for typed parameter name that represents stalled_cycles_backend
 * perf event which can be used to measure the count of stalled cpu cycles
 * in the backend of the instruction processor pipeline by application
 * running on the platform. It corresponds to the
 * "perf.stalled_cycles_backend" field in the *Stats APIs.
 *
 * Since: 3.0.0
 */
# define VIR_PERF_PARAM_STALLED_CYCLES_BACKEND "stalled_cycles_backend"

/**
 * VIR_PERF_PARAM_REF_CPU_CYCLES:
 *
 * Macro for typed parameter name that represents ref_cpu_cycles
 * perf event which can be used to measure the count of total cpu
 * cycles not affected by CPU frequency scaling by applications
 * running on the platform. It corresponds to the
 * "perf.ref_cpu_cycles" field in the *Stats APIs.
 *
 * Since: 3.0.0
 */
# define VIR_PERF_PARAM_REF_CPU_CYCLES "ref_cpu_cycles"

/**
 * VIR_PERF_PARAM_CPU_CLOCK:
 *
 * Macro for typed parameter name that represents cpu_clock
 * perf event which can be used to measure the count of cpu
 * clock time by applications running on the platform. It
 * corresponds to the "perf.cpu_clock" field in the *Stats
 * APIs.
 *
 * Since: 3.2.0
 */
# define VIR_PERF_PARAM_CPU_CLOCK "cpu_clock"

/**
 * VIR_PERF_PARAM_TASK_CLOCK:
 *
 * Macro for typed parameter name that represents task_clock
 * perf event which can be used to measure the count of task
 * clock time by applications running on the platform. It
 * corresponds to the "perf.task_clock" field in the *Stats
 * APIs.
 *
 * Since: 3.2.0
 */
# define VIR_PERF_PARAM_TASK_CLOCK "task_clock"

/**
 * VIR_PERF_PARAM_PAGE_FAULTS:
 *
 * Macro for typed parameter name that represents page_faults
 * perf event which can be used to measure the count of page
 * faults by applications running on the platform. It corresponds
 * to the "perf.page_faults" field in the *Stats APIs.
 *
 * Since: 3.2.0
 */
# define VIR_PERF_PARAM_PAGE_FAULTS "page_faults"

/**
 * VIR_PERF_PARAM_CONTEXT_SWITCHES:
 *
 * Macro for typed parameter name that represents context_switches
 * perf event which can be used to measure the count of context
 * switches by applications running on the platform. It corresponds
 * to the "perf.context_switches" field in the *Stats APIs.
 *
 * Since: 3.2.0
 */
# define VIR_PERF_PARAM_CONTEXT_SWITCHES "context_switches"

/**
 * VIR_PERF_PARAM_CPU_MIGRATIONS:
 *
 * Macro for typed parameter name that represents cpu_migrations
 * perf event which can be used to measure the count of cpu
 * migrations by applications running on the platform. It corresponds
 * to the "perf.cpu_migrations" field in the *Stats APIs.
 *
 * Since: 3.2.0
 */
# define VIR_PERF_PARAM_CPU_MIGRATIONS "cpu_migrations"

/**
 * VIR_PERF_PARAM_PAGE_FAULTS_MIN:
 *
 * Macro for typed parameter name that represents page_faults_min
 * perf event which can be used to measure the count of minor page
 * faults by applications running on the platform. It corresponds
 * to the "perf.page_faults_min" field in the *Stats APIs.
 *
 * Since: 3.2.0
 */
# define VIR_PERF_PARAM_PAGE_FAULTS_MIN  "page_faults_min"

/**
 * VIR_PERF_PARAM_PAGE_FAULTS_MAJ:
 *
 * Macro for typed parameter name that represents page_faults_maj
 * perf event which can be used to measure the count of major page
 * faults by applications running on the platform. It corresponds
 * to the "perf.page_faults_maj" field in the *Stats APIs.
 *
 * Since: 3.2.0
 */
# define VIR_PERF_PARAM_PAGE_FAULTS_MAJ  "page_faults_maj"

/**
 * VIR_PERF_PARAM_ALIGNMENT_FAULTS:
 *
 * Macro for typed parameter name that represents alignment_faults
 * perf event which can be used to measure the count of alignment
 * faults by applications running on the platform. It corresponds
 * to the "perf.alignment_faults" field in the *Stats APIs.
 *
 * Since: 3.2.0
 */
# define VIR_PERF_PARAM_ALIGNMENT_FAULTS  "alignment_faults"

/**
 * VIR_PERF_PARAM_EMULATION_FAULTS:
 *
 * Macro for typed parameter name that represents emulation_faults
 * perf event which can be used to measure the count of emulation
 * faults by applications running on the platform. It corresponds
 * to the "perf.emulation_faults" field in the *Stats APIs.
 *
 * Since: 3.2.0
 */
# define VIR_PERF_PARAM_EMULATION_FAULTS  "emulation_faults"

int virDomainGetPerfEvents(virDomainPtr dom,
                           virTypedParameterPtr *params,
                           int *nparams,
                           unsigned int flags);
int virDomainSetPerfEvents(virDomainPtr dom,
                           virTypedParameterPtr params,
                           int nparams,
                           unsigned int flags);

/*
 * BlockJob API
 */

/**
 * virDomainBlockJobType:
 *
 * Describes various possible block jobs.
 *
 * Since: 0.9.4
 */
typedef enum {
    /* Placeholder (Since: 0.9.4) */
    VIR_DOMAIN_BLOCK_JOB_TYPE_UNKNOWN = 0,

    /* Block Pull (virDomainBlockPull, or virDomainBlockRebase without
     * flags), job ends on completion
     *
     * Since: 0.9.4
     */
    VIR_DOMAIN_BLOCK_JOB_TYPE_PULL = 1,

    /* Block Copy (virDomainBlockCopy, or virDomainBlockRebase with
     * flags), job exists as long as mirroring is active
     *
     * Since: 0.9.12
     */
    VIR_DOMAIN_BLOCK_JOB_TYPE_COPY = 2,

    /* Block Commit (virDomainBlockCommit without flags), job ends on
     * completion
     *
     * Since: 0.10.2
     */
    VIR_DOMAIN_BLOCK_JOB_TYPE_COMMIT = 3,

    /* Active Block Commit (virDomainBlockCommit with flags), job
     * exists as long as sync is active
     *
     * Since: 1.2.6
     */
    VIR_DOMAIN_BLOCK_JOB_TYPE_ACTIVE_COMMIT = 4,

    /* Backup (virDomainBackupBegin)
     *
     * Since: 6.0.0
     */
    VIR_DOMAIN_BLOCK_JOB_TYPE_BACKUP = 5,

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_BLOCK_JOB_TYPE_LAST /* (Since: 0.9.10) */
# endif
} virDomainBlockJobType;

/**
 * virDomainBlockJobAbortFlags:
 *
 * VIR_DOMAIN_BLOCK_JOB_ABORT_ASYNC: Request only, do not wait for completion
 * VIR_DOMAIN_BLOCK_JOB_ABORT_PIVOT: Pivot to new file when ending a copy or
 *                                   active commit job
 *
 * Since: 0.9.12
 */
typedef enum {
    VIR_DOMAIN_BLOCK_JOB_ABORT_ASYNC = 1 << 0, /* (Since: 0.9.12) */
    VIR_DOMAIN_BLOCK_JOB_ABORT_PIVOT = 1 << 1, /* (Since: 0.9.12) */
} virDomainBlockJobAbortFlags;

int virDomainBlockJobAbort(virDomainPtr dom, const char *disk,
                           unsigned int flags);

/**
 * virDomainBlockJobInfoFlags:
 *
 * Flags for use with virDomainGetBlockJobInfo
 *
 * Since: 1.2.9
 */
typedef enum {
    VIR_DOMAIN_BLOCK_JOB_INFO_BANDWIDTH_BYTES = 1 << 0, /* bandwidth in bytes/s
                                                           instead of MiB/s (Since: 1.2.9) */
} virDomainBlockJobInfoFlags;

/**
 * virDomainBlockJobCursor:
 *
 * An iterator for monitoring block job operations
 *
 * Since: 0.9.4
 */
typedef unsigned long long virDomainBlockJobCursor;

/**
 * virDomainBlockJobInfo:
 *
 * Since: 0.9.4
 */
typedef struct _virDomainBlockJobInfo virDomainBlockJobInfo;
struct _virDomainBlockJobInfo {
    int type; /* virDomainBlockJobType */
    unsigned long bandwidth; /* either bytes/s or MiB/s, according to flags */

    /*
     * The following fields provide an indication of block job progress.  @cur
     * indicates the current position and will be between 0 and @end.  @end is
     * the final cursor position for this operation and represents completion.
     * To approximate progress, divide @cur by @end.
     */
    virDomainBlockJobCursor cur;
    virDomainBlockJobCursor end;
};

/**
 * virDomainBlockJobInfoPtr:
 *
 * Since: 0.9.4
 */
typedef virDomainBlockJobInfo *virDomainBlockJobInfoPtr;

int virDomainGetBlockJobInfo(virDomainPtr dom, const char *disk,
                             virDomainBlockJobInfoPtr info,
                             unsigned int flags);

/**
 * virDomainBlockJobSetSpeedFlags:
 *
 * Flags for use with virDomainBlockJobSetSpeed
 *
 * Since: 1.2.9
 */
typedef enum {
    VIR_DOMAIN_BLOCK_JOB_SPEED_BANDWIDTH_BYTES = 1 << 0, /* bandwidth in bytes/s
                                                            instead of MiB/s (Since: 1.2.9) */
} virDomainBlockJobSetSpeedFlags;

int virDomainBlockJobSetSpeed(virDomainPtr dom, const char *disk,
                              unsigned long bandwidth, unsigned int flags);

/**
 * virDomainBlockPullFlags:
 *
 * Flags for use with virDomainBlockPull (values chosen to be a subset of the
 * flags for virDomainBlockRebase)
 *
 * Since: 1.2.9
 */
typedef enum {
    VIR_DOMAIN_BLOCK_PULL_BANDWIDTH_BYTES = 1 << 6, /* bandwidth in bytes/s
                                                       instead of MiB/s (Since: 1.2.9) */
} virDomainBlockPullFlags;

int virDomainBlockPull(virDomainPtr dom, const char *disk,
                       unsigned long bandwidth, unsigned int flags);

/**
 * virDomainBlockRebaseFlags:
 *
 * Flags available for virDomainBlockRebase().
 *
 * Since: 0.9.12
 */
typedef enum {
    VIR_DOMAIN_BLOCK_REBASE_SHALLOW   = 1 << 0, /* Limit copy to top of source
                                                   backing chain (Since: 0.9.12) */
    VIR_DOMAIN_BLOCK_REBASE_REUSE_EXT = 1 << 1, /* Reuse existing external
                                                   file for a copy (Since: 0.9.12) */
    VIR_DOMAIN_BLOCK_REBASE_COPY_RAW  = 1 << 2, /* Make destination file raw (Since: 0.9.12) */
    VIR_DOMAIN_BLOCK_REBASE_COPY      = 1 << 3, /* Start a copy job (Since: 0.9.12) */
    VIR_DOMAIN_BLOCK_REBASE_RELATIVE  = 1 << 4, /* Keep backing chain
                                                   referenced using relative
                                                   names (Since: 1.2.7) */
    VIR_DOMAIN_BLOCK_REBASE_COPY_DEV  = 1 << 5, /* Treat destination as block
                                                   device instead of file (Since: 1.2.9) */
    VIR_DOMAIN_BLOCK_REBASE_BANDWIDTH_BYTES = 1 << 6, /* bandwidth in bytes/s
                                                         instead of MiB/s (Since: 1.2.9) */
} virDomainBlockRebaseFlags;

int virDomainBlockRebase(virDomainPtr dom, const char *disk,
                         const char *base, unsigned long bandwidth,
                         unsigned int flags);

/**
 * virDomainBlockCopyFlags:
 *
 * Flags available for virDomainBlockCopy().
 *
 * Since: 1.2.8
 */
typedef enum {
    /* Limit copy to top of source backing chain (Since: 1.2.8) */
    VIR_DOMAIN_BLOCK_COPY_SHALLOW   = 1 << 0,

    /* Reuse existing external file for a copy (Since: 1.2.8) */
    VIR_DOMAIN_BLOCK_COPY_REUSE_EXT = 1 << 1,

    /* Don't force usage of recoverable job for the copy operation (Since: 3.5.0) */
    VIR_DOMAIN_BLOCK_COPY_TRANSIENT_JOB = 1 << 2,

    /* Force the copy job to synchronously propagate guest writes into
     * the destination image, so that the copy is guaranteed to converge
     *
     * Since: 8.0.0
     */
    VIR_DOMAIN_BLOCK_COPY_SYNCHRONOUS_WRITES = 1 << 3,
} virDomainBlockCopyFlags;

/**
 * VIR_DOMAIN_BLOCK_COPY_BANDWIDTH:
 * Macro for the virDomainBlockCopy bandwidth tunable: it represents
 * the maximum bandwidth in bytes/s, and is used while getting the
 * copy operation into the mirrored phase, with a type of ullong.  For
 * compatibility with virDomainBlockJobSetSpeed(), values larger than
 * 2^52 bytes/sec (a 32-bit MiB/s value) may be rejected on input due
 * to overflow considerations (but do you really have an interface
 * with that much bandwidth?), and values larger than 2^31 bytes/sec
 * may cause overflow problems if queried in bytes/sec.  Hypervisors
 * may further restrict the set of valid values. Specifying 0 is the
 * same as omitting this parameter, to request no bandwidth limiting.
 * Some hypervisors may lack support for this parameter, while still
 * allowing a subsequent change of bandwidth via
 * virDomainBlockJobSetSpeed().  The actual speed can be determined
 * with virDomainGetBlockJobInfo().
 *
 * Since: 1.2.8
 */
# define VIR_DOMAIN_BLOCK_COPY_BANDWIDTH "bandwidth"

/**
 * VIR_DOMAIN_BLOCK_COPY_GRANULARITY:
 * Macro for the virDomainBlockCopy granularity tunable: it represents
 * the granularity in bytes at which the copy operation recognizes
 * dirty blocks that need copying, as an unsigned int.  Hypervisors may
 * restrict this to be a power of two or fall within a certain
 * range. Specifying 0 is the same as omitting this parameter, to
 * request the hypervisor default.
 *
 * Since: 1.2.8
 */
# define VIR_DOMAIN_BLOCK_COPY_GRANULARITY "granularity"

/**
 * VIR_DOMAIN_BLOCK_COPY_BUF_SIZE:
 * Macro for the virDomainBlockCopy buffer size tunable: it represents
 * how much data in bytes can be in flight between source and destination,
 * as an unsigned long long. Specifying 0 is the same as omitting this
 * parameter, to request the hypervisor default.
 *
 * Since: 1.2.8
 */
# define VIR_DOMAIN_BLOCK_COPY_BUF_SIZE "buf-size"

int virDomainBlockCopy(virDomainPtr dom, const char *disk,
                       const char *destxml,
                       virTypedParameterPtr params,
                       int nparams,
                       unsigned int flags);

/**
 * virDomainBlockCommitFlags:
 *
 * Flags available for virDomainBlockCommit().
 *
 * Since: 0.10.2
 */
typedef enum {
    VIR_DOMAIN_BLOCK_COMMIT_SHALLOW = 1 << 0, /* NULL base means next backing
                                                 file, not whole chain (Since: 0.10.2) */
    VIR_DOMAIN_BLOCK_COMMIT_DELETE  = 1 << 1, /* Delete any files that are now
                                                 invalid after their contents
                                                 have been committed (Since: 0.10.2) */
    VIR_DOMAIN_BLOCK_COMMIT_ACTIVE  = 1 << 2, /* Allow a two-phase commit when
                                                 top is the active layer (Since: 1.2.6) */
    VIR_DOMAIN_BLOCK_COMMIT_RELATIVE = 1 << 3, /* keep the backing chain
                                                  referenced using relative
                                                  names (Since: 1.2.7) */
    VIR_DOMAIN_BLOCK_COMMIT_BANDWIDTH_BYTES = 1 << 4, /* bandwidth in bytes/s
                                                         instead of MiB/s (Since: 1.2.9) */
} virDomainBlockCommitFlags;

int virDomainBlockCommit(virDomainPtr dom, const char *disk, const char *base,
                         const char *top, unsigned long bandwidth,
                         unsigned int flags);


/* Block I/O throttling support */

/**
 * VIR_DOMAIN_BLOCK_IOTUNE_TOTAL_BYTES_SEC:
 *
 * Macro for the BlockIoTune tunable weight: it represents the total
 * bytes per second permitted through a block device, as a ullong.
 *
 * Since: 0.9.8
 */
# define VIR_DOMAIN_BLOCK_IOTUNE_TOTAL_BYTES_SEC "total_bytes_sec"

/**
 * VIR_DOMAIN_BLOCK_IOTUNE_READ_BYTES_SEC:
 *
 * Macro for the BlockIoTune tunable weight: it represents the read
 * bytes per second permitted through a block device, as a ullong.
 *
 * Since: 0.9.8
 */
# define VIR_DOMAIN_BLOCK_IOTUNE_READ_BYTES_SEC "read_bytes_sec"

/**
 * VIR_DOMAIN_BLOCK_IOTUNE_WRITE_BYTES_SEC:
 *
 * Macro for the BlockIoTune tunable weight: it represents the write
 * bytes per second permitted through a block device, as a ullong.
 *
 * Since: 0.9.8
 */
# define VIR_DOMAIN_BLOCK_IOTUNE_WRITE_BYTES_SEC "write_bytes_sec"

/**
 * VIR_DOMAIN_BLOCK_IOTUNE_TOTAL_IOPS_SEC:
 *
 * Macro for the BlockIoTune tunable weight: it represents the total
 * I/O operations per second permitted through a block device, as a ullong.
 *
 * Since: 0.9.8
 */
# define VIR_DOMAIN_BLOCK_IOTUNE_TOTAL_IOPS_SEC "total_iops_sec"

/**
 * VIR_DOMAIN_BLOCK_IOTUNE_READ_IOPS_SEC:
 *
 * Macro for the BlockIoTune tunable weight: it represents the read
 * I/O operations per second permitted through a block device, as a ullong.
 *
 * Since: 0.9.8
 */
# define VIR_DOMAIN_BLOCK_IOTUNE_READ_IOPS_SEC "read_iops_sec"

/**
 * VIR_DOMAIN_BLOCK_IOTUNE_WRITE_IOPS_SEC:
 * Macro for the BlockIoTune tunable weight: it represents the write
 * I/O operations per second permitted through a block device, as a ullong.
 *
 * Since: 0.9.8
 */
# define VIR_DOMAIN_BLOCK_IOTUNE_WRITE_IOPS_SEC "write_iops_sec"

/**
 * VIR_DOMAIN_BLOCK_IOTUNE_TOTAL_BYTES_SEC_MAX:
 *
 * Macro for the BlockIoTune tunable weight: it represents the maximum total
 * bytes per second permitted through a block device, as a ullong.
 *
 * Since: 1.2.11
 */
# define VIR_DOMAIN_BLOCK_IOTUNE_TOTAL_BYTES_SEC_MAX "total_bytes_sec_max"

/**
 * VIR_DOMAIN_BLOCK_IOTUNE_READ_BYTES_SEC_MAX:
 *
 * Macro for the BlockIoTune tunable weight: it represents the maximum read
 * bytes per second permitted through a block device, as a ullong.
 *
 * Since: 1.2.11
 */
# define VIR_DOMAIN_BLOCK_IOTUNE_READ_BYTES_SEC_MAX "read_bytes_sec_max"

/**
 * VIR_DOMAIN_BLOCK_IOTUNE_WRITE_BYTES_SEC_MAX:
 *
 * Macro for the BlockIoTune tunable weight: it represents the maximum write
 * bytes per second permitted through a block device, as a ullong.
 *
 * Since: 1.2.11
 */
# define VIR_DOMAIN_BLOCK_IOTUNE_WRITE_BYTES_SEC_MAX "write_bytes_sec_max"

/**
 * VIR_DOMAIN_BLOCK_IOTUNE_TOTAL_IOPS_SEC_MAX:
 *
 * Macro for the BlockIoTune tunable weight: it represents the maximum
 * I/O operations per second permitted through a block device, as a ullong.
 *
 * Since: 1.2.11
 */
# define VIR_DOMAIN_BLOCK_IOTUNE_TOTAL_IOPS_SEC_MAX "total_iops_sec_max"

/**
 * VIR_DOMAIN_BLOCK_IOTUNE_READ_IOPS_SEC_MAX:
 *
 * Macro for the BlockIoTune tunable weight: it represents the maximum read
 * I/O operations per second permitted through a block device, as a ullong.
 *
 * Since: 1.2.11
 */
# define VIR_DOMAIN_BLOCK_IOTUNE_READ_IOPS_SEC_MAX "read_iops_sec_max"

/**
 * VIR_DOMAIN_BLOCK_IOTUNE_WRITE_IOPS_SEC_MAX:
 * Macro for the BlockIoTune tunable weight: it represents the maximum write
 * I/O operations per second permitted through a block device, as a ullong.
 *
 * Since: 1.2.11
 */
# define VIR_DOMAIN_BLOCK_IOTUNE_WRITE_IOPS_SEC_MAX "write_iops_sec_max"

/**
 * VIR_DOMAIN_BLOCK_IOTUNE_TOTAL_BYTES_SEC_MAX_LENGTH:
 *
 * Macro for the BlockIoTune tunable weight: it represents the duration in
 * seconds for the burst allowed by total_bytes_sec_max, as a ullong.
 *
 * Since: 2.4.0
 */
# define VIR_DOMAIN_BLOCK_IOTUNE_TOTAL_BYTES_SEC_MAX_LENGTH "total_bytes_sec_max_length"

/**
 * VIR_DOMAIN_BLOCK_IOTUNE_READ_BYTES_SEC_MAX_LENGTH:
 *
 * Macro for the BlockIoTune tunable weight: it represents the duration in
 * seconds for the burst allowed by read_bytes_sec_max, as a ullong.
 *
 * Since: 2.4.0
 */
# define VIR_DOMAIN_BLOCK_IOTUNE_READ_BYTES_SEC_MAX_LENGTH "read_bytes_sec_max_length"

/**
 * VIR_DOMAIN_BLOCK_IOTUNE_WRITE_BYTES_SEC_MAX_LENGTH:
 *
 * Macro for the BlockIoTune tunable weight: it represents the duration in
 * seconds for the burst allowed by write_bytes_sec_max, as a ullong.
 *
 * Since: 2.4.0
 */
# define VIR_DOMAIN_BLOCK_IOTUNE_WRITE_BYTES_SEC_MAX_LENGTH "write_bytes_sec_max_length"

/**
 * VIR_DOMAIN_BLOCK_IOTUNE_TOTAL_IOPS_SEC_MAX_LENGTH:
 *
 * Macro for the BlockIoTune tunable weight: it represents the duration in
 * seconds for the burst allowed by total_iops_sec_max, as a ullong.
 *
 * Since: 2.4.0
 */
# define VIR_DOMAIN_BLOCK_IOTUNE_TOTAL_IOPS_SEC_MAX_LENGTH "total_iops_sec_max_length"

/**
 * VIR_DOMAIN_BLOCK_IOTUNE_READ_IOPS_SEC_MAX_LENGTH:
 *
 * Macro for the BlockIoTune tunable weight: it represents the duration in
 * seconds for the burst allowed by read_iops_sec_max, as a ullong.
 *
 * Since: 2.4.0
 */
# define VIR_DOMAIN_BLOCK_IOTUNE_READ_IOPS_SEC_MAX_LENGTH "read_iops_sec_max_length"

/**
 * VIR_DOMAIN_BLOCK_IOTUNE_WRITE_IOPS_SEC_MAX_LENGTH:
 *
 * Macro for the BlockIoTune tunable weight: it represents the duration in
 * seconds for the burst allowed by write_iops_sec_max, as a ullong.
 *
 * Since: 2.4.0
 */
# define VIR_DOMAIN_BLOCK_IOTUNE_WRITE_IOPS_SEC_MAX_LENGTH "write_iops_sec_max_length"

/**
 * VIR_DOMAIN_BLOCK_IOTUNE_SIZE_IOPS_SEC:
 * Macro for the BlockIoTune tunable weight: it represents the size
 * I/O operations per second permitted through a block device, as a ullong.
 *
 * Since: 1.2.11
 */
# define VIR_DOMAIN_BLOCK_IOTUNE_SIZE_IOPS_SEC "size_iops_sec"

/**
 * VIR_DOMAIN_BLOCK_IOTUNE_GROUP_NAME:
 * Macro for the BlockIoTune tunable weight: it represents a group name to
 * allow sharing of I/O throttling quota between multiple drives, as a string.
 *
 * Since: 3.0.0
 */
# define VIR_DOMAIN_BLOCK_IOTUNE_GROUP_NAME "group_name"

int
virDomainSetBlockIoTune(virDomainPtr dom,
                        const char *disk,
                        virTypedParameterPtr params,
                        int nparams,
                        unsigned int flags);
int
virDomainGetBlockIoTune(virDomainPtr dom,
                        const char *disk,
                        virTypedParameterPtr params,
                        int *nparams,
                        unsigned int flags);

/**
 * virDomainDiskErrorCode:
 *
 * Disk I/O error.
 *
 * Since: 0.9.10
 */
typedef enum {
    VIR_DOMAIN_DISK_ERROR_NONE      = 0, /* no error (Since: 0.9.10) */
    VIR_DOMAIN_DISK_ERROR_UNSPEC    = 1, /* unspecified I/O error (Since: 0.9.10) */
    VIR_DOMAIN_DISK_ERROR_NO_SPACE  = 2, /* no space left on the device (Since: 0.9.10) */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_DISK_ERROR_LAST /* (Since: 0.9.10) */
# endif
} virDomainDiskErrorCode;

/**
 * virDomainDiskError:
 *
 * Since: 0.9.10
 */
typedef struct _virDomainDiskError virDomainDiskError;

/**
 * virDomainDiskErrorPtr:
 *
 * Since: 0.9.10
 */
typedef virDomainDiskError *virDomainDiskErrorPtr;

struct _virDomainDiskError {
    char *disk; /* disk target */
    int error;  /* virDomainDiskErrorCode */
};

int virDomainGetDiskErrors(virDomainPtr dom,
                           virDomainDiskErrorPtr errors,
                           unsigned int maxerrors,
                           unsigned int flags);



/**
 * virKeycodeSet:
 *
 * Enum to specify which keycode mapping is in use for virDomainSendKey().
 *
 * Since: 0.9.3
 */
typedef enum {
    VIR_KEYCODE_SET_LINUX          = 0, /* (Since: 0.9.3) */
    VIR_KEYCODE_SET_XT             = 1, /* (Since: 0.9.3) */
    VIR_KEYCODE_SET_ATSET1         = 2, /* (Since: 0.9.3) */
    VIR_KEYCODE_SET_ATSET2         = 3, /* (Since: 0.9.3) */
    VIR_KEYCODE_SET_ATSET3         = 4, /* (Since: 0.9.3) */
    VIR_KEYCODE_SET_OSX            = 5, /* (Since: 0.9.4) */
    VIR_KEYCODE_SET_XT_KBD         = 6, /* (Since: 0.9.4) */
    VIR_KEYCODE_SET_USB            = 7, /* (Since: 0.9.4) */
    VIR_KEYCODE_SET_WIN32          = 8, /* (Since: 0.9.4) */
    VIR_KEYCODE_SET_QNUM           = 9, /* (Since: 4.2.0) */

# ifdef VIR_ENUM_SENTINELS
    VIR_KEYCODE_SET_LAST
    /*
     * NB: this enum value will increase over time as new keycode sets are
     * added to the libvirt API. It reflects the last keycode set supported
     * by this version of the libvirt API.
     *
     * Since: 0.9.4
     */
# endif
} virKeycodeSet;

/**
 * VIR_KEYCODE_SET_RFB:
 *
 * Compatibility alias for VIR_KEYCODE_SET_QNUM, which replaced it since 4.2.0.
 *
 * Since: 0.9.5
 */
# define VIR_KEYCODE_SET_RFB VIR_KEYCODE_SET_QNUM

/**
 * VIR_DOMAIN_SEND_KEY_MAX_KEYS:
 *
 * Maximum number of keycodes that can be sent in one virDomainSendKey() call.
 *
 * Since: 0.9.3
 */
# define VIR_DOMAIN_SEND_KEY_MAX_KEYS  16

int virDomainSendKey(virDomainPtr domain,
                     unsigned int codeset,
                     unsigned int holdtime,
                     unsigned int *keycodes,
                     int nkeycodes,
                     unsigned int flags);

/**
 * virDomainProcessSignal:
 *
 * These just happen to match Linux signal numbers. The numbers
 * will be mapped to whatever the SIGNUM is in the guest OS in
 * question by the agent delivering the signal. The names are
 * based on the POSIX / XSI signal standard though.
 *
 * Do not rely on all values matching Linux though. It is possible
 * this enum might be extended with new signals which have no
 * mapping in Linux.
 *
 * Since: 1.0.1
 */
typedef enum {
    VIR_DOMAIN_PROCESS_SIGNAL_NOP        =  0, /* No constant in POSIX/Linux (Since: 1.0.1) */
    VIR_DOMAIN_PROCESS_SIGNAL_HUP        =  1, /* SIGHUP (Since: 1.0.1) */
    VIR_DOMAIN_PROCESS_SIGNAL_INT        =  2, /* SIGINT (Since: 1.0.1) */
    VIR_DOMAIN_PROCESS_SIGNAL_QUIT       =  3, /* SIGQUIT (Since: 1.0.1) */
    VIR_DOMAIN_PROCESS_SIGNAL_ILL        =  4, /* SIGILL (Since: 1.0.1) */
    VIR_DOMAIN_PROCESS_SIGNAL_TRAP       =  5, /* SIGTRAP (Since: 1.0.1) */
    VIR_DOMAIN_PROCESS_SIGNAL_ABRT       =  6, /* SIGABRT (Since: 1.0.1) */
    VIR_DOMAIN_PROCESS_SIGNAL_BUS        =  7, /* SIGBUS (Since: 1.0.1) */
    VIR_DOMAIN_PROCESS_SIGNAL_FPE        =  8, /* SIGFPE (Since: 1.0.1) */
    VIR_DOMAIN_PROCESS_SIGNAL_KILL       =  9, /* SIGKILL (Since: 1.0.1) */

    VIR_DOMAIN_PROCESS_SIGNAL_USR1       = 10, /* SIGUSR1 (Since: 1.0.1) */
    VIR_DOMAIN_PROCESS_SIGNAL_SEGV       = 11, /* SIGSEGV (Since: 1.0.1) */
    VIR_DOMAIN_PROCESS_SIGNAL_USR2       = 12, /* SIGUSR2 (Since: 1.0.1) */
    VIR_DOMAIN_PROCESS_SIGNAL_PIPE       = 13, /* SIGPIPE (Since: 1.0.1) */
    VIR_DOMAIN_PROCESS_SIGNAL_ALRM       = 14, /* SIGALRM (Since: 1.0.1) */
    VIR_DOMAIN_PROCESS_SIGNAL_TERM       = 15, /* SIGTERM (Since: 1.0.1) */
    VIR_DOMAIN_PROCESS_SIGNAL_STKFLT     = 16, /* Not in POSIX (SIGSTKFLT on Linux (Since: 1.0.1) )*/
    VIR_DOMAIN_PROCESS_SIGNAL_CHLD       = 17, /* SIGCHLD (Since: 1.0.1) */
    VIR_DOMAIN_PROCESS_SIGNAL_CONT       = 18, /* SIGCONT (Since: 1.0.1) */
    VIR_DOMAIN_PROCESS_SIGNAL_STOP       = 19, /* SIGSTOP (Since: 1.0.1) */

    VIR_DOMAIN_PROCESS_SIGNAL_TSTP       = 20, /* SIGTSTP (Since: 1.0.1) */
    VIR_DOMAIN_PROCESS_SIGNAL_TTIN       = 21, /* SIGTTIN (Since: 1.0.1) */
    VIR_DOMAIN_PROCESS_SIGNAL_TTOU       = 22, /* SIGTTOU (Since: 1.0.1) */
    VIR_DOMAIN_PROCESS_SIGNAL_URG        = 23, /* SIGURG (Since: 1.0.1) */
    VIR_DOMAIN_PROCESS_SIGNAL_XCPU       = 24, /* SIGXCPU (Since: 1.0.1) */
    VIR_DOMAIN_PROCESS_SIGNAL_XFSZ       = 25, /* SIGXFSZ (Since: 1.0.1) */
    VIR_DOMAIN_PROCESS_SIGNAL_VTALRM     = 26, /* SIGVTALRM (Since: 1.0.1) */
    VIR_DOMAIN_PROCESS_SIGNAL_PROF       = 27, /* SIGPROF (Since: 1.0.1) */
    VIR_DOMAIN_PROCESS_SIGNAL_WINCH      = 28, /* Not in POSIX (SIGWINCH on Linux) (Since: 1.0.1) */
    VIR_DOMAIN_PROCESS_SIGNAL_POLL       = 29, /* SIGPOLL (also known as SIGIO on Linux) (Since: 1.0.1) */

    VIR_DOMAIN_PROCESS_SIGNAL_PWR        = 30, /* Not in POSIX (SIGPWR on Linux) (Since: 1.0.1) */
    VIR_DOMAIN_PROCESS_SIGNAL_SYS        = 31, /* SIGSYS (also known as SIGUNUSED on Linux) (Since: 1.0.1) */
    VIR_DOMAIN_PROCESS_SIGNAL_RT0        = 32, /* SIGRTMIN (Since: 1.0.1) */
    VIR_DOMAIN_PROCESS_SIGNAL_RT1        = 33, /* SIGRTMIN + 1 (Since: 1.0.1) */
    VIR_DOMAIN_PROCESS_SIGNAL_RT2        = 34, /* SIGRTMIN + 2 (Since: 1.0.1) */
    VIR_DOMAIN_PROCESS_SIGNAL_RT3        = 35, /* SIGRTMIN + 3 (Since: 1.0.1) */
    VIR_DOMAIN_PROCESS_SIGNAL_RT4        = 36, /* SIGRTMIN + 4 (Since: 1.0.1) */
    VIR_DOMAIN_PROCESS_SIGNAL_RT5        = 37, /* SIGRTMIN + 5 (Since: 1.0.1) */
    VIR_DOMAIN_PROCESS_SIGNAL_RT6        = 38, /* SIGRTMIN + 6 (Since: 1.0.1) */
    VIR_DOMAIN_PROCESS_SIGNAL_RT7        = 39, /* SIGRTMIN + 7 (Since: 1.0.1) */

    VIR_DOMAIN_PROCESS_SIGNAL_RT8        = 40, /* SIGRTMIN + 8 (Since: 1.0.1) */
    VIR_DOMAIN_PROCESS_SIGNAL_RT9        = 41, /* SIGRTMIN + 9 (Since: 1.0.1) */
    VIR_DOMAIN_PROCESS_SIGNAL_RT10       = 42, /* SIGRTMIN + 10 (Since: 1.0.1) */
    VIR_DOMAIN_PROCESS_SIGNAL_RT11       = 43, /* SIGRTMIN + 11 (Since: 1.0.1) */
    VIR_DOMAIN_PROCESS_SIGNAL_RT12       = 44, /* SIGRTMIN + 12 (Since: 1.0.1) */
    VIR_DOMAIN_PROCESS_SIGNAL_RT13       = 45, /* SIGRTMIN + 13 (Since: 1.0.1) */
    VIR_DOMAIN_PROCESS_SIGNAL_RT14       = 46, /* SIGRTMIN + 14 (Since: 1.0.1) */
    VIR_DOMAIN_PROCESS_SIGNAL_RT15       = 47, /* SIGRTMIN + 15 (Since: 1.0.1) */
    VIR_DOMAIN_PROCESS_SIGNAL_RT16       = 48, /* SIGRTMIN + 16 (Since: 1.0.1) */
    VIR_DOMAIN_PROCESS_SIGNAL_RT17       = 49, /* SIGRTMIN + 17 (Since: 1.0.1) */

    VIR_DOMAIN_PROCESS_SIGNAL_RT18       = 50, /* SIGRTMIN + 18 (Since: 1.0.1) */
    VIR_DOMAIN_PROCESS_SIGNAL_RT19       = 51, /* SIGRTMIN + 19 (Since: 1.0.1) */
    VIR_DOMAIN_PROCESS_SIGNAL_RT20       = 52, /* SIGRTMIN + 20 (Since: 1.0.1) */
    VIR_DOMAIN_PROCESS_SIGNAL_RT21       = 53, /* SIGRTMIN + 21 (Since: 1.0.1) */
    VIR_DOMAIN_PROCESS_SIGNAL_RT22       = 54, /* SIGRTMIN + 22 (Since: 1.0.1) */
    VIR_DOMAIN_PROCESS_SIGNAL_RT23       = 55, /* SIGRTMIN + 23 (Since: 1.0.1) */
    VIR_DOMAIN_PROCESS_SIGNAL_RT24       = 56, /* SIGRTMIN + 24 (Since: 1.0.1) */
    VIR_DOMAIN_PROCESS_SIGNAL_RT25       = 57, /* SIGRTMIN + 25 (Since: 1.0.1) */
    VIR_DOMAIN_PROCESS_SIGNAL_RT26       = 58, /* SIGRTMIN + 26 (Since: 1.0.1) */
    VIR_DOMAIN_PROCESS_SIGNAL_RT27       = 59, /* SIGRTMIN + 27 (Since: 1.0.1) */

    VIR_DOMAIN_PROCESS_SIGNAL_RT28       = 60, /* SIGRTMIN + 28 (Since: 1.0.1) */
    VIR_DOMAIN_PROCESS_SIGNAL_RT29       = 61, /* SIGRTMIN + 29 (Since: 1.0.1) */
    VIR_DOMAIN_PROCESS_SIGNAL_RT30       = 62, /* SIGRTMIN + 30 (Since: 1.0.1) */
    VIR_DOMAIN_PROCESS_SIGNAL_RT31       = 63, /* SIGRTMIN + 31 (Since: 1.0.1) */
    VIR_DOMAIN_PROCESS_SIGNAL_RT32       = 64, /* SIGRTMIN + 32 / SIGRTMAX (Since: 1.0.1) */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_PROCESS_SIGNAL_LAST /* (Since: 1.0.1) */
# endif
} virDomainProcessSignal;

int virDomainSendProcessSignal(virDomainPtr domain,
                               long long pid_value,
                               unsigned int signum,
                               unsigned int flags);

/*
 * Deprecated calls
 */
virDomainPtr            virDomainCreateLinux    (virConnectPtr conn,
                                                 const char *xmlDesc,
                                                 unsigned int flags);


/*
 * Domain Event Notification
 */

/**
 * virDomainEventType:
 *
 * a virDomainEventType is emitted during domain lifecycle events
 *
 * Since: 0.5.0
 */
typedef enum {
    VIR_DOMAIN_EVENT_DEFINED = 0, /* (Since: 0.5.0) */
    VIR_DOMAIN_EVENT_UNDEFINED = 1, /* (Since: 0.5.0) */
    VIR_DOMAIN_EVENT_STARTED = 2, /* (Since: 0.5.0) */
    VIR_DOMAIN_EVENT_SUSPENDED = 3, /* (Since: 0.5.0) */
    VIR_DOMAIN_EVENT_RESUMED = 4, /* (Since: 0.5.0) */
    VIR_DOMAIN_EVENT_STOPPED = 5, /* (Since: 0.5.0) */
    VIR_DOMAIN_EVENT_SHUTDOWN = 6, /* (Since: 0.9.8) */
    VIR_DOMAIN_EVENT_PMSUSPENDED = 7, /* (Since: 0.10.2) */
    VIR_DOMAIN_EVENT_CRASHED = 8, /* (Since: 1.1.1) */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_EVENT_LAST /* (Since: 0.9.10) */
# endif
} virDomainEventType;

/**
 * virDomainEventDefinedDetailType:
 *
 * Details on the cause of a 'defined' lifecycle event
 *
 * Since: 0.5.0
 */
typedef enum {
    VIR_DOMAIN_EVENT_DEFINED_ADDED = 0,     /* Newly created config file (Since: 0.5.0) */
    VIR_DOMAIN_EVENT_DEFINED_UPDATED = 1,   /* Changed config file (Since: 0.5.0) */
    VIR_DOMAIN_EVENT_DEFINED_RENAMED = 2,   /* Domain was renamed (Since: 1.2.19) */
    VIR_DOMAIN_EVENT_DEFINED_FROM_SNAPSHOT = 3,   /* Config was restored from a snapshot (Since: 1.3.3) */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_EVENT_DEFINED_LAST /* (Since: 0.9.10) */
# endif
} virDomainEventDefinedDetailType;

/**
 * virDomainEventUndefinedDetailType:
 *
 * Details on the cause of an 'undefined' lifecycle event
 *
 * Since: 0.5.0
 */
typedef enum {
    VIR_DOMAIN_EVENT_UNDEFINED_REMOVED = 0, /* Deleted the config file (Since: 0.5.0) */
    VIR_DOMAIN_EVENT_UNDEFINED_RENAMED = 1, /* Domain was renamed (Since: 1.2.19) */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_EVENT_UNDEFINED_LAST /* (Since: 0.9.10) */
# endif
} virDomainEventUndefinedDetailType;

/**
 * virDomainEventStartedDetailType:
 *
 * Details on the cause of a 'started' lifecycle event
 *
 * Since: 0.5.0
 */
typedef enum {
    VIR_DOMAIN_EVENT_STARTED_BOOTED = 0,   /* Normal startup from boot (Since: 0.5.0) */
    VIR_DOMAIN_EVENT_STARTED_MIGRATED = 1, /* Incoming migration from another host (Since: 0.5.0) */
    VIR_DOMAIN_EVENT_STARTED_RESTORED = 2, /* Restored from a state file (Since: 0.5.0) */
    VIR_DOMAIN_EVENT_STARTED_FROM_SNAPSHOT = 3, /* Restored from snapshot (Since: 0.8.0) */
    VIR_DOMAIN_EVENT_STARTED_WAKEUP = 4,   /* Started due to wakeup event (Since: 0.9.11) */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_EVENT_STARTED_LAST /* (Since: 0.9.10) */
# endif
} virDomainEventStartedDetailType;

/**
 * virDomainEventSuspendedDetailType:
 *
 * Details on the cause of a 'suspended' lifecycle event
 *
 * Since: 0.5.0
 */
typedef enum {
    VIR_DOMAIN_EVENT_SUSPENDED_PAUSED = 0,   /* Normal suspend due to admin pause (Since: 0.5.0) */
    VIR_DOMAIN_EVENT_SUSPENDED_MIGRATED = 1, /* Suspended for offline migration (Since: 0.5.0) */
    VIR_DOMAIN_EVENT_SUSPENDED_IOERROR = 2,  /* Suspended due to a disk I/O error (Since: 0.8.0) */
    VIR_DOMAIN_EVENT_SUSPENDED_WATCHDOG = 3,  /* Suspended due to a watchdog firing (Since: 0.8.0) */
    VIR_DOMAIN_EVENT_SUSPENDED_RESTORED = 4,  /* Restored from paused state file (Since: 0.9.5) */
    VIR_DOMAIN_EVENT_SUSPENDED_FROM_SNAPSHOT = 5, /* Restored from paused snapshot (Since: 0.9.5) */
    VIR_DOMAIN_EVENT_SUSPENDED_API_ERROR = 6, /* Some APIs (e.g., migration, snapshot) internally need to suspend a domain. This event detail is used when resume operation at the end of such API fails. (Since: 1.0.1) */
    VIR_DOMAIN_EVENT_SUSPENDED_POSTCOPY = 7, /* suspended for post-copy migration (Since: 1.3.3) */
    VIR_DOMAIN_EVENT_SUSPENDED_POSTCOPY_FAILED = 8, /* suspended after failed post-copy (Since: 1.3.3) */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_EVENT_SUSPENDED_LAST /* (Since: 0.9.10) */
# endif
} virDomainEventSuspendedDetailType;

/**
 * virDomainEventResumedDetailType:
 *
 * Details on the cause of a 'resumed' lifecycle event
 *
 * Since: 0.5.0
 */
typedef enum {
    VIR_DOMAIN_EVENT_RESUMED_UNPAUSED = 0,   /* Normal resume due to admin unpause (Since: 0.5.0) */
    VIR_DOMAIN_EVENT_RESUMED_MIGRATED = 1,   /* Resumed for completion of migration (Since: 0.5.0) */
    VIR_DOMAIN_EVENT_RESUMED_FROM_SNAPSHOT = 2, /* Resumed from snapshot (Since: 0.9.5) */
    VIR_DOMAIN_EVENT_RESUMED_POSTCOPY = 3,   /* Resumed, but migration is still
                                                running in post-copy mode (Since: 1.3.3) */
    VIR_DOMAIN_EVENT_RESUMED_POSTCOPY_FAILED = 4, /* Running, but migration failed in post-copy (Since: 8.5.0) */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_EVENT_RESUMED_LAST /* (Since: 0.9.10) */
# endif
} virDomainEventResumedDetailType;

/**
 * virDomainEventStoppedDetailType:
 *
 * Details on the cause of a 'stopped' lifecycle event
 *
 * Since: 0.5.0
 */
typedef enum {
    VIR_DOMAIN_EVENT_STOPPED_SHUTDOWN = 0,  /* Normal shutdown (Since: 0.5.0) */
    VIR_DOMAIN_EVENT_STOPPED_DESTROYED = 1, /* Forced poweroff from host (Since: 0.5.0) */
    VIR_DOMAIN_EVENT_STOPPED_CRASHED = 2,   /* Guest crashed (Since: 0.5.0) */
    VIR_DOMAIN_EVENT_STOPPED_MIGRATED = 3,  /* Migrated off to another host (Since: 0.5.0) */
    VIR_DOMAIN_EVENT_STOPPED_SAVED = 4,     /* Saved to a state file (Since: 0.5.0) */
    VIR_DOMAIN_EVENT_STOPPED_FAILED = 5,    /* Host emulator/mgmt failed (Since: 0.5.0) */
    VIR_DOMAIN_EVENT_STOPPED_FROM_SNAPSHOT = 6, /* offline snapshot loaded (Since: 0.8.0) */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_EVENT_STOPPED_LAST /* (Since: 0.9.10) */
# endif
} virDomainEventStoppedDetailType;


/**
 * virDomainEventShutdownDetailType:
 *
 * Details on the cause of a 'shutdown' lifecycle event
 *
 * Since: 0.9.8
 */
typedef enum {
    /* Guest finished shutdown sequence (Since: 0.9.8) */
    VIR_DOMAIN_EVENT_SHUTDOWN_FINISHED = 0,

    /* Domain finished shutting down after request from the guest itself
     * (e.g. hardware-specific action) (Since: 3.4.0) */
    VIR_DOMAIN_EVENT_SHUTDOWN_GUEST = 1,

    /* Domain finished shutting down after request from the host (e.g. killed by
     * a signal)
     *
     * Since: 3.4.0
     */
    VIR_DOMAIN_EVENT_SHUTDOWN_HOST = 2,

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_EVENT_SHUTDOWN_LAST /* (Since: 0.9.10) */
# endif
} virDomainEventShutdownDetailType;

/**
 * virDomainEventPMSuspendedDetailType:
 *
 * Details on the cause of a 'pmsuspended' lifecycle event
 *
 * Since: 0.10.2
 */
typedef enum {
    VIR_DOMAIN_EVENT_PMSUSPENDED_MEMORY = 0, /* Guest was PM suspended to memory (Since: 0.10.2) */
    VIR_DOMAIN_EVENT_PMSUSPENDED_DISK = 1, /* Guest was PM suspended to disk (Since: 1.0.0) */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_EVENT_PMSUSPENDED_LAST /* (Since: 0.10.2) */
# endif
} virDomainEventPMSuspendedDetailType;

/**
 * virDomainEventCrashedDetailType:
 *
 * Details on the cause of a 'crashed' lifecycle event
 *
 * Since: 1.1.1
 */
typedef enum {
    VIR_DOMAIN_EVENT_CRASHED_PANICKED = 0, /* Guest was panicked (Since: 1.1.1) */
    VIR_DOMAIN_EVENT_CRASHED_CRASHLOADED = 1, /* Guest was crashloaded (Since: 6.1.0) */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_EVENT_CRASHED_LAST /* (Since: 1.1.1) */
# endif
} virDomainEventCrashedDetailType;

/**
 * virDomainMemoryFailureRecipientType:
 *
 * Recipient of a memory failure event.
 *
 * Since: 6.9.0
 */
typedef enum {
    /* memory failure at hypersivor memory address space (Since: 6.9.0) */
    VIR_DOMAIN_EVENT_MEMORY_FAILURE_RECIPIENT_HYPERVISOR = 0,

    /* memory failure at guest memory address space (Since: 6.9.0) */
    VIR_DOMAIN_EVENT_MEMORY_FAILURE_RECIPIENT_GUEST = 1,

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_EVENT_MEMORY_FAILURE_RECIPIENT_LAST /* (Since: 6.9.0) */
# endif
} virDomainMemoryFailureRecipientType;


/**
 * virDomainMemoryFailureActionType:
 *
 * Action of a memory failure event.
 *
 * Since: 6.9.0
 */
typedef enum {
    /* the memory failure could be ignored. This will only be the case for
     * action-optional failures.
     *
     * Since: 6.9.0
     */
    VIR_DOMAIN_EVENT_MEMORY_FAILURE_ACTION_IGNORE = 0,

    /* memory failure occurred in guest memory, the guest enabled MCE handling
     * mechanism, and hypervisor could inject the MCE into the guest
     * successfully.
     *
     * Since: 6.9.0
     */
    VIR_DOMAIN_EVENT_MEMORY_FAILURE_ACTION_INJECT = 1,

    /* the failure is unrecoverable.  This occurs for action-required failures
     * if the recipient is the hypervisor; hypervisor will exit.
     *
     * Since: 6.9.0
     */
    VIR_DOMAIN_EVENT_MEMORY_FAILURE_ACTION_FATAL = 2,

    /* the failure is unrecoverable but confined to the guest. This occurs if
     * the recipient is a guest which is not ready to handle memory failures.
     *
     * Since: 6.9.0
     */
    VIR_DOMAIN_EVENT_MEMORY_FAILURE_ACTION_RESET = 3,

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_EVENT_MEMORY_FAILURE_ACTION_LAST /* (Since: 6.9.0) */
# endif
} virDomainMemoryFailureActionType;


/**
 * virDomainMemoryFailureFlags:
 *
 * Since: 6.9.0
 */
typedef enum {
    /* whether a memory failure event is action-required or action-optional
     * (e.g. a failure during memory scrub). (Since: 6.9.0) */
    VIR_DOMAIN_MEMORY_FAILURE_ACTION_REQUIRED = (1 << 0),

    /* whether the failure occurred while the previous failure was still in
     * progress.
     *
     * Since: 6.9.0
     */
    VIR_DOMAIN_MEMORY_FAILURE_RECURSIVE = (1 << 1),
} virDomainMemoryFailureFlags;


/**
 * virConnectDomainEventCallback:
 * @conn: virConnect connection
 * @dom: The domain on which the event occurred
 * @event: The specific virDomainEventType which occurred
 * @detail: event specific detail information (virDomainEvent*DetailType)
 * @opaque: opaque user data
 *
 * A callback function to be registered, and called when a domain event occurs
 *
 * Returns 0 (the return value is currently ignored)
 *
 * Since: 0.5.0
 */
typedef int (*virConnectDomainEventCallback)(virConnectPtr conn,
                                             virDomainPtr dom,
                                             int event,
                                             int detail,
                                             void *opaque);

int virConnectDomainEventRegister(virConnectPtr conn,
                                  virConnectDomainEventCallback cb,
                                  void *opaque,
                                  virFreeCallback freecb);

int virConnectDomainEventDeregister(virConnectPtr conn,
                                    virConnectDomainEventCallback cb);


int virDomainIsActive(virDomainPtr dom);
int virDomainIsPersistent(virDomainPtr dom);
int virDomainIsUpdated(virDomainPtr dom);

/**
 * virDomainJobType:
 *
 * Since: 0.7.7
 */
typedef enum {
    VIR_DOMAIN_JOB_NONE      = 0, /* No job is active (Since: 0.7.7) */
    VIR_DOMAIN_JOB_BOUNDED   = 1, /* Job with a finite completion time (Since: 0.7.7) */
    VIR_DOMAIN_JOB_UNBOUNDED = 2, /* Job without a finite completion time (Since: 0.7.7) */
    VIR_DOMAIN_JOB_COMPLETED = 3, /* Job has finished, but isn't cleaned up (Since: 0.7.7) */
    VIR_DOMAIN_JOB_FAILED    = 4, /* Job hit error, but isn't cleaned up (Since: 0.7.7) */
    VIR_DOMAIN_JOB_CANCELLED = 5, /* Job was aborted, but isn't cleaned up (Since: 0.7.7) */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_JOB_LAST /* (Since: 0.9.10) */
# endif
} virDomainJobType;

/**
 * virDomainJobInfo:
 *
 * Since: 0.7.7
 */
typedef struct _virDomainJobInfo virDomainJobInfo;

/**
 * virDomainJobInfoPtr:
 *
 * Since: 0.7.7
 */
typedef virDomainJobInfo *virDomainJobInfoPtr;
struct _virDomainJobInfo {
    /* One of virDomainJobType */
    int type;

    /* Time is measured in milliseconds */
    unsigned long long timeElapsed;    /* Always set */
    unsigned long long timeRemaining;  /* Only for VIR_DOMAIN_JOB_BOUNDED */

    /* Data is measured in bytes unless otherwise specified
     * and is measuring the job as a whole.
     *
     * For VIR_DOMAIN_JOB_UNBOUNDED, dataTotal may be less
     * than the final sum of dataProcessed + dataRemaining
     * in the event that the hypervisor has to repeat some
     * data, such as due to dirtied pages during migration.
     *
     * For VIR_DOMAIN_JOB_BOUNDED, dataTotal shall always
     * equal the sum of dataProcessed + dataRemaining.
     */
    unsigned long long dataTotal;
    unsigned long long dataProcessed;
    unsigned long long dataRemaining;

    /* As above, but only tracking guest memory progress */
    unsigned long long memTotal;
    unsigned long long memProcessed;
    unsigned long long memRemaining;

    /* As above, but only tracking guest disk file progress */
    unsigned long long fileTotal;
    unsigned long long fileProcessed;
    unsigned long long fileRemaining;
};

/**
 * virDomainGetJobStatsFlags:
 *
 * Flags OR'ed together to provide specific behavior when querying domain
 * job statistics.
 *
 * Since: 1.2.9
 */
typedef enum {
    VIR_DOMAIN_JOB_STATS_COMPLETED = 1 << 0, /* return stats of a recently
                                              * completed job (Since: 1.2.9) */
    VIR_DOMAIN_JOB_STATS_KEEP_COMPLETED = 1 << 1, /* don't remove completed
                                                     stats when reading them (Since: 6.0.0) */
} virDomainGetJobStatsFlags;

int virDomainGetJobInfo(virDomainPtr dom,
                        virDomainJobInfoPtr info);
int virDomainGetJobStats(virDomainPtr domain,
                         int *type,
                         virTypedParameterPtr *params,
                         int *nparams,
                         unsigned int flags);
int virDomainAbortJob(virDomainPtr dom);

/**
 * virDomainAbortJobFlagsValues:
 *
 * Flags OR'ed together to provide specific behavior when aborting a domain job.
 *
 * Since: 8.5.0
 */
typedef enum {
    /* Interrupt post-copy migration. Since migration in a post-copy phase
     * cannot be aborted without losing the domain (none of the hosts involved
     * in migration has a complete state of the domain), the migration will be
     * suspended and it can later be resumed using virDomainMigrate* APIs with
     * VIR_MIGRATE_POSTCOPY_RESUME flag. (Since: 8.5.0) */
    VIR_DOMAIN_ABORT_JOB_POSTCOPY = 1 << 0,
} virDomainAbortJobFlagsValues;

int virDomainAbortJobFlags(virDomainPtr dom,
                           unsigned int flags);

/**
 * virDomainJobOperation:
 *
 * Since: 3.3.0
 */
typedef enum {
    VIR_DOMAIN_JOB_OPERATION_UNKNOWN = 0, /* (Since: 3.3.0) */
    VIR_DOMAIN_JOB_OPERATION_START = 1, /* (Since: 3.3.0) */
    VIR_DOMAIN_JOB_OPERATION_SAVE = 2, /* (Since: 3.3.0) */
    VIR_DOMAIN_JOB_OPERATION_RESTORE = 3, /* (Since: 3.3.0) */
    VIR_DOMAIN_JOB_OPERATION_MIGRATION_IN = 4, /* (Since: 3.3.0) */
    VIR_DOMAIN_JOB_OPERATION_MIGRATION_OUT = 5, /* (Since: 3.3.0) */
    VIR_DOMAIN_JOB_OPERATION_SNAPSHOT = 6, /* (Since: 3.3.0) */
    VIR_DOMAIN_JOB_OPERATION_SNAPSHOT_REVERT = 7, /* (Since: 3.3.0) */
    VIR_DOMAIN_JOB_OPERATION_DUMP = 8, /* (Since: 3.3.0) */
    VIR_DOMAIN_JOB_OPERATION_BACKUP = 9, /* (Since: 6.0.0) */
    VIR_DOMAIN_JOB_OPERATION_SNAPSHOT_DELETE = 10, /* (Since: 9.0.0) */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_JOB_OPERATION_LAST /* (Since: 3.3.0) */
# endif
} virDomainJobOperation;

/**
 * VIR_DOMAIN_JOB_OPERATION:
 *
 * virDomainGetJobStats field: the operation which started the job as
 * VIR_TYPED_PARAM_INT. The values correspond to the items in
 * virDomainJobOperation enum.
 *
 * Since: 3.3.0
 */
# define VIR_DOMAIN_JOB_OPERATION                "operation"

/**
 * VIR_DOMAIN_JOB_TIME_ELAPSED:
 *
 * virDomainGetJobStats field: time (ms) since the beginning of the
 * job, as VIR_TYPED_PARAM_ULLONG.
 *
 * This field corresponds to timeElapsed field in virDomainJobInfo.
 *
 * Since: 1.0.3
 */
# define VIR_DOMAIN_JOB_TIME_ELAPSED             "time_elapsed"

/**
 * VIR_DOMAIN_JOB_TIME_ELAPSED_NET:
 *
 * virDomainGetJobStats field: time (ms) since the beginning of the
 * migration job NOT including the time required to transfer control
 * flow from the source host to the destination host,
 * as VIR_TYPED_PARAM_ULLONG.
 *
 * Since: 1.2.15
 */
# define VIR_DOMAIN_JOB_TIME_ELAPSED_NET         "time_elapsed_net"

/**
 * VIR_DOMAIN_JOB_TIME_REMAINING:
 *
 * virDomainGetJobStats field: remaining time (ms) for VIR_DOMAIN_JOB_BOUNDED
 * jobs, as VIR_TYPED_PARAM_ULLONG.
 *
 * This field corresponds to timeRemaining field in virDomainJobInfo.
 *
 * Since: 1.0.3
 */
# define VIR_DOMAIN_JOB_TIME_REMAINING           "time_remaining"

/**
 * VIR_DOMAIN_JOB_DOWNTIME:
 *
 * virDomainGetJobStats field: downtime (ms) that is expected to happen
 * during migration, as VIR_TYPED_PARAM_ULLONG. The real computed downtime
 * between the time guest CPUs were paused and the time they were resumed
 * is reported for completed migration.
 *
 * Since: 1.0.3
 */
# define VIR_DOMAIN_JOB_DOWNTIME                 "downtime"

/**
 * VIR_DOMAIN_JOB_DOWNTIME_NET:
 *
 * virDomainGetJobStats field: real measured downtime (ms) NOT including
 * the time required to transfer control flow from the source host to the
 * destination host, as VIR_TYPED_PARAM_ULLONG.
 *
 * Since: 1.2.15
 */
# define VIR_DOMAIN_JOB_DOWNTIME_NET             "downtime_net"

/**
 * VIR_DOMAIN_JOB_SETUP_TIME:
 *
 * virDomainGetJobStats field: total time in milliseconds spent preparing
 * the migration in the 'setup' phase before the iterations begin, as
 * VIR_TYPED_PARAM_ULLONG.
 *
 * Since: 1.2.9
 */
# define VIR_DOMAIN_JOB_SETUP_TIME               "setup_time"

/**
 * VIR_DOMAIN_JOB_DATA_TOTAL:
 *
 * virDomainGetJobStats field: total number of bytes supposed to be
 * transferred, as VIR_TYPED_PARAM_ULLONG. For VIR_DOMAIN_JOB_UNBOUNDED
 * jobs, this may be less than the sum of VIR_DOMAIN_JOB_DATA_PROCESSED and
 * VIR_DOMAIN_JOB_DATA_REMAINING in the event that the hypervisor has to
 * repeat some data, e.g., due to dirtied pages during migration. For
 * VIR_DOMAIN_JOB_BOUNDED jobs, VIR_DOMAIN_JOB_DATA_TOTAL shall always equal
 * VIR_DOMAIN_JOB_DATA_PROCESSED + VIR_DOMAIN_JOB_DATA_REMAINING.
 *
 * This field corresponds to dataTotal field in virDomainJobInfo.
 *
 * Since: 1.0.3
 */
# define VIR_DOMAIN_JOB_DATA_TOTAL               "data_total"

/**
 * VIR_DOMAIN_JOB_DATA_PROCESSED:
 *
 * virDomainGetJobStats field: number of bytes transferred from the
 * beginning of the job, as VIR_TYPED_PARAM_ULLONG.
 *
 * This field corresponds to dataProcessed field in virDomainJobInfo.
 *
 * Since: 1.0.3
 */
# define VIR_DOMAIN_JOB_DATA_PROCESSED           "data_processed"

/**
 * VIR_DOMAIN_JOB_DATA_REMAINING:
 *
 * virDomainGetJobStats field: number of bytes that still need to be
 * transferred, as VIR_TYPED_PARAM_ULLONG.
 *
 * This field corresponds to dataRemaining field in virDomainJobInfo.
 *
 * Since: 1.0.3
 */
# define VIR_DOMAIN_JOB_DATA_REMAINING           "data_remaining"

/**
 * VIR_DOMAIN_JOB_MEMORY_TOTAL:
 *
 * virDomainGetJobStats field: as VIR_DOMAIN_JOB_DATA_TOTAL but only
 * tracking guest memory progress, as VIR_TYPED_PARAM_ULLONG.
 *
 * This field corresponds to memTotal field in virDomainJobInfo.
 *
 * Since: 1.0.3
 */
# define VIR_DOMAIN_JOB_MEMORY_TOTAL             "memory_total"

/**
 * VIR_DOMAIN_JOB_MEMORY_PROCESSED:
 *
 * virDomainGetJobStats field: as VIR_DOMAIN_JOB_DATA_PROCESSED but only
 * tracking guest memory progress, as VIR_TYPED_PARAM_ULLONG.
 *
 * This field corresponds to memProcessed field in virDomainJobInfo.
 *
 * Since: 1.0.3
 */
# define VIR_DOMAIN_JOB_MEMORY_PROCESSED         "memory_processed"

/**
 * VIR_DOMAIN_JOB_MEMORY_REMAINING:
 *
 * virDomainGetJobStats field: as VIR_DOMAIN_JOB_DATA_REMAINING but only
 * tracking guest memory progress, as VIR_TYPED_PARAM_ULLONG.
 *
 * This field corresponds to memRemaining field in virDomainJobInfo.
 *
 * Since: 1.0.3
 */
# define VIR_DOMAIN_JOB_MEMORY_REMAINING         "memory_remaining"

/**
 * VIR_DOMAIN_JOB_MEMORY_CONSTANT:
 *
 * virDomainGetJobStats field: number of pages filled with a constant
 * byte (all bytes in a single page are identical) transferred since the
 * beginning of the migration job, as VIR_TYPED_PARAM_ULLONG.
 *
 * The most common example of such pages are zero pages, i.e., pages filled
 * with zero bytes.
 *
 * Since: 1.0.3
 */
# define VIR_DOMAIN_JOB_MEMORY_CONSTANT          "memory_constant"

/**
 * VIR_DOMAIN_JOB_MEMORY_NORMAL:
 *
 * virDomainGetJobStats field: number of pages that were transferred without
 * any kind of compression (i.e., pages which were not filled with a constant
 * byte and which could not be compressed) transferred since the beginning
 * of the migration job, as VIR_TYPED_PARAM_ULLONG.
 *
 * Since: 1.0.3
 */
# define VIR_DOMAIN_JOB_MEMORY_NORMAL            "memory_normal"

/**
 * VIR_DOMAIN_JOB_MEMORY_NORMAL_BYTES:
 *
 * virDomainGetJobStats field: number of bytes transferred as normal pages,
 * as VIR_TYPED_PARAM_ULLONG.
 *
 * See VIR_DOMAIN_JOB_MEMORY_NORMAL for more details.
 *
 * Since: 1.0.3
 */
# define VIR_DOMAIN_JOB_MEMORY_NORMAL_BYTES      "memory_normal_bytes"

/**
 * VIR_DOMAIN_JOB_MEMORY_BPS:
 *
 * virDomainGetJobStats field: network throughput used while migrating
 * memory in Bytes per second, as VIR_TYPED_PARAM_ULLONG.
 *
 * Since: 1.2.9
 */
# define VIR_DOMAIN_JOB_MEMORY_BPS               "memory_bps"

/** VIR_DOMAIN_JOB_MEMORY_DIRTY_RATE:
 *
 * virDomainGetJobStats field: number of memory pages dirtied by the guest
 * per second, as VIR_TYPED_PARAM_ULLONG. This statistics makes sense only
 * when live migration is running.
 *
 * Since: 1.3.1
 */
# define VIR_DOMAIN_JOB_MEMORY_DIRTY_RATE        "memory_dirty_rate"

/**
 * VIR_DOMAIN_JOB_MEMORY_PAGE_SIZE:
 *
 * virDomainGetJobStats field: memory page size in bytes, as
 * VIR_TYPED_PARAM_ULLONG. If present, this parameter can be used to
 * convert other page based statistics, such as
 * VIR_DOMAIN_JOB_MEMORY_DIRTY_RATE or VIR_DOMAIN_JOB_COMPRESSION_PAGES
 * to bytes.
 *
 * Since: 3.9.0
 */
# define VIR_DOMAIN_JOB_MEMORY_PAGE_SIZE         "memory_page_size"

/**
 * VIR_DOMAIN_JOB_MEMORY_ITERATION:
 *
 * virDomainGetJobStats field: current iteration over domain's memory
 * during live migration, as VIR_TYPED_PARAM_ULLONG. This is set to zero
 * when memory starts to be transferred and the value is increased by one
 * every time a new iteration is started to transfer memory pages dirtied
 * since the last iteration.
 *
 * Since: 1.3.1
 */
# define VIR_DOMAIN_JOB_MEMORY_ITERATION         "memory_iteration"

/**
 * VIR_DOMAIN_JOB_MEMORY_POSTCOPY_REQS:
 *
 * virDomainGetJobStats field: number page requests received from the
 * destination host during post-copy migration, as VIR_TYPED_PARAM_ULLONG.
 * This counter is incremented whenever the migrated domain tries to access
 * a memory page which has not been transferred from the source host yet.
 *
 * Since: 5.0.0
 */
# define VIR_DOMAIN_JOB_MEMORY_POSTCOPY_REQS     "memory_postcopy_requests"

/**
 * VIR_DOMAIN_JOB_DISK_TOTAL:
 *
 * virDomainGetJobStats field: as VIR_DOMAIN_JOB_DATA_TOTAL but only
 * tracking guest disk progress, as VIR_TYPED_PARAM_ULLONG.
 *
 * This field corresponds to fileTotal field in virDomainJobInfo.
 *
 * Since: 1.0.3
 */
# define VIR_DOMAIN_JOB_DISK_TOTAL               "disk_total"

/**
 * VIR_DOMAIN_JOB_DISK_PROCESSED:
 *
 * virDomainGetJobStats field: as VIR_DOMAIN_JOB_DATA_PROCESSED but only
 * tracking guest disk progress, as VIR_TYPED_PARAM_ULLONG.
 *
 * This field corresponds to fileProcessed field in virDomainJobInfo.
 *
 * Since: 1.0.3
 */
# define VIR_DOMAIN_JOB_DISK_PROCESSED           "disk_processed"

/**
 * VIR_DOMAIN_JOB_DISK_REMAINING:
 *
 * virDomainGetJobStats field: as VIR_DOMAIN_JOB_DATA_REMAINING but only
 * tracking guest disk progress, as VIR_TYPED_PARAM_ULLONG.
 *
 * This field corresponds to fileRemaining field in virDomainJobInfo.
 *
 * Since: 1.0.3
 */
# define VIR_DOMAIN_JOB_DISK_REMAINING           "disk_remaining"

/**
 * VIR_DOMAIN_JOB_DISK_BPS:
 *
 * virDomainGetJobStats field: network throughput used while migrating
 * disks in Bytes per second, as VIR_TYPED_PARAM_ULLONG.
 *
 * Since: 1.2.9
 */
# define VIR_DOMAIN_JOB_DISK_BPS                 "disk_bps"

/**
 * VIR_DOMAIN_JOB_COMPRESSION_CACHE:
 *
 * virDomainGetJobStats field: size of the cache (in bytes) used for
 * compressing repeatedly transferred memory pages during live migration,
 * as VIR_TYPED_PARAM_ULLONG.
 *
 * Since: 1.0.3
 */
# define VIR_DOMAIN_JOB_COMPRESSION_CACHE        "compression_cache"

/**
 * VIR_DOMAIN_JOB_COMPRESSION_BYTES:
 *
 * virDomainGetJobStats field: number of compressed bytes transferred
 * since the beginning of migration, as VIR_TYPED_PARAM_ULLONG.
 *
 * Since: 1.0.3
 */
# define VIR_DOMAIN_JOB_COMPRESSION_BYTES        "compression_bytes"

/**
 * VIR_DOMAIN_JOB_COMPRESSION_PAGES:
 *
 * virDomainGetJobStats field: number of compressed pages transferred
 * since the beginning of migration, as VIR_TYPED_PARAM_ULLONG.
 *
 * Since: 1.0.3
 */
# define VIR_DOMAIN_JOB_COMPRESSION_PAGES        "compression_pages"

/**
 * VIR_DOMAIN_JOB_COMPRESSION_CACHE_MISSES:
 *
 * virDomainGetJobStats field: number of repeatedly changing pages that
 * were not found in compression cache and thus could not be compressed,
 * as VIR_TYPED_PARAM_ULLONG.
 *
 * Since: 1.0.3
 */
# define VIR_DOMAIN_JOB_COMPRESSION_CACHE_MISSES "compression_cache_misses"

/**
 * VIR_DOMAIN_JOB_COMPRESSION_OVERFLOW:
 *
 * virDomainGetJobStats field: number of repeatedly changing pages that
 * were found in compression cache but were sent uncompressed because
 * the result of compression was larger than the original page as a whole,
 * as VIR_TYPED_PARAM_ULLONG.
 *
 * Since: 1.0.3
 */
# define VIR_DOMAIN_JOB_COMPRESSION_OVERFLOW     "compression_overflow"

/**
 * VIR_DOMAIN_JOB_AUTO_CONVERGE_THROTTLE:
 *
 * virDomainGetJobStats field: current percentage guest CPUs are throttled
 * to when auto-convergence decided migration was not converging, as
 * VIR_TYPED_PARAM_INT.
 *
 * Since: 2.0.0
 */
# define VIR_DOMAIN_JOB_AUTO_CONVERGE_THROTTLE  "auto_converge_throttle"

/**
 * VIR_DOMAIN_JOB_SUCCESS:
 *
 * virDomainGetJobStats field: Present only in statistics for a completed job.
 * Successful completion of the job as VIR_TYPED_PARAM_BOOLEAN.
 *
 * Since: 6.0.0
 */
# define VIR_DOMAIN_JOB_SUCCESS "success"

/**
 * VIR_DOMAIN_JOB_ERRMSG:
 *
 * virDomainGetJobStats field: Present only in statistics for a completed job.
 * Optional error message for a failed job.
 *
 * Since: 6.3.0
 */
# define VIR_DOMAIN_JOB_ERRMSG "errmsg"


/**
 * VIR_DOMAIN_JOB_DISK_TEMP_USED:
 * virDomainGetJobStats field: current usage of temporary disk space for the
 * job in bytes as VIR_TYPED_PARAM_ULLONG.
 *
 * Since: 6.0.0
 */
# define VIR_DOMAIN_JOB_DISK_TEMP_USED "disk_temp_used"

/**
 * VIR_DOMAIN_JOB_DISK_TEMP_TOTAL:
 * virDomainGetJobStats field: possible total temporary disk space for the
 * job in bytes as VIR_TYPED_PARAM_ULLONG.
 *
 * Since: 6.0.0
 */
# define VIR_DOMAIN_JOB_DISK_TEMP_TOTAL "disk_temp_total"

/**
 * virConnectDomainEventGenericCallback:
 * @conn: the connection pointer
 * @dom: the domain pointer
 * @opaque: application specified data
 *
 * A generic domain event callback handler, for use with
 * virConnectDomainEventRegisterAny(). Specific events usually
 * have a customization with extra parameters, often with @opaque being
 * passed in a different parameter position; use VIR_DOMAIN_EVENT_CALLBACK()
 * when registering an appropriate handler.
 *
 * Since: 0.8.0
 */
typedef void (*virConnectDomainEventGenericCallback)(virConnectPtr conn,
                                                     virDomainPtr dom,
                                                     void *opaque);

/**
 * virConnectDomainEventRTCChangeCallback:
 * @conn: connection object
 * @dom: domain on which the event occurred
 * @utcoffset: the new RTC offset from UTC, measured in seconds
 * @opaque: application specified data
 *
 * The callback signature to use when registering for an event of type
 * VIR_DOMAIN_EVENT_ID_RTC_CHANGE with virConnectDomainEventRegisterAny()
 *
 * Since: 0.8.0
 */
typedef void (*virConnectDomainEventRTCChangeCallback)(virConnectPtr conn,
                                                       virDomainPtr dom,
                                                       long long utcoffset,
                                                       void *opaque);

/**
 * virDomainEventWatchdogAction:
 *
 * The action that is to be taken due to the watchdog device firing
 *
 * Since: 0.8.0
 */
typedef enum {
    VIR_DOMAIN_EVENT_WATCHDOG_NONE = 0, /* No action, watchdog ignored (Since: 0.8.0) */
    VIR_DOMAIN_EVENT_WATCHDOG_PAUSE,    /* Guest CPUs are paused (Since: 0.8.0) */
    VIR_DOMAIN_EVENT_WATCHDOG_RESET,    /* Guest CPUs are reset (Since: 0.8.0) */
    VIR_DOMAIN_EVENT_WATCHDOG_POWEROFF, /* Guest is forcibly powered off (Since: 0.8.0) */
    VIR_DOMAIN_EVENT_WATCHDOG_SHUTDOWN, /* Guest is requested to gracefully shutdown (Since: 0.8.0) */
    VIR_DOMAIN_EVENT_WATCHDOG_DEBUG,    /* No action, a debug message logged (Since: 0.8.0) */
    VIR_DOMAIN_EVENT_WATCHDOG_INJECTNMI,/* Inject a non-maskable interrupt into guest (Since: 1.2.17) */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_EVENT_WATCHDOG_LAST /* (Since: 0.9.10) */
# endif
} virDomainEventWatchdogAction;

/**
 * virConnectDomainEventWatchdogCallback:
 * @conn: connection object
 * @dom: domain on which the event occurred
 * @action: action that is to be taken due to watchdog firing (virDomainEventWatchdogAction)
 * @opaque: application specified data
 *
 * The callback signature to use when registering for an event of type
 * VIR_DOMAIN_EVENT_ID_WATCHDOG with virConnectDomainEventRegisterAny()
 *
 * Since: 0.8.0
 */
typedef void (*virConnectDomainEventWatchdogCallback)(virConnectPtr conn,
                                                      virDomainPtr dom,
                                                      int action,
                                                      void *opaque);

/**
 * virDomainEventIOErrorAction:
 *
 * The action that is to be taken due to an IO error occurring
 *
 * Since: 0.8.0
 */
typedef enum {
    VIR_DOMAIN_EVENT_IO_ERROR_NONE = 0,  /* No action, IO error ignored (Since: 0.8.0) */
    VIR_DOMAIN_EVENT_IO_ERROR_PAUSE,     /* Guest CPUs are paused (Since: 0.8.0) */
    VIR_DOMAIN_EVENT_IO_ERROR_REPORT,    /* IO error reported to guest OS (Since: 0.8.0) */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_EVENT_IO_ERROR_LAST /* (Since: 0.9.10) */
# endif
} virDomainEventIOErrorAction;


/**
 * virConnectDomainEventIOErrorCallback:
 * @conn: connection object
 * @dom: domain on which the event occurred
 * @srcPath: The host file on which the IO error occurred
 * @devAlias: The guest device alias associated with the path
 * @action: action that is to be taken due to the IO error (virDomainEventIOErrorAction)
 * @opaque: application specified data
 *
 * The callback signature to use when registering for an event of type
 * VIR_DOMAIN_EVENT_ID_IO_ERROR with virConnectDomainEventRegisterAny()
 *
 * Since: 0.8.0
 */
typedef void (*virConnectDomainEventIOErrorCallback)(virConnectPtr conn,
                                                     virDomainPtr dom,
                                                     const char *srcPath,
                                                     const char *devAlias,
                                                     int action,
                                                     void *opaque);

/**
 * virConnectDomainEventIOErrorReasonCallback:
 * @conn: connection object
 * @dom: domain on which the event occurred
 * @srcPath: The host file on which the IO error occurred
 * @devAlias: The guest device alias associated with the path
 * @action: action that is to be taken due to the IO error (virDomainEventIOErrorAction)
 * @reason: the cause of the IO error
 * @opaque: application specified data
 *
 * The callback signature to use when registering for an event of type
 * VIR_DOMAIN_EVENT_ID_IO_ERROR_REASON with virConnectDomainEventRegisterAny()
 *
 * If the I/O error is known to be caused by an ENOSPC condition in
 * the host (where resizing the disk to be larger will allow the guest
 * to be resumed as if nothing happened), @reason will be "enospc".
 * Otherwise, @reason will be "", although future strings may be added
 * if determination of other error types becomes possible.
 *
 * Since: 0.8.1
 */
typedef void (*virConnectDomainEventIOErrorReasonCallback)(virConnectPtr conn,
                                                           virDomainPtr dom,
                                                           const char *srcPath,
                                                           const char *devAlias,
                                                           int action,
                                                           const char *reason,
                                                           void *opaque);

/**
 * virDomainEventGraphicsPhase:
 *
 * The phase of the graphics client connection
 *
 * Since: 0.8.0
 */
typedef enum {
    VIR_DOMAIN_EVENT_GRAPHICS_CONNECT = 0,  /* Initial socket connection established (Since: 0.8.0) */
    VIR_DOMAIN_EVENT_GRAPHICS_INITIALIZE,   /* Authentication & setup completed (Since: 0.8.0) */
    VIR_DOMAIN_EVENT_GRAPHICS_DISCONNECT,   /* Final socket disconnection (Since: 0.8.0) */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_EVENT_GRAPHICS_LAST /* (Since: 0.9.10) */
# endif
} virDomainEventGraphicsPhase;

/**
 * virDomainEventGraphicsAddressType:
 *
 * The type of address for the connection
 *
 * Since: 0.8.0
 */
typedef enum {
    VIR_DOMAIN_EVENT_GRAPHICS_ADDRESS_IPV4,  /* IPv4 address (Since: 0.8.0) */
    VIR_DOMAIN_EVENT_GRAPHICS_ADDRESS_IPV6,  /* IPv6 address (Since: 0.8.0) */
    VIR_DOMAIN_EVENT_GRAPHICS_ADDRESS_UNIX,  /* UNIX socket path (Since: 0.9.7) */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_EVENT_GRAPHICS_ADDRESS_LAST /* (Since: 0.9.10) */
# endif
} virDomainEventGraphicsAddressType;


/**
 * _virDomainEventGraphicsAddress:
 *
 * The data structure containing connection address details
 *
 * Since: 1.0.0
 */
struct _virDomainEventGraphicsAddress {
    int family;               /* Address family, virDomainEventGraphicsAddressType */
    char *node;               /* Address of node (eg IP address, or UNIX path) */
    char *service;            /* Service name/number (eg TCP port, or NULL) */
};

/**
 * virDomainEventGraphicsAddress:
 *
 * Since: 0.8.0
 */
typedef struct _virDomainEventGraphicsAddress virDomainEventGraphicsAddress;

/**
 * virDomainEventGraphicsAddressPtr:
 *
 * Since: 0.8.0
 */
typedef virDomainEventGraphicsAddress *virDomainEventGraphicsAddressPtr;


/**
 * _virDomainEventGraphicsSubjectIdentity:
 *
 * The data structure representing a single identity
 *
 * The types of identity differ according to the authentication scheme,
 * some examples are 'x509dname' and 'saslUsername'.
 */
struct _virDomainEventGraphicsSubjectIdentity {
    char *type;     /* Type of identity */
    char *name;     /* Identity value */
};

/**
 * virDomainEventGraphicsSubjectIdentity:
 *
 * Since: 0.8.0
 */
typedef struct _virDomainEventGraphicsSubjectIdentity virDomainEventGraphicsSubjectIdentity;

/**
 * virDomainEventGraphicsSubjectIdentityPtr:
 *
 * Since: 0.8.0
 */
typedef virDomainEventGraphicsSubjectIdentity *virDomainEventGraphicsSubjectIdentityPtr;


/**
 * virDomainEventGraphicsSubject:
 *
 * The data structure representing an authenticated subject
 *
 * A subject will have zero or more identities. The types of
 * identity differ according to the authentication scheme
 *
 * Since: 0.8.0
 */
struct _virDomainEventGraphicsSubject {
    int nidentity;                                /* Number of identities in array*/
    virDomainEventGraphicsSubjectIdentityPtr identities; /* Array of identities for subject */
};

/**
 * virDomainEventGraphicsSubject:
 *
 * Since: 0.8.0
 */
typedef struct _virDomainEventGraphicsSubject virDomainEventGraphicsSubject;

/**
 * virDomainEventGraphicsSubjectPtr:
 *
 * Since: 0.8.0
 */
typedef virDomainEventGraphicsSubject *virDomainEventGraphicsSubjectPtr;


/**
 * virConnectDomainEventGraphicsCallback:
 * @conn: connection object
 * @dom: domain on which the event occurred
 * @phase: the phase of the connection (virDomainEventGraphicsPhase)
 * @local: the local server address
 * @remote: the remote client address
 * @authScheme: the authentication scheme activated
 * @subject: the authenticated subject (user)
 * @opaque: application specified data
 *
 * The callback signature to use when registering for an event of type
 * VIR_DOMAIN_EVENT_ID_GRAPHICS with virConnectDomainEventRegisterAny()
 *
 * Since: 0.8.0
 */
typedef void (*virConnectDomainEventGraphicsCallback)(virConnectPtr conn,
                                                      virDomainPtr dom,
                                                      int phase,
                                                      const virDomainEventGraphicsAddress *local,
                                                      const virDomainEventGraphicsAddress *remote,
                                                      const char *authScheme,
                                                      const virDomainEventGraphicsSubject *subject,
                                                      void *opaque);

/**
 * virConnectDomainEventBlockJobStatus:
 *
 * Tracks status of a virDomainBlockPull(), virDomainBlockRebase(),
 * virDomainBlockCopy(), or virDomainBlockCommit() operation
 *
 * Since: 0.9.4
 */
typedef enum {
    VIR_DOMAIN_BLOCK_JOB_COMPLETED = 0, /* (Since: 0.9.4) */
    VIR_DOMAIN_BLOCK_JOB_FAILED = 1, /* (Since: 0.9.4) */
    VIR_DOMAIN_BLOCK_JOB_CANCELED = 2, /* (Since: 0.9.12) */
    VIR_DOMAIN_BLOCK_JOB_READY = 3, /* (Since: 1.0.0) */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_BLOCK_JOB_LAST /* (Since: 0.9.10) */
# endif
} virConnectDomainEventBlockJobStatus;

/**
 * virConnectDomainEventBlockJobCallback:
 * @conn: connection object
 * @dom: domain on which the event occurred
 * @disk: name associated with the affected disk (filename or target
 *        device, depending on how the callback was registered)
 * @type: type of block job (virDomainBlockJobType)
 * @status: status of the operation (virConnectDomainEventBlockJobStatus)
 * @opaque: application specified data
 *
 * The string returned for @disk can be used in any of the libvirt API
 * that operate on a particular disk of the domain, and depends on what
 * event type was registered with virConnectDomainEventRegisterAny().
 * If the callback was registered using the older type of
 * VIR_DOMAIN_EVENT_ID_BLOCK_JOB, then @disk contains the absolute file
 * name of the host resource for the active layer of the disk; however,
 * this name is unstable (pivoting via block copy or active block commit
 * will change which file is active, giving a different name for the two
 * events associated with the same job) and cannot be relied on if the
 * active layer is associated with a network resource.  If the callback
 * was registered using the newer type of VIR_DOMAIN_EVENT_ID_BLOCK_JOB_2,
 * then @disk will contain the device target shorthand (the <target
 * dev='...'/> sub-element, such as "vda").
 *
 * Since: 0.9.4
 */
typedef void (*virConnectDomainEventBlockJobCallback)(virConnectPtr conn,
                                                      virDomainPtr dom,
                                                      const char *disk,
                                                      int type,
                                                      int status,
                                                      void *opaque);

/**
 * virConnectDomainEventDiskChangeReason:
 *
 * The reason describing why this callback is called
 *
 * Since: 0.9.7
 */
typedef enum {
    /* Removable media changed to empty according to startup policy as source
     * was missing. oldSrcPath is set, newSrcPath is NULL
     *
     * Since: 0.9.7
     * */
    VIR_DOMAIN_EVENT_DISK_CHANGE_MISSING_ON_START = 0,

    /* Disk was dropped from domain as source file was missing.
     * oldSrcPath is set, newSrcPath is NULL
     *
     * Since: 1.1.2
     * */
    VIR_DOMAIN_EVENT_DISK_DROP_MISSING_ON_START = 1,

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_EVENT_DISK_CHANGE_LAST /* (Since: 0.9.10) */
# endif
} virConnectDomainEventDiskChangeReason;

/**
 * virConnectDomainEventDiskChangeCallback:
 * @conn: connection object
 * @dom: domain on which the event occurred
 * @oldSrcPath: old source path
 * @newSrcPath: new source path
 * @devAlias: device alias name
 * @reason: reason why this callback was called; any of
 *          virConnectDomainEventDiskChangeReason
 * @opaque: application specified data
 *
 * This callback occurs when disk gets changed. However,
 * not all @reason will cause both @oldSrcPath and @newSrcPath
 * to be non-NULL. Please see virConnectDomainEventDiskChangeReason
 * for more details.
 *
 * The callback signature to use when registering for an event of type
 * VIR_DOMAIN_EVENT_ID_DISK_CHANGE with virConnectDomainEventRegisterAny()
 *
 * Since: 0.9.7
 */
typedef void (*virConnectDomainEventDiskChangeCallback)(virConnectPtr conn,
                                                        virDomainPtr dom,
                                                        const char *oldSrcPath,
                                                        const char *newSrcPath,
                                                        const char *devAlias,
                                                        int reason,
                                                        void *opaque);

/**
 * virDomainEventTrayChangeReason:
 *
 * The reason describing why the callback was called
 *
 * Since: 0.9.11
 */
typedef enum {
    VIR_DOMAIN_EVENT_TRAY_CHANGE_OPEN = 0, /* (Since: 0.9.11) */
    VIR_DOMAIN_EVENT_TRAY_CHANGE_CLOSE, /* (Since: 0.9.11) */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_EVENT_TRAY_CHANGE_LAST /* (Since: 0.9.11) */
# endif
} virDomainEventTrayChangeReason;

/**
 * virConnectDomainEventTrayChangeCallback:
 * @conn: connection object
 * @dom: domain on which the event occurred
 * @devAlias: device alias
 * @reason: why the tray status was changed? (virDomainEventTrayChangeReason)
 * @opaque: application specified data
 *
 * This callback occurs when the tray of a removable device is moved.
 *
 * The callback signature to use when registering for an event of type
 * VIR_DOMAIN_EVENT_ID_TRAY_CHANGE with virConnectDomainEventRegisterAny()
 *
 * Since: 0.9.11
 */
typedef void (*virConnectDomainEventTrayChangeCallback)(virConnectPtr conn,
                                                        virDomainPtr dom,
                                                        const char *devAlias,
                                                        int reason,
                                                        void *opaque);

/**
 * virConnectDomainEventPMWakeupCallback:
 * @conn: connection object
 * @dom: domain on which the event occurred
 * @reason: reason why the callback was called, unused currently,
 *          always passes 0
 * @opaque: application specified data
 *
 * This callback occurs when the guest is woken up.
 *
 * The callback signature to use when registering for an event of type
 * VIR_DOMAIN_EVENT_ID_PMWAKEUP with virConnectDomainEventRegisterAny()
 *
 * Since: 0.9.11
 */
typedef void (*virConnectDomainEventPMWakeupCallback)(virConnectPtr conn,
                                                      virDomainPtr dom,
                                                      int reason,
                                                      void *opaque);

/**
 * virConnectDomainEventPMSuspendCallback:
 * @conn: connection object
 * @dom: domain on which the event occurred
 * @reason: reason why the callback was called, unused currently,
 *          always passes 0
 * @opaque: application specified data
 *
 * This callback occurs when the guest is suspended.
 *
 * The callback signature to use when registering for an event of type
 * VIR_DOMAIN_EVENT_ID_PMSUSPEND with virConnectDomainEventRegisterAny()
 *
 * Since: 0.9.11
 */
typedef void (*virConnectDomainEventPMSuspendCallback)(virConnectPtr conn,
                                                       virDomainPtr dom,
                                                       int reason,
                                                       void *opaque);


/**
 * virConnectDomainEventBalloonChangeCallback:
 * @conn: connection object
 * @dom: domain on which the event occurred
 * @actual: the new balloon level measured in kibibytes(blocks of 1024 bytes)
 * @opaque: application specified data
 *
 * The callback signature to use when registering for an event of type
 * VIR_DOMAIN_EVENT_ID_BALLOON_CHANGE with virConnectDomainEventRegisterAny()
 *
 * Since: 0.10.0
 */
typedef void (*virConnectDomainEventBalloonChangeCallback)(virConnectPtr conn,
                                                           virDomainPtr dom,
                                                           unsigned long long actual,
                                                           void *opaque);

/**
 * virConnectDomainEventPMSuspendDiskCallback:
 * @conn: connection object
 * @dom: domain on which the event occurred
 * @reason: reason why the callback was called, unused currently,
 *          always passes 0
 * @opaque: application specified data
 *
 * This callback occurs when the guest is suspended to disk.
 *
 * The callback signature to use when registering for an event of type
 * VIR_DOMAIN_EVENT_ID_PMSUSPEND_DISK with virConnectDomainEventRegisterAny()
 *
 * Since: 1.0.0
 */
typedef void (*virConnectDomainEventPMSuspendDiskCallback)(virConnectPtr conn,
                                                           virDomainPtr dom,
                                                           int reason,
                                                           void *opaque);

/**
 * virConnectDomainEventDeviceRemovedCallback:
 * @conn: connection object
 * @dom: domain on which the event occurred
 * @devAlias: device alias
 * @opaque: application specified data
 *
 * This callback occurs when a device is removed from the domain.
 *
 * The callback signature to use when registering for an event of type
 * VIR_DOMAIN_EVENT_ID_DEVICE_REMOVED with virConnectDomainEventRegisterAny()
 *
 * Since: 1.1.1
 */
typedef void (*virConnectDomainEventDeviceRemovedCallback)(virConnectPtr conn,
                                                           virDomainPtr dom,
                                                           const char *devAlias,
                                                           void *opaque);

/**
 * virConnectDomainEventDeviceAddedCallback:
 * @conn: connection object
 * @dom: domain on which the event occurred
 * @devAlias: device alias
 * @opaque: application specified data
 *
 * This callback occurs when a device is added to the domain.
 *
 * The callback signature to use when registering for an event of type
 * VIR_DOMAIN_EVENT_ID_DEVICE_ADDED with virConnectDomainEventRegisterAny()
 *
 * Since: 1.2.15
 */
typedef void (*virConnectDomainEventDeviceAddedCallback)(virConnectPtr conn,
                                                         virDomainPtr dom,
                                                         const char *devAlias,
                                                         void *opaque);


/**
 * virConnectDomainEventDeviceRemovalFailedCallback:
 * @conn: connection object
 * @dom: domain on which the event occurred
 * @devAlias: device alias
 * @opaque: application specified data
 *
 * This callback occurs when it's certain that removal of a device failed.
 *
 * The callback signature to use when registering for an event of type
 * VIR_DOMAIN_EVENT_ID_DEVICE_REMOVAL_FAILED with
 * virConnectDomainEventRegisterAny().
 *
 * Since: 1.3.4
 */
typedef void (*virConnectDomainEventDeviceRemovalFailedCallback)(virConnectPtr conn,
                                                                 virDomainPtr dom,
                                                                 const char *devAlias,
                                                                 void *opaque);

/**
 * virConnectDomainEventMetadataChangeCallback:
 * @conn: connection object
 * @dom: domain on which the event occurred
 * @type: a value from virDomainMetadataTypea
 * @nsuri: XML namespace URI
 * @opaque: application specified data
 *
 * This callback is triggered when the domain XML metadata is changed
 *
 * The callback signature to use when registering for an event of type
 * VIR_DOMAIN_EVENT_ID_METADATA_CHANGE with virConnectDomainEventRegisterAny().
 *
 * Since: 3.0.0
 */
typedef void (*virConnectDomainEventMetadataChangeCallback)(virConnectPtr conn,
                                                            virDomainPtr dom,
                                                            int type,
                                                            const char *nsuri,
                                                            void *opaque);


/**
 * virConnectDomainEventMigrationIterationCallback:
 * @conn: connection object
 * @dom: domain on which the event occurred
 * @iteration: current iteration over domain's memory
 * @opaque: application specific data
 *
 * This callback occurs during live migration when a new iteration over
 * domain's memory starts. The @iteration value is increased by one every
 * time a new iteration is started to transfer memory pages dirtied since
 * the last iteration.
 *
 * The callback signature to use when registering for an event of type
 * VIR_DOMAIN_EVENT_ID_MIGRATION_ITERATION with
 * virConnectDomainEventRegisterAny().
 *
 * Since: 1.3.2
 */
typedef void (*virConnectDomainEventMigrationIterationCallback)(virConnectPtr conn,
                                                                virDomainPtr dom,
                                                                int iteration,
                                                                void *opaque);

/**
 * virConnectDomainEventJobCompletedCallback:
 * @conn: connection object
 * @dom: domain on which the event occurred
 * @params: job statistics stored as an array of virTypedParameter
 * @nparams: size of the params array
 * @opaque: application specific data
 *
 * This callback occurs when a job (such as migration or backup) running on
 * the domain is completed.
 *
 * The params array will contain statistics of the just completed
 * job as virDomainGetJobStats would return. The callback must not free @params
 * (the array will be freed once the callback finishes).
 *
 * The callback signature to use when registering for an event of type
 * VIR_DOMAIN_EVENT_ID_JOB_COMPLETED with
 * virConnectDomainEventRegisterAny().
 *
 * Since: 1.3.3
 */
typedef void (*virConnectDomainEventJobCompletedCallback)(virConnectPtr conn,
                                                          virDomainPtr dom,
                                                          virTypedParameterPtr params,
                                                          int nparams,
                                                          void *opaque);

/**
 * VIR_DOMAIN_TUNABLE_CPU_VCPUPIN:
 *
 * Macro represents formatted pinning for one vcpu specified by id which is
 * appended to the parameter name, for example "cputune.vcpupin1",
 * as VIR_TYPED_PARAM_STRING.
 *
 * Since: 1.2.9
 */
# define VIR_DOMAIN_TUNABLE_CPU_VCPUPIN "cputune.vcpupin%u"

/**
 * VIR_DOMAIN_TUNABLE_CPU_EMULATORPIN:
 *
 * Macro represents formatted pinning for emulator process,
 * as VIR_TYPED_PARAM_STRING.
 *
 * Since: 1.2.9
 */
# define VIR_DOMAIN_TUNABLE_CPU_EMULATORPIN "cputune.emulatorpin"

/**
 * VIR_DOMAIN_TUNABLE_CPU_IOTHREADSPIN:
 *
 * Macro represents formatted pinning for one IOThread specified by id which is
 * appended to the parameter name, for example "cputune.iothreadpin1",
 * as VIR_TYPED_PARAM_STRING.
 *
 * Since: 1.2.14
 */
# define VIR_DOMAIN_TUNABLE_CPU_IOTHREADSPIN "cputune.iothreadpin%u"

/**
 * VIR_DOMAIN_TUNABLE_CPU_CPU_SHARES:
 *
 * Macro represents proportional weight of the scheduler used on the
 * host cpu, when using the posix scheduler, as VIR_TYPED_PARAM_ULLONG.
 *
 * Since: 1.2.9
 */
# define VIR_DOMAIN_TUNABLE_CPU_CPU_SHARES "cputune.cpu_shares"

/**
 * VIR_DOMAIN_TUNABLE_CPU_GLOBAL_PERIOD:
 *
 * Macro represents the enforcement period for a quota, in microseconds,
 * for whole domain, when using the posix scheduler, as VIR_TYPED_PARAM_ULLONG.
 *
 * Since: 1.3.3
 */
# define VIR_DOMAIN_TUNABLE_CPU_GLOBAL_PERIOD "cputune.global_period"

/**
 * VIR_DOMAIN_TUNABLE_CPU_GLOBAL_QUOTA:
 *
 * Macro represents the maximum bandwidth to be used within a period for
 * whole domain, when using the posix scheduler, as VIR_TYPED_PARAM_LLONG.
 *
 * Since: 1.3.3
 */
# define VIR_DOMAIN_TUNABLE_CPU_GLOBAL_QUOTA "cputune.global_quota"

/**
 * VIR_DOMAIN_TUNABLE_CPU_VCPU_PERIOD:
 *
 * Macro represents the enforcement period for a quota, in microseconds,
 * for vcpus only, when using the posix scheduler, as VIR_TYPED_PARAM_ULLONG.
 *
 * Since: 1.2.9
 */
# define VIR_DOMAIN_TUNABLE_CPU_VCPU_PERIOD "cputune.vcpu_period"

/**
 * VIR_DOMAIN_TUNABLE_CPU_VCPU_QUOTA:
 *
 * Macro represents the maximum bandwidth to be used within a period for
 * vcpus only, when using the posix scheduler, as VIR_TYPED_PARAM_LLONG.
 *
 * Since: 1.2.9
 */
# define VIR_DOMAIN_TUNABLE_CPU_VCPU_QUOTA "cputune.vcpu_quota"

/**
 * VIR_DOMAIN_TUNABLE_CPU_EMULATOR_PERIOD:
 *
 * Macro represents the enforcement period for a quota in microseconds,
 * when using the posix scheduler, for all emulator activity not tied to
 * vcpus, as VIR_TYPED_PARAM_ULLONG.
 *
 * Since: 1.2.9
 */
# define VIR_DOMAIN_TUNABLE_CPU_EMULATOR_PERIOD "cputune.emulator_period"

/**
 * VIR_DOMAIN_TUNABLE_CPU_EMULATOR_QUOTA:
 *
 * Macro represents the maximum bandwidth to be used within a period for
 * all emulator activity not tied to vcpus, when using the posix scheduler,
 * as an VIR_TYPED_PARAM_LLONG.
 *
 * Since: 1.2.9
 */
# define VIR_DOMAIN_TUNABLE_CPU_EMULATOR_QUOTA "cputune.emulator_quota"

/**
 * VIR_DOMAIN_TUNABLE_CPU_IOTHREAD_PERIOD:
 *
 * Macro represents the enforcement period for a quota, in microseconds, for
 * iothreads only, when using the posix scheduler, as VIR_TYPED_PARAM_ULLONG.
 *
 * Since: 2.2.0
 */
# define VIR_DOMAIN_TUNABLE_CPU_IOTHREAD_PERIOD "cputune.iothread_period"

/**
 * VIR_DOMAIN_TUNABLE_CPU_IOTHREAD_QUOTA:
 *
 * Macro represents the maximum bandwidth to be used within a period for
 * iothreads only, when using the posix scheduler, as VIR_TYPED_PARAM_LLONG.
 *
 * Since: 2.2.0
 */
# define VIR_DOMAIN_TUNABLE_CPU_IOTHREAD_QUOTA "cputune.iothread_quota"

/**
 * VIR_DOMAIN_TUNABLE_BLKDEV_DISK:
 *
 * Macro represents the name of guest disk for which the values are updated,
 * as VIR_TYPED_PARAM_STRING.
 *
 * Since: 1.2.9
 */
# define VIR_DOMAIN_TUNABLE_BLKDEV_DISK "blkdeviotune.disk"

/**
 * VIR_DOMAIN_TUNABLE_BLKDEV_TOTAL_BYTES_SEC:
 *
 * Macro represents the total throughput limit in bytes per second,
 * as VIR_TYPED_PARAM_ULLONG.
 *
 * Since: 1.2.9
 */
# define VIR_DOMAIN_TUNABLE_BLKDEV_TOTAL_BYTES_SEC "blkdeviotune.total_bytes_sec"

/**
 * VIR_DOMAIN_TUNABLE_BLKDEV_READ_BYTES_SEC:
 *
 * Macro represents the read throughput limit in bytes per second,
 * as VIR_TYPED_PARAM_ULLONG.
 *
 * Since: 1.2.9
 */
# define VIR_DOMAIN_TUNABLE_BLKDEV_READ_BYTES_SEC "blkdeviotune.read_bytes_sec"

/**
 * VIR_DOMAIN_TUNABLE_BLKDEV_WRITE_BYTES_SEC:
 *
 * Macro represents the write throughput limit in bytes per second,
 * as VIR_TYPED_PARAM_ULLONG.
 *
 * Since: 1.2.9
 */
# define VIR_DOMAIN_TUNABLE_BLKDEV_WRITE_BYTES_SEC "blkdeviotune.write_bytes_sec"

/**
 * VIR_DOMAIN_TUNABLE_BLKDEV_TOTAL_IOPS_SEC:
 *
 * Macro represents the total I/O operations per second,
 * as VIR_TYPED_PARAM_ULLONG.
 *
 * Since: 1.2.9
 */
# define VIR_DOMAIN_TUNABLE_BLKDEV_TOTAL_IOPS_SEC "blkdeviotune.total_iops_sec"

/**
 * VIR_DOMAIN_TUNABLE_BLKDEV_READ_IOPS_SEC:
 *
 * Macro represents the read I/O operations per second,
 * as VIR_TYPED_PARAM_ULLONG.
 *
 * Since: 1.2.9
 */
# define VIR_DOMAIN_TUNABLE_BLKDEV_READ_IOPS_SEC "blkdeviotune.read_iops_sec"

/**
 * VIR_DOMAIN_TUNABLE_BLKDEV_WRITE_IOPS_SEC:
 *
 * Macro represents the write I/O operations per second,
 * as VIR_TYPED_PARAM_ULLONG.
 *
 * Since: 1.2.9
 */
# define VIR_DOMAIN_TUNABLE_BLKDEV_WRITE_IOPS_SEC "blkdeviotune.write_iops_sec"

/**
 * VIR_DOMAIN_TUNABLE_BLKDEV_TOTAL_BYTES_SEC_MAX:
 *
 * Macro represents the total throughput limit during bursts in
 * maximum bytes per second, as VIR_TYPED_PARAM_ULLONG.
 *
 * Since: 1.2.11
 */
# define VIR_DOMAIN_TUNABLE_BLKDEV_TOTAL_BYTES_SEC_MAX "blkdeviotune.total_bytes_sec_max"

/**
 * VIR_DOMAIN_TUNABLE_BLKDEV_READ_BYTES_SEC_MAX:
 *
 * Macro represents the read throughput limit during bursts in
 * maximum bytes per second, as VIR_TYPED_PARAM_ULLONG.
 *
 * Since: 1.2.11
 */
# define VIR_DOMAIN_TUNABLE_BLKDEV_READ_BYTES_SEC_MAX "blkdeviotune.read_bytes_sec_max"

/**
 * VIR_DOMAIN_TUNABLE_BLKDEV_WRITE_BYTES_SEC_MAX:
 *
 * Macro represents the write throughput limit during bursts in
 * maximum bytes per second, as VIR_TYPED_PARAM_ULLONG.
 *
 * Since: 1.2.11
 */
# define VIR_DOMAIN_TUNABLE_BLKDEV_WRITE_BYTES_SEC_MAX "blkdeviotune.write_bytes_sec_max"

/**
 * VIR_DOMAIN_TUNABLE_BLKDEV_TOTAL_IOPS_SEC_MAX:
 *
 * Macro represents the total maximum I/O operations per second during bursts,
 * as VIR_TYPED_PARAM_ULLONG.
 *
 * Since: 1.2.11
 */
# define VIR_DOMAIN_TUNABLE_BLKDEV_TOTAL_IOPS_SEC_MAX "blkdeviotune.total_iops_sec_max"

/**
 * VIR_DOMAIN_TUNABLE_BLKDEV_READ_IOPS_SEC_MAX:
 *
 * Macro represents the read maximum I/O operations per second during bursts,
 * as VIR_TYPED_PARAM_ULLONG.
 *
 * Since: 1.2.11
 */
# define VIR_DOMAIN_TUNABLE_BLKDEV_READ_IOPS_SEC_MAX "blkdeviotune.read_iops_sec_max"

/**
 * VIR_DOMAIN_TUNABLE_BLKDEV_WRITE_IOPS_SEC_MAX:
 *
 * Macro represents the write maximum I/O operations per second during bursts,
 * as VIR_TYPED_PARAM_ULLONG.
 *
 * Since: 1.2.11
 */
# define VIR_DOMAIN_TUNABLE_BLKDEV_WRITE_IOPS_SEC_MAX "blkdeviotune.write_iops_sec_max"

/**
 * VIR_DOMAIN_TUNABLE_BLKDEV_SIZE_IOPS_SEC:
 *
 * Macro represents the size maximum I/O operations per second,
 * as VIR_TYPED_PARAM_ULLONG.
 *
 * Since: 1.2.11
 */
# define VIR_DOMAIN_TUNABLE_BLKDEV_SIZE_IOPS_SEC "blkdeviotune.size_iops_sec"

/**
 * VIR_DOMAIN_TUNABLE_BLKDEV_GROUP_NAME:
 *
 * Macro represents the group name to be used,
 * as VIR_TYPED_PARAM_STRING.
 *
 * Since: 3.0.0
 */
# define VIR_DOMAIN_TUNABLE_BLKDEV_GROUP_NAME "blkdeviotune.group_name"

/**
 * VIR_DOMAIN_TUNABLE_BLKDEV_TOTAL_BYTES_SEC_MAX_LENGTH:
 *
 * Macro represents the length in seconds allowed for a burst period
 * for the blkdeviotune.total_bytes_sec_max,
 * as VIR_TYPED_PARAM_ULLONG.
 *
 * Since: 2.4.0
 */
# define VIR_DOMAIN_TUNABLE_BLKDEV_TOTAL_BYTES_SEC_MAX_LENGTH "blkdeviotune.total_bytes_sec_max_length"

/**
 * VIR_DOMAIN_TUNABLE_BLKDEV_READ_BYTES_SEC_MAX_LENGTH:
 *
 * Macro represents the length in seconds allowed for a burst period
 * for the blkdeviotune.read_bytes_sec_max
 * as VIR_TYPED_PARAM_ULLONG.
 *
 * Since: 2.4.0
 */
# define VIR_DOMAIN_TUNABLE_BLKDEV_READ_BYTES_SEC_MAX_LENGTH "blkdeviotune.read_bytes_sec_max_length"

/**
 * VIR_DOMAIN_TUNABLE_BLKDEV_WRITE_BYTES_SEC_MAX_LENGTH:
 *
 * Macro represents the length in seconds allowed for a burst period
 * for the blkdeviotune.write_bytes_sec_max
 * as VIR_TYPED_PARAM_ULLONG.
 *
 * Since: 2.4.0
 */
# define VIR_DOMAIN_TUNABLE_BLKDEV_WRITE_BYTES_SEC_MAX_LENGTH "blkdeviotune.write_bytes_sec_max_length"

/**
 * VIR_DOMAIN_TUNABLE_BLKDEV_TOTAL_IOPS_SEC_MAX_LENGTH:
 *
 * Macro represents the length in seconds allowed for a burst period
 * for the blkdeviotune.total_iops_sec_max
 * as VIR_TYPED_PARAM_ULLONG.
 *
 * Since: 2.4.0
 */
# define VIR_DOMAIN_TUNABLE_BLKDEV_TOTAL_IOPS_SEC_MAX_LENGTH "blkdeviotune.total_iops_sec_max_length"

/**
 * VIR_DOMAIN_TUNABLE_BLKDEV_READ_IOPS_SEC_MAX_LENGTH:
 *
 * Macro represents the length in seconds allowed for a burst period
 * for the blkdeviotune.read_iops_sec_max
 * as VIR_TYPED_PARAM_ULLONG.
 *
 * Since: 2.4.0
 */
# define VIR_DOMAIN_TUNABLE_BLKDEV_READ_IOPS_SEC_MAX_LENGTH "blkdeviotune.read_iops_sec_max_length"

/**
 * VIR_DOMAIN_TUNABLE_BLKDEV_WRITE_IOPS_SEC_MAX_LENGTH:
 *
 * Macro represents the length in seconds allowed for a burst period
 * for the blkdeviotune.write_iops_sec_max
 * as VIR_TYPED_PARAM_ULLONG.
 *
 * Since: 2.4.0
 */
# define VIR_DOMAIN_TUNABLE_BLKDEV_WRITE_IOPS_SEC_MAX_LENGTH "blkdeviotune.write_iops_sec_max_length"

/**
 * virConnectDomainEventTunableCallback:
 * @conn: connection object
 * @dom: domain on which the event occurred
 * @params: changed tunable values stored as array of virTypedParameter
 * @nparams: size of the array
 * @opaque: application specified data
 *
 * This callback occurs when tunable values are updated. The params must not
 * be freed in the callback handler as it's done internally after the callback
 * handler is executed.
 *
 * Currently supported name spaces:
 *  "cputune.*"
 *  "blkdeviotune.*"
 *
 * The callback signature to use when registering for an event of type
 * VIR_DOMAIN_EVENT_ID_TUNABLE with virConnectDomainEventRegisterAny()
 *
 * Since: 1.2.9
 */
typedef void (*virConnectDomainEventTunableCallback)(virConnectPtr conn,
                                                     virDomainPtr dom,
                                                     virTypedParameterPtr params,
                                                     int nparams,
                                                     void *opaque);


/**
 * virConnectDomainEventAgentLifecycleState:
 *
 * Since: 1.2.11
 */
typedef enum {
    VIR_CONNECT_DOMAIN_EVENT_AGENT_LIFECYCLE_STATE_CONNECTED = 1, /* agent connected (Since: 1.2.11) */
    VIR_CONNECT_DOMAIN_EVENT_AGENT_LIFECYCLE_STATE_DISCONNECTED = 2, /* agent disconnected (Since: 1.2.11) */

# ifdef VIR_ENUM_SENTINELS
    VIR_CONNECT_DOMAIN_EVENT_AGENT_LIFECYCLE_STATE_LAST /* (Since: 1.2.11) */
# endif
} virConnectDomainEventAgentLifecycleState;

/**
 * virConnectDomainEventAgentLifecycleReason:
 *
 * Since: 1.2.11
 */
typedef enum {
    VIR_CONNECT_DOMAIN_EVENT_AGENT_LIFECYCLE_REASON_UNKNOWN = 0, /* unknown state change reason (Since: 1.2.11) */
    VIR_CONNECT_DOMAIN_EVENT_AGENT_LIFECYCLE_REASON_DOMAIN_STARTED = 1, /* state changed due to domain start (Since: 1.2.11) */
    VIR_CONNECT_DOMAIN_EVENT_AGENT_LIFECYCLE_REASON_CHANNEL = 2, /* channel state changed (Since: 1.2.11) */

# ifdef VIR_ENUM_SENTINELS
    VIR_CONNECT_DOMAIN_EVENT_AGENT_LIFECYCLE_REASON_LAST /* (Since: 1.2.11) */
# endif
} virConnectDomainEventAgentLifecycleReason;

/**
 * virConnectDomainEventAgentLifecycleCallback:
 * @conn: connection object
 * @dom: domain on which the event occurred
 * @state: new state of the guest agent, one of virConnectDomainEventAgentLifecycleState
 * @reason: reason for state change; one of virConnectDomainEventAgentLifecycleReason
 * @opaque: application specified data
 *
 * This callback occurs when libvirt detects a change in the state of a guest
 * agent.
 *
 * The callback signature to use when registering for an event of type
 * VIR_DOMAIN_EVENT_ID_AGENT_LIFECYCLE with virConnectDomainEventRegisterAny()
 *
 * Since: 1.2.11
 */
typedef void (*virConnectDomainEventAgentLifecycleCallback)(virConnectPtr conn,
                                                            virDomainPtr dom,
                                                            int state,
                                                            int reason,
                                                            void *opaque);


/**
 * virConnectDomainEventBlockThresholdCallback:
 * @conn: connection object
 * @dom: domain on which the event occurred
 * @dev: name associated with the affected disk or storage backing chain
 *       element
 * @path: for local storage, the path of the backing chain element
 * @threshold: threshold offset in bytes
 * @excess: number of bytes written beyond the threshold
 * @opaque: application specified data
 *
 * The callback occurs when the hypervisor detects that the given storage
 * element was written beyond the point specified by @threshold. The excess
 * data size written beyond @threshold is reported by @excess (if supported
 * by the hypervisor, 0 otherwise). The event is useful for thin-provisioned
 * storage.
 *
 * The threshold size can be set via the virDomainSetBlockThreshold API.
 *
 * The callback signature to use when registering for an event of type
 * VIR_DOMAIN_EVENT_ID_BLOCK_THRESHOLD with virConnectDomainEventRegisterAny()
 *
 * Since: 3.2.0
 */
typedef void (*virConnectDomainEventBlockThresholdCallback)(virConnectPtr conn,
                                                            virDomainPtr dom,
                                                            const char *dev,
                                                            const char *path,
                                                            unsigned long long threshold,
                                                            unsigned long long excess,
                                                            void *opaque);

/**
 * virConnectDomainEventMemoryFailureCallback:
 * @conn: connection object
 * @dom: domain on which the event occurred
 * @recipient: the recipient of hardware memory failure
 *             (virDomainMemoryFailureRecipientType)
 * @action: the action of hardware memory failure
 *          (virDomainMemoryFailureActionType)
 * @flags: the flags of hardware memory failure (virDomainMemoryFailureFlags)
 * @opaque: application specified data
 *
 * The callback occurs when the hypervisor handles the hardware memory
 * corrupted event.
 *
 * The callback signature to use when registering for an event of type
 * VIR_DOMAIN_EVENT_ID_MEMORY_FAILURE with virConnectDomainEventRegisterAny()
 *
 * Since: 6.9.0
 */
typedef void (*virConnectDomainEventMemoryFailureCallback)(virConnectPtr conn,
                                                           virDomainPtr dom,
                                                           int recipient,
                                                           int action,
                                                           unsigned int flags,
                                                           void *opaque);


/**
 * virConnectDomainEventMemoryDeviceSizeChangeCallback:
 * @conn: connection object
 * @dom: domain on which the event occurred
 * @alias: memory device alias
 * @size: new current size of memory device (in KiB)
 * @opaque: application specified data
 *
 * The callback occurs when the guest acknowledges request to change size of
 * memory device (so far only virtio-mem model supports this). The @size then
 * reflects the new amount of guest visible memory (in kibibytes).
 *
 * The callback signature to use when registering for an event of type
 * VIR_DOMAIN_EVENT_ID_MEMORY_DEVICE_SIZE_CHANGE with
 * virConnectDomainEventRegisterAny().
 *
 * Since: 7.9.0
 */
typedef void (*virConnectDomainEventMemoryDeviceSizeChangeCallback)(virConnectPtr conn,
                                                                    virDomainPtr dom,
                                                                    const char *alias,
                                                                    unsigned long long size,
                                                                    void *opaque);


/**
 * VIR_DOMAIN_EVENT_CALLBACK:
 *
 * Used to cast the event specific callback into the generic one
 * for use for virConnectDomainEventRegisterAny()
 *
 * Since: 0.8.0
 */
# define VIR_DOMAIN_EVENT_CALLBACK(cb) ((virConnectDomainEventGenericCallback)(cb))


/**
 * virDomainEventID:
 *
 * An enumeration of supported eventId parameters for
 * virConnectDomainEventRegisterAny().  Each event id determines which
 * signature of callback function will be used.
 *
 * Since: 0.8.0
 */
typedef enum {
    VIR_DOMAIN_EVENT_ID_LIFECYCLE = 0,       /* virConnectDomainEventCallback (Since: 0.8.0) */
    VIR_DOMAIN_EVENT_ID_REBOOT = 1,          /* virConnectDomainEventGenericCallback (Since: 0.8.0) */
    VIR_DOMAIN_EVENT_ID_RTC_CHANGE = 2,      /* virConnectDomainEventRTCChangeCallback (Since: 0.8.0) */
    VIR_DOMAIN_EVENT_ID_WATCHDOG = 3,        /* virConnectDomainEventWatchdogCallback (Since: 0.8.0) */
    VIR_DOMAIN_EVENT_ID_IO_ERROR = 4,        /* virConnectDomainEventIOErrorCallback (Since: 0.8.0) */
    VIR_DOMAIN_EVENT_ID_GRAPHICS = 5,        /* virConnectDomainEventGraphicsCallback (Since: 0.8.0) */
    VIR_DOMAIN_EVENT_ID_IO_ERROR_REASON = 6, /* virConnectDomainEventIOErrorReasonCallback (Since: 0.8.1) */
    VIR_DOMAIN_EVENT_ID_CONTROL_ERROR = 7,   /* virConnectDomainEventGenericCallback (Since: 0.9.2) */
    VIR_DOMAIN_EVENT_ID_BLOCK_JOB = 8,       /* virConnectDomainEventBlockJobCallback (Since: 0.9.4) */
    VIR_DOMAIN_EVENT_ID_DISK_CHANGE = 9,     /* virConnectDomainEventDiskChangeCallback (Since: 0.9.7) */
    VIR_DOMAIN_EVENT_ID_TRAY_CHANGE = 10,    /* virConnectDomainEventTrayChangeCallback (Since: 0.9.11) */
    VIR_DOMAIN_EVENT_ID_PMWAKEUP = 11,       /* virConnectDomainEventPMWakeupCallback (Since: 0.9.11) */
    VIR_DOMAIN_EVENT_ID_PMSUSPEND = 12,      /* virConnectDomainEventPMSuspendCallback (Since: 0.9.11) */
    VIR_DOMAIN_EVENT_ID_BALLOON_CHANGE = 13, /* virConnectDomainEventBalloonChangeCallback (Since: 0.10.0) */
    VIR_DOMAIN_EVENT_ID_PMSUSPEND_DISK = 14, /* virConnectDomainEventPMSuspendDiskCallback (Since: 1.0.0) */
    VIR_DOMAIN_EVENT_ID_DEVICE_REMOVED = 15, /* virConnectDomainEventDeviceRemovedCallback (Since: 1.1.1) */
    VIR_DOMAIN_EVENT_ID_BLOCK_JOB_2 = 16,    /* virConnectDomainEventBlockJobCallback (Since: 1.2.6) */
    VIR_DOMAIN_EVENT_ID_TUNABLE = 17,        /* virConnectDomainEventTunableCallback (Since: 1.2.9) */
    VIR_DOMAIN_EVENT_ID_AGENT_LIFECYCLE = 18,/* virConnectDomainEventAgentLifecycleCallback (Since: 1.2.11) */
    VIR_DOMAIN_EVENT_ID_DEVICE_ADDED = 19,   /* virConnectDomainEventDeviceAddedCallback (Since: 1.2.15) */
    VIR_DOMAIN_EVENT_ID_MIGRATION_ITERATION = 20, /* virConnectDomainEventMigrationIterationCallback (Since: 1.3.2) */
    VIR_DOMAIN_EVENT_ID_JOB_COMPLETED = 21,  /* virConnectDomainEventJobCompletedCallback (Since: 1.3.3) */
    VIR_DOMAIN_EVENT_ID_DEVICE_REMOVAL_FAILED = 22, /* virConnectDomainEventDeviceRemovalFailedCallback (Since: 1.3.4) */
    VIR_DOMAIN_EVENT_ID_METADATA_CHANGE = 23, /* virConnectDomainEventMetadataChangeCallback (Since: 3.0.0) */
    VIR_DOMAIN_EVENT_ID_BLOCK_THRESHOLD = 24, /* virConnectDomainEventBlockThresholdCallback (Since: 3.2.0) */
    VIR_DOMAIN_EVENT_ID_MEMORY_FAILURE = 25,  /* virConnectDomainEventMemoryFailureCallback (Since: 6.9.0) */
    VIR_DOMAIN_EVENT_ID_MEMORY_DEVICE_SIZE_CHANGE = 26, /* virConnectDomainEventMemoryDeviceSizeChangeCallback (Since: 7.9.0) */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_EVENT_ID_LAST
    /*
     * NB: this enum value will increase over time as new events are
     * added to the libvirt API. It reflects the last event ID supported
     * by this version of the libvirt API.
     *
     * Since: 0.8.0
     */
# endif
} virDomainEventID;


/* Use VIR_DOMAIN_EVENT_CALLBACK() to cast the 'cb' parameter  */
int virConnectDomainEventRegisterAny(virConnectPtr conn,
                                     virDomainPtr dom, /* Optional, to filter */
                                     int eventID,
                                     virConnectDomainEventGenericCallback cb,
                                     void *opaque,
                                     virFreeCallback freecb);

int virConnectDomainEventDeregisterAny(virConnectPtr conn,
                                       int callbackID);


/**
 * virDomainConsoleFlags:
 *
 * Since: 0.9.11
 */
typedef enum {

    VIR_DOMAIN_CONSOLE_FORCE = (1 << 0), /* abort a (possibly) active console
                                            connection to force a new
                                            connection (Since: 0.9.11) */
    VIR_DOMAIN_CONSOLE_SAFE = (1 << 1), /* check if the console driver supports
                                           safe console operations (Since: 0.9.11) */
} virDomainConsoleFlags;

int virDomainOpenConsole(virDomainPtr dom,
                         const char *dev_name,
                         virStreamPtr st,
                         unsigned int flags);

/**
 * virDomainChannelFlags:
 *
 * Since: 1.0.2
 */
typedef enum {
    VIR_DOMAIN_CHANNEL_FORCE = (1 << 0), /* abort a (possibly) active channel
                                            connection to force a new
                                            connection (Since: 1.0.2) */
} virDomainChannelFlags;

int virDomainOpenChannel(virDomainPtr dom,
                         const char *name,
                         virStreamPtr st,
                         unsigned int flags);

/**
 * virDomainOpenGraphicsFlags:
 *
 * Since: 0.9.7
 */
typedef enum {
    VIR_DOMAIN_OPEN_GRAPHICS_SKIPAUTH = (1 << 0), /* (Since: 0.9.7) */
} virDomainOpenGraphicsFlags;

int virDomainOpenGraphics(virDomainPtr dom,
                          unsigned int idx,
                          int fd,
                          unsigned int flags);

int virDomainOpenGraphicsFD(virDomainPtr dom,
                            unsigned int idx,
                            unsigned int flags);

int virDomainInjectNMI(virDomainPtr domain, unsigned int flags);

int virDomainFSTrim(virDomainPtr dom,
                    const char *mountPoint,
                    unsigned long long minimum,
                    unsigned int flags);

int virDomainFSFreeze(virDomainPtr dom,
                      const char **mountpoints,
                      unsigned int nmountpoints,
                      unsigned int flags);

int virDomainFSThaw(virDomainPtr dom,
                    const char **mountpoints,
                    unsigned int nmountpoints,
                    unsigned int flags);

/**
 * virDomainFSInfo:
 *
 * The data structure containing mounted file systems within a guset
 *
 * Since: 1.2.11
 */
typedef struct _virDomainFSInfo virDomainFSInfo;

/**
 * virDomainFSInfoPtr:
 *
 * Since: 1.2.11
 */
typedef virDomainFSInfo *virDomainFSInfoPtr;

struct _virDomainFSInfo {
    char *mountpoint; /* path to mount point */
    char *name;       /* device name in the guest (e.g. "sda1") */
    char *fstype;     /* filesystem type */
    size_t ndevAlias; /* number of elements in devAlias */
    char **devAlias;  /* array of disk device aliases */
};

void virDomainFSInfoFree(virDomainFSInfoPtr info);

int virDomainGetFSInfo(virDomainPtr dom,
                       virDomainFSInfoPtr **info,
                       unsigned int flags);

int virDomainGetTime(virDomainPtr dom,
                     long long *seconds,
                     unsigned int *nseconds,
                     unsigned int flags);
/**
 * virDomainSetTimeFlags:
 *
 * Since: 1.2.5
 */
typedef enum {
    VIR_DOMAIN_TIME_SYNC = (1 << 0), /* Re-sync domain time from domain's RTC (Since: 1.2.5) */
} virDomainSetTimeFlags;

int virDomainSetTime(virDomainPtr dom,
                     long long seconds,
                     unsigned int nseconds,
                     unsigned int flags);

/**
 * virSchedParameterType:
 *
 * A scheduler parameter field type.  Provided for backwards
 * compatibility; virTypedParameterType is the preferred enum
 *
 * Since: 0.2.3
 */
typedef enum {
    VIR_DOMAIN_SCHED_FIELD_INT     = VIR_TYPED_PARAM_INT, /* (Since: 0.2.3) */
    VIR_DOMAIN_SCHED_FIELD_UINT    = VIR_TYPED_PARAM_UINT, /* (Since: 0.2.3) */
    VIR_DOMAIN_SCHED_FIELD_LLONG   = VIR_TYPED_PARAM_LLONG, /* (Since: 0.2.3) */
    VIR_DOMAIN_SCHED_FIELD_ULLONG  = VIR_TYPED_PARAM_ULLONG, /* (Since: 0.2.3) */
    VIR_DOMAIN_SCHED_FIELD_DOUBLE  = VIR_TYPED_PARAM_DOUBLE, /* (Since: 0.2.3) */
    VIR_DOMAIN_SCHED_FIELD_BOOLEAN = VIR_TYPED_PARAM_BOOLEAN, /* (Since: 0.2.3) */
} virSchedParameterType;

/**
 * VIR_DOMAIN_SCHED_FIELD_LENGTH:
 *
 * Macro providing the field length of virSchedParameter.  Provided
 * for backwards compatibility; VIR_TYPED_PARAM_FIELD_LENGTH is the
 * preferred value
 *
 * Since: 0.2.3
 */
# define VIR_DOMAIN_SCHED_FIELD_LENGTH VIR_TYPED_PARAM_FIELD_LENGTH

/**
 * _virSchedParameter:
 *
 * Since: 0.2.3
 */
# define _virSchedParameter _virTypedParameter

/**
 * virSchedParameter:
 *
 * a virSchedParameter is the set of scheduler parameters.
 * Provided for backwards compatibility; virTypedParameter is the
 * preferred alias.
 *
 * Since: 0.2.3
 */
typedef struct _virTypedParameter virSchedParameter;

/**
 * virSchedParameterPtr:
 *
 * a virSchedParameterPtr is a pointer to a virSchedParameter structure.
 * Provided for backwards compatibility; virTypedParameterPtr is the
 * preferred alias since 0.9.2.
 *
 * Since: 0.2.3
 */
typedef virSchedParameter *virSchedParameterPtr;

/**
 * virBlkioParameterType:
 *
 * A blkio parameter field type.  Provided for backwards
 * compatibility; virTypedParameterType is the preferred enum
 *
 * Since: 0.9.0
 */
typedef enum {
    VIR_DOMAIN_BLKIO_PARAM_INT     = VIR_TYPED_PARAM_INT, /* (Since: 0.9.0) */
    VIR_DOMAIN_BLKIO_PARAM_UINT    = VIR_TYPED_PARAM_UINT, /* (Since: 0.9.0) */
    VIR_DOMAIN_BLKIO_PARAM_LLONG   = VIR_TYPED_PARAM_LLONG, /* (Since: 0.9.0) */
    VIR_DOMAIN_BLKIO_PARAM_ULLONG  = VIR_TYPED_PARAM_ULLONG, /* (Since: 0.9.0) */
    VIR_DOMAIN_BLKIO_PARAM_DOUBLE  = VIR_TYPED_PARAM_DOUBLE, /* (Since: 0.9.0) */
    VIR_DOMAIN_BLKIO_PARAM_BOOLEAN = VIR_TYPED_PARAM_BOOLEAN, /* (Since: 0.9.0) */
} virBlkioParameterType;

/**
 * VIR_DOMAIN_BLKIO_FIELD_LENGTH:
 *
 * Macro providing the field length of virBlkioParameter.  Provided
 * for backwards compatibility; VIR_TYPED_PARAM_FIELD_LENGTH is the
 * preferred value.
 *
 * Since: 0.9.0
 */
# define VIR_DOMAIN_BLKIO_FIELD_LENGTH VIR_TYPED_PARAM_FIELD_LENGTH

/**
 * _virBlkioParameter:
 *
 * Since: 0.9.0
 */
# define _virBlkioParameter _virTypedParameter

/**
 * virBlkioParameter:
 *
 * a virBlkioParameter is the set of blkio parameters.
 * Provided for backwards compatibility; virTypedParameter is the
 * preferred alias.
 *
 * Since: 0.9.0
 */
typedef struct _virTypedParameter virBlkioParameter;

/**
 * virBlkioParameterPtr:
 *
 * a virBlkioParameterPtr is a pointer to a virBlkioParameter structure.
 * Provided for backwards compatibility; virTypedParameterPtr is the
 * preferred alias.
 *
 * Since: 0.9.0
 */
typedef virBlkioParameter *virBlkioParameterPtr;

/**
 * virMemoryParameterType:
 *
 * A memory parameter field type.  Provided for backwards
 * compatibility; virTypedParameterType is the preferred enum
 *
 * Since: 0.8.5
 */
typedef enum {
    VIR_DOMAIN_MEMORY_PARAM_INT     = VIR_TYPED_PARAM_INT, /* (Since: 0.8.5) */
    VIR_DOMAIN_MEMORY_PARAM_UINT    = VIR_TYPED_PARAM_UINT, /* (Since: 0.8.5) */
    VIR_DOMAIN_MEMORY_PARAM_LLONG   = VIR_TYPED_PARAM_LLONG, /* (Since: 0.8.5) */
    VIR_DOMAIN_MEMORY_PARAM_ULLONG  = VIR_TYPED_PARAM_ULLONG, /* (Since: 0.8.5) */
    VIR_DOMAIN_MEMORY_PARAM_DOUBLE  = VIR_TYPED_PARAM_DOUBLE, /* (Since: 0.8.5) */
    VIR_DOMAIN_MEMORY_PARAM_BOOLEAN = VIR_TYPED_PARAM_BOOLEAN, /* (Since: 0.8.5) */
} virMemoryParameterType;

/**
 * VIR_DOMAIN_MEMORY_FIELD_LENGTH:
 *
 * Macro providing the field length of virMemoryParameter.  Provided
 * for backwards compatibility; VIR_TYPED_PARAM_FIELD_LENGTH is the
 * preferred value.
 *
 * Since: 0.8.5
 */
# define VIR_DOMAIN_MEMORY_FIELD_LENGTH VIR_TYPED_PARAM_FIELD_LENGTH

/**
 * _virMemoryParameter:
 *
 * Since: 0.8.5
 */
# define _virMemoryParameter _virTypedParameter

/**
 * virMemoryParameter:
 *
 * a virMemoryParameter is the set of scheduler parameters.
 * Provided for backwards compatibility; virTypedParameter is the
 * preferred alias.
 *
 * Since: 0.8.5
 */
typedef struct _virTypedParameter virMemoryParameter;

/**
 * virMemoryParameterPtr:
 *
 * a virMemoryParameterPtr is a pointer to a virMemoryParameter structure.
 * Provided for backwards compatibility; virTypedParameterPtr is the
 * preferred alias.
 *
 * Since: 0.8.5
 */
typedef virMemoryParameter *virMemoryParameterPtr;

/**
 * virDomainInterfaceAddressesSource:
 *
 * Since: 1.2.14
 */
typedef enum {
    VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_LEASE = 0, /* Parse DHCP lease file (Since: 1.2.14) */
    VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_AGENT = 1, /* Query qemu guest agent (Since: 1.2.14) */
    VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_ARP = 2, /* Query ARP tables (Since: 4.2.0) */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_LAST /* (Since: 1.2.14) */
# endif
} virDomainInterfaceAddressesSource;

/**
 * virDomainIPAddress:
 *
 * Since: 1.2.14
 */
typedef struct _virDomainInterfaceIPAddress virDomainIPAddress;

/**
 * virDomainIPAddressPtr:
 *
 * Since: 1.2.14
 */
typedef virDomainIPAddress *virDomainIPAddressPtr;
struct _virDomainInterfaceIPAddress {
    int type;                /* virIPAddrType */
    char *addr;              /* IP address */
    unsigned int prefix;     /* IP address prefix */
};

/**
 * virDomainInterface:
 *
 * Since: 1.2.14
 */
typedef struct _virDomainInterface virDomainInterface;

/**
 * virDomainInterfacePtr:
 *
 * Since: 1.2.14
 */
typedef virDomainInterface *virDomainInterfacePtr;
struct _virDomainInterface {
    char *name;                     /* interface name */
    char *hwaddr;                   /* hardware address, may be NULL */
    unsigned int naddrs;            /* number of items in @addrs */
    virDomainIPAddressPtr addrs;    /* array of IP addresses */
};

int virDomainInterfaceAddresses(virDomainPtr dom,
                                virDomainInterfacePtr **ifaces,
                                unsigned int source,
                                unsigned int flags);

void virDomainInterfaceFree(virDomainInterfacePtr iface);

/**
 * virDomainSetUserPasswordFlags:
 *
 * Since: 1.2.16
 */
typedef enum {
    VIR_DOMAIN_PASSWORD_ENCRYPTED = 1 << 0, /* the password is already encrypted (Since: 1.2.16) */
} virDomainSetUserPasswordFlags;

int virDomainSetUserPassword(virDomainPtr dom,
                             const char *user,
                             const char *password,
                             unsigned int flags);

int virDomainRename(virDomainPtr dom,
                    const char *new_name,
                    unsigned int flags);

int virDomainGetGuestVcpus(virDomainPtr domain,
                           virTypedParameterPtr *params,
                           unsigned int *nparams,
                           unsigned int flags);

int virDomainSetGuestVcpus(virDomainPtr domain,
                           const char *cpumap,
                           int state,
                           unsigned int flags);

int virDomainSetVcpu(virDomainPtr domain,
                     const char *vcpumap,
                     int state,
                     unsigned int flags);

int virDomainSetBlockThreshold(virDomainPtr domain,
                               const char *dev,
                               unsigned long long threshold,
                               unsigned int flags);

/**
 * virDomainLifecycle:
 *
 * Since: 3.9.0
 */
typedef enum {
    VIR_DOMAIN_LIFECYCLE_POWEROFF = 0, /* (Since: 3.9.0) */
    VIR_DOMAIN_LIFECYCLE_REBOOT = 1, /* (Since: 3.9.0) */
    VIR_DOMAIN_LIFECYCLE_CRASH = 2, /* (Since: 3.9.0) */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_LIFECYCLE_LAST /* (Since: 3.9.0) */
# endif
} virDomainLifecycle;

/**
 * virDomainLifecycleAction:
 *
 * Since: 3.9.0
 */
typedef enum {
    VIR_DOMAIN_LIFECYCLE_ACTION_DESTROY = 0, /* (Since: 3.9.0) */
    VIR_DOMAIN_LIFECYCLE_ACTION_RESTART = 1, /* (Since: 3.9.0) */
    VIR_DOMAIN_LIFECYCLE_ACTION_RESTART_RENAME = 2, /* (Since: 3.9.0) */
    VIR_DOMAIN_LIFECYCLE_ACTION_PRESERVE = 3, /* (Since: 3.9.0) */
    VIR_DOMAIN_LIFECYCLE_ACTION_COREDUMP_DESTROY = 4, /* (Since: 3.9.0) */
    VIR_DOMAIN_LIFECYCLE_ACTION_COREDUMP_RESTART = 5, /* (Since: 3.9.0) */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_LIFECYCLE_ACTION_LAST /* (Since: 3.9.0) */
# endif
} virDomainLifecycleAction;

int virDomainSetLifecycleAction(virDomainPtr domain,
                                unsigned int type,
                                unsigned int action,
                                unsigned int flags);

/**
 * Launch Security API
 */

/**
 * VIR_DOMAIN_LAUNCH_SECURITY_SEV_MEASUREMENT:
 *
 * Macro represents the launch measurement of the SEV guest,
 * as VIR_TYPED_PARAM_STRING.
 *
 * Since: 4.5.0
 */
# define VIR_DOMAIN_LAUNCH_SECURITY_SEV_MEASUREMENT "sev-measurement"

/**

 * VIR_DOMAIN_LAUNCH_SECURITY_SEV_API_MAJOR:
 *
 * Macro represents the API major version of the SEV host,
 * as VIR_TYPED_PARAM_UINT.
 *
 * Since: 8.0.0
 */
# define VIR_DOMAIN_LAUNCH_SECURITY_SEV_API_MAJOR "sev-api-major"

/**
 * VIR_DOMAIN_LAUNCH_SECURITY_SEV_API_MINOR:
 *
 * Macro represents the API minor version of the SEV guest,
 * as VIR_TYPED_PARAM_UINT.
 *
 * Since: 8.0.0
 */
# define VIR_DOMAIN_LAUNCH_SECURITY_SEV_API_MINOR "sev-api-minor"

/**
 * VIR_DOMAIN_LAUNCH_SECURITY_SEV_BUILD_ID:
 *
 * Macro represents the build ID of the SEV host,
 * as VIR_TYPED_PARAM_UINT.
 *
 * Since: 8.0.0
 */
# define VIR_DOMAIN_LAUNCH_SECURITY_SEV_BUILD_ID "sev-build-id"

/**
 * VIR_DOMAIN_LAUNCH_SECURITY_SEV_POLICY:
 *
 * Macro represents the policy of the SEV guest,
 * as VIR_TYPED_PARAM_UINT.
 *
 * Since: 8.0.0
 */
# define VIR_DOMAIN_LAUNCH_SECURITY_SEV_POLICY "sev-policy"

/**
 * VIR_DOMAIN_LAUNCH_SECURITY_SEV_SECRET_HEADER:
 *
 * A macro used to represent the SEV launch secret header. The secret header
 * is a base64-encoded VIR_TYPED_PARAM_STRING containing artifacts needed by
 * the SEV firmware to recover the plain text of the launch secret. See
 * section "6.6 LAUNCH_SECRET" in the SEV API specification for a detailed
 * description of the secret header.
 *
 * Since: 8.0.0
 */
# define VIR_DOMAIN_LAUNCH_SECURITY_SEV_SECRET_HEADER "sev-secret-header"

/**
 * VIR_DOMAIN_LAUNCH_SECURITY_SEV_SECRET:
 *
 * A macro used to represent the SEV launch secret. The secret is a
 * base64-encoded VIR_TYPED_PARAM_STRING containing an encrypted launch
 * secret. The secret is created by the domain owner after the SEV launch
 * measurement is retrieved and verified.
 *
 * Since: 8.0.0
 */
# define VIR_DOMAIN_LAUNCH_SECURITY_SEV_SECRET "sev-secret"

/**
 * VIR_DOMAIN_LAUNCH_SECURITY_SEV_SECRET_SET_ADDRESS:
 *
 * A macro used to represent the physical address within the guest's memory
 * where the secret will be set, as VIR_TYPED_PARAM_ULLONG. If not specified,
 * the address will be determined by the hypervisor.
 *
 * Since: 8.0.0
 */
# define VIR_DOMAIN_LAUNCH_SECURITY_SEV_SECRET_SET_ADDRESS "sev-secret-set-address"

int virDomainGetLaunchSecurityInfo(virDomainPtr domain,
                                   virTypedParameterPtr *params,
                                   int *nparams,
                                   unsigned int flags);

int virDomainSetLaunchSecurityState(virDomainPtr domain,
                                    virTypedParameterPtr params,
                                    int nparams,
                                    unsigned int flags);

/**
 * virDomainGuestInfoTypes:
 *
 * Since: 5.7.0
 */
typedef enum {
    VIR_DOMAIN_GUEST_INFO_USERS = (1 << 0), /* return active users (Since: 5.7.0) */
    VIR_DOMAIN_GUEST_INFO_OS = (1 << 1), /* return OS information (Since: 5.7.0) */
    VIR_DOMAIN_GUEST_INFO_TIMEZONE = (1 << 2), /* return timezone information (Since: 5.7.0) */
    VIR_DOMAIN_GUEST_INFO_HOSTNAME = (1 << 3), /* return hostname information (Since: 5.7.0) */
    VIR_DOMAIN_GUEST_INFO_FILESYSTEM = (1 << 4), /* return filesystem information (Since: 5.7.0) */
    VIR_DOMAIN_GUEST_INFO_DISKS = (1 << 5), /* return disks information (Since: 7.0.0) */
    VIR_DOMAIN_GUEST_INFO_INTERFACES = (1 << 6), /* return interfaces information (Since: 7.10.0) */
} virDomainGuestInfoTypes;

int virDomainGetGuestInfo(virDomainPtr domain,
                          unsigned int types,
                          virTypedParameterPtr *params,
                          int *nparams,
                          unsigned int flags);

/**
 * virDomainAgentResponseTimeoutValues:
 *
 * Since: 5.10.0
 */
typedef enum {
    VIR_DOMAIN_AGENT_RESPONSE_TIMEOUT_BLOCK = -2, /* (Since: 5.10.0) */
    VIR_DOMAIN_AGENT_RESPONSE_TIMEOUT_DEFAULT = -1, /* (Since: 5.10.0) */
    VIR_DOMAIN_AGENT_RESPONSE_TIMEOUT_NOWAIT = 0, /* (Since: 5.10.0) */
} virDomainAgentResponseTimeoutValues;

int virDomainAgentSetResponseTimeout(virDomainPtr domain,
                                     int timeout,
                                     unsigned int flags);

/**
 * virDomainBackupBeginFlags:
 *
 * Since: 6.0.0
 */
typedef enum {
    VIR_DOMAIN_BACKUP_BEGIN_REUSE_EXTERNAL = (1 << 0), /* reuse separately
                                                          provided images (Since: 6.0.0) */
} virDomainBackupBeginFlags;

int virDomainBackupBegin(virDomainPtr domain,
                         const char *backupXML,
                         const char *checkpointXML,
                         unsigned int flags);

char *virDomainBackupGetXMLDesc(virDomainPtr domain,
                                unsigned int flags);

int virDomainAuthorizedSSHKeysGet(virDomainPtr domain,
                                  const char *user,
                                  char ***keys,
                                  unsigned int flags);

/**
 * virDomainAuthorizedSSHKeysSetFlags:
 *
 * Since: 6.10.0
 */
typedef enum {
    VIR_DOMAIN_AUTHORIZED_SSH_KEYS_SET_APPEND = (1 << 0), /* don't truncate file, just append (Since: 6.10.0) */
    VIR_DOMAIN_AUTHORIZED_SSH_KEYS_SET_REMOVE = (1 << 1), /* remove keys, instead of adding them (Since: 6.10.0) */

} virDomainAuthorizedSSHKeysSetFlags;

int virDomainAuthorizedSSHKeysSet(virDomainPtr domain,
                                  const char *user,
                                  const char **keys,
                                  unsigned int nkeys,
                                  unsigned int flags);

/**
 * virDomainMessageType:
 *
 * Since: 7.1.0
 */
typedef enum {
    VIR_DOMAIN_MESSAGE_DEPRECATION = (1 << 0), /* (Since: 7.1.0) */
    VIR_DOMAIN_MESSAGE_TAINTING = (1 << 1), /* (Since: 7.1.0) */
} virDomainMessageType;

int virDomainGetMessages(virDomainPtr domain,
                         char ***msgs,
                         unsigned int flags);

/**
 * virDomainDirtyRateStatus:
 *
 * Details on the cause of a dirty rate calculation status.
 *
 * Since: 7.2.0
 */
typedef enum {
    VIR_DOMAIN_DIRTYRATE_UNSTARTED = 0, /* the dirtyrate calculation has
                                           not been started (Since: 7.2.0) */
    VIR_DOMAIN_DIRTYRATE_MEASURING = 1, /* the dirtyrate calculation is
                                           measuring (Since: 7.2.0) */
    VIR_DOMAIN_DIRTYRATE_MEASURED  = 2, /* the dirtyrate calculation is
                                           completed (Since: 7.2.0) */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_DIRTYRATE_LAST /* (Since: 7.2.0) */
# endif
} virDomainDirtyRateStatus;

/**
 * virDomainDirtyRateCalcFlags:
 *
 * Flags OR'ed together to provide specific behaviour when calculating dirty page
 * rate for a Domain
 *
 *
 * Since: 8.1.0
 */
typedef enum {
    VIR_DOMAIN_DIRTYRATE_MODE_PAGE_SAMPLING = 0,        /* default mode - page-sampling (Since: 8.1.0) */
    VIR_DOMAIN_DIRTYRATE_MODE_DIRTY_BITMAP = 1 << 0,    /* dirty-bitmap mode (Since: 8.1.0) */
    VIR_DOMAIN_DIRTYRATE_MODE_DIRTY_RING = 1 << 1,      /* dirty-ring mode (Since: 8.1.0) */
} virDomainDirtyRateCalcFlags;

int virDomainStartDirtyRateCalc(virDomainPtr domain,
                                int seconds,
                                unsigned int flags);


/**
 * virDomainFDAssociateFlags:
 *
 * Since: 9.0.0
 */
typedef enum {
    /* Attempt a best-effort restore of security labels after use (Since: 9.0.0) */
    VIR_DOMAIN_FD_ASSOCIATE_SECLABEL_RESTORE = (1 << 0),
    /* Use a seclabel allowing writes for the FD even if usage implies read-only mode (Since: 9.0.0) */
    VIR_DOMAIN_FD_ASSOCIATE_SECLABEL_WRITABLE = (1 << 1),
} virDomainFDAssociateFlags;


int virDomainFDAssociate(virDomainPtr domain,
                         const char *name,
                         unsigned int nfds,
                         int *fds,
                         unsigned int flags);

#endif /* LIBVIRT_DOMAIN_H */
