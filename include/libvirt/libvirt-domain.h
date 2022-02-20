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
 */
typedef struct _virDomain virDomain;

/**
 * virDomainPtr:
 *
 * a virDomainPtr is pointer to a virDomain private structure, this is the
 * type used to reference a domain in the API.
 */
typedef virDomain *virDomainPtr;

/**
 * virDomainState:
 *
 * A domain may be in different states at a given point in time
 */
typedef enum {
    VIR_DOMAIN_NOSTATE = 0,     /* no state */
    VIR_DOMAIN_RUNNING = 1,     /* the domain is running */
    VIR_DOMAIN_BLOCKED = 2,     /* the domain is blocked on resource */
    VIR_DOMAIN_PAUSED  = 3,     /* the domain is paused by user */
    VIR_DOMAIN_SHUTDOWN= 4,     /* the domain is being shut down */
    VIR_DOMAIN_SHUTOFF = 5,     /* the domain is shut off */
    VIR_DOMAIN_CRASHED = 6,     /* the domain is crashed */
    VIR_DOMAIN_PMSUSPENDED = 7, /* the domain is suspended by guest
                                   power management */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_LAST
    /*
     * NB: this enum value will increase over time as new states are
     * added to the libvirt API. It reflects the last state supported
     * by this version of the libvirt API.
     */
# endif
} virDomainState;

typedef enum {
    VIR_DOMAIN_NOSTATE_UNKNOWN = 0,

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_NOSTATE_LAST
# endif
} virDomainNostateReason;

typedef enum {
    VIR_DOMAIN_RUNNING_UNKNOWN = 0,
    VIR_DOMAIN_RUNNING_BOOTED = 1,          /* normal startup from boot */
    VIR_DOMAIN_RUNNING_MIGRATED = 2,        /* migrated from another host */
    VIR_DOMAIN_RUNNING_RESTORED = 3,        /* restored from a state file */
    VIR_DOMAIN_RUNNING_FROM_SNAPSHOT = 4,   /* restored from snapshot */
    VIR_DOMAIN_RUNNING_UNPAUSED = 5,        /* returned from paused state */
    VIR_DOMAIN_RUNNING_MIGRATION_CANCELED = 6,  /* returned from migration */
    VIR_DOMAIN_RUNNING_SAVE_CANCELED = 7,   /* returned from failed save process */
    VIR_DOMAIN_RUNNING_WAKEUP = 8,          /* returned from pmsuspended due to
                                               wakeup event */
    VIR_DOMAIN_RUNNING_CRASHED = 9,         /* resumed from crashed */
    VIR_DOMAIN_RUNNING_POSTCOPY = 10,       /* running in post-copy migration mode */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_RUNNING_LAST
# endif
} virDomainRunningReason;

typedef enum {
    VIR_DOMAIN_BLOCKED_UNKNOWN = 0,     /* the reason is unknown */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_BLOCKED_LAST
# endif
} virDomainBlockedReason;

typedef enum {
    VIR_DOMAIN_PAUSED_UNKNOWN = 0,      /* the reason is unknown */
    VIR_DOMAIN_PAUSED_USER = 1,         /* paused on user request */
    VIR_DOMAIN_PAUSED_MIGRATION = 2,    /* paused for offline migration */
    VIR_DOMAIN_PAUSED_SAVE = 3,         /* paused for save */
    VIR_DOMAIN_PAUSED_DUMP = 4,         /* paused for offline core dump */
    VIR_DOMAIN_PAUSED_IOERROR = 5,      /* paused due to a disk I/O error */
    VIR_DOMAIN_PAUSED_WATCHDOG = 6,     /* paused due to a watchdog event */
    VIR_DOMAIN_PAUSED_FROM_SNAPSHOT = 7, /* paused after restoring from snapshot */
    VIR_DOMAIN_PAUSED_SHUTTING_DOWN = 8, /* paused during shutdown process */
    VIR_DOMAIN_PAUSED_SNAPSHOT = 9,      /* paused while creating a snapshot */
    VIR_DOMAIN_PAUSED_CRASHED = 10,     /* paused due to a guest crash */
    VIR_DOMAIN_PAUSED_STARTING_UP = 11, /* the domain is being started */
    VIR_DOMAIN_PAUSED_POSTCOPY = 12,    /* paused for post-copy migration */
    VIR_DOMAIN_PAUSED_POSTCOPY_FAILED = 13, /* paused after failed post-copy */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_PAUSED_LAST
# endif
} virDomainPausedReason;

typedef enum {
    VIR_DOMAIN_SHUTDOWN_UNKNOWN = 0,    /* the reason is unknown */
    VIR_DOMAIN_SHUTDOWN_USER = 1,       /* shutting down on user request */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_SHUTDOWN_LAST
# endif
} virDomainShutdownReason;

typedef enum {
    VIR_DOMAIN_SHUTOFF_UNKNOWN = 0,     /* the reason is unknown */
    VIR_DOMAIN_SHUTOFF_SHUTDOWN = 1,    /* normal shutdown */
    VIR_DOMAIN_SHUTOFF_DESTROYED = 2,   /* forced poweroff */
    VIR_DOMAIN_SHUTOFF_CRASHED = 3,     /* domain crashed */
    VIR_DOMAIN_SHUTOFF_MIGRATED = 4,    /* migrated to another host */
    VIR_DOMAIN_SHUTOFF_SAVED = 5,       /* saved to a file */
    VIR_DOMAIN_SHUTOFF_FAILED = 6,      /* domain failed to start */
    VIR_DOMAIN_SHUTOFF_FROM_SNAPSHOT = 7, /* restored from a snapshot which was
                                           * taken while domain was shutoff */
    VIR_DOMAIN_SHUTOFF_DAEMON = 8,      /* daemon decides to kill domain
                                           during reconnection processing */
# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_SHUTOFF_LAST
# endif
} virDomainShutoffReason;

typedef enum {
    VIR_DOMAIN_CRASHED_UNKNOWN = 0,     /* crashed for unknown reason */
    VIR_DOMAIN_CRASHED_PANICKED = 1,    /* domain panicked */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_CRASHED_LAST
# endif
} virDomainCrashedReason;

typedef enum {
    VIR_DOMAIN_PMSUSPENDED_UNKNOWN = 0,

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_PMSUSPENDED_LAST
# endif
} virDomainPMSuspendedReason;

typedef enum {
    VIR_DOMAIN_PMSUSPENDED_DISK_UNKNOWN = 0,

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_PMSUSPENDED_DISK_LAST
# endif
} virDomainPMSuspendedDiskReason;

/**
 * virDomainControlState:
 *
 * Current state of a control interface to the domain.
 */
typedef enum {
    VIR_DOMAIN_CONTROL_OK = 0,       /* operational, ready to accept commands */
    VIR_DOMAIN_CONTROL_JOB = 1,      /* background job is running (can be
                                        monitored by virDomainGetJobInfo); only
                                        limited set of commands may be allowed */
    VIR_DOMAIN_CONTROL_OCCUPIED = 2, /* occupied by a running command */
    VIR_DOMAIN_CONTROL_ERROR = 3,    /* unusable, domain cannot be fully
                                        operated, possible reason is provided
                                        in the details field */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_CONTROL_LAST
# endif
} virDomainControlState;

/**
 * virDomainControlErrorReason:
 *
 * Reason for the error state.
 */
typedef enum {
    VIR_DOMAIN_CONTROL_ERROR_REASON_NONE = 0,     /* server didn't provide a
                                                     reason */
    VIR_DOMAIN_CONTROL_ERROR_REASON_UNKNOWN = 1,  /* unknown reason for the
                                                     error */
    VIR_DOMAIN_CONTROL_ERROR_REASON_MONITOR = 2,  /* monitor connection is
                                                     broken */
    VIR_DOMAIN_CONTROL_ERROR_REASON_INTERNAL = 3, /* error caused due to
                                                     internal failure in libvirt
                                                  */
# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_CONTROL_ERROR_REASON_LAST
# endif
} virDomainControlErrorReason;

/**
 * virDomainControlInfo:
 *
 * Structure filled in by virDomainGetControlInfo and providing details about
 * current state of control interface to a domain.
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
 */
typedef enum {
    VIR_DOMAIN_AFFECT_CURRENT = 0,      /* Affect current domain state.  */
    VIR_DOMAIN_AFFECT_LIVE    = 1 << 0, /* Affect running domain state.  */
    VIR_DOMAIN_AFFECT_CONFIG  = 1 << 1, /* Affect persistent domain state.  */
    /* 1 << 2 is reserved for virTypedParameterFlags */
} virDomainModificationImpact;

/**
 * virDomainInfoPtr:
 *
 * a virDomainInfo is a structure filled by virDomainGetInfo() and extracting
 * runtime information for a given active Domain
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
 */

typedef virDomainInfo *virDomainInfoPtr;

/**
 * virDomainCreateFlags:
 *
 * Flags OR'ed together to provide specific behaviour when creating a
 * Domain.
 */
typedef enum {
    VIR_DOMAIN_NONE               = 0,      /* Default behavior */
    VIR_DOMAIN_START_PAUSED       = 1 << 0, /* Launch guest in paused state */
    VIR_DOMAIN_START_AUTODESTROY  = 1 << 1, /* Automatically kill guest when virConnectPtr is closed */
    VIR_DOMAIN_START_BYPASS_CACHE = 1 << 2, /* Avoid file system cache pollution */
    VIR_DOMAIN_START_FORCE_BOOT   = 1 << 3, /* Boot, discarding any managed save */
    VIR_DOMAIN_START_VALIDATE     = 1 << 4, /* Validate the XML document against schema */
    VIR_DOMAIN_START_RESET_NVRAM  = 1 << 5, /* Re-initialize NVRAM from template */
} virDomainCreateFlags;


/* Management of scheduler parameters */

/**
 * VIR_DOMAIN_SCHEDULER_CPU_SHARES:
 *
 * Macro represents proportional weight of the scheduler used on the
 * host cpu, when using the posix scheduler, as a ullong.
 */
# define VIR_DOMAIN_SCHEDULER_CPU_SHARES "cpu_shares"

/**
 * VIR_DOMAIN_SCHEDULER_GLOBAL_PERIOD:
 *
 * Macro represents the enforcement period for a quota, in microseconds,
 * for whole domain, when using the posix scheduler, as a ullong.
 */
# define VIR_DOMAIN_SCHEDULER_GLOBAL_PERIOD "global_period"

/**
 * VIR_DOMAIN_SCHEDULER_GLOBAL_QUOTA:
 *
 * Macro represents the maximum bandwidth to be used within a period for
 * whole domain, when using the posix scheduler, as an llong.
 */
# define VIR_DOMAIN_SCHEDULER_GLOBAL_QUOTA "global_quota"

/**
 * VIR_DOMAIN_SCHEDULER_VCPU_PERIOD:
 *
 * Macro represents the enforcement period for a quota, in microseconds,
 * for vcpus only, when using the posix scheduler, as a ullong.
 */
# define VIR_DOMAIN_SCHEDULER_VCPU_PERIOD "vcpu_period"

/**
 * VIR_DOMAIN_SCHEDULER_VCPU_QUOTA:
 *
 * Macro represents the maximum bandwidth to be used within a period for
 * vcpus only, when using the posix scheduler, as an llong.
 */
# define VIR_DOMAIN_SCHEDULER_VCPU_QUOTA "vcpu_quota"

/**
 * VIR_DOMAIN_SCHEDULER_EMULATOR_PERIOD:
 *
 * Macro represents the enforcement period for a quota in microseconds,
 * when using the posix scheduler, for all emulator activity not tied to
 * vcpus, as a ullong.
 */
# define VIR_DOMAIN_SCHEDULER_EMULATOR_PERIOD "emulator_period"

/**
 * VIR_DOMAIN_SCHEDULER_EMULATOR_QUOTA:
 *
 * Macro represents the maximum bandwidth to be used within a period for
 * all emulator activity not tied to vcpus, when using the posix scheduler,
 * as an llong.
 */
# define VIR_DOMAIN_SCHEDULER_EMULATOR_QUOTA "emulator_quota"

/**
 * VIR_DOMAIN_SCHEDULER_IOTHREAD_PERIOD:
 *
 * Macro represents the enforcement period for a quota, in microseconds,
 * for IOThreads only, when using the posix scheduler, as a ullong.
 */
# define VIR_DOMAIN_SCHEDULER_IOTHREAD_PERIOD "iothread_period"

/**
 * VIR_DOMAIN_SCHEDULER_IOTHREAD_QUOTA:
 *
 * Macro represents the maximum bandwidth to be used within a period for
 * IOThreads only, when using the posix scheduler, as an llong.
 */
# define VIR_DOMAIN_SCHEDULER_IOTHREAD_QUOTA "iothread_quota"

/**
 * VIR_DOMAIN_SCHEDULER_WEIGHT:
 *
 * Macro represents the relative weight,  when using the credit
 * scheduler, as a uint.
 */
# define VIR_DOMAIN_SCHEDULER_WEIGHT "weight"

/**
 * VIR_DOMAIN_SCHEDULER_CAP:
 *
 * Macro represents the maximum scheduler cap, when using the credit
 * scheduler, as a uint.
 */
# define VIR_DOMAIN_SCHEDULER_CAP "cap"

/**
 * VIR_DOMAIN_SCHEDULER_RESERVATION:
 *
 * Macro represents the scheduler reservation value, when using the
 * allocation scheduler, as an llong.
 */
# define VIR_DOMAIN_SCHEDULER_RESERVATION "reservation"

/**
 * VIR_DOMAIN_SCHEDULER_LIMIT:
 *
 * Macro represents the scheduler limit value, when using the
 * allocation scheduler, as an llong.
 */
# define VIR_DOMAIN_SCHEDULER_LIMIT "limit"

/**
 * VIR_DOMAIN_SCHEDULER_SHARES:
 *
 * Macro represents the scheduler shares value, when using the
 * allocation scheduler, as an int.
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
 * virDomainBlockStats:
 *
 * Block device stats for virDomainBlockStats.
 *
 * Hypervisors may return a field set to ((long long)-1) which indicates
 * that the hypervisor does not support that statistic.
 *
 * NB. Here 'long long' means 64 bit integer.
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
 */
typedef virDomainBlockStatsStruct *virDomainBlockStatsPtr;


/**
 * VIR_DOMAIN_BLOCK_STATS_FIELD_LENGTH:
 *
 * Macro providing the field length of parameter names when using
 * virDomainBlockStatsFlags().
 */
# define VIR_DOMAIN_BLOCK_STATS_FIELD_LENGTH VIR_TYPED_PARAM_FIELD_LENGTH

/**
 * VIR_DOMAIN_BLOCK_STATS_READ_BYTES:
 *
 * Macro represents the total number of read bytes of the
 * block device, as an llong.
 */
# define VIR_DOMAIN_BLOCK_STATS_READ_BYTES "rd_bytes"

/**
 * VIR_DOMAIN_BLOCK_STATS_READ_REQ:
 *
 * Macro represents the total read requests of the
 * block device, as an llong.
 */
# define VIR_DOMAIN_BLOCK_STATS_READ_REQ "rd_operations"

/**
 * VIR_DOMAIN_BLOCK_STATS_READ_TOTAL_TIMES:
 *
 * Macro represents the total time spend on cache reads in
 * nano-seconds of the block device, as an llong.
 */
# define VIR_DOMAIN_BLOCK_STATS_READ_TOTAL_TIMES "rd_total_times"

/**
 * VIR_DOMAIN_BLOCK_STATS_WRITE_BYTES:
 *
 * Macro represents the total number of write bytes of the
 * block device, as an llong.
 */
# define VIR_DOMAIN_BLOCK_STATS_WRITE_BYTES "wr_bytes"

/**
 * VIR_DOMAIN_BLOCK_STATS_WRITE_REQ:
 *
 * Macro represents the total write requests of the
 * block device, as an llong.
 */
# define VIR_DOMAIN_BLOCK_STATS_WRITE_REQ "wr_operations"

/**
 * VIR_DOMAIN_BLOCK_STATS_WRITE_TOTAL_TIMES:
 *
 * Macro represents the total time spend on cache writes in
 * nano-seconds of the block device, as an llong.
 */
# define VIR_DOMAIN_BLOCK_STATS_WRITE_TOTAL_TIMES "wr_total_times"

/**
 * VIR_DOMAIN_BLOCK_STATS_FLUSH_REQ:
 *
 * Macro represents the total flush requests of the
 * block device, as an llong.
 */
# define VIR_DOMAIN_BLOCK_STATS_FLUSH_REQ "flush_operations"

/**
 * VIR_DOMAIN_BLOCK_STATS_FLUSH_TOTAL_TIMES:
 *
 * Macro represents the total time spend on cache flushing in
 * nano-seconds of the block device, as an llong.
 */
# define VIR_DOMAIN_BLOCK_STATS_FLUSH_TOTAL_TIMES "flush_total_times"

/**
 * VIR_DOMAIN_BLOCK_STATS_ERRS:
 *
 * In Xen this returns the mysterious 'oo_req', as an llong.
 */
# define VIR_DOMAIN_BLOCK_STATS_ERRS "errs"

/**
 * virDomainInterfaceStats:
 *
 * Network interface stats for virDomainInterfaceStats.
 *
 * Hypervisors may return a field set to ((long long)-1) which indicates
 * that the hypervisor does not support that statistic.
 *
 * NB. Here 'long long' means 64 bit integer.
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
 */
typedef virDomainInterfaceStatsStruct *virDomainInterfaceStatsPtr;

/**
 * Memory Statistics Tags:
 */
typedef enum {
    /* The total amount of data read from swap space (in kB). */
    VIR_DOMAIN_MEMORY_STAT_SWAP_IN         = 0,
    /* The total amount of memory written out to swap space (in kB). */
    VIR_DOMAIN_MEMORY_STAT_SWAP_OUT        = 1,

    /*
     * Page faults occur when a process makes a valid access to virtual memory
     * that is not available.  When servicing the page fault, if disk IO is
     * required, it is considered a major fault.  If not, it is a minor fault.
     * These are expressed as the number of faults that have occurred.
     */
    VIR_DOMAIN_MEMORY_STAT_MAJOR_FAULT     = 2,
    VIR_DOMAIN_MEMORY_STAT_MINOR_FAULT     = 3,

    /*
     * The amount of memory left completely unused by the system.  Memory that
     * is available but used for reclaimable caches should NOT be reported as
     * free.  This value is expressed in kB.
     */
    VIR_DOMAIN_MEMORY_STAT_UNUSED          = 4,

    /*
     * The total amount of usable memory as seen by the domain.  This value
     * may be less than the amount of memory assigned to the domain if a
     * balloon driver is in use or if the guest OS does not initialize all
     * assigned pages.  This value is expressed in kB.
     */
    VIR_DOMAIN_MEMORY_STAT_AVAILABLE       = 5,

    /* Current balloon value (in KB). */
    VIR_DOMAIN_MEMORY_STAT_ACTUAL_BALLOON  = 6,

    /* Resident Set Size of the process running the domain. This value
     * is in kB */
    VIR_DOMAIN_MEMORY_STAT_RSS             = 7,

    /*
     * How much the balloon can be inflated without pushing the guest system
     * to swap, corresponds to 'Available' in /proc/meminfo
     */
    VIR_DOMAIN_MEMORY_STAT_USABLE          = 8,

    /* Timestamp of the last update of statistics, in seconds. */
    VIR_DOMAIN_MEMORY_STAT_LAST_UPDATE     = 9,

    /*
     * The amount of memory, that can be quickly reclaimed without
     * additional I/O (in kB). Typically these pages are used for caching files
     * from disk.
     */
    VIR_DOMAIN_MEMORY_STAT_DISK_CACHES     = 10,

    /*
     * The number of successful huge page allocations from inside the domain via
     * virtio balloon.
     */
    VIR_DOMAIN_MEMORY_STAT_HUGETLB_PGALLOC    = 11,

    /*
     * The number of failed huge page allocations from inside the domain via
     * virtio balloon.
     */
    VIR_DOMAIN_MEMORY_STAT_HUGETLB_PGFAIL    = 12,

    /*
     * The number of statistics supported by this version of the interface.
     * To add new statistics, add them to the enum and increase this value.
     */
    VIR_DOMAIN_MEMORY_STAT_NR              = 13,

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_MEMORY_STAT_LAST = VIR_DOMAIN_MEMORY_STAT_NR
# endif
} virDomainMemoryStatTags;

typedef struct _virDomainMemoryStat virDomainMemoryStatStruct;

struct _virDomainMemoryStat {
    int tag;
    unsigned long long val;
};

typedef virDomainMemoryStatStruct *virDomainMemoryStatPtr;


/* Domain core dump flags. */
typedef enum {
    VIR_DUMP_CRASH        = (1 << 0), /* crash after dump */
    VIR_DUMP_LIVE         = (1 << 1), /* live dump */
    VIR_DUMP_BYPASS_CACHE = (1 << 2), /* avoid file system cache pollution */
    VIR_DUMP_RESET        = (1 << 3), /* reset domain after dump finishes */
    VIR_DUMP_MEMORY_ONLY  = (1 << 4), /* use dump-guest-memory */
} virDomainCoreDumpFlags;

/**
 * virDomainCoreDumpFormat:
 *
 * Values for specifying different formats of domain core dumps.
 */
typedef enum {
    VIR_DOMAIN_CORE_DUMP_FORMAT_RAW,          /* dump guest memory in raw format */
    VIR_DOMAIN_CORE_DUMP_FORMAT_KDUMP_ZLIB,   /* kdump-compressed format, with
                                               * zlib compression */
    VIR_DOMAIN_CORE_DUMP_FORMAT_KDUMP_LZO,    /* kdump-compressed format, with
                                               * lzo compression */
    VIR_DOMAIN_CORE_DUMP_FORMAT_KDUMP_SNAPPY, /* kdump-compressed format, with
                                               * snappy compression */
    VIR_DOMAIN_CORE_DUMP_FORMAT_WIN_DMP,      /* Windows full crashdump format */
# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_CORE_DUMP_FORMAT_LAST
    /*
     * NB: this enum value will increase over time as new formats are
     * added to the libvirt API. It reflects the last format supported
     * by this version of the libvirt API.
     */
# endif
} virDomainCoreDumpFormat;

/* Domain migration flags. */
typedef enum {
    /* Do not pause the domain during migration. The domain's memory will
     * be transferred to the destination host while the domain is running.
     * The migration may never converge if the domain is changing its memory
     * faster then it can be transferred. The domain can be manually paused
     * anytime during migration using virDomainSuspend.
     */
    VIR_MIGRATE_LIVE = (1 << 0),

    /* Tell the source libvirtd to connect directly to the destination host.
     * Without this flag the client (e.g., virsh) connects to both hosts and
     * controls the migration process. In peer-to-peer mode, the source
     * libvirtd controls the migration by calling the destination daemon
     * directly.
     */
    VIR_MIGRATE_PEER2PEER = (1 << 1),

    /* Tunnel migration data over libvirtd connection. Without this flag the
     * source hypervisor sends migration data directly to the destination
     * hypervisor. This flag can only be used when VIR_MIGRATE_PEER2PEER is
     * set as well.
     *
     * Note the less-common spelling that we're stuck with:
     * VIR_MIGRATE_TUNNELLED should be VIR_MIGRATE_TUNNELED.
     */
    VIR_MIGRATE_TUNNELLED = (1 << 2),

    /* Define the domain as persistent on the destination host after successful
     * migration. If the domain was persistent on the source host and
     * VIR_MIGRATE_UNDEFINE_SOURCE is not used, it will end up persistent on
     * both hosts.
     */
    VIR_MIGRATE_PERSIST_DEST = (1 << 3),

    /* Undefine the domain on the source host once migration successfully
     * finishes.
     */
    VIR_MIGRATE_UNDEFINE_SOURCE = (1 << 4),

    /* Leave the domain suspended on the destination host. virDomainResume (on
     * the virDomainPtr returned by the migration API) has to be called
     * explicitly to resume domain's virtual CPUs.
     */
    VIR_MIGRATE_PAUSED = (1 << 5),

    /* Migrate full disk images in addition to domain's memory. By default
     * only non-shared non-readonly disk images are transferred. The
     * VIR_MIGRATE_PARAM_MIGRATE_DISKS parameter can be used to specify which
     * disks should be migrated.
     *
     * This flag and VIR_MIGRATE_NON_SHARED_INC are mutually exclusive.
     */
    VIR_MIGRATE_NON_SHARED_DISK = (1 << 6),

    /* Migrate disk images in addition to domain's memory. This is similar to
     * VIR_MIGRATE_NON_SHARED_DISK, but only the top level of each disk's
     * backing chain is copied. That is, the rest of the backing chain is
     * expected to be present on the destination and to be exactly the same as
     * on the source host.
     *
     * This flag and VIR_MIGRATE_NON_SHARED_DISK are mutually exclusive.
     */
    VIR_MIGRATE_NON_SHARED_INC = (1 << 7),

    /* Protect against domain configuration changes during the migration
     * process. This flag is used automatically when both sides support it.
     * Explicitly setting this flag will cause migration to fail if either the
     * source or the destination does not support it.
     */
    VIR_MIGRATE_CHANGE_PROTECTION = (1 << 8),

    /* Force migration even if it is considered unsafe. In some cases libvirt
     * may refuse to migrate the domain because doing so may lead to potential
     * problems such as data corruption, and thus the migration is considered
     * unsafe. For a QEMU domain this may happen if the domain uses disks
     * without explicitly setting cache mode to "none". Migrating such domains
     * is unsafe unless the disk images are stored on coherent clustered
     * filesystem, such as GFS2 or GPFS.
     */
    VIR_MIGRATE_UNSAFE = (1 << 9),

    /* Migrate a domain definition without starting the domain on the
     * destination and without stopping it on the source host. Offline
     * migration requires VIR_MIGRATE_PERSIST_DEST to be set.
     *
     * Offline migration may not copy disk storage or any other file based
     * storage (such as UEFI variables).
     */
    VIR_MIGRATE_OFFLINE = (1 << 10),

    /* Compress migration data. The compression methods can be specified using
     * VIR_MIGRATE_PARAM_COMPRESSION. A hypervisor default method will be used
     * if this parameter is omitted. Individual compression methods can be
     * tuned via their specific VIR_MIGRATE_PARAM_COMPRESSION_* parameters.
     */
    VIR_MIGRATE_COMPRESSED = (1 << 11),

    /* Cancel migration if a soft error (such as I/O error) happens during
     * migration.
     */
    VIR_MIGRATE_ABORT_ON_ERROR = (1 << 12),

    /* Enable algorithms that ensure a live migration will eventually converge.
     * This usually means the domain will be slowed down to make sure it does
     * not change its memory faster than a hypervisor can transfer the changed
     * memory to the destination host. VIR_MIGRATE_PARAM_AUTO_CONVERGE_*
     * parameters can be used to tune the algorithm.
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
     */
    VIR_MIGRATE_RDMA_PIN_ALL = (1 << 14),

    /* Setting the VIR_MIGRATE_POSTCOPY flag tells libvirt to enable post-copy
     * migration. However, the migration will start normally and
     * virDomainMigrateStartPostCopy needs to be called to switch it into the
     * post-copy mode. See virDomainMigrateStartPostCopy for more details.
     */
    VIR_MIGRATE_POSTCOPY = (1 << 15),

    /* Setting the VIR_MIGRATE_TLS flag will cause the migration to attempt
     * to use the TLS environment configured by the hypervisor in order to
     * perform the migration. If incorrectly configured on either source or
     * destination, the migration will fail.
     */
    VIR_MIGRATE_TLS = (1 << 16),

    /* Send memory pages to the destination host through several network
     * connections. See VIR_MIGRATE_PARAM_PARALLEL_* parameters for
     * configuring the parallel migration.
     */
    VIR_MIGRATE_PARALLEL = (1 << 17),

     /* Force the guest writes which happen when copying disk images for
      * non-shared storage migration to be synchronously written to the
      * destination. This ensures the storage migration converges for VMs
      * doing heavy I/O on fast local storage and slow mirror.
      *
      * Requires one of VIR_MIGRATE_NON_SHARED_DISK, VIR_MIGRATE_NON_SHARED_INC
      * to be present as well.
      */
    VIR_MIGRATE_NON_SHARED_SYNCHRONOUS_WRITES = (1 << 18),

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
 */
# define VIR_MIGRATE_PARAM_URI               "migrate_uri"

/**
 * VIR_MIGRATE_PARAM_DEST_NAME:
 *
 * virDomainMigrate* params field: the name to be used for the domain on the
 * destination host as VIR_TYPED_PARAM_STRING. Omitting this parameter keeps
 * the domain name the same. This field is only allowed to be used with
 * hypervisors that support domain renaming during migration.
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
 */
# define VIR_MIGRATE_PARAM_PERSIST_XML  "persistent_xml"

/**
 * VIR_MIGRATE_PARAM_BANDWIDTH:
 *
 * virDomainMigrate* params field: the maximum bandwidth (in MiB/s) that will
 * be used for migration as VIR_TYPED_PARAM_ULLONG. If set to 0 or omitted,
 * libvirt will choose a suitable default. Some hypervisors do not support this
 * feature and will return an error if this field is used and is not 0.
 */
# define VIR_MIGRATE_PARAM_BANDWIDTH         "bandwidth"

/**
 * VIR_MIGRATE_PARAM_BANDWIDTH_POSTCOPY:
 *
 * virDomainMigrate* params field: the maximum bandwidth (in MiB/s) that will
 * be used for post-copy phase of a migration as VIR_TYPED_PARAM_ULLONG. If set
 * to 0 or omitted, post-copy migration speed will not be limited.
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
 */
# define VIR_MIGRATE_PARAM_LISTEN_ADDRESS    "listen_address"

/**
 * VIR_MIGRATE_PARAM_MIGRATE_DISKS:
 *
 * virDomainMigrate* params multiple field: The multiple values that list
 * the block devices to be migrated. At the moment this is only supported
 * by the QEMU driver but not for the tunnelled migration.
 */
# define VIR_MIGRATE_PARAM_MIGRATE_DISKS    "migrate_disks"

/**
 * VIR_MIGRATE_PARAM_DISKS_PORT:
 *
 * virDomainMigrate* params field: port that destination server should use
 * for incoming disks migration. Type is VIR_TYPED_PARAM_INT. If set to 0 or
 * omitted, libvirt will choose a suitable default. At the moment this is only
 * supported by the QEMU driver.
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
 */
# define VIR_MIGRATE_PARAM_DISKS_URI    "disks_uri"

/**
 * VIR_MIGRATE_PARAM_COMPRESSION:
 *
 * virDomainMigrate* params multiple field: name of the method used to
 * compress migration traffic. Supported compression methods: xbzrle, mt.
 * The parameter may be specified multiple times if more than one method
 * should be used.
 */
# define VIR_MIGRATE_PARAM_COMPRESSION    "compression"

/**
 * VIR_MIGRATE_PARAM_COMPRESSION_MT_LEVEL:
 *
 * virDomainMigrate* params field: the level of compression for multithread
 * compression as VIR_TYPED_PARAM_INT. Accepted values are in range 0-9.
 * 0 is no compression, 1 is maximum speed and 9 is maximum compression.
 */
# define VIR_MIGRATE_PARAM_COMPRESSION_MT_LEVEL    "compression.mt.level"

/**
 * VIR_MIGRATE_PARAM_COMPRESSION_MT_THREADS:
 *
 * virDomainMigrate* params field: the number of compression threads for
 * multithread compression as VIR_TYPED_PARAM_INT.
 */
# define VIR_MIGRATE_PARAM_COMPRESSION_MT_THREADS "compression.mt.threads"

/**
 * VIR_MIGRATE_PARAM_COMPRESSION_MT_DTHREADS:
 *
 * virDomainMigrate* params field: the number of decompression threads for
 * multithread compression as VIR_TYPED_PARAM_INT.
 */
# define VIR_MIGRATE_PARAM_COMPRESSION_MT_DTHREADS "compression.mt.dthreads"

/**
 * VIR_MIGRATE_PARAM_COMPRESSION_XBZRLE_CACHE:
 *
 * virDomainMigrate* params field: the size of page cache for xbzrle
 * compression as VIR_TYPED_PARAM_ULLONG.
 */
# define VIR_MIGRATE_PARAM_COMPRESSION_XBZRLE_CACHE "compression.xbzrle.cache"

/**
 * VIR_MIGRATE_PARAM_AUTO_CONVERGE_INITIAL:
 *
 * virDomainMigrate* params field: the initial percentage guest CPUs are
 * throttled to when auto-convergence decides migration is not converging.
 * As VIR_TYPED_PARAM_INT.
 */
# define VIR_MIGRATE_PARAM_AUTO_CONVERGE_INITIAL    "auto_converge.initial"

/**
 * VIR_MIGRATE_PARAM_AUTO_CONVERGE_INCREMENT:
 *
 * virDomainMigrate* params field: the increment added to
 * VIR_MIGRATE_PARAM_AUTO_CONVERGE_INITIAL whenever the hypervisor decides
 * the current rate is not enough to ensure convergence of the migration.
 * As VIR_TYPED_PARAM_INT.
 */
# define VIR_MIGRATE_PARAM_AUTO_CONVERGE_INCREMENT  "auto_converge.increment"

/**
 * VIR_MIGRATE_PARAM_PARALLEL_CONNECTIONS:
 *
 * virDomainMigrate* params field: number of connections used during parallel
 * migration. As VIR_TYPED_PARAM_INT.
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

/* Domain migration speed flags. */
typedef enum {
    /* Set or get maximum speed of post-copy migration. */
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

typedef enum {
    VIR_DOMAIN_SHUTDOWN_DEFAULT        = 0,        /* hypervisor choice */
    VIR_DOMAIN_SHUTDOWN_ACPI_POWER_BTN = (1 << 0), /* Send ACPI event */
    VIR_DOMAIN_SHUTDOWN_GUEST_AGENT    = (1 << 1), /* Use guest agent */
    VIR_DOMAIN_SHUTDOWN_INITCTL        = (1 << 2), /* Use initctl */
    VIR_DOMAIN_SHUTDOWN_SIGNAL         = (1 << 3), /* Send a signal */
    VIR_DOMAIN_SHUTDOWN_PARAVIRT       = (1 << 4), /* Use paravirt guest control */
} virDomainShutdownFlagValues;

int                     virDomainShutdown       (virDomainPtr domain);
int                     virDomainShutdownFlags  (virDomainPtr domain,
                                                 unsigned int flags);

typedef enum {
    VIR_DOMAIN_REBOOT_DEFAULT        = 0,        /* hypervisor choice */
    VIR_DOMAIN_REBOOT_ACPI_POWER_BTN = (1 << 0), /* Send ACPI event */
    VIR_DOMAIN_REBOOT_GUEST_AGENT    = (1 << 1), /* Use guest agent */
    VIR_DOMAIN_REBOOT_INITCTL        = (1 << 2), /* Use initctl */
    VIR_DOMAIN_REBOOT_SIGNAL         = (1 << 3), /* Send a signal */
    VIR_DOMAIN_REBOOT_PARAVIRT       = (1 << 4), /* Use paravirt guest control */
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
 */
typedef enum {
    VIR_DOMAIN_DESTROY_DEFAULT   = 0,      /* Default behavior - could lead to data loss!! */
    VIR_DOMAIN_DESTROY_GRACEFUL  = 1 << 0, /* only SIGTERM, no SIGKILL */
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
 * Flags for use in virDomainSaveFlags(), virDomainManagedSave(),
 * virDomainRestoreFlags(), and virDomainSaveImageDefineXML().  Not all
 * flags apply to all these functions.
 */
typedef enum {
    VIR_DOMAIN_SAVE_BYPASS_CACHE = 1 << 0, /* Avoid file system cache pollution */
    VIR_DOMAIN_SAVE_RUNNING      = 1 << 1, /* Favor running over paused */
    VIR_DOMAIN_SAVE_PAUSED       = 1 << 2, /* Favor paused over running */
    VIR_DOMAIN_SAVE_RESET_NVRAM  = 1 << 3, /* Re-initialize NVRAM from template */
} virDomainSaveRestoreFlags;

int                     virDomainSave           (virDomainPtr domain,
                                                 const char *to);
int                     virDomainSaveFlags      (virDomainPtr domain,
                                                 const char *to,
                                                 const char *dxml,
                                                 unsigned int flags);
int                     virDomainRestore        (virConnectPtr conn,
                                                 const char *from);
int                     virDomainRestoreFlags   (virConnectPtr conn,
                                                 const char *from,
                                                 const char *dxml,
                                                 unsigned int flags);

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
 */
# define VIR_DOMAIN_CPU_STATS_CPUTIME "cpu_time"

/**
 * VIR_DOMAIN_CPU_STATS_USERTIME:
 * cpu time charged to user instructions in nanoseconds, as a ullong
 */
# define VIR_DOMAIN_CPU_STATS_USERTIME "user_time"

/**
 * VIR_DOMAIN_CPU_STATS_SYSTEMTIME:
 * cpu time charged to system instructions in nanoseconds, as a ullong
 */
# define VIR_DOMAIN_CPU_STATS_SYSTEMTIME "system_time"

/**
 * VIR_DOMAIN_CPU_STATS_VCPUTIME:
 * vcpu usage in nanoseconds (cpu_time excluding hypervisor time),
 * as a ullong
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
 */

# define VIR_DOMAIN_BLKIO_WEIGHT "weight"

/**
 * VIR_DOMAIN_BLKIO_DEVICE_WEIGHT:
 *
 * Macro for the blkio tunable weight_device: it represents the
 * per-device weight, as a string.  The string is parsed as a
 * series of /path/to/device,weight elements, separated by ','.
 */

# define VIR_DOMAIN_BLKIO_DEVICE_WEIGHT "device_weight"

/**
 * VIR_DOMAIN_BLKIO_DEVICE_READ_IOPS:
 *
 * Macro for the blkio tunable throttle.read_iops_device: it represents
 * the number of reading the block device per second, as a string. The
 * string is parsed as a series of /path/to/device, read_iops elements,
 * separated by ','.
 */

# define VIR_DOMAIN_BLKIO_DEVICE_READ_IOPS "device_read_iops_sec"


/**
 * VIR_DOMAIN_BLKIO_DEVICE_WRITE_IOPS:
 *
 * Macro for the blkio tunable throttle.write_iops_device: it represents
 * the number of writing the block device per second, as a string. The
 * string is parsed as a series of /path/to/device, write_iops elements,
 * separated by ','.
 */
# define VIR_DOMAIN_BLKIO_DEVICE_WRITE_IOPS "device_write_iops_sec"


/**
 * VIR_DOMAIN_BLKIO_DEVICE_READ_BPS:
 *
 * Macro for the blkio tunable throttle.read_iops_device: it represents
 * the bytes of reading the block device per second, as a string. The
 * string is parsed as a series of /path/to/device, read_bps elements,
 * separated by ','.
 */
# define VIR_DOMAIN_BLKIO_DEVICE_READ_BPS "device_read_bytes_sec"


/**
 * VIR_DOMAIN_BLKIO_DEVICE_WRITE_BPS:
 *
 * Macro for the blkio tunable throttle.read_iops_device: it represents
 * the number of reading the block device per second, as a string. The
 * string is parsed as a series of /path/to/device, write_bps elements,
 * separated by ','.
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
 */

# define VIR_DOMAIN_MEMORY_PARAM_UNLIMITED 9007199254740991LL /* = INT64_MAX >> 10 */

/**
 * VIR_DOMAIN_MEMORY_HARD_LIMIT:
 *
 * Macro for the memory tunable hard_limit: it represents the maximum memory
 * the guest can use, as a ullong.
 */

# define VIR_DOMAIN_MEMORY_HARD_LIMIT "hard_limit"

/**
 * VIR_DOMAIN_MEMORY_SOFT_LIMIT:
 *
 * Macro for the memory tunable soft_limit: it represents the memory upper
 * limit enforced during memory contention, as a ullong.
 */

# define VIR_DOMAIN_MEMORY_SOFT_LIMIT "soft_limit"

/**
 * VIR_DOMAIN_MEMORY_MIN_GUARANTEE:
 *
 * Macro for the memory tunable min_guarantee: it represents the minimum
 * memory guaranteed to be reserved for the guest, as a ullong.
 */

# define VIR_DOMAIN_MEMORY_MIN_GUARANTEE "min_guarantee"

/**
 * VIR_DOMAIN_MEMORY_SWAP_HARD_LIMIT:
 *
 * Macro for the swap tunable swap_hard_limit: it represents the maximum swap
 * plus memory the guest can use, as a ullong. This limit has to be more than
 * VIR_DOMAIN_MEMORY_HARD_LIMIT.
 */

# define VIR_DOMAIN_MEMORY_SWAP_HARD_LIMIT "swap_hard_limit"

/* Set memory tunables for the domain */
int     virDomainSetMemoryParameters(virDomainPtr domain,
                                     virTypedParameterPtr params,
                                     int nparams, unsigned int flags);
int     virDomainGetMemoryParameters(virDomainPtr domain,
                                     virTypedParameterPtr params,
                                     int *nparams, unsigned int flags);

/* Memory size modification flags. */
typedef enum {
    /* See virDomainModificationImpact for these flags.  */
    VIR_DOMAIN_MEM_CURRENT = VIR_DOMAIN_AFFECT_CURRENT,
    VIR_DOMAIN_MEM_LIVE    = VIR_DOMAIN_AFFECT_LIVE,
    VIR_DOMAIN_MEM_CONFIG  = VIR_DOMAIN_AFFECT_CONFIG,

    /* Additionally, these flags may be bitwise-OR'd in.  */
    VIR_DOMAIN_MEM_MAXIMUM = (1 << 2), /* affect Max rather than current */
} virDomainMemoryModFlags;


/* Manage numa parameters */

/**
 * virDomainNumatuneMemMode:
 * Representation of the various modes in the <numatune> element of
 * a domain.
 */
typedef enum {
    VIR_DOMAIN_NUMATUNE_MEM_STRICT      = 0,
    VIR_DOMAIN_NUMATUNE_MEM_PREFERRED   = 1,
    VIR_DOMAIN_NUMATUNE_MEM_INTERLEAVE  = 2,
    VIR_DOMAIN_NUMATUNE_MEM_RESTRICTIVE = 3,

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_NUMATUNE_MEM_LAST /* This constant is subject to change */
# endif
} virDomainNumatuneMemMode;

/**
 * VIR_DOMAIN_NUMA_NODESET:
 *
 * Macro for typed parameter name that lists the numa nodeset of a
 * domain, as a string.
 */
# define VIR_DOMAIN_NUMA_NODESET "numa_nodeset"

/**
 * VIR_DOMAIN_NUMA_MODE:
 *
 * Macro for typed parameter name that lists the numa mode of a domain,
 * as an int containing a virDomainNumatuneMemMode value.
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

typedef enum {
    VIR_DOMAIN_GET_HOSTNAME_LEASE = (1 << 0), /* Parse DHCP lease file */
    VIR_DOMAIN_GET_HOSTNAME_AGENT = (1 << 1), /* Query qemu guest agent */
} virDomainGetHostnameFlags;

char *                  virDomainGetHostname    (virDomainPtr domain,
                                                 unsigned int flags);
int                     virDomainGetSecurityLabelList (virDomainPtr domain,
                                                       virSecurityLabelPtr* seclabels);

typedef enum {
    VIR_DOMAIN_METADATA_DESCRIPTION = 0, /* Operate on <description> */
    VIR_DOMAIN_METADATA_TITLE       = 1, /* Operate on <title> */
    VIR_DOMAIN_METADATA_ELEMENT     = 2, /* Operate on <metadata> */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_METADATA_LAST
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
 */

typedef enum {
    VIR_DOMAIN_XML_SECURE       = (1 << 0), /* dump security sensitive information too */
    VIR_DOMAIN_XML_INACTIVE     = (1 << 1), /* dump inactive domain information */
    VIR_DOMAIN_XML_UPDATE_CPU   = (1 << 2), /* update guest CPU requirements according to host CPU */
    VIR_DOMAIN_XML_MIGRATABLE   = (1 << 3), /* dump XML suitable for migration */
} virDomainXMLFlags;

typedef enum {
    VIR_DOMAIN_SAVE_IMAGE_XML_SECURE         = VIR_DOMAIN_XML_SECURE, /* dump security sensitive information too */
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
 */
# define VIR_DOMAIN_BANDWIDTH_IN_AVERAGE "inbound.average"

/**
 * VIR_DOMAIN_BANDWIDTH_IN_PEAK:
 *
 * Macro represents the inbound peak of NIC bandwidth, as a uint.
 */
# define VIR_DOMAIN_BANDWIDTH_IN_PEAK "inbound.peak"

/**
 * VIR_DOMAIN_BANDWIDTH_IN_BURST:
 *
 * Macro represents the inbound burst of NIC bandwidth, as a uint.
 */
# define VIR_DOMAIN_BANDWIDTH_IN_BURST "inbound.burst"

/**
 * VIR_DOMAIN_BANDWIDTH_IN_FLOOR:
 *
 * Macro represents the inbound floor of NIC bandwidth, as a uint.
 */
# define VIR_DOMAIN_BANDWIDTH_IN_FLOOR "inbound.floor"

/**
 * VIR_DOMAIN_BANDWIDTH_OUT_AVERAGE:
 *
 * Macro represents the outbound average of NIC bandwidth, as a uint.
 */
# define VIR_DOMAIN_BANDWIDTH_OUT_AVERAGE "outbound.average"

/**
 * VIR_DOMAIN_BANDWIDTH_OUT_PEAK:
 *
 * Macro represents the outbound peak of NIC bandwidth, as a uint.
 */
# define VIR_DOMAIN_BANDWIDTH_OUT_PEAK "outbound.peak"

/**
 * VIR_DOMAIN_BANDWIDTH_OUT_BURST:
 *
 * Macro represents the outbound burst of NIC bandwidth, as a uint.
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
 */
typedef enum {
    VIR_DOMAIN_BLOCK_RESIZE_BYTES = 1 << 0, /* size in bytes instead of KiB */
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
 */
typedef struct _virDomainBlockInfo virDomainBlockInfo;
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

/* Memory peeking flags. */

typedef enum {
    VIR_MEMORY_VIRTUAL            = 1 << 0, /* addresses are virtual addresses */
    VIR_MEMORY_PHYSICAL           = 1 << 1, /* addresses are physical addresses */
} virDomainMemoryFlags;

int                     virDomainMemoryPeek (virDomainPtr dom,
                                             unsigned long long start,
                                             size_t size,
                                             void *buffer,
                                             unsigned int flags);

typedef enum {
    VIR_DOMAIN_DEFINE_VALIDATE = (1 << 0), /* Validate the XML document against schema */
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

typedef enum {
    VIR_DOMAIN_UNDEFINE_MANAGED_SAVE       = (1 << 0), /* Also remove any
                                                          managed save */
    VIR_DOMAIN_UNDEFINE_SNAPSHOTS_METADATA = (1 << 1), /* If last use of domain,
                                                          then also remove any
                                                          snapshot metadata */
    VIR_DOMAIN_UNDEFINE_NVRAM              = (1 << 2), /* Also remove any
                                                          nvram file */
    VIR_DOMAIN_UNDEFINE_KEEP_NVRAM         = (1 << 3), /* Keep nvram file */
    VIR_DOMAIN_UNDEFINE_CHECKPOINTS_METADATA = (1 << 4), /* If last use of domain,
                                                            then also remove any
                                                            checkpoint metadata */

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
 */
typedef enum {
    VIR_CONNECT_LIST_DOMAINS_ACTIVE         = 1 << 0,
    VIR_CONNECT_LIST_DOMAINS_INACTIVE       = 1 << 1,

    VIR_CONNECT_LIST_DOMAINS_PERSISTENT     = 1 << 2,
    VIR_CONNECT_LIST_DOMAINS_TRANSIENT      = 1 << 3,

    VIR_CONNECT_LIST_DOMAINS_RUNNING        = 1 << 4,
    VIR_CONNECT_LIST_DOMAINS_PAUSED         = 1 << 5,
    VIR_CONNECT_LIST_DOMAINS_SHUTOFF        = 1 << 6,
    VIR_CONNECT_LIST_DOMAINS_OTHER          = 1 << 7,

    VIR_CONNECT_LIST_DOMAINS_MANAGEDSAVE    = 1 << 8,
    VIR_CONNECT_LIST_DOMAINS_NO_MANAGEDSAVE = 1 << 9,

    VIR_CONNECT_LIST_DOMAINS_AUTOSTART      = 1 << 10,
    VIR_CONNECT_LIST_DOMAINS_NO_AUTOSTART   = 1 << 11,

    VIR_CONNECT_LIST_DOMAINS_HAS_SNAPSHOT   = 1 << 12,
    VIR_CONNECT_LIST_DOMAINS_NO_SNAPSHOT    = 1 << 13,

    VIR_CONNECT_LIST_DOMAINS_HAS_CHECKPOINT = 1 << 14,
    VIR_CONNECT_LIST_DOMAINS_NO_CHECKPOINT  = 1 << 15,
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
 * virVcpuInfo: structure for information about a virtual CPU in a domain.
 */

typedef enum {
    VIR_VCPU_OFFLINE    = 0,    /* the virtual CPU is offline */
    VIR_VCPU_RUNNING    = 1,    /* the virtual CPU is running */
    VIR_VCPU_BLOCKED    = 2,    /* the virtual CPU is blocked on resource */

# ifdef VIR_ENUM_SENTINELS
    VIR_VCPU_LAST
# endif
} virVcpuState;

typedef enum {
    VIR_VCPU_INFO_CPU_OFFLINE     = -1, /* the vCPU is offline */
    VIR_VCPU_INFO_CPU_UNAVAILABLE = -2, /* the hypervisor does not expose real CPU information */
} virVcpuHostCpuState;

typedef struct _virVcpuInfo virVcpuInfo;
struct _virVcpuInfo {
    unsigned int number;        /* virtual CPU number */
    int state;                  /* value from virVcpuState */
    unsigned long long cpuTime; /* CPU time used, in nanoseconds */
    int cpu;                    /* real CPU number, or one of the values from virVcpuHostCpuState */
};
typedef virVcpuInfo *virVcpuInfoPtr;

/* Flags for controlling virtual CPU hot-plugging.  */
typedef enum {
    /* See virDomainModificationImpact for these flags.  */
    VIR_DOMAIN_VCPU_CURRENT = VIR_DOMAIN_AFFECT_CURRENT,
    VIR_DOMAIN_VCPU_LIVE    = VIR_DOMAIN_AFFECT_LIVE,
    VIR_DOMAIN_VCPU_CONFIG  = VIR_DOMAIN_AFFECT_CONFIG,

    /* Additionally, these flags may be bitwise-OR'd in.  */
    VIR_DOMAIN_VCPU_MAXIMUM = (1 << 2), /* Max rather than current count */
    VIR_DOMAIN_VCPU_GUEST   = (1 << 3), /* Modify state of the cpu in the guest */
    VIR_DOMAIN_VCPU_HOTPLUGGABLE = (1 << 4), /* Make vcpus added hot(un)pluggable */
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
 * virIOThreadInfo:
 *
 * The data structure for information about all IOThreads in a domain
 */
typedef struct _virDomainIOThreadInfo virDomainIOThreadInfo;
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
 * The polling interval is not available for statistical purposes.
 */
# define VIR_DOMAIN_IOTHREAD_POLL_MAX_NS "poll_max_ns"

/**
 * VIR_DOMAIN_IOTHREAD_POLL_GROW:
 *
 * This provides a value for the dynamic polling adjustment algorithm to
 * use to grow its polling interval up to the poll_max_ns value. A value
 * of 0 (zero) allows the hypervisor to choose its own value. The algorithm
 * to use for adjustment is hypervisor specific.
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
 */
# define VIR_DOMAIN_IOTHREAD_POLL_SHRINK "poll_shrink"

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
 */

# define VIR_USE_CPU(cpumap, cpu) ((cpumap)[(cpu) / 8] |= (1 << ((cpu) % 8)))

/**
 * VIR_UNUSE_CPU:
 * @cpumap: pointer to a bit map of real CPUs (in 8-bit bytes) (IN/OUT)
 * @cpu: the physical CPU number
 *
 * This macro is to be used in conjunction with virDomainPinVcpu() API.
 * It resets the bit (CPU not usable) of the related cpu in cpumap.
 */

# define VIR_UNUSE_CPU(cpumap, cpu) ((cpumap)[(cpu) / 8] &= ~(1 << ((cpu) % 8)))

/**
 * VIR_CPU_USED:
 * @cpumap: pointer to a bit map of real CPUs (in 8-bit bytes) (IN)
 * @cpu: the physical CPU number
 *
 * This macro can be used in conjunction with virNodeGetCPUMap() API.
 * It returns non-zero if the bit of the related CPU is set.
 */

# define VIR_CPU_USED(cpumap, cpu) ((cpumap)[(cpu) / 8] & (1 << ((cpu) % 8)))

/**
 * VIR_CPU_MAPLEN:
 * @cpu: number of physical CPUs
 *
 * This macro is to be used in conjunction with virDomainPinVcpu() API.
 * It returns the length (in bytes) required to store the complete
 * CPU map between a single virtual & all physical CPUs of a domain.
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
 */
# define VIR_GET_CPUMAP(cpumaps, maplen, vcpu) (&((cpumaps)[(vcpu) * (maplen)]))


typedef enum {
    /* See virDomainModificationImpact for these flags.  */
    VIR_DOMAIN_DEVICE_MODIFY_CURRENT = VIR_DOMAIN_AFFECT_CURRENT,
    VIR_DOMAIN_DEVICE_MODIFY_LIVE    = VIR_DOMAIN_AFFECT_LIVE,
    VIR_DOMAIN_DEVICE_MODIFY_CONFIG  = VIR_DOMAIN_AFFECT_CONFIG,

    /* Additionally, these flags may be bitwise-OR'd in.  */
    VIR_DOMAIN_DEVICE_MODIFY_FORCE = (1 << 2), /* Forcibly modify device
                                                  (ex. force eject a cdrom) */
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

typedef struct _virDomainStatsRecord virDomainStatsRecord;
typedef virDomainStatsRecord *virDomainStatsRecordPtr;
struct _virDomainStatsRecord {
    virDomainPtr dom;
    virTypedParameterPtr params;
    int nparams;
};

typedef enum {
    VIR_DOMAIN_STATS_STATE = (1 << 0), /* return domain state */
    VIR_DOMAIN_STATS_CPU_TOTAL = (1 << 1), /* return domain CPU info */
    VIR_DOMAIN_STATS_BALLOON = (1 << 2), /* return domain balloon info */
    VIR_DOMAIN_STATS_VCPU = (1 << 3), /* return domain virtual CPU info */
    VIR_DOMAIN_STATS_INTERFACE = (1 << 4), /* return domain interfaces info */
    VIR_DOMAIN_STATS_BLOCK = (1 << 5), /* return domain block info */
    VIR_DOMAIN_STATS_PERF = (1 << 6), /* return domain perf event info */
    VIR_DOMAIN_STATS_IOTHREAD = (1 << 7), /* return iothread poll info */
    VIR_DOMAIN_STATS_MEMORY = (1 << 8), /* return domain memory info */
    VIR_DOMAIN_STATS_DIRTYRATE = (1 << 9), /* return domain dirty rate info */
} virDomainStatsTypes;

typedef enum {
    VIR_CONNECT_GET_ALL_DOMAINS_STATS_ACTIVE = VIR_CONNECT_LIST_DOMAINS_ACTIVE,
    VIR_CONNECT_GET_ALL_DOMAINS_STATS_INACTIVE = VIR_CONNECT_LIST_DOMAINS_INACTIVE,

    VIR_CONNECT_GET_ALL_DOMAINS_STATS_PERSISTENT = VIR_CONNECT_LIST_DOMAINS_PERSISTENT,
    VIR_CONNECT_GET_ALL_DOMAINS_STATS_TRANSIENT = VIR_CONNECT_LIST_DOMAINS_TRANSIENT,

    VIR_CONNECT_GET_ALL_DOMAINS_STATS_RUNNING = VIR_CONNECT_LIST_DOMAINS_RUNNING,
    VIR_CONNECT_GET_ALL_DOMAINS_STATS_PAUSED = VIR_CONNECT_LIST_DOMAINS_PAUSED,
    VIR_CONNECT_GET_ALL_DOMAINS_STATS_SHUTOFF = VIR_CONNECT_LIST_DOMAINS_SHUTOFF,
    VIR_CONNECT_GET_ALL_DOMAINS_STATS_OTHER = VIR_CONNECT_LIST_DOMAINS_OTHER,

    VIR_CONNECT_GET_ALL_DOMAINS_STATS_NOWAIT = 1 << 29, /* report statistics that can be obtained
                                                           immediately without any blocking */
    VIR_CONNECT_GET_ALL_DOMAINS_STATS_BACKING = 1 << 30, /* include backing chain for block stats */
    VIR_CONNECT_GET_ALL_DOMAINS_STATS_ENFORCE_STATS = 1U << 31, /* enforce requested stats */
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
 */
# define VIR_PERF_PARAM_CMT "cmt"

/**
 * VIR_PERF_PARAM_MBMT:
 *
 * Macro for typed parameter name that represents MBMT perf event
 * which can be used to monitor total system bandwidth (bytes/s)
 * from one level of cache to another. It corresponds to the
 * "perf.mbmt" field in the *Stats APIs.

 */
# define VIR_PERF_PARAM_MBMT "mbmt"

/**
 * VIR_PERF_PARAM_MBML:
 *
 * Macro for typed parameter name that represents MBML perf event
 * which can be used to monitor the amount of data (bytes/s) sent
 * through the memory controller on the socket. It corresponds to
 * the "perf.mbml" field in the *Stats APIs.
 */
# define VIR_PERF_PARAM_MBML "mbml"

/**
 * VIR_PERF_PARAM_CACHE_MISSES:
 *
 * Macro for typed parameter name that represents cache_misses perf
 * event which can be used to measure the count of cache misses by
 * applications running on the platform. It corresponds to the
 * "perf.cache_misses" field in the *Stats APIs.
 */
# define VIR_PERF_PARAM_CACHE_MISSES "cache_misses"

/**
 * VIR_PERF_PARAM_CACHE_REFERENCES:
 *
 * Macro for typed parameter name that represents cache_references
 * perf event which can be used to measure the count of cache hits
 * by applications running on the platform. It corresponds to the
 * "perf.cache_references" field in the *Stats APIs.
 */
# define VIR_PERF_PARAM_CACHE_REFERENCES "cache_references"

/**
 * VIR_PERF_PARAM_INSTRUCTIONS:
 *
 * Macro for typed parameter name that represents instructions perf
 * event which can be used to measure the count of instructions
 * by applications running on the platform. It corresponds to the
 * "perf.instructions" field in the *Stats APIs.
 */
# define VIR_PERF_PARAM_INSTRUCTIONS "instructions"

/**
 * VIR_PERF_PARAM_CPU_CYCLES:
 *
 * Macro for typed parameter name that represents cpu_cycles perf event
 * describing the total/elapsed cpu cycles. This can be used to measure
 * how many cpu cycles one instruction needs.
 * It corresponds to the "perf.cpu_cycles" field in the *Stats APIs.
 */
# define VIR_PERF_PARAM_CPU_CYCLES "cpu_cycles"

/**
 * VIR_PERF_PARAM_BRANCH_INSTRUCTIONS:
 *
 * Macro for typed parameter name that represents branch_instructions
 * perf event which can be used to measure the count of branch instructions
 * by applications running on the platform. It corresponds to the
 * "perf.branch_instructions" field in the *Stats APIs.
 */
# define VIR_PERF_PARAM_BRANCH_INSTRUCTIONS "branch_instructions"

/**
 * VIR_PERF_PARAM_BRANCH_MISSES:
 *
 * Macro for typed parameter name that represents branch_misses
 * perf event which can be used to measure the count of branch misses
 * by applications running on the platform. It corresponds to the
 * "perf.branch_misses" field in the *Stats APIs.
 */
# define VIR_PERF_PARAM_BRANCH_MISSES "branch_misses"

/**
 * VIR_PERF_PARAM_BUS_CYCLES:
 *
 * Macro for typed parameter name that represents bus_cycles
 * perf event which can be used to measure the count of bus cycles
 * by applications running on the platform. It corresponds to the
 * "perf.bus_cycles" field in the *Stats APIs.
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
 */
# define VIR_PERF_PARAM_TASK_CLOCK "task_clock"

/**
* VIR_PERF_PARAM_PAGE_FAULTS:
*
* Macro for typed parameter name that represents page_faults
* perf event which can be used to measure the count of page
* faults by applications running on the platform. It corresponds
* to the "perf.page_faults" field in the *Stats APIs.
*/
# define VIR_PERF_PARAM_PAGE_FAULTS "page_faults"

/**
 * VIR_PERF_PARAM_CONTEXT_SWITCHES:
 *
 * Macro for typed parameter name that represents context_switches
 * perf event which can be used to measure the count of context
 * switches by applications running on the platform. It corresponds
 * to the "perf.context_switches" field in the *Stats APIs.
 */
# define VIR_PERF_PARAM_CONTEXT_SWITCHES "context_switches"

/**
 * VIR_PERF_PARAM_CPU_MIGRATIONS:
 *
 * Macro for typed parameter name that represents cpu_migrations
 * perf event which can be used to measure the count of cpu
 * migrations by applications running on the platform. It corresponds
 * to the "perf.cpu_migrations" field in the *Stats APIs.
 */
# define VIR_PERF_PARAM_CPU_MIGRATIONS "cpu_migrations"

/**
 * VIR_PERF_PARAM_PAGE_FAULTS_MIN:
 *
 * Macro for typed parameter name that represents page_faults_min
 * perf event which can be used to measure the count of minor page
 * faults by applications running on the platform. It corresponds
 * to the "perf.page_faults_min" field in the *Stats APIs.
 */
# define VIR_PERF_PARAM_PAGE_FAULTS_MIN  "page_faults_min"

/**
 * VIR_PERF_PARAM_PAGE_FAULTS_MAJ:
 *
 * Macro for typed parameter name that represents page_faults_maj
 * perf event which can be used to measure the count of major page
 * faults by applications running on the platform. It corresponds
 * to the "perf.page_faults_maj" field in the *Stats APIs.
 */
# define VIR_PERF_PARAM_PAGE_FAULTS_MAJ  "page_faults_maj"

/**
 * VIR_PERF_PARAM_ALIGNMENT_FAULTS:
 *
 * Macro for typed parameter name that represents alignment_faults
 * perf event which can be used to measure the count of alignment
 * faults by applications running on the platform. It corresponds
 * to the "perf.alignment_faults" field in the *Stats APIs.
 */
# define VIR_PERF_PARAM_ALIGNMENT_FAULTS  "alignment_faults"

/**
 * VIR_PERF_PARAM_EMULATION_FAULTS:
 *
 * Macro for typed parameter name that represents emulation_faults
 * perf event which can be used to measure the count of emulation
 * faults by applications running on the platform. It corresponds
 * to the "perf.emulation_faults" field in the *Stats APIs.
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
 */
typedef enum {
    /* Placeholder */
    VIR_DOMAIN_BLOCK_JOB_TYPE_UNKNOWN = 0,

    /* Block Pull (virDomainBlockPull, or virDomainBlockRebase without
     * flags), job ends on completion */
    VIR_DOMAIN_BLOCK_JOB_TYPE_PULL = 1,

    /* Block Copy (virDomainBlockCopy, or virDomainBlockRebase with
     * flags), job exists as long as mirroring is active */
    VIR_DOMAIN_BLOCK_JOB_TYPE_COPY = 2,

    /* Block Commit (virDomainBlockCommit without flags), job ends on
     * completion */
    VIR_DOMAIN_BLOCK_JOB_TYPE_COMMIT = 3,

    /* Active Block Commit (virDomainBlockCommit with flags), job
     * exists as long as sync is active */
    VIR_DOMAIN_BLOCK_JOB_TYPE_ACTIVE_COMMIT = 4,

    /* Backup (virDomainBackupBegin) */
    VIR_DOMAIN_BLOCK_JOB_TYPE_BACKUP = 5,

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_BLOCK_JOB_TYPE_LAST
# endif
} virDomainBlockJobType;

/**
 * virDomainBlockJobAbortFlags:
 *
 * VIR_DOMAIN_BLOCK_JOB_ABORT_ASYNC: Request only, do not wait for completion
 * VIR_DOMAIN_BLOCK_JOB_ABORT_PIVOT: Pivot to new file when ending a copy or
 *                                   active commit job
 */
typedef enum {
    VIR_DOMAIN_BLOCK_JOB_ABORT_ASYNC = 1 << 0,
    VIR_DOMAIN_BLOCK_JOB_ABORT_PIVOT = 1 << 1,
} virDomainBlockJobAbortFlags;

int virDomainBlockJobAbort(virDomainPtr dom, const char *disk,
                           unsigned int flags);

/* Flags for use with virDomainGetBlockJobInfo */
typedef enum {
    VIR_DOMAIN_BLOCK_JOB_INFO_BANDWIDTH_BYTES = 1 << 0, /* bandwidth in bytes/s
                                                           instead of MiB/s */
} virDomainBlockJobInfoFlags;

/* An iterator for monitoring block job operations */
typedef unsigned long long virDomainBlockJobCursor;

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
typedef virDomainBlockJobInfo *virDomainBlockJobInfoPtr;

int virDomainGetBlockJobInfo(virDomainPtr dom, const char *disk,
                             virDomainBlockJobInfoPtr info,
                             unsigned int flags);

/* Flags for use with virDomainBlockJobSetSpeed */
typedef enum {
    VIR_DOMAIN_BLOCK_JOB_SPEED_BANDWIDTH_BYTES = 1 << 0, /* bandwidth in bytes/s
                                                            instead of MiB/s */
} virDomainBlockJobSetSpeedFlags;

int virDomainBlockJobSetSpeed(virDomainPtr dom, const char *disk,
                              unsigned long bandwidth, unsigned int flags);

/* Flags for use with virDomainBlockPull (values chosen to be a subset
 * of the flags for virDomainBlockRebase) */
typedef enum {
    VIR_DOMAIN_BLOCK_PULL_BANDWIDTH_BYTES = 1 << 6, /* bandwidth in bytes/s
                                                       instead of MiB/s */
} virDomainBlockPullFlags;

int virDomainBlockPull(virDomainPtr dom, const char *disk,
                       unsigned long bandwidth, unsigned int flags);

/**
 * virDomainBlockRebaseFlags:
 *
 * Flags available for virDomainBlockRebase().
 */
typedef enum {
    VIR_DOMAIN_BLOCK_REBASE_SHALLOW   = 1 << 0, /* Limit copy to top of source
                                                   backing chain */
    VIR_DOMAIN_BLOCK_REBASE_REUSE_EXT = 1 << 1, /* Reuse existing external
                                                   file for a copy */
    VIR_DOMAIN_BLOCK_REBASE_COPY_RAW  = 1 << 2, /* Make destination file raw */
    VIR_DOMAIN_BLOCK_REBASE_COPY      = 1 << 3, /* Start a copy job */
    VIR_DOMAIN_BLOCK_REBASE_RELATIVE  = 1 << 4, /* Keep backing chain
                                                   referenced using relative
                                                   names */
    VIR_DOMAIN_BLOCK_REBASE_COPY_DEV  = 1 << 5, /* Treat destination as block
                                                   device instead of file */
    VIR_DOMAIN_BLOCK_REBASE_BANDWIDTH_BYTES = 1 << 6, /* bandwidth in bytes/s
                                                         instead of MiB/s */
} virDomainBlockRebaseFlags;

int virDomainBlockRebase(virDomainPtr dom, const char *disk,
                         const char *base, unsigned long bandwidth,
                         unsigned int flags);

/**
 * virDomainBlockCopyFlags:
 *
 * Flags available for virDomainBlockCopy().
 */
typedef enum {
    /* Limit copy to top of source backing chain */
    VIR_DOMAIN_BLOCK_COPY_SHALLOW   = 1 << 0,

    /* Reuse existing external file for a copy */
    VIR_DOMAIN_BLOCK_COPY_REUSE_EXT = 1 << 1,

    /* Don't force usage of recoverable job for the copy operation */
    VIR_DOMAIN_BLOCK_COPY_TRANSIENT_JOB = 1 << 2,

    /* Force the copy job to synchronously propagate guest writes into
     * the destination image, so that the copy is guaranteed to converge */
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
 */
# define VIR_DOMAIN_BLOCK_COPY_GRANULARITY "granularity"

/**
 * VIR_DOMAIN_BLOCK_COPY_BUF_SIZE:
 * Macro for the virDomainBlockCopy buffer size tunable: it represents
 * how much data in bytes can be in flight between source and destination,
 * as an unsigned long long. Specifying 0 is the same as omitting this
 * parameter, to request the hypervisor default.
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
 */
typedef enum {
    VIR_DOMAIN_BLOCK_COMMIT_SHALLOW = 1 << 0, /* NULL base means next backing
                                                 file, not whole chain */
    VIR_DOMAIN_BLOCK_COMMIT_DELETE  = 1 << 1, /* Delete any files that are now
                                                 invalid after their contents
                                                 have been committed */
    VIR_DOMAIN_BLOCK_COMMIT_ACTIVE  = 1 << 2, /* Allow a two-phase commit when
                                                 top is the active layer */
    VIR_DOMAIN_BLOCK_COMMIT_RELATIVE = 1 << 3, /* keep the backing chain
                                                  referenced using relative
                                                  names */
    VIR_DOMAIN_BLOCK_COMMIT_BANDWIDTH_BYTES = 1 << 4, /* bandwidth in bytes/s
                                                         instead of MiB/s */
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
 */
# define VIR_DOMAIN_BLOCK_IOTUNE_TOTAL_BYTES_SEC "total_bytes_sec"

/**
 * VIR_DOMAIN_BLOCK_IOTUNE_READ_BYTES_SEC:
 *
 * Macro for the BlockIoTune tunable weight: it represents the read
 * bytes per second permitted through a block device, as a ullong.
 */
# define VIR_DOMAIN_BLOCK_IOTUNE_READ_BYTES_SEC "read_bytes_sec"

/**
 * VIR_DOMAIN_BLOCK_IOTUNE_WRITE_BYTES_SEC:
 *
 * Macro for the BlockIoTune tunable weight: it represents the write
 * bytes per second permitted through a block device, as a ullong.
 */
# define VIR_DOMAIN_BLOCK_IOTUNE_WRITE_BYTES_SEC "write_bytes_sec"

/**
 * VIR_DOMAIN_BLOCK_IOTUNE_TOTAL_IOPS_SEC:
 *
 * Macro for the BlockIoTune tunable weight: it represents the total
 * I/O operations per second permitted through a block device, as a ullong.
 */
# define VIR_DOMAIN_BLOCK_IOTUNE_TOTAL_IOPS_SEC "total_iops_sec"

/**
 * VIR_DOMAIN_BLOCK_IOTUNE_READ_IOPS_SEC:
 *
 * Macro for the BlockIoTune tunable weight: it represents the read
 * I/O operations per second permitted through a block device, as a ullong.
 */
# define VIR_DOMAIN_BLOCK_IOTUNE_READ_IOPS_SEC "read_iops_sec"

/**
 * VIR_DOMAIN_BLOCK_IOTUNE_WRITE_IOPS_SEC:
 * Macro for the BlockIoTune tunable weight: it represents the write
 * I/O operations per second permitted through a block device, as a ullong.
 */
# define VIR_DOMAIN_BLOCK_IOTUNE_WRITE_IOPS_SEC "write_iops_sec"

/**
 * VIR_DOMAIN_BLOCK_IOTUNE_TOTAL_BYTES_SEC_MAX:
 *
 * Macro for the BlockIoTune tunable weight: it represents the maximum total
 * bytes per second permitted through a block device, as a ullong.
 */
# define VIR_DOMAIN_BLOCK_IOTUNE_TOTAL_BYTES_SEC_MAX "total_bytes_sec_max"

/**
 * VIR_DOMAIN_BLOCK_IOTUNE_READ_BYTES_SEC_MAX:
 *
 * Macro for the BlockIoTune tunable weight: it represents the maximum read
 * bytes per second permitted through a block device, as a ullong.
 */
# define VIR_DOMAIN_BLOCK_IOTUNE_READ_BYTES_SEC_MAX "read_bytes_sec_max"

/**
 * VIR_DOMAIN_BLOCK_IOTUNE_WRITE_BYTES_SEC_MAX:
 *
 * Macro for the BlockIoTune tunable weight: it represents the maximum write
 * bytes per second permitted through a block device, as a ullong.
 */
# define VIR_DOMAIN_BLOCK_IOTUNE_WRITE_BYTES_SEC_MAX "write_bytes_sec_max"

/**
 * VIR_DOMAIN_BLOCK_IOTUNE_TOTAL_IOPS_SEC_MAX:
 *
 * Macro for the BlockIoTune tunable weight: it represents the maximum
 * I/O operations per second permitted through a block device, as a ullong.
 */
# define VIR_DOMAIN_BLOCK_IOTUNE_TOTAL_IOPS_SEC_MAX "total_iops_sec_max"

/**
 * VIR_DOMAIN_BLOCK_IOTUNE_READ_IOPS_SEC_MAX:
 *
 * Macro for the BlockIoTune tunable weight: it represents the maximum read
 * I/O operations per second permitted through a block device, as a ullong.
 */
# define VIR_DOMAIN_BLOCK_IOTUNE_READ_IOPS_SEC_MAX "read_iops_sec_max"

/**
 * VIR_DOMAIN_BLOCK_IOTUNE_WRITE_IOPS_SEC_MAX:
 * Macro for the BlockIoTune tunable weight: it represents the maximum write
 * I/O operations per second permitted through a block device, as a ullong.
 */
# define VIR_DOMAIN_BLOCK_IOTUNE_WRITE_IOPS_SEC_MAX "write_iops_sec_max"

/**
 * VIR_DOMAIN_BLOCK_IOTUNE_TOTAL_BYTES_SEC_MAX_LENGTH:
 *
 * Macro for the BlockIoTune tunable weight: it represents the duration in
 * seconds for the burst allowed by total_bytes_sec_max, as a ullong.
 */
# define VIR_DOMAIN_BLOCK_IOTUNE_TOTAL_BYTES_SEC_MAX_LENGTH "total_bytes_sec_max_length"

/**
 * VIR_DOMAIN_BLOCK_IOTUNE_READ_BYTES_SEC_MAX_LENGTH:
 *
 * Macro for the BlockIoTune tunable weight: it represents the duration in
 * seconds for the burst allowed by read_bytes_sec_max, as a ullong.
 */
# define VIR_DOMAIN_BLOCK_IOTUNE_READ_BYTES_SEC_MAX_LENGTH "read_bytes_sec_max_length"

/**
 * VIR_DOMAIN_BLOCK_IOTUNE_WRITE_BYTES_SEC_MAX_LENGTH:
 *
 * Macro for the BlockIoTune tunable weight: it represents the duration in
 * seconds for the burst allowed by write_bytes_sec_max, as a ullong.
 */
# define VIR_DOMAIN_BLOCK_IOTUNE_WRITE_BYTES_SEC_MAX_LENGTH "write_bytes_sec_max_length"

/**
 * VIR_DOMAIN_BLOCK_IOTUNE_TOTAL_IOPS_SEC_MAX_LENGTH:
 *
 * Macro for the BlockIoTune tunable weight: it represents the duration in
 * seconds for the burst allowed by total_iops_sec_max, as a ullong.
 */
# define VIR_DOMAIN_BLOCK_IOTUNE_TOTAL_IOPS_SEC_MAX_LENGTH "total_iops_sec_max_length"

/**
 * VIR_DOMAIN_BLOCK_IOTUNE_READ_IOPS_SEC_MAX_LENGTH:
 *
 * Macro for the BlockIoTune tunable weight: it represents the duration in
 * seconds for the burst allowed by read_iops_sec_max, as a ullong.
 */
# define VIR_DOMAIN_BLOCK_IOTUNE_READ_IOPS_SEC_MAX_LENGTH "read_iops_sec_max_length"

/**
 * VIR_DOMAIN_BLOCK_IOTUNE_WRITE_IOPS_SEC_MAX_LENGTH:
 *
 * Macro for the BlockIoTune tunable weight: it represents the duration in
 * seconds for the burst allowed by write_iops_sec_max, as a ullong.
 */
# define VIR_DOMAIN_BLOCK_IOTUNE_WRITE_IOPS_SEC_MAX_LENGTH "write_iops_sec_max_length"

/**
 * VIR_DOMAIN_BLOCK_IOTUNE_SIZE_IOPS_SEC:
 * Macro for the BlockIoTune tunable weight: it represents the size
 * I/O operations per second permitted through a block device, as a ullong.
 */
# define VIR_DOMAIN_BLOCK_IOTUNE_SIZE_IOPS_SEC "size_iops_sec"

/**
 * VIR_DOMAIN_BLOCK_IOTUNE_GROUP_NAME:
 * Macro for the BlockIoTune tunable weight: it represents a group name to
 * allow sharing of I/O throttling quota between multiple drives, as a string.
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
 */
typedef enum {
    VIR_DOMAIN_DISK_ERROR_NONE      = 0, /* no error */
    VIR_DOMAIN_DISK_ERROR_UNSPEC    = 1, /* unspecified I/O error */
    VIR_DOMAIN_DISK_ERROR_NO_SPACE  = 2, /* no space left on the device */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_DISK_ERROR_LAST
# endif
} virDomainDiskErrorCode;

/**
 * virDomainDiskError:
 *
 */
typedef struct _virDomainDiskError virDomainDiskError;
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
 */
typedef enum {
    VIR_KEYCODE_SET_LINUX          = 0,
    VIR_KEYCODE_SET_XT             = 1,
    VIR_KEYCODE_SET_ATSET1         = 2,
    VIR_KEYCODE_SET_ATSET2         = 3,
    VIR_KEYCODE_SET_ATSET3         = 4,
    VIR_KEYCODE_SET_OSX            = 5,
    VIR_KEYCODE_SET_XT_KBD         = 6,
    VIR_KEYCODE_SET_USB            = 7,
    VIR_KEYCODE_SET_WIN32          = 8,
    VIR_KEYCODE_SET_QNUM           = 9,

# ifdef VIR_ENUM_SENTINELS
    VIR_KEYCODE_SET_LAST
    /*
     * NB: this enum value will increase over time as new keycode sets are
     * added to the libvirt API. It reflects the last keycode set supported
     * by this version of the libvirt API.
     */
# endif
} virKeycodeSet;

/**
 * VIR_KEYCODE_SET_RFB:
 *
 * Compatibility alias for VIR_KEYCODE_SET_QNUM, which replaced it since 4.2.0.
 */
# define VIR_KEYCODE_SET_RFB VIR_KEYCODE_SET_QNUM

/**
 * VIR_DOMAIN_SEND_KEY_MAX_KEYS:
 *
 * Maximum number of keycodes that can be sent in one virDomainSendKey() call.
 */
# define VIR_DOMAIN_SEND_KEY_MAX_KEYS  16

int virDomainSendKey(virDomainPtr domain,
                     unsigned int codeset,
                     unsigned int holdtime,
                     unsigned int *keycodes,
                     int nkeycodes,
                     unsigned int flags);

/*
 * These just happen to match Linux signal numbers. The numbers
 * will be mapped to whatever the SIGNUM is in the guest OS in
 * question by the agent delivering the signal. The names are
 * based on the POSIX / XSI signal standard though.
 *
 * Do not rely on all values matching Linux though. It is possible
 * this enum might be extended with new signals which have no
 * mapping in Linux.
 */
typedef enum {
    VIR_DOMAIN_PROCESS_SIGNAL_NOP        =  0, /* No constant in POSIX/Linux */
    VIR_DOMAIN_PROCESS_SIGNAL_HUP        =  1, /* SIGHUP */
    VIR_DOMAIN_PROCESS_SIGNAL_INT        =  2, /* SIGINT */
    VIR_DOMAIN_PROCESS_SIGNAL_QUIT       =  3, /* SIGQUIT */
    VIR_DOMAIN_PROCESS_SIGNAL_ILL        =  4, /* SIGILL */
    VIR_DOMAIN_PROCESS_SIGNAL_TRAP       =  5, /* SIGTRAP */
    VIR_DOMAIN_PROCESS_SIGNAL_ABRT       =  6, /* SIGABRT */
    VIR_DOMAIN_PROCESS_SIGNAL_BUS        =  7, /* SIGBUS */
    VIR_DOMAIN_PROCESS_SIGNAL_FPE        =  8, /* SIGFPE */
    VIR_DOMAIN_PROCESS_SIGNAL_KILL       =  9, /* SIGKILL */

    VIR_DOMAIN_PROCESS_SIGNAL_USR1       = 10, /* SIGUSR1 */
    VIR_DOMAIN_PROCESS_SIGNAL_SEGV       = 11, /* SIGSEGV */
    VIR_DOMAIN_PROCESS_SIGNAL_USR2       = 12, /* SIGUSR2 */
    VIR_DOMAIN_PROCESS_SIGNAL_PIPE       = 13, /* SIGPIPE */
    VIR_DOMAIN_PROCESS_SIGNAL_ALRM       = 14, /* SIGALRM */
    VIR_DOMAIN_PROCESS_SIGNAL_TERM       = 15, /* SIGTERM */
    VIR_DOMAIN_PROCESS_SIGNAL_STKFLT     = 16, /* Not in POSIX (SIGSTKFLT on Linux )*/
    VIR_DOMAIN_PROCESS_SIGNAL_CHLD       = 17, /* SIGCHLD */
    VIR_DOMAIN_PROCESS_SIGNAL_CONT       = 18, /* SIGCONT */
    VIR_DOMAIN_PROCESS_SIGNAL_STOP       = 19, /* SIGSTOP */

    VIR_DOMAIN_PROCESS_SIGNAL_TSTP       = 20, /* SIGTSTP */
    VIR_DOMAIN_PROCESS_SIGNAL_TTIN       = 21, /* SIGTTIN */
    VIR_DOMAIN_PROCESS_SIGNAL_TTOU       = 22, /* SIGTTOU */
    VIR_DOMAIN_PROCESS_SIGNAL_URG        = 23, /* SIGURG */
    VIR_DOMAIN_PROCESS_SIGNAL_XCPU       = 24, /* SIGXCPU */
    VIR_DOMAIN_PROCESS_SIGNAL_XFSZ       = 25, /* SIGXFSZ */
    VIR_DOMAIN_PROCESS_SIGNAL_VTALRM     = 26, /* SIGVTALRM */
    VIR_DOMAIN_PROCESS_SIGNAL_PROF       = 27, /* SIGPROF */
    VIR_DOMAIN_PROCESS_SIGNAL_WINCH      = 28, /* Not in POSIX (SIGWINCH on Linux) */
    VIR_DOMAIN_PROCESS_SIGNAL_POLL       = 29, /* SIGPOLL (also known as SIGIO on Linux) */

    VIR_DOMAIN_PROCESS_SIGNAL_PWR        = 30, /* Not in POSIX (SIGPWR on Linux) */
    VIR_DOMAIN_PROCESS_SIGNAL_SYS        = 31, /* SIGSYS (also known as SIGUNUSED on Linux) */
    VIR_DOMAIN_PROCESS_SIGNAL_RT0        = 32, /* SIGRTMIN */
    VIR_DOMAIN_PROCESS_SIGNAL_RT1        = 33, /* SIGRTMIN + 1 */
    VIR_DOMAIN_PROCESS_SIGNAL_RT2        = 34, /* SIGRTMIN + 2 */
    VIR_DOMAIN_PROCESS_SIGNAL_RT3        = 35, /* SIGRTMIN + 3 */
    VIR_DOMAIN_PROCESS_SIGNAL_RT4        = 36, /* SIGRTMIN + 4 */
    VIR_DOMAIN_PROCESS_SIGNAL_RT5        = 37, /* SIGRTMIN + 5 */
    VIR_DOMAIN_PROCESS_SIGNAL_RT6        = 38, /* SIGRTMIN + 6 */
    VIR_DOMAIN_PROCESS_SIGNAL_RT7        = 39, /* SIGRTMIN + 7 */

    VIR_DOMAIN_PROCESS_SIGNAL_RT8        = 40, /* SIGRTMIN + 8 */
    VIR_DOMAIN_PROCESS_SIGNAL_RT9        = 41, /* SIGRTMIN + 9 */
    VIR_DOMAIN_PROCESS_SIGNAL_RT10       = 42, /* SIGRTMIN + 10 */
    VIR_DOMAIN_PROCESS_SIGNAL_RT11       = 43, /* SIGRTMIN + 11 */
    VIR_DOMAIN_PROCESS_SIGNAL_RT12       = 44, /* SIGRTMIN + 12 */
    VIR_DOMAIN_PROCESS_SIGNAL_RT13       = 45, /* SIGRTMIN + 13 */
    VIR_DOMAIN_PROCESS_SIGNAL_RT14       = 46, /* SIGRTMIN + 14 */
    VIR_DOMAIN_PROCESS_SIGNAL_RT15       = 47, /* SIGRTMIN + 15 */
    VIR_DOMAIN_PROCESS_SIGNAL_RT16       = 48, /* SIGRTMIN + 16 */
    VIR_DOMAIN_PROCESS_SIGNAL_RT17       = 49, /* SIGRTMIN + 17 */

    VIR_DOMAIN_PROCESS_SIGNAL_RT18       = 50, /* SIGRTMIN + 18 */
    VIR_DOMAIN_PROCESS_SIGNAL_RT19       = 51, /* SIGRTMIN + 19 */
    VIR_DOMAIN_PROCESS_SIGNAL_RT20       = 52, /* SIGRTMIN + 20 */
    VIR_DOMAIN_PROCESS_SIGNAL_RT21       = 53, /* SIGRTMIN + 21 */
    VIR_DOMAIN_PROCESS_SIGNAL_RT22       = 54, /* SIGRTMIN + 22 */
    VIR_DOMAIN_PROCESS_SIGNAL_RT23       = 55, /* SIGRTMIN + 23 */
    VIR_DOMAIN_PROCESS_SIGNAL_RT24       = 56, /* SIGRTMIN + 24 */
    VIR_DOMAIN_PROCESS_SIGNAL_RT25       = 57, /* SIGRTMIN + 25 */
    VIR_DOMAIN_PROCESS_SIGNAL_RT26       = 58, /* SIGRTMIN + 26 */
    VIR_DOMAIN_PROCESS_SIGNAL_RT27       = 59, /* SIGRTMIN + 27 */

    VIR_DOMAIN_PROCESS_SIGNAL_RT28       = 60, /* SIGRTMIN + 28 */
    VIR_DOMAIN_PROCESS_SIGNAL_RT29       = 61, /* SIGRTMIN + 29 */
    VIR_DOMAIN_PROCESS_SIGNAL_RT30       = 62, /* SIGRTMIN + 30 */
    VIR_DOMAIN_PROCESS_SIGNAL_RT31       = 63, /* SIGRTMIN + 31 */
    VIR_DOMAIN_PROCESS_SIGNAL_RT32       = 64, /* SIGRTMIN + 32 / SIGRTMAX */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_PROCESS_SIGNAL_LAST
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
 */
typedef enum {
    VIR_DOMAIN_EVENT_DEFINED = 0,
    VIR_DOMAIN_EVENT_UNDEFINED = 1,
    VIR_DOMAIN_EVENT_STARTED = 2,
    VIR_DOMAIN_EVENT_SUSPENDED = 3,
    VIR_DOMAIN_EVENT_RESUMED = 4,
    VIR_DOMAIN_EVENT_STOPPED = 5,
    VIR_DOMAIN_EVENT_SHUTDOWN = 6,
    VIR_DOMAIN_EVENT_PMSUSPENDED = 7,
    VIR_DOMAIN_EVENT_CRASHED = 8,

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_EVENT_LAST
# endif
} virDomainEventType;

/**
 * virDomainEventDefinedDetailType:
 *
 * Details on the cause of a 'defined' lifecycle event
 */
typedef enum {
    VIR_DOMAIN_EVENT_DEFINED_ADDED = 0,     /* Newly created config file */
    VIR_DOMAIN_EVENT_DEFINED_UPDATED = 1,   /* Changed config file */
    VIR_DOMAIN_EVENT_DEFINED_RENAMED = 2,   /* Domain was renamed */
    VIR_DOMAIN_EVENT_DEFINED_FROM_SNAPSHOT = 3,   /* Config was restored from a snapshot */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_EVENT_DEFINED_LAST
# endif
} virDomainEventDefinedDetailType;

/**
 * virDomainEventUndefinedDetailType:
 *
 * Details on the cause of an 'undefined' lifecycle event
 */
typedef enum {
    VIR_DOMAIN_EVENT_UNDEFINED_REMOVED = 0, /* Deleted the config file */
    VIR_DOMAIN_EVENT_UNDEFINED_RENAMED = 1, /* Domain was renamed */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_EVENT_UNDEFINED_LAST
# endif
} virDomainEventUndefinedDetailType;

/**
 * virDomainEventStartedDetailType:
 *
 * Details on the cause of a 'started' lifecycle event
 */
typedef enum {
    VIR_DOMAIN_EVENT_STARTED_BOOTED = 0,   /* Normal startup from boot */
    VIR_DOMAIN_EVENT_STARTED_MIGRATED = 1, /* Incoming migration from another host */
    VIR_DOMAIN_EVENT_STARTED_RESTORED = 2, /* Restored from a state file */
    VIR_DOMAIN_EVENT_STARTED_FROM_SNAPSHOT = 3, /* Restored from snapshot */
    VIR_DOMAIN_EVENT_STARTED_WAKEUP = 4,   /* Started due to wakeup event */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_EVENT_STARTED_LAST
# endif
} virDomainEventStartedDetailType;

/**
 * virDomainEventSuspendedDetailType:
 *
 * Details on the cause of a 'suspended' lifecycle event
 */
typedef enum {
    VIR_DOMAIN_EVENT_SUSPENDED_PAUSED = 0,   /* Normal suspend due to admin pause */
    VIR_DOMAIN_EVENT_SUSPENDED_MIGRATED = 1, /* Suspended for offline migration */
    VIR_DOMAIN_EVENT_SUSPENDED_IOERROR = 2,  /* Suspended due to a disk I/O error */
    VIR_DOMAIN_EVENT_SUSPENDED_WATCHDOG = 3,  /* Suspended due to a watchdog firing */
    VIR_DOMAIN_EVENT_SUSPENDED_RESTORED = 4,  /* Restored from paused state file */
    VIR_DOMAIN_EVENT_SUSPENDED_FROM_SNAPSHOT = 5, /* Restored from paused snapshot */
    VIR_DOMAIN_EVENT_SUSPENDED_API_ERROR = 6, /* suspended after failure during libvirt API call */
    VIR_DOMAIN_EVENT_SUSPENDED_POSTCOPY = 7, /* suspended for post-copy migration */
    VIR_DOMAIN_EVENT_SUSPENDED_POSTCOPY_FAILED = 8, /* suspended after failed post-copy */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_EVENT_SUSPENDED_LAST
# endif
} virDomainEventSuspendedDetailType;

/**
 * virDomainEventResumedDetailType:
 *
 * Details on the cause of a 'resumed' lifecycle event
 */
typedef enum {
    VIR_DOMAIN_EVENT_RESUMED_UNPAUSED = 0,   /* Normal resume due to admin unpause */
    VIR_DOMAIN_EVENT_RESUMED_MIGRATED = 1,   /* Resumed for completion of migration */
    VIR_DOMAIN_EVENT_RESUMED_FROM_SNAPSHOT = 2, /* Resumed from snapshot */
    VIR_DOMAIN_EVENT_RESUMED_POSTCOPY = 3,   /* Resumed, but migration is still
                                                running in post-copy mode */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_EVENT_RESUMED_LAST
# endif
} virDomainEventResumedDetailType;

/**
 * virDomainEventStoppedDetailType:
 *
 * Details on the cause of a 'stopped' lifecycle event
 */
typedef enum {
    VIR_DOMAIN_EVENT_STOPPED_SHUTDOWN = 0,  /* Normal shutdown */
    VIR_DOMAIN_EVENT_STOPPED_DESTROYED = 1, /* Forced poweroff from host */
    VIR_DOMAIN_EVENT_STOPPED_CRASHED = 2,   /* Guest crashed */
    VIR_DOMAIN_EVENT_STOPPED_MIGRATED = 3,  /* Migrated off to another host */
    VIR_DOMAIN_EVENT_STOPPED_SAVED = 4,     /* Saved to a state file */
    VIR_DOMAIN_EVENT_STOPPED_FAILED = 5,    /* Host emulator/mgmt failed */
    VIR_DOMAIN_EVENT_STOPPED_FROM_SNAPSHOT = 6, /* offline snapshot loaded */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_EVENT_STOPPED_LAST
# endif
} virDomainEventStoppedDetailType;


/**
 * virDomainEventShutdownDetailType:
 *
 * Details on the cause of a 'shutdown' lifecycle event
 */
typedef enum {
    /* Guest finished shutdown sequence */
    VIR_DOMAIN_EVENT_SHUTDOWN_FINISHED = 0,

    /* Domain finished shutting down after request from the guest itself
     * (e.g. hardware-specific action) */
    VIR_DOMAIN_EVENT_SHUTDOWN_GUEST = 1,

    /* Domain finished shutting down after request from the host (e.g. killed by
     * a signal) */
    VIR_DOMAIN_EVENT_SHUTDOWN_HOST = 2,

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_EVENT_SHUTDOWN_LAST
# endif
} virDomainEventShutdownDetailType;

/**
 * virDomainEventPMSuspendedDetailType:
 *
 * Details on the cause of a 'pmsuspended' lifecycle event
 */
typedef enum {
    VIR_DOMAIN_EVENT_PMSUSPENDED_MEMORY = 0, /* Guest was PM suspended to memory */
    VIR_DOMAIN_EVENT_PMSUSPENDED_DISK = 1, /* Guest was PM suspended to disk */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_EVENT_PMSUSPENDED_LAST
# endif
} virDomainEventPMSuspendedDetailType;

/**
 * virDomainEventCrashedDetailType:
 *
 * Details on the cause of a 'crashed' lifecycle event
 */
typedef enum {
    VIR_DOMAIN_EVENT_CRASHED_PANICKED = 0, /* Guest was panicked */
    VIR_DOMAIN_EVENT_CRASHED_CRASHLOADED = 1, /* Guest was crashloaded */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_EVENT_CRASHED_LAST
# endif
} virDomainEventCrashedDetailType;

/**
 * virDomainMemoryFailureRecipientType:
 *
 * Recipient of a memory failure event.
 */
typedef enum {
    /* memory failure at hypersivor memory address space */
    VIR_DOMAIN_EVENT_MEMORY_FAILURE_RECIPIENT_HYPERVISOR = 0,

    /* memory failure at guest memory address space */
    VIR_DOMAIN_EVENT_MEMORY_FAILURE_RECIPIENT_GUEST = 1,

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_EVENT_MEMORY_FAILURE_RECIPIENT_LAST
# endif
} virDomainMemoryFailureRecipientType;


/**
 * virDomainMemoryFailureActionType:
 *
 * Action of a memory failure event.
 */
typedef enum {
    /* the memory failure could be ignored. This will only be the case for
     * action-optional failures. */
    VIR_DOMAIN_EVENT_MEMORY_FAILURE_ACTION_IGNORE = 0,

    /* memory failure occurred in guest memory, the guest enabled MCE handling
     * mechanism, and hypervisor could inject the MCE into the guest
     * successfully. */
    VIR_DOMAIN_EVENT_MEMORY_FAILURE_ACTION_INJECT = 1,

    /* the failure is unrecoverable.  This occurs for action-required failures
     * if the recipient is the hypervisor; hypervisor will exit. */
    VIR_DOMAIN_EVENT_MEMORY_FAILURE_ACTION_FATAL = 2,

    /* the failure is unrecoverable but confined to the guest. This occurs if
     * the recipient is a guest which is not ready to handle memory failures. */
    VIR_DOMAIN_EVENT_MEMORY_FAILURE_ACTION_RESET = 3,

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_EVENT_MEMORY_FAILURE_ACTION_LAST
# endif
} virDomainMemoryFailureActionType;


typedef enum {
    /* whether a memory failure event is action-required or action-optional
     * (e.g. a failure during memory scrub). */
    VIR_DOMAIN_MEMORY_FAILURE_ACTION_REQUIRED = (1 << 0),

    /* whether the failure occurred while the previous failure was still in
     * progress. */
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

typedef enum {
    VIR_DOMAIN_JOB_NONE      = 0, /* No job is active */
    VIR_DOMAIN_JOB_BOUNDED   = 1, /* Job with a finite completion time */
    VIR_DOMAIN_JOB_UNBOUNDED = 2, /* Job without a finite completion time */
    VIR_DOMAIN_JOB_COMPLETED = 3, /* Job has finished, but isn't cleaned up */
    VIR_DOMAIN_JOB_FAILED    = 4, /* Job hit error, but isn't cleaned up */
    VIR_DOMAIN_JOB_CANCELLED = 5, /* Job was aborted, but isn't cleaned up */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_JOB_LAST
# endif
} virDomainJobType;

typedef struct _virDomainJobInfo virDomainJobInfo;
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
 */
typedef enum {
    VIR_DOMAIN_JOB_STATS_COMPLETED = 1 << 0, /* return stats of a recently
                                              * completed job */
    VIR_DOMAIN_JOB_STATS_KEEP_COMPLETED = 1 << 1, /* don't remove completed
                                                     stats when reading them */
} virDomainGetJobStatsFlags;

int virDomainGetJobInfo(virDomainPtr dom,
                        virDomainJobInfoPtr info);
int virDomainGetJobStats(virDomainPtr domain,
                         int *type,
                         virTypedParameterPtr *params,
                         int *nparams,
                         unsigned int flags);
int virDomainAbortJob(virDomainPtr dom);

typedef enum {
    VIR_DOMAIN_JOB_OPERATION_UNKNOWN = 0,
    VIR_DOMAIN_JOB_OPERATION_START = 1,
    VIR_DOMAIN_JOB_OPERATION_SAVE = 2,
    VIR_DOMAIN_JOB_OPERATION_RESTORE = 3,
    VIR_DOMAIN_JOB_OPERATION_MIGRATION_IN = 4,
    VIR_DOMAIN_JOB_OPERATION_MIGRATION_OUT = 5,
    VIR_DOMAIN_JOB_OPERATION_SNAPSHOT = 6,
    VIR_DOMAIN_JOB_OPERATION_SNAPSHOT_REVERT = 7,
    VIR_DOMAIN_JOB_OPERATION_DUMP = 8,
    VIR_DOMAIN_JOB_OPERATION_BACKUP = 9,

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_JOB_OPERATION_LAST
# endif
} virDomainJobOperation;

/**
 * VIR_DOMAIN_JOB_OPERATION:
 *
 * virDomainGetJobStats field: the operation which started the job as
 * VIR_TYPED_PARAM_INT. The values correspond to the items in
 * virDomainJobOperation enum.
 */
# define VIR_DOMAIN_JOB_OPERATION                "operation"

/**
 * VIR_DOMAIN_JOB_TIME_ELAPSED:
 *
 * virDomainGetJobStats field: time (ms) since the beginning of the
 * job, as VIR_TYPED_PARAM_ULLONG.
 *
 * This field corresponds to timeElapsed field in virDomainJobInfo.
 */
# define VIR_DOMAIN_JOB_TIME_ELAPSED             "time_elapsed"

/**
 * VIR_DOMAIN_JOB_TIME_ELAPSED_NET:
 *
 * virDomainGetJobStats field: time (ms) since the beginning of the
 * migration job NOT including the time required to transfer control
 * flow from the source host to the destination host,
 * as VIR_TYPED_PARAM_ULLONG.
 */
# define VIR_DOMAIN_JOB_TIME_ELAPSED_NET         "time_elapsed_net"

/**
 * VIR_DOMAIN_JOB_TIME_REMAINING:
 *
 * virDomainGetJobStats field: remaining time (ms) for VIR_DOMAIN_JOB_BOUNDED
 * jobs, as VIR_TYPED_PARAM_ULLONG.
 *
 * This field corresponds to timeRemaining field in virDomainJobInfo.
 */
# define VIR_DOMAIN_JOB_TIME_REMAINING           "time_remaining"

/**
 * VIR_DOMAIN_JOB_DOWNTIME:
 *
 * virDomainGetJobStats field: downtime (ms) that is expected to happen
 * during migration, as VIR_TYPED_PARAM_ULLONG. The real computed downtime
 * between the time guest CPUs were paused and the time they were resumed
 * is reported for completed migration.
 */
# define VIR_DOMAIN_JOB_DOWNTIME                 "downtime"

/**
 * VIR_DOMAIN_JOB_DOWNTIME_NET:
 *
 * virDomainGetJobStats field: real measured downtime (ms) NOT including
 * the time required to transfer control flow from the source host to the
 * destination host, as VIR_TYPED_PARAM_ULLONG.
 */
# define VIR_DOMAIN_JOB_DOWNTIME_NET             "downtime_net"

/**
 * VIR_DOMAIN_JOB_SETUP_TIME:
 *
 * virDomainGetJobStats field: total time in milliseconds spent preparing
 * the migration in the 'setup' phase before the iterations begin, as
 * VIR_TYPED_PARAM_ULLONG.
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
 */
# define VIR_DOMAIN_JOB_DATA_TOTAL               "data_total"

/**
 * VIR_DOMAIN_JOB_DATA_PROCESSED:
 *
 * virDomainGetJobStats field: number of bytes transferred from the
 * beginning of the job, as VIR_TYPED_PARAM_ULLONG.
 *
 * This field corresponds to dataProcessed field in virDomainJobInfo.
 */
# define VIR_DOMAIN_JOB_DATA_PROCESSED           "data_processed"

/**
 * VIR_DOMAIN_JOB_DATA_REMAINING:
 *
 * virDomainGetJobStats field: number of bytes that still need to be
 * transferred, as VIR_TYPED_PARAM_ULLONG.
 *
 * This field corresponds to dataRemaining field in virDomainJobInfo.
 */
# define VIR_DOMAIN_JOB_DATA_REMAINING           "data_remaining"

/**
 * VIR_DOMAIN_JOB_MEMORY_TOTAL:
 *
 * virDomainGetJobStats field: as VIR_DOMAIN_JOB_DATA_TOTAL but only
 * tracking guest memory progress, as VIR_TYPED_PARAM_ULLONG.
 *
 * This field corresponds to memTotal field in virDomainJobInfo.
 */
# define VIR_DOMAIN_JOB_MEMORY_TOTAL             "memory_total"

/**
 * VIR_DOMAIN_JOB_MEMORY_PROCESSED:
 *
 * virDomainGetJobStats field: as VIR_DOMAIN_JOB_DATA_PROCESSED but only
 * tracking guest memory progress, as VIR_TYPED_PARAM_ULLONG.
 *
 * This field corresponds to memProcessed field in virDomainJobInfo.
 */
# define VIR_DOMAIN_JOB_MEMORY_PROCESSED         "memory_processed"

/**
 * VIR_DOMAIN_JOB_MEMORY_REMAINING:
 *
 * virDomainGetJobStats field: as VIR_DOMAIN_JOB_DATA_REMAINING but only
 * tracking guest memory progress, as VIR_TYPED_PARAM_ULLONG.
 *
 * This field corresponds to memRemaining field in virDomainJobInfo.
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
 */
# define VIR_DOMAIN_JOB_MEMORY_CONSTANT          "memory_constant"

/**
 * VIR_DOMAIN_JOB_MEMORY_NORMAL:
 *
 * virDomainGetJobStats field: number of pages that were transferred without
 * any kind of compression (i.e., pages which were not filled with a constant
 * byte and which could not be compressed) transferred since the beginning
 * of the migration job, as VIR_TYPED_PARAM_ULLONG.
 */
# define VIR_DOMAIN_JOB_MEMORY_NORMAL            "memory_normal"

/**
 * VIR_DOMAIN_JOB_MEMORY_NORMAL_BYTES:
 *
 * virDomainGetJobStats field: number of bytes transferred as normal pages,
 * as VIR_TYPED_PARAM_ULLONG.
 *
 * See VIR_DOMAIN_JOB_MEMORY_NORMAL for more details.
 */
# define VIR_DOMAIN_JOB_MEMORY_NORMAL_BYTES      "memory_normal_bytes"

/**
 * VIR_DOMAIN_JOB_MEMORY_BPS:
 *
 * virDomainGetJobStats field: network throughput used while migrating
 * memory in Bytes per second, as VIR_TYPED_PARAM_ULLONG.
 */
# define VIR_DOMAIN_JOB_MEMORY_BPS               "memory_bps"

/** VIR_DOMAIN_JOB_MEMORY_DIRTY_RATE:
 *
 * virDomainGetJobStats field: number of memory pages dirtied by the guest
 * per second, as VIR_TYPED_PARAM_ULLONG. This statistics makes sense only
 * when live migration is running.
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
 */
# define VIR_DOMAIN_JOB_MEMORY_ITERATION         "memory_iteration"

/**
 * VIR_DOMAIN_JOB_MEMORY_POSTCOPY_REQS:
 *
 * virDomainGetJobStats field: number page requests received from the
 * destination host during post-copy migration, as VIR_TYPED_PARAM_ULLONG.
 * This counter is incremented whenever the migrated domain tries to access
 * a memory page which has not been transferred from the source host yet.
 */
# define VIR_DOMAIN_JOB_MEMORY_POSTCOPY_REQS     "memory_postcopy_requests"

/**
 * VIR_DOMAIN_JOB_DISK_TOTAL:
 *
 * virDomainGetJobStats field: as VIR_DOMAIN_JOB_DATA_TOTAL but only
 * tracking guest disk progress, as VIR_TYPED_PARAM_ULLONG.
 *
 * This field corresponds to fileTotal field in virDomainJobInfo.
 */
# define VIR_DOMAIN_JOB_DISK_TOTAL               "disk_total"

/**
 * VIR_DOMAIN_JOB_DISK_PROCESSED:
 *
 * virDomainGetJobStats field: as VIR_DOMAIN_JOB_DATA_PROCESSED but only
 * tracking guest disk progress, as VIR_TYPED_PARAM_ULLONG.
 *
 * This field corresponds to fileProcessed field in virDomainJobInfo.
 */
# define VIR_DOMAIN_JOB_DISK_PROCESSED           "disk_processed"

/**
 * VIR_DOMAIN_JOB_DISK_REMAINING:
 *
 * virDomainGetJobStats field: as VIR_DOMAIN_JOB_DATA_REMAINING but only
 * tracking guest disk progress, as VIR_TYPED_PARAM_ULLONG.
 *
 * This field corresponds to fileRemaining field in virDomainJobInfo.
 */
# define VIR_DOMAIN_JOB_DISK_REMAINING           "disk_remaining"

/**
 * VIR_DOMAIN_JOB_DISK_BPS:
 *
 * virDomainGetJobStats field: network throughput used while migrating
 * disks in Bytes per second, as VIR_TYPED_PARAM_ULLONG.
 */
# define VIR_DOMAIN_JOB_DISK_BPS                 "disk_bps"

/**
 * VIR_DOMAIN_JOB_COMPRESSION_CACHE:
 *
 * virDomainGetJobStats field: size of the cache (in bytes) used for
 * compressing repeatedly transferred memory pages during live migration,
 * as VIR_TYPED_PARAM_ULLONG.
 */
# define VIR_DOMAIN_JOB_COMPRESSION_CACHE        "compression_cache"

/**
 * VIR_DOMAIN_JOB_COMPRESSION_BYTES:
 *
 * virDomainGetJobStats field: number of compressed bytes transferred
 * since the beginning of migration, as VIR_TYPED_PARAM_ULLONG.
 */
# define VIR_DOMAIN_JOB_COMPRESSION_BYTES        "compression_bytes"

/**
 * VIR_DOMAIN_JOB_COMPRESSION_PAGES:
 *
 * virDomainGetJobStats field: number of compressed pages transferred
 * since the beginning of migration, as VIR_TYPED_PARAM_ULLONG.
 */
# define VIR_DOMAIN_JOB_COMPRESSION_PAGES        "compression_pages"

/**
 * VIR_DOMAIN_JOB_COMPRESSION_CACHE_MISSES:
 *
 * virDomainGetJobStats field: number of repeatedly changing pages that
 * were not found in compression cache and thus could not be compressed,
 * as VIR_TYPED_PARAM_ULLONG.
 */
# define VIR_DOMAIN_JOB_COMPRESSION_CACHE_MISSES "compression_cache_misses"

/**
 * VIR_DOMAIN_JOB_COMPRESSION_OVERFLOW:
 *
 * virDomainGetJobStats field: number of repeatedly changing pages that
 * were found in compression cache but were sent uncompressed because
 * the result of compression was larger than the original page as a whole,
 * as VIR_TYPED_PARAM_ULLONG.
 */
# define VIR_DOMAIN_JOB_COMPRESSION_OVERFLOW     "compression_overflow"

/**
 * VIR_DOMAIN_JOB_AUTO_CONVERGE_THROTTLE:
 *
 * virDomainGetJobStats field: current percentage guest CPUs are throttled
 * to when auto-convergence decided migration was not converging, as
 * VIR_TYPED_PARAM_INT.
 */
# define VIR_DOMAIN_JOB_AUTO_CONVERGE_THROTTLE  "auto_converge_throttle"

/**
 * VIR_DOMAIN_JOB_SUCCESS:
 *
 * virDomainGetJobStats field: Present only in statistics for a completed job.
 * Successful completion of the job as VIR_TYPED_PARAM_BOOLEAN.
 */
# define VIR_DOMAIN_JOB_SUCCESS "success"

/**
 * VIR_DOMAIN_JOB_ERRMSG:
 *
 * virDomainGetJobStats field: Present only in statistics for a completed job.
 * Optional error message for a failed job.
 */
# define VIR_DOMAIN_JOB_ERRMSG "errmsg"


/**
 * VIR_DOMAIN_JOB_DISK_TEMP_USED:
 * virDomainGetJobStats field: current usage of temporary disk space for the
 * job in bytes as VIR_TYPED_PARAM_ULLONG.
 */
# define VIR_DOMAIN_JOB_DISK_TEMP_USED "disk_temp_used"

/**
 * VIR_DOMAIN_JOB_DISK_TEMP_TOTAL:
 * virDomainGetJobStats field: possible total temporary disk space for the
 * job in bytes as VIR_TYPED_PARAM_ULLONG.
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
 */
typedef void (*virConnectDomainEventRTCChangeCallback)(virConnectPtr conn,
                                                       virDomainPtr dom,
                                                       long long utcoffset,
                                                       void *opaque);

/**
 * virDomainEventWatchdogAction:
 *
 * The action that is to be taken due to the watchdog device firing
 */
typedef enum {
    VIR_DOMAIN_EVENT_WATCHDOG_NONE = 0, /* No action, watchdog ignored */
    VIR_DOMAIN_EVENT_WATCHDOG_PAUSE,    /* Guest CPUs are paused */
    VIR_DOMAIN_EVENT_WATCHDOG_RESET,    /* Guest CPUs are reset */
    VIR_DOMAIN_EVENT_WATCHDOG_POWEROFF, /* Guest is forcibly powered off */
    VIR_DOMAIN_EVENT_WATCHDOG_SHUTDOWN, /* Guest is requested to gracefully shutdown */
    VIR_DOMAIN_EVENT_WATCHDOG_DEBUG,    /* No action, a debug message logged */
    VIR_DOMAIN_EVENT_WATCHDOG_INJECTNMI,/* Inject a non-maskable interrupt into guest */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_EVENT_WATCHDOG_LAST
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
 */
typedef void (*virConnectDomainEventWatchdogCallback)(virConnectPtr conn,
                                                      virDomainPtr dom,
                                                      int action,
                                                      void *opaque);

/**
 * virDomainEventIOErrorAction:
 *
 * The action that is to be taken due to an IO error occurring
 */
typedef enum {
    VIR_DOMAIN_EVENT_IO_ERROR_NONE = 0,  /* No action, IO error ignored */
    VIR_DOMAIN_EVENT_IO_ERROR_PAUSE,     /* Guest CPUs are paused */
    VIR_DOMAIN_EVENT_IO_ERROR_REPORT,    /* IO error reported to guest OS */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_EVENT_IO_ERROR_LAST
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
 */
typedef enum {
    VIR_DOMAIN_EVENT_GRAPHICS_CONNECT = 0,  /* Initial socket connection established */
    VIR_DOMAIN_EVENT_GRAPHICS_INITIALIZE,   /* Authentication & setup completed */
    VIR_DOMAIN_EVENT_GRAPHICS_DISCONNECT,   /* Final socket disconnection */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_EVENT_GRAPHICS_LAST
# endif
} virDomainEventGraphicsPhase;

/**
 * virDomainEventGraphicsAddressType:
 *
 * The type of address for the connection
 */
typedef enum {
    VIR_DOMAIN_EVENT_GRAPHICS_ADDRESS_IPV4,  /* IPv4 address */
    VIR_DOMAIN_EVENT_GRAPHICS_ADDRESS_IPV6,  /* IPv6 address */
    VIR_DOMAIN_EVENT_GRAPHICS_ADDRESS_UNIX,  /* UNIX socket path */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_EVENT_GRAPHICS_ADDRESS_LAST
# endif
} virDomainEventGraphicsAddressType;


/**
 * virDomainEventGraphicsAddress:
 *
 * The data structure containing connection address details
 *
 */
struct _virDomainEventGraphicsAddress {
    int family;               /* Address family, virDomainEventGraphicsAddressType */
    char *node;               /* Address of node (eg IP address, or UNIX path) */
    char *service;            /* Service name/number (eg TCP port, or NULL) */
};
typedef struct _virDomainEventGraphicsAddress virDomainEventGraphicsAddress;
typedef virDomainEventGraphicsAddress *virDomainEventGraphicsAddressPtr;


/**
 * virDomainEventGraphicsSubjectIdentity:
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
typedef struct _virDomainEventGraphicsSubjectIdentity virDomainEventGraphicsSubjectIdentity;
typedef virDomainEventGraphicsSubjectIdentity *virDomainEventGraphicsSubjectIdentityPtr;


/**
 * virDomainEventGraphicsSubject:
 *
 * The data structure representing an authenticated subject
 *
 * A subject will have zero or more identities. The types of
 * identity differ according to the authentication scheme
 */
struct _virDomainEventGraphicsSubject {
    int nidentity;                                /* Number of identities in array*/
    virDomainEventGraphicsSubjectIdentityPtr identities; /* Array of identities for subject */
};
typedef struct _virDomainEventGraphicsSubject virDomainEventGraphicsSubject;
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
 */
typedef enum {
    VIR_DOMAIN_BLOCK_JOB_COMPLETED = 0,
    VIR_DOMAIN_BLOCK_JOB_FAILED = 1,
    VIR_DOMAIN_BLOCK_JOB_CANCELED = 2,
    VIR_DOMAIN_BLOCK_JOB_READY = 3,

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_BLOCK_JOB_LAST
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
 */
typedef enum {
    /* Removable media changed to empty according to startup policy as source
     * was missing. oldSrcPath is set, newSrcPath is NULL */
    VIR_DOMAIN_EVENT_DISK_CHANGE_MISSING_ON_START = 0,

    /* Disk was dropped from domain as source file was missing.
     * oldSrcPath is set, newSrcPath is NULL */
    VIR_DOMAIN_EVENT_DISK_DROP_MISSING_ON_START = 1,

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_EVENT_DISK_CHANGE_LAST
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
 */
typedef enum {
    VIR_DOMAIN_EVENT_TRAY_CHANGE_OPEN = 0,
    VIR_DOMAIN_EVENT_TRAY_CHANGE_CLOSE,

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_EVENT_TRAY_CHANGE_LAST
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
 */
# define VIR_DOMAIN_TUNABLE_CPU_VCPUPIN "cputune.vcpupin%u"

/**
 * VIR_DOMAIN_TUNABLE_CPU_EMULATORPIN:
 *
 * Macro represents formatted pinning for emulator process,
 * as VIR_TYPED_PARAM_STRING.
 */
# define VIR_DOMAIN_TUNABLE_CPU_EMULATORPIN "cputune.emulatorpin"

/**
 * VIR_DOMAIN_TUNABLE_CPU_IOTHREADSPIN:
 *
 * Macro represents formatted pinning for one IOThread specified by id which is
 * appended to the parameter name, for example "cputune.iothreadpin1",
 * as VIR_TYPED_PARAM_STRING.
 */
# define VIR_DOMAIN_TUNABLE_CPU_IOTHREADSPIN "cputune.iothreadpin%u"

/**
 * VIR_DOMAIN_TUNABLE_CPU_CPU_SHARES:
 *
 * Macro represents proportional weight of the scheduler used on the
 * host cpu, when using the posix scheduler, as VIR_TYPED_PARAM_ULLONG.
 */
# define VIR_DOMAIN_TUNABLE_CPU_CPU_SHARES "cputune.cpu_shares"

/**
 * VIR_DOMAIN_TUNABLE_CPU_GLOBAL_PERIOD:
 *
 * Macro represents the enforcement period for a quota, in microseconds,
 * for whole domain, when using the posix scheduler, as VIR_TYPED_PARAM_ULLONG.
 */
# define VIR_DOMAIN_TUNABLE_CPU_GLOBAL_PERIOD "cputune.global_period"

/**
 * VIR_DOMAIN_TUNABLE_CPU_GLOBAL_QUOTA:
 *
 * Macro represents the maximum bandwidth to be used within a period for
 * whole domain, when using the posix scheduler, as VIR_TYPED_PARAM_LLONG.
 */
# define VIR_DOMAIN_TUNABLE_CPU_GLOBAL_QUOTA "cputune.global_quota"

/**
 * VIR_DOMAIN_TUNABLE_CPU_VCPU_PERIOD:
 *
 * Macro represents the enforcement period for a quota, in microseconds,
 * for vcpus only, when using the posix scheduler, as VIR_TYPED_PARAM_ULLONG.
 */
# define VIR_DOMAIN_TUNABLE_CPU_VCPU_PERIOD "cputune.vcpu_period"

/**
 * VIR_DOMAIN_TUNABLE_CPU_VCPU_QUOTA:
 *
 * Macro represents the maximum bandwidth to be used within a period for
 * vcpus only, when using the posix scheduler, as VIR_TYPED_PARAM_LLONG.
 */
# define VIR_DOMAIN_TUNABLE_CPU_VCPU_QUOTA "cputune.vcpu_quota"

/**
 * VIR_DOMAIN_TUNABLE_CPU_EMULATOR_PERIOD:
 *
 * Macro represents the enforcement period for a quota in microseconds,
 * when using the posix scheduler, for all emulator activity not tied to
 * vcpus, as VIR_TYPED_PARAM_ULLONG.
 */
# define VIR_DOMAIN_TUNABLE_CPU_EMULATOR_PERIOD "cputune.emulator_period"

/**
 * VIR_DOMAIN_TUNABLE_CPU_EMULATOR_QUOTA:
 *
 * Macro represents the maximum bandwidth to be used within a period for
 * all emulator activity not tied to vcpus, when using the posix scheduler,
 * as an VIR_TYPED_PARAM_LLONG.
 */
# define VIR_DOMAIN_TUNABLE_CPU_EMULATOR_QUOTA "cputune.emulator_quota"

/**
 * VIR_DOMAIN_TUNABLE_CPU_IOTHREAD_PERIOD:
 *
 * Macro represents the enforcement period for a quota, in microseconds, for
 * iothreads only, when using the posix scheduler, as VIR_TYPED_PARAM_ULLONG.
 */
# define VIR_DOMAIN_TUNABLE_CPU_IOTHREAD_PERIOD "cputune.iothread_period"

/**
 * VIR_DOMAIN_TUNABLE_CPU_IOTHREAD_QUOTA:
 *
 * Macro represents the maximum bandwidth to be used within a period for
 * iothreads only, when using the posix scheduler, as VIR_TYPED_PARAM_LLONG.
 */
# define VIR_DOMAIN_TUNABLE_CPU_IOTHREAD_QUOTA "cputune.iothread_quota"

/**
 * VIR_DOMAIN_TUNABLE_BLKDEV_DISK:
 *
 * Macro represents the name of guest disk for which the values are updated,
 * as VIR_TYPED_PARAM_STRING.
 */
# define VIR_DOMAIN_TUNABLE_BLKDEV_DISK "blkdeviotune.disk"

/**
 * VIR_DOMAIN_TUNABLE_BLKDEV_TOTAL_BYTES_SEC:
 *
 * Macro represents the total throughput limit in bytes per second,
 * as VIR_TYPED_PARAM_ULLONG.
 */
# define VIR_DOMAIN_TUNABLE_BLKDEV_TOTAL_BYTES_SEC "blkdeviotune.total_bytes_sec"

/**
 * VIR_DOMAIN_TUNABLE_BLKDEV_READ_BYTES_SEC:
 *
 * Macro represents the read throughput limit in bytes per second,
 * as VIR_TYPED_PARAM_ULLONG.
 */
# define VIR_DOMAIN_TUNABLE_BLKDEV_READ_BYTES_SEC "blkdeviotune.read_bytes_sec"

/**
 * VIR_DOMAIN_TUNABLE_BLKDEV_WRITE_BYTES_SEC:
 *
 * Macro represents the write throughput limit in bytes per second,
 * as VIR_TYPED_PARAM_ULLONG.
 */
# define VIR_DOMAIN_TUNABLE_BLKDEV_WRITE_BYTES_SEC "blkdeviotune.write_bytes_sec"

/**
 * VIR_DOMAIN_TUNABLE_BLKDEV_TOTAL_IOPS_SEC:
 *
 * Macro represents the total I/O operations per second,
 * as VIR_TYPED_PARAM_ULLONG.
 */
# define VIR_DOMAIN_TUNABLE_BLKDEV_TOTAL_IOPS_SEC "blkdeviotune.total_iops_sec"

/**
 * VIR_DOMAIN_TUNABLE_BLKDEV_READ_IOPS_SEC:
 *
 * Macro represents the read I/O operations per second,
 * as VIR_TYPED_PARAM_ULLONG.
 */
# define VIR_DOMAIN_TUNABLE_BLKDEV_READ_IOPS_SEC "blkdeviotune.read_iops_sec"

/**
 * VIR_DOMAIN_TUNABLE_BLKDEV_WRITE_IOPS_SEC:
 *
 * Macro represents the write I/O operations per second,
 * as VIR_TYPED_PARAM_ULLONG.
 */
# define VIR_DOMAIN_TUNABLE_BLKDEV_WRITE_IOPS_SEC "blkdeviotune.write_iops_sec"

/**
 * VIR_DOMAIN_TUNABLE_BLKDEV_TOTAL_BYTES_SEC_MAX:
 *
 * Macro represents the total throughput limit during bursts in
 * maximum bytes per second, as VIR_TYPED_PARAM_ULLONG.
 */
# define VIR_DOMAIN_TUNABLE_BLKDEV_TOTAL_BYTES_SEC_MAX "blkdeviotune.total_bytes_sec_max"

/**
 * VIR_DOMAIN_TUNABLE_BLKDEV_READ_BYTES_SEC_MAX:
 *
 * Macro represents the read throughput limit during bursts in
 * maximum bytes per second, as VIR_TYPED_PARAM_ULLONG.
 */
# define VIR_DOMAIN_TUNABLE_BLKDEV_READ_BYTES_SEC_MAX "blkdeviotune.read_bytes_sec_max"

/**
 * VIR_DOMAIN_TUNABLE_BLKDEV_WRITE_BYTES_SEC_MAX:
 *
 * Macro represents the write throughput limit during bursts in
 * maximum bytes per second, as VIR_TYPED_PARAM_ULLONG.
 */
# define VIR_DOMAIN_TUNABLE_BLKDEV_WRITE_BYTES_SEC_MAX "blkdeviotune.write_bytes_sec_max"

/**
 * VIR_DOMAIN_TUNABLE_BLKDEV_TOTAL_IOPS_SEC_MAX:
 *
 * Macro represents the total maximum I/O operations per second during bursts,
 * as VIR_TYPED_PARAM_ULLONG.
 */
# define VIR_DOMAIN_TUNABLE_BLKDEV_TOTAL_IOPS_SEC_MAX "blkdeviotune.total_iops_sec_max"

/**
 * VIR_DOMAIN_TUNABLE_BLKDEV_READ_IOPS_SEC_MAX:
 *
 * Macro represents the read maximum I/O operations per second during bursts,
 * as VIR_TYPED_PARAM_ULLONG.
 */
# define VIR_DOMAIN_TUNABLE_BLKDEV_READ_IOPS_SEC_MAX "blkdeviotune.read_iops_sec_max"

/**
 * VIR_DOMAIN_TUNABLE_BLKDEV_WRITE_IOPS_SEC_MAX:
 *
 * Macro represents the write maximum I/O operations per second during bursts,
 * as VIR_TYPED_PARAM_ULLONG.
 */
# define VIR_DOMAIN_TUNABLE_BLKDEV_WRITE_IOPS_SEC_MAX "blkdeviotune.write_iops_sec_max"

/**
 * VIR_DOMAIN_TUNABLE_BLKDEV_SIZE_IOPS_SEC:
 *
 * Macro represents the size maximum I/O operations per second,
 * as VIR_TYPED_PARAM_ULLONG.
 */
# define VIR_DOMAIN_TUNABLE_BLKDEV_SIZE_IOPS_SEC "blkdeviotune.size_iops_sec"

/**
 * VIR_DOMAIN_TUNABLE_BLKDEV_GROUP_NAME:
 *
 * Macro represents the group name to be used,
 * as VIR_TYPED_PARAM_STRING.
 */
# define VIR_DOMAIN_TUNABLE_BLKDEV_GROUP_NAME "blkdeviotune.group_name"

/**
 * VIR_DOMAIN_TUNABLE_BLKDEV_TOTAL_BYTES_SEC_MAX_LENGTH:
 *
 * Macro represents the length in seconds allowed for a burst period
 * for the blkdeviotune.total_bytes_sec_max,
 * as VIR_TYPED_PARAM_ULLONG.
 */
# define VIR_DOMAIN_TUNABLE_BLKDEV_TOTAL_BYTES_SEC_MAX_LENGTH "blkdeviotune.total_bytes_sec_max_length"

/**
 * VIR_DOMAIN_TUNABLE_BLKDEV_READ_BYTES_SEC_MAX_LENGTH:
 *
 * Macro represents the length in seconds allowed for a burst period
 * for the blkdeviotune.read_bytes_sec_max
 * as VIR_TYPED_PARAM_ULLONG.
 */
# define VIR_DOMAIN_TUNABLE_BLKDEV_READ_BYTES_SEC_MAX_LENGTH "blkdeviotune.read_bytes_sec_max_length"

/**
 * VIR_DOMAIN_TUNABLE_BLKDEV_WRITE_BYTES_SEC_MAX_LENGTH:
 *
 * Macro represents the length in seconds allowed for a burst period
 * for the blkdeviotune.write_bytes_sec_max
 * as VIR_TYPED_PARAM_ULLONG.
 */
# define VIR_DOMAIN_TUNABLE_BLKDEV_WRITE_BYTES_SEC_MAX_LENGTH "blkdeviotune.write_bytes_sec_max_length"

/**
 * VIR_DOMAIN_TUNABLE_BLKDEV_TOTAL_IOPS_SEC_MAX_LENGTH:
 *
 * Macro represents the length in seconds allowed for a burst period
 * for the blkdeviotune.total_iops_sec_max
 * as VIR_TYPED_PARAM_ULLONG.
 */
# define VIR_DOMAIN_TUNABLE_BLKDEV_TOTAL_IOPS_SEC_MAX_LENGTH "blkdeviotune.total_iops_sec_max_length"

/**
 * VIR_DOMAIN_TUNABLE_BLKDEV_READ_IOPS_SEC_MAX_LENGTH:
 *
 * Macro represents the length in seconds allowed for a burst period
 * for the blkdeviotune.read_iops_sec_max
 * as VIR_TYPED_PARAM_ULLONG.
 */
# define VIR_DOMAIN_TUNABLE_BLKDEV_READ_IOPS_SEC_MAX_LENGTH "blkdeviotune.read_iops_sec_max_length"

/**
 * VIR_DOMAIN_TUNABLE_BLKDEV_WRITE_IOPS_SEC_MAX_LENGTH:
 *
 * Macro represents the length in seconds allowed for a burst period
 * for the blkdeviotune.write_iops_sec_max
 * as VIR_TYPED_PARAM_ULLONG.
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
 */
typedef void (*virConnectDomainEventTunableCallback)(virConnectPtr conn,
                                                     virDomainPtr dom,
                                                     virTypedParameterPtr params,
                                                     int nparams,
                                                     void *opaque);


typedef enum {
    VIR_CONNECT_DOMAIN_EVENT_AGENT_LIFECYCLE_STATE_CONNECTED = 1, /* agent connected */
    VIR_CONNECT_DOMAIN_EVENT_AGENT_LIFECYCLE_STATE_DISCONNECTED = 2, /* agent disconnected */

# ifdef VIR_ENUM_SENTINELS
    VIR_CONNECT_DOMAIN_EVENT_AGENT_LIFECYCLE_STATE_LAST
# endif
} virConnectDomainEventAgentLifecycleState;

typedef enum {
    VIR_CONNECT_DOMAIN_EVENT_AGENT_LIFECYCLE_REASON_UNKNOWN = 0, /* unknown state change reason */
    VIR_CONNECT_DOMAIN_EVENT_AGENT_LIFECYCLE_REASON_DOMAIN_STARTED = 1, /* state changed due to domain start */
    VIR_CONNECT_DOMAIN_EVENT_AGENT_LIFECYCLE_REASON_CHANNEL = 2, /* channel state changed */

# ifdef VIR_ENUM_SENTINELS
    VIR_CONNECT_DOMAIN_EVENT_AGENT_LIFECYCLE_REASON_LAST
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
 */
# define VIR_DOMAIN_EVENT_CALLBACK(cb) ((virConnectDomainEventGenericCallback)(cb))


/**
 * virDomainEventID:
 *
 * An enumeration of supported eventId parameters for
 * virConnectDomainEventRegisterAny().  Each event id determines which
 * signature of callback function will be used.
 */
typedef enum {
    VIR_DOMAIN_EVENT_ID_LIFECYCLE = 0,       /* virConnectDomainEventCallback */
    VIR_DOMAIN_EVENT_ID_REBOOT = 1,          /* virConnectDomainEventGenericCallback */
    VIR_DOMAIN_EVENT_ID_RTC_CHANGE = 2,      /* virConnectDomainEventRTCChangeCallback */
    VIR_DOMAIN_EVENT_ID_WATCHDOG = 3,        /* virConnectDomainEventWatchdogCallback */
    VIR_DOMAIN_EVENT_ID_IO_ERROR = 4,        /* virConnectDomainEventIOErrorCallback */
    VIR_DOMAIN_EVENT_ID_GRAPHICS = 5,        /* virConnectDomainEventGraphicsCallback */
    VIR_DOMAIN_EVENT_ID_IO_ERROR_REASON = 6, /* virConnectDomainEventIOErrorReasonCallback */
    VIR_DOMAIN_EVENT_ID_CONTROL_ERROR = 7,   /* virConnectDomainEventGenericCallback */
    VIR_DOMAIN_EVENT_ID_BLOCK_JOB = 8,       /* virConnectDomainEventBlockJobCallback */
    VIR_DOMAIN_EVENT_ID_DISK_CHANGE = 9,     /* virConnectDomainEventDiskChangeCallback */
    VIR_DOMAIN_EVENT_ID_TRAY_CHANGE = 10,    /* virConnectDomainEventTrayChangeCallback */
    VIR_DOMAIN_EVENT_ID_PMWAKEUP = 11,       /* virConnectDomainEventPMWakeupCallback */
    VIR_DOMAIN_EVENT_ID_PMSUSPEND = 12,      /* virConnectDomainEventPMSuspendCallback */
    VIR_DOMAIN_EVENT_ID_BALLOON_CHANGE = 13, /* virConnectDomainEventBalloonChangeCallback */
    VIR_DOMAIN_EVENT_ID_PMSUSPEND_DISK = 14, /* virConnectDomainEventPMSuspendDiskCallback */
    VIR_DOMAIN_EVENT_ID_DEVICE_REMOVED = 15, /* virConnectDomainEventDeviceRemovedCallback */
    VIR_DOMAIN_EVENT_ID_BLOCK_JOB_2 = 16,    /* virConnectDomainEventBlockJobCallback */
    VIR_DOMAIN_EVENT_ID_TUNABLE = 17,        /* virConnectDomainEventTunableCallback */
    VIR_DOMAIN_EVENT_ID_AGENT_LIFECYCLE = 18,/* virConnectDomainEventAgentLifecycleCallback */
    VIR_DOMAIN_EVENT_ID_DEVICE_ADDED = 19,   /* virConnectDomainEventDeviceAddedCallback */
    VIR_DOMAIN_EVENT_ID_MIGRATION_ITERATION = 20, /* virConnectDomainEventMigrationIterationCallback */
    VIR_DOMAIN_EVENT_ID_JOB_COMPLETED = 21,  /* virConnectDomainEventJobCompletedCallback */
    VIR_DOMAIN_EVENT_ID_DEVICE_REMOVAL_FAILED = 22, /* virConnectDomainEventDeviceRemovalFailedCallback */
    VIR_DOMAIN_EVENT_ID_METADATA_CHANGE = 23, /* virConnectDomainEventMetadataChangeCallback */
    VIR_DOMAIN_EVENT_ID_BLOCK_THRESHOLD = 24, /* virConnectDomainEventBlockThresholdCallback */
    VIR_DOMAIN_EVENT_ID_MEMORY_FAILURE = 25,  /* virConnectDomainEventMemoryFailureCallback */
    VIR_DOMAIN_EVENT_ID_MEMORY_DEVICE_SIZE_CHANGE = 26, /* virConnectDomainEventMemoryDeviceSizeChangeCallback */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_EVENT_ID_LAST
    /*
     * NB: this enum value will increase over time as new events are
     * added to the libvirt API. It reflects the last event ID supported
     * by this version of the libvirt API.
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
 * virDomainConsoleFlags
 *
 * Since 0.9.10
 */
typedef enum {

    VIR_DOMAIN_CONSOLE_FORCE = (1 << 0), /* abort a (possibly) active console
                                            connection to force a new
                                            connection */
    VIR_DOMAIN_CONSOLE_SAFE = (1 << 1), /* check if the console driver supports
                                           safe console operations */
} virDomainConsoleFlags;

int virDomainOpenConsole(virDomainPtr dom,
                         const char *dev_name,
                         virStreamPtr st,
                         unsigned int flags);

/**
 * virDomainChannelFlags
 *
 * Since 1.0.2
 */
typedef enum {
    VIR_DOMAIN_CHANNEL_FORCE = (1 << 0), /* abort a (possibly) active channel
                                            connection to force a new
                                            connection */
} virDomainChannelFlags;

int virDomainOpenChannel(virDomainPtr dom,
                         const char *name,
                         virStreamPtr st,
                         unsigned int flags);

typedef enum {
    VIR_DOMAIN_OPEN_GRAPHICS_SKIPAUTH = (1 << 0),
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
 */
typedef struct _virDomainFSInfo virDomainFSInfo;
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

typedef enum {
    VIR_DOMAIN_TIME_SYNC = (1 << 0), /* Re-sync domain time from domain's RTC */
} virDomainSetTimeFlags;

int virDomainSetTime(virDomainPtr dom,
                     long long seconds,
                     unsigned int nseconds,
                     unsigned int flags);

/**
 * virSchedParameterType:
 *
 * A scheduler parameter field type.  Provided for backwards
 * compatibility; virTypedParameterType is the preferred enum since
 * 0.9.2.
 */
typedef enum {
    VIR_DOMAIN_SCHED_FIELD_INT     = VIR_TYPED_PARAM_INT,
    VIR_DOMAIN_SCHED_FIELD_UINT    = VIR_TYPED_PARAM_UINT,
    VIR_DOMAIN_SCHED_FIELD_LLONG   = VIR_TYPED_PARAM_LLONG,
    VIR_DOMAIN_SCHED_FIELD_ULLONG  = VIR_TYPED_PARAM_ULLONG,
    VIR_DOMAIN_SCHED_FIELD_DOUBLE  = VIR_TYPED_PARAM_DOUBLE,
    VIR_DOMAIN_SCHED_FIELD_BOOLEAN = VIR_TYPED_PARAM_BOOLEAN,
} virSchedParameterType;

/**
 * VIR_DOMAIN_SCHED_FIELD_LENGTH:
 *
 * Macro providing the field length of virSchedParameter.  Provided
 * for backwards compatibility; VIR_TYPED_PARAM_FIELD_LENGTH is the
 * preferred value since 0.9.2.
 */
# define VIR_DOMAIN_SCHED_FIELD_LENGTH VIR_TYPED_PARAM_FIELD_LENGTH

/**
 * virSchedParameter:
 *
 * a virSchedParameter is the set of scheduler parameters.
 * Provided for backwards compatibility; virTypedParameter is the
 * preferred alias since 0.9.2.
 */
# define _virSchedParameter _virTypedParameter
typedef struct _virTypedParameter virSchedParameter;

/**
 * virSchedParameterPtr:
 *
 * a virSchedParameterPtr is a pointer to a virSchedParameter structure.
 * Provided for backwards compatibility; virTypedParameterPtr is the
 * preferred alias since 0.9.2.
 */
typedef virSchedParameter *virSchedParameterPtr;

/**
 * virBlkioParameterType:
 *
 * A blkio parameter field type.  Provided for backwards
 * compatibility; virTypedParameterType is the preferred enum since
 * 0.9.2.
 */
typedef enum {
    VIR_DOMAIN_BLKIO_PARAM_INT     = VIR_TYPED_PARAM_INT,
    VIR_DOMAIN_BLKIO_PARAM_UINT    = VIR_TYPED_PARAM_UINT,
    VIR_DOMAIN_BLKIO_PARAM_LLONG   = VIR_TYPED_PARAM_LLONG,
    VIR_DOMAIN_BLKIO_PARAM_ULLONG  = VIR_TYPED_PARAM_ULLONG,
    VIR_DOMAIN_BLKIO_PARAM_DOUBLE  = VIR_TYPED_PARAM_DOUBLE,
    VIR_DOMAIN_BLKIO_PARAM_BOOLEAN = VIR_TYPED_PARAM_BOOLEAN,
} virBlkioParameterType;

/**
 * VIR_DOMAIN_BLKIO_FIELD_LENGTH:
 *
 * Macro providing the field length of virBlkioParameter.  Provided
 * for backwards compatibility; VIR_TYPED_PARAM_FIELD_LENGTH is the
 * preferred value since 0.9.2.
 */
# define VIR_DOMAIN_BLKIO_FIELD_LENGTH VIR_TYPED_PARAM_FIELD_LENGTH

/**
 * virBlkioParameter:
 *
 * a virBlkioParameter is the set of blkio parameters.
 * Provided for backwards compatibility; virTypedParameter is the
 * preferred alias since 0.9.2.
 */
# define _virBlkioParameter _virTypedParameter
typedef struct _virTypedParameter virBlkioParameter;

/**
 * virBlkioParameterPtr:
 *
 * a virBlkioParameterPtr is a pointer to a virBlkioParameter structure.
 * Provided for backwards compatibility; virTypedParameterPtr is the
 * preferred alias since 0.9.2.
 */
typedef virBlkioParameter *virBlkioParameterPtr;

/**
 * virMemoryParameterType:
 *
 * A memory parameter field type.  Provided for backwards
 * compatibility; virTypedParameterType is the preferred enum since
 * 0.9.2.
 */
typedef enum {
    VIR_DOMAIN_MEMORY_PARAM_INT     = VIR_TYPED_PARAM_INT,
    VIR_DOMAIN_MEMORY_PARAM_UINT    = VIR_TYPED_PARAM_UINT,
    VIR_DOMAIN_MEMORY_PARAM_LLONG   = VIR_TYPED_PARAM_LLONG,
    VIR_DOMAIN_MEMORY_PARAM_ULLONG  = VIR_TYPED_PARAM_ULLONG,
    VIR_DOMAIN_MEMORY_PARAM_DOUBLE  = VIR_TYPED_PARAM_DOUBLE,
    VIR_DOMAIN_MEMORY_PARAM_BOOLEAN = VIR_TYPED_PARAM_BOOLEAN,
} virMemoryParameterType;

/**
 * VIR_DOMAIN_MEMORY_FIELD_LENGTH:
 *
 * Macro providing the field length of virMemoryParameter.  Provided
 * for backwards compatibility; VIR_TYPED_PARAM_FIELD_LENGTH is the
 * preferred value since 0.9.2.
 */
# define VIR_DOMAIN_MEMORY_FIELD_LENGTH VIR_TYPED_PARAM_FIELD_LENGTH

/**
 * virMemoryParameter:
 *
 * a virMemoryParameter is the set of scheduler parameters.
 * Provided for backwards compatibility; virTypedParameter is the
 * preferred alias since 0.9.2.
 */
# define _virMemoryParameter _virTypedParameter
typedef struct _virTypedParameter virMemoryParameter;

/**
 * virMemoryParameterPtr:
 *
 * a virMemoryParameterPtr is a pointer to a virMemoryParameter structure.
 * Provided for backwards compatibility; virTypedParameterPtr is the
 * preferred alias since 0.9.2.
 */
typedef virMemoryParameter *virMemoryParameterPtr;

typedef enum {
    VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_LEASE = 0, /* Parse DHCP lease file */
    VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_AGENT = 1, /* Query qemu guest agent */
    VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_ARP = 2, /* Query ARP tables */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_LAST
# endif
} virDomainInterfaceAddressesSource;

typedef struct _virDomainInterfaceIPAddress virDomainIPAddress;
typedef virDomainIPAddress *virDomainIPAddressPtr;
struct _virDomainInterfaceIPAddress {
    int type;                /* virIPAddrType */
    char *addr;              /* IP address */
    unsigned int prefix;     /* IP address prefix */
};

typedef struct _virDomainInterface virDomainInterface;
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

typedef enum {
    VIR_DOMAIN_PASSWORD_ENCRYPTED = 1 << 0, /* the password is already encrypted */
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

typedef enum {
    VIR_DOMAIN_LIFECYCLE_POWEROFF = 0,
    VIR_DOMAIN_LIFECYCLE_REBOOT = 1,
    VIR_DOMAIN_LIFECYCLE_CRASH = 2,

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_LIFECYCLE_LAST
# endif
} virDomainLifecycle;

typedef enum {
    VIR_DOMAIN_LIFECYCLE_ACTION_DESTROY = 0,
    VIR_DOMAIN_LIFECYCLE_ACTION_RESTART = 1,
    VIR_DOMAIN_LIFECYCLE_ACTION_RESTART_RENAME = 2,
    VIR_DOMAIN_LIFECYCLE_ACTION_PRESERVE = 3,
    VIR_DOMAIN_LIFECYCLE_ACTION_COREDUMP_DESTROY = 4,
    VIR_DOMAIN_LIFECYCLE_ACTION_COREDUMP_RESTART = 5,

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_LIFECYCLE_ACTION_LAST
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
 */
# define VIR_DOMAIN_LAUNCH_SECURITY_SEV_MEASUREMENT "sev-measurement"

/**

 * VIR_DOMAIN_LAUNCH_SECURITY_SEV_API_MAJOR:
 *
 * Macro represents the API major version of the SEV host,
 * as VIR_TYPED_PARAM_UINT.
 */
# define VIR_DOMAIN_LAUNCH_SECURITY_SEV_API_MAJOR "sev-api-major"

/**
 * VIR_DOMAIN_LAUNCH_SECURITY_SEV_API_MINOR:
 *
 * Macro represents the API minor version of the SEV guest,
 * as VIR_TYPED_PARAM_UINT.
 */
# define VIR_DOMAIN_LAUNCH_SECURITY_SEV_API_MINOR "sev-api-minor"

/**
 * VIR_DOMAIN_LAUNCH_SECURITY_SEV_BUILD_ID:
 *
 * Macro represents the build ID of the SEV host,
 * as VIR_TYPED_PARAM_UINT.
 */
# define VIR_DOMAIN_LAUNCH_SECURITY_SEV_BUILD_ID "sev-build-id"

/**
 * VIR_DOMAIN_LAUNCH_SECURITY_SEV_POLICY:
 *
 * Macro represents the policy of the SEV guest,
 * as VIR_TYPED_PARAM_UINT.
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
 */
# define VIR_DOMAIN_LAUNCH_SECURITY_SEV_SECRET_HEADER "sev-secret-header"

/**
 * VIR_DOMAIN_LAUNCH_SECURITY_SEV_SECRET:
 *
 * A macro used to represent the SEV launch secret. The secret is a
 * base64-encoded VIR_TYPED_PARAM_STRING containing an encrypted launch
 * secret. The secret is created by the domain owner after the SEV launch
 * measurement is retrieved and verified.
 */
# define VIR_DOMAIN_LAUNCH_SECURITY_SEV_SECRET "sev-secret"

/**
 * VIR_DOMAIN_LAUNCH_SECURITY_SEV_SECRET_SET_ADDRESS:
 *
 * A macro used to represent the physical address within the guest's memory
 * where the secret will be set, as VIR_TYPED_PARAM_ULLONG. If not specified,
 * the address will be determined by the hypervisor.
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

typedef enum {
    VIR_DOMAIN_GUEST_INFO_USERS = (1 << 0), /* return active users */
    VIR_DOMAIN_GUEST_INFO_OS = (1 << 1), /* return OS information */
    VIR_DOMAIN_GUEST_INFO_TIMEZONE = (1 << 2), /* return timezone information */
    VIR_DOMAIN_GUEST_INFO_HOSTNAME = (1 << 3), /* return hostname information */
    VIR_DOMAIN_GUEST_INFO_FILESYSTEM = (1 << 4), /* return filesystem information */
    VIR_DOMAIN_GUEST_INFO_DISKS = (1 << 5), /* return disks information */
    VIR_DOMAIN_GUEST_INFO_INTERFACES = (1 << 6), /* return interfaces information */
} virDomainGuestInfoTypes;

int virDomainGetGuestInfo(virDomainPtr domain,
                          unsigned int types,
                          virTypedParameterPtr *params,
                          int *nparams,
                          unsigned int flags);

typedef enum {
    VIR_DOMAIN_AGENT_RESPONSE_TIMEOUT_BLOCK = -2,
    VIR_DOMAIN_AGENT_RESPONSE_TIMEOUT_DEFAULT = -1,
    VIR_DOMAIN_AGENT_RESPONSE_TIMEOUT_NOWAIT = 0,
} virDomainAgentResponseTimeoutValues;

int virDomainAgentSetResponseTimeout(virDomainPtr domain,
                                     int timeout,
                                     unsigned int flags);

typedef enum {
    VIR_DOMAIN_BACKUP_BEGIN_REUSE_EXTERNAL = (1 << 0), /* reuse separately
                                                          provided images */
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

typedef enum {
    VIR_DOMAIN_AUTHORIZED_SSH_KEYS_SET_APPEND = (1 << 0), /* don't truncate file, just append */
    VIR_DOMAIN_AUTHORIZED_SSH_KEYS_SET_REMOVE = (1 << 1), /* remove keys, instead of adding them */

} virDomainAuthorizedSSHKeysSetFlags;

int virDomainAuthorizedSSHKeysSet(virDomainPtr domain,
                                  const char *user,
                                  const char **keys,
                                  unsigned int nkeys,
                                  unsigned int flags);

typedef enum {
    VIR_DOMAIN_MESSAGE_DEPRECATION = (1 << 0),
    VIR_DOMAIN_MESSAGE_TAINTING = (1 << 1),
} virDomainMessageType;

int virDomainGetMessages(virDomainPtr domain,
                         char ***msgs,
                         unsigned int flags);

/**
 * virDomainDirtyRateStatus:
 *
 * Details on the cause of a dirty rate calculation status.
 */
typedef enum {
    VIR_DOMAIN_DIRTYRATE_UNSTARTED = 0, /* the dirtyrate calculation has
                                           not been started */
    VIR_DOMAIN_DIRTYRATE_MEASURING = 1, /* the dirtyrate calculation is
                                           measuring */
    VIR_DOMAIN_DIRTYRATE_MEASURED  = 2, /* the dirtyrate calculation is
                                           completed */

# ifdef VIR_ENUM_SENTINELS
    VIR_DOMAIN_DIRTYRATE_LAST
# endif
} virDomainDirtyRateStatus;

/**
 * virDomainDirtyRateCalcFlags:
 *
 * Flags OR'ed together to provide specific behaviour when calculating dirty page
 * rate for a Domain
 *
 */
typedef enum {
    VIR_DOMAIN_DIRTYRATE_MODE_PAGE_SAMPLING = 0,        /* default mode - page-sampling */
    VIR_DOMAIN_DIRTYRATE_MODE_DIRTY_BITMAP = 1 << 0,    /* dirty-bitmap mode */
    VIR_DOMAIN_DIRTYRATE_MODE_DIRTY_RING = 1 << 1,      /* dirty-ring mode */
} virDomainDirtyRateCalcFlags;

int virDomainStartDirtyRateCalc(virDomainPtr domain,
                                int seconds,
                                unsigned int flags);

#endif /* LIBVIRT_DOMAIN_H */
