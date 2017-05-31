/*
 * qemu_domain.h: QEMU domain private state
 *
 * Copyright (C) 2006-2016 Red Hat, Inc.
 * Copyright (C) 2006 Daniel P. Berrange
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
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef __QEMU_DOMAIN_H__
# define __QEMU_DOMAIN_H__

# include "virthread.h"
# include "vircgroup.h"
# include "virperf.h"
# include "domain_addr.h"
# include "domain_conf.h"
# include "snapshot_conf.h"
# include "qemu_monitor.h"
# include "qemu_agent.h"
# include "qemu_conf.h"
# include "qemu_capabilities.h"
# include "virmdev.h"
# include "virchrdev.h"
# include "virobject.h"
# include "logging/log_manager.h"

# define QEMU_DOMAIN_FORMAT_LIVE_FLAGS      \
    (VIR_DOMAIN_XML_SECURE |                \
     VIR_DOMAIN_XML_UPDATE_CPU)

# if ULONG_MAX == 4294967295
/* QEMU has a 64-bit limit, but we are limited by our historical choice of
 * representing bandwidth in a long instead of a 64-bit int.  */
#  define QEMU_DOMAIN_MIG_BANDWIDTH_MAX ULONG_MAX
# else
#  define QEMU_DOMAIN_MIG_BANDWIDTH_MAX (INT64_MAX / (1024 * 1024))
# endif

# define JOB_MASK(job)                  (1 << (job - 1))
# define QEMU_JOB_DEFAULT_MASK          \
    (JOB_MASK(QEMU_JOB_QUERY) |         \
     JOB_MASK(QEMU_JOB_DESTROY) |       \
     JOB_MASK(QEMU_JOB_ABORT))

/* Jobs which have to be tracked in domain state XML. */
# define QEMU_DOMAIN_TRACK_JOBS         \
    (JOB_MASK(QEMU_JOB_DESTROY) |       \
     JOB_MASK(QEMU_JOB_ASYNC))

/* Only 1 job is allowed at any time
 * A job includes *all* monitor commands, even those just querying
 * information, not merely actions */
typedef enum {
    QEMU_JOB_NONE = 0,  /* Always set to 0 for easy if (jobActive) conditions */
    QEMU_JOB_QUERY,         /* Doesn't change any state */
    QEMU_JOB_DESTROY,       /* Destroys the domain (cannot be masked out) */
    QEMU_JOB_SUSPEND,       /* Suspends (stops vCPUs) the domain */
    QEMU_JOB_MODIFY,        /* May change state */
    QEMU_JOB_ABORT,         /* Abort current async job */
    QEMU_JOB_MIGRATION_OP,  /* Operation influencing outgoing migration */

    /* The following two items must always be the last items before JOB_LAST */
    QEMU_JOB_ASYNC,         /* Asynchronous job */
    QEMU_JOB_ASYNC_NESTED,  /* Normal job within an async job */

    QEMU_JOB_LAST
} qemuDomainJob;
VIR_ENUM_DECL(qemuDomainJob)

/* Async job consists of a series of jobs that may change state. Independent
 * jobs that do not change state (and possibly others if explicitly allowed by
 * current async job) are allowed to be run even if async job is active.
 */
typedef enum {
    QEMU_ASYNC_JOB_NONE = 0,
    QEMU_ASYNC_JOB_MIGRATION_OUT,
    QEMU_ASYNC_JOB_MIGRATION_IN,
    QEMU_ASYNC_JOB_SAVE,
    QEMU_ASYNC_JOB_DUMP,
    QEMU_ASYNC_JOB_SNAPSHOT,
    QEMU_ASYNC_JOB_START,

    QEMU_ASYNC_JOB_LAST
} qemuDomainAsyncJob;
VIR_ENUM_DECL(qemuDomainAsyncJob)

typedef struct _qemuDomainJobInfo qemuDomainJobInfo;
typedef qemuDomainJobInfo *qemuDomainJobInfoPtr;
struct _qemuDomainJobInfo {
    virDomainJobType type;
    virDomainJobOperation operation;
    unsigned long long started; /* When the async job started */
    unsigned long long stopped; /* When the domain's CPUs were stopped */
    unsigned long long sent; /* When the source sent status info to the
                                destination (only for migrations). */
    unsigned long long received; /* When the destination host received status
                                    info from the source (migrations only). */
    /* Computed values */
    unsigned long long timeElapsed;
    unsigned long long timeRemaining;
    long long timeDelta; /* delta = received - sent, i.e., the difference
                            between the source and the destination time plus
                            the time between the end of Perform phase on the
                            source and the beginning of Finish phase on the
                            destination. */
    bool timeDeltaSet;
    /* Raw values from QEMU */
    qemuMonitorMigrationStats stats;
};

struct qemuDomainJobObj {
    virCond cond;                       /* Use to coordinate jobs */
    qemuDomainJob active;               /* Currently running job */
    unsigned long long owner;           /* Thread id which set current job */
    const char *ownerAPI;               /* The API which owns the job */
    unsigned long long started;         /* When the current job started */

    virCond asyncCond;                  /* Use to coordinate with async jobs */
    qemuDomainAsyncJob asyncJob;        /* Currently active async job */
    unsigned long long asyncOwner;      /* Thread which set current async job */
    const char *asyncOwnerAPI;          /* The API which owns the async job */
    unsigned long long asyncStarted;    /* When the current async job started */
    int phase;                          /* Job phase (mainly for migrations) */
    unsigned long long mask;            /* Jobs allowed during async job */
    bool dump_memory_only;              /* use dump-guest-memory to do dump */
    qemuDomainJobInfoPtr current;       /* async job progress data */
    qemuDomainJobInfoPtr completed;     /* statistics data of a recently completed job */
    bool abortJob;                      /* abort of the job requested */
    bool spiceMigration;                /* we asked for spice migration and we
                                         * should wait for it to finish */
    bool spiceMigrated;                 /* spice migration completed */
    bool postcopyEnabled;               /* post-copy migration was enabled */
};

typedef void (*qemuDomainCleanupCallback)(virQEMUDriverPtr driver,
                                          virDomainObjPtr vm);

# define QEMU_DOMAIN_MASTER_KEY_LEN 32  /* 32 bytes for 256 bit random key */


/* helper data types for async device unplug */
typedef enum {
    QEMU_DOMAIN_UNPLUGGING_DEVICE_STATUS_NONE = 0,
    QEMU_DOMAIN_UNPLUGGING_DEVICE_STATUS_OK,
    QEMU_DOMAIN_UNPLUGGING_DEVICE_STATUS_GUEST_REJECTED,
} qemuDomainUnpluggingDeviceStatus;

typedef struct _qemuDomainUnpluggingDevice qemuDomainUnpluggingDevice;
typedef qemuDomainUnpluggingDevice *qemuDomainUnpluggingDevicePtr;
struct _qemuDomainUnpluggingDevice {
    const char *alias;
    qemuDomainUnpluggingDeviceStatus status;
};


typedef enum {
    QEMU_DOMAIN_NS_MOUNT = 0,
    QEMU_DOMAIN_NS_LAST
} qemuDomainNamespace;
VIR_ENUM_DECL(qemuDomainNamespace)

bool qemuDomainNamespaceEnabled(virDomainObjPtr vm,
                                qemuDomainNamespace ns);

/* Type of domain secret */
typedef enum {
    VIR_DOMAIN_SECRET_INFO_TYPE_PLAIN = 0,
    VIR_DOMAIN_SECRET_INFO_TYPE_AES,  /* utilize GNUTLS_CIPHER_AES_256_CBC */

    VIR_DOMAIN_SECRET_INFO_TYPE_LAST
} qemuDomainSecretInfoType;

typedef struct _qemuDomainSecretPlain qemuDomainSecretPlain;
typedef struct _qemuDomainSecretPlain *qemuDomainSecretPlainPtr;
struct _qemuDomainSecretPlain {
    char *username;
    uint8_t *secret;
    size_t secretlen;
};

# define QEMU_DOMAIN_AES_IV_LEN 16   /* 16 bytes for 128 bit random */
                                     /*    initialization vector */
typedef struct _qemuDomainSecretAES qemuDomainSecretAES;
typedef struct _qemuDomainSecretAES *qemuDomainSecretAESPtr;
struct _qemuDomainSecretAES {
    char *username;
    char *alias;      /* generated alias for secret */
    char *iv;         /* base64 encoded initialization vector */
    char *ciphertext; /* encoded/encrypted secret */
};

typedef struct _qemuDomainSecretInfo qemuDomainSecretInfo;
typedef qemuDomainSecretInfo *qemuDomainSecretInfoPtr;
struct _qemuDomainSecretInfo {
    qemuDomainSecretInfoType type;
    union {
        qemuDomainSecretPlain plain;
        qemuDomainSecretAES aes;
    } s;
};

typedef struct _qemuDomainObjPrivate qemuDomainObjPrivate;
typedef qemuDomainObjPrivate *qemuDomainObjPrivatePtr;
struct _qemuDomainObjPrivate {
    struct qemuDomainJobObj job;

    virBitmapPtr namespaces;

    qemuMonitorPtr mon;
    virDomainChrSourceDefPtr monConfig;
    bool monJSON;
    bool monError;
    unsigned long long monStart;

    qemuAgentPtr agent;
    bool agentError;

    bool gotShutdown;
    bool beingDestroyed;
    char *pidfile;

    virDomainPCIAddressSetPtr pciaddrs;
    virDomainUSBAddressSetPtr usbaddrs;

    virQEMUCapsPtr qemuCaps;
    char *lockState;

    bool fakeReboot;

    int jobs_queued;

    unsigned long migMaxBandwidth;
    char *origname;
    int nbdPort; /* Port used for migration with NBD */
    unsigned short migrationPort;
    int preMigrationState;

    virChrdevsPtr devs;

    qemuDomainCleanupCallback *cleanupCallbacks;
    size_t ncleanupCallbacks;
    size_t ncleanupCallbacks_max;

    virCgroupPtr cgroup;

    virPerfPtr perf;

    qemuDomainUnpluggingDevice unplug;

    char **qemuDevices; /* NULL-terminated list of devices aliases known to QEMU */

    bool hookRun;  /* true if there was a hook run over this domain */

    /* Bitmaps below hold data from the auto NUMA feature */
    virBitmapPtr autoNodeset;
    virBitmapPtr autoCpuset;

    bool signalIOError; /* true if the domain condition should be signalled on
                           I/O error */
    bool signalStop; /* true if the domain condition should be signalled on
                        QMP STOP event */
    char *machineName;
    char *libDir;            /* base path for per-domain files */
    char *channelTargetDir;  /* base path for per-domain channel targets */

    /* random masterKey and length for encryption (not to be saved in our */
    /* private XML) - need to restore at process reconnect */
    uint8_t *masterKey;
    size_t masterKeyLen;

    /* note whether memory device alias does not correspond to slot number */
    bool memAliasOrderMismatch;

    /* for migrations using TLS with a secret (not to be saved in our */
    /* private XML). */
    qemuDomainSecretInfoPtr migSecinfo;

    /* Used when fetching/storing the current 'tls-creds' migration setting */
    /* (not to be saved in our private XML). */
    char *migTLSAlias;

    /* CPU def used to start the domain when it differs from the one actually
     * provided by QEMU. */
    virCPUDefPtr origCPU;
};

# define QEMU_DOMAIN_PRIVATE(vm)	\
    ((qemuDomainObjPrivatePtr) (vm)->privateData)

# define QEMU_DOMAIN_DISK_PRIVATE(disk)	\
    ((qemuDomainDiskPrivatePtr) (disk)->privateData)

typedef struct _qemuDomainDiskPrivate qemuDomainDiskPrivate;
typedef qemuDomainDiskPrivate *qemuDomainDiskPrivatePtr;
struct _qemuDomainDiskPrivate {
    virObject parent;

    /* ideally we want a smarter way to interlock block jobs on single qemu disk
     * in the future, but for now we just disallow any concurrent job on a
     * single disk */
    bool blockjob;

    /* for some synchronous block jobs, we need to notify the owner */
    int blockJobType;   /* type of the block job from the event */
    int blockJobStatus; /* status of the finished block job */
    bool blockJobSync; /* the block job needs synchronized termination */

    bool migrating; /* the disk is being migrated */

    /* for storage devices using auth/secret
     * NB: *not* to be written to qemu domain object XML */
    qemuDomainSecretInfoPtr secinfo;

    /* for storage devices using encryption/secret
     * Can have both <auth> and <encryption> for some disks
     * NB:*not* to be written to qemu domain object XML */
    qemuDomainSecretInfoPtr encinfo;

    /* information about the device */
    bool tray; /* device has tray */
    bool removable; /* device media can be removed/changed */
};

# define QEMU_DOMAIN_HOSTDEV_PRIVATE(hostdev)	\
    ((qemuDomainHostdevPrivatePtr) (hostdev)->privateData)


typedef struct _qemuDomainVcpuPrivate qemuDomainVcpuPrivate;
typedef qemuDomainVcpuPrivate *qemuDomainVcpuPrivatePtr;
struct _qemuDomainVcpuPrivate {
    virObject parent;

    pid_t tid; /* vcpu thread id */
    int enable_id; /* order in which the vcpus were enabled in qemu */
    int qemu_id; /* ID reported by qemu as 'CPU' in query-cpus */
    char *alias;
    bool halted;

    /* information for hotpluggable cpus */
    char *type;
    int socket_id;
    int core_id;
    int thread_id;
    int vcpus;
};

# define QEMU_DOMAIN_VCPU_PRIVATE(vcpu)    \
    ((qemuDomainVcpuPrivatePtr) (vcpu)->privateData)


struct qemuDomainDiskInfo {
    bool removable;
    bool locked;
    bool tray;
    bool tray_open;
    bool empty;
    int io_status;
    char *nodename;
};

typedef struct _qemuDomainHostdevPrivate qemuDomainHostdevPrivate;
typedef qemuDomainHostdevPrivate *qemuDomainHostdevPrivatePtr;
struct _qemuDomainHostdevPrivate {
    virObject parent;

    /* for hostdev storage devices using auth/secret
     * NB: *not* to be written to qemu domain object XML */
    qemuDomainSecretInfoPtr secinfo;
};

# define QEMU_DOMAIN_CHR_SOURCE_PRIVATE(dev)	\
    ((qemuDomainChrSourcePrivatePtr) (dev)->privateData)

typedef struct _qemuDomainChrSourcePrivate qemuDomainChrSourcePrivate;
typedef qemuDomainChrSourcePrivate *qemuDomainChrSourcePrivatePtr;
struct _qemuDomainChrSourcePrivate {
    virObject parent;

    /* for char devices using secret
     * NB: *not* to be written to qemu domain object XML */
    qemuDomainSecretInfoPtr secinfo;
};


typedef enum {
    QEMU_PROCESS_EVENT_WATCHDOG = 0,
    QEMU_PROCESS_EVENT_GUESTPANIC,
    QEMU_PROCESS_EVENT_DEVICE_DELETED,
    QEMU_PROCESS_EVENT_NIC_RX_FILTER_CHANGED,
    QEMU_PROCESS_EVENT_SERIAL_CHANGED,
    QEMU_PROCESS_EVENT_BLOCK_JOB,
    QEMU_PROCESS_EVENT_MONITOR_EOF,

    QEMU_PROCESS_EVENT_LAST
} qemuProcessEventType;

struct qemuProcessEvent {
    virDomainObjPtr vm;
    qemuProcessEventType eventType;
    int action;
    int status;
    void *data;
};

typedef struct _qemuDomainLogContext qemuDomainLogContext;
typedef qemuDomainLogContext *qemuDomainLogContextPtr;

typedef struct _qemuDomainSaveCookie qemuDomainSaveCookie;
typedef qemuDomainSaveCookie *qemuDomainSaveCookiePtr;
struct _qemuDomainSaveCookie {
    virObject parent;

    virCPUDefPtr cpu;
};

qemuDomainSaveCookiePtr qemuDomainSaveCookieNew(virDomainObjPtr vm);

const char *qemuDomainAsyncJobPhaseToString(qemuDomainAsyncJob job,
                                            int phase);
int qemuDomainAsyncJobPhaseFromString(qemuDomainAsyncJob job,
                                      const char *phase);

void qemuDomainEventFlush(int timer, void *opaque);

void qemuDomainEventQueue(virQEMUDriverPtr driver,
                          virObjectEventPtr event);
void qemuDomainEventEmitJobCompleted(virQEMUDriverPtr driver,
                                     virDomainObjPtr vm);

int qemuDomainObjBeginJob(virQEMUDriverPtr driver,
                          virDomainObjPtr obj,
                          qemuDomainJob job)
    ATTRIBUTE_RETURN_CHECK;
int qemuDomainObjBeginAsyncJob(virQEMUDriverPtr driver,
                               virDomainObjPtr obj,
                               qemuDomainAsyncJob asyncJob,
                               virDomainJobOperation operation)
    ATTRIBUTE_RETURN_CHECK;
int qemuDomainObjBeginNestedJob(virQEMUDriverPtr driver,
                                virDomainObjPtr obj,
                                qemuDomainAsyncJob asyncJob)
    ATTRIBUTE_RETURN_CHECK;

void qemuDomainObjEndJob(virQEMUDriverPtr driver,
                         virDomainObjPtr obj);
void qemuDomainObjEndAsyncJob(virQEMUDriverPtr driver,
                              virDomainObjPtr obj);
void qemuDomainObjAbortAsyncJob(virDomainObjPtr obj);
void qemuDomainObjSetJobPhase(virQEMUDriverPtr driver,
                              virDomainObjPtr obj,
                              int phase);
void qemuDomainObjSetAsyncJobMask(virDomainObjPtr obj,
                                  unsigned long long allowedJobs);
void qemuDomainObjRestoreJob(virDomainObjPtr obj,
                             struct qemuDomainJobObj *job);
void qemuDomainObjDiscardAsyncJob(virQEMUDriverPtr driver,
                                  virDomainObjPtr obj);
void qemuDomainObjReleaseAsyncJob(virDomainObjPtr obj);

qemuMonitorPtr qemuDomainGetMonitor(virDomainObjPtr vm)
    ATTRIBUTE_NONNULL(1);
void qemuDomainObjEnterMonitor(virQEMUDriverPtr driver,
                               virDomainObjPtr obj)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);
int qemuDomainObjExitMonitor(virQEMUDriverPtr driver,
                             virDomainObjPtr obj)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2)
    ATTRIBUTE_RETURN_CHECK;
int qemuDomainObjEnterMonitorAsync(virQEMUDriverPtr driver,
                                   virDomainObjPtr obj,
                                   qemuDomainAsyncJob asyncJob)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;


qemuAgentPtr qemuDomainObjEnterAgent(virDomainObjPtr obj)
    ATTRIBUTE_NONNULL(1);
void qemuDomainObjExitAgent(virDomainObjPtr obj, qemuAgentPtr agent)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);


void qemuDomainObjEnterRemote(virDomainObjPtr obj)
    ATTRIBUTE_NONNULL(1);
void qemuDomainObjExitRemote(virDomainObjPtr obj)
    ATTRIBUTE_NONNULL(1);

virDomainDefPtr qemuDomainDefCopy(virQEMUDriverPtr driver,
                                  virDomainDefPtr src,
                                  unsigned int flags);

int qemuDomainDefFormatBuf(virQEMUDriverPtr driver,
                           virDomainDefPtr vm,
                           unsigned int flags,
                           virBuffer *buf);

char *qemuDomainDefFormatXML(virQEMUDriverPtr driver,
                             virDomainDefPtr vm,
                             unsigned int flags);

char *qemuDomainFormatXML(virQEMUDriverPtr driver,
                          virDomainObjPtr vm,
                          unsigned int flags);

char *qemuDomainDefFormatLive(virQEMUDriverPtr driver,
                              virDomainDefPtr def,
                              virCPUDefPtr origCPU,
                              bool inactive,
                              bool compatible);

void qemuDomainObjTaint(virQEMUDriverPtr driver,
                        virDomainObjPtr obj,
                        virDomainTaintFlags taint,
                        qemuDomainLogContextPtr logCtxt);

void qemuDomainObjCheckTaint(virQEMUDriverPtr driver,
                             virDomainObjPtr obj,
                             qemuDomainLogContextPtr logCtxt);
void qemuDomainObjCheckDiskTaint(virQEMUDriverPtr driver,
                                 virDomainObjPtr obj,
                                 virDomainDiskDefPtr disk,
                                 qemuDomainLogContextPtr logCtxt);
void qemuDomainObjCheckHostdevTaint(virQEMUDriverPtr driver,
                                    virDomainObjPtr obj,
                                    virDomainHostdevDefPtr disk,
                                    qemuDomainLogContextPtr logCtxt);
void qemuDomainObjCheckNetTaint(virQEMUDriverPtr driver,
                                virDomainObjPtr obj,
                                virDomainNetDefPtr net,
                                qemuDomainLogContextPtr logCtxt);

typedef enum {
    QEMU_DOMAIN_LOG_CONTEXT_MODE_START,
    QEMU_DOMAIN_LOG_CONTEXT_MODE_ATTACH,
    QEMU_DOMAIN_LOG_CONTEXT_MODE_STOP,
} qemuDomainLogContextMode;

qemuDomainLogContextPtr qemuDomainLogContextNew(virQEMUDriverPtr driver,
                                                virDomainObjPtr vm,
                                                qemuDomainLogContextMode mode);
int qemuDomainLogContextWrite(qemuDomainLogContextPtr ctxt,
                              const char *fmt, ...) ATTRIBUTE_FMT_PRINTF(2, 3);
ssize_t qemuDomainLogContextRead(qemuDomainLogContextPtr ctxt,
                                 char **msg);
int qemuDomainLogContextGetWriteFD(qemuDomainLogContextPtr ctxt);
void qemuDomainLogContextMarkPosition(qemuDomainLogContextPtr ctxt);

virLogManagerPtr qemuDomainLogContextGetManager(qemuDomainLogContextPtr ctxt);

int qemuDomainLogAppendMessage(virQEMUDriverPtr driver,
                               virDomainObjPtr vm,
                               const char *fmt,
                               ...) ATTRIBUTE_FMT_PRINTF(3, 4);

const char *qemuFindQemuImgBinary(virQEMUDriverPtr driver);

int qemuDomainSnapshotWriteMetadata(virDomainObjPtr vm,
                                    virDomainSnapshotObjPtr snapshot,
                                    virCapsPtr caps,
                                    virDomainXMLOptionPtr xmlopt,
                                    char *snapshotDir);

int qemuDomainSnapshotForEachQcow2(virQEMUDriverPtr driver,
                                   virDomainObjPtr vm,
                                   virDomainSnapshotObjPtr snap,
                                   const char *op,
                                   bool try_all);

int qemuDomainSnapshotDiscard(virQEMUDriverPtr driver,
                              virDomainObjPtr vm,
                              virDomainSnapshotObjPtr snap,
                              bool update_current,
                              bool metadata_only);

typedef struct _virQEMUSnapRemove virQEMUSnapRemove;
typedef virQEMUSnapRemove *virQEMUSnapRemovePtr;
struct _virQEMUSnapRemove {
    virQEMUDriverPtr driver;
    virDomainObjPtr vm;
    int err;
    bool metadata_only;
    bool current;
};

int qemuDomainSnapshotDiscardAll(void *payload,
                                 const void *name,
                                 void *data);

int qemuDomainSnapshotDiscardAllMetadata(virQEMUDriverPtr driver,
                                         virDomainObjPtr vm);

void qemuDomainRemoveInactive(virQEMUDriverPtr driver,
                              virDomainObjPtr vm);

void qemuDomainSetFakeReboot(virQEMUDriverPtr driver,
                             virDomainObjPtr vm,
                             bool value);

bool qemuDomainJobAllowed(qemuDomainObjPrivatePtr priv,
                          qemuDomainJob job);

int qemuDomainCheckDiskPresence(virConnectPtr conn,
                                virQEMUDriverPtr driver,
                                virDomainObjPtr vm,
                                unsigned int flags);

int qemuDomainDetermineDiskChain(virQEMUDriverPtr driver,
                                 virDomainObjPtr vm,
                                 virDomainDiskDefPtr disk,
                                 bool force_probe,
                                 bool report_broken);

bool qemuDomainDiskSourceDiffers(virDomainDiskDefPtr disk,
                                 virDomainDiskDefPtr origDisk);

bool qemuDomainDiskChangeSupported(virDomainDiskDefPtr disk,
                                   virDomainDiskDefPtr orig_disk);

int qemuDomainStorageFileInit(virQEMUDriverPtr driver,
                              virDomainObjPtr vm,
                              virStorageSourcePtr src);
char *qemuDomainStorageAlias(const char *device, int depth);

void qemuDomainDiskChainElementRevoke(virQEMUDriverPtr driver,
                                      virDomainObjPtr vm,
                                      virStorageSourcePtr elem);
int qemuDomainDiskChainElementPrepare(virQEMUDriverPtr driver,
                                      virDomainObjPtr vm,
                                      virStorageSourcePtr elem,
                                      bool readonly);

int qemuDomainCleanupAdd(virDomainObjPtr vm,
                         qemuDomainCleanupCallback cb);
void qemuDomainCleanupRemove(virDomainObjPtr vm,
                             qemuDomainCleanupCallback cb);
void qemuDomainCleanupRun(virQEMUDriverPtr driver,
                          virDomainObjPtr vm);

extern virDomainXMLPrivateDataCallbacks virQEMUDriverPrivateDataCallbacks;
extern virDomainXMLNamespace virQEMUDriverDomainXMLNamespace;
extern virDomainDefParserConfig virQEMUDriverDomainDefParserConfig;
extern virDomainABIStability virQEMUDriverDomainABIStability;
extern virSaveCookieCallbacks virQEMUDriverDomainSaveCookie;

int qemuDomainUpdateDeviceList(virQEMUDriverPtr driver,
                               virDomainObjPtr vm, int asyncJob);

int qemuDomainUpdateMemoryDeviceInfo(virQEMUDriverPtr driver,
                                     virDomainObjPtr vm,
                                     int asyncJob);

bool qemuDomainDefCheckABIStability(virQEMUDriverPtr driver,
                                    virDomainDefPtr src,
                                    virDomainDefPtr dst);

bool qemuDomainAgentAvailable(virDomainObjPtr vm,
                              bool reportError);

int qemuDomainJobInfoUpdateTime(qemuDomainJobInfoPtr jobInfo)
    ATTRIBUTE_NONNULL(1);
int qemuDomainJobInfoUpdateDowntime(qemuDomainJobInfoPtr jobInfo)
    ATTRIBUTE_NONNULL(1);
int qemuDomainJobInfoToInfo(qemuDomainJobInfoPtr jobInfo,
                            virDomainJobInfoPtr info)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);
int qemuDomainJobInfoToParams(qemuDomainJobInfoPtr jobInfo,
                              int *type,
                              virTypedParameterPtr *params,
                              int *nparams)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2)
    ATTRIBUTE_NONNULL(3) ATTRIBUTE_NONNULL(4);

int qemuDomainSupportsBlockJobs(virDomainObjPtr vm, bool *modern)
    ATTRIBUTE_NONNULL(1);
bool qemuDomainDiskBlockJobIsActive(virDomainDiskDefPtr disk);
bool qemuDomainHasBlockjob(virDomainObjPtr vm, bool copy_only)
    ATTRIBUTE_NONNULL(1);

int qemuDomainAlignMemorySizes(virDomainDefPtr def);
void qemuDomainMemoryDeviceAlignSize(virDomainDefPtr def,
                                     virDomainMemoryDefPtr mem);

virDomainChrDefPtr qemuFindAgentConfig(virDomainDefPtr def);

bool qemuDomainIsQ35(const virDomainDef *def);
bool qemuDomainIsI440FX(const virDomainDef *def);
bool qemuDomainHasPCIRoot(const virDomainDef *def);
bool qemuDomainHasPCIeRoot(const virDomainDef *def);
bool qemuDomainNeedsFDC(const virDomainDef *def);
bool qemuDomainIsS390CCW(const virDomainDef *def);
bool qemuDomainIsVirt(const virDomainDef *def);
bool qemuDomainIsPSeries(const virDomainDef *def);
bool qemuDomainHasBuiltinIDE(const virDomainDef *def);

bool qemuDomainMachineIsQ35(const char *machine);
bool qemuDomainMachineIsI440FX(const char *machine);
bool qemuDomainMachineNeedsFDC(const char *machine);
bool qemuDomainMachineIsS390CCW(const char *machine);
bool qemuDomainMachineIsVirt(const char *machine,
                             const virArch arch);
bool qemuDomainMachineIsPSeries(const char *machine,
                                const virArch arch);
bool qemuDomainMachineHasBuiltinIDE(const char *machine);

int qemuDomainUpdateCurrentMemorySize(virQEMUDriverPtr driver,
                                      virDomainObjPtr vm);

unsigned long long qemuDomainGetMemLockLimitBytes(virDomainDefPtr def);
int qemuDomainAdjustMaxMemLock(virDomainObjPtr vm);

int qemuDomainDefValidateMemoryHotplug(const virDomainDef *def,
                                       virQEMUCapsPtr qemuCaps,
                                       const virDomainMemoryDef *mem);

bool qemuDomainSupportsNewVcpuHotplug(virDomainObjPtr vm);
bool qemuDomainHasVcpuPids(virDomainObjPtr vm);
pid_t qemuDomainGetVcpuPid(virDomainObjPtr vm, unsigned int vcpuid);
int qemuDomainValidateVcpuInfo(virDomainObjPtr vm);
int qemuDomainRefreshVcpuInfo(virQEMUDriverPtr driver,
                              virDomainObjPtr vm,
                              int asyncJob,
                              bool state);
bool qemuDomainGetVcpuHalted(virDomainObjPtr vm, unsigned int vcpu);
int qemuDomainRefreshVcpuHalted(virQEMUDriverPtr driver,
                                virDomainObjPtr vm,
                                int asyncJob);

bool qemuDomainSupportsNicdev(virDomainDefPtr def,
                              virDomainNetDefPtr net);

bool qemuDomainSupportsNetdev(virDomainDefPtr def,
                              virQEMUCapsPtr qemuCaps,
                              virDomainNetDefPtr net);

bool qemuDomainNetSupportsMTU(virDomainNetType type);

int qemuDomainNetVLAN(virDomainNetDefPtr def);

int qemuDomainSetPrivatePaths(virQEMUDriverPtr driver,
                              virDomainObjPtr vm);

void qemuDomainClearPrivatePaths(virDomainObjPtr vm);

virDomainDiskDefPtr qemuDomainDiskByName(virDomainDefPtr def, const char *name);

char *qemuDomainGetMasterKeyFilePath(const char *libDir);

int qemuDomainMasterKeyReadFile(qemuDomainObjPrivatePtr priv);

int qemuDomainWriteMasterKeyFile(virQEMUDriverPtr driver,
                                 virDomainObjPtr vm);

int qemuDomainMasterKeyCreate(virDomainObjPtr vm);

void qemuDomainMasterKeyRemove(qemuDomainObjPrivatePtr priv);

void qemuDomainSecretInfoFree(qemuDomainSecretInfoPtr *secinfo)
    ATTRIBUTE_NONNULL(1);

void qemuDomainSecretDiskDestroy(virDomainDiskDefPtr disk)
    ATTRIBUTE_NONNULL(1);

bool qemuDomainSecretDiskCapable(virStorageSourcePtr src)
    ATTRIBUTE_NONNULL(1);

bool qemuDomainDiskHasEncryptionSecret(virStorageSourcePtr src)
    ATTRIBUTE_NONNULL(1);

qemuDomainSecretInfoPtr
qemuDomainSecretInfoTLSNew(virConnectPtr conn,
                           qemuDomainObjPrivatePtr priv,
                           const char *srcAlias,
                           const char *secretUUID);

int qemuDomainSecretDiskPrepare(virConnectPtr conn,
                                qemuDomainObjPrivatePtr priv,
                                virDomainDiskDefPtr disk)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);

void qemuDomainSecretHostdevDestroy(virDomainHostdevDefPtr disk)
    ATTRIBUTE_NONNULL(1);

int qemuDomainSecretHostdevPrepare(virConnectPtr conn,
                                   qemuDomainObjPrivatePtr priv,
                                   virDomainHostdevDefPtr hostdev)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);

void qemuDomainSecretChardevDestroy(virDomainChrSourceDefPtr dev)
    ATTRIBUTE_NONNULL(1);

int qemuDomainSecretChardevPrepare(virConnectPtr conn,
                                   virQEMUDriverConfigPtr cfg,
                                   qemuDomainObjPrivatePtr priv,
                                   const char *chrAlias,
                                   virDomainChrSourceDefPtr dev)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    ATTRIBUTE_NONNULL(4) ATTRIBUTE_NONNULL(5);

void qemuDomainSecretDestroy(virDomainObjPtr vm)
    ATTRIBUTE_NONNULL(1);

int qemuDomainSecretPrepare(virConnectPtr conn,
                            virQEMUDriverPtr driver,
                            virDomainObjPtr vm)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);

int qemuDomainDefValidateDiskLunSource(const virStorageSource *src)
    ATTRIBUTE_NONNULL(1);

int qemuDomainPrepareChannel(virDomainChrDefPtr chr,
                             const char *domainChannelTargetDir)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

void qemuDomainPrepareChardevSourceTLS(virDomainChrSourceDefPtr source,
                                       virQEMUDriverConfigPtr cfg)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

void qemuDomainPrepareChardevSource(virDomainDefPtr def,
                                    virQEMUDriverPtr driver)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int qemuDomainPrepareShmemChardev(virDomainShmemDefPtr shmem)
    ATTRIBUTE_NONNULL(1);

bool qemuDomainVcpuHotplugIsInOrder(virDomainDefPtr def)
    ATTRIBUTE_NONNULL(1);

void qemuDomainVcpuPersistOrder(virDomainDefPtr def)
    ATTRIBUTE_NONNULL(1);

int qemuDomainCheckMonitor(virQEMUDriverPtr driver,
                           virDomainObjPtr vm,
                           qemuDomainAsyncJob asyncJob);

bool qemuDomainSupportsVideoVga(virDomainVideoDefPtr video,
                                virQEMUCapsPtr qemuCaps);

int qemuDomainGetHostdevPath(virDomainDefPtr def,
                             virDomainHostdevDefPtr dev,
                             bool teardown,
                             size_t *npaths,
                             char ***path,
                             int **perms);

int qemuDomainBuildNamespace(virQEMUDriverConfigPtr cfg,
                             virSecurityManagerPtr mgr,
                             virDomainObjPtr vm);

int qemuDomainCreateNamespace(virQEMUDriverPtr driver,
                              virDomainObjPtr vm);

void qemuDomainDestroyNamespace(virQEMUDriverPtr driver,
                                virDomainObjPtr vm);

bool qemuDomainNamespaceAvailable(qemuDomainNamespace ns);

int qemuDomainNamespaceSetupDisk(virQEMUDriverPtr driver,
                                 virDomainObjPtr vm,
                                 virStorageSourcePtr src);

int qemuDomainNamespaceTeardownDisk(virQEMUDriverPtr driver,
                                    virDomainObjPtr vm,
                                    virStorageSourcePtr src);

int qemuDomainNamespaceSetupHostdev(virQEMUDriverPtr driver,
                                    virDomainObjPtr vm,
                                    virDomainHostdevDefPtr hostdev);

int qemuDomainNamespaceTeardownHostdev(virQEMUDriverPtr driver,
                                       virDomainObjPtr vm,
                                       virDomainHostdevDefPtr hostdev);

int qemuDomainNamespaceSetupMemory(virQEMUDriverPtr driver,
                                   virDomainObjPtr vm,
                                   virDomainMemoryDefPtr memory);

int qemuDomainNamespaceTeardownMemory(virQEMUDriverPtr driver,
                                      virDomainObjPtr vm,
                                      virDomainMemoryDefPtr memory);

int qemuDomainNamespaceSetupChardev(virQEMUDriverPtr driver,
                                    virDomainObjPtr vm,
                                    virDomainChrDefPtr chr);

int qemuDomainNamespaceTeardownChardev(virQEMUDriverPtr driver,
                                       virDomainObjPtr vm,
                                       virDomainChrDefPtr chr);

int qemuDomainNamespaceSetupRNG(virQEMUDriverPtr driver,
                                virDomainObjPtr vm,
                                virDomainRNGDefPtr rng);

int qemuDomainNamespaceTeardownRNG(virQEMUDriverPtr driver,
                                   virDomainObjPtr vm,
                                   virDomainRNGDefPtr rng);

virDomainDiskDefPtr qemuDomainDiskLookupByNodename(virDomainDefPtr def,
                                                   const char *nodename,
                                                   virStorageSourcePtr *src,
                                                   unsigned int *idx);

char *qemuDomainDiskBackingStoreGetName(virDomainDiskDefPtr disk,
                                        virStorageSourcePtr src,
                                        unsigned int idx);

virStorageSourcePtr qemuDomainGetStorageSourceByDevstr(const char *devstr,
                                                       virDomainDefPtr def);

int
qemuDomainUpdateCPU(virDomainObjPtr vm,
                    virCPUDefPtr cpu,
                    virCPUDefPtr *origCPU);

#endif /* __QEMU_DOMAIN_H__ */
