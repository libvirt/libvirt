/*
 * qemu_domain.h: QEMU domain private state
 *
 * Copyright (C) 2006-2014 Red Hat, Inc.
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
# include "domain_conf.h"
# include "snapshot_conf.h"
# include "qemu_monitor.h"
# include "qemu_agent.h"
# include "qemu_conf.h"
# include "qemu_capabilities.h"
# include "virchrdev.h"

# define QEMU_EXPECTED_VIRT_TYPES      \
    ((1 << VIR_DOMAIN_VIRT_QEMU) |     \
     (1 << VIR_DOMAIN_VIRT_KQEMU) |    \
     (1 << VIR_DOMAIN_VIRT_KVM) |      \
     (1 << VIR_DOMAIN_VIRT_XEN))

# define QEMU_DOMAIN_FORMAT_LIVE_FLAGS      \
    (VIR_DOMAIN_XML_SECURE |                \
     VIR_DOMAIN_XML_UPDATE_CPU)

# if ULONG_MAX == 4294967295
/* Qemu has a 64-bit limit, but we are limited by our historical choice of
 * representing bandwidth in a long instead of a 64-bit int.  */
#  define QEMU_DOMAIN_MIG_BANDWIDTH_MAX ULONG_MAX
# else
#  define QEMU_DOMAIN_MIG_BANDWIDTH_MAX (INT64_MAX / (1024 * 1024))
# endif

# define JOB_MASK(job)                  (1 << (job - 1))
# define DEFAULT_JOB_MASK               \
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
enum qemuDomainJob {
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
};
VIR_ENUM_DECL(qemuDomainJob)

/* Async job consists of a series of jobs that may change state. Independent
 * jobs that do not change state (and possibly others if explicitly allowed by
 * current async job) are allowed to be run even if async job is active.
 */
enum qemuDomainAsyncJob {
    QEMU_ASYNC_JOB_NONE = 0,
    QEMU_ASYNC_JOB_MIGRATION_OUT,
    QEMU_ASYNC_JOB_MIGRATION_IN,
    QEMU_ASYNC_JOB_SAVE,
    QEMU_ASYNC_JOB_DUMP,
    QEMU_ASYNC_JOB_SNAPSHOT,

    QEMU_ASYNC_JOB_LAST
};
VIR_ENUM_DECL(qemuDomainAsyncJob)

struct qemuDomainJobObj {
    virCond cond;                       /* Use to coordinate jobs */
    enum qemuDomainJob active;          /* Currently running job */
    unsigned long long owner;           /* Thread id which set current job */

    virCond asyncCond;                  /* Use to coordinate with async jobs */
    enum qemuDomainAsyncJob asyncJob;   /* Currently active async job */
    unsigned long long asyncOwner;      /* Thread which set current async job */
    int phase;                          /* Job phase (mainly for migrations) */
    unsigned long long mask;            /* Jobs allowed during async job */
    unsigned long long start;           /* When the async job started */
    bool dump_memory_only;              /* use dump-guest-memory to do dump */
    qemuMonitorMigrationStatus status;  /* Raw async job progress data */
    virDomainJobInfo info;              /* Processed async job progress data */
    bool asyncAbort;                    /* abort of async job requested */
};

typedef struct _qemuDomainPCIAddressSet qemuDomainPCIAddressSet;
typedef qemuDomainPCIAddressSet *qemuDomainPCIAddressSetPtr;

typedef void (*qemuDomainCleanupCallback)(virQEMUDriverPtr driver,
                                          virDomainObjPtr vm);
typedef struct _qemuDomainCCWAddressSet qemuDomainCCWAddressSet;
typedef qemuDomainCCWAddressSet *qemuDomainCCWAddressSetPtr;

typedef struct _qemuDomainObjPrivate qemuDomainObjPrivate;
typedef qemuDomainObjPrivate *qemuDomainObjPrivatePtr;
struct _qemuDomainObjPrivate {
    struct qemuDomainJobObj job;

    qemuMonitorPtr mon;
    virDomainChrSourceDefPtr monConfig;
    bool monJSON;
    bool monError;
    unsigned long long monStart;

    qemuAgentPtr agent;
    bool agentError;
    unsigned long long agentStart;

    bool gotShutdown;
    bool beingDestroyed;
    char *pidfile;

    int nvcpupids;
    int *vcpupids;

    qemuDomainPCIAddressSetPtr pciaddrs;
    qemuDomainCCWAddressSetPtr ccwaddrs;
    int persistentAddrs;

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

    virCond unplugFinished; /* signals that unpluggingDevice was unplugged */
    const char *unpluggingDevice; /* alias of the device that is being unplugged */
    char **qemuDevices; /* NULL-terminated list of devices aliases known to QEMU */

    bool hookRun;  /* true if there was a hook run over this domain */
};

typedef enum {
    QEMU_PROCESS_EVENT_WATCHDOG = 0,
    QEMU_PROCESS_EVENT_GUESTPANIC,

    QEMU_PROCESS_EVENT_LAST
} qemuProcessEventType;

struct qemuProcessEvent {
    virDomainObjPtr vm;
    qemuProcessEventType eventType;
    int action;
};

const char *qemuDomainAsyncJobPhaseToString(enum qemuDomainAsyncJob job,
                                            int phase);
int qemuDomainAsyncJobPhaseFromString(enum qemuDomainAsyncJob job,
                                      const char *phase);

void qemuDomainEventFlush(int timer, void *opaque);

void qemuDomainEventQueue(virQEMUDriverPtr driver,
                          virObjectEventPtr event);

int qemuDomainObjBeginJob(virQEMUDriverPtr driver,
                          virDomainObjPtr obj,
                          enum qemuDomainJob job)
    ATTRIBUTE_RETURN_CHECK;
int qemuDomainObjBeginAsyncJob(virQEMUDriverPtr driver,
                               virDomainObjPtr obj,
                               enum qemuDomainAsyncJob asyncJob)
    ATTRIBUTE_RETURN_CHECK;
int qemuDomainObjBeginNestedJob(virQEMUDriverPtr driver,
                                virDomainObjPtr obj,
                                enum qemuDomainAsyncJob asyncJob)
    ATTRIBUTE_RETURN_CHECK;

bool qemuDomainObjEndJob(virQEMUDriverPtr driver,
                         virDomainObjPtr obj)
    ATTRIBUTE_RETURN_CHECK;
bool qemuDomainObjEndAsyncJob(virQEMUDriverPtr driver,
                              virDomainObjPtr obj)
    ATTRIBUTE_RETURN_CHECK;
void qemuDomainObjAbortAsyncJob(virDomainObjPtr obj);
void qemuDomainObjSetJobPhase(virQEMUDriverPtr driver,
                              virDomainObjPtr obj,
                              int phase);
void qemuDomainObjSetAsyncJobMask(virDomainObjPtr obj,
                                  unsigned long long allowedJobs);
void qemuDomainObjRestoreJob(virDomainObjPtr obj,
                             struct qemuDomainJobObj *job);
void qemuDomainObjTransferJob(virDomainObjPtr obj);
void qemuDomainObjDiscardAsyncJob(virQEMUDriverPtr driver,
                                  virDomainObjPtr obj);
void qemuDomainObjReleaseAsyncJob(virDomainObjPtr obj);

void qemuDomainObjEnterMonitor(virQEMUDriverPtr driver,
                               virDomainObjPtr obj)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);
void qemuDomainObjExitMonitor(virQEMUDriverPtr driver,
                              virDomainObjPtr obj)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);
int qemuDomainObjEnterMonitorAsync(virQEMUDriverPtr driver,
                                   virDomainObjPtr obj,
                                   enum qemuDomainAsyncJob asyncJob)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;


void qemuDomainObjEnterAgent(virDomainObjPtr obj)
    ATTRIBUTE_NONNULL(1);
void qemuDomainObjExitAgent(virDomainObjPtr obj)
    ATTRIBUTE_NONNULL(1);


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
                              bool inactive,
                              bool compatible);

void qemuDomainObjTaint(virQEMUDriverPtr driver,
                        virDomainObjPtr obj,
                        enum virDomainTaintFlags taint,
                        int logFD);

void qemuDomainObjCheckTaint(virQEMUDriverPtr driver,
                             virDomainObjPtr obj,
                             int logFD);
void qemuDomainObjCheckDiskTaint(virQEMUDriverPtr driver,
                                 virDomainObjPtr obj,
                                 virDomainDiskDefPtr disk,
                                 int logFD);
void qemuDomainObjCheckNetTaint(virQEMUDriverPtr driver,
                                virDomainObjPtr obj,
                                virDomainNetDefPtr net,
                                int logFD);


int qemuDomainCreateLog(virQEMUDriverPtr driver, virDomainObjPtr vm, bool append);
int qemuDomainOpenLog(virQEMUDriverPtr driver, virDomainObjPtr vm, off_t pos);
int qemuDomainAppendLog(virQEMUDriverPtr driver,
                        virDomainObjPtr vm,
                        int logFD,
                        const char *fmt, ...) ATTRIBUTE_FMT_PRINTF(4, 5);

const char *qemuFindQemuImgBinary(virQEMUDriverPtr driver);

int qemuDomainSnapshotWriteMetadata(virDomainObjPtr vm,
                                    virDomainSnapshotObjPtr snapshot,
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

void qemuDomainSnapshotDiscardAll(void *payload,
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
                          enum qemuDomainJob job);

int qemuDomainCheckDiskPresence(virQEMUDriverPtr driver,
                                virDomainObjPtr vm,
                                bool start_with_state);

int qemuDiskChainCheckBroken(virDomainDiskDefPtr disk);

int qemuDomainDetermineDiskChain(virQEMUDriverPtr driver,
                                 virDomainObjPtr vm,
                                 virDomainDiskDefPtr disk,
                                 bool force);

int qemuDomainCleanupAdd(virDomainObjPtr vm,
                         qemuDomainCleanupCallback cb);
void qemuDomainCleanupRemove(virDomainObjPtr vm,
                             qemuDomainCleanupCallback cb);
void qemuDomainCleanupRun(virQEMUDriverPtr driver,
                          virDomainObjPtr vm);

extern virDomainXMLPrivateDataCallbacks virQEMUDriverPrivateDataCallbacks;
extern virDomainXMLNamespace virQEMUDriverDomainXMLNamespace;
extern virDomainDefParserConfig virQEMUDriverDomainDefParserConfig;

int qemuDomainUpdateDeviceList(virQEMUDriverPtr driver,
                               virDomainObjPtr vm);

bool qemuDomainDefCheckABIStability(virQEMUDriverPtr driver,
                                    virDomainDefPtr src,
                                    virDomainDefPtr dst);

bool qemuDomainAgentAvailable(qemuDomainObjPrivatePtr priv,
                              bool reportError);

#endif /* __QEMU_DOMAIN_H__ */
