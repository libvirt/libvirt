/*
 * qemu_domain.h: QEMU domain private state
 *
 * Copyright (C) 2006-2011 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef __QEMU_DOMAIN_H__
# define __QEMU_DOMAIN_H__

# include "threads.h"
# include "domain_conf.h"
# include "qemu_monitor.h"
# include "qemu_agent.h"
# include "qemu_conf.h"
# include "bitmap.h"
# include "virconsole.h"

# define QEMU_EXPECTED_VIRT_TYPES      \
    ((1 << VIR_DOMAIN_VIRT_QEMU) |     \
     (1 << VIR_DOMAIN_VIRT_KQEMU) |    \
     (1 << VIR_DOMAIN_VIRT_KVM) |      \
     (1 << VIR_DOMAIN_VIRT_XEN))

# define QEMU_DOMAIN_DEFAULT_MIG_BANDWIDTH_MAX 32
# if ULONG_MAX == 4294967295
/* Qemu has a 64-bit limit, but we are limited by our historical choice of
 * representing bandwidth in a long instead of a 64-bit int.  */
#  define QEMU_DOMAIN_FILE_MIG_BANDWIDTH_MAX    ULONG_MAX
# else
#  define QEMU_DOMAIN_FILE_MIG_BANDWIDTH_MAX    (INT64_MAX / (1024 * 1024))
# endif

# define JOB_MASK(job)                  (1 << (job - 1))
# define DEFAULT_JOB_MASK               \
    (JOB_MASK(QEMU_JOB_QUERY) |         \
     JOB_MASK(QEMU_JOB_DESTROY) |       \
     JOB_MASK(QEMU_JOB_ABORT))

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

    QEMU_ASYNC_JOB_LAST
};
VIR_ENUM_DECL(qemuDomainAsyncJob)

struct qemuDomainJobObj {
    virCond cond;                       /* Use to coordinate jobs */
    enum qemuDomainJob active;          /* Currently running job */

    virCond asyncCond;                  /* Use to coordinate with async jobs */
    enum qemuDomainAsyncJob asyncJob;   /* Currently active async job */
    int phase;                          /* Job phase (mainly for migrations) */
    unsigned long long mask;            /* Jobs allowed during async job */
    unsigned long long start;           /* When the async job started */
    virDomainJobInfo info;              /* Async job progress data */
};

typedef struct _qemuDomainPCIAddressSet qemuDomainPCIAddressSet;
typedef qemuDomainPCIAddressSet *qemuDomainPCIAddressSetPtr;

typedef void (*qemuDomainCleanupCallback)(struct qemud_driver *driver,
                                          virDomainObjPtr vm);

typedef struct _qemuDomainObjPrivate qemuDomainObjPrivate;
typedef qemuDomainObjPrivate *qemuDomainObjPrivatePtr;
struct _qemuDomainObjPrivate {
    struct qemuDomainJobObj job;

    qemuMonitorPtr mon;
    virDomainChrSourceDefPtr monConfig;
    int monJSON;
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
    int persistentAddrs;

    virBitmapPtr qemuCaps;
    char *lockState;

    bool fakeReboot;

    int jobs_queued;

    unsigned long migMaxBandwidth;
    char *origname;

    virConsolesPtr cons;

    qemuDomainCleanupCallback *cleanupCallbacks;
    size_t ncleanupCallbacks;
    size_t ncleanupCallbacks_max;
};

struct qemuDomainWatchdogEvent
{
    virDomainObjPtr vm;
    int action;
};

const char *qemuDomainAsyncJobPhaseToString(enum qemuDomainAsyncJob job,
                                            int phase);
int qemuDomainAsyncJobPhaseFromString(enum qemuDomainAsyncJob job,
                                      const char *phase);

void qemuDomainEventFlush(int timer, void *opaque);

/* driver must be locked before calling */
void qemuDomainEventQueue(struct qemud_driver *driver,
                          virDomainEventPtr event);

void qemuDomainSetPrivateDataHooks(virCapsPtr caps);
void qemuDomainSetNamespaceHooks(virCapsPtr caps);

int qemuDomainObjBeginJob(struct qemud_driver *driver,
                          virDomainObjPtr obj,
                          enum qemuDomainJob job)
    ATTRIBUTE_RETURN_CHECK;
int qemuDomainObjBeginAsyncJob(struct qemud_driver *driver,
                               virDomainObjPtr obj,
                               enum qemuDomainAsyncJob asyncJob)
    ATTRIBUTE_RETURN_CHECK;
int qemuDomainObjBeginJobWithDriver(struct qemud_driver *driver,
                                    virDomainObjPtr obj,
                                    enum qemuDomainJob job)
    ATTRIBUTE_RETURN_CHECK;
int qemuDomainObjBeginAsyncJobWithDriver(struct qemud_driver *driver,
                                         virDomainObjPtr obj,
                                         enum qemuDomainAsyncJob asyncJob)
    ATTRIBUTE_RETURN_CHECK;

int qemuDomainObjEndJob(struct qemud_driver *driver,
                        virDomainObjPtr obj)
    ATTRIBUTE_RETURN_CHECK;
int qemuDomainObjEndAsyncJob(struct qemud_driver *driver,
                             virDomainObjPtr obj)
    ATTRIBUTE_RETURN_CHECK;
void qemuDomainObjSetJobPhase(struct qemud_driver *driver,
                              virDomainObjPtr obj,
                              int phase);
void qemuDomainObjSetAsyncJobMask(virDomainObjPtr obj,
                                  unsigned long long allowedJobs);
void qemuDomainObjRestoreJob(virDomainObjPtr obj,
                             struct qemuDomainJobObj *job);
void qemuDomainObjDiscardAsyncJob(struct qemud_driver *driver,
                                  virDomainObjPtr obj);

void qemuDomainObjEnterMonitor(struct qemud_driver *driver,
                               virDomainObjPtr obj)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);
void qemuDomainObjExitMonitor(struct qemud_driver *driver,
                              virDomainObjPtr obj)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);
void qemuDomainObjEnterMonitorWithDriver(struct qemud_driver *driver,
                                         virDomainObjPtr obj)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);
int qemuDomainObjEnterMonitorAsync(struct qemud_driver *driver,
                                   virDomainObjPtr obj,
                                   enum qemuDomainAsyncJob asyncJob)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;
void qemuDomainObjExitMonitorWithDriver(struct qemud_driver *driver,
                                        virDomainObjPtr obj)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);


void qemuDomainObjEnterAgent(struct qemud_driver *driver,
                             virDomainObjPtr obj)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);
void qemuDomainObjExitAgent(struct qemud_driver *driver,
                            virDomainObjPtr obj)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);
void qemuDomainObjEnterAgentWithDriver(struct qemud_driver *driver,
                                       virDomainObjPtr obj)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);
void qemuDomainObjExitAgentWithDriver(struct qemud_driver *driver,
                                      virDomainObjPtr obj)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);


void qemuDomainObjEnterRemoteWithDriver(struct qemud_driver *driver,
                                        virDomainObjPtr obj)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);
void qemuDomainObjExitRemoteWithDriver(struct qemud_driver *driver,
                                       virDomainObjPtr obj)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

char *qemuDomainDefFormatXML(struct qemud_driver *driver,
                             virDomainDefPtr vm,
                             unsigned int flags);

char *qemuDomainFormatXML(struct qemud_driver *driver,
                          virDomainObjPtr vm,
                          unsigned int flags);

char *qemuDomainDefFormatLive(struct qemud_driver *driver,
                              virDomainDefPtr def,
                              bool inactive);

void qemuDomainObjTaint(struct qemud_driver *driver,
                        virDomainObjPtr obj,
                        enum virDomainTaintFlags taint,
                        int logFD);

void qemuDomainObjCheckTaint(struct qemud_driver *driver,
                             virDomainObjPtr obj,
                             int logFD);
void qemuDomainObjCheckDiskTaint(struct qemud_driver *driver,
                                 virDomainObjPtr obj,
                                 virDomainDiskDefPtr disk,
                                 int logFD);
void qemuDomainObjCheckNetTaint(struct qemud_driver *driver,
                                virDomainObjPtr obj,
                                virDomainNetDefPtr net,
                                int logFD);


int qemuDomainCreateLog(struct qemud_driver *driver, virDomainObjPtr vm, bool append);
int qemuDomainOpenLog(struct qemud_driver *driver, virDomainObjPtr vm, off_t pos);
int qemuDomainAppendLog(struct qemud_driver *driver,
                        virDomainObjPtr vm,
                        int logFD,
                        const char *fmt, ...) ATTRIBUTE_FMT_PRINTF(4, 5);

const char *qemuFindQemuImgBinary(struct qemud_driver *driver);

int qemuDomainSnapshotWriteMetadata(virDomainObjPtr vm,
                                    virDomainSnapshotObjPtr snapshot,
                                    char *snapshotDir);

int qemuDomainSnapshotForEachQcow2(struct qemud_driver *driver,
                                   virDomainObjPtr vm,
                                   virDomainSnapshotObjPtr snap,
                                   const char *op,
                                   bool try_all);

int qemuDomainSnapshotDiscard(struct qemud_driver *driver,
                              virDomainObjPtr vm,
                              virDomainSnapshotObjPtr snap,
                              bool update_current,
                              bool metadata_only);

struct qemu_snap_remove {
    struct qemud_driver *driver;
    virDomainObjPtr vm;
    int err;
    bool metadata_only;
    bool current;
};

void qemuDomainSnapshotDiscardAll(void *payload,
                                  const void *name,
                                  void *data);

int qemuDomainSnapshotDiscardAllMetadata(struct qemud_driver *driver,
                                         virDomainObjPtr vm);

void qemuDomainRemoveInactive(struct qemud_driver *driver,
                              virDomainObjPtr vm);

void qemuDomainSetFakeReboot(struct qemud_driver *driver,
                             virDomainObjPtr vm,
                             bool value);

bool qemuDomainJobAllowed(qemuDomainObjPrivatePtr priv,
                          enum qemuDomainJob job);

int qemuDomainCheckDiskPresence(struct qemud_driver *driver,
                                virDomainObjPtr vm,
                                bool start_with_state);

int qemuDomainCleanupAdd(virDomainObjPtr vm,
                         qemuDomainCleanupCallback cb);
void qemuDomainCleanupRemove(virDomainObjPtr vm,
                             qemuDomainCleanupCallback cb);
void qemuDomainCleanupRun(struct qemud_driver *driver,
                          virDomainObjPtr vm);

#endif /* __QEMU_DOMAIN_H__ */
