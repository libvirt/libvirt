/*
 * qemu_domainjob.h: helper functions for QEMU domain jobs
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

#pragma once

#include <glib-object.h>
#include "qemu_monitor.h"

#define JOB_MASK(job)                  (job == 0 ? 0 : 1 << (job - 1))
#define QEMU_JOB_DEFAULT_MASK \
    (JOB_MASK(QEMU_JOB_QUERY) | \
     JOB_MASK(QEMU_JOB_DESTROY) | \
     JOB_MASK(QEMU_JOB_ABORT))

/* Jobs which have to be tracked in domain state XML. */
#define QEMU_DOMAIN_TRACK_JOBS \
    (JOB_MASK(QEMU_JOB_DESTROY) | \
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
VIR_ENUM_DECL(qemuDomainJob);

typedef enum {
    QEMU_AGENT_JOB_NONE = 0,    /* No agent job. */
    QEMU_AGENT_JOB_QUERY,       /* Does not change state of domain */
    QEMU_AGENT_JOB_MODIFY,      /* May change state of domain */

    QEMU_AGENT_JOB_LAST
} qemuDomainAgentJob;
VIR_ENUM_DECL(qemuDomainAgentJob);

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
    QEMU_ASYNC_JOB_BACKUP,

    QEMU_ASYNC_JOB_LAST
} qemuDomainAsyncJob;
VIR_ENUM_DECL(qemuDomainAsyncJob);

typedef enum {
    QEMU_DOMAIN_JOB_STATUS_NONE = 0,
    QEMU_DOMAIN_JOB_STATUS_ACTIVE,
    QEMU_DOMAIN_JOB_STATUS_MIGRATING,
    QEMU_DOMAIN_JOB_STATUS_QEMU_COMPLETED,
    QEMU_DOMAIN_JOB_STATUS_PAUSED,
    QEMU_DOMAIN_JOB_STATUS_POSTCOPY,
    QEMU_DOMAIN_JOB_STATUS_COMPLETED,
    QEMU_DOMAIN_JOB_STATUS_FAILED,
    QEMU_DOMAIN_JOB_STATUS_CANCELED,
} qemuDomainJobStatus;

typedef enum {
    QEMU_DOMAIN_JOB_STATS_TYPE_NONE = 0,
    QEMU_DOMAIN_JOB_STATS_TYPE_MIGRATION,
    QEMU_DOMAIN_JOB_STATS_TYPE_SAVEDUMP,
    QEMU_DOMAIN_JOB_STATS_TYPE_MEMDUMP,
    QEMU_DOMAIN_JOB_STATS_TYPE_BACKUP,
} qemuDomainJobStatsType;


typedef struct _qemuDomainMirrorStats qemuDomainMirrorStats;
typedef qemuDomainMirrorStats *qemuDomainMirrorStatsPtr;
struct _qemuDomainMirrorStats {
    unsigned long long transferred;
    unsigned long long total;
};

typedef struct _qemuDomainBackupStats qemuDomainBackupStats;
struct _qemuDomainBackupStats {
    unsigned long long transferred;
    unsigned long long total;
    unsigned long long tmp_used;
    unsigned long long tmp_total;
};

typedef struct _qemuDomainJobInfo qemuDomainJobInfo;
typedef qemuDomainJobInfo *qemuDomainJobInfoPtr;
struct _qemuDomainJobInfo {
    qemuDomainJobStatus status;
    virDomainJobOperation operation;
    unsigned long long started; /* When the async job started */
    unsigned long long stopped; /* When the domain's CPUs were stopped */
    unsigned long long sent; /* When the source sent status info to the
                                destination (only for migrations). */
    unsigned long long received; /* When the destination host received status
                                    info from the source (migrations only). */
    /* Computed values */
    unsigned long long timeElapsed;
    long long timeDelta; /* delta = received - sent, i.e., the difference
                            between the source and the destination time plus
                            the time between the end of Perform phase on the
                            source and the beginning of Finish phase on the
                            destination. */
    bool timeDeltaSet;
    /* Raw values from QEMU */
    qemuDomainJobStatsType statsType;
    union {
        qemuMonitorMigrationStats mig;
        qemuMonitorDumpStats dump;
        qemuDomainBackupStats backup;
    } stats;
    qemuDomainMirrorStats mirrorStats;

    char *errmsg; /* optional error message for failed completed jobs */
};

void
qemuDomainJobInfoFree(qemuDomainJobInfoPtr info);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(qemuDomainJobInfo, qemuDomainJobInfoFree);

qemuDomainJobInfoPtr
qemuDomainJobInfoCopy(qemuDomainJobInfoPtr info);

typedef struct _qemuDomainJobObj qemuDomainJobObj;
typedef qemuDomainJobObj *qemuDomainJobObjPtr;

typedef void *(*qemuDomainObjPrivateJobAlloc)(void);
typedef void (*qemuDomainObjPrivateJobFree)(void *);
typedef void (*qemuDomainObjPrivateJobReset)(void *);
typedef int (*qemuDomainObjPrivateJobFormat)(virBufferPtr,
                                             qemuDomainJobObjPtr,
                                             virDomainObjPtr);
typedef int (*qemuDomainObjPrivateJobParse)(xmlXPathContextPtr,
                                            qemuDomainJobObjPtr,
                                            virDomainObjPtr);

typedef struct _qemuDomainObjPrivateJobCallbacks qemuDomainObjPrivateJobCallbacks;
typedef qemuDomainObjPrivateJobCallbacks *qemuDomainObjPrivateJobCallbacksPtr;
struct _qemuDomainObjPrivateJobCallbacks {
   qemuDomainObjPrivateJobAlloc allocJobPrivate;
   qemuDomainObjPrivateJobFree freeJobPrivate;
   qemuDomainObjPrivateJobReset resetJobPrivate;
   qemuDomainObjPrivateJobFormat formatJob;
   qemuDomainObjPrivateJobParse parseJob;
};

struct _qemuDomainJobObj {
    virCond cond;                       /* Use to coordinate jobs */

    /* The following members are for QEMU_JOB_* */
    qemuDomainJob active;               /* Currently running job */
    unsigned long long owner;           /* Thread id which set current job */
    const char *ownerAPI;               /* The API which owns the job */
    unsigned long long started;         /* When the current job started */

    /* The following members are for QEMU_AGENT_JOB_* */
    qemuDomainAgentJob agentActive;     /* Currently running agent job */
    unsigned long long agentOwner;      /* Thread id which set current agent job */
    const char *agentOwnerAPI;          /* The API which owns the agent job */
    unsigned long long agentStarted;    /* When the current agent job started */

    /* The following members are for QEMU_ASYNC_JOB_* */
    virCond asyncCond;                  /* Use to coordinate with async jobs */
    qemuDomainAsyncJob asyncJob;        /* Currently active async job */
    unsigned long long asyncOwner;      /* Thread which set current async job */
    const char *asyncOwnerAPI;          /* The API which owns the async job */
    unsigned long long asyncStarted;    /* When the current async job started */
    int phase;                          /* Job phase (mainly for migrations) */
    unsigned long long mask;            /* Jobs allowed during async job */
    qemuDomainJobInfoPtr current;       /* async job progress data */
    qemuDomainJobInfoPtr completed;     /* statistics data of a recently completed job */
    bool abortJob;                      /* abort of the job requested */
    char *error;                        /* job event completion error */
    unsigned long apiFlags; /* flags passed to the API which started the async job */

    void *privateData;                  /* job specific collection of data */
    qemuDomainObjPrivateJobCallbacksPtr cb;
};

const char *qemuDomainAsyncJobPhaseToString(qemuDomainAsyncJob job,
                                            int phase);
int qemuDomainAsyncJobPhaseFromString(qemuDomainAsyncJob job,
                                      const char *phase);

void qemuDomainEventEmitJobCompleted(virQEMUDriverPtr driver,
                                     virDomainObjPtr vm);

int qemuDomainObjBeginJob(virQEMUDriverPtr driver,
                          virDomainObjPtr obj,
                          qemuDomainJob job)
    G_GNUC_WARN_UNUSED_RESULT;
int qemuDomainObjBeginAgentJob(virQEMUDriverPtr driver,
                               virDomainObjPtr obj,
                               qemuDomainAgentJob agentJob)
    G_GNUC_WARN_UNUSED_RESULT;
int qemuDomainObjBeginAsyncJob(virQEMUDriverPtr driver,
                               virDomainObjPtr obj,
                               qemuDomainAsyncJob asyncJob,
                               virDomainJobOperation operation,
                               unsigned long apiFlags)
    G_GNUC_WARN_UNUSED_RESULT;
int qemuDomainObjBeginNestedJob(virQEMUDriverPtr driver,
                                virDomainObjPtr obj,
                                qemuDomainAsyncJob asyncJob)
    G_GNUC_WARN_UNUSED_RESULT;
int qemuDomainObjBeginJobNowait(virQEMUDriverPtr driver,
                                virDomainObjPtr obj,
                                qemuDomainJob job)
    G_GNUC_WARN_UNUSED_RESULT;

void qemuDomainObjEndJob(virQEMUDriverPtr driver,
                         virDomainObjPtr obj);
void qemuDomainObjEndAgentJob(virDomainObjPtr obj);
void qemuDomainObjEndAsyncJob(virQEMUDriverPtr driver,
                              virDomainObjPtr obj);
void qemuDomainObjAbortAsyncJob(virDomainObjPtr obj);
void qemuDomainObjSetJobPhase(virQEMUDriverPtr driver,
                              virDomainObjPtr obj,
                              int phase);
void qemuDomainObjSetAsyncJobMask(virDomainObjPtr obj,
                                  unsigned long long allowedJobs);
int qemuDomainObjRestoreJob(virDomainObjPtr obj,
                            qemuDomainJobObjPtr job);
void qemuDomainObjDiscardAsyncJob(virQEMUDriverPtr driver,
                                  virDomainObjPtr obj);
void qemuDomainObjReleaseAsyncJob(virDomainObjPtr obj);

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

bool qemuDomainTrackJob(qemuDomainJob job);

void qemuDomainObjClearJob(qemuDomainJobObjPtr job);
G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(qemuDomainJobObj, qemuDomainObjClearJob);

int
qemuDomainObjInitJob(qemuDomainJobObjPtr job,
                     qemuDomainObjPrivateJobCallbacksPtr cb);

bool qemuDomainJobAllowed(qemuDomainJobObjPtr jobs, qemuDomainJob newJob);

int
qemuDomainObjPrivateXMLFormatJob(virBufferPtr buf,
                                 virDomainObjPtr vm);

int
qemuDomainObjPrivateXMLParseJob(virDomainObjPtr vm,
                                xmlXPathContextPtr ctxt);
