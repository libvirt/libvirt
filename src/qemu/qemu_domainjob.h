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
#include "domain_job.h"


typedef enum {
    QEMU_DOMAIN_JOB_STATS_TYPE_NONE = 0,
    QEMU_DOMAIN_JOB_STATS_TYPE_MIGRATION,
    QEMU_DOMAIN_JOB_STATS_TYPE_SAVEDUMP,
    QEMU_DOMAIN_JOB_STATS_TYPE_MEMDUMP,
    QEMU_DOMAIN_JOB_STATS_TYPE_BACKUP,
} qemuDomainJobStatsType;


typedef struct _qemuDomainMirrorStats qemuDomainMirrorStats;
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

typedef struct _qemuDomainJobDataPrivate qemuDomainJobDataPrivate;
struct _qemuDomainJobDataPrivate {
    /* Raw values from QEMU */
    qemuDomainJobStatsType statsType;
    union {
        qemuMonitorMigrationStats mig;
        qemuMonitorDumpStats dump;
        qemuDomainBackupStats backup;
    } stats;
    qemuDomainMirrorStats mirrorStats;
};

extern virDomainJobDataPrivateDataCallbacks qemuJobDataPrivateDataCallbacks;

typedef struct _qemuDomainJobObj qemuDomainJobObj;

typedef void *(*qemuDomainObjPrivateJobAlloc)(void);
typedef void (*qemuDomainObjPrivateJobFree)(void *);
typedef void (*qemuDomainObjPrivateJobReset)(void *);
typedef int (*qemuDomainObjPrivateJobFormat)(virBuffer *,
                                             qemuDomainJobObj *,
                                             virDomainObj *);
typedef int (*qemuDomainObjPrivateJobParse)(xmlXPathContextPtr,
                                            qemuDomainJobObj *,
                                            virDomainObj *);

typedef struct _qemuDomainObjPrivateJobCallbacks qemuDomainObjPrivateJobCallbacks;
struct _qemuDomainObjPrivateJobCallbacks {
   qemuDomainObjPrivateJobAlloc allocJobPrivate;
   qemuDomainObjPrivateJobFree freeJobPrivate;
   qemuDomainObjPrivateJobReset resetJobPrivate;
   qemuDomainObjPrivateJobFormat formatJob;
   qemuDomainObjPrivateJobParse parseJob;
};

struct _qemuDomainJobObj {
    virCond cond;                       /* Use to coordinate jobs */

    int jobsQueued;

    /* The following members are for VIR_JOB_* */
    virDomainJob active;               /* Currently running job */
    unsigned long long owner;           /* Thread id which set current job */
    char *ownerAPI;                     /* The API which owns the job */
    unsigned long long started;         /* When the current job started */

    /* The following members are for VIR_AGENT_JOB_* */
    virDomainAgentJob agentActive;     /* Currently running agent job */
    unsigned long long agentOwner;      /* Thread id which set current agent job */
    char *agentOwnerAPI;                /* The API which owns the agent job */
    unsigned long long agentStarted;    /* When the current agent job started */

    /* The following members are for VIR_ASYNC_JOB_* */
    virCond asyncCond;                  /* Use to coordinate with async jobs */
    virDomainAsyncJob asyncJob;        /* Currently active async job */
    unsigned long long asyncOwner;      /* Thread which set current async job */
    char *asyncOwnerAPI;                /* The API which owns the async job */
    unsigned long long asyncStarted;    /* When the current async job started */
    int phase;                          /* Job phase (mainly for migrations) */
    unsigned long long mask;            /* Jobs allowed during async job */
    virDomainJobData *current;       /* async job progress data */
    virDomainJobData *completed;     /* statistics data of a recently completed job */
    bool abortJob;                      /* abort of the job requested */
    char *error;                        /* job event completion error */
    unsigned long apiFlags; /* flags passed to the API which started the async job */

    void *privateData;                  /* job specific collection of data */
    qemuDomainObjPrivateJobCallbacks *cb;
};

void qemuDomainJobSetStatsType(virDomainJobData *jobData,
                               qemuDomainJobStatsType type);

const char *qemuDomainAsyncJobPhaseToString(virDomainAsyncJob job,
                                            int phase);
int qemuDomainAsyncJobPhaseFromString(virDomainAsyncJob job,
                                      const char *phase);

void qemuDomainEventEmitJobCompleted(virQEMUDriver *driver,
                                     virDomainObj *vm);

int qemuDomainObjBeginJob(virQEMUDriver *driver,
                          virDomainObj *obj,
                          virDomainJob job)
    G_GNUC_WARN_UNUSED_RESULT;
int qemuDomainObjBeginAgentJob(virQEMUDriver *driver,
                               virDomainObj *obj,
                               virDomainAgentJob agentJob)
    G_GNUC_WARN_UNUSED_RESULT;
int qemuDomainObjBeginAsyncJob(virQEMUDriver *driver,
                               virDomainObj *obj,
                               virDomainAsyncJob asyncJob,
                               virDomainJobOperation operation,
                               unsigned long apiFlags)
    G_GNUC_WARN_UNUSED_RESULT;
int qemuDomainObjBeginNestedJob(virQEMUDriver *driver,
                                virDomainObj *obj,
                                virDomainAsyncJob asyncJob)
    G_GNUC_WARN_UNUSED_RESULT;
int qemuDomainObjBeginJobNowait(virQEMUDriver *driver,
                                virDomainObj *obj,
                                virDomainJob job)
    G_GNUC_WARN_UNUSED_RESULT;

void qemuDomainObjEndJob(virDomainObj *obj);
void qemuDomainObjEndAgentJob(virDomainObj *obj);
void qemuDomainObjEndAsyncJob(virDomainObj *obj);
void qemuDomainObjAbortAsyncJob(virDomainObj *obj);
void qemuDomainObjSetJobPhase(virDomainObj *obj,
                              int phase);
void qemuDomainObjSetAsyncJobMask(virDomainObj *obj,
                                  unsigned long long allowedJobs);
int qemuDomainObjRestoreJob(virDomainObj *obj,
                            qemuDomainJobObj *job);
void qemuDomainObjDiscardAsyncJob(virDomainObj *obj);
void qemuDomainObjReleaseAsyncJob(virDomainObj *obj);

int qemuDomainJobDataUpdateTime(virDomainJobData *jobData)
    ATTRIBUTE_NONNULL(1);
int qemuDomainJobDataUpdateDowntime(virDomainJobData *jobData)
    ATTRIBUTE_NONNULL(1);
int qemuDomainJobDataToInfo(virDomainJobData *jobData,
                            virDomainJobInfoPtr info)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);
int qemuDomainJobDataToParams(virDomainJobData *jobData,
                              int *type,
                              virTypedParameterPtr *params,
                              int *nparams)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2)
    ATTRIBUTE_NONNULL(3) ATTRIBUTE_NONNULL(4);

bool qemuDomainTrackJob(virDomainJob job);

void qemuDomainObjClearJob(qemuDomainJobObj *job);
G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(qemuDomainJobObj, qemuDomainObjClearJob);

int
qemuDomainObjInitJob(qemuDomainJobObj *job,
                     qemuDomainObjPrivateJobCallbacks *cb);

int
qemuDomainObjPrivateXMLFormatJob(virBuffer *buf,
                                 virDomainObj *vm);

int
qemuDomainObjPrivateXMLParseJob(virDomainObj *vm,
                                xmlXPathContextPtr ctxt);
