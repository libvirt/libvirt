/*
 * virdomainjob.h: job functions shared between hypervisor drivers
 *
 * Copyright (C) 2022 Red Hat, Inc.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#pragma once

#include "internal.h"
#include "virenum.h"
#include "virthread.h"
#include "virbuffer.h"
#include "virconftypes.h"
#include "virxml.h"

#define JOB_MASK(job)                  (job == 0 ? 0 : 1 << (job - 1))
#define VIR_JOB_DEFAULT_MASK \
    (JOB_MASK(VIR_JOB_QUERY) | \
     JOB_MASK(VIR_JOB_DESTROY) | \
     JOB_MASK(VIR_JOB_ABORT))

/* Jobs which have to be tracked in domain state XML. */
#define VIR_DOMAIN_TRACK_JOBS \
    (JOB_MASK(VIR_JOB_DESTROY) | \
     JOB_MASK(VIR_JOB_ASYNC))


/* Only 1 job is allowed at any time
 * A job includes *all* monitor commands / hypervisor.so api,
 * even those just querying information, not merely actions */
typedef enum {
    VIR_JOB_NONE = 0,  /* Always set to 0 for easy if (jobActive) conditions */
    VIR_JOB_QUERY,         /* Doesn't change any state */
    VIR_JOB_DESTROY,       /* Destroys the domain (cannot be masked out) */
    VIR_JOB_SUSPEND,       /* Suspends (stops vCPUs) the domain */
    VIR_JOB_MODIFY,        /* May change state */
    VIR_JOB_ABORT,         /* Abort current async job */
    VIR_JOB_MIGRATION_OP,  /* Operation influencing outgoing migration */
    VIR_JOB_MODIFY_MIGRATION_SAFE, /* Internal only job for event handlers which
                                      need to be processed even during migration.
                                      The code may only change state in a way
                                      that does not affect migration. */

    /* The following two items must always be the last items before JOB_LAST */
    VIR_JOB_ASYNC,         /* Asynchronous job */
    VIR_JOB_ASYNC_NESTED,  /* Normal job within an async job */

    VIR_JOB_LAST
} virDomainJob;
VIR_ENUM_DECL(virDomainJob);


/* Currently only QEMU driver uses agent jobs */
typedef enum {
    VIR_AGENT_JOB_NONE = 0,    /* No agent job. */
    VIR_AGENT_JOB_QUERY,       /* Does not change state of domain */
    VIR_AGENT_JOB_MODIFY,      /* May change state of domain */

    VIR_AGENT_JOB_LAST
} virDomainAgentJob;
VIR_ENUM_DECL(virDomainAgentJob);


/* Async job consists of a series of jobs that may change state. Independent
 * jobs that do not change state (and possibly others if explicitly allowed by
 * current async job) are allowed to be run even if async job is active.
 * Currently supported by QEMU only. */
typedef enum {
    VIR_ASYNC_JOB_NONE = 0,
    VIR_ASYNC_JOB_MIGRATION_OUT,
    VIR_ASYNC_JOB_MIGRATION_IN,
    VIR_ASYNC_JOB_SAVE,
    VIR_ASYNC_JOB_DUMP,
    VIR_ASYNC_JOB_SNAPSHOT,
    VIR_ASYNC_JOB_START,
    VIR_ASYNC_JOB_BACKUP,

    VIR_ASYNC_JOB_LAST
} virDomainAsyncJob;
VIR_ENUM_DECL(virDomainAsyncJob);


typedef enum {
    VIR_DOMAIN_JOB_STATUS_NONE = 0,
    VIR_DOMAIN_JOB_STATUS_ACTIVE,
    VIR_DOMAIN_JOB_STATUS_MIGRATING,
    VIR_DOMAIN_JOB_STATUS_HYPERVISOR_COMPLETED,
    VIR_DOMAIN_JOB_STATUS_PAUSED,
    VIR_DOMAIN_JOB_STATUS_POSTCOPY,
    VIR_DOMAIN_JOB_STATUS_POSTCOPY_PAUSED,
    VIR_DOMAIN_JOB_STATUS_COMPLETED,
    VIR_DOMAIN_JOB_STATUS_FAILED,
    VIR_DOMAIN_JOB_STATUS_CANCELED,
} virDomainJobStatus;

typedef void *(*virDomainJobDataPrivateDataAlloc) (void);
typedef void *(*virDomainJobDataPrivateDataCopy) (void *);
typedef void (*virDomainJobDataPrivateDataFree) (void *);

typedef struct _virDomainJobDataPrivateDataCallbacks virDomainJobDataPrivateDataCallbacks;
struct _virDomainJobDataPrivateDataCallbacks {
    virDomainJobDataPrivateDataAlloc allocPrivateData;
    virDomainJobDataPrivateDataCopy copyPrivateData;
    virDomainJobDataPrivateDataFree freePrivateData;
};


typedef struct _virDomainJobData virDomainJobData;
struct _virDomainJobData {
    virDomainJobType jobType;

    virDomainJobStatus status;
    virDomainJobOperation operation;
    unsigned long long started; /* When the async job started */
    unsigned long long stopped; /* When the domain's CPUs were stopped */
    unsigned long long sent; /* When the source sent status info to the
                                destination (only for migrations). */
    unsigned long long received; /* When the destination host received status
                                    info from the source (migrations only). */
    /* Computed values */
    unsigned long long timeElapsed;
    long long timeDelta; /* delta = received - sent, i.e., the difference between
                            the source and the destination time plus the time
                            between the end of Perform phase on the source and
                            the beginning of Finish phase on the destination. */
    bool timeDeltaSet;

    char *errmsg; /* optional error message for failed completed jobs */

    void *privateData; /* private data of hypervisors */
    virDomainJobDataPrivateDataCallbacks *privateDataCb; /* callbacks of private data,
                                                            hypervisor based */
};


virDomainJobData *
virDomainJobDataInit(virDomainJobDataPrivateDataCallbacks *cb);

void
virDomainJobDataFree(virDomainJobData *data);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virDomainJobData, virDomainJobDataFree);

virDomainJobData *
virDomainJobDataCopy(virDomainJobData *data);

virDomainJobType
virDomainJobStatusToType(virDomainJobStatus status);


typedef struct _virDomainObjPrivateJobCallbacks virDomainObjPrivateJobCallbacks;

typedef struct _virDomainJobObj virDomainJobObj;
struct _virDomainJobObj {
    virCond cond;               /* Use to coordinate jobs */

    int jobsQueued;
    unsigned int maxQueuedJobs;

    /* The following members are for VIR_JOB_* */
    virDomainJob active;        /* currently running job */
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
    bool asyncPaused;                   /* The async job is paused */
    int phase;                          /* Job phase (mainly for migrations) */
    unsigned long long mask;            /* Jobs allowed during async job */
    virDomainJobData *current;       /* async job progress data */
    virDomainJobData *completed;     /* statistics data of a recently completed job */
    bool abortJob;                      /* abort of the job requested */
    char *error;                        /* job event completion error */
    unsigned int apiFlags; /* flags passed to the API which started the async job */

    void *privateData;                  /* job specific collection of data */
    virDomainObjPrivateJobCallbacks *cb;
    virDomainJobDataPrivateDataCallbacks *jobDataPrivateCb; /* callbacks for privateData of
                                                               virDomainJobData, can be NULL */
};


typedef void *(*virDomainObjPrivateJobAlloc)(void);
typedef void (*virDomainObjPrivateJobFree)(void *);
typedef void (*virDomainObjPrivateJobReset)(void *);
typedef int (*virDomainObjPrivateJobFormat)(virBuffer *,
                                            virDomainJobObj *,
                                            virDomainObj *);
typedef int (*virDomainObjPrivateJobParse)(xmlXPathContextPtr,
                                           virDomainJobObj *,
                                           virDomainObj *);
typedef void (*virDomainObjPrivateSaveStatus)(virDomainObj *obj);

struct _virDomainObjPrivateJobCallbacks {
   virDomainObjPrivateJobAlloc allocJobPrivate;
   virDomainObjPrivateJobFree freeJobPrivate;
   virDomainObjPrivateJobReset resetJobPrivate;
   virDomainObjPrivateJobFormat formatJobPrivate;
   virDomainObjPrivateJobParse parseJobPrivate;
   virDomainObjPrivateSaveStatus saveStatusPrivate;
};


int virDomainObjInitJob(virDomainJobObj *job,
                        virDomainObjPrivateJobCallbacks *cb,
                        virDomainJobDataPrivateDataCallbacks *jobDataPrivateCb);

void virDomainObjResetJob(virDomainJobObj *job);

void virDomainObjResetAgentJob(virDomainJobObj *job);

void virDomainObjResetAsyncJob(virDomainJobObj *job);

int virDomainObjPreserveJob(virDomainJobObj *currJob,
                            virDomainJobObj *job);

void virDomainObjClearJob(virDomainJobObj *job);
G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(virDomainJobObj, virDomainObjClearJob);

void virDomainJobObjFree(virDomainJobObj *job);

bool virDomainTrackJob(virDomainJob job);

bool virDomainNestedJobAllowed(virDomainJobObj *jobs, virDomainJob newJob);

bool virDomainObjCanSetJob(virDomainJobObj *job,
                           virDomainJob newJob,
                           virDomainAgentJob newAgentJob);

int virDomainObjBeginJobInternal(virDomainObj *obj,
                                 virDomainJobObj *jobObj,
                                 virDomainJob job,
                                 virDomainAgentJob agentJob,
                                 virDomainAsyncJob asyncJob,
                                 bool nowait)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);

int virDomainObjBeginJob(virDomainObj *obj,
                         virDomainJob job)
    G_GNUC_WARN_UNUSED_RESULT;
int virDomainObjBeginAgentJob(virDomainObj *obj,
                              virDomainAgentJob agentJob)
    G_GNUC_WARN_UNUSED_RESULT;
int virDomainObjBeginAsyncJob(virDomainObj *obj,
                              virDomainAsyncJob asyncJob,
                              virDomainJobOperation operation,
                              unsigned int apiFlags)
    G_GNUC_WARN_UNUSED_RESULT;
int virDomainObjBeginNestedJob(virDomainObj *obj,
                               virDomainAsyncJob asyncJob)
    G_GNUC_WARN_UNUSED_RESULT;
int virDomainObjBeginJobNowait(virDomainObj *obj,
                               virDomainJob job)
    G_GNUC_WARN_UNUSED_RESULT;

void virDomainObjEndJob(virDomainObj *obj);
void virDomainObjEndAgentJob(virDomainObj *obj);
void virDomainObjEndAsyncJob(virDomainObj *obj);
