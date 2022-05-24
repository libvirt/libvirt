/*
 * Copyright (C) 2022 Red Hat, Inc.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#pragma once

#include "internal.h"
#include "virenum.h"

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
    virDomainJobDataPrivateDataCallbacks *privateDataCb; /* callbacks of private data, hypervisor based */
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
