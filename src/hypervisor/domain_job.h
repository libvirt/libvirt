/*
 * Copyright (C) 2022 Red Hat, Inc.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#pragma once

#include "internal.h"

typedef enum {
    VIR_DOMAIN_JOB_STATUS_NONE = 0,
    VIR_DOMAIN_JOB_STATUS_ACTIVE,
    VIR_DOMAIN_JOB_STATUS_MIGRATING,
    VIR_DOMAIN_JOB_STATUS_HYPERVISOR_COMPLETED,
    VIR_DOMAIN_JOB_STATUS_PAUSED,
    VIR_DOMAIN_JOB_STATUS_POSTCOPY,
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
