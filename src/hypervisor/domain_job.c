/*
 * Copyright (C) 2022 Red Hat, Inc.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include <config.h>
#include <string.h>

#include "domain_job.h"


virDomainJobData *
virDomainJobDataInit(virDomainJobDataPrivateDataCallbacks *cb)
{
    virDomainJobData *ret = g_new0(virDomainJobData, 1);

    ret->privateDataCb = cb;

    if (ret->privateDataCb)
        ret->privateData = ret->privateDataCb->allocPrivateData();

    return ret;
}

virDomainJobData *
virDomainJobDataCopy(virDomainJobData *data)
{
    virDomainJobData *ret = g_new0(virDomainJobData, 1);

    memcpy(ret, data, sizeof(*data));

    if (ret->privateDataCb)
        ret->privateData = data->privateDataCb->copyPrivateData(data->privateData);

    ret->errmsg = g_strdup(data->errmsg);

    return ret;
}

void
virDomainJobDataFree(virDomainJobData *data)
{
    if (!data)
        return;

    if (data->privateDataCb)
        data->privateDataCb->freePrivateData(data->privateData);

    g_free(data->errmsg);
    g_free(data);
}

virDomainJobType
virDomainJobStatusToType(virDomainJobStatus status)
{
    switch (status) {
    case VIR_DOMAIN_JOB_STATUS_NONE:
        break;

    case VIR_DOMAIN_JOB_STATUS_ACTIVE:
    case VIR_DOMAIN_JOB_STATUS_MIGRATING:
    case VIR_DOMAIN_JOB_STATUS_HYPERVISOR_COMPLETED:
    case VIR_DOMAIN_JOB_STATUS_POSTCOPY:
    case VIR_DOMAIN_JOB_STATUS_PAUSED:
        return VIR_DOMAIN_JOB_UNBOUNDED;

    case VIR_DOMAIN_JOB_STATUS_COMPLETED:
        return VIR_DOMAIN_JOB_COMPLETED;

    case VIR_DOMAIN_JOB_STATUS_FAILED:
        return VIR_DOMAIN_JOB_FAILED;

    case VIR_DOMAIN_JOB_STATUS_CANCELED:
        return VIR_DOMAIN_JOB_CANCELLED;
    }

    return VIR_DOMAIN_JOB_NONE;
}
