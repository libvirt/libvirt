/*
 * virdomainjob.c: job functions shared between hypervisor drivers
 *
 * Copyright (C) 2022 Red Hat, Inc.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include <config.h>
#include <string.h>

#include "virdomainjob.h"
#include "viralloc.h"
#include "virthreadjob.h"
#include "virlog.h"
#include "virtime.h"
#include "domain_conf.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("conf.virdomainjob");


VIR_ENUM_IMPL(virDomainJob,
              VIR_JOB_LAST,
              "none",
              "query",
              "destroy",
              "suspend",
              "modify",
              "abort",
              "migration operation",
              "modify migration safe",
              "none",   /* async job is never stored in job.active */
              "async nested",
);

VIR_ENUM_IMPL(virDomainAgentJob,
              VIR_AGENT_JOB_LAST,
              "none",
              "query",
              "modify",
);

VIR_ENUM_IMPL(virDomainAsyncJob,
              VIR_ASYNC_JOB_LAST,
              "none",
              "migration out",
              "migration in",
              "save",
              "dump",
              "snapshot",
              "start",
              "backup",
);

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
    case VIR_DOMAIN_JOB_STATUS_POSTCOPY_PAUSED:
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

int
virDomainObjInitJob(virDomainJobObj *job,
                    virDomainObjPrivateJobCallbacks *cb,
                    virDomainJobDataPrivateDataCallbacks *jobDataPrivateCb)
{
    memset(job, 0, sizeof(*job));
    job->cb = g_memdup(cb, sizeof(*cb));
    job->jobDataPrivateCb = g_memdup(jobDataPrivateCb, sizeof(*jobDataPrivateCb));

    if (virCondInit(&job->cond) < 0)
        return -1;

    if (virCondInit(&job->asyncCond) < 0) {
        virCondDestroy(&job->cond);
        return -1;
    }

    if (job->cb && job->cb->allocJobPrivate &&
        !(job->privateData = job->cb->allocJobPrivate())) {
        virCondDestroy(&job->cond);
        virCondDestroy(&job->asyncCond);
        return -1;
    }

    return 0;
}

void
virDomainObjResetJob(virDomainJobObj *job)
{
    job->active = VIR_JOB_NONE;
    job->owner = 0;
    g_clear_pointer(&job->ownerAPI, g_free);
    job->started = 0;
}

void
virDomainObjResetAgentJob(virDomainJobObj *job)
{
    job->agentActive = VIR_AGENT_JOB_NONE;
    job->agentOwner = 0;
    g_clear_pointer(&job->agentOwnerAPI, g_free);
    job->agentStarted = 0;
}

void
virDomainObjResetAsyncJob(virDomainJobObj *job)
{
    job->asyncJob = VIR_ASYNC_JOB_NONE;
    job->asyncOwner = 0;
    g_clear_pointer(&job->asyncOwnerAPI, g_free);
    job->asyncStarted = 0;
    job->asyncPaused = false;
    job->phase = 0;
    job->mask = VIR_JOB_DEFAULT_MASK;
    job->abortJob = false;
    VIR_FREE(job->error);
    g_clear_pointer(&job->current, virDomainJobDataFree);
    job->apiFlags = 0;

    if (job->cb && job->cb->resetJobPrivate)
        job->cb->resetJobPrivate(job->privateData);
}

/**
 * virDomainObjPreserveJob
 * @param currJob structure is a job that needs to be preserved
 * @param job structure where to store job details from @currJob
 *
 * Saves the current job details from @currJob to @job and resets the job in @currJob.
 *
 * Returns 0 on success, -1 on failure.
 */
int
virDomainObjPreserveJob(virDomainJobObj *currJob,
                        virDomainJobObj *job)
{
    memset(job, 0, sizeof(*job));
    job->active = currJob->active;
    job->owner = currJob->owner;
    job->asyncJob = currJob->asyncJob;
    job->asyncOwner = currJob->asyncOwner;
    job->phase = currJob->phase;
    job->privateData = g_steal_pointer(&currJob->privateData);
    job->apiFlags = currJob->apiFlags;

    if (currJob->cb && currJob->cb->allocJobPrivate &&
        !(currJob->privateData = currJob->cb->allocJobPrivate()))
        return -1;
    job->cb = g_memdup(currJob->cb, sizeof(*currJob->cb));

    virDomainObjResetJob(currJob);
    virDomainObjResetAsyncJob(currJob);
    return 0;
}

void
virDomainObjClearJob(virDomainJobObj *job)
{
    virDomainObjResetJob(job);
    virDomainObjResetAsyncJob(job);
    g_clear_pointer(&job->current, virDomainJobDataFree);
    g_clear_pointer(&job->completed, virDomainJobDataFree);
    virCondDestroy(&job->cond);
    virCondDestroy(&job->asyncCond);

    if (job->cb && job->cb->freeJobPrivate)
        g_clear_pointer(&job->privateData, job->cb->freeJobPrivate);

    g_clear_pointer(&job->cb, g_free);
    g_clear_pointer(&job->jobDataPrivateCb, g_free);
}

void
virDomainJobObjFree(virDomainJobObj *job)
{
    if (!job)
        return;

    virDomainObjClearJob(job);
    g_free(job);
}

bool
virDomainTrackJob(virDomainJob job)
{
    return (VIR_DOMAIN_TRACK_JOBS & JOB_MASK(job)) != 0;
}

bool
virDomainNestedJobAllowed(virDomainJobObj *jobs, virDomainJob newJob)
{
    return !jobs->asyncJob ||
           newJob == VIR_JOB_NONE ||
           (jobs->mask & JOB_MASK(newJob));
}

bool
virDomainObjCanSetJob(virDomainJobObj *job,
                      virDomainJob newJob,
                      virDomainAgentJob newAgentJob)
{
    return ((newJob == VIR_JOB_NONE ||
             job->active == VIR_JOB_NONE) &&
            (newAgentJob == VIR_AGENT_JOB_NONE ||
             job->agentActive == VIR_AGENT_JOB_NONE));
}

/* Give up waiting for mutex after 30 seconds */
#define VIR_JOB_WAIT_TIME (1000ull * 30)

/**
 * virDomainObjBeginJobInternal:
 * @obj: virDomainObj = domain object
 * @jobObj: virDomainJobObj = domain job object
 * @job: virDomainJob to start
 * @agentJob: virDomainAgentJob to start
 * @asyncJob: virDomainAsyncJob to start
 * @nowait: don't wait trying to acquire @job
 *
 * Acquires job for a domain object which must be locked before
 * calling. If there's already a job running waits up to
 * VIR_JOB_WAIT_TIME after which the functions fails reporting
 * an error unless @nowait is set.
 *
 * If @nowait is true this function tries to acquire job and if
 * it fails, then it returns immediately without waiting. No
 * error is reported in this case.
 *
 * Returns: 0 on success,
 *         -2 if unable to start job because of timeout or
 *            maxQueuedJobs limit,
 *         -1 otherwise.
 */
int
virDomainObjBeginJobInternal(virDomainObj *obj,
                             virDomainJobObj *jobObj,
                             virDomainJob job,
                             virDomainAgentJob agentJob,
                             virDomainAsyncJob asyncJob,
                             bool nowait)
{
    unsigned long long now = 0;
    unsigned long long then = 0;
    bool nested = job == VIR_JOB_ASYNC_NESTED;
    const char *blocker = NULL;
    const char *agentBlocker = NULL;
    int ret = -1;
    unsigned long long duration = 0;
    unsigned long long agentDuration = 0;
    unsigned long long asyncDuration = 0;
    const char *currentAPI = virThreadJobGet();

    VIR_DEBUG("Starting job: API=%s job=%s agentJob=%s asyncJob=%s "
              "(vm=%p name=%s, current job=%s agentJob=%s async=%s)",
              NULLSTR(currentAPI),
              virDomainJobTypeToString(job),
              virDomainAgentJobTypeToString(agentJob),
              virDomainAsyncJobTypeToString(asyncJob),
              obj, obj->def->name,
              virDomainJobTypeToString(jobObj->active),
              virDomainAgentJobTypeToString(jobObj->agentActive),
              virDomainAsyncJobTypeToString(jobObj->asyncJob));

    if (virTimeMillisNow(&now) < 0)
        return -1;

    jobObj->jobsQueued++;
    then = now + VIR_JOB_WAIT_TIME;

 retry:
    if (job != VIR_JOB_ASYNC &&
        job != VIR_JOB_DESTROY &&
        jobObj->maxQueuedJobs &&
        jobObj->jobsQueued > jobObj->maxQueuedJobs) {
        goto error;
    }

    while (!nested && !virDomainNestedJobAllowed(jobObj, job)) {
        if (nowait)
            goto cleanup;

        VIR_DEBUG("Waiting for async job (vm=%p name=%s)", obj, obj->def->name);
        if (virCondWaitUntil(&jobObj->asyncCond, &obj->parent.lock, then) < 0)
            goto error;
    }

    while (!virDomainObjCanSetJob(jobObj, job, agentJob)) {
        if (nowait)
            goto cleanup;

        VIR_DEBUG("Waiting for job (vm=%p name=%s)", obj, obj->def->name);
        if (virCondWaitUntil(&jobObj->cond, &obj->parent.lock, then) < 0)
            goto error;
    }

    /* No job is active but a new async job could have been started while obj
     * was unlocked, so we need to recheck it. */
    if (!nested && !virDomainNestedJobAllowed(jobObj, job))
        goto retry;

    if (obj->removing) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];

        virUUIDFormat(obj->def->uuid, uuidstr);
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching uuid '%1$s' (%2$s)"),
                       uuidstr, obj->def->name);
        goto cleanup;
    }

    ignore_value(virTimeMillisNow(&now));

    if (job) {
        virDomainObjResetJob(jobObj);

        if (job != VIR_JOB_ASYNC) {
            VIR_DEBUG("Started job: %s (async=%s vm=%p name=%s)",
                      virDomainJobTypeToString(job),
                      virDomainAsyncJobTypeToString(jobObj->asyncJob),
                      obj, obj->def->name);
            jobObj->active = job;
            jobObj->owner = virThreadSelfID();
            jobObj->ownerAPI = g_strdup(virThreadJobGet());
            jobObj->started = now;
        } else {
            VIR_DEBUG("Started async job: %s (vm=%p name=%s)",
                      virDomainAsyncJobTypeToString(asyncJob),
                      obj, obj->def->name);
            virDomainObjResetAsyncJob(jobObj);
            jobObj->current = virDomainJobDataInit(jobObj->jobDataPrivateCb);
            jobObj->current->status = VIR_DOMAIN_JOB_STATUS_ACTIVE;
            jobObj->asyncJob = asyncJob;
            jobObj->asyncOwner = virThreadSelfID();
            jobObj->asyncOwnerAPI = g_strdup(virThreadJobGet());
            jobObj->asyncStarted = now;
            jobObj->current->started = now;
        }
    }

    if (agentJob) {
        virDomainObjResetAgentJob(jobObj);
        VIR_DEBUG("Started agent job: %s (vm=%p name=%s job=%s async=%s)",
                  virDomainAgentJobTypeToString(agentJob),
                  obj, obj->def->name,
                  virDomainJobTypeToString(jobObj->active),
                  virDomainAsyncJobTypeToString(jobObj->asyncJob));
        jobObj->agentActive = agentJob;
        jobObj->agentOwner = virThreadSelfID();
        jobObj->agentOwnerAPI = g_strdup(virThreadJobGet());
        jobObj->agentStarted = now;
    }

    if (virDomainTrackJob(job) && jobObj->cb &&
        jobObj->cb->saveStatusPrivate)
        jobObj->cb->saveStatusPrivate(obj);

    return 0;

 error:
    ignore_value(virTimeMillisNow(&now));
    if (jobObj->active && jobObj->started)
        duration = now - jobObj->started;
    if (jobObj->agentActive && jobObj->agentStarted)
        agentDuration = now - jobObj->agentStarted;
    if (jobObj->asyncJob && jobObj->asyncStarted)
        asyncDuration = now - jobObj->asyncStarted;

    VIR_WARN("Cannot start job (%s, %s, %s) in API %s for domain %s; "
             "current job is (%s, %s, %s) "
             "owned by (%llu %s, %llu %s, %llu %s (flags=0x%x)) "
             "for (%llus, %llus, %llus)",
             virDomainJobTypeToString(job),
             virDomainAgentJobTypeToString(agentJob),
             virDomainAsyncJobTypeToString(asyncJob),
             NULLSTR(currentAPI),
             obj->def->name,
             virDomainJobTypeToString(jobObj->active),
             virDomainAgentJobTypeToString(jobObj->agentActive),
             virDomainAsyncJobTypeToString(jobObj->asyncJob),
             jobObj->owner, NULLSTR(jobObj->ownerAPI),
             jobObj->agentOwner, NULLSTR(jobObj->agentOwnerAPI),
             jobObj->asyncOwner, NULLSTR(jobObj->asyncOwnerAPI),
             jobObj->apiFlags,
             duration / 1000, agentDuration / 1000, asyncDuration / 1000);

    if (job) {
        if (nested || virDomainNestedJobAllowed(jobObj, job))
            blocker = jobObj->ownerAPI;
        else
            blocker = jobObj->asyncOwnerAPI;
    }

    if (agentJob)
        agentBlocker = jobObj->agentOwnerAPI;

    if (errno == ETIMEDOUT) {
        if (blocker && agentBlocker) {
            virReportError(VIR_ERR_OPERATION_TIMEOUT,
                           _("cannot acquire state change lock (held by monitor=%1$s agent=%2$s)"),
                           blocker, agentBlocker);
        } else if (blocker) {
            virReportError(VIR_ERR_OPERATION_TIMEOUT,
                           _("cannot acquire state change lock (held by monitor=%1$s)"),
                           blocker);
        } else if (agentBlocker) {
            virReportError(VIR_ERR_OPERATION_TIMEOUT,
                           _("cannot acquire state change lock (held by agent=%1$s)"),
                           agentBlocker);
        } else {
            virReportError(VIR_ERR_OPERATION_TIMEOUT, "%s",
                           _("cannot acquire state change lock"));
        }
        ret = -2;
    } else if (jobObj->maxQueuedJobs &&
               jobObj->jobsQueued > jobObj->maxQueuedJobs) {
        if (blocker && agentBlocker) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("cannot acquire state change lock (held by monitor=%1$s agent=%2$s) due to max_queued limit"),
                           blocker, agentBlocker);
        } else if (blocker) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("cannot acquire state change lock (held by monitor=%1$s) due to max_queued limit"),
                           blocker);
        } else if (agentBlocker) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("cannot acquire state change lock (held by agent=%1$s) due to max_queued limit"),
                           agentBlocker);
        } else {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("cannot acquire state change lock due to max_queued limit"));
        }
        ret = -2;
    } else {
        virReportSystemError(errno, "%s", _("cannot acquire job mutex"));
    }

 cleanup:
    jobObj->jobsQueued--;
    return ret;
}

/*
 * obj must be locked before calling
 *
 * This must be called by anything that will change the VM state
 * in any way, or anything that will use the Hypervisor monitor.
 *
 * Successful calls must be followed by EndJob eventually
 */
int virDomainObjBeginJob(virDomainObj *obj,
                         virDomainJob job)
{
    if (virDomainObjBeginJobInternal(obj, obj->job, job,
                                     VIR_AGENT_JOB_NONE,
                                     VIR_ASYNC_JOB_NONE, false) < 0)
        return -1;
    return 0;
}

/**
 * virDomainObjBeginAgentJob:
 *
 * Grabs agent type of job. Use if caller talks to guest agent only.
 *
 * To end job call virDomainObjEndAgentJob.
 */
int
virDomainObjBeginAgentJob(virDomainObj *obj,
                          virDomainAgentJob agentJob)
{
    return virDomainObjBeginJobInternal(obj, obj->job, VIR_JOB_NONE,
                                        agentJob,
                                        VIR_ASYNC_JOB_NONE, false);
}

int virDomainObjBeginAsyncJob(virDomainObj *obj,
                              virDomainAsyncJob asyncJob,
                              virDomainJobOperation operation,
                              unsigned int apiFlags)
{
    if (virDomainObjBeginJobInternal(obj, obj->job, VIR_JOB_ASYNC,
                                     VIR_AGENT_JOB_NONE,
                                     asyncJob, false) < 0)
        return -1;

    obj->job->current->operation = operation;
    obj->job->apiFlags = apiFlags;
    return 0;
}

int
virDomainObjBeginNestedJob(virDomainObj *obj,
                            virDomainAsyncJob asyncJob)
{
    if (asyncJob != obj->job->asyncJob) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected async job %1$d type expected %2$d"),
                       asyncJob, obj->job->asyncJob);
        return -1;
    }

    if (obj->job->asyncOwner != virThreadSelfID()) {
        VIR_WARN("This thread doesn't seem to be the async job owner: %llu",
                 obj->job->asyncOwner);
    }

    return virDomainObjBeginJobInternal(obj, obj->job,
                                        VIR_JOB_ASYNC_NESTED,
                                        VIR_AGENT_JOB_NONE,
                                        VIR_ASYNC_JOB_NONE,
                                        false);
}

/**
 * virDomainObjBeginJobNowait:
 *
 * @obj: domain object
 * @job: virDomainJob to start
 *
 * Acquires job for a domain object which must be locked before
 * calling. If there's already a job running it returns
 * immediately without any error reported.
 *
 * Returns: see virDomainObjBeginJobInternal
 */
int
virDomainObjBeginJobNowait(virDomainObj *obj,
                           virDomainJob job)
{
    return virDomainObjBeginJobInternal(obj, obj->job, job,
                                        VIR_AGENT_JOB_NONE,
                                        VIR_ASYNC_JOB_NONE, true);
}

/*
 * obj must be locked and have a reference before calling
 *
 * To be called after completing the work associated with the
 * earlier virDomainBeginJob() call
 */
void
virDomainObjEndJob(virDomainObj *obj)
{
    virDomainJob job = obj->job->active;

    obj->job->jobsQueued--;

    VIR_DEBUG("Stopping job: %s (async=%s vm=%p name=%s)",
              virDomainJobTypeToString(job),
              virDomainAsyncJobTypeToString(obj->job->asyncJob),
              obj, obj->def->name);

    virDomainObjResetJob(obj->job);

    if (virDomainTrackJob(job) && obj->job->cb &&
        obj->job->cb->saveStatusPrivate)
        obj->job->cb->saveStatusPrivate(obj);
    /* We indeed need to wake up ALL threads waiting because
     * grabbing a job requires checking more variables. */
    virCondBroadcast(&obj->job->cond);
}

void
virDomainObjEndAgentJob(virDomainObj *obj)
{
    virDomainAgentJob agentJob = obj->job->agentActive;

    obj->job->jobsQueued--;

    VIR_DEBUG("Stopping agent job: %s (async=%s vm=%p name=%s)",
              virDomainAgentJobTypeToString(agentJob),
              virDomainAsyncJobTypeToString(obj->job->asyncJob),
              obj, obj->def->name);

    virDomainObjResetAgentJob(obj->job);
    /* We indeed need to wake up ALL threads waiting because
     * grabbing a job requires checking more variables. */
    virCondBroadcast(&obj->job->cond);
}

void
virDomainObjEndAsyncJob(virDomainObj *obj)
{
    obj->job->jobsQueued--;

    VIR_DEBUG("Stopping async job: %s (vm=%p name=%s)",
              virDomainAsyncJobTypeToString(obj->job->asyncJob),
              obj, obj->def->name);

    virDomainObjResetAsyncJob(obj->job);
    if (obj->job->cb && obj->job->cb->saveStatusPrivate)
        obj->job->cb->saveStatusPrivate(obj);
    virCondBroadcast(&obj->job->asyncCond);
}
