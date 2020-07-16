/*
 * qemu_domainjob.c: helper functions for QEMU domain jobs
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

#include <config.h>

#include "qemu_domain.h"
#include "qemu_migration.h"
#include "qemu_domainjob.h"
#include "viralloc.h"
#include "virlog.h"
#include "virerror.h"
#include "virtime.h"
#include "virthreadjob.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_domainjob");

VIR_ENUM_IMPL(qemuDomainJob,
              QEMU_JOB_LAST,
              "none",
              "query",
              "destroy",
              "suspend",
              "modify",
              "abort",
              "migration operation",
              "none",   /* async job is never stored in job.active */
              "async nested",
);

VIR_ENUM_IMPL(qemuDomainAgentJob,
              QEMU_AGENT_JOB_LAST,
              "none",
              "query",
              "modify",
);

VIR_ENUM_IMPL(qemuDomainAsyncJob,
              QEMU_ASYNC_JOB_LAST,
              "none",
              "migration out",
              "migration in",
              "save",
              "dump",
              "snapshot",
              "start",
              "backup",
);

const char *
qemuDomainAsyncJobPhaseToString(qemuDomainAsyncJob job,
                                int phase G_GNUC_UNUSED)
{
    switch (job) {
    case QEMU_ASYNC_JOB_MIGRATION_OUT:
    case QEMU_ASYNC_JOB_MIGRATION_IN:
        return qemuMigrationJobPhaseTypeToString(phase);

    case QEMU_ASYNC_JOB_SAVE:
    case QEMU_ASYNC_JOB_DUMP:
    case QEMU_ASYNC_JOB_SNAPSHOT:
    case QEMU_ASYNC_JOB_START:
    case QEMU_ASYNC_JOB_NONE:
    case QEMU_ASYNC_JOB_BACKUP:
        G_GNUC_FALLTHROUGH;
    case QEMU_ASYNC_JOB_LAST:
        break;
    }

    return "none";
}

int
qemuDomainAsyncJobPhaseFromString(qemuDomainAsyncJob job,
                                  const char *phase)
{
    if (!phase)
        return 0;

    switch (job) {
    case QEMU_ASYNC_JOB_MIGRATION_OUT:
    case QEMU_ASYNC_JOB_MIGRATION_IN:
        return qemuMigrationJobPhaseTypeFromString(phase);

    case QEMU_ASYNC_JOB_SAVE:
    case QEMU_ASYNC_JOB_DUMP:
    case QEMU_ASYNC_JOB_SNAPSHOT:
    case QEMU_ASYNC_JOB_START:
    case QEMU_ASYNC_JOB_NONE:
    case QEMU_ASYNC_JOB_BACKUP:
        G_GNUC_FALLTHROUGH;
    case QEMU_ASYNC_JOB_LAST:
        break;
    }

    if (STREQ(phase, "none"))
        return 0;
    else
        return -1;
}


void
qemuDomainJobInfoFree(qemuDomainJobInfoPtr info)
{
    g_free(info->errmsg);
    g_free(info);
}


qemuDomainJobInfoPtr
qemuDomainJobInfoCopy(qemuDomainJobInfoPtr info)
{
    qemuDomainJobInfoPtr ret = g_new0(qemuDomainJobInfo, 1);

    memcpy(ret, info, sizeof(*info));

    ret->errmsg = g_strdup(info->errmsg);

    return ret;
}

void
qemuDomainEventEmitJobCompleted(virQEMUDriverPtr driver,
                                virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virObjectEventPtr event;
    virTypedParameterPtr params = NULL;
    int nparams = 0;
    int type;

    if (!priv->job.completed)
        return;

    if (qemuDomainJobInfoToParams(priv->job.completed, &type,
                                  &params, &nparams) < 0) {
        VIR_WARN("Could not get stats for completed job; domain %s",
                 vm->def->name);
    }

    event = virDomainEventJobCompletedNewFromObj(vm, params, nparams);
    virObjectEventStateQueue(driver->domainEventState, event);
}


int
qemuDomainObjInitJob(qemuDomainJobObjPtr job,
                     qemuDomainObjPrivateJobCallbacksPtr cb)
{
    memset(job, 0, sizeof(*job));
    job->cb = cb;

    if (!(job->privateData = job->cb->allocJobPrivate()))
        return -1;

    if (virCondInit(&job->cond) < 0) {
        job->cb->freeJobPrivate(job->privateData);
        return -1;
    }

    if (virCondInit(&job->asyncCond) < 0) {
        job->cb->freeJobPrivate(job->privateData);
        virCondDestroy(&job->cond);
        return -1;
    }

    return 0;
}


static void
qemuDomainObjResetJob(qemuDomainJobObjPtr job)
{
    job->active = QEMU_JOB_NONE;
    job->owner = 0;
    job->ownerAPI = NULL;
    job->started = 0;
}


static void
qemuDomainObjResetAgentJob(qemuDomainJobObjPtr job)
{
    job->agentActive = QEMU_AGENT_JOB_NONE;
    job->agentOwner = 0;
    job->agentOwnerAPI = NULL;
    job->agentStarted = 0;
}


static void
qemuDomainObjResetAsyncJob(qemuDomainJobObjPtr job)
{
    job->asyncJob = QEMU_ASYNC_JOB_NONE;
    job->asyncOwner = 0;
    job->asyncOwnerAPI = NULL;
    job->asyncStarted = 0;
    job->phase = 0;
    job->mask = QEMU_JOB_DEFAULT_MASK;
    job->abortJob = false;
    VIR_FREE(job->error);
    g_clear_pointer(&job->current, qemuDomainJobInfoFree);
    job->cb->resetJobPrivate(job->privateData);
    job->apiFlags = 0;
}

int
qemuDomainObjRestoreJob(virDomainObjPtr obj,
                        qemuDomainJobObjPtr job)
{
    qemuDomainObjPrivatePtr priv = obj->privateData;

    memset(job, 0, sizeof(*job));
    job->active = priv->job.active;
    job->owner = priv->job.owner;
    job->asyncJob = priv->job.asyncJob;
    job->asyncOwner = priv->job.asyncOwner;
    job->phase = priv->job.phase;
    job->privateData = g_steal_pointer(&priv->job.privateData);
    job->apiFlags = priv->job.apiFlags;

    if (!(priv->job.privateData = priv->job.cb->allocJobPrivate()))
        return -1;
    job->cb = priv->job.cb;

    qemuDomainObjResetJob(&priv->job);
    qemuDomainObjResetAsyncJob(&priv->job);
    return 0;
}

void
qemuDomainObjFreeJob(qemuDomainJobObjPtr job)
{
    qemuDomainObjResetJob(job);
    qemuDomainObjResetAsyncJob(job);
    job->cb->freeJobPrivate(job->privateData);
    g_clear_pointer(&job->current, qemuDomainJobInfoFree);
    g_clear_pointer(&job->completed, qemuDomainJobInfoFree);
    virCondDestroy(&job->cond);
    virCondDestroy(&job->asyncCond);
}

bool
qemuDomainTrackJob(qemuDomainJob job)
{
    return (QEMU_DOMAIN_TRACK_JOBS & JOB_MASK(job)) != 0;
}


int
qemuDomainJobInfoUpdateTime(qemuDomainJobInfoPtr jobInfo)
{
    unsigned long long now;

    if (!jobInfo->started)
        return 0;

    if (virTimeMillisNow(&now) < 0)
        return -1;

    if (now < jobInfo->started) {
        VIR_WARN("Async job starts in the future");
        jobInfo->started = 0;
        return 0;
    }

    jobInfo->timeElapsed = now - jobInfo->started;
    return 0;
}

int
qemuDomainJobInfoUpdateDowntime(qemuDomainJobInfoPtr jobInfo)
{
    unsigned long long now;

    if (!jobInfo->stopped)
        return 0;

    if (virTimeMillisNow(&now) < 0)
        return -1;

    if (now < jobInfo->stopped) {
        VIR_WARN("Guest's CPUs stopped in the future");
        jobInfo->stopped = 0;
        return 0;
    }

    jobInfo->stats.mig.downtime = now - jobInfo->stopped;
    jobInfo->stats.mig.downtime_set = true;
    return 0;
}

static virDomainJobType
qemuDomainJobStatusToType(qemuDomainJobStatus status)
{
    switch (status) {
    case QEMU_DOMAIN_JOB_STATUS_NONE:
        break;

    case QEMU_DOMAIN_JOB_STATUS_ACTIVE:
    case QEMU_DOMAIN_JOB_STATUS_MIGRATING:
    case QEMU_DOMAIN_JOB_STATUS_QEMU_COMPLETED:
    case QEMU_DOMAIN_JOB_STATUS_POSTCOPY:
    case QEMU_DOMAIN_JOB_STATUS_PAUSED:
        return VIR_DOMAIN_JOB_UNBOUNDED;

    case QEMU_DOMAIN_JOB_STATUS_COMPLETED:
        return VIR_DOMAIN_JOB_COMPLETED;

    case QEMU_DOMAIN_JOB_STATUS_FAILED:
        return VIR_DOMAIN_JOB_FAILED;

    case QEMU_DOMAIN_JOB_STATUS_CANCELED:
        return VIR_DOMAIN_JOB_CANCELLED;
    }

    return VIR_DOMAIN_JOB_NONE;
}

int
qemuDomainJobInfoToInfo(qemuDomainJobInfoPtr jobInfo,
                        virDomainJobInfoPtr info)
{
    info->type = qemuDomainJobStatusToType(jobInfo->status);
    info->timeElapsed = jobInfo->timeElapsed;

    switch (jobInfo->statsType) {
    case QEMU_DOMAIN_JOB_STATS_TYPE_MIGRATION:
        info->memTotal = jobInfo->stats.mig.ram_total;
        info->memRemaining = jobInfo->stats.mig.ram_remaining;
        info->memProcessed = jobInfo->stats.mig.ram_transferred;
        info->fileTotal = jobInfo->stats.mig.disk_total +
                          jobInfo->mirrorStats.total;
        info->fileRemaining = jobInfo->stats.mig.disk_remaining +
                              (jobInfo->mirrorStats.total -
                               jobInfo->mirrorStats.transferred);
        info->fileProcessed = jobInfo->stats.mig.disk_transferred +
                              jobInfo->mirrorStats.transferred;
        break;

    case QEMU_DOMAIN_JOB_STATS_TYPE_SAVEDUMP:
        info->memTotal = jobInfo->stats.mig.ram_total;
        info->memRemaining = jobInfo->stats.mig.ram_remaining;
        info->memProcessed = jobInfo->stats.mig.ram_transferred;
        break;

    case QEMU_DOMAIN_JOB_STATS_TYPE_MEMDUMP:
        info->memTotal = jobInfo->stats.dump.total;
        info->memProcessed = jobInfo->stats.dump.completed;
        info->memRemaining = info->memTotal - info->memProcessed;
        break;

    case QEMU_DOMAIN_JOB_STATS_TYPE_BACKUP:
        info->fileTotal = jobInfo->stats.backup.total;
        info->fileProcessed = jobInfo->stats.backup.transferred;
        info->fileRemaining = info->fileTotal - info->fileProcessed;
        break;

    case QEMU_DOMAIN_JOB_STATS_TYPE_NONE:
        break;
    }

    info->dataTotal = info->memTotal + info->fileTotal;
    info->dataRemaining = info->memRemaining + info->fileRemaining;
    info->dataProcessed = info->memProcessed + info->fileProcessed;

    return 0;
}


static int
qemuDomainMigrationJobInfoToParams(qemuDomainJobInfoPtr jobInfo,
                                   int *type,
                                   virTypedParameterPtr *params,
                                   int *nparams)
{
    qemuMonitorMigrationStats *stats = &jobInfo->stats.mig;
    qemuDomainMirrorStatsPtr mirrorStats = &jobInfo->mirrorStats;
    virTypedParameterPtr par = NULL;
    int maxpar = 0;
    int npar = 0;
    unsigned long long mirrorRemaining = mirrorStats->total -
                                         mirrorStats->transferred;

    if (virTypedParamsAddInt(&par, &npar, &maxpar,
                             VIR_DOMAIN_JOB_OPERATION,
                             jobInfo->operation) < 0)
        goto error;

    if (virTypedParamsAddULLong(&par, &npar, &maxpar,
                                VIR_DOMAIN_JOB_TIME_ELAPSED,
                                jobInfo->timeElapsed) < 0)
        goto error;

    if (jobInfo->timeDeltaSet &&
        jobInfo->timeElapsed > jobInfo->timeDelta &&
        virTypedParamsAddULLong(&par, &npar, &maxpar,
                                VIR_DOMAIN_JOB_TIME_ELAPSED_NET,
                                jobInfo->timeElapsed - jobInfo->timeDelta) < 0)
        goto error;

    if (stats->downtime_set &&
        virTypedParamsAddULLong(&par, &npar, &maxpar,
                                VIR_DOMAIN_JOB_DOWNTIME,
                                stats->downtime) < 0)
        goto error;

    if (stats->downtime_set &&
        jobInfo->timeDeltaSet &&
        stats->downtime > jobInfo->timeDelta &&
        virTypedParamsAddULLong(&par, &npar, &maxpar,
                                VIR_DOMAIN_JOB_DOWNTIME_NET,
                                stats->downtime - jobInfo->timeDelta) < 0)
        goto error;

    if (stats->setup_time_set &&
        virTypedParamsAddULLong(&par, &npar, &maxpar,
                                VIR_DOMAIN_JOB_SETUP_TIME,
                                stats->setup_time) < 0)
        goto error;

    if (virTypedParamsAddULLong(&par, &npar, &maxpar,
                                VIR_DOMAIN_JOB_DATA_TOTAL,
                                stats->ram_total +
                                stats->disk_total +
                                mirrorStats->total) < 0 ||
        virTypedParamsAddULLong(&par, &npar, &maxpar,
                                VIR_DOMAIN_JOB_DATA_PROCESSED,
                                stats->ram_transferred +
                                stats->disk_transferred +
                                mirrorStats->transferred) < 0 ||
        virTypedParamsAddULLong(&par, &npar, &maxpar,
                                VIR_DOMAIN_JOB_DATA_REMAINING,
                                stats->ram_remaining +
                                stats->disk_remaining +
                                mirrorRemaining) < 0)
        goto error;

    if (virTypedParamsAddULLong(&par, &npar, &maxpar,
                                VIR_DOMAIN_JOB_MEMORY_TOTAL,
                                stats->ram_total) < 0 ||
        virTypedParamsAddULLong(&par, &npar, &maxpar,
                                VIR_DOMAIN_JOB_MEMORY_PROCESSED,
                                stats->ram_transferred) < 0 ||
        virTypedParamsAddULLong(&par, &npar, &maxpar,
                                VIR_DOMAIN_JOB_MEMORY_REMAINING,
                                stats->ram_remaining) < 0)
        goto error;

    if (stats->ram_bps &&
        virTypedParamsAddULLong(&par, &npar, &maxpar,
                                VIR_DOMAIN_JOB_MEMORY_BPS,
                                stats->ram_bps) < 0)
        goto error;

    if (stats->ram_duplicate_set) {
        if (virTypedParamsAddULLong(&par, &npar, &maxpar,
                                    VIR_DOMAIN_JOB_MEMORY_CONSTANT,
                                    stats->ram_duplicate) < 0 ||
            virTypedParamsAddULLong(&par, &npar, &maxpar,
                                    VIR_DOMAIN_JOB_MEMORY_NORMAL,
                                    stats->ram_normal) < 0 ||
            virTypedParamsAddULLong(&par, &npar, &maxpar,
                                    VIR_DOMAIN_JOB_MEMORY_NORMAL_BYTES,
                                    stats->ram_normal_bytes) < 0)
            goto error;
    }

    if (virTypedParamsAddULLong(&par, &npar, &maxpar,
                                VIR_DOMAIN_JOB_MEMORY_DIRTY_RATE,
                                stats->ram_dirty_rate) < 0 ||
        virTypedParamsAddULLong(&par, &npar, &maxpar,
                                VIR_DOMAIN_JOB_MEMORY_ITERATION,
                                stats->ram_iteration) < 0 ||
        virTypedParamsAddULLong(&par, &npar, &maxpar,
                                VIR_DOMAIN_JOB_MEMORY_POSTCOPY_REQS,
                                stats->ram_postcopy_reqs) < 0)
        goto error;

    if (stats->ram_page_size > 0 &&
        virTypedParamsAddULLong(&par, &npar, &maxpar,
                                VIR_DOMAIN_JOB_MEMORY_PAGE_SIZE,
                                stats->ram_page_size) < 0)
        goto error;

    /* The remaining stats are disk, mirror, or migration specific
     * so if this is a SAVEDUMP, we can just skip them */
    if (jobInfo->statsType == QEMU_DOMAIN_JOB_STATS_TYPE_SAVEDUMP)
        goto done;

    if (virTypedParamsAddULLong(&par, &npar, &maxpar,
                                VIR_DOMAIN_JOB_DISK_TOTAL,
                                stats->disk_total +
                                mirrorStats->total) < 0 ||
        virTypedParamsAddULLong(&par, &npar, &maxpar,
                                VIR_DOMAIN_JOB_DISK_PROCESSED,
                                stats->disk_transferred +
                                mirrorStats->transferred) < 0 ||
        virTypedParamsAddULLong(&par, &npar, &maxpar,
                                VIR_DOMAIN_JOB_DISK_REMAINING,
                                stats->disk_remaining +
                                mirrorRemaining) < 0)
        goto error;

    if (stats->disk_bps &&
        virTypedParamsAddULLong(&par, &npar, &maxpar,
                                VIR_DOMAIN_JOB_DISK_BPS,
                                stats->disk_bps) < 0)
        goto error;

    if (stats->xbzrle_set) {
        if (virTypedParamsAddULLong(&par, &npar, &maxpar,
                                    VIR_DOMAIN_JOB_COMPRESSION_CACHE,
                                    stats->xbzrle_cache_size) < 0 ||
            virTypedParamsAddULLong(&par, &npar, &maxpar,
                                    VIR_DOMAIN_JOB_COMPRESSION_BYTES,
                                    stats->xbzrle_bytes) < 0 ||
            virTypedParamsAddULLong(&par, &npar, &maxpar,
                                    VIR_DOMAIN_JOB_COMPRESSION_PAGES,
                                    stats->xbzrle_pages) < 0 ||
            virTypedParamsAddULLong(&par, &npar, &maxpar,
                                    VIR_DOMAIN_JOB_COMPRESSION_CACHE_MISSES,
                                    stats->xbzrle_cache_miss) < 0 ||
            virTypedParamsAddULLong(&par, &npar, &maxpar,
                                    VIR_DOMAIN_JOB_COMPRESSION_OVERFLOW,
                                    stats->xbzrle_overflow) < 0)
            goto error;
    }

    if (stats->cpu_throttle_percentage &&
        virTypedParamsAddInt(&par, &npar, &maxpar,
                             VIR_DOMAIN_JOB_AUTO_CONVERGE_THROTTLE,
                             stats->cpu_throttle_percentage) < 0)
        goto error;

 done:
    *type = qemuDomainJobStatusToType(jobInfo->status);
    *params = par;
    *nparams = npar;
    return 0;

 error:
    virTypedParamsFree(par, npar);
    return -1;
}


static int
qemuDomainDumpJobInfoToParams(qemuDomainJobInfoPtr jobInfo,
                              int *type,
                              virTypedParameterPtr *params,
                              int *nparams)
{
    qemuMonitorDumpStats *stats = &jobInfo->stats.dump;
    virTypedParameterPtr par = NULL;
    int maxpar = 0;
    int npar = 0;

    if (virTypedParamsAddInt(&par, &npar, &maxpar,
                             VIR_DOMAIN_JOB_OPERATION,
                             jobInfo->operation) < 0)
        goto error;

    if (virTypedParamsAddULLong(&par, &npar, &maxpar,
                                VIR_DOMAIN_JOB_TIME_ELAPSED,
                                jobInfo->timeElapsed) < 0)
        goto error;

    if (virTypedParamsAddULLong(&par, &npar, &maxpar,
                                VIR_DOMAIN_JOB_MEMORY_TOTAL,
                                stats->total) < 0 ||
        virTypedParamsAddULLong(&par, &npar, &maxpar,
                                VIR_DOMAIN_JOB_MEMORY_PROCESSED,
                                stats->completed) < 0 ||
        virTypedParamsAddULLong(&par, &npar, &maxpar,
                                VIR_DOMAIN_JOB_MEMORY_REMAINING,
                                stats->total - stats->completed) < 0)
        goto error;

    *type = qemuDomainJobStatusToType(jobInfo->status);
    *params = par;
    *nparams = npar;
    return 0;

 error:
    virTypedParamsFree(par, npar);
    return -1;
}


static int
qemuDomainBackupJobInfoToParams(qemuDomainJobInfoPtr jobInfo,
                                int *type,
                                virTypedParameterPtr *params,
                                int *nparams)
{
    qemuDomainBackupStats *stats = &jobInfo->stats.backup;
    g_autoptr(virTypedParamList) par = g_new0(virTypedParamList, 1);

    if (virTypedParamListAddInt(par, jobInfo->operation,
                                VIR_DOMAIN_JOB_OPERATION) < 0)
        return -1;

    if (virTypedParamListAddULLong(par, jobInfo->timeElapsed,
                                   VIR_DOMAIN_JOB_TIME_ELAPSED) < 0)
        return -1;

    if (stats->transferred > 0 || stats->total > 0) {
        if (virTypedParamListAddULLong(par, stats->total,
                                       VIR_DOMAIN_JOB_DISK_TOTAL) < 0)
            return -1;

        if (virTypedParamListAddULLong(par, stats->transferred,
                                       VIR_DOMAIN_JOB_DISK_PROCESSED) < 0)
            return -1;

        if (virTypedParamListAddULLong(par, stats->total - stats->transferred,
                                       VIR_DOMAIN_JOB_DISK_REMAINING) < 0)
            return -1;
    }

    if (stats->tmp_used > 0 || stats->tmp_total > 0) {
        if (virTypedParamListAddULLong(par, stats->tmp_used,
                                       VIR_DOMAIN_JOB_DISK_TEMP_USED) < 0)
            return -1;

        if (virTypedParamListAddULLong(par, stats->tmp_total,
                                       VIR_DOMAIN_JOB_DISK_TEMP_TOTAL) < 0)
            return -1;
    }

    if (jobInfo->status != QEMU_DOMAIN_JOB_STATUS_ACTIVE &&
        virTypedParamListAddBoolean(par,
                                    jobInfo->status == QEMU_DOMAIN_JOB_STATUS_COMPLETED,
                                    VIR_DOMAIN_JOB_SUCCESS) < 0)
        return -1;

    if (jobInfo->errmsg &&
        virTypedParamListAddString(par, jobInfo->errmsg, VIR_DOMAIN_JOB_ERRMSG) < 0)
        return -1;

    *nparams = virTypedParamListStealParams(par, params);
    *type = qemuDomainJobStatusToType(jobInfo->status);
    return 0;
}


int
qemuDomainJobInfoToParams(qemuDomainJobInfoPtr jobInfo,
                          int *type,
                          virTypedParameterPtr *params,
                          int *nparams)
{
    switch (jobInfo->statsType) {
    case QEMU_DOMAIN_JOB_STATS_TYPE_MIGRATION:
    case QEMU_DOMAIN_JOB_STATS_TYPE_SAVEDUMP:
        return qemuDomainMigrationJobInfoToParams(jobInfo, type, params, nparams);

    case QEMU_DOMAIN_JOB_STATS_TYPE_MEMDUMP:
        return qemuDomainDumpJobInfoToParams(jobInfo, type, params, nparams);

    case QEMU_DOMAIN_JOB_STATS_TYPE_BACKUP:
        return qemuDomainBackupJobInfoToParams(jobInfo, type, params, nparams);

    case QEMU_DOMAIN_JOB_STATS_TYPE_NONE:
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("invalid job statistics type"));
        break;

    default:
        virReportEnumRangeError(qemuDomainJobStatsType, jobInfo->statsType);
        break;
    }

    return -1;
}


void
qemuDomainObjSetJobPhase(virQEMUDriverPtr driver,
                         virDomainObjPtr obj,
                         int phase)
{
    qemuDomainObjPrivatePtr priv = obj->privateData;
    unsigned long long me = virThreadSelfID();

    if (!priv->job.asyncJob)
        return;

    VIR_DEBUG("Setting '%s' phase to '%s'",
              qemuDomainAsyncJobTypeToString(priv->job.asyncJob),
              qemuDomainAsyncJobPhaseToString(priv->job.asyncJob, phase));

    if (priv->job.asyncOwner && me != priv->job.asyncOwner) {
        VIR_WARN("'%s' async job is owned by thread %llu",
                 qemuDomainAsyncJobTypeToString(priv->job.asyncJob),
                 priv->job.asyncOwner);
    }

    priv->job.phase = phase;
    priv->job.asyncOwner = me;
    qemuDomainObjSaveStatus(driver, obj);
}

void
qemuDomainObjSetAsyncJobMask(virDomainObjPtr obj,
                             unsigned long long allowedJobs)
{
    qemuDomainObjPrivatePtr priv = obj->privateData;

    if (!priv->job.asyncJob)
        return;

    priv->job.mask = allowedJobs | JOB_MASK(QEMU_JOB_DESTROY);
}

void
qemuDomainObjDiscardAsyncJob(virQEMUDriverPtr driver, virDomainObjPtr obj)
{
    qemuDomainObjPrivatePtr priv = obj->privateData;

    if (priv->job.active == QEMU_JOB_ASYNC_NESTED)
        qemuDomainObjResetJob(&priv->job);
    qemuDomainObjResetAsyncJob(&priv->job);
    qemuDomainObjSaveStatus(driver, obj);
}

void
qemuDomainObjReleaseAsyncJob(virDomainObjPtr obj)
{
    qemuDomainObjPrivatePtr priv = obj->privateData;

    VIR_DEBUG("Releasing ownership of '%s' async job",
              qemuDomainAsyncJobTypeToString(priv->job.asyncJob));

    if (priv->job.asyncOwner != virThreadSelfID()) {
        VIR_WARN("'%s' async job is owned by thread %llu",
                 qemuDomainAsyncJobTypeToString(priv->job.asyncJob),
                 priv->job.asyncOwner);
    }
    priv->job.asyncOwner = 0;
}

static bool
qemuDomainNestedJobAllowed(qemuDomainJobObjPtr jobs, qemuDomainJob newJob)
{
    return !jobs->asyncJob ||
           newJob == QEMU_JOB_NONE ||
           (jobs->mask & JOB_MASK(newJob)) != 0;
}

bool
qemuDomainJobAllowed(qemuDomainJobObjPtr jobs, qemuDomainJob newJob)
{
    return !jobs->active && qemuDomainNestedJobAllowed(jobs, newJob);
}

static bool
qemuDomainObjCanSetJob(qemuDomainJobObjPtr job,
                       qemuDomainJob newJob,
                       qemuDomainAgentJob newAgentJob)
{
    return ((newJob == QEMU_JOB_NONE ||
             job->active == QEMU_JOB_NONE) &&
            (newAgentJob == QEMU_AGENT_JOB_NONE ||
             job->agentActive == QEMU_AGENT_JOB_NONE));
}

/* Give up waiting for mutex after 30 seconds */
#define QEMU_JOB_WAIT_TIME (1000ull * 30)

/**
 * qemuDomainObjBeginJobInternal:
 * @driver: qemu driver
 * @obj: domain object
 * @job: qemuDomainJob to start
 * @asyncJob: qemuDomainAsyncJob to start
 * @nowait: don't wait trying to acquire @job
 *
 * Acquires job for a domain object which must be locked before
 * calling. If there's already a job running waits up to
 * QEMU_JOB_WAIT_TIME after which the functions fails reporting
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
static int ATTRIBUTE_NONNULL(1)
qemuDomainObjBeginJobInternal(virQEMUDriverPtr driver,
                              virDomainObjPtr obj,
                              qemuDomainJob job,
                              qemuDomainAgentJob agentJob,
                              qemuDomainAsyncJob asyncJob,
                              bool nowait)
{
    qemuDomainObjPrivatePtr priv = obj->privateData;
    unsigned long long now;
    unsigned long long then;
    bool nested = job == QEMU_JOB_ASYNC_NESTED;
    bool async = job == QEMU_JOB_ASYNC;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    const char *blocker = NULL;
    const char *agentBlocker = NULL;
    int ret = -1;
    unsigned long long duration = 0;
    unsigned long long agentDuration = 0;
    unsigned long long asyncDuration = 0;

    VIR_DEBUG("Starting job: job=%s agentJob=%s asyncJob=%s "
              "(vm=%p name=%s, current job=%s agentJob=%s async=%s)",
              qemuDomainJobTypeToString(job),
              qemuDomainAgentJobTypeToString(agentJob),
              qemuDomainAsyncJobTypeToString(asyncJob),
              obj, obj->def->name,
              qemuDomainJobTypeToString(priv->job.active),
              qemuDomainAgentJobTypeToString(priv->job.agentActive),
              qemuDomainAsyncJobTypeToString(priv->job.asyncJob));

    if (virTimeMillisNow(&now) < 0)
        return -1;

    priv->jobs_queued++;
    then = now + QEMU_JOB_WAIT_TIME;

 retry:
    if ((!async && job != QEMU_JOB_DESTROY) &&
        cfg->maxQueuedJobs &&
        priv->jobs_queued > cfg->maxQueuedJobs) {
        goto error;
    }

    while (!nested && !qemuDomainNestedJobAllowed(&priv->job, job)) {
        if (nowait)
            goto cleanup;

        VIR_DEBUG("Waiting for async job (vm=%p name=%s)", obj, obj->def->name);
        if (virCondWaitUntil(&priv->job.asyncCond, &obj->parent.lock, then) < 0)
            goto error;
    }

    while (!qemuDomainObjCanSetJob(&priv->job, job, agentJob)) {
        if (nowait)
            goto cleanup;

        VIR_DEBUG("Waiting for job (vm=%p name=%s)", obj, obj->def->name);
        if (virCondWaitUntil(&priv->job.cond, &obj->parent.lock, then) < 0)
            goto error;
    }

    /* No job is active but a new async job could have been started while obj
     * was unlocked, so we need to recheck it. */
    if (!nested && !qemuDomainNestedJobAllowed(&priv->job, job))
        goto retry;

    ignore_value(virTimeMillisNow(&now));

    if (job) {
        qemuDomainObjResetJob(&priv->job);

        if (job != QEMU_JOB_ASYNC) {
            VIR_DEBUG("Started job: %s (async=%s vm=%p name=%s)",
                      qemuDomainJobTypeToString(job),
                      qemuDomainAsyncJobTypeToString(priv->job.asyncJob),
                      obj, obj->def->name);
            priv->job.active = job;
            priv->job.owner = virThreadSelfID();
            priv->job.ownerAPI = virThreadJobGet();
            priv->job.started = now;
        } else {
            VIR_DEBUG("Started async job: %s (vm=%p name=%s)",
                      qemuDomainAsyncJobTypeToString(asyncJob),
                      obj, obj->def->name);
            qemuDomainObjResetAsyncJob(&priv->job);
            priv->job.current = g_new0(qemuDomainJobInfo, 1);
            priv->job.current->status = QEMU_DOMAIN_JOB_STATUS_ACTIVE;
            priv->job.asyncJob = asyncJob;
            priv->job.asyncOwner = virThreadSelfID();
            priv->job.asyncOwnerAPI = virThreadJobGet();
            priv->job.asyncStarted = now;
            priv->job.current->started = now;
        }
    }

    if (agentJob) {
        qemuDomainObjResetAgentJob(&priv->job);

        VIR_DEBUG("Started agent job: %s (vm=%p name=%s job=%s async=%s)",
                  qemuDomainAgentJobTypeToString(agentJob),
                  obj, obj->def->name,
                  qemuDomainJobTypeToString(priv->job.active),
                  qemuDomainAsyncJobTypeToString(priv->job.asyncJob));
        priv->job.agentActive = agentJob;
        priv->job.agentOwner = virThreadSelfID();
        priv->job.agentOwnerAPI = virThreadJobGet();
        priv->job.agentStarted = now;
    }

    if (qemuDomainTrackJob(job))
        qemuDomainObjSaveStatus(driver, obj);

    return 0;

 error:
    ignore_value(virTimeMillisNow(&now));
    if (priv->job.active && priv->job.started)
        duration = now - priv->job.started;
    if (priv->job.agentActive && priv->job.agentStarted)
        agentDuration = now - priv->job.agentStarted;
    if (priv->job.asyncJob && priv->job.asyncStarted)
        asyncDuration = now - priv->job.asyncStarted;

    VIR_WARN("Cannot start job (%s, %s, %s) for domain %s; "
             "current job is (%s, %s, %s) "
             "owned by (%llu %s, %llu %s, %llu %s (flags=0x%lx)) "
             "for (%llus, %llus, %llus)",
             qemuDomainJobTypeToString(job),
             qemuDomainAgentJobTypeToString(agentJob),
             qemuDomainAsyncJobTypeToString(asyncJob),
             obj->def->name,
             qemuDomainJobTypeToString(priv->job.active),
             qemuDomainAgentJobTypeToString(priv->job.agentActive),
             qemuDomainAsyncJobTypeToString(priv->job.asyncJob),
             priv->job.owner, NULLSTR(priv->job.ownerAPI),
             priv->job.agentOwner, NULLSTR(priv->job.agentOwnerAPI),
             priv->job.asyncOwner, NULLSTR(priv->job.asyncOwnerAPI),
             priv->job.apiFlags,
             duration / 1000, agentDuration / 1000, asyncDuration / 1000);

    if (job) {
        if (nested || qemuDomainNestedJobAllowed(&priv->job, job))
            blocker = priv->job.ownerAPI;
        else
            blocker = priv->job.asyncOwnerAPI;
    }

    if (agentJob)
        agentBlocker = priv->job.agentOwnerAPI;

    if (errno == ETIMEDOUT) {
        if (blocker && agentBlocker) {
            virReportError(VIR_ERR_OPERATION_TIMEOUT,
                           _("cannot acquire state change "
                             "lock (held by monitor=%s agent=%s)"),
                           blocker, agentBlocker);
        } else if (blocker) {
            virReportError(VIR_ERR_OPERATION_TIMEOUT,
                           _("cannot acquire state change "
                             "lock (held by monitor=%s)"),
                           blocker);
        } else if (agentBlocker) {
            virReportError(VIR_ERR_OPERATION_TIMEOUT,
                           _("cannot acquire state change "
                             "lock (held by agent=%s)"),
                           agentBlocker);
        } else {
            virReportError(VIR_ERR_OPERATION_TIMEOUT, "%s",
                           _("cannot acquire state change lock"));
        }
        ret = -2;
    } else if (cfg->maxQueuedJobs &&
               priv->jobs_queued > cfg->maxQueuedJobs) {
        if (blocker && agentBlocker) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("cannot acquire state change "
                             "lock (held by monitor=%s agent=%s) "
                             "due to max_queued limit"),
                           blocker, agentBlocker);
        } else if (blocker) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("cannot acquire state change "
                             "lock (held by monitor=%s) "
                             "due to max_queued limit"),
                           blocker);
        } else if (agentBlocker) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("cannot acquire state change "
                             "lock (held by agent=%s) "
                             "due to max_queued limit"),
                           agentBlocker);
        } else {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("cannot acquire state change lock "
                             "due to max_queued limit"));
        }
        ret = -2;
    } else {
        virReportSystemError(errno, "%s", _("cannot acquire job mutex"));
    }

 cleanup:
    priv->jobs_queued--;
    return ret;
}

/*
 * obj must be locked before calling
 *
 * This must be called by anything that will change the VM state
 * in any way, or anything that will use the QEMU monitor.
 *
 * Successful calls must be followed by EndJob eventually
 */
int qemuDomainObjBeginJob(virQEMUDriverPtr driver,
                          virDomainObjPtr obj,
                          qemuDomainJob job)
{
    if (qemuDomainObjBeginJobInternal(driver, obj, job,
                                      QEMU_AGENT_JOB_NONE,
                                      QEMU_ASYNC_JOB_NONE, false) < 0)
        return -1;
    else
        return 0;
}

/**
 * qemuDomainObjBeginAgentJob:
 *
 * Grabs agent type of job. Use if caller talks to guest agent only.
 *
 * To end job call qemuDomainObjEndAgentJob.
 */
int
qemuDomainObjBeginAgentJob(virQEMUDriverPtr driver,
                           virDomainObjPtr obj,
                           qemuDomainAgentJob agentJob)
{
    return qemuDomainObjBeginJobInternal(driver, obj, QEMU_JOB_NONE,
                                         agentJob,
                                         QEMU_ASYNC_JOB_NONE, false);
}

int qemuDomainObjBeginAsyncJob(virQEMUDriverPtr driver,
                               virDomainObjPtr obj,
                               qemuDomainAsyncJob asyncJob,
                               virDomainJobOperation operation,
                               unsigned long apiFlags)
{
    qemuDomainObjPrivatePtr priv;

    if (qemuDomainObjBeginJobInternal(driver, obj, QEMU_JOB_ASYNC,
                                      QEMU_AGENT_JOB_NONE,
                                      asyncJob, false) < 0)
        return -1;

    priv = obj->privateData;
    priv->job.current->operation = operation;
    priv->job.apiFlags = apiFlags;
    return 0;
}

int
qemuDomainObjBeginNestedJob(virQEMUDriverPtr driver,
                            virDomainObjPtr obj,
                            qemuDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivatePtr priv = obj->privateData;

    if (asyncJob != priv->job.asyncJob) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected async job %d type expected %d"),
                       asyncJob, priv->job.asyncJob);
        return -1;
    }

    if (priv->job.asyncOwner != virThreadSelfID()) {
        VIR_WARN("This thread doesn't seem to be the async job owner: %llu",
                 priv->job.asyncOwner);
    }

    return qemuDomainObjBeginJobInternal(driver, obj,
                                         QEMU_JOB_ASYNC_NESTED,
                                         QEMU_AGENT_JOB_NONE,
                                         QEMU_ASYNC_JOB_NONE,
                                         false);
}

/**
 * qemuDomainObjBeginJobNowait:
 *
 * @driver: qemu driver
 * @obj: domain object
 * @job: qemuDomainJob to start
 *
 * Acquires job for a domain object which must be locked before
 * calling. If there's already a job running it returns
 * immediately without any error reported.
 *
 * Returns: see qemuDomainObjBeginJobInternal
 */
int
qemuDomainObjBeginJobNowait(virQEMUDriverPtr driver,
                            virDomainObjPtr obj,
                            qemuDomainJob job)
{
    return qemuDomainObjBeginJobInternal(driver, obj, job,
                                         QEMU_AGENT_JOB_NONE,
                                         QEMU_ASYNC_JOB_NONE, true);
}

/*
 * obj must be locked and have a reference before calling
 *
 * To be called after completing the work associated with the
 * earlier qemuDomainBeginJob() call
 */
void
qemuDomainObjEndJob(virQEMUDriverPtr driver, virDomainObjPtr obj)
{
    qemuDomainObjPrivatePtr priv = obj->privateData;
    qemuDomainJob job = priv->job.active;

    priv->jobs_queued--;

    VIR_DEBUG("Stopping job: %s (async=%s vm=%p name=%s)",
              qemuDomainJobTypeToString(job),
              qemuDomainAsyncJobTypeToString(priv->job.asyncJob),
              obj, obj->def->name);

    qemuDomainObjResetJob(&priv->job);
    if (qemuDomainTrackJob(job))
        qemuDomainObjSaveStatus(driver, obj);
    /* We indeed need to wake up ALL threads waiting because
     * grabbing a job requires checking more variables. */
    virCondBroadcast(&priv->job.cond);
}

void
qemuDomainObjEndAgentJob(virDomainObjPtr obj)
{
    qemuDomainObjPrivatePtr priv = obj->privateData;
    qemuDomainAgentJob agentJob = priv->job.agentActive;

    priv->jobs_queued--;

    VIR_DEBUG("Stopping agent job: %s (async=%s vm=%p name=%s)",
              qemuDomainAgentJobTypeToString(agentJob),
              qemuDomainAsyncJobTypeToString(priv->job.asyncJob),
              obj, obj->def->name);

    qemuDomainObjResetAgentJob(&priv->job);
    /* We indeed need to wake up ALL threads waiting because
     * grabbing a job requires checking more variables. */
    virCondBroadcast(&priv->job.cond);
}

void
qemuDomainObjEndAsyncJob(virQEMUDriverPtr driver, virDomainObjPtr obj)
{
    qemuDomainObjPrivatePtr priv = obj->privateData;

    priv->jobs_queued--;

    VIR_DEBUG("Stopping async job: %s (vm=%p name=%s)",
              qemuDomainAsyncJobTypeToString(priv->job.asyncJob),
              obj, obj->def->name);

    qemuDomainObjResetAsyncJob(&priv->job);
    qemuDomainObjSaveStatus(driver, obj);
    virCondBroadcast(&priv->job.asyncCond);
}

void
qemuDomainObjAbortAsyncJob(virDomainObjPtr obj)
{
    qemuDomainObjPrivatePtr priv = obj->privateData;

    VIR_DEBUG("Requesting abort of async job: %s (vm=%p name=%s)",
              qemuDomainAsyncJobTypeToString(priv->job.asyncJob),
              obj, obj->def->name);

    priv->job.abortJob = true;
    virDomainObjBroadcast(obj);
}


static int
qemuDomainObjPrivateXMLFormatNBDMigrationSource(virBufferPtr buf,
                                                virStorageSourcePtr src,
                                                virDomainXMLOptionPtr xmlopt)
{
    g_auto(virBuffer) attrBuf = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) childBuf = VIR_BUFFER_INIT_CHILD(buf);

    virBufferAsprintf(&attrBuf, " type='%s' format='%s'",
                      virStorageTypeToString(src->type),
                      virStorageFileFormatTypeToString(src->format));

    if (virDomainDiskSourceFormat(&childBuf, src, "source", 0, false,
                                  VIR_DOMAIN_DEF_FORMAT_STATUS,
                                  false, false, xmlopt) < 0)
        return -1;

    virXMLFormatElement(buf, "migrationSource", &attrBuf, &childBuf);

    return 0;
}


static int
qemuDomainObjPrivateXMLFormatNBDMigration(virBufferPtr buf,
                                          virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    size_t i;
    virDomainDiskDefPtr disk;
    qemuDomainDiskPrivatePtr diskPriv;

    for (i = 0; i < vm->def->ndisks; i++) {
        g_auto(virBuffer) attrBuf = VIR_BUFFER_INITIALIZER;
        g_auto(virBuffer) childBuf = VIR_BUFFER_INIT_CHILD(buf);
        disk = vm->def->disks[i];
        diskPriv = QEMU_DOMAIN_DISK_PRIVATE(disk);

        virBufferAsprintf(&attrBuf, " dev='%s' migrating='%s'",
                          disk->dst, diskPriv->migrating ? "yes" : "no");

        if (diskPriv->migrSource &&
            qemuDomainObjPrivateXMLFormatNBDMigrationSource(&childBuf,
                                                            diskPriv->migrSource,
                                                            priv->driver->xmlopt) < 0)
            return -1;

        virXMLFormatElement(buf, "disk", &attrBuf, &childBuf);
    }

    return 0;
}

int
qemuDomainObjPrivateXMLFormatJob(virBufferPtr buf,
                                 virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    qemuDomainJobObjPtr jobObj = &priv->job;
    g_auto(virBuffer) attrBuf = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) childBuf = VIR_BUFFER_INIT_CHILD(buf);
    qemuDomainJob job = priv->job.active;

    if (!qemuDomainTrackJob(job))
        job = QEMU_JOB_NONE;

    if (job == QEMU_JOB_NONE &&
        priv->job.asyncJob == QEMU_ASYNC_JOB_NONE)
        return 0;

    virBufferAsprintf(&attrBuf, " type='%s' async='%s'",
                      qemuDomainJobTypeToString(job),
                      qemuDomainAsyncJobTypeToString(priv->job.asyncJob));

    if (priv->job.phase) {
        virBufferAsprintf(&attrBuf, " phase='%s'",
                          qemuDomainAsyncJobPhaseToString(priv->job.asyncJob,
                                                          priv->job.phase));
    }

    if (priv->job.asyncJob != QEMU_ASYNC_JOB_NONE)
        virBufferAsprintf(&attrBuf, " flags='0x%lx'", priv->job.apiFlags);

    if (priv->job.asyncJob == QEMU_ASYNC_JOB_MIGRATION_OUT &&
        qemuDomainObjPrivateXMLFormatNBDMigration(&childBuf, vm) < 0)
        return -1;

    if (jobObj->cb->formatJob(&childBuf, jobObj) < 0)
        return -1;

    virXMLFormatElement(buf, "job", &attrBuf, &childBuf);

    return 0;
}


static int
qemuDomainObjPrivateXMLParseJobNBDSource(xmlNodePtr node,
                                         xmlXPathContextPtr ctxt,
                                         virDomainDiskDefPtr disk,
                                         virDomainXMLOptionPtr xmlopt)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt);
    qemuDomainDiskPrivatePtr diskPriv = QEMU_DOMAIN_DISK_PRIVATE(disk);
    g_autofree char *format = NULL;
    g_autofree char *type = NULL;
    g_autoptr(virStorageSource) migrSource = NULL;
    xmlNodePtr sourceNode;

    ctxt->node = node;

    if (!(ctxt->node = virXPathNode("./migrationSource", ctxt)))
        return 0;

    if (!(type = virXMLPropString(ctxt->node, "type"))) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing storage source type"));
        return -1;
    }

    if (!(format = virXMLPropString(ctxt->node, "format"))) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing storage source format"));
        return -1;
    }

    if (!(migrSource = virDomainStorageSourceParseBase(type, format, NULL)))
        return -1;

    /* newer libvirt uses the <source> subelement instead of formatting the
     * source directly into <migrationSource> */
    if ((sourceNode = virXPathNode("./source", ctxt)))
        ctxt->node = sourceNode;

    if (virDomainStorageSourceParse(ctxt->node, ctxt, migrSource,
                                    VIR_DOMAIN_DEF_PARSE_STATUS, xmlopt) < 0)
        return -1;

    diskPriv->migrSource = g_steal_pointer(&migrSource);
    return 0;
}


static int
qemuDomainObjPrivateXMLParseJobNBD(virDomainObjPtr vm,
                                   xmlXPathContextPtr ctxt)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    g_autofree xmlNodePtr *nodes = NULL;
    size_t i;
    int n;

    if ((n = virXPathNodeSet("./disk[@migrating='yes']", ctxt, &nodes)) < 0)
        return -1;

    if (n > 0) {
        if (priv->job.asyncJob != QEMU_ASYNC_JOB_MIGRATION_OUT) {
            VIR_WARN("Found disks marked for migration but we were not "
                     "migrating");
            n = 0;
        }
        for (i = 0; i < n; i++) {
            virDomainDiskDefPtr disk;
            g_autofree char *dst = NULL;

            if ((dst = virXMLPropString(nodes[i], "dev")) &&
                (disk = virDomainDiskByTarget(vm->def, dst))) {
                QEMU_DOMAIN_DISK_PRIVATE(disk)->migrating = true;

                if (qemuDomainObjPrivateXMLParseJobNBDSource(nodes[i], ctxt,
                                                             disk,
                                                             priv->driver->xmlopt) < 0)
                    return -1;
            }
        }
    }

    return 0;
}

int
qemuDomainObjPrivateXMLParseJob(virDomainObjPtr vm,
                                xmlXPathContextPtr ctxt)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    qemuDomainJobObjPtr job = &priv->job;
    VIR_XPATH_NODE_AUTORESTORE(ctxt);
    g_autofree char *tmp = NULL;

    if (!(ctxt->node = virXPathNode("./job[1]", ctxt)))
        return 0;

    if ((tmp = virXPathString("string(@type)", ctxt))) {
        int type;

        if ((type = qemuDomainJobTypeFromString(tmp)) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unknown job type %s"), tmp);
            return -1;
        }
        VIR_FREE(tmp);
        priv->job.active = type;
    }

    if ((tmp = virXPathString("string(@async)", ctxt))) {
        int async;

        if ((async = qemuDomainAsyncJobTypeFromString(tmp)) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unknown async job type %s"), tmp);
            return -1;
        }
        VIR_FREE(tmp);
        priv->job.asyncJob = async;

        if ((tmp = virXPathString("string(@phase)", ctxt))) {
            priv->job.phase = qemuDomainAsyncJobPhaseFromString(async, tmp);
            if (priv->job.phase < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Unknown job phase %s"), tmp);
                return -1;
            }
            VIR_FREE(tmp);
        }
    }

    if (virXPathULongHex("string(@flags)", ctxt, &priv->job.apiFlags) == -2) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid job flags"));
        return -1;
    }

    if (qemuDomainObjPrivateXMLParseJobNBD(vm, ctxt) < 0)
        return -1;

    if (job->cb->parseJob(ctxt, job) < 0)
        return -1;

    return 0;
}
