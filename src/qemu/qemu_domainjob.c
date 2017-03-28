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

static void *
qemuJobDataAllocPrivateData(void)
{
    return g_new0(qemuDomainJobDataPrivate, 1);
}


static void *
qemuJobDataCopyPrivateData(void *data)
{
    qemuDomainJobDataPrivate *ret = g_new0(qemuDomainJobDataPrivate, 1);

    memcpy(ret, data, sizeof(qemuDomainJobDataPrivate));

    return ret;
}


static void
qemuJobDataFreePrivateData(void *data)
{
    g_free(data);
}


virDomainJobDataPrivateDataCallbacks qemuJobDataPrivateDataCallbacks = {
    .allocPrivateData = qemuJobDataAllocPrivateData,
    .copyPrivateData = qemuJobDataCopyPrivateData,
    .freePrivateData = qemuJobDataFreePrivateData,
};


void
qemuDomainJobSetStatsType(virDomainJobData *jobData,
                          qemuDomainJobStatsType type)
{
    qemuDomainJobDataPrivate *privData = jobData->privateData;

    privData->statsType = type;
}


const char *
qemuDomainAsyncJobPhaseToString(virDomainAsyncJob job,
                                int phase G_GNUC_UNUSED)
{
    switch (job) {
    case VIR_ASYNC_JOB_MIGRATION_OUT:
    case VIR_ASYNC_JOB_MIGRATION_IN:
        return qemuMigrationJobPhaseTypeToString(phase);

    case VIR_ASYNC_JOB_SAVE:
    case VIR_ASYNC_JOB_DUMP:
    case VIR_ASYNC_JOB_SNAPSHOT:
    case VIR_ASYNC_JOB_START:
    case VIR_ASYNC_JOB_NONE:
    case VIR_ASYNC_JOB_BACKUP:
        G_GNUC_FALLTHROUGH;
    case VIR_ASYNC_JOB_LAST:
        break;
    }

    return "none";
}

int
qemuDomainAsyncJobPhaseFromString(virDomainAsyncJob job,
                                  const char *phase)
{
    if (!phase)
        return 0;

    switch (job) {
    case VIR_ASYNC_JOB_MIGRATION_OUT:
    case VIR_ASYNC_JOB_MIGRATION_IN:
        return qemuMigrationJobPhaseTypeFromString(phase);

    case VIR_ASYNC_JOB_SAVE:
    case VIR_ASYNC_JOB_DUMP:
    case VIR_ASYNC_JOB_SNAPSHOT:
    case VIR_ASYNC_JOB_START:
    case VIR_ASYNC_JOB_NONE:
    case VIR_ASYNC_JOB_BACKUP:
        G_GNUC_FALLTHROUGH;
    case VIR_ASYNC_JOB_LAST:
        break;
    }

    if (STREQ(phase, "none"))
        return 0;

    return -1;
}


void
qemuDomainEventEmitJobCompleted(virQEMUDriver *driver,
                                virDomainObj *vm)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    virObjectEvent *event;
    virTypedParameterPtr params = NULL;
    int nparams = 0;
    int type;

    if (!priv->job.completed)
        return;

    if (qemuDomainJobDataToParams(priv->job.completed, &type,
                                  &params, &nparams) < 0) {
        VIR_WARN("Could not get stats for completed job; domain %s",
                 vm->def->name);
    }

    event = virDomainEventJobCompletedNewFromObj(vm, params, nparams);
    virObjectEventStateQueue(driver->domainEventState, event);
}


int
qemuDomainObjInitJob(qemuDomainJobObj *job,
                     qemuDomainObjPrivateJobCallbacks *cb)
{
    memset(job, 0, sizeof(*job));
    job->cb = cb;

    if (virCondInit(&job->cond) < 0)
        return -1;

    if (virCondInit(&job->asyncCond) < 0) {
        virCondDestroy(&job->cond);
        return -1;
    }

    if (job->cb &&
        !(job->privateData = job->cb->allocJobPrivate())) {
        virCondDestroy(&job->cond);
        virCondDestroy(&job->asyncCond);
        return -1;
    }

    return 0;
}


static void
qemuDomainObjResetJob(qemuDomainJobObj *job)
{
    job->active = VIR_JOB_NONE;
    job->owner = 0;
    g_clear_pointer(&job->ownerAPI, g_free);
    job->started = 0;
}


static void
qemuDomainObjResetAgentJob(qemuDomainJobObj *job)
{
    job->agentActive = VIR_AGENT_JOB_NONE;
    job->agentOwner = 0;
    g_clear_pointer(&job->agentOwnerAPI, g_free);
    job->agentStarted = 0;
}


static void
qemuDomainObjResetAsyncJob(qemuDomainJobObj *job)
{
    job->asyncJob = VIR_ASYNC_JOB_NONE;
    job->asyncOwner = 0;
    g_clear_pointer(&job->asyncOwnerAPI, g_free);
    job->asyncStarted = 0;
    job->phase = 0;
    job->mask = VIR_JOB_DEFAULT_MASK;
    job->abortJob = false;
    VIR_FREE(job->error);
    g_clear_pointer(&job->current, virDomainJobDataFree);
    job->apiFlags = 0;

    if (job->cb)
        job->cb->resetJobPrivate(job->privateData);
}

int
qemuDomainObjRestoreJob(virDomainObj *obj,
                        qemuDomainJobObj *job)
{
    qemuDomainObjPrivate *priv = obj->privateData;

    memset(job, 0, sizeof(*job));
    job->active = priv->job.active;
    job->owner = priv->job.owner;
    job->asyncJob = priv->job.asyncJob;
    job->asyncOwner = priv->job.asyncOwner;
    job->phase = priv->job.phase;
    job->privateData = g_steal_pointer(&priv->job.privateData);
    job->apiFlags = priv->job.apiFlags;

    if (priv->job.cb &&
        !(priv->job.privateData = priv->job.cb->allocJobPrivate()))
        return -1;
    job->cb = priv->job.cb;

    qemuDomainObjResetJob(&priv->job);
    qemuDomainObjResetAsyncJob(&priv->job);
    return 0;
}

void
qemuDomainObjClearJob(qemuDomainJobObj *job)
{
    qemuDomainObjResetJob(job);
    qemuDomainObjResetAsyncJob(job);
    g_clear_pointer(&job->current, virDomainJobDataFree);
    g_clear_pointer(&job->completed, virDomainJobDataFree);
    virCondDestroy(&job->cond);
    virCondDestroy(&job->asyncCond);

    if (job->cb)
        g_clear_pointer(&job->privateData, job->cb->freeJobPrivate);
}

bool
qemuDomainTrackJob(virDomainJob job)
{
    return (VIR_DOMAIN_TRACK_JOBS & JOB_MASK(job)) != 0;
}


int
qemuDomainJobDataUpdateTime(virDomainJobData *jobData)
{
    unsigned long long now;

    if (!jobData->started)
        return 0;

    if (virTimeMillisNow(&now) < 0)
        return -1;

    if (now < jobData->started) {
        VIR_WARN("Async job starts in the future");
        jobData->started = 0;
        return 0;
    }

    jobData->timeElapsed = now - jobData->started;
    return 0;
}

int
qemuDomainJobDataUpdateDowntime(virDomainJobData *jobData)
{
    unsigned long long now;
    qemuDomainJobDataPrivate *priv = jobData->privateData;

    if (!jobData->stopped)
        return 0;

    if (virTimeMillisNow(&now) < 0)
        return -1;

    if (now < jobData->stopped) {
        VIR_WARN("Guest's CPUs stopped in the future");
        jobData->stopped = 0;
        return 0;
    }

    priv->stats.mig.downtime = now - jobData->stopped;
    priv->stats.mig.downtime_set = true;
    return 0;
}


int
qemuDomainJobDataToInfo(virDomainJobData *jobData,
                        virDomainJobInfoPtr info)
{
    qemuDomainJobDataPrivate *priv = jobData->privateData;
    info->type = virDomainJobStatusToType(jobData->status);
    info->timeElapsed = jobData->timeElapsed;

    switch (priv->statsType) {
    case QEMU_DOMAIN_JOB_STATS_TYPE_MIGRATION:
        info->memTotal = priv->stats.mig.ram_total;
        info->memRemaining = priv->stats.mig.ram_remaining;
        info->memProcessed = priv->stats.mig.ram_transferred;
        info->fileTotal = priv->stats.mig.disk_total +
                          priv->mirrorStats.total;
        info->fileRemaining = priv->stats.mig.disk_remaining +
                              (priv->mirrorStats.total -
                               priv->mirrorStats.transferred);
        info->fileProcessed = priv->stats.mig.disk_transferred +
                              priv->mirrorStats.transferred;
        break;

    case QEMU_DOMAIN_JOB_STATS_TYPE_SAVEDUMP:
        info->memTotal = priv->stats.mig.ram_total;
        info->memRemaining = priv->stats.mig.ram_remaining;
        info->memProcessed = priv->stats.mig.ram_transferred;
        break;

    case QEMU_DOMAIN_JOB_STATS_TYPE_MEMDUMP:
        info->memTotal = priv->stats.dump.total;
        info->memProcessed = priv->stats.dump.completed;
        info->memRemaining = info->memTotal - info->memProcessed;
        break;

    case QEMU_DOMAIN_JOB_STATS_TYPE_BACKUP:
        info->fileTotal = priv->stats.backup.total;
        info->fileProcessed = priv->stats.backup.transferred;
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
qemuDomainMigrationJobDataToParams(virDomainJobData *jobData,
                                   int *type,
                                   virTypedParameterPtr *params,
                                   int *nparams)
{
    qemuDomainJobDataPrivate *priv = jobData->privateData;
    qemuMonitorMigrationStats *stats = &priv->stats.mig;
    qemuDomainMirrorStats *mirrorStats = &priv->mirrorStats;
    virTypedParameterPtr par = NULL;
    int maxpar = 0;
    int npar = 0;
    unsigned long long mirrorRemaining = mirrorStats->total -
                                         mirrorStats->transferred;

    if (virTypedParamsAddInt(&par, &npar, &maxpar,
                             VIR_DOMAIN_JOB_OPERATION,
                             jobData->operation) < 0)
        goto error;

    if (virTypedParamsAddULLong(&par, &npar, &maxpar,
                                VIR_DOMAIN_JOB_TIME_ELAPSED,
                                jobData->timeElapsed) < 0)
        goto error;

    if (jobData->timeDeltaSet &&
        jobData->timeElapsed > jobData->timeDelta &&
        virTypedParamsAddULLong(&par, &npar, &maxpar,
                                VIR_DOMAIN_JOB_TIME_ELAPSED_NET,
                                jobData->timeElapsed - jobData->timeDelta) < 0)
        goto error;

    if (stats->downtime_set &&
        virTypedParamsAddULLong(&par, &npar, &maxpar,
                                VIR_DOMAIN_JOB_DOWNTIME,
                                stats->downtime) < 0)
        goto error;

    if (stats->downtime_set &&
        jobData->timeDeltaSet &&
        stats->downtime > jobData->timeDelta &&
        virTypedParamsAddULLong(&par, &npar, &maxpar,
                                VIR_DOMAIN_JOB_DOWNTIME_NET,
                                stats->downtime - jobData->timeDelta) < 0)
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
    if (priv->statsType == QEMU_DOMAIN_JOB_STATS_TYPE_SAVEDUMP)
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
    *type = virDomainJobStatusToType(jobData->status);
    *params = par;
    *nparams = npar;
    return 0;

 error:
    virTypedParamsFree(par, npar);
    return -1;
}


static int
qemuDomainDumpJobDataToParams(virDomainJobData *jobData,
                              int *type,
                              virTypedParameterPtr *params,
                              int *nparams)
{
    qemuDomainJobDataPrivate *priv = jobData->privateData;
    qemuMonitorDumpStats *stats = &priv->stats.dump;
    virTypedParameterPtr par = NULL;
    int maxpar = 0;
    int npar = 0;

    if (virTypedParamsAddInt(&par, &npar, &maxpar,
                             VIR_DOMAIN_JOB_OPERATION,
                             jobData->operation) < 0)
        goto error;

    if (virTypedParamsAddULLong(&par, &npar, &maxpar,
                                VIR_DOMAIN_JOB_TIME_ELAPSED,
                                jobData->timeElapsed) < 0)
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

    *type = virDomainJobStatusToType(jobData->status);
    *params = par;
    *nparams = npar;
    return 0;

 error:
    virTypedParamsFree(par, npar);
    return -1;
}


static int
qemuDomainBackupJobDataToParams(virDomainJobData *jobData,
                                int *type,
                                virTypedParameterPtr *params,
                                int *nparams)
{
    qemuDomainJobDataPrivate *priv = jobData->privateData;
    qemuDomainBackupStats *stats = &priv->stats.backup;
    g_autoptr(virTypedParamList) par = g_new0(virTypedParamList, 1);

    if (virTypedParamListAddInt(par, jobData->operation,
                                VIR_DOMAIN_JOB_OPERATION) < 0)
        return -1;

    if (virTypedParamListAddULLong(par, jobData->timeElapsed,
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

    if (jobData->status != VIR_DOMAIN_JOB_STATUS_ACTIVE &&
        virTypedParamListAddBoolean(par,
                                    jobData->status == VIR_DOMAIN_JOB_STATUS_COMPLETED,
                                    VIR_DOMAIN_JOB_SUCCESS) < 0)
        return -1;

    if (jobData->errmsg &&
        virTypedParamListAddString(par, jobData->errmsg, VIR_DOMAIN_JOB_ERRMSG) < 0)
        return -1;

    *nparams = virTypedParamListStealParams(par, params);
    *type = virDomainJobStatusToType(jobData->status);
    return 0;
}


int
qemuDomainJobDataToParams(virDomainJobData *jobData,
                          int *type,
                          virTypedParameterPtr *params,
                          int *nparams)
{
    qemuDomainJobDataPrivate *priv = jobData->privateData;

    switch (priv->statsType) {
    case QEMU_DOMAIN_JOB_STATS_TYPE_MIGRATION:
    case QEMU_DOMAIN_JOB_STATS_TYPE_SAVEDUMP:
        return qemuDomainMigrationJobDataToParams(jobData, type, params, nparams);

    case QEMU_DOMAIN_JOB_STATS_TYPE_MEMDUMP:
        return qemuDomainDumpJobDataToParams(jobData, type, params, nparams);

    case QEMU_DOMAIN_JOB_STATS_TYPE_BACKUP:
        return qemuDomainBackupJobDataToParams(jobData, type, params, nparams);

    case QEMU_DOMAIN_JOB_STATS_TYPE_NONE:
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("invalid job statistics type"));
        break;

    default:
        virReportEnumRangeError(qemuDomainJobStatsType, priv->statsType);
        break;
    }

    return -1;
}


void
qemuDomainObjSetJobPhase(virDomainObj *obj,
                         int phase)
{
    qemuDomainObjPrivate *priv = obj->privateData;
    unsigned long long me = virThreadSelfID();

    if (!priv->job.asyncJob)
        return;

    VIR_DEBUG("Setting '%s' phase to '%s'",
              virDomainAsyncJobTypeToString(priv->job.asyncJob),
              qemuDomainAsyncJobPhaseToString(priv->job.asyncJob, phase));

    if (priv->job.asyncOwner == 0) {
        priv->job.asyncOwnerAPI = g_strdup(virThreadJobGet());
    } else if (me != priv->job.asyncOwner) {
        VIR_WARN("'%s' async job is owned by thread %llu",
                 virDomainAsyncJobTypeToString(priv->job.asyncJob),
                 priv->job.asyncOwner);
    }

    priv->job.phase = phase;
    priv->job.asyncOwner = me;
    qemuDomainSaveStatus(obj);
}

void
qemuDomainObjSetAsyncJobMask(virDomainObj *obj,
                             unsigned long long allowedJobs)
{
    qemuDomainObjPrivate *priv = obj->privateData;

    if (!priv->job.asyncJob)
        return;

    priv->job.mask = allowedJobs | JOB_MASK(VIR_JOB_DESTROY);
}

void
qemuDomainObjDiscardAsyncJob(virDomainObj *obj)
{
    qemuDomainObjPrivate *priv = obj->privateData;

    if (priv->job.active == VIR_JOB_ASYNC_NESTED)
        qemuDomainObjResetJob(&priv->job);
    qemuDomainObjResetAsyncJob(&priv->job);
    qemuDomainSaveStatus(obj);
}

void
qemuDomainObjReleaseAsyncJob(virDomainObj *obj)
{
    qemuDomainObjPrivate *priv = obj->privateData;

    VIR_DEBUG("Releasing ownership of '%s' async job",
              virDomainAsyncJobTypeToString(priv->job.asyncJob));

    if (priv->job.asyncOwner != virThreadSelfID()) {
        VIR_WARN("'%s' async job is owned by thread %llu",
                 virDomainAsyncJobTypeToString(priv->job.asyncJob),
                 priv->job.asyncOwner);
    }
    priv->job.asyncOwner = 0;
}

static bool
qemuDomainNestedJobAllowed(qemuDomainJobObj *jobs, virDomainJob newJob)
{
    return !jobs->asyncJob ||
           newJob == VIR_JOB_NONE ||
           (jobs->mask & JOB_MASK(newJob)) != 0;
}

static bool
qemuDomainObjCanSetJob(qemuDomainJobObj *job,
                       virDomainJob newJob,
                       virDomainAgentJob newAgentJob)
{
    return ((newJob == VIR_JOB_NONE ||
             job->active == VIR_JOB_NONE) &&
            (newAgentJob == VIR_AGENT_JOB_NONE ||
             job->agentActive == VIR_AGENT_JOB_NONE));
}

/* Give up waiting for mutex after 30 seconds */
#define QEMU_JOB_WAIT_TIME (1000ull * 30)

/**
 * qemuDomainObjBeginJobInternal:
 * @driver: qemu driver
 * @obj: domain object
 * @job: virDomainJob to start
 * @asyncJob: virDomainAsyncJob to start
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
qemuDomainObjBeginJobInternal(virQEMUDriver *driver,
                              virDomainObj *obj,
                              virDomainJob job,
                              virDomainAgentJob agentJob,
                              virDomainAsyncJob asyncJob,
                              bool nowait)
{
    qemuDomainObjPrivate *priv = obj->privateData;
    unsigned long long now;
    unsigned long long then;
    bool nested = job == VIR_JOB_ASYNC_NESTED;
    bool async = job == VIR_JOB_ASYNC;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
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
              virDomainJobTypeToString(priv->job.active),
              virDomainAgentJobTypeToString(priv->job.agentActive),
              virDomainAsyncJobTypeToString(priv->job.asyncJob));

    if (virTimeMillisNow(&now) < 0)
        return -1;

    priv->job.jobsQueued++;
    then = now + QEMU_JOB_WAIT_TIME;

 retry:
    if ((!async && job != VIR_JOB_DESTROY) &&
        cfg->maxQueuedJobs &&
        priv->job.jobsQueued > cfg->maxQueuedJobs) {
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

    if (obj->removing) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];

        virUUIDFormat(obj->def->uuid, uuidstr);
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching uuid '%s' (%s)"),
                       uuidstr, obj->def->name);
        goto cleanup;
    }

    ignore_value(virTimeMillisNow(&now));

    if (job) {
        qemuDomainObjResetJob(&priv->job);

        if (job != VIR_JOB_ASYNC) {
            VIR_DEBUG("Started job: %s (async=%s vm=%p name=%s)",
                      virDomainJobTypeToString(job),
                      virDomainAsyncJobTypeToString(priv->job.asyncJob),
                      obj, obj->def->name);
            priv->job.active = job;
            priv->job.owner = virThreadSelfID();
            priv->job.ownerAPI = g_strdup(virThreadJobGet());
            priv->job.started = now;
        } else {
            VIR_DEBUG("Started async job: %s (vm=%p name=%s)",
                      virDomainAsyncJobTypeToString(asyncJob),
                      obj, obj->def->name);
            qemuDomainObjResetAsyncJob(&priv->job);
            priv->job.current = virDomainJobDataInit(&qemuJobDataPrivateDataCallbacks);
            priv->job.current->status = VIR_DOMAIN_JOB_STATUS_ACTIVE;
            priv->job.asyncJob = asyncJob;
            priv->job.asyncOwner = virThreadSelfID();
            priv->job.asyncOwnerAPI = g_strdup(virThreadJobGet());
            priv->job.asyncStarted = now;
            priv->job.current->started = now;
        }
    }

    if (agentJob) {
        qemuDomainObjResetAgentJob(&priv->job);

        VIR_DEBUG("Started agent job: %s (vm=%p name=%s job=%s async=%s)",
                  virDomainAgentJobTypeToString(agentJob),
                  obj, obj->def->name,
                  virDomainJobTypeToString(priv->job.active),
                  virDomainAsyncJobTypeToString(priv->job.asyncJob));
        priv->job.agentActive = agentJob;
        priv->job.agentOwner = virThreadSelfID();
        priv->job.agentOwnerAPI = g_strdup(virThreadJobGet());
        priv->job.agentStarted = now;
    }

    if (qemuDomainTrackJob(job))
        qemuDomainSaveStatus(obj);

    return 0;

 error:
    ignore_value(virTimeMillisNow(&now));
    if (priv->job.active && priv->job.started)
        duration = now - priv->job.started;
    if (priv->job.agentActive && priv->job.agentStarted)
        agentDuration = now - priv->job.agentStarted;
    if (priv->job.asyncJob && priv->job.asyncStarted)
        asyncDuration = now - priv->job.asyncStarted;

    VIR_WARN("Cannot start job (%s, %s, %s) in API %s for domain %s; "
             "current job is (%s, %s, %s) "
             "owned by (%llu %s, %llu %s, %llu %s (flags=0x%lx)) "
             "for (%llus, %llus, %llus)",
             virDomainJobTypeToString(job),
             virDomainAgentJobTypeToString(agentJob),
             virDomainAsyncJobTypeToString(asyncJob),
             NULLSTR(currentAPI),
             obj->def->name,
             virDomainJobTypeToString(priv->job.active),
             virDomainAgentJobTypeToString(priv->job.agentActive),
             virDomainAsyncJobTypeToString(priv->job.asyncJob),
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
               priv->job.jobsQueued > cfg->maxQueuedJobs) {
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
    priv->job.jobsQueued--;
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
int qemuDomainObjBeginJob(virQEMUDriver *driver,
                          virDomainObj *obj,
                          virDomainJob job)
{
    if (qemuDomainObjBeginJobInternal(driver, obj, job,
                                      VIR_AGENT_JOB_NONE,
                                      VIR_ASYNC_JOB_NONE, false) < 0)
        return -1;
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
qemuDomainObjBeginAgentJob(virQEMUDriver *driver,
                           virDomainObj *obj,
                           virDomainAgentJob agentJob)
{
    return qemuDomainObjBeginJobInternal(driver, obj, VIR_JOB_NONE,
                                         agentJob,
                                         VIR_ASYNC_JOB_NONE, false);
}

int qemuDomainObjBeginAsyncJob(virQEMUDriver *driver,
                               virDomainObj *obj,
                               virDomainAsyncJob asyncJob,
                               virDomainJobOperation operation,
                               unsigned long apiFlags)
{
    qemuDomainObjPrivate *priv;

    if (qemuDomainObjBeginJobInternal(driver, obj, VIR_JOB_ASYNC,
                                      VIR_AGENT_JOB_NONE,
                                      asyncJob, false) < 0)
        return -1;

    priv = obj->privateData;
    priv->job.current->operation = operation;
    priv->job.apiFlags = apiFlags;
    return 0;
}

int
qemuDomainObjBeginNestedJob(virQEMUDriver *driver,
                            virDomainObj *obj,
                            virDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivate *priv = obj->privateData;

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
                                         VIR_JOB_ASYNC_NESTED,
                                         VIR_AGENT_JOB_NONE,
                                         VIR_ASYNC_JOB_NONE,
                                         false);
}

/**
 * qemuDomainObjBeginJobNowait:
 *
 * @driver: qemu driver
 * @obj: domain object
 * @job: virDomainJob to start
 *
 * Acquires job for a domain object which must be locked before
 * calling. If there's already a job running it returns
 * immediately without any error reported.
 *
 * Returns: see qemuDomainObjBeginJobInternal
 */
int
qemuDomainObjBeginJobNowait(virQEMUDriver *driver,
                            virDomainObj *obj,
                            virDomainJob job)
{
    return qemuDomainObjBeginJobInternal(driver, obj, job,
                                         VIR_AGENT_JOB_NONE,
                                         VIR_ASYNC_JOB_NONE, true);
}

/*
 * obj must be locked and have a reference before calling
 *
 * To be called after completing the work associated with the
 * earlier qemuDomainBeginJob() call
 */
void
qemuDomainObjEndJob(virDomainObj *obj)
{
    qemuDomainObjPrivate *priv = obj->privateData;
    virDomainJob job = priv->job.active;

    priv->job.jobsQueued--;

    VIR_DEBUG("Stopping job: %s (async=%s vm=%p name=%s)",
              virDomainJobTypeToString(job),
              virDomainAsyncJobTypeToString(priv->job.asyncJob),
              obj, obj->def->name);

    qemuDomainObjResetJob(&priv->job);
    if (qemuDomainTrackJob(job))
        qemuDomainSaveStatus(obj);
    /* We indeed need to wake up ALL threads waiting because
     * grabbing a job requires checking more variables. */
    virCondBroadcast(&priv->job.cond);
}

void
qemuDomainObjEndAgentJob(virDomainObj *obj)
{
    qemuDomainObjPrivate *priv = obj->privateData;
    virDomainAgentJob agentJob = priv->job.agentActive;

    priv->job.jobsQueued--;

    VIR_DEBUG("Stopping agent job: %s (async=%s vm=%p name=%s)",
              virDomainAgentJobTypeToString(agentJob),
              virDomainAsyncJobTypeToString(priv->job.asyncJob),
              obj, obj->def->name);

    qemuDomainObjResetAgentJob(&priv->job);
    /* We indeed need to wake up ALL threads waiting because
     * grabbing a job requires checking more variables. */
    virCondBroadcast(&priv->job.cond);
}

void
qemuDomainObjEndAsyncJob(virDomainObj *obj)
{
    qemuDomainObjPrivate *priv = obj->privateData;

    priv->job.jobsQueued--;

    VIR_DEBUG("Stopping async job: %s (vm=%p name=%s)",
              virDomainAsyncJobTypeToString(priv->job.asyncJob),
              obj, obj->def->name);

    qemuDomainObjResetAsyncJob(&priv->job);
    qemuDomainSaveStatus(obj);
    virCondBroadcast(&priv->job.asyncCond);
}

void
qemuDomainObjAbortAsyncJob(virDomainObj *obj)
{
    qemuDomainObjPrivate *priv = obj->privateData;

    VIR_DEBUG("Requesting abort of async job: %s (vm=%p name=%s)",
              virDomainAsyncJobTypeToString(priv->job.asyncJob),
              obj, obj->def->name);

    priv->job.abortJob = true;
    virDomainObjBroadcast(obj);
}

int
qemuDomainObjPrivateXMLFormatJob(virBuffer *buf,
                                 virDomainObj *vm)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    g_auto(virBuffer) attrBuf = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) childBuf = VIR_BUFFER_INIT_CHILD(buf);
    virDomainJob job = priv->job.active;

    if (!qemuDomainTrackJob(job))
        job = VIR_JOB_NONE;

    if (job == VIR_JOB_NONE &&
        priv->job.asyncJob == VIR_ASYNC_JOB_NONE)
        return 0;

    virBufferAsprintf(&attrBuf, " type='%s' async='%s'",
                      virDomainJobTypeToString(job),
                      virDomainAsyncJobTypeToString(priv->job.asyncJob));

    if (priv->job.phase) {
        virBufferAsprintf(&attrBuf, " phase='%s'",
                          qemuDomainAsyncJobPhaseToString(priv->job.asyncJob,
                                                          priv->job.phase));
    }

    if (priv->job.asyncJob != VIR_ASYNC_JOB_NONE)
        virBufferAsprintf(&attrBuf, " flags='0x%lx'", priv->job.apiFlags);

    if (priv->job.cb &&
        priv->job.cb->formatJob(&childBuf, &priv->job, vm) < 0)
        return -1;

    virXMLFormatElement(buf, "job", &attrBuf, &childBuf);

    return 0;
}


int
qemuDomainObjPrivateXMLParseJob(virDomainObj *vm,
                                xmlXPathContextPtr ctxt)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    qemuDomainJobObj *job = &priv->job;
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    g_autofree char *tmp = NULL;

    if (!(ctxt->node = virXPathNode("./job[1]", ctxt)))
        return 0;

    if ((tmp = virXPathString("string(@type)", ctxt))) {
        int type;

        if ((type = virDomainJobTypeFromString(tmp)) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unknown job type %s"), tmp);
            return -1;
        }
        VIR_FREE(tmp);
        priv->job.active = type;
    }

    if ((tmp = virXPathString("string(@async)", ctxt))) {
        int async;

        if ((async = virDomainAsyncJobTypeFromString(tmp)) < 0) {
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

    if (priv->job.cb &&
        priv->job.cb->parseJob(ctxt, job, vm) < 0)
        return -1;

    return 0;
}
