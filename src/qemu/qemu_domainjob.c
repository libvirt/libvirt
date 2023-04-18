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
    virObjectEvent *event;
    virTypedParameterPtr params = NULL;
    int nparams = 0;
    int type;

    if (!vm->job->completed)
        return;

    if (qemuDomainJobDataToParams(vm->job->completed, &type,
                                  &params, &nparams) < 0) {
        VIR_WARN("Could not get stats for completed job; domain %s",
                 vm->def->name);
    }

    event = virDomainEventJobCompletedNewFromObj(vm, params, nparams);
    virObjectEventStateQueue(driver->domainEventState, event);
}


void
qemuDomainObjRestoreAsyncJob(virDomainObj *vm,
                             virDomainAsyncJob asyncJob,
                             int phase,
                             unsigned long long started,
                             virDomainJobOperation operation,
                             qemuDomainJobStatsType statsType,
                             virDomainJobStatus status,
                             unsigned long long allowedJobs)
{
    virDomainJobObj *job = vm->job;

    VIR_DEBUG("Restoring %s async job for domain %s",
              virDomainAsyncJobTypeToString(asyncJob), vm->def->name);

    if (started == 0)
        ignore_value(virTimeMillisNow(&started));

    job->jobsQueued++;
    job->asyncJob = asyncJob;
    job->phase = phase;
    job->asyncOwnerAPI = g_strdup(virThreadJobGet());
    job->asyncStarted = started;

    qemuDomainObjSetAsyncJobMask(vm, allowedJobs);

    job->current = virDomainJobDataInit(&virQEMUDriverDomainJobConfig.jobDataPrivateCb);
    qemuDomainJobSetStatsType(vm->job->current, statsType);
    job->current->operation = operation;
    job->current->status = status;
    job->current->started = started;
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
    g_autoptr(virTypedParamList) par = virTypedParamListNew();

    virTypedParamListAddInt(par, jobData->operation, VIR_DOMAIN_JOB_OPERATION);
    virTypedParamListAddULLong(par, jobData->timeElapsed, VIR_DOMAIN_JOB_TIME_ELAPSED);

    if (stats->transferred > 0 || stats->total > 0) {
        virTypedParamListAddULLong(par, stats->total, VIR_DOMAIN_JOB_DISK_TOTAL);
        virTypedParamListAddULLong(par, stats->transferred, VIR_DOMAIN_JOB_DISK_PROCESSED);
        virTypedParamListAddULLong(par, stats->total - stats->transferred, VIR_DOMAIN_JOB_DISK_REMAINING);
    }

    if (stats->tmp_used > 0 || stats->tmp_total > 0) {
        virTypedParamListAddULLong(par, stats->tmp_used, VIR_DOMAIN_JOB_DISK_TEMP_USED);
        virTypedParamListAddULLong(par, stats->tmp_total, VIR_DOMAIN_JOB_DISK_TEMP_TOTAL);
    }

    if (jobData->status != VIR_DOMAIN_JOB_STATUS_ACTIVE)
        virTypedParamListAddBoolean(par, jobData->status == VIR_DOMAIN_JOB_STATUS_COMPLETED,
                                    VIR_DOMAIN_JOB_SUCCESS);

    if (jobData->errmsg)
        virTypedParamListAddString(par, jobData->errmsg, VIR_DOMAIN_JOB_ERRMSG);

    if (virTypedParamListSteal(par, params, nparams) < 0)
        return -1;

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


/*
 * Sets the job phase without changing the job owner. The owner is supposed to
 * be 0 or the current thread, a warning is issued otherwise.
 */
void
qemuDomainObjSetJobPhase(virDomainObj *obj,
                         int phase)
{
    unsigned long long me = virThreadSelfID();

    if (!obj->job->asyncJob)
        return;

    VIR_DEBUG("Setting '%s' phase to '%s'",
              virDomainAsyncJobTypeToString(obj->job->asyncJob),
              qemuDomainAsyncJobPhaseToString(obj->job->asyncJob, phase));

    if (obj->job->asyncOwner != 0 &&
        obj->job->asyncOwner != me) {
        VIR_WARN("'%s' async job is owned by thread %llu, API '%s'",
                 virDomainAsyncJobTypeToString(obj->job->asyncJob),
                 obj->job->asyncOwner,
                 NULLSTR(obj->job->asyncOwnerAPI));
    }

    obj->job->phase = phase;
    qemuDomainSaveStatus(obj);
}


/*
 * Changes the job owner and sets the job phase. The current owner is supposed
 * to be 0 or the current thread, a warning is issued otherwise.
 */
void
qemuDomainObjStartJobPhase(virDomainObj *obj,
                           int phase)
{
    unsigned long long me = virThreadSelfID();

    if (!obj->job->asyncJob)
        return;

    VIR_DEBUG("Starting phase '%s' of '%s' job",
              qemuDomainAsyncJobPhaseToString(obj->job->asyncJob, phase),
              virDomainAsyncJobTypeToString(obj->job->asyncJob));

    if (obj->job->asyncOwner == 0) {
        obj->job->asyncOwnerAPI = g_strdup(virThreadJobGet());
    } else if (me != obj->job->asyncOwner) {
        VIR_WARN("'%s' async job is owned by thread %llu, API '%s'",
                 virDomainAsyncJobTypeToString(obj->job->asyncJob),
                 obj->job->asyncOwner,
                 NULLSTR(obj->job->asyncOwnerAPI));
    }

    obj->job->asyncOwner = me;
    qemuDomainObjSetJobPhase(obj, phase);
}


void
qemuDomainObjSetAsyncJobMask(virDomainObj *obj,
                             unsigned long long allowedJobs)
{
    if (!obj->job->asyncJob)
        return;

    obj->job->mask = allowedJobs | JOB_MASK(VIR_JOB_DESTROY);
}

void
qemuDomainObjDiscardAsyncJob(virDomainObj *obj)
{
    if (obj->job->active == VIR_JOB_ASYNC_NESTED)
        virDomainObjResetJob(obj->job);
    virDomainObjResetAsyncJob(obj->job);
    qemuDomainSaveStatus(obj);
}

void
qemuDomainObjReleaseAsyncJob(virDomainObj *obj)
{
    VIR_DEBUG("Releasing ownership of '%s' async job",
              virDomainAsyncJobTypeToString(obj->job->asyncJob));

    if (obj->job->asyncOwner != 0 &&
        obj->job->asyncOwner != virThreadSelfID()) {
        VIR_WARN("'%s' async job is owned by thread %llu",
                 virDomainAsyncJobTypeToString(obj->job->asyncJob),
                 obj->job->asyncOwner);
    }
    obj->job->asyncOwner = 0;
}

void
qemuDomainObjAbortAsyncJob(virDomainObj *obj)
{
    VIR_DEBUG("Requesting abort of async job: %s (vm=%p name=%s)",
              virDomainAsyncJobTypeToString(obj->job->asyncJob),
              obj, obj->def->name);

    obj->job->abortJob = true;
    virDomainObjBroadcast(obj);
}

int
qemuDomainObjPrivateXMLFormatJob(virBuffer *buf,
                                 virDomainObj *vm)
{
    g_auto(virBuffer) attrBuf = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) childBuf = VIR_BUFFER_INIT_CHILD(buf);
    virDomainJob job = vm->job->active;

    if (!virDomainTrackJob(job))
        job = VIR_JOB_NONE;

    if (job == VIR_JOB_NONE &&
        vm->job->asyncJob == VIR_ASYNC_JOB_NONE)
        return 0;

    virBufferAsprintf(&attrBuf, " type='%s' async='%s'",
                      virDomainJobTypeToString(job),
                      virDomainAsyncJobTypeToString(vm->job->asyncJob));

    if (vm->job->phase) {
        virBufferAsprintf(&attrBuf, " phase='%s'",
                          qemuDomainAsyncJobPhaseToString(vm->job->asyncJob,
                                                          vm->job->phase));
    }

    if (vm->job->asyncJob != VIR_ASYNC_JOB_NONE) {
        virBufferAsprintf(&attrBuf, " flags='0x%x'", vm->job->apiFlags);
        virBufferAsprintf(&attrBuf, " asyncStarted='%llu'", vm->job->asyncStarted);
        if (vm->job->asyncPaused)
            virBufferAddLit(&attrBuf, " asyncPaused='yes'");
    }

    if (vm->job->cb &&
        vm->job->cb->formatJobPrivate(&childBuf, vm->job, vm) < 0)
        return -1;

    virXMLFormatElement(buf, "job", &attrBuf, &childBuf);

    return 0;
}


int
qemuDomainObjPrivateXMLParseJob(virDomainObj *vm,
                                xmlXPathContextPtr ctxt)
{
    virDomainJobObj *job = vm->job;
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    g_autofree char *tmp = NULL;

    if (!(ctxt->node = virXPathNode("./job[1]", ctxt)))
        return 0;

    if ((tmp = virXPathString("string(@type)", ctxt))) {
        int type;

        if ((type = virDomainJobTypeFromString(tmp)) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unknown job type %1$s"), tmp);
            return -1;
        }
        VIR_FREE(tmp);
        vm->job->active = type;
    }

    if ((tmp = virXPathString("string(@async)", ctxt))) {
        int async;
        virTristateBool paused;

        if ((async = virDomainAsyncJobTypeFromString(tmp)) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unknown async job type %1$s"), tmp);
            return -1;
        }
        VIR_FREE(tmp);
        vm->job->asyncJob = async;

        if ((tmp = virXPathString("string(@phase)", ctxt))) {
            vm->job->phase = qemuDomainAsyncJobPhaseFromString(async, tmp);
            if (vm->job->phase < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Unknown job phase %1$s"), tmp);
                return -1;
            }
            VIR_FREE(tmp);
        }

        if (virXPathULongLong("string(@asyncStarted)", ctxt,
                              &vm->job->asyncStarted) == -2) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Invalid async job start"));
            return -1;
        }

        if (virXMLPropTristateBool(ctxt->node, "asyncPaused", VIR_XML_PROP_NONE,
                                   &paused) < 0)
            return -1;

        vm->job->asyncPaused = paused == VIR_TRISTATE_BOOL_YES;
    }

    if (virXMLPropUInt(ctxt->node, "flags", 16, VIR_XML_PROP_NONE,
                       &vm->job->apiFlags) < 0)
        return -1;

    if (vm->job->cb &&
        vm->job->cb->parseJobPrivate(ctxt, job, vm) < 0)
        return -1;

    return 0;
}
