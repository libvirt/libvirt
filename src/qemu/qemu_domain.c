/*
 * qemu_domain.c: QEMU domain private state
 *
 * Copyright (C) 2006-2015 Red Hat, Inc.
 * Copyright (C) 2006 Daniel P. Berrange
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
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include "qemu_domain.h"
#include "qemu_command.h"
#include "qemu_capabilities.h"
#include "qemu_migration.h"
#include "viralloc.h"
#include "virlog.h"
#include "virerror.h"
#include "c-ctype.h"
#include "cpu/cpu.h"
#include "viruuid.h"
#include "virfile.h"
#include "domain_addr.h"
#include "domain_event.h"
#include "virtime.h"
#include "virstoragefile.h"
#include "virstring.h"
#include "virthreadjob.h"

#include "storage/storage_driver.h"

#include <sys/time.h>
#include <fcntl.h>

#include <libxml/xpathInternals.h>

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_domain");

#define QEMU_NAMESPACE_HREF "http://libvirt.org/schemas/domain/qemu/1.0"

VIR_ENUM_IMPL(qemuDomainJob, QEMU_JOB_LAST,
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

VIR_ENUM_IMPL(qemuDomainAsyncJob, QEMU_ASYNC_JOB_LAST,
              "none",
              "migration out",
              "migration in",
              "save",
              "dump",
              "snapshot",
);


const char *
qemuDomainAsyncJobPhaseToString(qemuDomainAsyncJob job,
                                int phase ATTRIBUTE_UNUSED)
{
    switch (job) {
    case QEMU_ASYNC_JOB_MIGRATION_OUT:
    case QEMU_ASYNC_JOB_MIGRATION_IN:
        return qemuMigrationJobPhaseTypeToString(phase);

    case QEMU_ASYNC_JOB_SAVE:
    case QEMU_ASYNC_JOB_DUMP:
    case QEMU_ASYNC_JOB_SNAPSHOT:
    case QEMU_ASYNC_JOB_NONE:
    case QEMU_ASYNC_JOB_LAST:
        ; /* fall through */
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
    case QEMU_ASYNC_JOB_NONE:
    case QEMU_ASYNC_JOB_LAST:
        ; /* fall through */
    }

    if (STREQ(phase, "none"))
        return 0;
    else
        return -1;
}


void qemuDomainEventQueue(virQEMUDriverPtr driver,
                          virObjectEventPtr event)
{
    if (event)
        virObjectEventStateQueue(driver->domainEventState, event);
}


static int
qemuDomainObjInitJob(qemuDomainObjPrivatePtr priv)
{
    memset(&priv->job, 0, sizeof(priv->job));

    if (virCondInit(&priv->job.cond) < 0)
        return -1;

    if (virCondInit(&priv->job.asyncCond) < 0) {
        virCondDestroy(&priv->job.cond);
        return -1;
    }

    return 0;
}

static void
qemuDomainObjResetJob(qemuDomainObjPrivatePtr priv)
{
    struct qemuDomainJobObj *job = &priv->job;

    job->active = QEMU_JOB_NONE;
    job->owner = 0;
    job->ownerAPI = NULL;
    job->started = 0;
}

static void
qemuDomainObjResetAsyncJob(qemuDomainObjPrivatePtr priv)
{
    struct qemuDomainJobObj *job = &priv->job;

    job->asyncJob = QEMU_ASYNC_JOB_NONE;
    job->asyncOwner = 0;
    job->asyncOwnerAPI = NULL;
    job->asyncStarted = 0;
    job->phase = 0;
    job->mask = QEMU_JOB_DEFAULT_MASK;
    job->dump_memory_only = false;
    job->abortJob = false;
    job->spiceMigrated = false;
    VIR_FREE(job->current);
}

void
qemuDomainObjRestoreJob(virDomainObjPtr obj,
                        struct qemuDomainJobObj *job)
{
    qemuDomainObjPrivatePtr priv = obj->privateData;

    memset(job, 0, sizeof(*job));
    job->active = priv->job.active;
    job->owner = priv->job.owner;
    job->asyncJob = priv->job.asyncJob;
    job->asyncOwner = priv->job.asyncOwner;
    job->phase = priv->job.phase;

    qemuDomainObjResetJob(priv);
    qemuDomainObjResetAsyncJob(priv);
}

static void
qemuDomainObjFreeJob(qemuDomainObjPrivatePtr priv)
{
    VIR_FREE(priv->job.current);
    VIR_FREE(priv->job.completed);
    virCondDestroy(&priv->job.cond);
    virCondDestroy(&priv->job.asyncCond);
}

static bool
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

    jobInfo->status.downtime = now - jobInfo->stopped;
    jobInfo->status.downtime_set = true;
    return 0;
}

int
qemuDomainJobInfoToInfo(qemuDomainJobInfoPtr jobInfo,
                        virDomainJobInfoPtr info)
{
    info->type = jobInfo->type;
    info->timeElapsed = jobInfo->timeElapsed;
    info->timeRemaining = jobInfo->timeRemaining;

    info->memTotal = jobInfo->status.ram_total;
    info->memRemaining = jobInfo->status.ram_remaining;
    info->memProcessed = jobInfo->status.ram_transferred;

    info->fileTotal = jobInfo->status.disk_total;
    info->fileRemaining = jobInfo->status.disk_remaining;
    info->fileProcessed = jobInfo->status.disk_transferred;

    info->dataTotal = info->memTotal + info->fileTotal;
    info->dataRemaining = info->memRemaining + info->fileRemaining;
    info->dataProcessed = info->memProcessed + info->fileProcessed;

    return 0;
}

int
qemuDomainJobInfoToParams(qemuDomainJobInfoPtr jobInfo,
                          int *type,
                          virTypedParameterPtr *params,
                          int *nparams)
{
    qemuMonitorMigrationStatus *status = &jobInfo->status;
    virTypedParameterPtr par = NULL;
    int maxpar = 0;
    int npar = 0;

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

    if (jobInfo->type == VIR_DOMAIN_JOB_BOUNDED &&
        virTypedParamsAddULLong(&par, &npar, &maxpar,
                                VIR_DOMAIN_JOB_TIME_REMAINING,
                                jobInfo->timeRemaining) < 0)
        goto error;

    if (status->downtime_set &&
        virTypedParamsAddULLong(&par, &npar, &maxpar,
                                VIR_DOMAIN_JOB_DOWNTIME,
                                status->downtime) < 0)
        goto error;

    if (status->downtime_set &&
        jobInfo->timeDeltaSet &&
        status->downtime > jobInfo->timeDelta &&
        virTypedParamsAddULLong(&par, &npar, &maxpar,
                                VIR_DOMAIN_JOB_DOWNTIME_NET,
                                status->downtime - jobInfo->timeDelta) < 0)
        goto error;

    if (status->setup_time_set &&
        virTypedParamsAddULLong(&par, &npar, &maxpar,
                                VIR_DOMAIN_JOB_SETUP_TIME,
                                status->setup_time) < 0)
        goto error;

    if (virTypedParamsAddULLong(&par, &npar, &maxpar,
                                VIR_DOMAIN_JOB_DATA_TOTAL,
                                status->ram_total +
                                status->disk_total) < 0 ||
        virTypedParamsAddULLong(&par, &npar, &maxpar,
                                VIR_DOMAIN_JOB_DATA_PROCESSED,
                                status->ram_transferred +
                                status->disk_transferred) < 0 ||
        virTypedParamsAddULLong(&par, &npar, &maxpar,
                                VIR_DOMAIN_JOB_DATA_REMAINING,
                                status->ram_remaining +
                                status->disk_remaining) < 0)
        goto error;

    if (virTypedParamsAddULLong(&par, &npar, &maxpar,
                                VIR_DOMAIN_JOB_MEMORY_TOTAL,
                                status->ram_total) < 0 ||
        virTypedParamsAddULLong(&par, &npar, &maxpar,
                                VIR_DOMAIN_JOB_MEMORY_PROCESSED,
                                status->ram_transferred) < 0 ||
        virTypedParamsAddULLong(&par, &npar, &maxpar,
                                VIR_DOMAIN_JOB_MEMORY_REMAINING,
                                status->ram_remaining) < 0)
        goto error;

    if (status->ram_bps &&
        virTypedParamsAddULLong(&par, &npar, &maxpar,
                                VIR_DOMAIN_JOB_MEMORY_BPS,
                                status->ram_bps) < 0)
        goto error;

    if (status->ram_duplicate_set) {
        if (virTypedParamsAddULLong(&par, &npar, &maxpar,
                                    VIR_DOMAIN_JOB_MEMORY_CONSTANT,
                                    status->ram_duplicate) < 0 ||
            virTypedParamsAddULLong(&par, &npar, &maxpar,
                                    VIR_DOMAIN_JOB_MEMORY_NORMAL,
                                    status->ram_normal) < 0 ||
            virTypedParamsAddULLong(&par, &npar, &maxpar,
                                    VIR_DOMAIN_JOB_MEMORY_NORMAL_BYTES,
                                    status->ram_normal_bytes) < 0)
            goto error;
    }

    if (virTypedParamsAddULLong(&par, &npar, &maxpar,
                                VIR_DOMAIN_JOB_DISK_TOTAL,
                                status->disk_total) < 0 ||
        virTypedParamsAddULLong(&par, &npar, &maxpar,
                                VIR_DOMAIN_JOB_DISK_PROCESSED,
                                status->disk_transferred) < 0 ||
        virTypedParamsAddULLong(&par, &npar, &maxpar,
                                VIR_DOMAIN_JOB_DISK_REMAINING,
                                status->disk_remaining) < 0)
        goto error;

    if (status->disk_bps &&
        virTypedParamsAddULLong(&par, &npar, &maxpar,
                                VIR_DOMAIN_JOB_DISK_BPS,
                                status->disk_bps) < 0)
        goto error;

    if (status->xbzrle_set) {
        if (virTypedParamsAddULLong(&par, &npar, &maxpar,
                                    VIR_DOMAIN_JOB_COMPRESSION_CACHE,
                                    status->xbzrle_cache_size) < 0 ||
            virTypedParamsAddULLong(&par, &npar, &maxpar,
                                    VIR_DOMAIN_JOB_COMPRESSION_BYTES,
                                    status->xbzrle_bytes) < 0 ||
            virTypedParamsAddULLong(&par, &npar, &maxpar,
                                    VIR_DOMAIN_JOB_COMPRESSION_PAGES,
                                    status->xbzrle_pages) < 0 ||
            virTypedParamsAddULLong(&par, &npar, &maxpar,
                                    VIR_DOMAIN_JOB_COMPRESSION_CACHE_MISSES,
                                    status->xbzrle_cache_miss) < 0 ||
            virTypedParamsAddULLong(&par, &npar, &maxpar,
                                    VIR_DOMAIN_JOB_COMPRESSION_OVERFLOW,
                                    status->xbzrle_overflow) < 0)
            goto error;
    }

    *type = jobInfo->type;
    *params = par;
    *nparams = npar;
    return 0;

 error:
    virTypedParamsFree(par, npar);
    return -1;
}


static virClassPtr qemuDomainDiskPrivateClass;

static int
qemuDomainDiskPrivateOnceInit(void)
{
    qemuDomainDiskPrivateClass = virClassNew(virClassForObject(),
                                             "qemuDomainDiskPrivate",
                                             sizeof(qemuDomainDiskPrivate),
                                             NULL);
    if (!qemuDomainDiskPrivateClass)
        return -1;
    else
        return 0;
}

VIR_ONCE_GLOBAL_INIT(qemuDomainDiskPrivate)

static virObjectPtr
qemuDomainDiskPrivateNew(void)
{
    qemuDomainDiskPrivatePtr priv;

    if (qemuDomainDiskPrivateInitialize() < 0)
        return NULL;

    if (!(priv = virObjectNew(qemuDomainDiskPrivateClass)))
        return NULL;

    return (virObjectPtr) priv;
}


static void *
qemuDomainObjPrivateAlloc(void)
{
    qemuDomainObjPrivatePtr priv;

    if (VIR_ALLOC(priv) < 0)
        return NULL;

    if (qemuDomainObjInitJob(priv) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to init qemu driver mutexes"));
        goto error;
    }

    if (virCondInit(&priv->unplugFinished) < 0)
        goto error;

    if (!(priv->devs = virChrdevAlloc()))
        goto error;

    priv->migMaxBandwidth = QEMU_DOMAIN_MIG_BANDWIDTH_MAX;

    return priv;

 error:
    VIR_FREE(priv);
    return NULL;
}

static void
qemuDomainObjPrivateFree(void *data)
{
    qemuDomainObjPrivatePtr priv = data;

    virObjectUnref(priv->qemuCaps);

    virCgroupFree(&priv->cgroup);
    virDomainPCIAddressSetFree(priv->pciaddrs);
    virDomainCCWAddressSetFree(priv->ccwaddrs);
    virDomainVirtioSerialAddrSetFree(priv->vioserialaddrs);
    virDomainChrSourceDefFree(priv->monConfig);
    qemuDomainObjFreeJob(priv);
    VIR_FREE(priv->vcpupids);
    VIR_FREE(priv->lockState);
    VIR_FREE(priv->origname);

    virCondDestroy(&priv->unplugFinished);
    virStringFreeList(priv->qemuDevices);
    virChrdevFree(priv->devs);

    /* This should never be non-NULL if we get here, but just in case... */
    if (priv->mon) {
        VIR_ERROR(_("Unexpected QEMU monitor still active during domain deletion"));
        qemuMonitorClose(priv->mon);
    }
    if (priv->agent) {
        VIR_ERROR(_("Unexpected QEMU agent still active during domain deletion"));
        qemuAgentClose(priv->agent);
    }
    VIR_FREE(priv->cleanupCallbacks);
    virBitmapFree(priv->autoNodeset);
    virBitmapFree(priv->autoCpuset);
    VIR_FREE(priv);
}


static int
qemuDomainObjPrivateXMLFormat(virBufferPtr buf,
                              virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    const char *monitorpath;
    qemuDomainJob job;

    /* priv->monitor_chr is set only for qemu */
    if (priv->monConfig) {
        switch (priv->monConfig->type) {
        case VIR_DOMAIN_CHR_TYPE_UNIX:
            monitorpath = priv->monConfig->data.nix.path;
            break;
        default:
        case VIR_DOMAIN_CHR_TYPE_PTY:
            monitorpath = priv->monConfig->data.file.path;
            break;
        }

        virBufferEscapeString(buf, "<monitor path='%s'", monitorpath);
        if (priv->monJSON)
            virBufferAddLit(buf, " json='1'");
        virBufferAsprintf(buf, " type='%s'/>\n",
                          virDomainChrTypeToString(priv->monConfig->type));
    }


    if (priv->nvcpupids) {
        size_t i;
        virBufferAddLit(buf, "<vcpus>\n");
        virBufferAdjustIndent(buf, 2);
        for (i = 0; i < priv->nvcpupids; i++)
            virBufferAsprintf(buf, "<vcpu pid='%d'/>\n", priv->vcpupids[i]);
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</vcpus>\n");
    }

    if (priv->qemuCaps) {
        size_t i;
        virBufferAddLit(buf, "<qemuCaps>\n");
        virBufferAdjustIndent(buf, 2);
        for (i = 0; i < QEMU_CAPS_LAST; i++) {
            if (virQEMUCapsGet(priv->qemuCaps, i)) {
                virBufferAsprintf(buf, "<flag name='%s'/>\n",
                                  virQEMUCapsTypeToString(i));
            }
        }
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</qemuCaps>\n");
    }

    if (priv->lockState)
        virBufferAsprintf(buf, "<lockstate>%s</lockstate>\n", priv->lockState);

    job = priv->job.active;
    if (!qemuDomainTrackJob(job))
        priv->job.active = QEMU_JOB_NONE;

    if (priv->job.active || priv->job.asyncJob) {
        virBufferAsprintf(buf, "<job type='%s' async='%s'",
                          qemuDomainJobTypeToString(priv->job.active),
                          qemuDomainAsyncJobTypeToString(priv->job.asyncJob));
        if (priv->job.phase) {
            virBufferAsprintf(buf, " phase='%s'",
                              qemuDomainAsyncJobPhaseToString(
                                    priv->job.asyncJob, priv->job.phase));
        }
        if (priv->job.asyncJob != QEMU_ASYNC_JOB_MIGRATION_OUT) {
            virBufferAddLit(buf, "/>\n");
        } else {
            size_t i;
            virDomainDiskDefPtr disk;
            qemuDomainDiskPrivatePtr diskPriv;

            virBufferAddLit(buf, ">\n");
            virBufferAdjustIndent(buf, 2);

            for (i = 0; i < vm->def->ndisks; i++) {
                disk = vm->def->disks[i];
                diskPriv = QEMU_DOMAIN_DISK_PRIVATE(disk);
                virBufferAsprintf(buf, "<disk dev='%s' migrating='%s'/>\n",
                                  disk->dst,
                                  diskPriv->migrating ? "yes" : "no");
            }

            virBufferAdjustIndent(buf, -2);
            virBufferAddLit(buf, "</job>\n");
        }
    }
    priv->job.active = job;

    if (priv->fakeReboot)
        virBufferAddLit(buf, "<fakereboot/>\n");

    if (priv->qemuDevices && *priv->qemuDevices) {
        char **tmp = priv->qemuDevices;
        virBufferAddLit(buf, "<devices>\n");
        virBufferAdjustIndent(buf, 2);
        while (*tmp) {
            virBufferAsprintf(buf, "<device alias='%s'/>\n", *tmp);
            tmp++;
        }
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</devices>\n");
    }

    if (priv->autoNodeset) {
        char *nodeset = virBitmapFormat(priv->autoNodeset);

        if (!nodeset)
            return -1;

        virBufferAsprintf(buf, "<numad nodeset='%s'/>\n", nodeset);
        VIR_FREE(nodeset);
    }

    return 0;
}

static int
qemuDomainObjPrivateXMLParse(xmlXPathContextPtr ctxt,
                             virDomainObjPtr vm,
                             virDomainDefParserConfigPtr config)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virQEMUDriverPtr driver = config->priv;
    char *monitorpath;
    char *tmp = NULL;
    int n;
    size_t i;
    xmlNodePtr *nodes = NULL;
    virQEMUCapsPtr qemuCaps = NULL;
    virCapsPtr caps = NULL;

    if (VIR_ALLOC(priv->monConfig) < 0)
        goto error;

    if (!(monitorpath =
          virXPathString("string(./monitor[1]/@path)", ctxt))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("no monitor path"));
        goto error;
    }

    tmp = virXPathString("string(./monitor[1]/@type)", ctxt);
    if (tmp)
        priv->monConfig->type = virDomainChrTypeFromString(tmp);
    else
        priv->monConfig->type = VIR_DOMAIN_CHR_TYPE_PTY;
    VIR_FREE(tmp);

    priv->monJSON = virXPathBoolean("count(./monitor[@json = '1']) > 0",
                                    ctxt) > 0;

    switch (priv->monConfig->type) {
    case VIR_DOMAIN_CHR_TYPE_PTY:
        priv->monConfig->data.file.path = monitorpath;
        break;
    case VIR_DOMAIN_CHR_TYPE_UNIX:
        priv->monConfig->data.nix.path = monitorpath;
        break;
    default:
        VIR_FREE(monitorpath);
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unsupported monitor type '%s'"),
                       virDomainChrTypeToString(priv->monConfig->type));
        goto error;
    }

    n = virXPathNodeSet("./vcpus/vcpu", ctxt, &nodes);
    if (n < 0)
        goto error;
    if (n) {
        priv->nvcpupids = n;
        if (VIR_REALLOC_N(priv->vcpupids, priv->nvcpupids) < 0)
            goto error;

        for (i = 0; i < n; i++) {
            char *pidstr = virXMLPropString(nodes[i], "pid");
            if (!pidstr)
                goto error;

            if (virStrToLong_i(pidstr, NULL, 10, &(priv->vcpupids[i])) < 0) {
                VIR_FREE(pidstr);
                goto error;
            }
            VIR_FREE(pidstr);
        }
        VIR_FREE(nodes);
    }

    if ((n = virXPathNodeSet("./qemuCaps/flag", ctxt, &nodes)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("failed to parse qemu capabilities flags"));
        goto error;
    }
    if (n > 0) {
        if (!(qemuCaps = virQEMUCapsNew()))
            goto error;

        for (i = 0; i < n; i++) {
            char *str = virXMLPropString(nodes[i], "name");
            if (str) {
                int flag = virQEMUCapsTypeFromString(str);
                if (flag < 0) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("Unknown qemu capabilities flag %s"), str);
                    VIR_FREE(str);
                    goto error;
                }
                VIR_FREE(str);
                virQEMUCapsSet(qemuCaps, flag);
            }
        }

        priv->qemuCaps = qemuCaps;
        qemuCaps = NULL;
    }
    VIR_FREE(nodes);

    priv->lockState = virXPathString("string(./lockstate)", ctxt);

    if ((tmp = virXPathString("string(./job[1]/@type)", ctxt))) {
        int type;

        if ((type = qemuDomainJobTypeFromString(tmp)) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unknown job type %s"), tmp);
            VIR_FREE(tmp);
            goto error;
        }
        VIR_FREE(tmp);
        priv->job.active = type;
    }

    if ((tmp = virXPathString("string(./job[1]/@async)", ctxt))) {
        int async;

        if ((async = qemuDomainAsyncJobTypeFromString(tmp)) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unknown async job type %s"), tmp);
            VIR_FREE(tmp);
            goto error;
        }
        VIR_FREE(tmp);
        priv->job.asyncJob = async;

        if ((tmp = virXPathString("string(./job[1]/@phase)", ctxt))) {
            priv->job.phase = qemuDomainAsyncJobPhaseFromString(async, tmp);
            if (priv->job.phase < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Unknown job phase %s"), tmp);
                VIR_FREE(tmp);
                goto error;
            }
            VIR_FREE(tmp);
        }
    }

    if ((n = virXPathNodeSet("./job[1]/disk[@migrating='yes']",
                             ctxt, &nodes)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to parse list of disks marked for migration"));
        goto error;
    }
    if (n > 0) {
        if (priv->job.asyncJob != QEMU_ASYNC_JOB_MIGRATION_OUT) {
            VIR_WARN("Found disks marked for migration but we were not "
                     "migrating");
            n = 0;
        }
        for (i = 0; i < n; i++) {
            char *dst = virXMLPropString(nodes[i], "dev");
            virDomainDiskDefPtr disk;

            if (dst && (disk = virDomainDiskByName(vm->def, dst, false)))
                QEMU_DOMAIN_DISK_PRIVATE(disk)->migrating = true;
            VIR_FREE(dst);
        }
    }
    VIR_FREE(nodes);

    priv->fakeReboot = virXPathBoolean("boolean(./fakereboot)", ctxt) == 1;

    if ((n = virXPathNodeSet("./devices/device", ctxt, &nodes)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to parse qemu device list"));
        goto error;
    }
    if (n > 0) {
        /* NULL-terminated list */
        if (VIR_ALLOC_N(priv->qemuDevices, n + 1) < 0)
            goto error;

        for (i = 0; i < n; i++) {
            priv->qemuDevices[i] = virXMLPropString(nodes[i], "alias");
            if (!priv->qemuDevices[i]) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("failed to parse qemu device list"));
                goto error;
            }
        }
    }
    VIR_FREE(nodes);

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto error;

    if ((tmp = virXPathString("string(./numad/@nodeset)", ctxt))) {
        if (virBitmapParse(tmp, 0, &priv->autoNodeset,
                           caps->host.nnumaCell_max) < 0)
            goto error;

        if (!(priv->autoCpuset = virCapabilitiesGetCpusForNodemask(caps,
                                                                   priv->autoNodeset)))
            goto error;
    }
    virObjectUnref(caps);
    VIR_FREE(tmp);

    return 0;

 error:
    virDomainChrSourceDefFree(priv->monConfig);
    priv->monConfig = NULL;
    VIR_FREE(nodes);
    VIR_FREE(tmp);
    virStringFreeList(priv->qemuDevices);
    priv->qemuDevices = NULL;
    virObjectUnref(qemuCaps);
    virObjectUnref(caps);
    return -1;
}


virDomainXMLPrivateDataCallbacks virQEMUDriverPrivateDataCallbacks = {
    .alloc = qemuDomainObjPrivateAlloc,
    .free = qemuDomainObjPrivateFree,
    .diskNew = qemuDomainDiskPrivateNew,
    .parse = qemuDomainObjPrivateXMLParse,
    .format = qemuDomainObjPrivateXMLFormat,
};


static void
qemuDomainDefNamespaceFree(void *nsdata)
{
    qemuDomainCmdlineDefPtr cmd = nsdata;

    qemuDomainCmdlineDefFree(cmd);
}

static int
qemuDomainDefNamespaceParse(xmlDocPtr xml ATTRIBUTE_UNUSED,
                            xmlNodePtr root ATTRIBUTE_UNUSED,
                            xmlXPathContextPtr ctxt,
                            void **data)
{
    qemuDomainCmdlineDefPtr cmd = NULL;
    bool uses_qemu_ns = false;
    xmlNodePtr *nodes = NULL;
    int n;
    size_t i;

    if (xmlXPathRegisterNs(ctxt, BAD_CAST "qemu", BAD_CAST QEMU_NAMESPACE_HREF) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to register xml namespace '%s'"),
                       QEMU_NAMESPACE_HREF);
        return -1;
    }

    if (VIR_ALLOC(cmd) < 0)
        return -1;

    /* first handle the extra command-line arguments */
    n = virXPathNodeSet("./qemu:commandline/qemu:arg", ctxt, &nodes);
    if (n < 0)
        goto error;
    uses_qemu_ns |= n > 0;

    if (n && VIR_ALLOC_N(cmd->args, n) < 0)
        goto error;

    for (i = 0; i < n; i++) {
        cmd->args[cmd->num_args] = virXMLPropString(nodes[i], "value");
        if (cmd->args[cmd->num_args] == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("No qemu command-line argument specified"));
            goto error;
        }
        cmd->num_args++;
    }

    VIR_FREE(nodes);

    /* now handle the extra environment variables */
    n = virXPathNodeSet("./qemu:commandline/qemu:env", ctxt, &nodes);
    if (n < 0)
        goto error;
    uses_qemu_ns |= n > 0;

    if (n && VIR_ALLOC_N(cmd->env_name, n) < 0)
        goto error;

    if (n && VIR_ALLOC_N(cmd->env_value, n) < 0)
        goto error;

    for (i = 0; i < n; i++) {
        char *tmp;

        tmp = virXMLPropString(nodes[i], "name");
        if (tmp == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("No qemu environment name specified"));
            goto error;
        }
        if (tmp[0] == '\0') {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("Empty qemu environment name specified"));
            goto error;
        }
        if (!c_isalpha(tmp[0]) && tmp[0] != '_') {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("Invalid environment name, it must begin with a letter or underscore"));
            goto error;
        }
        if (strspn(tmp, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_") != strlen(tmp)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("Invalid environment name, it must contain only alphanumerics and underscore"));
            goto error;
        }

        cmd->env_name[cmd->num_env] = tmp;

        cmd->env_value[cmd->num_env] = virXMLPropString(nodes[i], "value");
        /* a NULL value for command is allowed, since it might be empty */
        cmd->num_env++;
    }

    VIR_FREE(nodes);

    if (uses_qemu_ns)
        *data = cmd;
    else
        VIR_FREE(cmd);

    return 0;

 error:
    VIR_FREE(nodes);
    qemuDomainDefNamespaceFree(cmd);
    return -1;
}

static int
qemuDomainDefNamespaceFormatXML(virBufferPtr buf,
                                void *nsdata)
{
    qemuDomainCmdlineDefPtr cmd = nsdata;
    size_t i;

    if (!cmd->num_args && !cmd->num_env)
        return 0;

    virBufferAddLit(buf, "<qemu:commandline>\n");
    virBufferAdjustIndent(buf, 2);

    for (i = 0; i < cmd->num_args; i++)
        virBufferEscapeString(buf, "<qemu:arg value='%s'/>\n",
                              cmd->args[i]);
    for (i = 0; i < cmd->num_env; i++) {
        virBufferAsprintf(buf, "<qemu:env name='%s'", cmd->env_name[i]);
        if (cmd->env_value[i])
            virBufferEscapeString(buf, " value='%s'", cmd->env_value[i]);
        virBufferAddLit(buf, "/>\n");
    }

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</qemu:commandline>\n");
    return 0;
}

static const char *
qemuDomainDefNamespaceHref(void)
{
    return "xmlns:qemu='" QEMU_NAMESPACE_HREF "'";
}


virDomainXMLNamespace virQEMUDriverDomainXMLNamespace = {
    .parse = qemuDomainDefNamespaceParse,
    .free = qemuDomainDefNamespaceFree,
    .format = qemuDomainDefNamespaceFormatXML,
    .href = qemuDomainDefNamespaceHref,
};


static int
qemuDomainDefPostParse(virDomainDefPtr def,
                       virCapsPtr caps,
                       void *opaque)
{
    virQEMUDriverPtr driver = opaque;
    virQEMUCapsPtr qemuCaps = NULL;
    bool addDefaultUSB = true;
    bool addImplicitSATA = false;
    bool addPCIRoot = false;
    bool addPCIeRoot = false;
    bool addDefaultMemballoon = true;
    bool addDefaultUSBKBD = false;
    bool addDefaultUSBMouse = false;
    bool addPanicDevice = false;
    int ret = -1;

    if (def->os.bootloader || def->os.bootloaderArgs) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("bootloader is not supported by QEMU"));
        return ret;
    }

    /* check for emulator and create a default one if needed */
    if (!def->emulator &&
        !(def->emulator = virDomainDefGetDefaultEmulator(def, caps)))
        return ret;


    qemuCaps = virQEMUCapsCacheLookup(driver->qemuCapsCache, def->emulator);

    /* Add implicit PCI root controller if the machine has one */
    switch (def->os.arch) {
    case VIR_ARCH_I686:
    case VIR_ARCH_X86_64:
        if (!def->os.machine)
            break;
        if (STREQ(def->os.machine, "isapc")) {
            addDefaultUSB = false;
            break;
        }
        if (STRPREFIX(def->os.machine, "pc-q35") ||
            STREQ(def->os.machine, "q35")) {
            addPCIeRoot = true;
            addDefaultUSB = false;
            addImplicitSATA = true;
            break;
        }
        if (!STRPREFIX(def->os.machine, "pc-0.") &&
            !STRPREFIX(def->os.machine, "pc-1.") &&
            !STRPREFIX(def->os.machine, "pc-i440") &&
            STRNEQ(def->os.machine, "pc") &&
            !STRPREFIX(def->os.machine, "rhel"))
            break;
        addPCIRoot = true;
        break;

    case VIR_ARCH_ARMV7L:
    case VIR_ARCH_AARCH64:
        addDefaultUSB = false;
        addDefaultMemballoon = false;
        if (STREQ(def->os.machine, "virt") ||
            STRPREFIX(def->os.machine, "virt-")) {
            addPCIeRoot = virQEMUCapsGet(qemuCaps, QEMU_CAPS_OBJECT_GPEX);
        }
        break;

    case VIR_ARCH_PPC64:
    case VIR_ARCH_PPC64LE:
        addPCIRoot = true;
        addDefaultUSBKBD = true;
        addDefaultUSBMouse = true;
        /* For pSeries guests, the firmware provides the same
         * functionality as the pvpanic device, so automatically
         * add the definition if not already present */
        if (STRPREFIX(def->os.machine, "pseries"))
            addPanicDevice = true;
        break;

    case VIR_ARCH_ALPHA:
    case VIR_ARCH_PPC:
    case VIR_ARCH_PPCEMB:
    case VIR_ARCH_SH4:
    case VIR_ARCH_SH4EB:
        addPCIRoot = true;
        break;
    case VIR_ARCH_S390:
        addDefaultUSB = false;
        break;
    case VIR_ARCH_S390X:
        addDefaultUSB = false;
        break;

    case VIR_ARCH_SPARC:
    case VIR_ARCH_SPARC64:
        addPCIRoot = true;
        break;

    default:
        break;
    }

    if (addDefaultUSB &&
        virDomainDefMaybeAddController(
            def, VIR_DOMAIN_CONTROLLER_TYPE_USB, 0, -1) < 0)
        goto cleanup;

    if (addImplicitSATA &&
        virDomainDefMaybeAddController(
            def, VIR_DOMAIN_CONTROLLER_TYPE_SATA, 0, -1) < 0)
        goto cleanup;

    /* NB: any machine that sets addPCIRoot to true must also return
     * true from the function qemuDomainSupportsPCI().
     */
    if (addPCIRoot &&
        virDomainDefMaybeAddController(
            def, VIR_DOMAIN_CONTROLLER_TYPE_PCI, 0,
            VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT) < 0)
        goto cleanup;

    /* When a machine has a pcie-root, make sure that there is always
     * a dmi-to-pci-bridge controller added as bus 1, and a pci-bridge
     * as bus 2, so that standard PCI devices can be connected
     *
     * NB: any machine that sets addPCIeRoot to true must also return
     * true from the function qemuDomainSupportsPCI().
     */
    if (addPCIeRoot) {
        if (virDomainDefMaybeAddController(
                def, VIR_DOMAIN_CONTROLLER_TYPE_PCI, 0,
                VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT) < 0 ||
            virDomainDefMaybeAddController(
                def, VIR_DOMAIN_CONTROLLER_TYPE_PCI, 1,
                VIR_DOMAIN_CONTROLLER_MODEL_DMI_TO_PCI_BRIDGE) < 0 ||
            virDomainDefMaybeAddController(
                def, VIR_DOMAIN_CONTROLLER_TYPE_PCI, 2,
                VIR_DOMAIN_CONTROLLER_MODEL_PCI_BRIDGE) < 0) {
            goto cleanup;
        }
    }

    if (addDefaultMemballoon && !def->memballoon) {
        virDomainMemballoonDefPtr memballoon;
        if (VIR_ALLOC(memballoon) < 0)
            goto cleanup;

        memballoon->model = VIR_DOMAIN_MEMBALLOON_MODEL_VIRTIO;
        def->memballoon = memballoon;
    }

    if (addDefaultUSBKBD &&
        def->ngraphics > 0 &&
        virDomainDefMaybeAddInput(def,
                                  VIR_DOMAIN_INPUT_TYPE_KBD,
                                  VIR_DOMAIN_INPUT_BUS_USB) < 0)
        goto cleanup;

    if (addDefaultUSBMouse &&
        def->ngraphics > 0 &&
        virDomainDefMaybeAddInput(def,
                                  VIR_DOMAIN_INPUT_TYPE_MOUSE,
                                  VIR_DOMAIN_INPUT_BUS_USB) < 0)
        goto cleanup;

    if (addPanicDevice && !def->panic) {
        virDomainPanicDefPtr panic;
        if (VIR_ALLOC(panic) < 0)
            goto cleanup;

        def->panic = panic;
    }

    ret = 0;
 cleanup:
    virObjectUnref(qemuCaps);
    return ret;
}

static const char *
qemuDomainDefaultNetModel(const virDomainDef *def,
                          virQEMUCapsPtr qemuCaps)
{
    if (ARCH_IS_S390(def->os.arch))
        return "virtio";

    if (def->os.arch == VIR_ARCH_ARMV7L ||
        def->os.arch == VIR_ARCH_AARCH64) {
        if (STREQ(def->os.machine, "versatilepb"))
            return "smc91c111";

        if (STREQ(def->os.machine, "virt"))
            return "virtio";

        /* Incomplete. vexpress (and a few others) use this, but not all
         * arm boards */
        return "lan9118";
    }

    /* Try several network devices in turn; each of these devices is
     * less likely be supported out-of-the-box by the guest operating
     * system than the previous one */
    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_RTL8139))
        return "rtl8139";
    else if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_E1000))
        return "e1000";
    else if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_VIRTIO_NET))
        return "virtio";

    /* We've had no luck detecting support for any network device,
     * but we have to return something: might as well be rtl8139 */
    return "rtl8139";
}

static int
qemuDomainDeviceDefPostParse(virDomainDeviceDefPtr dev,
                             const virDomainDef *def,
                             virCapsPtr caps ATTRIBUTE_UNUSED,
                             void *opaque)
{
    virQEMUDriverPtr driver = opaque;
    virQEMUCapsPtr qemuCaps = NULL;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    int ret = -1;

    qemuCaps = virQEMUCapsCacheLookup(driver->qemuCapsCache, def->emulator);

    if (dev->type == VIR_DOMAIN_DEVICE_NET &&
        dev->data.net->type != VIR_DOMAIN_NET_TYPE_HOSTDEV &&
        !dev->data.net->model) {
        if (VIR_STRDUP(dev->data.net->model,
                       qemuDomainDefaultNetModel(def, qemuCaps)) < 0)
            goto cleanup;
    }

    /* set default disk types and drivers */
    if (dev->type == VIR_DOMAIN_DEVICE_DISK) {
        virDomainDiskDefPtr disk = dev->data.disk;

        /* assign default storage format and driver according to config */
        if (cfg->allowDiskFormatProbing) {
            /* default disk format for drives */
            if (virDomainDiskGetFormat(disk) == VIR_STORAGE_FILE_NONE &&
                (virDomainDiskGetType(disk) == VIR_STORAGE_TYPE_FILE ||
                 virDomainDiskGetType(disk) == VIR_STORAGE_TYPE_BLOCK))
                virDomainDiskSetFormat(disk, VIR_STORAGE_FILE_AUTO);

            /* default disk format for mirrored drive */
            if (disk->mirror &&
                disk->mirror->format == VIR_STORAGE_FILE_NONE)
                disk->mirror->format = VIR_STORAGE_FILE_AUTO;
        } else {
            /* default driver if probing is forbidden */
            if (!virDomainDiskGetDriver(disk) &&
                virDomainDiskSetDriver(disk, "qemu") < 0)
                goto cleanup;

            /* default disk format for drives */
            if (virDomainDiskGetFormat(disk) == VIR_STORAGE_FILE_NONE &&
                (virDomainDiskGetType(disk) == VIR_STORAGE_TYPE_FILE ||
                 virDomainDiskGetType(disk) == VIR_STORAGE_TYPE_BLOCK))
                virDomainDiskSetFormat(disk, VIR_STORAGE_FILE_RAW);

            /* default disk format for mirrored drive */
            if (disk->mirror &&
                disk->mirror->format == VIR_STORAGE_FILE_NONE)
                disk->mirror->format = VIR_STORAGE_FILE_RAW;
        }
    }

    /* set the default console type for S390 arches */
    if (dev->type == VIR_DOMAIN_DEVICE_CHR &&
        dev->data.chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE &&
        dev->data.chr->targetType == VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_NONE &&
        ARCH_IS_S390(def->os.arch))
        dev->data.chr->targetType = VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_VIRTIO;

    /* set the default USB model to none for s390 unless an address is found */
    if (dev->type == VIR_DOMAIN_DEVICE_CONTROLLER &&
        dev->data.controller->type == VIR_DOMAIN_CONTROLLER_TYPE_USB &&
        dev->data.controller->model == -1 &&
        dev->data.controller->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
        ARCH_IS_S390(def->os.arch))
        dev->data.controller->model = VIR_DOMAIN_CONTROLLER_MODEL_USB_NONE;

    /* set the default SCSI controller model for S390 arches */
    if (dev->type == VIR_DOMAIN_DEVICE_CONTROLLER &&
        dev->data.controller->type == VIR_DOMAIN_CONTROLLER_TYPE_SCSI &&
        dev->data.controller->model == -1 &&
        ARCH_IS_S390(def->os.arch))
        dev->data.controller->model = VIR_DOMAIN_CONTROLLER_MODEL_SCSI_VIRTIO_SCSI;

    /* auto generate unix socket path */
    if (dev->type == VIR_DOMAIN_DEVICE_CHR &&
        dev->data.chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CHANNEL &&
        dev->data.chr->targetType == VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_VIRTIO &&
        dev->data.chr->source.type == VIR_DOMAIN_CHR_TYPE_UNIX &&
        !dev->data.chr->source.data.nix.path) {
        if (virAsprintf(&dev->data.chr->source.data.nix.path,
                        "%s/domain-%s/%s",
                        cfg->channelTargetDir, def->name,
                        dev->data.chr->target.name ? dev->data.chr->target.name
                        : "unknown.sock") < 0)
            goto cleanup;

        dev->data.chr->source.data.nix.listen = true;
    }

    /* forbid capabilities mode hostdev in this kind of hypervisor */
    if (dev->type == VIR_DOMAIN_DEVICE_HOSTDEV &&
        dev->data.hostdev->mode == VIR_DOMAIN_HOSTDEV_MODE_CAPABILITIES) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("hostdev mode 'capabilities' is not "
                         "supported in %s"),
                       virDomainVirtTypeToString(def->virtType));
        goto cleanup;
    }

    if (dev->type == VIR_DOMAIN_DEVICE_VIDEO &&
        dev->data.video->type == VIR_DOMAIN_VIDEO_TYPE_QXL) {
        if (dev->data.video->vgamem) {
            if (dev->data.video->vgamem < 1024) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("value for 'vgamem' must be at least 1 MiB "
                                 "(1024 KiB)"));
                goto cleanup;
            }
            if (dev->data.video->vgamem != VIR_ROUND_UP_POWER_OF_TWO(dev->data.video->vgamem)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("value for 'vgamem' must be power of two"));
                goto cleanup;
            }
        } else {
            dev->data.video->vgamem = QEMU_QXL_VGAMEM_DEFAULT;
        }
    }

    if (dev->type == VIR_DOMAIN_DEVICE_MEMORY &&
        !virDomainDefHasMemoryHotplug(def)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("maxMemory has to be specified when using memory "
                         "devices "));
        goto cleanup;
    }

    ret = 0;

 cleanup:
    virObjectUnref(qemuCaps);
    virObjectUnref(cfg);
    return ret;
}


virDomainDefParserConfig virQEMUDriverDomainDefParserConfig = {
    .devicesPostParseCallback = qemuDomainDeviceDefPostParse,
    .domainPostParseCallback = qemuDomainDefPostParse,
};


static void
qemuDomainObjSaveJob(virQEMUDriverPtr driver, virDomainObjPtr obj)
{
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);

    if (virDomainObjIsActive(obj)) {
        if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, obj) < 0)
            VIR_WARN("Failed to save status on vm %s", obj->def->name);
    }

    virObjectUnref(cfg);
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
    qemuDomainObjSaveJob(driver, obj);
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
        qemuDomainObjResetJob(priv);
    qemuDomainObjResetAsyncJob(priv);
    qemuDomainObjSaveJob(driver, obj);
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
qemuDomainNestedJobAllowed(qemuDomainObjPrivatePtr priv, qemuDomainJob job)
{
    return !priv->job.asyncJob || (priv->job.mask & JOB_MASK(job)) != 0;
}

bool
qemuDomainJobAllowed(qemuDomainObjPrivatePtr priv, qemuDomainJob job)
{
    return !priv->job.active && qemuDomainNestedJobAllowed(priv, job);
}

/* Give up waiting for mutex after 30 seconds */
#define QEMU_JOB_WAIT_TIME (1000ull * 30)

/*
 * obj must be locked before calling
 */
static int ATTRIBUTE_NONNULL(1)
qemuDomainObjBeginJobInternal(virQEMUDriverPtr driver,
                              virDomainObjPtr obj,
                              qemuDomainJob job,
                              qemuDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivatePtr priv = obj->privateData;
    unsigned long long now;
    unsigned long long then;
    bool nested = job == QEMU_JOB_ASYNC_NESTED;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    const char *blocker = NULL;
    int ret = -1;
    unsigned long long duration = 0;
    unsigned long long asyncDuration = 0;

    VIR_DEBUG("Starting %s: %s (async=%s vm=%p name=%s)",
              job == QEMU_JOB_ASYNC ? "async job" : "job",
              qemuDomainJobTypeToString(job),
              qemuDomainAsyncJobTypeToString(priv->job.asyncJob),
              obj, obj->def->name);

    if (virTimeMillisNow(&now) < 0) {
        virObjectUnref(cfg);
        return -1;
    }

    priv->jobs_queued++;
    then = now + QEMU_JOB_WAIT_TIME;

 retry:
    if (cfg->maxQueuedJobs &&
        priv->jobs_queued > cfg->maxQueuedJobs) {
        goto error;
    }

    while (!nested && !qemuDomainNestedJobAllowed(priv, job)) {
        VIR_DEBUG("Waiting for async job (vm=%p name=%s)", obj, obj->def->name);
        if (virCondWaitUntil(&priv->job.asyncCond, &obj->parent.lock, then) < 0)
            goto error;
    }

    while (priv->job.active) {
        VIR_DEBUG("Waiting for job (vm=%p name=%s)", obj, obj->def->name);
        if (virCondWaitUntil(&priv->job.cond, &obj->parent.lock, then) < 0)
            goto error;
    }

    /* No job is active but a new async job could have been started while obj
     * was unlocked, so we need to recheck it. */
    if (!nested && !qemuDomainNestedJobAllowed(priv, job))
        goto retry;

    qemuDomainObjResetJob(priv);

    ignore_value(virTimeMillisNow(&now));

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
        qemuDomainObjResetAsyncJob(priv);
        if (VIR_ALLOC(priv->job.current) < 0)
            goto cleanup;
        priv->job.asyncJob = asyncJob;
        priv->job.asyncOwner = virThreadSelfID();
        priv->job.asyncOwnerAPI = virThreadJobGet();
        priv->job.asyncStarted = now;
        priv->job.current->started = now;
    }

    if (qemuDomainTrackJob(job))
        qemuDomainObjSaveJob(driver, obj);

    virObjectUnref(cfg);
    return 0;

 error:
    ignore_value(virTimeMillisNow(&now));
    if (priv->job.active && priv->job.started)
        duration = now - priv->job.started;
    if (priv->job.asyncJob && priv->job.asyncStarted)
        asyncDuration = now - priv->job.asyncStarted;

    VIR_WARN("Cannot start job (%s, %s) for domain %s; "
             "current job is (%s, %s) owned by (%llu %s, %llu %s) "
             "for (%llus, %llus)",
             qemuDomainJobTypeToString(job),
             qemuDomainAsyncJobTypeToString(asyncJob),
             obj->def->name,
             qemuDomainJobTypeToString(priv->job.active),
             qemuDomainAsyncJobTypeToString(priv->job.asyncJob),
             priv->job.owner, NULLSTR(priv->job.ownerAPI),
             priv->job.asyncOwner, NULLSTR(priv->job.asyncOwnerAPI),
             duration / 1000, asyncDuration / 1000);

    if (nested || qemuDomainNestedJobAllowed(priv, job))
        blocker = priv->job.ownerAPI;
    else
        blocker = priv->job.asyncOwnerAPI;

    ret = -1;
    if (errno == ETIMEDOUT) {
        if (blocker) {
            virReportError(VIR_ERR_OPERATION_TIMEOUT,
                           _("cannot acquire state change lock (held by %s)"),
                           blocker);
        } else {
            virReportError(VIR_ERR_OPERATION_TIMEOUT, "%s",
                           _("cannot acquire state change lock"));
        }
        ret = -2;
    } else if (cfg->maxQueuedJobs &&
               priv->jobs_queued > cfg->maxQueuedJobs) {
        if (blocker) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("cannot acquire state change lock (held by %s) "
                             "due to max_queued limit"),
                           blocker);
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
    virObjectUnref(cfg);
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
                                      QEMU_ASYNC_JOB_NONE) < 0)
        return -1;
    else
        return 0;
}

int qemuDomainObjBeginAsyncJob(virQEMUDriverPtr driver,
                               virDomainObjPtr obj,
                               qemuDomainAsyncJob asyncJob)
{
    if (qemuDomainObjBeginJobInternal(driver, obj, QEMU_JOB_ASYNC,
                                      asyncJob) < 0)
        return -1;
    else
        return 0;
}

static int ATTRIBUTE_RETURN_CHECK
qemuDomainObjBeginNestedJob(virQEMUDriverPtr driver,
                            virDomainObjPtr obj,
                            qemuDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivatePtr priv = obj->privateData;

    if (asyncJob != priv->job.asyncJob) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected async job %d"), asyncJob);
        return -1;
    }

    if (priv->job.asyncOwner != virThreadSelfID()) {
        VIR_WARN("This thread doesn't seem to be the async job owner: %llu",
                 priv->job.asyncOwner);
    }

    return qemuDomainObjBeginJobInternal(driver, obj,
                                         QEMU_JOB_ASYNC_NESTED,
                                         QEMU_ASYNC_JOB_NONE);
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

    qemuDomainObjResetJob(priv);
    if (qemuDomainTrackJob(job))
        qemuDomainObjSaveJob(driver, obj);
    virCondSignal(&priv->job.cond);
}

void
qemuDomainObjEndAsyncJob(virQEMUDriverPtr driver, virDomainObjPtr obj)
{
    qemuDomainObjPrivatePtr priv = obj->privateData;

    priv->jobs_queued--;

    VIR_DEBUG("Stopping async job: %s (vm=%p name=%s)",
              qemuDomainAsyncJobTypeToString(priv->job.asyncJob),
              obj, obj->def->name);

    qemuDomainObjResetAsyncJob(priv);
    qemuDomainObjSaveJob(driver, obj);
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

/*
 * obj must be locked before calling
 *
 * To be called immediately before any QEMU monitor API call
 * Must have already either called qemuDomainObjBeginJob() and checked
 * that the VM is still active; may not be used for nested async jobs.
 *
 * To be followed with qemuDomainObjExitMonitor() once complete
 */
static int
qemuDomainObjEnterMonitorInternal(virQEMUDriverPtr driver,
                                  virDomainObjPtr obj,
                                  qemuDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivatePtr priv = obj->privateData;

    if (asyncJob != QEMU_ASYNC_JOB_NONE) {
        int ret;
        if ((ret = qemuDomainObjBeginNestedJob(driver, obj, asyncJob)) < 0)
            return ret;
        if (!virDomainObjIsActive(obj)) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("domain is no longer running"));
            qemuDomainObjEndJob(driver, obj);
            return -1;
        }
    } else if (priv->job.asyncOwner == virThreadSelfID()) {
        VIR_WARN("This thread seems to be the async job owner; entering"
                 " monitor without asking for a nested job is dangerous");
    }

    VIR_DEBUG("Entering monitor (mon=%p vm=%p name=%s)",
              priv->mon, obj, obj->def->name);
    virObjectLock(priv->mon);
    virObjectRef(priv->mon);
    ignore_value(virTimeMillisNow(&priv->monStart));
    virObjectUnlock(obj);

    return 0;
}

static void ATTRIBUTE_NONNULL(1)
qemuDomainObjExitMonitorInternal(virQEMUDriverPtr driver,
                                 virDomainObjPtr obj)
{
    qemuDomainObjPrivatePtr priv = obj->privateData;
    bool hasRefs;

    hasRefs = virObjectUnref(priv->mon);

    if (hasRefs)
        virObjectUnlock(priv->mon);

    virObjectLock(obj);
    VIR_DEBUG("Exited monitor (mon=%p vm=%p name=%s)",
              priv->mon, obj, obj->def->name);

    priv->monStart = 0;
    if (!hasRefs)
        priv->mon = NULL;

    if (priv->job.active == QEMU_JOB_ASYNC_NESTED) {
        qemuDomainObjResetJob(priv);
        qemuDomainObjSaveJob(driver, obj);
        virCondSignal(&priv->job.cond);
    }
}

void qemuDomainObjEnterMonitor(virQEMUDriverPtr driver,
                               virDomainObjPtr obj)
{
    ignore_value(qemuDomainObjEnterMonitorInternal(driver, obj,
                                                   QEMU_ASYNC_JOB_NONE));
}

/* obj must NOT be locked before calling
 *
 * Should be paired with an earlier qemuDomainObjEnterMonitor() call
 *
 * Returns -1 if the domain is no longer alive after exiting the monitor.
 * In that case, the caller should be careful when using obj's data,
 * e.g. the live definition in vm->def has been freed by qemuProcessStop
 * and replaced by the persistent definition, so pointers stolen
 * from the live definition could no longer be valid.
 */
int qemuDomainObjExitMonitor(virQEMUDriverPtr driver,
                             virDomainObjPtr obj)
{
    qemuDomainObjExitMonitorInternal(driver, obj);
    if (!virDomainObjIsActive(obj)) {
        if (!virGetLastError())
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("domain is no longer running"));
        return -1;
    }
    return 0;
}

/*
 * obj must be locked before calling
 *
 * To be called immediately before any QEMU monitor API call.
 * Must have already either called qemuDomainObjBeginJob()
 * and checked that the VM is still active, with asyncJob of
 * QEMU_ASYNC_JOB_NONE; or already called qemuDomainObjBeginAsyncJob,
 * with the same asyncJob.
 *
 * Returns 0 if job was started, in which case this must be followed with
 * qemuDomainObjExitMonitor(); -2 if waiting for the nested job times out;
 * or -1 if the job could not be started (probably because the vm exited
 * in the meantime).
 */
int
qemuDomainObjEnterMonitorAsync(virQEMUDriverPtr driver,
                               virDomainObjPtr obj,
                               qemuDomainAsyncJob asyncJob)
{
    return qemuDomainObjEnterMonitorInternal(driver, obj, asyncJob);
}



/*
 * obj must be locked before calling
 *
 * To be called immediately before any QEMU agent API call.
 * Must have already called qemuDomainObjBeginJob() and checked
 * that the VM is still active.
 *
 * To be followed with qemuDomainObjExitAgent() once complete
 */
void
qemuDomainObjEnterAgent(virDomainObjPtr obj)
{
    qemuDomainObjPrivatePtr priv = obj->privateData;

    VIR_DEBUG("Entering agent (agent=%p vm=%p name=%s)",
              priv->agent, obj, obj->def->name);
    virObjectLock(priv->agent);
    virObjectRef(priv->agent);
    ignore_value(virTimeMillisNow(&priv->agentStart));
    virObjectUnlock(obj);
}


/* obj must NOT be locked before calling
 *
 * Should be paired with an earlier qemuDomainObjEnterAgent() call
 */
void
qemuDomainObjExitAgent(virDomainObjPtr obj)
{
    qemuDomainObjPrivatePtr priv = obj->privateData;
    bool hasRefs;

    hasRefs = virObjectUnref(priv->agent);

    if (hasRefs)
        virObjectUnlock(priv->agent);

    virObjectLock(obj);
    VIR_DEBUG("Exited agent (agent=%p vm=%p name=%s)",
              priv->agent, obj, obj->def->name);

    priv->agentStart = 0;
    if (!hasRefs)
        priv->agent = NULL;
}

void qemuDomainObjEnterRemote(virDomainObjPtr obj)
{
    VIR_DEBUG("Entering remote (vm=%p name=%s)",
              obj, obj->def->name);
    virObjectUnlock(obj);
}

void qemuDomainObjExitRemote(virDomainObjPtr obj)
{
    virObjectLock(obj);
    VIR_DEBUG("Exited remote (vm=%p name=%s)",
              obj, obj->def->name);
}


virDomainDefPtr
qemuDomainDefCopy(virQEMUDriverPtr driver,
                  virDomainDefPtr src,
                  unsigned int flags)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    virDomainDefPtr ret = NULL;
    virCapsPtr caps = NULL;
    char *xml = NULL;

    if (qemuDomainDefFormatBuf(driver, src, flags, &buf) < 0)
        goto cleanup;

    xml = virBufferContentAndReset(&buf);

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    if (!(ret = virDomainDefParseString(xml, caps, driver->xmlopt,
                                        VIR_DOMAIN_DEF_PARSE_INACTIVE)))
        goto cleanup;

 cleanup:
    VIR_FREE(xml);
    virObjectUnref(caps);
    return ret;
}

int
qemuDomainDefFormatBuf(virQEMUDriverPtr driver,
                       virDomainDefPtr def,
                       unsigned int flags,
                       virBuffer *buf)
{
    int ret = -1;
    virCPUDefPtr cpu = NULL;
    virCPUDefPtr def_cpu = def->cpu;
    virDomainControllerDefPtr *controllers = NULL;
    int ncontrollers = 0;
    virCapsPtr caps = NULL;

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    /* Update guest CPU requirements according to host CPU */
    if ((flags & VIR_DOMAIN_XML_UPDATE_CPU) &&
        def_cpu &&
        (def_cpu->mode != VIR_CPU_MODE_CUSTOM || def_cpu->model)) {
        if (!caps->host.cpu ||
            !caps->host.cpu->model) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           "%s", _("cannot get host CPU capabilities"));
            goto cleanup;
        }

        if (!(cpu = virCPUDefCopy(def_cpu)) ||
            cpuUpdate(cpu, caps->host.cpu) < 0)
            goto cleanup;
        def->cpu = cpu;
    }

    if ((flags & VIR_DOMAIN_XML_MIGRATABLE)) {
        size_t i;
        int toremove = 0;
        virDomainControllerDefPtr usb = NULL, pci = NULL;

        /* If only the default USB controller is present, we can remove it
         * and make the XML compatible with older versions of libvirt which
         * didn't support USB controllers in the XML but always added the
         * default one to qemu anyway.
         */
        for (i = 0; i < def->ncontrollers; i++) {
            if (def->controllers[i]->type == VIR_DOMAIN_CONTROLLER_TYPE_USB) {
                if (usb) {
                    usb = NULL;
                    break;
                }
                usb = def->controllers[i];
            }
        }
        if (usb && usb->idx == 0 && usb->model == -1) {
            VIR_DEBUG("Removing default USB controller from domain '%s'"
                      " for migration compatibility", def->name);
            toremove++;
        } else {
            usb = NULL;
        }

        /* Remove the default PCI controller if there is only one present
         * and its model is pci-root */
        for (i = 0; i < def->ncontrollers; i++) {
            if (def->controllers[i]->type == VIR_DOMAIN_CONTROLLER_TYPE_PCI) {
                if (pci) {
                    pci = NULL;
                    break;
                }
                pci = def->controllers[i];
            }
        }

        if (pci && pci->idx == 0 &&
            pci->model == VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT) {
            VIR_DEBUG("Removing default pci-root from domain '%s'"
                      " for migration compatibility", def->name);
            toremove++;
        } else {
            pci = NULL;
        }

        if (toremove) {
            controllers = def->controllers;
            ncontrollers = def->ncontrollers;
            if (VIR_ALLOC_N(def->controllers, ncontrollers - toremove) < 0) {
                controllers = NULL;
                goto cleanup;
            }

            def->ncontrollers = 0;
            for (i = 0; i < ncontrollers; i++) {
                if (controllers[i] != usb && controllers[i] != pci)
                    def->controllers[def->ncontrollers++] = controllers[i];
            }
        }


    }

    ret = virDomainDefFormatInternal(def,
                                     virDomainDefFormatConvertXMLFlags(flags),
                                     buf);

 cleanup:
    def->cpu = def_cpu;
    virCPUDefFree(cpu);
    if (controllers) {
        VIR_FREE(def->controllers);
        def->controllers = controllers;
        def->ncontrollers = ncontrollers;
    }
    virObjectUnref(caps);
    return ret;
}

char *qemuDomainDefFormatXML(virQEMUDriverPtr driver,
                             virDomainDefPtr def,
                             unsigned int flags)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (qemuDomainDefFormatBuf(driver, def, flags, &buf) < 0) {
        virBufferFreeAndReset(&buf);
        return NULL;
    }

    if (virBufferError(&buf)) {
        virReportOOMError();
        virBufferFreeAndReset(&buf);
        return NULL;
    }

    return virBufferContentAndReset(&buf);
}

char *qemuDomainFormatXML(virQEMUDriverPtr driver,
                          virDomainObjPtr vm,
                          unsigned int flags)
{
    virDomainDefPtr def;

    if ((flags & VIR_DOMAIN_XML_INACTIVE) && vm->newDef)
        def = vm->newDef;
    else
        def = vm->def;

    return qemuDomainDefFormatXML(driver, def, flags);
}

char *
qemuDomainDefFormatLive(virQEMUDriverPtr driver,
                        virDomainDefPtr def,
                        bool inactive,
                        bool compatible)
{
    unsigned int flags = QEMU_DOMAIN_FORMAT_LIVE_FLAGS;

    if (inactive)
        flags |= VIR_DOMAIN_XML_INACTIVE;
    if (compatible)
        flags |= VIR_DOMAIN_XML_MIGRATABLE;

    return qemuDomainDefFormatXML(driver, def, flags);
}


void qemuDomainObjTaint(virQEMUDriverPtr driver,
                        virDomainObjPtr obj,
                        virDomainTaintFlags taint,
                        int logFD)
{
    virErrorPtr orig_err = NULL;

    if (virDomainObjTaint(obj, taint)) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(obj->def->uuid, uuidstr);

        VIR_WARN("Domain id=%d name='%s' uuid=%s is tainted: %s",
                 obj->def->id,
                 obj->def->name,
                 uuidstr,
                 virDomainTaintTypeToString(taint));

        /* We don't care about errors logging taint info, so
         * preserve original error, and clear any error that
         * is raised */
        orig_err = virSaveLastError();
        if (qemuDomainAppendLog(driver, obj, logFD,
                                "Domain id=%d is tainted: %s\n",
                                obj->def->id,
                                virDomainTaintTypeToString(taint)) < 0)
            virResetLastError();
        if (orig_err) {
            virSetError(orig_err);
            virFreeError(orig_err);
        }
    }
}


void qemuDomainObjCheckTaint(virQEMUDriverPtr driver,
                             virDomainObjPtr obj,
                             int logFD)
{
    size_t i;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    qemuDomainObjPrivatePtr priv = obj->privateData;

    if (virQEMUDriverIsPrivileged(driver) &&
        (!cfg->clearEmulatorCapabilities ||
         cfg->user == 0 ||
         cfg->group == 0))
        qemuDomainObjTaint(driver, obj, VIR_DOMAIN_TAINT_HIGH_PRIVILEGES, logFD);

    if (priv->hookRun)
        qemuDomainObjTaint(driver, obj, VIR_DOMAIN_TAINT_HOOK, logFD);

    if (obj->def->namespaceData) {
        qemuDomainCmdlineDefPtr qemucmd = obj->def->namespaceData;
        if (qemucmd->num_args || qemucmd->num_env)
            qemuDomainObjTaint(driver, obj, VIR_DOMAIN_TAINT_CUSTOM_ARGV, logFD);
    }

    if (obj->def->cpu && obj->def->cpu->mode == VIR_CPU_MODE_HOST_PASSTHROUGH)
        qemuDomainObjTaint(driver, obj, VIR_DOMAIN_TAINT_HOST_CPU, logFD);

    for (i = 0; i < obj->def->ndisks; i++)
        qemuDomainObjCheckDiskTaint(driver, obj, obj->def->disks[i], logFD);

    for (i = 0; i < obj->def->nhostdevs; i++)
        qemuDomainObjCheckHostdevTaint(driver, obj, obj->def->hostdevs[i],
                                       logFD);

    for (i = 0; i < obj->def->nnets; i++)
        qemuDomainObjCheckNetTaint(driver, obj, obj->def->nets[i], logFD);

    if (obj->def->os.dtb)
        qemuDomainObjTaint(driver, obj, VIR_DOMAIN_TAINT_CUSTOM_DTB, logFD);

    virObjectUnref(cfg);
}


void qemuDomainObjCheckDiskTaint(virQEMUDriverPtr driver,
                                 virDomainObjPtr obj,
                                 virDomainDiskDefPtr disk,
                                 int logFD)
{
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    int format = virDomainDiskGetFormat(disk);

    if ((!format || format == VIR_STORAGE_FILE_AUTO) &&
        cfg->allowDiskFormatProbing)
        qemuDomainObjTaint(driver, obj, VIR_DOMAIN_TAINT_DISK_PROBING, logFD);

    if (disk->rawio == VIR_TRISTATE_BOOL_YES)
        qemuDomainObjTaint(driver, obj, VIR_DOMAIN_TAINT_HIGH_PRIVILEGES,
                           logFD);

    if (disk->device == VIR_DOMAIN_DISK_DEVICE_CDROM &&
        virStorageSourceGetActualType(disk->src) == VIR_STORAGE_TYPE_BLOCK &&
        disk->src->path)
        qemuDomainObjTaint(driver, obj, VIR_DOMAIN_TAINT_CDROM_PASSTHROUGH,
                           logFD);

    virObjectUnref(cfg);
}


void qemuDomainObjCheckHostdevTaint(virQEMUDriverPtr driver,
                                    virDomainObjPtr obj,
                                    virDomainHostdevDefPtr hostdev,
                                    int logFD)
{
    virDomainHostdevSubsysSCSIPtr scsisrc = &hostdev->source.subsys.u.scsi;

    if (hostdev->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI &&
        scsisrc->rawio == VIR_TRISTATE_BOOL_YES)
            qemuDomainObjTaint(driver, obj, VIR_DOMAIN_TAINT_HIGH_PRIVILEGES,
                               logFD);
}


void qemuDomainObjCheckNetTaint(virQEMUDriverPtr driver,
                                virDomainObjPtr obj,
                                virDomainNetDefPtr net,
                                int logFD)
{
    /* script is only useful for NET_TYPE_ETHERNET (qemu) and
     * NET_TYPE_BRIDGE (xen), but could be (incorrectly) specified for
     * any interface type. In any case, it's adding user sauce into
     * the soup, so it should taint the domain.
     */
    if (net->script != NULL)
        qemuDomainObjTaint(driver, obj, VIR_DOMAIN_TAINT_SHELL_SCRIPTS, logFD);
}


static int
qemuDomainOpenLogHelper(virQEMUDriverConfigPtr cfg,
                        virDomainObjPtr vm,
                        int oflags,
                        mode_t mode)
{
    char *logfile;
    int fd = -1;
    bool trunc = false;

    if (virAsprintf(&logfile, "%s/%s.log", cfg->logDir, vm->def->name) < 0)
        return -1;

    /* To make SELinux happy we always need to open in append mode.
     * So we fake O_TRUNC by calling ftruncate after open instead
     */
    if (oflags & O_TRUNC) {
        oflags &= ~O_TRUNC;
        oflags |= O_APPEND;
        trunc = true;
    }

    if ((fd = open(logfile, oflags, mode)) < 0) {
        virReportSystemError(errno, _("failed to create logfile %s"),
                             logfile);
        goto cleanup;
    }
    if (virSetCloseExec(fd) < 0) {
        virReportSystemError(errno, _("failed to set close-on-exec flag on %s"),
                             logfile);
        VIR_FORCE_CLOSE(fd);
        goto cleanup;
    }
    if (trunc &&
        ftruncate(fd, 0) < 0) {
        virReportSystemError(errno, _("failed to truncate %s"),
                             logfile);
        VIR_FORCE_CLOSE(fd);
        goto cleanup;
    }

 cleanup:
    VIR_FREE(logfile);
    return fd;
}


int
qemuDomainCreateLog(virQEMUDriverPtr driver, virDomainObjPtr vm,
                    bool append)
{
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    int oflags;
    int ret;

    oflags = O_CREAT | O_WRONLY;
    /* Only logrotate files in /var/log, so only append if running privileged */
    if (virQEMUDriverIsPrivileged(driver) || append)
        oflags |= O_APPEND;
    else
        oflags |= O_TRUNC;

    ret = qemuDomainOpenLogHelper(cfg, vm, oflags, S_IRUSR | S_IWUSR);
    virObjectUnref(cfg);
    return ret;
}


int
qemuDomainOpenLog(virQEMUDriverPtr driver, virDomainObjPtr vm, off_t pos)
{
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    int fd;
    off_t off;
    int whence;

    fd = qemuDomainOpenLogHelper(cfg, vm, O_RDONLY, 0);
    virObjectUnref(cfg);
    if (fd < 0)
        return -1;

    if (pos < 0) {
        off = 0;
        whence = SEEK_END;
    } else {
        off = pos;
        whence = SEEK_SET;
    }

    if (lseek(fd, off, whence) < 0) {
        if (whence == SEEK_END)
            virReportSystemError(errno,
                                 _("unable to seek to end of log for %s"),
                                 vm->def->name);
        else
            virReportSystemError(errno,
                                 _("unable to seek to %lld from start for %s"),
                                 (long long)off, vm->def->name);
        VIR_FORCE_CLOSE(fd);
    }

    return fd;
}


int qemuDomainAppendLog(virQEMUDriverPtr driver,
                        virDomainObjPtr obj,
                        int logFD,
                        const char *fmt, ...)
{
    int fd = logFD;
    va_list argptr;
    char *message = NULL;
    int ret = -1;

    va_start(argptr, fmt);

    if ((fd == -1) &&
        (fd = qemuDomainCreateLog(driver, obj, true)) < 0)
        goto cleanup;

    if (virVasprintf(&message, fmt, argptr) < 0)
        goto cleanup;
    if (safewrite(fd, message, strlen(message)) < 0) {
        virReportSystemError(errno, _("Unable to write to domain logfile %s"),
                             obj->def->name);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    va_end(argptr);

    if (fd != logFD)
        VIR_FORCE_CLOSE(fd);

    VIR_FREE(message);
    return ret;
}

/* Locate an appropriate 'qemu-img' binary.  */
const char *
qemuFindQemuImgBinary(virQEMUDriverPtr driver)
{
    if (!driver->qemuImgBinary)
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("unable to find kvm-img or qemu-img"));

    return driver->qemuImgBinary;
}

int
qemuDomainSnapshotWriteMetadata(virDomainObjPtr vm,
                                virDomainSnapshotObjPtr snapshot,
                                char *snapshotDir)
{
    char *newxml = NULL;
    int ret = -1;
    char *snapDir = NULL;
    char *snapFile = NULL;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    virUUIDFormat(vm->def->uuid, uuidstr);
    newxml = virDomainSnapshotDefFormat(
        uuidstr, snapshot->def,
        virDomainDefFormatConvertXMLFlags(QEMU_DOMAIN_FORMAT_LIVE_FLAGS),
        1);
    if (newxml == NULL)
        return -1;

    if (virAsprintf(&snapDir, "%s/%s", snapshotDir, vm->def->name) < 0)
        goto cleanup;
    if (virFileMakePath(snapDir) < 0) {
        virReportSystemError(errno, _("cannot create snapshot directory '%s'"),
                             snapDir);
        goto cleanup;
    }

    if (virAsprintf(&snapFile, "%s/%s.xml", snapDir, snapshot->def->name) < 0)
        goto cleanup;

    ret = virXMLSaveFile(snapFile, NULL, "snapshot-edit", newxml);

 cleanup:
    VIR_FREE(snapFile);
    VIR_FREE(snapDir);
    VIR_FREE(newxml);
    return ret;
}

/* The domain is expected to be locked and inactive. Return -1 on normal
 * failure, 1 if we skipped a disk due to try_all.  */
static int
qemuDomainSnapshotForEachQcow2Raw(virQEMUDriverPtr driver,
                                  virDomainDefPtr def,
                                  const char *name,
                                  const char *op,
                                  bool try_all,
                                  int ndisks)
{
    const char *qemuimgarg[] = { NULL, "snapshot", NULL, NULL, NULL, NULL };
    size_t i;
    bool skipped = false;

    qemuimgarg[0] = qemuFindQemuImgBinary(driver);
    if (qemuimgarg[0] == NULL) {
        /* qemuFindQemuImgBinary set the error */
        return -1;
    }

    qemuimgarg[2] = op;
    qemuimgarg[3] = name;

    for (i = 0; i < ndisks; i++) {
        /* FIXME: we also need to handle LVM here */
        if (def->disks[i]->device == VIR_DOMAIN_DISK_DEVICE_DISK) {
            int format = virDomainDiskGetFormat(def->disks[i]);

            if (format > 0 && format != VIR_STORAGE_FILE_QCOW2) {
                if (try_all) {
                    /* Continue on even in the face of error, since other
                     * disks in this VM may have the same snapshot name.
                     */
                    VIR_WARN("skipping snapshot action on %s",
                             def->disks[i]->dst);
                    skipped = true;
                    continue;
                } else if (STREQ(op, "-c") && i) {
                    /* We must roll back partial creation by deleting
                     * all earlier snapshots.  */
                    qemuDomainSnapshotForEachQcow2Raw(driver, def, name,
                                                      "-d", false, i);
                }
                virReportError(VIR_ERR_OPERATION_INVALID,
                               _("Disk device '%s' does not support"
                                 " snapshotting"),
                               def->disks[i]->dst);
                return -1;
            }

            qemuimgarg[4] = virDomainDiskGetSource(def->disks[i]);

            if (virRun(qemuimgarg, NULL) < 0) {
                if (try_all) {
                    VIR_WARN("skipping snapshot action on %s",
                             def->disks[i]->dst);
                    skipped = true;
                    continue;
                } else if (STREQ(op, "-c") && i) {
                    /* We must roll back partial creation by deleting
                     * all earlier snapshots.  */
                    qemuDomainSnapshotForEachQcow2Raw(driver, def, name,
                                                      "-d", false, i);
                }
                return -1;
            }
        }
    }

    return skipped ? 1 : 0;
}

/* The domain is expected to be locked and inactive. Return -1 on normal
 * failure, 1 if we skipped a disk due to try_all.  */
int
qemuDomainSnapshotForEachQcow2(virQEMUDriverPtr driver,
                               virDomainObjPtr vm,
                               virDomainSnapshotObjPtr snap,
                               const char *op,
                               bool try_all)
{
    /* Prefer action on the disks in use at the time the snapshot was
     * created; but fall back to current definition if dealing with a
     * snapshot created prior to libvirt 0.9.5.  */
    virDomainDefPtr def = snap->def->dom;

    if (!def)
        def = vm->def;
    return qemuDomainSnapshotForEachQcow2Raw(driver, def, snap->def->name,
                                             op, try_all, def->ndisks);
}

/* Discard one snapshot (or its metadata), without reparenting any children.  */
int
qemuDomainSnapshotDiscard(virQEMUDriverPtr driver,
                          virDomainObjPtr vm,
                          virDomainSnapshotObjPtr snap,
                          bool update_current,
                          bool metadata_only)
{
    char *snapFile = NULL;
    int ret = -1;
    qemuDomainObjPrivatePtr priv;
    virDomainSnapshotObjPtr parentsnap = NULL;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);

    if (!metadata_only) {
        if (!virDomainObjIsActive(vm)) {
            /* Ignore any skipped disks */
            if (qemuDomainSnapshotForEachQcow2(driver, vm, snap, "-d",
                                               true) < 0)
                goto cleanup;
        } else {
            priv = vm->privateData;
            qemuDomainObjEnterMonitor(driver, vm);
            /* we continue on even in the face of error */
            qemuMonitorDeleteSnapshot(priv->mon, snap->def->name);
            ignore_value(qemuDomainObjExitMonitor(driver, vm));
        }
    }

    if (virAsprintf(&snapFile, "%s/%s/%s.xml", cfg->snapshotDir,
                    vm->def->name, snap->def->name) < 0)
        goto cleanup;

    if (snap == vm->current_snapshot) {
        if (update_current && snap->def->parent) {
            parentsnap = virDomainSnapshotFindByName(vm->snapshots,
                                                     snap->def->parent);
            if (!parentsnap) {
                VIR_WARN("missing parent snapshot matching name '%s'",
                         snap->def->parent);
            } else {
                parentsnap->def->current = true;
                if (qemuDomainSnapshotWriteMetadata(vm, parentsnap,
                                                    cfg->snapshotDir) < 0) {
                    VIR_WARN("failed to set parent snapshot '%s' as current",
                             snap->def->parent);
                    parentsnap->def->current = false;
                    parentsnap = NULL;
                }
            }
        }
        vm->current_snapshot = parentsnap;
    }

    if (unlink(snapFile) < 0)
        VIR_WARN("Failed to unlink %s", snapFile);
    virDomainSnapshotObjListRemove(vm->snapshots, snap);

    ret = 0;

 cleanup:
    VIR_FREE(snapFile);
    virObjectUnref(cfg);
    return ret;
}

/* Hash iterator callback to discard multiple snapshots.  */
void qemuDomainSnapshotDiscardAll(void *payload,
                                  const void *name ATTRIBUTE_UNUSED,
                                  void *data)
{
    virDomainSnapshotObjPtr snap = payload;
    virQEMUSnapRemovePtr curr = data;
    int err;

    if (snap->def->current)
        curr->current = true;
    err = qemuDomainSnapshotDiscard(curr->driver, curr->vm, snap, false,
                                    curr->metadata_only);
    if (err && !curr->err)
        curr->err = err;
}

int
qemuDomainSnapshotDiscardAllMetadata(virQEMUDriverPtr driver,
                                     virDomainObjPtr vm)
{
    virQEMUSnapRemove rem;

    rem.driver = driver;
    rem.vm = vm;
    rem.metadata_only = true;
    rem.err = 0;
    virDomainSnapshotForEach(vm->snapshots, qemuDomainSnapshotDiscardAll,
                             &rem);

    return rem.err;
}

/*
 * The caller must hold a lock the vm.
 */
void
qemuDomainRemoveInactive(virQEMUDriverPtr driver,
                         virDomainObjPtr vm)
{
    bool haveJob = true;
    char *snapDir;
    virQEMUDriverConfigPtr cfg;

    if (vm->persistent) {
        /* Short-circuit, we don't want to remove a persistent domain */
        return;
    }

    cfg = virQEMUDriverGetConfig(driver);

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        haveJob = false;

    /* Remove any snapshot metadata prior to removing the domain */
    if (qemuDomainSnapshotDiscardAllMetadata(driver, vm) < 0) {
        VIR_WARN("unable to remove all snapshots for domain %s",
                 vm->def->name);
    }
    else if (virAsprintf(&snapDir, "%s/%s", cfg->snapshotDir,
                         vm->def->name) < 0) {
        VIR_WARN("unable to remove snapshot directory %s/%s",
                 cfg->snapshotDir, vm->def->name);
    } else {
        if (rmdir(snapDir) < 0 && errno != ENOENT)
            VIR_WARN("unable to remove snapshot directory %s", snapDir);
        VIR_FREE(snapDir);
    }

    virObjectRef(vm);

    virDomainObjListRemove(driver->domains, vm);
    /*
     * virDomainObjListRemove() leaves the domain unlocked so it can
     * be unref'd for other drivers that depend on that, but we still
     * need to reset a job and we have a reference from the API that
     * called this function.  So we need to lock it back.  This is
     * just a workaround for the qemu driver.
     *
     * XXX: Ideally, the global handling of domain objects and object
     *      lists would be refactored so we don't need hacks like
     *      this, but since that requires refactor of all drivers,
     *      it's a work for another day.
     */
    virObjectLock(vm);
    virObjectUnref(cfg);

    if (haveJob)
        qemuDomainObjEndJob(driver, vm);

    virObjectUnref(vm);
}

void
qemuDomainSetFakeReboot(virQEMUDriverPtr driver,
                        virDomainObjPtr vm,
                        bool value)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);

    if (priv->fakeReboot == value)
        goto cleanup;

    priv->fakeReboot = value;

    if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm) < 0)
        VIR_WARN("Failed to save status on vm %s", vm->def->name);

 cleanup:
    virObjectUnref(cfg);
}

static int
qemuDomainCheckRemoveOptionalDisk(virQEMUDriverPtr driver,
                                  virDomainObjPtr vm,
                                  size_t diskIndex)
{
    char uuid[VIR_UUID_STRING_BUFLEN];
    virObjectEventPtr event = NULL;
    virDomainDiskDefPtr disk = vm->def->disks[diskIndex];
    const char *src = virDomainDiskGetSource(disk);

    virUUIDFormat(vm->def->uuid, uuid);

    VIR_DEBUG("Dropping disk '%s' on domain '%s' (UUID '%s') "
              "due to inaccessible source '%s'",
              disk->dst, vm->def->name, uuid, src);

    if (disk->device == VIR_DOMAIN_DISK_DEVICE_CDROM ||
        disk->device == VIR_DOMAIN_DISK_DEVICE_FLOPPY) {

        event = virDomainEventDiskChangeNewFromObj(vm, src, NULL,
                                                   disk->info.alias,
                                                   VIR_DOMAIN_EVENT_DISK_CHANGE_MISSING_ON_START);
        ignore_value(virDomainDiskSetSource(disk, NULL));
    } else {
        event = virDomainEventDiskChangeNewFromObj(vm, src, NULL,
                                                   disk->info.alias,
                                                   VIR_DOMAIN_EVENT_DISK_DROP_MISSING_ON_START);
        virDomainDiskRemove(vm->def, diskIndex);
        virDomainDiskDefFree(disk);
    }

    qemuDomainEventQueue(driver, event);

    return 0;
}

static int
qemuDomainCheckDiskStartupPolicy(virQEMUDriverPtr driver,
                                 virDomainObjPtr vm,
                                 size_t diskIndex,
                                 bool cold_boot)
{
    int startupPolicy = vm->def->disks[diskIndex]->startupPolicy;
    int device = vm->def->disks[diskIndex]->device;

    switch ((virDomainStartupPolicy) startupPolicy) {
        case VIR_DOMAIN_STARTUP_POLICY_OPTIONAL:
            /* Once started with an optional disk, qemu saves its section
             * in the migration stream, so later, when restoring from it
             * we must make sure the sections match. */
            if (!cold_boot &&
                device != VIR_DOMAIN_DISK_DEVICE_FLOPPY &&
                device != VIR_DOMAIN_DISK_DEVICE_CDROM)
                goto error;
            break;

        case VIR_DOMAIN_STARTUP_POLICY_MANDATORY:
            goto error;

        case VIR_DOMAIN_STARTUP_POLICY_REQUISITE:
            if (cold_boot)
                goto error;
            break;

        case VIR_DOMAIN_STARTUP_POLICY_DEFAULT:
        case VIR_DOMAIN_STARTUP_POLICY_LAST:
            /* this should never happen */
            break;
    }

    if (qemuDomainCheckRemoveOptionalDisk(driver, vm, diskIndex) < 0)
        goto error;

    return 0;

 error:
    return -1;
}


int
qemuDomainCheckDiskPresence(virQEMUDriverPtr driver,
                            virDomainObjPtr vm,
                            bool cold_boot)
{
    int ret = -1;
    size_t i;

    VIR_DEBUG("Checking for disk presence");
    for (i = vm->def->ndisks; i > 0; i--) {
        size_t idx = i - 1;
        virDomainDiskDefPtr disk = vm->def->disks[idx];
        virStorageFileFormat format = virDomainDiskGetFormat(disk);

        if (virStorageSourceIsEmpty(disk->src))
            continue;

        /* There is no need to check the backing chain for disks
         * without backing support, the fact that the file exists is
         * more than enough */
        if (virStorageSourceIsLocalStorage(disk->src) &&
            format >= VIR_STORAGE_FILE_NONE &&
            format < VIR_STORAGE_FILE_BACKING &&
            virFileExists(virDomainDiskGetSource(disk)))
            continue;

        if (qemuDomainDetermineDiskChain(driver, vm, disk, true, true) >= 0)
            continue;

        if (disk->startupPolicy &&
            qemuDomainCheckDiskStartupPolicy(driver, vm, idx,
                                             cold_boot) >= 0) {
            virResetLastError();
            continue;
        }

        goto error;
    }

    ret = 0;

 error:
    return ret;
}

/*
 * The vm must be locked when any of the following cleanup functions is
 * called.
 */
int
qemuDomainCleanupAdd(virDomainObjPtr vm,
                     qemuDomainCleanupCallback cb)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    size_t i;

    VIR_DEBUG("vm=%s, cb=%p", vm->def->name, cb);

    for (i = 0; i < priv->ncleanupCallbacks; i++) {
        if (priv->cleanupCallbacks[i] == cb)
            return 0;
    }

    if (VIR_RESIZE_N(priv->cleanupCallbacks,
                     priv->ncleanupCallbacks_max,
                     priv->ncleanupCallbacks, 1) < 0)
        return -1;

    priv->cleanupCallbacks[priv->ncleanupCallbacks++] = cb;
    return 0;
}

void
qemuDomainCleanupRemove(virDomainObjPtr vm,
                        qemuDomainCleanupCallback cb)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    size_t i;

    VIR_DEBUG("vm=%s, cb=%p", vm->def->name, cb);

    for (i = 0; i < priv->ncleanupCallbacks; i++) {
        if (priv->cleanupCallbacks[i] == cb)
            VIR_DELETE_ELEMENT_INPLACE(priv->cleanupCallbacks,
                                       i, priv->ncleanupCallbacks);
    }

    VIR_SHRINK_N(priv->cleanupCallbacks,
                 priv->ncleanupCallbacks_max,
                 priv->ncleanupCallbacks_max - priv->ncleanupCallbacks);
}

void
qemuDomainCleanupRun(virQEMUDriverPtr driver,
                     virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    size_t i;

    VIR_DEBUG("driver=%p, vm=%s", driver, vm->def->name);

    /* run cleanup callbacks in reverse order */
    for (i = 0; i < priv->ncleanupCallbacks; i++) {
        if (priv->cleanupCallbacks[priv->ncleanupCallbacks - (i + 1)])
            priv->cleanupCallbacks[i](driver, vm);
    }

    VIR_FREE(priv->cleanupCallbacks);
    priv->ncleanupCallbacks = 0;
    priv->ncleanupCallbacks_max = 0;
}

static void
qemuDomainGetImageIds(virQEMUDriverConfigPtr cfg,
                      virDomainObjPtr vm,
                      virStorageSourcePtr src,
                      uid_t *uid, gid_t *gid)
{
    virSecurityLabelDefPtr vmlabel;
    virSecurityDeviceLabelDefPtr disklabel;

    if (uid)
        *uid = -1;
    if (gid)
        *gid = -1;

    if (cfg) {
        if (uid)
            *uid = cfg->user;

        if (gid)
            *gid = cfg->group;
    }

    if (vm && (vmlabel = virDomainDefGetSecurityLabelDef(vm->def, "dac")) &&
        vmlabel->label)
        virParseOwnershipIds(vmlabel->label, uid, gid);

    if ((disklabel = virStorageSourceGetSecurityLabelDef(src, "dac")) &&
        disklabel->label)
        virParseOwnershipIds(disklabel->label, uid, gid);
}


int
qemuDomainStorageFileInit(virQEMUDriverPtr driver,
                          virDomainObjPtr vm,
                          virStorageSourcePtr src)
{
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    uid_t uid;
    gid_t gid;
    int ret = -1;

    qemuDomainGetImageIds(cfg, vm, src, &uid, &gid);

    if (virStorageFileInitAs(src, uid, gid) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virObjectUnref(cfg);
    return ret;
}


char *
qemuDomainStorageAlias(const char *device, int depth)
{
    char *alias;

    if (STRPREFIX(device, QEMU_DRIVE_HOST_PREFIX))
        device += strlen(QEMU_DRIVE_HOST_PREFIX);

    if (!depth)
        ignore_value(VIR_STRDUP(alias, device));
    else
        ignore_value(virAsprintf(&alias, "%s.%d", device, depth));
    return alias;
}


int
qemuDomainDetermineDiskChain(virQEMUDriverPtr driver,
                             virDomainObjPtr vm,
                             virDomainDiskDefPtr disk,
                             bool force_probe,
                             bool report_broken)
{
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    int ret = 0;
    uid_t uid;
    gid_t gid;

    if (virStorageSourceIsEmpty(disk->src))
        goto cleanup;

    if (disk->src->backingStore) {
        if (force_probe)
            virStorageSourceBackingStoreClear(disk->src);
        else
            goto cleanup;
    }

    qemuDomainGetImageIds(cfg, vm, disk->src, &uid, &gid);

    if (virStorageFileGetMetadata(disk->src,
                                  uid, gid,
                                  cfg->allowDiskFormatProbing,
                                  report_broken) < 0)
        ret = -1;

 cleanup:
    virObjectUnref(cfg);
    return ret;
}


bool
qemuDomainDiskSourceDiffers(virConnectPtr conn,
                            virDomainDiskDefPtr disk,
                            virDomainDiskDefPtr origDisk)
{
    char *diskSrc = NULL, *origDiskSrc = NULL;
    bool diskEmpty, origDiskEmpty;
    bool ret = true;

    diskEmpty = virStorageSourceIsEmpty(disk->src);
    origDiskEmpty = virStorageSourceIsEmpty(origDisk->src);

    if (diskEmpty && origDiskEmpty)
        return false;

    if (diskEmpty ^ origDiskEmpty)
        return true;

    if (qemuGetDriveSourceString(disk->src, conn, &diskSrc) < 0 ||
        qemuGetDriveSourceString(origDisk->src, conn, &origDiskSrc) < 0)
        goto cleanup;

    /* So far in qemu disk sources are considered different
     * if either path to disk or its format changes. */
    ret = virDomainDiskGetFormat(disk) != virDomainDiskGetFormat(origDisk) ||
          STRNEQ_NULLABLE(diskSrc, origDiskSrc);
 cleanup:
    VIR_FREE(diskSrc);
    VIR_FREE(origDiskSrc);
    return ret;
}


/*
 * Makes sure the @disk differs from @orig_disk only by the source
 * path and nothing else.  Fields that are being checked and the
 * information whether they are nullable (may not be specified) or is
 * taken from the virDomainDiskDefFormat() code.
 */
bool
qemuDomainDiskChangeSupported(virDomainDiskDefPtr disk,
                              virDomainDiskDefPtr orig_disk)
{
#define CHECK_EQ(field, field_name, nullable)                           \
    do {                                                                \
        if (nullable && !disk->field)                                   \
            break;                                                      \
        if (disk->field != orig_disk->field) {                          \
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED,               \
                           _("cannot modify field '%s' of the disk"),   \
                           field_name);                                 \
            return false;                                               \
        }                                                               \
    } while (0)

    CHECK_EQ(device, "device", false);
    CHECK_EQ(bus, "bus", false);
    if (STRNEQ(disk->dst, orig_disk->dst)) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("cannot modify field '%s' of the disk"),
                       "bus");
        return false;
    }
    CHECK_EQ(tray_status, "tray", true);
    CHECK_EQ(removable, "removable", true);

    if (disk->geometry.cylinders &&
        disk->geometry.heads &&
        disk->geometry.sectors) {
        CHECK_EQ(geometry.cylinders, "geometry cylinders", false);
        CHECK_EQ(geometry.heads, "geometry heads", false);
        CHECK_EQ(geometry.sectors, "geometry sectors", false);
        CHECK_EQ(geometry.trans, "BIOS-translation-modus", true);
    }

    CHECK_EQ(blockio.logical_block_size,
             "blockio logical_block_size", false);
    CHECK_EQ(blockio.physical_block_size,
             "blockio physical_block_size", false);

    CHECK_EQ(blkdeviotune.total_bytes_sec,
             "blkdeviotune total_bytes_sec",
             true);
    CHECK_EQ(blkdeviotune.read_bytes_sec,
             "blkdeviotune read_bytes_sec",
             true);
    CHECK_EQ(blkdeviotune.write_bytes_sec,
             "blkdeviotune write_bytes_sec",
             true);
    CHECK_EQ(blkdeviotune.total_iops_sec,
             "blkdeviotune total_iops_sec",
             true);
    CHECK_EQ(blkdeviotune.read_iops_sec,
             "blkdeviotune read_iops_sec",
             true);
    CHECK_EQ(blkdeviotune.write_iops_sec,
             "blkdeviotune write_iops_sec",
             true);
    CHECK_EQ(blkdeviotune.total_bytes_sec_max,
             "blkdeviotune total_bytes_sec_max",
             true);
    CHECK_EQ(blkdeviotune.read_bytes_sec_max,
             "blkdeviotune read_bytes_sec_max",
             true);
    CHECK_EQ(blkdeviotune.write_bytes_sec_max,
             "blkdeviotune write_bytes_sec_max",
             true);
    CHECK_EQ(blkdeviotune.total_iops_sec_max,
             "blkdeviotune total_iops_sec_max",
             true);
    CHECK_EQ(blkdeviotune.read_iops_sec_max,
             "blkdeviotune read_iops_sec_max",
             true);
    CHECK_EQ(blkdeviotune.write_iops_sec_max,
             "blkdeviotune write_iops_sec_max",
             true);
    CHECK_EQ(blkdeviotune.size_iops_sec,
             "blkdeviotune size_iops_sec",
             true);

    if (disk->serial && STRNEQ_NULLABLE(disk->serial, orig_disk->serial)) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("cannot modify field '%s' of the disk"),
                       "serial");
        return false;
    }

    if (disk->wwn && STRNEQ_NULLABLE(disk->wwn, orig_disk->wwn)) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("cannot modify field '%s' of the disk"),
                       "wwn");
        return false;
    }

    if (disk->vendor && STRNEQ_NULLABLE(disk->vendor, orig_disk->vendor)) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("cannot modify field '%s' of the disk"),
                       "vendor");
        return false;
    }

    if (disk->product && STRNEQ_NULLABLE(disk->product, orig_disk->product)) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("cannot modify field '%s' of the disk"),
                       "product");
        return false;
    }

    CHECK_EQ(cachemode, "cache", true);
    CHECK_EQ(error_policy, "error_policy", true);
    CHECK_EQ(rerror_policy, "rerror_policy", true);
    CHECK_EQ(iomode, "io", true);
    CHECK_EQ(ioeventfd, "ioeventfd", true);
    CHECK_EQ(event_idx, "event_idx", true);
    CHECK_EQ(copy_on_read, "copy_on_read", true);
    CHECK_EQ(snapshot, "snapshot", true);
    /* startupPolicy is allowed to be updated. Therefore not checked here. */
    CHECK_EQ(transient, "transient", true);
    CHECK_EQ(info.bootIndex, "boot order", true);
    CHECK_EQ(rawio, "rawio", true);
    CHECK_EQ(sgio, "sgio", true);
    CHECK_EQ(discard, "discard", true);
    CHECK_EQ(iothread, "iothread", true);

    if (disk->domain_name &&
        STRNEQ_NULLABLE(disk->domain_name, orig_disk->domain_name)) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("cannot modify field '%s' of the disk"),
                       "backenddomain");
        return false;
    }

#undef CHECK_EQ

    return true;
}

bool
qemuDomainDiskBlockJobIsActive(virDomainDiskDefPtr disk)
{
    qemuDomainDiskPrivatePtr diskPriv = QEMU_DOMAIN_DISK_PRIVATE(disk);

    if (disk->mirror) {
        virReportError(VIR_ERR_BLOCK_COPY_ACTIVE,
                       _("disk '%s' already in active block job"),
                       disk->dst);

        return true;
    }

    if (diskPriv->blockjob) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("disk '%s' already in active block job"),
                       disk->dst);
        return true;
    }

    return false;
}


/**
 * qemuDomainHasBlockjob:
 * @vm: domain object
 * @copy_only: Reject only block copy job
 *
 * Return true if @vm has at least one disk involved in a current block
 * copy/commit/pull job. If @copy_only is true this returns true only if the
 * disk is involved in a block copy.
 * */
bool
qemuDomainHasBlockjob(virDomainObjPtr vm,
                      bool copy_only)
{
    size_t i;
    for (i = 0; i < vm->def->ndisks; i++) {
        virDomainDiskDefPtr disk = vm->def->disks[i];
        qemuDomainDiskPrivatePtr diskPriv = QEMU_DOMAIN_DISK_PRIVATE(disk);

        if (!copy_only && diskPriv->blockjob)
            return true;

        if (disk->mirror && disk->mirrorJob == VIR_DOMAIN_BLOCK_JOB_TYPE_COPY)
            return true;
    }

    return false;
}


int
qemuDomainUpdateDeviceList(virQEMUDriverPtr driver,
                           virDomainObjPtr vm,
                           int asyncJob)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    char **aliases;
    int rc;

    if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE_DEL_EVENT))
        return 0;

    if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) < 0)
        return -1;
    rc = qemuMonitorGetDeviceAliases(priv->mon, &aliases);
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        return -1;
    if (rc < 0)
        return -1;

    virStringFreeList(priv->qemuDevices);
    priv->qemuDevices = aliases;
    return 0;
}


int
qemuDomainUpdateMemoryDeviceInfo(virQEMUDriverPtr driver,
                                 virDomainObjPtr vm,
                                 int asyncJob)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virHashTablePtr meminfo = NULL;
    int rc;
    size_t i;

    if (vm->def->nmems == 0)
        return 0;

    if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) < 0)
        return -1;

    rc = qemuMonitorGetMemoryDeviceInfo(priv->mon, &meminfo);

    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        return -1;

    /* if qemu doesn't support the info request, just carry on */
    if (rc == -2)
        return 0;

    if (rc < 0)
        return -1;

    for (i = 0; i < vm->def->nmems; i++) {
        virDomainMemoryDefPtr mem = vm->def->mems[i];
        qemuMonitorMemoryDeviceInfoPtr dimm;

        if (!mem->info.alias)
            continue;

        if (!(dimm = virHashLookup(meminfo, mem->info.alias)))
            continue;

        mem->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DIMM;
        mem->info.addr.dimm.slot = dimm->slot;
        mem->info.addr.dimm.base = dimm->address;
    }

    virHashFree(meminfo);
    return 0;
}


bool
qemuDomainDefCheckABIStability(virQEMUDriverPtr driver,
                               virDomainDefPtr src,
                               virDomainDefPtr dst)
{
    virDomainDefPtr migratableDefSrc = NULL;
    virDomainDefPtr migratableDefDst = NULL;
    const int flags = VIR_DOMAIN_XML_SECURE | VIR_DOMAIN_XML_UPDATE_CPU | VIR_DOMAIN_XML_MIGRATABLE;
    bool ret = false;

    if (!(migratableDefSrc = qemuDomainDefCopy(driver, src, flags)) ||
        !(migratableDefDst = qemuDomainDefCopy(driver, dst, flags)))
        goto cleanup;

    ret = virDomainDefCheckABIStability(migratableDefSrc, migratableDefDst);

 cleanup:
    virDomainDefFree(migratableDefSrc);
    virDomainDefFree(migratableDefDst);
    return ret;
}

bool
qemuDomainAgentAvailable(virDomainObjPtr vm,
                         bool reportError)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (virDomainObjGetState(vm, NULL) != VIR_DOMAIN_RUNNING) {
        if (reportError) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("domain is not running"));
        }
        return false;
    }
    if (priv->agentError) {
        if (reportError) {
            virReportError(VIR_ERR_AGENT_UNRESPONSIVE, "%s",
                           _("QEMU guest agent is not "
                             "available due to an error"));
        }
        return false;
    }
    if (!priv->agent) {
        if (qemuFindAgentConfig(vm->def)) {
            if (reportError) {
                virReportError(VIR_ERR_AGENT_UNRESPONSIVE, "%s",
                               _("QEMU guest agent is not connected"));
            }
            return false;
        } else {
            if (reportError) {
                virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                               _("QEMU guest agent is not configured"));
            }
            return false;
        }
    }
    return true;
}


static unsigned long long
qemuDomainGetMemorySizeAlignment(virDomainDefPtr def)
{
    /* PPC requires the memory sizes to be rounded to 256MiB increments, so
     * round them to the size always. */
    if (ARCH_IS_PPC64(def->os.arch))
        return 256 * 1024;

    /* Align memory size. QEMU requires rounding to next 4KiB block.
     * We'll take the "traditional" path and round it to 1MiB*/

    return 1024;
}


static unsigned long long
qemuDomainGetMemoryModuleSizeAlignment(const virDomainDef *def,
                                       const virDomainMemoryDef *mem ATTRIBUTE_UNUSED)
{
    /* PPC requires the memory sizes to be rounded to 256MiB increments, so
     * round them to the size always. */
    if (ARCH_IS_PPC64(def->os.arch))
        return 256 * 1024;

    /* dimm memory modules require 2MiB alignment rather than the 1MiB we are
     * using elsewhere. */
    return 2048;
}


int
qemuDomainAlignMemorySizes(virDomainDefPtr def)
{
    unsigned long long initialmem = 0;
    unsigned long long mem;
    unsigned long long align = qemuDomainGetMemorySizeAlignment(def);
    size_t ncells = virDomainNumaGetNodeCount(def->numa);
    size_t i;

    /* align NUMA cell sizes if relevant */
    for (i = 0; i < ncells; i++) {
        mem = VIR_ROUND_UP(virDomainNumaGetNodeMemorySize(def->numa, i), align);
        initialmem += mem;
        virDomainNumaSetNodeMemorySize(def->numa, i, mem);
    }

    /* align initial memory size, if NUMA is present calculate it as total of
     * individual aligned NUMA node sizes */
    if (initialmem == 0)
        initialmem = VIR_ROUND_UP(virDomainDefGetMemoryInitial(def), align);

    virDomainDefSetMemoryInitial(def, initialmem);

    def->mem.max_memory = VIR_ROUND_UP(def->mem.max_memory, align);

    /* Align memory module sizes */
    for (i = 0; i < def->nmems; i++) {
        align = qemuDomainGetMemoryModuleSizeAlignment(def, def->mems[i]);
        def->mems[i]->size = VIR_ROUND_UP(def->mems[i]->size, align);
    }

    return 0;
}


/**
 * qemuDomainMemoryDeviceAlignSize:
 * @mem: memory device definition object
 *
 * Aligns the size of the memory module as qemu enforces it. The size is updated
 * inplace. Default rounding is now to 1 MiB (qemu requires rouding to page,
 * size so this should be safe).
 */
void
qemuDomainMemoryDeviceAlignSize(virDomainDefPtr def,
                                virDomainMemoryDefPtr mem)
{
    mem->size = VIR_ROUND_UP(mem->size, qemuDomainGetMemorySizeAlignment(def));
}


/**
 * qemuDomainGetMonitor:
 * @vm: domain object
 *
 * Returns the monitor pointer corresponding to the domain object @vm.
 */
qemuMonitorPtr
qemuDomainGetMonitor(virDomainObjPtr vm)
{
    return ((qemuDomainObjPrivatePtr) vm->privateData)->mon;
}


/**
 * qemuDomainSupportsBlockJobs:
 * @vm: domain object
 * @modern: pointer to bool that returns whether modern block jobs are supported
 *
 * Returns -1 in case when qemu does not support block jobs at all. Otherwise
 * returns 0 and optionally fills @modern to denote that modern (async) block
 * jobs are supported.
 */
int
qemuDomainSupportsBlockJobs(virDomainObjPtr vm,
                            bool *modern)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    bool asynchronous = virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_BLOCKJOB_ASYNC);
    bool synchronous = virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_BLOCKJOB_SYNC);

    if (!synchronous && !asynchronous) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("block jobs not supported with this QEMU binary"));
        return -1;
    }

    if (modern)
        *modern = asynchronous;

    return 0;
}


/**
 * qemuFindAgentConfig:
 * @def: domain definition
 *
 * Returns the pointer to the channel definition that is used to access the
 * guest agent if the agent is configured or NULL otherwise.
 */
virDomainChrSourceDefPtr
qemuFindAgentConfig(virDomainDefPtr def)
{
    virDomainChrSourceDefPtr config = NULL;
    size_t i;

    for (i = 0; i < def->nchannels; i++) {
        virDomainChrDefPtr channel = def->channels[i];

        if (channel->targetType != VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_VIRTIO)
            continue;

        if (STREQ_NULLABLE(channel->target.name, "org.qemu.guest_agent.0")) {
            config = &channel->source;
            break;
        }
    }

    return config;
}


bool
qemuDomainMachineIsQ35(const virDomainDef *def)
{
    return (STRPREFIX(def->os.machine, "pc-q35") ||
            STREQ(def->os.machine, "q35"));
}


bool
qemuDomainMachineIsI440FX(const virDomainDef *def)
{
    return (STREQ(def->os.machine, "pc") ||
            STRPREFIX(def->os.machine, "pc-0.") ||
            STRPREFIX(def->os.machine, "pc-1.") ||
            STRPREFIX(def->os.machine, "pc-i440") ||
            STRPREFIX(def->os.machine, "rhel"));
}


bool
qemuDomainMachineNeedsFDC(const virDomainDef *def)
{
    char *p = STRSKIP(def->os.machine, "pc-q35-");

    if (p) {
        if (STRPREFIX(p, "1.") ||
            STRPREFIX(p, "2.0") ||
            STRPREFIX(p, "2.1") ||
            STRPREFIX(p, "2.2") ||
            STRPREFIX(p, "2.3"))
            return false;
        return true;
    }
    return false;
}


bool
qemuDomainMachineIsS390CCW(const virDomainDef *def)
{
    return STRPREFIX(def->os.machine, "s390-ccw");
}


/**
 * qemuDomainUpdateCurrentMemorySize:
 *
 * Updates the current balloon size from the monitor if necessary. In case when
 * the balloon is not present for the domain, the function recalculates the
 * maximum size to reflect possible changes.
 *
 * Returns 0 on success and updates vm->def->mem.cur_balloon if necessary, -1 on
 * error and reports libvirt error.
 */
int
qemuDomainUpdateCurrentMemorySize(virQEMUDriverPtr driver,
                                  virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    unsigned long long balloon;
    int ret = -1;

    /* inactive domain doesn't need size update */
    if (!virDomainObjIsActive(vm))
        return 0;

    /* if no balloning is available, the current size equals to the current
     * full memory size */
    if (!vm->def->memballoon ||
        vm->def->memballoon->model == VIR_DOMAIN_MEMBALLOON_MODEL_NONE) {
        vm->def->mem.cur_balloon = virDomainDefGetMemoryActual(vm->def);
        return 0;
    }

    /* current size is always automagically updated via the event */
    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_BALLOON_EVENT))
        return 0;

    /* here we need to ask the monitor */

    /* Don't delay if someone's using the monitor, just use existing most
     * recent data instead */
    if (qemuDomainJobAllowed(priv, QEMU_JOB_QUERY)) {
        if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_QUERY) < 0)
            return -1;

        if (!virDomainObjIsActive(vm)) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("domain is not running"));
            goto endjob;
        }

        qemuDomainObjEnterMonitor(driver, vm);
        ret = qemuMonitorGetBalloonInfo(priv->mon, &balloon);
        if (qemuDomainObjExitMonitor(driver, vm) < 0)
            ret = -1;

 endjob:
        qemuDomainObjEndJob(driver, vm);

        if (ret < 0)
            return -1;

        vm->def->mem.cur_balloon = balloon;
    }

    return 0;
}
