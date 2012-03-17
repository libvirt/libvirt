/*
 * qemu_domain.h: QEMU domain private state
 *
 * Copyright (C) 2006-2012 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include "qemu_domain.h"
#include "qemu_command.h"
#include "qemu_capabilities.h"
#include "qemu_migration.h"
#include "memory.h"
#include "logging.h"
#include "virterror_internal.h"
#include "c-ctype.h"
#include "cpu/cpu.h"
#include "ignore-value.h"
#include "uuid.h"
#include "virfile.h"
#include "domain_event.h"
#include "virtime.h"

#include <sys/time.h>
#include <fcntl.h>

#include <libxml/xpathInternals.h>

#define VIR_FROM_THIS VIR_FROM_QEMU

#define QEMU_NAMESPACE_HREF "http://libvirt.org/schemas/domain/qemu/1.0"

#define QEMU_DOMAIN_FORMAT_LIVE_FLAGS       \
    (VIR_DOMAIN_XML_SECURE |                \
     VIR_DOMAIN_XML_UPDATE_CPU)

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
);


const char *
qemuDomainAsyncJobPhaseToString(enum qemuDomainAsyncJob job,
                                int phase ATTRIBUTE_UNUSED)
{
    switch (job) {
    case QEMU_ASYNC_JOB_MIGRATION_OUT:
    case QEMU_ASYNC_JOB_MIGRATION_IN:
        return qemuMigrationJobPhaseTypeToString(phase);

    case QEMU_ASYNC_JOB_SAVE:
    case QEMU_ASYNC_JOB_DUMP:
    case QEMU_ASYNC_JOB_NONE:
    case QEMU_ASYNC_JOB_LAST:
        ; /* fall through */
    }

    return "none";
}

int
qemuDomainAsyncJobPhaseFromString(enum qemuDomainAsyncJob job,
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
    case QEMU_ASYNC_JOB_NONE:
    case QEMU_ASYNC_JOB_LAST:
        ; /* fall through */
    }

    if (STREQ(phase, "none"))
        return 0;
    else
        return -1;
}


/* driver must be locked before calling */
void qemuDomainEventQueue(struct qemud_driver *driver,
                          virDomainEventPtr event)
{
    virDomainEventStateQueue(driver->domainEventState, event);
}


static int
qemuDomainObjInitJob(qemuDomainObjPrivatePtr priv)
{
    memset(&priv->job, 0, sizeof(priv->job));

    if (virCondInit(&priv->job.cond) < 0)
        return -1;

    if (virCondInit(&priv->job.asyncCond) < 0) {
        ignore_value(virCondDestroy(&priv->job.cond));
        return -1;
    }

    return 0;
}

static void
qemuDomainObjResetJob(qemuDomainObjPrivatePtr priv)
{
    struct qemuDomainJobObj *job = &priv->job;

    job->active = QEMU_JOB_NONE;
}

static void
qemuDomainObjResetAsyncJob(qemuDomainObjPrivatePtr priv)
{
    struct qemuDomainJobObj *job = &priv->job;

    job->asyncJob = QEMU_ASYNC_JOB_NONE;
    job->phase = 0;
    job->mask = DEFAULT_JOB_MASK;
    job->start = 0;
    memset(&job->info, 0, sizeof(job->info));
}

void
qemuDomainObjRestoreJob(virDomainObjPtr obj,
                        struct qemuDomainJobObj *job)
{
    qemuDomainObjPrivatePtr priv = obj->privateData;

    memset(job, 0, sizeof(*job));
    job->active = priv->job.active;
    job->asyncJob = priv->job.asyncJob;
    job->phase = priv->job.phase;

    qemuDomainObjResetJob(priv);
    qemuDomainObjResetAsyncJob(priv);
}

static void
qemuDomainObjFreeJob(qemuDomainObjPrivatePtr priv)
{
    ignore_value(virCondDestroy(&priv->job.cond));
    ignore_value(virCondDestroy(&priv->job.asyncCond));
}


static void *qemuDomainObjPrivateAlloc(void)
{
    qemuDomainObjPrivatePtr priv;

    if (VIR_ALLOC(priv) < 0)
        return NULL;

    if (qemuDomainObjInitJob(priv) < 0)
        goto error;

    if (!(priv->cons = virConsoleAlloc()))
        goto error;

    priv->migMaxBandwidth = QEMU_DOMAIN_DEFAULT_MIG_BANDWIDTH_MAX;

    return priv;

error:
    VIR_FREE(priv);
    return NULL;
}

static void qemuDomainObjPrivateFree(void *data)
{
    qemuDomainObjPrivatePtr priv = data;

    qemuCapsFree(priv->qemuCaps);

    qemuDomainPCIAddressSetFree(priv->pciaddrs);
    virDomainChrSourceDefFree(priv->monConfig);
    qemuDomainObjFreeJob(priv);
    VIR_FREE(priv->vcpupids);
    VIR_FREE(priv->lockState);
    VIR_FREE(priv->origname);

    virConsoleFree(priv->cons);

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
    VIR_FREE(priv);
}


static int qemuDomainObjPrivateXMLFormat(virBufferPtr buf, void *data)
{
    qemuDomainObjPrivatePtr priv = data;
    const char *monitorpath;

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

        virBufferEscapeString(buf, "  <monitor path='%s'", monitorpath);
        if (priv->monJSON)
            virBufferAddLit(buf, " json='1'");
        virBufferAsprintf(buf, " type='%s'/>\n",
                          virDomainChrTypeToString(priv->monConfig->type));
    }


    if (priv->nvcpupids) {
        int i;
        virBufferAddLit(buf, "  <vcpus>\n");
        for (i = 0 ; i < priv->nvcpupids ; i++) {
            virBufferAsprintf(buf, "    <vcpu pid='%d'/>\n", priv->vcpupids[i]);
        }
        virBufferAddLit(buf, "  </vcpus>\n");
    }

    if (priv->qemuCaps) {
        int i;
        virBufferAddLit(buf, "  <qemuCaps>\n");
        for (i = 0 ; i < QEMU_CAPS_LAST ; i++) {
            if (qemuCapsGet(priv->qemuCaps, i)) {
                virBufferAsprintf(buf, "    <flag name='%s'/>\n",
                                  qemuCapsTypeToString(i));
            }
        }
        virBufferAddLit(buf, "  </qemuCaps>\n");
    }

    if (priv->lockState)
        virBufferAsprintf(buf, "  <lockstate>%s</lockstate>\n", priv->lockState);

    if (priv->job.active || priv->job.asyncJob) {
        virBufferAsprintf(buf, "  <job type='%s' async='%s'",
                          qemuDomainJobTypeToString(priv->job.active),
                          qemuDomainAsyncJobTypeToString(priv->job.asyncJob));
        if (priv->job.phase) {
            virBufferAsprintf(buf, " phase='%s'",
                              qemuDomainAsyncJobPhaseToString(
                                    priv->job.asyncJob, priv->job.phase));
        }
        virBufferAddLit(buf, "/>\n");
    }

    if (priv->fakeReboot)
        virBufferAsprintf(buf, "  <fakereboot/>\n");

    return 0;
}

static int qemuDomainObjPrivateXMLParse(xmlXPathContextPtr ctxt, void *data)
{
    qemuDomainObjPrivatePtr priv = data;
    char *monitorpath;
    char *tmp;
    int n, i;
    xmlNodePtr *nodes = NULL;
    virBitmapPtr qemuCaps = NULL;

    if (VIR_ALLOC(priv->monConfig) < 0) {
        virReportOOMError();
        goto error;
    }

    if (!(monitorpath =
          virXPathString("string(./monitor[1]/@path)", ctxt))) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        "%s", _("no monitor path"));
        goto error;
    }

    tmp = virXPathString("string(./monitor[1]/@type)", ctxt);
    if (tmp)
        priv->monConfig->type = virDomainChrTypeFromString(tmp);
    else
        priv->monConfig->type = VIR_DOMAIN_CHR_TYPE_PTY;
    VIR_FREE(tmp);

    if (virXPathBoolean("count(./monitor[@json = '1']) > 0", ctxt)) {
        priv->monJSON = 1;
    } else {
        priv->monJSON = 0;
    }

    switch (priv->monConfig->type) {
    case VIR_DOMAIN_CHR_TYPE_PTY:
        priv->monConfig->data.file.path = monitorpath;
        break;
    case VIR_DOMAIN_CHR_TYPE_UNIX:
        priv->monConfig->data.nix.path = monitorpath;
        break;
    default:
        VIR_FREE(monitorpath);
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("unsupported monitor type '%s'"),
                        virDomainChrTypeToString(priv->monConfig->type));
        goto error;
    }

    n = virXPathNodeSet("./vcpus/vcpu", ctxt, &nodes);
    if (n < 0)
        goto error;
    if (n) {
        priv->nvcpupids = n;
        if (VIR_REALLOC_N(priv->vcpupids, priv->nvcpupids) < 0) {
            virReportOOMError();
            goto error;
        }

        for (i = 0 ; i < n ; i++) {
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
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        "%s", _("failed to parse qemu capabilities flags"));
        goto error;
    }
    if (n > 0) {
        if (!(qemuCaps = qemuCapsNew()))
            goto error;

        for (i = 0 ; i < n ; i++) {
            char *str = virXMLPropString(nodes[i], "name");
            if (str) {
                int flag = qemuCapsTypeFromString(str);
                if (flag < 0) {
                    qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                    _("Unknown qemu capabilities flag %s"), str);
                    VIR_FREE(str);
                    goto error;
                }
                VIR_FREE(str);
                qemuCapsSet(qemuCaps, flag);
            }
        }

        priv->qemuCaps = qemuCaps;
    }
    VIR_FREE(nodes);

    priv->lockState = virXPathString("string(./lockstate)", ctxt);

    if ((tmp = virXPathString("string(./job[1]/@type)", ctxt))) {
        int type;

        if ((type = qemuDomainJobTypeFromString(tmp)) < 0) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
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
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("Unknown async job type %s"), tmp);
            VIR_FREE(tmp);
            goto error;
        }
        VIR_FREE(tmp);
        priv->job.asyncJob = async;

        if ((tmp = virXPathString("string(./job[1]/@phase)", ctxt))) {
            priv->job.phase = qemuDomainAsyncJobPhaseFromString(async, tmp);
            if (priv->job.phase < 0) {
                qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                _("Unknown job phase %s"), tmp);
                VIR_FREE(tmp);
                goto error;
            }
            VIR_FREE(tmp);
        }
    }

    priv->fakeReboot = virXPathBoolean("boolean(./fakereboot)", ctxt) == 1;

    return 0;

error:
    virDomainChrSourceDefFree(priv->monConfig);
    priv->monConfig = NULL;
    VIR_FREE(nodes);
    qemuCapsFree(qemuCaps);
    return -1;
}


static void
qemuDomainDefNamespaceFree(void *nsdata)
{
    qemuDomainCmdlineDefPtr cmd = nsdata;
    unsigned int i;

    if (!cmd)
        return;

    for (i = 0; i < cmd->num_args; i++)
        VIR_FREE(cmd->args[i]);
    for (i = 0; i < cmd->num_env; i++) {
        VIR_FREE(cmd->env_name[i]);
        VIR_FREE(cmd->env_value[i]);
    }
    VIR_FREE(cmd->args);
    VIR_FREE(cmd->env_name);
    VIR_FREE(cmd->env_value);
    VIR_FREE(cmd);
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
    int n, i;

    if (xmlXPathRegisterNs(ctxt, BAD_CAST "qemu", BAD_CAST QEMU_NAMESPACE_HREF) < 0) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("Failed to register xml namespace '%s'"),
                        QEMU_NAMESPACE_HREF);
        return -1;
    }

    if (VIR_ALLOC(cmd) < 0) {
        virReportOOMError();
        return -1;
    }

    /* first handle the extra command-line arguments */
    n = virXPathNodeSet("./qemu:commandline/qemu:arg", ctxt, &nodes);
    if (n < 0)
        goto error;
    uses_qemu_ns |= n > 0;

    if (n && VIR_ALLOC_N(cmd->args, n) < 0)
        goto no_memory;

    for (i = 0; i < n; i++) {
        cmd->args[cmd->num_args] = virXMLPropString(nodes[i], "value");
        if (cmd->args[cmd->num_args] == NULL) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
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
        goto no_memory;

    if (n && VIR_ALLOC_N(cmd->env_value, n) < 0)
        goto no_memory;

    for (i = 0; i < n; i++) {
        char *tmp;

        tmp = virXMLPropString(nodes[i], "name");
        if (tmp == NULL) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            "%s", _("No qemu environment name specified"));
            goto error;
        }
        if (tmp[0] == '\0') {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            "%s", _("Empty qemu environment name specified"));
            goto error;
        }
        if (!c_isalpha(tmp[0]) && tmp[0] != '_') {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            "%s", _("Invalid environment name, it must begin with a letter or underscore"));
            goto error;
        }
        if (strspn(tmp, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_") != strlen(tmp)) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
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

no_memory:
    virReportOOMError();

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
    unsigned int i;

    if (!cmd->num_args && !cmd->num_env)
        return 0;

    virBufferAddLit(buf, "  <qemu:commandline>\n");
    for (i = 0; i < cmd->num_args; i++)
        virBufferEscapeString(buf, "    <qemu:arg value='%s'/>\n",
                              cmd->args[i]);
    for (i = 0; i < cmd->num_env; i++) {
        virBufferAsprintf(buf, "    <qemu:env name='%s'", cmd->env_name[i]);
        if (cmd->env_value[i])
            virBufferEscapeString(buf, " value='%s'", cmd->env_value[i]);
        virBufferAddLit(buf, "/>\n");
    }
    virBufferAddLit(buf, "  </qemu:commandline>\n");

    return 0;
}

static const char *
qemuDomainDefNamespaceHref(void)
{
    return "xmlns:qemu='" QEMU_NAMESPACE_HREF "'";
}


void qemuDomainSetPrivateDataHooks(virCapsPtr caps)
{
    /* Domain XML parser hooks */
    caps->privateDataAllocFunc = qemuDomainObjPrivateAlloc;
    caps->privateDataFreeFunc = qemuDomainObjPrivateFree;
    caps->privateDataXMLFormat = qemuDomainObjPrivateXMLFormat;
    caps->privateDataXMLParse = qemuDomainObjPrivateXMLParse;

}

void qemuDomainSetNamespaceHooks(virCapsPtr caps)
{
    /* Domain Namespace XML parser hooks */
    caps->ns.parse = qemuDomainDefNamespaceParse;
    caps->ns.free = qemuDomainDefNamespaceFree;
    caps->ns.format = qemuDomainDefNamespaceFormatXML;
    caps->ns.href = qemuDomainDefNamespaceHref;
}

static void
qemuDomainObjSaveJob(struct qemud_driver *driver, virDomainObjPtr obj)
{
    if (!virDomainObjIsActive(obj)) {
        /* don't write the state file yet, it will be written once the domain
         * gets activated */
        return;
    }

    if (virDomainSaveStatus(driver->caps, driver->stateDir, obj) < 0)
        VIR_WARN("Failed to save status on vm %s", obj->def->name);
}

void
qemuDomainObjSetJobPhase(struct qemud_driver *driver,
                         virDomainObjPtr obj,
                         int phase)
{
    qemuDomainObjPrivatePtr priv = obj->privateData;

    if (!priv->job.asyncJob)
        return;

    priv->job.phase = phase;
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
qemuDomainObjDiscardAsyncJob(struct qemud_driver *driver, virDomainObjPtr obj)
{
    qemuDomainObjPrivatePtr priv = obj->privateData;

    if (priv->job.active == QEMU_JOB_ASYNC_NESTED)
        qemuDomainObjResetJob(priv);
    qemuDomainObjResetAsyncJob(priv);
    qemuDomainObjSaveJob(driver, obj);
}

static bool
qemuDomainNestedJobAllowed(qemuDomainObjPrivatePtr priv, enum qemuDomainJob job)
{
    return !priv->job.asyncJob || (priv->job.mask & JOB_MASK(job)) != 0;
}

bool
qemuDomainJobAllowed(qemuDomainObjPrivatePtr priv, enum qemuDomainJob job)
{
    return !priv->job.active && qemuDomainNestedJobAllowed(priv, job);
}

/* Give up waiting for mutex after 30 seconds */
#define QEMU_JOB_WAIT_TIME (1000ull * 30)

/*
 * obj must be locked before calling; driver_locked says if qemu_driver is
 * locked or not.
 */
static int ATTRIBUTE_NONNULL(1)
qemuDomainObjBeginJobInternal(struct qemud_driver *driver,
                              bool driver_locked,
                              virDomainObjPtr obj,
                              enum qemuDomainJob job,
                              enum qemuDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivatePtr priv = obj->privateData;
    unsigned long long now;
    unsigned long long then;
    bool nested = job == QEMU_JOB_ASYNC_NESTED;

    priv->jobs_queued++;

    if (virTimeMillisNow(&now) < 0)
        return -1;
    then = now + QEMU_JOB_WAIT_TIME;

    virDomainObjRef(obj);
    if (driver_locked)
        qemuDriverUnlock(driver);

retry:
    if (driver->max_queued &&
        priv->jobs_queued > driver->max_queued) {
        goto error;
    }

    while (!nested && !qemuDomainNestedJobAllowed(priv, job)) {
        if (virCondWaitUntil(&priv->job.asyncCond, &obj->lock, then) < 0)
            goto error;
    }

    while (priv->job.active) {
        if (virCondWaitUntil(&priv->job.cond, &obj->lock, then) < 0)
            goto error;
    }

    /* No job is active but a new async job could have been started while obj
     * was unlocked, so we need to recheck it. */
    if (!nested && !qemuDomainNestedJobAllowed(priv, job))
        goto retry;

    qemuDomainObjResetJob(priv);

    if (job != QEMU_JOB_ASYNC) {
        VIR_DEBUG("Starting job: %s (async=%s)",
                   qemuDomainJobTypeToString(job),
                   qemuDomainAsyncJobTypeToString(priv->job.asyncJob));
        priv->job.active = job;
    } else {
        VIR_DEBUG("Starting async job: %s",
                  qemuDomainAsyncJobTypeToString(asyncJob));
        qemuDomainObjResetAsyncJob(priv);
        priv->job.asyncJob = asyncJob;
        priv->job.start = now;
    }

    if (driver_locked) {
        virDomainObjUnlock(obj);
        qemuDriverLock(driver);
        virDomainObjLock(obj);
    }

    qemuDomainObjSaveJob(driver, obj);

    return 0;

error:
    if (errno == ETIMEDOUT)
        qemuReportError(VIR_ERR_OPERATION_TIMEOUT,
                        "%s", _("cannot acquire state change lock"));
    else if (driver->max_queued &&
             priv->jobs_queued > driver->max_queued)
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        "%s", _("cannot acquire state change lock "
                                "due to max_queued limit"));
    else
        virReportSystemError(errno,
                             "%s", _("cannot acquire job mutex"));
    priv->jobs_queued--;
    if (driver_locked) {
        virDomainObjUnlock(obj);
        qemuDriverLock(driver);
        virDomainObjLock(obj);
    }
    /* Safe to ignore value since ref count was incremented above */
    ignore_value(virDomainObjUnref(obj));
    return -1;
}

/*
 * obj must be locked before calling, qemud_driver must NOT be locked
 *
 * This must be called by anything that will change the VM state
 * in any way, or anything that will use the QEMU monitor.
 *
 * Upon successful return, the object will have its ref count increased,
 * successful calls must be followed by EndJob eventually
 */
int qemuDomainObjBeginJob(struct qemud_driver *driver,
                          virDomainObjPtr obj,
                          enum qemuDomainJob job)
{
    return qemuDomainObjBeginJobInternal(driver, false, obj, job,
                                         QEMU_ASYNC_JOB_NONE);
}

int qemuDomainObjBeginAsyncJob(struct qemud_driver *driver,
                               virDomainObjPtr obj,
                               enum qemuDomainAsyncJob asyncJob)
{
    return qemuDomainObjBeginJobInternal(driver, false, obj, QEMU_JOB_ASYNC,
                                         asyncJob);
}

/*
 * obj must be locked before calling. If qemud_driver is passed, it MUST be
 * locked; otherwise it MUST NOT be locked.
 *
 * This must be called by anything that will change the VM state
 * in any way, or anything that will use the QEMU monitor.
 *
 * Upon successful return, the object will have its ref count increased,
 * successful calls must be followed by EndJob eventually
 */
int qemuDomainObjBeginJobWithDriver(struct qemud_driver *driver,
                                    virDomainObjPtr obj,
                                    enum qemuDomainJob job)
{
    if (job <= QEMU_JOB_NONE || job >= QEMU_JOB_ASYNC) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("Attempt to start invalid job"));
        return -1;
    }

    return qemuDomainObjBeginJobInternal(driver, true, obj, job,
                                         QEMU_ASYNC_JOB_NONE);
}

int qemuDomainObjBeginAsyncJobWithDriver(struct qemud_driver *driver,
                                         virDomainObjPtr obj,
                                         enum qemuDomainAsyncJob asyncJob)
{
    return qemuDomainObjBeginJobInternal(driver, true, obj, QEMU_JOB_ASYNC,
                                         asyncJob);
}

/*
 * obj must be locked before calling, qemud_driver does not matter
 *
 * To be called after completing the work associated with the
 * earlier qemuDomainBeginJob() call
 *
 * Returns remaining refcount on 'obj', maybe 0 to indicated it
 * was deleted
 */
int qemuDomainObjEndJob(struct qemud_driver *driver, virDomainObjPtr obj)
{
    qemuDomainObjPrivatePtr priv = obj->privateData;

    priv->jobs_queued--;

    VIR_DEBUG("Stopping job: %s (async=%s)",
              qemuDomainJobTypeToString(priv->job.active),
              qemuDomainAsyncJobTypeToString(priv->job.asyncJob));

    qemuDomainObjResetJob(priv);
    qemuDomainObjSaveJob(driver, obj);
    virCondSignal(&priv->job.cond);

    return virDomainObjUnref(obj);
}

int
qemuDomainObjEndAsyncJob(struct qemud_driver *driver, virDomainObjPtr obj)
{
    qemuDomainObjPrivatePtr priv = obj->privateData;

    priv->jobs_queued--;

    VIR_DEBUG("Stopping async job: %s",
              qemuDomainAsyncJobTypeToString(priv->job.asyncJob));

    qemuDomainObjResetAsyncJob(priv);
    qemuDomainObjSaveJob(driver, obj);
    virCondBroadcast(&priv->job.asyncCond);

    return virDomainObjUnref(obj);
}

static int
qemuDomainObjEnterMonitorInternal(struct qemud_driver *driver,
                                  bool driver_locked,
                                  virDomainObjPtr obj,
                                  enum qemuDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivatePtr priv = obj->privateData;

    if (asyncJob != QEMU_ASYNC_JOB_NONE) {
        if (asyncJob != priv->job.asyncJob) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("unexpected async job %d"), asyncJob);
            return -1;
        }
        if (qemuDomainObjBeginJobInternal(driver, driver_locked, obj,
                                          QEMU_JOB_ASYNC_NESTED,
                                          QEMU_ASYNC_JOB_NONE) < 0)
            return -1;
        if (!virDomainObjIsActive(obj)) {
            qemuReportError(VIR_ERR_OPERATION_FAILED, "%s",
                            _("domain is no longer running"));
            /* Still referenced by the containing async job.  */
            ignore_value(qemuDomainObjEndJob(driver, obj));
            return -1;
        }
    }

    qemuMonitorLock(priv->mon);
    qemuMonitorRef(priv->mon);
    ignore_value(virTimeMillisNow(&priv->monStart));
    virDomainObjUnlock(obj);
    if (driver_locked)
        qemuDriverUnlock(driver);

    return 0;
}

static void ATTRIBUTE_NONNULL(1)
qemuDomainObjExitMonitorInternal(struct qemud_driver *driver,
                                 bool driver_locked,
                                 virDomainObjPtr obj)
{
    qemuDomainObjPrivatePtr priv = obj->privateData;
    int refs;

    refs = qemuMonitorUnref(priv->mon);

    if (refs > 0)
        qemuMonitorUnlock(priv->mon);

    if (driver_locked)
        qemuDriverLock(driver);
    virDomainObjLock(obj);

    priv->monStart = 0;
    if (refs == 0) {
        priv->mon = NULL;
    }

    if (priv->job.active == QEMU_JOB_ASYNC_NESTED) {
        qemuDomainObjResetJob(priv);
        qemuDomainObjSaveJob(driver, obj);
        virCondSignal(&priv->job.cond);

        /* safe to ignore since the surrounding async job increased
         * the reference counter as well */
        ignore_value(virDomainObjUnref(obj));
    }
}

/*
 * obj must be locked before calling, qemud_driver must be unlocked
 *
 * To be called immediately before any QEMU monitor API call
 * Must have already either called qemuDomainObjBeginJob() and checked
 * that the VM is still active; may not be used for nested async jobs.
 *
 * To be followed with qemuDomainObjExitMonitor() once complete
 */
void qemuDomainObjEnterMonitor(struct qemud_driver *driver,
                               virDomainObjPtr obj)
{
    ignore_value(qemuDomainObjEnterMonitorInternal(driver, false, obj,
                                                   QEMU_ASYNC_JOB_NONE));
}

/* obj must NOT be locked before calling, qemud_driver must be unlocked
 *
 * Should be paired with an earlier qemuDomainObjEnterMonitor() call
 */
void qemuDomainObjExitMonitor(struct qemud_driver *driver,
                              virDomainObjPtr obj)
{
    qemuDomainObjExitMonitorInternal(driver, false, obj);
}

/*
 * obj must be locked before calling, qemud_driver must be locked
 *
 * To be called immediately before any QEMU monitor API call
 * Must have already either called qemuDomainObjBeginJobWithDriver() and
 * checked that the VM is still active; may not be used for nested async jobs.
 *
 * To be followed with qemuDomainObjExitMonitorWithDriver() once complete
 */
void qemuDomainObjEnterMonitorWithDriver(struct qemud_driver *driver,
                                         virDomainObjPtr obj)
{
    ignore_value(qemuDomainObjEnterMonitorInternal(driver, true, obj,
                                                   QEMU_ASYNC_JOB_NONE));
}

/*
 * obj and qemud_driver must be locked before calling
 *
 * To be called immediately before any QEMU monitor API call.
 * Must have already either called qemuDomainObjBeginJobWithDriver()
 * and checked that the VM is still active, with asyncJob of
 * QEMU_ASYNC_JOB_NONE; or already called qemuDomainObjBeginAsyncJob,
 * with the same asyncJob.
 *
 * Returns 0 if job was started, in which case this must be followed with
 * qemuDomainObjExitMonitorWithDriver(); or -1 if the job could not be
 * started (probably because the vm exited in the meantime).
 */
int
qemuDomainObjEnterMonitorAsync(struct qemud_driver *driver,
                               virDomainObjPtr obj,
                               enum qemuDomainAsyncJob asyncJob)
{
    return qemuDomainObjEnterMonitorInternal(driver, true, obj, asyncJob);
}

/* obj must NOT be locked before calling, qemud_driver must be unlocked,
 * and will be locked after returning
 *
 * Should be paired with an earlier qemuDomainObjEnterMonitorWithDriver() call
 */
void qemuDomainObjExitMonitorWithDriver(struct qemud_driver *driver,
                                        virDomainObjPtr obj)
{
    qemuDomainObjExitMonitorInternal(driver, true, obj);
}



static int
qemuDomainObjEnterAgentInternal(struct qemud_driver *driver,
                                bool driver_locked,
                                virDomainObjPtr obj)
{
    qemuDomainObjPrivatePtr priv = obj->privateData;

    qemuAgentLock(priv->agent);
    qemuAgentRef(priv->agent);
    ignore_value(virTimeMillisNow(&priv->agentStart));
    virDomainObjUnlock(obj);
    if (driver_locked)
        qemuDriverUnlock(driver);

    return 0;
}

static void ATTRIBUTE_NONNULL(1)
qemuDomainObjExitAgentInternal(struct qemud_driver *driver,
                               bool driver_locked,
                               virDomainObjPtr obj)
{
    qemuDomainObjPrivatePtr priv = obj->privateData;
    int refs;

    refs = qemuAgentUnref(priv->agent);

    if (refs > 0)
        qemuAgentUnlock(priv->agent);

    if (driver_locked)
        qemuDriverLock(driver);
    virDomainObjLock(obj);

    priv->agentStart = 0;
    if (refs == 0) {
        priv->agent = NULL;
    }
}

/*
 * obj must be locked before calling, qemud_driver must be unlocked
 *
 * To be called immediately before any QEMU agent API call
 * Must have already either called qemuDomainObjBeginJob() and checked
 * that the VM is still active;
 *
 * To be followed with qemuDomainObjExitAgent() once complete
 */
void qemuDomainObjEnterAgent(struct qemud_driver *driver,
                             virDomainObjPtr obj)
{
    ignore_value(qemuDomainObjEnterAgentInternal(driver, false, obj));
}

/* obj must NOT be locked before calling, qemud_driver must be unlocked
 *
 * Should be paired with an earlier qemuDomainObjEnterAgent() call
 */
void qemuDomainObjExitAgent(struct qemud_driver *driver,
                            virDomainObjPtr obj)
{
    qemuDomainObjExitAgentInternal(driver, false, obj);
}

/*
 * obj must be locked before calling, qemud_driver must be locked
 *
 * To be called immediately before any QEMU agent API call
 * Must have already either called qemuDomainObjBeginJobWithDriver() and
 * checked that the VM is still active; may not be used for nested async jobs.
 *
 * To be followed with qemuDomainObjExitAgentWithDriver() once complete
 */
void qemuDomainObjEnterAgentWithDriver(struct qemud_driver *driver,
                                       virDomainObjPtr obj)
{
    ignore_value(qemuDomainObjEnterAgentInternal(driver, true, obj));
}

/* obj must NOT be locked before calling, qemud_driver must be unlocked,
 * and will be locked after returning
 *
 * Should be paired with an earlier qemuDomainObjEnterAgentWithDriver() call
 */
void qemuDomainObjExitAgentWithDriver(struct qemud_driver *driver,
                                      virDomainObjPtr obj)
{
    qemuDomainObjExitAgentInternal(driver, true, obj);
}

void qemuDomainObjEnterRemoteWithDriver(struct qemud_driver *driver,
                                        virDomainObjPtr obj)
{
    virDomainObjRef(obj);
    virDomainObjUnlock(obj);
    qemuDriverUnlock(driver);
}

void qemuDomainObjExitRemoteWithDriver(struct qemud_driver *driver,
                                       virDomainObjPtr obj)
{
    qemuDriverLock(driver);
    virDomainObjLock(obj);
    /* Safe to ignore value, since we incremented ref in
     * qemuDomainObjEnterRemoteWithDriver */
    ignore_value(virDomainObjUnref(obj));
}


char *qemuDomainDefFormatXML(struct qemud_driver *driver,
                             virDomainDefPtr def,
                             unsigned int flags)
{
    char *ret = NULL;
    virCPUDefPtr cpu = NULL;
    virCPUDefPtr def_cpu = def->cpu;

    /* Update guest CPU requirements according to host CPU */
    if ((flags & VIR_DOMAIN_XML_UPDATE_CPU) &&
        def_cpu &&
        (def_cpu->mode != VIR_CPU_MODE_CUSTOM || def_cpu->model)) {
        if (!driver->caps || !driver->caps->host.cpu) {
            qemuReportError(VIR_ERR_OPERATION_FAILED,
                            "%s", _("cannot get host CPU capabilities"));
            goto cleanup;
        }

        if (!(cpu = virCPUDefCopy(def_cpu)) ||
            cpuUpdate(cpu, driver->caps->host.cpu) < 0)
            goto cleanup;
        def->cpu = cpu;
    }

    ret = virDomainDefFormat(def, flags);

cleanup:
    def->cpu = def_cpu;
    virCPUDefFree(cpu);
    return ret;
}

char *qemuDomainFormatXML(struct qemud_driver *driver,
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
qemuDomainDefFormatLive(struct qemud_driver *driver,
                        virDomainDefPtr def,
                        bool inactive)
{
    unsigned int flags = QEMU_DOMAIN_FORMAT_LIVE_FLAGS;

    if (inactive)
        flags |= VIR_DOMAIN_XML_INACTIVE;

    return qemuDomainDefFormatXML(driver, def, flags);
}


void qemuDomainObjTaint(struct qemud_driver *driver,
                        virDomainObjPtr obj,
                        enum virDomainTaintFlags taint,
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


void qemuDomainObjCheckTaint(struct qemud_driver *driver,
                             virDomainObjPtr obj,
                             int logFD)
{
    int i;

    if (driver->privileged &&
        (!driver->clearEmulatorCapabilities ||
         driver->user == 0 ||
         driver->group == 0))
        qemuDomainObjTaint(driver, obj, VIR_DOMAIN_TAINT_HIGH_PRIVILEGES, logFD);

    if (obj->def->namespaceData) {
        qemuDomainCmdlineDefPtr qemucmd = obj->def->namespaceData;
        if (qemucmd->num_args || qemucmd->num_env)
            qemuDomainObjTaint(driver, obj, VIR_DOMAIN_TAINT_CUSTOM_ARGV, logFD);
    }

    if (obj->def->cpu && obj->def->cpu->mode == VIR_CPU_MODE_HOST_PASSTHROUGH)
        qemuDomainObjTaint(driver, obj, VIR_DOMAIN_TAINT_HOST_CPU, logFD);

    for (i = 0 ; i < obj->def->ndisks ; i++)
        qemuDomainObjCheckDiskTaint(driver, obj, obj->def->disks[i], logFD);

    for (i = 0 ; i < obj->def->nnets ; i++)
        qemuDomainObjCheckNetTaint(driver, obj, obj->def->nets[i], logFD);
}


void qemuDomainObjCheckDiskTaint(struct qemud_driver *driver,
                                 virDomainObjPtr obj,
                                 virDomainDiskDefPtr disk,
                                 int logFD)
{
    if (!disk->driverType &&
        driver->allowDiskFormatProbing)
        qemuDomainObjTaint(driver, obj, VIR_DOMAIN_TAINT_DISK_PROBING, logFD);

    if (disk->rawio == 1)
        qemuDomainObjTaint(driver, obj, VIR_DOMAIN_TAINT_HIGH_PRIVILEGES, logFD);
}


void qemuDomainObjCheckNetTaint(struct qemud_driver *driver,
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
qemuDomainOpenLogHelper(struct qemud_driver *driver,
                        virDomainObjPtr vm,
                        int oflags,
                        mode_t mode)
{
    char *logfile;
    int fd = -1;

    if (virAsprintf(&logfile, "%s/%s.log", driver->logDir, vm->def->name) < 0) {
        virReportOOMError();
        return -1;
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

cleanup:
    VIR_FREE(logfile);
    return fd;
}


int
qemuDomainCreateLog(struct qemud_driver *driver, virDomainObjPtr vm,
                    bool append)
{
    int oflags;

    oflags = O_CREAT | O_WRONLY;
    /* Only logrotate files in /var/log, so only append if running privileged */
    if (driver->privileged || append)
        oflags |= O_APPEND;
    else
        oflags |= O_TRUNC;

    return qemuDomainOpenLogHelper(driver, vm, oflags, S_IRUSR | S_IWUSR);
}


int
qemuDomainOpenLog(struct qemud_driver *driver, virDomainObjPtr vm, off_t pos)
{
    int fd;
    off_t off;
    int whence;

    if ((fd = qemuDomainOpenLogHelper(driver, vm, O_RDONLY, 0)) < 0)
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


int qemuDomainAppendLog(struct qemud_driver *driver,
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

    if (virVasprintf(&message, fmt, argptr) < 0) {
        virReportOOMError();
        goto cleanup;
    }
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
qemuFindQemuImgBinary(struct qemud_driver *driver)
{
    if (!driver->qemuImgBinary) {
        driver->qemuImgBinary = virFindFileInPath("kvm-img");
        if (!driver->qemuImgBinary)
            driver->qemuImgBinary = virFindFileInPath("qemu-img");
        if (!driver->qemuImgBinary)
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            "%s", _("unable to find kvm-img or qemu-img"));
    }

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
    char *tmp;

    virUUIDFormat(vm->def->uuid, uuidstr);
    newxml = virDomainSnapshotDefFormat(uuidstr, snapshot->def,
                                        QEMU_DOMAIN_FORMAT_LIVE_FLAGS, 1);
    if (newxml == NULL)
        return -1;

    if (virAsprintf(&snapDir, "%s/%s", snapshotDir, vm->def->name) < 0) {
        virReportOOMError();
        goto cleanup;
    }
    if (virFileMakePath(snapDir) < 0) {
        virReportSystemError(errno, _("cannot create snapshot directory '%s'"),
                             snapDir);
        goto cleanup;
    }

    if (virAsprintf(&snapFile, "%s/%s.xml", snapDir, snapshot->def->name) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if (virAsprintf(&tmp, "snapshot-edit %s", vm->def->name) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    ret = virXMLSaveFile(snapFile, snapshot->def->name, tmp, newxml);
    VIR_FREE(tmp);

cleanup:
    VIR_FREE(snapFile);
    VIR_FREE(snapDir);
    VIR_FREE(newxml);
    return ret;
}

/* The domain is expected to be locked and inactive. Return -1 on normal
 * failure, 1 if we skipped a disk due to try_all.  */
static int
qemuDomainSnapshotForEachQcow2Raw(struct qemud_driver *driver,
                                  virDomainDefPtr def,
                                  const char *name,
                                  const char *op,
                                  bool try_all,
                                  int ndisks)
{
    const char *qemuimgarg[] = { NULL, "snapshot", NULL, NULL, NULL, NULL };
    int i;
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
            if (!def->disks[i]->driverType ||
                STRNEQ(def->disks[i]->driverType, "qcow2")) {
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
                qemuReportError(VIR_ERR_OPERATION_INVALID,
                                _("Disk device '%s' does not support"
                                  " snapshotting"),
                                def->disks[i]->dst);
                return -1;
            }

            qemuimgarg[4] = def->disks[i]->src;

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
qemuDomainSnapshotForEachQcow2(struct qemud_driver *driver,
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
qemuDomainSnapshotDiscard(struct qemud_driver *driver,
                          virDomainObjPtr vm,
                          virDomainSnapshotObjPtr snap,
                          bool update_current,
                          bool metadata_only)
{
    char *snapFile = NULL;
    int ret = -1;
    qemuDomainObjPrivatePtr priv;
    virDomainSnapshotObjPtr parentsnap = NULL;

    if (!metadata_only) {
        if (!virDomainObjIsActive(vm)) {
            /* Ignore any skipped disks */
            if (qemuDomainSnapshotForEachQcow2(driver, vm, snap, "-d",
                                               true) < 0)
                goto cleanup;
        } else {
            priv = vm->privateData;
            qemuDomainObjEnterMonitorWithDriver(driver, vm);
            /* we continue on even in the face of error */
            qemuMonitorDeleteSnapshot(priv->mon, snap->def->name);
            qemuDomainObjExitMonitorWithDriver(driver, vm);
        }
    }

    if (virAsprintf(&snapFile, "%s/%s/%s.xml", driver->snapshotDir,
                    vm->def->name, snap->def->name) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if (snap == vm->current_snapshot) {
        if (update_current && snap->def->parent) {
            parentsnap = virDomainSnapshotFindByName(&vm->snapshots,
                                                     snap->def->parent);
            if (!parentsnap) {
                VIR_WARN("missing parent snapshot matching name '%s'",
                         snap->def->parent);
            } else {
                parentsnap->def->current = true;
                if (qemuDomainSnapshotWriteMetadata(vm, parentsnap,
                                                    driver->snapshotDir) < 0) {
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
    virDomainSnapshotObjListRemove(&vm->snapshots, snap);

    ret = 0;

cleanup:
    VIR_FREE(snapFile);

    return ret;
}

/* Hash iterator callback to discard multiple snapshots.  */
void qemuDomainSnapshotDiscardAll(void *payload,
                                  const void *name ATTRIBUTE_UNUSED,
                                  void *data)
{
    virDomainSnapshotObjPtr snap = payload;
    struct qemu_snap_remove *curr = data;
    int err;

    if (snap->def->current)
        curr->current = true;
    err = qemuDomainSnapshotDiscard(curr->driver, curr->vm, snap, false,
                                    curr->metadata_only);
    if (err && !curr->err)
        curr->err = err;
}

int
qemuDomainSnapshotDiscardAllMetadata(struct qemud_driver *driver,
                                     virDomainObjPtr vm)
{
    struct qemu_snap_remove rem;

    rem.driver = driver;
    rem.vm = vm;
    rem.metadata_only = true;
    rem.err = 0;
    virHashForEach(vm->snapshots.objs, qemuDomainSnapshotDiscardAll, &rem);

    return rem.err;
}

/*
 * The caller must hold a lock on both driver and vm, and there must
 * be no remaining references to vm.
 */
void
qemuDomainRemoveInactive(struct qemud_driver *driver,
                         virDomainObjPtr vm)
{
    char *snapDir;

    /* Remove any snapshot metadata prior to removing the domain */
    if (qemuDomainSnapshotDiscardAllMetadata(driver, vm) < 0) {
        VIR_WARN("unable to remove all snapshots for domain %s",
                 vm->def->name);
    }
    else if (virAsprintf(&snapDir, "%s/%s", driver->snapshotDir,
                         vm->def->name) < 0) {
        VIR_WARN("unable to remove snapshot directory %s/%s",
                 driver->snapshotDir, vm->def->name);
    } else {
        if (rmdir(snapDir) < 0 && errno != ENOENT)
            VIR_WARN("unable to remove snapshot directory %s", snapDir);
        VIR_FREE(snapDir);
    }
    virDomainRemoveInactive(&driver->domains, vm);
}

void
qemuDomainSetFakeReboot(struct qemud_driver *driver,
                        virDomainObjPtr vm,
                        bool value)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (priv->fakeReboot == value)
        return;

    priv->fakeReboot = value;

    if (virDomainSaveStatus(driver->caps, driver->stateDir, vm) < 0)
        VIR_WARN("Failed to save status on vm %s", vm->def->name);
}

int
qemuDomainCheckDiskPresence(struct qemud_driver *driver,
                            virDomainObjPtr vm,
                            bool cold_boot)
{
    int ret = -1;
    int i;
    virDomainDiskDefPtr disk;
    char uuid[VIR_UUID_STRING_BUFLEN];
    virDomainEventPtr event = NULL;

    virUUIDFormat(vm->def->uuid, uuid);

    for (i = 0; i < vm->def->ndisks; i++) {
        disk = vm->def->disks[i];

        if (!disk->startupPolicy || !disk->src)
            continue;

        if (virFileAccessibleAs(disk->src, F_OK,
                                driver->user,
                                driver->group) >= 0) {
            /* disk accessible */
            continue;
        }

        switch ((enum virDomainStartupPolicy) disk->startupPolicy) {
            case VIR_DOMAIN_STARTUP_POLICY_OPTIONAL:
                break;

            case VIR_DOMAIN_STARTUP_POLICY_MANDATORY:
                virReportSystemError(errno,
                                     _("cannot access file '%s'"),
                                     disk->src);
                goto cleanup;
                break;

            case VIR_DOMAIN_STARTUP_POLICY_REQUISITE:
                if (cold_boot) {
                    virReportSystemError(errno,
                                         _("cannot access file '%s'"),
                                         disk->src);
                    goto cleanup;
                }
                break;

            case VIR_DOMAIN_STARTUP_POLICY_DEFAULT:
            case VIR_DOMAIN_STARTUP_POLICY_LAST:
                /* this should never happen */
                break;
        }

        VIR_DEBUG("Dropping disk '%s' on domain '%s' (UUID '%s') "
                  "due to inaccessible source '%s'",
                  disk->dst, vm->def->name, uuid, disk->src);

        event = virDomainEventDiskChangeNewFromObj(vm, disk->src, NULL, disk->info.alias,
                                                   VIR_DOMAIN_EVENT_DISK_CHANGE_MISSING_ON_START);
        if (event)
            qemuDomainEventQueue(driver, event);

        VIR_FREE(disk->src);
    }

    ret = 0;

cleanup:
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
    int i;

    VIR_DEBUG("vm=%s, cb=%p", vm->def->name, cb);

    for (i = 0; i < priv->ncleanupCallbacks; i++) {
        if (priv->cleanupCallbacks[i] == cb)
            return 0;
    }

    if (VIR_RESIZE_N(priv->cleanupCallbacks,
                     priv->ncleanupCallbacks_max,
                     priv->ncleanupCallbacks, 1) < 0) {
        virReportOOMError();
        return -1;
    }

    priv->cleanupCallbacks[priv->ncleanupCallbacks++] = cb;
    return 0;
}

void
qemuDomainCleanupRemove(virDomainObjPtr vm,
                        qemuDomainCleanupCallback cb)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int i;

    VIR_DEBUG("vm=%s, cb=%p", vm->def->name, cb);

    for (i = 0; i < priv->ncleanupCallbacks; i++) {
        if (priv->cleanupCallbacks[i] == cb) {
            memmove(priv->cleanupCallbacks + i,
                    priv->cleanupCallbacks + i + 1,
                    priv->ncleanupCallbacks - i - 1);
            priv->ncleanupCallbacks--;
        }
    }

    VIR_SHRINK_N(priv->cleanupCallbacks,
                 priv->ncleanupCallbacks_max,
                 priv->ncleanupCallbacks_max - priv->ncleanupCallbacks);
}

void
qemuDomainCleanupRun(struct qemud_driver *driver,
                     virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int i;

    VIR_DEBUG("driver=%p, vm=%s", driver, vm->def->name);

    /* run cleanup callbacks in reverse order */
    for (i = priv->ncleanupCallbacks - 1; i >= 0; i--) {
        if (priv->cleanupCallbacks[i])
            priv->cleanupCallbacks[i](driver, vm);
    }

    VIR_FREE(priv->cleanupCallbacks);
    priv->ncleanupCallbacks = 0;
    priv->ncleanupCallbacks_max = 0;
}
