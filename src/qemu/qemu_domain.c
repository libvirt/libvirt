/*
 * qemu_domain.h: QEMU domain private state
 *
 * Copyright (C) 2006-2011 Red Hat, Inc.
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
#include "memory.h"
#include "logging.h"
#include "virterror_internal.h"
#include "c-ctype.h"
#include "event.h"
#include "cpu/cpu.h"
#include "ignore-value.h"

#include <sys/time.h>

#include <libxml/xpathInternals.h>

#define VIR_FROM_THIS VIR_FROM_QEMU

#define QEMU_NAMESPACE_HREF "http://libvirt.org/schemas/domain/qemu/1.0"

#define timeval_to_ms(tv)       (((tv).tv_sec * 1000ull) + ((tv).tv_usec / 1000))


static void qemuDomainEventDispatchFunc(virConnectPtr conn,
                                        virDomainEventPtr event,
                                        virConnectDomainEventGenericCallback cb,
                                        void *cbopaque,
                                        void *opaque)
{
    struct qemud_driver *driver = opaque;

    /* Drop the lock whle dispatching, for sake of re-entrancy */
    qemuDriverUnlock(driver);
    virDomainEventDispatchDefaultFunc(conn, event, cb, cbopaque, NULL);
    qemuDriverLock(driver);
}

void qemuDomainEventFlush(int timer ATTRIBUTE_UNUSED, void *opaque)
{
    struct qemud_driver *driver = opaque;
    virDomainEventQueue tempQueue;

    qemuDriverLock(driver);

    driver->domainEventDispatching = 1;

    /* Copy the queue, so we're reentrant safe */
    tempQueue.count = driver->domainEventQueue->count;
    tempQueue.events = driver->domainEventQueue->events;
    driver->domainEventQueue->count = 0;
    driver->domainEventQueue->events = NULL;

    virEventUpdateTimeout(driver->domainEventTimer, -1);
    virDomainEventQueueDispatch(&tempQueue,
                                driver->domainEventCallbacks,
                                qemuDomainEventDispatchFunc,
                                driver);

    /* Purge any deleted callbacks */
    virDomainEventCallbackListPurgeMarked(driver->domainEventCallbacks);

    driver->domainEventDispatching = 0;
    qemuDriverUnlock(driver);
}


/* driver must be locked before calling */
void qemuDomainEventQueue(struct qemud_driver *driver,
                          virDomainEventPtr event)
{
    if (virDomainEventQueuePush(driver->domainEventQueue,
                                event) < 0)
        virDomainEventFree(event);
    if (driver->domainEventQueue->count == 1)
        virEventUpdateTimeout(driver->domainEventTimer, 0);
}


static void *qemuDomainObjPrivateAlloc(void)
{
    qemuDomainObjPrivatePtr priv;

    if (VIR_ALLOC(priv) < 0)
        return NULL;

    return priv;
}

static void qemuDomainObjPrivateFree(void *data)
{
    qemuDomainObjPrivatePtr priv = data;

    qemuDomainPCIAddressSetFree(priv->pciaddrs);
    virDomainChrSourceDefFree(priv->monConfig);
    VIR_FREE(priv->vcpupids);

    /* This should never be non-NULL if we get here, but just in case... */
    if (priv->mon) {
        VIR_ERROR0(_("Unexpected QEMU monitor still active during domain deletion"));
        qemuMonitorClose(priv->mon);
    }
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
        virBufferVSprintf(buf, " type='%s'/>\n",
                          virDomainChrTypeToString(priv->monConfig->type));
    }


    if (priv->nvcpupids) {
        int i;
        virBufferAddLit(buf, "  <vcpus>\n");
        for (i = 0 ; i < priv->nvcpupids ; i++) {
            virBufferVSprintf(buf, "    <vcpu pid='%d'/>\n", priv->vcpupids[i]);
        }
        virBufferAddLit(buf, "  </vcpus>\n");
    }

    return 0;
}

static int qemuDomainObjPrivateXMLParse(xmlXPathContextPtr ctxt, void *data)
{
    qemuDomainObjPrivatePtr priv = data;
    char *monitorpath;
    char *tmp;
    int n, i;
    xmlNodePtr *nodes = NULL;

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

    return 0;

error:
    virDomainChrSourceDefFree(priv->monConfig);
    priv->monConfig = NULL;
    VIR_FREE(nodes);
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
qemuDomainDefNamespaceParse(xmlDocPtr xml,
                            xmlNodePtr root,
                            xmlXPathContextPtr ctxt,
                            void **data)
{
    qemuDomainCmdlineDefPtr cmd = NULL;
    xmlNsPtr ns;
    xmlNodePtr *nodes = NULL;
    int n, i;

    ns = xmlSearchNs(xml, root, BAD_CAST "qemu");
    if (!ns)
        /* this is fine; it just means there was no qemu namespace listed */
        return 0;

    if (STRNEQ((const char *)ns->href, QEMU_NAMESPACE_HREF)) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("Found namespace '%s' doesn't match expected '%s'"),
                        ns->href, QEMU_NAMESPACE_HREF);
        return -1;
    }

    if (xmlXPathRegisterNs(ctxt, ns->prefix, ns->href) < 0) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("Failed to register xml namespace '%s'"), ns->href);
        return -1;
    }

    if (VIR_ALLOC(cmd) < 0) {
        virReportOOMError();
        return -1;
    }

    /* first handle the extra command-line arguments */
    n = virXPathNodeSet("./qemu:commandline/qemu:arg", ctxt, &nodes);
    if (n < 0)
        /* virXPathNodeSet already set the error */
        goto error;

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
        /* virXPathNodeSet already set the error */
        goto error;

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

    *data = cmd;

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
        virBufferVSprintf(buf, "    <qemu:env name='%s'", cmd->env_name[i]);
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

/*
 * obj must be locked before calling, qemud_driver must NOT be locked
 *
 * This must be called by anything that will change the VM state
 * in any way, or anything that will use the QEMU monitor.
 *
 * Upon successful return, the object will have its ref count increased,
 * successful calls must be followed by EndJob eventually
 */

/* Give up waiting for mutex after 30 seconds */
#define QEMU_JOB_WAIT_TIME (1000ull * 30)

int qemuDomainObjBeginJob(virDomainObjPtr obj)
{
    qemuDomainObjPrivatePtr priv = obj->privateData;
    struct timeval now;
    unsigned long long then;

    if (gettimeofday(&now, NULL) < 0) {
        virReportSystemError(errno, "%s",
                             _("cannot get time of day"));
        return -1;
    }
    then = timeval_to_ms(now) + QEMU_JOB_WAIT_TIME;

    virDomainObjRef(obj);

    while (priv->jobActive) {
        if (virCondWaitUntil(&priv->jobCond, &obj->lock, then) < 0) {
            /* Safe to ignore value since ref count was incremented above */
            ignore_value(virDomainObjUnref(obj));
            if (errno == ETIMEDOUT)
                qemuReportError(VIR_ERR_OPERATION_TIMEOUT,
                                "%s", _("cannot acquire state change lock"));
            else
                virReportSystemError(errno,
                                     "%s", _("cannot acquire job mutex"));
            return -1;
        }
    }
    priv->jobActive = QEMU_JOB_UNSPECIFIED;
    priv->jobSignals = 0;
    memset(&priv->jobSignalsData, 0, sizeof(priv->jobSignalsData));
    priv->jobStart = timeval_to_ms(now);
    memset(&priv->jobInfo, 0, sizeof(priv->jobInfo));

    return 0;
}

/*
 * obj must be locked before calling, qemud_driver must be locked
 *
 * This must be called by anything that will change the VM state
 * in any way, or anything that will use the QEMU monitor.
 */
int qemuDomainObjBeginJobWithDriver(struct qemud_driver *driver,
                                    virDomainObjPtr obj)
{
    qemuDomainObjPrivatePtr priv = obj->privateData;
    struct timeval now;
    unsigned long long then;

    if (gettimeofday(&now, NULL) < 0) {
        virReportSystemError(errno, "%s",
                             _("cannot get time of day"));
        return -1;
    }
    then = timeval_to_ms(now) + QEMU_JOB_WAIT_TIME;

    virDomainObjRef(obj);
    qemuDriverUnlock(driver);

    while (priv->jobActive) {
        if (virCondWaitUntil(&priv->jobCond, &obj->lock, then) < 0) {
            if (errno == ETIMEDOUT)
                qemuReportError(VIR_ERR_OPERATION_TIMEOUT,
                                "%s", _("cannot acquire state change lock"));
            else
                virReportSystemError(errno,
                                     "%s", _("cannot acquire job mutex"));
            virDomainObjUnlock(obj);
            qemuDriverLock(driver);
            virDomainObjLock(obj);
            /* Safe to ignore value since ref count was incremented above */
            ignore_value(virDomainObjUnref(obj));
            return -1;
        }
    }
    priv->jobActive = QEMU_JOB_UNSPECIFIED;
    priv->jobSignals = 0;
    memset(&priv->jobSignalsData, 0, sizeof(priv->jobSignalsData));
    priv->jobStart = timeval_to_ms(now);
    memset(&priv->jobInfo, 0, sizeof(priv->jobInfo));

    virDomainObjUnlock(obj);
    qemuDriverLock(driver);
    virDomainObjLock(obj);

    return 0;
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
int qemuDomainObjEndJob(virDomainObjPtr obj)
{
    qemuDomainObjPrivatePtr priv = obj->privateData;

    priv->jobActive = QEMU_JOB_NONE;
    priv->jobSignals = 0;
    memset(&priv->jobSignalsData, 0, sizeof(priv->jobSignalsData));
    priv->jobStart = 0;
    memset(&priv->jobInfo, 0, sizeof(priv->jobInfo));
    virCondSignal(&priv->jobCond);

    return virDomainObjUnref(obj);
}


/*
 * obj must be locked before calling, qemud_driver must be unlocked
 *
 * To be called immediately before any QEMU monitor API call
 * Must have already called qemuDomainObjBeginJob(), and checked
 * that the VM is still active.
 *
 * To be followed with qemuDomainObjExitMonitor() once complete
 */
void qemuDomainObjEnterMonitor(virDomainObjPtr obj)
{
    qemuDomainObjPrivatePtr priv = obj->privateData;

    qemuMonitorLock(priv->mon);
    qemuMonitorRef(priv->mon);
    virDomainObjUnlock(obj);
}


/* obj must NOT be locked before calling, qemud_driver must be unlocked
 *
 * Should be paired with an earlier qemuDomainObjEnterMonitor() call
 */
void qemuDomainObjExitMonitor(virDomainObjPtr obj)
{
    qemuDomainObjPrivatePtr priv = obj->privateData;
    int refs;

    refs = qemuMonitorUnref(priv->mon);

    if (refs > 0)
        qemuMonitorUnlock(priv->mon);

    virDomainObjLock(obj);

    if (refs == 0) {
        priv->mon = NULL;
    }
}


/*
 * obj must be locked before calling, qemud_driver must be locked
 *
 * To be called immediately before any QEMU monitor API call
 * Must have already called qemuDomainObjBeginJob().
 *
 * To be followed with qemuDomainObjExitMonitorWithDriver() once complete
 */
void qemuDomainObjEnterMonitorWithDriver(struct qemud_driver *driver,
                                         virDomainObjPtr obj)
{
    qemuDomainObjPrivatePtr priv = obj->privateData;

    qemuMonitorLock(priv->mon);
    qemuMonitorRef(priv->mon);
    virDomainObjUnlock(obj);
    qemuDriverUnlock(driver);
}


/* obj must NOT be locked before calling, qemud_driver must be unlocked,
 * and will be locked after returning
 *
 * Should be paired with an earlier qemuDomainObjEnterMonitorWithDriver() call
 */
void qemuDomainObjExitMonitorWithDriver(struct qemud_driver *driver,
                                        virDomainObjPtr obj)
{
    qemuDomainObjPrivatePtr priv = obj->privateData;
    int refs;

    refs = qemuMonitorUnref(priv->mon);

    if (refs > 0)
        qemuMonitorUnlock(priv->mon);

    qemuDriverLock(driver);
    virDomainObjLock(obj);

    if (refs == 0) {
        priv->mon = NULL;
    }
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


char *qemuDomainFormatXML(struct qemud_driver *driver,
                          virDomainObjPtr vm,
                          int flags)
{
    char *ret = NULL;
    virCPUDefPtr cpu = NULL;
    virDomainDefPtr def;
    virCPUDefPtr def_cpu;

    if ((flags & VIR_DOMAIN_XML_INACTIVE) && vm->newDef)
        def = vm->newDef;
    else
        def = vm->def;
    def_cpu = def->cpu;

    /* Update guest CPU requirements according to host CPU */
    if ((flags & VIR_DOMAIN_XML_UPDATE_CPU) && def_cpu && def_cpu->model) {
        if (!driver->caps || !driver->caps->host.cpu) {
            qemuReportError(VIR_ERR_OPERATION_FAILED,
                            "%s", _("cannot get host CPU capabilities"));
            goto cleanup;
        }

        if (!(cpu = virCPUDefCopy(def_cpu))
            || cpuUpdate(cpu, driver->caps->host.cpu))
            goto cleanup;
        def->cpu = cpu;
    }

    ret = virDomainDefFormat(def, flags);

cleanup:
    def->cpu = def_cpu;
    virCPUDefFree(cpu);
    return ret;
}
