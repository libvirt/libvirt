/*
 * qemu_process.c: QEMU process management
 *
 * Copyright (C) 2006-2016 Red Hat, Inc.
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
 */

#include <config.h>

#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>
#if defined(__linux__)
# include <linux/capability.h>
#elif defined(__FreeBSD__)
# include <sys/param.h>
# include <sys/cpuset.h>
#endif

#include <sys/utsname.h>

#if WITH_CAPNG
# include <cap-ng.h>
#endif

#include "qemu_process.h"
#define LIBVIRT_QEMU_PROCESSPRIV_H_ALLOW
#include "qemu_processpriv.h"
#include "qemu_alias.h"
#include "qemu_block.h"
#include "qemu_domain.h"
#include "qemu_domain_address.h"
#include "qemu_cgroup.h"
#include "qemu_capabilities.h"
#include "qemu_monitor.h"
#include "qemu_command.h"
#include "qemu_hostdev.h"
#include "qemu_hotplug.h"
#include "qemu_migration.h"
#include "qemu_migration_params.h"
#include "qemu_interface.h"
#include "qemu_security.h"
#include "qemu_extdevice.h"
#include "qemu_firmware.h"

#include "cpu/cpu.h"
#include "cpu/cpu_x86.h"
#include "datatypes.h"
#include "virlog.h"
#include "virerror.h"
#include "viralloc.h"
#include "virhook.h"
#include "virfile.h"
#include "virpidfile.h"
#include "virhostcpu.h"
#include "domain_audit.h"
#include "domain_nwfilter.h"
#include "locking/domain_lock.h"
#include "viruuid.h"
#include "virprocess.h"
#include "virtime.h"
#include "virnetdevtap.h"
#include "virnetdevopenvswitch.h"
#include "virnetdevmidonet.h"
#include "virbitmap.h"
#include "viratomic.h"
#include "virnuma.h"
#include "virstring.h"
#include "virhostdev.h"
#include "secret_util.h"
#include "configmake.h"
#include "nwfilter_conf.h"
#include "netdev_bandwidth_conf.h"
#include "virresctrl.h"
#include "virvsock.h"
#include "viridentity.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_process");

/**
 * qemuProcessRemoveDomainStatus
 *
 * remove all state files of a domain from statedir
 *
 * Returns 0 on success
 */
static int
qemuProcessRemoveDomainStatus(virQEMUDriverPtr driver,
                              virDomainObjPtr vm)
{
    char ebuf[1024];
    char *file = NULL;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    int ret = -1;

    if (virAsprintf(&file, "%s/%s.xml", cfg->stateDir, vm->def->name) < 0)
        goto cleanup;

    if (unlink(file) < 0 && errno != ENOENT && errno != ENOTDIR)
        VIR_WARN("Failed to remove domain XML for %s: %s",
                 vm->def->name, virStrerror(errno, ebuf, sizeof(ebuf)));
    VIR_FREE(file);

    if (priv->pidfile &&
        unlink(priv->pidfile) < 0 &&
        errno != ENOENT)
        VIR_WARN("Failed to remove PID file for %s: %s",
                 vm->def->name, virStrerror(errno, ebuf, sizeof(ebuf)));

    ret = 0;
 cleanup:
    virObjectUnref(cfg);
    return ret;
}


/*
 * This is a callback registered with a qemuAgentPtr instance,
 * and to be invoked when the agent console hits an end of file
 * condition, or error, thus indicating VM shutdown should be
 * performed
 */
static void
qemuProcessHandleAgentEOF(qemuAgentPtr agent,
                          virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv;

    VIR_DEBUG("Received EOF from agent on %p '%s'", vm, vm->def->name);

    virObjectLock(vm);

    priv = vm->privateData;

    if (!priv->agent) {
        VIR_DEBUG("Agent freed already");
        goto unlock;
    }

    if (priv->beingDestroyed) {
        VIR_DEBUG("Domain is being destroyed, agent EOF is expected");
        goto unlock;
    }

    qemuAgentClose(agent);
    priv->agent = NULL;
    priv->agentError = false;

    virObjectUnlock(vm);
    return;

 unlock:
    virObjectUnlock(vm);
    return;
}


/*
 * This is invoked when there is some kind of error
 * parsing data to/from the agent. The VM can continue
 * to run, but no further agent commands will be
 * allowed
 */
static void
qemuProcessHandleAgentError(qemuAgentPtr agent ATTRIBUTE_UNUSED,
                            virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv;

    VIR_DEBUG("Received error from agent on %p '%s'", vm, vm->def->name);

    virObjectLock(vm);

    priv = vm->privateData;

    priv->agentError = true;

    virObjectUnlock(vm);
}

static void qemuProcessHandleAgentDestroy(qemuAgentPtr agent,
                                          virDomainObjPtr vm)
{
    VIR_DEBUG("Received destroy agent=%p vm=%p", agent, vm);

    virObjectUnref(vm);
}


static qemuAgentCallbacks agentCallbacks = {
    .destroy = qemuProcessHandleAgentDestroy,
    .eofNotify = qemuProcessHandleAgentEOF,
    .errorNotify = qemuProcessHandleAgentError,
};


int
qemuConnectAgent(virQEMUDriverPtr driver, virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    qemuAgentPtr agent = NULL;
    virDomainChrDefPtr config = qemuFindAgentConfig(vm->def);

    if (!config)
        return 0;

    if (priv->agent)
        return 0;

    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_VSERPORT_CHANGE) &&
        config->state != VIR_DOMAIN_CHR_DEVICE_STATE_CONNECTED) {
        VIR_DEBUG("Deferring connecting to guest agent");
        return 0;
    }

    if (qemuSecuritySetDaemonSocketLabel(driver->securityManager, vm->def) < 0) {
        VIR_ERROR(_("Failed to set security context for agent for %s"),
                  vm->def->name);
        goto cleanup;
    }

    /* Hold an extra reference because we can't allow 'vm' to be
     * deleted while the agent is active */
    virObjectRef(vm);

    virObjectUnlock(vm);

    agent = qemuAgentOpen(vm,
                          config->source,
                          &agentCallbacks);

    virObjectLock(vm);

    if (agent == NULL)
        virObjectUnref(vm);

    if (!virDomainObjIsActive(vm)) {
        qemuAgentClose(agent);
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("guest crashed while connecting to the guest agent"));
        return -1;
    }

    if (qemuSecurityClearSocketLabel(driver->securityManager, vm->def) < 0) {
        VIR_ERROR(_("Failed to clear security context for agent for %s"),
                  vm->def->name);
        qemuAgentClose(agent);
        goto cleanup;
    }

    priv->agent = agent;
    if (!priv->agent)
        VIR_INFO("Failed to connect agent for %s", vm->def->name);

 cleanup:
    if (!priv->agent) {
        VIR_WARN("Cannot connect to QEMU guest agent for %s", vm->def->name);
        priv->agentError = true;
        virResetLastError();
    }

    return 0;
}


/*
 * This is a callback registered with a qemuMonitorPtr instance,
 * and to be invoked when the monitor console hits an end of file
 * condition, or error, thus indicating VM shutdown should be
 * performed
 */
static void
qemuProcessHandleMonitorEOF(qemuMonitorPtr mon,
                            virDomainObjPtr vm,
                            void *opaque)
{
    virQEMUDriverPtr driver = opaque;
    qemuDomainObjPrivatePtr priv;
    struct qemuProcessEvent *processEvent;

    virObjectLock(vm);

    VIR_DEBUG("Received EOF on %p '%s'", vm, vm->def->name);

    priv = vm->privateData;
    if (priv->beingDestroyed) {
        VIR_DEBUG("Domain is being destroyed, EOF is expected");
        goto cleanup;
    }

    if (VIR_ALLOC(processEvent) < 0)
        goto cleanup;

    processEvent->eventType = QEMU_PROCESS_EVENT_MONITOR_EOF;
    processEvent->vm = virObjectRef(vm);

    if (virThreadPoolSendJob(driver->workerPool, 0, processEvent) < 0) {
        ignore_value(virObjectUnref(vm));
        qemuProcessEventFree(processEvent);
        goto cleanup;
    }

    /* We don't want this EOF handler to be called over and over while the
     * thread is waiting for a job.
     */
    qemuMonitorUnregister(mon);

    /* We don't want any cleanup from EOF handler (or any other
     * thread) to enter qemu namespace. */
    qemuDomainDestroyNamespace(driver, vm);

 cleanup:
    virObjectUnlock(vm);
}


/*
 * This is invoked when there is some kind of error
 * parsing data to/from the monitor. The VM can continue
 * to run, but no further monitor commands will be
 * allowed
 */
static void
qemuProcessHandleMonitorError(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                              virDomainObjPtr vm,
                              void *opaque)
{
    virQEMUDriverPtr driver = opaque;
    virObjectEventPtr event = NULL;

    VIR_DEBUG("Received error on %p '%s'", vm, vm->def->name);

    virObjectLock(vm);

    ((qemuDomainObjPrivatePtr) vm->privateData)->monError = true;
    event = virDomainEventControlErrorNewFromObj(vm);
    virObjectEventStateQueue(driver->domainEventState, event);

    virObjectUnlock(vm);
}


/**
 * qemuProcessFindDomainDiskByAliasOrQOM:
 * @vm: domain object to search for the disk
 * @alias: -drive or -device alias of the disk
 * @qomid: QOM tree device name
 *
 * Looks up a disk in the domain definition of @vm which either matches the
 * -drive or -device alias used for the backend and frontend respectively or the
 * QOM name. If @alias is empty it's treated as NULL as it's a mandatory field
 * in some cases.
 *
 * Returns a disk from @vm or NULL if it could not be found.
 */
virDomainDiskDefPtr
qemuProcessFindDomainDiskByAliasOrQOM(virDomainObjPtr vm,
                                      const char *alias,
                                      const char *qomid)
{
    size_t i;

    if (alias && *alias == '\0')
        alias = NULL;

    if (alias)
        alias = qemuAliasDiskDriveSkipPrefix(alias);

    for (i = 0; i < vm->def->ndisks; i++) {
        virDomainDiskDefPtr disk = vm->def->disks[i];
        qemuDomainDiskPrivatePtr diskPriv = QEMU_DOMAIN_DISK_PRIVATE(disk);

        if ((disk->info.alias && STREQ_NULLABLE(disk->info.alias, alias)) ||
            (diskPriv->qomName && STREQ_NULLABLE(diskPriv->qomName, qomid)))
            return disk;
    }

    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("no disk found with alias '%s' or id '%s'"),
                   NULLSTR(alias), NULLSTR(qomid));
    return NULL;
}


static int
qemuProcessHandleReset(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                       virDomainObjPtr vm,
                       void *opaque)
{
    virQEMUDriverPtr driver = opaque;
    virObjectEventPtr event;
    qemuDomainObjPrivatePtr priv;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    int ret = -1;

    virObjectLock(vm);

    event = virDomainEventRebootNewFromObj(vm);
    priv = vm->privateData;
    if (priv->agent)
        qemuAgentNotifyEvent(priv->agent, QEMU_AGENT_EVENT_RESET);

    if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm, driver->caps) < 0)
        VIR_WARN("Failed to save status on vm %s", vm->def->name);

    if (vm->def->onReboot == VIR_DOMAIN_LIFECYCLE_ACTION_DESTROY ||
        vm->def->onReboot == VIR_DOMAIN_LIFECYCLE_ACTION_PRESERVE) {

        if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
            goto cleanup;

        if (!virDomainObjIsActive(vm)) {
            VIR_DEBUG("Ignoring RESET event from inactive domain %s",
                      vm->def->name);
            goto endjob;
        }

        qemuProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_DESTROYED,
                        QEMU_ASYNC_JOB_NONE, 0);
        virDomainAuditStop(vm, "destroyed");
        qemuDomainRemoveInactive(driver, vm);
     endjob:
        qemuDomainObjEndJob(driver, vm);
    }

    ret = 0;
 cleanup:
    virObjectUnlock(vm);
    virObjectEventStateQueue(driver->domainEventState, event);
    virObjectUnref(cfg);
    return ret;
}


/*
 * Since we have the '-no-shutdown' flag set, the
 * QEMU process will currently have guest OS shutdown
 * and the CPUS stopped. To fake the reboot, we thus
 * want todo a reset of the virtual hardware, followed
 * by restart of the CPUs. This should result in the
 * guest OS booting up again
 */
static void
qemuProcessFakeReboot(void *opaque)
{
    virDomainObjPtr vm = opaque;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virQEMUDriverPtr driver = priv->driver;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    virDomainRunningReason reason = VIR_DOMAIN_RUNNING_BOOTED;
    int ret = -1, rc;

    VIR_DEBUG("vm=%p", vm);
    virObjectLock(vm);
    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("guest unexpectedly quit"));
        goto endjob;
    }

    qemuDomainObjEnterMonitor(driver, vm);
    rc = qemuMonitorSystemReset(priv->mon);

    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        goto endjob;

    if (rc < 0)
        goto endjob;

    if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_CRASHED)
        reason = VIR_DOMAIN_RUNNING_CRASHED;

    if (qemuProcessStartCPUs(driver, vm,
                             reason,
                             QEMU_ASYNC_JOB_NONE) < 0) {
        if (virGetLastErrorCode() == VIR_ERR_OK)
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("resume operation failed"));
        goto endjob;
    }

    if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm, driver->caps) < 0) {
        VIR_WARN("Unable to save status on vm %s after state change",
                 vm->def->name);
    }

    ret = 0;

 endjob:
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    if (ret == -1)
        ignore_value(qemuProcessKill(vm, VIR_QEMU_PROCESS_KILL_FORCE));
    virDomainObjEndAPI(&vm);
    virObjectUnref(cfg);
}


void
qemuProcessShutdownOrReboot(virQEMUDriverPtr driver,
                            virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (priv->fakeReboot) {
        qemuDomainSetFakeReboot(driver, vm, false);
        virObjectRef(vm);
        virThread th;
        if (virThreadCreate(&th,
                            false,
                            qemuProcessFakeReboot,
                            vm) < 0) {
            VIR_ERROR(_("Failed to create reboot thread, killing domain"));
            ignore_value(qemuProcessKill(vm, VIR_QEMU_PROCESS_KILL_NOWAIT));
            virObjectUnref(vm);
        }
    } else {
        ignore_value(qemuProcessKill(vm, VIR_QEMU_PROCESS_KILL_NOWAIT));
    }
}


static int
qemuProcessHandleEvent(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                       virDomainObjPtr vm,
                       const char *eventName,
                       long long seconds,
                       unsigned int micros,
                       const char *details,
                       void *opaque)
{
    virQEMUDriverPtr driver = opaque;
    virObjectEventPtr event = NULL;

    VIR_DEBUG("vm=%p", vm);

    virObjectLock(vm);
    event = virDomainQemuMonitorEventNew(vm->def->id, vm->def->name,
                                         vm->def->uuid, eventName,
                                         seconds, micros, details);

    virObjectUnlock(vm);
    virObjectEventStateQueue(driver->domainEventState, event);

    return 0;
}


static int
qemuProcessHandleShutdown(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                          virDomainObjPtr vm,
                          virTristateBool guest_initiated,
                          void *opaque)
{
    virQEMUDriverPtr driver = opaque;
    qemuDomainObjPrivatePtr priv;
    virObjectEventPtr event = NULL;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    int detail = 0;

    VIR_DEBUG("vm=%p", vm);

    virObjectLock(vm);

    priv = vm->privateData;
    if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_SHUTDOWN) {
        VIR_DEBUG("Ignoring repeated SHUTDOWN event from domain %s",
                  vm->def->name);
        goto unlock;
    } else if (!virDomainObjIsActive(vm)) {
        VIR_DEBUG("Ignoring SHUTDOWN event from inactive domain %s",
                  vm->def->name);
        goto unlock;
    }

    VIR_DEBUG("Transitioned guest %s to shutdown state",
              vm->def->name);
    virDomainObjSetState(vm,
                         VIR_DOMAIN_SHUTDOWN,
                         VIR_DOMAIN_SHUTDOWN_UNKNOWN);

    switch (guest_initiated) {
    case VIR_TRISTATE_BOOL_YES:
        detail = VIR_DOMAIN_EVENT_SHUTDOWN_GUEST;
        break;

    case VIR_TRISTATE_BOOL_NO:
        detail = VIR_DOMAIN_EVENT_SHUTDOWN_HOST;
        break;

    case VIR_TRISTATE_BOOL_ABSENT:
    case VIR_TRISTATE_BOOL_LAST:
    default:
        detail = VIR_DOMAIN_EVENT_SHUTDOWN_FINISHED;
        break;
    }

    event = virDomainEventLifecycleNewFromObj(vm,
                                              VIR_DOMAIN_EVENT_SHUTDOWN,
                                              detail);

    if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm, driver->caps) < 0) {
        VIR_WARN("Unable to save status on vm %s after state change",
                 vm->def->name);
    }

    if (priv->agent)
        qemuAgentNotifyEvent(priv->agent, QEMU_AGENT_EVENT_SHUTDOWN);

    qemuProcessShutdownOrReboot(driver, vm);

 unlock:
    virObjectUnlock(vm);
    virObjectEventStateQueue(driver->domainEventState, event);
    virObjectUnref(cfg);

    return 0;
}


static int
qemuProcessHandleStop(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                      virDomainObjPtr vm,
                      void *opaque)
{
    virQEMUDriverPtr driver = opaque;
    virObjectEventPtr event = NULL;
    virDomainPausedReason reason;
    virDomainEventSuspendedDetailType detail;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    qemuDomainObjPrivatePtr priv = vm->privateData;

    virObjectLock(vm);

    reason = priv->pausedReason;
    priv->pausedReason = VIR_DOMAIN_PAUSED_UNKNOWN;

    if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_RUNNING) {
        if (priv->job.asyncJob == QEMU_ASYNC_JOB_MIGRATION_OUT) {
            if (priv->job.current->status == QEMU_DOMAIN_JOB_STATUS_POSTCOPY)
                reason = VIR_DOMAIN_PAUSED_POSTCOPY;
            else
                reason = VIR_DOMAIN_PAUSED_MIGRATION;
        }

        detail = qemuDomainPausedReasonToSuspendedEvent(reason);
        VIR_DEBUG("Transitioned guest %s to paused state, "
                  "reason %s, event detail %d",
                  vm->def->name, virDomainPausedReasonTypeToString(reason),
                  detail);

        if (priv->job.current)
            ignore_value(virTimeMillisNow(&priv->job.current->stopped));

        if (priv->signalStop)
            virDomainObjBroadcast(vm);

        virDomainObjSetState(vm, VIR_DOMAIN_PAUSED, reason);
        event = virDomainEventLifecycleNewFromObj(vm,
                                                  VIR_DOMAIN_EVENT_SUSPENDED,
                                                  detail);

        VIR_FREE(priv->lockState);
        if (virDomainLockProcessPause(driver->lockManager, vm, &priv->lockState) < 0)
            VIR_WARN("Unable to release lease on %s", vm->def->name);
        VIR_DEBUG("Preserving lock state '%s'", NULLSTR(priv->lockState));

        if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm, driver->caps) < 0) {
            VIR_WARN("Unable to save status on vm %s after state change",
                     vm->def->name);
        }
    }

    virObjectUnlock(vm);
    virObjectEventStateQueue(driver->domainEventState, event);
    virObjectUnref(cfg);

    return 0;
}


static int
qemuProcessHandleResume(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                        virDomainObjPtr vm,
                        void *opaque)
{
    virQEMUDriverPtr driver = opaque;
    virObjectEventPtr event = NULL;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    qemuDomainObjPrivatePtr priv;
    virDomainRunningReason reason = VIR_DOMAIN_RUNNING_UNPAUSED;
    virDomainEventResumedDetailType eventDetail;

    virObjectLock(vm);

    priv = vm->privateData;
    if (priv->runningReason != VIR_DOMAIN_RUNNING_UNKNOWN) {
        reason = priv->runningReason;
        priv->runningReason = VIR_DOMAIN_RUNNING_UNKNOWN;
    }

    if (virDomainObjGetState(vm, NULL) != VIR_DOMAIN_RUNNING) {
        eventDetail = qemuDomainRunningReasonToResumeEvent(reason);
        VIR_DEBUG("Transitioned guest %s into running state, reason '%s', "
                  "event detail %d",
                  vm->def->name, virDomainRunningReasonTypeToString(reason),
                  eventDetail);

        virDomainObjSetState(vm, VIR_DOMAIN_RUNNING, reason);
        event = virDomainEventLifecycleNewFromObj(vm,
                                                  VIR_DOMAIN_EVENT_RESUMED,
                                                  eventDetail);

        if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm, driver->caps) < 0) {
            VIR_WARN("Unable to save status on vm %s after state change",
                     vm->def->name);
        }
    }

    virObjectUnlock(vm);
    virObjectEventStateQueue(driver->domainEventState, event);
    virObjectUnref(cfg);
    return 0;
}

static int
qemuProcessHandleRTCChange(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                           virDomainObjPtr vm,
                           long long offset,
                           void *opaque)
{
    virQEMUDriverPtr driver = opaque;
    virObjectEventPtr event = NULL;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);

    virObjectLock(vm);

    if (vm->def->clock.offset == VIR_DOMAIN_CLOCK_OFFSET_VARIABLE) {
        /* when a basedate is manually given on the qemu commandline
         * rather than simply "-rtc base=utc", the offset sent by qemu
         * in this event is *not* the new offset from UTC, but is
         * instead the new offset from the *original basedate* +
         * uptime. For example, if the original offset was 3600 and
         * the guest clock has been advanced by 10 seconds, qemu will
         * send "10" in the event - this means that the new offset
         * from UTC is 3610, *not* 10. If the guest clock is advanced
         * by another 10 seconds, qemu will now send "20" - i.e. each
         * event is the sum of the most recent change and all previous
         * changes since the domain was started. Fortunately, we have
         * saved the initial offset in "adjustment0", so to arrive at
         * the proper new "adjustment", we just add the most recent
         * offset to adjustment0.
         */
        offset += vm->def->clock.data.variable.adjustment0;
        vm->def->clock.data.variable.adjustment = offset;

        if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm, driver->caps) < 0)
           VIR_WARN("unable to save domain status with RTC change");
    }

    event = virDomainEventRTCChangeNewFromObj(vm, offset);

    virObjectUnlock(vm);

    virObjectEventStateQueue(driver->domainEventState, event);
    virObjectUnref(cfg);
    return 0;
}


static int
qemuProcessHandleWatchdog(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                          virDomainObjPtr vm,
                          int action,
                          void *opaque)
{
    virQEMUDriverPtr driver = opaque;
    virObjectEventPtr watchdogEvent = NULL;
    virObjectEventPtr lifecycleEvent = NULL;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);

    virObjectLock(vm);
    watchdogEvent = virDomainEventWatchdogNewFromObj(vm, action);

    if (action == VIR_DOMAIN_EVENT_WATCHDOG_PAUSE &&
        virDomainObjGetState(vm, NULL) == VIR_DOMAIN_RUNNING) {
        qemuDomainObjPrivatePtr priv = vm->privateData;
        VIR_DEBUG("Transitioned guest %s to paused state due to watchdog", vm->def->name);

        virDomainObjSetState(vm, VIR_DOMAIN_PAUSED, VIR_DOMAIN_PAUSED_WATCHDOG);
        lifecycleEvent = virDomainEventLifecycleNewFromObj(vm,
                                                  VIR_DOMAIN_EVENT_SUSPENDED,
                                                  VIR_DOMAIN_EVENT_SUSPENDED_WATCHDOG);

        VIR_FREE(priv->lockState);
        if (virDomainLockProcessPause(driver->lockManager, vm, &priv->lockState) < 0)
            VIR_WARN("Unable to release lease on %s", vm->def->name);
        VIR_DEBUG("Preserving lock state '%s'", NULLSTR(priv->lockState));

        if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm, driver->caps) < 0) {
            VIR_WARN("Unable to save status on vm %s after watchdog event",
                     vm->def->name);
        }
    }

    if (vm->def->watchdog->action == VIR_DOMAIN_WATCHDOG_ACTION_DUMP) {
        struct qemuProcessEvent *processEvent;
        if (VIR_ALLOC(processEvent) == 0) {
            processEvent->eventType = QEMU_PROCESS_EVENT_WATCHDOG;
            processEvent->action = VIR_DOMAIN_WATCHDOG_ACTION_DUMP;
            /* Hold an extra reference because we can't allow 'vm' to be
             * deleted before handling watchdog event is finished.
             */
            processEvent->vm = virObjectRef(vm);
            if (virThreadPoolSendJob(driver->workerPool, 0, processEvent) < 0) {
                if (!virObjectUnref(vm))
                    vm = NULL;
                qemuProcessEventFree(processEvent);
            }
        }
    }

    if (vm)
        virObjectUnlock(vm);
    virObjectEventStateQueue(driver->domainEventState, watchdogEvent);
    virObjectEventStateQueue(driver->domainEventState, lifecycleEvent);

    virObjectUnref(cfg);
    return 0;
}


static int
qemuProcessHandleIOError(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                         virDomainObjPtr vm,
                         const char *diskAlias,
                         const char *nodename,
                         int action,
                         const char *reason,
                         void *opaque)
{
    virQEMUDriverPtr driver = opaque;
    virObjectEventPtr ioErrorEvent = NULL;
    virObjectEventPtr ioErrorEvent2 = NULL;
    virObjectEventPtr lifecycleEvent = NULL;
    const char *srcPath;
    const char *devAlias;
    virDomainDiskDefPtr disk;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);

    virObjectLock(vm);

    if (*diskAlias == '\0')
        diskAlias = NULL;

    if (diskAlias)
        disk = qemuProcessFindDomainDiskByAliasOrQOM(vm, diskAlias, NULL);
    else if (nodename)
        disk = qemuDomainDiskLookupByNodename(vm->def, nodename, NULL, NULL);
    else
        disk = NULL;

    if (disk) {
        srcPath = virDomainDiskGetSource(disk);
        devAlias = disk->info.alias;
    } else {
        srcPath = "";
        devAlias = "";
    }

    ioErrorEvent = virDomainEventIOErrorNewFromObj(vm, srcPath, devAlias, action);
    ioErrorEvent2 = virDomainEventIOErrorReasonNewFromObj(vm, srcPath, devAlias, action, reason);

    if (action == VIR_DOMAIN_EVENT_IO_ERROR_PAUSE &&
        virDomainObjGetState(vm, NULL) == VIR_DOMAIN_RUNNING) {
        qemuDomainObjPrivatePtr priv = vm->privateData;
        VIR_DEBUG("Transitioned guest %s to paused state due to IO error", vm->def->name);

        if (priv->signalIOError)
            virDomainObjBroadcast(vm);

        virDomainObjSetState(vm, VIR_DOMAIN_PAUSED, VIR_DOMAIN_PAUSED_IOERROR);
        lifecycleEvent = virDomainEventLifecycleNewFromObj(vm,
                                                  VIR_DOMAIN_EVENT_SUSPENDED,
                                                  VIR_DOMAIN_EVENT_SUSPENDED_IOERROR);

        VIR_FREE(priv->lockState);
        if (virDomainLockProcessPause(driver->lockManager, vm, &priv->lockState) < 0)
            VIR_WARN("Unable to release lease on %s", vm->def->name);
        VIR_DEBUG("Preserving lock state '%s'", NULLSTR(priv->lockState));

        if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm, driver->caps) < 0)
            VIR_WARN("Unable to save status on vm %s after IO error", vm->def->name);
    }
    virObjectUnlock(vm);

    virObjectEventStateQueue(driver->domainEventState, ioErrorEvent);
    virObjectEventStateQueue(driver->domainEventState, ioErrorEvent2);
    virObjectEventStateQueue(driver->domainEventState, lifecycleEvent);
    virObjectUnref(cfg);
    return 0;
}

static int
qemuProcessHandleBlockJob(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                          virDomainObjPtr vm,
                          const char *diskAlias,
                          int type,
                          int status,
                          const char *error,
                          void *opaque)
{
    virQEMUDriverPtr driver = opaque;
    struct qemuProcessEvent *processEvent = NULL;
    virDomainDiskDefPtr disk;
    qemuBlockJobDataPtr job = NULL;
    char *data = NULL;

    virObjectLock(vm);

    VIR_DEBUG("Block job for device %s (domain: %p,%s) type %d status %d",
              diskAlias, vm, vm->def->name, type, status);

    if (!(disk = qemuProcessFindDomainDiskByAliasOrQOM(vm, diskAlias, NULL)))
        goto cleanup;

    job = qemuBlockJobDiskGetJob(disk);

    if (job && job->synchronous) {
        /* We have a SYNC API waiting for this event, dispatch it back */
        job->newstate = status;
        VIR_FREE(job->errmsg);
        ignore_value(VIR_STRDUP_QUIET(job->errmsg, error));
        virDomainObjBroadcast(vm);
    } else {
        /* there is no waiting SYNC API, dispatch the update to a thread */
        if (VIR_ALLOC(processEvent) < 0)
            goto cleanup;

        processEvent->eventType = QEMU_PROCESS_EVENT_BLOCK_JOB;
        if (VIR_STRDUP(data, diskAlias) < 0)
            goto cleanup;
        processEvent->data = data;
        processEvent->vm = virObjectRef(vm);
        processEvent->action = type;
        processEvent->status = status;

        if (virThreadPoolSendJob(driver->workerPool, 0, processEvent) < 0) {
            ignore_value(virObjectUnref(vm));
            goto cleanup;
        }

        processEvent = NULL;
    }

 cleanup:
    qemuBlockJobStartupFinalize(job);
    qemuProcessEventFree(processEvent);
    virObjectUnlock(vm);
    return 0;
}


static int
qemuProcessHandleGraphics(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                          virDomainObjPtr vm,
                          int phase,
                          int localFamily,
                          const char *localNode,
                          const char *localService,
                          int remoteFamily,
                          const char *remoteNode,
                          const char *remoteService,
                          const char *authScheme,
                          const char *x509dname,
                          const char *saslUsername,
                          void *opaque)
{
    virQEMUDriverPtr driver = opaque;
    virObjectEventPtr event;
    virDomainEventGraphicsAddressPtr localAddr = NULL;
    virDomainEventGraphicsAddressPtr remoteAddr = NULL;
    virDomainEventGraphicsSubjectPtr subject = NULL;
    size_t i;

    if (VIR_ALLOC(localAddr) < 0)
        goto error;
    localAddr->family = localFamily;
    if (VIR_STRDUP(localAddr->service, localService) < 0 ||
        VIR_STRDUP(localAddr->node, localNode) < 0)
        goto error;

    if (VIR_ALLOC(remoteAddr) < 0)
        goto error;
    remoteAddr->family = remoteFamily;
    if (VIR_STRDUP(remoteAddr->service, remoteService) < 0 ||
        VIR_STRDUP(remoteAddr->node, remoteNode) < 0)
        goto error;

    if (VIR_ALLOC(subject) < 0)
        goto error;
    if (x509dname) {
        if (VIR_REALLOC_N(subject->identities, subject->nidentity+1) < 0)
            goto error;
        subject->nidentity++;
        if (VIR_STRDUP(subject->identities[subject->nidentity-1].type, "x509dname") < 0 ||
            VIR_STRDUP(subject->identities[subject->nidentity-1].name, x509dname) < 0)
            goto error;
    }
    if (saslUsername) {
        if (VIR_REALLOC_N(subject->identities, subject->nidentity+1) < 0)
            goto error;
        subject->nidentity++;
        if (VIR_STRDUP(subject->identities[subject->nidentity-1].type, "saslUsername") < 0 ||
            VIR_STRDUP(subject->identities[subject->nidentity-1].name, saslUsername) < 0)
            goto error;
    }

    virObjectLock(vm);
    event = virDomainEventGraphicsNewFromObj(vm, phase, localAddr, remoteAddr, authScheme, subject);
    virObjectUnlock(vm);

    virObjectEventStateQueue(driver->domainEventState, event);

    return 0;

 error:
    if (localAddr) {
        VIR_FREE(localAddr->service);
        VIR_FREE(localAddr->node);
        VIR_FREE(localAddr);
    }
    if (remoteAddr) {
        VIR_FREE(remoteAddr->service);
        VIR_FREE(remoteAddr->node);
        VIR_FREE(remoteAddr);
    }
    if (subject) {
        for (i = 0; i < subject->nidentity; i++) {
            VIR_FREE(subject->identities[i].type);
            VIR_FREE(subject->identities[i].name);
        }
        VIR_FREE(subject->identities);
        VIR_FREE(subject);
    }

    return -1;
}

static int
qemuProcessHandleTrayChange(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                            virDomainObjPtr vm,
                            const char *devAlias,
                            const char *devid,
                            int reason,
                            void *opaque)
{
    virQEMUDriverPtr driver = opaque;
    virObjectEventPtr event = NULL;
    virDomainDiskDefPtr disk;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);

    virObjectLock(vm);
    disk = qemuProcessFindDomainDiskByAliasOrQOM(vm, devAlias, devid);

    if (disk) {
        event = virDomainEventTrayChangeNewFromObj(vm, disk->info.alias, reason);
        /* Update disk tray status */
        if (reason == VIR_DOMAIN_EVENT_TRAY_CHANGE_OPEN)
            disk->tray_status = VIR_DOMAIN_DISK_TRAY_OPEN;
        else if (reason == VIR_DOMAIN_EVENT_TRAY_CHANGE_CLOSE)
            disk->tray_status = VIR_DOMAIN_DISK_TRAY_CLOSED;

        if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm, driver->caps) < 0) {
            VIR_WARN("Unable to save status on vm %s after tray moved event",
                     vm->def->name);
        }

        virDomainObjBroadcast(vm);
    }

    virObjectUnlock(vm);
    virObjectEventStateQueue(driver->domainEventState, event);
    virObjectUnref(cfg);
    return 0;
}

static int
qemuProcessHandlePMWakeup(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                          virDomainObjPtr vm,
                          void *opaque)
{
    virQEMUDriverPtr driver = opaque;
    virObjectEventPtr event = NULL;
    virObjectEventPtr lifecycleEvent = NULL;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);

    virObjectLock(vm);
    event = virDomainEventPMWakeupNewFromObj(vm);

    /* Don't set domain status back to running if it wasn't paused
     * from guest side, otherwise it can just cause confusion.
     */
    if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_PMSUSPENDED) {
        VIR_DEBUG("Transitioned guest %s from pmsuspended to running "
                  "state due to QMP wakeup event", vm->def->name);

        virDomainObjSetState(vm, VIR_DOMAIN_RUNNING,
                             VIR_DOMAIN_RUNNING_WAKEUP);
        lifecycleEvent = virDomainEventLifecycleNewFromObj(vm,
                                                  VIR_DOMAIN_EVENT_STARTED,
                                                  VIR_DOMAIN_EVENT_STARTED_WAKEUP);

        if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm, driver->caps) < 0) {
            VIR_WARN("Unable to save status on vm %s after wakeup event",
                     vm->def->name);
        }
    }

    virObjectUnlock(vm);
    virObjectEventStateQueue(driver->domainEventState, event);
    virObjectEventStateQueue(driver->domainEventState, lifecycleEvent);
    virObjectUnref(cfg);
    return 0;
}

static int
qemuProcessHandlePMSuspend(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                           virDomainObjPtr vm,
                           void *opaque)
{
    virQEMUDriverPtr driver = opaque;
    virObjectEventPtr event = NULL;
    virObjectEventPtr lifecycleEvent = NULL;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);

    virObjectLock(vm);
    event = virDomainEventPMSuspendNewFromObj(vm);

    if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_RUNNING) {
        qemuDomainObjPrivatePtr priv = vm->privateData;
        VIR_DEBUG("Transitioned guest %s to pmsuspended state due to "
                  "QMP suspend event", vm->def->name);

        virDomainObjSetState(vm, VIR_DOMAIN_PMSUSPENDED,
                             VIR_DOMAIN_PMSUSPENDED_UNKNOWN);
        lifecycleEvent =
            virDomainEventLifecycleNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_PMSUSPENDED,
                                     VIR_DOMAIN_EVENT_PMSUSPENDED_MEMORY);

        if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm, driver->caps) < 0) {
            VIR_WARN("Unable to save status on vm %s after suspend event",
                     vm->def->name);
        }

        if (priv->agent)
            qemuAgentNotifyEvent(priv->agent, QEMU_AGENT_EVENT_SUSPEND);
    }

    virObjectUnlock(vm);

    virObjectEventStateQueue(driver->domainEventState, event);
    virObjectEventStateQueue(driver->domainEventState, lifecycleEvent);
    virObjectUnref(cfg);
    return 0;
}

static int
qemuProcessHandleBalloonChange(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                               virDomainObjPtr vm,
                               unsigned long long actual,
                               void *opaque)
{
    virQEMUDriverPtr driver = opaque;
    virObjectEventPtr event = NULL;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);

    virObjectLock(vm);
    event = virDomainEventBalloonChangeNewFromObj(vm, actual);

    VIR_DEBUG("Updating balloon from %lld to %lld kb",
              vm->def->mem.cur_balloon, actual);
    vm->def->mem.cur_balloon = actual;

    if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm, driver->caps) < 0)
        VIR_WARN("unable to save domain status with balloon change");

    virObjectUnlock(vm);

    virObjectEventStateQueue(driver->domainEventState, event);
    virObjectUnref(cfg);
    return 0;
}

static int
qemuProcessHandlePMSuspendDisk(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                               virDomainObjPtr vm,
                               void *opaque)
{
    virQEMUDriverPtr driver = opaque;
    virObjectEventPtr event = NULL;
    virObjectEventPtr lifecycleEvent = NULL;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);

    virObjectLock(vm);
    event = virDomainEventPMSuspendDiskNewFromObj(vm);

    if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_RUNNING) {
        qemuDomainObjPrivatePtr priv = vm->privateData;
        VIR_DEBUG("Transitioned guest %s to pmsuspended state due to "
                  "QMP suspend_disk event", vm->def->name);

        virDomainObjSetState(vm, VIR_DOMAIN_PMSUSPENDED,
                             VIR_DOMAIN_PMSUSPENDED_UNKNOWN);
        lifecycleEvent =
            virDomainEventLifecycleNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_PMSUSPENDED,
                                     VIR_DOMAIN_EVENT_PMSUSPENDED_DISK);

        if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm, driver->caps) < 0) {
            VIR_WARN("Unable to save status on vm %s after suspend event",
                     vm->def->name);
        }

        if (priv->agent)
            qemuAgentNotifyEvent(priv->agent, QEMU_AGENT_EVENT_SUSPEND);
    }

    virObjectUnlock(vm);

    virObjectEventStateQueue(driver->domainEventState, event);
    virObjectEventStateQueue(driver->domainEventState, lifecycleEvent);
    virObjectUnref(cfg);

    return 0;
}


static int
qemuProcessHandleGuestPanic(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                            virDomainObjPtr vm,
                            qemuMonitorEventPanicInfoPtr info,
                            void *opaque)
{
    virQEMUDriverPtr driver = opaque;
    struct qemuProcessEvent *processEvent;

    virObjectLock(vm);
    if (VIR_ALLOC(processEvent) < 0)
        goto cleanup;

    processEvent->eventType = QEMU_PROCESS_EVENT_GUESTPANIC;
    processEvent->action = vm->def->onCrash;
    processEvent->data = info;
    /* Hold an extra reference because we can't allow 'vm' to be
     * deleted before handling guest panic event is finished.
     */
    processEvent->vm = virObjectRef(vm);

    if (virThreadPoolSendJob(driver->workerPool, 0, processEvent) < 0) {
        if (!virObjectUnref(vm))
            vm = NULL;
        qemuProcessEventFree(processEvent);
    }

 cleanup:
    if (vm)
        virObjectUnlock(vm);

    return 0;
}


int
qemuProcessHandleDeviceDeleted(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                               virDomainObjPtr vm,
                               const char *devAlias,
                               void *opaque)
{
    virQEMUDriverPtr driver = opaque;
    struct qemuProcessEvent *processEvent = NULL;
    char *data;

    virObjectLock(vm);

    VIR_DEBUG("Device %s removed from domain %p %s",
              devAlias, vm, vm->def->name);

    if (qemuDomainSignalDeviceRemoval(vm, devAlias,
                                      QEMU_DOMAIN_UNPLUGGING_DEVICE_STATUS_OK))
        goto cleanup;

    if (VIR_ALLOC(processEvent) < 0)
        goto error;

    processEvent->eventType = QEMU_PROCESS_EVENT_DEVICE_DELETED;
    if (VIR_STRDUP(data, devAlias) < 0)
        goto error;
    processEvent->data = data;
    processEvent->vm = virObjectRef(vm);

    if (virThreadPoolSendJob(driver->workerPool, 0, processEvent) < 0) {
        ignore_value(virObjectUnref(vm));
        goto error;
    }

 cleanup:
    virObjectUnlock(vm);
    return 0;
 error:
    qemuProcessEventFree(processEvent);
    goto cleanup;
}


/**
 *
 * Meaning of fields reported by the event according to the ACPI standard:
 * @source:
 *  0x00 - 0xff: Notification values, as passed at the request time
 *  0x100: Operating System Shutdown Processing
 *  0x103: Ejection processing
 *  0x200: Insertion processing
 *  other values are reserved
 *
 * @status:
 *   general values
 *     0x00: success
 *     0x01: non-specific failure
 *     0x02: unrecognized notify code
 *     0x03 - 0x7f: reserved
 *     other values are specific to the notification type (see below)
 *
 *   for the 0x100 source the following additional codes are standardized:
 *     0x80: OS Shutdown request denied
 *     0x81: OS Shutdown in progress
 *     0x82: OS Shutdown completed
 *     0x83: OS Graceful shutdown not supported
 *     other higher values are reserved
 *
 *  for the 0x003 (Ejection request) and 0x103 (Ejection processing) source
 *  the following additional codes are standardized:
 *     0x80: Device ejection not supported by OSPM
 *     0x81: Device in use by application
 *     0x82: Device Busy
 *     0x83: Ejection dependency is busy or not supported for ejection by OSPM
 *     0x84: Ejection is in progress (pending)
 *     other higher values are reserved
 *
 *  for the 0x200 source the following additional codes are standardized:
 *     0x80: Device insertion in progress (pending)
 *     0x81: Device driver load failure
 *     0x82: Device insertion not supported by OSPM
 *     0x83-0x8F: Reserved
 *     0x90-0x9F: Insertion failure - Resources Unavailable as described by the
 *                                    following bit encodings:
 *                                    Bit [3]: Bus or Segment Numbers
 *                                    Bit [2]: Interrupts
 *                                    Bit [1]: I/O
 *                                    Bit [0]: Memory
 *     other higher values are reserved
 *
 * Other fields and semantics are specific to the qemu handling of the event.
 *  - @alias may be NULL for successful unplug operations
 *  - @slotType describes the device type a bit more closely, currently the
 *    only known value is 'DIMM'
 *  - @slot describes the specific device
 *
 *  Note that qemu does not emit the event for all the documented sources or
 *  devices.
 */
static int
qemuProcessHandleAcpiOstInfo(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                             virDomainObjPtr vm,
                             const char *alias,
                             const char *slotType,
                             const char *slot,
                             unsigned int source,
                             unsigned int status,
                             void *opaque)
{
    virQEMUDriverPtr driver = opaque;
    virObjectEventPtr event = NULL;

    virObjectLock(vm);

    VIR_DEBUG("ACPI OST info for device %s domain %p %s. "
              "slotType='%s' slot='%s' source=%u status=%u",
              NULLSTR(alias), vm, vm->def->name, slotType, slot, source, status);

    if (!alias)
        goto cleanup;

    if (STREQ(slotType, "DIMM")) {
        if ((source == 0x003 || source == 0x103) &&
            (status == 0x01 || (status >= 0x80 && status <= 0x83))) {
            qemuDomainSignalDeviceRemoval(vm, alias,
                                          QEMU_DOMAIN_UNPLUGGING_DEVICE_STATUS_GUEST_REJECTED);

            event = virDomainEventDeviceRemovalFailedNewFromObj(vm, alias);
        }
    }

 cleanup:
    virObjectUnlock(vm);
    virObjectEventStateQueue(driver->domainEventState, event);

    return 0;
}


static int
qemuProcessHandleBlockThreshold(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                                virDomainObjPtr vm,
                                const char *nodename,
                                unsigned long long threshold,
                                unsigned long long excess,
                                void *opaque)
{
    virQEMUDriverPtr driver = opaque;
    virObjectEventPtr event = NULL;
    virDomainDiskDefPtr disk;
    virStorageSourcePtr src;
    unsigned int idx;
    char *dev = NULL;
    const char *path = NULL;

    virObjectLock(vm);

    VIR_DEBUG("BLOCK_WRITE_THRESHOLD event for block node '%s' in domain %p %s:"
              "threshold '%llu' exceeded by '%llu'",
              nodename, vm, vm->def->name, threshold, excess);

    if ((disk = qemuDomainDiskLookupByNodename(vm->def, nodename, &src, &idx))) {
        if (virStorageSourceIsLocalStorage(src))
            path = src->path;

        if ((dev = qemuDomainDiskBackingStoreGetName(disk, src, idx))) {
            event = virDomainEventBlockThresholdNewFromObj(vm, dev, path,
                                                           threshold, excess);
            VIR_FREE(dev);
        }
    }

    virObjectUnlock(vm);
    virObjectEventStateQueue(driver->domainEventState, event);

    return 0;
}


static int
qemuProcessHandleNicRxFilterChanged(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                                    virDomainObjPtr vm,
                                    const char *devAlias,
                                    void *opaque)
{
    virQEMUDriverPtr driver = opaque;
    struct qemuProcessEvent *processEvent = NULL;
    char *data;

    virObjectLock(vm);

    VIR_DEBUG("Device %s RX Filter changed in domain %p %s",
              devAlias, vm, vm->def->name);

    if (VIR_ALLOC(processEvent) < 0)
        goto error;

    processEvent->eventType = QEMU_PROCESS_EVENT_NIC_RX_FILTER_CHANGED;
    if (VIR_STRDUP(data, devAlias) < 0)
        goto error;
    processEvent->data = data;
    processEvent->vm = virObjectRef(vm);

    if (virThreadPoolSendJob(driver->workerPool, 0, processEvent) < 0) {
        ignore_value(virObjectUnref(vm));
        goto error;
    }

 cleanup:
    virObjectUnlock(vm);
    return 0;
 error:
    qemuProcessEventFree(processEvent);
    goto cleanup;
}


static int
qemuProcessHandleSerialChanged(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                               virDomainObjPtr vm,
                               const char *devAlias,
                               bool connected,
                               void *opaque)
{
    virQEMUDriverPtr driver = opaque;
    struct qemuProcessEvent *processEvent = NULL;
    char *data;

    virObjectLock(vm);

    VIR_DEBUG("Serial port %s state changed to '%d' in domain %p %s",
              devAlias, connected, vm, vm->def->name);

    if (VIR_ALLOC(processEvent) < 0)
        goto error;

    processEvent->eventType = QEMU_PROCESS_EVENT_SERIAL_CHANGED;
    if (VIR_STRDUP(data, devAlias) < 0)
        goto error;
    processEvent->data = data;
    processEvent->action = connected;
    processEvent->vm = virObjectRef(vm);

    if (virThreadPoolSendJob(driver->workerPool, 0, processEvent) < 0) {
        ignore_value(virObjectUnref(vm));
        goto error;
    }

 cleanup:
    virObjectUnlock(vm);
    return 0;
 error:
    qemuProcessEventFree(processEvent);
    goto cleanup;
}


static int
qemuProcessHandleSpiceMigrated(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                               virDomainObjPtr vm,
                               void *opaque ATTRIBUTE_UNUSED)
{
    qemuDomainObjPrivatePtr priv;

    virObjectLock(vm);

    VIR_DEBUG("Spice migration completed for domain %p %s",
              vm, vm->def->name);

    priv = vm->privateData;
    if (priv->job.asyncJob != QEMU_ASYNC_JOB_MIGRATION_OUT) {
        VIR_DEBUG("got SPICE_MIGRATE_COMPLETED event without a migration job");
        goto cleanup;
    }

    priv->job.spiceMigrated = true;
    virDomainObjBroadcast(vm);

 cleanup:
    virObjectUnlock(vm);
    return 0;
}


static int
qemuProcessHandleMigrationStatus(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                                 virDomainObjPtr vm,
                                 int status,
                                 void *opaque)
{
    qemuDomainObjPrivatePtr priv;
    virQEMUDriverPtr driver = opaque;
    virObjectEventPtr event = NULL;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    int reason;

    virObjectLock(vm);

    VIR_DEBUG("Migration of domain %p %s changed state to %s",
              vm, vm->def->name,
              qemuMonitorMigrationStatusTypeToString(status));

    priv = vm->privateData;
    if (priv->job.asyncJob == QEMU_ASYNC_JOB_NONE) {
        VIR_DEBUG("got MIGRATION event without a migration job");
        goto cleanup;
    }

    priv->job.current->stats.mig.status = status;
    virDomainObjBroadcast(vm);

    if (status == QEMU_MONITOR_MIGRATION_STATUS_POSTCOPY &&
        virDomainObjGetState(vm, &reason) == VIR_DOMAIN_PAUSED &&
        reason == VIR_DOMAIN_PAUSED_MIGRATION) {
        VIR_DEBUG("Correcting paused state reason for domain %s to %s",
                  vm->def->name,
                  virDomainPausedReasonTypeToString(VIR_DOMAIN_PAUSED_POSTCOPY));

        virDomainObjSetState(vm, VIR_DOMAIN_PAUSED, VIR_DOMAIN_PAUSED_POSTCOPY);
        event = virDomainEventLifecycleNewFromObj(vm,
                                                  VIR_DOMAIN_EVENT_SUSPENDED,
                                                  VIR_DOMAIN_EVENT_SUSPENDED_POSTCOPY);

        if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm, driver->caps) < 0) {
            VIR_WARN("Unable to save status on vm %s after state change",
                     vm->def->name);
        }
    }

 cleanup:
    virObjectUnlock(vm);
    virObjectEventStateQueue(driver->domainEventState, event);
    virObjectUnref(cfg);
    return 0;
}


static int
qemuProcessHandleMigrationPass(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                               virDomainObjPtr vm,
                               int pass,
                               void *opaque)
{
    virQEMUDriverPtr driver = opaque;
    qemuDomainObjPrivatePtr priv;

    virObjectLock(vm);

    VIR_DEBUG("Migrating domain %p %s, iteration %d",
              vm, vm->def->name, pass);

    priv = vm->privateData;
    if (priv->job.asyncJob == QEMU_ASYNC_JOB_NONE) {
        VIR_DEBUG("got MIGRATION_PASS event without a migration job");
        goto cleanup;
    }

    virObjectEventStateQueue(driver->domainEventState,
                         virDomainEventMigrationIterationNewFromObj(vm, pass));

 cleanup:
    virObjectUnlock(vm);
    return 0;
}


static int
qemuProcessHandleDumpCompleted(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                               virDomainObjPtr vm,
                               int status,
                               qemuMonitorDumpStatsPtr stats,
                               const char *error,
                               void *opaque ATTRIBUTE_UNUSED)
{
    qemuDomainObjPrivatePtr priv;

    virObjectLock(vm);

    VIR_DEBUG("Dump completed for domain %p %s with stats=%p error='%s'",
              vm, vm->def->name, stats, NULLSTR(error));

    priv = vm->privateData;
    if (priv->job.asyncJob == QEMU_ASYNC_JOB_NONE) {
        VIR_DEBUG("got DUMP_COMPLETED event without a dump_completed job");
        goto cleanup;
    }
    priv->job.dumpCompleted = true;
    priv->job.current->stats.dump = *stats;
    ignore_value(VIR_STRDUP_QUIET(priv->job.error, error));

    /* Force error if extracting the DUMP_COMPLETED status failed */
    if (!error && status < 0) {
        ignore_value(VIR_STRDUP_QUIET(priv->job.error, virGetLastErrorMessage()));
        priv->job.current->stats.dump.status = QEMU_MONITOR_DUMP_STATUS_FAILED;
    }

    virDomainObjBroadcast(vm);

 cleanup:
    virResetLastError();
    virObjectUnlock(vm);
    return 0;
}


static int
qemuProcessHandlePRManagerStatusChanged(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                                        virDomainObjPtr vm,
                                        const char *prManager,
                                        bool connected,
                                        void *opaque)
{
    virQEMUDriverPtr driver = opaque;
    qemuDomainObjPrivatePtr priv;
    struct qemuProcessEvent *processEvent = NULL;
    const char *managedAlias = qemuDomainGetManagedPRAlias();
    int ret = -1;

    virObjectLock(vm);

    VIR_DEBUG("pr-manager %s status changed for domain %p %s connected=%d",
              prManager, vm, vm->def->name, connected);

    if (connected) {
        /* Connect events are boring. */
        ret = 0;
        goto cleanup;
    }
    /* Disconnect events are more interesting. */

    if (STRNEQ(prManager, managedAlias)) {
        VIR_DEBUG("pr-manager %s not managed, ignoring event",
                  prManager);
        ret = 0;
        goto cleanup;
    }

    priv = vm->privateData;
    priv->prDaemonRunning = false;

    if (VIR_ALLOC(processEvent) < 0)
        goto cleanup;

    processEvent->eventType = QEMU_PROCESS_EVENT_PR_DISCONNECT;
    processEvent->vm = virObjectRef(vm);

    if (virThreadPoolSendJob(driver->workerPool, 0, processEvent) < 0) {
        qemuProcessEventFree(processEvent);
        virObjectUnref(vm);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virObjectUnlock(vm);
    return ret;
}


static int
qemuProcessHandleRdmaGidStatusChanged(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                                      virDomainObjPtr vm,
                                      const char *netdev,
                                      bool gid_status,
                                      unsigned long long subnet_prefix,
                                      unsigned long long interface_id,
                                      void *opaque)
{
    virQEMUDriverPtr driver = opaque;
    struct qemuProcessEvent *processEvent = NULL;
    qemuMonitorRdmaGidStatusPtr info = NULL;
    int ret = -1;

    virObjectLock(vm);

    VIR_DEBUG("netdev=%s,gid_status=%d,subnet_prefix=0x%llx,interface_id=0x%llx",
              netdev, gid_status, subnet_prefix, interface_id);

    if (VIR_ALLOC(info) < 0 ||
        VIR_STRDUP(info->netdev, netdev) < 0)
        goto cleanup;

    info->gid_status = gid_status;
    info->subnet_prefix = subnet_prefix;
    info->interface_id = interface_id;

    if (VIR_ALLOC(processEvent) < 0)
        goto cleanup;

    processEvent->eventType = QEMU_PROCESS_EVENT_RDMA_GID_STATUS_CHANGED;
    processEvent->vm = virObjectRef(vm);
    VIR_STEAL_PTR(processEvent->data, info);

    if (virThreadPoolSendJob(driver->workerPool, 0, processEvent) < 0) {
        qemuProcessEventFree(processEvent);
        virObjectUnref(vm);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    qemuMonitorEventRdmaGidStatusFree(info);
    virObjectUnlock(vm);
    return ret;
}


static qemuMonitorCallbacks monitorCallbacks = {
    .eofNotify = qemuProcessHandleMonitorEOF,
    .errorNotify = qemuProcessHandleMonitorError,
    .domainEvent = qemuProcessHandleEvent,
    .domainShutdown = qemuProcessHandleShutdown,
    .domainStop = qemuProcessHandleStop,
    .domainResume = qemuProcessHandleResume,
    .domainReset = qemuProcessHandleReset,
    .domainRTCChange = qemuProcessHandleRTCChange,
    .domainWatchdog = qemuProcessHandleWatchdog,
    .domainIOError = qemuProcessHandleIOError,
    .domainGraphics = qemuProcessHandleGraphics,
    .domainBlockJob = qemuProcessHandleBlockJob,
    .domainTrayChange = qemuProcessHandleTrayChange,
    .domainPMWakeup = qemuProcessHandlePMWakeup,
    .domainPMSuspend = qemuProcessHandlePMSuspend,
    .domainBalloonChange = qemuProcessHandleBalloonChange,
    .domainPMSuspendDisk = qemuProcessHandlePMSuspendDisk,
    .domainGuestPanic = qemuProcessHandleGuestPanic,
    .domainDeviceDeleted = qemuProcessHandleDeviceDeleted,
    .domainNicRxFilterChanged = qemuProcessHandleNicRxFilterChanged,
    .domainSerialChange = qemuProcessHandleSerialChanged,
    .domainSpiceMigrated = qemuProcessHandleSpiceMigrated,
    .domainMigrationStatus = qemuProcessHandleMigrationStatus,
    .domainMigrationPass = qemuProcessHandleMigrationPass,
    .domainAcpiOstInfo = qemuProcessHandleAcpiOstInfo,
    .domainBlockThreshold = qemuProcessHandleBlockThreshold,
    .domainDumpCompleted = qemuProcessHandleDumpCompleted,
    .domainPRManagerStatusChanged = qemuProcessHandlePRManagerStatusChanged,
    .domainRdmaGidStatusChanged = qemuProcessHandleRdmaGidStatusChanged,
};

static void
qemuProcessMonitorReportLogError(qemuMonitorPtr mon,
                                 const char *msg,
                                 void *opaque);


static void
qemuProcessMonitorLogFree(void *opaque)
{
    qemuDomainLogContextPtr logCtxt = opaque;
    virObjectUnref(logCtxt);
}


static int
qemuProcessInitMonitor(virQEMUDriverPtr driver,
                       virDomainObjPtr vm,
                       qemuDomainAsyncJob asyncJob)
{
    int ret;

    if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) < 0)
        return -1;

    ret = qemuMonitorSetCapabilities(QEMU_DOMAIN_PRIVATE(vm)->mon);

    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        ret = -1;

    return ret;
}


static int
qemuConnectMonitor(virQEMUDriverPtr driver, virDomainObjPtr vm, int asyncJob,
                   bool retry, qemuDomainLogContextPtr logCtxt)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    qemuMonitorPtr mon = NULL;
    unsigned long long timeout = 0;
    virDomainChrSourceDefPtr monConfig;

    if (qemuSecuritySetDaemonSocketLabel(driver->securityManager, vm->def) < 0) {
        VIR_ERROR(_("Failed to set security context for monitor for %s"),
                  vm->def->name);
        return -1;
    }

    /* When using hugepages, kernel zeroes them out before
     * handing them over to qemu. This can be very time
     * consuming. Therefore, add a second to timeout for each
     * 1GiB of guest RAM. */
    timeout = vm->def->mem.total_memory / (1024 * 1024);

    /* Hold an extra reference because we can't allow 'vm' to be
     * deleted until the monitor gets its own reference. */
    virObjectRef(vm);

    ignore_value(virTimeMillisNow(&priv->monStart));
    monConfig = virObjectRef(priv->monConfig);
    virObjectUnlock(vm);

    mon = qemuMonitorOpen(vm,
                          monConfig,
                          retry,
                          timeout,
                          &monitorCallbacks,
                          driver);

    if (mon && logCtxt) {
        virObjectRef(logCtxt);
        qemuMonitorSetDomainLog(mon,
                                qemuProcessMonitorReportLogError,
                                logCtxt,
                                qemuProcessMonitorLogFree);
    }

    virObjectLock(vm);
    virObjectUnref(monConfig);
    virObjectUnref(vm);
    priv->monStart = 0;

    if (!virDomainObjIsActive(vm)) {
        qemuMonitorClose(mon);
        mon = NULL;
    }
    priv->mon = mon;

    if (qemuSecurityClearSocketLabel(driver->securityManager, vm->def) < 0) {
        VIR_ERROR(_("Failed to clear security context for monitor for %s"),
                  vm->def->name);
        return -1;
    }

    if (priv->mon == NULL) {
        VIR_INFO("Failed to connect monitor for %s", vm->def->name);
        return -1;
    }

    if (qemuProcessInitMonitor(driver, vm, asyncJob) < 0)
        return -1;

    if (qemuMigrationCapsCheck(driver, vm, asyncJob) < 0)
        return -1;

    return 0;
}


/**
 * qemuProcessReadLog: Read log file of a qemu VM
 * @logCtxt: the domain log context
 * @msg: pointer to buffer to store the read messages in
 * @max: maximum length of the message returned in @msg
 *
 * Reads log of a qemu VM. Skips messages not produced by qemu or irrelevant
 * messages. If @max is not zero, @msg will contain at most @max characters
 * from the end of the log and @msg will start after a new line if possible.
 *
 * Returns 0 on success or -1 on error
 */
static int
qemuProcessReadLog(qemuDomainLogContextPtr logCtxt,
                   char **msg,
                   size_t max)
{
    char *buf;
    ssize_t got;
    char *eol;
    char *filter_next;
    size_t skip;

    if ((got = qemuDomainLogContextRead(logCtxt, &buf)) < 0)
        return -1;

    /* Filter out debug messages from intermediate libvirt process */
    filter_next = buf;
    while ((eol = strchr(filter_next, '\n'))) {
        *eol = '\0';
        if (virLogProbablyLogMessage(filter_next) ||
            strstr(filter_next, "char device redirected to")) {
            skip = (eol + 1) - filter_next;
            memmove(filter_next, eol + 1, buf + got - eol);
            got -= skip;
        } else {
            filter_next = eol + 1;
            *eol = '\n';
        }
    }
    filter_next = NULL; /* silence false coverity warning */

    if (got > 0 &&
        buf[got - 1] == '\n') {
        buf[got - 1] = '\0';
        got--;
    }

    if (max > 0 && got > max) {
        skip = got - max;

        if (buf[skip - 1] != '\n' &&
            (eol = strchr(buf + skip, '\n')) &&
            !virStringIsEmpty(eol + 1))
            skip = eol + 1 - buf;

        memmove(buf, buf + skip, got - skip + 1);
        got -= skip;
    }

    ignore_value(VIR_REALLOC_N_QUIET(buf, got + 1));
    *msg = buf;
    return 0;
}


static int
qemuProcessReportLogError(qemuDomainLogContextPtr logCtxt,
                          const char *msgprefix)
{
    char *logmsg = NULL;
    size_t max;

    max = VIR_ERROR_MAX_LENGTH - 1;
    max -= strlen(msgprefix);
    /* The length of the formatting string minus two '%s' */
    max -= strlen(_("%s: %s")) - 4;

    if (qemuProcessReadLog(logCtxt, &logmsg, max) < 0)
        return -1;

    virResetLastError();
    if (virStringIsEmpty(logmsg))
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", msgprefix);
    else
        virReportError(VIR_ERR_INTERNAL_ERROR, _("%s: %s"), msgprefix, logmsg);

    VIR_FREE(logmsg);
    return 0;
}


static void
qemuProcessMonitorReportLogError(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                                 const char *msg,
                                 void *opaque)
{
    qemuDomainLogContextPtr logCtxt = opaque;
    qemuProcessReportLogError(logCtxt, msg);
}


static int
qemuProcessLookupPTYs(virDomainChrDefPtr *devices,
                      int count,
                      virHashTablePtr info)
{
    char *id = NULL;
    size_t i;
    int ret = -1;

    for (i = 0; i < count; i++) {
        virDomainChrDefPtr chr = devices[i];
        if (chr->source->type == VIR_DOMAIN_CHR_TYPE_PTY) {
            qemuMonitorChardevInfoPtr entry;

            VIR_FREE(id);
            if (virAsprintf(&id, "char%s", chr->info.alias) < 0)
                return -1;

            entry = virHashLookup(info, id);
            if (!entry || !entry->ptyPath) {
                if (chr->source->data.file.path == NULL) {
                    /* neither the log output nor 'info chardev' had a
                     * pty path for this chardev, report an error
                     */
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("no assigned pty for device %s"), id);
                    goto cleanup;
                } else {
                    /* 'info chardev' had no pty path for this chardev,
                     * but the log output had, so we're fine
                     */
                    continue;
                }
            }

            VIR_FREE(chr->source->data.file.path);
            if (VIR_STRDUP(chr->source->data.file.path, entry->ptyPath) < 0)
                goto cleanup;
        }
    }

    ret = 0;
 cleanup:
    VIR_FREE(id);
    return ret;
}

static int
qemuProcessFindCharDevicePTYsMonitor(virDomainObjPtr vm,
                                     virHashTablePtr info)
{
    size_t i = 0;

    if (qemuProcessLookupPTYs(vm->def->serials, vm->def->nserials, info) < 0)
        return -1;

    if (qemuProcessLookupPTYs(vm->def->parallels, vm->def->nparallels,
                              info) < 0)
        return -1;

    if (qemuProcessLookupPTYs(vm->def->channels, vm->def->nchannels, info) < 0)
        return -1;
    /* For historical reasons, console[0] can be just an alias
     * for serial[0]. That's why we need to update it as well. */
    if (vm->def->nconsoles) {
        virDomainChrDefPtr chr = vm->def->consoles[0];

        if (vm->def->nserials &&
            chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE &&
            chr->targetType == VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SERIAL) {
            /* yes, the first console is just an alias for serials[0] */
            i = 1;
            if (virDomainChrSourceDefCopy(chr->source,
                                          ((vm->def->serials[0])->source)) < 0)
                return -1;
        }
    }

    if (qemuProcessLookupPTYs(vm->def->consoles + i, vm->def->nconsoles - i,
                              info) < 0)
        return -1;

    return 0;
}


static int
qemuProcessRefreshChannelVirtioState(virQEMUDriverPtr driver,
                                     virDomainObjPtr vm,
                                     virHashTablePtr info,
                                     int booted)
{
    size_t i;
    int agentReason = VIR_CONNECT_DOMAIN_EVENT_AGENT_LIFECYCLE_REASON_CHANNEL;
    qemuMonitorChardevInfoPtr entry;
    virObjectEventPtr event = NULL;
    char *id = NULL;
    int ret = -1;

    if (booted)
        agentReason = VIR_CONNECT_DOMAIN_EVENT_AGENT_LIFECYCLE_REASON_DOMAIN_STARTED;

    for (i = 0; i < vm->def->nchannels; i++) {
        virDomainChrDefPtr chr = vm->def->channels[i];
        if (chr->targetType == VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_VIRTIO) {

            VIR_FREE(id);
            if (virAsprintf(&id, "char%s", chr->info.alias) < 0)
                goto cleanup;

            /* port state not reported */
            if (!(entry = virHashLookup(info, id)) ||
                !entry->state)
                continue;

            if (entry->state != VIR_DOMAIN_CHR_DEVICE_STATE_DEFAULT &&
                STREQ_NULLABLE(chr->target.name, "org.qemu.guest_agent.0") &&
                (event = virDomainEventAgentLifecycleNewFromObj(vm, entry->state,
                                                                agentReason)))
                virObjectEventStateQueue(driver->domainEventState, event);

            chr->state = entry->state;
        }
    }

    ret = 0;
 cleanup:
    VIR_FREE(id);
    return ret;
}


int
qemuRefreshVirtioChannelState(virQEMUDriverPtr driver,
                              virDomainObjPtr vm,
                              qemuDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virHashTablePtr info = NULL;
    int ret = -1;

    if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) < 0)
        goto cleanup;

    ret = qemuMonitorGetChardevInfo(priv->mon, &info);
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        ret = -1;

    if (ret < 0)
        goto cleanup;

    ret = qemuProcessRefreshChannelVirtioState(driver, vm, info, false);

 cleanup:
    virHashFree(info);
    return ret;
}


static int
qemuProcessRefreshPRManagerState(virDomainObjPtr vm,
                                 virHashTablePtr info)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    qemuMonitorPRManagerInfoPtr prManagerInfo;
    const char *managedAlias = qemuDomainGetManagedPRAlias();
    int ret = -1;

    if (!(prManagerInfo = virHashLookup(info, managedAlias))) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("missing info on pr-manager %s"),
                       managedAlias);
        goto cleanup;
    }

    priv->prDaemonRunning = prManagerInfo->connected;

    if (!priv->prDaemonRunning &&
        qemuProcessStartManagedPRDaemon(vm) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    return ret;
}


static int
qemuRefreshPRManagerState(virQEMUDriverPtr driver,
                          virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virHashTablePtr info = NULL;
    int ret = -1;

    if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_PR_MANAGER_HELPER) ||
        !virDomainDefHasManagedPR(vm->def))
        return 0;

    qemuDomainObjEnterMonitor(driver, vm);
    ret = qemuMonitorGetPRManagerInfo(priv->mon, &info);
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        ret = -1;

    if (ret < 0)
        goto cleanup;

    ret = qemuProcessRefreshPRManagerState(vm, info);

 cleanup:
    virHashFree(info);
    return ret;
}


static void
qemuRefreshRTC(virQEMUDriverPtr driver,
               virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    time_t now, then;
    struct tm thenbits;
    long localOffset;
    int rv;

    if (vm->def->clock.offset != VIR_DOMAIN_CLOCK_OFFSET_VARIABLE)
        return;

    memset(&thenbits, 0, sizeof(thenbits));
    qemuDomainObjEnterMonitor(driver, vm);
    now = time(NULL);
    rv = qemuMonitorGetRTCTime(priv->mon, &thenbits);
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        rv = -1;

    if (rv < 0)
        return;

    thenbits.tm_isdst = -1;
    if ((then = mktime(&thenbits)) == (time_t)-1) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to convert time"));
        return;
    }

    /* Thing is, @now is in local TZ but @then in UTC. */
    if (virTimeLocalOffsetFromUTC(&localOffset) < 0)
        return;

    vm->def->clock.data.variable.adjustment = then - now + localOffset;
}

int
qemuProcessRefreshBalloonState(virQEMUDriverPtr driver,
                               virDomainObjPtr vm,
                               int asyncJob)
{
    unsigned long long balloon;
    int rc;

    /* if no ballooning is available, the current size equals to the current
     * full memory size */
    if (!virDomainDefHasMemballoon(vm->def)) {
        vm->def->mem.cur_balloon = virDomainDefGetMemoryTotal(vm->def);
        return 0;
    }

    if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) < 0)
        return -1;

    rc = qemuMonitorGetBalloonInfo(qemuDomainGetMonitor(vm), &balloon);
    if (qemuDomainObjExitMonitor(driver, vm) < 0 || rc < 0)
        return -1;

    vm->def->mem.cur_balloon = balloon;

    return 0;
}


static int
qemuProcessWaitForMonitor(virQEMUDriverPtr driver,
                          virDomainObjPtr vm,
                          int asyncJob,
                          qemuDomainLogContextPtr logCtxt)
{
    int ret = -1;
    virHashTablePtr info = NULL;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    bool retry = true;

    if (priv->qemuCaps &&
        virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_CHARDEV_FD_PASS))
        retry = false;

    VIR_DEBUG("Connect monitor to vm=%p name='%s' retry=%d",
              vm, vm->def->name, retry);

    if (qemuConnectMonitor(driver, vm, asyncJob, retry, logCtxt) < 0)
        goto cleanup;

    /* Try to get the pty path mappings again via the monitor. This is much more
     * reliable if it's available.
     * Note that the monitor itself can be on a pty, so we still need to try the
     * log output method. */
    if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) < 0)
        goto cleanup;
    ret = qemuMonitorGetChardevInfo(priv->mon, &info);
    VIR_DEBUG("qemuMonitorGetChardevInfo returned %i", ret);
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        ret = -1;

    if (ret == 0) {
        if ((ret = qemuProcessFindCharDevicePTYsMonitor(vm, info)) < 0)
            goto cleanup;

        if ((ret = qemuProcessRefreshChannelVirtioState(driver, vm, info,
                                                        true)) < 0)
            goto cleanup;
    }

 cleanup:
    virHashFree(info);

    if (logCtxt && kill(vm->pid, 0) == -1 && errno == ESRCH) {
        qemuProcessReportLogError(logCtxt,
                                  _("process exited while connecting to monitor"));
        ret = -1;
    }

    return ret;
}


static int
qemuProcessDetectIOThreadPIDs(virQEMUDriverPtr driver,
                              virDomainObjPtr vm,
                              int asyncJob)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    qemuMonitorIOThreadInfoPtr *iothreads = NULL;
    int niothreads = 0;
    int ret = -1;
    size_t i;

    if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_OBJECT_IOTHREAD)) {
        ret = 0;
        goto cleanup;
    }

    /* Get the list of IOThreads from qemu */
    if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) < 0)
        goto cleanup;
    niothreads = qemuMonitorGetIOThreads(priv->mon, &iothreads);
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        goto cleanup;
    if (niothreads < 0)
        goto cleanup;

    if (niothreads != vm->def->niothreadids) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("got wrong number of IOThread pids from QEMU monitor. "
                         "got %d, wanted %zu"),
                       niothreads, vm->def->niothreadids);
        goto cleanup;
    }

    /* Nothing to do */
    if (niothreads == 0) {
        ret = 0;
        goto cleanup;
    }

    for (i = 0; i < niothreads; i++) {
        virDomainIOThreadIDDefPtr iothrid;

        if (!(iothrid = virDomainIOThreadIDFind(vm->def,
                                                iothreads[i]->iothread_id))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("iothread %d not found"),
                           iothreads[i]->iothread_id);
            goto cleanup;
        }
        iothrid->thread_id = iothreads[i]->thread_id;
    }

    ret = 0;

 cleanup:
    if (iothreads) {
        for (i = 0; i < niothreads; i++)
            VIR_FREE(iothreads[i]);
        VIR_FREE(iothreads);
    }
    return ret;
}


static int
qemuProcessGetAllCpuAffinity(virBitmapPtr *cpumapRet)
{
    *cpumapRet = NULL;

    if (!virHostCPUHasBitmap())
        return 0;

    if (!(*cpumapRet = virHostCPUGetOnlineBitmap()))
        return -1;

    return 0;
}


/*
 * To be run between fork/exec of QEMU only
 */
#if defined(HAVE_SCHED_GETAFFINITY) || defined(HAVE_BSD_CPU_AFFINITY)
static int
qemuProcessInitCpuAffinity(virDomainObjPtr vm)
{
    VIR_AUTOPTR(virBitmap) cpumapToSet = NULL;
    virDomainNumatuneMemMode mem_mode;
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (!vm->pid) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot setup CPU affinity until process is started"));
        return -1;
    }

    /* Here is the deal, we can't set cpuset.mems before qemu is
     * started as it clashes with KVM allocation. Therefore, we
     * used to let qemu allocate its memory anywhere as we would
     * then move the memory to desired NUMA node via CGroups.
     * However, that might not be always possible because qemu
     * might lock some parts of its memory (e.g. due to VFIO).
     * Even if it possible, memory has to be copied between NUMA
     * nodes which is suboptimal.
     * Solution is to set affinity that matches the best what we
     * would have set in CGroups and then fix it later, once qemu
     * is already running. */
    if (virDomainNumaGetNodeCount(vm->def->numa) <= 1 &&
        virDomainNumatuneGetMode(vm->def->numa, -1, &mem_mode) == 0 &&
        mem_mode == VIR_DOMAIN_NUMATUNE_MEM_STRICT) {
        virBitmapPtr nodeset = NULL;

        if (virDomainNumatuneMaybeGetNodeset(vm->def->numa,
                                             priv->autoNodeset,
                                             &nodeset,
                                             -1) < 0)
            return -1;

        if (virNumaNodesetToCPUset(nodeset, &cpumapToSet) < 0)
            return -1;
    } else if (vm->def->cputune.emulatorpin) {
        if (!(cpumapToSet = virBitmapNewCopy(vm->def->cputune.emulatorpin)))
            return -1;
    } else {
        if (qemuProcessGetAllCpuAffinity(&cpumapToSet) < 0)
            return -1;
    }

    if (cpumapToSet &&
        virProcessSetAffinity(vm->pid, cpumapToSet) < 0) {
        return -1;
    }

    return 0;
}
#else /* !defined(HAVE_SCHED_GETAFFINITY) && !defined(HAVE_BSD_CPU_AFFINITY) */
static int
qemuProcessInitCpuAffinity(virDomainObjPtr vm ATTRIBUTE_UNUSED)
{
    return 0;
}
#endif /* !defined(HAVE_SCHED_GETAFFINITY) && !defined(HAVE_BSD_CPU_AFFINITY) */

/* set link states to down on interfaces at qemu start */
static int
qemuProcessSetLinkStates(virQEMUDriverPtr driver,
                         virDomainObjPtr vm,
                         qemuDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virDomainDefPtr def = vm->def;
    size_t i;
    int ret = -1;
    int rv;

    if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) < 0)
        return -1;

    for (i = 0; i < def->nnets; i++) {
        if (def->nets[i]->linkstate == VIR_DOMAIN_NET_INTERFACE_LINK_STATE_DOWN) {
            if (!def->nets[i]->info.alias) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("missing alias for network device"));
                goto cleanup;
            }

            VIR_DEBUG("Setting link state: %s", def->nets[i]->info.alias);

            rv = qemuMonitorSetLink(priv->mon,
                                    def->nets[i]->info.alias,
                                    VIR_DOMAIN_NET_INTERFACE_LINK_STATE_DOWN);
            if (rv < 0) {
                virReportError(VIR_ERR_OPERATION_FAILED,
                               _("Couldn't set link state on interface: %s"),
                               def->nets[i]->info.alias);
                goto cleanup;
            }
        }
    }

    ret = 0;

 cleanup:
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        ret = -1;
    return ret;
}


/**
 * qemuProcessSetupPid:
 *
 * This function sets resource properties (affinity, cgroups,
 * scheduler) for any PID associated with a domain.  It should be used
 * to set up emulator PIDs as well as vCPU and I/O thread pids to
 * ensure they are all handled the same way.
 *
 * Returns 0 on success, -1 on error.
 */
static int
qemuProcessSetupPid(virDomainObjPtr vm,
                    pid_t pid,
                    virCgroupThreadName nameval,
                    int id,
                    virBitmapPtr cpumask,
                    unsigned long long period,
                    long long quota,
                    virDomainThreadSchedParamPtr sched)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virDomainNumatuneMemMode mem_mode;
    virCgroupPtr cgroup = NULL;
    virBitmapPtr use_cpumask = NULL;
    VIR_AUTOPTR(virBitmap) hostcpumap = NULL;
    char *mem_mask = NULL;
    int ret = -1;

    if ((period || quota) &&
        !virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPU)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("cgroup cpu is required for scheduler tuning"));
        goto cleanup;
    }

    /* Infer which cpumask shall be used. */
    if (cpumask) {
        use_cpumask = cpumask;
    } else if (vm->def->placement_mode == VIR_DOMAIN_CPU_PLACEMENT_MODE_AUTO) {
        use_cpumask = priv->autoCpuset;
    } else if (vm->def->cpumask) {
        use_cpumask = vm->def->cpumask;
    } else {
        /* You may think this is redundant, but we can't assume libvirtd
         * itself is running on all pCPUs, so we need to explicitly set
         * the spawned QEMU instance to all pCPUs if no map is given in
         * its config file */
        if (qemuProcessGetAllCpuAffinity(&hostcpumap) < 0)
            goto cleanup;
        use_cpumask = hostcpumap;
    }

    /*
     * If CPU cgroup controller is not initialized here, then we need
     * neither period nor quota settings.  And if CPUSET controller is
     * not initialized either, then there's nothing to do anyway.
     */
    if (virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPU) ||
        virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPUSET)) {

        if (virDomainNumatuneGetMode(vm->def->numa, -1, &mem_mode) == 0 &&
            mem_mode == VIR_DOMAIN_NUMATUNE_MEM_STRICT &&
            virDomainNumatuneMaybeFormatNodeset(vm->def->numa,
                                                priv->autoNodeset,
                                                &mem_mask, -1) < 0)
            goto cleanup;

        if (virCgroupNewThread(priv->cgroup, nameval, id, true, &cgroup) < 0)
            goto cleanup;

        if (virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPUSET)) {
            if (use_cpumask &&
                qemuSetupCgroupCpusetCpus(cgroup, use_cpumask) < 0)
                goto cleanup;

            if (mem_mask && virCgroupSetCpusetMems(cgroup, mem_mask) < 0)
                goto cleanup;

        }

        if ((period || quota) &&
            qemuSetupCgroupVcpuBW(cgroup, period, quota) < 0)
            goto cleanup;

        /* Move the thread to the sub dir */
        if (virCgroupAddThread(cgroup, pid) < 0)
            goto cleanup;

    }

    /* Setup legacy affinity. */
    if (use_cpumask && virProcessSetAffinity(pid, use_cpumask) < 0)
        goto cleanup;

    /* Set scheduler type and priority, but not for the main thread. */
    if (sched &&
        nameval != VIR_CGROUP_THREAD_EMULATOR &&
        virProcessSetScheduler(pid, sched->policy, sched->priority) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    VIR_FREE(mem_mask);
    if (cgroup) {
        if (ret < 0)
            virCgroupRemove(cgroup);
        virCgroupFree(&cgroup);
    }

    return ret;
}


static int
qemuProcessSetupEmulator(virDomainObjPtr vm)
{
    return qemuProcessSetupPid(vm, vm->pid, VIR_CGROUP_THREAD_EMULATOR,
                               0, vm->def->cputune.emulatorpin,
                               vm->def->cputune.emulator_period,
                               vm->def->cputune.emulator_quota,
                               vm->def->cputune.emulatorsched);
}


static int
qemuProcessResctrlCreate(virQEMUDriverPtr driver,
                         virDomainObjPtr vm)
{
    int ret = -1;
    size_t i = 0;
    virCapsPtr caps = NULL;
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (!vm->def->nresctrls)
        return 0;

    /* Force capability refresh since resctrl info can change
     * XXX: move cache info into virresctrl so caps are not needed */
    caps = virQEMUDriverGetCapabilities(driver, true);
    if (!caps)
        return -1;

    for (i = 0; i < vm->def->nresctrls; i++) {
        size_t j = 0;
        if (virResctrlAllocCreate(caps->host.resctrl,
                                  vm->def->resctrls[i]->alloc,
                                  priv->machineName) < 0)
            goto cleanup;

        for (j = 0; j < vm->def->resctrls[i]->nmonitors; j++) {
            virDomainResctrlMonDefPtr mon = NULL;

            mon = vm->def->resctrls[i]->monitors[j];
            if (virResctrlMonitorCreate(mon->instance,
                                        priv->machineName) < 0)
                goto cleanup;
        }
    }

    ret = 0;
 cleanup:
    virObjectUnref(caps);
    return ret;
}


static char *
qemuProcessBuildPRHelperPidfilePath(virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    const char *prdAlias = qemuDomainGetManagedPRAlias();

    return virPidFileBuildPath(priv->libDir, prdAlias);
}


void
qemuProcessKillManagedPRDaemon(virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virErrorPtr orig_err;
    char *pidfile;

    if (!(pidfile = qemuProcessBuildPRHelperPidfilePath(vm))) {
        VIR_WARN("Unable to construct pr-helper pidfile path");
        return;
    }

    virErrorPreserveLast(&orig_err);
    if (virPidFileForceCleanupPath(pidfile) < 0) {
        VIR_WARN("Unable to kill pr-helper process");
    } else {
        if (unlink(pidfile) < 0 &&
            errno != ENOENT) {
            virReportSystemError(errno,
                                 _("Unable to remove stale pidfile %s"),
                                 pidfile);
        } else {
            priv->prDaemonRunning = false;
        }
    }
    virErrorRestore(&orig_err);

    VIR_FREE(pidfile);
}


static int
qemuProcessStartPRDaemonHook(void *opaque)
{
    virDomainObjPtr vm = opaque;
    size_t i, nfds = 0;
    int *fds = NULL;
    int ret = -1;

    if (qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT)) {
        if (virProcessGetNamespaces(vm->pid, &nfds, &fds) < 0)
            return ret;

        if (nfds > 0 &&
            virProcessSetNamespaces(nfds, fds) < 0)
            goto cleanup;
    }

    ret = 0;
 cleanup:
    for (i = 0; i < nfds; i++)
        VIR_FORCE_CLOSE(fds[i]);
    VIR_FREE(fds);
    return ret;
}


int
qemuProcessStartManagedPRDaemon(virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virQEMUDriverPtr driver = priv->driver;
    virQEMUDriverConfigPtr cfg;
    int errfd = -1;
    char *pidfile = NULL;
    int pidfd = -1;
    char *socketPath = NULL;
    pid_t cpid = -1;
    virCommandPtr cmd = NULL;
    virTimeBackOffVar timebackoff;
    const unsigned long long timeout = 500000; /* ms */
    int ret = -1;

    cfg = virQEMUDriverGetConfig(driver);

    if (!virFileIsExecutable(cfg->prHelperName)) {
        virReportSystemError(errno, _("'%s' is not a suitable pr helper"),
                             cfg->prHelperName);
        goto cleanup;
    }

    if (!(pidfile = qemuProcessBuildPRHelperPidfilePath(vm)))
        goto cleanup;

    /* Just try to acquire. Dummy pid will be replaced later */
    if ((pidfd = virPidFileAcquirePath(pidfile, false, -1)) < 0)
        goto cleanup;

    if (!(socketPath = qemuDomainGetManagedPRSocketPath(priv)))
        goto cleanup;

    /* Remove stale socket */
    if (unlink(socketPath) < 0 &&
        errno != ENOENT) {
        virReportSystemError(errno,
                             _("Unable to remove stale socket path: %s"),
                             socketPath);
        goto cleanup;
    }

    if (!(cmd = virCommandNewArgList(cfg->prHelperName,
                                     "-k", socketPath,
                                     "-f", pidfile,
                                     NULL)))
        goto cleanup;

    virCommandDaemonize(cmd);
    /* We want our virCommand to write child PID into the pidfile
     * so that we can read it even before exec(). */
    virCommandSetPidFile(cmd, pidfile);
    virCommandSetErrorFD(cmd, &errfd);

    /* Place the process into the same namespace and cgroup as
     * qemu (so that it shares the same view of the system). */
    virCommandSetPreExecHook(cmd, qemuProcessStartPRDaemonHook, vm);

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    if (virPidFileReadPath(pidfile, &cpid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("pr helper %s didn't show up"),
                       cfg->prHelperName);
        goto cleanup;
    }

    if (virTimeBackOffStart(&timebackoff, 1, timeout) < 0)
        goto cleanup;
    while (virTimeBackOffWait(&timebackoff)) {
        char errbuf[1024] = { 0 };

        if (virFileExists(socketPath))
            break;

        if (virProcessKill(cpid, 0) == 0)
            continue;

        if (saferead(errfd, errbuf, sizeof(errbuf) - 1) < 0) {
            virReportSystemError(errno,
                                 _("pr helper %s died unexpectedly"),
                                 cfg->prHelperName);
        } else {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("pr helper died and reported: %s"), errbuf);
        }
        goto cleanup;
    }

    if (!virFileExists(socketPath)) {
        virReportError(VIR_ERR_OPERATION_TIMEOUT, "%s",
                       _("pr helper socked did not show up"));
        goto cleanup;
    }

    if (priv->cgroup &&
        virCgroupAddMachineProcess(priv->cgroup, cpid) < 0)
        goto cleanup;

    if (qemuSecurityDomainSetPathLabel(driver, vm, socketPath, true) < 0)
        goto cleanup;

    priv->prDaemonRunning = true;
    ret = 0;
 cleanup:
    if (ret < 0) {
        virCommandAbort(cmd);
        if (cpid >= 0)
            virProcessKillPainfully(cpid, true);
        if (pidfile)
            unlink(pidfile);
    }
    virCommandFree(cmd);
    VIR_FREE(socketPath);
    VIR_FORCE_CLOSE(pidfd);
    VIR_FREE(pidfile);
    VIR_FORCE_CLOSE(errfd);
    virObjectUnref(cfg);
    return ret;
}


static int
qemuProcessInitPasswords(virQEMUDriverPtr driver,
                         virDomainObjPtr vm,
                         int asyncJob)
{
    int ret = 0;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    size_t i;

    for (i = 0; i < vm->def->ngraphics; ++i) {
        virDomainGraphicsDefPtr graphics = vm->def->graphics[i];
        if (graphics->type == VIR_DOMAIN_GRAPHICS_TYPE_VNC) {
            ret = qemuDomainChangeGraphicsPasswords(driver, vm,
                                                    VIR_DOMAIN_GRAPHICS_TYPE_VNC,
                                                    &graphics->data.vnc.auth,
                                                    cfg->vncPassword,
                                                    asyncJob);
        } else if (graphics->type == VIR_DOMAIN_GRAPHICS_TYPE_SPICE) {
            ret = qemuDomainChangeGraphicsPasswords(driver, vm,
                                                    VIR_DOMAIN_GRAPHICS_TYPE_SPICE,
                                                    &graphics->data.spice.auth,
                                                    cfg->spicePassword,
                                                    asyncJob);
        }

        if (ret < 0)
            goto cleanup;
    }

 cleanup:
    virObjectUnref(cfg);
    return ret;
}


static int
qemuProcessPrepareChardevDevice(virDomainDefPtr def ATTRIBUTE_UNUSED,
                                virDomainChrDefPtr dev,
                                void *opaque ATTRIBUTE_UNUSED)
{
    int fd;
    if (dev->source->type != VIR_DOMAIN_CHR_TYPE_FILE)
        return 0;

    if ((fd = open(dev->source->data.file.path,
                   O_CREAT | O_APPEND, S_IRUSR|S_IWUSR)) < 0) {
        virReportSystemError(errno,
                             _("Unable to pre-create chardev file '%s'"),
                             dev->source->data.file.path);
        return -1;
    }

    VIR_FORCE_CLOSE(fd);

    return 0;
}


static int
qemuProcessCleanupChardevDevice(virDomainDefPtr def ATTRIBUTE_UNUSED,
                                virDomainChrDefPtr dev,
                                void *opaque ATTRIBUTE_UNUSED)
{
    if (dev->source->type == VIR_DOMAIN_CHR_TYPE_UNIX &&
        dev->source->data.nix.listen &&
        dev->source->data.nix.path)
        unlink(dev->source->data.nix.path);

    return 0;
}


/**
 * Loads and update video memory size for video devices according to QEMU
 * process as the QEMU will silently update the values that we pass to QEMU
 * through command line.  We need to load these updated values and store them
 * into the status XML.
 *
 * We will fail if for some reason the values cannot be loaded from QEMU because
 * its mandatory to get the correct video memory size to status XML to not break
 * migration.
 */
static int
qemuProcessUpdateVideoRamSize(virQEMUDriverPtr driver,
                              virDomainObjPtr vm,
                              int asyncJob)
{
    int ret = -1;
    ssize_t i;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virDomainVideoDefPtr video = NULL;
    virQEMUDriverConfigPtr cfg = NULL;

    if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) < 0)
        return -1;

    for (i = 0; i < vm->def->nvideos; i++) {
        video = vm->def->videos[i];

        switch (video->type) {
        case VIR_DOMAIN_VIDEO_TYPE_VGA:
            if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_VGA_VGAMEM)) {
                if (qemuMonitorUpdateVideoMemorySize(priv->mon, video, "VGA") < 0)
                    goto error;
            }
            break;
        case VIR_DOMAIN_VIDEO_TYPE_QXL:
            if (i == 0) {
                if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_QXL_VGAMEM) &&
                    qemuMonitorUpdateVideoMemorySize(priv->mon, video,
                                                     "qxl-vga") < 0)
                        goto error;

                if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_QXL_VRAM64) &&
                    qemuMonitorUpdateVideoVram64Size(priv->mon, video,
                                                     "qxl-vga") < 0)
                    goto error;
            } else {
                if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_QXL_VGAMEM) &&
                    qemuMonitorUpdateVideoMemorySize(priv->mon, video,
                                                     "qxl") < 0)
                        goto error;

                if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_QXL_VRAM64) &&
                    qemuMonitorUpdateVideoVram64Size(priv->mon, video,
                                                     "qxl") < 0)
                        goto error;
            }
            break;
        case VIR_DOMAIN_VIDEO_TYPE_VMVGA:
            if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_VMWARE_SVGA_VGAMEM)) {
                if (qemuMonitorUpdateVideoMemorySize(priv->mon, video,
                                                     "vmware-svga") < 0)
                    goto error;
            }
            break;
        case VIR_DOMAIN_VIDEO_TYPE_CIRRUS:
        case VIR_DOMAIN_VIDEO_TYPE_XEN:
        case VIR_DOMAIN_VIDEO_TYPE_VBOX:
        case VIR_DOMAIN_VIDEO_TYPE_LAST:
            break;
        }

    }

    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        return -1;

    cfg = virQEMUDriverGetConfig(driver);
    ret = virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm, driver->caps);
    virObjectUnref(cfg);

    return ret;

 error:
    ignore_value(qemuDomainObjExitMonitor(driver, vm));
    return -1;
}


struct qemuProcessHookData {
    virDomainObjPtr vm;
    virQEMUDriverPtr driver;
    virQEMUDriverConfigPtr cfg;
};

static int qemuProcessHook(void *data)
{
    struct qemuProcessHookData *h = data;
    qemuDomainObjPrivatePtr priv = h->vm->privateData;
    int ret = -1;
    int fd;
    virBitmapPtr nodeset = NULL;
    virDomainNumatuneMemMode mode;

    /* This method cannot use any mutexes, which are not
     * protected across fork()
     */

    qemuSecurityPostFork(h->driver->securityManager);

    /* Some later calls want pid present */
    h->vm->pid = getpid();

    VIR_DEBUG("Obtaining domain lock");
    /*
     * Since we're going to leak the returned FD to QEMU,
     * we need to make sure it gets a sensible label.
     * This mildly sucks, because there could be other
     * sockets the lock driver opens that we don't want
     * labelled. So far we're ok though.
     */
    if (qemuSecuritySetSocketLabel(h->driver->securityManager, h->vm->def) < 0)
        goto cleanup;
    if (virDomainLockProcessStart(h->driver->lockManager,
                                  h->cfg->uri,
                                  h->vm,
                                  /* QEMU is always paused initially */
                                  true,
                                  &fd) < 0)
        goto cleanup;
    if (qemuSecurityClearSocketLabel(h->driver->securityManager, h->vm->def) < 0)
        goto cleanup;

    if (qemuDomainBuildNamespace(h->cfg, h->driver->securityManager, h->vm) < 0)
        goto cleanup;

    if (virDomainNumatuneGetMode(h->vm->def->numa, -1, &mode) == 0) {
        if (mode == VIR_DOMAIN_NUMATUNE_MEM_STRICT &&
            h->cfg->cgroupControllers & (1 << VIR_CGROUP_CONTROLLER_CPUSET) &&
            virCgroupControllerAvailable(VIR_CGROUP_CONTROLLER_CPUSET)) {
            /* Use virNuma* API iff necessary. Once set and child is exec()-ed,
             * there's no way for us to change it. Rely on cgroups (if available
             * and enabled in the config) rather than virNuma*. */
            VIR_DEBUG("Relying on CGroups for memory binding");
        } else {
            nodeset = virDomainNumatuneGetNodeset(h->vm->def->numa,
                                                  priv->autoNodeset, -1);

            if (virNumaSetupMemoryPolicy(mode, nodeset) < 0)
                goto cleanup;
        }
    }

    ret = 0;

 cleanup:
    virObjectUnref(h->cfg);
    VIR_DEBUG("Hook complete ret=%d", ret);
    return ret;
}

int
qemuProcessPrepareMonitorChr(virDomainChrSourceDefPtr monConfig,
                             const char *domainDir)
{
    monConfig->type = VIR_DOMAIN_CHR_TYPE_UNIX;
    monConfig->data.nix.listen = true;

    if (virAsprintf(&monConfig->data.nix.path, "%s/monitor.sock",
                    domainDir) < 0)
        return -1;
    return 0;
}


/*
 * Precondition: vm must be locked, and a job must be active.
 * This method will call {Enter,Exit}Monitor
 */
int
qemuProcessStartCPUs(virQEMUDriverPtr driver, virDomainObjPtr vm,
                     virDomainRunningReason reason,
                     qemuDomainAsyncJob asyncJob)
{
    int ret = -1;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);

    /* Bring up netdevs before starting CPUs */
    if (qemuInterfaceStartDevices(vm->def) < 0)
       goto cleanup;

    VIR_DEBUG("Using lock state '%s'", NULLSTR(priv->lockState));
    if (virDomainLockProcessResume(driver->lockManager, cfg->uri,
                                   vm, priv->lockState) < 0) {
        /* Don't free priv->lockState on error, because we need
         * to make sure we have state still present if the user
         * tries to resume again
         */
        goto cleanup;
    }
    VIR_FREE(priv->lockState);

    priv->runningReason = reason;

    if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) < 0)
        goto release;

    ret = qemuMonitorStartCPUs(priv->mon);
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        ret = -1;

    if (ret < 0)
        goto release;

    /* The RESUME event handler will change the domain state with the reason
     * saved in priv->runningReason and it will also emit corresponding domain
     * lifecycle event.
     */

 cleanup:
    virObjectUnref(cfg);
    return ret;

 release:
    priv->runningReason = VIR_DOMAIN_RUNNING_UNKNOWN;
    if (virDomainLockProcessPause(driver->lockManager, vm, &priv->lockState) < 0)
        VIR_WARN("Unable to release lease on %s", vm->def->name);
    VIR_DEBUG("Preserving lock state '%s'", NULLSTR(priv->lockState));
    goto cleanup;
}


int qemuProcessStopCPUs(virQEMUDriverPtr driver,
                        virDomainObjPtr vm,
                        virDomainPausedReason reason,
                        qemuDomainAsyncJob asyncJob)
{
    int ret = -1;
    qemuDomainObjPrivatePtr priv = vm->privateData;

    VIR_FREE(priv->lockState);

    priv->pausedReason = reason;

    if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) < 0)
        goto cleanup;

    ret = qemuMonitorStopCPUs(priv->mon);
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        ret = -1;

    if (ret < 0)
        goto cleanup;

    /* de-activate netdevs after stopping CPUs */
    ignore_value(qemuInterfaceStopDevices(vm->def));

    if (priv->job.current)
        ignore_value(virTimeMillisNow(&priv->job.current->stopped));

    /* The STOP event handler will change the domain state with the reason
     * saved in priv->pausedReason and it will also emit corresponding domain
     * lifecycle event.
     */

    if (virDomainLockProcessPause(driver->lockManager, vm, &priv->lockState) < 0)
        VIR_WARN("Unable to release lease on %s", vm->def->name);
    VIR_DEBUG("Preserving lock state '%s'", NULLSTR(priv->lockState));

 cleanup:
    if (ret < 0)
        priv->pausedReason = VIR_DOMAIN_PAUSED_UNKNOWN;

    return ret;
}



static void
qemuProcessNotifyNets(virDomainDefPtr def)
{
    size_t i;
    virConnectPtr conn = NULL;

    for (i = 0; i < def->nnets; i++) {
        virDomainNetDefPtr net = def->nets[i];
        /* keep others from trying to use the macvtap device name, but
         * don't return error if this happens, since that causes the
         * domain to be unceremoniously killed, which would be *very*
         * impolite.
         */
        if (virDomainNetGetActualType(net) == VIR_DOMAIN_NET_TYPE_DIRECT)
           ignore_value(virNetDevMacVLanReserveName(net->ifname, false));

        if (net->type == VIR_DOMAIN_NET_TYPE_NETWORK) {
            if (!conn && !(conn = virGetConnectNetwork()))
                continue;
            virDomainNetNotifyActualDevice(conn, def, net);
        }
    }

    virObjectUnref(conn);
}

/* Attempt to instantiate the filters. Ignore failures because it's
 * possible that someone deleted a filter binding and the associated
 * filter while the guest was running and we don't want that action
 * to cause failure to keep the guest running during the reconnection
 * processing. Nor do we necessarily want other failures to do the
 * same. We'll just log the error conditions other than of course
 * ignoreExists possibility (e.g. the true flag) */
static void
qemuProcessFiltersInstantiate(virDomainDefPtr def)
{
    size_t i;

    for (i = 0; i < def->nnets; i++) {
        virDomainNetDefPtr net = def->nets[i];
        if ((net->filter) && (net->ifname)) {
            if (virDomainConfNWFilterInstantiate(def->name, def->uuid, net,
                                                 true) < 0) {
                VIR_WARN("filter '%s' instantiation for '%s' failed '%s'",
                         net->filter, net->ifname, virGetLastErrorMessage());
                virResetLastError();
            }
        }
    }
}

static int
qemuProcessUpdateState(virQEMUDriverPtr driver, virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virDomainState state;
    virDomainPausedReason reason;
    virDomainState newState = VIR_DOMAIN_NOSTATE;
    int oldReason;
    int newReason;
    bool running;
    char *msg = NULL;
    int ret;

    qemuDomainObjEnterMonitor(driver, vm);
    ret = qemuMonitorGetStatus(priv->mon, &running, &reason);
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        return -1;

    if (ret < 0)
        return -1;

    state = virDomainObjGetState(vm, &oldReason);

    if (running &&
        (state == VIR_DOMAIN_SHUTOFF ||
         (state == VIR_DOMAIN_PAUSED &&
          oldReason == VIR_DOMAIN_PAUSED_STARTING_UP))) {
        newState = VIR_DOMAIN_RUNNING;
        newReason = VIR_DOMAIN_RUNNING_BOOTED;
        ignore_value(VIR_STRDUP_QUIET(msg, "finished booting"));
    } else if (state == VIR_DOMAIN_PAUSED && running) {
        newState = VIR_DOMAIN_RUNNING;
        newReason = VIR_DOMAIN_RUNNING_UNPAUSED;
        ignore_value(VIR_STRDUP_QUIET(msg, "was unpaused"));
    } else if (state == VIR_DOMAIN_RUNNING && !running) {
        if (reason == VIR_DOMAIN_PAUSED_SHUTTING_DOWN) {
            newState = VIR_DOMAIN_SHUTDOWN;
            newReason = VIR_DOMAIN_SHUTDOWN_UNKNOWN;
            ignore_value(VIR_STRDUP_QUIET(msg, "shutdown"));
        } else if (reason == VIR_DOMAIN_PAUSED_CRASHED) {
            newState = VIR_DOMAIN_CRASHED;
            newReason = VIR_DOMAIN_CRASHED_PANICKED;
            ignore_value(VIR_STRDUP_QUIET(msg, "crashed"));
        } else {
            newState = VIR_DOMAIN_PAUSED;
            newReason = reason;
            ignore_value(virAsprintf(&msg, "was paused (%s)",
                                 virDomainPausedReasonTypeToString(reason)));
        }
    }

    if (newState != VIR_DOMAIN_NOSTATE) {
        VIR_DEBUG("Domain %s %s while its monitor was disconnected;"
                  " changing state to %s (%s)",
                  vm->def->name,
                  NULLSTR(msg),
                  virDomainStateTypeToString(newState),
                  virDomainStateReasonToString(newState, newReason));
        VIR_FREE(msg);
        virDomainObjSetState(vm, newState, newReason);
    }

    return 0;
}

static int
qemuProcessRecoverMigrationIn(virQEMUDriverPtr driver,
                              virDomainObjPtr vm,
                              const qemuDomainJobObj *job,
                              virDomainState state,
                              int reason)
{
    bool postcopy = (state == VIR_DOMAIN_PAUSED &&
                     reason == VIR_DOMAIN_PAUSED_POSTCOPY_FAILED) ||
                    (state == VIR_DOMAIN_RUNNING &&
                     reason == VIR_DOMAIN_RUNNING_POSTCOPY);

    switch ((qemuMigrationJobPhase) job->phase) {
    case QEMU_MIGRATION_PHASE_NONE:
    case QEMU_MIGRATION_PHASE_PERFORM2:
    case QEMU_MIGRATION_PHASE_BEGIN3:
    case QEMU_MIGRATION_PHASE_PERFORM3:
    case QEMU_MIGRATION_PHASE_PERFORM3_DONE:
    case QEMU_MIGRATION_PHASE_CONFIRM3_CANCELLED:
    case QEMU_MIGRATION_PHASE_CONFIRM3:
    case QEMU_MIGRATION_PHASE_LAST:
        /* N/A for incoming migration */
        break;

    case QEMU_MIGRATION_PHASE_PREPARE:
        VIR_DEBUG("Killing unfinished incoming migration for domain %s",
                  vm->def->name);
        return -1;

    case QEMU_MIGRATION_PHASE_FINISH2:
        /* source domain is already killed so let's just resume the domain
         * and hope we are all set */
        VIR_DEBUG("Incoming migration finished, resuming domain %s",
                  vm->def->name);
        if (qemuProcessStartCPUs(driver, vm,
                                 VIR_DOMAIN_RUNNING_MIGRATED,
                                 QEMU_ASYNC_JOB_NONE) < 0) {
            VIR_WARN("Could not resume domain %s", vm->def->name);
        }
        break;

    case QEMU_MIGRATION_PHASE_FINISH3:
        /* migration finished, we started resuming the domain but didn't
         * confirm success or failure yet; killing it seems safest unless
         * we already started guest CPUs or we were in post-copy mode */
        if (postcopy) {
            qemuMigrationAnyPostcopyFailed(driver, vm);
        } else if (state != VIR_DOMAIN_RUNNING) {
            VIR_DEBUG("Killing migrated domain %s", vm->def->name);
            return -1;
        }
        break;
    }

    qemuMigrationParamsReset(driver, vm, QEMU_ASYNC_JOB_NONE,
                             job->migParams, job->apiFlags);
    return 0;
}

static int
qemuProcessRecoverMigrationOut(virQEMUDriverPtr driver,
                               virDomainObjPtr vm,
                               const qemuDomainJobObj *job,
                               virDomainState state,
                               int reason,
                               unsigned int *stopFlags)
{
    bool postcopy = state == VIR_DOMAIN_PAUSED &&
                    (reason == VIR_DOMAIN_PAUSED_POSTCOPY ||
                     reason == VIR_DOMAIN_PAUSED_POSTCOPY_FAILED);
    bool resume = false;

    switch ((qemuMigrationJobPhase) job->phase) {
    case QEMU_MIGRATION_PHASE_NONE:
    case QEMU_MIGRATION_PHASE_PREPARE:
    case QEMU_MIGRATION_PHASE_FINISH2:
    case QEMU_MIGRATION_PHASE_FINISH3:
    case QEMU_MIGRATION_PHASE_LAST:
        /* N/A for outgoing migration */
        break;

    case QEMU_MIGRATION_PHASE_BEGIN3:
        /* nothing happened so far, just forget we were about to migrate the
         * domain */
        break;

    case QEMU_MIGRATION_PHASE_PERFORM2:
    case QEMU_MIGRATION_PHASE_PERFORM3:
        /* migration is still in progress, let's cancel it and resume the
         * domain; however we can only do that before migration enters
         * post-copy mode
         */
        if (postcopy) {
            qemuMigrationAnyPostcopyFailed(driver, vm);
        } else {
            VIR_DEBUG("Cancelling unfinished migration of domain %s",
                      vm->def->name);
            if (qemuMigrationSrcCancel(driver, vm) < 0) {
                VIR_WARN("Could not cancel ongoing migration of domain %s",
                         vm->def->name);
            }
            resume = true;
        }
        break;

    case QEMU_MIGRATION_PHASE_PERFORM3_DONE:
        /* migration finished but we didn't have a chance to get the result
         * of Finish3 step; third party needs to check what to do next; in
         * post-copy mode we can use PAUSED_POSTCOPY_FAILED state for this
         */
        if (postcopy)
            qemuMigrationAnyPostcopyFailed(driver, vm);
        break;

    case QEMU_MIGRATION_PHASE_CONFIRM3_CANCELLED:
        /* Finish3 failed, we need to resume the domain, but once we enter
         * post-copy mode there's no way back, so let's just mark the domain
         * as broken in that case
         */
        if (postcopy) {
            qemuMigrationAnyPostcopyFailed(driver, vm);
        } else {
            VIR_DEBUG("Resuming domain %s after failed migration",
                      vm->def->name);
            resume = true;
        }
        break;

    case QEMU_MIGRATION_PHASE_CONFIRM3:
        /* migration completed, we need to kill the domain here */
        *stopFlags |= VIR_QEMU_PROCESS_STOP_MIGRATED;
        return -1;
    }

    if (resume) {
        /* resume the domain but only if it was paused as a result of
         * migration
         */
        if (state == VIR_DOMAIN_PAUSED &&
            (reason == VIR_DOMAIN_PAUSED_MIGRATION ||
             reason == VIR_DOMAIN_PAUSED_UNKNOWN)) {
            if (qemuProcessStartCPUs(driver, vm,
                                     VIR_DOMAIN_RUNNING_MIGRATION_CANCELED,
                                     QEMU_ASYNC_JOB_NONE) < 0) {
                VIR_WARN("Could not resume domain %s", vm->def->name);
            }
        }
    }

    qemuMigrationParamsReset(driver, vm, QEMU_ASYNC_JOB_NONE,
                             job->migParams, job->apiFlags);
    return 0;
}

static int
qemuProcessRecoverJob(virQEMUDriverPtr driver,
                      virDomainObjPtr vm,
                      const qemuDomainJobObj *job,
                      unsigned int *stopFlags)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virDomainState state;
    int reason;

    state = virDomainObjGetState(vm, &reason);

    switch (job->asyncJob) {
    case QEMU_ASYNC_JOB_MIGRATION_OUT:
        if (qemuProcessRecoverMigrationOut(driver, vm, job,
                                           state, reason, stopFlags) < 0)
            return -1;
        break;

    case QEMU_ASYNC_JOB_MIGRATION_IN:
        if (qemuProcessRecoverMigrationIn(driver, vm, job,
                                          state, reason) < 0)
            return -1;
        break;

    case QEMU_ASYNC_JOB_SAVE:
    case QEMU_ASYNC_JOB_DUMP:
    case QEMU_ASYNC_JOB_SNAPSHOT:
        qemuDomainObjEnterMonitor(driver, vm);
        ignore_value(qemuMonitorMigrateCancel(priv->mon));
        if (qemuDomainObjExitMonitor(driver, vm) < 0)
            return -1;
        /* resume the domain but only if it was paused as a result of
         * running a migration-to-file operation.  Although we are
         * recovering an async job, this function is run at startup
         * and must resume things using sync monitor connections.  */
         if (state == VIR_DOMAIN_PAUSED &&
             ((job->asyncJob == QEMU_ASYNC_JOB_DUMP &&
               reason == VIR_DOMAIN_PAUSED_DUMP) ||
              (job->asyncJob == QEMU_ASYNC_JOB_SAVE &&
               reason == VIR_DOMAIN_PAUSED_SAVE) ||
              (job->asyncJob == QEMU_ASYNC_JOB_SNAPSHOT &&
               (reason == VIR_DOMAIN_PAUSED_SNAPSHOT ||
                reason == VIR_DOMAIN_PAUSED_MIGRATION)) ||
              reason == VIR_DOMAIN_PAUSED_UNKNOWN)) {
             if (qemuProcessStartCPUs(driver, vm,
                                      VIR_DOMAIN_RUNNING_SAVE_CANCELED,
                                      QEMU_ASYNC_JOB_NONE) < 0) {
                 VIR_WARN("Could not resume domain '%s' after migration to file",
                          vm->def->name);
            }
        }
        break;

    case QEMU_ASYNC_JOB_START:
        /* Already handled in VIR_DOMAIN_PAUSED_STARTING_UP check. */
        break;

    case QEMU_ASYNC_JOB_NONE:
    case QEMU_ASYNC_JOB_LAST:
        break;
    }

    if (!virDomainObjIsActive(vm))
        return -1;

    /* In case any special handling is added for job type that has been ignored
     * before, QEMU_DOMAIN_TRACK_JOBS (from qemu_domain.h) needs to be updated
     * for the job to be properly tracked in domain state XML.
     */
    switch (job->active) {
    case QEMU_JOB_QUERY:
        /* harmless */
        break;

    case QEMU_JOB_DESTROY:
        VIR_DEBUG("Domain %s should have already been destroyed",
                  vm->def->name);
        return -1;

    case QEMU_JOB_SUSPEND:
        /* mostly harmless */
        break;

    case QEMU_JOB_MODIFY:
        /* XXX depending on the command we may be in an inconsistent state and
         * we should probably fall back to "monitor error" state and refuse to
         */
        break;

    case QEMU_JOB_MIGRATION_OP:
    case QEMU_JOB_ABORT:
    case QEMU_JOB_ASYNC:
    case QEMU_JOB_ASYNC_NESTED:
        /* async job was already handled above */
    case QEMU_JOB_NONE:
    case QEMU_JOB_LAST:
        break;
    }

    return 0;
}

static int
qemuProcessUpdateDevices(virQEMUDriverPtr driver,
                         virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virDomainDeviceDef dev;
    const char **qemuDevices;
    char **old;
    char **tmp;
    int ret = -1;

    old = priv->qemuDevices;
    priv->qemuDevices = NULL;
    if (qemuDomainUpdateDeviceList(driver, vm, QEMU_ASYNC_JOB_NONE) < 0)
        goto cleanup;

    qemuDevices = (const char **)priv->qemuDevices;
    if ((tmp = old)) {
        while (*tmp) {
            if (!virStringListHasString(qemuDevices, *tmp) &&
                virDomainDefFindDevice(vm->def, *tmp, &dev, false) == 0 &&
                qemuDomainRemoveDevice(driver, vm, &dev) < 0) {
                goto cleanup;
            }
            tmp++;
        }
    }
    ret = 0;

 cleanup:
    virStringListFree(old);
    return ret;
}

static int
qemuDomainPerfRestart(virDomainObjPtr vm)
{
    size_t i;
    virDomainDefPtr def = vm->def;
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (!(priv->perf = virPerfNew()))
        return -1;

    for (i = 0; i < VIR_PERF_EVENT_LAST; i++) {
        if (def->perf.events[i] &&
            def->perf.events[i] == VIR_TRISTATE_BOOL_YES) {

            /* Failure to re-enable the perf event should not be fatal */
            if (virPerfEventEnable(priv->perf, i, vm->pid) < 0)
                def->perf.events[i] = VIR_TRISTATE_BOOL_NO;
        }
    }

    return 0;
}


static void
qemuProcessReconnectCheckMemAliasOrderMismatch(virDomainObjPtr vm)
{
    size_t i;
    int aliasidx;
    virDomainDefPtr def = vm->def;
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (!virDomainDefHasMemoryHotplug(def) || def->nmems == 0)
        return;

    for (i = 0; i < def->nmems; i++) {
        aliasidx = qemuDomainDeviceAliasIndex(&def->mems[i]->info, "dimm");

        if (def->mems[i]->info.addr.dimm.slot != aliasidx) {
            priv->memAliasOrderMismatch = true;
            break;
        }
    }
}


static bool
qemuProcessNeedHugepagesPath(virDomainDefPtr def,
                             virDomainMemoryDefPtr mem)
{
    const long system_pagesize = virGetSystemPageSizeKB();
    size_t i;

    if (def->mem.source == VIR_DOMAIN_MEMORY_SOURCE_FILE)
        return true;

    for (i = 0; i < def->mem.nhugepages; i++) {
        if (def->mem.hugepages[i].size != system_pagesize)
            return true;
    }

    for (i = 0; i < def->nmems; i++) {
        if (def->mems[i]->model == VIR_DOMAIN_MEMORY_MODEL_DIMM &&
            def->mems[i]->pagesize &&
            def->mems[i]->pagesize != system_pagesize)
            return true;
    }

    if (mem &&
        mem->model == VIR_DOMAIN_MEMORY_MODEL_DIMM &&
        mem->pagesize &&
        mem->pagesize != system_pagesize)
        return true;

    return false;
}


static bool
qemuProcessNeedMemoryBackingPath(virDomainDefPtr def,
                                 virDomainMemoryDefPtr mem)
{
    size_t i;
    size_t numaNodes;

    if (def->mem.source == VIR_DOMAIN_MEMORY_SOURCE_FILE ||
        def->mem.access != VIR_DOMAIN_MEMORY_ACCESS_DEFAULT)
        return true;

    numaNodes = virDomainNumaGetNodeCount(def->numa);
    for (i = 0; i < numaNodes; i++) {
        if (virDomainNumaGetNodeMemoryAccessMode(def->numa, i)
            != VIR_DOMAIN_MEMORY_ACCESS_DEFAULT)
            return true;
    }

    if (mem &&
        mem->model == VIR_DOMAIN_MEMORY_MODEL_DIMM &&
        (mem->access != VIR_DOMAIN_MEMORY_ACCESS_DEFAULT ||
         (mem->targetNode >= 0 &&
          virDomainNumaGetNodeMemoryAccessMode(def->numa, mem->targetNode)
          != VIR_DOMAIN_MEMORY_ACCESS_DEFAULT)))
        return true;

    return false;
}


static int
qemuProcessBuildDestroyMemoryPathsImpl(virQEMUDriverPtr driver,
                                       virDomainObjPtr vm,
                                       const char *path,
                                       bool build)
{
    if (build) {
        if (virFileExists(path))
            return 0;

        if (virFileMakePathWithMode(path, 0700) < 0) {
            virReportSystemError(errno,
                                 _("Unable to create %s"),
                                 path);
            return -1;
        }

        if (qemuSecurityDomainSetPathLabel(driver, vm, path, true) < 0)
            return -1;
    } else {
        if (virFileDeleteTree(path) < 0)
            return -1;
    }

    return 0;
}


int
qemuProcessBuildDestroyMemoryPaths(virQEMUDriverPtr driver,
                                   virDomainObjPtr vm,
                                   virDomainMemoryDefPtr mem,
                                   bool build)
{
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    char *path = NULL;
    size_t i;
    bool shouldBuildHP = false;
    bool shouldBuildMB = false;
    int ret = -1;

    if (build) {
        shouldBuildHP = qemuProcessNeedHugepagesPath(vm->def, mem);
        shouldBuildMB = qemuProcessNeedMemoryBackingPath(vm->def, mem);
    }

    if (!build || shouldBuildHP) {
        for (i = 0; i < cfg->nhugetlbfs; i++) {
            path = qemuGetDomainHugepagePath(vm->def, &cfg->hugetlbfs[i]);

            if (!path)
                goto cleanup;

            if (qemuProcessBuildDestroyMemoryPathsImpl(driver, vm,
                                                       path, build) < 0)
                goto cleanup;

            VIR_FREE(path);
        }
    }

    if (!build || shouldBuildMB) {
        if (qemuGetMemoryBackingDomainPath(vm->def, cfg, &path) < 0)
            goto cleanup;

        if (qemuProcessBuildDestroyMemoryPathsImpl(driver, vm,
                                                   path, build) < 0)
            goto cleanup;

        VIR_FREE(path);
    }

    ret = 0;
 cleanup:
    VIR_FREE(path);
    virObjectUnref(cfg);
    return ret;
}


int
qemuProcessDestroyMemoryBackingPath(virQEMUDriverPtr driver,
                                    virDomainObjPtr vm,
                                    virDomainMemoryDefPtr mem)
{
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    char *path = NULL;
    int ret = -1;

    if (qemuGetMemoryBackingPath(vm->def, cfg, mem->info.alias, &path) < 0)
        goto cleanup;

    if (unlink(path) < 0 &&
        errno != ENOENT) {
        virReportSystemError(errno, _("Unable to remove %s"), path);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FREE(path);
    virObjectUnref(cfg);
    return ret;
}


static int
qemuProcessVNCAllocatePorts(virQEMUDriverPtr driver,
                            virDomainGraphicsDefPtr graphics,
                            bool allocate)
{
    unsigned short port;

    if (!allocate) {
        if (graphics->data.vnc.autoport)
            graphics->data.vnc.port = 5900;

        return 0;
    }

    if (graphics->data.vnc.autoport) {
        if (virPortAllocatorAcquire(driver->remotePorts, &port) < 0)
            return -1;
        graphics->data.vnc.port = port;
    }

    if (graphics->data.vnc.websocket == -1) {
        if (virPortAllocatorAcquire(driver->webSocketPorts, &port) < 0)
            return -1;
        graphics->data.vnc.websocket = port;
        graphics->data.vnc.websocketGenerated = true;
    }

    return 0;
}

static int
qemuProcessSPICEAllocatePorts(virQEMUDriverPtr driver,
                              virDomainGraphicsDefPtr graphics,
                              bool allocate)
{
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    unsigned short port = 0;
    unsigned short tlsPort;
    size_t i;
    int defaultMode = graphics->data.spice.defaultMode;
    int ret = -1;

    bool needTLSPort = false;
    bool needPort = false;

    if (graphics->data.spice.autoport) {
        /* check if tlsPort or port need allocation */
        for (i = 0; i < VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_LAST; i++) {
            switch (graphics->data.spice.channels[i]) {
            case VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_MODE_SECURE:
                needTLSPort = true;
                break;

            case VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_MODE_INSECURE:
                needPort = true;
                break;

            case VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_MODE_ANY:
                /* default mode will be used */
                break;
            }
        }
        switch (defaultMode) {
        case VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_MODE_SECURE:
            needTLSPort = true;
            break;

        case VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_MODE_INSECURE:
            needPort = true;
            break;

        case VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_MODE_ANY:
            if (cfg->spiceTLS)
                needTLSPort = true;
            needPort = true;
            break;
        }
    }

    if (!allocate) {
        if (needPort || graphics->data.spice.port == -1)
            graphics->data.spice.port = 5901;

        if (needTLSPort || graphics->data.spice.tlsPort == -1)
            graphics->data.spice.tlsPort = 5902;

        ret = 0;
        goto cleanup;
    }

    if (needPort || graphics->data.spice.port == -1) {
        if (virPortAllocatorAcquire(driver->remotePorts, &port) < 0)
            goto cleanup;

        graphics->data.spice.port = port;

        if (!graphics->data.spice.autoport)
            graphics->data.spice.portReserved = true;
    }

    if (needTLSPort || graphics->data.spice.tlsPort == -1) {
        if (!cfg->spiceTLS) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Auto allocation of spice TLS port requested "
                             "but spice TLS is disabled in qemu.conf"));
            goto cleanup;
        }

        if (virPortAllocatorAcquire(driver->remotePorts, &tlsPort) < 0)
            goto cleanup;

        graphics->data.spice.tlsPort = tlsPort;

        if (!graphics->data.spice.autoport)
            graphics->data.spice.tlsPortReserved = true;
    }

    ret = 0;

 cleanup:
    virObjectUnref(cfg);
    return ret;
}


static int
qemuProcessVerifyHypervFeatures(virDomainDefPtr def,
                                virCPUDataPtr cpu)
{
    char *cpuFeature;
    size_t i;
    int rc;

    for (i = 0; i < VIR_DOMAIN_HYPERV_LAST; i++) {
        /* always supported string property */
        if (i == VIR_DOMAIN_HYPERV_VENDOR_ID)
            continue;

        if (def->hyperv_features[i] != VIR_TRISTATE_SWITCH_ON)
            continue;

        if (virAsprintf(&cpuFeature, "__kvm_hv_%s",
                        virDomainHypervTypeToString(i)) < 0)
            return -1;

        rc = virCPUDataCheckFeature(cpu, cpuFeature);
        VIR_FREE(cpuFeature);

        if (rc < 0)
            return -1;
        else if (rc == 1)
            continue;

        switch ((virDomainHyperv) i) {
        case VIR_DOMAIN_HYPERV_RELAXED:
        case VIR_DOMAIN_HYPERV_VAPIC:
        case VIR_DOMAIN_HYPERV_SPINLOCKS:
            VIR_WARN("host doesn't support hyperv '%s' feature",
                     virDomainHypervTypeToString(i));
            break;

        case VIR_DOMAIN_HYPERV_VPINDEX:
        case VIR_DOMAIN_HYPERV_RUNTIME:
        case VIR_DOMAIN_HYPERV_SYNIC:
        case VIR_DOMAIN_HYPERV_STIMER:
        case VIR_DOMAIN_HYPERV_RESET:
        case VIR_DOMAIN_HYPERV_FREQUENCIES:
        case VIR_DOMAIN_HYPERV_REENLIGHTENMENT:
        case VIR_DOMAIN_HYPERV_TLBFLUSH:
        case VIR_DOMAIN_HYPERV_IPI:
        case VIR_DOMAIN_HYPERV_EVMCS:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("host doesn't support hyperv '%s' feature"),
                           virDomainHypervTypeToString(i));
            return -1;

        /* coverity[dead_error_begin] */
        case VIR_DOMAIN_HYPERV_VENDOR_ID:
        case VIR_DOMAIN_HYPERV_LAST:
            break;
        }
    }

    return 0;
}


static int
qemuProcessVerifyKVMFeatures(virDomainDefPtr def,
                             virCPUDataPtr cpu)
{
    int rc = 0;

    if (def->features[VIR_DOMAIN_FEATURE_PVSPINLOCK] != VIR_TRISTATE_SWITCH_ON)
        return 0;

    rc = virCPUDataCheckFeature(cpu, VIR_CPU_x86_KVM_PV_UNHALT);

    if (rc <= 0) {
        if (rc == 0)
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("host doesn't support paravirtual spinlocks"));
        return -1;
    }

    return 0;
}


static int
qemuProcessVerifyCPUFeatures(virDomainDefPtr def,
                             virCPUDataPtr cpu)
{
    int rc;

    rc = virCPUCheckFeature(def->os.arch, def->cpu, "invtsc");

    if (rc < 0) {
        return -1;
    } else if (rc == 1) {
        rc = virCPUDataCheckFeature(cpu, "invtsc");
        if (rc <= 0) {
            if (rc == 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("host doesn't support invariant TSC"));
            }
            return -1;
        }
    }

    return 0;
}


static const char *
qemuProcessTranslateCPUFeatures(const char *name,
                                void *opaque)
{
    virQEMUCapsPtr qemuCaps = opaque;

    return virQEMUCapsCPUFeatureFromQEMU(qemuCaps, name);
}


static int
qemuProcessFetchGuestCPU(virQEMUDriverPtr driver,
                         virDomainObjPtr vm,
                         qemuDomainAsyncJob asyncJob,
                         virCPUDataPtr *enabled,
                         virCPUDataPtr *disabled)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virCPUDataPtr dataEnabled = NULL;
    virCPUDataPtr dataDisabled = NULL;
    bool generic;
    int rc;

    *enabled = NULL;
    *disabled = NULL;

    generic = virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_CPU_UNAVAILABLE_FEATURES);

    if (!generic && !ARCH_IS_X86(vm->def->os.arch))
        return 0;

    if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) < 0)
        goto error;

    if (generic) {
        rc = qemuMonitorGetGuestCPU(priv->mon,
                                    vm->def->os.arch,
                                    qemuProcessTranslateCPUFeatures, priv->qemuCaps,
                                    &dataEnabled, &dataDisabled);
    } else {
        rc = qemuMonitorGetGuestCPUx86(priv->mon, &dataEnabled, &dataDisabled);
    }

    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        goto error;

    if (rc == -1)
        goto error;

    *enabled = dataEnabled;
    *disabled = dataDisabled;
    return 0;

 error:
    virCPUDataFree(dataEnabled);
    virCPUDataFree(dataDisabled);
    return -1;
}


static int
qemuProcessVerifyCPU(virDomainObjPtr vm,
                     virCPUDataPtr cpu)
{
    virDomainDefPtr def = vm->def;

    if (!cpu)
        return 0;

    if (qemuProcessVerifyKVMFeatures(def, cpu) < 0 ||
        qemuProcessVerifyHypervFeatures(def, cpu) < 0)
        return -1;

    if (!def->cpu ||
        (def->cpu->mode == VIR_CPU_MODE_CUSTOM &&
         !def->cpu->model))
        return 0;

    if (qemuProcessVerifyCPUFeatures(def, cpu) < 0)
        return -1;

    return 0;
}


static int
qemuProcessUpdateLiveGuestCPU(virDomainObjPtr vm,
                              virCPUDataPtr enabled,
                              virCPUDataPtr disabled)
{
    virDomainDefPtr def = vm->def;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virCPUDefPtr orig = NULL;
    int rc;
    int ret = -1;

    if (!enabled)
        return 0;

    if (!def->cpu ||
        (def->cpu->mode == VIR_CPU_MODE_CUSTOM &&
         !def->cpu->model))
        return 0;

    if (!(orig = virCPUDefCopy(def->cpu)))
        goto cleanup;

    if ((rc = virCPUUpdateLive(def->os.arch, def->cpu, enabled, disabled)) < 0) {
        goto cleanup;
    } else if (rc == 0) {
        /* Store the original CPU in priv if QEMU changed it and we didn't
         * get the original CPU via migration, restore, or snapshot revert.
         */
        if (!priv->origCPU && !virCPUDefIsEqual(def->cpu, orig, false))
            VIR_STEAL_PTR(priv->origCPU, orig);

        def->cpu->check = VIR_CPU_CHECK_FULL;
    }

    ret = 0;

 cleanup:
    virCPUDefFree(orig);
    return ret;
}


static int
qemuProcessUpdateAndVerifyCPU(virQEMUDriverPtr driver,
                              virDomainObjPtr vm,
                              qemuDomainAsyncJob asyncJob)
{
    virCPUDataPtr cpu = NULL;
    virCPUDataPtr disabled = NULL;
    int ret = -1;

    if (qemuProcessFetchGuestCPU(driver, vm, asyncJob, &cpu, &disabled) < 0)
        goto cleanup;

    if (qemuProcessVerifyCPU(vm, cpu) < 0)
        goto cleanup;

    if (qemuProcessUpdateLiveGuestCPU(vm, cpu, disabled) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virCPUDataFree(cpu);
    virCPUDataFree(disabled);
    return ret;
}


static virDomainCapsCPUModelsPtr
qemuProcessFetchCPUDefinitions(virQEMUDriverPtr driver,
                               virDomainObjPtr vm,
                               qemuDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virDomainCapsCPUModelsPtr models = NULL;

    if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) < 0)
        goto error;

    models = virQEMUCapsFetchCPUDefinitions(priv->mon);

    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        goto error;

    return models;

 error:
    virObjectUnref(models);
    return NULL;
}


static int
qemuProcessUpdateCPU(virQEMUDriverPtr driver,
                     virDomainObjPtr vm,
                     qemuDomainAsyncJob asyncJob)
{
    virCPUDataPtr cpu = NULL;
    virCPUDataPtr disabled = NULL;
    virDomainCapsCPUModelsPtr models = NULL;
    int ret = -1;

    /* The host CPU model comes from host caps rather than QEMU caps so
     * fallback must be allowed no matter what the user specified in the XML.
     */
    vm->def->cpu->fallback = VIR_CPU_FALLBACK_ALLOW;

    if (qemuProcessFetchGuestCPU(driver, vm, asyncJob, &cpu, &disabled) < 0)
        goto cleanup;

    if (qemuProcessUpdateLiveGuestCPU(vm, cpu, disabled) < 0)
        goto cleanup;

    if (!(models = qemuProcessFetchCPUDefinitions(driver, vm, asyncJob)) ||
        virCPUTranslate(vm->def->os.arch, vm->def->cpu, models) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virCPUDataFree(cpu);
    virCPUDataFree(disabled);
    virObjectUnref(models);
    return ret;
}


static int
qemuPrepareNVRAM(virQEMUDriverConfigPtr cfg,
                 virDomainObjPtr vm)
{
    int ret = -1;
    int srcFD = -1;
    int dstFD = -1;
    virDomainLoaderDefPtr loader = vm->def->os.loader;
    bool created = false;
    const char *master_nvram_path;
    ssize_t r;

    if (!loader || !loader->nvram || virFileExists(loader->nvram))
        return 0;

    master_nvram_path = loader->templt;
    if (!loader->templt) {
        size_t i;
        for (i = 0; i < cfg->nfirmwares; i++) {
            if (STREQ(cfg->firmwares[i]->name, loader->path)) {
                master_nvram_path = cfg->firmwares[i]->nvram;
                break;
            }
        }
    }

    if (!master_nvram_path) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("unable to find any master var store for "
                         "loader: %s"), loader->path);
        goto cleanup;
    }

    if ((srcFD = virFileOpenAs(master_nvram_path, O_RDONLY,
                               0, -1, -1, 0)) < 0) {
        virReportSystemError(-srcFD,
                             _("Failed to open file '%s'"),
                             master_nvram_path);
        goto cleanup;
    }
    if ((dstFD = virFileOpenAs(loader->nvram,
                               O_WRONLY | O_CREAT | O_EXCL,
                               S_IRUSR | S_IWUSR,
                               cfg->user, cfg->group, 0)) < 0) {
        virReportSystemError(-dstFD,
                             _("Failed to create file '%s'"),
                             loader->nvram);
        goto cleanup;
    }
    created = true;

    do {
        char buf[1024];

        if ((r = saferead(srcFD, buf, sizeof(buf))) < 0) {
            virReportSystemError(errno,
                                 _("Unable to read from file '%s'"),
                                 master_nvram_path);
            goto cleanup;
        }

        if (safewrite(dstFD, buf, r) < 0) {
            virReportSystemError(errno,
                                 _("Unable to write to file '%s'"),
                                 loader->nvram);
            goto cleanup;
        }
    } while (r);

    if (VIR_CLOSE(srcFD) < 0) {
        virReportSystemError(errno,
                             _("Unable to close file '%s'"),
                             master_nvram_path);
        goto cleanup;
    }
    if (VIR_CLOSE(dstFD) < 0) {
        virReportSystemError(errno,
                             _("Unable to close file '%s'"),
                             loader->nvram);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    /* We successfully generated the nvram path, but failed to
     * copy the file content. Roll back. */
    if (ret < 0) {
        if (created)
            unlink(loader->nvram);
    }

    VIR_FORCE_CLOSE(srcFD);
    VIR_FORCE_CLOSE(dstFD);
    return ret;
}


static void
qemuLogOperation(virDomainObjPtr vm,
                 const char *msg,
                 virCommandPtr cmd,
                 qemuDomainLogContextPtr logCtxt)
{
    char *timestamp;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int qemuVersion = virQEMUCapsGetVersion(priv->qemuCaps);
    const char *package = virQEMUCapsGetPackage(priv->qemuCaps);
    char *hostname = virGetHostname();
    struct utsname uts;

    uname(&uts);

    if ((timestamp = virTimeStringNow()) == NULL)
        goto cleanup;

    if (qemuDomainLogContextWrite(logCtxt,
                                  "%s: %s %s, qemu version: %d.%d.%d%s, kernel: %s, hostname: %s\n",
                                  timestamp, msg, VIR_LOG_VERSION_STRING,
                                  (qemuVersion / 1000000) % 1000,
                                  (qemuVersion / 1000) % 1000,
                                  qemuVersion % 1000,
                                  NULLSTR_EMPTY(package),
                                  uts.release,
                                  NULLSTR_EMPTY(hostname)) < 0)
        goto cleanup;

    if (cmd) {
        char *args = virCommandToString(cmd, true);
        qemuDomainLogContextWrite(logCtxt, "%s\n", args);
        VIR_FREE(args);
    }

 cleanup:
    VIR_FREE(hostname);
    VIR_FREE(timestamp);
}


void
qemuProcessIncomingDefFree(qemuProcessIncomingDefPtr inc)
{
    if (!inc)
        return;

    VIR_FREE(inc->address);
    VIR_FREE(inc->launchURI);
    VIR_FREE(inc->deferredURI);
    VIR_FREE(inc);
}


/*
 * This function does not copy @path, the caller is responsible for keeping
 * the @path pointer valid during the lifetime of the allocated
 * qemuProcessIncomingDef structure.
 *
 * The caller is responsible for closing @fd, calling
 * qemuProcessIncomingDefFree will NOT close it.
 */
qemuProcessIncomingDefPtr
qemuProcessIncomingDefNew(virQEMUCapsPtr qemuCaps,
                          const char *listenAddress,
                          const char *migrateFrom,
                          int fd,
                          const char *path)
{
    qemuProcessIncomingDefPtr inc = NULL;

    if (qemuMigrationDstCheckProtocol(qemuCaps, migrateFrom) < 0)
        return NULL;

    if (VIR_ALLOC(inc) < 0)
        return NULL;

    if (VIR_STRDUP(inc->address, listenAddress) < 0)
        goto error;

    inc->launchURI = qemuMigrationDstGetURI(migrateFrom, fd);
    if (!inc->launchURI)
        goto error;

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_INCOMING_DEFER)) {
        inc->deferredURI = inc->launchURI;
        if (VIR_STRDUP(inc->launchURI, "defer") < 0)
            goto error;
    }

    inc->fd = fd;
    inc->path = path;

    return inc;

 error:
    qemuProcessIncomingDefFree(inc);
    return NULL;
}


/*
 * This function starts a new QEMU_ASYNC_JOB_START async job. The user is
 * responsible for calling qemuProcessEndJob to stop this job and for passing
 * QEMU_ASYNC_JOB_START as @asyncJob argument to any function requiring this
 * parameter between qemuProcessBeginJob and qemuProcessEndJob.
 */
int
qemuProcessBeginJob(virQEMUDriverPtr driver,
                    virDomainObjPtr vm,
                    virDomainJobOperation operation,
                    unsigned long apiFlags)
{
    if (qemuDomainObjBeginAsyncJob(driver, vm, QEMU_ASYNC_JOB_START,
                                   operation, apiFlags) < 0)
        return -1;

    qemuDomainObjSetAsyncJobMask(vm, QEMU_JOB_NONE);
    return 0;
}


void
qemuProcessEndJob(virQEMUDriverPtr driver,
                  virDomainObjPtr vm)
{
    qemuDomainObjEndAsyncJob(driver, vm);
}


static int
qemuProcessStartHook(virQEMUDriverPtr driver,
                     virDomainObjPtr vm,
                     virHookQemuOpType op,
                     virHookSubopType subop)
{
    char *xml;
    int ret;

    if (!virHookPresent(VIR_HOOK_DRIVER_QEMU))
        return 0;

    if (!(xml = qemuDomainDefFormatXML(driver, vm->def, 0)))
        return -1;

    ret = virHookCall(VIR_HOOK_DRIVER_QEMU, vm->def->name, op, subop,
                      NULL, xml, NULL);
    VIR_FREE(xml);

    return ret;
}


static int
qemuProcessGraphicsReservePorts(virDomainGraphicsDefPtr graphics,
                                bool reconnect)
{
    virDomainGraphicsListenDefPtr glisten;

    if (graphics->nListens <= 0)
        return 0;

    glisten = &graphics->listens[0];

    if (glisten->type != VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_ADDRESS &&
        glisten->type != VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_NETWORK)
        return 0;

    switch (graphics->type) {
    case VIR_DOMAIN_GRAPHICS_TYPE_VNC:
        if (!graphics->data.vnc.autoport ||
            reconnect) {
            if (virPortAllocatorSetUsed(graphics->data.vnc.port) < 0)
                return -1;
            graphics->data.vnc.portReserved = true;
        }
        if (graphics->data.vnc.websocket > 0 &&
            virPortAllocatorSetUsed(graphics->data.vnc.websocket) < 0)
            return -1;
        break;

    case VIR_DOMAIN_GRAPHICS_TYPE_SPICE:
        if (graphics->data.spice.autoport && !reconnect)
            return 0;

        if (graphics->data.spice.port > 0) {
            if (virPortAllocatorSetUsed(graphics->data.spice.port) < 0)
                return -1;
            graphics->data.spice.portReserved = true;
        }

        if (graphics->data.spice.tlsPort > 0) {
            if (virPortAllocatorSetUsed(graphics->data.spice.tlsPort) < 0)
                return -1;
            graphics->data.spice.tlsPortReserved = true;
        }
        break;

    case VIR_DOMAIN_GRAPHICS_TYPE_SDL:
    case VIR_DOMAIN_GRAPHICS_TYPE_RDP:
    case VIR_DOMAIN_GRAPHICS_TYPE_DESKTOP:
    case VIR_DOMAIN_GRAPHICS_TYPE_EGL_HEADLESS:
    case VIR_DOMAIN_GRAPHICS_TYPE_LAST:
        break;
    }

    return 0;
}


static int
qemuProcessGraphicsAllocatePorts(virQEMUDriverPtr driver,
                                 virDomainGraphicsDefPtr graphics,
                                 bool allocate)
{
    virDomainGraphicsListenDefPtr glisten;

    if (graphics->nListens <= 0)
        return 0;

    glisten = &graphics->listens[0];

    if (glisten->type != VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_ADDRESS &&
        glisten->type != VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_NETWORK)
        return 0;

    switch (graphics->type) {
    case VIR_DOMAIN_GRAPHICS_TYPE_VNC:
        if (qemuProcessVNCAllocatePorts(driver, graphics, allocate) < 0)
            return -1;
        break;

    case VIR_DOMAIN_GRAPHICS_TYPE_SPICE:
        if (qemuProcessSPICEAllocatePorts(driver, graphics, allocate) < 0)
            return -1;
        break;

    case VIR_DOMAIN_GRAPHICS_TYPE_SDL:
    case VIR_DOMAIN_GRAPHICS_TYPE_RDP:
    case VIR_DOMAIN_GRAPHICS_TYPE_DESKTOP:
    case VIR_DOMAIN_GRAPHICS_TYPE_EGL_HEADLESS:
    case VIR_DOMAIN_GRAPHICS_TYPE_LAST:
        break;
    }

    return 0;
}

static int
qemuProcessGetNetworkAddress(const char *netname,
                             char **netaddr)
{
    virConnectPtr conn = NULL;
    int ret = -1;
    virNetworkPtr net;
    virNetworkDefPtr netdef = NULL;
    virNetworkIPDefPtr ipdef;
    virSocketAddr addr;
    virSocketAddrPtr addrptr = NULL;
    char *dev_name = NULL;
    char *xml = NULL;

    *netaddr = NULL;

    if (!(conn = virGetConnectNetwork()))
        return -1;

    net = virNetworkLookupByName(conn, netname);
    if (!net)
        goto cleanup;

    xml = virNetworkGetXMLDesc(net, 0);
    if (!xml)
        goto cleanup;

    netdef = virNetworkDefParseString(xml);
    if (!netdef)
        goto cleanup;

    switch ((virNetworkForwardType) netdef->forward.type) {
    case VIR_NETWORK_FORWARD_NONE:
    case VIR_NETWORK_FORWARD_NAT:
    case VIR_NETWORK_FORWARD_ROUTE:
    case VIR_NETWORK_FORWARD_OPEN:
        ipdef = virNetworkDefGetIPByIndex(netdef, AF_UNSPEC, 0);
        if (!ipdef) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("network '%s' doesn't have an IP address"),
                           netdef->name);
            goto cleanup;
        }
        addrptr = &ipdef->address;
        break;

    case VIR_NETWORK_FORWARD_BRIDGE:
        if ((dev_name = netdef->bridge))
            break;
        /*
         * fall through if netdef->bridge wasn't set, since that is
         * macvtap bridge mode network.
         */
        ATTRIBUTE_FALLTHROUGH;

    case VIR_NETWORK_FORWARD_PRIVATE:
    case VIR_NETWORK_FORWARD_VEPA:
    case VIR_NETWORK_FORWARD_PASSTHROUGH:
        if ((netdef->forward.nifs > 0) && netdef->forward.ifs)
            dev_name = netdef->forward.ifs[0].device.dev;

        if (!dev_name) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("network '%s' has no associated interface or bridge"),
                           netdef->name);
            goto cleanup;
        }
        break;

    case VIR_NETWORK_FORWARD_HOSTDEV:
        break;

    case VIR_NETWORK_FORWARD_LAST:
    default:
        virReportEnumRangeError(virNetworkForwardType, netdef->forward.type);
        goto cleanup;
    }

    if (dev_name) {
        if (virNetDevIPAddrGet(dev_name, &addr) < 0)
            goto cleanup;
        addrptr = &addr;
    }

    if (!(addrptr &&
          (*netaddr = virSocketAddrFormat(addrptr)))) {
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virNetworkDefFree(netdef);
    virObjectUnref(net);
    virObjectUnref(conn);
    VIR_FREE(xml);
    return ret;
}


static int
qemuProcessGraphicsSetupNetworkAddress(virDomainGraphicsListenDefPtr glisten,
                                       const char *listenAddr)
{
    int rc;

    /* TODO: reject configuration without network specified for network listen */
    if (!glisten->network) {
        if (VIR_STRDUP(glisten->address, listenAddr) < 0)
            return -1;
        return 0;
    }

    rc = qemuProcessGetNetworkAddress(glisten->network, &glisten->address);
    if (rc <= -2) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("network-based listen isn't possible, "
                         "network driver isn't present"));
        return -1;
    }
    if (rc < 0)
        return -1;

    return 0;
}


static int
qemuProcessGraphicsSetupListen(virQEMUDriverPtr driver,
                               virDomainGraphicsDefPtr graphics,
                               virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    const char *type = virDomainGraphicsTypeToString(graphics->type);
    char *listenAddr = NULL;
    bool useSocket = false;
    size_t i;
    int ret = -1;

    switch (graphics->type) {
    case VIR_DOMAIN_GRAPHICS_TYPE_VNC:
        useSocket = cfg->vncAutoUnixSocket;
        listenAddr = cfg->vncListen;
        break;

    case VIR_DOMAIN_GRAPHICS_TYPE_SPICE:
        useSocket = cfg->spiceAutoUnixSocket;
        listenAddr = cfg->spiceListen;
        break;

    case VIR_DOMAIN_GRAPHICS_TYPE_SDL:
    case VIR_DOMAIN_GRAPHICS_TYPE_RDP:
    case VIR_DOMAIN_GRAPHICS_TYPE_DESKTOP:
    case VIR_DOMAIN_GRAPHICS_TYPE_EGL_HEADLESS:
    case VIR_DOMAIN_GRAPHICS_TYPE_LAST:
        break;
    }

    for (i = 0; i < graphics->nListens; i++) {
        virDomainGraphicsListenDefPtr glisten = &graphics->listens[i];

        switch (glisten->type) {
        case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_ADDRESS:
            if (!glisten->address) {
                /* If there is no address specified and qemu.conf has
                 * *_auto_unix_socket set we should use unix socket as
                 * default instead of tcp listen. */
                if (useSocket) {
                    memset(glisten, 0, sizeof(virDomainGraphicsListenDef));
                    if (virAsprintf(&glisten->socket, "%s/%s.sock",
                                    priv->libDir, type) < 0)
                        goto cleanup;
                    glisten->fromConfig = true;
                    glisten->type = VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_SOCKET;
                } else if (listenAddr) {
                    if (VIR_STRDUP(glisten->address, listenAddr) < 0)
                        goto cleanup;
                    glisten->fromConfig = true;
                }
            }
            break;

        case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_NETWORK:
            if (glisten->address || !listenAddr)
                continue;

            if (qemuProcessGraphicsSetupNetworkAddress(glisten,
                                                       listenAddr) < 0)
                goto cleanup;
            break;

        case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_SOCKET:
            if (!glisten->socket) {
                if (virAsprintf(&glisten->socket, "%s/%s.sock",
                                priv->libDir, type) < 0)
                    goto cleanup;
                glisten->autoGenerated = true;
            }
            break;

        case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_NONE:
        case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_LAST:
            break;
        }
    }

    ret = 0;

 cleanup:
    virObjectUnref(cfg);
    return ret;
}


static int
qemuProcessGraphicsSetupRenderNode(virDomainGraphicsDefPtr graphics,
                                   virQEMUCapsPtr qemuCaps)
{
    char **rendernode = NULL;

    if (!virDomainGraphicsNeedsAutoRenderNode(graphics))
        return 0;

    /* Don't bother picking a DRM node if QEMU doesn't support it. */
    if (graphics->type == VIR_DOMAIN_GRAPHICS_TYPE_SPICE) {
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_SPICE_RENDERNODE))
            return 0;

        rendernode = &graphics->data.spice.rendernode;
    } else {
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_EGL_HEADLESS_RENDERNODE))
            return 0;

        rendernode = &graphics->data.egl_headless.rendernode;
    }

    if (!(*rendernode = virHostGetDRMRenderNode()))
        return -1;

    return 0;
}


static int
qemuProcessSetupGraphics(virQEMUDriverPtr driver,
                         virDomainObjPtr vm,
                         virQEMUCapsPtr qemuCaps,
                         unsigned int flags)
{
    virDomainGraphicsDefPtr graphics;
    bool allocate = !(flags & VIR_QEMU_PROCESS_START_PRETEND);
    size_t i;
    int ret = -1;

    for (i = 0; i < vm->def->ngraphics; i++) {
        graphics = vm->def->graphics[i];

        if (qemuProcessGraphicsSetupRenderNode(graphics, qemuCaps) < 0)
            goto cleanup;

        if (qemuProcessGraphicsSetupListen(driver, graphics, vm) < 0)
            goto cleanup;
    }

    if (allocate) {
        for (i = 0; i < vm->def->ngraphics; i++) {
            graphics = vm->def->graphics[i];

            if (qemuProcessGraphicsReservePorts(graphics, false) < 0)
                goto cleanup;
        }
    }

    for (i = 0; i < vm->def->ngraphics; ++i) {
        graphics = vm->def->graphics[i];

        if (qemuProcessGraphicsAllocatePorts(driver, graphics, allocate) < 0)
            goto cleanup;
    }

    ret = 0;

 cleanup:
    return ret;
}


static int
qemuProcessSetupRawIO(virQEMUDriverPtr driver,
                      virDomainObjPtr vm,
                      virCommandPtr cmd ATTRIBUTE_UNUSED)
{
    bool rawio = false;
    size_t i;
    int ret = -1;

    /* in case a certain disk is desirous of CAP_SYS_RAWIO, add this */
    for (i = 0; i < vm->def->ndisks; i++) {
        virDomainDeviceDef dev;
        virDomainDiskDefPtr disk = vm->def->disks[i];

        if (disk->rawio == VIR_TRISTATE_BOOL_YES) {
            rawio = true;
#ifndef CAP_SYS_RAWIO
            break;
#endif
        }

        dev.type = VIR_DOMAIN_DEVICE_DISK;
        dev.data.disk = disk;
        if (qemuAddSharedDevice(driver, &dev, vm->def->name) < 0)
            goto cleanup;

        if (qemuSetUnprivSGIO(&dev) < 0)
            goto cleanup;
    }

    /* If rawio not already set, check hostdevs as well */
    if (!rawio) {
        for (i = 0; i < vm->def->nhostdevs; i++) {
            if (!virHostdevIsSCSIDevice(vm->def->hostdevs[i]))
                continue;

            virDomainHostdevSubsysSCSIPtr scsisrc =
                &vm->def->hostdevs[i]->source.subsys.u.scsi;
            if (scsisrc->rawio == VIR_TRISTATE_BOOL_YES) {
                rawio = true;
                break;
            }
        }
    }

    ret = 0;

 cleanup:
    if (rawio) {
#ifdef CAP_SYS_RAWIO
        if (ret == 0)
            virCommandAllowCap(cmd, CAP_SYS_RAWIO);
#else
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Raw I/O is not supported on this platform"));
        ret = -1;
#endif
    }
    return ret;
}


static int
qemuProcessSetupBalloon(virQEMUDriverPtr driver,
                        virDomainObjPtr vm,
                        qemuDomainAsyncJob asyncJob)
{
    unsigned long long balloon = vm->def->mem.cur_balloon;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int ret = -1;

    if (!virDomainDefHasMemballoon(vm->def))
        return 0;

    if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) < 0)
        return -1;

    if (vm->def->memballoon->period)
        qemuMonitorSetMemoryStatsPeriod(priv->mon, vm->def->memballoon,
                                        vm->def->memballoon->period);
    if (qemuMonitorSetBalloon(priv->mon, balloon) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        ret = -1;
    return ret;
}


static int
qemuProcessMakeDir(virQEMUDriverPtr driver,
                   virDomainObjPtr vm,
                   const char *path)
{
    int ret = -1;

    if (virFileMakePathWithMode(path, 0750) < 0) {
        virReportSystemError(errno, _("Cannot create directory '%s'"), path);
        goto cleanup;
    }

    if (qemuSecurityDomainSetPathLabel(driver, vm, path, true) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    return ret;
}


static void
qemuProcessStartWarnShmem(virDomainObjPtr vm)
{
    size_t i;
    bool check_shmem = false;
    bool shmem = vm->def->nshmems;

    /*
     * For vhost-user to work, the domain has to have some type of
     * shared memory configured.  We're not the proper ones to judge
     * whether shared hugepages or shm are enough and will be in the
     * future, so we'll just warn in case neither is configured.
     * Moreover failing would give the false illusion that libvirt is
     * really checking that everything works before running the domain
     * and not only we are unable to do that, but it's also not our
     * aim to do so.
     */
    for (i = 0; i < vm->def->nnets; i++) {
        if (virDomainNetGetActualType(vm->def->nets[i]) ==
                                      VIR_DOMAIN_NET_TYPE_VHOSTUSER) {
            check_shmem = true;
            break;
        }
    }

    if (!check_shmem)
        return;

    /*
     * This check is by no means complete.  We merely check
     * whether there are *some* hugepages enabled and *some* NUMA
     * nodes with shared memory access.
     */
    if (!shmem && vm->def->mem.nhugepages) {
        for (i = 0; i < virDomainNumaGetNodeCount(vm->def->numa); i++) {
            if (virDomainNumaGetNodeMemoryAccessMode(vm->def->numa, i) ==
                VIR_DOMAIN_MEMORY_ACCESS_SHARED) {
                shmem = true;
                break;
            }
        }
    }

    if (!shmem) {
        VIR_WARN("Detected vhost-user interface without any shared memory, "
                 "the interface might not be operational");
    }
}


static int
qemuProcessStartValidateGraphics(virDomainObjPtr vm)
{
    size_t i;

    for (i = 0; i < vm->def->ngraphics; i++) {
        virDomainGraphicsDefPtr graphics = vm->def->graphics[i];

        switch (graphics->type) {
        case VIR_DOMAIN_GRAPHICS_TYPE_VNC:
        case VIR_DOMAIN_GRAPHICS_TYPE_SPICE:
            if (graphics->nListens > 1) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("QEMU does not support multiple listens for "
                                 "one graphics device."));
                return -1;
            }
            break;

        case VIR_DOMAIN_GRAPHICS_TYPE_SDL:
        case VIR_DOMAIN_GRAPHICS_TYPE_RDP:
        case VIR_DOMAIN_GRAPHICS_TYPE_DESKTOP:
        case VIR_DOMAIN_GRAPHICS_TYPE_EGL_HEADLESS:
        case VIR_DOMAIN_GRAPHICS_TYPE_LAST:
            break;
        }
    }

    return 0;
}


static int
qemuProcessStartValidateVideo(virDomainObjPtr vm,
                              virQEMUCapsPtr qemuCaps)
{
    size_t i;
    virDomainVideoDefPtr video;

    for (i = 0; i < vm->def->nvideos; i++) {
        video = vm->def->videos[i];

        if ((video->type == VIR_DOMAIN_VIDEO_TYPE_VGA &&
             !virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_VGA)) ||
            (video->type == VIR_DOMAIN_VIDEO_TYPE_CIRRUS &&
             !virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_CIRRUS_VGA)) ||
            (video->type == VIR_DOMAIN_VIDEO_TYPE_VMVGA &&
             !virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_VMWARE_SVGA)) ||
            (video->type == VIR_DOMAIN_VIDEO_TYPE_QXL &&
             !virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_QXL)) ||
            (video->type == VIR_DOMAIN_VIDEO_TYPE_VIRTIO &&
             !virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_VIRTIO_GPU)) ||
            (video->type == VIR_DOMAIN_VIDEO_TYPE_VIRTIO &&
             video->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW &&
             !virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_VIRTIO_GPU_CCW))) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("this QEMU does not support '%s' video device"),
                           virDomainVideoTypeToString(video->type));
            return -1;
        }

        if (video->accel) {
            if (video->accel->accel3d == VIR_TRISTATE_SWITCH_ON &&
                (video->type != VIR_DOMAIN_VIDEO_TYPE_VIRTIO ||
                 !virQEMUCapsGet(qemuCaps, QEMU_CAPS_VIRTIO_GPU_VIRGL))) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("%s 3d acceleration is not supported"),
                               virDomainVideoTypeToString(video->type));
                return -1;
            }
        }
    }

    return 0;
}


static int
qemuProcessStartValidateIOThreads(virDomainObjPtr vm,
                                  virQEMUCapsPtr qemuCaps)
{
    size_t i;

    if (vm->def->niothreadids > 0 &&
        !virQEMUCapsGet(qemuCaps, QEMU_CAPS_OBJECT_IOTHREAD)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("IOThreads not supported for this QEMU"));
        return -1;
    }

    for (i = 0; i < vm->def->ncontrollers; i++) {
        virDomainControllerDefPtr cont = vm->def->controllers[i];

        if (cont->type == VIR_DOMAIN_CONTROLLER_TYPE_SCSI &&
            cont->model == VIR_DOMAIN_CONTROLLER_MODEL_SCSI_VIRTIO_SCSI &&
            cont->iothread > 0 &&
            !virQEMUCapsGet(qemuCaps, QEMU_CAPS_VIRTIO_SCSI_IOTHREAD)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("IOThreads for virtio-scsi not supported for "
                             "this QEMU"));
            return -1;
        }
    }

    return 0;
}


static int
qemuProcessStartValidateShmem(virDomainObjPtr vm)
{
    size_t i;

    for (i = 0; i < vm->def->nshmems; i++) {
        virDomainShmemDefPtr shmem = vm->def->shmems[i];

        if (strchr(shmem->name, '/')) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("shmem name '%s' must not contain '/'"),
                           shmem->name);
            return -1;
        }
    }

    return 0;
}


static int
qemuProcessStartValidateDisks(virDomainObjPtr vm,
                              virQEMUCapsPtr qemuCaps)
{
    size_t i;

    for (i = 0; i < vm->def->ndisks; i++) {
        virDomainDiskDefPtr disk = vm->def->disks[i];
        virStorageSourcePtr src = disk->src;

        /* This is a best effort check as we can only check if the command
         * option exists, but we cannot determine whether the running QEMU
         * was build with '--enable-vxhs'. */
        if (src->type == VIR_STORAGE_TYPE_NETWORK &&
            src->protocol == VIR_STORAGE_NET_PROTOCOL_VXHS &&
            !virQEMUCapsGet(qemuCaps, QEMU_CAPS_VXHS)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("VxHS protocol is not supported with this "
                             "QEMU binary"));
            return -1;
        }

        /* PowerPC pseries based VMs do not support floppy device */
        if (disk->device == VIR_DOMAIN_DISK_DEVICE_FLOPPY &&
            qemuDomainIsPSeries(vm->def)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("PowerPC pseries machines do not support floppy device"));
            return -1;
        }
    }

    return 0;
}


static int
qemuProcessStartValidateTSC(virDomainObjPtr vm,
                            virCapsPtr caps)
{
    size_t i;
    unsigned long long freq = 0;
    virHostCPUTscInfoPtr tsc;

    for (i = 0; i < vm->def->clock.ntimers; i++) {
        virDomainTimerDefPtr timer = vm->def->clock.timers[i];

        if (timer->name == VIR_DOMAIN_TIMER_NAME_TSC &&
            timer->frequency > 0) {
            freq = timer->frequency;
            break;
        }
    }

    if (freq == 0)
        return 0;

    VIR_DEBUG("Requested TSC frequency %llu Hz", freq);

    if (!caps->host.cpu || !caps->host.cpu->tsc) {
        VIR_DEBUG("Host TSC frequency could not be probed");
        return 0;
    }

    tsc = caps->host.cpu->tsc;
    VIR_DEBUG("Host TSC frequency %llu Hz, scaling %s",
              tsc->frequency, virTristateBoolTypeToString(tsc->scaling));

    if (freq == tsc->frequency || tsc->scaling == VIR_TRISTATE_BOOL_YES)
        return 0;

    if (tsc->scaling == VIR_TRISTATE_BOOL_ABSENT) {
        VIR_DEBUG("TSC frequencies do not match and scaling support is "
                  "unknown, QEMU will try and possibly fail later");
        return 0;
    }

    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                   _("Requested TSC frequency %llu Hz does not match "
                     "host (%llu Hz) and TSC scaling is not supported "
                     "by the host CPU"),
                   freq, tsc->frequency);
    return -1;
}


/**
 * qemuProcessStartValidate:
 * @vm: domain object
 * @qemuCaps: emulator capabilities
 * @migration: restoration of existing state
 *
 * This function aggregates checks done prior to start of a VM.
 *
 * Flag VIR_QEMU_PROCESS_START_PRETEND tells, that we don't want to actually
 * start the domain but create a valid qemu command.  If some code shouldn't be
 * executed in this case, make sure to check this flag.
 */
static int
qemuProcessStartValidate(virQEMUDriverPtr driver,
                         virDomainObjPtr vm,
                         virQEMUCapsPtr qemuCaps,
                         virCapsPtr caps,
                         unsigned int flags)
{
    if (!(flags & VIR_QEMU_PROCESS_START_PRETEND)) {
        if (vm->def->virtType == VIR_DOMAIN_VIRT_KVM) {
            VIR_DEBUG("Checking for KVM availability");
            if (!virFileExists("/dev/kvm")) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("Domain requires KVM, but it is not available. "
                                 "Check that virtualization is enabled in the "
                                 "host BIOS, and host configuration is setup to "
                                 "load the kvm modules."));
                return -1;
            }
        }

        VIR_DEBUG("Checking domain and device security labels");
        if (qemuSecurityCheckAllLabel(driver->securityManager, vm->def) < 0)
            return -1;

    }

    /* Checks below should not be executed when starting a qemu process for a
     * VM that was running before (migration, snapshots, save). It's more
     * important to start such VM than keep the configuration clean */
    if ((flags & VIR_QEMU_PROCESS_START_NEW) &&
        virDomainDefValidate(vm->def, caps, 0, driver->xmlopt) < 0)
        return -1;

    if (qemuProcessStartValidateGraphics(vm) < 0)
        return -1;

    if (qemuProcessStartValidateVideo(vm, qemuCaps) < 0)
        return -1;

    if (qemuProcessStartValidateIOThreads(vm, qemuCaps) < 0)
        return -1;

    if (qemuProcessStartValidateShmem(vm) < 0)
        return -1;

    if (vm->def->cpu) {
        if (virCPUValidateFeatures(vm->def->os.arch, vm->def->cpu) < 0)
            return -1;

        if (ARCH_IS_X86(vm->def->os.arch) &&
            !virQEMUCapsGet(qemuCaps, QEMU_CAPS_CPU_UNAVAILABLE_FEATURES)) {
            VIR_AUTOSTRINGLIST features = NULL;
            int n;

            if ((n = virCPUDefCheckFeatures(vm->def->cpu,
                                            virCPUx86FeatureFilterSelectMSR,
                                            NULL,
                                            &features)) < 0)
                return -1;

            if (n > 0) {
                VIR_AUTOFREE(char *) str = NULL;

                str = virStringListJoin((const char **)features, ", ");
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("Some features cannot be reliably used "
                                 "with this QEMU: %s"), str);
                return -1;
            }
        }
    }

    if (qemuProcessStartValidateDisks(vm, qemuCaps) < 0)
        return -1;

    if (qemuProcessStartValidateTSC(vm, caps) < 0)
        return -1;

    VIR_DEBUG("Checking for any possible (non-fatal) issues");

    qemuProcessStartWarnShmem(vm);

    return 0;
}


static int
qemuProcessStartUpdateCustomCaps(virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    VIR_AUTOUNREF(virQEMUDriverConfigPtr) cfg = virQEMUDriverGetConfig(priv->driver);
    qemuDomainXmlNsDefPtr nsdef = vm->def->namespaceData;
    char **next;
    int tmp;
    size_t i;

    if (cfg->capabilityfilters) {
        for (next = cfg->capabilityfilters; *next; next++) {
            if ((tmp = virQEMUCapsTypeFromString(*next)) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("invalid capability_filters capability '%s'"),
                               *next);
                return -1;
            }

            virQEMUCapsClear(priv->qemuCaps, tmp);
        }
    }

    if (nsdef) {
        for (i = 0; i < nsdef->ncapsadd; i++) {
            if ((tmp = virQEMUCapsTypeFromString(nsdef->capsadd[i])) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("invalid qemu namespace capability '%s'"),
                               nsdef->capsadd[i]);
                return -1;
            }

            virQEMUCapsSet(priv->qemuCaps, tmp);
        }

        for (i = 0; i < nsdef->ncapsdel; i++) {
            if ((tmp = virQEMUCapsTypeFromString(nsdef->capsdel[i])) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("invalid qemu namespace capability '%s'"),
                               nsdef->capsdel[i]);
                return -1;
            }

            virQEMUCapsClear(priv->qemuCaps, tmp);
        }
    }

    return 0;
}


/**
 * qemuProcessInit:
 *
 * Prepares the domain up to the point when priv->qemuCaps is initialized. The
 * function calls qemuProcessStop when needed.
 *
 * Flag VIR_QEMU_PROCESS_START_PRETEND tells, that we don't want to actually
 * start the domain but create a valid qemu command.  If some code shouldn't be
 * executed in this case, make sure to check this flag.
 *
 * Returns 0 on success, -1 on error.
 */
int
qemuProcessInit(virQEMUDriverPtr driver,
                virDomainObjPtr vm,
                virCPUDefPtr updatedCPU,
                qemuDomainAsyncJob asyncJob,
                bool migration,
                unsigned int flags)
{
    virCapsPtr caps = NULL;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int stopFlags;
    virCPUDefPtr origCPU = NULL;
    int ret = -1;

    VIR_DEBUG("vm=%p name=%s id=%d migration=%d",
              vm, vm->def->name, vm->def->id, migration);

    VIR_DEBUG("Beginning VM startup process");

    if (virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("VM is already active"));
        goto cleanup;
    }

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    /* in case when the post parse callback failed we need to re-run it on the
     * old config prior we start the VM */
    if (vm->def->postParseFailed) {
        VIR_DEBUG("re-running the post parse callback");

        if (virDomainDefPostParse(vm->def, caps, 0, driver->xmlopt, NULL) < 0)
            goto cleanup;
    }

    VIR_DEBUG("Determining emulator version");
    if (qemuDomainUpdateQEMUCaps(vm, driver->qemuCapsCache) < 0)
        goto cleanup;

    if (flags & VIR_QEMU_PROCESS_START_STANDALONE)
        virQEMUCapsClear(priv->qemuCaps, QEMU_CAPS_CHARDEV_FD_PASS);

    if (qemuDomainUpdateCPU(vm, updatedCPU, &origCPU) < 0)
        goto cleanup;

    if (qemuProcessStartValidate(driver, vm, priv->qemuCaps, caps, flags) < 0)
        goto cleanup;

    /* Do this upfront, so any part of the startup process can add
     * runtime state to vm->def that won't be persisted. This let's us
     * report implicit runtime defaults in the XML, like vnc listen/socket
     */
    VIR_DEBUG("Setting current domain def as transient");
    if (virDomainObjSetDefTransient(caps, driver->xmlopt, vm) < 0)
        goto cleanup;

    /* Update qemu capabilities according to lists passed in via namespace */
    if (qemuProcessStartUpdateCustomCaps(vm) < 0)
        goto cleanup;

    if (flags & VIR_QEMU_PROCESS_START_PRETEND) {
        if (qemuDomainSetPrivatePaths(driver, vm) < 0) {
            virDomainObjRemoveTransientDef(vm);
            goto cleanup;
        }
    } else {
        vm->def->id = qemuDriverAllocateID(driver);
        qemuDomainSetFakeReboot(driver, vm, false);
        virDomainObjSetState(vm, VIR_DOMAIN_PAUSED, VIR_DOMAIN_PAUSED_STARTING_UP);

        if (virAtomicIntInc(&driver->nactive) == 1 && driver->inhibitCallback)
            driver->inhibitCallback(true, driver->inhibitOpaque);

        /* Run an early hook to set-up missing devices */
        if (qemuProcessStartHook(driver, vm,
                                 VIR_HOOK_QEMU_OP_PREPARE,
                                 VIR_HOOK_SUBOP_BEGIN) < 0)
            goto stop;

        if (qemuDomainSetPrivatePaths(driver, vm) < 0)
            goto stop;

        VIR_STEAL_PTR(priv->origCPU, origCPU);
    }

    ret = 0;

 cleanup:
    virCPUDefFree(origCPU);
    virObjectUnref(caps);
    return ret;

 stop:
    stopFlags = VIR_QEMU_PROCESS_STOP_NO_RELABEL;
    if (migration)
        stopFlags |= VIR_QEMU_PROCESS_STOP_MIGRATED;
    qemuProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_FAILED, asyncJob, stopFlags);
    goto cleanup;
}


/**
 * qemuProcessNetworkPrepareDevices
 */
static int
qemuProcessNetworkPrepareDevices(virDomainDefPtr def)
{
    int ret = -1;
    size_t i;
    virConnectPtr conn = NULL;

    for (i = 0; i < def->nnets; i++) {
        virDomainNetDefPtr net = def->nets[i];
        virDomainNetType actualType;

        /* If appropriate, grab a physical device from the configured
         * network's pool of devices, or resolve bridge device name
         * to the one defined in the network definition.
         */
        if (net->type == VIR_DOMAIN_NET_TYPE_NETWORK) {
            if (!conn && !(conn = virGetConnectNetwork()))
                goto cleanup;
            if (virDomainNetAllocateActualDevice(conn, def, net) < 0)
                goto cleanup;
        }

        actualType = virDomainNetGetActualType(net);
        if (actualType == VIR_DOMAIN_NET_TYPE_HOSTDEV &&
            net->type == VIR_DOMAIN_NET_TYPE_NETWORK) {
            /* Each type='hostdev' network device must also have a
             * corresponding entry in the hostdevs array. For netdevs
             * that are hardcoded as type='hostdev', this is already
             * done by the parser, but for those allocated from a
             * network / determined at runtime, we need to do it
             * separately.
             */
            virDomainHostdevDefPtr hostdev = virDomainNetGetActualHostdev(net);
            virDomainHostdevSubsysPCIPtr pcisrc = &hostdev->source.subsys.u.pci;

            if (virDomainHostdevFind(def, hostdev, NULL) >= 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("PCI device %04x:%02x:%02x.%x "
                                 "allocated from network %s is already "
                                 "in use by domain %s"),
                               pcisrc->addr.domain, pcisrc->addr.bus,
                               pcisrc->addr.slot, pcisrc->addr.function,
                               net->data.network.name, def->name);
                goto cleanup;
            }
            if (virDomainHostdevInsert(def, hostdev) < 0)
                goto cleanup;
        }
    }
    ret = 0;
 cleanup:
    virObjectUnref(conn);
    return ret;
}


/**
 * qemuProcessSetupVcpu:
 * @vm: domain object
 * @vcpuid: id of VCPU to set defaults
 *
 * This function sets resource properties (cgroups, affinity, scheduler) for a
 * vCPU. This function expects that the vCPU is online and the vCPU pids were
 * correctly detected at the point when it's called.
 *
 * Returns 0 on success, -1 on error.
 */
int
qemuProcessSetupVcpu(virDomainObjPtr vm,
                     unsigned int vcpuid)
{
    pid_t vcpupid = qemuDomainGetVcpuPid(vm, vcpuid);
    virDomainVcpuDefPtr vcpu = virDomainDefGetVcpu(vm->def, vcpuid);
    virDomainResctrlMonDefPtr mon = NULL;
    size_t i = 0;

    if (qemuProcessSetupPid(vm, vcpupid, VIR_CGROUP_THREAD_VCPU,
                            vcpuid, vcpu->cpumask,
                            vm->def->cputune.period,
                            vm->def->cputune.quota,
                            &vcpu->sched) < 0)
        return -1;

    for (i = 0; i < vm->def->nresctrls; i++) {
        size_t j = 0;
        virDomainResctrlDefPtr ct = vm->def->resctrls[i];

        if (virBitmapIsBitSet(ct->vcpus, vcpuid)) {
            if (virResctrlAllocAddPID(ct->alloc, vcpupid) < 0)
                return -1;

            for (j = 0; j < ct->nmonitors; j++) {
                mon = ct->monitors[j];

                if (virBitmapEqual(ct->vcpus, mon->vcpus))
                    continue;

                if (virBitmapIsBitSet(mon->vcpus, vcpuid)) {
                    if (virResctrlMonitorAddPID(mon->instance, vcpupid) < 0)
                        return -1;
                    break;
                }
            }

            break;
        }
    }

    return 0;
}


static int
qemuProcessSetupVcpus(virDomainObjPtr vm)
{
    virDomainVcpuDefPtr vcpu;
    unsigned int maxvcpus = virDomainDefGetVcpusMax(vm->def);
    size_t i;

    if ((vm->def->cputune.period || vm->def->cputune.quota) &&
        !virCgroupHasController(((qemuDomainObjPrivatePtr) vm->privateData)->cgroup,
                                VIR_CGROUP_CONTROLLER_CPU)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("cgroup cpu is required for scheduler tuning"));
        return -1;
    }

    if (!qemuDomainHasVcpuPids(vm)) {
        /* If any CPU has custom affinity that differs from the
         * VM default affinity, we must reject it */
        for (i = 0; i < maxvcpus; i++) {
            vcpu = virDomainDefGetVcpu(vm->def, i);

            if (!vcpu->online)
                continue;

            if (vcpu->cpumask &&
                !virBitmapEqual(vm->def->cpumask, vcpu->cpumask)) {
                virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                                _("cpu affinity is not supported"));
                return -1;
            }
        }

        return 0;
    }

    for (i = 0; i < maxvcpus; i++) {
        vcpu = virDomainDefGetVcpu(vm->def, i);

        if (!vcpu->online)
            continue;

        if (qemuProcessSetupVcpu(vm, i) < 0)
            return -1;
    }

    return 0;
}


int
qemuProcessSetupIOThread(virDomainObjPtr vm,
                         virDomainIOThreadIDDefPtr iothread)
{
    return qemuProcessSetupPid(vm, iothread->thread_id,
                               VIR_CGROUP_THREAD_IOTHREAD,
                               iothread->iothread_id,
                               iothread->cpumask,
                               vm->def->cputune.iothread_period,
                               vm->def->cputune.iothread_quota,
                               &iothread->sched);
}


static int
qemuProcessSetupIOThreads(virDomainObjPtr vm)
{
    size_t i;

    for (i = 0; i < vm->def->niothreadids; i++) {
        virDomainIOThreadIDDefPtr info = vm->def->iothreadids[i];

        if (qemuProcessSetupIOThread(vm, info) < 0)
            return -1;
    }

    return 0;
}


static int
qemuProcessValidateHotpluggableVcpus(virDomainDefPtr def)
{
    virDomainVcpuDefPtr vcpu;
    virDomainVcpuDefPtr subvcpu;
    qemuDomainVcpuPrivatePtr vcpupriv;
    unsigned int maxvcpus = virDomainDefGetVcpusMax(def);
    size_t i = 0;
    size_t j;
    virBitmapPtr ordermap = NULL;
    int ret = -1;

    if (!(ordermap = virBitmapNew(maxvcpus + 1)))
        goto cleanup;

    /* validate:
     * - all hotpluggable entities to be hotplugged have the correct data
     * - vcpus belonging to a hotpluggable entity share configuration
     * - order of the hotpluggable entities is unique
     */
    for (i = 0; i < maxvcpus; i++) {
        vcpu = virDomainDefGetVcpu(def, i);
        vcpupriv = QEMU_DOMAIN_VCPU_PRIVATE(vcpu);

        /* skip over hotpluggable entities  */
        if (vcpupriv->vcpus == 0)
            continue;

        if (vcpu->order != 0) {
            if (virBitmapIsBitSet(ordermap, vcpu->order)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("duplicate vcpu order '%u'"), vcpu->order);
                goto cleanup;
            }

            if (virBitmapSetBit(ordermap, vcpu->order)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("vcpu order '%u' exceeds vcpu count"),
                               vcpu->order);
                goto cleanup;
            }
        }

        for (j = i + 1; j < (i + vcpupriv->vcpus); j++) {
            subvcpu = virDomainDefGetVcpu(def, j);
            if (subvcpu->hotpluggable != vcpu->hotpluggable ||
                subvcpu->online != vcpu->online ||
                subvcpu->order != vcpu->order) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("vcpus '%zu' and '%zu' are in the same hotplug "
                                 "group but differ in configuration"), i, j);
                goto cleanup;
            }
        }

        if (vcpu->online && vcpu->hotpluggable == VIR_TRISTATE_BOOL_YES) {
            if ((vcpupriv->socket_id == -1 && vcpupriv->core_id == -1 &&
                 vcpupriv->thread_id == -1 && vcpupriv->node_id == -1) ||
                !vcpupriv->type) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("vcpu '%zu' is missing hotplug data"), i);
                goto cleanup;
            }
        }
    }

    ret = 0;
 cleanup:
    virBitmapFree(ordermap);
    return ret;
}


static int
qemuDomainHasHotpluggableStartupVcpus(virDomainDefPtr def)
{
    size_t maxvcpus = virDomainDefGetVcpusMax(def);
    virDomainVcpuDefPtr vcpu;
    size_t i;

    for (i = 0; i < maxvcpus; i++) {
        vcpu = virDomainDefGetVcpu(def, i);

        if (vcpu->online && vcpu->hotpluggable == VIR_TRISTATE_BOOL_YES)
            return true;
    }

    return false;
}


static int
qemuProcessVcpusSortOrder(const void *a,
                          const void *b)
{
    virDomainVcpuDefPtr vcpua = *((virDomainVcpuDefPtr *)a);
    virDomainVcpuDefPtr vcpub = *((virDomainVcpuDefPtr *)b);

    return vcpua->order - vcpub->order;
}


static int
qemuProcessSetupHotpluggableVcpus(virQEMUDriverPtr driver,
                                  virDomainObjPtr vm,
                                  qemuDomainAsyncJob asyncJob)
{
    unsigned int maxvcpus = virDomainDefGetVcpusMax(vm->def);
    qemuDomainObjPrivatePtr priv = vm->privateData;
    qemuCgroupEmulatorAllNodesDataPtr emulatorCgroup = NULL;
    virDomainVcpuDefPtr vcpu;
    qemuDomainVcpuPrivatePtr vcpupriv;
    virJSONValuePtr vcpuprops = NULL;
    size_t i;
    int ret = -1;
    int rc;

    virDomainVcpuDefPtr *bootHotplug = NULL;
    size_t nbootHotplug = 0;

    for (i = 0; i < maxvcpus; i++) {
        vcpu = virDomainDefGetVcpu(vm->def, i);
        vcpupriv = QEMU_DOMAIN_VCPU_PRIVATE(vcpu);

        if (vcpu->hotpluggable == VIR_TRISTATE_BOOL_YES && vcpu->online &&
            vcpupriv->vcpus != 0) {
            if (virAsprintf(&vcpupriv->alias, "vcpu%zu", i) < 0)
                goto cleanup;

            if (VIR_APPEND_ELEMENT(bootHotplug, nbootHotplug, vcpu) < 0)
                goto cleanup;
        }
    }

    if (nbootHotplug == 0) {
        ret = 0;
        goto cleanup;
    }

    qsort(bootHotplug, nbootHotplug, sizeof(*bootHotplug),
          qemuProcessVcpusSortOrder);

    if (qemuCgroupEmulatorAllNodesAllow(priv->cgroup, &emulatorCgroup) < 0)
        goto cleanup;

    for (i = 0; i < nbootHotplug; i++) {
        vcpu = bootHotplug[i];

        if (!(vcpuprops = qemuBuildHotpluggableCPUProps(vcpu)))
            goto cleanup;

        if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) < 0)
            goto cleanup;

        rc = qemuMonitorAddDeviceArgs(qemuDomainGetMonitor(vm), vcpuprops);
        vcpuprops = NULL;

        if (qemuDomainObjExitMonitor(driver, vm) < 0)
            goto cleanup;

        if (rc < 0)
            goto cleanup;

        virJSONValueFree(vcpuprops);
    }

    ret = 0;

 cleanup:
    qemuCgroupEmulatorAllNodesRestore(emulatorCgroup);
    VIR_FREE(bootHotplug);
    virJSONValueFree(vcpuprops);
    return ret;
}


static int
qemuProcessUpdateGuestCPU(virDomainDefPtr def,
                          virQEMUCapsPtr qemuCaps,
                          virCapsPtr caps,
                          unsigned int flags)
{
    if (!def->cpu)
        return 0;

    /* nothing to do if only topology part of CPU def is used */
    if (def->cpu->mode == VIR_CPU_MODE_CUSTOM && !def->cpu->model)
        return 0;

    /* Old libvirt added host CPU model to host-model CPUs for migrations,
     * while new libvirt just turns host-model into custom mode. We need
     * to fix the mode to maintain backward compatibility and to avoid
     * the CPU model to be replaced in virCPUUpdate.
     */
    if (!(flags & VIR_QEMU_PROCESS_START_NEW) &&
        ARCH_IS_X86(def->os.arch) &&
        def->cpu->mode == VIR_CPU_MODE_HOST_MODEL &&
        def->cpu->model) {
        def->cpu->mode = VIR_CPU_MODE_CUSTOM;
    }

    if (!virQEMUCapsIsCPUModeSupported(qemuCaps, caps, def->virtType,
                                       def->cpu->mode)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("CPU mode '%s' for %s %s domain on %s host is not "
                         "supported by hypervisor"),
                       virCPUModeTypeToString(def->cpu->mode),
                       virArchToString(def->os.arch),
                       virDomainVirtTypeToString(def->virtType),
                       virArchToString(caps->host.arch));
        return -1;
    }

    if (virCPUConvertLegacy(caps->host.arch, def->cpu) < 0)
        return -1;

    /* nothing to update for host-passthrough */
    if (def->cpu->mode != VIR_CPU_MODE_HOST_PASSTHROUGH) {
        if (def->cpu->check == VIR_CPU_CHECK_PARTIAL &&
            virCPUCompare(caps->host.arch,
                          virQEMUCapsGetHostModel(qemuCaps, def->virtType,
                                                  VIR_QEMU_CAPS_HOST_CPU_FULL),
                          def->cpu, true) < 0)
            return -1;

        if (virCPUUpdate(def->os.arch, def->cpu,
                         virQEMUCapsGetHostModel(qemuCaps, def->virtType,
                                                 VIR_QEMU_CAPS_HOST_CPU_MIGRATABLE)) < 0)
            return -1;

        if (virCPUTranslate(def->os.arch, def->cpu,
                            virQEMUCapsGetCPUDefinitions(qemuCaps, def->virtType)) < 0)
            return -1;

        def->cpu->fallback = VIR_CPU_FALLBACK_FORBID;
    }

    if (virCPUDefFilterFeatures(def->cpu, virQEMUCapsCPUFilterFeatures,
                                &def->os.arch) < 0)
        return -1;

    return 0;
}


static int
qemuProcessPrepareDomainNUMAPlacement(virDomainObjPtr vm,
                                      virCapsPtr caps)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    char *nodeset = NULL;
    virBitmapPtr numadNodeset = NULL;
    virBitmapPtr hostMemoryNodeset = NULL;
    int ret = -1;

    /* Get the advisory nodeset from numad if 'placement' of
     * either <vcpu> or <numatune> is 'auto'.
     */
    if (!virDomainDefNeedsPlacementAdvice(vm->def))
        return 0;

    nodeset = virNumaGetAutoPlacementAdvice(virDomainDefGetVcpus(vm->def),
                                            virDomainDefGetMemoryTotal(vm->def));

    if (!nodeset)
        goto cleanup;

    if (!(hostMemoryNodeset = virNumaGetHostMemoryNodeset()))
        goto cleanup;

    VIR_DEBUG("Nodeset returned from numad: %s", nodeset);

    if (virBitmapParse(nodeset, &numadNodeset, VIR_DOMAIN_CPUMASK_LEN) < 0)
        goto cleanup;

    /* numad may return a nodeset that only contains cpus but cgroups don't play
     * well with that. Set the autoCpuset from all cpus from that nodeset, but
     * assign autoNodeset only with nodes containing memory. */
    if (!(priv->autoCpuset = virCapabilitiesGetCpusForNodemask(caps, numadNodeset)))
        goto cleanup;

    virBitmapIntersect(numadNodeset, hostMemoryNodeset);

    VIR_STEAL_PTR(priv->autoNodeset, numadNodeset);

    ret = 0;

 cleanup:
    VIR_FREE(nodeset);
    virBitmapFree(numadNodeset);
    virBitmapFree(hostMemoryNodeset);
    return ret;
}


static int
qemuProcessPrepareDomainStorage(virQEMUDriverPtr driver,
                                virDomainObjPtr vm,
                                qemuDomainObjPrivatePtr priv,
                                virQEMUDriverConfigPtr cfg,
                                unsigned int flags)
{
    size_t i;
    bool cold_boot = flags & VIR_QEMU_PROCESS_START_COLD;

    for (i = vm->def->ndisks; i > 0; i--) {
        size_t idx = i - 1;
        virDomainDiskDefPtr disk = vm->def->disks[idx];

        if (virDomainDiskTranslateSourcePool(disk) < 0) {
            if (qemuDomainCheckDiskStartupPolicy(driver, vm, idx, cold_boot) < 0)
                return -1;

            /* disk source was dropped */
            continue;
        }

        if (qemuDomainPrepareDiskSource(disk, priv, cfg) < 0)
            return -1;
    }

    return 0;
}


static void
qemuProcessPrepareAllowReboot(virDomainObjPtr vm)
{
    virDomainDefPtr def = vm->def;
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (priv->allowReboot != VIR_TRISTATE_BOOL_ABSENT)
        return;

    if (def->onReboot == VIR_DOMAIN_LIFECYCLE_ACTION_DESTROY &&
        def->onPoweroff == VIR_DOMAIN_LIFECYCLE_ACTION_DESTROY &&
        (def->onCrash == VIR_DOMAIN_LIFECYCLE_ACTION_DESTROY ||
         def->onCrash == VIR_DOMAIN_LIFECYCLE_ACTION_COREDUMP_DESTROY)) {
        priv->allowReboot = VIR_TRISTATE_BOOL_NO;
    } else {
        priv->allowReboot = VIR_TRISTATE_BOOL_YES;
    }
}


/**
 * qemuProcessPrepareDomain:
 * @driver: qemu driver
 * @vm: domain object
 * @flags: qemuProcessStartFlags
 *
 * This function groups all code that modifies only live XML of a domain which
 * is about to start and it's the only place to do those modifications.
 *
 * Flag VIR_QEMU_PROCESS_START_PRETEND tells, that we don't want to actually
 * start the domain but create a valid qemu command.  If some code shouldn't be
 * executed in this case, make sure to check this flag.
 *
 * TODO: move all XML modification from qemuBuildCommandLine into this function
 */
int
qemuProcessPrepareDomain(virQEMUDriverPtr driver,
                         virDomainObjPtr vm,
                         unsigned int flags)
{
    int ret = -1;
    size_t i;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    virCapsPtr caps;

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    priv->machineName = qemuDomainGetMachineName(vm);
    if (!priv->machineName)
        goto cleanup;

    if (!(flags & VIR_QEMU_PROCESS_START_PRETEND)) {
        /* If you are using a SecurityDriver with dynamic labelling,
           then generate a security label for isolation */
        VIR_DEBUG("Generating domain security label (if required)");
        if (qemuSecurityGenLabel(driver->securityManager, vm->def) < 0) {
            virDomainAuditSecurityLabel(vm, false);
            goto cleanup;
        }
        virDomainAuditSecurityLabel(vm, true);

        if (qemuProcessPrepareDomainNUMAPlacement(vm, caps) < 0)
            goto cleanup;
    }

    /* Whether we should use virtlogd as stdio handler for character
     * devices source backend. */
    if (cfg->stdioLogD &&
        virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_CHARDEV_FILE_APPEND)) {
        priv->chardevStdioLogd = true;
    }

    /* Track if this domain remembers original owner */
    priv->rememberOwner = cfg->rememberOwner;

    qemuProcessPrepareAllowReboot(vm);

    /* clear the 'blockdev' capability for VMs which have disks that need
     * -drive or which have floppies where we can't reliably get the QOM path */
    for (i = 0; i < vm->def->ndisks; i++) {
        if (qemuDiskBusNeedsDriveArg(vm->def->disks[i]->bus)) {
            virQEMUCapsClear(priv->qemuCaps, QEMU_CAPS_BLOCKDEV);
            break;
        }
    }

    /*
     * Normally PCI addresses are assigned in the virDomainCreate
     * or virDomainDefine methods. We might still need to assign
     * some here to cope with the question of upgrades. Regardless
     * we also need to populate the PCI address set cache for later
     * use in hotplug
     */
    VIR_DEBUG("Assigning domain PCI addresses");
    if ((qemuDomainAssignAddresses(vm->def, priv->qemuCaps, driver, vm,
                                   !!(flags & VIR_QEMU_PROCESS_START_NEW))) < 0) {
        goto cleanup;
    }

    if (qemuAssignDeviceAliases(vm->def, priv->qemuCaps) < 0)
        goto cleanup;

    VIR_DEBUG("Setting graphics devices");
    if (qemuProcessSetupGraphics(driver, vm, priv->qemuCaps, flags) < 0)
        goto cleanup;

    VIR_DEBUG("Create domain masterKey");
    if (qemuDomainMasterKeyCreate(vm) < 0)
        goto cleanup;

    VIR_DEBUG("Setting up storage");
    if (qemuProcessPrepareDomainStorage(driver, vm, priv, cfg, flags) < 0)
        goto cleanup;

    VIR_DEBUG("Prepare chardev source backends for TLS");
    qemuDomainPrepareChardevSource(vm->def, cfg);

    VIR_DEBUG("Prepare device secrets");
    if (qemuDomainSecretPrepare(driver, vm) < 0)
        goto cleanup;

    VIR_DEBUG("Prepare bios/uefi paths");
    if (qemuFirmwareFillDomain(driver, vm, flags) < 0)
        goto cleanup;

    for (i = 0; i < vm->def->nchannels; i++) {
        if (qemuDomainPrepareChannel(vm->def->channels[i],
                                     priv->channelTargetDir) < 0)
            goto cleanup;
    }

    if (!(priv->monConfig = virDomainChrSourceDefNew(driver->xmlopt)))
        goto cleanup;

    VIR_DEBUG("Preparing monitor state");
    if (qemuProcessPrepareMonitorChr(priv->monConfig, priv->libDir) < 0)
        goto cleanup;

    priv->monError = false;
    priv->monStart = 0;
    priv->runningReason = VIR_DOMAIN_RUNNING_UNKNOWN;
    priv->pausedReason = VIR_DOMAIN_PAUSED_UNKNOWN;

    VIR_DEBUG("Updating guest CPU definition");
    if (qemuProcessUpdateGuestCPU(vm->def, priv->qemuCaps, caps, flags) < 0)
        goto cleanup;

    for (i = 0; i < vm->def->nshmems; i++) {
        if (qemuDomainPrepareShmemChardev(vm->def->shmems[i]) < 0)
            goto cleanup;
    }

    ret = 0;
 cleanup:
    virObjectUnref(caps);
    virObjectUnref(cfg);
    return ret;
}


static int
qemuProcessSEVCreateFile(virDomainObjPtr vm,
                         const char *name,
                         const char *data)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virQEMUDriverPtr driver = priv->driver;
    char *configFile;
    int ret = -1;

    if (!(configFile = virFileBuildPath(priv->libDir, name, ".base64")))
        return -1;

    if (virFileRewriteStr(configFile, S_IRUSR | S_IWUSR, data) < 0) {
        virReportSystemError(errno, _("failed to write data to config '%s'"),
                             configFile);
        goto cleanup;
    }

    if (qemuSecurityDomainSetPathLabel(driver, vm, configFile, true) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    VIR_FREE(configFile);
    return ret;
}


static int
qemuProcessPrepareSEVGuestInput(virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virDomainDefPtr def = vm->def;
    virQEMUCapsPtr qemuCaps = priv->qemuCaps;
    virDomainSEVDefPtr sev = def->sev;

    if (!sev)
        return 0;

    VIR_DEBUG("Preparing SEV guest");

    if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_SEV_GUEST)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                        _("Domain %s asked for 'sev' launch but this "
                          "QEMU does not support SEV feature"), vm->def->name);
        return -1;
    }

    if (sev->dh_cert) {
        if (qemuProcessSEVCreateFile(vm, "dh_cert", sev->dh_cert) < 0)
            return -1;
    }

    if (sev->session) {
        if (qemuProcessSEVCreateFile(vm, "session", sev->session) < 0)
            return -1;
    }

    return 0;
}


static int
qemuProcessPrepareHostStorage(virQEMUDriverPtr driver,
                              virDomainObjPtr vm,
                              unsigned int flags)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    size_t i;
    bool cold_boot = flags & VIR_QEMU_PROCESS_START_COLD;
    bool blockdev = virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_BLOCKDEV);

    for (i = vm->def->ndisks; i > 0; i--) {
        size_t idx = i - 1;
        virDomainDiskDefPtr disk = vm->def->disks[idx];

        if (virStorageSourceIsEmpty(disk->src))
            continue;

        /* backing chain needs to be redetected if we aren't using blockdev */
        if (!blockdev)
            virStorageSourceBackingStoreClear(disk->src);

        /*
         * Go to applying startup policy for optional disk with nonexistent
         * source file immediately as determining chain will surely fail
         * and we don't want noisy error notice in logs for this case.
         */
        if (qemuDomainDiskIsMissingLocalOptional(disk) && cold_boot)
            VIR_INFO("optional disk '%s' source file is missing, "
                     "skip checking disk chain", disk->dst);
        else if (qemuDomainDetermineDiskChain(driver, vm, disk, NULL, true) >= 0)
            continue;

        if (qemuDomainCheckDiskStartupPolicy(driver, vm, idx, cold_boot) >= 0)
            continue;

        return -1;
    }

    return 0;
}


int
qemuProcessOpenVhostVsock(virDomainVsockDefPtr vsock)
{
    qemuDomainVsockPrivatePtr priv = (qemuDomainVsockPrivatePtr)vsock->privateData;
    const char *vsock_path = "/dev/vhost-vsock";
    int fd;

    if ((fd = open(vsock_path, O_RDWR)) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       "%s", _("unable to open vhost-vsock device"));
        return -1;
    }

    if (vsock->auto_cid == VIR_TRISTATE_BOOL_YES) {
        if (virVsockAcquireGuestCid(fd, &vsock->guest_cid) < 0)
            goto error;
    } else {
        if (virVsockSetGuestCid(fd, vsock->guest_cid) < 0)
            goto error;
    }

    priv->vhostfd = fd;
    return 0;

 error:
    VIR_FORCE_CLOSE(fd);
    return -1;
}


/**
 * qemuProcessPrepareHost:
 * @driver: qemu driver
 * @vm: domain object
 * @flags: qemuProcessStartFlags
 *
 * This function groups all code that modifies host system (which also may
 * update live XML) to prepare environment for a domain which is about to start
 * and it's the only place to do those modifications.
 *
 * TODO: move all host modification from qemuBuildCommandLine into this function
 */
int
qemuProcessPrepareHost(virQEMUDriverPtr driver,
                       virDomainObjPtr vm,
                       unsigned int flags)
{
    int ret = -1;
    unsigned int hostdev_flags = 0;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);

    if (qemuPrepareNVRAM(cfg, vm) < 0)
        goto cleanup;

    if (vm->def->vsock) {
        if (qemuProcessOpenVhostVsock(vm->def->vsock) < 0)
            goto cleanup;
    }
    /* network devices must be "prepared" before hostdevs, because
     * setting up a network device might create a new hostdev that
     * will need to be setup.
     */
    VIR_DEBUG("Preparing network devices");
    if (qemuProcessNetworkPrepareDevices(vm->def) < 0)
        goto cleanup;

    /* Must be run before security labelling */
    VIR_DEBUG("Preparing host devices");
    if (!cfg->relaxedACS)
        hostdev_flags |= VIR_HOSTDEV_STRICT_ACS_CHECK;
    if (flags & VIR_QEMU_PROCESS_START_NEW)
        hostdev_flags |= VIR_HOSTDEV_COLD_BOOT;
    if (qemuHostdevPrepareDomainDevices(driver, vm->def, priv->qemuCaps,
                                        hostdev_flags) < 0)
        goto cleanup;

    VIR_DEBUG("Preparing chr devices");
    if (virDomainChrDefForeach(vm->def,
                               true,
                               qemuProcessPrepareChardevDevice,
                               NULL) < 0)
        goto cleanup;

    if (qemuProcessBuildDestroyMemoryPaths(driver, vm, NULL, true) < 0)
        goto cleanup;

    /* Ensure no historical cgroup for this VM is lying around bogus
     * settings */
    VIR_DEBUG("Ensuring no historical cgroup is lying around");
    qemuRemoveCgroup(vm);

    if (virFileMakePath(cfg->logDir) < 0) {
        virReportSystemError(errno,
                             _("cannot create log directory %s"),
                             cfg->logDir);
        goto cleanup;
    }

    VIR_FREE(priv->pidfile);
    if (!(priv->pidfile = virPidFileBuildPath(cfg->stateDir, vm->def->name))) {
        virReportSystemError(errno,
                             "%s", _("Failed to build pidfile path."));
        goto cleanup;
    }

    if (unlink(priv->pidfile) < 0 &&
        errno != ENOENT) {
        virReportSystemError(errno,
                             _("Cannot remove stale PID file %s"),
                             priv->pidfile);
        goto cleanup;
    }

    /*
     * Create all per-domain directories in order to make sure domain
     * with any possible seclabels can access it.
     */
    if (qemuProcessMakeDir(driver, vm, priv->libDir) < 0 ||
        qemuProcessMakeDir(driver, vm, priv->channelTargetDir) < 0)
        goto cleanup;

    VIR_DEBUG("Write domain masterKey");
    if (qemuDomainWriteMasterKeyFile(driver, vm) < 0)
        goto cleanup;

    VIR_DEBUG("Preparing disks (host)");
    if (qemuProcessPrepareHostStorage(driver, vm, flags) < 0)
        goto cleanup;

    VIR_DEBUG("Preparing external devices");
    if (qemuExtDevicesPrepareHost(driver, vm->def) < 0)
        goto cleanup;

    if (qemuProcessPrepareSEVGuestInput(vm) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virObjectUnref(cfg);
    return ret;
}


/**
 * qemuProcessGenID:
 * @vm: Pointer to domain object
 * @flags: qemuProcessStartFlags
 *
 * If this domain is requesting to use genid, then update the GUID
 * value if the VIR_QEMU_PROCESS_START_GEN_VMID flag is set. This
 * flag is set on specific paths during domain start processing when
 * there is the possibility that the VM is potentially re-executing
 * something that has already been executed before.
 */
static int
qemuProcessGenID(virDomainObjPtr vm,
                 unsigned int flags)
{
    if (!vm->def->genidRequested)
        return 0;

    /* If we are coming from a path where we must provide a new gen id
     * value regardless of whether it was previously generated or provided,
     * then generate a new GUID value before we build the command line. */
    if (flags & VIR_QEMU_PROCESS_START_GEN_VMID) {
        if (virUUIDGenerate(vm->def->genid) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("failed to regenerate genid"));
            return -1;
        }
    }

    return 0;
}


/**
 * qemuProcessSetupDiskThrottlingBlockdev:
 *
 * Sets up disk trottling for -blockdev via block_set_io_throttle monitor
 * command. This hack should be replaced by proper use of the 'throttle'
 * blockdev driver in qemu once it will support changing of the throttle group.
 */
static int
qemuProcessSetupDiskThrottlingBlockdev(virQEMUDriverPtr driver,
                                       virDomainObjPtr vm,
                                       qemuDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    size_t i;
    int ret = -1;

    if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_BLOCKDEV))
        return 0;

    VIR_DEBUG("Setting up disk throttling for -blockdev via block_set_io_throttle");

    if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) < 0)
        return -1;

    for (i = 0; i < vm->def->ndisks; i++) {
        virDomainDiskDefPtr disk = vm->def->disks[i];
        qemuDomainDiskPrivatePtr diskPriv = QEMU_DOMAIN_DISK_PRIVATE(disk);

        if (!qemuDiskConfigBlkdeviotuneEnabled(disk))
            continue;

        if (qemuMonitorSetBlockIoThrottle(qemuDomainGetMonitor(vm), NULL,
                                          diskPriv->qomName, &disk->blkdeviotune,
                                          true, true, true) < 0)
            goto cleanup;
    }

    ret = 0;

 cleanup:
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        ret = -1;
    return ret;
}


/**
 * qemuProcessLaunch:
 *
 * Launch a new QEMU process with stopped virtual CPUs.
 *
 * The caller is supposed to call qemuProcessStop with appropriate
 * flags in case of failure.
 *
 * Returns 0 on success,
 *        -1 on error which happened before devices were labeled and thus
 *           there is no need to restore them,
 *        -2 on error requesting security labels to be restored.
 */
int
qemuProcessLaunch(virConnectPtr conn,
                  virQEMUDriverPtr driver,
                  virDomainObjPtr vm,
                  qemuDomainAsyncJob asyncJob,
                  qemuProcessIncomingDefPtr incoming,
                  virDomainMomentObjPtr snapshot,
                  virNetDevVPortProfileOp vmop,
                  unsigned int flags)
{
    int ret = -1;
    int rv;
    int logfile = -1;
    qemuDomainLogContextPtr logCtxt = NULL;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virCommandPtr cmd = NULL;
    struct qemuProcessHookData hookData;
    virQEMUDriverConfigPtr cfg;
    virCapsPtr caps = NULL;
    size_t nnicindexes = 0;
    int *nicindexes = NULL;
    size_t i;

    VIR_DEBUG("conn=%p driver=%p vm=%p name=%s if=%d asyncJob=%d "
              "incoming.launchURI=%s incoming.deferredURI=%s "
              "incoming.fd=%d incoming.path=%s "
              "snapshot=%p vmop=%d flags=0x%x",
              conn, driver, vm, vm->def->name, vm->def->id, asyncJob,
              NULLSTR(incoming ? incoming->launchURI : NULL),
              NULLSTR(incoming ? incoming->deferredURI : NULL),
              incoming ? incoming->fd : -1,
              NULLSTR(incoming ? incoming->path : NULL),
              snapshot, vmop, flags);

    /* Okay, these are just internal flags,
     * but doesn't hurt to check */
    virCheckFlags(VIR_QEMU_PROCESS_START_COLD |
                  VIR_QEMU_PROCESS_START_PAUSED |
                  VIR_QEMU_PROCESS_START_AUTODESTROY |
                  VIR_QEMU_PROCESS_START_NEW |
                  VIR_QEMU_PROCESS_START_GEN_VMID, -1);

    cfg = virQEMUDriverGetConfig(driver);

    if ((flags & VIR_QEMU_PROCESS_START_AUTODESTROY) && !conn) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Domain autodestroy requires a connection handle"));
        return -1;
    }

    hookData.vm = vm;
    hookData.driver = driver;
    /* We don't increase cfg's reference counter here. */
    hookData.cfg = cfg;

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    VIR_DEBUG("Creating domain log file");
    if (!(logCtxt = qemuDomainLogContextNew(driver, vm,
                                            QEMU_DOMAIN_LOG_CONTEXT_MODE_START))) {
        virLastErrorPrefixMessage("%s", _("can't connect to virtlogd"));
        goto cleanup;
    }
    logfile = qemuDomainLogContextGetWriteFD(logCtxt);

    if (qemuProcessGenID(vm, flags) < 0)
        goto cleanup;

    if (qemuExtDevicesStart(driver, vm, logCtxt) < 0)
        goto cleanup;

    VIR_DEBUG("Building emulator command line");
    if (!(cmd = qemuBuildCommandLine(driver,
                                     qemuDomainLogContextGetManager(logCtxt),
                                     driver->securityManager,
                                     vm,
                                     incoming ? incoming->launchURI : NULL,
                                     snapshot, vmop,
                                     false,
                                     qemuCheckFips(),
                                     &nnicindexes, &nicindexes)))
        goto cleanup;

    if (incoming && incoming->fd != -1)
        virCommandPassFD(cmd, incoming->fd, 0);

    /* now that we know it is about to start call the hook if present */
    if (qemuProcessStartHook(driver, vm,
                             VIR_HOOK_QEMU_OP_START,
                             VIR_HOOK_SUBOP_BEGIN) < 0)
        goto cleanup;

    qemuLogOperation(vm, "starting up", cmd, logCtxt);

    qemuDomainObjCheckTaint(driver, vm, logCtxt);

    qemuDomainLogContextMarkPosition(logCtxt);

    VIR_DEBUG("Building mount namespace");

    if (qemuDomainCreateNamespace(driver, vm) < 0)
        goto cleanup;

    VIR_DEBUG("Clear emulator capabilities: %d",
              cfg->clearEmulatorCapabilities);
    if (cfg->clearEmulatorCapabilities)
        virCommandClearCaps(cmd);

    VIR_DEBUG("Setting up raw IO");
    if (qemuProcessSetupRawIO(driver, vm, cmd) < 0)
        goto cleanup;

    virCommandSetPreExecHook(cmd, qemuProcessHook, &hookData);
    virCommandSetMaxProcesses(cmd, cfg->maxProcesses);
    virCommandSetMaxFiles(cmd, cfg->maxFiles);
    virCommandSetMaxCoreSize(cmd, cfg->maxCore);
    virCommandSetUmask(cmd, 0x002);

    VIR_DEBUG("Setting up security labelling");
    if (qemuSecuritySetChildProcessLabel(driver->securityManager,
                                         vm->def, cmd) < 0)
        goto cleanup;

    virCommandSetOutputFD(cmd, &logfile);
    virCommandSetErrorFD(cmd, &logfile);
    virCommandNonblockingFDs(cmd);
    virCommandSetPidFile(cmd, priv->pidfile);
    virCommandDaemonize(cmd);
    virCommandRequireHandshake(cmd);

    if (qemuSecurityPreFork(driver->securityManager) < 0)
        goto cleanup;
    rv = virCommandRun(cmd, NULL);
    qemuSecurityPostFork(driver->securityManager);

    /* wait for qemu process to show up */
    if (rv == 0) {
        if ((rv = virPidFileReadPath(priv->pidfile, &vm->pid)) < 0) {
            virReportSystemError(-rv,
                                 _("Domain %s didn't show up"),
                                 vm->def->name);
            goto cleanup;
        }
        VIR_DEBUG("QEMU vm=%p name=%s running with pid=%lld",
                  vm, vm->def->name, (long long)vm->pid);
    } else {
        VIR_DEBUG("QEMU vm=%p name=%s failed to spawn",
                  vm, vm->def->name);
        goto cleanup;
    }

    VIR_DEBUG("Writing early domain status to disk");
    if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm, driver->caps) < 0)
        goto cleanup;

    VIR_DEBUG("Waiting for handshake from child");
    if (virCommandHandshakeWait(cmd) < 0) {
        /* Read errors from child that occurred between fork and exec. */
        qemuProcessReportLogError(logCtxt,
                                  _("Process exited prior to exec"));
        goto cleanup;
    }

    VIR_DEBUG("Setting up domain cgroup (if required)");
    if (qemuSetupCgroup(vm, nnicindexes, nicindexes) < 0)
        goto cleanup;

    if (!(priv->perf = virPerfNew()))
        goto cleanup;

    for (i = 0; i < VIR_PERF_EVENT_LAST; i++) {
        if (vm->def->perf.events[i] == VIR_TRISTATE_BOOL_YES &&
            virPerfEventEnable(priv->perf, i, vm->pid) < 0)
            goto cleanup;
    }

    /* This must be done after cgroup placement to avoid resetting CPU
     * affinity */
    if (qemuProcessInitCpuAffinity(vm) < 0)
        goto cleanup;

    VIR_DEBUG("Setting emulator tuning/settings");
    if (qemuProcessSetupEmulator(vm) < 0)
        goto cleanup;

    VIR_DEBUG("Setting cgroup for external devices (if required)");
    if (qemuSetupCgroupForExtDevices(vm, driver) < 0)
        goto cleanup;

    VIR_DEBUG("Setting up resctrl");
    if (qemuProcessResctrlCreate(driver, vm) < 0)
        goto cleanup;

    VIR_DEBUG("Setting up managed PR daemon");
    if (virDomainDefHasManagedPR(vm->def) &&
        qemuProcessStartManagedPRDaemon(vm) < 0)
        goto cleanup;

    VIR_DEBUG("Setting domain security labels");
    if (qemuSecuritySetAllLabel(driver,
                                vm,
                                incoming ? incoming->path : NULL) < 0)
        goto cleanup;

    /* Security manager labeled all devices, therefore
     * if any operation from now on fails, we need to ask the caller to
     * restore labels.
     */
    ret = -2;

    if (incoming && incoming->fd != -1) {
        /* if there's an fd to migrate from, and it's a pipe, put the
         * proper security label on it
         */
        struct stat stdin_sb;

        VIR_DEBUG("setting security label on pipe used for migration");

        if (fstat(incoming->fd, &stdin_sb) < 0) {
            virReportSystemError(errno,
                                 _("cannot stat fd %d"), incoming->fd);
            goto cleanup;
        }
        if (S_ISFIFO(stdin_sb.st_mode) &&
            qemuSecuritySetImageFDLabel(driver->securityManager,
                                        vm->def, incoming->fd) < 0)
            goto cleanup;
    }

    VIR_DEBUG("Labelling done, completing handshake to child");
    if (virCommandHandshakeNotify(cmd) < 0)
        goto cleanup;
    VIR_DEBUG("Handshake complete, child running");

    if (rv == -1) /* The VM failed to start; tear filters before taps */
        virDomainConfVMNWFilterTeardown(vm);

    if (rv == -1) /* The VM failed to start */
        goto cleanup;

    VIR_DEBUG("Waiting for monitor to show up");
    if (qemuProcessWaitForMonitor(driver, vm, asyncJob, logCtxt) < 0)
        goto cleanup;

    if (qemuConnectAgent(driver, vm) < 0)
        goto cleanup;

    VIR_DEBUG("Verifying and updating provided guest CPU");
    if (qemuProcessUpdateAndVerifyCPU(driver, vm, asyncJob) < 0)
        goto cleanup;

    VIR_DEBUG("setting up hotpluggable cpus");
    if (qemuDomainHasHotpluggableStartupVcpus(vm->def)) {
        if (qemuDomainRefreshVcpuInfo(driver, vm, asyncJob, false) < 0)
            goto cleanup;

        if (qemuProcessValidateHotpluggableVcpus(vm->def) < 0)
            goto cleanup;

        if (qemuProcessSetupHotpluggableVcpus(driver, vm, asyncJob) < 0)
            goto cleanup;
    }

    VIR_DEBUG("Refreshing VCPU info");
    if (qemuDomainRefreshVcpuInfo(driver, vm, asyncJob, false) < 0)
        goto cleanup;

    if (qemuDomainValidateVcpuInfo(vm) < 0)
        goto cleanup;

    qemuDomainVcpuPersistOrder(vm->def);

    VIR_DEBUG("Detecting IOThread PIDs");
    if (qemuProcessDetectIOThreadPIDs(driver, vm, asyncJob) < 0)
        goto cleanup;

    VIR_DEBUG("Setting global CPU cgroup (if required)");
    if (qemuSetupGlobalCpuCgroup(vm) < 0)
        goto cleanup;

    VIR_DEBUG("Setting vCPU tuning/settings");
    if (qemuProcessSetupVcpus(vm) < 0)
        goto cleanup;

    VIR_DEBUG("Setting IOThread tuning/settings");
    if (qemuProcessSetupIOThreads(vm) < 0)
        goto cleanup;

    VIR_DEBUG("Setting emulator scheduler");
    if (vm->def->cputune.emulatorsched &&
        virProcessSetScheduler(vm->pid,
                               vm->def->cputune.emulatorsched->policy,
                               vm->def->cputune.emulatorsched->priority) < 0)
        goto cleanup;

    VIR_DEBUG("Setting any required VM passwords");
    if (qemuProcessInitPasswords(driver, vm, asyncJob) < 0)
        goto cleanup;

    /* set default link states */
    /* qemu doesn't support setting this on the command line, so
     * enter the monitor */
    VIR_DEBUG("Setting network link states");
    if (qemuProcessSetLinkStates(driver, vm, asyncJob) < 0)
        goto cleanup;

    VIR_DEBUG("Setting initial memory amount");
    if (qemuProcessSetupBalloon(driver, vm, asyncJob) < 0)
        goto cleanup;

    if (qemuProcessSetupDiskThrottlingBlockdev(driver, vm, asyncJob) < 0)
        goto cleanup;

    /* Since CPUs were not started yet, the balloon could not return the memory
     * to the host and thus cur_balloon needs to be updated so that GetXMLdesc
     * and friends return the correct size in case they can't grab the job */
    if (!incoming && !snapshot &&
        qemuProcessRefreshBalloonState(driver, vm, asyncJob) < 0)
        goto cleanup;

    if (flags & VIR_QEMU_PROCESS_START_AUTODESTROY &&
        qemuProcessAutoDestroyAdd(driver, vm, conn) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    if (ret < 0)
        qemuExtDevicesStop(driver, vm);
    qemuDomainSecretDestroy(vm);
    virCommandFree(cmd);
    virObjectUnref(logCtxt);
    virObjectUnref(cfg);
    virObjectUnref(caps);
    VIR_FREE(nicindexes);
    return ret;
}


/**
 * qemuProcessRefreshState:
 * @driver: qemu driver data
 * @vm: domain to refresh
 * @asyncJob: async job type
 *
 * This function gathers calls to refresh qemu state after startup. This
 * function is called after a deferred migration finishes so that we can update
 * state influenced by the migration stream.
 */
int
qemuProcessRefreshState(virQEMUDriverPtr driver,
                        virDomainObjPtr vm,
                        qemuDomainAsyncJob asyncJob)
{
    VIR_DEBUG("Fetching list of active devices");
    if (qemuDomainUpdateDeviceList(driver, vm, asyncJob) < 0)
        return -1;

    VIR_DEBUG("Updating info of memory devices");
    if (qemuDomainUpdateMemoryDeviceInfo(driver, vm, asyncJob) < 0)
        return -1;

    VIR_DEBUG("Detecting actual memory size for video device");
    if (qemuProcessUpdateVideoRamSize(driver, vm, asyncJob) < 0)
        return -1;

    VIR_DEBUG("Updating disk data");
    if (qemuProcessRefreshDisks(driver, vm, asyncJob) < 0)
        return -1;

    return 0;
}


/**
 * qemuProcessFinishStartup:
 *
 * Finish starting a new domain.
 */
int
qemuProcessFinishStartup(virQEMUDriverPtr driver,
                         virDomainObjPtr vm,
                         qemuDomainAsyncJob asyncJob,
                         bool startCPUs,
                         virDomainPausedReason pausedReason)
{
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    int ret = -1;

    if (startCPUs) {
        VIR_DEBUG("Starting domain CPUs");
        if (qemuProcessStartCPUs(driver, vm,
                                 VIR_DOMAIN_RUNNING_BOOTED,
                                 asyncJob) < 0) {
            if (virGetLastErrorCode() == VIR_ERR_OK)
                virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                               _("resume operation failed"));
            goto cleanup;
        }
    } else {
        virDomainObjSetState(vm, VIR_DOMAIN_PAUSED, pausedReason);
    }

    VIR_DEBUG("Writing domain status to disk");
    if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm, driver->caps) < 0)
        goto cleanup;

    if (qemuProcessStartHook(driver, vm,
                             VIR_HOOK_QEMU_OP_STARTED,
                             VIR_HOOK_SUBOP_BEGIN) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virObjectUnref(cfg);
    return ret;
}


int
qemuProcessStart(virConnectPtr conn,
                 virQEMUDriverPtr driver,
                 virDomainObjPtr vm,
                 virCPUDefPtr updatedCPU,
                 qemuDomainAsyncJob asyncJob,
                 const char *migrateFrom,
                 int migrateFd,
                 const char *migratePath,
                 virDomainMomentObjPtr snapshot,
                 virNetDevVPortProfileOp vmop,
                 unsigned int flags)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    qemuProcessIncomingDefPtr incoming = NULL;
    unsigned int stopFlags;
    bool relabel = false;
    int ret = -1;
    int rv;

    VIR_DEBUG("conn=%p driver=%p vm=%p name=%s id=%d asyncJob=%s "
              "migrateFrom=%s migrateFd=%d migratePath=%s "
              "snapshot=%p vmop=%d flags=0x%x",
              conn, driver, vm, vm->def->name, vm->def->id,
              qemuDomainAsyncJobTypeToString(asyncJob),
              NULLSTR(migrateFrom), migrateFd, NULLSTR(migratePath),
              snapshot, vmop, flags);

    virCheckFlagsGoto(VIR_QEMU_PROCESS_START_COLD |
                      VIR_QEMU_PROCESS_START_PAUSED |
                      VIR_QEMU_PROCESS_START_AUTODESTROY |
                      VIR_QEMU_PROCESS_START_GEN_VMID, cleanup);

    if (!migrateFrom && !snapshot)
        flags |= VIR_QEMU_PROCESS_START_NEW;

    if (qemuProcessInit(driver, vm, updatedCPU,
                        asyncJob, !!migrateFrom, flags) < 0)
        goto cleanup;

    if (migrateFrom) {
        incoming = qemuProcessIncomingDefNew(priv->qemuCaps, NULL, migrateFrom,
                                             migrateFd, migratePath);
        if (!incoming)
            goto stop;
    }

    if (qemuProcessPrepareDomain(driver, vm, flags) < 0)
        goto stop;

    if (qemuProcessPrepareHost(driver, vm, flags) < 0)
        goto stop;

    if ((rv = qemuProcessLaunch(conn, driver, vm, asyncJob, incoming,
                                snapshot, vmop, flags)) < 0) {
        if (rv == -2)
            relabel = true;
        goto stop;
    }
    relabel = true;

    if (incoming) {
        if (incoming->deferredURI &&
            qemuMigrationDstRun(driver, vm, incoming->deferredURI, asyncJob) < 0)
            goto stop;
    } else {
        /* Refresh state of devices from QEMU. During migration this happens
         * in qemuMigrationDstFinish to ensure that state information is fully
         * transferred. */
        if (qemuProcessRefreshState(driver, vm, asyncJob) < 0)
            goto stop;
    }

    if (qemuProcessFinishStartup(driver, vm, asyncJob,
                                 !(flags & VIR_QEMU_PROCESS_START_PAUSED),
                                 incoming ?
                                 VIR_DOMAIN_PAUSED_MIGRATION :
                                 VIR_DOMAIN_PAUSED_USER) < 0)
        goto stop;

    if (!incoming) {
        /* Keep watching qemu log for errors during incoming migration, otherwise
         * unset reporting errors from qemu log. */
        qemuMonitorSetDomainLog(priv->mon, NULL, NULL, NULL);
    }

    ret = 0;

 cleanup:
    qemuProcessIncomingDefFree(incoming);
    return ret;

 stop:
    stopFlags = 0;
    if (!relabel)
        stopFlags |= VIR_QEMU_PROCESS_STOP_NO_RELABEL;
    if (migrateFrom)
        stopFlags |= VIR_QEMU_PROCESS_STOP_MIGRATED;
    if (priv->mon)
        qemuMonitorSetDomainLog(priv->mon, NULL, NULL, NULL);
    qemuProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_FAILED, asyncJob, stopFlags);
    goto cleanup;
}


virCommandPtr
qemuProcessCreatePretendCmd(virQEMUDriverPtr driver,
                            virDomainObjPtr vm,
                            const char *migrateURI,
                            bool enableFips,
                            bool standalone,
                            unsigned int flags)
{
    virCommandPtr cmd = NULL;

    virCheckFlagsGoto(VIR_QEMU_PROCESS_START_COLD |
                      VIR_QEMU_PROCESS_START_PAUSED |
                      VIR_QEMU_PROCESS_START_AUTODESTROY, cleanup);

    flags |= VIR_QEMU_PROCESS_START_PRETEND;
    flags |= VIR_QEMU_PROCESS_START_NEW;
    if (standalone)
        flags |= VIR_QEMU_PROCESS_START_STANDALONE;

    if (qemuProcessInit(driver, vm, NULL, QEMU_ASYNC_JOB_NONE,
                        !!migrateURI, flags) < 0)
        goto cleanup;

    if (qemuProcessPrepareDomain(driver, vm, flags) < 0)
        goto cleanup;

    VIR_DEBUG("Building emulator command line");
    cmd = qemuBuildCommandLine(driver,
                               NULL,
                               driver->securityManager,
                               vm,
                               migrateURI,
                               NULL,
                               VIR_NETDEV_VPORT_PROFILE_OP_NO_OP,
                               standalone,
                               enableFips,
                               NULL,
                               NULL);

 cleanup:
    return cmd;
}


int
qemuProcessKill(virDomainObjPtr vm, unsigned int flags)
{
    int ret;

    VIR_DEBUG("vm=%p name=%s pid=%lld flags=0x%x",
              vm, vm->def->name,
              (long long)vm->pid, flags);

    if (!(flags & VIR_QEMU_PROCESS_KILL_NOCHECK)) {
        if (!virDomainObjIsActive(vm)) {
            VIR_DEBUG("VM '%s' not active", vm->def->name);
            return 0;
        }
    }

    if (flags & VIR_QEMU_PROCESS_KILL_NOWAIT) {
        virProcessKill(vm->pid,
                       (flags & VIR_QEMU_PROCESS_KILL_FORCE) ?
                       SIGKILL : SIGTERM);
        return 0;
    }

    /* Request an extra delay of two seconds per current nhostdevs
     * to be safe against stalls by the kernel freeing up the resources */
    ret = virProcessKillPainfullyDelay(vm->pid,
                                       !!(flags & VIR_QEMU_PROCESS_KILL_FORCE),
                                       vm->def->nhostdevs * 2);

    return ret;
}


/**
 * qemuProcessBeginStopJob:
 *
 * Stop all current jobs by killing the domain and start a new one for
 * qemuProcessStop.
 */
int
qemuProcessBeginStopJob(virQEMUDriverPtr driver,
                        virDomainObjPtr vm,
                        qemuDomainJob job,
                        bool forceKill)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    unsigned int killFlags = forceKill ? VIR_QEMU_PROCESS_KILL_FORCE : 0;
    int ret = -1;

    /* We need to prevent monitor EOF callback from doing our work (and
     * sending misleading events) while the vm is unlocked inside
     * BeginJob/ProcessKill API
     */
    priv->beingDestroyed = true;

    if (qemuProcessKill(vm, killFlags) < 0)
        goto cleanup;

    /* Wake up anything waiting on domain condition */
    virDomainObjBroadcast(vm);

    if (qemuDomainObjBeginJob(driver, vm, job) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    priv->beingDestroyed = false;
    return ret;
}


void qemuProcessStop(virQEMUDriverPtr driver,
                     virDomainObjPtr vm,
                     virDomainShutoffReason reason,
                     qemuDomainAsyncJob asyncJob,
                     unsigned int flags)
{
    int ret;
    int retries = 0;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virErrorPtr orig_err;
    virDomainDefPtr def;
    virNetDevVPortProfilePtr vport = NULL;
    size_t i;
    char *timestamp;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    virConnectPtr conn = NULL;

    VIR_DEBUG("Shutting down vm=%p name=%s id=%d pid=%lld, "
              "reason=%s, asyncJob=%s, flags=0x%x",
              vm, vm->def->name, vm->def->id,
              (long long)vm->pid,
              virDomainShutoffReasonTypeToString(reason),
              qemuDomainAsyncJobTypeToString(asyncJob),
              flags);

    /* This method is routinely used in clean up paths. Disable error
     * reporting so we don't squash a legit error. */
    orig_err = virSaveLastError();

    if (asyncJob != QEMU_ASYNC_JOB_NONE) {
        if (qemuDomainObjBeginNestedJob(driver, vm, asyncJob) < 0)
            goto cleanup;
    } else if (priv->job.asyncJob != QEMU_ASYNC_JOB_NONE &&
               priv->job.asyncOwner == virThreadSelfID() &&
               priv->job.active != QEMU_JOB_ASYNC_NESTED) {
        VIR_WARN("qemuProcessStop called without a nested job (async=%s)",
                 qemuDomainAsyncJobTypeToString(asyncJob));
    }

    if (!virDomainObjIsActive(vm)) {
        VIR_DEBUG("VM '%s' not active", vm->def->name);
        goto endjob;
    }

    qemuProcessBuildDestroyMemoryPaths(driver, vm, NULL, false);

    vm->def->id = -1;

    if (virAtomicIntDecAndTest(&driver->nactive) && driver->inhibitCallback)
        driver->inhibitCallback(false, driver->inhibitOpaque);

    /* Wake up anything waiting on domain condition */
    virDomainObjBroadcast(vm);

    if ((timestamp = virTimeStringNow()) != NULL) {
        qemuDomainLogAppendMessage(driver, vm, "%s: shutting down, reason=%s\n",
                                   timestamp,
                                   virDomainShutoffReasonTypeToString(reason));
        VIR_FREE(timestamp);
    }

    /* Clear network bandwidth */
    virDomainClearNetBandwidth(vm);

    virDomainConfVMNWFilterTeardown(vm);

    if (cfg->macFilter) {
        def = vm->def;
        for (i = 0; i < def->nnets; i++) {
            virDomainNetDefPtr net = def->nets[i];
            if (net->ifname == NULL)
                continue;
            ignore_value(ebtablesRemoveForwardAllowIn(driver->ebtables,
                                                      net->ifname,
                                                      &net->mac));
        }
    }

    virPortAllocatorRelease(priv->nbdPort);
    priv->nbdPort = 0;

    if (priv->agent) {
        qemuAgentClose(priv->agent);
        priv->agent = NULL;
    }
    priv->agentError = false;

    if (priv->mon) {
        qemuMonitorClose(priv->mon);
        priv->mon = NULL;
    }

    if (priv->monConfig) {
        if (priv->monConfig->type == VIR_DOMAIN_CHR_TYPE_UNIX)
            unlink(priv->monConfig->data.nix.path);
        virObjectUnref(priv->monConfig);
        priv->monConfig = NULL;
    }

    /* Remove the master key */
    qemuDomainMasterKeyRemove(priv);

    /* Do this before we delete the tree and remove pidfile. */
    qemuProcessKillManagedPRDaemon(vm);

    virFileDeleteTree(priv->libDir);
    virFileDeleteTree(priv->channelTargetDir);

    ignore_value(virDomainChrDefForeach(vm->def,
                                        false,
                                        qemuProcessCleanupChardevDevice,
                                        NULL));


    /* shut it off for sure */
    ignore_value(qemuProcessKill(vm,
                                 VIR_QEMU_PROCESS_KILL_FORCE|
                                 VIR_QEMU_PROCESS_KILL_NOCHECK));

    qemuDomainCleanupRun(driver, vm);

    qemuExtDevicesStop(driver, vm);

    /* Stop autodestroy in case guest is restarted */
    qemuProcessAutoDestroyRemove(driver, vm);

    /* now that we know it's stopped call the hook if present */
    if (virHookPresent(VIR_HOOK_DRIVER_QEMU)) {
        char *xml = qemuDomainDefFormatXML(driver, vm->def, 0);

        /* we can't stop the operation even if the script raised an error */
        ignore_value(virHookCall(VIR_HOOK_DRIVER_QEMU, vm->def->name,
                                 VIR_HOOK_QEMU_OP_STOPPED, VIR_HOOK_SUBOP_END,
                                 NULL, xml, NULL));
        VIR_FREE(xml);
    }

    /* Reset Security Labels unless caller don't want us to */
    if (!(flags & VIR_QEMU_PROCESS_STOP_NO_RELABEL))
        qemuSecurityRestoreAllLabel(driver, vm,
                                    !!(flags & VIR_QEMU_PROCESS_STOP_MIGRATED));

    qemuSecurityReleaseLabel(driver->securityManager, vm->def);

    for (i = 0; i < vm->def->ndisks; i++) {
        virDomainDeviceDef dev;
        virDomainDiskDefPtr disk = vm->def->disks[i];

        dev.type = VIR_DOMAIN_DEVICE_DISK;
        dev.data.disk = disk;
        ignore_value(qemuRemoveSharedDevice(driver, &dev, vm->def->name));
    }

    /* Clear out dynamically assigned labels */
    for (i = 0; i < vm->def->nseclabels; i++) {
        if (vm->def->seclabels[i]->type == VIR_DOMAIN_SECLABEL_DYNAMIC)
            VIR_FREE(vm->def->seclabels[i]->label);
        VIR_FREE(vm->def->seclabels[i]->imagelabel);
    }

    qemuHostdevReAttachDomainDevices(driver, vm->def);

    def = vm->def;
    for (i = 0; i < def->nnets; i++) {
        virDomainNetDefPtr net = def->nets[i];
        vport = virDomainNetGetActualVirtPortProfile(net);

        switch (virDomainNetGetActualType(net)) {
        case VIR_DOMAIN_NET_TYPE_DIRECT:
            ignore_value(virNetDevMacVLanDeleteWithVPortProfile(
                             net->ifname, &net->mac,
                             virDomainNetGetActualDirectDev(net),
                             virDomainNetGetActualDirectMode(net),
                             virDomainNetGetActualVirtPortProfile(net),
                             cfg->stateDir));
            break;
        case VIR_DOMAIN_NET_TYPE_ETHERNET:
            if (net->ifname) {
                ignore_value(virNetDevTapDelete(net->ifname, net->backend.tap));
                VIR_FREE(net->ifname);
            }
            break;
        case VIR_DOMAIN_NET_TYPE_BRIDGE:
        case VIR_DOMAIN_NET_TYPE_NETWORK:
#ifdef VIR_NETDEV_TAP_REQUIRE_MANUAL_CLEANUP
            if (!(vport && vport->virtPortType == VIR_NETDEV_VPORT_PROFILE_OPENVSWITCH))
                ignore_value(virNetDevTapDelete(net->ifname, net->backend.tap));
#endif
            break;
        case VIR_DOMAIN_NET_TYPE_USER:
        case VIR_DOMAIN_NET_TYPE_VHOSTUSER:
        case VIR_DOMAIN_NET_TYPE_SERVER:
        case VIR_DOMAIN_NET_TYPE_CLIENT:
        case VIR_DOMAIN_NET_TYPE_MCAST:
        case VIR_DOMAIN_NET_TYPE_INTERNAL:
        case VIR_DOMAIN_NET_TYPE_HOSTDEV:
        case VIR_DOMAIN_NET_TYPE_UDP:
        case VIR_DOMAIN_NET_TYPE_LAST:
            /* No special cleanup procedure for these types. */
            break;
        }
        /* release the physical device (or any other resources used by
         * this interface in the network driver
         */
        if (vport) {
            if (vport->virtPortType == VIR_NETDEV_VPORT_PROFILE_MIDONET) {
                ignore_value(virNetDevMidonetUnbindPort(vport));
            } else if (vport->virtPortType == VIR_NETDEV_VPORT_PROFILE_OPENVSWITCH) {
                ignore_value(virNetDevOpenvswitchRemovePort(
                                 virDomainNetGetActualBridgeName(net),
                                 net->ifname));
            }
        }

        /* kick the device out of the hostdev list too */
        virDomainNetRemoveHostdev(def, net);
        if (net->type == VIR_DOMAIN_NET_TYPE_NETWORK) {
            if (conn || (conn = virGetConnectNetwork()))
                virDomainNetReleaseActualDevice(conn, vm->def, net);
            else
                VIR_WARN("Unable to release network device '%s'", NULLSTR(net->ifname));
        }
    }

 retry:
    if ((ret = qemuRemoveCgroup(vm)) < 0) {
        if (ret == -EBUSY && (retries++ < 5)) {
            usleep(200*1000);
            goto retry;
        }
        VIR_WARN("Failed to remove cgroup for %s",
                 vm->def->name);
    }

    /* Remove resctrl allocation after cgroups are cleaned up which makes it
     * kind of safer (although removing the allocation should work even with
     * pids in tasks file */
    for (i = 0; i < vm->def->nresctrls; i++) {
        size_t j = 0;

        for (j = 0; j < vm->def->resctrls[i]->nmonitors; j++) {
            virDomainResctrlMonDefPtr mon = NULL;

            mon = vm->def->resctrls[i]->monitors[j];
            virResctrlMonitorRemove(mon->instance);
        }

        virResctrlAllocRemove(vm->def->resctrls[i]->alloc);
    }

    qemuProcessRemoveDomainStatus(driver, vm);

    /* Remove VNC and Spice ports from port reservation bitmap, but only if
       they were reserved by the driver (autoport=yes)
    */
    for (i = 0; i < vm->def->ngraphics; ++i) {
        virDomainGraphicsDefPtr graphics = vm->def->graphics[i];
        if (graphics->type == VIR_DOMAIN_GRAPHICS_TYPE_VNC) {
            if (graphics->data.vnc.autoport) {
                virPortAllocatorRelease(graphics->data.vnc.port);
            } else if (graphics->data.vnc.portReserved) {
                virPortAllocatorRelease(graphics->data.vnc.port);
                graphics->data.vnc.portReserved = false;
            }
            if (graphics->data.vnc.websocketGenerated) {
                virPortAllocatorRelease(graphics->data.vnc.websocket);
                graphics->data.vnc.websocketGenerated = false;
                graphics->data.vnc.websocket = -1;
            } else if (graphics->data.vnc.websocket) {
                virPortAllocatorRelease(graphics->data.vnc.websocket);
            }
        }
        if (graphics->type == VIR_DOMAIN_GRAPHICS_TYPE_SPICE) {
            if (graphics->data.spice.autoport) {
                virPortAllocatorRelease(graphics->data.spice.port);
                virPortAllocatorRelease(graphics->data.spice.tlsPort);
            } else {
                if (graphics->data.spice.portReserved) {
                    virPortAllocatorRelease(graphics->data.spice.port);
                    graphics->data.spice.portReserved = false;
                }

                if (graphics->data.spice.tlsPortReserved) {
                    virPortAllocatorRelease(graphics->data.spice.tlsPort);
                    graphics->data.spice.tlsPortReserved = false;
                }
            }
        }
    }

    vm->taint = 0;
    vm->pid = -1;
    virDomainObjSetState(vm, VIR_DOMAIN_SHUTOFF, reason);
    for (i = 0; i < vm->def->niothreadids; i++)
        vm->def->iothreadids[i]->thread_id = 0;

    /* clear all private data entries which are no longer needed */
    qemuDomainObjPrivateDataClear(priv);

    /* reset node name allocator */
    qemuDomainStorageIdReset(priv);

    /* The "release" hook cleans up additional resources */
    if (virHookPresent(VIR_HOOK_DRIVER_QEMU)) {
        char *xml = qemuDomainDefFormatXML(driver, vm->def, 0);

        /* we can't stop the operation even if the script raised an error */
        virHookCall(VIR_HOOK_DRIVER_QEMU, vm->def->name,
                    VIR_HOOK_QEMU_OP_RELEASE, VIR_HOOK_SUBOP_END,
                    NULL, xml, NULL);
        VIR_FREE(xml);
    }

    virDomainObjRemoveTransientDef(vm);

 endjob:
    if (asyncJob != QEMU_ASYNC_JOB_NONE)
        qemuDomainObjEndJob(driver, vm);

 cleanup:
    if (orig_err) {
        virSetError(orig_err);
        virFreeError(orig_err);
    }
    virObjectUnref(conn);
    virObjectUnref(cfg);
}


static void
qemuProcessAutoDestroy(virDomainObjPtr dom,
                       virConnectPtr conn,
                       void *opaque)
{
    virQEMUDriverPtr driver = opaque;
    qemuDomainObjPrivatePtr priv = dom->privateData;
    virObjectEventPtr event = NULL;
    unsigned int stopFlags = 0;

    VIR_DEBUG("vm=%s, conn=%p", dom->def->name, conn);

    if (priv->job.asyncJob == QEMU_ASYNC_JOB_MIGRATION_IN)
        stopFlags |= VIR_QEMU_PROCESS_STOP_MIGRATED;

    if (priv->job.asyncJob) {
        VIR_DEBUG("vm=%s has long-term job active, cancelling",
                  dom->def->name);
        qemuDomainObjDiscardAsyncJob(driver, dom);
    }

    VIR_DEBUG("Killing domain");

    if (qemuProcessBeginStopJob(driver, dom, QEMU_JOB_DESTROY, true) < 0)
        return;

    qemuProcessStop(driver, dom, VIR_DOMAIN_SHUTOFF_DESTROYED,
                    QEMU_ASYNC_JOB_NONE, stopFlags);

    virDomainAuditStop(dom, "destroyed");
    event = virDomainEventLifecycleNewFromObj(dom,
                                     VIR_DOMAIN_EVENT_STOPPED,
                                     VIR_DOMAIN_EVENT_STOPPED_DESTROYED);

    qemuDomainRemoveInactive(driver, dom);

    qemuDomainObjEndJob(driver, dom);

    virObjectEventStateQueue(driver->domainEventState, event);
}

int qemuProcessAutoDestroyAdd(virQEMUDriverPtr driver,
                              virDomainObjPtr vm,
                              virConnectPtr conn)
{
    VIR_DEBUG("vm=%s, conn=%p", vm->def->name, conn);
    return virCloseCallbacksSet(driver->closeCallbacks, vm, conn,
                                qemuProcessAutoDestroy);
}

int qemuProcessAutoDestroyRemove(virQEMUDriverPtr driver,
                                 virDomainObjPtr vm)
{
    int ret;
    VIR_DEBUG("vm=%s", vm->def->name);
    ret = virCloseCallbacksUnset(driver->closeCallbacks, vm,
                                 qemuProcessAutoDestroy);
    return ret;
}

bool qemuProcessAutoDestroyActive(virQEMUDriverPtr driver,
                                  virDomainObjPtr vm)
{
    virCloseCallback cb;
    VIR_DEBUG("vm=%s", vm->def->name);
    cb = virCloseCallbacksGet(driver->closeCallbacks, vm, NULL);
    return cb == qemuProcessAutoDestroy;
}


int
qemuProcessRefreshDisks(virQEMUDriverPtr driver,
                        virDomainObjPtr vm,
                        qemuDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    bool blockdev = virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_BLOCKDEV);
    virHashTablePtr table = NULL;
    int ret = -1;
    size_t i;

    if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) == 0) {
        table = qemuMonitorGetBlockInfo(priv->mon);
        if (qemuDomainObjExitMonitor(driver, vm) < 0)
            goto cleanup;
    }

    if (!table)
        goto cleanup;

    for (i = 0; i < vm->def->ndisks; i++) {
        virDomainDiskDefPtr disk = vm->def->disks[i];
        qemuDomainDiskPrivatePtr diskpriv = QEMU_DOMAIN_DISK_PRIVATE(disk);
        struct qemuDomainDiskInfo *info;
        const char *entryname = disk->info.alias;

        if (blockdev)
            entryname = diskpriv->qomName;

        if (!(info = virHashLookup(table, entryname)))
            continue;

        if (info->removable) {
            if (info->empty)
                virDomainDiskEmptySource(disk);

            if (info->tray) {
                if (info->tray_open)
                    disk->tray_status = VIR_DOMAIN_DISK_TRAY_OPEN;
                else
                    disk->tray_status = VIR_DOMAIN_DISK_TRAY_CLOSED;
            }
        }

        /* fill in additional data */
        diskpriv->removable = info->removable;
        diskpriv->tray = info->tray;
    }

    ret = 0;

 cleanup:
    virHashFree(table);
    return ret;
}


static int
qemuProcessRefreshCPU(virQEMUDriverPtr driver,
                      virDomainObjPtr vm)
{
    virCapsPtr caps = virQEMUDriverGetCapabilities(driver, false);
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virCPUDefPtr host = NULL;
    virCPUDefPtr cpu = NULL;
    int ret = -1;

    if (!caps)
        return -1;

    if (!virQEMUCapsGuestIsNative(caps->host.arch, vm->def->os.arch) ||
        !caps->host.cpu ||
        !vm->def->cpu) {
        ret = 0;
        goto cleanup;
    }

    /* If the domain with a host-model CPU was started by an old libvirt
     * (< 2.3) which didn't replace the CPU with a custom one, let's do it now
     * since the rest of our code does not really expect a host-model CPU in a
     * running domain.
     */
    if (vm->def->cpu->mode == VIR_CPU_MODE_HOST_MODEL) {
        if (!(host = virCPUCopyMigratable(caps->host.cpu->arch, caps->host.cpu)))
            goto cleanup;

        if (!(cpu = virCPUDefCopyWithoutModel(host)) ||
            virCPUDefCopyModelFilter(cpu, host, false,
                                     virQEMUCapsCPUFilterFeatures,
                                     &caps->host.cpu->arch) < 0)
            goto cleanup;

        if (virCPUUpdate(vm->def->os.arch, vm->def->cpu, cpu) < 0)
            goto cleanup;

        if (qemuProcessUpdateCPU(driver, vm, QEMU_ASYNC_JOB_NONE) < 0)
            goto cleanup;
    } else if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_QUERY_CPU_MODEL_EXPANSION)) {
        /* We only try to fix CPUs when the libvirt/QEMU combo used to start
         * the domain did not know about query-cpu-model-expansion in which
         * case the host-model is known to not contain features which QEMU
         * doesn't know about.
         */
        if (qemuDomainFixupCPUs(vm, &priv->origCPU) < 0)
            goto cleanup;
    }

    ret = 0;

 cleanup:
    virCPUDefFree(cpu);
    virCPUDefFree(host);
    virObjectUnref(caps);
    return ret;
}


static int
qemuProcessRefreshLegacyBlockjob(void *payload,
                                 const void *name,
                                 void *opaque)
{
    const char *jobname = name;
    virDomainObjPtr vm = opaque;
    qemuMonitorBlockJobInfoPtr info = payload;
    virDomainDiskDefPtr disk;
    qemuBlockJobDataPtr job;
    qemuBlockJobType jobtype = info->type;
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (!(disk = qemuProcessFindDomainDiskByAliasOrQOM(vm, jobname, jobname))) {
        VIR_DEBUG("could not find disk for block job '%s'", jobname);
        return 0;
    }

    if (jobtype == QEMU_BLOCKJOB_TYPE_COMMIT &&
        disk->mirrorJob == VIR_DOMAIN_BLOCK_JOB_TYPE_ACTIVE_COMMIT)
        jobtype = disk->mirrorJob;

    if (!(job = qemuBlockJobDiskNew(disk, jobtype, jobname)))
        return -1;

    qemuBlockJobStarted(job);

    if (disk->mirror) {
        if (info->ready == 1 ||
            (info->ready == -1 && info->end == info->cur)) {
            disk->mirrorState = VIR_DOMAIN_DISK_MIRROR_STATE_READY;
            job->state = VIR_DOMAIN_BLOCK_JOB_READY;
        }

        /* Pre-blockdev block copy labelled the chain of the mirrored device
         * just before pivoting. At that point it was no longer known whether
         * it's even necessary (e.g. disk is being reused). This code fixes
         * the labelling in case the job was started in a libvirt version
         * which did not label the chain when the block copy is being started.
         * Note that we can't do much on failure. */
        if (disk->mirrorJob == VIR_DOMAIN_BLOCK_JOB_TYPE_COPY) {
            if (qemuDomainDetermineDiskChain(priv->driver, vm, disk,
                                             disk->mirror, true) < 0)
                goto cleanup;

            if (disk->mirror->format &&
                disk->mirror->format != VIR_STORAGE_FILE_RAW &&
                (qemuDomainNamespaceSetupDisk(vm, disk->mirror) < 0 ||
                 qemuSetupImageChainCgroup(vm, disk->mirror) < 0 ||
                 qemuSecuritySetImageLabel(priv->driver, vm, disk->mirror,
                                           true) < 0))
                goto cleanup;
        }
    }

 cleanup:
    qemuBlockJobStartupFinalize(job);

    return 0;
}


static int
qemuProcessRefreshLegacyBlockjobs(virQEMUDriverPtr driver,
                                  virDomainObjPtr vm)
{
    virHashTablePtr blockJobs = NULL;
    int ret = -1;

    qemuDomainObjEnterMonitor(driver, vm);
    blockJobs = qemuMonitorGetAllBlockJobInfo(qemuDomainGetMonitor(vm), true);
    if (qemuDomainObjExitMonitor(driver, vm) < 0 || !blockJobs)
        goto cleanup;

    if (virHashForEach(blockJobs, qemuProcessRefreshLegacyBlockjob, vm) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virHashFree(blockJobs);
    return ret;
}


static int
qemuProcessRefreshBlockjobs(virQEMUDriverPtr driver,
                            virDomainObjPtr vm)
{
    return qemuProcessRefreshLegacyBlockjobs(driver, vm);
}


struct qemuProcessReconnectData {
    virQEMUDriverPtr driver;
    virDomainObjPtr obj;
    virIdentityPtr identity;
};
/*
 * Open an existing VM's monitor, re-detect VCPU threads
 * and re-reserve the security labels in use
 *
 * This function also inherits a locked and ref'd domain object.
 *
 * This function needs to:
 * 1. Enter job
 * 1. just before monitor reconnect do lightweight MonitorEnter
 *    (increase VM refcount and unlock VM)
 * 2. reconnect to monitor
 * 3. do lightweight MonitorExit (lock VM)
 * 4. continue reconnect process
 * 5. EndJob
 *
 * We can't do normal MonitorEnter & MonitorExit because these two lock the
 * monitor lock, which does not exists in this early phase.
 */
static void
qemuProcessReconnect(void *opaque)
{
    struct qemuProcessReconnectData *data = opaque;
    virQEMUDriverPtr driver = data->driver;
    virDomainObjPtr obj = data->obj;
    qemuDomainObjPrivatePtr priv;
    qemuDomainJobObj oldjob;
    int state;
    int reason;
    virQEMUDriverConfigPtr cfg;
    size_t i;
    unsigned int stopFlags = 0;
    bool jobStarted = false;
    virCapsPtr caps = NULL;
    bool retry = true;
    bool tryMonReconn = false;

    virIdentitySetCurrent(data->identity);
    virObjectUnref(data->identity);
    VIR_FREE(data);

    qemuDomainObjRestoreJob(obj, &oldjob);
    if (oldjob.asyncJob == QEMU_ASYNC_JOB_MIGRATION_IN)
        stopFlags |= VIR_QEMU_PROCESS_STOP_MIGRATED;

    cfg = virQEMUDriverGetConfig(driver);
    priv = obj->privateData;

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto error;

    if (qemuDomainObjBeginJob(driver, obj, QEMU_JOB_MODIFY) < 0)
        goto error;
    jobStarted = true;

    /* XXX If we ever gonna change pid file pattern, come up with
     * some intelligence here to deal with old paths. */
    if (!(priv->pidfile = virPidFileBuildPath(cfg->stateDir, obj->def->name)))
        goto error;

    /* Restore the masterKey */
    if (qemuDomainMasterKeyReadFile(priv) < 0)
        goto error;

    /* If we are connecting to a guest started by old libvirt there is no
     * allowReboot in status XML and we need to initialize it. */
    qemuProcessPrepareAllowReboot(obj);

    if (qemuHostdevUpdateActiveDomainDevices(driver, obj->def) < 0)
        goto error;

    if (priv->qemuCaps &&
        virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_CHARDEV_FD_PASS))
        retry = false;

    VIR_DEBUG("Reconnect monitor to def=%p name='%s' retry=%d",
              obj, obj->def->name, retry);

    tryMonReconn = true;

    /* XXX check PID liveliness & EXE path */
    if (qemuConnectMonitor(driver, obj, QEMU_ASYNC_JOB_NONE, retry, NULL) < 0)
        goto error;

    priv->machineName = qemuDomainGetMachineName(obj);
    if (!priv->machineName)
        goto error;

    if (qemuConnectCgroup(obj) < 0)
        goto error;

    if (qemuDomainPerfRestart(obj) < 0)
        goto error;

    /* XXX: Need to change as long as lock is introduced for
     * qemu_driver->sharedDevices.
     */
    for (i = 0; i < obj->def->ndisks; i++) {
        virDomainDiskDefPtr disk = obj->def->disks[i];
        virDomainDeviceDef dev;

        if (virDomainDiskTranslateSourcePool(disk) < 0)
            goto error;

        /* backing chains need to be refreshed only if they could change */
        if (priv->reconnectBlockjobs != VIR_TRISTATE_BOOL_NO &&
            !virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_BLOCKDEV)) {
            /* This should be the only place that calls
             * qemuDomainDetermineDiskChain with @report_broken == false
             * to guarantee best-effort domain reconnect */
            virStorageSourceBackingStoreClear(disk->src);
            if (qemuDomainDetermineDiskChain(driver, obj, disk, NULL, false) < 0)
                goto error;
        } else {
            VIR_DEBUG("skipping backing chain detection for '%s'", disk->dst);
        }

        dev.type = VIR_DOMAIN_DEVICE_DISK;
        dev.data.disk = disk;
        if (qemuAddSharedDevice(driver, &dev, obj->def->name) < 0)
            goto error;
    }

    for (i = 0; i < obj->def->ngraphics; i++) {
        if (qemuProcessGraphicsReservePorts(obj->def->graphics[i], true) < 0)
            goto error;
    }

    if (qemuProcessUpdateState(driver, obj) < 0)
        goto error;

    state = virDomainObjGetState(obj, &reason);
    if (state == VIR_DOMAIN_SHUTOFF ||
        (state == VIR_DOMAIN_PAUSED &&
         reason == VIR_DOMAIN_PAUSED_STARTING_UP)) {
        VIR_DEBUG("Domain '%s' wasn't fully started yet, killing it",
                  obj->def->name);
        goto error;
    }

    /* If upgrading from old libvirtd we won't have found any
     * caps in the domain status, so re-query them
     */
    if (!priv->qemuCaps &&
        (qemuDomainUpdateQEMUCaps(obj, driver->qemuCapsCache) < 0))
        goto error;

    /* In case the domain shutdown while we were not running,
     * we need to finish the shutdown process. And we need to do it after
     * we have virQEMUCaps filled in.
     */
    if (state == VIR_DOMAIN_SHUTDOWN ||
        (state == VIR_DOMAIN_PAUSED &&
         reason == VIR_DOMAIN_PAUSED_SHUTTING_DOWN)) {
        VIR_DEBUG("Finishing shutdown sequence for domain %s",
                  obj->def->name);
        qemuProcessShutdownOrReboot(driver, obj);
        goto cleanup;
    }

    if (qemuProcessBuildDestroyMemoryPaths(driver, obj, NULL, true) < 0)
        goto error;

    if ((qemuDomainAssignAddresses(obj->def, priv->qemuCaps,
                                   driver, obj, false)) < 0) {
        goto error;
    }

    /* if domain requests security driver we haven't loaded, report error, but
     * do not kill the domain
     */
    ignore_value(qemuSecurityCheckAllLabel(driver->securityManager,
                                           obj->def));

    if (qemuProcessRefreshCPU(driver, obj) < 0)
        goto error;

    if (qemuDomainRefreshVcpuInfo(driver, obj, QEMU_ASYNC_JOB_NONE, true) < 0)
        goto error;

    qemuDomainVcpuPersistOrder(obj->def);

    if (qemuProcessDetectIOThreadPIDs(driver, obj, QEMU_ASYNC_JOB_NONE) < 0)
        goto error;

    if (qemuSecurityReserveLabel(driver->securityManager, obj->def, obj->pid) < 0)
        goto error;

    qemuProcessNotifyNets(obj->def);

    qemuProcessFiltersInstantiate(obj->def);

    if (qemuProcessRefreshDisks(driver, obj, QEMU_ASYNC_JOB_NONE) < 0)
        goto error;

    if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_BLOCKDEV) &&
        qemuBlockNodeNamesDetect(driver, obj, QEMU_ASYNC_JOB_NONE) < 0)
        goto error;

    if (qemuProcessRefreshBlockjobs(driver, obj) < 0)
        goto error;

    if (qemuRefreshVirtioChannelState(driver, obj, QEMU_ASYNC_JOB_NONE) < 0)
        goto error;

    /* If querying of guest's RTC failed, report error, but do not kill the domain. */
    qemuRefreshRTC(driver, obj);

    if (qemuProcessRefreshBalloonState(driver, obj, QEMU_ASYNC_JOB_NONE) < 0)
        goto error;

    if (qemuProcessRecoverJob(driver, obj, &oldjob, &stopFlags) < 0)
        goto error;

    if (qemuProcessUpdateDevices(driver, obj) < 0)
        goto error;

    if (qemuRefreshPRManagerState(driver, obj) < 0)
        goto error;

    qemuProcessReconnectCheckMemAliasOrderMismatch(obj);

    if (qemuConnectAgent(driver, obj) < 0)
        goto error;

    for (i = 0; i < obj->def->nresctrls; i++) {
        size_t j = 0;

        if (virResctrlAllocDeterminePath(obj->def->resctrls[i]->alloc,
                                         priv->machineName) < 0)
            goto error;

        for (j = 0; j < obj->def->resctrls[i]->nmonitors; j++) {
            virDomainResctrlMonDefPtr mon = NULL;

            mon = obj->def->resctrls[i]->monitors[j];
            if (virResctrlMonitorDeterminePath(mon->instance,
                                               priv->machineName) < 0)
                goto error;
        }
    }

    /* update domain state XML with possibly updated state in virDomainObj */
    if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, obj, driver->caps) < 0)
        goto error;

    /* Run an hook to allow admins to do some magic */
    if (virHookPresent(VIR_HOOK_DRIVER_QEMU)) {
        char *xml = qemuDomainDefFormatXML(driver, obj->def, 0);
        int hookret;

        hookret = virHookCall(VIR_HOOK_DRIVER_QEMU, obj->def->name,
                              VIR_HOOK_QEMU_OP_RECONNECT, VIR_HOOK_SUBOP_BEGIN,
                              NULL, xml, NULL);
        VIR_FREE(xml);

        /*
         * If the script raised an error abort the launch
         */
        if (hookret < 0)
            goto error;
    }

    if (virAtomicIntInc(&driver->nactive) == 1 && driver->inhibitCallback)
        driver->inhibitCallback(true, driver->inhibitOpaque);

 cleanup:
    if (jobStarted) {
        if (!virDomainObjIsActive(obj))
            qemuDomainRemoveInactive(driver, obj);
        qemuDomainObjEndJob(driver, obj);
    } else {
        if (!virDomainObjIsActive(obj))
            qemuDomainRemoveInactiveJob(driver, obj);
    }
    virDomainObjEndAPI(&obj);
    virObjectUnref(cfg);
    virObjectUnref(caps);
    virNWFilterUnlockFilterUpdates();
    virIdentitySetCurrent(NULL);
    return;

 error:
    if (virDomainObjIsActive(obj)) {
        /* We can't get the monitor back, so must kill the VM
         * to remove danger of it ending up running twice if
         * user tries to start it again later.
         *
         * If we cannot get to the monitor when the QEMU command
         * line used -no-shutdown, then we can safely say that the
         * domain crashed; otherwise, if the monitor was started,
         * then we can blame ourselves, else we failed before the
         * monitor started so we don't really know. */
        if (!priv->mon && tryMonReconn &&
            qemuDomainIsUsingNoShutdown(priv))
            state = VIR_DOMAIN_SHUTOFF_CRASHED;
        else if (priv->mon)
            state = VIR_DOMAIN_SHUTOFF_DAEMON;
        else
            state = VIR_DOMAIN_SHUTOFF_UNKNOWN;

        /* If BeginJob failed, we jumped here without a job, let's hope another
         * thread didn't have a chance to start playing with the domain yet
         * (it's all we can do anyway).
         */
        qemuProcessStop(driver, obj, state, QEMU_ASYNC_JOB_NONE, stopFlags);
    }
    goto cleanup;
}

static int
qemuProcessReconnectHelper(virDomainObjPtr obj,
                           void *opaque)
{
    virThread thread;
    struct qemuProcessReconnectData *src = opaque;
    struct qemuProcessReconnectData *data;

    /* If the VM was inactive, we don't need to reconnect */
    if (!obj->pid)
        return 0;

    if (VIR_ALLOC(data) < 0)
        return -1;

    memcpy(data, src, sizeof(*data));
    data->obj = obj;
    data->identity = virIdentityGetCurrent();

    virNWFilterReadLockFilterUpdates();

    /* this lock and reference will be eventually transferred to the thread
     * that handles the reconnect */
    virObjectLock(obj);
    virObjectRef(obj);

    if (virThreadCreate(&thread, false, qemuProcessReconnect, data) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not create thread. QEMU initialization "
                         "might be incomplete"));
        /* We can't spawn a thread and thus connect to monitor. Kill qemu.
         * It's safe to call qemuProcessStop without a job here since there
         * is no thread that could be doing anything else with the same domain
         * object.
         */
        qemuProcessStop(src->driver, obj, VIR_DOMAIN_SHUTOFF_FAILED,
                        QEMU_ASYNC_JOB_NONE, 0);
        qemuDomainRemoveInactiveJobLocked(src->driver, obj);

        virDomainObjEndAPI(&obj);
        virNWFilterUnlockFilterUpdates();
        virObjectUnref(data->identity);
        VIR_FREE(data);
        return -1;
    }

    return 0;
}

/**
 * qemuProcessReconnectAll
 *
 * Try to re-open the resources for live VMs that we care
 * about.
 */
void
qemuProcessReconnectAll(virQEMUDriverPtr driver)
{
    struct qemuProcessReconnectData data = {.driver = driver};
    virDomainObjListForEach(driver->domains, qemuProcessReconnectHelper, &data);
}


static void virQEMUCapsMonitorNotify(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                                     virDomainObjPtr vm ATTRIBUTE_UNUSED,
                                     void *opaque ATTRIBUTE_UNUSED)
{
}

static qemuMonitorCallbacks callbacks = {
    .eofNotify = virQEMUCapsMonitorNotify,
    .errorNotify = virQEMUCapsMonitorNotify,
};


static void
qemuProcessQMPStop(qemuProcessQMPPtr proc)
{
    if (proc->mon) {
        virObjectUnlock(proc->mon);
        qemuMonitorClose(proc->mon);
        proc->mon = NULL;
    }

    if (proc->cmd) {
        virCommandAbort(proc->cmd);
        virCommandFree(proc->cmd);
        proc->cmd = NULL;
    }

    if (proc->monpath)
        unlink(proc->monpath);

    virDomainObjEndAPI(&proc->vm);

    if (proc->pid != 0) {
        char ebuf[1024];

        VIR_DEBUG("Killing QMP caps process %lld", (long long)proc->pid);
        if (virProcessKill(proc->pid, SIGKILL) < 0 && errno != ESRCH)
            VIR_ERROR(_("Failed to kill process %lld: %s"),
                      (long long)proc->pid,
                      virStrerror(errno, ebuf, sizeof(ebuf)));

        proc->pid = 0;
    }

    if (proc->pidfile)
        unlink(proc->pidfile);

    if (proc->uniqDir)
        rmdir(proc->uniqDir);
}


/**
 * qemuProcessQMPFree:
 * @proc: Stores process and connection state
 *
 * Kill QEMU process and free process data structure.
 */
void
qemuProcessQMPFree(qemuProcessQMPPtr proc)
{
    if (!proc)
        return;

    qemuProcessQMPStop(proc);
    VIR_FREE(proc->binary);
    VIR_FREE(proc->libDir);
    VIR_FREE(proc->uniqDir);
    VIR_FREE(proc->monpath);
    VIR_FREE(proc->monarg);
    VIR_FREE(proc->pidfile);
    VIR_FREE(proc->stderr);
    VIR_FREE(proc);
}


/**
 * qemuProcessQMPNew:
 * @binary: QEMU binary
 * @libDir: Directory for process and connection artifacts
 * @runUid: UserId for QEMU process
 * @runGid: GroupId for QEMU process
 * @forceTCG: Force TCG mode if true
 *
 * Allocate and initialize domain structure encapsulating QEMU process state
 * and monitor connection for completing QMP queries.
 */
qemuProcessQMPPtr
qemuProcessQMPNew(const char *binary,
                  const char *libDir,
                  uid_t runUid,
                  gid_t runGid,
                  bool forceTCG)
{
    qemuProcessQMPPtr ret = NULL;
    qemuProcessQMPPtr proc = NULL;

    VIR_DEBUG("exec=%s, libDir=%s, runUid=%u, runGid=%u, forceTCG=%d",
              binary, libDir, runUid, runGid, forceTCG);

    if (VIR_ALLOC(proc) < 0)
        goto cleanup;

    if (VIR_STRDUP(proc->binary, binary) < 0 ||
        VIR_STRDUP(proc->libDir, libDir) < 0)
        goto cleanup;

    proc->runUid = runUid;
    proc->runGid = runGid;
    proc->forceTCG = forceTCG;

    VIR_STEAL_PTR(ret, proc);

 cleanup:
    qemuProcessQMPFree(proc);
    return ret;
}


static int
qemuProcessQEMULabelUniqPath(qemuProcessQMPPtr proc)
{
    /* We cannot use the security driver here, but we should not need to. */
    if (chown(proc->uniqDir, proc->runUid, -1) < 0) {
        virReportSystemError(errno,
                             _("Cannot chown uniq path: %s"),
                             proc->uniqDir);
        return -1;
    }

    return 0;
}


static int
qemuProcessQMPInit(qemuProcessQMPPtr proc)
{
    char *template = NULL;
    int ret = -1;

    VIR_DEBUG("proc=%p, emulator=%s", proc, proc->binary);

    if (virAsprintf(&template, "%s/qmp-XXXXXX", proc->libDir) < 0)
        goto cleanup;

    if (!(proc->uniqDir = mkdtemp(template))) {
        virReportSystemError(errno,
                             _("Failed to create unique directory with "
                               "template '%s' for probing QEMU"),
                             template);
        goto cleanup;
    }

    if (qemuProcessQEMULabelUniqPath(proc) < 0)
        goto cleanup;

    if (virAsprintf(&proc->monpath, "%s/%s", proc->uniqDir,
                    "qmp.monitor") < 0)
        goto cleanup;

    if (virAsprintf(&proc->monarg, "unix:%s,server,nowait", proc->monpath) < 0)
        goto cleanup;

    /*
     * Normally we'd use runDir for pid files, but because we're using
     * -daemonize we need QEMU to be allowed to create them, rather
     * than libvirtd. So we're using libDir which QEMU can write to
     */
    if (virAsprintf(&proc->pidfile, "%s/%s", proc->uniqDir, "qmp.pid") < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    return ret;
}


static int
qemuProcessQMPLaunch(qemuProcessQMPPtr proc)
{
    const char *machine;
    int status = 0;
    int ret = -1;
    int rc;

    if (proc->forceTCG)
        machine = "none,accel=tcg";
    else
        machine = "none,accel=kvm:tcg";

    VIR_DEBUG("Try to probe capabilities of '%s' via QMP, machine %s",
              proc->binary, machine);

    /*
     * We explicitly need to use -daemonize here, rather than
     * virCommandDaemonize, because we need to synchronize
     * with QEMU creating its monitor socket API. Using
     * daemonize guarantees control won't return to libvirt
     * until the socket is present.
     */
    proc->cmd = virCommandNewArgList(proc->binary,
                                     "-S",
                                     "-no-user-config",
                                     "-nodefaults",
                                     "-nographic",
                                     "-machine", machine,
                                     "-qmp", proc->monarg,
                                     "-pidfile", proc->pidfile,
                                     "-daemonize",
                                    NULL);
    virCommandAddEnvPassCommon(proc->cmd);
    virCommandClearCaps(proc->cmd);

#if WITH_CAPNG
    /* QEMU might run into permission issues, e.g. /dev/sev (0600), override
     * them just for the purpose of probing */
    if (geteuid() == 0)
        virCommandAllowCap(proc->cmd, CAP_DAC_OVERRIDE);
#endif

    virCommandSetGID(proc->cmd, proc->runGid);
    virCommandSetUID(proc->cmd, proc->runUid);

    virCommandSetErrorBuffer(proc->cmd, &(proc->stderr));

    if (virCommandRun(proc->cmd, &status) < 0)
        goto cleanup;

    if (status != 0) {
        VIR_DEBUG("QEMU %s exited with status %d", proc->binary, status);
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to start QEMU binary %s for probing: %s"),
                       proc->binary,
                       proc->stderr ? proc->stderr : _("unknown error"));
        goto cleanup;
    }

    if ((rc = virPidFileReadPath(proc->pidfile, &proc->pid)) < 0) {
        virReportSystemError(-rc, _("Failed to read pidfile %s"), proc->pidfile);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    return ret;
}


int
qemuProcessQMPInitMonitor(qemuMonitorPtr mon)
{
    if (qemuMonitorSetCapabilities(mon) < 0) {
        VIR_DEBUG("Failed to set monitor capabilities %s",
                  virGetLastErrorMessage());
        return -1;
    }

    return 0;
}


static int
qemuProcessQMPConnectMonitor(qemuProcessQMPPtr proc)
{
    virDomainXMLOptionPtr xmlopt = NULL;
    virDomainChrSourceDef monConfig;
    int ret = -1;

    VIR_DEBUG("proc=%p, emulator=%s, proc->pid=%lld",
              proc, proc->binary, (long long)proc->pid);

    monConfig.type = VIR_DOMAIN_CHR_TYPE_UNIX;
    monConfig.data.nix.path = proc->monpath;
    monConfig.data.nix.listen = false;

    if (!(xmlopt = virDomainXMLOptionNew(NULL, NULL, NULL, NULL, NULL)) ||
        !(proc->vm = virDomainObjNew(xmlopt)))
        goto cleanup;

    proc->vm->pid = proc->pid;

    if (!(proc->mon = qemuMonitorOpen(proc->vm, &monConfig, true,
                                      0, &callbacks, NULL)))
        goto cleanup;

    virObjectLock(proc->mon);

    if (qemuProcessQMPInitMonitor(proc->mon) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virObjectUnref(xmlopt);
    return ret;
}


/**
 * qemuProcessQMPStart:
 * @proc: QEMU process and connection state created by qemuProcessQMPNew()
 *
 * Start and connect to QEMU binary so QMP queries can be made.
 *
 * Usage:
 *   proc = qemuProcessQMPNew(binary, libDir, runUid, runGid, forceTCG);
 *   qemuProcessQMPStart(proc);
 *   ** Send QMP Queries to QEMU using monitor (proc->mon) **
 *   qemuProcessQMPFree(proc);
 *
 * Process error output (proc->stderr) remains available in qemuProcessQMP
 * struct until qemuProcessQMPFree is called.
 */
int
qemuProcessQMPStart(qemuProcessQMPPtr proc)
{
    int ret = -1;

    VIR_DEBUG("proc=%p, emulator=%s", proc, proc->binary);

    if (qemuProcessQMPInit(proc) < 0)
        goto cleanup;

    if (qemuProcessQMPLaunch(proc) < 0)
        goto cleanup;

    if (qemuProcessQMPConnectMonitor(proc) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    return ret;
}
