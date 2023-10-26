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
#include "qemu_namespace.h"
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
#include "qemu_backup.h"
#include "qemu_dbus.h"
#include "qemu_snapshot.h"

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
#include "domain_cgroup.h"
#include "domain_nwfilter.h"
#include "domain_postparse.h"
#include "domain_validate.h"
#include "locking/domain_lock.h"
#include "viruuid.h"
#include "virprocess.h"
#include "virtime.h"
#include "virnetdevtap.h"
#include "virnetdevopenvswitch.h"
#include "virnetdevmidonet.h"
#include "virbitmap.h"
#include "virnuma.h"
#include "virstring.h"
#include "virhostdev.h"
#include "configmake.h"
#include "netdev_bandwidth_conf.h"
#include "virresctrl.h"
#include "virvsock.h"
#include "viridentity.h"
#include "virthreadjob.h"
#include "virutil.h"
#include "storage_source.h"
#include "backup_conf.h"

#include "logging/log_manager.h"
#include "logging/log_protocol.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_process");

/**
 * qemuProcessRemoveDomainStatus
 *
 * remove all state files of a domain from statedir
 */
static void
qemuProcessRemoveDomainStatus(virQEMUDriver *driver,
                              virDomainObj *vm)
{
    g_autofree char *file = NULL;
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);

    file = g_strdup_printf("%s/%s.xml", cfg->stateDir, vm->def->name);

    if (unlink(file) < 0 && errno != ENOENT && errno != ENOTDIR)
        VIR_WARN("Failed to remove domain XML for %s: %s",
                 vm->def->name, g_strerror(errno));

    if (priv->pidfile &&
        unlink(priv->pidfile) < 0 &&
        errno != ENOENT)
        VIR_WARN("Failed to remove PID file for %s: %s",
                 vm->def->name, g_strerror(errno));
}


/*
 * This is a callback registered with a qemuAgent *instance,
 * and to be invoked when the agent console hits an end of file
 * condition, or error, thus indicating VM shutdown should be
 * performed
 */
static void
qemuProcessHandleAgentEOF(qemuAgent *agent,
                          virDomainObj *vm)
{
    qemuDomainObjPrivate *priv;

    virObjectLock(vm);
    VIR_DEBUG("Received EOF from agent on %p '%s'", vm, vm->def->name);

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
qemuProcessHandleAgentError(qemuAgent *agent G_GNUC_UNUSED,
                            virDomainObj *vm)
{
    qemuDomainObjPrivate *priv;

    virObjectLock(vm);
    VIR_DEBUG("Received error from agent on %p '%s'", vm, vm->def->name);

    priv = vm->privateData;

    priv->agentError = true;

    virObjectUnlock(vm);
}


static qemuAgentCallbacks agentCallbacks = {
    .eofNotify = qemuProcessHandleAgentEOF,
    .errorNotify = qemuProcessHandleAgentError,
};


int
qemuConnectAgent(virQEMUDriver *driver, virDomainObj *vm)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    qemuAgent *agent = NULL;
    virDomainChrDef *config = qemuFindAgentConfig(vm->def);

    if (!config)
        return 0;

    if (priv->agent)
        return 0;

    if (config->state != VIR_DOMAIN_CHR_DEVICE_STATE_CONNECTED) {
        VIR_DEBUG("Deferring connecting to guest agent");
        return 0;
    }

    if (qemuSecuritySetDaemonSocketLabel(driver->securityManager, vm->def) < 0) {
        VIR_ERROR(_("Failed to set security context for agent for %1$s"),
                  vm->def->name);
        goto cleanup;
    }

    agent = qemuAgentOpen(vm,
                          config->source,
                          virEventThreadGetContext(priv->eventThread),
                          &agentCallbacks);

    if (!virDomainObjIsActive(vm)) {
        qemuAgentClose(agent);
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("guest crashed while connecting to the guest agent"));
        return -1;
    }

    if (qemuSecurityClearSocketLabel(driver->securityManager, vm->def) < 0) {
        VIR_ERROR(_("Failed to clear security context for agent for %1$s"),
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


/**
 * qemuProcessEventSubmit:
 * @vm: pointer to the domain object, the function will take an extra reference
 * @eventType: the event to be processed
 * @action: event specific action to be taken
 * @status: event specific status
 * @data: additional data for the event processor (the pointer is stolen and it
 *        will be properly freed
 *
 * Submits @eventType to be processed by the asynchronous event handling thread.
 */
static void
qemuProcessEventSubmit(virDomainObj *vm,
                       qemuProcessEventType eventType,
                       int action,
                       int status,
                       void *data)
{
    struct qemuProcessEvent *event = g_new0(struct qemuProcessEvent, 1);
    virQEMUDriver *driver = QEMU_DOMAIN_PRIVATE(vm)->driver;

    event->vm = virObjectRef(vm);
    event->eventType = eventType;
    event->action = action;
    event->status = status;
    event->data = data;

    if (virThreadPoolSendJob(driver->workerPool, 0, event) < 0) {
        virObjectUnref(event->vm);
        qemuProcessEventFree(event);
    }
}


/*
 * This is a callback registered with a qemuMonitor *instance,
 * and to be invoked when the monitor console hits an end of file
 * condition, or error, thus indicating VM shutdown should be
 * performed
 */
static void
qemuProcessHandleMonitorEOF(qemuMonitor *mon,
                            virDomainObj *vm)
{
    qemuDomainObjPrivate *priv;

    virObjectLock(vm);

    VIR_DEBUG("Received EOF on %p '%s'", vm, vm->def->name);

    priv = vm->privateData;
    if (priv->beingDestroyed) {
        VIR_DEBUG("Domain is being destroyed, EOF is expected");
        goto cleanup;
    }

    qemuProcessEventSubmit(vm, QEMU_PROCESS_EVENT_MONITOR_EOF,
                           0, 0, NULL);

    /* We don't want this EOF handler to be called over and over while the
     * thread is waiting for a job.
     */
    virObjectLock(mon);
    qemuMonitorUnregister(mon);
    virObjectUnlock(mon);

    /* We don't want any cleanup from EOF handler (or any other
     * thread) to enter qemu namespace. */
    qemuDomainDestroyNamespace(priv->driver, vm);

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
qemuProcessHandleMonitorError(qemuMonitor *mon G_GNUC_UNUSED,
                              virDomainObj *vm)
{
    qemuDomainObjPrivate *priv;
    virObjectEvent *event = NULL;

    virObjectLock(vm);
    VIR_DEBUG("Received error on %p '%s'", vm, vm->def->name);

    priv = vm->privateData;
    priv->monError = true;
    event = virDomainEventControlErrorNewFromObj(vm);
    virObjectEventStateQueue(priv->driver->domainEventState, event);

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
virDomainDiskDef *
qemuProcessFindDomainDiskByAliasOrQOM(virDomainObj *vm,
                                      const char *alias,
                                      const char *qomid)
{
    size_t i;

    if (alias && *alias == '\0')
        alias = NULL;

    if (alias)
        alias = qemuAliasDiskDriveSkipPrefix(alias);

    for (i = 0; i < vm->def->ndisks; i++) {
        virDomainDiskDef *disk = vm->def->disks[i];
        qemuDomainDiskPrivate *diskPriv = QEMU_DOMAIN_DISK_PRIVATE(disk);

        if ((disk->info.alias && STREQ_NULLABLE(disk->info.alias, alias)) ||
            (diskPriv->qomName && STREQ_NULLABLE(diskPriv->qomName, qomid)))
            return disk;
    }

    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("no disk found with alias '%1$s' or id '%2$s'"),
                   NULLSTR(alias), NULLSTR(qomid));
    return NULL;
}


static void
qemuProcessHandleReset(qemuMonitor *mon G_GNUC_UNUSED,
                       virDomainObj *vm)
{
    virQEMUDriver *driver;
    virObjectEvent *event = NULL;
    qemuDomainObjPrivate *priv;
    virDomainState state;
    int reason;

    virObjectLock(vm);
    priv = vm->privateData;
    driver = priv->driver;

    state = virDomainObjGetState(vm, &reason);

    /* ignore reset events on VM startup. Libvirt in certain instances does a
     * reset during startup so that the ACPI tables are re-generated */
    if (state == VIR_DOMAIN_PAUSED &&
        reason == VIR_DOMAIN_PAUSED_STARTING_UP) {
        VIR_DEBUG("ignoring reset event during startup");
        goto unlock;
    }

    event = virDomainEventRebootNewFromObj(vm);
    if (priv->agent)
        qemuAgentNotifyEvent(priv->agent, QEMU_AGENT_EVENT_RESET);

    qemuDomainSetFakeReboot(vm, false);
    qemuDomainSaveStatus(vm);

    qemuProcessEventSubmit(vm, QEMU_PROCESS_EVENT_RESET, 0, 0, NULL);

 unlock:
    virObjectUnlock(vm);
    virObjectEventStateQueue(driver->domainEventState, event);
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
    virDomainObj *vm = opaque;
    qemuDomainObjPrivate *priv = vm->privateData;
    virQEMUDriver *driver = priv->driver;
    virDomainRunningReason reason = VIR_DOMAIN_RUNNING_BOOTED;
    int ret = -1, rc;

    VIR_DEBUG("vm=%p", vm);
    virObjectLock(vm);
    if (virDomainObjBeginJob(vm, VIR_JOB_MODIFY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("guest unexpectedly quit"));
        goto endjob;
    }

    qemuDomainObjEnterMonitor(vm);
    rc = qemuMonitorSystemReset(priv->mon);

    qemuDomainObjExitMonitor(vm);

    if (rc < 0)
        goto endjob;

    if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_CRASHED)
        reason = VIR_DOMAIN_RUNNING_CRASHED;

    if (qemuProcessStartCPUs(driver, vm,
                             reason,
                             VIR_ASYNC_JOB_NONE) < 0) {
        if (virGetLastErrorCode() == VIR_ERR_OK)
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("resume operation failed"));
        goto endjob;
    }

    qemuDomainSaveStatus(vm);
    ret = 0;

 endjob:
    virDomainObjEndJob(vm);

 cleanup:
    priv->pausedShutdown = false;
    qemuDomainSetFakeReboot(vm, false);
    if (ret == -1)
        ignore_value(qemuProcessKill(vm, VIR_QEMU_PROCESS_KILL_FORCE));
    virDomainObjEndAPI(&vm);
}


void
qemuProcessShutdownOrReboot(virDomainObj *vm)
{
    qemuDomainObjPrivate *priv = vm->privateData;

    if (priv->fakeReboot ||
        vm->def->onPoweroff == VIR_DOMAIN_LIFECYCLE_ACTION_RESTART) {
        g_autofree char *name = g_strdup_printf("reboot-%s", vm->def->name);
        virThread th;

        virObjectRef(vm);
        if (virThreadCreateFull(&th,
                                false,
                                qemuProcessFakeReboot,
                                name,
                                false,
                                vm) < 0) {
            VIR_ERROR(_("Failed to create reboot thread, killing domain"));
            ignore_value(qemuProcessKill(vm, VIR_QEMU_PROCESS_KILL_NOWAIT));
            priv->pausedShutdown = false;
            qemuDomainSetFakeReboot(vm, false);
            virObjectUnref(vm);
        }
    } else {
        ignore_value(qemuProcessKill(vm, VIR_QEMU_PROCESS_KILL_NOWAIT));
    }
}


static void
qemuProcessHandleEvent(qemuMonitor *mon G_GNUC_UNUSED,
                       virDomainObj *vm,
                       const char *eventName,
                       long long seconds,
                       unsigned int micros,
                       const char *details)
{
    virQEMUDriver *driver;
    virObjectEvent *event = NULL;

    VIR_DEBUG("vm=%p", vm);

    virObjectLock(vm);
    driver = QEMU_DOMAIN_PRIVATE(vm)->driver;
    event = virDomainQemuMonitorEventNew(vm->def->id, vm->def->name,
                                         vm->def->uuid, eventName,
                                         seconds, micros, details);

    virObjectUnlock(vm);
    virObjectEventStateQueue(driver->domainEventState, event);
}


static void
qemuProcessHandleShutdown(qemuMonitor *mon G_GNUC_UNUSED,
                          virDomainObj *vm,
                          virTristateBool guest_initiated)
{
    virQEMUDriver *driver;
    qemuDomainObjPrivate *priv;
    virObjectEvent *event = NULL;
    int detail = 0;

    VIR_DEBUG("vm=%p", vm);

    virObjectLock(vm);

    priv = vm->privateData;
    driver = priv->driver;

    if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_SHUTDOWN) {
        VIR_DEBUG("Ignoring repeated SHUTDOWN event from domain %s",
                  vm->def->name);
        goto unlock;
    } else if (!virDomainObjIsActive(vm)) {
        VIR_DEBUG("Ignoring SHUTDOWN event from inactive domain %s",
                  vm->def->name);
        goto unlock;
    }

    /* In case of fake reboot qemu shutdown state is transient so don't
     * change domain state nor send events. */
    if (!priv->fakeReboot &&
        vm->def->onPoweroff != VIR_DOMAIN_LIFECYCLE_ACTION_RESTART) {
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
        qemuDomainSaveStatus(vm);
    } else {
        priv->pausedShutdown = true;
    }

    if (priv->agent)
        qemuAgentNotifyEvent(priv->agent, QEMU_AGENT_EVENT_SHUTDOWN);

    qemuProcessShutdownOrReboot(vm);

 unlock:
    virObjectUnlock(vm);
    virObjectEventStateQueue(driver->domainEventState, event);
}


static void
qemuProcessHandleStop(qemuMonitor *mon G_GNUC_UNUSED,
                      virDomainObj *vm)
{
    virQEMUDriver *driver;
    virObjectEvent *event = NULL;
    virDomainPausedReason reason;
    virDomainEventSuspendedDetailType detail;
    qemuDomainObjPrivate *priv = vm->privateData;

    virObjectLock(vm);

    driver = priv->driver;
    reason = priv->pausedReason;
    priv->pausedReason = VIR_DOMAIN_PAUSED_UNKNOWN;

    /* In case of fake reboot qemu paused state is transient so don't
     * reveal it in domain state nor sent events */
    if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_RUNNING &&
        !priv->pausedShutdown) {
        if (vm->job->asyncJob == VIR_ASYNC_JOB_MIGRATION_OUT) {
            if (vm->job->current->status == VIR_DOMAIN_JOB_STATUS_POSTCOPY)
                reason = VIR_DOMAIN_PAUSED_POSTCOPY;
            else
                reason = VIR_DOMAIN_PAUSED_MIGRATION;
        }

        detail = qemuDomainPausedReasonToSuspendedEvent(reason);
        VIR_DEBUG("Transitioned guest %s to paused state, "
                  "reason %s, event detail %d",
                  vm->def->name, virDomainPausedReasonTypeToString(reason),
                  detail);

        if (vm->job->current)
            ignore_value(virTimeMillisNow(&vm->job->current->stopped));

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

        qemuDomainSaveStatus(vm);
    }

    virObjectUnlock(vm);
    virObjectEventStateQueue(driver->domainEventState, event);
}


static void
qemuProcessHandleResume(qemuMonitor *mon G_GNUC_UNUSED,
                        virDomainObj *vm)
{
    virQEMUDriver *driver;
    virObjectEvent *event = NULL;
    qemuDomainObjPrivate *priv;
    virDomainRunningReason reason = VIR_DOMAIN_RUNNING_UNPAUSED;
    virDomainEventResumedDetailType eventDetail;

    virObjectLock(vm);

    priv = vm->privateData;
    driver = priv->driver;

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

        /* When a domain is running in (failed) post-copy migration on the
         * destination host, we need to make sure to set the appropriate reason
         * here. */
        if (virDomainObjIsPostcopy(vm, vm->job)) {
            if (virDomainObjIsFailedPostcopy(vm, vm->job))
                reason = VIR_DOMAIN_RUNNING_POSTCOPY_FAILED;
            else
                reason = VIR_DOMAIN_RUNNING_POSTCOPY;
        }
        virDomainObjSetState(vm, VIR_DOMAIN_RUNNING, reason);
        event = virDomainEventLifecycleNewFromObj(vm,
                                                  VIR_DOMAIN_EVENT_RESUMED,
                                                  eventDetail);
        qemuDomainSaveStatus(vm);
    }

    virObjectUnlock(vm);
    virObjectEventStateQueue(driver->domainEventState, event);
}

static void
qemuProcessHandleRTCChange(qemuMonitor *mon G_GNUC_UNUSED,
                           virDomainObj *vm,
                           long long offset)
{
    virQEMUDriver *driver;
    virObjectEvent *event = NULL;

    virObjectLock(vm);
    driver = QEMU_DOMAIN_PRIVATE(vm)->driver;

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

        qemuDomainSaveStatus(vm);
    }

    event = virDomainEventRTCChangeNewFromObj(vm, offset);

    virObjectUnlock(vm);

    virObjectEventStateQueue(driver->domainEventState, event);
}


static void
qemuProcessHandleWatchdog(qemuMonitor *mon G_GNUC_UNUSED,
                          virDomainObj *vm,
                          int action)
{
    virQEMUDriver *driver;
    virObjectEvent *watchdogEvent = NULL;
    virObjectEvent *lifecycleEvent = NULL;

    virObjectLock(vm);
    driver = QEMU_DOMAIN_PRIVATE(vm)->driver;
    watchdogEvent = virDomainEventWatchdogNewFromObj(vm, action);

    if (action == VIR_DOMAIN_EVENT_WATCHDOG_PAUSE &&
        virDomainObjGetState(vm, NULL) == VIR_DOMAIN_RUNNING) {
        qemuDomainObjPrivate *priv = vm->privateData;
        VIR_DEBUG("Transitioned guest %s to paused state due to watchdog", vm->def->name);

        virDomainObjSetState(vm, VIR_DOMAIN_PAUSED, VIR_DOMAIN_PAUSED_WATCHDOG);
        lifecycleEvent = virDomainEventLifecycleNewFromObj(vm,
                                                  VIR_DOMAIN_EVENT_SUSPENDED,
                                                  VIR_DOMAIN_EVENT_SUSPENDED_WATCHDOG);

        VIR_FREE(priv->lockState);
        if (virDomainLockProcessPause(driver->lockManager, vm, &priv->lockState) < 0)
            VIR_WARN("Unable to release lease on %s", vm->def->name);
        VIR_DEBUG("Preserving lock state '%s'", NULLSTR(priv->lockState));

        qemuDomainSaveStatus(vm);
    }

    if (vm->def->nwatchdogs &&
        vm->def->watchdogs[0]->action == VIR_DOMAIN_WATCHDOG_ACTION_DUMP) {
        qemuProcessEventSubmit(vm, QEMU_PROCESS_EVENT_WATCHDOG,
                               VIR_DOMAIN_WATCHDOG_ACTION_DUMP, 0, NULL);
    }

    virObjectUnlock(vm);
    virObjectEventStateQueue(driver->domainEventState, watchdogEvent);
    virObjectEventStateQueue(driver->domainEventState, lifecycleEvent);
}


static void
qemuProcessHandleIOError(qemuMonitor *mon G_GNUC_UNUSED,
                         virDomainObj *vm,
                         const char *diskAlias,
                         const char *nodename,
                         int action,
                         const char *reason)
{
    virQEMUDriver *driver;
    virObjectEvent *ioErrorEvent = NULL;
    virObjectEvent *ioErrorEvent2 = NULL;
    virObjectEvent *lifecycleEvent = NULL;
    const char *srcPath;
    const char *devAlias;
    virDomainDiskDef *disk;

    virObjectLock(vm);
    driver = QEMU_DOMAIN_PRIVATE(vm)->driver;

    if (*diskAlias == '\0')
        diskAlias = NULL;

    if (diskAlias)
        disk = qemuProcessFindDomainDiskByAliasOrQOM(vm, diskAlias, NULL);
    else if (nodename)
        disk = qemuDomainDiskLookupByNodename(vm->def, NULL, nodename, NULL);
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
        qemuDomainObjPrivate *priv = vm->privateData;
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

        qemuDomainSaveStatus(vm);
    }
    virObjectUnlock(vm);

    virObjectEventStateQueue(driver->domainEventState, ioErrorEvent);
    virObjectEventStateQueue(driver->domainEventState, ioErrorEvent2);
    virObjectEventStateQueue(driver->domainEventState, lifecycleEvent);
}


static void
qemuProcessHandleJobStatusChange(qemuMonitor *mon G_GNUC_UNUSED,
                                 virDomainObj *vm,
                                 const char *jobname,
                                 int status)
{
    qemuDomainObjPrivate *priv;
    qemuBlockJobData *job = NULL;
    int jobnewstate;

    virObjectLock(vm);
    priv = vm->privateData;

    VIR_DEBUG("job '%s'(domain: %p,%s) state changed to '%s'(%d)",
              jobname, vm, vm->def->name,
              qemuMonitorJobStatusTypeToString(status), status);

    if ((jobnewstate = qemuBlockjobConvertMonitorStatus(status)) == QEMU_BLOCKJOB_STATE_LAST)
        goto cleanup;

    if (!(job = virHashLookup(priv->blockjobs, jobname))) {
        VIR_DEBUG("job '%s' not registered", jobname);
        goto cleanup;
    }

    job->newstate = jobnewstate;

    if (job->synchronous) {
        VIR_DEBUG("job '%s' handled synchronously", jobname);
        virDomainObjBroadcast(vm);
    } else {
        VIR_DEBUG("job '%s' handled by event thread", jobname);
        qemuProcessEventSubmit(vm, QEMU_PROCESS_EVENT_JOB_STATUS_CHANGE,
                               0, 0, virObjectRef(job));
    }

 cleanup:
    virObjectUnlock(vm);
}


static void
qemuProcessHandleGraphics(qemuMonitor *mon G_GNUC_UNUSED,
                          virDomainObj *vm,
                          int phase,
                          int localFamily,
                          const char *localNode,
                          const char *localService,
                          int remoteFamily,
                          const char *remoteNode,
                          const char *remoteService,
                          const char *authScheme,
                          const char *x509dname,
                          const char *saslUsername)
{
    virQEMUDriver *driver;
    virObjectEvent *event;
    virDomainEventGraphicsAddressPtr localAddr = NULL;
    virDomainEventGraphicsAddressPtr remoteAddr = NULL;
    virDomainEventGraphicsSubjectPtr subject = NULL;

    localAddr = g_new0(virDomainEventGraphicsAddress, 1);
    localAddr->family = localFamily;
    localAddr->service = g_strdup(localService);
    localAddr->node = g_strdup(localNode);

    remoteAddr = g_new0(virDomainEventGraphicsAddress, 1);
    remoteAddr->family = remoteFamily;
    remoteAddr->service = g_strdup(remoteService);
    remoteAddr->node = g_strdup(remoteNode);

    subject = g_new0(virDomainEventGraphicsSubject, 1);
    if (x509dname) {
        VIR_REALLOC_N(subject->identities, subject->nidentity+1);
        subject->nidentity++;
        subject->identities[subject->nidentity - 1].type = g_strdup("x509dname");
        subject->identities[subject->nidentity - 1].name = g_strdup(x509dname);
    }
    if (saslUsername) {
        VIR_REALLOC_N(subject->identities, subject->nidentity+1);
        subject->nidentity++;
        subject->identities[subject->nidentity - 1].type = g_strdup("saslUsername");
        subject->identities[subject->nidentity - 1].name = g_strdup(saslUsername);
    }

    virObjectLock(vm);
    driver = QEMU_DOMAIN_PRIVATE(vm)->driver;
    event = virDomainEventGraphicsNewFromObj(vm, phase, localAddr, remoteAddr, authScheme, subject);
    virObjectUnlock(vm);

    virObjectEventStateQueue(driver->domainEventState, event);
}

static void
qemuProcessHandleTrayChange(qemuMonitor *mon G_GNUC_UNUSED,
                            virDomainObj *vm,
                            const char *devAlias,
                            const char *devid,
                            int reason)
{
    virQEMUDriver *driver;
    virObjectEvent *event = NULL;
    virDomainDiskDef *disk;

    virObjectLock(vm);
    driver = QEMU_DOMAIN_PRIVATE(vm)->driver;
    disk = qemuProcessFindDomainDiskByAliasOrQOM(vm, devAlias, devid);

    if (disk) {
        event = virDomainEventTrayChangeNewFromObj(vm, disk->info.alias, reason);
        /* Update disk tray status */
        if (reason == VIR_DOMAIN_EVENT_TRAY_CHANGE_OPEN)
            disk->tray_status = VIR_DOMAIN_DISK_TRAY_OPEN;
        else if (reason == VIR_DOMAIN_EVENT_TRAY_CHANGE_CLOSE)
            disk->tray_status = VIR_DOMAIN_DISK_TRAY_CLOSED;

        qemuDomainSaveStatus(vm);
        virDomainObjBroadcast(vm);
    }

    virObjectUnlock(vm);
    virObjectEventStateQueue(driver->domainEventState, event);
}

static void
qemuProcessHandlePMWakeup(qemuMonitor *mon G_GNUC_UNUSED,
                          virDomainObj *vm)
{
    virQEMUDriver *driver;
    virObjectEvent *event = NULL;
    virObjectEvent *lifecycleEvent = NULL;

    virObjectLock(vm);
    driver = QEMU_DOMAIN_PRIVATE(vm)->driver;
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
        qemuDomainSaveStatus(vm);
    }

    virObjectUnlock(vm);
    virObjectEventStateQueue(driver->domainEventState, event);
    virObjectEventStateQueue(driver->domainEventState, lifecycleEvent);
}

static void
qemuProcessHandlePMSuspend(qemuMonitor *mon G_GNUC_UNUSED,
                           virDomainObj *vm)
{
    virQEMUDriver *driver;
    virObjectEvent *event = NULL;
    virObjectEvent *lifecycleEvent = NULL;

    virObjectLock(vm);
    driver = QEMU_DOMAIN_PRIVATE(vm)->driver;
    event = virDomainEventPMSuspendNewFromObj(vm);

    if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_RUNNING) {
        qemuDomainObjPrivate *priv = vm->privateData;
        VIR_DEBUG("Transitioned guest %s to pmsuspended state due to "
                  "QMP suspend event", vm->def->name);

        virDomainObjSetState(vm, VIR_DOMAIN_PMSUSPENDED,
                             VIR_DOMAIN_PMSUSPENDED_UNKNOWN);
        lifecycleEvent =
            virDomainEventLifecycleNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_PMSUSPENDED,
                                     VIR_DOMAIN_EVENT_PMSUSPENDED_MEMORY);
        qemuDomainSaveStatus(vm);

        if (priv->agent)
            qemuAgentNotifyEvent(priv->agent, QEMU_AGENT_EVENT_SUSPEND);
    }

    virObjectUnlock(vm);

    virObjectEventStateQueue(driver->domainEventState, event);
    virObjectEventStateQueue(driver->domainEventState, lifecycleEvent);
}

static void
qemuProcessHandleBalloonChange(qemuMonitor *mon G_GNUC_UNUSED,
                               virDomainObj *vm,
                               unsigned long long actual)
{
    virQEMUDriver *driver;
    virObjectEvent *event = NULL;
    size_t i;

    virObjectLock(vm);
    driver = QEMU_DOMAIN_PRIVATE(vm)->driver;
    event = virDomainEventBalloonChangeNewFromObj(vm, actual);

    /* We want the balloon size stored in domain definition to
     * account for the actual size of virtio-mem too. But the
     * balloon size as reported by QEMU (@actual) contains just
     * the balloon size without any virtio-mem. Do a wee bit of
     * math to fix it. */
    VIR_DEBUG("balloon size before fix is %lld", actual);
    for (i = 0; i < vm->def->nmems; i++) {
        if (vm->def->mems[i]->model == VIR_DOMAIN_MEMORY_MODEL_VIRTIO_MEM)
            actual += vm->def->mems[i]->target.virtio_mem.currentsize;
    }

    VIR_DEBUG("Updating balloon from %lld to %lld kb",
              vm->def->mem.cur_balloon, actual);
    vm->def->mem.cur_balloon = actual;

    qemuDomainSaveStatus(vm);
    virObjectUnlock(vm);

    virObjectEventStateQueue(driver->domainEventState, event);
}

static void
qemuProcessHandlePMSuspendDisk(qemuMonitor *mon G_GNUC_UNUSED,
                               virDomainObj *vm)
{
    virQEMUDriver *driver;
    virObjectEvent *event = NULL;
    virObjectEvent *lifecycleEvent = NULL;

    virObjectLock(vm);
    driver = QEMU_DOMAIN_PRIVATE(vm)->driver;
    event = virDomainEventPMSuspendDiskNewFromObj(vm);

    if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_RUNNING) {
        qemuDomainObjPrivate *priv = vm->privateData;
        VIR_DEBUG("Transitioned guest %s to pmsuspended state due to "
                  "QMP suspend_disk event", vm->def->name);

        virDomainObjSetState(vm, VIR_DOMAIN_PMSUSPENDED,
                             VIR_DOMAIN_PMSUSPENDED_UNKNOWN);
        lifecycleEvent =
            virDomainEventLifecycleNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_PMSUSPENDED,
                                     VIR_DOMAIN_EVENT_PMSUSPENDED_DISK);
        qemuDomainSaveStatus(vm);

        if (priv->agent)
            qemuAgentNotifyEvent(priv->agent, QEMU_AGENT_EVENT_SUSPEND);
    }

    virObjectUnlock(vm);

    virObjectEventStateQueue(driver->domainEventState, event);
    virObjectEventStateQueue(driver->domainEventState, lifecycleEvent);
}


static void
qemuProcessHandleGuestPanic(qemuMonitor *mon G_GNUC_UNUSED,
                            virDomainObj *vm,
                            qemuMonitorEventPanicInfo *info)
{
    virObjectLock(vm);

    qemuProcessEventSubmit(vm, QEMU_PROCESS_EVENT_GUESTPANIC,
                           vm->def->onCrash, 0, info);

    virObjectUnlock(vm);
}


void
qemuProcessHandleDeviceDeleted(qemuMonitor *mon G_GNUC_UNUSED,
                               virDomainObj *vm,
                               const char *devAlias)
{
    virObjectLock(vm);

    VIR_DEBUG("Device %s removed from domain %p %s",
              devAlias, vm, vm->def->name);

    if (qemuDomainSignalDeviceRemoval(vm, devAlias,
                                      QEMU_DOMAIN_UNPLUGGING_DEVICE_STATUS_OK))
        goto cleanup;

    qemuProcessEventSubmit(vm, QEMU_PROCESS_EVENT_DEVICE_DELETED,
                           0, 0, g_strdup(devAlias));

 cleanup:
    virObjectUnlock(vm);
}


static void
qemuProcessHandleDeviceUnplugErr(qemuMonitor *mon G_GNUC_UNUSED,
                                 virDomainObj *vm,
                                 const char *devPath,
                                 const char *devAlias)
{
    virQEMUDriver *driver;
    virObjectEvent *event = NULL;

    virObjectLock(vm);
    driver = QEMU_DOMAIN_PRIVATE(vm)->driver;

    VIR_DEBUG("Device %s QOM path %s failed to be removed from domain %p %s",
              devAlias, devPath, vm, vm->def->name);

    /*
     * DEVICE_UNPLUG_GUEST_ERROR will always contain the QOM path
     * but QEMU will not guarantee that devAlias will be provided.
     *
     * However, given that all Libvirt devices have a devAlias, we
     * can ignore the case where QEMU emitted this event without it.
     */
    if (!devAlias)
        goto cleanup;

    qemuDomainSignalDeviceRemoval(vm, devAlias,
                                  QEMU_DOMAIN_UNPLUGGING_DEVICE_STATUS_GUEST_REJECTED);

    event = virDomainEventDeviceRemovalFailedNewFromObj(vm, devAlias);

 cleanup:
    virObjectUnlock(vm);
    virObjectEventStateQueue(driver->domainEventState, event);
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
static void
qemuProcessHandleAcpiOstInfo(qemuMonitor *mon G_GNUC_UNUSED,
                             virDomainObj *vm,
                             const char *alias,
                             const char *slotType,
                             const char *slot,
                             unsigned int source,
                             unsigned int status)
{
    virQEMUDriver *driver;
    virObjectEvent *event = NULL;

    virObjectLock(vm);
    driver = QEMU_DOMAIN_PRIVATE(vm)->driver;

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
}


static void
qemuProcessHandleBlockThreshold(qemuMonitor *mon G_GNUC_UNUSED,
                                virDomainObj *vm,
                                const char *nodename,
                                unsigned long long threshold,
                                unsigned long long excess)
{
    qemuDomainObjPrivate *priv;
    virQEMUDriver *driver;
    virObjectEvent *eventSource = NULL;
    virObjectEvent *eventDevice = NULL;
    virDomainDiskDef *disk;
    virStorageSource *src;
    const char *path = NULL;

    virObjectLock(vm);

    priv  = vm->privateData;
    driver = priv->driver;

    VIR_DEBUG("BLOCK_WRITE_THRESHOLD event for block node '%s' in domain %p %s:"
              "threshold '%llu' exceeded by '%llu'",
              nodename, vm, vm->def->name, threshold, excess);

    if ((disk = qemuDomainDiskLookupByNodename(vm->def, priv->backup, nodename, &src))) {
        if (virStorageSourceIsLocalStorage(src))
            path = src->path;

        if (src == disk->src &&
            !src->thresholdEventWithIndex) {
            g_autofree char *dev = qemuDomainDiskBackingStoreGetName(disk, 0);

            eventDevice = virDomainEventBlockThresholdNewFromObj(vm, dev, path,
                                                                 threshold, excess);
        }

        if (src->id != 0) {
            g_autofree char *dev = qemuDomainDiskBackingStoreGetName(disk, src->id);

            eventSource = virDomainEventBlockThresholdNewFromObj(vm, dev, path,
                                                                 threshold, excess);
        }
    }

    virObjectUnlock(vm);
    virObjectEventStateQueue(driver->domainEventState, eventDevice);
    virObjectEventStateQueue(driver->domainEventState, eventSource);
}


static void
qemuProcessHandleNetdevStreamDisconnected(qemuMonitor *mon G_GNUC_UNUSED,
                                          virDomainObj *vm,
                                          const char *devAlias)
{
    virObjectLock(vm);

    VIR_DEBUG("Device %s Netdev Stream Disconnected in domain %p %s",
              devAlias, vm, vm->def->name);

    qemuProcessEventSubmit(vm, QEMU_PROCESS_EVENT_NETDEV_STREAM_DISCONNECTED,
                           0, 0, g_strdup(devAlias));

    virObjectUnlock(vm);
}


static void
qemuProcessHandleNicRxFilterChanged(qemuMonitor *mon G_GNUC_UNUSED,
                                    virDomainObj *vm,
                                    const char *devAlias)
{
    virObjectLock(vm);

    VIR_DEBUG("Device %s RX Filter changed in domain %p %s",
              devAlias, vm, vm->def->name);

    qemuProcessEventSubmit(vm, QEMU_PROCESS_EVENT_NIC_RX_FILTER_CHANGED,
                           0, 0, g_strdup(devAlias));

    virObjectUnlock(vm);
}


static void
qemuProcessHandleSerialChanged(qemuMonitor *mon G_GNUC_UNUSED,
                               virDomainObj *vm,
                               const char *devAlias,
                               bool connected)
{
    virObjectLock(vm);

    VIR_DEBUG("Serial port %s state changed to '%d' in domain %p %s",
              devAlias, connected, vm, vm->def->name);

    qemuProcessEventSubmit(vm, QEMU_PROCESS_EVENT_SERIAL_CHANGED,
                           connected, 0, g_strdup(devAlias));

    virObjectUnlock(vm);
}


static void
qemuProcessHandleSpiceMigrated(qemuMonitor *mon G_GNUC_UNUSED,
                               virDomainObj *vm)
{
    qemuDomainJobPrivate *jobPriv;

    virObjectLock(vm);

    VIR_DEBUG("Spice migration completed for domain %p %s",
              vm, vm->def->name);

    jobPriv = vm->job->privateData;
    if (vm->job->asyncJob != VIR_ASYNC_JOB_MIGRATION_OUT) {
        VIR_DEBUG("got SPICE_MIGRATE_COMPLETED event without a migration job");
        goto cleanup;
    }

    jobPriv->spiceMigrated = true;
    virDomainObjBroadcast(vm);

 cleanup:
    virObjectUnlock(vm);
}


static void
qemuProcessHandleMigrationStatus(qemuMonitor *mon G_GNUC_UNUSED,
                                 virDomainObj *vm,
                                 int status)
{
    qemuDomainObjPrivate *priv;
    qemuDomainJobDataPrivate *privJob = NULL;
    virQEMUDriver *driver;
    virObjectEvent *event = NULL;
    virDomainState state;
    int reason;

    virObjectLock(vm);

    VIR_DEBUG("Migration of domain %p %s changed state to %s",
              vm, vm->def->name,
              qemuMonitorMigrationStatusTypeToString(status));

    priv = vm->privateData;
    driver = priv->driver;

    if (vm->job->asyncJob == VIR_ASYNC_JOB_NONE) {
        VIR_DEBUG("got MIGRATION event without a migration job");
        goto cleanup;
    }

    privJob = vm->job->current->privateData;

    privJob->stats.mig.status = status;
    virDomainObjBroadcast(vm);

    state = virDomainObjGetState(vm, &reason);

    switch ((qemuMonitorMigrationStatus) status) {
    case QEMU_MONITOR_MIGRATION_STATUS_POSTCOPY:
        if (vm->job->asyncJob == VIR_ASYNC_JOB_MIGRATION_OUT &&
            state == VIR_DOMAIN_PAUSED &&
            reason == VIR_DOMAIN_PAUSED_MIGRATION) {
            VIR_DEBUG("Correcting paused state reason for domain %s to %s",
                      vm->def->name,
                      virDomainPausedReasonTypeToString(VIR_DOMAIN_PAUSED_POSTCOPY));

            virDomainObjSetState(vm, VIR_DOMAIN_PAUSED, VIR_DOMAIN_PAUSED_POSTCOPY);
            event = virDomainEventLifecycleNewFromObj(vm,
                                                      VIR_DOMAIN_EVENT_SUSPENDED,
                                                      VIR_DOMAIN_EVENT_SUSPENDED_POSTCOPY);
            qemuDomainSaveStatus(vm);
        }
        break;

    case QEMU_MONITOR_MIGRATION_STATUS_POSTCOPY_PAUSED:
        if (vm->job->asyncJob == VIR_ASYNC_JOB_MIGRATION_OUT &&
            state == VIR_DOMAIN_PAUSED) {
            /* At this point no thread is watching the migration progress on
             * the source as it is just waiting for the Finish phase to end.
             * Thus we need to handle the event here. */
            qemuMigrationSrcPostcopyFailed(vm);
            qemuDomainSaveStatus(vm);
        }
        break;

    case QEMU_MONITOR_MIGRATION_STATUS_POSTCOPY_RECOVER:
        if (virDomainObjIsFailedPostcopy(vm, vm->job)) {
            int eventType = -1;
            int eventDetail = -1;

            if (state == VIR_DOMAIN_PAUSED) {
                reason = VIR_DOMAIN_PAUSED_POSTCOPY;
                eventType = VIR_DOMAIN_EVENT_SUSPENDED;
                eventDetail = qemuDomainPausedReasonToSuspendedEvent(reason);
            } else {
                reason = VIR_DOMAIN_RUNNING_POSTCOPY;
                eventType = VIR_DOMAIN_EVENT_RESUMED;
                eventDetail = qemuDomainRunningReasonToResumeEvent(reason);
            }

            VIR_DEBUG("Post-copy migration recovered; correcting state for domain '%s' to %s/%s",
                      vm->def->name,
                      virDomainStateTypeToString(state),
                      NULLSTR(virDomainStateReasonToString(state, reason)));
            vm->job->asyncPaused = false;
            virDomainObjSetState(vm, state, reason);
            event = virDomainEventLifecycleNewFromObj(vm, eventType, eventDetail);
            qemuDomainSaveStatus(vm);
        }
        break;

    case QEMU_MONITOR_MIGRATION_STATUS_COMPLETED:
        /* A post-copy migration marked as failed when reconnecting to a domain
         * with running migration may actually still be running, but we're not
         * watching it in any thread. Let's make sure the migration is properly
         * finished in case we get a "completed" event.
         */
        if (virDomainObjIsPostcopy(vm, vm->job) &&
            vm->job->phase == QEMU_MIGRATION_PHASE_POSTCOPY_FAILED &&
            vm->job->asyncOwner == 0) {
            qemuProcessEventSubmit(vm, QEMU_PROCESS_EVENT_UNATTENDED_MIGRATION,
                                   vm->job->asyncJob, status, NULL);
        }
        break;

    case QEMU_MONITOR_MIGRATION_STATUS_INACTIVE:
    case QEMU_MONITOR_MIGRATION_STATUS_SETUP:
    case QEMU_MONITOR_MIGRATION_STATUS_ACTIVE:
    case QEMU_MONITOR_MIGRATION_STATUS_PRE_SWITCHOVER:
    case QEMU_MONITOR_MIGRATION_STATUS_DEVICE:
    case QEMU_MONITOR_MIGRATION_STATUS_ERROR:
    case QEMU_MONITOR_MIGRATION_STATUS_CANCELLING:
    case QEMU_MONITOR_MIGRATION_STATUS_CANCELLED:
    case QEMU_MONITOR_MIGRATION_STATUS_WAIT_UNPLUG:
    case QEMU_MONITOR_MIGRATION_STATUS_LAST:
    default:
        break;
    }

 cleanup:
    virObjectUnlock(vm);
    virObjectEventStateQueue(driver->domainEventState, event);
}


static void
qemuProcessHandleMigrationPass(qemuMonitor *mon G_GNUC_UNUSED,
                               virDomainObj *vm,
                               int pass)
{
    qemuDomainObjPrivate *priv;

    virObjectLock(vm);

    VIR_DEBUG("Migrating domain %p %s, iteration %d",
              vm, vm->def->name, pass);

    priv = vm->privateData;
    if (vm->job->asyncJob == VIR_ASYNC_JOB_NONE) {
        VIR_DEBUG("got MIGRATION_PASS event without a migration job");
        goto cleanup;
    }

    virObjectEventStateQueue(priv->driver->domainEventState,
                         virDomainEventMigrationIterationNewFromObj(vm, pass));

 cleanup:
    virObjectUnlock(vm);
}


static void
qemuProcessHandleDumpCompleted(qemuMonitor *mon G_GNUC_UNUSED,
                               virDomainObj *vm,
                               int status,
                               qemuMonitorDumpStats *stats,
                               const char *error)
{
    qemuDomainJobPrivate *jobPriv;
    qemuDomainJobDataPrivate *privJobCurrent = NULL;

    virObjectLock(vm);

    VIR_DEBUG("Dump completed for domain %p %s with stats=%p error='%s'",
              vm, vm->def->name, stats, NULLSTR(error));

    jobPriv = vm->job->privateData;
    if (vm->job->asyncJob == VIR_ASYNC_JOB_NONE) {
        VIR_DEBUG("got DUMP_COMPLETED event without a dump_completed job");
        goto cleanup;
    }
    privJobCurrent = vm->job->current->privateData;
    jobPriv->dumpCompleted = true;
    privJobCurrent->stats.dump = *stats;
    vm->job->error = g_strdup(error);

    /* Force error if extracting the DUMP_COMPLETED status failed */
    if (!error && status < 0) {
        vm->job->error = g_strdup(virGetLastErrorMessage());
        privJobCurrent->stats.dump.status = QEMU_MONITOR_DUMP_STATUS_FAILED;
    }

    virDomainObjBroadcast(vm);

 cleanup:
    virResetLastError();
    virObjectUnlock(vm);
}


static void
qemuProcessHandlePRManagerStatusChanged(qemuMonitor *mon G_GNUC_UNUSED,
                                        virDomainObj *vm,
                                        const char *prManager,
                                        bool connected)
{
    qemuDomainObjPrivate *priv;
    const char *managedAlias = qemuDomainGetManagedPRAlias();

    virObjectLock(vm);

    VIR_DEBUG("pr-manager %s status changed for domain %p %s connected=%d",
              prManager, vm, vm->def->name, connected);

    /* Connect events are boring. */
    if (connected)
        goto cleanup;

    /* Disconnect events are more interesting. */

    if (STRNEQ(prManager, managedAlias)) {
        VIR_DEBUG("pr-manager %s not managed, ignoring event",
                  prManager);
        goto cleanup;
    }

    priv = vm->privateData;
    priv->prDaemonRunning = false;

    qemuProcessEventSubmit(vm, QEMU_PROCESS_EVENT_PR_DISCONNECT,
                           0, 0, NULL);

 cleanup:
    virObjectUnlock(vm);
}


static void
qemuProcessHandleRdmaGidStatusChanged(qemuMonitor *mon G_GNUC_UNUSED,
                                      virDomainObj *vm,
                                      const char *netdev,
                                      bool gid_status,
                                      unsigned long long subnet_prefix,
                                      unsigned long long interface_id)
{
    qemuMonitorRdmaGidStatus *info = NULL;

    virObjectLock(vm);

    VIR_DEBUG("netdev=%s,gid_status=%d,subnet_prefix=0x%llx,interface_id=0x%llx",
              netdev, gid_status, subnet_prefix, interface_id);

    info = g_new0(qemuMonitorRdmaGidStatus, 1);

    info->netdev = g_strdup(netdev);

    info->gid_status = gid_status;
    info->subnet_prefix = subnet_prefix;
    info->interface_id = interface_id;

    qemuProcessEventSubmit(vm, QEMU_PROCESS_EVENT_RDMA_GID_STATUS_CHANGED,
                           0, 0, info);

    virObjectUnlock(vm);
}


static void
qemuProcessHandleGuestCrashloaded(qemuMonitor *mon G_GNUC_UNUSED,
                                  virDomainObj *vm)
{
    virObjectLock(vm);

    qemuProcessEventSubmit(vm, QEMU_PROCESS_EVENT_GUEST_CRASHLOADED,
                           0, 0, NULL);

    virObjectUnlock(vm);
}


static void
qemuProcessHandleMemoryFailure(qemuMonitor *mon G_GNUC_UNUSED,
                               virDomainObj *vm,
                               qemuMonitorEventMemoryFailure *mfp)
{
    virQEMUDriver *driver;
    virObjectEvent *event = NULL;
    virDomainMemoryFailureRecipientType recipient;
    virDomainMemoryFailureActionType action;
    unsigned int flags = 0;

    virObjectLock(vm);
    driver = QEMU_DOMAIN_PRIVATE(vm)->driver;

    switch (mfp->recipient) {
    case QEMU_MONITOR_MEMORY_FAILURE_RECIPIENT_HYPERVISOR:
        recipient = VIR_DOMAIN_EVENT_MEMORY_FAILURE_RECIPIENT_HYPERVISOR;
        break;
    case QEMU_MONITOR_MEMORY_FAILURE_RECIPIENT_GUEST:
        recipient = VIR_DOMAIN_EVENT_MEMORY_FAILURE_RECIPIENT_GUEST;
        break;
    case QEMU_MONITOR_MEMORY_FAILURE_RECIPIENT_LAST:
    default:
        return;
    }

    switch (mfp->action) {
    case QEMU_MONITOR_MEMORY_FAILURE_ACTION_IGNORE:
        action = VIR_DOMAIN_EVENT_MEMORY_FAILURE_ACTION_IGNORE;
        break;
    case QEMU_MONITOR_MEMORY_FAILURE_ACTION_INJECT:
        action = VIR_DOMAIN_EVENT_MEMORY_FAILURE_ACTION_INJECT;
        break;
    case QEMU_MONITOR_MEMORY_FAILURE_ACTION_FATAL:
        action = VIR_DOMAIN_EVENT_MEMORY_FAILURE_ACTION_FATAL;
        break;
    case QEMU_MONITOR_MEMORY_FAILURE_ACTION_RESET:
        action = VIR_DOMAIN_EVENT_MEMORY_FAILURE_ACTION_RESET;
        break;
    case QEMU_MONITOR_MEMORY_FAILURE_ACTION_LAST:
    default:
        return;
    }

    if (mfp->action_required)
        flags |= VIR_DOMAIN_MEMORY_FAILURE_ACTION_REQUIRED;
    if (mfp->recursive)
        flags |= VIR_DOMAIN_MEMORY_FAILURE_RECURSIVE;

    event = virDomainEventMemoryFailureNewFromObj(vm, recipient, action, flags);

    virObjectUnlock(vm);

    virObjectEventStateQueue(driver->domainEventState, event);
}


static void
qemuProcessHandleMemoryDeviceSizeChange(qemuMonitor *mon G_GNUC_UNUSED,
                                        virDomainObj *vm,
                                        const char *devAlias,
                                        unsigned long long size)
{
    qemuMonitorMemoryDeviceSizeChange *info = NULL;

    virObjectLock(vm);

    VIR_DEBUG("Memory device '%s' changed size to '%llu' in domain '%s'",
              devAlias, size, vm->def->name);

    info = g_new0(qemuMonitorMemoryDeviceSizeChange, 1);
    info->devAlias = g_strdup(devAlias);
    info->size = size;

    qemuProcessEventSubmit(vm, QEMU_PROCESS_EVENT_MEMORY_DEVICE_SIZE_CHANGE,
                           0, 0, info);

    virObjectUnlock(vm);
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
    .jobStatusChange = qemuProcessHandleJobStatusChange,
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
    .domainGuestCrashloaded = qemuProcessHandleGuestCrashloaded,
    .domainMemoryFailure = qemuProcessHandleMemoryFailure,
    .domainMemoryDeviceSizeChange = qemuProcessHandleMemoryDeviceSizeChange,
    .domainDeviceUnplugError = qemuProcessHandleDeviceUnplugErr,
    .domainNetdevStreamDisconnected = qemuProcessHandleNetdevStreamDisconnected,
};

static void
qemuProcessMonitorReportLogError(qemuMonitor *mon,
                                 const char *msg,
                                 void *opaque);


static void
qemuProcessMonitorLogFree(void *opaque)
{
    qemuLogContext *logCtxt = opaque;
    g_clear_object(&logCtxt);
}


static int
qemuProcessInitMonitor(virDomainObj *vm,
                       virDomainAsyncJob asyncJob)
{
    int ret;

    if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) < 0)
        return -1;

    ret = qemuMonitorSetCapabilities(QEMU_DOMAIN_PRIVATE(vm)->mon);

    qemuDomainObjExitMonitor(vm);

    return ret;
}


static int
qemuConnectMonitor(virQEMUDriver *driver,
                   virDomainObj *vm,
                   int asyncJob,
                   qemuLogContext *logCtxt,
                   bool reconnect)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    qemuMonitor *mon = NULL;

    if (qemuSecuritySetDaemonSocketLabel(driver->securityManager, vm->def) < 0) {
        VIR_ERROR(_("Failed to set security context for monitor for %1$s"),
                  vm->def->name);
        return -1;
    }

    ignore_value(virTimeMillisNow(&priv->monStart));

    mon = qemuMonitorOpen(vm,
                          priv->monConfig,
                          virEventThreadGetContext(priv->eventThread),
                          &monitorCallbacks);

    if (mon && logCtxt) {
        g_object_ref(logCtxt);
        qemuMonitorSetDomainLog(mon,
                                qemuProcessMonitorReportLogError,
                                logCtxt,
                                qemuProcessMonitorLogFree);
    }

    priv->monStart = 0;
    priv->mon = mon;

    if (qemuSecurityClearSocketLabel(driver->securityManager, vm->def) < 0) {
        VIR_ERROR(_("Failed to clear security context for monitor for %1$s"),
                  vm->def->name);
        return -1;
    }

    if (priv->mon == NULL) {
        VIR_INFO("Failed to connect monitor for %s", vm->def->name);
        return -1;
    }

    if (qemuProcessInitMonitor(vm, asyncJob) < 0)
        return -1;

    if (qemuMigrationCapsCheck(vm, asyncJob, reconnect) < 0)
        return -1;

    return 0;
}


static int
qemuProcessReportLogError(qemuLogContext *logCtxt,
                          const char *msgprefix)
{
    g_autofree char *logmsg = NULL;

    /* assume that 1024 chars of qemu log is the right balance */
    if (qemuLogContextReadFiltered(logCtxt, &logmsg, 1024) < 0)
        return -1;

    virResetLastError();
    if (virStringIsEmpty(logmsg))
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", msgprefix);
    else
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s: %s", /* _( silence sc_libvirt_unmarked_diagnostics */
                       msgprefix, logmsg);

    return 0;
}


static void
qemuProcessMonitorReportLogError(qemuMonitor *mon G_GNUC_UNUSED,
                                 const char *msg,
                                 void *opaque)
{
    qemuLogContext *logCtxt = opaque;
    qemuProcessReportLogError(logCtxt, msg);
}


static int
qemuProcessLookupPTYs(virDomainChrDef **devices,
                      int count,
                      GHashTable *info)
{
    size_t i;

    for (i = 0; i < count; i++) {
        g_autofree char *id = NULL;
        virDomainChrDef *chr = devices[i];
        if (chr->source->type == VIR_DOMAIN_CHR_TYPE_PTY) {
            qemuMonitorChardevInfo *entry;

            id = g_strdup_printf("char%s", chr->info.alias);

            entry = virHashLookup(info, id);
            if (!entry || !entry->ptyPath) {
                if (chr->source->data.file.path == NULL) {
                    /* neither the log output nor 'info chardev' had a
                     * pty path for this chardev, report an error
                     */
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("no assigned pty for device %1$s"), id);
                    return -1;
                } else {
                    /* 'info chardev' had no pty path for this chardev,
                     * but the log output had, so we're fine
                     */
                    continue;
                }
            }

            g_free(chr->source->data.file.path);
            chr->source->data.file.path = g_strdup(entry->ptyPath);
        }
    }

    return 0;
}

static int
qemuProcessFindCharDevicePTYsMonitor(virDomainObj *vm,
                                     GHashTable *info)
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
        virDomainChrDef *chr = vm->def->consoles[0];

        if (vm->def->nserials &&
            chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE &&
            chr->targetType == VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SERIAL) {
            /* yes, the first console is just an alias for serials[0] */
            i = 1;
            virDomainChrSourceDefCopy(chr->source,
                                      ((vm->def->serials[0])->source));
        }
    }

    if (qemuProcessLookupPTYs(vm->def->consoles + i, vm->def->nconsoles - i,
                              info) < 0)
        return -1;

    return 0;
}


static void
qemuProcessRefreshChannelVirtioState(virQEMUDriver *driver,
                                     virDomainObj *vm,
                                     GHashTable *info,
                                     int booted)
{
    size_t i;
    int agentReason = VIR_CONNECT_DOMAIN_EVENT_AGENT_LIFECYCLE_REASON_CHANNEL;
    qemuMonitorChardevInfo *entry;
    virObjectEvent *event = NULL;
    g_autofree char *id = NULL;

    if (booted)
        agentReason = VIR_CONNECT_DOMAIN_EVENT_AGENT_LIFECYCLE_REASON_DOMAIN_STARTED;

    for (i = 0; i < vm->def->nchannels; i++) {
        virDomainChrDef *chr = vm->def->channels[i];
        if (chr->targetType == VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_VIRTIO) {

            VIR_FREE(id);
            id = g_strdup_printf("char%s", chr->info.alias);

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
}


int
qemuRefreshVirtioChannelState(virQEMUDriver *driver,
                              virDomainObj *vm,
                              virDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autoptr(GHashTable) info = NULL;
    int rc;

    if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) < 0)
        return -1;

    rc = qemuMonitorGetChardevInfo(priv->mon, &info);
    qemuDomainObjExitMonitor(vm);

    if (rc < 0)
        return -1;

    qemuProcessRefreshChannelVirtioState(driver, vm, info, false);

    return 0;
}


static int
qemuProcessRefreshPRManagerState(virDomainObj *vm,
                                 GHashTable *info)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    qemuMonitorPRManagerInfo *prManagerInfo;
    const char *managedAlias = qemuDomainGetManagedPRAlias();

    if (!(prManagerInfo = virHashLookup(info, managedAlias))) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("missing info on pr-manager %1$s"),
                       managedAlias);
        return -1;
    }

    priv->prDaemonRunning = prManagerInfo->connected;

    if (!priv->prDaemonRunning &&
        qemuProcessStartManagedPRDaemon(vm) < 0)
        return -1;

    return 0;
}


static int
qemuRefreshPRManagerState(virDomainObj *vm)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autoptr(GHashTable) info = NULL;
    int rc;

    if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_PR_MANAGER_HELPER) ||
        !qemuDomainDefHasManagedPR(vm))
        return 0;

    qemuDomainObjEnterMonitor(vm);
    rc = qemuMonitorGetPRManagerInfo(priv->mon, &info);
    qemuDomainObjExitMonitor(vm);

    if (rc < 0)
        return -1;


    return qemuProcessRefreshPRManagerState(vm, info);
}


static int
qemuProcessRefreshFdsetIndex(virDomainObj *vm)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autoptr(qemuMonitorFdsets) fdsets = NULL;
    size_t i;
    int rc;

    /* if the previous index was in the status XML we don't need to update it */
    if (priv->fdsetindexParsed)
        return 0;

    qemuDomainObjEnterMonitor(vm);
    rc = qemuMonitorQueryFdsets(priv->mon, &fdsets);
    qemuDomainObjExitMonitor(vm);

    if (rc < 0)
        return -1;

    for (i = 0; i < fdsets->nfdsets; i++) {
        if (fdsets->fdsets[i].id >= priv->fdsetindex)
            priv->fdsetindex = fdsets->fdsets[i].id + 1;
    }

    return 0;
}


static void
qemuRefreshRTC(virDomainObj *vm)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    time_t now, then;
    struct tm thenbits = { 0 };
    long localOffset;
    int rv;

    if (vm->def->clock.offset != VIR_DOMAIN_CLOCK_OFFSET_VARIABLE)
        return;

    qemuDomainObjEnterMonitor(vm);
    now = time(NULL);
    rv = qemuMonitorGetRTCTime(priv->mon, &thenbits);
    qemuDomainObjExitMonitor(vm);

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
qemuProcessRefreshBalloonState(virDomainObj *vm,
                               int asyncJob)
{
    unsigned long long balloon;
    size_t i;
    int rc;

    /* if no ballooning is available, the current size equals to the current
     * full memory size */
    if (!virDomainDefHasMemballoon(vm->def)) {
        vm->def->mem.cur_balloon = virDomainDefGetMemoryTotal(vm->def);
        return 0;
    }

    if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) < 0)
        return -1;

    rc = qemuMonitorGetBalloonInfo(qemuDomainGetMonitor(vm), &balloon);
    qemuDomainObjExitMonitor(vm);
    if (rc < 0)
        return -1;

    /* We want the balloon size stored in domain definition to
     * account for the actual size of virtio-mem too. But the
     * balloon size as reported by QEMU (@balloon) contains just
     * the balloon size without any virtio-mem. Do a wee bit of
     * math to fix it. */
    VIR_DEBUG("balloon size before fix is %lld", balloon);
    for (i = 0; i < vm->def->nmems; i++) {
        if (vm->def->mems[i]->model == VIR_DOMAIN_MEMORY_MODEL_VIRTIO_MEM)
            balloon += vm->def->mems[i]->target.virtio_mem.currentsize;
    }
    VIR_DEBUG("Updating balloon from %lld to %lld kb",
              vm->def->mem.cur_balloon, balloon);
    vm->def->mem.cur_balloon = balloon;

    return 0;
}


static int
qemuProcessWaitForMonitor(virQEMUDriver *driver,
                          virDomainObj *vm,
                          int asyncJob,
                          qemuLogContext *logCtxt)
{
    int ret = -1;
    g_autoptr(GHashTable) info = NULL;
    qemuDomainObjPrivate *priv = vm->privateData;

    VIR_DEBUG("Connect monitor to vm=%p name='%s'", vm, vm->def->name);

    if (qemuConnectMonitor(driver, vm, asyncJob, logCtxt, false) < 0)
        goto cleanup;

    /* Try to get the pty path mappings again via the monitor. This is much more
     * reliable if it's available.
     * Note that the monitor itself can be on a pty, so we still need to try the
     * log output method. */
    if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) < 0)
        goto cleanup;
    ret = qemuMonitorGetChardevInfo(priv->mon, &info);
    VIR_DEBUG("qemuMonitorGetChardevInfo returned %i", ret);
    qemuDomainObjExitMonitor(vm);

    if (ret == 0) {
        if ((ret = qemuProcessFindCharDevicePTYsMonitor(vm, info)) < 0)
            goto cleanup;

         qemuProcessRefreshChannelVirtioState(driver, vm, info, true);
    }

 cleanup:
    if (logCtxt && kill(vm->pid, 0) == -1 && errno == ESRCH) {
        qemuProcessReportLogError(logCtxt,
                                  _("process exited while connecting to monitor"));
        ret = -1;
    }

    return ret;
}


static int
qemuProcessDetectIOThreadPIDs(virDomainObj *vm,
                              int asyncJob)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    qemuMonitorIOThreadInfo **iothreads = NULL;
    int niothreads = 0;
    int ret = -1;
    size_t i;

    /* Get the list of IOThreads from qemu */
    if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) < 0)
        goto cleanup;
    ret = qemuMonitorGetIOThreads(priv->mon, &iothreads, &niothreads);
    qemuDomainObjExitMonitor(vm);
    if (ret < 0)
        goto cleanup;

    if (niothreads != vm->def->niothreadids) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("got wrong number of IOThread pids from QEMU monitor. got %1$d, wanted %2$zu"),
                       niothreads, vm->def->niothreadids);
        goto cleanup;
    }

    /* Nothing to do */
    if (niothreads == 0) {
        ret = 0;
        goto cleanup;
    }

    for (i = 0; i < niothreads; i++) {
        virDomainIOThreadIDDef *iothrid;

        if (!(iothrid = virDomainIOThreadIDFind(vm->def,
                                                iothreads[i]->iothread_id))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("iothread %1$d not found"),
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
qemuProcessGetAllCpuAffinity(virBitmap **cpumapRet)
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
#if defined(WITH_SCHED_GETAFFINITY) || defined(WITH_BSD_CPU_AFFINITY)
static int
qemuProcessInitCpuAffinity(virDomainObj *vm)
{
    bool settingAll = false;
    g_autoptr(virBitmap) cpumapToSet = NULL;
    virDomainNumatuneMemMode mem_mode;
    qemuDomainObjPrivate *priv = vm->privateData;

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
        virBitmap *nodeset = NULL;

        if (virDomainNumatuneMaybeGetNodeset(vm->def->numa,
                                             priv->autoNodeset,
                                             &nodeset,
                                             -1) < 0)
            return -1;

        if (virNumaNodesetToCPUset(nodeset, &cpumapToSet) < 0)
            return -1;
    } else if (vm->def->cputune.emulatorpin) {
        cpumapToSet = virBitmapNewCopy(vm->def->cputune.emulatorpin);
    } else {
        settingAll = true;
        if (qemuProcessGetAllCpuAffinity(&cpumapToSet) < 0)
            return -1;
    }

    /*
     * We only want to error out if we failed to set the affinity to
     * user-requested mapping.  If we are just trying to reset the affinity
     * to all CPUs and this fails it can only be an issue if:
     *  1) libvirtd does not have CAP_SYS_NICE
     *  2) libvirtd does not run on all CPUs
     *
     * This scenario can easily occur when libvirtd is run inside a
     * container with restrictive permissions and CPU pinning.
     *
     * See also: https://bugzilla.redhat.com/1819801#c2
     */
    if (cpumapToSet &&
        virProcessSetAffinity(vm->pid, cpumapToSet, settingAll) < 0) {
        return -1;
    }

    return 0;
}
#else /* !defined(WITH_SCHED_GETAFFINITY) && !defined(WITH_BSD_CPU_AFFINITY) */
static int
qemuProcessInitCpuAffinity(virDomainObj *vm G_GNUC_UNUSED)
{
    return 0;
}
#endif /* !defined(WITH_SCHED_GETAFFINITY) && !defined(WITH_BSD_CPU_AFFINITY) */

/* set link states to down on interfaces at qemu start */
static int
qemuProcessSetLinkStates(virDomainObj *vm,
                         virDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    virDomainDef *def = vm->def;
    size_t i;
    int ret = -1;
    int rv;

    if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) < 0)
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
                               _("Couldn't set link state on interface: %1$s"),
                               def->nets[i]->info.alias);
                goto cleanup;
            }
        }
    }

    ret = 0;

 cleanup:
    qemuDomainObjExitMonitor(vm);
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
qemuProcessSetupPid(virDomainObj *vm,
                    pid_t pid,
                    virCgroupThreadName nameval,
                    int id,
                    virBitmap *cpumask,
                    unsigned long long period,
                    long long quota,
                    virDomainThreadSchedParam *sched)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    virDomainNuma *numatune = vm->def->numa;
    virDomainNumatuneMemMode mem_mode;
    virCgroup *cgroup = NULL;
    virBitmap *use_cpumask = NULL;
    virBitmap *affinity_cpumask = NULL;
    g_autoptr(virBitmap) hostcpumap = NULL;
    g_autofree char *mem_mask = NULL;
    int ret = -1;
    size_t i;

    if ((period || quota) &&
        !virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPU)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("cgroup cpu is required for scheduler tuning"));
        goto cleanup;
    }

    /* Infer which cpumask shall be used. */
    if (!(use_cpumask = qemuDomainEvaluateCPUMask(vm->def,
                                                  cpumask, priv->autoCpuset))) {
        /* You may think this is redundant, but we can't assume libvirtd
         * itself is running on all pCPUs, so we need to explicitly set
         * the spawned QEMU instance to all pCPUs if no map is given in
         * its config file */
        if (qemuProcessGetAllCpuAffinity(&hostcpumap) < 0)
            goto cleanup;
        affinity_cpumask = hostcpumap;
    }

    /*
     * If CPU cgroup controller is not initialized here, then we need
     * neither period nor quota settings.  And if CPUSET controller is
     * not initialized either, then there's nothing to do anyway.
     */
    if (virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPU) ||
        virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPUSET)) {

        if (virDomainNumatuneGetMode(numatune, -1, &mem_mode) == 0) {
            /* QEMU allocates its memory from the emulator thread. Thus it
             * needs to access union of all host nodes configured. */
            if (mem_mode == VIR_DOMAIN_NUMATUNE_MEM_STRICT) {
                qemuDomainNumatuneMaybeFormatNodesetUnion(vm, NULL, &mem_mask);
            } else if (mem_mode == VIR_DOMAIN_NUMATUNE_MEM_RESTRICTIVE &&
                       virDomainNumatuneMaybeFormatNodeset(numatune,
                                                           priv->autoNodeset,
                                                           &mem_mask, -1) < 0) {
                goto cleanup;
            }
        }

        /* For restrictive numatune mode we need to set cpuset.mems for vCPU
         * threads based on the node they are in as there is nothing else uses
         * for such restriction (e.g. numa_set_membind). */
        if (nameval == VIR_CGROUP_THREAD_VCPU) {
            /* Look for the guest NUMA node of this vCPU */
            for (i = 0; i < virDomainNumaGetNodeCount(numatune); i++) {
                virBitmap *node_cpus = virDomainNumaGetNodeCpumask(numatune, i);

                if (!virBitmapIsBitSet(node_cpus, id))
                    continue;

                /* Update the mem_mask for this vCPU if the mode of its node is
                 * 'restrictive'. */
                if (virDomainNumatuneGetMode(numatune, i, &mem_mode) == 0 &&
                    mem_mode == VIR_DOMAIN_NUMATUNE_MEM_RESTRICTIVE) {
                    VIR_FREE(mem_mask);

                    if (virDomainNumatuneMaybeFormatNodeset(numatune,
                                                            priv->autoNodeset,
                                                            &mem_mask, i) < 0) {
                        goto cleanup;
                    }
                }

                break;
            }
        }

        if (virCgroupNewThread(priv->cgroup, nameval, id, true, &cgroup) < 0)
            goto cleanup;

        /* Move the thread to the sub dir before changing the settings so that
         * all take effect even with cgroupv2. */
        if (virCgroupAddThread(cgroup, pid) < 0)
            goto cleanup;

        if (virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPUSET)) {
            if (use_cpumask &&
                virDomainCgroupSetupCpusetCpus(cgroup, use_cpumask) < 0)
                goto cleanup;

            if (mem_mask && virCgroupSetCpusetMems(cgroup, mem_mask) < 0)
                goto cleanup;

        }

        if (virDomainCgroupSetupVcpuBW(cgroup, period, quota) < 0)
            goto cleanup;
    }

    if (!affinity_cpumask)
        affinity_cpumask = use_cpumask;

    /* Setup legacy affinity.
     *
     * We only want to error out if we failed to set the affinity to
     * user-requested mapping.  If we are just trying to reset the affinity
     * to all CPUs and this fails it can only be an issue if:
     *  1) libvirtd does not have CAP_SYS_NICE
     *  2) libvirtd does not run on all CPUs
     *
     * This scenario can easily occur when libvirtd is run inside a
     * container with restrictive permissions and CPU pinning.
     *
     * See also: https://bugzilla.redhat.com/1819801#c2
     */
    if (affinity_cpumask &&
        virProcessSetAffinity(pid, affinity_cpumask,
                              affinity_cpumask == hostcpumap) < 0) {
        goto cleanup;
    }

    /* Set scheduler type and priority, but not for the main thread. */
    if (sched &&
        nameval != VIR_CGROUP_THREAD_EMULATOR &&
        virProcessSetScheduler(pid, sched->policy, sched->priority) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    if (cgroup) {
        if (ret < 0)
            virCgroupRemove(cgroup);
        virCgroupFree(cgroup);
    }

    return ret;
}


int
qemuProcessSetupEmulator(virDomainObj *vm)
{
    return qemuProcessSetupPid(vm, vm->pid, VIR_CGROUP_THREAD_EMULATOR,
                               0, vm->def->cputune.emulatorpin,
                               vm->def->cputune.emulator_period,
                               vm->def->cputune.emulator_quota,
                               vm->def->cputune.emulatorsched);
}


static int
qemuProcessResctrlCreate(virQEMUDriver *driver,
                         virDomainObj *vm)
{
    size_t i = 0;
    g_autoptr(virCaps) caps = NULL;
    qemuDomainObjPrivate *priv = vm->privateData;

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
            return -1;

        for (j = 0; j < vm->def->resctrls[i]->nmonitors; j++) {
            virDomainResctrlMonDef *mon = NULL;

            mon = vm->def->resctrls[i]->monitors[j];
            if (virResctrlMonitorCreate(mon->instance,
                                        priv->machineName) < 0)
                return -1;
        }
    }

    return 0;
}


static char *
qemuProcessBuildPRHelperPidfilePathOld(virDomainObj *vm)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    const char *prdAlias = qemuDomainGetManagedPRAlias();

    return virPidFileBuildPath(priv->libDir, prdAlias);
}


static char *
qemuProcessBuildPRHelperPidfilePath(virDomainObj *vm)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autofree char *domname = virDomainDefGetShortName(vm->def);
    g_autofree char *prdName = g_strdup_printf("%s-%s", domname, qemuDomainGetManagedPRAlias());
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(priv->driver);

    return virPidFileBuildPath(cfg->stateDir, prdName);
}


void
qemuProcessKillManagedPRDaemon(virDomainObj *vm)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    virErrorPtr orig_err;
    g_autofree char *pidfile = NULL;

    if (!(pidfile = qemuProcessBuildPRHelperPidfilePath(vm))) {
        VIR_WARN("Unable to construct pr-helper pidfile path");
        return;
    }

    if (!virFileExists(pidfile)) {
        g_free(pidfile);
        if (!(pidfile = qemuProcessBuildPRHelperPidfilePathOld(vm))) {
            VIR_WARN("Unable to construct pr-helper pidfile path");
            return;
        }
    }

    virErrorPreserveLast(&orig_err);
    if (virPidFileForceCleanupPath(pidfile) < 0) {
        VIR_WARN("Unable to kill pr-helper process");
    } else {
        priv->prDaemonRunning = false;
    }
    virErrorRestore(&orig_err);
}


static int
qemuProcessStartPRDaemonHook(void *opaque)
{
    virDomainObj *vm = opaque;
    size_t i, nfds = 0;
    g_autofree int *fds = NULL;
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
    return ret;
}


int
qemuProcessStartManagedPRDaemon(virDomainObj *vm)
{
    const char *const prHelperDirs[] = {
        "/usr/libexec",
        NULL,
    };
    qemuDomainObjPrivate *priv = vm->privateData;
    virQEMUDriver *driver = priv->driver;
    g_autoptr(virQEMUDriverConfig) cfg = NULL;
    int errfd = -1;
    g_autofree char *prHelperPath = NULL;
    g_autofree char *pidfile = NULL;
    g_autofree char *socketPath = NULL;
    pid_t cpid = -1;
    g_autoptr(virCommand) cmd = NULL;
    virTimeBackOffVar timebackoff;
    const unsigned long long timeout = 500000; /* ms */
    int ret = -1;

    cfg = virQEMUDriverGetConfig(driver);

    prHelperPath = virFindFileInPathFull(cfg->prHelperName, prHelperDirs);

    if (!prHelperPath) {
        virReportSystemError(errno, _("'%1$s' is not a suitable pr helper"),
                             cfg->prHelperName);
        goto cleanup;
    }

    VIR_DEBUG("Using qemu-pr-helper: %s", prHelperPath);

    if (!(pidfile = qemuProcessBuildPRHelperPidfilePath(vm)))
        goto cleanup;

    if (!(socketPath = qemuDomainGetManagedPRSocketPath(priv)))
        goto cleanup;

    /* Remove stale socket */
    if (unlink(socketPath) < 0 &&
        errno != ENOENT) {
        virReportSystemError(errno,
                             _("Unable to remove stale socket path: %1$s"),
                             socketPath);
        goto cleanup;
    }

    if (!(cmd = virCommandNewArgList(prHelperPath,
                                     "-k", socketPath,
                                     NULL)))
        goto cleanup;

    virCommandDaemonize(cmd);
    virCommandSetPidFile(cmd, pidfile);
    virCommandSetErrorFD(cmd, &errfd);

    /* Place the process into the same namespace and cgroup as
     * qemu (so that it shares the same view of the system). */
    virCommandSetPreExecHook(cmd, qemuProcessStartPRDaemonHook, vm);

    if (cfg->schedCore == QEMU_SCHED_CORE_FULL) {
        pid_t cookie_pid = vm->pid;

        if (cookie_pid <= 0)
            cookie_pid = priv->schedCoreChildPID;

        virCommandSetRunAmong(cmd, cookie_pid);
    }

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    if (virPidFileReadPath(pidfile, &cpid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("pr helper %1$s didn't show up"),
                       prHelperPath);
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
                                 _("pr helper %1$s died unexpectedly"),
                                 prHelperPath);
        } else {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("pr helper died and reported: %1$s"), errbuf);
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
    VIR_FORCE_CLOSE(errfd);
    return ret;
}


static int
qemuProcessInitPasswords(virQEMUDriver *driver,
                         virDomainObj *vm,
                         int asyncJob)
{
    int ret = 0;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    size_t i;

    for (i = 0; i < vm->def->ngraphics; ++i) {
        virDomainGraphicsDef *graphics = vm->def->graphics[i];
        if (graphics->type == VIR_DOMAIN_GRAPHICS_TYPE_VNC) {
            ret = qemuDomainChangeGraphicsPasswords(vm,
                                                    VIR_DOMAIN_GRAPHICS_TYPE_VNC,
                                                    &graphics->data.vnc.auth,
                                                    cfg->vncPassword,
                                                    asyncJob);
        } else if (graphics->type == VIR_DOMAIN_GRAPHICS_TYPE_SPICE) {
            ret = qemuDomainChangeGraphicsPasswords(vm,
                                                    VIR_DOMAIN_GRAPHICS_TYPE_SPICE,
                                                    &graphics->data.spice.auth,
                                                    cfg->spicePassword,
                                                    asyncJob);
        }

        if (ret < 0)
            return ret;
    }

    return ret;
}


static int
qemuProcessCleanupChardevDevice(virDomainDef *def G_GNUC_UNUSED,
                                virDomainChrDef *dev,
                                void *opaque G_GNUC_UNUSED)
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
qemuProcessUpdateVideoRamSize(virQEMUDriver *driver,
                              virDomainObj *vm,
                              int asyncJob)
{
    int ret = -1;
    ssize_t i;
    qemuDomainObjPrivate *priv = vm->privateData;
    virDomainVideoDef *video = NULL;
    g_autoptr(virQEMUDriverConfig) cfg = NULL;

    if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) < 0)
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
        case VIR_DOMAIN_VIDEO_TYPE_DEFAULT:
        case VIR_DOMAIN_VIDEO_TYPE_CIRRUS:
        case VIR_DOMAIN_VIDEO_TYPE_XEN:
        case VIR_DOMAIN_VIDEO_TYPE_VBOX:
        case VIR_DOMAIN_VIDEO_TYPE_PARALLELS:
        case VIR_DOMAIN_VIDEO_TYPE_VIRTIO:
        case VIR_DOMAIN_VIDEO_TYPE_GOP:
        case VIR_DOMAIN_VIDEO_TYPE_NONE:
        case VIR_DOMAIN_VIDEO_TYPE_BOCHS:
        case VIR_DOMAIN_VIDEO_TYPE_RAMFB:
        case VIR_DOMAIN_VIDEO_TYPE_LAST:
            break;
        }

    }

    qemuDomainObjExitMonitor(vm);

    cfg = virQEMUDriverGetConfig(driver);
    ret = virDomainObjSave(vm, driver->xmlopt, cfg->stateDir);

    return ret;

 error:
    qemuDomainObjExitMonitor(vm);
    return -1;
}


struct qemuProcessHookData {
    virDomainObj *vm;
    virQEMUDriver *driver;
    virQEMUDriverConfig *cfg;
};

static int qemuProcessHook(void *data)
{
    struct qemuProcessHookData *h = data;
    qemuDomainObjPrivate *priv = h->vm->privateData;
    int ret = -1;
    int fd;
    virBitmap *nodeset = NULL;
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

    if (qemuDomainUnshareNamespace(h->cfg, h->driver->securityManager, h->vm) < 0)
        goto cleanup;

    if (virDomainNumatuneGetMode(h->vm->def->numa, -1, &mode) == 0) {
        if ((mode == VIR_DOMAIN_NUMATUNE_MEM_STRICT ||
             mode == VIR_DOMAIN_NUMATUNE_MEM_RESTRICTIVE) &&
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
qemuProcessPrepareMonitorChr(virDomainChrSourceDef *monConfig,
                             const char *domainDir)
{
    monConfig->type = VIR_DOMAIN_CHR_TYPE_UNIX;
    monConfig->data.nix.listen = true;

    monConfig->data.nix.path = g_strdup_printf("%s/monitor.sock", domainDir);
    return 0;
}


/*
 * Precondition: vm must be locked, and a job must be active.
 * This method will call {Enter,Exit}Monitor
 */
int
qemuProcessStartCPUs(virQEMUDriver *driver, virDomainObj *vm,
                     virDomainRunningReason reason,
                     virDomainAsyncJob asyncJob)
{
    int ret = -1;
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);

    /* Bring up netdevs before starting CPUs */
    if (qemuInterfaceStartDevices(vm->def) < 0)
       return -1;

    VIR_DEBUG("Using lock state '%s'", NULLSTR(priv->lockState));
    if (virDomainLockProcessResume(driver->lockManager, cfg->uri,
                                   vm, priv->lockState) < 0) {
        /* Don't free priv->lockState on error, because we need
         * to make sure we have state still present if the user
         * tries to resume again
         */
        return -1;
    }
    VIR_FREE(priv->lockState);

    priv->runningReason = reason;

    if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) < 0)
        goto release;

    ret = qemuMonitorStartCPUs(priv->mon);
    qemuDomainObjExitMonitor(vm);

    if (ret < 0)
        goto release;

    /* The RESUME event handler will change the domain state with the reason
     * saved in priv->runningReason and it will also emit corresponding domain
     * lifecycle event.
     */

    return ret;

 release:
    priv->runningReason = VIR_DOMAIN_RUNNING_UNKNOWN;
    if (virDomainLockProcessPause(driver->lockManager, vm, &priv->lockState) < 0)
        VIR_WARN("Unable to release lease on %s", vm->def->name);
    VIR_DEBUG("Preserving lock state '%s'", NULLSTR(priv->lockState));
    return ret;
}


int qemuProcessStopCPUs(virQEMUDriver *driver,
                        virDomainObj *vm,
                        virDomainPausedReason reason,
                        virDomainAsyncJob asyncJob)
{
    int ret = -1;
    qemuDomainObjPrivate *priv = vm->privateData;

    VIR_FREE(priv->lockState);

    priv->pausedReason = reason;

    if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) < 0)
        goto cleanup;

    ret = qemuMonitorStopCPUs(priv->mon);
    qemuDomainObjExitMonitor(vm);

    if (ret < 0)
        goto cleanup;

    /* de-activate netdevs after stopping CPUs */
    ignore_value(qemuInterfaceStopDevices(vm->def));

    if (vm->job->current)
        ignore_value(virTimeMillisNow(&vm->job->current->stopped));

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
qemuProcessNotifyNets(virDomainDef *def)
{
    size_t i;
    g_autoptr(virConnect) conn = NULL;

    for (i = 0; i < def->nnets; i++) {
        virDomainNetDef *net = def->nets[i];
        /* keep others from trying to use the macvtap device name, but
         * don't return error if this happens, since that causes the
         * domain to be unceremoniously killed, which would be *very*
         * impolite.
         */
        switch (virDomainNetGetActualType(net)) {
        case VIR_DOMAIN_NET_TYPE_DIRECT:
            virNetDevReserveName(net->ifname);
            break;
        case VIR_DOMAIN_NET_TYPE_BRIDGE:
        case VIR_DOMAIN_NET_TYPE_NETWORK:
        case VIR_DOMAIN_NET_TYPE_ETHERNET:
            virNetDevReserveName(net->ifname);
            break;
        case VIR_DOMAIN_NET_TYPE_USER:
        case VIR_DOMAIN_NET_TYPE_VHOSTUSER:
        case VIR_DOMAIN_NET_TYPE_SERVER:
        case VIR_DOMAIN_NET_TYPE_CLIENT:
        case VIR_DOMAIN_NET_TYPE_MCAST:
        case VIR_DOMAIN_NET_TYPE_INTERNAL:
        case VIR_DOMAIN_NET_TYPE_HOSTDEV:
        case VIR_DOMAIN_NET_TYPE_UDP:
        case VIR_DOMAIN_NET_TYPE_VDPA:
        case VIR_DOMAIN_NET_TYPE_NULL:
        case VIR_DOMAIN_NET_TYPE_VDS:
        case VIR_DOMAIN_NET_TYPE_LAST:
            break;
        }

        if (net->type == VIR_DOMAIN_NET_TYPE_NETWORK && !conn)
            conn = virGetConnectNetwork();

        virDomainNetNotifyActualDevice(conn, def, net);
    }
}

/* Attempt to instantiate the filters. Ignore failures because it's
 * possible that someone deleted a filter binding and the associated
 * filter while the guest was running and we don't want that action
 * to cause failure to keep the guest running during the reconnection
 * processing. Nor do we necessarily want other failures to do the
 * same. We'll just log the error conditions other than of course
 * ignoreExists possibility (e.g. the true flag) */
static void
qemuProcessFiltersInstantiate(virDomainDef *def)
{
    size_t i;

    for (i = 0; i < def->nnets; i++) {
        virDomainNetDef *net = def->nets[i];
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
qemuProcessUpdateState(virDomainObj *vm)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    virDomainState state;
    virDomainPausedReason reason;
    virDomainState newState = VIR_DOMAIN_NOSTATE;
    int oldReason;
    int newReason;
    bool running;
    g_autofree char *msg = NULL;
    int ret;

    qemuDomainObjEnterMonitor(vm);
    ret = qemuMonitorGetStatus(priv->mon, &running, &reason);
    qemuDomainObjExitMonitor(vm);

    if (ret < 0)
        return -1;

    state = virDomainObjGetState(vm, &oldReason);

    if (running &&
        (state == VIR_DOMAIN_SHUTOFF ||
         (state == VIR_DOMAIN_PAUSED &&
          oldReason == VIR_DOMAIN_PAUSED_STARTING_UP))) {
        newState = VIR_DOMAIN_RUNNING;
        newReason = VIR_DOMAIN_RUNNING_BOOTED;
        msg = g_strdup("finished booting");
    } else if (state == VIR_DOMAIN_PAUSED && running) {
        newState = VIR_DOMAIN_RUNNING;
        newReason = VIR_DOMAIN_RUNNING_UNPAUSED;
        msg = g_strdup("was unpaused");
    } else if (state == VIR_DOMAIN_RUNNING && !running) {
        if (reason == VIR_DOMAIN_PAUSED_SHUTTING_DOWN) {
            newState = VIR_DOMAIN_SHUTDOWN;
            newReason = VIR_DOMAIN_SHUTDOWN_UNKNOWN;
            msg = g_strdup("shutdown");
        } else if (reason == VIR_DOMAIN_PAUSED_CRASHED) {
            newState = VIR_DOMAIN_CRASHED;
            newReason = VIR_DOMAIN_CRASHED_PANICKED;
            msg = g_strdup("crashed");
        } else {
            newState = VIR_DOMAIN_PAUSED;
            newReason = reason;
            msg = g_strdup_printf("was paused (%s)",
                                  virDomainPausedReasonTypeToString(reason));
        }
    }

    if (newState != VIR_DOMAIN_NOSTATE) {
        VIR_DEBUG("Domain %s %s while its monitor was disconnected;"
                  " changing state to %s (%s)",
                  vm->def->name,
                  NULLSTR(msg),
                  virDomainStateTypeToString(newState),
                  virDomainStateReasonToString(newState, newReason));
        virDomainObjSetState(vm, newState, newReason);
    }

    return 0;
}


void
qemuProcessCleanupMigrationJob(virQEMUDriver *driver,
                               virDomainObj *vm)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    virDomainState state;
    int reason;

    state = virDomainObjGetState(vm, &reason);

    VIR_DEBUG("driver=%p, vm=%s, asyncJob=%s, state=%s, reason=%s",
              driver, vm->def->name,
              virDomainAsyncJobTypeToString(vm->job->asyncJob),
              virDomainStateTypeToString(state),
              virDomainStateReasonToString(state, reason));

    if (vm->job->asyncJob != VIR_ASYNC_JOB_MIGRATION_IN &&
        vm->job->asyncJob != VIR_ASYNC_JOB_MIGRATION_OUT)
        return;

    virPortAllocatorRelease(priv->migrationPort);
    priv->migrationPort = 0;
    qemuDomainObjDiscardAsyncJob(vm);
}


static void
qemuProcessRestoreMigrationJob(virDomainObj *vm,
                               virDomainJobObj *job)
{
    qemuDomainJobPrivate *jobPriv = job->privateData;
    virDomainJobOperation op;
    unsigned long long allowedJobs;

    if (job->asyncJob == VIR_ASYNC_JOB_MIGRATION_IN) {
        op = VIR_DOMAIN_JOB_OPERATION_MIGRATION_IN;
        allowedJobs = VIR_JOB_NONE;
    } else {
        op = VIR_DOMAIN_JOB_OPERATION_MIGRATION_OUT;
        allowedJobs = VIR_JOB_DEFAULT_MASK | JOB_MASK(VIR_JOB_MIGRATION_OP);
    }
    allowedJobs |= JOB_MASK(VIR_JOB_MODIFY_MIGRATION_SAFE);

    qemuDomainObjRestoreAsyncJob(vm, job->asyncJob, job->phase,
                                 job->asyncStarted, op,
                                 QEMU_DOMAIN_JOB_STATS_TYPE_MIGRATION,
                                 VIR_DOMAIN_JOB_STATUS_PAUSED,
                                 allowedJobs);

    job->privateData = g_steal_pointer(&vm->job->privateData);
    vm->job->privateData = jobPriv;
    vm->job->apiFlags = job->apiFlags;
    vm->job->asyncPaused = job->asyncPaused;

    qemuDomainCleanupAdd(vm, qemuProcessCleanupMigrationJob);
}


/*
 * Returns
 *     -1 on error, the domain will be killed,
 *      0 the domain should remain running with the migration job discarded,
 *      1 the daemon was restarted during post-copy phase
 */
static int
qemuProcessRecoverMigrationIn(virQEMUDriver *driver,
                              virDomainObj *vm,
                              virDomainJobObj *job,
                              virDomainState state)
{
    VIR_DEBUG("Active incoming migration in phase %s",
              qemuMigrationJobPhaseTypeToString(job->phase));

    switch ((qemuMigrationJobPhase) job->phase) {
    case QEMU_MIGRATION_PHASE_NONE:
    case QEMU_MIGRATION_PHASE_PERFORM2:
    case QEMU_MIGRATION_PHASE_BEGIN3:
    case QEMU_MIGRATION_PHASE_PERFORM3:
    case QEMU_MIGRATION_PHASE_PERFORM3_DONE:
    case QEMU_MIGRATION_PHASE_CONFIRM3_CANCELLED:
    case QEMU_MIGRATION_PHASE_CONFIRM3:
    case QEMU_MIGRATION_PHASE_BEGIN_RESUME:
    case QEMU_MIGRATION_PHASE_PERFORM_RESUME:
    case QEMU_MIGRATION_PHASE_CONFIRM_RESUME:
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
                                 VIR_ASYNC_JOB_NONE) < 0) {
            VIR_WARN("Could not resume domain %s", vm->def->name);
        }
        break;

    case QEMU_MIGRATION_PHASE_FINISH3:
        /* migration finished, we started resuming the domain but didn't
         * confirm success or failure yet; killing it seems safest unless
         * we already started guest CPUs or we were in post-copy mode */
        if (virDomainObjIsPostcopy(vm, job))
            return 1;

        if (state != VIR_DOMAIN_RUNNING) {
            VIR_DEBUG("Killing migrated domain %s", vm->def->name);
            return -1;
        }
        break;

    case QEMU_MIGRATION_PHASE_POSTCOPY_FAILED:
    case QEMU_MIGRATION_PHASE_PREPARE_RESUME:
    case QEMU_MIGRATION_PHASE_FINISH_RESUME:
        return 1;
    }

    return 0;
}


/*
 * Returns
 *     -1 the domain should be killed (either after a successful migration or
 *        on error),
 *      0 the domain should remain running with the migration job discarded,
 *      1 the daemon was restarted during post-copy phase
 */
static int
qemuProcessRecoverMigrationOut(virQEMUDriver *driver,
                               virDomainObj *vm,
                               virDomainJobObj *job,
                               virDomainJobStatus migStatus,
                               virDomainState state,
                               int reason,
                               unsigned int *stopFlags)
{
    bool postcopy = virDomainObjIsPostcopy(vm, job);
    bool resume = false;

    VIR_DEBUG("Active outgoing migration in phase %s",
              qemuMigrationJobPhaseTypeToString(job->phase));

    switch ((qemuMigrationJobPhase) job->phase) {
    case QEMU_MIGRATION_PHASE_NONE:
    case QEMU_MIGRATION_PHASE_PREPARE:
    case QEMU_MIGRATION_PHASE_FINISH2:
    case QEMU_MIGRATION_PHASE_FINISH3:
    case QEMU_MIGRATION_PHASE_PREPARE_RESUME:
    case QEMU_MIGRATION_PHASE_FINISH_RESUME:
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
         * domain; we can do so even in post-copy phase as the domain was not
         * resumed on the destination host yet
         */
        VIR_DEBUG("Cancelling unfinished migration of domain %s",
                  vm->def->name);
        if (qemuMigrationSrcCancelUnattended(vm, job) < 0) {
            VIR_WARN("Could not cancel ongoing migration of domain %s",
                     vm->def->name);
        }
        resume = true;
        break;

    case QEMU_MIGRATION_PHASE_PERFORM3_DONE:
        /* migration finished but we didn't have a chance to get the result
         * of Finish3 step; third party needs to check what to do next; in
         * post-copy mode we can use PAUSED_POSTCOPY_FAILED state for this
         */
        if (postcopy)
            return 1;
        break;

    case QEMU_MIGRATION_PHASE_CONFIRM3_CANCELLED:
        /* Finish3 failed, we need to resume the domain, but once we enter
         * post-copy mode there's no way back, so let's just mark the domain
         * as broken in that case
         */
        if (postcopy)
            return 1;

        VIR_DEBUG("Resuming domain %s after failed migration",
                  vm->def->name);
        resume = true;
        break;

    case QEMU_MIGRATION_PHASE_CONFIRM3:
        /* migration completed, we need to kill the domain here */
        *stopFlags |= VIR_QEMU_PROCESS_STOP_MIGRATED;
        return -1;

    case QEMU_MIGRATION_PHASE_CONFIRM_RESUME:
        if (migStatus == VIR_DOMAIN_JOB_STATUS_HYPERVISOR_COMPLETED) {
            /* migration completed, we need to kill the domain here */
            *stopFlags |= VIR_QEMU_PROCESS_STOP_MIGRATED;
            return -1;
        }
        return 1;

    case QEMU_MIGRATION_PHASE_POSTCOPY_FAILED:
    case QEMU_MIGRATION_PHASE_BEGIN_RESUME:
    case QEMU_MIGRATION_PHASE_PERFORM_RESUME:
        return 1;
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
                                     VIR_ASYNC_JOB_NONE) < 0) {
                VIR_WARN("Could not resume domain %s", vm->def->name);
            }
        }
    }

    return 0;
}


static int
qemuProcessRecoverMigration(virQEMUDriver *driver,
                            virDomainObj *vm,
                            virDomainJobObj *job,
                            unsigned int *stopFlags)
{
    virDomainJobStatus migStatus = VIR_DOMAIN_JOB_STATUS_NONE;
    qemuDomainJobPrivate *jobPriv = job->privateData;
    qemuDomainObjPrivate *priv = vm->privateData;
    virDomainState state;
    int reason;
    int rc;

    state = virDomainObjGetState(vm, &reason);

    qemuMigrationAnyRefreshStatus(vm, VIR_ASYNC_JOB_NONE, &migStatus);

    if (job->asyncJob == VIR_ASYNC_JOB_MIGRATION_OUT) {
        rc = qemuProcessRecoverMigrationOut(driver, vm, job, migStatus,
                                            state, reason, stopFlags);
    } else {
        rc = qemuProcessRecoverMigrationIn(driver, vm, job, state);
    }

    if (rc < 0)
        return -1;

    if (rc > 0) {
        job->phase = QEMU_MIGRATION_PHASE_POSTCOPY_FAILED;
        /* Even though we restore the migration async job here, the APIs below
         * use VIR_ASYNC_JOB_NONE because we're already in a MODIFY job started
         * before we reconnected to the domain. */
        qemuProcessRestoreMigrationJob(vm, job);

        if (migStatus == VIR_DOMAIN_JOB_STATUS_POSTCOPY) {
            VIR_DEBUG("Post-copy migration of domain %s still running, it will be handled as unattended",
                      vm->def->name);
            vm->job->asyncPaused = false;
            return 0;
        }

        if (migStatus != VIR_DOMAIN_JOB_STATUS_HYPERVISOR_COMPLETED) {
            if (job->asyncJob == VIR_ASYNC_JOB_MIGRATION_OUT)
                qemuMigrationSrcPostcopyFailed(vm);
            else
                qemuMigrationDstPostcopyFailed(vm);
            /* Set the asyncPaused flag in case we're reconnecting to a domain
             * started by an older libvirt. */
            vm->job->asyncPaused = true;
            return 0;
        }

        VIR_DEBUG("Post-copy migration of domain %s already finished",
                  vm->def->name);
        if (job->asyncJob == VIR_ASYNC_JOB_MIGRATION_OUT) {
            qemuMigrationSrcComplete(driver, vm, VIR_ASYNC_JOB_NONE);
            /* No need to stop the restored job as the domain has just been
             * destroyed. */
        } else {
            qemuMigrationDstComplete(driver, vm, true, VIR_ASYNC_JOB_NONE, job);
            virDomainObjEndAsyncJob(vm);
        }
        return 0;
    }

    qemuMigrationParamsReset(vm, VIR_ASYNC_JOB_NONE,
                             jobPriv->migParams, job->apiFlags);
    qemuDomainSetMaxMemLock(vm, 0, &priv->preMigrationMemlock);

    return 0;
}


static void
qemuProcessAbortSnapshotDelete(virDomainObj *vm,
                               virDomainJobObj *job)
{
    size_t i;
    qemuDomainObjPrivate *priv = vm->privateData;
    qemuDomainJobPrivate *jobPriv = job->privateData;

    if (!jobPriv->snapshotDelete)
        return;

    for (i = 0; i < vm->def->ndisks; i++) {
        virDomainDiskDef *disk = vm->def->disks[i];
        g_autoptr(qemuBlockJobData) diskJob = qemuBlockJobDiskGetJob(disk);

        if (!diskJob)
            continue;

        if (diskJob->type != QEMU_BLOCKJOB_TYPE_COMMIT &&
            diskJob->type != QEMU_BLOCKJOB_TYPE_ACTIVE_COMMIT) {
            continue;
        }

        qemuBlockJobSyncBegin(diskJob);

        qemuDomainObjEnterMonitor(vm);
        ignore_value(qemuMonitorBlockJobCancel(priv->mon, diskJob->name, false));
        qemuDomainObjExitMonitor(vm);

        diskJob->state = QEMU_BLOCKJOB_STATE_ABORTING;

        qemuBlockJobSyncEnd(vm, diskJob, VIR_ASYNC_JOB_NONE);
    }
}


static int
qemuProcessRecoverJob(virQEMUDriver *driver,
                      virDomainObj *vm,
                      virDomainJobObj *job,
                      unsigned int *stopFlags)
{
    virDomainState state;
    int reason;

    state = virDomainObjGetState(vm, &reason);

    VIR_DEBUG("Recovering job for domain %s, state=%s(%s), async=%s, job=%s",
              vm->def->name,
              virDomainStateTypeToString(state),
              virDomainStateReasonToString(state, reason),
              virDomainAsyncJobTypeToString(job->asyncJob),
              virDomainJobTypeToString(job->active));

    switch (job->asyncJob) {
    case VIR_ASYNC_JOB_MIGRATION_OUT:
    case VIR_ASYNC_JOB_MIGRATION_IN:
        if (qemuProcessRecoverMigration(driver, vm, job, stopFlags) < 0)
            return -1;
        break;

    case VIR_ASYNC_JOB_SAVE:
    case VIR_ASYNC_JOB_DUMP:
    case VIR_ASYNC_JOB_SNAPSHOT:
        qemuMigrationSrcCancel(vm, VIR_ASYNC_JOB_NONE, false);
        /* resume the domain but only if it was paused as a result of
         * running a migration-to-file operation.  Although we are
         * recovering an async job, this function is run at startup
         * and must resume things using sync monitor connections.  */
         if (state == VIR_DOMAIN_PAUSED &&
             ((job->asyncJob == VIR_ASYNC_JOB_DUMP &&
               reason == VIR_DOMAIN_PAUSED_DUMP) ||
              (job->asyncJob == VIR_ASYNC_JOB_SAVE &&
               reason == VIR_DOMAIN_PAUSED_SAVE) ||
              (job->asyncJob == VIR_ASYNC_JOB_SNAPSHOT &&
               (reason == VIR_DOMAIN_PAUSED_SNAPSHOT ||
                reason == VIR_DOMAIN_PAUSED_MIGRATION)) ||
              reason == VIR_DOMAIN_PAUSED_UNKNOWN)) {
             if (qemuProcessStartCPUs(driver, vm,
                                      VIR_DOMAIN_RUNNING_SAVE_CANCELED,
                                      VIR_ASYNC_JOB_NONE) < 0) {
                 VIR_WARN("Could not resume domain '%s' after migration to file",
                          vm->def->name);
            }
        }
        qemuProcessAbortSnapshotDelete(vm, job);
        break;

    case VIR_ASYNC_JOB_START:
        /* Already handled in VIR_DOMAIN_PAUSED_STARTING_UP check. */
        break;

    case VIR_ASYNC_JOB_BACKUP:
        /* Restore the config of the async job which is not persisted */
        qemuDomainObjRestoreAsyncJob(vm, VIR_ASYNC_JOB_BACKUP, 0,
                                     job->asyncStarted,
                                     VIR_DOMAIN_JOB_OPERATION_BACKUP,
                                     QEMU_DOMAIN_JOB_STATS_TYPE_BACKUP,
                                     VIR_DOMAIN_JOB_STATUS_ACTIVE,
                                     (VIR_JOB_DEFAULT_MASK |
                                      JOB_MASK(VIR_JOB_SUSPEND) |
                                      JOB_MASK(VIR_JOB_MODIFY)));
        break;

    case VIR_ASYNC_JOB_NONE:
    case VIR_ASYNC_JOB_LAST:
        break;
    }

    if (!virDomainObjIsActive(vm))
        return -1;

    /* In case any special handling is added for job type that has been ignored
     * before, VIR_DOMAIN_TRACK_JOBS (from qemu_domain.h) needs to be updated
     * for the job to be properly tracked in domain state XML.
     */
    switch (job->active) {
    case VIR_JOB_QUERY:
        /* harmless */
        break;

    case VIR_JOB_DESTROY:
        VIR_DEBUG("Domain %s should have already been destroyed",
                  vm->def->name);
        return -1;

    case VIR_JOB_SUSPEND:
        /* mostly harmless */
        break;

    case VIR_JOB_MODIFY:
        /* XXX depending on the command we may be in an inconsistent state and
         * we should probably fall back to "monitor error" state and refuse to
         */
        break;

    case VIR_JOB_MODIFY_MIGRATION_SAFE:
        /* event handlers, the reconnection code already handles them as we
         * might as well just missed the event while we were not running
         */
        break;

    case VIR_JOB_MIGRATION_OP:
    case VIR_JOB_ABORT:
    case VIR_JOB_ASYNC:
    case VIR_JOB_ASYNC_NESTED:
        /* async job was already handled above */
    case VIR_JOB_NONE:
    case VIR_JOB_LAST:
        break;
    }

    return 0;
}

static int
qemuProcessUpdateDevices(virQEMUDriver *driver,
                         virDomainObj *vm)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    virDomainDeviceDef dev;
    g_auto(GStrv) old = g_steal_pointer(&priv->qemuDevices);
    GStrv tmp;

    if (qemuDomainUpdateDeviceList(vm, VIR_ASYNC_JOB_NONE) < 0)
        return -1;

    if (!old)
        return 0;

    for (tmp = old; *tmp; tmp++) {
        if (!g_strv_contains((const char **) priv->qemuDevices, *tmp) &&
            virDomainDefFindDevice(vm->def, *tmp, &dev, false) == 0 &&
            qemuDomainRemoveDevice(driver, vm, &dev))
            return -1;
    }

    return 0;
}

static int
qemuDomainPerfRestart(virDomainObj *vm)
{
    size_t i;
    virDomainDef *def = vm->def;
    qemuDomainObjPrivate *priv = vm->privateData;

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


static bool
qemuProcessDomainMemoryDefNeedHugepagesPath(const virDomainMemoryDef *mem,
                                            const long system_pagesize)
{
    unsigned long long pagesize = 0;

    switch (mem->model) {
    case VIR_DOMAIN_MEMORY_MODEL_DIMM:
        pagesize = mem->source.dimm.pagesize;
        break;
    case VIR_DOMAIN_MEMORY_MODEL_VIRTIO_MEM:
        pagesize = mem->source.virtio_mem.pagesize;
        break;
    case VIR_DOMAIN_MEMORY_MODEL_NONE:
    case VIR_DOMAIN_MEMORY_MODEL_NVDIMM:
    case VIR_DOMAIN_MEMORY_MODEL_VIRTIO_PMEM:
    case VIR_DOMAIN_MEMORY_MODEL_SGX_EPC:
    case VIR_DOMAIN_MEMORY_MODEL_LAST:
        /* None of these can be backed by hugepages. */
        return false;
    }

    return pagesize != 0 && pagesize != system_pagesize;
}


static bool
qemuProcessNeedHugepagesPath(virDomainDef *def,
                             virDomainMemoryDef *mem)
{
    const long system_pagesize = virGetSystemPageSizeKB();
    size_t i;

    switch ((virDomainMemorySource)def->mem.source) {
    case VIR_DOMAIN_MEMORY_SOURCE_FILE:
        /* This needs a hugetlbfs mount. */
        return true;
    case VIR_DOMAIN_MEMORY_SOURCE_MEMFD:
        /* memfd works without a hugetlbfs mount */
        return false;
    case VIR_DOMAIN_MEMORY_SOURCE_NONE:
    case VIR_DOMAIN_MEMORY_SOURCE_ANONYMOUS:
    case VIR_DOMAIN_MEMORY_SOURCE_LAST:
        break;
    }

    for (i = 0; i < def->mem.nhugepages; i++) {
        if (def->mem.hugepages[i].size != system_pagesize)
            return true;
    }

    for (i = 0; i < def->nmems; i++) {
        if (qemuProcessDomainMemoryDefNeedHugepagesPath(def->mems[i], system_pagesize))
            return true;
    }

    if (mem &&
        qemuProcessDomainMemoryDefNeedHugepagesPath(mem, system_pagesize))
        return true;

    return false;
}


static bool
qemuProcessNeedMemoryBackingPath(virDomainDef *def,
                                 virDomainMemoryDef *mem)
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

    for (i = 0; i < def->nmems; i++) {
        if (def->mems[i]->access != VIR_DOMAIN_MEMORY_ACCESS_DEFAULT)
            return true;
    }

    if (mem) {
        switch (mem->model) {
        case VIR_DOMAIN_MEMORY_MODEL_DIMM:
        case VIR_DOMAIN_MEMORY_MODEL_VIRTIO_MEM:
            if (mem->access != VIR_DOMAIN_MEMORY_ACCESS_DEFAULT) {
                /* No need to check for access mode on the target node,
                 * it was checked for in the previous loop. */
                return true;
            }
            break;

        case VIR_DOMAIN_MEMORY_MODEL_NONE:
        case VIR_DOMAIN_MEMORY_MODEL_NVDIMM:
        case VIR_DOMAIN_MEMORY_MODEL_VIRTIO_PMEM:
        case VIR_DOMAIN_MEMORY_MODEL_SGX_EPC:
        case VIR_DOMAIN_MEMORY_MODEL_LAST:
            /* Backed by user provided path. Not stored in memory
             * backing dir anyway. */
            break;
        }
    }

    return false;
}


static int
qemuProcessBuildDestroyMemoryPathsImpl(virQEMUDriver *driver,
                                       virDomainObj *vm,
                                       const char *path,
                                       bool build)
{
    if (build) {
        if (virFileExists(path))
            return 0;

        if (g_mkdir_with_parents(path, 0700) < 0) {
            virReportSystemError(errno,
                                 _("Unable to create %1$s"),
                                 path);
            return -1;
        }

        if (qemuDomainNamespaceSetupPath(vm, path, NULL) < 0)
            return -1;

        if (qemuSecurityDomainSetPathLabel(driver, vm, path, true) < 0)
            return -1;
    } else {
        if (virFileDeleteTree(path) < 0)
            return -1;
    }

    return 0;
}


int
qemuProcessBuildDestroyMemoryPaths(virQEMUDriver *driver,
                                   virDomainObj *vm,
                                   virDomainMemoryDef *mem,
                                   bool build)
{

    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    size_t i;
    bool shouldBuildHP = false;
    bool shouldBuildMB = false;

    if (build) {
        shouldBuildHP = qemuProcessNeedHugepagesPath(vm->def, mem);
        shouldBuildMB = qemuProcessNeedMemoryBackingPath(vm->def, mem);
    }

    if (!build || shouldBuildHP) {
        for (i = 0; i < cfg->nhugetlbfs; i++) {
            g_autofree char *path = NULL;
            path = qemuGetDomainHugepagePath(driver, vm->def, &cfg->hugetlbfs[i]);

            if (!path)
                return -1;

            if (build &&
                qemuHugepageMakeBasedir(driver, &cfg->hugetlbfs[i]) < 0)
                return -1;

            if (qemuProcessBuildDestroyMemoryPathsImpl(driver, vm,
                                                       path, build) < 0)
                return -1;
        }
    }

    if (!build || shouldBuildMB) {
        g_autofree char *path = NULL;
        if (qemuGetMemoryBackingDomainPath(driver, vm->def, &path) < 0)
            return -1;

        if (qemuProcessBuildDestroyMemoryPathsImpl(driver, vm,
                                                   path, build) < 0)
            return -1;
    }

    return 0;
}


int
qemuProcessDestroyMemoryBackingPath(virQEMUDriver *driver,
                                    virDomainObj *vm,
                                    virDomainMemoryDef *mem)
{
    g_autofree char *path = NULL;

    if (qemuGetMemoryBackingPath(driver, vm->def, mem->info.alias, &path) < 0)
        return -1;

    if (unlink(path) < 0 &&
        errno != ENOENT) {
        virReportSystemError(errno, _("Unable to remove %1$s"), path);
        return -1;
    }

    return 0;
}


static int
qemuProcessVNCAllocatePorts(virQEMUDriver *driver,
                            virDomainGraphicsDef *graphics,
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
        graphics->data.vnc.portReserved = true;
    }

    if (graphics->data.vnc.websocket == -1) {
        if (virPortAllocatorAcquire(driver->webSocketPorts, &port) < 0)
            return -1;
        graphics->data.vnc.websocket = port;
        graphics->data.vnc.websocketGenerated = true;
        graphics->data.vnc.websocketReserved = true;
    }

    return 0;
}

static int
qemuProcessSPICEAllocatePorts(virQEMUDriver *driver,
                              virDomainGraphicsDef *graphics,
                              bool allocate)
{
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    unsigned short port = 0;
    unsigned short tlsPort;
    size_t i;
    int defaultMode = graphics->data.spice.defaultMode;

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

        return 0;
    }

    if (needPort || graphics->data.spice.port == -1) {
        if (virPortAllocatorAcquire(driver->remotePorts, &port) < 0)
            return -1;

        graphics->data.spice.port = port;
        graphics->data.spice.portReserved = true;
    }

    if (needTLSPort || graphics->data.spice.tlsPort == -1) {
        if (!cfg->spiceTLS) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Auto allocation of spice TLS port requested but spice TLS is disabled in qemu.conf"));
            return -1;
        }

        if (virPortAllocatorAcquire(driver->remotePorts, &tlsPort) < 0)
            return -1;

        graphics->data.spice.tlsPort = tlsPort;
        graphics->data.spice.tlsPortReserved = true;
    }

    return 0;
}


static int
qemuProcessVerifyHypervFeatures(virDomainDef *def,
                                virCPUData *cpu)
{
    size_t i;
    int rc;

    for (i = 0; i < VIR_DOMAIN_HYPERV_LAST; i++) {
        g_autofree char *cpuFeature = NULL;

        /* always supported string property */
        if (i == VIR_DOMAIN_HYPERV_VENDOR_ID ||
            i == VIR_DOMAIN_HYPERV_SPINLOCKS)
            continue;

        if (def->hyperv_features[i] != VIR_TRISTATE_SWITCH_ON)
            continue;

        cpuFeature = g_strdup_printf("hv-%s", virDomainHypervTypeToString(i));

        rc = virCPUDataCheckFeature(cpu, cpuFeature);

        if (rc < 0) {
            return -1;
        } else if (rc == 1) {
            if (i == VIR_DOMAIN_HYPERV_STIMER) {
                if (def->hyperv_stimer_direct != VIR_TRISTATE_SWITCH_ON)
                    continue;

                rc = virCPUDataCheckFeature(cpu, VIR_CPU_x86_HV_STIMER_DIRECT);
                if (rc < 0)
                    return -1;
                else if (rc == 1)
                    continue;

                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("host doesn't support hyperv stimer '%1$s' feature"),
                               "direct");
                return -1;
            }
            continue;
        }

        switch ((virDomainHyperv) i) {
        case VIR_DOMAIN_HYPERV_RELAXED:
        case VIR_DOMAIN_HYPERV_VAPIC:
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
        case VIR_DOMAIN_HYPERV_AVIC:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("host doesn't support hyperv '%1$s' feature"),
                           virDomainHypervTypeToString(i));
            return -1;

        case VIR_DOMAIN_HYPERV_SPINLOCKS:
        case VIR_DOMAIN_HYPERV_VENDOR_ID:
        case VIR_DOMAIN_HYPERV_LAST:
            break;
        }
    }

    return 0;
}


static int
qemuProcessVerifyKVMFeatures(virDomainDef *def,
                             virCPUData *cpu)
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
qemuProcessVerifyCPUFeatures(virDomainDef *def,
                             virCPUData *cpu)
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


/* returns the QOM path to the first vcpu */
static const char *
qemuProcessGetVCPUQOMPath(virDomainObj *vm)
{
    virDomainVcpuDef *vcpu = virDomainDefGetVcpu(vm->def, 0);
    qemuDomainVcpuPrivate *vcpupriv;

    if (vcpu &&
        (vcpupriv = QEMU_DOMAIN_VCPU_PRIVATE(vcpu)) &&
        vcpupriv->qomPath)
        return vcpupriv->qomPath;

    return "/machine/unattached/device[0]";
}


static int
qemuProcessFetchGuestCPU(virDomainObj *vm,
                         virDomainAsyncJob asyncJob,
                         virCPUData **enabled,
                         virCPUData **disabled)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autoptr(virCPUData) dataEnabled = NULL;
    g_autoptr(virCPUData) dataDisabled = NULL;
    const char *cpuQOMPath = qemuProcessGetVCPUQOMPath(vm);
    bool generic;
    int rc;

    *enabled = NULL;
    *disabled = NULL;

    generic = virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_CPU_UNAVAILABLE_FEATURES);

    if (!generic && !ARCH_IS_X86(vm->def->os.arch))
        return 0;

    if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) < 0)
        return -1;

    if (generic) {
        rc = qemuMonitorGetGuestCPU(priv->mon,
                                    vm->def->os.arch,
                                    cpuQOMPath,
                                    virQEMUCapsCPUFeatureFromQEMU,
                                    &dataEnabled, &dataDisabled);
    } else {
        rc = qemuMonitorGetGuestCPUx86(priv->mon, cpuQOMPath, &dataEnabled, &dataDisabled);
    }

    qemuDomainObjExitMonitor(vm);

    if (rc == -1)
        return -1;

    *enabled = g_steal_pointer(&dataEnabled);
    *disabled = g_steal_pointer(&dataDisabled);
    return 0;
}


static int
qemuProcessVerifyCPU(virDomainObj *vm,
                     virCPUData *cpu)
{
    virDomainDef *def = vm->def;

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
qemuProcessUpdateLiveGuestCPU(virDomainObj *vm,
                              virCPUData *enabled,
                              virCPUData *disabled)
{
    virDomainDef *def = vm->def;
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autoptr(virCPUDef) orig = NULL;
    int rc;

    if (!enabled)
        return 0;

    if (!def->cpu ||
        (def->cpu->mode == VIR_CPU_MODE_CUSTOM &&
         !def->cpu->model))
        return 0;

    orig = virCPUDefCopy(def->cpu);

    if ((rc = virCPUUpdateLive(def->os.arch, def->cpu, enabled, disabled)) < 0) {
        return -1;
    } else if (rc == 0) {
        /* Store the original CPU in priv if QEMU changed it and we didn't
         * get the original CPU via migration, restore, or snapshot revert.
         */
        if (!priv->origCPU && !virCPUDefIsEqual(def->cpu, orig, false))
            priv->origCPU = g_steal_pointer(&orig);

        def->cpu->check = VIR_CPU_CHECK_FULL;
    }

    return 0;
}


static int
qemuProcessUpdateAndVerifyCPU(virDomainObj *vm,
                              virDomainAsyncJob asyncJob)
{
    g_autoptr(virCPUData) cpu = NULL;
    g_autoptr(virCPUData) disabled = NULL;

    if (qemuProcessFetchGuestCPU(vm, asyncJob, &cpu, &disabled) < 0)
        return -1;

    if (qemuProcessVerifyCPU(vm, cpu) < 0)
        return -1;

    if (qemuProcessUpdateLiveGuestCPU(vm, cpu, disabled) < 0)
        return -1;

    return 0;
}


static int
qemuProcessFetchCPUDefinitions(virDomainObj *vm,
                               virDomainAsyncJob asyncJob,
                               virDomainCapsCPUModels **cpuModels)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autoptr(virDomainCapsCPUModels) models = NULL;
    int rc;

    if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) < 0)
        return -1;

    rc = virQEMUCapsFetchCPUModels(priv->mon, vm->def->os.arch, &models);

    qemuDomainObjExitMonitor(vm);
    if (rc < 0)
        return -1;

    *cpuModels = g_steal_pointer(&models);
    return 0;
}


static int
qemuProcessUpdateCPU(virDomainObj *vm,
                     virDomainAsyncJob asyncJob)
{
    g_autoptr(virCPUData) cpu = NULL;
    g_autoptr(virCPUData) disabled = NULL;
    g_autoptr(virDomainCapsCPUModels) models = NULL;

    /* The host CPU model comes from host caps rather than QEMU caps so
     * fallback must be allowed no matter what the user specified in the XML.
     */
    vm->def->cpu->fallback = VIR_CPU_FALLBACK_ALLOW;

    if (qemuProcessFetchGuestCPU(vm, asyncJob, &cpu, &disabled) < 0)
        return -1;

    if (qemuProcessUpdateLiveGuestCPU(vm, cpu, disabled) < 0)
        return -1;

    if (qemuProcessFetchCPUDefinitions(vm, asyncJob, &models) < 0 ||
        virCPUTranslate(vm->def->os.arch, vm->def->cpu, models) < 0)
        return -1;

    return 0;
}


struct qemuPrepareNVRAMHelperData {
    int srcFD;
    const char *srcPath;
};

static int
qemuPrepareNVRAMHelper(int dstFD,
                       const char *dstPath,
                       const void *opaque)
{
    const struct qemuPrepareNVRAMHelperData *data = opaque;
    ssize_t r;

    do {
        char buf[1024];

        if ((r = saferead(data->srcFD, buf, sizeof(buf))) < 0) {
            virReportSystemError(errno,
                                 _("Unable to read from file '%1$s'"),
                                 data->srcPath);
            return -2;
        }

        if (safewrite(dstFD, buf, r) < 0) {
            virReportSystemError(errno,
                                 _("Unable to write to file '%1$s'"),
                                 dstPath);
            return -1;
        }
    } while (r);

    return 0;
}


static int
qemuPrepareNVRAM(virQEMUDriver *driver,
                 virDomainObj *vm,
                 bool reset_nvram)
{
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    VIR_AUTOCLOSE srcFD = -1;
    virDomainLoaderDef *loader = vm->def->os.loader;
    struct qemuPrepareNVRAMHelperData data;

    if (!loader || !loader->nvram)
        return 0;

    if (!virStorageSourceIsLocalStorage(loader->nvram)) {
        if (!reset_nvram) {
            return 0;
        } else {
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                    _("resetting of nvram is not supported with network backed nvram"));
            return -1;
        }
    }

    if (virFileExists(loader->nvram->path) && !reset_nvram)
        return 0;

    if (!loader->nvramTemplate) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("unable to find any master var store for loader: %1$s"),
                       loader->path);
        return -1;
    }

    if ((srcFD = virFileOpenAs(loader->nvramTemplate, O_RDONLY,
                               0, -1, -1, 0)) < 0) {
        virReportSystemError(-srcFD,
                             _("Failed to open file '%1$s'"),
                             loader->nvramTemplate);
        return -1;
    }

    data.srcFD = srcFD;
    data.srcPath = loader->nvramTemplate;

    if (virFileRewrite(loader->nvram->path,
                       S_IRUSR | S_IWUSR,
                       cfg->user, cfg->group,
                       qemuPrepareNVRAMHelper,
                       &data) < 0) {
        return -1;
    }

    return 0;
}


static void
qemuLogOperation(virDomainObj *vm,
                 const char *msg,
                 virCommand *cmd,
                 qemuLogContext *logCtxt)
{
    g_autofree char *timestamp = NULL;
    qemuDomainObjPrivate *priv = vm->privateData;
    int qemuVersion = virQEMUCapsGetVersion(priv->qemuCaps);
    const char *package = virQEMUCapsGetPackage(priv->qemuCaps);
    g_autofree char *hostname = virGetHostname();
    struct utsname uts;

    uname(&uts);

    if ((timestamp = virTimeStringNow()) == NULL)
        return;

    if (qemuLogContextWrite(logCtxt,
                            "%s: %s %s, qemu version: %d.%d.%d%s, kernel: %s, hostname: %s\n",
                            timestamp, msg, VIR_LOG_VERSION_STRING,
                            (qemuVersion / 1000000) % 1000,
                            (qemuVersion / 1000) % 1000,
                            qemuVersion % 1000,
                            NULLSTR_EMPTY(package),
                            uts.release,
                            NULLSTR_EMPTY(hostname)) < 0)
        return;

    if (cmd) {
        g_autofree char *args = virCommandToString(cmd, true);
        qemuLogContextWrite(logCtxt, "%s\n", args);
    }
}


void
qemuProcessIncomingDefFree(qemuProcessIncomingDef *inc)
{
    if (!inc)
        return;

    g_free(inc->address);
    g_free(inc->uri);
    g_free(inc);
}


/*
 * This function does not copy @path, the caller is responsible for keeping
 * the @path pointer valid during the lifetime of the allocated
 * qemuProcessIncomingDef structure.
 *
 * The caller is responsible for closing @fd, calling
 * qemuProcessIncomingDefFree will NOT close it.
 */
qemuProcessIncomingDef *
qemuProcessIncomingDefNew(virQEMUCaps *qemuCaps,
                          const char *listenAddress,
                          const char *migrateFrom,
                          int fd,
                          const char *path)
{
    qemuProcessIncomingDef *inc = NULL;

    if (qemuMigrationDstCheckProtocol(qemuCaps, migrateFrom) < 0)
        return NULL;

    inc = g_new0(qemuProcessIncomingDef, 1);

    inc->address = g_strdup(listenAddress);

    inc->uri = qemuMigrationDstGetURI(migrateFrom, fd);
    if (!inc->uri)
        goto error;

    inc->fd = fd;
    inc->path = path;

    return inc;

 error:
    qemuProcessIncomingDefFree(inc);
    return NULL;
}


/*
 * This function starts a new VIR_ASYNC_JOB_START async job. The user is
 * responsible for calling qemuProcessEndJob to stop this job and for passing
 * VIR_ASYNC_JOB_START as @asyncJob argument to any function requiring this
 * parameter between qemuProcessBeginJob and qemuProcessEndJob.
 */
int
qemuProcessBeginJob(virDomainObj *vm,
                    virDomainJobOperation operation,
                    unsigned int apiFlags)
{
    if (virDomainObjBeginAsyncJob(vm, VIR_ASYNC_JOB_START,
                                   operation, apiFlags) < 0)
        return -1;

    qemuDomainObjSetAsyncJobMask(vm, VIR_JOB_NONE);
    return 0;
}


void
qemuProcessEndJob(virDomainObj *vm)
{
    virDomainObjEndAsyncJob(vm);
}


static int
qemuProcessStartHook(virQEMUDriver *driver,
                     virDomainObj *vm,
                     virHookQemuOpType op,
                     virHookSubopType subop)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autofree char *xml = NULL;
    int ret;

    if (!virHookPresent(VIR_HOOK_DRIVER_QEMU))
        return 0;

    if (!(xml = qemuDomainDefFormatXML(driver, priv->qemuCaps, vm->def, 0)))
        return -1;

    ret = virHookCall(VIR_HOOK_DRIVER_QEMU, vm->def->name, op, subop,
                      NULL, xml, NULL);

    return ret;
}


static int
qemuProcessGraphicsReservePorts(virDomainGraphicsDef *graphics,
                                bool reconnect)
{
    virDomainGraphicsListenDef *glisten;

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
        if (graphics->data.vnc.websocket > 0) {
            if (virPortAllocatorSetUsed(graphics->data.vnc.websocket) < 0)
                return -1;
            graphics->data.vnc.websocketReserved = true;
        }
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
    case VIR_DOMAIN_GRAPHICS_TYPE_DBUS:
    case VIR_DOMAIN_GRAPHICS_TYPE_LAST:
        break;
    }

    return 0;
}


static int
qemuProcessGraphicsAllocatePorts(virQEMUDriver *driver,
                                 virDomainGraphicsDef *graphics,
                                 bool allocate)
{
    virDomainGraphicsListenDef *glisten;

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
    case VIR_DOMAIN_GRAPHICS_TYPE_DBUS:
    case VIR_DOMAIN_GRAPHICS_TYPE_LAST:
        break;
    }

    return 0;
}

static int
qemuProcessGetNetworkAddress(const char *netname,
                             char **netaddr)
{
    g_autoptr(virConnect) conn = NULL;
    g_autoptr(virNetwork) net = NULL;
    g_autoptr(virNetworkDef) netdef = NULL;
    virNetworkIPDef *ipdef;
    virSocketAddr addr;
    virSocketAddr *addrptr = NULL;
    char *dev_name = NULL;
    g_autofree char *xml = NULL;

    *netaddr = NULL;

    if (!(conn = virGetConnectNetwork()))
        return -1;

    net = virNetworkLookupByName(conn, netname);
    if (!net)
        return -1;

    xml = virNetworkGetXMLDesc(net, 0);
    if (!xml)
        return -1;

    netdef = virNetworkDefParse(xml, NULL, NULL, false);
    if (!netdef)
        return -1;

    switch ((virNetworkForwardType) netdef->forward.type) {
    case VIR_NETWORK_FORWARD_NONE:
    case VIR_NETWORK_FORWARD_NAT:
    case VIR_NETWORK_FORWARD_ROUTE:
    case VIR_NETWORK_FORWARD_OPEN:
        ipdef = virNetworkDefGetIPByIndex(netdef, AF_UNSPEC, 0);
        if (!ipdef) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("network '%1$s' doesn't have an IP address"),
                           netdef->name);
            return -1;
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
        G_GNUC_FALLTHROUGH;

    case VIR_NETWORK_FORWARD_PRIVATE:
    case VIR_NETWORK_FORWARD_VEPA:
    case VIR_NETWORK_FORWARD_PASSTHROUGH:
        if ((netdef->forward.nifs > 0) && netdef->forward.ifs)
            dev_name = netdef->forward.ifs[0].device.dev;

        if (!dev_name) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("network '%1$s' has no associated interface or bridge"),
                           netdef->name);
            return -1;
        }
        break;

    case VIR_NETWORK_FORWARD_HOSTDEV:
        break;

    case VIR_NETWORK_FORWARD_LAST:
    default:
        virReportEnumRangeError(virNetworkForwardType, netdef->forward.type);
        return -1;
    }

    if (dev_name) {
        if (virNetDevIPAddrGet(dev_name, &addr) < 0)
            return -1;
        addrptr = &addr;
    }

    if (!(addrptr &&
          (*netaddr = virSocketAddrFormat(addrptr)))) {
        return -1;
    }

    return 0;
}


static int
qemuProcessGraphicsSetupNetworkAddress(virDomainGraphicsListenDef *glisten,
                                       const char *listenAddr)
{
    int rc;

    /* TODO: reject configuration without network specified for network listen */
    if (!glisten->network) {
        glisten->address = g_strdup(listenAddr);
        return 0;
    }

    rc = qemuProcessGetNetworkAddress(glisten->network, &glisten->address);
    if (rc <= -2) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("network-based listen isn't possible, network driver isn't present"));
        return -1;
    }
    if (rc < 0)
        return -1;

    return 0;
}


static int
qemuProcessGraphicsSetupDBus(virQEMUDriver *driver,
                             virDomainGraphicsDef *graphics,
                             virDomainObj *vm)
{
    if (graphics->type != VIR_DOMAIN_GRAPHICS_TYPE_DBUS)
        return 0;

    if (!graphics->data.dbus.p2p && !graphics->data.dbus.address) {
        graphics->data.dbus.address = qemuDBusGetAddress(driver, vm);
    }

    return 0;
}


static int
qemuProcessGraphicsSetupListen(virQEMUDriver *driver,
                               virDomainGraphicsDef *graphics,
                               virDomainObj *vm)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    const char *type = virDomainGraphicsTypeToString(graphics->type);
    char *listenAddr = NULL;
    bool useSocket = false;
    size_t i;

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
    case VIR_DOMAIN_GRAPHICS_TYPE_DBUS:
    case VIR_DOMAIN_GRAPHICS_TYPE_LAST:
        break;
    }

    for (i = 0; i < graphics->nListens; i++) {
        virDomainGraphicsListenDef *glisten = &graphics->listens[i];

        switch (glisten->type) {
        case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_ADDRESS:
            if (!glisten->address) {
                /* If there is no address specified and qemu.conf has
                 * *_auto_unix_socket set we should use unix socket as
                 * default instead of tcp listen. */
                if (useSocket) {
                    memset(glisten, 0, sizeof(*glisten));
                    glisten->socket = g_strdup_printf("%s/%s.sock", priv->libDir,
                                                      type);
                    glisten->fromConfig = true;
                    glisten->type = VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_SOCKET;
                } else if (listenAddr) {
                    glisten->address = g_strdup(listenAddr);
                    glisten->fromConfig = true;
                }
            }
            break;

        case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_NETWORK:
            if (glisten->address || !listenAddr)
                continue;

            if (qemuProcessGraphicsSetupNetworkAddress(glisten,
                                                       listenAddr) < 0)
                return -1;
            break;

        case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_SOCKET:
            if (!glisten->socket) {
                glisten->socket = g_strdup_printf("%s/%s.sock", priv->libDir,
                                                  type);
                glisten->autoGenerated = true;
            }
            break;

        case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_NONE:
        case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_LAST:
            break;
        }
    }

    return 0;
}


static int
qemuProcessGraphicsSetupRenderNode(virDomainGraphicsDef *graphics,
                                   virQEMUCaps *qemuCaps)
{
    char **rendernode = NULL;

    if (!virDomainGraphicsNeedsAutoRenderNode(graphics))
        return 0;

    /* Don't bother picking a DRM node if QEMU doesn't support it. */
    switch (graphics->type) {
    case VIR_DOMAIN_GRAPHICS_TYPE_SPICE:
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_SPICE_RENDERNODE))
            return 0;

        rendernode = &graphics->data.spice.rendernode;
        break;
    case VIR_DOMAIN_GRAPHICS_TYPE_EGL_HEADLESS:
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_EGL_HEADLESS_RENDERNODE))
            return 0;

        rendernode = &graphics->data.egl_headless.rendernode;
        break;
    case VIR_DOMAIN_GRAPHICS_TYPE_DBUS:
        rendernode = &graphics->data.dbus.rendernode;
        break;
    case VIR_DOMAIN_GRAPHICS_TYPE_SDL:
    case VIR_DOMAIN_GRAPHICS_TYPE_VNC:
    case VIR_DOMAIN_GRAPHICS_TYPE_RDP:
    case VIR_DOMAIN_GRAPHICS_TYPE_DESKTOP:
    case VIR_DOMAIN_GRAPHICS_TYPE_LAST:
        virReportEnumRangeError(virDomainGraphicsType, graphics->type);
        break;
    }

    if (!(*rendernode = virHostGetDRMRenderNode()))
        return -1;

    return 0;
}


static int
qemuProcessSetupGraphics(virQEMUDriver *driver,
                         virDomainObj *vm,
                         virQEMUCaps *qemuCaps,
                         unsigned int flags)
{
    virDomainGraphicsDef *graphics;
    bool allocate = !(flags & VIR_QEMU_PROCESS_START_PRETEND);
    size_t i;

    for (i = 0; i < vm->def->ngraphics; i++) {
        graphics = vm->def->graphics[i];

        if (qemuProcessGraphicsSetupRenderNode(graphics, qemuCaps) < 0)
            return -1;

        if (qemuProcessGraphicsSetupListen(driver, graphics, vm) < 0)
            return -1;

        if (qemuProcessGraphicsSetupDBus(driver, graphics, vm) < 0)
            return -1;
    }

    if (allocate) {
        for (i = 0; i < vm->def->ngraphics; i++) {
            graphics = vm->def->graphics[i];

            if (qemuProcessGraphicsReservePorts(graphics, false) < 0)
                return -1;
        }
    }

    for (i = 0; i < vm->def->ngraphics; ++i) {
        graphics = vm->def->graphics[i];

        if (qemuProcessGraphicsAllocatePorts(driver, graphics, allocate) < 0)
            return -1;
    }

    return 0;
}


static int
qemuProcessSetupRawIO(virDomainObj *vm,
                      virCommand *cmd G_GNUC_UNUSED)
{
    bool rawio = false;
    size_t i;
    int ret = -1;

    /* in case a certain disk is desirous of CAP_SYS_RAWIO, add this */
    for (i = 0; i < vm->def->ndisks; i++) {
        virDomainDiskDef *disk = vm->def->disks[i];

        if (disk->rawio == VIR_TRISTATE_BOOL_YES) {
            rawio = true;
#ifndef CAP_SYS_RAWIO
            break;
#endif
        }
    }

    /* If rawio not already set, check hostdevs as well */
    if (!rawio) {
        for (i = 0; i < vm->def->nhostdevs; i++) {
            virDomainHostdevSubsysSCSI *scsisrc;

            if (!virHostdevIsSCSIDevice(vm->def->hostdevs[i]))
                continue;

            scsisrc = &vm->def->hostdevs[i]->source.subsys.u.scsi;
            if (scsisrc->rawio == VIR_TRISTATE_BOOL_YES) {
                rawio = true;
                break;
            }
        }
    }

    ret = 0;

    if (rawio) {
#ifdef CAP_SYS_RAWIO
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
qemuProcessSetupBalloon(virDomainObj *vm,
                        virDomainAsyncJob asyncJob)
{
    unsigned long long balloon = vm->def->mem.cur_balloon;
    qemuDomainObjPrivate *priv = vm->privateData;
    int ret = -1;

    if (!virDomainDefHasMemballoon(vm->def))
        return 0;

    if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) < 0)
        return -1;

    if (vm->def->memballoon->period)
        qemuMonitorSetMemoryStatsPeriod(priv->mon, vm->def->memballoon,
                                        vm->def->memballoon->period);
    if (qemuMonitorSetBalloon(priv->mon, balloon) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    qemuDomainObjExitMonitor(vm);
    return ret;
}


static int
qemuProcessMakeDir(virQEMUDriver *driver,
                   virDomainObj *vm,
                   const char *path)
{
    if (g_mkdir_with_parents(path, 0750) < 0) {
        virReportSystemError(errno, _("Cannot create directory '%1$s'"), path);
        return -1;
    }

    if (qemuSecurityDomainSetPathLabel(driver, vm, path, true) < 0)
        return -1;

    return 0;
}


static void
qemuProcessStartWarnShmem(virDomainObj *vm)
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
qemuProcessStartValidateGraphics(virDomainObj *vm)
{
    size_t i;

    for (i = 0; i < vm->def->ngraphics; i++) {
        virDomainGraphicsDef *graphics = vm->def->graphics[i];

        switch (graphics->type) {
        case VIR_DOMAIN_GRAPHICS_TYPE_VNC:
        case VIR_DOMAIN_GRAPHICS_TYPE_SPICE:
            if (graphics->nListens > 1) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("QEMU does not support multiple listens for one graphics device."));
                return -1;
            }
            break;

        case VIR_DOMAIN_GRAPHICS_TYPE_SDL:
        case VIR_DOMAIN_GRAPHICS_TYPE_RDP:
        case VIR_DOMAIN_GRAPHICS_TYPE_DESKTOP:
        case VIR_DOMAIN_GRAPHICS_TYPE_EGL_HEADLESS:
        case VIR_DOMAIN_GRAPHICS_TYPE_DBUS:
        case VIR_DOMAIN_GRAPHICS_TYPE_LAST:
            break;
        }
    }

    return 0;
}


static int
qemuProcessStartValidateShmem(virDomainObj *vm)
{
    size_t i;

    for (i = 0; i < vm->def->nshmems; i++) {
        virDomainShmemDef *shmem = vm->def->shmems[i];

        if (strchr(shmem->name, '/')) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("shmem name '%1$s' must not contain '/'"),
                           shmem->name);
            return -1;
        }
    }

    return 0;
}


static int
qemuProcessStartValidateDisks(virDomainObj *vm,
                              virQEMUCaps *qemuCaps)
{
    size_t i;

    for (i = 0; i < vm->def->ndisks; i++) {
        virDomainDiskDef *disk = vm->def->disks[i];
        virStorageSource *src = disk->src;

        /* This is a best effort check as we can only check if the command
         * option exists, but we cannot determine whether the running QEMU
         * was build with '--enable-vxhs'. */
        if (src->type == VIR_STORAGE_TYPE_NETWORK &&
            src->protocol == VIR_STORAGE_NET_PROTOCOL_VXHS &&
            !virQEMUCapsGet(qemuCaps, QEMU_CAPS_VXHS)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("VxHS protocol is not supported with this QEMU binary"));
            return -1;
        }

        /* PowerPC pseries based VMs do not support floppy device */
        if (disk->device == VIR_DOMAIN_DISK_DEVICE_FLOPPY &&
            qemuDomainIsPSeries(vm->def)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("PowerPC pseries machines do not support floppy device"));
            return -1;
        }

        if (src->type == VIR_STORAGE_TYPE_NVME &&
            !virQEMUCapsGet(qemuCaps, QEMU_CAPS_DRIVE_NVME)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("NVMe disks are not supported with this QEMU binary"));
            return -1;
        }
    }

    return 0;
}


/* 250 parts per million (ppm) is a half of NTP threshold */
#define TSC_TOLERANCE 250

static int
qemuProcessStartValidateTSC(virQEMUDriver *driver,
                            virDomainObj *vm)
{
    size_t i;
    unsigned long long freq = 0;
    unsigned long long tolerance;
    unsigned long long minFreq;
    unsigned long long maxFreq;
    virHostCPUTscInfo *tsc;
    g_autoptr(virCPUDef) cpu = NULL;

    for (i = 0; i < vm->def->clock.ntimers; i++) {
        virDomainTimerDef *timer = vm->def->clock.timers[i];

        if (timer->name == VIR_DOMAIN_TIMER_NAME_TSC &&
            timer->frequency > 0) {
            freq = timer->frequency;
            break;
        }
    }

    if (freq == 0)
        return 0;

    VIR_DEBUG("Requested TSC frequency %llu Hz", freq);

    cpu = virQEMUDriverGetHostCPU(driver);
    if (!cpu || !cpu->tsc) {
        VIR_DEBUG("Host TSC frequency could not be probed");
        return 0;
    }

    tsc = cpu->tsc;
    tolerance = tsc->frequency * TSC_TOLERANCE / 1000000;
    minFreq = tsc->frequency - tolerance;
    maxFreq = tsc->frequency + tolerance;

    VIR_DEBUG("Host TSC frequency %llu Hz, scaling %s, tolerance +/- %llu Hz",
              tsc->frequency, virTristateBoolTypeToString(tsc->scaling),
              tolerance);

    if (freq >= minFreq && freq <= maxFreq) {
        VIR_DEBUG("Requested TSC frequency is within tolerance interval");
        return 0;
    }

    if (tsc->scaling == VIR_TRISTATE_BOOL_YES)
        return 0;

    if (tsc->scaling == VIR_TRISTATE_BOOL_ABSENT) {
        VIR_DEBUG("Requested TSC frequency falls outside tolerance range and "
                  "scaling support is unknown, QEMU will try and possibly "
                  "fail later");
        return 0;
    }

    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                   _("Requested TSC frequency %1$llu Hz is outside tolerance range ([%2$llu, %3$llu] Hz) around host frequency %4$llu Hz and TSC scaling is not supported by the host CPU"),
                   freq, minFreq, maxFreq, tsc->frequency);
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
qemuProcessStartValidate(virQEMUDriver *driver,
                         virDomainObj *vm,
                         virQEMUCaps *qemuCaps,
                         unsigned int flags)
{
    if (!(flags & VIR_QEMU_PROCESS_START_PRETEND)) {
        if (vm->def->virtType == VIR_DOMAIN_VIRT_KVM) {
            VIR_DEBUG("Checking for KVM availability");
            if (!virFileExists("/dev/kvm")) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("Domain requires KVM, but it is not available. Check that virtualization is enabled in the host BIOS, and host configuration is setup to load the kvm modules."));
                return -1;
            }
        }

        VIR_DEBUG("Checking domain and device security labels");
        if (qemuSecurityCheckAllLabel(driver->securityManager, vm->def) < 0)
            return -1;

    }

    if (virDomainDefValidate(vm->def, 0, driver->xmlopt, qemuCaps) < 0)
        return -1;

    if (qemuProcessStartValidateGraphics(vm) < 0)
        return -1;

    if (qemuProcessStartValidateShmem(vm) < 0)
        return -1;

    if (vm->def->cpu) {
        if (virCPUValidateFeatures(vm->def->os.arch, vm->def->cpu) < 0)
            return -1;

        if (ARCH_IS_X86(vm->def->os.arch) &&
            !virQEMUCapsGet(qemuCaps, QEMU_CAPS_CPU_UNAVAILABLE_FEATURES)) {
            g_auto(GStrv) features = NULL;
            int n;

            if ((n = virCPUDefCheckFeatures(vm->def->cpu,
                                            virCPUx86FeatureFilterSelectMSR,
                                            NULL,
                                            &features)) < 0)
                return -1;

            if (n > 0) {
                g_autofree char *str = NULL;

                str = g_strjoinv(", ", features);
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("Some features cannot be reliably used with this QEMU: %1$s"), str);
                return -1;
            }
        }
    }

    if (qemuProcessStartValidateDisks(vm, qemuCaps) < 0)
        return -1;

    if (qemuProcessStartValidateTSC(driver, vm) < 0)
        return -1;

    VIR_DEBUG("Checking for any possible (non-fatal) issues");

    qemuProcessStartWarnShmem(vm);

    return 0;
}


static int
qemuProcessStartUpdateCustomCaps(virDomainObj *vm)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(priv->driver);
    qemuDomainXmlNsDef *nsdef = vm->def->namespaceData;
    char **next;
    int tmp;

    if (cfg->capabilityfilters) {
        for (next = cfg->capabilityfilters; *next; next++) {
            if ((tmp = virQEMUCapsTypeFromString(*next)) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("invalid capability_filters capability '%1$s'"),
                               *next);
                return -1;
            }

            virQEMUCapsClear(priv->qemuCaps, tmp);
        }
    }

    if (nsdef) {
        for (next = nsdef->capsadd; next && *next; next++) {
            if ((tmp = virQEMUCapsTypeFromString(*next)) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("invalid qemu namespace capability '%1$s'"),
                               *next);
                return -1;
            }

            virQEMUCapsSet(priv->qemuCaps, tmp);
        }

        for (next = nsdef->capsdel; next && *next; next++) {
            if ((tmp = virQEMUCapsTypeFromString(*next)) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("invalid qemu namespace capability '%1$s'"),
                               *next);
                return -1;
            }

            virQEMUCapsClear(priv->qemuCaps, tmp);
        }
    }

    return 0;
}


/**
 * qemuProcessPrepareQEMUCaps:
 * @vm: domain object
 * @qemuCapsCache: cache of QEMU capabilities
 *
 * Prepare the capabilities of a QEMU process for startup. This includes
 * copying the caps to a static cache and potential post-processing depending
 * on the configuration of the VM and startup process.
 *
 * Returns 0 on success, -1 on error.
 */
static int
qemuProcessPrepareQEMUCaps(virDomainObj *vm,
                           virFileCache *qemuCapsCache)
{
    qemuDomainObjPrivate *priv = vm->privateData;

    virObjectUnref(priv->qemuCaps);
    if (!(priv->qemuCaps = virQEMUCapsCacheLookupCopy(qemuCapsCache,
                                                      vm->def->emulator)))
        return -1;

    /* Update qemu capabilities according to lists passed in via namespace */
    if (qemuProcessStartUpdateCustomCaps(vm) < 0)
        return -1;

    /* re-process capability lockouts since we might have removed capabilities */
    virQEMUCapsInitProcessCapsInterlock(priv->qemuCaps);

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
qemuProcessInit(virQEMUDriver *driver,
                virDomainObj *vm,
                virCPUDef *updatedCPU,
                virDomainAsyncJob asyncJob,
                bool migration,
                unsigned int flags)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    int stopFlags;
    virCPUDef *origCPU = NULL;
    int ret = -1;

    VIR_DEBUG("vm=%p name=%s id=%d migration=%d",
              vm, vm->def->name, vm->def->id, migration);

    VIR_DEBUG("Beginning VM startup process");

    if (virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("VM is already active"));
        goto cleanup;
    }

    /* in case when the post parse callback failed we need to re-run it on the
     * old config prior we start the VM */
    if (vm->def->postParseFailed) {
        VIR_DEBUG("re-running the post parse callback");

        /* we don't have the private copy of qemuCaps at this point */
        if (virDomainDefPostParse(vm->def, 0, driver->xmlopt, NULL) < 0)
            goto cleanup;
    }

    VIR_DEBUG("Determining emulator version");
    if (qemuProcessPrepareQEMUCaps(vm, driver->qemuCapsCache) < 0)
        goto cleanup;

    if (qemuDomainUpdateCPU(vm, updatedCPU, &origCPU) < 0)
        goto cleanup;

    if (qemuProcessStartValidate(driver, vm, priv->qemuCaps, flags) < 0)
        goto cleanup;

    /* Do this upfront, so any part of the startup process can add
     * runtime state to vm->def that won't be persisted. This let's us
     * report implicit runtime defaults in the XML, like vnc listen/socket
     */
    VIR_DEBUG("Setting current domain def as transient");
    if (virDomainObjSetDefTransient(driver->xmlopt, vm, priv->qemuCaps) < 0)
        goto cleanup;

    if (flags & VIR_QEMU_PROCESS_START_PRETEND) {
        if (qemuDomainSetPrivatePaths(driver, vm) < 0) {
            virDomainObjRemoveTransientDef(vm);
            goto cleanup;
        }
    } else {
        vm->def->id = qemuDriverAllocateID(driver);
        qemuDomainSetFakeReboot(vm, false);
        virDomainObjSetState(vm, VIR_DOMAIN_PAUSED, VIR_DOMAIN_PAUSED_STARTING_UP);

        if (g_atomic_int_add(&driver->nactive, 1) == 0 && driver->inhibitCallback)
            driver->inhibitCallback(true, driver->inhibitOpaque);

        /* Run an early hook to set-up missing devices */
        if (qemuProcessStartHook(driver, vm,
                                 VIR_HOOK_QEMU_OP_PREPARE,
                                 VIR_HOOK_SUBOP_BEGIN) < 0)
            goto stop;

        if (qemuDomainSetPrivatePaths(driver, vm) < 0)
            goto stop;

        priv->origCPU = g_steal_pointer(&origCPU);
    }

    ret = 0;

 cleanup:
    virCPUDefFree(origCPU);
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
qemuProcessNetworkPrepareDevices(virQEMUDriver *driver,
                                 virDomainObj *vm)
{
    virDomainDef *def = vm->def;
    qemuDomainObjPrivate *priv = vm->privateData;
    size_t i;
    g_autoptr(virConnect) conn = NULL;

    for (i = 0; i < def->nnets; i++) {
        virDomainNetDef *net = def->nets[i];
        virDomainNetType actualType;

        /* If appropriate, grab a physical device from the configured
         * network's pool of devices, or resolve bridge device name
         * to the one defined in the network definition.
         */
        if (net->type == VIR_DOMAIN_NET_TYPE_NETWORK) {
            if (!conn && !(conn = virGetConnectNetwork()))
                return -1;
            if (virDomainNetAllocateActualDevice(conn, def, net) < 0)
                return -1;
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
            virDomainHostdevDef *hostdev = virDomainNetGetActualHostdev(net);
            virDomainHostdevSubsysPCI *pcisrc = &hostdev->source.subsys.u.pci;

            if (virDomainHostdevFind(def, hostdev, NULL) >= 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("PCI device %1$04x:%2$02x:%3$02x.%4$x allocated from network %5$s is already in use by domain %6$s"),
                               pcisrc->addr.domain, pcisrc->addr.bus,
                               pcisrc->addr.slot, pcisrc->addr.function,
                               net->data.network.name, def->name);
                return -1;
            }

            /* For hostdev present in qemuProcessPrepareDomain() phase this was
             * done already, but this code runs after that, so we have to call
             * it ourselves. */
            if (qemuDomainPrepareHostdev(hostdev, priv) < 0)
                return -1;

            if (virDomainHostdevInsert(def, hostdev) < 0)
                return -1;
        } else if (actualType == VIR_DOMAIN_NET_TYPE_USER &&
                   net->backend.type == VIR_DOMAIN_NET_BACKEND_DEFAULT &&
                   !priv->disableSlirp &&
                   virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DBUS_VMSTATE)) {
            if (qemuInterfacePrepareSlirp(driver, net) < 0)
                return -1;
         }

    }
    return 0;
}


struct qemuProcessSetupVcpuSchedCoreHelperData {
    pid_t vcpupid;
    pid_t dummypid;
};

static int
qemuProcessSetupVcpuSchedCoreHelper(pid_t ppid G_GNUC_UNUSED,
                                    void *opaque)
{
    struct qemuProcessSetupVcpuSchedCoreHelperData *data = opaque;

    if (virProcessSchedCoreShareFrom(data->dummypid) < 0) {
        virReportSystemError(errno,
                             _("unable to share scheduling cookie from %1$lld"),
                             (long long) data->dummypid);
        return -1;
    }

    if (virProcessSchedCoreShareTo(data->vcpupid) < 0) {
        virReportSystemError(errno,
                             _("unable to share scheduling cookie to %1$lld"),
                             (long long) data->vcpupid);
        return -1;
    }

    return 0;
}


/**
 * qemuProcessSetupVcpu:
 * @vm: domain object
 * @vcpuid: id of VCPU to set defaults
 * @schedCore: whether to set scheduling group
 *
 * This function sets resource properties (cgroups, affinity, scheduler) for a
 * vCPU. This function expects that the vCPU is online and the vCPU pids were
 * correctly detected at the point when it's called.
 *
 * Returns 0 on success, -1 on error.
 */
int
qemuProcessSetupVcpu(virDomainObj *vm,
                     unsigned int vcpuid,
                     bool schedCore)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(priv->driver);
    pid_t vcpupid = qemuDomainGetVcpuPid(vm, vcpuid);
    virDomainVcpuDef *vcpu = virDomainDefGetVcpu(vm->def, vcpuid);
    virDomainResctrlMonDef *mon = NULL;
    size_t i = 0;

    if (qemuProcessSetupPid(vm, vcpupid, VIR_CGROUP_THREAD_VCPU,
                            vcpuid, vcpu->cpumask,
                            vm->def->cputune.period,
                            vm->def->cputune.quota,
                            &vcpu->sched) < 0)
        return -1;

    if (schedCore &&
        cfg->schedCore == QEMU_SCHED_CORE_VCPUS) {
        struct qemuProcessSetupVcpuSchedCoreHelperData data = { .vcpupid = vcpupid,
            .dummypid = -1 };

        for (i = 0; i < virDomainDefGetVcpusMax(vm->def); i++) {
            pid_t temptid = qemuDomainGetVcpuPid(vm, i);

            if (temptid > 0) {
                data.dummypid = temptid;
                break;
            }
        }

        if (data.dummypid == -1) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Unable to find a vCPU that is online"));
            return -1;
        }

        if (virProcessRunInFork(qemuProcessSetupVcpuSchedCoreHelper, &data) < 0)
            return -1;
    }

    for (i = 0; i < vm->def->nresctrls; i++) {
        size_t j = 0;
        virDomainResctrlDef *ct = vm->def->resctrls[i];

        if (virBitmapIsBitSet(ct->vcpus, vcpuid)) {
            if (virResctrlAllocAddPID(ct->alloc, vcpupid) < 0)
                return -1;

            for (j = 0; j < ct->nmonitors; j++) {
                mon = ct->monitors[j];

                if (virBitmapEqual(ct->vcpus, mon->vcpus) &&
                    !virResctrlAllocIsEmpty(ct->alloc))
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
qemuProcessSetupAllVcpusSchedCoreHelper(pid_t ppid G_GNUC_UNUSED,
                                        void *opaque)
{
    virDomainObj *vm = opaque;
    size_t i;

    /* Since we are setting all vCPU threads at once and from a forked off
     * child, we don't need the dummy schedCoreChildPID and can create one on
     * our own. */
    if (virProcessSchedCoreCreate() < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to set SCHED_CORE"));

        return -1;
    }

    for (i = 0; i < virDomainDefGetVcpusMax(vm->def); i++) {
        pid_t vcpupid = qemuDomainGetVcpuPid(vm, i);

        if (vcpupid > 0 &&
            virProcessSchedCoreShareTo(vcpupid) < 0) {
            virReportSystemError(errno,
                                 _("unable to share scheduling cookie to %1$lld"),
                                 (long long) vcpupid);
            return -1;
        }
    }

    return 0;
}


static int
qemuProcessSetupVcpus(virDomainObj *vm)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(priv->driver);
    virDomainVcpuDef *vcpu;
    unsigned int maxvcpus = virDomainDefGetVcpusMax(vm->def);
    size_t i;

    if ((vm->def->cputune.period || vm->def->cputune.quota) &&
        !virCgroupHasController(((qemuDomainObjPrivate *) vm->privateData)->cgroup,
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

        if (qemuProcessSetupVcpu(vm, i, false) < 0)
            return -1;
    }

    if (cfg->schedCore == QEMU_SCHED_CORE_VCPUS &&
        virProcessRunInFork(qemuProcessSetupAllVcpusSchedCoreHelper, vm) < 0)
        return -1;

    return 0;
}


int
qemuProcessSetupIOThread(virDomainObj *vm,
                         virDomainIOThreadIDDef *iothread)
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
qemuProcessSetupIOThreads(virDomainObj *vm)
{
    size_t i;

    for (i = 0; i < vm->def->niothreadids; i++) {
        virDomainIOThreadIDDef *info = vm->def->iothreadids[i];

        if (qemuProcessSetupIOThread(vm, info) < 0)
            return -1;
    }

    return 0;
}


static int
qemuProcessValidateHotpluggableVcpus(virDomainDef *def)
{
    virDomainVcpuDef *vcpu;
    virDomainVcpuDef *subvcpu;
    qemuDomainVcpuPrivate *vcpupriv;
    unsigned int maxvcpus = virDomainDefGetVcpusMax(def);
    size_t i = 0;
    size_t j;
    g_autoptr(virBitmap) ordermap = virBitmapNew(maxvcpus + 1);

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
                               _("duplicate vcpu order '%1$u'"), vcpu->order);
                return -1;
            }

            if (virBitmapSetBit(ordermap, vcpu->order)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("vcpu order '%1$u' exceeds vcpu count"),
                               vcpu->order);
                return -1;
            }
        }

        for (j = i + 1; j < (i + vcpupriv->vcpus); j++) {
            subvcpu = virDomainDefGetVcpu(def, j);
            if (subvcpu->hotpluggable != vcpu->hotpluggable ||
                subvcpu->online != vcpu->online ||
                subvcpu->order != vcpu->order) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("vcpus '%1$zu' and '%2$zu' are in the same hotplug group but differ in configuration"),
                               i, j);
                return -1;
            }
        }

        if (vcpu->online && vcpu->hotpluggable == VIR_TRISTATE_BOOL_YES) {
            if ((vcpupriv->socket_id == -1 && vcpupriv->core_id == -1 &&
                 vcpupriv->thread_id == -1 && vcpupriv->node_id == -1) ||
                !vcpupriv->type) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("vcpu '%1$zu' is missing hotplug data"), i);
                return -1;
            }
        }
    }

    return 0;
}


static int
qemuDomainHasHotpluggableStartupVcpus(virDomainDef *def)
{
    size_t maxvcpus = virDomainDefGetVcpusMax(def);
    virDomainVcpuDef *vcpu;
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
    virDomainVcpuDef *vcpua = *((virDomainVcpuDef **)a);
    virDomainVcpuDef *vcpub = *((virDomainVcpuDef **)b);

    return vcpua->order - vcpub->order;
}


static int
qemuProcessSetupHotpluggableVcpus(virDomainObj *vm,
                                  virDomainAsyncJob asyncJob)
{
    unsigned int maxvcpus = virDomainDefGetVcpusMax(vm->def);
    qemuDomainObjPrivate *priv = vm->privateData;
    virCgroupEmulatorAllNodesData *emulatorCgroup = NULL;
    virDomainVcpuDef *vcpu;
    qemuDomainVcpuPrivate *vcpupriv;
    size_t i;
    int ret = -1;
    int rc;

    g_autofree virDomainVcpuDef **bootHotplug = NULL;
    size_t nbootHotplug = 0;

    for (i = 0; i < maxvcpus; i++) {
        vcpu = virDomainDefGetVcpu(vm->def, i);
        vcpupriv = QEMU_DOMAIN_VCPU_PRIVATE(vcpu);

        if (vcpu->hotpluggable == VIR_TRISTATE_BOOL_YES && vcpu->online &&
            vcpupriv->vcpus != 0) {
            vcpupriv->alias = g_strdup_printf("vcpu%zu", i);

            VIR_APPEND_ELEMENT(bootHotplug, nbootHotplug, vcpu);
        }
    }

    if (nbootHotplug == 0)
        return 0;

    qsort(bootHotplug, nbootHotplug, sizeof(*bootHotplug),
          qemuProcessVcpusSortOrder);

    if (virDomainCgroupEmulatorAllNodesAllow(priv->cgroup, &emulatorCgroup) < 0)
        goto cleanup;

    for (i = 0; i < nbootHotplug; i++) {
        g_autoptr(virJSONValue) vcpuprops = NULL;
        vcpu = bootHotplug[i];

        if (!(vcpuprops = qemuBuildHotpluggableCPUProps(vcpu)))
            goto cleanup;

        if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) < 0)
            goto cleanup;

        rc = qemuMonitorAddDeviceProps(qemuDomainGetMonitor(vm), &vcpuprops);

        qemuDomainObjExitMonitor(vm);

        if (rc < 0)
            goto cleanup;
    }

    ret = 0;

 cleanup:
    virDomainCgroupEmulatorAllNodesRestore(emulatorCgroup);
    return ret;
}


static bool
qemuProcessDropUnknownCPUFeatures(const char *name,
                                  virCPUFeaturePolicy policy,
                                  void *opaque)
{
    const char **features = opaque;

    if (policy != VIR_CPU_FEATURE_DISABLE &&
        policy != VIR_CPU_FEATURE_FORBID)
        return true;

    if (g_strv_contains(features, name))
        return true;

    /* Features unknown to QEMU are implicitly disabled, we can just drop them
     * from the definition. */
    return false;
}


static int
qemuProcessUpdateGuestCPU(virDomainDef *def,
                          virQEMUCaps *qemuCaps,
                          virArch hostarch,
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

    if (!virQEMUCapsIsCPUModeSupported(qemuCaps, hostarch, def->virtType,
                                       def->cpu->mode, def->os.machine)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("CPU mode '%1$s' for %2$s %3$s domain on %4$s host is not supported by hypervisor"),
                       virCPUModeTypeToString(def->cpu->mode),
                       virArchToString(def->os.arch),
                       virDomainVirtTypeToString(def->virtType),
                       virArchToString(hostarch));
        return -1;
    }

    if (virCPUConvertLegacy(hostarch, def->cpu) < 0)
        return -1;

    if (def->cpu->check != VIR_CPU_CHECK_NONE) {
        virCPUDef *host;

        host = virQEMUCapsGetHostModel(qemuCaps, def->virtType,
                                       VIR_QEMU_CAPS_HOST_CPU_FULL);

        if (host && virCPUCheckForbiddenFeatures(def->cpu, host) < 0)
            return -1;
    }

    /* nothing to update for host-passthrough / maximum */
    if (def->cpu->mode != VIR_CPU_MODE_HOST_PASSTHROUGH &&
        def->cpu->mode != VIR_CPU_MODE_MAXIMUM) {
        g_autoptr(virDomainCapsCPUModels) cpuModels = NULL;

        if (def->cpu->check == VIR_CPU_CHECK_PARTIAL &&
            virCPUCompare(hostarch,
                          virQEMUCapsGetHostModel(qemuCaps, def->virtType,
                                                  VIR_QEMU_CAPS_HOST_CPU_FULL),
                          def->cpu, true) < 0)
            return -1;

        if (virCPUUpdate(def->os.arch, def->cpu,
                         virQEMUCapsGetHostModel(qemuCaps, def->virtType,
                                                 VIR_QEMU_CAPS_HOST_CPU_MIGRATABLE)) < 0)
            return -1;

        cpuModels = virQEMUCapsGetCPUModels(qemuCaps, def->virtType, NULL, NULL);

        if (virCPUTranslate(def->os.arch, def->cpu, cpuModels) < 0)
            return -1;

        def->cpu->fallback = VIR_CPU_FALLBACK_FORBID;
    }

    if (virCPUDefFilterFeatures(def->cpu, virQEMUCapsCPUFilterFeatures,
                                &def->os.arch) < 0)
        return -1;

    if (ARCH_IS_X86(def->os.arch)) {
        g_auto(GStrv) features = NULL;

        if (virQEMUCapsGetCPUFeatures(qemuCaps, def->virtType, false, &features) < 0)
            return -1;

        if (features &&
            virCPUDefFilterFeatures(def->cpu, qemuProcessDropUnknownCPUFeatures,
                                    features) < 0)
            return -1;
    }

    return 0;
}


static int
qemuProcessPrepareDomainNUMAPlacement(virDomainObj *vm)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autofree char *nodeset = NULL;
    g_autoptr(virBitmap) numadNodeset = NULL;
    g_autoptr(virBitmap) hostMemoryNodeset = NULL;
    g_autoptr(virCapsHostNUMA) caps = NULL;

    /* Get the advisory nodeset from numad if 'placement' of
     * either <vcpu> or <numatune> is 'auto'.
     */
    if (!virDomainDefNeedsPlacementAdvice(vm->def))
        return 0;

    nodeset = virNumaGetAutoPlacementAdvice(virDomainDefGetVcpus(vm->def),
                                            virDomainDefGetMemoryTotal(vm->def));

    if (!nodeset)
        return -1;

    if (!(hostMemoryNodeset = virNumaGetHostMemoryNodeset()))
        return -1;

    VIR_DEBUG("Nodeset returned from numad: %s", nodeset);

    if (virBitmapParse(nodeset, &numadNodeset, VIR_DOMAIN_CPUMASK_LEN) < 0)
        return -1;

    if (!(caps = virCapabilitiesHostNUMANewHost()))
        return -1;

    /* numad may return a nodeset that only contains cpus but cgroups don't play
     * well with that. Set the autoCpuset from all cpus from that nodeset, but
     * assign autoNodeset only with nodes containing memory. */
    if (!(priv->autoCpuset = virCapabilitiesHostNUMAGetCpus(caps, numadNodeset)))
        return -1;

    virBitmapIntersect(numadNodeset, hostMemoryNodeset);

    priv->autoNodeset = g_steal_pointer(&numadNodeset);

    return 0;
}


static void
qemuProcessPrepareDeviceBootorder(virDomainDef *def)
{
    size_t i;
    unsigned int bootCD = 0;
    unsigned int bootFloppy = 0;
    unsigned int bootDisk = 0;
    unsigned int bootNetwork = 0;

    if (def->os.nBootDevs == 0)
        return;

    for (i = 0; i < def->os.nBootDevs; i++) {
        switch (def->os.bootDevs[i]) {
        case VIR_DOMAIN_BOOT_CDROM:
            bootCD = i + 1;
            break;

        case VIR_DOMAIN_BOOT_FLOPPY:
            bootFloppy = i + 1;
            break;

        case VIR_DOMAIN_BOOT_DISK:
            bootDisk = i + 1;
            break;

        case VIR_DOMAIN_BOOT_NET:
            bootNetwork = i + 1;
            break;

        case VIR_DOMAIN_BOOT_LAST:
        default:
            break;
        }
    }

    for (i = 0; i < def->ndisks; i++) {
        virDomainDiskDef *disk = def->disks[i];

        switch (disk->device) {
        case VIR_DOMAIN_DISK_DEVICE_CDROM:
            disk->info.effectiveBootIndex = bootCD;
            bootCD = 0;
            break;

        case VIR_DOMAIN_DISK_DEVICE_DISK:
        case VIR_DOMAIN_DISK_DEVICE_LUN:
            disk->info.effectiveBootIndex = bootDisk;
            bootDisk = 0;
            break;

        case VIR_DOMAIN_DISK_DEVICE_FLOPPY:
            disk->info.effectiveBootIndex = bootFloppy;
            bootFloppy = 0;
            break;

        case VIR_DOMAIN_DISK_DEVICE_LAST:
        default:
            break;
        }
    }

    if (def->nnets > 0 && bootNetwork > 0) {
        /* If network boot is enabled, the first network device gets enabled. If
         * that one is backed by a host device, then we need to find the first
         * corresponding host device */
        if (virDomainNetGetActualType(def->nets[0]) == VIR_DOMAIN_NET_TYPE_HOSTDEV) {
            for (i = 0; i < def->nhostdevs; i++) {
                virDomainHostdevDef *hostdev = def->hostdevs[i];
                virDomainHostdevSubsys *subsys = &hostdev->source.subsys;

                if (hostdev->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS &&
                    subsys->type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI &&
                    hostdev->info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_UNASSIGNED &&
                    hostdev->parentnet) {
                    hostdev->info->effectiveBootIndex = bootNetwork;
                    break;
                }
            }
        } else {
            def->nets[0]->info.effectiveBootIndex = bootNetwork;
        }
    }
}


static int
qemuProcessPrepareDomainStorage(virQEMUDriver *driver,
                                virDomainObj *vm,
                                qemuDomainObjPrivate *priv,
                                virQEMUDriverConfig *cfg,
                                unsigned int flags)
{
    size_t i;
    bool cold_boot = flags & VIR_QEMU_PROCESS_START_COLD;

    for (i = vm->def->ndisks; i > 0; i--) {
        size_t idx = i - 1;
        virDomainDiskDef *disk = vm->def->disks[idx];

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


static int
qemuProcessPrepareDomainHostdevs(virDomainObj *vm,
                                 qemuDomainObjPrivate *priv)
{
    size_t i;

    for (i = 0; i < vm->def->nhostdevs; i++) {
        virDomainHostdevDef *hostdev = vm->def->hostdevs[i];

        if (qemuDomainPrepareHostdev(hostdev, priv) < 0)
            return -1;
    }

    return 0;
}


/**
 * qemuProcessRebootAllowed:
 * @def: domain definition
 *
 * This function encapsulates the logic which dictated whether '-no-reboot' was
 * used instead of '-no-shutdown' which is used  QEMU versions which don't
 * support the 'set-action' QMP command.
 */
bool
qemuProcessRebootAllowed(const virDomainDef *def)
{
    return def->onReboot != VIR_DOMAIN_LIFECYCLE_ACTION_DESTROY ||
           def->onPoweroff != VIR_DOMAIN_LIFECYCLE_ACTION_DESTROY ||
           (def->onCrash != VIR_DOMAIN_LIFECYCLE_ACTION_DESTROY &&
            def->onCrash != VIR_DOMAIN_LIFECYCLE_ACTION_COREDUMP_DESTROY);
}


static void
qemuProcessPrepareAllowReboot(virDomainObj *vm)
{
    virDomainDef *def = vm->def;
    qemuDomainObjPrivate *priv = vm->privateData;

    /* with 'set-action' QMP command we don't need to keep this around as
     * we always update qemu with the proper state */
    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_SET_ACTION))
        return;

    if (priv->allowReboot != VIR_TRISTATE_BOOL_ABSENT)
        return;

    priv->allowReboot = virTristateBoolFromBool(qemuProcessRebootAllowed(def));
}


static int
qemuProcessUpdateSEVInfo(virDomainObj *vm)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    virQEMUCaps *qemuCaps = priv->qemuCaps;
    virDomainSEVDef *sev = &vm->def->sec->data.sev;
    virSEVCapability *sevCaps = NULL;

    /* if platform specific info like 'cbitpos' and 'reducedPhysBits' have
     * not been supplied, we need to autofill them from caps now as both are
     * mandatory on QEMU cmdline
     */
    sevCaps = virQEMUCapsGetSEVCapabilities(qemuCaps);
    if (!sev->haveCbitpos) {
        sev->cbitpos = sevCaps->cbitpos;
        sev->haveCbitpos = true;
    }

    if (!sev->haveReducedPhysBits) {
        sev->reduced_phys_bits = sevCaps->reduced_phys_bits;
        sev->haveReducedPhysBits = true;
    }

    return 0;
}


/* qemuProcessPrepareChardevSource:
 * @def: live domain definition
 * @cfg: driver configuration
 *
 * Iterate through all devices that use virDomainChrSourceDef as backend.
 */
static int
qemuProcessPrepareChardevSource(virDomainDef *def,
                                virQEMUDriverConfig *cfg)
{
    struct qemuDomainPrepareChardevSourceData data = { .cfg = cfg };

    return qemuDomainDeviceBackendChardevForeach(def,
                                                 qemuDomainPrepareChardevSourceOne,
                                                 &data);
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
 * This function MUST be called before qemuProcessPrepareHost().
 *
 * TODO: move all XML modification from qemuBuildCommandLine into this function
 */
int
qemuProcessPrepareDomain(virQEMUDriver *driver,
                         virDomainObj *vm,
                         unsigned int flags)
{
    size_t i;
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);

    priv->machineName = qemuDomainGetMachineName(vm);
    if (!priv->machineName)
        return -1;

    if (!(flags & VIR_QEMU_PROCESS_START_PRETEND)) {
        /* If you are using a SecurityDriver with dynamic labelling,
           then generate a security label for isolation */
        VIR_DEBUG("Generating domain security label (if required)");
        if (qemuSecurityGenLabel(driver->securityManager, vm->def) < 0) {
            virDomainAuditSecurityLabel(vm, false);
            return -1;
        }
        virDomainAuditSecurityLabel(vm, true);

        if (qemuProcessPrepareDomainNUMAPlacement(vm) < 0)
            return -1;
    }

    /* Whether we should use virtlogd as stdio handler for character
     * devices source backend. */
    priv->chardevStdioLogd = cfg->stdioLogD;

    /* Track if this domain remembers original owner */
    priv->rememberOwner = cfg->rememberOwner;

    qemuProcessPrepareAllowReboot(vm);

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
        return -1;
    }

    if (qemuAssignDeviceAliases(vm->def) < 0)
        return -1;

    qemuProcessPrepareDeviceBootorder(vm->def);

    VIR_DEBUG("Setting graphics devices");
    if (qemuProcessSetupGraphics(driver, vm, priv->qemuCaps, flags) < 0)
        return -1;

    VIR_DEBUG("Create domain masterKey");
    if (qemuDomainMasterKeyCreate(vm) < 0)
        return -1;

    VIR_DEBUG("Setting up storage");
    if (qemuProcessPrepareDomainStorage(driver, vm, priv, cfg, flags) < 0)
        return -1;

    VIR_DEBUG("Setting up host devices");
    if (qemuProcessPrepareDomainHostdevs(vm, priv) < 0)
        return -1;

    VIR_DEBUG("Prepare chardev source backends");
    if (qemuProcessPrepareChardevSource(vm->def, cfg) < 0)
        return -1;

    VIR_DEBUG("Prepare device secrets");
    if (qemuDomainSecretPrepare(driver, vm) < 0)
        return -1;

    VIR_DEBUG("Prepare bios/uefi paths");
    if (qemuFirmwareFillDomain(driver, vm->def, false) < 0)
        return -1;
    if (qemuDomainInitializePflashStorageSource(vm, cfg) < 0)
        return -1;

    VIR_DEBUG("Preparing external devices");
    if (qemuExtDevicesPrepareDomain(driver, vm) < 0)
        return -1;

    if (flags & VIR_QEMU_PROCESS_START_NEW) {
        VIR_DEBUG("Aligning guest memory");
        if (qemuDomainAlignMemorySizes(vm->def) < 0)
            return -1;
    }

    for (i = 0; i < vm->def->nchannels; i++) {
        if (qemuDomainPrepareChannel(vm->def->channels[i],
                                     priv->channelTargetDir) < 0)
            return -1;
    }

    if (!(priv->monConfig = virDomainChrSourceDefNew(driver->xmlopt)))
        return -1;

    VIR_DEBUG("Preparing monitor state");
    if (qemuProcessPrepareMonitorChr(priv->monConfig, priv->libDir) < 0)
        return -1;

    priv->monError = false;
    priv->monStart = 0;
    priv->runningReason = VIR_DOMAIN_RUNNING_UNKNOWN;
    priv->pausedReason = VIR_DOMAIN_PAUSED_UNKNOWN;

    VIR_DEBUG("Updating guest CPU definition");
    if (qemuProcessUpdateGuestCPU(vm->def, priv->qemuCaps, driver->hostarch, flags) < 0)
        return -1;

    for (i = 0; i < vm->def->nshmems; i++)
        qemuDomainPrepareShmemChardev(vm->def->shmems[i]);

    if (vm->def->sec &&
        vm->def->sec->sectype == VIR_DOMAIN_LAUNCH_SECURITY_SEV) {
        VIR_DEBUG("Updating SEV platform info");
        if (qemuProcessUpdateSEVInfo(vm) < 0)
            return -1;
    }

    return 0;
}


static int
qemuProcessSEVCreateFile(virDomainObj *vm,
                         const char *name,
                         const char *data)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    virQEMUDriver *driver = priv->driver;
    g_autofree char *configFile = NULL;

    if (!(configFile = virFileBuildPath(priv->libDir, name, ".base64")))
        return -1;

    if (virFileRewriteStr(configFile, S_IRUSR | S_IWUSR, data) < 0) {
        virReportSystemError(errno, _("failed to write data to config '%1$s'"),
                             configFile);
        return -1;
    }

    if (qemuSecurityDomainSetPathLabel(driver, vm, configFile, true) < 0)
        return -1;

    return 0;
}


static int
qemuProcessPrepareSEVGuestInput(virDomainObj *vm)
{
    virDomainSEVDef *sev = &vm->def->sec->data.sev;

    VIR_DEBUG("Preparing SEV guest");

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
qemuProcessPrepareLaunchSecurityGuestInput(virDomainObj *vm)
{
    virDomainSecDef *sec = vm->def->sec;

    if (!sec)
        return 0;

    switch ((virDomainLaunchSecurity) sec->sectype) {
    case VIR_DOMAIN_LAUNCH_SECURITY_SEV:
        return qemuProcessPrepareSEVGuestInput(vm);
    case VIR_DOMAIN_LAUNCH_SECURITY_PV:
        return 0;
    case VIR_DOMAIN_LAUNCH_SECURITY_NONE:
    case VIR_DOMAIN_LAUNCH_SECURITY_LAST:
        virReportEnumRangeError(virDomainLaunchSecurity, sec->sectype);
        return -1;
    }

    return 0;
}


static int
qemuProcessPrepareHostStorageSourceVDPA(virStorageSource *src,
                                        qemuDomainObjPrivate *priv)
{
    qemuDomainStorageSourcePrivate *srcpriv = NULL;
    virStorageType actualType = virStorageSourceGetActualType(src);
    int vdpafd = -1;

    if (actualType != VIR_STORAGE_TYPE_VHOST_VDPA)
        return 0;

    if ((vdpafd = qemuVDPAConnect(src->vdpadev)) < 0)
        return -1;

    srcpriv = qemuDomainStorageSourcePrivateFetch(src);

    srcpriv->fdpass = qemuFDPassNew(qemuBlockStorageSourceGetStorageNodename(src), priv);
    qemuFDPassAddFD(srcpriv->fdpass, &vdpafd, "-vdpa");
    return 0;
}


/**
 * See qemuProcessPrepareHostStorageSourceChain
 */
int
qemuProcessPrepareHostStorageSource(virDomainObj *vm,
                                    virStorageSource *src)
{
    /* connect to any necessary vdpa block devices */
    if (qemuProcessPrepareHostStorageSourceVDPA(src, vm->privateData) < 0)
        return -1;

    return 0;
}


/**
 * qemuProcessPrepareHostStorageSourceChain:
 *
 * @vm: domain object
 * @chain: source chain
 *
 * Prepare the host side of a disk for use with the VM. Note that this function
 * accesses host resources.
 */
int
qemuProcessPrepareHostStorageSourceChain(virDomainObj *vm,
                                         virStorageSource *chain)
{
    virStorageSource *n;

    for (n = chain; virStorageSourceIsBacking(n); n = n->backingStore) {
        if (qemuProcessPrepareHostStorageSource(vm, n) < 0)
            return -1;
    }

    return 0;
}


/**
 * qemuProcessPrepareHostStorageDisk:
 *
 * @vm: domain object
 * @disk: disk definition object
 *
 * Prepare the host side of a disk for use with the VM. Note that this function
 * accesses host resources.
 *
 * Note that this function does not call qemuDomainDetermineDiskChain as that is
 * needed in qemuProcessPrepareHostStorage to remove disks based on the startup
 * policy, thus other callers need to call it explicitly.
 */
int
qemuProcessPrepareHostStorageDisk(virDomainObj *vm,
                                  virDomainDiskDef *disk)
{
    if (qemuProcessPrepareHostStorageSourceChain(vm, disk->src) < 0)
        return -1;

    return 0;
}


static int
qemuProcessPrepareHostStorage(virQEMUDriver *driver,
                              virDomainObj *vm,
                              unsigned int flags)
{
    size_t i;
    bool cold_boot = flags & VIR_QEMU_PROCESS_START_COLD;

    for (i = vm->def->ndisks; i > 0; i--) {
        size_t idx = i - 1;
        virDomainDiskDef *disk = vm->def->disks[idx];

        if (virStorageSourceIsEmpty(disk->src))
            continue;

        /* backing chain needs to be redetected if we aren't using blockdev */
        if (qemuDiskBusIsSD(disk->bus))
            virStorageSourceBackingStoreClear(disk->src);

        /*
         * Go to applying startup policy for optional disk with nonexistent
         * source file immediately as determining chain will surely fail
         * and we don't want noisy error notice in logs for this case.
         */
        if (qemuDomainDiskIsMissingLocalOptional(disk) && cold_boot)
            VIR_INFO("optional disk '%s' source file is missing, "
                     "skip checking disk chain", disk->dst);
        else if (qemuDomainDetermineDiskChain(driver, vm, disk, NULL) >= 0)
            continue;

        if (qemuDomainCheckDiskStartupPolicy(driver, vm, idx, cold_boot) >= 0)
            continue;

        return -1;
    }

    for (i = 0; i < vm->def->ndisks; i++) {
        virDomainDiskDef *disk = vm->def->disks[i];

        if (qemuProcessPrepareHostStorageDisk(vm, disk) < 0)
            return -1;
    }

    return 0;
}


int
qemuProcessOpenVhostVsock(virDomainVsockDef *vsock)
{
    qemuDomainVsockPrivate *priv = (qemuDomainVsockPrivate *)vsock->privateData;
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


static int
qemuProcessPrepareHostBackendChardevFileHelper(const char *path,
                                               virTristateSwitch append,
                                               int *fd,
                                               virLogManager *logManager,
                                               virSecurityManager *secManager,
                                               virQEMUDriverConfig *cfg,
                                               const virDomainDef *def)
{
    if (logManager) {
        int flags = 0;

        if (append == VIR_TRISTATE_SWITCH_ABSENT ||
            append == VIR_TRISTATE_SWITCH_OFF)
            flags |= VIR_LOG_MANAGER_PROTOCOL_DOMAIN_OPEN_LOG_FILE_TRUNCATE;

        if ((*fd = virLogManagerDomainOpenLogFile(logManager,
                                                  "qemu",
                                                  def->uuid,
                                                  def->name,
                                                  path,
                                                  flags,
                                                  NULL, NULL)) < 0)
            return -1;
    } else {
        int oflags = O_CREAT | O_WRONLY;

        switch (append) {
        case VIR_TRISTATE_SWITCH_ABSENT:
        case VIR_TRISTATE_SWITCH_OFF:
            oflags |= O_TRUNC;
            break;
        case VIR_TRISTATE_SWITCH_ON:
            oflags |= O_APPEND;
            break;
        case VIR_TRISTATE_SWITCH_LAST:
            break;
        }

        if ((*fd = qemuDomainOpenFile(cfg, def, path, oflags, NULL)) < 0)
            return -1;

        if (qemuSecuritySetImageFDLabel(secManager, (virDomainDef*)def, *fd) < 0) {
            VIR_FORCE_CLOSE(*fd);
            return -1;
        }
    }

    return 0;
}


struct qemuProcessPrepareHostBackendChardevData {
    qemuDomainObjPrivate *priv;
    virLogManager *logManager;
    virQEMUDriverConfig *cfg;
    virDomainDef *def;
    const char *fdprefix;
};


static int
qemuProcessPrepareHostBackendChardevOne(virDomainDeviceDef *dev,
                                        virDomainChrSourceDef *chardev,
                                        void *opaque)
{
    struct qemuProcessPrepareHostBackendChardevData *data = opaque;
    qemuDomainChrSourcePrivate *charpriv = QEMU_DOMAIN_CHR_SOURCE_PRIVATE(chardev);
    const char *devalias = NULL;

    /* this function is also called for the monitor backend which doesn't have
     * a 'dev' */
    if (dev) {
        virDomainDeviceInfo *info = virDomainDeviceGetInfo(dev);
        devalias = info->alias;

        /* vhost-user disk doesn't use FD passing */
        if (dev->type == VIR_DOMAIN_DEVICE_DISK)
            return 0;

        if (dev->type == VIR_DOMAIN_DEVICE_NET) {
            /* due to a historical bug in qemu we don't use FD passtrhough for
             * vhost-sockets for network devices */
            return 0;
        }

        /* TPMs FD passing setup is special and handled separately */
        if (dev->type == VIR_DOMAIN_DEVICE_TPM)
            return 0;
    } else {
        devalias = data->fdprefix;
    }

    switch ((virDomainChrType) chardev->type) {
    case VIR_DOMAIN_CHR_TYPE_NULL:
    case VIR_DOMAIN_CHR_TYPE_VC:
    case VIR_DOMAIN_CHR_TYPE_PTY:
    case VIR_DOMAIN_CHR_TYPE_DEV:
    case VIR_DOMAIN_CHR_TYPE_PIPE:
    case VIR_DOMAIN_CHR_TYPE_STDIO:
    case VIR_DOMAIN_CHR_TYPE_UDP:
    case VIR_DOMAIN_CHR_TYPE_TCP:
    case VIR_DOMAIN_CHR_TYPE_SPICEVMC:
    case VIR_DOMAIN_CHR_TYPE_SPICEPORT:
    case VIR_DOMAIN_CHR_TYPE_QEMU_VDAGENT:
    case VIR_DOMAIN_CHR_TYPE_DBUS:
        break;

    case VIR_DOMAIN_CHR_TYPE_FILE: {
        VIR_AUTOCLOSE sourcefd = -1;

        if (qemuProcessPrepareHostBackendChardevFileHelper(chardev->data.file.path,
                                                           chardev->data.file.append,
                                                           &sourcefd,
                                                           data->logManager,
                                                           data->priv->driver->securityManager,
                                                           data->cfg,
                                                           data->def) < 0)
            return -1;

        charpriv->sourcefd = qemuFDPassNew(devalias, data->priv);

        qemuFDPassAddFD(charpriv->sourcefd, &sourcefd, "-source");
    }
        break;

    case VIR_DOMAIN_CHR_TYPE_UNIX:
        if (chardev->data.nix.listen) {
            g_autofree char *name = g_strdup_printf("%s-source", devalias);
            VIR_AUTOCLOSE sourcefd = -1;

            if (qemuSecuritySetSocketLabel(data->priv->driver->securityManager, data->def) < 0)
                return -1;

            sourcefd = qemuOpenChrChardevUNIXSocket(chardev);

            if (qemuSecurityClearSocketLabel(data->priv->driver->securityManager, data->def) < 0 ||
                sourcefd < 0)
                return -1;

            charpriv->directfd = qemuFDPassDirectNew(name, &sourcefd);
        }
        break;

    case VIR_DOMAIN_CHR_TYPE_NMDM:
    case VIR_DOMAIN_CHR_TYPE_LAST:
    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unsupported chardev '%1$s'"),
                       virDomainChrTypeToString(chardev->type));
        return -1;
    }

    if (chardev->logfile) {
        VIR_AUTOCLOSE logfd = -1;

        if (qemuProcessPrepareHostBackendChardevFileHelper(chardev->logfile,
                                                           chardev->logappend,
                                                           &logfd,
                                                           data->logManager,
                                                           data->priv->driver->securityManager,
                                                           data->cfg,
                                                           data->def) < 0)
            return -1;

        charpriv->logfd = qemuFDPassNew(devalias, data->priv);

        qemuFDPassAddFD(charpriv->logfd, &logfd, "-log");
    }

    return 0;
}


/* prepare the chardev backends for various devices:
 * serial/parallel/channel chardevs, vhost-user disks, vhost-user network
 * interfaces, smartcards, shared memory, and redirdevs */
static int
qemuProcessPrepareHostBackendChardev(virDomainObj *vm)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(priv->driver);
    struct qemuProcessPrepareHostBackendChardevData data = {
        .priv = priv,
        .logManager = NULL,
        .cfg = cfg,
        .def = vm->def,
    };
    g_autoptr(virLogManager) logManager = NULL;

    if (cfg->stdioLogD) {
        if (!(logManager = data.logManager = virLogManagerNew(priv->driver->privileged)))
            return -1;
    }

    if (qemuDomainDeviceBackendChardevForeach(vm->def,
                                              qemuProcessPrepareHostBackendChardevOne,
                                              &data) < 0)
        return -1;

    data.fdprefix = "monitor";

    if (qemuProcessPrepareHostBackendChardevOne(NULL, priv->monConfig, &data) < 0)
        return -1;

    return 0;
}


int
qemuProcessPrepareHostBackendChardevHotplug(virDomainObj *vm,
                                            virDomainDeviceDef *dev)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(priv->driver);
    struct qemuProcessPrepareHostBackendChardevData data = {
        .priv = priv,
        .logManager = NULL,
        .cfg = cfg,
        .def = vm->def,
    };
    g_autoptr(virLogManager) logManager = NULL;

    if (cfg->stdioLogD) {
        if (!(logManager = data.logManager = virLogManagerNew(priv->driver->privileged)))
            return -1;
    }

    if (qemuDomainDeviceBackendChardevForeachOne(dev,
                                                 qemuProcessPrepareHostBackendChardevOne,
                                                 &data) < 0)
        return -1;

    return 0;
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
 * This function MUST be called only after qemuProcessPrepareDomain().
 *
 * TODO: move all host modification from qemuBuildCommandLine into this function
 */
int
qemuProcessPrepareHost(virQEMUDriver *driver,
                       virDomainObj *vm,
                       unsigned int flags)
{
    unsigned int hostdev_flags = 0;
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);

    /*
     * Create all per-domain directories in order to make sure domain
     * with any possible seclabels can access it.
     */
    if (qemuProcessMakeDir(driver, vm, priv->libDir) < 0 ||
        qemuProcessMakeDir(driver, vm, priv->channelTargetDir) < 0)
        return -1;

    if (qemuPrepareNVRAM(driver, vm, !!(flags & VIR_QEMU_PROCESS_START_RESET_NVRAM)) < 0)
        return -1;

    if (vm->def->vsock) {
        if (qemuProcessOpenVhostVsock(vm->def->vsock) < 0)
            return -1;
    }
    /* network devices must be "prepared" before hostdevs, because
     * setting up a network device might create a new hostdev that
     * will need to be setup.
     */
    VIR_DEBUG("Preparing network devices");
    if (qemuProcessNetworkPrepareDevices(driver, vm) < 0)
        return -1;

    /* Must be run before security labelling */
    VIR_DEBUG("Preparing host devices");
    if (!cfg->relaxedACS)
        hostdev_flags |= VIR_HOSTDEV_STRICT_ACS_CHECK;
    if (flags & VIR_QEMU_PROCESS_START_NEW)
        hostdev_flags |= VIR_HOSTDEV_COLD_BOOT;
    if (qemuHostdevPrepareDomainDevices(driver, vm->def, hostdev_flags) < 0)
        return -1;

    VIR_DEBUG("Preparing chr device backends");
    if (qemuProcessPrepareHostBackendChardev(vm) < 0)
        return -1;

    if (qemuProcessBuildDestroyMemoryPaths(driver, vm, NULL, true) < 0)
        return -1;

    /* Ensure no historical cgroup for this VM is lying around bogus
     * settings */
    VIR_DEBUG("Ensuring no historical cgroup is lying around");
    virDomainCgroupRemoveCgroup(vm, priv->cgroup, priv->machineName);

    if (g_mkdir_with_parents(cfg->logDir, 0777) < 0) {
        virReportSystemError(errno,
                             _("cannot create log directory %1$s"),
                             cfg->logDir);
        return -1;
    }

    VIR_FREE(priv->pidfile);
    if (!(priv->pidfile = virPidFileBuildPath(cfg->stateDir, vm->def->name))) {
        virReportSystemError(errno,
                             "%s", _("Failed to build pidfile path."));
        return -1;
    }

    if (unlink(priv->pidfile) < 0 &&
        errno != ENOENT) {
        virReportSystemError(errno,
                             _("Cannot remove stale PID file %1$s"),
                             priv->pidfile);
        return -1;
    }

    VIR_DEBUG("Write domain masterKey");
    if (qemuDomainWriteMasterKeyFile(driver, vm) < 0)
        return -1;

    VIR_DEBUG("Preparing disks (host)");
    if (qemuProcessPrepareHostStorage(driver, vm, flags) < 0)
        return -1;

    VIR_DEBUG("Preparing external devices");
    if (qemuExtDevicesPrepareHost(driver, vm) < 0)
        return -1;

    if (qemuProcessPrepareLaunchSecurityGuestInput(vm) < 0)
        return -1;

    return 0;
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
qemuProcessGenID(virDomainObj *vm,
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
 * qemuProcessSetupDiskThrottling:
 *
 * Sets up disk trottling for -blockdev via block_set_io_throttle monitor
 * command. This hack should be replaced by proper use of the 'throttle'
 * blockdev driver in qemu once it will support changing of the throttle group.
 * Same hack is done in qemuDomainAttachDiskGeneric.
 */
static int
qemuProcessSetupDiskThrottling(virDomainObj *vm,
                               virDomainAsyncJob asyncJob)
{
    size_t i;
    int ret = -1;

    VIR_DEBUG("Setting up disk throttling for -blockdev via block_set_io_throttle");

    if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) < 0)
        return -1;

    for (i = 0; i < vm->def->ndisks; i++) {
        virDomainDiskDef *disk = vm->def->disks[i];

        /* Setting throttling for empty drives fails */
        if (virStorageSourceIsEmpty(disk->src))
            continue;

        if (!qemuDiskConfigBlkdeviotuneEnabled(disk))
            continue;

        if (qemuMonitorSetBlockIoThrottle(qemuDomainGetMonitor(vm),
                                          QEMU_DOMAIN_DISK_PRIVATE(disk)->qomName,
                                          &disk->blkdeviotune) < 0)
            goto cleanup;
    }

    ret = 0;

 cleanup:
    qemuDomainObjExitMonitor(vm);
    return ret;
}


static int
qemuProcessEnableDomainNamespaces(virQEMUDriver *driver,
                                  virDomainObj *vm)
{
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    const char *state = "disabled";

    if (virBitmapIsBitSet(cfg->namespaces, QEMU_DOMAIN_NS_MOUNT) &&
        qemuDomainEnableNamespace(vm, QEMU_DOMAIN_NS_MOUNT) < 0)
        return -1;

    if (qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT))
        state = "enabled";

    VIR_DEBUG("Mount namespace for domain name=%s is %s",
              vm->def->name, state);
    return 0;
}


static int
qemuProcessEnablePerf(virDomainObj *vm)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    size_t i;

    if (!(priv->perf = virPerfNew()))
        return -1;

    for (i = 0; i < VIR_PERF_EVENT_LAST; i++) {
        if (vm->def->perf.events[i] == VIR_TRISTATE_BOOL_YES &&
            virPerfEventEnable(priv->perf, i, vm->pid) < 0)
            return -1;
    }

    return 0;
}


static int
qemuProcessSetupDisksTransientSnapshot(virDomainObj *vm,
                                       virDomainAsyncJob asyncJob)
{
    g_autoptr(qemuSnapshotDiskContext) snapctxt = NULL;
    g_autoptr(GHashTable) blockNamedNodeData = NULL;
    size_t i;

    if (!(blockNamedNodeData = qemuBlockGetNamedNodeData(vm, asyncJob)))
        return -1;

    snapctxt = qemuSnapshotDiskContextNew(vm->def->ndisks, vm, asyncJob);

    for (i = 0; i < vm->def->ndisks; i++) {
        virDomainDiskDef *domdisk = vm->def->disks[i];
        g_autoptr(virDomainSnapshotDiskDef) snapdisk = NULL;

        if (!domdisk->transient ||
            domdisk->transientShareBacking == VIR_TRISTATE_BOOL_YES)
            continue;

        /* validation code makes sure that we do this only for local disks
         * with a file source */

        if (!(snapdisk = qemuSnapshotGetTransientDiskDef(domdisk, vm->def->name)))
            return -1;

        if (qemuSnapshotDiskPrepareOne(snapctxt, domdisk, snapdisk,
                                       blockNamedNodeData,
                                       false,
                                       false) < 0)
            return -1;
    }

    if (qemuSnapshotDiskCreate(snapctxt) < 0)
        return -1;

    for (i = 0; i < vm->def->ndisks; i++) {
        virDomainDiskDef *domdisk = vm->def->disks[i];

        if (!domdisk->transient ||
            domdisk->transientShareBacking == VIR_TRISTATE_BOOL_YES)
            continue;

        QEMU_DOMAIN_DISK_PRIVATE(domdisk)->transientOverlayCreated = true;
    }

    return 0;
}


static int
qemuProcessSetupDisksTransientHotplug(virDomainObj *vm,
                                      virDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    bool hasHotpluggedDisk = false;
    size_t i;

    for (i = 0; i < vm->def->ndisks; i++) {
        virDomainDiskDef *domdisk = vm->def->disks[i];

        if (!domdisk->transient ||
            domdisk->transientShareBacking != VIR_TRISTATE_BOOL_YES)
            continue;

        if (qemuDomainAttachDiskGeneric(vm, domdisk, asyncJob) < 0)
            return -1;

        hasHotpluggedDisk = true;
    }

    /* in order to allow booting from such disks we need to issue a system-reset
     * so that the firmware tables recording bootable devices are regerated */
    if (hasHotpluggedDisk) {
        int rc;

        if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) < 0)
            return -1;

        rc = qemuMonitorSystemReset(priv->mon);

        qemuDomainObjExitMonitor(vm);
        if (rc < 0)
            return -1;
    }

    return 0;
}


static int
qemuProcessSetupDisksTransient(virDomainObj *vm,
                               virDomainAsyncJob asyncJob)
{
    if (qemuProcessSetupDisksTransientSnapshot(vm, asyncJob) < 0)
        return -1;

    if (qemuProcessSetupDisksTransientHotplug(vm, asyncJob) < 0)
        return -1;

    return 0;
}


static int
qemuProcessSetupLifecycleActions(virDomainObj *vm,
                                 virDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    int rc;

    if (!(virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_SET_ACTION)))
        return 0;

    /* for now we handle only onReboot->destroy here as an alternative to
     * '-no-reboot' on the commandline */
    if (vm->def->onReboot != VIR_DOMAIN_LIFECYCLE_ACTION_DESTROY)
        return 0;

    if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) < 0)
        return -1;

    rc = qemuMonitorSetAction(priv->mon,
                              QEMU_MONITOR_ACTION_SHUTDOWN_KEEP,
                              QEMU_MONITOR_ACTION_REBOOT_SHUTDOWN,
                              QEMU_MONITOR_ACTION_WATCHDOG_KEEP,
                              QEMU_MONITOR_ACTION_PANIC_KEEP);

    qemuDomainObjExitMonitor(vm);
    if (rc < 0)
        return -1;

    return 0;
}


int
qemuProcessDeleteThreadContext(virDomainObj *vm)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    GSList *next = priv->threadContextAliases;
    int ret = -1;

    if (!next)
        return 0;

    for (; next; next = next->next) {
        if (qemuMonitorDelObject(priv->mon, next->data, true) < 0)
            goto cleanup;
    }

    ret = 0;
 cleanup:
    g_slist_free_full(g_steal_pointer(&priv->threadContextAliases), g_free);
    return ret;
}


static int
qemuProcessDeleteThreadContextHelper(virDomainObj *vm,
                                     virDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    int ret = -1;

    if (!priv->threadContextAliases)
        return 0;

    VIR_DEBUG("Deleting thread context objects");
    if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) < 0)
        return -1;

    ret = qemuProcessDeleteThreadContext(vm);

    qemuDomainObjExitMonitor(vm);

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
                  virQEMUDriver *driver,
                  virDomainObj *vm,
                  virDomainAsyncJob asyncJob,
                  qemuProcessIncomingDef *incoming,
                  virDomainMomentObj *snapshot,
                  virNetDevVPortProfileOp vmop,
                  unsigned int flags)
{
    int ret = -1;
    int rv;
    int logfile = -1;
    g_autoptr(qemuLogContext) logCtxt = NULL;
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autoptr(virCommand) cmd = NULL;
    struct qemuProcessHookData hookData;
    g_autoptr(virQEMUDriverConfig) cfg = NULL;
    size_t nnicindexes = 0;
    g_autofree int *nicindexes = NULL;
    unsigned long long maxMemLock = 0;
    bool incomingMigrationExtDevices = false;

    VIR_DEBUG("conn=%p driver=%p vm=%p name=%s id=%d asyncJob=%d "
              "incoming.uri=%s "
              "incoming.fd=%d incoming.path=%s "
              "snapshot=%p vmop=%d flags=0x%x",
              conn, driver, vm, vm->def->name, vm->def->id, asyncJob,
              NULLSTR(incoming ? incoming->uri : NULL),
              incoming ? incoming->fd : -1,
              NULLSTR(incoming ? incoming->path : NULL),
              snapshot, vmop, flags);

    /* Okay, these are just internal flags,
     * but doesn't hurt to check */
    virCheckFlags(VIR_QEMU_PROCESS_START_COLD |
                  VIR_QEMU_PROCESS_START_PAUSED |
                  VIR_QEMU_PROCESS_START_AUTODESTROY |
                  VIR_QEMU_PROCESS_START_NEW |
                  VIR_QEMU_PROCESS_START_GEN_VMID |
                  VIR_QEMU_PROCESS_START_RESET_NVRAM, -1);

    cfg = virQEMUDriverGetConfig(driver);

    if (flags & VIR_QEMU_PROCESS_START_AUTODESTROY) {
        if (!conn) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Domain autodestroy requires a connection handle"));
            return -1;
        }
        if (driver->embeddedRoot) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Domain autodestroy not supported for embedded drivers yet"));
            return -1;
        }
    }

    hookData.vm = vm;
    hookData.driver = driver;
    /* We don't increase cfg's reference counter here. */
    hookData.cfg = cfg;

    VIR_DEBUG("Creating domain log file");
    if (!(logCtxt = qemuLogContextNew(driver, vm, vm->def->name))) {
        virLastErrorPrefixMessage("%s", _("can't connect to virtlogd"));
        goto cleanup;
    }
    logfile = qemuLogContextGetWriteFD(logCtxt);

    if (qemuProcessGenID(vm, flags) < 0)
        goto cleanup;

    if (qemuDomainSchedCoreStart(cfg, vm) < 0)
        goto cleanup;

    /* For external devices the rules of incoming migration are a bit stricter,
     * than plain @incoming != NULL. They need to differentiate between
     * incoming migration and restore from a save file.  */
    incomingMigrationExtDevices = incoming &&
        vmop == VIR_NETDEV_VPORT_PROFILE_OP_MIGRATE_IN_START;

    if (qemuExtDevicesStart(driver, vm, incomingMigrationExtDevices) < 0)
        goto cleanup;

    if (!(cmd = qemuBuildCommandLine(vm,
                                     incoming ? "defer" : NULL,
                                     snapshot, vmop,
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

    qemuDomainObjCheckTaint(driver, vm, logCtxt, incoming != NULL);

    qemuLogContextMarkPosition(logCtxt);

    if (qemuProcessEnableDomainNamespaces(driver, vm) < 0)
        goto cleanup;

    VIR_DEBUG("Setting up raw IO");
    if (qemuProcessSetupRawIO(vm, cmd) < 0)
        goto cleanup;

    virCommandSetPreExecHook(cmd, qemuProcessHook, &hookData);
    virCommandSetUmask(cmd, 0x002);

    VIR_DEBUG("Setting up process limits");

    /* In some situations, eg. VFIO passthrough, QEMU might need to lock a
     * significant amount of memory, so we need to set the limit accordingly */
    maxMemLock = qemuDomainGetMemLockLimitBytes(vm->def);

    /* For all these settings, zero indicates that the limit should
     * not be set explicitly and the default/inherited limit should
     * be applied instead */
    if (maxMemLock > 0)
        virCommandSetMaxMemLock(cmd, maxMemLock);
    if (cfg->maxProcesses > 0)
        virCommandSetMaxProcesses(cmd, cfg->maxProcesses);
    if (cfg->maxFiles > 0)
        virCommandSetMaxFiles(cmd, cfg->maxFiles);
    if (cfg->schedCore == QEMU_SCHED_CORE_EMULATOR ||
        cfg->schedCore == QEMU_SCHED_CORE_FULL)
        virCommandSetRunAmong(cmd, priv->schedCoreChildPID);

    /* In this case, however, zero means that core dumps should be
     * disabled, and so we always need to set the limit explicitly */
    virCommandSetMaxCoreSize(cmd, cfg->maxCore);

    VIR_DEBUG("Setting up security labelling");
    if (qemuSecuritySetChildProcessLabel(driver->securityManager,
                                         vm->def, false, cmd) < 0)
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
                                 _("Domain %1$s didn't show up"),
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
    if (virDomainObjSave(vm, driver->xmlopt, cfg->stateDir) < 0)
        goto cleanup;

    VIR_DEBUG("Waiting for handshake from child");
    if (virCommandHandshakeWait(cmd) < 0) {
        /* Read errors from child that occurred between fork and exec. */
        qemuProcessReportLogError(logCtxt,
                                  _("Process exited prior to exec"));
        goto cleanup;
    }

    VIR_DEBUG("Building domain mount namespace (if required)");
    if (qemuDomainBuildNamespace(cfg, vm) < 0)
        goto cleanup;

    VIR_DEBUG("Setting up domain cgroup (if required)");
    if (qemuSetupCgroup(vm, nnicindexes, nicindexes) < 0)
        goto cleanup;

    VIR_DEBUG("Setting up domain perf (if required)");
    if (qemuProcessEnablePerf(vm) < 0)
        goto cleanup;

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
                                incoming ? incoming->path : NULL,
                                incoming != NULL) < 0)
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
                                 _("cannot stat fd %1$d"), incoming->fd);
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

    if (qemuDomainObjStartWorker(vm) < 0)
        goto cleanup;

    VIR_DEBUG("Waiting for monitor to show up");
    if (qemuProcessWaitForMonitor(driver, vm, asyncJob, logCtxt) < 0)
        goto cleanup;

    if (qemuConnectAgent(driver, vm) < 0)
        goto cleanup;

    VIR_DEBUG("setting up hotpluggable cpus");
    if (qemuDomainHasHotpluggableStartupVcpus(vm->def)) {
        if (qemuDomainRefreshVcpuInfo(vm, asyncJob, false) < 0)
            goto cleanup;

        if (qemuProcessValidateHotpluggableVcpus(vm->def) < 0)
            goto cleanup;

        if (qemuProcessSetupHotpluggableVcpus(vm, asyncJob) < 0)
            goto cleanup;
    }

    VIR_DEBUG("Refreshing VCPU info");
    if (qemuDomainRefreshVcpuInfo(vm, asyncJob, false) < 0)
        goto cleanup;

    if (qemuDomainValidateVcpuInfo(vm) < 0)
        goto cleanup;

    qemuDomainVcpuPersistOrder(vm->def);

    VIR_DEBUG("Verifying and updating provided guest CPU");
    if (qemuProcessUpdateAndVerifyCPU(vm, asyncJob) < 0)
        goto cleanup;

    VIR_DEBUG("Detecting IOThread PIDs");
    if (qemuProcessDetectIOThreadPIDs(vm, asyncJob) < 0)
        goto cleanup;

    VIR_DEBUG("Setting global CPU cgroup (if required)");
    if (virDomainCgroupSetupGlobalCpuCgroup(vm, priv->cgroup) < 0)
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
    if (qemuProcessSetLinkStates(vm, asyncJob) < 0)
        goto cleanup;

    VIR_DEBUG("Setting initial memory amount");
    if (qemuProcessSetupBalloon(vm, asyncJob) < 0)
        goto cleanup;

    if (qemuProcessSetupDiskThrottling(vm, asyncJob) < 0)
        goto cleanup;

    /* Since CPUs were not started yet, the balloon could not return the memory
     * to the host and thus cur_balloon needs to be updated so that GetXMLdesc
     * and friends return the correct size in case they can't grab the job */
    if (!incoming && !snapshot &&
        qemuProcessRefreshBalloonState(vm, asyncJob) < 0)
        goto cleanup;

    if (flags & VIR_QEMU_PROCESS_START_AUTODESTROY)
        virCloseCallbacksDomainAdd(vm, conn, qemuProcessAutoDestroy);

    if (!incoming && !snapshot) {
        VIR_DEBUG("Setting up transient disk");
        if (qemuProcessSetupDisksTransient(vm, asyncJob) < 0)
            goto cleanup;
    }

    VIR_DEBUG("Setting handling of lifecycle actions");
    if (qemuProcessSetupLifecycleActions(vm, asyncJob) < 0)
        goto cleanup;

    if (qemuProcessDeleteThreadContextHelper(vm, asyncJob) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    qemuDomainSchedCoreStop(priv);
    qemuDomainStartupCleanup(vm);
    return ret;
}


static int
qemuProcessRefreshRxFilters(virDomainObj *vm,
                            virDomainAsyncJob asyncJob)
{
    size_t i;

    for (i = 0; i < vm->def->nnets; i++) {
        virDomainNetDef *def = vm->def->nets[i];

        if (!virDomainNetGetActualTrustGuestRxFilters(def))
            continue;

        if (qemuDomainSyncRxFilter(vm, def, asyncJob) < 0)
            return -1;
    }

    return 0;
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
qemuProcessRefreshState(virQEMUDriver *driver,
                        virDomainObj *vm,
                        virDomainAsyncJob asyncJob)
{
    VIR_DEBUG("Fetching list of active devices");
    if (qemuDomainUpdateDeviceList(vm, asyncJob) < 0)
        return -1;

    VIR_DEBUG("Updating info of memory devices");
    if (qemuDomainUpdateMemoryDeviceInfo(vm, asyncJob) < 0)
        return -1;

    VIR_DEBUG("Detecting actual memory size for video device");
    if (qemuProcessUpdateVideoRamSize(driver, vm, asyncJob) < 0)
        return -1;

    VIR_DEBUG("Updating disk data");
    if (qemuProcessRefreshDisks(vm, asyncJob) < 0)
        return -1;

    VIR_DEBUG("Updating rx-filter data");
    if (qemuProcessRefreshRxFilters(vm, asyncJob) < 0)
        return -1;

    return 0;
}


/**
 * qemuProcessFinishStartup:
 *
 * Finish starting a new domain.
 */
int
qemuProcessFinishStartup(virQEMUDriver *driver,
                         virDomainObj *vm,
                         virDomainAsyncJob asyncJob,
                         bool startCPUs,
                         virDomainPausedReason pausedReason)
{
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);

    if (startCPUs) {
        VIR_DEBUG("Starting domain CPUs");
        if (qemuProcessStartCPUs(driver, vm,
                                 VIR_DOMAIN_RUNNING_BOOTED,
                                 asyncJob) < 0) {
            if (virGetLastErrorCode() == VIR_ERR_OK)
                virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                               _("resume operation failed"));
            return -1;
        }
    } else {
        virDomainObjSetState(vm, VIR_DOMAIN_PAUSED, pausedReason);
    }

    VIR_DEBUG("Writing domain status to disk");
    if (virDomainObjSave(vm, driver->xmlopt, cfg->stateDir) < 0)
        return -1;

    if (qemuProcessStartHook(driver, vm,
                             VIR_HOOK_QEMU_OP_STARTED,
                             VIR_HOOK_SUBOP_BEGIN) < 0)
        return -1;

    return 0;
}


int
qemuProcessStart(virConnectPtr conn,
                 virQEMUDriver *driver,
                 virDomainObj *vm,
                 virCPUDef *updatedCPU,
                 virDomainAsyncJob asyncJob,
                 const char *migrateFrom,
                 int migrateFd,
                 const char *migratePath,
                 virDomainMomentObj *snapshot,
                 virNetDevVPortProfileOp vmop,
                 unsigned int flags)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    qemuProcessIncomingDef *incoming = NULL;
    unsigned int stopFlags;
    bool relabel = false;
    bool relabelSavedState = false;
    int ret = -1;
    int rv;

    VIR_DEBUG("conn=%p driver=%p vm=%p name=%s id=%d asyncJob=%s "
              "migrateFrom=%s migrateFd=%d migratePath=%s "
              "snapshot=%p vmop=%d flags=0x%x",
              conn, driver, vm, vm->def->name, vm->def->id,
              virDomainAsyncJobTypeToString(asyncJob),
              NULLSTR(migrateFrom), migrateFd, NULLSTR(migratePath),
              snapshot, vmop, flags);

    virCheckFlagsGoto(VIR_QEMU_PROCESS_START_COLD |
                      VIR_QEMU_PROCESS_START_PAUSED |
                      VIR_QEMU_PROCESS_START_AUTODESTROY |
                      VIR_QEMU_PROCESS_START_GEN_VMID |
                      VIR_QEMU_PROCESS_START_RESET_NVRAM, cleanup);

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

    if (migratePath) {
        if (qemuSecuritySetSavedStateLabel(driver->securityManager,
                                           vm->def, migratePath) < 0)
            goto cleanup;
        relabelSavedState = true;
    }

    if ((rv = qemuProcessLaunch(conn, driver, vm, asyncJob, incoming,
                                snapshot, vmop, flags)) < 0) {
        if (rv == -2)
            relabel = true;
        goto stop;
    }
    relabel = true;

    if (incoming) {
        if (qemuMigrationDstRun(vm, incoming->uri, asyncJob) < 0)
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
    if (relabelSavedState &&
        qemuSecurityRestoreSavedStateLabel(driver->securityManager,
                                           vm->def, migratePath) < 0)
        VIR_WARN("failed to restore save state label on %s", migratePath);
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


/**
 * qemuProcessStartWithMemoryState:
 * @conn: connection object
 * @driver: qemu driver object
 * @vm: domain object
 * @fd: FD pointer of memory state file
 * @path: path to memory state file
 * @snapshot: internal snapshot to load when starting QEMU process or NULL
 * @data: data from memory state file or NULL
 * @asyncJob: type of asynchronous job
 * @start_flags: flags to start QEMU process with
 * @reason: audit log reason
 * @started: boolean to store if QEMU process was started
 *
 * Start VM with existing memory state. Make sure that the stored memory state
 * is correctly decompressed so it can be loaded by QEMU process.
 *
 * When reverting to internal snapshot caller needs to pass @snapshot
 * to correctly start QEMU process, @fd, @path, @data needs to be NULL.
 *
 * When restoring VM from saved image caller needs to pass @fd, @path and
 * @data to correctly start QEMU process, @snapshot needs to be NULL.
 *
 * For audit purposes the expected @reason is one of `restored` or `from-snapshot`.
 *
 * Returns 0 on success, -1 on error.
 */
int
qemuProcessStartWithMemoryState(virConnectPtr conn,
                                virQEMUDriver *driver,
                                virDomainObj *vm,
                                int *fd,
                                const char *path,
                                virDomainMomentObj *snapshot,
                                virQEMUSaveData *data,
                                virDomainAsyncJob asyncJob,
                                unsigned int start_flags,
                                const char *reason,
                                bool *started)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autoptr(qemuDomainSaveCookie) cookie = NULL;
    VIR_AUTOCLOSE intermediatefd = -1;
    g_autoptr(virCommand) cmd = NULL;
    g_autofree char *errbuf = NULL;
    int rc = 0;

    if (data) {
        if (virSaveCookieParseString(data->cookie, (virObject **)&cookie,
                                     virDomainXMLOptionGetSaveCookie(driver->xmlopt)) < 0)
            return -1;

        if (qemuSaveImageDecompressionStart(data, fd, &intermediatefd,
                                            &errbuf, &cmd) < 0) {
            return -1;
        }
    }

    if (qemuSaveImageDecompressionStart(data, fd, &intermediatefd, &errbuf, &cmd) < 0)
        return -1;

    /* No cookie means libvirt which saved the domain was too old to mess up
     * the CPU definitions.
     */
    if (cookie &&
        qemuDomainFixupCPUs(vm, &cookie->cpu) < 0)
        return -1;

    if (cookie && !cookie->slirpHelper)
        priv->disableSlirp = true;

    if (qemuProcessStart(conn, driver, vm, cookie ? cookie->cpu : NULL,
                         asyncJob, "stdio", *fd, path, snapshot,
                         VIR_NETDEV_VPORT_PROFILE_OP_RESTORE,
                         start_flags) == 0)
        *started = true;

    if (data) {
        rc = qemuSaveImageDecompressionStop(cmd, fd, &intermediatefd, errbuf,
                                            *started, path);
    }

    virDomainAuditStart(vm, reason, *started);
    if (!*started || rc < 0)
        return -1;

    /* qemuProcessStart doesn't unset the qemu error reporting infrastructure
     * in case of migration (which is used in this case) so we need to reset it
     * so that the handle to virtlogd is not held open unnecessarily */
    qemuMonitorSetDomainLog(qemuDomainGetMonitor(vm), NULL, NULL, NULL);

    return 0;
}


int
qemuProcessCreatePretendCmdPrepare(virQEMUDriver *driver,
                                   virDomainObj *vm,
                                   const char *migrateURI,
                                   unsigned int flags)
{
    virCheckFlags(VIR_QEMU_PROCESS_START_COLD |
                  VIR_QEMU_PROCESS_START_PAUSED |
                  VIR_QEMU_PROCESS_START_AUTODESTROY, -1);

    flags |= VIR_QEMU_PROCESS_START_PRETEND;

    if (!migrateURI)
        flags |= VIR_QEMU_PROCESS_START_NEW;

    if (qemuProcessInit(driver, vm, NULL, VIR_ASYNC_JOB_NONE,
                        !!migrateURI, flags) < 0)
        return -1;

    if (qemuProcessPrepareDomain(driver, vm, flags) < 0)
        return -1;

    return 0;
}


virCommand *
qemuProcessCreatePretendCmdBuild(virDomainObj *vm,
                                 const char *migrateURI)
{
    return qemuBuildCommandLine(vm,
                                migrateURI,
                                NULL,
                                VIR_NETDEV_VPORT_PROFILE_OP_NO_OP,
                                NULL,
                                NULL);
}


int
qemuProcessKill(virDomainObj *vm, unsigned int flags)
{
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
    return virProcessKillPainfullyDelay(vm->pid,
                                        !!(flags & VIR_QEMU_PROCESS_KILL_FORCE),
                                        vm->def->nhostdevs * 2,
                                        false);
}


/**
 * qemuProcessBeginStopJob:
 *
 * Stop all current jobs by killing the domain and start a new one for
 * qemuProcessStop.
 */
int
qemuProcessBeginStopJob(virDomainObj *vm,
                        virDomainJob job,
                        bool forceKill)
{
    qemuDomainObjPrivate *priv = vm->privateData;
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
    VIR_DEBUG("waking up all jobs waiting on the domain condition");
    virDomainObjBroadcast(vm);

    if (virDomainObjBeginJob(vm, job) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    priv->beingDestroyed = false;
    return ret;
}


void qemuProcessStop(virQEMUDriver *driver,
                     virDomainObj *vm,
                     virDomainShutoffReason reason,
                     virDomainAsyncJob asyncJob,
                     unsigned int flags)
{
    int ret;
    int retries = 0;
    qemuDomainObjPrivate *priv = vm->privateData;
    virErrorPtr orig_err;
    virDomainDef *def = vm->def;
    const virNetDevVPortProfile *vport = NULL;
    size_t i;
    g_autofree char *timestamp = NULL;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    g_autoptr(virConnect) conn = NULL;
    bool outgoingMigration;

    VIR_DEBUG("Shutting down vm=%p name=%s id=%d pid=%lld, "
              "reason=%s, asyncJob=%s, flags=0x%x",
              vm, vm->def->name, vm->def->id,
              (long long)vm->pid,
              virDomainShutoffReasonTypeToString(reason),
              virDomainAsyncJobTypeToString(asyncJob),
              flags);

    /* This method is routinely used in clean up paths. Disable error
     * reporting so we don't squash a legit error. */
    virErrorPreserveLast(&orig_err);

    if (asyncJob != VIR_ASYNC_JOB_NONE) {
        if (virDomainObjBeginNestedJob(vm, asyncJob) < 0)
            goto cleanup;
    } else if (vm->job->asyncJob != VIR_ASYNC_JOB_NONE &&
               vm->job->asyncOwner == virThreadSelfID() &&
               vm->job->active != VIR_JOB_ASYNC_NESTED) {
        VIR_WARN("qemuProcessStop called without a nested job (async=%s)",
                 virDomainAsyncJobTypeToString(asyncJob));
    }

    if (!virDomainObjIsActive(vm)) {
        VIR_DEBUG("VM '%s' not active", vm->def->name);
        goto endjob;
    }

    qemuProcessBuildDestroyMemoryPaths(driver, vm, NULL, false);

    if (!!g_atomic_int_dec_and_test(&driver->nactive) && driver->inhibitCallback)
        driver->inhibitCallback(false, driver->inhibitOpaque);

    if ((timestamp = virTimeStringNow()) != NULL) {
        qemuDomainLogAppendMessage(driver, vm, "%s: shutting down, reason=%s\n",
                                   timestamp,
                                   virDomainShutoffReasonTypeToString(reason));
    }

    /* Clear network bandwidth */
    virDomainClearNetBandwidth(vm->def);

    virDomainConfVMNWFilterTeardown(vm);

    if (cfg->macFilter) {
        for (i = 0; i < def->nnets; i++) {
            virDomainNetDef *net = def->nets[i];
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
        g_clear_pointer(&priv->agent, qemuAgentClose);
    }
    priv->agentError = false;

    if (priv->mon) {
        g_clear_pointer(&priv->mon, qemuMonitorClose);
    }

    if (priv->monConfig) {
        if (priv->monConfig->type == VIR_DOMAIN_CHR_TYPE_UNIX)
            unlink(priv->monConfig->data.nix.path);
        g_clear_pointer(&priv->monConfig, virObjectUnref);
    }

    qemuDomainObjStopWorker(vm);

    /* Remove the master key */
    qemuDomainMasterKeyRemove(priv);

    /* Do this before we delete the tree and remove pidfile. */
    qemuProcessKillManagedPRDaemon(vm);

    ignore_value(virDomainChrDefForeach(vm->def,
                                        false,
                                        qemuProcessCleanupChardevDevice,
                                        NULL));


    /* shut it off for sure */
    ignore_value(qemuProcessKill(vm,
                                 VIR_QEMU_PROCESS_KILL_FORCE|
                                 VIR_QEMU_PROCESS_KILL_NOCHECK));

    /* Its namespace is also gone then. */
    qemuDomainDestroyNamespace(driver, vm);

    qemuDomainCleanupRun(driver, vm);

    outgoingMigration = (flags & VIR_QEMU_PROCESS_STOP_MIGRATED) &&
        (asyncJob == VIR_ASYNC_JOB_MIGRATION_OUT);
    qemuExtDevicesStop(driver, vm, outgoingMigration);

    qemuDBusStop(driver, vm);

    vm->def->id = -1;

    /* Wake up anything waiting on domain condition */
    virDomainObjBroadcast(vm);

    virFileDeleteTree(priv->libDir);
    virFileDeleteTree(priv->channelTargetDir);

    /* Stop autodestroy in case guest is restarted */
    virCloseCallbacksDomainRemove(vm, NULL, qemuProcessAutoDestroy);

    /* now that we know it's stopped call the hook if present */
    if (virHookPresent(VIR_HOOK_DRIVER_QEMU)) {
        g_autofree char *xml = qemuDomainDefFormatXML(driver, NULL, vm->def, 0);

        /* we can't stop the operation even if the script raised an error */
        ignore_value(virHookCall(VIR_HOOK_DRIVER_QEMU, vm->def->name,
                                 VIR_HOOK_QEMU_OP_STOPPED, VIR_HOOK_SUBOP_END,
                                 NULL, xml, NULL));
    }

    /* Reset Security Labels unless caller don't want us to */
    if (!(flags & VIR_QEMU_PROCESS_STOP_NO_RELABEL))
        qemuSecurityRestoreAllLabel(driver, vm,
                                    !!(flags & VIR_QEMU_PROCESS_STOP_MIGRATED));

    /* Clear out dynamically assigned labels */
    for (i = 0; i < vm->def->nseclabels; i++) {
        if (vm->def->seclabels[i]->type == VIR_DOMAIN_SECLABEL_DYNAMIC)
            VIR_FREE(vm->def->seclabels[i]->label);
        VIR_FREE(vm->def->seclabels[i]->imagelabel);
    }

    qemuHostdevReAttachDomainDevices(driver, vm->def);

    for (i = 0; i < def->nnets; i++) {
        virDomainNetDef *net = def->nets[i];
        vport = virDomainNetGetActualVirtPortProfile(net);
        switch (virDomainNetGetActualType(net)) {
        case VIR_DOMAIN_NET_TYPE_DIRECT:
            if (QEMU_DOMAIN_NETWORK_PRIVATE(net)->created) {
                virNetDevMacVLanDeleteWithVPortProfile(net->ifname, &net->mac,
                                                       virDomainNetGetActualDirectDev(net),
                                                       virDomainNetGetActualDirectMode(net),
                                                       virDomainNetGetActualVirtPortProfile(net),
                                                       cfg->stateDir);
            }
            break;
        case VIR_DOMAIN_NET_TYPE_ETHERNET:
            if (net->managed_tap != VIR_TRISTATE_BOOL_NO && net->ifname) {
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
        case VIR_DOMAIN_NET_TYPE_VDPA:
        case VIR_DOMAIN_NET_TYPE_NULL:
        case VIR_DOMAIN_NET_TYPE_VDS:
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
    if ((ret = virDomainCgroupRemoveCgroup(vm, priv->cgroup, priv->machineName)) < 0) {
        if (ret == -EBUSY && (retries++ < 5)) {
            g_usleep(200*1000);
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
            virDomainResctrlMonDef *mon = NULL;

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
        virDomainGraphicsDef *graphics = vm->def->graphics[i];
        if (graphics->type == VIR_DOMAIN_GRAPHICS_TYPE_VNC) {
            if (graphics->data.vnc.portReserved) {
                virPortAllocatorRelease(graphics->data.vnc.port);
                graphics->data.vnc.portReserved = false;
            }
            if (graphics->data.vnc.websocketReserved) {
                virPortAllocatorRelease(graphics->data.vnc.websocket);
                graphics->data.vnc.websocketReserved = false;
            }
            if (graphics->data.vnc.websocketGenerated) {
                graphics->data.vnc.websocketGenerated = false;
                graphics->data.vnc.websocket = -1;
            }
        }
        if (graphics->type == VIR_DOMAIN_GRAPHICS_TYPE_SPICE) {
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

    for (i = 0; i < vm->ndeprecations; i++)
        g_free(vm->deprecations[i]);
    g_clear_pointer(&vm->deprecations, g_free);
    vm->ndeprecations = 0;
    vm->taint = 0;
    vm->pid = 0;
    virDomainObjSetState(vm, VIR_DOMAIN_SHUTOFF, reason);
    for (i = 0; i < vm->def->niothreadids; i++)
        vm->def->iothreadids[i]->thread_id = 0;

    /* clean up a possible backup job */
    if (priv->backup)
        qemuBackupJobTerminate(vm, VIR_DOMAIN_JOB_STATUS_CANCELED);

    /* Do this explicitly after vm->pid is reset so that security drivers don't
     * try to enter the domain's namespace which is non-existent by now as qemu
     * is no longer running. */
    if (!(flags & VIR_QEMU_PROCESS_STOP_NO_RELABEL)) {
        for (i = 0; i < def->ndisks; i++) {
            virDomainDiskDef *disk = def->disks[i];

            if (disk->mirror) {
                if (qemuSecurityRestoreImageLabel(driver, vm, disk->mirror, false) < 0)
                    VIR_WARN("Unable to restore security label on %s", disk->dst);

                if (virStorageSourceChainHasNVMe(disk->mirror))
                    qemuHostdevReAttachOneNVMeDisk(driver, vm->def->name, disk->mirror);
            }

            qemuBlockRemoveImageMetadata(driver, vm, disk->dst, disk->src);

            /* for now transient disks are forbidden with migration so they
             * can be handled here */
            if (disk->transient &&
                QEMU_DOMAIN_DISK_PRIVATE(disk)->transientOverlayCreated) {
                VIR_DEBUG("Removing transient overlay '%s' of disk '%s'",
                          disk->src->path, disk->dst);
                if (qemuDomainStorageFileInit(driver, vm, disk->src, NULL) >= 0) {
                    virStorageSourceUnlink(disk->src);
                    virStorageSourceDeinit(disk->src);
                }
            }
        }
    }

    qemuSecurityReleaseLabel(driver->securityManager, vm->def);

    /* clear all private data entries which are no longer needed */
    qemuDomainObjPrivateDataClear(priv);

    /* The "release" hook cleans up additional resources */
    if (virHookPresent(VIR_HOOK_DRIVER_QEMU)) {
        g_autofree char *xml = qemuDomainDefFormatXML(driver, NULL, vm->def, 0);

        /* we can't stop the operation even if the script raised an error */
        virHookCall(VIR_HOOK_DRIVER_QEMU, vm->def->name,
                    VIR_HOOK_QEMU_OP_RELEASE, VIR_HOOK_SUBOP_END,
                    NULL, xml, NULL);
    }

    virDomainObjRemoveTransientDef(vm);

 endjob:
    if (asyncJob != VIR_ASYNC_JOB_NONE)
        virDomainObjEndJob(vm);

 cleanup:
    virErrorRestore(&orig_err);
}


void
qemuProcessAutoDestroy(virDomainObj *dom,
                       virConnectPtr conn)
{
    qemuDomainObjPrivate *priv = dom->privateData;
    virQEMUDriver *driver = priv->driver;
    virObjectEvent *event = NULL;
    unsigned int stopFlags = 0;

    VIR_DEBUG("vm=%s, conn=%p", dom->def->name, conn);

    if (dom->job->asyncJob == VIR_ASYNC_JOB_MIGRATION_IN)
        stopFlags |= VIR_QEMU_PROCESS_STOP_MIGRATED;

    if (dom->job->asyncJob) {
        VIR_DEBUG("vm=%s has long-term job active, cancelling",
                  dom->def->name);
        qemuDomainObjDiscardAsyncJob(dom);
    }

    VIR_DEBUG("Killing domain");

    if (qemuProcessBeginStopJob(dom, VIR_JOB_DESTROY, true) < 0)
        return;

    qemuProcessStop(driver, dom, VIR_DOMAIN_SHUTOFF_DESTROYED,
                    VIR_ASYNC_JOB_NONE, stopFlags);

    virDomainAuditStop(dom, "destroyed");
    event = virDomainEventLifecycleNewFromObj(dom,
                                     VIR_DOMAIN_EVENT_STOPPED,
                                     VIR_DOMAIN_EVENT_STOPPED_DESTROYED);

    qemuDomainRemoveInactive(driver, dom, 0, false);

    virDomainObjEndJob(dom);

    virObjectEventStateQueue(driver->domainEventState, event);
}


void
qemuProcessRefreshDiskProps(virDomainDiskDef *disk,
                            struct qemuDomainDiskInfo *info)
{
    qemuDomainDiskPrivate *diskpriv = QEMU_DOMAIN_DISK_PRIVATE(disk);

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

    diskpriv->removable = info->removable;
    diskpriv->tray = info->tray;
}


int
qemuProcessRefreshDisks(virDomainObj *vm,
                        virDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    virQEMUDriver *driver = priv->driver;
    g_autoptr(GHashTable) table = NULL;
    size_t i;

    if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) == 0) {
        table = qemuMonitorGetBlockInfo(priv->mon);
        qemuDomainObjExitMonitor(vm);
    }

    if (!table)
        return -1;

    for (i = 0; i < vm->def->ndisks; i++) {
        virDomainDiskDef *disk = vm->def->disks[i];
        qemuDomainDiskPrivate *diskpriv = QEMU_DOMAIN_DISK_PRIVATE(disk);
        struct qemuDomainDiskInfo *info;
        const char *entryname = disk->info.alias;
        virDomainDiskTray old_tray_status = disk->tray_status;

        if (diskpriv->qomName)
            entryname = diskpriv->qomName;

        if (!(info = virHashLookup(table, entryname)))
            continue;

        qemuProcessRefreshDiskProps(disk, info);

        if (diskpriv->tray &&
            old_tray_status != disk->tray_status) {
            virDomainEventTrayChangeReason reason = VIR_DOMAIN_EVENT_TRAY_CHANGE_OPEN;
            virObjectEvent *event;

            if (disk->tray_status == VIR_DOMAIN_DISK_TRAY_CLOSED)
                reason = VIR_DOMAIN_EVENT_TRAY_CHANGE_CLOSE;

            event = virDomainEventTrayChangeNewFromObj(vm, disk->info.alias, reason);
            virObjectEventStateQueue(driver->domainEventState, event);
        }
    }

    return 0;
}


static int
qemuProcessRefreshCPUMigratability(virDomainObj *vm,
                                   virDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    virDomainDef *def = vm->def;
    const char *cpuQOMPath = qemuProcessGetVCPUQOMPath(vm);
    bool migratable;
    int rc;

    if (def->cpu->mode != VIR_CPU_MODE_HOST_PASSTHROUGH &&
        def->cpu->mode != VIR_CPU_MODE_MAXIMUM)
        return 0;

    /* If the cpu.migratable capability is present, the migratable attribute
     * is set correctly. */
    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_CPU_MIGRATABLE))
        return 0;

    if (!ARCH_IS_X86(def->os.arch))
        return 0;

    if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) < 0)
        return -1;

    rc = qemuMonitorGetCPUMigratable(priv->mon, cpuQOMPath, &migratable);

    qemuDomainObjExitMonitor(vm);
    if (rc < 0)
        return -1;

    if (rc == 1)
        migratable = false;

    /* Libvirt 6.5.0 would set migratable='off' for running domains even though
     * the actual default used by QEMU was 'on'. */
    if (def->cpu->migratable == VIR_TRISTATE_SWITCH_OFF && migratable) {
        VIR_DEBUG("Fixing CPU migratable attribute");
        def->cpu->migratable = VIR_TRISTATE_SWITCH_ON;
    }

    if (def->cpu->migratable == VIR_TRISTATE_SWITCH_ABSENT)
        def->cpu->migratable = virTristateSwitchFromBool(migratable);

    return 0;
}


static int
qemuProcessRefreshCPU(virQEMUDriver *driver,
                      virDomainObj *vm)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autoptr(virCPUDef) host = NULL;
    g_autoptr(virCPUDef) hostmig = NULL;
    g_autoptr(virCPUDef) cpu = NULL;

    if (!virQEMUCapsGuestIsNative(driver->hostarch, vm->def->os.arch))
        return 0;

    if (!vm->def->cpu)
        return 0;

    if (qemuProcessRefreshCPUMigratability(vm, VIR_ASYNC_JOB_NONE) < 0)
        return -1;

    if (!(host = virQEMUDriverGetHostCPU(driver))) {
        virResetLastError();
        return 0;
    }

    /* If the domain with a host-model CPU was started by an old libvirt
     * (< 2.3) which didn't replace the CPU with a custom one, let's do it now
     * since the rest of our code does not really expect a host-model CPU in a
     * running domain.
     */
    if (vm->def->cpu->mode == VIR_CPU_MODE_HOST_MODEL) {
        /*
         * PSeries domains are able to run with host-model CPU by design,
         * even on Libvirt newer than 2.3, never replacing host-model with
         * custom in the virCPUUpdate() call. It is not needed to call
         * virCPUUpdate() and qemuProcessUpdateCPU() in this case.
         */
        if (qemuDomainIsPSeries(vm->def))
            return 0;

        if (!(hostmig = virCPUCopyMigratable(host->arch, host)))
            return -1;

        cpu = virCPUDefCopyWithoutModel(hostmig);

        virCPUDefCopyModelFilter(cpu, hostmig, false, virQEMUCapsCPUFilterFeatures,
                                 &host->arch);

        if (virCPUUpdate(vm->def->os.arch, vm->def->cpu, cpu) < 0)
            return -1;

        if (qemuProcessUpdateCPU(vm, VIR_ASYNC_JOB_NONE) < 0)
            return -1;
    } else if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_QUERY_CPU_MODEL_EXPANSION)) {
        /* We only try to fix CPUs when the libvirt/QEMU combo used to start
         * the domain did not know about query-cpu-model-expansion in which
         * case the host-model is known to not contain features which QEMU
         * doesn't know about.
         */
        if (qemuDomainFixupCPUs(vm, &priv->origCPU) < 0)
            return -1;
    }

    return 0;
}


/**
 * qemuProcessReloadMachineTypes:
 *
 * Reload machine type information into the 'qemuCaps' object from the current
 * qemu.
 */
static int
qemuProcessReloadMachineTypes(virDomainObj *vm)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    bool fail = false;

    qemuDomainObjEnterMonitor(vm);

    if (virQEMUCapsInitQMPArch(priv->qemuCaps, priv->mon) < 0)
        fail = true;

    if (!fail &&
        virQEMUCapsProbeQMPMachineTypes(priv->qemuCaps,
                                        vm->def->virtType,
                                        priv->mon) < 0)
        fail = true;

    qemuDomainObjExitMonitor(vm);

    if (fail)
        return -1;

    return 0;
}


struct qemuProcessReconnectData {
    virQEMUDriver *driver;
    virDomainObj *obj;
    virIdentity *identity;
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
    virQEMUDriver *driver = data->driver;
    virDomainObj *obj = data->obj;
    qemuDomainObjPrivate *priv;
    g_auto(virDomainJobObj) oldjob = {
      .cb = NULL,
    };
    int state;
    int reason;
    g_autoptr(virQEMUDriverConfig) cfg = NULL;
    size_t i;
    unsigned int stopFlags = 0;
    bool jobStarted = false;
    bool tryMonReconn = false;

    virIdentitySetCurrent(data->identity);
    g_clear_object(&data->identity);
    VIR_FREE(data);

    cfg = virQEMUDriverGetConfig(driver);
    priv = obj->privateData;

    virDomainObjPreserveJob(obj->job, &oldjob);
    if (oldjob.asyncJob == VIR_ASYNC_JOB_MIGRATION_IN)
        stopFlags |= VIR_QEMU_PROCESS_STOP_MIGRATED;
    if (oldjob.asyncJob == VIR_ASYNC_JOB_BACKUP && priv->backup)
        priv->backup->apiFlags = oldjob.apiFlags;

    if (virDomainObjBeginJob(obj, VIR_JOB_MODIFY) < 0)
        goto error;
    jobStarted = true;

    /* XXX If we ever gonna change pid file pattern, come up with
     * some intelligence here to deal with old paths. */
    if (!(priv->pidfile = virPidFileBuildPath(cfg->stateDir, obj->def->name)))
        goto error;

    /* Restore the masterKey */
    if (qemuDomainMasterKeyReadFile(priv) < 0)
        goto error;

    if (qemuExtDevicesInitPaths(driver, obj->def) < 0)
        goto error;

    /* If we are connecting to a guest started by old libvirt there is no
     * allowReboot in status XML and we need to initialize it. */
    qemuProcessPrepareAllowReboot(obj);

    if (qemuHostdevUpdateActiveDomainDevices(driver, obj->def) < 0)
        goto error;

    if (qemuDomainObjStartWorker(obj) < 0)
        goto error;

    VIR_DEBUG("Reconnect monitor to def=%p name='%s'", obj, obj->def->name);

    tryMonReconn = true;

    /* XXX check PID liveliness & EXE path */
    if (qemuConnectMonitor(driver, obj, VIR_ASYNC_JOB_NONE, NULL, true) < 0)
        goto error;

    priv->machineName = qemuDomainGetMachineName(obj);
    if (!priv->machineName)
        goto error;

    if (virDomainCgroupConnectCgroup("qemu",
                                     obj,
                                     &priv->cgroup,
                                     cfg->cgroupControllers,
                                     priv->driver->privileged,
                                     priv->machineName) < 0)
        goto error;

    if (qemuDomainPerfRestart(obj) < 0)
        goto error;

    for (i = 0; i < obj->def->ndisks; i++) {
        virDomainDiskDef *disk = obj->def->disks[i];

        if (virDomainDiskTranslateSourcePool(disk) < 0)
            goto error;
    }

    for (i = 0; i < obj->def->ngraphics; i++) {
        if (qemuProcessGraphicsReservePorts(obj->def->graphics[i], true) < 0)
            goto error;
    }

    if (qemuProcessUpdateState(obj) < 0)
        goto error;

    state = virDomainObjGetState(obj, &reason);
    if (state == VIR_DOMAIN_SHUTOFF ||
        (state == VIR_DOMAIN_PAUSED &&
         reason == VIR_DOMAIN_PAUSED_STARTING_UP)) {
        VIR_DEBUG("Domain '%s' wasn't fully started yet, killing it",
                  obj->def->name);
        goto error;
    }

    if (!priv->qemuCaps) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("domain '%1$s' has no capabilities recorded"),
                       obj->def->name);
        goto error;
    }

    /* Reload and populate machine type data into 'qemuCaps' as that is not
     * serialized into the status XML. */
    if (qemuProcessReloadMachineTypes(obj) < 0)
        goto error;

    if (qemuDomainAssignAddresses(obj->def, priv->qemuCaps,
                                  driver, obj, false) < 0) {
        goto error;
    }

    /* In case the domain shutdown or fake reboot while we were not running,
     * we need to finish the shutdown or fake reboot process. And we need to
     * do it after we have virQEMUCaps filled in.
     */
    if (state == VIR_DOMAIN_SHUTDOWN ||
        (state == VIR_DOMAIN_PAUSED &&
         reason == VIR_DOMAIN_PAUSED_SHUTTING_DOWN) ||
        (priv->fakeReboot && state == VIR_DOMAIN_PAUSED &&
         reason == VIR_DOMAIN_PAUSED_USER)) {
        VIR_DEBUG("Finishing shutdown sequence for domain %s",
                  obj->def->name);
        qemuProcessShutdownOrReboot(obj);
        goto cleanup;
    }

    /* if domain requests security driver we haven't loaded, report error, but
     * do not kill the domain
     */
    ignore_value(qemuSecurityCheckAllLabel(driver->securityManager,
                                           obj->def));

    if (qemuDomainRefreshVcpuInfo(obj, VIR_ASYNC_JOB_NONE, true) < 0)
        goto error;

    qemuDomainVcpuPersistOrder(obj->def);

    if (qemuProcessRefreshCPU(driver, obj) < 0)
        goto error;

    if (qemuDomainUpdateMemoryDeviceInfo(obj, VIR_ASYNC_JOB_NONE) < 0)
        goto error;

    if (qemuProcessDetectIOThreadPIDs(obj, VIR_ASYNC_JOB_NONE) < 0)
        goto error;

    if (qemuSecurityReserveLabel(driver->securityManager, obj->def, obj->pid) < 0)
        goto error;

    if (qemuProcessRefreshRxFilters(obj, VIR_ASYNC_JOB_NONE) < 0)
        goto error;

    qemuProcessNotifyNets(obj->def);

    qemuProcessFiltersInstantiate(obj->def);

    if (qemuProcessRefreshDisks(obj, VIR_ASYNC_JOB_NONE) < 0)
        goto error;

    /* At this point we've already checked that the startup of the VM was
     * completed successfully before, thus that also implies that all transient
     * disk overlays were created. */
    for (i = 0; i < obj->def->ndisks; i++) {
        virDomainDiskDef *disk = obj->def->disks[i];

        if (disk->transient)
            QEMU_DOMAIN_DISK_PRIVATE(disk)->transientOverlayCreated = true;
    }

    if (qemuRefreshVirtioChannelState(driver, obj, VIR_ASYNC_JOB_NONE) < 0)
        goto error;

    /* If querying of guest's RTC failed, report error, but do not kill the domain. */
    qemuRefreshRTC(obj);

    if (qemuProcessRefreshBalloonState(obj, VIR_ASYNC_JOB_NONE) < 0)
        goto error;

    if (qemuProcessRecoverJob(driver, obj, &oldjob, &stopFlags) < 0)
        goto error;

    if (qemuBlockJobRefreshJobs(obj) < 0)
        goto error;

    if (qemuProcessUpdateDevices(driver, obj) < 0)
        goto error;

    if (qemuRefreshPRManagerState(obj) < 0)
        goto error;

    if (qemuProcessRefreshFdsetIndex(obj) < 0)
        goto error;

    if (qemuConnectAgent(driver, obj) < 0)
        goto error;

    for (i = 0; i < obj->def->nresctrls; i++) {
        size_t j = 0;

        if (virResctrlAllocDeterminePath(obj->def->resctrls[i]->alloc,
                                         priv->machineName) < 0)
            goto error;

        for (j = 0; j < obj->def->resctrls[i]->nmonitors; j++) {
            virDomainResctrlMonDef *mon = NULL;

            mon = obj->def->resctrls[i]->monitors[j];
            if (virResctrlMonitorDeterminePath(mon->instance,
                                               priv->machineName) < 0)
                goto error;
        }
    }

    for (i = 0; i < obj->def->ndisks; i++)
        if (qemuNbdkitStorageSourceManageProcess(obj->def->disks[i]->src, obj) < 0)
            goto error;

    if (obj->def->os.loader && obj->def->os.loader->nvram)
        if (qemuNbdkitStorageSourceManageProcess(obj->def->os.loader->nvram, obj) < 0)
            goto error;

    /* update domain state XML with possibly updated state in virDomainObj */
    if (virDomainObjSave(obj, driver->xmlopt, cfg->stateDir) < 0)
        goto error;

    /* Run an hook to allow admins to do some magic */
    if (virHookPresent(VIR_HOOK_DRIVER_QEMU)) {
        g_autofree char *xml = qemuDomainDefFormatXML(driver,
                                                          priv->qemuCaps,
                                                          obj->def, 0);
        int hookret;

        hookret = virHookCall(VIR_HOOK_DRIVER_QEMU, obj->def->name,
                              VIR_HOOK_QEMU_OP_RECONNECT, VIR_HOOK_SUBOP_BEGIN,
                              NULL, xml, NULL);

        /*
         * If the script raised an error abort the launch
         */
        if (hookret < 0)
            goto error;
    }

    if (g_atomic_int_add(&driver->nactive, 1) == 0 && driver->inhibitCallback)
        driver->inhibitCallback(true, driver->inhibitOpaque);

 cleanup:
    if (jobStarted)
        virDomainObjEndJob(obj);
    if (!virDomainObjIsActive(obj))
        qemuDomainRemoveInactive(driver, obj, 0, false);
    virDomainObjEndAPI(&obj);
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
            (priv->allowReboot == VIR_TRISTATE_BOOL_YES ||
             virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_SET_ACTION)))
            state = VIR_DOMAIN_SHUTOFF_CRASHED;
        else if (priv->mon)
            state = VIR_DOMAIN_SHUTOFF_DAEMON;
        else
            state = VIR_DOMAIN_SHUTOFF_UNKNOWN;

        /* If BeginJob failed, we jumped here without a job, let's hope another
         * thread didn't have a chance to start playing with the domain yet
         * (it's all we can do anyway).
         */
        qemuProcessStop(driver, obj, state, VIR_ASYNC_JOB_NONE, stopFlags);
    }
    goto cleanup;
}

static int
qemuProcessReconnectHelper(virDomainObj *obj,
                           void *opaque)
{
    virThread thread;
    struct qemuProcessReconnectData *src = opaque;
    struct qemuProcessReconnectData *data;
    g_autofree char *name = NULL;

    /* If the VM was inactive, we don't need to reconnect */
    if (obj->pid == 0)
        return 0;

    data = g_new0(struct qemuProcessReconnectData, 1);

    memcpy(data, src, sizeof(*data));
    data->obj = obj;
    data->identity = virIdentityGetCurrent();

    /* this lock and reference will be eventually transferred to the thread
     * that handles the reconnect */
    virObjectLock(obj);
    virObjectRef(obj);

    name = g_strdup_printf("init-%s", obj->def->name);

    if (virThreadCreateFull(&thread, false, qemuProcessReconnect,
                            name, false, data) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not create thread. QEMU initialization might be incomplete"));
        /* We can't spawn a thread and thus connect to monitor. Kill qemu.
         * It's safe to call qemuProcessStop without a job here since there
         * is no thread that could be doing anything else with the same domain
         * object.
         */
        qemuProcessStop(src->driver, obj, VIR_DOMAIN_SHUTOFF_FAILED,
                        VIR_ASYNC_JOB_NONE, 0);
        qemuDomainRemoveInactiveLocked(src->driver, obj);

        virDomainObjEndAPI(&obj);
        g_clear_object(&data->identity);
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
qemuProcessReconnectAll(virQEMUDriver *driver)
{
    struct qemuProcessReconnectData data = {.driver = driver};
    virDomainObjListForEach(driver->domains, true,
                            qemuProcessReconnectHelper, &data);
}


static void virQEMUCapsMonitorNotify(qemuMonitor *mon G_GNUC_UNUSED,
                                     virDomainObj *vm G_GNUC_UNUSED)
{
}

static qemuMonitorCallbacks callbacks = {
    .eofNotify = virQEMUCapsMonitorNotify,
    .errorNotify = virQEMUCapsMonitorNotify,
};


static void
qemuProcessQMPStop(qemuProcessQMP *proc)
{
    if (proc->mon) {
        virObjectUnlock(proc->mon);
        g_clear_pointer(&proc->mon, qemuMonitorClose);
    }

    if (proc->cmd) {
        virCommandAbort(proc->cmd);
        g_clear_pointer(&proc->cmd, virCommandFree);
    }

    if (proc->monpath)
        unlink(proc->monpath);

    virDomainObjEndAPI(&proc->vm);

    if (proc->pid != 0) {
        VIR_DEBUG("Killing QMP caps process %lld", (long long)proc->pid);
        virProcessKillPainfully(proc->pid, true);
        virResetLastError();
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
qemuProcessQMPFree(qemuProcessQMP *proc)
{
    if (!proc)
        return;

    qemuProcessQMPStop(proc);

    g_object_unref(proc->eventThread);

    g_free(proc->binary);
    g_free(proc->libDir);
    g_free(proc->uniqDir);
    g_free(proc->monpath);
    g_free(proc->monarg);
    g_free(proc->pidfile);
    g_free(proc->stdErr);
    g_free(proc);
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
qemuProcessQMP *
qemuProcessQMPNew(const char *binary,
                  const char *libDir,
                  uid_t runUid,
                  gid_t runGid,
                  bool forceTCG)
{
    g_autoptr(qemuProcessQMP) proc = NULL;
    const char *threadSuffix;
    g_autofree char *threadName = NULL;

    VIR_DEBUG("exec=%s, libDir=%s, runUid=%u, runGid=%u, forceTCG=%d",
              binary, libDir, runUid, runGid, forceTCG);

    proc = g_new0(qemuProcessQMP, 1);

    proc->binary = g_strdup(binary);
    proc->libDir = g_strdup(libDir);

    proc->runUid = runUid;
    proc->runGid = runGid;
    proc->forceTCG = forceTCG;

    threadSuffix = strrchr(binary, '-');
    if (threadSuffix)
        threadSuffix++;
    else
        threadSuffix = binary;
    threadName = g_strdup_printf("qmp-%s", threadSuffix);

    if (!(proc->eventThread = virEventThreadNew(threadName)))
        return NULL;

    return g_steal_pointer(&proc);
}


static int
qemuProcessQEMULabelUniqPath(qemuProcessQMP *proc)
{
    /* We cannot use the security driver here, but we should not need to. */
    if (chown(proc->uniqDir, proc->runUid, -1) < 0) {
        virReportSystemError(errno,
                             _("Cannot chown uniq path: %1$s"),
                             proc->uniqDir);
        return -1;
    }

    return 0;
}


static int
qemuProcessQMPInit(qemuProcessQMP *proc)
{
    g_autofree char *template = NULL;

    VIR_DEBUG("proc=%p, emulator=%s", proc, proc->binary);

    template = g_strdup_printf("%s/qmp-XXXXXX", proc->libDir);

    if (!(proc->uniqDir = g_mkdtemp(template))) {
        virReportSystemError(errno,
                             _("Failed to create unique directory with template '%1$s' for probing QEMU"),
                             template);
        return -1;
    }
    /* if g_mkdtemp succeeds, proc->uniqDir is now the owner of
     * the string. Set template to NULL to avoid freeing
     * the memory in this case */
    template = NULL;

    if (qemuProcessQEMULabelUniqPath(proc) < 0)
        return -1;

    proc->monpath = g_strdup_printf("%s/%s", proc->uniqDir, "qmp.monitor");

    proc->monarg = g_strdup_printf("unix:%s,server=on,wait=off", proc->monpath);

    /*
     * Normally we'd use runDir for pid files, but because we're using
     * -daemonize we need QEMU to be allowed to create them, rather
     * than libvirtd. So we're using libDir which QEMU can write to
     */
    proc->pidfile = g_strdup_printf("%s/%s", proc->uniqDir, "qmp.pid");

    return 0;
}


#if defined(__linux__)
# define hwaccel "kvm:tcg"
#elif defined(__APPLE__)
# define hwaccel "hvf:tcg"
#else
# define hwaccel "tcg"
#endif

static int
qemuProcessQMPLaunch(qemuProcessQMP *proc)
{
    const char *machine;
    int status = 0;
    int rc;

    if (proc->forceTCG)
        machine = "none,accel=tcg";
    else
        machine = "none,accel=" hwaccel;

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

    virCommandSetErrorBuffer(proc->cmd, &(proc->stdErr));

    if (virCommandRun(proc->cmd, &status) < 0)
        return -1;

    if (status != 0) {
        VIR_DEBUG("QEMU %s exited with status %d", proc->binary, status);
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to start QEMU binary %1$s for probing: %2$s"),
                       proc->binary,
                       proc->stdErr ? proc->stdErr : _("unknown error"));
        return -1;
    }

    if ((rc = virPidFileReadPath(proc->pidfile, &proc->pid)) < 0) {
        virReportSystemError(-rc, _("Failed to read pidfile %1$s"), proc->pidfile);
        return -1;
    }

    return 0;
}


int
qemuProcessQMPInitMonitor(qemuMonitor *mon)
{
    if (qemuMonitorSetCapabilities(mon) < 0) {
        VIR_DEBUG("Failed to set monitor capabilities %s",
                  virGetLastErrorMessage());
        return -1;
    }

    return 0;
}


static int
qemuProcessQMPConnectMonitor(qemuProcessQMP *proc)
{
    g_autoptr(virDomainXMLOption) xmlopt = NULL;
    virDomainChrSourceDef monConfig;

    VIR_DEBUG("proc=%p, emulator=%s, proc->pid=%lld",
              proc, proc->binary, (long long)proc->pid);

    monConfig.type = VIR_DOMAIN_CHR_TYPE_UNIX;
    monConfig.data.nix.path = proc->monpath;
    monConfig.data.nix.listen = false;

    if (!(xmlopt = virDomainXMLOptionNew(NULL, NULL, NULL, NULL, NULL, NULL)) ||
        !(proc->vm = virDomainObjNew(xmlopt)) ||
        !(proc->vm->def = virDomainDefNew(xmlopt)))
        return -1;

    proc->vm->pid = proc->pid;

    if (!(proc->mon = qemuMonitorOpen(proc->vm, &monConfig,
                                      virEventThreadGetContext(proc->eventThread),
                                      &callbacks)))
        return -1;

    virObjectLock(proc->mon);

    if (qemuProcessQMPInitMonitor(proc->mon) < 0)
        return -1;

    return 0;
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
 * Process error output (proc->stdErr) remains available in qemuProcessQMP
 * struct until qemuProcessQMPFree is called.
 */
int
qemuProcessQMPStart(qemuProcessQMP *proc)
{
    VIR_DEBUG("proc=%p, emulator=%s", proc, proc->binary);

    if (qemuProcessQMPInit(proc) < 0)
        return -1;

    if (qemuProcessQMPLaunch(proc) < 0)
        return -1;

    if (qemuProcessQMPConnectMonitor(proc) < 0)
        return -1;

    return 0;
}


void
qemuProcessHandleNbdkitExit(qemuNbdkitProcess *nbdkit,
                            virDomainObj *vm)
{
    virObjectLock(vm);
    VIR_DEBUG("nbdkit process %i died", nbdkit->pid);
    qemuProcessEventSubmit(vm, QEMU_PROCESS_EVENT_NBDKIT_EXITED, 0, 0, nbdkit);
    virObjectUnlock(vm);
}
