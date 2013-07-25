/*---------------------------------------------------------------------------*/
/*  Copyright (C) 2006-2013 Red Hat, Inc.
 *  Copyright (C) 2011-2013 SUSE LINUX Products GmbH, Nuernberg, Germany.
 *  Copyright (C) 2011 Univention GmbH.
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
 * Authors:
 *     Jim Fehlig <jfehlig@novell.com>
 *     Markus Groß <gross@univention.de>
 *     Daniel P. Berrange <berrange@redhat.com>
 */
/*---------------------------------------------------------------------------*/

#include <config.h>

#include <math.h>
#include <libxl.h>
#include <libxl_utils.h>
#include <fcntl.h>
#include <regex.h>

#include "internal.h"
#include "virlog.h"
#include "virerror.h"
#include "virconf.h"
#include "datatypes.h"
#include "virfile.h"
#include "viralloc.h"
#include "viruuid.h"
#include "vircommand.h"
#include "libxl_driver.h"
#include "libxl_conf.h"
#include "xen_xm.h"
#include "virtypedparam.h"
#include "viruri.h"
#include "virstring.h"
#include "virsysinfo.h"
#include "viraccessapicheck.h"

#define VIR_FROM_THIS VIR_FROM_LIBXL

#define LIBXL_DOM_REQ_POWEROFF 0
#define LIBXL_DOM_REQ_REBOOT   1
#define LIBXL_DOM_REQ_SUSPEND  2
#define LIBXL_DOM_REQ_CRASH    3
#define LIBXL_DOM_REQ_HALT     4

#define LIBXL_CONFIG_FORMAT_XM "xen-xm"

/* Number of Xen scheduler parameters */
#define XEN_SCHED_CREDIT_NPARAM   2

/* Append an event registration to the list of registrations */
#define LIBXL_EV_REG_APPEND(head, add)                 \
    do {                                               \
        libxlEventHookInfoPtr temp;                    \
        if (head) {                                    \
            temp = head;                               \
            while (temp->next)                         \
                temp = temp->next;                     \
            temp->next = add;                          \
        } else {                                       \
            head = add;                                \
        }                                              \
    } while (0)

/* Remove an event registration from the list of registrations */
#define LIBXL_EV_REG_REMOVE(head, del)                 \
    do {                                               \
        libxlEventHookInfoPtr temp;                    \
        if (head == del) {                             \
            head = head->next;                         \
        } else {                                       \
            temp = head;                               \
            while (temp->next && temp->next != del)    \
                temp = temp->next;                     \
            if (temp->next) {                          \
                temp->next = del->next;                \
            }                                          \
        }                                              \
    } while (0)

/* Object used to store info related to libxl event registrations */
struct _libxlEventHookInfo {
    libxlEventHookInfoPtr next;
    libxlDomainObjPrivatePtr priv;
    void *xl_priv;
    int id;
};

static virClassPtr libxlDomainObjPrivateClass;

static libxlDriverPrivatePtr libxl_driver = NULL;

/* Function declarations */
static int
libxlDomainManagedSaveLoad(virDomainObjPtr vm,
                           void *opaque);

static int
libxlVmStart(libxlDriverPrivatePtr driver, virDomainObjPtr vm,
             bool start_paused, int restore_fd);

static void
libxlDomainObjPrivateDispose(void *obj);

/* Function definitions */
static int
libxlDomainObjPrivateOnceInit(void)
{
    if (!(libxlDomainObjPrivateClass = virClassNew(virClassForObjectLockable(),
                                                   "libxlDomainObjPrivate",
                                                   sizeof(libxlDomainObjPrivate),
                                                   libxlDomainObjPrivateDispose)))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(libxlDomainObjPrivate)

static void
libxlDriverLock(libxlDriverPrivatePtr driver)
{
    virMutexLock(&driver->lock);
}

static void
libxlDriverUnlock(libxlDriverPrivatePtr driver)
{
    virMutexUnlock(&driver->lock);
}

static void
libxlEventHookInfoFree(void *obj)
{
    libxlEventHookInfoPtr info = obj;

    /* Drop reference on libxlDomainObjPrivate */
    virObjectUnref(info->priv);
    VIR_FREE(info);
}

static void
libxlFDEventCallback(int watch ATTRIBUTE_UNUSED,
                     int fd,
                     int vir_events,
                     void *fd_info)
{
    libxlEventHookInfoPtr info = fd_info;
    int events = 0;

    virObjectLock(info->priv);
    if (vir_events & VIR_EVENT_HANDLE_READABLE)
        events |= POLLIN;
    if (vir_events & VIR_EVENT_HANDLE_WRITABLE)
        events |= POLLOUT;
    if (vir_events & VIR_EVENT_HANDLE_ERROR)
        events |= POLLERR;
    if (vir_events & VIR_EVENT_HANDLE_HANGUP)
        events |= POLLHUP;

    virObjectUnlock(info->priv);
    libxl_osevent_occurred_fd(info->priv->ctx, info->xl_priv, fd, 0, events);
}

static int
libxlFDRegisterEventHook(void *priv, int fd, void **hndp,
                         short events, void *xl_priv)
{
    int vir_events = VIR_EVENT_HANDLE_ERROR;
    libxlEventHookInfoPtr info;

    if (VIR_ALLOC(info) < 0)
        return -1;

    info->priv = priv;
    /*
     * Take a reference on the domain object.  Reference is dropped in
     * libxlEventHookInfoFree, ensuring the domain object outlives the fd
     * event objects.
     */
    virObjectRef(info->priv);
    info->xl_priv = xl_priv;

    if (events & POLLIN)
        vir_events |= VIR_EVENT_HANDLE_READABLE;
    if (events & POLLOUT)
        vir_events |= VIR_EVENT_HANDLE_WRITABLE;

    info->id = virEventAddHandle(fd, vir_events, libxlFDEventCallback,
                                 info, libxlEventHookInfoFree);
    if (info->id < 0) {
        virObjectUnref(info->priv);
        VIR_FREE(info);
        return -1;
    }

    *hndp = info;

    return 0;
}

static int
libxlFDModifyEventHook(void *priv ATTRIBUTE_UNUSED,
                       int fd ATTRIBUTE_UNUSED,
                       void **hndp,
                       short events)
{
    libxlEventHookInfoPtr info = *hndp;
    int vir_events = VIR_EVENT_HANDLE_ERROR;

    virObjectLock(info->priv);
    if (events & POLLIN)
        vir_events |= VIR_EVENT_HANDLE_READABLE;
    if (events & POLLOUT)
        vir_events |= VIR_EVENT_HANDLE_WRITABLE;

    virEventUpdateHandle(info->id, vir_events);
    virObjectUnlock(info->priv);

    return 0;
}

static void
libxlFDDeregisterEventHook(void *priv ATTRIBUTE_UNUSED,
                           int fd ATTRIBUTE_UNUSED,
                           void *hnd)
{
    libxlEventHookInfoPtr info = hnd;
    libxlDomainObjPrivatePtr p = info->priv;

    virObjectLock(p);
    virEventRemoveHandle(info->id);
    virObjectUnlock(p);
}

static void
libxlTimerCallback(int timer ATTRIBUTE_UNUSED, void *timer_info)
{
    libxlEventHookInfoPtr info = timer_info;
    libxlDomainObjPrivatePtr p = info->priv;

    virObjectLock(p);
    /*
     * libxl expects the event to be deregistered when calling
     * libxl_osevent_occurred_timeout, but we dont want the event info
     * destroyed.  Disable the timeout and only remove it after returning
     * from libxl.
     */
    virEventUpdateTimeout(info->id, -1);
    virObjectUnlock(p);
    libxl_osevent_occurred_timeout(p->ctx, info->xl_priv);
    virObjectLock(p);
    /*
     * Timeout could have been freed while the lock was dropped.
     * Only remove it from the list if it still exists.
     */
    if (virEventRemoveTimeout(info->id) == 0)
        LIBXL_EV_REG_REMOVE(p->timerRegistrations, info);
    virObjectUnlock(p);
}

static int
libxlTimeoutRegisterEventHook(void *priv,
                              void **hndp,
                              struct timeval abs_t,
                              void *xl_priv)
{
    libxlEventHookInfoPtr info;
    struct timeval now;
    struct timeval res;
    static struct timeval zero;
    int timeout;

    if (VIR_ALLOC(info) < 0)
        return -1;

    info->priv = priv;
    /*
     * Also take a reference on the domain object.  Reference is dropped in
     * libxlEventHookInfoFree, ensuring the domain object outlives the timeout
     * event objects.
     */
    virObjectRef(info->priv);
    info->xl_priv = xl_priv;

    gettimeofday(&now, NULL);
    timersub(&abs_t, &now, &res);
    /* Ensure timeout is not overflowed */
    if (timercmp(&res, &zero, <)) {
        timeout = 0;
    } else if (res.tv_sec > INT_MAX / 1000) {
        timeout = INT_MAX;
    } else {
        timeout = res.tv_sec * 1000 + (res.tv_usec + 999) / 1000;
    }
    info->id = virEventAddTimeout(timeout, libxlTimerCallback,
                                  info, libxlEventHookInfoFree);
    if (info->id < 0) {
        virObjectUnref(info->priv);
        VIR_FREE(info);
        return -1;
    }

    virObjectLock(info->priv);
    LIBXL_EV_REG_APPEND(info->priv->timerRegistrations, info);
    virObjectUnlock(info->priv);
    *hndp = info;

    return 0;
}

/*
 * Note:  There are two changes wrt timeouts starting with xen-unstable
 * changeset 26469:
 *
 * 1. Timeout modify callbacks will only be invoked with an abs_t of {0,0},
 * i.e. make the timeout fire immediately.  Prior to this commit, timeout
 * modify callbacks were never invoked.
 *
 * 2. Timeout deregister hooks will no longer be called.
 */
static int
libxlTimeoutModifyEventHook(void *priv ATTRIBUTE_UNUSED,
                            void **hndp,
                            struct timeval abs_t ATTRIBUTE_UNUSED)
{
    libxlEventHookInfoPtr info = *hndp;

    virObjectLock(info->priv);
    /* Make the timeout fire */
    virEventUpdateTimeout(info->id, 0);
    virObjectUnlock(info->priv);

    return 0;
}

static void
libxlTimeoutDeregisterEventHook(void *priv ATTRIBUTE_UNUSED,
                                void *hnd)
{
    libxlEventHookInfoPtr info = hnd;
    libxlDomainObjPrivatePtr p = info->priv;

    virObjectLock(p);
    /*
     * Only remove the timeout from the list if removal from the
     * event loop is successful.
     */
    if (virEventRemoveTimeout(info->id) == 0)
        LIBXL_EV_REG_REMOVE(p->timerRegistrations, info);
    virObjectUnlock(p);
}

static void
libxlRegisteredTimeoutsCleanup(libxlDomainObjPrivatePtr priv)
{
    libxlEventHookInfoPtr info;

    virObjectLock(priv);
    info = priv->timerRegistrations;
    while (info) {
        /*
         * libxl expects the event to be deregistered when calling
         * libxl_osevent_occurred_timeout, but we dont want the event info
         * destroyed.  Disable the timeout and only remove it after returning
         * from libxl.
         */
        virEventUpdateTimeout(info->id, -1);
        libxl_osevent_occurred_timeout(priv->ctx, info->xl_priv);
        virEventRemoveTimeout(info->id);
        info = info->next;
    }
    priv->timerRegistrations = NULL;
    virObjectUnlock(priv);
}

static const libxl_osevent_hooks libxl_event_callbacks = {
    .fd_register = libxlFDRegisterEventHook,
    .fd_modify = libxlFDModifyEventHook,
    .fd_deregister = libxlFDDeregisterEventHook,
    .timeout_register = libxlTimeoutRegisterEventHook,
    .timeout_modify = libxlTimeoutModifyEventHook,
    .timeout_deregister = libxlTimeoutDeregisterEventHook,
};

static void *
libxlDomainObjPrivateAlloc(void)
{
    libxlDomainObjPrivatePtr priv;

    if (libxlDomainObjPrivateInitialize() < 0)
        return NULL;

    if (!(priv = virObjectLockableNew(libxlDomainObjPrivateClass)))
        return NULL;

    if (libxl_ctx_alloc(&priv->ctx, LIBXL_VERSION, 0, libxl_driver->logger)) {
        VIR_ERROR(_("Failed libxl context initialization"));
        virObjectUnref(priv);
        return NULL;
    }

    libxl_osevent_register_hooks(priv->ctx, &libxl_event_callbacks, priv);

    return priv;
}

static void
libxlDomainObjPrivateDispose(void *obj)
{
    libxlDomainObjPrivatePtr priv = obj;

    if (priv->deathW)
        libxl_evdisable_domain_death(priv->ctx, priv->deathW);

    libxl_ctx_free(priv->ctx);
}

static void
libxlDomainObjPrivateFree(void *data)
{
    libxlDomainObjPrivatePtr priv = data;

    if (priv->deathW) {
        libxl_evdisable_domain_death(priv->ctx, priv->deathW);
        priv->deathW = NULL;
    }

    virObjectUnref(priv);
}

virDomainXMLPrivateDataCallbacks libxlDomainXMLPrivateDataCallbacks = {
    .alloc = libxlDomainObjPrivateAlloc,
    .free = libxlDomainObjPrivateFree,
};


static int
libxlDomainDeviceDefPostParse(virDomainDeviceDefPtr dev,
                              virDomainDefPtr def,
                              virCapsPtr caps ATTRIBUTE_UNUSED,
                              void *opaque ATTRIBUTE_UNUSED)
{
    if (dev->type == VIR_DOMAIN_DEVICE_CHR &&
        dev->data.chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE &&
        dev->data.chr->targetType == VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_NONE &&
        STRNEQ(def->os.type, "hvm"))
        dev->data.chr->targetType = VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_XEN;

    return 0;
}


virDomainDefParserConfig libxlDomainDefParserConfig = {
    .macPrefix = { 0x00, 0x16, 0x3e },
    .devicesPostParseCallback = libxlDomainDeviceDefPostParse,
};


/* driver must be locked before calling */
static void
libxlDomainEventQueue(libxlDriverPrivatePtr driver, virDomainEventPtr event)
{
    virDomainEventStateQueue(driver->domainEventState, event);
}

static int
libxlAutostartDomain(virDomainObjPtr vm,
                     void *opaque)
{
    libxlDriverPrivatePtr driver = opaque;
    virErrorPtr err;
    int ret = -1;

    virObjectLock(vm);
    virResetLastError();

    if (vm->autostart && !virDomainObjIsActive(vm) &&
        libxlVmStart(driver, vm, false, -1) < 0) {
        err = virGetLastError();
        VIR_ERROR(_("Failed to autostart VM '%s': %s"),
                  vm->def->name,
                  err ? err->message : _("unknown error"));
        goto cleanup;
    }

    ret = 0;
cleanup:
    virObjectUnlock(vm);
    return ret;
}

static int
libxlDoNodeGetInfo(libxlDriverPrivatePtr driver, virNodeInfoPtr info)
{
    libxl_physinfo phy_info;
    const libxl_version_info* ver_info;
    virArch hostarch = virArchFromHost();

    if (libxl_get_physinfo(driver->ctx, &phy_info)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("libxl_get_physinfo_info failed"));
        return -1;
    }

    if ((ver_info = libxl_get_version_info(driver->ctx)) == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("libxl_get_version_info failed"));
        return -1;
    }

    if (virStrcpyStatic(info->model, virArchToString(hostarch)) == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("machine type %s too big for destination"),
                       virArchToString(hostarch));
        return -1;
    }

    info->memory = phy_info.total_pages * (ver_info->pagesize / 1024);
    info->cpus = phy_info.nr_cpus;
    info->nodes = phy_info.nr_nodes;
    info->cores = phy_info.cores_per_socket;
    info->threads = phy_info.threads_per_core;
    info->sockets = 1;
    info->mhz = phy_info.cpu_khz / 1000;
    return 0;
}

static char *
libxlDomainManagedSavePath(libxlDriverPrivatePtr driver, virDomainObjPtr vm) {
    char *ret;

    ignore_value(virAsprintf(&ret, "%s/%s.save", driver->saveDir, vm->def->name));
    return ret;
}

/* This internal function expects the driver lock to already be held on
 * entry. */
static int ATTRIBUTE_NONNULL(3) ATTRIBUTE_NONNULL(4)
libxlSaveImageOpen(libxlDriverPrivatePtr driver, const char *from,
                     virDomainDefPtr *ret_def, libxlSavefileHeaderPtr ret_hdr)
{
    int fd;
    virDomainDefPtr def = NULL;
    libxlSavefileHeader hdr;
    char *xml = NULL;

    if ((fd = virFileOpenAs(from, O_RDONLY, 0, -1, -1, 0)) < 0) {
        virReportSystemError(-fd,
                             _("Failed to open domain image file '%s'"), from);
        goto error;
    }

    if (saferead(fd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       "%s", _("failed to read libxl header"));
        goto error;
    }

    if (memcmp(hdr.magic, LIBXL_SAVE_MAGIC, sizeof(hdr.magic))) {
        virReportError(VIR_ERR_INVALID_ARG, "%s", _("image magic is incorrect"));
        goto error;
    }

    if (hdr.version > LIBXL_SAVE_VERSION) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("image version is not supported (%d > %d)"),
                       hdr.version, LIBXL_SAVE_VERSION);
        goto error;
    }

    if (hdr.xmlLen <= 0) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("invalid XML length: %d"), hdr.xmlLen);
        goto error;
    }

    if (VIR_ALLOC_N(xml, hdr.xmlLen) < 0)
        goto error;

    if (saferead(fd, xml, hdr.xmlLen) != hdr.xmlLen) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s", _("failed to read XML"));
        goto error;
    }

    if (!(def = virDomainDefParseString(xml, driver->caps, driver->xmlopt,
                                        1 << VIR_DOMAIN_VIRT_XEN,
                                        VIR_DOMAIN_XML_INACTIVE)))
        goto error;

    VIR_FREE(xml);

    *ret_def = def;
    *ret_hdr = hdr;

    return fd;

error:
    VIR_FREE(xml);
    virDomainDefFree(def);
    VIR_FORCE_CLOSE(fd);
    return -1;
}

/*
 * Cleanup function for domain that has reached shutoff state.
 *
 * virDomainObjPtr should be locked on invocation
 */
static void
libxlVmCleanup(libxlDriverPrivatePtr driver,
               virDomainObjPtr vm,
               virDomainShutoffReason reason)
{
    libxlDomainObjPrivatePtr priv = vm->privateData;
    int vnc_port;
    char *file;
    size_t i;

    if (priv->deathW) {
        libxl_evdisable_domain_death(priv->ctx, priv->deathW);
        priv->deathW = NULL;
    }

    if (vm->persistent) {
        vm->def->id = -1;
        virDomainObjSetState(vm, VIR_DOMAIN_SHUTOFF, reason);
    }

    driver->nactive--;
    if (!driver->nactive && driver->inhibitCallback)
        driver->inhibitCallback(false, driver->inhibitOpaque);

    if ((vm->def->ngraphics == 1) &&
        vm->def->graphics[0]->type == VIR_DOMAIN_GRAPHICS_TYPE_VNC &&
        vm->def->graphics[0]->data.vnc.autoport) {
        vnc_port = vm->def->graphics[0]->data.vnc.port;
        if (vnc_port >= LIBXL_VNC_PORT_MIN) {
            if (virPortAllocatorRelease(driver->reservedVNCPorts,
                                        vnc_port) < 0)
                VIR_DEBUG("Could not mark port %d as unused", vnc_port);
        }
    }

    /* Remove any cputune settings */
    if (vm->def->cputune.nvcpupin) {
        for (i = 0; i < vm->def->cputune.nvcpupin; ++i) {
            virBitmapFree(vm->def->cputune.vcpupin[i]->cpumask);
            VIR_FREE(vm->def->cputune.vcpupin[i]);
        }
        VIR_FREE(vm->def->cputune.vcpupin);
        vm->def->cputune.nvcpupin = 0;
    }

    if (virAsprintf(&file, "%s/%s.xml", driver->stateDir, vm->def->name) > 0) {
        if (unlink(file) < 0 && errno != ENOENT && errno != ENOTDIR)
            VIR_DEBUG("Failed to remove domain XML for %s", vm->def->name);
        VIR_FREE(file);
    }

    if (vm->newDef) {
        virDomainDefFree(vm->def);
        vm->def = vm->newDef;
        vm->def->id = -1;
        vm->newDef = NULL;
    }

    libxlRegisteredTimeoutsCleanup(priv);
}

/*
 * Reap a domain from libxenlight.
 *
 * virDomainObjPtr should be locked on invocation
 */
static int
libxlVmReap(libxlDriverPrivatePtr driver,
            virDomainObjPtr vm,
            virDomainShutoffReason reason)
{
    libxlDomainObjPrivatePtr priv = vm->privateData;

    if (libxl_domain_destroy(priv->ctx, vm->def->id, NULL) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to cleanup domain %d"), vm->def->id);
        return -1;
    }

    libxlVmCleanup(driver, vm, reason);
    return 0;
}

/*
 * Handle previously registered event notification from libxenlight.
 *
 * Note: Xen 4.3 removed the const from the event handler signature.
 * Detect which signature to use based on
 * LIBXL_HAVE_NONCONST_EVENT_OCCURS_EVENT_ARG.
 */

#ifdef LIBXL_HAVE_NONCONST_EVENT_OCCURS_EVENT_ARG
# define VIR_LIBXL_EVENT_CONST /* empty */
#else
# define VIR_LIBXL_EVENT_CONST const
#endif

static void
libxlEventHandler(void *data, VIR_LIBXL_EVENT_CONST libxl_event *event)
{
    libxlDriverPrivatePtr driver = libxl_driver;
    libxlDomainObjPrivatePtr priv = ((virDomainObjPtr)data)->privateData;
    virDomainObjPtr vm = NULL;
    virDomainEventPtr dom_event = NULL;
    libxl_shutdown_reason xl_reason = event->u.domain_shutdown.shutdown_reason;

    if (event->type == LIBXL_EVENT_TYPE_DOMAIN_SHUTDOWN) {
        virDomainShutoffReason reason;

        /*
         * Similar to the xl implementation, ignore SUSPEND.  Any actions needed
         * after calling libxl_domain_suspend() are handled by it's callers.
         */
        if (xl_reason == LIBXL_SHUTDOWN_REASON_SUSPEND)
            goto cleanup;

        libxlDriverLock(driver);
        vm = virDomainObjListFindByID(driver->domains, event->domid);
        libxlDriverUnlock(driver);

        if (!vm)
            goto cleanup;

        switch (xl_reason) {
            case LIBXL_SHUTDOWN_REASON_POWEROFF:
            case LIBXL_SHUTDOWN_REASON_CRASH:
                if (xl_reason == LIBXL_SHUTDOWN_REASON_CRASH) {
                    dom_event = virDomainEventNewFromObj(vm,
                                              VIR_DOMAIN_EVENT_STOPPED,
                                              VIR_DOMAIN_EVENT_STOPPED_CRASHED);
                    reason = VIR_DOMAIN_SHUTOFF_CRASHED;
                } else {
                    reason = VIR_DOMAIN_SHUTOFF_SHUTDOWN;
                }
                libxlVmReap(driver, vm, reason);
                if (!vm->persistent) {
                    virDomainObjListRemove(driver->domains, vm);
                    vm = NULL;
                }
                break;
            case LIBXL_SHUTDOWN_REASON_REBOOT:
                libxlVmReap(driver, vm, VIR_DOMAIN_SHUTOFF_SHUTDOWN);
                libxlVmStart(driver, vm, 0, -1);
                break;
            default:
                VIR_INFO("Unhandled shutdown_reason %d", xl_reason);
                break;
        }
    }

cleanup:
    if (vm)
        virObjectUnlock(vm);
    if (dom_event) {
        libxlDriverLock(driver);
        libxlDomainEventQueue(driver, dom_event);
        libxlDriverUnlock(driver);
    }
    /* Cast away any const */
    libxl_event_free(priv->ctx, (libxl_event *)event);
}

static const struct libxl_event_hooks ev_hooks = {
    .event_occurs_mask = LIBXL_EVENTMASK_ALL,
    .event_occurs = libxlEventHandler,
    .disaster = NULL,
};

/*
 * Register domain events with libxenlight and insert event handles
 * in libvirt's event loop.
 */
static int
libxlCreateDomEvents(virDomainObjPtr vm)
{
    libxlDomainObjPrivatePtr priv = vm->privateData;

    libxl_event_register_callbacks(priv->ctx, &ev_hooks, vm);

    if (libxl_evenable_domain_death(priv->ctx, vm->def->id, 0, &priv->deathW))
        goto error;

    return 0;

error:
    if (priv->deathW) {
        libxl_evdisable_domain_death(priv->ctx, priv->deathW);
        priv->deathW = NULL;
    }
    return -1;
}

static int
libxlDomainSetVcpuAffinities(libxlDriverPrivatePtr driver, virDomainObjPtr vm)
{
    libxlDomainObjPrivatePtr priv = vm->privateData;
    virDomainDefPtr def = vm->def;
    libxl_bitmap map;
    uint8_t *cpumask = NULL;
    uint8_t *cpumap = NULL;
    virNodeInfo nodeinfo;
    size_t cpumaplen;
    int vcpu;
    size_t i;
    int ret = -1;

    if (libxlDoNodeGetInfo(driver, &nodeinfo) < 0)
        goto cleanup;

    cpumaplen = VIR_CPU_MAPLEN(VIR_NODEINFO_MAXCPUS(nodeinfo));

    for (vcpu = 0; vcpu < def->cputune.nvcpupin; ++vcpu) {
        if (vcpu != def->cputune.vcpupin[vcpu]->vcpuid)
            continue;

        if (VIR_ALLOC_N(cpumap, cpumaplen) < 0)
            goto cleanup;

        cpumask = (uint8_t*) def->cputune.vcpupin[vcpu]->cpumask;

        for (i = 0; i < VIR_DOMAIN_CPUMASK_LEN; ++i) {
            if (cpumask[i])
                VIR_USE_CPU(cpumap, i);
        }

        map.size = cpumaplen;
        map.map = cpumap;

        if (libxl_set_vcpuaffinity(priv->ctx, def->id, vcpu, &map) != 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to pin vcpu '%d' with libxenlight"), vcpu);
            goto cleanup;
        }

        VIR_FREE(cpumap);
    }

    ret = 0;

cleanup:
    VIR_FREE(cpumap);
    return ret;
}

static int
libxlFreeMem(libxlDomainObjPrivatePtr priv, libxl_domain_config *d_config)
{
    uint32_t needed_mem;
    uint32_t free_mem;
    size_t i;
    int ret = -1;
    int tries = 3;
    int wait_secs = 10;

    if ((ret = libxl_domain_need_memory(priv->ctx, &d_config->b_info,
                                        &needed_mem)) >= 0) {
        for (i = 0; i < tries; ++i) {
            if ((ret = libxl_get_free_memory(priv->ctx, &free_mem)) < 0)
                break;

            if (free_mem >= needed_mem) {
                ret = 0;
                break;
            }

            if ((ret = libxl_set_memory_target(priv->ctx, 0,
                                               free_mem - needed_mem,
                                               /* relative */ 1, 0)) < 0)
                break;

            ret = libxl_wait_for_free_memory(priv->ctx, 0, needed_mem,
                                             wait_secs);
            if (ret == 0 || ret != ERROR_NOMEM)
                break;

            if ((ret = libxl_wait_for_memory_target(priv->ctx, 0, 1)) < 0)
                break;
        }
    }

    return ret;
}

/*
 * Start a domain through libxenlight.
 *
 * virDomainObjPtr should be locked on invocation
 */
static int
libxlVmStart(libxlDriverPrivatePtr driver, virDomainObjPtr vm,
             bool start_paused, int restore_fd)
{
    libxl_domain_config d_config;
    virDomainDefPtr def = NULL;
    virDomainEventPtr event = NULL;
    libxlSavefileHeader hdr;
    int ret;
    uint32_t domid = 0;
    char *dom_xml = NULL;
    char *managed_save_path = NULL;
    int managed_save_fd = -1;
    libxlDomainObjPrivatePtr priv = vm->privateData;

    /* If there is a managed saved state restore it instead of starting
     * from scratch. The old state is removed once the restoring succeeded. */
    if (restore_fd < 0) {
        managed_save_path = libxlDomainManagedSavePath(driver, vm);
        if (managed_save_path == NULL)
            goto error;

        if (virFileExists(managed_save_path)) {

            managed_save_fd = libxlSaveImageOpen(driver, managed_save_path,
                                                 &def, &hdr);
            if (managed_save_fd < 0)
                goto error;

            restore_fd = managed_save_fd;

            if (STRNEQ(vm->def->name, def->name) ||
                memcmp(vm->def->uuid, def->uuid, VIR_UUID_BUFLEN)) {
                char vm_uuidstr[VIR_UUID_STRING_BUFLEN];
                char def_uuidstr[VIR_UUID_STRING_BUFLEN];
                virUUIDFormat(vm->def->uuid, vm_uuidstr);
                virUUIDFormat(def->uuid, def_uuidstr);
                virReportError(VIR_ERR_OPERATION_FAILED,
                               _("cannot restore domain '%s' uuid %s from a file"
                                 " which belongs to domain '%s' uuid %s"),
                               vm->def->name, vm_uuidstr, def->name, def_uuidstr);
                goto error;
            }

            virDomainObjAssignDef(vm, def, true, NULL);
            def = NULL;

            if (unlink(managed_save_path) < 0) {
                VIR_WARN("Failed to remove the managed state %s",
                         managed_save_path);
            }
            vm->hasManagedSave = false;
        }
        VIR_FREE(managed_save_path);
    }

    libxl_domain_config_init(&d_config);

    if (libxlBuildDomainConfig(driver, vm, &d_config) < 0)
        goto error;

    if (driver->autoballoon && libxlFreeMem(priv, &d_config) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("libxenlight failed to get free memory for domain '%s'"),
                       d_config.c_info.name);
        goto error;
    }

    /* use as synchronous operations => ao_how = NULL and no intermediate reports => ao_progress = NULL */

    if (restore_fd < 0)
        ret = libxl_domain_create_new(priv->ctx, &d_config,
                                      &domid, NULL, NULL);
    else
        ret = libxl_domain_create_restore(priv->ctx, &d_config, &domid,
                                          restore_fd, NULL, NULL);

    if (ret) {
        if (restore_fd < 0)
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("libxenlight failed to create new domain '%s'"),
                           d_config.c_info.name);
        else
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("libxenlight failed to restore domain '%s'"),
                           d_config.c_info.name);
        goto error;
    }

    vm->def->id = domid;
    if ((dom_xml = virDomainDefFormat(vm->def, 0)) == NULL)
        goto error;

    if (libxl_userdata_store(priv->ctx, domid, "libvirt-xml",
                             (uint8_t *)dom_xml, strlen(dom_xml) + 1)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("libxenlight failed to store userdata"));
        goto error;
    }

    if (libxlCreateDomEvents(vm) < 0)
        goto error;

    if (libxlDomainSetVcpuAffinities(driver, vm) < 0)
        goto error;

    if (!start_paused) {
        libxl_domain_unpause(priv->ctx, domid);
        virDomainObjSetState(vm, VIR_DOMAIN_RUNNING, VIR_DOMAIN_RUNNING_BOOTED);
    } else {
        virDomainObjSetState(vm, VIR_DOMAIN_PAUSED, VIR_DOMAIN_PAUSED_USER);
    }


    if (virDomainSaveStatus(driver->xmlopt, driver->stateDir, vm) < 0)
        goto error;

    if (!driver->nactive && driver->inhibitCallback)
        driver->inhibitCallback(true, driver->inhibitOpaque);
    driver->nactive++;

    event = virDomainEventNewFromObj(vm, VIR_DOMAIN_EVENT_STARTED,
                                     restore_fd < 0 ?
                                         VIR_DOMAIN_EVENT_STARTED_BOOTED :
                                         VIR_DOMAIN_EVENT_STARTED_RESTORED);
    if (event)
        libxlDomainEventQueue(driver, event);

    libxl_domain_config_dispose(&d_config);
    VIR_FREE(dom_xml);
    VIR_FORCE_CLOSE(managed_save_fd);
    return 0;

error:
    if (domid > 0) {
        libxl_domain_destroy(priv->ctx, domid, NULL);
        vm->def->id = -1;
        virDomainObjSetState(vm, VIR_DOMAIN_SHUTOFF, VIR_DOMAIN_SHUTOFF_FAILED);
    }
    libxl_domain_config_dispose(&d_config);
    VIR_FREE(dom_xml);
    VIR_FREE(managed_save_path);
    virDomainDefFree(def);
    VIR_FORCE_CLOSE(managed_save_fd);
    return -1;
}


/*
 * Reconnect to running domains that were previously started/created
 * with libxenlight driver.
 */
static int
libxlReconnectDomain(virDomainObjPtr vm,
                     void *opaque)
{
    libxlDriverPrivatePtr driver = opaque;
    int rc;
    libxl_dominfo d_info;
    int len;
    uint8_t *data = NULL;

    virObjectLock(vm);

    /* Does domain still exist? */
    rc = libxl_domain_info(driver->ctx, &d_info, vm->def->id);
    if (rc == ERROR_INVAL) {
        goto out;
    } else if (rc != 0) {
        VIR_DEBUG("libxl_domain_info failed (code %d), ignoring domain %d",
                  rc, vm->def->id);
        goto out;
    }

    /* Is this a domain that was under libvirt control? */
    if (libxl_userdata_retrieve(driver->ctx, vm->def->id,
                                "libvirt-xml", &data, &len)) {
        VIR_DEBUG("libxl_userdata_retrieve failed, ignoring domain %d", vm->def->id);
        goto out;
    }

    /* Update domid in case it changed (e.g. reboot) while we were gone? */
    vm->def->id = d_info.domid;
    virDomainObjSetState(vm, VIR_DOMAIN_RUNNING, VIR_DOMAIN_RUNNING_UNKNOWN);

    if (!driver->nactive && driver->inhibitCallback)
        driver->inhibitCallback(true, driver->inhibitOpaque);
    driver->nactive++;

    /* Recreate domain death et. al. events */
    libxlCreateDomEvents(vm);
    virObjectUnlock(vm);
    return 0;

out:
    libxlVmCleanup(driver, vm, VIR_DOMAIN_SHUTOFF_UNKNOWN);
    if (!vm->persistent)
        virDomainObjListRemoveLocked(driver->domains, vm);
    else
        virObjectUnlock(vm);

    return -1;
}

static void
libxlReconnectDomains(libxlDriverPrivatePtr driver)
{
    virDomainObjListForEach(driver->domains, libxlReconnectDomain, driver);
}

static int
libxlStateCleanup(void)
{
    if (!libxl_driver)
        return -1;

    libxlDriverLock(libxl_driver);
    virObjectUnref(libxl_driver->caps);
    virObjectUnref(libxl_driver->xmlopt);
    virObjectUnref(libxl_driver->domains);
    libxl_ctx_free(libxl_driver->ctx);
    xtl_logger_destroy(libxl_driver->logger);
    if (libxl_driver->logger_file)
        VIR_FORCE_FCLOSE(libxl_driver->logger_file);

    virObjectUnref(libxl_driver->reservedVNCPorts);

    VIR_FREE(libxl_driver->configDir);
    VIR_FREE(libxl_driver->autostartDir);
    VIR_FREE(libxl_driver->logDir);
    VIR_FREE(libxl_driver->stateDir);
    VIR_FREE(libxl_driver->libDir);
    VIR_FREE(libxl_driver->saveDir);

    virDomainEventStateFree(libxl_driver->domainEventState);
    virSysinfoDefFree(libxl_driver->hostsysinfo);

    libxlDriverUnlock(libxl_driver);
    virMutexDestroy(&libxl_driver->lock);
    VIR_FREE(libxl_driver);

    return 0;
}

static bool
libxlGetAutoballoon(libxlDriverPrivatePtr driver)
{
    const libxl_version_info *info;
    regex_t regex;
    int ret;

    info = libxl_get_version_info(driver->ctx);
    if (!info)
        return true; /* default to on */

    ret = regcomp(&regex,
            "(^| )dom0_mem=((|min:|max:)[0-9]+[bBkKmMgG]?,?)+($| )",
            REG_NOSUB | REG_EXTENDED);
    if (ret)
        return true;

    ret = regexec(&regex, info->commandline, 0, NULL, 0);
    regfree(&regex);
    return ret == REG_NOMATCH;
}


static int
libxlStateInitialize(bool privileged,
                     virStateInhibitCallback callback ATTRIBUTE_UNUSED,
                     void *opaque ATTRIBUTE_UNUSED)
{
    const libxl_version_info *ver_info;
    char *log_file = NULL;
    virCommandPtr cmd;
    int status, ret = 0;
    unsigned int free_mem;
    char ebuf[1024];

    /* Disable libxl driver if non-root */
    if (!privileged) {
        VIR_INFO("Not running privileged, disabling libxenlight driver");
        return 0;
    }

    /* Disable driver if legacy xen toolstack (xend) is in use */
    cmd = virCommandNewArgList("/usr/sbin/xend", "status", NULL);
    if (virCommandRun(cmd, &status) == 0 && status == 0) {
        VIR_INFO("Legacy xen tool stack seems to be in use, disabling "
                  "libxenlight driver.");
        virCommandFree(cmd);
        return 0;
    }
    virCommandFree(cmd);

    if (VIR_ALLOC(libxl_driver) < 0)
        return -1;

    if (virMutexInit(&libxl_driver->lock) < 0) {
        VIR_ERROR(_("cannot initialize mutex"));
        VIR_FREE(libxl_driver);
        return -1;
    }
    libxlDriverLock(libxl_driver);

    /* Allocate bitmap for vnc port reservation */
    if (!(libxl_driver->reservedVNCPorts =
          virPortAllocatorNew(LIBXL_VNC_PORT_MIN,
                              LIBXL_VNC_PORT_MAX)))
        goto error;

    if (!(libxl_driver->domains = virDomainObjListNew()))
        goto error;

    if (VIR_STRDUP(libxl_driver->configDir, LIBXL_CONFIG_DIR) < 0)
        goto error;

    if (VIR_STRDUP(libxl_driver->autostartDir, LIBXL_AUTOSTART_DIR) < 0)
        goto error;

    if (VIR_STRDUP(libxl_driver->logDir, LIBXL_LOG_DIR) < 0)
        goto error;

    if (VIR_STRDUP(libxl_driver->stateDir, LIBXL_STATE_DIR) < 0)
        goto error;

    if (VIR_STRDUP(libxl_driver->libDir, LIBXL_LIB_DIR) < 0)
        goto error;

    if (VIR_STRDUP(libxl_driver->saveDir, LIBXL_SAVE_DIR) < 0)
        goto error;

    if (virFileMakePath(libxl_driver->logDir) < 0) {
        VIR_ERROR(_("Failed to create log dir '%s': %s"),
                  libxl_driver->logDir, virStrerror(errno, ebuf, sizeof(ebuf)));
        goto error;
    }
    if (virFileMakePath(libxl_driver->stateDir) < 0) {
        VIR_ERROR(_("Failed to create state dir '%s': %s"),
                  libxl_driver->stateDir, virStrerror(errno, ebuf, sizeof(ebuf)));
        goto error;
    }
    if (virFileMakePath(libxl_driver->libDir) < 0) {
        VIR_ERROR(_("Failed to create lib dir '%s': %s"),
                  libxl_driver->libDir, virStrerror(errno, ebuf, sizeof(ebuf)));
        goto error;
    }
    if (virFileMakePath(libxl_driver->saveDir) < 0) {
        VIR_ERROR(_("Failed to create save dir '%s': %s"),
                  libxl_driver->saveDir, virStrerror(errno, ebuf, sizeof(ebuf)));
        goto error;
    }

    if (virAsprintf(&log_file, "%s/libxl.log", libxl_driver->logDir) < 0)
        goto error;

    if ((libxl_driver->logger_file = fopen(log_file, "a")) == NULL)  {
        virReportSystemError(errno,
                             _("failed to create logfile %s"),
                             log_file);
        goto error;
    }
    VIR_FREE(log_file);

    /* read the host sysinfo */
    if (privileged)
        libxl_driver->hostsysinfo = virSysinfoRead();

    libxl_driver->domainEventState = virDomainEventStateNew();
    if (!libxl_driver->domainEventState)
        goto error;

    libxl_driver->logger =
            (xentoollog_logger *)xtl_createlogger_stdiostream(libxl_driver->logger_file, XTL_DEBUG,  0);
    if (!libxl_driver->logger) {
        VIR_INFO("cannot create logger for libxenlight, disabling driver");
        goto fail;
    }

    if (libxl_ctx_alloc(&libxl_driver->ctx,
                       LIBXL_VERSION, 0,
                       libxl_driver->logger)) {
        VIR_INFO("cannot initialize libxenlight context, probably not running in a Xen Dom0, disabling driver");
        goto fail;
    }

    if ((ver_info = libxl_get_version_info(libxl_driver->ctx)) == NULL) {
        VIR_INFO("cannot version information from libxenlight, disabling driver");
        goto fail;
    }
    libxl_driver->version = (ver_info->xen_version_major * 1000000) +
            (ver_info->xen_version_minor * 1000);

    if ((libxl_driver->caps =
         libxlMakeCapabilities(libxl_driver->ctx)) == NULL) {
        VIR_ERROR(_("cannot create capabilities for libxenlight"));
        goto error;
    }

    if (!(libxl_driver->xmlopt = virDomainXMLOptionNew(&libxlDomainDefParserConfig,
                                                       &libxlDomainXMLPrivateDataCallbacks,
                                                       NULL)))
        goto error;

    /* This will fill xenstore info about free and dom0 memory if missing,
     * should be called before starting first domain */
    if (libxl_get_free_memory(libxl_driver->ctx, &free_mem)) {
        VIR_ERROR(_("Unable to configure libxl's memory management parameters"));
        goto error;
    }

    /* setup autoballoon */
    libxl_driver->autoballoon = libxlGetAutoballoon(libxl_driver);

    /* Load running domains first. */
    if (virDomainObjListLoadAllConfigs(libxl_driver->domains,
                                       libxl_driver->stateDir,
                                       libxl_driver->autostartDir,
                                       1,
                                       libxl_driver->caps,
                                       libxl_driver->xmlopt,
                                       1 << VIR_DOMAIN_VIRT_XEN,
                                       NULL, NULL) < 0)
        goto error;

    libxlReconnectDomains(libxl_driver);

    /* Then inactive persistent configs */
    if (virDomainObjListLoadAllConfigs(libxl_driver->domains,
                                       libxl_driver->configDir,
                                       libxl_driver->autostartDir,
                                       0,
                                       libxl_driver->caps,
                                       libxl_driver->xmlopt,
                                       1 << VIR_DOMAIN_VIRT_XEN,
                                       NULL, NULL) < 0)
        goto error;

    virDomainObjListForEach(libxl_driver->domains, libxlDomainManagedSaveLoad,
                            libxl_driver);

    libxlDriverUnlock(libxl_driver);

    return 0;

error:
    ret = -1;
fail:
    VIR_FREE(log_file);
    if (libxl_driver)
        libxlDriverUnlock(libxl_driver);
    libxlStateCleanup();
    return ret;
}

static void
libxlStateAutoStart(void)
{
    if (!libxl_driver)
        return;

    libxlDriverLock(libxl_driver);
    virDomainObjListForEach(libxl_driver->domains, libxlAutostartDomain,
                            libxl_driver);
    libxlDriverUnlock(libxl_driver);
}

static int
libxlStateReload(void)
{
    if (!libxl_driver)
        return 0;

    libxlDriverLock(libxl_driver);
    virDomainObjListLoadAllConfigs(libxl_driver->domains,
                                   libxl_driver->configDir,
                                   libxl_driver->autostartDir,
                                   1,
                                   libxl_driver->caps,
                                   libxl_driver->xmlopt,
                                   1 << VIR_DOMAIN_VIRT_XEN,
                                   NULL, libxl_driver);

    virDomainObjListForEach(libxl_driver->domains, libxlAutostartDomain,
                            libxl_driver);

    libxlDriverUnlock(libxl_driver);

    return 0;
}


static virDrvOpenStatus
libxlConnectOpen(virConnectPtr conn,
                 virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                 unsigned int flags)
{
    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    if (conn->uri == NULL) {
        if (libxl_driver == NULL)
            return VIR_DRV_OPEN_DECLINED;

        if (!(conn->uri = virURIParse("xen:///")))
            return VIR_DRV_OPEN_ERROR;
    } else {
        /* Only xen scheme */
        if (conn->uri->scheme == NULL || STRNEQ(conn->uri->scheme, "xen"))
            return VIR_DRV_OPEN_DECLINED;

        /* If server name is given, its for remote driver */
        if (conn->uri->server != NULL)
            return VIR_DRV_OPEN_DECLINED;

        /* Error if xen or libxl scheme specified but driver not started. */
        if (libxl_driver == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("libxenlight state driver is not active"));
            return VIR_DRV_OPEN_ERROR;
        }

        /* /session isn't supported in libxenlight */
        if (conn->uri->path &&
            STRNEQ(conn->uri->path, "") &&
            STRNEQ(conn->uri->path, "/") &&
            STRNEQ(conn->uri->path, "/system")) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unexpected Xen URI path '%s', try xen:///"),
                           NULLSTR(conn->uri->path));
            return VIR_DRV_OPEN_ERROR;
        }
    }

    if (virConnectOpenEnsureACL(conn) < 0)
        return VIR_DRV_OPEN_ERROR;

    conn->privateData = libxl_driver;

    return VIR_DRV_OPEN_SUCCESS;
};

static int
libxlConnectClose(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    conn->privateData = NULL;
    return 0;
}

static const char *
libxlConnectGetType(virConnectPtr conn)
{
    if (virConnectGetTypeEnsureACL(conn) < 0)
        return NULL;

    return "Xen";
}

static int
libxlConnectGetVersion(virConnectPtr conn, unsigned long *version)
{
    libxlDriverPrivatePtr driver = conn->privateData;

    if (virConnectGetVersionEnsureACL(conn) < 0)
        return 0;

    libxlDriverLock(driver);
    *version = driver->version;
    libxlDriverUnlock(driver);
    return 0;
}


static char *libxlConnectGetHostname(virConnectPtr conn)
{
    if (virConnectGetHostnameEnsureACL(conn) < 0)
        return NULL;

    return virGetHostname();
}

static char *
libxlConnectGetSysinfo(virConnectPtr conn, unsigned int flags)
{
    libxlDriverPrivatePtr driver = conn->privateData;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virCheckFlags(0, NULL);

    if (virConnectGetSysinfoEnsureACL(conn) < 0)
        return NULL;

    if (!driver->hostsysinfo) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Host SMBIOS information is not available"));
        return NULL;
    }

    if (virSysinfoFormat(&buf, driver->hostsysinfo) < 0)
        return NULL;
    if (virBufferError(&buf)) {
        virReportOOMError();
        return NULL;
    }
    return virBufferContentAndReset(&buf);
}

static int
libxlConnectGetMaxVcpus(virConnectPtr conn, const char *type ATTRIBUTE_UNUSED)
{
    int ret;
    libxlDriverPrivatePtr driver = conn->privateData;

    if (virConnectGetMaxVcpusEnsureACL(conn) < 0)
        return -1;

    ret = libxl_get_max_cpus(driver->ctx);
    /* libxl_get_max_cpus() will return 0 if there were any failures,
       e.g. xc_physinfo() failing */
    if (ret == 0)
        return -1;

    return ret;
}

static int
libxlNodeGetInfo(virConnectPtr conn, virNodeInfoPtr info)
{
    if (virNodeGetInfoEnsureACL(conn) < 0)
        return -1;

    return libxlDoNodeGetInfo(conn->privateData, info);
}

static char *
libxlConnectGetCapabilities(virConnectPtr conn)
{
    libxlDriverPrivatePtr driver = conn->privateData;
    char *xml;

    if (virConnectGetCapabilitiesEnsureACL(conn) < 0)
        return NULL;

    libxlDriverLock(driver);
    if ((xml = virCapabilitiesFormatXML(driver->caps)) == NULL)
        virReportOOMError();
    libxlDriverUnlock(driver);

    return xml;
}

static int
libxlConnectListDomains(virConnectPtr conn, int *ids, int nids)
{
    libxlDriverPrivatePtr driver = conn->privateData;
    int n;

    if (virConnectListDomainsEnsureACL(conn) < 0)
        return -1;

    libxlDriverLock(driver);
    n = virDomainObjListGetActiveIDs(driver->domains, ids, nids,
                                     virConnectListDomainsCheckACL, conn);
    libxlDriverUnlock(driver);

    return n;
}

static int
libxlConnectNumOfDomains(virConnectPtr conn)
{
    libxlDriverPrivatePtr driver = conn->privateData;
    int n;

    if (virConnectNumOfDomainsEnsureACL(conn) < 0)
        return -1;

    libxlDriverLock(driver);
    n = virDomainObjListNumOfDomains(driver->domains, true,
                                     virConnectNumOfDomainsCheckACL, conn);
    libxlDriverUnlock(driver);

    return n;
}

static virDomainPtr
libxlDomainCreateXML(virConnectPtr conn, const char *xml,
                     unsigned int flags)
{
    libxlDriverPrivatePtr driver = conn->privateData;
    virDomainDefPtr def;
    virDomainObjPtr vm = NULL;
    virDomainPtr dom = NULL;

    virCheckFlags(VIR_DOMAIN_START_PAUSED, NULL);

    libxlDriverLock(driver);
    if (!(def = virDomainDefParseString(xml, driver->caps, driver->xmlopt,
                                        1 << VIR_DOMAIN_VIRT_XEN,
                                        VIR_DOMAIN_XML_INACTIVE)))
        goto cleanup;

    if (virDomainCreateXMLEnsureACL(conn, def) < 0)
        goto cleanup;

    if (!(vm = virDomainObjListAdd(driver->domains, def,
                                   driver->xmlopt,
                                   VIR_DOMAIN_OBJ_LIST_ADD_CHECK_LIVE,
                                   NULL)))
        goto cleanup;
    def = NULL;

    if (libxlVmStart(driver, vm, (flags & VIR_DOMAIN_START_PAUSED) != 0,
                     -1) < 0) {
        virDomainObjListRemove(driver->domains, vm);
        vm = NULL;
        goto cleanup;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom)
        dom->id = vm->def->id;

cleanup:
    virDomainDefFree(def);
    if (vm)
        virObjectUnlock(vm);
    libxlDriverUnlock(driver);
    return dom;
}

static virDomainPtr
libxlDomainLookupByID(virConnectPtr conn, int id)
{
    libxlDriverPrivatePtr driver = conn->privateData;
    virDomainObjPtr vm;
    virDomainPtr dom = NULL;

    libxlDriverLock(driver);
    vm = virDomainObjListFindByID(driver->domains, id);
    libxlDriverUnlock(driver);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }

    if (virDomainLookupByIDEnsureACL(conn, vm->def) < 0)
        goto cleanup;

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom)
        dom->id = vm->def->id;

  cleanup:
    if (vm)
        virObjectUnlock(vm);
    return dom;
}

static virDomainPtr
libxlDomainLookupByUUID(virConnectPtr conn, const unsigned char *uuid)
{
    libxlDriverPrivatePtr driver = conn->privateData;
    virDomainObjPtr vm;
    virDomainPtr dom = NULL;

    libxlDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, uuid);
    libxlDriverUnlock(driver);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }

    if (virDomainLookupByUUIDEnsureACL(conn, vm->def) < 0)
        goto cleanup;

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom)
        dom->id = vm->def->id;

  cleanup:
    if (vm)
        virObjectUnlock(vm);
    return dom;
}

static virDomainPtr
libxlDomainLookupByName(virConnectPtr conn, const char *name)
{
    libxlDriverPrivatePtr driver = conn->privateData;
    virDomainObjPtr vm;
    virDomainPtr dom = NULL;

    libxlDriverLock(driver);
    vm = virDomainObjListFindByName(driver->domains, name);
    libxlDriverUnlock(driver);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }

    if (virDomainLookupByNameEnsureACL(conn, vm->def) < 0)
        goto cleanup;

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom)
        dom->id = vm->def->id;

  cleanup:
    if (vm)
        virObjectUnlock(vm);
    return dom;
}

static int
libxlDomainSuspend(virDomainPtr dom)
{
    libxlDriverPrivatePtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    libxlDomainObjPrivatePtr priv;
    virDomainEventPtr event = NULL;
    int ret = -1;

    libxlDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    libxlDriverUnlock(driver);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("No domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (virDomainSuspendEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s", _("Domain is not running"));
        goto cleanup;
    }

    priv = vm->privateData;

    if (virDomainObjGetState(vm, NULL) != VIR_DOMAIN_PAUSED) {
        if (libxl_domain_pause(priv->ctx, dom->id) != 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to suspend domain '%d' with libxenlight"),
                           dom->id);
            goto cleanup;
        }

        virDomainObjSetState(vm, VIR_DOMAIN_PAUSED, VIR_DOMAIN_PAUSED_USER);

        event = virDomainEventNewFromObj(vm, VIR_DOMAIN_EVENT_SUSPENDED,
                                         VIR_DOMAIN_EVENT_SUSPENDED_PAUSED);
    }

    if (virDomainSaveStatus(driver->xmlopt, driver->stateDir, vm) < 0)
        goto cleanup;

    ret = 0;

cleanup:
    if (vm)
        virObjectUnlock(vm);
    if (event) {
        libxlDriverLock(driver);
        libxlDomainEventQueue(driver, event);
        libxlDriverUnlock(driver);
    }
    return ret;
}


static int
libxlDomainResume(virDomainPtr dom)
{
    libxlDriverPrivatePtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    libxlDomainObjPrivatePtr priv;
    virDomainEventPtr event = NULL;
    int ret = -1;

    libxlDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    libxlDriverUnlock(driver);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("No domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (virDomainResumeEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s", _("Domain is not running"));
        goto cleanup;
    }

    priv = vm->privateData;

    if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_PAUSED) {
        if (libxl_domain_unpause(priv->ctx, dom->id) != 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to resume domain '%d' with libxenlight"),
                           dom->id);
            goto cleanup;
        }

        virDomainObjSetState(vm, VIR_DOMAIN_RUNNING,
                             VIR_DOMAIN_RUNNING_UNPAUSED);

        event = virDomainEventNewFromObj(vm, VIR_DOMAIN_EVENT_RESUMED,
                                         VIR_DOMAIN_EVENT_RESUMED_UNPAUSED);
    }

    if (virDomainSaveStatus(driver->xmlopt, driver->stateDir, vm) < 0)
        goto cleanup;

    ret = 0;

cleanup:
    if (vm)
        virObjectUnlock(vm);
    if (event) {
        libxlDriverLock(driver);
        libxlDomainEventQueue(driver, event);
        libxlDriverUnlock(driver);
    }
    return ret;
}

static int
libxlDomainShutdownFlags(virDomainPtr dom, unsigned int flags)
{
    libxlDriverPrivatePtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;
    libxlDomainObjPrivatePtr priv;

    virCheckFlags(0, -1);

    libxlDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("No domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (virDomainShutdownFlagsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("Domain is not running"));
        goto cleanup;
    }

    priv = vm->privateData;
    if (libxl_domain_shutdown(priv->ctx, dom->id) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to shutdown domain '%d' with libxenlight"),
                       dom->id);
        goto cleanup;
    }

    /* vm is marked shutoff (or removed from domains list if not persistent)
     * in shutdown event handler.
     */
    ret = 0;

cleanup:
    if (vm)
        virObjectUnlock(vm);
    libxlDriverUnlock(driver);
    return ret;
}

static int
libxlDomainShutdown(virDomainPtr dom)
{
    return libxlDomainShutdownFlags(dom, 0);
}


static int
libxlDomainReboot(virDomainPtr dom, unsigned int flags)
{
    libxlDriverPrivatePtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;
    libxlDomainObjPrivatePtr priv;

    virCheckFlags(0, -1);

    libxlDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("No domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (virDomainRebootEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("Domain is not running"));
        goto cleanup;
    }

    priv = vm->privateData;
    if (libxl_domain_reboot(priv->ctx, dom->id) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to reboot domain '%d' with libxenlight"),
                       dom->id);
        goto cleanup;
    }
    ret = 0;

cleanup:
    if (vm)
        virObjectUnlock(vm);
    libxlDriverUnlock(driver);
    return ret;
}

static int
libxlDomainDestroyFlags(virDomainPtr dom,
                        unsigned int flags)
{
    libxlDriverPrivatePtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;
    virDomainEventPtr event = NULL;

    virCheckFlags(0, -1);

    libxlDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("No domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (virDomainDestroyFlagsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("Domain is not running"));
        goto cleanup;
    }

    event = virDomainEventNewFromObj(vm,VIR_DOMAIN_EVENT_STOPPED,
                                     VIR_DOMAIN_EVENT_STOPPED_DESTROYED);

    if (libxlVmReap(driver, vm, VIR_DOMAIN_SHUTOFF_DESTROYED) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to destroy domain '%d'"), dom->id);
        goto cleanup;
    }

    if (!vm->persistent) {
        virDomainObjListRemove(driver->domains, vm);
        vm = NULL;
    }

    ret = 0;

cleanup:
    if (vm)
        virObjectUnlock(vm);
    if (event)
        libxlDomainEventQueue(driver, event);
    libxlDriverUnlock(driver);
    return ret;
}

static int
libxlDomainDestroy(virDomainPtr dom)
{
    return libxlDomainDestroyFlags(dom, 0);
}

static char *
libxlDomainGetOSType(virDomainPtr dom)
{
    libxlDriverPrivatePtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    char *type = NULL;

    libxlDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    libxlDriverUnlock(driver);
    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("No domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (virDomainGetOSTypeEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (VIR_STRDUP(type, vm->def->os.type) < 0)
        goto cleanup;

cleanup:
    if (vm)
        virObjectUnlock(vm);
    return type;
}

static unsigned long long
libxlDomainGetMaxMemory(virDomainPtr dom)
{
    libxlDriverPrivatePtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    unsigned long long ret = 0;

    libxlDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    libxlDriverUnlock(driver);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s", _("no domain with matching uuid"));
        goto cleanup;
    }

    if (virDomainGetMaxMemoryEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    ret = vm->def->mem.max_balloon;

cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static int
libxlDomainSetMemoryFlags(virDomainPtr dom, unsigned long newmem,
                          unsigned int flags)
{
    libxlDriverPrivatePtr driver = dom->conn->privateData;
    libxlDomainObjPrivatePtr priv;
    virDomainObjPtr vm;
    virDomainDefPtr persistentDef = NULL;
    bool isActive;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_MEM_LIVE |
                  VIR_DOMAIN_MEM_CONFIG |
                  VIR_DOMAIN_MEM_MAXIMUM, -1);

    libxlDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    libxlDriverUnlock(driver);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s", _("no domain with matching uuid"));
        goto cleanup;
    }

    if (virDomainSetMemoryFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    isActive = virDomainObjIsActive(vm);

    if (flags == VIR_DOMAIN_MEM_CURRENT) {
        if (isActive)
            flags = VIR_DOMAIN_MEM_LIVE;
        else
            flags = VIR_DOMAIN_MEM_CONFIG;
    }
    if (flags == VIR_DOMAIN_MEM_MAXIMUM) {
        if (isActive)
            flags = VIR_DOMAIN_MEM_LIVE | VIR_DOMAIN_MEM_MAXIMUM;
        else
            flags = VIR_DOMAIN_MEM_CONFIG | VIR_DOMAIN_MEM_MAXIMUM;
    }

    if (!isActive && (flags & VIR_DOMAIN_MEM_LIVE)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("cannot set memory on an inactive domain"));
        goto cleanup;
    }

    if (flags & VIR_DOMAIN_MEM_CONFIG) {
        if (!vm->persistent) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("cannot change persistent config of a transient domain"));
            goto cleanup;
        }
        if (!(persistentDef = virDomainObjGetPersistentDef(driver->caps,
                                                           driver->xmlopt,
                                                           vm)))
            goto cleanup;
    }

    if (flags & VIR_DOMAIN_MEM_MAXIMUM) {
        /* resize the maximum memory */

        if (flags & VIR_DOMAIN_MEM_LIVE) {
            priv = vm->privateData;
            if (libxl_domain_setmaxmem(priv->ctx, dom->id, newmem) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Failed to set maximum memory for domain '%d'"
                                 " with libxenlight"), dom->id);
                goto cleanup;
            }
        }

        if (flags & VIR_DOMAIN_MEM_CONFIG) {
            /* Help clang 2.8 decipher the logic flow.  */
            sa_assert(persistentDef);
            persistentDef->mem.max_balloon = newmem;
            if (persistentDef->mem.cur_balloon > newmem)
                persistentDef->mem.cur_balloon = newmem;
            ret = virDomainSaveConfig(driver->configDir, persistentDef);
            goto cleanup;
        }

    } else {
        /* resize the current memory */

        if (newmem > vm->def->mem.max_balloon) {
            virReportError(VIR_ERR_INVALID_ARG, "%s",
                           _("cannot set memory higher than max memory"));
            goto cleanup;
        }

        if (flags & VIR_DOMAIN_MEM_LIVE) {
            priv = vm->privateData;
            if (libxl_set_memory_target(priv->ctx, dom->id, newmem, 0,
                                        /* force */ 1) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Failed to set memory for domain '%d'"
                                 " with libxenlight"), dom->id);
                goto cleanup;
            }
        }

        if (flags & VIR_DOMAIN_MEM_CONFIG) {
            sa_assert(persistentDef);
            persistentDef->mem.cur_balloon = newmem;
            ret = virDomainSaveConfig(driver->configDir, persistentDef);
            goto cleanup;
        }
    }

    ret = 0;

cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static int
libxlDomainSetMemory(virDomainPtr dom, unsigned long memory)
{
    return libxlDomainSetMemoryFlags(dom, memory, VIR_DOMAIN_MEM_LIVE);
}

static int
libxlDomainSetMaxMemory(virDomainPtr dom, unsigned long memory)
{
    return libxlDomainSetMemoryFlags(dom, memory, VIR_DOMAIN_MEM_MAXIMUM);
}

static int
libxlDomainGetInfo(virDomainPtr dom, virDomainInfoPtr info)
{
    libxlDriverPrivatePtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    libxl_dominfo d_info;
    int ret = -1;

    libxlDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    libxlDriverUnlock(driver);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s",
                       _("no domain with matching uuid"));
        goto cleanup;
    }

    if (virDomainGetInfoEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        info->cpuTime = 0;
        info->memory = vm->def->mem.cur_balloon;
        info->maxMem = vm->def->mem.max_balloon;
    } else {
        if (libxl_domain_info(driver->ctx, &d_info, dom->id) != 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("libxl_domain_info failed for domain '%d'"), dom->id);
            goto cleanup;
        }
        info->cpuTime = d_info.cpu_time;
        info->memory = d_info.current_memkb;
        info->maxMem = d_info.max_memkb;
    }

    info->state = virDomainObjGetState(vm, NULL);
    info->nrVirtCpu = vm->def->vcpus;
    ret = 0;

  cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static int
libxlDomainGetState(virDomainPtr dom,
                    int *state,
                    int *reason,
                    unsigned int flags)
{
    libxlDriverPrivatePtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;

    virCheckFlags(0, -1);

    libxlDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    libxlDriverUnlock(driver);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s",
                       _("no domain with matching uuid"));
        goto cleanup;
    }

    if (virDomainGetStateEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    *state = virDomainObjGetState(vm, reason);
    ret = 0;

  cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

/* This internal function expects the driver lock to already be held on
 * entry and the vm must be active. */
static int
libxlDoDomainSave(libxlDriverPrivatePtr driver, virDomainObjPtr vm,
                  const char *to)
{
    libxlDomainObjPrivatePtr priv = vm->privateData;
    libxlSavefileHeader hdr;
    virDomainEventPtr event = NULL;
    char *xml = NULL;
    uint32_t xml_len;
    int fd = -1;
    int ret = -1;

    if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_PAUSED) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("Domain '%d' has to be running because libxenlight will"
                         " suspend it"), vm->def->id);
        goto cleanup;
    }

    if ((fd = virFileOpenAs(to, O_CREAT|O_TRUNC|O_WRONLY, S_IRUSR|S_IWUSR,
                            -1, -1, 0)) < 0) {
        virReportSystemError(-fd,
                             _("Failed to create domain save file '%s'"), to);
        goto cleanup;
    }

    if ((xml = virDomainDefFormat(vm->def, 0)) == NULL)
        goto cleanup;
    xml_len = strlen(xml) + 1;

    memset(&hdr, 0, sizeof(hdr));
    memcpy(hdr.magic, LIBXL_SAVE_MAGIC, sizeof(hdr.magic));
    hdr.version = LIBXL_SAVE_VERSION;
    hdr.xmlLen = xml_len;

    if (safewrite(fd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("Failed to write save file header"));
        goto cleanup;
    }

    if (safewrite(fd, xml, xml_len) != xml_len) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("Failed to write xml description"));
        goto cleanup;
    }

    if (libxl_domain_suspend(priv->ctx, vm->def->id, fd, 0, NULL) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to save domain '%d' with libxenlight"),
                       vm->def->id);
        goto cleanup;
    }

    event = virDomainEventNewFromObj(vm, VIR_DOMAIN_EVENT_STOPPED,
                                         VIR_DOMAIN_EVENT_STOPPED_SAVED);

    if (libxlVmReap(driver, vm, VIR_DOMAIN_SHUTOFF_SAVED) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to destroy domain '%d'"), vm->def->id);
        goto cleanup;
    }

    vm->hasManagedSave = true;
    ret = 0;

cleanup:
    VIR_FREE(xml);
    if (VIR_CLOSE(fd) < 0)
        virReportSystemError(errno, "%s", _("cannot close file"));
    if (event)
        libxlDomainEventQueue(driver, event);
    return ret;
}

static int
libxlDomainSaveFlags(virDomainPtr dom, const char *to, const char *dxml,
                     unsigned int flags)
{
    libxlDriverPrivatePtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;

    virCheckFlags(0, -1);
    if (dxml) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("xml modification unsupported"));
        return -1;
    }

    libxlDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("No domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (virDomainSaveFlagsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s", _("Domain is not running"));
        goto cleanup;
    }

    if (libxlDoDomainSave(driver, vm, to) < 0)
        goto cleanup;

    if (!vm->persistent) {
        virDomainObjListRemove(driver->domains, vm);
        vm = NULL;
    }

    ret = 0;

cleanup:
    if (vm)
        virObjectUnlock(vm);
    libxlDriverUnlock(driver);
    return ret;
}

static int
libxlDomainSave(virDomainPtr dom, const char *to)
{
    return libxlDomainSaveFlags(dom, to, NULL, 0);
}

static int
libxlDomainRestoreFlags(virConnectPtr conn, const char *from,
                        const char *dxml, unsigned int flags)
{
    libxlDriverPrivatePtr driver = conn->privateData;
    virDomainObjPtr vm = NULL;
    virDomainDefPtr def = NULL;
    libxlSavefileHeader hdr;
    int fd = -1;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_SAVE_PAUSED, -1);
    if (dxml) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("xml modification unsupported"));
        return -1;
    }

    libxlDriverLock(driver);

    fd = libxlSaveImageOpen(driver, from, &def, &hdr);
    if (fd < 0)
        goto cleanup;

    if (virDomainRestoreFlagsEnsureACL(conn, def) < 0)
        goto cleanup;

    if (!(vm = virDomainObjListAdd(driver->domains, def,
                                   driver->xmlopt,
                                   VIR_DOMAIN_OBJ_LIST_ADD_LIVE |
                                   VIR_DOMAIN_OBJ_LIST_ADD_CHECK_LIVE,
                                   NULL)))
        goto cleanup;

    def = NULL;

    ret = libxlVmStart(driver, vm, (flags & VIR_DOMAIN_SAVE_PAUSED) != 0, fd);
    if (ret < 0 && !vm->persistent) {
        virDomainObjListRemove(driver->domains, vm);
        vm = NULL;
    }

cleanup:
    if (VIR_CLOSE(fd) < 0)
        virReportSystemError(errno, "%s", _("cannot close file"));
    virDomainDefFree(def);
    if (vm)
        virObjectUnlock(vm);
    libxlDriverUnlock(driver);
    return ret;
}

static int
libxlDomainRestore(virConnectPtr conn, const char *from)
{
    return libxlDomainRestoreFlags(conn, from, NULL, 0);
}

static int
libxlDomainCoreDump(virDomainPtr dom, const char *to, unsigned int flags)
{
    libxlDriverPrivatePtr driver = dom->conn->privateData;
    libxlDomainObjPrivatePtr priv;
    virDomainObjPtr vm;
    virDomainEventPtr event = NULL;
    bool paused = false;
    int ret = -1;

    virCheckFlags(VIR_DUMP_LIVE | VIR_DUMP_CRASH, -1);

    libxlDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    libxlDriverUnlock(driver);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("No domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (virDomainCoreDumpEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s", _("Domain is not running"));
        goto cleanup;
    }

    priv = vm->privateData;

    if (!(flags & VIR_DUMP_LIVE) &&
        virDomainObjGetState(vm, NULL) == VIR_DOMAIN_RUNNING) {
        if (libxl_domain_pause(priv->ctx, dom->id) != 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Before dumping core, failed to suspend domain '%d'"
                             " with libxenlight"),
                           dom->id);
            goto cleanup;
        }
        virDomainObjSetState(vm, VIR_DOMAIN_PAUSED, VIR_DOMAIN_PAUSED_DUMP);
        paused = true;
    }

    if (libxl_domain_core_dump(priv->ctx, dom->id, to, NULL) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to dump core of domain '%d' with libxenlight"),
                       dom->id);
        goto cleanup_unpause;
    }

    libxlDriverLock(driver);
    if (flags & VIR_DUMP_CRASH) {
        if (libxlVmReap(driver, vm, VIR_DOMAIN_SHUTOFF_CRASHED) != 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to destroy domain '%d'"), dom->id);
            goto cleanup_unlock;
        }

        event = virDomainEventNewFromObj(vm, VIR_DOMAIN_EVENT_STOPPED,
                                         VIR_DOMAIN_EVENT_STOPPED_CRASHED);
    }

    if ((flags & VIR_DUMP_CRASH) && !vm->persistent) {
        virDomainObjListRemove(driver->domains, vm);
        vm = NULL;
    }

    ret = 0;

cleanup_unlock:
    libxlDriverUnlock(driver);
cleanup_unpause:
    if (virDomainObjIsActive(vm) && paused) {
        if (libxl_domain_unpause(priv->ctx, dom->id) != 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("After dumping core, failed to resume domain '%d' with"
                             " libxenlight"), dom->id);
        } else {
            virDomainObjSetState(vm, VIR_DOMAIN_RUNNING,
                                 VIR_DOMAIN_RUNNING_UNPAUSED);
        }
    }
cleanup:
    if (vm)
        virObjectUnlock(vm);
    if (event) {
        libxlDriverLock(driver);
        libxlDomainEventQueue(driver, event);
        libxlDriverUnlock(driver);
    }
    return ret;
}

static int
libxlDomainManagedSave(virDomainPtr dom, unsigned int flags)
{
    libxlDriverPrivatePtr driver = dom->conn->privateData;
    virDomainObjPtr vm = NULL;
    char *name = NULL;
    int ret = -1;

    virCheckFlags(0, -1);

    libxlDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("No domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (virDomainManagedSaveEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s", _("Domain is not running"));
        goto cleanup;
    }
    if (!vm->persistent) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("cannot do managed save for transient domain"));
        goto cleanup;
    }

    name = libxlDomainManagedSavePath(driver, vm);
    if (name == NULL)
        goto cleanup;

    VIR_INFO("Saving state to %s", name);

    if (libxlDoDomainSave(driver, vm, name) < 0)
        goto cleanup;

    if (!vm->persistent) {
        virDomainObjListRemove(driver->domains, vm);
        vm = NULL;
    }

    ret = 0;

cleanup:
    if (vm)
        virObjectUnlock(vm);
    libxlDriverUnlock(driver);
    VIR_FREE(name);
    return ret;
}

static int
libxlDomainManagedSaveLoad(virDomainObjPtr vm,
                           void *opaque)
{
    libxlDriverPrivatePtr driver = opaque;
    char *name;
    int ret = -1;

    virObjectLock(vm);

    if (!(name = libxlDomainManagedSavePath(driver, vm)))
        goto cleanup;

    vm->hasManagedSave = virFileExists(name);

    ret = 0;
cleanup:
    virObjectUnlock(vm);
    VIR_FREE(name);
    return ret;
}

static int
libxlDomainHasManagedSaveImage(virDomainPtr dom, unsigned int flags)
{
    libxlDriverPrivatePtr driver = dom->conn->privateData;
    virDomainObjPtr vm = NULL;
    int ret = -1;

    virCheckFlags(0, -1);

    libxlDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("No domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (virDomainHasManagedSaveImageEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    ret = vm->hasManagedSave;

cleanup:
    if (vm)
        virObjectUnlock(vm);
    libxlDriverUnlock(driver);
    return ret;
}

static int
libxlDomainManagedSaveRemove(virDomainPtr dom, unsigned int flags)
{
    libxlDriverPrivatePtr driver = dom->conn->privateData;
    virDomainObjPtr vm = NULL;
    int ret = -1;
    char *name = NULL;

    virCheckFlags(0, -1);

    libxlDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("No domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (virDomainManagedSaveRemoveEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    name = libxlDomainManagedSavePath(driver, vm);
    if (name == NULL)
        goto cleanup;

    ret = unlink(name);
    vm->hasManagedSave = false;

cleanup:
    VIR_FREE(name);
    if (vm)
        virObjectUnlock(vm);
    libxlDriverUnlock(driver);
    return ret;
}

static int
libxlDomainSetVcpusFlags(virDomainPtr dom, unsigned int nvcpus,
                         unsigned int flags)
{
    libxlDriverPrivatePtr driver = dom->conn->privateData;
    libxlDomainObjPrivatePtr priv;
    virDomainDefPtr def;
    virDomainObjPtr vm;
    libxl_bitmap map;
    uint8_t *bitmask = NULL;
    unsigned int maplen;
    size_t i;
    unsigned int pos;
    int max;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_VCPU_LIVE |
                  VIR_DOMAIN_VCPU_CONFIG |
                  VIR_DOMAIN_VCPU_MAXIMUM, -1);

    /* At least one of LIVE or CONFIG must be set.  MAXIMUM cannot be
     * mixed with LIVE.  */
    if ((flags & (VIR_DOMAIN_VCPU_LIVE | VIR_DOMAIN_VCPU_CONFIG)) == 0 ||
        (flags & (VIR_DOMAIN_VCPU_MAXIMUM | VIR_DOMAIN_VCPU_LIVE)) ==
         (VIR_DOMAIN_VCPU_MAXIMUM | VIR_DOMAIN_VCPU_LIVE)) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("invalid flag combination: (0x%x)"), flags);
        return -1;
    }

    if (!nvcpus) {
        virReportError(VIR_ERR_INVALID_ARG, "%s", _("nvcpus is zero"));
        return -1;
    }

    libxlDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    libxlDriverUnlock(driver);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s", _("no domain with matching uuid"));
        goto cleanup;
    }

    if (virDomainSetVcpusFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm) && (flags & VIR_DOMAIN_VCPU_LIVE)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("cannot set vcpus on an inactive domain"));
        goto cleanup;
    }

    if (!vm->persistent && (flags & VIR_DOMAIN_VCPU_CONFIG)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("cannot change persistent config of a transient domain"));
        goto cleanup;
    }

    if ((max = libxlConnectGetMaxVcpus(dom->conn, NULL)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("could not determine max vcpus for the domain"));
        goto cleanup;
    }

    if (!(flags & VIR_DOMAIN_VCPU_MAXIMUM) && vm->def->maxvcpus < max) {
        max = vm->def->maxvcpus;
    }

    if (nvcpus > max) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("requested vcpus is greater than max allowable"
                         " vcpus for the domain: %d > %d"), nvcpus, max);
        goto cleanup;
    }

    priv = vm->privateData;

    if (!(def = virDomainObjGetPersistentDef(driver->caps, driver->xmlopt, vm)))
        goto cleanup;

    maplen = VIR_CPU_MAPLEN(nvcpus);
    if (VIR_ALLOC_N(bitmask, maplen) < 0)
        goto cleanup;

    for (i = 0; i < nvcpus; ++i) {
        pos = i / 8;
        bitmask[pos] |= 1 << (i % 8);
    }

    map.size = maplen;
    map.map = bitmask;

    switch (flags) {
    case VIR_DOMAIN_VCPU_MAXIMUM | VIR_DOMAIN_VCPU_CONFIG:
        def->maxvcpus = nvcpus;
        if (nvcpus < def->vcpus)
            def->vcpus = nvcpus;
        break;

    case VIR_DOMAIN_VCPU_CONFIG:
        def->vcpus = nvcpus;
        break;

    case VIR_DOMAIN_VCPU_LIVE:
        if (libxl_set_vcpuonline(priv->ctx, dom->id, &map) != 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to set vcpus for domain '%d'"
                             " with libxenlight"), dom->id);
            goto cleanup;
        }
        break;

    case VIR_DOMAIN_VCPU_LIVE | VIR_DOMAIN_VCPU_CONFIG:
        if (libxl_set_vcpuonline(priv->ctx, dom->id, &map) != 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to set vcpus for domain '%d'"
                             " with libxenlight"), dom->id);
            goto cleanup;
        }
        def->vcpus = nvcpus;
        break;
    }

    ret = 0;

    if (flags & VIR_DOMAIN_VCPU_CONFIG)
        ret = virDomainSaveConfig(driver->configDir, def);

cleanup:
    VIR_FREE(bitmask);
     if (vm)
        virObjectUnlock(vm);
    return ret;
}

static int
libxlDomainSetVcpus(virDomainPtr dom, unsigned int nvcpus)
{
    return libxlDomainSetVcpusFlags(dom, nvcpus, VIR_DOMAIN_VCPU_LIVE);
}

static int
libxlDomainGetVcpusFlags(virDomainPtr dom, unsigned int flags)
{
    libxlDriverPrivatePtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    virDomainDefPtr def;
    int ret = -1;
    bool active;

    virCheckFlags(VIR_DOMAIN_VCPU_LIVE |
                  VIR_DOMAIN_VCPU_CONFIG |
                  VIR_DOMAIN_VCPU_MAXIMUM, -1);

    libxlDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    libxlDriverUnlock(driver);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s", _("no domain with matching uuid"));
        goto cleanup;
    }

    if (virDomainGetVcpusFlagsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    active = virDomainObjIsActive(vm);

    if ((flags & (VIR_DOMAIN_VCPU_LIVE | VIR_DOMAIN_VCPU_CONFIG)) == 0) {
        if (active)
            flags |= VIR_DOMAIN_VCPU_LIVE;
        else
            flags |= VIR_DOMAIN_VCPU_CONFIG;
    }
    if ((flags & VIR_DOMAIN_VCPU_LIVE) && (flags & VIR_DOMAIN_VCPU_CONFIG)) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("invalid flag combination: (0x%x)"), flags);
        return -1;
    }

    if (flags & VIR_DOMAIN_VCPU_LIVE) {
        if (!active) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           "%s", _("Domain is not running"));
            goto cleanup;
        }
        def = vm->def;
    } else {
        if (!vm->persistent) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           "%s", _("domain is transient"));
            goto cleanup;
        }
        def = vm->newDef ? vm->newDef : vm->def;
    }

    ret = (flags & VIR_DOMAIN_VCPU_MAXIMUM) ? def->maxvcpus : def->vcpus;

cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static int
libxlDomainPinVcpu(virDomainPtr dom, unsigned int vcpu, unsigned char *cpumap,
                   int maplen)
{
    libxlDriverPrivatePtr driver = dom->conn->privateData;
    libxlDomainObjPrivatePtr priv;
    virDomainObjPtr vm;
    int ret = -1;
    libxl_bitmap map;

    libxlDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    libxlDriverUnlock(driver);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s", _("no domain with matching uuid"));
        goto cleanup;
    }

    if (virDomainPinVcpuEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("cannot pin vcpus on an inactive domain"));
        goto cleanup;
    }

    priv = vm->privateData;

    map.size = maplen;
    map.map = cpumap;
    if (libxl_set_vcpuaffinity(priv->ctx, dom->id, vcpu, &map) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to pin vcpu '%d' with libxenlight"), vcpu);
        goto cleanup;
    }

    if (!vm->def->cputune.vcpupin) {
        if (VIR_ALLOC(vm->def->cputune.vcpupin) < 0)
            goto cleanup;
        vm->def->cputune.nvcpupin = 0;
    }
    if (virDomainVcpuPinAdd(&vm->def->cputune.vcpupin,
                            &vm->def->cputune.nvcpupin,
                            cpumap,
                            maplen,
                            vcpu) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("failed to update or add vcpupin xml"));
        goto cleanup;
    }

    if (virDomainSaveStatus(driver->xmlopt, driver->stateDir, vm) < 0)
        goto cleanup;

    ret = 0;

cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}


static int
libxlDomainGetVcpus(virDomainPtr dom, virVcpuInfoPtr info, int maxinfo,
                    unsigned char *cpumaps, int maplen)
{
    libxlDriverPrivatePtr driver = dom->conn->privateData;
    libxlDomainObjPrivatePtr priv;
    virDomainObjPtr vm;
    int ret = -1;
    libxl_vcpuinfo *vcpuinfo;
    int maxcpu, hostcpus;
    size_t i;
    unsigned char *cpumap;

    libxlDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    libxlDriverUnlock(driver);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s", _("no domain with matching uuid"));
        goto cleanup;
    }

    if (virDomainGetVcpusEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s", _("Domain is not running"));
        goto cleanup;
    }

    priv = vm->privateData;
    if ((vcpuinfo = libxl_list_vcpu(priv->ctx, dom->id, &maxcpu,
                                    &hostcpus)) == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to list vcpus for domain '%d' with libxenlight"),
                       dom->id);
        goto cleanup;
    }

    if (cpumaps && maplen > 0)
        memset(cpumaps, 0, maplen * maxinfo);
    for (i = 0; i < maxcpu && i < maxinfo; ++i) {
        info[i].number = vcpuinfo[i].vcpuid;
        info[i].cpu = vcpuinfo[i].cpu;
        info[i].cpuTime = vcpuinfo[i].vcpu_time;
        if (vcpuinfo[i].running)
            info[i].state = VIR_VCPU_RUNNING;
        else if (vcpuinfo[i].blocked)
            info[i].state = VIR_VCPU_BLOCKED;
        else
            info[i].state = VIR_VCPU_OFFLINE;

        if (cpumaps && maplen > 0) {
            cpumap = VIR_GET_CPUMAP(cpumaps, maplen, i);
            memcpy(cpumap, vcpuinfo[i].cpumap.map,
                   MIN(maplen, vcpuinfo[i].cpumap.size));
        }

        libxl_vcpuinfo_dispose(&vcpuinfo[i]);
    }
    VIR_FREE(vcpuinfo);

    ret = maxinfo;

cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static char *
libxlDomainGetXMLDesc(virDomainPtr dom, unsigned int flags)
{
    libxlDriverPrivatePtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    char *ret = NULL;

    /* Flags checked by virDomainDefFormat */

    libxlDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    libxlDriverUnlock(driver);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s",
                       _("no domain with matching uuid"));
        goto cleanup;
    }

    if (virDomainGetXMLDescEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    ret = virDomainDefFormat(vm->def, flags);

  cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static char *
libxlConnectDomainXMLFromNative(virConnectPtr conn, const char * nativeFormat,
                                const char * nativeConfig,
                                unsigned int flags)
{
    libxlDriverPrivatePtr driver = conn->privateData;
    const libxl_version_info *ver_info;
    virDomainDefPtr def = NULL;
    virConfPtr conf = NULL;
    char *xml = NULL;

    virCheckFlags(0, NULL);

    if (virConnectDomainXMLFromNativeEnsureACL(conn) < 0)
        goto cleanup;

    if (STRNEQ(nativeFormat, LIBXL_CONFIG_FORMAT_XM)) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unsupported config type %s"), nativeFormat);
        goto cleanup;
    }

    if ((ver_info = libxl_get_version_info(driver->ctx)) == NULL) {
        VIR_ERROR(_("cannot get version information from libxenlight"));
        goto cleanup;
    }

    if (!(conf = virConfReadMem(nativeConfig, strlen(nativeConfig), 0)))
        goto cleanup;

    if (!(def = xenParseXM(conf, ver_info->xen_version_major, driver->caps))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("parsing xm config failed"));
        goto cleanup;
    }

    xml = virDomainDefFormat(def, VIR_DOMAIN_XML_INACTIVE);

cleanup:
    virDomainDefFree(def);
    if (conf)
        virConfFree(conf);
    return xml;
}

#define MAX_CONFIG_SIZE (1024 * 65)
static char *
libxlConnectDomainXMLToNative(virConnectPtr conn, const char * nativeFormat,
                              const char * domainXml,
                              unsigned int flags)
{
    libxlDriverPrivatePtr driver = conn->privateData;
    const libxl_version_info *ver_info;
    virDomainDefPtr def = NULL;
    virConfPtr conf = NULL;
    int len = MAX_CONFIG_SIZE;
    char *ret = NULL;

    virCheckFlags(0, NULL);

    if (virConnectDomainXMLToNativeEnsureACL(conn) < 0)
        goto cleanup;

    if (STRNEQ(nativeFormat, LIBXL_CONFIG_FORMAT_XM)) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unsupported config type %s"), nativeFormat);
        goto cleanup;
    }

    if ((ver_info = libxl_get_version_info(driver->ctx)) == NULL) {
        VIR_ERROR(_("cannot get version information from libxenlight"));
        goto cleanup;
    }

    if (!(def = virDomainDefParseString(domainXml,
                                        driver->caps, driver->xmlopt,
                                        1 << VIR_DOMAIN_VIRT_XEN, 0)))
        goto cleanup;

    if (!(conf = xenFormatXM(conn, def, ver_info->xen_version_major)))
        goto cleanup;

    if (VIR_ALLOC_N(ret, len) < 0)
        goto cleanup;

    if (virConfWriteMem(ret, &len, conf) < 0) {
        VIR_FREE(ret);
        goto cleanup;
    }

cleanup:
    virDomainDefFree(def);
    if (conf)
        virConfFree(conf);
    return ret;
}

static int
libxlConnectListDefinedDomains(virConnectPtr conn,
                               char **const names, int nnames)
{
    libxlDriverPrivatePtr driver = conn->privateData;
    int n;

    if (virConnectListDefinedDomainsEnsureACL(conn) < 0)
        return -1;

    libxlDriverLock(driver);
    n = virDomainObjListGetInactiveNames(driver->domains, names, nnames,
                                         virConnectListDefinedDomainsCheckACL, conn);
    libxlDriverUnlock(driver);
    return n;
}

static int
libxlConnectNumOfDefinedDomains(virConnectPtr conn)
{
    libxlDriverPrivatePtr driver = conn->privateData;
    int n;

    if (virConnectNumOfDefinedDomainsEnsureACL(conn) < 0)
        return -1;

    libxlDriverLock(driver);
    n = virDomainObjListNumOfDomains(driver->domains, false,
                                     virConnectNumOfDefinedDomainsCheckACL,
                                     conn);
    libxlDriverUnlock(driver);

    return n;
}

static int
libxlDomainCreateWithFlags(virDomainPtr dom,
                           unsigned int flags)
{
    libxlDriverPrivatePtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_START_PAUSED, -1);

    libxlDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("No domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (virDomainCreateWithFlagsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("Domain is already running"));
        goto cleanup;
    }

    ret = libxlVmStart(driver, vm, (flags & VIR_DOMAIN_START_PAUSED) != 0, -1);

cleanup:
    if (vm)
        virObjectUnlock(vm);
    libxlDriverUnlock(driver);
    return ret;
}

static int
libxlDomainCreate(virDomainPtr dom)
{
    return libxlDomainCreateWithFlags(dom, 0);
}

static virDomainPtr
libxlDomainDefineXML(virConnectPtr conn, const char *xml)
{
    libxlDriverPrivatePtr driver = conn->privateData;
    virDomainDefPtr def = NULL;
    virDomainObjPtr vm = NULL;
    virDomainPtr dom = NULL;
    virDomainEventPtr event = NULL;
    virDomainDefPtr oldDef = NULL;

    libxlDriverLock(driver);
    if (!(def = virDomainDefParseString(xml, driver->caps, driver->xmlopt,
                                        1 << VIR_DOMAIN_VIRT_XEN,
                                        VIR_DOMAIN_XML_INACTIVE)))
        goto cleanup;

    if (virDomainDefineXMLEnsureACL(conn, def) < 0)
        goto cleanup;

    if (!(vm = virDomainObjListAdd(driver->domains, def,
                                   driver->xmlopt,
                                   0,
                                   &oldDef)))
        goto cleanup;
    def = NULL;
    vm->persistent = 1;

    if (virDomainSaveConfig(driver->configDir,
                            vm->newDef ? vm->newDef : vm->def) < 0) {
        virDomainObjListRemove(driver->domains, vm);
        vm = NULL;
        goto cleanup;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom)
        dom->id = vm->def->id;

    event = virDomainEventNewFromObj(vm, VIR_DOMAIN_EVENT_DEFINED,
                                     !oldDef ?
                                     VIR_DOMAIN_EVENT_DEFINED_ADDED :
                                     VIR_DOMAIN_EVENT_DEFINED_UPDATED);

cleanup:
    virDomainDefFree(def);
    virDomainDefFree(oldDef);
    if (vm)
        virObjectUnlock(vm);
    if (event)
        libxlDomainEventQueue(driver, event);
    libxlDriverUnlock(driver);
    return dom;
}

static int
libxlDomainUndefineFlags(virDomainPtr dom,
                         unsigned int flags)
{
    libxlDriverPrivatePtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    virDomainEventPtr event = NULL;
    char *name = NULL;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_UNDEFINE_MANAGED_SAVE, -1);

    libxlDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];

        virUUIDFormat(dom->uuid, uuidstr);
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (virDomainUndefineFlagsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!vm->persistent) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("cannot undefine transient domain"));
        goto cleanup;
    }

    name = libxlDomainManagedSavePath(driver, vm);
    if (name == NULL)
        goto cleanup;

    if (virFileExists(name)) {
        if (flags & VIR_DOMAIN_UNDEFINE_MANAGED_SAVE) {
            if (unlink(name) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Failed to remove domain managed save image"));
                goto cleanup;
            }
        } else {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("Refusing to undefine while domain managed "
                             "save image exists"));
            goto cleanup;
        }
    }

    if (virDomainDeleteConfig(driver->configDir,
                              driver->autostartDir,
                              vm) < 0)
        goto cleanup;

    event = virDomainEventNewFromObj(vm, VIR_DOMAIN_EVENT_UNDEFINED,
                                     VIR_DOMAIN_EVENT_UNDEFINED_REMOVED);

    if (virDomainObjIsActive(vm)) {
        vm->persistent = 0;
    } else {
        virDomainObjListRemove(driver->domains, vm);
        vm = NULL;
    }

    ret = 0;

  cleanup:
    VIR_FREE(name);
    if (vm)
        virObjectUnlock(vm);
    if (event)
        libxlDomainEventQueue(driver, event);
    libxlDriverUnlock(driver);
    return ret;
}

static int
libxlDomainUndefine(virDomainPtr dom)
{
    return libxlDomainUndefineFlags(dom, 0);
}

static int
libxlDomainChangeEjectableMedia(libxlDomainObjPrivatePtr priv,
                                virDomainObjPtr vm, virDomainDiskDefPtr disk)
{
    virDomainDiskDefPtr origdisk = NULL;
    libxl_device_disk x_disk;
    size_t i;
    int ret = -1;

    for (i = 0; i < vm->def->ndisks; i++) {
        if (vm->def->disks[i]->bus == disk->bus &&
            STREQ(vm->def->disks[i]->dst, disk->dst)) {
            origdisk = vm->def->disks[i];
            break;
        }
    }

    if (!origdisk) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("No device with bus '%s' and target '%s'"),
                       virDomainDiskBusTypeToString(disk->bus), disk->dst);
        goto cleanup;
    }

    if (origdisk->device != VIR_DOMAIN_DISK_DEVICE_CDROM) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Removable media not supported for %s device"),
                       virDomainDiskDeviceTypeToString(disk->device));
        return -1;
    }

    if (libxlMakeDisk(disk, &x_disk) < 0)
        goto cleanup;

    if ((ret = libxl_cdrom_insert(priv->ctx, vm->def->id, &x_disk, NULL)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("libxenlight failed to change media for disk '%s'"),
                       disk->dst);
        goto cleanup;
    }

    VIR_FREE(origdisk->src);
    origdisk->src = disk->src;
    disk->src = NULL;
    origdisk->type = disk->type;


    virDomainDiskDefFree(disk);

    ret = 0;

cleanup:
    return ret;
}

static int
libxlDomainAttachDeviceDiskLive(libxlDomainObjPrivatePtr priv,
                                virDomainObjPtr vm, virDomainDeviceDefPtr dev)
{
    virDomainDiskDefPtr l_disk = dev->data.disk;
    libxl_device_disk x_disk;
    int ret = -1;

    switch (l_disk->device)  {
        case VIR_DOMAIN_DISK_DEVICE_CDROM:
            ret = libxlDomainChangeEjectableMedia(priv, vm, l_disk);
            break;
        case VIR_DOMAIN_DISK_DEVICE_DISK:
            if (l_disk->bus == VIR_DOMAIN_DISK_BUS_XEN) {
                if (virDomainDiskIndexByName(vm->def, l_disk->dst, true) >= 0) {
                    virReportError(VIR_ERR_OPERATION_FAILED,
                                   _("target %s already exists"), l_disk->dst);
                    goto cleanup;
                }

                if (!l_disk->src) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   "%s", _("disk source path is missing"));
                    goto cleanup;
                }

                if (VIR_REALLOC_N(vm->def->disks, vm->def->ndisks+1) < 0)
                    goto cleanup;

                if (libxlMakeDisk(l_disk, &x_disk) < 0)
                    goto cleanup;

                if ((ret = libxl_device_disk_add(priv->ctx, vm->def->id,
                                                &x_disk, NULL)) < 0) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("libxenlight failed to attach disk '%s'"),
                                   l_disk->dst);
                    goto cleanup;
                }

                virDomainDiskInsertPreAlloced(vm->def, l_disk);

            } else {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("disk bus '%s' cannot be hotplugged."),
                               virDomainDiskBusTypeToString(l_disk->bus));
            }
            break;
        default:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("disk device type '%s' cannot be hotplugged"),
                           virDomainDiskDeviceTypeToString(l_disk->device));
            break;
    }

cleanup:
    return ret;
}

static int
libxlDomainDetachDeviceDiskLive(libxlDomainObjPrivatePtr priv,
                                virDomainObjPtr vm, virDomainDeviceDefPtr dev)
{
    virDomainDiskDefPtr l_disk = NULL;
    libxl_device_disk x_disk;
    int idx;
    int ret = -1;

    switch (dev->data.disk->device)  {
        case VIR_DOMAIN_DISK_DEVICE_DISK:
            if (dev->data.disk->bus == VIR_DOMAIN_DISK_BUS_XEN) {

                if ((idx = virDomainDiskIndexByName(vm->def,
                                                    dev->data.disk->dst,
                                                    false)) < 0) {
                    virReportError(VIR_ERR_OPERATION_FAILED,
                                   _("disk %s not found"), dev->data.disk->dst);
                    goto cleanup;
                }

                l_disk = vm->def->disks[idx];

                if (libxlMakeDisk(l_disk, &x_disk) < 0)
                    goto cleanup;

                if ((ret = libxl_device_disk_remove(priv->ctx, vm->def->id,
                                                    &x_disk, NULL)) < 0) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("libxenlight failed to detach disk '%s'"),
                                   l_disk->dst);
                    goto cleanup;
                }

                virDomainDiskRemove(vm->def, idx);
                virDomainDiskDefFree(l_disk);

            } else {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("disk bus '%s' cannot be hot unplugged."),
                               virDomainDiskBusTypeToString(dev->data.disk->bus));
            }
            break;
        default:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("device type '%s' cannot hot unplugged"),
                           virDomainDiskDeviceTypeToString(dev->data.disk->device));
            break;
    }

cleanup:
    return ret;
}

static int
libxlDomainAttachDeviceLive(libxlDomainObjPrivatePtr priv, virDomainObjPtr vm,
                            virDomainDeviceDefPtr dev)
{
    int ret = -1;

    switch (dev->type) {
        case VIR_DOMAIN_DEVICE_DISK:
            ret = libxlDomainAttachDeviceDiskLive(priv, vm, dev);
            if (!ret)
                dev->data.disk = NULL;
            break;

        default:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("device type '%s' cannot be attached"),
                           virDomainDeviceTypeToString(dev->type));
            break;
    }

    return ret;
}

static int
libxlDomainAttachDeviceConfig(virDomainDefPtr vmdef, virDomainDeviceDefPtr dev)
{
    virDomainDiskDefPtr disk;

    switch (dev->type) {
        case VIR_DOMAIN_DEVICE_DISK:
            disk = dev->data.disk;
            if (virDomainDiskIndexByName(vmdef, disk->dst, true) >= 0) {
                virReportError(VIR_ERR_INVALID_ARG,
                               _("target %s already exists."), disk->dst);
                return -1;
            }
            if (virDomainDiskInsert(vmdef, disk))
                return -1;
            /* vmdef has the pointer. Generic codes for vmdef will do all jobs */
            dev->data.disk = NULL;
            break;

        default:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("persistent attach of device is not supported"));
            return -1;
    }
    return 0;
}

static int
libxlDomainDetachDeviceLive(libxlDomainObjPrivatePtr priv, virDomainObjPtr vm,
                            virDomainDeviceDefPtr dev)
{
    int ret = -1;

    switch (dev->type) {
        case VIR_DOMAIN_DEVICE_DISK:
            ret = libxlDomainDetachDeviceDiskLive(priv, vm, dev);
            break;

        default:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("device type '%s' cannot be detached"),
                           virDomainDeviceTypeToString(dev->type));
            break;
    }

    return ret;
}

static int
libxlDomainDetachDeviceConfig(virDomainDefPtr vmdef, virDomainDeviceDefPtr dev)
{
    virDomainDiskDefPtr disk, detach;
    int ret = -1;

    switch (dev->type) {
        case VIR_DOMAIN_DEVICE_DISK:
            disk = dev->data.disk;
            if (!(detach = virDomainDiskRemoveByName(vmdef, disk->dst))) {
                virReportError(VIR_ERR_INVALID_ARG,
                               _("no target device %s"), disk->dst);
                break;
            }
            virDomainDiskDefFree(detach);
            ret = 0;
            break;
        default:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("persistent detach of device is not supported"));
            break;
    }

    return ret;
}

static int
libxlDomainUpdateDeviceLive(libxlDomainObjPrivatePtr priv,
                            virDomainObjPtr vm, virDomainDeviceDefPtr dev)
{
    virDomainDiskDefPtr disk;
    int ret = -1;

    switch (dev->type) {
        case VIR_DOMAIN_DEVICE_DISK:
            disk = dev->data.disk;
            switch (disk->device) {
                case VIR_DOMAIN_DISK_DEVICE_CDROM:
                    ret = libxlDomainChangeEjectableMedia(priv, vm, disk);
                    if (ret == 0)
                        dev->data.disk = NULL;
                    break;
                default:
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("disk bus '%s' cannot be updated."),
                                   virDomainDiskBusTypeToString(disk->bus));
                    break;
            }
            break;
        default:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("device type '%s' cannot be updated"),
                           virDomainDeviceTypeToString(dev->type));
            break;
    }

    return ret;
}

static int
libxlDomainUpdateDeviceConfig(virDomainDefPtr vmdef, virDomainDeviceDefPtr dev)
{
    virDomainDiskDefPtr orig;
    virDomainDiskDefPtr disk;
    int idx;
    int ret = -1;

    switch (dev->type) {
        case VIR_DOMAIN_DEVICE_DISK:
            disk = dev->data.disk;
            if ((idx = virDomainDiskIndexByName(vmdef, disk->dst, false)) < 0) {
                virReportError(VIR_ERR_INVALID_ARG,
                               _("target %s doesn't exist."), disk->dst);
                goto cleanup;
            }
            orig = vmdef->disks[idx];
            if (!(orig->device == VIR_DOMAIN_DISK_DEVICE_CDROM)) {
                virReportError(VIR_ERR_INVALID_ARG, "%s",
                               _("this disk doesn't support update"));
                goto cleanup;
            }

            VIR_FREE(orig->src);
            orig->src = disk->src;
            orig->type = disk->type;
            if (disk->driverName) {
                VIR_FREE(orig->driverName);
                orig->driverName = disk->driverName;
                disk->driverName = NULL;
            }
            orig->format = disk->format;
            disk->src = NULL;
            break;
        default:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("persistent update of device is not supported"));
            goto cleanup;
    }

    ret = 0;

cleanup:
    return ret;
}


static int
libxlDomainAttachDeviceFlags(virDomainPtr dom, const char *xml,
                             unsigned int flags)
{
    libxlDriverPrivatePtr driver = dom->conn->privateData;
    virDomainObjPtr vm = NULL;
    virDomainDefPtr vmdef = NULL;
    virDomainDeviceDefPtr dev = NULL;
    libxlDomainObjPrivatePtr priv;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_DEVICE_MODIFY_LIVE |
                  VIR_DOMAIN_DEVICE_MODIFY_CONFIG, -1);

    libxlDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s", _("no domain with matching uuid"));
        goto cleanup;
    }

    if (virDomainAttachDeviceFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (virDomainObjIsActive(vm)) {
        if (flags == VIR_DOMAIN_DEVICE_MODIFY_CURRENT)
            flags |= VIR_DOMAIN_DEVICE_MODIFY_LIVE;
    } else {
        if (flags == VIR_DOMAIN_DEVICE_MODIFY_CURRENT)
            flags |= VIR_DOMAIN_DEVICE_MODIFY_CONFIG;
        /* check consistency between flags and the vm state */
        if (flags & VIR_DOMAIN_DEVICE_MODIFY_LIVE) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           "%s", _("Domain is not running"));
            goto cleanup;
        }
    }

    if ((flags & VIR_DOMAIN_DEVICE_MODIFY_CONFIG) && !vm->persistent) {
         virReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("cannot modify device on transient domain"));
         goto cleanup;
    }

    priv = vm->privateData;

    if (flags & VIR_DOMAIN_DEVICE_MODIFY_CONFIG) {
        if (!(dev = virDomainDeviceDefParse(xml, vm->def,
                                            driver->caps, driver->xmlopt,
                                            VIR_DOMAIN_XML_INACTIVE)))
            goto cleanup;

        /* Make a copy for updated domain. */
        if (!(vmdef = virDomainObjCopyPersistentDef(vm, driver->caps,
                                                    driver->xmlopt)))
            goto cleanup;

        if ((ret = libxlDomainAttachDeviceConfig(vmdef, dev)) < 0)
            goto cleanup;
    } else {
        ret = 0;
    }

    if (flags & VIR_DOMAIN_DEVICE_MODIFY_LIVE) {
        /* If dev exists it was created to modify the domain config. Free it. */
        virDomainDeviceDefFree(dev);
        if (!(dev = virDomainDeviceDefParse(xml, vm->def,
                                            driver->caps, driver->xmlopt,
                                            VIR_DOMAIN_XML_INACTIVE)))
            goto cleanup;

        if ((ret = libxlDomainAttachDeviceLive(priv, vm, dev)) < 0)
            goto cleanup;

        /*
         * update domain status forcibly because the domain status may be
         * changed even if we attach the device failed.
         */
        if (virDomainSaveStatus(driver->xmlopt, driver->stateDir, vm) < 0)
            ret = -1;
    }

    /* Finally, if no error until here, we can save config. */
    if (!ret && (flags & VIR_DOMAIN_DEVICE_MODIFY_CONFIG)) {
        ret = virDomainSaveConfig(driver->configDir, vmdef);
        if (!ret) {
            virDomainObjAssignDef(vm, vmdef, false, NULL);
            vmdef = NULL;
        }
    }

cleanup:
    virDomainDefFree(vmdef);
    virDomainDeviceDefFree(dev);
    if (vm)
        virObjectUnlock(vm);
    libxlDriverUnlock(driver);
    return ret;
}

static int
libxlDomainAttachDevice(virDomainPtr dom, const char *xml)
{
    return libxlDomainAttachDeviceFlags(dom, xml,
                                        VIR_DOMAIN_DEVICE_MODIFY_LIVE);
}

static int
libxlDomainDetachDeviceFlags(virDomainPtr dom, const char *xml,
                             unsigned int flags)
{
    libxlDriverPrivatePtr driver = dom->conn->privateData;
    virDomainObjPtr vm = NULL;
    virDomainDefPtr vmdef = NULL;
    virDomainDeviceDefPtr dev = NULL;
    libxlDomainObjPrivatePtr priv;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_DEVICE_MODIFY_LIVE |
                  VIR_DOMAIN_DEVICE_MODIFY_CONFIG, -1);

    libxlDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s", _("no domain with matching uuid"));
        goto cleanup;
    }

    if (virDomainDetachDeviceFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (virDomainObjIsActive(vm)) {
        if (flags == VIR_DOMAIN_DEVICE_MODIFY_CURRENT)
            flags |= VIR_DOMAIN_DEVICE_MODIFY_LIVE;
    } else {
        if (flags == VIR_DOMAIN_DEVICE_MODIFY_CURRENT)
            flags |= VIR_DOMAIN_DEVICE_MODIFY_CONFIG;
        /* check consistency between flags and the vm state */
        if (flags & VIR_DOMAIN_DEVICE_MODIFY_LIVE) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           "%s", _("Domain is not running"));
            goto cleanup;
        }
    }

    if ((flags & VIR_DOMAIN_DEVICE_MODIFY_CONFIG) && !vm->persistent) {
         virReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("cannot modify device on transient domain"));
         goto cleanup;
    }

    priv = vm->privateData;

    if (flags & VIR_DOMAIN_DEVICE_MODIFY_CONFIG) {
        if (!(dev = virDomainDeviceDefParse(xml, vm->def,
                                            driver->caps, driver->xmlopt,
                                            VIR_DOMAIN_XML_INACTIVE)))
            goto cleanup;

        /* Make a copy for updated domain. */
        if (!(vmdef = virDomainObjCopyPersistentDef(vm, driver->caps,
                                                    driver->xmlopt)))
            goto cleanup;

        if ((ret = libxlDomainDetachDeviceConfig(vmdef, dev)) < 0)
            goto cleanup;
    } else {
        ret = 0;
    }

    if (flags & VIR_DOMAIN_DEVICE_MODIFY_LIVE) {
        /* If dev exists it was created to modify the domain config. Free it. */
        virDomainDeviceDefFree(dev);
        if (!(dev = virDomainDeviceDefParse(xml, vm->def,
                                            driver->caps, driver->xmlopt,
                                            VIR_DOMAIN_XML_INACTIVE)))
            goto cleanup;

        if ((ret = libxlDomainDetachDeviceLive(priv, vm, dev)) < 0)
            goto cleanup;

        /*
         * update domain status forcibly because the domain status may be
         * changed even if we attach the device failed.
         */
        if (virDomainSaveStatus(driver->xmlopt, driver->stateDir, vm) < 0)
            ret = -1;
    }

    /* Finally, if no error until here, we can save config. */
    if (!ret && (flags & VIR_DOMAIN_DEVICE_MODIFY_CONFIG)) {
        ret = virDomainSaveConfig(driver->configDir, vmdef);
        if (!ret) {
            virDomainObjAssignDef(vm, vmdef, false, NULL);
            vmdef = NULL;
        }
    }

cleanup:
    virDomainDefFree(vmdef);
    virDomainDeviceDefFree(dev);
    if (vm)
        virObjectUnlock(vm);
    libxlDriverUnlock(driver);
    return ret;
}

static int
libxlDomainDetachDevice(virDomainPtr dom, const char *xml)
{
    return libxlDomainDetachDeviceFlags(dom, xml,
                                        VIR_DOMAIN_DEVICE_MODIFY_LIVE);
}

static int
libxlDomainUpdateDeviceFlags(virDomainPtr dom, const char *xml,
                             unsigned int flags)
{
    libxlDriverPrivatePtr driver = dom->conn->privateData;
    virDomainObjPtr vm = NULL;
    virDomainDefPtr vmdef = NULL;
    virDomainDeviceDefPtr dev = NULL;
    libxlDomainObjPrivatePtr priv;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_DEVICE_MODIFY_LIVE |
                  VIR_DOMAIN_DEVICE_MODIFY_CONFIG, -1);

    libxlDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s", _("no domain with matching uuid"));
        goto cleanup;
    }

    if (virDomainUpdateDeviceFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (virDomainObjIsActive(vm)) {
        if (flags == VIR_DOMAIN_DEVICE_MODIFY_CURRENT)
            flags |= VIR_DOMAIN_DEVICE_MODIFY_LIVE;
    } else {
        if (flags == VIR_DOMAIN_DEVICE_MODIFY_CURRENT)
            flags |= VIR_DOMAIN_DEVICE_MODIFY_CONFIG;
        /* check consistency between flags and the vm state */
        if (flags & VIR_DOMAIN_DEVICE_MODIFY_LIVE) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           "%s", _("Domain is not running"));
            goto cleanup;
        }
    }

    if ((flags & VIR_DOMAIN_DEVICE_MODIFY_CONFIG) && !vm->persistent) {
         virReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("cannot modify device on transient domain"));
         goto cleanup;
    }

    priv = vm->privateData;

    if (flags & VIR_DOMAIN_DEVICE_MODIFY_CONFIG) {
        if (!(dev = virDomainDeviceDefParse(xml, vm->def,
                                            driver->caps, driver->xmlopt,
                                            VIR_DOMAIN_XML_INACTIVE)))
            goto cleanup;

        /* Make a copy for updated domain. */
        if (!(vmdef = virDomainObjCopyPersistentDef(vm, driver->caps,
                                                    driver->xmlopt)))
            goto cleanup;

        if ((ret = libxlDomainUpdateDeviceConfig(vmdef, dev)) < 0)
            goto cleanup;
    } else {
        ret = 0;
    }

    if (flags & VIR_DOMAIN_DEVICE_MODIFY_LIVE) {
        /* If dev exists it was created to modify the domain config. Free it. */
        virDomainDeviceDefFree(dev);
        if (!(dev = virDomainDeviceDefParse(xml, vm->def,
                                            driver->caps, driver->xmlopt,
                                            VIR_DOMAIN_XML_INACTIVE)))
            goto cleanup;

        if ((ret = libxlDomainUpdateDeviceLive(priv, vm, dev)) < 0)
            goto cleanup;

        /*
         * update domain status forcibly because the domain status may be
         * changed even if we attach the device failed.
         */
        if (virDomainSaveStatus(driver->xmlopt, driver->stateDir, vm) < 0)
            ret = -1;
    }

    /* Finally, if no error until here, we can save config. */
    if (!ret && (flags & VIR_DOMAIN_DEVICE_MODIFY_CONFIG)) {
        ret = virDomainSaveConfig(driver->configDir, vmdef);
        if (!ret) {
            virDomainObjAssignDef(vm, vmdef, false, NULL);
            vmdef = NULL;
        }
    }

cleanup:
    virDomainDefFree(vmdef);
    virDomainDeviceDefFree(dev);
    if (vm)
        virObjectUnlock(vm);
    libxlDriverUnlock(driver);
    return ret;
}

static unsigned long long
libxlNodeGetFreeMemory(virConnectPtr conn)
{
    libxl_physinfo phy_info;
    const libxl_version_info* ver_info;
    libxlDriverPrivatePtr driver = conn->privateData;

    if (virNodeGetFreeMemoryEnsureACL(conn) < 0)
        return 0;

    if (libxl_get_physinfo(driver->ctx, &phy_info)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("libxl_get_physinfo_info failed"));
        return 0;
    }

    if ((ver_info = libxl_get_version_info(driver->ctx)) == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("libxl_get_version_info failed"));
        return 0;
    }

    return phy_info.free_pages * ver_info->pagesize;
}

static int
libxlNodeGetCellsFreeMemory(virConnectPtr conn,
                            unsigned long long *freeMems,
                            int startCell,
                            int maxCells)
{
    int n, lastCell, numCells;
    int ret = -1, nr_nodes = 0;
    libxl_numainfo *numa_info = NULL;
    libxlDriverPrivatePtr driver = conn->privateData;

    if (virNodeGetCellsFreeMemoryEnsureACL(conn) < 0)
        return -1;

    /* Early failure is probably worth just a warning */
    numa_info = libxl_get_numainfo(driver->ctx, &nr_nodes);
    if (numa_info == NULL || nr_nodes == 0) {
        VIR_WARN("libxl_get_numainfo failed to retrieve NUMA data");
        return 0;
    }

    /* Check/sanitize the cell range */
    if (startCell > nr_nodes) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("start cell %d out of range (0-%d)"),
                       startCell, nr_nodes);
        goto cleanup;
    }
    lastCell = startCell + maxCells - 1;
    if (lastCell > nr_nodes)
        lastCell = nr_nodes;

    for (numCells = 0, n = startCell; n <= lastCell; n++) {
        if (numa_info[n].size == LIBXL_NUMAINFO_INVALID_ENTRY)
            freeMems[numCells++] = 0;
        else
            freeMems[numCells++] = numa_info[n].free;
    }
    ret = numCells;

cleanup:
    libxl_numainfo_list_free(numa_info, nr_nodes);
    return ret;
}

static int
libxlConnectDomainEventRegister(virConnectPtr conn,
                                virConnectDomainEventCallback callback, void *opaque,
                                virFreeCallback freecb)
{
    libxlDriverPrivatePtr driver = conn->privateData;
    int ret;

    if (virConnectDomainEventRegisterEnsureACL(conn) < 0)
        return -1;

    libxlDriverLock(driver);
    ret = virDomainEventStateRegister(conn,
                                      driver->domainEventState,
                                      callback, opaque, freecb);
    libxlDriverUnlock(driver);

    return ret;
}


static int
libxlConnectDomainEventDeregister(virConnectPtr conn,
                                  virConnectDomainEventCallback callback)
{
    libxlDriverPrivatePtr driver = conn->privateData;
    int ret;

    if (virConnectDomainEventDeregisterEnsureACL(conn) < 0)
        return -1;

    libxlDriverLock(driver);
    ret = virDomainEventStateDeregister(conn,
                                        driver->domainEventState,
                                        callback);
    libxlDriverUnlock(driver);

    return ret;
}

static int
libxlDomainGetAutostart(virDomainPtr dom, int *autostart)
{
    libxlDriverPrivatePtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;

    libxlDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    libxlDriverUnlock(driver);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("No domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (virDomainGetAutostartEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    *autostart = vm->autostart;
    ret = 0;

cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static int
libxlDomainSetAutostart(virDomainPtr dom, int autostart)
{
    libxlDriverPrivatePtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    char *configFile = NULL, *autostartLink = NULL;
    int ret = -1;

    libxlDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("No domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (virDomainSetAutostartEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!vm->persistent) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("cannot set autostart for transient domain"));
        goto cleanup;
    }

    autostart = (autostart != 0);

    if (vm->autostart != autostart) {
        if (!(configFile = virDomainConfigFile(driver->configDir, vm->def->name)))
            goto cleanup;
        if (!(autostartLink = virDomainConfigFile(driver->autostartDir, vm->def->name)))
            goto cleanup;

        if (autostart) {
            if (virFileMakePath(driver->autostartDir) < 0) {
                virReportSystemError(errno,
                                     _("cannot create autostart directory %s"),
                                     driver->autostartDir);
                goto cleanup;
            }

            if (symlink(configFile, autostartLink) < 0) {
                virReportSystemError(errno,
                                     _("Failed to create symlink '%s to '%s'"),
                                     autostartLink, configFile);
                goto cleanup;
            }
        } else {
            if (unlink(autostartLink) < 0 && errno != ENOENT && errno != ENOTDIR) {
                virReportSystemError(errno,
                                     _("Failed to delete symlink '%s'"),
                                     autostartLink);
                goto cleanup;
            }
        }

        vm->autostart = autostart;
    }
    ret = 0;

cleanup:
    VIR_FREE(configFile);
    VIR_FREE(autostartLink);
    if (vm)
        virObjectUnlock(vm);
    libxlDriverUnlock(driver);
    return ret;
}

static char *
libxlDomainGetSchedulerType(virDomainPtr dom, int *nparams)
{
    libxlDriverPrivatePtr driver = dom->conn->privateData;
    libxlDomainObjPrivatePtr priv;
    virDomainObjPtr vm;
    char * ret = NULL;
    const char *name = NULL;
    libxl_scheduler sched_id;

    libxlDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    libxlDriverUnlock(driver);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s", _("no domain with matching uuid"));
        goto cleanup;
    }

    if (virDomainGetSchedulerTypeEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s", _("Domain is not running"));
        goto cleanup;
    }

    priv = vm->privateData;
    sched_id = libxl_get_scheduler(priv->ctx);

    if (nparams)
        *nparams = 0;
    switch (sched_id) {
    case LIBXL_SCHEDULER_SEDF:
        name = "sedf";
        break;
    case LIBXL_SCHEDULER_CREDIT:
        name = "credit";
        if (nparams)
            *nparams = XEN_SCHED_CREDIT_NPARAM;
        break;
    case LIBXL_SCHEDULER_CREDIT2:
        name = "credit2";
        break;
    case LIBXL_SCHEDULER_ARINC653:
        name = "arinc653";
        break;
    default:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("Failed to get scheduler id for domain '%d'"
                     " with libxenlight"), dom->id);
        goto cleanup;
    }

    ignore_value(VIR_STRDUP(ret, name));

cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static int
libxlDomainGetSchedulerParametersFlags(virDomainPtr dom,
                                       virTypedParameterPtr params,
                                       int *nparams,
                                       unsigned int flags)
{
    libxlDriverPrivatePtr driver = dom->conn->privateData;
    libxlDomainObjPrivatePtr priv;
    virDomainObjPtr vm;
    libxl_domain_sched_params sc_info;
    libxl_scheduler sched_id;
    int ret = -1;

    virCheckFlags(VIR_TYPED_PARAM_STRING_OKAY, -1);

    /* We don't return strings, and thus trivially support this flag.  */
    flags &= ~VIR_TYPED_PARAM_STRING_OKAY;

    libxlDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    libxlDriverUnlock(driver);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s",
                       _("no domain with matching uuid"));
        goto cleanup;
    }

    if (virDomainGetSchedulerParametersFlagsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Domain is not running"));
        goto cleanup;
    }

    priv = vm->privateData;

    sched_id = libxl_get_scheduler(priv->ctx);

    if (sched_id != LIBXL_SCHEDULER_CREDIT) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Only 'credit' scheduler is supported"));
        goto cleanup;
    }

    if (libxl_domain_sched_params_get(priv->ctx, dom->id, &sc_info) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to get scheduler parameters for domain '%d'"
                         " with libxenlight"), dom->id);
        goto cleanup;
    }

    if (virTypedParameterAssign(&params[0], VIR_DOMAIN_SCHEDULER_WEIGHT,
                                VIR_TYPED_PARAM_UINT, sc_info.weight) < 0)
        goto cleanup;

    if (*nparams > 1) {
        if (virTypedParameterAssign(&params[0], VIR_DOMAIN_SCHEDULER_CAP,
                                    VIR_TYPED_PARAM_UINT, sc_info.cap) < 0)
            goto cleanup;
    }

    if (*nparams > XEN_SCHED_CREDIT_NPARAM)
        *nparams = XEN_SCHED_CREDIT_NPARAM;
    ret = 0;

cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static int
libxlDomainGetSchedulerParameters(virDomainPtr dom, virTypedParameterPtr params,
                                  int *nparams)
{
    return libxlDomainGetSchedulerParametersFlags(dom, params, nparams, 0);
}

static int
libxlDomainSetSchedulerParametersFlags(virDomainPtr dom,
                                       virTypedParameterPtr params,
                                       int nparams,
                                       unsigned int flags)
{
    libxlDriverPrivatePtr driver = dom->conn->privateData;
    libxlDomainObjPrivatePtr priv;
    virDomainObjPtr vm;
    libxl_domain_sched_params sc_info;
    int sched_id;
    size_t i;
    int ret = -1;

    virCheckFlags(0, -1);
    if (virTypedParamsValidate(params, nparams,
                               VIR_DOMAIN_SCHEDULER_WEIGHT,
                               VIR_TYPED_PARAM_UINT,
                               VIR_DOMAIN_SCHEDULER_CAP,
                               VIR_TYPED_PARAM_UINT,
                               NULL) < 0)
        return -1;

    libxlDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    libxlDriverUnlock(driver);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s", _("no domain with matching uuid"));
        goto cleanup;
    }

    if (virDomainSetSchedulerParametersFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s", _("Domain is not running"));
        goto cleanup;
    }

    priv = vm->privateData;

    sched_id = libxl_get_scheduler(priv->ctx);

    if (sched_id != LIBXL_SCHEDULER_CREDIT) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Only 'credit' scheduler is supported"));
        goto cleanup;
    }

    if (libxl_domain_sched_params_get(priv->ctx, dom->id, &sc_info) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to get scheduler parameters for domain '%d'"
                         " with libxenlight"), dom->id);
        goto cleanup;
    }

    for (i = 0; i < nparams; ++i) {
        virTypedParameterPtr param = &params[i];

        if (STREQ(param->field, VIR_DOMAIN_SCHEDULER_WEIGHT)) {
            sc_info.weight = params[i].value.ui;
        } else if (STREQ(param->field, VIR_DOMAIN_SCHEDULER_CAP)) {
            sc_info.cap = params[i].value.ui;
        }
    }

    if (libxl_domain_sched_params_set(priv->ctx, dom->id, &sc_info) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to set scheduler parameters for domain '%d'"
                         " with libxenlight"), dom->id);
        goto cleanup;
    }

    ret = 0;

cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static int
libxlDomainSetSchedulerParameters(virDomainPtr dom, virTypedParameterPtr params,
                                  int nparams)
{
    return libxlDomainSetSchedulerParametersFlags(dom, params, nparams, 0);
}

/* NUMA node affinity information is available through libxl
 * starting from Xen 4.3. */
#ifdef LIBXL_HAVE_DOMAIN_NODEAFFINITY

/* Number of Xen NUMA parameters */
# define LIBXL_NUMA_NPARAM 2

static int
libxlDomainGetNumaParameters(virDomainPtr dom,
                             virTypedParameterPtr params,
                             int *nparams,
                             unsigned int flags)
{
    libxlDriverPrivatePtr driver = dom->conn->privateData;
    libxlDomainObjPrivatePtr priv;
    virDomainObjPtr vm;
    libxl_bitmap nodemap;
    virBitmapPtr nodes = NULL;
    char *nodeset = NULL;
    int rc, ret = -1;
    size_t i, j;

    /* In Xen 4.3, it is possible to query the NUMA node affinity of a domain
     * via libxl, but not to change it. We therefore only allow AFFECT_LIVE. */
    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_TYPED_PARAM_STRING_OKAY, -1);

    /* We blindly return a string, and let libvirt.c and remote_driver.c do
     * the filtering on behalf of older clients that can't parse it. */
    flags &= ~VIR_TYPED_PARAM_STRING_OKAY;

    libxlDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    libxlDriverUnlock(driver);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s",
                       _("no domain with matching uuid"));
        goto cleanup;
    }

    if (virDomainGetNumaParametersEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Domain is not running"));
        goto cleanup;
    }

    priv = vm->privateData;

    libxl_bitmap_init(&nodemap);

    if ((*nparams) == 0) {
        *nparams = LIBXL_NUMA_NPARAM;
        ret = 0;
        goto cleanup;
    }

    for (i = 0; i < LIBXL_NUMA_NPARAM && i < *nparams; i++) {
        virMemoryParameterPtr param = &params[i];

        switch (i) {
        case 0:
            /* NUMA mode */

            /* Xen implements something that is really close to numactl's
             * 'interleave' policy (see `man 8 numactl' for details). */
            if (virTypedParameterAssign(param, VIR_DOMAIN_NUMA_MODE,
                                        VIR_TYPED_PARAM_INT,
                                        VIR_DOMAIN_NUMATUNE_MEM_INTERLEAVE) < 0)
                goto cleanup;

            break;

        case 1:
            /* Node affinity */

            /* Let's allocate both libxl and libvirt bitmaps */
            if (libxl_node_bitmap_alloc(priv->ctx, &nodemap, 0) ||
                !(nodes = virBitmapNew(libxl_get_max_nodes(priv->ctx)))) {
                virReportOOMError();
                goto cleanup;
            }

            rc = libxl_domain_get_nodeaffinity(priv->ctx,
                                               vm->def->id,
                                               &nodemap);
            if (rc != 0) {
                virReportSystemError(-rc, "%s",
                                     _("unable to get numa affinity"));
                goto cleanup;
            }

            /* First, we convert libxl_bitmap into virBitmap. After that,
             * we format virBitmap as a string that can be returned. */
            virBitmapClearAll(nodes);
            libxl_for_each_set_bit(j, nodemap) {
                if (virBitmapSetBit(nodes, j)) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("Node %zu out of range"), j);
                    goto cleanup;
                }
            }

            nodeset = virBitmapFormat(nodes);
            if (!nodeset && VIR_STRDUP(nodeset, "") < 0)
                goto cleanup;

            if (virTypedParameterAssign(param, VIR_DOMAIN_NUMA_NODESET,
                                        VIR_TYPED_PARAM_STRING, nodeset) < 0)
                goto cleanup;

            nodeset = NULL;

            break;

        default:
            break;
        }
    }

    if (*nparams > LIBXL_NUMA_NPARAM)
        *nparams = LIBXL_NUMA_NPARAM;
    ret = 0;

cleanup:
    VIR_FREE(nodeset);
    virBitmapFree(nodes);
    libxl_bitmap_dispose(&nodemap);
    if (vm)
        virObjectUnlock(vm);
    return ret;
}
#endif

static int
libxlDomainIsActive(virDomainPtr dom)
{
    libxlDriverPrivatePtr driver = dom->conn->privateData;
    virDomainObjPtr obj;
    int ret = -1;

    libxlDriverLock(driver);
    obj = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    libxlDriverUnlock(driver);
    if (!obj) {
        virReportError(VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }

    if (virDomainIsActiveEnsureACL(dom->conn, obj->def) < 0)
        goto cleanup;

    ret = virDomainObjIsActive(obj);

  cleanup:
    if (obj)
        virObjectUnlock(obj);
    return ret;
}

static int
libxlDomainIsPersistent(virDomainPtr dom)
{
    libxlDriverPrivatePtr driver = dom->conn->privateData;
    virDomainObjPtr obj;
    int ret = -1;

    libxlDriverLock(driver);
    obj = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    libxlDriverUnlock(driver);
    if (!obj) {
        virReportError(VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }

    if (virDomainIsPersistentEnsureACL(dom->conn, obj->def) < 0)
        goto cleanup;

    ret = obj->persistent;

  cleanup:
    if (obj)
        virObjectUnlock(obj);
    return ret;
}

static int
libxlDomainIsUpdated(virDomainPtr dom)
{
    libxlDriverPrivatePtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;

    libxlDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    libxlDriverUnlock(driver);
    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }

    if (virDomainIsUpdatedEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    ret = vm->updated;

cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static int
libxlConnectDomainEventRegisterAny(virConnectPtr conn, virDomainPtr dom, int eventID,
                                   virConnectDomainEventGenericCallback callback,
                                   void *opaque, virFreeCallback freecb)
{
    libxlDriverPrivatePtr driver = conn->privateData;
    int ret;

    if (virConnectDomainEventRegisterAnyEnsureACL(conn) < 0)
        return -1;

    libxlDriverLock(driver);
    if (virDomainEventStateRegisterID(conn,
                                      driver->domainEventState,
                                      dom, eventID, callback, opaque,
                                      freecb, &ret) < 0)
        ret = -1;
    libxlDriverUnlock(driver);

    return ret;
}


static int
libxlConnectDomainEventDeregisterAny(virConnectPtr conn, int callbackID)
{
    libxlDriverPrivatePtr driver = conn->privateData;
    int ret;

    if (virConnectDomainEventDeregisterAnyEnsureACL(conn) < 0)
        return -1;

    libxlDriverLock(driver);
    ret = virDomainEventStateDeregisterID(conn,
                                          driver->domainEventState,
                                          callbackID);
    libxlDriverUnlock(driver);

    return ret;
}


static int
libxlConnectIsAlive(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    return 1;
}

static int
libxlConnectListAllDomains(virConnectPtr conn,
                           virDomainPtr **domains,
                           unsigned int flags)
{
    libxlDriverPrivatePtr driver = conn->privateData;
    int ret = -1;

    virCheckFlags(VIR_CONNECT_LIST_DOMAINS_FILTERS_ALL, -1);

    if (virConnectListAllDomainsEnsureACL(conn) < 0)
        return -1;

    libxlDriverLock(driver);
    ret = virDomainObjListExport(driver->domains, conn, domains,
                                 virConnectListAllDomainsCheckACL, flags);
    libxlDriverUnlock(driver);

    return ret;
}

/* Which features are supported by this driver? */
static int
libxlConnectSupportsFeature(virConnectPtr conn, int feature)
{
    if (virConnectSupportsFeatureEnsureACL(conn) < 0)
        return -1;

    switch (feature) {
    case VIR_DRV_FEATURE_TYPED_PARAM_STRING:
        return 1;
    default:
        return 0;
    }
}


static virDriver libxlDriver = {
    .no = VIR_DRV_LIBXL,
    .name = "xenlight",
    .connectOpen = libxlConnectOpen, /* 0.9.0 */
    .connectClose = libxlConnectClose, /* 0.9.0 */
    .connectGetType = libxlConnectGetType, /* 0.9.0 */
    .connectGetVersion = libxlConnectGetVersion, /* 0.9.0 */
    .connectGetHostname = libxlConnectGetHostname, /* 0.9.0 */
    .connectGetSysinfo = libxlConnectGetSysinfo, /* 1.1.0 */
    .connectGetMaxVcpus = libxlConnectGetMaxVcpus, /* 0.9.0 */
    .nodeGetInfo = libxlNodeGetInfo, /* 0.9.0 */
    .connectGetCapabilities = libxlConnectGetCapabilities, /* 0.9.0 */
    .connectListDomains = libxlConnectListDomains, /* 0.9.0 */
    .connectNumOfDomains = libxlConnectNumOfDomains, /* 0.9.0 */
    .connectListAllDomains = libxlConnectListAllDomains, /* 0.9.13 */
    .domainCreateXML = libxlDomainCreateXML, /* 0.9.0 */
    .domainLookupByID = libxlDomainLookupByID, /* 0.9.0 */
    .domainLookupByUUID = libxlDomainLookupByUUID, /* 0.9.0 */
    .domainLookupByName = libxlDomainLookupByName, /* 0.9.0 */
    .domainSuspend = libxlDomainSuspend, /* 0.9.0 */
    .domainResume = libxlDomainResume, /* 0.9.0 */
    .domainShutdown = libxlDomainShutdown, /* 0.9.0 */
    .domainShutdownFlags = libxlDomainShutdownFlags, /* 0.9.10 */
    .domainReboot = libxlDomainReboot, /* 0.9.0 */
    .domainDestroy = libxlDomainDestroy, /* 0.9.0 */
    .domainDestroyFlags = libxlDomainDestroyFlags, /* 0.9.4 */
    .domainGetOSType = libxlDomainGetOSType, /* 0.9.0 */
    .domainGetMaxMemory = libxlDomainGetMaxMemory, /* 0.9.0 */
    .domainSetMaxMemory = libxlDomainSetMaxMemory, /* 0.9.2 */
    .domainSetMemory = libxlDomainSetMemory, /* 0.9.0 */
    .domainSetMemoryFlags = libxlDomainSetMemoryFlags, /* 0.9.0 */
    .domainGetInfo = libxlDomainGetInfo, /* 0.9.0 */
    .domainGetState = libxlDomainGetState, /* 0.9.2 */
    .domainSave = libxlDomainSave, /* 0.9.2 */
    .domainSaveFlags = libxlDomainSaveFlags, /* 0.9.4 */
    .domainRestore = libxlDomainRestore, /* 0.9.2 */
    .domainRestoreFlags = libxlDomainRestoreFlags, /* 0.9.4 */
    .domainCoreDump = libxlDomainCoreDump, /* 0.9.2 */
    .domainSetVcpus = libxlDomainSetVcpus, /* 0.9.0 */
    .domainSetVcpusFlags = libxlDomainSetVcpusFlags, /* 0.9.0 */
    .domainGetVcpusFlags = libxlDomainGetVcpusFlags, /* 0.9.0 */
    .domainPinVcpu = libxlDomainPinVcpu, /* 0.9.0 */
    .domainGetVcpus = libxlDomainGetVcpus, /* 0.9.0 */
    .domainGetXMLDesc = libxlDomainGetXMLDesc, /* 0.9.0 */
    .connectDomainXMLFromNative = libxlConnectDomainXMLFromNative, /* 0.9.0 */
    .connectDomainXMLToNative = libxlConnectDomainXMLToNative, /* 0.9.0 */
    .connectListDefinedDomains = libxlConnectListDefinedDomains, /* 0.9.0 */
    .connectNumOfDefinedDomains = libxlConnectNumOfDefinedDomains, /* 0.9.0 */
    .domainCreate = libxlDomainCreate, /* 0.9.0 */
    .domainCreateWithFlags = libxlDomainCreateWithFlags, /* 0.9.0 */
    .domainDefineXML = libxlDomainDefineXML, /* 0.9.0 */
    .domainUndefine = libxlDomainUndefine, /* 0.9.0 */
    .domainUndefineFlags = libxlDomainUndefineFlags, /* 0.9.4 */
    .domainAttachDevice = libxlDomainAttachDevice, /* 0.9.2 */
    .domainAttachDeviceFlags = libxlDomainAttachDeviceFlags, /* 0.9.2 */
    .domainDetachDevice = libxlDomainDetachDevice,    /* 0.9.2 */
    .domainDetachDeviceFlags = libxlDomainDetachDeviceFlags, /* 0.9.2 */
    .domainUpdateDeviceFlags = libxlDomainUpdateDeviceFlags, /* 0.9.2 */
    .domainGetAutostart = libxlDomainGetAutostart, /* 0.9.0 */
    .domainSetAutostart = libxlDomainSetAutostart, /* 0.9.0 */
    .domainGetSchedulerType = libxlDomainGetSchedulerType, /* 0.9.0 */
    .domainGetSchedulerParameters = libxlDomainGetSchedulerParameters, /* 0.9.0 */
    .domainGetSchedulerParametersFlags = libxlDomainGetSchedulerParametersFlags, /* 0.9.2 */
    .domainSetSchedulerParameters = libxlDomainSetSchedulerParameters, /* 0.9.0 */
    .domainSetSchedulerParametersFlags = libxlDomainSetSchedulerParametersFlags, /* 0.9.2 */
#ifdef LIBXL_HAVE_DOMAIN_NODEAFFINITY
    .domainGetNumaParameters = libxlDomainGetNumaParameters, /* 1.1.1 */
#endif
    .nodeGetFreeMemory = libxlNodeGetFreeMemory, /* 0.9.0 */
    .nodeGetCellsFreeMemory = libxlNodeGetCellsFreeMemory, /* 1.1.1 */
    .connectDomainEventRegister = libxlConnectDomainEventRegister, /* 0.9.0 */
    .connectDomainEventDeregister = libxlConnectDomainEventDeregister, /* 0.9.0 */
    .domainManagedSave = libxlDomainManagedSave, /* 0.9.2 */
    .domainHasManagedSaveImage = libxlDomainHasManagedSaveImage, /* 0.9.2 */
    .domainManagedSaveRemove = libxlDomainManagedSaveRemove, /* 0.9.2 */
    .domainIsActive = libxlDomainIsActive, /* 0.9.0 */
    .domainIsPersistent = libxlDomainIsPersistent, /* 0.9.0 */
    .domainIsUpdated = libxlDomainIsUpdated, /* 0.9.0 */
    .connectDomainEventRegisterAny = libxlConnectDomainEventRegisterAny, /* 0.9.0 */
    .connectDomainEventDeregisterAny = libxlConnectDomainEventDeregisterAny, /* 0.9.0 */
    .connectIsAlive = libxlConnectIsAlive, /* 0.9.8 */
    .connectSupportsFeature = libxlConnectSupportsFeature, /* 1.1.1 */
};

static virStateDriver libxlStateDriver = {
    .name = "LIBXL",
    .stateInitialize = libxlStateInitialize,
    .stateAutoStart = libxlStateAutoStart,
    .stateCleanup = libxlStateCleanup,
    .stateReload = libxlStateReload,
};


int
libxlRegister(void)
{
    if (virRegisterDriver(&libxlDriver) < 0)
        return -1;
    if (virRegisterStateDriver(&libxlStateDriver) < 0)
        return -1;

    return 0;
}
