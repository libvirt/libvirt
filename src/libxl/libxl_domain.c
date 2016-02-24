/*
 * libxl_domain.c: libxl domain object private state
 *
 * Copyright (C) 2011-2015 SUSE LINUX Products GmbH, Nuernberg, Germany.
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
 *     Jim Fehlig <jfehlig@suse.com>
 */

#include <config.h>

#include <fcntl.h>

#include "libxl_domain.h"

#include "viralloc.h"
#include "viratomic.h"
#include "virfile.h"
#include "virerror.h"
#include "virlog.h"
#include "virstring.h"
#include "virtime.h"
#include "locking/domain_lock.h"
#include "xen_common.h"

#define VIR_FROM_THIS VIR_FROM_LIBXL

VIR_LOG_INIT("libxl.libxl_domain");

VIR_ENUM_IMPL(libxlDomainJob, LIBXL_JOB_LAST,
              "none",
              "query",
              "destroy",
              "modify",
);

static virClassPtr libxlDomainObjPrivateClass;

static void
libxlDomainObjPrivateDispose(void *obj);

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

static int
libxlDomainObjInitJob(libxlDomainObjPrivatePtr priv)
{
    memset(&priv->job, 0, sizeof(priv->job));

    if (virCondInit(&priv->job.cond) < 0)
        return -1;

    if (VIR_ALLOC(priv->job.current) < 0)
        return -1;

    return 0;
}

static void
libxlDomainObjResetJob(libxlDomainObjPrivatePtr priv)
{
    struct libxlDomainJobObj *job = &priv->job;

    job->active = LIBXL_JOB_NONE;
    job->owner = 0;
}

static void
libxlDomainObjFreeJob(libxlDomainObjPrivatePtr priv)
{
    ignore_value(virCondDestroy(&priv->job.cond));
    VIR_FREE(priv->job.current);
}

/* Give up waiting for mutex after 30 seconds */
#define LIBXL_JOB_WAIT_TIME (1000ull * 30)

/*
 * obj must be locked before calling, libxlDriverPrivatePtr must NOT be locked
 *
 * This must be called by anything that will change the VM state
 * in any way
 *
 * Upon successful return, the object will have its ref count increased,
 * successful calls must be followed by EndJob eventually
 */
int
libxlDomainObjBeginJob(libxlDriverPrivatePtr driver ATTRIBUTE_UNUSED,
                       virDomainObjPtr obj,
                       enum libxlDomainJob job)
{
    libxlDomainObjPrivatePtr priv = obj->privateData;
    unsigned long long now;
    unsigned long long then;

    if (virTimeMillisNow(&now) < 0)
        return -1;
    then = now + LIBXL_JOB_WAIT_TIME;

    virObjectRef(obj);

    while (priv->job.active) {
        VIR_DEBUG("Wait normal job condition for starting job: %s",
                  libxlDomainJobTypeToString(job));
        if (virCondWaitUntil(&priv->job.cond, &obj->parent.lock, then) < 0)
            goto error;
    }

    libxlDomainObjResetJob(priv);

    VIR_DEBUG("Starting job: %s", libxlDomainJobTypeToString(job));
    priv->job.active = job;
    priv->job.owner = virThreadSelfID();
    priv->job.started = now;
    priv->job.current->type = VIR_DOMAIN_JOB_UNBOUNDED;

    return 0;

 error:
    VIR_WARN("Cannot start job (%s) for domain %s;"
             " current job is (%s) owned by (%d)",
             libxlDomainJobTypeToString(job),
             obj->def->name,
             libxlDomainJobTypeToString(priv->job.active),
             priv->job.owner);

    if (errno == ETIMEDOUT)
        virReportError(VIR_ERR_OPERATION_TIMEOUT,
                       "%s", _("cannot acquire state change lock"));
    else
        virReportSystemError(errno,
                             "%s", _("cannot acquire job mutex"));

    virObjectUnref(obj);
    return -1;
}

/*
 * obj must be locked before calling
 *
 * To be called after completing the work associated with the
 * earlier libxlDomainBeginJob() call
 *
 * Returns true if the remaining reference count on obj is
 * non-zero, false if the reference count has dropped to zero
 * and obj is disposed.
 */
bool
libxlDomainObjEndJob(libxlDriverPrivatePtr driver ATTRIBUTE_UNUSED,
                     virDomainObjPtr obj)
{
    libxlDomainObjPrivatePtr priv = obj->privateData;
    enum libxlDomainJob job = priv->job.active;

    VIR_DEBUG("Stopping job: %s",
              libxlDomainJobTypeToString(job));

    libxlDomainObjResetJob(priv);
    virCondSignal(&priv->job.cond);

    return virObjectUnref(obj);
}

int
libxlDomainJobUpdateTime(struct libxlDomainJobObj *job)
{
    virDomainJobInfoPtr jobInfo = job->current;
    unsigned long long now;

    if (!job->started)
        return 0;

    if (virTimeMillisNow(&now) < 0)
        return -1;

    if (now < job->started) {
        job->started = 0;
        return 0;
    }

    jobInfo->timeElapsed = now - job->started;
    return 0;
}

static void *
libxlDomainObjPrivateAlloc(void)
{
    libxlDomainObjPrivatePtr priv;

    if (libxlDomainObjPrivateInitialize() < 0)
        return NULL;

    if (!(priv = virObjectLockableNew(libxlDomainObjPrivateClass)))
        return NULL;

    if (!(priv->devs = virChrdevAlloc())) {
        virObjectUnref(priv);
        return NULL;
    }

    if (libxlDomainObjInitJob(priv) < 0) {
        virChrdevFree(priv->devs);
        virObjectUnref(priv);
        return NULL;
    }

    return priv;
}

static void
libxlDomainObjPrivateDispose(void *obj)
{
    libxlDomainObjPrivatePtr priv = obj;

    libxlDomainObjFreeJob(priv);
    virChrdevFree(priv->devs);
}

static void
libxlDomainObjPrivateFree(void *data)
{
    libxlDomainObjPrivatePtr priv = data;

    VIR_FREE(priv->lockState);
    virObjectUnref(priv);
}

static int
libxlDomainObjPrivateXMLParse(xmlXPathContextPtr ctxt,
                              virDomainObjPtr vm,
                              virDomainDefParserConfigPtr config ATTRIBUTE_UNUSED)
{
    libxlDomainObjPrivatePtr priv = vm->privateData;

    priv->lockState = virXPathString("string(./lockstate)", ctxt);

    return 0;
}

static int
libxlDomainObjPrivateXMLFormat(virBufferPtr buf,
                               virDomainObjPtr vm)
{
    libxlDomainObjPrivatePtr priv = vm->privateData;

    if (priv->lockState)
        virBufferAsprintf(buf, "<lockstate>%s</lockstate>\n", priv->lockState);

    return 0;
}

virDomainXMLPrivateDataCallbacks libxlDomainXMLPrivateDataCallbacks = {
    .alloc = libxlDomainObjPrivateAlloc,
    .free = libxlDomainObjPrivateFree,
    .parse = libxlDomainObjPrivateXMLParse,
    .format = libxlDomainObjPrivateXMLFormat,
};


static int
libxlDomainDeviceDefPostParse(virDomainDeviceDefPtr dev,
                              const virDomainDef *def,
                              virCapsPtr caps ATTRIBUTE_UNUSED,
                              unsigned int parseFlags ATTRIBUTE_UNUSED,
                              void *opaque ATTRIBUTE_UNUSED)
{
    if (dev->type == VIR_DOMAIN_DEVICE_CHR &&
        dev->data.chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE &&
        dev->data.chr->targetType == VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_NONE &&
        def->os.type != VIR_DOMAIN_OSTYPE_HVM)
        dev->data.chr->targetType = VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_XEN;

    if (dev->type == VIR_DOMAIN_DEVICE_NET &&
            (dev->data.net->type == VIR_DOMAIN_NET_TYPE_BRIDGE ||
             dev->data.net->type == VIR_DOMAIN_NET_TYPE_ETHERNET ||
             dev->data.net->type == VIR_DOMAIN_NET_TYPE_NETWORK)) {
        if (dev->data.net->nips > 1) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                    _("multiple IP addresses not supported on device type %s"),
                    virDomainNetTypeToString(dev->data.net->type));
            return -1;
        }
    }

    if (dev->type == VIR_DOMAIN_DEVICE_HOSTDEV ||
        (dev->type == VIR_DOMAIN_DEVICE_NET &&
         dev->data.net->type == VIR_DOMAIN_NET_TYPE_HOSTDEV)) {

        virDomainHostdevDefPtr hostdev;
        virDomainHostdevSubsysPCIPtr pcisrc;

        if (dev->type == VIR_DOMAIN_DEVICE_NET)
            hostdev = &dev->data.net->data.hostdev.def;
        else
            hostdev = dev->data.hostdev;
        pcisrc = &hostdev->source.subsys.u.pci;

        /* forbid capabilities mode hostdev in this kind of hypervisor */
        if (hostdev->mode == VIR_DOMAIN_HOSTDEV_MODE_CAPABILITIES) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("hostdev mode 'capabilities' is not "
                             "supported in %s"),
                           virDomainVirtTypeToString(def->virtType));
            return -1;
        }

        if (hostdev->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS &&
            hostdev->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI &&
            pcisrc->backend == VIR_DOMAIN_HOSTDEV_PCI_BACKEND_DEFAULT)
            pcisrc->backend = VIR_DOMAIN_HOSTDEV_PCI_BACKEND_XEN;
    }

    if (dev->type == VIR_DOMAIN_DEVICE_VIDEO && def->os.type == VIR_DOMAIN_OSTYPE_HVM) {
        int dm_type = libxlDomainGetEmulatorType(def);

        switch (dev->data.video->type) {
        case VIR_DOMAIN_VIDEO_TYPE_VGA:
        case VIR_DOMAIN_VIDEO_TYPE_XEN:
            if (dev->data.video->vram == 0) {
                if (dm_type == LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN)
                    dev->data.video->vram = 16 * 1024;
                else
                    dev->data.video->vram = 8 * 1024;
                }
            break;
        case VIR_DOMAIN_VIDEO_TYPE_CIRRUS:
            if (dev->data.video->vram == 0) {
                if (dm_type == LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN)
                    dev->data.video->vram = 8 * 1024;
                else
                    dev->data.video->vram = 4 * 1024;
            }
            break;
        case VIR_DOMAIN_VIDEO_TYPE_QXL:
            if (dev->data.video->vram == 0)
                dev->data.video->vram = 128 * 1024;
            break;
        }
    }

    if (virDomainDeviceDefCheckUnsupportedMemoryDevice(dev) < 0)
        return -1;

    return 0;
}

static int
libxlDomainDefPostParse(virDomainDefPtr def,
                        virCapsPtr caps ATTRIBUTE_UNUSED,
                        unsigned int parseFlags ATTRIBUTE_UNUSED,
                        void *opaque ATTRIBUTE_UNUSED)
{
    /* Xen PV domains always have a PV console, so add one to the domain config
     * via post-parse callback if not explicitly specified in the XML. */
    if (def->os.type != VIR_DOMAIN_OSTYPE_HVM && def->nconsoles == 0) {
        virDomainChrDefPtr chrdef;

        if (!(chrdef = virDomainChrDefNew()))
            return -1;

        chrdef->source.type = VIR_DOMAIN_CHR_TYPE_PTY;
        chrdef->deviceType = VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE;
        chrdef->target.port = 0;
        chrdef->targetType = VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_XEN;

        if (VIR_ALLOC_N(def->consoles, 1) < 0) {
            virDomainChrDefFree(chrdef);
            return -1;
        }

        def->nconsoles = 1;
        def->consoles[0] = chrdef;
    }

    /* add implicit input devices */
    if (xenDomainDefAddImplicitInputDevice(def) < 0)
        return -1;

    /* memory hotplug tunables are not supported by this driver */
    if (virDomainDefCheckUnsupportedMemoryHotplug(def) < 0)
        return -1;

    return 0;
}

virDomainDefParserConfig libxlDomainDefParserConfig = {
    .macPrefix = { 0x00, 0x16, 0x3e },
    .devicesPostParseCallback = libxlDomainDeviceDefPostParse,
    .domainPostParseCallback = libxlDomainDefPostParse,
};


struct libxlShutdownThreadInfo
{
    libxlDriverPrivatePtr driver;
    virDomainObjPtr vm;
    libxl_event *event;
};


static void
libxlDomainShutdownThread(void *opaque)
{
    struct libxlShutdownThreadInfo *shutdown_info = opaque;
    virDomainObjPtr vm = shutdown_info->vm;
    libxl_event *ev = shutdown_info->event;
    libxlDriverPrivatePtr driver = shutdown_info->driver;
    virObjectEventPtr dom_event = NULL;
    libxl_shutdown_reason xl_reason = ev->u.domain_shutdown.shutdown_reason;
    libxlDriverConfigPtr cfg;

    cfg = libxlDriverConfigGet(driver);

    if (libxlDomainObjBeginJob(driver, vm, LIBXL_JOB_MODIFY) < 0)
        goto cleanup;

    if (xl_reason == LIBXL_SHUTDOWN_REASON_POWEROFF) {
        virDomainObjSetState(vm, VIR_DOMAIN_SHUTOFF,
                             VIR_DOMAIN_SHUTOFF_SHUTDOWN);

        dom_event = virDomainEventLifecycleNewFromObj(vm,
                                           VIR_DOMAIN_EVENT_STOPPED,
                                           VIR_DOMAIN_EVENT_STOPPED_SHUTDOWN);
        switch ((virDomainLifecycleAction) vm->def->onPoweroff) {
        case VIR_DOMAIN_LIFECYCLE_DESTROY:
            goto destroy;
        case VIR_DOMAIN_LIFECYCLE_RESTART:
        case VIR_DOMAIN_LIFECYCLE_RESTART_RENAME:
            goto restart;
        case VIR_DOMAIN_LIFECYCLE_PRESERVE:
        case VIR_DOMAIN_LIFECYCLE_LAST:
            goto endjob;
        }
    } else if (xl_reason == LIBXL_SHUTDOWN_REASON_CRASH) {
        virDomainObjSetState(vm, VIR_DOMAIN_SHUTOFF,
                             VIR_DOMAIN_SHUTOFF_CRASHED);

        dom_event = virDomainEventLifecycleNewFromObj(vm,
                                           VIR_DOMAIN_EVENT_STOPPED,
                                           VIR_DOMAIN_EVENT_STOPPED_CRASHED);
        switch ((virDomainLifecycleCrashAction) vm->def->onCrash) {
        case VIR_DOMAIN_LIFECYCLE_CRASH_DESTROY:
            goto destroy;
        case VIR_DOMAIN_LIFECYCLE_CRASH_RESTART:
        case VIR_DOMAIN_LIFECYCLE_CRASH_RESTART_RENAME:
            goto restart;
        case VIR_DOMAIN_LIFECYCLE_CRASH_PRESERVE:
        case VIR_DOMAIN_LIFECYCLE_CRASH_LAST:
            goto endjob;
        case VIR_DOMAIN_LIFECYCLE_CRASH_COREDUMP_DESTROY:
            libxlDomainAutoCoreDump(driver, vm);
            goto destroy;
        case VIR_DOMAIN_LIFECYCLE_CRASH_COREDUMP_RESTART:
            libxlDomainAutoCoreDump(driver, vm);
            goto restart;
        }
    } else if (xl_reason == LIBXL_SHUTDOWN_REASON_REBOOT) {
        virDomainObjSetState(vm, VIR_DOMAIN_SHUTOFF,
                             VIR_DOMAIN_SHUTOFF_SHUTDOWN);

        dom_event = virDomainEventLifecycleNewFromObj(vm,
                                           VIR_DOMAIN_EVENT_STOPPED,
                                           VIR_DOMAIN_EVENT_STOPPED_SHUTDOWN);
        switch ((virDomainLifecycleAction) vm->def->onReboot) {
        case VIR_DOMAIN_LIFECYCLE_DESTROY:
            goto destroy;
        case VIR_DOMAIN_LIFECYCLE_RESTART:
        case VIR_DOMAIN_LIFECYCLE_RESTART_RENAME:
            goto restart;
        case VIR_DOMAIN_LIFECYCLE_PRESERVE:
        case VIR_DOMAIN_LIFECYCLE_LAST:
            goto endjob;
        }
    } else {
        VIR_INFO("Unhandled shutdown_reason %d", xl_reason);
        goto endjob;
    }

 destroy:
    if (dom_event) {
        libxlDomainEventQueue(driver, dom_event);
        dom_event = NULL;
    }
    libxlDomainDestroyInternal(driver, vm);
    libxlDomainCleanup(driver, vm);
    if (!vm->persistent)
        virDomainObjListRemove(driver->domains, vm);

    goto endjob;

 restart:
    if (dom_event) {
        libxlDomainEventQueue(driver, dom_event);
        dom_event = NULL;
    }
    libxlDomainDestroyInternal(driver, vm);
    libxlDomainCleanup(driver, vm);
    if (libxlDomainStart(driver, vm, false, -1) < 0) {
        virErrorPtr err = virGetLastError();
        VIR_ERROR(_("Failed to restart VM '%s': %s"),
                  vm->def->name, err ? err->message : _("unknown error"));
    }

 endjob:
    if (!libxlDomainObjEndJob(driver, vm))
        vm = NULL;

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    if (dom_event)
        libxlDomainEventQueue(driver, dom_event);
    libxl_event_free(cfg->ctx, ev);
    VIR_FREE(shutdown_info);
    virObjectUnref(cfg);
}

/*
 * Handle previously registered domain event notification from libxenlight.
 */
void
libxlDomainEventHandler(void *data, VIR_LIBXL_EVENT_CONST libxl_event *event)
{
    libxlDriverPrivatePtr driver = data;
    virDomainObjPtr vm = NULL;
    libxl_shutdown_reason xl_reason = event->u.domain_shutdown.shutdown_reason;
    struct libxlShutdownThreadInfo *shutdown_info = NULL;
    virThread thread;
    libxlDriverConfigPtr cfg;

    if (event->type != LIBXL_EVENT_TYPE_DOMAIN_SHUTDOWN) {
        VIR_INFO("Unhandled event type %d", event->type);
        goto error;
    }

    /*
     * Similar to the xl implementation, ignore SUSPEND.  Any actions needed
     * after calling libxl_domain_suspend() are handled by its callers.
     */
    if (xl_reason == LIBXL_SHUTDOWN_REASON_SUSPEND)
        goto error;

    vm = virDomainObjListFindByID(driver->domains, event->domid);
    if (!vm) {
        VIR_INFO("Received event for unknown domain ID %d", event->domid);
        goto error;
    }

    /*
     * Start a thread to handle shutdown.  We don't want to be tying up
     * libxl's event machinery by doing a potentially lengthy shutdown.
     */
    if (VIR_ALLOC(shutdown_info) < 0)
        goto error;

    shutdown_info->driver = driver;
    shutdown_info->vm = vm;
    shutdown_info->event = (libxl_event *)event;
    if (virThreadCreate(&thread, false, libxlDomainShutdownThread,
                        shutdown_info) < 0) {
        /*
         * Not much we can do on error here except log it.
         */
        VIR_ERROR(_("Failed to create thread to handle domain shutdown"));
        goto error;
    }

    /*
     * VM is unlocked and libxl_event freed in shutdown thread
     */
    return;

 error:
    cfg = libxlDriverConfigGet(driver);
    /* Cast away any const */
    libxl_event_free(cfg->ctx, (libxl_event *)event);
    virObjectUnref(cfg);
    if (vm)
        virObjectUnlock(vm);
    VIR_FREE(shutdown_info);
}

void
libxlDomainEventQueue(libxlDriverPrivatePtr driver, virObjectEventPtr event)
{
    virObjectEventStateQueue(driver->domainEventState, event);
}

char *
libxlDomainManagedSavePath(libxlDriverPrivatePtr driver, virDomainObjPtr vm)
{
    char *ret;
    libxlDriverConfigPtr cfg = libxlDriverConfigGet(driver);

    ignore_value(virAsprintf(&ret, "%s/%s.save", cfg->saveDir, vm->def->name));
    virObjectUnref(cfg);
    return ret;
}

/*
 * Open a saved image file and initialize domain definition from the header.
 *
 * Returns the opened fd on success, -1 on failure.
 */
int
libxlDomainSaveImageOpen(libxlDriverPrivatePtr driver,
                         libxlDriverConfigPtr cfg,
                         const char *from,
                         virDomainDefPtr *ret_def,
                         libxlSavefileHeaderPtr ret_hdr)
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

    if (!(def = virDomainDefParseString(xml, cfg->caps, driver->xmlopt,
                                        VIR_DOMAIN_DEF_PARSE_INACTIVE)))
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
 * Internal domain destroy function.
 *
 * virDomainObjPtr must be locked on invocation
 */
int
libxlDomainDestroyInternal(libxlDriverPrivatePtr driver,
                           virDomainObjPtr vm)
{
    libxlDriverConfigPtr cfg = libxlDriverConfigGet(driver);
    int ret = -1;

    /* Unlock virDomainObj during destroy, which can take considerable
     * time on large memory domains.
     */
    virObjectUnlock(vm);
    ret = libxl_domain_destroy(cfg->ctx, vm->def->id, NULL);
    virObjectLock(vm);

    virObjectUnref(cfg);
    return ret;
}

/*
 * Cleanup function for domain that has reached shutoff state.
 *
 * virDomainObjPtr must be locked on invocation
 */
void
libxlDomainCleanup(libxlDriverPrivatePtr driver,
                   virDomainObjPtr vm)
{
    libxlDomainObjPrivatePtr priv = vm->privateData;
    libxlDriverConfigPtr cfg = libxlDriverConfigGet(driver);
    int vnc_port;
    char *file;
    virHostdevManagerPtr hostdev_mgr = driver->hostdevMgr;

    virHostdevReAttachDomainDevices(hostdev_mgr, LIBXL_DRIVER_NAME,
                                    vm->def, VIR_HOSTDEV_SP_PCI, NULL);

    VIR_FREE(priv->lockState);
    if (virDomainLockProcessPause(driver->lockManager, vm, &priv->lockState) < 0)
        VIR_WARN("Unable to release lease on %s", vm->def->name);
    VIR_DEBUG("Preserving lock state '%s'", NULLSTR(priv->lockState));

    vm->def->id = -1;

    if (priv->deathW) {
        libxl_evdisable_domain_death(cfg->ctx, priv->deathW);
        priv->deathW = NULL;
    }

    if (virAtomicIntDecAndTest(&driver->nactive) && driver->inhibitCallback)
        driver->inhibitCallback(false, driver->inhibitOpaque);

    if ((vm->def->ngraphics == 1) &&
        vm->def->graphics[0]->type == VIR_DOMAIN_GRAPHICS_TYPE_VNC &&
        vm->def->graphics[0]->data.vnc.autoport) {
        vnc_port = vm->def->graphics[0]->data.vnc.port;
        if (vnc_port >= LIBXL_VNC_PORT_MIN) {
            if (virPortAllocatorRelease(driver->reservedGraphicsPorts,
                                        vnc_port) < 0)
                VIR_DEBUG("Could not mark port %d as unused", vnc_port);
        }
    }

    if ((vm->def->nnets)) {
        size_t i;

        for (i = 0; i < vm->def->nnets; i++) {
            virDomainNetDefPtr net = vm->def->nets[i];

            if (net->ifname &&
                STRPREFIX(net->ifname, LIBXL_GENERATED_PREFIX_XEN))
                VIR_FREE(net->ifname);
        }
    }

    if (virAsprintf(&file, "%s/%s.xml", cfg->stateDir, vm->def->name) > 0) {
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

    virObjectUnref(cfg);
}

/*
 * Core dump domain to default dump path.
 *
 * virDomainObjPtr must be locked on invocation
 */
int
libxlDomainAutoCoreDump(libxlDriverPrivatePtr driver,
                        virDomainObjPtr vm)
{
    libxlDriverConfigPtr cfg = libxlDriverConfigGet(driver);
    time_t curtime = time(NULL);
    char timestr[100];
    struct tm time_info;
    char *dumpfile = NULL;
    int ret = -1;

    localtime_r(&curtime, &time_info);
    strftime(timestr, sizeof(timestr), "%Y-%m-%d-%H:%M:%S", &time_info);

    if (virAsprintf(&dumpfile, "%s/%s-%s",
                    cfg->autoDumpDir,
                    vm->def->name,
                    timestr) < 0)
        goto cleanup;

    /* Unlock virDomainObj while dumping core */
    virObjectUnlock(vm);
    libxl_domain_core_dump(cfg->ctx, vm->def->id, dumpfile, NULL);
    virObjectLock(vm);

    ret = 0;

 cleanup:
    VIR_FREE(dumpfile);
    virObjectUnref(cfg);

    return ret;
}

int
libxlDomainSetVcpuAffinities(libxlDriverPrivatePtr driver, virDomainObjPtr vm)
{
    libxlDriverConfigPtr cfg = libxlDriverConfigGet(driver);
    virDomainVcpuInfoPtr vcpu;
    libxl_bitmap map;
    virBitmapPtr cpumask = NULL;
    size_t i;
    int ret = -1;

    libxl_bitmap_init(&map);

    for (i = 0; i < virDomainDefGetVcpus(vm->def); ++i) {
        vcpu = virDomainDefGetVcpu(vm->def, i);

        if (!vcpu->online)
            continue;

        if (!(cpumask = vcpu->cpumask))
            cpumask = vm->def->cpumask;

        if (!cpumask)
            continue;

        if (virBitmapToData(cpumask, &map.map, (int *)&map.size) < 0)
            goto cleanup;

        if (libxl_set_vcpuaffinity(cfg->ctx, vm->def->id, i, &map) != 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to pin vcpu '%zu' with libxenlight"), i);
            goto cleanup;
        }

        libxl_bitmap_dispose(&map); /* Also returns to freshly-init'd state */
    }

    ret = 0;

 cleanup:
    libxl_bitmap_dispose(&map);
    virObjectUnref(cfg);
    return ret;
}

static int
libxlDomainFreeMem(libxl_ctx *ctx, libxl_domain_config *d_config)
{
    uint32_t needed_mem;
    uint32_t free_mem;
    int tries = 3;
    int wait_secs = 10;

    if (libxl_domain_need_memory(ctx, &d_config->b_info, &needed_mem) < 0)
        goto error;

    do {
        if (libxl_get_free_memory(ctx, &free_mem) < 0)
            goto error;

        if (free_mem >= needed_mem)
            return 0;

        if (libxl_set_memory_target(ctx, 0, free_mem - needed_mem,
                                    /* relative */ 1, 0) < 0)
            goto error;

        if (libxl_wait_for_memory_target(ctx, 0, wait_secs) < 0)
            goto error;

        tries--;
    } while (tries > 0);

 error:
    virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                   _("Failed to balloon domain0 memory"));
    return -1;
}

static void
libxlConsoleCallback(libxl_ctx *ctx, libxl_event *ev, void *for_callback)
{
    virDomainObjPtr vm = for_callback;
    size_t i;

    virObjectLock(vm);
    for (i = 0; i < vm->def->nconsoles; i++) {
        virDomainChrDefPtr chr = vm->def->consoles[i];
        if (chr && chr->source.type == VIR_DOMAIN_CHR_TYPE_PTY) {
            libxl_console_type console_type;
            char *console = NULL;
            int ret;

            console_type =
                (chr->targetType == VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SERIAL ?
                 LIBXL_CONSOLE_TYPE_SERIAL : LIBXL_CONSOLE_TYPE_PV);
            ret = libxl_console_get_tty(ctx, ev->domid,
                                        chr->target.port, console_type,
                                        &console);
            if (!ret) {
                VIR_FREE(chr->source.data.file.path);
                if (console && console[0] != '\0') {
                    ignore_value(VIR_STRDUP(chr->source.data.file.path,
                                            console));
                }
            }
            VIR_FREE(console);
        }
    }
    virObjectUnlock(vm);
    libxl_event_free(ctx, ev);
}

/*
 * Create interface names for the network devices in parameter def.
 * Names are created with the pattern 'vif<domid>.<devid><suffix>'.
 * devid is extracted from the network devices in the d_config
 * parameter. User-provided interface names are skipped.
 */
static void
libxlDomainCreateIfaceNames(virDomainDefPtr def, libxl_domain_config *d_config)
{
    size_t i;

    for (i = 0; i < def->nnets && i < d_config->num_nics; i++) {
        virDomainNetDefPtr net = def->nets[i];
        libxl_device_nic *x_nic = &d_config->nics[i];
        const char *suffix =
            x_nic->nictype != LIBXL_NIC_TYPE_VIF ? "-emu" : "";

        if (net->ifname)
            continue;

        ignore_value(virAsprintf(&net->ifname,
                                 LIBXL_GENERATED_PREFIX_XEN "%d.%d%s",
                                 def->id, x_nic->devid, suffix));
    }
}


/*
 * Start a domain through libxenlight.
 *
 * virDomainObjPtr must be locked and a job acquired on invocation
 */
int
libxlDomainStart(libxlDriverPrivatePtr driver, virDomainObjPtr vm,
                 bool start_paused, int restore_fd)
{
    libxl_domain_config d_config;
    virDomainDefPtr def = NULL;
    virObjectEventPtr event = NULL;
    libxlSavefileHeader hdr;
    int ret = -1;
    uint32_t domid = 0;
    char *dom_xml = NULL;
    char *managed_save_path = NULL;
    int managed_save_fd = -1;
    libxlDomainObjPrivatePtr priv = vm->privateData;
    libxlDriverConfigPtr cfg;
#ifdef LIBXL_HAVE_DOMAIN_CREATE_RESTORE_PARAMS
    libxl_domain_restore_params params;
#endif
    virHostdevManagerPtr hostdev_mgr = driver->hostdevMgr;
    libxl_asyncprogress_how aop_console_how;

    libxl_domain_config_init(&d_config);

    cfg = libxlDriverConfigGet(driver);
    /* If there is a managed saved state restore it instead of starting
     * from scratch. The old state is removed once the restoring succeeded. */
    if (restore_fd < 0) {
        managed_save_path = libxlDomainManagedSavePath(driver, vm);
        if (managed_save_path == NULL)
            goto cleanup;

        if (virFileExists(managed_save_path)) {

            managed_save_fd = libxlDomainSaveImageOpen(driver, cfg,
                                                       managed_save_path,
                                                       &def, &hdr);
            if (managed_save_fd < 0)
                goto cleanup;

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
                goto cleanup;
            }

            virDomainObjAssignDef(vm, def, true, NULL);
            def = NULL;

            if (unlink(managed_save_path) < 0)
                VIR_WARN("Failed to remove the managed state %s",
                         managed_save_path);

            vm->hasManagedSave = false;
        }
        VIR_FREE(managed_save_path);
    }

    if (virDomainObjSetDefTransient(cfg->caps, driver->xmlopt,
                                    vm, true) < 0)
        goto cleanup;

    if (libxlBuildDomainConfig(driver->reservedGraphicsPorts, vm->def,
                               cfg->ctx, &d_config) < 0)
        goto cleanup;

    if (cfg->autoballoon && libxlDomainFreeMem(cfg->ctx, &d_config) < 0)
        goto cleanup;

    if (virHostdevPrepareDomainDevices(hostdev_mgr, LIBXL_DRIVER_NAME,
                                       vm->def, VIR_HOSTDEV_SP_PCI) < 0)
        goto cleanup;

    if (virDomainLockProcessStart(driver->lockManager,
                                  "xen:///system",
                                  vm,
                                  true,
                                  NULL) < 0)
        goto cleanup;

    if (virDomainLockProcessResume(driver->lockManager,
                                  "xen:///system",
                                  vm,
                                  priv->lockState) < 0)
        goto cleanup;
    VIR_FREE(priv->lockState);

    /* Unlock virDomainObj while creating the domain */
    virObjectUnlock(vm);

    aop_console_how.for_callback = vm;
    aop_console_how.callback = libxlConsoleCallback;
    if (restore_fd < 0) {
        ret = libxl_domain_create_new(cfg->ctx, &d_config,
                                      &domid, NULL, &aop_console_how);
    } else {
#ifdef LIBXL_HAVE_DOMAIN_CREATE_RESTORE_PARAMS
        params.checkpointed_stream = 0;
        ret = libxl_domain_create_restore(cfg->ctx, &d_config, &domid,
                                          restore_fd, &params, NULL,
                                          &aop_console_how);
#else
        ret = libxl_domain_create_restore(cfg->ctx, &d_config, &domid,
                                          restore_fd, NULL, &aop_console_how);
#endif
    }
    virObjectLock(vm);

    if (ret) {
        if (restore_fd < 0)
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("libxenlight failed to create new domain '%s'"),
                           d_config.c_info.name);
        else
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("libxenlight failed to restore domain '%s'"),
                           d_config.c_info.name);
        goto release_dom;
    }

    /*
     * The domain has been successfully created with libxl, so it should
     * be cleaned up if there are any subsequent failures.
     */
    vm->def->id = domid;

    /* Always enable domain death events */
    if (libxl_evenable_domain_death(cfg->ctx, vm->def->id, 0, &priv->deathW))
        goto cleanup_dom;

    libxlDomainCreateIfaceNames(vm->def, &d_config);

    if ((dom_xml = virDomainDefFormat(vm->def, cfg->caps, 0)) == NULL)
        goto cleanup_dom;

    if (libxl_userdata_store(cfg->ctx, domid, "libvirt-xml",
                             (uint8_t *)dom_xml, strlen(dom_xml) + 1)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("libxenlight failed to store userdata"));
        goto cleanup_dom;
    }

    if (libxlDomainSetVcpuAffinities(driver, vm) < 0)
        goto cleanup_dom;

    if (!start_paused) {
        libxl_domain_unpause(cfg->ctx, domid);
        virDomainObjSetState(vm, VIR_DOMAIN_RUNNING, VIR_DOMAIN_RUNNING_BOOTED);
    } else {
        virDomainObjSetState(vm, VIR_DOMAIN_PAUSED, VIR_DOMAIN_PAUSED_USER);
    }

    if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm, cfg->caps) < 0)
        goto cleanup_dom;

    if (virAtomicIntInc(&driver->nactive) == 1 && driver->inhibitCallback)
        driver->inhibitCallback(true, driver->inhibitOpaque);

    event = virDomainEventLifecycleNewFromObj(vm, VIR_DOMAIN_EVENT_STARTED,
                                     restore_fd < 0 ?
                                         VIR_DOMAIN_EVENT_STARTED_BOOTED :
                                         VIR_DOMAIN_EVENT_STARTED_RESTORED);
    if (event)
        libxlDomainEventQueue(driver, event);

    ret = 0;
    goto cleanup;

 cleanup_dom:
    ret = -1;
    if (priv->deathW) {
        libxl_evdisable_domain_death(cfg->ctx, priv->deathW);
        priv->deathW = NULL;
    }
    libxlDomainDestroyInternal(driver, vm);
    vm->def->id = -1;
    virDomainObjSetState(vm, VIR_DOMAIN_SHUTOFF, VIR_DOMAIN_SHUTOFF_FAILED);

 release_dom:
    virDomainLockProcessPause(driver->lockManager, vm, &priv->lockState);

 cleanup:
    libxl_domain_config_dispose(&d_config);
    VIR_FREE(dom_xml);
    VIR_FREE(managed_save_path);
    virDomainDefFree(def);
    VIR_FORCE_CLOSE(managed_save_fd);
    virObjectUnref(cfg);
    return ret;
}

bool
libxlDomainDefCheckABIStability(libxlDriverPrivatePtr driver,
                                virDomainDefPtr src,
                                virDomainDefPtr dst)
{
    virDomainDefPtr migratableDefSrc = NULL;
    virDomainDefPtr migratableDefDst = NULL;
    libxlDriverConfigPtr cfg = libxlDriverConfigGet(driver);
    bool ret = false;

    if (!(migratableDefSrc = virDomainDefCopy(src, cfg->caps, driver->xmlopt, true)) ||
        !(migratableDefDst = virDomainDefCopy(dst, cfg->caps, driver->xmlopt, true)))
        goto cleanup;

    ret = virDomainDefCheckABIStability(migratableDefSrc, migratableDefDst);

 cleanup:
    virDomainDefFree(migratableDefSrc);
    virDomainDefFree(migratableDefDst);
    virObjectUnref(cfg);
    return ret;
}
