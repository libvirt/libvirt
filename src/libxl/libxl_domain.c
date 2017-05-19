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
#include "libxl_capabilities.h"

#include "viralloc.h"
#include "viratomic.h"
#include "virfile.h"
#include "virerror.h"
#include "virhook.h"
#include "virlog.h"
#include "virstring.h"
#include "virtime.h"
#include "locking/domain_lock.h"
#include "xen_common.h"
#include "network/bridge_driver.h"

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
void
libxlDomainObjEndJob(libxlDriverPrivatePtr driver ATTRIBUTE_UNUSED,
                     virDomainObjPtr obj)
{
    libxlDomainObjPrivatePtr priv = obj->privateData;
    enum libxlDomainJob job = priv->job.active;

    VIR_DEBUG("Stopping job: %s",
              libxlDomainJobTypeToString(job));

    libxlDomainObjResetJob(priv);
    virCondSignal(&priv->job.cond);
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
                              void *opaque ATTRIBUTE_UNUSED,
                              void *parseOpaque ATTRIBUTE_UNUSED)
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
        if (dev->data.net->guestIP.nips > 1) {
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

    if (dev->type == VIR_DOMAIN_DEVICE_DISK) {
        virDomainDiskDefPtr disk = dev->data.disk;
        int actual_type = virStorageSourceGetActualType(disk->src);
        int format = virDomainDiskGetFormat(disk);

        /* for network-based disks, set 'qemu' as the default driver */
        if (actual_type == VIR_STORAGE_TYPE_NETWORK) {
            if (!virDomainDiskGetDriver(disk) &&
                virDomainDiskSetDriver(disk, "qemu") < 0)
                return -1;
        }

        /* xl.cfg default format is raw. See xl-disk-configuration(5) */
        if (format == VIR_STORAGE_FILE_NONE)
            virDomainDiskSetFormat(disk, VIR_STORAGE_FILE_RAW);
    }

    return 0;
}

static int
libxlDomainDefPostParse(virDomainDefPtr def,
                        virCapsPtr caps ATTRIBUTE_UNUSED,
                        unsigned int parseFlags ATTRIBUTE_UNUSED,
                        void *opaque ATTRIBUTE_UNUSED,
                        void *parseOpaque ATTRIBUTE_UNUSED)
{
    /* Xen PV domains always have a PV console, so add one to the domain config
     * via post-parse callback if not explicitly specified in the XML. */
    if (def->os.type != VIR_DOMAIN_OSTYPE_HVM && def->nconsoles == 0) {
        virDomainChrDefPtr chrdef;

        if (!(chrdef = virDomainChrDefNew(NULL)))
            return -1;

        chrdef->source->type = VIR_DOMAIN_CHR_TYPE_PTY;
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

    /* For x86_64 HVM, always enable pae */
    if (def->os.type == VIR_DOMAIN_OSTYPE_HVM &&
        def->os.arch == VIR_ARCH_X86_64) {
        def->features[VIR_DOMAIN_FEATURE_PAE] = VIR_TRISTATE_SWITCH_ON;
    }

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
    libxl_event *event;
};


static void
libxlDomainShutdownThread(void *opaque)
{
    struct libxlShutdownThreadInfo *shutdown_info = opaque;
    virDomainObjPtr vm = NULL;
    libxl_event *ev = shutdown_info->event;
    libxlDriverPrivatePtr driver = shutdown_info->driver;
    virObjectEventPtr dom_event = NULL;
    libxl_shutdown_reason xl_reason = ev->u.domain_shutdown.shutdown_reason;
    libxlDriverConfigPtr cfg;

    cfg = libxlDriverConfigGet(driver);

    vm = virDomainObjListFindByIDRef(driver->domains, ev->domid);
    if (!vm) {
        VIR_INFO("Received event for unknown domain ID %d", ev->domid);
        goto cleanup;
    }

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
    if (libxlDomainStartNew(driver, vm, false) < 0) {
        VIR_ERROR(_("Failed to restart VM '%s': %s"),
                  vm->def->name, virGetLastErrorMessage());
    }

 endjob:
    libxlDomainObjEndJob(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
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

    /*
     * Start a thread to handle shutdown.  We don't want to be tying up
     * libxl's event machinery by doing a potentially lengthy shutdown.
     */
    if (VIR_ALLOC(shutdown_info) < 0)
        goto error;

    shutdown_info->driver = driver;
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
     * libxlShutdownThreadInfo and libxl_event are freed in shutdown thread
     */
    return;

 error:
    cfg = libxlDriverConfigGet(driver);
    /* Cast away any const */
    libxl_event_free(cfg->ctx, (libxl_event *)event);
    virObjectUnref(cfg);
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

    if (!(def = virDomainDefParseString(xml, cfg->caps, driver->xmlopt, NULL,
                                        VIR_DOMAIN_DEF_PARSE_INACTIVE |
                                        VIR_DOMAIN_DEF_PARSE_SKIP_VALIDATE)))
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
    unsigned int hostdev_flags = VIR_HOSTDEV_SP_PCI;

#ifdef LIBXL_HAVE_PVUSB
    hostdev_flags |= VIR_HOSTDEV_SP_USB;
#endif

    /* now that we know it's stopped call the hook if present */
    if (virHookPresent(VIR_HOOK_DRIVER_LIBXL)) {
        char *xml = virDomainDefFormat(vm->def, cfg->caps, 0);

        /* we can't stop the operation even if the script raised an error */
        ignore_value(virHookCall(VIR_HOOK_DRIVER_LIBXL, vm->def->name,
                                 VIR_HOOK_LIBXL_OP_STOPPED, VIR_HOOK_SUBOP_END,
                                 NULL, xml, NULL));
        VIR_FREE(xml);
    }

    virHostdevReAttachDomainDevices(hostdev_mgr, LIBXL_DRIVER_NAME,
                                    vm->def, hostdev_flags, NULL);

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

            /* cleanup actual device */
            virDomainNetRemoveHostdev(vm->def, net);
            networkReleaseActualDevice(vm->def, net);
        }
    }

    if (virAsprintf(&file, "%s/%s.xml", cfg->stateDir, vm->def->name) > 0) {
        if (unlink(file) < 0 && errno != ENOENT && errno != ENOTDIR)
            VIR_DEBUG("Failed to remove domain XML for %s", vm->def->name);
        VIR_FREE(file);
    }

    /* The "release" hook cleans up additional resources */
    if (virHookPresent(VIR_HOOK_DRIVER_LIBXL)) {
        char *xml = virDomainDefFormat(vm->def, cfg->caps, 0);

        /* we can't stop the operation even if the script raised an error */
        ignore_value(virHookCall(VIR_HOOK_DRIVER_LIBXL, vm->def->name,
                                 VIR_HOOK_LIBXL_OP_RELEASE, VIR_HOOK_SUBOP_END,
                                 NULL, xml, NULL));
        VIR_FREE(xml);
    }

    libxlLoggerCloseFile(cfg->logger, vm->def->id);

    virDomainObjRemoveTransientDef(vm);
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
    virDomainVcpuDefPtr vcpu;
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
    int32_t target_mem;
    int tries = 3;
    int wait_secs = 10;

    if (libxl_domain_need_memory(ctx, &d_config->b_info, &needed_mem) < 0)
        goto error;

    do {
        if (libxl_get_free_memory(ctx, &free_mem) < 0)
            goto error;

        if (free_mem >= needed_mem)
            return 0;

        target_mem = free_mem - needed_mem;
        if (libxl_set_memory_target(ctx, 0, target_mem,
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

static int
libxlNetworkPrepareDevices(virDomainDefPtr def)
{
    size_t i;

    for (i = 0; i < def->nnets; i++) {
        virDomainNetDefPtr net = def->nets[i];
        virDomainNetType actualType;

        /* If appropriate, grab a physical device from the configured
         * network's pool of devices, or resolve bridge device name
         * to the one defined in the network definition.
         */
        if (networkAllocateActualDevice(def, net) < 0)
            return -1;

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

            if (hostdev->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS &&
                hostdev->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI)
                pcisrc->backend = VIR_DOMAIN_HOSTDEV_PCI_BACKEND_XEN;

            if (virDomainHostdevInsert(def, hostdev) < 0)
                return -1;
        }
    }
    return 0;
}

static void
libxlConsoleCallback(libxl_ctx *ctx, libxl_event *ev, void *for_callback)
{
    virDomainObjPtr vm = for_callback;
    size_t i;
    virDomainChrDefPtr chr;
    char *console = NULL;
    int ret;

    virObjectLock(vm);
    for (i = 0; i < vm->def->nconsoles; i++) {
        chr = vm->def->consoles[i];

        if (i == 0 &&
            chr->targetType == VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SERIAL)
            chr = vm->def->serials[0];

        if (chr->source->type == VIR_DOMAIN_CHR_TYPE_PTY) {
            libxl_console_type console_type;

            console_type =
                (chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL ?
                 LIBXL_CONSOLE_TYPE_SERIAL : LIBXL_CONSOLE_TYPE_PV);
            ret = libxl_console_get_tty(ctx, ev->domid,
                                        chr->target.port, console_type,
                                        &console);
            if (!ret) {
                VIR_FREE(chr->source->data.file.path);
                if (console && console[0] != '\0') {
                    ignore_value(VIR_STRDUP(chr->source->data.file.path,
                                            console));
                }
            }
            VIR_FREE(console);
        }
    }
    for (i = 0; i < vm->def->nserials; i++) {
        chr = vm->def->serials[i];

        ignore_value(virAsprintf(&chr->info.alias, "serial%zd", i));
        if (chr->source->type == VIR_DOMAIN_CHR_TYPE_PTY) {
            if (chr->source->data.file.path)
                continue;
            ret = libxl_console_get_tty(ctx, ev->domid,
                                        chr->target.port,
                                        LIBXL_CONSOLE_TYPE_SERIAL,
                                        &console);
            if (!ret) {
                VIR_FREE(chr->source->data.file.path);
                if (console && console[0] != '\0') {
                    ignore_value(VIR_STRDUP(chr->source->data.file.path,
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

static void
libxlDomainUpdateDiskParams(virDomainDefPtr def, libxl_ctx *ctx)
{
    libxl_device_disk *disks;
    int num_disks = 0;
    size_t i;
    int idx;

    disks = libxl_device_disk_list(ctx, def->id, &num_disks);
    if (!disks)
        return;

    for (i = 0; i < num_disks; i++) {
        if ((idx = virDomainDiskIndexByName(def, disks[i].vdev, false)) < 0)
            continue;

        libxlUpdateDiskDef(def->disks[idx], &disks[i]);
    }

    for (i = 0; i < num_disks; i++)
        libxl_device_disk_dispose(&disks[i]);
    VIR_FREE(disks);
}

#ifdef LIBXL_HAVE_DEVICE_CHANNEL
static void
libxlDomainCreateChannelPTY(virDomainDefPtr def, libxl_ctx *ctx)
{
    libxl_device_channel *x_channels;
    virDomainChrDefPtr chr;
    size_t i;
    int nchannels;

    x_channels = libxl_device_channel_list(ctx, def->id, &nchannels);
    if (!x_channels)
        return;

    for (i = 0; i < def->nchannels; i++) {
        libxl_channelinfo channelinfo;
        int ret;

        chr = def->channels[i];
        if (chr->source->type != VIR_DOMAIN_CHR_TYPE_PTY)
            continue;

        ret = libxl_device_channel_getinfo(ctx, def->id, &x_channels[i],
                                           &channelinfo);

        if (!ret && channelinfo.u.pty.path &&
            *channelinfo.u.pty.path != '\0') {
                VIR_FREE(chr->source->data.file.path);
                ignore_value(VIR_STRDUP(chr->source->data.file.path,
                                        channelinfo.u.pty.path));
            }
    }

    for (i = 0; i < nchannels; i++)
        libxl_device_channel_dispose(&x_channels[i]);
}
#endif

#ifdef LIBXL_HAVE_SRM_V2
# define LIBXL_DOMSTART_RESTORE_VER_ATTR /* empty */
#else
# define LIBXL_DOMSTART_RESTORE_VER_ATTR ATTRIBUTE_UNUSED
#endif

/*
 * Start a domain through libxenlight.
 *
 * virDomainObjPtr must be locked and a job acquired on invocation
 */
static int
libxlDomainStart(libxlDriverPrivatePtr driver,
                 virDomainObjPtr vm,
                 bool start_paused,
                 int restore_fd,
                 uint32_t restore_ver LIBXL_DOMSTART_RESTORE_VER_ATTR)
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
    virHostdevManagerPtr hostdev_mgr = driver->hostdevMgr;
    libxl_asyncprogress_how aop_console_how;
    libxl_domain_restore_params params;
    unsigned int hostdev_flags = VIR_HOSTDEV_SP_PCI;
    char *config_json = NULL;

#ifdef LIBXL_HAVE_PVUSB
    hostdev_flags |= VIR_HOSTDEV_SP_USB;
#endif

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
            restore_ver = hdr.version;

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

    if (virDomainObjSetDefTransient(cfg->caps, driver->xmlopt, vm) < 0)
        goto cleanup;

    /* Run an early hook to set-up missing devices */
    if (virHookPresent(VIR_HOOK_DRIVER_LIBXL)) {
        char *xml = virDomainDefFormat(vm->def, cfg->caps, 0);
        int hookret;

        hookret = virHookCall(VIR_HOOK_DRIVER_LIBXL, vm->def->name,
                              VIR_HOOK_LIBXL_OP_PREPARE, VIR_HOOK_SUBOP_BEGIN,
                              NULL, xml, NULL);
        VIR_FREE(xml);

        /*
         * If the script raised an error abort the launch
         */
        if (hookret < 0)
            goto cleanup_dom;
    }

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

    if (libxlNetworkPrepareDevices(vm->def) < 0)
        goto cleanup_dom;

    if (libxlBuildDomainConfig(driver->reservedGraphicsPorts, vm->def,
                               cfg->channelDir, cfg->ctx, cfg->caps, &d_config) < 0)
        goto cleanup_dom;

    if (cfg->autoballoon && libxlDomainFreeMem(cfg->ctx, &d_config) < 0)
        goto cleanup_dom;

    if (virHostdevPrepareDomainDevices(hostdev_mgr, LIBXL_DRIVER_NAME,
                                       vm->def, hostdev_flags) < 0)
        goto cleanup_dom;

    /* now that we know it is about to start call the hook if present */
    if (virHookPresent(VIR_HOOK_DRIVER_LIBXL)) {
        char *xml = virDomainDefFormat(vm->def, cfg->caps, 0);
        int hookret;

        hookret = virHookCall(VIR_HOOK_DRIVER_LIBXL, vm->def->name,
                              VIR_HOOK_LIBXL_OP_START, VIR_HOOK_SUBOP_BEGIN,
                              NULL, xml, NULL);
        VIR_FREE(xml);

        /*
         * If the script raised an error abort the launch
         */
        if (hookret < 0)
            goto cleanup_dom;
    }

    if (priv->hookRun) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(vm->def->uuid, uuidstr);

        VIR_WARN("Domain id='%d' name='%s' uuid='%s' is tainted: hook",
                 vm->def->id,
                 vm->def->name,
                 uuidstr);
    }

    /* Unlock virDomainObj while creating the domain */
    virObjectUnlock(vm);

    aop_console_how.for_callback = vm;
    aop_console_how.callback = libxlConsoleCallback;
    if (restore_fd < 0) {
        ret = libxl_domain_create_new(cfg->ctx, &d_config,
                                      &domid, NULL, &aop_console_how);
    } else {
        libxl_domain_restore_params_init(&params);
#ifdef LIBXL_HAVE_SRM_V2
        params.stream_version = restore_ver;
#endif
        ret = libxl_domain_create_restore(cfg->ctx, &d_config, &domid,
                                          restore_fd, &params, NULL,
                                          &aop_console_how);
        libxl_domain_restore_params_dispose(&params);
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
        goto cleanup_dom;
    }

    /*
     * The domain has been successfully created with libxl, so it should
     * be cleaned up if there are any subsequent failures.
     */
    vm->def->id = domid;
    config_json = libxl_domain_config_to_json(cfg->ctx, &d_config);

    libxlLoggerOpenFile(cfg->logger, domid, vm->def->name, config_json);

    /* Always enable domain death events */
    if (libxl_evenable_domain_death(cfg->ctx, vm->def->id, 0, &priv->deathW))
        goto destroy_dom;

    libxlDomainCreateIfaceNames(vm->def, &d_config);
    libxlDomainUpdateDiskParams(vm->def, cfg->ctx);

#ifdef LIBXL_HAVE_DEVICE_CHANNEL
    if (vm->def->nchannels > 0)
        libxlDomainCreateChannelPTY(vm->def, cfg->ctx);
#endif

    if ((dom_xml = virDomainDefFormat(vm->def, cfg->caps, 0)) == NULL)
        goto destroy_dom;

    if (libxl_userdata_store(cfg->ctx, domid, "libvirt-xml",
                             (uint8_t *)dom_xml, strlen(dom_xml) + 1)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("libxenlight failed to store userdata"));
        goto destroy_dom;
    }

    if (libxlDomainSetVcpuAffinities(driver, vm) < 0)
        goto destroy_dom;

    if (!start_paused) {
        libxl_domain_unpause(cfg->ctx, domid);
        virDomainObjSetState(vm, VIR_DOMAIN_RUNNING, VIR_DOMAIN_RUNNING_BOOTED);
    } else {
        virDomainObjSetState(vm, VIR_DOMAIN_PAUSED, VIR_DOMAIN_PAUSED_USER);
    }

    if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm, cfg->caps) < 0)
        goto destroy_dom;

    if (virAtomicIntInc(&driver->nactive) == 1 && driver->inhibitCallback)
        driver->inhibitCallback(true, driver->inhibitOpaque);

    /* finally we can call the 'started' hook script if any */
    if (virHookPresent(VIR_HOOK_DRIVER_LIBXL)) {
        char *xml = virDomainDefFormat(vm->def, cfg->caps, 0);
        int hookret;

        hookret = virHookCall(VIR_HOOK_DRIVER_LIBXL, vm->def->name,
                              VIR_HOOK_LIBXL_OP_STARTED, VIR_HOOK_SUBOP_BEGIN,
                              NULL, xml, NULL);
        VIR_FREE(xml);

        /*
         * If the script raised an error abort the launch
         */
        if (hookret < 0)
            goto cleanup_dom;
    }

    event = virDomainEventLifecycleNewFromObj(vm, VIR_DOMAIN_EVENT_STARTED,
                                     restore_fd < 0 ?
                                         VIR_DOMAIN_EVENT_STARTED_BOOTED :
                                         VIR_DOMAIN_EVENT_STARTED_RESTORED);
    if (event)
        libxlDomainEventQueue(driver, event);

    ret = 0;
    goto cleanup;

 destroy_dom:
    ret = -1;
    libxlDomainDestroyInternal(driver, vm);
    vm->def->id = -1;
    virDomainObjSetState(vm, VIR_DOMAIN_SHUTOFF, VIR_DOMAIN_SHUTOFF_FAILED);

 cleanup_dom:
    libxlDomainCleanup(driver, vm);

 cleanup:
    libxl_domain_config_dispose(&d_config);
    VIR_FREE(config_json);
    VIR_FREE(dom_xml);
    VIR_FREE(managed_save_path);
    virDomainDefFree(def);
    VIR_FORCE_CLOSE(managed_save_fd);
    virObjectUnref(cfg);
    return ret;
}

int
libxlDomainStartNew(libxlDriverPrivatePtr driver,
            virDomainObjPtr vm,
            bool start_paused)
{
    return libxlDomainStart(driver, vm, start_paused, -1, LIBXL_SAVE_VERSION);
}

int
libxlDomainStartRestore(libxlDriverPrivatePtr driver,
                        virDomainObjPtr vm,
                        bool start_paused,
                        int restore_fd,
                        uint32_t restore_ver)
{
    return libxlDomainStart(driver, vm, start_paused,
                            restore_fd, restore_ver);
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

    if (!(migratableDefSrc = virDomainDefCopy(src, cfg->caps, driver->xmlopt, NULL, true)) ||
        !(migratableDefDst = virDomainDefCopy(dst, cfg->caps, driver->xmlopt, NULL, true)))
        goto cleanup;

    ret = virDomainDefCheckABIStability(migratableDefSrc,
                                        migratableDefDst,
                                        driver->xmlopt);

 cleanup:
    virDomainDefFree(migratableDefSrc);
    virDomainDefFree(migratableDefDst);
    virObjectUnref(cfg);
    return ret;
}
