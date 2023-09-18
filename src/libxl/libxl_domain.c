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
 */

#include <config.h>

#include <fcntl.h>

#include "libxl_api_wrapper.h"
#include "libxl_domain.h"
#include "libxl_capabilities.h"

#include "datatypes.h"
#include "viralloc.h"
#include "virfile.h"
#include "virerror.h"
#include "virhook.h"
#include "virlog.h"
#include "virtime.h"
#include "locking/domain_lock.h"
#include "xen_common.h"
#include "driver.h"
#include "domain_validate.h"

#define VIR_FROM_THIS VIR_FROM_LIBXL

VIR_LOG_INIT("libxl.libxl_domain");


int
libxlDomainJobGetTimeElapsed(virDomainJobObj *job, unsigned long long *timeElapsed)
{
    unsigned long long now;

    if (!job->started)
        return 0;

    if (virTimeMillisNow(&now) < 0)
        return -1;

    if (now < job->started) {
        job->started = 0;
        return 0;
    }

    *timeElapsed = now - job->started;
    return 0;
}

static void *
libxlDomainObjPrivateAlloc(void *opaque G_GNUC_UNUSED)
{
    libxlDomainObjPrivate *priv;

    priv = g_new0(libxlDomainObjPrivate, 1);

    if (!(priv->devs = virChrdevAlloc())) {
        g_free(priv);
        return NULL;
    }

    return priv;
}

static void
libxlDomainObjPrivateFree(void *data)
{
    libxlDomainObjPrivate *priv = data;

    g_free(priv->lockState);
    virChrdevFree(priv->devs);
    g_free(priv);
}

static int
libxlDomainObjPrivateXMLParse(xmlXPathContextPtr ctxt,
                              virDomainObj *vm,
                              virDomainDefParserConfig *config G_GNUC_UNUSED)
{
    libxlDomainObjPrivate *priv = vm->privateData;

    priv->lockState = virXPathString("string(./lockstate)", ctxt);
    priv->lockProcessRunning = virXPathBoolean("boolean(./lockProcessRunning)", ctxt);

    return 0;
}

static int
libxlDomainObjPrivateXMLFormat(virBuffer *buf,
                               virDomainObj *vm)
{
    libxlDomainObjPrivate *priv = vm->privateData;

    if (priv->lockState)
        virBufferAsprintf(buf, "<lockstate>%s</lockstate>\n", priv->lockState);

    if (priv->lockProcessRunning)
        virBufferAddLit(buf, "<lockProcessRunning/>\n");

    return 0;
}

virDomainXMLPrivateDataCallbacks libxlDomainXMLPrivateDataCallbacks = {
    .alloc = libxlDomainObjPrivateAlloc,
    .free = libxlDomainObjPrivateFree,
    .parse = libxlDomainObjPrivateXMLParse,
    .format = libxlDomainObjPrivateXMLFormat,
};


static int
libxlDomainDeviceDefPostParse(virDomainDeviceDef *dev,
                              const virDomainDef *def,
                              unsigned int parseFlags G_GNUC_UNUSED,
                              void *opaque G_GNUC_UNUSED,
                              void *parseOpaque G_GNUC_UNUSED)
{
    if (dev->type == VIR_DOMAIN_DEVICE_CHR &&
        dev->data.chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE &&
        dev->data.chr->targetType == VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_NONE &&
        def->os.type != VIR_DOMAIN_OSTYPE_HVM)
        dev->data.chr->targetType = VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_XEN;

    if (dev->type == VIR_DOMAIN_DEVICE_HOSTDEV ||
        (dev->type == VIR_DOMAIN_DEVICE_NET &&
         dev->data.net->type == VIR_DOMAIN_NET_TYPE_HOSTDEV)) {

        virDomainHostdevDef *hostdev;
        virDomainHostdevSubsysPCI *pcisrc;

        if (dev->type == VIR_DOMAIN_DEVICE_NET)
            hostdev = &dev->data.net->data.hostdev.def;
        else
            hostdev = dev->data.hostdev;
        pcisrc = &hostdev->source.subsys.u.pci;

        /* forbid capabilities mode hostdev in this kind of hypervisor */
        if (hostdev->mode == VIR_DOMAIN_HOSTDEV_MODE_CAPABILITIES) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("hostdev mode 'capabilities' is not supported in %1$s"),
                           virDomainVirtTypeToString(def->virtType));
            return -1;
        }

        if (hostdev->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS &&
            hostdev->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI &&
            pcisrc->backend == VIR_DOMAIN_HOSTDEV_PCI_BACKEND_DEFAULT)
            pcisrc->backend = VIR_DOMAIN_HOSTDEV_PCI_BACKEND_XEN;
    }

    if (dev->type == VIR_DOMAIN_DEVICE_VIDEO) {
        if (dev->data.video->type == VIR_DOMAIN_VIDEO_TYPE_DEFAULT) {
            if (def->os.type == VIR_DOMAIN_OSTYPE_XEN ||
                def->os.type == VIR_DOMAIN_OSTYPE_LINUX)
                dev->data.video->type = VIR_DOMAIN_VIDEO_TYPE_XEN;
            else if (ARCH_IS_PPC64(def->os.arch))
                dev->data.video->type = VIR_DOMAIN_VIDEO_TYPE_VGA;
            else
                dev->data.video->type = VIR_DOMAIN_VIDEO_TYPE_CIRRUS;
        }

        if (def->os.type == VIR_DOMAIN_OSTYPE_HVM) {
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
                case VIR_DOMAIN_VIDEO_TYPE_DEFAULT:
                case VIR_DOMAIN_VIDEO_TYPE_VMVGA:
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
    }

    if (dev->type == VIR_DOMAIN_DEVICE_DISK) {
        virDomainDiskDef *disk = dev->data.disk;
        virStorageType actual_type = virStorageSourceGetActualType(disk->src);
        int format = virDomainDiskGetFormat(disk);

        /* for network-based disks, set 'qemu' as the default driver */
        if (actual_type == VIR_STORAGE_TYPE_NETWORK) {
            if (!virDomainDiskGetDriver(disk))
                virDomainDiskSetDriver(disk, "qemu");
        }

        /* xl.cfg default format is raw. See xl-disk-configuration(5) */
        if (format == VIR_STORAGE_FILE_NONE)
            virDomainDiskSetFormat(disk, VIR_STORAGE_FILE_RAW);
    }

    return 0;
}

static int
libxlDomainDefPostParse(virDomainDef *def,
                        unsigned int parseFlags G_GNUC_UNUSED,
                        void *opaque G_GNUC_UNUSED,
                        void *parseOpaque G_GNUC_UNUSED)
{
    /* Xen PV domains always have a PV console, so add one to the domain config
     * via post-parse callback if not explicitly specified in the XML. */
    if (def->os.type != VIR_DOMAIN_OSTYPE_HVM && def->nconsoles == 0) {
        virDomainChrDef *chrdef;

        if (!(chrdef = virDomainChrDefNew(NULL)))
            return -1;

        chrdef->source->type = VIR_DOMAIN_CHR_TYPE_PTY;
        chrdef->deviceType = VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE;
        chrdef->target.port = 0;
        chrdef->targetType = VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_XEN;

        def->consoles = g_new0(virDomainChrDef *, 1);
        def->nconsoles = 1;
        def->consoles[0] = chrdef;
    }

    /* add implicit input devices */
    if (xenDomainDefAddImplicitInputDevice(def) < 0)
        return -1;

    /* For x86_64 HVM */
    if (def->os.type == VIR_DOMAIN_OSTYPE_HVM &&
        def->os.arch == VIR_ARCH_X86_64) {
        /* always enable pae */
        def->features[VIR_DOMAIN_FEATURE_PAE] = VIR_TRISTATE_SWITCH_ON;

        /* if vnuma is effective enable acpi */
        if (virDomainNumaGetNodeCount(def->numa) > 0)
            def->features[VIR_DOMAIN_FEATURE_ACPI] = VIR_TRISTATE_SWITCH_ON;
    }

    /* add implicit balloon device */
    if (def->memballoon == NULL) {
        virDomainMemballoonDef *memballoon;
        memballoon = g_new0(virDomainMemballoonDef,
                            1);

        memballoon->model = VIR_DOMAIN_MEMBALLOON_MODEL_XEN;
        def->memballoon = memballoon;
    }

    /* add implicit xenbus device */
    if (virDomainControllerFindByType(def, VIR_DOMAIN_CONTROLLER_TYPE_XENBUS) == -1)
        if (virDomainDefAddController(def, VIR_DOMAIN_CONTROLLER_TYPE_XENBUS, -1, -1) == NULL)
            return -1;

    return 0;
}

static int
libxlDomainDefValidate(const virDomainDef *def,
                       void *opaque,
                       void *parseOpaque G_GNUC_UNUSED)
{
    libxlDriverPrivate *driver = opaque;
    g_autoptr(libxlDriverConfig) cfg = libxlDriverConfigGet(driver);
    bool reqSecureBoot = false;

    if (!virCapabilitiesDomainSupported(cfg->caps, def->os.type,
                                        def->os.arch,
                                        def->virtType))
        return -1;

    /* Xen+ovmf does not support secure boot */
    if (def->os.firmware == VIR_DOMAIN_OS_DEF_FIRMWARE_EFI) {
        if (def->os.firmwareFeatures &&
            def->os.firmwareFeatures[VIR_DOMAIN_OS_DEF_FIRMWARE_FEATURE_SECURE_BOOT])
            reqSecureBoot = true;
    }
    if (virDomainDefHasOldStyleUEFI(def)) {
        if (def->os.loader &&
            def->os.loader->secure == VIR_TRISTATE_BOOL_YES)
            reqSecureBoot = true;
    }
    if (reqSecureBoot) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Secure boot is not supported on Xen"));
        return -1;
    }

    if (def->nsounds > 0) {
        virDomainSoundDef *snd = def->sounds[0];

        switch (snd->model) {
            case VIR_DOMAIN_SOUND_MODEL_ICH6:
            case VIR_DOMAIN_SOUND_MODEL_ES1370:
            case VIR_DOMAIN_SOUND_MODEL_AC97:
            case VIR_DOMAIN_SOUND_MODEL_SB16:
                break;
            default:
            case VIR_DOMAIN_SOUND_MODEL_PCSPK:
            case VIR_DOMAIN_SOUND_MODEL_ICH7:
            case VIR_DOMAIN_SOUND_MODEL_USB:
            case VIR_DOMAIN_SOUND_MODEL_ICH9:
            case VIR_DOMAIN_SOUND_MODEL_LAST:
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                        _("unsupported audio model %1$s"),
                        virDomainSoundModelTypeToString(snd->model));
                return -1;
        }
    }

    return 0;
}

virDomainDefParserConfig libxlDomainDefParserConfig = {
    .macPrefix = { 0x00, 0x16, 0x3e },
    .netPrefix = LIBXL_GENERATED_PREFIX_XEN,
    .devicesPostParseCallback = libxlDomainDeviceDefPostParse,
    .domainPostParseCallback = libxlDomainDefPostParse,
    .domainValidateCallback = libxlDomainDefValidate,

    .features = VIR_DOMAIN_DEF_FEATURE_USER_ALIAS |
                VIR_DOMAIN_DEF_FEATURE_FW_AUTOSELECT |
                VIR_DOMAIN_DEF_FEATURE_NET_MODEL_STRING,
};


static void
libxlDomainShutdownHandleDestroy(libxlDriverPrivate *driver,
                                 virDomainObj *vm)
{
    libxlDomainDestroyInternal(driver, vm);
    libxlDomainCleanup(driver, vm);
    if (!vm->persistent)
        virDomainObjListRemove(driver->domains, vm);
}


static void
libxlDomainShutdownHandleRestart(libxlDriverPrivate *driver,
                                 virDomainObj *vm)
{
    libxlDomainDestroyInternal(driver, vm);
    libxlDomainCleanup(driver, vm);
    if (libxlDomainStartNew(driver, vm, false) < 0) {
        VIR_ERROR(_("Failed to restart VM '%1$s': %2$s"),
                  vm->def->name, virGetLastErrorMessage());
    }
}


struct libxlEventHandlerThreadInfo
{
    libxlDriverPrivate *driver;
    libxl_event *event;
};


static void
libxlDomainShutdownThread(void *opaque)
{
    struct libxlEventHandlerThreadInfo *shutdown_info = opaque;
    virDomainObj *vm = NULL;
    libxl_event *ev = shutdown_info->event;
    libxlDriverPrivate *driver = shutdown_info->driver;
    virObjectEvent *dom_event = NULL;
    libxl_shutdown_reason xl_reason = ev->u.domain_shutdown.shutdown_reason;
    g_autoptr(libxlDriverConfig) cfg = libxlDriverConfigGet(driver);
    libxl_domain_config d_config;

    libxl_domain_config_init(&d_config);

    vm = virDomainObjListFindByID(driver->domains, ev->domid);
    if (!vm) {
        /* Nothing to do if we can't find the virDomainObj */
        goto cleanup;
    }

    if (virDomainObjBeginJob(vm, VIR_JOB_MODIFY) < 0)
        goto cleanup;

    if (xl_reason == LIBXL_SHUTDOWN_REASON_POWEROFF) {
        virDomainObjSetState(vm, VIR_DOMAIN_SHUTOFF,
                             VIR_DOMAIN_SHUTOFF_SHUTDOWN);

        dom_event = virDomainEventLifecycleNewFromObj(vm,
                                           VIR_DOMAIN_EVENT_STOPPED,
                                           VIR_DOMAIN_EVENT_STOPPED_SHUTDOWN);
        switch ((virDomainLifecycleAction) vm->def->onPoweroff) {
        case VIR_DOMAIN_LIFECYCLE_ACTION_DESTROY:
            libxlDomainShutdownHandleDestroy(driver, vm);
            goto endjob;
        case VIR_DOMAIN_LIFECYCLE_ACTION_RESTART:
        case VIR_DOMAIN_LIFECYCLE_ACTION_RESTART_RENAME:
            libxlDomainShutdownHandleRestart(driver, vm);
            goto endjob;
        case VIR_DOMAIN_LIFECYCLE_ACTION_PRESERVE:
        case VIR_DOMAIN_LIFECYCLE_ACTION_COREDUMP_DESTROY:
        case VIR_DOMAIN_LIFECYCLE_ACTION_COREDUMP_RESTART:
        case VIR_DOMAIN_LIFECYCLE_ACTION_LAST:
            goto endjob;
        }
    } else if (xl_reason == LIBXL_SHUTDOWN_REASON_CRASH) {
        virDomainObjSetState(vm, VIR_DOMAIN_SHUTOFF,
                             VIR_DOMAIN_SHUTOFF_CRASHED);

        dom_event = virDomainEventLifecycleNewFromObj(vm,
                                           VIR_DOMAIN_EVENT_STOPPED,
                                           VIR_DOMAIN_EVENT_STOPPED_CRASHED);
        switch ((virDomainLifecycleAction) vm->def->onCrash) {
        case VIR_DOMAIN_LIFECYCLE_ACTION_DESTROY:
            libxlDomainShutdownHandleDestroy(driver, vm);
            goto endjob;
        case VIR_DOMAIN_LIFECYCLE_ACTION_RESTART:
        case VIR_DOMAIN_LIFECYCLE_ACTION_RESTART_RENAME:
            libxlDomainShutdownHandleRestart(driver, vm);
            goto endjob;
        case VIR_DOMAIN_LIFECYCLE_ACTION_PRESERVE:
        case VIR_DOMAIN_LIFECYCLE_ACTION_LAST:
            goto endjob;
        case VIR_DOMAIN_LIFECYCLE_ACTION_COREDUMP_DESTROY:
            libxlDomainAutoCoreDump(driver, vm);
            libxlDomainShutdownHandleDestroy(driver, vm);
            goto endjob;
        case VIR_DOMAIN_LIFECYCLE_ACTION_COREDUMP_RESTART:
            libxlDomainAutoCoreDump(driver, vm);
            libxlDomainShutdownHandleRestart(driver, vm);
            goto endjob;
        }
    } else if (xl_reason == LIBXL_SHUTDOWN_REASON_REBOOT) {
        virDomainObjSetState(vm, VIR_DOMAIN_SHUTOFF,
                             VIR_DOMAIN_SHUTOFF_SHUTDOWN);

        dom_event = virDomainEventLifecycleNewFromObj(vm,
                                           VIR_DOMAIN_EVENT_STOPPED,
                                           VIR_DOMAIN_EVENT_STOPPED_SHUTDOWN);
        switch ((virDomainLifecycleAction) vm->def->onReboot) {
        case VIR_DOMAIN_LIFECYCLE_ACTION_DESTROY:
            libxlDomainShutdownHandleDestroy(driver, vm);
            goto endjob;
        case VIR_DOMAIN_LIFECYCLE_ACTION_RESTART:
        case VIR_DOMAIN_LIFECYCLE_ACTION_RESTART_RENAME:
            libxlDomainShutdownHandleRestart(driver, vm);
            goto endjob;
        case VIR_DOMAIN_LIFECYCLE_ACTION_PRESERVE:
        case VIR_DOMAIN_LIFECYCLE_ACTION_COREDUMP_DESTROY:
        case VIR_DOMAIN_LIFECYCLE_ACTION_COREDUMP_RESTART:
        case VIR_DOMAIN_LIFECYCLE_ACTION_LAST:
            goto endjob;
        }
    } else if (xl_reason == LIBXL_SHUTDOWN_REASON_SOFT_RESET) {
        libxlDomainObjPrivate *priv = vm->privateData;

        if (libxlRetrieveDomainConfigurationWrapper(cfg->ctx, vm->def->id,
                                                    &d_config) != 0) {
            VIR_ERROR(_("Failed to retrieve config for VM '%1$s'. Unable to perform soft reset. Destroying VM"),
                      vm->def->name);
            libxlDomainShutdownHandleDestroy(driver, vm);
            goto endjob;
        }

        if (priv->deathW) {
            libxl_evdisable_domain_death(cfg->ctx, priv->deathW);
            priv->deathW = NULL;
        }

        if (libxl_domain_soft_reset(cfg->ctx, &d_config, vm->def->id,
                                    NULL, NULL) != 0) {
            VIR_ERROR(_("Failed to soft reset VM '%1$s'. Destroying VM"),
                      vm->def->name);
            libxlDomainShutdownHandleDestroy(driver, vm);
            goto endjob;
        }
        libxl_evenable_domain_death(cfg->ctx, vm->def->id, 0, &priv->deathW);
        libxlDomainUnpauseWrapper(cfg->ctx, vm->def->id);
    } else {
        VIR_INFO("Unhandled shutdown_reason %d", xl_reason);
    }

 endjob:
    virDomainObjEndJob(vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    virObjectEventStateQueue(driver->domainEventState, dom_event);
    libxl_event_free(cfg->ctx, ev);
    VIR_FREE(shutdown_info);
    libxl_domain_config_dispose(&d_config);
}

static void
libxlDomainDeathThread(void *opaque)
{
    struct libxlEventHandlerThreadInfo *death_info = opaque;
    virDomainObj *vm = NULL;
    libxl_event *ev = death_info->event;
    libxlDriverPrivate *driver = death_info->driver;
    virObjectEvent *dom_event = NULL;
    g_autoptr(libxlDriverConfig) cfg = libxlDriverConfigGet(driver);

    vm = virDomainObjListFindByID(driver->domains, ev->domid);
    if (!vm) {
        /* Nothing to do if we can't find the virDomainObj */
        goto cleanup;
    }

    if (virDomainObjBeginJob(vm, VIR_JOB_MODIFY) < 0)
        goto cleanup;

    virDomainObjSetState(vm, VIR_DOMAIN_SHUTOFF, VIR_DOMAIN_SHUTOFF_DESTROYED);
    dom_event = virDomainEventLifecycleNewFromObj(vm,
                                                  VIR_DOMAIN_EVENT_STOPPED,
                                                  VIR_DOMAIN_EVENT_STOPPED_DESTROYED);
    libxlDomainCleanup(driver, vm);
    if (!vm->persistent)
        virDomainObjListRemove(driver->domains, vm);
    virDomainObjEndJob(vm);
    virObjectEventStateQueue(driver->domainEventState, dom_event);

 cleanup:
    virDomainObjEndAPI(&vm);
    libxl_event_free(cfg->ctx, ev);
    VIR_FREE(death_info);
}


/*
 * Handle previously registered domain event notification from libxenlight.
 */
void
libxlDomainEventHandler(void *data, libxl_event *event)
{
    libxlDriverPrivate *driver = data;
    libxl_shutdown_reason xl_reason = event->u.domain_shutdown.shutdown_reason;
    g_autoptr(libxlDriverConfig) cfg = NULL;
    struct libxlEventHandlerThreadInfo *thread_info = NULL;
    virThread thread;
    g_autofree char *thread_name = NULL;

    VIR_DEBUG("Received libxl event '%d' for domid '%d'", event->type, event->domid);

    if (event->type != LIBXL_EVENT_TYPE_DOMAIN_SHUTDOWN &&
            event->type != LIBXL_EVENT_TYPE_DOMAIN_DEATH) {
        VIR_INFO("Unhandled event type %d", event->type);
        goto cleanup;
    }

    /*
     * Similar to the xl implementation, ignore SUSPEND.  Any actions needed
     * after calling libxl_domain_suspend() are handled by its callers.
     */
    if (xl_reason == LIBXL_SHUTDOWN_REASON_SUSPEND)
        goto cleanup;

    /*
     * Start event-specific threads to handle shutdown and death.
     * They are potentially lengthy operations and we don't want to be
     * blocking this event handler while they are in progress.
     */
    if (event->type == LIBXL_EVENT_TYPE_DOMAIN_SHUTDOWN) {
        thread_info = g_new0(struct libxlEventHandlerThreadInfo, 1);

        thread_info->driver = driver;
        thread_info->event = (libxl_event *)event;
        thread_name = g_strdup_printf("shutdown-event-%d", event->domid);
        /*
         * Cleanup will be handled by the shutdown thread.
         */
        if (virThreadCreateFull(&thread, false, libxlDomainShutdownThread,
                                thread_name, false, thread_info) < 0) {
            /*
             * Not much we can do on error here except log it.
             */
            VIR_ERROR(_("Failed to create thread to handle domain shutdown"));
            goto cleanup;
        }
        /*
         * libxlEventHandlerThreadInfo and libxl_event are freed in the
         * shutdown thread
         */
        return;
    } else if (event->type == LIBXL_EVENT_TYPE_DOMAIN_DEATH) {
        thread_info = g_new0(struct libxlEventHandlerThreadInfo, 1);

        thread_info->driver = driver;
        thread_info->event = (libxl_event *)event;
        thread_name = g_strdup_printf("death-event-%d", event->domid);
        /*
         * Cleanup will be handled by the death thread.
         */
        if (virThreadCreateFull(&thread, false, libxlDomainDeathThread,
                                thread_name, false, thread_info) < 0) {
            /*
             * Not much we can do on error here except log it.
             */
            VIR_ERROR(_("Failed to create thread to handle domain death"));
            goto cleanup;
        }
        /*
         * libxlEventHandlerThreadInfo and libxl_event are freed in the
         * death thread
         */
        return;
    }

 cleanup:
    VIR_FREE(thread_info);
    cfg = libxlDriverConfigGet(driver);
    /* Cast away any const */
    libxl_event_free(cfg->ctx, (libxl_event *)event);
}

char *
libxlDomainManagedSavePath(libxlDriverPrivate *driver, virDomainObj *vm)
{
    char *ret;
    g_autoptr(libxlDriverConfig) cfg = libxlDriverConfigGet(driver);

    ret = g_strdup_printf("%s/%s.save", cfg->saveDir, vm->def->name);
    return ret;
}

/*
 * Open a saved image file and initialize domain definition from the header.
 *
 * Returns the opened fd on success, -1 on failure.
 */
int
libxlDomainSaveImageOpen(libxlDriverPrivate *driver,
                         const char *from,
                         virDomainDef **ret_def,
                         libxlSavefileHeader *ret_hdr)
{
    int fd;
    g_autoptr(virDomainDef) def = NULL;
    libxlSavefileHeader hdr;
    g_autofree char *xml = NULL;

    if ((fd = virFileOpenAs(from, O_RDONLY, 0, -1, -1, 0)) < 0) {
        virReportSystemError(-fd,
                             _("Failed to open domain image file '%1$s'"), from);
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
                       _("image version is not supported (%1$d > %2$d)"),
                       hdr.version, LIBXL_SAVE_VERSION);
        goto error;
    }

    if (hdr.xmlLen <= 0) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("invalid XML length: %1$d"), hdr.xmlLen);
        goto error;
    }

    xml = g_new0(char, hdr.xmlLen);

    if (saferead(fd, xml, hdr.xmlLen) != hdr.xmlLen) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s", _("failed to read XML"));
        goto error;
    }

    if (!(def = virDomainDefParseString(xml, driver->xmlopt, NULL,
                                        VIR_DOMAIN_DEF_PARSE_INACTIVE |
                                        VIR_DOMAIN_DEF_PARSE_SKIP_VALIDATE)))
        goto error;

    *ret_def = g_steal_pointer(&def);
    *ret_hdr = hdr;

    return fd;

 error:
    VIR_FORCE_CLOSE(fd);
    return -1;
}

static void
libxlNetworkUnwindDevices(virDomainDef *def)
{
    if (def->nnets) {
        size_t i;

        for (i = 0; i < def->nnets; i++) {
            virDomainNetDef *net = def->nets[i];

            if (net->ifname &&
                STRPREFIX(net->ifname, LIBXL_GENERATED_PREFIX_XEN))
                VIR_FREE(net->ifname);

            /* cleanup actual device */
            virDomainNetRemoveHostdev(def, net);
            if (net->type == VIR_DOMAIN_NET_TYPE_NETWORK) {
                g_autoptr(virConnect) conn = virGetConnectNetwork();

                if (conn)
                    virDomainNetReleaseActualDevice(conn, def, net);
                else
                    VIR_WARN("Unable to release network device '%s'", NULLSTR(net->ifname));
            }
        }
    }
}

int
libxlDomainHookRun(libxlDriverPrivate *driver,
                   virDomainDef *def,
                   unsigned int def_fmtflags,
                   int hookop,
                   int hooksubop,
                   char **output)
{
    g_autofree char *xml = NULL;

    if (!virHookPresent(VIR_HOOK_DRIVER_LIBXL))
        return 0;

    xml = virDomainDefFormat(def, driver->xmlopt, def_fmtflags);
    return virHookCall(VIR_HOOK_DRIVER_LIBXL, def->name,
                       hookop, hooksubop,
                       NULL, xml, output);
}

/*
 * Internal domain destroy function.
 *
 * virDomainObj *must be locked on invocation
 */
int
libxlDomainDestroyInternal(libxlDriverPrivate *driver,
                           virDomainObj *vm)
{
    g_autoptr(libxlDriverConfig) cfg = libxlDriverConfigGet(driver);
    libxlDomainObjPrivate *priv = vm->privateData;
    int ret = -1;

    if (priv->deathW) {
        libxl_evdisable_domain_death(cfg->ctx, priv->deathW);
        priv->deathW = NULL;
    }

    /* Unlock virDomainObj during destroy, which can take considerable
     * time on large memory domains.
     */
    virObjectUnlock(vm);
    ret = libxl_domain_destroy(cfg->ctx, vm->def->id, NULL);
    virObjectLock(vm);

    return ret;
}

/*
 * Cleanup function for domain that has reached shutoff state.
 *
 * virDomainObj *must be locked on invocation
 */
void
libxlDomainCleanup(libxlDriverPrivate *driver,
                   virDomainObj *vm)
{
    libxlDomainObjPrivate *priv = vm->privateData;
    g_autoptr(libxlDriverConfig) cfg = libxlDriverConfigGet(driver);
    char *file;
    virHostdevManager *hostdev_mgr = driver->hostdevMgr;
    unsigned int hostdev_flags = VIR_HOSTDEV_SP_PCI;
    size_t i;
    virErrorPtr save_err;

    VIR_DEBUG("Cleaning up domain with id '%d' and name '%s'",
              vm->def->id, vm->def->name);

    virErrorPreserveLast(&save_err);

    hostdev_flags |= VIR_HOSTDEV_SP_USB;

    /* Call hook with stopped operation. Ignore error and continue with cleanup */
    ignore_value(libxlDomainHookRun(driver, vm->def, 0,
                                    VIR_HOOK_LIBXL_OP_STOPPED,
                                    VIR_HOOK_SUBOP_END, NULL));

    virHostdevReAttachDomainDevices(hostdev_mgr, LIBXL_DRIVER_INTERNAL_NAME,
                                    vm->def, hostdev_flags);

    if (priv->lockProcessRunning) {
        VIR_FREE(priv->lockState);
        if (virDomainLockProcessPause(driver->lockManager, vm, &priv->lockState) < 0)
            VIR_WARN("Unable to release lease on %s", vm->def->name);
        else
            priv->lockProcessRunning = false;
        VIR_DEBUG("Preserving lock state '%s'", NULLSTR(priv->lockState));
    }

    libxlLoggerCloseFile(cfg->logger, vm->def->id);
    vm->def->id = -1;

    if (priv->deathW) {
        libxl_evdisable_domain_death(cfg->ctx, priv->deathW);
        priv->deathW = NULL;
    }

    if (!!g_atomic_int_dec_and_test(&driver->nactive) && driver->inhibitCallback)
        driver->inhibitCallback(false, driver->inhibitOpaque);

    /* Release auto-allocated graphics ports */
    for (i = 0; i < vm->def->ngraphics; i++) {
        virDomainGraphicsDef *graphics = vm->def->graphics[i];
        int gport = -1;

        switch (graphics->type) {
        case VIR_DOMAIN_GRAPHICS_TYPE_VNC:
            if (graphics->data.vnc.autoport &&
                graphics->data.vnc.port >= LIBXL_VNC_PORT_MIN)
                gport = graphics->data.vnc.port;
            break;
        case VIR_DOMAIN_GRAPHICS_TYPE_SPICE:
            if (graphics->data.spice.autoport)
                gport = graphics->data.spice.port;
            break;
        case VIR_DOMAIN_GRAPHICS_TYPE_SDL:
        case VIR_DOMAIN_GRAPHICS_TYPE_RDP:
        case VIR_DOMAIN_GRAPHICS_TYPE_DESKTOP:
        case VIR_DOMAIN_GRAPHICS_TYPE_EGL_HEADLESS:
        case VIR_DOMAIN_GRAPHICS_TYPE_DBUS:
        case VIR_DOMAIN_GRAPHICS_TYPE_LAST:
            break;
        }
        if (gport != -1) {
            if (virPortAllocatorRelease(gport) < 0)
                VIR_DEBUG("Could not mark port %d as unused", gport);
        }
    }

    libxlNetworkUnwindDevices(vm->def);

    file = g_strdup_printf("%s/%s.xml", cfg->stateDir, vm->def->name);
    if (unlink(file) < 0 && errno != ENOENT && errno != ENOTDIR)
        VIR_DEBUG("Failed to remove domain XML for %s", vm->def->name);
    VIR_FREE(file);

    /* Call hook with release operation. Ignore error and continue with cleanup */
    ignore_value(libxlDomainHookRun(driver, vm->def, 0,
                                    VIR_HOOK_LIBXL_OP_RELEASE,
                                    VIR_HOOK_SUBOP_END, NULL));

    virDomainObjRemoveTransientDef(vm);
    virErrorRestore(&save_err);
}

/*
 * Core dump domain to default dump path.
 *
 * virDomainObj *must be locked on invocation
 */
int
libxlDomainAutoCoreDump(libxlDriverPrivate *driver,
                        virDomainObj *vm)
{
    g_autoptr(libxlDriverConfig) cfg = libxlDriverConfigGet(driver);
    g_autoptr(GDateTime) now = g_date_time_new_now_local();
    g_autofree char *nowstr = NULL;
    g_autofree char *dumpfile = NULL;

    nowstr = g_date_time_format(now, "%Y-%m-%d-%H:%M:%S");

    dumpfile = g_strdup_printf("%s/%s-%s", cfg->autoDumpDir, vm->def->name,
                               nowstr);

    /* Unlock virDomainObj while dumping core */
    virObjectUnlock(vm);
    libxl_domain_core_dump(cfg->ctx, vm->def->id, dumpfile, NULL);
    virObjectLock(vm);

    return 0;
}

static int
libxlDomainFreeMem(libxl_ctx *ctx, libxl_domain_config *d_config)
{
    uint64_t needed_mem;
    uint64_t free_mem;
    int64_t target_mem;
    int tries = 3;
    int wait_secs = 10;

    if (libxlDomainNeedMemoryWrapper(ctx, d_config, &needed_mem) < 0)
        goto error;

    do {
        if (libxlGetFreeMemoryWrapper(ctx, &free_mem) < 0)
            goto error;

        if (free_mem >= needed_mem)
            return 0;

        target_mem = free_mem - needed_mem;
        if (libxlSetMemoryTargetWrapper(ctx, 0, target_mem,
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
libxlNetworkPrepareDevices(virDomainDef *def)
{
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

        /* final validation now that actual type is known */
        if (virDomainActualNetDefValidate(net) < 0)
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
            virDomainHostdevDef *hostdev = virDomainNetGetActualHostdev(net);
            virDomainHostdevSubsysPCI *pcisrc = &hostdev->source.subsys.u.pci;

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
    virDomainObj *vm = for_callback;
    size_t i;
    virDomainChrDef *chr;
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
                if (console && console[0] != '\0')
                    chr->source->data.file.path = g_strdup(console);
            }
            VIR_FREE(console);
        }
    }
    for (i = 0; i < vm->def->nserials; i++) {
        chr = vm->def->serials[i];

        chr->info.alias = g_strdup_printf("serial%zd", i);
        if (chr->source->type == VIR_DOMAIN_CHR_TYPE_PTY) {
            if (chr->source->data.file.path)
                continue;
            ret = libxl_console_get_tty(ctx, ev->domid,
                                        chr->target.port,
                                        LIBXL_CONSOLE_TYPE_SERIAL,
                                        &console);
            if (!ret) {
                VIR_FREE(chr->source->data.file.path);
                if (console && console[0] != '\0')
                    chr->source->data.file.path = g_strdup(console);
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
libxlDomainCreateIfaceNames(virDomainDef *def, libxl_domain_config *d_config)
{
    size_t i;

    for (i = 0; i < def->nnets && i < d_config->num_nics; i++) {
        virDomainNetDef *net = def->nets[i];
        libxl_device_nic *x_nic = &d_config->nics[i];
        const char *suffix =
            x_nic->nictype != LIBXL_NIC_TYPE_VIF ? "-emu" : "";

        if (net->ifname)
            continue;

        net->ifname = g_strdup_printf(LIBXL_GENERATED_PREFIX_XEN "%d.%d%s",
                                      def->id, x_nic->devid, suffix);
    }
}

static void
libxlDomainUpdateDiskParams(virDomainDef *def, libxl_ctx *ctx)
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

static void
libxlDomainCreateChannelPTY(virDomainDef *def, libxl_ctx *ctx)
{
    libxl_device_channel *x_channels;
    virDomainChrDef *chr;
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
                chr->source->data.file.path = g_strdup(channelinfo.u.pty.path);
            }
    }

    for (i = 0; i < nchannels; i++)
        libxl_device_channel_dispose(&x_channels[i]);
}

static int
libxlDomainStartPrepare(libxlDriverPrivate *driver,
                        virDomainObj *vm)
{
    virHostdevManager *hostdev_mgr = driver->hostdevMgr;
    unsigned int hostdev_flags = VIR_HOSTDEV_SP_PCI | VIR_HOSTDEV_SP_USB;
    virErrorPtr save_err;

    if (virDomainObjSetDefTransient(driver->xmlopt, vm, NULL) < 0)
        return -1;

    /* Run an early hook to set-up missing devices */
    if (libxlDomainHookRun(driver, vm->def, 0,
                           VIR_HOOK_LIBXL_OP_PREPARE,
                           VIR_HOOK_SUBOP_BEGIN, NULL) < 0)
        goto error;

    if (virDomainLockProcessStart(driver->lockManager,
                                  "xen:///system",
                                  vm,
                                  true,
                                  NULL) < 0)
        goto error;

    if (libxlNetworkPrepareDevices(vm->def) < 0)
        goto error;

    if (virHostdevPrepareDomainDevices(hostdev_mgr, LIBXL_DRIVER_INTERNAL_NAME,
                                       vm->def, hostdev_flags) < 0)
        goto error;

    return 0;

 error:
    virErrorPreserveLast(&save_err);
    libxlNetworkUnwindDevices(vm->def);
    virHostdevReAttachDomainDevices(hostdev_mgr, LIBXL_DRIVER_INTERNAL_NAME,
                                    vm->def, hostdev_flags);
    virDomainObjRemoveTransientDef(vm);
    virErrorRestore(&save_err);
    return -1;
}

static int
libxlDomainStartPerform(libxlDriverPrivate *driver,
                        virDomainObj *vm,
                        bool start_paused,
                        int restore_fd,
                        uint32_t restore_ver)
{
    libxl_domain_config d_config;
    int ret = -1;
    int libxlret = -1;
    uint32_t domid = 0;
    g_autofree char *dom_xml = NULL;
    libxlDomainObjPrivate *priv = vm->privateData;
    g_autoptr(libxlDriverConfig) cfg = libxlDriverConfigGet(driver);
    libxl_asyncprogress_how aop_console_how;
    libxl_domain_restore_params params;
    g_autofree char *config_json = NULL;

    libxl_domain_config_init(&d_config);

    if (libxlBuildDomainConfig(driver->reservedGraphicsPorts, vm->def,
                               cfg, &d_config) < 0)
        goto cleanup;

    if (cfg->autoballoon && libxlDomainFreeMem(cfg->ctx, &d_config) < 0)
        goto cleanup;

    /* now that we know it is about to start call the hook if present */
    if (libxlDomainHookRun(driver, vm->def, 0,
                           VIR_HOOK_LIBXL_OP_START,
                           VIR_HOOK_SUBOP_BEGIN, NULL) < 0)
        goto cleanup;

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
        libxlret = libxl_domain_create_new(cfg->ctx, &d_config,
                                      &domid, NULL, &aop_console_how);
    } else {
        libxl_domain_restore_params_init(&params);
        params.stream_version = restore_ver;
        libxlret = libxlDomainCreateRestoreWrapper(cfg->ctx, &d_config, &domid,
                                              restore_fd, &params,
                                          &aop_console_how);
        libxl_domain_restore_params_dispose(&params);
    }
    virObjectLock(vm);

    if (libxlret) {
        if (restore_fd < 0)
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("libxenlight failed to create new domain '%1$s'"),
                           d_config.c_info.name);
        else
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("libxenlight failed to restore domain '%1$s'"),
                           d_config.c_info.name);
        goto cleanup;
    }

    /*
     * The domain has been successfully created with libxl, so it should
     * be cleaned up if there are any subsequent failures.
     */
    vm->def->id = domid;
    config_json = libxl_domain_config_to_json(cfg->ctx, &d_config);

    libxlLoggerOpenFile(cfg->logger, domid, vm->def->name, config_json);

    if (virDomainLockProcessResume(driver->lockManager,
                                  "xen:///system",
                                  vm,
                                  priv->lockState) < 0)
        goto destroy_dom;
    VIR_FREE(priv->lockState);
    priv->lockProcessRunning = true;

    /* Always enable domain death events */
    if (libxl_evenable_domain_death(cfg->ctx, vm->def->id, 0, &priv->deathW))
        goto destroy_dom;

    libxlDomainCreateIfaceNames(vm->def, &d_config);
    libxlDomainUpdateDiskParams(vm->def, cfg->ctx);

    if (vm->def->nchannels > 0)
        libxlDomainCreateChannelPTY(vm->def, cfg->ctx);

    if ((dom_xml = virDomainDefFormat(vm->def, driver->xmlopt, 0)) == NULL)
        goto destroy_dom;

    if (libxl_userdata_store(cfg->ctx, domid, "libvirt-xml",
                             (uint8_t *)dom_xml, strlen(dom_xml) + 1)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("libxenlight failed to store userdata"));
        goto destroy_dom;
    }

    if (!start_paused) {
        libxlDomainUnpauseWrapper(cfg->ctx, domid);
        virDomainObjSetState(vm, VIR_DOMAIN_RUNNING, VIR_DOMAIN_RUNNING_BOOTED);
    } else {
        virDomainObjSetState(vm, VIR_DOMAIN_PAUSED, VIR_DOMAIN_PAUSED_USER);
    }

    if (virDomainObjSave(vm, driver->xmlopt, cfg->stateDir) < 0)
        goto destroy_dom;

    /* finally we can call the 'started' hook script if any */
    if (libxlDomainHookRun(driver, vm->def, 0,
                           VIR_HOOK_LIBXL_OP_STARTED,
                           VIR_HOOK_SUBOP_BEGIN, NULL) < 0)
        goto destroy_dom;

    ret = 0;
    goto cleanup;

 destroy_dom:
    libxlDomainDestroyInternal(driver, vm);
    vm->def->id = -1;
    virDomainObjSetState(vm, VIR_DOMAIN_SHUTOFF, VIR_DOMAIN_SHUTOFF_FAILED);

 cleanup:
    libxl_domain_config_dispose(&d_config);
    return ret;
}

/*
 * Start a domain through libxenlight.
 *
 * virDomainObj must be locked and a job acquired on invocation
 */
static int
libxlDomainStart(libxlDriverPrivate *driver,
                 virDomainObj *vm,
                 bool start_paused,
                 int restore_fd,
                 uint32_t restore_ver)
{
    virObjectEvent *event = NULL;

    if (libxlDomainStartPrepare(driver, vm) < 0)
        return -1;

    if (libxlDomainStartPerform(driver, vm, start_paused,
                                restore_fd, restore_ver) < 0) {
        libxlDomainCleanup(driver, vm);
        return -1;
    }

    if (g_atomic_int_add(&driver->nactive, 1) == 0 && driver->inhibitCallback)
        driver->inhibitCallback(true, driver->inhibitOpaque);

    event = virDomainEventLifecycleNewFromObj(vm, VIR_DOMAIN_EVENT_STARTED,
                                              restore_fd < 0 ?
                                              VIR_DOMAIN_EVENT_STARTED_BOOTED :
                                              VIR_DOMAIN_EVENT_STARTED_RESTORED);
    virObjectEventStateQueue(driver->domainEventState, event);

    return 0;
}

int
libxlDomainStartNew(libxlDriverPrivate *driver,
            virDomainObj *vm,
            bool start_paused)
{
    g_autofree char *managed_save_path = NULL;
    int restore_fd = -1;
    g_autoptr(virDomainDef) def = NULL;
    libxlSavefileHeader hdr;
    uint32_t restore_ver = LIBXL_SAVE_VERSION;
    int ret = -1;

    /* If there is a managed saved state restore it instead of starting
     * from scratch. The old state is removed once the restoring succeeded. */
    managed_save_path = libxlDomainManagedSavePath(driver, vm);
    if (managed_save_path == NULL)
        return -1;

    if (virFileExists(managed_save_path)) {
        restore_fd = libxlDomainSaveImageOpen(driver, managed_save_path,
                                              &def, &hdr);
        if (restore_fd < 0)
            goto cleanup;

        restore_ver = hdr.version;

        if (STRNEQ(vm->def->name, def->name) ||
            memcmp(vm->def->uuid, def->uuid, VIR_UUID_BUFLEN)) {
            char vm_uuidstr[VIR_UUID_STRING_BUFLEN];
            char def_uuidstr[VIR_UUID_STRING_BUFLEN];
            virUUIDFormat(vm->def->uuid, vm_uuidstr);
            virUUIDFormat(def->uuid, def_uuidstr);
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("cannot restore domain '%1$s' uuid %2$s from a file which belongs to domain '%3$s' uuid %4$s"),
                           vm->def->name, vm_uuidstr, def->name, def_uuidstr);
            goto cleanup;
        }

        virDomainObjAssignDef(vm, &def, true, NULL);

        if (unlink(managed_save_path) < 0)
            VIR_WARN("Failed to remove the managed state %s",
                     managed_save_path);

        vm->hasManagedSave = false;
    }

    ret = libxlDomainStart(driver, vm, start_paused, restore_fd, restore_ver);

 cleanup:
    VIR_FORCE_CLOSE(restore_fd);
    return ret;
}

int
libxlDomainStartRestore(libxlDriverPrivate *driver,
                        virDomainObj *vm,
                        bool start_paused,
                        int restore_fd,
                        uint32_t restore_ver)
{
    return libxlDomainStart(driver, vm, start_paused,
                            restore_fd, restore_ver);
}

bool
libxlDomainDefCheckABIStability(libxlDriverPrivate *driver,
                                virDomainDef *src,
                                virDomainDef *dst)
{
    g_autoptr(virDomainDef) migratableDefSrc = NULL;
    g_autoptr(virDomainDef) migratableDefDst = NULL;

    if (!(migratableDefSrc = virDomainDefCopy(src, driver->xmlopt, NULL, true)) ||
        !(migratableDefDst = virDomainDefCopy(dst, driver->xmlopt, NULL, true)))
        return false;

    return virDomainDefCheckABIStability(migratableDefSrc,
                                         migratableDefDst,
                                         driver->xmlopt);
}


static void
libxlDomainDefNamespaceFree(void *nsdata)
{
    libxlDomainXmlNsDef *def = nsdata;

    if (!def)
        return;

    g_strfreev(def->args);
    g_free(def);
}


static int
libxlDomainDefNamespaceParse(xmlXPathContextPtr ctxt,
                             void **data)
{
    libxlDomainXmlNsDef *nsdata = NULL;
    g_autofree xmlNodePtr *nodes = NULL;
    ssize_t nnodes;
    size_t i;
    int ret = -1;

    if ((nnodes = virXPathNodeSet("./xen:commandline/xen:arg", ctxt, &nodes)) < 0)
        return -1;

    if (nnodes == 0)
        return 0;

    nsdata = g_new0(libxlDomainXmlNsDef, 1);
    nsdata->args = g_new0(char *, nnodes + 1);

    for (i = 0; i < nnodes; i++) {
        if (!(nsdata->args[nsdata->num_args++] = virXMLPropString(nodes[i], "value"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("No device model command-line argument specified"));
            goto cleanup;
        }
    }

    *data = g_steal_pointer(&nsdata);
    ret = 0;

 cleanup:
    libxlDomainDefNamespaceFree(nsdata);
    return ret;
}


static int
libxlDomainDefNamespaceFormatXML(virBuffer *buf,
                                 void *nsdata)
{
    libxlDomainXmlNsDef *cmd = nsdata;
    size_t i;

    if (!cmd->num_args)
        return 0;

    virBufferAddLit(buf, "<xen:commandline>\n");
    virBufferAdjustIndent(buf, 2);

    for (i = 0; i < cmd->num_args; i++)
        virBufferEscapeString(buf, "<xen:arg value='%s'/>\n",
                              cmd->args[i]);

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</xen:commandline>\n");

    return 0;
}


virXMLNamespace libxlDriverDomainXMLNamespace = {
    .parse = libxlDomainDefNamespaceParse,
    .free = libxlDomainDefNamespaceFree,
    .format = libxlDomainDefNamespaceFormatXML,
    .prefix = "xen",
    .uri = "http://libvirt.org/schemas/domain/xen/1.0",
};
