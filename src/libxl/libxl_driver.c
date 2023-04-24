/*
 * libxl_driver.c: core driver methods for managing libxenlight domains
 *
 * Copyright (C) 2006-2015 Red Hat, Inc.
 * Copyright (C) 2011-2015 SUSE LINUX Products GmbH, Nuernberg, Germany.
 * Copyright (C) 2011 Univention GmbH.
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

#include <libxl.h>
#include <libxl_utils.h>
#include <xenstore.h>
#include <fcntl.h>

#include "internal.h"
#include "virlog.h"
#include "virerror.h"
#include "virconf.h"
#include "datatypes.h"
#include "virfile.h"
#include "viralloc.h"
#include "viruuid.h"
#include "virhook.h"
#include "libxl_api_wrapper.h"
#include "libxl_domain.h"
#include "libxl_driver.h"
#include "libxl_conf.h"
#include "libxl_capabilities.h"
#include "libxl_migration.h"
#include "xen_xm.h"
#include "xen_xl.h"
#include "virtypedparam.h"
#include "viruri.h"
#include "viraccessapicheck.h"
#include "virhostdev.h"
#include "virpidfile.h"
#include "locking/domain_lock.h"
#include "virnetdevtap.h"
#include "cpu/cpu.h"
#include "virutil.h"
#include "domain_validate.h"
#include "domain_driver.h"

#define VIR_FROM_THIS VIR_FROM_LIBXL

VIR_LOG_INIT("libxl.libxl_driver");

#define LIBXL_DOM_REQ_POWEROFF 0
#define LIBXL_DOM_REQ_REBOOT   1
#define LIBXL_DOM_REQ_SUSPEND  2
#define LIBXL_DOM_REQ_CRASH    3
#define LIBXL_DOM_REQ_HALT     4

#define LIBXL_NB_TOTAL_CPU_STAT_PARAM 1
#define LIBXL_NB_TOTAL_BLK_STAT_PARAM 6

#define HYPERVISOR_CAPABILITIES "/proc/xen/capabilities"
#define HYPERVISOR_XENSTORED "/dev/xen/xenstored"

/* Number of Xen scheduler parameters. credit and credit2 both support 2 */
#define XEN_SCHED_CREDIT_NPARAM   2

#define LIBXL_CHECK_DOM0_GOTO(name, label) \
    do { \
        if (STREQ_NULLABLE(name, "Domain-0")) { \
            virReportError(VIR_ERR_OPERATION_INVALID, "%s", \
                           _("Domain-0 does not support requested operation")); \
            goto label; \
        } \
    } while (0)


static libxlDriverPrivate *libxl_driver;

/* Object used to store info related to libxl event registrations */
typedef struct _libxlOSEventHookInfo libxlOSEventHookInfo;
struct _libxlOSEventHookInfo {
    libxl_ctx *ctx;
    void *xl_priv;
    int id;
};

/* Object used to store disk statistics across multiple xen backends */
typedef struct _libxlBlockStats libxlBlockStats;
struct _libxlBlockStats {
    long long rd_req;
    long long rd_bytes;
    long long wr_req;
    long long wr_bytes;
    long long f_req;

    char *backend;
    union {
        struct {
            long long ds_req;
            long long oo_req;
        } vbd;
    } u;
};

/* Function declarations */
static int
libxlDomainManagedSaveLoad(virDomainObj *vm,
                           void *opaque);


/* Function definitions */
static void
libxlOSEventHookInfoFree(void *obj)
{
    g_free(obj);
}

static void
libxlFDEventCallback(int watch G_GNUC_UNUSED,
                     int fd,
                     int vir_events,
                     void *fd_info)
{
    libxlOSEventHookInfo *info = fd_info;
    int events = 0;

    if (vir_events & VIR_EVENT_HANDLE_READABLE)
        events |= POLLIN;
    if (vir_events & VIR_EVENT_HANDLE_WRITABLE)
        events |= POLLOUT;
    if (vir_events & VIR_EVENT_HANDLE_ERROR)
        events |= POLLERR;
    if (vir_events & VIR_EVENT_HANDLE_HANGUP)
        events |= POLLHUP;

    libxl_osevent_occurred_fd(info->ctx, info->xl_priv, fd, 0, events);
}

static int
libxlFDRegisterEventHook(void *priv,
                         int fd,
                         void **hndp,
                         short events,
                         void *xl_priv)
{
    int vir_events = VIR_EVENT_HANDLE_ERROR;
    libxlOSEventHookInfo *info;

    info = g_new0(libxlOSEventHookInfo, 1);

    info->ctx = priv;
    info->xl_priv = xl_priv;

    if (events & POLLIN)
        vir_events |= VIR_EVENT_HANDLE_READABLE;
    if (events & POLLOUT)
        vir_events |= VIR_EVENT_HANDLE_WRITABLE;

    info->id = virEventAddHandle(fd, vir_events, libxlFDEventCallback,
                                 info, libxlOSEventHookInfoFree);
    if (info->id < 0) {
        VIR_FREE(info);
        return -1;
    }

    *hndp = info;

    return 0;
}

static int
libxlFDModifyEventHook(void *priv G_GNUC_UNUSED,
                       int fd G_GNUC_UNUSED,
                       void **hndp,
                       short events)
{
    libxlOSEventHookInfo *info = *hndp;
    int vir_events = VIR_EVENT_HANDLE_ERROR;

    if (events & POLLIN)
        vir_events |= VIR_EVENT_HANDLE_READABLE;
    if (events & POLLOUT)
        vir_events |= VIR_EVENT_HANDLE_WRITABLE;

    virEventUpdateHandle(info->id, vir_events);

    return 0;
}

static void
libxlFDDeregisterEventHook(void *priv G_GNUC_UNUSED,
                           int fd G_GNUC_UNUSED,
                           void *hnd)
{
    libxlOSEventHookInfo *info = hnd;

    virEventRemoveHandle(info->id);
}

static void
libxlTimerCallback(int timer G_GNUC_UNUSED, void *timer_info)
{
    libxlOSEventHookInfo *info = timer_info;

    /*
     * libxl expects the event to be deregistered when calling
     * libxl_osevent_occurred_timeout, but we dont want the event info
     * destroyed.  Disable the timeout and only remove it after returning
     * from libxl.
     */
    virEventUpdateTimeout(info->id, -1);
    libxl_osevent_occurred_timeout(info->ctx, info->xl_priv);
    virEventRemoveTimeout(info->id);
}

static int
libxlTimeoutRegisterEventHook(void *priv,
                              void **hndp,
                              struct timeval abs_t,
                              void *xl_priv)
{
    libxlOSEventHookInfo *info;
    gint64 now_us;
    gint64 abs_us;
    gint64 res_ms;
    int timeout;

    info = g_new0(libxlOSEventHookInfo, 1);

    info->ctx = priv;
    info->xl_priv = xl_priv;

    now_us = g_get_real_time();
    abs_us = (abs_t.tv_sec * (1000LL*1000LL)) + abs_t.tv_usec;
    if (now_us >= abs_us) {
        timeout = 0;
    } else {
        res_ms = (abs_us - now_us) / 1000;
        if (res_ms > INT_MAX)
            timeout = INT_MAX;
        else
            timeout = res_ms;
    }
    info->id = virEventAddTimeout(timeout, libxlTimerCallback,
                                  info, libxlOSEventHookInfoFree);
    if (info->id < 0) {
        VIR_FREE(info);
        return -1;
    }

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
libxlTimeoutModifyEventHook(void *priv G_GNUC_UNUSED,
                            void **hndp,
                            struct timeval abs_t G_GNUC_UNUSED)
{
    libxlOSEventHookInfo *info = *hndp;

    /* Make the timeout fire */
    virEventUpdateTimeout(info->id, 0);

    return 0;
}

static void
libxlTimeoutDeregisterEventHook(void *priv G_GNUC_UNUSED,
                                void *hnd)
{
    libxlOSEventHookInfo *info = hnd;

    virEventRemoveTimeout(info->id);
}

static virDomainObj *
libxlDomObjFromDomain(virDomainPtr dom)
{
    virDomainObj *vm;
    libxlDriverPrivate *driver = dom->conn->privateData;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    if (!vm) {
        virUUIDFormat(dom->uuid, uuidstr);
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching uuid '%1$s' (%2$s)"),
                       uuidstr, dom->name);
        return NULL;
    }

    return vm;
}

static int
libxlAutostartDomain(virDomainObj *vm,
                     void *opaque)
{
    libxlDriverPrivate *driver = opaque;
    int ret = -1;

    virObjectRef(vm);
    virObjectLock(vm);
    virResetLastError();

    if (virDomainObjBeginJob(vm, VIR_JOB_MODIFY) < 0)
        goto cleanup;

    if (vm->autostart && !virDomainObjIsActive(vm) &&
        libxlDomainStartNew(driver, vm, false) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to autostart VM '%1$s': %2$s"),
                       vm->def->name, virGetLastErrorMessage());
        goto endjob;
    }

    ret = 0;

 endjob:
    virDomainObjEndJob(vm);
 cleanup:
    virDomainObjEndAPI(&vm);

    return ret;
}


static void
libxlReconnectNotifyNets(virDomainDef *def)
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
        if (virDomainNetGetActualType(net) == VIR_DOMAIN_NET_TYPE_DIRECT)
            virNetDevReserveName(net->ifname);

        if (net->type == VIR_DOMAIN_NET_TYPE_NETWORK && !conn)
            conn = virGetConnectNetwork();

        virDomainNetNotifyActualDevice(conn, def, net);
    }
}


/*
 * Reconnect to running domains that were previously started/created
 * with libxenlight driver.
 */
static int
libxlReconnectDomain(virDomainObj *vm,
                     void *opaque)
{
    libxlDriverPrivate *driver = opaque;
    libxlDomainObjPrivate *priv = vm->privateData;
    libxlDriverConfig *cfg = libxlDriverConfigGet(driver);
    int rc;
    libxl_dominfo d_info;
    int len;
    g_autofree uint8_t *data = NULL;
    virHostdevManager *hostdev_mgr = driver->hostdevMgr;
    unsigned int hostdev_flags = VIR_HOSTDEV_SP_PCI;
    int ret = -1;
    size_t i;

    hostdev_flags |= VIR_HOSTDEV_SP_USB;

    virObjectRef(vm);
    virObjectLock(vm);

    libxl_dominfo_init(&d_info);

    /* Does domain still exist? */
    rc = libxl_domain_info(cfg->ctx, &d_info, vm->def->id);
    if (rc == ERROR_INVAL) {
        goto error;
    } else if (rc != 0) {
        VIR_DEBUG("libxl_domain_info failed (code %d), ignoring domain %d",
                  rc, vm->def->id);
        goto error;
    }

    /* Is this a domain that was under libvirt control? */
    if (libxl_userdata_retrieve(cfg->ctx, vm->def->id,
                                "libvirt-xml", &data, &len)) {
        VIR_DEBUG("libxl_userdata_retrieve failed, ignoring domain %d", vm->def->id);
        goto error;
    }

    /* Update domid in case it changed (e.g. reboot) while we were gone? */
    vm->def->id = d_info.domid;

    libxlLoggerOpenFile(cfg->logger, vm->def->id, vm->def->name, NULL);

    /* Update hostdev state */
    if (virHostdevUpdateActiveDomainDevices(hostdev_mgr, LIBXL_DRIVER_INTERNAL_NAME,
                                            vm->def, hostdev_flags) < 0)
        goto error;

    if (d_info.shutdown &&
            d_info.shutdown_reason == LIBXL_SHUTDOWN_REASON_SUSPEND)
        virDomainObjSetState(vm, VIR_DOMAIN_PMSUSPENDED,
                             VIR_DOMAIN_PMSUSPENDED_UNKNOWN);
    else if (d_info.paused)
        virDomainObjSetState(vm, VIR_DOMAIN_PAUSED,
                             VIR_DOMAIN_PAUSED_UNKNOWN);
    else
        virDomainObjSetState(vm, VIR_DOMAIN_RUNNING,
                             VIR_DOMAIN_RUNNING_UNKNOWN);

    if (g_atomic_int_add(&driver->nactive, 1) == 0 && driver->inhibitCallback)
        driver->inhibitCallback(true, driver->inhibitOpaque);

    /* Enable domain death events */
    libxl_evenable_domain_death(cfg->ctx, vm->def->id, 0, &priv->deathW);

    libxlReconnectNotifyNets(vm->def);

    /* Set any auto-allocated graphics ports to used */
    for (i = 0; i < vm->def->ngraphics; i++) {
        virDomainGraphicsDef *graphics = vm->def->graphics[i];

         switch (graphics->type) {
         case VIR_DOMAIN_GRAPHICS_TYPE_VNC:
             if (graphics->data.vnc.autoport)
                 virPortAllocatorSetUsed(graphics->data.vnc.port);
             break;
         case VIR_DOMAIN_GRAPHICS_TYPE_SPICE:
             if (graphics->data.spice.autoport)
                 virPortAllocatorSetUsed(graphics->data.spice.port);
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

    if (virDomainObjSave(vm, driver->xmlopt, cfg->stateDir) < 0)
        VIR_WARN("Cannot update XML for running Xen guest %s", vm->def->name);

    /* now that we know it's reconnected call the hook */
    if (STRNEQ("Domain-0", vm->def->name) &&
        (libxlDomainHookRun(driver, vm->def, 0,
                            VIR_HOOK_LIBXL_OP_RECONNECT,
                            VIR_HOOK_SUBOP_BEGIN, NULL) < 0))
        goto error;

    ret = 0;

 cleanup:
    libxl_dominfo_dispose(&d_info);
    virDomainObjEndAPI(&vm);
    virObjectUnref(cfg);
    return ret;

 error:
    libxlDomainCleanup(driver, vm);
    if (!vm->persistent)
        virDomainObjListRemoveLocked(driver->domains, vm);
    goto cleanup;
}

static void
libxlReconnectDomains(libxlDriverPrivate *driver)
{
    virDomainObjListForEach(driver->domains, true, libxlReconnectDomain, driver);
}

static int
libxlStateCleanup(void)
{
    if (!libxl_driver)
        return -1;

    virObjectUnref(libxl_driver->hostdevMgr);
    virObjectUnref(libxl_driver->xmlopt);
    virObjectUnref(libxl_driver->domains);
    virPortAllocatorRangeFree(libxl_driver->reservedGraphicsPorts);
    virPortAllocatorRangeFree(libxl_driver->migrationPorts);
    virLockManagerPluginUnref(libxl_driver->lockManager);

    virObjectUnref(libxl_driver->domainEventState);
    virSysinfoDefFree(libxl_driver->hostsysinfo);

    if (libxl_driver->lockFD != -1)
        virPidFileRelease(libxl_driver->config->stateDir, "driver", libxl_driver->lockFD);

    virObjectUnref(libxl_driver->config);
    virMutexDestroy(&libxl_driver->lock);
    VIR_FREE(libxl_driver);

    return 0;
}

static bool
libxlDriverShouldLoad(bool privileged)
{
    /* Don't load if non-root */
    if (!privileged) {
        VIR_INFO("Not running privileged, disabling libxenlight driver");
        return false;
    }

    if (virFileExists(HYPERVISOR_CAPABILITIES)) {
        int status;
        g_autofree char *output = NULL;
        /*
         * Don't load if not running on a Xen control domain (dom0). It is not
         * sufficient to check for the file to exist as any guest can mount
         * xenfs to /proc/xen.
         */
        status = virFileReadAll(HYPERVISOR_CAPABILITIES, 10, &output);
        if (status >= 0)
            status = strncmp(output, "control_d", 9);
        if (status) {
            VIR_INFO("No Xen capabilities detected, probably not running "
                     "in a Xen Dom0.  Disabling libxenlight driver");

            return false;
        }
    } else if (!virFileExists(HYPERVISOR_XENSTORED)) {
        VIR_INFO("Disabling driver as neither " HYPERVISOR_CAPABILITIES
                 " nor " HYPERVISOR_XENSTORED " exist");
        return false;
    }

    return true;
}

/* Callbacks wrapping libvirt's event loop interface */
static const libxl_osevent_hooks libxl_osevent_callbacks = {
    .fd_register = libxlFDRegisterEventHook,
    .fd_modify = libxlFDModifyEventHook,
    .fd_deregister = libxlFDDeregisterEventHook,
    .timeout_register = libxlTimeoutRegisterEventHook,
    .timeout_modify = libxlTimeoutModifyEventHook,
    .timeout_deregister = libxlTimeoutDeregisterEventHook,
};

static const libxl_childproc_hooks libxl_child_hooks = {
    .chldowner = libxl_sigchld_owner_libxl_always_selective_reap,
};

const struct libxl_event_hooks ev_hooks = {
    .event_occurs_mask = LIBXL_EVENTMASK_ALL,
    .event_occurs = libxlDomainEventHandler,
    .disaster = NULL,
};

static int
libxlAddDom0(libxlDriverPrivate *driver)
{
    libxlDriverConfig *cfg = libxlDriverConfigGet(driver);
    g_autoptr(virDomainDef) def = NULL;
    virDomainObj *vm = NULL;
    libxl_dominfo d_info;
    unsigned long long maxmem;
    int ret = -1;

    libxl_dominfo_init(&d_info);

    /* Ensure we have a dom0 */
    if (libxl_domain_info(cfg->ctx, &d_info, 0) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("unable to get Domain-0 information from libxenlight"));
        goto cleanup;
    }

    /*
     * On a driver reload dom0 will already exist. On host restart it must
     * created.
     */
    if ((vm = virDomainObjListFindByID(driver->domains, 0)) == NULL) {
        if (!(def = virDomainDefNew(driver->xmlopt)))
            goto cleanup;

        def->id = 0;
        def->virtType = VIR_DOMAIN_VIRT_XEN;
        def->name = g_strdup("Domain-0");

        def->os.type = VIR_DOMAIN_OSTYPE_XEN;

        if (virUUIDParse("00000000-0000-0000-0000-000000000000", def->uuid) < 0)
            goto cleanup;

        if (!(vm = virDomainObjListAdd(driver->domains, &def,
                                       driver->xmlopt,
                                       0,
                                       NULL)))
            goto cleanup;

        vm->persistent = 1;
        virDomainObjSetState(vm, VIR_DOMAIN_RUNNING, VIR_DOMAIN_RUNNING_BOOTED);
    }

    if (virDomainDefSetVcpusMax(vm->def, d_info.vcpu_max_id + 1, driver->xmlopt))
        goto cleanup;

    if (virDomainDefSetVcpus(vm->def, d_info.vcpu_online) < 0)
        goto cleanup;
    vm->def->mem.cur_balloon = d_info.current_memkb;
    if (libxlDriverGetDom0MaxmemConf(cfg, &maxmem) < 0)
        maxmem = d_info.current_memkb;
    virDomainDefSetMemoryTotal(vm->def, maxmem);

    ret = 0;

 cleanup:
    libxl_dominfo_dispose(&d_info);
    virDomainObjEndAPI(&vm);
    virObjectUnref(cfg);
    return ret;
}

static int
libxlStateInitialize(bool privileged,
                     const char *root,
                     bool monolithic G_GNUC_UNUSED,
                     virStateInhibitCallback callback,
                     void *opaque)
{
    libxlDriverConfig *cfg;
    g_autofree char *driverConf = NULL;
    bool autostart = true;

    if (root != NULL) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Driver does not support embedded mode"));
        return -1;
    }

    if (!libxlDriverShouldLoad(privileged))
        return VIR_DRV_STATE_INIT_SKIPPED;

    libxl_driver = g_new0(libxlDriverPrivate, 1);

    libxl_driver->lockFD = -1;
    if (virMutexInit(&libxl_driver->lock) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("cannot initialize mutex"));
        VIR_FREE(libxl_driver);
        return VIR_DRV_STATE_INIT_ERROR;
    }

    libxl_driver->inhibitCallback = callback;
    libxl_driver->inhibitOpaque = opaque;

    /* Allocate bitmap for vnc port reservation */
    if (!(libxl_driver->reservedGraphicsPorts =
          virPortAllocatorRangeNew(_("VNC"),
                                   LIBXL_VNC_PORT_MIN,
                                   LIBXL_VNC_PORT_MAX)))
        goto error;

    /* Allocate bitmap for migration port reservation */
    if (!(libxl_driver->migrationPorts =
          virPortAllocatorRangeNew(_("migration"),
                                   LIBXL_MIGRATION_PORT_MIN,
                                   LIBXL_MIGRATION_PORT_MAX)))
        goto error;

    if (!(libxl_driver->domains = virDomainObjListNew()))
        goto error;

    if (!(libxl_driver->hostdevMgr = virHostdevManagerGetDefault()))
        goto error;

    if (!(cfg = libxlDriverConfigNew()))
        goto error;

    if (libxlDriverConfigInit(cfg) < 0)
        goto error;

    driverConf = g_strdup_printf("%s/libxl.conf", cfg->configBaseDir);

    if (libxlDriverConfigLoadFile(cfg, driverConf) < 0)
        goto error;

    /* Register the callbacks providing access to libvirt's event loop */
    libxl_osevent_register_hooks(cfg->ctx, &libxl_osevent_callbacks, cfg->ctx);

    /* Setup child process handling.  See $xen-src/tools/libxl/libxl_event.h */
    libxl_childproc_setmode(cfg->ctx, &libxl_child_hooks, cfg->ctx);

    /* Register callback to handle domain events */
    libxl_event_register_callbacks(cfg->ctx, &ev_hooks, libxl_driver);

    libxl_driver->config = cfg;
    if (g_mkdir_with_parents(cfg->stateDir, 0777) < 0) {
        virReportSystemError(errno,
                             _("failed to create state dir '%1$s'"),
                             cfg->stateDir);
        goto error;
    }
    if (g_mkdir_with_parents(cfg->libDir, 0777) < 0) {
        virReportSystemError(errno,
                             _("failed to create lib dir '%1$s'"),
                             cfg->libDir);
        goto error;
    }
    if (g_mkdir_with_parents(cfg->saveDir, 0777) < 0) {
        virReportSystemError(errno,
                             _("failed to create save dir '%1$s'"),
                             cfg->saveDir);
        goto error;
    }
    if (g_mkdir_with_parents(cfg->autoDumpDir, 0777) < 0) {
        virReportSystemError(errno,
                             _("failed to create dump dir '%1$s'"),
                             cfg->autoDumpDir);
        goto error;
    }
    if (g_mkdir_with_parents(cfg->channelDir, 0777) < 0) {
        virReportSystemError(errno,
                             _("failed to create channel dir '%1$s'"),
                             cfg->channelDir);
        goto error;
    }

    if ((libxl_driver->lockFD =
         virPidFileAcquire(cfg->stateDir, "driver", getpid())) < 0)
        goto error;

    if (!(libxl_driver->lockManager =
          virLockManagerPluginNew(cfg->lockManagerName ?
                                  cfg->lockManagerName : "nop",
                                  "libxl",
                                  cfg->configBaseDir,
                                  0)))
        goto error;

    /* read the host sysinfo */
    libxl_driver->hostsysinfo = virSysinfoRead();

    libxl_driver->domainEventState = virObjectEventStateNew();
    if (!libxl_driver->domainEventState)
        goto error;

    if ((cfg->caps = libxlMakeCapabilities(cfg->ctx)) == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("cannot create capabilities for libxenlight"));
        goto error;
    }

    if (!(libxl_driver->xmlopt = libxlCreateXMLConf(libxl_driver)))
        goto error;

    /* Load running domains first. */
    if (virDomainObjListLoadAllConfigs(libxl_driver->domains,
                                       cfg->stateDir,
                                       cfg->autostartDir,
                                       true,
                                       libxl_driver->xmlopt,
                                       NULL, NULL) < 0)
        goto error;

    /* Add Domain-0 */
    if (libxlAddDom0(libxl_driver) < 0)
        goto error;

    libxlReconnectDomains(libxl_driver);

    /* Then inactive persistent configs */
    if (virDomainObjListLoadAllConfigs(libxl_driver->domains,
                                       cfg->configDir,
                                       cfg->autostartDir,
                                       false,
                                       libxl_driver->xmlopt,
                                       NULL, NULL) < 0)
        goto error;

    if (virDriverShouldAutostart(cfg->stateDir, &autostart) < 0)
        goto error;

    if (autostart) {
        virDomainObjListForEach(libxl_driver->domains, false,
                                libxlAutostartDomain,
                                libxl_driver);
    }

    virDomainObjListForEach(libxl_driver->domains, false,
                            libxlDomainManagedSaveLoad,
                            libxl_driver);

    return VIR_DRV_STATE_INIT_COMPLETE;

 error:
    libxlStateCleanup();
    return VIR_DRV_STATE_INIT_ERROR;
}

static int
libxlStateReload(void)
{
    libxlDriverConfig *cfg;

    if (!libxl_driver)
        return 0;

    cfg = libxlDriverConfigGet(libxl_driver);

    virDomainObjListLoadAllConfigs(libxl_driver->domains,
                                   cfg->configDir,
                                   cfg->autostartDir,
                                   false,
                                   libxl_driver->xmlopt,
                                   NULL, libxl_driver);

    virObjectUnref(cfg);
    return 0;
}


static int
libxlConnectURIProbe(char **uri)
{
    if (libxl_driver == NULL)
        return 0;

    *uri = g_strdup("xen:///system");
    return 1;
}


static virDrvOpenStatus
libxlConnectOpen(virConnectPtr conn,
                 virConnectAuthPtr auth G_GNUC_UNUSED,
                 virConf *conf G_GNUC_UNUSED,
                 unsigned int flags)
{
    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    /* Error if xen or libxl scheme specified but driver not started. */
    if (libxl_driver == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("libxenlight state driver is not active"));
        return VIR_DRV_OPEN_ERROR;
    }

    /* /session isn't supported in libxenlight */
    if (STRNEQ(conn->uri->path, "") &&
        STRNEQ(conn->uri->path, "/") &&
        STRNEQ(conn->uri->path, "/system")) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected Xen URI path '%1$s', try xen:///system"),
                       conn->uri->path);
        return VIR_DRV_OPEN_ERROR;
    }

    if (virConnectOpenEnsureACL(conn) < 0)
        return VIR_DRV_OPEN_ERROR;

    conn->privateData = libxl_driver;

    return VIR_DRV_OPEN_SUCCESS;
};

static int
libxlConnectClose(virConnectPtr conn G_GNUC_UNUSED)
{
    conn->privateData = NULL;
    return 0;
}

static const char *
libxlConnectGetType(virConnectPtr conn)
{
    if (virConnectGetTypeEnsureACL(conn) < 0)
        return NULL;

    return LIBXL_DRIVER_EXTERNAL_NAME;
}

static int
libxlConnectGetVersion(virConnectPtr conn, unsigned long *version)
{
    libxlDriverPrivate *driver = conn->privateData;
    libxlDriverConfig *cfg;

    if (virConnectGetVersionEnsureACL(conn) < 0)
        return 0;

    cfg = libxlDriverConfigGet(driver);
    *version = cfg->version;
    virObjectUnref(cfg);
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
    libxlDriverPrivate *driver = conn->privateData;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

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
    return virBufferContentAndReset(&buf);
}

static int
libxlConnectGetMaxVcpus(virConnectPtr conn, const char *type G_GNUC_UNUSED)
{
    int ret;
    libxlDriverPrivate *driver = conn->privateData;
    libxlDriverConfig *cfg;

    if (virConnectGetMaxVcpusEnsureACL(conn) < 0)
        return -1;

    cfg = libxlDriverConfigGet(driver);
    ret = libxl_get_max_cpus(cfg->ctx);
    if (ret < 0)
        ret = -1;

    virObjectUnref(cfg);
    return ret;
}

static int
libxlNodeGetInfo(virConnectPtr conn, virNodeInfoPtr info)
{
    if (virNodeGetInfoEnsureACL(conn) < 0)
        return -1;

    return libxlDriverNodeGetInfo(conn->privateData, info);
}

static char *
libxlConnectGetCapabilities(virConnectPtr conn)
{
    libxlDriverPrivate *driver = conn->privateData;
    char *xml;
    libxlDriverConfig *cfg;

    if (virConnectGetCapabilitiesEnsureACL(conn) < 0)
        return NULL;

    cfg = libxlDriverConfigGet(driver);
    xml = virCapabilitiesFormatXML(cfg->caps);

    virObjectUnref(cfg);
    return xml;
}

static int
libxlConnectListDomains(virConnectPtr conn, int *ids, int nids)
{
    libxlDriverPrivate *driver = conn->privateData;

    if (virConnectListDomainsEnsureACL(conn) < 0)
        return -1;

    return virDomainObjListGetActiveIDs(driver->domains, ids, nids,
                                        virConnectListDomainsCheckACL, conn);
}

static int
libxlConnectNumOfDomains(virConnectPtr conn)
{
    libxlDriverPrivate *driver = conn->privateData;

    if (virConnectNumOfDomainsEnsureACL(conn) < 0)
        return -1;

    return virDomainObjListNumOfDomains(driver->domains, true,
                                        virConnectNumOfDomainsCheckACL, conn);
}

static virDomainPtr
libxlDomainCreateXML(virConnectPtr conn, const char *xml,
                     unsigned int flags)
{
    libxlDriverPrivate *driver = conn->privateData;
    g_autoptr(virDomainDef) def = NULL;
    virDomainObj *vm = NULL;
    virDomainPtr dom = NULL;
    libxlDriverConfig *cfg = libxlDriverConfigGet(driver);
    unsigned int parse_flags = VIR_DOMAIN_DEF_PARSE_INACTIVE;

    virCheckFlags(VIR_DOMAIN_START_PAUSED |
                  VIR_DOMAIN_START_VALIDATE, NULL);

    if (flags & VIR_DOMAIN_START_VALIDATE)
        parse_flags |= VIR_DOMAIN_DEF_PARSE_VALIDATE_SCHEMA;

    if (!(def = virDomainDefParseString(xml, driver->xmlopt,
                                        NULL, parse_flags)))
        goto cleanup;

    if (virDomainCreateXMLEnsureACL(conn, def) < 0)
        goto cleanup;

    if (!(vm = virDomainObjListAdd(driver->domains, &def,
                                   driver->xmlopt,
                                   VIR_DOMAIN_OBJ_LIST_ADD_LIVE |
                                   VIR_DOMAIN_OBJ_LIST_ADD_CHECK_LIVE,
                                   NULL)))
        goto cleanup;

    if (virDomainObjBeginJob(vm, VIR_JOB_MODIFY) < 0) {
        if (!vm->persistent)
            virDomainObjListRemove(driver->domains, vm);
        goto cleanup;
    }

    if (libxlDomainStartNew(driver, vm,
                         (flags & VIR_DOMAIN_START_PAUSED) != 0) < 0) {
        if (!vm->persistent)
            virDomainObjListRemove(driver->domains, vm);
        goto endjob;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid, vm->def->id);

 endjob:
    virDomainObjEndJob(vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    virObjectUnref(cfg);
    return dom;
}

static virDomainPtr
libxlDomainLookupByID(virConnectPtr conn, int id)
{
    libxlDriverPrivate *driver = conn->privateData;
    virDomainObj *vm;
    virDomainPtr dom = NULL;

    vm = virDomainObjListFindByID(driver->domains, id);
    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }

    if (virDomainLookupByIDEnsureACL(conn, vm->def) < 0)
        goto cleanup;

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid, vm->def->id);

 cleanup:
    virDomainObjEndAPI(&vm);
    return dom;
}

static virDomainPtr
libxlDomainLookupByUUID(virConnectPtr conn, const unsigned char *uuid)
{
    libxlDriverPrivate *driver = conn->privateData;
    virDomainObj *vm;
    virDomainPtr dom = NULL;

    vm = virDomainObjListFindByUUID(driver->domains, uuid);
    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }

    if (virDomainLookupByUUIDEnsureACL(conn, vm->def) < 0)
        goto cleanup;

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid, vm->def->id);

 cleanup:
    virDomainObjEndAPI(&vm);
    return dom;
}

static virDomainPtr
libxlDomainLookupByName(virConnectPtr conn, const char *name)
{
    libxlDriverPrivate *driver = conn->privateData;
    virDomainObj *vm;
    virDomainPtr dom = NULL;

    vm = virDomainObjListFindByName(driver->domains, name);
    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }

    if (virDomainLookupByNameEnsureACL(conn, vm->def) < 0)
        goto cleanup;

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid, vm->def->id);

 cleanup:
    virDomainObjEndAPI(&vm);
    return dom;
}

static int
libxlDomainSuspend(virDomainPtr dom)
{
    libxlDriverPrivate *driver = dom->conn->privateData;
    libxlDriverConfig *cfg = libxlDriverConfigGet(driver);
    virDomainObj *vm;
    virObjectEvent *event = NULL;
    int ret = -1;

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    LIBXL_CHECK_DOM0_GOTO(vm->def->name, cleanup);

    if (virDomainSuspendEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (virDomainObjBeginJob(vm, VIR_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjCheckActive(vm) < 0)
        goto endjob;

    if (virDomainObjGetState(vm, NULL) != VIR_DOMAIN_PAUSED) {
        if (libxlDomainPauseWrapper(cfg->ctx, vm->def->id) != 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to suspend domain '%1$d' with libxenlight"),
                           vm->def->id);
            goto endjob;
        }

        virDomainObjSetState(vm, VIR_DOMAIN_PAUSED, VIR_DOMAIN_PAUSED_USER);

        event = virDomainEventLifecycleNewFromObj(vm, VIR_DOMAIN_EVENT_SUSPENDED,
                                         VIR_DOMAIN_EVENT_SUSPENDED_PAUSED);
    }

    if (virDomainObjSave(vm, driver->xmlopt, cfg->stateDir) < 0)
        goto endjob;

    ret = 0;

 endjob:
    virDomainObjEndJob(vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    virObjectEventStateQueue(driver->domainEventState, event);
    virObjectUnref(cfg);
    return ret;
}


static int
libxlDomainResume(virDomainPtr dom)
{
    libxlDriverPrivate *driver = dom->conn->privateData;
    libxlDriverConfig *cfg = libxlDriverConfigGet(driver);
    virDomainObj *vm;
    virObjectEvent *event = NULL;
    int ret = -1;

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    LIBXL_CHECK_DOM0_GOTO(vm->def->name, cleanup);

    if (virDomainResumeEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (virDomainObjBeginJob(vm, VIR_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjCheckActive(vm) < 0)
        goto endjob;

    if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_PAUSED) {
        if (libxlDomainUnpauseWrapper(cfg->ctx, vm->def->id) != 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to resume domain '%1$d' with libxenlight"),
                           vm->def->id);
            goto endjob;
        }

        virDomainObjSetState(vm, VIR_DOMAIN_RUNNING,
                             VIR_DOMAIN_RUNNING_UNPAUSED);

        event = virDomainEventLifecycleNewFromObj(vm, VIR_DOMAIN_EVENT_RESUMED,
                                         VIR_DOMAIN_EVENT_RESUMED_UNPAUSED);
    }

    if (virDomainObjSave(vm, driver->xmlopt, cfg->stateDir) < 0)
        goto endjob;

    ret = 0;

 endjob:
    virDomainObjEndJob(vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    virObjectEventStateQueue(driver->domainEventState, event);
    virObjectUnref(cfg);
    return ret;
}

static int
libxlDomainShutdownFlags(virDomainPtr dom, unsigned int flags)
{
    libxlDriverPrivate *driver = dom->conn->privateData;
    libxlDriverConfig *cfg = libxlDriverConfigGet(driver);
    virDomainObj *vm;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_SHUTDOWN_ACPI_POWER_BTN |
                  VIR_DOMAIN_SHUTDOWN_PARAVIRT, -1);
    if (flags == 0)
        flags = VIR_DOMAIN_SHUTDOWN_PARAVIRT |
            VIR_DOMAIN_SHUTDOWN_ACPI_POWER_BTN;

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    LIBXL_CHECK_DOM0_GOTO(vm->def->name, cleanup);

    if (virDomainShutdownFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (virDomainObjCheckActive(vm) < 0)
        goto cleanup;

    if (flags & VIR_DOMAIN_SHUTDOWN_PARAVIRT) {
        ret = libxlDomainShutdownWrapper(cfg->ctx, vm->def->id);
        if (ret == 0)
            goto cleanup;

        if (ret != ERROR_NOPARAVIRT) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to shutdown domain '%1$d' with libxenlight"),
                           vm->def->id);
            ret = -1;
            goto cleanup;
        }
        ret = -1;
    }

    if (flags & VIR_DOMAIN_SHUTDOWN_ACPI_POWER_BTN) {
        ret = libxlSendTriggerWrapper(cfg->ctx, vm->def->id,
                                      LIBXL_TRIGGER_POWER, 0);
        if (ret == 0)
            goto cleanup;

        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to shutdown domain '%1$d' with libxenlight"),
                       vm->def->id);
        ret = -1;
    }

 cleanup:
    virDomainObjEndAPI(&vm);
    virObjectUnref(cfg);
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
    libxlDriverPrivate *driver = dom->conn->privateData;
    libxlDriverConfig *cfg = libxlDriverConfigGet(driver);
    virDomainObj *vm;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_REBOOT_PARAVIRT, -1);
    if (flags == 0)
        flags = VIR_DOMAIN_REBOOT_PARAVIRT;

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    LIBXL_CHECK_DOM0_GOTO(vm->def->name, cleanup);

    if (virDomainRebootEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (virDomainObjCheckActive(vm) < 0)
        goto cleanup;

    if (flags & VIR_DOMAIN_REBOOT_PARAVIRT) {
        ret = libxlDomainRebootWrapper(cfg->ctx, vm->def->id);
        if (ret == 0)
            goto cleanup;

        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to reboot domain '%1$d' with libxenlight"),
                       vm->def->id);
        ret = -1;
    }

 cleanup:
    virDomainObjEndAPI(&vm);
    virObjectUnref(cfg);
    return ret;
}

static int
libxlDomainDestroyFlags(virDomainPtr dom,
                        unsigned int flags)
{
    libxlDriverPrivate *driver = dom->conn->privateData;
    libxlDriverConfig *cfg = libxlDriverConfigGet(driver);
    virDomainObj *vm;
    int ret = -1;
    virObjectEvent *event = NULL;

    virCheckFlags(0, -1);

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    LIBXL_CHECK_DOM0_GOTO(vm->def->name, cleanup);

    if (virDomainDestroyFlagsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (virDomainObjBeginJob(vm, VIR_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjCheckActive(vm) < 0)
        goto endjob;

    if (libxlDomainDestroyInternal(driver, vm) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to destroy domain '%1$d'"), vm->def->id);
        goto endjob;
    }

    virDomainObjSetState(vm, VIR_DOMAIN_SHUTOFF,
                         VIR_DOMAIN_SHUTOFF_DESTROYED);

    event = virDomainEventLifecycleNewFromObj(vm, VIR_DOMAIN_EVENT_STOPPED,
                                     VIR_DOMAIN_EVENT_STOPPED_DESTROYED);

    libxlDomainCleanup(driver, vm);
    if (!vm->persistent)
        virDomainObjListRemove(driver->domains, vm);

    ret = 0;

 endjob:
    virDomainObjEndJob(vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    virObjectEventStateQueue(driver->domainEventState, event);
    virObjectUnref(cfg);
    return ret;
}

static int
libxlDomainDestroy(virDomainPtr dom)
{
    return libxlDomainDestroyFlags(dom, 0);
}

#ifdef LIBXL_HAVE_DOMAIN_SUSPEND_ONLY
static int
libxlDomainPMSuspendForDuration(virDomainPtr dom,
                                unsigned int target,
                                unsigned long long duration,
                                unsigned int flags)
{
    virDomainObj *vm;
    int ret = -1;
    libxlDriverPrivate *driver = dom->conn->privateData;
    libxlDriverConfig *cfg = libxlDriverConfigGet(driver);
    virObjectEvent *event = NULL;

    virCheckFlags(0, -1);
    if (target != VIR_NODE_SUSPEND_TARGET_MEM) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED,
                _("PMSuspend type %1$d not supported by libxenlight driver"),
                target);
        return -1;
    }

    if (duration != 0) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                _("Duration not supported. Use 0 for now"));
        return -1;
    }

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainPMSuspendForDurationEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (virDomainObjBeginJob(vm, VIR_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjCheckActive(vm) < 0)
        goto endjob;

    /* Unlock virDomainObj *to not deadlock with even handler, which will try
     * to send lifecycle event
     */
    virObjectUnlock(vm);
    ret = libxl_domain_suspend_only(cfg->ctx, vm->def->id, NULL);
    virObjectLock(vm);

    if (ret < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to suspend domain '%1$d'"), vm->def->id);
        goto endjob;
    }

    virDomainObjSetState(vm, VIR_DOMAIN_PMSUSPENDED, VIR_DOMAIN_PMSUSPENDED_UNKNOWN);
    event = virDomainEventLifecycleNewFromObj(vm, VIR_DOMAIN_EVENT_PMSUSPENDED,
                                              VIR_DOMAIN_EVENT_PMSUSPENDED_MEMORY);

    ret = 0;

 endjob:
    virDomainObjEndJob(vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    virObjectEventStateQueue(driver->domainEventState, event);
    return ret;
}
#endif

static int
libxlDomainPMWakeup(virDomainPtr dom, unsigned int flags)
{
    libxlDriverPrivate *driver = dom->conn->privateData;
    virDomainObj *vm;
    int ret = -1;
    virObjectEvent *event = NULL;
    libxlDomainObjPrivate *priv;
    libxlDriverConfig *cfg = libxlDriverConfigGet(driver);

    virCheckFlags(0, -1);

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainPMWakeupEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (virDomainObjBeginJob(vm, VIR_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjGetState(vm, NULL) != VIR_DOMAIN_PMSUSPENDED) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("Domain is not suspended"));
        goto endjob;
    }


    priv = vm->privateData;
    if (libxl_domain_resume(cfg->ctx, vm->def->id, 1, NULL) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to resume domain '%1$d'"), vm->def->id);
        goto endjob;
    }
    virDomainObjSetState(vm, VIR_DOMAIN_RUNNING, VIR_DOMAIN_RUNNING_WAKEUP);
    /* re-enable death event - libxl reports it only once */
    if (priv->deathW)
        libxl_evdisable_domain_death(cfg->ctx, priv->deathW);
    if (libxl_evenable_domain_death(cfg->ctx, vm->def->id, 0, &priv->deathW))
        goto destroy_dom;

    event = virDomainEventLifecycleNewFromObj(vm, VIR_DOMAIN_EVENT_STARTED,
                                     VIR_DOMAIN_EVENT_STARTED_WAKEUP);

    ret = 0;
    goto endjob;

 destroy_dom:
    libxlDomainDestroyInternal(driver, vm);
    vm->def->id = -1;
    virDomainObjSetState(vm, VIR_DOMAIN_SHUTOFF, VIR_DOMAIN_SHUTOFF_FAILED);
    event = virDomainEventLifecycleNewFromObj(vm, VIR_DOMAIN_EVENT_STOPPED,
                                              VIR_DOMAIN_EVENT_STOPPED_FAILED);
    libxlDomainCleanup(driver, vm);

 endjob:
    virDomainObjEndJob(vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    virObjectEventStateQueue(driver->domainEventState, event);
    return ret;
}

static char *
libxlDomainGetOSType(virDomainPtr dom)
{
    virDomainObj *vm;
    char *type = NULL;

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetOSTypeEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    type = g_strdup(virDomainOSTypeToString(vm->def->os.type));

 cleanup:
    virDomainObjEndAPI(&vm);
    return type;
}

static unsigned long long
libxlDomainGetMaxMemory(virDomainPtr dom)
{
    virDomainObj *vm;
    unsigned long long ret = 0;

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetMaxMemoryEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    ret = virDomainDefGetMemoryTotal(vm->def);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}


/*
 * Helper method for --current, --live, and --config options, and check
 * whether domain is active or can get persistent domain configuration.
 *
 * Return 0 if success, also change the flags and get the persistent
 * domain configuration if needed. Return -1 on error.
 */
static int
virDomainLiveConfigHelperMethod(virCaps *caps G_GNUC_UNUSED,
                                virDomainXMLOption *xmlopt,
                                virDomainObj *dom,
                                unsigned int *flags,
                                virDomainDef **persistentDef)
{
    if (virDomainObjUpdateModificationImpact(dom, flags) < 0)
        return -1;

    if (*flags & VIR_DOMAIN_AFFECT_CONFIG) {
        if (!(*persistentDef = virDomainObjGetPersistentDef(xmlopt, dom, NULL))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Get persistent config failed"));
            return -1;
        }
    }

    return 0;
}


static int
libxlDomainSetMemoryFlags(virDomainPtr dom, unsigned long newmem,
                          unsigned int flags)
{
    libxlDriverPrivate *driver = dom->conn->privateData;
    libxlDriverConfig *cfg = libxlDriverConfigGet(driver);
    virDomainObj *vm;
    virDomainDef *persistentDef = NULL;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_MEM_LIVE |
                  VIR_DOMAIN_MEM_CONFIG |
                  VIR_DOMAIN_MEM_MAXIMUM, -1);

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainSetMemoryFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (virDomainObjBeginJob(vm, VIR_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainLiveConfigHelperMethod(cfg->caps, driver->xmlopt, vm, &flags,
                                        &persistentDef) < 0)
        goto endjob;

    if (flags & VIR_DOMAIN_MEM_MAXIMUM) {
        /* resize the maximum memory */

        if (flags & VIR_DOMAIN_MEM_LIVE) {
            if (libxl_domain_setmaxmem(cfg->ctx, vm->def->id, newmem) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Failed to set maximum memory for domain '%1$d' with libxenlight"),
                               vm->def->id);
                goto endjob;
            }
        }

        if (flags & VIR_DOMAIN_MEM_CONFIG) {
            virDomainDefSetMemoryTotal(persistentDef, newmem);
            if (persistentDef->mem.cur_balloon > newmem)
                persistentDef->mem.cur_balloon = newmem;
            ret = virDomainDefSave(persistentDef, driver->xmlopt, cfg->configDir);
            goto endjob;
        }

    } else {
        /* resize the current memory */

        if (newmem > virDomainDefGetMemoryTotal(vm->def)) {
            virReportError(VIR_ERR_INVALID_ARG, "%s",
                           _("cannot set memory higher than max memory"));
            goto endjob;
        }

        if (flags & VIR_DOMAIN_MEM_LIVE) {
            int res;

            /* Unlock virDomainObj while ballooning memory */
            virObjectUnlock(vm);
            res = libxlSetMemoryTargetWrapper(cfg->ctx, vm->def->id, newmem, 0,
                                              /* force */ 1);
            virObjectLock(vm);
            if (res < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Failed to set memory for domain '%1$d' with libxenlight"),
                               vm->def->id);
                goto endjob;
            }
            vm->def->mem.cur_balloon = newmem;
        }

        if (flags & VIR_DOMAIN_MEM_CONFIG) {
            persistentDef->mem.cur_balloon = newmem;
            ret = virDomainDefSave(persistentDef, driver->xmlopt, cfg->configDir);
            goto endjob;
        }
    }

    ret = 0;

 endjob:
    virDomainObjEndJob(vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    virObjectUnref(cfg);
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
    libxlDriverPrivate *driver = dom->conn->privateData;
    libxlDriverConfig *cfg = libxlDriverConfigGet(driver);
    virDomainObj *vm;
    libxl_dominfo d_info;
    int ret = -1;

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetInfoEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    info->maxMem = virDomainDefGetMemoryTotal(vm->def);
    if (!virDomainObjIsActive(vm)) {
        info->cpuTime = 0;
        info->memory = vm->def->mem.cur_balloon;
    } else {
        libxl_dominfo_init(&d_info);

        if (libxl_domain_info(cfg->ctx, &d_info, vm->def->id) != 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("libxl_domain_info failed for domain '%1$d'"),
                           vm->def->id);
            goto cleanup;
        }
        info->cpuTime = d_info.cpu_time;
        info->memory = d_info.current_memkb;

        libxl_dominfo_dispose(&d_info);
    }

    info->state = virDomainObjGetState(vm, NULL);
    info->nrVirtCpu = virDomainDefGetVcpus(vm->def);
    ret = 0;

 cleanup:
    virDomainObjEndAPI(&vm);
    virObjectUnref(cfg);
    return ret;
}

static int
libxlDomainGetState(virDomainPtr dom,
                    int *state,
                    int *reason,
                    unsigned int flags)
{
    virDomainObj *vm;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetStateEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    *state = virDomainObjGetState(vm, reason);
    ret = 0;

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

/*
 * virDomainObj *must be locked on invocation
 */
static int
libxlDoDomainSave(libxlDriverPrivate *driver,
                  virDomainObj *vm,
                  const char *to,
                  bool managed)
{
    libxlDriverConfig *cfg = libxlDriverConfigGet(driver);
    libxlSavefileHeader hdr = { 0 };
    virObjectEvent *event = NULL;
    g_autofree char *xml = NULL;
    uint32_t xml_len;
    int fd = -1;
    int ret = -1;

    if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_PAUSED) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("Domain '%1$d' has to be running because libxenlight will suspend it"),
                       vm->def->id);
        goto cleanup;
    }

    if ((fd = virFileOpenAs(to, O_CREAT|O_TRUNC|O_WRONLY, S_IRUSR|S_IWUSR,
                            -1, -1, 0)) < 0) {
        virReportSystemError(-fd,
                             _("Failed to create domain save file '%1$s'"), to);
        goto cleanup;
    }

    if ((xml = virDomainDefFormat(vm->def, driver->xmlopt, 0)) == NULL)
        goto cleanup;
    xml_len = strlen(xml) + 1;

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

    /* Unlock virDomainObj while saving domain */
    virObjectUnlock(vm);
    ret = libxl_domain_suspend(cfg->ctx, vm->def->id, fd, 0, NULL);
    virObjectLock(vm);

    if (ret != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to save domain '%1$d' with libxenlight"),
                       vm->def->id);
        ret = -1;
        goto cleanup;
    }

    virDomainObjSetState(vm, VIR_DOMAIN_SHUTOFF,
                         VIR_DOMAIN_SHUTOFF_SAVED);

    event = virDomainEventLifecycleNewFromObj(vm, VIR_DOMAIN_EVENT_STOPPED,
                                         VIR_DOMAIN_EVENT_STOPPED_SAVED);

    if (libxlDomainDestroyInternal(driver, vm) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to destroy domain '%1$d'"), vm->def->id);
        goto cleanup;
    }

    libxlDomainCleanup(driver, vm);
    vm->hasManagedSave = managed;
    ret = 0;

 cleanup:
    if (VIR_CLOSE(fd) < 0)
        virReportSystemError(errno, "%s", _("cannot close file"));
    virObjectEventStateQueue(driver->domainEventState, event);
    virObjectUnref(cfg);
    return ret;
}

static int
libxlDomainSaveFlags(virDomainPtr dom, const char *to, const char *dxml,
                     unsigned int flags)
{
    libxlDriverPrivate *driver = dom->conn->privateData;
    virDomainObj *vm;
    int ret = -1;

#ifdef LIBXL_HAVE_NO_SUSPEND_RESUME
    virReportUnsupportedError();
    return -1;
#endif

    virCheckFlags(0, -1);
    if (dxml) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("xml modification unsupported"));
        return -1;
    }

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    LIBXL_CHECK_DOM0_GOTO(vm->def->name, cleanup);

    if (virDomainSaveFlagsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (virDomainObjBeginJob(vm, VIR_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjCheckActive(vm) < 0)
        goto endjob;

    if (libxlDoDomainSave(driver, vm, to, false) < 0)
        goto endjob;

    if (!vm->persistent)
        virDomainObjListRemove(driver->domains, vm);

    ret = 0;

 endjob:
    virDomainObjEndJob(vm);

 cleanup:
    virDomainObjEndAPI(&vm);
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
    libxlDriverPrivate *driver = conn->privateData;
    virDomainObj *vm = NULL;
    g_autoptr(virDomainDef) def = NULL;
    libxlSavefileHeader hdr;
    int fd = -1;
    int ret = -1;

#ifdef LIBXL_HAVE_NO_SUSPEND_RESUME
    virReportUnsupportedError();
    return -1;
#endif

    virCheckFlags(VIR_DOMAIN_SAVE_PAUSED, -1);
    if (dxml) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("xml modification unsupported"));
        return -1;
    }

    fd = libxlDomainSaveImageOpen(driver, from, &def, &hdr);
    if (fd < 0)
        goto cleanup;

    if (virDomainRestoreFlagsEnsureACL(conn, def) < 0)
        goto cleanup;

    if (!(vm = virDomainObjListAdd(driver->domains, &def,
                                   driver->xmlopt,
                                   VIR_DOMAIN_OBJ_LIST_ADD_LIVE |
                                   VIR_DOMAIN_OBJ_LIST_ADD_CHECK_LIVE,
                                   NULL)))
        goto cleanup;

    if (virDomainObjBeginJob(vm, VIR_JOB_MODIFY) < 0) {
        if (!vm->persistent)
            virDomainObjListRemove(driver->domains, vm);
        goto cleanup;
    }

    ret = libxlDomainStartRestore(driver, vm,
                                  (flags & VIR_DOMAIN_SAVE_PAUSED) != 0,
                                  fd, hdr.version);
    if (ret < 0 && !vm->persistent)
        virDomainObjListRemove(driver->domains, vm);

    virDomainObjEndJob(vm);

 cleanup:
    if (VIR_CLOSE(fd) < 0)
        virReportSystemError(errno, "%s", _("cannot close file"));
    virDomainObjEndAPI(&vm);
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
    libxlDriverPrivate *driver = dom->conn->privateData;
    libxlDriverConfig *cfg = libxlDriverConfigGet(driver);
    virDomainObj *vm;
    virObjectEvent *event = NULL;
    bool paused = false;
    int ret = -1;

    virCheckFlags(VIR_DUMP_LIVE | VIR_DUMP_CRASH, -1);

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    LIBXL_CHECK_DOM0_GOTO(vm->def->name, cleanup);

    if (virDomainCoreDumpEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (virDomainObjBeginJob(vm, VIR_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjCheckActive(vm) < 0)
        goto endjob;

    if (!(flags & VIR_DUMP_LIVE) &&
        virDomainObjGetState(vm, NULL) == VIR_DOMAIN_RUNNING) {
        if (libxlDomainPauseWrapper(cfg->ctx, vm->def->id) != 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Before dumping core, failed to suspend domain '%1$d' with libxenlight"),
                           vm->def->id);
            goto endjob;
        }
        virDomainObjSetState(vm, VIR_DOMAIN_PAUSED, VIR_DOMAIN_PAUSED_DUMP);
        paused = true;
    }

    /* Unlock virDomainObj while dumping core */
    virObjectUnlock(vm);
    ret = libxl_domain_core_dump(cfg->ctx, vm->def->id, to, NULL);
    virObjectLock(vm);
    if (ret != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to dump core of domain '%1$d' with libxenlight"),
                       vm->def->id);
        ret = -1;
        goto unpause;
    }

    if (flags & VIR_DUMP_CRASH) {
        if (libxlDomainDestroyInternal(driver, vm) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to destroy domain '%1$d'"), vm->def->id);
            goto unpause;
        }

        libxlDomainCleanup(driver, vm);
        virDomainObjSetState(vm, VIR_DOMAIN_SHUTOFF,
                             VIR_DOMAIN_SHUTOFF_CRASHED);
        event = virDomainEventLifecycleNewFromObj(vm, VIR_DOMAIN_EVENT_STOPPED,
                                         VIR_DOMAIN_EVENT_STOPPED_CRASHED);
        if (!vm->persistent)
            virDomainObjListRemove(driver->domains, vm);
    }

    ret = 0;

 unpause:
    if (virDomainObjIsActive(vm) && paused) {
        if (libxlDomainUnpauseWrapper(cfg->ctx, vm->def->id) != 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("After dumping core, failed to resume domain '%1$d' with libxenlight"),
                           vm->def->id);
        } else {
            virDomainObjSetState(vm, VIR_DOMAIN_RUNNING,
                                 VIR_DOMAIN_RUNNING_UNPAUSED);
        }
    }

 endjob:
    virDomainObjEndJob(vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    virObjectEventStateQueue(driver->domainEventState, event);
    virObjectUnref(cfg);
    return ret;
}

static int
libxlDomainManagedSave(virDomainPtr dom, unsigned int flags)
{
    libxlDriverPrivate *driver = dom->conn->privateData;
    virDomainObj *vm = NULL;
    g_autofree char *name = NULL;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    LIBXL_CHECK_DOM0_GOTO(vm->def->name, cleanup);

    if (virDomainManagedSaveEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (virDomainObjBeginJob(vm, VIR_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjCheckActive(vm) < 0)
        goto endjob;
    if (!vm->persistent) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("cannot do managed save for transient domain"));
        goto endjob;
    }

    name = libxlDomainManagedSavePath(driver, vm);
    if (name == NULL)
        goto endjob;

    VIR_INFO("Saving state to %s", name);

    if (libxlDoDomainSave(driver, vm, name, true) < 0)
        goto endjob;

    if (!vm->persistent)
        virDomainObjListRemove(driver->domains, vm);

    ret = 0;

 endjob:
    virDomainObjEndJob(vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
libxlDomainManagedSaveLoad(virDomainObj *vm,
                           void *opaque)
{
    libxlDriverPrivate *driver = opaque;
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
    virDomainObj *vm = NULL;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainHasManagedSaveImageEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    ret = vm->hasManagedSave;

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
libxlDomainManagedSaveRemove(virDomainPtr dom, unsigned int flags)
{
    libxlDriverPrivate *driver = dom->conn->privateData;
    virDomainObj *vm = NULL;
    int ret = -1;
    g_autofree char *name = NULL;

    virCheckFlags(0, -1);

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainManagedSaveRemoveEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    name = libxlDomainManagedSavePath(driver, vm);
    if (name == NULL)
        goto cleanup;

    ret = unlink(name);
    vm->hasManagedSave = false;

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
libxlDomainSetVcpusFlags(virDomainPtr dom, unsigned int nvcpus,
                         unsigned int flags)
{
    libxlDriverPrivate *driver = dom->conn->privateData;
    libxlDriverConfig *cfg = libxlDriverConfigGet(driver);
    virDomainDef *def;
    virDomainObj *vm;
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
                       _("invalid flag combination: (0x%1$x)"), flags);
        return -1;
    }

    if (!nvcpus) {
        virReportError(VIR_ERR_INVALID_ARG, "%s", _("nvcpus is zero"));
        return -1;
    }

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainSetVcpusFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (virDomainObjBeginJob(vm, VIR_JOB_MODIFY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm) && (flags & VIR_DOMAIN_VCPU_LIVE)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("cannot set vcpus on an inactive domain"));
        goto endjob;
    }

    if (!vm->persistent && (flags & VIR_DOMAIN_VCPU_CONFIG)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("cannot change persistent config of a transient domain"));
        goto endjob;
    }

    if ((max = libxlConnectGetMaxVcpus(dom->conn, NULL)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("could not determine max vcpus for the domain"));
        goto endjob;
    }

    if (!(flags & VIR_DOMAIN_VCPU_MAXIMUM) && virDomainDefGetVcpusMax(vm->def) < max)
        max = virDomainDefGetVcpusMax(vm->def);

    if (nvcpus > max) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("requested vcpus is greater than max allowable vcpus for the domain: %1$d > %2$d"),
                       nvcpus, max);
        goto endjob;
    }

    if (!(def = virDomainObjGetPersistentDef(driver->xmlopt, vm, NULL)))
        goto endjob;

    maplen = VIR_CPU_MAPLEN(nvcpus);
    bitmask = g_new0(uint8_t, maplen);

    for (i = 0; i < nvcpus; ++i) {
        pos = i / 8;
        bitmask[pos] |= 1 << (i % 8);
    }

    map.size = maplen;
    map.map = bitmask;

    switch (flags) {
    case VIR_DOMAIN_VCPU_MAXIMUM | VIR_DOMAIN_VCPU_CONFIG:
        if (virDomainDefSetVcpusMax(def, nvcpus, driver->xmlopt) < 0)
            goto cleanup;
        break;

    case VIR_DOMAIN_VCPU_CONFIG:
        if (virDomainDefSetVcpus(def, nvcpus) < 0)
            goto cleanup;
        break;

    case VIR_DOMAIN_VCPU_LIVE:
        if (libxlSetVcpuonlineWrapper(cfg->ctx, vm->def->id, &map) != 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to set vcpus for domain '%1$d' with libxenlight"),
                           vm->def->id);
            goto endjob;
        }
        if (virDomainDefSetVcpus(vm->def, nvcpus) < 0)
            goto endjob;
        break;

    case VIR_DOMAIN_VCPU_LIVE | VIR_DOMAIN_VCPU_CONFIG:
        if (libxlSetVcpuonlineWrapper(cfg->ctx, vm->def->id, &map) != 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to set vcpus for domain '%1$d' with libxenlight"),
                           vm->def->id);
            goto endjob;
        }
        if (virDomainDefSetVcpus(vm->def, nvcpus) < 0 ||
            virDomainDefSetVcpus(def, nvcpus) < 0)
            goto endjob;
        break;
    }

    ret = 0;

    if (flags & VIR_DOMAIN_VCPU_LIVE) {
        if (virDomainObjSave(vm, driver->xmlopt, cfg->stateDir) < 0) {
            VIR_WARN("Unable to save status on vm %s after changing vcpus",
                     vm->def->name);
        }
    }
    if (flags & VIR_DOMAIN_VCPU_CONFIG) {
        if (virDomainDefSave(def, driver->xmlopt, cfg->configDir) < 0) {
            VIR_WARN("Unable to save configuration of vm %s after changing vcpus",
                     vm->def->name);
        }
    }

 endjob:
    virDomainObjEndJob(vm);

 cleanup:
    VIR_FREE(bitmask);
    virDomainObjEndAPI(&vm);
    virObjectUnref(cfg);
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
    virDomainObj *vm;
    virDomainDef *def;
    int ret = -1;
    bool active;

    virCheckFlags(VIR_DOMAIN_VCPU_LIVE |
                  VIR_DOMAIN_VCPU_CONFIG |
                  VIR_DOMAIN_VCPU_MAXIMUM, -1);

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetVcpusFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
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
                       _("invalid flag combination: (0x%1$x)"), flags);
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

    if (flags & VIR_DOMAIN_VCPU_MAXIMUM)
        ret = virDomainDefGetVcpusMax(def);
    else
        ret = virDomainDefGetVcpus(def);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
libxlDomainGetMaxVcpus(virDomainPtr dom)
{
    return libxlDomainGetVcpusFlags(dom, (VIR_DOMAIN_AFFECT_LIVE |
                                          VIR_DOMAIN_VCPU_MAXIMUM));
}

static int
libxlDomainPinVcpuFlags(virDomainPtr dom, unsigned int vcpu,
                        unsigned char *cpumap, int maplen,
                        unsigned int flags)
{
    libxlDriverPrivate *driver = dom->conn->privateData;
    libxlDriverConfig *cfg = libxlDriverConfigGet(driver);
    virDomainDef *targetDef = NULL;
    g_autoptr(virBitmap) pcpumap = NULL;
    virDomainVcpuDef *vcpuinfo;
    virDomainObj *vm;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainPinVcpuFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (virDomainObjBeginJob(vm, VIR_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainLiveConfigHelperMethod(cfg->caps, driver->xmlopt, vm,
                                        &flags, &targetDef) < 0)
        goto endjob;

    if (flags & VIR_DOMAIN_AFFECT_LIVE)
        targetDef = vm->def;

    pcpumap = virBitmapNewData(cpumap, maplen);
    if (!pcpumap)
        goto endjob;

    if (!(vcpuinfo = virDomainDefGetVcpu(targetDef, vcpu)) ||
        !vcpuinfo->online) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("vcpu '%1$u' is not active"), vcpu);
        goto endjob;
    }

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        libxl_bitmap map = { .size = maplen, .map = cpumap };
        if (libxl_set_vcpuaffinity(cfg->ctx, vm->def->id, vcpu, &map, NULL) != 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to pin vcpu '%1$d' with libxenlight"),
                           vcpu);
            goto endjob;
        }
    }

    virBitmapFree(vcpuinfo->cpumask);
    vcpuinfo->cpumask = g_steal_pointer(&pcpumap);

    ret = 0;

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        ret = virDomainObjSave(vm, driver->xmlopt, cfg->stateDir);
    } else if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        ret = virDomainDefSave(targetDef, driver->xmlopt, cfg->configDir);
    }

 endjob:
    virDomainObjEndJob(vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    virObjectUnref(cfg);
    return ret;
}

static int
libxlDomainPinVcpu(virDomainPtr dom, unsigned int vcpu, unsigned char *cpumap,
                   int maplen)
{
    return libxlDomainPinVcpuFlags(dom, vcpu, cpumap, maplen,
                                   VIR_DOMAIN_AFFECT_LIVE);
}

static int
libxlDomainGetVcpuPinInfo(virDomainPtr dom, int ncpumaps,
                          unsigned char *cpumaps, int maplen,
                          unsigned int flags)
{
    libxlDriverPrivate *driver = dom->conn->privateData;
    libxlDriverConfig *cfg = libxlDriverConfigGet(driver);
    virDomainObj *vm = NULL;
    virDomainDef *targetDef = NULL;
    g_autoptr(virBitmap) hostcpus = NULL;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetVcpuPinInfoEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (virDomainLiveConfigHelperMethod(cfg->caps, driver->xmlopt, vm,
                                        &flags, &targetDef) < 0)
        goto cleanup;

    if (flags & VIR_DOMAIN_AFFECT_LIVE)
        targetDef = vm->def;

    hostcpus = virBitmapNew(libxl_get_max_cpus(cfg->ctx));
    virBitmapSetAll(hostcpus);

    ret = virDomainDefGetVcpuPinInfoHelper(targetDef, maplen, ncpumaps, cpumaps,
                                           hostcpus, NULL);

 cleanup:
    virDomainObjEndAPI(&vm);
    virObjectUnref(cfg);
    return ret;
}

static int
libxlDomainGetVcpus(virDomainPtr dom, virVcpuInfoPtr info, int maxinfo,
                    unsigned char *cpumaps, int maplen)
{
    libxlDriverPrivate *driver = dom->conn->privateData;
    libxlDriverConfig *cfg = libxlDriverConfigGet(driver);
    virDomainObj *vm;
    int ret = -1;
    libxl_vcpuinfo *vcpuinfo;
    int maxcpu, hostcpus;
    size_t i;
    unsigned char *cpumap;

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetVcpusEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (virDomainObjCheckActive(vm) < 0)
        goto cleanup;

    if ((vcpuinfo = libxl_list_vcpu(cfg->ctx, vm->def->id, &maxcpu,
                                    &hostcpus)) == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to list vcpus for domain '%1$d' with libxenlight"),
                       vm->def->id);
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
    virDomainObjEndAPI(&vm);
    virObjectUnref(cfg);
    return ret;
}

static char *
libxlDomainGetXMLDesc(virDomainPtr dom, unsigned int flags)
{
    libxlDriverPrivate *driver = dom->conn->privateData;
    libxlDriverConfig *cfg = libxlDriverConfigGet(driver);
    virDomainObj *vm;
    virDomainDef *def;
    char *ret = NULL;

    virCheckFlags(VIR_DOMAIN_XML_COMMON_FLAGS, NULL);

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetXMLDescEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if ((flags & VIR_DOMAIN_XML_INACTIVE) && vm->newDef)
        def = vm->newDef;
    else
        def = vm->def;

    ret = virDomainDefFormat(def, driver->xmlopt,
                             virDomainDefFormatConvertXMLFlags(flags));

 cleanup:
    virDomainObjEndAPI(&vm);
    virObjectUnref(cfg);
    return ret;
}

static char *
libxlConnectDomainXMLFromNative(virConnectPtr conn,
                                const char *nativeFormat,
                                const char *nativeConfig,
                                unsigned int flags)
{
    libxlDriverPrivate *driver = conn->privateData;
    libxlDriverConfig *cfg = libxlDriverConfigGet(driver);
    g_autoptr(virDomainDef) def = NULL;
    g_autoptr(virConf) conf = NULL;
    char *xml = NULL;

    virCheckFlags(0, NULL);

    if (virConnectDomainXMLFromNativeEnsureACL(conn) < 0)
        goto cleanup;

    if (STREQ(nativeFormat, XEN_CONFIG_FORMAT_XL)) {
        if (!(conf = virConfReadString(nativeConfig, 0)))
            goto cleanup;
        if (!(def = xenParseXL(conf,
                               cfg->caps,
                               driver->xmlopt)))
            goto cleanup;
    } else if (STREQ(nativeFormat, XEN_CONFIG_FORMAT_XM)) {
        if (!(conf = virConfReadString(nativeConfig, 0)))
            goto cleanup;

        if (!(def = xenParseXM(conf,
                               cfg->caps,
                               driver->xmlopt)))
            goto cleanup;
    } else if (STREQ(nativeFormat, XEN_CONFIG_FORMAT_SEXPR)) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("conversion from 'xen-sxpr' format is no longer supported"));
        goto cleanup;
    } else {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unsupported config type %1$s"), nativeFormat);
        goto cleanup;
    }

    xml = virDomainDefFormat(def, driver->xmlopt, VIR_DOMAIN_DEF_FORMAT_INACTIVE);

 cleanup:
    virObjectUnref(cfg);
    return xml;
}

#define MAX_CONFIG_SIZE (1024 * 65)
static char *
libxlConnectDomainXMLToNative(virConnectPtr conn, const char * nativeFormat,
                              const char * domainXml,
                              unsigned int flags)
{
    libxlDriverPrivate *driver = conn->privateData;
    libxlDriverConfig *cfg = libxlDriverConfigGet(driver);
    g_autoptr(virDomainDef) def = NULL;
    g_autoptr(virConf) conf = NULL;
    int len = MAX_CONFIG_SIZE;
    char *ret = NULL;

    virCheckFlags(0, NULL);

    if (virConnectDomainXMLToNativeEnsureACL(conn) < 0)
        goto cleanup;

    if (!(def = virDomainDefParseString(domainXml,
                                        driver->xmlopt, NULL,
                                        VIR_DOMAIN_DEF_PARSE_INACTIVE)))
        goto cleanup;

    if (STREQ(nativeFormat, XEN_CONFIG_FORMAT_XL)) {
        if (!(conf = xenFormatXL(def, conn)))
            goto cleanup;
    } else if (STREQ(nativeFormat, XEN_CONFIG_FORMAT_XM)) {
        if (!(conf = xenFormatXM(conn, def)))
            goto cleanup;
    } else {

        virReportError(VIR_ERR_INVALID_ARG,
                       _("unsupported config type %1$s"), nativeFormat);
        goto cleanup;
    }

    ret = g_new0(char, len);

    if (virConfWriteMem(ret, &len, conf) < 0) {
        VIR_FREE(ret);
        goto cleanup;
    }

 cleanup:
    virObjectUnref(cfg);
    return ret;
}

static int
libxlConnectListDefinedDomains(virConnectPtr conn,
                               char **const names, int nnames)
{
    libxlDriverPrivate *driver = conn->privateData;

    if (virConnectListDefinedDomainsEnsureACL(conn) < 0)
        return -1;

    return virDomainObjListGetInactiveNames(driver->domains, names, nnames,
                                            virConnectListDefinedDomainsCheckACL,
                                            conn);
}

static int
libxlConnectNumOfDefinedDomains(virConnectPtr conn)
{
    libxlDriverPrivate *driver = conn->privateData;

    if (virConnectNumOfDefinedDomainsEnsureACL(conn) < 0)
        return -1;

    return virDomainObjListNumOfDomains(driver->domains, false,
                                        virConnectNumOfDefinedDomainsCheckACL,
                                        conn);
}

static int
libxlDomainCreateWithFlags(virDomainPtr dom,
                           unsigned int flags)
{
    libxlDriverPrivate *driver = dom->conn->privateData;
    virDomainObj *vm;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_START_PAUSED, -1);

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainCreateWithFlagsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (virDomainObjBeginJob(vm, VIR_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("Domain is already running"));
        goto endjob;
    }

    ret = libxlDomainStartNew(driver, vm,
                              (flags & VIR_DOMAIN_START_PAUSED) != 0);
    if (ret < 0)
        goto endjob;
    dom->id = vm->def->id;

 endjob:
    virDomainObjEndJob(vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
libxlDomainCreate(virDomainPtr dom)
{
    return libxlDomainCreateWithFlags(dom, 0);
}

static virDomainPtr
libxlDomainDefineXMLFlags(virConnectPtr conn, const char *xml, unsigned int flags)
{
    libxlDriverPrivate *driver = conn->privateData;
    libxlDriverConfig *cfg = libxlDriverConfigGet(driver);
    g_autoptr(virDomainDef) def = NULL;
    virDomainObj *vm = NULL;
    virDomainPtr dom = NULL;
    virObjectEvent *event = NULL;
    g_autoptr(virDomainDef) oldDef = NULL;
    unsigned int parse_flags = VIR_DOMAIN_DEF_PARSE_INACTIVE;

    virCheckFlags(VIR_DOMAIN_DEFINE_VALIDATE, NULL);

    if (flags & VIR_DOMAIN_DEFINE_VALIDATE)
        parse_flags |= VIR_DOMAIN_DEF_PARSE_VALIDATE_SCHEMA;

    if (!(def = virDomainDefParseString(xml, driver->xmlopt,
                                        NULL, parse_flags)))
        goto cleanup;

    if (virXMLCheckIllegalChars("name", def->name, "\n") < 0)
        goto cleanup;

    if (virDomainDefineXMLFlagsEnsureACL(conn, def) < 0)
        goto cleanup;

    if (!(vm = virDomainObjListAdd(driver->domains, &def,
                                   driver->xmlopt,
                                   0,
                                   &oldDef)))
        goto cleanup;

    vm->persistent = 1;

    if (virDomainDefSave(vm->newDef ? vm->newDef : vm->def,
                         driver->xmlopt, cfg->configDir) < 0) {
        virDomainObjListRemove(driver->domains, vm);
        goto cleanup;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid, vm->def->id);

    event = virDomainEventLifecycleNewFromObj(vm, VIR_DOMAIN_EVENT_DEFINED,
                                     !oldDef ?
                                     VIR_DOMAIN_EVENT_DEFINED_ADDED :
                                     VIR_DOMAIN_EVENT_DEFINED_UPDATED);

 cleanup:
    virDomainObjEndAPI(&vm);
    virObjectEventStateQueue(driver->domainEventState, event);
    virObjectUnref(cfg);
    return dom;
}

static virDomainPtr
libxlDomainDefineXML(virConnectPtr conn, const char *xml)
{
    return libxlDomainDefineXMLFlags(conn, xml, 0);
}

static int
libxlDomainUndefineFlags(virDomainPtr dom,
                         unsigned int flags)
{
    libxlDriverPrivate *driver = dom->conn->privateData;
    libxlDriverConfig *cfg = libxlDriverConfigGet(driver);
    virDomainObj *vm;
    virObjectEvent *event = NULL;
    g_autofree char *name = NULL;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_UNDEFINE_MANAGED_SAVE, -1);

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

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
                           _("Refusing to undefine while domain managed save image exists"));
            goto cleanup;
        }
    }

    if (virDomainDeleteConfig(cfg->configDir, cfg->autostartDir, vm) < 0)
        goto cleanup;

    event = virDomainEventLifecycleNewFromObj(vm, VIR_DOMAIN_EVENT_UNDEFINED,
                                     VIR_DOMAIN_EVENT_UNDEFINED_REMOVED);

    if (virDomainObjIsActive(vm))
        vm->persistent = 0;
    else
        virDomainObjListRemove(driver->domains, vm);

    ret = 0;

 cleanup:
    virDomainObjEndAPI(&vm);
    virObjectEventStateQueue(driver->domainEventState, event);
    virObjectUnref(cfg);
    return ret;
}

static int
libxlDomainUndefine(virDomainPtr dom)
{
    return libxlDomainUndefineFlags(dom, 0);
}

static int
libxlDomainChangeEjectableMedia(virDomainObj *vm, virDomainDiskDef *disk)
{
    libxlDriverConfig *cfg = libxlDriverConfigGet(libxl_driver);
    virDomainDiskDef *origdisk = NULL;
    libxl_device_disk x_disk;
    size_t i;
    int ret = -1;

    libxl_device_disk_init(&x_disk);
    for (i = 0; i < vm->def->ndisks; i++) {
        if (vm->def->disks[i]->bus == disk->bus &&
            STREQ(vm->def->disks[i]->dst, disk->dst)) {
            origdisk = vm->def->disks[i];
            break;
        }
    }

    if (!origdisk) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("No device with bus '%1$s' and target '%2$s'"),
                       virDomainDiskBusTypeToString(disk->bus), disk->dst);
        goto cleanup;
    }

    if (origdisk->device != VIR_DOMAIN_DISK_DEVICE_CDROM) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Removable media not supported for %1$s device"),
                       virDomainDiskDeviceTypeToString(disk->device));
        goto cleanup;
    }

    if (libxlMakeDisk(disk, &x_disk) < 0)
        goto cleanup;

    if ((ret = libxl_cdrom_insert(cfg->ctx, vm->def->id, &x_disk, NULL)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("libxenlight failed to change media for disk '%1$s'"),
                       disk->dst);
        goto cleanup;
    }

    virDomainDiskSetSource(origdisk, virDomainDiskGetSource(disk));
    virDomainDiskSetType(origdisk, virDomainDiskGetType(disk));

    virDomainDiskDefFree(disk);

    ret = 0;

 cleanup:
    libxl_device_disk_dispose(&x_disk);
    virObjectUnref(cfg);
    return ret;
}

static int
libxlDomainAttachDeviceDiskLive(virDomainObj *vm, virDomainDeviceDef *dev)
{
    libxlDriverConfig *cfg = libxlDriverConfigGet(libxl_driver);
    virDomainDiskDef *l_disk = dev->data.disk;
    libxl_device_disk x_disk;
    int ret = -1;

    libxl_device_disk_init(&x_disk);
    switch (l_disk->device)  {
        case VIR_DOMAIN_DISK_DEVICE_CDROM:
            ret = libxlDomainChangeEjectableMedia(vm, l_disk);
            break;
        case VIR_DOMAIN_DISK_DEVICE_DISK:
            if (l_disk->bus == VIR_DOMAIN_DISK_BUS_XEN) {
                if (virDomainDiskIndexByName(vm->def, l_disk->dst, true) >= 0) {
                    virReportError(VIR_ERR_OPERATION_FAILED,
                                   _("target %1$s already exists"), l_disk->dst);
                    goto cleanup;
                }

                if (!virDomainDiskGetSource(l_disk)) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   "%s", _("disk source path is missing"));
                    goto cleanup;
                }

                if (libxlMakeDisk(l_disk, &x_disk) < 0)
                    goto cleanup;

                if (virDomainLockImageAttach(libxl_driver->lockManager,
                                             "xen:///system",
                                             vm, l_disk->src) < 0)
                    goto cleanup;

                if ((ret = libxl_device_disk_add(cfg->ctx, vm->def->id,
                                                &x_disk, NULL)) < 0) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("libxenlight failed to attach disk '%1$s'"),
                                   l_disk->dst);
                    if (virDomainLockImageDetach(libxl_driver->lockManager,
                                                 vm, l_disk->src) < 0) {
                        VIR_WARN("Unable to release lock on %s",
                                 virDomainDiskGetSource(l_disk));
                    }
                    goto cleanup;
                }

                libxlUpdateDiskDef(l_disk, &x_disk);
                virDomainDiskInsert(vm->def, l_disk);

            } else {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("disk bus '%1$s' cannot be hotplugged."),
                               virDomainDiskBusTypeToString(l_disk->bus));
            }
            break;
        case VIR_DOMAIN_DISK_DEVICE_FLOPPY:
        case VIR_DOMAIN_DISK_DEVICE_LUN:
        case VIR_DOMAIN_DISK_DEVICE_LAST:
        default:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("disk device type '%1$s' cannot be hotplugged"),
                           virDomainDiskDeviceTypeToString(l_disk->device));
            break;
    }

 cleanup:
    libxl_device_disk_dispose(&x_disk);
    virObjectUnref(cfg);
    return ret;
}

static int
libxlDomainAttachHostPCIDevice(libxlDriverPrivate *driver,
                               virDomainObj *vm,
                               virDomainHostdevDef *hostdev)
{
    libxlDriverConfig *cfg = libxlDriverConfigGet(driver);
    libxl_device_pci pcidev;
    virDomainHostdevDef *found;
    virHostdevManager *hostdev_mgr = driver->hostdevMgr;
    virDomainHostdevSubsysPCI *pcisrc = &hostdev->source.subsys.u.pci;
    int ret = -1;

    libxl_device_pci_init(&pcidev);

    if (virDomainHostdevFind(vm->def, hostdev, &found) >= 0) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("target pci device %1$04x:%2$02x:%3$02x.%4$d already exists"),
                       pcisrc->addr.domain, pcisrc->addr.bus,
                       pcisrc->addr.slot, pcisrc->addr.function);
        goto cleanup;
    }

    VIR_REALLOC_N(vm->def->hostdevs, vm->def->nhostdevs + 1);

    if (virHostdevPreparePCIDevices(hostdev_mgr, LIBXL_DRIVER_INTERNAL_NAME,
                                    vm->def->name, vm->def->uuid,
                                    &hostdev, 1, 0) < 0)
        goto cleanup;

    if (libxlMakePCI(hostdev, &pcidev) < 0)
        goto error;

    if (libxl_device_pci_add(cfg->ctx, vm->def->id, &pcidev, 0) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("libxenlight failed to attach pci device %1$04x:%2$02x:%3$02x.%4$d"),
                       pcisrc->addr.domain, pcisrc->addr.bus,
                       pcisrc->addr.slot, pcisrc->addr.function);
        goto error;
    }

    vm->def->hostdevs[vm->def->nhostdevs++] = hostdev;
    ret = 0;
    goto cleanup;

 error:
    virHostdevReAttachPCIDevices(hostdev_mgr, LIBXL_DRIVER_INTERNAL_NAME,
                                 vm->def->name, &hostdev, 1);

 cleanup:
    virObjectUnref(cfg);
    libxl_device_pci_dispose(&pcidev);
    return ret;
}

static int
libxlDomainAttachControllerDevice(libxlDriverPrivate *driver,
                                  virDomainObj *vm,
                                  virDomainControllerDef *controller)
{
    libxlDriverConfig *cfg = libxlDriverConfigGet(driver);
    const char *type = virDomainControllerTypeToString(controller->type);
    libxl_device_usbctrl usbctrl;
    int ret = -1;

    libxl_device_usbctrl_init(&usbctrl);

    if (controller->type != VIR_DOMAIN_CONTROLLER_TYPE_USB) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("'%1$s' controller cannot be hot plugged."),
                       type);
        goto cleanup;
    }

    if (controller->idx == -1)
        controller->idx = virDomainControllerFindUnusedIndex(vm->def,
                                                             controller->type);

    if (controller->opts.usbopts.ports == -1)
        controller->opts.usbopts.ports = 8;

    if (virDomainControllerFind(vm->def, controller->type, controller->idx) >= 0) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("target %1$s:%2$d already exists"),
                       type, controller->idx);
        goto cleanup;
    }

    VIR_REALLOC_N(vm->def->controllers, vm->def->ncontrollers + 1);

    if (libxlMakeUSBController(controller, &usbctrl) < 0)
        goto cleanup;

    if (libxl_device_usbctrl_add(cfg->ctx, vm->def->id, &usbctrl, 0) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("libxenlight failed to attach USB controller"));
        goto cleanup;
    }

    virDomainControllerInsertPreAlloced(vm->def, controller);
    ret = 0;

 cleanup:
    virObjectUnref(cfg);
    libxl_device_usbctrl_dispose(&usbctrl);
    return ret;
}

static int
libxlDomainAttachHostUSBDevice(libxlDriverPrivate *driver,
                               virDomainObj *vm,
                               virDomainHostdevDef *hostdev)
{
    libxlDriverConfig *cfg = libxlDriverConfigGet(driver);
    libxl_device_usbdev usbdev;
    virHostdevManager *hostdev_mgr = driver->hostdevMgr;
    int ret = -1;
    size_t i;
    int ports = 0, usbdevs = 0;

    libxl_device_usbdev_init(&usbdev);

    if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS ||
        hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB)
        goto cleanup;

    /* search for available controller:port */
    for (i = 0; i < vm->def->ncontrollers; i++)
        ports += vm->def->controllers[i]->opts.usbopts.ports;

    for (i = 0; i < vm->def->nhostdevs; i++) {
        if (hostdev->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS &&
            hostdev->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB)
            usbdevs++;
    }

    if (ports <= usbdevs) {
        /* no free ports, we will create a new usb controller */
        virDomainControllerDef *controller;

        if (!(controller = virDomainControllerDefNew(VIR_DOMAIN_CONTROLLER_TYPE_USB)))
            goto cleanup;

        controller->model = VIR_DOMAIN_CONTROLLER_MODEL_USB_QUSB2;
        controller->idx = -1;
        controller->opts.usbopts.ports = 8;

        if (libxlDomainAttachControllerDevice(driver, vm, controller) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("No available USB controller and port, and failed to attach a new one"));
            virDomainControllerDefFree(controller);
            goto cleanup;
        }
    }

    VIR_REALLOC_N(vm->def->hostdevs, vm->def->nhostdevs + 1);

    if (virHostdevPrepareUSBDevices(hostdev_mgr, LIBXL_DRIVER_INTERNAL_NAME,
                                    vm->def->name, &hostdev, 1, 0) < 0)
        goto cleanup;

    if (libxlMakeUSB(hostdev, &usbdev) < 0)
        goto reattach;

    if (libxl_device_usbdev_add(cfg->ctx, vm->def->id, &usbdev, 0) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("libxenlight failed to attach usb device Busnum:%1$3x, Devnum:%2$3x"),
                       hostdev->source.subsys.u.usb.bus,
                       hostdev->source.subsys.u.usb.device);
        goto reattach;
    }

    vm->def->hostdevs[vm->def->nhostdevs++] = hostdev;
    ret = 0;
    goto cleanup;

 reattach:
    virHostdevReAttachUSBDevices(hostdev_mgr, LIBXL_DRIVER_INTERNAL_NAME,
                                 vm->def->name, &hostdev, 1);

 cleanup:
    virObjectUnref(cfg);
    libxl_device_usbdev_dispose(&usbdev);
    return ret;
}

static int
libxlDomainAttachHostDevice(libxlDriverPrivate *driver,
                            virDomainObj *vm,
                            virDomainHostdevDef *hostdev)
{
    if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("hostdev mode '%1$s' not supported"),
                       virDomainHostdevModeTypeToString(hostdev->mode));
        return -1;
    }

    switch (hostdev->source.subsys.type) {
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI:
        if (libxlDomainAttachHostPCIDevice(driver, vm, hostdev) < 0)
            return -1;
        break;

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB:
        if (libxlDomainAttachHostUSBDevice(driver, vm, hostdev) < 0)
            return -1;
        break;

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI:
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI_HOST:
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_MDEV:
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_LAST:
    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("hostdev subsys type '%1$s' not supported"),
                       virDomainHostdevSubsysTypeToString(hostdev->source.subsys.type));
        return -1;
    }

    return 0;
}

static int
libxlDomainDetachDeviceDiskLive(virDomainObj *vm, virDomainDeviceDef *dev)
{
    libxlDriverConfig *cfg = libxlDriverConfigGet(libxl_driver);
    virDomainDiskDef *l_disk = NULL;
    libxl_device_disk x_disk;
    int idx;
    int ret = -1;

    libxl_device_disk_init(&x_disk);
    switch (dev->data.disk->device)  {
        case VIR_DOMAIN_DISK_DEVICE_DISK:
            if (dev->data.disk->bus == VIR_DOMAIN_DISK_BUS_XEN) {

                if ((idx = virDomainDiskIndexByName(vm->def,
                                                    dev->data.disk->dst,
                                                    false)) < 0) {
                    virReportError(VIR_ERR_OPERATION_FAILED,
                                   _("disk %1$s not found"), dev->data.disk->dst);
                    goto cleanup;
                }

                l_disk = vm->def->disks[idx];

                if (libxlMakeDisk(l_disk, &x_disk) < 0)
                    goto cleanup;

                if ((ret = libxl_device_disk_remove(cfg->ctx, vm->def->id,
                                                    &x_disk, NULL)) < 0) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("libxenlight failed to detach disk '%1$s'"),
                                   l_disk->dst);
                    goto cleanup;
                }

                if (virDomainLockImageDetach(libxl_driver->lockManager,
                                             vm, l_disk->src) < 0)
                    VIR_WARN("Unable to release lock on %s",
                             virDomainDiskGetSource(l_disk));

                virDomainDiskRemove(vm->def, idx);
                virDomainDiskDefFree(l_disk);

            } else {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("disk bus '%1$s' cannot be hot unplugged."),
                               virDomainDiskBusTypeToString(dev->data.disk->bus));
            }
            break;
        case VIR_DOMAIN_DISK_DEVICE_CDROM:
        case VIR_DOMAIN_DISK_DEVICE_FLOPPY:
        case VIR_DOMAIN_DISK_DEVICE_LUN:
        case VIR_DOMAIN_DISK_DEVICE_LAST:
        default:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("device type '%1$s' cannot hot unplugged"),
                           virDomainDiskDeviceTypeToString(dev->data.disk->device));
            break;
    }

 cleanup:
    libxl_device_disk_dispose(&x_disk);
    virObjectUnref(cfg);
    return ret;
}

static int
libxlDomainAttachNetDevice(libxlDriverPrivate *driver,
                           virDomainObj *vm,
                           virDomainNetDef *net)
{
    libxlDriverConfig *cfg = libxlDriverConfigGet(driver);
    virDomainNetType actualType;
    libxl_device_nic nic;
    int ret = -1;
    char mac[VIR_MAC_STRING_BUFLEN];
    g_autoptr(virConnect) conn = NULL;
    virErrorPtr save_err = NULL;

    libxl_device_nic_init(&nic);

    /* preallocate new slot for device */
    VIR_REALLOC_N(vm->def->nets, vm->def->nnets + 1);

    /* If appropriate, grab a physical device from the configured
     * network's pool of devices, or resolve bridge device name
     * to the one defined in the network definition.
     */
    if (net->type == VIR_DOMAIN_NET_TYPE_NETWORK) {
        if (!(conn = virGetConnectNetwork()))
            goto cleanup;
        if (virDomainNetAllocateActualDevice(conn, vm->def, net) < 0)
            goto cleanup;
    }

    /* final validation now that actual type is known */
    if (virDomainActualNetDefValidate(net) < 0)
        return -1;

    actualType = virDomainNetGetActualType(net);

    if (virDomainHasNet(vm->def, net)) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("network device with mac %1$s already exists"),
                       virMacAddrFormat(&net->mac, mac));
        goto cleanup;
    }

    if (actualType == VIR_DOMAIN_NET_TYPE_HOSTDEV) {
        virDomainHostdevDef *hostdev = virDomainNetGetActualHostdev(net);
        virDomainHostdevSubsysPCI *pcisrc = &hostdev->source.subsys.u.pci;

        /* For those just allocated from a network pool whose backend is
         * still VIR_DOMAIN_HOSTDEV_PCI_BACKEND_DEFAULT, we need to set
         * backend correctly.
         */
        if (hostdev->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS &&
            hostdev->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI)
            pcisrc->backend = VIR_DOMAIN_HOSTDEV_PCI_BACKEND_XEN;

        /* This is really a "smart hostdev", so it should be attached
         * as a hostdev (the hostdev code will reach over into the
         * netdev-specific code as appropriate), then also added to
         * the nets list if successful.
         */
        ret = libxlDomainAttachHostDevice(driver, vm, hostdev);
        goto cleanup;
    }

    if (libxlMakeNic(vm->def, net, &nic, true) < 0)
        goto cleanup;

    if (libxl_device_nic_add(cfg->ctx, vm->def->id, &nic, 0)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("libxenlight failed to attach network device"));
        goto cleanup;
    }

    ret = 0;

 cleanup:
    virErrorPreserveLast(&save_err);
    libxl_device_nic_dispose(&nic);
    if (!ret) {
        vm->def->nets[vm->def->nnets++] = net;
    } else {
        virDomainNetRemoveHostdev(vm->def, net);
        if (net->type == VIR_DOMAIN_NET_TYPE_NETWORK && conn)
            virDomainNetReleaseActualDevice(conn, vm->def, net);
    }
    virObjectUnref(cfg);
    virErrorRestore(&save_err);
    return ret;
}

static int
libxlDomainAttachDeviceLive(libxlDriverPrivate *driver,
                            virDomainObj *vm,
                            virDomainDeviceDef *dev)
{
    int ret = -1;

    switch (dev->type) {
        case VIR_DOMAIN_DEVICE_DISK:
            ret = libxlDomainAttachDeviceDiskLive(vm, dev);
            if (!ret)
                dev->data.disk = NULL;
            break;

        case VIR_DOMAIN_DEVICE_CONTROLLER:
            ret = libxlDomainAttachControllerDevice(driver, vm, dev->data.controller);
            if (!ret)
                dev->data.controller = NULL;
            break;

        case VIR_DOMAIN_DEVICE_NET:
            ret = libxlDomainAttachNetDevice(driver, vm,
                                             dev->data.net);
            if (!ret)
                dev->data.net = NULL;
            break;

        case VIR_DOMAIN_DEVICE_HOSTDEV:
            ret = libxlDomainAttachHostDevice(driver, vm,
                                              dev->data.hostdev);
            if (!ret)
                dev->data.hostdev = NULL;
            break;

        case VIR_DOMAIN_DEVICE_LEASE:
        case VIR_DOMAIN_DEVICE_FS:
        case VIR_DOMAIN_DEVICE_INPUT:
        case VIR_DOMAIN_DEVICE_SOUND:
        case VIR_DOMAIN_DEVICE_VIDEO:
        case VIR_DOMAIN_DEVICE_WATCHDOG:
        case VIR_DOMAIN_DEVICE_GRAPHICS:
        case VIR_DOMAIN_DEVICE_HUB:
        case VIR_DOMAIN_DEVICE_REDIRDEV:
        case VIR_DOMAIN_DEVICE_NONE:
        case VIR_DOMAIN_DEVICE_SMARTCARD:
        case VIR_DOMAIN_DEVICE_CHR:
        case VIR_DOMAIN_DEVICE_MEMBALLOON:
        case VIR_DOMAIN_DEVICE_NVRAM:
        case VIR_DOMAIN_DEVICE_LAST:
        case VIR_DOMAIN_DEVICE_RNG:
        case VIR_DOMAIN_DEVICE_TPM:
        case VIR_DOMAIN_DEVICE_PANIC:
        case VIR_DOMAIN_DEVICE_SHMEM:
        case VIR_DOMAIN_DEVICE_MEMORY:
        case VIR_DOMAIN_DEVICE_IOMMU:
        case VIR_DOMAIN_DEVICE_VSOCK:
        case VIR_DOMAIN_DEVICE_AUDIO:
        case VIR_DOMAIN_DEVICE_CRYPTO:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("device type '%1$s' cannot be attached"),
                           virDomainDeviceTypeToString(dev->type));
            break;
    }

    return ret;
}

static int
libxlDomainAttachDeviceConfig(virDomainDef *vmdef, virDomainDeviceDef *dev)
{
    virDomainDiskDef *disk;
    virDomainNetDef *net;
    virDomainHostdevDef *hostdev;
    virDomainControllerDef *controller;
    virDomainHostdevDef *found;
    char mac[VIR_MAC_STRING_BUFLEN];

    switch (dev->type) {
        case VIR_DOMAIN_DEVICE_DISK:
            disk = dev->data.disk;
            if (virDomainDiskIndexByName(vmdef, disk->dst, true) >= 0) {
                virReportError(VIR_ERR_INVALID_ARG,
                               _("target %1$s already exists."), disk->dst);
                return -1;
            }
            virDomainDiskInsert(vmdef, disk);
            /* vmdef has the pointer. Generic codes for vmdef will do all jobs */
            dev->data.disk = NULL;
            break;

        case VIR_DOMAIN_DEVICE_CONTROLLER:
            controller = dev->data.controller;
            if (controller->idx != -1 &&
                virDomainControllerFind(vmdef, controller->type,
                                        controller->idx) >= 0) {
                virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                               _("Target already exists"));
                return -1;
            }

            virDomainControllerInsert(vmdef, controller);
            dev->data.controller = NULL;
            break;

        case VIR_DOMAIN_DEVICE_NET:
            net = dev->data.net;
            if (virDomainHasNet(vmdef, net)) {
                virReportError(VIR_ERR_INVALID_ARG,
                               _("network device with mac %1$s already exists"),
                               virMacAddrFormat(&net->mac, mac));
                return -1;
            }
            if (virDomainNetInsert(vmdef, net))
                return -1;
            dev->data.net = NULL;
            break;

        case VIR_DOMAIN_DEVICE_HOSTDEV:
            hostdev = dev->data.hostdev;

            switch (hostdev->source.subsys.type) {
            case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI:
            case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB:
            case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_LAST:
                return -1;
            case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI:
            case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI_HOST:
            case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_MDEV:
                break;
            }

            if (virDomainHostdevFind(vmdef, hostdev, &found) >= 0) {
                virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                               _("device is already in the domain configuration"));
                return -1;
            }

            if (virDomainHostdevInsert(vmdef, hostdev) < 0)
                return -1;
            dev->data.hostdev = NULL;
            break;

        case VIR_DOMAIN_DEVICE_LEASE:
        case VIR_DOMAIN_DEVICE_FS:
        case VIR_DOMAIN_DEVICE_INPUT:
        case VIR_DOMAIN_DEVICE_SOUND:
        case VIR_DOMAIN_DEVICE_VIDEO:
        case VIR_DOMAIN_DEVICE_WATCHDOG:
        case VIR_DOMAIN_DEVICE_GRAPHICS:
        case VIR_DOMAIN_DEVICE_HUB:
        case VIR_DOMAIN_DEVICE_REDIRDEV:
        case VIR_DOMAIN_DEVICE_NONE:
        case VIR_DOMAIN_DEVICE_SMARTCARD:
        case VIR_DOMAIN_DEVICE_CHR:
        case VIR_DOMAIN_DEVICE_MEMBALLOON:
        case VIR_DOMAIN_DEVICE_NVRAM:
        case VIR_DOMAIN_DEVICE_LAST:
        case VIR_DOMAIN_DEVICE_RNG:
        case VIR_DOMAIN_DEVICE_TPM:
        case VIR_DOMAIN_DEVICE_PANIC:
        case VIR_DOMAIN_DEVICE_SHMEM:
        case VIR_DOMAIN_DEVICE_MEMORY:
        case VIR_DOMAIN_DEVICE_IOMMU:
        case VIR_DOMAIN_DEVICE_VSOCK:
        case VIR_DOMAIN_DEVICE_AUDIO:
        case VIR_DOMAIN_DEVICE_CRYPTO:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("persistent attach of device is not supported"));
            return -1;
    }
    return 0;
}

static int
libxlComparePCIDevice(virDomainDef *def G_GNUC_UNUSED,
                      virDomainDeviceDef *device G_GNUC_UNUSED,
                      virDomainDeviceInfo *info1,
                      void *opaque)
{
    virDomainDeviceInfo *info2 = opaque;

    if (info1->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI ||
        info2->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI)
        return 0;

    if (info1->addr.pci.domain == info2->addr.pci.domain &&
        info1->addr.pci.bus == info2->addr.pci.bus &&
        info1->addr.pci.slot == info2->addr.pci.slot &&
        info1->addr.pci.function != info2->addr.pci.function)
        return -1;
    return 0;
}

static bool
libxlIsMultiFunctionDevice(virDomainDef *def,
                           virDomainDeviceInfo *dev)
{
    if (virDomainDeviceInfoIterate(def, libxlComparePCIDevice, dev) < 0)
        return true;
    return false;
}

static int
libxlDomainDetachHostPCIDevice(libxlDriverPrivate *driver,
                               virDomainObj *vm,
                               virDomainHostdevDef *hostdev)
{
    libxlDriverConfig *cfg = libxlDriverConfigGet(driver);
    virDomainHostdevSubsys *subsys = &hostdev->source.subsys;
    virDomainHostdevSubsysPCI *pcisrc = &subsys->u.pci;
    libxl_device_pci pcidev;
    virDomainHostdevDef *detach;
    int idx;
    virHostdevManager *hostdev_mgr = driver->hostdevMgr;
    int ret = -1;

    libxl_device_pci_init(&pcidev);

    idx = virDomainHostdevFind(vm->def, hostdev, &detach);
    if (idx < 0) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("host pci device %1$04x:%2$02x:%3$02x.%4$d not found"),
                       pcisrc->addr.domain, pcisrc->addr.bus,
                       pcisrc->addr.slot, pcisrc->addr.function);
        goto cleanup;
    }

    if (libxlIsMultiFunctionDevice(vm->def, detach->info)) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("cannot hot unplug multifunction PCI device: %1$04x:%2$02x:%3$02x.%4$d"),
                       pcisrc->addr.domain, pcisrc->addr.bus,
                       pcisrc->addr.slot, pcisrc->addr.function);
        goto error;
    }


    if (libxlMakePCI(detach, &pcidev) < 0)
        goto error;

    if (libxl_device_pci_remove(cfg->ctx, vm->def->id, &pcidev, 0) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("libxenlight failed to detach pci device %1$04x:%2$02x:%3$02x.%4$d"),
                       pcisrc->addr.domain, pcisrc->addr.bus,
                       pcisrc->addr.slot, pcisrc->addr.function);
        goto error;
    }


    virDomainHostdevRemove(vm->def, idx);

    virHostdevReAttachPCIDevices(hostdev_mgr, LIBXL_DRIVER_INTERNAL_NAME,
                                 vm->def->name, &hostdev, 1);

    ret = 0;

 error:
    virDomainHostdevDefFree(detach);

 cleanup:
    virObjectUnref(cfg);
    libxl_device_pci_dispose(&pcidev);
    return ret;
}

static int
libxlDomainDetachControllerDevice(libxlDriverPrivate *driver,
                                  virDomainObj *vm,
                                  virDomainDeviceDef *dev)
{
    int idx, ret = -1;
    virDomainControllerDef *detach = NULL;
    virDomainControllerDef *controller = dev->data.controller;
    const char *type = virDomainControllerTypeToString(controller->type);
    libxl_device_usbctrl usbctrl;
    libxlDriverConfig *cfg = libxlDriverConfigGet(driver);

    libxl_device_usbctrl_init(&usbctrl);

    if (controller->type != VIR_DOMAIN_CONTROLLER_TYPE_USB) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("'%1$s' controller cannot be hot plugged."),
                       type);
        goto cleanup;
    }

    if ((idx = virDomainControllerFind(vm->def,
                                       controller->type,
                                       controller->idx)) < 0) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("controller %1$s:%2$d not found"),
                       type, controller->idx);
        goto cleanup;
    }

    detach = vm->def->controllers[idx];

    if (libxlMakeUSBController(controller, &usbctrl) < 0)
        goto cleanup;

    if (libxl_device_usbctrl_remove(cfg->ctx, vm->def->id, &usbctrl, 0) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("libxenlight failed to detach USB controller"));
        goto cleanup;
    }

    virDomainControllerRemove(vm->def, idx);
    ret = 0;

 cleanup:
    virDomainControllerDefFree(detach);
    virObjectUnref(cfg);
    libxl_device_usbctrl_dispose(&usbctrl);
    return ret;
}

static int
libxlDomainDetachHostUSBDevice(libxlDriverPrivate *driver,
                               virDomainObj *vm,
                               virDomainHostdevDef *hostdev)
{
    libxlDriverConfig *cfg = libxlDriverConfigGet(driver);
    virDomainHostdevSubsys *subsys = &hostdev->source.subsys;
    virDomainHostdevSubsysUSB *usbsrc = &subsys->u.usb;
    virHostdevManager *hostdev_mgr = driver->hostdevMgr;
    libxl_device_usbdev usbdev;
    libxl_device_usbdev *usbdevs = NULL;
    int num = 0;
    virDomainHostdevDef *detach;
    int idx;
    size_t i;
    bool found = false;
    int ret = -1;

    libxl_device_usbdev_init(&usbdev);

    idx = virDomainHostdevFind(vm->def, hostdev, &detach);
    if (idx < 0) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("host USB device Busnum: %1$3x, Devnum: %2$3x not found"),
                       usbsrc->bus, usbsrc->device);
        goto cleanup;
    }

    usbdevs = libxl_device_usbdev_list(cfg->ctx, vm->def->id, &num);
    for (i = 0; i < num; i++) {
        if (usbdevs[i].u.hostdev.hostbus == usbsrc->bus &&
            usbdevs[i].u.hostdev.hostaddr == usbsrc->device) {
            libxl_device_usbdev_copy(cfg->ctx, &usbdev, &usbdevs[i]);
            found = true;
            break;
        }
    }
    libxl_device_usbdev_list_free(usbdevs, num);

    if (!found) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("host USB device Busnum: %1$3x, Devnum: %2$3x not found"),
                       usbsrc->bus, usbsrc->device);
        goto cleanup;
    }

    if (libxl_device_usbdev_remove(cfg->ctx, vm->def->id, &usbdev, 0) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("libxenlight failed to detach USB device Busnum: %1$3x, Devnum: %2$3x"),
                       usbsrc->bus, usbsrc->device);
        goto cleanup;
    }

    virDomainHostdevRemove(vm->def, idx);

    virHostdevReAttachUSBDevices(hostdev_mgr, LIBXL_DRIVER_INTERNAL_NAME,
                                 vm->def->name, &hostdev, 1);

    ret = 0;

 cleanup:
    virDomainHostdevDefFree(detach);
    virObjectUnref(cfg);
    libxl_device_usbdev_dispose(&usbdev);
    return ret;
}

static int
libxlDomainDetachHostDevice(libxlDriverPrivate *driver,
                            virDomainObj *vm,
                            virDomainHostdevDef *hostdev)
{
    virDomainHostdevSubsys *subsys = &hostdev->source.subsys;

    if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("hostdev mode '%1$s' not supported"),
                       virDomainHostdevModeTypeToString(hostdev->mode));
        return -1;
    }

    switch (subsys->type) {
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI:
            return libxlDomainDetachHostPCIDevice(driver, vm, hostdev);

        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB:
            return libxlDomainDetachHostUSBDevice(driver, vm, hostdev);

        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI:
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI_HOST:
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_MDEV:
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_LAST:
        default:
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unexpected hostdev type %1$d"), subsys->type);
            break;
    }

    return -1;
}

static int
libxlDomainDetachNetDevice(libxlDriverPrivate *driver,
                           virDomainObj *vm,
                           virDomainNetDef *net)
{
    libxlDriverConfig *cfg = libxlDriverConfigGet(driver);
    int detachidx;
    virDomainNetDef *detach = NULL;
    libxl_device_nic nic;
    char mac[VIR_MAC_STRING_BUFLEN];
    int ret = -1;
    virErrorPtr save_err = NULL;

    libxl_device_nic_init(&nic);

    if ((detachidx = virDomainNetFindIdx(vm->def, net)) < 0)
        goto cleanup;

    detach = vm->def->nets[detachidx];

    if (virDomainNetGetActualType(detach) == VIR_DOMAIN_NET_TYPE_HOSTDEV) {
        /* This is really a "smart hostdev", so it should be attached as a
         * hostdev, then also removed from nets list (see out:) if successful.
         */
        ret = libxlDomainDetachHostDevice(driver, vm,
                                          virDomainNetGetActualHostdev(detach));
        goto cleanup;
    }

    if (libxl_mac_to_device_nic(cfg->ctx, vm->def->id,
                                virMacAddrFormat(&detach->mac, mac), &nic))
        goto cleanup;

    if (libxl_device_nic_remove(cfg->ctx, vm->def->id, &nic, 0)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("libxenlight failed to detach network device"));
        goto cleanup;
    }

    ret = 0;

 cleanup:
    virErrorPreserveLast(&save_err);
    libxl_device_nic_dispose(&nic);
    if (!ret) {
        if (detach->type == VIR_DOMAIN_NET_TYPE_NETWORK) {
            g_autoptr(virConnect) conn = virGetConnectNetwork();
            if (conn)
                virDomainNetReleaseActualDevice(conn, vm->def, detach);
            else
                VIR_WARN("Unable to release network device '%s'", NULLSTR(detach->ifname));
        }
        virDomainNetRemove(vm->def, detachidx);
    }
    virObjectUnref(cfg);
    virErrorRestore(&save_err);
    return ret;
}

static int
libxlDomainDetachDeviceLive(libxlDriverPrivate *driver,
                            virDomainObj *vm,
                            virDomainDeviceDef *dev)
{
    virDomainHostdevDef *hostdev;
    int ret = -1;

    switch (dev->type) {
        case VIR_DOMAIN_DEVICE_DISK:
            ret = libxlDomainDetachDeviceDiskLive(vm, dev);
            break;

        case VIR_DOMAIN_DEVICE_CONTROLLER:
            ret = libxlDomainDetachControllerDevice(driver, vm, dev);
            break;

        case VIR_DOMAIN_DEVICE_NET:
            ret = libxlDomainDetachNetDevice(driver, vm,
                                             dev->data.net);
            break;

        case VIR_DOMAIN_DEVICE_HOSTDEV:
            hostdev = dev->data.hostdev;

            /* If this is a network hostdev, we need to use the higher-level
             * detach function so that mac address / virtualport are reset
             */
            if (hostdev->parentnet)
                ret = libxlDomainDetachNetDevice(driver, vm,
                                                 hostdev->parentnet);
            else
                ret = libxlDomainDetachHostDevice(driver, vm, hostdev);
            break;

        case VIR_DOMAIN_DEVICE_LEASE:
        case VIR_DOMAIN_DEVICE_FS:
        case VIR_DOMAIN_DEVICE_INPUT:
        case VIR_DOMAIN_DEVICE_SOUND:
        case VIR_DOMAIN_DEVICE_VIDEO:
        case VIR_DOMAIN_DEVICE_WATCHDOG:
        case VIR_DOMAIN_DEVICE_GRAPHICS:
        case VIR_DOMAIN_DEVICE_HUB:
        case VIR_DOMAIN_DEVICE_REDIRDEV:
        case VIR_DOMAIN_DEVICE_NONE:
        case VIR_DOMAIN_DEVICE_SMARTCARD:
        case VIR_DOMAIN_DEVICE_CHR:
        case VIR_DOMAIN_DEVICE_MEMBALLOON:
        case VIR_DOMAIN_DEVICE_NVRAM:
        case VIR_DOMAIN_DEVICE_LAST:
        case VIR_DOMAIN_DEVICE_RNG:
        case VIR_DOMAIN_DEVICE_TPM:
        case VIR_DOMAIN_DEVICE_PANIC:
        case VIR_DOMAIN_DEVICE_SHMEM:
        case VIR_DOMAIN_DEVICE_MEMORY:
        case VIR_DOMAIN_DEVICE_IOMMU:
        case VIR_DOMAIN_DEVICE_VSOCK:
        case VIR_DOMAIN_DEVICE_AUDIO:
        case VIR_DOMAIN_DEVICE_CRYPTO:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("device type '%1$s' cannot be detached"),
                           virDomainDeviceTypeToString(dev->type));
            break;
    }

    return ret;
}


static int
libxlDomainDetachDeviceConfig(virDomainDef *vmdef, virDomainDeviceDef *dev)
{
    virDomainDiskDef *disk;
    virDomainDiskDef *detach;
    virDomainHostdevDef *hostdev;
    virDomainHostdevDef *det_hostdev;
    virDomainControllerDef *cont;
    virDomainControllerDef *det_cont;
    virDomainNetDef *net;
    int idx;

    switch (dev->type) {
        case VIR_DOMAIN_DEVICE_DISK:
            disk = dev->data.disk;
            if (!(detach = virDomainDiskRemoveByName(vmdef, disk->dst))) {
                virReportError(VIR_ERR_INVALID_ARG,
                               _("no target device %1$s"), disk->dst);
                return -1;
            }
            virDomainDiskDefFree(detach);
            break;

        case VIR_DOMAIN_DEVICE_CONTROLLER:
            cont = dev->data.controller;
            if ((idx = virDomainControllerFind(vmdef, cont->type,
                                               cont->idx)) < 0) {
                virReportError(VIR_ERR_INVALID_ARG, "%s",
                               _("device not present in domain configuration"));
                return -1;
            }
            det_cont = virDomainControllerRemove(vmdef, idx);
            virDomainControllerDefFree(det_cont);
            break;

        case VIR_DOMAIN_DEVICE_NET:
            net = dev->data.net;
            if ((idx = virDomainNetFindIdx(vmdef, net)) < 0)
                return -1;

            /* this is guaranteed to succeed */
            virDomainNetDefFree(virDomainNetRemove(vmdef, idx));
            break;

        case VIR_DOMAIN_DEVICE_HOSTDEV: {
            hostdev = dev->data.hostdev;
            if ((idx = virDomainHostdevFind(vmdef, hostdev, &det_hostdev)) < 0) {
                virReportError(VIR_ERR_INVALID_ARG, "%s",
                               _("device not present in domain configuration"));
                return -1;
            }
            virDomainHostdevRemove(vmdef, idx);
            virDomainHostdevDefFree(det_hostdev);
            break;
        }

        case VIR_DOMAIN_DEVICE_LEASE:
        case VIR_DOMAIN_DEVICE_FS:
        case VIR_DOMAIN_DEVICE_INPUT:
        case VIR_DOMAIN_DEVICE_SOUND:
        case VIR_DOMAIN_DEVICE_VIDEO:
        case VIR_DOMAIN_DEVICE_WATCHDOG:
        case VIR_DOMAIN_DEVICE_GRAPHICS:
        case VIR_DOMAIN_DEVICE_HUB:
        case VIR_DOMAIN_DEVICE_REDIRDEV:
        case VIR_DOMAIN_DEVICE_NONE:
        case VIR_DOMAIN_DEVICE_SMARTCARD:
        case VIR_DOMAIN_DEVICE_CHR:
        case VIR_DOMAIN_DEVICE_MEMBALLOON:
        case VIR_DOMAIN_DEVICE_NVRAM:
        case VIR_DOMAIN_DEVICE_LAST:
        case VIR_DOMAIN_DEVICE_RNG:
        case VIR_DOMAIN_DEVICE_TPM:
        case VIR_DOMAIN_DEVICE_PANIC:
        case VIR_DOMAIN_DEVICE_SHMEM:
        case VIR_DOMAIN_DEVICE_MEMORY:
        case VIR_DOMAIN_DEVICE_IOMMU:
        case VIR_DOMAIN_DEVICE_VSOCK:
        case VIR_DOMAIN_DEVICE_AUDIO:
        case VIR_DOMAIN_DEVICE_CRYPTO:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("persistent detach of device is not supported"));
            return -1;
    }

    return 0;
}

static int
libxlDomainUpdateDeviceLive(virDomainObj *vm, virDomainDeviceDef *dev)
{
    virDomainDiskDef *disk;
    int ret = -1;

    switch (dev->type) {
        case VIR_DOMAIN_DEVICE_DISK:
            disk = dev->data.disk;
            switch (disk->device) {
                case VIR_DOMAIN_DISK_DEVICE_CDROM:
                    ret = libxlDomainChangeEjectableMedia(vm, disk);
                    if (ret == 0)
                        dev->data.disk = NULL;
                    break;
                case VIR_DOMAIN_DISK_DEVICE_DISK:
                case VIR_DOMAIN_DISK_DEVICE_FLOPPY:
                case VIR_DOMAIN_DISK_DEVICE_LUN:
                case VIR_DOMAIN_DISK_DEVICE_LAST:
                default:
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("disk bus '%1$s' cannot be updated."),
                                   virDomainDiskBusTypeToString(disk->bus));
                    break;
            }
            break;

        case VIR_DOMAIN_DEVICE_LEASE:
        case VIR_DOMAIN_DEVICE_FS:
        case VIR_DOMAIN_DEVICE_NET:
        case VIR_DOMAIN_DEVICE_INPUT:
        case VIR_DOMAIN_DEVICE_SOUND:
        case VIR_DOMAIN_DEVICE_VIDEO:
        case VIR_DOMAIN_DEVICE_HOSTDEV:
        case VIR_DOMAIN_DEVICE_WATCHDOG:
        case VIR_DOMAIN_DEVICE_CONTROLLER:
        case VIR_DOMAIN_DEVICE_GRAPHICS:
        case VIR_DOMAIN_DEVICE_HUB:
        case VIR_DOMAIN_DEVICE_REDIRDEV:
        case VIR_DOMAIN_DEVICE_NONE:
        case VIR_DOMAIN_DEVICE_SMARTCARD:
        case VIR_DOMAIN_DEVICE_CHR:
        case VIR_DOMAIN_DEVICE_MEMBALLOON:
        case VIR_DOMAIN_DEVICE_NVRAM:
        case VIR_DOMAIN_DEVICE_LAST:
        case VIR_DOMAIN_DEVICE_RNG:
        case VIR_DOMAIN_DEVICE_TPM:
        case VIR_DOMAIN_DEVICE_PANIC:
        case VIR_DOMAIN_DEVICE_SHMEM:
        case VIR_DOMAIN_DEVICE_MEMORY:
        case VIR_DOMAIN_DEVICE_IOMMU:
        case VIR_DOMAIN_DEVICE_VSOCK:
        case VIR_DOMAIN_DEVICE_AUDIO:
        case VIR_DOMAIN_DEVICE_CRYPTO:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("device type '%1$s' cannot be updated"),
                           virDomainDeviceTypeToString(dev->type));
            break;
    }

    return ret;
}

static int
libxlDomainUpdateDeviceConfig(virDomainDef *vmdef, virDomainDeviceDef *dev)
{
    virDomainDiskDef *orig;
    virDomainDiskDef *disk;

    switch (dev->type) {
        case VIR_DOMAIN_DEVICE_DISK:
            disk = dev->data.disk;
            if (!(orig = virDomainDiskByTarget(vmdef, disk->dst))) {
                virReportError(VIR_ERR_INVALID_ARG,
                               _("target %1$s doesn't exist."), disk->dst);
                return -1;
            }
            if (!(orig->device == VIR_DOMAIN_DISK_DEVICE_CDROM)) {
                virReportError(VIR_ERR_INVALID_ARG, "%s",
                               _("this disk doesn't support update"));
                return -1;
            }

            virDomainDiskSetSource(orig, virDomainDiskGetSource(disk));
            virDomainDiskSetType(orig, virDomainDiskGetType(disk));
            virDomainDiskSetFormat(orig, virDomainDiskGetFormat(disk));
            virDomainDiskSetDriver(orig, virDomainDiskGetDriver(disk));
            break;

        case VIR_DOMAIN_DEVICE_LEASE:
        case VIR_DOMAIN_DEVICE_FS:
        case VIR_DOMAIN_DEVICE_NET:
        case VIR_DOMAIN_DEVICE_INPUT:
        case VIR_DOMAIN_DEVICE_SOUND:
        case VIR_DOMAIN_DEVICE_VIDEO:
        case VIR_DOMAIN_DEVICE_HOSTDEV:
        case VIR_DOMAIN_DEVICE_WATCHDOG:
        case VIR_DOMAIN_DEVICE_CONTROLLER:
        case VIR_DOMAIN_DEVICE_GRAPHICS:
        case VIR_DOMAIN_DEVICE_HUB:
        case VIR_DOMAIN_DEVICE_REDIRDEV:
        case VIR_DOMAIN_DEVICE_NONE:
        case VIR_DOMAIN_DEVICE_SMARTCARD:
        case VIR_DOMAIN_DEVICE_CHR:
        case VIR_DOMAIN_DEVICE_MEMBALLOON:
        case VIR_DOMAIN_DEVICE_NVRAM:
        case VIR_DOMAIN_DEVICE_LAST:
        case VIR_DOMAIN_DEVICE_RNG:
        case VIR_DOMAIN_DEVICE_TPM:
        case VIR_DOMAIN_DEVICE_PANIC:
        case VIR_DOMAIN_DEVICE_SHMEM:
        case VIR_DOMAIN_DEVICE_MEMORY:
        case VIR_DOMAIN_DEVICE_IOMMU:
        case VIR_DOMAIN_DEVICE_VSOCK:
        case VIR_DOMAIN_DEVICE_AUDIO:
        case VIR_DOMAIN_DEVICE_CRYPTO:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("persistent update of device is not supported"));
            return -1;
    }

    return 0;
}


static void
libxlDomainAttachDeviceNormalize(const virDomainDeviceDef *devConf,
                                 virDomainDeviceDef *devLive)
{
    /*
     * Fixup anything that needs to be identical in the live and
     * config versions of DeviceDef, but might not be. Do this by
     * changing the contents of devLive. This is done after all
     * post-parse tweaks and validation, so be very careful about what
     * changes are made.
     */

    /* MAC address should be identical in both DeviceDefs, but if it
     * wasn't specified in the XML, and was instead autogenerated, it
     * will be different for the two since they are each the result of
     * a separate parser call. If it *was* specified, it will already
     * be the same, so copying does no harm.
     */

    if (devConf->type == VIR_DOMAIN_DEVICE_NET)
        virMacAddrSet(&devLive->data.net->mac, &devConf->data.net->mac);

}


static int
libxlDomainAttachDeviceFlags(virDomainPtr dom, const char *xml,
                             unsigned int flags)
{
    libxlDriverPrivate *driver = dom->conn->privateData;
    libxlDriverConfig *cfg = libxlDriverConfigGet(driver);
    virDomainObj *vm = NULL;
    g_autoptr(virDomainDef) vmdef = NULL;
    virDomainDeviceDef *devConf = NULL;
    virDomainDeviceDef devConfSave = { 0 };
    virDomainDeviceDef *devLive = NULL;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_DEVICE_MODIFY_LIVE |
                  VIR_DOMAIN_DEVICE_MODIFY_CONFIG, -1);

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainAttachDeviceFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (virDomainObjBeginJob(vm, VIR_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjUpdateModificationImpact(vm, &flags) < 0)
        goto endjob;

    if (flags & VIR_DOMAIN_DEVICE_MODIFY_CONFIG) {
        if (!(devConf = virDomainDeviceDefParse(xml, vm->def,
                                                driver->xmlopt, NULL,
                                                VIR_DOMAIN_DEF_PARSE_INACTIVE)))
            goto endjob;

        /* Make a copy for updated domain. */
        if (!(vmdef = virDomainObjCopyPersistentDef(vm, driver->xmlopt, NULL)))
            goto endjob;

        /*
         * devConf will be NULLed out by
         * libxlDomainAttachDeviceConfig(), so save it for later use by
         * libxlDomainAttachDeviceNormalize()
         */
        devConfSave = *devConf;

        if (libxlDomainAttachDeviceConfig(vmdef, devConf) < 0)
            goto endjob;
    }

    if (flags & VIR_DOMAIN_DEVICE_MODIFY_LIVE) {
        if (!(devLive = virDomainDeviceDefParse(xml, vm->def,
                                            driver->xmlopt, NULL,
                                            VIR_DOMAIN_DEF_PARSE_INACTIVE)))
            goto endjob;

        if (flags & VIR_DOMAIN_AFFECT_CONFIG)
            libxlDomainAttachDeviceNormalize(&devConfSave, devLive);

        if (libxlDomainAttachDeviceLive(driver, vm, devLive) < 0)
            goto endjob;

        /*
         * update domain status forcibly because the domain status may be
         * changed even if we attach the device failed.
         */
        if (virDomainObjSave(vm, driver->xmlopt, cfg->stateDir) < 0)
            goto endjob;
    }

    ret = 0;

    /* Finally, if no error until here, we can save config. */
    if (flags & VIR_DOMAIN_DEVICE_MODIFY_CONFIG) {
        ret = virDomainDefSave(vmdef, driver->xmlopt, cfg->configDir);
        if (!ret)
            virDomainObjAssignDef(vm, &vmdef, false, NULL);
    }

 endjob:
    virDomainObjEndJob(vm);

 cleanup:
    virDomainDeviceDefFree(devConf);
    virDomainDeviceDefFree(devLive);
    virDomainObjEndAPI(&vm);
    virObjectUnref(cfg);
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
    libxlDriverPrivate *driver = dom->conn->privateData;
    libxlDriverConfig *cfg = libxlDriverConfigGet(driver);
    virDomainObj *vm = NULL;
    g_autoptr(virDomainDef) vmdef = NULL;
    virDomainDeviceDef *dev = NULL;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_DEVICE_MODIFY_LIVE |
                  VIR_DOMAIN_DEVICE_MODIFY_CONFIG, -1);

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainDetachDeviceFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (virDomainObjBeginJob(vm, VIR_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjUpdateModificationImpact(vm, &flags) < 0)
        goto endjob;

    if (flags & VIR_DOMAIN_DEVICE_MODIFY_CONFIG) {
        if (!(dev = virDomainDeviceDefParse(xml, vm->def,
                                            driver->xmlopt, NULL,
                                            VIR_DOMAIN_DEF_PARSE_INACTIVE |
                                            VIR_DOMAIN_DEF_PARSE_SKIP_VALIDATE)))
            goto endjob;

        /* Make a copy for updated domain. */
        if (!(vmdef = virDomainObjCopyPersistentDef(vm, driver->xmlopt, NULL)))
            goto endjob;

        if (libxlDomainDetachDeviceConfig(vmdef, dev) < 0)
            goto endjob;
    }

    if (flags & VIR_DOMAIN_DEVICE_MODIFY_LIVE) {
        /* If dev exists it was created to modify the domain config. Free it. */
        virDomainDeviceDefFree(dev);
        if (!(dev = virDomainDeviceDefParse(xml, vm->def,
                                            driver->xmlopt, NULL,
                                            VIR_DOMAIN_DEF_PARSE_INACTIVE |
                                            VIR_DOMAIN_DEF_PARSE_SKIP_VALIDATE)))
            goto endjob;

        if (libxlDomainDetachDeviceLive(driver, vm, dev) < 0)
            goto endjob;

        /*
         * update domain status forcibly because the domain status may be
         * changed even if we attach the device failed.
         */
        if (virDomainObjSave(vm, driver->xmlopt, cfg->stateDir) < 0)
            goto endjob;
    }

    ret = 0;

    /* Finally, if no error until here, we can save config. */
    if (flags & VIR_DOMAIN_DEVICE_MODIFY_CONFIG) {
        ret = virDomainDefSave(vmdef, driver->xmlopt, cfg->configDir);
        if (!ret)
            virDomainObjAssignDef(vm, &vmdef, false, NULL);
    }

 endjob:
    virDomainObjEndJob(vm);

 cleanup:
    virDomainDeviceDefFree(dev);
    virDomainObjEndAPI(&vm);
    virObjectUnref(cfg);
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
    libxlDriverPrivate *driver = dom->conn->privateData;
    libxlDriverConfig *cfg = libxlDriverConfigGet(driver);
    virDomainObj *vm = NULL;
    g_autoptr(virDomainDef) vmdef = NULL;
    virDomainDeviceDef *dev = NULL;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_DEVICE_MODIFY_LIVE |
                  VIR_DOMAIN_DEVICE_MODIFY_CONFIG, -1);

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainUpdateDeviceFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (virDomainObjUpdateModificationImpact(vm, &flags) < 0)
        goto cleanup;

    if (flags & VIR_DOMAIN_DEVICE_MODIFY_CONFIG) {
        if (!(dev = virDomainDeviceDefParse(xml, vm->def,
                                            driver->xmlopt, NULL,
                                            VIR_DOMAIN_DEF_PARSE_INACTIVE)))
            goto cleanup;

        /* Make a copy for updated domain. */
        if (!(vmdef = virDomainObjCopyPersistentDef(vm, driver->xmlopt, NULL)))
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
                                            driver->xmlopt, NULL,
                                            VIR_DOMAIN_DEF_PARSE_INACTIVE)))
            goto cleanup;

        if ((ret = libxlDomainUpdateDeviceLive(vm, dev)) < 0)
            goto cleanup;

        /*
         * update domain status forcibly because the domain status may be
         * changed even if we attach the device failed.
         */
        if (virDomainObjSave(vm, driver->xmlopt, cfg->stateDir) < 0)
            ret = -1;
    }

    /* Finally, if no error until here, we can save config. */
    if (!ret && (flags & VIR_DOMAIN_DEVICE_MODIFY_CONFIG)) {
        ret = virDomainDefSave(vmdef, driver->xmlopt, cfg->configDir);
        if (!ret)
            virDomainObjAssignDef(vm, &vmdef, false, NULL);
    }

 cleanup:
    virDomainDeviceDefFree(dev);
    virDomainObjEndAPI(&vm);
    virObjectUnref(cfg);
    return ret;
}

static unsigned long long
libxlNodeGetFreeMemory(virConnectPtr conn)
{
    libxl_physinfo phy_info;
    libxlDriverPrivate *driver = conn->privateData;
    libxlDriverConfig *cfg = libxlDriverConfigGet(driver);
    unsigned long long ret = 0;

    libxl_physinfo_init(&phy_info);
    if (virNodeGetFreeMemoryEnsureACL(conn) < 0)
        goto cleanup;

    if (libxl_get_physinfo(cfg->ctx, &phy_info)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("libxl_get_physinfo_info failed"));
        goto cleanup;
    }

    ret = phy_info.free_pages * cfg->verInfo->pagesize;

 cleanup:
    libxl_physinfo_dispose(&phy_info);
    virObjectUnref(cfg);
    return ret;
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
    libxlDriverPrivate *driver = conn->privateData;
    libxlDriverConfig *cfg = libxlDriverConfigGet(driver);

    if (virNodeGetCellsFreeMemoryEnsureACL(conn) < 0)
        goto cleanup;

    numa_info = libxl_get_numainfo(cfg->ctx, &nr_nodes);
    if (numa_info == NULL || nr_nodes == 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("libxl_get_numainfo failed"));
        goto cleanup;
    }

    /* Check/sanitize the cell range */
    if (startCell >= nr_nodes) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("start cell %1$d out of range (0-%2$d)"),
                       startCell, nr_nodes - 1);
        goto cleanup;
    }
    lastCell = startCell + maxCells - 1;
    if (lastCell >= nr_nodes)
        lastCell = nr_nodes - 1;

    for (numCells = 0, n = startCell; n <= lastCell; n++) {
        if (numa_info[n].size == LIBXL_NUMAINFO_INVALID_ENTRY)
            freeMems[numCells++] = 0;
        else
            freeMems[numCells++] = numa_info[n].free;
    }

    ret = numCells;

 cleanup:
    libxl_numainfo_list_free(numa_info, nr_nodes);
    virObjectUnref(cfg);
    return ret;
}

static int
libxlConnectDomainEventRegister(virConnectPtr conn,
                                virConnectDomainEventCallback callback,
                                void *opaque,
                                virFreeCallback freecb)
{
    libxlDriverPrivate *driver = conn->privateData;

    if (virConnectDomainEventRegisterEnsureACL(conn) < 0)
        return -1;

    if (virDomainEventStateRegister(conn,
                                    driver->domainEventState,
                                    callback, opaque, freecb) < 0)
        return -1;

    return 0;
}


static int
libxlConnectDomainEventDeregister(virConnectPtr conn,
                                  virConnectDomainEventCallback callback)
{
    libxlDriverPrivate *driver = conn->privateData;

    if (virConnectDomainEventDeregisterEnsureACL(conn) < 0)
        return -1;

    if (virDomainEventStateDeregister(conn,
                                      driver->domainEventState,
                                      callback) < 0)
        return -1;

    return 0;
}

static int
libxlDomainGetAutostart(virDomainPtr dom, int *autostart)
{
    virDomainObj *vm;
    int ret = -1;

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetAutostartEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    *autostart = vm->autostart;
    ret = 0;

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
libxlDomainSetAutostart(virDomainPtr dom, int autostart)
{
    libxlDriverPrivate *driver = dom->conn->privateData;
    libxlDriverConfig *cfg = libxlDriverConfigGet(driver);
    virDomainObj *vm;
    g_autofree char *configFile = NULL;
    g_autofree char *autostartLink = NULL;
    int ret = -1;

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    LIBXL_CHECK_DOM0_GOTO(vm->def->name, cleanup);

    if (virDomainSetAutostartEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (virDomainObjBeginJob(vm, VIR_JOB_MODIFY) < 0)
        goto cleanup;

    if (!vm->persistent) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("cannot set autostart for transient domain"));
        goto endjob;
    }

    autostart = (autostart != 0);

    if (vm->autostart != autostart) {
        if (!(configFile = virDomainConfigFile(cfg->configDir, vm->def->name)))
            goto endjob;
        if (!(autostartLink = virDomainConfigFile(cfg->autostartDir, vm->def->name)))
            goto endjob;

        if (autostart) {
            if (g_mkdir_with_parents(cfg->autostartDir, 0777) < 0) {
                virReportSystemError(errno,
                                     _("cannot create autostart directory %1$s"),
                                     cfg->autostartDir);
                goto endjob;
            }

            if (symlink(configFile, autostartLink) < 0) {
                virReportSystemError(errno,
                                     _("Failed to create symlink '%1$s' to '%2$s'"),
                                     autostartLink, configFile);
                goto endjob;
            }
        } else {
            if (unlink(autostartLink) < 0 && errno != ENOENT && errno != ENOTDIR) {
                virReportSystemError(errno,
                                     _("Failed to delete symlink '%1$s'"),
                                     autostartLink);
                goto endjob;
            }
        }

        vm->autostart = autostart;
    }
    ret = 0;

 endjob:
    virDomainObjEndJob(vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    virObjectUnref(cfg);
    return ret;
}

static char *
libxlDomainGetSchedulerType(virDomainPtr dom, int *nparams)
{
    libxlDriverPrivate *driver = dom->conn->privateData;
    libxlDriverConfig *cfg = libxlDriverConfigGet(driver);
    virDomainObj *vm;
    char * ret = NULL;
    const char *name = NULL;
    libxl_scheduler sched_id;

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetSchedulerTypeEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (virDomainObjCheckActive(vm) < 0)
        goto cleanup;

    sched_id = libxl_get_scheduler(cfg->ctx);

    if (nparams)
        *nparams = 0;
    switch ((int)sched_id) {
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
        if (nparams)
            *nparams = XEN_SCHED_CREDIT_NPARAM;
        break;
    case LIBXL_SCHEDULER_ARINC653:
        name = "arinc653";
        break;
    default:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to get scheduler id for domain '%1$d' with libxenlight"),
                       vm->def->id);
        goto cleanup;
    }

    ret = g_strdup(name);

 cleanup:
    virDomainObjEndAPI(&vm);
    virObjectUnref(cfg);
    return ret;
}

static int
libxlDomainGetSchedulerParametersFlags(virDomainPtr dom,
                                       virTypedParameterPtr params,
                                       int *nparams,
                                       unsigned int flags)
{
    libxlDriverPrivate *driver = dom->conn->privateData;
    libxlDriverConfig *cfg = libxlDriverConfigGet(driver);
    virDomainObj *vm;
    libxl_domain_sched_params sc_info;
    libxl_scheduler sched_id;
    int ret = -1;

    virCheckFlags(VIR_TYPED_PARAM_STRING_OKAY, -1);

    /* We don't return strings, and thus trivially support this flag.  */
    flags &= ~VIR_TYPED_PARAM_STRING_OKAY;

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetSchedulerParametersFlagsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (virDomainObjCheckActive(vm) < 0)
        goto cleanup;

    /* Only credit and credit2 are supported for now. */
    sched_id = libxl_get_scheduler(cfg->ctx);
    if (sched_id != LIBXL_SCHEDULER_CREDIT && sched_id != LIBXL_SCHEDULER_CREDIT2) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Only 'credit' and 'credit2' schedulers are supported"));
        goto cleanup;
    }

    if (libxl_domain_sched_params_get(cfg->ctx, vm->def->id, &sc_info) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to get scheduler parameters for domain '%1$d' with libxenlight"),
                       vm->def->id);
        goto cleanup;
    }

    if (virTypedParameterAssign(&params[0], VIR_DOMAIN_SCHEDULER_WEIGHT,
                                VIR_TYPED_PARAM_UINT, sc_info.weight) < 0)
        goto cleanup;

    if (*nparams > 1) {
        if (virTypedParameterAssign(&params[1], VIR_DOMAIN_SCHEDULER_CAP,
                                    VIR_TYPED_PARAM_UINT, sc_info.cap) < 0)
            goto cleanup;
    }

    if (*nparams > XEN_SCHED_CREDIT_NPARAM)
        *nparams = XEN_SCHED_CREDIT_NPARAM;
    ret = 0;

 cleanup:
    virDomainObjEndAPI(&vm);
    virObjectUnref(cfg);
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
    libxlDriverPrivate *driver = dom->conn->privateData;
    libxlDriverConfig *cfg = libxlDriverConfigGet(driver);
    virDomainObj *vm;
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

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainSetSchedulerParametersFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (virDomainObjBeginJob(vm, VIR_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjCheckActive(vm) < 0)
        goto endjob;

    /* Only credit and credit2 are supported for now. */
    sched_id = libxl_get_scheduler(cfg->ctx);
    if (sched_id != LIBXL_SCHEDULER_CREDIT && sched_id != LIBXL_SCHEDULER_CREDIT2) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Only 'credit' and 'credit2' schedulers are supported"));
        goto endjob;
    }

    if (libxl_domain_sched_params_get(cfg->ctx, vm->def->id, &sc_info) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to get scheduler parameters for domain '%1$d' with libxenlight"),
                       vm->def->id);
        goto endjob;
    }

    for (i = 0; i < nparams; ++i) {
        virTypedParameterPtr param = &params[i];

        if (STREQ(param->field, VIR_DOMAIN_SCHEDULER_WEIGHT))
            sc_info.weight = params[i].value.ui;
        else if (STREQ(param->field, VIR_DOMAIN_SCHEDULER_CAP))
            sc_info.cap = params[i].value.ui;
    }

    if (libxl_domain_sched_params_set(cfg->ctx, vm->def->id, &sc_info) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to set scheduler parameters for domain '%1$d' with libxenlight"),
                       vm->def->id);
        goto endjob;
    }

    ret = 0;

 endjob:
    virDomainObjEndJob(vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    virObjectUnref(cfg);
    return ret;
}


static int
libxlDomainOpenConsole(virDomainPtr dom,
                       const char *dev_name,
                       virStreamPtr st,
                       unsigned int flags)
{
    virDomainObj *vm = NULL;
    int ret = -1;
    virDomainChrDef *chr = NULL;
    libxlDomainObjPrivate *priv;

    virCheckFlags(VIR_DOMAIN_CONSOLE_FORCE, -1);

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    LIBXL_CHECK_DOM0_GOTO(vm->def->name, cleanup);

    if (virDomainOpenConsoleEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (virDomainObjCheckActive(vm) < 0)
        goto cleanup;

    priv = vm->privateData;
    if (dev_name) {
        size_t i;

        for (i = 0; !chr && i < vm->def->nserials; i++) {
            if (STREQ(dev_name, vm->def->serials[i]->info.alias)) {
                chr = vm->def->serials[i];
                break;
            }
        }
    } else if (vm->def->nconsoles) {
        chr = vm->def->consoles[0];
        if (chr->targetType == VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SERIAL)
            chr = vm->def->serials[0];
    }

    if (!chr) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot find character device %1$s"),
                       NULLSTR(dev_name));
        goto cleanup;
    }

    if (chr->source->type != VIR_DOMAIN_CHR_TYPE_PTY) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("character device %1$s is not using a PTY"),
                       dev_name ? dev_name : NULLSTR(chr->info.alias));
        goto cleanup;
    }

    /* handle mutually exclusive access to console devices */
    ret = virChrdevOpen(priv->devs,
                        chr->source,
                        st,
                        (flags & VIR_DOMAIN_CONSOLE_FORCE) != 0);

    if (ret == 1) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("Active console session exists for this domain"));
        ret = -1;
    }

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
libxlDomainSetSchedulerParameters(virDomainPtr dom, virTypedParameterPtr params,
                                  int nparams)
{
    return libxlDomainSetSchedulerParametersFlags(dom, params, nparams, 0);
}

/* Number of Xen NUMA parameters */
#define LIBXL_NUMA_NPARAM 2

static int
libxlDomainGetNumaParameters(virDomainPtr dom,
                             virTypedParameterPtr params,
                             int *nparams,
                             unsigned int flags)
{
    libxlDriverPrivate *driver = dom->conn->privateData;
    libxlDriverConfig *cfg = libxlDriverConfigGet(driver);
    virDomainObj *vm;
    libxl_bitmap nodemap;
    g_autoptr(virBitmap) nodes = NULL;
    int rc, ret = -1;
    size_t i, j;

    /* In Xen 4.3, it is possible to query the NUMA node affinity of a domain
     * via libxl, but not to change it. We therefore only allow AFFECT_LIVE. */
    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_TYPED_PARAM_STRING_OKAY, -1);

    /* We blindly return a string, and let libvirt.c and remote_driver.c do
     * the filtering on behalf of older clients that can't parse it. */
    flags &= ~VIR_TYPED_PARAM_STRING_OKAY;

    libxl_bitmap_init(&nodemap);

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetNumaParametersEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (virDomainObjCheckActive(vm) < 0)
        goto cleanup;

    if ((*nparams) == 0) {
        *nparams = LIBXL_NUMA_NPARAM;
        ret = 0;
        goto cleanup;
    }

    for (i = 0; i < LIBXL_NUMA_NPARAM && i < *nparams; i++) {
        virMemoryParameterPtr param = &params[i];
        int numnodes;
        g_autofree char *nodeset = NULL;

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
            numnodes = libxl_get_max_nodes(cfg->ctx);
            if (numnodes <= 0)
                goto cleanup;

            if (libxl_node_bitmap_alloc(cfg->ctx, &nodemap, 0))
                abort();

            nodes = virBitmapNew(numnodes);

            rc = libxl_domain_get_nodeaffinity(cfg->ctx,
                                               vm->def->id,
                                               &nodemap);
            if (rc != 0) {
                virReportSystemError(-rc, "%s",
                                     _("unable to get numa affinity"));
                goto cleanup;
            }

            /* First, we convert libxl_bitmap into virBitmap. After that,
             * we format virBitmap as a string that can be returned. */
            libxl_for_each_set_bit(j, nodemap) {
                if (virBitmapSetBit(nodes, j)) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("Node %1$zu out of range"), j);
                    goto cleanup;
                }
            }

            if (!(nodeset = virBitmapFormat(nodes)))
                goto cleanup;

            if (virTypedParameterAssign(param, VIR_DOMAIN_NUMA_NODESET,
                                        VIR_TYPED_PARAM_STRING, nodeset) < 0)
                goto cleanup;

            nodeset = NULL;

            break;
        }
    }

    if (*nparams > LIBXL_NUMA_NPARAM)
        *nparams = LIBXL_NUMA_NPARAM;
    ret = 0;

 cleanup:
    libxl_bitmap_dispose(&nodemap);
    virDomainObjEndAPI(&vm);
    virObjectUnref(cfg);
    return ret;
}

static int
libxlDomainIsActive(virDomainPtr dom)
{
    virDomainObj *obj;
    int ret = -1;

    if (!(obj = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainIsActiveEnsureACL(dom->conn, obj->def) < 0)
        goto cleanup;

    ret = virDomainObjIsActive(obj);

 cleanup:
    virDomainObjEndAPI(&obj);
    return ret;
}

static int
libxlDomainIsPersistent(virDomainPtr dom)
{
    virDomainObj *obj;
    int ret = -1;

    if (!(obj = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainIsPersistentEnsureACL(dom->conn, obj->def) < 0)
        goto cleanup;

    ret = obj->persistent;

 cleanup:
    virDomainObjEndAPI(&obj);
    return ret;
}

static int
libxlDomainIsUpdated(virDomainPtr dom)
{
    virDomainObj *vm;
    int ret = -1;

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainIsUpdatedEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    ret = vm->updated;

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
libxlDomainInterfaceStats(virDomainPtr dom,
                          const char *device,
                          virDomainInterfaceStatsPtr stats)
{
    virDomainObj *vm;
    virDomainNetDef *net = NULL;
    int ret = -1;

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainInterfaceStatsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (virDomainObjBeginJob(vm, VIR_JOB_QUERY) < 0)
        goto cleanup;

    if (virDomainObjCheckActive(vm) < 0)
        goto endjob;

    if (!(net = virDomainNetFind(vm->def, device)))
        goto endjob;

    if (virNetDevTapInterfaceStats(net->ifname, stats,
                                   !virDomainNetTypeSharesHostView(net)) < 0)
        goto endjob;

    ret = 0;

 endjob:
    virDomainObjEndJob(vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
libxlDomainGetTotalCPUStats(libxlDriverPrivate *driver,
                            virDomainObj *vm,
                            virTypedParameterPtr params,
                            unsigned int nparams)
{
    libxlDriverConfig *cfg;
    libxl_dominfo d_info;
    int ret = -1;

    if (nparams == 0)
        return LIBXL_NB_TOTAL_CPU_STAT_PARAM;

    libxl_dominfo_init(&d_info);
    cfg = libxlDriverConfigGet(driver);

    if (libxl_domain_info(cfg->ctx, &d_info, vm->def->id) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("libxl_domain_info failed for domain '%1$d'"),
                       vm->def->id);
        goto cleanup;
    }

    if (virTypedParameterAssign(&params[0], VIR_DOMAIN_CPU_STATS_CPUTIME,
                                VIR_TYPED_PARAM_ULLONG, d_info.cpu_time) < 0)
        goto cleanup;

    ret = nparams;

 cleanup:
    libxl_dominfo_dispose(&d_info);
    virObjectUnref(cfg);
    return ret;
}

static int
libxlDomainGetPerCPUStats(libxlDriverPrivate *driver,
                          virDomainObj *vm,
                          virTypedParameterPtr params,
                          unsigned int nparams,
                          int start_cpu,
                          unsigned int ncpus)
{
    libxl_vcpuinfo *vcpuinfo;
    int maxcpu, hostcpus;
    size_t i;
    libxlDriverConfig *cfg;
    int ret = -1;

    if (nparams == 0 && ncpus != 0)
        return LIBXL_NB_TOTAL_CPU_STAT_PARAM;
    else if (nparams == 0)
        return virDomainDefGetVcpusMax(vm->def);

    cfg = libxlDriverConfigGet(driver);
    if ((vcpuinfo = libxl_list_vcpu(cfg->ctx, vm->def->id, &maxcpu,
                                    &hostcpus)) == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to list vcpus for domain '%1$d' with libxenlight"),
                       vm->def->id);
        goto cleanup;
    }

    for (i = start_cpu; i < maxcpu && i < ncpus; ++i) {
        if (virTypedParameterAssign(&params[(i-start_cpu)],
                                    VIR_DOMAIN_CPU_STATS_CPUTIME,
                                    VIR_TYPED_PARAM_ULLONG,
                                    vcpuinfo[i].vcpu_time) < 0)
            goto cleanup;
    }
    ret = nparams;

 cleanup:
    if (vcpuinfo)
        libxl_vcpuinfo_list_free(vcpuinfo, maxcpu);
    virObjectUnref(cfg);
    return ret;
}

static int
libxlDomainGetCPUStats(virDomainPtr dom,
                       virTypedParameterPtr params,
                       unsigned int nparams,
                       int start_cpu,
                       unsigned int ncpus,
                       unsigned int flags)
{
    libxlDriverPrivate *driver = dom->conn->privateData;
    virDomainObj *vm = NULL;
    int ret = -1;

    virCheckFlags(VIR_TYPED_PARAM_STRING_OKAY, -1);

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetCPUStatsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (virDomainObjCheckActive(vm) < 0)
        goto cleanup;

    if (start_cpu == -1)
        ret = libxlDomainGetTotalCPUStats(driver, vm, params, nparams);
    else
        ret = libxlDomainGetPerCPUStats(driver, vm, params, nparams,
                                          start_cpu, ncpus);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

#define LIBXL_SET_MEMSTAT(TAG, VAL) \
        if (i < nr_stats) { \
            stats[i].tag = TAG; \
            stats[i].val = VAL; \
            i++; \
        }

static int
libxlDomainMemoryStats(virDomainPtr dom,
                       virDomainMemoryStatPtr stats,
                       unsigned int nr_stats,
                       unsigned int flags)
{
    libxlDriverPrivate *driver = dom->conn->privateData;
    libxlDriverConfig *cfg;
    virDomainObj *vm;
    libxl_dominfo d_info;
    unsigned mem, maxmem;
    size_t i = 0;
    int ret = -1;

    virCheckFlags(0, -1);

    libxl_dominfo_init(&d_info);
    cfg = libxlDriverConfigGet(driver);

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainMemoryStatsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (virDomainObjBeginJob(vm, VIR_JOB_QUERY) < 0)
        goto cleanup;

    if (virDomainObjCheckActive(vm) < 0)
        goto endjob;

    if (libxl_domain_info(cfg->ctx, &d_info, vm->def->id) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("libxl_domain_info failed for domain '%1$d'"),
                       vm->def->id);
        goto endjob;
    }
    mem = d_info.current_memkb;
    maxmem = virDomainDefGetMemoryTotal(vm->def);

    LIBXL_SET_MEMSTAT(VIR_DOMAIN_MEMORY_STAT_ACTUAL_BALLOON, mem);
    LIBXL_SET_MEMSTAT(VIR_DOMAIN_MEMORY_STAT_AVAILABLE, maxmem);

    ret = i;

 endjob:
    virDomainObjEndJob(vm);

 cleanup:
    libxl_dominfo_dispose(&d_info);
    virDomainObjEndAPI(&vm);
    virObjectUnref(cfg);
    return ret;
}

#undef LIBXL_SET_MEMSTAT

static int
libxlDomainGetJobInfo(virDomainPtr dom,
                      virDomainJobInfoPtr info)
{
    virDomainObj *vm;
    int ret = -1;
    unsigned long long timeElapsed = 0;

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetJobInfoEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!vm->job->active) {
        memset(info, 0, sizeof(*info));
        info->type = VIR_DOMAIN_JOB_NONE;
        ret = 0;
        goto cleanup;
    }

    /* In libxl we don't have an estimated completion time
     * thus we always set to unbounded and update time
     * for the active job. */
    if (libxlDomainJobGetTimeElapsed(vm->job, &timeElapsed) < 0)
        goto cleanup;

    /* setting only these two attributes is enough because libxl never sets
     * anything else */
    memset(info, 0, sizeof(*info));
    info->type = VIR_DOMAIN_JOB_UNBOUNDED;
    info->timeElapsed = timeElapsed;
    ret = 0;

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
libxlDomainGetJobStats(virDomainPtr dom,
                       int *type,
                       virTypedParameterPtr *params,
                       int *nparams,
                       unsigned int flags)
{
    virDomainObj *vm;
    int ret = -1;
    int maxparams = 0;
    unsigned long long timeElapsed = 0;

    /* VIR_DOMAIN_JOB_STATS_COMPLETED not supported yet */
    virCheckFlags(0, -1);

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetJobStatsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!vm->job->active) {
        *type = VIR_DOMAIN_JOB_NONE;
        *params = NULL;
        *nparams = 0;
        ret = 0;
        goto cleanup;
    }

    /* In libxl we don't have an estimated completion time
     * thus we always set to unbounded and update time
     * for the active job. */
    if (libxlDomainJobGetTimeElapsed(vm->job, &timeElapsed) < 0)
        goto cleanup;

    if (virTypedParamsAddULLong(params, nparams, &maxparams,
                                VIR_DOMAIN_JOB_TIME_ELAPSED,
                                timeElapsed) < 0)
        goto cleanup;

    *type = VIR_DOMAIN_JOB_UNBOUNDED;
    ret = 0;

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

#ifdef __linux__
static int
libxlDiskPathToID(const char *virtpath)
{
    static char const* drive_prefix[] = {"xvd", "hd", "sd"};
    int disk, partition, chrused;
    int fmt, id;
    size_t i;

    fmt = id = -1;

    /* Find any disk prefixes we know about */
    for (i = 0; i < G_N_ELEMENTS(drive_prefix); i++) {
        if (STRPREFIX(virtpath, drive_prefix[i]) &&
            !virDiskNameParse(virtpath, &disk, &partition)) {
            fmt = i;
            break;
        }
    }

    /* Handle it same way as xvd */
    if (fmt < 0 &&
        (sscanf(virtpath, "d%ip%i%n", &disk, &partition, &chrused) >= 2
         && chrused == strlen(virtpath)))
        fmt = 0;

    /* Test indexes ranges and calculate the device id */
    switch (fmt) {
    case 0: /* xvd */
        if (disk <= 15 && partition <= 15)
            id = (202 << 8) | (disk << 4) | partition;
        else if ((disk <= ((1<<20)-1)) || partition <= 255)
            id = (1 << 28) | (disk << 8) | partition;
        break;
    case 1: /* hd */
        if (disk <= 3 && partition <= 63)
            id = ((disk < 2 ? 3 : 22) << 8) | ((disk & 1) << 6) | partition;
        break;
    case 2: /* sd */
        if (disk <= 15 && (partition <= 15))
            id = (8 << 8) | (disk << 4) | partition;
        break;
    default: /* invalid */
        break;
    }
    return id;
}

# define LIBXL_VBD_SECTOR_SIZE 512

static int
libxlDiskSectorSize(int domid, int devno)
{
    char *path, *val;
    struct xs_handle *handle;
    int ret = LIBXL_VBD_SECTOR_SIZE;
    unsigned int len;

    handle = xs_daemon_open_readonly();
    if (!handle) {
        VIR_WARN("cannot read sector size");
        return ret;
    }

    path = val = NULL;
    path = g_strdup_printf("/local/domain/%d/device/vbd/%d/backend", domid, devno);

    if ((val = xs_read(handle, XBT_NULL, path, &len)) == NULL)
        goto cleanup;

    VIR_FREE(path);
    path = g_strdup_printf("%s/physical-sector-size", val);

    VIR_FREE(val);
    if ((val = xs_read(handle, XBT_NULL, path, &len)) == NULL)
        goto cleanup;

    if (sscanf(val, "%d", &ret) != 1)
        ret = LIBXL_VBD_SECTOR_SIZE;

 cleanup:
    VIR_FREE(val);
    VIR_FREE(path);
    xs_daemon_close(handle);
    return ret;
}

static int
libxlDomainBlockStatsVBD(virDomainObj *vm,
                         const char *dev,
                         libxlBlockStats *stats)
{
    int ret = -1;
    int devno = libxlDiskPathToID(dev);
    int size;
    char *path, *name, *val;
    unsigned long long status;

    path = name = val = NULL;
    if (devno < 0) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("cannot find device number"));
        return ret;
    }

    size = libxlDiskSectorSize(vm->def->id, devno);

    stats->backend = g_strdup("vbd");

    path = g_strdup_printf("/sys/bus/xen-backend/devices/vbd-%d-%d/statistics",
                           vm->def->id, devno);

    if (!virFileExists(path)) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       "%s", _("cannot open bus path"));
        goto cleanup;
    }

# define LIBXL_SET_VBDSTAT(FIELD, VAR, MUL) \
    name = g_strdup_printf("%s/"FIELD, path); \
    if ((virFileReadAll(name, 256, &val) < 0) || \
        (sscanf(val, "%llu", &status) != 1)) { \
        virReportError(VIR_ERR_OPERATION_FAILED, \
                       _("cannot read %1$s"), name); \
        goto cleanup; \
    } \
    VAR += (status * MUL); \
    VIR_FREE(name); \
    VIR_FREE(val);

    LIBXL_SET_VBDSTAT("f_req",  stats->f_req,  1)
    LIBXL_SET_VBDSTAT("wr_req", stats->wr_req, 1)
    LIBXL_SET_VBDSTAT("rd_req", stats->rd_req, 1)
    LIBXL_SET_VBDSTAT("wr_sect", stats->wr_bytes, size)
    LIBXL_SET_VBDSTAT("rd_sect", stats->rd_bytes, size)

    LIBXL_SET_VBDSTAT("ds_req", stats->u.vbd.ds_req, size)
    LIBXL_SET_VBDSTAT("oo_req", stats->u.vbd.oo_req, 1)
    ret = 0;

 cleanup:
    VIR_FREE(name);
    VIR_FREE(path);
    VIR_FREE(val);

# undef LIBXL_SET_VBDSTAT

    return ret;
}
#else
static int
libxlDomainBlockStatsVBD(virDomainObj *vm G_GNUC_UNUSED,
                         const char *dev G_GNUC_UNUSED,
                         libxlBlockStats *stats G_GNUC_UNUSED)
{
    virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                   "%s", _("platform unsupported"));
    return -1;
}
#endif

static int
libxlDomainBlockStatsGatherSingle(virDomainObj *vm,
                                  const char *path,
                                  libxlBlockStats *stats)
{
    virDomainDiskDef *disk;
    const char *disk_drv;
    int ret = -1, disk_fmt;

    if (!(disk = virDomainDiskByName(vm->def, path, false))) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("invalid path: %1$s"), path);
        return ret;
    }

    disk_fmt = virDomainDiskGetFormat(disk);
    if (!(disk_drv = virDomainDiskGetDriver(disk)))
        disk_drv = "qemu";

    if (STREQ(disk_drv, "phy")) {
        if (disk_fmt != VIR_STORAGE_FILE_RAW) {
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                           _("unsupported format %1$s"),
                           virStorageFileFormatTypeToString(disk_fmt));
            return ret;
        }

        ret = libxlDomainBlockStatsVBD(vm, disk->dst, stats);
    } else {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("unsupported disk driver %1$s"),
                       disk_drv);
    }
    return ret;
}

static int
libxlDomainBlockStatsGather(virDomainObj *vm,
                            const char *path,
                            libxlBlockStats *stats)
{
    int ret = -1;

    if (*path) {
        if (libxlDomainBlockStatsGatherSingle(vm, path, stats) < 0)
            return ret;
    } else {
        size_t i;

        for (i = 0; i < vm->def->ndisks; ++i) {
            if (libxlDomainBlockStatsGatherSingle(vm, vm->def->disks[i]->dst,
                                                  stats) < 0)
                return ret;
        }
    }
    return 0;
}

static int
libxlDomainBlockStats(virDomainPtr dom,
                      const char *path,
                      virDomainBlockStatsPtr stats)
{
    virDomainObj *vm;
    libxlBlockStats blkstats = { 0 };
    int ret = -1;

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainBlockStatsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (virDomainObjBeginJob(vm, VIR_JOB_QUERY) < 0)
        goto cleanup;

    if (virDomainObjCheckActive(vm) < 0)
        goto endjob;

    if ((ret = libxlDomainBlockStatsGather(vm, path, &blkstats)) < 0)
        goto endjob;

    stats->rd_req = blkstats.rd_req;
    stats->rd_bytes = blkstats.rd_bytes;
    stats->wr_req = blkstats.wr_req;
    stats->wr_bytes = blkstats.wr_bytes;
    if (STREQ_NULLABLE(blkstats.backend, "vbd"))
        stats->errs = blkstats.u.vbd.oo_req;
    else
        stats->errs = -1;

 endjob:
    virDomainObjEndJob(vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
libxlDomainBlockStatsFlags(virDomainPtr dom,
                           const char *path,
                           virTypedParameterPtr params,
                           int *nparams,
                           unsigned int flags)
{
    virDomainObj *vm;
    libxlBlockStats blkstats = { 0 };
    int nstats;
    int ret = -1;

    virCheckFlags(VIR_TYPED_PARAM_STRING_OKAY, -1);

    flags &= ~VIR_TYPED_PARAM_STRING_OKAY;

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainBlockStatsFlagsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (virDomainObjBeginJob(vm, VIR_JOB_QUERY) < 0)
        goto cleanup;

    if (virDomainObjCheckActive(vm) < 0)
        goto endjob;

    /* return count of supported stats */
    if (*nparams == 0) {
        *nparams = LIBXL_NB_TOTAL_BLK_STAT_PARAM;
        ret = 0;
        goto endjob;
    }

    if ((ret = libxlDomainBlockStatsGather(vm, path, &blkstats)) < 0)
        goto endjob;

    nstats = 0;

#define LIBXL_BLKSTAT_ASSIGN_PARAM(VAR, NAME) \
    if (nstats < *nparams && (blkstats.VAR) != -1) { \
        if (virTypedParameterAssign(params + nstats, NAME, \
                                    VIR_TYPED_PARAM_LLONG, (blkstats.VAR)) < 0) \
            goto endjob; \
        nstats++; \
    }

    LIBXL_BLKSTAT_ASSIGN_PARAM(wr_bytes, VIR_DOMAIN_BLOCK_STATS_WRITE_BYTES);
    LIBXL_BLKSTAT_ASSIGN_PARAM(wr_req, VIR_DOMAIN_BLOCK_STATS_WRITE_REQ);

    LIBXL_BLKSTAT_ASSIGN_PARAM(rd_bytes, VIR_DOMAIN_BLOCK_STATS_READ_BYTES);
    LIBXL_BLKSTAT_ASSIGN_PARAM(rd_req, VIR_DOMAIN_BLOCK_STATS_READ_REQ);

    LIBXL_BLKSTAT_ASSIGN_PARAM(f_req, VIR_DOMAIN_BLOCK_STATS_FLUSH_REQ);

    if (STREQ_NULLABLE(blkstats.backend, "vbd"))
        LIBXL_BLKSTAT_ASSIGN_PARAM(u.vbd.oo_req, VIR_DOMAIN_BLOCK_STATS_ERRS);

    *nparams = nstats;

#undef LIBXL_BLKSTAT_ASSIGN_PARAM

 endjob:
    virDomainObjEndJob(vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
libxlConnectDomainEventRegisterAny(virConnectPtr conn, virDomainPtr dom, int eventID,
                                   virConnectDomainEventGenericCallback callback,
                                   void *opaque, virFreeCallback freecb)
{
    libxlDriverPrivate *driver = conn->privateData;
    int ret;

    if (virConnectDomainEventRegisterAnyEnsureACL(conn) < 0)
        return -1;

    if (virDomainEventStateRegisterID(conn,
                                      driver->domainEventState,
                                      dom, eventID, callback, opaque,
                                      freecb, &ret) < 0)
        ret = -1;

    return ret;
}


static int
libxlConnectDomainEventDeregisterAny(virConnectPtr conn, int callbackID)
{
    libxlDriverPrivate *driver = conn->privateData;

    if (virConnectDomainEventDeregisterAnyEnsureACL(conn) < 0)
        return -1;

    if (virObjectEventStateDeregisterID(conn,
                                        driver->domainEventState,
                                        callbackID, true) < 0)
        return -1;

    return 0;
}


static int
libxlConnectIsAlive(virConnectPtr conn G_GNUC_UNUSED)
{
    return 1;
}

static int
libxlConnectListAllDomains(virConnectPtr conn,
                           virDomainPtr **domains,
                           unsigned int flags)
{
    libxlDriverPrivate *driver = conn->privateData;

    virCheckFlags(VIR_CONNECT_LIST_DOMAINS_FILTERS_ALL, -1);

    if (virConnectListAllDomainsEnsureACL(conn) < 0)
        return -1;

    return virDomainObjListExport(driver->domains, conn, domains,
                                  virConnectListAllDomainsCheckACL, flags);
}

/* Which features are supported by this driver? */
static int
libxlConnectSupportsFeature(virConnectPtr conn, int feature)
{
    int supported;

    if (virConnectSupportsFeatureEnsureACL(conn) < 0)
        return -1;

    if (virDriverFeatureIsGlobal(feature, &supported))
        return supported;

    switch ((virDrvFeature) feature) {
    case VIR_DRV_FEATURE_REMOTE:
    case VIR_DRV_FEATURE_PROGRAM_KEEPALIVE:
    case VIR_DRV_FEATURE_REMOTE_CLOSE_CALLBACK:
    case VIR_DRV_FEATURE_REMOTE_EVENT_CALLBACK:
    case VIR_DRV_FEATURE_TYPED_PARAM_STRING:
    case VIR_DRV_FEATURE_NETWORK_UPDATE_HAS_CORRECT_ORDER:
    case VIR_DRV_FEATURE_FD_PASSING:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Global feature %1$d should have already been handled"),
                       feature);
        return -1;
    case VIR_DRV_FEATURE_MIGRATION_V3:
    case VIR_DRV_FEATURE_MIGRATION_PARAMS:
    case VIR_DRV_FEATURE_MIGRATION_P2P:
    case VIR_DRV_FEATURE_MIGRATE_CHANGE_PROTECTION:
        return 1;
    case VIR_DRV_FEATURE_MIGRATION_DIRECT:
    case VIR_DRV_FEATURE_MIGRATION_OFFLINE:
    case VIR_DRV_FEATURE_MIGRATION_V1:
    case VIR_DRV_FEATURE_MIGRATION_V2:
    case VIR_DRV_FEATURE_XML_MIGRATABLE:
    default:
        return 0;
    }
}

static int
libxlNodeDeviceDetachFlags(virNodeDevicePtr dev,
                           const char *driverName,
                           unsigned int flags)
{
    libxlDriverPrivate *driver = dev->conn->privateData;
    virHostdevManager *hostdev_mgr = driver->hostdevMgr;

    virCheckFlags(0, -1);

    if (!driverName)
        driverName = "xen";

    if (STRNEQ(driverName, "xen")) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unsupported driver name '%1$s'"), driverName);
        return -1;
    }

    /* virNodeDeviceDetachFlagsEnsureACL() is being called by
     * virDomainDriverNodeDeviceDetachFlags() */
    return virDomainDriverNodeDeviceDetachFlags(dev, hostdev_mgr,
                                                VIR_PCI_STUB_DRIVER_XEN, NULL);
}

static int
libxlNodeDeviceDettach(virNodeDevicePtr dev)
{
    return libxlNodeDeviceDetachFlags(dev, NULL, 0);
}

static int
libxlNodeDeviceReAttach(virNodeDevicePtr dev)
{
    libxlDriverPrivate *driver = dev->conn->privateData;
    virHostdevManager *hostdev_mgr = driver->hostdevMgr;

    /* virNodeDeviceReAttachEnsureACL() is being called by
     * virDomainDriverNodeDeviceReAttach() */
    return virDomainDriverNodeDeviceReAttach(dev, hostdev_mgr);
}

static int
libxlNodeDeviceReset(virNodeDevicePtr dev)
{
    libxlDriverPrivate *driver = dev->conn->privateData;
    virHostdevManager *hostdev_mgr = driver->hostdevMgr;

    /* virNodeDeviceResetEnsureACL() is being called by
     * virDomainDriverNodeDeviceReset() */
    return virDomainDriverNodeDeviceReset(dev, hostdev_mgr);
}

static char *
libxlDomainMigrateBegin3Params(virDomainPtr domain,
                               virTypedParameterPtr params,
                               int nparams,
                               char **cookieout,
                               int *cookieoutlen,
                               unsigned int flags)
{
    const char *xmlin = NULL;
    virDomainObj *vm = NULL;
    char *xmlout = NULL;

#ifdef LIBXL_HAVE_NO_SUSPEND_RESUME
    virReportUnsupportedError();
    return NULL;
#endif

    virCheckFlags(LIBXL_MIGRATION_FLAGS, NULL);
    if (virTypedParamsValidate(params, nparams, LIBXL_MIGRATION_PARAMETERS) < 0)
        return NULL;

    if (virTypedParamsGetString(params, nparams,
                                VIR_MIGRATE_PARAM_DEST_XML,
                                &xmlin) < 0)
        return NULL;

    if (!(vm = libxlDomObjFromDomain(domain)))
        return NULL;

    if (STREQ_NULLABLE(vm->def->name, "Domain-0")) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Domain-0 cannot be migrated"));
        goto cleanup;
    }

    if (virDomainMigrateBegin3ParamsEnsureACL(domain->conn, vm->def) < 0)
        goto cleanup;

    if (virDomainObjCheckActive(vm) < 0)
        goto cleanup;

    xmlout = libxlDomainMigrationSrcBegin(domain->conn, vm, xmlin,
                                          cookieout, cookieoutlen);

 cleanup:
    virDomainObjEndAPI(&vm);
    return xmlout;
}

static int
libxlDomainMigratePrepareTunnel3Params(virConnectPtr dconn,
                                       virStreamPtr st,
                                       virTypedParameterPtr params,
                                       int nparams,
                                       const char *cookiein,
                                       int cookieinlen,
                                       char **cookieout G_GNUC_UNUSED,
                                       int *cookieoutlen G_GNUC_UNUSED,
                                       unsigned int flags)
{
    libxlDriverPrivate *driver = dconn->privateData;
    g_autoptr(virDomainDef) def = NULL;
    const char *dom_xml = NULL;
    const char *dname = NULL;
    const char *uri_in = NULL;

#ifdef LIBXL_HAVE_NO_SUSPEND_RESUME
    virReportUnsupportedError();
    return -1;
#endif

    virCheckFlags(LIBXL_MIGRATION_FLAGS, -1);
    if (virTypedParamsValidate(params, nparams, LIBXL_MIGRATION_PARAMETERS) < 0)
        return -1;

    if (virTypedParamsGetString(params, nparams,
                                VIR_MIGRATE_PARAM_DEST_XML,
                                &dom_xml) < 0 ||
        virTypedParamsGetString(params, nparams,
                                VIR_MIGRATE_PARAM_DEST_NAME,
                                &dname) < 0 ||
        virTypedParamsGetString(params, nparams,
                                VIR_MIGRATE_PARAM_URI,
                                &uri_in) < 0)

        return -1;

    if (!(def = libxlDomainMigrationDstPrepareDef(driver, dom_xml, dname)))
        return -1;

    if (virDomainMigratePrepareTunnel3ParamsEnsureACL(dconn, def) < 0)
        return -1;

    if (libxlDomainMigrationDstPrepareTunnel3(dconn, st, &def, cookiein,
                                              cookieinlen, flags) < 0)
        return -1;

    return 0;
}

static int
libxlDomainMigratePrepare3Params(virConnectPtr dconn,
                                 virTypedParameterPtr params,
                                 int nparams,
                                 const char *cookiein,
                                 int cookieinlen,
                                 char **cookieout G_GNUC_UNUSED,
                                 int *cookieoutlen G_GNUC_UNUSED,
                                 char **uri_out,
                                 unsigned int flags)
{
    libxlDriverPrivate *driver = dconn->privateData;
    g_autoptr(virDomainDef) def = NULL;
    const char *dom_xml = NULL;
    const char *dname = NULL;
    const char *uri_in = NULL;

#ifdef LIBXL_HAVE_NO_SUSPEND_RESUME
    virReportUnsupportedError();
    return -1;
#endif

    virCheckFlags(LIBXL_MIGRATION_FLAGS, -1);
    if (virTypedParamsValidate(params, nparams, LIBXL_MIGRATION_PARAMETERS) < 0)
        return -1;

    if (virTypedParamsGetString(params, nparams,
                                VIR_MIGRATE_PARAM_DEST_XML,
                                &dom_xml) < 0 ||
        virTypedParamsGetString(params, nparams,
                                VIR_MIGRATE_PARAM_DEST_NAME,
                                &dname) < 0 ||
        virTypedParamsGetString(params, nparams,
                                VIR_MIGRATE_PARAM_URI,
                                &uri_in) < 0)

        return -1;

    if (!(def = libxlDomainMigrationDstPrepareDef(driver, dom_xml, dname)))
        return -1;

    if (virDomainMigratePrepare3ParamsEnsureACL(dconn, def) < 0)
        return -1;

    if (libxlDomainMigrationDstPrepare(dconn, &def, uri_in, uri_out,
                                       cookiein, cookieinlen, flags) < 0)
        return -1;

    return 0;
}

static int
libxlDomainMigratePerform3Params(virDomainPtr dom,
                                 const char *dconnuri,
                                 virTypedParameterPtr params,
                                 int nparams,
                                 const char *cookiein G_GNUC_UNUSED,
                                 int cookieinlen G_GNUC_UNUSED,
                                 char **cookieout G_GNUC_UNUSED,
                                 int *cookieoutlen G_GNUC_UNUSED,
                                 unsigned int flags)
{
    libxlDriverPrivate *driver = dom->conn->privateData;
    virDomainObj *vm = NULL;
    const char *dom_xml = NULL;
    const char *dname = NULL;
    const char *uri = NULL;
    int ret = -1;

#ifdef LIBXL_HAVE_NO_SUSPEND_RESUME
    virReportUnsupportedError();
    return -1;
#endif

    virCheckFlags(LIBXL_MIGRATION_FLAGS, -1);
    if (virTypedParamsValidate(params, nparams, LIBXL_MIGRATION_PARAMETERS) < 0)
        goto cleanup;

    if (virTypedParamsGetString(params, nparams,
                                VIR_MIGRATE_PARAM_DEST_XML,
                                &dom_xml) < 0 ||
        virTypedParamsGetString(params, nparams,
                                VIR_MIGRATE_PARAM_DEST_NAME,
                                &dname) < 0 ||
        virTypedParamsGetString(params, nparams,
                                VIR_MIGRATE_PARAM_URI,
                                &uri) < 0)

        goto cleanup;

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainMigratePerform3ParamsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if ((flags & (VIR_MIGRATE_TUNNELLED | VIR_MIGRATE_PEER2PEER))) {
        if (libxlDomainMigrationSrcPerformP2P(driver, vm, dom->conn, dom_xml,
                                              dconnuri, uri, dname, flags) < 0)
            goto cleanup;
    } else {
        if (libxlDomainMigrationSrcPerform(driver, vm, dom_xml, dconnuri,
                                           uri, dname, flags) < 0)
            goto cleanup;
    }

    ret = 0;

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static virDomainPtr
libxlDomainMigrateFinish3Params(virConnectPtr dconn,
                                virTypedParameterPtr params,
                                int nparams,
                                const char *cookiein G_GNUC_UNUSED,
                                int cookieinlen G_GNUC_UNUSED,
                                char **cookieout G_GNUC_UNUSED,
                                int *cookieoutlen G_GNUC_UNUSED,
                                unsigned int flags,
                                int cancelled)
{
    libxlDriverPrivate *driver = dconn->privateData;
    virDomainObj *vm = NULL;
    const char *dname = NULL;
    virDomainPtr ret = NULL;

#ifdef LIBXL_HAVE_NO_SUSPEND_RESUME
    virReportUnsupportedError();
    return NULL;
#endif

    virCheckFlags(LIBXL_MIGRATION_FLAGS, NULL);
    if (virTypedParamsValidate(params, nparams, LIBXL_MIGRATION_PARAMETERS) < 0)
        return NULL;

    if (virTypedParamsGetString(params, nparams,
                                VIR_MIGRATE_PARAM_DEST_NAME,
                                &dname) < 0)
        return NULL;

    if (!dname ||
        !(vm = virDomainObjListFindByName(driver->domains, dname))) {
        /* Migration obviously failed if the domain doesn't exist */
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("Migration failed. No domain on destination host with matching name '%1$s'"),
                       NULLSTR(dname));
        return NULL;
    }

    if (virDomainMigrateFinish3ParamsEnsureACL(dconn, vm->def) < 0) {
        virDomainObjEndAPI(&vm);
        return NULL;
    }

    ret = libxlDomainMigrationDstFinish(dconn, vm, flags, cancelled);

    virDomainObjEndAPI(&vm);

    return ret;
}

static int
libxlDomainMigrateConfirm3Params(virDomainPtr domain,
                                 virTypedParameterPtr params,
                                 int nparams,
                                 const char *cookiein G_GNUC_UNUSED,
                                 int cookieinlen G_GNUC_UNUSED,
                                 unsigned int flags,
                                 int cancelled)
{
    libxlDriverPrivate *driver = domain->conn->privateData;
    virDomainObj *vm = NULL;
    int ret = -1;

#ifdef LIBXL_HAVE_NO_SUSPEND_RESUME
    virReportUnsupportedError();
    return -1;
#endif

    virCheckFlags(LIBXL_MIGRATION_FLAGS, -1);
    if (virTypedParamsValidate(params, nparams, LIBXL_MIGRATION_PARAMETERS) < 0)
        return -1;

    if (!(vm = libxlDomObjFromDomain(domain)))
        return -1;

    if (virDomainMigrateConfirm3ParamsEnsureACL(domain->conn, vm->def) < 0)
        goto cleanup;

    ret = libxlDomainMigrationSrcConfirm(driver, vm, flags, cancelled);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int libxlNodeGetSecurityModel(virConnectPtr conn,
                                     virSecurityModelPtr secmodel)
{
    memset(secmodel, 0, sizeof(*secmodel));

    if (virNodeGetSecurityModelEnsureACL(conn) < 0)
        return -1;

    /*
     * Currently the libxl driver does not support security model.
     * Similar to the qemu driver, treat this as success and simply
     * return no data in secmodel.  Avoids spamming the libvirt log
     * with "this function is not supported by the connection driver:
     * virNodeGetSecurityModel"
     */
    return 0;
}

static int
libxlGetDHCPInterfaces(virDomainObj *vm,
                       virDomainInterfacePtr **ifaces)
{
    g_autoptr(virConnect) conn = NULL;
    virDomainInterfacePtr *ifaces_ret = NULL;
    size_t ifaces_count = 0;
    size_t i;

    if (!(conn = virGetConnectNetwork()))
        return -1;

    for (i = 0; i < vm->def->nnets; i++) {
        g_autoptr(virNetwork) network = NULL;
        char macaddr[VIR_MAC_STRING_BUFLEN];
        virNetworkDHCPLeasePtr *leases = NULL;
        int n_leases = 0;
        virDomainInterfacePtr iface = NULL;
        size_t j;

        if (vm->def->nets[i]->type != VIR_DOMAIN_NET_TYPE_NETWORK)
            continue;

        virMacAddrFormat(&(vm->def->nets[i]->mac), macaddr);

        network = virNetworkLookupByName(conn,
                                         vm->def->nets[i]->data.network.name);
        if (!network)
            goto error;

        if ((n_leases = virNetworkGetDHCPLeases(network, macaddr,
                                                &leases, 0)) < 0)
            goto error;

        if (n_leases) {
            ifaces_ret = g_renew(virDomainInterfacePtr, ifaces_ret, ifaces_count + 1);
            ifaces_ret[ifaces_count] = g_new0(virDomainInterface, 1);
            iface = ifaces_ret[ifaces_count];
            ifaces_count++;

            /* Assuming each lease corresponds to a separate IP */
            iface->naddrs = n_leases;

            iface->addrs = g_new0(virDomainIPAddress, iface->naddrs);
            iface->name = g_strdup(vm->def->nets[i]->ifname);
            iface->hwaddr = g_strdup(macaddr);
        }

        for (j = 0; j < n_leases; j++) {
            virNetworkDHCPLeasePtr lease = leases[j];
            virDomainIPAddressPtr ip_addr = &iface->addrs[j];

            ip_addr->addr = g_strdup(lease->ipaddr);
            ip_addr->type = lease->type;
            ip_addr->prefix = lease->prefix;

            virNetworkDHCPLeaseFree(leases[j]);
        }

        VIR_FREE(leases);
    }

    *ifaces = g_steal_pointer(&ifaces_ret);
    return ifaces_count;

 error:
    if (ifaces_ret) {
        for (i = 0; i < ifaces_count; i++)
            virDomainInterfaceFree(ifaces_ret[i]);
    }
    VIR_FREE(ifaces_ret);

    return -1;
}


static int
libxlDomainInterfaceAddresses(virDomainPtr dom,
                              virDomainInterfacePtr **ifaces,
                              unsigned int source,
                              unsigned int flags)
{
    virDomainObj *vm = NULL;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainInterfaceAddressesEnsureACL(dom->conn, vm->def, source) < 0)
        goto cleanup;

    if (virDomainObjCheckActive(vm) < 0)
        goto cleanup;

    switch (source) {
    case VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_LEASE:
        ret = libxlGetDHCPInterfaces(vm, ifaces);
        break;

    default:
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED,
                       _("Unsupported IP address data source %1$d"),
                       source);
        break;
    }

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}


static char *
libxlConnectGetDomainCapabilities(virConnectPtr conn,
                                  const char *emulatorbin,
                                  const char *arch_str,
                                  const char *machine,
                                  const char *virttype_str,
                                  unsigned int flags)
{
    libxlDriverPrivate *driver = conn->privateData;
    libxlDriverConfig *cfg;
    char *ret = NULL;
    int virttype = VIR_DOMAIN_VIRT_XEN;
    virDomainCaps *domCaps = NULL;
    int arch = virArchFromHost(); /* virArch */

    virCheckFlags(0, ret);

    if (virConnectGetDomainCapabilitiesEnsureACL(conn) < 0)
        return ret;

    cfg = libxlDriverConfigGet(driver);

    if (virttype_str &&
        (virttype = virDomainVirtTypeFromString(virttype_str)) < 0) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unknown virttype: %1$s"),
                       virttype_str);
        goto cleanup;
    }

    if (virttype != VIR_DOMAIN_VIRT_XEN) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unknown virttype: %1$s"),
                       virttype_str);
        goto cleanup;
    }

    if (arch_str && (arch = virArchFromString(arch_str)) == VIR_ARCH_NONE) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unknown architecture: %1$s"),
                       arch_str);
        goto cleanup;
    }

    if (emulatorbin == NULL)
        emulatorbin = "/usr/bin/qemu-system-x86_64";

    if (machine) {
        if (STRNEQ(machine, "xenpv") &&
            STRNEQ(machine, "xenpvh") &&
            STRNEQ(machine, "xenfv")) {
            virReportError(VIR_ERR_INVALID_ARG, "%s",
                           _("Xen only supports 'xenpv', 'xenpvh' and 'xenfv' machines"));
            goto cleanup;
        }
    } else {
        machine = "xenpv";
    }

    if (!(domCaps = virDomainCapsNew(emulatorbin, machine, arch, virttype)))
        goto cleanup;

    if (libxlMakeDomainCapabilities(domCaps, cfg->firmwares,
                                    cfg->nfirmwares) < 0)
        goto cleanup;

    ret = virDomainCapsFormat(domCaps);

 cleanup:
    virObjectUnref(domCaps);
    virObjectUnref(cfg);
    return ret;
}


static int
libxlConnectCompareCPU(virConnectPtr conn,
                       const char *xmlDesc,
                       unsigned int flags)
{
    libxlDriverPrivate *driver = conn->privateData;
    libxlDriverConfig *cfg;
    int ret = VIR_CPU_COMPARE_ERROR;
    bool failIncompatible;
    bool validateXML;

    virCheckFlags(VIR_CONNECT_COMPARE_CPU_FAIL_INCOMPATIBLE |
                  VIR_CONNECT_COMPARE_CPU_VALIDATE_XML,
                  VIR_CPU_COMPARE_ERROR);

    if (virConnectCompareCPUEnsureACL(conn) < 0)
        return ret;

    failIncompatible = !!(flags & VIR_CONNECT_COMPARE_CPU_FAIL_INCOMPATIBLE);
    validateXML = !!(flags & VIR_CONNECT_COMPARE_CPU_VALIDATE_XML);

    cfg = libxlDriverConfigGet(driver);

    ret = virCPUCompareXML(cfg->caps->host.arch, cfg->caps->host.cpu,
                           xmlDesc, failIncompatible, validateXML);

    virObjectUnref(cfg);
    return ret;
}

static char *
libxlConnectBaselineCPU(virConnectPtr conn,
                        const char **xmlCPUs,
                        unsigned int ncpus,
                        unsigned int flags)
{
    virCPUDef **cpus = NULL;
    virCPUDef *cpu = NULL;
    char *cpustr = NULL;

    virCheckFlags(VIR_CONNECT_BASELINE_CPU_EXPAND_FEATURES |
                  VIR_CONNECT_BASELINE_CPU_MIGRATABLE, NULL);

    if (virConnectBaselineCPUEnsureACL(conn) < 0)
        goto cleanup;

    if (!(cpus = virCPUDefListParse(xmlCPUs, ncpus, VIR_CPU_TYPE_HOST)))
        goto cleanup;

    if (!(cpu = virCPUBaseline(VIR_ARCH_NONE, cpus, ncpus, NULL, NULL,
                               !!(flags & VIR_CONNECT_BASELINE_CPU_MIGRATABLE))))
        goto cleanup;

    if ((flags & VIR_CONNECT_BASELINE_CPU_EXPAND_FEATURES) &&
        virCPUExpandFeatures(cpus[0]->arch, cpu) < 0)
        goto cleanup;

    cpustr = virCPUDefFormat(cpu, NULL);

 cleanup:
    virCPUDefListFree(cpus);
    virCPUDefFree(cpu);

    return cpustr;
}

static int
libxlDomainSetMetadata(virDomainPtr dom,
                       int type,
                       const char *metadata,
                       const char *key,
                       const char *uri,
                       unsigned int flags)
{
    libxlDriverPrivate *driver = dom->conn->privateData;
    g_autoptr(libxlDriverConfig) cfg = libxlDriverConfigGet(driver);
    virDomainObj *vm = NULL;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

    if (!(vm = libxlDomObjFromDomain(dom)))
        return -1;

    if (virDomainSetMetadataEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (virDomainObjBeginJob(vm, VIR_JOB_MODIFY) < 0)
        goto cleanup;

    ret = virDomainObjSetMetadata(vm, type, metadata, key, uri,
                                  driver->xmlopt, cfg->stateDir,
                                  cfg->configDir, flags);

    if (ret == 0) {
        virObjectEvent *ev = NULL;
        ev = virDomainEventMetadataChangeNewFromObj(vm, type, uri);
        virObjectEventStateQueue(driver->domainEventState, ev);
    }

    virDomainObjEndJob(vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static char *
libxlDomainGetMetadata(virDomainPtr dom,
                       int type,
                       const char *uri,
                       unsigned int flags)
{
    virDomainObj *vm;
    char *ret = NULL;

    if (!(vm = libxlDomObjFromDomain(dom)))
        return NULL;

    if (virDomainGetMetadataEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    ret = virDomainObjGetMetadata(vm, type, uri, flags);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
libxlDomainGetMessages(virDomainPtr dom,
                      char ***msgs,
                      unsigned int flags)
{
    virDomainObj *vm = NULL;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(vm = libxlDomObjFromDomain(dom)))
        return -1;

    if (virDomainGetMessagesEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    ret = virDomainObjGetMessages(vm, msgs, flags);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static virHypervisorDriver libxlHypervisorDriver = {
    .name = LIBXL_DRIVER_EXTERNAL_NAME,
    .connectURIProbe = libxlConnectURIProbe,
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
#ifdef LIBXL_HAVE_DOMAIN_SUSPEND_ONLY
    .domainPMSuspendForDuration = libxlDomainPMSuspendForDuration, /* 4.8.0 */
#endif
    .domainPMWakeup = libxlDomainPMWakeup, /* 4.8.0 */
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
    .domainGetMaxVcpus = libxlDomainGetMaxVcpus, /* 3.0.0 */
    .domainPinVcpu = libxlDomainPinVcpu, /* 0.9.0 */
    .domainPinVcpuFlags = libxlDomainPinVcpuFlags, /* 1.2.1 */
    .domainGetVcpus = libxlDomainGetVcpus, /* 0.9.0 */
    .domainGetVcpuPinInfo = libxlDomainGetVcpuPinInfo, /* 1.2.1 */
    .domainGetXMLDesc = libxlDomainGetXMLDesc, /* 0.9.0 */
    .connectDomainXMLFromNative = libxlConnectDomainXMLFromNative, /* 0.9.0 */
    .connectDomainXMLToNative = libxlConnectDomainXMLToNative, /* 0.9.0 */
    .connectListDefinedDomains = libxlConnectListDefinedDomains, /* 0.9.0 */
    .connectNumOfDefinedDomains = libxlConnectNumOfDefinedDomains, /* 0.9.0 */
    .domainCreate = libxlDomainCreate, /* 0.9.0 */
    .domainCreateWithFlags = libxlDomainCreateWithFlags, /* 0.9.0 */
    .domainDefineXML = libxlDomainDefineXML, /* 0.9.0 */
    .domainDefineXMLFlags = libxlDomainDefineXMLFlags, /* 1.2.12 */
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
    .domainGetNumaParameters = libxlDomainGetNumaParameters, /* 1.1.1 */
    .nodeGetFreeMemory = libxlNodeGetFreeMemory, /* 0.9.0 */
    .nodeGetCellsFreeMemory = libxlNodeGetCellsFreeMemory, /* 1.1.1 */
    .domainGetJobInfo = libxlDomainGetJobInfo, /* 1.3.1 */
    .domainGetJobStats = libxlDomainGetJobStats, /* 1.3.1 */
    .domainMemoryStats = libxlDomainMemoryStats, /* 1.3.0 */
    .domainGetCPUStats = libxlDomainGetCPUStats, /* 1.3.0 */
    .domainInterfaceStats = libxlDomainInterfaceStats, /* 1.3.2 */
    .domainBlockStats = libxlDomainBlockStats, /* 2.1.0 */
    .domainBlockStatsFlags = libxlDomainBlockStatsFlags, /* 2.1.0 */
    .connectDomainEventRegister = libxlConnectDomainEventRegister, /* 0.9.0 */
    .connectDomainEventDeregister = libxlConnectDomainEventDeregister, /* 0.9.0 */
    .domainManagedSave = libxlDomainManagedSave, /* 0.9.2 */
    .domainHasManagedSaveImage = libxlDomainHasManagedSaveImage, /* 0.9.2 */
    .domainManagedSaveRemove = libxlDomainManagedSaveRemove, /* 0.9.2 */
    .domainOpenConsole = libxlDomainOpenConsole, /* 1.1.2 */
    .domainIsActive = libxlDomainIsActive, /* 0.9.0 */
    .domainIsPersistent = libxlDomainIsPersistent, /* 0.9.0 */
    .domainIsUpdated = libxlDomainIsUpdated, /* 0.9.0 */
    .connectDomainEventRegisterAny = libxlConnectDomainEventRegisterAny, /* 0.9.0 */
    .connectDomainEventDeregisterAny = libxlConnectDomainEventDeregisterAny, /* 0.9.0 */
    .connectIsAlive = libxlConnectIsAlive, /* 0.9.8 */
    .connectSupportsFeature = libxlConnectSupportsFeature, /* 1.1.1 */
    .nodeDeviceDettach = libxlNodeDeviceDettach, /* 1.2.3 */
    .nodeDeviceDetachFlags = libxlNodeDeviceDetachFlags, /* 1.2.3 */
    .nodeDeviceReAttach = libxlNodeDeviceReAttach, /* 1.2.3 */
    .nodeDeviceReset = libxlNodeDeviceReset, /* 1.2.3 */
    .domainMigrateBegin3Params = libxlDomainMigrateBegin3Params, /* 1.2.6 */
    .domainMigratePrepare3Params = libxlDomainMigratePrepare3Params, /* 1.2.6 */
    .domainMigratePrepareTunnel3Params = libxlDomainMigratePrepareTunnel3Params, /* 3.1.0 */
    .domainMigratePerform3Params = libxlDomainMigratePerform3Params, /* 1.2.6 */
    .domainMigrateFinish3Params = libxlDomainMigrateFinish3Params, /* 1.2.6 */
    .domainMigrateConfirm3Params = libxlDomainMigrateConfirm3Params, /* 1.2.6 */
    .nodeGetSecurityModel = libxlNodeGetSecurityModel, /* 1.2.16 */
    .domainInterfaceAddresses = libxlDomainInterfaceAddresses, /* 1.3.5 */
    .connectGetDomainCapabilities = libxlConnectGetDomainCapabilities, /* 2.0.0 */
    .connectCompareCPU = libxlConnectCompareCPU, /* 2.3.0 */
    .connectBaselineCPU = libxlConnectBaselineCPU, /* 2.3.0 */
    .domainSetMetadata = libxlDomainSetMetadata, /* 5.7.0 */
    .domainGetMetadata = libxlDomainGetMetadata, /* 5.7.0 */
    .domainGetMessages = libxlDomainGetMessages, /* 8.0.0 */

};

static virConnectDriver libxlConnectDriver = {
    .localOnly = true,
    .uriSchemes = (const char *[]){ "xen", NULL },
    .hypervisorDriver = &libxlHypervisorDriver,
};

static virStateDriver libxlStateDriver = {
    .name = LIBXL_DRIVER_EXTERNAL_NAME,
    .stateInitialize = libxlStateInitialize,
    .stateCleanup = libxlStateCleanup,
    .stateReload = libxlStateReload,
};


int
libxlRegister(void)
{
    if (virRegisterConnectDriver(&libxlConnectDriver,
                                 true) < 0)
        return -1;
    if (virRegisterStateDriver(&libxlStateDriver) < 0)
        return -1;

    return 0;
}
