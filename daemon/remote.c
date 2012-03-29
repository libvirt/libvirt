/*
 * remote.c: handlers for RPC method calls
 *
 * Copyright (C) 2007-2012 Red Hat, Inc.
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
 * Author: Richard W.M. Jones <rjones@redhat.com>
 */

#include <config.h>

#include "virterror_internal.h"

#if HAVE_POLKIT0
# include <polkit/polkit.h>
# include <polkit-dbus/polkit-dbus.h>
#endif

#include "remote.h"
#include "libvirtd.h"
#include "libvirt_internal.h"
#include "datatypes.h"
#include "memory.h"
#include "logging.h"
#include "util.h"
#include "stream.h"
#include "uuid.h"
#include "libvirt/libvirt-qemu.h"
#include "command.h"
#include "intprops.h"
#include "virnetserverservice.h"
#include "virnetserver.h"
#include "virfile.h"
#include "virtypedparam.h"

#include "remote_protocol.h"
#include "qemu_protocol.h"


#define VIR_FROM_THIS VIR_FROM_RPC

#define virNetError(code, ...)                                    \
    virReportErrorHelper(VIR_FROM_THIS, code, __FILE__,           \
                         __FUNCTION__, __LINE__, __VA_ARGS__)

#if SIZEOF_LONG < 8
# define HYPER_TO_TYPE(_type, _to, _from)                               \
    do {                                                                \
        if ((_from) != (_type)(_from)) {                                \
            virNetError(VIR_ERR_OVERFLOW,                               \
                        _("conversion from hyper to %s overflowed"),    \
                        #_type);                                        \
            goto cleanup;                                               \
        }                                                               \
        (_to) = (_from);                                                \
    } while (0)

# define HYPER_TO_LONG(_to, _from) HYPER_TO_TYPE(long, _to, _from)
# define HYPER_TO_ULONG(_to, _from) HYPER_TO_TYPE(unsigned long, _to, _from)
#else
# define HYPER_TO_LONG(_to, _from) (_to) = (_from)
# define HYPER_TO_ULONG(_to, _from) (_to) = (_from)
#endif

static virDomainPtr get_nonnull_domain(virConnectPtr conn, remote_nonnull_domain domain);
static virNetworkPtr get_nonnull_network(virConnectPtr conn, remote_nonnull_network network);
static virInterfacePtr get_nonnull_interface(virConnectPtr conn, remote_nonnull_interface iface);
static virStoragePoolPtr get_nonnull_storage_pool(virConnectPtr conn, remote_nonnull_storage_pool pool);
static virStorageVolPtr get_nonnull_storage_vol(virConnectPtr conn, remote_nonnull_storage_vol vol);
static virSecretPtr get_nonnull_secret(virConnectPtr conn, remote_nonnull_secret secret);
static virNWFilterPtr get_nonnull_nwfilter(virConnectPtr conn, remote_nonnull_nwfilter nwfilter);
static virDomainSnapshotPtr get_nonnull_domain_snapshot(virDomainPtr dom, remote_nonnull_domain_snapshot snapshot);
static void make_nonnull_domain(remote_nonnull_domain *dom_dst, virDomainPtr dom_src);
static void make_nonnull_network(remote_nonnull_network *net_dst, virNetworkPtr net_src);
static void make_nonnull_interface(remote_nonnull_interface *interface_dst, virInterfacePtr interface_src);
static void make_nonnull_storage_pool(remote_nonnull_storage_pool *pool_dst, virStoragePoolPtr pool_src);
static void make_nonnull_storage_vol(remote_nonnull_storage_vol *vol_dst, virStorageVolPtr vol_src);
static void make_nonnull_node_device(remote_nonnull_node_device *dev_dst, virNodeDevicePtr dev_src);
static void make_nonnull_secret(remote_nonnull_secret *secret_dst, virSecretPtr secret_src);
static void make_nonnull_nwfilter(remote_nonnull_nwfilter *net_dst, virNWFilterPtr nwfilter_src);
static void make_nonnull_domain_snapshot(remote_nonnull_domain_snapshot *snapshot_dst, virDomainSnapshotPtr snapshot_src);

static virTypedParameterPtr
remoteDeserializeTypedParameters(remote_typed_param *args_params_val,
                                 u_int args_params_len,
                                 int limit,
                                 int *nparams);

static int
remoteSerializeDomainDiskErrors(virDomainDiskErrorPtr errors,
                                int nerrors,
                                remote_domain_disk_error **ret_errors_val,
                                u_int *ret_errors_len);

#include "remote_dispatch.h"
#include "qemu_dispatch.h"


/* Prototypes */
static void
remoteDispatchDomainEventSend(virNetServerClientPtr client,
                              virNetServerProgramPtr program,
                              int procnr,
                              xdrproc_t proc,
                              void *data);

static int remoteRelayDomainEventLifecycle(virConnectPtr conn ATTRIBUTE_UNUSED,
                                           virDomainPtr dom,
                                           int event,
                                           int detail,
                                           void *opaque)
{
    virNetServerClientPtr client = opaque;
    remote_domain_event_lifecycle_msg data;

    if (!client)
        return -1;

    VIR_DEBUG("Relaying domain lifecycle event %d %d", event, detail);

    /* build return data */
    memset(&data, 0, sizeof(data));
    make_nonnull_domain(&data.dom, dom);
    data.event = event;
    data.detail = detail;

    remoteDispatchDomainEventSend(client, remoteProgram,
                                  REMOTE_PROC_DOMAIN_EVENT_LIFECYCLE,
                                  (xdrproc_t)xdr_remote_domain_event_lifecycle_msg, &data);

    return 0;
}

static int remoteRelayDomainEventReboot(virConnectPtr conn ATTRIBUTE_UNUSED,
                                        virDomainPtr dom,
                                        void *opaque)
{
    virNetServerClientPtr client = opaque;
    remote_domain_event_reboot_msg data;

    if (!client)
        return -1;

    VIR_DEBUG("Relaying domain reboot event %s %d", dom->name, dom->id);

    /* build return data */
    memset(&data, 0, sizeof(data));
    make_nonnull_domain(&data.dom, dom);

    remoteDispatchDomainEventSend(client, remoteProgram,
                                  REMOTE_PROC_DOMAIN_EVENT_REBOOT,
                                  (xdrproc_t)xdr_remote_domain_event_reboot_msg, &data);

    return 0;
}


static int remoteRelayDomainEventRTCChange(virConnectPtr conn ATTRIBUTE_UNUSED,
                                           virDomainPtr dom,
                                           long long offset,
                                           void *opaque)
{
    virNetServerClientPtr client = opaque;
    remote_domain_event_rtc_change_msg data;

    if (!client)
        return -1;

    VIR_DEBUG("Relaying domain rtc change event %s %d %lld", dom->name, dom->id, offset);

    /* build return data */
    memset(&data, 0, sizeof(data));
    make_nonnull_domain(&data.dom, dom);
    data.offset = offset;

    remoteDispatchDomainEventSend(client, remoteProgram,
                                  REMOTE_PROC_DOMAIN_EVENT_RTC_CHANGE,
                                  (xdrproc_t)xdr_remote_domain_event_rtc_change_msg, &data);

    return 0;
}


static int remoteRelayDomainEventWatchdog(virConnectPtr conn ATTRIBUTE_UNUSED,
                                          virDomainPtr dom,
                                          int action,
                                          void *opaque)
{
    virNetServerClientPtr client = opaque;
    remote_domain_event_watchdog_msg data;

    if (!client)
        return -1;

    VIR_DEBUG("Relaying domain watchdog event %s %d %d", dom->name, dom->id, action);

    /* build return data */
    memset(&data, 0, sizeof(data));
    make_nonnull_domain(&data.dom, dom);
    data.action = action;

    remoteDispatchDomainEventSend(client, remoteProgram,
                                  REMOTE_PROC_DOMAIN_EVENT_WATCHDOG,
                                  (xdrproc_t)xdr_remote_domain_event_watchdog_msg, &data);

    return 0;
}


static int remoteRelayDomainEventIOError(virConnectPtr conn ATTRIBUTE_UNUSED,
                                         virDomainPtr dom,
                                         const char *srcPath,
                                         const char *devAlias,
                                         int action,
                                         void *opaque)
{
    virNetServerClientPtr client = opaque;
    remote_domain_event_io_error_msg data;

    if (!client)
        return -1;

    VIR_DEBUG("Relaying domain io error %s %d %s %s %d", dom->name, dom->id, srcPath, devAlias, action);

    /* build return data */
    memset(&data, 0, sizeof(data));
    data.srcPath = strdup(srcPath);
    if (data.srcPath == NULL)
        goto mem_error;
    data.devAlias = strdup(devAlias);
    if (data.devAlias == NULL)
        goto mem_error;
    make_nonnull_domain(&data.dom, dom);
    data.action = action;

    remoteDispatchDomainEventSend(client, remoteProgram,
                                  REMOTE_PROC_DOMAIN_EVENT_IO_ERROR,
                                  (xdrproc_t)xdr_remote_domain_event_io_error_msg, &data);

    return 0;
mem_error:
    virReportOOMError();
    VIR_FREE(data.srcPath);
    VIR_FREE(data.devAlias);
    return -1;
}


static int remoteRelayDomainEventIOErrorReason(virConnectPtr conn ATTRIBUTE_UNUSED,
                                               virDomainPtr dom,
                                               const char *srcPath,
                                               const char *devAlias,
                                               int action,
                                               const char *reason,
                                               void *opaque)
{
    virNetServerClientPtr client = opaque;
    remote_domain_event_io_error_reason_msg data;

    if (!client)
        return -1;

    VIR_DEBUG("Relaying domain io error %s %d %s %s %d %s",
              dom->name, dom->id, srcPath, devAlias, action, reason);

    /* build return data */
    memset(&data, 0, sizeof(data));
    data.srcPath = strdup(srcPath);
    if (data.srcPath == NULL)
        goto mem_error;
    data.devAlias = strdup(devAlias);
    if (data.devAlias == NULL)
        goto mem_error;
    data.action = action;
    data.reason = strdup(reason);
    if (data.reason == NULL)
        goto mem_error;

    make_nonnull_domain(&data.dom, dom);

    remoteDispatchDomainEventSend(client, remoteProgram,
                                  REMOTE_PROC_DOMAIN_EVENT_IO_ERROR_REASON,
                                  (xdrproc_t)xdr_remote_domain_event_io_error_reason_msg, &data);

    return 0;

mem_error:
    virReportOOMError();
    VIR_FREE(data.srcPath);
    VIR_FREE(data.devAlias);
    VIR_FREE(data.reason);
    return -1;
}


static int remoteRelayDomainEventGraphics(virConnectPtr conn ATTRIBUTE_UNUSED,
                                          virDomainPtr dom,
                                          int phase,
                                          virDomainEventGraphicsAddressPtr local,
                                          virDomainEventGraphicsAddressPtr remote,
                                          const char *authScheme,
                                          virDomainEventGraphicsSubjectPtr subject,
                                          void *opaque)
{
    virNetServerClientPtr client = opaque;
    remote_domain_event_graphics_msg data;
    int i;

    if (!client)
        return -1;

    VIR_DEBUG("Relaying domain graphics event %s %d %d - %d %s %s  - %d %s %s - %s", dom->name, dom->id, phase,
              local->family, local->service, local->node,
              remote->family, remote->service, remote->node,
              authScheme);

    VIR_DEBUG("Subject %d", subject->nidentity);
    for (i = 0 ; i < subject->nidentity ; i++) {
        VIR_DEBUG("  %s=%s", subject->identities[i].type, subject->identities[i].name);
    }

    /* build return data */
    memset(&data, 0, sizeof(data));
    data.phase = phase;
    data.local.family = local->family;
    data.remote.family = remote->family;
    data.authScheme = strdup(authScheme);
    if (data.authScheme == NULL)
        goto mem_error;

    data.local.node = strdup(local->node);
    if (data.local.node == NULL)
        goto mem_error;
    data.local.service = strdup(local->service);
    if (data.local.service == NULL)
        goto mem_error;

    data.remote.node = strdup(remote->node);
    if (data.remote.node == NULL)
        goto mem_error;
    data.remote.service = strdup(remote->service);
    if (data.remote.service == NULL)
        goto mem_error;

    data.subject.subject_len = subject->nidentity;
    if (VIR_ALLOC_N(data.subject.subject_val, data.subject.subject_len) < 0)
        goto mem_error;

    for (i = 0 ; i < data.subject.subject_len ; i++) {
        data.subject.subject_val[i].type = strdup(subject->identities[i].type);
        if (data.subject.subject_val[i].type == NULL)
            goto mem_error;
        data.subject.subject_val[i].name = strdup(subject->identities[i].name);
        if (data.subject.subject_val[i].name == NULL)
            goto mem_error;
    }
    make_nonnull_domain(&data.dom, dom);

    remoteDispatchDomainEventSend(client, remoteProgram,
                                  REMOTE_PROC_DOMAIN_EVENT_GRAPHICS,
                                  (xdrproc_t)xdr_remote_domain_event_graphics_msg, &data);

    return 0;

mem_error:
    virReportOOMError();
    VIR_FREE(data.authScheme);
    VIR_FREE(data.local.node);
    VIR_FREE(data.local.service);
    VIR_FREE(data.remote.node);
    VIR_FREE(data.remote.service);
    if (data.subject.subject_val != NULL) {
        for (i = 0 ; i < data.subject.subject_len ; i++) {
            VIR_FREE(data.subject.subject_val[i].type);
            VIR_FREE(data.subject.subject_val[i].name);
        }
        VIR_FREE(data.subject.subject_val);
    }
    return -1;
}

static int remoteRelayDomainEventBlockJob(virConnectPtr conn ATTRIBUTE_UNUSED,
                                          virDomainPtr dom,
                                          const char *path,
                                          int type,
                                          int status,
                                          void *opaque)
{
    virNetServerClientPtr client = opaque;
    remote_domain_event_block_job_msg data;

    if (!client)
        return -1;

    VIR_DEBUG("Relaying domain block job event %s %d %s %i, %i",
              dom->name, dom->id, path, type, status);

    /* build return data */
    memset(&data, 0, sizeof(data));
    data.path = strdup(path);
    if (data.path == NULL)
        goto mem_error;
    data.type = type;
    data.status = status;
    make_nonnull_domain(&data.dom, dom);

    remoteDispatchDomainEventSend(client, remoteProgram,
                                  REMOTE_PROC_DOMAIN_EVENT_BLOCK_JOB,
                                  (xdrproc_t)xdr_remote_domain_event_block_job_msg, &data);

    return 0;

mem_error:
    virReportOOMError();
    VIR_FREE(data.path);
    return -1;
}


static int remoteRelayDomainEventControlError(virConnectPtr conn ATTRIBUTE_UNUSED,
                                              virDomainPtr dom,
                                              void *opaque)
{
    virNetServerClientPtr client = opaque;
    remote_domain_event_control_error_msg data;

    if (!client)
        return -1;

    VIR_DEBUG("Relaying domain control error %s %d", dom->name, dom->id);

    /* build return data */
    memset(&data, 0, sizeof(data));
    make_nonnull_domain(&data.dom, dom);

    remoteDispatchDomainEventSend(client, remoteProgram,
                                  REMOTE_PROC_DOMAIN_EVENT_CONTROL_ERROR,
                                  (xdrproc_t)xdr_remote_domain_event_control_error_msg, &data);

    return 0;
}


static int remoteRelayDomainEventDiskChange(virConnectPtr conn ATTRIBUTE_UNUSED,
                                            virDomainPtr dom,
                                            const char *oldSrcPath,
                                            const char *newSrcPath,
                                            const char *devAlias,
                                            int reason,
                                            void *opaque)
{
    virNetServerClientPtr client = opaque;
    remote_domain_event_disk_change_msg data;
    char **oldSrcPath_p = NULL, **newSrcPath_p = NULL;

    if (!client)
        return -1;

    VIR_DEBUG("Relaying domain %s %d disk change %s %s %s %d",
              dom->name, dom->id, oldSrcPath, newSrcPath, devAlias, reason);

    /* build return data */
    memset(&data, 0, sizeof(data));
    if (oldSrcPath &&
        ((VIR_ALLOC(oldSrcPath_p) < 0) ||
         !(*oldSrcPath_p = strdup(oldSrcPath))))
        goto mem_error;

    if (newSrcPath &&
        ((VIR_ALLOC(newSrcPath_p) < 0) ||
         !(*newSrcPath_p = strdup(newSrcPath))))
        goto mem_error;

    data.oldSrcPath = oldSrcPath_p;
    data.newSrcPath = newSrcPath_p;
    if (!(data.devAlias = strdup(devAlias)))
        goto mem_error;
    data.reason = reason;

    make_nonnull_domain(&data.dom, dom);

    remoteDispatchDomainEventSend(client, remoteProgram,
                                  REMOTE_PROC_DOMAIN_EVENT_DISK_CHANGE,
                                  (xdrproc_t)xdr_remote_domain_event_disk_change_msg, &data);

    return 0;

mem_error:
    VIR_FREE(oldSrcPath_p);
    VIR_FREE(newSrcPath_p);
    virReportOOMError();
    return -1;
}


static int remoteRelayDomainEventTrayChange(virConnectPtr conn ATTRIBUTE_UNUSED,
                                            virDomainPtr dom,
                                            const char *devAlias,
                                            int reason,
                                            void *opaque) {
    virNetServerClientPtr client = opaque;
    remote_domain_event_tray_change_msg data;

    if (!client)
        return -1;

    VIR_DEBUG("Relaying domain %s %d tray change devAlias: %s reason: %d",
              dom->name, dom->id, devAlias, reason);

    /* build return data */
    memset(&data, 0, sizeof(data));

    if (!(data.devAlias = strdup(devAlias))) {
        virReportOOMError();
        return -1;
    }
    data.reason = reason;

    make_nonnull_domain(&data.dom, dom);

    remoteDispatchDomainEventSend(client, remoteProgram,
                                  REMOTE_PROC_DOMAIN_EVENT_TRAY_CHANGE,
                                  (xdrproc_t)xdr_remote_domain_event_tray_change_msg, &data);

    return 0;
}

static int remoteRelayDomainEventPMWakeup(virConnectPtr conn ATTRIBUTE_UNUSED,
                                          virDomainPtr dom,
                                          void *opaque) {
    virNetServerClientPtr client = opaque;
    remote_domain_event_pmwakeup_msg data;

    if (!client)
        return -1;

    VIR_DEBUG("Relaying domain %s %d system pmwakeup", dom->name, dom->id);

    /* build return data */
    memset(&data, 0, sizeof(data));
    make_nonnull_domain(&data.dom, dom);

    remoteDispatchDomainEventSend(client, remoteProgram,
                                  REMOTE_PROC_DOMAIN_EVENT_PMWAKEUP,
                                  (xdrproc_t)xdr_remote_domain_event_pmwakeup_msg, &data);

    return 0;
}

static int remoteRelayDomainEventPMSuspend(virConnectPtr conn ATTRIBUTE_UNUSED,
                                           virDomainPtr dom,
                                           void *opaque) {
    virNetServerClientPtr client = opaque;
    remote_domain_event_pmsuspend_msg data;

    if (!client)
        return -1;

    VIR_DEBUG("Relaying domain %s %d system pmsuspend", dom->name, dom->id);

    /* build return data */
    memset(&data, 0, sizeof(data));
    make_nonnull_domain(&data.dom, dom);

    remoteDispatchDomainEventSend(client, remoteProgram,
                                  REMOTE_PROC_DOMAIN_EVENT_PMSUSPEND,
                                  (xdrproc_t)xdr_remote_domain_event_pmsuspend_msg, &data);

    return 0;
}

static virConnectDomainEventGenericCallback domainEventCallbacks[] = {
    VIR_DOMAIN_EVENT_CALLBACK(remoteRelayDomainEventLifecycle),
    VIR_DOMAIN_EVENT_CALLBACK(remoteRelayDomainEventReboot),
    VIR_DOMAIN_EVENT_CALLBACK(remoteRelayDomainEventRTCChange),
    VIR_DOMAIN_EVENT_CALLBACK(remoteRelayDomainEventWatchdog),
    VIR_DOMAIN_EVENT_CALLBACK(remoteRelayDomainEventIOError),
    VIR_DOMAIN_EVENT_CALLBACK(remoteRelayDomainEventGraphics),
    VIR_DOMAIN_EVENT_CALLBACK(remoteRelayDomainEventIOErrorReason),
    VIR_DOMAIN_EVENT_CALLBACK(remoteRelayDomainEventControlError),
    VIR_DOMAIN_EVENT_CALLBACK(remoteRelayDomainEventBlockJob),
    VIR_DOMAIN_EVENT_CALLBACK(remoteRelayDomainEventDiskChange),
    VIR_DOMAIN_EVENT_CALLBACK(remoteRelayDomainEventTrayChange),
    VIR_DOMAIN_EVENT_CALLBACK(remoteRelayDomainEventPMWakeup),
    VIR_DOMAIN_EVENT_CALLBACK(remoteRelayDomainEventPMSuspend),
};

verify(ARRAY_CARDINALITY(domainEventCallbacks) == VIR_DOMAIN_EVENT_ID_LAST);

/*
 * You must hold lock for at least the client
 * We don't free stuff here, merely disconnect the client's
 * network socket & resources.
 * We keep the libvirt connection open until any async
 * jobs have finished, then clean it up elsewhere
 */
static void remoteClientFreeFunc(void *data)
{
    struct daemonClientPrivate *priv = data;

    /* Deregister event delivery callback */
    if (priv->conn) {
        int i;

        for (i = 0 ; i < VIR_DOMAIN_EVENT_ID_LAST ; i++) {
            if (priv->domainEventCallbackID[i] != -1) {
                VIR_DEBUG("Deregistering to relay remote events %d", i);
                virConnectDomainEventDeregisterAny(priv->conn,
                                                   priv->domainEventCallbackID[i]);
            }
            priv->domainEventCallbackID[i] = -1;
        }

        virConnectClose(priv->conn);
    }

    VIR_FREE(priv);
}


static void remoteClientCloseFunc(virNetServerClientPtr client)
{
    struct daemonClientPrivate *priv = virNetServerClientGetPrivateData(client);

    daemonRemoveAllClientStreams(priv->streams);
}


int remoteClientInitHook(virNetServerPtr srv ATTRIBUTE_UNUSED,
                         virNetServerClientPtr client)
{
    struct daemonClientPrivate *priv;
    int i;

    if (VIR_ALLOC(priv) < 0) {
        virReportOOMError();
        return -1;
    }

    if (virMutexInit(&priv->lock) < 0) {
        VIR_FREE(priv);
        virReportOOMError();
        return -1;
    }

    for (i = 0 ; i < VIR_DOMAIN_EVENT_ID_LAST ; i++)
        priv->domainEventCallbackID[i] = -1;

    virNetServerClientSetPrivateData(client, priv,
                                     remoteClientFreeFunc);
    virNetServerClientSetCloseHook(client, remoteClientCloseFunc);
    return 0;
}

/*----- Functions. -----*/

static int
remoteDispatchOpen(virNetServerPtr server,
                   virNetServerClientPtr client,
                   virNetMessagePtr msg ATTRIBUTE_UNUSED,
                   virNetMessageErrorPtr rerr,
                   struct remote_open_args *args)
{
    const char *name;
    unsigned int flags;
    struct daemonClientPrivate *priv = virNetServerClientGetPrivateData(client);
    int rv = -1;

    VIR_DEBUG("priv=%p conn=%p", priv, priv->conn);
    virMutexLock(&priv->lock);
    /* Already opened? */
    if (priv->conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection already open"));
        goto cleanup;
    }

    if (virNetServerKeepAliveRequired(server) && !priv->keepalive_supported) {
        virNetError(VIR_ERR_OPERATION_FAILED, "%s",
                    _("keepalive support is required to connect"));
        goto cleanup;
    }

    name = args->name ? *args->name : NULL;

    /* If this connection arrived on a readonly socket, force
     * the connection to be readonly.
     */
    flags = args->flags;
    if (virNetServerClientGetReadonly(client))
        flags |= VIR_CONNECT_RO;

    priv->conn =
        flags & VIR_CONNECT_RO
        ? virConnectOpenReadOnly(name)
        : virConnectOpen(name);

    if (priv->conn == NULL)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        virNetMessageSaveError(rerr);
    virMutexUnlock(&priv->lock);
    return rv;
}


static int
remoteDispatchClose(virNetServerPtr server ATTRIBUTE_UNUSED,
                    virNetServerClientPtr client ATTRIBUTE_UNUSED,
                    virNetMessagePtr msg ATTRIBUTE_UNUSED,
                    virNetMessageErrorPtr rerr ATTRIBUTE_UNUSED)
{
    virNetServerClientDelayedClose(client);
    return 0;
}


static int
remoteDispatchDomainGetSchedulerType(virNetServerPtr server ATTRIBUTE_UNUSED,
                                     virNetServerClientPtr client ATTRIBUTE_UNUSED,
                                     virNetMessagePtr msg ATTRIBUTE_UNUSED,
                                     virNetMessageErrorPtr rerr,
                                     remote_domain_get_scheduler_type_args *args,
                                     remote_domain_get_scheduler_type_ret *ret)
{
    virDomainPtr dom = NULL;
    char *type;
    int nparams;
    int rv = -1;
    struct daemonClientPrivate *priv =
        virNetServerClientGetPrivateData(client);

    if (!priv->conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(priv->conn, args->dom)))
        goto cleanup;

    if (!(type = virDomainGetSchedulerType(dom, &nparams)))
        goto cleanup;

    ret->type = type;
    ret->nparams = nparams;
    rv = 0;

cleanup:
    if (rv < 0)
        virNetMessageSaveError(rerr);
    if (dom)
        virDomainFree(dom);
    return rv;
}

/* Helper to serialize typed parameters. This also filters out any string
 * parameters that must not be returned to older clients.  */
static int
remoteSerializeTypedParameters(virTypedParameterPtr params,
                               int nparams,
                               remote_typed_param **ret_params_val,
                               u_int *ret_params_len,
                               unsigned int flags)
{
    int i;
    int j;
    int rv = -1;
    remote_typed_param *val;

    *ret_params_len = nparams;
    if (VIR_ALLOC_N(val, nparams) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    for (i = 0, j = 0; i < nparams; ++i) {
        /* virDomainGetCPUStats can return a sparse array; also, we
         * can't pass back strings to older clients.  */
        if (!params[i].type ||
            (!(flags & VIR_TYPED_PARAM_STRING_OKAY) &&
             params[i].type == VIR_TYPED_PARAM_STRING)) {
            --*ret_params_len;
            continue;
        }

        /* remoteDispatchClientRequest will free this: */
        val[j].field = strdup(params[i].field);
        if (val[j].field == NULL) {
            virReportOOMError();
            goto cleanup;
        }
        val[j].value.type = params[i].type;
        switch (params[i].type) {
        case VIR_TYPED_PARAM_INT:
            val[j].value.remote_typed_param_value_u.i = params[i].value.i;
            break;
        case VIR_TYPED_PARAM_UINT:
            val[j].value.remote_typed_param_value_u.ui = params[i].value.ui;
            break;
        case VIR_TYPED_PARAM_LLONG:
            val[j].value.remote_typed_param_value_u.l = params[i].value.l;
            break;
        case VIR_TYPED_PARAM_ULLONG:
            val[j].value.remote_typed_param_value_u.ul = params[i].value.ul;
            break;
        case VIR_TYPED_PARAM_DOUBLE:
            val[j].value.remote_typed_param_value_u.d = params[i].value.d;
            break;
        case VIR_TYPED_PARAM_BOOLEAN:
            val[j].value.remote_typed_param_value_u.b = params[i].value.b;
            break;
        case VIR_TYPED_PARAM_STRING:
            val[j].value.remote_typed_param_value_u.s =
                strdup(params[i].value.s);
            if (val[j].value.remote_typed_param_value_u.s == NULL) {
                virReportOOMError();
                goto cleanup;
            }
            break;
        default:
            virNetError(VIR_ERR_RPC, _("unknown parameter type: %d"),
                        params[i].type);
            goto cleanup;
        }
        j++;
    }

    *ret_params_val = val;
    val = NULL;
    rv = 0;

cleanup:
    if (val) {
        for (i = 0; i < nparams; i++) {
            VIR_FREE(val[i].field);
            if (val[i].value.type == VIR_TYPED_PARAM_STRING)
                VIR_FREE(val[i].value.remote_typed_param_value_u.s);
        }
        VIR_FREE(val);
    }
    return rv;
}

/* Helper to deserialize typed parameters. */
static virTypedParameterPtr
remoteDeserializeTypedParameters(remote_typed_param *args_params_val,
                                 u_int args_params_len,
                                 int limit,
                                 int *nparams)
{
    int i = 0;
    int rv = -1;
    virTypedParameterPtr params = NULL;

    /* Check the length of the returned list carefully. */
    if (args_params_len > limit) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("nparams too large"));
        goto cleanup;
    }
    if (VIR_ALLOC_N(params, args_params_len) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    *nparams = args_params_len;

    /* Deserialise the result. */
    for (i = 0; i < args_params_len; ++i) {
        if (virStrcpyStatic(params[i].field,
                            args_params_val[i].field) == NULL) {
            virNetError(VIR_ERR_INTERNAL_ERROR,
                        _("Parameter %s too big for destination"),
                        args_params_val[i].field);
            goto cleanup;
        }
        params[i].type = args_params_val[i].value.type;
        switch (params[i].type) {
        case VIR_TYPED_PARAM_INT:
            params[i].value.i =
                args_params_val[i].value.remote_typed_param_value_u.i;
            break;
        case VIR_TYPED_PARAM_UINT:
            params[i].value.ui =
                args_params_val[i].value.remote_typed_param_value_u.ui;
            break;
        case VIR_TYPED_PARAM_LLONG:
            params[i].value.l =
                args_params_val[i].value.remote_typed_param_value_u.l;
            break;
        case VIR_TYPED_PARAM_ULLONG:
            params[i].value.ul =
                args_params_val[i].value.remote_typed_param_value_u.ul;
            break;
        case VIR_TYPED_PARAM_DOUBLE:
            params[i].value.d =
                args_params_val[i].value.remote_typed_param_value_u.d;
            break;
        case VIR_TYPED_PARAM_BOOLEAN:
            params[i].value.b =
                args_params_val[i].value.remote_typed_param_value_u.b;
            break;
        case VIR_TYPED_PARAM_STRING:
            params[i].value.s =
                strdup(args_params_val[i].value.remote_typed_param_value_u.s);
            if (params[i].value.s == NULL) {
                virReportOOMError();
                goto cleanup;
            }
            break;
        default:
            virNetError(VIR_ERR_INTERNAL_ERROR, _("unknown parameter type: %d"),
                        params[i].type);
            goto cleanup;
        }
    }

    rv = 0;

cleanup:
    if (rv < 0) {
        virTypedParameterArrayClear(params, i);
        VIR_FREE(params);
    }
    return params;
}

static int
remoteDispatchDomainGetSchedulerParameters(virNetServerPtr server ATTRIBUTE_UNUSED,
                                           virNetServerClientPtr client ATTRIBUTE_UNUSED,
                                           virNetMessagePtr msg ATTRIBUTE_UNUSED,
                                           virNetMessageErrorPtr rerr,
                                           remote_domain_get_scheduler_parameters_args *args,
                                           remote_domain_get_scheduler_parameters_ret *ret)
{
    virDomainPtr dom = NULL;
    virTypedParameterPtr params = NULL;
    int nparams = args->nparams;
    int rv = -1;
    struct daemonClientPrivate *priv =
        virNetServerClientGetPrivateData(client);

    if (!priv->conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (nparams > REMOTE_DOMAIN_SCHEDULER_PARAMETERS_MAX) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("nparams too large"));
        goto cleanup;
    }
    if (VIR_ALLOC_N(params, nparams) < 0)
        goto no_memory;

    if (!(dom = get_nonnull_domain(priv->conn, args->dom)))
        goto cleanup;

    if (virDomainGetSchedulerParameters(dom, params, &nparams) < 0)
        goto cleanup;

    if (remoteSerializeTypedParameters(params, nparams,
                                       &ret->params.params_val,
                                       &ret->params.params_len,
                                       0) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        virNetMessageSaveError(rerr);
    virTypedParameterArrayClear(params, nparams);
    VIR_FREE(params);
    if (dom)
        virDomainFree(dom);
    return rv;

no_memory:
    virReportOOMError();
    goto cleanup;
}

static int
remoteDispatchDomainGetSchedulerParametersFlags(virNetServerPtr server ATTRIBUTE_UNUSED,
                                                virNetServerClientPtr client ATTRIBUTE_UNUSED,
                                                virNetMessagePtr msg ATTRIBUTE_UNUSED,
                                                virNetMessageErrorPtr rerr,
                                                remote_domain_get_scheduler_parameters_flags_args *args,
                                                remote_domain_get_scheduler_parameters_flags_ret *ret)
{
    virDomainPtr dom = NULL;
    virTypedParameterPtr params = NULL;
    int nparams = args->nparams;
    int rv = -1;
    struct daemonClientPrivate *priv =
        virNetServerClientGetPrivateData(client);

    if (!priv->conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (nparams > REMOTE_DOMAIN_SCHEDULER_PARAMETERS_MAX) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("nparams too large"));
        goto cleanup;
    }
    if (VIR_ALLOC_N(params, nparams) < 0)
        goto no_memory;

    if (!(dom = get_nonnull_domain(priv->conn, args->dom)))
        goto cleanup;

    if (virDomainGetSchedulerParametersFlags(dom, params, &nparams,
                                             args->flags) < 0)
        goto cleanup;

    if (remoteSerializeTypedParameters(params, nparams,
                                       &ret->params.params_val,
                                       &ret->params.params_len,
                                       args->flags) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        virNetMessageSaveError(rerr);
    virTypedParameterArrayClear(params, nparams);
    VIR_FREE(params);
    if (dom)
        virDomainFree(dom);
    return rv;

no_memory:
    virReportOOMError();
    goto cleanup;
}

static int
remoteDispatchDomainMemoryStats(virNetServerPtr server ATTRIBUTE_UNUSED,
                                virNetServerClientPtr client ATTRIBUTE_UNUSED,
                                virNetMessagePtr msg ATTRIBUTE_UNUSED,
                                virNetMessageErrorPtr rerr,
                                remote_domain_memory_stats_args *args,
                                remote_domain_memory_stats_ret *ret)
{
    virDomainPtr dom = NULL;
    struct _virDomainMemoryStat *stats;
    int nr_stats, i;
    int rv = -1;
    struct daemonClientPrivate *priv =
        virNetServerClientGetPrivateData(client);

    if (!priv->conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (args->maxStats > REMOTE_DOMAIN_MEMORY_STATS_MAX) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("maxStats > REMOTE_DOMAIN_MEMORY_STATS_MAX"));
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(priv->conn, args->dom)))
        goto cleanup;

    /* Allocate stats array for making dispatch call */
    if (VIR_ALLOC_N(stats, args->maxStats) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    nr_stats = virDomainMemoryStats(dom, stats, args->maxStats, args->flags);
    if (nr_stats < 0)
        goto cleanup;

    /* Allocate return buffer */
    if (VIR_ALLOC_N(ret->stats.stats_val, args->maxStats) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    /* Copy the stats into the xdr return structure */
    for (i = 0; i < nr_stats; i++) {
        ret->stats.stats_val[i].tag = stats[i].tag;
        ret->stats.stats_val[i].val = stats[i].val;
    }
    ret->stats.stats_len = nr_stats;
    rv = 0;

cleanup:
    if (rv < 0)
        virNetMessageSaveError(rerr);
    if (dom)
        virDomainFree(dom);
    VIR_FREE(stats);
    return rv;
}

static int
remoteDispatchDomainBlockPeek(virNetServerPtr server ATTRIBUTE_UNUSED,
                              virNetServerClientPtr client ATTRIBUTE_UNUSED,
                              virNetMessagePtr msg ATTRIBUTE_UNUSED,
                              virNetMessageErrorPtr rerr,
                              remote_domain_block_peek_args *args,
                              remote_domain_block_peek_ret *ret)
{
    virDomainPtr dom = NULL;
    char *path;
    unsigned long long offset;
    size_t size;
    unsigned int flags;
    int rv = -1;
    struct daemonClientPrivate *priv =
        virNetServerClientGetPrivateData(client);

    if (!priv->conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(priv->conn, args->dom)))
        goto cleanup;
    path = args->path;
    offset = args->offset;
    size = args->size;
    flags = args->flags;

    if (size > REMOTE_DOMAIN_BLOCK_PEEK_BUFFER_MAX) {
        virNetError(VIR_ERR_INTERNAL_ERROR,
                    "%s", _("size > maximum buffer size"));
        goto cleanup;
    }

    ret->buffer.buffer_len = size;
    if (VIR_ALLOC_N(ret->buffer.buffer_val, size) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if (virDomainBlockPeek(dom, path, offset, size,
                           ret->buffer.buffer_val, flags) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0) {
        virNetMessageSaveError(rerr);
        VIR_FREE(ret->buffer.buffer_val);
    }
    if (dom)
        virDomainFree(dom);
    return rv;
}

static int
remoteDispatchDomainBlockStatsFlags(virNetServerPtr server ATTRIBUTE_UNUSED,
                                    virNetServerClientPtr client ATTRIBUTE_UNUSED,
                                    virNetMessagePtr msg ATTRIBUTE_UNUSED,
                                    virNetMessageErrorPtr rerr,
                                    remote_domain_block_stats_flags_args *args,
                                    remote_domain_block_stats_flags_ret *ret)
{
    virTypedParameterPtr params = NULL;
    virDomainPtr dom = NULL;
    const char *path = args->path;
    int nparams = args->nparams;
    unsigned int flags;
    int rv = -1;
    struct daemonClientPrivate *priv =
        virNetServerClientGetPrivateData(client);

    if (!priv->conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(priv->conn, args->dom)))
        goto cleanup;
    flags = args->flags;

    if (nparams > REMOTE_DOMAIN_BLOCK_STATS_PARAMETERS_MAX) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("nparams too large"));
        goto cleanup;
    }
    if (VIR_ALLOC_N(params, nparams) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if (virDomainBlockStatsFlags(dom, path, params, &nparams, flags) < 0)
        goto cleanup;

    /* In this case, we need to send back the number of parameters
     * supported
     */
    if (args->nparams == 0) {
        ret->nparams = nparams;
        goto success;
    }

    /* Serialise the block stats. */
    if (remoteSerializeTypedParameters(params, nparams,
                                       &ret->params.params_val,
                                       &ret->params.params_len,
                                       args->flags) < 0)
        goto cleanup;

success:
    rv = 0;

cleanup:
    if (rv < 0)
        virNetMessageSaveError(rerr);
    virTypedParameterArrayClear(params, nparams);
    VIR_FREE(params);
    if (dom)
        virDomainFree(dom);
    return rv;
}

static int
remoteDispatchDomainMemoryPeek(virNetServerPtr server ATTRIBUTE_UNUSED,
                               virNetServerClientPtr client ATTRIBUTE_UNUSED,
                               virNetMessagePtr msg ATTRIBUTE_UNUSED,
                               virNetMessageErrorPtr rerr,
                               remote_domain_memory_peek_args *args,
                               remote_domain_memory_peek_ret *ret)
{
    virDomainPtr dom = NULL;
    unsigned long long offset;
    size_t size;
    unsigned int flags;
    int rv = -1;
    struct daemonClientPrivate *priv =
        virNetServerClientGetPrivateData(client);

    if (!priv->conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(priv->conn, args->dom)))
        goto cleanup;
    offset = args->offset;
    size = args->size;
    flags = args->flags;

    if (size > REMOTE_DOMAIN_MEMORY_PEEK_BUFFER_MAX) {
        virNetError(VIR_ERR_INTERNAL_ERROR,
                    "%s", _("size > maximum buffer size"));
        goto cleanup;
    }

    ret->buffer.buffer_len = size;
    if (VIR_ALLOC_N(ret->buffer.buffer_val, size) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if (virDomainMemoryPeek(dom, offset, size,
                            ret->buffer.buffer_val, flags) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0) {
        virNetMessageSaveError(rerr);
        VIR_FREE(ret->buffer.buffer_val);
    }
    if (dom)
        virDomainFree(dom);
    return rv;
}

static int
remoteDispatchDomainGetSecurityLabel(virNetServerPtr server ATTRIBUTE_UNUSED,
                                     virNetServerClientPtr client ATTRIBUTE_UNUSED,
                                     virNetMessagePtr msg ATTRIBUTE_UNUSED,
                                     virNetMessageErrorPtr rerr,
                                     remote_domain_get_security_label_args *args,
                                     remote_domain_get_security_label_ret *ret)
{
    virDomainPtr dom = NULL;
    virSecurityLabelPtr seclabel = NULL;
    int rv = -1;
    struct daemonClientPrivate *priv =
        virNetServerClientGetPrivateData(client);

    if (!priv->conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(priv->conn, args->dom)))
        goto cleanup;

    if (VIR_ALLOC(seclabel) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if (virDomainGetSecurityLabel(dom, seclabel) < 0)
        goto cleanup;

    ret->label.label_len = strlen(seclabel->label) + 1;
    if (VIR_ALLOC_N(ret->label.label_val, ret->label.label_len) < 0) {
        virReportOOMError();
        goto cleanup;
    }
    strcpy(ret->label.label_val, seclabel->label);
    ret->enforcing = seclabel->enforcing;

    rv = 0;

cleanup:
    if (rv < 0)
        virNetMessageSaveError(rerr);
    if (dom)
        virDomainFree(dom);
    VIR_FREE(seclabel);
    return rv;
}

static int
remoteDispatchNodeGetSecurityModel(virNetServerPtr server ATTRIBUTE_UNUSED,
                                   virNetServerClientPtr client ATTRIBUTE_UNUSED,
                                   virNetMessagePtr msg ATTRIBUTE_UNUSED,
                                   virNetMessageErrorPtr rerr,
                                   remote_node_get_security_model_ret *ret)
{
    virSecurityModel secmodel;
    int rv = -1;
    struct daemonClientPrivate *priv =
        virNetServerClientGetPrivateData(client);

    if (!priv->conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    memset(&secmodel, 0, sizeof(secmodel));
    if (virNodeGetSecurityModel(priv->conn, &secmodel) < 0)
        goto cleanup;

    ret->model.model_len = strlen(secmodel.model) + 1;
    if (VIR_ALLOC_N(ret->model.model_val, ret->model.model_len) < 0) {
        virReportOOMError();
        goto cleanup;
    }
    strcpy(ret->model.model_val, secmodel.model);

    ret->doi.doi_len = strlen(secmodel.doi) + 1;
    if (VIR_ALLOC_N(ret->doi.doi_val, ret->doi.doi_len) < 0) {
        virReportOOMError();
        goto cleanup;
    }
    strcpy(ret->doi.doi_val, secmodel.doi);

    rv = 0;

cleanup:
    if (rv < 0)
        virNetMessageSaveError(rerr);
    return rv;
}

static int
remoteDispatchDomainGetVcpuPinInfo(virNetServerPtr server ATTRIBUTE_UNUSED,
                                   virNetServerClientPtr client ATTRIBUTE_UNUSED,
                                   virNetMessagePtr msg ATTRIBUTE_UNUSED,
                                   virNetMessageErrorPtr rerr,
                                   remote_domain_get_vcpu_pin_info_args *args,
                                   remote_domain_get_vcpu_pin_info_ret *ret)
{
    virDomainPtr dom = NULL;
    unsigned char *cpumaps = NULL;
    int num;
    int rv = -1;
    struct daemonClientPrivate *priv =
        virNetServerClientGetPrivateData(client);

    if (!priv->conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(priv->conn, args->dom)))
        goto cleanup;

    if (args->ncpumaps > REMOTE_VCPUINFO_MAX) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("ncpumaps > REMOTE_VCPUINFO_MAX"));
        goto cleanup;
    }

    if (INT_MULTIPLY_OVERFLOW(args->ncpumaps, args->maplen) ||
        args->ncpumaps * args->maplen > REMOTE_CPUMAPS_MAX) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("maxinfo * maplen > REMOTE_CPUMAPS_MAX"));
        goto cleanup;
    }

    /* Allocate buffers to take the results. */
    if (args->maplen > 0 &&
        VIR_ALLOC_N(cpumaps, args->ncpumaps * args->maplen) < 0)
        goto no_memory;

    if ((num = virDomainGetVcpuPinInfo(dom,
                                       args->ncpumaps,
                                       cpumaps,
                                       args->maplen,
                                       args->flags)) < 0)
        goto cleanup;

    ret->num = num;
    /* Don't need to allocate/copy the cpumaps if we make the reasonable
     * assumption that unsigned char and char are the same size.
     * Note that remoteDispatchClientRequest will free.
     */
    ret->cpumaps.cpumaps_len = args->ncpumaps * args->maplen;
    ret->cpumaps.cpumaps_val = (char *) cpumaps;
    cpumaps = NULL;

    rv = 0;

cleanup:
    if (rv < 0)
        virNetMessageSaveError(rerr);
    VIR_FREE(cpumaps);
    if (dom)
        virDomainFree(dom);
    return rv;

no_memory:
    virReportOOMError();
    goto cleanup;
}

static int
remoteDispatchDomainGetVcpus(virNetServerPtr server ATTRIBUTE_UNUSED,
                             virNetServerClientPtr client ATTRIBUTE_UNUSED,
                             virNetMessagePtr msg ATTRIBUTE_UNUSED,
                             virNetMessageErrorPtr rerr,
                             remote_domain_get_vcpus_args *args,
                             remote_domain_get_vcpus_ret *ret)
{
    virDomainPtr dom = NULL;
    virVcpuInfoPtr info = NULL;
    unsigned char *cpumaps = NULL;
    int info_len, i;
    int rv = -1;
    struct daemonClientPrivate *priv =
        virNetServerClientGetPrivateData(client);

    if (!priv->conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(priv->conn, args->dom)))
        goto cleanup;

    if (args->maxinfo > REMOTE_VCPUINFO_MAX) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("maxinfo > REMOTE_VCPUINFO_MAX"));
        goto cleanup;
    }

    if (INT_MULTIPLY_OVERFLOW(args->maxinfo, args->maplen) ||
        args->maxinfo * args->maplen > REMOTE_CPUMAPS_MAX) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("maxinfo * maplen > REMOTE_CPUMAPS_MAX"));
        goto cleanup;
    }

    /* Allocate buffers to take the results. */
    if (VIR_ALLOC_N(info, args->maxinfo) < 0)
        goto no_memory;
    if (args->maplen > 0 &&
        VIR_ALLOC_N(cpumaps, args->maxinfo * args->maplen) < 0)
        goto no_memory;

    if ((info_len = virDomainGetVcpus(dom,
                                      info, args->maxinfo,
                                      cpumaps, args->maplen)) < 0)
        goto cleanup;

    /* Allocate the return buffer for info. */
    ret->info.info_len = info_len;
    if (VIR_ALLOC_N(ret->info.info_val, info_len) < 0)
        goto no_memory;

    for (i = 0; i < info_len; ++i) {
        ret->info.info_val[i].number = info[i].number;
        ret->info.info_val[i].state = info[i].state;
        ret->info.info_val[i].cpu_time = info[i].cpuTime;
        ret->info.info_val[i].cpu = info[i].cpu;
    }

    /* Don't need to allocate/copy the cpumaps if we make the reasonable
     * assumption that unsigned char and char are the same size.
     * Note that remoteDispatchClientRequest will free.
     */
    ret->cpumaps.cpumaps_len = args->maxinfo * args->maplen;
    ret->cpumaps.cpumaps_val = (char *) cpumaps;
    cpumaps = NULL;

    rv = 0;

cleanup:
    if (rv < 0) {
        virNetMessageSaveError(rerr);
        VIR_FREE(ret->info.info_val);
    }
    VIR_FREE(cpumaps);
    VIR_FREE(info);
    if (dom)
        virDomainFree(dom);
    return rv;

no_memory:
    virReportOOMError();
    goto cleanup;
}

static int
remoteDispatchDomainMigratePrepare(virNetServerPtr server ATTRIBUTE_UNUSED,
                                   virNetServerClientPtr client ATTRIBUTE_UNUSED,
                                   virNetMessagePtr msg ATTRIBUTE_UNUSED,
                                   virNetMessageErrorPtr rerr,
                                   remote_domain_migrate_prepare_args *args,
                                   remote_domain_migrate_prepare_ret *ret)
{
    char *cookie = NULL;
    int cookielen = 0;
    char *uri_in;
    char **uri_out;
    char *dname;
    int rv = -1;
    struct daemonClientPrivate *priv =
        virNetServerClientGetPrivateData(client);

    if (!priv->conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    uri_in = args->uri_in == NULL ? NULL : *args->uri_in;
    dname = args->dname == NULL ? NULL : *args->dname;

    /* Wacky world of XDR ... */
    if (VIR_ALLOC(uri_out) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if (virDomainMigratePrepare(priv->conn, &cookie, &cookielen,
                                uri_in, uri_out,
                                args->flags, dname, args->resource) < 0)
        goto cleanup;

    /* remoteDispatchClientRequest will free cookie, uri_out and
     * the string if there is one.
     */
    ret->cookie.cookie_len = cookielen;
    ret->cookie.cookie_val = cookie;
    if (*uri_out == NULL) {
        ret->uri_out = NULL;
    } else {
        ret->uri_out = uri_out;
        uri_out = NULL;
    }

    rv = 0;

cleanup:
    if (rv < 0)
        virNetMessageSaveError(rerr);
    VIR_FREE(uri_out);
    return rv;
}

static int
remoteDispatchDomainMigratePrepare2(virNetServerPtr server ATTRIBUTE_UNUSED,
                                    virNetServerClientPtr client ATTRIBUTE_UNUSED,
                                    virNetMessagePtr msg ATTRIBUTE_UNUSED,
                                    virNetMessageErrorPtr rerr,
                                    remote_domain_migrate_prepare2_args *args,
                                    remote_domain_migrate_prepare2_ret *ret)
{
    char *cookie = NULL;
    int cookielen = 0;
    char *uri_in;
    char **uri_out;
    char *dname;
    int rv = -1;
    struct daemonClientPrivate *priv =
        virNetServerClientGetPrivateData(client);

    if (!priv->conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    uri_in = args->uri_in == NULL ? NULL : *args->uri_in;
    dname = args->dname == NULL ? NULL : *args->dname;

    /* Wacky world of XDR ... */
    if (VIR_ALLOC(uri_out) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if (virDomainMigratePrepare2(priv->conn, &cookie, &cookielen,
                                 uri_in, uri_out,
                                 args->flags, dname, args->resource,
                                 args->dom_xml) < 0)
        goto cleanup;

    /* remoteDispatchClientRequest will free cookie, uri_out and
     * the string if there is one.
     */
    ret->cookie.cookie_len = cookielen;
    ret->cookie.cookie_val = cookie;
    ret->uri_out = *uri_out == NULL ? NULL : uri_out;

    rv = 0;

cleanup:
    if (rv < 0)
        virNetMessageSaveError(rerr);
    return rv;
}

static int
remoteDispatchDomainGetMemoryParameters(virNetServerPtr server ATTRIBUTE_UNUSED,
                                        virNetServerClientPtr client ATTRIBUTE_UNUSED,
                                        virNetMessagePtr msg ATTRIBUTE_UNUSED,
                                        virNetMessageErrorPtr rerr,
                                        remote_domain_get_memory_parameters_args *args,
                                        remote_domain_get_memory_parameters_ret *ret)
{
    virDomainPtr dom = NULL;
    virTypedParameterPtr params = NULL;
    int nparams = args->nparams;
    unsigned int flags;
    int rv = -1;
    struct daemonClientPrivate *priv =
        virNetServerClientGetPrivateData(client);

    if (!priv->conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    flags = args->flags;

    if (nparams > REMOTE_DOMAIN_MEMORY_PARAMETERS_MAX) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("nparams too large"));
        goto cleanup;
    }
    if (VIR_ALLOC_N(params, nparams) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(priv->conn, args->dom)))
        goto cleanup;

    if (virDomainGetMemoryParameters(dom, params, &nparams, flags) < 0)
        goto cleanup;

    /* In this case, we need to send back the number of parameters
     * supported
     */
    if (args->nparams == 0) {
        ret->nparams = nparams;
        goto success;
    }

    if (remoteSerializeTypedParameters(params, nparams,
                                       &ret->params.params_val,
                                       &ret->params.params_len,
                                       args->flags) < 0)
        goto cleanup;

success:
    rv = 0;

cleanup:
    if (rv < 0)
        virNetMessageSaveError(rerr);
    virTypedParameterArrayClear(params, nparams);
    VIR_FREE(params);
    if (dom)
        virDomainFree(dom);
    return rv;
}

static int
remoteDispatchDomainGetNumaParameters(virNetServerPtr server ATTRIBUTE_UNUSED,
                                      virNetServerClientPtr client ATTRIBUTE_UNUSED,
                                      virNetMessagePtr msg ATTRIBUTE_UNUSED,
                                      virNetMessageErrorPtr rerr,
                                      remote_domain_get_numa_parameters_args *args,
                                      remote_domain_get_numa_parameters_ret *ret)
{
    virDomainPtr dom = NULL;
    virTypedParameterPtr params = NULL;
    int nparams = args->nparams;
    unsigned int flags;
    int rv = -1;
    struct daemonClientPrivate *priv =
        virNetServerClientGetPrivateData(client);

    if (!priv->conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    flags = args->flags;

    if (nparams > REMOTE_DOMAIN_NUMA_PARAMETERS_MAX) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("nparams too large"));
        goto cleanup;
    }
    if (VIR_ALLOC_N(params, nparams) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(priv->conn, args->dom)))
        goto cleanup;

    if (virDomainGetNumaParameters(dom, params, &nparams, flags) < 0)
        goto cleanup;

    /* In this case, we need to send back the number of parameters
     * supported
     */
    if (args->nparams == 0) {
        ret->nparams = nparams;
        goto success;
    }

    if (remoteSerializeTypedParameters(params, nparams,
                                       &ret->params.params_val,
                                       &ret->params.params_len,
                                       flags) < 0)
        goto cleanup;

success:
    rv = 0;

cleanup:
    if (rv < 0)
        virNetMessageSaveError(rerr);
    virTypedParameterArrayClear(params, nparams);
    VIR_FREE(params);
    if (dom)
        virDomainFree(dom);
    return rv;
}

static int
remoteDispatchDomainGetBlkioParameters(virNetServerPtr server ATTRIBUTE_UNUSED,
                                       virNetServerClientPtr client ATTRIBUTE_UNUSED,
                                       virNetMessagePtr msg ATTRIBUTE_UNUSED,
                                       virNetMessageErrorPtr rerr,
                                       remote_domain_get_blkio_parameters_args *args,
                                       remote_domain_get_blkio_parameters_ret *ret)
{
    virDomainPtr dom = NULL;
    virTypedParameterPtr params = NULL;
    int nparams = args->nparams;
    unsigned int flags;
    int rv = -1;
    struct daemonClientPrivate *priv =
        virNetServerClientGetPrivateData(client);

    if (!priv->conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    flags = args->flags;

    if (nparams > REMOTE_DOMAIN_BLKIO_PARAMETERS_MAX) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("nparams too large"));
        goto cleanup;
    }
    if (VIR_ALLOC_N(params, nparams) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(priv->conn, args->dom)))
        goto cleanup;

    if (virDomainGetBlkioParameters(dom, params, &nparams, flags) < 0)
        goto cleanup;

    /* In this case, we need to send back the number of parameters
     * supported
     */
    if (args->nparams == 0) {
        ret->nparams = nparams;
        goto success;
    }

    if (remoteSerializeTypedParameters(params, nparams,
                                       &ret->params.params_val,
                                       &ret->params.params_len,
                                       args->flags) < 0)
        goto cleanup;

success:
    rv = 0;

cleanup:
    if (rv < 0)
        virNetMessageSaveError(rerr);
    virTypedParameterArrayClear(params, nparams);
    VIR_FREE(params);
    if (dom)
        virDomainFree(dom);
    return rv;
}

static int
remoteDispatchNodeGetCPUStats(virNetServerPtr server ATTRIBUTE_UNUSED,
                              virNetServerClientPtr client ATTRIBUTE_UNUSED,
                              virNetMessagePtr msg ATTRIBUTE_UNUSED,
                              virNetMessageErrorPtr rerr,
                              remote_node_get_cpu_stats_args *args,
                              remote_node_get_cpu_stats_ret *ret)
{
    virNodeCPUStatsPtr params = NULL;
    int i;
    int cpuNum = args->cpuNum;
    int nparams = args->nparams;
    unsigned int flags;
    int rv = -1;
    struct daemonClientPrivate *priv =
        virNetServerClientGetPrivateData(client);

    if (!priv->conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    flags = args->flags;

    if (nparams > REMOTE_NODE_CPU_STATS_MAX) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("nparams too large"));
        goto cleanup;
    }
    if (VIR_ALLOC_N(params, nparams) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if (virNodeGetCPUStats(priv->conn, cpuNum, params, &nparams, flags) < 0)
        goto cleanup;

    /* In this case, we need to send back the number of stats
     * supported
     */
    if (args->nparams == 0) {
        ret->nparams = nparams;
        goto success;
    }

    /* Serialise the memory parameters. */
    ret->params.params_len = nparams;
    if (VIR_ALLOC_N(ret->params.params_val, nparams) < 0)
        goto no_memory;

    for (i = 0; i < nparams; ++i) {
        /* remoteDispatchClientRequest will free this: */
        ret->params.params_val[i].field = strdup(params[i].field);
        if (ret->params.params_val[i].field == NULL)
            goto no_memory;

        ret->params.params_val[i].value = params[i].value;
    }

success:
    rv = 0;

cleanup:
    if (rv < 0) {
        virNetMessageSaveError(rerr);
        if (ret->params.params_val) {
            for (i = 0; i < nparams; i++)
                VIR_FREE(ret->params.params_val[i].field);
            VIR_FREE(ret->params.params_val);
        }
    }
    VIR_FREE(params);
    return rv;

no_memory:
    virReportOOMError();
    goto cleanup;
}

static int
remoteDispatchNodeGetMemoryStats(virNetServerPtr server ATTRIBUTE_UNUSED,
                                 virNetServerClientPtr client ATTRIBUTE_UNUSED,
                                 virNetMessagePtr msg ATTRIBUTE_UNUSED,
                                 virNetMessageErrorPtr rerr,
                                 remote_node_get_memory_stats_args *args,
                                 remote_node_get_memory_stats_ret *ret)
{
    virNodeMemoryStatsPtr params = NULL;
    int i;
    int cellNum = args->cellNum;
    int nparams = args->nparams;
    unsigned int flags;
    int rv = -1;
    struct daemonClientPrivate *priv =
        virNetServerClientGetPrivateData(client);

    if (!priv->conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    flags = args->flags;

    if (nparams > REMOTE_NODE_MEMORY_STATS_MAX) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("nparams too large"));
        goto cleanup;
    }
    if (VIR_ALLOC_N(params, nparams) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if (virNodeGetMemoryStats(priv->conn, cellNum, params, &nparams, flags) < 0)
        goto cleanup;

    /* In this case, we need to send back the number of parameters
     * supported
     */
    if (args->nparams == 0) {
        ret->nparams = nparams;
        goto success;
    }

    /* Serialise the memory parameters. */
    ret->params.params_len = nparams;
    if (VIR_ALLOC_N(ret->params.params_val, nparams) < 0)
        goto no_memory;

    for (i = 0; i < nparams; ++i) {
        /* remoteDispatchClientRequest will free this: */
        ret->params.params_val[i].field = strdup(params[i].field);
        if (ret->params.params_val[i].field == NULL)
            goto no_memory;

        ret->params.params_val[i].value = params[i].value;
    }

success:
    rv = 0;

cleanup:
    if (rv < 0) {
        virNetMessageSaveError(rerr);
        if (ret->params.params_val) {
            for (i = 0; i < nparams; i++)
                VIR_FREE(ret->params.params_val[i].field);
            VIR_FREE(ret->params.params_val);
        }
    }
    VIR_FREE(params);
    return rv;

no_memory:
    virReportOOMError();
    goto cleanup;
}

static int
remoteDispatchDomainGetBlockJobInfo(virNetServerPtr server ATTRIBUTE_UNUSED,
                                    virNetServerClientPtr client ATTRIBUTE_UNUSED,
                                    virNetMessagePtr msg ATTRIBUTE_UNUSED,
                                    virNetMessageErrorPtr rerr,
                                    remote_domain_get_block_job_info_args *args,
                                    remote_domain_get_block_job_info_ret *ret)
{
    virDomainPtr dom = NULL;
    virDomainBlockJobInfo tmp;
    int rv = -1;
    struct daemonClientPrivate *priv =
        virNetServerClientGetPrivateData(client);

    if (!priv->conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(priv->conn, args->dom)))
        goto cleanup;

    rv = virDomainGetBlockJobInfo(dom, args->path, &tmp, args->flags);
    if (rv <= 0)
        goto cleanup;

    ret->type = tmp.type;
    ret->bandwidth = tmp.bandwidth;
    ret->cur = tmp.cur;
    ret->end = tmp.end;
    ret->found = 1;
    rv = 0;

cleanup:
    if (rv < 0)
        virNetMessageSaveError(rerr);
    if (dom)
        virDomainFree(dom);
    return rv;
}

static int
remoteDispatchDomainGetBlockIoTune(virNetServerPtr server ATTRIBUTE_UNUSED,
                                   virNetServerClientPtr client ATTRIBUTE_UNUSED,
                                   virNetMessagePtr hdr ATTRIBUTE_UNUSED,
                                   virNetMessageErrorPtr rerr,
                                   remote_domain_get_block_io_tune_args *args,
                                   remote_domain_get_block_io_tune_ret *ret)
{
    virDomainPtr dom = NULL;
    int rv = -1;
    virTypedParameterPtr params = NULL;
    int nparams = args->nparams;
    struct daemonClientPrivate *priv =
        virNetServerClientGetPrivateData(client);

    if (!priv->conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (nparams > REMOTE_DOMAIN_BLOCK_IO_TUNE_PARAMETERS_MAX) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("nparams too large"));
        goto cleanup;
    }

    if (VIR_ALLOC_N(params, nparams) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(priv->conn, args->dom)))
        goto cleanup;

    if (virDomainGetBlockIoTune(dom, args->disk ? *args->disk : NULL,
                                params, &nparams, args->flags) < 0)
        goto cleanup;

    /* In this case, we need to send back the number of parameters
     * supported
     */
    if (args->nparams == 0) {
        ret->nparams = nparams;
        goto success;
    }

    /* Serialise the block I/O tuning parameters. */
    if (remoteSerializeTypedParameters(params, nparams,
                                       &ret->params.params_val,
                                       &ret->params.params_len,
                                       args->flags) < 0)
        goto cleanup;

success:
    rv = 0;

cleanup:
    if (rv < 0)
        virNetMessageSaveError(rerr);
    virTypedParameterArrayClear(params, nparams);
    VIR_FREE(params);
    if (dom)
        virDomainFree(dom);
    return rv;
}

/*-------------------------------------------------------------*/

static int
remoteDispatchAuthList(virNetServerPtr server ATTRIBUTE_UNUSED,
                       virNetServerClientPtr client,
                       virNetMessagePtr msg ATTRIBUTE_UNUSED,
                       virNetMessageErrorPtr rerr,
                       remote_auth_list_ret *ret)
{
    int rv = -1;
    int auth = virNetServerClientGetAuth(client);
    uid_t callerUid;
    gid_t callerGid;
    pid_t callerPid;

    /* If the client is root then we want to bypass the
     * policykit auth to avoid root being denied if
     * some piece of polkit isn't present/running
     */
    if (auth == VIR_NET_SERVER_SERVICE_AUTH_POLKIT) {
        if (virNetServerClientGetUNIXIdentity(client, &callerUid, &callerGid,
                                              &callerPid) < 0) {
            /* Don't do anything on error - it'll be validated at next
             * phase of auth anyway */
            virResetLastError();
        } else if (callerUid == 0) {
            char *ident;
            if (virAsprintf(&ident, "pid:%lld,uid:%d",
                            (long long) callerPid, callerUid) < 0) {
                virReportOOMError();
                goto cleanup;
            }
            VIR_INFO("Bypass polkit auth for privileged client %s", ident);
            if (virNetServerClientSetIdentity(client, ident) < 0)
                virResetLastError();
            else
                auth = VIR_NET_SERVER_SERVICE_AUTH_NONE;
            VIR_FREE(ident);
        }
    }

    ret->types.types_len = 1;
    if (VIR_ALLOC_N(ret->types.types_val, ret->types.types_len) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    switch (auth) {
    case VIR_NET_SERVER_SERVICE_AUTH_NONE:
        ret->types.types_val[0] = REMOTE_AUTH_NONE;
        break;
    case VIR_NET_SERVER_SERVICE_AUTH_POLKIT:
        ret->types.types_val[0] = REMOTE_AUTH_POLKIT;
        break;
    case VIR_NET_SERVER_SERVICE_AUTH_SASL:
        ret->types.types_val[0] = REMOTE_AUTH_SASL;
        break;
    default:
        ret->types.types_val[0] = REMOTE_AUTH_NONE;
    }

    rv = 0;

cleanup:
    if (rv < 0)
        virNetMessageSaveError(rerr);
    return rv;
}


#ifdef HAVE_SASL
/*
 * Initializes the SASL session in prepare for authentication
 * and gives the client a list of allowed mechanisms to choose
 */
static int
remoteDispatchAuthSaslInit(virNetServerPtr server ATTRIBUTE_UNUSED,
                           virNetServerClientPtr client,
                           virNetMessagePtr msg ATTRIBUTE_UNUSED,
                           virNetMessageErrorPtr rerr,
                           remote_auth_sasl_init_ret *ret)
{
    virNetSASLSessionPtr sasl = NULL;
    struct daemonClientPrivate *priv =
        virNetServerClientGetPrivateData(client);

    virMutexLock(&priv->lock);

    VIR_DEBUG("Initialize SASL auth %d", virNetServerClientGetFD(client));
    if (virNetServerClientGetAuth(client) != VIR_NET_SERVER_SERVICE_AUTH_SASL ||
        priv->sasl != NULL) {
        VIR_ERROR(_("client tried invalid SASL init request"));
        goto authfail;
    }

    sasl = virNetSASLSessionNewServer(saslCtxt,
                                      "libvirt",
                                      virNetServerClientLocalAddrString(client),
                                      virNetServerClientRemoteAddrString(client));
    if (!sasl)
        goto authfail;

    /* Inform SASL that we've got an external SSF layer from TLS */
    if (virNetServerClientHasTLSSession(client)) {
        int ssf;

        if ((ssf = virNetServerClientGetTLSKeySize(client)) < 0)
            goto authfail;

        ssf *= 8; /* key size is bytes, sasl wants bits */

        VIR_DEBUG("Setting external SSF %d", ssf);
        if (virNetSASLSessionExtKeySize(sasl, ssf) < 0)
            goto authfail;
    }

    if (virNetServerClientIsSecure(client))
        /* If we've got TLS or UNIX domain sock, we don't care about SSF */
        virNetSASLSessionSecProps(sasl, 0, 0, true);
    else
        /* Plain TCP, better get an SSF layer */
        virNetSASLSessionSecProps(sasl,
                                  56,  /* Good enough to require kerberos */
                                  100000,  /* Arbitrary big number */
                                  false); /* No anonymous */

    if (!(ret->mechlist = virNetSASLSessionListMechanisms(sasl)))
        goto authfail;
    VIR_DEBUG("Available mechanisms for client: '%s'", ret->mechlist);

    priv->sasl = sasl;
    virMutexUnlock(&priv->lock);
    return 0;

authfail:
    virResetLastError();
    virNetError(VIR_ERR_AUTH_FAILED, "%s",
                _("authentication failed"));
    virNetMessageSaveError(rerr);
    PROBE(RPC_SERVER_CLIENT_AUTH_FAIL,
          "client=%p auth=%d",
          client, REMOTE_AUTH_SASL);
    virNetSASLSessionFree(sasl);
    virMutexUnlock(&priv->lock);
    return -1;
}

/*
 * Returns 0 if ok, -1 on error, -2 if rejected
 */
static int
remoteSASLFinish(virNetServerClientPtr client)
{
    const char *identity;
    struct daemonClientPrivate *priv = virNetServerClientGetPrivateData(client);
    int ssf;

    /* TLS or UNIX domain sockets trivially OK */
    if (!virNetServerClientIsSecure(client)) {
        if ((ssf = virNetSASLSessionGetKeySize(priv->sasl)) < 0)
            goto error;

        VIR_DEBUG("negotiated an SSF of %d", ssf);
        if (ssf < 56) { /* 56 is good for Kerberos */
            VIR_ERROR(_("negotiated SSF %d was not strong enough"), ssf);
            return -2;
        }
    }

    if (!(identity = virNetSASLSessionGetIdentity(priv->sasl)))
        return -2;

    if (!virNetSASLContextCheckIdentity(saslCtxt, identity))
        return -2;

    if (virNetServerClientSetIdentity(client, identity) < 0)
        goto error;

    virNetServerClientSetSASLSession(client, priv->sasl);

    VIR_DEBUG("Authentication successful %d", virNetServerClientGetFD(client));

    PROBE(RPC_SERVER_CLIENT_AUTH_ALLOW,
          "client=%p auth=%d identity=%s",
          client, REMOTE_AUTH_SASL, identity);

    virNetSASLSessionFree(priv->sasl);
    priv->sasl = NULL;

    return 0;

error:
    return -1;
}

/*
 * This starts the SASL authentication negotiation.
 */
static int
remoteDispatchAuthSaslStart(virNetServerPtr server ATTRIBUTE_UNUSED,
                            virNetServerClientPtr client,
                            virNetMessagePtr msg ATTRIBUTE_UNUSED,
                            virNetMessageErrorPtr rerr,
                            remote_auth_sasl_start_args *args,
                            remote_auth_sasl_start_ret *ret)
{
    const char *serverout;
    size_t serveroutlen;
    int err;
    int rv = -1;
    struct daemonClientPrivate *priv =
        virNetServerClientGetPrivateData(client);
    const char *identity;

    virMutexLock(&priv->lock);

    VIR_DEBUG("Start SASL auth %d", virNetServerClientGetFD(client));
    if (virNetServerClientGetAuth(client) != VIR_NET_SERVER_SERVICE_AUTH_SASL ||
        priv->sasl == NULL) {
        VIR_ERROR(_("client tried invalid SASL start request"));
        goto authfail;
    }

    VIR_DEBUG("Using SASL mechanism %s. Data %d bytes, nil: %d",
              args->mech, args->data.data_len, args->nil);
    err = virNetSASLSessionServerStart(priv->sasl,
                                       args->mech,
                                       /* NB, distinction of NULL vs "" is *critical* in SASL */
                                       args->nil ? NULL : args->data.data_val,
                                       args->data.data_len,
                                       &serverout,
                                       &serveroutlen);
    if (err != VIR_NET_SASL_COMPLETE &&
        err != VIR_NET_SASL_CONTINUE)
        goto authfail;

    if (serveroutlen > REMOTE_AUTH_SASL_DATA_MAX) {
        VIR_ERROR(_("sasl start reply data too long %d"), (int)serveroutlen);
        goto authfail;
    }

    /* NB, distinction of NULL vs "" is *critical* in SASL */
    if (serverout) {
        if (VIR_ALLOC_N(ret->data.data_val, serveroutlen) < 0)
            goto authfail;
        memcpy(ret->data.data_val, serverout, serveroutlen);
    } else {
        ret->data.data_val = NULL;
    }
    ret->nil = serverout ? 0 : 1;
    ret->data.data_len = serveroutlen;

    VIR_DEBUG("SASL return data %d bytes, nil; %d", ret->data.data_len, ret->nil);
    if (err == VIR_NET_SASL_CONTINUE) {
        ret->complete = 0;
    } else {
        /* Check username whitelist ACL */
        if ((err = remoteSASLFinish(client)) < 0) {
            if (err == -2)
                goto authdeny;
            else
                goto authfail;
        }

        ret->complete = 1;
    }

    virMutexUnlock(&priv->lock);
    return 0;

authfail:
    PROBE(RPC_SERVER_CLIENT_AUTH_FAIL,
          "client=%p auth=%d",
          client, REMOTE_AUTH_SASL);
    goto error;

authdeny:
    identity = virNetSASLSessionGetIdentity(priv->sasl);
    PROBE(RPC_SERVER_CLIENT_AUTH_DENY,
          "client=%p auth=%d identity=%s",
          client, REMOTE_AUTH_SASL, identity);
    goto error;

error:
    virNetSASLSessionFree(priv->sasl);
    priv->sasl = NULL;
    virResetLastError();
    virNetError(VIR_ERR_AUTH_FAILED, "%s",
                _("authentication failed"));
    if (rv < 0)
        virNetMessageSaveError(rerr);
    virMutexUnlock(&priv->lock);
    return -1;
}


static int
remoteDispatchAuthSaslStep(virNetServerPtr server ATTRIBUTE_UNUSED,
                           virNetServerClientPtr client,
                           virNetMessagePtr msg ATTRIBUTE_UNUSED,
                           virNetMessageErrorPtr rerr,
                           remote_auth_sasl_step_args *args,
                           remote_auth_sasl_step_ret *ret)
{
    const char *serverout;
    size_t serveroutlen;
    int err;
    int rv = -1;
    struct daemonClientPrivate *priv =
        virNetServerClientGetPrivateData(client);
    const char *identity;

    virMutexLock(&priv->lock);

    VIR_DEBUG("Step SASL auth %d", virNetServerClientGetFD(client));
    if (virNetServerClientGetAuth(client) != VIR_NET_SERVER_SERVICE_AUTH_SASL ||
        priv->sasl == NULL) {
        VIR_ERROR(_("client tried invalid SASL start request"));
        goto authfail;
    }

    VIR_DEBUG("Step using SASL Data %d bytes, nil: %d",
              args->data.data_len, args->nil);
    err = virNetSASLSessionServerStep(priv->sasl,
                                      /* NB, distinction of NULL vs "" is *critical* in SASL */
                                      args->nil ? NULL : args->data.data_val,
                                      args->data.data_len,
                                      &serverout,
                                      &serveroutlen);
    if (err != VIR_NET_SASL_COMPLETE &&
        err != VIR_NET_SASL_CONTINUE)
        goto authfail;

    if (serveroutlen > REMOTE_AUTH_SASL_DATA_MAX) {
        VIR_ERROR(_("sasl step reply data too long %d"),
                  (int)serveroutlen);
        goto authfail;
    }

    /* NB, distinction of NULL vs "" is *critical* in SASL */
    if (serverout) {
        if (VIR_ALLOC_N(ret->data.data_val, serveroutlen) < 0)
            goto authfail;
        memcpy(ret->data.data_val, serverout, serveroutlen);
    } else {
        ret->data.data_val = NULL;
    }
    ret->nil = serverout ? 0 : 1;
    ret->data.data_len = serveroutlen;

    VIR_DEBUG("SASL return data %d bytes, nil; %d", ret->data.data_len, ret->nil);
    if (err == VIR_NET_SASL_CONTINUE) {
        ret->complete = 0;
    } else {
        /* Check username whitelist ACL */
        if ((err = remoteSASLFinish(client)) < 0) {
            if (err == -2)
                goto authdeny;
            else
                goto authfail;
        }

        ret->complete = 1;
    }

    virMutexUnlock(&priv->lock);
    return 0;

authfail:
    PROBE(RPC_SERVER_CLIENT_AUTH_FAIL,
          "client=%p auth=%d",
          client, REMOTE_AUTH_SASL);
    goto error;

authdeny:
    identity = virNetSASLSessionGetIdentity(priv->sasl);
    PROBE(RPC_SERVER_CLIENT_AUTH_DENY,
          "client=%p auth=%d identity=%s",
          client, REMOTE_AUTH_SASL, identity);
    goto error;

error:
    virNetSASLSessionFree(priv->sasl);
    priv->sasl = NULL;
    virResetLastError();
    virNetError(VIR_ERR_AUTH_FAILED, "%s",
                _("authentication failed"));
    if (rv < 0)
        virNetMessageSaveError(rerr);
    virMutexUnlock(&priv->lock);
    return -1;
}
#else
static int
remoteDispatchAuthSaslInit(virNetServerPtr server ATTRIBUTE_UNUSED,
                           virNetServerClientPtr client ATTRIBUTE_UNUSED,
                           virNetMessagePtr msg ATTRIBUTE_UNUSED,
                           virNetMessageErrorPtr rerr,
                           remote_auth_sasl_init_ret *ret ATTRIBUTE_UNUSED)
{
    VIR_WARN("Client tried unsupported SASL auth");
    virNetError(VIR_ERR_AUTH_FAILED, "%s",
                _("authentication failed"));
    virNetMessageSaveError(rerr);
    return -1;
}
static int
remoteDispatchAuthSaslStart(virNetServerPtr server ATTRIBUTE_UNUSED,
                            virNetServerClientPtr client ATTRIBUTE_UNUSED,
                            virNetMessagePtr msg ATTRIBUTE_UNUSED,
                            virNetMessageErrorPtr rerr,
                            remote_auth_sasl_start_args *args ATTRIBUTE_UNUSED,
                            remote_auth_sasl_start_ret *ret ATTRIBUTE_UNUSED)
{
    VIR_WARN("Client tried unsupported SASL auth");
    virNetError(VIR_ERR_AUTH_FAILED, "%s",
                _("authentication failed"));
    virNetMessageSaveError(rerr);
    return -1;
}
static int
remoteDispatchAuthSaslStep(virNetServerPtr server ATTRIBUTE_UNUSED,
                           virNetServerClientPtr client ATTRIBUTE_UNUSED,
                           virNetMessagePtr msg ATTRIBUTE_UNUSED,
                           virNetMessageErrorPtr rerr,
                           remote_auth_sasl_step_args *args ATTRIBUTE_UNUSED,
                           remote_auth_sasl_step_ret *ret ATTRIBUTE_UNUSED)
{
    VIR_WARN("Client tried unsupported SASL auth");
    virNetError(VIR_ERR_AUTH_FAILED, "%s",
                _("authentication failed"));
    virNetMessageSaveError(rerr);
    return -1;
}
#endif



#if HAVE_POLKIT1
static int
remoteDispatchAuthPolkit(virNetServerPtr server ATTRIBUTE_UNUSED,
                         virNetServerClientPtr client,
                         virNetMessagePtr msg ATTRIBUTE_UNUSED,
                         virNetMessageErrorPtr rerr,
                         remote_auth_polkit_ret *ret)
{
    pid_t callerPid = -1;
    gid_t callerGid = -1;
    uid_t callerUid = -1;
    const char *action;
    int status = -1;
    char *ident = NULL;
    bool authdismissed = 0;
    char *pkout = NULL;
    struct daemonClientPrivate *priv =
        virNetServerClientGetPrivateData(client);
    virCommandPtr cmd = NULL;

    virMutexLock(&priv->lock);
    action = virNetServerClientGetReadonly(client) ?
        "org.libvirt.unix.monitor" :
        "org.libvirt.unix.manage";

    cmd = virCommandNewArgList(PKCHECK_PATH, "--action-id", action, NULL);
    virCommandSetOutputBuffer(cmd, &pkout);
    virCommandSetErrorBuffer(cmd, &pkout);

    VIR_DEBUG("Start PolicyKit auth %d", virNetServerClientGetFD(client));
    if (virNetServerClientGetAuth(client) != VIR_NET_SERVER_SERVICE_AUTH_POLKIT) {
        VIR_ERROR(_("client tried invalid PolicyKit init request"));
        goto authfail;
    }

    if (virNetServerClientGetUNIXIdentity(client, &callerUid, &callerGid,
                                          &callerPid) < 0) {
        goto authfail;
    }

    VIR_INFO("Checking PID %lld running as %d",
             (long long) callerPid, callerUid);

    virCommandAddArg(cmd, "--process");
    virCommandAddArgFormat(cmd, "%lld", (long long) callerPid);
    virCommandAddArg(cmd, "--allow-user-interaction");

    if (virAsprintf(&ident, "pid:%lld,uid:%d",
                    (long long) callerPid, callerUid) < 0) {
        virReportOOMError();
        goto authfail;
    }

    if (virCommandRun(cmd, &status) < 0)
        goto authfail;

    authdismissed = (pkout && strstr(pkout, "dismissed=true"));
    if (status != 0) {
        char *tmp = virCommandTranslateStatus(status);
        VIR_ERROR(_("Policy kit denied action %s from pid %lld, uid %d: %s"),
                  action, (long long) callerPid, callerUid, NULLSTR(tmp));
        VIR_FREE(tmp);
        goto authdeny;
    }
    PROBE(RPC_SERVER_CLIENT_AUTH_ALLOW,
          "client=%p auth=%d identity=%s",
          client, REMOTE_AUTH_POLKIT, ident);
    VIR_INFO("Policy allowed action %s from pid %lld, uid %d",
             action, (long long) callerPid, callerUid);
    ret->complete = 1;

    virNetServerClientSetIdentity(client, ident);
    virMutexUnlock(&priv->lock);
    virCommandFree(cmd);
    VIR_FREE(pkout);
    VIR_FREE(ident);

    return 0;

error:
    virCommandFree(cmd);
    VIR_FREE(ident);
    virResetLastError();

    if (authdismissed) {
        virNetError(VIR_ERR_AUTH_CANCELLED, "%s",
                    _("authentication cancelled by user"));
    } else {
        virNetError(VIR_ERR_AUTH_FAILED, "%s",
                    pkout && *pkout ? pkout : _("authentication failed"));
    }

    VIR_FREE(pkout);
    virNetMessageSaveError(rerr);
    virMutexUnlock(&priv->lock);
    return -1;

authfail:
    PROBE(RPC_SERVER_CLIENT_AUTH_FAIL,
          "client=%p auth=%d",
          client, REMOTE_AUTH_POLKIT);
    goto error;

authdeny:
    PROBE(RPC_SERVER_CLIENT_AUTH_DENY,
          "client=%p auth=%d identity=%s",
          client, REMOTE_AUTH_POLKIT, ident);
    goto error;
}
#elif HAVE_POLKIT0
static int
remoteDispatchAuthPolkit(virNetServerPtr server,
                         virNetServerClientPtr client,
                         virNetMessagePtr msg ATTRIBUTE_UNUSED,
                         virNetMessageErrorPtr rerr,
                         remote_auth_polkit_ret *ret)
{
    pid_t callerPid;
    gid_t callerGid;
    uid_t callerUid;
    PolKitCaller *pkcaller = NULL;
    PolKitAction *pkaction = NULL;
    PolKitContext *pkcontext = NULL;
    PolKitError *pkerr = NULL;
    PolKitResult pkresult;
    DBusError err;
    const char *action;
    char *ident = NULL;
    struct daemonClientPrivate *priv =
        virNetServerClientGetPrivateData(client);

    virMutexLock(&priv->lock);

    action = virNetServerClientGetReadonly(client) ?
        "org.libvirt.unix.monitor" :
        "org.libvirt.unix.manage";

    VIR_DEBUG("Start PolicyKit auth %d", virNetServerClientGetFD(client));
    if (virNetServerClientGetAuth(client) != VIR_NET_SERVER_SERVICE_AUTH_POLKIT) {
        VIR_ERROR(_("client tried invalid PolicyKit init request"));
        goto authfail;
    }

    if (virNetServerClientGetUNIXIdentity(client, &callerUid, &callerGid,
                                          &callerPid) < 0) {
        VIR_ERROR(_("cannot get peer socket identity"));
        goto authfail;
    }

    if (virAsprintf(&ident, "pid:%lld,uid:%d",
                    (long long) callerPid, callerUid) < 0) {
        virReportOOMError();
        goto authfail;
    }

    VIR_INFO("Checking PID %lld running as %d",
             (long long) callerPid, callerUid);
    dbus_error_init(&err);
    if (!(pkcaller = polkit_caller_new_from_pid(virNetServerGetDBusConn(server),
                                                callerPid, &err))) {
        VIR_ERROR(_("Failed to lookup policy kit caller: %s"), err.message);
        dbus_error_free(&err);
        goto authfail;
    }

    if (!(pkaction = polkit_action_new())) {
        char ebuf[1024];
        VIR_ERROR(_("Failed to create polkit action %s"),
                  virStrerror(errno, ebuf, sizeof(ebuf)));
        polkit_caller_unref(pkcaller);
        goto authfail;
    }
    polkit_action_set_action_id(pkaction, action);

    if (!(pkcontext = polkit_context_new()) ||
        !polkit_context_init(pkcontext, &pkerr)) {
        char ebuf[1024];
        VIR_ERROR(_("Failed to create polkit context %s"),
                  (pkerr ? polkit_error_get_error_message(pkerr)
                   : virStrerror(errno, ebuf, sizeof(ebuf))));
        if (pkerr)
            polkit_error_free(pkerr);
        polkit_caller_unref(pkcaller);
        polkit_action_unref(pkaction);
        dbus_error_free(&err);
        goto authfail;
    }

# if HAVE_POLKIT_CONTEXT_IS_CALLER_AUTHORIZED
    pkresult = polkit_context_is_caller_authorized(pkcontext,
                                                   pkaction,
                                                   pkcaller,
                                                   0,
                                                   &pkerr);
    if (pkerr && polkit_error_is_set(pkerr)) {
        VIR_ERROR(_("Policy kit failed to check authorization %d %s"),
                  polkit_error_get_error_code(pkerr),
                  polkit_error_get_error_message(pkerr));
        goto authfail;
    }
# else
    pkresult = polkit_context_can_caller_do_action(pkcontext,
                                                   pkaction,
                                                   pkcaller);
# endif
    polkit_context_unref(pkcontext);
    polkit_caller_unref(pkcaller);
    polkit_action_unref(pkaction);
    if (pkresult != POLKIT_RESULT_YES) {
        VIR_ERROR(_("Policy kit denied action %s from pid %lld, uid %d, result: %s"),
                  action, (long long) callerPid, callerUid,
                  polkit_result_to_string_representation(pkresult));
        goto authdeny;
    }
    PROBE(RPC_SERVER_CLIENT_AUTH_ALLOW,
          "client=%p auth=%d identity=%s",
          client, REMOTE_AUTH_POLKIT, ident);
    VIR_INFO("Policy allowed action %s from pid %lld, uid %d, result %s",
             action, (long long) callerPid, callerUid,
             polkit_result_to_string_representation(pkresult));
    ret->complete = 1;
    virNetServerClientSetIdentity(client, ident);

    virMutexUnlock(&priv->lock);
    VIR_FREE(ident);
    return 0;

error:
    VIR_FREE(ident);
    virResetLastError();
    virNetError(VIR_ERR_AUTH_FAILED, "%s",
                _("authentication failed"));
    virNetMessageSaveError(rerr);
    virMutexUnlock(&priv->lock);
    return -1;

authfail:
    PROBE(RPC_SERVER_CLIENT_AUTH_FAIL,
          "client=%p auth=%d",
          client, REMOTE_AUTH_POLKIT);
    goto error;

authdeny:
    PROBE(RPC_SERVER_CLIENT_AUTH_DENY,
          "client=%p auth=%d identity=%s",
          client, REMOTE_AUTH_POLKIT, ident);
    goto error;
}

#else /* !HAVE_POLKIT0 & !HAVE_POLKIT1*/

static int
remoteDispatchAuthPolkit(virNetServerPtr server ATTRIBUTE_UNUSED,
                         virNetServerClientPtr client ATTRIBUTE_UNUSED,
                         virNetMessagePtr msg ATTRIBUTE_UNUSED,
                         virNetMessageErrorPtr rerr,
                         remote_auth_polkit_ret *ret ATTRIBUTE_UNUSED)
{
    VIR_ERROR(_("client tried unsupported PolicyKit init request"));
    virNetError(VIR_ERR_AUTH_FAILED, "%s",
                _("authentication failed"));
    virNetMessageSaveError(rerr);
    return -1;
}
#endif /* HAVE_POLKIT1 */


/***************************************************************
 *     NODE INFO APIS
 **************************************************************/

static int
remoteDispatchNodeDeviceGetParent(virNetServerPtr server ATTRIBUTE_UNUSED,
                                  virNetServerClientPtr client ATTRIBUTE_UNUSED,
                                  virNetMessagePtr msg ATTRIBUTE_UNUSED,
                                  virNetMessageErrorPtr rerr,
                                  remote_node_device_get_parent_args *args,
                                  remote_node_device_get_parent_ret *ret)
{
    virNodeDevicePtr dev = NULL;
    const char *parent = NULL;
    int rv = -1;
    struct daemonClientPrivate *priv =
        virNetServerClientGetPrivateData(client);

    if (!priv->conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dev = virNodeDeviceLookupByName(priv->conn, args->name)))
        goto cleanup;

    parent = virNodeDeviceGetParent(dev);

    if (parent == NULL) {
        ret->parent = NULL;
    } else {
        /* remoteDispatchClientRequest will free this. */
        char **parent_p;
        if (VIR_ALLOC(parent_p) < 0) {
            virReportOOMError();
            goto cleanup;
        }
        if (!(*parent_p = strdup(parent))) {
            VIR_FREE(parent_p);
            virReportOOMError();
            goto cleanup;
        }
        ret->parent = parent_p;
    }

    rv = 0;

cleanup:
    if (rv < 0)
        virNetMessageSaveError(rerr);
    if (dev)
        virNodeDeviceFree(dev);
    return rv;
}


/***************************
 * Register / deregister events
 ***************************/
static int
remoteDispatchDomainEventsRegister(virNetServerPtr server ATTRIBUTE_UNUSED,
                                   virNetServerClientPtr client ATTRIBUTE_UNUSED,
                                   virNetMessagePtr msg ATTRIBUTE_UNUSED,
                                   virNetMessageErrorPtr rerr ATTRIBUTE_UNUSED,
                                   remote_domain_events_register_ret *ret ATTRIBUTE_UNUSED)
{
    int callbackID;
    int rv = -1;
    struct daemonClientPrivate *priv =
        virNetServerClientGetPrivateData(client);

    if (!priv->conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    virMutexLock(&priv->lock);

    if (priv->domainEventCallbackID[VIR_DOMAIN_EVENT_ID_LIFECYCLE] != -1) {
        virNetError(VIR_ERR_INTERNAL_ERROR, _("domain event %d already registered"), VIR_DOMAIN_EVENT_ID_LIFECYCLE);
        goto cleanup;
    }

    if ((callbackID = virConnectDomainEventRegisterAny(priv->conn,
                                                       NULL,
                                                       VIR_DOMAIN_EVENT_ID_LIFECYCLE,
                                                       VIR_DOMAIN_EVENT_CALLBACK(remoteRelayDomainEventLifecycle),
                                                       client, NULL)) < 0)
        goto cleanup;

    priv->domainEventCallbackID[VIR_DOMAIN_EVENT_ID_LIFECYCLE] = callbackID;

    rv = 0;

cleanup:
    if (rv < 0)
        virNetMessageSaveError(rerr);
    virMutexUnlock(&priv->lock);
    return rv;
}

static int
remoteDispatchDomainEventsDeregister(virNetServerPtr server ATTRIBUTE_UNUSED,
                                     virNetServerClientPtr client ATTRIBUTE_UNUSED,
                                     virNetMessagePtr msg ATTRIBUTE_UNUSED,
                                     virNetMessageErrorPtr rerr ATTRIBUTE_UNUSED,
                                     remote_domain_events_deregister_ret *ret ATTRIBUTE_UNUSED)
{
    int rv = -1;
    struct daemonClientPrivate *priv =
        virNetServerClientGetPrivateData(client);

    if (!priv->conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    virMutexLock(&priv->lock);

    if (priv->domainEventCallbackID[VIR_DOMAIN_EVENT_ID_LIFECYCLE] < 0) {
        virNetError(VIR_ERR_INTERNAL_ERROR, _("domain event %d not registered"), VIR_DOMAIN_EVENT_ID_LIFECYCLE);
        goto cleanup;
    }

    if (virConnectDomainEventDeregisterAny(priv->conn,
                                           priv->domainEventCallbackID[VIR_DOMAIN_EVENT_ID_LIFECYCLE]) < 0)
        goto cleanup;

    priv->domainEventCallbackID[VIR_DOMAIN_EVENT_ID_LIFECYCLE] = -1;

    rv = 0;

cleanup:
    if (rv < 0)
        virNetMessageSaveError(rerr);
    virMutexUnlock(&priv->lock);
    return rv;
}

static void
remoteDispatchDomainEventSend(virNetServerClientPtr client,
                              virNetServerProgramPtr program,
                              int procnr,
                              xdrproc_t proc,
                              void *data)
{
    virNetMessagePtr msg;

    if (!(msg = virNetMessageNew(false)))
        goto cleanup;

    msg->header.prog = virNetServerProgramGetID(program);
    msg->header.vers = virNetServerProgramGetVersion(program);
    msg->header.proc = procnr;
    msg->header.type = VIR_NET_MESSAGE;
    msg->header.serial = 1;
    msg->header.status = VIR_NET_OK;

    if (virNetMessageEncodeHeader(msg) < 0)
        goto cleanup;

    if (virNetMessageEncodePayload(msg, proc, data) < 0)
        goto cleanup;

    VIR_DEBUG("Queue event %d %zu", procnr, msg->bufferLength);
    virNetServerClientSendMessage(client, msg);

    xdr_free(proc, data);
    return;

cleanup:
    virNetMessageFree(msg);
    xdr_free(proc, data);
}

static int
remoteDispatchSecretGetValue(virNetServerPtr server ATTRIBUTE_UNUSED,
                             virNetServerClientPtr client ATTRIBUTE_UNUSED,
                             virNetMessagePtr msg ATTRIBUTE_UNUSED,
                             virNetMessageErrorPtr rerr,
                             remote_secret_get_value_args *args,
                             remote_secret_get_value_ret *ret)
{
    virSecretPtr secret = NULL;
    size_t value_size;
    unsigned char *value;
    int rv = -1;
    struct daemonClientPrivate *priv =
        virNetServerClientGetPrivateData(client);

    if (!priv->conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(secret = get_nonnull_secret(priv->conn, args->secret)))
        goto cleanup;

    if (!(value = virSecretGetValue(secret, &value_size, args->flags)))
        goto cleanup;

    ret->value.value_len = value_size;
    ret->value.value_val = (char *)value;

    rv = 0;

cleanup:
    if (rv < 0)
        virNetMessageSaveError(rerr);
    if (secret)
        virSecretFree(secret);
    return rv;
}

static int
remoteDispatchDomainGetState(virNetServerPtr server ATTRIBUTE_UNUSED,
                             virNetServerClientPtr client ATTRIBUTE_UNUSED,
                             virNetMessagePtr msg ATTRIBUTE_UNUSED,
                             virNetMessageErrorPtr rerr,
                             remote_domain_get_state_args *args,
                             remote_domain_get_state_ret *ret)
{
    virDomainPtr dom = NULL;
    int rv = -1;
    struct daemonClientPrivate *priv =
        virNetServerClientGetPrivateData(client);

    if (!priv->conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(priv->conn, args->dom)))
        goto cleanup;

    if (virDomainGetState(dom, &ret->state, &ret->reason, args->flags) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        virNetMessageSaveError(rerr);
    if (dom)
        virDomainFree(dom);
    return rv;
}

static int
remoteDispatchDomainEventsRegisterAny(virNetServerPtr server ATTRIBUTE_UNUSED,
                                      virNetServerClientPtr client ATTRIBUTE_UNUSED,
                                      virNetMessagePtr msg ATTRIBUTE_UNUSED,
                                      virNetMessageErrorPtr rerr ATTRIBUTE_UNUSED,
                                      remote_domain_events_register_any_args *args)
{
    int callbackID;
    int rv = -1;
    struct daemonClientPrivate *priv =
        virNetServerClientGetPrivateData(client);

    if (!priv->conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    virMutexLock(&priv->lock);

    if (args->eventID >= VIR_DOMAIN_EVENT_ID_LAST ||
        args->eventID < 0) {
        virNetError(VIR_ERR_INTERNAL_ERROR, _("unsupported event ID %d"), args->eventID);
        goto cleanup;
    }

    if (priv->domainEventCallbackID[args->eventID] != -1)  {
        virNetError(VIR_ERR_INTERNAL_ERROR, _("domain event %d already registered"), args->eventID);
        goto cleanup;
    }

    if ((callbackID = virConnectDomainEventRegisterAny(priv->conn,
                                                       NULL,
                                                       args->eventID,
                                                       domainEventCallbacks[args->eventID],
                                                       client, NULL)) < 0)
        goto cleanup;

    priv->domainEventCallbackID[args->eventID] = callbackID;

    rv = 0;

cleanup:
    if (rv < 0)
        virNetMessageSaveError(rerr);
    virMutexUnlock(&priv->lock);
    return rv;
}


static int
remoteDispatchDomainEventsDeregisterAny(virNetServerPtr server ATTRIBUTE_UNUSED,
                                        virNetServerClientPtr client ATTRIBUTE_UNUSED,
                                        virNetMessagePtr msg ATTRIBUTE_UNUSED,
                                        virNetMessageErrorPtr rerr ATTRIBUTE_UNUSED,
                                        remote_domain_events_deregister_any_args *args)
{
    int callbackID = -1;
    int rv = -1;
    struct daemonClientPrivate *priv =
        virNetServerClientGetPrivateData(client);

    if (!priv->conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    virMutexLock(&priv->lock);

    if (args->eventID >= VIR_DOMAIN_EVENT_ID_LAST ||
        args->eventID < 0) {
        virNetError(VIR_ERR_INTERNAL_ERROR, _("unsupported event ID %d"), args->eventID);
        goto cleanup;
    }

    callbackID = priv->domainEventCallbackID[args->eventID];
    if (callbackID < 0) {
        virNetError(VIR_ERR_INTERNAL_ERROR, _("domain event %d not registered"), args->eventID);
        goto cleanup;
    }

    if (virConnectDomainEventDeregisterAny(priv->conn, callbackID) < 0)
        goto cleanup;

    priv->domainEventCallbackID[args->eventID] = -1;

    rv = 0;

cleanup:
    if (rv < 0)
        virNetMessageSaveError(rerr);
    virMutexUnlock(&priv->lock);
    return rv;
}

static int
qemuDispatchMonitorCommand(virNetServerPtr server ATTRIBUTE_UNUSED,
                           virNetServerClientPtr client ATTRIBUTE_UNUSED,
                           virNetMessagePtr msg ATTRIBUTE_UNUSED,
                           virNetMessageErrorPtr rerr,
                           qemu_monitor_command_args *args,
                           qemu_monitor_command_ret *ret)
{
    virDomainPtr dom = NULL;
    int rv = -1;
    struct daemonClientPrivate *priv =
        virNetServerClientGetPrivateData(client);

    if (!priv->conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(priv->conn, args->dom)))
        goto cleanup;

    if (virDomainQemuMonitorCommand(dom, args->cmd, &ret->result,
                                    args->flags) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        virNetMessageSaveError(rerr);
    if (dom)
        virDomainFree(dom);
    return rv;
}


static int
remoteDispatchDomainMigrateBegin3(virNetServerPtr server ATTRIBUTE_UNUSED,
                                  virNetServerClientPtr client ATTRIBUTE_UNUSED,
                                  virNetMessagePtr msg ATTRIBUTE_UNUSED,
                                  virNetMessageErrorPtr rerr,
                                  remote_domain_migrate_begin3_args *args,
                                  remote_domain_migrate_begin3_ret *ret)
{
    char *xml = NULL;
    virDomainPtr dom = NULL;
    char *dname;
    char *xmlin;
    char *cookieout = NULL;
    int cookieoutlen = 0;
    int rv = -1;
    struct daemonClientPrivate *priv =
        virNetServerClientGetPrivateData(client);

    if (!priv->conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(priv->conn, args->dom)))
        goto cleanup;

    xmlin = args->xmlin == NULL ? NULL : *args->xmlin;
    dname = args->dname == NULL ? NULL : *args->dname;

    if (!(xml = virDomainMigrateBegin3(dom, xmlin,
                                       &cookieout, &cookieoutlen,
                                       args->flags, dname, args->resource)))
        goto cleanup;

    /* remoteDispatchClientRequest will free cookie and
     * the xml string if there is one.
     */
    ret->cookie_out.cookie_out_len = cookieoutlen;
    ret->cookie_out.cookie_out_val = cookieout;
    ret->xml = xml;

    rv = 0;

cleanup:
    if (rv < 0)
        virNetMessageSaveError(rerr);
    if (dom)
        virDomainFree(dom);
    return rv;
}


static int
remoteDispatchDomainMigratePrepare3(virNetServerPtr server ATTRIBUTE_UNUSED,
                                    virNetServerClientPtr client ATTRIBUTE_UNUSED,
                                    virNetMessagePtr msg ATTRIBUTE_UNUSED,
                                    virNetMessageErrorPtr rerr,
                                    remote_domain_migrate_prepare3_args *args,
                                    remote_domain_migrate_prepare3_ret *ret)
{
    char *cookieout = NULL;
    int cookieoutlen = 0;
    char *uri_in;
    char **uri_out;
    char *dname;
    int rv = -1;
    struct daemonClientPrivate *priv =
        virNetServerClientGetPrivateData(client);

    if (!priv->conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    uri_in = args->uri_in == NULL ? NULL : *args->uri_in;
    dname = args->dname == NULL ? NULL : *args->dname;

    /* Wacky world of XDR ... */
    if (VIR_ALLOC(uri_out) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if (virDomainMigratePrepare3(priv->conn,
                                 args->cookie_in.cookie_in_val,
                                 args->cookie_in.cookie_in_len,
                                 &cookieout, &cookieoutlen,
                                 uri_in, uri_out,
                                 args->flags, dname, args->resource,
                                 args->dom_xml) < 0)
        goto cleanup;

    /* remoteDispatchClientRequest will free cookie, uri_out and
     * the string if there is one.
     */
    ret->cookie_out.cookie_out_len = cookieoutlen;
    ret->cookie_out.cookie_out_val = cookieout;
    ret->uri_out = *uri_out == NULL ? NULL : uri_out;

    rv = 0;

cleanup:
    if (rv < 0) {
        virNetMessageSaveError(rerr);
        VIR_FREE(uri_out);
    }
    return rv;
}


static int
remoteDispatchDomainMigratePerform3(virNetServerPtr server ATTRIBUTE_UNUSED,
                                    virNetServerClientPtr client ATTRIBUTE_UNUSED,
                                    virNetMessagePtr msg ATTRIBUTE_UNUSED,
                                    virNetMessageErrorPtr rerr,
                                    remote_domain_migrate_perform3_args *args,
                                    remote_domain_migrate_perform3_ret *ret)
{
    virDomainPtr dom = NULL;
    char *xmlin;
    char *dname;
    char *uri;
    char *dconnuri;
    char *cookieout = NULL;
    int cookieoutlen = 0;
    int rv = -1;
    struct daemonClientPrivate *priv =
        virNetServerClientGetPrivateData(client);

    if (!priv->conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(priv->conn, args->dom)))
        goto cleanup;

    xmlin = args->xmlin == NULL ? NULL : *args->xmlin;
    dname = args->dname == NULL ? NULL : *args->dname;
    uri = args->uri == NULL ? NULL : *args->uri;
    dconnuri = args->dconnuri == NULL ? NULL : *args->dconnuri;

    if (virDomainMigratePerform3(dom, xmlin,
                                 args->cookie_in.cookie_in_val,
                                 args->cookie_in.cookie_in_len,
                                 &cookieout, &cookieoutlen,
                                 dconnuri, uri,
                                 args->flags, dname, args->resource) < 0)
        goto cleanup;

    /* remoteDispatchClientRequest will free cookie
     */
    ret->cookie_out.cookie_out_len = cookieoutlen;
    ret->cookie_out.cookie_out_val = cookieout;

    rv = 0;

cleanup:
    if (rv < 0)
        virNetMessageSaveError(rerr);
    if (dom)
        virDomainFree(dom);
    return rv;
}


static int
remoteDispatchDomainMigrateFinish3(virNetServerPtr server ATTRIBUTE_UNUSED,
                                   virNetServerClientPtr client ATTRIBUTE_UNUSED,
                                   virNetMessagePtr msg ATTRIBUTE_UNUSED,
                                   virNetMessageErrorPtr rerr,
                                   remote_domain_migrate_finish3_args *args,
                                   remote_domain_migrate_finish3_ret *ret)
{
    virDomainPtr dom = NULL;
    char *cookieout = NULL;
    int cookieoutlen = 0;
    char *uri;
    char *dconnuri;
    int rv = -1;
    struct daemonClientPrivate *priv =
        virNetServerClientGetPrivateData(client);

    if (!priv->conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    uri = args->uri == NULL ? NULL : *args->uri;
    dconnuri = args->dconnuri == NULL ? NULL : *args->dconnuri;

    if (!(dom = virDomainMigrateFinish3(priv->conn, args->dname,
                                        args->cookie_in.cookie_in_val,
                                        args->cookie_in.cookie_in_len,
                                        &cookieout, &cookieoutlen,
                                        dconnuri, uri,
                                        args->flags,
                                        args->cancelled)))
        goto cleanup;

    make_nonnull_domain(&ret->dom, dom);

    /* remoteDispatchClientRequest will free cookie
     */
    ret->cookie_out.cookie_out_len = cookieoutlen;
    ret->cookie_out.cookie_out_val = cookieout;

    rv = 0;

cleanup:
    if (rv < 0) {
        virNetMessageSaveError(rerr);
        VIR_FREE(cookieout);
    }
    if (dom)
        virDomainFree(dom);
    return rv;
}


static int
remoteDispatchDomainMigrateConfirm3(virNetServerPtr server ATTRIBUTE_UNUSED,
                                    virNetServerClientPtr client ATTRIBUTE_UNUSED,
                                    virNetMessagePtr msg ATTRIBUTE_UNUSED,
                                    virNetMessageErrorPtr rerr,
                                    remote_domain_migrate_confirm3_args *args)
{
    virDomainPtr dom = NULL;
    int rv = -1;
    struct daemonClientPrivate *priv =
        virNetServerClientGetPrivateData(client);

    if (!priv->conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(priv->conn, args->dom)))
        goto cleanup;

    if (virDomainMigrateConfirm3(dom,
                                 args->cookie_in.cookie_in_val,
                                 args->cookie_in.cookie_in_len,
                                 args->flags, args->cancelled) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        virNetMessageSaveError(rerr);
    if (dom)
        virDomainFree(dom);
    return rv;
}


static int remoteDispatchSupportsFeature(
    virNetServerPtr server ATTRIBUTE_UNUSED,
    virNetServerClientPtr client,
    virNetMessagePtr msg ATTRIBUTE_UNUSED,
    virNetMessageErrorPtr rerr,
    remote_supports_feature_args *args,
    remote_supports_feature_ret *ret)
{
    int rv = -1;
    int supported;
    struct daemonClientPrivate *priv =
        virNetServerClientGetPrivateData(client);

    /* This feature is checked before opening the connection, thus we must
     * check it first.
     */
    if (args->feature == VIR_DRV_FEATURE_PROGRAM_KEEPALIVE) {
        if (virNetServerClientStartKeepAlive(client) < 0)
            goto cleanup;
        supported = 1;
        goto done;
    }

    if (!priv->conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    switch (args->feature) {
    case VIR_DRV_FEATURE_FD_PASSING:
        supported = 1;
        break;

    default:
        if ((supported = virDrvSupportsFeature(priv->conn, args->feature)) < 0)
            goto cleanup;
        break;
    }

done:
    ret->supported = supported;
    rv = 0;

cleanup:
    if (rv < 0)
        virNetMessageSaveError(rerr);
    return rv;
}


static int
remoteDispatchDomainOpenGraphics(virNetServerPtr server ATTRIBUTE_UNUSED,
                                 virNetServerClientPtr client ATTRIBUTE_UNUSED,
                                 virNetMessagePtr msg,
                                 virNetMessageErrorPtr rerr,
                                 remote_domain_open_graphics_args *args)
{
    virDomainPtr dom = NULL;
    int rv = -1;
    int fd = -1;
    struct daemonClientPrivate *priv =
        virNetServerClientGetPrivateData(client);

    if (!priv->conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(priv->conn, args->dom)))
        goto cleanup;

    if ((fd = virNetMessageDupFD(msg, 0)) < 0)
        goto cleanup;

    if (virDomainOpenGraphics(dom,
                              args->idx,
                              fd,
                              args->flags) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    VIR_FORCE_CLOSE(fd);
    if (rv < 0)
        virNetMessageSaveError(rerr);
    if (dom)
        virDomainFree(dom);
    return rv;
}

static int
remoteDispatchDomainGetInterfaceParameters(virNetServerPtr server ATTRIBUTE_UNUSED,
                                           virNetServerClientPtr client ATTRIBUTE_UNUSED,
                                           virNetMessagePtr msg ATTRIBUTE_UNUSED,
                                           virNetMessageErrorPtr rerr,
                                           remote_domain_get_interface_parameters_args *args,
                                           remote_domain_get_interface_parameters_ret *ret)
{
    virDomainPtr dom = NULL;
    virTypedParameterPtr params = NULL;
    const char *device = args->device;
    int nparams = args->nparams;
    unsigned int flags;
    int rv = -1;
    struct daemonClientPrivate *priv =
        virNetServerClientGetPrivateData(client);

    if (!priv->conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    flags = args->flags;

    if (nparams > REMOTE_DOMAIN_INTERFACE_PARAMETERS_MAX) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("nparams too large"));
        goto cleanup;
    }
    if (VIR_ALLOC_N(params, nparams) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(priv->conn, args->dom)))
        goto cleanup;

    if (virDomainGetInterfaceParameters(dom, device, params, &nparams, flags) < 0)
        goto cleanup;

    /* In this case, we need to send back the number of parameters
     * supported
     */
    if (args->nparams == 0) {
        ret->nparams = nparams;
        goto success;
    }

    if (remoteSerializeTypedParameters(params, nparams,
                                       &ret->params.params_val,
                                       &ret->params.params_len,
                                       flags) < 0)
        goto cleanup;

success:
    rv = 0;

cleanup:
    if (rv < 0)
        virNetMessageSaveError(rerr);
    virTypedParameterArrayClear(params, nparams);
    VIR_FREE(params);
    if (dom)
        virDomainFree(dom);
    return rv;
}

static int
remoteDispatchDomainGetCPUStats(virNetServerPtr server ATTRIBUTE_UNUSED,
                                virNetServerClientPtr client ATTRIBUTE_UNUSED,
                                virNetMessagePtr hdr ATTRIBUTE_UNUSED,
                                virNetMessageErrorPtr rerr,
                                remote_domain_get_cpu_stats_args *args,
                                remote_domain_get_cpu_stats_ret *ret)
{
    virDomainPtr dom = NULL;
    struct daemonClientPrivate *priv;
    virTypedParameterPtr params = NULL;
    int rv = -1;
    int percpu_len = 0;

    priv = virNetServerClientGetPrivateData(client);
    if (!priv->conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (args->nparams > REMOTE_NODE_CPU_STATS_MAX) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("nparams too large"));
        goto cleanup;
    }
    if (args->ncpus > REMOTE_DOMAIN_GET_CPU_STATS_NCPUS_MAX) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("ncpus too large"));
        goto cleanup;
    }

    if (args->nparams > 0 &&
        VIR_ALLOC_N(params, args->ncpus * args->nparams) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(priv->conn, args->dom)))
        goto cleanup;

    percpu_len = virDomainGetCPUStats(dom, params, args->nparams,
                                      args->start_cpu, args->ncpus,
                                      args->flags);
    if (percpu_len < 0)
        goto cleanup;
    /* If nparams == 0, the function returns a single value */
    if (args->nparams == 0)
        goto success;

    if (remoteSerializeTypedParameters(params, args->nparams * args->ncpus,
                                       &ret->params.params_val,
                                       &ret->params.params_len,
                                       args->flags) < 0)
        goto cleanup;

success:
    rv = 0;
    ret->nparams = percpu_len;
    if (args->nparams && !(args->flags & VIR_TYPED_PARAM_STRING_OKAY)) {
        int i;

        for (i = 0; i < percpu_len; i++) {
            if (params[i].type == VIR_TYPED_PARAM_STRING)
                ret->nparams--;
        }
    }

cleanup:
    if (rv < 0)
         virNetMessageSaveError(rerr);
    virTypedParameterArrayClear(params, args->ncpus * args->nparams);
    VIR_FREE(params);
    if (dom)
        virDomainFree(dom);
    return rv;
}

static int remoteDispatchDomainGetDiskErrors(
    virNetServerPtr server ATTRIBUTE_UNUSED,
    virNetServerClientPtr client,
    virNetMessagePtr msg ATTRIBUTE_UNUSED,
    virNetMessageErrorPtr rerr,
    remote_domain_get_disk_errors_args *args,
    remote_domain_get_disk_errors_ret *ret)
{
    int rv = -1;
    virDomainPtr dom = NULL;
    virDomainDiskErrorPtr errors = NULL;
    int len = 0;
    struct daemonClientPrivate *priv =
        virNetServerClientGetPrivateData(client);

    if (!priv->conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(priv->conn, args->dom)))
        goto cleanup;

    if (args->maxerrors > REMOTE_DOMAIN_DISK_ERRORS_MAX) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("maxerrors too large"));
        goto cleanup;
    }

    if (args->maxerrors &&
        VIR_ALLOC_N(errors, args->maxerrors) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if ((len = virDomainGetDiskErrors(dom, errors,
                                      args->maxerrors,
                                      args->flags)) < 0)
        goto cleanup;

    ret->nerrors = len;
    if (errors &&
        remoteSerializeDomainDiskErrors(errors, len,
                                        &ret->errors.errors_val,
                                        &ret->errors.errors_len) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        virNetMessageSaveError(rerr);
    if (dom)
        virDomainFree(dom);
    if (errors) {
        int i;
        for (i = 0; i < len; i++)
            VIR_FREE(errors[i].disk);
    }
    VIR_FREE(errors);
    return rv;
}

/*----- Helpers. -----*/

/* get_nonnull_domain and get_nonnull_network turn an on-wire
 * (name, uuid) pair into virDomainPtr or virNetworkPtr object.
 * virDomainPtr or virNetworkPtr cannot be NULL.
 *
 * NB. If these return NULL then the caller must return an error.
 */
static virDomainPtr
get_nonnull_domain(virConnectPtr conn, remote_nonnull_domain domain)
{
    virDomainPtr dom;
    dom = virGetDomain(conn, domain.name, BAD_CAST domain.uuid);
    /* Should we believe the domain.id sent by the client?  Maybe
     * this should be a check rather than an assignment? XXX
     */
    if (dom) dom->id = domain.id;
    return dom;
}

static virNetworkPtr
get_nonnull_network(virConnectPtr conn, remote_nonnull_network network)
{
    return virGetNetwork(conn, network.name, BAD_CAST network.uuid);
}

static virInterfacePtr
get_nonnull_interface(virConnectPtr conn, remote_nonnull_interface iface)
{
    return virGetInterface(conn, iface.name, iface.mac);
}

static virStoragePoolPtr
get_nonnull_storage_pool(virConnectPtr conn, remote_nonnull_storage_pool pool)
{
    return virGetStoragePool(conn, pool.name, BAD_CAST pool.uuid);
}

static virStorageVolPtr
get_nonnull_storage_vol(virConnectPtr conn, remote_nonnull_storage_vol vol)
{
    virStorageVolPtr ret;
    ret = virGetStorageVol(conn, vol.pool, vol.name, vol.key);
    return ret;
}

static virSecretPtr
get_nonnull_secret(virConnectPtr conn, remote_nonnull_secret secret)
{
    return virGetSecret(conn, BAD_CAST secret.uuid, secret.usageType, secret.usageID);
}

static virNWFilterPtr
get_nonnull_nwfilter(virConnectPtr conn, remote_nonnull_nwfilter nwfilter)
{
    return virGetNWFilter(conn, nwfilter.name, BAD_CAST nwfilter.uuid);
}

static virDomainSnapshotPtr
get_nonnull_domain_snapshot(virDomainPtr dom, remote_nonnull_domain_snapshot snapshot)
{
    return virGetDomainSnapshot(dom, snapshot.name);
}

/* Make remote_nonnull_domain and remote_nonnull_network. */
static void
make_nonnull_domain(remote_nonnull_domain *dom_dst, virDomainPtr dom_src)
{
    dom_dst->id = dom_src->id;
    dom_dst->name = strdup(dom_src->name);
    memcpy(dom_dst->uuid, dom_src->uuid, VIR_UUID_BUFLEN);
}

static void
make_nonnull_network(remote_nonnull_network *net_dst, virNetworkPtr net_src)
{
    net_dst->name = strdup(net_src->name);
    memcpy(net_dst->uuid, net_src->uuid, VIR_UUID_BUFLEN);
}

static void
make_nonnull_interface(remote_nonnull_interface *interface_dst,
                       virInterfacePtr interface_src)
{
    interface_dst->name = strdup(interface_src->name);
    interface_dst->mac = strdup(interface_src->mac);
}

static void
make_nonnull_storage_pool(remote_nonnull_storage_pool *pool_dst, virStoragePoolPtr pool_src)
{
    pool_dst->name = strdup(pool_src->name);
    memcpy(pool_dst->uuid, pool_src->uuid, VIR_UUID_BUFLEN);
}

static void
make_nonnull_storage_vol(remote_nonnull_storage_vol *vol_dst, virStorageVolPtr vol_src)
{
    vol_dst->pool = strdup(vol_src->pool);
    vol_dst->name = strdup(vol_src->name);
    vol_dst->key = strdup(vol_src->key);
}

static void
make_nonnull_node_device(remote_nonnull_node_device *dev_dst, virNodeDevicePtr dev_src)
{
    dev_dst->name = strdup(dev_src->name);
}

static void
make_nonnull_secret(remote_nonnull_secret *secret_dst, virSecretPtr secret_src)
{
    memcpy(secret_dst->uuid, secret_src->uuid, VIR_UUID_BUFLEN);
    secret_dst->usageType = secret_src->usageType;
    secret_dst->usageID = strdup(secret_src->usageID);
}

static void
make_nonnull_nwfilter(remote_nonnull_nwfilter *nwfilter_dst, virNWFilterPtr nwfilter_src)
{
    nwfilter_dst->name = strdup(nwfilter_src->name);
    memcpy(nwfilter_dst->uuid, nwfilter_src->uuid, VIR_UUID_BUFLEN);
}

static void
make_nonnull_domain_snapshot(remote_nonnull_domain_snapshot *snapshot_dst, virDomainSnapshotPtr snapshot_src)
{
    snapshot_dst->name = strdup(snapshot_src->name);
    make_nonnull_domain(&snapshot_dst->dom, snapshot_src->domain);
}

static int
remoteSerializeDomainDiskErrors(virDomainDiskErrorPtr errors,
                                int nerrors,
                                remote_domain_disk_error **ret_errors_val,
                                u_int *ret_errors_len)
{
    remote_domain_disk_error *val = NULL;
    int i = 0;

    if (VIR_ALLOC_N(val, nerrors) < 0)
        goto no_memory;

    for (i = 0; i < nerrors; i++) {
        if (!(val[i].disk = strdup(errors[i].disk)))
            goto no_memory;
        val[i].error = errors[i].error;
    }

    *ret_errors_len = nerrors;
    *ret_errors_val = val;

    return 0;

no_memory:
    if (val) {
        int j;
        for (j = 0; j < i; j++)
            VIR_FREE(val[j].disk);
        VIR_FREE(val);
    }
    virReportOOMError();
    return -1;
}
