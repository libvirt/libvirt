/*
 * remote.c: handlers for RPC method calls
 *
 * Copyright (C) 2007-2011 Red Hat, Inc.
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

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/poll.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdlib.h>
#include <pwd.h>
#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>
#include <fnmatch.h>
#include <arpa/inet.h>
#include "virterror_internal.h"

#if HAVE_POLKIT0
# include <polkit/polkit.h>
# include <polkit-dbus/polkit-dbus.h>
#endif

#include "remote.h"
#include "dispatch.h"

#include "libvirt_internal.h"
#include "datatypes.h"
#include "memory.h"
#include "util.h"
#include "stream.h"
#include "uuid.h"
#include "network.h"
#include "libvirt/libvirt-qemu.h"
#include "command.h"

#define VIR_FROM_THIS VIR_FROM_REMOTE

#define virNetError(code, ...)                                    \
    virReportErrorHelper(VIR_FROM_THIS, code, __FILE__,           \
                         __FUNCTION__, __LINE__, __VA_ARGS__)

#if SIZEOF_LONG < 8
# define HYPER_TO_TYPE(_type, _to, _from)                                     \
    do {                                                                      \
        if ((_from) != (_type)(_from)) {                                      \
            virNetError(VIR_ERR_INTERNAL_ERROR,                               \
                        _("conversion from hyper to %s overflowed"), #_type); \
            goto cleanup;                                                     \
        }                                                                     \
        (_to) = (_from);                                                      \
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


#include "remote_dispatch_prototypes.h"
#include "qemu_dispatch_prototypes.h"

static const dispatch_data const dispatch_table[] = {
#include "remote_dispatch_table.h"
};

static const dispatch_data const qemu_dispatch_table[] = {
#include "qemu_dispatch_table.h"
};

const dispatch_data const *remoteGetDispatchData(int proc)
{
    if (proc >= ARRAY_CARDINALITY(dispatch_table) ||
        dispatch_table[proc].fn == NULL) {
        return NULL;
    }

    return &(dispatch_table[proc]);
}

const dispatch_data const *qemuGetDispatchData(int proc)
{
    if (proc >= ARRAY_CARDINALITY(qemu_dispatch_table) ||
        qemu_dispatch_table[proc].fn == NULL) {
        return NULL;
    }

    return &(qemu_dispatch_table[proc]);
}

/* Prototypes */
static void
remoteDispatchDomainEventSend(struct qemud_client *client,
                              int procnr,
                              xdrproc_t proc,
                              void *data);

static int remoteRelayDomainEventLifecycle(virConnectPtr conn ATTRIBUTE_UNUSED,
                                           virDomainPtr dom,
                                           int event,
                                           int detail,
                                           void *opaque)
{
    struct qemud_client *client = opaque;
    remote_domain_event_lifecycle_msg data;

    if (!client)
        return -1;

    VIR_DEBUG("Relaying domain lifecycle event %d %d", event, detail);

    virMutexLock(&client->lock);

    /* build return data */
    memset(&data, 0, sizeof data);
    make_nonnull_domain(&data.dom, dom);
    data.event = event;
    data.detail = detail;

    remoteDispatchDomainEventSend(client,
                                  REMOTE_PROC_DOMAIN_EVENT_LIFECYCLE,
                                  (xdrproc_t)xdr_remote_domain_event_lifecycle_msg, &data);

    virMutexUnlock(&client->lock);

    return 0;
}

static int remoteRelayDomainEventReboot(virConnectPtr conn ATTRIBUTE_UNUSED,
                                        virDomainPtr dom,
                                        void *opaque)
{
    struct qemud_client *client = opaque;
    remote_domain_event_reboot_msg data;

    if (!client)
        return -1;

    VIR_DEBUG("Relaying domain reboot event %s %d", dom->name, dom->id);

    virMutexLock(&client->lock);

    /* build return data */
    memset(&data, 0, sizeof data);
    make_nonnull_domain(&data.dom, dom);

    remoteDispatchDomainEventSend(client,
                                  REMOTE_PROC_DOMAIN_EVENT_REBOOT,
                                  (xdrproc_t)xdr_remote_domain_event_reboot_msg, &data);

    virMutexUnlock(&client->lock);

    return 0;
}


static int remoteRelayDomainEventRTCChange(virConnectPtr conn ATTRIBUTE_UNUSED,
                                           virDomainPtr dom,
                                           long long offset,
                                           void *opaque)
{
    struct qemud_client *client = opaque;
    remote_domain_event_rtc_change_msg data;

    if (!client)
        return -1;

    VIR_DEBUG("Relaying domain rtc change event %s %d %lld", dom->name, dom->id, offset);

    virMutexLock(&client->lock);

    /* build return data */
    memset(&data, 0, sizeof data);
    make_nonnull_domain(&data.dom, dom);
    data.offset = offset;

    remoteDispatchDomainEventSend(client,
                                  REMOTE_PROC_DOMAIN_EVENT_RTC_CHANGE,
                                  (xdrproc_t)xdr_remote_domain_event_rtc_change_msg, &data);

    virMutexUnlock(&client->lock);

    return 0;
}


static int remoteRelayDomainEventWatchdog(virConnectPtr conn ATTRIBUTE_UNUSED,
                                          virDomainPtr dom,
                                          int action,
                                          void *opaque)
{
    struct qemud_client *client = opaque;
    remote_domain_event_watchdog_msg data;

    if (!client)
        return -1;

    VIR_DEBUG("Relaying domain watchdog event %s %d %d", dom->name, dom->id, action);

    virMutexLock(&client->lock);

    /* build return data */
    memset(&data, 0, sizeof data);
    make_nonnull_domain(&data.dom, dom);
    data.action = action;

    remoteDispatchDomainEventSend(client,
                                  REMOTE_PROC_DOMAIN_EVENT_WATCHDOG,
                                  (xdrproc_t)xdr_remote_domain_event_watchdog_msg, &data);

    virMutexUnlock(&client->lock);

    return 0;
}


static int remoteRelayDomainEventIOError(virConnectPtr conn ATTRIBUTE_UNUSED,
                                         virDomainPtr dom,
                                         const char *srcPath,
                                         const char *devAlias,
                                         int action,
                                         void *opaque)
{
    struct qemud_client *client = opaque;
    remote_domain_event_io_error_msg data;

    if (!client)
        return -1;

    VIR_DEBUG("Relaying domain io error %s %d %s %s %d", dom->name, dom->id, srcPath, devAlias, action);

    virMutexLock(&client->lock);

    /* build return data */
    memset(&data, 0, sizeof data);
    make_nonnull_domain(&data.dom, dom);
    data.srcPath = (char*)srcPath;
    data.devAlias = (char*)devAlias;
    data.action = action;

    remoteDispatchDomainEventSend(client,
                                  REMOTE_PROC_DOMAIN_EVENT_IO_ERROR,
                                  (xdrproc_t)xdr_remote_domain_event_io_error_msg, &data);

    virMutexUnlock(&client->lock);

    return 0;
}


static int remoteRelayDomainEventIOErrorReason(virConnectPtr conn ATTRIBUTE_UNUSED,
                                               virDomainPtr dom,
                                               const char *srcPath,
                                               const char *devAlias,
                                               int action,
                                               const char *reason,
                                               void *opaque)
{
    struct qemud_client *client = opaque;
    remote_domain_event_io_error_reason_msg data;

    if (!client)
        return -1;

    VIR_DEBUG("Relaying domain io error %s %d %s %s %d %s",
              dom->name, dom->id, srcPath, devAlias, action, reason);

    virMutexLock(&client->lock);

    /* build return data */
    memset(&data, 0, sizeof data);
    make_nonnull_domain(&data.dom, dom);
    data.srcPath = (char*)srcPath;
    data.devAlias = (char*)devAlias;
    data.action = action;
    data.reason = (char*)reason;

    remoteDispatchDomainEventSend(client,
                                  REMOTE_PROC_DOMAIN_EVENT_IO_ERROR_REASON,
                                  (xdrproc_t)xdr_remote_domain_event_io_error_reason_msg, &data);

    virMutexUnlock(&client->lock);

    return 0;
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
    struct qemud_client *client = opaque;
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

    virMutexLock(&client->lock);

    /* build return data */
    memset(&data, 0, sizeof data);
    make_nonnull_domain(&data.dom, dom);
    data.phase = phase;
    data.authScheme = (char*)authScheme;

    data.local.family = local->family;
    data.local.node = (char *)local->node;
    data.local.service = (char *)local->service;

    data.remote.family = remote->family;
    data.remote.node = (char*)remote->node;
    data.remote.service = (char*)remote->service;

    data.subject.subject_len = subject->nidentity;
    if (VIR_ALLOC_N(data.subject.subject_val, data.subject.subject_len) < 0) {
        VIR_WARN("cannot allocate memory for graphics event subject");
        return -1;
    }
    for (i = 0 ; i < data.subject.subject_len ; i++) {
        data.subject.subject_val[i].type = (char*)subject->identities[i].type;
        data.subject.subject_val[i].name = (char*)subject->identities[i].name;
    }

    remoteDispatchDomainEventSend(client,
                                  REMOTE_PROC_DOMAIN_EVENT_GRAPHICS,
                                  (xdrproc_t)xdr_remote_domain_event_graphics_msg, &data);

    VIR_FREE(data.subject.subject_val);

    virMutexUnlock(&client->lock);

    return 0;
}


static int remoteRelayDomainEventControlError(virConnectPtr conn ATTRIBUTE_UNUSED,
                                              virDomainPtr dom,
                                              void *opaque)
{
    struct qemud_client *client = opaque;
    remote_domain_event_control_error_msg data;

    if (!client)
        return -1;

    VIR_DEBUG("Relaying domain control error %s %d", dom->name, dom->id);

    virMutexLock(&client->lock);

    /* build return data */
    memset(&data, 0, sizeof data);
    make_nonnull_domain(&data.dom, dom);

    remoteDispatchDomainEventSend(client,
                                  REMOTE_PROC_DOMAIN_EVENT_CONTROL_ERROR,
                                  (xdrproc_t)xdr_remote_domain_event_control_error_msg, &data);

    virMutexUnlock(&client->lock);

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
};

verify(ARRAY_CARDINALITY(domainEventCallbacks) == VIR_DOMAIN_EVENT_ID_LAST);

/*----- Functions. -----*/

static int
remoteDispatchOpen(struct qemud_server *server,
                   struct qemud_client *client,
                   virConnectPtr conn,
                   remote_message_header *hdr ATTRIBUTE_UNUSED,
                   remote_error *rerr,
                   struct remote_open_args *args, void *ret ATTRIBUTE_UNUSED)
{
    const char *name;
    int flags;
    int rv = -1;

    virMutexLock(&server->lock);
    virMutexLock(&client->lock);
    virMutexUnlock(&server->lock);

    if (conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection already open"));
        goto cleanup;
    }

    name = args->name ? *args->name : NULL;

    /* If this connection arrived on a readonly socket, force
     * the connection to be readonly.
     */
    flags = args->flags;
    if (client->readonly) flags |= VIR_CONNECT_RO;

    client->conn =
        flags & VIR_CONNECT_RO
        ? virConnectOpenReadOnly(name)
        : virConnectOpen(name);

    if (client->conn == NULL)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    virMutexUnlock(&client->lock);
    return rv;
}


static int
remoteDispatchClose(struct qemud_server *server ATTRIBUTE_UNUSED,
                    struct qemud_client *client ATTRIBUTE_UNUSED,
                    virConnectPtr conn ATTRIBUTE_UNUSED,
                    remote_message_header *hdr ATTRIBUTE_UNUSED,
                    remote_error *rerr ATTRIBUTE_UNUSED,
                    void *args ATTRIBUTE_UNUSED, void *ret ATTRIBUTE_UNUSED)
{
    virMutexLock(&server->lock);
    virMutexLock(&client->lock);
    virMutexUnlock(&server->lock);

    client->closing = 1;

    virMutexUnlock(&client->lock);
    return 0;
}

static int
remoteDispatchDomainGetSchedulerType(struct qemud_server *server ATTRIBUTE_UNUSED,
                                     struct qemud_client *client ATTRIBUTE_UNUSED,
                                     virConnectPtr conn,
                                     remote_message_header *hdr ATTRIBUTE_UNUSED,
                                     remote_error *rerr,
                                     remote_domain_get_scheduler_type_args *args,
                                     remote_domain_get_scheduler_type_ret *ret)
{
    virDomainPtr dom = NULL;
    char *type;
    int nparams;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(conn, args->dom)))
        goto cleanup;

    if (!(type = virDomainGetSchedulerType(dom, &nparams)))
        goto cleanup;

    ret->type = type;
    ret->nparams = nparams;
    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (dom)
        virDomainFree(dom);
    return rv;
}

/* Helper to serialize typed parameters. */
static int
remoteSerializeTypedParameters(virTypedParameterPtr params,
                               int nparams,
                               remote_typed_param **ret_params_val,
                               u_int *ret_params_len)
{
    int i;
    int rv = -1;
    remote_typed_param *val;

    *ret_params_len = nparams;
    if (VIR_ALLOC_N(val, nparams) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    for (i = 0; i < nparams; ++i) {
        /* remoteDispatchClientRequest will free this: */
        val[i].field = strdup (params[i].field);
        if (val[i].field == NULL) {
            virReportOOMError();
            goto cleanup;
        }
        val[i].value.type = params[i].type;
        switch (params[i].type) {
        case VIR_TYPED_PARAM_INT:
            val[i].value.remote_typed_param_value_u.i = params[i].value.i;
            break;
        case VIR_TYPED_PARAM_UINT:
            val[i].value.remote_typed_param_value_u.ui = params[i].value.ui;
            break;
        case VIR_TYPED_PARAM_LLONG:
            val[i].value.remote_typed_param_value_u.l = params[i].value.l;
            break;
        case VIR_TYPED_PARAM_ULLONG:
            val[i].value.remote_typed_param_value_u.ul = params[i].value.ul;
            break;
        case VIR_TYPED_PARAM_DOUBLE:
            val[i].value.remote_typed_param_value_u.d = params[i].value.d;
            break;
        case VIR_TYPED_PARAM_BOOLEAN:
            val[i].value.remote_typed_param_value_u.b = params[i].value.b;
            break;
        default:
            virNetError(VIR_ERR_RPC, _("unknown parameter type: %d"),
                        params[i].type);
            goto cleanup;
        }
    }

    *ret_params_val = val;
    val = NULL;
    rv = 0;

cleanup:
    if (val) {
        for (i = 0; i < nparams; i++)
            VIR_FREE(val[i].field);
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
    int i;
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
        default:
            virNetError(VIR_ERR_INTERNAL_ERROR, _("unknown parameter type: %d"),
                        params[i].type);
            goto cleanup;
        }
    }

    rv = 0;

cleanup:
    if (rv < 0)
        VIR_FREE(params);
    return params;
}

static int
remoteDispatchDomainGetSchedulerParameters(struct qemud_server *server ATTRIBUTE_UNUSED,
                                           struct qemud_client *client ATTRIBUTE_UNUSED,
                                           virConnectPtr conn,
                                           remote_message_header *hdr ATTRIBUTE_UNUSED,
                                           remote_error *rerr,
                                           remote_domain_get_scheduler_parameters_args *args,
                                           remote_domain_get_scheduler_parameters_ret *ret)
{
    virDomainPtr dom = NULL;
    virTypedParameterPtr params = NULL;
    int nparams = args->nparams;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (nparams > REMOTE_DOMAIN_SCHEDULER_PARAMETERS_MAX) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("nparams too large"));
        goto cleanup;
    }
    if (VIR_ALLOC_N(params, nparams) < 0)
        goto no_memory;

    if (!(dom = get_nonnull_domain(conn, args->dom)))
        goto cleanup;

    if (virDomainGetSchedulerParameters(dom, params, &nparams) < 0)
        goto cleanup;

    if (remoteSerializeTypedParameters(params, nparams,
                                       &ret->params.params_val,
                                       &ret->params.params_len) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (dom)
        virDomainFree(dom);
    VIR_FREE(params);
    return rv;

no_memory:
    virReportOOMError();
    goto cleanup;
}

static int
remoteDispatchDomainGetSchedulerParametersFlags(struct qemud_server *server ATTRIBUTE_UNUSED,
                                                struct qemud_client *client ATTRIBUTE_UNUSED,
                                                virConnectPtr conn,
                                                remote_message_header *hdr ATTRIBUTE_UNUSED,
                                                remote_error *rerr,
                                                remote_domain_get_scheduler_parameters_flags_args *args,
                                                remote_domain_get_scheduler_parameters_flags_ret *ret)
{
    virDomainPtr dom = NULL;
    virTypedParameterPtr params = NULL;
    int nparams = args->nparams;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (nparams > REMOTE_DOMAIN_SCHEDULER_PARAMETERS_MAX) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("nparams too large"));
        goto cleanup;
    }
    if (VIR_ALLOC_N(params, nparams) < 0)
        goto no_memory;

    if (!(dom = get_nonnull_domain(conn, args->dom)))
        goto cleanup;

    if (virDomainGetSchedulerParametersFlags(dom, params, &nparams,
                                             args->flags) < 0)
        goto cleanup;

    if (remoteSerializeTypedParameters(params, nparams,
                                       &ret->params.params_val,
                                       &ret->params.params_len) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (dom)
        virDomainFree(dom);
    VIR_FREE(params);
    return rv;

no_memory:
    virReportOOMError();
    goto cleanup;
}

static int
remoteDispatchDomainMemoryStats(struct qemud_server *server ATTRIBUTE_UNUSED,
                                struct qemud_client *client ATTRIBUTE_UNUSED,
                                virConnectPtr conn,
                                remote_message_header *hdr ATTRIBUTE_UNUSED,
                                remote_error *rerr,
                                remote_domain_memory_stats_args *args,
                                remote_domain_memory_stats_ret *ret)
{
    virDomainPtr dom = NULL;
    struct _virDomainMemoryStat *stats;
    int nr_stats, i;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (args->maxStats > REMOTE_DOMAIN_MEMORY_STATS_MAX) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("maxStats > REMOTE_DOMAIN_MEMORY_STATS_MAX"));
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(conn, args->dom)))
        goto cleanup;

    /* Allocate stats array for making dispatch call */
    if (VIR_ALLOC_N(stats, args->maxStats) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    nr_stats = virDomainMemoryStats(dom, stats, args->maxStats, 0);
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
        remoteDispatchError(rerr);
    if (dom)
        virDomainFree(dom);
    VIR_FREE(stats);
    return rv;
}

static int
remoteDispatchDomainBlockPeek(struct qemud_server *server ATTRIBUTE_UNUSED,
                              struct qemud_client *client ATTRIBUTE_UNUSED,
                              virConnectPtr conn,
                              remote_message_header *hdr ATTRIBUTE_UNUSED,
                              remote_error *rerr,
                              remote_domain_block_peek_args *args,
                              remote_domain_block_peek_ret *ret)
{
    virDomainPtr dom = NULL;
    char *path;
    unsigned long long offset;
    size_t size;
    unsigned int flags;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(conn, args->dom)))
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
        remoteDispatchError(rerr);
        VIR_FREE(ret->buffer.buffer_val);
    }
    if (dom)
        virDomainFree(dom);
    return rv;
}

static int
remoteDispatchDomainMemoryPeek(struct qemud_server *server ATTRIBUTE_UNUSED,
                               struct qemud_client *client ATTRIBUTE_UNUSED,
                               virConnectPtr conn,
                               remote_message_header *hdr ATTRIBUTE_UNUSED,
                               remote_error *rerr,
                               remote_domain_memory_peek_args *args,
                               remote_domain_memory_peek_ret *ret)
{
    virDomainPtr dom = NULL;
    unsigned long long offset;
    size_t size;
    unsigned int flags;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(conn, args->dom)))
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
        remoteDispatchError(rerr);
        VIR_FREE(ret->buffer.buffer_val);
    }
    if (dom)
        virDomainFree(dom);
    return rv;
}

static int
remoteDispatchDomainGetSecurityLabel(struct qemud_server *server ATTRIBUTE_UNUSED,
                                     struct qemud_client *client ATTRIBUTE_UNUSED,
                                     virConnectPtr conn,
                                     remote_message_header *hdr ATTRIBUTE_UNUSED,
                                     remote_error *rerr,
                                     remote_domain_get_security_label_args *args,
                                     remote_domain_get_security_label_ret *ret)
{
    virDomainPtr dom = NULL;
    virSecurityLabelPtr seclabel = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(conn, args->dom)))
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
        remoteDispatchError(rerr);
    if (dom)
        virDomainFree(dom);
    VIR_FREE(seclabel);
    return rv;
}

static int
remoteDispatchNodeGetSecurityModel(struct qemud_server *server ATTRIBUTE_UNUSED,
                                   struct qemud_client *client ATTRIBUTE_UNUSED,
                                   virConnectPtr conn,
                                   remote_message_header *hdr ATTRIBUTE_UNUSED,
                                   remote_error *rerr,
                                   void *args ATTRIBUTE_UNUSED,
                                   remote_node_get_security_model_ret *ret)
{
    virSecurityModel secmodel;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    memset(&secmodel, 0, sizeof secmodel);
    if (virNodeGetSecurityModel(conn, &secmodel) < 0)
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
        remoteDispatchError(rerr);
    return rv;
}

static int
remoteDispatchDomainGetVcpus(struct qemud_server *server ATTRIBUTE_UNUSED,
                             struct qemud_client *client ATTRIBUTE_UNUSED,
                             virConnectPtr conn,
                             remote_message_header *hdr ATTRIBUTE_UNUSED,
                             remote_error *rerr,
                             remote_domain_get_vcpus_args *args,
                             remote_domain_get_vcpus_ret *ret)
{
    virDomainPtr dom = NULL;
    virVcpuInfoPtr info = NULL;
    unsigned char *cpumaps = NULL;
    int info_len, i;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(conn, args->dom)))
        goto cleanup;

    if (args->maxinfo > REMOTE_VCPUINFO_MAX) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("maxinfo > REMOTE_VCPUINFO_MAX"));
        goto cleanup;
    }

    if (args->maxinfo * args->maplen > REMOTE_CPUMAPS_MAX) {
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
        remoteDispatchError(rerr);
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
remoteDispatchDomainMigratePrepare(struct qemud_server *server ATTRIBUTE_UNUSED,
                                   struct qemud_client *client ATTRIBUTE_UNUSED,
                                   virConnectPtr conn,
                                   remote_message_header *hdr ATTRIBUTE_UNUSED,
                                   remote_error *rerr,
                                   remote_domain_migrate_prepare_args *args,
                                   remote_domain_migrate_prepare_ret *ret)
{
    char *cookie = NULL;
    int cookielen = 0;
    char *uri_in;
    char **uri_out;
    char *dname;
    int rv = -1;

    if (!conn) {
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

    if (virDomainMigratePrepare(conn, &cookie, &cookielen,
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
        remoteDispatchError(rerr);
    VIR_FREE(uri_out);
    return rv;
}

static int
remoteDispatchDomainMigratePrepare2(struct qemud_server *server ATTRIBUTE_UNUSED,
                                    struct qemud_client *client ATTRIBUTE_UNUSED,
                                    virConnectPtr conn,
                                    remote_message_header *hdr ATTRIBUTE_UNUSED,
                                    remote_error *rerr,
                                    remote_domain_migrate_prepare2_args *args,
                                    remote_domain_migrate_prepare2_ret *ret)
{
    char *cookie = NULL;
    int cookielen = 0;
    char *uri_in;
    char **uri_out;
    char *dname;
    int rv = -1;

    if (!conn) {
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

    if (virDomainMigratePrepare2(conn, &cookie, &cookielen,
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
        remoteDispatchError(rerr);
    return rv;
}

static int
remoteDispatchDomainPinVcpu(struct qemud_server *server ATTRIBUTE_UNUSED,
                            struct qemud_client *client ATTRIBUTE_UNUSED,
                            virConnectPtr conn,
                            remote_message_header *hdr ATTRIBUTE_UNUSED,
                            remote_error *rerr,
                            remote_domain_pin_vcpu_args *args,
                            void *ret ATTRIBUTE_UNUSED)
{
    virDomainPtr dom = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(conn, args->dom)))
        goto cleanup;

    if (args->cpumap.cpumap_len > REMOTE_CPUMAP_MAX) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("cpumap_len > REMOTE_CPUMAP_MAX"));
        goto cleanup;
    }

    if (virDomainPinVcpu(dom, args->vcpu,
                         (unsigned char *) args->cpumap.cpumap_val,
                         args->cpumap.cpumap_len) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (dom)
        virDomainFree(dom);
    return rv;
}

static int
remoteDispatchDomainGetMemoryParameters(struct qemud_server *server
                                        ATTRIBUTE_UNUSED,
                                        struct qemud_client *client
                                        ATTRIBUTE_UNUSED,
                                        virConnectPtr conn,
                                        remote_message_header *
                                        hdr ATTRIBUTE_UNUSED,
                                        remote_error * rerr,
                                        remote_domain_get_memory_parameters_args
                                        * args,
                                        remote_domain_get_memory_parameters_ret
                                        * ret)
{
    virDomainPtr dom = NULL;
    virTypedParameterPtr params = NULL;
    int nparams = args->nparams;
    unsigned int flags;
    int rv = -1;

    if (!conn) {
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

    if (!(dom = get_nonnull_domain(conn, args->dom)))
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
                                       &ret->params.params_len) < 0)
        goto cleanup;

success:
    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (dom)
        virDomainFree(dom);
    VIR_FREE(params);
    return rv;
}

static int
remoteDispatchDomainGetBlkioParameters(struct qemud_server *server
                                        ATTRIBUTE_UNUSED,
                                        struct qemud_client *client
                                        ATTRIBUTE_UNUSED,
                                        virConnectPtr conn,
                                        remote_message_header *
                                        hdr ATTRIBUTE_UNUSED,
                                        remote_error * rerr,
                                        remote_domain_get_blkio_parameters_args
                                        * args,
                                        remote_domain_get_blkio_parameters_ret
                                        * ret)
{
    virDomainPtr dom = NULL;
    virTypedParameterPtr params = NULL;
    int nparams = args->nparams;
    unsigned int flags;
    int rv = -1;

    if (!conn) {
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

    if (!(dom = get_nonnull_domain(conn, args->dom)))
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
                                       &ret->params.params_len) < 0)
        goto cleanup;

success:
    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    VIR_FREE(params);
    if (dom)
        virDomainFree(dom);
    return rv;
}

static int
remoteDispatchDomainScreenshot(struct qemud_server *server ATTRIBUTE_UNUSED,
                               struct qemud_client *client,
                               virConnectPtr conn,
                               remote_message_header *hdr,
                               remote_error *rerr,
                               remote_domain_screenshot_args *args,
                               remote_domain_screenshot_ret *ret)
{
    int rv = -1;
    struct qemud_client_stream *stream = NULL;
    virDomainPtr dom = NULL;
    char *mime, **mime_p;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    ret->mime = NULL;

    if (!(dom = get_nonnull_domain (conn, args->dom)))
        goto cleanup;

    if (!(stream = remoteCreateClientStream(conn, hdr)))
        goto cleanup;

    if (!(mime = virDomainScreenshot(dom, stream->st, args->screen, args->flags)))
        goto cleanup;

    if (remoteAddClientStream(client, stream, 1) < 0) {
        virStreamAbort(stream->st);
        goto cleanup;
    }

    if (VIR_ALLOC(mime_p) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    *mime_p = strdup(mime);
    if (*mime_p == NULL) {
        virReportOOMError();
        VIR_FREE(mime_p);
        goto cleanup;
    }

    ret->mime = mime_p;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    VIR_FREE(mime);
    if (dom)
        virDomainFree(dom);
    if (stream && rv != 0) {
        virStreamAbort(stream->st);
        remoteFreeClientStream(client, stream);
    }
    return rv;
}

/*-------------------------------------------------------------*/

static int
remoteDispatchAuthList(struct qemud_server *server,
                       struct qemud_client *client,
                       virConnectPtr conn ATTRIBUTE_UNUSED,
                       remote_message_header *hdr ATTRIBUTE_UNUSED,
                       remote_error *rerr,
                       void *args ATTRIBUTE_UNUSED,
                       remote_auth_list_ret *ret)
{
    int rv = -1;

    ret->types.types_len = 1;
    if (VIR_ALLOC_N(ret->types.types_val, ret->types.types_len) < 0) {
        virReportOOMError();
        goto cleanup;
    }
    virMutexLock(&server->lock);
    virMutexLock(&client->lock);
    virMutexUnlock(&server->lock);
    ret->types.types_val[0] = client->auth;
    virMutexUnlock(&client->lock);

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    return rv;
}


#if HAVE_SASL
/*
 * Initializes the SASL session in prepare for authentication
 * and gives the client a list of allowed mechanisms to choose
 *
 * XXX callbacks for stuff like password verification ?
 */
static int
remoteDispatchAuthSaslInit(struct qemud_server *server,
                           struct qemud_client *client,
                           virConnectPtr conn ATTRIBUTE_UNUSED,
                           remote_message_header *hdr ATTRIBUTE_UNUSED,
                           remote_error *rerr,
                           void *args ATTRIBUTE_UNUSED,
                           remote_auth_sasl_init_ret *ret)
{
    const char *mechlist = NULL;
    sasl_security_properties_t secprops;
    int err;
    virSocketAddr sa;
    char *localAddr, *remoteAddr;

    virMutexLock(&server->lock);
    virMutexLock(&client->lock);
    virMutexUnlock(&server->lock);

    VIR_DEBUG("Initialize SASL auth %d", client->fd);
    if (client->auth != REMOTE_AUTH_SASL ||
        client->saslconn != NULL) {
        VIR_ERROR(_("client tried invalid SASL init request"));
        goto authfail;
    }

    /* Get local address in form  IPADDR:PORT */
    sa.len = sizeof(sa.data.stor);
    if (getsockname(client->fd, &sa.data.sa, &sa.len) < 0) {
        char ebuf[1024];
        virNetError(VIR_ERR_INTERNAL_ERROR,
                    _("failed to get sock address: %s"),
                    virStrerror(errno, ebuf, sizeof ebuf));
        goto error;
    }
    if ((localAddr = virSocketFormatAddrFull(&sa, true, ";")) == NULL)
        goto error;

    /* Get remote address in form  IPADDR:PORT */
    sa.len = sizeof(sa.data.stor);
    if (getpeername(client->fd, &sa.data.sa, &sa.len) < 0) {
        char ebuf[1024];
        virNetError(VIR_ERR_INTERNAL_ERROR, _("failed to get peer address: %s"),
                    virStrerror(errno, ebuf, sizeof ebuf));
        VIR_FREE(localAddr);
        goto error;
    }
    if ((remoteAddr = virSocketFormatAddrFull(&sa, true, ";")) == NULL) {
        VIR_FREE(localAddr);
        goto error;
    }

    err = sasl_server_new("libvirt",
                          NULL, /* FQDN - just delegates to gethostname */
                          NULL, /* User realm */
                          localAddr,
                          remoteAddr,
                          NULL, /* XXX Callbacks */
                          SASL_SUCCESS_DATA,
                          &client->saslconn);
    VIR_FREE(localAddr);
    VIR_FREE(remoteAddr);
    if (err != SASL_OK) {
        VIR_ERROR(_("sasl context setup failed %d (%s)"),
                  err, sasl_errstring(err, NULL, NULL));
        client->saslconn = NULL;
        goto authfail;
    }

    /* Inform SASL that we've got an external SSF layer from TLS */
    if (client->type == QEMUD_SOCK_TYPE_TLS) {
        gnutls_cipher_algorithm_t cipher;
        sasl_ssf_t ssf;

        cipher = gnutls_cipher_get(client->tlssession);
        if (!(ssf = (sasl_ssf_t)gnutls_cipher_get_key_size(cipher))) {
            VIR_ERROR(_("cannot get TLS cipher size"));
            sasl_dispose(&client->saslconn);
            client->saslconn = NULL;
            goto authfail;
        }
        ssf *= 8; /* tls key size is bytes, sasl wants bits */

        err = sasl_setprop(client->saslconn, SASL_SSF_EXTERNAL, &ssf);
        if (err != SASL_OK) {
            VIR_ERROR(_("cannot set SASL external SSF %d (%s)"),
                      err, sasl_errstring(err, NULL, NULL));
            sasl_dispose(&client->saslconn);
            client->saslconn = NULL;
            goto authfail;
        }
    }

    memset(&secprops, 0, sizeof secprops);
    if (client->type == QEMUD_SOCK_TYPE_TLS ||
        client->type == QEMUD_SOCK_TYPE_UNIX) {
        /* If we've got TLS or UNIX domain sock, we don't care about SSF */
        secprops.min_ssf = 0;
        secprops.max_ssf = 0;
        secprops.maxbufsize = 8192;
        secprops.security_flags = 0;
    } else {
        /* Plain TCP, better get an SSF layer */
        secprops.min_ssf = 56; /* Good enough to require kerberos */
        secprops.max_ssf = 100000; /* Arbitrary big number */
        secprops.maxbufsize = 8192;
        /* Forbid any anonymous or trivially crackable auth */
        secprops.security_flags =
            SASL_SEC_NOANONYMOUS | SASL_SEC_NOPLAINTEXT;
    }

    err = sasl_setprop(client->saslconn, SASL_SEC_PROPS, &secprops);
    if (err != SASL_OK) {
        VIR_ERROR(_("cannot set SASL security props %d (%s)"),
                  err, sasl_errstring(err, NULL, NULL));
        sasl_dispose(&client->saslconn);
        client->saslconn = NULL;
        goto authfail;
    }

    err = sasl_listmech(client->saslconn,
                        NULL, /* Don't need to set user */
                        "", /* Prefix */
                        ",", /* Separator */
                        "", /* Suffix */
                        &mechlist,
                        NULL,
                        NULL);
    if (err != SASL_OK) {
        VIR_ERROR(_("cannot list SASL mechanisms %d (%s)"),
                  err, sasl_errdetail(client->saslconn));
        sasl_dispose(&client->saslconn);
        client->saslconn = NULL;
        goto authfail;
    }
    VIR_DEBUG("Available mechanisms for client: '%s'", mechlist);
    ret->mechlist = strdup(mechlist);
    if (!ret->mechlist) {
        VIR_ERROR(_("cannot allocate mechlist"));
        sasl_dispose(&client->saslconn);
        client->saslconn = NULL;
        goto authfail;
    }

    virMutexUnlock(&client->lock);
    return 0;

authfail:
    remoteDispatchAuthError(rerr);
error:
    PROBE(CLIENT_AUTH_FAIL, "fd=%d, auth=%d", client->fd, REMOTE_AUTH_SASL);
    virMutexUnlock(&client->lock);
    return -1;
}


/* We asked for an SSF layer, so sanity check that we actually
 * got what we asked for
 * Returns 0 if ok, -1 on error, -2 if rejected
 */
static int
remoteSASLCheckSSF(struct qemud_client *client,
                   remote_error *rerr) {
    const void *val;
    int err, ssf;

    if (client->type == QEMUD_SOCK_TYPE_TLS ||
        client->type == QEMUD_SOCK_TYPE_UNIX)
        return 0; /* TLS or UNIX domain sockets trivially OK */

    err = sasl_getprop(client->saslconn, SASL_SSF, &val);
    if (err != SASL_OK) {
        VIR_ERROR(_("cannot query SASL ssf on connection %d (%s)"),
                  err, sasl_errstring(err, NULL, NULL));
        remoteDispatchAuthError(rerr);
        sasl_dispose(&client->saslconn);
        client->saslconn = NULL;
        return -1;
    }
    ssf = *(const int *)val;
    VIR_DEBUG("negotiated an SSF of %d", ssf);
    if (ssf < 56) { /* 56 is good for Kerberos */
        VIR_ERROR(_("negotiated SSF %d was not strong enough"), ssf);
        remoteDispatchAuthError(rerr);
        sasl_dispose(&client->saslconn);
        client->saslconn = NULL;
        return -2;
    }

    /* Only setup for read initially, because we're about to send an RPC
     * reply which must be in plain text. When the next incoming RPC
     * arrives, we'll switch on writes too
     *
     * cf qemudClientReadSASL  in qemud.c
     */
    client->saslSSF = QEMUD_SASL_SSF_READ;

    /* We have a SSF !*/
    return 0;
}

/*
 * Returns 0 if ok, -1 on error, -2 if rejected
 */
static int
remoteSASLCheckAccess(struct qemud_server *server,
                      struct qemud_client *client,
                      remote_error *rerr) {
    const void *val;
    int err;
    char **wildcards;

    err = sasl_getprop(client->saslconn, SASL_USERNAME, &val);
    if (err != SASL_OK) {
        VIR_ERROR(_("cannot query SASL username on connection %d (%s)"),
                  err, sasl_errstring(err, NULL, NULL));
        remoteDispatchAuthError(rerr);
        sasl_dispose(&client->saslconn);
        client->saslconn = NULL;
        return -1;
    }
    if (val == NULL) {
        VIR_ERROR(_("no client username was found"));
        remoteDispatchAuthError(rerr);
        sasl_dispose(&client->saslconn);
        client->saslconn = NULL;
        return -1;
    }
    VIR_DEBUG("SASL client username %s", (const char *)val);

    client->saslUsername = strdup((const char*)val);
    if (client->saslUsername == NULL) {
        VIR_ERROR(_("out of memory copying username"));
        remoteDispatchAuthError(rerr);
        sasl_dispose(&client->saslconn);
        client->saslconn = NULL;
        return -1;
    }

    /* If the list is not set, allow any DN. */
    wildcards = server->saslUsernameWhitelist;
    if (!wildcards)
        return 0; /* No ACL, allow all */

    while (*wildcards) {
        if (fnmatch(*wildcards, client->saslUsername, 0) == 0)
            return 0; /* Allowed */
        wildcards++;
    }

    /* Denied */
    VIR_ERROR(_("SASL client %s not allowed in whitelist"), client->saslUsername);
    remoteDispatchAuthError(rerr);
    sasl_dispose(&client->saslconn);
    client->saslconn = NULL;
    return -2;
}


/*
 * This starts the SASL authentication negotiation.
 */
static int
remoteDispatchAuthSaslStart(struct qemud_server *server,
                            struct qemud_client *client,
                            virConnectPtr conn ATTRIBUTE_UNUSED,
                            remote_message_header *hdr ATTRIBUTE_UNUSED,
                            remote_error *rerr,
                            remote_auth_sasl_start_args *args,
                            remote_auth_sasl_start_ret *ret)
{
    const char *serverout;
    unsigned int serveroutlen;
    int err;

    virMutexLock(&server->lock);
    virMutexLock(&client->lock);
    virMutexUnlock(&server->lock);

    VIR_DEBUG("Start SASL auth %d", client->fd);
    if (client->auth != REMOTE_AUTH_SASL ||
        client->saslconn == NULL) {
        VIR_ERROR(_("client tried invalid SASL start request"));
        goto authfail;
    }

    VIR_DEBUG("Using SASL mechanism %s. Data %d bytes, nil: %d",
              args->mech, args->data.data_len, args->nil);
    err = sasl_server_start(client->saslconn,
                            args->mech,
                            /* NB, distinction of NULL vs "" is *critical* in SASL */
                            args->nil ? NULL : args->data.data_val,
                            args->data.data_len,
                            &serverout,
                            &serveroutlen);
    if (err != SASL_OK &&
        err != SASL_CONTINUE) {
        VIR_ERROR(_("sasl start failed %d (%s)"),
                  err, sasl_errdetail(client->saslconn));
        sasl_dispose(&client->saslconn);
        client->saslconn = NULL;
        goto authfail;
    }
    if (serveroutlen > REMOTE_AUTH_SASL_DATA_MAX) {
        VIR_ERROR(_("sasl start reply data too long %d"), serveroutlen);
        sasl_dispose(&client->saslconn);
        client->saslconn = NULL;
        goto authfail;
    }

    /* NB, distinction of NULL vs "" is *critical* in SASL */
    if (serverout) {
        if (VIR_ALLOC_N(ret->data.data_val, serveroutlen) < 0) {
            virReportOOMError();
            remoteDispatchError(rerr);
            goto error;
        }
        memcpy(ret->data.data_val, serverout, serveroutlen);
    } else {
        ret->data.data_val = NULL;
    }
    ret->nil = serverout ? 0 : 1;
    ret->data.data_len = serveroutlen;

    VIR_DEBUG("SASL return data %d bytes, nil; %d", ret->data.data_len, ret->nil);
    if (err == SASL_CONTINUE) {
        ret->complete = 0;
    } else {
        /* Check username whitelist ACL */
        if ((err = remoteSASLCheckAccess(server, client, rerr)) < 0 ||
            (err = remoteSASLCheckSSF(client, rerr)) < 0) {
            if (err == -2)
                goto authdeny;
            else
                goto authfail;
        }

        VIR_DEBUG("Authentication successful %d", client->fd);
        PROBE(CLIENT_AUTH_ALLOW, "fd=%d, auth=%d, username=%s",
              client->fd, REMOTE_AUTH_SASL, client->saslUsername);
        ret->complete = 1;
        client->auth = REMOTE_AUTH_NONE;
    }

    virMutexUnlock(&client->lock);
    return 0;

authfail:
    PROBE(CLIENT_AUTH_FAIL, "fd=%d, auth=%d", client->fd, REMOTE_AUTH_SASL);
    remoteDispatchAuthError(rerr);
    goto error;

authdeny:
    PROBE(CLIENT_AUTH_DENY, "fd=%d, auth=%d, username=%s",
          client->fd, REMOTE_AUTH_SASL, client->saslUsername);
    goto error;

error:
    virMutexUnlock(&client->lock);
    return -1;
}


static int
remoteDispatchAuthSaslStep(struct qemud_server *server,
                           struct qemud_client *client,
                           virConnectPtr conn ATTRIBUTE_UNUSED,
                           remote_message_header *hdr ATTRIBUTE_UNUSED,
                           remote_error *rerr,
                           remote_auth_sasl_step_args *args,
                           remote_auth_sasl_step_ret *ret)
{
    const char *serverout;
    unsigned int serveroutlen;
    int err;

    virMutexLock(&server->lock);
    virMutexLock(&client->lock);
    virMutexUnlock(&server->lock);

    VIR_DEBUG("Step SASL auth %d", client->fd);
    if (client->auth != REMOTE_AUTH_SASL ||
        client->saslconn == NULL) {
        VIR_ERROR(_("client tried invalid SASL start request"));
        goto authfail;
    }

    VIR_DEBUG("Using SASL Data %d bytes, nil: %d",
              args->data.data_len, args->nil);
    err = sasl_server_step(client->saslconn,
                           /* NB, distinction of NULL vs "" is *critical* in SASL */
                           args->nil ? NULL : args->data.data_val,
                           args->data.data_len,
                           &serverout,
                           &serveroutlen);
    if (err != SASL_OK &&
        err != SASL_CONTINUE) {
        VIR_ERROR(_("sasl step failed %d (%s)"),
                  err, sasl_errdetail(client->saslconn));
        sasl_dispose(&client->saslconn);
        client->saslconn = NULL;
        goto authfail;
    }

    if (serveroutlen > REMOTE_AUTH_SASL_DATA_MAX) {
        VIR_ERROR(_("sasl step reply data too long %d"),
                  serveroutlen);
        sasl_dispose(&client->saslconn);
        client->saslconn = NULL;
        goto authfail;
    }

    /* NB, distinction of NULL vs "" is *critical* in SASL */
    if (serverout) {
        if (VIR_ALLOC_N(ret->data.data_val, serveroutlen) < 0) {
            virReportOOMError();
            remoteDispatchError(rerr);
            goto error;
        }
        memcpy(ret->data.data_val, serverout, serveroutlen);
    } else {
        ret->data.data_val = NULL;
    }
    ret->nil = serverout ? 0 : 1;
    ret->data.data_len = serveroutlen;

    VIR_DEBUG("SASL return data %d bytes, nil; %d", ret->data.data_len, ret->nil);
    if (err == SASL_CONTINUE) {
        ret->complete = 0;
    } else {
        /* Check username whitelist ACL */
        if ((err = remoteSASLCheckAccess(server, client, rerr)) < 0 ||
            (err = remoteSASLCheckSSF(client, rerr)) < 0) {
            if (err == -2)
                goto authdeny;
            else
                goto authfail;
        }

        VIR_DEBUG("Authentication successful %d", client->fd);
        PROBE(CLIENT_AUTH_ALLOW, "fd=%d, auth=%d, username=%s",
              client->fd, REMOTE_AUTH_SASL, client->saslUsername);
        ret->complete = 1;
        client->auth = REMOTE_AUTH_NONE;
    }

    virMutexUnlock(&client->lock);
    return 0;

authfail:
    PROBE(CLIENT_AUTH_FAIL, "fd=%d, auth=%d", client->fd, REMOTE_AUTH_SASL);
    remoteDispatchAuthError(rerr);
    goto error;

authdeny:
    PROBE(CLIENT_AUTH_DENY, "fd=%d, auth=%d, username=%s",
          client->fd, REMOTE_AUTH_SASL, client->saslUsername);
    goto error;

error:
    virMutexUnlock(&client->lock);
    return -1;
}


#else /* HAVE_SASL */
static int
remoteDispatchAuthSaslInit(struct qemud_server *server ATTRIBUTE_UNUSED,
                           struct qemud_client *client ATTRIBUTE_UNUSED,
                           virConnectPtr conn ATTRIBUTE_UNUSED,
                           remote_message_header *hdr ATTRIBUTE_UNUSED,
                           remote_error *rerr,
                           void *args ATTRIBUTE_UNUSED,
                           remote_auth_sasl_init_ret *ret ATTRIBUTE_UNUSED)
{
    VIR_ERROR(_("client tried unsupported SASL init request"));
    PROBE(CLIENT_AUTH_FAIL, "fd=%d, auth=%d", client->fd, REMOTE_AUTH_SASL);
    remoteDispatchAuthError(rerr);
    return -1;
}

static int
remoteDispatchAuthSaslStart(struct qemud_server *server ATTRIBUTE_UNUSED,
                            struct qemud_client *client ATTRIBUTE_UNUSED,
                            virConnectPtr conn ATTRIBUTE_UNUSED,
                            remote_message_header *hdr ATTRIBUTE_UNUSED,
                            remote_error *rerr,
                            remote_auth_sasl_start_args *args ATTRIBUTE_UNUSED,
                            remote_auth_sasl_start_ret *ret ATTRIBUTE_UNUSED)
{
    VIR_ERROR(_("client tried unsupported SASL start request"));
    PROBE(CLIENT_AUTH_FAIL, "fd=%d, auth=%d", client->fd, REMOTE_AUTH_SASL);
    remoteDispatchAuthError(rerr);
    return -1;
}

static int
remoteDispatchAuthSaslStep(struct qemud_server *server ATTRIBUTE_UNUSED,
                           struct qemud_client *client ATTRIBUTE_UNUSED,
                           virConnectPtr conn ATTRIBUTE_UNUSED,
                           remote_message_header *hdr ATTRIBUTE_UNUSED,
                           remote_error *rerr,
                           remote_auth_sasl_step_args *args ATTRIBUTE_UNUSED,
                           remote_auth_sasl_step_ret *ret ATTRIBUTE_UNUSED)
{
    VIR_ERROR(_("client tried unsupported SASL step request"));
    PROBE(CLIENT_AUTH_FAIL, "fd=%d, auth=%d", client->fd, REMOTE_AUTH_SASL);
    remoteDispatchAuthError(rerr);
    return -1;
}
#endif /* HAVE_SASL */


#if HAVE_POLKIT1
static int
remoteDispatchAuthPolkit(struct qemud_server *server,
                         struct qemud_client *client,
                         virConnectPtr conn ATTRIBUTE_UNUSED,
                         remote_message_header *hdr ATTRIBUTE_UNUSED,
                         remote_error *rerr,
                         void *args ATTRIBUTE_UNUSED,
                         remote_auth_polkit_ret *ret)
{
    pid_t callerPid = -1;
    uid_t callerUid = -1;
    const char *action;
    int status = -1;
    char pidbuf[50];
    char ident[100];
    int rv;

    memset(ident, 0, sizeof ident);

    virMutexLock(&server->lock);
    virMutexLock(&client->lock);
    virMutexUnlock(&server->lock);

    action = client->readonly ?
        "org.libvirt.unix.monitor" :
        "org.libvirt.unix.manage";

    const char * const pkcheck [] = {
      PKCHECK_PATH,
      "--action-id", action,
      "--process", pidbuf,
      "--allow-user-interaction",
      NULL
    };

    VIR_DEBUG("Start PolicyKit auth %d", client->fd);
    if (client->auth != REMOTE_AUTH_POLKIT) {
        VIR_ERROR(_("client tried invalid PolicyKit init request"));
        goto authfail;
    }

    if (qemudGetSocketIdentity(client->fd, &callerUid, &callerPid) < 0) {
        VIR_ERROR(_("cannot get peer socket identity"));
        goto authfail;
    }

    VIR_INFO("Checking PID %d running as %d", callerPid, callerUid);

    rv = snprintf(pidbuf, sizeof pidbuf, "%d", callerPid);
    if (rv < 0 || rv >= sizeof pidbuf) {
        VIR_ERROR(_("Caller PID was too large %d"), callerPid);
        goto authfail;
    }

    rv = snprintf(ident, sizeof ident, "pid:%d,uid:%d", callerPid, callerUid);
    if (rv < 0 || rv >= sizeof ident) {
        VIR_ERROR(_("Caller identity was too large %d:%d"), callerPid, callerUid);
        goto authfail;
    }

    if (virRun(pkcheck, &status) < 0) {
        VIR_ERROR(_("Cannot invoke %s"), PKCHECK_PATH);
        goto authfail;
    }
    if (status != 0) {
        char *tmp = virCommandTranslateStatus(status);
        VIR_ERROR(_("Policy kit denied action %s from pid %d, uid %d: %s"),
                  action, callerPid, callerUid, NULLSTR(tmp));
        VIR_FREE(tmp);
        goto authdeny;
    }
    PROBE(CLIENT_AUTH_ALLOW, "fd=%d, auth=%d, username=%s",
          client->fd, REMOTE_AUTH_POLKIT, (char *)ident);
    VIR_INFO("Policy allowed action %s from pid %d, uid %d",
             action, callerPid, callerUid);
    ret->complete = 1;
    client->auth = REMOTE_AUTH_NONE;

    virMutexUnlock(&client->lock);
    return 0;

authfail:
    PROBE(CLIENT_AUTH_FAIL, "fd=%d, auth=%d", client->fd, REMOTE_AUTH_POLKIT);
    goto error;

authdeny:
    PROBE(CLIENT_AUTH_DENY, "fd=%d, auth=%d, username=%s",
          client->fd, REMOTE_AUTH_POLKIT, (char *)ident);
    goto error;

error:
    remoteDispatchAuthError(rerr);
    virMutexUnlock(&client->lock);
    return -1;
}
#elif HAVE_POLKIT0
static int
remoteDispatchAuthPolkit(struct qemud_server *server,
                         struct qemud_client *client,
                         virConnectPtr conn ATTRIBUTE_UNUSED,
                         remote_message_header *hdr ATTRIBUTE_UNUSED,
                         remote_error *rerr,
                         void *args ATTRIBUTE_UNUSED,
                         remote_auth_polkit_ret *ret)
{
    pid_t callerPid;
    uid_t callerUid;
    PolKitCaller *pkcaller = NULL;
    PolKitAction *pkaction = NULL;
    PolKitContext *pkcontext = NULL;
    PolKitError *pkerr = NULL;
    PolKitResult pkresult;
    DBusError err;
    const char *action;
    char ident[100];
    int rv;

    memset(ident, 0, sizeof ident);

    virMutexLock(&server->lock);
    virMutexLock(&client->lock);
    virMutexUnlock(&server->lock);

    action = client->readonly ?
        "org.libvirt.unix.monitor" :
        "org.libvirt.unix.manage";

    VIR_DEBUG("Start PolicyKit auth %d", client->fd);
    if (client->auth != REMOTE_AUTH_POLKIT) {
        VIR_ERROR(_("client tried invalid PolicyKit init request"));
        goto authfail;
    }

    if (qemudGetSocketIdentity(client->fd, &callerUid, &callerPid) < 0) {
        VIR_ERROR(_("cannot get peer socket identity"));
        goto authfail;
    }

    rv = snprintf(ident, sizeof ident, "pid:%d,uid:%d", callerPid, callerUid);
    if (rv < 0 || rv >= sizeof ident) {
        VIR_ERROR(_("Caller identity was too large %d:%d"), callerPid, callerUid);
        goto authfail;
    }

    VIR_INFO("Checking PID %d running as %d", callerPid, callerUid);
    dbus_error_init(&err);
    if (!(pkcaller = polkit_caller_new_from_pid(server->sysbus,
                                                callerPid, &err))) {
        VIR_ERROR(_("Failed to lookup policy kit caller: %s"), err.message);
        dbus_error_free(&err);
        goto authfail;
    }

    if (!(pkaction = polkit_action_new())) {
        char ebuf[1024];
        VIR_ERROR(_("Failed to create polkit action %s"),
                  virStrerror(errno, ebuf, sizeof ebuf));
        polkit_caller_unref(pkcaller);
        goto authfail;
    }
    polkit_action_set_action_id(pkaction, action);

    if (!(pkcontext = polkit_context_new()) ||
        !polkit_context_init(pkcontext, &pkerr)) {
        char ebuf[1024];
        VIR_ERROR(_("Failed to create polkit context %s"),
                  (pkerr ? polkit_error_get_error_message(pkerr)
                   : virStrerror(errno, ebuf, sizeof ebuf)));
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
        VIR_ERROR(_("Policy kit denied action %s from pid %d, uid %d, result: %s"),
                  action, callerPid, callerUid,
                  polkit_result_to_string_representation(pkresult));
        goto authdeny;
    }
    PROBE(CLIENT_AUTH_ALLOW, "fd=%d, auth=%d, username=%s",
          client->fd, REMOTE_AUTH_POLKIT, ident);
    VIR_INFO("Policy allowed action %s from pid %d, uid %d, result %s",
             action, callerPid, callerUid,
             polkit_result_to_string_representation(pkresult));
    ret->complete = 1;
    client->auth = REMOTE_AUTH_NONE;

    virMutexUnlock(&client->lock);
    return 0;

authfail:
    PROBE(CLIENT_AUTH_FAIL, "fd=%d, auth=%d", client->fd, REMOTE_AUTH_POLKIT);
    goto error;

authdeny:
    PROBE(CLIENT_AUTH_DENY, "fd=%d, auth=%d, username=%s",
          client->fd, REMOTE_AUTH_POLKIT, ident);
    goto error;

error:
    remoteDispatchAuthError(rerr);
    virMutexUnlock(&client->lock);
    return -1;
}

#else /* !HAVE_POLKIT0 & !HAVE_POLKIT1*/

static int
remoteDispatchAuthPolkit(struct qemud_server *server ATTRIBUTE_UNUSED,
                         struct qemud_client *client ATTRIBUTE_UNUSED,
                         virConnectPtr conn ATTRIBUTE_UNUSED,
                         remote_message_header *hdr ATTRIBUTE_UNUSED,
                         remote_error *rerr,
                         void *args ATTRIBUTE_UNUSED,
                         remote_auth_polkit_ret *ret ATTRIBUTE_UNUSED)
{
    VIR_ERROR(_("client tried unsupported PolicyKit init request"));
    remoteDispatchAuthError(rerr);
    return -1;
}
#endif /* HAVE_POLKIT1 */


/***************************************************************
 *     NODE INFO APIS
 **************************************************************/

static int
remoteDispatchNodeDeviceGetParent(struct qemud_server *server ATTRIBUTE_UNUSED,
                                  struct qemud_client *client ATTRIBUTE_UNUSED,
                                  virConnectPtr conn,
                                  remote_message_header *hdr ATTRIBUTE_UNUSED,
                                  remote_error *rerr,
                                  remote_node_device_get_parent_args *args,
                                  remote_node_device_get_parent_ret *ret)
{
    virNodeDevicePtr dev = NULL;
    const char *parent = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dev = virNodeDeviceLookupByName(conn, args->name)))
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
        remoteDispatchError(rerr);
    if (dev)
        virNodeDeviceFree(dev);
    return rv;
}


/***************************
 * Register / deregister events
 ***************************/
static int
remoteDispatchDomainEventsRegister(struct qemud_server *server ATTRIBUTE_UNUSED,
                                   struct qemud_client *client ATTRIBUTE_UNUSED,
                                   virConnectPtr conn,
                                   remote_message_header *hdr ATTRIBUTE_UNUSED,
                                   remote_error *rerr ATTRIBUTE_UNUSED,
                                   void *args ATTRIBUTE_UNUSED,
                                   remote_domain_events_register_ret *ret ATTRIBUTE_UNUSED)
{
    int callbackID;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (client->domainEventCallbackID[VIR_DOMAIN_EVENT_ID_LIFECYCLE] != -1) {
        virNetError(VIR_ERR_INTERNAL_ERROR, _("domain event %d already registered"), VIR_DOMAIN_EVENT_ID_LIFECYCLE);
        goto cleanup;
    }

    if ((callbackID = virConnectDomainEventRegisterAny(conn,
                                                       NULL,
                                                       VIR_DOMAIN_EVENT_ID_LIFECYCLE,
                                                       VIR_DOMAIN_EVENT_CALLBACK(remoteRelayDomainEventLifecycle),
                                                       client, NULL)) < 0)
        goto cleanup;

    client->domainEventCallbackID[VIR_DOMAIN_EVENT_ID_LIFECYCLE] = callbackID;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    return rv;
}

static int
remoteDispatchDomainEventsDeregister(struct qemud_server *server ATTRIBUTE_UNUSED,
                                     struct qemud_client *client ATTRIBUTE_UNUSED,
                                     virConnectPtr conn,
                                     remote_message_header *hdr ATTRIBUTE_UNUSED,
                                     remote_error *rerr ATTRIBUTE_UNUSED,
                                     void *args ATTRIBUTE_UNUSED,
                                     remote_domain_events_deregister_ret *ret ATTRIBUTE_UNUSED)
{
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (client->domainEventCallbackID[VIR_DOMAIN_EVENT_ID_LIFECYCLE] < 0) {
        virNetError(VIR_ERR_INTERNAL_ERROR, _("domain event %d not registered"), VIR_DOMAIN_EVENT_ID_LIFECYCLE);
        goto cleanup;
    }

    if (virConnectDomainEventDeregisterAny(conn,
                                           client->domainEventCallbackID[VIR_DOMAIN_EVENT_ID_LIFECYCLE]) < 0)
        goto cleanup;

    client->domainEventCallbackID[VIR_DOMAIN_EVENT_ID_LIFECYCLE] = -1;
    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    return rv;
}

static void
remoteDispatchDomainEventSend(struct qemud_client *client,
                              int procnr,
                              xdrproc_t proc,
                              void *data)
{
    struct qemud_client_message *msg = NULL;
    XDR xdr;
    unsigned int len;

    if (VIR_ALLOC(msg) < 0)
        return;

    msg->hdr.prog = REMOTE_PROGRAM;
    msg->hdr.vers = REMOTE_PROTOCOL_VERSION;
    msg->hdr.proc = procnr;
    msg->hdr.type = REMOTE_MESSAGE;
    msg->hdr.serial = 1;
    msg->hdr.status = REMOTE_OK;

    if (remoteEncodeClientMessageHeader(msg) < 0)
        goto cleanup;

    /* Serialise the return header and event. */
    xdrmem_create(&xdr,
                  msg->buffer,
                  msg->bufferLength,
                  XDR_ENCODE);

    /* Skip over the header we just wrote */
    if (xdr_setpos(&xdr, msg->bufferOffset) == 0)
        goto xdr_cleanup;

    if (!(proc)(&xdr, data)) {
        VIR_WARN("Failed to serialize domain event %d", procnr);
        goto xdr_cleanup;
    }

    /* Update length word to include payload*/
    len = msg->bufferOffset = xdr_getpos(&xdr);
    if (xdr_setpos(&xdr, 0) == 0)
        goto xdr_cleanup;

    if (!xdr_u_int(&xdr, &len))
        goto xdr_cleanup;

    /* Send it. */
    msg->async = 1;
    msg->bufferLength = len;
    msg->bufferOffset = 0;

    VIR_DEBUG("Queue event %d %d", procnr, msg->bufferLength);
    qemudClientMessageQueuePush(&client->tx, msg);
    qemudUpdateClientEvent(client);

    xdr_destroy(&xdr);
    return;

xdr_cleanup:
    xdr_destroy(&xdr);
cleanup:
    VIR_FREE(msg);
}

static int
remoteDispatchSecretGetValue(struct qemud_server *server ATTRIBUTE_UNUSED,
                             struct qemud_client *client ATTRIBUTE_UNUSED,
                             virConnectPtr conn,
                             remote_message_header *hdr ATTRIBUTE_UNUSED,
                             remote_error *rerr,
                             remote_secret_get_value_args *args,
                             remote_secret_get_value_ret *ret)
{
    virSecretPtr secret = NULL;
    size_t value_size;
    unsigned char *value;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(secret = get_nonnull_secret(conn, args->secret)))
        goto cleanup;

    if (!(value = virSecretGetValue(secret, &value_size, args->flags)))
        goto cleanup;

    ret->value.value_len = value_size;
    ret->value.value_val = (char *)value;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (secret)
        virSecretFree(secret);
    return rv;
}

static int
remoteDispatchDomainGetState(struct qemud_server *server ATTRIBUTE_UNUSED,
                             struct qemud_client *client ATTRIBUTE_UNUSED,
                             virConnectPtr conn,
                             remote_message_header *hdr ATTRIBUTE_UNUSED,
                             remote_error *rerr,
                             remote_domain_get_state_args *args,
                             remote_domain_get_state_ret *ret)
{
    virDomainPtr dom = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(conn, args->dom)))
        goto cleanup;

    if (virDomainGetState(dom, &ret->state, &ret->reason, args->flags) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (dom)
        virDomainFree(dom);
    return rv;
}

static int
remoteDispatchDomainEventsRegisterAny(struct qemud_server *server ATTRIBUTE_UNUSED,
                                      struct qemud_client *client ATTRIBUTE_UNUSED,
                                      virConnectPtr conn,
                                      remote_message_header *hdr ATTRIBUTE_UNUSED,
                                      remote_error *rerr ATTRIBUTE_UNUSED,
                                      remote_domain_events_register_any_args *args,
                                      void *ret ATTRIBUTE_UNUSED)
{
    int callbackID;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (args->eventID >= VIR_DOMAIN_EVENT_ID_LAST ||
        args->eventID < 0) {
        virNetError(VIR_ERR_INTERNAL_ERROR, _("unsupported event ID %d"), args->eventID);
        goto cleanup;
    }

    if (client->domainEventCallbackID[args->eventID] != -1)  {
        virNetError(VIR_ERR_INTERNAL_ERROR, _("domain event %d already registered"), args->eventID);
        goto cleanup;
    }

    if ((callbackID = virConnectDomainEventRegisterAny(conn,
                                                       NULL,
                                                       args->eventID,
                                                       domainEventCallbacks[args->eventID],
                                                       client, NULL)) < 0)
        goto cleanup;

    client->domainEventCallbackID[args->eventID] = callbackID;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    return rv;
}


static int
remoteDispatchDomainEventsDeregisterAny(struct qemud_server *server ATTRIBUTE_UNUSED,
                                        struct qemud_client *client ATTRIBUTE_UNUSED,
                                        virConnectPtr conn,
                                        remote_message_header *hdr ATTRIBUTE_UNUSED,
                                        remote_error *rerr ATTRIBUTE_UNUSED,
                                        remote_domain_events_deregister_any_args *args,
                                        void *ret ATTRIBUTE_UNUSED)
{
    int callbackID = -1;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (args->eventID >= VIR_DOMAIN_EVENT_ID_LAST ||
        args->eventID < 0) {
        virNetError(VIR_ERR_INTERNAL_ERROR, _("unsupported event ID %d"), args->eventID);
        goto cleanup;
    }

    if ((callbackID = client->domainEventCallbackID[args->eventID]) < 0) {
        virNetError(VIR_ERR_INTERNAL_ERROR, _("domain event %d not registered"), args->eventID);
        goto cleanup;
    }

    if (virConnectDomainEventDeregisterAny(conn, callbackID) < 0)
        goto cleanup;

    client->domainEventCallbackID[args->eventID] = -1;
    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    return rv;
}

static int
qemuDispatchMonitorCommand(struct qemud_server *server ATTRIBUTE_UNUSED,
                           struct qemud_client *client ATTRIBUTE_UNUSED,
                           virConnectPtr conn,
                           remote_message_header *hdr ATTRIBUTE_UNUSED,
                           remote_error *rerr,
                           qemu_monitor_command_args *args,
                           qemu_monitor_command_ret *ret)
{
    virDomainPtr dom = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(conn, args->dom)))
        goto cleanup;

    if (virDomainQemuMonitorCommand(dom, args->cmd, &ret->result,
                                    args->flags) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (dom)
        virDomainFree(dom);
    return rv;
}


#include "remote_dispatch_bodies.h"
#include "qemu_dispatch_bodies.h"


static int
remoteDispatchDomainMigrateBegin3(struct qemud_server *server ATTRIBUTE_UNUSED,
                                  struct qemud_client *client ATTRIBUTE_UNUSED,
                                  virConnectPtr conn,
                                  remote_message_header *hdr ATTRIBUTE_UNUSED,
                                  remote_error *rerr,
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

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(conn, args->dom)))
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
        remoteDispatchError(rerr);
    if (dom)
        virDomainFree(dom);
    return rv;
}


static int
remoteDispatchDomainMigratePrepare3(struct qemud_server *server ATTRIBUTE_UNUSED,
                                    struct qemud_client *client ATTRIBUTE_UNUSED,
                                    virConnectPtr conn,
                                    remote_message_header *hdr ATTRIBUTE_UNUSED,
                                    remote_error *rerr,
                                    remote_domain_migrate_prepare3_args *args,
                                    remote_domain_migrate_prepare3_ret *ret)
{
    char *cookieout = NULL;
    int cookieoutlen = 0;
    char *uri_in;
    char **uri_out;
    char *dname;
    int rv = -1;

    if (!conn) {
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

    if (virDomainMigratePrepare3(conn,
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
        remoteDispatchError(rerr);
        VIR_FREE(uri_out);
    }
    return rv;
}

static int
remoteDispatchDomainMigratePerform3(struct qemud_server *server ATTRIBUTE_UNUSED,
                                    struct qemud_client *client ATTRIBUTE_UNUSED,
                                    virConnectPtr conn,
                                    remote_message_header *hdr ATTRIBUTE_UNUSED,
                                    remote_error *rerr,
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

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(conn, args->dom)))
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
        remoteDispatchError(rerr);
    if (dom)
        virDomainFree(dom);
    return rv;
}


static int
remoteDispatchDomainMigrateFinish3(struct qemud_server *server ATTRIBUTE_UNUSED,
                                   struct qemud_client *client ATTRIBUTE_UNUSED,
                                   virConnectPtr conn,
                                   remote_message_header *hdr ATTRIBUTE_UNUSED,
                                   remote_error *rerr,
                                   remote_domain_migrate_finish3_args *args,
                                   remote_domain_migrate_finish3_ret *ret)
{
    virDomainPtr dom = NULL;
    char *cookieout = NULL;
    int cookieoutlen = 0;
    char *uri;
    char *dconnuri;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    uri = args->uri == NULL ? NULL : *args->uri;
    dconnuri = args->dconnuri == NULL ? NULL : *args->dconnuri;

    if (!(dom = virDomainMigrateFinish3(conn, args->dname,
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
        remoteDispatchError(rerr);
        VIR_FREE(cookieout);
    }
    if (dom)
        virDomainFree(dom);
    return rv;
}


static int
remoteDispatchDomainMigrateConfirm3(struct qemud_server *server ATTRIBUTE_UNUSED,
                                    struct qemud_client *client ATTRIBUTE_UNUSED,
                                    virConnectPtr conn,
                                    remote_message_header *hdr ATTRIBUTE_UNUSED,
                                    remote_error *rerr,
                                    remote_domain_migrate_confirm3_args *args,
                                    void *ret ATTRIBUTE_UNUSED)
{
    virDomainPtr dom = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(conn, args->dom)))
        goto cleanup;

    if (virDomainMigrateConfirm3(dom,
                                 args->cookie_in.cookie_in_val,
                                 args->cookie_in.cookie_in_len,
                                 args->flags, args->cancelled) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (dom)
        virDomainFree(dom);
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
