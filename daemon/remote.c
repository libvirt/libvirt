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
        VIR_WARN0("cannot allocate memory for graphics event subject");
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


static virConnectDomainEventGenericCallback domainEventCallbacks[] = {
    VIR_DOMAIN_EVENT_CALLBACK(remoteRelayDomainEventLifecycle),
    VIR_DOMAIN_EVENT_CALLBACK(remoteRelayDomainEventReboot),
    VIR_DOMAIN_EVENT_CALLBACK(remoteRelayDomainEventRTCChange),
    VIR_DOMAIN_EVENT_CALLBACK(remoteRelayDomainEventWatchdog),
    VIR_DOMAIN_EVENT_CALLBACK(remoteRelayDomainEventIOError),
    VIR_DOMAIN_EVENT_CALLBACK(remoteRelayDomainEventGraphics),
    VIR_DOMAIN_EVENT_CALLBACK(remoteRelayDomainEventIOErrorReason),
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
remoteDispatchSupportsFeature(struct qemud_server *server ATTRIBUTE_UNUSED,
                              struct qemud_client *client ATTRIBUTE_UNUSED,
                              virConnectPtr conn,
                              remote_message_header *hdr ATTRIBUTE_UNUSED,
                              remote_error *rerr,
                              remote_supports_feature_args *args, remote_supports_feature_ret *ret)
{
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if ((ret->supported = virDrvSupportsFeature(conn, args->feature)) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    return rv;
}

static int
remoteDispatchGetType(struct qemud_server *server ATTRIBUTE_UNUSED,
                      struct qemud_client *client ATTRIBUTE_UNUSED,
                      virConnectPtr conn,
                      remote_message_header *hdr ATTRIBUTE_UNUSED,
                      remote_error *rerr,
                      void *args ATTRIBUTE_UNUSED, remote_get_type_ret *ret)
{
    const char *type;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(type = virConnectGetType(conn)))
        goto cleanup;

    /* We have to strdup because remoteDispatchClientRequest will
     * free this string after it's been serialised.
     */
    if (!(ret->type = strdup(type))) {
        virReportOOMError();
        goto cleanup;
    }

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    return rv;
}

static int
remoteDispatchGetVersion(struct qemud_server *server ATTRIBUTE_UNUSED,
                         struct qemud_client *client ATTRIBUTE_UNUSED,
                         virConnectPtr conn,
                         remote_message_header *hdr ATTRIBUTE_UNUSED,
                         remote_error *rerr,
                         void *args ATTRIBUTE_UNUSED,
                         remote_get_version_ret *ret)
{
    unsigned long hvVer;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (virConnectGetVersion(conn, &hvVer) < 0)
        goto cleanup;

    ret->hv_ver = hvVer;
    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    return rv;
}

static int
remoteDispatchGetLibVersion(struct qemud_server *server ATTRIBUTE_UNUSED,
                            struct qemud_client *client ATTRIBUTE_UNUSED,
                            virConnectPtr conn,
                            remote_message_header *hdr ATTRIBUTE_UNUSED,
                            remote_error *rerr,
                            void *args ATTRIBUTE_UNUSED,
                            remote_get_lib_version_ret *ret)
{
    unsigned long libVer;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (virConnectGetLibVersion(conn, &libVer) < 0)
        goto cleanup;

    ret->lib_ver = libVer;
    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    return rv;
}

static int
remoteDispatchGetHostname(struct qemud_server *server ATTRIBUTE_UNUSED,
                          struct qemud_client *client ATTRIBUTE_UNUSED,
                          virConnectPtr conn,
                          remote_message_header *hdr ATTRIBUTE_UNUSED,
                          remote_error *rerr,
                          void *args ATTRIBUTE_UNUSED,
                          remote_get_hostname_ret *ret)
{
    char *hostname;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(hostname = virConnectGetHostname(conn)))
        goto cleanup;

    ret->hostname = hostname;
    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    return rv;
}

static int
remoteDispatchGetUri(struct qemud_server *server ATTRIBUTE_UNUSED,
                     struct qemud_client *client ATTRIBUTE_UNUSED,
                     virConnectPtr conn,
                     remote_message_header *hdr ATTRIBUTE_UNUSED,
                     remote_error *rerr,
                     void *args ATTRIBUTE_UNUSED,
                     remote_get_uri_ret *ret)
{
    char *uri;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(uri = virConnectGetURI(conn)))
        goto cleanup;

    ret->uri = uri;
    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    return rv;
}

static int
remoteDispatchGetSysinfo(struct qemud_server *server ATTRIBUTE_UNUSED,
                         struct qemud_client *client ATTRIBUTE_UNUSED,
                         virConnectPtr conn,
                         remote_message_header *hdr ATTRIBUTE_UNUSED,
                         remote_error *rerr,
                         remote_get_sysinfo_args *args,
                         remote_get_sysinfo_ret *ret)
{
    unsigned int flags;
    char *sysinfo;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    flags = args->flags;
    if (!(sysinfo = virConnectGetSysinfo(conn, flags)))
        goto cleanup;

    ret->sysinfo = sysinfo;
    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    return rv;
}

static int
remoteDispatchGetMaxVcpus(struct qemud_server *server ATTRIBUTE_UNUSED,
                          struct qemud_client *client ATTRIBUTE_UNUSED,
                          virConnectPtr conn,
                          remote_message_header *hdr ATTRIBUTE_UNUSED,
                          remote_error *rerr,
                          remote_get_max_vcpus_args *args,
                          remote_get_max_vcpus_ret *ret)
{
    char *type;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    type = args->type ? *args->type : NULL;
    if ((ret->max_vcpus = virConnectGetMaxVcpus(conn, type)) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    return rv;
}

static int
remoteDispatchNodeGetInfo(struct qemud_server *server ATTRIBUTE_UNUSED,
                          struct qemud_client *client ATTRIBUTE_UNUSED,
                          virConnectPtr conn,
                          remote_message_header *hdr ATTRIBUTE_UNUSED,
                          remote_error *rerr,
                          void *args ATTRIBUTE_UNUSED,
                          remote_node_get_info_ret *ret)
{
    virNodeInfo info;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (virNodeGetInfo(conn, &info) < 0)
        goto cleanup;

    memcpy(ret->model, info.model, sizeof ret->model);
    ret->memory = info.memory;
    ret->cpus = info.cpus;
    ret->mhz = info.mhz;
    ret->nodes = info.nodes;
    ret->sockets = info.sockets;
    ret->cores = info.cores;
    ret->threads = info.threads;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    return rv;
}

static int
remoteDispatchGetCapabilities(struct qemud_server *server ATTRIBUTE_UNUSED,
                              struct qemud_client *client ATTRIBUTE_UNUSED,
                              virConnectPtr conn,
                              remote_message_header *hdr ATTRIBUTE_UNUSED,
                              remote_error *rerr,
                              void *args ATTRIBUTE_UNUSED,
                              remote_get_capabilities_ret *ret)
{
    char *caps;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(caps = virConnectGetCapabilities(conn)))
        goto cleanup;

    ret->capabilities = caps;
    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    return rv;
}

static int
remoteDispatchNodeGetCellsFreeMemory(struct qemud_server *server ATTRIBUTE_UNUSED,
                                     struct qemud_client *client ATTRIBUTE_UNUSED,
                                     virConnectPtr conn,
                                     remote_message_header *hdr ATTRIBUTE_UNUSED,
                                     remote_error *rerr,
                                     remote_node_get_cells_free_memory_args *args,
                                     remote_node_get_cells_free_memory_ret *ret)
{
    int len;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (args->maxCells > REMOTE_NODE_MAX_CELLS) {
        virNetError(VIR_ERR_INTERNAL_ERROR,
                    "%s", _("maxCells > REMOTE_NODE_MAX_CELLS"));
        goto cleanup;
    }

    /* Allocate return buffer. */
    if (VIR_ALLOC_N(ret->freeMems.freeMems_val, args->maxCells) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    len = virNodeGetCellsFreeMemory(conn,
                                    (unsigned long long *)ret->freeMems.freeMems_val,
                                    args->startCell,
                                    args->maxCells);
    if (len <= 0)
        goto cleanup;
    ret->freeMems.freeMems_len = len;

    rv = 0;

cleanup:
    if (rv < 0) {
        remoteDispatchError(rerr);
        VIR_FREE(ret->freeMems.freeMems_val);
    }
    return rv;
}


static int
remoteDispatchNodeGetFreeMemory(struct qemud_server *server ATTRIBUTE_UNUSED,
                                struct qemud_client *client ATTRIBUTE_UNUSED,
                                virConnectPtr conn,
                                remote_message_header *hdr ATTRIBUTE_UNUSED,
                                remote_error *rerr,
                                void *args ATTRIBUTE_UNUSED,
                                remote_node_get_free_memory_ret *ret)
{
    unsigned long long freeMem;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if ((freeMem = virNodeGetFreeMemory(conn)) == 0)
        goto cleanup;
    ret->freeMem = freeMem;
    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    return rv;
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
    virSchedParameterPtr params = NULL;
    int i;
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

    /* Serialise the scheduler parameters. */
    ret->params.params_len = nparams;
    if (VIR_ALLOC_N(ret->params.params_val, nparams) < 0)
        goto no_memory;

    for (i = 0; i < nparams; ++i) {
        /* remoteDispatchClientRequest will free this: */
        ret->params.params_val[i].field = strdup(params[i].field);
        if (ret->params.params_val[i].field == NULL)
            goto no_memory;

        ret->params.params_val[i].value.type = params[i].type;
        switch (params[i].type) {
        case VIR_DOMAIN_SCHED_FIELD_INT:
            ret->params.params_val[i].value.remote_sched_param_value_u.i = params[i].value.i; break;
        case VIR_DOMAIN_SCHED_FIELD_UINT:
            ret->params.params_val[i].value.remote_sched_param_value_u.ui = params[i].value.ui; break;
        case VIR_DOMAIN_SCHED_FIELD_LLONG:
            ret->params.params_val[i].value.remote_sched_param_value_u.l = params[i].value.l; break;
        case VIR_DOMAIN_SCHED_FIELD_ULLONG:
            ret->params.params_val[i].value.remote_sched_param_value_u.ul = params[i].value.ul; break;
        case VIR_DOMAIN_SCHED_FIELD_DOUBLE:
            ret->params.params_val[i].value.remote_sched_param_value_u.d = params[i].value.d; break;
        case VIR_DOMAIN_SCHED_FIELD_BOOLEAN:
            ret->params.params_val[i].value.remote_sched_param_value_u.b = params[i].value.b; break;
        default:
            virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("unknown type"));
            goto cleanup;
        }
    }

    rv = 0;

cleanup:
    if (rv < 0) {
        remoteDispatchError(rerr);
        if (ret->params.params_val) {
            for (i = 0 ; i < nparams ; i++)
                VIR_FREE(ret->params.params_val[i].field);
            VIR_FREE(ret->params.params_val);
        }
    }
    if (dom)
        virDomainFree(dom);
    VIR_FREE(params);
    return rv;

no_memory:
    virReportOOMError();
    goto cleanup;
}

static int
remoteDispatchDomainSetSchedulerParameters(struct qemud_server *server ATTRIBUTE_UNUSED,
                                           struct qemud_client *client ATTRIBUTE_UNUSED,
                                           virConnectPtr conn,
                                           remote_message_header *hdr ATTRIBUTE_UNUSED,
                                           remote_error *rerr,
                                           remote_domain_set_scheduler_parameters_args *args,
                                           void *ret ATTRIBUTE_UNUSED)
{
    virDomainPtr dom = NULL;
    virSchedParameterPtr params = NULL;
    int i, nparams;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    nparams = args->params.params_len;

    if (nparams > REMOTE_DOMAIN_SCHEDULER_PARAMETERS_MAX) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("nparams too large"));
        goto cleanup;
    }
    if (VIR_ALLOC_N(params, nparams) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    /* Deserialise parameters. */
    for (i = 0; i < nparams; ++i) {
        if (virStrcpyStatic(params[i].field, args->params.params_val[i].field) == NULL) {
            virNetError(VIR_ERR_INTERNAL_ERROR, _("Field %s too big for destination"),
                                      args->params.params_val[i].field);
            goto cleanup;
        }
        params[i].type = args->params.params_val[i].value.type;
        switch (params[i].type) {
        case VIR_DOMAIN_SCHED_FIELD_INT:
            params[i].value.i = args->params.params_val[i].value.remote_sched_param_value_u.i; break;
        case VIR_DOMAIN_SCHED_FIELD_UINT:
            params[i].value.ui = args->params.params_val[i].value.remote_sched_param_value_u.ui; break;
        case VIR_DOMAIN_SCHED_FIELD_LLONG:
            params[i].value.l = args->params.params_val[i].value.remote_sched_param_value_u.l; break;
        case VIR_DOMAIN_SCHED_FIELD_ULLONG:
            params[i].value.ul = args->params.params_val[i].value.remote_sched_param_value_u.ul; break;
        case VIR_DOMAIN_SCHED_FIELD_DOUBLE:
            params[i].value.d = args->params.params_val[i].value.remote_sched_param_value_u.d; break;
        case VIR_DOMAIN_SCHED_FIELD_BOOLEAN:
            params[i].value.b = args->params.params_val[i].value.remote_sched_param_value_u.b; break;
        }
    }

    if (!(dom = get_nonnull_domain(conn, args->dom)))
        goto cleanup;

    if (virDomainSetSchedulerParameters(dom, params, nparams) < 0)
        goto cleanup;

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
remoteDispatchDomainBlockStats(struct qemud_server *server ATTRIBUTE_UNUSED,
                               struct qemud_client *client ATTRIBUTE_UNUSED,
                               virConnectPtr conn,
                               remote_message_header *hdr ATTRIBUTE_UNUSED,
                               remote_error *rerr,
                               remote_domain_block_stats_args *args,
                               remote_domain_block_stats_ret *ret)
{
    virDomainPtr dom = NULL;
    char *path;
    struct _virDomainBlockStats stats;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(conn, args->dom)))
        goto cleanup;
    path = args->path;

    if (virDomainBlockStats(dom, path, &stats, sizeof stats) < 0)
        goto cleanup;

    ret->rd_req = stats.rd_req;
    ret->rd_bytes = stats.rd_bytes;
    ret->wr_req = stats.wr_req;
    ret->wr_bytes = stats.wr_bytes;
    ret->errs = stats.errs;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (dom)
        virDomainFree(dom);
    return rv;
}

static int
remoteDispatchDomainInterfaceStats(struct qemud_server *server ATTRIBUTE_UNUSED,
                                   struct qemud_client *client ATTRIBUTE_UNUSED,
                                   virConnectPtr conn,
                                   remote_message_header *hdr ATTRIBUTE_UNUSED,
                                   remote_error *rerr,
                                   remote_domain_interface_stats_args *args,
                                   remote_domain_interface_stats_ret *ret)
{
    virDomainPtr dom = NULL;
    char *path;
    struct _virDomainInterfaceStats stats;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(conn, args->dom)))
        goto cleanup;
    path = args->path;

    if (virDomainInterfaceStats(dom, path, &stats, sizeof stats) < 0)
        goto cleanup;

    ret->rx_bytes = stats.rx_bytes;
    ret->rx_packets = stats.rx_packets;
    ret->rx_errs = stats.rx_errs;
    ret->rx_drop = stats.rx_drop;
    ret->tx_bytes = stats.tx_bytes;
    ret->tx_packets = stats.tx_packets;
    ret->tx_errs = stats.tx_errs;
    ret->tx_drop = stats.tx_drop;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (dom)
        virDomainFree(dom);
    return rv;
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
    if (dom)
        virDomainFree(dom);

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
remoteDispatchDomainAttachDevice(struct qemud_server *server ATTRIBUTE_UNUSED,
                                 struct qemud_client *client ATTRIBUTE_UNUSED,
                                 virConnectPtr conn,
                                 remote_message_header *hdr ATTRIBUTE_UNUSED,
                                 remote_error *rerr,
                                 remote_domain_attach_device_args *args,
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

    if (virDomainAttachDevice(dom, args->xml) < 0)
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
remoteDispatchDomainAttachDeviceFlags(struct qemud_server *server ATTRIBUTE_UNUSED,
                                      struct qemud_client *client ATTRIBUTE_UNUSED,
                                      virConnectPtr conn,
                                      remote_message_header *hdr ATTRIBUTE_UNUSED,
                                      remote_error *rerr,
                                      remote_domain_attach_device_flags_args *args,
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

    if (virDomainAttachDeviceFlags(dom, args->xml, args->flags) < 0)
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
remoteDispatchDomainUpdateDeviceFlags(struct qemud_server *server ATTRIBUTE_UNUSED,
                                      struct qemud_client *client ATTRIBUTE_UNUSED,
                                      virConnectPtr conn,
                                      remote_message_header *hdr ATTRIBUTE_UNUSED,
                                      remote_error *rerr,
                                      remote_domain_update_device_flags_args *args,
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

    if (virDomainUpdateDeviceFlags(dom, args->xml, args->flags) < 0)
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
remoteDispatchDomainCreate(struct qemud_server *server ATTRIBUTE_UNUSED,
                           struct qemud_client *client ATTRIBUTE_UNUSED,
                           virConnectPtr conn,
                           remote_message_header *hdr ATTRIBUTE_UNUSED,
                           remote_error *rerr,
                           remote_domain_create_args *args,
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

    if (virDomainCreate(dom) < 0)
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
remoteDispatchDomainCreateWithFlags(struct qemud_server *server ATTRIBUTE_UNUSED,
                                    struct qemud_client *client ATTRIBUTE_UNUSED,
                                    virConnectPtr conn,
                                    remote_message_header *hdr ATTRIBUTE_UNUSED,
                                    remote_error *rerr,
                                    remote_domain_create_with_flags_args *args,
                                    remote_domain_create_with_flags_ret *ret)
{
    int rv = -1;
    virDomainPtr dom = NULL;

    if (!(dom = get_nonnull_domain(conn, args->dom)))
        goto cleanup;

    if (virDomainCreateWithFlags(dom, args->flags) < 0)
        goto cleanup;

    make_nonnull_domain(&ret->dom, dom);

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (dom)
        virDomainFree(dom);
    return rv;
}

static int
remoteDispatchDomainCreateXml(struct qemud_server *server ATTRIBUTE_UNUSED,
                              struct qemud_client *client ATTRIBUTE_UNUSED,
                              virConnectPtr conn,
                              remote_message_header *hdr ATTRIBUTE_UNUSED,
                              remote_error *rerr,
                              remote_domain_create_xml_args *args,
                              remote_domain_create_xml_ret *ret)
{
    virDomainPtr dom = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dom = virDomainCreateXML(conn, args->xml_desc, args->flags)))
        goto cleanup;

    make_nonnull_domain(&ret->dom, dom);

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (dom)
        virDomainFree(dom);
    return rv;
}

static int
remoteDispatchDomainDefineXml(struct qemud_server *server ATTRIBUTE_UNUSED,
                              struct qemud_client *client ATTRIBUTE_UNUSED,
                              virConnectPtr conn,
                              remote_message_header *hdr ATTRIBUTE_UNUSED,
                              remote_error *rerr,
                              remote_domain_define_xml_args *args,
                              remote_domain_define_xml_ret *ret)
{
    virDomainPtr dom = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dom = virDomainDefineXML(conn, args->xml)))
        goto cleanup;

    make_nonnull_domain(&ret->dom, dom);

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (dom)
        virDomainFree(dom);
    return rv;
}

static int
remoteDispatchDomainDestroy(struct qemud_server *server ATTRIBUTE_UNUSED,
                            struct qemud_client *client ATTRIBUTE_UNUSED,
                            virConnectPtr conn,
                            remote_message_header *hdr ATTRIBUTE_UNUSED,
                            remote_error *rerr,
                            remote_domain_destroy_args *args,
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

    if (virDomainDestroy(dom) < 0)
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
remoteDispatchDomainDetachDevice(struct qemud_server *server ATTRIBUTE_UNUSED,
                                 struct qemud_client *client ATTRIBUTE_UNUSED,
                                 virConnectPtr conn,
                                 remote_message_header *hdr ATTRIBUTE_UNUSED,
                                 remote_error *rerr,
                                 remote_domain_detach_device_args *args,
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

    if (virDomainDetachDevice(dom, args->xml) < 0)
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
remoteDispatchDomainDetachDeviceFlags(struct qemud_server *server ATTRIBUTE_UNUSED,
                                      struct qemud_client *client ATTRIBUTE_UNUSED,
                                      virConnectPtr conn,
                                      remote_message_header *hdr ATTRIBUTE_UNUSED,
                                      remote_error *rerr,
                                      remote_domain_detach_device_flags_args *args,
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

    if (virDomainDetachDeviceFlags(dom, args->xml, args->flags) < 0)
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
remoteDispatchDomainDumpXml(struct qemud_server *server ATTRIBUTE_UNUSED,
                            struct qemud_client *client ATTRIBUTE_UNUSED,
                            virConnectPtr conn,
                            remote_message_header *hdr ATTRIBUTE_UNUSED,
                            remote_error *rerr,
                            remote_domain_dump_xml_args *args,
                            remote_domain_dump_xml_ret *ret)
{
    virDomainPtr dom = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(conn, args->dom)))
        goto cleanup;

    /* remoteDispatchClientRequest will free this. */
    if (!(ret->xml = virDomainGetXMLDesc(dom, args->flags)))
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
remoteDispatchDomainXmlFromNative(struct qemud_server *server ATTRIBUTE_UNUSED,
                                  struct qemud_client *client ATTRIBUTE_UNUSED,
                                  virConnectPtr conn,
                                  remote_message_header *hdr ATTRIBUTE_UNUSED,
                                  remote_error *rerr,
                                  remote_domain_xml_from_native_args *args,
                                  remote_domain_xml_from_native_ret *ret)
{
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    /* remoteDispatchClientRequest will free this. */
    if (!(ret->domainXml = virConnectDomainXMLFromNative(conn,
                                                         args->nativeFormat,
                                                         args->nativeConfig,
                                                         args->flags)))
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    return rv;
}

static int
remoteDispatchDomainXmlToNative(struct qemud_server *server ATTRIBUTE_UNUSED,
                                struct qemud_client *client ATTRIBUTE_UNUSED,
                                virConnectPtr conn,
                                remote_message_header *hdr ATTRIBUTE_UNUSED,
                                remote_error *rerr,
                                remote_domain_xml_to_native_args *args,
                                remote_domain_xml_to_native_ret *ret)
{
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    /* remoteDispatchClientRequest will free this. */
    if (!(ret->nativeConfig = virConnectDomainXMLToNative(conn,
                                                          args->nativeFormat,
                                                          args->domainXml,
                                                          args->flags)))
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    return rv;
}


static int
remoteDispatchDomainGetAutostart(struct qemud_server *server ATTRIBUTE_UNUSED,
                                 struct qemud_client *client ATTRIBUTE_UNUSED,
                                 virConnectPtr conn,
                                 remote_message_header *hdr ATTRIBUTE_UNUSED,
                                 remote_error *rerr,
                                 remote_domain_get_autostart_args *args,
                                 remote_domain_get_autostart_ret *ret)
{
    virDomainPtr dom = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(conn, args->dom)))
        goto cleanup;

    if (virDomainGetAutostart(dom, &ret->autostart) < 0)
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
remoteDispatchDomainGetInfo(struct qemud_server *server ATTRIBUTE_UNUSED,
                            struct qemud_client *client ATTRIBUTE_UNUSED,
                            virConnectPtr conn,
                            remote_message_header *hdr ATTRIBUTE_UNUSED,
                            remote_error *rerr,
                            remote_domain_get_info_args *args,
                            remote_domain_get_info_ret *ret)
{
    virDomainPtr dom = NULL;
    virDomainInfo info;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(conn, args->dom)))
        goto cleanup;

    if (virDomainGetInfo(dom, &info) < 0)
        goto cleanup;

    ret->state = info.state;
    ret->max_mem = info.maxMem;
    ret->memory = info.memory;
    ret->nr_virt_cpu = info.nrVirtCpu;
    ret->cpu_time = info.cpuTime;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (dom)
        virDomainFree(dom);
    return rv;
}

static int
remoteDispatchDomainGetMaxMemory(struct qemud_server *server ATTRIBUTE_UNUSED,
                                 struct qemud_client *client ATTRIBUTE_UNUSED,
                                 virConnectPtr conn,
                                 remote_message_header *hdr ATTRIBUTE_UNUSED,
                                 remote_error *rerr,
                                 remote_domain_get_max_memory_args *args,
                                 remote_domain_get_max_memory_ret *ret)
{
    virDomainPtr dom = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(conn, args->dom)))
        goto cleanup;

    if ((ret->memory = virDomainGetMaxMemory(dom)) == 0)
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
remoteDispatchDomainGetMaxVcpus(struct qemud_server *server ATTRIBUTE_UNUSED,
                                struct qemud_client *client ATTRIBUTE_UNUSED,
                                virConnectPtr conn,
                                remote_message_header *hdr ATTRIBUTE_UNUSED,
                                remote_error *rerr,
                                remote_domain_get_max_vcpus_args *args,
                                remote_domain_get_max_vcpus_ret *ret)
{
    virDomainPtr dom = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(conn, args->dom)))
        goto cleanup;

    if ((ret->num = virDomainGetMaxVcpus(dom)) < 0)
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
remoteDispatchDomainGetOsType(struct qemud_server *server ATTRIBUTE_UNUSED,
                              struct qemud_client *client ATTRIBUTE_UNUSED,
                              virConnectPtr conn,
                              remote_message_header *hdr ATTRIBUTE_UNUSED,
                              remote_error *rerr,
                              remote_domain_get_os_type_args *args,
                              remote_domain_get_os_type_ret *ret)
{
    virDomainPtr dom = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(conn, args->dom)))
        goto cleanup;

    /* remoteDispatchClientRequest will free this */
    if (!(ret->type = virDomainGetOSType(dom)))
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
remoteDispatchDomainGetVcpusFlags(struct qemud_server *server ATTRIBUTE_UNUSED,
                                  struct qemud_client *client ATTRIBUTE_UNUSED,
                                  virConnectPtr conn,
                                  remote_message_header *hdr ATTRIBUTE_UNUSED,
                                  remote_error *rerr,
                                  remote_domain_get_vcpus_flags_args *args,
                                  remote_domain_get_vcpus_flags_ret *ret)
{
    virDomainPtr dom = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(conn, args->dom)))
        goto cleanup;

    if ((ret->num = virDomainGetVcpusFlags(dom, args->flags)) < 0)
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
remoteDispatchDomainMigratePerform(struct qemud_server *server ATTRIBUTE_UNUSED,
                                   struct qemud_client *client ATTRIBUTE_UNUSED,
                                   virConnectPtr conn,
                                   remote_message_header *hdr ATTRIBUTE_UNUSED,
                                   remote_error *rerr,
                                   remote_domain_migrate_perform_args *args,
                                   void *ret ATTRIBUTE_UNUSED)
{
    virDomainPtr dom = NULL;
    char *dname;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(conn, args->dom)))
        goto cleanup;

    dname = args->dname == NULL ? NULL : *args->dname;

    if (virDomainMigratePerform(dom,
                                args->cookie.cookie_val,
                                args->cookie.cookie_len,
                                args->uri,
                                args->flags, dname, args->resource) < 0)
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
remoteDispatchDomainMigrateFinish(struct qemud_server *server ATTRIBUTE_UNUSED,
                                  struct qemud_client *client ATTRIBUTE_UNUSED,
                                  virConnectPtr conn,
                                  remote_message_header *hdr ATTRIBUTE_UNUSED,
                                  remote_error *rerr,
                                  remote_domain_migrate_finish_args *args,
                                  remote_domain_migrate_finish_ret *ret)
{
    virDomainPtr dom = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dom = virDomainMigrateFinish(conn, args->dname,
                                       args->cookie.cookie_val,
                                       args->cookie.cookie_len,
                                       args->uri,
                                       args->flags)))
        goto cleanup;

    make_nonnull_domain(&ret->ddom, dom);
    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (dom)
        virDomainFree(dom);
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
remoteDispatchDomainMigrateFinish2(struct qemud_server *server ATTRIBUTE_UNUSED,
                                   struct qemud_client *client ATTRIBUTE_UNUSED,
                                   virConnectPtr conn,
                                   remote_message_header *hdr ATTRIBUTE_UNUSED,
                                   remote_error *rerr,
                                   remote_domain_migrate_finish2_args *args,
                                   remote_domain_migrate_finish2_ret *ret)
{
    virDomainPtr dom = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dom = virDomainMigrateFinish2(conn, args->dname,
                                        args->cookie.cookie_val,
                                        args->cookie.cookie_len,
                                        args->uri,
                                        args->flags,
                                        args->retcode)))
        goto cleanup;

    make_nonnull_domain(&ret->ddom, dom);

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (dom)
        virDomainFree(dom);
    return rv;
}

static int
remoteDispatchDomainMigratePrepareTunnel(struct qemud_server *server ATTRIBUTE_UNUSED,
                                         struct qemud_client *client,
                                         virConnectPtr conn,
                                         remote_message_header *hdr,
                                         remote_error *rerr,
                                         remote_domain_migrate_prepare_tunnel_args *args,
                                         void *ret ATTRIBUTE_UNUSED)
{
    char *dname;
    struct qemud_client_stream *stream = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    dname = args->dname == NULL ? NULL : *args->dname;

    if (!(stream = remoteCreateClientStream(conn, hdr))) {
        virReportOOMError();
        goto cleanup;
    }

    if (virDomainMigratePrepareTunnel(conn, stream->st,
                                      args->flags, dname, args->resource,
                                      args->dom_xml) < 0)
        goto cleanup;

    if (remoteAddClientStream(client, stream, 0) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0) {
        remoteDispatchError(rerr);
        if (stream) {
            virStreamAbort(stream->st);
            remoteFreeClientStream(client, stream);
        }
    }
    return rv;
}

static int
remoteDispatchListDefinedDomains(struct qemud_server *server ATTRIBUTE_UNUSED,
                                 struct qemud_client *client ATTRIBUTE_UNUSED,
                                 virConnectPtr conn,
                                 remote_message_header *hdr ATTRIBUTE_UNUSED,
                                 remote_error *rerr,
                                 remote_list_defined_domains_args *args,
                                 remote_list_defined_domains_ret *ret)
{
    int rv = -1;
    int len;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (args->maxnames > REMOTE_DOMAIN_NAME_LIST_MAX) {
        virNetError(VIR_ERR_INTERNAL_ERROR,
                    "%s", _("maxnames > REMOTE_DOMAIN_NAME_LIST_MAX"));
        goto cleanup;
    }

    /* Allocate return buffer. */
    if (VIR_ALLOC_N(ret->names.names_val, args->maxnames) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    len = virConnectListDefinedDomains(conn,
                                       ret->names.names_val, args->maxnames);
    if (len < 0)
        goto cleanup;
    ret->names.names_len = len;

    rv = 0;

cleanup:
    if (rv < 0) {
        remoteDispatchError(rerr);
        VIR_FREE(ret->names.names_val);
    }
    return rv;
}

static int
remoteDispatchDomainLookupById(struct qemud_server *server ATTRIBUTE_UNUSED,
                               struct qemud_client *client ATTRIBUTE_UNUSED,
                               virConnectPtr conn,
                               remote_message_header *hdr ATTRIBUTE_UNUSED,
                               remote_error *rerr,
                               remote_domain_lookup_by_id_args *args,
                               remote_domain_lookup_by_id_ret *ret)
{
    virDomainPtr dom = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dom = virDomainLookupByID(conn, args->id)))
        goto cleanup;

    make_nonnull_domain(&ret->dom, dom);

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (dom)
        virDomainFree(dom);
    return rv;
}

static int
remoteDispatchDomainLookupByName(struct qemud_server *server ATTRIBUTE_UNUSED,
                                 struct qemud_client *client ATTRIBUTE_UNUSED,
                                 virConnectPtr conn,
                                 remote_message_header *hdr ATTRIBUTE_UNUSED,
                                 remote_error *rerr,
                                 remote_domain_lookup_by_name_args *args,
                                 remote_domain_lookup_by_name_ret *ret)
{
    virDomainPtr dom = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dom = virDomainLookupByName(conn, args->name)))
        goto cleanup;

    make_nonnull_domain(&ret->dom, dom);

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (dom)
        virDomainFree(dom);
    return rv;
}

static int
remoteDispatchDomainLookupByUuid(struct qemud_server *server ATTRIBUTE_UNUSED,
                                 struct qemud_client *client ATTRIBUTE_UNUSED,
                                 virConnectPtr conn,
                                 remote_message_header *hdr ATTRIBUTE_UNUSED,
                                 remote_error *rerr,
                                 remote_domain_lookup_by_uuid_args *args,
                                 remote_domain_lookup_by_uuid_ret *ret)
{
    virDomainPtr dom = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dom = virDomainLookupByUUID(conn, (unsigned char *) args->uuid)))
        goto cleanup;

    make_nonnull_domain(&ret->dom, dom);

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (dom)
        virDomainFree(dom);
    return rv;
}

static int
remoteDispatchNumOfDefinedDomains(struct qemud_server *server ATTRIBUTE_UNUSED,
                                  struct qemud_client *client ATTRIBUTE_UNUSED,
                                  virConnectPtr conn,
                                  remote_message_header *hdr ATTRIBUTE_UNUSED,
                                  remote_error *rerr,
                                  void *args ATTRIBUTE_UNUSED,
                                  remote_num_of_defined_domains_ret *ret)
{
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if ((ret->num = virConnectNumOfDefinedDomains(conn)) < 0)
        goto cleanup;

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
remoteDispatchDomainReboot(struct qemud_server *server ATTRIBUTE_UNUSED,
                           struct qemud_client *client ATTRIBUTE_UNUSED,
                           virConnectPtr conn,
                           remote_message_header *hdr ATTRIBUTE_UNUSED,
                           remote_error *rerr,
                           remote_domain_reboot_args *args,
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

    if (virDomainReboot(dom, args->flags) < 0)
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
remoteDispatchDomainRestore(struct qemud_server *server ATTRIBUTE_UNUSED,
                            struct qemud_client *client ATTRIBUTE_UNUSED,
                            virConnectPtr conn,
                            remote_message_header *hdr ATTRIBUTE_UNUSED,
                            remote_error *rerr,
                            remote_domain_restore_args *args,
                            void *ret ATTRIBUTE_UNUSED)
{
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (virDomainRestore(conn, args->from) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    return rv;
}

static int
remoteDispatchDomainResume(struct qemud_server *server ATTRIBUTE_UNUSED,
                           struct qemud_client *client ATTRIBUTE_UNUSED,
                           virConnectPtr conn,
                           remote_message_header *hdr ATTRIBUTE_UNUSED,
                           remote_error *rerr,
                           remote_domain_resume_args *args,
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

    if (virDomainResume(dom) < 0)
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
remoteDispatchDomainSave(struct qemud_server *server ATTRIBUTE_UNUSED,
                         struct qemud_client *client ATTRIBUTE_UNUSED,
                         virConnectPtr conn,
                         remote_message_header *hdr ATTRIBUTE_UNUSED,
                         remote_error *rerr,
                         remote_domain_save_args *args,
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

    if (virDomainSave(dom, args->to) < 0)
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
remoteDispatchDomainCoreDump(struct qemud_server *server ATTRIBUTE_UNUSED,
                             struct qemud_client *client ATTRIBUTE_UNUSED,
                             virConnectPtr conn,
                             remote_message_header *hdr ATTRIBUTE_UNUSED,
                             remote_error *rerr,
                             remote_domain_core_dump_args *args,
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

    if (virDomainCoreDump(dom, args->to, args->flags) < 0)
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
remoteDispatchDomainSetAutostart(struct qemud_server *server ATTRIBUTE_UNUSED,
                                 struct qemud_client *client ATTRIBUTE_UNUSED,
                                 virConnectPtr conn,
                                 remote_message_header *hdr ATTRIBUTE_UNUSED,
                                 remote_error *rerr,
                                 remote_domain_set_autostart_args *args,
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

    if (virDomainSetAutostart(dom, args->autostart) < 0)
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
remoteDispatchDomainSetMaxMemory(struct qemud_server *server ATTRIBUTE_UNUSED,
                                 struct qemud_client *client ATTRIBUTE_UNUSED,
                                 virConnectPtr conn,
                                 remote_message_header *hdr ATTRIBUTE_UNUSED,
                                 remote_error *rerr,
                                 remote_domain_set_max_memory_args *args,
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

    if (virDomainSetMaxMemory(dom, args->memory) < 0)
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
remoteDispatchDomainSetMemory(struct qemud_server *server ATTRIBUTE_UNUSED,
                              struct qemud_client *client ATTRIBUTE_UNUSED,
                              virConnectPtr conn,
                              remote_message_header *hdr ATTRIBUTE_UNUSED,
                              remote_error *rerr,
                              remote_domain_set_memory_args *args,
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

    if (virDomainSetMemory(dom, args->memory) < 0)
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
remoteDispatchDomainSetMemoryFlags(struct qemud_server *server ATTRIBUTE_UNUSED,
                                   struct qemud_client *client ATTRIBUTE_UNUSED,
                                   virConnectPtr conn,
                                   remote_message_header *hdr ATTRIBUTE_UNUSED,
                                   remote_error *rerr,
                                   remote_domain_set_memory_flags_args *args,
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

    if (virDomainSetMemoryFlags(dom, args->memory, args->flags) < 0)
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
remoteDispatchDomainSetMemoryParameters(struct qemud_server *server
                                        ATTRIBUTE_UNUSED,
                                        struct qemud_client *client
                                        ATTRIBUTE_UNUSED,
                                        virConnectPtr conn,
                                        remote_message_header *
                                        hdr ATTRIBUTE_UNUSED,
                                        remote_error * rerr,
                                        remote_domain_set_memory_parameters_args
                                        * args, void *ret ATTRIBUTE_UNUSED)
{
    virDomainPtr dom = NULL;
    virMemoryParameterPtr params = NULL;
    int i, nparams;
    unsigned int flags;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    nparams = args->params.params_len;
    flags = args->flags;

    if (nparams > REMOTE_DOMAIN_MEMORY_PARAMETERS_MAX) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("nparams too large"));
        goto cleanup;
    }
    if (VIR_ALLOC_N(params, nparams) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    /* Deserialise parameters. */
    for (i = 0; i < nparams; ++i) {
        if (virStrcpyStatic
            (params[i].field, args->params.params_val[i].field) == NULL) {
            virNetError(VIR_ERR_INTERNAL_ERROR,
                        _("Field %s too big for destination"),
                        args->params.params_val[i].field);
            goto cleanup;
        }
        params[i].type = args->params.params_val[i].value.type;
        switch (params[i].type) {
            case VIR_DOMAIN_MEMORY_PARAM_INT:
                params[i].value.i =
                    args->params.params_val[i].value.
                    remote_memory_param_value_u.i;
                break;
            case VIR_DOMAIN_MEMORY_PARAM_UINT:
                params[i].value.ui =
                    args->params.params_val[i].value.
                    remote_memory_param_value_u.ui;
                break;
            case VIR_DOMAIN_MEMORY_PARAM_LLONG:
                params[i].value.l =
                    args->params.params_val[i].value.
                    remote_memory_param_value_u.l;
                break;
            case VIR_DOMAIN_MEMORY_PARAM_ULLONG:
                params[i].value.ul =
                    args->params.params_val[i].value.
                    remote_memory_param_value_u.ul;
                break;
            case VIR_DOMAIN_MEMORY_PARAM_DOUBLE:
                params[i].value.d =
                    args->params.params_val[i].value.
                    remote_memory_param_value_u.d;
                break;
            case VIR_DOMAIN_MEMORY_PARAM_BOOLEAN:
                params[i].value.b =
                    args->params.params_val[i].value.
                    remote_memory_param_value_u.b;
                break;
        }
    }

    if (!(dom = get_nonnull_domain(conn, args->dom)))
        goto cleanup;

    if (virDomainSetMemoryParameters(dom, params, nparams, flags) < 0)
        goto cleanup;

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
    virMemoryParameterPtr params = NULL;
    int i;
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

    /* Serialise the memory parameters. */
    ret->params.params_len = nparams;
    if (VIR_ALLOC_N(ret->params.params_val, nparams) < 0)
        goto no_memory;

    for (i = 0; i < nparams; ++i) {
        /* remoteDispatchClientRequest will free this: */
        ret->params.params_val[i].field = strdup(params[i].field);
        if (ret->params.params_val[i].field == NULL)
            goto no_memory;

        ret->params.params_val[i].value.type = params[i].type;
        switch (params[i].type) {
            case VIR_DOMAIN_MEMORY_PARAM_INT:
                ret->params.params_val[i].
                    value.remote_memory_param_value_u.i =
                    params[i].value.i;
                break;
            case VIR_DOMAIN_MEMORY_PARAM_UINT:
                ret->params.params_val[i].
                    value.remote_memory_param_value_u.ui =
                    params[i].value.ui;
                break;
            case VIR_DOMAIN_MEMORY_PARAM_LLONG:
                ret->params.params_val[i].
                    value.remote_memory_param_value_u.l =
                    params[i].value.l;
                break;
            case VIR_DOMAIN_MEMORY_PARAM_ULLONG:
                ret->params.params_val[i].
                    value.remote_memory_param_value_u.ul =
                    params[i].value.ul;
                break;
            case VIR_DOMAIN_MEMORY_PARAM_DOUBLE:
                ret->params.params_val[i].
                    value.remote_memory_param_value_u.d =
                    params[i].value.d;
                break;
            case VIR_DOMAIN_MEMORY_PARAM_BOOLEAN:
                ret->params.params_val[i].
                    value.remote_memory_param_value_u.b =
                    params[i].value.b;
                break;
            default:
                virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("unknown type"));
                goto cleanup;
        }
    }

success:
    rv = 0;

cleanup:
    if (rv < 0) {
        remoteDispatchError(rerr);
        if (ret->params.params_val) {
            for (i = 0; i < nparams; i++)
                VIR_FREE(ret->params.params_val[i].field);
            VIR_FREE(ret->params.params_val);
        }
    }
    if (dom)
        virDomainFree(dom);
    VIR_FREE(params);
    return rv;

no_memory:
    virReportOOMError();
    goto cleanup;
}

static int
remoteDispatchDomainSetBlkioParameters(struct qemud_server *server
                                        ATTRIBUTE_UNUSED,
                                        struct qemud_client *client
                                        ATTRIBUTE_UNUSED,
                                        virConnectPtr conn,
                                        remote_message_header *
                                        hdr ATTRIBUTE_UNUSED,
                                        remote_error * rerr,
                                        remote_domain_set_blkio_parameters_args
                                        * args, void *ret ATTRIBUTE_UNUSED)
{
    virDomainPtr dom = NULL;
    virBlkioParameterPtr params = NULL;
    int i, nparams;
    unsigned int flags;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    nparams = args->params.params_len;
    flags = args->flags;

    if (nparams > REMOTE_DOMAIN_BLKIO_PARAMETERS_MAX) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("nparams too large"));
        goto cleanup;
    }
    if (VIR_ALLOC_N(params, nparams) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    /* Deserialise parameters. */
    for (i = 0; i < nparams; ++i) {
        if (virStrcpyStatic
            (params[i].field, args->params.params_val[i].field) == NULL) {
            virNetError(VIR_ERR_INTERNAL_ERROR,
                        _("Field %s too big for destination"),
                        args->params.params_val[i].field);
            goto cleanup;
        }
        params[i].type = args->params.params_val[i].value.type;
        switch (params[i].type) {
            case VIR_DOMAIN_BLKIO_PARAM_INT:
                params[i].value.i =
                    args->params.params_val[i].value.
                    remote_blkio_param_value_u.i;
                break;
            case VIR_DOMAIN_BLKIO_PARAM_UINT:
                params[i].value.ui =
                    args->params.params_val[i].value.
                    remote_blkio_param_value_u.ui;
                break;
            case VIR_DOMAIN_BLKIO_PARAM_LLONG:
                params[i].value.l =
                    args->params.params_val[i].value.
                    remote_blkio_param_value_u.l;
                break;
            case VIR_DOMAIN_BLKIO_PARAM_ULLONG:
                params[i].value.ul =
                    args->params.params_val[i].value.
                    remote_blkio_param_value_u.ul;
                break;
            case VIR_DOMAIN_BLKIO_PARAM_DOUBLE:
                params[i].value.d =
                    args->params.params_val[i].value.
                    remote_blkio_param_value_u.d;
                break;
            case VIR_DOMAIN_BLKIO_PARAM_BOOLEAN:
                params[i].value.b =
                    args->params.params_val[i].value.
                    remote_blkio_param_value_u.b;
                break;
        }
    }

    if (!(dom = get_nonnull_domain(conn, args->dom)))
        goto cleanup;

    if (virDomainSetBlkioParameters(dom, params, nparams, flags) < 0)
        goto cleanup;

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
    virBlkioParameterPtr params = NULL;
    int i;
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

    /* Serialise the blkio parameters. */
    ret->params.params_len = nparams;
    if (VIR_ALLOC_N(ret->params.params_val, nparams) < 0)
        goto no_memory;

    for (i = 0; i < nparams; ++i) {
        // remoteDispatchClientRequest will free this:
        ret->params.params_val[i].field = strdup(params[i].field);
        if (ret->params.params_val[i].field == NULL)
            goto no_memory;

        ret->params.params_val[i].value.type = params[i].type;
        switch (params[i].type) {
            case VIR_DOMAIN_BLKIO_PARAM_INT:
                ret->params.params_val[i].
                    value.remote_blkio_param_value_u.i =
                    params[i].value.i;
                break;
            case VIR_DOMAIN_BLKIO_PARAM_UINT:
                ret->params.params_val[i].
                    value.remote_blkio_param_value_u.ui =
                    params[i].value.ui;
                break;
            case VIR_DOMAIN_BLKIO_PARAM_LLONG:
                ret->params.params_val[i].
                    value.remote_blkio_param_value_u.l =
                    params[i].value.l;
                break;
            case VIR_DOMAIN_BLKIO_PARAM_ULLONG:
                ret->params.params_val[i].
                    value.remote_blkio_param_value_u.ul =
                    params[i].value.ul;
                break;
            case VIR_DOMAIN_BLKIO_PARAM_DOUBLE:
                ret->params.params_val[i].
                    value.remote_blkio_param_value_u.d =
                    params[i].value.d;
                break;
            case VIR_DOMAIN_BLKIO_PARAM_BOOLEAN:
                ret->params.params_val[i].
                    value.remote_blkio_param_value_u.b =
                    params[i].value.b;
                break;
            default:
                virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("unknown type"));
                goto cleanup;
        }
    }

success:
    rv = 0;

cleanup:
    if (rv < 0) {
        remoteDispatchError(rerr);
        if (ret->params.params_val) {
            for (i = 0; i < nparams; i++)
                VIR_FREE(ret->params.params_val[i].field);
            VIR_FREE(ret->params.params_val);
        }
    }
    VIR_FREE(params);
    if (dom)
        virDomainFree(dom);
    return rv;

no_memory:
    virReportOOMError();
    goto cleanup;
}

static int
remoteDispatchDomainSetVcpus(struct qemud_server *server ATTRIBUTE_UNUSED,
                             struct qemud_client *client ATTRIBUTE_UNUSED,
                             virConnectPtr conn,
                             remote_message_header *hdr ATTRIBUTE_UNUSED,
                             remote_error *rerr,
                             remote_domain_set_vcpus_args *args,
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

    if (virDomainSetVcpus(dom, args->nvcpus) < 0)
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
remoteDispatchDomainSetVcpusFlags(struct qemud_server *server ATTRIBUTE_UNUSED,
                                  struct qemud_client *client ATTRIBUTE_UNUSED,
                                  virConnectPtr conn,
                                  remote_message_header *hdr ATTRIBUTE_UNUSED,
                                  remote_error *rerr,
                                  remote_domain_set_vcpus_flags_args *args,
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

    if (virDomainSetVcpusFlags(dom, args->nvcpus, args->flags) < 0)
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
remoteDispatchDomainShutdown(struct qemud_server *server ATTRIBUTE_UNUSED,
                             struct qemud_client *client ATTRIBUTE_UNUSED,
                             virConnectPtr conn,
                             remote_message_header *hdr ATTRIBUTE_UNUSED,
                             remote_error *rerr,
                             remote_domain_shutdown_args *args,
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

    if (virDomainShutdown(dom) < 0)
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
remoteDispatchDomainSuspend(struct qemud_server *server ATTRIBUTE_UNUSED,
                            struct qemud_client *client ATTRIBUTE_UNUSED,
                            virConnectPtr conn,
                            remote_message_header *hdr ATTRIBUTE_UNUSED,
                            remote_error *rerr,
                            remote_domain_suspend_args *args,
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

    if (virDomainSuspend(dom) < 0)
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
remoteDispatchDomainUndefine(struct qemud_server *server ATTRIBUTE_UNUSED,
                             struct qemud_client *client ATTRIBUTE_UNUSED,
                             virConnectPtr conn,
                             remote_message_header *hdr ATTRIBUTE_UNUSED,
                             remote_error *rerr,
                             remote_domain_undefine_args *args,
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

    if (virDomainUndefine(dom) < 0)
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
remoteDispatchListDefinedNetworks(struct qemud_server *server ATTRIBUTE_UNUSED,
                                  struct qemud_client *client ATTRIBUTE_UNUSED,
                                  virConnectPtr conn,
                                  remote_message_header *hdr ATTRIBUTE_UNUSED,
                                  remote_error *rerr,
                                  remote_list_defined_networks_args *args,
                                  remote_list_defined_networks_ret *ret)
{
    int rv = -1;
    int len;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (args->maxnames > REMOTE_NETWORK_NAME_LIST_MAX) {
        virNetError(VIR_ERR_INTERNAL_ERROR,
                    "%s", _("maxnames > REMOTE_NETWORK_NAME_LIST_MAX"));
        goto cleanup;
    }

    /* Allocate return buffer. */
    if (VIR_ALLOC_N(ret->names.names_val, args->maxnames) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    len = virConnectListDefinedNetworks(conn,
                                      ret->names.names_val, args->maxnames);
    if (len < 0)
        goto cleanup;
    ret->names.names_len = len;

    rv = 0;

cleanup:
    if (rv < 0) {
        remoteDispatchError(rerr);
        VIR_FREE(ret->names.names_val);
    }
    return rv;
}

static int
remoteDispatchListDomains(struct qemud_server *server ATTRIBUTE_UNUSED,
                          struct qemud_client *client ATTRIBUTE_UNUSED,
                          virConnectPtr conn,
                          remote_message_header *hdr ATTRIBUTE_UNUSED,
                          remote_error *rerr,
                          remote_list_domains_args *args,
                          remote_list_domains_ret *ret)
{
    int rv = -1;
    int len;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (args->maxids > REMOTE_DOMAIN_ID_LIST_MAX) {
        virNetError(VIR_ERR_INTERNAL_ERROR,
                    "%s", _("maxids > REMOTE_DOMAIN_ID_LIST_MAX"));
        goto cleanup;
    }

    /* Allocate return buffer. */
    if (VIR_ALLOC_N(ret->ids.ids_val, args->maxids) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    len = virConnectListDomains(conn,
                                ret->ids.ids_val, args->maxids);
    if (len < 0)
        goto cleanup;
    ret->ids.ids_len = len;

    rv = 0;

cleanup:
    if (rv < 0) {
        remoteDispatchError(rerr);
        VIR_FREE(ret->ids.ids_val);
    }
    return rv;
}

static int
remoteDispatchDomainManagedSave(struct qemud_server *server ATTRIBUTE_UNUSED,
                                struct qemud_client *client ATTRIBUTE_UNUSED,
                                virConnectPtr conn,
                                remote_message_header *hdr ATTRIBUTE_UNUSED,
                                remote_error *rerr,
                                remote_domain_managed_save_args *args,
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

    if (virDomainManagedSave(dom, args->flags) < 0)
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
remoteDispatchDomainHasManagedSaveImage(struct qemud_server *server ATTRIBUTE_UNUSED,
                                        struct qemud_client *client ATTRIBUTE_UNUSED,
                                        virConnectPtr conn,
                                        remote_message_header *hdr ATTRIBUTE_UNUSED,
                                        remote_error *rerr,
                                        remote_domain_has_managed_save_image_args *args,
                                        remote_domain_has_managed_save_image_ret *ret)
{
    virDomainPtr dom = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(conn, args->dom)))
        goto cleanup;

    if ((ret->ret = virDomainHasManagedSaveImage(dom, args->flags)) < 0)
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
remoteDispatchDomainManagedSaveRemove(struct qemud_server *server ATTRIBUTE_UNUSED,
                                      struct qemud_client *client ATTRIBUTE_UNUSED,
                                      virConnectPtr conn,
                                      remote_message_header *hdr ATTRIBUTE_UNUSED,
                                      remote_error *rerr,
                                      remote_domain_managed_save_remove_args *args,
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

    if (virDomainManagedSaveRemove(dom, args->flags) < 0)
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
remoteDispatchListNetworks(struct qemud_server *server ATTRIBUTE_UNUSED,
                           struct qemud_client *client ATTRIBUTE_UNUSED,
                           virConnectPtr conn,
                           remote_message_header *hdr ATTRIBUTE_UNUSED,
                           remote_error *rerr,
                           remote_list_networks_args *args,
                           remote_list_networks_ret *ret)
{
    int rv = -1;
    int len;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (args->maxnames > REMOTE_NETWORK_NAME_LIST_MAX) {
        virNetError(VIR_ERR_INTERNAL_ERROR,
                    "%s", _("maxnames > REMOTE_NETWORK_NAME_LIST_MAX"));
        goto cleanup;
    }

    /* Allocate return buffer. */
    if (VIR_ALLOC_N(ret->names.names_val, args->maxnames) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    len = virConnectListNetworks(conn,
                                 ret->names.names_val, args->maxnames);
    if (len < 0)
        goto cleanup;
    ret->names.names_len = len;

    rv = 0;

cleanup:
    if (rv < 0) {
        remoteDispatchError(rerr);
        VIR_FREE(ret->names.names_val);
    }
    return rv;
}

static int
remoteDispatchNetworkCreate(struct qemud_server *server ATTRIBUTE_UNUSED,
                            struct qemud_client *client ATTRIBUTE_UNUSED,
                            virConnectPtr conn,
                            remote_message_header *hdr ATTRIBUTE_UNUSED,
                            remote_error *rerr,
                            remote_network_create_args *args,
                            void *ret ATTRIBUTE_UNUSED)
{
    virNetworkPtr net = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(net = get_nonnull_network(conn, args->net)))
        goto cleanup;

    if (virNetworkCreate(net) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (net)
        virNetworkFree(net);
    return rv;
}

static int
remoteDispatchNetworkCreateXml(struct qemud_server *server ATTRIBUTE_UNUSED,
                               struct qemud_client *client ATTRIBUTE_UNUSED,
                               virConnectPtr conn,
                               remote_message_header *hdr ATTRIBUTE_UNUSED,
                               remote_error *rerr,
                               remote_network_create_xml_args *args,
                               remote_network_create_xml_ret *ret)
{
    virNetworkPtr net = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(net = virNetworkCreateXML(conn, args->xml)))
        goto cleanup;

    make_nonnull_network(&ret->net, net);

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (net)
        virNetworkFree(net);
    return rv;
}

static int
remoteDispatchNetworkDefineXml(struct qemud_server *server ATTRIBUTE_UNUSED,
                               struct qemud_client *client ATTRIBUTE_UNUSED,
                               virConnectPtr conn,
                               remote_message_header *hdr ATTRIBUTE_UNUSED,
                               remote_error *rerr,
                               remote_network_define_xml_args *args,
                               remote_network_define_xml_ret *ret)
{
    virNetworkPtr net = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(net = virNetworkDefineXML(conn, args->xml)))
        goto cleanup;

    make_nonnull_network(&ret->net, net);

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (net)
        virNetworkFree(net);
    return rv;
}

static int
remoteDispatchNetworkDestroy(struct qemud_server *server ATTRIBUTE_UNUSED,
                             struct qemud_client *client ATTRIBUTE_UNUSED,
                             virConnectPtr conn,
                             remote_message_header *hdr ATTRIBUTE_UNUSED,
                             remote_error *rerr,
                             remote_network_destroy_args *args,
                             void *ret ATTRIBUTE_UNUSED)
{
    virNetworkPtr net = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(net = get_nonnull_network(conn, args->net)))
        goto cleanup;

    if (virNetworkDestroy(net) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (net)
        virNetworkFree(net);
    return rv;
}

static int
remoteDispatchNetworkDumpXml(struct qemud_server *server ATTRIBUTE_UNUSED,
                             struct qemud_client *client ATTRIBUTE_UNUSED,
                             virConnectPtr conn,
                             remote_message_header *hdr ATTRIBUTE_UNUSED,
                             remote_error *rerr,
                             remote_network_dump_xml_args *args,
                             remote_network_dump_xml_ret *ret)
{
    virNetworkPtr net = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(net = get_nonnull_network(conn, args->net)))
        goto cleanup;

    /* remoteDispatchClientRequest will free this. */
    if (!(ret->xml = virNetworkGetXMLDesc(net, args->flags)))
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (net)
        virNetworkFree(net);
    return rv;
}

static int
remoteDispatchNetworkGetAutostart(struct qemud_server *server ATTRIBUTE_UNUSED,
                                  struct qemud_client *client ATTRIBUTE_UNUSED,
                                  virConnectPtr conn,
                                  remote_message_header *hdr ATTRIBUTE_UNUSED,
                                  remote_error *rerr,
                                  remote_network_get_autostart_args *args,
                                  remote_network_get_autostart_ret *ret)
{
    virNetworkPtr net = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(net = get_nonnull_network(conn, args->net)))
        goto cleanup;

    if (virNetworkGetAutostart(net, &ret->autostart) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (net)
        virNetworkFree(net);
    return rv;
}

static int
remoteDispatchNetworkGetBridgeName(struct qemud_server *server ATTRIBUTE_UNUSED,
                                   struct qemud_client *client ATTRIBUTE_UNUSED,
                                   virConnectPtr conn,
                                   remote_message_header *hdr ATTRIBUTE_UNUSED,
                                   remote_error *rerr,
                                   remote_network_get_bridge_name_args *args,
                                   remote_network_get_bridge_name_ret *ret)
{
    virNetworkPtr net = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(net = get_nonnull_network(conn, args->net)))
        goto cleanup;

    /* remoteDispatchClientRequest will free this. */
    if (!(ret->name = virNetworkGetBridgeName(net)))
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (net)
        virNetworkFree(net);
    return rv;
}

static int
remoteDispatchNetworkLookupByName(struct qemud_server *server ATTRIBUTE_UNUSED,
                                  struct qemud_client *client ATTRIBUTE_UNUSED,
                                  virConnectPtr conn,
                                  remote_message_header *hdr ATTRIBUTE_UNUSED,
                                  remote_error *rerr,
                                  remote_network_lookup_by_name_args *args,
                                  remote_network_lookup_by_name_ret *ret)
{
    virNetworkPtr net = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(net = virNetworkLookupByName(conn, args->name)))
        goto cleanup;

    make_nonnull_network(&ret->net, net);

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (net)
        virNetworkFree(net);
    return rv;
}

static int
remoteDispatchNetworkLookupByUuid(struct qemud_server *server ATTRIBUTE_UNUSED,
                                  struct qemud_client *client ATTRIBUTE_UNUSED,
                                  virConnectPtr conn,
                                  remote_message_header *hdr ATTRIBUTE_UNUSED,
                                  remote_error *rerr,
                                  remote_network_lookup_by_uuid_args *args,
                                  remote_network_lookup_by_uuid_ret *ret)
{
    virNetworkPtr net = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(net = virNetworkLookupByUUID(conn, (unsigned char *) args->uuid)))
        goto cleanup;

    make_nonnull_network(&ret->net, net);

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (net)
        virNetworkFree(net);
    return rv;
}

static int
remoteDispatchNetworkSetAutostart(struct qemud_server *server ATTRIBUTE_UNUSED,
                                  struct qemud_client *client ATTRIBUTE_UNUSED,
                                  virConnectPtr conn,
                                  remote_message_header *hdr ATTRIBUTE_UNUSED,
                                  remote_error *rerr,
                                  remote_network_set_autostart_args *args,
                                  void *ret ATTRIBUTE_UNUSED)
{
    virNetworkPtr net = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(net = get_nonnull_network(conn, args->net)))
        goto cleanup;

    if (virNetworkSetAutostart(net, args->autostart) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (net)
        virNetworkFree(net);
    return rv;
}

static int
remoteDispatchNetworkUndefine(struct qemud_server *server ATTRIBUTE_UNUSED,
                              struct qemud_client *client ATTRIBUTE_UNUSED,
                              virConnectPtr conn,
                              remote_message_header *hdr ATTRIBUTE_UNUSED,
                              remote_error *rerr,
                              remote_network_undefine_args *args,
                              void *ret ATTRIBUTE_UNUSED)
{
    virNetworkPtr net = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(net = get_nonnull_network(conn, args->net)))
        goto cleanup;

    if (virNetworkUndefine(net) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (net)
        virNetworkFree(net);
    return rv;
}

static int
remoteDispatchNumOfDefinedNetworks(struct qemud_server *server ATTRIBUTE_UNUSED,
                                   struct qemud_client *client ATTRIBUTE_UNUSED,
                                   virConnectPtr conn,
                                   remote_message_header *hdr ATTRIBUTE_UNUSED,
                                   remote_error *rerr,
                                   void *args ATTRIBUTE_UNUSED,
                                   remote_num_of_defined_networks_ret *ret)
{
    int rv = -1;
    int len;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    len = virConnectNumOfDefinedNetworks(conn);
    if (len < 0)
        goto cleanup;
    ret->num = len;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    return rv;
}

static int
remoteDispatchNumOfDomains(struct qemud_server *server ATTRIBUTE_UNUSED,
                           struct qemud_client *client ATTRIBUTE_UNUSED,
                           virConnectPtr conn,
                           remote_message_header *hdr ATTRIBUTE_UNUSED,
                           remote_error *rerr,
                           void *args ATTRIBUTE_UNUSED,
                           remote_num_of_domains_ret *ret)
{
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if ((ret->num = virConnectNumOfDomains(conn)) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    return rv;
}

static int
remoteDispatchNumOfNetworks(struct qemud_server *server ATTRIBUTE_UNUSED,
                            struct qemud_client *client ATTRIBUTE_UNUSED,
                            virConnectPtr conn,
                            remote_message_header *hdr ATTRIBUTE_UNUSED,
                            remote_error *rerr,
                            void *args ATTRIBUTE_UNUSED,
                            remote_num_of_networks_ret *ret)
{
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if ((ret->num = virConnectNumOfNetworks(conn)) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    return rv;
}


/*-------------------------------------------------------------*/
static int
remoteDispatchNumOfInterfaces(struct qemud_server *server ATTRIBUTE_UNUSED,
                              struct qemud_client *client ATTRIBUTE_UNUSED,
                              virConnectPtr conn,
                              remote_message_header *hdr ATTRIBUTE_UNUSED,
                              remote_error *rerr,
                              void *args ATTRIBUTE_UNUSED,
                              remote_num_of_interfaces_ret *ret)
{
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if ((ret->num = virConnectNumOfInterfaces(conn)) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    return rv;
}

static int
remoteDispatchListInterfaces(struct qemud_server *server ATTRIBUTE_UNUSED,
                             struct qemud_client *client ATTRIBUTE_UNUSED,
                             virConnectPtr conn,
                             remote_message_header *hdr ATTRIBUTE_UNUSED,
                             remote_error *rerr,
                             remote_list_interfaces_args *args,
                             remote_list_interfaces_ret *ret)
{
    int rv = -1;
    int len;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (args->maxnames > REMOTE_INTERFACE_NAME_LIST_MAX) {
        virNetError(VIR_ERR_INTERNAL_ERROR,
                    "%s", _("maxnames > REMOTE_INTERFACE_NAME_LIST_MAX"));
        goto cleanup;
    }

    /* Allocate return buffer. */
    if (VIR_ALLOC_N(ret->names.names_val, args->maxnames) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    len = virConnectListInterfaces(conn,
                                   ret->names.names_val, args->maxnames);
    if (len < 0)
        goto cleanup;
    ret->names.names_len = len;

    rv = 0;

cleanup:
    if (rv < 0) {
        remoteDispatchError(rerr);
        VIR_FREE(ret->names.names_val);
    }
    return rv;
}

static int
remoteDispatchNumOfDefinedInterfaces(struct qemud_server *server ATTRIBUTE_UNUSED,
                                     struct qemud_client *client ATTRIBUTE_UNUSED,
                                     virConnectPtr conn,
                                     remote_message_header *hdr ATTRIBUTE_UNUSED,
                                     remote_error *rerr,
                                     void *args ATTRIBUTE_UNUSED,
                                     remote_num_of_defined_interfaces_ret *ret)
{
    int rv = -1;
    int len;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    len = virConnectNumOfDefinedInterfaces(conn);
    if (len < 0)
        goto cleanup;
    ret->num = len;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    return rv;
}

static int
remoteDispatchListDefinedInterfaces(struct qemud_server *server ATTRIBUTE_UNUSED,
                                    struct qemud_client *client ATTRIBUTE_UNUSED,
                                    virConnectPtr conn,
                                    remote_message_header *hdr ATTRIBUTE_UNUSED,
                                    remote_error *rerr,
                                    remote_list_defined_interfaces_args *args,
                                    remote_list_defined_interfaces_ret *ret)
{
    int rv = -1;
    int len;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (args->maxnames > REMOTE_DEFINED_INTERFACE_NAME_LIST_MAX) {
        virNetError(VIR_ERR_INTERNAL_ERROR,
                    "%s", _("maxnames > REMOTE_DEFINED_INTERFACE_NAME_LIST_MAX"));
        goto cleanup;
    }

    /* Allocate return buffer. */
    if (VIR_ALLOC_N(ret->names.names_val, args->maxnames) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    len = virConnectListDefinedInterfaces(conn,
                                          ret->names.names_val, args->maxnames);
    if (len < 0)
        goto cleanup;
    ret->names.names_len = len;

    rv = 0;

cleanup:
    if (rv < 0) {
        remoteDispatchError(rerr);
        VIR_FREE(ret->names.names_val);
    }
    return rv;
}

static int
remoteDispatchInterfaceLookupByName(struct qemud_server *server ATTRIBUTE_UNUSED,
                                    struct qemud_client *client ATTRIBUTE_UNUSED,
                                    virConnectPtr conn,
                                    remote_message_header *hdr ATTRIBUTE_UNUSED,
                                    remote_error *rerr,
                                    remote_interface_lookup_by_name_args *args,
                                    remote_interface_lookup_by_name_ret *ret)
{
    virInterfacePtr iface = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(iface = virInterfaceLookupByName(conn, args->name)))
        goto cleanup;

    make_nonnull_interface(&ret->iface, iface);

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (iface)
        virInterfaceFree(iface);
    return rv;
}

static int
remoteDispatchInterfaceLookupByMacString(struct qemud_server *server ATTRIBUTE_UNUSED,
                                         struct qemud_client *client ATTRIBUTE_UNUSED,
                                         virConnectPtr conn,
                                         remote_message_header *hdr ATTRIBUTE_UNUSED,
                                         remote_error *rerr,
                                         remote_interface_lookup_by_mac_string_args *args,
                                         remote_interface_lookup_by_mac_string_ret *ret)
{
    virInterfacePtr iface = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(iface = virInterfaceLookupByMACString(conn, args->mac)))
        goto cleanup;

    make_nonnull_interface(&ret->iface, iface);

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (iface)
        virInterfaceFree(iface);
    return rv;
}

static int
remoteDispatchInterfaceGetXmlDesc(struct qemud_server *server ATTRIBUTE_UNUSED,
                                  struct qemud_client *client ATTRIBUTE_UNUSED,
                                  virConnectPtr conn,
                                  remote_message_header *hdr ATTRIBUTE_UNUSED,
                                  remote_error *rerr,
                                  remote_interface_get_xml_desc_args *args,
                                  remote_interface_get_xml_desc_ret *ret)
{
    virInterfacePtr iface = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(iface = get_nonnull_interface(conn, args->iface)))
        goto cleanup;

    /* remoteDispatchClientRequest will free this. */
    if (!(ret->xml = virInterfaceGetXMLDesc(iface, args->flags)))
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (iface)
        virInterfaceFree(iface);
    return rv;
}

static int
remoteDispatchInterfaceDefineXml(struct qemud_server *server ATTRIBUTE_UNUSED,
                                 struct qemud_client *client ATTRIBUTE_UNUSED,
                                 virConnectPtr conn,
                                 remote_message_header *hdr ATTRIBUTE_UNUSED,
                                 remote_error *rerr,
                                 remote_interface_define_xml_args *args,
                                 remote_interface_define_xml_ret *ret)
{
    virInterfacePtr iface = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(iface = virInterfaceDefineXML(conn, args->xml, args->flags)))
        goto cleanup;

    make_nonnull_interface(&ret->iface, iface);

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (iface)
        virInterfaceFree(iface);
    return rv;
}

static int
remoteDispatchInterfaceUndefine(struct qemud_server *server ATTRIBUTE_UNUSED,
                                struct qemud_client *client ATTRIBUTE_UNUSED,
                                virConnectPtr conn,
                                remote_message_header *hdr ATTRIBUTE_UNUSED,
                                remote_error *rerr,
                                remote_interface_undefine_args *args,
                                void *ret ATTRIBUTE_UNUSED)
{
    virInterfacePtr iface = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(iface = get_nonnull_interface(conn, args->iface)))
        goto cleanup;

    if (virInterfaceUndefine(iface) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (iface)
        virInterfaceFree(iface);
    return rv;
}

static int
remoteDispatchInterfaceCreate(struct qemud_server *server ATTRIBUTE_UNUSED,
                              struct qemud_client *client ATTRIBUTE_UNUSED,
                              virConnectPtr conn,
                              remote_message_header *hdr ATTRIBUTE_UNUSED,
                              remote_error *rerr,
                              remote_interface_create_args *args,
                              void *ret ATTRIBUTE_UNUSED)
{
    virInterfacePtr iface = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(iface = get_nonnull_interface(conn, args->iface)))
        goto cleanup;

    if (virInterfaceCreate(iface, args->flags) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (iface)
        virInterfaceFree(iface);
    return rv;
}

static int
remoteDispatchInterfaceDestroy(struct qemud_server *server ATTRIBUTE_UNUSED,
                               struct qemud_client *client ATTRIBUTE_UNUSED,
                               virConnectPtr conn,
                               remote_message_header *hdr ATTRIBUTE_UNUSED,
                               remote_error *rerr,
                               remote_interface_destroy_args *args,
                               void *ret ATTRIBUTE_UNUSED)
{
    virInterfacePtr iface = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(iface = get_nonnull_interface(conn, args->iface)))
        goto cleanup;

    if (virInterfaceDestroy(iface, args->flags) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (iface)
        virInterfaceFree(iface);
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
        VIR_ERROR0(_("client tried invalid SASL init request"));
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
            VIR_ERROR0(_("cannot get TLS cipher size"));
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
        VIR_ERROR0(_("cannot allocate mechlist"));
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
        VIR_ERROR0(_("no client username was found"));
        remoteDispatchAuthError(rerr);
        sasl_dispose(&client->saslconn);
        client->saslconn = NULL;
        return -1;
    }
    VIR_DEBUG("SASL client username %s", (const char *)val);

    client->saslUsername = strdup((const char*)val);
    if (client->saslUsername == NULL) {
        VIR_ERROR0(_("out of memory copying username"));
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
        VIR_ERROR0(_("client tried invalid SASL start request"));
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
        VIR_ERROR0(_("client tried invalid SASL start request"));
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
    VIR_ERROR0(_("client tried unsupported SASL init request"));
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
    VIR_ERROR0(_("client tried unsupported SASL start request"));
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
    VIR_ERROR0(_("client tried unsupported SASL step request"));
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
        VIR_ERROR0(_("client tried invalid PolicyKit init request"));
        goto authfail;
    }

    if (qemudGetSocketIdentity(client->fd, &callerUid, &callerPid) < 0) {
        VIR_ERROR0(_("cannot get peer socket identity"));
        goto authfail;
    }

    VIR_INFO(_("Checking PID %d running as %d"), callerPid, callerUid);

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
    VIR_INFO(_("Policy allowed action %s from pid %d, uid %d"),
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
        VIR_ERROR0(_("client tried invalid PolicyKit init request"));
        goto authfail;
    }

    if (qemudGetSocketIdentity(client->fd, &callerUid, &callerPid) < 0) {
        VIR_ERROR0(_("cannot get peer socket identity"));
        goto authfail;
    }

    rv = snprintf(ident, sizeof ident, "pid:%d,uid:%d", callerPid, callerUid);
    if (rv < 0 || rv >= sizeof ident) {
        VIR_ERROR(_("Caller identity was too large %d:%d"), callerPid, callerUid);
        goto authfail;
    }

    VIR_INFO(_("Checking PID %d running as %d"), callerPid, callerUid);
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
    VIR_INFO(_("Policy allowed action %s from pid %d, uid %d, result %s"),
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
    VIR_ERROR0(_("client tried unsupported PolicyKit init request"));
    remoteDispatchAuthError(rerr);
    return -1;
}
#endif /* HAVE_POLKIT1 */


/***************************************************************
 *     STORAGE POOL APIS
 ***************************************************************/


static int
remoteDispatchListDefinedStoragePools(struct qemud_server *server ATTRIBUTE_UNUSED,
                                      struct qemud_client *client ATTRIBUTE_UNUSED,
                                      virConnectPtr conn,
                                      remote_message_header *hdr ATTRIBUTE_UNUSED,
                                      remote_error *rerr,
                                      remote_list_defined_storage_pools_args *args,
                                      remote_list_defined_storage_pools_ret *ret)
{
    int rv = -1;
    int len;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (args->maxnames > REMOTE_NETWORK_NAME_LIST_MAX) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("maxnames > REMOTE_NETWORK_NAME_LIST_MAX"));
        goto cleanup;
    }

    /* Allocate return buffer. */
    if (VIR_ALLOC_N(ret->names.names_val, args->maxnames) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    len = virConnectListDefinedStoragePools(conn,
                                            ret->names.names_val, args->maxnames);
    if (len < 0)
        goto cleanup;
    ret->names.names_len = len;

    rv = 0;

cleanup:
    if (rv < 0) {
        remoteDispatchError(rerr);
        VIR_FREE(ret->names.names_val);
    }
    return rv;
}

static int
remoteDispatchListStoragePools(struct qemud_server *server ATTRIBUTE_UNUSED,
                               struct qemud_client *client ATTRIBUTE_UNUSED,
                               virConnectPtr conn,
                               remote_message_header *hdr ATTRIBUTE_UNUSED,
                               remote_error *rerr,
                               remote_list_storage_pools_args *args,
                               remote_list_storage_pools_ret *ret)
{
    int rv = -1;
    int len;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (args->maxnames > REMOTE_STORAGE_POOL_NAME_LIST_MAX) {
        virNetError(VIR_ERR_INTERNAL_ERROR,
                    "%s", _("maxnames > REMOTE_STORAGE_POOL_NAME_LIST_MAX"));
        goto cleanup;
    }

    /* Allocate return buffer. */
    if (VIR_ALLOC_N(ret->names.names_val, args->maxnames) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    len = virConnectListStoragePools(conn,
                                     ret->names.names_val, args->maxnames);
    if (len < 0)
        goto cleanup;
    ret->names.names_len = len;

    rv = 0;

cleanup:
    if (rv < 0) {
        remoteDispatchError(rerr);
        VIR_FREE(ret->names.names_val);
    }
    return rv;
}

static int
remoteDispatchFindStoragePoolSources(struct qemud_server *server ATTRIBUTE_UNUSED,
                                     struct qemud_client *client ATTRIBUTE_UNUSED,
                                     virConnectPtr conn,
                                     remote_message_header *hdr ATTRIBUTE_UNUSED,
                                     remote_error *rerr,
                                     remote_find_storage_pool_sources_args *args,
                                     remote_find_storage_pool_sources_ret *ret)
{
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(ret->xml =
          virConnectFindStoragePoolSources(conn,
                                           args->type,
                                           args->srcSpec ? *args->srcSpec : NULL,
                                           args->flags)))
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    return rv;
}


static int
remoteDispatchStoragePoolCreate(struct qemud_server *server ATTRIBUTE_UNUSED,
                                struct qemud_client *client ATTRIBUTE_UNUSED,
                                virConnectPtr conn,
                                remote_message_header *hdr ATTRIBUTE_UNUSED,
                                remote_error *rerr,
                                remote_storage_pool_create_args *args,
                                void *ret ATTRIBUTE_UNUSED)
{
    virStoragePoolPtr pool = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(pool = get_nonnull_storage_pool(conn, args->pool)))
        goto cleanup;

    if (virStoragePoolCreate(pool, args->flags) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (pool)
        virStoragePoolFree(pool);
    return rv;
}

static int
remoteDispatchStoragePoolCreateXml(struct qemud_server *server ATTRIBUTE_UNUSED,
                                   struct qemud_client *client ATTRIBUTE_UNUSED,
                                   virConnectPtr conn,
                                   remote_message_header *hdr ATTRIBUTE_UNUSED,
                                   remote_error *rerr,
                                   remote_storage_pool_create_xml_args *args,
                                   remote_storage_pool_create_xml_ret *ret)
{
    virStoragePoolPtr pool = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(pool = virStoragePoolCreateXML(conn, args->xml, args->flags)))
        goto cleanup;

    make_nonnull_storage_pool(&ret->pool, pool);

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (pool)
        virStoragePoolFree(pool);
    return rv;
}

static int
remoteDispatchStoragePoolDefineXml(struct qemud_server *server ATTRIBUTE_UNUSED,
                                   struct qemud_client *client ATTRIBUTE_UNUSED,
                                   virConnectPtr conn,
                                   remote_message_header *hdr ATTRIBUTE_UNUSED,
                                   remote_error *rerr,
                                   remote_storage_pool_define_xml_args *args,
                                   remote_storage_pool_define_xml_ret *ret)
{
    virStoragePoolPtr pool = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(pool = virStoragePoolDefineXML(conn, args->xml, args->flags)))
        goto cleanup;

    make_nonnull_storage_pool(&ret->pool, pool);

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (pool)
        virStoragePoolFree(pool);
    return rv;
}

static int
remoteDispatchStoragePoolBuild(struct qemud_server *server ATTRIBUTE_UNUSED,
                               struct qemud_client *client ATTRIBUTE_UNUSED,
                               virConnectPtr conn,
                               remote_message_header *hdr ATTRIBUTE_UNUSED,
                               remote_error *rerr,
                               remote_storage_pool_build_args *args,
                               void *ret ATTRIBUTE_UNUSED)
{
    virStoragePoolPtr pool = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(pool = get_nonnull_storage_pool(conn, args->pool)))
        goto cleanup;

    if (virStoragePoolBuild(pool, args->flags) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (pool)
        virStoragePoolFree(pool);
    return rv;
}


static int
remoteDispatchStoragePoolDestroy(struct qemud_server *server ATTRIBUTE_UNUSED,
                                 struct qemud_client *client ATTRIBUTE_UNUSED,
                                 virConnectPtr conn,
                                 remote_message_header *hdr ATTRIBUTE_UNUSED,
                                 remote_error *rerr,
                                 remote_storage_pool_destroy_args *args,
                                 void *ret ATTRIBUTE_UNUSED)
{
    virStoragePoolPtr pool = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(pool = get_nonnull_storage_pool(conn, args->pool)))
        goto cleanup;

    if (virStoragePoolDestroy(pool) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (pool)
        virStoragePoolFree(pool);
    return rv;
}

static int
remoteDispatchStoragePoolDelete(struct qemud_server *server ATTRIBUTE_UNUSED,
                                struct qemud_client *client ATTRIBUTE_UNUSED,
                                virConnectPtr conn,
                                remote_message_header *hdr ATTRIBUTE_UNUSED,
                                remote_error *rerr,
                                remote_storage_pool_delete_args *args,
                                void *ret ATTRIBUTE_UNUSED)
{
    virStoragePoolPtr pool = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(pool = get_nonnull_storage_pool(conn, args->pool)))
        goto cleanup;

    if (virStoragePoolDelete(pool, args->flags) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (pool)
        virStoragePoolFree(pool);
    return rv;
}

static int
remoteDispatchStoragePoolRefresh(struct qemud_server *server ATTRIBUTE_UNUSED,
                                 struct qemud_client *client ATTRIBUTE_UNUSED,
                                 virConnectPtr conn,
                                 remote_message_header *hdr ATTRIBUTE_UNUSED,
                                 remote_error *rerr,
                                 remote_storage_pool_refresh_args *args,
                                 void *ret ATTRIBUTE_UNUSED)
{
    virStoragePoolPtr pool = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(pool = get_nonnull_storage_pool(conn, args->pool)))
        goto cleanup;

    if (virStoragePoolRefresh(pool, args->flags) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (pool)
        virStoragePoolFree(pool);
    return rv;
}

static int
remoteDispatchStoragePoolGetInfo(struct qemud_server *server ATTRIBUTE_UNUSED,
                                 struct qemud_client *client ATTRIBUTE_UNUSED,
                                 virConnectPtr conn,
                                 remote_message_header *hdr ATTRIBUTE_UNUSED,
                                 remote_error *rerr,
                                 remote_storage_pool_get_info_args *args,
                                 remote_storage_pool_get_info_ret *ret)
{
    virStoragePoolPtr pool = NULL;
    virStoragePoolInfo info;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(pool = get_nonnull_storage_pool(conn, args->pool)))
        goto cleanup;

    if (virStoragePoolGetInfo(pool, &info) < 0)
        goto cleanup;

    ret->state = info.state;
    ret->capacity = info.capacity;
    ret->allocation = info.allocation;
    ret->available = info.available;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (pool)
        virStoragePoolFree(pool);
    return rv;
}

static int
remoteDispatchStoragePoolDumpXml(struct qemud_server *server ATTRIBUTE_UNUSED,
                                 struct qemud_client *client ATTRIBUTE_UNUSED,
                                 virConnectPtr conn,
                                 remote_message_header *hdr ATTRIBUTE_UNUSED,
                                 remote_error *rerr,
                                 remote_storage_pool_dump_xml_args *args,
                                 remote_storage_pool_dump_xml_ret *ret)
{
    virStoragePoolPtr pool = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(pool = get_nonnull_storage_pool(conn, args->pool)))
        goto cleanup;

    /* remoteDispatchClientRequest will free this. */
    if (!(ret->xml = virStoragePoolGetXMLDesc(pool, args->flags)))
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (pool)
        virStoragePoolFree(pool);
    return rv;
}

static int
remoteDispatchStoragePoolGetAutostart(struct qemud_server *server ATTRIBUTE_UNUSED,
                                      struct qemud_client *client ATTRIBUTE_UNUSED,
                                      virConnectPtr conn,
                                      remote_message_header *hdr ATTRIBUTE_UNUSED,
                                      remote_error *rerr,
                                      remote_storage_pool_get_autostart_args *args,
                                      remote_storage_pool_get_autostart_ret *ret)
{
    virStoragePoolPtr pool = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(pool = get_nonnull_storage_pool(conn, args->pool)))
        goto cleanup;

    if (virStoragePoolGetAutostart(pool, &ret->autostart) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (pool)
        virStoragePoolFree(pool);
    return rv;
}


static int
remoteDispatchStoragePoolLookupByName(struct qemud_server *server ATTRIBUTE_UNUSED,
                                      struct qemud_client *client ATTRIBUTE_UNUSED,
                                      virConnectPtr conn,
                                      remote_message_header *hdr ATTRIBUTE_UNUSED,
                                      remote_error *rerr,
                                      remote_storage_pool_lookup_by_name_args *args,
                                      remote_storage_pool_lookup_by_name_ret *ret)
{
    virStoragePoolPtr pool = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(pool = virStoragePoolLookupByName(conn, args->name)))
        goto cleanup;

    make_nonnull_storage_pool(&ret->pool, pool);

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (pool)
        virStoragePoolFree(pool);
    return rv;
}

static int
remoteDispatchStoragePoolLookupByUuid(struct qemud_server *server ATTRIBUTE_UNUSED,
                                      struct qemud_client *client ATTRIBUTE_UNUSED,
                                      virConnectPtr conn,
                                      remote_message_header *hdr ATTRIBUTE_UNUSED,
                                      remote_error *rerr,
                                      remote_storage_pool_lookup_by_uuid_args *args,
                                      remote_storage_pool_lookup_by_uuid_ret *ret)
{
    virStoragePoolPtr pool = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(pool = virStoragePoolLookupByUUID(conn, (unsigned char *) args->uuid)))
        goto cleanup;

    make_nonnull_storage_pool(&ret->pool, pool);

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (pool)
        virStoragePoolFree(pool);
    return rv;
}

static int
remoteDispatchStoragePoolLookupByVolume(struct qemud_server *server ATTRIBUTE_UNUSED,
                                        struct qemud_client *client ATTRIBUTE_UNUSED,
                                        virConnectPtr conn,
                                        remote_message_header *hdr ATTRIBUTE_UNUSED,
                                        remote_error *rerr,
                                        remote_storage_pool_lookup_by_volume_args *args,
                                        remote_storage_pool_lookup_by_volume_ret *ret)
{
    virStoragePoolPtr pool = NULL;
    virStorageVolPtr vol = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(vol = get_nonnull_storage_vol(conn, args->vol)))
        goto cleanup;

    if (!(pool = virStoragePoolLookupByVolume(vol)))
        goto cleanup;

    make_nonnull_storage_pool(&ret->pool, pool);

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (vol)
        virStorageVolFree(vol);
    if (pool)
        virStoragePoolFree(pool);
    return rv;
}

static int
remoteDispatchStoragePoolSetAutostart(struct qemud_server *server ATTRIBUTE_UNUSED,
                                      struct qemud_client *client ATTRIBUTE_UNUSED,
                                      virConnectPtr conn,
                                      remote_message_header *hdr ATTRIBUTE_UNUSED,
                                      remote_error *rerr,
                                      remote_storage_pool_set_autostart_args *args,
                                      void *ret ATTRIBUTE_UNUSED)
{
    virStoragePoolPtr pool = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(pool = get_nonnull_storage_pool(conn, args->pool)))
        goto cleanup;

    if (virStoragePoolSetAutostart(pool, args->autostart) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (pool)
        virStoragePoolFree(pool);
    return rv;
}

static int
remoteDispatchStoragePoolUndefine(struct qemud_server *server ATTRIBUTE_UNUSED,
                                  struct qemud_client *client ATTRIBUTE_UNUSED,
                                  virConnectPtr conn,
                                  remote_message_header *hdr ATTRIBUTE_UNUSED,
                                  remote_error *rerr,
                                  remote_storage_pool_undefine_args *args,
                                  void *ret ATTRIBUTE_UNUSED)
{
    virStoragePoolPtr pool = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(pool = get_nonnull_storage_pool(conn, args->pool)))
        goto cleanup;

    if (virStoragePoolUndefine(pool) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (pool)
        virStoragePoolFree(pool);
    return rv;
}

static int
remoteDispatchNumOfStoragePools(struct qemud_server *server ATTRIBUTE_UNUSED,
                                struct qemud_client *client ATTRIBUTE_UNUSED,
                                virConnectPtr conn,
                                remote_message_header *hdr ATTRIBUTE_UNUSED,
                                remote_error *rerr,
                                void *args ATTRIBUTE_UNUSED,
                                remote_num_of_storage_pools_ret *ret)
{
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if ((ret->num = virConnectNumOfStoragePools(conn)) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    return rv;
}

static int
remoteDispatchNumOfDefinedStoragePools(struct qemud_server *server ATTRIBUTE_UNUSED,
                                       struct qemud_client *client ATTRIBUTE_UNUSED,
                                       virConnectPtr conn,
                                       remote_message_header *hdr ATTRIBUTE_UNUSED,
                                       remote_error *rerr,
                                       void *args ATTRIBUTE_UNUSED,
                                       remote_num_of_defined_storage_pools_ret *ret)
{
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if ((ret->num = virConnectNumOfDefinedStoragePools(conn)) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    return rv;
}

static int
remoteDispatchStoragePoolListVolumes(struct qemud_server *server ATTRIBUTE_UNUSED,
                                     struct qemud_client *client ATTRIBUTE_UNUSED,
                                     virConnectPtr conn,
                                     remote_message_header *hdr ATTRIBUTE_UNUSED,
                                     remote_error *rerr,
                                     remote_storage_pool_list_volumes_args *args,
                                     remote_storage_pool_list_volumes_ret *ret)
{
    virStoragePoolPtr pool = NULL;
    int rv = -1;
    int len;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (args->maxnames > REMOTE_STORAGE_VOL_NAME_LIST_MAX) {
        virNetError(VIR_ERR_INTERNAL_ERROR,
                    "%s", _("maxnames > REMOTE_STORAGE_VOL_NAME_LIST_MAX"));
        goto cleanup;
    }

    if (!(pool = get_nonnull_storage_pool(conn, args->pool)))
        goto cleanup;

    /* Allocate return buffer. */
    if (VIR_ALLOC_N(ret->names.names_val, args->maxnames) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    len = virStoragePoolListVolumes(pool,
                                    ret->names.names_val, args->maxnames);
    if (len < 0)
        goto cleanup;
    ret->names.names_len = len;

    rv = 0;

cleanup:
    if (rv < 0) {
        remoteDispatchError(rerr);
        VIR_FREE(ret->names.names_val);
    }
    if (pool)
        virStoragePoolFree(pool);
    return rv;
}


static int
remoteDispatchStoragePoolNumOfVolumes(struct qemud_server *server ATTRIBUTE_UNUSED,
                                      struct qemud_client *client ATTRIBUTE_UNUSED,
                                      virConnectPtr conn,
                                      remote_message_header *hdr ATTRIBUTE_UNUSED,
                                      remote_error *rerr,
                                      remote_storage_pool_num_of_volumes_args *args,
                                      remote_storage_pool_num_of_volumes_ret *ret)
{
    virStoragePoolPtr pool = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(pool = get_nonnull_storage_pool(conn, args->pool)))
        goto cleanup;

    if ((ret->num = virStoragePoolNumOfVolumes(pool)) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (pool)
        virStoragePoolFree(pool);
    return rv;
}


/***************************************************************
 *     STORAGE VOL APIS
 ***************************************************************/



static int
remoteDispatchStorageVolCreateXml(struct qemud_server *server ATTRIBUTE_UNUSED,
                                  struct qemud_client *client ATTRIBUTE_UNUSED,
                                  virConnectPtr conn,
                                  remote_message_header *hdr ATTRIBUTE_UNUSED,
                                  remote_error *rerr,
                                  remote_storage_vol_create_xml_args *args,
                                  remote_storage_vol_create_xml_ret *ret)
{
    virStoragePoolPtr pool = NULL;
    virStorageVolPtr vol = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(pool = get_nonnull_storage_pool(conn, args->pool)))
        goto cleanup;

    if (!(vol = virStorageVolCreateXML(pool, args->xml, args->flags)))
        goto cleanup;

    make_nonnull_storage_vol(&ret->vol, vol);
    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (pool)
        virStoragePoolFree(pool);
    if (vol)
        virStorageVolFree(vol);
    return rv;
}

static int
remoteDispatchStorageVolCreateXmlFrom(struct qemud_server *server ATTRIBUTE_UNUSED,
                                      struct qemud_client *client ATTRIBUTE_UNUSED,
                                      virConnectPtr conn,
                                      remote_message_header *hdr ATTRIBUTE_UNUSED,
                                      remote_error *rerr,
                                      remote_storage_vol_create_xml_from_args *args,
                                      remote_storage_vol_create_xml_from_ret *ret)
{
    virStoragePoolPtr pool = NULL;
    virStorageVolPtr clonevol = NULL;
    virStorageVolPtr newvol = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(pool = get_nonnull_storage_pool(conn, args->pool)))
        goto cleanup;

    if (!(clonevol = get_nonnull_storage_vol(conn, args->clonevol)))
        goto cleanup;

    if (!(newvol = virStorageVolCreateXMLFrom(pool, args->xml, clonevol,
                                              args->flags)))
        goto cleanup;

    make_nonnull_storage_vol(&ret->vol, newvol);
    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (newvol)
        virStorageVolFree(newvol);
    if (clonevol)
        virStorageVolFree(clonevol);
    if (pool)
        virStoragePoolFree(pool);
    return rv;
}

static int
remoteDispatchStorageVolDelete(struct qemud_server *server ATTRIBUTE_UNUSED,
                               struct qemud_client *client ATTRIBUTE_UNUSED,
                               virConnectPtr conn,
                               remote_message_header *hdr ATTRIBUTE_UNUSED,
                               remote_error *rerr,
                               remote_storage_vol_delete_args *args,
                               void *ret ATTRIBUTE_UNUSED)
{
    virStorageVolPtr vol = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(vol = get_nonnull_storage_vol(conn, args->vol)))
        goto cleanup;

    if (virStorageVolDelete(vol, args->flags) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (vol)
        virStorageVolFree(vol);
    return rv;
}

static int
remoteDispatchStorageVolWipe(struct qemud_server *server ATTRIBUTE_UNUSED,
                             struct qemud_client *client ATTRIBUTE_UNUSED,
                             virConnectPtr conn,
                             remote_message_header *hdr ATTRIBUTE_UNUSED,
                             remote_error *rerr,
                             remote_storage_vol_wipe_args *args,
                             void *ret ATTRIBUTE_UNUSED)
{
    virStorageVolPtr vol = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(vol = get_nonnull_storage_vol(conn, args->vol)))
        goto cleanup;

    if (virStorageVolWipe(vol, args->flags) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (vol)
        virStorageVolFree(vol);
    return rv;
}

static int
remoteDispatchStorageVolGetInfo(struct qemud_server *server ATTRIBUTE_UNUSED,
                                struct qemud_client *client ATTRIBUTE_UNUSED,
                                virConnectPtr conn,
                                remote_message_header *hdr ATTRIBUTE_UNUSED,
                                remote_error *rerr,
                                remote_storage_vol_get_info_args *args,
                                remote_storage_vol_get_info_ret *ret)
{
    virStorageVolPtr vol = NULL;
    virStorageVolInfo info;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(vol = get_nonnull_storage_vol(conn, args->vol)))
        goto cleanup;

    if (virStorageVolGetInfo(vol, &info) < 0)
        goto cleanup;

    ret->type = info.type;
    ret->capacity = info.capacity;
    ret->allocation = info.allocation;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (vol)
        virStorageVolFree(vol);
    return rv;
}

static int
remoteDispatchStorageVolDumpXml(struct qemud_server *server ATTRIBUTE_UNUSED,
                                struct qemud_client *client ATTRIBUTE_UNUSED,
                                virConnectPtr conn,
                                remote_message_header *hdr ATTRIBUTE_UNUSED,
                                remote_error *rerr,
                                remote_storage_vol_dump_xml_args *args,
                                remote_storage_vol_dump_xml_ret *ret)
{
    virStorageVolPtr vol = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(vol = get_nonnull_storage_vol(conn, args->vol)))
        goto cleanup;

    /* remoteDispatchClientRequest will free this. */
    if (!(ret->xml = virStorageVolGetXMLDesc(vol, args->flags)))
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (vol)
        virStorageVolFree(vol);
    return rv;
}


static int
remoteDispatchStorageVolGetPath(struct qemud_server *server ATTRIBUTE_UNUSED,
                                struct qemud_client *client ATTRIBUTE_UNUSED,
                                virConnectPtr conn,
                                remote_message_header *hdr ATTRIBUTE_UNUSED,
                                remote_error *rerr,
                                remote_storage_vol_get_path_args *args,
                                remote_storage_vol_get_path_ret *ret)
{
    virStorageVolPtr vol = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(vol = get_nonnull_storage_vol(conn, args->vol)))
        goto cleanup;

    /* remoteDispatchClientRequest will free this. */
    if (!(ret->name = virStorageVolGetPath(vol)))
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (vol)
        virStorageVolFree(vol);
    return rv;
}


static int
remoteDispatchStorageVolLookupByName(struct qemud_server *server ATTRIBUTE_UNUSED,
                                     struct qemud_client *client ATTRIBUTE_UNUSED,
                                     virConnectPtr conn,
                                     remote_message_header *hdr ATTRIBUTE_UNUSED,
                                     remote_error *rerr,
                                     remote_storage_vol_lookup_by_name_args *args,
                                     remote_storage_vol_lookup_by_name_ret *ret)
{
    virStoragePoolPtr pool = NULL;
    virStorageVolPtr vol = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(pool = get_nonnull_storage_pool(conn, args->pool)))
        goto cleanup;

    if (!(vol = virStorageVolLookupByName(pool, args->name)))
        goto cleanup;

    make_nonnull_storage_vol(&ret->vol, vol);

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (pool)
        virStoragePoolFree(pool);
    if (vol)
        virStorageVolFree(vol);
    return rv;
}

static int
remoteDispatchStorageVolLookupByKey(struct qemud_server *server ATTRIBUTE_UNUSED,
                                    struct qemud_client *client ATTRIBUTE_UNUSED,
                                    virConnectPtr conn,
                                    remote_message_header *hdr ATTRIBUTE_UNUSED,
                                    remote_error *rerr,
                                    remote_storage_vol_lookup_by_key_args *args,
                                    remote_storage_vol_lookup_by_key_ret *ret)
{
    virStorageVolPtr vol = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(vol = virStorageVolLookupByKey(conn, args->key)))
        goto cleanup;

    make_nonnull_storage_vol(&ret->vol, vol);

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (vol)
        virStorageVolFree(vol);
    return rv;
}


static int
remoteDispatchStorageVolLookupByPath(struct qemud_server *server ATTRIBUTE_UNUSED,
                                     struct qemud_client *client ATTRIBUTE_UNUSED,
                                     virConnectPtr conn,
                                     remote_message_header *hdr ATTRIBUTE_UNUSED,
                                     remote_error *rerr,
                                     remote_storage_vol_lookup_by_path_args *args,
                                     remote_storage_vol_lookup_by_path_ret *ret)
{
    virStorageVolPtr vol = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(vol = virStorageVolLookupByPath(conn, args->path)))
        goto cleanup;

    make_nonnull_storage_vol(&ret->vol, vol);

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (vol)
        virStorageVolFree(vol);
    return rv;
}


/***************************************************************
 *     NODE INFO APIS
 **************************************************************/

static int
remoteDispatchNodeNumOfDevices(struct qemud_server *server ATTRIBUTE_UNUSED,
                               struct qemud_client *client ATTRIBUTE_UNUSED,
                               virConnectPtr conn,
                               remote_message_header *hdr ATTRIBUTE_UNUSED,
                               remote_error *rerr,
                               remote_node_num_of_devices_args *args,
                               remote_node_num_of_devices_ret *ret)
{
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if ((ret->num = virNodeNumOfDevices(conn,
                                        args->cap ? *args->cap : NULL,
                                        args->flags)) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    return rv;
}


static int
remoteDispatchNodeListDevices(struct qemud_server *server ATTRIBUTE_UNUSED,
                              struct qemud_client *client ATTRIBUTE_UNUSED,
                              virConnectPtr conn,
                              remote_message_header *hdr ATTRIBUTE_UNUSED,
                              remote_error *rerr,
                              remote_node_list_devices_args *args,
                              remote_node_list_devices_ret *ret)
{
    int rv = -1;
    int len;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (args->maxnames > REMOTE_NODE_DEVICE_NAME_LIST_MAX) {
        virNetError(VIR_ERR_INTERNAL_ERROR,
                    "%s", _("maxnames > REMOTE_NODE_DEVICE_NAME_LIST_MAX"));
        goto cleanup;
    }

    /* Allocate return buffer. */
    if (VIR_ALLOC_N(ret->names.names_val, args->maxnames) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    len = virNodeListDevices(conn,
                             args->cap ? *args->cap : NULL,
                             ret->names.names_val, args->maxnames, args->flags);
    if (len < 0)
        goto cleanup;
    ret->names.names_len = len;

    rv = 0;

cleanup:
    if (rv < 0) {
        remoteDispatchError(rerr);
        VIR_FREE(ret->names.names_val);
    }
    return rv;
}


static int
remoteDispatchNodeDeviceLookupByName(struct qemud_server *server ATTRIBUTE_UNUSED,
                                     struct qemud_client *client ATTRIBUTE_UNUSED,
                                     virConnectPtr conn,
                                     remote_message_header *hdr ATTRIBUTE_UNUSED,
                                     remote_error *rerr,
                                     remote_node_device_lookup_by_name_args *args,
                                     remote_node_device_lookup_by_name_ret *ret)
{
    virNodeDevicePtr dev = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dev = virNodeDeviceLookupByName(conn, args->name)))
        goto cleanup;

    make_nonnull_node_device(&ret->dev, dev);

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (dev)
        virNodeDeviceFree(dev);
    return rv;
}


static int
remoteDispatchNodeDeviceDumpXml(struct qemud_server *server ATTRIBUTE_UNUSED,
                                struct qemud_client *client ATTRIBUTE_UNUSED,
                                virConnectPtr conn,
                                remote_message_header *hdr ATTRIBUTE_UNUSED,
                                remote_error *rerr,
                                remote_node_device_dump_xml_args *args,
                                remote_node_device_dump_xml_ret *ret)
{
    virNodeDevicePtr dev = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dev = virNodeDeviceLookupByName(conn, args->name)))
        goto cleanup;

    /* remoteDispatchClientRequest will free this. */
    if (!(ret->xml = virNodeDeviceGetXMLDesc(dev, args->flags)))
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (dev)
        virNodeDeviceFree(dev);
    return rv;
}


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


static int
remoteDispatchNodeDeviceNumOfCaps(struct qemud_server *server ATTRIBUTE_UNUSED,
                                  struct qemud_client *client ATTRIBUTE_UNUSED,
                                  virConnectPtr conn,
                                  remote_message_header *hdr ATTRIBUTE_UNUSED,
                                  remote_error *rerr,
                                  remote_node_device_num_of_caps_args *args,
                                  remote_node_device_num_of_caps_ret *ret)
{
    virNodeDevicePtr dev = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dev = virNodeDeviceLookupByName(conn, args->name)))
        goto cleanup;

    if ((ret->num = virNodeDeviceNumOfCaps(dev)) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (dev)
        virNodeDeviceFree(dev);
    return rv;
}


static int
remoteDispatchNodeDeviceListCaps(struct qemud_server *server ATTRIBUTE_UNUSED,
                                 struct qemud_client *client ATTRIBUTE_UNUSED,
                                 virConnectPtr conn,
                                 remote_message_header *hdr ATTRIBUTE_UNUSED,
                                 remote_error *rerr,
                                 remote_node_device_list_caps_args *args,
                                 remote_node_device_list_caps_ret *ret)
{
    virNodeDevicePtr dev = NULL;
    int rv = -1;
    int len;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dev = virNodeDeviceLookupByName(conn, args->name)))
        goto cleanup;

    if (args->maxnames > REMOTE_NODE_DEVICE_NAME_LIST_MAX) {
        virNetError(VIR_ERR_INTERNAL_ERROR,
                    "%s", _("maxnames > REMOTE_NODE_DEVICE_NAME_LIST_MAX"));
        goto cleanup;
    }

    /* Allocate return buffer. */
    if (VIR_ALLOC_N(ret->names.names_val, args->maxnames) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    len = virNodeDeviceListCaps(dev, ret->names.names_val,
                                args->maxnames);
    if (len < 0)
        goto cleanup;
    ret->names.names_len = len;

    rv = 0;

cleanup:
    if (rv < 0) {
        remoteDispatchError(rerr);
        VIR_FREE(ret->names.names_val);
    }
    if (dev)
        virNodeDeviceFree(dev);
    return rv;
}


static int
remoteDispatchNodeDeviceDettach(struct qemud_server *server ATTRIBUTE_UNUSED,
                                struct qemud_client *client ATTRIBUTE_UNUSED,
                                virConnectPtr conn,
                                remote_message_header *hdr ATTRIBUTE_UNUSED,
                                remote_error *rerr,
                                remote_node_device_dettach_args *args,
                                void *ret ATTRIBUTE_UNUSED)
{
    virNodeDevicePtr dev = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dev = virNodeDeviceLookupByName(conn, args->name)))
        goto cleanup;

    if (virNodeDeviceDettach(dev) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (dev)
        virNodeDeviceFree(dev);
    return rv;
}


static int
remoteDispatchNodeDeviceReAttach(struct qemud_server *server ATTRIBUTE_UNUSED,
                                 struct qemud_client *client ATTRIBUTE_UNUSED,
                                 virConnectPtr conn,
                                 remote_message_header *hdr ATTRIBUTE_UNUSED,
                                 remote_error *rerr,
                                 remote_node_device_re_attach_args *args,
                                 void *ret ATTRIBUTE_UNUSED)
{
    virNodeDevicePtr dev = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dev = virNodeDeviceLookupByName(conn, args->name)))
        goto cleanup;

    if (virNodeDeviceReAttach(dev) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (dev)
        virNodeDeviceFree(dev);
    return rv;
}


static int
remoteDispatchNodeDeviceReset(struct qemud_server *server ATTRIBUTE_UNUSED,
                              struct qemud_client *client ATTRIBUTE_UNUSED,
                              virConnectPtr conn,
                              remote_message_header *hdr ATTRIBUTE_UNUSED,
                              remote_error *rerr,
                              remote_node_device_reset_args *args,
                              void *ret ATTRIBUTE_UNUSED)
{
    virNodeDevicePtr dev = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dev = virNodeDeviceLookupByName(conn, args->name)))
        goto cleanup;

    if (virNodeDeviceReset(dev) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (dev)
        virNodeDeviceFree(dev);
    return rv;
}


static int
remoteDispatchNodeDeviceCreateXml(struct qemud_server *server ATTRIBUTE_UNUSED,
                                  struct qemud_client *client ATTRIBUTE_UNUSED,
                                  virConnectPtr conn,
                                  remote_message_header *hdr ATTRIBUTE_UNUSED,
                                  remote_error *rerr,
                                  remote_node_device_create_xml_args *args,
                                  remote_node_device_create_xml_ret *ret)
{
    virNodeDevicePtr dev = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dev = virNodeDeviceCreateXML(conn, args->xml_desc, args->flags)))
        goto cleanup;

    make_nonnull_node_device(&ret->dev, dev);

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (dev)
        virNodeDeviceFree(dev);
    return rv;
}


static int
remoteDispatchNodeDeviceDestroy(struct qemud_server *server ATTRIBUTE_UNUSED,
                                struct qemud_client *client ATTRIBUTE_UNUSED,
                                virConnectPtr conn,
                                remote_message_header *hdr ATTRIBUTE_UNUSED,
                                remote_error *rerr,
                                remote_node_device_destroy_args *args,
                                void *ret ATTRIBUTE_UNUSED)
{
    virNodeDevicePtr dev = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dev = virNodeDeviceLookupByName(conn, args->name)))
        goto cleanup;

    if (virNodeDeviceDestroy(dev) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (dev)
        virNodeDeviceFree(dev);
    return rv;
}

static int remoteDispatchStorageVolUpload(struct qemud_server *server ATTRIBUTE_UNUSED,
                                          struct qemud_client *client,
                                          virConnectPtr conn,
                                          remote_message_header *hdr,
                                          remote_error *rerr,
                                          remote_storage_vol_upload_args *args,
                                          void *ret ATTRIBUTE_UNUSED)
{
    struct qemud_client_stream *stream = NULL;
    virStorageVolPtr vol = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(vol = get_nonnull_storage_vol(conn, args->vol)))
        goto cleanup;

    if (!(stream = remoteCreateClientStream(conn, hdr)))
        goto cleanup;

    if (virStorageVolUpload(vol, stream->st,
                            args->offset, args->length,
                            args->flags) < 0)
        goto cleanup;

    if (remoteAddClientStream(client, stream, 0) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (vol)
        virStorageVolFree(vol);
    if (stream && rv != 0) {
        virStreamAbort(stream->st);
        remoteFreeClientStream(client, stream);
    }
    return rv;
}

static int remoteDispatchStorageVolDownload(struct qemud_server *server ATTRIBUTE_UNUSED,
                                            struct qemud_client *client,
                                            virConnectPtr conn,
                                            remote_message_header *hdr,
                                            remote_error *rerr,
                                            remote_storage_vol_download_args *args,
                                            void *ret ATTRIBUTE_UNUSED)
{
    struct qemud_client_stream *stream = NULL;
    virStorageVolPtr vol = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(vol = get_nonnull_storage_vol(conn, args->vol)))
        goto cleanup;

    if (!(stream = remoteCreateClientStream(conn, hdr)))
        goto cleanup;

    if (virStorageVolDownload(vol, stream->st,
                              args->offset, args->length,
                              args->flags) < 0)
        goto cleanup;

    if (remoteAddClientStream(client, stream, 1) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (vol)
        virStorageVolFree(vol);
    if (stream && rv != 0) {
        virStreamAbort(stream->st);
        remoteFreeClientStream(client, stream);
    }
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
remoteDispatchNumOfSecrets(struct qemud_server *server ATTRIBUTE_UNUSED,
                           struct qemud_client *client ATTRIBUTE_UNUSED,
                           virConnectPtr conn,
                           remote_message_header *hdr ATTRIBUTE_UNUSED,
                           remote_error *rerr,
                           void *args ATTRIBUTE_UNUSED,
                           remote_num_of_secrets_ret *ret)
{
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if ((ret->num = virConnectNumOfSecrets(conn)) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    return rv;
}

static int
remoteDispatchListSecrets(struct qemud_server *server ATTRIBUTE_UNUSED,
                          struct qemud_client *client ATTRIBUTE_UNUSED,
                          virConnectPtr conn,
                          remote_message_header *hdr ATTRIBUTE_UNUSED,
                          remote_error *rerr,
                          remote_list_secrets_args *args,
                          remote_list_secrets_ret *ret)
{
    int rv = -1;
    int len;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (args->maxuuids > REMOTE_SECRET_UUID_LIST_MAX) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("maxuuids > REMOTE_SECRET_UUID_LIST_MAX"));
        goto cleanup;
    }

    if (VIR_ALLOC_N(ret->uuids.uuids_val, args->maxuuids) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    len = virConnectListSecrets(conn, ret->uuids.uuids_val,
                                args->maxuuids);
    if (len < 0)
        goto cleanup;
    ret->uuids.uuids_len = len;

    rv = 0;

cleanup:
    if (rv < 0) {
        remoteDispatchError(rerr);
        VIR_FREE(ret->uuids.uuids_val);
    }
    return rv;
}

static int
remoteDispatchSecretDefineXml(struct qemud_server *server ATTRIBUTE_UNUSED,
                              struct qemud_client *client ATTRIBUTE_UNUSED,
                              virConnectPtr conn,
                              remote_message_header *hdr ATTRIBUTE_UNUSED,
                              remote_error *rerr,
                              remote_secret_define_xml_args *args,
                              remote_secret_define_xml_ret *ret)
{
    virSecretPtr secret = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(secret = virSecretDefineXML(conn, args->xml, args->flags)))
        goto cleanup;

    make_nonnull_secret(&ret->secret, secret);
    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (secret)
        virSecretFree(secret);
    return rv;
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
remoteDispatchSecretGetXmlDesc(struct qemud_server *server ATTRIBUTE_UNUSED,
                               struct qemud_client *client ATTRIBUTE_UNUSED,
                               virConnectPtr conn,
                               remote_message_header *hdr ATTRIBUTE_UNUSED,
                               remote_error *rerr,
                               remote_secret_get_xml_desc_args *args,
                               remote_secret_get_xml_desc_ret *ret)
{
    virSecretPtr secret = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(secret = get_nonnull_secret(conn, args->secret)))
        goto cleanup;
    if (!(ret->xml = virSecretGetXMLDesc(secret, args->flags)))
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (secret)
        virSecretFree(secret);
    return rv;
}

static int
remoteDispatchSecretLookupByUuid(struct qemud_server *server ATTRIBUTE_UNUSED,
                                 struct qemud_client *client ATTRIBUTE_UNUSED,
                                 virConnectPtr conn,
                                 remote_message_header *hdr ATTRIBUTE_UNUSED,
                                 remote_error *rerr,
                                 remote_secret_lookup_by_uuid_args *args,
                                 remote_secret_lookup_by_uuid_ret *ret)
{
    virSecretPtr secret = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(secret = virSecretLookupByUUID(conn, (unsigned char *)args->uuid)))
        goto cleanup;

    make_nonnull_secret(&ret->secret, secret);

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (secret)
        virSecretFree(secret);
    return rv;
}

static int
remoteDispatchSecretSetValue(struct qemud_server *server ATTRIBUTE_UNUSED,
                             struct qemud_client *client ATTRIBUTE_UNUSED,
                             virConnectPtr conn,
                             remote_message_header *hdr ATTRIBUTE_UNUSED,
                             remote_error *rerr,
                             remote_secret_set_value_args *args,
                             void *ret ATTRIBUTE_UNUSED)
{
    virSecretPtr secret = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(secret = get_nonnull_secret(conn, args->secret)))
        goto cleanup;
    if (virSecretSetValue(secret, (const unsigned char *)args->value.value_val,
                          args->value.value_len, args->flags) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (secret)
        virSecretFree(secret);
    return rv;
}

static int
remoteDispatchSecretUndefine(struct qemud_server *server ATTRIBUTE_UNUSED,
                             struct qemud_client *client ATTRIBUTE_UNUSED,
                             virConnectPtr conn,
                             remote_message_header *hdr ATTRIBUTE_UNUSED,
                             remote_error *rerr,
                             remote_secret_undefine_args *args,
                             void *ret ATTRIBUTE_UNUSED)
{
    virSecretPtr secret = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(secret = get_nonnull_secret(conn, args->secret)))
        goto cleanup;
    if (virSecretUndefine(secret) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (secret)
        virSecretFree(secret);
    return rv;
}

static int
remoteDispatchSecretLookupByUsage(struct qemud_server *server ATTRIBUTE_UNUSED,
                                  struct qemud_client *client ATTRIBUTE_UNUSED,
                                  virConnectPtr conn,
                                  remote_message_header *hdr ATTRIBUTE_UNUSED,
                                  remote_error *rerr,
                                  remote_secret_lookup_by_usage_args *args,
                                  remote_secret_lookup_by_usage_ret *ret)
{
    virSecretPtr secret = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(secret = virSecretLookupByUsage(conn, args->usageType, args->usageID)))
        goto cleanup;

    make_nonnull_secret(&ret->secret, secret);

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (secret)
        virSecretFree(secret);
    return rv;
}


static int remoteDispatchDomainIsActive(struct qemud_server *server ATTRIBUTE_UNUSED,
                                        struct qemud_client *client ATTRIBUTE_UNUSED,
                                        virConnectPtr conn,
                                        remote_message_header *hdr ATTRIBUTE_UNUSED,
                                        remote_error *rerr,
                                        remote_domain_is_active_args *args,
                                        remote_domain_is_active_ret *ret)
{
    virDomainPtr dom = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(conn, args->dom)))
        goto cleanup;

    if ((ret->active = virDomainIsActive(dom)) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (dom)
        virDomainFree(dom);
    return rv;
}

static int remoteDispatchDomainIsPersistent(struct qemud_server *server ATTRIBUTE_UNUSED,
                                            struct qemud_client *client ATTRIBUTE_UNUSED,
                                            virConnectPtr conn,
                                            remote_message_header *hdr ATTRIBUTE_UNUSED,
                                            remote_error *rerr,
                                            remote_domain_is_persistent_args *args,
                                            remote_domain_is_persistent_ret *ret)
{
    virDomainPtr dom = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(conn, args->dom)))
        goto cleanup;

    if ((ret->persistent = virDomainIsPersistent(dom)) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (dom)
        virDomainFree(dom);
    return rv;
}

static int remoteDispatchDomainIsUpdated(struct qemud_server *server ATTRIBUTE_UNUSED,
                                            struct qemud_client *client ATTRIBUTE_UNUSED,
                                            virConnectPtr conn,
                                            remote_message_header *hdr ATTRIBUTE_UNUSED,
                                            remote_error *rerr,
                                            remote_domain_is_updated_args *args,
                                            remote_domain_is_updated_ret *ret)
{
    virDomainPtr dom = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(conn, args->dom)))
        goto cleanup;

    if ((ret->updated = virDomainIsUpdated(dom)) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (dom)
        virDomainFree(dom);
    return rv;
}

static int remoteDispatchInterfaceIsActive(struct qemud_server *server ATTRIBUTE_UNUSED,
                                           struct qemud_client *client ATTRIBUTE_UNUSED,
                                           virConnectPtr conn,
                                           remote_message_header *hdr ATTRIBUTE_UNUSED,
                                           remote_error *rerr,
                                           remote_interface_is_active_args *args,
                                           remote_interface_is_active_ret *ret)
{
    virInterfacePtr iface = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(iface = get_nonnull_interface(conn, args->iface)))
        goto cleanup;

    if ((ret->active = virInterfaceIsActive(iface)) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (iface)
        virInterfaceFree(iface);
    return rv;
}

static int remoteDispatchNetworkIsActive(struct qemud_server *server ATTRIBUTE_UNUSED,
                                         struct qemud_client *client ATTRIBUTE_UNUSED,
                                         virConnectPtr conn,
                                         remote_message_header *hdr ATTRIBUTE_UNUSED,
                                         remote_error *rerr,
                                         remote_network_is_active_args *args,
                                         remote_network_is_active_ret *ret)
{
    virNetworkPtr net = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(net = get_nonnull_network(conn, args->net)))
        goto cleanup;

    if ((ret->active = virNetworkIsActive(net)) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (net)
        virNetworkFree(net);
    return rv;
}

static int remoteDispatchNetworkIsPersistent(struct qemud_server *server ATTRIBUTE_UNUSED,
                                             struct qemud_client *client ATTRIBUTE_UNUSED,
                                             virConnectPtr conn,
                                             remote_message_header *hdr ATTRIBUTE_UNUSED,
                                             remote_error *rerr,
                                             remote_network_is_persistent_args *args,
                                             remote_network_is_persistent_ret *ret)
{
    virNetworkPtr net = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(net = get_nonnull_network(conn, args->net)))
        goto cleanup;

    if ((ret->persistent = virNetworkIsPersistent(net)) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (net)
        virNetworkFree(net);
    return rv;
}

static int remoteDispatchStoragePoolIsActive(struct qemud_server *server ATTRIBUTE_UNUSED,
                                             struct qemud_client *client ATTRIBUTE_UNUSED,
                                             virConnectPtr conn,
                                             remote_message_header *hdr ATTRIBUTE_UNUSED,
                                             remote_error *rerr,
                                             remote_storage_pool_is_active_args *args,
                                             remote_storage_pool_is_active_ret *ret)
{
    virStoragePoolPtr pool = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(pool = get_nonnull_storage_pool(conn, args->pool)))
        goto cleanup;

    if ((ret->active = virStoragePoolIsActive(pool)) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (pool)
        virStoragePoolFree(pool);
    return rv;
}

static int remoteDispatchStoragePoolIsPersistent(struct qemud_server *server ATTRIBUTE_UNUSED,
                                                 struct qemud_client *client ATTRIBUTE_UNUSED,
                                                 virConnectPtr conn,
                                                 remote_message_header *hdr ATTRIBUTE_UNUSED,
                                                 remote_error *rerr,
                                                 remote_storage_pool_is_persistent_args *args,
                                                 remote_storage_pool_is_persistent_ret *ret)
{
    virStoragePoolPtr pool = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(pool = get_nonnull_storage_pool(conn, args->pool)))
        goto cleanup;

    if ((ret->persistent = virStoragePoolIsPersistent(pool)) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (pool)
        virStoragePoolFree(pool);
    return rv;
}


static int remoteDispatchIsSecure(struct qemud_server *server ATTRIBUTE_UNUSED,
                                  struct qemud_client *client ATTRIBUTE_UNUSED,
                                  virConnectPtr conn,
                                  remote_message_header *hdr ATTRIBUTE_UNUSED,
                                  remote_error *rerr,
                                  void *args ATTRIBUTE_UNUSED,
                                  remote_is_secure_ret *ret)
{
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if ((ret->secure = virConnectIsSecure(conn)) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    return rv;
}


static int
remoteDispatchCpuCompare(struct qemud_server *server ATTRIBUTE_UNUSED,
                         struct qemud_client *client ATTRIBUTE_UNUSED,
                         virConnectPtr conn,
                         remote_message_header *hdr ATTRIBUTE_UNUSED,
                         remote_error *rerr,
                         remote_cpu_compare_args *args,
                         remote_cpu_compare_ret *ret)
{
    int result;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if ((result = virConnectCompareCPU(conn, args->xml, args->flags)) == VIR_CPU_COMPARE_ERROR)
        goto cleanup;

    ret->result = result;
    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    return rv;
}


static int
remoteDispatchCpuBaseline(struct qemud_server *server ATTRIBUTE_UNUSED,
                          struct qemud_client *client ATTRIBUTE_UNUSED,
                          virConnectPtr conn,
                          remote_message_header *hdr ATTRIBUTE_UNUSED,
                          remote_error *rerr,
                          remote_cpu_baseline_args *args,
                          remote_cpu_baseline_ret *ret)
{
    char *cpu;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(cpu = virConnectBaselineCPU(conn,
                                      (const char **) args->xmlCPUs.xmlCPUs_val,
                                      args->xmlCPUs.xmlCPUs_len,
                                      args->flags)))
        goto cleanup;

    ret->cpu = cpu;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    return rv;
}


static int
remoteDispatchDomainGetJobInfo(struct qemud_server *server ATTRIBUTE_UNUSED,
                               struct qemud_client *client ATTRIBUTE_UNUSED,
                               virConnectPtr conn,
                               remote_message_header *hdr ATTRIBUTE_UNUSED,
                               remote_error *rerr,
                               remote_domain_get_job_info_args *args,
                               remote_domain_get_job_info_ret *ret)
{
    virDomainPtr dom = NULL;
    virDomainJobInfo info;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(conn, args->dom)))
        goto cleanup;

    if (virDomainGetJobInfo(dom, &info) < 0)
        goto cleanup;

    ret->type = info.type;
    ret->timeElapsed = info.timeElapsed;
    ret->timeRemaining = info.timeRemaining;
    ret->dataTotal = info.dataTotal;
    ret->dataProcessed = info.dataProcessed;
    ret->dataRemaining = info.dataRemaining;
    ret->memTotal = info.memTotal;
    ret->memProcessed = info.memProcessed;
    ret->memRemaining = info.memRemaining;
    ret->fileTotal = info.fileTotal;
    ret->fileProcessed = info.fileProcessed;
    ret->fileRemaining = info.fileRemaining;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (dom)
        virDomainFree(dom);
    return rv;
}


static int
remoteDispatchDomainAbortJob(struct qemud_server *server ATTRIBUTE_UNUSED,
                             struct qemud_client *client ATTRIBUTE_UNUSED,
                             virConnectPtr conn,
                             remote_message_header *hdr ATTRIBUTE_UNUSED,
                             remote_error *rerr,
                             remote_domain_abort_job_args *args,
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

    if (virDomainAbortJob(dom) < 0)
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
remoteDispatchDomainMigrateSetMaxDowntime(struct qemud_server *server ATTRIBUTE_UNUSED,
                                          struct qemud_client *client ATTRIBUTE_UNUSED,
                                          virConnectPtr conn,
                                          remote_message_header *hdr ATTRIBUTE_UNUSED,
                                          remote_error *rerr,
                                          remote_domain_migrate_set_max_downtime_args *args,
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

    if (virDomainMigrateSetMaxDowntime(dom, args->downtime, args->flags) < 0)
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
remoteDispatchDomainMigrateSetMaxSpeed(struct qemud_server *server ATTRIBUTE_UNUSED,
                                       struct qemud_client *client ATTRIBUTE_UNUSED,
                                       virConnectPtr conn,
                                       remote_message_header *hdr ATTRIBUTE_UNUSED,
                                       remote_error *rerr,
                                       remote_domain_migrate_set_max_speed_args *args,
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

    if (virDomainMigrateSetMaxSpeed(dom, args->bandwidth, args->flags) < 0)
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
remoteDispatchDomainSnapshotCreateXml(struct qemud_server *server ATTRIBUTE_UNUSED,
                                      struct qemud_client *client ATTRIBUTE_UNUSED,
                                      virConnectPtr conn,
                                      remote_message_header *hdr ATTRIBUTE_UNUSED,
                                      remote_error *rerr,
                                      remote_domain_snapshot_create_xml_args *args,
                                      remote_domain_snapshot_create_xml_ret *ret)
{
    virDomainSnapshotPtr snapshot = NULL;
    virDomainPtr dom = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(conn, args->domain)))
        goto cleanup;

    if (!(snapshot = virDomainSnapshotCreateXML(dom, args->xml_desc, args->flags)))
        goto cleanup;

    make_nonnull_domain_snapshot(&ret->snap, snapshot);

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (snapshot)
        virDomainSnapshotFree(snapshot);
    if (dom)
        virDomainFree(dom);
    return rv;
}

static int
remoteDispatchDomainSnapshotDumpXml(struct qemud_server *server ATTRIBUTE_UNUSED,
                                    struct qemud_client *client ATTRIBUTE_UNUSED,
                                    virConnectPtr conn,
                                    remote_message_header *hdr ATTRIBUTE_UNUSED,
                                    remote_error *rerr,
                                    remote_domain_snapshot_dump_xml_args *args,
                                    remote_domain_snapshot_dump_xml_ret *ret)
{
    virDomainPtr dom = NULL;
    virDomainSnapshotPtr snapshot = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(conn, args->snap.domain)))
        goto cleanup;

    if (!(snapshot = get_nonnull_domain_snapshot(dom, args->snap)))
        goto cleanup;

    /* remoteDispatchClientRequest will free this. */
    if (!(ret->xml = virDomainSnapshotGetXMLDesc(snapshot, args->flags)))
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (snapshot)
        virDomainSnapshotFree(snapshot);
    if (dom)
        virDomainFree(dom);
    return rv;
}

static int
remoteDispatchDomainSnapshotNum(struct qemud_server *server ATTRIBUTE_UNUSED,
                                struct qemud_client *client ATTRIBUTE_UNUSED,
                                virConnectPtr conn,
                                remote_message_header *hdr ATTRIBUTE_UNUSED,
                                remote_error *rerr,
                                remote_domain_snapshot_num_args *args,
                                remote_domain_snapshot_num_ret *ret)
{
    virDomainPtr dom = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(conn, args->domain)))
        goto cleanup;

    if ((ret->num = virDomainSnapshotNum(dom, args->flags)) < 0)
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
remoteDispatchDomainSnapshotListNames(struct qemud_server *server ATTRIBUTE_UNUSED,
                                      struct qemud_client *client ATTRIBUTE_UNUSED,
                                      virConnectPtr conn,
                                      remote_message_header *hdr ATTRIBUTE_UNUSED,
                                      remote_error *rerr,
                                      remote_domain_snapshot_list_names_args *args,
                                      remote_domain_snapshot_list_names_ret *ret)
{
    virDomainPtr dom = NULL;
    int rv = -1;
    int len;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (args->nameslen > REMOTE_DOMAIN_SNAPSHOT_LIST_NAMES_MAX) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("nameslen > REMOTE_DOMAIN_SNAPSHOT_LIST_NAMES_MAX"));
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(conn, args->domain)))
        goto cleanup;

    /* Allocate return buffer. */
    if (VIR_ALLOC_N(ret->names.names_val, args->nameslen) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    len = virDomainSnapshotListNames(dom,
                                     ret->names.names_val,
                                     args->nameslen,
                                     args->flags);
    if (len < 0)
        goto cleanup;
    ret->names.names_len = len;

    rv = 0;

cleanup:
    if (rv < 0) {
        remoteDispatchError(rerr);
        VIR_FREE(ret->names.names_val);
    }
    if (dom)
        virDomainFree(dom);
    return rv;
}

static int
remoteDispatchDomainSnapshotLookupByName(struct qemud_server *server ATTRIBUTE_UNUSED,
                                         struct qemud_client *client ATTRIBUTE_UNUSED,
                                         virConnectPtr conn,
                                         remote_message_header *hdr ATTRIBUTE_UNUSED,
                                         remote_error *rerr,
                                         remote_domain_snapshot_lookup_by_name_args *args,
                                         remote_domain_snapshot_lookup_by_name_ret *ret)
{
    virDomainSnapshotPtr snapshot = NULL;
    virDomainPtr dom = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(conn, args->domain)))
        goto cleanup;

    if (!(snapshot = virDomainSnapshotLookupByName(dom, args->name, args->flags)))
        goto cleanup;

    make_nonnull_domain_snapshot(&ret->snap, snapshot);

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (snapshot)
        virDomainSnapshotFree(snapshot);
    if (dom)
        virDomainFree(dom);
    return rv;
}

static int
remoteDispatchDomainHasCurrentSnapshot(struct qemud_server *server ATTRIBUTE_UNUSED,
                                       struct qemud_client *client ATTRIBUTE_UNUSED,
                                       virConnectPtr conn,
                                       remote_message_header *hdr ATTRIBUTE_UNUSED,
                                       remote_error *rerr,
                                       remote_domain_has_current_snapshot_args *args,
                                       remote_domain_has_current_snapshot_ret *ret)
{
    virDomainPtr dom = NULL;
    int result;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(conn, args->domain)))
        goto cleanup;

    result = virDomainHasCurrentSnapshot(dom, args->flags);
    if (result < 0)
        goto cleanup;

    ret->result = result;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (dom)
        virDomainFree(dom);
    return rv;
}

static int
remoteDispatchDomainSnapshotCurrent(struct qemud_server *server ATTRIBUTE_UNUSED,
                                    struct qemud_client *client ATTRIBUTE_UNUSED,
                                    virConnectPtr conn,
                                    remote_message_header *hdr ATTRIBUTE_UNUSED,
                                    remote_error *rerr,
                                    remote_domain_snapshot_current_args *args,
                                    remote_domain_snapshot_current_ret *ret)
{
    virDomainSnapshotPtr snapshot = NULL;
    virDomainPtr dom = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(conn, args->domain)))
        goto cleanup;

    if (!(snapshot = virDomainSnapshotCurrent(dom, args->flags)))
        goto cleanup;

    make_nonnull_domain_snapshot(&ret->snap, snapshot);

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (snapshot)
        virDomainSnapshotFree(snapshot);
    if (dom)
        virDomainFree(dom);
    return rv;
}

static int
remoteDispatchDomainRevertToSnapshot(struct qemud_server *server ATTRIBUTE_UNUSED,
                                     struct qemud_client *client ATTRIBUTE_UNUSED,
                                     virConnectPtr conn,
                                     remote_message_header *hdr ATTRIBUTE_UNUSED,
                                     remote_error *rerr,
                                     remote_domain_revert_to_snapshot_args *args,
                                     void *ret ATTRIBUTE_UNUSED)
{
    virDomainPtr dom = NULL;
    virDomainSnapshotPtr snapshot = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(conn, args->snap.domain)))
        goto cleanup;

    if (!(snapshot = get_nonnull_domain_snapshot(dom, args->snap)))
        goto cleanup;

    if (virDomainRevertToSnapshot(snapshot, args->flags) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (snapshot)
        virDomainSnapshotFree(snapshot);
    if (dom)
        virDomainFree(dom);
    return rv;
}

static int
remoteDispatchDomainSnapshotDelete(struct qemud_server *server ATTRIBUTE_UNUSED,
                                   struct qemud_client *client ATTRIBUTE_UNUSED,
                                   virConnectPtr conn,
                                   remote_message_header *hdr ATTRIBUTE_UNUSED,
                                   remote_error *rerr,
                                   remote_domain_snapshot_delete_args *args,
                                   void *ret ATTRIBUTE_UNUSED)
{
    virDomainPtr dom = NULL;
    virDomainSnapshotPtr snapshot = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(conn, args->snap.domain)))
        goto cleanup;

    if (!(snapshot = get_nonnull_domain_snapshot(dom, args->snap)))
        goto cleanup;

    if (virDomainSnapshotDelete(snapshot, args->flags) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (snapshot)
        virDomainSnapshotFree(snapshot);
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
remoteDispatchNwfilterLookupByName(struct qemud_server *server ATTRIBUTE_UNUSED,
                                   struct qemud_client *client ATTRIBUTE_UNUSED,
                                   virConnectPtr conn,
                                   remote_message_header *hdr ATTRIBUTE_UNUSED,
                                   remote_error *rerr,
                                   remote_nwfilter_lookup_by_name_args *args,
                                   remote_nwfilter_lookup_by_name_ret *ret)
{
    virNWFilterPtr nwfilter = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(nwfilter = virNWFilterLookupByName(conn, args->name)))
        goto cleanup;

    make_nonnull_nwfilter(&ret->nwfilter, nwfilter);

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (nwfilter)
        virNWFilterFree(nwfilter);
    return rv;
}

static int
remoteDispatchNwfilterLookupByUuid(struct qemud_server *server ATTRIBUTE_UNUSED,
                                   struct qemud_client *client ATTRIBUTE_UNUSED,
                                   virConnectPtr conn,
                                   remote_message_header *hdr ATTRIBUTE_UNUSED,
                                   remote_error *rerr,
                                   remote_nwfilter_lookup_by_uuid_args *args,
                                   remote_nwfilter_lookup_by_uuid_ret *ret)
{
    virNWFilterPtr nwfilter = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(nwfilter = virNWFilterLookupByUUID(conn, (unsigned char *) args->uuid)))
        goto cleanup;

    make_nonnull_nwfilter(&ret->nwfilter, nwfilter);

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (nwfilter)
        virNWFilterFree(nwfilter);
    return rv;
}


static int
remoteDispatchNwfilterDefineXml(struct qemud_server *server ATTRIBUTE_UNUSED,
                                struct qemud_client *client ATTRIBUTE_UNUSED,
                                virConnectPtr conn,
                                remote_message_header *hdr ATTRIBUTE_UNUSED,
                                remote_error *rerr,
                                remote_nwfilter_define_xml_args *args,
                                remote_nwfilter_define_xml_ret *ret)
{
    virNWFilterPtr nwfilter = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(nwfilter = virNWFilterDefineXML(conn, args->xml)))
        goto cleanup;

    make_nonnull_nwfilter(&ret->nwfilter, nwfilter);

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (nwfilter)
        virNWFilterFree(nwfilter);
    return rv;
}


static int
remoteDispatchNwfilterUndefine(struct qemud_server *server ATTRIBUTE_UNUSED,
                               struct qemud_client *client ATTRIBUTE_UNUSED,
                               virConnectPtr conn,
                               remote_message_header *hdr ATTRIBUTE_UNUSED,
                               remote_error *rerr,
                               remote_nwfilter_undefine_args *args,
                               void *ret ATTRIBUTE_UNUSED)
{
    virNWFilterPtr nwfilter = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(nwfilter = get_nonnull_nwfilter(conn, args->nwfilter)))
        goto cleanup;

    if (virNWFilterUndefine(nwfilter) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (nwfilter)
        virNWFilterFree(nwfilter);
    return rv;
}

static int
remoteDispatchListNwfilters(struct qemud_server *server ATTRIBUTE_UNUSED,
                            struct qemud_client *client ATTRIBUTE_UNUSED,
                            virConnectPtr conn,
                            remote_message_header *hdr ATTRIBUTE_UNUSED,
                            remote_error *rerr,
                            remote_list_nwfilters_args *args,
                            remote_list_nwfilters_ret *ret)
{
    int rv = -1;
    int len;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (args->maxnames > REMOTE_NWFILTER_NAME_LIST_MAX) {
        virNetError(VIR_ERR_INTERNAL_ERROR,
                    "%s", _("maxnames > REMOTE_NWFILTER_NAME_LIST_MAX"));
        goto cleanup;
    }

    /* Allocate return buffer. */
    if (VIR_ALLOC_N(ret->names.names_val, args->maxnames) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    len = virConnectListNWFilters(conn,
                                  ret->names.names_val, args->maxnames);
    if (len < 0)
        goto cleanup;
    ret->names.names_len = len;

    rv = 0;

cleanup:
    if (rv < 0) {
        remoteDispatchError(rerr);
        VIR_FREE(ret->names.names_val);
    }
    return rv;
}


static int
remoteDispatchNwfilterGetXmlDesc(struct qemud_server *server ATTRIBUTE_UNUSED,
                                 struct qemud_client *client ATTRIBUTE_UNUSED,
                                 virConnectPtr conn,
                                 remote_message_header *hdr ATTRIBUTE_UNUSED,
                                 remote_error *rerr,
                                 remote_nwfilter_get_xml_desc_args *args,
                                 remote_nwfilter_get_xml_desc_ret *ret)
{
    virNWFilterPtr nwfilter = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(nwfilter = get_nonnull_nwfilter(conn, args->nwfilter)))
        goto cleanup;

    /* remoteDispatchClientRequest will free this. */
    if (!(ret->xml = virNWFilterGetXMLDesc(nwfilter, args->flags)))
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (nwfilter)
        virNWFilterFree(nwfilter);
    return rv;
}


static int
remoteDispatchNumOfNwfilters(struct qemud_server *server ATTRIBUTE_UNUSED,
                             struct qemud_client *client ATTRIBUTE_UNUSED,
                             virConnectPtr conn,
                             remote_message_header *hdr ATTRIBUTE_UNUSED,
                             remote_error *rerr,
                             void *args ATTRIBUTE_UNUSED,
                             remote_num_of_nwfilters_ret *ret)
{
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if ((ret->num = virConnectNumOfNWFilters(conn)) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    return rv;
}


static int
remoteDispatchDomainGetBlockInfo(struct qemud_server *server ATTRIBUTE_UNUSED,
                                 struct qemud_client *client ATTRIBUTE_UNUSED,
                                 virConnectPtr conn,
                                 remote_message_header *hdr ATTRIBUTE_UNUSED,
                                 remote_error *rerr,
                                 remote_domain_get_block_info_args *args,
                                 remote_domain_get_block_info_ret *ret)
{
    virDomainPtr dom = NULL;
    virDomainBlockInfo info;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(conn, args->dom)))
        goto cleanup;

    if (virDomainGetBlockInfo(dom, args->path, &info, args->flags) < 0)
        goto cleanup;

    ret->capacity = info.capacity;
    ret->allocation = info.allocation;
    ret->physical = info.physical;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (dom)
        virDomainFree(dom);
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

    if (!(dom = get_nonnull_domain(conn, args->domain)))
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


static int
remoteDispatchDomainOpenConsole(struct qemud_server *server ATTRIBUTE_UNUSED,
                                struct qemud_client *client,
                                virConnectPtr conn,
                                remote_message_header *hdr,
                                remote_error *rerr,
                                remote_domain_open_console_args *args,
                                void *ret ATTRIBUTE_UNUSED)
{
    struct qemud_client_stream *stream = NULL;
    virDomainPtr dom = NULL;
    int rv = -1;

    if (!conn) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s", _("connection not open"));
        goto cleanup;
    }

    if (!(dom = get_nonnull_domain(conn, args->domain)))
        goto cleanup;

    if (!(stream = remoteCreateClientStream(conn, hdr))) {
        virReportOOMError();
        goto cleanup;
    }

    if (virDomainOpenConsole(dom,
                             args->devname ? *args->devname : NULL,
                             stream->st,
                             args->flags) < 0)
        goto cleanup;

    if (remoteAddClientStream(client, stream, 1) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    if (rv < 0)
        remoteDispatchError(rerr);
    if (stream && rv < 0) {
        virStreamAbort(stream->st);
        remoteFreeClientStream(client, stream);
    }
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
    make_nonnull_domain(&snapshot_dst->domain, snapshot_src->domain);
}
