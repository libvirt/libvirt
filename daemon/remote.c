/*
 * remote.c: handlers for RPC method calls
 *
 * Copyright (C) 2007, 2008, 2009 Red Hat, Inc.
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
#include "virterror_internal.h"

#if HAVE_POLKIT0
#include <polkit/polkit.h>
#include <polkit-dbus/polkit-dbus.h>
#endif

#include "remote.h"
#include "dispatch.h"

#include "libvirt_internal.h"
#include "datatypes.h"
#include "memory.h"
#include "util.h"
#include "stream.h"

#define VIR_FROM_THIS VIR_FROM_REMOTE
#define REMOTE_DEBUG(fmt, ...) DEBUG(fmt, __VA_ARGS__)

static virDomainPtr get_nonnull_domain (virConnectPtr conn, remote_nonnull_domain domain);
static virNetworkPtr get_nonnull_network (virConnectPtr conn, remote_nonnull_network network);
static virInterfacePtr get_nonnull_interface (virConnectPtr conn, remote_nonnull_interface iface);
static virStoragePoolPtr get_nonnull_storage_pool (virConnectPtr conn, remote_nonnull_storage_pool pool);
static virStorageVolPtr get_nonnull_storage_vol (virConnectPtr conn, remote_nonnull_storage_vol vol);
static virSecretPtr get_nonnull_secret (virConnectPtr conn, remote_nonnull_secret secret);
static void make_nonnull_domain (remote_nonnull_domain *dom_dst, virDomainPtr dom_src);
static void make_nonnull_network (remote_nonnull_network *net_dst, virNetworkPtr net_src);
static void make_nonnull_interface (remote_nonnull_interface *interface_dst, virInterfacePtr interface_src);
static void make_nonnull_storage_pool (remote_nonnull_storage_pool *pool_dst, virStoragePoolPtr pool_src);
static void make_nonnull_storage_vol (remote_nonnull_storage_vol *vol_dst, virStorageVolPtr vol_src);
static void make_nonnull_node_device (remote_nonnull_node_device *dev_dst, virNodeDevicePtr dev_src);
static void make_nonnull_secret (remote_nonnull_secret *secret_dst, virSecretPtr secret_src);


#include "remote_dispatch_prototypes.h"

static const dispatch_data const dispatch_table[] = {
#include "remote_dispatch_table.h"
};

const dispatch_data const *remoteGetDispatchData(int proc)
{
    if (proc >= ARRAY_CARDINALITY(dispatch_table) ||
        dispatch_table[proc].fn == NULL) {
        return NULL;
    }

    return &(dispatch_table[proc]);
}

/* Prototypes */
static void
remoteDispatchDomainEventSend (struct qemud_client *client,
                               remote_domain_event_msg *data);

int remoteRelayDomainEvent (virConnectPtr conn ATTRIBUTE_UNUSED,
                            virDomainPtr dom,
                            int event,
                            int detail,
                            void *opaque)
{
    struct qemud_client *client = opaque;
    REMOTE_DEBUG("Relaying domain event %d %d", event, detail);

    if (client) {
        remote_domain_event_msg data;

        virMutexLock(&client->lock);

        /* build return data */
        memset(&data, 0, sizeof data);
        make_nonnull_domain (&data.dom, dom);
        data.event = event;
        data.detail = detail;

        remoteDispatchDomainEventSend (client, &data);

        virMutexUnlock(&client->lock);
    }
    return 0;
}


/*----- Functions. -----*/

static int
remoteDispatchOpen (struct qemud_server *server,
                    struct qemud_client *client,
                    virConnectPtr conn,
                    remote_message_header *hdr ATTRIBUTE_UNUSED,
                    remote_error *rerr,
                    struct remote_open_args *args, void *ret ATTRIBUTE_UNUSED)
{
    const char *name;
    int flags, rc;

    /* Already opened? */
    if (conn) {
        remoteDispatchFormatError (rerr, "%s", _("connection already open"));
        return -1;
    }

    virMutexLock(&server->lock);
    virMutexLock(&client->lock);
    virMutexUnlock(&server->lock);

    name = args->name ? *args->name : NULL;

    /* If this connection arrived on a readonly socket, force
     * the connection to be readonly.
     */
    flags = args->flags;
    if (client->readonly) flags |= VIR_CONNECT_RO;

    client->conn =
        flags & VIR_CONNECT_RO
        ? virConnectOpenReadOnly (name)
        : virConnectOpen (name);

    if (client->conn == NULL)
        remoteDispatchConnError(rerr, NULL);

    rc = client->conn ? 0 : -1;
    virMutexUnlock(&client->lock);
    return rc;
}

#define CHECK_CONN(client)                                              \
    if (!client->conn) {                                                \
        remoteDispatchFormatError (rerr, "%s", _("connection not open")); \
        return -1;                                                      \
    }

static int
remoteDispatchClose (struct qemud_server *server ATTRIBUTE_UNUSED,
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
remoteDispatchSupportsFeature (struct qemud_server *server ATTRIBUTE_UNUSED,
                               struct qemud_client *client ATTRIBUTE_UNUSED,
                               virConnectPtr conn,
                               remote_message_header *hdr ATTRIBUTE_UNUSED,
                               remote_error *rerr,
                               remote_supports_feature_args *args, remote_supports_feature_ret *ret)
{
    ret->supported = virDrvSupportsFeature (conn, args->feature);

    if (ret->supported == -1) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    return 0;
}

static int
remoteDispatchGetType (struct qemud_server *server ATTRIBUTE_UNUSED,
                       struct qemud_client *client ATTRIBUTE_UNUSED,
                       virConnectPtr conn,
                       remote_message_header *hdr ATTRIBUTE_UNUSED,
                       remote_error *rerr,
                       void *args ATTRIBUTE_UNUSED, remote_get_type_ret *ret)
{
    const char *type;

    type = virConnectGetType (conn);
    if (type == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    /* We have to strdup because remoteDispatchClientRequest will
     * free this string after it's been serialised.
     */
    ret->type = strdup (type);
    if (!ret->type) {
        remoteDispatchFormatError (rerr, "%s", _("out of memory in strdup"));
        return -1;
    }

    return 0;
}

static int
remoteDispatchGetVersion (struct qemud_server *server ATTRIBUTE_UNUSED,
                          struct qemud_client *client ATTRIBUTE_UNUSED,
                          virConnectPtr conn,
                          remote_message_header *hdr ATTRIBUTE_UNUSED,
                          remote_error *rerr,
                          void *args ATTRIBUTE_UNUSED,
                          remote_get_version_ret *ret)
{
    unsigned long hvVer;

    if (virConnectGetVersion (conn, &hvVer) == -1) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    ret->hv_ver = hvVer;
    return 0;
}

static int
remoteDispatchGetLibVersion (struct qemud_server *server ATTRIBUTE_UNUSED,
                             struct qemud_client *client ATTRIBUTE_UNUSED,
                             virConnectPtr conn,
                             remote_message_header *hdr ATTRIBUTE_UNUSED,
                             remote_error *rerr,
                             void *args ATTRIBUTE_UNUSED,
                             remote_get_lib_version_ret *ret)
{
    unsigned long libVer;

    if (virConnectGetLibVersion (conn, &libVer) == -1) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    ret->lib_ver = libVer;
    return 0;
}

static int
remoteDispatchGetHostname (struct qemud_server *server ATTRIBUTE_UNUSED,
                           struct qemud_client *client ATTRIBUTE_UNUSED,
                           virConnectPtr conn,
                           remote_message_header *hdr ATTRIBUTE_UNUSED,
                           remote_error *rerr,
                           void *args ATTRIBUTE_UNUSED,
                           remote_get_hostname_ret *ret)
{
    char *hostname;

    hostname = virConnectGetHostname (conn);
    if (hostname == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    ret->hostname = hostname;
    return 0;
}

static int
remoteDispatchGetUri (struct qemud_server *server ATTRIBUTE_UNUSED,
                      struct qemud_client *client ATTRIBUTE_UNUSED,
                      virConnectPtr conn,
                      remote_message_header *hdr ATTRIBUTE_UNUSED,
                      remote_error *rerr,
                      void *args ATTRIBUTE_UNUSED,
                      remote_get_uri_ret *ret)
{
    char *uri;
    CHECK_CONN(client);

    uri = virConnectGetURI (conn);
    if (uri == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    ret->uri = uri;
    return 0;
}

static int
remoteDispatchGetMaxVcpus (struct qemud_server *server ATTRIBUTE_UNUSED,
                           struct qemud_client *client ATTRIBUTE_UNUSED,
                           virConnectPtr conn,
                           remote_message_header *hdr ATTRIBUTE_UNUSED,
                           remote_error *rerr,
                           remote_get_max_vcpus_args *args,
                           remote_get_max_vcpus_ret *ret)
{
    char *type;

    type = args->type ? *args->type : NULL;
    ret->max_vcpus = virConnectGetMaxVcpus (conn, type);
    if (ret->max_vcpus == -1) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    return 0;
}

static int
remoteDispatchNodeGetInfo (struct qemud_server *server ATTRIBUTE_UNUSED,
                           struct qemud_client *client ATTRIBUTE_UNUSED,
                           virConnectPtr conn,
                           remote_message_header *hdr ATTRIBUTE_UNUSED,
                           remote_error *rerr,
                           void *args ATTRIBUTE_UNUSED,
                           remote_node_get_info_ret *ret)
{
    virNodeInfo info;

    if (virNodeGetInfo (conn, &info) == -1) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    memcpy (ret->model, info.model, sizeof ret->model);
    ret->memory = info.memory;
    ret->cpus = info.cpus;
    ret->mhz = info.mhz;
    ret->nodes = info.nodes;
    ret->sockets = info.sockets;
    ret->cores = info.cores;
    ret->threads = info.threads;

    return 0;
}

static int
remoteDispatchGetCapabilities (struct qemud_server *server ATTRIBUTE_UNUSED,
                               struct qemud_client *client ATTRIBUTE_UNUSED,
                               virConnectPtr conn,
                               remote_message_header *hdr ATTRIBUTE_UNUSED,
                               remote_error *rerr,
                               void *args ATTRIBUTE_UNUSED,
                               remote_get_capabilities_ret *ret)
{
    char *caps;

    caps = virConnectGetCapabilities (conn);
    if (caps == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    ret->capabilities = caps;
    return 0;
}

static int
remoteDispatchNodeGetCellsFreeMemory (struct qemud_server *server ATTRIBUTE_UNUSED,
                                      struct qemud_client *client ATTRIBUTE_UNUSED,
                                      virConnectPtr conn,
                                      remote_message_header *hdr ATTRIBUTE_UNUSED,
                                      remote_error *rerr,
                                      remote_node_get_cells_free_memory_args *args,
                                      remote_node_get_cells_free_memory_ret *ret)
{
    int err;

    if (args->maxCells > REMOTE_NODE_MAX_CELLS) {
        remoteDispatchFormatError (rerr,
                                   "%s", _("maxCells > REMOTE_NODE_MAX_CELLS"));
        return -1;
    }

    /* Allocate return buffer. */
    if (VIR_ALLOC_N(ret->freeMems.freeMems_val, args->maxCells) < 0) {
        remoteDispatchOOMError(rerr);
        return -1;
    }

    err = virNodeGetCellsFreeMemory(conn,
                                    (unsigned long long *)ret->freeMems.freeMems_val,
                                    args->startCell,
                                    args->maxCells);
    if (err <= 0) {
        VIR_FREE(ret->freeMems.freeMems_val);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }
    ret->freeMems.freeMems_len = err;

    return 0;
}


static int
remoteDispatchNodeGetFreeMemory (struct qemud_server *server ATTRIBUTE_UNUSED,
                                 struct qemud_client *client ATTRIBUTE_UNUSED,
                                 virConnectPtr conn,
                                 remote_message_header *hdr ATTRIBUTE_UNUSED,
                                 remote_error *rerr,
                                 void *args ATTRIBUTE_UNUSED,
                                 remote_node_get_free_memory_ret *ret)
{
    unsigned long long freeMem;

    freeMem = virNodeGetFreeMemory(conn);
    if (freeMem == 0) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }
    ret->freeMem = freeMem;
    return 0;
}


static int
remoteDispatchDomainGetSchedulerType (struct qemud_server *server ATTRIBUTE_UNUSED,
                                      struct qemud_client *client ATTRIBUTE_UNUSED,
                                      virConnectPtr conn,
                                      remote_message_header *hdr ATTRIBUTE_UNUSED,
                                      remote_error *rerr,
                                      remote_domain_get_scheduler_type_args *args,
                                      remote_domain_get_scheduler_type_ret *ret)
{
    virDomainPtr dom;
    char *type;
    int nparams;

    dom = get_nonnull_domain (conn, args->dom);
    if (dom == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    type = virDomainGetSchedulerType (dom, &nparams);
    if (type == NULL) {
        virDomainFree(dom);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    ret->type = type;
    ret->nparams = nparams;
    virDomainFree(dom);
    return 0;
}

static int
remoteDispatchDomainGetSchedulerParameters (struct qemud_server *server ATTRIBUTE_UNUSED,
                                            struct qemud_client *client ATTRIBUTE_UNUSED,
                                            virConnectPtr conn,
                                            remote_message_header *hdr ATTRIBUTE_UNUSED,
                                            remote_error *rerr,
                                            remote_domain_get_scheduler_parameters_args *args,
                                            remote_domain_get_scheduler_parameters_ret *ret)
{
    virDomainPtr dom;
    virSchedParameterPtr params;
    int i, r, nparams;

    nparams = args->nparams;

    if (nparams > REMOTE_DOMAIN_SCHEDULER_PARAMETERS_MAX) {
        remoteDispatchFormatError (rerr, "%s", _("nparams too large"));
        return -1;
    }
    if (VIR_ALLOC_N(params, nparams) < 0) {
        remoteDispatchOOMError(rerr);
        return -1;
    }

    dom = get_nonnull_domain (conn, args->dom);
    if (dom == NULL) {
        VIR_FREE(params);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    r = virDomainGetSchedulerParameters (dom, params, &nparams);
    if (r == -1) {
        virDomainFree(dom);
        VIR_FREE(params);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    /* Serialise the scheduler parameters. */
    ret->params.params_len = nparams;
    if (VIR_ALLOC_N(ret->params.params_val, nparams) < 0)
        goto oom;

    for (i = 0; i < nparams; ++i) {
        // remoteDispatchClientRequest will free this:
        ret->params.params_val[i].field = strdup (params[i].field);
        if (ret->params.params_val[i].field == NULL)
            goto oom;

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
            remoteDispatchFormatError (rerr, "%s", _("unknown type"));
            goto cleanup;
        }
    }
    virDomainFree(dom);
    VIR_FREE(params);

    return 0;

oom:
    remoteDispatchOOMError(rerr);
cleanup:
    virDomainFree(dom);
    for (i = 0 ; i < nparams ; i++)
        VIR_FREE(ret->params.params_val[i].field);
    VIR_FREE(params);
    return -1;
}

static int
remoteDispatchDomainSetSchedulerParameters (struct qemud_server *server ATTRIBUTE_UNUSED,
                                            struct qemud_client *client ATTRIBUTE_UNUSED,
                                            virConnectPtr conn,
                                            remote_message_header *hdr ATTRIBUTE_UNUSED,
                                            remote_error *rerr,
                                            remote_domain_set_scheduler_parameters_args *args,
                                            void *ret ATTRIBUTE_UNUSED)
{
    virDomainPtr dom;
    int i, r, nparams;
    virSchedParameterPtr params;

    nparams = args->params.params_len;

    if (nparams > REMOTE_DOMAIN_SCHEDULER_PARAMETERS_MAX) {
        remoteDispatchFormatError (rerr, "%s", _("nparams too large"));
        return -1;
    }
    if (VIR_ALLOC_N(params, nparams) < 0) {
        remoteDispatchOOMError(rerr);
        return -1;
    }

    /* Deserialise parameters. */
    for (i = 0; i < nparams; ++i) {
        if (virStrcpyStatic(params[i].field, args->params.params_val[i].field) == NULL) {
            remoteDispatchFormatError(rerr, _("Field %s too big for destination"),
                                      args->params.params_val[i].field);
            return -1;
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

    dom = get_nonnull_domain (conn, args->dom);
    if (dom == NULL) {
        VIR_FREE(params);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    r = virDomainSetSchedulerParameters (dom, params, nparams);
    virDomainFree(dom);
    VIR_FREE(params);
    if (r == -1) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    return 0;
}

static int
remoteDispatchDomainBlockStats (struct qemud_server *server ATTRIBUTE_UNUSED,
                                struct qemud_client *client ATTRIBUTE_UNUSED,
                                virConnectPtr conn,
                                remote_message_header *hdr ATTRIBUTE_UNUSED,
                                remote_error *rerr,
                                remote_domain_block_stats_args *args,
                                remote_domain_block_stats_ret *ret)
{
    virDomainPtr dom;
    char *path;
    struct _virDomainBlockStats stats;

    dom = get_nonnull_domain (conn, args->dom);
    if (dom == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }
    path = args->path;

    if (virDomainBlockStats (dom, path, &stats, sizeof stats) == -1) {
        virDomainFree (dom);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }
    virDomainFree (dom);

    ret->rd_req = stats.rd_req;
    ret->rd_bytes = stats.rd_bytes;
    ret->wr_req = stats.wr_req;
    ret->wr_bytes = stats.wr_bytes;
    ret->errs = stats.errs;

    return 0;
}

static int
remoteDispatchDomainInterfaceStats (struct qemud_server *server ATTRIBUTE_UNUSED,
                                    struct qemud_client *client ATTRIBUTE_UNUSED,
                                    virConnectPtr conn,
                                    remote_message_header *hdr ATTRIBUTE_UNUSED,
                                    remote_error *rerr,
                                    remote_domain_interface_stats_args *args,
                                    remote_domain_interface_stats_ret *ret)
{
    virDomainPtr dom;
    char *path;
    struct _virDomainInterfaceStats stats;

    dom = get_nonnull_domain (conn, args->dom);
    if (dom == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }
    path = args->path;

    if (virDomainInterfaceStats (dom, path, &stats, sizeof stats) == -1) {
        virDomainFree (dom);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }
    virDomainFree (dom);

    ret->rx_bytes = stats.rx_bytes;
    ret->rx_packets = stats.rx_packets;
    ret->rx_errs = stats.rx_errs;
    ret->rx_drop = stats.rx_drop;
    ret->tx_bytes = stats.tx_bytes;
    ret->tx_packets = stats.tx_packets;
    ret->tx_errs = stats.tx_errs;
    ret->tx_drop = stats.tx_drop;

    return 0;
}

static int
remoteDispatchDomainMemoryStats (struct qemud_server *server ATTRIBUTE_UNUSED,
                                 struct qemud_client *client ATTRIBUTE_UNUSED,
                                 virConnectPtr conn,
                                 remote_message_header *hdr ATTRIBUTE_UNUSED,
                                 remote_error *rerr,
                                 remote_domain_memory_stats_args *args,
                                 remote_domain_memory_stats_ret *ret)
{
    virDomainPtr dom;
    struct _virDomainMemoryStat *stats;
    unsigned int nr_stats, i;

    if (args->maxStats > REMOTE_DOMAIN_MEMORY_STATS_MAX) {
        remoteDispatchFormatError (rerr, "%s",
                               _("maxStats > REMOTE_DOMAIN_MEMORY_STATS_MAX"));
        return -1;
    }

    dom = get_nonnull_domain (conn, args->dom);
    if (dom == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    /* Allocate stats array for making dispatch call */
    if (VIR_ALLOC_N(stats, args->maxStats) < 0) {
        remoteDispatchOOMError(rerr);
        return -1;
     }

    nr_stats = virDomainMemoryStats (dom, stats, args->maxStats, 0);
    virDomainFree (dom);
    if (nr_stats == -1) {
        VIR_FREE(stats);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    /* Allocate return buffer */
    if (VIR_ALLOC_N(ret->stats.stats_val, args->maxStats) < 0) {
        VIR_FREE(stats);
        remoteDispatchOOMError(rerr);
        return -1;
    }

    /* Copy the stats into the xdr return structure */
    for (i = 0; i < nr_stats; i++) {
        ret->stats.stats_val[i].tag = stats[i].tag;
        ret->stats.stats_val[i].val = stats[i].val;
    }
    ret->stats.stats_len = nr_stats;
    VIR_FREE(stats);
    return 0;
}

static int
remoteDispatchDomainBlockPeek (struct qemud_server *server ATTRIBUTE_UNUSED,
                               struct qemud_client *client ATTRIBUTE_UNUSED,
                               virConnectPtr conn,
                               remote_message_header *hdr ATTRIBUTE_UNUSED,
                               remote_error *rerr,
                               remote_domain_block_peek_args *args,
                               remote_domain_block_peek_ret *ret)
{
    virDomainPtr dom;
    char *path;
    unsigned long long offset;
    size_t size;
    unsigned int flags;

    dom = get_nonnull_domain (conn, args->dom);
    if (dom == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }
    path = args->path;
    offset = args->offset;
    size = args->size;
    flags = args->flags;

    if (size > REMOTE_DOMAIN_BLOCK_PEEK_BUFFER_MAX) {
        virDomainFree (dom);
        remoteDispatchFormatError (rerr,
                                   "%s", _("size > maximum buffer size"));
        return -1;
    }

    ret->buffer.buffer_len = size;
    if (VIR_ALLOC_N (ret->buffer.buffer_val, size) < 0) {
        virDomainFree (dom);
        remoteDispatchOOMError(rerr);
        return -1;
    }

    if (virDomainBlockPeek (dom, path, offset, size,
                            ret->buffer.buffer_val, flags) == -1) {
        /* free (ret->buffer.buffer_val); - caller frees */
        virDomainFree (dom);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }
    virDomainFree (dom);

    return 0;
}

static int
remoteDispatchDomainMemoryPeek (struct qemud_server *server ATTRIBUTE_UNUSED,
                                struct qemud_client *client ATTRIBUTE_UNUSED,
                                virConnectPtr conn,
                                remote_message_header *hdr ATTRIBUTE_UNUSED,
                                remote_error *rerr,
                                remote_domain_memory_peek_args *args,
                                remote_domain_memory_peek_ret *ret)
{
    virDomainPtr dom;
    unsigned long long offset;
    size_t size;
    unsigned int flags;

    dom = get_nonnull_domain (conn, args->dom);
    if (dom == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }
    offset = args->offset;
    size = args->size;
    flags = args->flags;

    if (size > REMOTE_DOMAIN_MEMORY_PEEK_BUFFER_MAX) {
        virDomainFree (dom);
        remoteDispatchFormatError (rerr,
                                   "%s", _("size > maximum buffer size"));
        return -1;
    }

    ret->buffer.buffer_len = size;
    if (VIR_ALLOC_N (ret->buffer.buffer_val, size) < 0) {
        virDomainFree (dom);
        remoteDispatchOOMError(rerr);
        return -1;
    }

    if (virDomainMemoryPeek (dom, offset, size,
                             ret->buffer.buffer_val, flags) == -1) {
        /* free (ret->buffer.buffer_val); - caller frees */
        virDomainFree (dom);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }
    virDomainFree (dom);

    return 0;
}

static int
remoteDispatchDomainAttachDevice (struct qemud_server *server ATTRIBUTE_UNUSED,
                                  struct qemud_client *client ATTRIBUTE_UNUSED,
                                  virConnectPtr conn,
                                  remote_message_header *hdr ATTRIBUTE_UNUSED,
                                  remote_error *rerr,
                                  remote_domain_attach_device_args *args,
                                  void *ret ATTRIBUTE_UNUSED)
{
    virDomainPtr dom;

    dom = get_nonnull_domain (conn, args->dom);
    if (dom == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    if (virDomainAttachDevice (dom, args->xml) == -1) {
        virDomainFree(dom);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }
    virDomainFree(dom);
    return 0;
}

static int
remoteDispatchDomainCreate (struct qemud_server *server ATTRIBUTE_UNUSED,
                            struct qemud_client *client ATTRIBUTE_UNUSED,
                            virConnectPtr conn,
                            remote_message_header *hdr ATTRIBUTE_UNUSED,
                            remote_error *rerr,
                            remote_domain_create_args *args,
                            void *ret ATTRIBUTE_UNUSED)
{
    virDomainPtr dom;

    dom = get_nonnull_domain (conn, args->dom);
    if (dom == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    if (virDomainCreate (dom) == -1) {
        virDomainFree(dom);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }
    virDomainFree(dom);
    return 0;
}

static int
remoteDispatchDomainCreateXml (struct qemud_server *server ATTRIBUTE_UNUSED,
                               struct qemud_client *client ATTRIBUTE_UNUSED,
                               virConnectPtr conn,
                               remote_message_header *hdr ATTRIBUTE_UNUSED,
                               remote_error *rerr,
                               remote_domain_create_xml_args *args,
                               remote_domain_create_xml_ret *ret)
{
    virDomainPtr dom;

    dom = virDomainCreateXML (conn, args->xml_desc, args->flags);
    if (dom == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    make_nonnull_domain (&ret->dom, dom);
    virDomainFree(dom);

    return 0;
}

static int
remoteDispatchDomainDefineXml (struct qemud_server *server ATTRIBUTE_UNUSED,
                               struct qemud_client *client ATTRIBUTE_UNUSED,
                               virConnectPtr conn,
                               remote_message_header *hdr ATTRIBUTE_UNUSED,
                               remote_error *rerr,
                               remote_domain_define_xml_args *args,
                               remote_domain_define_xml_ret *ret)
{
    virDomainPtr dom;

    dom = virDomainDefineXML (conn, args->xml);
    if (dom == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    make_nonnull_domain (&ret->dom, dom);
    virDomainFree(dom);

    return 0;
}

static int
remoteDispatchDomainDestroy (struct qemud_server *server ATTRIBUTE_UNUSED,
                             struct qemud_client *client ATTRIBUTE_UNUSED,
                             virConnectPtr conn,
                             remote_message_header *hdr ATTRIBUTE_UNUSED,
                             remote_error *rerr,
                             remote_domain_destroy_args *args,
                             void *ret ATTRIBUTE_UNUSED)
{
    virDomainPtr dom;

    dom = get_nonnull_domain (conn, args->dom);
    if (dom == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    if (virDomainDestroy (dom) == -1) {
        virDomainFree(dom);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }
    virDomainFree(dom);
    return 0;
}

static int
remoteDispatchDomainDetachDevice (struct qemud_server *server ATTRIBUTE_UNUSED,
                                  struct qemud_client *client ATTRIBUTE_UNUSED,
                                  virConnectPtr conn,
                                  remote_message_header *hdr ATTRIBUTE_UNUSED,
                                  remote_error *rerr,
                                  remote_domain_detach_device_args *args,
                                  void *ret ATTRIBUTE_UNUSED)
{
    virDomainPtr dom;

    dom = get_nonnull_domain (conn, args->dom);
    if (dom == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    if (virDomainDetachDevice (dom, args->xml) == -1) {
        virDomainFree(dom);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    virDomainFree(dom);
    return 0;
}

static int
remoteDispatchDomainDumpXml (struct qemud_server *server ATTRIBUTE_UNUSED,
                             struct qemud_client *client ATTRIBUTE_UNUSED,
                             virConnectPtr conn,
                             remote_message_header *hdr ATTRIBUTE_UNUSED,
                             remote_error *rerr,
                             remote_domain_dump_xml_args *args,
                             remote_domain_dump_xml_ret *ret)
{
    virDomainPtr dom;

    dom = get_nonnull_domain (conn, args->dom);
    if (dom == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    /* remoteDispatchClientRequest will free this. */
    ret->xml = virDomainGetXMLDesc (dom, args->flags);
    if (!ret->xml) {
        virDomainFree(dom);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }
    virDomainFree(dom);
    return 0;
}

static int
remoteDispatchDomainXmlFromNative (struct qemud_server *server ATTRIBUTE_UNUSED,
                                   struct qemud_client *client ATTRIBUTE_UNUSED,
                                   virConnectPtr conn,
                                   remote_message_header *hdr ATTRIBUTE_UNUSED,
                                   remote_error *rerr,
                                   remote_domain_xml_from_native_args *args,
                                   remote_domain_xml_from_native_ret *ret)
{
    /* remoteDispatchClientRequest will free this. */
    ret->domainXml = virConnectDomainXMLFromNative (conn,
                                                    args->nativeFormat,
                                                    args->nativeConfig,
                                                    args->flags);
    if (!ret->domainXml) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }
    return 0;
}

static int
remoteDispatchDomainXmlToNative (struct qemud_server *server ATTRIBUTE_UNUSED,
                                 struct qemud_client *client ATTRIBUTE_UNUSED,
                                 virConnectPtr conn,
                                 remote_message_header *hdr ATTRIBUTE_UNUSED,
                                 remote_error *rerr,
                                 remote_domain_xml_to_native_args *args,
                                 remote_domain_xml_to_native_ret *ret)
{
    /* remoteDispatchClientRequest will free this. */
    ret->nativeConfig = virConnectDomainXMLToNative (conn,
                                                     args->nativeFormat,
                                                     args->domainXml,
                                                     args->flags);
    if (!ret->nativeConfig) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }
    return 0;
}


static int
remoteDispatchDomainGetAutostart (struct qemud_server *server ATTRIBUTE_UNUSED,
                                  struct qemud_client *client ATTRIBUTE_UNUSED,
                                  virConnectPtr conn,
                                  remote_message_header *hdr ATTRIBUTE_UNUSED,
                                  remote_error *rerr,
                                  remote_domain_get_autostart_args *args,
                                  remote_domain_get_autostart_ret *ret)
{
    virDomainPtr dom;

    dom = get_nonnull_domain (conn, args->dom);
    if (dom == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    if (virDomainGetAutostart (dom, &ret->autostart) == -1) {
        virDomainFree(dom);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }
    virDomainFree(dom);
    return 0;
}

static int
remoteDispatchDomainGetInfo (struct qemud_server *server ATTRIBUTE_UNUSED,
                             struct qemud_client *client ATTRIBUTE_UNUSED,
                             virConnectPtr conn,
                             remote_message_header *hdr ATTRIBUTE_UNUSED,
                             remote_error *rerr,
                             remote_domain_get_info_args *args,
                             remote_domain_get_info_ret *ret)
{
    virDomainPtr dom;
    virDomainInfo info;

    dom = get_nonnull_domain (conn, args->dom);
    if (dom == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    if (virDomainGetInfo (dom, &info) == -1) {
        virDomainFree(dom);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    ret->state = info.state;
    ret->max_mem = info.maxMem;
    ret->memory = info.memory;
    ret->nr_virt_cpu = info.nrVirtCpu;
    ret->cpu_time = info.cpuTime;

    virDomainFree(dom);

    return 0;
}

static int
remoteDispatchDomainGetMaxMemory (struct qemud_server *server ATTRIBUTE_UNUSED,
                                  struct qemud_client *client ATTRIBUTE_UNUSED,
                                  virConnectPtr conn,
                                  remote_message_header *hdr ATTRIBUTE_UNUSED,
                                  remote_error *rerr,
                                  remote_domain_get_max_memory_args *args,
                                  remote_domain_get_max_memory_ret *ret)
{
    virDomainPtr dom;

    dom = get_nonnull_domain (conn, args->dom);
    if (dom == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    ret->memory = virDomainGetMaxMemory (dom);
    if (ret->memory == 0) {
        virDomainFree(dom);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }
    virDomainFree(dom);
    return 0;
}

static int
remoteDispatchDomainGetMaxVcpus (struct qemud_server *server ATTRIBUTE_UNUSED,
                                 struct qemud_client *client ATTRIBUTE_UNUSED,
                                 virConnectPtr conn,
                                 remote_message_header *hdr ATTRIBUTE_UNUSED,
                                 remote_error *rerr,
                                 remote_domain_get_max_vcpus_args *args,
                                 remote_domain_get_max_vcpus_ret *ret)
{
    virDomainPtr dom;

    dom = get_nonnull_domain (conn, args->dom);
    if (dom == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    ret->num = virDomainGetMaxVcpus (dom);
    if (ret->num == -1) {
        virDomainFree(dom);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }
    virDomainFree(dom);
    return 0;
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
    virDomainPtr dom;
    virSecurityLabel seclabel;

    dom = get_nonnull_domain(conn, args->dom);
    if (dom == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    memset(&seclabel, 0, sizeof seclabel);
    if (virDomainGetSecurityLabel(dom, &seclabel) == -1) {
        virDomainFree(dom);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    ret->label.label_len = strlen(seclabel.label) + 1;
    if (VIR_ALLOC_N(ret->label.label_val, ret->label.label_len) < 0) {
        virDomainFree(dom);
        remoteDispatchOOMError(rerr);
        return -1;
    }
    strcpy(ret->label.label_val, seclabel.label);
    ret->enforcing = seclabel.enforcing;
    virDomainFree(dom);

    return 0;
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

    memset(&secmodel, 0, sizeof secmodel);
    if (virNodeGetSecurityModel(conn, &secmodel) == -1) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    ret->model.model_len = strlen(secmodel.model) + 1;
    if (VIR_ALLOC_N(ret->model.model_val, ret->model.model_len) < 0) {
        remoteDispatchOOMError(rerr);
        return -1;
    }
    strcpy(ret->model.model_val, secmodel.model);

    ret->doi.doi_len = strlen(secmodel.doi) + 1;
    if (VIR_ALLOC_N(ret->doi.doi_val, ret->doi.doi_len) < 0) {
        remoteDispatchOOMError(rerr);
        return -1;
    }
    strcpy(ret->doi.doi_val, secmodel.doi);

    return 0;
}

static int
remoteDispatchDomainGetOsType (struct qemud_server *server ATTRIBUTE_UNUSED,
                               struct qemud_client *client ATTRIBUTE_UNUSED,
                               virConnectPtr conn,
                               remote_message_header *hdr ATTRIBUTE_UNUSED,
                               remote_error *rerr,
                               remote_domain_get_os_type_args *args,
                               remote_domain_get_os_type_ret *ret)
{
    virDomainPtr dom;

    dom = get_nonnull_domain (conn, args->dom);
    if (dom == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    /* remoteDispatchClientRequest will free this */
    ret->type = virDomainGetOSType (dom);
    if (ret->type == NULL) {
        virDomainFree(dom);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }
    virDomainFree(dom);
    return 0;
}

static int
remoteDispatchDomainGetVcpus (struct qemud_server *server ATTRIBUTE_UNUSED,
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

    dom = get_nonnull_domain (conn, args->dom);
    if (dom == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    if (args->maxinfo > REMOTE_VCPUINFO_MAX) {
        virDomainFree(dom);
        remoteDispatchFormatError (rerr, "%s", _("maxinfo > REMOTE_VCPUINFO_MAX"));
        return -1;
    }

    if (args->maxinfo * args->maplen > REMOTE_CPUMAPS_MAX) {
        virDomainFree(dom);
        remoteDispatchFormatError (rerr, "%s", _("maxinfo * maplen > REMOTE_CPUMAPS_MAX"));
        return -1;
    }

    /* Allocate buffers to take the results. */
    if (VIR_ALLOC_N(info, args->maxinfo) < 0)
        goto oom;
    if (args->maplen > 0 &&
        VIR_ALLOC_N(cpumaps, args->maxinfo * args->maplen) < 0)
        goto oom;

    info_len = virDomainGetVcpus (dom,
                                  info, args->maxinfo,
                                  cpumaps, args->maplen);
    if (info_len == -1) {
        VIR_FREE(info);
        VIR_FREE(cpumaps);
        virDomainFree(dom);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    /* Allocate the return buffer for info. */
    ret->info.info_len = info_len;
    if (VIR_ALLOC_N(ret->info.info_val, info_len) < 0)
        goto oom;

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

    VIR_FREE(info);
    virDomainFree(dom);
    return 0;

oom:
    VIR_FREE(info);
    VIR_FREE(cpumaps);
    virDomainFree(dom);
    remoteDispatchOOMError(rerr);
    return -1;
}

static int
remoteDispatchDomainMigratePrepare (struct qemud_server *server ATTRIBUTE_UNUSED,
                                    struct qemud_client *client ATTRIBUTE_UNUSED,
                                    virConnectPtr conn,
                                    remote_message_header *hdr ATTRIBUTE_UNUSED,
                                    remote_error *rerr,
                                    remote_domain_migrate_prepare_args *args,
                                    remote_domain_migrate_prepare_ret *ret)
{
    int r;
    char *cookie = NULL;
    int cookielen = 0;
    char *uri_in;
    char **uri_out;
    char *dname;

    uri_in = args->uri_in == NULL ? NULL : *args->uri_in;
    dname = args->dname == NULL ? NULL : *args->dname;

    /* Wacky world of XDR ... */
    if (VIR_ALLOC(uri_out) < 0) {
        remoteDispatchOOMError(rerr);
        return -1;
    }

    r = virDomainMigratePrepare (conn, &cookie, &cookielen,
                                 uri_in, uri_out,
                                 args->flags, dname, args->resource);
    if (r == -1) {
        VIR_FREE(uri_out);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    /* remoteDispatchClientRequest will free cookie, uri_out and
     * the string if there is one.
     */
    ret->cookie.cookie_len = cookielen;
    ret->cookie.cookie_val = cookie;
    if (*uri_out == NULL) {
        ret->uri_out = NULL;
        VIR_FREE(uri_out);
    } else {
        ret->uri_out = uri_out;
    }

    return 0;
}

static int
remoteDispatchDomainMigratePerform (struct qemud_server *server ATTRIBUTE_UNUSED,
                                    struct qemud_client *client ATTRIBUTE_UNUSED,
                                    virConnectPtr conn,
                                    remote_message_header *hdr ATTRIBUTE_UNUSED,
                                    remote_error *rerr,
                                    remote_domain_migrate_perform_args *args,
                                    void *ret ATTRIBUTE_UNUSED)
{
    int r;
    virDomainPtr dom;
    char *dname;

    dom = get_nonnull_domain (conn, args->dom);
    if (dom == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    dname = args->dname == NULL ? NULL : *args->dname;

    r = virDomainMigratePerform (dom,
                                 args->cookie.cookie_val,
                                 args->cookie.cookie_len,
                                 args->uri,
                                 args->flags, dname, args->resource);
    virDomainFree (dom);
    if (r == -1) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    return 0;
}

static int
remoteDispatchDomainMigrateFinish (struct qemud_server *server ATTRIBUTE_UNUSED,
                                   struct qemud_client *client ATTRIBUTE_UNUSED,
                                   virConnectPtr conn,
                                   remote_message_header *hdr ATTRIBUTE_UNUSED,
                                   remote_error *rerr,
                                   remote_domain_migrate_finish_args *args,
                                   remote_domain_migrate_finish_ret *ret)
{
    virDomainPtr ddom;
    CHECK_CONN (client);

    ddom = virDomainMigrateFinish (conn, args->dname,
                                   args->cookie.cookie_val,
                                   args->cookie.cookie_len,
                                   args->uri,
                                   args->flags);
    if (ddom == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    make_nonnull_domain (&ret->ddom, ddom);
    virDomainFree (ddom);
    return 0;
}

static int
remoteDispatchDomainMigratePrepare2 (struct qemud_server *server ATTRIBUTE_UNUSED,
                                     struct qemud_client *client ATTRIBUTE_UNUSED,
                                     virConnectPtr conn,
                                     remote_message_header *hdr ATTRIBUTE_UNUSED,
                                     remote_error *rerr,
                                     remote_domain_migrate_prepare2_args *args,
                                     remote_domain_migrate_prepare2_ret *ret)
{
    int r;
    char *cookie = NULL;
    int cookielen = 0;
    char *uri_in;
    char **uri_out;
    char *dname;
    CHECK_CONN (client);

    uri_in = args->uri_in == NULL ? NULL : *args->uri_in;
    dname = args->dname == NULL ? NULL : *args->dname;

    /* Wacky world of XDR ... */
    if (VIR_ALLOC(uri_out) < 0) {
        remoteDispatchOOMError(rerr);
        return -1;
    }

    r = virDomainMigratePrepare2 (conn, &cookie, &cookielen,
                                  uri_in, uri_out,
                                  args->flags, dname, args->resource,
                                  args->dom_xml);
    if (r == -1) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    /* remoteDispatchClientRequest will free cookie, uri_out and
     * the string if there is one.
     */
    ret->cookie.cookie_len = cookielen;
    ret->cookie.cookie_val = cookie;
    ret->uri_out = *uri_out == NULL ? NULL : uri_out;

    return 0;
}

static int
remoteDispatchDomainMigrateFinish2 (struct qemud_server *server ATTRIBUTE_UNUSED,
                                    struct qemud_client *client ATTRIBUTE_UNUSED,
                                    virConnectPtr conn,
                                    remote_message_header *hdr ATTRIBUTE_UNUSED,
                                    remote_error *rerr,
                                    remote_domain_migrate_finish2_args *args,
                                    remote_domain_migrate_finish2_ret *ret)
{
    virDomainPtr ddom;
    CHECK_CONN (client);

    ddom = virDomainMigrateFinish2 (conn, args->dname,
                                    args->cookie.cookie_val,
                                    args->cookie.cookie_len,
                                    args->uri,
                                    args->flags,
                                    args->retcode);
    if (ddom == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    make_nonnull_domain (&ret->ddom, ddom);

    return 0;
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
    int r;
    char *dname;
    struct qemud_client_stream *stream;
    CHECK_CONN (client);

    dname = args->dname == NULL ? NULL : *args->dname;

    stream = remoteCreateClientStream(conn, hdr);
    if (!stream) {
        remoteDispatchOOMError(rerr);
        return -1;
    }

    r = virDomainMigratePrepareTunnel(conn, stream->st,
                                      args->flags, dname, args->resource,
                                      args->dom_xml);
    if (r == -1) {
        remoteFreeClientStream(client, stream);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    if (remoteAddClientStream(client, stream, 0) < 0) {
        remoteDispatchConnError(rerr, conn);
        virStreamAbort(stream->st);
        remoteFreeClientStream(client, stream);
        return -1;
    }

    return 0;
}

static int
remoteDispatchListDefinedDomains (struct qemud_server *server ATTRIBUTE_UNUSED,
                                  struct qemud_client *client ATTRIBUTE_UNUSED,
                                  virConnectPtr conn,
                                  remote_message_header *hdr ATTRIBUTE_UNUSED,
                                  remote_error *rerr,
                                  remote_list_defined_domains_args *args,
                                  remote_list_defined_domains_ret *ret)
{

    if (args->maxnames > REMOTE_DOMAIN_NAME_LIST_MAX) {
        remoteDispatchFormatError (rerr,
                                   "%s", _("maxnames > REMOTE_DOMAIN_NAME_LIST_MAX"));
        return -1;
    }

    /* Allocate return buffer. */
    if (VIR_ALLOC_N(ret->names.names_val, args->maxnames) < 0) {
        remoteDispatchOOMError(rerr);
        return -1;
    }

    ret->names.names_len =
        virConnectListDefinedDomains (conn,
                                      ret->names.names_val, args->maxnames);
    if (ret->names.names_len == -1) {
        VIR_FREE(ret->names.names_val);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    return 0;
}

static int
remoteDispatchDomainLookupById (struct qemud_server *server ATTRIBUTE_UNUSED,
                                struct qemud_client *client ATTRIBUTE_UNUSED,
                                virConnectPtr conn,
                                remote_message_header *hdr ATTRIBUTE_UNUSED,
                                remote_error *rerr,
                                remote_domain_lookup_by_id_args *args,
                                remote_domain_lookup_by_id_ret *ret)
{
    virDomainPtr dom;

    dom = virDomainLookupByID (conn, args->id);
    if (dom == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    make_nonnull_domain (&ret->dom, dom);
    virDomainFree(dom);
    return 0;
}

static int
remoteDispatchDomainLookupByName (struct qemud_server *server ATTRIBUTE_UNUSED,
                                  struct qemud_client *client ATTRIBUTE_UNUSED,
                                  virConnectPtr conn,
                                  remote_message_header *hdr ATTRIBUTE_UNUSED,
                                  remote_error *rerr,
                                  remote_domain_lookup_by_name_args *args,
                                  remote_domain_lookup_by_name_ret *ret)
{
    virDomainPtr dom;

    dom = virDomainLookupByName (conn, args->name);
    if (dom == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    make_nonnull_domain (&ret->dom, dom);
    virDomainFree(dom);
    return 0;
}

static int
remoteDispatchDomainLookupByUuid (struct qemud_server *server ATTRIBUTE_UNUSED,
                                  struct qemud_client *client ATTRIBUTE_UNUSED,
                                  virConnectPtr conn,
                                  remote_message_header *hdr ATTRIBUTE_UNUSED,
                                  remote_error *rerr,
                                  remote_domain_lookup_by_uuid_args *args,
                                  remote_domain_lookup_by_uuid_ret *ret)
{
    virDomainPtr dom;

    dom = virDomainLookupByUUID (conn, (unsigned char *) args->uuid);
    if (dom == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    make_nonnull_domain (&ret->dom, dom);
    virDomainFree(dom);
    return 0;
}

static int
remoteDispatchNumOfDefinedDomains (struct qemud_server *server ATTRIBUTE_UNUSED,
                                   struct qemud_client *client ATTRIBUTE_UNUSED,
                                   virConnectPtr conn,
                                   remote_message_header *hdr ATTRIBUTE_UNUSED,
                                   remote_error *rerr,
                                   void *args ATTRIBUTE_UNUSED,
                                   remote_num_of_defined_domains_ret *ret)
{

    ret->num = virConnectNumOfDefinedDomains (conn);
    if (ret->num == -1) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    return 0;
}

static int
remoteDispatchDomainPinVcpu (struct qemud_server *server ATTRIBUTE_UNUSED,
                             struct qemud_client *client ATTRIBUTE_UNUSED,
                             virConnectPtr conn,
                             remote_message_header *hdr ATTRIBUTE_UNUSED,
                             remote_error *rerr,
                             remote_domain_pin_vcpu_args *args,
                             void *ret ATTRIBUTE_UNUSED)
{
    virDomainPtr dom;
    int rv;

    dom = get_nonnull_domain (conn, args->dom);
    if (dom == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    if (args->cpumap.cpumap_len > REMOTE_CPUMAP_MAX) {
        virDomainFree(dom);
        remoteDispatchFormatError (rerr, "%s", _("cpumap_len > REMOTE_CPUMAP_MAX"));
        return -1;
    }

    rv = virDomainPinVcpu (dom, args->vcpu,
                           (unsigned char *) args->cpumap.cpumap_val,
                           args->cpumap.cpumap_len);
    if (rv == -1) {
        virDomainFree(dom);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }
    virDomainFree(dom);
    return 0;
}

static int
remoteDispatchDomainReboot (struct qemud_server *server ATTRIBUTE_UNUSED,
                            struct qemud_client *client ATTRIBUTE_UNUSED,
                            virConnectPtr conn,
                            remote_message_header *hdr ATTRIBUTE_UNUSED,
                            remote_error *rerr,
                            remote_domain_reboot_args *args,
                            void *ret ATTRIBUTE_UNUSED)
{
    virDomainPtr dom;

    dom = get_nonnull_domain (conn, args->dom);
    if (dom == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    if (virDomainReboot (dom, args->flags) == -1) {
        virDomainFree(dom);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }
    virDomainFree(dom);
    return 0;
}

static int
remoteDispatchDomainRestore (struct qemud_server *server ATTRIBUTE_UNUSED,
                             struct qemud_client *client ATTRIBUTE_UNUSED,
                             virConnectPtr conn,
                             remote_message_header *hdr ATTRIBUTE_UNUSED,
                             remote_error *rerr,
                             remote_domain_restore_args *args,
                             void *ret ATTRIBUTE_UNUSED)
{

    if (virDomainRestore (conn, args->from) == -1) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    return 0;
}

static int
remoteDispatchDomainResume (struct qemud_server *server ATTRIBUTE_UNUSED,
                            struct qemud_client *client ATTRIBUTE_UNUSED,
                            virConnectPtr conn,
                            remote_message_header *hdr ATTRIBUTE_UNUSED,
                            remote_error *rerr,
                            remote_domain_resume_args *args,
                            void *ret ATTRIBUTE_UNUSED)
{
    virDomainPtr dom;

    dom = get_nonnull_domain (conn, args->dom);
    if (dom == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    if (virDomainResume (dom) == -1) {
        virDomainFree(dom);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }
    virDomainFree(dom);
    return 0;
}

static int
remoteDispatchDomainSave (struct qemud_server *server ATTRIBUTE_UNUSED,
                          struct qemud_client *client ATTRIBUTE_UNUSED,
                          virConnectPtr conn,
                          remote_message_header *hdr ATTRIBUTE_UNUSED,
                          remote_error *rerr,
                          remote_domain_save_args *args,
                          void *ret ATTRIBUTE_UNUSED)
{
    virDomainPtr dom;

    dom = get_nonnull_domain (conn, args->dom);
    if (dom == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    if (virDomainSave (dom, args->to) == -1) {
        virDomainFree(dom);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }
    virDomainFree(dom);
    return 0;
}

static int
remoteDispatchDomainCoreDump (struct qemud_server *server ATTRIBUTE_UNUSED,
                              struct qemud_client *client ATTRIBUTE_UNUSED,
                              virConnectPtr conn,
                              remote_message_header *hdr ATTRIBUTE_UNUSED,
                              remote_error *rerr,
                              remote_domain_core_dump_args *args,
                              void *ret ATTRIBUTE_UNUSED)
{
    virDomainPtr dom;

    dom = get_nonnull_domain (conn, args->dom);
    if (dom == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    if (virDomainCoreDump (dom, args->to, args->flags) == -1) {
        virDomainFree(dom);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }
    virDomainFree(dom);
    return 0;
}

static int
remoteDispatchDomainSetAutostart (struct qemud_server *server ATTRIBUTE_UNUSED,
                                  struct qemud_client *client ATTRIBUTE_UNUSED,
                                  virConnectPtr conn,
                                  remote_message_header *hdr ATTRIBUTE_UNUSED,
                                  remote_error *rerr,
                                  remote_domain_set_autostart_args *args,
                                  void *ret ATTRIBUTE_UNUSED)
{
    virDomainPtr dom;

    dom = get_nonnull_domain (conn, args->dom);
    if (dom == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    if (virDomainSetAutostart (dom, args->autostart) == -1) {
        virDomainFree(dom);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }
    virDomainFree(dom);
    return 0;
}

static int
remoteDispatchDomainSetMaxMemory (struct qemud_server *server ATTRIBUTE_UNUSED,
                                  struct qemud_client *client ATTRIBUTE_UNUSED,
                                  virConnectPtr conn,
                                  remote_message_header *hdr ATTRIBUTE_UNUSED,
                                  remote_error *rerr,
                                  remote_domain_set_max_memory_args *args,
                                  void *ret ATTRIBUTE_UNUSED)
{
    virDomainPtr dom;

    dom = get_nonnull_domain (conn, args->dom);
    if (dom == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    if (virDomainSetMaxMemory (dom, args->memory) == -1) {
        virDomainFree(dom);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }
    virDomainFree(dom);
    return 0;
}

static int
remoteDispatchDomainSetMemory (struct qemud_server *server ATTRIBUTE_UNUSED,
                               struct qemud_client *client ATTRIBUTE_UNUSED,
                               virConnectPtr conn,
                               remote_message_header *hdr ATTRIBUTE_UNUSED,
                               remote_error *rerr,
                               remote_domain_set_memory_args *args,
                               void *ret ATTRIBUTE_UNUSED)
{
    virDomainPtr dom;

    dom = get_nonnull_domain (conn, args->dom);
    if (dom == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    if (virDomainSetMemory (dom, args->memory) == -1) {
        virDomainFree(dom);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }
    virDomainFree(dom);
    return 0;
}

static int
remoteDispatchDomainSetVcpus (struct qemud_server *server ATTRIBUTE_UNUSED,
                              struct qemud_client *client ATTRIBUTE_UNUSED,
                              virConnectPtr conn,
                              remote_message_header *hdr ATTRIBUTE_UNUSED,
                              remote_error *rerr,
                              remote_domain_set_vcpus_args *args,
                              void *ret ATTRIBUTE_UNUSED)
{
    virDomainPtr dom;

    dom = get_nonnull_domain (conn, args->dom);
    if (dom == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    if (virDomainSetVcpus (dom, args->nvcpus) == -1) {
        virDomainFree(dom);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }
    virDomainFree(dom);
    return 0;
}

static int
remoteDispatchDomainShutdown (struct qemud_server *server ATTRIBUTE_UNUSED,
                              struct qemud_client *client ATTRIBUTE_UNUSED,
                              virConnectPtr conn,
                              remote_message_header *hdr ATTRIBUTE_UNUSED,
                              remote_error *rerr,
                              remote_domain_shutdown_args *args,
                              void *ret ATTRIBUTE_UNUSED)
{
    virDomainPtr dom;

    dom = get_nonnull_domain (conn, args->dom);
    if (dom == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    if (virDomainShutdown (dom) == -1) {
        virDomainFree(dom);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }
    virDomainFree(dom);
    return 0;
}

static int
remoteDispatchDomainSuspend (struct qemud_server *server ATTRIBUTE_UNUSED,
                             struct qemud_client *client ATTRIBUTE_UNUSED,
                             virConnectPtr conn,
                             remote_message_header *hdr ATTRIBUTE_UNUSED,
                             remote_error *rerr,
                             remote_domain_suspend_args *args,
                             void *ret ATTRIBUTE_UNUSED)
{
    virDomainPtr dom;

    dom = get_nonnull_domain (conn, args->dom);
    if (dom == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    if (virDomainSuspend (dom) == -1) {
        virDomainFree(dom);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }
    virDomainFree(dom);
    return 0;
}

static int
remoteDispatchDomainUndefine (struct qemud_server *server ATTRIBUTE_UNUSED,
                              struct qemud_client *client ATTRIBUTE_UNUSED,
                              virConnectPtr conn,
                              remote_message_header *hdr ATTRIBUTE_UNUSED,
                              remote_error *rerr,
                              remote_domain_undefine_args *args,
                              void *ret ATTRIBUTE_UNUSED)
{
    virDomainPtr dom;

    dom = get_nonnull_domain (conn, args->dom);
    if (dom == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    if (virDomainUndefine (dom) == -1) {
        virDomainFree(dom);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }
    virDomainFree(dom);
    return 0;
}

static int
remoteDispatchListDefinedNetworks (struct qemud_server *server ATTRIBUTE_UNUSED,
                                   struct qemud_client *client ATTRIBUTE_UNUSED,
                                   virConnectPtr conn,
                                   remote_message_header *hdr ATTRIBUTE_UNUSED,
                                   remote_error *rerr,
                                   remote_list_defined_networks_args *args,
                                   remote_list_defined_networks_ret *ret)
{

    if (args->maxnames > REMOTE_NETWORK_NAME_LIST_MAX) {
        remoteDispatchFormatError (rerr,
                                   "%s", _("maxnames > REMOTE_NETWORK_NAME_LIST_MAX"));
        return -1;
    }

    /* Allocate return buffer. */
    if (VIR_ALLOC_N(ret->names.names_val, args->maxnames) < 0) {
        remoteDispatchOOMError(rerr);
        return -1;
    }

    ret->names.names_len =
        virConnectListDefinedNetworks (conn,
                                       ret->names.names_val, args->maxnames);
    if (ret->names.names_len == -1) {
        VIR_FREE(ret->names.names_val);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    return 0;
}

static int
remoteDispatchListDomains (struct qemud_server *server ATTRIBUTE_UNUSED,
                           struct qemud_client *client ATTRIBUTE_UNUSED,
                           virConnectPtr conn,
                           remote_message_header *hdr ATTRIBUTE_UNUSED,
                           remote_error *rerr,
                           remote_list_domains_args *args,
                           remote_list_domains_ret *ret)
{

    if (args->maxids > REMOTE_DOMAIN_ID_LIST_MAX) {
        remoteDispatchFormatError (rerr,
                                   "%s", _("maxids > REMOTE_DOMAIN_ID_LIST_MAX"));
        return -1;
    }

    /* Allocate return buffer. */
    if (VIR_ALLOC_N(ret->ids.ids_val, args->maxids) < 0) {
        remoteDispatchOOMError(rerr);
        return -1;
    }

    ret->ids.ids_len = virConnectListDomains (conn,
                                              ret->ids.ids_val, args->maxids);
    if (ret->ids.ids_len == -1) {
        VIR_FREE(ret->ids.ids_val);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    return 0;
}

static int
remoteDispatchListNetworks (struct qemud_server *server ATTRIBUTE_UNUSED,
                            struct qemud_client *client ATTRIBUTE_UNUSED,
                            virConnectPtr conn,
                            remote_message_header *hdr ATTRIBUTE_UNUSED,
                            remote_error *rerr,
                            remote_list_networks_args *args,
                            remote_list_networks_ret *ret)
{

    if (args->maxnames > REMOTE_NETWORK_NAME_LIST_MAX) {
        remoteDispatchFormatError (rerr,
                                   "%s", _("maxnames > REMOTE_NETWORK_NAME_LIST_MAX"));
        return -1;
    }

    /* Allocate return buffer. */
    if (VIR_ALLOC_N(ret->names.names_val, args->maxnames) < 0) {
        remoteDispatchOOMError(rerr);
        return -1;
    }

    ret->names.names_len =
        virConnectListNetworks (conn,
                                ret->names.names_val, args->maxnames);
    if (ret->names.names_len == -1) {
        VIR_FREE(ret->names.names_len);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    return 0;
}

static int
remoteDispatchNetworkCreate (struct qemud_server *server ATTRIBUTE_UNUSED,
                             struct qemud_client *client ATTRIBUTE_UNUSED,
                             virConnectPtr conn,
                             remote_message_header *hdr ATTRIBUTE_UNUSED,
                             remote_error *rerr,
                             remote_network_create_args *args,
                             void *ret ATTRIBUTE_UNUSED)
{
    virNetworkPtr net;

    net = get_nonnull_network (conn, args->net);
    if (net == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    if (virNetworkCreate (net) == -1) {
        virNetworkFree(net);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }
    virNetworkFree(net);
    return 0;
}

static int
remoteDispatchNetworkCreateXml (struct qemud_server *server ATTRIBUTE_UNUSED,
                                struct qemud_client *client ATTRIBUTE_UNUSED,
                                virConnectPtr conn,
                                remote_message_header *hdr ATTRIBUTE_UNUSED,
                                remote_error *rerr,
                                remote_network_create_xml_args *args,
                                remote_network_create_xml_ret *ret)
{
    virNetworkPtr net;

    net = virNetworkCreateXML (conn, args->xml);
    if (net == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    make_nonnull_network (&ret->net, net);
    virNetworkFree(net);
    return 0;
}

static int
remoteDispatchNetworkDefineXml (struct qemud_server *server ATTRIBUTE_UNUSED,
                                struct qemud_client *client ATTRIBUTE_UNUSED,
                                virConnectPtr conn,
                                remote_message_header *hdr ATTRIBUTE_UNUSED,
                                remote_error *rerr,
                                remote_network_define_xml_args *args,
                                remote_network_define_xml_ret *ret)
{
    virNetworkPtr net;

    net = virNetworkDefineXML (conn, args->xml);
    if (net == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    make_nonnull_network (&ret->net, net);
    virNetworkFree(net);
    return 0;
}

static int
remoteDispatchNetworkDestroy (struct qemud_server *server ATTRIBUTE_UNUSED,
                              struct qemud_client *client ATTRIBUTE_UNUSED,
                              virConnectPtr conn,
                              remote_message_header *hdr ATTRIBUTE_UNUSED,
                              remote_error *rerr,
                              remote_network_destroy_args *args,
                              void *ret ATTRIBUTE_UNUSED)
{
    virNetworkPtr net;

    net = get_nonnull_network (conn, args->net);
    if (net == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    if (virNetworkDestroy (net) == -1) {
        virNetworkFree(net);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }
    virNetworkFree(net);
    return 0;
}

static int
remoteDispatchNetworkDumpXml (struct qemud_server *server ATTRIBUTE_UNUSED,
                              struct qemud_client *client ATTRIBUTE_UNUSED,
                              virConnectPtr conn,
                              remote_message_header *hdr ATTRIBUTE_UNUSED,
                              remote_error *rerr,
                              remote_network_dump_xml_args *args,
                              remote_network_dump_xml_ret *ret)
{
    virNetworkPtr net;

    net = get_nonnull_network (conn, args->net);
    if (net == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    /* remoteDispatchClientRequest will free this. */
    ret->xml = virNetworkGetXMLDesc (net, args->flags);
    if (!ret->xml) {
        virNetworkFree(net);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }
    virNetworkFree(net);
    return 0;
}

static int
remoteDispatchNetworkGetAutostart (struct qemud_server *server ATTRIBUTE_UNUSED,
                                   struct qemud_client *client ATTRIBUTE_UNUSED,
                                   virConnectPtr conn,
                                   remote_message_header *hdr ATTRIBUTE_UNUSED,
                                   remote_error *rerr,
                                   remote_network_get_autostart_args *args,
                                   remote_network_get_autostart_ret *ret)
{
    virNetworkPtr net;

    net = get_nonnull_network (conn, args->net);
    if (net == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    if (virNetworkGetAutostart (net, &ret->autostart) == -1) {
        virNetworkFree(net);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }
    virNetworkFree(net);
    return 0;
}

static int
remoteDispatchNetworkGetBridgeName (struct qemud_server *server ATTRIBUTE_UNUSED,
                                    struct qemud_client *client ATTRIBUTE_UNUSED,
                                    virConnectPtr conn,
                                    remote_message_header *hdr ATTRIBUTE_UNUSED,
                                    remote_error *rerr,
                                    remote_network_get_bridge_name_args *args,
                                    remote_network_get_bridge_name_ret *ret)
{
    virNetworkPtr net;

    net = get_nonnull_network (conn, args->net);
    if (net == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    /* remoteDispatchClientRequest will free this. */
    ret->name = virNetworkGetBridgeName (net);
    if (!ret->name) {
        virNetworkFree(net);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }
    virNetworkFree(net);
    return 0;
}

static int
remoteDispatchNetworkLookupByName (struct qemud_server *server ATTRIBUTE_UNUSED,
                                   struct qemud_client *client ATTRIBUTE_UNUSED,
                                   virConnectPtr conn,
                                   remote_message_header *hdr ATTRIBUTE_UNUSED,
                                   remote_error *rerr,
                                   remote_network_lookup_by_name_args *args,
                                   remote_network_lookup_by_name_ret *ret)
{
    virNetworkPtr net;

    net = virNetworkLookupByName (conn, args->name);
    if (net == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    make_nonnull_network (&ret->net, net);
    virNetworkFree(net);
    return 0;
}

static int
remoteDispatchNetworkLookupByUuid (struct qemud_server *server ATTRIBUTE_UNUSED,
                                   struct qemud_client *client ATTRIBUTE_UNUSED,
                                   virConnectPtr conn,
                                   remote_message_header *hdr ATTRIBUTE_UNUSED,
                                   remote_error *rerr,
                                   remote_network_lookup_by_uuid_args *args,
                                   remote_network_lookup_by_uuid_ret *ret)
{
    virNetworkPtr net;

    net = virNetworkLookupByUUID (conn, (unsigned char *) args->uuid);
    if (net == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    make_nonnull_network (&ret->net, net);
    virNetworkFree(net);
    return 0;
}

static int
remoteDispatchNetworkSetAutostart (struct qemud_server *server ATTRIBUTE_UNUSED,
                                   struct qemud_client *client ATTRIBUTE_UNUSED,
                                   virConnectPtr conn,
                                   remote_message_header *hdr ATTRIBUTE_UNUSED,
                                   remote_error *rerr,
                                   remote_network_set_autostart_args *args,
                                   void *ret ATTRIBUTE_UNUSED)
{
    virNetworkPtr net;

    net = get_nonnull_network (conn, args->net);
    if (net == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    if (virNetworkSetAutostart (net, args->autostart) == -1) {
        virNetworkFree(net);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }
    virNetworkFree(net);
    return 0;
}

static int
remoteDispatchNetworkUndefine (struct qemud_server *server ATTRIBUTE_UNUSED,
                               struct qemud_client *client ATTRIBUTE_UNUSED,
                               virConnectPtr conn,
                               remote_message_header *hdr ATTRIBUTE_UNUSED,
                               remote_error *rerr,
                               remote_network_undefine_args *args,
                               void *ret ATTRIBUTE_UNUSED)
{
    virNetworkPtr net;

    net = get_nonnull_network (conn, args->net);
    if (net == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    if (virNetworkUndefine (net) == -1) {
        virNetworkFree(net);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }
    virNetworkFree(net);
    return 0;
}

static int
remoteDispatchNumOfDefinedNetworks (struct qemud_server *server ATTRIBUTE_UNUSED,
                                    struct qemud_client *client ATTRIBUTE_UNUSED,
                                    virConnectPtr conn,
                                    remote_message_header *hdr ATTRIBUTE_UNUSED,
                                    remote_error *rerr,
                                    void *args ATTRIBUTE_UNUSED,
                                    remote_num_of_defined_networks_ret *ret)
{

    ret->num = virConnectNumOfDefinedNetworks (conn);
    if (ret->num == -1) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    return 0;
}

static int
remoteDispatchNumOfDomains (struct qemud_server *server ATTRIBUTE_UNUSED,
                            struct qemud_client *client ATTRIBUTE_UNUSED,
                            virConnectPtr conn,
                            remote_message_header *hdr ATTRIBUTE_UNUSED,
                            remote_error *rerr,
                            void *args ATTRIBUTE_UNUSED,
                            remote_num_of_domains_ret *ret)
{

    ret->num = virConnectNumOfDomains (conn);
    if (ret->num == -1) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    return 0;
}

static int
remoteDispatchNumOfNetworks (struct qemud_server *server ATTRIBUTE_UNUSED,
                             struct qemud_client *client ATTRIBUTE_UNUSED,
                             virConnectPtr conn,
                             remote_message_header *hdr ATTRIBUTE_UNUSED,
                             remote_error *rerr,
                             void *args ATTRIBUTE_UNUSED,
                             remote_num_of_networks_ret *ret)
{

    ret->num = virConnectNumOfNetworks (conn);
    if (ret->num == -1) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    return 0;
}


/*-------------------------------------------------------------*/
static int
remoteDispatchNumOfInterfaces (struct qemud_server *server ATTRIBUTE_UNUSED,
                               struct qemud_client *client ATTRIBUTE_UNUSED,
                               virConnectPtr conn,
                               remote_message_header *hdr ATTRIBUTE_UNUSED,
                               remote_error *rerr,
                               void *args ATTRIBUTE_UNUSED,
                               remote_num_of_interfaces_ret *ret)
{

    ret->num = virConnectNumOfInterfaces (conn);
    if (ret->num == -1) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    return 0;
}

static int
remoteDispatchListInterfaces (struct qemud_server *server ATTRIBUTE_UNUSED,
                              struct qemud_client *client ATTRIBUTE_UNUSED,
                              virConnectPtr conn,
                              remote_message_header *hdr ATTRIBUTE_UNUSED,
                              remote_error *rerr,
                              remote_list_interfaces_args *args,
                              remote_list_interfaces_ret *ret)
{

    if (args->maxnames > REMOTE_INTERFACE_NAME_LIST_MAX) {
        remoteDispatchFormatError (rerr,
                                   "%s", _("maxnames > REMOTE_INTERFACE_NAME_LIST_MAX"));
        return -1;
    }

    /* Allocate return buffer. */
    if (VIR_ALLOC_N(ret->names.names_val, args->maxnames) < 0) {
        remoteDispatchOOMError(rerr);
        return -1;
    }

    ret->names.names_len =
        virConnectListInterfaces (conn,
                                  ret->names.names_val, args->maxnames);
    if (ret->names.names_len == -1) {
        VIR_FREE(ret->names.names_len);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    return 0;
}

static int
remoteDispatchNumOfDefinedInterfaces (struct qemud_server *server ATTRIBUTE_UNUSED,
                                      struct qemud_client *client ATTRIBUTE_UNUSED,
                                      virConnectPtr conn,
                                      remote_message_header *hdr ATTRIBUTE_UNUSED,
                                      remote_error *rerr,
                                      void *args ATTRIBUTE_UNUSED,
                                      remote_num_of_defined_interfaces_ret *ret)
{

    ret->num = virConnectNumOfDefinedInterfaces (conn);
    if (ret->num == -1) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    return 0;
}

static int
remoteDispatchListDefinedInterfaces (struct qemud_server *server ATTRIBUTE_UNUSED,
                                     struct qemud_client *client ATTRIBUTE_UNUSED,
                                     virConnectPtr conn,
                                     remote_message_header *hdr ATTRIBUTE_UNUSED,
                                     remote_error *rerr,
                                     remote_list_defined_interfaces_args *args,
                                     remote_list_defined_interfaces_ret *ret)
{

    if (args->maxnames > REMOTE_DEFINED_INTERFACE_NAME_LIST_MAX) {
        remoteDispatchFormatError (rerr,
                                   "%s", _("maxnames > REMOTE_DEFINED_INTERFACE_NAME_LIST_MAX"));
        return -1;
    }

    /* Allocate return buffer. */
    if (VIR_ALLOC_N(ret->names.names_val, args->maxnames) < 0) {
        remoteDispatchOOMError(rerr);
        return -1;
    }

    ret->names.names_len =
        virConnectListDefinedInterfaces (conn,
                                         ret->names.names_val, args->maxnames);
    if (ret->names.names_len == -1) {
        VIR_FREE(ret->names.names_len);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    return 0;
}

static int
remoteDispatchInterfaceLookupByName (struct qemud_server *server ATTRIBUTE_UNUSED,
                                     struct qemud_client *client ATTRIBUTE_UNUSED,
                                     virConnectPtr conn,
                                     remote_message_header *hdr ATTRIBUTE_UNUSED,
                                     remote_error *rerr,
                                     remote_interface_lookup_by_name_args *args,
                                     remote_interface_lookup_by_name_ret *ret)
{
    virInterfacePtr iface;

    iface = virInterfaceLookupByName (conn, args->name);
    if (iface == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    make_nonnull_interface (&ret->iface, iface);
    virInterfaceFree(iface);
    return 0;
}

static int
remoteDispatchInterfaceLookupByMacString (struct qemud_server *server ATTRIBUTE_UNUSED,
                                          struct qemud_client *client ATTRIBUTE_UNUSED,
                                          virConnectPtr conn,
                                          remote_message_header *hdr ATTRIBUTE_UNUSED,
                                          remote_error *rerr,
                                          remote_interface_lookup_by_mac_string_args *args,
                                          remote_interface_lookup_by_mac_string_ret *ret)
{
    virInterfacePtr iface;

    iface = virInterfaceLookupByMACString (conn, args->mac);
    if (iface == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    make_nonnull_interface (&ret->iface, iface);
    virInterfaceFree(iface);
    return 0;
}

static int
remoteDispatchInterfaceGetXmlDesc (struct qemud_server *server ATTRIBUTE_UNUSED,
                                   struct qemud_client *client ATTRIBUTE_UNUSED,
                                   virConnectPtr conn,
                                   remote_message_header *hdr ATTRIBUTE_UNUSED,
                                   remote_error *rerr,
                                   remote_interface_get_xml_desc_args *args,
                                   remote_interface_get_xml_desc_ret *ret)
{
    virInterfacePtr iface;

    iface = get_nonnull_interface (conn, args->iface);
    if (iface == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    /* remoteDispatchClientRequest will free this. */
    ret->xml = virInterfaceGetXMLDesc (iface, args->flags);
    if (!ret->xml) {
        virInterfaceFree(iface);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }
    virInterfaceFree(iface);
    return 0;
}

static int
remoteDispatchInterfaceDefineXml (struct qemud_server *server ATTRIBUTE_UNUSED,
                                  struct qemud_client *client ATTRIBUTE_UNUSED,
                                  virConnectPtr conn,
                                  remote_message_header *hdr ATTRIBUTE_UNUSED,
                                  remote_error *rerr,
                                  remote_interface_define_xml_args *args,
                                  remote_interface_define_xml_ret *ret)
{
    virInterfacePtr iface;

    iface = virInterfaceDefineXML (conn, args->xml, args->flags);
    if (iface == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    make_nonnull_interface (&ret->iface, iface);
    virInterfaceFree(iface);
    return 0;
}

static int
remoteDispatchInterfaceUndefine (struct qemud_server *server ATTRIBUTE_UNUSED,
                                 struct qemud_client *client ATTRIBUTE_UNUSED,
                                 virConnectPtr conn,
                                 remote_message_header *hdr ATTRIBUTE_UNUSED,
                                 remote_error *rerr,
                                 remote_interface_undefine_args *args,
                                 void *ret ATTRIBUTE_UNUSED)
{
    virInterfacePtr iface;

    iface = get_nonnull_interface (conn, args->iface);
    if (iface == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    if (virInterfaceUndefine (iface) == -1) {
        virInterfaceFree(iface);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }
    virInterfaceFree(iface);
    return 0;
}

static int
remoteDispatchInterfaceCreate (struct qemud_server *server ATTRIBUTE_UNUSED,
                               struct qemud_client *client ATTRIBUTE_UNUSED,
                               virConnectPtr conn,
                               remote_message_header *hdr ATTRIBUTE_UNUSED,
                               remote_error *rerr,
                               remote_interface_create_args *args,
                               void *ret ATTRIBUTE_UNUSED)
{
    virInterfacePtr iface;

    iface = get_nonnull_interface (conn, args->iface);
    if (iface == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    if (virInterfaceCreate (iface, args->flags) == -1) {
        virInterfaceFree(iface);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }
    virInterfaceFree(iface);
    return 0;
}

static int
remoteDispatchInterfaceDestroy (struct qemud_server *server ATTRIBUTE_UNUSED,
                                struct qemud_client *client ATTRIBUTE_UNUSED,
                                virConnectPtr conn,
                                remote_message_header *hdr ATTRIBUTE_UNUSED,
                                remote_error *rerr,
                                remote_interface_destroy_args *args,
                                void *ret ATTRIBUTE_UNUSED)
{
    virInterfacePtr iface;

    iface = get_nonnull_interface (conn, args->iface);
    if (iface == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    if (virInterfaceDestroy (iface, args->flags) == -1) {
        virInterfaceFree(iface);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }
    virInterfaceFree(iface);
    return 0;
}

/*-------------------------------------------------------------*/

static int
remoteDispatchAuthList (struct qemud_server *server,
                        struct qemud_client *client,
                        virConnectPtr conn ATTRIBUTE_UNUSED,
                        remote_message_header *hdr ATTRIBUTE_UNUSED,
                        remote_error *rerr,
                        void *args ATTRIBUTE_UNUSED,
                        remote_auth_list_ret *ret)
{
    ret->types.types_len = 1;
    if (VIR_ALLOC_N(ret->types.types_val, ret->types.types_len) < 0) {
        remoteDispatchOOMError(rerr);
        return -1;
    }
    virMutexLock(&server->lock);
    virMutexLock(&client->lock);
    virMutexUnlock(&server->lock);
    ret->types.types_val[0] = client->auth;
    virMutexUnlock(&client->lock);

    return 0;
}


#if HAVE_SASL
/*
 * NB, keep in sync with similar method in src/remote_internal.c
 */
static char *addrToString(remote_error *rerr,
                          struct sockaddr_storage *sa, socklen_t salen) {
    char host[1024], port[20];
    char *addr;
    int err;

    if ((err = getnameinfo((struct sockaddr *)sa, salen,
                           host, sizeof(host),
                           port, sizeof(port),
                           NI_NUMERICHOST | NI_NUMERICSERV)) != 0) {
        remoteDispatchFormatError(rerr,
                                  _("Cannot resolve address %d: %s"),
                                  err, gai_strerror(err));
        return NULL;
    }

    if (virAsprintf(&addr, "%s;%s", host, port) == -1) {
        virReportOOMError(NULL);
        return NULL;
    }

    return addr;
}


/*
 * Initializes the SASL session in prepare for authentication
 * and gives the client a list of allowed mechanisms to choose
 *
 * XXX callbacks for stuff like password verification ?
 */
static int
remoteDispatchAuthSaslInit (struct qemud_server *server,
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
    struct sockaddr_storage sa;
    socklen_t salen;
    char *localAddr, *remoteAddr;

    virMutexLock(&server->lock);
    virMutexLock(&client->lock);
    virMutexUnlock(&server->lock);

    REMOTE_DEBUG("Initialize SASL auth %d", client->fd);
    if (client->auth != REMOTE_AUTH_SASL ||
        client->saslconn != NULL) {
        VIR_ERROR0(_("client tried invalid SASL init request"));
        goto authfail;
    }

    /* Get local address in form  IPADDR:PORT */
    salen = sizeof(sa);
    if (getsockname(client->fd, (struct sockaddr*)&sa, &salen) < 0) {
        char ebuf[1024];
        remoteDispatchFormatError(rerr,
                                  _("failed to get sock address: %s"),
                                  virStrerror(errno, ebuf, sizeof ebuf));
        goto error;
    }
    if ((localAddr = addrToString(rerr, &sa, salen)) == NULL) {
        goto error;
    }

    /* Get remote address in form  IPADDR:PORT */
    salen = sizeof(sa);
    if (getpeername(client->fd, (struct sockaddr*)&sa, &salen) < 0) {
        char ebuf[1024];
        remoteDispatchFormatError(rerr, _("failed to get peer address: %s"),
                                  virStrerror(errno, ebuf, sizeof ebuf));
        VIR_FREE(localAddr);
        goto error;
    }
    if ((remoteAddr = addrToString(rerr, &sa, salen)) == NULL) {
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

    memset (&secprops, 0, sizeof secprops);
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
    REMOTE_DEBUG("Available mechanisms for client: '%s'", mechlist);
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
    virMutexUnlock(&client->lock);
    return -1;
}


/* We asked for an SSF layer, so sanity check that we actually
 * got what we asked for */
static int
remoteSASLCheckSSF (struct qemud_client *client,
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
    REMOTE_DEBUG("negotiated an SSF of %d", ssf);
    if (ssf < 56) { /* 56 is good for Kerberos */
        VIR_ERROR(_("negotiated SSF %d was not strong enough"), ssf);
        remoteDispatchAuthError(rerr);
        sasl_dispose(&client->saslconn);
        client->saslconn = NULL;
        return -1;
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

static int
remoteSASLCheckAccess (struct qemud_server *server,
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
    REMOTE_DEBUG("SASL client username %s", (const char *)val);

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
        if (fnmatch (*wildcards, client->saslUsername, 0) == 0)
            return 0; /* Allowed */
        wildcards++;
    }

    /* Denied */
    VIR_ERROR(_("SASL client %s not allowed in whitelist"), client->saslUsername);
    remoteDispatchAuthError(rerr);
    sasl_dispose(&client->saslconn);
    client->saslconn = NULL;
    return -1;
}


/*
 * This starts the SASL authentication negotiation.
 */
static int
remoteDispatchAuthSaslStart (struct qemud_server *server,
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

    REMOTE_DEBUG("Start SASL auth %d", client->fd);
    if (client->auth != REMOTE_AUTH_SASL ||
        client->saslconn == NULL) {
        VIR_ERROR0(_("client tried invalid SASL start request"));
        goto authfail;
    }

    REMOTE_DEBUG("Using SASL mechanism %s. Data %d bytes, nil: %d",
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
            remoteDispatchOOMError(rerr);
            goto error;
        }
        memcpy(ret->data.data_val, serverout, serveroutlen);
    } else {
        ret->data.data_val = NULL;
    }
    ret->nil = serverout ? 0 : 1;
    ret->data.data_len = serveroutlen;

    REMOTE_DEBUG("SASL return data %d bytes, nil; %d", ret->data.data_len, ret->nil);
    if (err == SASL_CONTINUE) {
        ret->complete = 0;
    } else {
        if (remoteSASLCheckSSF(client, rerr) < 0)
            goto error;

        /* Check username whitelist ACL */
        if (remoteSASLCheckAccess(server, client, rerr) < 0)
            goto error;

        REMOTE_DEBUG("Authentication successful %d", client->fd);
        ret->complete = 1;
        client->auth = REMOTE_AUTH_NONE;
    }

    virMutexUnlock(&client->lock);
    return 0;

authfail:
    remoteDispatchAuthError(rerr);
error:
    virMutexUnlock(&client->lock);
    return -1;
}


static int
remoteDispatchAuthSaslStep (struct qemud_server *server,
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

    REMOTE_DEBUG("Step SASL auth %d", client->fd);
    if (client->auth != REMOTE_AUTH_SASL ||
        client->saslconn == NULL) {
        VIR_ERROR0(_("client tried invalid SASL start request"));
        goto authfail;
    }

    REMOTE_DEBUG("Using SASL Data %d bytes, nil: %d",
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
            remoteDispatchOOMError(rerr);
            goto error;
        }
        memcpy(ret->data.data_val, serverout, serveroutlen);
    } else {
        ret->data.data_val = NULL;
    }
    ret->nil = serverout ? 0 : 1;
    ret->data.data_len = serveroutlen;

    REMOTE_DEBUG("SASL return data %d bytes, nil; %d", ret->data.data_len, ret->nil);
    if (err == SASL_CONTINUE) {
        ret->complete = 0;
    } else {
        if (remoteSASLCheckSSF(client, rerr) < 0)
            goto error;

        /* Check username whitelist ACL */
        if (remoteSASLCheckAccess(server, client, rerr) < 0)
            goto error;

        REMOTE_DEBUG("Authentication successful %d", client->fd);
        ret->complete = 1;
        client->auth = REMOTE_AUTH_NONE;
    }

    virMutexUnlock(&client->lock);
    return 0;

authfail:
    remoteDispatchAuthError(rerr);
error:
    virMutexUnlock(&client->lock);
    return -1;
}


#else /* HAVE_SASL */
static int
remoteDispatchAuthSaslInit (struct qemud_server *server ATTRIBUTE_UNUSED,
                            struct qemud_client *client ATTRIBUTE_UNUSED,
                            virConnectPtr conn ATTRIBUTE_UNUSED,
                            remote_message_header *hdr ATTRIBUTE_UNUSED,
                            remote_error *rerr,
                            void *args ATTRIBUTE_UNUSED,
                            remote_auth_sasl_init_ret *ret ATTRIBUTE_UNUSED)
{
    VIR_ERROR0(_("client tried unsupported SASL init request"));
    remoteDispatchAuthError(rerr);
    return -1;
}

static int
remoteDispatchAuthSaslStart (struct qemud_server *server ATTRIBUTE_UNUSED,
                             struct qemud_client *client ATTRIBUTE_UNUSED,
                             virConnectPtr conn ATTRIBUTE_UNUSED,
                             remote_message_header *hdr ATTRIBUTE_UNUSED,
                             remote_error *rerr,
                             remote_auth_sasl_start_args *args ATTRIBUTE_UNUSED,
                             remote_auth_sasl_start_ret *ret ATTRIBUTE_UNUSED)
{
    VIR_ERROR0(_("client tried unsupported SASL start request"));
    remoteDispatchAuthError(rerr);
    return -1;
}

static int
remoteDispatchAuthSaslStep (struct qemud_server *server ATTRIBUTE_UNUSED,
                            struct qemud_client *client ATTRIBUTE_UNUSED,
                            virConnectPtr conn ATTRIBUTE_UNUSED,
                            remote_message_header *hdr ATTRIBUTE_UNUSED,
                            remote_error *rerr,
                            remote_auth_sasl_step_args *args ATTRIBUTE_UNUSED,
                            remote_auth_sasl_step_ret *ret ATTRIBUTE_UNUSED)
{
    VIR_ERROR0(_("client tried unsupported SASL step request"));
    remoteDispatchAuthError(rerr);
    return -1;
}
#endif /* HAVE_SASL */


#if HAVE_POLKIT1
static int
remoteDispatchAuthPolkit (struct qemud_server *server,
                          struct qemud_client *client,
                          virConnectPtr conn ATTRIBUTE_UNUSED,
                          remote_message_header *hdr ATTRIBUTE_UNUSED,
                          remote_error *rerr,
                          void *args ATTRIBUTE_UNUSED,
                          remote_auth_polkit_ret *ret)
{
    pid_t callerPid;
    uid_t callerUid;
    const char *action;
    int status = -1;
    char pidbuf[50];
    int rv;

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

    REMOTE_DEBUG("Start PolicyKit auth %d", client->fd);
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

    if (virRun(NULL, pkcheck, &status) < 0) {
        VIR_ERROR(_("Cannot invoke %s"), PKCHECK_PATH);
        goto authfail;
    }
    if (status != 0) {
        VIR_ERROR(_("Policy kit denied action %s from pid %d, uid %d, result: %d\n"),
                  action, callerPid, callerUid, status);
        goto authfail;
    }
    VIR_INFO(_("Policy allowed action %s from pid %d, uid %d"),
             action, callerPid, callerUid);
    ret->complete = 1;
    client->auth = REMOTE_AUTH_NONE;

    virMutexUnlock(&client->lock);
    return 0;

authfail:
    remoteDispatchAuthError(rerr);
    virMutexUnlock(&client->lock);
    return -1;
}
#elif HAVE_POLKIT0
static int
remoteDispatchAuthPolkit (struct qemud_server *server,
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

    virMutexLock(&server->lock);
    virMutexLock(&client->lock);
    virMutexUnlock(&server->lock);

    action = client->readonly ?
        "org.libvirt.unix.monitor" :
        "org.libvirt.unix.manage";

    REMOTE_DEBUG("Start PolicyKit auth %d", client->fd);
    if (client->auth != REMOTE_AUTH_POLKIT) {
        VIR_ERROR0(_("client tried invalid PolicyKit init request"));
        goto authfail;
    }

    if (qemudGetSocketIdentity(client->fd, &callerUid, &callerPid) < 0) {
        VIR_ERROR0(_("cannot get peer socket identity"));
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
        VIR_ERROR(_("Failed to create polkit action %s\n"),
                  virStrerror(errno, ebuf, sizeof ebuf));
        polkit_caller_unref(pkcaller);
        goto authfail;
    }
    polkit_action_set_action_id(pkaction, action);

    if (!(pkcontext = polkit_context_new()) ||
        !polkit_context_init(pkcontext, &pkerr)) {
        char ebuf[1024];
        VIR_ERROR(_("Failed to create polkit context %s\n"),
                  (pkerr ? polkit_error_get_error_message(pkerr)
                   : virStrerror(errno, ebuf, sizeof ebuf)));
        if (pkerr)
            polkit_error_free(pkerr);
        polkit_caller_unref(pkcaller);
        polkit_action_unref(pkaction);
        dbus_error_free(&err);
        goto authfail;
    }

#if HAVE_POLKIT_CONTEXT_IS_CALLER_AUTHORIZED
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
#else
    pkresult = polkit_context_can_caller_do_action(pkcontext,
                                                   pkaction,
                                                   pkcaller);
#endif
    polkit_context_unref(pkcontext);
    polkit_caller_unref(pkcaller);
    polkit_action_unref(pkaction);
    if (pkresult != POLKIT_RESULT_YES) {
        VIR_ERROR(_("Policy kit denied action %s from pid %d, uid %d, result: %s\n"),
                  action, callerPid, callerUid,
                  polkit_result_to_string_representation(pkresult));
        goto authfail;
    }
    VIR_INFO(_("Policy allowed action %s from pid %d, uid %d, result %s"),
             action, callerPid, callerUid,
             polkit_result_to_string_representation(pkresult));
    ret->complete = 1;
    client->auth = REMOTE_AUTH_NONE;

    virMutexUnlock(&client->lock);
    return 0;

authfail:
    remoteDispatchAuthError(rerr);
    virMutexUnlock(&client->lock);
    return -1;
}

#else /* !HAVE_POLKIT0 & !HAVE_POLKIT1*/

static int
remoteDispatchAuthPolkit (struct qemud_server *server ATTRIBUTE_UNUSED,
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
remoteDispatchListDefinedStoragePools (struct qemud_server *server ATTRIBUTE_UNUSED,
                                       struct qemud_client *client ATTRIBUTE_UNUSED,
                                       virConnectPtr conn,
                                       remote_message_header *hdr ATTRIBUTE_UNUSED,
                                       remote_error *rerr,
                                       remote_list_defined_storage_pools_args *args,
                                       remote_list_defined_storage_pools_ret *ret)
{

    if (args->maxnames > REMOTE_NETWORK_NAME_LIST_MAX) {
        remoteDispatchFormatError (rerr, "%s",
                            _("maxnames > REMOTE_NETWORK_NAME_LIST_MAX"));
        return -1;
    }

    /* Allocate return buffer. */
    if (VIR_ALLOC_N(ret->names.names_val, args->maxnames) < 0) {
        remoteDispatchOOMError(rerr);
        return -1;
    }

    ret->names.names_len =
        virConnectListDefinedStoragePools (conn,
                                           ret->names.names_val, args->maxnames);
    if (ret->names.names_len == -1) {
        VIR_FREE(ret->names.names_val);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    return 0;
}

static int
remoteDispatchListStoragePools (struct qemud_server *server ATTRIBUTE_UNUSED,
                                struct qemud_client *client ATTRIBUTE_UNUSED,
                                virConnectPtr conn,
                                remote_message_header *hdr ATTRIBUTE_UNUSED,
                                remote_error *rerr,
                                remote_list_storage_pools_args *args,
                                remote_list_storage_pools_ret *ret)
{

    if (args->maxnames > REMOTE_STORAGE_POOL_NAME_LIST_MAX) {
        remoteDispatchFormatError (rerr,
                                   "%s", _("maxnames > REMOTE_STORAGE_POOL_NAME_LIST_MAX"));
        return -1;
    }

    /* Allocate return buffer. */
    if (VIR_ALLOC_N(ret->names.names_val, args->maxnames) < 0) {
        remoteDispatchOOMError(rerr);
        return -1;
    }

    ret->names.names_len =
        virConnectListStoragePools (conn,
                                ret->names.names_val, args->maxnames);
    if (ret->names.names_len == -1) {
        VIR_FREE(ret->names.names_val);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    return 0;
}

static int
remoteDispatchFindStoragePoolSources (struct qemud_server *server ATTRIBUTE_UNUSED,
                                      struct qemud_client *client ATTRIBUTE_UNUSED,
                                      virConnectPtr conn,
                                      remote_message_header *hdr ATTRIBUTE_UNUSED,
                                      remote_error *rerr,
                                      remote_find_storage_pool_sources_args *args,
                                      remote_find_storage_pool_sources_ret *ret)
{
    ret->xml =
        virConnectFindStoragePoolSources (conn,
                                          args->type,
                                          args->srcSpec ? *args->srcSpec : NULL,
                                          args->flags);
    if (ret->xml == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    return 0;
}


static int
remoteDispatchStoragePoolCreate (struct qemud_server *server ATTRIBUTE_UNUSED,
                                 struct qemud_client *client ATTRIBUTE_UNUSED,
                                 virConnectPtr conn,
                                 remote_message_header *hdr ATTRIBUTE_UNUSED,
                                 remote_error *rerr,
                                 remote_storage_pool_create_args *args,
                                 void *ret ATTRIBUTE_UNUSED)
{
    virStoragePoolPtr pool;

    pool = get_nonnull_storage_pool (conn, args->pool);
    if (pool == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    if (virStoragePoolCreate (pool, args->flags) == -1) {
        virStoragePoolFree(pool);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }
    virStoragePoolFree(pool);
    return 0;
}

static int
remoteDispatchStoragePoolCreateXml (struct qemud_server *server ATTRIBUTE_UNUSED,
                                    struct qemud_client *client ATTRIBUTE_UNUSED,
                                    virConnectPtr conn,
                                    remote_message_header *hdr ATTRIBUTE_UNUSED,
                                    remote_error *rerr,
                                    remote_storage_pool_create_xml_args *args,
                                    remote_storage_pool_create_xml_ret *ret)
{
    virStoragePoolPtr pool;

    pool = virStoragePoolCreateXML (conn, args->xml, args->flags);
    if (pool == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    make_nonnull_storage_pool (&ret->pool, pool);
    virStoragePoolFree(pool);
    return 0;
}

static int
remoteDispatchStoragePoolDefineXml (struct qemud_server *server ATTRIBUTE_UNUSED,
                                    struct qemud_client *client ATTRIBUTE_UNUSED,
                                    virConnectPtr conn,
                                    remote_message_header *hdr ATTRIBUTE_UNUSED,
                                    remote_error *rerr,
                                    remote_storage_pool_define_xml_args *args,
                                    remote_storage_pool_define_xml_ret *ret)
{
    virStoragePoolPtr pool;

    pool = virStoragePoolDefineXML (conn, args->xml, args->flags);
    if (pool == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    make_nonnull_storage_pool (&ret->pool, pool);
    virStoragePoolFree(pool);
    return 0;
}

static int
remoteDispatchStoragePoolBuild (struct qemud_server *server ATTRIBUTE_UNUSED,
                                struct qemud_client *client ATTRIBUTE_UNUSED,
                                virConnectPtr conn,
                                remote_message_header *hdr ATTRIBUTE_UNUSED,
                                remote_error *rerr,
                                remote_storage_pool_build_args *args,
                                void *ret ATTRIBUTE_UNUSED)
{
    virStoragePoolPtr pool;

    pool = get_nonnull_storage_pool (conn, args->pool);
    if (pool == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    if (virStoragePoolBuild (pool, args->flags) == -1) {
        virStoragePoolFree(pool);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }
    virStoragePoolFree(pool);
    return 0;
}


static int
remoteDispatchStoragePoolDestroy (struct qemud_server *server ATTRIBUTE_UNUSED,
                                  struct qemud_client *client ATTRIBUTE_UNUSED,
                                  virConnectPtr conn,
                                  remote_message_header *hdr ATTRIBUTE_UNUSED,
                                  remote_error *rerr,
                                  remote_storage_pool_destroy_args *args,
                                  void *ret ATTRIBUTE_UNUSED)
{
    virStoragePoolPtr pool;

    pool = get_nonnull_storage_pool (conn, args->pool);
    if (pool == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    if (virStoragePoolDestroy (pool) == -1) {
        virStoragePoolFree(pool);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }
    virStoragePoolFree(pool);
    return 0;
}

static int
remoteDispatchStoragePoolDelete (struct qemud_server *server ATTRIBUTE_UNUSED,
                                 struct qemud_client *client ATTRIBUTE_UNUSED,
                                 virConnectPtr conn,
                                 remote_message_header *hdr ATTRIBUTE_UNUSED,
                                 remote_error *rerr,
                                 remote_storage_pool_delete_args *args,
                                 void *ret ATTRIBUTE_UNUSED)
{
    virStoragePoolPtr pool;

    pool = get_nonnull_storage_pool (conn, args->pool);
    if (pool == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    if (virStoragePoolDelete (pool, args->flags) == -1) {
        virStoragePoolFree(pool);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }
    virStoragePoolFree(pool);
    return 0;
}

static int
remoteDispatchStoragePoolRefresh (struct qemud_server *server ATTRIBUTE_UNUSED,
                                  struct qemud_client *client ATTRIBUTE_UNUSED,
                                  virConnectPtr conn,
                                  remote_message_header *hdr ATTRIBUTE_UNUSED,
                                  remote_error *rerr,
                                  remote_storage_pool_refresh_args *args,
                                  void *ret ATTRIBUTE_UNUSED)
{
    virStoragePoolPtr pool;

    pool = get_nonnull_storage_pool (conn, args->pool);
    if (pool == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    if (virStoragePoolRefresh (pool, args->flags) == -1) {
        virStoragePoolFree(pool);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }
    virStoragePoolFree(pool);
    return 0;
}

static int
remoteDispatchStoragePoolGetInfo (struct qemud_server *server ATTRIBUTE_UNUSED,
                                  struct qemud_client *client ATTRIBUTE_UNUSED,
                                  virConnectPtr conn,
                                  remote_message_header *hdr ATTRIBUTE_UNUSED,
                                  remote_error *rerr,
                                  remote_storage_pool_get_info_args *args,
                                  remote_storage_pool_get_info_ret *ret)
{
    virStoragePoolPtr pool;
    virStoragePoolInfo info;

    pool = get_nonnull_storage_pool (conn, args->pool);
    if (pool == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    if (virStoragePoolGetInfo (pool, &info) == -1) {
        virStoragePoolFree(pool);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    ret->state = info.state;
    ret->capacity = info.capacity;
    ret->allocation = info.allocation;
    ret->available = info.available;

    virStoragePoolFree(pool);

    return 0;
}

static int
remoteDispatchStoragePoolDumpXml (struct qemud_server *server ATTRIBUTE_UNUSED,
                                  struct qemud_client *client ATTRIBUTE_UNUSED,
                                  virConnectPtr conn,
                                  remote_message_header *hdr ATTRIBUTE_UNUSED,
                                  remote_error *rerr,
                                  remote_storage_pool_dump_xml_args *args,
                                  remote_storage_pool_dump_xml_ret *ret)
{
    virStoragePoolPtr pool;

    pool = get_nonnull_storage_pool (conn, args->pool);
    if (pool == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    /* remoteDispatchClientRequest will free this. */
    ret->xml = virStoragePoolGetXMLDesc (pool, args->flags);
    if (!ret->xml) {
        virStoragePoolFree(pool);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }
    virStoragePoolFree(pool);
    return 0;
}

static int
remoteDispatchStoragePoolGetAutostart (struct qemud_server *server ATTRIBUTE_UNUSED,
                                       struct qemud_client *client ATTRIBUTE_UNUSED,
                                       virConnectPtr conn,
                                       remote_message_header *hdr ATTRIBUTE_UNUSED,
                                       remote_error *rerr,
                                       remote_storage_pool_get_autostart_args *args,
                                       remote_storage_pool_get_autostart_ret *ret)
{
    virStoragePoolPtr pool;

    pool = get_nonnull_storage_pool (conn, args->pool);
    if (pool == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    if (virStoragePoolGetAutostart (pool, &ret->autostart) == -1) {
        virStoragePoolFree(pool);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }
    virStoragePoolFree(pool);
    return 0;
}


static int
remoteDispatchStoragePoolLookupByName (struct qemud_server *server ATTRIBUTE_UNUSED,
                                       struct qemud_client *client ATTRIBUTE_UNUSED,
                                       virConnectPtr conn,
                                       remote_message_header *hdr ATTRIBUTE_UNUSED,
                                       remote_error *rerr,
                                       remote_storage_pool_lookup_by_name_args *args,
                                       remote_storage_pool_lookup_by_name_ret *ret)
{
    virStoragePoolPtr pool;

    pool = virStoragePoolLookupByName (conn, args->name);
    if (pool == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    make_nonnull_storage_pool (&ret->pool, pool);
    virStoragePoolFree(pool);
    return 0;
}

static int
remoteDispatchStoragePoolLookupByUuid (struct qemud_server *server ATTRIBUTE_UNUSED,
                                       struct qemud_client *client ATTRIBUTE_UNUSED,
                                       virConnectPtr conn,
                                       remote_message_header *hdr ATTRIBUTE_UNUSED,
                                       remote_error *rerr,
                                       remote_storage_pool_lookup_by_uuid_args *args,
                                       remote_storage_pool_lookup_by_uuid_ret *ret)
{
    virStoragePoolPtr pool;

    pool = virStoragePoolLookupByUUID (conn, (unsigned char *) args->uuid);
    if (pool == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    make_nonnull_storage_pool (&ret->pool, pool);
    virStoragePoolFree(pool);
    return 0;
}

static int
remoteDispatchStoragePoolLookupByVolume (struct qemud_server *server ATTRIBUTE_UNUSED,
                                         struct qemud_client *client ATTRIBUTE_UNUSED,
                                         virConnectPtr conn,
                                         remote_message_header *hdr ATTRIBUTE_UNUSED,
                                         remote_error *rerr,
                                         remote_storage_pool_lookup_by_volume_args *args,
                                         remote_storage_pool_lookup_by_volume_ret *ret)
{
    virStoragePoolPtr pool;
    virStorageVolPtr vol;

    vol = get_nonnull_storage_vol (conn, args->vol);
    if (vol == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    pool = virStoragePoolLookupByVolume (vol);
    virStorageVolFree(vol);
    if (pool == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    make_nonnull_storage_pool (&ret->pool, pool);
    virStoragePoolFree(pool);
    return 0;
}

static int
remoteDispatchStoragePoolSetAutostart (struct qemud_server *server ATTRIBUTE_UNUSED,
                                       struct qemud_client *client ATTRIBUTE_UNUSED,
                                       virConnectPtr conn,
                                       remote_message_header *hdr ATTRIBUTE_UNUSED,
                                       remote_error *rerr,
                                       remote_storage_pool_set_autostart_args *args,
                                       void *ret ATTRIBUTE_UNUSED)
{
    virStoragePoolPtr pool;

    pool = get_nonnull_storage_pool (conn, args->pool);
    if (pool == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    if (virStoragePoolSetAutostart (pool, args->autostart) == -1) {
        virStoragePoolFree(pool);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }
    virStoragePoolFree(pool);
    return 0;
}

static int
remoteDispatchStoragePoolUndefine (struct qemud_server *server ATTRIBUTE_UNUSED,
                                   struct qemud_client *client ATTRIBUTE_UNUSED,
                                   virConnectPtr conn,
                                   remote_message_header *hdr ATTRIBUTE_UNUSED,
                                   remote_error *rerr,
                                   remote_storage_pool_undefine_args *args,
                                   void *ret ATTRIBUTE_UNUSED)
{
    virStoragePoolPtr pool;

    pool = get_nonnull_storage_pool (conn, args->pool);
    if (pool == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    if (virStoragePoolUndefine (pool) == -1) {
        virStoragePoolFree(pool);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }
    virStoragePoolFree(pool);
    return 0;
}

static int
remoteDispatchNumOfStoragePools (struct qemud_server *server ATTRIBUTE_UNUSED,
                                 struct qemud_client *client ATTRIBUTE_UNUSED,
                                 virConnectPtr conn,
                                 remote_message_header *hdr ATTRIBUTE_UNUSED,
                                 remote_error *rerr,
                                 void *args ATTRIBUTE_UNUSED,
                                 remote_num_of_storage_pools_ret *ret)
{

    ret->num = virConnectNumOfStoragePools (conn);
    if (ret->num == -1) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    return 0;
}

static int
remoteDispatchNumOfDefinedStoragePools (struct qemud_server *server ATTRIBUTE_UNUSED,
                                        struct qemud_client *client ATTRIBUTE_UNUSED,
                                        virConnectPtr conn,
                                        remote_message_header *hdr ATTRIBUTE_UNUSED,
                                        remote_error *rerr,
                                        void *args ATTRIBUTE_UNUSED,
                                        remote_num_of_defined_storage_pools_ret *ret)
{

    ret->num = virConnectNumOfDefinedStoragePools (conn);
    if (ret->num == -1) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    return 0;
}

static int
remoteDispatchStoragePoolListVolumes (struct qemud_server *server ATTRIBUTE_UNUSED,
                                      struct qemud_client *client ATTRIBUTE_UNUSED,
                                      virConnectPtr conn,
                                      remote_message_header *hdr ATTRIBUTE_UNUSED,
                                      remote_error *rerr,
                                      remote_storage_pool_list_volumes_args *args,
                                      remote_storage_pool_list_volumes_ret *ret)
{
    virStoragePoolPtr pool;

    if (args->maxnames > REMOTE_STORAGE_VOL_NAME_LIST_MAX) {
        remoteDispatchFormatError (rerr,
                                   "%s", _("maxnames > REMOTE_STORAGE_VOL_NAME_LIST_MAX"));
        return -1;
    }

    pool = get_nonnull_storage_pool (conn, args->pool);
    if (pool == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    /* Allocate return buffer. */
    if (VIR_ALLOC_N(ret->names.names_val, args->maxnames) < 0) {
        virStoragePoolFree(pool);
        remoteDispatchOOMError(rerr);
        return -1;
    }

    ret->names.names_len =
        virStoragePoolListVolumes (pool,
                                   ret->names.names_val, args->maxnames);
    virStoragePoolFree(pool);
    if (ret->names.names_len == -1) {
        VIR_FREE(ret->names.names_val);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    return 0;
}


static int
remoteDispatchStoragePoolNumOfVolumes (struct qemud_server *server ATTRIBUTE_UNUSED,
                                       struct qemud_client *client ATTRIBUTE_UNUSED,
                                       virConnectPtr conn,
                                       remote_message_header *hdr ATTRIBUTE_UNUSED,
                                       remote_error *rerr,
                                       remote_storage_pool_num_of_volumes_args *args,
                                       remote_storage_pool_num_of_volumes_ret *ret)
{
    virStoragePoolPtr pool;

    pool = get_nonnull_storage_pool (conn, args->pool);
    if (pool == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    ret->num = virStoragePoolNumOfVolumes (pool);
    virStoragePoolFree(pool);
    if (ret->num == -1) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    return 0;
}


/***************************************************************
 *     STORAGE VOL APIS
 ***************************************************************/



static int
remoteDispatchStorageVolCreateXml (struct qemud_server *server ATTRIBUTE_UNUSED,
                                   struct qemud_client *client ATTRIBUTE_UNUSED,
                                   virConnectPtr conn,
                                   remote_message_header *hdr ATTRIBUTE_UNUSED,
                                   remote_error *rerr,
                                   remote_storage_vol_create_xml_args *args,
                                   remote_storage_vol_create_xml_ret *ret)
{
    virStoragePoolPtr pool;
    virStorageVolPtr vol;

    pool = get_nonnull_storage_pool (conn, args->pool);
    if (pool == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    vol = virStorageVolCreateXML (pool, args->xml, args->flags);
    virStoragePoolFree(pool);
    if (vol == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    make_nonnull_storage_vol (&ret->vol, vol);
    virStorageVolFree(vol);
    return 0;
}

static int
remoteDispatchStorageVolCreateXmlFrom (struct qemud_server *server ATTRIBUTE_UNUSED,
                                       struct qemud_client *client ATTRIBUTE_UNUSED,
                                       virConnectPtr conn,
                                       remote_message_header *hdr ATTRIBUTE_UNUSED,
                                       remote_error *rerr,
                                       remote_storage_vol_create_xml_from_args *args,
                                       remote_storage_vol_create_xml_from_ret *ret)
{
    virStoragePoolPtr pool;
    virStorageVolPtr clonevol, newvol;

    pool = get_nonnull_storage_pool (conn, args->pool);
    if (pool == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    clonevol = get_nonnull_storage_vol (conn, args->clonevol);
    if (clonevol == NULL) {
        virStoragePoolFree(pool);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    newvol = virStorageVolCreateXMLFrom (pool, args->xml, clonevol,
                                         args->flags);
    virStorageVolFree(clonevol);
    virStoragePoolFree(pool);
    if (newvol == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    make_nonnull_storage_vol (&ret->vol, newvol);
    virStorageVolFree(newvol);
    return 0;
}

static int
remoteDispatchStorageVolDelete (struct qemud_server *server ATTRIBUTE_UNUSED,
                                struct qemud_client *client ATTRIBUTE_UNUSED,
                                virConnectPtr conn,
                                remote_message_header *hdr ATTRIBUTE_UNUSED,
                                remote_error *rerr,
                                remote_storage_vol_delete_args *args,
                                void *ret ATTRIBUTE_UNUSED)
{
    virStorageVolPtr vol;

    vol = get_nonnull_storage_vol (conn, args->vol);
    if (vol == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    if (virStorageVolDelete (vol, args->flags) == -1) {
        virStorageVolFree(vol);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }
    virStorageVolFree(vol);
    return 0;
}

static int
remoteDispatchStorageVolGetInfo (struct qemud_server *server ATTRIBUTE_UNUSED,
                                 struct qemud_client *client ATTRIBUTE_UNUSED,
                                 virConnectPtr conn,
                                 remote_message_header *hdr ATTRIBUTE_UNUSED,
                                 remote_error *rerr,
                                 remote_storage_vol_get_info_args *args,
                                 remote_storage_vol_get_info_ret *ret)
{
    virStorageVolPtr vol;
    virStorageVolInfo info;

    vol = get_nonnull_storage_vol (conn, args->vol);
    if (vol == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    if (virStorageVolGetInfo (vol, &info) == -1) {
        virStorageVolFree(vol);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    ret->type = info.type;
    ret->capacity = info.capacity;
    ret->allocation = info.allocation;

    virStorageVolFree(vol);

    return 0;
}

static int
remoteDispatchStorageVolDumpXml (struct qemud_server *server ATTRIBUTE_UNUSED,
                                 struct qemud_client *client ATTRIBUTE_UNUSED,
                                 virConnectPtr conn,
                                 remote_message_header *hdr ATTRIBUTE_UNUSED,
                                 remote_error *rerr,
                                 remote_storage_vol_dump_xml_args *args,
                                 remote_storage_vol_dump_xml_ret *ret)
{
    virStorageVolPtr vol;

    vol = get_nonnull_storage_vol (conn, args->vol);
    if (vol == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    /* remoteDispatchClientRequest will free this. */
    ret->xml = virStorageVolGetXMLDesc (vol, args->flags);
    if (!ret->xml) {
        virStorageVolFree(vol);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }
    virStorageVolFree(vol);
    return 0;
}


static int
remoteDispatchStorageVolGetPath (struct qemud_server *server ATTRIBUTE_UNUSED,
                                 struct qemud_client *client ATTRIBUTE_UNUSED,
                                 virConnectPtr conn,
                                 remote_message_header *hdr ATTRIBUTE_UNUSED,
                                 remote_error *rerr,
                                 remote_storage_vol_get_path_args *args,
                                 remote_storage_vol_get_path_ret *ret)
{
    virStorageVolPtr vol;

    vol = get_nonnull_storage_vol (conn, args->vol);
    if (vol == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    /* remoteDispatchClientRequest will free this. */
    ret->name = virStorageVolGetPath (vol);
    if (!ret->name) {
        virStorageVolFree(vol);
        remoteDispatchConnError(rerr, conn);
        return -1;
    }
    virStorageVolFree(vol);
    return 0;
}


static int
remoteDispatchStorageVolLookupByName (struct qemud_server *server ATTRIBUTE_UNUSED,
                                      struct qemud_client *client ATTRIBUTE_UNUSED,
                                      virConnectPtr conn,
                                      remote_message_header *hdr ATTRIBUTE_UNUSED,
                                      remote_error *rerr,
                                      remote_storage_vol_lookup_by_name_args *args,
                                      remote_storage_vol_lookup_by_name_ret *ret)
{
    virStoragePoolPtr pool;
    virStorageVolPtr vol;

    pool = get_nonnull_storage_pool (conn, args->pool);
    if (pool == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    vol = virStorageVolLookupByName (pool, args->name);
    virStoragePoolFree(pool);
    if (vol == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    make_nonnull_storage_vol (&ret->vol, vol);
    virStorageVolFree(vol);
    return 0;
}

static int
remoteDispatchStorageVolLookupByKey (struct qemud_server *server ATTRIBUTE_UNUSED,
                                     struct qemud_client *client ATTRIBUTE_UNUSED,
                                     virConnectPtr conn,
                                     remote_message_header *hdr ATTRIBUTE_UNUSED,
                                     remote_error *rerr,
                                     remote_storage_vol_lookup_by_key_args *args,
                                     remote_storage_vol_lookup_by_key_ret *ret)
{
    virStorageVolPtr vol;

    vol = virStorageVolLookupByKey (conn, args->key);
    if (vol == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    make_nonnull_storage_vol (&ret->vol, vol);
    virStorageVolFree(vol);
    return 0;
}


static int
remoteDispatchStorageVolLookupByPath (struct qemud_server *server ATTRIBUTE_UNUSED,
                                      struct qemud_client *client ATTRIBUTE_UNUSED,
                                      virConnectPtr conn,
                                      remote_message_header *hdr ATTRIBUTE_UNUSED,
                                      remote_error *rerr,
                                      remote_storage_vol_lookup_by_path_args *args,
                                      remote_storage_vol_lookup_by_path_ret *ret)
{
    virStorageVolPtr vol;

    vol = virStorageVolLookupByPath (conn, args->path);
    if (vol == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    make_nonnull_storage_vol (&ret->vol, vol);
    virStorageVolFree(vol);
    return 0;
}


/***************************************************************
 *     NODE INFO APIS
 **************************************************************/

static int
remoteDispatchNodeNumOfDevices (struct qemud_server *server ATTRIBUTE_UNUSED,
                                struct qemud_client *client ATTRIBUTE_UNUSED,
                                virConnectPtr conn,
                                remote_message_header *hdr ATTRIBUTE_UNUSED,
                                remote_error *rerr,
                                remote_node_num_of_devices_args *args,
                                remote_node_num_of_devices_ret *ret)
{
    CHECK_CONN(client);

    ret->num = virNodeNumOfDevices (conn,
                                    args->cap ? *args->cap : NULL,
                                    args->flags);
    if (ret->num == -1) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    return 0;
}


static int
remoteDispatchNodeListDevices (struct qemud_server *server ATTRIBUTE_UNUSED,
                               struct qemud_client *client ATTRIBUTE_UNUSED,
                               virConnectPtr conn,
                               remote_message_header *hdr ATTRIBUTE_UNUSED,
                               remote_error *rerr,
                               remote_node_list_devices_args *args,
                               remote_node_list_devices_ret *ret)
{
    CHECK_CONN(client);

    if (args->maxnames > REMOTE_NODE_DEVICE_NAME_LIST_MAX) {
        remoteDispatchFormatError(rerr,
                                  "%s", _("maxnames > REMOTE_NODE_DEVICE_NAME_LIST_MAX"));
        return -1;
    }

    /* Allocate return buffer. */
    if (VIR_ALLOC_N(ret->names.names_val, args->maxnames) < 0) {
        remoteDispatchOOMError(rerr);
        return -1;
    }

    ret->names.names_len =
        virNodeListDevices (conn,
                            args->cap ? *args->cap : NULL,
                            ret->names.names_val, args->maxnames, args->flags);
    if (ret->names.names_len == -1) {
        remoteDispatchConnError(rerr, conn);
        VIR_FREE(ret->names.names_val);
        return -1;
    }

    return 0;
}


static int
remoteDispatchNodeDeviceLookupByName (struct qemud_server *server ATTRIBUTE_UNUSED,
                                      struct qemud_client *client ATTRIBUTE_UNUSED,
                                      virConnectPtr conn,
                                      remote_message_header *hdr ATTRIBUTE_UNUSED,
                                      remote_error *rerr,
                                      remote_node_device_lookup_by_name_args *args,
                                      remote_node_device_lookup_by_name_ret *ret)
{
    virNodeDevicePtr dev;

    CHECK_CONN(client);

    dev = virNodeDeviceLookupByName (conn, args->name);
    if (dev == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    make_nonnull_node_device (&ret->dev, dev);
    virNodeDeviceFree(dev);
    return 0;
}


static int
remoteDispatchNodeDeviceDumpXml (struct qemud_server *server ATTRIBUTE_UNUSED,
                                 struct qemud_client *client ATTRIBUTE_UNUSED,
                                 virConnectPtr conn,
                                 remote_message_header *hdr ATTRIBUTE_UNUSED,
                                 remote_error *rerr,
                                 remote_node_device_dump_xml_args *args,
                                 remote_node_device_dump_xml_ret *ret)
{
    virNodeDevicePtr dev;
    CHECK_CONN(client);

    dev = virNodeDeviceLookupByName(conn, args->name);
    if (dev == NULL) {
        remoteDispatchFormatError(rerr, "%s", _("node_device not found"));
        return -1;
    }

    /* remoteDispatchClientRequest will free this. */
    ret->xml = virNodeDeviceGetXMLDesc (dev, args->flags);
    if (!ret->xml) {
        remoteDispatchConnError(rerr, conn);
        virNodeDeviceFree(dev);
        return -1;
    }
    virNodeDeviceFree(dev);
    return 0;
}


static int
remoteDispatchNodeDeviceGetParent (struct qemud_server *server ATTRIBUTE_UNUSED,
                                   struct qemud_client *client ATTRIBUTE_UNUSED,
                                   virConnectPtr conn,
                                   remote_message_header *hdr ATTRIBUTE_UNUSED,
                                   remote_error *rerr,
                                   remote_node_device_get_parent_args *args,
                                   remote_node_device_get_parent_ret *ret)
{
    virNodeDevicePtr dev;
    const char *parent;
    CHECK_CONN(client);

    dev = virNodeDeviceLookupByName(conn, args->name);
    if (dev == NULL) {
        remoteDispatchFormatError(rerr, "%s", _("node_device not found"));
        return -1;
    }

    parent = virNodeDeviceGetParent(dev);

    if (parent == NULL) {
        ret->parent = NULL;
    } else {
        /* remoteDispatchClientRequest will free this. */
        char **parent_p;
        if (VIR_ALLOC(parent_p) < 0) {
            remoteDispatchOOMError(rerr);
            return -1;
        }
        *parent_p = strdup(parent);
        if (*parent_p == NULL) {
            remoteDispatchOOMError(rerr);
            return -1;
        }
        ret->parent = parent_p;
    }

    virNodeDeviceFree(dev);
    return 0;
}


static int
remoteDispatchNodeDeviceNumOfCaps (struct qemud_server *server ATTRIBUTE_UNUSED,
                                   struct qemud_client *client ATTRIBUTE_UNUSED,
                                   virConnectPtr conn,
                                   remote_message_header *hdr ATTRIBUTE_UNUSED,
                                   remote_error *rerr,
                                   remote_node_device_num_of_caps_args *args,
                                   remote_node_device_num_of_caps_ret *ret)
{
    virNodeDevicePtr dev;
    CHECK_CONN(client);

    dev = virNodeDeviceLookupByName(conn, args->name);
    if (dev == NULL) {
        remoteDispatchFormatError(rerr, "%s", _("node_device not found"));
        return -1;
    }

    ret->num = virNodeDeviceNumOfCaps(dev);
    if (ret->num < 0) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    virNodeDeviceFree(dev);
    return 0;
}


static int
remoteDispatchNodeDeviceListCaps (struct qemud_server *server ATTRIBUTE_UNUSED,
                                  struct qemud_client *client ATTRIBUTE_UNUSED,
                                  virConnectPtr conn,
                                  remote_message_header *hdr ATTRIBUTE_UNUSED,
                                  remote_error *rerr,
                                  remote_node_device_list_caps_args *args,
                                  remote_node_device_list_caps_ret *ret)
{
    virNodeDevicePtr dev;
    CHECK_CONN(client);

    dev = virNodeDeviceLookupByName(conn, args->name);
    if (dev == NULL) {
        remoteDispatchFormatError(rerr, "%s", _("node_device not found"));
        return -1;
    }

    if (args->maxnames > REMOTE_NODE_DEVICE_NAME_LIST_MAX) {
        remoteDispatchFormatError(rerr,
                                  "%s", _("maxnames > REMOTE_NODE_DEVICE_NAME_LIST_MAX"));
        return -1;
    }

    /* Allocate return buffer. */
    if (VIR_ALLOC_N(ret->names.names_val, args->maxnames) < 0) {
        remoteDispatchOOMError(rerr);
        return -1;
    }

    ret->names.names_len =
        virNodeDeviceListCaps (dev, ret->names.names_val,
                               args->maxnames);
    if (ret->names.names_len == -1) {
        remoteDispatchConnError(rerr, conn);
        VIR_FREE(ret->names.names_val);
        return -1;
    }

    return 0;
}


static int
remoteDispatchNodeDeviceDettach (struct qemud_server *server ATTRIBUTE_UNUSED,
                                 struct qemud_client *client ATTRIBUTE_UNUSED,
                                 virConnectPtr conn,
                                 remote_message_header *hdr ATTRIBUTE_UNUSED,
                                 remote_error *rerr,
                                 remote_node_device_dettach_args *args,
                                 void *ret ATTRIBUTE_UNUSED)
{
    virNodeDevicePtr dev;
    CHECK_CONN(client);

    dev = virNodeDeviceLookupByName(conn, args->name);
    if (dev == NULL) {
        remoteDispatchFormatError(rerr, "%s", _("node_device not found"));
        return -1;
    }

    if (virNodeDeviceDettach(dev) == -1) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    return 0;
}


static int
remoteDispatchNodeDeviceReAttach (struct qemud_server *server ATTRIBUTE_UNUSED,
                                  struct qemud_client *client ATTRIBUTE_UNUSED,
                                  virConnectPtr conn,
                                  remote_message_header *hdr ATTRIBUTE_UNUSED,
                                  remote_error *rerr,
                                  remote_node_device_re_attach_args *args,
                                  void *ret ATTRIBUTE_UNUSED)
{
    virNodeDevicePtr dev;
    CHECK_CONN(client);

    dev = virNodeDeviceLookupByName(conn, args->name);
    if (dev == NULL) {
        remoteDispatchFormatError(rerr, "%s", _("node_device not found"));
        return -1;
    }

    if (virNodeDeviceReAttach(dev) == -1) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    return 0;
}


static int
remoteDispatchNodeDeviceReset (struct qemud_server *server ATTRIBUTE_UNUSED,
                               struct qemud_client *client ATTRIBUTE_UNUSED,
                               virConnectPtr conn,
                               remote_message_header *hdr ATTRIBUTE_UNUSED,
                               remote_error *rerr,
                               remote_node_device_reset_args *args,
                               void *ret ATTRIBUTE_UNUSED)
{
    virNodeDevicePtr dev;
    CHECK_CONN(client);

    dev = virNodeDeviceLookupByName(conn, args->name);
    if (dev == NULL) {
        remoteDispatchFormatError(rerr, "%s", _("node_device not found"));
        return -1;
    }

    if (virNodeDeviceReset(dev) == -1) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    return 0;
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
    virNodeDevicePtr dev;

    dev = virNodeDeviceCreateXML (conn, args->xml_desc, args->flags);
    if (dev == NULL) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    make_nonnull_node_device (&ret->dev, dev);
    virNodeDeviceFree(dev);

    return 0;
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
    virNodeDevicePtr dev;

    dev = virNodeDeviceLookupByName(conn, args->name);
    if (dev == NULL) {
        remoteDispatchFormatError(rerr, "%s", _("node_device not found"));
        return -1;
    }

    if (virNodeDeviceDestroy(dev) == -1) {
        remoteDispatchConnError(rerr, conn);
        return -1;
    }

    return 0;
}



/***************************
 * Register / deregister events
 ***************************/
static int
remoteDispatchDomainEventsRegister (struct qemud_server *server ATTRIBUTE_UNUSED,
                                    struct qemud_client *client ATTRIBUTE_UNUSED,
                                    virConnectPtr conn,
                                    remote_message_header *hdr ATTRIBUTE_UNUSED,
                                    remote_error *rerr ATTRIBUTE_UNUSED,
                                    void *args ATTRIBUTE_UNUSED,
                                    remote_domain_events_register_ret *ret ATTRIBUTE_UNUSED)
{
    CHECK_CONN(client);

    /* Register event delivery callback */
    REMOTE_DEBUG("%s","Registering to relay remote events");
    virConnectDomainEventRegister(conn, remoteRelayDomainEvent, client, NULL);

    if(ret)
        ret->cb_registered = 1;
    return 0;
}

static int
remoteDispatchDomainEventsDeregister (struct qemud_server *server ATTRIBUTE_UNUSED,
                                      struct qemud_client *client ATTRIBUTE_UNUSED,
                                      virConnectPtr conn,
                                      remote_message_header *hdr ATTRIBUTE_UNUSED,
                                      remote_error *rerr ATTRIBUTE_UNUSED,
                                      void *args ATTRIBUTE_UNUSED,
                                      remote_domain_events_deregister_ret *ret ATTRIBUTE_UNUSED)
{
    CHECK_CONN(client);

    /* Deregister event delivery callback */
    REMOTE_DEBUG("%s","Deregistering to relay remote events");
    virConnectDomainEventDeregister(conn, remoteRelayDomainEvent);

    if(ret)
        ret->cb_registered = 0;
    return 0;
}

static void
remoteDispatchDomainEventSend (struct qemud_client *client,
                               remote_domain_event_msg *data)
{
    struct qemud_client_message *msg = NULL;
    XDR xdr;
    unsigned int len;

    if (VIR_ALLOC(msg) < 0)
        return;

    msg->hdr.prog = REMOTE_PROGRAM;
    msg->hdr.vers = REMOTE_PROTOCOL_VERSION;
    msg->hdr.proc = REMOTE_PROC_DOMAIN_EVENT;
    msg->hdr.type = REMOTE_MESSAGE;
    msg->hdr.serial = 1;
    msg->hdr.status = REMOTE_OK;

    if (remoteEncodeClientMessageHeader(msg) < 0)
        goto error;

    /* Serialise the return header and event. */
    xdrmem_create (&xdr,
                   msg->buffer,
                   msg->bufferLength,
                   XDR_ENCODE);

    /* Skip over the header we just wrote */
    if (xdr_setpos (&xdr, msg->bufferOffset) == 0)
        goto xdr_error;

    if (!xdr_remote_domain_event_msg(&xdr, data))
        goto xdr_error;

    /* Update length word to include payload*/
    len = msg->bufferOffset = xdr_getpos (&xdr);
    if (xdr_setpos (&xdr, 0) == 0)
        goto xdr_error;

    if (!xdr_u_int (&xdr, &len))
        goto xdr_error;

    /* Send it. */
    msg->async = 1;
    msg->bufferLength = len;
    msg->bufferOffset = 0;
    qemudClientMessageQueuePush(&client->tx, msg);
    qemudUpdateClientEvent(client);

    xdr_destroy (&xdr);
    return;

xdr_error:
    xdr_destroy(&xdr);
error:
    VIR_FREE(msg);
}

static int
remoteDispatchNumOfSecrets (struct qemud_server *server ATTRIBUTE_UNUSED,
                            struct qemud_client *client ATTRIBUTE_UNUSED,
                            virConnectPtr conn,
                            remote_message_header *hdr ATTRIBUTE_UNUSED,
                            remote_error *err,
                            void *args ATTRIBUTE_UNUSED,
                            remote_num_of_secrets_ret *ret)
{
    ret->num = virConnectNumOfSecrets (conn);
    if (ret->num == -1) {
        remoteDispatchConnError (err, conn);
        return -1;
    }

    return 0;
}

static int
remoteDispatchListSecrets (struct qemud_server *server ATTRIBUTE_UNUSED,
                           struct qemud_client *client ATTRIBUTE_UNUSED,
                           virConnectPtr conn,
                           remote_message_header *hdr ATTRIBUTE_UNUSED,
                           remote_error *err,
                           remote_list_secrets_args *args,
                           remote_list_secrets_ret *ret)
{
    if (args->maxuuids > REMOTE_SECRET_UUID_LIST_MAX) {
        remoteDispatchFormatError (err, "%s",
                                   _("maxuuids > REMOTE_SECRET_UUID_LIST_MAX"));
        return -1;
    }

    if (VIR_ALLOC_N (ret->uuids.uuids_val, args->maxuuids) < 0) {
        remoteDispatchOOMError (err);
        return -1;
    }

    ret->uuids.uuids_len = virConnectListSecrets (conn, ret->uuids.uuids_val,
                                                  args->maxuuids);
    if (ret->uuids.uuids_len == -1) {
        VIR_FREE (ret->uuids.uuids_val);
        remoteDispatchConnError (err, conn);
        return -1;
    }

    return 0;
}

static int
remoteDispatchSecretDefineXml (struct qemud_server *server ATTRIBUTE_UNUSED,
                               struct qemud_client *client ATTRIBUTE_UNUSED,
                               virConnectPtr conn,
                               remote_message_header *hdr ATTRIBUTE_UNUSED,
                               remote_error *err,
                               remote_secret_define_xml_args *args,
                               remote_secret_define_xml_ret *ret)
{
    virSecretPtr secret;

    secret = virSecretDefineXML (conn, args->xml, args->flags);
    if (secret == NULL) {
        remoteDispatchConnError (err, conn);
        return -1;
    }

    make_nonnull_secret (&ret->secret, secret);
    virSecretFree (secret);
    return 0;
}

static int
remoteDispatchSecretGetValue (struct qemud_server *server ATTRIBUTE_UNUSED,
                              struct qemud_client *client ATTRIBUTE_UNUSED,
                              virConnectPtr conn,
                              remote_message_header *hdr ATTRIBUTE_UNUSED,
                              remote_error *err,
                              remote_secret_get_value_args *args,
                              remote_secret_get_value_ret *ret)
{
    virSecretPtr secret;
    size_t value_size;
    unsigned char *value;

    secret = get_nonnull_secret (conn, args->secret);
    if (secret == NULL) {
        remoteDispatchConnError (err, conn);
        return -1;
    }

    value = virSecretGetValue (secret, &value_size, args->flags);
    if (value == NULL) {
        remoteDispatchConnError (err, conn);
        virSecretFree(secret);
        return -1;
    }

    ret->value.value_len = value_size;
    ret->value.value_val = (char *)value;
    virSecretFree(secret);
    return 0;
}

static int
remoteDispatchSecretGetXmlDesc (struct qemud_server *server ATTRIBUTE_UNUSED,
                                struct qemud_client *client ATTRIBUTE_UNUSED,
                                virConnectPtr conn,
                                remote_message_header *hdr ATTRIBUTE_UNUSED,
                                remote_error *err,
                                remote_secret_get_xml_desc_args *args,
                                remote_secret_get_xml_desc_ret *ret)
{
    virSecretPtr secret;

    secret = get_nonnull_secret (conn, args->secret);
    if (secret == NULL) {
        remoteDispatchConnError (err, conn);
        return -1;
    }
    ret->xml = virSecretGetXMLDesc (secret, args->flags);
    if (ret->xml == NULL) {
        remoteDispatchConnError (err, conn);
        virSecretFree(secret);
        return -1;
    }
    virSecretFree(secret);
    return 0;
}

static int
remoteDispatchSecretLookupByUuid (struct qemud_server *server ATTRIBUTE_UNUSED,
                                  struct qemud_client *client ATTRIBUTE_UNUSED,
                                  virConnectPtr conn,
                                  remote_message_header *hdr ATTRIBUTE_UNUSED,
                                  remote_error *err,
                                  remote_secret_lookup_by_uuid_args *args,
                                  remote_secret_lookup_by_uuid_ret *ret)
{
    virSecretPtr secret;

    secret = virSecretLookupByUUID (conn, (unsigned char *)args->uuid);
    if (secret == NULL) {
        remoteDispatchConnError (err, conn);
        return -1;
    }

    make_nonnull_secret (&ret->secret, secret);
    virSecretFree (secret);
    return 0;
}

static int
remoteDispatchSecretSetValue (struct qemud_server *server ATTRIBUTE_UNUSED,
                              struct qemud_client *client ATTRIBUTE_UNUSED,
                              virConnectPtr conn,
                              remote_message_header *hdr ATTRIBUTE_UNUSED,
                              remote_error *err,
                              remote_secret_set_value_args *args,
                              void *ret ATTRIBUTE_UNUSED)
{
    virSecretPtr secret;

    secret = get_nonnull_secret (conn, args->secret);
    if (secret == NULL) {
        remoteDispatchConnError (err, conn);
        return -1;
    }
    if (virSecretSetValue (secret, (const unsigned char *)args->value.value_val,
                           args->value.value_len, args->flags) < 0) {
        remoteDispatchConnError (err, conn);
        virSecretFree(secret);
        return -1;
    }

    virSecretFree(secret);
    return 0;
}

static int
remoteDispatchSecretUndefine (struct qemud_server *server ATTRIBUTE_UNUSED,
                              struct qemud_client *client ATTRIBUTE_UNUSED,
                              virConnectPtr conn,
                              remote_message_header *hdr ATTRIBUTE_UNUSED,
                              remote_error *err,
                              remote_secret_undefine_args *args,
                              void *ret ATTRIBUTE_UNUSED)
{
    virSecretPtr secret;

    secret = get_nonnull_secret (conn, args->secret);
    if (secret == NULL) {
        remoteDispatchConnError (err, conn);
        return -1;
    }
    if (virSecretUndefine (secret) < 0) {
        remoteDispatchConnError (err, conn);
        virSecretFree(secret);
        return -1;
    }

    virSecretFree(secret);
    return 0;
}

static int
remoteDispatchSecretLookupByUsage (struct qemud_server *server ATTRIBUTE_UNUSED,
                                   struct qemud_client *client ATTRIBUTE_UNUSED,
                                   virConnectPtr conn,
                                   remote_message_header *hdr ATTRIBUTE_UNUSED,
                                   remote_error *err,
                                   remote_secret_lookup_by_usage_args *args,
                                   remote_secret_lookup_by_usage_ret *ret)
{
    virSecretPtr secret;

    secret = virSecretLookupByUsage (conn, args->usageType, args->usageID);
    if (secret == NULL) {
        remoteDispatchConnError (err, conn);
        return -1;
    }

    make_nonnull_secret (&ret->secret, secret);
    virSecretFree (secret);
    return 0;
}


static int remoteDispatchDomainIsActive(struct qemud_server *server ATTRIBUTE_UNUSED,
                                        struct qemud_client *client ATTRIBUTE_UNUSED,
                                        virConnectPtr conn,
                                        remote_message_header *hdr ATTRIBUTE_UNUSED,
                                        remote_error *err,
                                        remote_domain_is_active_args *args,
                                        remote_domain_is_active_ret *ret)
{
    virDomainPtr domain;

    domain = get_nonnull_domain(conn, args->dom);
    if (domain == NULL) {
        remoteDispatchConnError(err, conn);
        return -1;
    }

    ret->active = virDomainIsActive(domain);

    if (ret->active < 0) {
        remoteDispatchConnError(err, conn);
        return -1;
    }

    return 0;
}

static int remoteDispatchDomainIsPersistent(struct qemud_server *server ATTRIBUTE_UNUSED,
                                            struct qemud_client *client ATTRIBUTE_UNUSED,
                                            virConnectPtr conn,
                                            remote_message_header *hdr ATTRIBUTE_UNUSED,
                                            remote_error *err,
                                            remote_domain_is_persistent_args *args,
                                            remote_domain_is_persistent_ret *ret)
{
    virDomainPtr domain;

    domain = get_nonnull_domain(conn, args->dom);
    if (domain == NULL) {
        remoteDispatchConnError(err, conn);
        return -1;
    }

    ret->persistent = virDomainIsPersistent(domain);

    if (ret->persistent < 0) {
        remoteDispatchConnError(err, conn);
        return -1;
    }

    return 0;
}

static int remoteDispatchInterfaceIsActive(struct qemud_server *server ATTRIBUTE_UNUSED,
                                           struct qemud_client *client ATTRIBUTE_UNUSED,
                                           virConnectPtr conn,
                                           remote_message_header *hdr ATTRIBUTE_UNUSED,
                                           remote_error *err,
                                           remote_interface_is_active_args *args,
                                           remote_interface_is_active_ret *ret)
{
    virInterfacePtr iface;

    iface = get_nonnull_interface(conn, args->iface);
    if (iface == NULL) {
        remoteDispatchConnError(err, conn);
        return -1;
    }

    ret->active = virInterfaceIsActive(iface);

    if (ret->active < 0) {
        remoteDispatchConnError(err, conn);
        return -1;
    }

    return 0;
}

static int remoteDispatchNetworkIsActive(struct qemud_server *server ATTRIBUTE_UNUSED,
                                         struct qemud_client *client ATTRIBUTE_UNUSED,
                                         virConnectPtr conn,
                                         remote_message_header *hdr ATTRIBUTE_UNUSED,
                                         remote_error *err,
                                         remote_network_is_active_args *args,
                                         remote_network_is_active_ret *ret)
{
    virNetworkPtr network;

    network = get_nonnull_network(conn, args->net);
    if (network == NULL) {
        remoteDispatchConnError(err, conn);
        return -1;
    }

    ret->active = virNetworkIsActive(network);

    if (ret->active < 0) {
        remoteDispatchConnError(err, conn);
        return -1;
    }

    return 0;
}

static int remoteDispatchNetworkIsPersistent(struct qemud_server *server ATTRIBUTE_UNUSED,
                                             struct qemud_client *client ATTRIBUTE_UNUSED,
                                             virConnectPtr conn,
                                             remote_message_header *hdr ATTRIBUTE_UNUSED,
                                             remote_error *err,
                                             remote_network_is_persistent_args *args,
                                             remote_network_is_persistent_ret *ret)
{
    virNetworkPtr network;

    network = get_nonnull_network(conn, args->net);
    if (network == NULL) {
        remoteDispatchConnError(err, conn);
        return -1;
    }

    ret->persistent = virNetworkIsPersistent(network);

    if (ret->persistent < 0) {
        remoteDispatchConnError(err, conn);
        return -1;
    }

    return 0;
}

static int remoteDispatchStoragePoolIsActive(struct qemud_server *server ATTRIBUTE_UNUSED,
                                             struct qemud_client *client ATTRIBUTE_UNUSED,
                                             virConnectPtr conn,
                                             remote_message_header *hdr ATTRIBUTE_UNUSED,
                                             remote_error *err,
                                             remote_storage_pool_is_active_args *args,
                                             remote_storage_pool_is_active_ret *ret)
{
    virStoragePoolPtr pool;

    pool = get_nonnull_storage_pool(conn, args->pool);
    if (pool == NULL) {
        remoteDispatchConnError(err, conn);
        return -1;
    }

    ret->active = virStoragePoolIsActive(pool);

    if (ret->active < 0) {
        remoteDispatchConnError(err, conn);
        return -1;
    }

    return 0;
}

static int remoteDispatchStoragePoolIsPersistent(struct qemud_server *server ATTRIBUTE_UNUSED,
                                                 struct qemud_client *client ATTRIBUTE_UNUSED,
                                                 virConnectPtr conn,
                                                 remote_message_header *hdr ATTRIBUTE_UNUSED,
                                                 remote_error *err,
                                                 remote_storage_pool_is_persistent_args *args,
                                                 remote_storage_pool_is_persistent_ret *ret)
{
    virStoragePoolPtr pool;

    pool = get_nonnull_storage_pool(conn, args->pool);
    if (pool == NULL) {
        remoteDispatchConnError(err, conn);
        return -1;
    }

    ret->persistent = virStoragePoolIsPersistent(pool);

    if (ret->persistent < 0) {
        remoteDispatchConnError(err, conn);
        return -1;
    }

    return 0;
}


static int remoteDispatchIsSecure(struct qemud_server *server ATTRIBUTE_UNUSED,
                                  struct qemud_client *client ATTRIBUTE_UNUSED,
                                  virConnectPtr conn,
                                  remote_message_header *hdr ATTRIBUTE_UNUSED,
                                  remote_error *err,
                                  void *args ATTRIBUTE_UNUSED,
                                  remote_is_secure_ret *ret)
{
    ret->secure = virConnectIsSecure(conn);

    if (ret->secure < 0) {
        remoteDispatchConnError(err, conn);
        return -1;
    }

    return 0;
}


static int
remoteDispatchCpuCompare(struct qemud_server *server ATTRIBUTE_UNUSED,
                         struct qemud_client *client ATTRIBUTE_UNUSED,
                         virConnectPtr conn,
                         remote_message_header *hdr ATTRIBUTE_UNUSED,
                         remote_error *err,
                         remote_cpu_compare_args *args,
                         remote_cpu_compare_ret *ret)
{
    int result;

    result = virConnectCompareCPU(conn, args->xml, args->flags);
    if (result == VIR_CPU_COMPARE_ERROR) {
        remoteDispatchConnError(err, conn);
        return -1;
    }

    ret->result = result;
    return 0;
}


/*----- Helpers. -----*/

/* get_nonnull_domain and get_nonnull_network turn an on-wire
 * (name, uuid) pair into virDomainPtr or virNetworkPtr object.
 * virDomainPtr or virNetworkPtr cannot be NULL.
 *
 * NB. If these return NULL then the caller must return an error.
 */
static virDomainPtr
get_nonnull_domain (virConnectPtr conn, remote_nonnull_domain domain)
{
    virDomainPtr dom;
    dom = virGetDomain (conn, domain.name, BAD_CAST domain.uuid);
    /* Should we believe the domain.id sent by the client?  Maybe
     * this should be a check rather than an assignment? XXX
     */
    if (dom) dom->id = domain.id;
    return dom;
}

static virNetworkPtr
get_nonnull_network (virConnectPtr conn, remote_nonnull_network network)
{
    return virGetNetwork (conn, network.name, BAD_CAST network.uuid);
}

static virInterfacePtr
get_nonnull_interface (virConnectPtr conn, remote_nonnull_interface iface)
{
    return virGetInterface (conn, iface.name, iface.mac);
}

static virStoragePoolPtr
get_nonnull_storage_pool (virConnectPtr conn, remote_nonnull_storage_pool pool)
{
    return virGetStoragePool (conn, pool.name, BAD_CAST pool.uuid);
}

static virStorageVolPtr
get_nonnull_storage_vol (virConnectPtr conn, remote_nonnull_storage_vol vol)
{
    virStorageVolPtr ret;
    ret = virGetStorageVol (conn, vol.pool, vol.name, vol.key);
    return ret;
}

static virSecretPtr
get_nonnull_secret (virConnectPtr conn, remote_nonnull_secret secret)
{
    return virGetSecret (conn, BAD_CAST secret.uuid, secret.usageType, secret.usageID);
}

/* Make remote_nonnull_domain and remote_nonnull_network. */
static void
make_nonnull_domain (remote_nonnull_domain *dom_dst, virDomainPtr dom_src)
{
    dom_dst->id = dom_src->id;
    dom_dst->name = strdup (dom_src->name);
    memcpy (dom_dst->uuid, dom_src->uuid, VIR_UUID_BUFLEN);
}

static void
make_nonnull_network (remote_nonnull_network *net_dst, virNetworkPtr net_src)
{
    net_dst->name = strdup (net_src->name);
    memcpy (net_dst->uuid, net_src->uuid, VIR_UUID_BUFLEN);
}

static void
make_nonnull_interface (remote_nonnull_interface *interface_dst,
                        virInterfacePtr interface_src)
{
    interface_dst->name = strdup (interface_src->name);
    interface_dst->mac = strdup (interface_src->mac);
}

static void
make_nonnull_storage_pool (remote_nonnull_storage_pool *pool_dst, virStoragePoolPtr pool_src)
{
    pool_dst->name = strdup (pool_src->name);
    memcpy (pool_dst->uuid, pool_src->uuid, VIR_UUID_BUFLEN);
}

static void
make_nonnull_storage_vol (remote_nonnull_storage_vol *vol_dst, virStorageVolPtr vol_src)
{
    vol_dst->pool = strdup (vol_src->pool);
    vol_dst->name = strdup (vol_src->name);
    vol_dst->key = strdup (vol_src->key);
}

static void
make_nonnull_node_device (remote_nonnull_node_device *dev_dst, virNodeDevicePtr dev_src)
{
    dev_dst->name = strdup(dev_src->name);
}

static void
make_nonnull_secret (remote_nonnull_secret *secret_dst, virSecretPtr secret_src)
{
    memcpy (secret_dst->uuid, secret_src->uuid, VIR_UUID_BUFLEN);
    secret_dst->usageType = secret_src->usageType;
    secret_dst->usageID = strdup (secret_src->usageID);
}
