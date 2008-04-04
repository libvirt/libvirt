/*
 * remote.c: code handling remote requests (from remote_internal.c)
 *
 * Copyright (C) 2007, 2008 Red Hat, Inc.
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
#include <paths.h>
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
#include <ctype.h>
#include <fnmatch.h>

#ifdef HAVE_POLKIT
#include <polkit/polkit.h>
#include <polkit-dbus/polkit-dbus.h>
#endif

#include "libvirt/virterror.h"

#include "internal.h"
#include "../src/internal.h"

#define DEBUG 0

#define REMOTE_DEBUG(fmt,...) qemudDebug("REMOTE: " fmt, __VA_ARGS__)

static void remoteDispatchError (struct qemud_client *client,
                                 remote_message_header *req,
                                 const char *fmt, ...)
    ATTRIBUTE_FORMAT(printf, 3, 4);
static virDomainPtr get_nonnull_domain (virConnectPtr conn, remote_nonnull_domain domain);
static virNetworkPtr get_nonnull_network (virConnectPtr conn, remote_nonnull_network network);
static virStoragePoolPtr get_nonnull_storage_pool (virConnectPtr conn, remote_nonnull_storage_pool pool);
static virStorageVolPtr get_nonnull_storage_vol (virConnectPtr conn, remote_nonnull_storage_vol vol);
static void make_nonnull_domain (remote_nonnull_domain *dom_dst, virDomainPtr dom_src);
static void make_nonnull_network (remote_nonnull_network *net_dst, virNetworkPtr net_src);
static void make_nonnull_storage_pool (remote_nonnull_storage_pool *pool_dst, virStoragePoolPtr pool_src);
static void make_nonnull_storage_vol (remote_nonnull_storage_vol *vol_dst, virStorageVolPtr vol_src);

#include "remote_dispatch_prototypes.h"

typedef int (*dispatch_fn) (struct qemud_server *server,
                            struct qemud_client *client,
                            remote_message_header *req,
                            char *args,
                            char *ret);

/* This function gets called from qemud when it detects an incoming
 * remote protocol message.  At this point, client->buffer contains
 * the full call message (including length word which we skip).
 */
void
remoteDispatchClientRequest (struct qemud_server *server,
                             struct qemud_client *client)
{
    XDR xdr;
    remote_message_header req, rep;
    dispatch_fn fn;
    xdrproc_t args_filter = (xdrproc_t) xdr_void;
    xdrproc_t ret_filter = (xdrproc_t) xdr_void;
    char *args = NULL, *ret = NULL;
    int rv, len;

#include "remote_dispatch_localvars.h"

    /* Parse the header. */
    xdrmem_create (&xdr, client->buffer, client->bufferLength, XDR_DECODE);

    if (!xdr_remote_message_header (&xdr, &req)) {
        remoteDispatchError (client, NULL, "%s", _("xdr_remote_message_header"));
        xdr_destroy (&xdr);
        return;
    }

    /* Check version, etc. */
    if (req.prog != REMOTE_PROGRAM) {
        remoteDispatchError (client, &req,
                             _("program mismatch (actual %x, expected %x)"),
                             req.prog, REMOTE_PROGRAM);
        xdr_destroy (&xdr);
        return;
    }
    if (req.vers != REMOTE_PROTOCOL_VERSION) {
        remoteDispatchError (client, &req,
                             _("version mismatch (actual %x, expected %x)"),
                             req.vers, REMOTE_PROTOCOL_VERSION);
        xdr_destroy (&xdr);
        return;
    }
    if (req.direction != REMOTE_CALL) {
        remoteDispatchError (client, &req, _("direction (%d) != REMOTE_CALL"),
                             (int) req.direction);
        xdr_destroy (&xdr);
        return;
    }
    if (req.status != REMOTE_OK) {
        remoteDispatchError (client, &req, _("status (%d) != REMOTE_OK"),
                             (int) req.status);
        xdr_destroy (&xdr);
        return;
    }

    /* If client is marked as needing auth, don't allow any RPC ops,
     * except for authentication ones
     */
    if (client->auth) {
        if (req.proc != REMOTE_PROC_AUTH_LIST &&
            req.proc != REMOTE_PROC_AUTH_SASL_INIT &&
            req.proc != REMOTE_PROC_AUTH_SASL_START &&
            req.proc != REMOTE_PROC_AUTH_SASL_STEP &&
            req.proc != REMOTE_PROC_AUTH_POLKIT
            ) {
            remoteDispatchError (client, &req, "%s", _("authentication required"));
            xdr_destroy (&xdr);
            return;
        }
    }

    /* Based on the procedure number, dispatch.  In future we may base
     * this on the version number as well.
     */
    switch (req.proc) {
#include "remote_dispatch_proc_switch.h"

    default:
        remoteDispatchError (client, &req, _("unknown procedure: %d"),
                             req.proc);
        xdr_destroy (&xdr);
        return;
    }

    /* Parse args. */
    if (!(*args_filter) (&xdr, args)) {
        remoteDispatchError (client, &req, "%s", _("parse args failed"));
        xdr_destroy (&xdr);
        return;
    }

    xdr_destroy (&xdr);

    /* Call function. */
    rv = fn (server, client, &req, args, ret);
    xdr_free (args_filter, args);

    /* Dispatch function must return -2, -1 or 0.  Anything else is
     * an internal error.
     */
    if (rv < -2 || rv > 0) {
        remoteDispatchError (client, &req,
                             _("internal error - dispatch function returned invalid code %d"), rv);
        return;
    }

    /* Dispatch error?  If so then the function has already set up the
     * return buffer, so just return immediately.
     */
    if (rv == -2) return;

    /* Return header. */
    rep.prog = req.prog;
    rep.vers = req.vers;
    rep.proc = req.proc;
    rep.direction = REMOTE_REPLY;
    rep.serial = req.serial;
    rep.status = rv == 0 ? REMOTE_OK : REMOTE_ERROR;

    /* Serialise the return header. */
    xdrmem_create (&xdr, client->buffer, sizeof client->buffer, XDR_ENCODE);

    len = 0; /* We'll come back and write this later. */
    if (!xdr_int (&xdr, &len)) {
        remoteDispatchError (client, &req, "%s", _("dummy length"));
        xdr_destroy (&xdr);
        if (rv == 0) xdr_free (ret_filter, ret);
        return;
    }

    if (!xdr_remote_message_header (&xdr, &rep)) {
        remoteDispatchError (client, &req, "%s", _("serialise reply header"));
        xdr_destroy (&xdr);
        if (rv == 0) xdr_free (ret_filter, ret);
        return;
    }

    /* If OK, serialise return structure, if error serialise error. */
    if (rv == 0) {
        if (!(*ret_filter) (&xdr, ret)) {
            remoteDispatchError (client, &req, "%s", _("serialise return struct"));
            xdr_destroy (&xdr);
            return;
        }
        xdr_free (ret_filter, ret);
    } else /* error */ {
        virErrorPtr verr;
        remote_error error;
        remote_nonnull_domain dom;
        remote_nonnull_network net;

        verr = client->conn
            ? virConnGetLastError (client->conn)
            : virGetLastError ();

        if (verr) {
            error.code = verr->code;
            error.domain = verr->domain;
            error.message = verr->message ? &verr->message : NULL;
            error.level = verr->level;
            if (verr->dom) {
                dom.name = verr->dom->name;
                memcpy (dom.uuid, verr->dom->uuid, VIR_UUID_BUFLEN);
                dom.id = verr->dom->id;
            }
            error.dom = verr->dom ? &dom : NULL;
            error.str1 = verr->str1 ? &verr->str1 : NULL;
            error.str2 = verr->str2 ? &verr->str2 : NULL;
            error.str3 = verr->str3 ? &verr->str3 : NULL;
            error.int1 = verr->int1;
            error.int2 = verr->int2;
            if (verr->net) {
                net.name = verr->net->name;
                memcpy (net.uuid, verr->net->uuid, VIR_UUID_BUFLEN);
            }
            error.net = verr->net ? &net : NULL;
        } else {
            /* Error was NULL so synthesize an error. */
            char msgbuf[] = "remoteDispatchClientRequest: internal error: library function returned error but did not set virterror";
            char *msg = msgbuf;

            error.code = VIR_ERR_RPC;
            error.domain = VIR_FROM_REMOTE;
            error.message = &msg;
            error.level = VIR_ERR_ERROR;
            error.dom = NULL;
            error.str1 = &msg;
            error.str2 = NULL;
            error.str3 = NULL;
            error.int1 = 0;
            error.int2 = 0;
            error.net = NULL;
        }

        if (!xdr_remote_error (&xdr, &error)) {
            remoteDispatchError (client, &req, "%s", _("serialise return error"));
            xdr_destroy (&xdr);
            return;
        }
    }

    /* Write the length word. */
    len = xdr_getpos (&xdr);
    if (xdr_setpos (&xdr, 0) == 0) {
        remoteDispatchError (client, &req, "%s", _("xdr_setpos"));
        xdr_destroy (&xdr);
        return;
    }

    if (!xdr_int (&xdr, &len)) {
        remoteDispatchError (client, &req, "%s", _("serialise return length"));
        xdr_destroy (&xdr);
        return;
    }

    xdr_destroy (&xdr);

    /* Set up the output buffer. */
    client->mode = QEMUD_MODE_TX_PACKET;
    client->bufferLength = len;
    client->bufferOffset = 0;
}

/* An error occurred during the dispatching process itself (ie. not
 * an error from the function being called).  We return an error
 * reply.
 */
static void
remoteDispatchSendError (struct qemud_client *client,
                         remote_message_header *req,
                         int code, const char *msg)
{
    remote_message_header rep;
    remote_error error;
    XDR xdr;
    int len;

    /* Future versions of the protocol may use different vers or prog.  Try
     * our hardest to send back a message that such clients could see.
     */
    if (req) {
        rep.prog = req->prog;
        rep.vers = req->vers;
        rep.proc = req->proc;
        rep.direction = REMOTE_REPLY;
        rep.serial = req->serial;
        rep.status = REMOTE_ERROR;
    } else {
        rep.prog = REMOTE_PROGRAM;
        rep.vers = REMOTE_PROTOCOL_VERSION;
        rep.proc = REMOTE_PROC_OPEN;
        rep.direction = REMOTE_REPLY;
        rep.serial = 1;
        rep.status = REMOTE_ERROR;
    }

    /* Construct the error. */
    error.code = code;
    error.domain = VIR_FROM_REMOTE;
    error.message = (char**)&msg;
    error.level = VIR_ERR_ERROR;
    error.dom = NULL;
    error.str1 = (char**)&msg;
    error.str2 = NULL;
    error.str3 = NULL;
    error.int1 = 0;
    error.int2 = 0;
    error.net = NULL;

    /* Serialise the return header and error. */
    xdrmem_create (&xdr, client->buffer, sizeof client->buffer, XDR_ENCODE);

    len = 0; /* We'll come back and write this later. */
    if (!xdr_int (&xdr, &len)) {
        xdr_destroy (&xdr);
        return;
    }

    if (!xdr_remote_message_header (&xdr, &rep)) {
        xdr_destroy (&xdr);
        return;
    }

    if (!xdr_remote_error (&xdr, &error)) {
        xdr_destroy (&xdr);
        return;
    }

    len = xdr_getpos (&xdr);
    if (xdr_setpos (&xdr, 0) == 0) {
        xdr_destroy (&xdr);
        return;
    }

    if (!xdr_int (&xdr, &len)) {
        xdr_destroy (&xdr);
        return;
    }

    xdr_destroy (&xdr);

    /* Send it. */
    client->mode = QEMUD_MODE_TX_PACKET;
    client->bufferLength = len;
    client->bufferOffset = 0;
}

static void
remoteDispatchFailAuth (struct qemud_client *client,
                        remote_message_header *req)
{
    remoteDispatchSendError (client, req, VIR_ERR_AUTH_FAILED, "authentication failed");
}

static void
remoteDispatchError (struct qemud_client *client,
                     remote_message_header *req,
                     const char *fmt, ...)
{
    va_list args;
    char msgbuf[1024];
    char *msg = msgbuf;

    va_start (args, fmt);
    vsnprintf (msgbuf, sizeof msgbuf, fmt, args);
    va_end (args);

    remoteDispatchSendError (client, req, VIR_ERR_RPC, msg);
}



/*----- Functions. -----*/

static int
remoteDispatchOpen (struct qemud_server *server ATTRIBUTE_UNUSED,
                    struct qemud_client *client, remote_message_header *req,
                    struct remote_open_args *args, void *ret ATTRIBUTE_UNUSED)
{
    const char *name;
    int flags;

    /* Already opened? */
    if (client->conn) {
        remoteDispatchError (client, req, "%s", _("connection already open"));
        return -2;
    }

    name = args->name ? *args->name : NULL;

#if DEBUG
    fprintf (stderr, "remoteDispatchOpen: name = %s\n", name);
#endif

    /* If this connection arrived on a readonly socket, force
     * the connection to be readonly.
     */
    flags = args->flags;
    if (client->readonly) flags |= VIR_CONNECT_RO;

    client->conn =
        flags & VIR_CONNECT_RO
        ? virConnectOpenReadOnly (name)
        : virConnectOpen (name);

    return client->conn ? 0 : -1;
}

#define CHECK_CONN(client)                      \
    if (!client->conn) {                        \
        remoteDispatchError (client, req, "%s", _("connection not open"));   \
        return -2;                                                  \
    }

static int
remoteDispatchClose (struct qemud_server *server ATTRIBUTE_UNUSED,
                     struct qemud_client *client, remote_message_header *req,
                     void *args ATTRIBUTE_UNUSED, void *ret ATTRIBUTE_UNUSED)
{
    int rv;
    CHECK_CONN(client);

    rv = virConnectClose (client->conn);
    if (rv == 0) client->conn = NULL;

    return rv;
}

static int
remoteDispatchSupportsFeature (struct qemud_server *server ATTRIBUTE_UNUSED,
                               struct qemud_client *client, remote_message_header *req,
                               remote_supports_feature_args *args, remote_supports_feature_ret *ret)
{
    CHECK_CONN(client);

    ret->supported = __virDrvSupportsFeature (client->conn, args->feature);
    if (ret->supported == -1) return -1;

    return 0;
}

static int
remoteDispatchGetType (struct qemud_server *server ATTRIBUTE_UNUSED,
                       struct qemud_client *client, remote_message_header *req,
                       void *args ATTRIBUTE_UNUSED, remote_get_type_ret *ret)
{
    const char *type;
    CHECK_CONN(client);

    type = virConnectGetType (client->conn);
    if (type == NULL) return -1;

    /* We have to strdup because remoteDispatchClientRequest will
     * free this string after it's been serialised.
     */
    ret->type = strdup (type);
    if (!ret->type) {
        remoteDispatchError (client, req, "%s", _("out of memory in strdup"));
        return -2;
    }

    return 0;
}

static int
remoteDispatchGetVersion (struct qemud_server *server ATTRIBUTE_UNUSED,
                          struct qemud_client *client,
                          remote_message_header *req,
                          void *args ATTRIBUTE_UNUSED,
                          remote_get_version_ret *ret)
{
    unsigned long hvVer;
    CHECK_CONN(client);

    if (virConnectGetVersion (client->conn, &hvVer) == -1)
        return -1;

    ret->hv_ver = hvVer;
    return 0;
}

static int
remoteDispatchGetHostname (struct qemud_server *server ATTRIBUTE_UNUSED,
                           struct qemud_client *client,
                           remote_message_header *req,
                           void *args ATTRIBUTE_UNUSED,
                           remote_get_hostname_ret *ret)
{
    char *hostname;
    CHECK_CONN(client);

    hostname = virConnectGetHostname (client->conn);
    if (hostname == NULL) return -1;

    ret->hostname = hostname;
    return 0;
}

static int
remoteDispatchGetMaxVcpus (struct qemud_server *server ATTRIBUTE_UNUSED,
                           struct qemud_client *client,
                           remote_message_header *req,
                           remote_get_max_vcpus_args *args,
                           remote_get_max_vcpus_ret *ret)
{
    char *type;
    CHECK_CONN(client);

    type = args->type ? *args->type : NULL;
    ret->max_vcpus = virConnectGetMaxVcpus (client->conn, type);
    if (ret->max_vcpus == -1) return -1;

    return 0;
}

static int
remoteDispatchNodeGetInfo (struct qemud_server *server ATTRIBUTE_UNUSED,
                           struct qemud_client *client,
                           remote_message_header *req,
                           void *args ATTRIBUTE_UNUSED,
                           remote_node_get_info_ret *ret)
{
    virNodeInfo info;
    CHECK_CONN(client);

    if (virNodeGetInfo (client->conn, &info) == -1)
        return -1;

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
                               struct qemud_client *client,
                               remote_message_header *req,
                               void *args ATTRIBUTE_UNUSED,
                               remote_get_capabilities_ret *ret)
{
    char *caps;
    CHECK_CONN(client);

    caps = virConnectGetCapabilities (client->conn);
    if (caps == NULL) return -1;

    ret->capabilities = caps;
    return 0;
}

static int
remoteDispatchDomainGetSchedulerType (struct qemud_server *server ATTRIBUTE_UNUSED,
                                      struct qemud_client *client,
                                      remote_message_header *req,
                                      remote_domain_get_scheduler_type_args *args,
                                      remote_domain_get_scheduler_type_ret *ret)
{
    virDomainPtr dom;
    char *type;
    int nparams;
    CHECK_CONN(client);

    dom = get_nonnull_domain (client->conn, args->dom);
    if (dom == NULL) {
        remoteDispatchError (client, req, "%s", _("domain not found"));
        return -2;
    }

    type = virDomainGetSchedulerType (dom, &nparams);
    if (type == NULL) {
        virDomainFree(dom);
        return -1;
    }

    ret->type = type;
    ret->nparams = nparams;
    virDomainFree(dom);
    return 0;
}

static int
remoteDispatchDomainGetSchedulerParameters (struct qemud_server *server ATTRIBUTE_UNUSED,
                                            struct qemud_client *client,
                                            remote_message_header *req,
                                            remote_domain_get_scheduler_parameters_args *args,
                                            remote_domain_get_scheduler_parameters_ret *ret)
{
    virDomainPtr dom;
    virSchedParameterPtr params;
    int i, r, nparams;
    CHECK_CONN(client);

    nparams = args->nparams;

    if (nparams > REMOTE_DOMAIN_SCHEDULER_PARAMETERS_MAX) {
        remoteDispatchError (client, req, "%s", _("nparams too large"));
        return -2;
    }
    params = malloc (sizeof (*params) * nparams);
    if (params == NULL) {
        remoteDispatchError (client, req, "%s", _("out of memory allocating array"));
        return -2;
    }

    dom = get_nonnull_domain (client->conn, args->dom);
    if (dom == NULL) {
        free (params);
        remoteDispatchError (client, req, "%s", _("domain not found"));
        return -2;
    }

    r = virDomainGetSchedulerParameters (dom, params, &nparams);
    if (r == -1) {
        virDomainFree(dom);
        free (params);
        return -1;
    }

    /* Serialise the scheduler parameters. */
    ret->params.params_len = nparams;
    ret->params.params_val = malloc (sizeof (*(ret->params.params_val))
                                     * nparams);
    if (ret->params.params_val == NULL) {
        virDomainFree(dom);
        free (params);
        remoteDispatchError (client, req,
                             "%s", _("out of memory allocating return array"));
        return -2;
    }

    for (i = 0; i < nparams; ++i) {
        // remoteDispatchClientRequest will free this:
        ret->params.params_val[i].field = strdup (params[i].field);
        if (ret->params.params_val[i].field == NULL) {
            virDomainFree(dom);
            free (params);
            remoteDispatchError (client, req,
                                 "%s", _("out of memory allocating return array"));
            return -2;
        }
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
            virDomainFree(dom);
            free (params);
            remoteDispatchError (client, req, "%s", _("unknown type"));
            return -2;
        }
    }
    virDomainFree(dom);
    free (params);

    return 0;
}

static int
remoteDispatchDomainSetSchedulerParameters (struct qemud_server *server ATTRIBUTE_UNUSED,
                                            struct qemud_client *client,
                                            remote_message_header *req,
                                            remote_domain_set_scheduler_parameters_args *args,
                                            void *ret ATTRIBUTE_UNUSED)
{
    virDomainPtr dom;
    int i, r, nparams;
    virSchedParameterPtr params;
    CHECK_CONN(client);

    nparams = args->params.params_len;

    if (nparams > REMOTE_DOMAIN_SCHEDULER_PARAMETERS_MAX) {
        remoteDispatchError (client, req, "%s", _("nparams too large"));
        return -2;
    }
    params = malloc (sizeof (*params) * nparams);
    if (params == NULL) {
        remoteDispatchError (client, req, "%s", _("out of memory allocating array"));
        return -2;
    }

    /* Deserialise parameters. */
    for (i = 0; i < nparams; ++i) {
        strncpy (params[i].field, args->params.params_val[i].field,
                 VIR_DOMAIN_SCHED_FIELD_LENGTH);
        params[i].field[VIR_DOMAIN_SCHED_FIELD_LENGTH-1] = '\0';
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

    dom = get_nonnull_domain (client->conn, args->dom);
    if (dom == NULL) {
        free (params);
        remoteDispatchError (client, req, "%s", _("domain not found"));
        return -2;
    }

    r = virDomainSetSchedulerParameters (dom, params, nparams);
    virDomainFree(dom);
    free (params);
    if (r == -1) return -1;

    return 0;
}

static int
remoteDispatchDomainBlockStats (struct qemud_server *server ATTRIBUTE_UNUSED,
                                struct qemud_client *client,
                                remote_message_header *req,
                                remote_domain_block_stats_args *args,
                                remote_domain_block_stats_ret *ret)
{
    virDomainPtr dom;
    char *path;
    struct _virDomainBlockStats stats;
    CHECK_CONN (client);

    dom = get_nonnull_domain (client->conn, args->dom);
    if (dom == NULL) {
        remoteDispatchError (client, req, "%s", _("domain not found"));
        return -2;
    }
    path = args->path;

    if (virDomainBlockStats (dom, path, &stats, sizeof stats) == -1)
        return -1;

    ret->rd_req = stats.rd_req;
    ret->rd_bytes = stats.rd_bytes;
    ret->wr_req = stats.wr_req;
    ret->wr_bytes = stats.wr_bytes;
    ret->errs = stats.errs;

    return 0;
}

static int
remoteDispatchDomainInterfaceStats (struct qemud_server *server ATTRIBUTE_UNUSED,
                                    struct qemud_client *client,
                                    remote_message_header *req,
                                    remote_domain_interface_stats_args *args,
                                    remote_domain_interface_stats_ret *ret)
{
    virDomainPtr dom;
    char *path;
    struct _virDomainInterfaceStats stats;
    CHECK_CONN (client);

    dom = get_nonnull_domain (client->conn, args->dom);
    if (dom == NULL) {
        remoteDispatchError (client, req, "%s", _("domain not found"));
        return -2;
    }
    path = args->path;

    if (virDomainInterfaceStats (dom, path, &stats, sizeof stats) == -1)
        return -1;

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
remoteDispatchDomainAttachDevice (struct qemud_server *server ATTRIBUTE_UNUSED,
                                  struct qemud_client *client,
                                  remote_message_header *req,
                                  remote_domain_attach_device_args *args,
                                  void *ret ATTRIBUTE_UNUSED)
{
    virDomainPtr dom;
    CHECK_CONN(client);

    dom = get_nonnull_domain (client->conn, args->dom);
    if (dom == NULL) {
        remoteDispatchError (client, req, "%s", _("domain not found"));
        return -2;
    }

    if (virDomainAttachDevice (dom, args->xml) == -1) {
        virDomainFree(dom);
        return -1;
    }
    virDomainFree(dom);
    return 0;
}

static int
remoteDispatchDomainCreate (struct qemud_server *server ATTRIBUTE_UNUSED,
                            struct qemud_client *client,
                            remote_message_header *req,
                            remote_domain_create_args *args,
                            void *ret ATTRIBUTE_UNUSED)
{
    virDomainPtr dom;
    CHECK_CONN(client);

    dom = get_nonnull_domain (client->conn, args->dom);
    if (dom == NULL) {
        remoteDispatchError (client, req, "%s", _("domain not found"));
        return -2;
    }

    if (virDomainCreate (dom) == -1) {
        virDomainFree(dom);
        return -1;
    }
    virDomainFree(dom);
    return 0;
}

static int
remoteDispatchDomainCreateLinux (struct qemud_server *server ATTRIBUTE_UNUSED,
                                 struct qemud_client *client,
                                 remote_message_header *req,
                                 remote_domain_create_linux_args *args,
                                 remote_domain_create_linux_ret *ret)
{
    virDomainPtr dom;
    CHECK_CONN(client);

    dom = virDomainCreateLinux (client->conn, args->xml_desc, args->flags);
    if (dom == NULL) return -1;

    make_nonnull_domain (&ret->dom, dom);
    virDomainFree(dom);

    return 0;
}

static int
remoteDispatchDomainDefineXml (struct qemud_server *server ATTRIBUTE_UNUSED,
                               struct qemud_client *client,
                               remote_message_header *req,
                               remote_domain_define_xml_args *args,
                               remote_domain_define_xml_ret *ret)
{
    virDomainPtr dom;
    CHECK_CONN(client);

    dom = virDomainDefineXML (client->conn, args->xml);
    if (dom == NULL) return -1;

    make_nonnull_domain (&ret->dom, dom);
    virDomainFree(dom);

    return 0;
}

static int
remoteDispatchDomainDestroy (struct qemud_server *server ATTRIBUTE_UNUSED,
                             struct qemud_client *client,
                             remote_message_header *req,
                             remote_domain_destroy_args *args,
                             void *ret ATTRIBUTE_UNUSED)
{
    virDomainPtr dom;
    CHECK_CONN(client);

    dom = get_nonnull_domain (client->conn, args->dom);
    if (dom == NULL) {
        remoteDispatchError (client, req, "%s", _("domain not found"));
        return -2;
    }

    if (virDomainDestroy (dom) == -1)
        return -1;
    /* No need to free dom - destroy does it for us */
    return 0;
}

static int
remoteDispatchDomainDetachDevice (struct qemud_server *server ATTRIBUTE_UNUSED,
                                  struct qemud_client *client,
                                  remote_message_header *req,
                                  remote_domain_detach_device_args *args,
                                  void *ret ATTRIBUTE_UNUSED)
{
    virDomainPtr dom;
    CHECK_CONN(client);

    dom = get_nonnull_domain (client->conn, args->dom);
    if (dom == NULL) {
        remoteDispatchError (client, req, "%s", _("domain not found"));
        return -2;
    }

    if (virDomainDetachDevice (dom, args->xml) == -1) {
        virDomainFree(dom);
        return -1;
    }

    virDomainFree(dom);
    return 0;
}

static int
remoteDispatchDomainDumpXml (struct qemud_server *server ATTRIBUTE_UNUSED,
                             struct qemud_client *client,
                             remote_message_header *req,
                             remote_domain_dump_xml_args *args,
                             remote_domain_dump_xml_ret *ret)
{
    virDomainPtr dom;
    CHECK_CONN(client);

    dom = get_nonnull_domain (client->conn, args->dom);
    if (dom == NULL) {
        remoteDispatchError (client, req, "%s", _("domain not found"));
        return -2;
    }

    /* remoteDispatchClientRequest will free this. */
    ret->xml = virDomainGetXMLDesc (dom, args->flags);
    if (!ret->xml) {
            virDomainFree(dom);
            return -1;
    }
    virDomainFree(dom);
    return 0;
}

static int
remoteDispatchDomainGetAutostart (struct qemud_server *server ATTRIBUTE_UNUSED,
                                  struct qemud_client *client,
                                  remote_message_header *req,
                                  remote_domain_get_autostart_args *args,
                                  remote_domain_get_autostart_ret *ret)
{
    virDomainPtr dom;
    CHECK_CONN(client);

    dom = get_nonnull_domain (client->conn, args->dom);
    if (dom == NULL) {
        remoteDispatchError (client, req, "%s", _("domain not found"));
        return -2;
    }

    if (virDomainGetAutostart (dom, &ret->autostart) == -1) {
        virDomainFree(dom);
        return -1;
    }
    virDomainFree(dom);
    return 0;
}

static int
remoteDispatchDomainGetInfo (struct qemud_server *server ATTRIBUTE_UNUSED,
                             struct qemud_client *client,
                             remote_message_header *req,
                             remote_domain_get_info_args *args,
                             remote_domain_get_info_ret *ret)
{
    virDomainPtr dom;
    virDomainInfo info;
    CHECK_CONN(client);

    dom = get_nonnull_domain (client->conn, args->dom);
    if (dom == NULL) {
        remoteDispatchError (client, req, "%s", _("domain not found"));
        return -2;
    }

    if (virDomainGetInfo (dom, &info) == -1) {
        virDomainFree(dom);
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
                                  struct qemud_client *client,
                                  remote_message_header *req,
                                  remote_domain_get_max_memory_args *args,
                                  remote_domain_get_max_memory_ret *ret)
{
    virDomainPtr dom;
    CHECK_CONN(client);

    dom = get_nonnull_domain (client->conn, args->dom);
    if (dom == NULL) {
        remoteDispatchError (client, req, "%s", _("domain not found"));
        return -2;
    }

    ret->memory = virDomainGetMaxMemory (dom);
    if (ret->memory == 0) {
        virDomainFree(dom);
        return -1;
    }
    virDomainFree(dom);
    return 0;
}

static int
remoteDispatchDomainGetMaxVcpus (struct qemud_server *server ATTRIBUTE_UNUSED,
                                 struct qemud_client *client,
                                 remote_message_header *req,
                                 remote_domain_get_max_vcpus_args *args,
                                 remote_domain_get_max_vcpus_ret *ret)
{
    virDomainPtr dom;
    CHECK_CONN(client);

    dom = get_nonnull_domain (client->conn, args->dom);
    if (dom == NULL) {
        remoteDispatchError (client, req, "%s", _("domain not found"));
        return -2;
    }

    ret->num = virDomainGetMaxVcpus (dom);
    if (ret->num == -1) {
        virDomainFree(dom);
        return -1;
    }
    virDomainFree(dom);
    return 0;
}

static int
remoteDispatchDomainGetOsType (struct qemud_server *server ATTRIBUTE_UNUSED,
                               struct qemud_client *client,
                               remote_message_header *req,
                               remote_domain_get_os_type_args *args,
                               remote_domain_get_os_type_ret *ret)
{
    virDomainPtr dom;
    CHECK_CONN(client);

    dom = get_nonnull_domain (client->conn, args->dom);
    if (dom == NULL) {
        remoteDispatchError (client, req, "%s", _("domain not found"));
        return -2;
    }

    /* remoteDispatchClientRequest will free this */
    ret->type = virDomainGetOSType (dom);
    if (ret->type == NULL) {
            virDomainFree(dom);
            return -1;
    }
    virDomainFree(dom);
    return 0;
}

static int
remoteDispatchDomainGetVcpus (struct qemud_server *server ATTRIBUTE_UNUSED,
                              struct qemud_client *client,
                              remote_message_header *req,
                              remote_domain_get_vcpus_args *args,
                              remote_domain_get_vcpus_ret *ret)
{
    virDomainPtr dom;
    virVcpuInfoPtr info;
    unsigned char *cpumaps;
    int info_len, i;
    CHECK_CONN(client);

    dom = get_nonnull_domain (client->conn, args->dom);
    if (dom == NULL) {
        remoteDispatchError (client, req, "%s", _("domain not found"));
        return -2;
    }

    if (args->maxinfo > REMOTE_VCPUINFO_MAX) {
        virDomainFree(dom);
        remoteDispatchError (client, req, "%s", _("maxinfo > REMOTE_VCPUINFO_MAX"));
        return -2;
    }

    if (args->maxinfo * args->maplen > REMOTE_CPUMAPS_MAX) {
        virDomainFree(dom);
        remoteDispatchError (client, req, "%s", _("maxinfo * maplen > REMOTE_CPUMAPS_MAX"));
        return -2;
    }

    /* Allocate buffers to take the results. */
    info = calloc (args->maxinfo, sizeof (*info));
    cpumaps = calloc (args->maxinfo * args->maplen, sizeof (*cpumaps));

    info_len = virDomainGetVcpus (dom,
                                  info, args->maxinfo,
                                  cpumaps, args->maplen);
    if (info_len == -1) {
        virDomainFree(dom);
        return -1;
    }

    /* Allocate the return buffer for info. */
    ret->info.info_len = info_len;
    ret->info.info_val = calloc (info_len, sizeof (*(ret->info.info_val)));

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

    virDomainFree(dom);
    return 0;
}

static int
remoteDispatchDomainMigratePrepare (struct qemud_server *server ATTRIBUTE_UNUSED,
                                    struct qemud_client *client,
                                    remote_message_header *req,
                                    remote_domain_migrate_prepare_args *args,
                                    remote_domain_migrate_prepare_ret *ret)
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
    uri_out = calloc (1, sizeof (*uri_out));

    r = __virDomainMigratePrepare (client->conn, &cookie, &cookielen,
                                   uri_in, uri_out,
                                   args->flags, dname, args->resource);
    if (r == -1) return -1;

    /* remoteDispatchClientRequest will free cookie, uri_out and
     * the string if there is one.
     */
    ret->cookie.cookie_len = cookielen;
    ret->cookie.cookie_val = cookie;
    ret->uri_out = *uri_out == NULL ? NULL : uri_out;

    return 0;
}

static int
remoteDispatchDomainMigratePerform (struct qemud_server *server ATTRIBUTE_UNUSED,
                                    struct qemud_client *client,
                                    remote_message_header *req,
                                    remote_domain_migrate_perform_args *args,
                                    void *ret ATTRIBUTE_UNUSED)
{
    int r;
    virDomainPtr dom;
    char *dname;
    CHECK_CONN (client);

    dom = get_nonnull_domain (client->conn, args->dom);
    if (dom == NULL) {
        remoteDispatchError (client, req, "%s", _("domain not found"));
        return -2;
    }

    dname = args->dname == NULL ? NULL : *args->dname;

    r = __virDomainMigratePerform (dom,
                                   args->cookie.cookie_val,
                                   args->cookie.cookie_len,
                                   args->uri,
                                   args->flags, dname, args->resource);
    if (r == -1) return -1;

    return 0;
}

static int
remoteDispatchDomainMigrateFinish (struct qemud_server *server ATTRIBUTE_UNUSED,
                                   struct qemud_client *client,
                                   remote_message_header *req,
                                   remote_domain_migrate_finish_args *args,
                                   remote_domain_migrate_finish_ret *ret)
{
    virDomainPtr ddom;
    CHECK_CONN (client);

    ddom = __virDomainMigrateFinish (client->conn, args->dname,
                                     args->cookie.cookie_val,
                                     args->cookie.cookie_len,
                                     args->uri,
                                     args->flags);
    if (ddom == NULL) return -1;

    make_nonnull_domain (&ret->ddom, ddom);

    return 0;
}

static int
remoteDispatchListDefinedDomains (struct qemud_server *server ATTRIBUTE_UNUSED,
                                  struct qemud_client *client,
                                  remote_message_header *req,
                                  remote_list_defined_domains_args *args,
                                  remote_list_defined_domains_ret *ret)
{
    CHECK_CONN(client);

    if (args->maxnames > REMOTE_DOMAIN_NAME_LIST_MAX) {
        remoteDispatchError (client, req,
                             "%s", _("maxnames > REMOTE_DOMAIN_NAME_LIST_MAX"));
        return -2;
    }

    /* Allocate return buffer. */
    ret->names.names_val = calloc (args->maxnames, sizeof (*(ret->names.names_val)));

    ret->names.names_len =
        virConnectListDefinedDomains (client->conn,
                                      ret->names.names_val, args->maxnames);
    if (ret->names.names_len == -1) return -1;

    return 0;
}

static int
remoteDispatchDomainLookupById (struct qemud_server *server ATTRIBUTE_UNUSED,
                                struct qemud_client *client,
                                remote_message_header *req,
                                remote_domain_lookup_by_id_args *args,
                                remote_domain_lookup_by_id_ret *ret)
{
    virDomainPtr dom;
    CHECK_CONN(client);

    dom = virDomainLookupByID (client->conn, args->id);
    if (dom == NULL) return -1;

    make_nonnull_domain (&ret->dom, dom);
    virDomainFree(dom);
    return 0;
}

static int
remoteDispatchDomainLookupByName (struct qemud_server *server ATTRIBUTE_UNUSED,
                                  struct qemud_client *client,
                                  remote_message_header *req,
                                  remote_domain_lookup_by_name_args *args,
                                  remote_domain_lookup_by_name_ret *ret)
{
    virDomainPtr dom;
    CHECK_CONN(client);

    dom = virDomainLookupByName (client->conn, args->name);
    if (dom == NULL) return -1;

    make_nonnull_domain (&ret->dom, dom);
    virDomainFree(dom);
    return 0;
}

static int
remoteDispatchDomainLookupByUuid (struct qemud_server *server ATTRIBUTE_UNUSED,
                                  struct qemud_client *client,
                                  remote_message_header *req,
                                  remote_domain_lookup_by_uuid_args *args,
                                  remote_domain_lookup_by_uuid_ret *ret)
{
    virDomainPtr dom;
    CHECK_CONN(client);

    dom = virDomainLookupByUUID (client->conn, (unsigned char *) args->uuid);
    if (dom == NULL) return -1;

    make_nonnull_domain (&ret->dom, dom);
    virDomainFree(dom);
    return 0;
}

static int
remoteDispatchNumOfDefinedDomains (struct qemud_server *server ATTRIBUTE_UNUSED,
                                   struct qemud_client *client,
                                   remote_message_header *req,
                                   void *args ATTRIBUTE_UNUSED,
                                   remote_num_of_defined_domains_ret *ret)
{
    CHECK_CONN(client);

    ret->num = virConnectNumOfDefinedDomains (client->conn);
    if (ret->num == -1) return -1;

    return 0;
}

static int
remoteDispatchDomainPinVcpu (struct qemud_server *server ATTRIBUTE_UNUSED,
                             struct qemud_client *client,
                             remote_message_header *req,
                             remote_domain_pin_vcpu_args *args,
                             void *ret ATTRIBUTE_UNUSED)
{
    virDomainPtr dom;
    int rv;
    CHECK_CONN(client);

    dom = get_nonnull_domain (client->conn, args->dom);
    if (dom == NULL) {
        remoteDispatchError (client, req, "%s", _("domain not found"));
        return -2;
    }

    if (args->cpumap.cpumap_len > REMOTE_CPUMAP_MAX) {
        virDomainFree(dom);
        remoteDispatchError (client, req, "%s", _("cpumap_len > REMOTE_CPUMAP_MAX"));
        return -2;
    }

    rv = virDomainPinVcpu (dom, args->vcpu,
                           (unsigned char *) args->cpumap.cpumap_val,
                           args->cpumap.cpumap_len);
    if (rv == -1) {
        virDomainFree(dom);
        return -1;
    }
    virDomainFree(dom);
    return 0;
}

static int
remoteDispatchDomainReboot (struct qemud_server *server ATTRIBUTE_UNUSED,
                            struct qemud_client *client,
                            remote_message_header *req,
                            remote_domain_reboot_args *args,
                            void *ret ATTRIBUTE_UNUSED)
{
    virDomainPtr dom;
    CHECK_CONN(client);

    dom = get_nonnull_domain (client->conn, args->dom);
    if (dom == NULL) {
        remoteDispatchError (client, req, "%s", _("domain not found"));
        return -2;
    }

    if (virDomainReboot (dom, args->flags) == -1) {
        virDomainFree(dom);
        return -1;
    }
    virDomainFree(dom);
    return 0;
}

static int
remoteDispatchDomainRestore (struct qemud_server *server ATTRIBUTE_UNUSED,
                             struct qemud_client *client,
                             remote_message_header *req,
                             remote_domain_restore_args *args,
                             void *ret ATTRIBUTE_UNUSED)
{
    CHECK_CONN(client);

    if (virDomainRestore (client->conn, args->from) == -1)
        return -1;

    return 0;
}

static int
remoteDispatchDomainResume (struct qemud_server *server ATTRIBUTE_UNUSED,
                            struct qemud_client *client,
                            remote_message_header *req,
                            remote_domain_resume_args *args,
                            void *ret ATTRIBUTE_UNUSED)
{
    virDomainPtr dom;
    CHECK_CONN(client);

    dom = get_nonnull_domain (client->conn, args->dom);
    if (dom == NULL) {
        remoteDispatchError (client, req, "%s", _("domain not found"));
        return -2;
    }

    if (virDomainResume (dom) == -1) {
        virDomainFree(dom);
        return -1;
    }
    virDomainFree(dom);
    return 0;
}

static int
remoteDispatchDomainSave (struct qemud_server *server ATTRIBUTE_UNUSED,
                          struct qemud_client *client,
                          remote_message_header *req,
                          remote_domain_save_args *args,
                          void *ret ATTRIBUTE_UNUSED)
{
    virDomainPtr dom;
    CHECK_CONN(client);

    dom = get_nonnull_domain (client->conn, args->dom);
    if (dom == NULL) {
        remoteDispatchError (client, req, "%s", _("domain not found"));
        return -2;
    }

    if (virDomainSave (dom, args->to) == -1) {
        virDomainFree(dom);
        return -1;
    }
    virDomainFree(dom);
    return 0;
}

static int
remoteDispatchDomainCoreDump (struct qemud_server *server ATTRIBUTE_UNUSED,
                              struct qemud_client *client,
                              remote_message_header *req,
                              remote_domain_core_dump_args *args,
                              void *ret ATTRIBUTE_UNUSED)
{
    virDomainPtr dom;
    CHECK_CONN(client);

    dom = get_nonnull_domain (client->conn, args->dom);
    if (dom == NULL) {
        remoteDispatchError (client, req, "%s", _("domain not found"));
        return -2;
    }

    if (virDomainCoreDump (dom, args->to, args->flags) == -1) {
        virDomainFree(dom);
        return -1;
    }
    virDomainFree(dom);
    return 0;
}

static int
remoteDispatchDomainSetAutostart (struct qemud_server *server ATTRIBUTE_UNUSED,
                                  struct qemud_client *client,
                                  remote_message_header *req,
                                  remote_domain_set_autostart_args *args,
                                  void *ret ATTRIBUTE_UNUSED)
{
    virDomainPtr dom;
    CHECK_CONN(client);

    dom = get_nonnull_domain (client->conn, args->dom);
    if (dom == NULL) {
        remoteDispatchError (client, req, "%s", _("domain not found"));
        return -2;
    }

    if (virDomainSetAutostart (dom, args->autostart) == -1) {
        virDomainFree(dom);
        return -1;
    }
    virDomainFree(dom);
    return 0;
}

static int
remoteDispatchDomainSetMaxMemory (struct qemud_server *server ATTRIBUTE_UNUSED,
                                  struct qemud_client *client,
                                  remote_message_header *req,
                                  remote_domain_set_max_memory_args *args,
                                  void *ret ATTRIBUTE_UNUSED)
{
    virDomainPtr dom;
    CHECK_CONN(client);

    dom = get_nonnull_domain (client->conn, args->dom);
    if (dom == NULL) {
        remoteDispatchError (client, req, "%s", _("domain not found"));
        return -2;
    }

    if (virDomainSetMaxMemory (dom, args->memory) == -1) {
        virDomainFree(dom);
        return -1;
    }
    virDomainFree(dom);
    return 0;
}

static int
remoteDispatchDomainSetMemory (struct qemud_server *server ATTRIBUTE_UNUSED,
                               struct qemud_client *client,
                               remote_message_header *req,
                               remote_domain_set_memory_args *args,
                               void *ret ATTRIBUTE_UNUSED)
{
    virDomainPtr dom;
    CHECK_CONN(client);

    dom = get_nonnull_domain (client->conn, args->dom);
    if (dom == NULL) {
        remoteDispatchError (client, req, "%s", _("domain not found"));
        return -2;
    }

    if (virDomainSetMemory (dom, args->memory) == -1) {
        virDomainFree(dom);
        return -1;
    }
    virDomainFree(dom);
    return 0;
}

static int
remoteDispatchDomainSetVcpus (struct qemud_server *server ATTRIBUTE_UNUSED,
                              struct qemud_client *client,
                              remote_message_header *req,
                              remote_domain_set_vcpus_args *args,
                              void *ret ATTRIBUTE_UNUSED)
{
    virDomainPtr dom;
    CHECK_CONN(client);

    dom = get_nonnull_domain (client->conn, args->dom);
    if (dom == NULL) {
        remoteDispatchError (client, req, "%s", _("domain not found"));
        return -2;
    }

    if (virDomainSetVcpus (dom, args->nvcpus) == -1) {
        virDomainFree(dom);
        return -1;
    }
    virDomainFree(dom);
    return 0;
}

static int
remoteDispatchDomainShutdown (struct qemud_server *server ATTRIBUTE_UNUSED,
                              struct qemud_client *client,
                              remote_message_header *req,
                              remote_domain_shutdown_args *args,
                              void *ret ATTRIBUTE_UNUSED)
{
    virDomainPtr dom;
    CHECK_CONN(client);

    dom = get_nonnull_domain (client->conn, args->dom);
    if (dom == NULL) {
        remoteDispatchError (client, req, "%s", _("domain not found"));
        return -2;
    }

    if (virDomainShutdown (dom) == -1) {
        virDomainFree(dom);
        return -1;
    }
    virDomainFree(dom);
    return 0;
}

static int
remoteDispatchDomainSuspend (struct qemud_server *server ATTRIBUTE_UNUSED,
                             struct qemud_client *client,
                             remote_message_header *req,
                             remote_domain_suspend_args *args,
                             void *ret ATTRIBUTE_UNUSED)
{
    virDomainPtr dom;
    CHECK_CONN(client);

    dom = get_nonnull_domain (client->conn, args->dom);
    if (dom == NULL) {
        remoteDispatchError (client, req, "%s", _("domain not found"));
        return -2;
    }

    if (virDomainSuspend (dom) == -1) {
        virDomainFree(dom);
        return -1;
    }
    virDomainFree(dom);
    return 0;
}

static int
remoteDispatchDomainUndefine (struct qemud_server *server ATTRIBUTE_UNUSED,
                              struct qemud_client *client,
                              remote_message_header *req,
                              remote_domain_undefine_args *args,
                              void *ret ATTRIBUTE_UNUSED)
{
    virDomainPtr dom;
    CHECK_CONN(client);

    dom = get_nonnull_domain (client->conn, args->dom);
    if (dom == NULL) {
        remoteDispatchError (client, req, "%s", _("domain not found"));
        return -2;
    }

    if (virDomainUndefine (dom) == -1) {
        virDomainFree(dom);
        return -1;
    }
    virDomainFree(dom);
    return 0;
}

static int
remoteDispatchListDefinedNetworks (struct qemud_server *server ATTRIBUTE_UNUSED,
                                   struct qemud_client *client,
                                   remote_message_header *req,
                                   remote_list_defined_networks_args *args,
                                   remote_list_defined_networks_ret *ret)
{
    CHECK_CONN(client);

    if (args->maxnames > REMOTE_NETWORK_NAME_LIST_MAX) {
        remoteDispatchError (client, req,
                             "%s", _("maxnames > REMOTE_NETWORK_NAME_LIST_MAX"));
        return -2;
    }

    /* Allocate return buffer. */
    ret->names.names_val = calloc (args->maxnames, sizeof (*(ret->names.names_val)));

    ret->names.names_len =
        virConnectListDefinedNetworks (client->conn,
                                       ret->names.names_val, args->maxnames);
    if (ret->names.names_len == -1) return -1;

    return 0;
}

static int
remoteDispatchListDomains (struct qemud_server *server ATTRIBUTE_UNUSED,
                           struct qemud_client *client,
                           remote_message_header *req,
                           remote_list_domains_args *args,
                           remote_list_domains_ret *ret)
{
    CHECK_CONN(client);

    if (args->maxids > REMOTE_DOMAIN_ID_LIST_MAX) {
        remoteDispatchError (client, req,
                             "%s", _("maxids > REMOTE_DOMAIN_ID_LIST_MAX"));
        return -2;
    }

    /* Allocate return buffer. */
    ret->ids.ids_val = calloc (args->maxids, sizeof (*(ret->ids.ids_val)));

    ret->ids.ids_len = virConnectListDomains (client->conn,
                                              ret->ids.ids_val, args->maxids);
    if (ret->ids.ids_len == -1) return -1;

    return 0;
}

static int
remoteDispatchListNetworks (struct qemud_server *server ATTRIBUTE_UNUSED,
                            struct qemud_client *client,
                            remote_message_header *req,
                            remote_list_networks_args *args,
                            remote_list_networks_ret *ret)
{
    CHECK_CONN(client);

    if (args->maxnames > REMOTE_NETWORK_NAME_LIST_MAX) {
        remoteDispatchError (client, req,
                             "%s", _("maxnames > REMOTE_NETWORK_NAME_LIST_MAX"));
        return -2;
    }

    /* Allocate return buffer. */
    ret->names.names_val = calloc (args->maxnames, sizeof (*(ret->names.names_val)));

    ret->names.names_len =
        virConnectListNetworks (client->conn,
                                ret->names.names_val, args->maxnames);
    if (ret->names.names_len == -1) return -1;

    return 0;
}

static int
remoteDispatchNetworkCreate (struct qemud_server *server ATTRIBUTE_UNUSED,
                             struct qemud_client *client,
                             remote_message_header *req,
                             remote_network_create_args *args,
                             void *ret ATTRIBUTE_UNUSED)
{
    virNetworkPtr net;
    CHECK_CONN(client);

    net = get_nonnull_network (client->conn, args->net);
    if (net == NULL) {
        remoteDispatchError (client, req, "%s", _("network not found"));
        return -2;
    }

    if (virNetworkCreate (net) == -1) {
        virNetworkFree(net);
        return -1;
    }
    virNetworkFree(net);
    return 0;
}

static int
remoteDispatchNetworkCreateXml (struct qemud_server *server ATTRIBUTE_UNUSED,
                                struct qemud_client *client,
                                remote_message_header *req,
                                remote_network_create_xml_args *args,
                                remote_network_create_xml_ret *ret)
{
    virNetworkPtr net;
    CHECK_CONN(client);

    net = virNetworkCreateXML (client->conn, args->xml);
    if (net == NULL) return -1;

    make_nonnull_network (&ret->net, net);
    virNetworkFree(net);
    return 0;
}

static int
remoteDispatchNetworkDefineXml (struct qemud_server *server ATTRIBUTE_UNUSED,
                                struct qemud_client *client,
                                remote_message_header *req,
                                remote_network_define_xml_args *args,
                                remote_network_define_xml_ret *ret)
{
    virNetworkPtr net;
    CHECK_CONN(client);

    net = virNetworkDefineXML (client->conn, args->xml);
    if (net == NULL) return -1;

    make_nonnull_network (&ret->net, net);
    virNetworkFree(net);
    return 0;
}

static int
remoteDispatchNetworkDestroy (struct qemud_server *server ATTRIBUTE_UNUSED,
                              struct qemud_client *client,
                              remote_message_header *req,
                              remote_network_destroy_args *args,
                              void *ret ATTRIBUTE_UNUSED)
{
    virNetworkPtr net;
    CHECK_CONN(client);

    net = get_nonnull_network (client->conn, args->net);
    if (net == NULL) {
        remoteDispatchError (client, req, "%s", _("network not found"));
        return -2;
    }

    if (virNetworkDestroy (net) == -1) {
        virNetworkFree(net);
        return -1;
    }
    virNetworkFree(net);
    return 0;
}

static int
remoteDispatchNetworkDumpXml (struct qemud_server *server ATTRIBUTE_UNUSED,
                              struct qemud_client *client,
                              remote_message_header *req,
                              remote_network_dump_xml_args *args,
                              remote_network_dump_xml_ret *ret)
{
    virNetworkPtr net;
    CHECK_CONN(client);

    net = get_nonnull_network (client->conn, args->net);
    if (net == NULL) {
        remoteDispatchError (client, req, "%s", _("network not found"));
        return -2;
    }

    /* remoteDispatchClientRequest will free this. */
    ret->xml = virNetworkGetXMLDesc (net, args->flags);
    if (!ret->xml) {
        virNetworkFree(net);
        return -1;
    }
    virNetworkFree(net);
    return 0;
}

static int
remoteDispatchNetworkGetAutostart (struct qemud_server *server ATTRIBUTE_UNUSED,
                                   struct qemud_client *client,
                                   remote_message_header *req,
                                   remote_network_get_autostart_args *args,
                                   remote_network_get_autostart_ret *ret)
{
    virNetworkPtr net;
    CHECK_CONN(client);

    net = get_nonnull_network (client->conn, args->net);
    if (net == NULL) {
        remoteDispatchError (client, req, "%s", _("network not found"));
        return -2;
    }

    if (virNetworkGetAutostart (net, &ret->autostart) == -1) {
        virNetworkFree(net);
        return -1;
    }
    virNetworkFree(net);
    return 0;
}

static int
remoteDispatchNetworkGetBridgeName (struct qemud_server *server ATTRIBUTE_UNUSED,
                                    struct qemud_client *client,
                                    remote_message_header *req,
                                    remote_network_get_bridge_name_args *args,
                                    remote_network_get_bridge_name_ret *ret)
{
    virNetworkPtr net;
    CHECK_CONN(client);

    net = get_nonnull_network (client->conn, args->net);
    if (net == NULL) {
        remoteDispatchError (client, req, "%s", _("network not found"));
        return -2;
    }

    /* remoteDispatchClientRequest will free this. */
    ret->name = virNetworkGetBridgeName (net);
    if (!ret->name) {
        virNetworkFree(net);
        return -1;
    }
    virNetworkFree(net);
    return 0;
}

static int
remoteDispatchNetworkLookupByName (struct qemud_server *server ATTRIBUTE_UNUSED,
                                   struct qemud_client *client,
                                   remote_message_header *req,
                                   remote_network_lookup_by_name_args *args,
                                   remote_network_lookup_by_name_ret *ret)
{
    virNetworkPtr net;
    CHECK_CONN(client);

    net = virNetworkLookupByName (client->conn, args->name);
    if (net == NULL) return -1;

    make_nonnull_network (&ret->net, net);
    virNetworkFree(net);
    return 0;
}

static int
remoteDispatchNetworkLookupByUuid (struct qemud_server *server ATTRIBUTE_UNUSED,
                                   struct qemud_client *client,
                                   remote_message_header *req,
                                   remote_network_lookup_by_uuid_args *args,
                                   remote_network_lookup_by_uuid_ret *ret)
{
    virNetworkPtr net;
    CHECK_CONN(client);

    net = virNetworkLookupByUUID (client->conn, (unsigned char *) args->uuid);
    if (net == NULL) return -1;

    make_nonnull_network (&ret->net, net);
    virNetworkFree(net);
    return 0;
}

static int
remoteDispatchNetworkSetAutostart (struct qemud_server *server ATTRIBUTE_UNUSED,
                                   struct qemud_client *client,
                                   remote_message_header *req,
                                   remote_network_set_autostart_args *args,
                                   void *ret ATTRIBUTE_UNUSED)
{
    virNetworkPtr net;
    CHECK_CONN(client);

    net = get_nonnull_network (client->conn, args->net);
    if (net == NULL) {
        remoteDispatchError (client, req, "%s", _("network not found"));
        return -2;
    }

    if (virNetworkSetAutostart (net, args->autostart) == -1) {
        virNetworkFree(net);
        return -1;
    }
    virNetworkFree(net);
    return 0;
}

static int
remoteDispatchNetworkUndefine (struct qemud_server *server ATTRIBUTE_UNUSED,
                               struct qemud_client *client,
                               remote_message_header *req,
                               remote_network_undefine_args *args,
                               void *ret ATTRIBUTE_UNUSED)
{
    virNetworkPtr net;
    CHECK_CONN(client);

    net = get_nonnull_network (client->conn, args->net);
    if (net == NULL) {
        remoteDispatchError (client, req, "%s", _("network not found"));
        return -2;
    }

    if (virNetworkUndefine (net) == -1) {
        virNetworkFree(net);
        return -1;
    }
    virNetworkFree(net);
    return 0;
}

static int
remoteDispatchNumOfDefinedNetworks (struct qemud_server *server ATTRIBUTE_UNUSED,
                                    struct qemud_client *client,
                                    remote_message_header *req,
                                    void *args ATTRIBUTE_UNUSED,
                                    remote_num_of_defined_networks_ret *ret)
{
    CHECK_CONN(client);

    ret->num = virConnectNumOfDefinedNetworks (client->conn);
    if (ret->num == -1) return -1;

    return 0;
}

static int
remoteDispatchNumOfDomains (struct qemud_server *server ATTRIBUTE_UNUSED,
                            struct qemud_client *client,
                            remote_message_header *req,
                            void *args ATTRIBUTE_UNUSED,
                            remote_num_of_domains_ret *ret)
{
    CHECK_CONN(client);

    ret->num = virConnectNumOfDomains (client->conn);
    if (ret->num == -1) return -1;

    return 0;
}

static int
remoteDispatchNumOfNetworks (struct qemud_server *server ATTRIBUTE_UNUSED,
                             struct qemud_client *client,
                             remote_message_header *req,
                             void *args ATTRIBUTE_UNUSED,
                             remote_num_of_networks_ret *ret)
{
    CHECK_CONN(client);

    ret->num = virConnectNumOfNetworks (client->conn);
    if (ret->num == -1) return -1;

    return 0;
}


static int
remoteDispatchAuthList (struct qemud_server *server ATTRIBUTE_UNUSED,
                        struct qemud_client *client,
                        remote_message_header *req ATTRIBUTE_UNUSED,
                        void *args ATTRIBUTE_UNUSED,
                        remote_auth_list_ret *ret)
{
    ret->types.types_len = 1;
    if ((ret->types.types_val = calloc (ret->types.types_len, sizeof (*(ret->types.types_val)))) == NULL) {
        remoteDispatchSendError(client, req, VIR_ERR_NO_MEMORY, "auth types");
        return -2;
    }
    ret->types.types_val[0] = client->auth;
    return 0;
}


#if HAVE_SASL
/*
 * NB, keep in sync with similar method in src/remote_internal.c
 */
static char *addrToString(struct qemud_client *client,
                          remote_message_header *req,
                          struct sockaddr_storage *sa, socklen_t salen) {
    char host[1024], port[20];
    char *addr;
    int err;

    if ((err = getnameinfo((struct sockaddr *)sa, salen,
                           host, sizeof(host),
                           port, sizeof(port),
                           NI_NUMERICHOST | NI_NUMERICSERV)) != 0) {
        remoteDispatchError(client, req,
                            _("Cannot resolve address %d: %s"),
                            err, gai_strerror(err));
        return NULL;
    }

    addr = malloc(strlen(host) + 1 + strlen(port) + 1);
    if (!addr) {
        remoteDispatchError(client, req, "%s", _("cannot allocate address"));
        return NULL;
    }

    strcpy(addr, host);
    strcat(addr, ";");
    strcat(addr, port);
    return addr;
}


/*
 * Initializes the SASL session in prepare for authentication
 * and gives the client a list of allowed mechansims to choose
 *
 * XXX callbacks for stuff like password verification ?
 */
static int
remoteDispatchAuthSaslInit (struct qemud_server *server ATTRIBUTE_UNUSED,
                            struct qemud_client *client,
                            remote_message_header *req,
                            void *args ATTRIBUTE_UNUSED,
                            remote_auth_sasl_init_ret *ret)
{
    const char *mechlist = NULL;
    sasl_security_properties_t secprops;
    int err;
    struct sockaddr_storage sa;
    socklen_t salen;
    char *localAddr, *remoteAddr;

    REMOTE_DEBUG("Initialize SASL auth %d", client->fd);
    if (client->auth != REMOTE_AUTH_SASL ||
        client->saslconn != NULL) {
        qemudLog(QEMUD_ERR, "%s", _("client tried invalid SASL init request"));
        remoteDispatchFailAuth(client, req);
        return -2;
    }

    /* Get local address in form  IPADDR:PORT */
    salen = sizeof(sa);
    if (getsockname(client->fd, (struct sockaddr*)&sa, &salen) < 0) {
        remoteDispatchError(client, req,
                            _("failed to get sock address %d (%s)"),
                            errno, strerror(errno));
        return -2;
    }
    if ((localAddr = addrToString(client, req, &sa, salen)) == NULL) {
        return -2;
    }

    /* Get remote address in form  IPADDR:PORT */
    salen = sizeof(sa);
    if (getpeername(client->fd, (struct sockaddr*)&sa, &salen) < 0) {
        remoteDispatchError(client, req, _("failed to get peer address %d (%s)"),
                            errno, strerror(errno));
        free(localAddr);
        return -2;
    }
    if ((remoteAddr = addrToString(client, req, &sa, salen)) == NULL) {
        free(localAddr);
        return -2;
    }

    err = sasl_server_new("libvirt",
                          NULL, /* FQDN - just delegates to gethostname */
                          NULL, /* User realm */
                          localAddr,
                          remoteAddr,
                          NULL, /* XXX Callbacks */
                          SASL_SUCCESS_DATA,
                          &client->saslconn);
    free(localAddr);
    free(remoteAddr);
    if (err != SASL_OK) {
        qemudLog(QEMUD_ERR, _("sasl context setup failed %d (%s)"),
                 err, sasl_errstring(err, NULL, NULL));
        remoteDispatchFailAuth(client, req);
        client->saslconn = NULL;
        return -2;
    }

    /* Inform SASL that we've got an external SSF layer from TLS */
    if (client->type == QEMUD_SOCK_TYPE_TLS) {
        gnutls_cipher_algorithm_t cipher;
        sasl_ssf_t ssf;

        cipher = gnutls_cipher_get(client->tlssession);
        if (!(ssf = (sasl_ssf_t)gnutls_cipher_get_key_size(cipher))) {
            qemudLog(QEMUD_ERR, "%s", _("cannot TLS get cipher size"));
            remoteDispatchFailAuth(client, req);
            sasl_dispose(&client->saslconn);
            client->saslconn = NULL;
            return -2;
        }
        ssf *= 8; /* tls key size is bytes, sasl wants bits */

        err = sasl_setprop(client->saslconn, SASL_SSF_EXTERNAL, &ssf);
        if (err != SASL_OK) {
            qemudLog(QEMUD_ERR, _("cannot set SASL external SSF %d (%s)"),
                     err, sasl_errstring(err, NULL, NULL));
            remoteDispatchFailAuth(client, req);
            sasl_dispose(&client->saslconn);
            client->saslconn = NULL;
            return -2;
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
        qemudLog(QEMUD_ERR, _("cannot set SASL security props %d (%s)"),
                 err, sasl_errstring(err, NULL, NULL));
        remoteDispatchFailAuth(client, req);
        sasl_dispose(&client->saslconn);
        client->saslconn = NULL;
        return -2;
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
        qemudLog(QEMUD_ERR, _("cannot list SASL mechanisms %d (%s)"),
                 err, sasl_errdetail(client->saslconn));
        remoteDispatchFailAuth(client, req);
        sasl_dispose(&client->saslconn);
        client->saslconn = NULL;
        return -2;
    }
    REMOTE_DEBUG("Available mechanisms for client: '%s'", mechlist);
    ret->mechlist = strdup(mechlist);
    if (!ret->mechlist) {
        qemudLog(QEMUD_ERR, "%s", _("cannot allocate mechlist"));
        remoteDispatchFailAuth(client, req);
        sasl_dispose(&client->saslconn);
        client->saslconn = NULL;
        return -2;
    }

    return 0;
}


/* We asked for an SSF layer, so sanity check that we actually
 * got what we asked for */
static int
remoteSASLCheckSSF (struct qemud_client *client,
                    remote_message_header *req) {
    const void *val;
    int err, ssf;

    if (client->type == QEMUD_SOCK_TYPE_TLS ||
        client->type == QEMUD_SOCK_TYPE_UNIX)
        return 0; /* TLS or UNIX domain sockets trivially OK */

    err = sasl_getprop(client->saslconn, SASL_SSF, &val);
    if (err != SASL_OK) {
        qemudLog(QEMUD_ERR, _("cannot query SASL ssf on connection %d (%s)"),
                 err, sasl_errstring(err, NULL, NULL));
        remoteDispatchFailAuth(client, req);
        sasl_dispose(&client->saslconn);
        client->saslconn = NULL;
        return -1;
    }
    ssf = *(const int *)val;
    REMOTE_DEBUG("negotiated an SSF of %d", ssf);
    if (ssf < 56) { /* 56 is good for Kerberos */
        qemudLog(QEMUD_ERR, _("negotiated SSF %d was not strong enough"), ssf);
        remoteDispatchFailAuth(client, req);
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
                       remote_message_header *req) {
    const void *val;
    int err;
    char **wildcards;

    err = sasl_getprop(client->saslconn, SASL_USERNAME, &val);
    if (err != SASL_OK) {
        qemudLog(QEMUD_ERR,
                 _("cannot query SASL username on connection %d (%s)"),
                 err, sasl_errstring(err, NULL, NULL));
        remoteDispatchFailAuth(client, req);
        sasl_dispose(&client->saslconn);
        client->saslconn = NULL;
        return -1;
    }
    if (val == NULL) {
        qemudLog(QEMUD_ERR, "%s", _("no client username was found"));
        remoteDispatchFailAuth(client, req);
        sasl_dispose(&client->saslconn);
        client->saslconn = NULL;
        return -1;
    }
    REMOTE_DEBUG("SASL client username %s", (const char *)val);

    client->saslUsername = strdup((const char*)val);
    if (client->saslUsername == NULL) {
        qemudLog(QEMUD_ERR, "%s", _("out of memory copying username"));
        remoteDispatchFailAuth(client, req);
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
    qemudLog(QEMUD_ERR, _("SASL client %s not allowed in whitelist"),
             client->saslUsername);
    remoteDispatchFailAuth(client, req);
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
                             remote_message_header *req,
                             remote_auth_sasl_start_args *args,
                             remote_auth_sasl_start_ret *ret)
{
    const char *serverout;
    unsigned int serveroutlen;
    int err;

    REMOTE_DEBUG("Start SASL auth %d", client->fd);
    if (client->auth != REMOTE_AUTH_SASL ||
        client->saslconn == NULL) {
        qemudLog(QEMUD_ERR, "%s", _("client tried invalid SASL start request"));
        remoteDispatchFailAuth(client, req);
        return -2;
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
        qemudLog(QEMUD_ERR, _("sasl start failed %d (%s)"),
                 err, sasl_errdetail(client->saslconn));
        sasl_dispose(&client->saslconn);
        client->saslconn = NULL;
        remoteDispatchFailAuth(client, req);
        return -2;
    }
    if (serveroutlen > REMOTE_AUTH_SASL_DATA_MAX) {
        qemudLog(QEMUD_ERR, _("sasl start reply data too long %d"),
                 serveroutlen);
        sasl_dispose(&client->saslconn);
        client->saslconn = NULL;
        remoteDispatchFailAuth(client, req);
        return -2;
    }

    /* NB, distinction of NULL vs "" is *critical* in SASL */
    if (serverout) {
        ret->data.data_val = malloc(serveroutlen);
        if (!ret->data.data_val) {
            remoteDispatchError (client, req,
                                 "%s", _("out of memory allocating array"));
            return -2;
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
        if (remoteSASLCheckSSF(client, req) < 0)
            return -2;

        /* Check username whitelist ACL */
        if (remoteSASLCheckAccess(server, client, req) < 0)
            return -2;

        REMOTE_DEBUG("Authentication successful %d", client->fd);
        ret->complete = 1;
        client->auth = REMOTE_AUTH_NONE;
    }

    return 0;
}


static int
remoteDispatchAuthSaslStep (struct qemud_server *server,
                            struct qemud_client *client,
                            remote_message_header *req,
                            remote_auth_sasl_step_args *args,
                            remote_auth_sasl_step_ret *ret)
{
    const char *serverout;
    unsigned int serveroutlen;
    int err;

    REMOTE_DEBUG("Step SASL auth %d", client->fd);
    if (client->auth != REMOTE_AUTH_SASL ||
        client->saslconn == NULL) {
        qemudLog(QEMUD_ERR, "%s", _("client tried invalid SASL start request"));
        remoteDispatchFailAuth(client, req);
        return -2;
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
        qemudLog(QEMUD_ERR, _("sasl step failed %d (%s)"),
                 err, sasl_errdetail(client->saslconn));
        sasl_dispose(&client->saslconn);
        client->saslconn = NULL;
        remoteDispatchFailAuth(client, req);
        return -2;
    }

    if (serveroutlen > REMOTE_AUTH_SASL_DATA_MAX) {
        qemudLog(QEMUD_ERR, _("sasl step reply data too long %d"),
                 serveroutlen);
        sasl_dispose(&client->saslconn);
        client->saslconn = NULL;
        remoteDispatchFailAuth(client, req);
        return -2;
    }

    /* NB, distinction of NULL vs "" is *critical* in SASL */
    if (serverout) {
        ret->data.data_val = malloc(serveroutlen);
        if (!ret->data.data_val) {
            remoteDispatchError (client, req,
                                 "%s", _("out of memory allocating array"));
            return -2;
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
        if (remoteSASLCheckSSF(client, req) < 0)
            return -2;

        /* Check username whitelist ACL */
        if (remoteSASLCheckAccess(server, client, req) < 0)
            return -2;

        REMOTE_DEBUG("Authentication successful %d", client->fd);
        ret->complete = 1;
        client->auth = REMOTE_AUTH_NONE;
    }

    return 0;
}


#else /* HAVE_SASL */
static int
remoteDispatchAuthSaslInit (struct qemud_server *server ATTRIBUTE_UNUSED,
                            struct qemud_client *client,
                            remote_message_header *req,
                            void *args ATTRIBUTE_UNUSED,
                            remote_auth_sasl_init_ret *ret ATTRIBUTE_UNUSED)
{
    qemudLog(QEMUD_ERR, "%s", _("client tried unsupported SASL init request"));
    remoteDispatchFailAuth(client, req);
    return -1;
}

static int
remoteDispatchAuthSaslStart (struct qemud_server *server ATTRIBUTE_UNUSED,
                             struct qemud_client *client,
                             remote_message_header *req,
                             remote_auth_sasl_start_args *args ATTRIBUTE_UNUSED,
                             remote_auth_sasl_start_ret *ret ATTRIBUTE_UNUSED)
{
    qemudLog(QEMUD_ERR, "%s", _("client tried unsupported SASL start request"));
    remoteDispatchFailAuth(client, req);
    return -1;
}

static int
remoteDispatchAuthSaslStep (struct qemud_server *server ATTRIBUTE_UNUSED,
                            struct qemud_client *client,
                            remote_message_header *req,
                            remote_auth_sasl_step_args *args ATTRIBUTE_UNUSED,
                            remote_auth_sasl_step_ret *ret ATTRIBUTE_UNUSED)
{
    qemudLog(QEMUD_ERR, "%s", _("client tried unsupported SASL step request"));
    remoteDispatchFailAuth(client, req);
    return -1;
}
#endif /* HAVE_SASL */


#if HAVE_POLKIT
static int
remoteDispatchAuthPolkit (struct qemud_server *server ATTRIBUTE_UNUSED,
                          struct qemud_client *client,
                          remote_message_header *req,
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
    const char *action = client->readonly ?
        "org.libvirt.unix.monitor" :
        "org.libvirt.unix.manage";

    REMOTE_DEBUG("Start PolicyKit auth %d", client->fd);
    if (client->auth != REMOTE_AUTH_POLKIT) {
        qemudLog(QEMUD_ERR,
                 "%s", _("client tried invalid PolicyKit init request"));
        remoteDispatchFailAuth(client, req);
        return -2;
    }

    if (qemudGetSocketIdentity(client->fd, &callerUid, &callerPid) < 0) {
        qemudLog(QEMUD_ERR, "%s", _("cannot get peer socket identity"));
        remoteDispatchFailAuth(client, req);
        return -2;
    }

    qemudLog(QEMUD_INFO, _("Checking PID %d running as %d"),
             callerPid, callerUid);
    dbus_error_init(&err);
    if (!(pkcaller = polkit_caller_new_from_pid(server->sysbus,
                                                callerPid, &err))) {
        qemudLog(QEMUD_ERR, _("Failed to lookup policy kit caller: %s"),
                 err.message);
        dbus_error_free(&err);
        remoteDispatchFailAuth(client, req);
        return -2;
    }

    if (!(pkaction = polkit_action_new())) {
        qemudLog(QEMUD_ERR, _("Failed to create polkit action %s\n"),
                 strerror(errno));
        polkit_caller_unref(pkcaller);
        remoteDispatchFailAuth(client, req);
        return -2;
    }
    polkit_action_set_action_id(pkaction, action);

    if (!(pkcontext = polkit_context_new()) ||
        !polkit_context_init(pkcontext, &pkerr)) {
        qemudLog(QEMUD_ERR, _("Failed to create polkit context %s\n"),
                 (pkerr ? polkit_error_get_error_message(pkerr)
                  : strerror(errno)));
        if (pkerr)
            polkit_error_free(pkerr);
        polkit_caller_unref(pkcaller);
        polkit_action_unref(pkaction);
        dbus_error_free(&err);
        remoteDispatchFailAuth(client, req);
        return -2;
    }

#if HAVE_POLKIT_CONTEXT_IS_CALLER_AUTHORIZED
    pkresult = polkit_context_is_caller_authorized(pkcontext,
                                                   pkaction,
                                                   pkcaller,
                                                   0,
                                                   &pkerr);
    if (pkerr && polkit_error_is_set(pkerr)) {
        qemudLog(QEMUD_ERR,
                 _("Policy kit failed to check authorization %d %s"),
                 polkit_error_get_error_code(pkerr),
                 polkit_error_get_error_message(pkerr));
        remoteDispatchFailAuth(client, req);
        return -2;
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
        qemudLog(QEMUD_ERR,
                 _("Policy kit denied action %s from pid %d, uid %d,"
                   " result: %s\n"),
                 action, callerPid, callerUid,
                 polkit_result_to_string_representation(pkresult));
        remoteDispatchFailAuth(client, req);
        return -2;
    }
    qemudLog(QEMUD_INFO,
             _("Policy allowed action %s from pid %d, uid %d, result %s"),
             action, callerPid, callerUid,
             polkit_result_to_string_representation(pkresult));
    ret->complete = 1;
    client->auth = REMOTE_AUTH_NONE;

    return 0;
}

#else /* HAVE_POLKIT */

static int
remoteDispatchAuthPolkit (struct qemud_server *server ATTRIBUTE_UNUSED,
                              struct qemud_client *client,
                              remote_message_header *req,
                              void *args ATTRIBUTE_UNUSED,
                              remote_auth_polkit_ret *ret ATTRIBUTE_UNUSED)
{
    qemudLog(QEMUD_ERR,
             "%s", _("client tried unsupported PolicyKit init request"));
    remoteDispatchFailAuth(client, req);
    return -1;
}
#endif /* HAVE_POLKIT */


/***************************************************************
 *     STORAGE POOL APIS
 ***************************************************************/


static int
remoteDispatchListDefinedStoragePools (struct qemud_server *server ATTRIBUTE_UNUSED,
                                       struct qemud_client *client,
                                       remote_message_header *req,
                                       remote_list_defined_storage_pools_args *args,
                                       remote_list_defined_storage_pools_ret *ret)
{
    CHECK_CONN(client);

    if (args->maxnames > REMOTE_NETWORK_NAME_LIST_MAX) {
        remoteDispatchError (client, req,
                             "%s", _("maxnames > REMOTE_NETWORK_NAME_LIST_MAX"));
        return -2;
    }

    /* Allocate return buffer. */
    ret->names.names_val = calloc (args->maxnames, sizeof (char *));

    ret->names.names_len =
        virConnectListDefinedStoragePools (client->conn,
                                       ret->names.names_val, args->maxnames);
    if (ret->names.names_len == -1) return -1;

    return 0;
}

static int
remoteDispatchListStoragePools (struct qemud_server *server ATTRIBUTE_UNUSED,
                                struct qemud_client *client,
                                remote_message_header *req,
                                remote_list_storage_pools_args *args,
                                remote_list_storage_pools_ret *ret)
{
    CHECK_CONN(client);

    if (args->maxnames > REMOTE_STORAGE_POOL_NAME_LIST_MAX) {
        remoteDispatchError (client, req,
                             "%s", _("maxnames > REMOTE_STORAGE_POOL_NAME_LIST_MAX"));
        return -2;
    }

    /* Allocate return buffer. */
    ret->names.names_val = calloc (args->maxnames, sizeof (char *));

    ret->names.names_len =
        virConnectListStoragePools (client->conn,
                                ret->names.names_val, args->maxnames);
    if (ret->names.names_len == -1) return -1;

    return 0;
}

static int
remoteDispatchStoragePoolCreate (struct qemud_server *server ATTRIBUTE_UNUSED,
                                 struct qemud_client *client,
                                 remote_message_header *req,
                                 remote_storage_pool_create_args *args,
                                 void *ret ATTRIBUTE_UNUSED)
{
    virStoragePoolPtr pool;
    CHECK_CONN(client);

    pool = get_nonnull_storage_pool (client->conn, args->pool);
    if (pool == NULL) {
        remoteDispatchError (client, req, "%s", _("storage_pool not found"));
        return -2;
    }

    if (virStoragePoolCreate (pool, args->flags) == -1) {
        virStoragePoolFree(pool);
        return -1;
    }
    virStoragePoolFree(pool);
    return 0;
}

static int
remoteDispatchStoragePoolCreateXml (struct qemud_server *server ATTRIBUTE_UNUSED,
                                    struct qemud_client *client,
                                    remote_message_header *req,
                                    remote_storage_pool_create_xml_args *args,
                                    remote_storage_pool_create_xml_ret *ret)
{
    virStoragePoolPtr pool;
    CHECK_CONN(client);

    pool = virStoragePoolCreateXML (client->conn, args->xml, args->flags);
    if (pool == NULL) return -1;

    make_nonnull_storage_pool (&ret->pool, pool);
    virStoragePoolFree(pool);
    return 0;
}

static int
remoteDispatchStoragePoolDefineXml (struct qemud_server *server ATTRIBUTE_UNUSED,
                                    struct qemud_client *client,
                                    remote_message_header *req,
                                    remote_storage_pool_define_xml_args *args,
                                    remote_storage_pool_define_xml_ret *ret)
{
    virStoragePoolPtr pool;
    CHECK_CONN(client);

    pool = virStoragePoolDefineXML (client->conn, args->xml, args->flags);
    if (pool == NULL) return -1;

    make_nonnull_storage_pool (&ret->pool, pool);
    virStoragePoolFree(pool);
    return 0;
}

static int
remoteDispatchStoragePoolBuild (struct qemud_server *server ATTRIBUTE_UNUSED,
                                 struct qemud_client *client,
                                 remote_message_header *req,
                                 remote_storage_pool_build_args *args,
                                 void *ret ATTRIBUTE_UNUSED)
{
    virStoragePoolPtr pool;
    CHECK_CONN(client);

    pool = get_nonnull_storage_pool (client->conn, args->pool);
    if (pool == NULL) {
        remoteDispatchError (client, req, "%s", _("storage_pool not found"));
        return -2;
    }

    if (virStoragePoolBuild (pool, args->flags) == -1) {
        virStoragePoolFree(pool);
        return -1;
    }
    virStoragePoolFree(pool);
    return 0;
}


static int
remoteDispatchStoragePoolDestroy (struct qemud_server *server ATTRIBUTE_UNUSED,
                                  struct qemud_client *client,
                                  remote_message_header *req,
                                  remote_storage_pool_destroy_args *args,
                                  void *ret ATTRIBUTE_UNUSED)
{
    virStoragePoolPtr pool;
    CHECK_CONN(client);

    pool = get_nonnull_storage_pool (client->conn, args->pool);
    if (pool == NULL) {
        remoteDispatchError (client, req, "%s", _("storage_pool not found"));
        return -2;
    }

    if (virStoragePoolDestroy (pool) == -1) {
        virStoragePoolFree(pool);
        return -1;
    }
    virStoragePoolFree(pool);
    return 0;
}

static int
remoteDispatchStoragePoolDelete (struct qemud_server *server ATTRIBUTE_UNUSED,
                                 struct qemud_client *client,
                                 remote_message_header *req,
                                 remote_storage_pool_delete_args *args,
                                 void *ret ATTRIBUTE_UNUSED)
{
    virStoragePoolPtr pool;
    CHECK_CONN(client);

    pool = get_nonnull_storage_pool (client->conn, args->pool);
    if (pool == NULL) {
        remoteDispatchError (client, req, "%s", _("storage_pool not found"));
        return -2;
    }

    if (virStoragePoolDelete (pool, args->flags) == -1) {
        virStoragePoolFree(pool);
        return -1;
    }
    virStoragePoolFree(pool);
    return 0;
}

static int
remoteDispatchStoragePoolRefresh (struct qemud_server *server ATTRIBUTE_UNUSED,
                                  struct qemud_client *client,
                                  remote_message_header *req,
                                  remote_storage_pool_refresh_args *args,
                                  void *ret ATTRIBUTE_UNUSED)
{
    virStoragePoolPtr pool;
    CHECK_CONN(client);

    pool = get_nonnull_storage_pool (client->conn, args->pool);
    if (pool == NULL) {
        remoteDispatchError (client, req, "%s", _("storage_pool not found"));
        return -2;
    }

    if (virStoragePoolRefresh (pool, args->flags) == -1) {
        virStoragePoolFree(pool);
        return -1;
    }
    virStoragePoolFree(pool);
    return 0;
}

static int
remoteDispatchStoragePoolGetInfo (struct qemud_server *server ATTRIBUTE_UNUSED,
                                  struct qemud_client *client,
                                  remote_message_header *req,
                                  remote_storage_pool_get_info_args *args,
                                  remote_storage_pool_get_info_ret *ret)
{
    virStoragePoolPtr pool;
    virStoragePoolInfo info;
    CHECK_CONN(client);

    pool = get_nonnull_storage_pool (client->conn, args->pool);
    if (pool == NULL) {
        remoteDispatchError (client, req, "%s", _("storage_pool not found"));
        return -2;
    }

    if (virStoragePoolGetInfo (pool, &info) == -1) {
        virStoragePoolFree(pool);
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
                                  struct qemud_client *client,
                                  remote_message_header *req,
                                  remote_storage_pool_dump_xml_args *args,
                                  remote_storage_pool_dump_xml_ret *ret)
{
    virStoragePoolPtr pool;
    CHECK_CONN(client);

    pool = get_nonnull_storage_pool (client->conn, args->pool);
    if (pool == NULL) {
        remoteDispatchError (client, req, "%s", _("storage_pool not found"));
        return -2;
    }

    /* remoteDispatchClientRequest will free this. */
    ret->xml = virStoragePoolGetXMLDesc (pool, args->flags);
    if (!ret->xml) {
        virStoragePoolFree(pool);
        return -1;
    }
    virStoragePoolFree(pool);
    return 0;
}

static int
remoteDispatchStoragePoolGetAutostart (struct qemud_server *server ATTRIBUTE_UNUSED,
                                       struct qemud_client *client,
                                       remote_message_header *req,
                                       remote_storage_pool_get_autostart_args *args,
                                       remote_storage_pool_get_autostart_ret *ret)
{
    virStoragePoolPtr pool;
    CHECK_CONN(client);

    pool = get_nonnull_storage_pool (client->conn, args->pool);
    if (pool == NULL) {
        remoteDispatchError (client, req, "%s", _("storage_pool not found"));
        return -2;
    }

    if (virStoragePoolGetAutostart (pool, &ret->autostart) == -1) {
        virStoragePoolFree(pool);
        return -1;
    }
    virStoragePoolFree(pool);
    return 0;
}


static int
remoteDispatchStoragePoolLookupByName (struct qemud_server *server ATTRIBUTE_UNUSED,
                                       struct qemud_client *client,
                                       remote_message_header *req,
                                       remote_storage_pool_lookup_by_name_args *args,
                                       remote_storage_pool_lookup_by_name_ret *ret)
{
    virStoragePoolPtr pool;
    CHECK_CONN(client);

    pool = virStoragePoolLookupByName (client->conn, args->name);
    if (pool == NULL) return -1;

    make_nonnull_storage_pool (&ret->pool, pool);
    virStoragePoolFree(pool);
    return 0;
}

static int
remoteDispatchStoragePoolLookupByUuid (struct qemud_server *server ATTRIBUTE_UNUSED,
                                       struct qemud_client *client,
                                       remote_message_header *req,
                                       remote_storage_pool_lookup_by_uuid_args *args,
                                       remote_storage_pool_lookup_by_uuid_ret *ret)
{
    virStoragePoolPtr pool;
    CHECK_CONN(client);

    pool = virStoragePoolLookupByUUID (client->conn, (unsigned char *) args->uuid);
    if (pool == NULL) return -1;

    make_nonnull_storage_pool (&ret->pool, pool);
    virStoragePoolFree(pool);
    return 0;
}

static int
remoteDispatchStoragePoolLookupByVolume (struct qemud_server *server ATTRIBUTE_UNUSED,
                                         struct qemud_client *client,
                                         remote_message_header *req,
                                         remote_storage_pool_lookup_by_volume_args *args,
                                         remote_storage_pool_lookup_by_volume_ret *ret)
{
    virStoragePoolPtr pool;
    virStorageVolPtr vol;
    CHECK_CONN(client);

    vol = get_nonnull_storage_vol (client->conn, args->vol);

    pool = virStoragePoolLookupByVolume (vol);
    virStorageVolFree(vol);
    if (pool == NULL) return -1;

    make_nonnull_storage_pool (&ret->pool, pool);
    virStoragePoolFree(pool);
    return 0;
}

static int
remoteDispatchStoragePoolSetAutostart (struct qemud_server *server ATTRIBUTE_UNUSED,
                                       struct qemud_client *client,
                                       remote_message_header *req,
                                       remote_storage_pool_set_autostart_args *args,
                                       void *ret ATTRIBUTE_UNUSED)
{
    virStoragePoolPtr pool;
    CHECK_CONN(client);

    pool = get_nonnull_storage_pool (client->conn, args->pool);
    if (pool == NULL) {
        remoteDispatchError (client, req, "%s", _("storage_pool not found"));
        return -2;
    }

    if (virStoragePoolSetAutostart (pool, args->autostart) == -1) {
        virStoragePoolFree(pool);
        return -1;
    }
    virStoragePoolFree(pool);
    return 0;
}

static int
remoteDispatchStoragePoolUndefine (struct qemud_server *server ATTRIBUTE_UNUSED,
                                   struct qemud_client *client,
                                   remote_message_header *req,
                                   remote_storage_pool_undefine_args *args,
                                   void *ret ATTRIBUTE_UNUSED)
{
    virStoragePoolPtr pool;
    CHECK_CONN(client);

    pool = get_nonnull_storage_pool (client->conn, args->pool);
    if (pool == NULL) {
        remoteDispatchError (client, req, "%s", _("storage_pool not found"));
        return -2;
    }

    if (virStoragePoolUndefine (pool) == -1) {
        virStoragePoolFree(pool);
        return -1;
    }
    virStoragePoolFree(pool);
    return 0;
}

static int
remoteDispatchNumOfStoragePools (struct qemud_server *server ATTRIBUTE_UNUSED,
                                 struct qemud_client *client,
                                 remote_message_header *req,
                                 void *args ATTRIBUTE_UNUSED,
                                 remote_num_of_storage_pools_ret *ret)
{
    CHECK_CONN(client);

    ret->num = virConnectNumOfStoragePools (client->conn);
    if (ret->num == -1) return -1;

    return 0;
}

static int
remoteDispatchNumOfDefinedStoragePools (struct qemud_server *server ATTRIBUTE_UNUSED,
                                        struct qemud_client *client,
                                        remote_message_header *req,
                                        void *args ATTRIBUTE_UNUSED,
                                        remote_num_of_defined_storage_pools_ret *ret)
{
    CHECK_CONN(client);

    ret->num = virConnectNumOfDefinedStoragePools (client->conn);
    if (ret->num == -1) return -1;

    return 0;
}

static int
remoteDispatchStoragePoolListVolumes (struct qemud_server *server ATTRIBUTE_UNUSED,
                                      struct qemud_client *client,
                                      remote_message_header *req,
                                      remote_storage_pool_list_volumes_args *args,
                                      remote_storage_pool_list_volumes_ret *ret)
{
    virStoragePoolPtr pool;
    CHECK_CONN(client);

    if (args->maxnames > REMOTE_STORAGE_VOL_NAME_LIST_MAX) {
        remoteDispatchError (client, req,
                             "%s", _("maxnames > REMOTE_STORAGE_VOL_NAME_LIST_MAX"));
        return -2;
    }

    pool = get_nonnull_storage_pool (client->conn, args->pool);
    if (pool == NULL) {
        remoteDispatchError (client, req, "%s", _("storage_pool not found"));
        return -2;
    }

    /* Allocate return buffer. */
    ret->names.names_val = calloc (args->maxnames, sizeof (char *));

    ret->names.names_len =
        virStoragePoolListVolumes (pool,
                                   ret->names.names_val, args->maxnames);
    virStoragePoolFree(pool);
    if (ret->names.names_len == -1) return -1;

    return 0;
}


static int
remoteDispatchStoragePoolNumOfVolumes (struct qemud_server *server ATTRIBUTE_UNUSED,
                                       struct qemud_client *client,
                                       remote_message_header *req,
                                       remote_storage_pool_num_of_volumes_args *args,
                                       remote_storage_pool_num_of_volumes_ret *ret)
{
    virStoragePoolPtr pool;
    CHECK_CONN(client);

    pool = get_nonnull_storage_pool (client->conn, args->pool);
    if (pool == NULL) {
        remoteDispatchError (client, req, "%s", _("storage_pool not found"));
        return -2;
    }

    ret->num = virStoragePoolNumOfVolumes (pool);
    virStoragePoolFree(pool);
    if (ret->num == -1) return -1;

    return 0;
}


/***************************************************************
 *     STORAGE VOL APIS
 ***************************************************************/



static int
remoteDispatchStorageVolCreateXml (struct qemud_server *server ATTRIBUTE_UNUSED,
                                   struct qemud_client *client,
                                   remote_message_header *req,
                                   remote_storage_vol_create_xml_args *args,
                                   remote_storage_vol_create_xml_ret *ret)
{
    virStoragePoolPtr pool;
    virStorageVolPtr vol;
    CHECK_CONN(client);

    pool = get_nonnull_storage_pool (client->conn, args->pool);
    if (pool == NULL) {
        remoteDispatchError (client, req, "%s", _("storage_pool not found"));
        return -2;
    }

    vol = virStorageVolCreateXML (pool, args->xml, args->flags);
    virStoragePoolFree(pool);
    if (vol == NULL) return -1;

    make_nonnull_storage_vol (&ret->vol, vol);
    virStorageVolFree(vol);
    return 0;
}


static int
remoteDispatchStorageVolDelete (struct qemud_server *server ATTRIBUTE_UNUSED,
                                struct qemud_client *client,
                                remote_message_header *req,
                                remote_storage_vol_delete_args *args,
                                void *ret ATTRIBUTE_UNUSED)
{
    virStorageVolPtr vol;
    CHECK_CONN(client);

    vol = get_nonnull_storage_vol (client->conn, args->vol);
    if (vol == NULL) {
        remoteDispatchError (client, req, "%s", _("storage_vol not found"));
        return -2;
    }

    if (virStorageVolDelete (vol, args->flags) == -1) {
        virStorageVolFree(vol);
        return -1;
    }
    virStorageVolFree(vol);
    return 0;
}

static int
remoteDispatchStorageVolGetInfo (struct qemud_server *server ATTRIBUTE_UNUSED,
                                 struct qemud_client *client,
                                 remote_message_header *req,
                                 remote_storage_vol_get_info_args *args,
                                 remote_storage_vol_get_info_ret *ret)
{
    virStorageVolPtr vol;
    virStorageVolInfo info;
    CHECK_CONN(client);

    vol = get_nonnull_storage_vol (client->conn, args->vol);
    if (vol == NULL) {
        remoteDispatchError (client, req, "%s", _("storage_vol not found"));
        return -2;
    }

    if (virStorageVolGetInfo (vol, &info) == -1) {
        virStorageVolFree(vol);
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
                                 struct qemud_client *client,
                                 remote_message_header *req,
                                 remote_storage_vol_dump_xml_args *args,
                                 remote_storage_vol_dump_xml_ret *ret)
{
    virStorageVolPtr vol;
    CHECK_CONN(client);

    vol = get_nonnull_storage_vol (client->conn, args->vol);
    if (vol == NULL) {
        remoteDispatchError (client, req, "%s", _("storage_vol not found"));
        return -2;
    }

    /* remoteDispatchClientRequest will free this. */
    ret->xml = virStorageVolGetXMLDesc (vol, args->flags);
    if (!ret->xml) {
        virStorageVolFree(vol);
        return -1;
    }
    virStorageVolFree(vol);
    return 0;
}


static int
remoteDispatchStorageVolGetPath (struct qemud_server *server ATTRIBUTE_UNUSED,
                                 struct qemud_client *client,
                                 remote_message_header *req,
                                 remote_storage_vol_get_path_args *args,
                                 remote_storage_vol_get_path_ret *ret)
{
    virStorageVolPtr vol;
    CHECK_CONN(client);

    vol = get_nonnull_storage_vol (client->conn, args->vol);
    if (vol == NULL) {
        remoteDispatchError (client, req, "%s", _("storage_vol not found"));
        return -2;
    }

    /* remoteDispatchClientRequest will free this. */
    ret->name = virStorageVolGetPath (vol);
    if (!ret->name) {
        virStorageVolFree(vol);
        return -1;
    }
    virStorageVolFree(vol);
    return 0;
}


static int
remoteDispatchStorageVolLookupByName (struct qemud_server *server ATTRIBUTE_UNUSED,
                                      struct qemud_client *client,
                                      remote_message_header *req,
                                      remote_storage_vol_lookup_by_name_args *args,
                                      remote_storage_vol_lookup_by_name_ret *ret)
{
    virStoragePoolPtr pool;
    virStorageVolPtr vol;
    CHECK_CONN(client);

    pool = get_nonnull_storage_pool (client->conn, args->pool);
    if (pool == NULL) {
        remoteDispatchError (client, req, "%s", _("storage_pool not found"));
        return -2;
    }

    vol = virStorageVolLookupByName (pool, args->name);
    virStoragePoolFree(pool);
    if (vol == NULL) return -1;

    make_nonnull_storage_vol (&ret->vol, vol);
    virStorageVolFree(vol);
    return 0;
}

static int
remoteDispatchStorageVolLookupByKey (struct qemud_server *server ATTRIBUTE_UNUSED,
                                     struct qemud_client *client,
                                     remote_message_header *req,
                                     remote_storage_vol_lookup_by_key_args *args,
                                     remote_storage_vol_lookup_by_key_ret *ret)
{
    virStorageVolPtr vol;
    CHECK_CONN(client);

    vol = virStorageVolLookupByKey (client->conn, args->key);
    if (vol == NULL) return -1;

    make_nonnull_storage_vol (&ret->vol, vol);
    virStorageVolFree(vol);
    return 0;
}


static int
remoteDispatchStorageVolLookupByPath (struct qemud_server *server ATTRIBUTE_UNUSED,
                                      struct qemud_client *client,
                                      remote_message_header *req,
                                      remote_storage_vol_lookup_by_path_args *args,
                                      remote_storage_vol_lookup_by_path_ret *ret)
{
    virStorageVolPtr vol;
    CHECK_CONN(client);

    vol = virStorageVolLookupByPath (client->conn, args->path);
    if (vol == NULL) return -1;

    make_nonnull_storage_vol (&ret->vol, vol);
    virStorageVolFree(vol);
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

/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
