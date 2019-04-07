/*
 * virt-admin.c: a shell to exercise the libvirt admin API
 *
 * Copyright (C) 2015 Red Hat, Inc.
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
#include "virt-admin.h"

#include <getopt.h>

#if WITH_READLINE
# include <readline/readline.h>
# include <readline/history.h>
#endif

#include "internal.h"
#include "viralloc.h"
#include "virerror.h"
#include "virfile.h"
#include "virstring.h"
#include "virthread.h"
#include "virgettext.h"
#include "virtime.h"
#include "virt-admin-completer.h"
#include "vsh-table.h"

/* Gnulib doesn't guarantee SA_SIGINFO support.  */
#ifndef SA_SIGINFO
# define SA_SIGINFO 0
#endif

#define VIRT_ADMIN_PROMPT "virt-admin # "

/* we don't need precision to milliseconds in this module */
#define VIRT_ADMIN_TIME_BUFLEN VIR_TIME_STRING_BUFLEN - 3

static char *progname;

static const vshCmdGrp cmdGroups[];
static const vshClientHooks hooks;

VIR_ENUM_DECL(virClientTransport);
VIR_ENUM_IMPL(virClientTransport,
              VIR_CLIENT_TRANS_LAST,
              N_("unix"),
              N_("tcp"),
              N_("tls"));

static const char *
vshAdmClientTransportToString(int transport)
{
    const char *str = virClientTransportTypeToString(transport);
    return str ? _(str) : _("unknown");
}

/*
 * vshAdmGetTimeStr:
 *
 * Produces string representation (local time) of @then
 * (seconds since epoch UTC) using format 'YYYY-MM-DD HH:MM:SS+ZZZZ'.
 *
 * Returns 0 if conversion finished successfully, -1 in case of an error.
 * Caller is responsible for freeing the string returned.
 */
static int
vshAdmGetTimeStr(vshControl *ctl, time_t then, char **result)
{
    char *tmp = NULL;
    struct tm timeinfo;

    if (!localtime_r(&then, &timeinfo))
        goto error;

    if (VIR_ALLOC_N(tmp, VIRT_ADMIN_TIME_BUFLEN) < 0)
        goto error;

    if (strftime(tmp, VIRT_ADMIN_TIME_BUFLEN, "%Y-%m-%d %H:%M:%S%z",
                 &timeinfo) == 0) {
        VIR_FREE(tmp);
        goto error;
    }

    *result = tmp;
    return 0;

 error:
    vshError(ctl, "%s", _("Timestamp string conversion failed"));
    return -1;
}

/*
 * vshAdmCatchDisconnect:
 *
 * We get here when the connection was closed. Unlike virsh, we do not save
 * the fact that the event was raised, since there is virAdmConnectIsAlive to
 * check if the communication channel has not been closed by remote party.
 */
static void
vshAdmCatchDisconnect(virAdmConnectPtr conn ATTRIBUTE_UNUSED,
                      int reason,
                      void *opaque)
{
    vshControl *ctl = opaque;
    const char *str = "unknown reason";
    virErrorPtr error;
    char *uri = NULL;

    if (reason == VIR_CONNECT_CLOSE_REASON_CLIENT)
        return;

    error = virSaveLastError();
    uri = virAdmConnectGetURI(conn);

    switch ((virConnectCloseReason) reason) {
    case VIR_CONNECT_CLOSE_REASON_ERROR:
        str = N_("Disconnected from %s due to I/O error");
        break;
    case VIR_CONNECT_CLOSE_REASON_EOF:
        str = N_("Disconnected from %s due to end of file");
        break;
    case VIR_CONNECT_CLOSE_REASON_KEEPALIVE:
        str = N_("Disconnected from %s due to keepalive timeout");
        break;
        /* coverity[dead_error_condition] */
    case VIR_CONNECT_CLOSE_REASON_CLIENT:
    case VIR_CONNECT_CLOSE_REASON_LAST:
        break;
    }

    vshError(ctl, _(str), NULLSTR(uri));
    VIR_FREE(uri);

    if (error) {
        virSetError(error);
        virFreeError(error);
    }
}

static int
vshAdmConnect(vshControl *ctl, unsigned int flags)
{
    vshAdmControlPtr priv = ctl->privData;

    priv->conn = virAdmConnectOpen(ctl->connname, flags);

    if (!priv->conn) {
        if (priv->wantReconnect)
            vshError(ctl, "%s", _("Failed to reconnect to the admin server"));
        else
            vshError(ctl, "%s", _("Failed to connect to the admin server"));
        return -1;
    } else {
        if (virAdmConnectRegisterCloseCallback(priv->conn, vshAdmCatchDisconnect,
                                               NULL, NULL) < 0)
            vshError(ctl, "%s", _("Unable to register disconnect callback"));

        if (priv->wantReconnect)
            vshPrint(ctl, "%s\n", _("Reconnected to the admin server"));
    }

    return 0;
}

static int
vshAdmDisconnect(vshControl *ctl)
{
    int ret = 0;
    vshAdmControlPtr priv = ctl->privData;

    if (!priv->conn)
        return ret;

    virAdmConnectUnregisterCloseCallback(priv->conn, vshAdmCatchDisconnect);
    ret = virAdmConnectClose(priv->conn);
    if (ret < 0)
        vshError(ctl, "%s", _("Failed to disconnect from the admin server"));
    else if (ret > 0)
        vshError(ctl, "%s", _("One or more references were leaked after "
                              "disconnect from the hypervisor"));
    priv->conn = NULL;
    return ret;
}

/*
 * vshAdmReconnect:
 *
 * Reconnect to a daemon's admin server
 *
 */
static void
vshAdmReconnect(vshControl *ctl)
{
    vshAdmControlPtr priv = ctl->privData;
    if (priv->conn)
        priv->wantReconnect = true;

    vshAdmDisconnect(ctl);
    vshAdmConnect(ctl, 0);

    priv->wantReconnect = false;
}

/*
 * 'uri' command
 */

static const vshCmdInfo info_uri[] = {
    {.name = "help",
     .data = N_("print the admin server URI")
    },
    {.name = "desc",
     .data = ""
    },
    {.name = NULL}
};

static bool
cmdURI(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    char *uri;
    vshAdmControlPtr priv = ctl->privData;

    uri = virAdmConnectGetURI(priv->conn);
    if (!uri) {
        vshError(ctl, "%s", _("failed to get URI"));
        return false;
    }

    vshPrint(ctl, "%s\n", uri);
    VIR_FREE(uri);

    return true;
}

/*
 * "version" command
 */

static const vshCmdInfo info_version[] = {
    {.name = "help",
     .data = N_("show version")
    },
    {.name = "desc",
     .data = N_("Display the system and also the daemon version information.")
    },
    {.name = NULL}
};

static bool
cmdVersion(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    unsigned long libVersion;
    unsigned long long includeVersion;
    unsigned long long daemonVersion;
    int ret;
    unsigned int major;
    unsigned int minor;
    unsigned int rel;
    vshAdmControlPtr priv = ctl->privData;

    includeVersion = LIBVIR_VERSION_NUMBER;
    major = includeVersion / 1000000;
    includeVersion %= 1000000;
    minor = includeVersion / 1000;
    rel = includeVersion % 1000;
    vshPrint(ctl, _("Compiled against library: libvirt %d.%d.%d\n"),
             major, minor, rel);

    ret = virGetVersion(&libVersion, NULL, NULL);
    if (ret < 0) {
        vshError(ctl, "%s", _("failed to get the library version"));
        return false;
    }
    major = libVersion / 1000000;
    libVersion %= 1000000;
    minor = libVersion / 1000;
    rel = libVersion % 1000;
    vshPrint(ctl, _("Using library: libvirt %d.%d.%d\n"),
             major, minor, rel);

    ret = virAdmConnectGetLibVersion(priv->conn, &daemonVersion);
    if (ret < 0) {
        vshError(ctl, "%s", _("failed to get the daemon version"));
    } else {
        major = daemonVersion / 1000000;
        daemonVersion %= 1000000;
        minor = daemonVersion / 1000;
        rel = daemonVersion % 1000;
        vshPrint(ctl, _("Running against daemon: %d.%d.%d\n"),
                 major, minor, rel);
    }

    return true;
}


/* ---------------
 * Command Connect
 * ---------------
 */

static const vshCmdOptDef opts_connect[] = {
    {.name = "name",
     .type = VSH_OT_STRING,
     .flags = VSH_OFLAG_EMPTY_OK,
     .help = N_("daemon's admin server connection URI")
    },
    {.name = NULL}
};

static const vshCmdInfo info_connect[] = {
    {.name = "help",
     .data = N_("connect to daemon's admin server")
    },
    {.name = "desc",
     .data = N_("Connect to a daemon's administrating server.")
    },
    {.name = NULL}
};

static bool
cmdConnect(vshControl *ctl, const vshCmd *cmd)
{
    const char *name = NULL;
    vshAdmControlPtr priv = ctl->privData;
    bool connected = priv->conn;

    if (vshCommandOptStringReq(ctl, cmd, "name", &name) < 0)
        return false;

    if (name) {
        VIR_FREE(ctl->connname);
        ctl->connname = vshStrdup(ctl, name);
    }

    vshAdmReconnect(ctl);
    if (!connected && priv->conn)
        vshPrint(ctl, "%s\n", _("Connected to the admin server"));

    return !!priv->conn;
}


/* ---------------
 * Command srv-list
 * ---------------
 */

static const vshCmdInfo info_srv_list[] = {
    {.name = "help",
     .data = N_("list available servers on a daemon")
    },
    {.name = "desc",
     .data = N_("List all manageable servers on a daemon.")
    },
    {.name = NULL}
};

static bool
cmdSrvList(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    int nsrvs = 0;
    size_t i;
    bool ret = false;
    char *uri = NULL;
    virAdmServerPtr *srvs = NULL;
    vshAdmControlPtr priv = ctl->privData;
    vshTablePtr table = NULL;

    /* Obtain a list of available servers on the daemon */
    if ((nsrvs = virAdmConnectListServers(priv->conn, &srvs, 0)) < 0) {
        uri = virAdmConnectGetURI(priv->conn);
        vshError(ctl, _("failed to obtain list of available servers from %s"),
                 NULLSTR(uri));
        goto cleanup;
    }

    table = vshTableNew(_("Id"), _("Name"), NULL);
    if (!table)
        goto cleanup;

    for (i = 0; i < nsrvs; i++) {
        VIR_AUTOFREE(char *) idStr = NULL;
        if (virAsprintf(&idStr, "%zu", i) < 0)
            goto cleanup;

        if (vshTableRowAppend(table,
                              idStr,
                              virAdmServerGetName(srvs[i]),
                              NULL) < 0)
            goto cleanup;
    }

    vshTablePrintToStdout(table, ctl);

    ret = true;
 cleanup:
    vshTableFree(table);
    if (srvs) {
        for (i = 0; i < nsrvs; i++)
            virAdmServerFree(srvs[i]);
        VIR_FREE(srvs);
    }
    VIR_FREE(uri);

    return ret;
}


/* ---------------------------
 * Command srv-threadpool-info
 * ---------------------------
 */

static const vshCmdInfo info_srv_threadpool_info[] = {
    {.name = "help",
     .data = N_("get server workerpool parameters")
    },
    {.name = "desc",
     .data = N_("Retrieve threadpool attributes from a server. ")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_srv_threadpool_info[] = {
    {.name = "server",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .completer = vshAdmServerCompleter,
     .help = N_("Server to retrieve threadpool attributes from."),
    },
    {.name = NULL}
};

static bool
cmdSrvThreadpoolInfo(vshControl *ctl, const vshCmd *cmd)
{
    bool ret = false;
    virTypedParameterPtr params = NULL;
    int nparams = 0;
    size_t i;
    const char *srvname = NULL;
    virAdmServerPtr srv = NULL;
    vshAdmControlPtr priv = ctl->privData;

    if (vshCommandOptStringReq(ctl, cmd, "server", &srvname) < 0)
        return false;

    if (!(srv = virAdmConnectLookupServer(priv->conn, srvname, 0)))
        goto cleanup;

    if (virAdmServerGetThreadPoolParameters(srv, &params,
                                            &nparams, 0) < 0) {
        vshError(ctl, "%s",
                 _("Unable to get server workerpool parameters"));
        goto cleanup;
    }

    for (i = 0; i < nparams; i++)
        vshPrint(ctl, "%-15s: %u\n", params[i].field, params[i].value.ui);

    ret = true;

 cleanup:
    virTypedParamsFree(params, nparams);
    if (srv)
        virAdmServerFree(srv);
    return ret;
}

/* --------------------------
 * Command srv-threadpool-set
 * --------------------------
 */

static const vshCmdInfo info_srv_threadpool_set[] = {
    {.name = "help",
     .data = N_("set server workerpool parameters")
    },
    {.name = "desc",
     .data = N_("Tune threadpool attributes on a server. See OPTIONS for "
                "currently supported attributes.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_srv_threadpool_set[] = {
    {.name = "server",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .completer = vshAdmServerCompleter,
     .help = N_("Server to alter threadpool attributes on."),
    },
    {.name = "min-workers",
     .type = VSH_OT_INT,
     .help = N_("Change bottom limit to number of workers."),
    },
    {.name = "max-workers",
     .type = VSH_OT_INT,
     .help = N_("Change upper limit to number of workers."),
    },
    {.name = "priority-workers",
     .type = VSH_OT_INT,
     .help = N_("Change the current number of priority workers"),
    },
    {.name = NULL}
};

static bool
cmdSrvThreadpoolSet(vshControl *ctl, const vshCmd *cmd)
{
    bool ret = false;
    int rv = 0;
    unsigned int val, min, max;
    int maxparams = 0;
    int nparams = 0;
    const char *srvname = NULL;
    virTypedParameterPtr params = NULL;
    virAdmServerPtr srv = NULL;
    vshAdmControlPtr priv = ctl->privData;

    if (vshCommandOptStringReq(ctl, cmd, "server", &srvname) < 0)
        return false;

#define PARSE_CMD_TYPED_PARAM(NAME, FIELD) \
    if ((rv = vshCommandOptUInt(ctl, cmd, NAME, &val)) < 0) { \
        vshError(ctl, _("Unable to parse integer parameter '%s'"), NAME); \
        goto cleanup; \
    } else if (rv > 0) { \
        if (virTypedParamsAddUInt(&params, &nparams, &maxparams, \
                                  FIELD, val) < 0) \
        goto save_error; \
    }

    PARSE_CMD_TYPED_PARAM("max-workers", VIR_THREADPOOL_WORKERS_MAX);
    PARSE_CMD_TYPED_PARAM("min-workers", VIR_THREADPOOL_WORKERS_MIN);
    PARSE_CMD_TYPED_PARAM("priority-workers", VIR_THREADPOOL_WORKERS_PRIORITY);

#undef PARSE_CMD_TYPED_PARAM

    if (!nparams) {
        vshError(ctl, "%s",
                 _("At least one of options --min-workers, --max-workers, "
                   "--priority-workers is mandatory "));
            goto cleanup;
    }

    if (virTypedParamsGetUInt(params, nparams,
                              VIR_THREADPOOL_WORKERS_MAX, &max) &&
        virTypedParamsGetUInt(params, nparams,
                              VIR_THREADPOOL_WORKERS_MIN, &min) && min > max) {
        vshError(ctl, "%s", _("--min-workers must be less than or equal to "
                              "--max-workers"));
        goto cleanup;
    }

    if (!(srv = virAdmConnectLookupServer(priv->conn, srvname, 0)))
        goto cleanup;

    if (virAdmServerSetThreadPoolParameters(srv, params,
                                            nparams, 0) < 0)
        goto error;

    ret = true;

 cleanup:
    virTypedParamsFree(params, nparams);
    if (srv)
        virAdmServerFree(srv);
    return ret;

 save_error:
    vshSaveLibvirtError();

 error:
    vshError(ctl, "%s", _("Unable to change server workerpool parameters"));
    goto cleanup;
}

/* ------------------------
 * Command srv-clients-list
 * ------------------------
 */

static const vshCmdInfo info_srv_clients_list[] = {
    {.name = "help",
     .data = N_("list clients connected to <server>")
    },
    {.name = "desc",
     .data = N_("List all manageable clients connected to <server>.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_srv_clients_list[] = {
    {.name = "server",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .completer = vshAdmServerCompleter,
     .help = N_("server which to list connected clients from"),
    },
    {.name = NULL}
};

static bool
cmdSrvClientsList(vshControl *ctl, const vshCmd *cmd)
{
    int nclts = 0;
    size_t i;
    bool ret = false;
    const char *srvname = NULL;
    unsigned long long id;
    virClientTransport transport;
    virAdmServerPtr srv = NULL;
    virAdmClientPtr *clts = NULL;
    vshAdmControlPtr priv = ctl->privData;
    vshTablePtr table = NULL;

    if (vshCommandOptStringReq(ctl, cmd, "server", &srvname) < 0)
        return false;

    if (!(srv = virAdmConnectLookupServer(priv->conn, srvname, 0)))
        goto cleanup;

    /* Obtain a list of clients connected to server @srv */
    if ((nclts = virAdmServerListClients(srv, &clts, 0)) < 0) {
        vshError(ctl, _("failed to obtain list of connected clients "
                        "from server '%s'"), virAdmServerGetName(srv));
        goto cleanup;
    }

    table = vshTableNew(_("Id"), _("Transport"), _("Connected since"), NULL);
    if (!table)
        goto cleanup;

    for (i = 0; i < nclts; i++) {
        VIR_AUTOFREE(char *) timestr = NULL;
        VIR_AUTOFREE(char *) idStr = NULL;
        virAdmClientPtr client = clts[i];
        id = virAdmClientGetID(client);
        transport = virAdmClientGetTransport(client);
        if (vshAdmGetTimeStr(ctl, virAdmClientGetTimestamp(client),
                             &timestr) < 0)
            goto cleanup;

        if (virAsprintf(&idStr, "%llu", id) < 0)
            goto cleanup;
        if (vshTableRowAppend(table, idStr,
                              vshAdmClientTransportToString(transport),
                              timestr, NULL) < 0)
            goto cleanup;
    }

    vshTablePrintToStdout(table, ctl);

    ret = true;

 cleanup:
    vshTableFree(table);
    if (clts) {
        for (i = 0; i < nclts; i++)
            virAdmClientFree(clts[i]);
        VIR_FREE(clts);
    }
    virAdmServerFree(srv);
    return ret;
}

/* -------------------
 * Command client-info
 * -------------------
 */

static const vshCmdInfo info_client_info[] = {
    {.name = "help",
     .data = N_("retrieve client's identity info from server")
    },
    {.name = "desc",
     .data = N_("Retrieve identity details about <client> from <server>")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_client_info[] = {
    {.name = "server",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .completer = vshAdmServerCompleter,
     .help = N_("server to which <client> is connected to"),
    },
    {.name = "client",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("client which to retrieve identity information for"),
    },
    {.name = NULL}
};

static bool
cmdClientInfo(vshControl *ctl, const vshCmd *cmd)
{
    bool ret = false;
    size_t i;
    unsigned long long id;
    const char *srvname = NULL;
    char *timestr = NULL;
    virAdmServerPtr srv = NULL;
    virAdmClientPtr clnt = NULL;
    virTypedParameterPtr params = NULL;
    int nparams = 0;
    vshAdmControlPtr priv = ctl->privData;

    if (vshCommandOptULongLong(ctl, cmd, "client", &id) < 0)
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "server", &srvname) < 0)
        return false;

    if (!(srv = virAdmConnectLookupServer(priv->conn, srvname, 0)) ||
        !(clnt = virAdmServerLookupClient(srv, id, 0)))
        goto cleanup;

    /* Retrieve client identity info */
    if (virAdmClientGetInfo(clnt, &params, &nparams, 0) < 0) {
        vshError(ctl, _("failed to retrieve client identity information for "
                        "client '%llu' connected to server '%s'"),
                        id, virAdmServerGetName(srv));
        goto cleanup;
    }

    if (vshAdmGetTimeStr(ctl, virAdmClientGetTimestamp(clnt), &timestr) < 0)
        goto cleanup;

    /* this info is provided by the client object itself */
    vshPrint(ctl, "%-15s: %llu\n", "id", virAdmClientGetID(clnt));
    vshPrint(ctl, "%-15s: %s\n", "connection_time", timestr);
    vshPrint(ctl, "%-15s: %s\n", "transport",
             vshAdmClientTransportToString(virAdmClientGetTransport(clnt)));

    for (i = 0; i < nparams; i++) {
        char *str = vshGetTypedParamValue(ctl, &params[i]);
        vshPrint(ctl, "%-15s: %s\n", params[i].field, str);
        VIR_FREE(str);
    }

    ret = true;

 cleanup:
    virTypedParamsFree(params, nparams);
    virAdmServerFree(srv);
    virAdmClientFree(clnt);
    VIR_FREE(timestr);
    return ret;
}

/* -------------------------
 * Command client-disconnect
 * -------------------------
 */

static const vshCmdInfo info_client_disconnect[] = {
    {.name = "help",
     .data = N_("force disconnect a client from the given server")
    },
    {.name = "desc",
     .data = N_("Force close a specific client's connection to the given "
                "server.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_client_disconnect[] = {
    {.name = "server",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .completer = vshAdmServerCompleter,
     .help = N_("server which the client is currently connected to"),
    },
    {.name = "client",
     .type = VSH_OT_INT,
     .flags = VSH_OFLAG_REQ,
     .help = N_("client which to disconnect, specified by ID"),
    },
    {.name = NULL}
};

static bool
cmdClientDisconnect(vshControl *ctl, const vshCmd *cmd)
{
    bool ret = false;
    const char *srvname = NULL;
    unsigned long long id = 0;
    virAdmServerPtr srv = NULL;
    virAdmClientPtr client = NULL;
    vshAdmControlPtr priv = ctl->privData;

    if (vshCommandOptStringReq(ctl, cmd, "server", &srvname) < 0)
        return false;

    if (vshCommandOptULongLongWrap(ctl, cmd, "client", &id) < 0)
        return false;

    if (!(srv = virAdmConnectLookupServer(priv->conn, srvname, 0)))
        goto cleanup;

    if (!(client = virAdmServerLookupClient(srv, id, 0)))
        goto cleanup;

    if (virAdmClientClose(client, 0) < 0) {
        vshError(ctl, _("Failed to disconnect client '%llu' from server %s"),
                 id, virAdmServerGetName(srv));
        goto cleanup;
    }

    vshPrint(ctl, _("Client '%llu' disconnected"), id);
    ret = true;
 cleanup:
    virAdmClientFree(client);
    virAdmServerFree(srv);
    return ret;
}

/* ------------------------
 * Command srv-clients-info
 * ------------------------
 */

static const vshCmdInfo info_srv_clients_info[] = {
    {.name = "help",
     .data = N_("get server's client-related configuration limits")
    },
    {.name = "desc",
     .data = N_("Retrieve server's client-related configuration limits ")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_srv_clients_info[] = {
    {.name = "server",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .completer = vshAdmServerCompleter,
     .help = N_("Server to retrieve the client limits from."),
    },
    {.name = NULL}
};

static bool
cmdSrvClientsInfo(vshControl *ctl, const vshCmd *cmd)
{
    bool ret = false;
    virTypedParameterPtr params = NULL;
    int nparams = 0;
    size_t i;
    const char *srvname = NULL;
    virAdmServerPtr srv = NULL;
    vshAdmControlPtr priv = ctl->privData;

    if (vshCommandOptStringReq(ctl, cmd, "server", &srvname) < 0)
        return false;

    if (!(srv = virAdmConnectLookupServer(priv->conn, srvname, 0)))
        goto cleanup;

    if (virAdmServerGetClientLimits(srv, &params, &nparams, 0) < 0) {
        vshError(ctl, "%s", _("Unable to retrieve client limits "
                              "from server's configuration"));
        goto cleanup;
    }

    for (i = 0; i < nparams; i++)
        vshPrint(ctl, "%-20s: %u\n", params[i].field, params[i].value.ui);

    ret = true;

 cleanup:
    virTypedParamsFree(params, nparams);
    virAdmServerFree(srv);
    return ret;
}

/* -----------------------
 * Command srv-clients-set
 * -----------------------
 */

static const vshCmdInfo info_srv_clients_set[] = {
    {.name = "help",
     .data = N_("set server's client-related configuration limits")
    },
    {.name = "desc",
     .data = N_("Tune server's client-related configuration limits. "
                "See OPTIONS for currently supported attributes.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_srv_clients_set[] = {
    {.name = "server",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .completer = vshAdmServerCompleter,
     .help = N_("Server to alter the client-related configuration limits on."),
    },
    {.name = "max-clients",
     .type = VSH_OT_INT,
     .help = N_("Change the upper limit to overall number of clients "
                "connected to the server."),
    },
    {.name = "max-unauth-clients",
     .type = VSH_OT_INT,
     .help = N_("Change the upper limit to number of clients waiting for "
                "authentication to be connected to the server"),
    },
    {.name = NULL}
};

static bool
cmdSrvClientsSet(vshControl *ctl, const vshCmd *cmd)
{
    bool ret = false;
    int rv = 0;
    unsigned int val, max, unauth_max;
    int maxparams = 0;
    int nparams = 0;
    const char *srvname = NULL;
    virAdmServerPtr srv = NULL;
    virTypedParameterPtr params = NULL;
    vshAdmControlPtr priv = ctl->privData;

    if (vshCommandOptStringReq(ctl, cmd, "server", &srvname) < 0)
        return false;

#define PARSE_CMD_TYPED_PARAM(NAME, FIELD) \
    if ((rv = vshCommandOptUInt(ctl, cmd, NAME, &val)) < 0) { \
        vshError(ctl, _("Unable to parse integer parameter '%s'"), NAME); \
        goto cleanup; \
    } else if (rv > 0) { \
        if (virTypedParamsAddUInt(&params, &nparams, &maxparams, \
                                  FIELD, val) < 0) \
        goto save_error; \
    }

    PARSE_CMD_TYPED_PARAM("max-clients", VIR_SERVER_CLIENTS_MAX);
    PARSE_CMD_TYPED_PARAM("max-unauth-clients", VIR_SERVER_CLIENTS_UNAUTH_MAX);

#undef PARSE_CMD_TYPED_PARAM

    if (!nparams) {
        vshError(ctl, "%s", _("At least one of options --max-clients, "
                              "--max-unauth-clients is mandatory"));
        goto cleanup;
    }

    if (virTypedParamsGetUInt(params, nparams,
                              VIR_SERVER_CLIENTS_MAX, &max) &&
        virTypedParamsGetUInt(params, nparams,
                              VIR_SERVER_CLIENTS_UNAUTH_MAX, &unauth_max) &&
        unauth_max > max) {
        vshError(ctl, "%s", _("--max-unauth-clients must be less than or equal to "
                              "--max-clients"));
        goto cleanup;
    }

    if (!(srv = virAdmConnectLookupServer(priv->conn, srvname, 0)))
        goto cleanup;

    if (virAdmServerSetClientLimits(srv, params, nparams, 0) < 0)
        goto error;

    ret = true;

 cleanup:
    virTypedParamsFree(params, nparams);
    virAdmServerFree(srv);
    return ret;

 save_error:
    vshSaveLibvirtError();

 error:
    vshError(ctl, "%s", _("Unable to change server's client-related "
                          "configuration limits"));
    goto cleanup;
}

/* --------------------------
 * Command daemon-log-filters
 * --------------------------
 */
static const vshCmdInfo info_daemon_log_filters[] = {
    {.name = "help",
     .data = N_("fetch or set the currently defined set of logging filters on "
                "daemon")
    },
    {.name = "desc",
     .data = N_("Depending on whether run with or without options, the command "
                "fetches or redefines the existing active set of filters on "
                "daemon.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_daemon_log_filters[] = {
    {.name = "filters",
     .type = VSH_OT_STRING,
     .help = N_("redefine the existing set of logging filters"),
     .flags = VSH_OFLAG_EMPTY_OK
    },
    {.name = NULL}
};

static bool
cmdDaemonLogFilters(vshControl *ctl, const vshCmd *cmd)
{
    int nfilters;
    char *filters = NULL;
    vshAdmControlPtr priv = ctl->privData;

    if (vshCommandOptBool(cmd, "filters")) {
        if ((vshCommandOptStringReq(ctl, cmd, "filters",
                                    (const char **) &filters) < 0 ||
             virAdmConnectSetLoggingFilters(priv->conn, filters, 0) < 0)) {
            vshError(ctl, _("Unable to change daemon logging settings"));
            return false;
        }
    } else {
        if ((nfilters = virAdmConnectGetLoggingFilters(priv->conn,
                                                       &filters, 0)) < 0) {
            vshError(ctl, _("Unable to get daemon logging filters information"));
            return false;
        }

        vshPrintExtra(ctl, " %-15s", _("Logging filters: "));
        vshPrint(ctl, "%s\n", NULLSTR_EMPTY(filters));
    }

    return true;
}

/* --------------------------
 * Command daemon-log-outputs
 * --------------------------
 */
static const vshCmdInfo info_daemon_log_outputs[] = {
    {.name = "help",
     .data = N_("fetch or set the currently defined set of logging outputs on "
                "daemon")
    },
    {.name = "desc",
     .data = N_("Depending on whether run with or without options, the command "
                "fetches or redefines the existing active set of outputs on "
                "daemon.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_daemon_log_outputs[] = {
    {.name = "outputs",
     .type = VSH_OT_STRING,
     .help = N_("redefine the existing set of logging outputs"),
     .flags = VSH_OFLAG_EMPTY_OK
    },
    {.name = NULL}
};

static bool
cmdDaemonLogOutputs(vshControl *ctl, const vshCmd *cmd)
{
    int noutputs;
    char *outputs = NULL;
    vshAdmControlPtr priv = ctl->privData;

    if (vshCommandOptBool(cmd, "outputs")) {
        if ((vshCommandOptStringReq(ctl, cmd, "outputs",
                                    (const char **) &outputs) < 0 ||
             virAdmConnectSetLoggingOutputs(priv->conn, outputs, 0) < 0)) {
            vshError(ctl, _("Unable to change daemon logging settings"));
            return false;
        }
    } else {
        if ((noutputs = virAdmConnectGetLoggingOutputs(priv->conn,
                                                       &outputs, 0)) < 0) {
            vshError(ctl, _("Unable to get daemon logging outputs information"));
            return false;
        }

        vshPrintExtra(ctl, " %-15s", _("Logging outputs: "));
        vshPrint(ctl, "%s\n", NULLSTR_EMPTY(outputs));
    }

    return true;
}

static void *
vshAdmConnectionHandler(vshControl *ctl)
{
    vshAdmControlPtr priv = ctl->privData;

    if (!virAdmConnectIsAlive(priv->conn))
        vshAdmReconnect(ctl);

    if (!virAdmConnectIsAlive(priv->conn)) {
        vshError(ctl, "%s", _("no valid connection"));
        return NULL;
    }

    return priv->conn;
}

/*
 * Initialize connection.
 */
static bool
vshAdmInit(vshControl *ctl)
{
    vshAdmControlPtr priv = ctl->privData;

    /* Since we have the commandline arguments parsed, we need to
     * reload our initial settings to make debugging and readline
     * work properly */
    vshInitReload(ctl);

    if (priv->conn)
        return false;

    /* set up the library error handler */
    virSetErrorFunc(NULL, vshErrorHandler);

    if (virEventRegisterDefaultImpl() < 0)
        return false;

    if (virThreadCreate(&ctl->eventLoop, true, vshEventLoop, ctl) < 0)
        return false;
    ctl->eventLoopStarted = true;

    if (ctl->connname) {
        vshAdmReconnect(ctl);
        /* Connecting to a named connection must succeed, but we delay
         * connecting to the default connection until we need it
         * (since the first command might be 'connect' which allows a
         * non-default connection, or might be 'help' which needs no
         * connection).
         */
        if (!priv->conn) {
            vshReportError(ctl);
            return false;
        }
    }

    return true;
}

static void
vshAdmDeinitTimer(int timer ATTRIBUTE_UNUSED, void *opaque ATTRIBUTE_UNUSED)
{
    /* nothing to be done here */
}

/*
 * Deinitialize virt-admin
 */
static void
vshAdmDeinit(vshControl *ctl)
{
    vshAdmControlPtr priv = ctl->privData;

    vshDeinit(ctl);
    VIR_FREE(ctl->connname);

    if (priv->conn)
        vshAdmDisconnect(ctl);

    virResetLastError();

    if (ctl->eventLoopStarted) {
        int timer;

        virMutexLock(&ctl->lock);
        ctl->quit = true;
        /* HACK: Add a dummy timeout to break event loop */
        timer = virEventAddTimeout(0, vshAdmDeinitTimer, NULL, NULL);
        virMutexUnlock(&ctl->lock);

        virThreadJoin(&ctl->eventLoop);

        if (timer != -1)
            virEventRemoveTimeout(timer);

        ctl->eventLoopStarted = false;
    }

    virMutexDestroy(&ctl->lock);
}

/*
 * Print usage
 */
static void
vshAdmUsage(void)
{
    const vshCmdGrp *grp;
    const vshCmdDef *cmd;

    fprintf(stdout, _("\n%s [options]... [<command_string>]"
                      "\n%s [options]... <command> [args...]\n\n"
                      "  options:\n"
                      "    -c | --connect=URI      daemon admin connection URI\n"
                      "    -d | --debug=NUM        debug level [0-4]\n"
                      "    -h | --help             this help\n"
                      "    -l | --log=FILE         output logging to file\n"
                      "    -q | --quiet            quiet mode\n"
                      "    -v                      short version\n"
                      "    -V                      long version\n"
                      "         --version[=TYPE]   version, TYPE is short or long (default short)\n"
                      "  commands (non interactive mode):\n\n"), progname,
            progname);

    for (grp = cmdGroups; grp->name; grp++) {
        fprintf(stdout, _(" %s (help keyword '%s')\n"),
                grp->name, grp->keyword);
        for (cmd = grp->commands; cmd->name; cmd++) {
            if (cmd->flags & VSH_CMD_FLAG_ALIAS)
                continue;
            fprintf(stdout,
                    "    %-30s %s\n", cmd->name,
                    _(vshCmddefGetInfo(cmd, "help")));
        }
        fprintf(stdout, "\n");
    }

    fprintf(stdout, "%s",
            _("\n  (specify help <group> for details about the commands in the group)\n"));
    fprintf(stdout, "%s",
            _("\n  (specify help <command> for details about the command)\n\n"));
    return;
}

/*
 * Show version and options compiled in
 */
static void
vshAdmShowVersion(vshControl *ctl ATTRIBUTE_UNUSED)
{
    /* FIXME - list a copyright blurb, as in GNU programs?  */
    vshPrint(ctl, _("Virt-admin command line tool of libvirt %s\n"), VERSION);
    vshPrint(ctl, _("See web site at %s\n\n"), "https://libvirt.org/");

    vshPrint(ctl, "%s", _("Compiled with support for:"));
#ifdef WITH_LIBVIRTD
    vshPrint(ctl, " Daemon");
#endif
#ifdef ENABLE_DEBUG
    vshPrint(ctl, " Debug");
#endif
#if WITH_READLINE
    vshPrint(ctl, " Readline");
#endif
    vshPrint(ctl, "\n");
}

static bool
vshAdmParseArgv(vshControl *ctl, int argc, char **argv)
{
    int arg, debug;
    size_t i;
    int longindex = -1;
    struct option opt[] = {
        {"connect", required_argument, NULL, 'c'},
        {"debug", required_argument, NULL, 'd'},
        {"help", no_argument, NULL, 'h'},
        {"log", required_argument, NULL, 'l'},
        {"quiet", no_argument, NULL, 'q'},
        {"version", optional_argument, NULL, 'v'},
        {NULL, 0, NULL, 0}
    };

    /* Standard (non-command) options. The leading + ensures that no
     * argument reordering takes place, so that command options are
     * not confused with top-level virt-admin options. */
    while ((arg = getopt_long(argc, argv, "+:c:d:hl:qvV", opt, &longindex)) != -1) {
        switch (arg) {
        case 'c':
            VIR_FREE(ctl->connname);
            ctl->connname = vshStrdup(ctl, optarg);
            break;
        case 'd':
            if (virStrToLong_i(optarg, NULL, 10, &debug) < 0) {
                vshError(ctl, _("option %s takes a numeric argument"),
                         longindex == -1 ? "-d" : "--debug");
                exit(EXIT_FAILURE);
            }
            if (debug < VSH_ERR_DEBUG || debug > VSH_ERR_ERROR)
                vshError(ctl, _("ignoring debug level %d out of range [%d-%d]"),
                         debug, VSH_ERR_DEBUG, VSH_ERR_ERROR);
            else
                ctl->debug = debug;
            break;
        case 'h':
            vshAdmUsage();
            exit(EXIT_SUCCESS);
            break;
        case 'l':
            vshCloseLogFile(ctl);
            ctl->logfile = vshStrdup(ctl, optarg);
            vshOpenLogFile(ctl);
            break;
        case 'q':
            ctl->quiet = true;
            break;
        case 'v':
            if (STRNEQ_NULLABLE(optarg, "long")) {
                puts(VERSION);
                exit(EXIT_SUCCESS);
            }
            ATTRIBUTE_FALLTHROUGH;
        case 'V':
            vshAdmShowVersion(ctl);
            exit(EXIT_SUCCESS);
        case ':':
            for (i = 0; opt[i].name != NULL; i++) {
                if (opt[i].val == optopt)
                    break;
            }
            if (opt[i].name)
                vshError(ctl, _("option '-%c'/'--%s' requires an argument"),
                         optopt, opt[i].name);
            else
                vshError(ctl, _("option '-%c' requires an argument"), optopt);
            exit(EXIT_FAILURE);
        case '?':
            if (optopt)
                vshError(ctl, _("unsupported option '-%c'. See --help."), optopt);
            else
                vshError(ctl, _("unsupported option '%s'. See --help."), argv[optind - 1]);
            exit(EXIT_FAILURE);
        default:
            vshError(ctl, _("unknown option"));
            exit(EXIT_FAILURE);
        }
        longindex = -1;
    }

    if (argc == optind) {
        ctl->imode = true;
    } else {
        /* parse command */
        ctl->imode = false;
        if (argc - optind == 1) {
            vshDebug(ctl, VSH_ERR_INFO, "commands: \"%s\"\n", argv[optind]);
            return vshCommandStringParse(ctl, argv[optind], NULL);
        } else {
            return vshCommandArgvParse(ctl, argc - optind, argv + optind);
        }
    }
    return true;
}

static const vshCmdDef vshAdmCmds[] = {
    VSH_CMD_CD,
    VSH_CMD_ECHO,
    VSH_CMD_EXIT,
    VSH_CMD_HELP,
    VSH_CMD_PWD,
    VSH_CMD_QUIT,
    VSH_CMD_SELF_TEST,
    VSH_CMD_COMPLETE,
    {.name = "uri",
     .handler = cmdURI,
     .opts = NULL,
     .info = info_uri,
     .flags = 0
    },
    {.name = "version",
     .handler = cmdVersion,
     .opts = NULL,
     .info = info_version,
     .flags = 0
    },
    {.name = "connect",
     .handler = cmdConnect,
     .opts = opts_connect,
     .info = info_connect,
     .flags = VSH_CMD_FLAG_NOCONNECT
    },
    {.name = NULL}
};

static const vshCmdDef monitoringCmds[] = {
    {.name = "srv-list",
     .flags = VSH_CMD_FLAG_ALIAS,
     .alias = "server-list"
    },
    {.name = "server-list",
     .handler = cmdSrvList,
     .opts = NULL,
     .info = info_srv_list,
     .flags = 0
    },
    {.name = "srv-threadpool-info",
     .flags = VSH_CMD_FLAG_ALIAS,
     .alias = "server-threadpool-info"
    },
    {.name = "server-threadpool-info",
     .handler = cmdSrvThreadpoolInfo,
     .opts = opts_srv_threadpool_info,
     .info = info_srv_threadpool_info,
     .flags = 0
    },
    {.name = "srv-clients-list",
     .flags = VSH_CMD_FLAG_ALIAS,
     .alias = "client-list"
    },
    {.name = "client-list",
     .handler = cmdSrvClientsList,
     .opts = opts_srv_clients_list,
     .info = info_srv_clients_list,
     .flags = 0
    },
    {.name = "client-info",
     .handler = cmdClientInfo,
     .opts = opts_client_info,
     .info = info_client_info,
     .flags = 0
    },
    {.name = "srv-clients-info",
     .flags = VSH_CMD_FLAG_ALIAS,
     .alias = "server-clients-info"
    },
    {.name = "server-clients-info",
     .handler = cmdSrvClientsInfo,
     .opts = opts_srv_clients_info,
     .info = info_srv_clients_info,
     .flags = 0
    },
    {.name = NULL}
};

static const vshCmdDef managementCmds[] = {
    {.name = "srv-threadpool-set",
     .flags = VSH_CMD_FLAG_ALIAS,
     .alias = "server-threadpool-set"
    },
    {.name = "server-threadpool-set",
     .handler = cmdSrvThreadpoolSet,
     .opts = opts_srv_threadpool_set,
     .info = info_srv_threadpool_set,
     .flags = 0
    },
    {.name = "client-disconnect",
     .handler = cmdClientDisconnect,
     .opts = opts_client_disconnect,
     .info = info_client_disconnect,
     .flags = 0
    },
    {.name = "srv-clients-set",
     .flags = VSH_CMD_FLAG_ALIAS,
     .alias = "server-clients-set"
    },
    {.name = "server-clients-set",
     .handler = cmdSrvClientsSet,
     .opts = opts_srv_clients_set,
     .info = info_srv_clients_set,
     .flags = 0
    },
    {.name = "daemon-log-filters",
     .handler = cmdDaemonLogFilters,
     .opts = opts_daemon_log_filters,
     .info = info_daemon_log_filters,
     .flags = 0
    },
    {.name = "daemon-log-outputs",
     .handler = cmdDaemonLogOutputs,
     .opts = opts_daemon_log_outputs,
     .info = info_daemon_log_outputs,
     .flags = 0
    },
    {.name = NULL}
};

static const vshCmdGrp cmdGroups[] = {
    {"Virt-admin itself", "virt-admin", vshAdmCmds},
    {"Monitoring commands", "monitor", monitoringCmds},
    {"Management commands", "management", managementCmds},
    {NULL, NULL, NULL}
};

static const vshClientHooks hooks = {
    .connHandler = vshAdmConnectionHandler
};

int
main(int argc, char **argv)
{
    vshControl _ctl, *ctl = &_ctl;
    vshAdmControl virtAdminCtl;
    bool ret = true;

    memset(ctl, 0, sizeof(vshControl));
    memset(&virtAdminCtl, 0, sizeof(vshAdmControl));
    ctl->name = "virt-admin";        /* hardcoded name of the binary */
    ctl->env_prefix = "VIRT_ADMIN";
    ctl->log_fd = -1;                /* Initialize log file descriptor */
    ctl->debug = VSH_DEBUG_DEFAULT;
    ctl->hooks = &hooks;

    ctl->eventPipe[0] = -1;
    ctl->eventPipe[1] = -1;
    ctl->privData = &virtAdminCtl;

    if (!(progname = strrchr(argv[0], '/')))
        progname = argv[0];
    else
        progname++;
    ctl->progname = progname;

    if (virGettextInitialize() < 0)
        return EXIT_FAILURE;

    if (isatty(STDIN_FILENO)) {
        ctl->istty = true;

#ifndef WIN32
        if (tcgetattr(STDIN_FILENO, &ctl->termattr) < 0)
            ctl->istty = false;
#endif
    }

    if (virMutexInit(&ctl->lock) < 0) {
        vshError(ctl, "%s", _("Failed to initialize mutex"));
        return EXIT_FAILURE;
    }

    if (virAdmInitialize() < 0) {
        vshError(ctl, "%s", _("Failed to initialize libvirt"));
        return EXIT_FAILURE;
    }

    virFileActivateDirOverride(argv[0]);

    if (!vshInit(ctl, cmdGroups, NULL))
        exit(EXIT_FAILURE);

    if (!vshAdmParseArgv(ctl, argc, argv) ||
        !vshAdmInit(ctl)) {
        vshAdmDeinit(ctl);
        exit(EXIT_FAILURE);
    }

    if (!ctl->imode) {
        ret = vshCommandRun(ctl, ctl->cmd);
    } else {
        /* interactive mode */
        if (!ctl->quiet) {
            vshPrint(ctl,
                     _("Welcome to %s, the administrating virtualization "
                       "interactive terminal.\n\n"),
                     progname);
            vshPrint(ctl, "%s",
                     _("Type:  'help' for help with commands\n"
                       "       'quit' to quit\n\n"));
        }

        do {
            ctl->cmdstr = vshReadline(ctl, VIRT_ADMIN_PROMPT);
            if (ctl->cmdstr == NULL)
                break;          /* EOF */
            if (*ctl->cmdstr) {
#if WITH_READLINE
                add_history(ctl->cmdstr);
#endif
                if (vshCommandStringParse(ctl, ctl->cmdstr, NULL))
                    vshCommandRun(ctl, ctl->cmd);
            }
            VIR_FREE(ctl->cmdstr);
        } while (ctl->imode);

        if (ctl->cmdstr == NULL)
            fputc('\n', stdout);        /* line break after alone prompt */
    }

    vshAdmDeinit(ctl);
    exit(ret ? EXIT_SUCCESS : EXIT_FAILURE);
}
