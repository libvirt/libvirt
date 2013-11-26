/*
 * remote_driver.c: driver to provide access to libvirtd running
 *   on a remote machine
 *
 * Copyright (C) 2007-2013 Red Hat, Inc.
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
 * Author: Richard Jones <rjones@redhat.com>
 */

#include <config.h>

#include <unistd.h>
#include <assert.h>

#include "virnetclient.h"
#include "virnetclientprogram.h"
#include "virnetclientstream.h"
#include "virerror.h"
#include "virlog.h"
#include "datatypes.h"
#include "domain_event.h"
#include "driver.h"
#include "virbuffer.h"
#include "remote_driver.h"
#include "remote_protocol.h"
#include "lxc_protocol.h"
#include "qemu_protocol.h"
#include "viralloc.h"
#include "virfile.h"
#include "vircommand.h"
#include "intprops.h"
#include "virtypedparam.h"
#include "viruri.h"
#include "virauth.h"
#include "virauthconfig.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_REMOTE

#if SIZEOF_LONG < 8
# define HYPER_TO_TYPE(_type, _to, _from)                                     \
    do {                                                                      \
        if ((_from) != (_type)(_from)) {                                      \
            virReportError(VIR_ERR_INTERNAL_ERROR,                               \
                           _("conversion from hyper to %s overflowed"), #_type); \
            goto done;                                                        \
        }                                                                     \
        (_to) = (_from);                                                      \
    } while (0)

# define HYPER_TO_LONG(_to, _from) HYPER_TO_TYPE(long, _to, _from)
# define HYPER_TO_ULONG(_to, _from) HYPER_TO_TYPE(unsigned long, _to, _from)
#else
# define HYPER_TO_LONG(_to, _from) (_to) = (_from)
# define HYPER_TO_ULONG(_to, _from) (_to) = (_from)
#endif

static bool inside_daemon = false;
static virDriverPtr remoteDriver = NULL;

struct private_data {
    virMutex lock;

    virNetClientPtr client;
    virNetClientProgramPtr remoteProgram;
    virNetClientProgramPtr qemuProgram;
    virNetClientProgramPtr lxcProgram;

    int counter; /* Serial number for RPC */

#ifdef WITH_GNUTLS
    virNetTLSContextPtr tls;
#endif

    int is_secure;              /* Secure if TLS or SASL or UNIX sockets */
    char *type;                 /* Cached return from remoteType. */
    int localUses;              /* Ref count for private data */
    char *hostname;             /* Original hostname */
    bool serverKeepAlive;       /* Does server support keepalive protocol? */

    virDomainEventStatePtr domainEventState;
};

enum {
    REMOTE_CALL_QEMU              = (1 << 0),
    REMOTE_CALL_LXC               = (1 << 1),
};


static void remoteDriverLock(struct private_data *driver)
{
    virMutexLock(&driver->lock);
}

static void remoteDriverUnlock(struct private_data *driver)
{
    virMutexUnlock(&driver->lock);
}

static int call(virConnectPtr conn, struct private_data *priv,
                unsigned int flags, int proc_nr,
                xdrproc_t args_filter, char *args,
                xdrproc_t ret_filter, char *ret);
static int callFull(virConnectPtr conn, struct private_data *priv,
                    unsigned int flags,
                    int *fdin, size_t fdinlen,
                    int **fdout, size_t *fdoutlen,
                    int proc_nr,
                    xdrproc_t args_filter, char *args,
                    xdrproc_t ret_filter, char *ret);
static int remoteAuthenticate(virConnectPtr conn, struct private_data *priv,
                              virConnectAuthPtr auth, const char *authtype);
#if WITH_SASL
static int remoteAuthSASL(virConnectPtr conn, struct private_data *priv,
                          virConnectAuthPtr auth, const char *mech);
#endif
#if WITH_POLKIT
static int remoteAuthPolkit(virConnectPtr conn, struct private_data *priv,
                            virConnectAuthPtr auth);
#endif /* WITH_POLKIT */

static virDomainPtr get_nonnull_domain(virConnectPtr conn, remote_nonnull_domain domain);
static virNetworkPtr get_nonnull_network(virConnectPtr conn, remote_nonnull_network network);
static virNWFilterPtr get_nonnull_nwfilter(virConnectPtr conn, remote_nonnull_nwfilter nwfilter);
static virInterfacePtr get_nonnull_interface(virConnectPtr conn, remote_nonnull_interface iface);
static virStoragePoolPtr get_nonnull_storage_pool(virConnectPtr conn, remote_nonnull_storage_pool pool);
static virStorageVolPtr get_nonnull_storage_vol(virConnectPtr conn, remote_nonnull_storage_vol vol);
static virNodeDevicePtr get_nonnull_node_device(virConnectPtr conn, remote_nonnull_node_device dev);
static virSecretPtr get_nonnull_secret(virConnectPtr conn, remote_nonnull_secret secret);
static virDomainSnapshotPtr get_nonnull_domain_snapshot(virDomainPtr domain, remote_nonnull_domain_snapshot snapshot);
static void make_nonnull_domain(remote_nonnull_domain *dom_dst, virDomainPtr dom_src);
static void make_nonnull_network(remote_nonnull_network *net_dst, virNetworkPtr net_src);
static void make_nonnull_interface(remote_nonnull_interface *interface_dst, virInterfacePtr interface_src);
static void make_nonnull_storage_pool(remote_nonnull_storage_pool *pool_dst, virStoragePoolPtr vol_src);
static void make_nonnull_storage_vol(remote_nonnull_storage_vol *vol_dst, virStorageVolPtr vol_src);
static void make_nonnull_secret(remote_nonnull_secret *secret_dst, virSecretPtr secret_src);
static void make_nonnull_nwfilter(remote_nonnull_nwfilter *nwfilter_dst, virNWFilterPtr nwfilter_src);
static void make_nonnull_domain_snapshot(remote_nonnull_domain_snapshot *snapshot_dst, virDomainSnapshotPtr snapshot_src);
static void remoteDomainEventQueue(struct private_data *priv, virDomainEventPtr event);
/*----------------------------------------------------------------------*/

/* Helper functions for remoteOpen. */
static char *get_transport_from_scheme(char *scheme);

#ifdef WITH_LIBVIRTD
static int
remoteStateInitialize(bool privileged ATTRIBUTE_UNUSED,
                      virStateInhibitCallback callback ATTRIBUTE_UNUSED,
                      void *opaque ATTRIBUTE_UNUSED)
{
    /* Mark that we're inside the daemon so we can avoid
     * re-entering ourselves
     */
    inside_daemon = true;
    return 0;
}
#endif

#ifndef WIN32
/**
 * remoteFindDaemonPath:
 *
 * Tries to find the path to the libvirtd binary.
 *
 * Returns path on success or NULL in case of error.
 */
static const char *
remoteFindDaemonPath(void)
{
    static const char *serverPaths[] = {
        SBINDIR "/libvirtd",
        SBINDIR "/libvirtd_dbg",
        NULL
    };
    size_t i;
    const char *customDaemon = virGetEnvBlockSUID("LIBVIRTD_PATH");

    if (customDaemon)
        return customDaemon;

    for (i = 0; serverPaths[i]; i++) {
        if (virFileIsExecutable(serverPaths[i])) {
            return serverPaths[i];
        }
    }
    return NULL;
}
#endif


static void
remoteDomainBuildEventLifecycle(virNetClientProgramPtr prog ATTRIBUTE_UNUSED,
                                virNetClientPtr client ATTRIBUTE_UNUSED,
                                void *evdata, void *opaque);
static void
remoteDomainBuildEventReboot(virNetClientProgramPtr prog ATTRIBUTE_UNUSED,
                             virNetClientPtr client ATTRIBUTE_UNUSED,
                             void *evdata, void *opaque);
static void
remoteDomainBuildEventRTCChange(virNetClientProgramPtr prog,
                                virNetClientPtr client,
                                void *evdata, void *opaque);
static void
remoteDomainBuildEventWatchdog(virNetClientProgramPtr prog,
                               virNetClientPtr client,
                               void *evdata, void *opaque);
static void
remoteDomainBuildEventIOError(virNetClientProgramPtr prog,
                              virNetClientPtr client,
                              void *evdata, void *opaque);
static void
remoteDomainBuildEventIOErrorReason(virNetClientProgramPtr prog,
                                    virNetClientPtr client,
                                    void *evdata, void *opaque);
static void
remoteDomainBuildEventGraphics(virNetClientProgramPtr prog,
                               virNetClientPtr client,
                               void *evdata, void *opaque);
static void
remoteDomainBuildEventControlError(virNetClientProgramPtr prog,
                                   virNetClientPtr client,
                                   void *evdata, void *opaque);

static void
remoteDomainBuildEventBlockJob(virNetClientProgramPtr prog,
                               virNetClientPtr client,
                               void *evdata, void *opaque);

static void
remoteDomainBuildEventDiskChange(virNetClientProgramPtr prog,
                                 virNetClientPtr client,
                                 void *evdata, void *opaque);

static void
remoteDomainBuildEventTrayChange(virNetClientProgramPtr prog,
                                 virNetClientPtr client,
                                 void *evdata, void *opaque);

static void
remoteDomainBuildEventPMWakeup(virNetClientProgramPtr prog,
                               virNetClientPtr client,
                               void *evdata, void *opaque);

static void
remoteDomainBuildEventPMSuspend(virNetClientProgramPtr prog,
                                virNetClientPtr client,
                                void *evdata, void *opaque);
static void
remoteDomainBuildEventBalloonChange(virNetClientProgramPtr prog,
                                    virNetClientPtr client,
                                    void *evdata, void *opaque);
static void
remoteDomainBuildEventPMSuspendDisk(virNetClientProgramPtr prog,
                                  virNetClientPtr client,
                                  void *evdata, void *opaque);

static void
remoteDomainBuildEventDeviceRemoved(virNetClientProgramPtr prog,
                                    virNetClientPtr client,
                                    void *evdata, void *opaque);

static virNetClientProgramEvent remoteDomainEvents[] = {
    { REMOTE_PROC_DOMAIN_EVENT_RTC_CHANGE,
      remoteDomainBuildEventRTCChange,
      sizeof(remote_domain_event_rtc_change_msg),
      (xdrproc_t)xdr_remote_domain_event_rtc_change_msg },
    { REMOTE_PROC_DOMAIN_EVENT_REBOOT,
      remoteDomainBuildEventReboot,
      sizeof(remote_domain_event_reboot_msg),
      (xdrproc_t)xdr_remote_domain_event_reboot_msg },
    { REMOTE_PROC_DOMAIN_EVENT_LIFECYCLE,
      remoteDomainBuildEventLifecycle,
      sizeof(remote_domain_event_lifecycle_msg),
      (xdrproc_t)xdr_remote_domain_event_lifecycle_msg },
    { REMOTE_PROC_DOMAIN_EVENT_WATCHDOG,
      remoteDomainBuildEventWatchdog,
      sizeof(remote_domain_event_watchdog_msg),
      (xdrproc_t)xdr_remote_domain_event_watchdog_msg},
    { REMOTE_PROC_DOMAIN_EVENT_IO_ERROR,
      remoteDomainBuildEventIOError,
      sizeof(remote_domain_event_io_error_msg),
      (xdrproc_t)xdr_remote_domain_event_io_error_msg },
    { REMOTE_PROC_DOMAIN_EVENT_IO_ERROR_REASON,
      remoteDomainBuildEventIOErrorReason,
      sizeof(remote_domain_event_io_error_reason_msg),
      (xdrproc_t)xdr_remote_domain_event_io_error_reason_msg },
    { REMOTE_PROC_DOMAIN_EVENT_GRAPHICS,
      remoteDomainBuildEventGraphics,
      sizeof(remote_domain_event_graphics_msg),
      (xdrproc_t)xdr_remote_domain_event_graphics_msg },
    { REMOTE_PROC_DOMAIN_EVENT_CONTROL_ERROR,
      remoteDomainBuildEventControlError,
      sizeof(remote_domain_event_control_error_msg),
      (xdrproc_t)xdr_remote_domain_event_control_error_msg },
    { REMOTE_PROC_DOMAIN_EVENT_BLOCK_JOB,
      remoteDomainBuildEventBlockJob,
      sizeof(remote_domain_event_block_job_msg),
      (xdrproc_t)xdr_remote_domain_event_block_job_msg },
    { REMOTE_PROC_DOMAIN_EVENT_DISK_CHANGE,
      remoteDomainBuildEventDiskChange,
      sizeof(remote_domain_event_disk_change_msg),
      (xdrproc_t)xdr_remote_domain_event_disk_change_msg },
    { REMOTE_PROC_DOMAIN_EVENT_TRAY_CHANGE,
      remoteDomainBuildEventTrayChange,
      sizeof(remote_domain_event_tray_change_msg),
      (xdrproc_t)xdr_remote_domain_event_tray_change_msg },
    { REMOTE_PROC_DOMAIN_EVENT_PMWAKEUP,
      remoteDomainBuildEventPMWakeup,
      sizeof(remote_domain_event_pmwakeup_msg),
      (xdrproc_t)xdr_remote_domain_event_pmwakeup_msg },
    { REMOTE_PROC_DOMAIN_EVENT_PMSUSPEND,
      remoteDomainBuildEventPMSuspend,
      sizeof(remote_domain_event_pmsuspend_msg),
      (xdrproc_t)xdr_remote_domain_event_pmsuspend_msg },
    { REMOTE_PROC_DOMAIN_EVENT_BALLOON_CHANGE,
      remoteDomainBuildEventBalloonChange,
      sizeof(remote_domain_event_balloon_change_msg),
      (xdrproc_t)xdr_remote_domain_event_balloon_change_msg },
    { REMOTE_PROC_DOMAIN_EVENT_PMSUSPEND_DISK,
      remoteDomainBuildEventPMSuspendDisk,
      sizeof(remote_domain_event_pmsuspend_disk_msg),
      (xdrproc_t)xdr_remote_domain_event_pmsuspend_disk_msg },
    { REMOTE_PROC_DOMAIN_EVENT_DEVICE_REMOVED,
      remoteDomainBuildEventDeviceRemoved,
      sizeof(remote_domain_event_device_removed_msg),
      (xdrproc_t)xdr_remote_domain_event_device_removed_msg },
};

enum virDrvOpenRemoteFlags {
    VIR_DRV_OPEN_REMOTE_RO = (1 << 0),
    VIR_DRV_OPEN_REMOTE_USER      = (1 << 1), /* Use the per-user socket path */
    VIR_DRV_OPEN_REMOTE_AUTOSTART = (1 << 2), /* Autostart a per-user daemon */
};


static void
remoteClientCloseFunc(virNetClientPtr client ATTRIBUTE_UNUSED,
                      int reason,
                      void *opaque)
{
    virConnectCloseCallbackDataPtr cbdata = opaque;

    virObjectLock(cbdata);

    if (cbdata->callback) {
        VIR_DEBUG("Triggering connection close callback %p reason=%d, opaque=%p",
                  cbdata->callback, reason, cbdata->opaque);
        cbdata->callback(cbdata->conn, reason, cbdata->opaque);

        if (cbdata->freeCallback)
            cbdata->freeCallback(cbdata->opaque);
        cbdata->callback = NULL;
        cbdata->freeCallback = NULL;
    }
    virObjectUnlock(cbdata);

    /* free the connection reference that comes along with the callback
     * registration */
    virObjectUnref(cbdata->conn);
}

/* helper macro to ease extraction of arguments from the URI */
#define EXTRACT_URI_ARG_STR(ARG_NAME, ARG_VAR)          \
    if (STRCASEEQ(var->name, ARG_NAME)) {               \
        VIR_FREE(ARG_VAR);                              \
        if (VIR_STRDUP(ARG_VAR, var->value) < 0)        \
            goto failed;                                \
        var->ignore = 1;                                \
        continue;                                       \
    }

#define EXTRACT_URI_ARG_BOOL(ARG_NAME, ARG_VAR)                             \
    if (STRCASEEQ(var->name, ARG_NAME)) {                                   \
        int tmp;                                                            \
        if (virStrToLong_i(var->value, NULL, 10, &tmp) < 0) {               \
            virReportError(VIR_ERR_INVALID_ARG,                             \
                           _("Failed to parse value of URI component %s"),  \
                           var->name);                                      \
            goto failed;                                                    \
        }                                                                   \
        ARG_VAR = tmp == 0;                                                 \
        var->ignore = 1;                                                    \
        continue;                                                           \
    }
/*
 * URIs that this driver needs to handle:
 *
 * The easy answer:
 *   - Everything that no one else has yet claimed, but nothing if
 *     we're inside the libvirtd daemon
 *
 * The hard answer:
 *   - Plain paths (///var/lib/xen/xend-socket)  -> UNIX domain socket
 *   - xxx://servername/      -> TLS connection
 *   - xxx+tls://servername/  -> TLS connection
 *   - xxx+tls:///            -> TLS connection to localhost
 *   - xxx+tcp://servername/  -> TCP connection
 *   - xxx+tcp:///            -> TCP connection to localhost
 *   - xxx+unix:///           -> UNIX domain socket
 *   - xxx:///                -> UNIX domain socket
 *   - xxx+ssh:///            -> SSH connection (legacy)
 *   - xxx+libssh2:///        -> SSH connection (using libssh2)
 */
static int
doRemoteOpen(virConnectPtr conn,
             struct private_data *priv,
             virConnectAuthPtr auth ATTRIBUTE_UNUSED,
             unsigned int flags)
{
    char *transport_str = NULL;
    enum {
        trans_tls,
        trans_unix,
        trans_ssh,
        trans_libssh2,
        trans_ext,
        trans_tcp,
    } transport;
#ifndef WIN32
    const char *daemonPath = NULL;
#endif

    /* We handle *ALL* URIs here. The caller has rejected any
     * URIs we don't care about */

    if (conn->uri) {
        if (!conn->uri->scheme) {
            /* This is the ///var/lib/xen/xend-socket local path style */
            if (!conn->uri->path)
                return VIR_DRV_OPEN_DECLINED;
            if (conn->uri->path[0] != '/')
                return VIR_DRV_OPEN_DECLINED;

            transport = trans_unix;
        } else {
            transport_str = get_transport_from_scheme(conn->uri->scheme);

            if (!transport_str) {
                if (conn->uri->server)
                    transport = trans_tls;
                else
                    transport = trans_unix;
            } else {
                if (STRCASEEQ(transport_str, "tls"))
                    transport = trans_tls;
                else if (STRCASEEQ(transport_str, "unix")) {
                    if (conn->uri->server) {
                        virReportError(VIR_ERR_INVALID_ARG,
                                       _("using unix socket and remote "
                                         "server '%s' is not supported."),
                                       conn->uri->server);
                        return VIR_DRV_OPEN_ERROR;
                    } else {
                        transport = trans_unix;
                    }
                } else if (STRCASEEQ(transport_str, "ssh"))
                    transport = trans_ssh;
                else if (STRCASEEQ(transport_str, "libssh2"))
                    transport = trans_libssh2;
                else if (STRCASEEQ(transport_str, "ext"))
                    transport = trans_ext;
                else if (STRCASEEQ(transport_str, "tcp"))
                    transport = trans_tcp;
                else {
                    virReportError(VIR_ERR_INVALID_ARG, "%s",
                                   _("remote_open: transport in URL not recognised "
                                     "(should be tls|unix|ssh|ext|tcp|libssh2)"));
                    return VIR_DRV_OPEN_ERROR;
                }
            }
        }
    } else {
        /* No URI, then must be probing so use UNIX socket */
        transport = trans_unix;
    }

    /*
     * We don't want to be executing external programs in setuid mode,
     * so this rules out 'ext' and 'ssh' transports. Exclude libssh
     * and tls too, since we're not confident the libraries are safe
     * for setuid usage. Just allow UNIX sockets, since that does
     * not require any external libraries or command execution
     */
    if (virIsSUID() &&
        transport != trans_unix) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Only Unix socket URI transport is allowed in setuid mode"));
        return VIR_DRV_OPEN_ERROR;
    }

    /* Local variables which we will initialize. These can
     * get freed in the failed: path.
     */
    char *name = NULL, *command = NULL, *sockname = NULL, *netcat = NULL;
    char *port = NULL, *authtype = NULL, *username = NULL;
    bool sanity = true, verify = true, tty ATTRIBUTE_UNUSED = true;
    char *pkipath = NULL, *keyfile = NULL, *sshauth = NULL;

    char *knownHostsVerify = NULL,  *knownHosts = NULL;

    /* Return code from this function, and the private data. */
    int retcode = VIR_DRV_OPEN_ERROR;

    /* Remote server defaults to "localhost" if not specified. */
    if (conn->uri && conn->uri->port != 0) {
        if (virAsprintf(&port, "%d", conn->uri->port) < 0)
            goto failed;
    } else if (transport == trans_tls) {
        if (VIR_STRDUP(port, LIBVIRTD_TLS_PORT) < 0)
            goto failed;
    } else if (transport == trans_tcp) {
        if (VIR_STRDUP(port, LIBVIRTD_TCP_PORT) < 0)
            goto failed;
    } /* Port not used for unix, ext., default for ssh */

    if (VIR_STRDUP(priv->hostname,
                   conn->uri && conn->uri->server ?
                   conn->uri->server : "localhost") < 0)
        goto failed;

    if (conn->uri && VIR_STRDUP(username, conn->uri->user) < 0)
        goto failed;

    /* Get the variables from the query string.
     * Then we need to reconstruct the query string (because
     * feasibly it might contain variables needed by the real driver,
     * although that won't be the case for now).
     */
    size_t i;

    if (conn->uri) {
        for (i = 0; i < conn->uri->paramsCount; i++) {
            virURIParamPtr var = &conn->uri->params[i];
            EXTRACT_URI_ARG_STR("name", name);
            EXTRACT_URI_ARG_STR("command", command);
            EXTRACT_URI_ARG_STR("socket", sockname);
            EXTRACT_URI_ARG_STR("auth", authtype);
            EXTRACT_URI_ARG_STR("sshauth", sshauth);
            EXTRACT_URI_ARG_STR("netcat", netcat);
            EXTRACT_URI_ARG_STR("keyfile", keyfile);
            EXTRACT_URI_ARG_STR("pkipath", pkipath);
            EXTRACT_URI_ARG_STR("known_hosts", knownHosts);
            EXTRACT_URI_ARG_STR("known_hosts_verify", knownHostsVerify);

            EXTRACT_URI_ARG_BOOL("no_sanity", sanity);
            EXTRACT_URI_ARG_BOOL("no_verify", verify);
            EXTRACT_URI_ARG_BOOL("no_tty", tty);

            if (STRCASEEQ(var->name, "authfile")) {
                /* Strip this param, used by virauth.c */
                var->ignore = 1;
                continue;
            }

            VIR_DEBUG("passing through variable '%s' ('%s') to remote end",
                       var->name, var->value);
        }

        /* Construct the original name. */
        if (!name) {
            if (conn->uri->scheme &&
                (STREQ(conn->uri->scheme, "remote") ||
                 STRPREFIX(conn->uri->scheme, "remote+"))) {
                /* Allow remote serve to probe */
                if (VIR_STRDUP(name, "") < 0)
                    goto failed;
            } else {
                virURI tmpuri = {
                    .scheme = conn->uri->scheme,
                    .query = virURIFormatParams(conn->uri),
                    .path = conn->uri->path,
                    .fragment = conn->uri->fragment,
                };

                /* Evil, blank out transport scheme temporarily */
                if (transport_str) {
                    assert(transport_str[-1] == '+');
                    transport_str[-1] = '\0';
                }

                name = virURIFormat(&tmpuri);

                VIR_FREE(tmpuri.query);

                /* Restore transport scheme */
                if (transport_str)
                    transport_str[-1] = '+';

                if (!name)
                    goto failed;
            }
        }
    } else {
        /* Probe URI server side */
        if (VIR_STRDUP(name, "") < 0)
            goto failed;
    }

    VIR_DEBUG("proceeding with name = %s", name);

    /* For ext transport, command is required. */
    if (transport == trans_ext && !command) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("remote_open: for 'ext' transport, command is required"));
        goto failed;
    }

    VIR_DEBUG("Connecting with transport %d", transport);
    /* Connect to the remote service. */
    switch (transport) {
    case trans_tls:
#ifdef WITH_GNUTLS
        priv->tls = virNetTLSContextNewClientPath(pkipath,
                                                  geteuid() != 0 ? true : false,
                                                  sanity, verify);
        if (!priv->tls)
            goto failed;
        priv->is_secure = 1;
#else
        (void)sanity;
        (void)verify;
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("GNUTLS support not available in this build"));
        goto failed;
#endif

        /*FALLTHROUGH*/
    case trans_tcp:
        priv->client = virNetClientNewTCP(priv->hostname, port);
        if (!priv->client)
            goto failed;

#ifdef WITH_GNUTLS
        if (priv->tls) {
            VIR_DEBUG("Starting TLS session");
            if (virNetClientSetTLSSession(priv->client, priv->tls) < 0)
                goto failed;
        }
#endif

        break;

    case trans_libssh2:
        if (!sockname) {
            /* Right now we don't support default session connections */
            if (STREQ_NULLABLE(conn->uri->path, "/session")) {
                virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                               _("Connecting to session instance without "
                                 "socket path is not supported by the libssh2 "
                                 "connection driver"));
                goto failed;
            }

            if (VIR_STRDUP(sockname,
                           flags & VIR_DRV_OPEN_REMOTE_RO ?
                           LIBVIRTD_PRIV_UNIX_SOCKET_RO : LIBVIRTD_PRIV_UNIX_SOCKET) < 0)
                goto failed;
        }

        VIR_DEBUG("Starting LibSSH2 session");

        priv->client = virNetClientNewLibSSH2(priv->hostname,
                                              port,
                                              username,
                                              keyfile,
                                              knownHosts,
                                              knownHostsVerify,
                                              sshauth,
                                              netcat,
                                              sockname,
                                              auth,
                                              conn->uri);
        if (!priv->client)
            goto failed;

        priv->is_secure = 1;
        break;

#ifndef WIN32
    case trans_unix:
        if (!sockname) {
            if (flags & VIR_DRV_OPEN_REMOTE_USER) {
                char *userdir = virGetUserRuntimeDirectory();

                if (!userdir)
                    goto failed;

                if (virAsprintf(&sockname, "%s/" LIBVIRTD_USER_UNIX_SOCKET, userdir) < 0) {
                    VIR_FREE(userdir);
                    goto failed;
                }
                VIR_FREE(userdir);
            } else {
                if (VIR_STRDUP(sockname,
                               flags & VIR_DRV_OPEN_REMOTE_RO ?
                               LIBVIRTD_PRIV_UNIX_SOCKET_RO : LIBVIRTD_PRIV_UNIX_SOCKET) < 0)
                    goto failed;
            }
            VIR_DEBUG("Proceeding with sockname %s", sockname);
        }

        if ((flags & VIR_DRV_OPEN_REMOTE_AUTOSTART) &&
            !(daemonPath = remoteFindDaemonPath())) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unable to locate libvirtd daemon in %s "
                             "(to override, set $LIBVIRTD_PATH to the "
                             "name of the libvirtd binary)"),
                           SBINDIR);
            goto failed;
        }
        if (!(priv->client = virNetClientNewUNIX(sockname,
                                                 flags & VIR_DRV_OPEN_REMOTE_AUTOSTART,
                                                 daemonPath)))
            goto failed;

        priv->is_secure = 1;
        break;

    case trans_ssh:
        if (!command && VIR_STRDUP(command, "ssh") < 0)
            goto failed;

        if (!sockname) {
            /* Right now we don't support default session connections */
            if (STREQ_NULLABLE(conn->uri->path, "/session")) {
                virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                               _("Connecting to session instance without "
                                 "socket path is not supported by the ssh "
                                 "connection driver"));
                goto failed;
            }

            if (VIR_STRDUP(sockname,
                           flags & VIR_DRV_OPEN_REMOTE_RO ?
                           LIBVIRTD_PRIV_UNIX_SOCKET_RO : LIBVIRTD_PRIV_UNIX_SOCKET) < 0)
                goto failed;
        }

        if (!(priv->client = virNetClientNewSSH(priv->hostname,
                                                port,
                                                command,
                                                username,
                                                !tty,
                                                !verify,
                                                netcat ? netcat : "nc",
                                                keyfile,
                                                sockname)))
            goto failed;

        priv->is_secure = 1;
        break;

    case trans_ext: {
        char const *cmd_argv[] = { command, NULL };
        if (!(priv->client = virNetClientNewExternal(cmd_argv)))
            goto failed;

        /* Do not set 'is_secure' flag since we can't guarantee
         * an external program is secure, and this flag must be
         * pessimistic */
    }   break;

#else /* WIN32 */

    case trans_unix:
    case trans_ssh:
    case trans_ext:
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("transport methods unix, ssh and ext are not supported "
                         "under Windows"));
        goto failed;

#endif /* WIN32 */
    } /* switch (transport) */


    if (virNetClientRegisterAsyncIO(priv->client) < 0) {
        VIR_DEBUG("Failed to add event watch, disabling events and support for"
                  " keepalive messages");
        virResetLastError();
    } else {
        if (virNetClientRegisterKeepAlive(priv->client) < 0)
            goto failed;
    }

    virObjectRef(conn->closeCallback);

    virNetClientSetCloseCallback(priv->client,
                                 remoteClientCloseFunc,
                                 conn->closeCallback, virObjectFreeCallback);

    if (!(priv->remoteProgram = virNetClientProgramNew(REMOTE_PROGRAM,
                                                       REMOTE_PROTOCOL_VERSION,
                                                       remoteDomainEvents,
                                                       ARRAY_CARDINALITY(remoteDomainEvents),
                                                       conn)))
        goto failed;
    if (!(priv->lxcProgram = virNetClientProgramNew(LXC_PROGRAM,
                                                    LXC_PROTOCOL_VERSION,
                                                    NULL,
                                                    0,
                                                    NULL)))
        goto failed;
    if (!(priv->qemuProgram = virNetClientProgramNew(QEMU_PROGRAM,
                                                     QEMU_PROTOCOL_VERSION,
                                                     NULL,
                                                     0,
                                                     NULL)))
        goto failed;

    if (virNetClientAddProgram(priv->client, priv->remoteProgram) < 0 ||
        virNetClientAddProgram(priv->client, priv->lxcProgram) < 0 ||
        virNetClientAddProgram(priv->client, priv->qemuProgram) < 0)
        goto failed;

    /* Try and authenticate with server */
    VIR_DEBUG("Trying authentication");
    if (remoteAuthenticate(conn, priv, auth, authtype) == -1)
        goto failed;

    if (virNetClientKeepAliveIsSupported(priv->client)) {
        remote_connect_supports_feature_args args =
            { VIR_DRV_FEATURE_PROGRAM_KEEPALIVE };
        remote_connect_supports_feature_ret ret = { 0 };
        int rc;

        rc = call(conn, priv, 0, REMOTE_PROC_CONNECT_SUPPORTS_FEATURE,
                  (xdrproc_t)xdr_remote_connect_supports_feature_args, (char *) &args,
                  (xdrproc_t)xdr_remote_connect_supports_feature_ret, (char *) &ret);

        if (rc != -1 && ret.supported) {
            priv->serverKeepAlive = true;
        } else {
            VIR_INFO("Disabling keepalive protocol since it is not supported"
                     " by the server");
        }
    }

    /* Finally we can call the remote side's open function. */
    {
        remote_connect_open_args args = { &name, flags };

        VIR_DEBUG("Trying to open URI %s", name);
        if (call(conn, priv, 0, REMOTE_PROC_CONNECT_OPEN,
                 (xdrproc_t) xdr_remote_connect_open_args, (char *) &args,
                 (xdrproc_t) xdr_void, (char *) NULL) == -1)
            goto failed;
    }

    /* Now try and find out what URI the daemon used */
    if (conn->uri == NULL) {
        remote_connect_get_uri_ret uriret;

        VIR_DEBUG("Trying to query remote URI");
        memset(&uriret, 0, sizeof(uriret));
        if (call(conn, priv, 0,
                 REMOTE_PROC_CONNECT_GET_URI,
                 (xdrproc_t) xdr_void, (char *) NULL,
                 (xdrproc_t) xdr_remote_connect_get_uri_ret, (char *) &uriret) < 0)
            goto failed;

        VIR_DEBUG("Auto-probed URI is %s", uriret.uri);
        conn->uri = virURIParse(uriret.uri);
        VIR_FREE(uriret.uri);
        if (!conn->uri)
            goto failed;
    }

    if (!(priv->domainEventState = virDomainEventStateNew()))
        goto failed;

    /* Successful. */
    retcode = VIR_DRV_OPEN_SUCCESS;

 cleanup:
    /* Free up the URL and strings. */
    VIR_FREE(name);
    VIR_FREE(command);
    VIR_FREE(sockname);
    VIR_FREE(authtype);
    VIR_FREE(netcat);
    VIR_FREE(sshauth);
    VIR_FREE(keyfile);
    VIR_FREE(username);
    VIR_FREE(port);
    VIR_FREE(pkipath);
    VIR_FREE(knownHostsVerify);
    VIR_FREE(knownHosts);

    return retcode;

 failed:
    virObjectUnref(priv->remoteProgram);
    virObjectUnref(priv->lxcProgram);
    virObjectUnref(priv->qemuProgram);
    virNetClientClose(priv->client);
    virObjectUnref(priv->client);
    priv->client = NULL;
#ifdef WITH_GNUTLS
    virObjectUnref(priv->tls);
    priv->tls = NULL;
#endif

    VIR_FREE(priv->hostname);
    goto cleanup;
}
#undef EXTRACT_URI_ARG_STR
#undef EXTRACT_URI_ARG_BOOL

static struct private_data *
remoteAllocPrivateData(void)
{
    struct private_data *priv;
    if (VIR_ALLOC(priv) < 0)
        return NULL;

    if (virMutexInit(&priv->lock) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("cannot initialize mutex"));
        VIR_FREE(priv);
        return NULL;
    }
    remoteDriverLock(priv);
    priv->localUses = 1;

    return priv;
}

static int
remoteOpenSecondaryDriver(virConnectPtr conn,
                          virConnectAuthPtr auth,
                          unsigned int flags,
                          struct private_data **priv)
{
    int ret;
    int rflags = 0;

    if (!((*priv) = remoteAllocPrivateData()))
        return VIR_DRV_OPEN_ERROR;

    if (flags & VIR_CONNECT_RO)
        rflags |= VIR_DRV_OPEN_REMOTE_RO;

    ret = doRemoteOpen(conn, *priv, auth, rflags);
    if (ret != VIR_DRV_OPEN_SUCCESS) {
        remoteDriverUnlock(*priv);
        VIR_FREE(*priv);
    } else {
        (*priv)->localUses = 1;
        remoteDriverUnlock(*priv);
    }

    return ret;
}

static virDrvOpenStatus
remoteConnectOpen(virConnectPtr conn,
                  virConnectAuthPtr auth,
                  unsigned int flags)
{
    struct private_data *priv;
    int ret, rflags = 0;
    const char *autostart = virGetEnvBlockSUID("LIBVIRT_AUTOSTART");

    if (inside_daemon && (!conn->uri || (conn->uri && !conn->uri->server)))
        return VIR_DRV_OPEN_DECLINED;

    if (!(priv = remoteAllocPrivateData()))
        return VIR_DRV_OPEN_ERROR;

    if (flags & VIR_CONNECT_RO)
        rflags |= VIR_DRV_OPEN_REMOTE_RO;

    /*
     * If no servername is given, and no +XXX
     * transport is listed, or transport is unix,
     * and path is /session, and uid is unprivileged
     * then auto-spawn a daemon.
     */
    if (conn->uri &&
        !conn->uri->server &&
        conn->uri->path &&
        conn->uri->scheme &&
        ((strchr(conn->uri->scheme, '+') == 0)||
         (strstr(conn->uri->scheme, "+unix") != NULL)) &&
        (STREQ(conn->uri->path, "/session") ||
         STRPREFIX(conn->uri->scheme, "test+")) &&
        geteuid() > 0) {
        VIR_DEBUG("Auto-spawn user daemon instance");
        rflags |= VIR_DRV_OPEN_REMOTE_USER;
        if (!virIsSUID() &&
            (!autostart ||
             STRNEQ(autostart, "0")))
            rflags |= VIR_DRV_OPEN_REMOTE_AUTOSTART;
    }

    /*
     * If URI is NULL, then do a UNIX connection possibly auto-spawning
     * unprivileged server and probe remote server for URI. On Solaris,
     * this isn't supported, but we may be privileged enough to connect
     * to the UNIX socket anyway.
     */
    if (!conn->uri) {
        VIR_DEBUG("Auto-probe remote URI");
#ifndef __sun
        if (geteuid() > 0) {
            VIR_DEBUG("Auto-spawn user daemon instance");
            rflags |= VIR_DRV_OPEN_REMOTE_USER;
            if (!virIsSUID() &&
                (!autostart ||
                 STRNEQ(autostart, "0")))
                rflags |= VIR_DRV_OPEN_REMOTE_AUTOSTART;
        }
#endif
    }

    ret = doRemoteOpen(conn, priv, auth, rflags);
    if (ret != VIR_DRV_OPEN_SUCCESS) {
        conn->privateData = NULL;
        remoteDriverUnlock(priv);
        VIR_FREE(priv);
    } else {
        conn->privateData = priv;
        remoteDriverUnlock(priv);
    }
    return ret;
}


/* In a string "driver+transport" return a pointer to "transport". */
static char *
get_transport_from_scheme(char *scheme)
{
    char *p = strchr(scheme, '+');
    return p ? p + 1 : NULL;
}

/*----------------------------------------------------------------------*/


static int
doRemoteClose(virConnectPtr conn, struct private_data *priv)
{
    int ret = 0;

    if (call(conn, priv, 0, REMOTE_PROC_CONNECT_CLOSE,
             (xdrproc_t) xdr_void, (char *) NULL,
             (xdrproc_t) xdr_void, (char *) NULL) == -1)
        ret = -1;

#ifdef WITH_GNUTLS
    virObjectUnref(priv->tls);
    priv->tls = NULL;
#endif

    virNetClientSetCloseCallback(priv->client,
                                 NULL,
                                 conn->closeCallback, virObjectFreeCallback);

    virNetClientClose(priv->client);
    virObjectUnref(priv->client);
    priv->client = NULL;
    virObjectUnref(priv->remoteProgram);
    virObjectUnref(priv->lxcProgram);
    virObjectUnref(priv->qemuProgram);
    priv->remoteProgram = priv->qemuProgram = priv->lxcProgram = NULL;

    /* Free hostname copy */
    VIR_FREE(priv->hostname);

    /* See comment for remoteType. */
    VIR_FREE(priv->type);

    virDomainEventStateFree(priv->domainEventState);
    priv->domainEventState = NULL;

    return ret;
}

static int
remoteConnectClose(virConnectPtr conn)
{
    int ret = 0;
    struct private_data *priv = conn->privateData;

    remoteDriverLock(priv);
    priv->localUses--;
    if (!priv->localUses) {
        ret = doRemoteClose(conn, priv);
        conn->privateData = NULL;
        remoteDriverUnlock(priv);
        virMutexDestroy(&priv->lock);
        VIR_FREE(priv);
    }
    if (priv)
        remoteDriverUnlock(priv);

    return ret;
}


/* Unfortunately this function is defined to return a static string.
 * Since the remote end always answers with the same type (for a
 * single connection anyway) we cache the type in the connection's
 * private data, and free it when we close the connection.
 *
 * See also:
 * http://www.redhat.com/archives/libvir-list/2007-February/msg00096.html
 */
static const char *
remoteConnectGetType(virConnectPtr conn)
{
    char *rv = NULL;
    remote_connect_get_type_ret ret;
    struct private_data *priv = conn->privateData;

    remoteDriverLock(priv);

    /* Cached? */
    if (priv->type) {
        rv = priv->type;
        goto done;
    }

    memset(&ret, 0, sizeof(ret));
    if (call(conn, priv, 0, REMOTE_PROC_CONNECT_GET_TYPE,
             (xdrproc_t) xdr_void, (char *) NULL,
             (xdrproc_t) xdr_remote_connect_get_type_ret, (char *) &ret) == -1)
        goto done;

    /* Stash. */
    rv = priv->type = ret.type;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int remoteConnectIsSecure(virConnectPtr conn)
{
    int rv = -1;
    struct private_data *priv = conn->privateData;
    remote_connect_is_secure_ret ret;
    remoteDriverLock(priv);

    memset(&ret, 0, sizeof(ret));
    if (call(conn, priv, 0, REMOTE_PROC_CONNECT_IS_SECURE,
             (xdrproc_t) xdr_void, (char *) NULL,
             (xdrproc_t) xdr_remote_connect_is_secure_ret, (char *) &ret) == -1)
        goto done;

    /* We claim to be secure, if the remote driver
     * transport itself is secure, and the remote
     * HV connection is secure
     *
     * ie, we don't want to claim to be secure if the
     * remote driver is used to connect to a XenD
     * driver using unencrypted HTTP:/// access
     */
    rv = priv->is_secure && ret.secure ? 1 : 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int remoteConnectIsEncrypted(virConnectPtr conn)
{
    int rv = -1;
    bool encrypted;
    struct private_data *priv = conn->privateData;
    remote_connect_is_secure_ret ret;
    remoteDriverLock(priv);

    memset(&ret, 0, sizeof(ret));
    if (call(conn, priv, 0, REMOTE_PROC_CONNECT_IS_SECURE,
             (xdrproc_t) xdr_void, (char *) NULL,
             (xdrproc_t) xdr_remote_connect_is_secure_ret, (char *) &ret) == -1)
        goto done;

    encrypted = virNetClientIsEncrypted(priv->client);

    /* We claim to be encrypted, if the remote driver
     * transport itself is encrypted, and the remote
     * HV connection is secure.
     *
     * Yes, we really don't check the remote 'encrypted'
     * option, since it will almost always be false,
     * even if secure (eg UNIX sockets).
     */
    rv = encrypted && ret.secure ? 1 : 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteNodeGetCPUStats(virConnectPtr conn,
                      int cpuNum,
                      virNodeCPUStatsPtr params, int *nparams,
                      unsigned int flags)
{
    int rv = -1;
    remote_node_get_cpu_stats_args args;
    remote_node_get_cpu_stats_ret ret;
    size_t i;
    struct private_data *priv = conn->privateData;

    remoteDriverLock(priv);

    args.nparams = *nparams;
    args.cpuNum = cpuNum;
    args.flags = flags;

    memset(&ret, 0, sizeof(ret));
    if (call(conn, priv, 0, REMOTE_PROC_NODE_GET_CPU_STATS,
             (xdrproc_t) xdr_remote_node_get_cpu_stats_args,
             (char *) &args,
             (xdrproc_t) xdr_remote_node_get_cpu_stats_ret,
             (char *) &ret) == -1)
        goto done;

    /* Check the length of the returned list carefully. */
    if (ret.params.params_len > REMOTE_NODE_CPU_STATS_MAX ||
        ret.params.params_len > *nparams) {
        virReportError(VIR_ERR_RPC, "%s",
                       _("remoteNodeGetCPUStats: "
                         "returned number of stats exceeds limit"));
        goto cleanup;
    }
    /* Handle the case when the caller does not know the number of stats
     * and is asking for the number of stats supported
     */
    if (*nparams == 0) {
        *nparams = ret.nparams;
        rv = 0;
        goto cleanup;
    }

    *nparams = ret.params.params_len;

    /* Deserialise the result. */
    for (i = 0; i < *nparams; ++i) {
        if (virStrcpyStatic(params[i].field, ret.params.params_val[i].field) == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Stats %s too big for destination"),
                           ret.params.params_val[i].field);
            goto cleanup;
        }
        params[i].value = ret.params.params_val[i].value;
    }

    rv = 0;

cleanup:
    xdr_free((xdrproc_t) xdr_remote_node_get_cpu_stats_ret, (char *) &ret);
done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteNodeGetMemoryStats(virConnectPtr conn,
                         int cellNum,
                         virNodeMemoryStatsPtr params,
                         int *nparams,
                         unsigned int flags)
{
    int rv = -1;
    remote_node_get_memory_stats_args args;
    remote_node_get_memory_stats_ret ret;
    size_t i;
    struct private_data *priv = conn->privateData;

    remoteDriverLock(priv);

    args.nparams = *nparams;
    args.cellNum = cellNum;
    args.flags = flags;

    memset(&ret, 0, sizeof(ret));
    if (call(conn, priv, 0, REMOTE_PROC_NODE_GET_MEMORY_STATS,
             (xdrproc_t) xdr_remote_node_get_memory_stats_args, (char *) &args,
             (xdrproc_t) xdr_remote_node_get_memory_stats_ret, (char *) &ret) == -1)
        goto done;

    /* Check the length of the returned list carefully. */
    if (ret.params.params_len > REMOTE_NODE_MEMORY_STATS_MAX ||
        ret.params.params_len > *nparams) {
        virReportError(VIR_ERR_RPC, "%s",
                       _("remoteNodeGetMemoryStats: "
                         "returned number of stats exceeds limit"));
        goto cleanup;
    }
    /* Handle the case when the caller does not know the number of stats
     * and is asking for the number of stats supported
     */
    if (*nparams == 0) {
        *nparams = ret.nparams;
        rv = 0;
        goto cleanup;
    }

    *nparams = ret.params.params_len;

    /* Deserialise the result. */
    for (i = 0; i < *nparams; ++i) {
        if (virStrcpyStatic(params[i].field, ret.params.params_val[i].field) == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Stats %s too big for destination"),
                           ret.params.params_val[i].field);
            goto cleanup;
        }
        params[i].value = ret.params.params_val[i].value;
    }

    rv = 0;

cleanup:
    xdr_free((xdrproc_t) xdr_remote_node_get_memory_stats_ret, (char *) &ret);
done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteNodeGetCellsFreeMemory(virConnectPtr conn,
                             unsigned long long *freeMems,
                             int startCell,
                             int maxCells)
{
    int rv = -1;
    remote_node_get_cells_free_memory_args args;
    remote_node_get_cells_free_memory_ret ret;
    size_t i;
    struct private_data *priv = conn->privateData;

    remoteDriverLock(priv);

    if (maxCells > REMOTE_NODE_MAX_CELLS) {
        virReportError(VIR_ERR_RPC,
                       _("too many NUMA cells: %d > %d"),
                       maxCells, REMOTE_NODE_MAX_CELLS);
        goto done;
    }

    args.startCell = startCell;
    args.maxcells = maxCells;

    memset(&ret, 0, sizeof(ret));
    if (call(conn, priv, 0, REMOTE_PROC_NODE_GET_CELLS_FREE_MEMORY,
             (xdrproc_t) xdr_remote_node_get_cells_free_memory_args, (char *)&args,
             (xdrproc_t) xdr_remote_node_get_cells_free_memory_ret, (char *)&ret) == -1)
        goto done;

    for (i = 0; i < ret.cells.cells_len; i++)
        freeMems[i] = ret.cells.cells_val[i];

    xdr_free((xdrproc_t) xdr_remote_node_get_cells_free_memory_ret, (char *) &ret);

    rv = ret.cells.cells_len;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteConnectListDomains(virConnectPtr conn, int *ids, int maxids)
{
    int rv = -1;
    size_t i;
    remote_connect_list_domains_args args;
    remote_connect_list_domains_ret ret;
    struct private_data *priv = conn->privateData;

    remoteDriverLock(priv);

    if (maxids > REMOTE_DOMAIN_LIST_MAX) {
        virReportError(VIR_ERR_RPC,
                       _("Too many domains '%d' for limit '%d'"),
                       maxids, REMOTE_DOMAIN_LIST_MAX);
        goto done;
    }
    args.maxids = maxids;

    memset(&ret, 0, sizeof(ret));
    if (call(conn, priv, 0, REMOTE_PROC_CONNECT_LIST_DOMAINS,
             (xdrproc_t) xdr_remote_connect_list_domains_args, (char *) &args,
             (xdrproc_t) xdr_remote_connect_list_domains_ret, (char *) &ret) == -1)
        goto done;

    if (ret.ids.ids_len > maxids) {
        virReportError(VIR_ERR_RPC,
                       _("Too many domains '%d' for limit '%d'"),
                       ret.ids.ids_len, maxids);
        goto cleanup;
    }

    for (i = 0; i < ret.ids.ids_len; ++i)
        ids[i] = ret.ids.ids_val[i];

    rv = ret.ids.ids_len;

cleanup:
    xdr_free((xdrproc_t) xdr_remote_connect_list_domains_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteConnectListAllDomains(virConnectPtr conn,
                            virDomainPtr **domains,
                            unsigned int flags)
{
    int rv = -1;
    size_t i;
    virDomainPtr *doms = NULL;
    remote_connect_list_all_domains_args args;
    remote_connect_list_all_domains_ret ret;

    struct private_data *priv = conn->privateData;

    remoteDriverLock(priv);

    args.need_results = !!domains;
    args.flags = flags;

    memset(&ret, 0, sizeof(ret));
    if (call(conn,
             priv,
             0,
             REMOTE_PROC_CONNECT_LIST_ALL_DOMAINS,
             (xdrproc_t) xdr_remote_connect_list_all_domains_args,
             (char *) &args,
             (xdrproc_t) xdr_remote_connect_list_all_domains_ret,
             (char *) &ret) == -1)
        goto done;

    if (ret.domains.domains_len > REMOTE_DOMAIN_LIST_MAX) {
        virReportError(VIR_ERR_RPC,
                       _("Too many domains '%d' for limit '%d'"),
                       ret.domains.domains_len, REMOTE_DOMAIN_LIST_MAX);
        goto cleanup;
    }

    if (domains) {
        if (VIR_ALLOC_N(doms, ret.domains.domains_len + 1) < 0)
            goto cleanup;

        for (i = 0; i < ret.domains.domains_len; i++) {
            doms[i] = get_nonnull_domain(conn, ret.domains.domains_val[i]);
            if (!doms[i])
                goto cleanup;
        }
        *domains = doms;
        doms = NULL;
    }

    rv = ret.ret;

cleanup:
    if (doms) {
        for (i = 0; i < ret.domains.domains_len; i++)
            if (doms[i])
                virDomainFree(doms[i]);
        VIR_FREE(doms);
    }

    xdr_free((xdrproc_t) xdr_remote_connect_list_all_domains_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return rv;
}

/* Helper to free typed parameters. */
static void
remoteFreeTypedParameters(remote_typed_param *args_params_val,
                          u_int args_params_len)
{
    size_t i;

    if (args_params_val == NULL)
        return;

    for (i = 0; i < args_params_len; i++) {
        VIR_FREE(args_params_val[i].field);
        if (args_params_val[i].value.type == VIR_TYPED_PARAM_STRING)
            VIR_FREE(args_params_val[i].value.remote_typed_param_value_u.s);
    }

    VIR_FREE(args_params_val);
}

/* Helper to serialize typed parameters. */
static int
remoteSerializeTypedParameters(virTypedParameterPtr params,
                               int nparams,
                               remote_typed_param **args_params_val,
                               u_int *args_params_len)
{
    size_t i;
    int rv = -1;
    remote_typed_param *val;

    *args_params_len = nparams;
    if (VIR_ALLOC_N(val, nparams) < 0)
        goto cleanup;

    for (i = 0; i < nparams; ++i) {
        /* call() will free this: */
        if (VIR_STRDUP(val[i].field, params[i].field) < 0)
            goto cleanup;
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
        case VIR_TYPED_PARAM_STRING:
            if (VIR_STRDUP(val[i].value.remote_typed_param_value_u.s,
                           params[i].value.s) < 0)
                goto cleanup;
            break;
        default:
            virReportError(VIR_ERR_RPC, _("unknown parameter type: %d"),
                           params[i].type);
            goto cleanup;
        }
    }

    *args_params_val = val;
    val = NULL;
    rv = 0;

cleanup:
    remoteFreeTypedParameters(val, nparams);
    return rv;
}

/* Helper to deserialize typed parameters. */
static int
remoteDeserializeTypedParameters(remote_typed_param *ret_params_val,
                                 u_int ret_params_len,
                                 int limit,
                                 virTypedParameterPtr *params,
                                 int *nparams)
{
    size_t i = 0;
    int rv = -1;
    bool userAllocated = *params != NULL;

    if (userAllocated) {
        /* Check the length of the returned list carefully. */
        if (ret_params_len > limit || ret_params_len > *nparams) {
            virReportError(VIR_ERR_RPC, "%s",
                           _("returned number of parameters exceeds limit"));
            goto cleanup;
        }
    } else {
        if (VIR_ALLOC_N(*params, ret_params_len) < 0)
            goto cleanup;
    }
    *nparams = ret_params_len;

    /* Deserialise the result. */
    for (i = 0; i < ret_params_len; ++i) {
        virTypedParameterPtr param = *params + i;
        remote_typed_param *ret_param = ret_params_val + i;

        if (virStrcpyStatic(param->field,
                            ret_param->field) == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Parameter %s too big for destination"),
                           ret_param->field);
            goto cleanup;
        }

        param->type = ret_param->value.type;
        switch (param->type) {
        case VIR_TYPED_PARAM_INT:
            param->value.i =
                ret_param->value.remote_typed_param_value_u.i;
            break;
        case VIR_TYPED_PARAM_UINT:
            param->value.ui =
                ret_param->value.remote_typed_param_value_u.ui;
            break;
        case VIR_TYPED_PARAM_LLONG:
            param->value.l =
                ret_param->value.remote_typed_param_value_u.l;
            break;
        case VIR_TYPED_PARAM_ULLONG:
            param->value.ul =
                ret_param->value.remote_typed_param_value_u.ul;
            break;
        case VIR_TYPED_PARAM_DOUBLE:
            param->value.d =
                ret_param->value.remote_typed_param_value_u.d;
            break;
        case VIR_TYPED_PARAM_BOOLEAN:
            param->value.b =
                ret_param->value.remote_typed_param_value_u.b;
            break;
        case VIR_TYPED_PARAM_STRING:
            if (VIR_STRDUP(param->value.s,
                           ret_param->value.remote_typed_param_value_u.s) < 0)
                goto cleanup;
            break;
        default:
            virReportError(VIR_ERR_RPC, _("unknown parameter type: %d"),
                           param->type);
            goto cleanup;
        }
    }

    rv = 0;

cleanup:
    if (rv < 0) {
        if (userAllocated) {
            virTypedParamsClear(*params, i);
        } else {
            virTypedParamsFree(*params, i);
            *params = NULL;
        }
    }
    return rv;
}

static int
remoteDeserializeDomainDiskErrors(remote_domain_disk_error *ret_errors_val,
                                  u_int ret_errors_len,
                                  int limit,
                                  virDomainDiskErrorPtr errors,
                                  int maxerrors)
{
    size_t i = 0;
    size_t j;

    if (ret_errors_len > limit || ret_errors_len > maxerrors) {
        virReportError(VIR_ERR_RPC, "%s",
                       _("returned number of disk errors exceeds limit"));
        goto error;
    }

    for (i = 0; i < ret_errors_len; i++) {
        if (VIR_STRDUP(errors[i].disk, ret_errors_val[i].disk) < 0)
            goto error;
        errors[i].error = ret_errors_val[i].error;
    }

    return 0;

error:
    for (j = 0; j < i; j++)
        VIR_FREE(errors[i].disk);

    return -1;
}

static int
remoteDomainBlockStatsFlags(virDomainPtr domain,
                            const char *path,
                            virTypedParameterPtr params,
                            int *nparams,
                            unsigned int flags)
{
    int rv = -1;
    remote_domain_block_stats_flags_args args;
    remote_domain_block_stats_flags_ret ret;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain(&args.dom, domain);
    args.nparams = *nparams;
    args.path = (char *) path;
    args.flags = flags;

    memset(&ret, 0, sizeof(ret));
    if (call(domain->conn, priv, 0, REMOTE_PROC_DOMAIN_BLOCK_STATS_FLAGS,
             (xdrproc_t) xdr_remote_domain_block_stats_flags_args, (char *) &args,
             (xdrproc_t) xdr_remote_domain_block_stats_flags_ret, (char *) &ret) == -1)
        goto done;

    /* Check the length of the returned list carefully. */
    if (ret.params.params_len > REMOTE_DOMAIN_BLOCK_STATS_PARAMETERS_MAX ||
        ret.params.params_len > *nparams) {
        virReportError(VIR_ERR_RPC, "%s",
                       _("remoteDomainBlockStatsFlags: "
                         "returned number of stats exceeds limit"));
        goto cleanup;
    }

    /* Handle the case when the caller does not know the number of stats
     * and is asking for the number of stats supported
     */
    if (*nparams == 0) {
        *nparams = ret.nparams;
        rv = 0;
        goto cleanup;
    }

    *nparams = ret.params.params_len;

    /* Deserialise the result. */
    if (remoteDeserializeTypedParameters(ret.params.params_val,
                                         ret.params.params_len,
                                         REMOTE_DOMAIN_MEMORY_PARAMETERS_MAX,
                                         &params,
                                         nparams) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    xdr_free((xdrproc_t) xdr_remote_domain_block_stats_flags_ret,
             (char *) &ret);
done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteDomainGetMemoryParameters(virDomainPtr domain,
                                virTypedParameterPtr params, int *nparams,
                                unsigned int flags)
{
    int rv = -1;
    remote_domain_get_memory_parameters_args args;
    remote_domain_get_memory_parameters_ret ret;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain(&args.dom, domain);
    args.nparams = *nparams;
    args.flags = flags;

    memset(&ret, 0, sizeof(ret));
    if (call(domain->conn, priv, 0, REMOTE_PROC_DOMAIN_GET_MEMORY_PARAMETERS,
             (xdrproc_t) xdr_remote_domain_get_memory_parameters_args, (char *) &args,
             (xdrproc_t) xdr_remote_domain_get_memory_parameters_ret, (char *) &ret) == -1)
        goto done;

    /* Handle the case when the caller does not know the number of parameters
     * and is asking for the number of parameters supported
     */
    if (*nparams == 0) {
        *nparams = ret.nparams;
        rv = 0;
        goto cleanup;
    }

    if (remoteDeserializeTypedParameters(ret.params.params_val,
                                         ret.params.params_len,
                                         REMOTE_DOMAIN_MEMORY_PARAMETERS_MAX,
                                         &params,
                                         nparams) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    xdr_free((xdrproc_t) xdr_remote_domain_get_memory_parameters_ret,
             (char *) &ret);
done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteDomainGetNumaParameters(virDomainPtr domain,
                              virTypedParameterPtr params, int *nparams,
                              unsigned int flags)
{
    int rv = -1;
    remote_domain_get_numa_parameters_args args;
    remote_domain_get_numa_parameters_ret ret;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain(&args.dom, domain);
    args.nparams = *nparams;
    args.flags = flags;

    memset(&ret, 0, sizeof(ret));
    if (call(domain->conn, priv, 0, REMOTE_PROC_DOMAIN_GET_NUMA_PARAMETERS,
             (xdrproc_t) xdr_remote_domain_get_numa_parameters_args, (char *) &args,
             (xdrproc_t) xdr_remote_domain_get_numa_parameters_ret, (char *) &ret) == -1)
        goto done;

    /* Handle the case when the caller does not know the number of parameters
     * and is asking for the number of parameters supported
     */
    if (*nparams == 0) {
        *nparams = ret.nparams;
        rv = 0;
        goto cleanup;
    }

    if (remoteDeserializeTypedParameters(ret.params.params_val,
                                         ret.params.params_len,
                                         REMOTE_DOMAIN_NUMA_PARAMETERS_MAX,
                                         &params,
                                         nparams) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    xdr_free((xdrproc_t) xdr_remote_domain_get_numa_parameters_ret,
             (char *) &ret);
done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteDomainGetBlkioParameters(virDomainPtr domain,
                               virTypedParameterPtr params, int *nparams,
                               unsigned int flags)
{
    int rv = -1;
    remote_domain_get_blkio_parameters_args args;
    remote_domain_get_blkio_parameters_ret ret;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain(&args.dom, domain);
    args.nparams = *nparams;
    args.flags = flags;

    memset(&ret, 0, sizeof(ret));
    if (call(domain->conn, priv, 0, REMOTE_PROC_DOMAIN_GET_BLKIO_PARAMETERS,
             (xdrproc_t) xdr_remote_domain_get_blkio_parameters_args, (char *) &args,
             (xdrproc_t) xdr_remote_domain_get_blkio_parameters_ret, (char *) &ret) == -1)
        goto done;

    /* Handle the case when the caller does not know the number of parameters
     * and is asking for the number of parameters supported
     */
    if (*nparams == 0) {
        *nparams = ret.nparams;
        rv = 0;
        goto cleanup;
    }

    if (remoteDeserializeTypedParameters(ret.params.params_val,
                                         ret.params.params_len,
                                         REMOTE_DOMAIN_BLKIO_PARAMETERS_MAX,
                                         &params,
                                         nparams) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    xdr_free((xdrproc_t) xdr_remote_domain_get_blkio_parameters_ret,
             (char *) &ret);
done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteDomainGetVcpuPinInfo(virDomainPtr domain,
                           int ncpumaps,
                           unsigned char *cpumaps,
                           int maplen,
                           unsigned int flags)
{
    int rv = -1;
    size_t i;
    remote_domain_get_vcpu_pin_info_args args;
    remote_domain_get_vcpu_pin_info_ret ret;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    if (ncpumaps > REMOTE_VCPUINFO_MAX) {
        virReportError(VIR_ERR_RPC,
                       _("vCPU count exceeds maximum: %d > %d"),
                       ncpumaps, REMOTE_VCPUINFO_MAX);
        goto done;
    }

    if (INT_MULTIPLY_OVERFLOW(ncpumaps, maplen) ||
        ncpumaps * maplen > REMOTE_CPUMAPS_MAX) {
        virReportError(VIR_ERR_RPC,
                       _("vCPU map buffer length exceeds maximum: %d > %d"),
                       ncpumaps * maplen, REMOTE_CPUMAPS_MAX);
        goto done;
    }

    make_nonnull_domain(&args.dom, domain);
    args.ncpumaps = ncpumaps;
    args.maplen = maplen;
    args.flags = flags;

    memset(&ret, 0, sizeof(ret));

    if (call(domain->conn, priv, 0, REMOTE_PROC_DOMAIN_GET_VCPU_PIN_INFO,
             (xdrproc_t) xdr_remote_domain_get_vcpu_pin_info_args,
             (char *) &args,
             (xdrproc_t) xdr_remote_domain_get_vcpu_pin_info_ret,
             (char *) &ret) == -1)
        goto done;

    if (ret.num > ncpumaps) {
        virReportError(VIR_ERR_RPC,
                       _("host reports too many vCPUs: %d > %d"),
                       ret.num, ncpumaps);
        goto cleanup;
    }

    if (ret.cpumaps.cpumaps_len > ncpumaps * maplen) {
        virReportError(VIR_ERR_RPC,
                       _("host reports map buffer length exceeds maximum: %d > %d"),
                       ret.cpumaps.cpumaps_len, ncpumaps * maplen);
        goto cleanup;
    }

    memset(cpumaps, 0, ncpumaps * maplen);

    for (i = 0; i < ret.cpumaps.cpumaps_len; ++i)
        cpumaps[i] = ret.cpumaps.cpumaps_val[i];

    rv = ret.num;

cleanup:
    xdr_free((xdrproc_t) xdr_remote_domain_get_vcpu_pin_info_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteDomainPinEmulator(virDomainPtr dom,
                        unsigned char *cpumap,
                        int cpumaplen,
                        unsigned int flags)
{
    int rv = -1;
    struct private_data *priv = dom->conn->privateData;
    remote_domain_pin_emulator_args args;

    remoteDriverLock(priv);

    if (cpumaplen > REMOTE_CPUMAP_MAX) {
        virReportError(VIR_ERR_RPC,
                       _("%s length greater than maximum: %d > %d"),
                       "cpumap", cpumaplen, REMOTE_CPUMAP_MAX);
        goto done;
    }

    make_nonnull_domain(&args.dom, dom);
    args.cpumap.cpumap_val = (char *)cpumap;
    args.cpumap.cpumap_len = cpumaplen;
    args.flags = flags;

    if (call(dom->conn, priv, 0, REMOTE_PROC_DOMAIN_PIN_EMULATOR,
             (xdrproc_t) xdr_remote_domain_pin_emulator_args,
             (char *) &args,
             (xdrproc_t) xdr_void, (char *) NULL) == -1) {
        goto done;
    }

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}


static int
remoteDomainGetEmulatorPinInfo(virDomainPtr domain,
                               unsigned char *cpumaps,
                               int maplen,
                               unsigned int flags)
{
    int rv = -1;
    size_t i;
    remote_domain_get_emulator_pin_info_args args;
    remote_domain_get_emulator_pin_info_ret ret;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    /* There is only one cpumap for all emulator threads */
    if (maplen > REMOTE_CPUMAPS_MAX) {
        virReportError(VIR_ERR_RPC,
                       _("vCPU map buffer length exceeds maximum: %d > %d"),
                       maplen, REMOTE_CPUMAPS_MAX);
        goto done;
    }

    make_nonnull_domain(&args.dom, domain);
    args.maplen = maplen;
    args.flags = flags;

    memset(&ret, 0, sizeof(ret));

    if (call(domain->conn, priv, 0, REMOTE_PROC_DOMAIN_GET_EMULATOR_PIN_INFO,
             (xdrproc_t) xdr_remote_domain_get_emulator_pin_info_args,
             (char *) &args,
             (xdrproc_t) xdr_remote_domain_get_emulator_pin_info_ret,
             (char *) &ret) == -1)
        goto done;

    if (ret.cpumaps.cpumaps_len > maplen) {
        virReportError(VIR_ERR_RPC,
                       _("host reports map buffer length exceeds maximum: %d > %d"),
                       ret.cpumaps.cpumaps_len, maplen);
        goto cleanup;
    }

    memset(cpumaps, 0, maplen);

    for (i = 0; i < ret.cpumaps.cpumaps_len; ++i)
        cpumaps[i] = ret.cpumaps.cpumaps_val[i];

    rv = ret.ret;

cleanup:
    xdr_free((xdrproc_t) xdr_remote_domain_get_emulator_pin_info_ret,
             (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteDomainGetVcpus(virDomainPtr domain,
                     virVcpuInfoPtr info,
                     int maxinfo,
                     unsigned char *cpumaps,
                     int maplen)
{
    int rv = -1;
    size_t i;
    remote_domain_get_vcpus_args args;
    remote_domain_get_vcpus_ret ret;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    if (maxinfo > REMOTE_VCPUINFO_MAX) {
        virReportError(VIR_ERR_RPC,
                       _("vCPU count exceeds maximum: %d > %d"),
                       maxinfo, REMOTE_VCPUINFO_MAX);
        goto done;
    }
    if (INT_MULTIPLY_OVERFLOW(maxinfo, maplen) ||
        maxinfo * maplen > REMOTE_CPUMAPS_MAX) {
        virReportError(VIR_ERR_RPC,
                       _("vCPU map buffer length exceeds maximum: %d > %d"),
                       maxinfo * maplen, REMOTE_CPUMAPS_MAX);
        goto done;
    }

    make_nonnull_domain(&args.dom, domain);
    args.maxinfo = maxinfo;
    args.maplen = maplen;

    memset(&ret, 0, sizeof(ret));
    if (call(domain->conn, priv, 0, REMOTE_PROC_DOMAIN_GET_VCPUS,
             (xdrproc_t) xdr_remote_domain_get_vcpus_args, (char *) &args,
             (xdrproc_t) xdr_remote_domain_get_vcpus_ret, (char *) &ret) == -1)
        goto done;

    if (ret.info.info_len > maxinfo) {
        virReportError(VIR_ERR_RPC,
                       _("host reports too many vCPUs: %d > %d"),
                       ret.info.info_len, maxinfo);
        goto cleanup;
    }
    if (ret.cpumaps.cpumaps_len > maxinfo * maplen) {
        virReportError(VIR_ERR_RPC,
                       _("host reports map buffer length exceeds maximum: %d > %d"),
                       ret.cpumaps.cpumaps_len, maxinfo * maplen);
        goto cleanup;
    }

    memset(info, 0, sizeof(virVcpuInfo) * maxinfo);
    memset(cpumaps, 0, maxinfo * maplen);

    for (i = 0; i < ret.info.info_len; ++i) {
        info[i].number = ret.info.info_val[i].number;
        info[i].state = ret.info.info_val[i].state;
        info[i].cpuTime = ret.info.info_val[i].cpu_time;
        info[i].cpu = ret.info.info_val[i].cpu;
    }

    for (i = 0; i < ret.cpumaps.cpumaps_len; ++i)
        cpumaps[i] = ret.cpumaps.cpumaps_val[i];

    rv = ret.info.info_len;

cleanup:
    xdr_free((xdrproc_t) xdr_remote_domain_get_vcpus_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteDomainGetSecurityLabel(virDomainPtr domain, virSecurityLabelPtr seclabel)
{
    remote_domain_get_security_label_args args;
    remote_domain_get_security_label_ret ret;
    struct private_data *priv = domain->conn->privateData;
    int rv = -1;

    remoteDriverLock(priv);

    make_nonnull_domain(&args.dom, domain);
    memset(&ret, 0, sizeof(ret));
    memset(seclabel, 0, sizeof(*seclabel));

    if (call(domain->conn, priv, 0, REMOTE_PROC_DOMAIN_GET_SECURITY_LABEL,
             (xdrproc_t) xdr_remote_domain_get_security_label_args, (char *)&args,
             (xdrproc_t) xdr_remote_domain_get_security_label_ret, (char *)&ret) == -1) {
        goto done;
    }

    if (ret.label.label_val != NULL) {
        if (strlen(ret.label.label_val) >= sizeof(seclabel->label)) {
            virReportError(VIR_ERR_RPC, _("security label exceeds maximum: %zu"),
                           sizeof(seclabel->label) - 1);
            goto cleanup;
        }
        strcpy(seclabel->label, ret.label.label_val);
        seclabel->enforcing = ret.enforcing;
    }

    rv = 0;

cleanup:
    xdr_free((xdrproc_t) xdr_remote_domain_get_security_label_ret, (char *)&ret);

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteDomainGetSecurityLabelList(virDomainPtr domain, virSecurityLabelPtr* seclabels)
{
    remote_domain_get_security_label_list_args args;
    remote_domain_get_security_label_list_ret ret;
    struct private_data *priv = domain->conn->privateData;
    size_t i;
    int rv = -1;

    remoteDriverLock(priv);

    make_nonnull_domain(&args.dom, domain);
    memset(&ret, 0, sizeof(ret));

    if (call(domain->conn, priv, 0, REMOTE_PROC_DOMAIN_GET_SECURITY_LABEL_LIST,
             (xdrproc_t) xdr_remote_domain_get_security_label_list_args, (char *)&args,
             (xdrproc_t) xdr_remote_domain_get_security_label_list_ret, (char *)&ret) == -1) {
        goto done;
    }

    if (VIR_ALLOC_N(*seclabels, ret.labels.labels_len) < 0)
        goto cleanup;

    for (i = 0; i < ret.labels.labels_len; i++) {
        remote_domain_get_security_label_ret *cur = &ret.labels.labels_val[i];
        if (cur->label.label_val != NULL) {
            if (strlen(cur->label.label_val) >= sizeof((*seclabels)->label)) {
                virReportError(VIR_ERR_RPC, _("security label exceeds maximum: %zd"),
                               sizeof((*seclabels)->label) - 1);
                VIR_FREE(*seclabels);
                goto cleanup;
            }
            strcpy((*seclabels)[i].label, cur->label.label_val);
            (*seclabels)[i].enforcing = cur->enforcing;
        }
    }
    rv = ret.ret;

cleanup:
    xdr_free((xdrproc_t) xdr_remote_domain_get_security_label_list_ret, (char *)&ret);

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteDomainGetState(virDomainPtr domain,
                     int *state,
                     int *reason,
                     unsigned int flags)
{
    int rv = -1;
    remote_domain_get_state_args args;
    remote_domain_get_state_ret ret;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain(&args.dom, domain);
    args.flags = flags;

    memset(&ret, 0, sizeof(ret));
    if (call(domain->conn, priv, 0, REMOTE_PROC_DOMAIN_GET_STATE,
             (xdrproc_t) xdr_remote_domain_get_state_args, (char *) &args,
             (xdrproc_t) xdr_remote_domain_get_state_ret, (char *) &ret) == -1)
        goto done;

    *state = ret.state;
    if (reason)
        *reason = ret.reason;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteNodeGetSecurityModel(virConnectPtr conn, virSecurityModelPtr secmodel)
{
    remote_node_get_security_model_ret ret;
    struct private_data *priv = conn->privateData;
    int rv = -1;

    remoteDriverLock(priv);

    memset(&ret, 0, sizeof(ret));
    memset(secmodel, 0, sizeof(*secmodel));

    if (call(conn, priv, 0, REMOTE_PROC_NODE_GET_SECURITY_MODEL,
             (xdrproc_t) xdr_void, NULL,
             (xdrproc_t) xdr_remote_node_get_security_model_ret, (char *)&ret) == -1) {
        goto done;
    }

    if (ret.model.model_val != NULL) {
        if (strlen(ret.model.model_val) >= sizeof(secmodel->model)) {
            virReportError(VIR_ERR_RPC, _("security model exceeds maximum: %zu"),
                           sizeof(secmodel->model) - 1);
            goto cleanup;
        }
        strcpy(secmodel->model, ret.model.model_val);
    }

    if (ret.doi.doi_val != NULL) {
        if (strlen(ret.doi.doi_val) >= sizeof(secmodel->doi)) {
            virReportError(VIR_ERR_RPC, _("security doi exceeds maximum: %zu"),
                           sizeof(secmodel->doi) - 1);
            goto cleanup;
        }
        strcpy(secmodel->doi, ret.doi.doi_val);
    }

    rv = 0;

cleanup:
    xdr_free((xdrproc_t) xdr_remote_node_get_security_model_ret, (char *)&ret);

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteDomainMigratePrepare(virConnectPtr dconn,
                           char **cookie, int *cookielen,
                           const char *uri_in, char **uri_out,
                           unsigned long flags, const char *dname,
                           unsigned long resource)
{
    int rv = -1;
    remote_domain_migrate_prepare_args args;
    remote_domain_migrate_prepare_ret ret;
    struct private_data *priv = dconn->privateData;

    remoteDriverLock(priv);

    args.uri_in = uri_in == NULL ? NULL : (char **) &uri_in;
    args.flags = flags;
    args.dname = dname == NULL ? NULL : (char **) &dname;
    args.resource = resource;

    memset(&ret, 0, sizeof(ret));
    if (call(dconn, priv, 0, REMOTE_PROC_DOMAIN_MIGRATE_PREPARE,
             (xdrproc_t) xdr_remote_domain_migrate_prepare_args, (char *) &args,
             (xdrproc_t) xdr_remote_domain_migrate_prepare_ret, (char *) &ret) == -1)
        goto done;

    if (ret.cookie.cookie_len > 0) {
        *cookie = ret.cookie.cookie_val; /* Caller frees. */
        *cookielen = ret.cookie.cookie_len;
    }
    if (ret.uri_out)
        *uri_out = *ret.uri_out; /* Caller frees. */

    VIR_FREE(ret.uri_out);
    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteDomainMigratePrepare2(virConnectPtr dconn,
                            char **cookie, int *cookielen,
                            const char *uri_in, char **uri_out,
                            unsigned long flags, const char *dname,
                            unsigned long resource,
                            const char *dom_xml)
{
    int rv = -1;
    remote_domain_migrate_prepare2_args args;
    remote_domain_migrate_prepare2_ret ret;
    struct private_data *priv = dconn->privateData;

    remoteDriverLock(priv);

    args.uri_in = uri_in == NULL ? NULL : (char **) &uri_in;
    args.flags = flags;
    args.dname = dname == NULL ? NULL : (char **) &dname;
    args.resource = resource;
    args.dom_xml = (char *) dom_xml;

    memset(&ret, 0, sizeof(ret));
    if (call(dconn, priv, 0, REMOTE_PROC_DOMAIN_MIGRATE_PREPARE2,
             (xdrproc_t) xdr_remote_domain_migrate_prepare2_args, (char *) &args,
             (xdrproc_t) xdr_remote_domain_migrate_prepare2_ret, (char *) &ret) == -1)
        goto done;

    if (ret.cookie.cookie_len > 0) {
        if (!cookie || !cookielen) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("caller ignores cookie or cookielen"));
            goto error;
        }
        *cookie = ret.cookie.cookie_val; /* Caller frees. */
        *cookielen = ret.cookie.cookie_len;
    }
    if (ret.uri_out) {
        if (!uri_out) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("caller ignores uri_out"));
            goto error;
        }
        *uri_out = *ret.uri_out; /* Caller frees. */
    }

    rv = 0;

done:
    VIR_FREE(ret.uri_out);
    remoteDriverUnlock(priv);
    return rv;
error:
    if (ret.cookie.cookie_len)
        VIR_FREE(ret.cookie.cookie_val);
    if (ret.uri_out)
        VIR_FREE(*ret.uri_out);
    goto done;
}

static int
remoteDomainCreate(virDomainPtr domain)
{
    int rv = -1;
    remote_domain_create_args args;
    remote_domain_lookup_by_uuid_args args2;
    remote_domain_lookup_by_uuid_ret ret2;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain(&args.dom, domain);

    if (call(domain->conn, priv, 0, REMOTE_PROC_DOMAIN_CREATE,
             (xdrproc_t) xdr_remote_domain_create_args, (char *) &args,
             (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto done;

    /* Need to do a lookup figure out ID of newly started guest, because
     * bug in design of REMOTE_PROC_DOMAIN_CREATE means we aren't getting
     * it returned.
     */
    memcpy(args2.uuid, domain->uuid, VIR_UUID_BUFLEN);
    memset(&ret2, 0, sizeof(ret2));
    if (call(domain->conn, priv, 0, REMOTE_PROC_DOMAIN_LOOKUP_BY_UUID,
             (xdrproc_t) xdr_remote_domain_lookup_by_uuid_args, (char *) &args2,
             (xdrproc_t) xdr_remote_domain_lookup_by_uuid_ret, (char *) &ret2) == -1)
        goto done;

    domain->id = ret2.dom.id;
    xdr_free((xdrproc_t) &xdr_remote_domain_lookup_by_uuid_ret, (char *) &ret2);

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteDomainCreateWithFlags(virDomainPtr dom, unsigned int flags)
{
    int rv = -1;
    struct private_data *priv = dom->conn->privateData;
    remote_domain_create_with_flags_args args;
    remote_domain_create_with_flags_args ret;

    remoteDriverLock(priv);

    make_nonnull_domain(&args.dom, dom);
    args.flags = flags;

    memset(&ret, 0, sizeof(ret));
    if (call(dom->conn, priv, 0, REMOTE_PROC_DOMAIN_CREATE_WITH_FLAGS,
             (xdrproc_t)xdr_remote_domain_create_with_flags_args, (char *)&args,
             (xdrproc_t)xdr_remote_domain_create_with_flags_ret, (char *)&ret) == -1) {
        goto done;
    }

    dom->id = ret.dom.id;
    xdr_free((xdrproc_t) &xdr_remote_domain_create_with_flags_ret, (char *) &ret);
    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static char *
remoteDomainGetSchedulerType(virDomainPtr domain, int *nparams)
{
    char *rv = NULL;
    remote_domain_get_scheduler_type_args args;
    remote_domain_get_scheduler_type_ret ret;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain(&args.dom, domain);

    memset(&ret, 0, sizeof(ret));
    if (call(domain->conn, priv, 0, REMOTE_PROC_DOMAIN_GET_SCHEDULER_TYPE,
             (xdrproc_t) xdr_remote_domain_get_scheduler_type_args, (char *) &args,
             (xdrproc_t) xdr_remote_domain_get_scheduler_type_ret, (char *) &ret) == -1)
        goto done;

    if (nparams) *nparams = ret.nparams;

    /* Caller frees this. */
    rv = ret.type;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteDomainMemoryStats(virDomainPtr domain,
                        struct _virDomainMemoryStat *stats,
                        unsigned int nr_stats,
                        unsigned int flags)
{
    int rv = -1;
    remote_domain_memory_stats_args args;
    remote_domain_memory_stats_ret ret;
    struct private_data *priv = domain->conn->privateData;
    size_t i;

    remoteDriverLock(priv);

    make_nonnull_domain(&args.dom, domain);
    if (nr_stats > REMOTE_DOMAIN_MEMORY_STATS_MAX) {
        virReportError(VIR_ERR_RPC,
                       _("too many memory stats requested: %d > %d"), nr_stats,
                       REMOTE_DOMAIN_MEMORY_STATS_MAX);
        goto done;
    }
    args.maxStats = nr_stats;
    args.flags = flags;
    memset(&ret, 0, sizeof(ret));

    if (call(domain->conn, priv, 0, REMOTE_PROC_DOMAIN_MEMORY_STATS,
             (xdrproc_t) xdr_remote_domain_memory_stats_args,
             (char *) &args,
             (xdrproc_t) xdr_remote_domain_memory_stats_ret,
             (char *) &ret) == -1)
        goto done;

    for (i = 0; i < ret.stats.stats_len; i++) {
        stats[i].tag = ret.stats.stats_val[i].tag;
        stats[i].val = ret.stats.stats_val[i].val;
    }
    rv = ret.stats.stats_len;
    xdr_free((xdrproc_t) xdr_remote_domain_memory_stats_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteDomainBlockPeek(virDomainPtr domain,
                      const char *path,
                      unsigned long long offset,
                      size_t size,
                      void *buffer,
                      unsigned int flags)
{
    int rv = -1;
    remote_domain_block_peek_args args;
    remote_domain_block_peek_ret ret;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    if (size > REMOTE_DOMAIN_BLOCK_PEEK_BUFFER_MAX) {
        virReportError(VIR_ERR_RPC,
                       _("block peek request too large for remote protocol, %zi > %d"),
                       size, REMOTE_DOMAIN_BLOCK_PEEK_BUFFER_MAX);
        goto done;
    }

    make_nonnull_domain(&args.dom, domain);
    args.path = (char *) path;
    args.offset = offset;
    args.size = size;
    args.flags = flags;

    memset(&ret, 0, sizeof(ret));
    if (call(domain->conn, priv, 0, REMOTE_PROC_DOMAIN_BLOCK_PEEK,
             (xdrproc_t) xdr_remote_domain_block_peek_args,
             (char *) &args,
             (xdrproc_t) xdr_remote_domain_block_peek_ret,
             (char *) &ret) == -1)
        goto done;

    if (ret.buffer.buffer_len != size) {
        virReportError(VIR_ERR_RPC, "%s",
                       _("returned buffer is not same size as requested"));
        goto cleanup;
    }

    memcpy(buffer, ret.buffer.buffer_val, size);
    rv = 0;

cleanup:
    VIR_FREE(ret.buffer.buffer_val);

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteDomainMemoryPeek(virDomainPtr domain,
                       unsigned long long offset,
                       size_t size,
                       void *buffer,
                       unsigned int flags)
{
    int rv = -1;
    remote_domain_memory_peek_args args;
    remote_domain_memory_peek_ret ret;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    if (size > REMOTE_DOMAIN_MEMORY_PEEK_BUFFER_MAX) {
        virReportError(VIR_ERR_RPC,
                       _("memory peek request too large for remote protocol, %zi > %d"),
                       size, REMOTE_DOMAIN_MEMORY_PEEK_BUFFER_MAX);
        goto done;
    }

    make_nonnull_domain(&args.dom, domain);
    args.offset = offset;
    args.size = size;
    args.flags = flags;

    memset(&ret, 0, sizeof(ret));
    if (call(domain->conn, priv, 0, REMOTE_PROC_DOMAIN_MEMORY_PEEK,
             (xdrproc_t) xdr_remote_domain_memory_peek_args,
             (char *) &args,
             (xdrproc_t) xdr_remote_domain_memory_peek_ret,
             (char *) &ret) == -1)
        goto done;

    if (ret.buffer.buffer_len != size) {
        virReportError(VIR_ERR_RPC, "%s",
                       _("returned buffer is not same size as requested"));
        goto cleanup;
    }

    memcpy(buffer, ret.buffer.buffer_val, size);
    rv = 0;

cleanup:
    VIR_FREE(ret.buffer.buffer_val);

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int remoteDomainGetBlockJobInfo(virDomainPtr domain,
                                       const char *path,
                                       virDomainBlockJobInfoPtr info,
                                       unsigned int flags)
{
    int rv = -1;
    remote_domain_get_block_job_info_args args;
    remote_domain_get_block_job_info_ret ret;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain(&args.dom, domain);
    args.path = (char *)path;
    args.flags = flags;

    if (call(domain->conn, priv, 0, REMOTE_PROC_DOMAIN_GET_BLOCK_JOB_INFO,
             (xdrproc_t)xdr_remote_domain_get_block_job_info_args,
               (char *)&args,
             (xdrproc_t)xdr_remote_domain_get_block_job_info_ret,
               (char *)&ret) == -1)
        goto done;

    if (ret.found) {
        info->type = ret.type;
        info->bandwidth = ret.bandwidth;
        info->cur = ret.cur;
        info->end = ret.end;
        rv = 1;
    } else {
        rv = 0;
    }

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int remoteDomainGetBlockIoTune(virDomainPtr domain,
                                      const char *disk,
                                      virTypedParameterPtr params,
                                      int *nparams,
                                      unsigned int flags)
{
    int rv = -1;
    remote_domain_get_block_io_tune_args args;
    remote_domain_get_block_io_tune_ret ret;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain(&args.dom, domain);
    args.disk = disk ? (char **)&disk : NULL;
    args.nparams = *nparams;
    args.flags = flags;

    memset(&ret, 0, sizeof(ret));


    if (call(domain->conn, priv, 0, REMOTE_PROC_DOMAIN_GET_BLOCK_IO_TUNE,
             (xdrproc_t) xdr_remote_domain_get_block_io_tune_args,
               (char *) &args,
             (xdrproc_t) xdr_remote_domain_get_block_io_tune_ret,
               (char *) &ret) == -1) {
        goto done;
    }

    /* Handle the case when the caller does not know the number of parameters
     * and is asking for the number of parameters supported
     */
    if (*nparams == 0) {
        *nparams = ret.nparams;
        rv = 0;
        goto cleanup;
    }

    if (remoteDeserializeTypedParameters(ret.params.params_val,
                                         ret.params.params_len,
                                         REMOTE_DOMAIN_MEMORY_PARAMETERS_MAX,
                                         &params,
                                         nparams) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    xdr_free((xdrproc_t) xdr_remote_domain_get_block_io_tune_ret,
             (char *) &ret);
done:
    remoteDriverUnlock(priv);
    return rv;
}

static int remoteDomainGetCPUStats(virDomainPtr domain,
                                   virTypedParameterPtr params,
                                   unsigned int nparams,
                                   int start_cpu,
                                   unsigned int ncpus,
                                   unsigned int flags)
{
    struct private_data *priv = domain->conn->privateData;
    remote_domain_get_cpu_stats_args args;
    remote_domain_get_cpu_stats_ret ret;
    int rv = -1;
    int cpu;

    remoteDriverLock(priv);

    if (nparams > REMOTE_NODE_CPU_STATS_MAX) {
        virReportError(VIR_ERR_RPC,
                       _("nparams count exceeds maximum: %u > %u"),
                       nparams, REMOTE_NODE_CPU_STATS_MAX);
        goto done;
    }
    if (ncpus > REMOTE_DOMAIN_GET_CPU_STATS_NCPUS_MAX) {
        virReportError(VIR_ERR_RPC,
                       _("ncpus count exceeds maximum: %u > %u"),
                       ncpus, REMOTE_DOMAIN_GET_CPU_STATS_NCPUS_MAX);
        goto done;
    }

    make_nonnull_domain(&args.dom, domain);
    args.nparams = nparams;
    args.start_cpu = start_cpu;
    args.ncpus = ncpus;
    args.flags = flags;

    memset(&ret, 0, sizeof(ret));

    if (call(domain->conn, priv, 0, REMOTE_PROC_DOMAIN_GET_CPU_STATS,
             (xdrproc_t) xdr_remote_domain_get_cpu_stats_args,
             (char *) &args,
             (xdrproc_t) xdr_remote_domain_get_cpu_stats_ret,
             (char *) &ret) == -1)
        goto done;

    /* Check the length of the returned list carefully. */
    if (ret.params.params_len > nparams * ncpus ||
        (ret.params.params_len &&
         ((ret.params.params_len % ret.nparams) || ret.nparams > nparams))) {
        virReportError(VIR_ERR_RPC, "%s",
                       _("remoteDomainGetCPUStats: "
                         "returned number of stats exceeds limit"));
        memset(params, 0, sizeof(*params) * nparams * ncpus);
        goto cleanup;
    }

    /* Handle the case when the caller does not know the number of stats
     * and is asking for the number of stats supported
     */
    if (nparams == 0) {
        rv = ret.nparams;
        goto cleanup;
    }

    /* The remote side did not send back any zero entries, so we have
     * to expand things back into a possibly sparse array, where the
     * tail of the array may be omitted.
     */
    memset(params, 0, sizeof(*params) * nparams * ncpus);
    ncpus = ret.params.params_len / ret.nparams;
    for (cpu = 0; cpu < ncpus; cpu++) {
        int tmp = nparams;
        virTypedParameterPtr cpu_params = &params[cpu * nparams];
        remote_typed_param *stride = &ret.params.params_val[cpu * ret.nparams];

        if (remoteDeserializeTypedParameters(stride, ret.nparams,
                                             REMOTE_NODE_CPU_STATS_MAX,
                                             &cpu_params, &tmp) < 0)
            goto cleanup;
    }

    rv = ret.nparams;
cleanup:
    if (rv < 0)
        virTypedParamsClear(params, nparams * ncpus);

    xdr_free((xdrproc_t) xdr_remote_domain_get_cpu_stats_ret,
             (char *) &ret);
done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteConnectListAllNetworks(virConnectPtr conn,
                             virNetworkPtr **nets,
                             unsigned int flags)
{
    int rv = -1;
    size_t i;
    virNetworkPtr *tmp_nets = NULL;
    remote_connect_list_all_networks_args args;
    remote_connect_list_all_networks_ret ret;

    struct private_data *priv = conn->privateData;

    remoteDriverLock(priv);

    args.need_results = !!nets;
    args.flags = flags;

    memset(&ret, 0, sizeof(ret));
    if (call(conn,
             priv,
             0,
             REMOTE_PROC_CONNECT_LIST_ALL_NETWORKS,
             (xdrproc_t) xdr_remote_connect_list_all_networks_args,
             (char *) &args,
             (xdrproc_t) xdr_remote_connect_list_all_networks_ret,
             (char *) &ret) == -1)
        goto done;

    if (ret.nets.nets_len > REMOTE_NETWORK_LIST_MAX) {
        virReportError(VIR_ERR_RPC,
                       _("Too many networks '%d' for limit '%d'"),
                       ret.nets.nets_len, REMOTE_NETWORK_LIST_MAX);
        goto cleanup;
    }

    if (nets) {
        if (VIR_ALLOC_N(tmp_nets, ret.nets.nets_len + 1) < 0)
            goto cleanup;

        for (i = 0; i < ret.nets.nets_len; i++) {
            tmp_nets[i] = get_nonnull_network(conn, ret.nets.nets_val[i]);
            if (!tmp_nets[i])
                goto cleanup;
        }
        *nets = tmp_nets;
        tmp_nets = NULL;
    }

    rv = ret.ret;

cleanup:
    if (tmp_nets) {
        for (i = 0; i < ret.nets.nets_len; i++)
            if (tmp_nets[i])
                virNetworkFree(tmp_nets[i]);
        VIR_FREE(tmp_nets);
    }

    xdr_free((xdrproc_t) xdr_remote_connect_list_all_networks_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteConnectListAllInterfaces(virConnectPtr conn,
                               virInterfacePtr **ifaces,
                               unsigned int flags)
{
    int rv = -1;
    size_t i;
    virInterfacePtr *tmp_ifaces = NULL;
    remote_connect_list_all_interfaces_args args;
    remote_connect_list_all_interfaces_ret ret;

    struct private_data *priv = conn->privateData;

    remoteDriverLock(priv);

    args.need_results = !!ifaces;
    args.flags = flags;

    memset(&ret, 0, sizeof(ret));
    if (call(conn,
             priv,
             0,
             REMOTE_PROC_CONNECT_LIST_ALL_INTERFACES,
             (xdrproc_t) xdr_remote_connect_list_all_interfaces_args,
             (char *) &args,
             (xdrproc_t) xdr_remote_connect_list_all_interfaces_ret,
             (char *) &ret) == -1)
        goto done;

    if (ret.ifaces.ifaces_len > REMOTE_INTERFACE_LIST_MAX) {
        virReportError(VIR_ERR_RPC,
                       _("Too many interfaces '%d' for limit '%d'"),
                       ret.ifaces.ifaces_len, REMOTE_INTERFACE_LIST_MAX);
        goto cleanup;
    }

    if (ifaces) {
        if (VIR_ALLOC_N(tmp_ifaces, ret.ifaces.ifaces_len + 1) < 0)
            goto cleanup;

        for (i = 0; i < ret.ifaces.ifaces_len; i++) {
            tmp_ifaces[i] = get_nonnull_interface(conn, ret.ifaces.ifaces_val[i]);
            if (!tmp_ifaces[i])
                goto cleanup;
        }
        *ifaces = tmp_ifaces;
        tmp_ifaces = NULL;
    }

    rv = ret.ret;

cleanup:
    if (tmp_ifaces) {
        for (i = 0; i < ret.ifaces.ifaces_len; i++)
            if (tmp_ifaces[i])
                virInterfaceFree(tmp_ifaces[i]);
    }
    VIR_FREE(tmp_ifaces);

    xdr_free((xdrproc_t) xdr_remote_connect_list_all_interfaces_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteConnectListAllNodeDevices(virConnectPtr conn,
                                virNodeDevicePtr **devices,
                                unsigned int flags)
{
    int rv = -1;
    size_t i;
    virNodeDevicePtr *tmp_devices = NULL;
    remote_connect_list_all_node_devices_args args;
    remote_connect_list_all_node_devices_ret ret;

    struct private_data *priv = conn->privateData;

    remoteDriverLock(priv);

    args.need_results = !!devices;
    args.flags = flags;

    memset(&ret, 0, sizeof(ret));
    if (call(conn,
             priv,
             0,
             REMOTE_PROC_CONNECT_LIST_ALL_NODE_DEVICES,
             (xdrproc_t) xdr_remote_connect_list_all_node_devices_args,
             (char *) &args,
             (xdrproc_t) xdr_remote_connect_list_all_node_devices_ret,
             (char *) &ret) == -1)
        goto done;

    if (ret.devices.devices_len > REMOTE_NODE_DEVICE_LIST_MAX) {
        virReportError(VIR_ERR_RPC,
                       _("Too many node devices '%d' for limit '%d'"),
                       ret.devices.devices_len, REMOTE_NODE_DEVICE_LIST_MAX);
        goto cleanup;
    }

    if (devices) {
        if (VIR_ALLOC_N(tmp_devices, ret.devices.devices_len + 1) < 0)
            goto cleanup;

        for (i = 0; i < ret.devices.devices_len; i++) {
            tmp_devices[i] = get_nonnull_node_device(conn, ret.devices.devices_val[i]);
            if (!tmp_devices[i])
                goto cleanup;
        }
        *devices = tmp_devices;
        tmp_devices = NULL;
    }

    rv = ret.ret;

cleanup:
    if (tmp_devices) {
        for (i = 0; i < ret.devices.devices_len; i++)
            if (tmp_devices[i])
                virNodeDeviceFree(tmp_devices[i]);
        VIR_FREE(tmp_devices);
    }

    xdr_free((xdrproc_t) xdr_remote_connect_list_all_node_devices_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteConnectListAllNWFilters(virConnectPtr conn,
                              virNWFilterPtr **filters,
                              unsigned int flags)
{
    int rv = -1;
    size_t i;
    virNWFilterPtr *tmp_filters = NULL;
    remote_connect_list_all_nwfilters_args args;
    remote_connect_list_all_nwfilters_ret ret;

    struct private_data *priv = conn->privateData;

    remoteDriverLock(priv);

    args.need_results = !!filters;
    args.flags = flags;

    memset(&ret, 0, sizeof(ret));
    if (call(conn,
             priv,
             0,
             REMOTE_PROC_CONNECT_LIST_ALL_NWFILTERS,
             (xdrproc_t) xdr_remote_connect_list_all_nwfilters_args,
             (char *) &args,
             (xdrproc_t) xdr_remote_connect_list_all_nwfilters_ret,
             (char *) &ret) == -1)
        goto done;

    if (ret.filters.filters_len > REMOTE_NWFILTER_LIST_MAX) {
        virReportError(VIR_ERR_RPC,
                       _("Too many network filters '%d' for limit '%d'"),
                       ret.filters.filters_len, REMOTE_NWFILTER_LIST_MAX);
        goto cleanup;
    }

    if (filters) {
        if (VIR_ALLOC_N(tmp_filters, ret.filters.filters_len + 1) < 0)
            goto cleanup;

        for (i = 0; i < ret.filters.filters_len; i++) {
            tmp_filters[i] = get_nonnull_nwfilter(conn, ret.filters.filters_val[i]);
            if (!tmp_filters[i])
                goto cleanup;
        }
        *filters = tmp_filters;
        tmp_filters = NULL;
    }

    rv = ret.ret;

cleanup:
    if (tmp_filters) {
        for (i = 0; i < ret.filters.filters_len; i++)
            if (tmp_filters[i])
                virNWFilterFree(tmp_filters[i]);
        VIR_FREE(tmp_filters);
    }

    xdr_free((xdrproc_t) xdr_remote_connect_list_all_nwfilters_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteConnectListAllSecrets(virConnectPtr conn,
                            virSecretPtr **secrets,
                            unsigned int flags)
{
    int rv = -1;
    size_t i;
    virSecretPtr *tmp_secrets = NULL;
    remote_connect_list_all_secrets_args args;
    remote_connect_list_all_secrets_ret ret;

    struct private_data *priv = conn->privateData;

    remoteDriverLock(priv);

    args.need_results = !!secrets;
    args.flags = flags;

    memset(&ret, 0, sizeof(ret));
    if (call(conn,
             priv,
             0,
             REMOTE_PROC_CONNECT_LIST_ALL_SECRETS,
             (xdrproc_t) xdr_remote_connect_list_all_secrets_args,
             (char *) &args,
             (xdrproc_t) xdr_remote_connect_list_all_secrets_ret,
             (char *) &ret) == -1)
        goto done;

    if (ret.secrets.secrets_len > REMOTE_SECRET_LIST_MAX) {
        virReportError(VIR_ERR_RPC,
                       _("Too many secrets '%d' for limit '%d'"),
                       ret.secrets.secrets_len, REMOTE_SECRET_LIST_MAX);
        goto cleanup;
    }

    if (secrets) {
        if (VIR_ALLOC_N(tmp_secrets, ret.secrets.secrets_len + 1) < 0)
            goto cleanup;

        for (i = 0; i < ret.secrets.secrets_len; i++) {
            tmp_secrets[i] = get_nonnull_secret(conn, ret.secrets.secrets_val[i]);
            if (!tmp_secrets[i])
                goto cleanup;
        }
        *secrets = tmp_secrets;
        tmp_secrets = NULL;
    }

    rv = ret.ret;

cleanup:
    if (tmp_secrets) {
        for (i = 0; i < ret.secrets.secrets_len; i++)
            if (tmp_secrets[i])
                virSecretFree(tmp_secrets[i]);
        VIR_FREE(tmp_secrets);
    }

    xdr_free((xdrproc_t) xdr_remote_connect_list_all_secrets_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return rv;
}

/*----------------------------------------------------------------------*/

static virDrvOpenStatus ATTRIBUTE_NONNULL(1)
remoteGenericOpen(virConnectPtr conn, virConnectAuthPtr auth,
                  unsigned int flags, void **genericPrivateData)
{
    if (inside_daemon)
        return VIR_DRV_OPEN_DECLINED;

    if (conn->driver &&
        STREQ(conn->driver->name, "remote")) {
        struct private_data *priv;

        /* If we're here, the remote driver is already
         * in use due to a) a QEMU uri, or b) a remote
         * URI. So we can re-use existing connection */
        priv = conn->privateData;
        remoteDriverLock(priv);
        priv->localUses++;
        *genericPrivateData = priv;
        remoteDriverUnlock(priv);
        return VIR_DRV_OPEN_SUCCESS;
    } else if (conn->networkDriver &&
               STREQ(conn->networkDriver->name, "remote")) {
        struct private_data *priv = conn->networkPrivateData;
        remoteDriverLock(priv);
        *genericPrivateData = priv;
        priv->localUses++;
        remoteDriverUnlock(priv);
        return VIR_DRV_OPEN_SUCCESS;
    } else {
        /* Using a non-remote driver, so we need to open a
         * new connection for network APIs, forcing it to
         * use the UNIX transport. This handles Xen driver
         * which doesn't have its own impl of the network APIs. */
        struct private_data *priv;
        int ret = remoteOpenSecondaryDriver(conn, auth, flags, &priv);
        *genericPrivateData = priv;
        return ret;
    }
}

static int
remoteGenericClose(virConnectPtr conn, void **genericPrivateData)
{
    int rv = 0;
    struct private_data *priv = *genericPrivateData;

    remoteDriverLock(priv);
    priv->localUses--;
    if (!priv->localUses) {
        rv = doRemoteClose(conn, priv);
        *genericPrivateData = NULL;
        remoteDriverUnlock(priv);
        virMutexDestroy(&priv->lock);
        VIR_FREE(priv);
    }
    if (priv)
        remoteDriverUnlock(priv);
    return rv;
}

static virDrvOpenStatus ATTRIBUTE_NONNULL(1)
remoteNetworkOpen(virConnectPtr conn, virConnectAuthPtr auth,
                  unsigned int flags)
{
    return remoteGenericOpen(conn, auth, flags, &conn->networkPrivateData);
}

static int
remoteNetworkClose(virConnectPtr conn)
{
    return remoteGenericClose(conn, &conn->networkPrivateData);
}

/*----------------------------------------------------------------------*/

static virDrvOpenStatus ATTRIBUTE_NONNULL(1)
remoteInterfaceOpen(virConnectPtr conn, virConnectAuthPtr auth,
                    unsigned int flags)
{
    return remoteGenericOpen(conn, auth, flags, &conn->interfacePrivateData);
}

static int
remoteInterfaceClose(virConnectPtr conn)
{
    return remoteGenericClose(conn, &conn->interfacePrivateData);
}

/*----------------------------------------------------------------------*/

static virDrvOpenStatus ATTRIBUTE_NONNULL(1)
remoteStorageOpen(virConnectPtr conn, virConnectAuthPtr auth,
                  unsigned int flags)
{
    return remoteGenericOpen(conn, auth, flags, &conn->storagePrivateData);
}

static int
remoteStorageClose(virConnectPtr conn)
{
    return remoteGenericClose(conn, &conn->storagePrivateData);
}

static char *
remoteConnectFindStoragePoolSources(virConnectPtr conn,
                                    const char *type,
                                    const char *srcSpec,
                                    unsigned int flags)
{
    char *rv = NULL;
    remote_connect_find_storage_pool_sources_args args;
    remote_connect_find_storage_pool_sources_ret ret;
    struct private_data *priv = conn->storagePrivateData;

    remoteDriverLock(priv);

    args.type = (char*)type;
    args.srcSpec = srcSpec ? (char **)&srcSpec : NULL;
    args.flags = flags;

    memset(&ret, 0, sizeof(ret));
    if (call(conn, priv, 0, REMOTE_PROC_CONNECT_FIND_STORAGE_POOL_SOURCES,
             (xdrproc_t) xdr_remote_connect_find_storage_pool_sources_args, (char *) &args,
             (xdrproc_t) xdr_remote_connect_find_storage_pool_sources_ret, (char *) &ret) == -1)
        goto done;

    rv = ret.xml;
    ret.xml = NULL; /* To stop xdr_free free'ing it */

    xdr_free((xdrproc_t) xdr_remote_connect_find_storage_pool_sources_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteConnectListAllStoragePools(virConnectPtr conn,
                                 virStoragePoolPtr **pools,
                                 unsigned int flags)
{
    int rv = -1;
    size_t i;
    virStoragePoolPtr *tmp_pools = NULL;
    remote_connect_list_all_storage_pools_args args;
    remote_connect_list_all_storage_pools_ret ret;

    struct private_data *priv = conn->privateData;

    remoteDriverLock(priv);

    args.need_results = !!pools;
    args.flags = flags;

    memset(&ret, 0, sizeof(ret));
    if (call(conn,
             priv,
             0,
             REMOTE_PROC_CONNECT_LIST_ALL_STORAGE_POOLS,
             (xdrproc_t) xdr_remote_connect_list_all_storage_pools_args,
             (char *) &args,
             (xdrproc_t) xdr_remote_connect_list_all_storage_pools_ret,
             (char *) &ret) == -1)
        goto done;

    if (ret.pools.pools_len > REMOTE_STORAGE_POOL_LIST_MAX) {
        virReportError(VIR_ERR_RPC,
                       _("Too many storage pools '%d' for limit '%d'"),
                       ret.pools.pools_len, REMOTE_STORAGE_POOL_LIST_MAX);
        goto cleanup;
    }

    if (pools) {
        if (VIR_ALLOC_N(tmp_pools, ret.pools.pools_len + 1) < 0)
            goto cleanup;

        for (i = 0; i < ret.pools.pools_len; i++) {
            tmp_pools[i] = get_nonnull_storage_pool(conn, ret.pools.pools_val[i]);
            if (!tmp_pools[i])
                goto cleanup;
        }
        *pools = tmp_pools;
        tmp_pools = NULL;
    }

    rv = ret.ret;

cleanup:
    if (tmp_pools) {
        for (i = 0; i < ret.pools.pools_len; i++)
            if (tmp_pools[i])
                virStoragePoolFree(tmp_pools[i]);
        VIR_FREE(tmp_pools);
    }

    xdr_free((xdrproc_t) xdr_remote_connect_list_all_storage_pools_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteStoragePoolListAllVolumes(virStoragePoolPtr pool,
                                virStorageVolPtr **vols,
                                unsigned int flags)
{
    int rv = -1;
    size_t i;
    virStorageVolPtr *tmp_vols = NULL;
    remote_storage_pool_list_all_volumes_args args;
    remote_storage_pool_list_all_volumes_ret ret;

    struct private_data *priv = pool->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_storage_pool(&args.pool, pool);
    args.need_results = !!vols;
    args.flags = flags;

    memset(&ret, 0, sizeof(ret));
    if (call(pool->conn,
             priv,
             0,
             REMOTE_PROC_STORAGE_POOL_LIST_ALL_VOLUMES,
             (xdrproc_t) xdr_remote_storage_pool_list_all_volumes_args,
             (char *) &args,
             (xdrproc_t) xdr_remote_storage_pool_list_all_volumes_ret,
             (char *) &ret) == -1)
        goto done;

    if (ret.vols.vols_len > REMOTE_STORAGE_VOL_LIST_MAX) {
        virReportError(VIR_ERR_RPC,
                       _("Too many storage volumes '%d' for limit '%d'"),
                       ret.vols.vols_len, REMOTE_STORAGE_VOL_LIST_MAX);
        goto cleanup;
    }

    if (vols) {
        if (VIR_ALLOC_N(tmp_vols, ret.vols.vols_len + 1) < 0)
            goto cleanup;

        for (i = 0; i < ret.vols.vols_len; i++) {
            tmp_vols[i] = get_nonnull_storage_vol(pool->conn, ret.vols.vols_val[i]);
            if (!tmp_vols[i])
                goto cleanup;
        }
        *vols = tmp_vols;
        tmp_vols = NULL;
    }

    rv = ret.ret;

cleanup:
    if (tmp_vols) {
        for (i = 0; i < ret.vols.vols_len; i++)
            if (tmp_vols[i])
                virStorageVolFree(tmp_vols[i]);
        VIR_FREE(tmp_vols);
    }

    xdr_free((xdrproc_t) xdr_remote_storage_pool_list_all_volumes_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return rv;
}


/*----------------------------------------------------------------------*/

static virDrvOpenStatus ATTRIBUTE_NONNULL(1)
remoteNodeDeviceOpen(virConnectPtr conn, virConnectAuthPtr auth,
                     unsigned int flags)
{
    return remoteGenericOpen(conn, auth, flags, &conn->nodeDevicePrivateData);
}

static int
remoteNodeDeviceClose(virConnectPtr conn)
{
    return remoteGenericClose(conn, &conn->nodeDevicePrivateData);
}

static int
remoteNodeDeviceDettach(virNodeDevicePtr dev)
{
    int rv = -1;
    remote_node_device_dettach_args args;
    /* This method is unusual in that it uses the HV driver, not the devMon driver
     * hence its use of privateData, instead of nodeDevicePrivateData */
    struct private_data *priv = dev->conn->privateData;

    remoteDriverLock(priv);

    args.name = dev->name;

    if (call(dev->conn, priv, 0, REMOTE_PROC_NODE_DEVICE_DETTACH,
             (xdrproc_t) xdr_remote_node_device_dettach_args, (char *) &args,
             (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto done;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteNodeDeviceDetachFlags(virNodeDevicePtr dev,
                            const char *driverName,
                            unsigned int flags)
{
    int rv = -1;
    remote_node_device_detach_flags_args args;
    /* This method is unusual in that it uses the HV driver, not the
     * devMon driver hence its use of privateData, instead of
     * nodeDevicePrivateData
     */
    struct private_data *priv = dev->conn->privateData;

    remoteDriverLock(priv);

    args.name = dev->name;
    args.driverName = driverName ? (char**)&driverName : NULL;
    args.flags = flags;

    if (call(dev->conn, priv, 0, REMOTE_PROC_NODE_DEVICE_DETACH_FLAGS,
             (xdrproc_t) xdr_remote_node_device_detach_flags_args,
             (char *) &args, (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto done;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteNodeDeviceReAttach(virNodeDevicePtr dev)
{
    int rv = -1;
    remote_node_device_re_attach_args args;
    /* This method is unusual in that it uses the HV driver, not the devMon driver
     * hence its use of privateData, instead of nodeDevicePrivateData */
    struct private_data *priv = dev->conn->privateData;

    remoteDriverLock(priv);

    args.name = dev->name;

    if (call(dev->conn, priv, 0, REMOTE_PROC_NODE_DEVICE_RE_ATTACH,
             (xdrproc_t) xdr_remote_node_device_re_attach_args, (char *) &args,
             (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto done;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteNodeDeviceReset(virNodeDevicePtr dev)
{
    int rv = -1;
    remote_node_device_reset_args args;
    /* This method is unusual in that it uses the HV driver, not the devMon driver
     * hence its use of privateData, instead of nodeDevicePrivateData */
    struct private_data *priv = dev->conn->privateData;

    remoteDriverLock(priv);

    args.name = dev->name;

    if (call(dev->conn, priv, 0, REMOTE_PROC_NODE_DEVICE_RESET,
             (xdrproc_t) xdr_remote_node_device_reset_args, (char *) &args,
             (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto done;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

/* ------------------------------------------------------------- */

static virDrvOpenStatus ATTRIBUTE_NONNULL(1)
remoteNWFilterOpen(virConnectPtr conn, virConnectAuthPtr auth,
                   unsigned int flags)
{
    return remoteGenericOpen(conn, auth, flags, &conn->nwfilterPrivateData);
}

static int
remoteNWFilterClose(virConnectPtr conn)
{
    return remoteGenericClose(conn, &conn->nwfilterPrivateData);
}

/*----------------------------------------------------------------------*/

static int
remoteAuthenticate(virConnectPtr conn, struct private_data *priv,
                   virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                   const char *authtype)
{
    struct remote_auth_list_ret ret;
    int err, type = REMOTE_AUTH_NONE;

    memset(&ret, 0, sizeof(ret));
    err = call(conn, priv, 0,
               REMOTE_PROC_AUTH_LIST,
               (xdrproc_t) xdr_void, (char *) NULL,
               (xdrproc_t) xdr_remote_auth_list_ret, (char *) &ret);
    if (err < 0) {
        virErrorPtr verr = virGetLastError();
        if (verr && verr->code == VIR_ERR_NO_SUPPORT) {
            /* Missing RPC - old server - ignore */
            virResetLastError();
            return 0;
        }
        return -1;
    }

    if (ret.types.types_len == 0)
        return 0;

    if (authtype) {
        int want;
        size_t i;
        if (STRCASEEQ(authtype, "sasl") ||
            STRCASEEQLEN(authtype, "sasl.", 5)) {
            want = REMOTE_AUTH_SASL;
        } else if (STRCASEEQ(authtype, "polkit")) {
            want = REMOTE_AUTH_POLKIT;
        } else {
            virReportError(VIR_ERR_AUTH_FAILED,
                           _("unknown authentication type %s"), authtype);
            return -1;
        }
        for (i = 0; i < ret.types.types_len; i++) {
            if (ret.types.types_val[i] == want)
                type = want;
        }
        if (type == REMOTE_AUTH_NONE) {
            virReportError(VIR_ERR_AUTH_FAILED,
                           _("requested authentication type %s rejected"),
                           authtype);
            return -1;
        }
    } else {
        type = ret.types.types_val[0];
    }

    switch (type) {
#if WITH_SASL
    case REMOTE_AUTH_SASL: {
        const char *mech = NULL;
        if (authtype &&
            STRCASEEQLEN(authtype, "sasl.", 5))
            mech = authtype + 5;

        if (remoteAuthSASL(conn, priv, auth, mech) < 0) {
            VIR_FREE(ret.types.types_val);
            return -1;
        }
        break;
    }
#endif

#if WITH_POLKIT
    case REMOTE_AUTH_POLKIT:
        if (remoteAuthPolkit(conn, priv, auth) < 0) {
            VIR_FREE(ret.types.types_val);
            return -1;
        }
        break;
#endif

    case REMOTE_AUTH_NONE:
        /* Nothing todo, hurrah ! */
        break;

    default:
        virReportError(VIR_ERR_AUTH_FAILED,
                       _("unsupported authentication type %d"),
                       ret.types.types_val[0]);
        VIR_FREE(ret.types.types_val);
        return -1;
    }

    VIR_FREE(ret.types.types_val);

    return 0;
}



#if WITH_SASL
static int remoteAuthCredVir2SASL(int vircred)
{
    switch (vircred) {
    case VIR_CRED_USERNAME:
        return SASL_CB_USER;

    case VIR_CRED_AUTHNAME:
        return SASL_CB_AUTHNAME;

    case VIR_CRED_LANGUAGE:
        return SASL_CB_LANGUAGE;

    case VIR_CRED_CNONCE:
        return SASL_CB_CNONCE;

    case VIR_CRED_PASSPHRASE:
        return SASL_CB_PASS;

    case VIR_CRED_ECHOPROMPT:
        return SASL_CB_ECHOPROMPT;

    case VIR_CRED_NOECHOPROMPT:
        return SASL_CB_NOECHOPROMPT;

    case VIR_CRED_REALM:
        return SASL_CB_GETREALM;
    }

    return 0;
}

static int remoteAuthCredSASL2Vir(int vircred)
{
    switch (vircred) {
    case SASL_CB_USER:
        return VIR_CRED_USERNAME;

    case SASL_CB_AUTHNAME:
        return VIR_CRED_AUTHNAME;

    case SASL_CB_LANGUAGE:
        return VIR_CRED_LANGUAGE;

    case SASL_CB_CNONCE:
        return VIR_CRED_CNONCE;

    case SASL_CB_PASS:
        return VIR_CRED_PASSPHRASE;

    case SASL_CB_ECHOPROMPT:
        return VIR_CRED_ECHOPROMPT;

    case SASL_CB_NOECHOPROMPT:
        return VIR_CRED_NOECHOPROMPT;

    case SASL_CB_GETREALM:
        return VIR_CRED_REALM;
    }

    return 0;
}

/*
 * @param credtype array of credential types client supports
 * @param ncredtype size of credtype array
 * @return the SASL callback structure, or NULL on error
 *
 * Build up the SASL callback structure. We register one callback for
 * each credential type that the libvirt client indicated they support.
 * We explicitly leave the callback function pointer at NULL though,
 * because we don't actually want to get SASL callbacks triggered.
 * Instead, we want the start/step functions to return SASL_INTERACT.
 * This lets us give the libvirt client a list of all required
 * credentials in one go, rather than triggering the callback one
 * credential at a time,
 */
static sasl_callback_t *remoteAuthMakeCallbacks(int *credtype, int ncredtype)
{
    sasl_callback_t *cbs;
    size_t i;
    int n;
    if (VIR_ALLOC_N(cbs, ncredtype+1) < 0) {
        return NULL;
    }

    for (i = 0, n = 0; i < ncredtype; i++) {
        int id = remoteAuthCredVir2SASL(credtype[i]);
        if (id != 0)
            cbs[n++].id = id;
        /* Don't fill proc or context fields of sasl_callback_t
         * because we want to use interactions instead */
    }
    cbs[n].id = 0;
    return cbs;
}


/*
 * @param interact SASL interactions required
 * @param cred populated with libvirt credential metadata
 * @return the size of the cred array returned
 *
 * Builds up an array of libvirt credential structs, populating
 * with data from the SASL interaction struct. These two structs
 * are basically a 1-to-1 copy of each other.
 */
static int remoteAuthMakeCredentials(sasl_interact_t *interact,
                                     virConnectCredentialPtr *cred,
                                     size_t *ncred)
{
    int ninteract;
    if (!cred)
        return -1;

    for (ninteract = 0, *ncred = 0; interact[ninteract].id != 0; ninteract++) {
        if (interact[ninteract].result)
            continue;
        (*ncred)++;
    }

    if (VIR_ALLOC_N(*cred, *ncred) < 0)
        return -1;

    for (ninteract = 0, *ncred = 0; interact[ninteract].id != 0; ninteract++) {
        if (interact[ninteract].result)
            continue;

        (*cred)[*ncred].type = remoteAuthCredSASL2Vir(interact[ninteract].id);
        if (!(*cred)[*ncred].type) {
            *ncred = 0;
            VIR_FREE(*cred);
            return -1;
        }
        if (interact[*ncred].challenge)
            (*cred)[*ncred].challenge = interact[ninteract].challenge;
        (*cred)[*ncred].prompt = interact[ninteract].prompt;
        if (interact[*ncred].defresult)
            (*cred)[*ncred].defresult = interact[ninteract].defresult;
        (*cred)[*ncred].result = NULL;

        (*ncred)++;
    }

    return 0;
}


/*
 * @param cred the populated libvirt credentials
 * @param interact the SASL interactions to fill in results for
 *
 * Fills the SASL interactions with the result from the libvirt
 * callbacks
 */
static void remoteAuthFillInteract(virConnectCredentialPtr cred,
                                   sasl_interact_t *interact)
{
    int ninteract, ncred;
    for (ninteract = 0, ncred = 0; interact[ninteract].id != 0; ninteract++) {
        if (interact[ninteract].result)
            continue;
        interact[ninteract].result = cred[ncred].result;
        interact[ninteract].len = cred[ncred].resultlen;
        ncred++;
    }
}

struct remoteAuthInteractState {
    sasl_interact_t *interact;
    virConnectCredentialPtr cred;
    size_t ncred;
    virAuthConfigPtr config;
};



static int remoteAuthFillFromConfig(virConnectPtr conn,
                                    struct remoteAuthInteractState *state)
{
    int ret = -1;
    int ninteract;
    const char *credname;
    char *path = NULL;

    VIR_DEBUG("Trying to fill auth parameters from config file");

    if (!state->config) {
        if (virAuthGetConfigFilePath(conn, &path) < 0)
            goto cleanup;
        if (path == NULL) {
            ret = 0;
            goto cleanup;
        }

        if (!(state->config = virAuthConfigNew(path)))
            goto cleanup;
    }

    for (ninteract = 0; state->interact[ninteract].id != 0; ninteract++) {
        const char *value = NULL;

        switch (state->interact[ninteract].id) {
        case SASL_CB_USER:
            credname = "username";
            break;
        case SASL_CB_AUTHNAME:
            credname = "authname";
            break;
        case SASL_CB_PASS:
            credname = "password";
            break;
        case SASL_CB_GETREALM:
            credname = "realm";
            break;
        default:
            credname = NULL;
            break;
        }

        if (credname &&
            virAuthConfigLookup(state->config,
                                "libvirt",
                                VIR_URI_SERVER(conn->uri),
                                credname,
                                &value) < 0)
            goto cleanup;

        if (value) {
            state->interact[ninteract].result = value;
            state->interact[ninteract].len = strlen(value);
        }
    }

    ret = 0;

cleanup:
    VIR_FREE(path);
    return ret;
}


static void remoteAuthInteractStateClear(struct remoteAuthInteractState *state,
                                         bool final)
{
    size_t i;
    if (!state)
        return;

    for (i = 0; i < state->ncred; i++)
        VIR_FREE(state->cred[i].result);
    VIR_FREE(state->cred);
    state->ncred = 0;

    if (final)
        virAuthConfigFree(state->config);
}


static int remoteAuthInteract(virConnectPtr conn,
                              struct remoteAuthInteractState *state,
                              virConnectAuthPtr auth)
{
    int ret = -1;

    VIR_DEBUG("Starting SASL interaction");
    remoteAuthInteractStateClear(state, false);

    /* Fills state->interact with any values from the auth config file */
    if (remoteAuthFillFromConfig(conn, state) < 0)
        goto cleanup;

    /* Populates state->cred for anything not found in the auth config */
    if (remoteAuthMakeCredentials(state->interact, &state->cred, &state->ncred) < 0) {
        virReportError(VIR_ERR_AUTH_FAILED, "%s",
                       _("Failed to make auth credentials"));
        goto cleanup;
    }

    /* If there was anything not in the auth config, we need to
     * run the interactive callback
     */
    if (state->ncred) {
        /* Run the authentication callback */
        if (!auth || !auth->cb) {
            virReportError(VIR_ERR_AUTH_FAILED, "%s",
                           _("No authentication callback available"));
            goto cleanup;
        }

        if ((*(auth->cb))(state->cred, state->ncred, auth->cbdata) < 0) {
            virReportError(VIR_ERR_AUTH_FAILED, "%s",
                           _("Failed to collect auth credentials"));
            goto cleanup;
        }

        /* Copy user's responses from cred into interact */
        remoteAuthFillInteract(state->cred, state->interact);
    }

    /*
     * 'interact' now has pointers to strings in 'state->cred'
     * so we must not free state->cred until the *next*
     * sasl_start/step function is complete. Hence we
     * call remoteAuthInteractStateClear() at the *start*
     * of this method, rather than the end.
     */

    ret = 0;

cleanup:
    return ret;
}


/* Perform the SASL authentication process
 */
static int
remoteAuthSASL(virConnectPtr conn, struct private_data *priv,
               virConnectAuthPtr auth, const char *wantmech)
{
    remote_auth_sasl_init_ret iret;
    remote_auth_sasl_start_args sargs;
    remote_auth_sasl_start_ret sret;
    remote_auth_sasl_step_args pargs;
    remote_auth_sasl_step_ret pret;
    const char *clientout;
    char *serverin = NULL;
    size_t clientoutlen, serverinlen;
    const char *mech;
    int err, complete;
    int ssf;
    sasl_callback_t *saslcb = NULL;
    int ret = -1;
    const char *mechlist;
    virNetSASLContextPtr saslCtxt;
    virNetSASLSessionPtr sasl = NULL;
    struct remoteAuthInteractState state;

    memset(&state, 0, sizeof(state));

    VIR_DEBUG("Client initialize SASL authentication");

    if (!(saslCtxt = virNetSASLContextNewClient()))
        goto cleanup;

    if (auth) {
        if ((saslcb = remoteAuthMakeCallbacks(auth->credtype, auth->ncredtype)) == NULL)
            goto cleanup;
    } else {
        saslcb = NULL;
    }

    /* Setup a handle for being a client */
    if (!(sasl = virNetSASLSessionNewClient(saslCtxt,
                                            "libvirt",
                                            priv->hostname,
                                            virNetClientLocalAddrString(priv->client),
                                            virNetClientRemoteAddrString(priv->client),
                                            saslcb)))
        goto cleanup;
    /* saslcb is now owned by sasl */
    saslcb = NULL;

# ifdef WITH_GNUTLS
    /* Initialize some connection props we care about */
    if (priv->tls) {
        if ((ssf = virNetClientGetTLSKeySize(priv->client)) < 0)
            goto cleanup;

        ssf *= 8; /* key size is bytes, sasl wants bits */

        VIR_DEBUG("Setting external SSF %d", ssf);
        if (virNetSASLSessionExtKeySize(sasl, ssf) < 0)
            goto cleanup;
    }
# endif

    /* If we've got a secure channel (TLS or UNIX sock), we don't care about SSF */
    /* If we're not secure, then forbid any anonymous or trivially crackable auth */
    if (virNetSASLSessionSecProps(sasl,
                                  priv->is_secure ? 0 : 56, /* Equiv to DES supported by all Kerberos */
                                  priv->is_secure ? 0 : 100000, /* Very strong ! AES == 256 */
                                  priv->is_secure ? true : false) < 0)
        goto cleanup;

    /* First call is to inquire about supported mechanisms in the server */
    memset(&iret, 0, sizeof(iret));
    if (call(conn, priv, 0, REMOTE_PROC_AUTH_SASL_INIT,
             (xdrproc_t) xdr_void, (char *)NULL,
             (xdrproc_t) xdr_remote_auth_sasl_init_ret, (char *) &iret) != 0)
        goto cleanup;


    mechlist = iret.mechlist;
    if (wantmech) {
        if (strstr(mechlist, wantmech) == NULL) {
            virReportError(VIR_ERR_AUTH_FAILED,
                           _("SASL mechanism %s not supported by server"),
                           wantmech);
            VIR_FREE(iret.mechlist);
            goto cleanup;
        }
        mechlist = wantmech;
    }
 restart:
    /* Start the auth negotiation on the client end first */
    VIR_DEBUG("Client start negotiation mechlist '%s'", mechlist);
    if ((err = virNetSASLSessionClientStart(sasl,
                                            mechlist,
                                            &state.interact,
                                            &clientout,
                                            &clientoutlen,
                                            &mech)) < 0)
        goto cleanup;

    /* Need to gather some credentials from the client */
    if (err == VIR_NET_SASL_INTERACT) {
        if (remoteAuthInteract(conn, &state, auth) < 0) {
            VIR_FREE(iret.mechlist);
            goto cleanup;
        }
        goto restart;
    }
    VIR_FREE(iret.mechlist);

    if (clientoutlen > REMOTE_AUTH_SASL_DATA_MAX) {
        virReportError(VIR_ERR_AUTH_FAILED,
                       _("SASL negotiation data too long: %zu bytes"),
                       clientoutlen);
        goto cleanup;
    }
    /* NB, distinction of NULL vs "" is *critical* in SASL */
    memset(&sargs, 0, sizeof(sargs));
    sargs.nil = clientout ? 0 : 1;
    sargs.data.data_val = (char*)clientout;
    sargs.data.data_len = clientoutlen;
    sargs.mech = (char*)mech;
    VIR_DEBUG("Server start negotiation with mech %s. Data %zu bytes %p",
              mech, clientoutlen, clientout);

    /* Now send the initial auth data to the server */
    memset(&sret, 0, sizeof(sret));
    if (call(conn, priv, 0, REMOTE_PROC_AUTH_SASL_START,
             (xdrproc_t) xdr_remote_auth_sasl_start_args, (char *) &sargs,
             (xdrproc_t) xdr_remote_auth_sasl_start_ret, (char *) &sret) != 0)
        goto cleanup;

    complete = sret.complete;
    /* NB, distinction of NULL vs "" is *critical* in SASL */
    serverin = sret.nil ? NULL : sret.data.data_val;
    serverinlen = sret.data.data_len;
    VIR_DEBUG("Client step result complete: %d. Data %zu bytes %p",
              complete, serverinlen, serverin);

    /* Previous server call showed completion & sasl_client_start() told us
     * we are locally complete too */
    if (complete && err == VIR_NET_SASL_COMPLETE)
        goto done;

    /* Loop-the-loop...
     * Even if the server has completed, the client must *always* do at least one step
     * in this loop to verify the server isn't lying about something. Mutual auth */
    for (;;) {
        if ((err = virNetSASLSessionClientStep(sasl,
                                               serverin,
                                               serverinlen,
                                               &state.interact,
                                               &clientout,
                                               &clientoutlen)) < 0)
            goto cleanup;

        /* Need to gather some credentials from the client */
        if (err == VIR_NET_SASL_INTERACT) {
            if (remoteAuthInteract(conn, &state, auth) < 0) {
                VIR_FREE(iret.mechlist);
                goto cleanup;
            }
            continue;
        }

        VIR_FREE(serverin);
        VIR_DEBUG("Client step result %d. Data %zu bytes %p",
                  err, clientoutlen, clientout);

        /* Previous server call showed completion & we're now locally complete too */
        if (complete && err == VIR_NET_SASL_COMPLETE)
            break;

        /* Not done, prepare to talk with the server for another iteration */
        /* NB, distinction of NULL vs "" is *critical* in SASL */
        memset(&pargs, 0, sizeof(pargs));
        pargs.nil = clientout ? 0 : 1;
        pargs.data.data_val = (char*)clientout;
        pargs.data.data_len = clientoutlen;
        VIR_DEBUG("Server step with %zu bytes %p",
                  clientoutlen, clientout);

        memset(&pret, 0, sizeof(pret));
        if (call(conn, priv, 0, REMOTE_PROC_AUTH_SASL_STEP,
                 (xdrproc_t) xdr_remote_auth_sasl_step_args, (char *) &pargs,
                 (xdrproc_t) xdr_remote_auth_sasl_step_ret, (char *) &pret) != 0)
            goto cleanup;

        complete = pret.complete;
        /* NB, distinction of NULL vs "" is *critical* in SASL */
        serverin = pret.nil ? NULL : pret.data.data_val;
        serverinlen = pret.data.data_len;

        VIR_DEBUG("Client step result complete: %d. Data %zu bytes %p",
                  complete, serverinlen, serverin);

        /* This server call shows complete, and earlier client step was OK */
        if (complete && err == VIR_NET_SASL_COMPLETE) {
            VIR_FREE(serverin);
            break;
        }
    }

    /* Check for suitable SSF if not already secure (TLS or UNIX sock) */
    if (!priv->is_secure) {
        if ((ssf = virNetSASLSessionGetKeySize(sasl)) < 0)
            goto cleanup;

        VIR_DEBUG("SASL SSF value %d", ssf);
        if (ssf < 56) { /* 56 == DES level, good for Kerberos */
            virReportError(VIR_ERR_AUTH_FAILED,
                           _("negotiation SSF %d was not strong enough"), ssf);
            goto cleanup;
        }
        priv->is_secure = 1;
    }

done:
    VIR_DEBUG("SASL authentication complete");
    virNetClientSetSASLSession(priv->client, sasl);
    ret = 0;

 cleanup:
    VIR_FREE(serverin);

    remoteAuthInteractStateClear(&state, true);
    VIR_FREE(saslcb);
    virObjectUnref(sasl);
    virObjectUnref(saslCtxt);

    return ret;
}
#endif /* WITH_SASL */


#if WITH_POLKIT
# if WITH_POLKIT1
static int
remoteAuthPolkit(virConnectPtr conn, struct private_data *priv,
                 virConnectAuthPtr auth ATTRIBUTE_UNUSED)
{
    remote_auth_polkit_ret ret;
    VIR_DEBUG("Client initialize PolicyKit-1 authentication");

    memset(&ret, 0, sizeof(ret));
    if (call(conn, priv, 0, REMOTE_PROC_AUTH_POLKIT,
             (xdrproc_t) xdr_void, (char *)NULL,
             (xdrproc_t) xdr_remote_auth_polkit_ret, (char *) &ret) != 0) {
        return -1; /* virError already set by call */
    }

    VIR_DEBUG("PolicyKit-1 authentication complete");
    return 0;
}
# elif WITH_POLKIT0
/* Perform the PolicyKit authentication process
 */
static int
remoteAuthPolkit(virConnectPtr conn, struct private_data *priv,
                 virConnectAuthPtr auth)
{
    remote_auth_polkit_ret ret;
    size_t i;
    int allowcb = 0;
    virConnectCredential cred = {
        VIR_CRED_EXTERNAL,
        conn->flags & VIR_CONNECT_RO ? "org.libvirt.unix.monitor" : "org.libvirt.unix.manage",
        "PolicyKit",
        NULL,
        NULL,
        0,
    };
    VIR_DEBUG("Client initialize PolicyKit-0 authentication");

    /* Check auth first and if it succeeds we are done. */
    memset(&ret, 0, sizeof(ret));
    if (call(conn, priv, 0, REMOTE_PROC_AUTH_POLKIT,
             (xdrproc_t) xdr_void, (char *)NULL,
             (xdrproc_t) xdr_remote_auth_polkit_ret, (char *) &ret) == 0)
        goto out;

    /* Auth failed.  Ask client to obtain it and check again. */
    if (auth && auth->cb) {
        /* Check if the necessary credential type for PolicyKit is supported */
        for (i = 0; i < auth->ncredtype; i++) {
            if (auth->credtype[i] == VIR_CRED_EXTERNAL)
                allowcb = 1;
        }

        if (allowcb) {
            VIR_DEBUG("Client run callback for PolicyKit authentication");
            /* Run the authentication callback */
            if ((*(auth->cb))(&cred, 1, auth->cbdata) < 0) {
                virReportError(VIR_ERR_AUTH_FAILED, "%s",
                               _("Failed to collect auth credentials"));
                return -1;
            }
        } else {
            VIR_DEBUG("Client auth callback does not support PolicyKit");
            return -1;
        }
    } else {
        VIR_DEBUG("No auth callback provided");
        return -1;
    }

    memset(&ret, 0, sizeof(ret));
    if (call(conn, priv, 0, REMOTE_PROC_AUTH_POLKIT,
             (xdrproc_t) xdr_void, (char *)NULL,
             (xdrproc_t) xdr_remote_auth_polkit_ret, (char *) &ret) != 0) {
        return -1; /* virError already set by call */
    }

out:
    VIR_DEBUG("PolicyKit-0 authentication complete");
    return 0;
}
# endif /* WITH_POLKIT0 */
#endif /* WITH_POLKIT */
/*----------------------------------------------------------------------*/

static int remoteConnectDomainEventRegister(virConnectPtr conn,
                                            virConnectDomainEventCallback callback,
                                            void *opaque,
                                            virFreeCallback freecb)
{
    int rv = -1;
    struct private_data *priv = conn->privateData;
    int count;

    remoteDriverLock(priv);

    if ((count = virDomainEventStateRegister(conn, priv->domainEventState,
                                             callback, opaque, freecb)) < 0) {
         virReportError(VIR_ERR_RPC, "%s", _("adding cb to list"));
         goto done;
    }

    if (count == 1) {
        /* Tell the server when we are the first callback deregistering */
        if (call(conn, priv, 0, REMOTE_PROC_CONNECT_DOMAIN_EVENT_REGISTER,
                 (xdrproc_t) xdr_void, (char *) NULL,
                 (xdrproc_t) xdr_void, (char *) NULL) == -1)
            goto done;
    }

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int remoteConnectDomainEventDeregister(virConnectPtr conn,
                                              virConnectDomainEventCallback callback)
{
    struct private_data *priv = conn->privateData;
    int rv = -1;
    int count;

    remoteDriverLock(priv);

    if ((count = virDomainEventStateDeregister(conn,
                                               priv->domainEventState,
                                               callback)) < 0)
        goto done;

    if (count == 0) {
        /* Tell the server when we are the last callback deregistering */
        if (call(conn, priv, 0, REMOTE_PROC_CONNECT_DOMAIN_EVENT_DEREGISTER,
                 (xdrproc_t) xdr_void, (char *) NULL,
                 (xdrproc_t) xdr_void, (char *) NULL) == -1)
            goto done;
    }

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}


static void
remoteDomainBuildEventLifecycle(virNetClientProgramPtr prog ATTRIBUTE_UNUSED,
                                virNetClientPtr client ATTRIBUTE_UNUSED,
                                void *evdata, void *opaque)
{
    virConnectPtr conn = opaque;
    struct private_data *priv = conn->privateData;
    remote_domain_event_lifecycle_msg *msg = evdata;
    virDomainPtr dom;
    virDomainEventPtr event = NULL;

    dom = get_nonnull_domain(conn, msg->dom);
    if (!dom)
        return;

    event = virDomainEventNewFromDom(dom, msg->event, msg->detail);
    virDomainFree(dom);

    remoteDomainEventQueue(priv, event);
}


static void
remoteDomainBuildEventReboot(virNetClientProgramPtr prog ATTRIBUTE_UNUSED,
                             virNetClientPtr client ATTRIBUTE_UNUSED,
                             void *evdata, void *opaque)
{
    virConnectPtr conn = opaque;
    struct private_data *priv = conn->privateData;
    remote_domain_event_reboot_msg *msg = evdata;
    virDomainPtr dom;
    virDomainEventPtr event = NULL;

    dom = get_nonnull_domain(conn, msg->dom);
    if (!dom)
        return;

    event = virDomainEventRebootNewFromDom(dom);
    virDomainFree(dom);

    remoteDomainEventQueue(priv, event);
}


static void
remoteDomainBuildEventRTCChange(virNetClientProgramPtr prog ATTRIBUTE_UNUSED,
                                virNetClientPtr client ATTRIBUTE_UNUSED,
                                void *evdata, void *opaque)
{
    virConnectPtr conn = opaque;
    struct private_data *priv = conn->privateData;
    remote_domain_event_rtc_change_msg *msg = evdata;
    virDomainPtr dom;
    virDomainEventPtr event = NULL;

    dom = get_nonnull_domain(conn, msg->dom);
    if (!dom)
        return;

    event = virDomainEventRTCChangeNewFromDom(dom, msg->offset);
    virDomainFree(dom);

    remoteDomainEventQueue(priv, event);
}


static void
remoteDomainBuildEventWatchdog(virNetClientProgramPtr prog ATTRIBUTE_UNUSED,
                               virNetClientPtr client ATTRIBUTE_UNUSED,
                               void *evdata, void *opaque)
{
    virConnectPtr conn = opaque;
    struct private_data *priv = conn->privateData;
    remote_domain_event_watchdog_msg *msg = evdata;
    virDomainPtr dom;
    virDomainEventPtr event = NULL;

    dom = get_nonnull_domain(conn, msg->dom);
    if (!dom)
        return;

    event = virDomainEventWatchdogNewFromDom(dom, msg->action);
    virDomainFree(dom);

    remoteDomainEventQueue(priv, event);
}


static void
remoteDomainBuildEventIOError(virNetClientProgramPtr prog ATTRIBUTE_UNUSED,
                              virNetClientPtr client ATTRIBUTE_UNUSED,
                              void *evdata, void *opaque)
{
    virConnectPtr conn = opaque;
    struct private_data *priv = conn->privateData;
    remote_domain_event_io_error_msg *msg = evdata;
    virDomainPtr dom;
    virDomainEventPtr event = NULL;

    dom = get_nonnull_domain(conn, msg->dom);
    if (!dom)
        return;

    event = virDomainEventIOErrorNewFromDom(dom,
                                            msg->srcPath,
                                            msg->devAlias,
                                            msg->action);
    virDomainFree(dom);

    remoteDomainEventQueue(priv, event);
}


static void
remoteDomainBuildEventIOErrorReason(virNetClientProgramPtr prog ATTRIBUTE_UNUSED,
                                    virNetClientPtr client ATTRIBUTE_UNUSED,
                                    void *evdata, void *opaque)
{
    virConnectPtr conn = opaque;
    struct private_data *priv = conn->privateData;
    remote_domain_event_io_error_reason_msg *msg = evdata;
    virDomainPtr dom;
    virDomainEventPtr event = NULL;

    dom = get_nonnull_domain(conn, msg->dom);
    if (!dom)
        return;

    event = virDomainEventIOErrorReasonNewFromDom(dom,
                                                  msg->srcPath,
                                                  msg->devAlias,
                                                  msg->action,
                                                  msg->reason);

    virDomainFree(dom);

    remoteDomainEventQueue(priv, event);
}

static void
remoteDomainBuildEventBlockJob(virNetClientProgramPtr prog ATTRIBUTE_UNUSED,
                               virNetClientPtr client ATTRIBUTE_UNUSED,
                               void *evdata, void *opaque)
{
    virConnectPtr conn = opaque;
    struct private_data *priv = conn->privateData;
    remote_domain_event_block_job_msg *msg = evdata;
    virDomainPtr dom;
    virDomainEventPtr event = NULL;

    dom = get_nonnull_domain(conn, msg->dom);
    if (!dom)
        return;

    event = virDomainEventBlockJobNewFromDom(dom, msg->path, msg->type,
                                             msg->status);

    virDomainFree(dom);

    remoteDomainEventQueue(priv, event);
}

static void
remoteDomainBuildEventGraphics(virNetClientProgramPtr prog ATTRIBUTE_UNUSED,
                               virNetClientPtr client ATTRIBUTE_UNUSED,
                               void *evdata, void *opaque)
{
    virConnectPtr conn = opaque;
    struct private_data *priv = conn->privateData;
    remote_domain_event_graphics_msg *msg = evdata;
    virDomainPtr dom;
    virDomainEventPtr event = NULL;
    virDomainEventGraphicsAddressPtr localAddr = NULL;
    virDomainEventGraphicsAddressPtr remoteAddr = NULL;
    virDomainEventGraphicsSubjectPtr subject = NULL;
    size_t i;

    dom = get_nonnull_domain(conn, msg->dom);
    if (!dom)
        return;

    if (VIR_ALLOC(localAddr) < 0)
        goto error;
    localAddr->family = msg->local.family;
    if (VIR_STRDUP(localAddr->service, msg->local.service) < 0 ||
        VIR_STRDUP(localAddr->node, msg->local.node) < 0)
        goto error;

    if (VIR_ALLOC(remoteAddr) < 0)
        goto error;
    remoteAddr->family = msg->remote.family;
    if (VIR_STRDUP(remoteAddr->service, msg->remote.service) < 0 ||
        VIR_STRDUP(remoteAddr->node, msg->remote.node) < 0)
        goto error;

    if (VIR_ALLOC(subject) < 0)
        goto error;
    if (VIR_ALLOC_N(subject->identities, msg->subject.subject_len) < 0)
        goto error;
    subject->nidentity = msg->subject.subject_len;
    for (i = 0; i < subject->nidentity; i++) {
        if (VIR_STRDUP(subject->identities[i].type, msg->subject.subject_val[i].type) < 0 ||
            VIR_STRDUP(subject->identities[i].name, msg->subject.subject_val[i].name) < 0)
            goto error;
    }

    event = virDomainEventGraphicsNewFromDom(dom,
                                             msg->phase,
                                             localAddr,
                                             remoteAddr,
                                             msg->authScheme,
                                             subject);

    virDomainFree(dom);

    remoteDomainEventQueue(priv, event);
    return;

error:
    if (localAddr) {
        VIR_FREE(localAddr->service);
        VIR_FREE(localAddr->node);
        VIR_FREE(localAddr);
    }
    if (remoteAddr) {
        VIR_FREE(remoteAddr->service);
        VIR_FREE(remoteAddr->node);
        VIR_FREE(remoteAddr);
    }
    if (subject) {
        for (i = 0; i < subject->nidentity; i++) {
            VIR_FREE(subject->identities[i].type);
            VIR_FREE(subject->identities[i].name);
        }
        VIR_FREE(subject->identities);
        VIR_FREE(subject);
    }
    virDomainFree(dom);
    return;
}


static void
remoteDomainBuildEventControlError(virNetClientProgramPtr prog ATTRIBUTE_UNUSED,
                                   virNetClientPtr client ATTRIBUTE_UNUSED,
                                   void *evdata, void *opaque)
{
    virConnectPtr conn = opaque;
    struct private_data *priv = conn->privateData;
    remote_domain_event_control_error_msg *msg = evdata;
    virDomainPtr dom;
    virDomainEventPtr event = NULL;

    dom = get_nonnull_domain(conn, msg->dom);
    if (!dom)
        return;

    event = virDomainEventControlErrorNewFromDom(dom);

    virDomainFree(dom);

    remoteDomainEventQueue(priv, event);
}


static void
remoteDomainBuildEventDiskChange(virNetClientProgramPtr prog ATTRIBUTE_UNUSED,
                                 virNetClientPtr client ATTRIBUTE_UNUSED,
                                 void *evdata, void *opaque)
{
    virConnectPtr conn = opaque;
    struct private_data *priv = conn->privateData;
    remote_domain_event_disk_change_msg *msg = evdata;
    virDomainPtr dom;
    virDomainEventPtr event = NULL;

    dom = get_nonnull_domain(conn, msg->dom);
    if (!dom)
        return;

    event = virDomainEventDiskChangeNewFromDom(dom,
                                               msg->oldSrcPath ? *msg->oldSrcPath : NULL,
                                               msg->newSrcPath ? *msg->newSrcPath : NULL,
                                               msg->devAlias,
                                               msg->reason);

    virDomainFree(dom);

    remoteDomainEventQueue(priv, event);
}


static void
remoteDomainBuildEventTrayChange(virNetClientProgramPtr prog ATTRIBUTE_UNUSED,
                                 virNetClientPtr client ATTRIBUTE_UNUSED,
                                 void *evdata, void *opaque)
{
    virConnectPtr conn = opaque;
    struct private_data *priv = conn->privateData;
    remote_domain_event_tray_change_msg *msg = evdata;
    virDomainPtr dom;
    virDomainEventPtr event = NULL;

    dom = get_nonnull_domain(conn, msg->dom);
    if (!dom)
        return;

    event = virDomainEventTrayChangeNewFromDom(dom,
                                               msg->devAlias,
                                               msg->reason);

    virDomainFree(dom);

    remoteDomainEventQueue(priv, event);
}

static void
remoteDomainBuildEventPMWakeup(virNetClientProgramPtr prog ATTRIBUTE_UNUSED,
                               virNetClientPtr client ATTRIBUTE_UNUSED,
                               void *evdata, void *opaque)
{
    virConnectPtr conn = opaque;
    struct private_data *priv = conn->privateData;
    remote_domain_event_pmwakeup_msg *msg = evdata;
    virDomainPtr dom;
    virDomainEventPtr event = NULL;

    dom = get_nonnull_domain(conn, msg->dom);
    if (!dom)
        return;

    event = virDomainEventPMWakeupNewFromDom(dom);

    virDomainFree(dom);

    remoteDomainEventQueue(priv, event);
}

static void
remoteDomainBuildEventPMSuspend(virNetClientProgramPtr prog ATTRIBUTE_UNUSED,
                                virNetClientPtr client ATTRIBUTE_UNUSED,
                                void *evdata, void *opaque)
{
    virConnectPtr conn = opaque;
    struct private_data *priv = conn->privateData;
    remote_domain_event_pmsuspend_msg *msg = evdata;
    virDomainPtr dom;
    virDomainEventPtr event = NULL;

    dom = get_nonnull_domain(conn, msg->dom);
    if (!dom)
        return;

    event = virDomainEventPMSuspendNewFromDom(dom);

    virDomainFree(dom);

    remoteDomainEventQueue(priv, event);
}


static void
remoteDomainBuildEventBalloonChange(virNetClientProgramPtr prog ATTRIBUTE_UNUSED,
                                    virNetClientPtr client ATTRIBUTE_UNUSED,
                                    void *evdata, void *opaque)
{
    virConnectPtr conn = opaque;
    struct private_data *priv = conn->privateData;
    remote_domain_event_balloon_change_msg *msg = evdata;
    virDomainPtr dom;
    virDomainEventPtr event = NULL;

    dom = get_nonnull_domain(conn, msg->dom);
    if (!dom)
        return;

    event = virDomainEventBalloonChangeNewFromDom(dom, msg->actual);
    virDomainFree(dom);

    remoteDomainEventQueue(priv, event);
}


static void
remoteDomainBuildEventPMSuspendDisk(virNetClientProgramPtr prog ATTRIBUTE_UNUSED,
                                    virNetClientPtr client ATTRIBUTE_UNUSED,
                                    void *evdata, void *opaque)
{
    virConnectPtr conn = opaque;
    struct private_data *priv = conn->privateData;
    remote_domain_event_pmsuspend_disk_msg *msg = evdata;
    virDomainPtr dom;
    virDomainEventPtr event = NULL;

    dom = get_nonnull_domain(conn, msg->dom);
    if (!dom)
        return;

    event = virDomainEventPMSuspendDiskNewFromDom(dom);

    virDomainFree(dom);

    remoteDomainEventQueue(priv, event);
}


static void
remoteDomainBuildEventDeviceRemoved(virNetClientProgramPtr prog ATTRIBUTE_UNUSED,
                                    virNetClientPtr client ATTRIBUTE_UNUSED,
                                    void *evdata, void *opaque)
{
    virConnectPtr conn = opaque;
    struct private_data *priv = conn->privateData;
    remote_domain_event_device_removed_msg *msg = evdata;
    virDomainPtr dom;
    virDomainEventPtr event = NULL;

    dom = get_nonnull_domain(conn, msg->dom);
    if (!dom)
        return;

    event = virDomainEventDeviceRemovedNewFromDom(dom, msg->devAlias);

    virDomainFree(dom);

    remoteDomainEventQueue(priv, event);
}


static virDrvOpenStatus ATTRIBUTE_NONNULL(1)
remoteSecretOpen(virConnectPtr conn, virConnectAuthPtr auth,
                 unsigned int flags)
{
    return remoteGenericOpen(conn, auth, flags, &conn->secretPrivateData);
}

static int
remoteSecretClose(virConnectPtr conn)
{
    return remoteGenericClose(conn, &conn->secretPrivateData);
}

static unsigned char *
remoteSecretGetValue(virSecretPtr secret, size_t *value_size,
                     unsigned int flags, unsigned int internalFlags)
{
    unsigned char *rv = NULL;
    remote_secret_get_value_args args;
    remote_secret_get_value_ret ret;
    struct private_data *priv = secret->conn->secretPrivateData;

    remoteDriverLock(priv);

    /* internalFlags intentionally do not go over the wire */
    if (internalFlags) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("no internalFlags support"));
        goto done;
    }

    make_nonnull_secret(&args.secret, secret);
    args.flags = flags;

    memset(&ret, 0, sizeof(ret));
    if (call(secret->conn, priv, 0, REMOTE_PROC_SECRET_GET_VALUE,
             (xdrproc_t) xdr_remote_secret_get_value_args, (char *) &args,
             (xdrproc_t) xdr_remote_secret_get_value_ret, (char *) &ret) == -1)
        goto done;

    *value_size = ret.value.value_len;
    rv = (unsigned char *) ret.value.value_val; /* Caller frees. */

done:
    remoteDriverUnlock(priv);
    return rv;
}


static int
remoteStreamSend(virStreamPtr st,
                 const char *data,
                 size_t nbytes)
{
    VIR_DEBUG("st=%p data=%p nbytes=%zu", st, data, nbytes);
    struct private_data *priv = st->conn->privateData;
    virNetClientStreamPtr privst = st->privateData;
    int rv;

    if (virNetClientStreamRaiseError(privst))
        return -1;

    remoteDriverLock(priv);
    priv->localUses++;
    remoteDriverUnlock(priv);

    rv = virNetClientStreamSendPacket(privst,
                                      priv->client,
                                      VIR_NET_CONTINUE,
                                      data,
                                      nbytes);

    remoteDriverLock(priv);
    priv->localUses--;
    remoteDriverUnlock(priv);
    return rv;
}


static int
remoteStreamRecv(virStreamPtr st,
                 char *data,
                 size_t nbytes)
{
    VIR_DEBUG("st=%p data=%p nbytes=%zu", st, data, nbytes);
    struct private_data *priv = st->conn->privateData;
    virNetClientStreamPtr privst = st->privateData;
    int rv;

    if (virNetClientStreamRaiseError(privst))
        return -1;

    remoteDriverLock(priv);
    priv->localUses++;
    remoteDriverUnlock(priv);

    rv = virNetClientStreamRecvPacket(privst,
                                      priv->client,
                                      data,
                                      nbytes,
                                      (st->flags & VIR_STREAM_NONBLOCK));

    VIR_DEBUG("Done %d", rv);

    remoteDriverLock(priv);
    priv->localUses--;
    remoteDriverUnlock(priv);
    return rv;
}

struct remoteStreamCallbackData {
    virStreamPtr st;
    virStreamEventCallback cb;
    void *opaque;
    virFreeCallback ff;
};

static void remoteStreamEventCallback(virNetClientStreamPtr stream ATTRIBUTE_UNUSED,
                                      int events,
                                      void *opaque)
{
    struct remoteStreamCallbackData *cbdata = opaque;

    (cbdata->cb)(cbdata->st, events, cbdata->opaque);
}


static void remoteStreamCallbackFree(void *opaque)
{
    struct remoteStreamCallbackData *cbdata = opaque;

    if (!cbdata->cb && cbdata->ff)
        (cbdata->ff)(cbdata->opaque);

    virStreamFree(cbdata->st);
    VIR_FREE(opaque);
}


static int
remoteStreamEventAddCallback(virStreamPtr st,
                             int events,
                             virStreamEventCallback cb,
                             void *opaque,
                             virFreeCallback ff)
{
    struct private_data *priv = st->conn->privateData;
    virNetClientStreamPtr privst = st->privateData;
    int ret = -1;
    struct remoteStreamCallbackData *cbdata;

    if (VIR_ALLOC(cbdata) < 0)
        return -1;
    cbdata->cb = cb;
    cbdata->opaque = opaque;
    cbdata->ff = ff;
    cbdata->st = st;
    virStreamRef(st);

    remoteDriverLock(priv);

    if ((ret = virNetClientStreamEventAddCallback(privst,
                                                  events,
                                                  remoteStreamEventCallback,
                                                  cbdata,
                                                  remoteStreamCallbackFree)) < 0) {
        VIR_FREE(cbdata);
        goto cleanup;
    }

cleanup:
    remoteDriverUnlock(priv);
    /* coverity[leaked_storage] - cbdata is not leaked */
    return ret;
}


static int
remoteStreamEventUpdateCallback(virStreamPtr st,
                                int events)
{
    struct private_data *priv = st->conn->privateData;
    virNetClientStreamPtr privst = st->privateData;
    int ret = -1;

    remoteDriverLock(priv);

    ret = virNetClientStreamEventUpdateCallback(privst, events);

    remoteDriverUnlock(priv);
    return ret;
}


static int
remoteStreamEventRemoveCallback(virStreamPtr st)
{
    struct private_data *priv = st->conn->privateData;
    virNetClientStreamPtr privst = st->privateData;
    int ret = -1;

    remoteDriverLock(priv);

    ret = virNetClientStreamEventRemoveCallback(privst);

    remoteDriverUnlock(priv);
    return ret;
}


static int
remoteStreamFinish(virStreamPtr st)
{
    struct private_data *priv = st->conn->privateData;
    virNetClientStreamPtr privst = st->privateData;
    int ret = -1;

    remoteDriverLock(priv);

    if (virNetClientStreamRaiseError(privst))
        goto cleanup;

    priv->localUses++;
    remoteDriverUnlock(priv);

    ret = virNetClientStreamSendPacket(privst,
                                       priv->client,
                                       VIR_NET_OK,
                                       NULL,
                                       0);

    remoteDriverLock(priv);
    priv->localUses--;

cleanup:
    virNetClientRemoveStream(priv->client, privst);
    virObjectUnref(privst);
    st->privateData = NULL;
    st->driver = NULL;

    remoteDriverUnlock(priv);
    return ret;
}


static int
remoteStreamAbort(virStreamPtr st)
{
    struct private_data *priv = st->conn->privateData;
    virNetClientStreamPtr privst = st->privateData;
    int ret = -1;

    remoteDriverLock(priv);

    if (virNetClientStreamRaiseError(privst))
        goto cleanup;

    priv->localUses++;
    remoteDriverUnlock(priv);

    ret = virNetClientStreamSendPacket(privst,
                                       priv->client,
                                       VIR_NET_ERROR,
                                       NULL,
                                       0);

    remoteDriverLock(priv);
    priv->localUses--;

cleanup:
    virNetClientRemoveStream(priv->client, privst);
    virObjectUnref(privst);
    st->privateData = NULL;
    st->driver = NULL;

    remoteDriverUnlock(priv);
    return ret;
}


static virStreamDriver remoteStreamDrv = {
    .streamRecv = remoteStreamRecv,
    .streamSend = remoteStreamSend,
    .streamFinish = remoteStreamFinish,
    .streamAbort = remoteStreamAbort,
    .streamEventAddCallback = remoteStreamEventAddCallback,
    .streamEventUpdateCallback = remoteStreamEventUpdateCallback,
    .streamEventRemoveCallback = remoteStreamEventRemoveCallback,
};


static int remoteConnectDomainEventRegisterAny(virConnectPtr conn,
                                               virDomainPtr dom,
                                               int eventID,
                                               virConnectDomainEventGenericCallback callback,
                                               void *opaque,
                                               virFreeCallback freecb)
{
    int rv = -1;
    struct private_data *priv = conn->privateData;
    remote_connect_domain_event_register_any_args args;
    int callbackID;
    int count;

    remoteDriverLock(priv);

    if ((count = virDomainEventStateRegisterID(conn,
                                               priv->domainEventState,
                                               dom, eventID,
                                               callback, opaque, freecb,
                                               &callbackID)) < 0) {
        virReportError(VIR_ERR_RPC, "%s", _("adding cb to list"));
        goto done;
    }

    /* If this is the first callback for this eventID, we need to enable
     * events on the server */
    if (count == 1) {
        args.eventID = eventID;

        if (call(conn, priv, 0, REMOTE_PROC_CONNECT_DOMAIN_EVENT_REGISTER_ANY,
                 (xdrproc_t) xdr_remote_connect_domain_event_register_any_args, (char *) &args,
                 (xdrproc_t) xdr_void, (char *)NULL) == -1) {
            virDomainEventStateDeregisterID(conn,
                                            priv->domainEventState,
                                            callbackID);
            goto done;
        }
    }

    rv = callbackID;

done:
    remoteDriverUnlock(priv);
    return rv;
}


static int remoteConnectDomainEventDeregisterAny(virConnectPtr conn,
                                                 int callbackID)
{
    struct private_data *priv = conn->privateData;
    int rv = -1;
    remote_connect_domain_event_deregister_any_args args;
    int eventID;
    int count;

    remoteDriverLock(priv);

    if ((eventID = virDomainEventStateEventID(conn,
                                              priv->domainEventState,
                                              callbackID)) < 0) {
        virReportError(VIR_ERR_RPC, _("unable to find callback ID %d"), callbackID);
        goto done;
    }

    if ((count = virDomainEventStateDeregisterID(conn,
                                                 priv->domainEventState,
                                                 callbackID)) < 0) {
        virReportError(VIR_ERR_RPC, _("unable to find callback ID %d"), callbackID);
        goto done;
    }

    /* If that was the last callback for this eventID, we need to disable
     * events on the server */
    if (count == 0) {
        args.eventID = eventID;

        if (call(conn, priv, 0, REMOTE_PROC_CONNECT_DOMAIN_EVENT_DEREGISTER_ANY,
                 (xdrproc_t) xdr_remote_connect_domain_event_deregister_any_args, (char *) &args,
                 (xdrproc_t) xdr_void, (char *) NULL) == -1)
            goto done;
    }

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}


/*----------------------------------------------------------------------*/

static int
remoteDomainQemuMonitorCommand(virDomainPtr domain, const char *cmd,
                               char **result, unsigned int flags)
{
    int rv = -1;
    qemu_domain_monitor_command_args args;
    qemu_domain_monitor_command_ret ret;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain(&args.dom, domain);
    args.cmd = (char *)cmd;
    args.flags = flags;

    memset(&ret, 0, sizeof(ret));
    if (call(domain->conn, priv, REMOTE_CALL_QEMU, QEMU_PROC_DOMAIN_MONITOR_COMMAND,
             (xdrproc_t) xdr_qemu_domain_monitor_command_args, (char *) &args,
             (xdrproc_t) xdr_qemu_domain_monitor_command_ret, (char *) &ret) == -1)
        goto done;

    if (VIR_STRDUP(*result, ret.result) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    xdr_free((xdrproc_t) xdr_qemu_domain_monitor_command_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return rv;
}


static char *
remoteDomainMigrateBegin3(virDomainPtr domain,
                          const char *xmlin,
                          char **cookieout,
                          int *cookieoutlen,
                          unsigned long flags,
                          const char *dname,
                          unsigned long resource)
{
    char *rv = NULL;
    remote_domain_migrate_begin3_args args;
    remote_domain_migrate_begin3_ret ret;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    memset(&args, 0, sizeof(args));
    memset(&ret, 0, sizeof(ret));

    make_nonnull_domain(&args.dom, domain);
    args.xmlin = xmlin == NULL ? NULL : (char **) &xmlin;
    args.flags = flags;
    args.dname = dname == NULL ? NULL : (char **) &dname;
    args.resource = resource;

    if (call(domain->conn, priv, 0, REMOTE_PROC_DOMAIN_MIGRATE_BEGIN3,
             (xdrproc_t) xdr_remote_domain_migrate_begin3_args, (char *) &args,
             (xdrproc_t) xdr_remote_domain_migrate_begin3_ret, (char *) &ret) == -1)
        goto done;

    if (ret.cookie_out.cookie_out_len > 0) {
        if (!cookieout || !cookieoutlen) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("caller ignores cookieout or cookieoutlen"));
            goto error;
        }
        *cookieout = ret.cookie_out.cookie_out_val; /* Caller frees. */
        *cookieoutlen = ret.cookie_out.cookie_out_len;
    }

    rv = ret.xml; /* caller frees */

done:
    remoteDriverUnlock(priv);
    return rv;

error:
    VIR_FREE(ret.cookie_out.cookie_out_val);
    goto done;
}


static int
remoteDomainMigratePrepare3(virConnectPtr dconn,
                            const char *cookiein,
                            int cookieinlen,
                            char **cookieout,
                            int *cookieoutlen,
                            const char *uri_in,
                            char **uri_out,
                            unsigned long flags,
                            const char *dname,
                            unsigned long resource,
                            const char *dom_xml)
{
    int rv = -1;
    remote_domain_migrate_prepare3_args args;
    remote_domain_migrate_prepare3_ret ret;
    struct private_data *priv = dconn->privateData;

    remoteDriverLock(priv);

    memset(&args, 0, sizeof(args));
    memset(&ret, 0, sizeof(ret));

    args.cookie_in.cookie_in_val = (char *)cookiein;
    args.cookie_in.cookie_in_len = cookieinlen;
    args.uri_in = uri_in == NULL ? NULL : (char **) &uri_in;
    args.flags = flags;
    args.dname = dname == NULL ? NULL : (char **) &dname;
    args.resource = resource;
    args.dom_xml = (char *) dom_xml;

    memset(&ret, 0, sizeof(ret));
    if (call(dconn, priv, 0, REMOTE_PROC_DOMAIN_MIGRATE_PREPARE3,
             (xdrproc_t) xdr_remote_domain_migrate_prepare3_args, (char *) &args,
             (xdrproc_t) xdr_remote_domain_migrate_prepare3_ret, (char *) &ret) == -1)
        goto done;

    if (ret.cookie_out.cookie_out_len > 0) {
        if (!cookieout || !cookieoutlen) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("caller ignores cookieout or cookieoutlen"));
            goto error;
        }
        *cookieout = ret.cookie_out.cookie_out_val; /* Caller frees. */
        *cookieoutlen = ret.cookie_out.cookie_out_len;
    }
    if (ret.uri_out) {
        if (!uri_out) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("caller ignores uri_out"));
            goto error;
        }
        *uri_out = *ret.uri_out; /* Caller frees. */
    }

    rv = 0;

done:
    VIR_FREE(ret.uri_out);
    remoteDriverUnlock(priv);
    return rv;
error:
    VIR_FREE(ret.cookie_out.cookie_out_val);
    if (ret.uri_out)
        VIR_FREE(*ret.uri_out);
    goto done;
}


static int
remoteDomainMigratePrepareTunnel3(virConnectPtr dconn,
                                  virStreamPtr st,
                                  const char *cookiein,
                                  int cookieinlen,
                                  char **cookieout,
                                  int *cookieoutlen,
                                  unsigned long flags,
                                  const char *dname,
                                  unsigned long resource,
                                  const char *dom_xml)
{
    struct private_data *priv = dconn->privateData;
    int rv = -1;
    remote_domain_migrate_prepare_tunnel3_args args;
    remote_domain_migrate_prepare_tunnel3_ret ret;
    virNetClientStreamPtr netst;

    remoteDriverLock(priv);

    memset(&args, 0, sizeof(args));
    memset(&ret, 0, sizeof(ret));

    if (!(netst = virNetClientStreamNew(priv->remoteProgram,
                                        REMOTE_PROC_DOMAIN_MIGRATE_PREPARE_TUNNEL3,
                                        priv->counter)))
        goto done;

    if (virNetClientAddStream(priv->client, netst) < 0) {
        virObjectUnref(netst);
        goto done;
    }

    st->driver = &remoteStreamDrv;
    st->privateData = netst;

    args.cookie_in.cookie_in_val = (char *)cookiein;
    args.cookie_in.cookie_in_len = cookieinlen;
    args.flags = flags;
    args.dname = dname == NULL ? NULL : (char **) &dname;
    args.resource = resource;
    args.dom_xml = (char *) dom_xml;

    if (call(dconn, priv, 0, REMOTE_PROC_DOMAIN_MIGRATE_PREPARE_TUNNEL3,
             (xdrproc_t) xdr_remote_domain_migrate_prepare_tunnel3_args, (char *) &args,
             (xdrproc_t) xdr_remote_domain_migrate_prepare_tunnel3_ret, (char *) &ret) == -1) {
        virNetClientRemoveStream(priv->client, netst);
        virObjectUnref(netst);
        goto done;
    }

    if (ret.cookie_out.cookie_out_len > 0) {
        if (!cookieout || !cookieoutlen) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("caller ignores cookieout or cookieoutlen"));
            goto error;
        }
        *cookieout = ret.cookie_out.cookie_out_val; /* Caller frees. */
        *cookieoutlen = ret.cookie_out.cookie_out_len;
    }

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;

error:
    VIR_FREE(ret.cookie_out.cookie_out_val);
    goto done;
}


static int
remoteDomainMigratePerform3(virDomainPtr dom,
                            const char *xmlin,
                            const char *cookiein,
                            int cookieinlen,
                            char **cookieout,
                            int *cookieoutlen,
                            const char *dconnuri,
                            const char *uri,
                            unsigned long flags,
                            const char *dname,
                            unsigned long resource)
{
    int rv = -1;
    remote_domain_migrate_perform3_args args;
    remote_domain_migrate_perform3_ret ret;
    struct private_data *priv = dom->conn->privateData;

    remoteDriverLock(priv);

    memset(&args, 0, sizeof(args));
    memset(&ret, 0, sizeof(ret));

    make_nonnull_domain(&args.dom, dom);

    args.xmlin = xmlin == NULL ? NULL : (char **) &xmlin;
    args.cookie_in.cookie_in_val = (char *)cookiein;
    args.cookie_in.cookie_in_len = cookieinlen;
    args.flags = flags;
    args.dname = dname == NULL ? NULL : (char **) &dname;
    args.uri = uri == NULL ? NULL : (char **) &uri;
    args.dconnuri = dconnuri == NULL ? NULL : (char **) &dconnuri;
    args.resource = resource;

    if (call(dom->conn, priv, 0, REMOTE_PROC_DOMAIN_MIGRATE_PERFORM3,
             (xdrproc_t) xdr_remote_domain_migrate_perform3_args, (char *) &args,
             (xdrproc_t) xdr_remote_domain_migrate_perform3_ret, (char *) &ret) == -1)
        goto done;

    if (ret.cookie_out.cookie_out_len > 0) {
        if (!cookieout || !cookieoutlen) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("caller ignores cookieout or cookieoutlen"));
            goto error;
        }
        *cookieout = ret.cookie_out.cookie_out_val; /* Caller frees. */
        *cookieoutlen = ret.cookie_out.cookie_out_len;
    }

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;

error:
    VIR_FREE(ret.cookie_out.cookie_out_val);
    goto done;
}


static virDomainPtr
remoteDomainMigrateFinish3(virConnectPtr dconn,
                           const char *dname,
                           const char *cookiein,
                           int cookieinlen,
                           char **cookieout,
                           int *cookieoutlen,
                           const char *dconnuri,
                           const char *uri,
                           unsigned long flags,
                           int cancelled)
{
    remote_domain_migrate_finish3_args args;
    remote_domain_migrate_finish3_ret ret;
    struct private_data *priv = dconn->privateData;
    virDomainPtr rv = NULL;

    remoteDriverLock(priv);

    memset(&args, 0, sizeof(args));
    memset(&ret, 0, sizeof(ret));

    args.cookie_in.cookie_in_val = (char *)cookiein;
    args.cookie_in.cookie_in_len = cookieinlen;
    args.dname = (char *) dname;
    args.uri = uri == NULL ? NULL : (char **) &uri;
    args.dconnuri = dconnuri == NULL ? NULL : (char **) &dconnuri;
    args.flags = flags;
    args.cancelled = cancelled;

    if (call(dconn, priv, 0, REMOTE_PROC_DOMAIN_MIGRATE_FINISH3,
             (xdrproc_t) xdr_remote_domain_migrate_finish3_args, (char *) &args,
             (xdrproc_t) xdr_remote_domain_migrate_finish3_ret, (char *) &ret) == -1)
        goto done;

    rv = get_nonnull_domain(dconn, ret.dom);

    if (ret.cookie_out.cookie_out_len > 0) {
        if (!cookieout || !cookieoutlen) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("caller ignores cookieout or cookieoutlen"));
            goto error;
        }
        *cookieout = ret.cookie_out.cookie_out_val; /* Caller frees. */
        *cookieoutlen = ret.cookie_out.cookie_out_len;
        ret.cookie_out.cookie_out_val = NULL;
        ret.cookie_out.cookie_out_len = 0;
    }

    xdr_free((xdrproc_t) &xdr_remote_domain_migrate_finish3_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return rv;

error:
    VIR_FREE(ret.cookie_out.cookie_out_val);
    goto done;
}


static int
remoteDomainMigrateConfirm3(virDomainPtr domain,
                            const char *cookiein,
                            int cookieinlen,
                            unsigned long flags,
                            int cancelled)
{
    int rv = -1;
    remote_domain_migrate_confirm3_args args;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    memset(&args, 0, sizeof(args));

    make_nonnull_domain(&args.dom, domain);
    args.cookie_in.cookie_in_len = cookieinlen;
    args.cookie_in.cookie_in_val = (char *) cookiein;
    args.flags = flags;
    args.cancelled = cancelled;

    if (call(domain->conn, priv, 0, REMOTE_PROC_DOMAIN_MIGRATE_CONFIRM3,
             (xdrproc_t) xdr_remote_domain_migrate_confirm3_args, (char *) &args,
             (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto done;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}


static int
remoteConnectGetCPUModelNames(virConnectPtr conn,
                              const char *arch,
                              char ***models,
                              unsigned int flags)
{
    int rv = -1;
    size_t i;
    char **retmodels = NULL;
    remote_connect_get_cpu_model_names_args args;
    remote_connect_get_cpu_model_names_ret ret;

    struct private_data *priv = conn->privateData;

    remoteDriverLock(priv);

    args.arch = (char *) arch;
    args.need_results = !!models;
    args.flags = flags;

    memset(&ret, 0, sizeof(ret));
    if (call(conn, priv, 0, REMOTE_PROC_CONNECT_GET_CPU_MODEL_NAMES,
             (xdrproc_t) xdr_remote_connect_get_cpu_model_names_args,
             (char *) &args,
             (xdrproc_t) xdr_remote_connect_get_cpu_model_names_ret,
             (char *) &ret) < 0)
        goto done;

    /* Check the length of the returned list carefully. */
    if (ret.models.models_len > REMOTE_CONNECT_CPU_MODELS_MAX) {
        virReportError(VIR_ERR_RPC,
                       _("Too many model names '%d' for limit '%d'"),
                       ret.models.models_len,
                       REMOTE_CONNECT_CPU_MODELS_MAX);
        goto cleanup;
    }

    if (models) {
        if (VIR_ALLOC_N(retmodels, ret.models.models_len + 1) < 0)
            goto cleanup;

        for (i = 0; i < ret.models.models_len; i++) {
            retmodels[i] = ret.models.models_val[i];
            ret.models.models_val[i] = NULL;
        }
        *models = retmodels;
        retmodels = NULL;
    }

    rv = ret.ret;

cleanup:
    virStringFreeList(retmodels);

    xdr_free((xdrproc_t) xdr_remote_connect_get_cpu_model_names_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return rv;
}


static int
remoteDomainOpenGraphics(virDomainPtr dom,
                         unsigned int idx,
                         int fd,
                         unsigned int flags)
{
    int rv = -1;
    remote_domain_open_graphics_args args;
    struct private_data *priv = dom->conn->privateData;
    int fdin[] = { fd };
    size_t fdinlen = ARRAY_CARDINALITY(fdin);

    remoteDriverLock(priv);

    make_nonnull_domain(&args.dom, dom);
    args.idx = idx;
    args.flags = flags;

    if (callFull(dom->conn, priv, 0,
                 fdin, fdinlen,
                 NULL, NULL,
                 REMOTE_PROC_DOMAIN_OPEN_GRAPHICS,
                 (xdrproc_t) xdr_remote_domain_open_graphics_args, (char *) &args,
                 (xdrproc_t) xdr_void, NULL) == -1)
        goto done;

    rv = 0;

done:
    remoteDriverUnlock(priv);

    return rv;
}


static int
remoteConnectSetKeepAlive(virConnectPtr conn, int interval, unsigned int count)
{
    struct private_data *priv = conn->privateData;
    int ret = -1;

    remoteDriverLock(priv);
    if (!virNetClientKeepAliveIsSupported(priv->client)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("the caller doesn't support keepalive protocol;"
                         " perhaps it's missing event loop implementation"));
        goto cleanup;
    }

    if (!priv->serverKeepAlive) {
        ret = 1;
        goto cleanup;
    }

    if (interval > 0) {
        ret = virNetClientKeepAliveStart(priv->client, interval, count);
    } else {
        virNetClientKeepAliveStop(priv->client);
        ret = 0;
    }

cleanup:
    remoteDriverUnlock(priv);
    return ret;
}


static int
remoteConnectIsAlive(virConnectPtr conn)
{
    struct private_data *priv = conn->privateData;
    bool ret;

    remoteDriverLock(priv);
    ret = virNetClientIsOpen(priv->client);
    remoteDriverUnlock(priv);

    if (ret)
        return 1;
    else
        return 0;
}


static int
remoteDomainGetDiskErrors(virDomainPtr dom,
                          virDomainDiskErrorPtr errors,
                          unsigned int maxerrors,
                          unsigned int flags)
{
    int rv = -1;
    struct private_data *priv = dom->conn->privateData;
    remote_domain_get_disk_errors_args args;
    remote_domain_get_disk_errors_ret ret;

    remoteDriverLock(priv);

    make_nonnull_domain(&args.dom, dom);
    args.maxerrors = maxerrors;
    args.flags = flags;

    memset(&ret, 0, sizeof(ret));

    if (call(dom->conn, priv, 0, REMOTE_PROC_DOMAIN_GET_DISK_ERRORS,
             (xdrproc_t) xdr_remote_domain_get_disk_errors_args,
             (char *) &args,
             (xdrproc_t) xdr_remote_domain_get_disk_errors_ret,
             (char *) &ret) == -1)
        goto done;

    if (remoteDeserializeDomainDiskErrors(ret.errors.errors_val,
                                          ret.errors.errors_len,
                                          REMOTE_DOMAIN_DISK_ERRORS_MAX,
                                          errors,
                                          maxerrors) < 0)
        goto cleanup;

    rv = ret.nerrors;

cleanup:
    xdr_free((xdrproc_t) xdr_remote_domain_get_disk_errors_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return rv;
}

#include "remote_client_bodies.h"
#include "lxc_client_bodies.h"
#include "qemu_client_bodies.h"

/*
 * Serial a set of arguments into a method call message,
 * send that to the server and wait for reply
 */
static int
callFull(virConnectPtr conn ATTRIBUTE_UNUSED,
         struct private_data *priv,
         unsigned int flags,
         int *fdin,
         size_t fdinlen,
         int **fdout,
         size_t *fdoutlen,
         int proc_nr,
         xdrproc_t args_filter, char *args,
         xdrproc_t ret_filter, char *ret)
{
    int rv;
    virNetClientProgramPtr prog;
    int counter = priv->counter++;
    virNetClientPtr client = priv->client;
    priv->localUses++;

    if (flags & REMOTE_CALL_QEMU)
        prog = priv->qemuProgram;
    else if (flags & REMOTE_CALL_LXC)
        prog = priv->lxcProgram;
    else
        prog = priv->remoteProgram;

    /* Unlock, so that if we get any async events/stream data
     * while processing the RPC, we don't deadlock when our
     * callbacks for those are invoked
     */
    remoteDriverUnlock(priv);
    rv = virNetClientProgramCall(prog,
                                 client,
                                 counter,
                                 proc_nr,
                                 fdinlen, fdin,
                                 fdoutlen, fdout,
                                 args_filter, args,
                                 ret_filter, ret);
    remoteDriverLock(priv);
    priv->localUses--;

    return rv;
}

static int
call(virConnectPtr conn,
     struct private_data *priv,
     unsigned int flags,
     int proc_nr,
     xdrproc_t args_filter, char *args,
     xdrproc_t ret_filter, char *ret)
{
    return callFull(conn, priv, flags,
                    NULL, 0,
                    NULL, NULL,
                    proc_nr,
                    args_filter, args,
                    ret_filter, ret);
}


static int
remoteDomainGetInterfaceParameters(virDomainPtr domain,
                                   const char *device,
                                   virTypedParameterPtr params, int *nparams,
                                   unsigned int flags)
{
    int rv = -1;
    remote_domain_get_interface_parameters_args args;
    remote_domain_get_interface_parameters_ret ret;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain(&args.dom, domain);
    args.device = (char *)device;
    args.nparams = *nparams;
    args.flags = flags;

    memset(&ret, 0, sizeof(ret));
    if (call(domain->conn, priv, 0, REMOTE_PROC_DOMAIN_GET_INTERFACE_PARAMETERS,
             (xdrproc_t) xdr_remote_domain_get_interface_parameters_args, (char *) &args,
             (xdrproc_t) xdr_remote_domain_get_interface_parameters_ret, (char *) &ret) == -1)
        goto done;

    /* Handle the case when the caller does not know the number of parameters
     * and is asking for the number of parameters supported
     */
    if (*nparams == 0) {
        *nparams = ret.nparams;
        rv = 0;
        goto cleanup;
    }

    if (remoteDeserializeTypedParameters(ret.params.params_val,
                                         ret.params.params_len,
                                         REMOTE_DOMAIN_INTERFACE_PARAMETERS_MAX,
                                         &params,
                                         nparams) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    xdr_free((xdrproc_t) xdr_remote_domain_get_interface_parameters_ret,
             (char *) &ret);
done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteDomainListAllSnapshots(virDomainPtr dom,
                             virDomainSnapshotPtr **snapshots,
                             unsigned int flags)
{
    int rv = -1;
    size_t i;
    virDomainSnapshotPtr *snaps = NULL;
    remote_domain_list_all_snapshots_args args;
    remote_domain_list_all_snapshots_ret ret;

    struct private_data *priv = dom->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain(&args.dom, dom);
    args.need_results = !!snapshots;
    args.flags = flags;

    memset(&ret, 0, sizeof(ret));
    if (call(dom->conn,
             priv,
             0,
             REMOTE_PROC_DOMAIN_LIST_ALL_SNAPSHOTS,
             (xdrproc_t) xdr_remote_domain_list_all_snapshots_args,
             (char *) &args,
             (xdrproc_t) xdr_remote_domain_list_all_snapshots_ret,
             (char *) &ret) == -1)
        goto done;

    if (ret.snapshots.snapshots_len > REMOTE_DOMAIN_SNAPSHOT_LIST_MAX) {
        virReportError(VIR_ERR_RPC,
                       _("Too many domain snapshots '%d' for limit '%d'"),
                       ret.snapshots.snapshots_len,
                       REMOTE_DOMAIN_SNAPSHOT_LIST_MAX);
        goto cleanup;
    }

    if (snapshots) {
        if (VIR_ALLOC_N(snaps, ret.snapshots.snapshots_len + 1) < 0)
            goto cleanup;
        for (i = 0; i < ret.snapshots.snapshots_len; i++) {
            snaps[i] = get_nonnull_domain_snapshot(dom, ret.snapshots.snapshots_val[i]);
            if (!snaps[i])
                goto cleanup;
        }
        *snapshots = snaps;
        snaps = NULL;
    }

    rv = ret.ret;

cleanup:
    if (snaps) {
        for (i = 0; i < ret.snapshots.snapshots_len; i++)
            if (snaps[i])
                virDomainSnapshotFree(snaps[i]);
        VIR_FREE(snaps);
    }

    xdr_free((xdrproc_t) xdr_remote_domain_list_all_snapshots_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteDomainSnapshotListAllChildren(virDomainSnapshotPtr parent,
                                    virDomainSnapshotPtr **snapshots,
                                    unsigned int flags)
{
    int rv = -1;
    size_t i;
    virDomainSnapshotPtr *snaps = NULL;
    remote_domain_snapshot_list_all_children_args args;
    remote_domain_snapshot_list_all_children_ret ret;

    struct private_data *priv = parent->domain->conn->privateData;

    remoteDriverLock(priv);

    args.need_results = !!snapshots;
    args.flags = flags;
    make_nonnull_domain_snapshot(&args.snapshot, parent);

    memset(&ret, 0, sizeof(ret));
    if (call(parent->domain->conn,
             priv,
             0,
             REMOTE_PROC_DOMAIN_SNAPSHOT_LIST_ALL_CHILDREN,
             (xdrproc_t) xdr_remote_domain_snapshot_list_all_children_args,
             (char *) &args,
             (xdrproc_t) xdr_remote_domain_snapshot_list_all_children_ret,
             (char *) &ret) == -1)
        goto done;

    if (ret.snapshots.snapshots_len > REMOTE_DOMAIN_SNAPSHOT_LIST_MAX) {
        virReportError(VIR_ERR_RPC,
                       _("Too many domain snapshots '%d' for limit '%d'"),
                       ret.snapshots.snapshots_len,
                       REMOTE_DOMAIN_SNAPSHOT_LIST_MAX);
        goto cleanup;
    }

    if (snapshots) {
        if (VIR_ALLOC_N(snaps, ret.snapshots.snapshots_len + 1) < 0)
            goto cleanup;
        for (i = 0; i < ret.snapshots.snapshots_len; i++) {
            snaps[i] = get_nonnull_domain_snapshot(parent->domain, ret.snapshots.snapshots_val[i]);
            if (!snaps[i])
                goto cleanup;
        }
        *snapshots = snaps;
        snaps = NULL;
    }

    rv = ret.ret;

cleanup:
    if (snaps) {
        for (i = 0; i < ret.snapshots.snapshots_len; i++)
            if (snaps[i])
                virDomainSnapshotFree(snaps[i]);
        VIR_FREE(snaps);
    }

    xdr_free((xdrproc_t) xdr_remote_domain_snapshot_list_all_children_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteNodeGetMemoryParameters(virConnectPtr conn,
                              virTypedParameterPtr params,
                              int *nparams,
                              unsigned int flags)
{
    int rv = -1;
    remote_node_get_memory_parameters_args args;
    remote_node_get_memory_parameters_ret ret;
    struct private_data *priv = conn->privateData;

    remoteDriverLock(priv);

    args.nparams = *nparams;
    args.flags = flags;

    memset(&ret, 0, sizeof(ret));
    if (call(conn, priv, 0, REMOTE_PROC_NODE_GET_MEMORY_PARAMETERS,
             (xdrproc_t) xdr_remote_node_get_memory_parameters_args, (char *) &args,
             (xdrproc_t) xdr_remote_node_get_memory_parameters_ret, (char *) &ret) == -1)
        goto done;

    /* Handle the case when the caller does not know the number of parameters
     * and is asking for the number of parameters supported
     */
    if (*nparams == 0) {
        *nparams = ret.nparams;
        rv = 0;
        goto cleanup;
    }

    if (remoteDeserializeTypedParameters(ret.params.params_val,
                                         ret.params.params_len,
                                         REMOTE_NODE_MEMORY_PARAMETERS_MAX,
                                         &params,
                                         nparams) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    xdr_free((xdrproc_t) xdr_remote_node_get_memory_parameters_ret,
             (char *) &ret);
done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteNodeGetCPUMap(virConnectPtr conn,
                    unsigned char **cpumap,
                    unsigned int *online,
                    unsigned int flags)
{
    int rv = -1;
    remote_node_get_cpu_map_args args;
    remote_node_get_cpu_map_ret ret;
    struct private_data *priv = conn->privateData;

    remoteDriverLock(priv);

    args.need_map = !!cpumap;
    args.need_online = !!online;
    args.flags = flags;

    memset(&ret, 0, sizeof(ret));
    if (call(conn, priv, 0, REMOTE_PROC_NODE_GET_CPU_MAP,
             (xdrproc_t) xdr_remote_node_get_cpu_map_args,
             (char *) &args,
             (xdrproc_t) xdr_remote_node_get_cpu_map_ret,
             (char *) &ret) == -1)
        goto done;

    if (ret.ret < 0)
        goto cleanup;

    if (cpumap) {
        if (VIR_ALLOC_N(*cpumap, ret.cpumap.cpumap_len) < 0)
            goto cleanup;
        memcpy(*cpumap, ret.cpumap.cpumap_val, ret.cpumap.cpumap_len);
    }

    if (online)
        *online = ret.online;

    rv = ret.ret;

cleanup:
    xdr_free((xdrproc_t) xdr_remote_node_get_cpu_map_ret, (char *) &ret);
done:
    remoteDriverUnlock(priv);
    return rv;
}


static int
remoteDomainLxcOpenNamespace(virDomainPtr domain,
                             int **fdlist,
                             unsigned int flags)
{
    int rv = -1;
    lxc_domain_open_namespace_args args;
    struct private_data *priv = domain->conn->privateData;
    size_t nfds = 0;

    remoteDriverLock(priv);

    make_nonnull_domain(&args.dom, domain);
    args.flags = flags;

    *fdlist = NULL;

    if (callFull(domain->conn, priv, REMOTE_CALL_LXC,
                 NULL, 0,
                 fdlist, &nfds,
                 LXC_PROC_DOMAIN_OPEN_NAMESPACE,
                 (xdrproc_t) xdr_lxc_domain_open_namespace_args, (char *) &args,
                 (xdrproc_t) xdr_void, NULL) == -1)
        goto done;

    rv = nfds;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteDomainGetJobStats(virDomainPtr domain,
                        int *type,
                        virTypedParameterPtr *params,
                        int *nparams,
                        unsigned int flags)
{
    int rv = -1;
    remote_domain_get_job_stats_args args;
    remote_domain_get_job_stats_ret ret;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain(&args.dom, domain);
    args.flags = flags;

    memset(&ret, 0, sizeof(ret));
    if (call(domain->conn, priv, 0, REMOTE_PROC_DOMAIN_GET_JOB_STATS,
             (xdrproc_t) xdr_remote_domain_get_job_stats_args, (char *) &args,
             (xdrproc_t) xdr_remote_domain_get_job_stats_ret, (char *) &ret) == -1)
        goto done;

    if (ret.params.params_len > REMOTE_DOMAIN_JOB_STATS_MAX) {
        virReportError(VIR_ERR_RPC,
                       _("Too many job stats '%d' for limit '%d'"),
                       ret.params.params_len,
                       REMOTE_DOMAIN_JOB_STATS_MAX);
        goto cleanup;
    }

    *type = ret.type;

    if (remoteDeserializeTypedParameters(ret.params.params_val,
                                         ret.params.params_len,
                                         0, params, nparams) < 0)
        goto cleanup;

    rv = 0;

cleanup:
    xdr_free((xdrproc_t) xdr_remote_domain_get_job_stats_ret,
             (char *) &ret);
done:
    remoteDriverUnlock(priv);
    return rv;
}


static char *
remoteDomainMigrateBegin3Params(virDomainPtr domain,
                                virTypedParameterPtr params,
                                int nparams,
                                char **cookieout,
                                int *cookieoutlen,
                                unsigned int flags)
{
    char *rv = NULL;
    remote_domain_migrate_begin3_params_args args;
    remote_domain_migrate_begin3_params_ret ret;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    memset(&args, 0, sizeof(args));
    memset(&ret, 0, sizeof(ret));

    make_nonnull_domain(&args.dom, domain);
    args.flags = flags;

    if (nparams > REMOTE_DOMAIN_MIGRATE_PARAM_LIST_MAX) {
        virReportError(VIR_ERR_RPC,
                       _("Too many migration parameters '%d' for limit '%d'"),
                       nparams, REMOTE_DOMAIN_MIGRATE_PARAM_LIST_MAX);
        goto cleanup;
    }

    if (remoteSerializeTypedParameters(params, nparams,
                                       &args.params.params_val,
                                       &args.params.params_len) < 0) {
        xdr_free((xdrproc_t) xdr_remote_domain_migrate_begin3_params_args,
                 (char *) &args);
        goto cleanup;
    }

    if (call(domain->conn, priv, 0, REMOTE_PROC_DOMAIN_MIGRATE_BEGIN3_PARAMS,
             (xdrproc_t) xdr_remote_domain_migrate_begin3_params_args,
             (char *) &args,
             (xdrproc_t) xdr_remote_domain_migrate_begin3_params_ret,
             (char *) &ret) == -1)
        goto cleanup;

    if (ret.cookie_out.cookie_out_len > 0) {
        if (!cookieout || !cookieoutlen) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("caller ignores cookieout or cookieoutlen"));
            goto error;
        }
        *cookieout = ret.cookie_out.cookie_out_val; /* Caller frees. */
        *cookieoutlen = ret.cookie_out.cookie_out_len;
    }

    rv = ret.xml; /* caller frees */

cleanup:
    remoteFreeTypedParameters(args.params.params_val, args.params.params_len);
    remoteDriverUnlock(priv);
    return rv;

error:
    VIR_FREE(ret.cookie_out.cookie_out_val);
    goto cleanup;
}


static int
remoteDomainMigratePrepare3Params(virConnectPtr dconn,
                                  virTypedParameterPtr params,
                                  int nparams,
                                  const char *cookiein,
                                  int cookieinlen,
                                  char **cookieout,
                                  int *cookieoutlen,
                                  char **uri_out,
                                  unsigned int flags)
{
    int rv = -1;
    remote_domain_migrate_prepare3_params_args args;
    remote_domain_migrate_prepare3_params_ret ret;
    struct private_data *priv = dconn->privateData;

    remoteDriverLock(priv);

    memset(&args, 0, sizeof(args));
    memset(&ret, 0, sizeof(ret));

    if (nparams > REMOTE_DOMAIN_MIGRATE_PARAM_LIST_MAX) {
        virReportError(VIR_ERR_RPC,
                       _("Too many migration parameters '%d' for limit '%d'"),
                       nparams, REMOTE_DOMAIN_MIGRATE_PARAM_LIST_MAX);
        goto cleanup;
    }

    if (remoteSerializeTypedParameters(params, nparams,
                                       &args.params.params_val,
                                       &args.params.params_len) < 0) {
        xdr_free((xdrproc_t) xdr_remote_domain_migrate_prepare3_params_args,
                 (char *) &args);
        goto cleanup;
    }

    args.cookie_in.cookie_in_val = (char *)cookiein;
    args.cookie_in.cookie_in_len = cookieinlen;
    args.flags = flags;

    if (call(dconn, priv, 0, REMOTE_PROC_DOMAIN_MIGRATE_PREPARE3_PARAMS,
             (xdrproc_t) xdr_remote_domain_migrate_prepare3_params_args,
             (char *) &args,
             (xdrproc_t) xdr_remote_domain_migrate_prepare3_params_ret,
             (char *) &ret) == -1)
        goto cleanup;

    if (ret.cookie_out.cookie_out_len > 0) {
        if (!cookieout || !cookieoutlen) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("caller ignores cookieout or cookieoutlen"));
            goto error;
        }
        *cookieout = ret.cookie_out.cookie_out_val; /* Caller frees. */
        *cookieoutlen = ret.cookie_out.cookie_out_len;
    }
    if (ret.uri_out) {
        if (!uri_out) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("caller ignores uri_out"));
            goto error;
        }
        *uri_out = *ret.uri_out; /* Caller frees. */
    }

    rv = 0;

cleanup:
    remoteFreeTypedParameters(args.params.params_val, args.params.params_len);
    VIR_FREE(ret.uri_out);
    remoteDriverUnlock(priv);
    return rv;

error:
    VIR_FREE(ret.cookie_out.cookie_out_val);
    if (ret.uri_out)
        VIR_FREE(*ret.uri_out);
    goto cleanup;
}


static int
remoteDomainMigratePrepareTunnel3Params(virConnectPtr dconn,
                                        virStreamPtr st,
                                        virTypedParameterPtr params,
                                        int nparams,
                                        const char *cookiein,
                                        int cookieinlen,
                                        char **cookieout,
                                        int *cookieoutlen,
                                        unsigned int flags)
{
    struct private_data *priv = dconn->privateData;
    int rv = -1;
    remote_domain_migrate_prepare_tunnel3_params_args args;
    remote_domain_migrate_prepare_tunnel3_params_ret ret;
    virNetClientStreamPtr netst;

    remoteDriverLock(priv);

    memset(&args, 0, sizeof(args));
    memset(&ret, 0, sizeof(ret));

    if (nparams > REMOTE_DOMAIN_MIGRATE_PARAM_LIST_MAX) {
        virReportError(VIR_ERR_RPC,
                       _("Too many migration parameters '%d' for limit '%d'"),
                       nparams, REMOTE_DOMAIN_MIGRATE_PARAM_LIST_MAX);
        goto cleanup;
    }

    args.cookie_in.cookie_in_val = (char *)cookiein;
    args.cookie_in.cookie_in_len = cookieinlen;
    args.flags = flags;

    if (remoteSerializeTypedParameters(params, nparams,
                                       &args.params.params_val,
                                       &args.params.params_len) < 0) {
        xdr_free((xdrproc_t) xdr_remote_domain_migrate_prepare_tunnel3_params_args,
                 (char *) &args);
        goto cleanup;
    }

    if (!(netst = virNetClientStreamNew(priv->remoteProgram,
                                        REMOTE_PROC_DOMAIN_MIGRATE_PREPARE_TUNNEL3_PARAMS,
                                        priv->counter)))
        goto cleanup;

    if (virNetClientAddStream(priv->client, netst) < 0) {
        virObjectUnref(netst);
        goto cleanup;
    }

    st->driver = &remoteStreamDrv;
    st->privateData = netst;

    if (call(dconn, priv, 0, REMOTE_PROC_DOMAIN_MIGRATE_PREPARE_TUNNEL3_PARAMS,
             (xdrproc_t) xdr_remote_domain_migrate_prepare_tunnel3_params_args,
             (char *) &args,
             (xdrproc_t) xdr_remote_domain_migrate_prepare_tunnel3_params_ret,
             (char *) &ret) == -1) {
        virNetClientRemoveStream(priv->client, netst);
        virObjectUnref(netst);
        goto cleanup;
    }

    if (ret.cookie_out.cookie_out_len > 0) {
        if (!cookieout || !cookieoutlen) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("caller ignores cookieout or cookieoutlen"));
            goto error;
        }
        *cookieout = ret.cookie_out.cookie_out_val; /* Caller frees. */
        *cookieoutlen = ret.cookie_out.cookie_out_len;
    }

    rv = 0;

cleanup:
    remoteFreeTypedParameters(args.params.params_val, args.params.params_len);
    remoteDriverUnlock(priv);
    return rv;

error:
    VIR_FREE(ret.cookie_out.cookie_out_val);
    goto cleanup;
}


static int
remoteDomainMigratePerform3Params(virDomainPtr dom,
                                  const char *dconnuri,
                                  virTypedParameterPtr params,
                                  int nparams,
                                  const char *cookiein,
                                  int cookieinlen,
                                  char **cookieout,
                                  int *cookieoutlen,
                                  unsigned int flags)
{
    int rv = -1;
    remote_domain_migrate_perform3_params_args args;
    remote_domain_migrate_perform3_params_ret ret;
    struct private_data *priv = dom->conn->privateData;

    remoteDriverLock(priv);

    memset(&args, 0, sizeof(args));
    memset(&ret, 0, sizeof(ret));

    if (nparams > REMOTE_DOMAIN_MIGRATE_PARAM_LIST_MAX) {
        virReportError(VIR_ERR_RPC,
                       _("Too many migration parameters '%d' for limit '%d'"),
                       nparams, REMOTE_DOMAIN_MIGRATE_PARAM_LIST_MAX);
        goto cleanup;
    }

    make_nonnull_domain(&args.dom, dom);
    args.dconnuri = dconnuri == NULL ? NULL : (char **) &dconnuri;
    args.cookie_in.cookie_in_val = (char *)cookiein;
    args.cookie_in.cookie_in_len = cookieinlen;
    args.flags = flags;

    if (remoteSerializeTypedParameters(params, nparams,
                                       &args.params.params_val,
                                       &args.params.params_len) < 0) {
        xdr_free((xdrproc_t) xdr_remote_domain_migrate_perform3_params_args,
                 (char *) &args);
        goto cleanup;
    }

    if (call(dom->conn, priv, 0, REMOTE_PROC_DOMAIN_MIGRATE_PERFORM3_PARAMS,
             (xdrproc_t) xdr_remote_domain_migrate_perform3_params_args,
             (char *) &args,
             (xdrproc_t) xdr_remote_domain_migrate_perform3_params_ret,
             (char *) &ret) == -1)
        goto cleanup;

    if (ret.cookie_out.cookie_out_len > 0) {
        if (!cookieout || !cookieoutlen) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("caller ignores cookieout or cookieoutlen"));
            goto error;
        }
        *cookieout = ret.cookie_out.cookie_out_val; /* Caller frees. */
        *cookieoutlen = ret.cookie_out.cookie_out_len;
    }

    rv = 0;

cleanup:
    remoteFreeTypedParameters(args.params.params_val, args.params.params_len);
    remoteDriverUnlock(priv);
    return rv;

error:
    VIR_FREE(ret.cookie_out.cookie_out_val);
    goto cleanup;
}


static virDomainPtr
remoteDomainMigrateFinish3Params(virConnectPtr dconn,
                                 virTypedParameterPtr params,
                                 int nparams,
                                 const char *cookiein,
                                 int cookieinlen,
                                 char **cookieout,
                                 int *cookieoutlen,
                                 unsigned int flags,
                                 int cancelled)
{
    remote_domain_migrate_finish3_params_args args;
    remote_domain_migrate_finish3_params_ret ret;
    struct private_data *priv = dconn->privateData;
    virDomainPtr rv = NULL;

    remoteDriverLock(priv);

    memset(&args, 0, sizeof(args));
    memset(&ret, 0, sizeof(ret));

    if (nparams > REMOTE_DOMAIN_MIGRATE_PARAM_LIST_MAX) {
        virReportError(VIR_ERR_RPC,
                       _("Too many migration parameters '%d' for limit '%d'"),
                       nparams, REMOTE_DOMAIN_MIGRATE_PARAM_LIST_MAX);
        goto cleanup;
    }

    args.cookie_in.cookie_in_val = (char *)cookiein;
    args.cookie_in.cookie_in_len = cookieinlen;
    args.flags = flags;
    args.cancelled = cancelled;

    if (remoteSerializeTypedParameters(params, nparams,
                                       &args.params.params_val,
                                       &args.params.params_len) < 0) {
        xdr_free((xdrproc_t) xdr_remote_domain_migrate_finish3_params_args,
                 (char *) &args);
        goto cleanup;
    }

    if (call(dconn, priv, 0, REMOTE_PROC_DOMAIN_MIGRATE_FINISH3_PARAMS,
             (xdrproc_t) xdr_remote_domain_migrate_finish3_params_args,
             (char *) &args,
             (xdrproc_t) xdr_remote_domain_migrate_finish3_params_ret,
             (char *) &ret) == -1)
        goto cleanup;

    rv = get_nonnull_domain(dconn, ret.dom);

    if (ret.cookie_out.cookie_out_len > 0) {
        if (!cookieout || !cookieoutlen) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("caller ignores cookieout or cookieoutlen"));
            goto error;
        }
        *cookieout = ret.cookie_out.cookie_out_val; /* Caller frees. */
        *cookieoutlen = ret.cookie_out.cookie_out_len;
        ret.cookie_out.cookie_out_val = NULL;
        ret.cookie_out.cookie_out_len = 0;
    }

    xdr_free((xdrproc_t) &xdr_remote_domain_migrate_finish3_params_ret,
             (char *) &ret);

cleanup:
    remoteFreeTypedParameters(args.params.params_val, args.params.params_len);
    remoteDriverUnlock(priv);
    return rv;

error:
    VIR_FREE(ret.cookie_out.cookie_out_val);
    goto cleanup;
}


static int
remoteDomainMigrateConfirm3Params(virDomainPtr domain,
                                  virTypedParameterPtr params,
                                  int nparams,
                                  const char *cookiein,
                                  int cookieinlen,
                                  unsigned int flags,
                                  int cancelled)
{
    int rv = -1;
    remote_domain_migrate_confirm3_params_args args;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    memset(&args, 0, sizeof(args));

    if (nparams > REMOTE_DOMAIN_MIGRATE_PARAM_LIST_MAX) {
        virReportError(VIR_ERR_RPC,
                       _("Too many migration parameters '%d' for limit '%d'"),
                       nparams, REMOTE_DOMAIN_MIGRATE_PARAM_LIST_MAX);
        goto cleanup;
    }

    make_nonnull_domain(&args.dom, domain);
    args.cookie_in.cookie_in_len = cookieinlen;
    args.cookie_in.cookie_in_val = (char *) cookiein;
    args.flags = flags;
    args.cancelled = cancelled;

    if (remoteSerializeTypedParameters(params, nparams,
                                       &args.params.params_val,
                                       &args.params.params_len) < 0) {
        xdr_free((xdrproc_t) xdr_remote_domain_migrate_confirm3_params_args,
                 (char *) &args);
        goto cleanup;
    }

    if (call(domain->conn, priv, 0, REMOTE_PROC_DOMAIN_MIGRATE_CONFIRM3_PARAMS,
             (xdrproc_t) xdr_remote_domain_migrate_confirm3_params_args,
             (char *) &args, (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto cleanup;

    rv = 0;

cleanup:
    remoteFreeTypedParameters(args.params.params_val, args.params.params_len);
    remoteDriverUnlock(priv);
    return rv;
}


static virDomainPtr
remoteDomainCreateXMLWithFiles(virConnectPtr conn, const char *xml_desc,
                               unsigned int nfiles, int *files, unsigned int flags)
{
    virDomainPtr rv = NULL;
    struct private_data *priv = conn->privateData;
    remote_domain_create_xml_with_files_args args;
    remote_domain_create_xml_with_files_ret ret;

    remoteDriverLock(priv);

    args.xml_desc = (char *)xml_desc;
    args.flags = flags;

    memset(&ret, 0, sizeof(ret));

    if (callFull(conn, priv, 0,
                 files, nfiles,
                 NULL, NULL,
                 REMOTE_PROC_DOMAIN_CREATE_XML_WITH_FILES,
                 (xdrproc_t)xdr_remote_domain_create_xml_with_files_args, (char *)&args,
                 (xdrproc_t)xdr_remote_domain_create_xml_with_files_ret, (char *)&ret) == -1) {
        goto done;
    }

    rv = get_nonnull_domain(conn, ret.dom);
    xdr_free((xdrproc_t)xdr_remote_domain_create_xml_with_files_ret, (char *)&ret);

done:
    remoteDriverUnlock(priv);
    return rv;
}


static int
remoteDomainCreateWithFiles(virDomainPtr dom,
                            unsigned int nfiles, int *files,
                            unsigned int flags)
{
    int rv = -1;
    struct private_data *priv = dom->conn->privateData;
    remote_domain_create_with_files_args args;
    remote_domain_create_with_files_ret ret;

    remoteDriverLock(priv);

    make_nonnull_domain(&args.dom, dom);
    args.flags = flags;

    memset(&ret, 0, sizeof(ret));

    if (callFull(dom->conn, priv, 0,
                 files, nfiles,
                 NULL, NULL,
                 REMOTE_PROC_DOMAIN_CREATE_WITH_FILES,
                 (xdrproc_t)xdr_remote_domain_create_with_files_args, (char *)&args,
                 (xdrproc_t)xdr_remote_domain_create_with_files_ret, (char *)&ret) == -1) {
        goto done;
    }

    dom->id = ret.dom.id;
    xdr_free((xdrproc_t) &xdr_remote_domain_create_with_files_ret, (char *) &ret);
    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static void
remoteDomainEventQueue(struct private_data *priv, virDomainEventPtr event)
{
    virDomainEventStateQueue(priv->domainEventState, event);
}

/* get_nonnull_domain and get_nonnull_network turn an on-wire
 * (name, uuid) pair into virDomainPtr or virNetworkPtr object.
 * These can return NULL if underlying memory allocations fail,
 * but if they do then virterror_internal.has been set.
 */
static virDomainPtr
get_nonnull_domain(virConnectPtr conn, remote_nonnull_domain domain)
{
    virDomainPtr dom;
    dom = virGetDomain(conn, domain.name, BAD_CAST domain.uuid);
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
    return virGetStoragePool(conn, pool.name, BAD_CAST pool.uuid,
                             NULL, NULL);
}

static virStorageVolPtr
get_nonnull_storage_vol(virConnectPtr conn, remote_nonnull_storage_vol vol)
{
    return virGetStorageVol(conn, vol.pool, vol.name, vol.key,
                            NULL, NULL);
}

static virNodeDevicePtr
get_nonnull_node_device(virConnectPtr conn, remote_nonnull_node_device dev)
{
    return virGetNodeDevice(conn, dev.name);
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
get_nonnull_domain_snapshot(virDomainPtr domain, remote_nonnull_domain_snapshot snapshot)
{
    return virGetDomainSnapshot(domain, snapshot.name);
}


/* Make remote_nonnull_domain and remote_nonnull_network. */
static void
make_nonnull_domain(remote_nonnull_domain *dom_dst, virDomainPtr dom_src)
{
    dom_dst->id = dom_src->id;
    dom_dst->name = dom_src->name;
    memcpy(dom_dst->uuid, dom_src->uuid, VIR_UUID_BUFLEN);
}

static void
make_nonnull_network(remote_nonnull_network *net_dst, virNetworkPtr net_src)
{
    net_dst->name = net_src->name;
    memcpy(net_dst->uuid, net_src->uuid, VIR_UUID_BUFLEN);
}

static void
make_nonnull_interface(remote_nonnull_interface *interface_dst,
                        virInterfacePtr interface_src)
{
    interface_dst->name = interface_src->name;
    interface_dst->mac = interface_src->mac;
}

static void
make_nonnull_storage_pool(remote_nonnull_storage_pool *pool_dst, virStoragePoolPtr pool_src)
{
    pool_dst->name = pool_src->name;
    memcpy(pool_dst->uuid, pool_src->uuid, VIR_UUID_BUFLEN);
}

static void
make_nonnull_storage_vol(remote_nonnull_storage_vol *vol_dst, virStorageVolPtr vol_src)
{
    vol_dst->pool = vol_src->pool;
    vol_dst->name = vol_src->name;
    vol_dst->key = vol_src->key;
}

static void
make_nonnull_secret(remote_nonnull_secret *secret_dst, virSecretPtr secret_src)
{
    memcpy(secret_dst->uuid, secret_src->uuid, VIR_UUID_BUFLEN);
    secret_dst->usageType = secret_src->usageType;
    secret_dst->usageID = secret_src->usageID;
}

static void
make_nonnull_nwfilter(remote_nonnull_nwfilter *nwfilter_dst, virNWFilterPtr nwfilter_src)
{
    nwfilter_dst->name = nwfilter_src->name;
    memcpy(nwfilter_dst->uuid, nwfilter_src->uuid, VIR_UUID_BUFLEN);
}

static void
make_nonnull_domain_snapshot(remote_nonnull_domain_snapshot *snapshot_dst, virDomainSnapshotPtr snapshot_src)
{
    snapshot_dst->name = snapshot_src->name;
    make_nonnull_domain(&snapshot_dst->dom, snapshot_src->domain);
}

/*----------------------------------------------------------------------*/

unsigned long remoteVersion(void)
{
    return REMOTE_PROTOCOL_VERSION;
}

static virDriver remote_driver = {
    .no = VIR_DRV_REMOTE,
    .name = "remote",
    .connectOpen = remoteConnectOpen, /* 0.3.0 */
    .connectClose = remoteConnectClose, /* 0.3.0 */
    .connectSupportsFeature = remoteConnectSupportsFeature, /* 0.3.0 */
    .connectGetType = remoteConnectGetType, /* 0.3.0 */
    .connectGetVersion = remoteConnectGetVersion, /* 0.3.0 */
    .connectGetLibVersion = remoteConnectGetLibVersion, /* 0.7.3 */
    .connectGetHostname = remoteConnectGetHostname, /* 0.3.0 */
    .connectGetSysinfo = remoteConnectGetSysinfo, /* 0.8.8 */
    .connectGetMaxVcpus = remoteConnectGetMaxVcpus, /* 0.3.0 */
    .nodeGetInfo = remoteNodeGetInfo, /* 0.3.0 */
    .connectGetCapabilities = remoteConnectGetCapabilities, /* 0.3.0 */
    .connectListDomains = remoteConnectListDomains, /* 0.3.0 */
    .connectNumOfDomains = remoteConnectNumOfDomains, /* 0.3.0 */
    .connectListAllDomains = remoteConnectListAllDomains, /* 0.9.13 */
    .domainCreateXML = remoteDomainCreateXML, /* 0.3.0 */
    .domainCreateXMLWithFiles = remoteDomainCreateXMLWithFiles, /* 1.1.1 */
    .domainLookupByID = remoteDomainLookupByID, /* 0.3.0 */
    .domainLookupByUUID = remoteDomainLookupByUUID, /* 0.3.0 */
    .domainLookupByName = remoteDomainLookupByName, /* 0.3.0 */
    .domainSuspend = remoteDomainSuspend, /* 0.3.0 */
    .domainResume = remoteDomainResume, /* 0.3.0 */
    .domainPMSuspendForDuration = remoteDomainPMSuspendForDuration, /* 0.9.10 */
    .domainPMWakeup = remoteDomainPMWakeup, /* 0.9.11 */
    .domainShutdown = remoteDomainShutdown, /* 0.3.0 */
    .domainShutdownFlags = remoteDomainShutdownFlags, /* 0.9.10 */
    .domainReboot = remoteDomainReboot, /* 0.3.0 */
    .domainReset = remoteDomainReset, /* 0.9.7 */
    .domainDestroy = remoteDomainDestroy, /* 0.3.0 */
    .domainDestroyFlags = remoteDomainDestroyFlags, /* 0.9.4 */
    .domainGetOSType = remoteDomainGetOSType, /* 0.3.0 */
    .domainGetMaxMemory = remoteDomainGetMaxMemory, /* 0.3.0 */
    .domainSetMaxMemory = remoteDomainSetMaxMemory, /* 0.3.0 */
    .domainSetMemory = remoteDomainSetMemory, /* 0.3.0 */
    .domainSetMemoryFlags = remoteDomainSetMemoryFlags, /* 0.9.0 */
    .domainSetMemoryStatsPeriod = remoteDomainSetMemoryStatsPeriod, /* 1.1.1 */
    .domainSetMemoryParameters = remoteDomainSetMemoryParameters, /* 0.8.5 */
    .domainGetMemoryParameters = remoteDomainGetMemoryParameters, /* 0.8.5 */
    .domainSetBlkioParameters = remoteDomainSetBlkioParameters, /* 0.9.0 */
    .domainGetBlkioParameters = remoteDomainGetBlkioParameters, /* 0.9.0 */
    .domainGetInfo = remoteDomainGetInfo, /* 0.3.0 */
    .domainGetState = remoteDomainGetState, /* 0.9.2 */
    .domainGetControlInfo = remoteDomainGetControlInfo, /* 0.9.3 */
    .domainSave = remoteDomainSave, /* 0.3.0 */
    .domainSaveFlags = remoteDomainSaveFlags, /* 0.9.4 */
    .domainRestore = remoteDomainRestore, /* 0.3.0 */
    .domainRestoreFlags = remoteDomainRestoreFlags, /* 0.9.4 */
    .domainSaveImageGetXMLDesc = remoteDomainSaveImageGetXMLDesc, /* 0.9.4 */
    .domainSaveImageDefineXML = remoteDomainSaveImageDefineXML, /* 0.9.4 */
    .domainCoreDump = remoteDomainCoreDump, /* 0.3.0 */
    .domainScreenshot = remoteDomainScreenshot, /* 0.9.2 */
    .domainSetVcpus = remoteDomainSetVcpus, /* 0.3.0 */
    .domainSetVcpusFlags = remoteDomainSetVcpusFlags, /* 0.8.5 */
    .domainGetVcpusFlags = remoteDomainGetVcpusFlags, /* 0.8.5 */
    .domainPinVcpu = remoteDomainPinVcpu, /* 0.3.0 */
    .domainPinVcpuFlags = remoteDomainPinVcpuFlags, /* 0.9.3 */
    .domainGetVcpuPinInfo = remoteDomainGetVcpuPinInfo, /* 0.9.3 */
    .domainPinEmulator = remoteDomainPinEmulator, /* 0.10.0 */
    .domainGetEmulatorPinInfo = remoteDomainGetEmulatorPinInfo, /* 0.10.0 */
    .domainGetVcpus = remoteDomainGetVcpus, /* 0.3.0 */
    .domainGetMaxVcpus = remoteDomainGetMaxVcpus, /* 0.3.0 */
    .domainGetSecurityLabel = remoteDomainGetSecurityLabel, /* 0.6.1 */
    .domainGetSecurityLabelList = remoteDomainGetSecurityLabelList, /* 0.10.0 */
    .nodeGetSecurityModel = remoteNodeGetSecurityModel, /* 0.6.1 */
    .domainGetXMLDesc = remoteDomainGetXMLDesc, /* 0.3.0 */
    .connectDomainXMLFromNative = remoteConnectDomainXMLFromNative, /* 0.6.4 */
    .connectDomainXMLToNative = remoteConnectDomainXMLToNative, /* 0.6.4 */
    .connectListDefinedDomains = remoteConnectListDefinedDomains, /* 0.3.0 */
    .connectNumOfDefinedDomains = remoteConnectNumOfDefinedDomains, /* 0.3.0 */
    .domainCreate = remoteDomainCreate, /* 0.3.0 */
    .domainCreateWithFlags = remoteDomainCreateWithFlags, /* 0.8.2 */
    .domainCreateWithFiles = remoteDomainCreateWithFiles, /* 1.1.1 */
    .domainDefineXML = remoteDomainDefineXML, /* 0.3.0 */
    .domainUndefine = remoteDomainUndefine, /* 0.3.0 */
    .domainUndefineFlags = remoteDomainUndefineFlags, /* 0.9.4 */
    .domainAttachDevice = remoteDomainAttachDevice, /* 0.3.0 */
    .domainAttachDeviceFlags = remoteDomainAttachDeviceFlags, /* 0.7.7 */
    .domainDetachDevice = remoteDomainDetachDevice, /* 0.3.0 */
    .domainDetachDeviceFlags = remoteDomainDetachDeviceFlags, /* 0.7.7 */
    .domainUpdateDeviceFlags = remoteDomainUpdateDeviceFlags, /* 0.8.0 */
    .domainGetAutostart = remoteDomainGetAutostart, /* 0.3.0 */
    .domainSetAutostart = remoteDomainSetAutostart, /* 0.3.0 */
    .domainGetSchedulerType = remoteDomainGetSchedulerType, /* 0.3.0 */
    .domainGetSchedulerParameters = remoteDomainGetSchedulerParameters, /* 0.3.0 */
    .domainGetSchedulerParametersFlags = remoteDomainGetSchedulerParametersFlags, /* 0.9.2 */
    .domainSetSchedulerParameters = remoteDomainSetSchedulerParameters, /* 0.3.0 */
    .domainSetSchedulerParametersFlags = remoteDomainSetSchedulerParametersFlags, /* 0.9.2 */
    .domainMigratePrepare = remoteDomainMigratePrepare, /* 0.3.2 */
    .domainMigratePerform = remoteDomainMigratePerform, /* 0.3.2 */
    .domainMigrateFinish = remoteDomainMigrateFinish, /* 0.3.2 */
    .domainBlockResize = remoteDomainBlockResize, /* 0.9.8 */
    .domainBlockStats = remoteDomainBlockStats, /* 0.3.2 */
    .domainBlockStatsFlags = remoteDomainBlockStatsFlags, /* 0.9.5 */
    .domainInterfaceStats = remoteDomainInterfaceStats, /* 0.3.2 */
    .domainSetInterfaceParameters = remoteDomainSetInterfaceParameters, /* 0.9.9 */
    .domainGetInterfaceParameters = remoteDomainGetInterfaceParameters, /* 0.9.9 */
    .domainMemoryStats = remoteDomainMemoryStats, /* 0.7.5 */
    .domainBlockPeek = remoteDomainBlockPeek, /* 0.4.2 */
    .domainMemoryPeek = remoteDomainMemoryPeek, /* 0.4.2 */
    .domainGetBlockInfo = remoteDomainGetBlockInfo, /* 0.8.1 */
    .nodeGetCPUStats = remoteNodeGetCPUStats, /* 0.9.3 */
    .nodeGetMemoryStats = remoteNodeGetMemoryStats, /* 0.9.3 */
    .nodeGetCellsFreeMemory = remoteNodeGetCellsFreeMemory, /* 0.3.3 */
    .nodeGetFreeMemory = remoteNodeGetFreeMemory, /* 0.3.3 */
    .connectDomainEventRegister = remoteConnectDomainEventRegister, /* 0.5.0 */
    .connectDomainEventDeregister = remoteConnectDomainEventDeregister, /* 0.5.0 */
    .domainMigratePrepare2 = remoteDomainMigratePrepare2, /* 0.5.0 */
    .domainMigrateFinish2 = remoteDomainMigrateFinish2, /* 0.5.0 */
    .nodeDeviceDettach = remoteNodeDeviceDettach, /* 0.6.1 */
    .nodeDeviceDetachFlags = remoteNodeDeviceDetachFlags, /* 1.0.5 */
    .nodeDeviceReAttach = remoteNodeDeviceReAttach, /* 0.6.1 */
    .nodeDeviceReset = remoteNodeDeviceReset, /* 0.6.1 */
    .domainMigratePrepareTunnel = remoteDomainMigratePrepareTunnel, /* 0.7.2 */
    .connectIsEncrypted = remoteConnectIsEncrypted, /* 0.7.3 */
    .connectIsSecure = remoteConnectIsSecure, /* 0.7.3 */
    .domainIsActive = remoteDomainIsActive, /* 0.7.3 */
    .domainIsPersistent = remoteDomainIsPersistent, /* 0.7.3 */
    .domainIsUpdated = remoteDomainIsUpdated, /* 0.8.6 */
    .connectCompareCPU = remoteConnectCompareCPU, /* 0.7.5 */
    .connectBaselineCPU = remoteConnectBaselineCPU, /* 0.7.7 */
    .domainGetJobInfo = remoteDomainGetJobInfo, /* 0.7.7 */
    .domainGetJobStats = remoteDomainGetJobStats, /* 1.0.3 */
    .domainAbortJob = remoteDomainAbortJob, /* 0.7.7 */
    .domainMigrateSetMaxDowntime = remoteDomainMigrateSetMaxDowntime, /* 0.8.0 */
    .domainMigrateGetCompressionCache = remoteDomainMigrateGetCompressionCache, /* 1.0.3 */
    .domainMigrateSetCompressionCache = remoteDomainMigrateSetCompressionCache, /* 1.0.3 */
    .domainMigrateSetMaxSpeed = remoteDomainMigrateSetMaxSpeed, /* 0.9.0 */
    .domainMigrateGetMaxSpeed = remoteDomainMigrateGetMaxSpeed, /* 0.9.5 */
    .connectDomainEventRegisterAny = remoteConnectDomainEventRegisterAny, /* 0.8.0 */
    .connectDomainEventDeregisterAny = remoteConnectDomainEventDeregisterAny, /* 0.8.0 */
    .domainManagedSave = remoteDomainManagedSave, /* 0.8.0 */
    .domainHasManagedSaveImage = remoteDomainHasManagedSaveImage, /* 0.8.0 */
    .domainManagedSaveRemove = remoteDomainManagedSaveRemove, /* 0.8.0 */
    .domainSnapshotCreateXML = remoteDomainSnapshotCreateXML, /* 0.8.0 */
    .domainSnapshotGetXMLDesc = remoteDomainSnapshotGetXMLDesc, /* 0.8.0 */
    .domainSnapshotNum = remoteDomainSnapshotNum, /* 0.8.0 */
    .domainSnapshotListNames = remoteDomainSnapshotListNames, /* 0.8.0 */
    .domainListAllSnapshots = remoteDomainListAllSnapshots, /* 0.9.13 */
    .domainSnapshotNumChildren = remoteDomainSnapshotNumChildren, /* 0.9.7 */
    .domainSnapshotListAllChildren = remoteDomainSnapshotListAllChildren, /* 0.9.13 */
    .domainSnapshotListChildrenNames = remoteDomainSnapshotListChildrenNames, /* 0.9.7 */
    .domainSnapshotLookupByName = remoteDomainSnapshotLookupByName, /* 0.8.0 */
    .domainHasCurrentSnapshot = remoteDomainHasCurrentSnapshot, /* 0.8.0 */
    .domainSnapshotGetParent = remoteDomainSnapshotGetParent, /* 0.9.7 */
    .domainSnapshotCurrent = remoteDomainSnapshotCurrent, /* 0.8.0 */
    .domainRevertToSnapshot = remoteDomainRevertToSnapshot, /* 0.8.0 */
    .domainSnapshotIsCurrent = remoteDomainSnapshotIsCurrent, /* 0.9.13 */
    .domainSnapshotHasMetadata = remoteDomainSnapshotHasMetadata, /* 0.9.13 */
    .domainSnapshotDelete = remoteDomainSnapshotDelete, /* 0.8.0 */
    .domainQemuMonitorCommand = remoteDomainQemuMonitorCommand, /* 0.8.3 */
    .domainQemuAttach = remoteDomainQemuAttach, /* 0.9.4 */
    .domainQemuAgentCommand = remoteDomainQemuAgentCommand, /* 0.10.0 */
    .domainOpenConsole = remoteDomainOpenConsole, /* 0.8.6 */
    .domainOpenChannel = remoteDomainOpenChannel, /* 1.0.2 */
    .domainOpenGraphics = remoteDomainOpenGraphics, /* 0.9.7 */
    .domainInjectNMI = remoteDomainInjectNMI, /* 0.9.2 */
    .domainMigrateBegin3 = remoteDomainMigrateBegin3, /* 0.9.2 */
    .domainMigratePrepare3 = remoteDomainMigratePrepare3, /* 0.9.2 */
    .domainMigratePrepareTunnel3 = remoteDomainMigratePrepareTunnel3, /* 0.9.2 */
    .domainMigratePerform3 = remoteDomainMigratePerform3, /* 0.9.2 */
    .domainMigrateFinish3 = remoteDomainMigrateFinish3, /* 0.9.2 */
    .domainMigrateConfirm3 = remoteDomainMigrateConfirm3, /* 0.9.2 */
    .domainSendKey = remoteDomainSendKey, /* 0.9.3 */
    .domainSendProcessSignal = remoteDomainSendProcessSignal, /* 1.0.1 */
    .domainBlockJobAbort = remoteDomainBlockJobAbort, /* 0.9.4 */
    .domainGetBlockJobInfo = remoteDomainGetBlockJobInfo, /* 0.9.4 */
    .domainBlockJobSetSpeed = remoteDomainBlockJobSetSpeed, /* 0.9.4 */
    .domainBlockPull = remoteDomainBlockPull, /* 0.9.4 */
    .domainBlockRebase = remoteDomainBlockRebase, /* 0.9.10 */
    .domainBlockCommit = remoteDomainBlockCommit, /* 0.10.2 */
    .connectSetKeepAlive = remoteConnectSetKeepAlive, /* 0.9.8 */
    .connectIsAlive = remoteConnectIsAlive, /* 0.9.8 */
    .nodeSuspendForDuration = remoteNodeSuspendForDuration, /* 0.9.8 */
    .domainSetBlockIoTune = remoteDomainSetBlockIoTune, /* 0.9.8 */
    .domainGetBlockIoTune = remoteDomainGetBlockIoTune, /* 0.9.8 */
    .domainSetNumaParameters = remoteDomainSetNumaParameters, /* 0.9.9 */
    .domainGetNumaParameters = remoteDomainGetNumaParameters, /* 0.9.9 */
    .domainGetCPUStats = remoteDomainGetCPUStats, /* 0.9.10 */
    .domainGetDiskErrors = remoteDomainGetDiskErrors, /* 0.9.10 */
    .domainSetMetadata = remoteDomainSetMetadata, /* 0.9.10 */
    .domainGetMetadata = remoteDomainGetMetadata, /* 0.9.10 */
    .domainGetHostname = remoteDomainGetHostname, /* 0.10.0 */
    .nodeSetMemoryParameters = remoteNodeSetMemoryParameters, /* 0.10.2 */
    .nodeGetMemoryParameters = remoteNodeGetMemoryParameters, /* 0.10.2 */
    .nodeGetCPUMap = remoteNodeGetCPUMap, /* 1.0.0 */
    .domainFSTrim = remoteDomainFSTrim, /* 1.0.1 */
    .domainLxcOpenNamespace = remoteDomainLxcOpenNamespace, /* 1.0.2 */
    .domainMigrateBegin3Params = remoteDomainMigrateBegin3Params, /* 1.1.0 */
    .domainMigratePrepare3Params = remoteDomainMigratePrepare3Params, /* 1.1.0 */
    .domainMigratePrepareTunnel3Params = remoteDomainMigratePrepareTunnel3Params, /* 1.1.0 */
    .domainMigratePerform3Params = remoteDomainMigratePerform3Params, /* 1.1.0 */
    .domainMigrateFinish3Params = remoteDomainMigrateFinish3Params, /* 1.1.0 */
    .domainMigrateConfirm3Params = remoteDomainMigrateConfirm3Params, /* 1.1.0 */
    .connectGetCPUModelNames = remoteConnectGetCPUModelNames, /* 1.1.3 */
};

static virNetworkDriver network_driver = {
    .name = "remote",
    .networkOpen = remoteNetworkOpen, /* 0.3.0 */
    .networkClose = remoteNetworkClose, /* 0.3.0 */
    .connectNumOfNetworks = remoteConnectNumOfNetworks, /* 0.3.0 */
    .connectListNetworks = remoteConnectListNetworks, /* 0.3.0 */
    .connectNumOfDefinedNetworks = remoteConnectNumOfDefinedNetworks, /* 0.3.0 */
    .connectListDefinedNetworks = remoteConnectListDefinedNetworks, /* 0.3.0 */
    .connectListAllNetworks = remoteConnectListAllNetworks, /* 0.10.2 */
    .networkLookupByUUID = remoteNetworkLookupByUUID, /* 0.3.0 */
    .networkLookupByName = remoteNetworkLookupByName, /* 0.3.0 */
    .networkCreateXML = remoteNetworkCreateXML, /* 0.3.0 */
    .networkDefineXML = remoteNetworkDefineXML, /* 0.3.0 */
    .networkUndefine = remoteNetworkUndefine, /* 0.3.0 */
    .networkUpdate = remoteNetworkUpdate, /* 0.10.2 */
    .networkCreate = remoteNetworkCreate, /* 0.3.0 */
    .networkDestroy = remoteNetworkDestroy, /* 0.3.0 */
    .networkGetXMLDesc = remoteNetworkGetXMLDesc, /* 0.3.0 */
    .networkGetBridgeName = remoteNetworkGetBridgeName, /* 0.3.0 */
    .networkGetAutostart = remoteNetworkGetAutostart, /* 0.3.0 */
    .networkSetAutostart = remoteNetworkSetAutostart, /* 0.3.0 */
    .networkIsActive = remoteNetworkIsActive, /* 0.7.3 */
    .networkIsPersistent = remoteNetworkIsPersistent, /* 0.7.3 */
};

static virInterfaceDriver interface_driver = {
    .name = "remote",
    .interfaceOpen = remoteInterfaceOpen, /* 0.7.2 */
    .interfaceClose = remoteInterfaceClose, /* 0.7.2 */
    .connectNumOfInterfaces = remoteConnectNumOfInterfaces, /* 0.7.2 */
    .connectListInterfaces = remoteConnectListInterfaces, /* 0.7.2 */
    .connectNumOfDefinedInterfaces = remoteConnectNumOfDefinedInterfaces, /* 0.7.2 */
    .connectListDefinedInterfaces = remoteConnectListDefinedInterfaces, /* 0.7.2 */
    .connectListAllInterfaces = remoteConnectListAllInterfaces, /* 0.10.2 */
    .interfaceLookupByName = remoteInterfaceLookupByName, /* 0.7.2 */
    .interfaceLookupByMACString = remoteInterfaceLookupByMACString, /* 0.7.2 */
    .interfaceGetXMLDesc = remoteInterfaceGetXMLDesc, /* 0.7.2 */
    .interfaceDefineXML = remoteInterfaceDefineXML, /* 0.7.2 */
    .interfaceUndefine = remoteInterfaceUndefine, /* 0.7.2 */
    .interfaceCreate = remoteInterfaceCreate, /* 0.7.2 */
    .interfaceDestroy = remoteInterfaceDestroy, /* 0.7.2 */
    .interfaceIsActive = remoteInterfaceIsActive, /* 0.7.3 */
    .interfaceChangeBegin = remoteInterfaceChangeBegin, /* 0.9.2 */
    .interfaceChangeCommit = remoteInterfaceChangeCommit, /* 0.9.2 */
    .interfaceChangeRollback = remoteInterfaceChangeRollback, /* 0.9.2 */
};

static virStorageDriver storage_driver = {
    .name = "remote",
    .storageOpen = remoteStorageOpen, /* 0.4.1 */
    .storageClose = remoteStorageClose, /* 0.4.1 */
    .connectNumOfStoragePools = remoteConnectNumOfStoragePools, /* 0.4.1 */
    .connectListStoragePools = remoteConnectListStoragePools, /* 0.4.1 */
    .connectNumOfDefinedStoragePools = remoteConnectNumOfDefinedStoragePools, /* 0.4.1 */
    .connectListDefinedStoragePools = remoteConnectListDefinedStoragePools, /* 0.4.1 */
    .connectListAllStoragePools = remoteConnectListAllStoragePools, /* 0.10.2 */
    .connectFindStoragePoolSources = remoteConnectFindStoragePoolSources, /* 0.4.5 */
    .storagePoolLookupByName = remoteStoragePoolLookupByName, /* 0.4.1 */
    .storagePoolLookupByUUID = remoteStoragePoolLookupByUUID, /* 0.4.1 */
    .storagePoolLookupByVolume = remoteStoragePoolLookupByVolume, /* 0.4.1 */
    .storagePoolCreateXML = remoteStoragePoolCreateXML, /* 0.4.1 */
    .storagePoolDefineXML = remoteStoragePoolDefineXML, /* 0.4.1 */
    .storagePoolBuild = remoteStoragePoolBuild, /* 0.4.1 */
    .storagePoolUndefine = remoteStoragePoolUndefine, /* 0.4.1 */
    .storagePoolCreate = remoteStoragePoolCreate, /* 0.4.1 */
    .storagePoolDestroy = remoteStoragePoolDestroy, /* 0.4.1 */
    .storagePoolDelete = remoteStoragePoolDelete, /* 0.4.1 */
    .storagePoolRefresh = remoteStoragePoolRefresh, /* 0.4.1 */
    .storagePoolGetInfo = remoteStoragePoolGetInfo, /* 0.4.1 */
    .storagePoolGetXMLDesc = remoteStoragePoolGetXMLDesc, /* 0.4.1 */
    .storagePoolGetAutostart = remoteStoragePoolGetAutostart, /* 0.4.1 */
    .storagePoolSetAutostart = remoteStoragePoolSetAutostart, /* 0.4.1 */
    .storagePoolNumOfVolumes = remoteStoragePoolNumOfVolumes, /* 0.4.1 */
    .storagePoolListVolumes = remoteStoragePoolListVolumes, /* 0.4.1 */
    .storagePoolListAllVolumes = remoteStoragePoolListAllVolumes, /* 0.10.0 */

    .storageVolLookupByName = remoteStorageVolLookupByName, /* 0.4.1 */
    .storageVolLookupByKey = remoteStorageVolLookupByKey, /* 0.4.1 */
    .storageVolLookupByPath = remoteStorageVolLookupByPath, /* 0.4.1 */
    .storageVolCreateXML = remoteStorageVolCreateXML, /* 0.4.1 */
    .storageVolCreateXMLFrom = remoteStorageVolCreateXMLFrom, /* 0.6.4 */
    .storageVolDownload = remoteStorageVolDownload, /* 0.9.0 */
    .storageVolUpload = remoteStorageVolUpload, /* 0.9.0 */
    .storageVolDelete = remoteStorageVolDelete, /* 0.4.1 */
    .storageVolWipe = remoteStorageVolWipe, /* 0.8.0 */
    .storageVolWipePattern = remoteStorageVolWipePattern, /* 0.9.10 */
    .storageVolGetInfo = remoteStorageVolGetInfo, /* 0.4.1 */
    .storageVolGetXMLDesc = remoteStorageVolGetXMLDesc, /* 0.4.1 */
    .storageVolGetPath = remoteStorageVolGetPath, /* 0.4.1 */
    .storageVolResize = remoteStorageVolResize, /* 0.9.10 */
    .storagePoolIsActive = remoteStoragePoolIsActive, /* 0.7.3 */
    .storagePoolIsPersistent = remoteStoragePoolIsPersistent, /* 0.7.3 */
};

static virSecretDriver secret_driver = {
    .name = "remote",
    .secretOpen = remoteSecretOpen, /* 0.7.1 */
    .secretClose = remoteSecretClose, /* 0.7.1 */
    .connectNumOfSecrets = remoteConnectNumOfSecrets, /* 0.7.1 */
    .connectListSecrets = remoteConnectListSecrets, /* 0.7.1 */
    .connectListAllSecrets = remoteConnectListAllSecrets, /* 0.10.2 */
    .secretLookupByUUID = remoteSecretLookupByUUID, /* 0.7.1 */
    .secretLookupByUsage = remoteSecretLookupByUsage, /* 0.7.1 */
    .secretDefineXML = remoteSecretDefineXML, /* 0.7.1 */
    .secretGetXMLDesc = remoteSecretGetXMLDesc, /* 0.7.1 */
    .secretSetValue = remoteSecretSetValue, /* 0.7.1 */
    .secretGetValue = remoteSecretGetValue, /* 0.7.1 */
    .secretUndefine = remoteSecretUndefine /* 0.7.1 */
};

static virNodeDeviceDriver node_device_driver = {
    .name = "remote",
    .nodeDeviceOpen = remoteNodeDeviceOpen, /* 0.5.0 */
    .nodeDeviceClose = remoteNodeDeviceClose, /* 0.5.0 */
    .nodeNumOfDevices = remoteNodeNumOfDevices, /* 0.5.0 */
    .nodeListDevices = remoteNodeListDevices, /* 0.5.0 */
    .connectListAllNodeDevices  = remoteConnectListAllNodeDevices, /* 0.10.2 */
    .nodeDeviceLookupByName = remoteNodeDeviceLookupByName, /* 0.5.0 */
    .nodeDeviceLookupSCSIHostByWWN = remoteNodeDeviceLookupSCSIHostByWWN, /* 1.0.2 */
    .nodeDeviceGetXMLDesc = remoteNodeDeviceGetXMLDesc, /* 0.5.0 */
    .nodeDeviceGetParent = remoteNodeDeviceGetParent, /* 0.5.0 */
    .nodeDeviceNumOfCaps = remoteNodeDeviceNumOfCaps, /* 0.5.0 */
    .nodeDeviceListCaps = remoteNodeDeviceListCaps, /* 0.5.0 */
    .nodeDeviceCreateXML = remoteNodeDeviceCreateXML, /* 0.6.3 */
    .nodeDeviceDestroy = remoteNodeDeviceDestroy /* 0.6.3 */
};

static virNWFilterDriver nwfilter_driver = {
    .name = "remote",
    .nwfilterOpen = remoteNWFilterOpen, /* 0.8.0 */
    .nwfilterClose = remoteNWFilterClose, /* 0.8.0 */
    .nwfilterLookupByUUID = remoteNWFilterLookupByUUID, /* 0.8.0 */
    .nwfilterLookupByName = remoteNWFilterLookupByName, /* 0.8.0 */
    .nwfilterGetXMLDesc           = remoteNWFilterGetXMLDesc, /* 0.8.0 */
    .nwfilterDefineXML            = remoteNWFilterDefineXML, /* 0.8.0 */
    .nwfilterUndefine             = remoteNWFilterUndefine, /* 0.8.0 */
    .connectNumOfNWFilters       = remoteConnectNumOfNWFilters, /* 0.8.0 */
    .connectListNWFilters        = remoteConnectListNWFilters, /* 0.8.0 */
    .connectListAllNWFilters     = remoteConnectListAllNWFilters, /* 0.10.2 */
};


#ifdef WITH_LIBVIRTD
static virStateDriver state_driver = {
    .name = "Remote",
    .stateInitialize = remoteStateInitialize,
};
#endif


/** remoteRegister:
 *
 * Register driver with libvirt driver system.
 *
 * Returns -1 on error.
 */
int
remoteRegister(void)
{
    remoteDriver = &remote_driver;

    if (virRegisterDriver(&remote_driver) == -1) return -1;
    if (virRegisterNetworkDriver(&network_driver) == -1) return -1;
    if (virRegisterInterfaceDriver(&interface_driver) == -1) return -1;
    if (virRegisterStorageDriver(&storage_driver) == -1) return -1;
    if (virRegisterNodeDeviceDriver(&node_device_driver) == -1) return -1;
    if (virRegisterSecretDriver(&secret_driver) == -1) return -1;
    if (virRegisterNWFilterDriver(&nwfilter_driver) == -1) return -1;
#ifdef WITH_LIBVIRTD
    if (virRegisterStateDriver(&state_driver) == -1) return -1;
#endif

    return 0;
}
