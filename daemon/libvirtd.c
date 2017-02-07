/*
 * libvirtd.c: daemon start of day, guest process & i/o management
 *
 * Copyright (C) 2006-2015 Red Hat, Inc.
 * Copyright (C) 2006 Daniel P. Berrange
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
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <getopt.h>
#include <stdlib.h>
#include <grp.h>

#include "libvirt_internal.h"
#include "virerror.h"
#include "virfile.h"
#include "virlog.h"
#include "virpidfile.h"
#include "virprocess.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

#include "libvirtd.h"
#include "libvirtd-config.h"

#include "admin.h"
#include "viruuid.h"
#include "remote_driver.h"
#include "viralloc.h"
#include "virconf.h"
#include "virnetlink.h"
#include "virnetdaemon.h"
#include "remote.h"
#include "virhook.h"
#include "viraudit.h"
#include "virstring.h"
#include "locking/lock_manager.h"
#include "viraccessmanager.h"
#include "virutil.h"
#include "virgettext.h"
#include "util/virnetdevopenvswitch.h"

#ifdef WITH_DRIVER_MODULES
# include "driver.h"
#else
# ifdef WITH_QEMU
#  include "qemu/qemu_driver.h"
# endif
# ifdef WITH_LXC
#  include "lxc/lxc_driver.h"
# endif
# ifdef WITH_XEN
#  include "xen/xen_driver.h"
# endif
# ifdef WITH_LIBXL
#  include "libxl/libxl_driver.h"
# endif
# ifdef WITH_UML
#  include "uml/uml_driver.h"
# endif
# ifdef WITH_VBOX
#  include "vbox/vbox_driver.h"
# endif
# ifdef WITH_BHYVE
#  include "bhyve/bhyve_driver.h"
# endif
# ifdef WITH_NETWORK
#  include "network/bridge_driver.h"
# endif
# ifdef WITH_INTERFACE
#  include "interface/interface_driver.h"
# endif
# ifdef WITH_STORAGE
#  include "storage/storage_driver.h"
# endif
# ifdef WITH_NODE_DEVICES
#  include "node_device/node_device_driver.h"
# endif
# ifdef WITH_SECRETS
#  include "secret/secret_driver.h"
# endif
# ifdef WITH_NWFILTER
#  include "nwfilter/nwfilter_driver.h"
# endif
#endif
#ifdef WITH_VZ
# include "vz/vz_driver.h"
#endif

#include "configmake.h"

#include "virdbus.h"

VIR_LOG_INIT("daemon.libvirtd");

#if WITH_SASL
virNetSASLContextPtr saslCtxt = NULL;
#endif
virNetServerProgramPtr remoteProgram = NULL;
virNetServerProgramPtr adminProgram = NULL;
virNetServerProgramPtr qemuProgram = NULL;
virNetServerProgramPtr lxcProgram = NULL;

volatile bool driversInitialized = false;

enum {
    VIR_DAEMON_ERR_NONE = 0,
    VIR_DAEMON_ERR_PIDFILE,
    VIR_DAEMON_ERR_RUNDIR,
    VIR_DAEMON_ERR_INIT,
    VIR_DAEMON_ERR_SIGNAL,
    VIR_DAEMON_ERR_PRIVS,
    VIR_DAEMON_ERR_NETWORK,
    VIR_DAEMON_ERR_CONFIG,
    VIR_DAEMON_ERR_HOOKS,
    VIR_DAEMON_ERR_AUDIT,

    VIR_DAEMON_ERR_LAST
};

VIR_ENUM_DECL(virDaemonErr)
VIR_ENUM_IMPL(virDaemonErr, VIR_DAEMON_ERR_LAST,
              "Initialization successful",
              "Unable to obtain pidfile",
              "Unable to create rundir",
              "Unable to initialize libvirt",
              "Unable to setup signal handlers",
              "Unable to drop privileges",
              "Unable to initialize network sockets",
              "Unable to load configuration file",
              "Unable to look for hook scripts",
              "Unable to initialize audit system")

static int daemonForkIntoBackground(const char *argv0)
{
    int statuspipe[2];
    if (pipe(statuspipe) < 0)
        return -1;

    pid_t pid = fork();
    switch (pid) {
    case 0:
        {
            /* intermediate child */
            int stdinfd = -1;
            int stdoutfd = -1;
            int nextpid;

            VIR_FORCE_CLOSE(statuspipe[0]);

            if ((stdinfd = open("/dev/null", O_RDONLY)) <= STDERR_FILENO)
                goto cleanup;
            if ((stdoutfd = open("/dev/null", O_WRONLY)) <= STDERR_FILENO)
                goto cleanup;
            if (dup2(stdinfd, STDIN_FILENO) != STDIN_FILENO)
                goto cleanup;
            if (dup2(stdoutfd, STDOUT_FILENO) != STDOUT_FILENO)
                goto cleanup;
            if (dup2(stdoutfd, STDERR_FILENO) != STDERR_FILENO)
                goto cleanup;
            if (VIR_CLOSE(stdinfd) < 0)
                goto cleanup;
            if (VIR_CLOSE(stdoutfd) < 0)
                goto cleanup;

            if (setsid() < 0)
                goto cleanup;

            nextpid = fork();
            switch (nextpid) {
            case 0: /* grandchild */
                return statuspipe[1];
            case -1: /* error */
                goto cleanup;
            default: /* intermediate child succeeded */
                _exit(EXIT_SUCCESS);
            }

        cleanup:
            VIR_FORCE_CLOSE(stdoutfd);
            VIR_FORCE_CLOSE(stdinfd);
            VIR_FORCE_CLOSE(statuspipe[1]);
            _exit(EXIT_FAILURE);

        }

    case -1: /* error in parent */
        goto error;

    default:
        {
            /* parent */
            int ret;
            char status;

            VIR_FORCE_CLOSE(statuspipe[1]);

            /* We wait to make sure the first child forked successfully */
            if (virProcessWait(pid, NULL, false) < 0)
                goto error;

            /* If we get here, then the grandchild was spawned, so we
             * must exit.  Block until the second child initializes
             * successfully */
        again:
            ret = read(statuspipe[0], &status, 1);
            if (ret == -1 && errno == EINTR)
                goto again;

            VIR_FORCE_CLOSE(statuspipe[0]);

            if (ret != 1) {
                char ebuf[1024];

                fprintf(stderr,
                        _("%s: error: unable to determine if daemon is "
                          "running: %s\n"), argv0,
                        virStrerror(errno, ebuf, sizeof(ebuf)));
                exit(EXIT_FAILURE);
            } else if (status != 0) {
                fprintf(stderr,
                        _("%s: error: %s. Check /var/log/messages or run "
                          "without --daemon for more info.\n"), argv0,
                        virDaemonErrTypeToString(status));
                exit(EXIT_FAILURE);
            }
            _exit(EXIT_SUCCESS);
        }
    }

 error:
    VIR_FORCE_CLOSE(statuspipe[0]);
    VIR_FORCE_CLOSE(statuspipe[1]);
    return -1;
}


static int
daemonUnixSocketPaths(struct daemonConfig *config,
                      bool privileged,
                      char **sockfile,
                      char **rosockfile,
                      char **admsockfile)
{
    if (config->unix_sock_dir) {
        if (virAsprintf(sockfile, "%s/libvirt-sock", config->unix_sock_dir) < 0)
            goto error;

        if (privileged) {
            if (virAsprintf(rosockfile, "%s/libvirt-sock-ro", config->unix_sock_dir) < 0)
                goto error;
            if (virAsprintf(admsockfile, "%s/libvirt-admin-sock", config->unix_sock_dir) < 0)
                goto error;
        }
    } else {
        if (privileged) {
            if (VIR_STRDUP(*sockfile, LOCALSTATEDIR "/run/libvirt/libvirt-sock") < 0 ||
                VIR_STRDUP(*rosockfile, LOCALSTATEDIR "/run/libvirt/libvirt-sock-ro") < 0 ||
                VIR_STRDUP(*admsockfile, LOCALSTATEDIR "/run/libvirt/libvirt-admin-sock") < 0)
                goto error;
        } else {
            char *rundir = NULL;
            mode_t old_umask;

            if (!(rundir = virGetUserRuntimeDirectory()))
                goto error;

            old_umask = umask(077);
            if (virFileMakePath(rundir) < 0) {
                umask(old_umask);
                goto error;
            }
            umask(old_umask);

            if (virAsprintf(sockfile, "%s/libvirt-sock", rundir) < 0 ||
                virAsprintf(admsockfile, "%s/libvirt-admin-sock", rundir) < 0) {
                VIR_FREE(rundir);
                goto error;
            }

            VIR_FREE(rundir);
        }
    }
    return 0;

 error:
    return -1;
}


static void daemonErrorHandler(void *opaque ATTRIBUTE_UNUSED,
                               virErrorPtr err ATTRIBUTE_UNUSED)
{
    /* Don't do anything, since logging infrastructure already
     * took care of reporting the error */
}

static int daemonErrorLogFilter(virErrorPtr err, int priority)
{
    /* These error codes don't really reflect real errors. They
     * are expected events that occur when an app tries to check
     * whether a particular guest already exists. This filters
     * them to a lower log level to prevent pollution of syslog
     */
    switch (err->code) {
    case VIR_ERR_NO_DOMAIN:
    case VIR_ERR_NO_NETWORK:
    case VIR_ERR_NO_STORAGE_POOL:
    case VIR_ERR_NO_STORAGE_VOL:
    case VIR_ERR_NO_NODE_DEVICE:
    case VIR_ERR_NO_INTERFACE:
    case VIR_ERR_NO_NWFILTER:
    case VIR_ERR_NO_SECRET:
    case VIR_ERR_NO_DOMAIN_SNAPSHOT:
    case VIR_ERR_OPERATION_INVALID:
    case VIR_ERR_NO_DOMAIN_METADATA:
    case VIR_ERR_NO_SERVER:
    case VIR_ERR_NO_CLIENT:
        return VIR_LOG_DEBUG;
    }

    return priority;
}

static void daemonInitialize(void)
{
    /*
     * Note that the order is important: the first ones have a higher
     * priority when calling virStateInitialize. We must register the
     * network, storage and nodedev drivers before any stateful domain
     * driver, since their resources must be auto-started before any
     * domains can be auto-started.
     */
#ifdef WITH_DRIVER_MODULES
    /* We don't care if any of these fail, because the whole point
     * is to allow users to only install modules they want to use.
     * If they try to open a connection for a module that
     * is not loaded they'll get a suitable error at that point
     */
# ifdef WITH_NETWORK
    virDriverLoadModule("network");
# endif
# ifdef WITH_INTERFACE
    virDriverLoadModule("interface");
# endif
# ifdef WITH_STORAGE
    virDriverLoadModule("storage");
# endif
# ifdef WITH_NODE_DEVICES
    virDriverLoadModule("nodedev");
# endif
# ifdef WITH_SECRETS
    virDriverLoadModule("secret");
# endif
# ifdef WITH_NWFILTER
    virDriverLoadModule("nwfilter");
# endif
# ifdef WITH_XEN
    virDriverLoadModule("xen");
# endif
# ifdef WITH_LIBXL
    virDriverLoadModule("libxl");
# endif
# ifdef WITH_QEMU
    virDriverLoadModule("qemu");
# endif
# ifdef WITH_LXC
    virDriverLoadModule("lxc");
# endif
# ifdef WITH_UML
    virDriverLoadModule("uml");
# endif
# ifdef WITH_VBOX
    virDriverLoadModule("vbox");
# endif
# ifdef WITH_BHYVE
    virDriverLoadModule("bhyve");
# endif
# ifdef WITH_VZ
    virDriverLoadModule("vz");
# endif
#else
# ifdef WITH_NETWORK
    networkRegister();
# endif
# ifdef WITH_INTERFACE
    interfaceRegister();
# endif
# ifdef WITH_STORAGE
    storageRegister();
# endif
# ifdef WITH_NODE_DEVICES
    nodedevRegister();
# endif
# ifdef WITH_SECRETS
    secretRegister();
# endif
# ifdef WITH_NWFILTER
    nwfilterRegister();
# endif
# ifdef WITH_XEN
    xenRegister();
# endif
# ifdef WITH_LIBXL
    libxlRegister();
# endif
# ifdef WITH_QEMU
    qemuRegister();
# endif
# ifdef WITH_LXC
    lxcRegister();
# endif
# ifdef WITH_UML
    umlRegister();
# endif
# ifdef WITH_VBOX
    vboxRegister();
# endif
# ifdef WITH_BHYVE
    bhyveRegister();
# endif
# ifdef WITH_VZ
    vzRegister();
# endif
#endif
}


static int ATTRIBUTE_NONNULL(3)
daemonSetupNetworking(virNetServerPtr srv,
                      virNetServerPtr srvAdm,
                      struct daemonConfig *config,
                      const char *sock_path,
                      const char *sock_path_ro,
                      const char *sock_path_adm,
                      bool ipsock,
                      bool privileged)
{
    virNetServerServicePtr svc = NULL;
    virNetServerServicePtr svcAdm = NULL;
    virNetServerServicePtr svcRO = NULL;
    virNetServerServicePtr svcTCP = NULL;
#if WITH_GNUTLS
    virNetServerServicePtr svcTLS = NULL;
#endif
    gid_t unix_sock_gid = 0;
    int unix_sock_ro_mask = 0;
    int unix_sock_rw_mask = 0;
    int unix_sock_adm_mask = 0;
    int ret = -1;

    unsigned int cur_fd = STDERR_FILENO + 1;
    unsigned int nfds = virGetListenFDs();

    if (config->unix_sock_group) {
        if (virGetGroupID(config->unix_sock_group, &unix_sock_gid) < 0)
            return ret;
    }

    if (nfds > (sock_path_ro ? 2 : 1)) {
        VIR_ERROR(_("Too many (%u) FDs passed from caller"), nfds);
        return ret;
    }

    if (virStrToLong_i(config->unix_sock_ro_perms, NULL, 8, &unix_sock_ro_mask) != 0) {
        VIR_ERROR(_("Failed to parse mode '%s'"), config->unix_sock_ro_perms);
        goto cleanup;
    }

    if (virStrToLong_i(config->unix_sock_admin_perms, NULL, 8, &unix_sock_adm_mask) != 0) {
        VIR_ERROR(_("Failed to parse mode '%s'"), config->unix_sock_admin_perms);
        goto cleanup;
    }

    if (virStrToLong_i(config->unix_sock_rw_perms, NULL, 8, &unix_sock_rw_mask) != 0) {
        VIR_ERROR(_("Failed to parse mode '%s'"), config->unix_sock_rw_perms);
        goto cleanup;
    }

    if (!(svc = virNetServerServiceNewFDOrUNIX(sock_path,
                                               unix_sock_rw_mask,
                                               unix_sock_gid,
                                               config->auth_unix_rw,
#if WITH_GNUTLS
                                               NULL,
#endif
                                               false,
                                               config->max_queued_clients,
                                               config->max_client_requests,
                                               nfds, &cur_fd)))
        goto cleanup;
    if (sock_path_ro) {
        if (!(svcRO = virNetServerServiceNewFDOrUNIX(sock_path_ro,
                                                     unix_sock_ro_mask,
                                                     unix_sock_gid,
                                                     config->auth_unix_ro,
#if WITH_GNUTLS
                                                     NULL,
#endif
                                                     true,
                                                     config->max_queued_clients,
                                                     config->max_client_requests,
                                                     nfds, &cur_fd)))
            goto cleanup;
    }

    if (virNetServerAddService(srv, svc,
                               config->mdns_adv && !ipsock ?
                               "_libvirt._tcp" :
                               NULL) < 0)
        goto cleanup;

    if (svcRO &&
        virNetServerAddService(srv, svcRO, NULL) < 0)
        goto cleanup;

    if (sock_path_adm) {
        VIR_DEBUG("Registering unix socket %s", sock_path_adm);
        if (!(svcAdm = virNetServerServiceNewUNIX(sock_path_adm,
                                                  unix_sock_adm_mask,
                                                  unix_sock_gid,
                                                  REMOTE_AUTH_NONE,
#if WITH_GNUTLS
                                                  NULL,
#endif
                                                  false,
                                                  config->admin_max_queued_clients,
                                                  config->admin_max_client_requests)))
            goto cleanup;

        if (virNetServerAddService(srvAdm, svcAdm, NULL) < 0)
            goto cleanup;
    }

    if (ipsock) {
        if (config->listen_tcp) {
            VIR_DEBUG("Registering TCP socket %s:%s",
                      config->listen_addr, config->tcp_port);
            if (!(svcTCP = virNetServerServiceNewTCP(config->listen_addr,
                                                     config->tcp_port,
                                                     AF_UNSPEC,
                                                     config->auth_tcp,
#if WITH_GNUTLS
                                                     NULL,
#endif
                                                     false,
                                                     config->max_queued_clients,
                                                     config->max_client_requests)))
                goto cleanup;

            if (virNetServerAddService(srv, svcTCP,
                                       config->mdns_adv ? "_libvirt._tcp" : NULL) < 0)
                goto cleanup;
        }

#if WITH_GNUTLS
        if (config->listen_tls) {
            virNetTLSContextPtr ctxt = NULL;

            if (config->ca_file ||
                config->cert_file ||
                config->key_file) {
                if (!(ctxt = virNetTLSContextNewServer(config->ca_file,
                                                       config->crl_file,
                                                       config->cert_file,
                                                       config->key_file,
                                                       (const char *const*)config->tls_allowed_dn_list,
                                                       config->tls_priority,
                                                       config->tls_no_sanity_certificate ? false : true,
                                                       config->tls_no_verify_certificate ? false : true)))
                    goto cleanup;
            } else {
                if (!(ctxt = virNetTLSContextNewServerPath(NULL,
                                                           !privileged,
                                                           (const char *const*)config->tls_allowed_dn_list,
                                                           config->tls_priority,
                                                           config->tls_no_sanity_certificate ? false : true,
                                                           config->tls_no_verify_certificate ? false : true)))
                    goto cleanup;
            }

            VIR_DEBUG("Registering TLS socket %s:%s",
                      config->listen_addr, config->tls_port);
            if (!(svcTLS =
                  virNetServerServiceNewTCP(config->listen_addr,
                                            config->tls_port,
                                            AF_UNSPEC,
                                            config->auth_tls,
                                            ctxt,
                                            false,
                                            config->max_queued_clients,
                                            config->max_client_requests))) {
                virObjectUnref(ctxt);
                goto cleanup;
            }
            if (virNetServerAddService(srv, svcTLS,
                                       config->mdns_adv &&
                                       !config->listen_tcp ? "_libvirt._tcp" : NULL) < 0)
                goto cleanup;

            virObjectUnref(ctxt);
        }
#else
        (void)privileged;
        if (config->listen_tls) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("This libvirtd build does not support TLS"));
            goto cleanup;
        }
#endif
    }

#if WITH_SASL
    if (config->auth_unix_rw == REMOTE_AUTH_SASL ||
        config->auth_unix_ro == REMOTE_AUTH_SASL ||
# if WITH_GNUTLS
        config->auth_tls == REMOTE_AUTH_SASL ||
# endif
        config->auth_tcp == REMOTE_AUTH_SASL) {
        saslCtxt = virNetSASLContextNewServer(
            (const char *const*)config->sasl_allowed_username_list);
        if (!saslCtxt)
            goto cleanup;
    }
#endif

    ret = 0;

 cleanup:
#if WITH_GNUTLS
    virObjectUnref(svcTLS);
#endif
    virObjectUnref(svcTCP);
    virObjectUnref(svcRO);
    virObjectUnref(svcAdm);
    virObjectUnref(svc);
    return ret;
}


/*
 * Set up the openvswitch timeout
 */
static void
daemonSetupNetDevOpenvswitch(struct daemonConfig *config)
{
    virNetDevOpenvswitchSetTimeout(config->ovs_timeout);
}


/*
 * Set up the logging environment
 * By default if daemonized all errors go to the logfile libvirtd.log,
 * but if verbose or error debugging is asked for then also output
 * informational and debug messages. Default size if 64 kB.
 */
static int
daemonSetupLogging(struct daemonConfig *config,
                   bool privileged,
                   bool verbose,
                   bool godaemon)
{
    virLogReset();

    /*
     * Libvirtd's order of precedence is:
     * cmdline > environment > config
     *
     * The default output is applied only if there was no setting from either
     * the config or the environment. Because we don't have a way to determine
     * if the log level has been set, we must process variables in the opposite
     * order, each one overriding the previous.
     */
    if (config->log_level != 0)
        virLogSetDefaultPriority(config->log_level);

    if (virLogSetDefaultOutput("libvirtd.log", godaemon, privileged) < 0)
        return -1;

    /* In case the config is empty, the filters become empty and outputs will
     * be set to default
     */
    ignore_value(virLogSetFilters(config->log_filters));
    ignore_value(virLogSetOutputs(config->log_outputs));

    /* If there are some environment variables defined, use those instead */
    virLogSetFromEnv();

    /*
     * Command line override for --verbose
     */
    if ((verbose) && (virLogGetDefaultPriority() > VIR_LOG_INFO))
        virLogSetDefaultPriority(VIR_LOG_INFO);

    return 0;
}


static int
daemonSetupAccessManager(struct daemonConfig *config)
{
    virAccessManagerPtr mgr;
    const char *none[] = { "none", NULL };
    const char **drv = (const char **)config->access_drivers;

    if (!drv ||
        !drv[0])
        drv = none;

    if (!(mgr = virAccessManagerNewStack(drv)))
        return -1;

    virAccessManagerSetDefault(mgr);
    virObjectUnref(mgr);
    return 0;
}


/* Display version information. */
static void
daemonVersion(const char *argv0)
{
    printf("%s (%s) %s\n", argv0, PACKAGE_NAME, PACKAGE_VERSION);
}

#ifdef __sun
static int
daemonSetupPrivs(void)
{
    chown("/var/run/libvirt", SYSTEM_UID, SYSTEM_UID);

    if (__init_daemon_priv(PU_RESETGROUPS | PU_CLEARLIMITSET,
                           SYSTEM_UID, SYSTEM_UID, PRIV_XVM_CONTROL, NULL)) {
        VIR_ERROR(_("additional privileges are required"));
        return -1;
    }

    if (priv_set(PRIV_OFF, PRIV_ALLSETS, PRIV_FILE_LINK_ANY, PRIV_PROC_INFO,
                 PRIV_PROC_SESSION, PRIV_PROC_EXEC, PRIV_PROC_FORK, NULL)) {
        VIR_ERROR(_("failed to set reduced privileges"));
        return -1;
    }

    return 0;
}
#else
# define daemonSetupPrivs() 0
#endif


static void daemonShutdownHandler(virNetDaemonPtr dmn,
                                  siginfo_t *sig ATTRIBUTE_UNUSED,
                                  void *opaque ATTRIBUTE_UNUSED)
{
    virNetDaemonQuit(dmn);
}

static void daemonReloadHandler(virNetDaemonPtr dmn ATTRIBUTE_UNUSED,
                                siginfo_t *sig ATTRIBUTE_UNUSED,
                                void *opaque ATTRIBUTE_UNUSED)
{
    if (!driversInitialized) {
        VIR_WARN("Drivers are not initialized, reload ignored");
        return;
    }

    VIR_INFO("Reloading configuration on SIGHUP");
    virHookCall(VIR_HOOK_DRIVER_DAEMON, "-",
                VIR_HOOK_DAEMON_OP_RELOAD, SIGHUP, "SIGHUP", NULL, NULL);
    if (virStateReload() < 0)
        VIR_WARN("Error while reloading drivers");
}

static int daemonSetupSignals(virNetDaemonPtr dmn)
{
    if (virNetDaemonAddSignalHandler(dmn, SIGINT, daemonShutdownHandler, NULL) < 0)
        return -1;
    if (virNetDaemonAddSignalHandler(dmn, SIGQUIT, daemonShutdownHandler, NULL) < 0)
        return -1;
    if (virNetDaemonAddSignalHandler(dmn, SIGTERM, daemonShutdownHandler, NULL) < 0)
        return -1;
    if (virNetDaemonAddSignalHandler(dmn, SIGHUP, daemonReloadHandler, NULL) < 0)
        return -1;
    return 0;
}


static void daemonInhibitCallback(bool inhibit, void *opaque)
{
    virNetDaemonPtr dmn = opaque;

    if (inhibit)
        virNetDaemonAddShutdownInhibition(dmn);
    else
        virNetDaemonRemoveShutdownInhibition(dmn);
}


#ifdef HAVE_DBUS
static DBusConnection *sessionBus;
static DBusConnection *systemBus;

static void daemonStopWorker(void *opaque)
{
    virNetDaemonPtr dmn = opaque;

    VIR_DEBUG("Begin stop dmn=%p", dmn);

    ignore_value(virStateStop());

    VIR_DEBUG("Completed stop dmn=%p", dmn);

    /* Exit libvirtd cleanly */
    virNetDaemonQuit(dmn);
}


/* We do this in a thread to not block the main loop */
static void daemonStop(virNetDaemonPtr dmn)
{
    virThread thr;
    virObjectRef(dmn);
    if (virThreadCreate(&thr, false, daemonStopWorker, dmn) < 0)
        virObjectUnref(dmn);
}


static DBusHandlerResult
handleSessionMessageFunc(DBusConnection *connection ATTRIBUTE_UNUSED,
                         DBusMessage *message,
                         void *opaque)
{
    virNetDaemonPtr dmn = opaque;

    VIR_DEBUG("dmn=%p", dmn);

    if (dbus_message_is_signal(message,
                               DBUS_INTERFACE_LOCAL,
                               "Disconnected"))
        daemonStop(dmn);

    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}


static DBusHandlerResult
handleSystemMessageFunc(DBusConnection *connection ATTRIBUTE_UNUSED,
                        DBusMessage *message,
                        void *opaque)
{
    virNetDaemonPtr dmn = opaque;

    VIR_DEBUG("dmn=%p", dmn);

    if (dbus_message_is_signal(message,
                               "org.freedesktop.login1.Manager",
                               "PrepareForShutdown"))
        daemonStop(dmn);

    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}
#endif


static void daemonRunStateInit(void *opaque)
{
    virNetDaemonPtr dmn = opaque;
    virIdentityPtr sysident = virIdentityGetSystem();

    virIdentitySetCurrent(sysident);

    /* Since driver initialization can take time inhibit daemon shutdown until
       we're done so clients get a chance to connect */
    daemonInhibitCallback(true, dmn);

    /* Start the stateful HV drivers
     * This is deliberately done after telling the parent process
     * we're ready, since it can take a long time and this will
     * seriously delay OS bootup process */
    if (virStateInitialize(virNetDaemonIsPrivileged(dmn),
                           daemonInhibitCallback,
                           dmn) < 0) {
        VIR_ERROR(_("Driver state initialization failed"));
        /* Ensure the main event loop quits */
        kill(getpid(), SIGTERM);
        goto cleanup;
    }

    driversInitialized = true;

#ifdef HAVE_DBUS
    /* Tie the non-privileged libvirtd to the session/shutdown lifecycle */
    if (!virNetDaemonIsPrivileged(dmn)) {

        sessionBus = virDBusGetSessionBus();
        if (sessionBus != NULL)
            dbus_connection_add_filter(sessionBus,
                                       handleSessionMessageFunc, dmn, NULL);

        systemBus = virDBusGetSystemBus();
        if (systemBus != NULL) {
            dbus_connection_add_filter(systemBus,
                                       handleSystemMessageFunc, dmn, NULL);
            dbus_bus_add_match(systemBus,
                               "type='signal',sender='org.freedesktop.login1', interface='org.freedesktop.login1.Manager'",
                               NULL);
        }
    }
#endif
    /* Only now accept clients from network */
    virNetDaemonUpdateServices(dmn, true);
 cleanup:
    daemonInhibitCallback(false, dmn);
    virObjectUnref(dmn);
    virObjectUnref(sysident);
    virIdentitySetCurrent(NULL);
}

static int daemonStateInit(virNetDaemonPtr dmn)
{
    virThread thr;
    virObjectRef(dmn);
    if (virThreadCreate(&thr, false, daemonRunStateInit, dmn) < 0) {
        virObjectUnref(dmn);
        return -1;
    }
    return 0;
}

static int migrateProfile(void)
{
    char *old_base = NULL;
    char *updated = NULL;
    char *home = NULL;
    char *xdg_dir = NULL;
    char *config_dir = NULL;
    const char *config_home;
    int ret = -1;
    mode_t old_umask;

    VIR_DEBUG("Checking if user profile needs migrating");

    if (!(home = virGetUserDirectory()))
        goto cleanup;

    if (virAsprintf(&old_base, "%s/.libvirt", home) < 0)
        goto cleanup;

    /* if the new directory is there or the old one is not: do nothing */
    if (!(config_dir = virGetUserConfigDirectory()))
        goto cleanup;

    if (!virFileIsDir(old_base) || virFileExists(config_dir)) {
        VIR_DEBUG("No old profile in '%s' / "
                  "new profile directory already present '%s'",
                  old_base, config_dir);
        ret = 0;
        goto cleanup;
    }

    /* test if we already attempted to migrate first */
    if (virAsprintf(&updated, "%s/DEPRECATED-DIRECTORY", old_base) < 0)
        goto cleanup;
    if (virFileExists(updated))
        goto cleanup;

    config_home = virGetEnvBlockSUID("XDG_CONFIG_HOME");
    if (config_home && config_home[0] != '\0') {
        if (VIR_STRDUP(xdg_dir, config_home) < 0)
            goto cleanup;
    } else {
        if (virAsprintf(&xdg_dir, "%s/.config", home) < 0)
            goto cleanup;
    }

    old_umask = umask(077);
    if (virFileMakePath(xdg_dir) < 0) {
        umask(old_umask);
        goto cleanup;
    }
    umask(old_umask);

    if (rename(old_base, config_dir) < 0) {
        int fd = creat(updated, 0600);
        VIR_FORCE_CLOSE(fd);
        VIR_ERROR(_("Unable to migrate %s to %s"), old_base, config_dir);
        goto cleanup;
    }

    VIR_DEBUG("Profile migrated from %s to %s", old_base, config_dir);
    ret = 0;

 cleanup:
    VIR_FREE(home);
    VIR_FREE(old_base);
    VIR_FREE(xdg_dir);
    VIR_FREE(config_dir);
    VIR_FREE(updated);

    return ret;
}

static int
daemonSetupHostUUID(const struct daemonConfig *config)
{
    static const char *machine_id = "/etc/machine-id";
    char buf[VIR_UUID_STRING_BUFLEN];
    const char *uuid;

    if (config->host_uuid) {
        uuid = config->host_uuid;
    } else if (!config->host_uuid_source ||
               STREQ(config->host_uuid_source, "smbios")) {
        /* smbios UUID is fetched on demand in virGetHostUUID */
        return 0;
    } else if (STREQ(config->host_uuid_source, "machine-id")) {
        if (virFileReadBufQuiet(machine_id, buf, sizeof(buf)) < 0) {
            VIR_ERROR(_("Can't read %s"), machine_id);
            return -1;
        }

        uuid = buf;
    } else {
        VIR_ERROR(_("invalid UUID source: %s"), config->host_uuid_source);
        return -1;
    }

    if (virSetHostUUIDStr(uuid)) {
        VIR_ERROR(_("invalid host UUID: %s"), uuid);
        return -1;
    }

    return 0;
}

/* Print command-line usage. */
static void
daemonUsage(const char *argv0, bool privileged)
{
    fprintf(stderr,
            _("\n"
              "Usage:\n"
              "  %s [options]\n"
              "\n"
              "Options:\n"
              "  -h | --help            Display program help:\n"
              "  -v | --verbose         Verbose messages.\n"
              "  -d | --daemon          Run as a daemon & write PID file.\n"
              "  -l | --listen          Listen for TCP/IP connections.\n"
              "  -t | --timeout <secs>  Exit after timeout period.\n"
              "  -f | --config <file>   Configuration file.\n"
              "  -V | --version         Display version information.\n"
              "  -p | --pid-file <file> Change name of PID file.\n"
              "\n"
              "libvirt management daemon:\n"),
            argv0);

    if (privileged) {
        fprintf(stderr,
                _("\n"
                  "  Default paths:\n"
                  "\n"
                  "    Configuration file (unless overridden by -f):\n"
                  "      %s\n"
                  "\n"
                  "    Sockets:\n"
                  "      %s\n"
                  "      %s\n"
                  "\n"
                  "    TLS:\n"
                  "      CA certificate:     %s\n"
                  "      Server certificate: %s\n"
                  "      Server private key: %s\n"
                  "\n"
                  "    PID file (unless overridden by -p):\n"
                  "      %s/run/libvirtd.pid\n"
                  "\n"),
                LIBVIRTD_CONFIGURATION_FILE,
                LIBVIRTD_PRIV_UNIX_SOCKET,
                LIBVIRTD_PRIV_UNIX_SOCKET_RO,
                LIBVIRT_CACERT,
                LIBVIRT_SERVERCERT,
                LIBVIRT_SERVERKEY,
                LOCALSTATEDIR);
    } else {
        fprintf(stderr, "%s",
                _("\n"
                  "  Default paths:\n"
                  "\n"
                  "    Configuration file (unless overridden by -f):\n"
                  "      $XDG_CONFIG_HOME/libvirt/libvirtd.conf\n"
                  "\n"
                  "    Sockets:\n"
                  "      $XDG_RUNTIME_DIR/libvirt/libvirt-sock\n"
                  "\n"
                  "    TLS:\n"
                  "      CA certificate:     $HOME/.pki/libvirt/cacert.pem\n"
                  "      Server certificate: $HOME/.pki/libvirt/servercert.pem\n"
                  "      Server private key: $HOME/.pki/libvirt/serverkey.pem\n"
                  "\n"
                  "    PID file:\n"
                  "      $XDG_RUNTIME_DIR/libvirt/libvirtd.pid\n"
                  "\n"));
    }
}

int main(int argc, char **argv) {
    virNetDaemonPtr dmn = NULL;
    virNetServerPtr srv = NULL;
    virNetServerPtr srvAdm = NULL;
    char *remote_config_file = NULL;
    int statuswrite = -1;
    int ret = 1;
    int pid_file_fd = -1;
    char *pid_file = NULL;
    char *sock_file = NULL;
    char *sock_file_ro = NULL;
    char *sock_file_adm = NULL;
    int timeout = -1;        /* -t: Shutdown timeout */
    int verbose = 0;
    int godaemon = 0;
    int ipsock = 0;
    struct daemonConfig *config;
    bool privileged = geteuid() == 0 ? true : false;
    bool implicit_conf = false;
    char *run_dir = NULL;
    mode_t old_umask;

    struct option opts[] = {
        { "verbose", no_argument, &verbose, 'v'},
        { "daemon", no_argument, &godaemon, 'd'},
        { "listen", no_argument, &ipsock, 'l'},
        { "config", required_argument, NULL, 'f'},
        { "timeout", required_argument, NULL, 't'},
        { "pid-file", required_argument, NULL, 'p'},
        { "version", no_argument, NULL, 'V' },
        { "help", no_argument, NULL, 'h' },
        {0, 0, 0, 0}
    };

    if (virGettextInitialize() < 0 ||
        virInitialize() < 0) {
        fprintf(stderr, _("%s: initialization failed\n"), argv[0]);
        exit(EXIT_FAILURE);
    }

    virUpdateSelfLastChanged(argv[0]);

    virFileActivateDirOverride(argv[0]);

    while (1) {
        int optidx = 0;
        int c;
        char *tmp;

        c = getopt_long(argc, argv, "ldf:p:t:vVh", opts, &optidx);

        if (c == -1)
            break;

        switch (c) {
        case 0:
            /* Got one of the flags */
            break;
        case 'v':
            verbose = 1;
            break;
        case 'd':
            godaemon = 1;
            break;
        case 'l':
            ipsock = 1;
            break;

        case 't':
            if (virStrToLong_i(optarg, &tmp, 10, &timeout) != 0
                || timeout <= 0
                /* Ensure that we can multiply by 1000 without overflowing.  */
                || timeout > INT_MAX / 1000) {
                VIR_ERROR(_("Invalid value for timeout"));
                exit(EXIT_FAILURE);
            }
            break;

        case 'p':
            VIR_FREE(pid_file);
            if (VIR_STRDUP_QUIET(pid_file, optarg) < 0) {
                VIR_ERROR(_("Can't allocate memory"));
                exit(EXIT_FAILURE);
            }
            break;

        case 'f':
            VIR_FREE(remote_config_file);
            if (VIR_STRDUP_QUIET(remote_config_file, optarg) < 0) {
                VIR_ERROR(_("Can't allocate memory"));
                exit(EXIT_FAILURE);
            }
            break;

        case 'V':
            daemonVersion(argv[0]);
            exit(EXIT_SUCCESS);

        case 'h':
            daemonUsage(argv[0], privileged);
            exit(EXIT_SUCCESS);

        case '?':
        default:
            daemonUsage(argv[0], privileged);
            exit(EXIT_FAILURE);
        }
    }

    if (optind != argc) {
        fprintf(stderr, "%s: unexpected, non-option, command line arguments\n",
                argv[0]);
        exit(EXIT_FAILURE);
    }

    if (!(config = daemonConfigNew(privileged))) {
        VIR_ERROR(_("Can't create initial configuration"));
        exit(EXIT_FAILURE);
    }

    /* No explicit config, so try and find a default one */
    if (remote_config_file == NULL) {
        implicit_conf = true;
        if (daemonConfigFilePath(privileged,
                                 &remote_config_file) < 0) {
            VIR_ERROR(_("Can't determine config path"));
            exit(EXIT_FAILURE);
        }
    }

    /* Read the config file if it exists*/
    if (remote_config_file &&
        daemonConfigLoadFile(config, remote_config_file, implicit_conf) < 0) {
        VIR_ERROR(_("Can't load config file: %s: %s"),
                  virGetLastErrorMessage(), remote_config_file);
        exit(EXIT_FAILURE);
    }

    if (!privileged &&
        migrateProfile() < 0) {
        VIR_ERROR(_("Exiting due to failure to migrate profile"));
        exit(EXIT_FAILURE);
    }

    if (daemonSetupHostUUID(config) < 0) {
        VIR_ERROR(_("Can't setup host uuid"));
        exit(EXIT_FAILURE);
    }

    if (daemonSetupLogging(config, privileged, verbose, godaemon) < 0) {
        VIR_ERROR(_("Can't initialize logging"));
        exit(EXIT_FAILURE);
    }

    daemonSetupNetDevOpenvswitch(config);

    if (daemonSetupAccessManager(config) < 0) {
        VIR_ERROR(_("Can't initialize access manager"));
        exit(EXIT_FAILURE);
    }

    if (!pid_file &&
        virPidFileConstructPath(privileged,
                                LOCALSTATEDIR,
                                "libvirtd",
                                &pid_file) < 0) {
        VIR_ERROR(_("Can't determine pid file path."));
        exit(EXIT_FAILURE);
    }
    VIR_DEBUG("Decided on pid file path '%s'", NULLSTR(pid_file));

    if (daemonUnixSocketPaths(config,
                              privileged,
                              &sock_file,
                              &sock_file_ro,
                              &sock_file_adm) < 0) {
        VIR_ERROR(_("Can't determine socket paths"));
        exit(EXIT_FAILURE);
    }
    VIR_DEBUG("Decided on socket paths '%s', '%s' and '%s'",
              sock_file,
              NULLSTR(sock_file_ro),
              NULLSTR(sock_file_adm));

    if (godaemon) {
        char ebuf[1024];

        if (chdir("/") < 0) {
            VIR_ERROR(_("cannot change to root directory: %s"),
                      virStrerror(errno, ebuf, sizeof(ebuf)));
            goto cleanup;
        }

        if ((statuswrite = daemonForkIntoBackground(argv[0])) < 0) {
            VIR_ERROR(_("Failed to fork as daemon: %s"),
                      virStrerror(errno, ebuf, sizeof(ebuf)));
            goto cleanup;
        }
    }

    /* Ensure the rundir exists (on tmpfs on some systems) */
    if (privileged) {
        if (VIR_STRDUP_QUIET(run_dir, LOCALSTATEDIR "/run/libvirt") < 0) {
            VIR_ERROR(_("Can't allocate memory"));
            goto cleanup;
        }
    } else {
        run_dir = virGetUserRuntimeDirectory();

        if (!run_dir) {
            VIR_ERROR(_("Can't determine user directory"));
            goto cleanup;
        }
    }
    if (privileged)
        old_umask = umask(022);
    else
        old_umask = umask(077);
    VIR_DEBUG("Ensuring run dir '%s' exists", run_dir);
    if (virFileMakePath(run_dir) < 0) {
        char ebuf[1024];
        VIR_ERROR(_("unable to create rundir %s: %s"), run_dir,
                  virStrerror(errno, ebuf, sizeof(ebuf)));
        ret = VIR_DAEMON_ERR_RUNDIR;
        goto cleanup;
    }
    umask(old_umask);

    /* Try to claim the pidfile, exiting if we can't */
    if ((pid_file_fd = virPidFileAcquirePath(pid_file, false, getpid())) < 0) {
        ret = VIR_DAEMON_ERR_PIDFILE;
        goto cleanup;
    }

    if (virNetlinkStartup() < 0) {
        ret = VIR_DAEMON_ERR_INIT;
        goto cleanup;
    }

    if (!(srv = virNetServerNew("libvirtd", 1,
                                config->min_workers,
                                config->max_workers,
                                config->prio_workers,
                                config->max_clients,
                                config->max_anonymous_clients,
                                config->keepalive_interval,
                                config->keepalive_count,
                                config->mdns_adv ? config->mdns_name : NULL,
                                remoteClientInitHook,
                                NULL,
                                remoteClientFreeFunc,
                                NULL))) {
        ret = VIR_DAEMON_ERR_INIT;
        goto cleanup;
    }

    if (!(dmn = virNetDaemonNew()) ||
        virNetDaemonAddServer(dmn, srv) < 0) {
        ret = VIR_DAEMON_ERR_INIT;
        goto cleanup;
    }

    /* Beyond this point, nothing should rely on using
     * getuid/geteuid() == 0, for privilege level checks.
     */
    VIR_DEBUG("Dropping privileges (if required)");
    if (daemonSetupPrivs() < 0) {
        ret = VIR_DAEMON_ERR_PRIVS;
        goto cleanup;
    }

    daemonInitialize();

    remoteProcs[REMOTE_PROC_AUTH_LIST].needAuth = false;
    remoteProcs[REMOTE_PROC_AUTH_SASL_INIT].needAuth = false;
    remoteProcs[REMOTE_PROC_AUTH_SASL_STEP].needAuth = false;
    remoteProcs[REMOTE_PROC_AUTH_SASL_START].needAuth = false;
    remoteProcs[REMOTE_PROC_AUTH_POLKIT].needAuth = false;
    if (!(remoteProgram = virNetServerProgramNew(REMOTE_PROGRAM,
                                                 REMOTE_PROTOCOL_VERSION,
                                                 remoteProcs,
                                                 remoteNProcs))) {
        ret = VIR_DAEMON_ERR_INIT;
        goto cleanup;
    }
    if (virNetServerAddProgram(srv, remoteProgram) < 0) {
        ret = VIR_DAEMON_ERR_INIT;
        goto cleanup;
    }

    if (!(lxcProgram = virNetServerProgramNew(LXC_PROGRAM,
                                              LXC_PROTOCOL_VERSION,
                                              lxcProcs,
                                              lxcNProcs))) {
        ret = VIR_DAEMON_ERR_INIT;
        goto cleanup;
    }
    if (virNetServerAddProgram(srv, lxcProgram) < 0) {
        ret = VIR_DAEMON_ERR_INIT;
        goto cleanup;
    }

    if (!(qemuProgram = virNetServerProgramNew(QEMU_PROGRAM,
                                               QEMU_PROTOCOL_VERSION,
                                               qemuProcs,
                                               qemuNProcs))) {
        ret = VIR_DAEMON_ERR_INIT;
        goto cleanup;
    }
    if (virNetServerAddProgram(srv, qemuProgram) < 0) {
        ret = VIR_DAEMON_ERR_INIT;
        goto cleanup;
    }

    if (!(srvAdm = virNetServerNew("admin", 1,
                                   config->admin_min_workers,
                                   config->admin_max_workers,
                                   0,
                                   config->admin_max_clients,
                                   0,
                                   config->admin_keepalive_interval,
                                   config->admin_keepalive_count,
                                   NULL,
                                   remoteAdmClientInitHook,
                                   NULL,
                                   remoteAdmClientFreeFunc,
                                   dmn))) {
        ret = VIR_DAEMON_ERR_INIT;
        goto cleanup;
    }

    if (virNetDaemonAddServer(dmn, srvAdm) < 0) {
        ret = VIR_DAEMON_ERR_INIT;
        goto cleanup;
    }

    if (!(adminProgram = virNetServerProgramNew(ADMIN_PROGRAM,
                                                ADMIN_PROTOCOL_VERSION,
                                                adminProcs,
                                                adminNProcs))) {
        ret = VIR_DAEMON_ERR_INIT;
        goto cleanup;
    }
    if (virNetServerAddProgram(srvAdm, adminProgram) < 0) {
        ret = VIR_DAEMON_ERR_INIT;
        goto cleanup;
    }

    if (timeout != -1) {
        VIR_DEBUG("Registering shutdown timeout %d", timeout);
        virNetDaemonAutoShutdown(dmn, timeout);
    }

    if ((daemonSetupSignals(dmn)) < 0) {
        ret = VIR_DAEMON_ERR_SIGNAL;
        goto cleanup;
    }

    if (config->audit_level) {
        VIR_DEBUG("Attempting to configure auditing subsystem");
        if (virAuditOpen() < 0) {
            if (config->audit_level > 1) {
                ret = VIR_DAEMON_ERR_AUDIT;
                goto cleanup;
            }
            VIR_DEBUG("Proceeding without auditing");
        }
    }
    virAuditLog(config->audit_logging > 0);

    /* setup the hooks if any */
    if (virHookInitialize() < 0) {
        ret = VIR_DAEMON_ERR_HOOKS;
        goto cleanup;
    }

    /* Disable error func, now logging is setup */
    virSetErrorFunc(NULL, daemonErrorHandler);
    virSetErrorLogPriorityFunc(daemonErrorLogFilter);

    /*
     * Call the daemon startup hook
     * TODO: should we abort the daemon startup if the script returned
     *       an error ?
     */
    virHookCall(VIR_HOOK_DRIVER_DAEMON, "-", VIR_HOOK_DAEMON_OP_START,
                0, "start", NULL, NULL);

    if (daemonSetupNetworking(srv, srvAdm,
                              config,
                              sock_file,
                              sock_file_ro,
                              sock_file_adm,
                              ipsock, privileged) < 0) {
        ret = VIR_DAEMON_ERR_NETWORK;
        goto cleanup;
    }

    /* Tell parent of daemon that basic initialization is complete
     * In particular we're ready to accept net connections & have
     * written the pidfile
     */
    if (statuswrite != -1) {
        char status = 0;
        while (write(statuswrite, &status, 1) == -1 &&
               errno == EINTR)
            ;
        VIR_FORCE_CLOSE(statuswrite);
    }

    /* Initialize drivers & then start accepting new clients from network */
    if (daemonStateInit(dmn) < 0) {
        ret = VIR_DAEMON_ERR_INIT;
        goto cleanup;
    }

#if defined(__linux__) && defined(NETLINK_ROUTE)
    /* Register the netlink event service for NETLINK_ROUTE */
    if (virNetlinkEventServiceStart(NETLINK_ROUTE, 0) < 0) {
        ret = VIR_DAEMON_ERR_NETWORK;
        goto cleanup;
    }
#endif

#if defined(__linux__) && defined(NETLINK_KOBJECT_UEVENT)
    /* Register the netlink event service for NETLINK_KOBJECT_UEVENT */
    if (virNetlinkEventServiceStart(NETLINK_KOBJECT_UEVENT, 1) < 0) {
        ret = VIR_DAEMON_ERR_NETWORK;
        goto cleanup;
    }
#endif

    /* Run event loop. */
    virNetDaemonRun(dmn);

    ret = 0;

    virHookCall(VIR_HOOK_DRIVER_DAEMON, "-", VIR_HOOK_DAEMON_OP_SHUTDOWN,
                0, "shutdown", NULL, NULL);

 cleanup:
    virNetlinkEventServiceStopAll();
    virObjectUnref(remoteProgram);
    virObjectUnref(lxcProgram);
    virObjectUnref(qemuProgram);
    virObjectUnref(adminProgram);
    virNetDaemonClose(dmn);
    virObjectUnref(srv);
    virObjectUnref(srvAdm);
    virNetlinkShutdown();
    if (statuswrite != -1) {
        if (ret != 0) {
            /* Tell parent of daemon what failed */
            char status = ret;
            while (write(statuswrite, &status, 1) == -1 &&
                   errno == EINTR)
                ;
        }
        VIR_FORCE_CLOSE(statuswrite);
    }
    if (pid_file_fd != -1)
        virPidFileReleasePath(pid_file, pid_file_fd);

    VIR_FREE(sock_file);
    VIR_FREE(sock_file_ro);
    VIR_FREE(sock_file_adm);
    VIR_FREE(pid_file);
    VIR_FREE(remote_config_file);
    VIR_FREE(run_dir);

    daemonConfigFree(config);

    if (driversInitialized) {
        driversInitialized = false;
        virStateCleanup();
    }
    /* Now that the hypervisor shutdown inhibition functions that use
     * 'dmn' as a parameter are done, we can finally unref 'dmn' */
    virObjectUnref(dmn);

    return ret;
}
