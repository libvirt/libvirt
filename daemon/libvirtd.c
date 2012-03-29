/*
 * libvirtd.c: daemon start of day, guest process & i/o management
 *
 * Copyright (C) 2006-2012 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
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
#include <locale.h>

#include "libvirt_internal.h"
#include "virterror_internal.h"
#include "virfile.h"
#include "virpidfile.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

#include "libvirtd.h"

#include "util.h"
#include "uuid.h"
#include "remote_driver.h"
#include "conf.h"
#include "memory.h"
#include "conf.h"
#include "virnetlink.h"
#include "virnetserver.h"
#include "threads.h"
#include "remote.h"
#include "remote_driver.h"
#include "hooks.h"
#include "uuid.h"
#include "viraudit.h"

#ifdef WITH_DRIVER_MODULES
# include "driver.h"
#else
# ifdef WITH_QEMU
#  include "qemu/qemu_driver.h"
# endif
# ifdef WITH_LXC
#  include "lxc/lxc_driver.h"
# endif
# ifdef WITH_LIBXL
#  include "libxl/libxl_driver.h"
# endif
# ifdef WITH_UML
#  include "uml/uml_driver.h"
# endif
# ifdef WITH_NETWORK
#  include "network/bridge_driver.h"
# endif
# ifdef WITH_NETCF
#  include "interface/netcf_driver.h"
# endif
# ifdef WITH_STORAGE_DIR
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

#include "configmake.h"

#if HAVE_SASL
virNetSASLContextPtr saslCtxt = NULL;
#endif
virNetServerProgramPtr remoteProgram = NULL;
virNetServerProgramPtr qemuProgram = NULL;

struct daemonConfig {
    char *host_uuid;

    int listen_tls;
    int listen_tcp;
    char *listen_addr;
    char *tls_port;
    char *tcp_port;

    char *unix_sock_ro_perms;
    char *unix_sock_rw_perms;
    char *unix_sock_group;
    char *unix_sock_dir;

    int auth_unix_rw;
    int auth_unix_ro;
    int auth_tcp;
    int auth_tls;

    int mdns_adv;
    char *mdns_name;

    int tls_no_verify_certificate;
    int tls_no_sanity_certificate;
    char **tls_allowed_dn_list;
    char **sasl_allowed_username_list;

    char *key_file;
    char *cert_file;
    char *ca_file;
    char *crl_file;

    int min_workers;
    int max_workers;
    int max_clients;

    int prio_workers;

    int max_requests;
    int max_client_requests;

    int log_level;
    char *log_filters;
    char *log_outputs;
    int log_buffer_size;

    int audit_level;
    int audit_logging;

    int keepalive_interval;
    unsigned int keepalive_count;
    int keepalive_required;
};

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

            if ((stdinfd = open("/dev/null", O_RDONLY)) < 0)
                goto cleanup;
            if ((stdoutfd = open("/dev/null", O_WRONLY)) < 0)
                goto cleanup;
            if (dup2(stdinfd, STDIN_FILENO) != STDIN_FILENO)
                goto cleanup;
            if (dup2(stdoutfd, STDOUT_FILENO) != STDOUT_FILENO)
                goto cleanup;
            if (dup2(stdoutfd, STDERR_FILENO) != STDERR_FILENO)
                goto cleanup;
            if (stdinfd > STDERR_FILENO && VIR_CLOSE(stdinfd) < 0)
                goto cleanup;
            if (stdoutfd > STDERR_FILENO && VIR_CLOSE(stdoutfd) < 0)
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
            if (virPidWait(pid, NULL) < 0)
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
daemonPidFilePath(bool privileged,
                  char **pidfile)
{
    if (privileged) {
        if (!(*pidfile = strdup(LOCALSTATEDIR "/run/libvirtd.pid")))
            goto no_memory;
    } else {
        char *userdir = NULL;

        if (!(userdir = virGetUserDirectory(geteuid())))
            goto error;

        if (virAsprintf(pidfile, "%s/.libvirt/libvirtd.pid", userdir) < 0) {
            VIR_FREE(userdir);
            goto no_memory;
        }

        VIR_FREE(userdir);
    }

    return 0;

no_memory:
    virReportOOMError();
error:
    return -1;
}

static int
daemonUnixSocketPaths(struct daemonConfig *config,
                      bool privileged,
                      char **sockfile,
                      char **rosockfile)
{
    if (config->unix_sock_dir) {
        if (virAsprintf(sockfile, "%s/libvirt-sock", config->unix_sock_dir) < 0)
            goto no_memory;
        if (privileged &&
            virAsprintf(rosockfile, "%s/libvirt-sock-ro", config->unix_sock_dir) < 0)
            goto no_memory;
    } else {
        if (privileged) {
            if (!(*sockfile = strdup(LOCALSTATEDIR "/run/libvirt/libvirt-sock")))
                goto no_memory;
            if (!(*rosockfile = strdup(LOCALSTATEDIR "/run/libvirt/libvirt-sock-ro")))
                goto no_memory;
        } else {
            char *userdir = NULL;

            if (!(userdir = virGetUserDirectory(geteuid())))
                goto error;

            if (virAsprintf(sockfile, "@%s/.libvirt/libvirt-sock", userdir) < 0) {
                VIR_FREE(userdir);
                goto no_memory;
            }

            VIR_FREE(userdir);
        }
    }
    return 0;

no_memory:
    virReportOOMError();
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
        return VIR_LOG_DEBUG;
    }

    return priority;
}

static void daemonInitialize(void)
{
    /*
     * Note that the order is important: the first ones have a higher
     * priority when calling virStateInitialize. We must register
     * the network, storage and nodedev drivers before any domain
     * drivers, since their resources must be auto-started before
     * any domains can be auto-started.
     */
#ifdef WITH_DRIVER_MODULES
    /* We don't care if any of these fail, because the whole point
     * is to allow users to only install modules they want to use.
     * If they try to open a connection for a module that
     * is not loaded they'll get a suitable error at that point
     */
    virDriverLoadModule("network");
    virDriverLoadModule("storage");
    virDriverLoadModule("nodedev");
    virDriverLoadModule("secret");
    virDriverLoadModule("qemu");
    virDriverLoadModule("lxc");
    virDriverLoadModule("uml");
    virDriverLoadModule("nwfilter");
#else
# ifdef WITH_NETWORK
    networkRegister();
# endif
# ifdef WITH_NETCF
    interfaceRegister();
# endif
# ifdef WITH_STORAGE_DIR
    storageRegister();
# endif
# if defined(WITH_NODE_DEVICES)
    nodedevRegister();
# endif
# ifdef WITH_SECRETS
    secretRegister();
# endif
# ifdef WITH_NWFILTER
    nwfilterRegister();
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
#endif
}


static int daemonSetupNetworking(virNetServerPtr srv,
                                 struct daemonConfig *config,
                                 const char *sock_path,
                                 const char *sock_path_ro,
                                 bool ipsock,
                                 bool privileged)
{
    virNetServerServicePtr svc = NULL;
    virNetServerServicePtr svcRO = NULL;
    virNetServerServicePtr svcTCP = NULL;
    virNetServerServicePtr svcTLS = NULL;
    gid_t unix_sock_gid = 0;
    int unix_sock_ro_mask = 0;
    int unix_sock_rw_mask = 0;

    if (config->unix_sock_group) {
        if (virGetGroupID(config->unix_sock_group, &unix_sock_gid) < 0)
            return -1;
    }

    if (virStrToLong_i(config->unix_sock_ro_perms, NULL, 8, &unix_sock_ro_mask) != 0) {
        VIR_ERROR(_("Failed to parse mode '%s'"), config->unix_sock_ro_perms);
        goto error;
    }

    if (virStrToLong_i(config->unix_sock_rw_perms, NULL, 8, &unix_sock_rw_mask) != 0) {
        VIR_ERROR(_("Failed to parse mode '%s'"), config->unix_sock_rw_perms);
        goto error;
    }

    if (!(svc = virNetServerServiceNewUNIX(sock_path,
                                           unix_sock_rw_mask,
                                           unix_sock_gid,
                                           config->auth_unix_rw,
                                           false,
                                           config->max_client_requests,
                                           NULL)))
        goto error;
    if (sock_path_ro &&
        !(svcRO = virNetServerServiceNewUNIX(sock_path_ro,
                                             unix_sock_ro_mask,
                                             unix_sock_gid,
                                             config->auth_unix_ro,
                                             true,
                                             config->max_client_requests,
                                             NULL)))
        goto error;

    if (virNetServerAddService(srv, svc,
                               config->mdns_adv && !ipsock ?
                               "_libvirt._tcp" :
                               NULL) < 0)
        goto error;

    if (svcRO &&
        virNetServerAddService(srv, svcRO, NULL) < 0)
        goto error;

    if (ipsock) {
        if (config->listen_tcp) {
            if (!(svcTCP = virNetServerServiceNewTCP(config->listen_addr,
                                                     config->tcp_port,
                                                     config->auth_tcp,
                                                     false,
                                                     config->max_client_requests,
                                                     NULL)))
                goto error;

            if (virNetServerAddService(srv, svcTCP,
                                       config->mdns_adv ? "_libvirt._tcp" : NULL) < 0)
                goto error;
        }

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
                                                       config->tls_no_sanity_certificate ? false : true,
                                                       config->tls_no_verify_certificate ? false : true)))
                    goto error;
            } else {
                if (!(ctxt = virNetTLSContextNewServerPath(NULL,
                                                           !privileged,
                                                           (const char *const*)config->tls_allowed_dn_list,
                                                           config->tls_no_sanity_certificate ? false : true,
                                                           config->tls_no_verify_certificate ? false : true)))
                    goto error;
            }

            if (!(svcTLS =
                  virNetServerServiceNewTCP(config->listen_addr,
                                            config->tls_port,
                                            config->auth_tls,
                                            false,
                                            config->max_client_requests,
                                            ctxt))) {
                virNetTLSContextFree(ctxt);
                goto error;
            }
            if (virNetServerAddService(srv, svcTLS,
                                       config->mdns_adv &&
                                       !config->listen_tcp ? "_libvirt._tcp" : NULL) < 0)
                goto error;

            virNetTLSContextFree(ctxt);
        }
    }

#if HAVE_SASL
    if (config->auth_unix_rw == REMOTE_AUTH_SASL ||
        config->auth_unix_ro == REMOTE_AUTH_SASL ||
        config->auth_tcp == REMOTE_AUTH_SASL ||
        config->auth_tls == REMOTE_AUTH_SASL) {
        saslCtxt = virNetSASLContextNewServer(
            (const char *const*)config->sasl_allowed_username_list);
        if (!saslCtxt)
            goto error;
    }
#endif

    return 0;

error:
    virNetServerServiceFree(svcTLS);
    virNetServerServiceFree(svcTCP);
    virNetServerServiceFree(svc);
    virNetServerServiceFree(svcRO);
    return -1;
}


static int daemonShutdownCheck(virNetServerPtr srv ATTRIBUTE_UNUSED,
                               void *opaque ATTRIBUTE_UNUSED)
{
    if (virStateActive())
        return 0;

    return 1;
}


/* Allocate an array of malloc'd strings from the config file, filename
 * (used only in diagnostics), using handle "conf".  Upon error, return -1
 * and free any allocated memory.  Otherwise, save the array in *list_arg
 * and return 0.
 */
static int
remoteConfigGetStringList(virConfPtr conf, const char *key, char ***list_arg,
                          const char *filename)
{
    char **list;
    virConfValuePtr p = virConfGetValue (conf, key);
    if (!p)
        return 0;

    switch (p->type) {
    case VIR_CONF_STRING:
        if (VIR_ALLOC_N(list, 2) < 0) {
            VIR_ERROR(_("failed to allocate memory for %s config list"), key);
            return -1;
        }
        list[0] = strdup (p->str);
        list[1] = NULL;
        if (list[0] == NULL) {
            VIR_ERROR(_("failed to allocate memory for %s config list value"),
                      key);
            VIR_FREE(list);
            return -1;
        }
        break;

    case VIR_CONF_LIST: {
        int i, len = 0;
        virConfValuePtr pp;
        for (pp = p->list; pp; pp = pp->next)
            len++;
        if (VIR_ALLOC_N(list, 1+len) < 0) {
            VIR_ERROR(_("failed to allocate memory for %s config list"), key);
            return -1;
        }
        for (i = 0, pp = p->list; pp; ++i, pp = pp->next) {
            if (pp->type != VIR_CONF_STRING) {
                VIR_ERROR(_("remoteReadConfigFile: %s: %s:"
                            " must be a string or list of strings"),
                          filename, key);
                VIR_FREE(list);
                return -1;
            }
            list[i] = strdup (pp->str);
            if (list[i] == NULL) {
                int j;
                for (j = 0 ; j < i ; j++)
                    VIR_FREE(list[j]);
                VIR_FREE(list);
                VIR_ERROR(_("failed to allocate memory for %s config list value"),
                          key);
                return -1;
            }

        }
        list[i] = NULL;
        break;
    }

    default:
        VIR_ERROR(_("remoteReadConfigFile: %s: %s:"
                    " must be a string or list of strings"),
                  filename, key);
        return -1;
    }

    *list_arg = list;
    return 0;
}

/* A helper function used by each of the following macros.  */
static int
checkType (virConfValuePtr p, const char *filename,
           const char *key, virConfType required_type)
{
    if (p->type != required_type) {
        VIR_ERROR(_("remoteReadConfigFile: %s: %s: invalid type:"
                    " got %s; expected %s"), filename, key,
                  virConfTypeName (p->type),
                  virConfTypeName (required_type));
        return -1;
    }
    return 0;
}

/* If there is no config data for the key, #var_name, then do nothing.
   If there is valid data of type VIR_CONF_STRING, and strdup succeeds,
   store the result in var_name.  Otherwise, (i.e. invalid type, or strdup
   failure), give a diagnostic and "goto" the cleanup-and-fail label.  */
#define GET_CONF_STR(conf, filename, var_name)                          \
    do {                                                                \
        virConfValuePtr p = virConfGetValue (conf, #var_name);          \
        if (p) {                                                        \
            if (checkType (p, filename, #var_name, VIR_CONF_STRING) < 0) \
                goto error;                                             \
            VIR_FREE(data->var_name);                                   \
            if (!(data->var_name = strdup (p->str))) {                  \
                virReportOOMError();                                    \
                goto error;                                             \
            }                                                           \
        }                                                               \
    } while (0)

/* Like GET_CONF_STR, but for integral values.  */
#define GET_CONF_INT(conf, filename, var_name)                          \
    do {                                                                \
        virConfValuePtr p = virConfGetValue (conf, #var_name);          \
        if (p) {                                                        \
            if (checkType (p, filename, #var_name, VIR_CONF_LONG) < 0)  \
                goto error;                                             \
            data->var_name = p->l;                                      \
        }                                                               \
    } while (0)


static int remoteConfigGetAuth(virConfPtr conf, const char *key, int *auth, const char *filename) {
    virConfValuePtr p;

    p = virConfGetValue (conf, key);
    if (!p)
        return 0;

    if (checkType (p, filename, key, VIR_CONF_STRING) < 0)
        return -1;

    if (!p->str)
        return 0;

    if (STREQ(p->str, "none")) {
        *auth = VIR_NET_SERVER_SERVICE_AUTH_NONE;
#if HAVE_SASL
    } else if (STREQ(p->str, "sasl")) {
        *auth = VIR_NET_SERVER_SERVICE_AUTH_SASL;
#endif
    } else if (STREQ(p->str, "polkit")) {
        *auth = VIR_NET_SERVER_SERVICE_AUTH_POLKIT;
    } else {
        VIR_ERROR(_("remoteReadConfigFile: %s: %s: unsupported auth %s"),
                  filename, key, p->str);
        return -1;
    }

    return 0;
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
     * In order to achieve this, we must process configuration in
     * different order for the log level versus the filters and
     * outputs. Because filters and outputs append, we have to look at
     * the environment first and then only check the config file if
     * there was no result from the environment. The default output is
     * then applied only if there was no setting from either of the
     * first two. Because we don't have a way to determine if the log
     * level has been set, we must process variables in the opposite
     * order, each one overriding the previous.
     */
    if (config->log_level != 0)
        virLogSetDefaultPriority(config->log_level);

    virLogSetFromEnv();

    virLogSetBufferSize(config->log_buffer_size);

    if (virLogGetNbFilters() == 0)
        virLogParseFilters(config->log_filters);

    if (virLogGetNbOutputs() == 0)
        virLogParseOutputs(config->log_outputs);

    /*
     * If no defined outputs, then direct to libvirtd.log when running
     * as daemon. Otherwise the default output is stderr.
     */
    if (virLogGetNbOutputs() == 0) {
        char *tmp = NULL;

        if (godaemon) {
            if (privileged) {
                if (virAsprintf(&tmp, "%d:file:%s/log/libvirt/libvirtd.log",
                                virLogGetDefaultPriority(),
                                LOCALSTATEDIR) == -1)
                    goto no_memory;
            } else {
                char *userdir = virGetUserDirectory(geteuid());
                if (!userdir)
                    goto error;

                if (virAsprintf(&tmp, "%d:file:%s/.libvirt/libvirtd.log",
                                virLogGetDefaultPriority(), userdir) == -1) {
                    VIR_FREE(userdir);
                    goto no_memory;
                }
                VIR_FREE(userdir);
            }
        } else {
            if (virAsprintf(&tmp, "%d:stderr", virLogGetDefaultPriority()) < 0)
                goto no_memory;
        }
        virLogParseOutputs(tmp);
        VIR_FREE(tmp);
    }

    /*
     * Command line override for --verbose
     */
    if ((verbose) && (virLogGetDefaultPriority() > VIR_LOG_INFO))
        virLogSetDefaultPriority(VIR_LOG_INFO);

    return 0;

no_memory:
    virReportOOMError();
error:
    return -1;
}


static int
daemonConfigFilePath(bool privileged, char **configfile)
{
    if (privileged) {
        if (!(*configfile = strdup(SYSCONFDIR "/libvirt/libvirtd.conf")))
            goto no_memory;
    } else {
        char *userdir = NULL;

        if (!(userdir = virGetUserDirectory(geteuid())))
            goto error;

        if (virAsprintf(configfile, "%s/.libvirt/libvirtd.conf", userdir) < 0) {
            VIR_FREE(userdir);
            goto no_memory;
        }
        VIR_FREE(userdir);
    }

    return 0;

no_memory:
    virReportOOMError();
error:
    return -1;
}

static void
daemonConfigFree(struct daemonConfig *data);

static struct daemonConfig*
daemonConfigNew(bool privileged ATTRIBUTE_UNUSED)
{
    struct daemonConfig *data;
    char *localhost;
    int ret;

    if (VIR_ALLOC(data) < 0) {
        virReportOOMError();
        return NULL;
    }

    data->listen_tls = 1;
    data->listen_tcp = 0;

    if (!(data->tls_port = strdup(LIBVIRTD_TLS_PORT)))
        goto no_memory;
    if (!(data->tcp_port = strdup(LIBVIRTD_TCP_PORT)))
        goto no_memory;

    /* Only default to PolicyKit if running as root */
#if HAVE_POLKIT
    if (privileged) {
        data->auth_unix_rw = REMOTE_AUTH_POLKIT;
        data->auth_unix_ro = REMOTE_AUTH_POLKIT;
    } else {
#endif
        data->auth_unix_rw = REMOTE_AUTH_NONE;
        data->auth_unix_ro = REMOTE_AUTH_NONE;
#if HAVE_POLKIT
    }
#endif

    if (data->auth_unix_rw == REMOTE_AUTH_POLKIT)
        data->unix_sock_rw_perms = strdup("0777"); /* Allow world */
    else
        data->unix_sock_rw_perms = strdup("0700"); /* Allow user only */
    data->unix_sock_ro_perms = strdup("0777"); /* Always allow world */
    if (!data->unix_sock_ro_perms ||
        !data->unix_sock_rw_perms)
        goto no_memory;

#if HAVE_SASL
    data->auth_tcp = REMOTE_AUTH_SASL;
#else
    data->auth_tcp = REMOTE_AUTH_NONE;
#endif
    data->auth_tls = REMOTE_AUTH_NONE;

    data->mdns_adv = 0;

    data->min_workers = 5;
    data->max_workers = 20;
    data->max_clients = 20;

    data->prio_workers = 5;

    data->max_requests = 20;
    data->max_client_requests = 5;

    data->log_buffer_size = 64;

    data->audit_level = 1;
    data->audit_logging = 0;

    data->keepalive_interval = 5;
    data->keepalive_count = 5;
    data->keepalive_required = 0;

    localhost = virGetHostname(NULL);
    if (localhost == NULL) {
        /* we couldn't resolve the hostname; assume that we are
         * running in disconnected operation, and report a less
         * useful Avahi string
         */
        ret = virAsprintf(&data->mdns_name, "Virtualization Host");
    } else {
        char *tmp;
        /* Extract the host part of the potentially FQDN */
        if ((tmp = strchr(localhost, '.')))
            *tmp = '\0';
        ret = virAsprintf(&data->mdns_name, "Virtualization Host %s",
                          localhost);
    }
    VIR_FREE(localhost);
    if (ret < 0)
        goto no_memory;

    return data;

no_memory:
    virReportOOMError();
    daemonConfigFree(data);
    return NULL;
}

static void
daemonConfigFree(struct daemonConfig *data)
{
    char **tmp;

    if (!data)
        return;

    VIR_FREE(data->listen_addr);
    VIR_FREE(data->tls_port);
    VIR_FREE(data->tcp_port);

    VIR_FREE(data->unix_sock_ro_perms);
    VIR_FREE(data->unix_sock_rw_perms);
    VIR_FREE(data->unix_sock_group);
    VIR_FREE(data->unix_sock_dir);
    VIR_FREE(data->mdns_name);

    tmp = data->tls_allowed_dn_list;
    while (tmp && *tmp) {
        VIR_FREE(*tmp);
        tmp++;
    }
    VIR_FREE(data->tls_allowed_dn_list);

    tmp = data->sasl_allowed_username_list;
    while (tmp && *tmp) {
        VIR_FREE(*tmp);
        tmp++;
    }
    VIR_FREE(data->sasl_allowed_username_list);

    VIR_FREE(data->key_file);
    VIR_FREE(data->ca_file);
    VIR_FREE(data->cert_file);
    VIR_FREE(data->crl_file);

    VIR_FREE(data->log_filters);
    VIR_FREE(data->log_outputs);

    VIR_FREE(data);
}


/* Read the config file if it exists.
 * Only used in the remote case, hence the name.
 */
static int
daemonConfigLoad(struct daemonConfig *data,
                 const char *filename,
                 bool allow_missing)
{
    virConfPtr conf;

    if (allow_missing &&
        access(filename, R_OK) == -1 &&
        errno == ENOENT)
        return 0;

    conf = virConfReadFile (filename, 0);
    if (!conf)
        return -1;

    GET_CONF_INT (conf, filename, listen_tcp);
    GET_CONF_INT (conf, filename, listen_tls);
    GET_CONF_STR (conf, filename, tls_port);
    GET_CONF_STR (conf, filename, tcp_port);
    GET_CONF_STR (conf, filename, listen_addr);

    if (remoteConfigGetAuth(conf, "auth_unix_rw", &data->auth_unix_rw, filename) < 0)
        goto error;
#if HAVE_POLKIT
    /* Change default perms to be wide-open if PolicyKit is enabled.
     * Admin can always override in config file
     */
    if (data->auth_unix_rw == REMOTE_AUTH_POLKIT) {
        VIR_FREE(data->unix_sock_rw_perms);
        if (!(data->unix_sock_rw_perms = strdup("0777"))) {
            virReportOOMError();
            goto error;
        }
    }
#endif
    if (remoteConfigGetAuth(conf, "auth_unix_ro", &data->auth_unix_ro, filename) < 0)
        goto error;
    if (remoteConfigGetAuth(conf, "auth_tcp", &data->auth_tcp, filename) < 0)
        goto error;
    if (remoteConfigGetAuth(conf, "auth_tls", &data->auth_tls, filename) < 0)
        goto error;

    GET_CONF_STR (conf, filename, unix_sock_group);
    GET_CONF_STR (conf, filename, unix_sock_ro_perms);
    GET_CONF_STR (conf, filename, unix_sock_rw_perms);

    GET_CONF_STR (conf, filename, unix_sock_dir);

    GET_CONF_INT (conf, filename, mdns_adv);
    GET_CONF_STR (conf, filename, mdns_name);

    GET_CONF_INT (conf, filename, tls_no_sanity_certificate);
    GET_CONF_INT (conf, filename, tls_no_verify_certificate);

    GET_CONF_STR (conf, filename, key_file);
    GET_CONF_STR (conf, filename, cert_file);
    GET_CONF_STR (conf, filename, ca_file);
    GET_CONF_STR (conf, filename, crl_file);

    if (remoteConfigGetStringList(conf, "tls_allowed_dn_list",
                                  &data->tls_allowed_dn_list, filename) < 0)
        goto error;


    if (remoteConfigGetStringList(conf, "sasl_allowed_username_list",
                                  &data->sasl_allowed_username_list, filename) < 0)
        goto error;


    GET_CONF_INT (conf, filename, min_workers);
    GET_CONF_INT (conf, filename, max_workers);
    GET_CONF_INT (conf, filename, max_clients);

    GET_CONF_INT (conf, filename, prio_workers);

    GET_CONF_INT (conf, filename, max_requests);
    GET_CONF_INT (conf, filename, max_client_requests);

    GET_CONF_INT (conf, filename, audit_level);
    GET_CONF_INT (conf, filename, audit_logging);

    GET_CONF_STR (conf, filename, host_uuid);

    GET_CONF_INT (conf, filename, log_level);
    GET_CONF_STR (conf, filename, log_filters);
    GET_CONF_STR (conf, filename, log_outputs);
    GET_CONF_INT (conf, filename, log_buffer_size);

    GET_CONF_INT (conf, filename, keepalive_interval);
    GET_CONF_INT (conf, filename, keepalive_count);
    GET_CONF_INT (conf, filename, keepalive_required);

    virConfFree (conf);
    return 0;

error:
    virConfFree (conf);
    return -1;
}

/* Display version information. */
static void
daemonVersion(const char *argv0)
{
    printf ("%s (%s) %s\n", argv0, PACKAGE_NAME, PACKAGE_VERSION);
}

#ifdef __sun
static int
daemonSetupPrivs(void)
{
    chown ("/var/run/libvirt", SYSTEM_UID, SYSTEM_UID);

    if (__init_daemon_priv (PU_RESETGROUPS | PU_CLEARLIMITSET,
        SYSTEM_UID, SYSTEM_UID, PRIV_XVM_CONTROL, NULL)) {
        VIR_ERROR(_("additional privileges are required"));
        return -1;
    }

    if (priv_set (PRIV_OFF, PRIV_ALLSETS, PRIV_FILE_LINK_ANY, PRIV_PROC_INFO,
        PRIV_PROC_SESSION, PRIV_PROC_EXEC, PRIV_PROC_FORK, NULL)) {
        VIR_ERROR(_("failed to set reduced privileges"));
        return -1;
    }

    return 0;
}
#else
# define daemonSetupPrivs() 0
#endif


static void daemonShutdownHandler(virNetServerPtr srv,
                                  siginfo_t *sig ATTRIBUTE_UNUSED,
                                  void *opaque ATTRIBUTE_UNUSED)
{
    virNetServerQuit(srv);
}

static void daemonReloadHandler(virNetServerPtr srv ATTRIBUTE_UNUSED,
                                siginfo_t *sig ATTRIBUTE_UNUSED,
                                void *opaque ATTRIBUTE_UNUSED)
{
        VIR_INFO("Reloading configuration on SIGHUP");
        virHookCall(VIR_HOOK_DRIVER_DAEMON, "-",
                    VIR_HOOK_DAEMON_OP_RELOAD, SIGHUP, "SIGHUP", NULL, NULL);
        if (virStateReload() < 0)
            VIR_WARN("Error while reloading drivers");
}

static int daemonSetupSignals(virNetServerPtr srv)
{
    if (virNetServerAddSignalHandler(srv, SIGINT, daemonShutdownHandler, NULL) < 0)
        return -1;
    if (virNetServerAddSignalHandler(srv, SIGQUIT, daemonShutdownHandler, NULL) < 0)
        return -1;
    if (virNetServerAddSignalHandler(srv, SIGTERM, daemonShutdownHandler, NULL) < 0)
        return -1;
    if (virNetServerAddSignalHandler(srv, SIGHUP, daemonReloadHandler, NULL) < 0)
        return -1;
    return 0;
}

static void daemonRunStateInit(void *opaque)
{
    virNetServerPtr srv = opaque;

    /* Start the stateful HV drivers
     * This is deliberately done after telling the parent process
     * we're ready, since it can take a long time and this will
     * seriously delay OS bootup process */
    if (virStateInitialize(virNetServerIsPrivileged(srv)) < 0) {
        VIR_ERROR(_("Driver state initialization failed"));
        /* Ensure the main event loop quits */
        kill(getpid(), SIGTERM);
        virNetServerFree(srv);
        return;
    }

    /* Only now accept clients from network */
    virNetServerUpdateServices(srv, true);
    virNetServerFree(srv);
}

static int daemonStateInit(virNetServerPtr srv)
{
    virThread thr;
    virNetServerRef(srv);
    if (virThreadCreate(&thr, false, daemonRunStateInit, srv) < 0) {
        virNetServerFree(srv);
        return -1;
    }
    return 0;
}

/* Print command-line usage. */
static void
daemonUsage(const char *argv0, bool privileged)
{
    fprintf (stderr,
             _("\n\
Usage:\n\
  %s [options]\n\
\n\
Options:\n\
  -v | --verbose         Verbose messages.\n\
  -d | --daemon          Run as a daemon & write PID file.\n\
  -l | --listen          Listen for TCP/IP connections.\n\
  -t | --timeout <secs>  Exit after timeout period.\n\
  -f | --config <file>   Configuration file.\n\
     | --version         Display version information.\n\
  -p | --pid-file <file> Change name of PID file.\n\
\n\
libvirt management daemon:\n"), argv0);

    if (privileged) {
        fprintf(stderr,
                _("\n\
  Default paths:\n\
\n\
    Configuration file (unless overridden by -f):\n\
      %s/libvirt/libvirtd.conf\n\
\n\
    Sockets:\n\
      %s/run/libvirt/libvirt-sock\n\
      %s/run/libvirt/libvirt-sock-ro\n\
\n\
    TLS:\n\
      CA certificate:     %s/pki/CA/caert.pem\n\
      Server certificate: %s/pki/libvirt/servercert.pem\n\
      Server private key: %s/pki/libvirt/private/serverkey.pem\n\
\n\
    PID file (unless overridden by -p):\n\
      %s/run/libvirtd.pid\n\
\n"),
                SYSCONFDIR,
                LOCALSTATEDIR,
                LOCALSTATEDIR,
                SYSCONFDIR,
                SYSCONFDIR,
                SYSCONFDIR,
                LOCALSTATEDIR);
    } else {
        fprintf(stderr,
                "%s", _("\n\
  Default paths:\n\
\n\
    Configuration file (unless overridden by -f):\n\
      $HOME/.libvirt/libvirtd.conf\n\
\n\
    Sockets:\n\
      $HOME/.libvirt/libvirt-sock (in UNIX abstract namespace)\n\
\n\
    TLS:\n\
      CA certificate:     $HOME/.pki/libvirt/cacert.pem\n\
      Server certificate: $HOME/.pki/libvirt/servercert.pem\n\
      Server private key: $HOME/.pki/libvirt/serverkey.pem\n\
\n\
    PID file:\n\
      $HOME/.libvirt/libvirtd.pid\n\
\n"));
    }
}

enum {
    OPT_VERSION = 129
};

#define MAX_LISTEN 5
int main(int argc, char **argv) {
    virNetServerPtr srv = NULL;
    char *remote_config_file = NULL;
    int statuswrite = -1;
    int ret = 1;
    int pid_file_fd = -1;
    char *pid_file = NULL;
    char *sock_file = NULL;
    char *sock_file_ro = NULL;
    int timeout = -1;        /* -t: Shutdown timeout */
    int verbose = 0;
    int godaemon = 0;
    int ipsock = 0;
    struct daemonConfig *config;
    bool privileged = geteuid() == 0 ? true : false;
    bool implicit_conf = false;
    bool use_polkit_dbus;
    char *run_dir = NULL;
    mode_t old_umask;

    struct option opts[] = {
        { "verbose", no_argument, &verbose, 1},
        { "daemon", no_argument, &godaemon, 1},
        { "listen", no_argument, &ipsock, 1},
        { "config", required_argument, NULL, 'f'},
        { "timeout", required_argument, NULL, 't'},
        { "pid-file", required_argument, NULL, 'p'},
        { "version", no_argument, NULL, OPT_VERSION },
        { "help", no_argument, NULL, '?' },
        {0, 0, 0, 0}
    };

    if (setlocale (LC_ALL, "") == NULL ||
        bindtextdomain (PACKAGE, LOCALEDIR) == NULL ||
        textdomain(PACKAGE) == NULL ||
        virInitialize() < 0) {
        fprintf(stderr, _("%s: initialization failed\n"), argv[0]);
        exit(EXIT_FAILURE);
    }

    /* initialize early logging */
    virLogSetFromEnv();

    while (1) {
        int optidx = 0;
        int c;
        char *tmp;

        c = getopt_long(argc, argv, "ldf:p:t:v", opts, &optidx);

        if (c == -1) {
            break;
        }

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
            if (!(pid_file = strdup(optarg))) {
                VIR_ERROR(_("Can't allocate memory"));
                exit(EXIT_FAILURE);
            }
            break;

        case 'f':
            VIR_FREE(remote_config_file);
            if (!(remote_config_file = strdup(optarg))) {
                VIR_ERROR(_("Can't allocate memory"));
                exit(EXIT_FAILURE);
            }
            break;

        case OPT_VERSION:
            daemonVersion(argv[0]);
            return 0;

        case '?':
            daemonUsage(argv[0], privileged);
            return 2;

        default:
            VIR_ERROR(_("%s: internal error: unknown flag: %c"),
                      argv[0], c);
            exit (EXIT_FAILURE);
        }
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
        daemonConfigLoad(config, remote_config_file, implicit_conf) < 0) {
        VIR_ERROR(_("Can't load config file '%s'"), remote_config_file);
        exit(EXIT_FAILURE);
    }

    if (config->host_uuid &&
        virSetHostUUIDStr(config->host_uuid) < 0) {
        VIR_ERROR(_("invalid host UUID: %s"), config->host_uuid);
        exit(EXIT_FAILURE);
    }

    if (daemonSetupLogging(config, privileged, verbose, godaemon) < 0) {
        VIR_ERROR(_("Can't initialize logging"));
        exit(EXIT_FAILURE);
    }

    if (!pid_file &&
        daemonPidFilePath(privileged,
                          &pid_file) < 0) {
        VIR_ERROR(_("Can't determine pid file path."));
        exit(EXIT_FAILURE);
    }

    if (daemonUnixSocketPaths(config,
                              privileged,
                              &sock_file,
                              &sock_file_ro) < 0) {
        VIR_ERROR(_("Can't determine socket paths"));
        exit(EXIT_FAILURE);
    }

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
        run_dir = strdup(LOCALSTATEDIR "/run/libvirt");
    } else {
        char *user_dir = virGetUserDirectory(geteuid());

        if (!user_dir) {
            VIR_ERROR(_("Can't determine user directory"));
            goto cleanup;
        }
        ignore_value(virAsprintf(&run_dir, "%s/.libvirt/", user_dir));
        VIR_FREE(user_dir);
    }
    if (!run_dir) {
        virReportOOMError();
        goto cleanup;
    }

    old_umask = umask(022);
    if (virFileMakePath(run_dir) < 0) {
        char ebuf[1024];
        VIR_ERROR(_("unable to create rundir %s: %s"), run_dir,
                  virStrerror(errno, ebuf, sizeof(ebuf)));
        ret = VIR_DAEMON_ERR_RUNDIR;
        goto cleanup;
    }
    umask(old_umask);

    /* Try to claim the pidfile, exiting if we can't */
    if ((pid_file_fd = virPidFileAcquirePath(pid_file, getpid())) < 0) {
        ret = VIR_DAEMON_ERR_PIDFILE;
        goto cleanup;
    }

    use_polkit_dbus = config->auth_unix_rw == REMOTE_AUTH_POLKIT ||
            config->auth_unix_ro == REMOTE_AUTH_POLKIT;
    if (!(srv = virNetServerNew(config->min_workers,
                                config->max_workers,
                                config->prio_workers,
                                config->max_clients,
                                config->keepalive_interval,
                                config->keepalive_count,
                                !!config->keepalive_required,
                                config->mdns_adv ? config->mdns_name : NULL,
                                use_polkit_dbus,
                                remoteClientInitHook))) {
        ret = VIR_DAEMON_ERR_INIT;
        goto cleanup;
    }

    /* Beyond this point, nothing should rely on using
     * getuid/geteuid() == 0, for privilege level checks.
     */
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

    if (timeout != -1)
        virNetServerAutoShutdown(srv,
                                 timeout,
                                 daemonShutdownCheck,
                                 NULL);

    if ((daemonSetupSignals(srv)) < 0) {
        ret = VIR_DAEMON_ERR_SIGNAL;
        goto cleanup;
    }

    if (config->audit_level) {
        if (virAuditOpen() < 0) {
            if (config->audit_level > 1) {
                ret = VIR_DAEMON_ERR_AUDIT;
                goto cleanup;
            }
        }
    }
    virAuditLog(config->audit_logging);

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

    if (daemonSetupNetworking(srv, config,
                              sock_file, sock_file_ro,
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
    if (daemonStateInit(srv) < 0) {
        ret = VIR_DAEMON_ERR_INIT;
        goto cleanup;
    }

    /* Register the netlink event service */
    if (virNetlinkEventServiceStart() < 0) {
        ret = VIR_DAEMON_ERR_NETWORK;
        goto cleanup;
    }

    /* Run event loop. */
    virNetServerRun(srv);

    ret = 0;

    virHookCall(VIR_HOOK_DRIVER_DAEMON, "-", VIR_HOOK_DAEMON_OP_SHUTDOWN,
                0, "shutdown", NULL, NULL);

cleanup:
    virNetlinkEventServiceStop();
    virNetServerProgramFree(remoteProgram);
    virNetServerProgramFree(qemuProgram);
    virNetServerClose(srv);
    virNetServerFree(srv);
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
    VIR_FREE(pid_file);
    VIR_FREE(remote_config_file);
    VIR_FREE(run_dir);

    daemonConfigFree(config);
    virLogShutdown();

    return ret;
}
