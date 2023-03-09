/*
 * remote_daemon_config.c: libvirtd config file handling
 *
 * Copyright (C) 2006-2018 Red Hat, Inc.
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
 */

#include <config.h>

#include "remote_daemon_config.h"
#include "virconf.h"
#include "viralloc.h"
#include "virerror.h"
#include "virlog.h"
#include "rpc/virnetserver.h"
#include "configmake.h"
#include "remote_protocol.h"
#include "remote_driver.h"
#include "util/virnetdevopenvswitch.h"
#include "virutil.h"

#define VIR_FROM_THIS VIR_FROM_CONF

VIR_LOG_INIT("daemon.libvirtd-config");


static int
remoteConfigGetAuth(virConf *conf,
                    const char *filename,
                    const char *key,
                    int *auth)
{
    char *authstr = NULL;

    if (virConfGetValueString(conf, key, &authstr) < 0)
        return -1;

    if (!authstr)
        return 0;

    if (STREQ(authstr, "none")) {
        *auth = VIR_NET_SERVER_SERVICE_AUTH_NONE;
#if WITH_SASL
    } else if (STREQ(authstr, "sasl")) {
        *auth = VIR_NET_SERVER_SERVICE_AUTH_SASL;
#endif
    } else if (STREQ(authstr, "polkit")) {
        *auth = VIR_NET_SERVER_SERVICE_AUTH_POLKIT;
    } else {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("%1$s: %2$s: unsupported auth %3$s"),
                       filename, key, authstr);
        VIR_FREE(authstr);
        return -1;
    }

    VIR_FREE(authstr);
    return 0;
}

void
daemonConfigFilePath(bool privileged, char **configfile)
{
    if (privileged) {
        *configfile = g_strdup(SYSCONFDIR "/libvirt/" DAEMON_NAME ".conf");
    } else {
        g_autofree char *configdir = NULL;

        configdir = virGetUserConfigDirectory();

        *configfile = g_strdup_printf("%s/%s.conf", configdir, DAEMON_NAME);
    }
}

struct daemonConfig*
daemonConfigNew(bool privileged G_GNUC_UNUSED)
{
    struct daemonConfig *data;

    data = g_new0(struct daemonConfig, 1);

#ifdef WITH_IP
# ifdef LIBVIRTD
    data->listen_tls = true; /* Only honoured if --listen is set */
# else /* ! LIBVIRTD */
    data->listen_tls = false; /* Always honoured, --listen doesn't exist. */
# endif /* ! LIBVIRTD */
    data->listen_tcp = false;

    data->tls_port = g_strdup(LIBVIRTD_TLS_PORT);
    data->tcp_port = g_strdup(LIBVIRTD_TCP_PORT);
#endif /* !WITH_IP */

    /* Only default to PolicyKit if running as root */
#if WITH_POLKIT
    if (privileged) {
        data->auth_unix_rw = REMOTE_AUTH_POLKIT;
        data->auth_unix_ro = REMOTE_AUTH_POLKIT;
    } else {
#endif
        data->auth_unix_rw = REMOTE_AUTH_NONE;
        data->auth_unix_ro = REMOTE_AUTH_NONE;
#if WITH_POLKIT
    }
#endif

    data->unix_sock_rw_perms = g_strdup(data->auth_unix_rw == REMOTE_AUTH_POLKIT ? "0777" : "0700");
    data->unix_sock_ro_perms = g_strdup("0777");
    data->unix_sock_admin_perms = g_strdup("0700");

#ifdef WITH_IP
# if WITH_SASL
    data->auth_tcp = REMOTE_AUTH_SASL;
# else
    data->auth_tcp = REMOTE_AUTH_NONE;
# endif
    data->auth_tls = REMOTE_AUTH_NONE;
#endif /* ! WITH_IP */

#if WITH_IP
    data->tcp_min_ssf = 56; /* good enough for kerberos */
#endif

    data->min_workers = 5;
    data->max_workers = 20;
    data->max_clients = 5000;
    data->max_queued_clients = 1000;
    data->max_anonymous_clients = 20;

    data->prio_workers = 5;

    data->max_client_requests = 5;

    data->audit_level = 1;
    data->audit_logging = false;

    data->keepalive_interval = 5;
    data->keepalive_count = 5;

    data->admin_min_workers = 5;
    data->admin_max_workers = 20;
    data->admin_max_clients = 5000;
    data->admin_max_queued_clients = 20;
    data->admin_max_client_requests = 5;

    data->admin_keepalive_interval = 5;
    data->admin_keepalive_count = 5;

    data->ovs_timeout = VIR_NETDEV_OVS_DEFAULT_TIMEOUT;

    return data;
}

void
daemonConfigFree(struct daemonConfig *data)
{
    char **tmp;

    if (!data)
        return;

#ifdef WITH_IP
    g_free(data->listen_addr);
    g_free(data->tls_port);
    g_free(data->tcp_port);
#endif /* ! WITH_IP */

    tmp = data->access_drivers;
    while (tmp && *tmp) {
        g_free(*tmp);
        tmp++;
    }
    g_free(data->access_drivers);

    g_free(data->unix_sock_admin_perms);
    g_free(data->unix_sock_ro_perms);
    g_free(data->unix_sock_rw_perms);
    g_free(data->unix_sock_group);
    g_free(data->unix_sock_dir);

    tmp = data->sasl_allowed_username_list;
    while (tmp && *tmp) {
        g_free(*tmp);
        tmp++;
    }
    g_free(data->sasl_allowed_username_list);

#ifdef WITH_IP
    tmp = data->tls_allowed_dn_list;
    while (tmp && *tmp) {
        g_free(*tmp);
        tmp++;
    }
    g_free(data->tls_allowed_dn_list);

    g_free(data->tls_priority);

    g_free(data->key_file);
    g_free(data->ca_file);
    g_free(data->cert_file);
    g_free(data->crl_file);
#endif /* ! WITH_IP */

    g_free(data->host_uuid);
    g_free(data->host_uuid_source);
    g_free(data->log_filters);
    g_free(data->log_outputs);

    g_free(data);
}

static int
daemonConfigLoadOptions(struct daemonConfig *data,
                        const char *filename,
                        virConf *conf)
{
    int rc G_GNUC_UNUSED;

#ifdef WITH_IP
    if (virConfGetValueBool(conf, "listen_tcp", &data->listen_tcp) < 0)
        return -1;
    if (virConfGetValueBool(conf, "listen_tls", &data->listen_tls) < 0)
        return -1;
    if (virConfGetValueString(conf, "tls_port", &data->tls_port) < 0)
        return -1;
    if (virConfGetValueString(conf, "tcp_port", &data->tcp_port) < 0)
        return -1;
    if (virConfGetValueString(conf, "listen_addr", &data->listen_addr) < 0)
        return -1;
#endif /* !WITH_IP */

    if (remoteConfigGetAuth(conf, filename, "auth_unix_rw", &data->auth_unix_rw) < 0)
        return -1;
#if WITH_POLKIT
    /* Change default perms to be wide-open if PolicyKit is enabled.
     * Admin can always override in config file
     */
    if (data->auth_unix_rw == REMOTE_AUTH_POLKIT) {
        VIR_FREE(data->unix_sock_rw_perms);
        data->unix_sock_rw_perms = g_strdup("0777");
    }
#endif
    if (remoteConfigGetAuth(conf, filename, "auth_unix_ro", &data->auth_unix_ro) < 0)
        return -1;

#ifdef WITH_IP
    if (remoteConfigGetAuth(conf, filename, "auth_tcp", &data->auth_tcp) < 0)
        return -1;
    if (remoteConfigGetAuth(conf, filename, "auth_tls", &data->auth_tls) < 0)
        return -1;
#endif /* ! WITH_IP */

    if (virConfGetValueStringList(conf, "access_drivers", false,
                                  &data->access_drivers) < 0)
        return -1;

    if (virConfGetValueString(conf, "unix_sock_group", &data->unix_sock_group) < 0)
        return -1;
    if (virConfGetValueString(conf, "unix_sock_admin_perms", &data->unix_sock_admin_perms) < 0)
        return -1;
    if (virConfGetValueString(conf, "unix_sock_ro_perms", &data->unix_sock_ro_perms) < 0)
        return -1;
    if (virConfGetValueString(conf, "unix_sock_rw_perms", &data->unix_sock_rw_perms) < 0)
        return -1;

    if (virConfGetValueString(conf, "unix_sock_dir", &data->unix_sock_dir) < 0)
        return -1;

#ifdef WITH_IP
    if (virConfGetValueBool(conf, "tls_no_sanity_certificate", &data->tls_no_sanity_certificate) < 0)
        return -1;
    if (virConfGetValueBool(conf, "tls_no_verify_certificate", &data->tls_no_verify_certificate) < 0)
        return -1;

    if (virConfGetValueString(conf, "key_file", &data->key_file) < 0)
        return -1;
    if (virConfGetValueString(conf, "cert_file", &data->cert_file) < 0)
        return -1;
    if (virConfGetValueString(conf, "ca_file", &data->ca_file) < 0)
        return -1;
    if (virConfGetValueString(conf, "crl_file", &data->crl_file) < 0)
        return -1;

    if (virConfGetValueStringList(conf, "tls_allowed_dn_list", false,
                                  &data->tls_allowed_dn_list) < 0)
        return -1;

    if (virConfGetValueString(conf, "tls_priority", &data->tls_priority) < 0)
        return -1;

    if ((rc = virConfGetValueUInt(conf, "tcp_min_ssf", &data->tcp_min_ssf)) < 0) {
        return -1;
    } else if (rc > 0 && data->tcp_min_ssf < SSF_WARNING_LEVEL) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("minimum SSF levels lower than %1$d are not supported"),
                       SSF_WARNING_LEVEL);
        return -1;
    }

#endif /* ! WITH_IP */

    if (virConfGetValueStringList(conf, "sasl_allowed_username_list", false,
                                  &data->sasl_allowed_username_list) < 0)
        return -1;

    if (virConfGetValueUInt(conf, "min_workers", &data->min_workers) < 0)
        return -1;
    if (virConfGetValueUInt(conf, "max_workers", &data->max_workers) < 0)
        return -1;
    if (data->max_workers < 1) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("'max_workers' must be greater than 0"));
        return -1;
    }
    if (virConfGetValueUInt(conf, "max_clients", &data->max_clients) < 0)
        return -1;
    if (virConfGetValueUInt(conf, "max_queued_clients", &data->max_queued_clients) < 0)
        return -1;
    if (virConfGetValueUInt(conf, "max_anonymous_clients", &data->max_anonymous_clients) < 0)
        return -1;

    if (virConfGetValueUInt(conf, "prio_workers", &data->prio_workers) < 0)
        return -1;

    if (virConfGetValueUInt(conf, "max_client_requests", &data->max_client_requests) < 0)
        return -1;

    if (virConfGetValueUInt(conf, "admin_min_workers", &data->admin_min_workers) < 0)
        return -1;
    if (virConfGetValueUInt(conf, "admin_max_workers", &data->admin_max_workers) < 0)
        return -1;
    if (virConfGetValueUInt(conf, "admin_max_clients", &data->admin_max_clients) < 0)
        return -1;
    if (virConfGetValueUInt(conf, "admin_max_queued_clients", &data->admin_max_queued_clients) < 0)
        return -1;
    if (virConfGetValueUInt(conf, "admin_max_client_requests", &data->admin_max_client_requests) < 0)
        return -1;

    if (virConfGetValueUInt(conf, "audit_level", &data->audit_level) < 0)
        return -1;
    if (virConfGetValueBool(conf, "audit_logging", &data->audit_logging) < 0)
        return -1;

    if (virConfGetValueString(conf, "host_uuid", &data->host_uuid) < 0)
        return -1;
    if (virConfGetValueString(conf, "host_uuid_source", &data->host_uuid_source) < 0)
        return -1;

    if (virConfGetValueUInt(conf, "log_level", &data->log_level) < 0)
        return -1;
    if (virConfGetValueString(conf, "log_filters", &data->log_filters) < 0)
        return -1;
    if (virConfGetValueString(conf, "log_outputs", &data->log_outputs) < 0)
        return -1;

    if (virConfGetValueInt(conf, "keepalive_interval", &data->keepalive_interval) < 0)
        return -1;
    if (virConfGetValueUInt(conf, "keepalive_count", &data->keepalive_count) < 0)
        return -1;

    if (virConfGetValueInt(conf, "admin_keepalive_interval", &data->admin_keepalive_interval) < 0)
        return -1;
    if (virConfGetValueUInt(conf, "admin_keepalive_count", &data->admin_keepalive_count) < 0)
        return -1;

    if (virConfGetValueUInt(conf, "ovs_timeout", &data->ovs_timeout) < 0)
        return -1;

    return 0;
}


/* Read the config file if it exists.
 * Only used in the remote case, hence the name.
 */
int
daemonConfigLoadFile(struct daemonConfig *data,
                     const char *filename,
                     bool allow_missing)
{
    g_autoptr(virConf) conf = NULL;

    if (allow_missing &&
        access(filename, R_OK) == -1 &&
        errno == ENOENT)
        return 0;

    conf = virConfReadFile(filename, 0);
    if (!conf)
        return -1;

    return daemonConfigLoadOptions(data, filename, conf);
}

int daemonConfigLoadData(struct daemonConfig *data,
                         const char *filename,
                         const char *filedata)
{
    g_autoptr(virConf) conf = NULL;

    conf = virConfReadString(filedata, 0);
    if (!conf)
        return -1;

    return daemonConfigLoadOptions(data, filename, conf);
}
