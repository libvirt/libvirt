/*
 * libvirtd-config.c: daemon start of day, guest process & i/o management
 *
 * Copyright (C) 2006-2012, 2014, 2015 Red Hat, Inc.
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

#include "libvirtd-config.h"
#include "virconf.h"
#include "viralloc.h"
#include "virerror.h"
#include "virlog.h"
#include "rpc/virnetserver.h"
#include "configmake.h"
#include "remote/remote_protocol.h"
#include "remote/remote_driver.h"
#include "util/virnetdevopenvswitch.h"
#include "virstring.h"
#include "virutil.h"

#define VIR_FROM_THIS VIR_FROM_CONF

VIR_LOG_INIT("daemon.libvirtd-config");


static int
remoteConfigGetAuth(virConfPtr conf,
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
                       _("%s: %s: unsupported auth %s"),
                       filename, key, authstr);
        VIR_FREE(authstr);
        return -1;
    }

    VIR_FREE(authstr);
    return 0;
}

int
daemonConfigFilePath(bool privileged, char **configfile)
{
    if (privileged) {
        if (VIR_STRDUP(*configfile, SYSCONFDIR "/libvirt/libvirtd.conf") < 0)
            goto error;
    } else {
        char *configdir = NULL;

        if (!(configdir = virGetUserConfigDirectory()))
            goto error;

        if (virAsprintf(configfile, "%s/libvirtd.conf", configdir) < 0) {
            VIR_FREE(configdir);
            goto error;
        }
        VIR_FREE(configdir);
    }

    return 0;

 error:
    return -1;
}

struct daemonConfig*
daemonConfigNew(bool privileged ATTRIBUTE_UNUSED)
{
    struct daemonConfig *data;
    char *localhost;
    int ret;

    if (VIR_ALLOC(data) < 0)
        return NULL;

    data->listen_tls = 1;
    data->listen_tcp = 0;

    if (VIR_STRDUP(data->tls_port, LIBVIRTD_TLS_PORT) < 0 ||
        VIR_STRDUP(data->tcp_port, LIBVIRTD_TCP_PORT) < 0)
        goto error;

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

    if (VIR_STRDUP(data->unix_sock_rw_perms,
                   data->auth_unix_rw == REMOTE_AUTH_POLKIT ? "0777" : "0700") < 0 ||
        VIR_STRDUP(data->unix_sock_ro_perms, "0777") < 0 ||
        VIR_STRDUP(data->unix_sock_admin_perms, "0700") < 0)
        goto error;

#if WITH_SASL
    data->auth_tcp = REMOTE_AUTH_SASL;
#else
    data->auth_tcp = REMOTE_AUTH_NONE;
#endif
    data->auth_tls = REMOTE_AUTH_NONE;

    data->mdns_adv = 0;

    data->min_workers = 5;
    data->max_workers = 20;
    data->max_clients = 5000;
    data->max_queued_clients = 1000;
    data->max_anonymous_clients = 20;

    data->prio_workers = 5;

    data->max_requests = 20;
    data->max_client_requests = 5;

    data->audit_level = 1;
    data->audit_logging = 0;

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

    localhost = virGetHostname();
    if (localhost == NULL) {
        /* we couldn't resolve the hostname; assume that we are
         * running in disconnected operation, and report a less
         * useful Avahi string
         */
        ret = VIR_STRDUP(data->mdns_name, "Virtualization Host");
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
        goto error;

    return data;

 error:
    daemonConfigFree(data);
    return NULL;
}

void
daemonConfigFree(struct daemonConfig *data)
{
    char **tmp;

    if (!data)
        return;

    VIR_FREE(data->listen_addr);
    VIR_FREE(data->tls_port);
    VIR_FREE(data->tcp_port);
    tmp = data->access_drivers;
    while (tmp && *tmp) {
        VIR_FREE(*tmp);
        tmp++;
    }
    VIR_FREE(data->access_drivers);

    VIR_FREE(data->unix_sock_admin_perms);
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
    VIR_FREE(data->tls_priority);

    VIR_FREE(data->key_file);
    VIR_FREE(data->ca_file);
    VIR_FREE(data->cert_file);
    VIR_FREE(data->crl_file);

    VIR_FREE(data->host_uuid);
    VIR_FREE(data->host_uuid_source);
    VIR_FREE(data->log_filters);
    VIR_FREE(data->log_outputs);

    VIR_FREE(data);
}

static int
daemonConfigLoadOptions(struct daemonConfig *data,
                        const char *filename,
                        virConfPtr conf)
{
    if (virConfGetValueBool(conf, "listen_tcp", &data->listen_tcp) < 0)
        goto error;
    if (virConfGetValueBool(conf, "listen_tls", &data->listen_tls) < 0)
        goto error;
    if (virConfGetValueString(conf, "tls_port", &data->tls_port) < 0)
        goto error;
    if (virConfGetValueString(conf, "tcp_port", &data->tcp_port) < 0)
        goto error;
    if (virConfGetValueString(conf, "listen_addr", &data->listen_addr) < 0)
        goto error;

    if (remoteConfigGetAuth(conf, filename, "auth_unix_rw", &data->auth_unix_rw) < 0)
        goto error;
#if WITH_POLKIT
    /* Change default perms to be wide-open if PolicyKit is enabled.
     * Admin can always override in config file
     */
    if (data->auth_unix_rw == REMOTE_AUTH_POLKIT) {
        VIR_FREE(data->unix_sock_rw_perms);
        if (VIR_STRDUP(data->unix_sock_rw_perms, "0777") < 0)
            goto error;
    }
#endif
    if (remoteConfigGetAuth(conf, filename, "auth_unix_ro", &data->auth_unix_ro) < 0)
        goto error;
    if (remoteConfigGetAuth(conf, filename, "auth_tcp", &data->auth_tcp) < 0)
        goto error;
    if (remoteConfigGetAuth(conf, filename, "auth_tls", &data->auth_tls) < 0)
        goto error;

    if (virConfGetValueStringList(conf, "access_drivers", false,
                                  &data->access_drivers) < 0)
        goto error;

    if (virConfGetValueString(conf, "unix_sock_group", &data->unix_sock_group) < 0)
        goto error;
    if (virConfGetValueString(conf, "unix_sock_admin_perms", &data->unix_sock_admin_perms) < 0)
        goto error;
    if (virConfGetValueString(conf, "unix_sock_ro_perms", &data->unix_sock_ro_perms) < 0)
        goto error;
    if (virConfGetValueString(conf, "unix_sock_rw_perms", &data->unix_sock_rw_perms) < 0)
        goto error;

    if (virConfGetValueString(conf, "unix_sock_dir", &data->unix_sock_dir) < 0)
        goto error;

    if (virConfGetValueBool(conf, "mdns_adv", &data->mdns_adv) < 0)
        goto error;
    if (virConfGetValueString(conf, "mdns_name", &data->mdns_name) < 0)
        goto error;

    if (virConfGetValueBool(conf, "tls_no_sanity_certificate", &data->tls_no_sanity_certificate) < 0)
        goto error;
    if (virConfGetValueBool(conf, "tls_no_verify_certificate", &data->tls_no_verify_certificate) < 0)
        goto error;

    if (virConfGetValueString(conf, "key_file", &data->key_file) < 0)
        goto error;
    if (virConfGetValueString(conf, "cert_file", &data->cert_file) < 0)
        goto error;
    if (virConfGetValueString(conf, "ca_file", &data->ca_file) < 0)
        goto error;
    if (virConfGetValueString(conf, "crl_file", &data->crl_file) < 0)
        goto error;

    if (virConfGetValueStringList(conf, "tls_allowed_dn_list", false,
                                  &data->tls_allowed_dn_list) < 0)
        goto error;


    if (virConfGetValueStringList(conf, "sasl_allowed_username_list", false,
                                  &data->sasl_allowed_username_list) < 0)
        goto error;

    if (virConfGetValueString(conf, "tls_priority", &data->tls_priority) < 0)
        goto error;

    if (virConfGetValueUInt(conf, "min_workers", &data->min_workers) < 0)
        goto error;
    if (virConfGetValueUInt(conf, "max_workers", &data->max_workers) < 0)
        goto error;
    if (virConfGetValueUInt(conf, "max_clients", &data->max_clients) < 0)
        goto error;
    if (virConfGetValueUInt(conf, "max_queued_clients", &data->max_queued_clients) < 0)
        goto error;
    if (virConfGetValueUInt(conf, "max_anonymous_clients", &data->max_anonymous_clients) < 0)
        goto error;

    if (virConfGetValueUInt(conf, "prio_workers", &data->prio_workers) < 0)
        goto error;

    if (virConfGetValueUInt(conf, "max_requests", &data->max_requests) < 0)
        goto error;
    if (virConfGetValueUInt(conf, "max_client_requests", &data->max_client_requests) < 0)
        goto error;

    if (virConfGetValueUInt(conf, "admin_min_workers", &data->admin_min_workers) < 0)
        goto error;
    if (virConfGetValueUInt(conf, "admin_max_workers", &data->admin_max_workers) < 0)
        goto error;
    if (virConfGetValueUInt(conf, "admin_max_clients", &data->admin_max_clients) < 0)
        goto error;
    if (virConfGetValueUInt(conf, "admin_max_queued_clients", &data->admin_max_queued_clients) < 0)
        goto error;
    if (virConfGetValueUInt(conf, "admin_max_client_requests", &data->admin_max_client_requests) < 0)
        goto error;

    if (virConfGetValueUInt(conf, "audit_level", &data->audit_level) < 0)
        goto error;
    if (virConfGetValueBool(conf, "audit_logging", &data->audit_logging) < 0)
        goto error;

    if (virConfGetValueString(conf, "host_uuid", &data->host_uuid) < 0)
        goto error;
    if (virConfGetValueString(conf, "host_uuid_source", &data->host_uuid_source) < 0)
        goto error;

    if (virConfGetValueUInt(conf, "log_level", &data->log_level) < 0)
        goto error;
    if (virConfGetValueString(conf, "log_filters", &data->log_filters) < 0)
        goto error;
    if (virConfGetValueString(conf, "log_outputs", &data->log_outputs) < 0)
        goto error;

    if (virConfGetValueInt(conf, "keepalive_interval", &data->keepalive_interval) < 0)
        goto error;
    if (virConfGetValueUInt(conf, "keepalive_count", &data->keepalive_count) < 0)
        goto error;

    if (virConfGetValueInt(conf, "admin_keepalive_interval", &data->admin_keepalive_interval) < 0)
        goto error;
    if (virConfGetValueUInt(conf, "admin_keepalive_count", &data->admin_keepalive_count) < 0)
        goto error;

    if (virConfGetValueUInt(conf, "ovs_timeout", &data->ovs_timeout) < 0)
        goto error;

    return 0;

 error:
    return -1;
}


/* Read the config file if it exists.
 * Only used in the remote case, hence the name.
 */
int
daemonConfigLoadFile(struct daemonConfig *data,
                     const char *filename,
                     bool allow_missing)
{
    virConfPtr conf;
    int ret;

    if (allow_missing &&
        access(filename, R_OK) == -1 &&
        errno == ENOENT)
        return 0;

    conf = virConfReadFile(filename, 0);
    if (!conf)
        return -1;

    ret = daemonConfigLoadOptions(data, filename, conf);
    virConfFree(conf);
    return ret;
}

int daemonConfigLoadData(struct daemonConfig *data,
                         const char *filename,
                         const char *filedata)
{
    virConfPtr conf;
    int ret;

    conf = virConfReadMem(filedata, strlen(filedata), 0);
    if (!conf)
        return -1;

    ret = daemonConfigLoadOptions(data, filename, conf);
    virConfFree(conf);
    return ret;
}
