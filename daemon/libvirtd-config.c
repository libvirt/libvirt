/*
 * libvirtd-config.c: daemon start of day, guest process & i/o management
 *
 * Copyright (C) 2006-2012, 2014 Red Hat, Inc.
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
#include "virstring.h"
#include "virutil.h"

#define VIR_FROM_THIS VIR_FROM_CONF

VIR_LOG_INIT("daemon.libvirtd-config");

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
    virConfValuePtr p = virConfGetValue(conf, key);
    if (!p)
        return 0;

    switch (p->type) {
    case VIR_CONF_STRING:
        if (VIR_ALLOC_N(list, 2) < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("failed to allocate memory for %s config list"),
                           key);
            return -1;
        }
        if (VIR_STRDUP(list[0], p->str) < 0) {
            VIR_FREE(list);
            return -1;
        }
        list[1] = NULL;
        break;

    case VIR_CONF_LIST: {
        int len = 0;
        size_t i;
        virConfValuePtr pp;
        for (pp = p->list; pp; pp = pp->next)
            len++;
        if (VIR_ALLOC_N(list, 1+len) < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("failed to allocate memory for %s config list"),
                           key);
            return -1;
        }
        for (i = 0, pp = p->list; pp; ++i, pp = pp->next) {
            if (pp->type != VIR_CONF_STRING) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("remoteReadConfigFile: %s: %s:"
                                 " must be a string or list of strings"),
                               filename, key);
                VIR_FREE(list);
                return -1;
            }
            if (VIR_STRDUP(list[i], pp->str) < 0) {
                size_t j;
                for (j = 0; j < i; j++)
                    VIR_FREE(list[j]);
                VIR_FREE(list);
                return -1;
            }

        }
        list[i] = NULL;
        break;
    }

    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("remoteReadConfigFile: %s: %s:"
                         " must be a string or list of strings"),
                       filename, key);
        return -1;
    }

    *list_arg = list;
    return 0;
}

/* A helper function used by each of the following macros.  */
static int
checkType(virConfValuePtr p, const char *filename,
          const char *key, virConfType required_type)
{
    if (p->type != required_type) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("remoteReadConfigFile: %s: %s: invalid type:"
                         " got %s; expected %s"), filename, key,
                       virConfTypeName(p->type),
                       virConfTypeName(required_type));
        return -1;
    }
    return 0;
}

/* If there is no config data for the key, #var_name, then do nothing.
   If there is valid data of type VIR_CONF_STRING, and VIR_STRDUP succeeds,
   store the result in var_name.  Otherwise, (i.e. invalid type, or VIR_STRDUP
   failure), give a diagnostic and "goto" the cleanup-and-fail label.  */
#define GET_CONF_STR(conf, filename, var_name)                          \
    do {                                                                \
        virConfValuePtr p = virConfGetValue(conf, #var_name);           \
        if (p) {                                                        \
            if (checkType(p, filename, #var_name, VIR_CONF_STRING) < 0) \
                goto error;                                             \
            VIR_FREE(data->var_name);                                   \
            if (VIR_STRDUP(data->var_name, p->str) < 0)                 \
                goto error;                                             \
        }                                                               \
    } while (0)

/* Like GET_CONF_STR, but for integral values.  */
#define GET_CONF_INT(conf, filename, var_name)                          \
    do {                                                                \
        virConfValuePtr p = virConfGetValue(conf, #var_name);           \
        if (p) {                                                        \
            if (checkType(p, filename, #var_name, VIR_CONF_LONG) < 0)   \
                goto error;                                             \
            data->var_name = p->l;                                      \
        }                                                               \
    } while (0)


static int
remoteConfigGetAuth(virConfPtr conf,
                    const char *key,
                    int *auth,
                    const char *filename)
{
    virConfValuePtr p;

    p = virConfGetValue(conf, key);
    if (!p)
        return 0;

    if (checkType(p, filename, key, VIR_CONF_STRING) < 0)
        return -1;

    if (!p->str)
        return 0;

    if (STREQ(p->str, "none")) {
        *auth = VIR_NET_SERVER_SERVICE_AUTH_NONE;
#if WITH_SASL
    } else if (STREQ(p->str, "sasl")) {
        *auth = VIR_NET_SERVER_SERVICE_AUTH_SASL;
#endif
    } else if (STREQ(p->str, "polkit")) {
        *auth = VIR_NET_SERVER_SERVICE_AUTH_POLKIT;
    } else {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("remoteReadConfigFile: %s: %s: unsupported auth %s"),
                       filename, key, p->str);
        return -1;
    }

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
        VIR_STRDUP(data->unix_sock_ro_perms, "0777") < 0)
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
    data->max_anonymous_clients = 20;

    data->prio_workers = 5;

    data->max_requests = 20;
    data->max_client_requests = 5;

    data->audit_level = 1;
    data->audit_logging = 0;

    data->keepalive_interval = 5;
    data->keepalive_count = 5;
    data->keepalive_required = 0;

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

    VIR_FREE(data->host_uuid);
    VIR_FREE(data->log_filters);
    VIR_FREE(data->log_outputs);

    VIR_FREE(data);
}

static int
daemonConfigLoadOptions(struct daemonConfig *data,
                        const char *filename,
                        virConfPtr conf)
{
    GET_CONF_INT(conf, filename, listen_tcp);
    GET_CONF_INT(conf, filename, listen_tls);
    GET_CONF_STR(conf, filename, tls_port);
    GET_CONF_STR(conf, filename, tcp_port);
    GET_CONF_STR(conf, filename, listen_addr);

    if (remoteConfigGetAuth(conf, "auth_unix_rw", &data->auth_unix_rw, filename) < 0)
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
    if (remoteConfigGetAuth(conf, "auth_unix_ro", &data->auth_unix_ro, filename) < 0)
        goto error;
    if (remoteConfigGetAuth(conf, "auth_tcp", &data->auth_tcp, filename) < 0)
        goto error;
    if (remoteConfigGetAuth(conf, "auth_tls", &data->auth_tls, filename) < 0)
        goto error;

    if (remoteConfigGetStringList(conf, "access_drivers",
                                  &data->access_drivers, filename) < 0)
        goto error;

    GET_CONF_STR(conf, filename, unix_sock_group);
    GET_CONF_STR(conf, filename, unix_sock_ro_perms);
    GET_CONF_STR(conf, filename, unix_sock_rw_perms);

    GET_CONF_STR(conf, filename, unix_sock_dir);

    GET_CONF_INT(conf, filename, mdns_adv);
    GET_CONF_STR(conf, filename, mdns_name);

    GET_CONF_INT(conf, filename, tls_no_sanity_certificate);
    GET_CONF_INT(conf, filename, tls_no_verify_certificate);

    GET_CONF_STR(conf, filename, key_file);
    GET_CONF_STR(conf, filename, cert_file);
    GET_CONF_STR(conf, filename, ca_file);
    GET_CONF_STR(conf, filename, crl_file);

    if (remoteConfigGetStringList(conf, "tls_allowed_dn_list",
                                  &data->tls_allowed_dn_list, filename) < 0)
        goto error;


    if (remoteConfigGetStringList(conf, "sasl_allowed_username_list",
                                  &data->sasl_allowed_username_list, filename) < 0)
        goto error;


    GET_CONF_INT(conf, filename, min_workers);
    GET_CONF_INT(conf, filename, max_workers);
    GET_CONF_INT(conf, filename, max_clients);
    GET_CONF_INT(conf, filename, max_queued_clients);
    GET_CONF_INT(conf, filename, max_anonymous_clients);

    GET_CONF_INT(conf, filename, prio_workers);

    GET_CONF_INT(conf, filename, max_requests);
    GET_CONF_INT(conf, filename, max_client_requests);

    GET_CONF_INT(conf, filename, audit_level);
    GET_CONF_INT(conf, filename, audit_logging);

    GET_CONF_STR(conf, filename, host_uuid);

    GET_CONF_INT(conf, filename, log_level);
    GET_CONF_STR(conf, filename, log_filters);
    GET_CONF_STR(conf, filename, log_outputs);

    GET_CONF_INT(conf, filename, keepalive_interval);
    GET_CONF_INT(conf, filename, keepalive_count);
    GET_CONF_INT(conf, filename, keepalive_required);

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
