/*
 * remote_daemon_config.h: libvirtd config file handling
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

#pragma once

#include "internal.h"

struct daemonConfig {
    char *host_uuid;
    char *host_uuid_source;

#ifdef WITH_IP
    bool listen_tls;
    bool listen_tcp;
    char *listen_addr;
    char *tls_port;
    char *tcp_port;
#endif /* ! WITH_IP */

    char *unix_sock_admin_perms;
    char *unix_sock_ro_perms;
    char *unix_sock_rw_perms;
    char *unix_sock_group;
    char *unix_sock_dir;

    int auth_unix_rw;
    int auth_unix_ro;

#ifdef WITH_IP
    int auth_tcp;
    int auth_tls;
#endif /* ! WITH_IP */

    char **access_drivers;

#ifdef WITH_IP
    bool tls_no_verify_certificate;
    bool tls_no_sanity_certificate;
    char **tls_allowed_dn_list;
    char *tls_priority;
    unsigned int tcp_min_ssf;

    char *key_file;
    char *cert_file;
    char *ca_file;
    char *crl_file;
#endif /* ! WITH_IP */

    char **sasl_allowed_username_list;

    unsigned int min_workers;
    unsigned int max_workers;
    unsigned int max_clients;
    unsigned int max_queued_clients;
    unsigned int max_anonymous_clients;

    unsigned int prio_workers;

    unsigned int max_client_requests;

    unsigned int log_level;
    char *log_filters;
    char *log_outputs;

    unsigned int audit_level;
    bool audit_logging;

    int keepalive_interval;
    unsigned int keepalive_count;

    unsigned int admin_min_workers;
    unsigned int admin_max_workers;
    unsigned int admin_max_clients;
    unsigned int admin_max_queued_clients;
    unsigned int admin_max_client_requests;

    int admin_keepalive_interval;
    unsigned int admin_keepalive_count;

    unsigned int ovs_timeout;
};


void daemonConfigFilePath(bool privileged, char **configfile);
struct daemonConfig* daemonConfigNew(bool privileged);
void daemonConfigFree(struct daemonConfig *data);
int daemonConfigLoadFile(struct daemonConfig *data,
                         const char *filename,
                         bool allow_missing);
int daemonConfigLoadData(struct daemonConfig *data,
                         const char *filename,
                         const char *filedata);
