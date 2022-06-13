/* -*- c -*-
 * admin_protocol.x: private protocol for communicating between
 *   remote_internal driver and libvirtd.  This protocol is
 *   internal and may change at any time.
 *
 * Copyright (C) 2014-2015 Red Hat, Inc.
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

%#include <libvirt/libvirt-admin.h>
%#include "virxdrdefs.h"

/*----- Data types. -----*/

/* Length of long, but not unbounded, strings.
 * This is an arbitrary limit designed to stop the decoder from trying
 * to allocate unbounded amounts of memory when fed with a bad message.
 */
const ADMIN_STRING_MAX = 4194304;

/* Upper limit on list of servers */
const ADMIN_SERVER_LIST_MAX = 16384;

/* Upper limit on number of threadpool parameters */
const ADMIN_SERVER_THREADPOOL_PARAMETERS_MAX = 32;

/* Upper limit on list of clients */
const ADMIN_CLIENT_LIST_MAX = 16384;

/* Upper limit on number of client info parameters */
const ADMIN_CLIENT_INFO_PARAMETERS_MAX = 64;

/* Upper limit on number of client processing controls */
const ADMIN_SERVER_CLIENT_LIMITS_MAX = 32;

/* A long string, which may NOT be NULL. */
typedef string admin_nonnull_string<ADMIN_STRING_MAX>;

/* A long string, which may be NULL. */
typedef admin_nonnull_string *admin_string;

union admin_typed_param_value switch (int type) {
 case VIR_TYPED_PARAM_INT:
     int i;
 case VIR_TYPED_PARAM_UINT:
     unsigned int ui;
 case VIR_TYPED_PARAM_LLONG:
     hyper l;
 case VIR_TYPED_PARAM_ULLONG:
     unsigned hyper ul;
 case VIR_TYPED_PARAM_DOUBLE:
     double d;
 case VIR_TYPED_PARAM_BOOLEAN:
     int b;
 case VIR_TYPED_PARAM_STRING:
     admin_nonnull_string s;
};

struct admin_typed_param {
    admin_nonnull_string field;
    admin_typed_param_value value;
};

/* A server which may NOT be NULL */
struct admin_nonnull_server {
    admin_nonnull_string name;
};

/* A client which may NOT be NULL */
struct admin_nonnull_client {
    admin_nonnull_server srv;
    unsigned hyper id;
    hyper timestamp;
    unsigned int transport;
};

/*----- Protocol. -----*/

struct admin_connect_open_args {
    unsigned int flags;
};

struct admin_connect_get_lib_version_ret {
    unsigned hyper libVer;
};

struct admin_connect_list_servers_args {
    unsigned int need_results;
    unsigned int flags;
};

struct admin_connect_list_servers_ret { /* insert@1 */
    admin_nonnull_server servers<ADMIN_SERVER_LIST_MAX>;
    unsigned int ret;
};

struct admin_connect_lookup_server_args {
    admin_nonnull_string name;
    unsigned int flags;
};

struct admin_connect_lookup_server_ret {
    admin_nonnull_server srv;
};

struct admin_server_get_threadpool_parameters_args {
    admin_nonnull_server srv;
    unsigned int flags;
};

struct admin_server_get_threadpool_parameters_ret {
    admin_typed_param params<ADMIN_SERVER_THREADPOOL_PARAMETERS_MAX>;
};

struct admin_server_set_threadpool_parameters_args {
    admin_nonnull_server srv;
    admin_typed_param params<ADMIN_SERVER_THREADPOOL_PARAMETERS_MAX>;
    unsigned int flags;
};

struct admin_server_list_clients_args {
    admin_nonnull_server srv;
    unsigned int need_results;
    unsigned int flags;
};

struct admin_server_list_clients_ret { /* insert@1 */
    admin_nonnull_client clients<ADMIN_CLIENT_LIST_MAX>;
    unsigned int ret;
};

struct admin_server_lookup_client_args {
    admin_nonnull_server srv;
    unsigned hyper id;
    unsigned int flags;
};

struct admin_server_lookup_client_ret {
    admin_nonnull_client clnt;
};

struct admin_client_get_info_args {
    admin_nonnull_client clnt;
    unsigned int flags;
};

struct admin_client_get_info_ret { /* insert@1 */
    admin_typed_param params<ADMIN_CLIENT_INFO_PARAMETERS_MAX>;
};

struct admin_client_close_args {
    admin_nonnull_client clnt;
    unsigned int flags;
};

struct admin_server_get_client_limits_args {
    admin_nonnull_server srv;
    unsigned int flags;
};

struct admin_server_get_client_limits_ret {
    admin_typed_param params<ADMIN_SERVER_CLIENT_LIMITS_MAX>;
};

struct admin_server_set_client_limits_args {
    admin_nonnull_server srv;
    admin_typed_param params<ADMIN_SERVER_CLIENT_LIMITS_MAX>;
    unsigned int flags;
};

struct admin_server_update_tls_files_args {
    admin_nonnull_server srv;
    unsigned int flags;
};

struct admin_connect_get_logging_outputs_args {
    unsigned int flags;
};

struct admin_connect_get_logging_outputs_ret {
    admin_nonnull_string outputs;
    unsigned int noutputs;
};

struct admin_connect_get_logging_filters_args {
    unsigned int flags;
};

struct admin_connect_get_logging_filters_ret {
    admin_string filters;
    unsigned int nfilters;
};

struct admin_connect_set_logging_outputs_args {
    admin_string outputs;
    unsigned int flags;
};

struct admin_connect_set_logging_filters_args {
    admin_string filters;
    unsigned int flags;
};

struct admin_connect_set_daemon_timeout_args {
    unsigned int timeout;
    unsigned int flags;
};

/* Define the program number, protocol version and procedure numbers here. */
const ADMIN_PROGRAM = 0x06900690;
const ADMIN_PROTOCOL_VERSION = 1;

enum admin_procedure {
    /* Each function must be preceded by a comment providing one or
     * more annotations:
     *
     * - @generate: none|client|server|both
     *
     *   Whether to generate the dispatch stubs for the server
     *   and/or client code.
     *
     * - @readstream: paramnumber
     * - @writestream: paramnumber
     *
     *   The @readstream or @writestream annotations let daemon and src/remote
     *   create a stream.  The direction is defined from the src/remote point
     *   of view.  A readstream transfers data from daemon to src/remote.  The
     *   <paramnumber> specifies at which offset the stream parameter is inserted
     *   in the function parameter list.
     */
    /**
     * @generate: none
     */
    ADMIN_PROC_CONNECT_OPEN = 1,

    /**
     * @generate: none
     */
    ADMIN_PROC_CONNECT_CLOSE = 2,

    /**
     * @generate: both
     */
    ADMIN_PROC_CONNECT_GET_LIB_VERSION = 3,

    /**
      * @generate: both
      */
    ADMIN_PROC_CONNECT_LIST_SERVERS = 4,

    /**
      * @generate: both
      */
    ADMIN_PROC_CONNECT_LOOKUP_SERVER = 5,

    /**
     * @generate: none
     */
    ADMIN_PROC_SERVER_GET_THREADPOOL_PARAMETERS = 6,

    /**
     * @generate: none
     */
    ADMIN_PROC_SERVER_SET_THREADPOOL_PARAMETERS = 7,

    /**
     * @generate: both
     */
    ADMIN_PROC_SERVER_LIST_CLIENTS = 8,

    /**
     * @generate: both
     */
    ADMIN_PROC_SERVER_LOOKUP_CLIENT = 9,

    /**
     * @generate: none
     */
    ADMIN_PROC_CLIENT_GET_INFO = 10,

    /**
     * @generate: both
     */
    ADMIN_PROC_CLIENT_CLOSE = 11,

    /**
     * @generate: none
     */
    ADMIN_PROC_SERVER_GET_CLIENT_LIMITS = 12,

    /**
     * @generate: none
     */
    ADMIN_PROC_SERVER_SET_CLIENT_LIMITS = 13,

    /**
     * @generate: none
     */
    ADMIN_PROC_CONNECT_GET_LOGGING_OUTPUTS = 14,

    /**
     * @generate: none
     */
    ADMIN_PROC_CONNECT_GET_LOGGING_FILTERS = 15,

    /**
     * @generate: both
     */
    ADMIN_PROC_CONNECT_SET_LOGGING_OUTPUTS = 16,

    /**
     * @generate: both
     */
    ADMIN_PROC_CONNECT_SET_LOGGING_FILTERS = 17,

    /**
     * @generate: both
     */
    ADMIN_PROC_SERVER_UPDATE_TLS_FILES = 18,

    /**
     * @generate: both
     */
    ADMIN_PROC_CONNECT_SET_DAEMON_TIMEOUT = 19
};
