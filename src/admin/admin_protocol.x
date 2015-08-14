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
 *
 * Author: Martin Kletzander <mkletzan@redhat.com>
 */

%#include "virxdrdefs.h"

/*----- Data types. -----*/

/* Length of long, but not unbounded, strings.
 * This is an arbitrary limit designed to stop the decoder from trying
 * to allocate unbounded amounts of memory when fed with a bad message.
 */
const ADMIN_STRING_MAX = 4194304;

/* Upper limit on list of servers */
const ADMIN_SERVER_LIST_MAX = 16384;

/* A long string, which may NOT be NULL. */
typedef string admin_nonnull_string<ADMIN_STRING_MAX>;

/* A long string, which may be NULL. */
typedef admin_nonnull_string *admin_string;

/* A server which may NOT be NULL */
struct admin_nonnull_server {
    admin_nonnull_string name;
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

struct admin_connect_list_servers_ret {
    admin_nonnull_server servers<ADMIN_SERVER_LIST_MAX>;
    unsigned int ret;
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
      * @generate: none
      * @priority: high
      */
    ADMIN_PROC_CONNECT_LIST_SERVERS = 4
};
