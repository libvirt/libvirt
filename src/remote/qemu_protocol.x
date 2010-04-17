/* -*- c -*-
 * qemu_protocol.x: private protocol for communicating between
 *   remote_internal driver and libvirtd.  This protocol is
 *   internal and may change at any time.
 *
 * Copyright (C) 2010 Red Hat, Inc.
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
 * Author: Chris Lalancette <clalance@redhat.com>
 */

%#include "internal.h"
%#include "remote_protocol.h"
%#include <arpa/inet.h>

/*----- Protocol. -----*/
struct qemu_monitor_command_args {
    remote_nonnull_domain domain;
    remote_nonnull_string cmd;
    int flags;
};

struct qemu_monitor_command_ret {
    remote_nonnull_string result;
};

/* Define the program number, protocol version and procedure numbers here. */
const QEMU_PROGRAM = 0x20008087;
const QEMU_PROTOCOL_VERSION = 1;

enum qemu_procedure {
    QEMU_PROC_MONITOR_COMMAND = 1
};
