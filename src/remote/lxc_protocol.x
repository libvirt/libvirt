/* -*- c -*-
 * lxc_protocol.x: private protocol for communicating between
 *   remote_internal driver and libvirtd.  This protocol is
 *   internal and may change at any time.
 *
 * Copyright (C) 2010-2013 Red Hat, Inc.
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
 * Author: Daniel Berrange <berrange@redhat.com>
 */

%#include "internal.h"
%#include "remote_protocol.h"

/*----- Protocol. -----*/
struct lxc_domain_open_namespace_args {
    remote_nonnull_domain dom;
    unsigned int flags;
};


/* Define the program number, protocol version and procedure numbers here. */
const LXC_PROGRAM = 0x00068000;
const LXC_PROTOCOL_VERSION = 1;

enum lxc_procedure {
    /* Each function must have a three-word comment.  The first word is
     * whether gendispatch.pl handles daemon, the second whether
     * it handles src/remote.
     * The last argument describes priority of API. There are two accepted
     * values: low, high; Each API that might eventually access hypervisor's
     * monitor (and thus block) MUST fall into low priority. However, there
     * are some exceptions to this rule, e.g. domainDestroy. Other APIs MAY
     * be marked as high priority. If in doubt, it's safe to choose low. */
    LXC_PROC_DOMAIN_OPEN_NAMESPACE = 1 /* skipgen skipgen priority:low */
};
