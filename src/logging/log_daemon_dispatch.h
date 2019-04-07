/*
 * log_daemon_dispatch.h: log management daemon dispatch
 *
 * Copyright (C) 2006-2015 Red Hat, Inc.
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
 * License along with this library;  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifndef LIBVIRT_LOG_DAEMON_DISPATCH_H
# define LIBVIRT_LOG_DAEMON_DISPATCH_H

# include "rpc/virnetserverprogram.h"

extern virNetServerProgramProc virLogManagerProtocolProcs[];
extern size_t virLogManagerProtocolNProcs;

#endif /* LIBVIRT_LOG_DAEMON_DISPATCH_H */
