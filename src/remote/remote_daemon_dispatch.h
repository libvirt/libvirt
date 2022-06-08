/*
 * remote_daemon_dispatch.h: handlers for RPC method calls
 *
 * Copyright (C) 2007-2018 Red Hat, Inc.
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

#include "rpc/virnetserverprogram.h"
#include "rpc/virnetserverclient.h"


extern virNetServerProgramProc remoteProcs[];
extern size_t remoteNProcs;

extern virNetServerProgramProc lxcProcs[];
extern size_t lxcNProcs;

extern virNetServerProgramProc qemuProcs[];
extern size_t qemuNProcs;

void remoteClientFree(void *data);
void *remoteClientNew(virNetServerClient *client,
                      void *opaque);
