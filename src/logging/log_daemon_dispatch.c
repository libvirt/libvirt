/*
 * log_daemon_dispatch.c: log management daemon dispatch
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
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include "rpc/virnetserver.h"
#include "rpc/virnetserverclient.h"
#include "virlog.h"
#include "virstring.h"
#include "log_daemon.h"
#include "log_protocol.h"
#include "virerror.h"

#define VIR_FROM_THIS VIR_FROM_RPC

VIR_LOG_INIT("logging.log_daemon_dispatch");

#include "log_daemon_dispatch_stubs.h"
