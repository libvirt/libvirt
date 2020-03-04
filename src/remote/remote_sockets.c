/*
 * remote_sockets.c: helpers for getting remote driver socket paths
 *
 * Copyright (C) 2007-2019 Red Hat, Inc.
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

#include <config.h>

#include "remote_sockets.h"

VIR_ENUM_IMPL(remoteDriverTransport,
              REMOTE_DRIVER_TRANSPORT_LAST,
              "tls",
              "unix",
              "ssh",
              "libssh2",
              "ext",
              "tcp",
              "libssh");

VIR_ENUM_IMPL(remoteDriverMode,
              REMOTE_DRIVER_MODE_LAST,
              "auto",
              "legacy",
              "direct");
