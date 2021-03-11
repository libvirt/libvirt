/*
 * remote_daemon_stream.h: APIs for managing client streams
 *
 * Copyright (C) 2009-2018 Red Hat, Inc.
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

#include "remote_daemon.h"

daemonClientStream *
daemonCreateClientStream(virNetServerClient *client,
                         virStreamPtr st,
                         virNetServerProgram *prog,
                         struct virNetMessageHeader *hdr,
                         bool allowSkip);

int daemonFreeClientStream(virNetServerClient *client,
                           daemonClientStream *stream);

int daemonAddClientStream(virNetServerClient *client,
                          daemonClientStream *stream,
                          bool transmit);

int
daemonRemoveClientStream(virNetServerClient *client,
                         daemonClientStream *stream);

void
daemonRemoveAllClientStreams(daemonClientStream *stream);
