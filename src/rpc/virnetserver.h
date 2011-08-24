/*
 * virnetserver.h: generic network RPC server
 *
 * Copyright (C) 2006-2011 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef __VIR_NET_SERVER_H__
# define __VIR_NET_SERVER_H__

# include <signal.h>
# if HAVE_DBUS
#  include <dbus/dbus.h>
# endif

# include "virnettlscontext.h"
# include "virnetserverprogram.h"
# include "virnetserverclient.h"
# include "virnetserverservice.h"

typedef int (*virNetServerClientInitHook)(virNetServerPtr srv,
                                          virNetServerClientPtr client);

virNetServerPtr virNetServerNew(size_t min_workers,
                                size_t max_workers,
                                size_t priority_workers,
                                size_t max_clients,
                                int keepaliveInterval,
                                unsigned int keepaliveCount,
                                bool keepaliveRequired,
                                const char *mdnsGroupName,
                                bool connectDBus,
                                virNetServerClientInitHook clientInitHook);

typedef int (*virNetServerAutoShutdownFunc)(virNetServerPtr srv, void *opaque);

void virNetServerRef(virNetServerPtr srv);

bool virNetServerIsPrivileged(virNetServerPtr srv);

# if HAVE_DBUS
DBusConnection* virNetServerGetDBusConn(virNetServerPtr srv);
# endif

void virNetServerAutoShutdown(virNetServerPtr srv,
                              unsigned int timeout,
                              virNetServerAutoShutdownFunc func,
                              void *opaque);

typedef void (*virNetServerSignalFunc)(virNetServerPtr srv, siginfo_t *info, void *opaque);

int virNetServerAddSignalHandler(virNetServerPtr srv,
                                 int signum,
                                 virNetServerSignalFunc func,
                                 void *opaque);

int virNetServerAddService(virNetServerPtr srv,
                           virNetServerServicePtr svc,
                           const char *mdnsEntryName);

int virNetServerAddProgram(virNetServerPtr srv,
                           virNetServerProgramPtr prog);

int virNetServerSetTLSContext(virNetServerPtr srv,
                              virNetTLSContextPtr tls);

void virNetServerUpdateServices(virNetServerPtr srv,
                                bool enabled);

void virNetServerRun(virNetServerPtr srv);

void virNetServerQuit(virNetServerPtr srv);

void virNetServerFree(virNetServerPtr srv);

void virNetServerClose(virNetServerPtr srv);

bool virNetServerKeepAliveRequired(virNetServerPtr srv);

#endif
