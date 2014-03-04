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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef __VIR_NET_SERVER_H__
# define __VIR_NET_SERVER_H__

# include <signal.h>

# ifdef WITH_GNUTLS
#  include "virnettlscontext.h"
# endif
# include "virnetserverprogram.h"
# include "virnetserverclient.h"
# include "virnetserverservice.h"
# include "virobject.h"
# include "virjson.h"

virNetServerPtr virNetServerNew(size_t min_workers,
                                size_t max_workers,
                                size_t priority_workers,
                                size_t max_clients,
                                size_t max_anonymous_clients,
                                int keepaliveInterval,
                                unsigned int keepaliveCount,
                                bool keepaliveRequired,
                                const char *mdnsGroupName,
                                virNetServerClientPrivNew clientPrivNew,
                                virNetServerClientPrivPreExecRestart clientPrivPreExecRestart,
                                virFreeCallback clientPrivFree,
                                void *clientPrivOpaque);

virNetServerPtr virNetServerNewPostExecRestart(virJSONValuePtr object,
                                               virNetServerClientPrivNew clientPrivNew,
                                               virNetServerClientPrivNewPostExecRestart clientPrivNewPostExecRestart,
                                               virNetServerClientPrivPreExecRestart clientPrivPreExecRestart,
                                               virFreeCallback clientPrivFree,
                                               void *clientPrivOpaque);

virJSONValuePtr virNetServerPreExecRestart(virNetServerPtr srv);

typedef int (*virNetServerAutoShutdownFunc)(virNetServerPtr srv, void *opaque);

bool virNetServerIsPrivileged(virNetServerPtr srv);

void virNetServerAutoShutdown(virNetServerPtr srv,
                              unsigned int timeout);

void virNetServerAddShutdownInhibition(virNetServerPtr srv);
void virNetServerRemoveShutdownInhibition(virNetServerPtr srv);

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

# if WITH_GNUTLS
int virNetServerSetTLSContext(virNetServerPtr srv,
                              virNetTLSContextPtr tls);
# endif

void virNetServerUpdateServices(virNetServerPtr srv,
                                bool enabled);

void virNetServerRun(virNetServerPtr srv);

void virNetServerQuit(virNetServerPtr srv);

void virNetServerClose(virNetServerPtr srv);

bool virNetServerKeepAliveRequired(virNetServerPtr srv);

size_t virNetServerTrackPendingAuth(virNetServerPtr srv);
size_t virNetServerTrackCompletedAuth(virNetServerPtr srv);

#endif
