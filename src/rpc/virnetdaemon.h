/*
 * virnetdaemon.h
 *
 * Copyright (C) 2015 Red Hat, Inc.
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

#ifndef __VIR_NET_DAEMON_H__
# define __VIR_NET_DAEMON_H__

# include <signal.h>

# ifdef WITH_GNUTLS
#  include "virnettlscontext.h"
# endif
# include "virobject.h"
# include "virjson.h"
# include "virnetserverprogram.h"
# include "virnetserverclient.h"
# include "virnetserverservice.h"
# include "virnetserver.h"

virNetDaemonPtr virNetDaemonNew(void);

int virNetDaemonAddServer(virNetDaemonPtr dmn, virNetServerPtr);

virNetServerPtr virNetDaemonAddServerPostExec(virNetDaemonPtr dmn,
                                              virNetServerClientPrivNew clientPrivNew,
                                              virNetServerClientPrivNewPostExecRestart clientPrivNewPostExecRestart,
                                              virNetServerClientPrivPreExecRestart clientPrivPreExecRestart,
                                              virFreeCallback clientPrivFree,
                                              void *clientPrivOpaque);

virNetDaemonPtr virNetDaemonNewPostExecRestart(virJSONValuePtr object);

virJSONValuePtr virNetDaemonPreExecRestart(virNetDaemonPtr dmn);

typedef int (*virNetDaemonAutoShutdownFunc)(virNetDaemonPtr dmn, void *opaque);

bool virNetDaemonIsPrivileged(virNetDaemonPtr dmn);

void virNetDaemonAutoShutdown(virNetDaemonPtr dmn,
                              unsigned int timeout);

void virNetDaemonAddShutdownInhibition(virNetDaemonPtr dmn);
void virNetDaemonRemoveShutdownInhibition(virNetDaemonPtr dmn);

typedef void (*virNetDaemonSignalFunc)(virNetDaemonPtr dmn, siginfo_t *info, void *opaque);

int virNetDaemonAddSignalHandler(virNetDaemonPtr dmn,
                                 int signum,
                                 virNetDaemonSignalFunc func,
                                 void *opaque);

void virNetDaemonUpdateServices(virNetDaemonPtr dmn,
                                bool enabled);

void virNetDaemonRun(virNetDaemonPtr dmn);

void virNetDaemonQuit(virNetDaemonPtr dmn);

void virNetDaemonClose(virNetDaemonPtr dmn);

bool virNetDaemonHasClients(virNetDaemonPtr dmn);

virNetServerPtr virNetDaemonGetServer(virNetDaemonPtr dmn,
                                      int subServerID);

#endif /* __VIR_NET_DAEMON_H__ */
