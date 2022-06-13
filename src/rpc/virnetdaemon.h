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
 */

#pragma once

#include <signal.h>

#include "virjson.h"
#include "virnetserverprogram.h"
#include "virnetserverclient.h"
#include "virnetserver.h"

virNetDaemon *virNetDaemonNew(void);

int virNetDaemonAddServer(virNetDaemon *dmn,
                          virNetServer *srv);

typedef virNetServer *(*virNetDaemonNewServerPostExecRestart)(virNetDaemon *dmn,
                                                                const char *name,
                                                                virJSONValue *object,
                                                                void *opaque);
virNetDaemon *virNetDaemonNewPostExecRestart(virJSONValue *object,
                                               size_t nDefServerNames,
                                               const char **defServerNames,
                                               virNetDaemonNewServerPostExecRestart cb,
                                               void *opaque);

virJSONValue *virNetDaemonPreExecRestart(virNetDaemon *dmn);

bool virNetDaemonIsPrivileged(virNetDaemon *dmn);

int virNetDaemonAutoShutdown(virNetDaemon *dmn,
                             unsigned int timeout) G_GNUC_WARN_UNUSED_RESULT;

void virNetDaemonAddShutdownInhibition(virNetDaemon *dmn);
void virNetDaemonRemoveShutdownInhibition(virNetDaemon *dmn);

#ifdef WIN32
# define siginfo_t void
#endif

typedef void (*virNetDaemonSignalFunc)(virNetDaemon *dmn, siginfo_t *info, void *opaque);

int virNetDaemonAddSignalHandler(virNetDaemon *dmn,
                                 int signum,
                                 virNetDaemonSignalFunc func,
                                 void *opaque);

void virNetDaemonUpdateServices(virNetDaemon *dmn,
                                bool enabled);

void virNetDaemonSetStateStopWorkerThread(virNetDaemon *dmn,
                                          virThread **thr);

void virNetDaemonRun(virNetDaemon *dmn);

void virNetDaemonQuit(virNetDaemon *dmn);
void virNetDaemonQuitExecRestart(virNetDaemon *dmn);

bool virNetDaemonHasClients(virNetDaemon *dmn);

virNetServer *virNetDaemonGetServer(virNetDaemon *dmn,
                                      const char *serverName);
ssize_t virNetDaemonGetServers(virNetDaemon *dmn, virNetServer ***servers);
bool virNetDaemonHasServer(virNetDaemon *dmn,
                           const char *serverName);

typedef int (*virNetDaemonShutdownCallback)(void);

void virNetDaemonSetShutdownCallbacks(virNetDaemon *dmn,
                                      virNetDaemonShutdownCallback prepareCb,
                                      virNetDaemonShutdownCallback waitCb);
