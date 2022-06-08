/*
 * virnetserver.h: generic network RPC server
 *
 * Copyright (C) 2006-2015 Red Hat, Inc.
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
 */

#pragma once

#include "virnettlscontext.h"
#include "virnetserverprogram.h"
#include "virnetserverclient.h"
#include "virnetserverservice.h"
#include "virjson.h"
#include "virsystemd.h"


virNetServer *virNetServerNew(const char *name,
                                unsigned long long next_client_id,
                                size_t min_workers,
                                size_t max_workers,
                                size_t priority_workers,
                                size_t max_clients,
                                size_t max_anonymous_clients,
                                int keepaliveInterval,
                                unsigned int keepaliveCount,
                                virNetServerClientPrivNew clientPrivNew,
                                virNetServerClientPrivPreExecRestart clientPrivPreExecRestart,
                                virFreeCallback clientPrivFree,
                                void *clientPrivOpaque)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(10) ATTRIBUTE_NONNULL(12);

virNetServer *virNetServerNewPostExecRestart(virJSONValue *object,
                                               const char *name,
                                               virNetServerClientPrivNew clientPrivNew,
                                               virNetServerClientPrivNewPostExecRestart clientPrivNewPostExecRestart,
                                               virNetServerClientPrivPreExecRestart clientPrivPreExecRestart,
                                               virFreeCallback clientPrivFree,
                                               void *clientPrivOpaque)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    ATTRIBUTE_NONNULL(4) ATTRIBUTE_NONNULL(5) ATTRIBUTE_NONNULL(6);

void virNetServerClose(virNetServer *srv);
void virNetServerShutdownWait(virNetServer *srv);

virJSONValue *virNetServerPreExecRestart(virNetServer *srv);

int virNetServerAddService(virNetServer *srv,
                           virNetServerService *svc);
int virNetServerAddServiceTCP(virNetServer *srv,
                              virSystemdActivation *act,
                              const char *actname,
                              const char *nodename,
                              const char *service,
                              int family,
                              int auth,
                              virNetTLSContext *tls,
                              bool readonly,
                              size_t max_queued_clients,
                              size_t nrequests_client_max);
int virNetServerAddServiceUNIX(virNetServer *srv,
                               virSystemdActivation *act,
                               const char *actname,
                               const char *path,
                               mode_t mask,
                               gid_t grp,
                               int auth,
                               virNetTLSContext *tls,
                               bool readonly,
                               size_t max_queued_clients,
                               size_t nrequests_client_max);

int virNetServerAddProgram(virNetServer *srv,
                           virNetServerProgram *prog);

int virNetServerSetTLSContext(virNetServer *srv,
                              virNetTLSContext *tls);


int virNetServerAddClient(virNetServer *srv,
                          virNetServerClient *client);
bool virNetServerHasClients(virNetServer *srv);
void virNetServerProcessClients(virNetServer *srv);
void virNetServerSetClientAuthenticated(virNetServer *srv, virNetServerClient *client);

void virNetServerUpdateServices(virNetServer *srv, bool enabled);

const char *virNetServerGetName(virNetServer *srv);

int virNetServerGetThreadPoolParameters(virNetServer *srv,
                                        size_t *minWorkers,
                                        size_t *maxWorkers,
                                        size_t *nWorkers,
                                        size_t *freeWorkers,
                                        size_t *nPrioWorkers,
                                        size_t *jobQueueDepth);

int virNetServerSetThreadPoolParameters(virNetServer *srv,
                                        long long int minWorkers,
                                        long long int maxWorkers,
                                        long long int prioWorkers);

unsigned long long virNetServerNextClientID(virNetServer *srv);

virNetServerClient *virNetServerGetClient(virNetServer *srv,
                                            unsigned long long id);

bool virNetServerNeedsAuth(virNetServer *srv,
                           int auth);

int virNetServerGetClients(virNetServer *srv,
                           virNetServerClient ***clients);

size_t virNetServerGetMaxClients(virNetServer *srv);
size_t virNetServerGetCurrentClients(virNetServer *srv);
size_t virNetServerGetMaxUnauthClients(virNetServer *srv);
size_t virNetServerGetCurrentUnauthClients(virNetServer *srv);

int virNetServerSetClientLimits(virNetServer *srv,
                                long long int maxClients,
                                long long int maxClientsUnauth);

int virNetServerUpdateTlsFiles(virNetServer *srv);
