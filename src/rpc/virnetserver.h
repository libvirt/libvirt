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
#include "virobject.h"
#include "virjson.h"
#include "virsystemd.h"


virNetServerPtr virNetServerNew(const char *name,
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

virNetServerPtr virNetServerNewPostExecRestart(virJSONValuePtr object,
                                               const char *name,
                                               virNetServerClientPrivNew clientPrivNew,
                                               virNetServerClientPrivNewPostExecRestart clientPrivNewPostExecRestart,
                                               virNetServerClientPrivPreExecRestart clientPrivPreExecRestart,
                                               virFreeCallback clientPrivFree,
                                               void *clientPrivOpaque)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    ATTRIBUTE_NONNULL(4) ATTRIBUTE_NONNULL(5) ATTRIBUTE_NONNULL(6);

void virNetServerClose(virNetServerPtr srv);

virJSONValuePtr virNetServerPreExecRestart(virNetServerPtr srv);

int virNetServerAddService(virNetServerPtr srv,
                           virNetServerServicePtr svc);
int virNetServerAddServiceTCP(virNetServerPtr srv,
                              virSystemdActivationPtr act,
                              const char *actname,
                              const char *nodename,
                              const char *service,
                              int family,
                              int auth,
                              virNetTLSContextPtr tls,
                              bool readonly,
                              size_t max_queued_clients,
                              size_t nrequests_client_max);
int virNetServerAddServiceUNIX(virNetServerPtr srv,
                               virSystemdActivationPtr act,
                               const char *actname,
                               const char *path,
                               mode_t mask,
                               gid_t grp,
                               int auth,
                               virNetTLSContextPtr tls,
                               bool readonly,
                               size_t max_queued_clients,
                               size_t nrequests_client_max);

int virNetServerAddProgram(virNetServerPtr srv,
                           virNetServerProgramPtr prog);

int virNetServerSetTLSContext(virNetServerPtr srv,
                              virNetTLSContextPtr tls);


int virNetServerAddClient(virNetServerPtr srv,
                          virNetServerClientPtr client);
bool virNetServerHasClients(virNetServerPtr srv);
void virNetServerProcessClients(virNetServerPtr srv);
void virNetServerSetClientAuthenticated(virNetServerPtr srv, virNetServerClientPtr client);

void virNetServerUpdateServices(virNetServerPtr srv, bool enabled);

const char *virNetServerGetName(virNetServerPtr srv);

int virNetServerGetThreadPoolParameters(virNetServerPtr srv,
                                        size_t *minWorkers,
                                        size_t *maxWorkers,
                                        size_t *nWorkers,
                                        size_t *freeWorkers,
                                        size_t *nPrioWorkers,
                                        size_t *jobQueueDepth);

int virNetServerSetThreadPoolParameters(virNetServerPtr srv,
                                        long long int minWorkers,
                                        long long int maxWorkers,
                                        long long int prioWorkers);

unsigned long long virNetServerNextClientID(virNetServerPtr srv);

virNetServerClientPtr virNetServerGetClient(virNetServerPtr srv,
                                            unsigned long long id);

int virNetServerGetClients(virNetServerPtr srv,
                           virNetServerClientPtr **clients);

size_t virNetServerGetMaxClients(virNetServerPtr srv);
size_t virNetServerGetCurrentClients(virNetServerPtr srv);
size_t virNetServerGetMaxUnauthClients(virNetServerPtr srv);
size_t virNetServerGetCurrentUnauthClients(virNetServerPtr srv);

int virNetServerSetClientLimits(virNetServerPtr srv,
                                long long int maxClients,
                                long long int maxClientsUnauth);
