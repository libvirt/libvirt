/*
 * virnetserverservice.h: generic network RPC server service
 *
 * Copyright (C) 2006-2011, 2014 Red Hat, Inc.
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

#include "virnetserverprogram.h"

typedef enum {
    VIR_NET_SERVER_SERVICE_AUTH_NONE = 0,
    VIR_NET_SERVER_SERVICE_AUTH_SASL,
    VIR_NET_SERVER_SERVICE_AUTH_POLKIT,
} virNetServerServiceAuthMethods;

typedef int (*virNetServerServiceDispatchFunc)(virNetServerService *svc,
                                               virNetSocket *sock,
                                               void *opaque);

virNetServerService *virNetServerServiceNewTCP(const char *nodename,
                                                 const char *service,
                                                 int family,
                                                 int auth,
                                                 virNetTLSContext *tls,
                                                 bool readonly,
                                                 size_t max_queued_clients,
                                                 size_t nrequests_client_max);
virNetServerService *virNetServerServiceNewUNIX(const char *path,
                                                  mode_t mask,
                                                  gid_t grp,
                                                  int auth,
                                                  virNetTLSContext *tls,
                                                  bool readonly,
                                                  size_t max_queued_clients,
                                                  size_t nrequests_client_max);
virNetServerService *virNetServerServiceNewFDs(int *fd,
                                                 size_t nfds,
                                                 bool unlinkUNIX,
                                                 int auth,
                                                 virNetTLSContext *tls,
                                                 bool readonly,
                                                 size_t max_queued_clients,
                                                 size_t nrequests_client_max);

virNetServerService *virNetServerServiceNewPostExecRestart(virJSONValue *object);

virJSONValue *virNetServerServicePreExecRestart(virNetServerService *service);

int virNetServerServiceGetPort(virNetServerService *svc);

int virNetServerServiceGetAuth(virNetServerService *svc);
bool virNetServerServiceIsReadonly(virNetServerService *svc);
size_t virNetServerServiceGetMaxRequests(virNetServerService *svc);
virNetTLSContext *virNetServerServiceGetTLSContext(virNetServerService *svc);

void virNetServerServiceSetDispatcher(virNetServerService *svc,
                                      virNetServerServiceDispatchFunc func,
                                      void *opaque);

void virNetServerServiceToggle(virNetServerService *svc,
                               bool enabled);

void virNetServerServiceClose(virNetServerService *svc);

bool virNetServerServiceTimerActive(virNetServerService *svc);
