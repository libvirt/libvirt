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
#include "virobject.h"

typedef enum {
    VIR_NET_SERVER_SERVICE_AUTH_NONE = 0,
    VIR_NET_SERVER_SERVICE_AUTH_SASL,
    VIR_NET_SERVER_SERVICE_AUTH_POLKIT,
} virNetServerServiceAuthMethods;

typedef int (*virNetServerServiceDispatchFunc)(virNetServerServicePtr svc,
                                               virNetSocketPtr sock,
                                               void *opaque);

virNetServerServicePtr virNetServerServiceNewFDOrUNIX(const char *path,
                                                      mode_t mask,
                                                      gid_t grp,
                                                      int auth,
                                                      virNetTLSContextPtr tls,
                                                      bool readonly,
                                                      size_t max_queued_clients,
                                                      size_t nrequests_client_max,
                                                      unsigned int nfds,
                                                      unsigned int *cur_fd);
virNetServerServicePtr virNetServerServiceNewTCP(const char *nodename,
                                                 const char *service,
                                                 int family,
                                                 int auth,
                                                 virNetTLSContextPtr tls,
                                                 bool readonly,
                                                 size_t max_queued_clients,
                                                 size_t nrequests_client_max);
virNetServerServicePtr virNetServerServiceNewUNIX(const char *path,
                                                  mode_t mask,
                                                  gid_t grp,
                                                  int auth,
                                                  virNetTLSContextPtr tls,
                                                  bool readonly,
                                                  size_t max_queued_clients,
                                                  size_t nrequests_client_max);
virNetServerServicePtr virNetServerServiceNewFD(int fd,
                                                int auth,
                                                virNetTLSContextPtr tls,
                                                bool readonly,
                                                size_t max_queued_clients,
                                                size_t nrequests_client_max);

virNetServerServicePtr virNetServerServiceNewPostExecRestart(virJSONValuePtr object);

virJSONValuePtr virNetServerServicePreExecRestart(virNetServerServicePtr service);

int virNetServerServiceGetPort(virNetServerServicePtr svc);

int virNetServerServiceGetAuth(virNetServerServicePtr svc);
bool virNetServerServiceIsReadonly(virNetServerServicePtr svc);
size_t virNetServerServiceGetMaxRequests(virNetServerServicePtr svc);
virNetTLSContextPtr virNetServerServiceGetTLSContext(virNetServerServicePtr svc);

void virNetServerServiceSetDispatcher(virNetServerServicePtr svc,
                                      virNetServerServiceDispatchFunc func,
                                      void *opaque);

void virNetServerServiceToggle(virNetServerServicePtr svc,
                               bool enabled);

void virNetServerServiceClose(virNetServerServicePtr svc);
