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
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef __VIR_NET_SERVER_SERVICE_H__
# define __VIR_NET_SERVER_SERVICE_H__

# include "virnetserverprogram.h"
# include "virobject.h"

enum {
    VIR_NET_SERVER_SERVICE_AUTH_NONE = 0,
    VIR_NET_SERVER_SERVICE_AUTH_SASL,
    VIR_NET_SERVER_SERVICE_AUTH_POLKIT,
};

typedef int (*virNetServerServiceDispatchFunc)(virNetServerServicePtr svc,
                                               virNetSocketPtr sock,
                                               void *opaque);

virNetServerServicePtr virNetServerServiceNewFDOrUNIX(const char *path,
                                                      mode_t mask,
                                                      gid_t grp,
                                                      int auth,
# if WITH_GNUTLS
                                                      virNetTLSContextPtr tls,
# endif
                                                      bool readonly,
                                                      size_t max_queued_clients,
                                                      size_t nrequests_client_max,
                                                      unsigned int nfds,
                                                      unsigned int *cur_fd);
virNetServerServicePtr virNetServerServiceNewTCP(const char *nodename,
                                                 const char *service,
                                                 int family,
                                                 int auth,
# if WITH_GNUTLS
                                                 virNetTLSContextPtr tls,
# endif
                                                 bool readonly,
                                                 size_t max_queued_clients,
                                                 size_t nrequests_client_max);
virNetServerServicePtr virNetServerServiceNewUNIX(const char *path,
                                                  mode_t mask,
                                                  gid_t grp,
                                                  int auth,
# if WITH_GNUTLS
                                                  virNetTLSContextPtr tls,
# endif
                                                  bool readonly,
                                                  size_t max_queued_clients,
                                                  size_t nrequests_client_max);
virNetServerServicePtr virNetServerServiceNewFD(int fd,
                                                int auth,
# if WITH_GNUTLS
                                                virNetTLSContextPtr tls,
# endif
                                                bool readonly,
                                                size_t max_queued_clients,
                                                size_t nrequests_client_max);

virNetServerServicePtr virNetServerServiceNewPostExecRestart(virJSONValuePtr object);

virJSONValuePtr virNetServerServicePreExecRestart(virNetServerServicePtr service);

int virNetServerServiceGetPort(virNetServerServicePtr svc);

int virNetServerServiceGetAuth(virNetServerServicePtr svc);
bool virNetServerServiceIsReadonly(virNetServerServicePtr svc);
size_t virNetServerServiceGetMaxRequests(virNetServerServicePtr svc);
# ifdef WITH_GNUTLS
virNetTLSContextPtr virNetServerServiceGetTLSContext(virNetServerServicePtr svc);
# endif

void virNetServerServiceSetDispatcher(virNetServerServicePtr svc,
                                      virNetServerServiceDispatchFunc func,
                                      void *opaque);

void virNetServerServiceToggle(virNetServerServicePtr svc,
                               bool enabled);

void virNetServerServiceClose(virNetServerServicePtr svc);

#endif
