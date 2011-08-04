/*
 * virnetserverservice.h: generic network RPC server service
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

#ifndef __VIR_NET_SERVER_SERVICE_H__
# define __VIR_NET_SERVER_SERVICE_H__

# include "virnetserverprogram.h"

enum {
    VIR_NET_SERVER_SERVICE_AUTH_NONE = 0,
    VIR_NET_SERVER_SERVICE_AUTH_SASL,
    VIR_NET_SERVER_SERVICE_AUTH_POLKIT,
};

typedef int (*virNetServerServiceDispatchFunc)(virNetServerServicePtr svc,
                                               virNetServerClientPtr client,
                                               void *opaque);

virNetServerServicePtr virNetServerServiceNewTCP(const char *nodename,
                                                 const char *service,
                                                 int auth,
                                                 bool readonly,
                                                 size_t nrequests_client_max,
                                                 virNetTLSContextPtr tls);
virNetServerServicePtr virNetServerServiceNewUNIX(const char *path,
                                                  mode_t mask,
                                                  gid_t grp,
                                                  int auth,
                                                  bool readonly,
                                                  size_t nrequests_client_max,
                                                  virNetTLSContextPtr tls);

int virNetServerServiceGetPort(virNetServerServicePtr svc);

int virNetServerServiceGetAuth(virNetServerServicePtr svc);
bool virNetServerServiceIsReadonly(virNetServerServicePtr svc);

void virNetServerServiceRef(virNetServerServicePtr svc);

void virNetServerServiceSetDispatcher(virNetServerServicePtr svc,
                                      virNetServerServiceDispatchFunc func,
                                      void *opaque);

void virNetServerServiceFree(virNetServerServicePtr svc);

void virNetServerServiceToggle(virNetServerServicePtr svc,
                               bool enabled);

void virNetServerServiceClose(virNetServerServicePtr svc);

#endif
