/*
 * admin_server.h: admin methods to manage daemons and clients
 *
 * Copyright (C) 2016 Red Hat, Inc.
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
 * Authors: Erik Skultety <eskultet@redhat.com>
 *          Martin Kletzander <mkletzan@redhat.com>
 */

#ifndef __LIBVIRTD_ADMIN_SERVER_H__
# define __LIBVIRTD_ADMIN_SERVER_H__

# include "rpc/virnetdaemon.h"
# include "rpc/virnetserver.h"

int adminConnectListServers(virNetDaemonPtr dmn,
                            virNetServerPtr **servers,
                            unsigned int flags);

virNetServerPtr adminConnectLookupServer(virNetDaemonPtr dmn,
                                         const char *name,
                                         unsigned int flags);

int
adminServerGetThreadPoolParameters(virNetServerPtr srv,
                                   virTypedParameterPtr *params,
                                   int *nparams,
                                   unsigned int flags);
int
adminServerSetThreadPoolParameters(virNetServerPtr srv,
                                   virTypedParameterPtr params,
                                   int nparams,
                                   unsigned int flags);

int adminServerListClients(virNetServerPtr srv,
                           virNetServerClientPtr **clients,
                           unsigned int flags);

virNetServerClientPtr adminServerLookupClient(virNetServerPtr srv,
                                              unsigned long long id,
                                              unsigned int flags);

int adminClientGetInfo(virNetServerClientPtr client,
                       virTypedParameterPtr *params,
                       int *nparams,
                       unsigned int flags);

int adminClientClose(virNetServerClientPtr client,
                     unsigned int flags);

int adminServerGetClientLimits(virNetServerPtr srv,
                               virTypedParameterPtr *params,
                               int *nparams,
                               unsigned int flags);

int adminServerSetClientLimits(virNetServerPtr srv,
                               virTypedParameterPtr params,
                               int nparams,
                               unsigned int flags);

#endif /* __LIBVIRTD_ADMIN_SERVER_H__ */
