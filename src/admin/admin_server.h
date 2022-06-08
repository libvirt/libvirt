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
 */

#pragma once

#include "rpc/virnetdaemon.h"

int adminConnectListServers(virNetDaemon *dmn,
                            virNetServer ***servers,
                            unsigned int flags);

virNetServer *adminConnectLookupServer(virNetDaemon *dmn,
                                         const char *name,
                                         unsigned int flags);

int
adminServerGetThreadPoolParameters(virNetServer *srv,
                                   virTypedParameterPtr *params,
                                   int *nparams,
                                   unsigned int flags);
int
adminServerSetThreadPoolParameters(virNetServer *srv,
                                   virTypedParameterPtr params,
                                   int nparams,
                                   unsigned int flags);

int adminServerListClients(virNetServer *srv,
                           virNetServerClient ***clients,
                           unsigned int flags);

virNetServerClient *adminServerLookupClient(virNetServer *srv,
                                              unsigned long long id,
                                              unsigned int flags);

int adminClientGetInfo(virNetServerClient *client,
                       virTypedParameterPtr *params,
                       int *nparams,
                       unsigned int flags);

int adminClientClose(virNetServerClient *client,
                     unsigned int flags);

int adminServerGetClientLimits(virNetServer *srv,
                               virTypedParameterPtr *params,
                               int *nparams,
                               unsigned int flags);

int adminServerSetClientLimits(virNetServer *srv,
                               virTypedParameterPtr params,
                               int nparams,
                               unsigned int flags);

int adminServerUpdateTlsFiles(virNetServer *srv,
                              unsigned int flags);
