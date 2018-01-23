/*
 * admin_server_dispatch.h: handlers for admin RPC method calls
 *
 * Copyright (C) 2014-2016 Red Hat, Inc.
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

#ifndef __ADMIN_SERVER_DISPATCH_H__
# define __ADMIN_SERVER_DISPATCH_H__

# include "rpc/virnetserverprogram.h"
# include "rpc/virnetserverclient.h"
# include "admin/admin_protocol.h"


extern virNetServerProgramProc adminProcs[];
extern size_t adminNProcs;

void remoteAdmClientFree(void *data);
void *remoteAdmClientNew(virNetServerClientPtr client, void *opaque);
void *remoteAdmClientNewPostExecRestart(virNetServerClientPtr client,
                                        virJSONValuePtr object,
                                        void *opaque);
virJSONValuePtr remoteAdmClientPreExecRestart(virNetServerClientPtr client,
                                              void *data);

#endif /* __ADMIN_SERVER_DISPATCH_H__ */
