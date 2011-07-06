/*
 * remote.h: handlers for RPC method calls
 *
 * Copyright (C) 2007, 2008, 2009 Red Hat, Inc.
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
 * Author: Richard W.M. Jones <rjones@redhat.com>
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef __LIBVIRTD_REMOTE_H__
# define __LIBVIRTD_REMOTE_H__

# include "remote_protocol.h"
# include "rpc/virnetserverprogram.h"
# include "rpc/virnetserverclient.h"


extern virNetServerProgramProc remoteProcs[];
extern size_t remoteNProcs;

extern virNetServerProgramProc qemuProcs[];
extern size_t qemuNProcs;

int remoteClientInitHook(virNetServerPtr srv,
                         virNetServerClientPtr client);

#endif /* __LIBVIRTD_REMOTE_H__ */
