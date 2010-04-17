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


# include "libvirtd.h"

typedef union {
# include "remote_dispatch_args.h"
} dispatch_args;

typedef union {
# include "remote_dispatch_ret.h"
} dispatch_ret;

typedef union {
# include "qemu_dispatch_args.h"
} qemu_dispatch_args;

typedef union {
# include "qemu_dispatch_ret.h"
} qemu_dispatch_ret;



/**
 * When the RPC handler is called:
 *
 *  - Server object is unlocked
 *  - Client object is unlocked
 *
 * Both must be locked before use. Server lock must
 * be held before attempting to lock client.
 *
 * Without any locking, it is safe to use:
 *
 *   'conn', 'rerr', 'args and 'ret'
 */
typedef int (*dispatch_fn) (struct qemud_server *server,
                            struct qemud_client *client,
                            virConnectPtr conn,
                            remote_message_header *hdr,
                            remote_error *err,
                            dispatch_args *args,
                            dispatch_ret *ret);

typedef struct {
    dispatch_fn fn;
    xdrproc_t args_filter;
    xdrproc_t ret_filter;
} dispatch_data;


const dispatch_data const *remoteGetDispatchData(int proc);
const dispatch_data const *qemuGetDispatchData(int proc);



#endif /* __LIBVIRTD_REMOTE_H__ */
