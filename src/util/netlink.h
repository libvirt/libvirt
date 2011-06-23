/*
 * Copyright (C) 2010-2011 Red Hat, Inc.
 * Copyright (C) 2010 IBM Corporation
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
 */

#ifndef __VIR_NETLINK_H__
# define __VIR_NETLINK_H__

# include "config.h"

# if defined(__linux__) && defined(HAVE_LIBNL)

#  include <netlink/msg.h>

# else

struct nl_msg;

# endif /* __linux__ */

int nlComm(struct nl_msg *nl_msg,
           unsigned char **respbuf, unsigned int *respbuflen,
           int nl_pid);

#endif /* __VIR_NETLINK_H__ */
