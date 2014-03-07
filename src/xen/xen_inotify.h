/*
 * xen_inotify.h: Xen notification of xml files
 *
 * Copyright (C) 2011 Red Hat, Inc.
 * Copyright (C) 2008 VirtualIron
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
 * Author: Ben Guthro
 */
#ifndef __VIR_XEN_INOTIFY_H__
# define __VIR_XEN_INOTIFY_H__

# include "internal.h"

int xenInotifyOpen(virConnectPtr conn,
                   virConnectAuthPtr auth,
                   unsigned int flags);
int xenInotifyClose(virConnectPtr conn);

#endif
