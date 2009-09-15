/*
 * node_device_hal.h: node device enumeration - HAL-based implementation
 *
 * Copyright (C) 2009 Red Hat, Inc.
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
 */

#ifndef __VIR_NODE_DEVICE_HAL_H__
#define __VIR_NODE_DEVICE_HAL_H__

#ifdef __linux__

#define check_fc_host(d) check_fc_host_linux(d)
int check_fc_host_linux(union _virNodeDevCapData *d);

#define check_vport_capable(d) check_vport_capable_linux(d)
int check_vport_capable_linux(union _virNodeDevCapData *d);

#define read_wwn(host, file, wwn) read_wwn_linux(host, file, wwn)
int read_wwn_linux(int host, const char *file, char **wwn);

#else  /* __linux__ */

#define check_fc_host(d)
#define check_vport_capable(d)
#define read_wwn(host, file, wwn)

#endif /* __linux__ */

#endif /* __VIR_NODE_DEVICE_HAL_H__ */
