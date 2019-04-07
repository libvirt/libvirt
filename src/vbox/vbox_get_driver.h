/*
 * Copyright (C) 2014, Taowei Luo (uaedante@gmail.com)
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

#ifndef LIBVIRT_VBOX_GET_DRIVER_H
# define LIBVIRT_VBOX_GET_DRIVER_H

# include "internal.h"

virHypervisorDriverPtr vboxGetHypervisorDriver(uint32_t uVersion);
virNetworkDriverPtr vboxGetNetworkDriver(uint32_t uVersion);
virStorageDriverPtr vboxGetStorageDriver(uint32_t uVersion);

#endif /* LIBVIRT_VBOX_GET_DRIVER_H */
