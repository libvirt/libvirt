/*
 * qemu_interface.h: QEMU interface management
 *
 * Copyright IBM Corp. 2014
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
 * Authors:
 *     Matthew J. Rosato <mjrosato@linux.vnet.ibm.com>
 */

#ifndef __QEMU_INTERFACE_H__
# define __QEMU_INTERFACE_H__

# include "domain_conf.h"

int qemuInterfaceStartDevice(virDomainNetDefPtr net);
int qemuInterfaceStartDevices(virDomainDefPtr def);
int qemuInterfaceStopDevice(virDomainNetDefPtr net);
int qemuInterfaceStopDevices(virDomainDefPtr def);

#endif /* __QEMU_INTERFACE_H__ */
