/*
 * lxc_hostdev.h: VIRLXC hostdev management
 *
 * Copyright (C) 2006-2007, 2009-2010 Red Hat, Inc.
 * Copyright (C) 2006 Daniel P. Berrange
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

#ifndef LIBVIRT_LXC_HOSTDEV_H
# define LIBVIRT_LXC_HOSTDEV_H

# include "lxc_conf.h"
# include "domain_conf.h"

int virLXCUpdateActiveUSBHostdevs(virLXCDriverPtr driver,
                                  virDomainDefPtr def);
int virLXCFindHostdevUSBDevice(virDomainHostdevDefPtr hostdev,
                               bool mandatory,
                               virUSBDevicePtr *usb);
int virLXCPrepareHostdevUSBDevices(virLXCDriverPtr driver,
                                   const char *name,
                                   virUSBDeviceListPtr list);
int virLXCPrepareHostDevices(virLXCDriverPtr driver,
                             virDomainDefPtr def);
void virLXCDomainReAttachHostDevices(virLXCDriverPtr driver,
                                     virDomainDefPtr def);

#endif /* LIBVIRT_LXC_HOSTDEV_H */
