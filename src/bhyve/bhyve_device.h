/*
 * bhyve_device.h: bhyve device management headers
 *
 * Copyright (C) 2014 Roman Bogorodskiy
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
 * Author: Roman Bogorodskiy
 */

#ifndef __BHYVE_DEVICE_H__
# define __BHYVE_DEVICE_H__

# include "domain_conf.h"
# include "virpci.h"
# include "bhyve_domain.h"

int bhyveDomainAssignPCIAddresses(virDomainDefPtr def, virDomainObjPtr obj);

virDomainPCIAddressSetPtr bhyveDomainPCIAddressSetCreate(virDomainDefPtr def,
                                                         unsigned int nbuses);

int bhyveDomainAssignAddresses(virDomainDefPtr def, virDomainObjPtr obj)
    ATTRIBUTE_NONNULL(1);

#endif /* __BHYVE_DEVICE_H__ */
