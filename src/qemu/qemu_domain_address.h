/*
 * qemu_domain_address.h: QEMU domain address
 *
 * Copyright (C) 2006-2016 Red Hat, Inc.
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
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef __QEMU_DOMAIN_ADDRESS_H__

# include "domain_addr.h"
# include "domain_conf.h"
# include "qemu_conf.h"
# include "qemu_capabilities.h"

int qemuDomainSetSCSIControllerModel(const virDomainDef *def,
                                     virQEMUCapsPtr qemuCaps,
                                     int *model);

int qemuDomainAssignAddresses(virDomainDefPtr def,
                              virQEMUCapsPtr qemuCaps,
                              virQEMUDriverPtr driver,
                              virDomainObjPtr obj,
                              bool newDomain)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);

int qemuDomainEnsurePCIAddress(virDomainObjPtr obj,
                               virDomainDeviceDefPtr dev,
                               virQEMUDriverPtr driver)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);

int qemuDomainFillDeviceIsolationGroup(virDomainDefPtr def,
                                       virDomainDeviceDefPtr dev)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

void qemuDomainReleaseDeviceAddress(virDomainObjPtr vm,
                                    virDomainDeviceInfoPtr info,
                                    const char *devstr);

virDomainCCWAddressSetPtr
qemuDomainCCWAddrSetCreateFromDomain(virDomainDefPtr def)
    ATTRIBUTE_NONNULL(1);

int qemuDomainAssignMemoryDeviceSlot(virDomainDefPtr def,
                                     virDomainMemoryDefPtr mem);


# define __QEMU_DOMAIN_ADDRESS_H__

#endif /* __QEMU_DOMAIN_ADDRESS_H__ */
