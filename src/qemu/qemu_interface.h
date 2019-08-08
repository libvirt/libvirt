/*
 * qemu_interface.h: QEMU interface management
 *
 * Copyright (C) 2014, 2016 Red Hat, Inc.
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
 */

#pragma once

#include "domain_conf.h"
#include "qemu_conf.h"
#include "qemu_domain.h"
#include "qemu_slirp.h"

int qemuInterfaceStartDevice(virDomainNetDefPtr net);
int qemuInterfaceStartDevices(virDomainDefPtr def);
int qemuInterfaceStopDevice(virDomainNetDefPtr net);
int qemuInterfaceStopDevices(virDomainDefPtr def);

int qemuInterfaceDirectConnect(virDomainDefPtr def,
                               virQEMUDriverPtr driver,
                               virDomainNetDefPtr net,
                               int *tapfd,
                               size_t tapfdSize,
                               virNetDevVPortProfileOp vmop);

int qemuInterfaceEthernetConnect(virDomainDefPtr def,
                                 virQEMUDriverPtr driver,
                                 virDomainNetDefPtr net,
                                 int *tapfd,
                                 size_t tapfdSize);

int qemuInterfaceBridgeConnect(virDomainDefPtr def,
                               virQEMUDriverPtr driver,
                               virDomainNetDefPtr net,
                               int *tapfd,
                               size_t *tapfdSize)
    ATTRIBUTE_NONNULL(2);

int qemuInterfaceOpenVhostNet(virDomainDefPtr def,
                              virDomainNetDefPtr net,
                              int *vhostfd,
                              size_t *vhostfdSize);

qemuSlirpPtr qemuInterfacePrepareSlirp(virQEMUDriverPtr driver,
                                       virDomainNetDefPtr net);
