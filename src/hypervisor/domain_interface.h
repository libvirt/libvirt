/*
 * Copyright (C) 2015-2016 Red Hat, Inc.
 * Copyright IBM Corp. 2014
 *
 * domain_interface.h: methods to manage guest/domain interfaces
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

#include "virebtables.h"

int
virDomainInterfaceEthernetConnect(virDomainDef *def,
                           virDomainNetDef *net,
                           ebtablesContext *ebtables,
                           bool macFilter,
                           bool privileged,
                           int *tapfd,
                           size_t tapfdSize);

bool
virDomainInterfaceIsVnetCompatModel(const virDomainNetDef *net);

int virDomainInterfaceStartDevice(virDomainNetDef *net);
int virDomainInterfaceStartDevices(virDomainDef *def);
int virDomainInterfaceStopDevice(virDomainNetDef *net);
int virDomainInterfaceStopDevices(virDomainDef *def);
void virDomainInterfaceVportRemove(virDomainNetDef *net);
void virDomainInterfaceDeleteDevice(virDomainDef *def,
                                virDomainNetDef *net,
                                bool priv_net_created,
                                char *stateDir);
int virDomainInterfaceClearQoS(virDomainDef *def,
                               virDomainNetDef *net);
void virDomainClearNetBandwidth(virDomainDef *def)
    ATTRIBUTE_NONNULL(1);
