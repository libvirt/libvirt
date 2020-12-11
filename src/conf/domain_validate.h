/*
 * domain_validate.h: domain general validation functions
 *
 * Copyright IBM Corp, 2020
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

#include <glib-object.h>

#include "domain_conf.h"
#include "virconftypes.h"

int virDomainVideoDefValidate(const virDomainVideoDef *video,
                              const virDomainDef *def);
int virDomainDiskDefValidate(const virDomainDef *def,
                             const virDomainDiskDef *disk);
int virDomainRedirdevDefValidate(const virDomainDef *def,
                                 const virDomainRedirdevDef *redirdev);
int virDomainChrDefValidate(const virDomainChrDef *chr,
                            const virDomainDef *def);
int virDomainRNGDefValidate(const virDomainRNGDef *rng,
                            const virDomainDef *def);
int virDomainSmartcardDefValidate(const virDomainSmartcardDef *smartcard,
                                  const virDomainDef *def);
int virDomainControllerDefValidate(const virDomainControllerDef *controller);
int virDomainDeviceValidateAliasForHotplug(virDomainObjPtr vm,
                                           virDomainDeviceDefPtr dev,
                                           unsigned int flags);
int virDomainDefValidate(virDomainDefPtr def,
                         unsigned int parseFlags,
                         virDomainXMLOptionPtr xmlopt,
                         void *parseOpaque);
int virDomainActualNetDefValidate(const virDomainNetDef *net);
int virDomainNetDefValidate(const virDomainNetDef *net);
int virDomainHostdevDefValidate(const virDomainHostdevDef *hostdev);
int virDomainMemoryDefValidate(const virDomainMemoryDef *mem,
                               const virDomainDef *def);
int virDomainVsockDefValidate(const virDomainVsockDef *vsock);
int virDomainInputDefValidate(const virDomainInputDef *input);
int virDomainShmemDefValidate(const virDomainShmemDef *shmem);
int virDomainDeviceDefValidate(const virDomainDeviceDef *dev,
                               const virDomainDef *def,
                               unsigned int parseFlags,
                               virDomainXMLOptionPtr xmlopt,
                               void *parseOpaque);
