/*
 * qemu_hostdev.h: QEMU hostdev management
 *
 * Copyright (C) 2006-2007, 2009-2013 Red Hat, Inc.
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

#ifndef __QEMU_HOSTDEV_H__
# define __QEMU_HOSTDEV_H__

# include "qemu_conf.h"
# include "domain_conf.h"

bool qemuHostdevHostSupportsPassthroughLegacy(void);
bool qemuHostdevHostSupportsPassthroughVFIO(void);

int qemuHostdevUpdateActiveMediatedDevices(virQEMUDriverPtr driver,
                                           virDomainDefPtr def);
int qemuHostdevUpdateActivePCIDevices(virQEMUDriverPtr driver,
                                      virDomainDefPtr def);
int qemuHostdevUpdateActiveUSBDevices(virQEMUDriverPtr driver,
                                      virDomainDefPtr def);
int qemuHostdevUpdateActiveSCSIDevices(virQEMUDriverPtr driver,
                                       virDomainDefPtr def);
int qemuHostdevUpdateActiveDomainDevices(virQEMUDriverPtr driver,
                                         virDomainDefPtr def);

int qemuHostdevPreparePCIDevices(virQEMUDriverPtr driver,
                                 const char *name,
                                 const unsigned char *uuid,
                                 virDomainHostdevDefPtr *hostdevs,
                                 int nhostdevs,
                                 virQEMUCapsPtr qemuCaps,
                                 unsigned int flags);
int qemuHostdevPrepareUSBDevices(virQEMUDriverPtr driver,
                                 const char *name,
                                 virDomainHostdevDefPtr *hostdevs,
                                 int nhostdevs,
                                 unsigned int flags);
int qemuHostdevPrepareSCSIDevices(virQEMUDriverPtr driver,
                                  const char *name,
                                  virDomainHostdevDefPtr *hostdevs,
                                  int nhostdevs);
int qemuHostdevPrepareSCSIVHostDevices(virQEMUDriverPtr driver,
                                       const char *name,
                                       virDomainHostdevDefPtr *hostdevs,
                                       int nhostdevs);
int qemuHostdevPrepareMediatedDevices(virQEMUDriverPtr driver,
                                      const char *name,
                                      virDomainHostdevDefPtr *hostdevs,
                                      int nhostdevs);
int qemuHostdevPrepareDomainDevices(virQEMUDriverPtr driver,
                                    virDomainDefPtr def,
                                    virQEMUCapsPtr qemuCaps,
                                    unsigned int flags);

void qemuHostdevReAttachPCIDevices(virQEMUDriverPtr driver,
                                   const char *name,
                                   virDomainHostdevDefPtr *hostdevs,
                                   int nhostdevs);
void qemuHostdevReAttachUSBDevices(virQEMUDriverPtr driver,
                                   const char *name,
                                   virDomainHostdevDefPtr *hostdevs,
                                   int nhostdevs);
void qemuHostdevReAttachSCSIDevices(virQEMUDriverPtr driver,
                                    const char *name,
                                    virDomainHostdevDefPtr *hostdevs,
                                    int nhostdevs);
void qemuHostdevReAttachSCSIVHostDevices(virQEMUDriverPtr driver,
                                         const char *name,
                                         virDomainHostdevDefPtr *hostdevs,
                                         int nhostdevs);
void qemuHostdevReAttachMediatedDevices(virQEMUDriverPtr driver,
                                        const char *name,
                                        virDomainHostdevDefPtr *hostdevs,
                                        int nhostdevs);
void qemuHostdevReAttachDomainDevices(virQEMUDriverPtr driver,
                                      virDomainDefPtr def);

#endif /* __QEMU_HOSTDEV_H__ */
