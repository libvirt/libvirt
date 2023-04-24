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
 */

#pragma once

#include "qemu_conf.h"

bool qemuHostdevNeedsVFIO(const virDomainHostdevDef *hostdev);

bool qemuHostdevHostSupportsPassthroughVFIO(void);

int qemuHostdevUpdateActiveNVMeDisks(virQEMUDriver *driver,
                                     virDomainDef *def);
int qemuHostdevUpdateActiveMediatedDevices(virQEMUDriver *driver,
                                           virDomainDef *def);
int qemuHostdevUpdateActivePCIDevices(virQEMUDriver *driver,
                                      virDomainDef *def);
int qemuHostdevUpdateActiveUSBDevices(virQEMUDriver *driver,
                                      virDomainDef *def);
int qemuHostdevUpdateActiveSCSIDevices(virQEMUDriver *driver,
                                       virDomainDef *def);
int qemuHostdevUpdateActiveDomainDevices(virQEMUDriver *driver,
                                         virDomainDef *def);

int qemuHostdevPrepareOneNVMeDisk(virQEMUDriver *driver,
                                  const char *name,
                                  virStorageSource *src);
int qemuHostdevPrepareNVMeDisks(virQEMUDriver *driver,
                                const char *name,
                                virDomainDiskDef **disks,
                                size_t ndisks);
int qemuHostdevPreparePCIDevices(virQEMUDriver *driver,
                                 const char *name,
                                 const unsigned char *uuid,
                                 virDomainHostdevDef **hostdevs,
                                 int nhostdevs,
                                 unsigned int flags);
int qemuHostdevPrepareUSBDevices(virQEMUDriver *driver,
                                 const char *name,
                                 virDomainHostdevDef **hostdevs,
                                 int nhostdevs,
                                 unsigned int flags);
int qemuHostdevPrepareSCSIDevices(virQEMUDriver *driver,
                                  const char *name,
                                  virDomainHostdevDef **hostdevs,
                                  int nhostdevs);
int qemuHostdevPrepareSCSIVHostDevices(virQEMUDriver *driver,
                                       const char *name,
                                       virDomainHostdevDef **hostdevs,
                                       int nhostdevs);
int qemuHostdevPrepareMediatedDevices(virQEMUDriver *driver,
                                      const char *name,
                                      virDomainHostdevDef **hostdevs,
                                      int nhostdevs);
int qemuHostdevPrepareDomainDevices(virQEMUDriver *driver,
                                    virDomainDef *def,
                                    unsigned int flags);

void qemuHostdevReAttachOneNVMeDisk(virQEMUDriver *driver,
                                    const char *name,
                                    virStorageSource *src);
void qemuHostdevReAttachNVMeDisks(virQEMUDriver *driver,
                                  const char *name,
                                  virDomainDiskDef **disks,
                                  size_t ndisks);
void qemuHostdevReAttachPCIDevices(virQEMUDriver *driver,
                                   const char *name,
                                   virDomainHostdevDef **hostdevs,
                                   int nhostdevs);
void qemuHostdevReAttachUSBDevices(virQEMUDriver *driver,
                                   const char *name,
                                   virDomainHostdevDef **hostdevs,
                                   int nhostdevs);
void qemuHostdevReAttachSCSIDevices(virQEMUDriver *driver,
                                    const char *name,
                                    virDomainHostdevDef **hostdevs,
                                    int nhostdevs);
void qemuHostdevReAttachSCSIVHostDevices(virQEMUDriver *driver,
                                         const char *name,
                                         virDomainHostdevDef **hostdevs,
                                         int nhostdevs);
void qemuHostdevReAttachMediatedDevices(virQEMUDriver *driver,
                                        const char *name,
                                        virDomainHostdevDef **hostdevs,
                                        int nhostdevs);
void qemuHostdevReAttachDomainDevices(virQEMUDriver *driver,
                                      virDomainDef *def);
