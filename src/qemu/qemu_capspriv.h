/*
 * qemu_capspriv.h: private declarations for QEMU capabilities generation
 *
 * Copyright (C) 2015 Samsung Electronics Co. Ltd
 * Copyright (C) 2015 Pavel Fedin
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

#ifndef LIBVIRT_QEMU_CAPSPRIV_H_ALLOW
# error "qemu_capspriv.h may only be included by qemu_capabilities.c or test suites"
#endif /* LIBVIRT_QEMU_CAPSPRIV_H_ALLOW */

#pragma once

virQEMUCaps *virQEMUCapsNewCopy(virQEMUCaps *qemuCaps);

virQEMUCaps *
virQEMUCapsNewForBinaryInternal(virArch hostArch,
                                const char *binary,
                                const char *libDir,
                                uid_t runUid,
                                gid_t runGid,
                                const char *hostCPUSignature,
                                unsigned int microcodeVersion,
                                const char *kernelVersion,
                                virCPUData* cpuData);

int virQEMUCapsLoadCache(virArch hostArch,
                         virQEMUCaps *qemuCaps,
                         const char *filename,
                         bool skipInvalidation);
char *virQEMUCapsFormatCache(virQEMUCaps *qemuCaps);

int
virQEMUCapsInitQMPMonitor(virQEMUCaps *qemuCaps,
                          qemuMonitor *mon);

int
virQEMUCapsInitQMPMonitorTCG(virQEMUCaps *qemuCaps,
                             qemuMonitor *mon);

void
virQEMUCapsSetArch(virQEMUCaps *qemuCaps,
                   virArch arch);

void
virQEMUCapsUpdateHostCPUModel(virQEMUCaps *qemuCaps,
                              virArch hostArch,
                              virDomainVirtType type);
int
virQEMUCapsInitCPUModel(virQEMUCaps *qemuCaps,
                        virDomainVirtType type,
                        virCPUDef *cpu,
                        bool migratable);

qemuMonitorCPUModelInfo *
virQEMUCapsGetCPUModelInfo(virQEMUCaps *qemuCaps,
                           virDomainVirtType type);

void
virQEMUCapsSetCPUModelInfo(virQEMUCaps *qemuCaps,
                           virDomainVirtType type,
                           qemuMonitorCPUModelInfo *modelInfo);

virCPUData *
virQEMUCapsGetCPUModelX86Data(virQEMUCaps *qemuCaps,
                              qemuMonitorCPUModelInfo *model,
                              bool migratable);

virCPUDef *
virQEMUCapsProbeHostCPU(virArch hostArch,
                        virDomainCapsCPUModels *models) G_NO_INLINE;

void
virQEMUCapsSetGICCapabilities(virQEMUCaps *qemuCaps,
                              virGICCapability *capabilities,
                              size_t ncapabilities);

int
virQEMUCapsProbeCPUDefinitionsTest(virQEMUCaps *qemuCaps,
                                   qemuMonitor *mon);

void
virQEMUCapsSetMicrocodeVersion(virQEMUCaps *qemuCaps,
                               unsigned int microcodeVersion);

void
virQEMUCapsStripMachineAliases(virQEMUCaps *qemuCaps);

bool
virQEMUCapsHasMachines(virQEMUCaps *qemuCaps);

bool
virQEMUCapsHaveAccel(virQEMUCaps *qemuCaps);
