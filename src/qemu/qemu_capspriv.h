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
 *
 * Author: Pavel Fedin <p.fedin@samsung.com>
 */

#ifndef __QEMU_CAPSPRIV_H_ALLOW__
# error "qemu_capspriv.h may only be included by qemu_capabilities.c or test suites"
#endif

#ifndef __QEMU_CAPSPRIV_H__
# define __QEMU_CAPSPRIV_H__

virQEMUCapsPtr virQEMUCapsNewCopy(virQEMUCapsPtr qemuCaps);

virQEMUCapsPtr
virQEMUCapsNewForBinaryInternal(virArch hostArch,
                                const char *binary,
                                const char *libDir,
                                uid_t runUid,
                                gid_t runGid,
                                unsigned int microcodeVersion,
                                const char *kernelVersion);

int virQEMUCapsLoadCache(virArch hostArch,
                         virQEMUCapsPtr qemuCaps,
                         const char *filename);
char *virQEMUCapsFormatCache(virQEMUCapsPtr qemuCaps);

int
virQEMUCapsInitQMPMonitor(virQEMUCapsPtr qemuCaps,
                          qemuMonitorPtr mon);

int
virQEMUCapsInitQMPMonitorTCG(virQEMUCapsPtr qemuCaps,
                             qemuMonitorPtr mon);

void
virQEMUCapsSetArch(virQEMUCapsPtr qemuCaps,
                   virArch arch);

void
virQEMUCapsFreeHostCPUModel(virQEMUCapsPtr qemuCaps,
                            virArch hostArch,
                            virDomainVirtType type);

void
virQEMUCapsInitHostCPUModel(virQEMUCapsPtr qemuCaps,
                            virArch hostArch,
                            virDomainVirtType type);

int
virQEMUCapsInitCPUModel(virQEMUCapsPtr qemuCaps,
                        virDomainVirtType type,
                        virCPUDefPtr cpu,
                        bool migratable);

void
virQEMUCapsInitQMPBasicArch(virQEMUCapsPtr qemuCaps);

void
virQEMUCapsSetCPUModelInfo(virQEMUCapsPtr qemuCaps,
                           virDomainVirtType type,
                           qemuMonitorCPUModelInfoPtr modelInfo);

virCPUDefPtr
virQEMUCapsProbeHostCPUForEmulator(virArch hostArch,
                                   virQEMUCapsPtr qemuCaps,
                                   virDomainVirtType type) ATTRIBUTE_NOINLINE;

void
virQEMUCapsSetGICCapabilities(virQEMUCapsPtr qemuCaps,
                              virGICCapability *capabilities,
                              size_t ncapabilities);

void
virQEMUCapsSetSEVCapabilities(virQEMUCapsPtr qemuCaps,
                              virSEVCapability *capabilities);

int
virQEMUCapsProbeQMPCPUDefinitions(virQEMUCapsPtr qemuCaps,
                                  qemuMonitorPtr mon,
                                  bool tcg);

void
virQEMUCapsSetMicrocodeVersion(virQEMUCapsPtr qemuCaps,
                               unsigned int microcodeVersion);

void
virQEMUCapsStripMachineAliases(virQEMUCapsPtr qemuCaps);
#endif
