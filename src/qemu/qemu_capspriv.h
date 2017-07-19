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

# include "virarch.h"

struct _virQEMUCapsCachePriv {
    char *libDir;
    uid_t runUid;
    gid_t runGid;
    virArch hostArch;
};
typedef struct _virQEMUCapsCachePriv virQEMUCapsCachePriv;
typedef virQEMUCapsCachePriv *virQEMUCapsCachePrivPtr;


virQEMUCapsPtr virQEMUCapsNewCopy(virQEMUCapsPtr qemuCaps);

virQEMUCapsPtr
virQEMUCapsNewForBinaryInternal(virArch hostArch,
                                const char *binary,
                                const char *libDir,
                                uid_t runUid,
                                gid_t runGid,
                                bool qmpOnly);

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
virQEMUCapsSetVersion(virQEMUCapsPtr qemuCaps,
                      unsigned int version);

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

int
virQEMUCapsParseHelpStr(const char *qemu,
                        const char *str,
                        virQEMUCapsPtr qemuCaps,
                        unsigned int *version,
                        bool *is_kvm,
                        unsigned int *kvm_version,
                        bool check_yajl,
                        const char *qmperr);

int
virQEMUCapsParseDeviceStr(virQEMUCapsPtr qemuCaps,
                          const char *str);
#endif
