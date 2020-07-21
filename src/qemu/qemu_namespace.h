/*
 * qemu_namespace.h: QEMU domain namespace helpers
 *
 * Copyright (C) 2006-2020 Red Hat, Inc.
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

#include "virenum.h"
#include "qemu_conf.h"
#include "virconf.h"

typedef enum {
    QEMU_DOMAIN_NS_MOUNT = 0,
    QEMU_DOMAIN_NS_LAST
} qemuDomainNamespace;
VIR_ENUM_DECL(qemuDomainNamespace);

int qemuDomainEnableNamespace(virDomainObjPtr vm,
                              qemuDomainNamespace ns);

bool qemuDomainNamespaceEnabled(virDomainObjPtr vm,
                                qemuDomainNamespace ns);

int qemuDomainUnshareNamespace(virQEMUDriverConfigPtr cfg,
                               virSecurityManagerPtr mgr,
                               virDomainObjPtr vm);

int qemuDomainBuildNamespace(virQEMUDriverConfigPtr cfg,
                             virDomainObjPtr vm);

void qemuDomainDestroyNamespace(virQEMUDriverPtr driver,
                                virDomainObjPtr vm);

bool qemuDomainNamespaceAvailable(qemuDomainNamespace ns);

int qemuDomainNamespaceSetupDisk(virDomainObjPtr vm,
                                 virStorageSourcePtr src);

int qemuDomainNamespaceTeardownDisk(virDomainObjPtr vm,
                                    virStorageSourcePtr src);

int qemuDomainNamespaceSetupHostdev(virDomainObjPtr vm,
                                    virDomainHostdevDefPtr hostdev);

int qemuDomainNamespaceTeardownHostdev(virDomainObjPtr vm,
                                       virDomainHostdevDefPtr hostdev);

int qemuDomainNamespaceSetupMemory(virDomainObjPtr vm,
                                   virDomainMemoryDefPtr memory);

int qemuDomainNamespaceTeardownMemory(virDomainObjPtr vm,
                                      virDomainMemoryDefPtr memory);

int qemuDomainNamespaceSetupChardev(virDomainObjPtr vm,
                                    virDomainChrDefPtr chr);

int qemuDomainNamespaceTeardownChardev(virDomainObjPtr vm,
                                       virDomainChrDefPtr chr);

int qemuDomainNamespaceSetupRNG(virDomainObjPtr vm,
                                virDomainRNGDefPtr rng);

int qemuDomainNamespaceTeardownRNG(virDomainObjPtr vm,
                                   virDomainRNGDefPtr rng);

int qemuDomainNamespaceSetupInput(virDomainObjPtr vm,
                                  virDomainInputDefPtr input);

int qemuDomainNamespaceTeardownInput(virDomainObjPtr vm,
                                     virDomainInputDefPtr input);
