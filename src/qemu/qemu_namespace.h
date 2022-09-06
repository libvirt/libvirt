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

typedef enum {
    QEMU_DOMAIN_NS_MOUNT = 0,
    QEMU_DOMAIN_NS_LAST
} qemuDomainNamespace;
VIR_ENUM_DECL(qemuDomainNamespace);

int qemuDomainEnableNamespace(virDomainObj *vm,
                              qemuDomainNamespace ns);

bool qemuDomainNamespaceEnabled(virDomainObj *vm,
                                qemuDomainNamespace ns);

int qemuDomainUnshareNamespace(virQEMUDriverConfig *cfg,
                               virSecurityManager *mgr,
                               virDomainObj *vm);

int qemuDomainBuildNamespace(virQEMUDriverConfig *cfg,
                             virDomainObj *vm);

void qemuDomainDestroyNamespace(virQEMUDriver *driver,
                                virDomainObj *vm);

bool qemuDomainNamespaceAvailable(qemuDomainNamespace ns);

int qemuDomainNamespaceSetupPath(virDomainObj *vm,
                                 const char *path,
                                 bool *created);

int qemuDomainNamespaceSetupDisk(virDomainObj *vm,
                                 virStorageSource *src,
                                 bool *created);

int qemuDomainNamespaceTeardownDisk(virDomainObj *vm,
                                    virStorageSource *src);

int qemuDomainNamespaceSetupHostdev(virDomainObj *vm,
                                    virDomainHostdevDef *hostdev,
                                    bool *created);

int qemuDomainNamespaceTeardownHostdev(virDomainObj *vm,
                                       virDomainHostdevDef *hostdev);

int qemuDomainNamespaceSetupMemory(virDomainObj *vm,
                                   virDomainMemoryDef *memory,
                                   bool *created);

int qemuDomainNamespaceTeardownMemory(virDomainObj *vm,
                                      virDomainMemoryDef *memory);

int qemuDomainNamespaceSetupChardev(virDomainObj *vm,
                                    virDomainChrDef *chr,
                                    bool *created);

int qemuDomainNamespaceTeardownChardev(virDomainObj *vm,
                                       virDomainChrDef *chr);

int qemuDomainNamespaceSetupRNG(virDomainObj *vm,
                                virDomainRNGDef *rng,
                                bool *created);

int qemuDomainNamespaceTeardownRNG(virDomainObj *vm,
                                   virDomainRNGDef *rng);

int qemuDomainNamespaceSetupInput(virDomainObj *vm,
                                  virDomainInputDef *input,
                                  bool *created);

int qemuDomainNamespaceTeardownInput(virDomainObj *vm,
                                     virDomainInputDef *input);
