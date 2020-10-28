/*
 * qemu_dbus.h: QEMU dbus daemon
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
#include "qemu_domain.h"

char *qemuDBusGetAddress(virQEMUDriverPtr driver,
                         virDomainObjPtr vm);

int qemuDBusStart(virQEMUDriverPtr driver,
                  virDomainObjPtr vm);

void qemuDBusStop(virQEMUDriverPtr driver,
                  virDomainObjPtr vm);

int qemuDBusVMStateAdd(virDomainObjPtr vm, const char *id);

void qemuDBusVMStateRemove(virDomainObjPtr vm, const char *id);

int qemuDBusSetupCgroup(virQEMUDriverPtr driver,
                        virDomainObjPtr vm,
                        virCgroupPtr cgroup);
