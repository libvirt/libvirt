/*
 * qemu_dbus.h: QEMU DBus-related helpers
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

typedef struct _qemuDBusVMState qemuDBusVMState;
typedef qemuDBusVMState *qemuDBusVMStatePtr;
struct _qemuDBusVMState {
    char *id;
    char *addr;
};


qemuDBusVMStatePtr qemuDBusVMStateNew(const char *id, const char *addr);

void qemuDBusVMStateFree(qemuDBusVMStatePtr self);

int qemuDBusVMStateAdd(virQEMUDriverPtr driver, virDomainObjPtr vm,
                       const char *id, const char *addr, bool hot);

void qemuDBusVMStateRemove(virQEMUDriverPtr driver, virDomainObjPtr vm,
                           const char *id, bool hot);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(qemuDBusVMState, qemuDBusVMStateFree);
