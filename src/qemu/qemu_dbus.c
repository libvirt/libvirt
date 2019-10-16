/*
 * qemu_dbus.c: QEMU DBus-related helpers
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

#include <config.h>

#include "qemu_extdevice.h"
#include "qemu_dbus.h"
#include "qemu_hotplug.h"
#include "qemu_security.h"

#include "viralloc.h"
#include "virlog.h"
#include "virstring.h"
#include "virtime.h"
#include "virpidfile.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.dbus");


qemuDBusVMStatePtr
qemuDBusVMStateNew(const char *id, const char *addr)
{
    g_autoptr(qemuDBusVMState) self = NULL;

    if (VIR_ALLOC(self) < 0)
        return NULL;

    if (VIR_STRDUP(self->id, id) < 0)
        return NULL;

    if (VIR_STRDUP(self->addr, addr) < 0)
        return NULL;

    return g_steal_pointer(&self);
}


void
qemuDBusVMStateFree(qemuDBusVMStatePtr self)
{
    if (!self)
        return;

    VIR_FREE(self->id);
    VIR_FREE(self->addr);
    VIR_FREE(self);
}


int
qemuDBusVMStateAdd(virQEMUDriverPtr driver, virDomainObjPtr vm,
                   const char *id, const char *addr, bool hot)
{
    qemuDBusVMStatePtr d = qemuDBusVMStateNew(id, addr);
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (virHashAddEntry(priv->dbusVMStates, id, d) < 0) {
        qemuDBusVMStateFree(d);
        return -1;
    }

    if (hot && virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DBUS_VMSTATE) &&
        qemuDomainAttachDBusVMState(driver, vm, id, addr, QEMU_ASYNC_JOB_NONE) < 0)
        return -1;

    return 0;
}


void
qemuDBusVMStateRemove(virQEMUDriverPtr driver, virDomainObjPtr vm,
                      const char *id, bool hot)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (virHashRemoveEntry(priv->dbusVMStates, id) < 0 ||
        (hot && virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DBUS_VMSTATE) &&
         qemuDomainDetachDBusVMState(driver, vm, id, QEMU_ASYNC_JOB_NONE) < 0))
        VIR_ERROR(_("Failed to remove vmstate id '%s'"), vm->def->name);
}
