/*
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

#include "internal.h"
#include "qemu/qemu_capabilities.h"
#define __QEMU_CAPSRIV_H_ALLOW__
#include "qemu/qemu_capspriv.h"
#undef __QEMU_CAPSRIV_H_ALLOW__


virCPUDefPtr
virQEMUCapsProbeHostCPUForEmulator(virCapsPtr caps,
                                   virQEMUCapsPtr qemuCaps ATTRIBUTE_UNUSED,
                                   virDomainVirtType type ATTRIBUTE_UNUSED)
{
    if (!caps || !caps->host.cpu || !caps->host.cpu->model)
        return NULL;

    return virCPUDefCopy(caps->host.cpu);
}
