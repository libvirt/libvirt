/*
 * vircgroupv2devices.h: methods for cgroups v2 BPF devices
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

#include <sys/types.h>

#include "internal.h"

#include "vircgroup.h"

bool
virCgroupV2DevicesAvailable(virCgroup *group)
    G_NO_INLINE;

int
virCgroupV2DevicesDetectProg(virCgroup *group);

int
virCgroupV2DevicesCreateProg(virCgroup *group);

int
virCgroupV2DevicesPrepareProg(virCgroup *group);

int
virCgroupV2DevicesCloseProg(virCgroup *group);

uint32_t
virCgroupV2DevicesGetPerms(int perms,
                           char type);

uint64_t
virCgroupV2DevicesGetKey(int major,
                         int minor);
