/*
 * bhyve_rctl.h: Resource limits management with rctl(8)
 *
 * Copyright (C) 2026 The FreeBSD Foundation
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

#include "domain_conf.h"

int
bhyveRctlGetMemoryHardLimit(pid_t pid, unsigned long long *kb);

int
bhyveRctlSetMemoryHardLimit(pid_t pid, unsigned long long kb);

int
bhyveRctlSetIoLimits(pid_t pid, const virBlkioDevice *device);
