/*
 * qemu_hotplugpriv.h: private declarations for QEMU device hotplug management
 *
 * Copyright (C) 2013 Red Hat, Inc.
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
 */

#ifndef LIBVIRT_QEMU_HOTPLUGPRIV_H_ALLOW
# error "qemu_hotplugpriv.h may only be included by qemu_hotplug.c or test suites"
#endif /* LIBVIRT_QEMU_HOTPLUGPRIV_H_ALLOW */

#pragma once

/*
 * This header file should never be used outside unit tests.
 */

extern unsigned long long qemuDomainRemoveDeviceWaitTime;
