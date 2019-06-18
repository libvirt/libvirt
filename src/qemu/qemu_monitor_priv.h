/*
 * qemu_monitor_priv.h: interaction with QEMU monitor console (private)
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

#ifndef LIBVIRT_QEMU_MONITOR_PRIV_H_ALLOW
# error "qemu_monitor_priv.h may only be included by qemu_monitor.c or test suites"
#endif /* LIBVIRT_QEMU_MONITOR_PRIV_H_ALLOW */

#pragma once

#include "qemu_monitor.h"

void
qemuMonitorResetCommandID(qemuMonitorPtr mon);
