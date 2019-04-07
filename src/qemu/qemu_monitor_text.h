/*
 * qemu_monitor_text.h: interaction with QEMU monitor console
 *
 * Copyright (C) 2006-2009, 2011-2012 Red Hat, Inc.
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

#ifndef LIBVIRT_QEMU_MONITOR_TEXT_H
# define LIBVIRT_QEMU_MONITOR_TEXT_H

# include "internal.h"

# include "qemu_monitor.h"

int qemuMonitorTextSetCPU(qemuMonitorPtr mon, int cpu, bool online);

int qemuMonitorTextAddDrive(qemuMonitorPtr mon,
                             const char *drivestr);

int qemuMonitorTextDriveDel(qemuMonitorPtr mon,
                             const char *drivestr);

int qemuMonitorTextCreateSnapshot(qemuMonitorPtr mon, const char *name);
int qemuMonitorTextLoadSnapshot(qemuMonitorPtr mon, const char *name);
int qemuMonitorTextDeleteSnapshot(qemuMonitorPtr mon, const char *name);

#endif /* LIBVIRT_QEMU_MONITOR_TEXT_H */
