/*
 * qemu_processpriv.h: private declarations for QEMU process management
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

#ifndef __QEMU_PROCESSPRIV_H__
# define __QEMU_PROCESSPRIV_H__

# include "domain_conf.h"
# include "qemu_monitor.h"

/*
 * This header file should never be used outside unit tests.
 */

int qemuProcessHandleDeviceDeleted(qemuMonitorPtr mon,
                                   virDomainObjPtr vm,
                                   const char *devAlias,
                                   void *opaque);

#endif /* __QEMU_PROCESSPRIV_H__ */
