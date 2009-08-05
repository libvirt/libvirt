
/*
 * esx_vmx.c: VMX related methods for the VMware ESX driver
 *
 * Copyright (C) 2009 Matthias Bolte <matthias.bolte@googlemail.com>
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 */

#ifndef __ESX_VMX_H__
#define __ESX_VMX_H__

#include "internal.h"
#include "domain_conf.h"
#include "esx_vi.h"

virDomainDefPtr
esxVMX_ParseConfig(virConnectPtr conn, const char *vmx,
                   esxVI_APIVersion apiVersion);

int
esxVMX_ParseSCSIController(virConnectPtr conn, virConfPtr conf,
                           int controller, int *present, char **virtualDev);

char *
esxVMX_IndexToDiskName(virConnectPtr conn, int idx, const char *prefix);

int
esxVMX_ParseDisk(virConnectPtr conn, virConfPtr conf, int device, int bus,
                 int controller, int id, const char *virtualDev,
                 virDomainDiskDefPtr *def);
int
esxVMX_ParseEthernet(virConnectPtr conn, virConfPtr conf, int controller,
                     virDomainNetDefPtr *def);

int
esxVMX_ParseSerial(virConnectPtr conn, virConfPtr conf, int port,
                   virDomainChrDefPtr *def);

int
esxVMX_ParseParallel(virConnectPtr conn, virConfPtr conf, int port,
                     virDomainChrDefPtr *def);

#endif /* __ESX_VMX_H__ */
