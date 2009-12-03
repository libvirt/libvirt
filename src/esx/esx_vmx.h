
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
#include "conf.h"
#include "domain_conf.h"
#include "esx_vi.h"

int
esxVMX_SCSIDiskNameToControllerAndID(virConnectPtr conn, const char *name,
                                     int *controller, int *id);

int
esxVMX_IDEDiskNameToControllerAndID(virConnectPtr conn, const char *name,
                                    int *controller, int *id);

int
esxVMX_FloppyDiskNameToController(virConnectPtr conn, const char *name,
                                  int *controller);

int
esxVMX_GatherSCSIControllers(virConnectPtr conn, virDomainDefPtr conf,
                             char *virtualDev[4], int present[4]);

char *
esxVMX_AbsolutePathToDatastoreRelatedPath(virConnectPtr conn,
                                          esxVI_Context *ctx,
                                          const char *absolutePath);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VMX -> Domain XML
 */

char *
esxVMX_ParseFileName(virConnectPtr conn, esxVI_Context *ctx,
                     const char *fileName, const char *datastoreName,
                     const char *directoryName);

virDomainDefPtr
esxVMX_ParseConfig(virConnectPtr conn, esxVI_Context *ctx, const char *vmx,
                   const char *datastoreName, const char *directoryName,
                   esxVI_APIVersion apiVersion);

int
esxVMX_ParseSCSIController(virConnectPtr conn, virConfPtr conf,
                           int controller, int *present, char **virtualDev);

int
esxVMX_ParseDisk(virConnectPtr conn, esxVI_Context *ctx, virConfPtr conf,
                 int device, int bus, int controller, int id,
                 const char *virtualDev, const char *datastoreName,
                 const char *directoryName, virDomainDiskDefPtr *def);
int
esxVMX_ParseEthernet(virConnectPtr conn, virConfPtr conf, int controller,
                     virDomainNetDefPtr *def);

int
esxVMX_ParseSerial(virConnectPtr conn, esxVI_Context *ctx, virConfPtr conf,
                   int port, const char *datastoreName,
                   const char *directoryName, virDomainChrDefPtr *def);

int
esxVMX_ParseParallel(virConnectPtr conn, esxVI_Context *ctx, virConfPtr conf,
                     int port, const char *datastoreName,
                     const char *directoryName, virDomainChrDefPtr *def);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Domain XML -> VMX
 */

char *
esxVMX_FormatFileName(virConnectPtr conn, esxVI_Context *ctx, const char *src);

char *
esxVMX_FormatConfig(virConnectPtr conn, esxVI_Context *ctx,
                    virDomainDefPtr def, esxVI_APIVersion apiVersion);

int
esxVMX_FormatHardDisk(virConnectPtr conn, esxVI_Context *ctx,
                      virDomainDiskDefPtr def, virBufferPtr buffer);

int
esxVMX_FormatCDROM(virConnectPtr conn, esxVI_Context *ctx,
                   virDomainDiskDefPtr def, virBufferPtr buffer);

int
esxVMX_FormatFloppy(virConnectPtr conn, esxVI_Context *ctx,
                    virDomainDiskDefPtr def, virBufferPtr buffer);

int
esxVMX_FormatEthernet(virConnectPtr conn, virDomainNetDefPtr def,
                      int controller, virBufferPtr buffer);

int
esxVMX_FormatSerial(virConnectPtr conn, esxVI_Context *ctx,
                    virDomainChrDefPtr def, virBufferPtr buffer);

int
esxVMX_FormatParallel(virConnectPtr conn, esxVI_Context *ctx,
                      virDomainChrDefPtr def, virBufferPtr buffer);

#endif /* __ESX_VMX_H__ */
