
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
esxVMX_SCSIDiskNameToControllerAndID(const char *name, int *controller, int *id);

int
esxVMX_IDEDiskNameToControllerAndID(const char *name, int *controller, int *id);

int
esxVMX_FloppyDiskNameToController(const char *name, int *controller);

int
esxVMX_GatherSCSIControllers(virDomainDefPtr conf, char *virtualDev[4],
                             int present[4]);

char *
esxVMX_AbsolutePathToDatastoreRelatedPath(esxVI_Context *ctx,
                                          const char *absolutePath);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VMX -> Domain XML
 */

char *
esxVMX_ParseFileName(esxVI_Context *ctx, const char *fileName,
                     const char *datastoreName, const char *directoryName);

virDomainDefPtr
esxVMX_ParseConfig(esxVI_Context *ctx, const char *vmx,
                   const char *datastoreName, const char *directoryName,
                   esxVI_APIVersion apiVersion);

int
esxVMX_ParseVNC(virConfPtr conf, virDomainGraphicsDefPtr *def);

int
esxVMX_ParseSCSIController(virConfPtr conf, int controller, int *present,
                           char **virtualDev);

int
esxVMX_ParseDisk(esxVI_Context *ctx, virConfPtr conf, int device, int bus,
                 int controller, int id, const char *virtualDev,
                 const char *datastoreName, const char *directoryName,
                 virDomainDiskDefPtr *def);
int
esxVMX_ParseEthernet(virConfPtr conf, int controller, virDomainNetDefPtr *def);

int
esxVMX_ParseSerial(esxVI_Context *ctx, virConfPtr conf, int port,
                   const char *datastoreName, const char *directoryName,
                   virDomainChrDefPtr *def);

int
esxVMX_ParseParallel(esxVI_Context *ctx, virConfPtr conf, int port,
                     const char *datastoreName, const char *directoryName,
                     virDomainChrDefPtr *def);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Domain XML -> VMX
 */

char *
esxVMX_FormatFileName(esxVI_Context *ctx, const char *src);

char *
esxVMX_FormatConfig(esxVI_Context *ctx, virDomainDefPtr def,
                    esxVI_APIVersion apiVersion);

int
esxVMX_FormatVNC(virDomainGraphicsDefPtr def, virBufferPtr buffer);

int
esxVMX_FormatHardDisk(esxVI_Context *ctx, virDomainDiskDefPtr def,
                      virBufferPtr buffer);

int
esxVMX_FormatCDROM(esxVI_Context *ctx, virDomainDiskDefPtr def,
                   virBufferPtr buffer);

int
esxVMX_FormatFloppy(esxVI_Context *ctx, virDomainDiskDefPtr def,
                    virBufferPtr buffer);

int
esxVMX_FormatEthernet(virDomainNetDefPtr def, int controller,
                      virBufferPtr buffer);

int
esxVMX_FormatSerial(esxVI_Context *ctx, virDomainChrDefPtr def,
                    virBufferPtr buffer);

int
esxVMX_FormatParallel(esxVI_Context *ctx, virDomainChrDefPtr def,
                      virBufferPtr buffer);

#endif /* __ESX_VMX_H__ */
