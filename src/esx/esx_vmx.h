
/*
 * esx_vmx.h: VMX related functions for the VMware ESX driver
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
# define __ESX_VMX_H__

# include <stdbool.h>

# include "internal.h"
# include "conf.h"
# include "domain_conf.h"
# include "esx_vi.h"

typedef struct _esxVMX_Context esxVMX_Context;



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Context
 */

typedef char * (*esxVMX_ParseFileName)(const char *fileName, void *opaque);
typedef char * (*esxVMX_FormatFileName)(const char *src, void *opaque);
typedef int (*esxVMX_AutodetectSCSIControllerModel)(virDomainDiskDefPtr def,
                                                    int *model, void *opaque);

/*
 * esxVMX_ParseFileName is only used by esxVMX_ParseConfig.
 * esxVMX_FormatFileName is only used by esxVMX_FormatConfig.
 * esxVMX_AutodetectSCSIControllerModel is optionally used by esxVMX_FormatConfig.
 */
struct _esxVMX_Context {
    void *opaque;
    esxVMX_ParseFileName parseFileName;
    esxVMX_FormatFileName formatFileName;
    esxVMX_AutodetectSCSIControllerModel autodetectSCSIControllerModel;
};



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Helpers
 */

int
esxVMX_SCSIDiskNameToControllerAndUnit(const char *name, int *controller,
                                       int *unit);

int
esxVMX_IDEDiskNameToBusAndUnit(const char *name, int *bus, int *unit);

int
esxVMX_FloppyDiskNameToUnit(const char *name, int *unit);

int
esxVMX_VerifyDiskAddress(virCapsPtr caps, virDomainDiskDefPtr disk);

int
esxVMX_HandleLegacySCSIDiskDriverName(virDomainDefPtr def,
                                      virDomainDiskDefPtr disk);

int
esxVMX_GatherSCSIControllers(esxVMX_Context *ctx, virDomainDefPtr def,
                             int virtualDev[4], bool present[4]);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VMX -> Domain XML
 */

virDomainDefPtr
esxVMX_ParseConfig(esxVMX_Context *ctx, virCapsPtr caps, const char *vmx,
                   esxVI_ProductVersion productVersion);

int
esxVMX_ParseVNC(virConfPtr conf, virDomainGraphicsDefPtr *def);

int
esxVMX_ParseSCSIController(virConfPtr conf, int controller, bool *present,
                           int *virtualDev);

int
esxVMX_ParseDisk(esxVMX_Context *ctx, virCapsPtr caps, virConfPtr conf,
                 int device, int busType, int controllerOrBus, int unit,
                 virDomainDiskDefPtr *def);
int
esxVMX_ParseEthernet(virConfPtr conf, int controller, virDomainNetDefPtr *def);

int
esxVMX_ParseSerial(esxVMX_Context *ctx, virConfPtr conf, int port,
                   virDomainChrDefPtr *def);

int
esxVMX_ParseParallel(esxVMX_Context *ctx, virConfPtr conf, int port,
                     virDomainChrDefPtr *def);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Domain XML -> VMX
 */

char *
esxVMX_FormatConfig(esxVMX_Context *ctx, virCapsPtr caps, virDomainDefPtr def,
                    esxVI_ProductVersion productVersion);

int
esxVMX_FormatVNC(virDomainGraphicsDefPtr def, virBufferPtr buffer);

int
esxVMX_FormatHardDisk(esxVMX_Context *ctx, virDomainDiskDefPtr def,
                      virBufferPtr buffer);

int
esxVMX_FormatCDROM(esxVMX_Context *ctx, virDomainDiskDefPtr def,
                   virBufferPtr buffer);

int
esxVMX_FormatFloppy(esxVMX_Context *ctx, virDomainDiskDefPtr def,
                    virBufferPtr buffer, bool floppy_present[2]);

int
esxVMX_FormatEthernet(virDomainNetDefPtr def, int controller,
                      virBufferPtr buffer);

int
esxVMX_FormatSerial(esxVMX_Context *ctx, virDomainChrDefPtr def,
                    virBufferPtr buffer);

int
esxVMX_FormatParallel(esxVMX_Context *ctx, virDomainChrDefPtr def,
                      virBufferPtr buffer);

#endif /* __ESX_VMX_H__ */
