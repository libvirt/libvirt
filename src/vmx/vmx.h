
/*
 * vmx.h: VMware VMX parsing/formatting functions
 *
 * Copyright (C) 2009-2010 Matthias Bolte <matthias.bolte@googlemail.com>
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

#ifndef __VIR_VMX_H__
# define __VIR_VMX_H__

# include "internal.h"
# include "conf.h"
# include "domain_conf.h"

typedef struct _virVMXContext virVMXContext;



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Context
 */

typedef char * (*virVMXParseFileName)(const char *fileName, void *opaque);
typedef char * (*virVMXFormatFileName)(const char *src, void *opaque);
typedef int (*virVMXAutodetectSCSIControllerModel)(virDomainDiskDefPtr def,
                                                   int *model, void *opaque);

/*
 * virVMXParseFileName is only used by virVMXParseConfig.
 * virVMXFormatFileName is only used by virVMXFormatConfig.
 * virVMXAutodetectSCSIControllerModel is optionally used by virVMXFormatConfig.
 */
struct _virVMXContext {
    void *opaque;
    virVMXParseFileName parseFileName;
    virVMXFormatFileName formatFileName;
    virVMXAutodetectSCSIControllerModel autodetectSCSIControllerModel;
};



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Helpers
 */

char *virVMXEscapeHex(const char *string, char escape, const char *special);

# define virVMXEscapeHexPipe(_string) virVMXEscapeHex(_string, '|', "\"")

# define virVMXEscapeHexPercent(_string) virVMXEscapeHex(_string, '%', "/\\")

int virVMXUnescapeHex(char *string, char escape);

# define virVMXUnescapeHexPipe(_string) virVMXUnescapeHex(_string, '|')

# define virVMXUnescapeHexPercent(_string) virVMXUnescapeHex(_string, '%')

char *virVMXConvertToUTF8(const char *encoding, const char *string);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VMX -> Domain XML
 */

virDomainDefPtr virVMXParseConfig(virVMXContext *ctx, virCapsPtr caps,
                                  const char *vmx);

int virVMXParseVNC(virConfPtr conf, virDomainGraphicsDefPtr *def);

int virVMXParseSCSIController(virConfPtr conf, int controller, bool *present,
                              int *virtualDev);

int virVMXParseDisk(virVMXContext *ctx, virCapsPtr caps, virConfPtr conf,
                    int device, int busType, int controllerOrBus, int unit,
                    virDomainDiskDefPtr *def);

int virVMXParseEthernet(virConfPtr conf, int controller, virDomainNetDefPtr *def);

int virVMXParseSerial(virVMXContext *ctx, virConfPtr conf, int port,
                      virDomainChrDefPtr *def);

int virVMXParseParallel(virVMXContext *ctx, virConfPtr conf, int port,
                        virDomainChrDefPtr *def);

int virVMXParseSVGA(virConfPtr conf, virDomainVideoDefPtr *def);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Domain XML -> VMX
 */

char *virVMXFormatConfig(virVMXContext *ctx, virCapsPtr caps,
                         virDomainDefPtr def, int virtualHW_version);

int virVMXFormatVNC(virDomainGraphicsDefPtr def, virBufferPtr buffer);

int virVMXFormatHardDisk(virVMXContext *ctx, virDomainDiskDefPtr def,
                         virBufferPtr buffer);

int virVMXFormatCDROM(virVMXContext *ctx, virDomainDiskDefPtr def,
                      virBufferPtr buffer);

int virVMXFormatFloppy(virVMXContext *ctx, virDomainDiskDefPtr def,
                       virBufferPtr buffer, bool floppy_present[2]);

int virVMXFormatEthernet(virDomainNetDefPtr def, int controller,
                         virBufferPtr buffer);

int virVMXFormatSerial(virVMXContext *ctx, virDomainChrDefPtr def,
                       virBufferPtr buffer);

int virVMXFormatParallel(virVMXContext *ctx, virDomainChrDefPtr def,
                         virBufferPtr buffer);

int virVMXFormatSVGA(virDomainVideoDefPtr def, virBufferPtr buffer);

#endif /* __VIR_VMX_H__ */
