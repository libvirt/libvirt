/*
 * vmx.h: VMware VMX parsing/formatting functions
 *
 * Copyright (C) 2009-2011, 2015 Matthias Bolte <matthias.bolte@googlemail.com>
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

#pragma once

#include "internal.h"
#include "domain_conf.h"

#define VMX_CONFIG_FORMAT_ARGV "vmware-vmx"

typedef struct _virVMXContext virVMXContext;

virDomainXMLOption *virVMXDomainXMLConfInit(virCaps *caps);


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Context
 */

typedef int (*virVMXParseFileName)(const char *fileName,
                                   void *opaque,
                                   char **src,
                                   bool allow_missing);
typedef char * (*virVMXFormatFileName)(const char *src, void *opaque);
typedef int (*virVMXAutodetectSCSIControllerModel)(virDomainDiskDef *def,
                                                   int *model, void *opaque);

/*
 * parseFileName is only used by virVMXParseConfig.
 * formatFileName is only used by virVMXFormatConfig.
 * autodetectSCSIControllerModel is optionally used by virVMXFormatConfig.
 * datacenterPath is only used by virVMXFormatConfig.
 * moref is only used by virVMXFormatConfig.
 */
struct _virVMXContext {
    void *opaque;
    virVMXParseFileName parseFileName;
    virVMXFormatFileName formatFileName;
    virVMXAutodetectSCSIControllerModel autodetectSCSIControllerModel;
    const char *datacenterPath; /* including folders */
    const char *moref;
};



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Helpers
 */

char *virVMXEscapeHex(const char *string, char escape, const char *special);

#define virVMXEscapeHexPipe(_string) virVMXEscapeHex(_string, '|', "\"")

#define virVMXEscapeHexPercent(_string) virVMXEscapeHex(_string, '%', "/\\")

int virVMXUnescapeHex(char *string, char escape);

#define virVMXUnescapeHexPipe(_string) virVMXUnescapeHex(_string, '|')

#define virVMXUnescapeHexPercent(_string) virVMXUnescapeHex(_string, '%')

char *virVMXConvertToUTF8(const char *encoding, const char *string);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VMX -> Domain XML
 */

virDomainDef *virVMXParseConfig(virVMXContext *ctx,
                                  virDomainXMLOption *xmlopt,
                                  virCaps *caps,
                                  const char *vmx);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Domain XML -> VMX
 */

char *virVMXFormatConfig(virVMXContext *ctx, virDomainXMLOption *xmlopt,
                         virDomainDef *def, int virtualHW_version);
