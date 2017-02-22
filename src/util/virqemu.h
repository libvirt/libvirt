/*
 * virqemu.h: utilities for working with qemu and its tools
 *
 * Copyright (C) 2009, 2012-2016 Red Hat, Inc.
 * Copyright (C) 2009 Daniel P. Berrange
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


#ifndef __VIR_QEMU_H_
# define __VIR_QEMU_H_

# include "internal.h"
# include "virbuffer.h"
# include "virjson.h"
# include "virstorageencryption.h"

typedef int (*virQEMUBuildCommandLineJSONArrayFormatFunc)(const char *key,
                                                          virJSONValuePtr array,
                                                          virBufferPtr buf);
int virQEMUBuildCommandLineJSONArrayBitmap(const char *key,
                                           virJSONValuePtr array,
                                           virBufferPtr buf);
int virQEMUBuildCommandLineJSONArrayNumbered(const char *key,
                                             virJSONValuePtr array,
                                             virBufferPtr buf);

int virQEMUBuildCommandLineJSON(virJSONValuePtr value,
                                virBufferPtr buf,
                                virQEMUBuildCommandLineJSONArrayFormatFunc array);

char *virQEMUBuildObjectCommandlineFromJSON(const char *type,
                                            const char *alias,
                                            virJSONValuePtr props);

char *virQEMUBuildDriveCommandlineFromJSON(virJSONValuePtr src);

void virQEMUBuildBufferEscapeComma(virBufferPtr buf, const char *str);
void virQEMUBuildBufferEscape(virBufferPtr buf, const char *str);
void virQEMUBuildLuksOpts(virBufferPtr buf,
                          virStorageEncryptionInfoDefPtr enc,
                          const char *alias)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);

#endif /* __VIR_QEMU_H_ */
