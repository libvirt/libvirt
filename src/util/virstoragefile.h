/*
 * virstoragefile.h: file utility functions for FS storage backend
 *
 * Copyright (C) 2007-2009, 2012-2016 Red Hat, Inc.
 * Copyright (C) 2007-2008 Daniel P. Berrange
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

#pragma once

#include "internal.h"

int virStorageFileParseBackingStoreStr(const char *str,
                                       char **target,
                                       unsigned int *chainIndex)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(3);

int virStorageFileGetSCSIKey(const char *path,
                             char **key,
                             bool ignoreError);
int virStorageFileGetNPIVKey(const char *path,
                             char **key);
