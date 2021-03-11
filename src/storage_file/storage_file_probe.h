/*
 * storage_file_probe.h: file utility functions for FS storage backend
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

#include <sys/stat.h>

#include "storage_source_conf.h"

/* Minimum header size required to probe all known formats with
 * virStorageFileProbeFormat, or obtain metadata from a known format.
 * Rounded to multiple of 512 (ISO has a 5-byte magic at offset
 * 32769).  Some formats can be probed with fewer bytes.  Although
 * some formats theoretically permit metadata that can rely on offsets
 * beyond this size, in practice that doesn't matter.  */
#define VIR_STORAGE_MAX_HEADER 0x8200

int
virStorageFileProbeGetMetadata(virStorageSource *meta,
                               char *buf,
                               size_t len);

int
virStorageFileProbeFormat(const char *path,
                          uid_t uid,
                          gid_t gid);
