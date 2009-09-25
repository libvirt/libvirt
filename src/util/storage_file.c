/*
 * storage_file.c: file utility functions for FS storage backend
 *
 * Copyright (C) 2007-2009 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>
#include "storage_file.h"

VIR_ENUM_IMPL(virStorageFileFormat,
              VIR_STORAGE_FILE_LAST,
              "raw", "dir", "bochs",
              "cloop", "cow", "dmg", "iso",
              "qcow", "qcow2", "vmdk", "vpc")
