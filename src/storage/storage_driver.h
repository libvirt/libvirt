/*
 * storage_driver.h: core driver for storage APIs
 *
 * Copyright (C) 2006-2008, 2014 Red Hat, Inc.
 * Copyright (C) 2006-2008 Daniel P. Berrange
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

#include "domain_conf.h"
#include "virstorageobj.h"

virStoragePoolObj *virStoragePoolObjFindPoolByUUID(const unsigned char *uuid)
    ATTRIBUTE_NONNULL(1);

virStoragePoolPtr
storagePoolLookupByTargetPath(virConnectPtr conn,
                              const char *path)
    ATTRIBUTE_NONNULL(2);

char *virStoragePoolObjBuildTempFilePath(virStoragePoolObj *obj,
                                         virStorageVolDef *voldef)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) G_GNUC_WARN_UNUSED_RESULT;

int storageRegister(void);
int storageRegisterAll(void);
