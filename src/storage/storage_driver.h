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
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef __VIR_STORAGE_DRIVER_H__
# define __VIR_STORAGE_DRIVER_H__

# include <sys/stat.h>

# include "domain_conf.h"
# include "virstorageobj.h"

int virStorageTranslateDiskSourcePool(virConnectPtr conn,
                                      virDomainDiskDefPtr def);

virStoragePoolObjPtr virStoragePoolObjFindPoolByUUID(const unsigned char *uuid)
    ATTRIBUTE_NONNULL(1);

virStoragePoolPtr
storagePoolLookupByTargetPath(virConnectPtr conn,
                              const char *path)
    ATTRIBUTE_NONNULL(2);

char *virStoragePoolObjBuildTempFilePath(virStoragePoolObjPtr pool,
                                         virStorageVolDefPtr vol)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;

int storageRegister(void);
int storageRegisterAll(void);

#endif /* __VIR_STORAGE_DRIVER_H__ */
