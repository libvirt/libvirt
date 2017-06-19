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
# include "virstoragefile.h"

int virStorageFileInit(virStorageSourcePtr src);
int virStorageFileInitAs(virStorageSourcePtr src,
                         uid_t uid, gid_t gid);
void virStorageFileDeinit(virStorageSourcePtr src);

int virStorageFileCreate(virStorageSourcePtr src);
int virStorageFileUnlink(virStorageSourcePtr src);
int virStorageFileStat(virStorageSourcePtr src,
                       struct stat *stat);
ssize_t virStorageFileReadHeader(virStorageSourcePtr src,
                                 ssize_t max_len,
                                 char **buf);
const char *virStorageFileGetUniqueIdentifier(virStorageSourcePtr src);
int virStorageFileAccess(virStorageSourcePtr src, int mode);
int virStorageFileChown(const virStorageSource *src, uid_t uid, gid_t gid);

bool virStorageFileSupportsSecurityDriver(const virStorageSource *src);

int virStorageFileGetMetadata(virStorageSourcePtr src,
                              uid_t uid, gid_t gid,
                              bool allow_probe,
                              bool report_broken)
    ATTRIBUTE_NONNULL(1);

char *virStorageFileGetBackingStoreStr(virStorageSourcePtr src)
    ATTRIBUTE_NONNULL(1);

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
