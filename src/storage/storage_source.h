/*
 * storage_source.h: Storage source accessors to real storaget
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

#ifndef __VIR_STORAGE_SOURCE_H__
# define __VIR_STORAGE_SOURCE_H__

# include <sys/stat.h>

# include "virstoragefile.h"

int virStorageFileInit(virStorageSourcePtr src);
int virStorageFileInitAs(virStorageSourcePtr src,
                         uid_t uid, gid_t gid);
void virStorageFileDeinit(virStorageSourcePtr src);

int virStorageFileCreate(virStorageSourcePtr src);
int virStorageFileUnlink(virStorageSourcePtr src);
int virStorageFileStat(virStorageSourcePtr src,
                       struct stat *stat);
ssize_t virStorageFileRead(virStorageSourcePtr src,
                           size_t offset,
                           size_t len,
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

#endif /* __VIR_STORAGE_SOURCE_H__ */
