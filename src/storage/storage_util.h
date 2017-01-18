/*
 * storage_util.h: utility functions for storage driver
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

#ifndef __VIR_STORAGE_UTIL_H__
# define __VIR_STORAGE_UTIL_H__

# include <sys/stat.h>

# include "internal.h"
# include "storage_conf.h"
# include "vircommand.h"
# include "storage_driver.h"
# include "storage_backend.h"

/* File creation/cloning functions used for cloning between backends */
int virStorageBackendCreateRaw(virConnectPtr conn,
                               virStoragePoolObjPtr pool,
                               virStorageVolDefPtr vol,
                               virStorageVolDefPtr inputvol,
                               unsigned int flags);

int virStorageBackendCreateQemuImg(virConnectPtr conn,
                                   virStoragePoolObjPtr pool,
                                   virStorageVolDefPtr vol,
                                   virStorageVolDefPtr inputvol,
                                   unsigned int flags);

int virStorageBackendCreatePloop(virConnectPtr conn,
                                 virStoragePoolObjPtr pool,
                                 virStorageVolDefPtr vol,
                                 virStorageVolDefPtr inputvol,
                                 unsigned int flags);

int virStoragePloopResize(virStorageVolDefPtr vol,
                          unsigned long long capacity);

virStorageBackendBuildVolFrom
virStorageBackendGetBuildVolFromFunction(virStorageVolDefPtr vol,
                                         virStorageVolDefPtr inputvol);

int virStorageBackendVolUploadLocal(virConnectPtr conn,
                                    virStoragePoolObjPtr pool,
                                    virStorageVolDefPtr vol,
                                    virStreamPtr stream,
                                    unsigned long long offset,
                                    unsigned long long len,
                                    unsigned int flags);
int virStorageBackendVolDownloadLocal(virConnectPtr conn,
                                      virStoragePoolObjPtr pool,
                                      virStorageVolDefPtr vol,
                                      virStreamPtr stream,
                                      unsigned long long offset,
                                      unsigned long long len,
                                      unsigned int flags);

int virStorageBackendVolWipeLocal(virConnectPtr conn,
                                  virStoragePoolObjPtr pool,
                                  virStorageVolDefPtr vol,
                                  unsigned int algorithm,
                                  unsigned int flags);

/* Local/Common Storage Pool Backend APIs */
int virStorageBackendBuildLocal(virStoragePoolObjPtr pool);

int virStorageBackendUmountLocal(virStoragePoolObjPtr pool);

int virStorageBackendDeleteLocal(virConnectPtr conn,
                                 virStoragePoolObjPtr pool,
                                 unsigned int flags);

int virStorageBackendRefreshLocal(virConnectPtr conn,
                                  virStoragePoolObjPtr pool);

int virStorageBackendFindGlusterPoolSources(const char *host,
                                            int pooltype,
                                            virStoragePoolSourceListPtr list,
                                            bool report);

bool virStorageBackendDeviceIsEmpty(const char *devpath,
                                    const char *format,
                                    bool writelabel);

/* VolOpenCheckMode flags */
enum {
    VIR_STORAGE_VOL_OPEN_NOERROR = 1 << 0, /* don't error if unexpected type
                                            * encountered, just warn */
    VIR_STORAGE_VOL_OPEN_REG     = 1 << 1, /* regular files okay */
    VIR_STORAGE_VOL_OPEN_BLOCK   = 1 << 2, /* block files okay */
    VIR_STORAGE_VOL_OPEN_CHAR    = 1 << 3, /* char files okay */
    VIR_STORAGE_VOL_OPEN_DIR     = 1 << 4, /* directories okay */
};

/* VolReadErrorMode flags
 * If flag is present, then operation won't cause fatal error for
 * specified operation, rather a VIR_WARN will be issued and a -2 returned
 * for function call
 */
enum {
    VIR_STORAGE_VOL_READ_NOERROR    = 1 << 0, /* ignore *read errors */
};

# define VIR_STORAGE_VOL_OPEN_DEFAULT (VIR_STORAGE_VOL_OPEN_REG      |\
                                       VIR_STORAGE_VOL_OPEN_BLOCK)

# define VIR_STORAGE_VOL_FS_OPEN_FLAGS    (VIR_STORAGE_VOL_OPEN_DEFAULT | \
                                           VIR_STORAGE_VOL_OPEN_DIR)
# define VIR_STORAGE_VOL_FS_PROBE_FLAGS   (VIR_STORAGE_VOL_FS_OPEN_FLAGS | \
                                           VIR_STORAGE_VOL_OPEN_NOERROR)

int virStorageBackendVolOpen(const char *path, struct stat *sb,
                             unsigned int flags)
    ATTRIBUTE_RETURN_CHECK
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

# define VIR_STORAGE_DEFAULT_POOL_PERM_MODE 0755
# define VIR_STORAGE_DEFAULT_VOL_PERM_MODE  0600

int virStorageBackendUpdateVolInfo(virStorageVolDefPtr vol,
                                   bool withBlockVolFormat,
                                   unsigned int openflags,
                                   unsigned int readflags);
int virStorageBackendUpdateVolTargetInfoFD(virStorageSourcePtr target,
                                           int fd,
                                           struct stat *sb);

bool virStorageBackendPoolPathIsStable(const char *path);
char *virStorageBackendStablePath(virStoragePoolObjPtr pool,
                                  const char *devpath,
                                  bool loop);

virCommandPtr
virStorageBackendCreateQemuImgCmdFromVol(virConnectPtr conn,
                                         virStoragePoolObjPtr pool,
                                         virStorageVolDefPtr vol,
                                         virStorageVolDefPtr inputvol,
                                         unsigned int flags,
                                         const char *create_tool,
                                         int imgformat,
                                         const char *secretPath);

int virStorageBackendSCSIFindLUs(virStoragePoolObjPtr pool,
                                 uint32_t scanhost);

#endif /* __VIR_STORAGE_UTIL_H__ */
