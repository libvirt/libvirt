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

#ifndef LIBVIRT_STORAGE_UTIL_H
# define LIBVIRT_STORAGE_UTIL_H

# include <sys/stat.h>

# include "internal.h"
# include "vircommand.h"
# include "storage_driver.h"
# include "storage_backend.h"

/* Storage Pool Namespace options to share w/ storage_backend_fs.c and
 * the virStorageBackendFileSystemMountCmd method */
typedef struct _virStoragePoolFSMountOptionsDef virStoragePoolFSMountOptionsDef;
typedef virStoragePoolFSMountOptionsDef *virStoragePoolFSMountOptionsDefPtr;
struct _virStoragePoolFSMountOptionsDef {
    size_t noptions;
    char **options;
};

int
virStorageBackendNamespaceInit(int poolType,
                               virStoragePoolXMLNamespacePtr xmlns);


/* File creation/cloning functions used for cloning between backends */

int
virStorageBackendCreateVolUsingQemuImg(virStoragePoolObjPtr pool,
                                       virStorageVolDefPtr vol,
                                       virStorageVolDefPtr inputvol,
                                       unsigned int flags);

virStorageBackendBuildVolFrom
virStorageBackendGetBuildVolFromFunction(virStorageVolDefPtr vol,
                                         virStorageVolDefPtr inputvol);

int virStorageBackendVolCreateLocal(virStoragePoolObjPtr pool,
                                    virStorageVolDefPtr vol);

int virStorageBackendVolBuildLocal(virStoragePoolObjPtr pool,
                                   virStorageVolDefPtr vol,
                                   unsigned int flags);

int virStorageBackendVolBuildFromLocal(virStoragePoolObjPtr pool,
                                       virStorageVolDefPtr vol,
                                       virStorageVolDefPtr inputvol,
                                       unsigned int flags);

int virStorageBackendVolDeleteLocal(virStoragePoolObjPtr pool,
                                    virStorageVolDefPtr vol,
                                    unsigned int flags);

int virStorageBackendVolRefreshLocal(virStoragePoolObjPtr pool,
                                     virStorageVolDefPtr vol);

int virStorageBackendVolResizeLocal(virStoragePoolObjPtr pool,
                                    virStorageVolDefPtr vol,
                                    unsigned long long capacity,
                                    unsigned int flags);

int virStorageBackendVolUploadLocal(virStoragePoolObjPtr pool,
                                    virStorageVolDefPtr vol,
                                    virStreamPtr stream,
                                    unsigned long long offset,
                                    unsigned long long len,
                                    unsigned int flags);

int virStorageBackendVolDownloadLocal(virStoragePoolObjPtr pool,
                                      virStorageVolDefPtr vol,
                                      virStreamPtr stream,
                                      unsigned long long offset,
                                      unsigned long long len,
                                      unsigned int flags);

int virStorageBackendVolWipeLocal(virStoragePoolObjPtr pool,
                                  virStorageVolDefPtr vol,
                                  unsigned int algorithm,
                                  unsigned int flags);

/* Local/Common Storage Pool Backend APIs */
int virStorageBackendBuildLocal(virStoragePoolObjPtr pool);

int virStorageBackendDeleteLocal(virStoragePoolObjPtr pool,
                                 unsigned int flags);

int
virStorageBackendRefreshVolTargetUpdate(virStorageVolDefPtr vol);

int virStorageBackendRefreshLocal(virStoragePoolObjPtr pool);

int virStorageUtilGlusterExtractPoolSources(const char *host,
                                            const char *xml,
                                            virStoragePoolSourceListPtr list,
                                            virStoragePoolType pooltype);
int virStorageBackendFindGlusterPoolSources(const char *host,
                                            virStoragePoolType pooltype,
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

# define VIR_STORAGE_DEFAULT_POOL_PERM_MODE 0711
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

typedef enum {
    VIR_STORAGE_VOL_ENCRYPT_NONE = 0,
    VIR_STORAGE_VOL_ENCRYPT_CREATE,
    VIR_STORAGE_VOL_ENCRYPT_CONVERT,
    VIR_STORAGE_VOL_ENCRYPT_DONE,
} virStorageVolEncryptConvertStep;

virCommandPtr
virStorageBackendCreateQemuImgCmdFromVol(virStoragePoolObjPtr pool,
                                         virStorageVolDefPtr vol,
                                         virStorageVolDefPtr inputvol,
                                         unsigned int flags,
                                         const char *create_tool,
                                         const char *secretPath,
                                         const char *inputSecretPath,
                                         virStorageVolEncryptConvertStep convertStep);

int virStorageBackendSCSIFindLUs(virStoragePoolObjPtr pool,
                                 uint32_t scanhost);

int
virStorageBackendZeroPartitionTable(const char *path,
                                    unsigned long long size);

char *
virStorageBackendFileSystemGetPoolSource(virStoragePoolObjPtr pool);

virCommandPtr
virStorageBackendFileSystemMountCmd(const char *cmdstr,
                                    virStoragePoolDefPtr def,
                                    const char *src);

virCommandPtr
virStorageBackendLogicalChangeCmd(const char *cmdstr,
                                  virStoragePoolDefPtr def,
                                  bool on);

#endif /* LIBVIRT_STORAGE_UTIL_H */
