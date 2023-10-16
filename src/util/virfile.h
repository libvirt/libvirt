/*
 * virfile.h: safer file handling
 *
 * Copyright (C) 2010-2014 Red Hat, Inc.
 * Copyright (C) 2010 IBM Corporation
 * Copyright (C) 2010 Stefan Berger
 * Copyright (C) 2010 Eric Blake
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

#pragma once

#include <dirent.h>

#include "internal.h"
#include "virbitmap.h"
#include "virenum.h"

typedef enum {
    VIR_FILE_CLOSE_PRESERVE_ERRNO = 1 << 0,
    VIR_FILE_CLOSE_IGNORE_EBADF = 1 << 1,
    VIR_FILE_CLOSE_DONT_LOG = 1 << 2,
} virFileCloseFlags;

#ifdef __APPLE__
# define VIR_FILE_MODULE_EXT ".dylib"
#else
# define VIR_FILE_MODULE_EXT ".so"
#endif

ssize_t saferead(int fd, void *buf, size_t count) G_GNUC_WARN_UNUSED_RESULT;
ssize_t safewrite(int fd, const void *buf, size_t count)
    G_GNUC_WARN_UNUSED_RESULT;
int safezero(int fd, off_t offset, off_t len)
    G_GNUC_WARN_UNUSED_RESULT;
int virFileAllocate(int fd, off_t offset, off_t len)
    G_GNUC_WARN_UNUSED_RESULT;

/* Don't call these directly - use the macros below */
int virFileClose(int *fdptr, virFileCloseFlags flags)
        G_GNUC_WARN_UNUSED_RESULT;
int virFileFclose(FILE **file, bool preserve_errno) G_GNUC_WARN_UNUSED_RESULT;
FILE *virFileFdopen(int *fdptr, const char *mode) G_GNUC_WARN_UNUSED_RESULT;

static inline void virForceCloseHelper(int *fd)
{
    ignore_value(virFileClose(fd, VIR_FILE_CLOSE_PRESERVE_ERRNO));
}

int virCloseRange(unsigned int from, unsigned int to);
int virCloseRangeInit(void);
bool virCloseRangeIsSupported(void);
int virCloseFrom(int fromfd);

/* For use on normal paths; caller must check return value,
   and failure sets errno per close. */
#define VIR_CLOSE(FD) virFileClose(&(FD), 0)
#define VIR_FCLOSE(FILE) virFileFclose(&(FILE), false)

/* Wrapper around fdopen that consumes fd on success. */
#define VIR_FDOPEN(FD, MODE) virFileFdopen(&(FD), MODE)

/* For use on cleanup paths; errno is unaffected by close,
   and no return value to worry about. */
#define VIR_FORCE_CLOSE(FD) virForceCloseHelper(&(FD))
#define VIR_FORCE_FCLOSE(FILE) ignore_value(virFileFclose(&(FILE), true))

/* Similar VIR_FORCE_CLOSE() but ignores EBADF errors since they are expected
 * during mass close after fork(). */
#define VIR_MASS_CLOSE(FD) \
    ignore_value(virFileClose(&(FD), \
                 VIR_FILE_CLOSE_PRESERVE_ERRNO | \
                 VIR_FILE_CLOSE_IGNORE_EBADF))

#define VIR_LOG_CLOSE(FD) \
    ignore_value(virFileClose(&(FD), \
                 VIR_FILE_CLOSE_PRESERVE_ERRNO | \
                 VIR_FILE_CLOSE_DONT_LOG))

/**
 * VIR_AUTOCLOSE:
 *
 * Macro to automatically force close the fd by calling virForceCloseHelper
 * when the fd goes out of scope. It's used to eliminate VIR_FORCE_CLOSE
 * in cleanup sections.
 */
#define VIR_AUTOCLOSE __attribute__((cleanup(virForceCloseHelper))) int

G_DEFINE_AUTOPTR_CLEANUP_FUNC(FILE, fclose);

/* Opaque type for managing a wrapper around a fd.  */
struct _virFileWrapperFd;

typedef struct _virFileWrapperFd virFileWrapperFd;

int virFileDirectFdFlag(void);

typedef enum {
    VIR_FILE_WRAPPER_BYPASS_CACHE   = (1 << 0),
    VIR_FILE_WRAPPER_NON_BLOCKING   = (1 << 1),
} virFileWrapperFdFlags;

virFileWrapperFd *virFileWrapperFdNew(int *fd,
                                        const char *name,
                                        unsigned int flags)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) G_GNUC_WARN_UNUSED_RESULT;

int virFileWrapperFdClose(virFileWrapperFd *dfd);

void virFileWrapperFdFree(virFileWrapperFd *dfd);

int virFileLock(int fd, bool shared, off_t start, off_t len, bool waitForLock)
    G_NO_INLINE;
int virFileUnlock(int fd, off_t start, off_t len)
    G_NO_INLINE;

typedef int (*virFileRewriteFunc)(int fd,
                                  const char *path,
                                  const void *opaque);
int virFileRewrite(const char *path,
                   mode_t mode,
                   uid_t uid, gid_t gid,
                   virFileRewriteFunc rewrite,
                   const void *opaque);
int virFileRewriteStr(const char *path,
                      mode_t mode,
                      const char *str);

int virFileResize(const char *path,
                  unsigned long long capacity,
                  bool pre_allocate);

int virFileTouch(const char *path, mode_t mode);

int virFileUpdatePerm(const char *path,
                      mode_t mode_remove,
                      mode_t mode_add);

int virFileLoopDeviceAssociate(const char *file,
                               char **dev);

int virFileNBDDeviceAssociate(const char *file,
                              const char *fmtstr,
                              bool readonly,
                              char **dev);

int virFileDeleteTree(const char *dir);

int virFileReadHeaderFD(int fd, int maxlen, char **buf)
    G_GNUC_WARN_UNUSED_RESULT ATTRIBUTE_NONNULL(3);
int virFileReadHeaderQuiet(const char *path, int maxlen, char **buf)
    G_GNUC_WARN_UNUSED_RESULT ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(3);
int virFileReadLimFD(int fd, int maxlen, char **buf)
    G_GNUC_WARN_UNUSED_RESULT ATTRIBUTE_NONNULL(3);
int virFileReadAll(const char *path, int maxlen, char **buf)
    G_GNUC_WARN_UNUSED_RESULT ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(3);
int virFileReadAllQuiet(const char *path, int maxlen, char **buf)
    G_GNUC_WARN_UNUSED_RESULT ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(3);
int virFileReadBufQuiet(const char *file, char *buf, int len)
    G_GNUC_WARN_UNUSED_RESULT ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int virFileWriteStr(const char *path, const char *str, mode_t mode)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) G_GNUC_WARN_UNUSED_RESULT;

int virFileLinkPointsTo(const char *checkLink,
                        const char *checkDest)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);
int virFileRelLinkPointsTo(const char *directory,
                           const char *checkLink,
                           const char *checkDest)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);

int virFileResolveLink(const char *linkpath,
                       char **resultpath) G_GNUC_WARN_UNUSED_RESULT;
int virFileResolveAllLinks(const char *linkpath,
                           char **resultpath) G_GNUC_WARN_UNUSED_RESULT;

int virFileIsLink(const char *linkpath)
    ATTRIBUTE_NONNULL(1) G_GNUC_WARN_UNUSED_RESULT;

char *virFindFileInPath(const char *file)
    G_NO_INLINE;
char *virFindFileInPathFull(const char *file,
                            const char *const *extraDirs)
    G_NO_INLINE;

char *virFileFindResource(const char *filename,
                          const char *builddir,
                          const char *installdir)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);
char *virFileFindResourceFull(const char *filename,
                              const char *prefix,
                              const char *suffix,
                              const char *builddir,
                              const char *installdir,
                              const char *envname)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(4) ATTRIBUTE_NONNULL(5);
void virFileActivateDirOverrideForProg(const char *argv0)
    ATTRIBUTE_NONNULL(1);
void virFileActivateDirOverrideForLib(void);

off_t virFileLength(const char *path, int fd) ATTRIBUTE_NONNULL(1);
bool virFileIsDir (const char *file) ATTRIBUTE_NONNULL(1);
bool virFileExists(const char *file) ATTRIBUTE_NONNULL(1) G_NO_INLINE;
bool virFileIsExecutable(const char *file) ATTRIBUTE_NONNULL(1);
bool virFileIsRegular(const char *file) ATTRIBUTE_NONNULL(1);

enum {
    VIR_FILE_SHFS_NFS = (1 << 0),
    VIR_FILE_SHFS_GFS2 = (1 << 1), /* Global File System 2 */
    VIR_FILE_SHFS_OCFS = (1 << 2), /* Oracle Cluster FS (2) */
    VIR_FILE_SHFS_AFS = (1 << 3), /* Andrew File System */
    VIR_FILE_SHFS_SMB = (1 << 4), /* Server message block - windows shares */
    VIR_FILE_SHFS_CIFS = (1 << 5), /* Common Internet File System - windows shares */
    VIR_FILE_SHFS_CEPH = (1 << 6),
    VIR_FILE_SHFS_GPFS = (1 << 7), /* General Parallel File System/IBM Spectrum Scale */
    VIR_FILE_SHFS_QB = (1 << 8), /* Quobyte shared filesystem */
    VIR_FILE_SHFS_ACFS = (1 << 9), /* Oracle ASM Cluster File System */
    VIR_FILE_SHFS_GLUSTERFS = (1 << 10), /* gluster's FUSE-based client */
    VIR_FILE_SHFS_BEEGFS = (1 << 11), /* BeeGFS/fhGFS */
};

int virFileIsSharedFSType(const char *path, unsigned int fstypes) ATTRIBUTE_NONNULL(1);
int virFileIsSharedFS(const char *path) ATTRIBUTE_NONNULL(1);
int virFileIsClusterFS(const char *path) ATTRIBUTE_NONNULL(1);
int virFileIsMountPoint(const char *file) ATTRIBUTE_NONNULL(1);
int virFileIsCDROM(const char *path)
    ATTRIBUTE_NONNULL(1) G_GNUC_WARN_UNUSED_RESULT;

int virFileGetMountSubtree(const char *mtabpath,
                           const char *prefix,
                           char ***mountsret,
                           size_t *nmountsret) G_GNUC_WARN_UNUSED_RESULT;
int virFileGetMountReverseSubtree(const char *mtabpath,
                                  const char *prefix,
                                  char ***mountsret,
                                  size_t *nmountsret) G_GNUC_WARN_UNUSED_RESULT;

char *virFileSanitizePath(const char *path);
char *virFileCanonicalizePath(const char *path) G_NO_INLINE;

enum {
    VIR_FILE_OPEN_NONE        = 0,
    VIR_FILE_OPEN_NOFORK      = (1 << 0),
    VIR_FILE_OPEN_FORK        = (1 << 1),
    VIR_FILE_OPEN_FORCE_MODE  = (1 << 2),
    VIR_FILE_OPEN_FORCE_OWNER = (1 << 3),
};
int virFileAccessibleAs(const char *path, int mode,
                        uid_t uid, gid_t gid)
    ATTRIBUTE_NONNULL(1) G_GNUC_WARN_UNUSED_RESULT;
int virFileOpenAs(const char *path, int openflags, mode_t mode,
                  uid_t uid, gid_t gid,
                  unsigned int flags)
    ATTRIBUTE_NONNULL(1) G_GNUC_WARN_UNUSED_RESULT;
int virFileRemove(const char *path, uid_t uid, gid_t gid);

int virFileChownFiles(const char *name, uid_t uid, gid_t gid)
    ATTRIBUTE_NONNULL(1) G_GNUC_WARN_UNUSED_RESULT;

enum {
    VIR_DIR_CREATE_NONE        = 0,
    VIR_DIR_CREATE_AS_UID      = (1 << 0),
    VIR_DIR_CREATE_ALLOW_EXIST = (1 << 1),
};
int virDirCreate(const char *path, mode_t mode, uid_t uid, gid_t gid,
                 unsigned int flags) G_GNUC_WARN_UNUSED_RESULT;
int virDirOpen(DIR **dirp, const char *dirname)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) G_GNUC_WARN_UNUSED_RESULT;
int virDirOpenIfExists(DIR **dirp, const char *dirname)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) G_GNUC_WARN_UNUSED_RESULT;
int virDirOpenQuiet(DIR **dirp, const char *dirname)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) G_GNUC_WARN_UNUSED_RESULT;
int virDirRead(DIR *dirp, struct dirent **ent, const char *dirname)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) G_GNUC_WARN_UNUSED_RESULT;
void virDirClose(DIR *dirp);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(DIR, virDirClose);
int virDirIsEmpty(const char *path,
                  bool hidden)
    ATTRIBUTE_NONNULL(1) G_GNUC_WARN_UNUSED_RESULT;

int virFileMakeParentPath(const char *path) G_GNUC_WARN_UNUSED_RESULT;

char *virFileBuildPath(const char *dir,
                       const char *name,
                       const char *ext) G_GNUC_WARN_UNUSED_RESULT;

void virFileRemoveLastComponent(char *path);

int virFileOpenTty(int *ttymaster,
                   char **ttyName,
                   int rawmode);

char *virFileFindMountPoint(const char *type);

typedef struct _virHugeTLBFS virHugeTLBFS;
struct _virHugeTLBFS {
    char *mnt_dir;                  /* Where the FS is mount to */
    unsigned long long size;        /* page size in kibibytes */
    bool deflt;                     /* is this the default huge page size */
};

int virFileGetHugepageSize(const char *path,
                           unsigned long long *size);
int virFileFindHugeTLBFS(virHugeTLBFS **ret_fs,
                         size_t *ret_nfs);

virHugeTLBFS *virFileGetDefaultHugepage(virHugeTLBFS *fs,
                                          size_t nfs);

int virFileSetupDev(const char *path,
                    const char *mount_options);

int virFileBindMountDevice(const char *src,
                           const char *dst);

int virFileMoveMount(const char *src,
                     const char *dst);

int virFileGetACLs(const char *file,
                   void **acl);

int virFileSetACLs(const char *file,
                   void *acl);

void virFileFreeACLs(void **acl);

int virFileCopyACLs(const char *src,
                    const char *dst);

int virFileComparePaths(const char *p1, const char *p2);

int virFileReadValueInt(int *value, const char *format, ...)
 G_GNUC_PRINTF(2, 3);
int virFileReadValueUint(unsigned int *value, const char *format, ...)
 G_GNUC_PRINTF(2, 3);
int virFileReadValueUllong(unsigned long long *value, const char *format, ...)
 G_GNUC_PRINTF(2, 3);
int virFileReadValueUllongQuiet(unsigned long long *value, const char *format, ...)
 G_GNUC_PRINTF(2, 3);
int virFileReadValueBitmap(virBitmap **value, const char *format, ...)
 G_GNUC_PRINTF(2, 3);
int virFileReadValueScaledInt(unsigned long long *value, const char *format, ...)
 G_GNUC_PRINTF(2, 3);
int virFileReadValueString(char **value, const char *format, ...)
 G_GNUC_PRINTF(2, 3);

int virFileWaitForExists(const char *path, size_t ms, size_t tries);


int virFileInData(int fd,
                  int *inData,
                  long long *length);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virFileWrapperFd, virFileWrapperFdFree);

int virFileGetXAttr(const char *path,
                    const char *name,
                    char **value)
    G_NO_INLINE;

int virFileGetXAttrQuiet(const char *path,
                         const char *name,
                         char **value)
    G_NO_INLINE;

int virFileSetXAttr(const char *path,
                    const char *name,
                    const char *value)
    G_NO_INLINE;

int virFileRemoveXAttr(const char *path,
                       const char *name)
    G_NO_INLINE;

int virFileDataSync(int fd);

int virFileSetCOW(const char *path,
                  virTristateBool state);

off_t virFileDiskCopy(int disk_fd, const char *disk_path, int remote_fd, const char *remote_path);
