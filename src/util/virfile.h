/*
 * virfile.h: safer file handling
 *
 * Copyright (C) 2010-2011, 2013 Red Hat, Inc.
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


#ifndef __VIR_FILE_H_
# define __VIR_FILE_H_

# include <stdio.h>

# include "internal.h"
# include "virstoragefile.h"

typedef enum virFileCloseFlags {
    VIR_FILE_CLOSE_PRESERVE_ERRNO = 1 << 0,
    VIR_FILE_CLOSE_IGNORE_EBADF = 1 << 1,
    VIR_FILE_CLOSE_DONT_LOG = 1 << 2,
} virFileCloseFlags;

ssize_t saferead(int fd, void *buf, size_t count) ATTRIBUTE_RETURN_CHECK;
ssize_t safewrite(int fd, const void *buf, size_t count)
    ATTRIBUTE_RETURN_CHECK;
int safezero(int fd, off_t offset, off_t len)
    ATTRIBUTE_RETURN_CHECK;

/* Don't call these directly - use the macros below */
int virFileClose(int *fdptr, virFileCloseFlags flags)
        ATTRIBUTE_RETURN_CHECK;
int virFileFclose(FILE **file, bool preserve_errno) ATTRIBUTE_RETURN_CHECK;
FILE *virFileFdopen(int *fdptr, const char *mode) ATTRIBUTE_RETURN_CHECK;

/* For use on normal paths; caller must check return value,
   and failure sets errno per close. */
# define VIR_CLOSE(FD) virFileClose(&(FD), 0)
# define VIR_FCLOSE(FILE) virFileFclose(&(FILE), false)

/* Wrapper around fdopen that consumes fd on success. */
# define VIR_FDOPEN(FD, MODE) virFileFdopen(&(FD), MODE)

/* For use on cleanup paths; errno is unaffected by close,
   and no return value to worry about. */
# define VIR_FORCE_CLOSE(FD) \
    ignore_value(virFileClose(&(FD), VIR_FILE_CLOSE_PRESERVE_ERRNO))
# define VIR_FORCE_FCLOSE(FILE) ignore_value(virFileFclose(&(FILE), true))

/* Similar VIR_FORCE_CLOSE() but ignores EBADF errors since they are expected
 * during mass close after fork(). */
# define VIR_MASS_CLOSE(FD)                         \
    ignore_value(virFileClose(&(FD),                \
                 VIR_FILE_CLOSE_PRESERVE_ERRNO |    \
                 VIR_FILE_CLOSE_IGNORE_EBADF))

# define VIR_LOG_CLOSE(FD)                          \
    ignore_value(virFileClose(&(FD),                \
                 VIR_FILE_CLOSE_PRESERVE_ERRNO |    \
                 VIR_FILE_CLOSE_DONT_LOG))

/* Opaque type for managing a wrapper around a fd.  */
struct _virFileWrapperFd;

typedef struct _virFileWrapperFd virFileWrapperFd;
typedef virFileWrapperFd *virFileWrapperFdPtr;

int virFileDirectFdFlag(void);

enum virFileWrapperFdFlags {
    VIR_FILE_WRAPPER_BYPASS_CACHE   = (1 << 0),
    VIR_FILE_WRAPPER_NON_BLOCKING   = (1 << 1),
};

virFileWrapperFdPtr virFileWrapperFdNew(int *fd,
                                        const char *name,
                                        unsigned int flags)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;

int virFileWrapperFdClose(virFileWrapperFdPtr dfd);

void virFileWrapperFdFree(virFileWrapperFdPtr dfd);

int virFileLock(int fd, bool shared, off_t start, off_t len, bool waitForLock);
int virFileUnlock(int fd, off_t start, off_t len);

typedef int (*virFileRewriteFunc)(int fd, void *opaque);
int virFileRewrite(const char *path,
                   mode_t mode,
                   virFileRewriteFunc rewrite,
                   void *opaque);

int virFileTouch(const char *path, mode_t mode);

int virFileUpdatePerm(const char *path,
                      mode_t mode_remove,
                      mode_t mode_add);

int virFileLoopDeviceAssociate(const char *file,
                               char **dev);

int virFileNBDDeviceAssociate(const char *file,
                              enum virStorageFileFormat fmt,
                              bool readonly,
                              char **dev);

int virFileDeleteTree(const char *dir);

int virFileReadHeaderFD(int fd, int maxlen, char **buf)
    ATTRIBUTE_RETURN_CHECK ATTRIBUTE_NONNULL(3);
int virFileReadLimFD(int fd, int maxlen, char **buf)
    ATTRIBUTE_RETURN_CHECK ATTRIBUTE_NONNULL(3);
int virFileReadAll(const char *path, int maxlen, char **buf)
    ATTRIBUTE_RETURN_CHECK ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(3);

int virFileWriteStr(const char *path, const char *str, mode_t mode)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;

int virFileMatchesNameSuffix(const char *file,
                             const char *name,
                             const char *suffix);

int virFileHasSuffix(const char *str,
                     const char *suffix);

int virFileStripSuffix(char *str,
                       const char *suffix) ATTRIBUTE_RETURN_CHECK;

int virFileLinkPointsTo(const char *checkLink,
                        const char *checkDest);

int virFileResolveLink(const char *linkpath,
                       char **resultpath) ATTRIBUTE_RETURN_CHECK;
int virFileResolveAllLinks(const char *linkpath,
                           char **resultpath) ATTRIBUTE_RETURN_CHECK;

int virFileIsLink(const char *linkpath)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;

char *virFindFileInPath(const char *file);

bool virFileIsDir (const char *file) ATTRIBUTE_NONNULL(1);
bool virFileExists(const char *file) ATTRIBUTE_NONNULL(1);
bool virFileIsExecutable(const char *file) ATTRIBUTE_NONNULL(1);

int virFileIsMountPoint(const char *file) ATTRIBUTE_NONNULL(1);

int virFileGetMountSubtree(const char *mtabpath,
                           const char *prefix,
                           char ***mountsret,
                           size_t *nmountsret) ATTRIBUTE_RETURN_CHECK;
int virFileGetMountReverseSubtree(const char *mtabpath,
                                  const char *prefix,
                                  char ***mountsret,
                                  size_t *nmountsret) ATTRIBUTE_RETURN_CHECK;

char *virFileSanitizePath(const char *path);

enum {
    VIR_FILE_OPEN_NONE        = 0,
    VIR_FILE_OPEN_NOFORK      = (1 << 0),
    VIR_FILE_OPEN_FORK        = (1 << 1),
    VIR_FILE_OPEN_FORCE_MODE  = (1 << 2),
    VIR_FILE_OPEN_FORCE_OWNER = (1 << 3),
};
int virFileAccessibleAs(const char *path, int mode,
                        uid_t uid, gid_t gid)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;
int virFileOpenAs(const char *path, int openflags, mode_t mode,
                  uid_t uid, gid_t gid,
                  unsigned int flags)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;

enum {
    VIR_DIR_CREATE_NONE        = 0,
    VIR_DIR_CREATE_AS_UID      = (1 << 0),
    VIR_DIR_CREATE_FORCE_PERMS = (1 << 1),
    VIR_DIR_CREATE_ALLOW_EXIST = (1 << 2),
};
int virDirCreate(const char *path, mode_t mode, uid_t uid, gid_t gid,
                 unsigned int flags) ATTRIBUTE_RETURN_CHECK;
int virFileMakePath(const char *path) ATTRIBUTE_RETURN_CHECK;
int virFileMakePathWithMode(const char *path,
                            mode_t mode) ATTRIBUTE_RETURN_CHECK;
int virFileMakeParentPath(const char *path) ATTRIBUTE_RETURN_CHECK;

char *virFileBuildPath(const char *dir,
                       const char *name,
                       const char *ext) ATTRIBUTE_RETURN_CHECK;


# ifdef WIN32
/* On Win32, the canonical directory separator is the backslash, and
 * the search path separator is the semicolon. Note that also the
 * (forward) slash works as directory separator.
 */
#  define VIR_FILE_DIR_SEPARATOR '\\'
#  define VIR_FILE_DIR_SEPARATOR_S "\\"
#  define VIR_FILE_IS_DIR_SEPARATOR(c) ((c) == VIR_FILE_DIR_SEPARATOR || (c) == '/')
#  define VIR_FILE_PATH_SEPARATOR ';'
#  define VIR_FILE_PATH_SEPARATOR_S ";"

# else  /* !WIN32 */

#  define VIR_FILE_DIR_SEPARATOR '/'
#  define VIR_FILE_DIR_SEPARATOR_S "/"
#  define VIR_FILE_IS_DIR_SEPARATOR(c) ((c) == VIR_FILE_DIR_SEPARATOR)
#  define VIR_FILE_PATH_SEPARATOR ':'
#  define VIR_FILE_PATH_SEPARATOR_S ":"

# endif /* !WIN32 */

bool virFileIsAbsPath(const char *path);
int virFileAbsPath(const char *path,
                   char **abspath) ATTRIBUTE_RETURN_CHECK;
const char *virFileSkipRoot(const char *path);

int virFileOpenTty(int *ttymaster,
                   char **ttyName,
                   int rawmode);

char *virFileFindMountPoint(const char *type);

void virFileWaitForDevices(void);

/* NB: this should be combined with virFileBuildPath */
# define virBuildPath(path, ...) \
    virBuildPathInternal(path, __VA_ARGS__, NULL)
int virBuildPathInternal(char **path, ...) ATTRIBUTE_SENTINEL;

int virFilePrintf(FILE *fp, const char *msg, ...)
    ATTRIBUTE_FMT_PRINTF(2, 3);

#endif /* __VIR_FILE_H */
