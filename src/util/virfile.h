/*
 * virfile.h: safer file handling
 *
 * Copyright (C) 2010-2011 Red Hat, Inc.
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
 * License along with this library;  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 */


#ifndef __VIR_FILES_H_
# define __VIR_FILES_H_

# include <stdio.h>

# include "internal.h"

typedef enum virFileCloseFlags {
    VIR_FILE_CLOSE_PRESERVE_ERRNO = 1 << 0,
    VIR_FILE_CLOSE_IGNORE_EBADF = 1 << 1,
    VIR_FILE_CLOSE_DONT_LOG = 1 << 2,
} virFileCloseFlags;

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

int virFileLock(int fd, bool shared, off_t start, off_t len);
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

#endif /* __VIR_FILES_H */
