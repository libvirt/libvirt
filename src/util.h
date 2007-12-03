/*
 * utils.h: common, generic utility functions
 *
 * Copyright (C) 2006, 2007 Binary Karma
 * Copyright (C) 2006 Shuveb Hussain
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
 * File created Jul 18, 2007 - Shuveb Hussain <shuveb@binarykarma.com>
 */

#ifndef __VIR_UTIL_H__
#define __VIR_UTIL_H__

#include "internal.h"

int virExec(virConnectPtr conn, char **argv, int *retpid, int infd, int *outfd, int *errfd);
int virExecNonBlock(virConnectPtr conn, char **argv, int *retpid, int infd, int *outfd, int *errfd);

int saferead(int fd, void *buf, size_t count);
ssize_t safewrite(int fd, const void *buf, size_t count);

int virFileReadAll(const char *path,
                   char *buf,
                   unsigned int buflen);

int virFileMatchesNameSuffix(const char *file,
                             const char *name,
                             const char *suffix);

int virFileHasSuffix(const char *str,
                     const char *suffix);

int virFileLinkPointsTo(const char *checkLink,
                        const char *checkDest);
int virFileMakePath(const char *path);

int virFileBuildPath(const char *dir,
                     const char *name,
                     const char *ext,
                     char *buf,
                     unsigned int buflen);


#endif /* __VIR_UTIL_H__ */
