/*
 * virutil.h: common, generic utility functions
 *
 * Copyright (C) 2010-2014 Red Hat, Inc.
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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#pragma once

#include "internal.h"
#include <unistd.h>
#include <sys/types.h>


int virSetBlocking(int fd, bool blocking) G_GNUC_WARN_UNUSED_RESULT;
int virSetNonBlock(int fd) G_GNUC_WARN_UNUSED_RESULT;
int virSetInherit(int fd, bool inherit) G_GNUC_WARN_UNUSED_RESULT;
int virSetCloseExec(int fd) G_GNUC_WARN_UNUSED_RESULT;
int virSetSockReuseAddr(int fd, bool fatal) G_GNUC_WARN_UNUSED_RESULT;

int virSetUIDGID(uid_t uid, gid_t gid, gid_t *groups, int ngroups);
int virSetUIDGIDWithCaps(uid_t uid, gid_t gid, gid_t *groups, int ngroups,
                         unsigned long long capBits,
                         bool clearExistingCaps);

void virWaitForDevices(void);

int virScaleInteger(unsigned long long *value, const char *suffix,
                    unsigned long long scale, unsigned long long limit)
    ATTRIBUTE_NONNULL(1) G_GNUC_WARN_UNUSED_RESULT;

char *virFormatIntDecimal(char *buf, size_t buflen, int val)
    ATTRIBUTE_NONNULL(1) G_GNUC_WARN_UNUSED_RESULT;

unsigned long long
virFormatIntPretty(unsigned long long val,
                   const char **unit);

int virDiskNameParse(const char *name, int *disk, int *partition);
int virDiskNameToIndex(const char* str);
char *virIndexToDiskName(unsigned int idx, const char *prefix);

/* No-op workarounds for functionality missing in mingw.  */
#ifndef WITH_GETUID
static inline int getuid(void)
{ return 0; }
#endif

#ifndef WITH_GETEUID
static inline int geteuid(void)
{ return 0; }
#endif

#ifndef WITH_GETGID
static inline int getgid(void)
{ return 0; }
#endif

#ifndef WITH_GETEGID
static inline int getegid(void)
{ return 0; }
#endif

#ifdef FUNC_PTHREAD_SIGMASK_BROKEN
# undef pthread_sigmask
static inline int pthread_sigmask(int how,
                                  const void *set,
                                  void *old)
{
    (void) how;
    (void) set;
    (void) old;
    return 0;
}
#endif

char *virGetHostname(void) G_NO_INLINE;
char *virGetHostnameQuiet(void);

char *virGetUserDirectory(void);
char *virGetUserDirectoryByUID(uid_t uid);
char *virGetUserConfigDirectory(void);
char *virGetUserCacheDirectory(void);
char *virGetUserRuntimeDirectory(void) G_NO_INLINE;
char *virGetUserShell(uid_t uid);
char *virGetUserName(uid_t uid) G_NO_INLINE;
char *virGetGroupName(gid_t gid) G_NO_INLINE;
int virGetGroupList(uid_t uid, gid_t group, gid_t **groups)
    ATTRIBUTE_NONNULL(3);
int virGetUserID(const char *name,
                 uid_t *uid) G_GNUC_WARN_UNUSED_RESULT;
int virGetGroupID(const char *name,
                  gid_t *gid) G_GNUC_WARN_UNUSED_RESULT;

bool virDoesUserExist(const char *name);
bool virDoesGroupExist(const char *name);


bool virValidateWWN(const char *wwn);

int virParseOwnershipIds(const char *label, uid_t *uidPtr, gid_t *gidPtr);


time_t virGetSelfLastChanged(void);
void virUpdateSelfLastChanged(const char *path);

long virGetSystemPageSize(void) G_NO_INLINE;
long virGetSystemPageSizeKB(void) G_NO_INLINE;

unsigned long long virMemoryLimitTruncate(unsigned long long value);
bool virMemoryLimitIsSet(unsigned long long value);
unsigned long long virMemoryMaxValue(bool ulong) G_NO_INLINE;

bool virHostHasIOMMU(void);

char *virHostGetDRMRenderNode(void) G_NO_INLINE;

/* Kernel cmdline match and comparison strategy for arg=value pairs */
typedef enum {
    /* substring comparison of argument values */
    VIR_KERNEL_CMDLINE_FLAGS_CMP_PREFIX = 1,

    /* strict string comparison of argument values */
    VIR_KERNEL_CMDLINE_FLAGS_CMP_EQ = 2,

    /* look for any occurrence of the argument with the expected value,
     * this should be used when an argument set to the expected value overrides
     * all the other occurrences of the argument, e.g. when looking for 'arg=1'
     * in 'arg=0 arg=1 arg=0' the search would succeed with this flag
     */
    VIR_KERNEL_CMDLINE_FLAGS_SEARCH_FIRST = 4,

    /* look for the last occurrence of argument with the expected value,
     * this should be used when the last occurrence of the argument overrides
     * all the other ones, e.g. when looking for 'arg=1' in 'arg=0 arg=1' the
     * search would succeed with this flag, but in 'arg=1 arg=0' it would not,
     * because 'arg=0' overrides all the previous occurrences of 'arg'
     */
    VIR_KERNEL_CMDLINE_FLAGS_SEARCH_LAST = 8,
} virKernelCmdlineFlags;

const char *virKernelCmdlineNextParam(const char *cmdline,
                                      char **param,
                                      char **val);

bool virKernelCmdlineMatchParam(const char *cmdline,
                                const char *arg,
                                const char **values,
                                size_t len_values,
                                virKernelCmdlineFlags flags);

/**
 * VIR_ASSIGN_IS_OVERFLOW:
 * @rvalue: value that is checked (evaluated twice)
 * @lvalue: value that the check is against (used in typeof())
 *
 * This macro assigns @lvalue to @rvalue and evaluates as true if the value of
 * @rvalue did not fit into the @lvalue.
 */
#define VIR_ASSIGN_IS_OVERFLOW(lvalue, rvalue) \
    (((lvalue) = (rvalue)) != (rvalue))

char *virGetPassword(void);

/*
 * virPipe:
 *
 * Open a pair of FDs which can be used to communicate
 * with each other. The FDs will have O_CLOEXEC set.
 * This will report a libvirt error on failure.
 *
 * Returns: -1 on error, 0 on success
 */
int virPipe(int fds[2]);

/*
 * virPipeQuiet:
 *
 * Open a pair of FDs which can be used to communicate
 * with each other. The FDs will have O_CLOEXEC set.
 * This will set errno on failure.
 *
 * Returns: -1 on error, 0 on success
 */
int virPipeQuiet(int fds[2]);

/*
 * virPipe:
 *
 * Open a pair of FDs which can be used to communicate
 * with each other. The FDs will have O_CLOEXEC and
 * O_NONBLOCK set.
 * This will report a libvirt error on failure.
 *
 * Returns: -1 on error, 0 on success
 */
int virPipeNonBlock(int fds[2]);
