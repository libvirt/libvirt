/*
 * utils.h: common, generic utility functions
 *
 * Copyright (C) 2010-2011 Red Hat, Inc.
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
# define __VIR_UTIL_H__

# include "verify.h"
# include "internal.h"
# include <unistd.h>
# include <sys/select.h>
# include <sys/types.h>
# include <stdarg.h>
# include <stdbool.h>

# ifndef MIN
#  define MIN(a, b) ((a) < (b) ? (a) : (b))
# endif

ssize_t saferead(int fd, void *buf, size_t count) ATTRIBUTE_RETURN_CHECK;
ssize_t safewrite(int fd, const void *buf, size_t count)
    ATTRIBUTE_RETURN_CHECK;
int safezero(int fd, int flags, off_t offset, off_t len)
    ATTRIBUTE_RETURN_CHECK;

enum {
    VIR_EXEC_NONE   = 0,
    VIR_EXEC_NONBLOCK = (1 << 0),
    VIR_EXEC_DAEMON = (1 << 1),
    VIR_EXEC_CLEAR_CAPS = (1 << 2),
};

int virSetNonBlock(int fd) ATTRIBUTE_RETURN_CHECK;
int virSetCloseExec(int fd) ATTRIBUTE_RETURN_CHECK;

/* This will execute in the context of the first child
 * after fork() but before execve() */
typedef int (*virExecHook)(void *data);

int virExecDaemonize(const char *const*argv,
                     const char *const*envp,
                     const fd_set *keepfd,
                     pid_t *retpid,
                     int infd, int *outfd, int *errfd,
                     int flags,
                     virExecHook hook,
                     void *data,
                     char *pidfile) ATTRIBUTE_RETURN_CHECK;
int virExecWithHook(const char *const*argv,
                    const char *const*envp,
                    const fd_set *keepfd,
                    int *retpid,
                    int infd,
                    int *outfd,
                    int *errfd,
                    int flags,
                    virExecHook hook,
                    void *data,
                    char *pidfile) ATTRIBUTE_RETURN_CHECK;
int virExec(const char *const*argv,
            const char *const*envp,
            const fd_set *keepfd,
            pid_t *retpid,
            int infd,
            int *outfd,
            int *errfd,
            int flags) ATTRIBUTE_RETURN_CHECK;
int virRun(const char *const*argv, int *status) ATTRIBUTE_RETURN_CHECK;
int virRunWithHook(const char *const*argv,
                   virExecHook hook, void *data,
                   int *status) ATTRIBUTE_RETURN_CHECK;
int virPipeReadUntilEOF(int outfd, int errfd,
                        char **outbuf, char **errbuf);
int virFork(pid_t *pid);

int virSetUIDGID(uid_t uid, gid_t gid);

int virFileReadLimFD(int fd, int maxlen, char **buf) ATTRIBUTE_RETURN_CHECK;

int virFileReadAll(const char *path, int maxlen, char **buf) ATTRIBUTE_RETURN_CHECK;

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

char *virFindFileInPath(const char *file);

bool virFileExists(const char *file) ATTRIBUTE_NONNULL(1);
bool virFileIsExecutable(const char *file) ATTRIBUTE_NONNULL(1);

char *virFileSanitizePath(const char *path);

enum {
    VIR_FILE_OP_NONE        = 0,
    VIR_FILE_OP_AS_UID      = (1 << 0),
    VIR_FILE_OP_FORCE_PERMS = (1 << 1),
};
typedef int (*virFileOperationHook)(int fd, void *data);
int virFileOperation(const char *path, int openflags, mode_t mode,
                     uid_t uid, gid_t gid,
                     virFileOperationHook hook, void *hookdata,
                     unsigned int flags) ATTRIBUTE_RETURN_CHECK;

enum {
    VIR_DIR_CREATE_NONE        = 0,
    VIR_DIR_CREATE_AS_UID      = (1 << 0),
    VIR_DIR_CREATE_FORCE_PERMS = (1 << 1),
    VIR_DIR_CREATE_ALLOW_EXIST = (1 << 2),
};
int virDirCreate(const char *path, mode_t mode, uid_t uid, gid_t gid,
                 unsigned int flags) ATTRIBUTE_RETURN_CHECK;
int virFileMakePath(const char *path) ATTRIBUTE_RETURN_CHECK;

int virFileBuildPath(const char *dir,
                     const char *name,
                     const char *ext,
                     char *buf,
                     unsigned int buflen) ATTRIBUTE_RETURN_CHECK;

int virFileAbsPath(const char *path,
                   char **abspath) ATTRIBUTE_RETURN_CHECK;

int virFileOpenTty(int *ttymaster,
                   char **ttyName,
                   int rawmode);
int virFileOpenTtyAt(const char *ptmx,
                     int *ttymaster,
                     char **ttyName,
                     int rawmode);

char* virFilePid(const char *dir,
                 const char *name);

int virFileWritePidPath(const char *path,
                        pid_t pid) ATTRIBUTE_RETURN_CHECK;
int virFileWritePid(const char *dir,
                    const char *name,
                    pid_t pid) ATTRIBUTE_RETURN_CHECK;
int virFileReadPid(const char *dir,
                   const char *name,
                   pid_t *pid) ATTRIBUTE_RETURN_CHECK;
int virFileDeletePid(const char *dir,
                     const char *name);

char *virArgvToString(const char *const *argv);

int virStrToLong_i(char const *s,
                     char **end_ptr,
                     int base,
                     int *result);

int virStrToLong_ui(char const *s,
                    char **end_ptr,
                    int base,
                    unsigned int *result);
int virStrToLong_l(char const *s,
                   char **end_ptr,
                   int base,
                   long *result);
int virStrToLong_ul(char const *s,
                    char **end_ptr,
                    int base,
                    unsigned long *result);
int virStrToLong_ll(char const *s,
                    char **end_ptr,
                    int base,
                    long long *result);
int virStrToLong_ull(char const *s,
                     char **end_ptr,
                     int base,
                     unsigned long long *result);
int virStrToDouble(char const *s,
                   char **end_ptr,
                   double *result);

int virHexToBin(unsigned char c);

int virMacAddrCompare (const char *mac1, const char *mac2);

void virSkipSpaces(const char **str);
int virParseNumber(const char **str);
int virParseVersionString(const char *str, unsigned long *version);
int virAsprintf(char **strp, const char *fmt, ...)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_FMT_PRINTF(2, 3);
int virVasprintf(char **strp, const char *fmt, va_list list)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_FMT_PRINTF(2, 0);
char *virStrncpy(char *dest, const char *src, size_t n, size_t destbytes)
    ATTRIBUTE_RETURN_CHECK;
char *virStrcpy(char *dest, const char *src, size_t destbytes)
    ATTRIBUTE_RETURN_CHECK;
# define virStrcpyStatic(dest, src) virStrcpy((dest), (src), sizeof(dest))

# define VIR_MAC_BUFLEN 6
# define VIR_MAC_PREFIX_BUFLEN 3
# define VIR_MAC_STRING_BUFLEN VIR_MAC_BUFLEN * 3

int virParseMacAddr(const char* str,
                    unsigned char *addr) ATTRIBUTE_RETURN_CHECK;
void virFormatMacAddr(const unsigned char *addr,
                      char *str);
void virGenerateMacAddr(const unsigned char *prefix,
                        unsigned char *addr);

int virDiskNameToIndex(const char* str);
char *virIndexToDiskName(int idx, const char *prefix);

int virEnumFromString(const char *const*types,
                      unsigned int ntypes,
                      const char *type);

const char *virEnumToString(const char *const*types,
                            unsigned int ntypes,
                            int type);

# define VIR_ENUM_IMPL(name, lastVal, ...)                               \
    static const char *const name ## TypeList[] = { __VA_ARGS__ };      \
    extern int (* name ## Verify (void)) [verify_true (ARRAY_CARDINALITY(name ## TypeList) == lastVal)]; \
    const char *name ## TypeToString(int type) {                        \
        return virEnumToString(name ## TypeList,                        \
                               ARRAY_CARDINALITY(name ## TypeList),     \
                               type);                                   \
    }                                                                   \
    int name ## TypeFromString(const char *type) {                      \
        return virEnumFromString(name ## TypeList,                      \
                                 ARRAY_CARDINALITY(name ## TypeList),   \
                                 type);                                 \
    }

# define VIR_ENUM_DECL(name)                             \
    const char *name ## TypeToString(int type);         \
    int name ## TypeFromString(const char*type);

# ifndef HAVE_GETUID
static inline int getuid (void) { return 0; }
# endif

# ifndef HAVE_GETGID
static inline int getgid (void) { return 0; }
# endif

char *virGetHostname(virConnectPtr conn);

int virKillProcess(pid_t pid, int sig);

char *virGetUserDirectory(uid_t uid);
char *virGetUserName(uid_t uid);
int virGetUserID(const char *name,
                 uid_t *uid) ATTRIBUTE_RETURN_CHECK;
int virGetGroupID(const char *name,
                  gid_t *gid) ATTRIBUTE_RETURN_CHECK;

int virRandomInitialize(unsigned int seed) ATTRIBUTE_RETURN_CHECK;
int virRandom(int max);

char *virFileFindMountPoint(const char *type);

void virFileWaitForDevices(void);

# define virBuildPath(path, ...) virBuildPathInternal(path, __VA_ARGS__, NULL)
int virBuildPathInternal(char **path, ...) ATTRIBUTE_SENTINEL;

char *virTimestamp(void);

#endif /* __VIR_UTIL_H__ */
