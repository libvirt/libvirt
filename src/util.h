
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

#include "verify.h"
#include <sys/select.h>
#include <sys/types.h>

int saferead(int fd, void *buf, size_t count);
ssize_t safewrite(int fd, const void *buf, size_t count);
int safezero(int fd, int flags, off_t offset, off_t len);

enum {
    VIR_EXEC_NONE   = 0,
    VIR_EXEC_NONBLOCK = (1 << 0),
    VIR_EXEC_DAEMON = (1 << 1),
};

int virSetNonBlock(int fd);
int virSetCloseExec(int fd);

/* This will execute in the context of the first child
 * after fork() but before execve() */
typedef int (*virExecHook)(void *data);

int virExecWithHook(virConnectPtr conn,
                    const char *const*argv,
                    const char *const*envp,
                    const fd_set *keepfd,
                    int *retpid,
                    int infd,
                    int *outfd,
                    int *errfd,
                    int flags,
                    virExecHook hook,
                    void *data);
int virExec(virConnectPtr conn,
            const char *const*argv,
            const char *const*envp,
            const fd_set *keepfd,
            pid_t *retpid,
            int infd,
            int *outfd,
            int *errfd,
            int flags);
int virRun(virConnectPtr conn, const char *const*argv, int *status);

int virFileReadLimFD(int fd, int maxlen, char **buf);

int virFileReadAll(const char *path, int maxlen, char **buf);

int virFileWriteStr(const char *path, const char *str);

int virFileMatchesNameSuffix(const char *file,
                             const char *name,
                             const char *suffix);

int virFileHasSuffix(const char *str,
                     const char *suffix);

int virFileStripSuffix(char *str,
                       const char *suffix);

int virFileLinkPointsTo(const char *checkLink,
                        const char *checkDest);

int virFileResolveLink(const char *linkpath,
                       char **resultpath);

int virFileExists(const char *path);

int virFileMakePath(const char *path);

int virFileBuildPath(const char *dir,
                     const char *name,
                     const char *ext,
                     char *buf,
                     unsigned int buflen);

int virFileOpenTty(int *ttymaster,
                   char **ttyName,
                   int rawmode);

char* virFilePid(const char *dir,
                 const char *name);
int virFileWritePid(const char *dir,
                    const char *name,
                    pid_t pid);
int virFileReadPid(const char *dir,
                   const char *name,
                   pid_t *pid);
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
int virStrToLong_ll(char const *s,
                    char **end_ptr,
                    int base,
                    long long *result);
int virStrToLong_ull(char const *s,
                     char **end_ptr,
                     int base,
                     unsigned long long *result);

int virMacAddrCompare (const char *mac1, const char *mac2);

void virSkipSpaces(const char **str);
int virParseNumber(const char **str);
int virAsprintf(char **strp, const char *fmt, ...)
    ATTRIBUTE_FORMAT(printf, 2, 3);

#define VIR_MAC_BUFLEN 6
#define VIR_MAC_PREFIX_BUFLEN 3
#define VIR_MAC_STRING_BUFLEN VIR_MAC_BUFLEN * 3

int virParseMacAddr(const char* str,
                    unsigned char *addr);
void virFormatMacAddr(const unsigned char *addr,
                      char *str);
void virGenerateMacAddr(const unsigned char *prefix,
                        unsigned char *addr);

int virDiskNameToIndex(const char* str);


int virEnumFromString(const char *const*types,
                      unsigned int ntypes,
                      const char *type);

const char *virEnumToString(const char *const*types,
                            unsigned int ntypes,
                            int type);

#define VIR_ENUM_IMPL(name, lastVal, ...)                               \
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

#define VIR_ENUM_DECL(name)                             \
    const char *name ## TypeToString(int type);         \
    int name ## TypeFromString(const char*type);

#ifndef HAVE_GETUID
static inline int getuid (void) { return 0; }
#endif

#ifndef HAVE_GETGID
static inline int getgid (void) { return 0; }
#endif

char *virGetHostname(void);

int virKillProcess(pid_t pid, int sig);

#ifdef HAVE_GETPWUID_R
char *virGetUserDirectory(virConnectPtr conn,
                          uid_t uid);
#endif

int virRandomInitialize(unsigned int seed);
int virRandom(int max);

#endif /* __VIR_UTIL_H__ */
