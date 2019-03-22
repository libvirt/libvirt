/*
 * Copyright (C) 2018 Red Hat, Inc.
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

#include <config.h>

#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include "virmock.h"
#include "virfile.h"
#include "virthread.h"
#include "virhash.h"
#include "virstring.h"
#include "viralloc.h"
#include "qemusecuritytest.h"
#include "security/security_manager.h"

#define VIR_FROM_THIS VIR_FROM_NONE

/* Okay, here's the deal. The qemusecuritytest calls several
 * virSecurityManager public APIs in order to check if XATTRs
 * work as expected. Therefore there is a lot we have to mock
 * (chown, stat, XATTR APIs, etc.). Since the test won't run as
 * root chown() would fail, therefore we have to keep everything
 * in memory. By default, all files are owned by 1:2.
 * By the way, since there are some cases where real stat needs
 * to be called, the mocked functions are effective only if
 * $ENVVAR is set.
 */

#define DEFAULT_UID 1
#define DEFAULT_GID 2


static int (*real_chown)(const char *path, uid_t uid, gid_t gid);
static int (*real_open)(const char *path, int flags, ...);
static int (*real_close)(int fd);


/* Global mutex to avoid races */
virMutex m = VIR_MUTEX_INITIALIZER;

/* Hash table to store XATTRs for paths. For simplicity, key is
 * "$path:$name" and value is just XATTR "$value". We don't need
 * to list XATTRs a path has, therefore we don't need something
 * more clever. */
virHashTablePtr xattr_paths = NULL;


/* The UID:GID is stored in a hash table. Again, for simplicity,
 * the path is the key and the value is an uint32_t , where
 * the lower half is UID and the higher is GID. */
virHashTablePtr chown_paths = NULL;


static void
init_hash(void)
{
    /* The reason the init is split is that virHash calls
     * virRandomBits() which in turn calls a gnutls function.
     * However, when gnutls is initializing itself it calls
     * stat() so we would call a gnutls function before it is
     * initialized which will lead to a crash.
     */

    if (xattr_paths)
        return;

    if (!(xattr_paths = virHashCreate(10, virHashValueFree))) {
        fprintf(stderr, "Unable to create hash table for XATTR paths\n");
        abort();
    }

    if (!(chown_paths = virHashCreate(10, virHashValueFree))) {
        fprintf(stderr, "Unable to create hash table for chowned paths\n");
        abort();
    }
}


static void
init_syms(void)
{
    if (real_chown)
        return;

    VIR_MOCK_REAL_INIT(chown);
    VIR_MOCK_REAL_INIT(open);
    VIR_MOCK_REAL_INIT(close);

    /* Intentionally not calling init_hash() here */
}


static char *
get_key(const char *path,
        const char *name)
{
    char *ret;

    if (virAsprintf(&ret, "%s:%s", path, name) < 0) {
        fprintf(stderr, "Unable to create hash table key\n");
        abort();
    }

    return ret;
}


int
virFileGetXAttrQuiet(const char *path,
                     const char *name,
                     char **value)
{
    int ret = -1;
    char *key;
    char *val;

    key = get_key(path, name);

    virMutexLock(&m);
    init_syms();
    init_hash();

    if (!(val = virHashLookup(xattr_paths, key))) {
        errno = ENODATA;
        goto cleanup;
    }

    if (VIR_STRDUP(*value, val) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virMutexUnlock(&m);
    VIR_FREE(key);
    return ret;
}


int virFileSetXAttr(const char *path,
                    const char *name,
                    const char *value)
{
    int ret = -1;
    char *key;
    char *val;

    key = get_key(path, name);
    if (VIR_STRDUP(val, value) < 0)
        return -1;

    virMutexLock(&m);
    init_syms();
    init_hash();

    if (virHashUpdateEntry(xattr_paths, key, val) < 0)
        goto cleanup;
    val = NULL;

    ret = 0;
 cleanup:
    virMutexUnlock(&m);
    VIR_FREE(val);
    VIR_FREE(key);
    return ret;
}


int virFileRemoveXAttr(const char *path,
                       const char *name)
{
    int ret = -1;
    char *key;

    key = get_key(path, name);

    virMutexLock(&m);
    init_syms();
    init_hash();

    if ((ret = virHashRemoveEntry(xattr_paths, key)) < 0)
        errno = ENODATA;

    virMutexUnlock(&m);
    VIR_FREE(key);
    return ret;
}


#define VIR_MOCK_STAT_HOOK \
    do { \
        if (getenv(ENVVAR)) { \
            uint32_t *val; \
\
            virMutexLock(&m); \
            init_hash(); \
\
            memset(sb, 0, sizeof(*sb)); \
\
            sb->st_mode = S_IFREG | 0666; \
            sb->st_size = 123456; \
            sb->st_ino = 1; \
\
            if (!(val = virHashLookup(chown_paths, path))) { \
                /* New path. Set the defaults */ \
                sb->st_uid = DEFAULT_UID; \
                sb->st_gid = DEFAULT_GID; \
            } else { \
                /* Known path. Set values passed to chown() earlier */ \
                sb->st_uid = *val & 0xffff; \
                sb->st_gid = *val >> 16; \
            } \
\
            virMutexUnlock(&m); \
\
            return 0; \
        } \
    } while (0)

static int
mock_chown(const char *path,
           uid_t uid,
           gid_t gid)
{
    uint32_t *val = NULL;
    int ret = -1;

    if (gid >> 16 || uid >> 16) {
        fprintf(stderr, "Attempt to set too high UID or GID: %lld %lld",
               (unsigned long long) uid, (unsigned long long) gid);
        abort();
    }

    if (VIR_ALLOC(val) < 0)
        return -1;

    *val = (gid << 16) + uid;

    virMutexLock(&m);
    init_hash();

    if (virHashUpdateEntry(chown_paths, path, val) < 0)
        goto cleanup;
    val = NULL;

    ret = 0;
 cleanup:
    virMutexUnlock(&m);
    VIR_FREE(val);
    return ret;
}


#include "virmockstathelpers.c"

static int
virMockStatRedirect(const char *path ATTRIBUTE_UNUSED, char **newpath ATTRIBUTE_UNUSED)
{
    return 0;
}


int
chown(const char *path, uid_t uid, gid_t gid)
{
    int ret;

    init_syms();

    if (getenv(ENVVAR))
        ret = mock_chown(path, uid, gid);
    else
        ret = real_chown(path, uid, gid);

    return ret;
}


int
open(const char *path, int flags, ...)
{
    int ret;

    init_syms();

    if (getenv(ENVVAR)) {
        ret = 42; /* Some dummy FD */
    } else if (flags & O_CREAT) {
        va_list ap;
        mode_t mode;
        va_start(ap, flags);
        mode = (mode_t) va_arg(ap, int);
        va_end(ap);
        ret = real_open(path, flags, mode);
    } else {
        ret = real_open(path, flags);
    }

    return ret;
}


int
close(int fd)
{
    int ret;

    init_syms();

    if (fd == 42 && getenv(ENVVAR))
        ret = 0;
    else
        ret = real_close(fd);

    return ret;
}


int virFileLock(int fd ATTRIBUTE_UNUSED,
                bool shared ATTRIBUTE_UNUSED,
                off_t start ATTRIBUTE_UNUSED,
                off_t len ATTRIBUTE_UNUSED,
                bool waitForLock ATTRIBUTE_UNUSED)
{
    return 0;
}


int virFileUnlock(int fd ATTRIBUTE_UNUSED,
                  off_t start ATTRIBUTE_UNUSED,
                  off_t len ATTRIBUTE_UNUSED)
{
    return 0;
}


static int
checkOwner(void *payload,
           const void *name,
           void *data)
{
    bool *chown_fail = data;
    uint32_t owner = *((uint32_t*) payload);

    if (owner % 16 != DEFAULT_UID ||
        owner >> 16 != DEFAULT_GID) {
        fprintf(stderr,
                "Path %s wasn't restored back to its original owner\n",
                (const char *) name);
        *chown_fail = true;
    }

    return 0;
}


static int
printXATTR(void *payload,
           const void *name,
           void *data)
{
    bool *xattr_fail = data;

    /* The fact that we are in this function means that there are
     * some XATTRs left behind. This is enough to claim an error. */
    *xattr_fail = true;

    /* Hash table key consists of "$path:$xattr_name", xattr
     * value is then the value stored in the hash table. */
    printf("key=%s val=%s\n", (const char *) name, (const char *) payload);
    return 0;
}


int checkPaths(void)
{
    int ret = -1;
    bool chown_fail = false;
    bool xattr_fail = false;

    virMutexLock(&m);
    init_hash();

    if ((virHashForEach(chown_paths, checkOwner, &chown_fail)) < 0)
        goto cleanup;

    if ((virHashForEach(xattr_paths, printXATTR, &xattr_fail)) < 0)
        goto cleanup;

    if (chown_fail || xattr_fail)
        goto cleanup;

    ret = 0;
 cleanup:
    virMutexUnlock(&m);
    return ret;
}


void freePaths(void)
{
    virMutexLock(&m);
    init_hash();

    virHashFree(chown_paths);
    virHashFree(xattr_paths);
    chown_paths = xattr_paths = NULL;
    virMutexUnlock(&m);
}


int
virProcessRunInFork(virProcessForkCallback cb,
                    void *opaque)
{
    return cb(-1, opaque);
}
