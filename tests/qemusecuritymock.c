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

#ifdef WITH_SELINUX
# include <selinux/selinux.h>
# include <selinux/label.h>
#endif

#include "virmock.h"
#include "virfile.h"
#include "virthread.h"
#include "virhash.h"
#include "qemusecuritytest.h"
#include "security/security_manager.h"
#include "virhostuptime.h"

#define VIR_FROM_THIS VIR_FROM_NONE

/* Okay, here's the deal. The qemusecuritytest calls several
 * virSecurityManager public APIs in order to check if XATTRs
 * work as expected. Therefore there is a lot we have to mock
 * (chown, stat, XATTR APIs, etc.). Since the test won't run as
 * root chown() would fail, therefore we have to keep everything
 * in memory. By default, all files are owned by 1:2 and have a
 * SELinux label.
 * By the way, since there are some cases where real stat needs
 * to be called, the mocked functions are effective only if
 * $ENVVAR is set.
 */

#define DEFAULT_UID 1
#define DEFAULT_GID 2
#define DEFAULT_SELINUX_LABEL "system_u:object_r:default_t:s0"


static int (*real_chown)(const char *path, uid_t uid, gid_t gid);
static int (*real_open)(const char *path, int flags, ...);
static int (*real_close)(int fd);
#ifdef WITH_SELINUX
static int (*real_setfilecon_raw)(const char *path, const char *context);
static int (*real_getfilecon_raw)(const char *path, char **context);
#endif


/* Global mutex to avoid races */
virMutex m = VIR_MUTEX_INITIALIZER;

/* Hash table to store XATTRs for paths. For simplicity, key is
 * "$path:$name" and value is just XATTR "$value". We don't need
 * to list XATTRs a path has, therefore we don't need something
 * more clever. */
GHashTable *xattr_paths = NULL;


/* The UID:GID is stored in a hash table. Again, for simplicity,
 * the path is the key and the value is an uint32_t , where
 * the lower half is UID and the higher is GID. */
GHashTable *chown_paths = NULL;

/* The SELinux label is stored in a hash table. For simplicity,
 * the path is the key and the value is the label. */
GHashTable *selinux_paths = NULL;


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

    xattr_paths = virHashNew(g_free);
    chown_paths = virHashNew(g_free);
    selinux_paths = virHashNew(g_free);
}


static void
init_syms(void)
{
    if (real_chown)
        return;

    VIR_MOCK_REAL_INIT(chown);
    VIR_MOCK_REAL_INIT(open);
    VIR_MOCK_REAL_INIT(close);
#ifdef WITH_SELINUX
    VIR_MOCK_REAL_INIT(setfilecon_raw);
    VIR_MOCK_REAL_INIT(getfilecon_raw);
#endif

    /* Intentionally not calling init_hash() here */
}


static char *
get_key(const char *path,
        const char *name)
{
    return g_strdup_printf("%s:%s", path, name);
}


int
virFileGetXAttrQuiet(const char *path,
                     const char *name,
                     char **value)
{
    g_autofree char *key = get_key(path, name);
    char *val;
    VIR_LOCK_GUARD lock = virLockGuardLock(&m);

    init_syms();
    init_hash();

    if (!(val = virHashLookup(xattr_paths, key))) {
        errno = ENODATA;
        return -1;
    }

    *value = g_strdup(val);

    return 0;
}


/*
 * This may look redundant but is needed to work around an
 * compiler quirk. The call from the real virFileGetXAttr
 * to the real virFileGetXAttrQuiet has a quirk where the
 * return value from virFileGetXAttrQuiet gets scrambled
 * if we mock virFileGetXAttrQuiet, returning -1 instead
 * of 0 despite succeeding. This happens on FreeBSD 11/12
 * hosts with Clang, and is suspected to be some kind of
 * compiler optimization. By mocking this function too we
 * can workaround it.
 */
int
virFileGetXAttr(const char *path,
                const char *name,
                char **value)
{
    int ret;

    if ((ret = virFileGetXAttrQuiet(path, name, value)) < 0) {
        virReportSystemError(errno,
                             "Unable to get XATTR %s on %s",
                             name, path);
    }

    return ret;
}


int virFileSetXAttr(const char *path,
                    const char *name,
                    const char *value)
{
    g_autofree char *key = get_key(path, name);
    g_autofree char *val = g_strdup(value);
    VIR_LOCK_GUARD lock = virLockGuardLock(&m);

    init_syms();
    init_hash();

    if (virHashUpdateEntry(xattr_paths, key, val) < 0)
        return -1;
    val = NULL;

    return 0;
}


int virFileRemoveXAttr(const char *path,
                       const char *name)
{
    int ret = -1;
    g_autofree char *key = get_key(path, name);
    VIR_LOCK_GUARD lock = virLockGuardLock(&m);

    init_syms();
    init_hash();

    if ((ret = virHashRemoveEntry(xattr_paths, key)) < 0)
        errno = ENODATA;

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
    g_autofree uint32_t *val = NULL;
    VIR_LOCK_GUARD lock = virLockGuardLock(&m);

    if (gid >> 16 || uid >> 16) {
        fprintf(stderr, "Attempt to set too high UID or GID: %llu %llu",
               (unsigned long long) uid, (unsigned long long) gid);
        abort();
    }

    val = g_new0(uint32_t, 1);

    *val = (gid << 16) + uid;

    init_hash();

    if (virHashUpdateEntry(chown_paths, path, val) < 0)
        return -1;

    val = NULL;
    return 0;
}


#include "virmockstathelpers.c"

static int
virMockStatRedirect(const char *path G_GNUC_UNUSED, char **newpath G_GNUC_UNUSED)
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


int virFileLock(int fd G_GNUC_UNUSED,
                bool shared G_GNUC_UNUSED,
                off_t start G_GNUC_UNUSED,
                off_t len G_GNUC_UNUSED,
                bool waitForLock G_GNUC_UNUSED)
{
    return 0;
}


int virFileUnlock(int fd G_GNUC_UNUSED,
                  off_t start G_GNUC_UNUSED,
                  off_t len G_GNUC_UNUSED)
{
    return 0;
}


typedef struct _checkOwnerData checkOwnerData;
struct _checkOwnerData {
    GHashTable *paths;
    bool chown_fail;
    bool selinux_fail;
};


static int
checkSELinux(void *payload,
             const char *name,
             void *opaque)
{
    checkOwnerData *data = opaque;
    char *label = payload;

    if (STRNEQ(label, DEFAULT_SELINUX_LABEL) &&
        !g_hash_table_contains(data->paths, name)) {
        fprintf(stderr,
                "Path %s wasn't restored back to its original SELinux label\n",
                name);
        data->selinux_fail = true;
    }

    return 0;
}


static int
checkOwner(void *payload,
           const char *name,
           void *opaque)
{
    checkOwnerData *data = opaque;
    uint32_t owner = *((uint32_t*) payload);

    if ((owner % 16 != DEFAULT_UID ||
         owner >> 16 != DEFAULT_GID) &&
        !g_hash_table_contains(data->paths, name)) {
        fprintf(stderr,
                "Path %s wasn't restored back to its original owner\n",
                name);
        data->chown_fail = true;
    }

    return 0;
}


static int
printXATTR(void *payload,
           const char *name,
           void *data)
{
    bool *xattr_fail = data;

    /* The fact that we are in this function means that there are
     * some XATTRs left behind. This is enough to claim an error. */
    *xattr_fail = true;

    /* Hash table key consists of "$path:$xattr_name", xattr
     * value is then the value stored in the hash table. */
    printf("key=%s val=%s\n", name, (const char *) payload);
    return 0;
}


/**
 * checkPaths:
 * @paths: a NULL terminated list of paths expected not to be restored
 *
 * Check if all paths were restored and if no XATTR was left
 * behind. Since restore is not done on all domain's paths, some
 * paths are expected to be not restored. A list of such paths
 * can be passed in @paths argument. If a path is not restored
 * but it's on the list no error is indicated.
 */
int checkPaths(GHashTable *paths)
{
    checkOwnerData data = { .paths = paths, .chown_fail = false, .selinux_fail = false };
    bool xattr_fail = false;
    GHashTableIter htitr;
    void *key;
    VIR_LOCK_GUARD lock = virLockGuardLock(&m);

    init_hash();

    g_hash_table_iter_init(&htitr, paths);

    while (g_hash_table_iter_next(&htitr, &key, NULL)) {
        if (!virHashLookup(chown_paths, key)) {
            fprintf(stderr, "Unexpected path restored: %s\n", (const char *) key);
            return -1;
        }
    }

    if (virHashForEach(selinux_paths, checkSELinux, &data) < 0)
        return -1;

    if (virHashForEach(chown_paths, checkOwner, &data) < 0)
        return -1;

    if (virHashForEach(xattr_paths, printXATTR, &xattr_fail) < 0)
        return -1;

    if (data.chown_fail || data.selinux_fail || xattr_fail)
        return -1;

    return 0;
}


void freePaths(void)
{
    VIR_LOCK_GUARD lock = virLockGuardLock(&m);

    init_hash();

    g_clear_pointer(&selinux_paths, g_hash_table_unref);
    g_clear_pointer(&chown_paths, g_hash_table_unref);
    g_clear_pointer(&xattr_paths, g_hash_table_unref);
}


int
virProcessRunInFork(virProcessForkCallback cb,
                    void *opaque)
{
    return cb(-1, opaque);
}


/* We don't really need to mock this function. The qemusecuritytest doesn't
 * care about the actual value. However, travis runs build and tests in a
 * container where utmp is missing and thus this function fails. */
int
virHostGetBootTime(unsigned long long *when)
{
    *when = 1234567890;
    return 0;
}


#ifdef WITH_SELINUX
int
is_selinux_enabled(void)
{
    return 1;
}


struct selabel_handle *
selabel_open(unsigned int backend G_GNUC_UNUSED,
             const struct selinux_opt *opts G_GNUC_UNUSED,
             unsigned nopts G_GNUC_UNUSED)
{
    return (void*)((intptr_t) 0x1);
}


void
selabel_close(struct selabel_handle *rec G_GNUC_UNUSED)
{
    /* nada */
}


const char *
selinux_virtual_domain_context_path(void)
{
    return abs_srcdir "/qemusecuritydata/virtual_domain_context";
}


const char *
selinux_virtual_image_context_path(void)
{
    return abs_srcdir "/qemusecuritydata/virtual_image_context";
}


int getcon_raw(char **context)
{
    *context = g_strdup("system_u:system_r:virtd_t:s0-s0:c0.c1023");
    return 0;
}


static int
mock_setfilecon_raw(const char *path,
                    const char *context)
{
    g_autofree char *val = g_strdup(context);
    VIR_LOCK_GUARD lock = virLockGuardLock(&m);

    init_hash();

    if (virHashUpdateEntry(selinux_paths, path, val) < 0)
        return -1;
    val = NULL;

    return 0;
}


static int
mock_getfilecon_raw(const char *path,
                    char **context)
{
    const char *val;
    VIR_LOCK_GUARD lock = virLockGuardLock(&m);

    init_hash();

    val = virHashLookup(selinux_paths, path);
    if (!val)
        val = DEFAULT_SELINUX_LABEL;

    *context = g_strdup(val);
    return 0;
}


int
setfilecon_raw(const char *path,
               const char *context)
{
    int ret;

    init_syms();

    if (getenv(ENVVAR))
        ret = mock_setfilecon_raw(path, context);
    else
        ret = real_setfilecon_raw(path, context);

    return ret;
}


int
getfilecon_raw(const char *path,
               char **context)
{
    int ret;

    init_syms();

    if (getenv(ENVVAR))
        ret = mock_getfilecon_raw(path, context);
    else
        ret = real_getfilecon_raw(path, context);

    return ret;
}


int
selabel_lookup_raw(struct selabel_handle *hnd G_GNUC_UNUSED,
                   char **context,
                   const char *key G_GNUC_UNUSED,
                   int type G_GNUC_UNUSED)
{
    /* This function will be called only if we haven't found original label in
     * XATTRs. Return something else than DEFAULT_SELINUX_LABEL so that it is
     * considered as error. */
    *context = g_strdup("system_u:object_r:default_t:s1");
    return 0;
}
#endif
