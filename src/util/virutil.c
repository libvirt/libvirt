/*
 * virutil.c: common, generic utility functions
 *
 * Copyright (C) 2006-2014 Red Hat, Inc.
 * Copyright (C) 2006 Daniel P. Berrange
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

#include <config.h>

#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/stat.h>

#ifdef MAJOR_IN_MKDEV
# include <sys/mkdev.h>
#elif MAJOR_IN_SYSMACROS
# include <sys/sysmacros.h>
#endif

#include <sys/types.h>
#include <termios.h>

#if WITH_DEVMAPPER
# include <libdevmapper.h>
#endif

#include <netdb.h>
#ifdef HAVE_GETPWUID_R
# include <pwd.h>
# include <grp.h>
#endif
#if WITH_CAPNG
# include <cap-ng.h>
# include <sys/prctl.h>
#endif

#ifdef WIN32
# ifdef HAVE_WINSOCK2_H
#  include <winsock2.h>
# endif
# include <windows.h>
# include <shlobj.h>
#endif

#ifdef HAVE_SYS_UN_H
# include <sys/un.h>
#endif

#include "c-ctype.h"
#include "mgetgroups.h"
#include "virerror.h"
#include "virlog.h"
#include "virbuffer.h"
#include "viralloc.h"
#include "verify.h"
#include "virfile.h"
#include "vircommand.h"
#include "nonblocking.h"
#include "virprocess.h"
#include "virstring.h"
#include "virutil.h"

verify(sizeof(gid_t) <= sizeof(unsigned int) &&
       sizeof(uid_t) <= sizeof(unsigned int));

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.util");

#ifndef WIN32

int virSetInherit(int fd, bool inherit)
{
    int fflags;
    if ((fflags = fcntl(fd, F_GETFD)) < 0)
        return -1;
    if (inherit)
        fflags &= ~FD_CLOEXEC;
    else
        fflags |= FD_CLOEXEC;
    if ((fcntl(fd, F_SETFD, fflags)) < 0)
        return -1;
    return 0;
}

#else /* WIN32 */

int virSetInherit(int fd G_GNUC_UNUSED, bool inherit G_GNUC_UNUSED)
{
    /* FIXME: Currently creating child processes is not supported on
     * Win32, so there is no point in failing calls that are only relevant
     * when creating child processes. So just pretend that we changed the
     * inheritance property of the given fd as requested. */
    return 0;
}

#endif /* WIN32 */

int virSetBlocking(int fd, bool blocking)
{
    return set_nonblocking_flag(fd, !blocking);
}

int virSetNonBlock(int fd)
{
    return virSetBlocking(fd, false);
}

int virSetCloseExec(int fd)
{
    return virSetInherit(fd, false);
}

#ifdef WIN32
int virSetSockReuseAddr(int fd G_GNUC_UNUSED, bool fatal G_GNUC_UNUSED)
{
    /*
     * SO_REUSEADDR on Windows is actually akin to SO_REUSEPORT
     * on Linux/BSD. ie it allows 2 apps to listen to the same
     * port at once which is certainly not what we want here.
     *
     * Win32 sockets have Linux/BSD-like SO_REUSEADDR behaviour
     * by default, so we can be a no-op.
     *
     * http://msdn.microsoft.com/en-us/library/windows/desktop/ms740621.aspx
     */
    return 0;
}
#else
int virSetSockReuseAddr(int fd, bool fatal)
{
    int opt = 1;
    int ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (ret < 0 && fatal) {
        virReportSystemError(errno, "%s",
                             _("Unable to set socket reuse addr flag"));
    }

    return ret;
}
#endif


/* Convert C from hexadecimal character to integer.  */
int
virHexToBin(unsigned char c)
{
    switch (c) {
    default: return c - '0';
    case 'a': case 'A': return 10;
    case 'b': case 'B': return 11;
    case 'c': case 'C': return 12;
    case 'd': case 'D': return 13;
    case 'e': case 'E': return 14;
    case 'f': case 'F': return 15;
    }
}

/* Scale an integer VALUE in-place by an optional case-insensitive
 * SUFFIX, defaulting to SCALE if suffix is NULL or empty (scale is
 * typically 1 or 1024).  Recognized suffixes include 'b' or 'bytes',
 * as well as power-of-two scaling via binary abbreviations ('KiB',
 * 'MiB', ...) or their one-letter counterpart ('k', 'M', ...), and
 * power-of-ten scaling via SI abbreviations ('KB', 'MB', ...).
 * Ensure that the result does not exceed LIMIT.  Return 0 on success,
 * -1 with error message raised on failure.  */
int
virScaleInteger(unsigned long long *value, const char *suffix,
                unsigned long long scale, unsigned long long limit)
{
    if (!suffix || !*suffix) {
        if (!scale) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("invalid scale %llu"), scale);
            return -1;
        }
        suffix = "";
    } else if (STRCASEEQ(suffix, "b") || STRCASEEQ(suffix, "byte") ||
               STRCASEEQ(suffix, "bytes")) {
        scale = 1;
    } else {
        int base;

        if (!suffix[1] || STRCASEEQ(suffix + 1, "iB")) {
            base = 1024;
        } else if (c_tolower(suffix[1]) == 'b' && !suffix[2]) {
            base = 1000;
        } else {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("unknown suffix '%s'"), suffix);
            return -1;
        }
        scale = 1;
        switch (c_tolower(*suffix)) {
        case 'e':
            scale *= base;
            G_GNUC_FALLTHROUGH;
        case 'p':
            scale *= base;
            G_GNUC_FALLTHROUGH;
        case 't':
            scale *= base;
            G_GNUC_FALLTHROUGH;
        case 'g':
            scale *= base;
            G_GNUC_FALLTHROUGH;
        case 'm':
            scale *= base;
            G_GNUC_FALLTHROUGH;
        case 'k':
            scale *= base;
            break;
        default:
            virReportError(VIR_ERR_INVALID_ARG,
                           _("unknown suffix '%s'"), suffix);
            return -1;
        }
    }

    if (*value && *value > (limit / scale)) {
        virReportError(VIR_ERR_OVERFLOW, _("value too large: %llu%s"),
                       *value, suffix);
        return -1;
    }
    *value *= scale;
    return 0;
}


/**
 * virParseVersionString:
 * @str: const char pointer to the version string
 * @version: unsigned long pointer to output the version number
 * @allowMissing: true to treat 3 like 3.0.0, false to error out on
 * missing minor or micro
 *
 * Parse an unsigned version number from a version string. Expecting
 * 'major.minor.micro' format, ignoring an optional suffix.
 *
 * The major, minor and micro numbers are encoded into a single version number:
 *
 *   1000000 * major + 1000 * minor + micro
 *
 * Returns the 0 for success, -1 for error.
 */
int
virParseVersionString(const char *str, unsigned long *version,
                      bool allowMissing)
{
    unsigned int major, minor = 0, micro = 0;
    char *tmp;

    if (virStrToLong_ui(str, &tmp, 10, &major) < 0)
        return -1;

    if (!allowMissing && *tmp != '.')
        return -1;

    if ((*tmp == '.') && virStrToLong_ui(tmp + 1, &tmp, 10, &minor) < 0)
        return -1;

    if (!allowMissing && *tmp != '.')
        return -1;

    if ((*tmp == '.') && virStrToLong_ui(tmp + 1, &tmp, 10, &micro) < 0)
        return -1;

    if (major > UINT_MAX / 1000000 || minor > 999 || micro > 999)
        return -1;

    *version = 1000000 * major + 1000 * minor + micro;

    return 0;
}

/**
 * Format @val as a base-10 decimal number, in the
 * buffer @buf of size @buflen. To allocate a suitable
 * sized buffer, the INT_BUFLEN(int) macro should be
 * used
 *
 * Returns pointer to start of the number in @buf
 */
char *
virFormatIntDecimal(char *buf, size_t buflen, int val)
{
    char *p = buf + buflen - 1;
    *p = '\0';
    if (val >= 0) {
        do {
            *--p = '0' + (val % 10);
            val /= 10;
        } while (val != 0);
    } else {
        do {
            *--p = '0' - (val % 10);
            val /= 10;
        } while (val != 0);
        *--p = '-';
    }
    return p;
}


/**
 * virFormatIntPretty
 *
 * @val: Value in bytes to be shortened
 * @unit: unit to be used
 *
 * Similar to vshPrettyCapacity, but operates on integers and not doubles
 *
 * NB: Since using unsigned long long, we are limited to at most a "PiB"
 *     to make pretty. This is because a PiB is 1152921504606846976 bytes,
 *     but that value * 1024 > ULLONG_MAX value 18446744073709551615 bytes.
 *
 * Returns shortened value that can be used with @unit.
 */
unsigned long long
virFormatIntPretty(unsigned long long val,
                   const char **unit)
{
    unsigned long long limit = 1024;

    if (val % limit || val == 0) {
        *unit = "B";
        return val;
    }
    limit *= 1024;
    if (val % limit) {
        *unit = "KiB";
        return val / (limit / 1024);
    }
    limit *= 1024;
    if (val % limit) {
        *unit = "MiB";
        return val / (limit / 1024);
    }
    limit *= 1024;
    if (val % limit) {
        *unit = "GiB";
        return val / (limit / 1024);
    }
    limit *= 1024;
    if (val % limit) {
        *unit = "TiB";
        return val / (limit / 1024);
    }
    limit *= 1024;
    *unit = "PiB";
    return val / (limit / 1024);
}


/* Translates a device name of the form (regex) /^[fhv]d[a-z]+[0-9]*$/
 * into the corresponding index and partition number
 * (e.g. sda0 => (0,0), hdz2 => (25,2), vdaa12 => (26,12))
 * @param name The name of the device
 * @param disk The disk index to be returned
 * @param partition The partition index to be returned
 * @return 0 on success, or -1 on failure
 */
int virDiskNameParse(const char *name, int *disk, int *partition)
{
    const char *ptr = NULL;
    char *rem;
    int idx = 0;
    static char const* const drive_prefix[] = {"fd", "hd", "vd", "sd", "xvd", "ubd"};
    size_t i;

    for (i = 0; i < G_N_ELEMENTS(drive_prefix); i++) {
        if (STRPREFIX(name, drive_prefix[i])) {
            ptr = name + strlen(drive_prefix[i]);
            break;
        }
    }

    if (!ptr || !c_islower(*ptr))
        return -1;

    for (i = 0; *ptr; i++) {
        if (!c_islower(*ptr))
            break;

        idx = (idx + (i < 1 ? 0 : 1)) * 26;
        idx += *ptr - 'a';
        ptr++;
    }

    /* Count the trailing digits.  */
    size_t n_digits = strspn(ptr, "0123456789");
    if (ptr[n_digits] != '\0')
        return -1;

    *disk = idx;

    /* Convert trailing digits into our partition index */
    if (partition) {
        *partition = 0;

        /* Shouldn't start by zero */
        if (n_digits > 1 && *ptr == '0')
            return -1;

        if (n_digits && virStrToLong_i(ptr, &rem, 10, partition) < 0)
            return -1;
    }

    return 0;
}

/* Translates a device name of the form (regex) /^[fhv]d[a-z]+[0-9]*$/
 * into the corresponding index (e.g. sda => 0, hdz => 25, vdaa => 26)
 * Note that any trailing string of digits is simply ignored.
 * @param name The name of the device
 * @return name's index, or -1 on failure
 */
int virDiskNameToIndex(const char *name)
{
    int idx;

    if (virDiskNameParse(name, &idx, NULL) < 0)
        idx = -1;

    return idx;
}

char *virIndexToDiskName(int idx, const char *prefix)
{
    char *name = NULL;
    size_t i;
    int ctr;
    int offset;

    if (idx < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Disk index %d is negative"), idx);
        return NULL;
    }

    for (i = 0, ctr = idx; ctr >= 0; ++i, ctr = ctr / 26 - 1) { }

    offset = strlen(prefix);

    if (VIR_ALLOC_N(name, offset + i + 1))
        return NULL;

    strcpy(name, prefix);
    name[offset + i] = '\0';

    for (i = i - 1, ctr = idx; ctr >= 0; --i, ctr = ctr / 26 - 1)
        name[offset + i] = 'a' + (ctr % 26);

    return name;
}

#ifndef AI_CANONIDN
# define AI_CANONIDN 0
#endif

#ifndef HOST_NAME_MAX
# define HOST_NAME_MAX 256
#endif

/* Who knew getting a hostname could be so delicate.  In Linux (and Unices
 * in general), many things depend on "hostname" returning a value that will
 * resolve one way or another.  In the modern world where networks frequently
 * come and go this is often being hard-coded to resolve to "localhost".  If
 * it *doesn't* resolve to localhost, then we would prefer to have the FQDN.
 * That leads us to 3 possibilities:
 *
 * 1)  gethostname() returns an FQDN (not localhost) - we return the string
 *     as-is, it's all of the information we want
 * 2)  gethostname() returns "localhost" - we return localhost; doing further
 *     work to try to resolve it is pointless
 * 3)  gethostname() returns a shortened hostname - in this case, we want to
 *     try to resolve this to a fully-qualified name.  Therefore we pass it
 *     to getaddrinfo().  There are two possible responses:
 *     a)  getaddrinfo() resolves to a FQDN - return the FQDN
 *     b)  getaddrinfo() fails or resolves to localhost - in this case, the
 *         data we got from gethostname() is actually more useful than what
 *         we got from getaddrinfo().  Return the value from gethostname()
 *         and hope for the best.
 */
static char *
virGetHostnameImpl(bool quiet)
{
    int r;
    char hostname[HOST_NAME_MAX+1], *result = NULL;
    struct addrinfo hints, *info;

    r = gethostname(hostname, sizeof(hostname));
    if (r == -1) {
        if (!quiet)
            virReportSystemError(errno,
                                 "%s", _("failed to determine host name"));
        return NULL;
    }
    NUL_TERMINATE(hostname);

    if (STRPREFIX(hostname, "localhost") || strchr(hostname, '.')) {
        /* in this case, gethostname returned localhost (meaning we can't
         * do any further canonicalization), or it returned an FQDN (and
         * we don't need to do any further canonicalization).  Return the
         * string as-is; it's up to callers to check whether "localhost"
         * is allowed.
         */
        ignore_value(VIR_STRDUP_QUIET(result, hostname));
        goto cleanup;
    }

    /* otherwise, it's a shortened, non-localhost, hostname.  Attempt to
     * canonicalize the hostname by running it through getaddrinfo
     */

    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = AI_CANONNAME|AI_CANONIDN;
    hints.ai_family = AF_UNSPEC;
    r = getaddrinfo(hostname, NULL, &hints, &info);
    if (r != 0) {
        if (!quiet)
            VIR_WARN("getaddrinfo failed for '%s': %s",
                     hostname, gai_strerror(r));
        ignore_value(VIR_STRDUP_QUIET(result, hostname));
        goto cleanup;
    }

    /* Tell static analyzers about getaddrinfo semantics.  */
    sa_assert(info);

    if (info->ai_canonname == NULL ||
        STRPREFIX(info->ai_canonname, "localhost"))
        /* in this case, we tried to canonicalize and we ended up back with
         * localhost.  Ignore the canonicalized name and just return the
         * original hostname
         */
        ignore_value(VIR_STRDUP_QUIET(result, hostname));
    else
        /* Caller frees this string. */
        ignore_value(VIR_STRDUP_QUIET(result, info->ai_canonname));

    freeaddrinfo(info);

 cleanup:
    if (!result)
        virReportOOMError();
    return result;
}


char *
virGetHostname(void)
{
    return virGetHostnameImpl(false);
}


char *
virGetHostnameQuiet(void)
{
    return virGetHostnameImpl(true);
}


char *
virGetUserDirectory(void)
{
    return virGetUserDirectoryByUID(geteuid());
}


#ifdef HAVE_GETPWUID_R
/* Look up fields from the user database for the given user.  On
 * error, set errno, report the error if not instructed otherwise via @quiet,
 * and return -1.  */
static int
virGetUserEnt(uid_t uid, char **name, gid_t *group, char **dir, char **shell, bool quiet)
{
    char *strbuf;
    struct passwd pwbuf;
    struct passwd *pw = NULL;
    long val = sysconf(_SC_GETPW_R_SIZE_MAX);
    size_t strbuflen = val;
    int rc;
    int ret = -1;

    if (name)
        *name = NULL;
    if (dir)
        *dir = NULL;
    if (shell)
        *shell = NULL;

    /* sysconf is a hint; if it fails, fall back to a reasonable size */
    if (val < 0)
        strbuflen = 1024;

    if (VIR_ALLOC_N(strbuf, strbuflen) < 0)
        return -1;

    /*
     * From the manpage (terrifying but true):
     *
     * ERRORS
     *  0 or ENOENT or ESRCH or EBADF or EPERM or ...
     *        The given name or uid was not found.
     */
    while ((rc = getpwuid_r(uid, &pwbuf, strbuf, strbuflen, &pw)) == ERANGE) {
        if (VIR_RESIZE_N(strbuf, strbuflen, strbuflen, strbuflen) < 0)
            goto cleanup;
    }

    if (rc != 0) {
        if (quiet)
            goto cleanup;

        virReportSystemError(rc,
                             _("Failed to find user record for uid '%u'"),
                             (unsigned int) uid);
        goto cleanup;
    } else if (pw == NULL) {
        if (quiet)
            goto cleanup;

        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("Failed to find user record for uid '%u'"),
                       (unsigned int) uid);
        goto cleanup;
    }

    if (name && VIR_STRDUP(*name, pw->pw_name) < 0)
        goto cleanup;
    if (group)
        *group = pw->pw_gid;
    if (dir && VIR_STRDUP(*dir, pw->pw_dir) < 0)
        goto cleanup;
    if (shell && VIR_STRDUP(*shell, pw->pw_shell) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    if (ret < 0) {
        if (name)
            VIR_FREE(*name);
        if (dir)
            VIR_FREE(*dir);
        if (shell)
            VIR_FREE(*shell);
    }
    VIR_FREE(strbuf);
    return ret;
}

static char *virGetGroupEnt(gid_t gid)
{
    char *strbuf;
    char *ret;
    struct group grbuf;
    struct group *gr = NULL;
    long val = sysconf(_SC_GETGR_R_SIZE_MAX);
    size_t strbuflen = val;
    int rc;

    /* sysconf is a hint; if it fails, fall back to a reasonable size */
    if (val < 0)
        strbuflen = 1024;

    if (VIR_ALLOC_N(strbuf, strbuflen) < 0)
        return NULL;

    /*
     * From the manpage (terrifying but true):
     *
     * ERRORS
     *  0 or ENOENT or ESRCH or EBADF or EPERM or ...
     *        The given name or gid was not found.
     */
    while ((rc = getgrgid_r(gid, &grbuf, strbuf, strbuflen, &gr)) == ERANGE) {
        if (VIR_RESIZE_N(strbuf, strbuflen, strbuflen, strbuflen) < 0) {
            VIR_FREE(strbuf);
            return NULL;
        }
    }
    if (rc != 0 || gr == NULL) {
        if (rc != 0) {
            virReportSystemError(rc,
                                 _("Failed to find group record for gid '%u'"),
                                 (unsigned int) gid);
        } else {
            virReportError(VIR_ERR_SYSTEM_ERROR,
                           _("Failed to find group record for gid '%u'"),
                           (unsigned int) gid);
        }

        VIR_FREE(strbuf);
        return NULL;
    }

    ignore_value(VIR_STRDUP(ret, gr->gr_name));
    VIR_FREE(strbuf);
    return ret;
}


char *
virGetUserDirectoryByUID(uid_t uid)
{
    char *ret;
    virGetUserEnt(uid, NULL, NULL, &ret, NULL, false);
    return ret;
}


char *virGetUserShell(uid_t uid)
{
    char *ret;
    virGetUserEnt(uid, NULL, NULL, NULL, &ret, false);
    return ret;
}


static char *virGetXDGDirectory(const char *xdgenvname, const char *xdgdefdir)
{
    const char *path = getenv(xdgenvname);
    char *ret = NULL;
    char *home = NULL;

    if (path && path[0]) {
        ignore_value(virAsprintf(&ret, "%s/libvirt", path));
    } else {
        home = virGetUserDirectory();
        if (home)
            ignore_value(virAsprintf(&ret, "%s/%s/libvirt", home, xdgdefdir));
    }

    VIR_FREE(home);
    return ret;
}

char *virGetUserConfigDirectory(void)
{
    return virGetXDGDirectory("XDG_CONFIG_HOME", ".config");
}

char *virGetUserCacheDirectory(void)
{
    return virGetXDGDirectory("XDG_CACHE_HOME", ".cache");
}

char *virGetUserRuntimeDirectory(void)
{
    const char *path = getenv("XDG_RUNTIME_DIR");

    if (!path || !path[0]) {
        return virGetUserCacheDirectory();
    } else {
        char *ret;

        ignore_value(virAsprintf(&ret, "%s/libvirt", path));
        return ret;
    }
}

char *virGetUserName(uid_t uid)
{
    char *ret;
    virGetUserEnt(uid, &ret, NULL, NULL, NULL, false);
    return ret;
}

char *virGetGroupName(gid_t gid)
{
    return virGetGroupEnt(gid);
}

/* Search in the password database for a user id that matches the user name
 * `name`. Returns 0 on success, -1 on failure or 1 if name cannot be found.
 *
 * Warns if @missing_ok is false
 */
static int
virGetUserIDByName(const char *name, uid_t *uid, bool missing_ok)
{
    char *strbuf = NULL;
    struct passwd pwbuf;
    struct passwd *pw = NULL;
    long val = sysconf(_SC_GETPW_R_SIZE_MAX);
    size_t strbuflen = val;
    int rc;
    int ret = -1;

    /* sysconf is a hint; if it fails, fall back to a reasonable size */
    if (val < 0)
        strbuflen = 1024;

    if (VIR_ALLOC_N(strbuf, strbuflen) < 0)
        goto cleanup;

    while ((rc = getpwnam_r(name, &pwbuf, strbuf, strbuflen, &pw)) == ERANGE) {
        if (VIR_RESIZE_N(strbuf, strbuflen, strbuflen, strbuflen) < 0)
            goto cleanup;
    }

    if (!pw) {
        if (rc != 0 && !missing_ok) {
            char buf[1024];
            /* log the possible error from getpwnam_r. Unfortunately error
             * reporting from this function is bad and we can't really
             * rely on it, so we just report that the user wasn't found */
            VIR_WARN("User record for user '%s' was not found: %s",
                     name, virStrerror(rc, buf, sizeof(buf)));
        }

        ret = 1;
        goto cleanup;
    }

    if (uid)
        *uid = pw->pw_uid;
    ret = 0;

 cleanup:
    VIR_FREE(strbuf);

    return ret;
}

/* Try to match a user id based on `user`. The default behavior is to parse
 * `user` first as a user name and then as a user id. However if `user`
 * contains a leading '+', the rest of the string is always parsed as a uid.
 *
 * Returns 0 on success and -1 otherwise.
 */
int
virGetUserID(const char *user, uid_t *uid)
{
    unsigned int uint_uid;

    if (*user == '+') {
        user++;
    } else {
        int rc = virGetUserIDByName(user, uid, false);
        if (rc <= 0)
            return rc;
    }

    if (virStrToLong_ui(user, NULL, 10, &uint_uid) < 0 ||
        ((uid_t) uint_uid) != uint_uid) {
        virReportError(VIR_ERR_INVALID_ARG, _("Failed to parse user '%s'"),
                       user);
        return -1;
    }

    *uid = uint_uid;

    return 0;
}

/* Search in the group database for a group id that matches the group name
 * `name`. Returns 0 on success, -1 on failure or 1 if name cannot be found.
 *
 * Warns if @missing_ok is false
 */
static int
virGetGroupIDByName(const char *name, gid_t *gid, bool missing_ok)
{
    char *strbuf = NULL;
    struct group grbuf;
    struct group *gr = NULL;
    long val = sysconf(_SC_GETGR_R_SIZE_MAX);
    size_t strbuflen = val;
    int rc;
    int ret = -1;

    /* sysconf is a hint; if it fails, fall back to a reasonable size */
    if (val < 0)
        strbuflen = 1024;

    if (VIR_ALLOC_N(strbuf, strbuflen) < 0)
        goto cleanup;

    while ((rc = getgrnam_r(name, &grbuf, strbuf, strbuflen, &gr)) == ERANGE) {
        if (VIR_RESIZE_N(strbuf, strbuflen, strbuflen, strbuflen) < 0)
            goto cleanup;
    }

    if (!gr) {
        if (rc != 0 && !missing_ok) {
            char buf[1024];
            /* log the possible error from getgrnam_r. Unfortunately error
             * reporting from this function is bad and we can't really
             * rely on it, so we just report that the user wasn't found */
            VIR_WARN("Group record for user '%s' was not found: %s",
                     name, virStrerror(rc, buf, sizeof(buf)));
        }

        ret = 1;
        goto cleanup;
    }

    if (gid)
        *gid = gr->gr_gid;
    ret = 0;

 cleanup:
    VIR_FREE(strbuf);

    return ret;
}

/* Try to match a group id based on `group`. The default behavior is to parse
 * `group` first as a group name and then as a group id. However if `group`
 * contains a leading '+', the rest of the string is always parsed as a guid.
 *
 * Returns 0 on success and -1 otherwise.
 */
int
virGetGroupID(const char *group, gid_t *gid)
{
    unsigned int uint_gid;

    if (*group == '+') {
        group++;
    } else {
        int rc = virGetGroupIDByName(group, gid, false);
        if (rc <= 0)
            return rc;
    }

    if (virStrToLong_ui(group, NULL, 10, &uint_gid) < 0 ||
        ((gid_t) uint_gid) != uint_gid) {
        virReportError(VIR_ERR_INVALID_ARG, _("Failed to parse group '%s'"),
                       group);
        return -1;
    }

    *gid = uint_gid;

    return 0;
}

/* Silently checks if User @name exists.
 * Returns if the user exists and fallbacks to false on error.
 */
bool
virDoesUserExist(const char *name)
{
    return virGetUserIDByName(name, NULL, true) == 0;
}

/* Silently checks if Group @name exists.
 * Returns if the group exists and fallbacks to false on error.
 */
bool
virDoesGroupExist(const char *name)
{
    return virGetGroupIDByName(name, NULL, true) == 0;
}


/* Compute the list of primary and supplementary groups associated
 * with @uid, and including @gid in the list (unless it is -1),
 * storing a malloc'd result into @list. If uid is -1 or doesn't exist in the
 * system database querying of the supplementary groups is skipped.
 *
 * Returns the size of the list on success, or -1 on failure with error
 * reported and errno set. May not be called between fork and exec.
 * */
int
virGetGroupList(uid_t uid, gid_t gid, gid_t **list)
{
    int ret = 0;
    char *user = NULL;
    gid_t primary;

    *list = NULL;

    /* invalid users have no supplementary groups */
    if (uid != (uid_t)-1 &&
        virGetUserEnt(uid, &user, &primary, NULL, NULL, true) >= 0) {
        if ((ret = mgetgroups(user, primary, list)) < 0) {
            virReportSystemError(errno,
                                 _("cannot get group list for '%s'"), user);
            ret = -1;
            goto cleanup;
        }
    }

    if (gid != (gid_t)-1) {
        size_t i;

        for (i = 0; i < ret; i++) {
            if ((*list)[i] == gid)
                goto cleanup;
        }
        if (VIR_APPEND_ELEMENT(*list, i, gid) < 0) {
            ret = -1;
            VIR_FREE(*list);
            goto cleanup;
        } else {
            ret = i;
        }
    }

 cleanup:
    VIR_FREE(user);
    return ret;
}


/* Set the real and effective uid and gid to the given values, as well
 * as all the supplementary groups, so that the process has all the
 * assumed group membership of that uid. Return 0 on success, -1 on
 * failure (the original system error remains in errno).
 */
int
virSetUIDGID(uid_t uid, gid_t gid, gid_t *groups G_GNUC_UNUSED,
             int ngroups G_GNUC_UNUSED)
{
    if (gid != (gid_t)-1 && setregid(gid, gid) < 0) {
        virReportSystemError(errno,
                             _("cannot change to '%u' group"),
                             (unsigned int) gid);
        return -1;
    }

# if HAVE_SETGROUPS
    if (gid != (gid_t)-1 && setgroups(ngroups, groups) < 0) {
        virReportSystemError(errno, "%s",
                             _("cannot set supplemental groups"));
        return -1;
    }
# endif

    if (uid != (uid_t)-1 && setreuid(uid, uid) < 0) {
        virReportSystemError(errno,
                             _("cannot change to uid to '%u'"),
                             (unsigned int) uid);
        return -1;
    }

    return 0;
}

#else /* ! HAVE_GETPWUID_R */

int
virGetGroupList(uid_t uid G_GNUC_UNUSED, gid_t gid G_GNUC_UNUSED,
                gid_t **list)
{
    *list = NULL;
    return 0;
}

bool
virDoesUserExist(const char *name G_GNUC_UNUSED)
{
    return false;
}

bool
virDoesGroupExist(const char *name G_GNUC_UNUSED)
{
    return false;
}

# ifdef WIN32
/* These methods are adapted from GLib2 under terms of LGPLv2+ */
static int
virGetWin32SpecialFolder(int csidl, char **path)
{
    char buf[MAX_PATH+1];
    LPITEMIDLIST pidl = NULL;
    int ret = 0;

    *path = NULL;

    if (SHGetSpecialFolderLocation(NULL, csidl, &pidl) == S_OK) {
        if (SHGetPathFromIDList(pidl, buf) && VIR_STRDUP(*path, buf) < 0)
            ret = -1;
        CoTaskMemFree(pidl);
    }
    return ret;
}

static int
virGetWin32DirectoryRoot(char **path)
{
    char windowsdir[MAX_PATH];

    *path = NULL;

    if (GetWindowsDirectory(windowsdir, G_N_ELEMENTS(windowsdir))) {
        const char *tmp;
        /* Usually X:\Windows, but in terminal server environments
         * might be an UNC path, AFAIK.
         */
        tmp = virFileSkipRoot(windowsdir);
        if (VIR_FILE_IS_DIR_SEPARATOR(tmp[-1]) &&
            tmp[-2] != ':')
            tmp--;

        windowsdir[tmp - windowsdir] = '\0';
    } else {
        strcpy(windowsdir, "C:\\");
    }

    return VIR_STRDUP(*path, windowsdir) < 0 ? -1 : 0;
}



char *
virGetUserDirectoryByUID(uid_t uid G_GNUC_UNUSED)
{
    /* Since Windows lacks setuid binaries, and since we already fake
     * geteuid(), we can safely assume that this is only called when
     * querying about the current user */
    const char *dir;
    char *ret;

    dir = getenv("HOME");

    /* Only believe HOME if it is an absolute path and exists */
    if (dir) {
        if (!virFileIsAbsPath(dir) ||
            !virFileExists(dir))
            dir = NULL;
    }

    /* In case HOME is Unix-style (it happens), convert it to
     * Windows style.
     */
    if (dir) {
        char *p;
        while ((p = strchr(dir, '/')) != NULL)
            *p = '\\';
    }

    if (!dir)
        /* USERPROFILE is probably the closest equivalent to $HOME? */
        dir = getenv("USERPROFILE");

    if (VIR_STRDUP(ret, dir) < 0)
        return NULL;

    if (!ret &&
        virGetWin32SpecialFolder(CSIDL_PROFILE, &ret) < 0)
        return NULL;

    if (!ret &&
        virGetWin32DirectoryRoot(&ret) < 0)
        return NULL;

    if (!ret) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to determine home directory"));
        return NULL;
    }

    return ret;
}

char *
virGetUserShell(uid_t uid G_GNUC_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR,
                   "%s", _("virGetUserShell is not available"));

    return NULL;
}

char *
virGetUserConfigDirectory(void)
{
    char *ret;
    if (virGetWin32SpecialFolder(CSIDL_LOCAL_APPDATA, &ret) < 0)
        return NULL;

    if (!ret) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to determine config directory"));
        return NULL;
    }
    return ret;
}

char *
virGetUserCacheDirectory(void)
{
    char *ret;
    if (virGetWin32SpecialFolder(CSIDL_INTERNET_CACHE, &ret) < 0)
        return NULL;

    if (!ret) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to determine config directory"));
        return NULL;
    }
    return ret;
}

char *
virGetUserRuntimeDirectory(void)
{
    return virGetUserCacheDirectory();
}

# else /* !HAVE_GETPWUID_R && !WIN32 */
char *
virGetUserDirectoryByUID(uid_t uid G_GNUC_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR,
                   "%s", _("virGetUserDirectory is not available"));

    return NULL;
}

char *
virGetUserShell(uid_t uid G_GNUC_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR,
                   "%s", _("virGetUserShell is not available"));

    return NULL;
}

char *
virGetUserConfigDirectory(void)
{
    virReportError(VIR_ERR_INTERNAL_ERROR,
                   "%s", _("virGetUserConfigDirectory is not available"));

    return NULL;
}

char *
virGetUserCacheDirectory(void)
{
    virReportError(VIR_ERR_INTERNAL_ERROR,
                   "%s", _("virGetUserCacheDirectory is not available"));

    return NULL;
}

char *
virGetUserRuntimeDirectory(void)
{
    virReportError(VIR_ERR_INTERNAL_ERROR,
                   "%s", _("virGetUserRuntimeDirectory is not available"));

    return NULL;
}
# endif /* ! HAVE_GETPWUID_R && ! WIN32 */

char *
virGetUserName(uid_t uid G_GNUC_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR,
                   "%s", _("virGetUserName is not available"));

    return NULL;
}

int virGetUserID(const char *name G_GNUC_UNUSED,
                 uid_t *uid G_GNUC_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR,
                   "%s", _("virGetUserID is not available"));

    return -1;
}


int virGetGroupID(const char *name G_GNUC_UNUSED,
                  gid_t *gid G_GNUC_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR,
                   "%s", _("virGetGroupID is not available"));

    return -1;
}

int
virSetUIDGID(uid_t uid G_GNUC_UNUSED,
             gid_t gid G_GNUC_UNUSED,
             gid_t *groups G_GNUC_UNUSED,
             int ngroups G_GNUC_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR,
                   "%s", _("virSetUIDGID is not available"));
    return -1;
}

char *
virGetGroupName(gid_t gid G_GNUC_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR,
                   "%s", _("virGetGroupName is not available"));

    return NULL;
}
#endif /* HAVE_GETPWUID_R */

#if WITH_CAPNG
/* Set the real and effective uid and gid to the given values, while
 * maintaining the capabilities indicated by bits in @capBits. Return
 * 0 on success, -1 on failure (the original system error remains in
 * errno).
 */
int
virSetUIDGIDWithCaps(uid_t uid, gid_t gid, gid_t *groups, int ngroups,
                     unsigned long long capBits, bool clearExistingCaps)
{
    size_t i;
    int capng_ret, ret = -1;
    bool need_setgid = false;
    bool need_setuid = false;
    bool need_setpcap = false;
    const char *capstr = NULL;

    /* First drop all caps (unless the requested uid is "unchanged" or
     * root and clearExistingCaps wasn't requested), then add back
     * those in capBits + the extra ones we need to change uid/gid and
     * change the capabilities bounding set.
     */

    if (clearExistingCaps || (uid != (uid_t)-1 && uid != 0))
        capng_clear(CAPNG_SELECT_BOTH);

    for (i = 0; i <= CAP_LAST_CAP; i++) {
        capstr = capng_capability_to_name(i);

        if (capBits & (1ULL << i)) {
            capng_update(CAPNG_ADD,
                         CAPNG_EFFECTIVE|CAPNG_INHERITABLE|
                         CAPNG_PERMITTED|CAPNG_BOUNDING_SET,
                         i);

            VIR_DEBUG("Added '%s' to child capabilities' set", capstr);
        }
    }

    if (gid != (gid_t)-1 &&
        !capng_have_capability(CAPNG_EFFECTIVE, CAP_SETGID)) {
        need_setgid = true;
        capng_update(CAPNG_ADD, CAPNG_EFFECTIVE|CAPNG_PERMITTED, CAP_SETGID);
    }
    if (uid != (uid_t)-1 &&
        !capng_have_capability(CAPNG_EFFECTIVE, CAP_SETUID)) {
        need_setuid = true;
        capng_update(CAPNG_ADD, CAPNG_EFFECTIVE|CAPNG_PERMITTED, CAP_SETUID);
    }
# ifdef PR_CAPBSET_DROP
    /* If newer kernel, we need also need setpcap to change the bounding set */
    if ((capBits || need_setgid || need_setuid) &&
        !capng_have_capability(CAPNG_EFFECTIVE, CAP_SETPCAP)) {
        need_setpcap = true;
    }
    if (need_setpcap)
        capng_update(CAPNG_ADD, CAPNG_EFFECTIVE|CAPNG_PERMITTED, CAP_SETPCAP);
# endif

    /* Tell system we want to keep caps across uid change */
    if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0)) {
        virReportSystemError(errno, "%s",
                             _("prctl failed to set KEEPCAPS"));
        goto cleanup;
    }

    /* Change to the temp capabilities */
    if ((capng_ret = capng_apply(CAPNG_SELECT_CAPS)) < 0) {
        /* Failed.  If we are running unprivileged, and the arguments make sense
         * for this scenario, assume we're starting some kind of setuid helper:
         * do not set any of capBits in the permitted or effective sets, and let
         * the program get them on its own.
         *
         * (Too bad we cannot restrict the bounding set to the capabilities we
         * would like the helper to have!).
         */
        if (getuid() > 0 && clearExistingCaps && !need_setuid && !need_setgid) {
            capng_clear(CAPNG_SELECT_CAPS);
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot apply process capabilities %d"), capng_ret);
            goto cleanup;
        }
    }

    if (virSetUIDGID(uid, gid, groups, ngroups) < 0)
        goto cleanup;

    /* Tell it we are done keeping capabilities */
    if (prctl(PR_SET_KEEPCAPS, 0, 0, 0, 0)) {
        virReportSystemError(errno, "%s",
                             _("prctl failed to reset KEEPCAPS"));
        goto cleanup;
    }

# ifdef PR_CAP_AMBIENT
    /* we couldn't do this in the loop earlier above, because the capabilities
     * were not applied yet, since in order to add a capability into the AMBIENT
     * set, it has to be present in both the PERMITTED and INHERITABLE sets
     * (capabilities(7))
     */
    for (i = 0; i <= CAP_LAST_CAP; i++) {
        capstr = capng_capability_to_name(i);

        if (capBits & (1ULL << i)) {
            if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, i, 0, 0) < 0) {
                virReportSystemError(errno,
                                     _("prctl failed to enable '%s' in the "
                                       "AMBIENT set"),
                                     capstr);
                goto cleanup;
            }
        }
    }
# endif

    /* Set bounding set while we have CAP_SETPCAP.  Unfortunately we cannot
     * do this if we failed to get the capability above, so ignore the
     * return value.
     */
    capng_apply(CAPNG_SELECT_BOUNDS);

    /* Drop the caps that allow setuid/gid (unless they were requested) */
    if (need_setgid)
        capng_update(CAPNG_DROP, CAPNG_EFFECTIVE|CAPNG_PERMITTED, CAP_SETGID);
    if (need_setuid)
        capng_update(CAPNG_DROP, CAPNG_EFFECTIVE|CAPNG_PERMITTED, CAP_SETUID);
    /* Throw away CAP_SETPCAP so no more changes */
    if (need_setpcap)
        capng_update(CAPNG_DROP, CAPNG_EFFECTIVE|CAPNG_PERMITTED, CAP_SETPCAP);

    if (((capng_ret = capng_apply(CAPNG_SELECT_CAPS)) < 0)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot apply process capabilities %d"), capng_ret);
        ret = -1;
        goto cleanup;
    }

    ret = 0;
 cleanup:
    return ret;
}

#else
/*
 * On platforms without libcapng, the capabilities setting is treated
 * as a NOP.
 */

int
virSetUIDGIDWithCaps(uid_t uid, gid_t gid, gid_t *groups, int ngroups,
                     unsigned long long capBits G_GNUC_UNUSED,
                     bool clearExistingCaps G_GNUC_UNUSED)
{
    return virSetUIDGID(uid, gid, groups, ngroups);
}
#endif


void virWaitForDevices(void)
{
    g_autoptr(virCommand) cmd = NULL;
    g_autofree char *udev = NULL;
    int exitstatus;

    if (!(udev = virFindFileInPath(UDEVADM)))
        return;

    if (!(cmd = virCommandNewArgList(udev, "settle", NULL)))
        return;

    /*
     * NOTE: we ignore errors here; this is just to make sure that any device
     * nodes that are being created finish before we try to scan them.
     */
    ignore_value(virCommandRun(cmd, &exitstatus));
}

#if WITH_DEVMAPPER
bool
virIsDevMapperDevice(const char *dev_name)
{
    struct stat buf;

    if (!stat(dev_name, &buf) &&
        S_ISBLK(buf.st_mode) &&
        dm_is_dm_major(major(buf.st_rdev)))
            return true;

    return false;
}
#else
bool virIsDevMapperDevice(const char *dev_name G_GNUC_UNUSED)
{
    return false;
}
#endif

bool
virValidateWWN(const char *wwn)
{
    size_t i;
    const char *p = wwn;

    if (STRPREFIX(wwn, "0x"))
        p += 2;

    for (i = 0; p[i]; i++) {
        if (!c_isxdigit(p[i]))
            break;
    }

    if (i != 16 || p[i]) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Malformed wwn: %s"), wwn);
        return false;
    }

    return true;
}

#if defined(major) && defined(minor)
int
virGetDeviceID(const char *path, int *maj, int *min)
{
    struct stat sb;

    if (stat(path, &sb) < 0)
        return -errno;

    if (!S_ISBLK(sb.st_mode))
        return -EINVAL;

    if (maj)
        *maj = major(sb.st_rdev);
    if (min)
        *min = minor(sb.st_rdev);

    return 0;
}
#else
int
virGetDeviceID(const char *path G_GNUC_UNUSED,
               int *maj G_GNUC_UNUSED,
               int *min G_GNUC_UNUSED)
{
    return -ENOSYS;
}
#endif

#define SYSFS_DEV_BLOCK_PATH "/sys/dev/block"

char *
virGetUnprivSGIOSysfsPath(const char *path,
                          const char *sysfs_dir)
{
    int maj, min;
    char *sysfs_path = NULL;
    int rc;

    if ((rc = virGetDeviceID(path, &maj, &min)) < 0) {
        virReportSystemError(-rc,
                             _("Unable to get device ID '%s'"),
                             path);
        return NULL;
    }

    ignore_value(virAsprintf(&sysfs_path, "%s/%d:%d/queue/unpriv_sgio",
                             sysfs_dir ? sysfs_dir : SYSFS_DEV_BLOCK_PATH,
                             maj, min));
    return sysfs_path;
}

int
virSetDeviceUnprivSGIO(const char *path,
                       const char *sysfs_dir,
                       int unpriv_sgio)
{
    char *sysfs_path = NULL;
    char *val = NULL;
    int ret = -1;
    int rc;

    if (!(sysfs_path = virGetUnprivSGIOSysfsPath(path, sysfs_dir)))
        return -1;

    if (!virFileExists(sysfs_path)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("unpriv_sgio is not supported by this kernel"));
        goto cleanup;
    }

    if (virAsprintf(&val, "%d", unpriv_sgio) < 0)
        goto cleanup;

    if ((rc = virFileWriteStr(sysfs_path, val, 0)) < 0) {
        virReportSystemError(-rc, _("failed to set %s"), sysfs_path);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FREE(sysfs_path);
    VIR_FREE(val);
    return ret;
}

int
virGetDeviceUnprivSGIO(const char *path,
                       const char *sysfs_dir,
                       int *unpriv_sgio)
{
    char *sysfs_path = NULL;
    char *buf = NULL;
    char *tmp = NULL;
    int ret = -1;

    if (!(sysfs_path = virGetUnprivSGIOSysfsPath(path, sysfs_dir)))
        return -1;

    if (!virFileExists(sysfs_path)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("unpriv_sgio is not supported by this kernel"));
        goto cleanup;
    }

    if (virFileReadAll(sysfs_path, 1024, &buf) < 0)
        goto cleanup;

    if ((tmp = strchr(buf, '\n')))
        *tmp = '\0';

    if (virStrToLong_i(buf, NULL, 10, unpriv_sgio) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to parse value of %s"), sysfs_path);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FREE(sysfs_path);
    VIR_FREE(buf);
    return ret;
}


/**
 * virParseOwnershipIds:
 *
 * Parse the usual "uid:gid" ownership specification into uid_t and
 * gid_t passed as parameters.  NULL value for those parameters mean
 * the information is not needed.  Also, none of those values are
 * changed in case of any error.
 *
 * Returns -1 on error, 0 otherwise.
 */
int
virParseOwnershipIds(const char *label, uid_t *uidPtr, gid_t *gidPtr)
{
    int rc = -1;
    uid_t theuid;
    gid_t thegid;
    char *tmp_label = NULL;
    char *sep = NULL;
    char *owner = NULL;
    char *group = NULL;

    if (VIR_STRDUP(tmp_label, label) < 0)
        goto cleanup;

    /* Split label */
    sep = strchr(tmp_label, ':');
    if (sep == NULL) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Failed to parse uid and gid from '%s'"),
                       label);
        goto cleanup;
    }
    *sep = '\0';
    owner = tmp_label;
    group = sep + 1;

    /* Parse owner and group, error message is defined by
     * virGetUserID or virGetGroupID.
     */
    if (virGetUserID(owner, &theuid) < 0 ||
        virGetGroupID(group, &thegid) < 0)
        goto cleanup;

    if (uidPtr)
        *uidPtr = theuid;
    if (gidPtr)
        *gidPtr = thegid;

    rc = 0;

 cleanup:
    VIR_FREE(tmp_label);

    return rc;
}

static time_t selfLastChanged;

time_t virGetSelfLastChanged(void)
{
    return selfLastChanged;
}


void virUpdateSelfLastChanged(const char *path)
{
    struct stat sb;

    if (stat(path, &sb) < 0)
        return;

    if (sb.st_ctime > selfLastChanged) {
        VIR_DEBUG("Setting self last changed to %lld for '%s'",
                  (long long)sb.st_ctime, path);
        selfLastChanged = sb.st_ctime;
    }
}


#ifndef WIN32
long virGetSystemPageSize(void)
{
    return sysconf(_SC_PAGESIZE);
}
#else /* WIN32 */
long virGetSystemPageSize(void)
{
    errno = ENOSYS;
    return -1;
}
#endif /* WIN32 */

long virGetSystemPageSizeKB(void)
{
    long val = virGetSystemPageSize();
    if (val < 0)
        return val;
    return val / 1024;
}

/**
 * virMemoryLimitTruncate
 *
 * Return truncated memory limit to VIR_DOMAIN_MEMORY_PARAM_UNLIMITED as maximum
 * which means that the limit is not set => unlimited.
 */
unsigned long long
virMemoryLimitTruncate(unsigned long long value)
{
    return value < VIR_DOMAIN_MEMORY_PARAM_UNLIMITED ? value :
        VIR_DOMAIN_MEMORY_PARAM_UNLIMITED;
}

/**
 * virMemoryLimitIsSet
 *
 * Returns true if the limit is set and false for unlimited value.
 */
bool
virMemoryLimitIsSet(unsigned long long value)
{
    return value < VIR_DOMAIN_MEMORY_PARAM_UNLIMITED;
}


/**
 * virMemoryMaxValue
 *
 * @capped: whether the value must fit into unsigned long
 *   (long long is assumed otherwise)
 *
 * Note: This function is mocked in tests/qemuxml2argvmock.c for test stability
 *
 * Returns the maximum possible memory value in bytes.
 */
unsigned long long
virMemoryMaxValue(bool capped)
{
    /* On 32-bit machines, our bound is 0xffffffff * KiB. On 64-bit
     * machines, our bound is off_t (2^63).  */
    if (capped && sizeof(unsigned long) < sizeof(long long))
        return 1024ull * ULONG_MAX;
    else
        return LLONG_MAX;
}


bool
virHostHasIOMMU(void)
{
    DIR *iommuDir = NULL;
    struct dirent *iommuGroup = NULL;
    bool ret = false;
    int direrr;

    if (virDirOpenQuiet(&iommuDir, "/sys/kernel/iommu_groups/") < 0)
        goto cleanup;

    while ((direrr = virDirRead(iommuDir, &iommuGroup, NULL)) > 0)
        break;

    if (direrr < 0 || !iommuGroup)
        goto cleanup;

    ret = true;

 cleanup:
    VIR_DIR_CLOSE(iommuDir);
    return ret;
}


/**
 * virHostGetDRMRenderNode:
 *
 * Picks the first DRM render node available. Missing DRI or missing DRM render
 * nodes in the system results in an error.
 *
 * Returns an absolute path to the first render node available or NULL in case
 * of an error with the error being reported.
 * Caller is responsible for freeing the result string.
 *
 */
char *
virHostGetDRMRenderNode(void)
{
    char *ret = NULL;
    DIR *driDir = NULL;
    const char *driPath = "/dev/dri";
    struct dirent *ent = NULL;
    int dirErr = 0;
    bool have_rendernode = false;

    if (virDirOpen(&driDir, driPath) < 0)
        return NULL;

    while ((dirErr = virDirRead(driDir, &ent, driPath)) > 0) {
        if (STRPREFIX(ent->d_name, "renderD")) {
            have_rendernode = true;
            break;
        }
    }

    if (dirErr < 0)
        goto cleanup;

    /* even if /dev/dri exists, there might be no renderDX nodes available */
    if (!have_rendernode) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("No DRM render nodes available"));
        goto cleanup;
    }

    if (virAsprintf(&ret, "%s/%s", driPath, ent->d_name) < 0)
        goto cleanup;

 cleanup:
    VIR_DIR_CLOSE(driDir);
    return ret;
}
