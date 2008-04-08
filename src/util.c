/*
 * utils.c: common, generic utility functions
 *
 * Copyright (C) 2006, 2007, 2008 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 * File created Jul 18, 2007 - Shuveb Hussain <shuveb@binarykarma.com>
 */

#include <config.h>

#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <string.h>
#include <ctype.h>

#ifdef HAVE_PATHS_H
#include <paths.h>
#endif

#include "libvirt/virterror.h"
#include "internal.h"
#include "event.h"
#include "buf.h"
#include "util.h"

#include "util-lib.c"

#ifndef MIN
# define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

#define MAX_ERROR_LEN   1024

#define TOLOWER(Ch) (isupper (Ch) ? tolower (Ch) : (Ch))

#define virLog(msg...) fprintf(stderr, msg)

#ifndef PROXY
static void
ReportError(virConnectPtr conn,
                      virDomainPtr dom,
                      virNetworkPtr net,
                      int code, const char *fmt, ...) {
    va_list args;
    char errorMessage[MAX_ERROR_LEN];

    if (fmt) {
        va_start(args, fmt);
        vsnprintf(errorMessage, MAX_ERROR_LEN-1, fmt, args);
        va_end(args);
    } else {
        errorMessage[0] = '\0';
    }
    __virRaiseError(conn, dom, net, VIR_FROM_NONE, code, VIR_ERR_ERROR,
                    NULL, NULL, NULL, -1, -1, "%s", errorMessage);
}

#ifndef __MINGW32__

static int virSetCloseExec(int fd) {
    int flags;
    if ((flags = fcntl(fd, F_GETFD)) < 0)
        return -1;
    flags |= FD_CLOEXEC;
    if ((fcntl(fd, F_SETFD, flags)) < 0)
        return -1;
    return 0;
}

static int virSetNonBlock(int fd) {
    int flags;
    if ((flags = fcntl(fd, F_GETFL)) < 0)
        return -1;
    flags |= O_NONBLOCK;
    if ((fcntl(fd, F_SETFL, flags)) < 0)
        return -1;
    return 0;
}

static int
_virExec(virConnectPtr conn,
          char **argv,
          int *retpid, int infd, int *outfd, int *errfd, int non_block) {
    int pid, null;
    int pipeout[2] = {-1,-1};
    int pipeerr[2] = {-1,-1};

    if ((null = open(_PATH_DEVNULL, O_RDONLY)) < 0) {
        ReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                    _("cannot open %s: %s"),
                    _PATH_DEVNULL, strerror(errno));
        goto cleanup;
    }

    if ((outfd != NULL && pipe(pipeout) < 0) ||
        (errfd != NULL && pipe(pipeerr) < 0)) {
        ReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                    _("cannot create pipe: %s"), strerror(errno));
        goto cleanup;
    }

    if ((pid = fork()) < 0) {
        ReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                    _("cannot fork child process: %s"), strerror(errno));
        goto cleanup;
    }

    if (pid) { /* parent */
        close(null);
        if (outfd) {
            close(pipeout[1]);
            if(non_block)
                if(virSetNonBlock(pipeout[0]) == -1)
                    ReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                        _("Failed to set non-blocking file descriptor flag"));

            if(virSetCloseExec(pipeout[0]) == -1)
                ReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                        _("Failed to set close-on-exec file descriptor flag"));
            *outfd = pipeout[0];
        }
        if (errfd) {
            close(pipeerr[1]);
            if(non_block)
                if(virSetNonBlock(pipeerr[0]) == -1)
                    ReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                          _("Failed to set non-blocking file descriptor flag"));

            if(virSetCloseExec(pipeerr[0]) == -1)
                ReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                        _("Failed to set close-on-exec file descriptor flag"));
            *errfd = pipeerr[0];
        }
        *retpid = pid;
        return 0;
    }

    /* child */

    if (pipeout[0] > 0 && close(pipeout[0]) < 0)
        _exit(1);
    if (pipeerr[0] > 0 && close(pipeerr[0]) < 0)
        _exit(1);

    if (dup2(infd >= 0 ? infd : null, STDIN_FILENO) < 0)
        _exit(1);
#ifndef ENABLE_DEBUG
    if (dup2(pipeout[1] > 0 ? pipeout[1] : null, STDOUT_FILENO) < 0)
        _exit(1);
    if (dup2(pipeerr[1] > 0 ? pipeerr[1] : null, STDERR_FILENO) < 0)
        _exit(1);
#else /* ENABLE_DEBUG */
    if (pipeout[1] > 0 && dup2(pipeout[1], STDOUT_FILENO) < 0)
        _exit(1);
    if (pipeerr[1] > 0 && dup2(pipeerr[1], STDERR_FILENO) < 0)
        _exit(1);
#endif /* ENABLE_DEBUG */

    close(null);
    if (pipeout[1] > 0)
        close(pipeout[1]);
    if (pipeerr[1] > 0)
        close(pipeerr[1]);

    execvp(argv[0], argv);

    _exit(1);

    return 0;

 cleanup:
    if (pipeerr[0] > 0)
        close(pipeerr[0]);
    if (pipeerr[1] > 0)
        close(pipeerr[1]);
    if (pipeout[0] > 0)
        close(pipeout[0]);
    if (pipeout[1] > 0)
        close(pipeout[1]);
    if (null > 0)
        close(null);
    return -1;
}

int
virExec(virConnectPtr conn,
          char **argv,
          int *retpid, int infd, int *outfd, int *errfd) {

    return(_virExec(conn, argv, retpid, infd, outfd, errfd, 0));
}

int
virExecNonBlock(virConnectPtr conn,
          char **argv,
          int *retpid, int infd, int *outfd, int *errfd) {

    return(_virExec(conn, argv, retpid, infd, outfd, errfd, 1));
}

/**
 * @conn connection to report errors against
 * @argv NULL terminated argv to run
 * @status optional variable to return exit status in
 *
 * Run a command without using the shell.
 *
 * If status is NULL, then return 0 if the command run and
 * exited with 0 status; Otherwise return -1
 *
 * If status is not-NULL, then return 0 if the command ran.
 * The status variable is filled with the command exit status
 * and should be checked by caller for success. Return -1
 * only if the command could not be run.
 */
int
virRun(virConnectPtr conn,
       char **argv,
       int *status) {
    int childpid, exitstatus, ret;

    if ((ret = virExec(conn, argv, &childpid, -1, NULL, NULL)) < 0)
        return ret;

    while ((ret = waitpid(childpid, &exitstatus, 0) == -1) && errno == EINTR);
    if (ret == -1)
        return -1;

    if (status == NULL) {
        errno = EINVAL;
        return (WIFEXITED(exitstatus) && WEXITSTATUS(exitstatus) == 0) ? 0 : -1;
    } else {
        *status = exitstatus;
        return 0;
    }
}

#else /* __MINGW32__ */

int
virExec(virConnectPtr conn,
        char **argv ATTRIBUTE_UNUSED,
        int *retpid ATTRIBUTE_UNUSED,
        int infd ATTRIBUTE_UNUSED,
        int *outfd ATTRIBUTE_UNUSED,
        int *errfd ATTRIBUTE_UNUSED)
{
    ReportError (conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR, __FUNCTION__);
    return -1;
}

int
virExecNonBlock(virConnectPtr conn,
                char **argv ATTRIBUTE_UNUSED,
                int *retpid ATTRIBUTE_UNUSED,
                int infd ATTRIBUTE_UNUSED,
                int *outfd ATTRIBUTE_UNUSED,
                int *errfd ATTRIBUTE_UNUSED)
{
    ReportError (conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR, __FUNCTION__);
    return -1;
}

#endif /* __MINGW32__ */

/* Like gnulib's fread_file, but read no more than the specified maximum
   number of bytes.  If the length of the input is <= max_len, and
   upon error while reading that data, it works just like fread_file.  */
static char *
fread_file_lim (FILE *stream, size_t max_len, size_t *length)
{
    char *buf = NULL;
    size_t alloc = 0;
    size_t size = 0;
    int save_errno;

    for (;;) {
        size_t count;
        size_t requested;

        if (size + BUFSIZ + 1 > alloc) {
            char *new_buf;

            alloc += alloc / 2;
            if (alloc < size + BUFSIZ + 1)
                alloc = size + BUFSIZ + 1;

            new_buf = realloc (buf, alloc);
            if (!new_buf) {
                save_errno = errno;
                break;
            }

            buf = new_buf;
        }

        /* Ensure that (size + requested <= max_len); */
        requested = MIN (size < max_len ? max_len - size : 0,
                         alloc - size - 1);
        count = fread (buf + size, 1, requested, stream);
        size += count;

        if (count != requested || requested == 0) {
            save_errno = errno;
            if (ferror (stream))
                break;
            buf[size] = '\0';
            *length = size;
            return buf;
        }
    }

    free (buf);
    errno = save_errno;
    return NULL;
}

int __virFileReadAll(const char *path, int maxlen, char **buf)
{
    FILE *fh;
    int ret = -1;
    size_t len;
    char *s;

    if (!(fh = fopen(path, "r"))) {
        virLog("Failed to open file '%s': %s",
               path, strerror(errno));
        goto error;
    }

    s = fread_file_lim(fh, maxlen+1, &len);
    if (s == NULL) {
        virLog("Failed to read '%s': %s", path, strerror (errno));
        goto error;
    }

    if (len > maxlen || (int)len != len) {
        free(s);
        virLog("File '%s' is too large %d, max %d",
               path, (int)len, maxlen);
        goto error;
    }

    *buf = s;
    ret = len;

 error:
    if (fh)
        fclose(fh);

    return ret;
}

int virFileMatchesNameSuffix(const char *file,
                             const char *name,
                             const char *suffix)
{
    int filelen = strlen(file);
    int namelen = strlen(name);
    int suffixlen = strlen(suffix);

    if (filelen == (namelen + suffixlen) &&
        !strncmp(file, name, namelen) &&
        !strncmp(file + namelen, suffix, suffixlen))
        return 1;
    else
        return 0;
}

int virFileHasSuffix(const char *str,
                     const char *suffix)
{
    int len = strlen(str);
    int suffixlen = strlen(suffix);

    if (len < suffixlen)
        return 0;

    return strcmp(str + len - suffixlen, suffix) == 0;
}

#ifndef __MINGW32__

int virFileLinkPointsTo(const char *checkLink,
                        const char *checkDest)
{
    char dest[PATH_MAX];
    char real[PATH_MAX];
    char checkReal[PATH_MAX];
    int n;

    /* read the link destination */
    if ((n = readlink(checkLink, dest, PATH_MAX)) < 0) {
        switch (errno) {
        case ENOENT:
        case ENOTDIR:
            return 0;

        case EINVAL:
            virLog("File '%s' is not a symlink",
                   checkLink);
            return 0;

        }
        virLog("Failed to read symlink '%s': %s",
               checkLink, strerror(errno));
        return 0;
    } else if (n >= PATH_MAX) {
        virLog("Symlink '%s' contents too long to fit in buffer",
               checkLink);
        return 0;
    }

    dest[n] = '\0';

    /* make absolute */
    if (dest[0] != '/') {
        char dir[PATH_MAX];
        char tmp[PATH_MAX];
        char *p;

        strncpy(dir, checkLink, PATH_MAX);
        dir[PATH_MAX-1] = '\0';

        if (!(p = strrchr(dir, '/'))) {
            virLog("Symlink path '%s' is not absolute", checkLink);
            return 0;
        }

        if (p == dir) /* handle unlikely root dir case */
            p++;

        *p = '\0';

        if (virFileBuildPath(dir, dest, NULL, tmp, PATH_MAX) < 0) {
            virLog("Path '%s/%s' is too long", dir, dest);
            return 0;
        }

        strncpy(dest, tmp, PATH_MAX);
        dest[PATH_MAX-1] = '\0';
    }

    /* canonicalize both paths */
    if (!realpath(dest, real)) {
        virLog("Failed to expand path '%s' :%s", dest, strerror(errno));
        strncpy(real, dest, PATH_MAX);
        real[PATH_MAX-1] = '\0';
    }

    if (!realpath(checkDest, checkReal)) {
        virLog("Failed to expand path '%s' :%s", checkDest, strerror(errno));
        strncpy(checkReal, checkDest, PATH_MAX);
        checkReal[PATH_MAX-1] = '\0';
    }

    /* compare */
    if (strcmp(checkReal, real) != 0) {
        virLog("Link '%s' does not point to '%s', ignoring",
               checkLink, checkReal);
        return 0;
    }

    return 1;
}

#else /* !__MINGW32__ */

/* Gnulib has an implementation of readlink which could be used
 * to implement this, but it requires LGPLv3.
 */

int
virFileLinkPointsTo (const char *checkLink ATTRIBUTE_UNUSED,
                     const char *checkDest ATTRIBUTE_UNUSED)
{
    virLog (_("%s: not implemented"), __FUNCTION__);
    return 0;
}

#endif /*! __MINGW32__ */

int virFileExists(const char *path)
{
    struct stat st;

    if (stat(path, &st) >= 0)
        return(1);
    return(0);
}

int virFileMakePath(const char *path)
{
    struct stat st;
    char parent[PATH_MAX];
    char *p;
    int err;

    if (stat(path, &st) >= 0)
        return 0;

    strncpy(parent, path, PATH_MAX);
    parent[PATH_MAX - 1] = '\0';

    if (!(p = strrchr(parent, '/')))
        return EINVAL;

    if (p == parent)
        return EPERM;

    *p = '\0';

    if ((err = virFileMakePath(parent)))
        return err;

    if (mkdir(path, 0777) < 0 && errno != EEXIST)
        return errno;

    return 0;
}

/* Build up a fully qualfiied path for a config file to be
 * associated with a persistent guest or network */
int virFileBuildPath(const char *dir,
                     const char *name,
                     const char *ext,
                     char *buf,
                     unsigned int buflen)
{
    if ((strlen(dir) + 1 + strlen(name) + (ext ? strlen(ext) : 0) + 1) >= (buflen-1))
        return -1;

    strcpy(buf, dir);
    strcat(buf, "/");
    strcat(buf, name);
    if (ext)
        strcat(buf, ext);
    return 0;
}

/* Like strtol, but produce an "int" result, and check more carefully.
   Return 0 upon success;  return -1 to indicate failure.
   When END_PTR is NULL, the byte after the final valid digit must be NUL.
   Otherwise, it's like strtol and lets the caller check any suffix for
   validity.  This function is careful to return -1 when the string S
   represents a number that is not representable as an "int". */
int
__virStrToLong_i(char const *s, char **end_ptr, int base, int *result)
{
    long int val;
    char *p;
    int err;

    errno = 0;
    val = strtol(s, &p, base);
    err = (errno || (!end_ptr && *p) || p == s || (int) val != val);
    if (end_ptr)
        *end_ptr = p;
    if (err)
        return -1;
    *result = val;
    return 0;
}

/* Just like virStrToLong_i, above, but produce an "unsigned int" value.  */
int
virStrToLong_ui(char const *s, char **end_ptr, int base, unsigned int *result)
{
    unsigned long int val;
    char *p;
    int err;

    errno = 0;
    val = strtoul(s, &p, base);
    err = (errno || (!end_ptr && *p) || p == s || (unsigned int) val != val);
    if (end_ptr)
        *end_ptr = p;
    if (err)
        return -1;
    *result = val;
    return 0;
}

/* Just like virStrToLong_i, above, but produce an "long long" value.  */
int
virStrToLong_ll(char const *s, char **end_ptr, int base, long long *result)
{
    long long val;
    char *p;
    int err;

    errno = 0;
    val = strtoll(s, &p, base);
    err = (errno || (!end_ptr && *p) || p == s || (long long) val != val);
    if (end_ptr)
        *end_ptr = p;
    if (err)
        return -1;
    *result = val;
    return 0;
}

/* Just like virStrToLong_i, above, but produce an "unsigned long long" value.  */
int
__virStrToLong_ull(char const *s, char **end_ptr, int base, unsigned long long *result)
{
    unsigned long long val;
    char *p;
    int err;

    errno = 0;
    val = strtoull(s, &p, base);
    err = (errno || (!end_ptr && *p) || p == s || (unsigned long long) val != val);
    if (end_ptr)
        *end_ptr = p;
    if (err)
        return -1;
    *result = val;
    return 0;
}
#endif /* PROXY */

/**
 * virSkipSpaces:
 * @str: pointer to the char pointer used
 *
 * Skip potential blanks, this includes space tabs, line feed,
 * carriage returns and also '\\' which can be erronously emitted
 * by xend
 */
void
virSkipSpaces(const char **str)
{
    const char *cur = *str;

    while ((*cur == ' ') || (*cur == '\t') || (*cur == '\n') ||
           (*cur == '\r') || (*cur == '\\'))
        cur++;
    *str = cur;
}

/**
 * virParseNumber:
 * @str: pointer to the char pointer used
 *
 * Parse an unsigned number
 *
 * Returns the unsigned number or -1 in case of error. @str will be
 *         updated to skip the number.
 */
int
virParseNumber(const char **str)
{
    int ret = 0;
    const char *cur = *str;

    if ((*cur < '0') || (*cur > '9'))
        return (-1);

    while ((*cur >= '0') && (*cur <= '9')) {
        unsigned int c = *cur - '0';

        if ((ret > INT_MAX / 10) ||
            ((ret == INT_MAX / 10) && (c > INT_MAX % 10)))
            return (-1);
        ret = ret * 10 + c;
        cur++;
    }
    *str = cur;
    return (ret);
}

/* Compare two MAC addresses, ignoring differences in case,
 * as well as leading zeros.
 */
int
__virMacAddrCompare (const char *p, const char *q)
{
    unsigned char c, d;
    do {
        while (*p == '0' && isxdigit (p[1]))
            ++p;
        while (*q == '0' && isxdigit (q[1]))
            ++q;
        c = TOLOWER (*p);
        d = TOLOWER (*q);

        if (c == 0 || d == 0)
            break;

        ++p;
        ++q;
    } while (c == d);

    if (UCHAR_MAX <= INT_MAX)
        return c - d;

    /* On machines where 'char' and 'int' are types of the same size, the
       difference of two 'unsigned char' values - including the sign bit -
       doesn't fit in an 'int'.  */
    return (c > d ? 1 : c < d ? -1 : 0);
}

/**
 * virParseMacAddr:
 * @str: string representation of MAC address, e.g., "0:1E:FC:E:3a:CB"
 * @addr: 6-byte MAC address
 *
 * Parse a MAC address
 *
 * Return 0 upon success, or -1 in case of error.
 */
int
virParseMacAddr(const char* str, unsigned char *addr)
{
    int i;

    errno = 0;
    for (i = 0; i < 6; i++) {
        char *end_ptr;
        unsigned long result;

        /* This is solely to avoid accepting the leading
         * space or "+" that strtoul would otherwise accept.
         */
        if (!isxdigit(*str))
            break;

        result = strtoul(str, &end_ptr, 16);

        if ((end_ptr - str) < 1 || 2 < (end_ptr - str) ||
            (errno != 0) ||
            (0xFF < result))
            break;

        addr[i] = (unsigned char) result;

	if ((i == 5) && (*end_ptr == '\0'))
	    return 0;
	if (*end_ptr != ':')
	    break;

        str = end_ptr + 1;
    }

    return -1;
}

/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 * End:
 */
