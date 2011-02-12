/*
 * xend_internal.c: access to Xen though the Xen Daemon interface
 *
 * Copyright (C) 2010-2011 Red Hat, Inc.
 * Copyright (C) 2005 Anthony Liguori <aliguori@us.ibm.com>
 *
 *  This file is subject to the terms and conditions of the GNU Lesser General
 *  Public License. See the file COPYING.LIB in the main directory of this
 *  archive for more details.
 */

#include <config.h>

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <math.h>
#include <stdarg.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <libxml/uri.h>
#include <errno.h>

#include "virterror_internal.h"
#include "logging.h"
#include "datatypes.h"
#include "xend_internal.h"
#include "driver.h"
#include "util.h"
#include "sexpr.h"
#include "buf.h"
#include "uuid.h"
#include "xen_driver.h"
#include "xen_hypervisor.h"
#include "xs_internal.h" /* To extract VNC port & Serial console TTY */
#include "memory.h"
#include "count-one-bits.h"
#include "files.h"

/* required for cpumap_t */
#include <xen/dom0_ops.h>

#define VIR_FROM_THIS VIR_FROM_XEND

/*
 * The number of Xen scheduler parameters
 */
#define XEN_SCHED_SEDF_NPARAM   6
#define XEN_SCHED_CRED_NPARAM   2

#ifdef WITH_RHEL5_API
# define XEND_CONFIG_MAX_VERS_NET_TYPE_IOEMU 0
# define XEND_CONFIG_MIN_VERS_PVFB_NEWCONF 2
#else
# define XEND_CONFIG_MAX_VERS_NET_TYPE_IOEMU 3
# define XEND_CONFIG_MIN_VERS_PVFB_NEWCONF 3
#endif

#define XEND_RCV_BUF_MAX_LEN 65536

static int
xenDaemonFormatSxprDisk(virConnectPtr conn ATTRIBUTE_UNUSED,
                        virDomainDiskDefPtr def,
                        virBufferPtr buf,
                        int hvm,
                        int xendConfigVersion,
                        int isAttach);
static int
xenDaemonFormatSxprNet(virConnectPtr conn ATTRIBUTE_UNUSED,
                       virDomainNetDefPtr def,
                       virBufferPtr buf,
                       int hvm,
                       int xendConfigVersion,
                       int isAttach);
static int
xenDaemonFormatSxprOnePCI(virDomainHostdevDefPtr def,
                          virBufferPtr buf,
                          int detach);

static int
virDomainXMLDevID(virDomainPtr domain,
                  virDomainDeviceDefPtr dev,
                  char *class,
                  char *ref,
                  int ref_len);

#define virXendError(code, ...)                                            \
        virReportErrorHelper(NULL, VIR_FROM_XEND, code, __FILE__,          \
                             __FUNCTION__, __LINE__, __VA_ARGS__)

#define virXendErrorInt(code, ival)                                        \
        virXendError(code, "%d", ival)

/**
 * do_connect:
 * @xend: pointer to the Xen Daemon structure
 *
 * Internal routine to (re)connect to the daemon
 *
 * Returns the socket file descriptor or -1 in case of error
 */
static int
do_connect(virConnectPtr xend)
{
    int s;
    int no_slow_start = 1;
    xenUnifiedPrivatePtr priv = (xenUnifiedPrivatePtr) xend->privateData;

    s = socket(priv->addrfamily, SOCK_STREAM, priv->addrprotocol);
    if (s == -1) {
        virXendError(VIR_ERR_INTERNAL_ERROR,
                     "%s", _("failed to create a socket"));
        return -1;
    }

    /*
     * try to desactivate slow-start
     */
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (void *)&no_slow_start,
               sizeof(no_slow_start));


    if (connect(s, (struct sockaddr *)&priv->addr, priv->addrlen) == -1) {
        VIR_FORCE_CLOSE(s); /* preserves errno */

        /*
         * Connecting to XenD when privileged is mandatory, so log this
         * error
         */
        if (xenHavePrivilege()) {
            virXendError(VIR_ERR_INTERNAL_ERROR,
                         "%s", _("failed to connect to xend"));
        }
    }

    return s;
}

/**
 * wr_sync:
 * @xend: the xend connection object
 * @fd:  the file descriptor
 * @buffer: the I/O buffer
 * @size: the size of the I/O
 * @do_read: write operation if 0, read operation otherwise
 *
 * Do a synchronous read or write on the file descriptor
 *
 * Returns the number of bytes exchanged, or -1 in case of error
 */
static size_t
wr_sync(int fd, void *buffer, size_t size, int do_read)
{
    size_t offset = 0;

    while (offset < size) {
        ssize_t len;

        if (do_read) {
            len = read(fd, ((char *) buffer) + offset, size - offset);
        } else {
            len = write(fd, ((char *) buffer) + offset, size - offset);
        }

        /* recoverable error, retry  */
        if ((len == -1) && ((errno == EAGAIN) || (errno == EINTR))) {
            continue;
        }

        /* eof */
        if (len == 0) {
            break;
        }

        /* unrecoverable error */
        if (len == -1) {
            if (do_read)
                virXendError(VIR_ERR_INTERNAL_ERROR,
                             "%s", _("failed to read from Xen Daemon"));
            else
                virXendError(VIR_ERR_INTERNAL_ERROR,
                             "%s", _("failed to write to Xen Daemon"));

            return (-1);
        }

        offset += len;
    }

    return offset;
}

/**
 * sread:
 * @fd:  the file descriptor
 * @buffer: the I/O buffer
 * @size: the size of the I/O
 *
 * Internal routine to do a synchronous read
 *
 * Returns the number of bytes read, or -1 in case of error
 */
static ssize_t
sread(int fd, void *buffer, size_t size)
{
    return wr_sync(fd, buffer, size, 1);
}

/**
 * swrite:
 * @fd:  the file descriptor
 * @buffer: the I/O buffer
 * @size: the size of the I/O
 *
 * Internal routine to do a synchronous write
 *
 * Returns the number of bytes written, or -1 in case of error
 */
static ssize_t
swrite(int fd, const void *buffer, size_t size)
{
    return wr_sync(fd, (void *) buffer, size, 0);
}

/**
 * swrites:
 * @fd:  the file descriptor
 * @string: the string to write
 *
 * Internal routine to do a synchronous write of a string
 *
 * Returns the number of bytes written, or -1 in case of error
 */
static ssize_t
swrites(int fd, const char *string)
{
    return swrite(fd, string, strlen(string));
}

/**
 * sreads:
 * @fd:  the file descriptor
 * @buffer: the I/O buffer
 * @n_buffer: the size of the I/O buffer
 *
 * Internal routine to do a synchronous read of a line
 *
 * Returns the number of bytes read, or -1 in case of error
 */
static ssize_t
sreads(int fd, char *buffer, size_t n_buffer)
{
    size_t offset;

    if (n_buffer < 1)
        return (-1);

    for (offset = 0; offset < (n_buffer - 1); offset++) {
        ssize_t ret;

        ret = sread(fd, buffer + offset, 1);
        if (ret == 0)
            break;
        else if (ret == -1)
            return ret;

        if (buffer[offset] == '\n') {
            offset++;
            break;
        }
    }
    buffer[offset] = 0;

    return offset;
}

static int
istartswith(const char *haystack, const char *needle)
{
    return STRCASEEQLEN(haystack, needle, strlen(needle));
}


/**
 * xend_req:
 * @fd: the file descriptor
 * @content: the buffer to store the content
 *
 * Read the HTTP response from a Xen Daemon request.
 * If the response contains content, memory is allocated to
 * hold the content.
 *
 * Returns the HTTP return code and @content is set to the
 * allocated memory containing HTTP content.
 */
static int ATTRIBUTE_NONNULL (2)
xend_req(int fd, char **content)
{
    char buffer[4096];
    int content_length = 0;
    int retcode = 0;

    while (sreads(fd, buffer, sizeof(buffer)) > 0) {
        if (STREQ(buffer, "\r\n"))
            break;

        if (istartswith(buffer, "Content-Length: "))
            content_length = atoi(buffer + 16);
        else if (istartswith(buffer, "HTTP/1.1 "))
            retcode = atoi(buffer + 9);
    }

    if (content_length > 0) {
        ssize_t ret;

        if (content_length > XEND_RCV_BUF_MAX_LEN) {
            virXendError(VIR_ERR_INTERNAL_ERROR,
                         _("Xend returned HTTP Content-Length of %d, "
                           "which exceeds maximum of %d"),
                         content_length,
                         XEND_RCV_BUF_MAX_LEN);
            return -1;
        }

        /* Allocate one byte beyond the end of the largest buffer we will read.
           Combined with the fact that VIR_ALLOC_N zeros the returned buffer,
           this guarantees that "content" will always be NUL-terminated. */
        if (VIR_ALLOC_N(*content, content_length + 1) < 0 ) {
            virReportOOMError();
            return -1;
        }

        ret = sread(fd, *content, content_length);
        if (ret < 0)
            return -1;
    }

    return retcode;
}

/**
 * xend_get:
 * @xend: pointer to the Xen Daemon structure
 * @path: the path used for the HTTP request
 * @content: the buffer to store the content
 *
 * Do an HTTP GET RPC with the Xen Daemon
 *
 * Returns the HTTP return code or -1 in case or error.
 */
static int ATTRIBUTE_NONNULL(3)
xend_get(virConnectPtr xend, const char *path,
         char **content)
{
    int ret;
    int s = do_connect(xend);

    if (s == -1)
        return s;

    swrites(s, "GET ");
    swrites(s, path);
    swrites(s, " HTTP/1.1\r\n");

    swrites(s,
            "Host: localhost:8000\r\n"
            "Accept-Encoding: identity\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n" "\r\n");

    ret = xend_req(s, content);
    VIR_FORCE_CLOSE(s);

    if (((ret < 0) || (ret >= 300)) &&
        ((ret != 404) || (!STRPREFIX(path, "/xend/domain/")))) {
        virXendError(VIR_ERR_GET_FAILED,
                     _("%d status from xen daemon: %s:%s"),
                     ret, path, NULLSTR(*content));
    }

    return ret;
}

/**
 * xend_post:
 * @xend: pointer to the Xen Daemon structure
 * @path: the path used for the HTTP request
 * @ops: the information sent for the POST
 *
 * Do an HTTP POST RPC with the Xen Daemon, this usually makes changes at the
 * Xen level.
 *
 * Returns the HTTP return code or -1 in case or error.
 */
static int
xend_post(virConnectPtr xend, const char *path, const char *ops)
{
    char buffer[100];
    char *err_buf = NULL;
    int ret;
    int s = do_connect(xend);

    if (s == -1)
        return s;

    swrites(s, "POST ");
    swrites(s, path);
    swrites(s, " HTTP/1.1\r\n");

    swrites(s,
            "Host: localhost:8000\r\n"
            "Accept-Encoding: identity\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: ");
    snprintf(buffer, sizeof(buffer), "%d", (int) strlen(ops));
    swrites(s, buffer);
    swrites(s, "\r\n\r\n");
    swrites(s, ops);

    ret = xend_req(s, &err_buf);
    VIR_FORCE_CLOSE(s);

    if ((ret < 0) || (ret >= 300)) {
        virXendError(VIR_ERR_POST_FAILED,
                     _("xend_post: error from xen daemon: %s"), err_buf);
    } else if ((ret == 202) && err_buf && (strstr(err_buf, "failed") != NULL)) {
        virXendError(VIR_ERR_POST_FAILED,
                     _("xend_post: error from xen daemon: %s"), err_buf);
        ret = -1;
    } else if (((ret >= 200) && (ret <= 202)) && err_buf &&
               (strstr(err_buf, "xend.err") != NULL)) {
        /* This is to catch case of things like 'virsh dump Domain-0 foo'
         * which returns a success code, but the word 'xend.err'
         * in body to indicate error :-(
         */
        virXendError(VIR_ERR_POST_FAILED,
                     _("xend_post: error from xen daemon: %s"), err_buf);
        ret = -1;
    }

    VIR_FREE(err_buf);
    return ret;
}


/**
 * http2unix:
 * @ret: the http return code
 *
 * Convert the HTTP return code to 0/-1 and set errno if needed
 *
 * Return -1 in case of error code 0 otherwise
 */
static int
http2unix(int ret)
{
    switch (ret) {
        case -1:
            break;
        case 200:
        case 201:
        case 202:
            return 0;
        case 404:
            errno = ESRCH;
            break;
        case 500:
            errno = EIO;
            break;
        default:
            virXendErrorInt(VIR_ERR_HTTP_ERROR, ret);
            errno = EINVAL;
            break;
    }
    return -1;
}

/**
 * xend_op_ext:
 * @xend: pointer to the Xen Daemon structure
 * @path: path for the object
 * @key: the key for the operation
 * @ap: input values to pass to the operation
 *
 * internal routine to run a POST RPC operation to the Xen Daemon
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
static int
xend_op_ext(virConnectPtr xend, const char *path, const char *key, va_list ap)
{
    const char *k = key, *v;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    int ret;
    char *content;

    while (k) {
        v = va_arg(ap, const char *);

        virBufferVSprintf(&buf, "%s", k);
        virBufferVSprintf(&buf, "%s", "=");
        virBufferVSprintf(&buf, "%s", v);
        k = va_arg(ap, const char *);

        if (k)
            virBufferVSprintf(&buf, "%s", "&");
    }

    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        virReportOOMError();
        return -1;
    }

    content = virBufferContentAndReset(&buf);
    DEBUG("xend op: %s\n", content);
    ret = http2unix(xend_post(xend, path, content));
    VIR_FREE(content);

    return ret;
}


/**
 * xend_op:
 * @xend: pointer to the Xen Daemon structure
 * @name: the domain name target of this operation
 * @key: the key for the operation
 * @ap: input values to pass to the operation
 * @...: input values to pass to the operation
 *
 * internal routine to run a POST RPC operation to the Xen Daemon targetting
 * a given domain.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
static int ATTRIBUTE_SENTINEL
xend_op(virConnectPtr xend, const char *name, const char *key, ...)
{
    char buffer[1024];
    va_list ap;
    int ret;

    snprintf(buffer, sizeof(buffer), "/xend/domain/%s", name);

    va_start(ap, key);
    ret = xend_op_ext(xend, buffer, key, ap);
    va_end(ap);

    return ret;
}


/**
 * sexpr_get:
 * @xend: pointer to the Xen Daemon structure
 * @fmt: format string for the path of the operation
 * @...: extra data to build the path of the operation
 *
 * Internal routine to run a simple GET RPC operation to the Xen Daemon
 *
 * Returns a parsed S-Expression in case of success, NULL in case of failure
 */
static struct sexpr *sexpr_get(virConnectPtr xend, const char *fmt, ...)
  ATTRIBUTE_FMT_PRINTF(2,3);

static struct sexpr *
sexpr_get(virConnectPtr xend, const char *fmt, ...)
{
    char *buffer = NULL;
    char path[1024];
    va_list ap;
    int ret;
    struct sexpr *res = NULL;

    va_start(ap, fmt);
    vsnprintf(path, sizeof(path), fmt, ap);
    va_end(ap);

    ret = xend_get(xend, path, &buffer);
    ret = http2unix(ret);
    if (ret == -1)
        goto cleanup;

    if (buffer == NULL)
        goto cleanup;

    res = string2sexpr(buffer);

cleanup:
    VIR_FREE(buffer);
    return res;
}

/**
 * sexpr_int:
 * @sexpr: an S-Expression
 * @name: the name for the value
 *
 * convenience function to lookup an int value in the S-Expression
 *
 * Returns the value found or 0 if not found (but may not be an error).
 * This function suffers from the flaw that zero is both a correct
 * return value and an error indicator: careful!
 */
static int
sexpr_int(const struct sexpr *sexpr, const char *name)
{
    const char *value = sexpr_node(sexpr, name);

    if (value) {
        return strtol(value, NULL, 0);
    }
    return 0;
}


/**
 * sexpr_float:
 * @sexpr: an S-Expression
 * @name: the name for the value
 *
 * convenience function to lookup a float value in the S-Expression
 *
 * Returns the value found or 0 if not found (but may not be an error)
 */
static double
sexpr_float(const struct sexpr *sexpr, const char *name)
{
    const char *value = sexpr_node(sexpr, name);

    if (value) {
        return strtod(value, NULL);
    }
    return 0;
}

/**
 * sexpr_u64:
 * @sexpr: an S-Expression
 * @name: the name for the value
 *
 * convenience function to lookup a 64bits unsigned int value in the
 * S-Expression
 *
 * Returns the value found or 0 if not found (but may not be an error)
 */
static uint64_t
sexpr_u64(const struct sexpr *sexpr, const char *name)
{
    const char *value = sexpr_node(sexpr, name);

    if (value) {
        return strtoll(value, NULL, 0);
    }
    return 0;
}


/**
 * sexpr_uuid:
 * @ptr: where to store the UUID, incremented
 * @sexpr: an S-Expression
 * @name: the name for the value
 *
 * convenience function to lookup an UUID value from the S-Expression
 *
 * Returns a -1 on error, 0 on success
 */
static int
sexpr_uuid(unsigned char *ptr, const struct sexpr *node, const char *path)
{
    const char *r = sexpr_node(node, path);
    if (!r)
        return -1;
    return virUUIDParse(r, ptr);
}


/**
 * urlencode:
 * @string: the input URL
 *
 * Encode an URL see RFC 2396 and following
 *
 * Returns the new string or NULL in case of error.
 */
static char *
urlencode(const char *string)
{
    size_t len = strlen(string);
    char *buffer;
    char *ptr;
    size_t i;

    if (VIR_ALLOC_N(buffer, len * 3 + 1) < 0) {
        virReportOOMError();
        return (NULL);
    }
    ptr = buffer;
    for (i = 0; i < len; i++) {
        switch (string[i]) {
            case ' ':
            case '\n':
            case '&':
                snprintf(ptr, 4, "%%%02x", string[i]);
                ptr += 3;
                break;
            default:
                *ptr = string[i];
                ptr++;
        }
    }

    *ptr = 0;

    return buffer;
}

/* PUBLIC FUNCTIONS */

/**
 * xenDaemonOpen_unix:
 * @conn: an existing virtual connection block
 * @path: the path for the Xen Daemon socket
 *
 * Creates a localhost Xen Daemon connection
 * Note: this doesn't try to check if the connection actually works
 *
 * Returns 0 in case of success, -1 in case of error.
 */
int
xenDaemonOpen_unix(virConnectPtr conn, const char *path)
{
    struct sockaddr_un *addr;
    xenUnifiedPrivatePtr priv;

    if ((conn == NULL) || (path == NULL))
        return (-1);

    priv = (xenUnifiedPrivatePtr) conn->privateData;
    memset(&priv->addr, 0, sizeof(priv->addr));
    priv->addrfamily = AF_UNIX;
    /*
     * This must be zero on Solaris at least for AF_UNIX (which should
     * really be PF_UNIX, but doesn't matter).
     */
    priv->addrprotocol = 0;
    priv->addrlen = sizeof(struct sockaddr_un);

    addr = (struct sockaddr_un *)&priv->addr;
    addr->sun_family = AF_UNIX;
    memset(addr->sun_path, 0, sizeof(addr->sun_path));
    if (virStrcpyStatic(addr->sun_path, path) == NULL)
        return -1;

    return (0);
}


/**
 * xenDaemonOpen_tcp:
 * @conn: an existing virtual connection block
 * @host: the host name for the Xen Daemon
 * @port: the port
 *
 * Creates a possibly remote Xen Daemon connection
 * Note: this doesn't try to check if the connection actually works
 *
 * Returns 0 in case of success, -1 in case of error.
 */
static int
xenDaemonOpen_tcp(virConnectPtr conn, const char *host, const char *port)
{
    xenUnifiedPrivatePtr priv;
    struct addrinfo *res, *r;
    struct addrinfo hints;
    int saved_errno = EINVAL;
    int ret;

    if ((conn == NULL) || (host == NULL) || (port == NULL))
        return (-1);

    priv = (xenUnifiedPrivatePtr) conn->privateData;

    priv->addrlen = 0;
    memset(&priv->addr, 0, sizeof(priv->addr));

    /* http://people.redhat.com/drepper/userapi-ipv6.html */
    memset (&hints, 0, sizeof hints);
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_ADDRCONFIG;

    ret = getaddrinfo (host, port, &hints, &res);
    if (ret != 0) {
        virXendError(VIR_ERR_UNKNOWN_HOST,
                     _("unable to resolve hostname '%s': %s"),
                     host, gai_strerror (ret));
        return -1;
    }

    /* Try to connect to each returned address in turn. */
    for (r = res; r; r = r->ai_next) {
        int sock;

        sock = socket (r->ai_family, SOCK_STREAM, r->ai_protocol);
        if (sock == -1) {
            saved_errno = errno;
            continue;
        }

        if (connect (sock, r->ai_addr, r->ai_addrlen) == -1) {
            saved_errno = errno;
            VIR_FORCE_CLOSE(sock);
            continue;
        }

        priv->addrlen = r->ai_addrlen;
        priv->addrfamily = r->ai_family;
        priv->addrprotocol = r->ai_protocol;
        memcpy(&priv->addr,
               r->ai_addr,
               r->ai_addrlen);
        VIR_FORCE_CLOSE(sock);
        break;
    }

    freeaddrinfo (res);

    if (!priv->addrlen) {
        /* Don't raise error when unprivileged, since proxy takes over */
        if (xenHavePrivilege())
            virReportSystemError(saved_errno,
                                 _("unable to connect to '%s:%s'"),
                                 host, port);
        return -1;
    }

    return 0;
}


/**
 * xend_wait_for_devices:
 * @xend: pointer to the Xen Daemon block
 * @name: name for the domain
 *
 * Block the domain until all the virtual devices are ready. This operation
 * is needed when creating a domain before resuming it.
 *
 * Returns 0 in case of success, -1 (with errno) in case of error.
 */
int
xend_wait_for_devices(virConnectPtr xend, const char *name)
{
    return xend_op(xend, name, "op", "wait_for_devices", NULL);
}


/**
 * xenDaemonListDomainsOld:
 * @xend: pointer to the Xen Daemon block
 *
 * This method will return an array of names of currently running
 * domains.  The memory should be released will a call to free().
 *
 * Returns a list of names or NULL in case of error.
 */
char **
xenDaemonListDomainsOld(virConnectPtr xend)
{
    size_t extra = 0;
    struct sexpr *root = NULL;
    char **ret = NULL;
    int count = 0;
    int i;
    char *ptr;
    struct sexpr *_for_i, *node;

    root = sexpr_get(xend, "/xend/domain");
    if (root == NULL)
        goto error;

    for (_for_i = root, node = root->u.s.car; _for_i->kind == SEXPR_CONS;
         _for_i = _for_i->u.s.cdr, node = _for_i->u.s.car) {
        if (node->kind != SEXPR_VALUE)
            continue;
        extra += strlen(node->u.value) + 1;
        count++;
    }

    /*
     * We can'tuse the normal allocation routines as we are mixing
     * an array of char * at the beginning followed by an array of char
     * ret points to the NULL terminated array of char *
     * ptr points to the current string after that array but in the same
     * allocated block
     */
    if (virAlloc((void *)&ptr,
                 (count + 1) * sizeof(char *) + extra * sizeof(char)) < 0)
        goto error;

    ret = (char **) ptr;
    ptr += sizeof(char *) * (count + 1);

    i = 0;
    for (_for_i = root, node = root->u.s.car; _for_i->kind == SEXPR_CONS;
         _for_i = _for_i->u.s.cdr, node = _for_i->u.s.car) {
        if (node->kind != SEXPR_VALUE)
            continue;
        ret[i] = ptr;
        strcpy(ptr, node->u.value);
        ptr += strlen(node->u.value) + 1;
        i++;
    }

    ret[i] = NULL;

  error:
    sexpr_free(root);
    return ret;
}


/**
 * xenDaemonDomainCreateXML:
 * @xend: A xend instance
 * @sexpr: An S-Expr description of the domain.
 *
 * This method will create a domain based on the passed in description.  The
 * domain will be paused after creation and must be unpaused with
 * xenDaemonResumeDomain() to begin execution.
 * This method may be deprecated once switching to XML-RPC based communcations
 * with xend.
 *
 * Returns 0 for success, -1 (with errno) on error
 */

int
xenDaemonDomainCreateXML(virConnectPtr xend, const char *sexpr)
{
    int ret, serrno;
    char *ptr;

    ptr = urlencode(sexpr);
    if (ptr == NULL) {
        /* this should be caught at the interface but ... */
        virXendError(VIR_ERR_INTERNAL_ERROR,
                     "%s", _("failed to urlencode the create S-Expr"));
        return (-1);
    }

    ret = xend_op(xend, "", "op", "create", "config", ptr, NULL);

    serrno = errno;
    VIR_FREE(ptr);
    errno = serrno;

    return ret;
}


/**
 * xenDaemonDomainLookupByName_ids:
 * @xend: A xend instance
 * @domname: The name of the domain
 * @uuid: return value for the UUID if not NULL
 *
 * This method looks up the id of a domain
 *
 * Returns the id on success; -1 (with errno) on error
 */
int
xenDaemonDomainLookupByName_ids(virConnectPtr xend, const char *domname,
                                unsigned char *uuid)
{
    struct sexpr *root;
    const char *value;
    int ret = -1;

    if (uuid != NULL)
        memset(uuid, 0, VIR_UUID_BUFLEN);
    root = sexpr_get(xend, "/xend/domain/%s?detail=1", domname);
    if (root == NULL)
        goto error;

    value = sexpr_node(root, "domain/domid");
    if (value == NULL) {
        virXendError(VIR_ERR_INTERNAL_ERROR,
                     "%s", _("domain information incomplete, missing domid"));
        goto error;
    }
    ret = strtol(value, NULL, 0);
    if ((ret == 0) && (value[0] != '0')) {
        virXendError(VIR_ERR_INTERNAL_ERROR,
                     "%s", _("domain information incorrect domid not numeric"));
        ret = -1;
    } else if (uuid != NULL) {
        if (sexpr_uuid(uuid, root, "domain/uuid") < 0) {
            virXendError(VIR_ERR_INTERNAL_ERROR,
                         "%s", _("domain information incomplete, missing uuid"));
        }
    }

  error:
    sexpr_free(root);
    return (ret);
}


/**
 * xenDaemonDomainLookupByID:
 * @xend: A xend instance
 * @id: The id of the domain
 * @name: return value for the name if not NULL
 * @uuid: return value for the UUID if not NULL
 *
 * This method looks up the name of a domain based on its id
 *
 * Returns the 0 on success; -1 (with errno) on error
 */
int
xenDaemonDomainLookupByID(virConnectPtr xend,
                          int id,
                          char **domname,
                          unsigned char *uuid)
{
    const char *name = NULL;
    struct sexpr *root;

    memset(uuid, 0, VIR_UUID_BUFLEN);

    root = sexpr_get(xend, "/xend/domain/%d?detail=1", id);
    if (root == NULL)
      goto error;

    name = sexpr_node(root, "domain/name");
    if (name == NULL) {
      virXendError(VIR_ERR_INTERNAL_ERROR,
                   "%s", _("domain information incomplete, missing name"));
      goto error;
    }
    if (domname) {
      *domname = strdup(name);
      if (*domname == NULL) {
          virReportOOMError();
          goto error;
      }
    }

    if (sexpr_uuid(uuid, root, "domain/uuid") < 0) {
      virXendError(VIR_ERR_INTERNAL_ERROR,
                   "%s", _("domain information incomplete, missing uuid"));
      goto error;
    }

    sexpr_free(root);
    return (0);

error:
    sexpr_free(root);
    if (domname)
        VIR_FREE(*domname);
    return (-1);
}


static int
xend_detect_config_version(virConnectPtr conn) {
    struct sexpr *root;
    const char *value;
    xenUnifiedPrivatePtr priv;

    if (!VIR_IS_CONNECT(conn)) {
        virXendError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }

    priv = (xenUnifiedPrivatePtr) conn->privateData;

    root = sexpr_get(conn, "/xend/node/");
    if (root == NULL)
        return (-1);

    value = sexpr_node(root, "node/xend_config_format");

    if (value) {
        priv->xendConfigVersion = strtol(value, NULL, 10);
    }  else {
        /* Xen prior to 3.0.3 did not have the xend_config_format
           field, and is implicitly version 1. */
        priv->xendConfigVersion = 1;
    }
    sexpr_free(root);
    return (0);
}


/*****************************************************************
 ******
 ****** Parsing of SEXPR into virDomainDef objects
 ******
 *****************************************************************/

/**
 * xenDaemonParseSxprOS
 * @node: the root of the parsed S-Expression
 * @def: the domain config
 * @hvm: true or 1 if no contains HVM S-Expression
 * @bootloader: true or 1 if a bootloader is defined
 *
 * Parse the xend sexp for description of os and append it to buf.
 *
 * Returns 0 in case of success and -1 in case of error
 */
static int
xenDaemonParseSxprOS(const struct sexpr *node,
                     virDomainDefPtr def,
                     int hvm)
{
    if (hvm) {
        if (sexpr_node_copy(node, "domain/image/hvm/loader", &def->os.loader) < 0)
            goto no_memory;
        if (def->os.loader == NULL) {
            if (sexpr_node_copy(node, "domain/image/hvm/kernel", &def->os.loader) < 0)
                goto no_memory;

            if (def->os.loader == NULL) {
                virXendError(VIR_ERR_INTERNAL_ERROR,
                             "%s", _("domain information incomplete, missing HVM loader"));
                return(-1);
            }
        } else {
            if (sexpr_node_copy(node, "domain/image/hvm/kernel", &def->os.kernel) < 0)
                goto no_memory;
            if (sexpr_node_copy(node, "domain/image/hvm/ramdisk", &def->os.initrd) < 0)
                goto no_memory;
            if (sexpr_node_copy(node, "domain/image/hvm/args", &def->os.cmdline) < 0)
                goto no_memory;
            if (sexpr_node_copy(node, "domain/image/hvm/root", &def->os.root) < 0)
                goto no_memory;
        }
    } else {
        if (sexpr_node_copy(node, "domain/image/linux/kernel", &def->os.kernel) < 0)
            goto no_memory;
        if (sexpr_node_copy(node, "domain/image/linux/ramdisk", &def->os.initrd) < 0)
            goto no_memory;
        if (sexpr_node_copy(node, "domain/image/linux/args", &def->os.cmdline) < 0)
            goto no_memory;
        if (sexpr_node_copy(node, "domain/image/linux/root", &def->os.root) < 0)
            goto no_memory;
    }

    /* If HVM kenrel == loader, then old xend, so kill off kernel */
    if (hvm &&
        def->os.kernel &&
        STREQ(def->os.kernel, def->os.loader)) {
        VIR_FREE(def->os.kernel);
    }

    if (!def->os.kernel &&
        hvm) {
        const char *boot = sexpr_node(node, "domain/image/hvm/boot");
        if ((boot != NULL) && (boot[0] != 0)) {
            while (*boot &&
                   def->os.nBootDevs < VIR_DOMAIN_BOOT_LAST) {
                if (*boot == 'a')
                    def->os.bootDevs[def->os.nBootDevs++] = VIR_DOMAIN_BOOT_FLOPPY;
                else if (*boot == 'c')
                    def->os.bootDevs[def->os.nBootDevs++] = VIR_DOMAIN_BOOT_DISK;
                else if (*boot == 'd')
                    def->os.bootDevs[def->os.nBootDevs++] = VIR_DOMAIN_BOOT_CDROM;
                else if (*boot == 'n')
                    def->os.bootDevs[def->os.nBootDevs++] = VIR_DOMAIN_BOOT_NET;
                boot++;
            }
        }
    }

    if (!hvm &&
        !def->os.kernel &&
        !def->os.bootloader) {
        virXendError(VIR_ERR_INTERNAL_ERROR,
                     "%s", _("domain information incomplete, missing kernel & bootloader"));
        return -1;
    }

    return 0;

no_memory:
    virReportOOMError();
    return -1;
}

virDomainChrDefPtr
xenDaemonParseSxprChar(const char *value,
                       const char *tty)
{
    const char *prefix;
    char *tmp;
    virDomainChrDefPtr def;

    if (VIR_ALLOC(def) < 0) {
        virReportOOMError();
        return NULL;
    }

    prefix = value;

    if (value[0] == '/') {
        def->source.type = VIR_DOMAIN_CHR_TYPE_DEV;
    } else {
        if ((tmp = strchr(value, ':')) != NULL) {
            *tmp = '\0';
            value = tmp + 1;
        }

        if (STRPREFIX(prefix, "telnet")) {
            def->source.type = VIR_DOMAIN_CHR_TYPE_TCP;
            def->source.data.tcp.protocol = VIR_DOMAIN_CHR_TCP_PROTOCOL_TELNET;
        } else {
            if ((def->source.type = virDomainChrTypeFromString(prefix)) < 0) {
                virXendError(VIR_ERR_INTERNAL_ERROR,
                             _("unknown chr device type '%s'"), prefix);
                goto error;
            }
        }
    }

    /* Compat with legacy  <console tty='/dev/pts/5'/> syntax */
    switch (def->source.type) {
    case VIR_DOMAIN_CHR_TYPE_PTY:
        if (tty != NULL &&
            !(def->source.data.file.path = strdup(tty)))
            goto no_memory;
        break;

    case VIR_DOMAIN_CHR_TYPE_FILE:
    case VIR_DOMAIN_CHR_TYPE_PIPE:
        if (!(def->source.data.file.path = strdup(value)))
            goto no_memory;
        break;

    case VIR_DOMAIN_CHR_TYPE_TCP:
    {
        const char *offset = strchr(value, ':');
        const char *offset2;

        if (offset == NULL) {
            virXendError(VIR_ERR_INTERNAL_ERROR,
                         "%s", _("malformed char device string"));
            goto error;
        }

        if (offset != value &&
            (def->source.data.tcp.host = strndup(value,
                                                 offset - value)) == NULL)
            goto no_memory;

        offset2 = strchr(offset, ',');
        if (offset2 == NULL)
            def->source.data.tcp.service = strdup(offset+1);
        else
            def->source.data.tcp.service = strndup(offset+1,
                                                   offset2-(offset+1));
        if (def->source.data.tcp.service == NULL)
            goto no_memory;

        if (offset2 && strstr(offset2, ",server"))
            def->source.data.tcp.listen = true;
    }
    break;

    case VIR_DOMAIN_CHR_TYPE_UDP:
    {
        const char *offset = strchr(value, ':');
        const char *offset2, *offset3;

        if (offset == NULL) {
            virXendError(VIR_ERR_INTERNAL_ERROR,
                         "%s", _("malformed char device string"));
            goto error;
        }

        if (offset != value &&
            (def->source.data.udp.connectHost
             = strndup(value, offset - value)) == NULL)
            goto no_memory;

        offset2 = strchr(offset, '@');
        if (offset2 != NULL) {
            if ((def->source.data.udp.connectService
                 = strndup(offset + 1, offset2-(offset+1))) == NULL)
                goto no_memory;

            offset3 = strchr(offset2, ':');
            if (offset3 == NULL) {
                virXendError(VIR_ERR_INTERNAL_ERROR,
                             "%s", _("malformed char device string"));
                goto error;
            }

            if (offset3 > (offset2 + 1) &&
                (def->source.data.udp.bindHost
                 = strndup(offset2 + 1, offset3 - (offset2+1))) == NULL)
                goto no_memory;

            if ((def->source.data.udp.bindService
                 = strdup(offset3 + 1)) == NULL)
                goto no_memory;
        } else {
            if ((def->source.data.udp.connectService
                 = strdup(offset + 1)) == NULL)
                goto no_memory;
        }
    }
    break;

    case VIR_DOMAIN_CHR_TYPE_UNIX:
    {
        const char *offset = strchr(value, ',');
        if (offset)
            def->source.data.nix.path = strndup(value, (offset - value));
        else
            def->source.data.nix.path = strdup(value);
        if (def->source.data.nix.path == NULL)
            goto no_memory;

        if (offset != NULL &&
            strstr(offset, ",server") != NULL)
            def->source.data.nix.listen = true;
    }
    break;
    }

    return def;

no_memory:
    virReportOOMError();
error:
    virDomainChrDefFree(def);
    return NULL;
}

/**
 * xend_parse_sexp_desc_disks
 * @conn: connection
 * @root: root sexpr
 * @xendConfigVersion: version of xend
 *
 * This parses out block devices from the domain sexpr
 *
 * Returns 0 if successful or -1 if failed.
 */
static int
xenDaemonParseSxprDisks(virDomainDefPtr def,
                        const struct sexpr *root,
                        int hvm,
                        int xendConfigVersion)
{
    const struct sexpr *cur, *node;
    virDomainDiskDefPtr disk = NULL;

    for (cur = root; cur->kind == SEXPR_CONS; cur = cur->u.s.cdr) {
        node = cur->u.s.car;
        /* Normally disks are in a (device (vbd ...)) block
           but blktap disks ended up in a differently named
           (device (tap ....)) block.... */
        if (sexpr_lookup(node, "device/vbd") ||
            sexpr_lookup(node, "device/tap") ||
            sexpr_lookup(node, "device/tap2")) {
            char *offset;
            const char *src = NULL;
            const char *dst = NULL;
            const char *mode = NULL;

            /* Again dealing with (vbd...) vs (tap ...) differences */
            if (sexpr_lookup(node, "device/vbd")) {
                src = sexpr_node(node, "device/vbd/uname");
                dst = sexpr_node(node, "device/vbd/dev");
                mode = sexpr_node(node, "device/vbd/mode");
            } else if (sexpr_lookup(node, "device/tap2")) {
                src = sexpr_node(node, "device/tap2/uname");
                dst = sexpr_node(node, "device/tap2/dev");
                mode = sexpr_node(node, "device/tap2/mode");
            } else {
                src = sexpr_node(node, "device/tap/uname");
                dst = sexpr_node(node, "device/tap/dev");
                mode = sexpr_node(node, "device/tap/mode");
            }

            if (VIR_ALLOC(disk) < 0)
                goto no_memory;

            if (dst == NULL) {
                virXendError(VIR_ERR_INTERNAL_ERROR,
                             "%s", _("domain information incomplete, vbd has no dev"));
                goto error;
            }

            if (src == NULL) {
                /* There is a case without the uname to the CD-ROM device */
                offset = strchr(dst, ':');
                if (!offset ||
                    !hvm ||
                    STRNEQ(offset, ":cdrom")) {
                    virXendError(VIR_ERR_INTERNAL_ERROR,
                                 "%s", _("domain information incomplete, vbd has no src"));
                    goto error;
                }
            }

            if (src != NULL) {
                offset = strchr(src, ':');
                if (!offset) {
                    virXendError(VIR_ERR_INTERNAL_ERROR,
                                 "%s", _("cannot parse vbd filename, missing driver name"));
                    goto error;
                }

                if (VIR_ALLOC_N(disk->driverName, (offset-src)+1) < 0)
                    goto no_memory;
                if (virStrncpy(disk->driverName, src, offset-src,
                              (offset-src)+1) == NULL) {
                    virXendError(VIR_ERR_INTERNAL_ERROR,
                                 _("Driver name %s too big for destination"),
                                 src);
                    goto error;
                }

                src = offset + 1;

                if (STREQ (disk->driverName, "tap") ||
                    STREQ (disk->driverName, "tap2")) {
                    offset = strchr(src, ':');
                    if (!offset) {
                        virXendError(VIR_ERR_INTERNAL_ERROR,
                                     "%s", _("cannot parse vbd filename, missing driver type"));
                        goto error;
                    }

                    if (VIR_ALLOC_N(disk->driverType, (offset-src)+1)< 0)
                        goto no_memory;
                    if (virStrncpy(disk->driverType, src, offset-src,
                                   (offset-src)+1) == NULL) {
                        virXendError(VIR_ERR_INTERNAL_ERROR,
                                     _("Driver type %s too big for destination"),
                                     src);
                        goto error;
                    }

                    src = offset + 1;
                    /* Its possible to use blktap driver for block devs
                       too, but kinda pointless because blkback is better,
                       so we assume common case here. If blktap becomes
                       omnipotent, we can revisit this, perhaps stat()'ing
                       the src file in question */
                    disk->type = VIR_DOMAIN_DISK_TYPE_FILE;
                } else if (STREQ(disk->driverName, "phy")) {
                    disk->type = VIR_DOMAIN_DISK_TYPE_BLOCK;
                } else if (STREQ(disk->driverName, "file")) {
                    disk->type = VIR_DOMAIN_DISK_TYPE_FILE;
                }
            } else {
                /* No CDROM media so can't really tell. We'll just
                   call if a FILE for now and update when media
                   is inserted later */
                disk->type = VIR_DOMAIN_DISK_TYPE_FILE;
            }

            if (STREQLEN (dst, "ioemu:", 6))
                dst += 6;

            disk->device = VIR_DOMAIN_DISK_DEVICE_DISK;
            /* New style disk config from Xen >= 3.0.3 */
            if (xendConfigVersion > 1) {
                offset = strrchr(dst, ':');
                if (offset) {
                    if (STREQ (offset, ":cdrom")) {
                        disk->device = VIR_DOMAIN_DISK_DEVICE_CDROM;
                    } else if (STREQ (offset, ":disk")) {
                        /* The default anyway */
                    } else {
                        /* Unknown, lets pretend its a disk too */
                    }
                    offset[0] = '\0';
                }
            }

            if (!(disk->dst = strdup(dst)))
                goto no_memory;
            if (src &&
                !(disk->src = strdup(src)))
                goto no_memory;

            if (STRPREFIX(disk->dst, "xvd"))
                disk->bus = VIR_DOMAIN_DISK_BUS_XEN;
            else if (STRPREFIX(disk->dst, "hd"))
                disk->bus = VIR_DOMAIN_DISK_BUS_IDE;
            else if (STRPREFIX(disk->dst, "sd"))
                disk->bus = VIR_DOMAIN_DISK_BUS_SCSI;
            else
                disk->bus = VIR_DOMAIN_DISK_BUS_IDE;

            if (mode &&
                strchr(mode, 'r'))
                disk->readonly = 1;
            if (mode &&
                strchr(mode, '!'))
                disk->shared = 1;

            if (VIR_REALLOC_N(def->disks, def->ndisks+1) < 0)
                goto no_memory;

            def->disks[def->ndisks++] = disk;
            disk = NULL;
        }
    }

    return 0;

no_memory:
    virReportOOMError();

error:
    virDomainDiskDefFree(disk);
    return -1;
}


static int
xenDaemonParseSxprNets(virDomainDefPtr def,
                       const struct sexpr *root)
{
    virDomainNetDefPtr net = NULL;
    const struct sexpr *cur, *node;
    const char *tmp;
    int vif_index = 0;

    for (cur = root; cur->kind == SEXPR_CONS; cur = cur->u.s.cdr) {
        node = cur->u.s.car;
        if (sexpr_lookup(node, "device/vif")) {
            const char *tmp2, *model, *type;
            char buf[50];
            tmp2 = sexpr_node(node, "device/vif/script");
            tmp = sexpr_node(node, "device/vif/bridge");
            model = sexpr_node(node, "device/vif/model");
            type = sexpr_node(node, "device/vif/type");

            if (VIR_ALLOC(net) < 0)
                goto no_memory;

            if (tmp != NULL ||
                (tmp2 != NULL && STREQ(tmp2, DEFAULT_VIF_SCRIPT))) {
                net->type = VIR_DOMAIN_NET_TYPE_BRIDGE;
                /* XXX virtual network reverse resolve */

                if (tmp &&
                    !(net->data.bridge.brname = strdup(tmp)))
                    goto no_memory;
                if (tmp2 &&
                    net->type == VIR_DOMAIN_NET_TYPE_BRIDGE &&
                    !(net->data.bridge.script = strdup(tmp2)))
                    goto no_memory;
                tmp = sexpr_node(node, "device/vif/ip");
                if (tmp &&
                    !(net->data.bridge.ipaddr = strdup(tmp)))
                    goto no_memory;
            } else {
                net->type = VIR_DOMAIN_NET_TYPE_ETHERNET;
                if (tmp2 &&
                    !(net->data.ethernet.script = strdup(tmp2)))
                    goto no_memory;
                tmp = sexpr_node(node, "device/vif/ip");
                if (tmp &&
                    !(net->data.ethernet.ipaddr = strdup(tmp)))
                    goto no_memory;
            }

            tmp = sexpr_node(node, "device/vif/vifname");
            if (!tmp) {
                snprintf(buf, sizeof(buf), "vif%d.%d", def->id, vif_index);
                tmp = buf;
            }
            if (!(net->ifname = strdup(tmp)))
                goto no_memory;

            tmp = sexpr_node(node, "device/vif/mac");
            if (tmp) {
                if (virParseMacAddr(tmp, net->mac) < 0) {
                    virXendError(VIR_ERR_INTERNAL_ERROR,
                                 _("malformed mac address '%s'"), tmp);
                    goto cleanup;
                }
            }

            if (model &&
                !(net->model = strdup(model)))
                goto no_memory;

            if (!model && type &&
                STREQ(type, "netfront") &&
                !(net->model = strdup("netfront")))
                goto no_memory;

            if (VIR_REALLOC_N(def->nets, def->nnets + 1) < 0)
                goto no_memory;

            def->nets[def->nnets++] = net;
            vif_index++;
        }
    }

    return 0;

no_memory:
    virReportOOMError();
cleanup:
    virDomainNetDefFree(net);
    return -1;
}


int
xenDaemonParseSxprSound(virDomainDefPtr def,
                        const char *str)
{
    if (STREQ(str, "all")) {
        int i;

        /*
         * Special compatability code for Xen with a bogus
         * sound=all in config.
         *
         * NB delibrately, don't include all possible
         * sound models anymore, just the 2 that were
         * historically present in Xen's QEMU.
         *
         * ie just es1370 + sb16.
         *
         * Hence use of MODEL_ES1370 + 1, instead of MODEL_LAST
         */

        if (VIR_ALLOC_N(def->sounds,
                        VIR_DOMAIN_SOUND_MODEL_ES1370 + 1) < 0)
            goto no_memory;


        for (i = 0 ; i < (VIR_DOMAIN_SOUND_MODEL_ES1370 + 1) ; i++) {
            virDomainSoundDefPtr sound;
            if (VIR_ALLOC(sound) < 0)
                goto no_memory;
            sound->model = i;
            def->sounds[def->nsounds++] = sound;
        }
    } else {
        char model[10];
        const char *offset = str, *offset2;

        do {
            int len;
            virDomainSoundDefPtr sound;
            offset2 = strchr(offset, ',');
            if (offset2)
                len = (offset2 - offset);
            else
                len = strlen(offset);
            if (virStrncpy(model, offset, len, sizeof(model)) == NULL) {
                virXendError(VIR_ERR_INTERNAL_ERROR,
                                 _("Sound model %s too big for destination"),
                             offset);
                goto error;
            }

            if (VIR_ALLOC(sound) < 0)
                goto no_memory;

            if ((sound->model = virDomainSoundModelTypeFromString(model)) < 0) {
                VIR_FREE(sound);
                goto error;
            }

            if (VIR_REALLOC_N(def->sounds, def->nsounds+1) < 0) {
                virDomainSoundDefFree(sound);
                goto no_memory;
            }

            def->sounds[def->nsounds++] = sound;
            offset = offset2 ? offset2 + 1 : NULL;
        } while (offset);
    }

    return 0;

no_memory:
    virReportOOMError();
error:
    return -1;
}


static int
xenDaemonParseSxprUSB(virDomainDefPtr def,
                      const struct sexpr *root)
{
    struct sexpr *cur, *node;
    const char *tmp;

    for (cur = sexpr_lookup(root, "domain/image/hvm"); cur && cur->kind == SEXPR_CONS; cur = cur->u.s.cdr) {
        node = cur->u.s.car;
        if (sexpr_lookup(node, "usbdevice")) {
            tmp = sexpr_node(node, "usbdevice");
            if (tmp && *tmp) {
                if (STREQ(tmp, "tablet") ||
                    STREQ(tmp, "mouse")) {
                    virDomainInputDefPtr input;
                    if (VIR_ALLOC(input) < 0)
                        goto no_memory;
                    input->bus = VIR_DOMAIN_INPUT_BUS_USB;
                    if (STREQ(tmp, "tablet"))
                        input->type = VIR_DOMAIN_INPUT_TYPE_TABLET;
                    else
                        input->type = VIR_DOMAIN_INPUT_TYPE_MOUSE;

                    if (VIR_REALLOC_N(def->inputs, def->ninputs+1) < 0) {
                        VIR_FREE(input);
                        goto no_memory;
                    }
                    def->inputs[def->ninputs++] = input;
                } else {
                    /* XXX Handle other non-input USB devices later */
                }
            }
        }
    }
    return 0;

no_memory:
    virReportOOMError();
    return -1;
}

static int
xenDaemonParseSxprGraphicsOld(virConnectPtr conn,
                              virDomainDefPtr def,
                              const struct sexpr *root,
                              int hvm,
                              int xendConfigVersion)
{
    xenUnifiedPrivatePtr priv = conn->privateData;
    const char *tmp;
    virDomainGraphicsDefPtr graphics = NULL;

    if ((tmp = sexpr_fmt_node(root, "domain/image/%s/vnc", hvm ? "hvm" : "linux")) &&
        tmp[0] == '1') {
        /* Graphics device (HVM, or old (pre-3.0.4) style PV VNC config) */
        int port;
        const char *listenAddr = sexpr_fmt_node(root, "domain/image/%s/vnclisten", hvm ? "hvm" : "linux");
        const char *vncPasswd = sexpr_fmt_node(root, "domain/image/%s/vncpasswd", hvm ? "hvm" : "linux");
        const char *keymap = sexpr_fmt_node(root, "domain/image/%s/keymap", hvm ? "hvm" : "linux");
        const char *unused = sexpr_fmt_node(root, "domain/image/%s/vncunused", hvm ? "hvm" : "linux");

        xenUnifiedLock(priv);
        port = xenStoreDomainGetVNCPort(conn, def->id);
        xenUnifiedUnlock(priv);

        if (VIR_ALLOC(graphics) < 0)
            goto no_memory;

        graphics->type = VIR_DOMAIN_GRAPHICS_TYPE_VNC;
        /* For Xen >= 3.0.3, don't generate a fixed port mapping
         * because it will almost certainly be wrong ! Just leave
         * it as -1 which lets caller see that the VNC server isn't
         * present yet. Subsquent dumps of the XML will eventually
         * find the port in XenStore once VNC server has started
         */
        if (port == -1 && xendConfigVersion < 2)
            port = 5900 + def->id;

        if ((unused && STREQ(unused, "1")) || port == -1)
            graphics->data.vnc.autoport = 1;
        graphics->data.vnc.port = port;

        if (listenAddr &&
            !(graphics->data.vnc.listenAddr = strdup(listenAddr)))
            goto no_memory;

        if (vncPasswd &&
            !(graphics->data.vnc.auth.passwd = strdup(vncPasswd)))
            goto no_memory;

        if (keymap &&
            !(graphics->data.vnc.keymap = strdup(keymap)))
            goto no_memory;

        if (VIR_ALLOC_N(def->graphics, 1) < 0)
            goto no_memory;
        def->graphics[0] = graphics;
        def->ngraphics = 1;
        graphics = NULL;
    } else if ((tmp = sexpr_fmt_node(root, "domain/image/%s/sdl", hvm ? "hvm" : "linux")) &&
               tmp[0] == '1') {
        /* Graphics device (HVM, or old (pre-3.0.4) style PV sdl config) */
        const char *display = sexpr_fmt_node(root, "domain/image/%s/display", hvm ? "hvm" : "linux");
        const char *xauth = sexpr_fmt_node(root, "domain/image/%s/xauthority", hvm ? "hvm" : "linux");

        if (VIR_ALLOC(graphics) < 0)
            goto no_memory;

        graphics->type = VIR_DOMAIN_GRAPHICS_TYPE_SDL;
        if (display &&
            !(graphics->data.sdl.display = strdup(display)))
            goto no_memory;
        if (xauth &&
            !(graphics->data.sdl.xauth = strdup(xauth)))
            goto no_memory;

        if (VIR_ALLOC_N(def->graphics, 1) < 0)
            goto no_memory;
        def->graphics[0] = graphics;
        def->ngraphics = 1;
        graphics = NULL;
    }

    return 0;

no_memory:
    virReportOOMError();
    virDomainGraphicsDefFree(graphics);
    return -1;
}


static int
xenDaemonParseSxprGraphicsNew(virConnectPtr conn,
                              virDomainDefPtr def,
                              const struct sexpr *root)
{
    xenUnifiedPrivatePtr priv = conn->privateData;
    virDomainGraphicsDefPtr graphics = NULL;
    const struct sexpr *cur, *node;
    const char *tmp;

    /* append network devices and framebuffer */
    for (cur = root; cur->kind == SEXPR_CONS; cur = cur->u.s.cdr) {
        node = cur->u.s.car;
        if (sexpr_lookup(node, "device/vfb")) {
            /* New style graphics config for PV guests in >= 3.0.4,
             * or for HVM guests in >= 3.0.5 */
            if (sexpr_node(node, "device/vfb/type")) {
                tmp = sexpr_node(node, "device/vfb/type");
            } else if (sexpr_node(node, "device/vfb/vnc")) {
                tmp = "vnc";
            } else if (sexpr_node(node, "device/vfb/sdl")) {
                tmp = "sdl";
            } else {
                tmp = "unknown";
            }

            if (VIR_ALLOC(graphics) < 0)
                goto no_memory;

            if ((graphics->type = virDomainGraphicsTypeFromString(tmp)) < 0) {
                virXendError(VIR_ERR_INTERNAL_ERROR,
                             _("unknown graphics type '%s'"), tmp);
                goto error;
            }

            if (graphics->type == VIR_DOMAIN_GRAPHICS_TYPE_SDL) {
                const char *display = sexpr_node(node, "device/vfb/display");
                const char *xauth = sexpr_node(node, "device/vfb/xauthority");
                if (display &&
                    !(graphics->data.sdl.display = strdup(display)))
                    goto no_memory;
                if (xauth &&
                    !(graphics->data.sdl.xauth = strdup(xauth)))
                    goto no_memory;
            } else {
                int port;
                const char *listenAddr = sexpr_node(node, "device/vfb/vnclisten");
                const char *vncPasswd = sexpr_node(node, "device/vfb/vncpasswd");
                const char *keymap = sexpr_node(node, "device/vfb/keymap");
                const char *unused = sexpr_node(node, "device/vfb/vncunused");

                xenUnifiedLock(priv);
                port = xenStoreDomainGetVNCPort(conn, def->id);
                xenUnifiedUnlock(priv);

                /* Didn't find port entry in xenstore */
                if (port == -1) {
                    const char *str = sexpr_node(node, "device/vfb/vncdisplay");
                    int val;
                    if (str != NULL && virStrToLong_i(str, NULL, 0, &val) == 0)
                        port = val;
                }

                if ((unused && STREQ(unused, "1")) || port == -1)
                    graphics->data.vnc.autoport = 1;

                if (port >= 0 && port < 5900)
                    port += 5900;
                graphics->data.vnc.port = port;

                if (listenAddr &&
                    !(graphics->data.vnc.listenAddr = strdup(listenAddr)))
                    goto no_memory;

                if (vncPasswd &&
                    !(graphics->data.vnc.auth.passwd = strdup(vncPasswd)))
                    goto no_memory;

                if (keymap &&
                    !(graphics->data.vnc.keymap = strdup(keymap)))
                    goto no_memory;
            }

            if (VIR_ALLOC_N(def->graphics, 1) < 0)
                goto no_memory;
            def->graphics[0] = graphics;
            def->ngraphics = 1;
            graphics = NULL;
            break;
        }
    }

    return 0;

no_memory:
    virReportOOMError();
error:
    virDomainGraphicsDefFree(graphics);
    return -1;
}

/**
 * xenDaemonParseSxprPCI
 * @root: root sexpr
 *
 * This parses out block devices from the domain sexpr
 *
 * Returns 0 if successful or -1 if failed.
 */
static int
xenDaemonParseSxprPCI(virDomainDefPtr def,
                      const struct sexpr *root)
{
    const struct sexpr *cur, *tmp = NULL, *node;
    virDomainHostdevDefPtr dev = NULL;

    /*
     * With the (domain ...) block we have the following odd setup
     *
     * (device
     *    (pci
     *       (dev (domain 0x0000) (bus 0x00) (slot 0x1b) (func 0x0))
     *       (dev (domain 0x0000) (bus 0x00) (slot 0x13) (func 0x0))
     *    )
     * )
     *
     * Normally there is one (device ...) block per device, but in
     * wierd world of Xen PCI, once (device ...) covers multiple
     * devices.
     */

    for (cur = root; cur->kind == SEXPR_CONS; cur = cur->u.s.cdr) {
        node = cur->u.s.car;
        if ((tmp = sexpr_lookup(node, "device/pci")) != NULL)
            break;
    }

    if (!tmp)
        return 0;

    for (cur = tmp; cur->kind == SEXPR_CONS; cur = cur->u.s.cdr) {
        const char *domain = NULL;
        const char *bus = NULL;
        const char *slot = NULL;
        const char *func = NULL;
        int domainID;
        int busID;
        int slotID;
        int funcID;

        node = cur->u.s.car;
        if (!sexpr_lookup(node, "dev"))
            continue;

        if (!(domain = sexpr_node(node, "dev/domain"))) {
            virXendError(VIR_ERR_INTERNAL_ERROR,
                         "%s", _("missing PCI domain"));
            goto error;
        }
        if (!(bus = sexpr_node(node, "dev/bus"))) {
            virXendError(VIR_ERR_INTERNAL_ERROR,
                         "%s", _("missing PCI bus"));
            goto error;
        }
        if (!(slot = sexpr_node(node, "dev/slot"))) {
            virXendError(VIR_ERR_INTERNAL_ERROR,
                         "%s", _("missing PCI slot"));
            goto error;
        }
        if (!(func = sexpr_node(node, "dev/func"))) {
            virXendError(VIR_ERR_INTERNAL_ERROR,
                         "%s", _("missing PCI func"));
            goto error;
        }

        if (virStrToLong_i(domain, NULL, 0, &domainID) < 0) {
            virXendError(VIR_ERR_INTERNAL_ERROR,
                         _("cannot parse PCI domain '%s'"), domain);
            goto error;
        }
        if (virStrToLong_i(bus, NULL, 0, &busID) < 0) {
            virXendError(VIR_ERR_INTERNAL_ERROR,
                         _("cannot parse PCI bus '%s'"), bus);
            goto error;
        }
        if (virStrToLong_i(slot, NULL, 0, &slotID) < 0) {
            virXendError(VIR_ERR_INTERNAL_ERROR,
                         _("cannot parse PCI slot '%s'"), slot);
            goto error;
        }
        if (virStrToLong_i(func, NULL, 0, &funcID) < 0) {
            virXendError(VIR_ERR_INTERNAL_ERROR,
                         _("cannot parse PCI func '%s'"), func);
            goto error;
        }

        if (VIR_ALLOC(dev) < 0)
            goto no_memory;

        dev->mode = VIR_DOMAIN_HOSTDEV_MODE_SUBSYS;
        dev->managed = 0;
        dev->source.subsys.type = VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI;
        dev->source.subsys.u.pci.domain = domainID;
        dev->source.subsys.u.pci.bus = busID;
        dev->source.subsys.u.pci.slot = slotID;
        dev->source.subsys.u.pci.function = funcID;

        if (VIR_REALLOC_N(def->hostdevs, def->nhostdevs+1) < 0) {
            goto no_memory;
        }

        def->hostdevs[def->nhostdevs++] = dev;
    }

    return 0;

no_memory:
    virReportOOMError();

error:
    virDomainHostdevDefFree(dev);
    return -1;
}


/**
 * xenDaemonParseSxpr:
 * @conn: the connection associated with the XML
 * @root: the root of the parsed S-Expression
 * @xendConfigVersion: version of xend
 * @cpus: set of cpus the domain may be pinned to
 *
 * Parse the xend sexp description and turn it into the XML format similar
 * to the one unsed for creation.
 *
 * Returns the 0 terminated XML string or NULL in case of error.
 *         the caller must free() the returned value.
 */
static virDomainDefPtr
xenDaemonParseSxpr(virConnectPtr conn,
                   const struct sexpr *root,
                   int xendConfigVersion,
                   const char *cpus)
{
    xenUnifiedPrivatePtr priv = conn->privateData;
    const char *tmp;
    virDomainDefPtr def;
    int hvm = 0;
    char *tty = NULL;

    if (VIR_ALLOC(def) < 0)
        goto no_memory;

    tmp = sexpr_node(root, "domain/domid");
    if (tmp == NULL && xendConfigVersion < 3) { /* Old XenD, domid was mandatory */
        virXendError(VIR_ERR_INTERNAL_ERROR,
                     "%s", _("domain information incomplete, missing id"));
        goto error;
    }
    def->virtType = VIR_DOMAIN_VIRT_XEN;
    if (tmp)
        def->id = sexpr_int(root, "domain/domid");
    else
        def->id = -1;

    if (sexpr_node_copy(root, "domain/name", &def->name) < 0)
        goto no_memory;
    if (def->name == NULL) {
        virXendError(VIR_ERR_INTERNAL_ERROR,
                     "%s", _("domain information incomplete, missing name"));
        goto error;
    }

    tmp = sexpr_node(root, "domain/uuid");
    if (tmp == NULL) {
        virXendError(VIR_ERR_INTERNAL_ERROR,
                     "%s", _("domain information incomplete, missing name"));
        goto error;
    }
    virUUIDParse(tmp, def->uuid);

    if (sexpr_node_copy(root, "domain/description", &def->description) < 0)
        goto no_memory;

    hvm = sexpr_lookup(root, "domain/image/hvm") ? 1 : 0;
    if (!hvm) {
        if (sexpr_node_copy(root, "domain/bootloader",
                            &def->os.bootloader) < 0)
            goto no_memory;

        if (!def->os.bootloader &&
            sexpr_has(root, "domain/bootloader") &&
            (def->os.bootloader = strdup("")) == NULL)
            goto no_memory;

        if (def->os.bootloader &&
            sexpr_node_copy(root, "domain/bootloader_args",
                            &def->os.bootloaderArgs) < 0)
            goto no_memory;
    }

    if (!(def->os.type = strdup(hvm ? "hvm" : "linux")))
        goto no_memory;

    if (def->id != 0) {
        if (sexpr_lookup(root, "domain/image")) {
            if (xenDaemonParseSxprOS(root, def, hvm) < 0)
                goto error;
        }
    }

    def->mem.max_balloon = (unsigned long)
                           (sexpr_u64(root, "domain/maxmem") << 10);
    def->mem.cur_balloon = (unsigned long)
                           (sexpr_u64(root, "domain/memory") << 10);
    if (def->mem.cur_balloon > def->mem.max_balloon)
        def->mem.cur_balloon = def->mem.max_balloon;

    if (cpus != NULL) {
        def->cpumasklen = VIR_DOMAIN_CPUMASK_LEN;
        if (VIR_ALLOC_N(def->cpumask, def->cpumasklen) < 0) {
            virReportOOMError();
            goto error;
        }

        if (virDomainCpuSetParse(&cpus,
                                 0, def->cpumask,
                                 def->cpumasklen) < 0) {
            virXendError(VIR_ERR_INTERNAL_ERROR,
                         _("invalid CPU mask %s"), cpus);
            goto error;
        }
    }

    def->maxvcpus = sexpr_int(root, "domain/vcpus");
    def->vcpus = count_one_bits_l(sexpr_u64(root, "domain/vcpu_avail"));
    if (!def->vcpus || def->maxvcpus < def->vcpus)
        def->vcpus = def->maxvcpus;

    tmp = sexpr_node(root, "domain/on_poweroff");
    if (tmp != NULL) {
        if ((def->onPoweroff = virDomainLifecycleTypeFromString(tmp)) < 0) {
            virXendError(VIR_ERR_INTERNAL_ERROR,
                         _("unknown lifecycle type %s"), tmp);
            goto error;
        }
    } else
        def->onPoweroff = VIR_DOMAIN_LIFECYCLE_DESTROY;

    tmp = sexpr_node(root, "domain/on_reboot");
    if (tmp != NULL) {
        if ((def->onReboot = virDomainLifecycleTypeFromString(tmp)) < 0) {
            virXendError(VIR_ERR_INTERNAL_ERROR,
                         _("unknown lifecycle type %s"), tmp);
            goto error;
        }
    } else
        def->onReboot = VIR_DOMAIN_LIFECYCLE_RESTART;

    tmp = sexpr_node(root, "domain/on_crash");
    if (tmp != NULL) {
        if ((def->onCrash = virDomainLifecycleCrashTypeFromString(tmp)) < 0) {
            virXendError(VIR_ERR_INTERNAL_ERROR,
                         _("unknown lifecycle type %s"), tmp);
            goto error;
        }
    } else
        def->onCrash = VIR_DOMAIN_LIFECYCLE_DESTROY;

    def->clock.offset = VIR_DOMAIN_CLOCK_OFFSET_UTC;
    if (hvm) {
        if (sexpr_int(root, "domain/image/hvm/acpi"))
            def->features |= (1 << VIR_DOMAIN_FEATURE_ACPI);
        if (sexpr_int(root, "domain/image/hvm/apic"))
            def->features |= (1 << VIR_DOMAIN_FEATURE_APIC);
        if (sexpr_int(root, "domain/image/hvm/pae"))
            def->features |= (1 << VIR_DOMAIN_FEATURE_PAE);
        if (sexpr_int(root, "domain/image/hvm/hap"))
            def->features |= (1 << VIR_DOMAIN_FEATURE_HAP);

        /* Old XenD only allows localtime here for HVM */
        if (sexpr_int(root, "domain/image/hvm/localtime"))
            def->clock.offset = VIR_DOMAIN_CLOCK_OFFSET_LOCALTIME;
    }

    /* Current XenD allows localtime here, for PV and HVM */
    if (sexpr_int(root, "domain/localtime"))
        def->clock.offset = VIR_DOMAIN_CLOCK_OFFSET_LOCALTIME;

    if (sexpr_node_copy(root, hvm ?
                        "domain/image/hvm/device_model" :
                        "domain/image/linux/device_model",
                        &def->emulator) < 0)
        goto no_memory;

    /* append block devices */
    if (xenDaemonParseSxprDisks(def, root, hvm, xendConfigVersion) < 0)
        goto error;

    if (xenDaemonParseSxprNets(def, root) < 0)
        goto error;

    if (xenDaemonParseSxprPCI(def, root) < 0)
        goto error;

    /* New style graphics device config */
    if (xenDaemonParseSxprGraphicsNew(conn, def, root) < 0)
        goto error;

    /* Graphics device (HVM <= 3.0.4, or PV <= 3.0.3) vnc config */
    if ((def->ngraphics == 0) &&
        xenDaemonParseSxprGraphicsOld(conn, def, root, hvm, xendConfigVersion) < 0)
        goto error;


    /* Old style cdrom config from Xen <= 3.0.2 */
    if (hvm &&
        xendConfigVersion == 1) {
        tmp = sexpr_node(root, "domain/image/hvm/cdrom");
        if ((tmp != NULL) && (tmp[0] != 0)) {
            virDomainDiskDefPtr disk;
            if (VIR_ALLOC(disk) < 0)
                goto no_memory;
            if (!(disk->src = strdup(tmp))) {
                virDomainDiskDefFree(disk);
                goto no_memory;
            }
            disk->type = VIR_DOMAIN_DISK_TYPE_FILE;
            disk->device = VIR_DOMAIN_DISK_DEVICE_CDROM;
            if (!(disk->dst = strdup("hdc"))) {
                virDomainDiskDefFree(disk);
                goto no_memory;
            }
            if (!(disk->driverName = strdup("file"))) {
                virDomainDiskDefFree(disk);
                goto no_memory;
            }
            disk->bus = VIR_DOMAIN_DISK_BUS_IDE;
            disk->readonly = 1;

            if (VIR_REALLOC_N(def->disks, def->ndisks+1) < 0) {
                virDomainDiskDefFree(disk);
                goto no_memory;
            }
            def->disks[def->ndisks++] = disk;
        }
    }


    /* Floppy disk config */
    if (hvm) {
        const char *const fds[] = { "fda", "fdb" };
        int i;
        for (i = 0 ; i < ARRAY_CARDINALITY(fds) ; i++) {
            tmp = sexpr_fmt_node(root, "domain/image/hvm/%s", fds[i]);
            if ((tmp != NULL) && (tmp[0] != 0)) {
                virDomainDiskDefPtr disk;
                if (VIR_ALLOC(disk) < 0)
                    goto no_memory;
                if (!(disk->src = strdup(tmp))) {
                    VIR_FREE(disk);
                    goto no_memory;
                }
                disk->type = VIR_DOMAIN_DISK_TYPE_FILE;
                disk->device = VIR_DOMAIN_DISK_DEVICE_FLOPPY;
                if (!(disk->dst = strdup(fds[i]))) {
                    virDomainDiskDefFree(disk);
                    goto no_memory;
                }
                if (!(disk->driverName = strdup("file"))) {
                    virDomainDiskDefFree(disk);
                    goto no_memory;
                }
                disk->bus = VIR_DOMAIN_DISK_BUS_FDC;

                if (VIR_REALLOC_N(def->disks, def->ndisks+1) < 0) {
                    virDomainDiskDefFree(disk);
                    goto no_memory;
                }
                def->disks[def->ndisks++] = disk;
            }
        }
    }

    /* in case of HVM we have USB device emulation */
    if (hvm &&
        xenDaemonParseSxprUSB(def, root) < 0)
        goto error;

    /* Character device config */
    xenUnifiedLock(priv);
    tty = xenStoreDomainGetConsolePath(conn, def->id);
    xenUnifiedUnlock(priv);
    if (hvm) {
        tmp = sexpr_node(root, "domain/image/hvm/serial");
        if (tmp && STRNEQ(tmp, "none")) {
            virDomainChrDefPtr chr;
            if ((chr = xenDaemonParseSxprChar(tmp, tty)) == NULL)
                goto error;
            if (VIR_REALLOC_N(def->serials, def->nserials+1) < 0) {
                virDomainChrDefFree(chr);
                goto no_memory;
            }
            chr->deviceType = VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL;
            def->serials[def->nserials++] = chr;
        }
        tmp = sexpr_node(root, "domain/image/hvm/parallel");
        if (tmp && STRNEQ(tmp, "none")) {
            virDomainChrDefPtr chr;
            /* XXX does XenD stuff parallel port tty info into xenstore somewhere ? */
            if ((chr = xenDaemonParseSxprChar(tmp, NULL)) == NULL)
                goto error;
            if (VIR_REALLOC_N(def->parallels, def->nparallels+1) < 0) {
                virDomainChrDefFree(chr);
                goto no_memory;
            }
            chr->deviceType = VIR_DOMAIN_CHR_DEVICE_TYPE_PARALLEL;
            def->parallels[def->nparallels++] = chr;
        }
    } else {
        /* Fake a paravirt console, since that's not in the sexpr */
        if (!(def->console = xenDaemonParseSxprChar("pty", tty)))
            goto error;
        def->console->deviceType = VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE;
        def->console->targetType = VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_XEN;
    }
    VIR_FREE(tty);


    /* Sound device config */
    if (hvm &&
        (tmp = sexpr_node(root, "domain/image/hvm/soundhw")) != NULL &&
        *tmp) {
        if (xenDaemonParseSxprSound(def, tmp) < 0)
            goto error;
    }

    return def;

no_memory:
    virReportOOMError();
error:
    VIR_FREE(tty);
    virDomainDefFree(def);
    return NULL;
}

virDomainDefPtr
xenDaemonParseSxprString(virConnectPtr conn,
                         const char *sexpr,
                         int xendConfigVersion)
{
    struct sexpr *root = string2sexpr(sexpr);
    virDomainDefPtr def;

    if (!root)
        return NULL;

    def = xenDaemonParseSxpr(conn, root, xendConfigVersion, NULL);

    sexpr_free(root);

    return def;
}


/**
 * sexpr_to_xend_domain_info:
 * @root: an S-Expression describing a domain
 * @info: a info data structure to fill=up
 *
 * Internal routine filling up the info structure with the values from
 * the domain root provided.
 *
 * Returns 0 in case of success, -1 in case of error
 */
static int
sexpr_to_xend_domain_info(virDomainPtr domain, const struct sexpr *root,
                          virDomainInfoPtr info)
{
    const char *flags;
    int vcpus;

    if ((root == NULL) || (info == NULL))
        return (-1);

    info->memory = sexpr_u64(root, "domain/memory") << 10;
    info->maxMem = sexpr_u64(root, "domain/maxmem") << 10;
    flags = sexpr_node(root, "domain/state");

    if (flags) {
        if (strchr(flags, 'c'))
            info->state = VIR_DOMAIN_CRASHED;
        else if (strchr(flags, 's'))
            info->state = VIR_DOMAIN_SHUTOFF;
        else if (strchr(flags, 'd'))
            info->state = VIR_DOMAIN_SHUTDOWN;
        else if (strchr(flags, 'p'))
            info->state = VIR_DOMAIN_PAUSED;
        else if (strchr(flags, 'b'))
            info->state = VIR_DOMAIN_BLOCKED;
        else if (strchr(flags, 'r'))
            info->state = VIR_DOMAIN_RUNNING;
    } else {
        /* Inactive domains don't have a state reported, so
           mark them SHUTOFF, rather than NOSTATE */
        if (domain->id < 0)
            info->state = VIR_DOMAIN_SHUTOFF;
        else
            info->state = VIR_DOMAIN_NOSTATE;
    }
    info->cpuTime = sexpr_float(root, "domain/cpu_time") * 1000000000;
    vcpus = sexpr_int(root, "domain/vcpus");
    info->nrVirtCpu = count_one_bits_l(sexpr_u64(root, "domain/vcpu_avail"));
    if (!info->nrVirtCpu || vcpus < info->nrVirtCpu)
        info->nrVirtCpu = vcpus;

    return (0);
}

/**
 * sexpr_to_xend_node_info:
 * @root: an S-Expression describing a domain
 * @info: a info data structure to fill up
 *
 * Internal routine filling up the info structure with the values from
 * the node root provided.
 *
 * Returns 0 in case of success, -1 in case of error
 */
static int
sexpr_to_xend_node_info(const struct sexpr *root, virNodeInfoPtr info)
{
    const char *machine;


    if ((root == NULL) || (info == NULL))
        return (-1);

    machine = sexpr_node(root, "node/machine");
    if (machine == NULL) {
        info->model[0] = 0;
    } else {
        snprintf(&info->model[0], sizeof(info->model) - 1, "%s", machine);
        info->model[sizeof(info->model) - 1] = 0;
    }
    info->memory = (unsigned long) sexpr_u64(root, "node/total_memory") << 10;

    info->cpus = sexpr_int(root, "node/nr_cpus");
    info->mhz = sexpr_int(root, "node/cpu_mhz");
    info->nodes = sexpr_int(root, "node/nr_nodes");
    info->sockets = sexpr_int(root, "node/sockets_per_node");
    info->cores = sexpr_int(root, "node/cores_per_socket");
    info->threads = sexpr_int(root, "node/threads_per_core");

    /* Xen 3.2.0 replaces sockets_per_node with 'nr_cpus'.
     * Old Xen calculated sockets_per_node using its internal
     * nr_cpus / (nodes*cores*threads), so fake it ourselves
     * in the same way
     */
    if (info->sockets == 0) {
        int nr_cpus = sexpr_int(root, "node/nr_cpus");
        int procs = info->nodes * info->cores * info->threads;
        if (procs == 0) /* Sanity check in case of Xen bugs in futures..*/
            return (-1);
        info->sockets = nr_cpus / procs;
    }

    /* On systems where NUMA nodes are not composed of whole sockets either Xen
     * provided us wrong number of sockets per node or we computed the wrong
     * number in the compatibility code above. In such case, we compute the
     * correct number of sockets on the host, lie about the number of NUMA
     * nodes, and force apps to check capabilities XML for the actual NUMA
     * topology.
     */
    if (info->nodes * info->sockets * info->cores * info->threads
        != info->cpus) {
        info->nodes = 1;
        info->sockets = info->cpus / (info->cores * info->threads);
    }

    return (0);
}


/**
 * sexpr_to_xend_topology
 * @root: an S-Expression describing a node
 * @caps: capability info
 *
 * Internal routine populating capability info with
 * NUMA node mapping details
 *
 * Does nothing when the system doesn't support NUMA (not an error).
 *
 * Returns 0 in case of success, -1 in case of error
 */
static int
sexpr_to_xend_topology(const struct sexpr *root,
                       virCapsPtr caps)
{
    const char *nodeToCpu;
    const char *cur;
    char *cpuset = NULL;
    int *cpuNums = NULL;
    int cell, cpu, nb_cpus;
    int n = 0;
    int numCpus;

    nodeToCpu = sexpr_node(root, "node/node_to_cpu");
    if (nodeToCpu == NULL)
        return 0;               /* no NUMA support */

    numCpus = sexpr_int(root, "node/nr_cpus");


    if (VIR_ALLOC_N(cpuset, numCpus) < 0)
        goto memory_error;
    if (VIR_ALLOC_N(cpuNums, numCpus) < 0)
        goto memory_error;

    cur = nodeToCpu;
    while (*cur != 0) {
        /*
         * Find the next NUMA cell described in the xend output
         */
        cur = strstr(cur, "node");
        if (cur == NULL)
            break;
        cur += 4;
        cell = virParseNumber(&cur);
        if (cell < 0)
            goto parse_error;
        virSkipSpaces(&cur);
        if (*cur != ':')
            goto parse_error;
        cur++;
        virSkipSpaces(&cur);
        if (STRPREFIX(cur, "no cpus")) {
            nb_cpus = 0;
            for (cpu = 0; cpu < numCpus; cpu++)
                cpuset[cpu] = 0;
        } else {
            nb_cpus = virDomainCpuSetParse(&cur, 'n', cpuset, numCpus);
            if (nb_cpus < 0)
                goto error;
        }

        for (n = 0, cpu = 0; cpu < numCpus; cpu++)
            if (cpuset[cpu] == 1)
                cpuNums[n++] = cpu;

        if (virCapabilitiesAddHostNUMACell(caps,
                                           cell,
                                           nb_cpus,
                                           cpuNums) < 0)
            goto memory_error;
    }
    VIR_FREE(cpuNums);
    VIR_FREE(cpuset);
    return (0);

  parse_error:
    virXendError(VIR_ERR_XEN_CALL, "%s", _("topology syntax error"));
  error:
    VIR_FREE(cpuNums);
    VIR_FREE(cpuset);

    return (-1);

  memory_error:
    VIR_FREE(cpuNums);
    VIR_FREE(cpuset);
    virReportOOMError();
    return (-1);
}


/**
 * sexpr_to_domain:
 * @conn: an existing virtual connection block
 * @root: an S-Expression describing a domain
 *
 * Internal routine returning the associated virDomainPtr for this domain
 *
 * Returns the domain pointer or NULL in case of error.
 */
static virDomainPtr
sexpr_to_domain(virConnectPtr conn, const struct sexpr *root)
{
    virDomainPtr ret = NULL;
    unsigned char uuid[VIR_UUID_BUFLEN];
    const char *name;
    const char *tmp;
    xenUnifiedPrivatePtr priv;

    if ((conn == NULL) || (root == NULL))
        return(NULL);

    priv = (xenUnifiedPrivatePtr) conn->privateData;

    if (sexpr_uuid(uuid, root, "domain/uuid") < 0)
        goto error;
    name = sexpr_node(root, "domain/name");
    if (name == NULL)
        goto error;

    ret = virGetDomain(conn, name, uuid);
    if (ret == NULL) return NULL;

    tmp = sexpr_node(root, "domain/domid");
    /* New 3.0.4 XenD will not report a domid for inactive domains,
     * so only error out for old XenD
     */
    if (!tmp && priv->xendConfigVersion < 3)
        goto error;

    if (tmp)
        ret->id = sexpr_int(root, "domain/domid");
    else
        ret->id = -1; /* An inactive domain */

    return (ret);

error:
    virXendError(VIR_ERR_INTERNAL_ERROR,
                 "%s", _("failed to parse Xend domain information"));
    if (ret != NULL)
        virUnrefDomain(ret);
    return(NULL);
}


/*****************************************************************
 ******
 ******
 ******
 ******
             Refactored
 ******
 ******
 ******
 ******
 *****************************************************************/
/**
 * xenDaemonOpen:
 * @conn: an existing virtual connection block
 * @name: optional argument to select a connection type
 * @flags: combination of virDrvOpenFlag(s)
 *
 * Creates a localhost Xen Daemon connection
 *
 * Returns 0 in case of success, -1 in case of error.
 */
virDrvOpenStatus
xenDaemonOpen(virConnectPtr conn,
              virConnectAuthPtr auth ATTRIBUTE_UNUSED,
              int flags ATTRIBUTE_UNUSED)
{
    char *port = NULL;
    int ret = VIR_DRV_OPEN_ERROR;

    /* Switch on the scheme, which we expect to be NULL (file),
     * "http" or "xen".
     */
    if (conn->uri->scheme == NULL) {
        /* It should be a file access */
        if (conn->uri->path == NULL) {
            virXendError(VIR_ERR_NO_CONNECT, __FUNCTION__);
            goto failed;
        }
        if (xenDaemonOpen_unix(conn, conn->uri->path) < 0 ||
            xend_detect_config_version(conn) == -1)
            goto failed;
    }
    else if (STRCASEEQ (conn->uri->scheme, "xen")) {
        /*
         * try first to open the unix socket
         */
        if (xenDaemonOpen_unix(conn, "/var/lib/xend/xend-socket") == 0 &&
            xend_detect_config_version(conn) != -1)
            goto done;

        /*
         * try though http on port 8000
         */
        if (xenDaemonOpen_tcp(conn, "localhost", "8000") < 0 ||
            xend_detect_config_version(conn) == -1)
            goto failed;
    } else if (STRCASEEQ (conn->uri->scheme, "http")) {
        if (conn->uri->port &&
            virAsprintf(&port, "%d", conn->uri->port) == -1) {
            virReportOOMError();
            goto failed;
        }

        if (xenDaemonOpen_tcp(conn,
                              conn->uri->server ? conn->uri->server : "localhost",
                              port ? port : "8000") < 0 ||
            xend_detect_config_version(conn) == -1)
            goto failed;
    } else {
        virXendError(VIR_ERR_NO_CONNECT, __FUNCTION__);
        goto failed;
    }

 done:
    ret = VIR_DRV_OPEN_SUCCESS;

failed:
    VIR_FREE(port);
    return ret;
}


/**
 * xenDaemonClose:
 * @conn: an existing virtual connection block
 *
 * This method should be called when a connection to xend instance
 * initialized with xenDaemonOpen is no longer needed
 * to free the associated resources.
 *
 * Returns 0 in case of success, -1 in case of error
 */
int
xenDaemonClose(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    return 0;
}

/**
 * xenDaemonDomainSuspend:
 * @domain: pointer to the Domain block
 *
 * Pause the domain, the domain is not scheduled anymore though its resources
 * are preserved. Use xenDaemonDomainResume() to resume execution.
 *
 * Returns 0 in case of success, -1 (with errno) in case of error.
 */
int
xenDaemonDomainSuspend(virDomainPtr domain)
{
    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)) {
        virXendError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        return(-1);
    }

    if (domain->id < 0) {
        virXendError(VIR_ERR_OPERATION_INVALID,
                     _("Domain %s isn't running."), domain->name);
        return(-1);
    }

    return xend_op(domain->conn, domain->name, "op", "pause", NULL);
}

/**
 * xenDaemonDomainResume:
 * @xend: pointer to the Xen Daemon block
 * @name: name for the domain
 *
 * Resume the domain after xenDaemonDomainSuspend() has been called
 *
 * Returns 0 in case of success, -1 (with errno) in case of error.
 */
int
xenDaemonDomainResume(virDomainPtr domain)
{
    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)) {
        virXendError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        return(-1);
    }

    if (domain->id < 0) {
        virXendError(VIR_ERR_OPERATION_INVALID,
                     _("Domain %s isn't running."), domain->name);
        return(-1);
    }

    return xend_op(domain->conn, domain->name, "op", "unpause", NULL);
}

/**
 * xenDaemonDomainShutdown:
 * @domain: pointer to the Domain block
 *
 * Shutdown the domain, the OS is requested to properly shutdown
 * and the domain may ignore it.  It will return immediately
 * after queuing the request.
 *
 * Returns 0 in case of success, -1 (with errno) in case of error.
 */
int
xenDaemonDomainShutdown(virDomainPtr domain)
{
    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)) {
        virXendError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        return(-1);
    }

    if (domain->id < 0) {
        virXendError(VIR_ERR_OPERATION_INVALID,
                     _("Domain %s isn't running."), domain->name);
        return(-1);
    }

    return xend_op(domain->conn, domain->name, "op", "shutdown", "reason", "poweroff", NULL);
}

/**
 * xenDaemonDomainReboot:
 * @domain: pointer to the Domain block
 * @flags: extra flags for the reboot operation, not used yet
 *
 * Reboot the domain, the OS is requested to properly shutdown
 * and restart but the domain may ignore it.  It will return immediately
 * after queuing the request.
 *
 * Returns 0 in case of success, -1 (with errno) in case of error.
 */
int
xenDaemonDomainReboot(virDomainPtr domain, unsigned int flags ATTRIBUTE_UNUSED)
{
    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)) {
        virXendError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        return(-1);
    }

    if (domain->id < 0) {
        virXendError(VIR_ERR_OPERATION_INVALID,
                     _("Domain %s isn't running."), domain->name);
        return(-1);
    }

    return xend_op(domain->conn, domain->name, "op", "shutdown", "reason", "reboot", NULL);
}

/**
 * xenDaemonDomainDestroy:
 * @domain: pointer to the Domain block
 *
 * Abruptly halt the domain, the OS is not properly shutdown and the
 * resources allocated for the domain are immediately freed, mounted
 * filesystems will be marked as uncleanly shutdown.
 * After calling this function, the domain's status will change to
 * dying and will go away completely once all of the resources have been
 * unmapped (usually from the backend devices).
 *
 * Returns 0 in case of success, -1 (with errno) in case of error.
 */
int
xenDaemonDomainDestroy(virDomainPtr domain)
{
    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)) {
        virXendError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        return(-1);
    }

    if (domain->id < 0) {
        virXendError(VIR_ERR_OPERATION_INVALID,
                     _("Domain %s isn't running."), domain->name);
        return(-1);
    }

    return xend_op(domain->conn, domain->name, "op", "destroy", NULL);
}

/**
 * xenDaemonDomainGetOSType:
 * @domain: a domain object
 *
 * Get the type of domain operation system.
 *
 * Returns the new string or NULL in case of error, the string must be
 *         freed by the caller.
 */
static char *
xenDaemonDomainGetOSType(virDomainPtr domain)
{
    char *type;
    struct sexpr *root;
    xenUnifiedPrivatePtr priv;

    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)) {
        virXendError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        return(NULL);
    }

    priv = (xenUnifiedPrivatePtr) domain->conn->privateData;

    if (domain->id < 0 && priv->xendConfigVersion < 3)
        return(NULL);

    /* can we ask for a subset ? worth it ? */
    root = sexpr_get(domain->conn, "/xend/domain/%s?detail=1", domain->name);
    if (root == NULL)
        return(NULL);

    if (sexpr_lookup(root, "domain/image/hvm")) {
        type = strdup("hvm");
    } else {
        type = strdup("linux");
    }

    if (type == NULL)
        virReportOOMError();

    sexpr_free(root);

    return(type);
}

/**
 * xenDaemonDomainSave:
 * @domain: pointer to the Domain block
 * @filename: path for the output file
 *
 * This method will suspend a domain and save its memory contents to
 * a file on disk.  Use xenDaemonDomainRestore() to restore a domain after
 * saving.
 * Note that for remote Xen Daemon the file path will be interpreted in
 * the remote host.
 *
 * Returns 0 in case of success, -1 (with errno) in case of error.
 */
int
xenDaemonDomainSave(virDomainPtr domain, const char *filename)
{
    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL) ||
        (filename == NULL)) {
        virXendError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        return(-1);
    }

    if (domain->id < 0) {
        virXendError(VIR_ERR_OPERATION_INVALID,
                     _("Domain %s isn't running."), domain->name);
        return(-1);
    }

    /* We can't save the state of Domain-0, that would mean stopping it too */
    if (domain->id == 0) {
        return(-1);
    }

    return xend_op(domain->conn, domain->name, "op", "save", "file", filename, NULL);
}

/**
 * xenDaemonDomainCoreDump:
 * @domain: pointer to the Domain block
 * @filename: path for the output file
 * @flags: extra flags, currently unused
 *
 * This method will dump the core of a domain on a given file for analysis.
 * Note that for remote Xen Daemon the file path will be interpreted in
 * the remote host.
 *
 * Returns 0 in case of success, -1 in case of error.
 */
static int
xenDaemonDomainCoreDump(virDomainPtr domain, const char *filename,
                        int flags ATTRIBUTE_UNUSED)
{
    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL) ||
        (filename == NULL)) {
        virXendError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        return(-1);
    }

    if (domain->id < 0) {
        virXendError(VIR_ERR_OPERATION_INVALID,
                     _("Domain %s isn't running."), domain->name);
        return(-1);
    }

    return xend_op(domain->conn, domain->name,
                   "op", "dump", "file", filename,
                   "live", (flags & VIR_DUMP_LIVE ? "1" : "0"),
                   "crash", (flags & VIR_DUMP_CRASH ? "1" : "0"),
                   NULL);
}

/**
 * xenDaemonDomainRestore:
 * @conn: pointer to the Xen Daemon block
 * @filename: path for the output file
 *
 * This method will restore a domain saved to disk by xenDaemonDomainSave().
 * Note that for remote Xen Daemon the file path will be interpreted in
 * the remote host.
 *
 * Returns 0 in case of success, -1 (with errno) in case of error.
 */
int
xenDaemonDomainRestore(virConnectPtr conn, const char *filename)
{
    if ((conn == NULL) || (filename == NULL)) {
        /* this should be caught at the interface but ... */
        virXendError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }
    return xend_op(conn, "", "op", "restore", "file", filename, NULL);
}


/**
 * xenDaemonDomainGetMaxMemory:
 * @domain: pointer to the domain block
 *
 * Ask the Xen Daemon for the maximum memory allowed for a domain
 *
 * Returns the memory size in kilobytes or 0 in case of error.
 */
unsigned long
xenDaemonDomainGetMaxMemory(virDomainPtr domain)
{
    unsigned long ret = 0;
    struct sexpr *root;
    xenUnifiedPrivatePtr priv;

    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)) {
        virXendError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        return(-1);
    }

    priv = (xenUnifiedPrivatePtr) domain->conn->privateData;

    if (domain->id < 0 && priv->xendConfigVersion < 3)
        return(-1);

    /* can we ask for a subset ? worth it ? */
    root = sexpr_get(domain->conn, "/xend/domain/%s?detail=1", domain->name);
    if (root == NULL)
        return(0);

    ret = (unsigned long) sexpr_u64(root, "domain/memory") << 10;
    sexpr_free(root);

    return(ret);
}


/**
 * xenDaemonDomainSetMaxMemory:
 * @domain: pointer to the Domain block
 * @memory: The maximum memory in kilobytes
 *
 * This method will set the maximum amount of memory that can be allocated to
 * a domain.  Please note that a domain is able to allocate up to this amount
 * on its own.
 *
 * Returns 0 for success; -1 (with errno) on error
 */
int
xenDaemonDomainSetMaxMemory(virDomainPtr domain, unsigned long memory)
{
    char buf[1024];
    xenUnifiedPrivatePtr priv;

    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)) {
        virXendError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        return(-1);
    }

    priv = (xenUnifiedPrivatePtr) domain->conn->privateData;

    if (domain->id < 0 && priv->xendConfigVersion < 3)
        return(-1);

    snprintf(buf, sizeof(buf), "%lu", VIR_DIV_UP(memory, 1024));
    return xend_op(domain->conn, domain->name, "op", "maxmem_set", "memory",
                   buf, NULL);
}

/**
 * xenDaemonDomainSetMemory:
 * @domain: pointer to the Domain block
 * @memory: The target memory in kilobytes
 *
 * This method will set a target memory allocation for a given domain and
 * request that the guest meet this target.  The guest may or may not actually
 * achieve this target.  When this function returns, it does not signify that
 * the domain has actually reached that target.
 *
 * Memory for a domain can only be allocated up to the maximum memory setting.
 * There is no safe guard for allocations that are too small so be careful
 * when using this function to reduce a domain's memory usage.
 *
 * Returns 0 for success; -1 (with errno) on error
 */
int
xenDaemonDomainSetMemory(virDomainPtr domain, unsigned long memory)
{
    char buf[1024];
    xenUnifiedPrivatePtr priv;

    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)) {
        virXendError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        return(-1);
    }

    priv = (xenUnifiedPrivatePtr) domain->conn->privateData;

    if (domain->id < 0 && priv->xendConfigVersion < 3)
        return(-1);

    snprintf(buf, sizeof(buf), "%lu", VIR_DIV_UP(memory, 1024));
    return xend_op(domain->conn, domain->name, "op", "mem_target_set",
                   "target", buf, NULL);
}


virDomainDefPtr
xenDaemonDomainFetch(virConnectPtr conn,
                     int domid,
                     const char *name,
                     const char *cpus)
{
    struct sexpr *root;
    xenUnifiedPrivatePtr priv;
    virDomainDefPtr def;

    if (name)
        root = sexpr_get(conn, "/xend/domain/%s?detail=1", name);
    else
        root = sexpr_get(conn, "/xend/domain/%d?detail=1", domid);
    if (root == NULL) {
        virXendError(VIR_ERR_XEN_CALL,
                      "%s", _("xenDaemonDomainFetch failed to"
                        " find this domain"));
        return (NULL);
    }

    priv = (xenUnifiedPrivatePtr) conn->privateData;

    if (!(def = xenDaemonParseSxpr(conn,
                                   root,
                                   priv->xendConfigVersion,
                                   cpus)))
        goto cleanup;

cleanup:
    sexpr_free(root);

    return (def);
}


/**
 * xenDaemonDomainDumpXML:
 * @domain: a domain object
 * @flags: potential dump flags
 * @cpus: list of cpu the domain is pinned to.
 *
 * Provide an XML description of the domain.
 *
 * Returns a 0 terminated UTF-8 encoded XML instance, or NULL in case of error.
 *         the caller must free() the returned value.
 */
char *
xenDaemonDomainDumpXML(virDomainPtr domain, int flags, const char *cpus)
{
    xenUnifiedPrivatePtr priv;
    virDomainDefPtr def;
    char *xml;

    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)) {
        virXendError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        return(NULL);
    }
    priv = (xenUnifiedPrivatePtr) domain->conn->privateData;

    if (domain->id < 0 && priv->xendConfigVersion < 3) {
        /* fall-through to the next driver to handle */
        return(NULL);
    }

    if (!(def = xenDaemonDomainFetch(domain->conn,
                                     domain->id,
                                     domain->name,
                                     cpus)))
        return(NULL);

    xml = virDomainDefFormat(def, flags);

    virDomainDefFree(def);

    return xml;
}


/**
 * xenDaemonDomainGetInfo:
 * @domain: a domain object
 * @info: pointer to a virDomainInfo structure allocated by the user
 *
 * This method looks up information about a domain and update the
 * information block provided.
 *
 * Returns 0 in case of success, -1 in case of error
 */
int
xenDaemonDomainGetInfo(virDomainPtr domain, virDomainInfoPtr info)
{
    struct sexpr *root;
    int ret;
    xenUnifiedPrivatePtr priv;

    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL) ||
        (info == NULL)) {
        virXendError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        return(-1);
    }

    priv = (xenUnifiedPrivatePtr) domain->conn->privateData;

    if (domain->id < 0 && priv->xendConfigVersion < 3)
        return(-1);

    root = sexpr_get(domain->conn, "/xend/domain/%s?detail=1", domain->name);
    if (root == NULL)
        return (-1);

    ret = sexpr_to_xend_domain_info(domain, root, info);
    sexpr_free(root);
    return (ret);
}


/**
 * xenDaemonLookupByName:
 * @conn: A xend instance
 * @name: The name of the domain
 *
 * This method looks up information about a domain and returns
 * it in the form of a struct xend_domain.  This should be
 * free()'d when no longer needed.
 *
 * Returns domain info on success; NULL (with errno) on error
 */
virDomainPtr
xenDaemonLookupByName(virConnectPtr conn, const char *domname)
{
    struct sexpr *root;
    virDomainPtr ret = NULL;

    if ((conn == NULL) || (domname == NULL)) {
        virXendError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        return(NULL);
    }

    root = sexpr_get(conn, "/xend/domain/%s?detail=1", domname);
    if (root == NULL)
        goto error;

    ret = sexpr_to_domain(conn, root);

error:
    sexpr_free(root);
    return(ret);
}


/**
 * xenDaemonNodeGetInfo:
 * @conn: pointer to the Xen Daemon block
 * @info: pointer to a virNodeInfo structure allocated by the user
 *
 * Extract hardware information about the node.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
xenDaemonNodeGetInfo(virConnectPtr conn, virNodeInfoPtr info) {
    int ret = -1;
    struct sexpr *root;

    if (!VIR_IS_CONNECT(conn)) {
        virXendError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }
    if (info == NULL) {
        virXendError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }

    root = sexpr_get(conn, "/xend/node/");
    if (root == NULL)
        return (-1);

    ret = sexpr_to_xend_node_info(root, info);
    sexpr_free(root);
    return (ret);
}

/**
 * xenDaemonNodeGetTopology:
 * @conn: pointer to the Xen Daemon block
 * @caps: capabilities info
 *
 * This method retrieves a node's topology information.
 *
 * Returns -1 in case of error, 0 otherwise.
 */
int
xenDaemonNodeGetTopology(virConnectPtr conn,
                         virCapsPtr caps) {
    int ret = -1;
    struct sexpr *root;

    if (!VIR_IS_CONNECT(conn)) {
        virXendError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }

    if (caps == NULL) {
        virXendError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }

    root = sexpr_get(conn, "/xend/node/");
    if (root == NULL) {
        return (-1);
    }

    ret = sexpr_to_xend_topology(root, caps);
    sexpr_free(root);
    return (ret);
}

/**
 * xenDaemonGetVersion:
 * @conn: pointer to the Xen Daemon block
 * @hvVer: return value for the version of the running hypervisor (OUT)
 *
 * Get the version level of the Hypervisor running.
 *
 * Returns -1 in case of error, 0 otherwise. if the version can't be
 *    extracted by lack of capacities returns 0 and @hvVer is 0, otherwise
 *    @hvVer value is major * 1,000,000 + minor * 1,000 + release
 */
int
xenDaemonGetVersion(virConnectPtr conn, unsigned long *hvVer)
{
    struct sexpr *root;
    int major, minor;
    unsigned long version;

    if (!VIR_IS_CONNECT(conn)) {
        virXendError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }
    if (hvVer == NULL) {
        virXendError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }
    root = sexpr_get(conn, "/xend/node/");
    if (root == NULL)
        return(-1);

    major = sexpr_int(root, "node/xen_major");
    minor = sexpr_int(root, "node/xen_minor");
    sexpr_free(root);
    version = major * 1000000 + minor * 1000;
    *hvVer = version;
    return(0);
}


/**
 * xenDaemonListDomains:
 * @conn: pointer to the hypervisor connection
 * @ids: array to collect the list of IDs of active domains
 * @maxids: size of @ids
 *
 * Collect the list of active domains, and store their ID in @maxids
 * TODO: this is quite expensive at the moment since there isn't one
 *       xend RPC providing both name and id for all domains.
 *
 * Returns the number of domain found or -1 in case of error
 */
int
xenDaemonListDomains(virConnectPtr conn, int *ids, int maxids)
{
    struct sexpr *root = NULL;
    int ret = -1;
    struct sexpr *_for_i, *node;
    long id;

    if (maxids == 0)
        return(0);

    if ((ids == NULL) || (maxids < 0))
        goto error;
    root = sexpr_get(conn, "/xend/domain");
    if (root == NULL)
        goto error;

    ret = 0;

    for (_for_i = root, node = root->u.s.car; _for_i->kind == SEXPR_CONS;
         _for_i = _for_i->u.s.cdr, node = _for_i->u.s.car) {
        if (node->kind != SEXPR_VALUE)
            continue;
        id = xenDaemonDomainLookupByName_ids(conn, node->u.value, NULL);
        if (id >= 0)
            ids[ret++] = (int) id;
        if (ret >= maxids)
            break;
    }

error:
    sexpr_free(root);
    return(ret);
}

/**
 * xenDaemonNumOfDomains:
 * @conn: pointer to the hypervisor connection
 *
 * Provides the number of active domains.
 *
 * Returns the number of domain found or -1 in case of error
 */
int
xenDaemonNumOfDomains(virConnectPtr conn)
{
    struct sexpr *root = NULL;
    int ret = -1;
    struct sexpr *_for_i, *node;

    root = sexpr_get(conn, "/xend/domain");
    if (root == NULL)
        goto error;

    ret = 0;

    for (_for_i = root, node = root->u.s.car; _for_i->kind == SEXPR_CONS;
         _for_i = _for_i->u.s.cdr, node = _for_i->u.s.car) {
        if (node->kind != SEXPR_VALUE)
            continue;
        ret++;
    }

error:
    sexpr_free(root);
    return(ret);
}


/**
 * xenDaemonLookupByID:
 * @conn: pointer to the hypervisor connection
 * @id: the domain ID number
 *
 * Try to find a domain based on the hypervisor ID number
 *
 * Returns a new domain object or NULL in case of failure
 */
virDomainPtr
xenDaemonLookupByID(virConnectPtr conn, int id) {
    char *name = NULL;
    unsigned char uuid[VIR_UUID_BUFLEN];
    virDomainPtr ret;

    if (xenDaemonDomainLookupByID(conn, id, &name, uuid) < 0) {
        goto error;
    }

    ret = virGetDomain(conn, name, uuid);
    if (ret == NULL) goto error;

    ret->id = id;
    VIR_FREE(name);
    return (ret);

 error:
    VIR_FREE(name);
    return (NULL);
}

/**
 * xenDaemonDomainSetVcpusFlags:
 * @domain: pointer to domain object
 * @nvcpus: the new number of virtual CPUs for this domain
 * @flags: bitwise-ORd from virDomainVcpuFlags
 *
 * Change virtual CPUs allocation of domain according to flags.
 *
 * Returns 0 on success, -1 if an error message was issued, and -2 if
 * the unified driver should keep trying.
 */
int
xenDaemonDomainSetVcpusFlags(virDomainPtr domain, unsigned int vcpus,
                             unsigned int flags)
{
    char buf[VIR_UUID_BUFLEN];
    xenUnifiedPrivatePtr priv;
    int max;

    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)
        || (vcpus < 1)) {
        virXendError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }

    priv = (xenUnifiedPrivatePtr) domain->conn->privateData;

    if ((domain->id < 0 && priv->xendConfigVersion < 3) ||
        (flags & VIR_DOMAIN_VCPU_MAXIMUM))
        return -2;

    /* With xendConfigVersion 2, only _LIVE is supported.  With
     * xendConfigVersion 3, only _LIVE|_CONFIG is supported for
     * running domains, or _CONFIG for inactive domains.  */
    if (priv->xendConfigVersion < 3) {
        if (flags & VIR_DOMAIN_VCPU_CONFIG) {
            virXendError(VIR_ERR_OPERATION_INVALID, "%s",
                         _("Xend version does not support modifying "
                           "persistent config"));
            return -1;
        }
    } else if (domain->id < 0) {
        if (flags & VIR_DOMAIN_VCPU_LIVE) {
            virXendError(VIR_ERR_OPERATION_INVALID, "%s",
                         _("domain not running"));
            return -1;
        }
    } else {
        if ((flags & (VIR_DOMAIN_VCPU_LIVE | VIR_DOMAIN_VCPU_CONFIG)) !=
            (VIR_DOMAIN_VCPU_LIVE | VIR_DOMAIN_VCPU_CONFIG)) {
            virXendError(VIR_ERR_OPERATION_INVALID, "%s",
                         _("Xend only supports modifying both live and "
                           "persistent config"));
        }
    }

    /* Unfortunately, xend_op does not validate whether this exceeds
     * the maximum.  */
    flags |= VIR_DOMAIN_VCPU_MAXIMUM;
    if ((max = xenDaemonDomainGetVcpusFlags(domain, flags)) < 0) {
        virXendError(VIR_ERR_OPERATION_INVALID, "%s",
                     _("could not determin max vcpus for the domain"));
        return -1;
    }
    if (vcpus > max) {
        virXendError(VIR_ERR_INVALID_ARG,
                     _("requested vcpus is greater than max allowable"
                       " vcpus for the domain: %d > %d"), vcpus, max);
        return -1;
    }

    snprintf(buf, sizeof(buf), "%d", vcpus);
    return xend_op(domain->conn, domain->name, "op", "set_vcpus", "vcpus",
                   buf, NULL);
}

/**
 * xenDaemonDomainPinCpu:
 * @domain: pointer to domain object
 * @vcpu: virtual CPU number
 * @cpumap: pointer to a bit map of real CPUs (in 8-bit bytes)
 * @maplen: length of cpumap in bytes
 *
 * Dynamically change the real CPUs which can be allocated to a virtual CPU.
 * NOTE: The XenD cpu affinity map format changed from "[0,1,2]" to
 *       "0,1,2"
 *       the XenD cpu affinity works only after cset 19579.
 *       there is no fine grained xend version detection possible, so we
 *       use the old format for anything before version 3
 *
 * Returns 0 for success; -1 (with errno) on error
 */
int
xenDaemonDomainPinVcpu(virDomainPtr domain, unsigned int vcpu,
                     unsigned char *cpumap, int maplen)
{
    char buf[VIR_UUID_BUFLEN], mapstr[sizeof(cpumap_t) * 64];
    int i, j;
    xenUnifiedPrivatePtr priv;

    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)
     || (cpumap == NULL) || (maplen < 1) || (maplen > (int)sizeof(cpumap_t))) {
        virXendError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }

    priv = (xenUnifiedPrivatePtr) domain->conn->privateData;
    if (priv->xendConfigVersion < 3) {
        mapstr[0] = '[';
        mapstr[1] = 0;
    } else {
        mapstr[0] = 0;
    }

    /* from bit map, build character string of mapped CPU numbers */
    for (i = 0; i < maplen; i++) for (j = 0; j < 8; j++)
     if (cpumap[i] & (1 << j)) {
        snprintf(buf, sizeof(buf), "%d,", (8 * i) + j);
        strcat(mapstr, buf);
    }
    if (priv->xendConfigVersion < 3)
        mapstr[strlen(mapstr) - 1] = ']';
    else
        mapstr[strlen(mapstr) - 1] = 0;

    snprintf(buf, sizeof(buf), "%d", vcpu);
    return(xend_op(domain->conn, domain->name, "op", "pincpu", "vcpu", buf,
                  "cpumap", mapstr, NULL));
}

/**
 * xenDaemonDomainGetVcpusFlags:
 * @domain: pointer to domain object
 * @flags: bitwise-ORd from virDomainVcpuFlags
 *
 * Extract information about virtual CPUs of domain according to flags.
 *
 * Returns the number of vcpus on success, -1 if an error message was
 * issued, and -2 if the unified driver should keep trying.

 */
int
xenDaemonDomainGetVcpusFlags(virDomainPtr domain, unsigned int flags)
{
    struct sexpr *root;
    int ret;
    xenUnifiedPrivatePtr priv;

    if (domain == NULL || domain->conn == NULL || domain->name == NULL) {
        virXendError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        return -1;
    }

    priv = (xenUnifiedPrivatePtr) domain->conn->privateData;

    /* If xendConfigVersion is 2, then we can only report _LIVE (and
     * xm_internal reports _CONFIG).  If it is 3, then _LIVE and
     * _CONFIG are always in sync for a running system.  */
    if (domain->id < 0 && priv->xendConfigVersion < 3)
        return -2;
    if (domain->id < 0 && (flags & VIR_DOMAIN_VCPU_LIVE)) {
        virXendError(VIR_ERR_OPERATION_INVALID, "%s",
                     _("domain not active"));
        return -1;
    }

    root = sexpr_get(domain->conn, "/xend/domain/%s?detail=1", domain->name);
    if (root == NULL)
        return -1;

    ret = sexpr_int(root, "domain/vcpus");
    if (!(flags & VIR_DOMAIN_VCPU_MAXIMUM)) {
        int vcpus = count_one_bits_l(sexpr_u64(root, "domain/vcpu_avail"));
        if (vcpus)
            ret = MIN(vcpus, ret);
    }
    if (!ret)
        ret = -2;
    sexpr_free(root);
    return ret;
}

/**
 * virDomainGetVcpus:
 * @domain: pointer to domain object, or NULL for Domain0
 * @info: pointer to an array of virVcpuInfo structures (OUT)
 * @maxinfo: number of structures in info array
 * @cpumaps: pointer to an bit map of real CPUs for all vcpus of this domain (in 8-bit bytes) (OUT)
 *	If cpumaps is NULL, then no cpumap information is returned by the API.
 *	It's assumed there is <maxinfo> cpumap in cpumaps array.
 *	The memory allocated to cpumaps must be (maxinfo * maplen) bytes
 *	(ie: calloc(maxinfo, maplen)).
 *	One cpumap inside cpumaps has the format described in virDomainPinVcpu() API.
 * @maplen: number of bytes in one cpumap, from 1 up to size of CPU map in
 *	underlying virtualization system (Xen...).
 *
 * Extract information about virtual CPUs of domain, store it in info array
 * and also in cpumaps if this pointer isn't NULL.
 *
 * Returns the number of info filled in case of success, -1 in case of failure.
 */
int
xenDaemonDomainGetVcpus(virDomainPtr domain, virVcpuInfoPtr info, int maxinfo,
                        unsigned char *cpumaps, int maplen)
{
    struct sexpr *root, *s, *t;
    virVcpuInfoPtr ipt = info;
    int nbinfo = 0, oln;
    unsigned char *cpumap;
    int vcpu, cpu;

    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)
        || (info == NULL) || (maxinfo < 1)) {
        virXendError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }
    if (cpumaps != NULL && maplen < 1) {
        virXendError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }

    root = sexpr_get(domain->conn, "/xend/domain/%s?op=vcpuinfo", domain->name);
    if (root == NULL)
        return (-1);

    if (cpumaps != NULL)
        memset(cpumaps, 0, maxinfo * maplen);

    /* scan the sexprs from "(vcpu (number x)...)" and get parameter values */
    for (s = root; s->kind == SEXPR_CONS; s = s->u.s.cdr) {
        if ((s->u.s.car->kind == SEXPR_CONS) &&
            (s->u.s.car->u.s.car->kind == SEXPR_VALUE) &&
            STREQ(s->u.s.car->u.s.car->u.value, "vcpu")) {
            t = s->u.s.car;
            vcpu = ipt->number = sexpr_int(t, "vcpu/number");
            if ((oln = sexpr_int(t, "vcpu/online")) != 0) {
                if (sexpr_int(t, "vcpu/running")) ipt->state = VIR_VCPU_RUNNING;
                if (sexpr_int(t, "vcpu/blocked")) ipt->state = VIR_VCPU_BLOCKED;
            }
            else
                ipt->state = VIR_VCPU_OFFLINE;
            ipt->cpuTime = sexpr_float(t, "vcpu/cpu_time") * 1000000000;
            ipt->cpu = oln ? sexpr_int(t, "vcpu/cpu") : -1;

            if (cpumaps != NULL && vcpu >= 0 && vcpu < maxinfo) {
                cpumap = (unsigned char *) VIR_GET_CPUMAP(cpumaps, maplen, vcpu);
                /*
                 * get sexpr from "(cpumap (x y z...))" and convert values
                 * to bitmap
                 */
                for (t = t->u.s.cdr; t->kind == SEXPR_CONS; t = t->u.s.cdr)
                    if ((t->u.s.car->kind == SEXPR_CONS) &&
                        (t->u.s.car->u.s.car->kind == SEXPR_VALUE) &&
                        STREQ(t->u.s.car->u.s.car->u.value, "cpumap") &&
                        (t->u.s.car->u.s.cdr->kind == SEXPR_CONS)) {
                        for (t = t->u.s.car->u.s.cdr->u.s.car; t->kind == SEXPR_CONS; t = t->u.s.cdr)
                            if (t->u.s.car->kind == SEXPR_VALUE
                                && virStrToLong_i(t->u.s.car->u.value, NULL, 10, &cpu) == 0
                                && cpu >= 0
                                && (VIR_CPU_MAPLEN(cpu+1) <= maplen)) {
                                VIR_USE_CPU(cpumap, cpu);
                            }
                        break;
                    }
            }

            if (++nbinfo == maxinfo) break;
            ipt++;
        }
    }
    sexpr_free(root);
    return(nbinfo);
}

/**
 * xenDaemonLookupByUUID:
 * @conn: pointer to the hypervisor connection
 * @uuid: the raw UUID for the domain
 *
 * Try to lookup a domain on xend based on its UUID.
 *
 * Returns a new domain object or NULL in case of failure
 */
virDomainPtr
xenDaemonLookupByUUID(virConnectPtr conn, const unsigned char *uuid)
{
    virDomainPtr ret;
    char *name = NULL;
    int id = -1;
    xenUnifiedPrivatePtr priv = (xenUnifiedPrivatePtr) conn->privateData;

    /* Old approach for xen <= 3.0.3 */
    if (priv->xendConfigVersion < 3) {
        char **names, **tmp;
        unsigned char ident[VIR_UUID_BUFLEN];
        names = xenDaemonListDomainsOld(conn);
        tmp = names;

        if (names == NULL) {
            return (NULL);
        }
        while (*tmp != NULL) {
            id = xenDaemonDomainLookupByName_ids(conn, *tmp, &ident[0]);
            if (id >= 0) {
                if (!memcmp(uuid, ident, VIR_UUID_BUFLEN)) {
                    name = strdup(*tmp);

                    if (name == NULL)
                        virReportOOMError();

                    break;
                }
            }
            tmp++;
        }
        VIR_FREE(names);
    } else { /* New approach for xen >= 3.0.4 */
        char *domname = NULL;
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        struct sexpr *root = NULL;

        virUUIDFormat(uuid, uuidstr);
        root = sexpr_get(conn, "/xend/domain/%s?detail=1", uuidstr);
        if (root == NULL)
            return (NULL);
        domname = (char*)sexpr_node(root, "domain/name");
        if (sexpr_node(root, "domain/domid")) /* only active domains have domid */
            id = sexpr_int(root, "domain/domid");
        else
            id = -1;

        if (domname) {
            name = strdup(domname);

            if (name == NULL)
                virReportOOMError();
        }

        sexpr_free(root);
    }

    if (name == NULL)
        return (NULL);

    ret = virGetDomain(conn, name, uuid);
    if (ret == NULL) goto cleanup;

    ret->id = id;

  cleanup:
    VIR_FREE(name);
    return (ret);
}

/**
 * xenDaemonCreateXML:
 * @conn: pointer to the hypervisor connection
 * @xmlDesc: an XML description of the domain
 * @flags: an optional set of virDomainFlags
 *
 * Launch a new Linux guest domain, based on an XML description similar
 * to the one returned by virDomainGetXMLDesc()
 * This function may requires privileged access to the hypervisor.
 *
 * Returns a new domain object or NULL in case of failure
 */
static virDomainPtr
xenDaemonCreateXML(virConnectPtr conn, const char *xmlDesc,
                     unsigned int flags)
{
    int ret;
    char *sexpr;
    virDomainPtr dom = NULL;
    xenUnifiedPrivatePtr priv;
    virDomainDefPtr def;

    virCheckFlags(0, NULL);

    priv = (xenUnifiedPrivatePtr) conn->privateData;

    if (!(def = virDomainDefParseString(priv->caps,
                                        xmlDesc,
                                        VIR_DOMAIN_XML_INACTIVE)))
        return (NULL);

    if (!(sexpr = xenDaemonFormatSxpr(conn, def, priv->xendConfigVersion))) {
        virDomainDefFree(def);
        return (NULL);
    }

    ret = xenDaemonDomainCreateXML(conn, sexpr);
    VIR_FREE(sexpr);
    if (ret != 0) {
        goto error;
    }

    /* This comes before wait_for_devices, to ensure that latter
       cleanup will destroy the domain upon failure */
    if (!(dom = virDomainLookupByName(conn, def->name)))
        goto error;

    if (xend_wait_for_devices(conn, def->name) < 0)
        goto error;

    if (xenDaemonDomainResume(dom) < 0)
        goto error;

    virDomainDefFree(def);
    return (dom);

  error:
    /* Make sure we don't leave a still-born domain around */
    if (dom != NULL) {
        xenDaemonDomainDestroy(dom);
        virUnrefDomain(dom);
    }
    virDomainDefFree(def);
    return (NULL);
}

/**
 * xenDaemonAttachDeviceFlags:
 * @domain: pointer to domain object
 * @xml: pointer to XML description of device
 * @flags: an OR'ed set of virDomainDeviceModifyFlags
 *
 * Create a virtual device attachment to backend.
 * XML description is translated into S-expression.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
static int
xenDaemonAttachDeviceFlags(virDomainPtr domain, const char *xml,
                           unsigned int flags)
{
    xenUnifiedPrivatePtr priv;
    char *sexpr = NULL;
    int ret = -1;
    virDomainDeviceDefPtr dev = NULL;
    virDomainDefPtr def = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char class[8], ref[80];
    char *target = NULL;

    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)) {
        virXendError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        return -1;
    }

    priv = (xenUnifiedPrivatePtr) domain->conn->privateData;

    if (domain->id < 0) {
        /* Cannot modify live config if domain is inactive */
        if (flags & VIR_DOMAIN_DEVICE_MODIFY_LIVE) {
            virXendError(VIR_ERR_OPERATION_INVALID, "%s",
                         _("Cannot modify live config if domain is inactive"));
            return -1;
        }
        /* If xendConfigVersion < 3 only live config can be changed */
        if (priv->xendConfigVersion < 3) {
            virXendError(VIR_ERR_OPERATION_INVALID, "%s",
                         _("Xend version does not support modifying "
                           "persistent config"));
            return -1;
        }
    } else {
        /* Only live config can be changed if xendConfigVersion < 3 */
        if (priv->xendConfigVersion < 3 &&
            (flags != VIR_DOMAIN_DEVICE_MODIFY_CURRENT &&
             flags != VIR_DOMAIN_DEVICE_MODIFY_LIVE)) {
            virXendError(VIR_ERR_OPERATION_INVALID, "%s",
                         _("Xend version does not support modifying "
                           "persistent config"));
            return -1;
        }
        /* Xen only supports modifying both live and persistent config if
         * xendConfigVersion >= 3
         */
        if (priv->xendConfigVersion >= 3 &&
            (flags != (VIR_DOMAIN_DEVICE_MODIFY_LIVE |
                       VIR_DOMAIN_DEVICE_MODIFY_CONFIG))) {
            virXendError(VIR_ERR_OPERATION_INVALID, "%s",
                         _("Xend only supports modifying both live and "
                           "persistent config"));
            return -1;
        }
    }

    if (!(def = xenDaemonDomainFetch(domain->conn,
                                     domain->id,
                                     domain->name,
                                     NULL)))
        goto cleanup;

    if (!(dev = virDomainDeviceDefParse(priv->caps,
                                        def, xml, VIR_DOMAIN_XML_INACTIVE)))
        goto cleanup;


    switch (dev->type) {
    case VIR_DOMAIN_DEVICE_DISK:
        if (xenDaemonFormatSxprDisk(domain->conn,
                                    dev->data.disk,
                                    &buf,
                                    STREQ(def->os.type, "hvm") ? 1 : 0,
                                    priv->xendConfigVersion, 1) < 0)
            goto cleanup;

        if (dev->data.disk->device != VIR_DOMAIN_DISK_DEVICE_CDROM) {
            if (!(target = strdup(dev->data.disk->dst))) {
                virReportOOMError();
                goto cleanup;
            }
        }
        break;

    case VIR_DOMAIN_DEVICE_NET:
        if (xenDaemonFormatSxprNet(domain->conn,
                                   dev->data.net,
                                   &buf,
                                   STREQ(def->os.type, "hvm") ? 1 : 0,
                                   priv->xendConfigVersion, 1) < 0)
            goto cleanup;

        char macStr[VIR_MAC_STRING_BUFLEN];
        virFormatMacAddr(dev->data.net->mac, macStr);

        if (!(target = strdup(macStr))) {
            virReportOOMError();
            goto cleanup;
        }
        break;

    case VIR_DOMAIN_DEVICE_HOSTDEV:
        if (dev->data.hostdev->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS &&
            dev->data.hostdev->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI) {
            if (xenDaemonFormatSxprOnePCI(dev->data.hostdev,
                                          &buf, 0) < 0)
                goto cleanup;

            virDomainDevicePCIAddress PCIAddr;

            PCIAddr = dev->data.hostdev->source.subsys.u.pci;
            virAsprintf(&target, "PCI device: %.4x:%.2x:%.2x", PCIAddr.domain,
                                 PCIAddr.bus, PCIAddr.slot);

            if (target == NULL) {
                virReportOOMError();
                goto cleanup;
            }
        } else {
            virXendError(VIR_ERR_NO_SUPPORT, "%s",
                         _("unsupported device type"));
            goto cleanup;
        }
        break;

    default:
        virXendError(VIR_ERR_NO_SUPPORT, "%s",
                     _("unsupported device type"));
        goto cleanup;
    }

    sexpr = virBufferContentAndReset(&buf);

    if (virDomainXMLDevID(domain, dev, class, ref, sizeof(ref))) {
        /* device doesn't exist, define it */
        ret = xend_op(domain->conn, domain->name, "op", "device_create",
                      "config", sexpr, NULL);
    } else {
        if (dev->data.disk->device != VIR_DOMAIN_DISK_DEVICE_CDROM) {
            virXendError(VIR_ERR_OPERATION_INVALID,
                         _("target '%s' already exists"), target);
        } else {
            /* device exists, attempt to modify it */
            ret = xend_op(domain->conn, domain->name, "op", "device_configure",
                          "config", sexpr, "dev", ref, NULL);
        }
    }

cleanup:
    VIR_FREE(sexpr);
    virDomainDefFree(def);
    virDomainDeviceDefFree(dev);
    VIR_FREE(target);
    return ret;
}

/**
 * xenDaemonUpdateDeviceFlags:
 * @domain: pointer to domain object
 * @xml: pointer to XML description of device
 * @flags: an OR'ed set of virDomainDeviceModifyFlags
 *
 * Create a virtual device attachment to backend.
 * XML description is translated into S-expression.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
static int
xenDaemonUpdateDeviceFlags(virDomainPtr domain, const char *xml,
                           unsigned int flags)
{
    xenUnifiedPrivatePtr priv;
    char *sexpr = NULL;
    int ret = -1;
    virDomainDeviceDefPtr dev = NULL;
    virDomainDefPtr def = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char class[8], ref[80];

    virCheckFlags(VIR_DOMAIN_DEVICE_MODIFY_CURRENT |
                  VIR_DOMAIN_DEVICE_MODIFY_LIVE |
                  VIR_DOMAIN_DEVICE_MODIFY_CONFIG, -1);

    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)) {
        virXendError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        return -1;
    }

    priv = (xenUnifiedPrivatePtr) domain->conn->privateData;

    if (domain->id < 0) {
        /* Cannot modify live config if domain is inactive */
        if (flags & VIR_DOMAIN_DEVICE_MODIFY_LIVE) {
            virXendError(VIR_ERR_OPERATION_INVALID, "%s",
                         _("Cannot modify live config if domain is inactive"));
            return -1;
        }
        /* If xendConfigVersion < 3 only live config can be changed */
        if (priv->xendConfigVersion < 3) {
            virXendError(VIR_ERR_OPERATION_INVALID, "%s",
                         _("Xend version does not support modifying "
                           "persistent config"));
            return -1;
        }
    } else {
        /* Only live config can be changed if xendConfigVersion < 3 */
        if (priv->xendConfigVersion < 3 &&
            (flags != VIR_DOMAIN_DEVICE_MODIFY_CURRENT &&
             flags != VIR_DOMAIN_DEVICE_MODIFY_LIVE)) {
            virXendError(VIR_ERR_OPERATION_INVALID, "%s",
                         _("Xend version does not support modifying "
                           "persistent config"));
            return -1;
        }
        /* Xen only supports modifying both live and persistent config if
         * xendConfigVersion >= 3
         */
        if (priv->xendConfigVersion >= 3 &&
            (flags != (VIR_DOMAIN_DEVICE_MODIFY_LIVE |
                       VIR_DOMAIN_DEVICE_MODIFY_CONFIG))) {
            virXendError(VIR_ERR_OPERATION_INVALID, "%s",
                         _("Xend only supports modifying both live and "
                           "persistent config"));
            return -1;
        }
    }

    if (!(def = xenDaemonDomainFetch(domain->conn,
                                     domain->id,
                                     domain->name,
                                     NULL)))
        goto cleanup;

    if (!(dev = virDomainDeviceDefParse(priv->caps,
                                        def, xml, VIR_DOMAIN_XML_INACTIVE)))
        goto cleanup;


    switch (dev->type) {
    case VIR_DOMAIN_DEVICE_DISK:
        if (xenDaemonFormatSxprDisk(domain->conn,
                                    dev->data.disk,
                                    &buf,
                                    STREQ(def->os.type, "hvm") ? 1 : 0,
                                    priv->xendConfigVersion, 1) < 0)
            goto cleanup;
        break;

    default:
        virXendError(VIR_ERR_NO_SUPPORT, "%s",
                     _("unsupported device type"));
        goto cleanup;
    }

    sexpr = virBufferContentAndReset(&buf);

    if (virDomainXMLDevID(domain, dev, class, ref, sizeof(ref))) {
        virXendError(VIR_ERR_OPERATION_INVALID, "%s",
                     _("requested device does not exist"));
        goto cleanup;
    } else {
        /* device exists, attempt to modify it */
        ret = xend_op(domain->conn, domain->name, "op", "device_configure",
                      "config", sexpr, "dev", ref, NULL);
    }

cleanup:
    VIR_FREE(sexpr);
    virDomainDefFree(def);
    virDomainDeviceDefFree(dev);
    return ret;
}

/**
 * xenDaemonDetachDeviceFlags:
 * @domain: pointer to domain object
 * @xml: pointer to XML description of device
 * @flags: an OR'ed set of virDomainDeviceModifyFlags
 *
 * Destroy a virtual device attachment to backend.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
static int
xenDaemonDetachDeviceFlags(virDomainPtr domain, const char *xml,
                           unsigned int flags)
{
    xenUnifiedPrivatePtr priv;
    char class[8], ref[80];
    virDomainDeviceDefPtr dev = NULL;
    virDomainDefPtr def = NULL;
    int ret = -1;
    char *xendev = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)) {
        virXendError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }

    priv = (xenUnifiedPrivatePtr) domain->conn->privateData;

    if (domain->id < 0) {
        /* Cannot modify live config if domain is inactive */
        if (flags & VIR_DOMAIN_DEVICE_MODIFY_LIVE) {
            virXendError(VIR_ERR_OPERATION_INVALID, "%s",
                         _("Cannot modify live config if domain is inactive"));
            return -1;
        }
        /* If xendConfigVersion < 3 only live config can be changed */
        if (priv->xendConfigVersion < 3) {
            virXendError(VIR_ERR_OPERATION_INVALID, "%s",
                         _("Xend version does not support modifying "
                           "persistent config"));
            return -1;
        }
    } else {
        /* Only live config can be changed if xendConfigVersion < 3 */
        if (priv->xendConfigVersion < 3 &&
            (flags != VIR_DOMAIN_DEVICE_MODIFY_CURRENT &&
             flags != VIR_DOMAIN_DEVICE_MODIFY_LIVE)) {
            virXendError(VIR_ERR_OPERATION_INVALID, "%s",
                         _("Xend version does not support modifying "
                           "persistent config"));
            return -1;
        }
        /* Xen only supports modifying both live and persistent config if
         * xendConfigVersion >= 3
         */
        if (priv->xendConfigVersion >= 3 &&
            (flags != (VIR_DOMAIN_DEVICE_MODIFY_LIVE |
                       VIR_DOMAIN_DEVICE_MODIFY_CONFIG))) {
            virXendError(VIR_ERR_OPERATION_INVALID, "%s",
                         _("Xend only supports modifying both live and "
                           "persistent config"));
            return -1;
        }
    }

    if (!(def = xenDaemonDomainFetch(domain->conn,
                                     domain->id,
                                     domain->name,
                                     NULL)))
        goto cleanup;

    if (!(dev = virDomainDeviceDefParse(priv->caps,
                                        def, xml, VIR_DOMAIN_XML_INACTIVE)))
        goto cleanup;

    if (virDomainXMLDevID(domain, dev, class, ref, sizeof(ref)))
        goto cleanup;

    if (dev->type == VIR_DOMAIN_DEVICE_HOSTDEV) {
        if (dev->data.hostdev->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS &&
            dev->data.hostdev->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI) {
            if (xenDaemonFormatSxprOnePCI(dev->data.hostdev,
                                          &buf, 1) < 0)
                goto cleanup;
        } else {
            virXendError(VIR_ERR_NO_SUPPORT, "%s",
                         _("unsupported device type"));
            goto cleanup;
        }
        xendev = virBufferContentAndReset(&buf);
        ret = xend_op(domain->conn, domain->name, "op", "device_configure",
                      "config", xendev, "dev", ref, NULL);
        VIR_FREE(xendev);
    }
    else {
        ret = xend_op(domain->conn, domain->name, "op", "device_destroy",
                      "type", class, "dev", ref, "force", "0", "rm_cfg", "1",
                      NULL);
    }

cleanup:
    virDomainDefFree(def);
    virDomainDeviceDefFree(dev);

    return ret;
}

int
xenDaemonDomainGetAutostart(virDomainPtr domain,
                            int *autostart)
{
    struct sexpr *root;
    const char *tmp;
    xenUnifiedPrivatePtr priv;

    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)) {
        virXendError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }

    /* xm_internal.c (the support for defined domains from /etc/xen
     * config files used by old Xen) will handle this.
     */
    priv = (xenUnifiedPrivatePtr) domain->conn->privateData;
    if (priv->xendConfigVersion < 3)
        return(-1);

    root = sexpr_get(domain->conn, "/xend/domain/%s?detail=1", domain->name);
    if (root == NULL) {
        virXendError(VIR_ERR_XEN_CALL,
                      "%s", _("xenDaemonGetAutostart failed to find this domain"));
        return (-1);
    }

    *autostart = 0;

    tmp = sexpr_node(root, "domain/on_xend_start");
    if (tmp && STREQ(tmp, "start")) {
        *autostart = 1;
    }

    sexpr_free(root);
    return 0;
}

int
xenDaemonDomainSetAutostart(virDomainPtr domain,
                            int autostart)
{
    struct sexpr *root, *autonode;
    char buf[4096];
    int ret = -1;
    xenUnifiedPrivatePtr priv;

    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)) {
        virXendError(VIR_ERR_INTERNAL_ERROR, __FUNCTION__);
        return (-1);
    }

    /* xm_internal.c (the support for defined domains from /etc/xen
     * config files used by old Xen) will handle this.
     */
    priv = (xenUnifiedPrivatePtr) domain->conn->privateData;
    if (priv->xendConfigVersion < 3)
        return(-1);

    root = sexpr_get(domain->conn, "/xend/domain/%s?detail=1", domain->name);
    if (root == NULL) {
        virXendError(VIR_ERR_XEN_CALL,
                      "%s", _("xenDaemonSetAutostart failed to find this domain"));
        return (-1);
    }

    autonode = sexpr_lookup(root, "domain/on_xend_start");
    if (autonode) {
        const char *val = (autonode->u.s.car->kind == SEXPR_VALUE
                           ? autonode->u.s.car->u.value : NULL);
        if (!val || (!STREQ(val, "ignore") && !STREQ(val, "start"))) {
            virXendError(VIR_ERR_INTERNAL_ERROR,
                         "%s", _("unexpected value from on_xend_start"));
            goto error;
        }

        /* Change the autostart value in place, then define the new sexpr */
        VIR_FREE(autonode->u.s.car->u.value);
        autonode->u.s.car->u.value = (autostart ? strdup("start")
                                                : strdup("ignore"));
        if (!(autonode->u.s.car->u.value)) {
            virReportOOMError();
            goto error;
        }

        if (sexpr2string(root, buf, sizeof(buf)) == 0) {
            virXendError(VIR_ERR_INTERNAL_ERROR,
                         "%s", _("sexpr2string failed"));
            goto error;
        }
        if (xend_op(domain->conn, "", "op", "new", "config", buf, NULL) != 0) {
            virXendError(VIR_ERR_XEN_CALL,
                         "%s", _("Failed to redefine sexpr"));
            goto error;
        }
    } else {
        virXendError(VIR_ERR_INTERNAL_ERROR,
                     "%s", _("on_xend_start not present in sexpr"));
        goto error;
    }

    ret = 0;
  error:
    sexpr_free(root);
    return ret;
}

int
xenDaemonDomainMigratePrepare (virConnectPtr dconn,
                               char **cookie ATTRIBUTE_UNUSED,
                               int *cookielen ATTRIBUTE_UNUSED,
                               const char *uri_in,
                               char **uri_out,
                               unsigned long flags ATTRIBUTE_UNUSED,
                               const char *dname ATTRIBUTE_UNUSED,
                               unsigned long resource ATTRIBUTE_UNUSED)
{
    /* If uri_in is NULL, get the current hostname as a best guess
     * of how the source host should connect to us.  Note that caller
     * deallocates this string.
     */
    if (uri_in == NULL) {
        *uri_out = virGetHostname(dconn);
        if (*uri_out == NULL)
            return -1;
    }

    return 0;
}

int
xenDaemonDomainMigratePerform (virDomainPtr domain,
                               const char *cookie ATTRIBUTE_UNUSED,
                               int cookielen ATTRIBUTE_UNUSED,
                               const char *uri,
                               unsigned long flags,
                               const char *dname,
                               unsigned long bandwidth)
{
    /* Upper layers have already checked domain. */
    /* NB: Passing port=0 to xend means it ignores
     * the port.  However this is somewhat specific to
     * the internals of the xend Python code. (XXX).
     */
    char port[16] = "0";
    char live[2] = "0";
    int ret;
    char *p, *hostname = NULL;

    int undefined_source = 0;

    /* Xen doesn't support renaming domains during migration. */
    if (dname) {
        virXendError(VIR_ERR_NO_SUPPORT,
                      "%s", _("xenDaemonDomainMigrate: Xen does not support"
                        " renaming domains during migration"));
        return -1;
    }

    /* Xen (at least up to 3.1.0) takes a resource parameter but
     * ignores it.
     */
    if (bandwidth) {
        virXendError(VIR_ERR_NO_SUPPORT,
                      "%s", _("xenDaemonDomainMigrate: Xen does not support"
                        " bandwidth limits during migration"));
        return -1;
    }

    /*
     * Check the flags.
     */
    if ((flags & VIR_MIGRATE_LIVE)) {
        strcpy (live, "1");
        flags &= ~VIR_MIGRATE_LIVE;
    }

    /* Undefine the VM on the source host after migration? */
    if (flags & VIR_MIGRATE_UNDEFINE_SOURCE) {
       undefined_source = 1;
       flags &= ~VIR_MIGRATE_UNDEFINE_SOURCE;
    }

    /* Ignore the persist_dest flag here */
    if (flags & VIR_MIGRATE_PERSIST_DEST)
        flags &= ~VIR_MIGRATE_PERSIST_DEST;

    /* This is buggy in Xend, but could be supported in principle.  Give
     * a nice error message.
     */
    if (flags & VIR_MIGRATE_PAUSED) {
        virXendError(VIR_ERR_NO_SUPPORT,
                      "%s", _("xenDaemonDomainMigrate: xend cannot migrate paused domains"));
        return -1;
    }

    /* XXX we could easily do tunnelled & peer2peer migration too
       if we want to. support these... */
    if (flags != 0) {
        virXendError(VIR_ERR_NO_SUPPORT,
                      "%s", _("xenDaemonDomainMigrate: unsupported flag"));
        return -1;
    }

    /* Set hostname and port.
     *
     * URI is non-NULL (guaranteed by caller).  We expect either
     * "hostname", "hostname:port" or "xenmigr://hostname[:port]/".
     */
    if (strstr (uri, "//")) {   /* Full URI. */
        xmlURIPtr uriptr = xmlParseURI (uri);
        if (!uriptr) {
            virXendError(VIR_ERR_INVALID_ARG,
                          "%s", _("xenDaemonDomainMigrate: invalid URI"));
            return -1;
        }
        if (uriptr->scheme && STRCASENEQ (uriptr->scheme, "xenmigr")) {
            virXendError(VIR_ERR_INVALID_ARG,
                          "%s", _("xenDaemonDomainMigrate: only xenmigr://"
                            " migrations are supported by Xen"));
            xmlFreeURI (uriptr);
            return -1;
        }
        if (!uriptr->server) {
            virXendError(VIR_ERR_INVALID_ARG,
                          "%s", _("xenDaemonDomainMigrate: a hostname must be"
                            " specified in the URI"));
            xmlFreeURI (uriptr);
            return -1;
        }
        hostname = strdup (uriptr->server);
        if (!hostname) {
            virReportOOMError();
            xmlFreeURI (uriptr);
            return -1;
        }
        if (uriptr->port)
            snprintf (port, sizeof port, "%d", uriptr->port);
        xmlFreeURI (uriptr);
    }
    else if ((p = strrchr (uri, ':')) != NULL) { /* "hostname:port" */
        int port_nr, n;

        if (virStrToLong_i(p+1, NULL, 10, &port_nr) < 0) {
            virXendError(VIR_ERR_INVALID_ARG,
                          "%s", _("xenDaemonDomainMigrate: invalid port number"));
            return -1;
        }
        snprintf (port, sizeof port, "%d", port_nr);

        /* Get the hostname. */
        n = p - uri; /* n = Length of hostname in bytes. */
        hostname = strdup (uri);
        if (!hostname) {
            virReportOOMError();
            return -1;
        }
        hostname[n] = '\0';
    }
    else {                      /* "hostname" (or IP address) */
        hostname = strdup (uri);
        if (!hostname) {
            virReportOOMError();
            return -1;
        }
    }

    DEBUG("hostname = %s, port = %s", hostname, port);

    /* Make the call.
     * NB:  xend will fail the operation if any parameters are
     * missing but happily accept unknown parameters.  This works
     * to our advantage since all parameters supported and required
     * by current xend can be included without breaking older xend.
     */
    ret = xend_op (domain->conn, domain->name,
                   "op", "migrate",
                   "destination", hostname,
                   "live", live,
                   "port", port,
                   "node", "-1", /* xen-unstable c/s 17753 */
                   "ssl", "0", /* xen-unstable c/s 17709 */
                   "change_home_server", "0", /* xen-unstable c/s 20326 */
                   "resource", "0", /* removed by xen-unstable c/s 17553 */
                   NULL);
    VIR_FREE (hostname);

    if (ret == 0 && undefined_source)
        xenDaemonDomainUndefine (domain);

    DEBUG0("migration done");

    return ret;
}

virDomainPtr xenDaemonDomainDefineXML(virConnectPtr conn, const char *xmlDesc) {
    int ret;
    char *sexpr;
    virDomainPtr dom;
    xenUnifiedPrivatePtr priv;
    virDomainDefPtr def;

    priv = (xenUnifiedPrivatePtr) conn->privateData;

    if (priv->xendConfigVersion < 3)
        return(NULL);

    if (!(def = virDomainDefParseString(priv->caps, xmlDesc,
                                        VIR_DOMAIN_XML_INACTIVE))) {
        virXendError(VIR_ERR_XML_ERROR,
                     "%s", _("failed to parse domain description"));
        return (NULL);
    }

    if (!(sexpr = xenDaemonFormatSxpr(conn, def, priv->xendConfigVersion))) {
        virXendError(VIR_ERR_XML_ERROR,
                     "%s", _("failed to build sexpr"));
        goto error;
    }

    ret = xend_op(conn, "", "op", "new", "config", sexpr, NULL);
    VIR_FREE(sexpr);
    if (ret != 0) {
        virXendError(VIR_ERR_XEN_CALL,
                     _("Failed to create inactive domain %s"), def->name);
        goto error;
    }

    dom = virDomainLookupByName(conn, def->name);
    if (dom == NULL) {
        goto error;
    }
    virDomainDefFree(def);
    return (dom);

  error:
    virDomainDefFree(def);
    return (NULL);
}
int xenDaemonDomainCreate(virDomainPtr domain)
{
    xenUnifiedPrivatePtr priv;
    int ret;
    virDomainPtr tmp;

    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)) {
        virXendError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        return(-1);
    }

    priv = (xenUnifiedPrivatePtr) domain->conn->privateData;

    if (priv->xendConfigVersion < 3)
        return(-1);

    ret = xend_op(domain->conn, domain->name, "op", "start", NULL);

    if (ret != -1) {
        /* Need to force a refresh of this object's ID */
        tmp = virDomainLookupByName(domain->conn, domain->name);
        if (tmp) {
            domain->id = tmp->id;
            virDomainFree(tmp);
        }
    }
    return ret;
}

int xenDaemonDomainUndefine(virDomainPtr domain)
{
    xenUnifiedPrivatePtr priv;

    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)) {
        virXendError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        return(-1);
    }

    priv = (xenUnifiedPrivatePtr) domain->conn->privateData;

    if (priv->xendConfigVersion < 3)
        return(-1);

    return xend_op(domain->conn, domain->name, "op", "delete", NULL);
}

/**
 * xenDaemonNumOfDomains:
 * @conn: pointer to the hypervisor connection
 *
 * Provides the number of active domains.
 *
 * Returns the number of domain found or -1 in case of error
 */
static int
xenDaemonNumOfDefinedDomains(virConnectPtr conn)
{
    struct sexpr *root = NULL;
    int ret = -1;
    struct sexpr *_for_i, *node;
    xenUnifiedPrivatePtr priv = (xenUnifiedPrivatePtr) conn->privateData;

    /* xm_internal.c (the support for defined domains from /etc/xen
     * config files used by old Xen) will handle this.
     */
    if (priv->xendConfigVersion < 3)
        return(-1);

    root = sexpr_get(conn, "/xend/domain?state=halted");
    if (root == NULL)
        goto error;

    ret = 0;

    for (_for_i = root, node = root->u.s.car; _for_i->kind == SEXPR_CONS;
         _for_i = _for_i->u.s.cdr, node = _for_i->u.s.car) {
        if (node->kind != SEXPR_VALUE)
            continue;
        ret++;
    }

error:
    sexpr_free(root);
    return(ret);
}

static int
xenDaemonListDefinedDomains(virConnectPtr conn, char **const names, int maxnames) {
    struct sexpr *root = NULL;
    int i, ret = -1;
    struct sexpr *_for_i, *node;
    xenUnifiedPrivatePtr priv = (xenUnifiedPrivatePtr) conn->privateData;

    if (priv->xendConfigVersion < 3)
        return(-1);

    if ((names == NULL) || (maxnames < 0))
        goto error;
    if (maxnames == 0)
        return(0);

    root = sexpr_get(conn, "/xend/domain?state=halted");
    if (root == NULL)
        goto error;

    ret = 0;

    for (_for_i = root, node = root->u.s.car; _for_i->kind == SEXPR_CONS;
         _for_i = _for_i->u.s.cdr, node = _for_i->u.s.car) {
        if (node->kind != SEXPR_VALUE)
            continue;

        if ((names[ret++] = strdup(node->u.value)) == NULL) {
            virReportOOMError();
            goto error;
        }

        if (ret >= maxnames)
            break;
    }

cleanup:
    sexpr_free(root);
    return(ret);

error:
    for (i = 0; i < ret; ++i)
        VIR_FREE(names[i]);

    ret = -1;

    goto cleanup;
}

/**
 * xenDaemonGetSchedulerType:
 * @domain: pointer to the Domain block
 * @nparams: give a number of scheduler parameters
 *
 * Get the scheduler type of Xen
 *
 * Returns a scheduler name (credit or sedf) which must be freed by the
 * caller or NULL in case of failure
 */
static char *
xenDaemonGetSchedulerType(virDomainPtr domain, int *nparams)
{
    xenUnifiedPrivatePtr priv;
    struct sexpr *root;
    const char *ret = NULL;
    char *schedulertype = NULL;

    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)
        || (nparams == NULL)) {
        virXendError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        return NULL;
    }

    /* Support only xendConfigVersion >=4 */
    priv = (xenUnifiedPrivatePtr) domain->conn->privateData;
    if (priv->xendConfigVersion < 4) {
        virXendError(VIR_ERR_NO_SUPPORT,
                      "%s", _("unsupported in xendConfigVersion < 4"));
        return NULL;
    }

    root = sexpr_get(domain->conn, "/xend/node/");
    if (root == NULL)
        return NULL;

    /* get xen_scheduler from xend/node */
    ret = sexpr_node(root, "node/xen_scheduler");
    if (ret == NULL){
        virXendError(VIR_ERR_INTERNAL_ERROR,
                     "%s", _("node information incomplete, missing scheduler name"));
        goto error;
    }
    if (STREQ (ret, "credit")) {
        schedulertype = strdup("credit");
        if (schedulertype == NULL){
            virReportOOMError();
            goto error;
        }
        *nparams = XEN_SCHED_CRED_NPARAM;
    } else if (STREQ (ret, "sedf")) {
        schedulertype = strdup("sedf");
        if (schedulertype == NULL){
            virReportOOMError();
            goto error;
        }
        *nparams = XEN_SCHED_SEDF_NPARAM;
    } else {
        virXendError(VIR_ERR_INTERNAL_ERROR, "%s", _("Unknown scheduler"));
        goto error;
    }

error:
    sexpr_free(root);
    return schedulertype;

}

static const char *str_weight = "weight";
static const char *str_cap = "cap";

/**
 * xenDaemonGetSchedulerParameters:
 * @domain: pointer to the Domain block
 * @params: pointer to scheduler parameters
 *          This memory area must be allocated by the caller
 * @nparams: a number of scheduler parameters which should be same as a
 *           given number from xenDaemonGetSchedulerType()
 *
 * Get the scheduler parameters
 *
 * Returns 0 or -1 in case of failure
 */
static int
xenDaemonGetSchedulerParameters(virDomainPtr domain,
                                virSchedParameterPtr params, int *nparams)
{
    xenUnifiedPrivatePtr priv;
    struct sexpr *root;
    char *sched_type = NULL;
    int sched_nparam = 0;
    int ret = -1;

    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)
        || (params == NULL) || (nparams == NULL)) {
        virXendError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }

    /* Support only xendConfigVersion >=4 */
    priv = (xenUnifiedPrivatePtr) domain->conn->privateData;
    if (priv->xendConfigVersion < 4) {
        virXendError(VIR_ERR_NO_SUPPORT,
                      "%s", _("unsupported in xendConfigVersion < 4"));
        return (-1);
    }

    /* look up the information by domain name */
    root = sexpr_get(domain->conn, "/xend/domain/%s?detail=1", domain->name);
    if (root == NULL)
        return (-1);

    /* get the scheduler type */
    sched_type = xenDaemonGetSchedulerType(domain, &sched_nparam);
    if (sched_type == NULL) {
        virXendError(VIR_ERR_INTERNAL_ERROR,
                     "%s", _("Failed to get a scheduler name"));
        goto error;
    }

    switch (sched_nparam){
        case XEN_SCHED_SEDF_NPARAM:
            /* TODO: Implement for Xen/SEDF */
            TODO
            goto error;
        case XEN_SCHED_CRED_NPARAM:
            /* get cpu_weight/cpu_cap from xend/domain */
            if (sexpr_node(root, "domain/cpu_weight") == NULL) {
                virXendError(VIR_ERR_INTERNAL_ERROR,
                        "%s", _("domain information incomplete, missing cpu_weight"));
                goto error;
            }
            if (sexpr_node(root, "domain/cpu_cap") == NULL) {
                virXendError(VIR_ERR_INTERNAL_ERROR,
                        "%s", _("domain information incomplete, missing cpu_cap"));
                goto error;
            }

            if (virStrcpyStatic(params[0].field, str_weight) == NULL) {
                virXendError(VIR_ERR_INTERNAL_ERROR,
                             _("Weight %s too big for destination"),
                             str_weight);
                goto error;
            }
            params[0].type = VIR_DOMAIN_SCHED_FIELD_UINT;
            params[0].value.ui = sexpr_int(root, "domain/cpu_weight");

            if (virStrcpyStatic(params[1].field, str_cap) == NULL) {
                virXendError(VIR_ERR_INTERNAL_ERROR,
                             _("Cap %s too big for destination"), str_cap);
                goto error;
            }
            params[1].type = VIR_DOMAIN_SCHED_FIELD_UINT;
            params[1].value.ui = sexpr_int(root, "domain/cpu_cap");
            *nparams = XEN_SCHED_CRED_NPARAM;
            ret = 0;
            break;
        default:
            virXendError(VIR_ERR_INTERNAL_ERROR, "%s", _("Unknown scheduler"));
            goto error;
    }

error:
    sexpr_free(root);
    VIR_FREE(sched_type);
    return (ret);
}

/**
 * xenDaemonSetSchedulerParameters:
 * @domain: pointer to the Domain block
 * @params: pointer to scheduler parameters
 * @nparams: a number of scheduler setting parameters
 *
 * Set the scheduler parameters
 *
 * Returns 0 or -1 in case of failure
 */
static int
xenDaemonSetSchedulerParameters(virDomainPtr domain,
                                virSchedParameterPtr params, int nparams)
{
    xenUnifiedPrivatePtr priv;
    struct sexpr *root;
    char *sched_type = NULL;
    int i;
    int sched_nparam = 0;
    int ret = -1;

    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)
        || (params == NULL)) {
        virXendError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }

    /* Support only xendConfigVersion >=4 and active domains */
    priv = (xenUnifiedPrivatePtr) domain->conn->privateData;
    if (priv->xendConfigVersion < 4) {
        virXendError(VIR_ERR_NO_SUPPORT,
                      "%s", _("unsupported in xendConfigVersion < 4"));
        return (-1);
    }

    /* look up the information by domain name */
    root = sexpr_get(domain->conn, "/xend/domain/%s?detail=1", domain->name);
    if (root == NULL)
        return (-1);

    /* get the scheduler type */
    sched_type = xenDaemonGetSchedulerType(domain, &sched_nparam);
    if (sched_type == NULL) {
        virXendError(VIR_ERR_INTERNAL_ERROR,
                     "%s", _("Failed to get a scheduler name"));
        goto error;
    }

    switch (sched_nparam){
        case XEN_SCHED_SEDF_NPARAM:
            /* TODO: Implement for Xen/SEDF */
            TODO
            goto error;
        case XEN_SCHED_CRED_NPARAM: {
            char buf_weight[VIR_UUID_BUFLEN];
            char buf_cap[VIR_UUID_BUFLEN];
            const char *weight = NULL;
            const char *cap = NULL;

            /* get the scheduler parameters */
            memset(&buf_weight, 0, VIR_UUID_BUFLEN);
            memset(&buf_cap, 0, VIR_UUID_BUFLEN);
            for (i = 0; i < nparams; i++) {
                if (STREQ (params[i].field, str_weight) &&
                    params[i].type == VIR_DOMAIN_SCHED_FIELD_UINT) {
                    snprintf(buf_weight, sizeof(buf_weight), "%u", params[i].value.ui);
                } else if (STREQ (params[i].field, str_cap) &&
                    params[i].type == VIR_DOMAIN_SCHED_FIELD_UINT) {
                    snprintf(buf_cap, sizeof(buf_cap), "%u", params[i].value.ui);
                } else {
                    virXendError(VIR_ERR_INVALID_ARG, __FUNCTION__);
                    goto error;
                }
            }

            /* if not get the scheduler parameter, set the current setting */
            if (strlen(buf_weight) == 0) {
                weight = sexpr_node(root, "domain/cpu_weight");
                if (weight == NULL) {
                    virXendError(VIR_ERR_INTERNAL_ERROR,
                                "%s", _("domain information incomplete, missing cpu_weight"));
                    goto error;
                }
                snprintf(buf_weight, sizeof(buf_weight), "%s", weight);
            }
            if (strlen(buf_cap) == 0) {
                cap = sexpr_node(root, "domain/cpu_cap");
                if (cap == NULL) {
                    virXendError(VIR_ERR_INTERNAL_ERROR,
                                "%s", _("domain information incomplete, missing cpu_cap"));
                    goto error;
                }
                snprintf(buf_cap, sizeof(buf_cap), "%s", cap);
            }

            ret = xend_op(domain->conn, domain->name, "op",
                          "domain_sched_credit_set", "weight", buf_weight,
                          "cap", buf_cap, NULL);
            break;
        }
        default:
            virXendError(VIR_ERR_INTERNAL_ERROR, "%s", _("Unknown scheduler"));
            goto error;
    }

error:
    sexpr_free(root);
    VIR_FREE(sched_type);
    return (ret);
}

/**
 * xenDaemonDomainBlockPeek:
 * @domain: domain object
 * @path: path to the file or device
 * @offset: offset
 * @size: size
 * @buffer: return buffer
 *
 * Returns 0 if successful, -1 if error, -2 if declined.
 */
int
xenDaemonDomainBlockPeek (virDomainPtr domain, const char *path,
                          unsigned long long offset, size_t size,
                          void *buffer)
{
    xenUnifiedPrivatePtr priv;
    struct sexpr *root = NULL;
    int fd = -1, ret = -1;
    int found = 0, i;
    virDomainDefPtr def;

    priv = (xenUnifiedPrivatePtr) domain->conn->privateData;

    if (domain->id < 0 && priv->xendConfigVersion < 3)
        return -2;              /* Decline, allow XM to handle it. */

    /* Security check: The path must correspond to a block device. */
    if (domain->id > 0)
        root = sexpr_get (domain->conn, "/xend/domain/%d?detail=1",
                          domain->id);
    else if (domain->id < 0)
        root = sexpr_get (domain->conn, "/xend/domain/%s?detail=1",
                          domain->name);
    else {
        /* This call always fails for dom0. */
        virXendError(VIR_ERR_NO_SUPPORT,
                      "%s", _("domainBlockPeek is not supported for dom0"));
        return -1;
    }

    if (!root) {
        virXendError(VIR_ERR_XEN_CALL, __FUNCTION__);
        return -1;
    }

    if (!(def = xenDaemonParseSxpr(domain->conn, root, priv->xendConfigVersion, NULL)))
        goto cleanup;

    for (i = 0 ; i < def->ndisks ; i++) {
        if (def->disks[i]->src &&
            STREQ(def->disks[i]->src, path)) {
            found = 1;
            break;
        }
    }
    if (!found) {
        virXendError(VIR_ERR_INVALID_ARG,
                      _("%s: invalid path"), path);
        goto cleanup;
    }

    /* The path is correct, now try to open it and get its size. */
    fd = open (path, O_RDONLY);
    if (fd == -1) {
        virReportSystemError(errno,
                             _("failed to open for reading: %s"),
                             path);
        goto cleanup;
    }

    /* Seek and read. */
    /* NB. Because we configure with AC_SYS_LARGEFILE, off_t should
     * be 64 bits on all platforms.
     */
    if (lseek (fd, offset, SEEK_SET) == (off_t) -1 ||
        saferead (fd, buffer, size) == (ssize_t) -1) {
        virReportSystemError(errno,
                             _("failed to lseek or read from file: %s"),
                             path);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FORCE_CLOSE(fd);
    sexpr_free(root);
    virDomainDefFree(def);
    return ret;
}

struct xenUnifiedDriver xenDaemonDriver = {
    xenDaemonOpen,               /* open */
    xenDaemonClose,              /* close */
    xenDaemonGetVersion,         /* version */
    NULL,                        /* hostname */
    xenDaemonNodeGetInfo,        /* nodeGetInfo */
    NULL,                        /* getCapabilities */
    xenDaemonListDomains,        /* listDomains */
    xenDaemonNumOfDomains,       /* numOfDomains */
    xenDaemonCreateXML,          /* domainCreateXML */
    xenDaemonDomainSuspend,      /* domainSuspend */
    xenDaemonDomainResume,       /* domainResume */
    xenDaemonDomainShutdown,     /* domainShutdown */
    xenDaemonDomainReboot,       /* domainReboot */
    xenDaemonDomainDestroy,      /* domainDestroy */
    xenDaemonDomainGetOSType,    /* domainGetOSType */
    xenDaemonDomainGetMaxMemory, /* domainGetMaxMemory */
    xenDaemonDomainSetMaxMemory, /* domainSetMaxMemory */
    xenDaemonDomainSetMemory,    /* domainMaxMemory */
    xenDaemonDomainGetInfo,      /* domainGetInfo */
    xenDaemonDomainSave,         /* domainSave */
    xenDaemonDomainRestore,      /* domainRestore */
    xenDaemonDomainCoreDump,     /* domainCoreDump */
    xenDaemonDomainPinVcpu,      /* domainPinVcpu */
    xenDaemonDomainGetVcpus,     /* domainGetVcpus */
    xenDaemonListDefinedDomains, /* listDefinedDomains */
    xenDaemonNumOfDefinedDomains,/* numOfDefinedDomains */
    xenDaemonDomainCreate,       /* domainCreate */
    xenDaemonDomainDefineXML,    /* domainDefineXML */
    xenDaemonDomainUndefine,     /* domainUndefine */
    xenDaemonAttachDeviceFlags,       /* domainAttachDeviceFlags */
    xenDaemonDetachDeviceFlags,       /* domainDetachDeviceFlags */
    xenDaemonUpdateDeviceFlags,       /* domainUpdateDeviceFlags */
    xenDaemonDomainGetAutostart, /* domainGetAutostart */
    xenDaemonDomainSetAutostart, /* domainSetAutostart */
    xenDaemonGetSchedulerType,   /* domainGetSchedulerType */
    xenDaemonGetSchedulerParameters, /* domainGetSchedulerParameters */
    xenDaemonSetSchedulerParameters, /* domainSetSchedulerParameters */
};

/************************************************************************
 *									*
 * Converter functions to go from the XML tree to an S-Expr for Xen	*
 *									*
 ************************************************************************/


/**
 * virtDomainParseXMLGraphicsDescVFB:
 * @conn: pointer to the hypervisor connection
 * @node: node containing graphics description
 * @buf: a buffer for the result S-Expr
 *
 * Parse the graphics part of the XML description and add it to the S-Expr
 * in buf.  This is a temporary interface as the S-Expr interface will be
 * replaced by XML-RPC in the future. However the XML format should stay
 * valid over time.
 *
 * Returns 0 in case of success, -1 in case of error
 */
static int
xenDaemonFormatSxprGraphicsNew(virDomainGraphicsDefPtr def,
                               virBufferPtr buf)
{
    if (def->type != VIR_DOMAIN_GRAPHICS_TYPE_SDL &&
        def->type != VIR_DOMAIN_GRAPHICS_TYPE_VNC) {
        virXendError(VIR_ERR_INTERNAL_ERROR,
                     _("unexpected graphics type %d"),
                     def->type);
        return -1;
    }

    virBufferAddLit(buf, "(device (vkbd))");
    virBufferAddLit(buf, "(device (vfb ");

    if (def->type == VIR_DOMAIN_GRAPHICS_TYPE_SDL) {
        virBufferAddLit(buf, "(type sdl)");
        if (def->data.sdl.display)
            virBufferVSprintf(buf, "(display '%s')", def->data.sdl.display);
        if (def->data.sdl.xauth)
            virBufferVSprintf(buf, "(xauthority '%s')", def->data.sdl.xauth);
    } else if (def->type == VIR_DOMAIN_GRAPHICS_TYPE_VNC) {
        virBufferAddLit(buf, "(type vnc)");
        if (def->data.vnc.autoport) {
            virBufferAddLit(buf, "(vncunused 1)");
        } else {
            virBufferAddLit(buf, "(vncunused 0)");
            virBufferVSprintf(buf, "(vncdisplay %d)", def->data.vnc.port-5900);
        }

        if (def->data.vnc.listenAddr)
            virBufferVSprintf(buf, "(vnclisten '%s')", def->data.vnc.listenAddr);
        if (def->data.vnc.auth.passwd)
            virBufferVSprintf(buf, "(vncpasswd '%s')", def->data.vnc.auth.passwd);
        if (def->data.vnc.keymap)
            virBufferVSprintf(buf, "(keymap '%s')", def->data.vnc.keymap);
    }

    virBufferAddLit(buf, "))");

    return 0;
}


static int
xenDaemonFormatSxprGraphicsOld(virDomainGraphicsDefPtr def,
                               virBufferPtr buf,
                               int xendConfigVersion)
{
    if (def->type != VIR_DOMAIN_GRAPHICS_TYPE_SDL &&
        def->type != VIR_DOMAIN_GRAPHICS_TYPE_VNC) {
        virXendError(VIR_ERR_INTERNAL_ERROR,
                     _("unexpected graphics type %d"),
                     def->type);
        return -1;
    }

    if (def->type == VIR_DOMAIN_GRAPHICS_TYPE_SDL) {
        virBufferAddLit(buf, "(sdl 1)");
        if (def->data.sdl.display)
            virBufferVSprintf(buf, "(display '%s')", def->data.sdl.display);
        if (def->data.sdl.xauth)
            virBufferVSprintf(buf, "(xauthority '%s')", def->data.sdl.xauth);
    } else if (def->type == VIR_DOMAIN_GRAPHICS_TYPE_VNC) {
        virBufferAddLit(buf, "(vnc 1)");
        if (xendConfigVersion >= 2) {
            if (def->data.vnc.autoport) {
                virBufferAddLit(buf, "(vncunused 1)");
            } else {
                virBufferAddLit(buf, "(vncunused 0)");
                virBufferVSprintf(buf, "(vncdisplay %d)", def->data.vnc.port-5900);
            }

            if (def->data.vnc.listenAddr)
                virBufferVSprintf(buf, "(vnclisten '%s')", def->data.vnc.listenAddr);
            if (def->data.vnc.auth.passwd)
                virBufferVSprintf(buf, "(vncpasswd '%s')", def->data.vnc.auth.passwd);
            if (def->data.vnc.keymap)
                virBufferVSprintf(buf, "(keymap '%s')", def->data.vnc.keymap);

        }
    }

    return 0;
}

int
xenDaemonFormatSxprChr(virDomainChrDefPtr def,
                       virBufferPtr buf)
{
    const char *type = virDomainChrTypeToString(def->source.type);

    if (!type) {
        virXendError(VIR_ERR_INTERNAL_ERROR,
                     "%s", _("unexpected chr device type"));
        return -1;
    }

    switch (def->source.type) {
    case VIR_DOMAIN_CHR_TYPE_NULL:
    case VIR_DOMAIN_CHR_TYPE_STDIO:
    case VIR_DOMAIN_CHR_TYPE_VC:
    case VIR_DOMAIN_CHR_TYPE_PTY:
        virBufferVSprintf(buf, "%s", type);
        break;

    case VIR_DOMAIN_CHR_TYPE_FILE:
    case VIR_DOMAIN_CHR_TYPE_PIPE:
        virBufferVSprintf(buf, "%s:", type);
        virBufferEscapeSexpr(buf, "%s", def->source.data.file.path);
        break;

    case VIR_DOMAIN_CHR_TYPE_DEV:
        virBufferEscapeSexpr(buf, "%s", def->source.data.file.path);
        break;

    case VIR_DOMAIN_CHR_TYPE_TCP:
        virBufferVSprintf(buf, "%s:%s:%s%s",
                          (def->source.data.tcp.protocol
                           == VIR_DOMAIN_CHR_TCP_PROTOCOL_RAW ?
                           "tcp" : "telnet"),
                          (def->source.data.tcp.host ?
                           def->source.data.tcp.host : ""),
                          (def->source.data.tcp.service ?
                           def->source.data.tcp.service : ""),
                          (def->source.data.tcp.listen ?
                           ",server,nowait" : ""));
        break;

    case VIR_DOMAIN_CHR_TYPE_UDP:
        virBufferVSprintf(buf, "%s:%s:%s@%s:%s", type,
                          (def->source.data.udp.connectHost ?
                           def->source.data.udp.connectHost : ""),
                          (def->source.data.udp.connectService ?
                           def->source.data.udp.connectService : ""),
                          (def->source.data.udp.bindHost ?
                           def->source.data.udp.bindHost : ""),
                          (def->source.data.udp.bindService ?
                           def->source.data.udp.bindService : ""));
        break;

    case VIR_DOMAIN_CHR_TYPE_UNIX:
        virBufferVSprintf(buf, "%s:", type);
        virBufferEscapeSexpr(buf, "%s", def->source.data.nix.path);
        if (def->source.data.nix.listen)
            virBufferAddLit(buf, ",server,nowait");
        break;
    }

    if (virBufferError(buf)) {
        virReportOOMError();
        return -1;
    }

    return 0;
}


/**
 * virDomainParseXMLDiskDesc:
 * @node: node containing disk description
 * @conn: pointer to the hypervisor connection
 * @buf: a buffer for the result S-Expr
 * @xendConfigVersion: xend configuration file format
 *
 * Parse the one disk in the XML description and add it to the S-Expr in buf
 * This is a temporary interface as the S-Expr interface
 * will be replaced by XML-RPC in the future. However the XML format should
 * stay valid over time.
 *
 * Returns 0 in case of success, -1 in case of error.
 */
static int
xenDaemonFormatSxprDisk(virConnectPtr conn ATTRIBUTE_UNUSED,
                        virDomainDiskDefPtr def,
                        virBufferPtr buf,
                        int hvm,
                        int xendConfigVersion,
                        int isAttach)
{
    /* Xend (all versions) put the floppy device config
     * under the hvm (image (os)) block
     */
    if (hvm &&
        def->device == VIR_DOMAIN_DISK_DEVICE_FLOPPY) {
        if (isAttach) {
            virXendError(VIR_ERR_INVALID_ARG,
                     _("Cannot directly attach floppy %s"), def->src);
            return -1;
        }
        return 0;
    }

    /* Xend <= 3.0.2 doesn't include cdrom config here */
    if (hvm &&
        def->device == VIR_DOMAIN_DISK_DEVICE_CDROM &&
        xendConfigVersion == 1) {
        if (isAttach) {
            virXendError(VIR_ERR_INVALID_ARG,
                     _("Cannot directly attach CDROM %s"), def->src);
            return -1;
        }
        return 0;
    }

    if (!isAttach)
        virBufferAddLit(buf, "(device ");

    /* Normally disks are in a (device (vbd ...)) block
     * but blktap disks ended up in a differently named
     * (device (tap ....)) block.... */
    if (def->driverName && STREQ(def->driverName, "tap")) {
        virBufferAddLit(buf, "(tap ");
    } else if (def->driverName && STREQ(def->driverName, "tap2")) {
        virBufferAddLit(buf, "(tap2 ");
    } else {
        virBufferAddLit(buf, "(vbd ");
    }

    if (hvm) {
        /* Xend <= 3.0.2 wants a ioemu: prefix on devices for HVM */
        if (xendConfigVersion == 1) {
            virBufferEscapeSexpr(buf, "(dev 'ioemu:%s')", def->dst);
        } else {
            /* But newer does not */
            virBufferEscapeSexpr(buf, "(dev '%s:", def->dst);
            virBufferVSprintf(buf, "%s')",
                              def->device == VIR_DOMAIN_DISK_DEVICE_CDROM ?
                              "cdrom" : "disk");
        }
    } else if (def->device == VIR_DOMAIN_DISK_DEVICE_CDROM) {
        virBufferEscapeSexpr(buf, "(dev '%s:cdrom')", def->dst);
    } else {
        virBufferEscapeSexpr(buf, "(dev '%s')", def->dst);
    }

    if (def->src) {
        if (def->driverName) {
            if (STREQ(def->driverName, "tap") ||
                STREQ(def->driverName, "tap2")) {
                virBufferEscapeSexpr(buf, "(uname '%s:", def->driverName);
                virBufferEscapeSexpr(buf, "%s:",
                                     def->driverType ? def->driverType : "aio");
                virBufferEscapeSexpr(buf, "%s')", def->src);
            } else {
                virBufferEscapeSexpr(buf, "(uname '%s:", def->driverName);
                virBufferEscapeSexpr(buf, "%s')", def->src);
            }
        } else {
            if (def->type == VIR_DOMAIN_DISK_TYPE_FILE) {
                virBufferEscapeSexpr(buf, "(uname 'file:%s')", def->src);
            } else if (def->type == VIR_DOMAIN_DISK_TYPE_BLOCK) {
                if (def->src[0] == '/')
                    virBufferEscapeSexpr(buf, "(uname 'phy:%s')", def->src);
                else
                    virBufferEscapeSexpr(buf, "(uname 'phy:/dev/%s')",
                                         def->src);
            } else {
                virXendError(VIR_ERR_CONFIG_UNSUPPORTED,
                             _("unsupported disk type %s"),
                             virDomainDiskTypeToString(def->type));
                return -1;
            }
        }
    }

    if (def->readonly)
        virBufferAddLit(buf, "(mode 'r')");
    else if (def->shared)
        virBufferAddLit(buf, "(mode 'w!')");
    else
        virBufferAddLit(buf, "(mode 'w')");

    if (!isAttach)
        virBufferAddLit(buf, ")");

    virBufferAddLit(buf, ")");

    return 0;
}

/**
 * xenDaemonFormatSxprNet
 * @conn: pointer to the hypervisor connection
 * @node: node containing the interface description
 * @buf: a buffer for the result S-Expr
 * @xendConfigVersion: xend configuration file format
 *
 * Parse the one interface the XML description and add it to the S-Expr in buf
 * This is a temporary interface as the S-Expr interface
 * will be replaced by XML-RPC in the future. However the XML format should
 * stay valid over time.
 *
 * Returns 0 in case of success, -1 in case of error.
 */
static int
xenDaemonFormatSxprNet(virConnectPtr conn,
                       virDomainNetDefPtr def,
                       virBufferPtr buf,
                       int hvm,
                       int xendConfigVersion,
                       int isAttach)
{
    const char *script = DEFAULT_VIF_SCRIPT;

    if (def->type != VIR_DOMAIN_NET_TYPE_BRIDGE &&
        def->type != VIR_DOMAIN_NET_TYPE_NETWORK &&
        def->type != VIR_DOMAIN_NET_TYPE_ETHERNET) {
        virXendError(VIR_ERR_INTERNAL_ERROR,
                     _("unsupported network type %d"), def->type);
        return -1;
    }

    if (!isAttach)
        virBufferAddLit(buf, "(device ");

    virBufferAddLit(buf, "(vif ");

    virBufferVSprintf(buf,
                      "(mac '%02x:%02x:%02x:%02x:%02x:%02x')",
                      def->mac[0], def->mac[1], def->mac[2],
                      def->mac[3], def->mac[4], def->mac[5]);

    switch (def->type) {
    case VIR_DOMAIN_NET_TYPE_BRIDGE:
        virBufferEscapeSexpr(buf, "(bridge '%s')", def->data.bridge.brname);
        if (def->data.bridge.script)
            script = def->data.bridge.script;

        virBufferEscapeSexpr(buf, "(script '%s')", script);
        if (def->data.bridge.ipaddr != NULL)
            virBufferEscapeSexpr(buf, "(ip '%s')", def->data.bridge.ipaddr);
        break;

    case VIR_DOMAIN_NET_TYPE_NETWORK:
    {
        virNetworkPtr network =
            virNetworkLookupByName(conn, def->data.network.name);
        char *bridge;

        if (!network) {
            virXendError(VIR_ERR_NO_NETWORK, "%s",
                         def->data.network.name);
            return -1;
        }

        bridge = virNetworkGetBridgeName(network);
        virNetworkFree(network);
        if (!bridge) {
            virXendError(VIR_ERR_INTERNAL_ERROR,
                         _("network %s is not active"),
                         def->data.network.name);
            return -1;
        }
        virBufferEscapeSexpr(buf, "(bridge '%s')", bridge);
        virBufferEscapeSexpr(buf, "(script '%s')", script);
        VIR_FREE(bridge);
    }
    break;

    case VIR_DOMAIN_NET_TYPE_ETHERNET:
        if (def->data.ethernet.script)
            virBufferEscapeSexpr(buf, "(script '%s')",
                                 def->data.ethernet.script);
        if (def->data.ethernet.ipaddr != NULL)
            virBufferEscapeSexpr(buf, "(ip '%s')", def->data.ethernet.ipaddr);
        break;

    case VIR_DOMAIN_NET_TYPE_USER:
    case VIR_DOMAIN_NET_TYPE_SERVER:
    case VIR_DOMAIN_NET_TYPE_CLIENT:
    case VIR_DOMAIN_NET_TYPE_MCAST:
    case VIR_DOMAIN_NET_TYPE_INTERNAL:
    case VIR_DOMAIN_NET_TYPE_DIRECT:
    case VIR_DOMAIN_NET_TYPE_LAST:
        break;
    }

    if (def->ifname != NULL &&
        !STRPREFIX(def->ifname, "vif"))
        virBufferEscapeSexpr(buf, "(vifname '%s')", def->ifname);

    if (!hvm) {
        if (def->model != NULL)
            virBufferEscapeSexpr(buf, "(model '%s')", def->model);
    }
    else if (def->model == NULL) {
        /*
         * apparently (type ioemu) breaks paravirt drivers on HVM so skip
         * this from XEND_CONFIG_MAX_VERS_NET_TYPE_IOEMU
         */
        if (xendConfigVersion <= XEND_CONFIG_MAX_VERS_NET_TYPE_IOEMU)
            virBufferAddLit(buf, "(type ioemu)");
    }
    else if (STREQ(def->model, "netfront")) {
        virBufferAddLit(buf, "(type netfront)");
    }
    else {
        virBufferEscapeSexpr(buf, "(model '%s')", def->model);
        virBufferAddLit(buf, "(type ioemu)");
    }

    if (!isAttach)
        virBufferAddLit(buf, ")");

    virBufferAddLit(buf, ")");

    return 0;
}


static void
xenDaemonFormatSxprPCI(virDomainHostdevDefPtr def,
                       virBufferPtr buf)
{
    virBufferVSprintf(buf, "(dev (domain 0x%04x)(bus 0x%02x)(slot 0x%02x)(func 0x%x))",
                      def->source.subsys.u.pci.domain,
                      def->source.subsys.u.pci.bus,
                      def->source.subsys.u.pci.slot,
                      def->source.subsys.u.pci.function);
}

static int
xenDaemonFormatSxprOnePCI(virDomainHostdevDefPtr def,
                          virBufferPtr buf,
                          int detach)
{
    if (def->managed) {
        virXendError(VIR_ERR_NO_SUPPORT, "%s",
                     _("managed PCI devices not supported with XenD"));
        return -1;
    }

    virBufferAddLit(buf, "(pci ");
    xenDaemonFormatSxprPCI(def, buf);
    if (detach)
        virBufferAddLit(buf, "(state 'Closing')");
    else
        virBufferAddLit(buf, "(state 'Initialising')");
    virBufferAddLit(buf, ")");

    return 0;
}

static int
xenDaemonFormatSxprAllPCI(virDomainDefPtr def,
                          virBufferPtr buf)
{
    int hasPCI = 0;
    int i;

    for (i = 0 ; i < def->nhostdevs ; i++)
        if (def->hostdevs[i]->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS &&
            def->hostdevs[i]->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI)
            hasPCI = 1;

    if (!hasPCI)
        return 0;

    /*
     * With the (domain ...) block we have the following odd setup
     *
     * (device
     *    (pci
     *       (dev (domain 0x0000) (bus 0x00) (slot 0x1b) (func 0x0))
     *       (dev (domain 0x0000) (bus 0x00) (slot 0x13) (func 0x0))
     *    )
     * )
     *
     * Normally there is one (device ...) block per device, but in the
     * weird world of Xen PCI, one (device ...) covers multiple devices.
     */

    virBufferAddLit(buf, "(device (pci ");
    for (i = 0 ; i < def->nhostdevs ; i++) {
        if (def->hostdevs[i]->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS &&
            def->hostdevs[i]->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI) {
            if (def->hostdevs[i]->managed) {
                virXendError(VIR_ERR_NO_SUPPORT, "%s",
                             _("managed PCI devices not supported with XenD"));
                return -1;
            }

            xenDaemonFormatSxprPCI(def->hostdevs[i], buf);
        }
    }
    virBufferAddLit(buf, "))");

    return 0;
}

int
xenDaemonFormatSxprSound(virDomainDefPtr def,
                         virBufferPtr buf)
{
    const char *str;
    int i;

    for (i = 0 ; i < def->nsounds ; i++) {
        if (!(str = virDomainSoundModelTypeToString(def->sounds[i]->model))) {
            virXendError(VIR_ERR_INTERNAL_ERROR,
                         _("unexpected sound model %d"),
                         def->sounds[i]->model);
            return -1;
        }
        if (i)
            virBufferAddChar(buf, ',');
        virBufferEscapeSexpr(buf, "%s", str);
    }

    if (virBufferError(buf)) {
        virReportOOMError();
        return -1;
    }

    return 0;
}


static int
xenDaemonFormatSxprInput(virDomainInputDefPtr input,
                         virBufferPtr buf)
{
    if (input->bus != VIR_DOMAIN_INPUT_BUS_USB)
        return 0;

    if (input->type != VIR_DOMAIN_INPUT_TYPE_MOUSE &&
        input->type != VIR_DOMAIN_INPUT_TYPE_TABLET) {
        virXendError(VIR_ERR_INTERNAL_ERROR,
                     _("unexpected input type %d"), input->type);
        return -1;
    }

    virBufferVSprintf(buf, "(usbdevice %s)",
                      input->type == VIR_DOMAIN_INPUT_TYPE_MOUSE ?
                      "mouse" : "tablet");

    return 0;
}


/* Computing the vcpu_avail bitmask works because MAX_VIRT_CPUS is
   either 32, or 64 on a platform where long is big enough.  */
verify(MAX_VIRT_CPUS <= sizeof(1UL) * CHAR_BIT);

/**
 * xenDaemonFormatSxpr:
 * @conn: pointer to the hypervisor connection
 * @def: domain config definition
 * @xendConfigVersion: xend configuration file format
 *
 * Generate an SEXPR representing the domain configuration.
 *
 * Returns the 0 terminated S-Expr string or NULL in case of error.
 *         the caller must free() the returned value.
 */
char *
xenDaemonFormatSxpr(virConnectPtr conn,
                    virDomainDefPtr def,
                    int xendConfigVersion)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    const char *tmp;
    char *bufout;
    int hvm = 0, i;

    DEBUG0("Formatting domain sexpr");

    virBufferAddLit(&buf, "(vm ");
    virBufferEscapeSexpr(&buf, "(name '%s')", def->name);
    virBufferVSprintf(&buf, "(memory %lu)(maxmem %lu)",
                      VIR_DIV_UP(def->mem.cur_balloon, 1024),
                      VIR_DIV_UP(def->mem.max_balloon, 1024));
    virBufferVSprintf(&buf, "(vcpus %u)", def->maxvcpus);
    /* Computing the vcpu_avail bitmask works because MAX_VIRT_CPUS is
       either 32, or 64 on a platform where long is big enough.  */
    if (def->vcpus < def->maxvcpus)
        virBufferVSprintf(&buf, "(vcpu_avail %lu)", (1UL << def->vcpus) - 1);

    if (def->cpumask) {
        char *ranges = virDomainCpuSetFormat(def->cpumask, def->cpumasklen);
        if (ranges == NULL)
            goto error;
        virBufferEscapeSexpr(&buf, "(cpus '%s')", ranges);
        VIR_FREE(ranges);
    }

    virUUIDFormat(def->uuid, uuidstr);
    virBufferVSprintf(&buf, "(uuid '%s')", uuidstr);

    if (def->description)
        virBufferEscapeSexpr(&buf, "(description '%s')", def->description);

    if (def->os.bootloader) {
        if (def->os.bootloader[0])
            virBufferEscapeSexpr(&buf, "(bootloader '%s')", def->os.bootloader);
        else
            virBufferAddLit(&buf, "(bootloader)");

        if (def->os.bootloaderArgs)
            virBufferEscapeSexpr(&buf, "(bootloader_args '%s')", def->os.bootloaderArgs);
    }

    if (!(tmp = virDomainLifecycleTypeToString(def->onPoweroff))) {
        virXendError(VIR_ERR_INTERNAL_ERROR,
                     _("unexpected lifecycle value %d"), def->onPoweroff);
        goto error;
    }
    virBufferVSprintf(&buf, "(on_poweroff '%s')", tmp);

    if (!(tmp = virDomainLifecycleTypeToString(def->onReboot))) {
        virXendError(VIR_ERR_INTERNAL_ERROR,
                     _("unexpected lifecycle value %d"), def->onReboot);
        goto error;
    }
    virBufferVSprintf(&buf, "(on_reboot '%s')", tmp);

    if (!(tmp = virDomainLifecycleCrashTypeToString(def->onCrash))) {
        virXendError(VIR_ERR_INTERNAL_ERROR,
                     _("unexpected lifecycle value %d"), def->onCrash);
        goto error;
    }
    virBufferVSprintf(&buf, "(on_crash '%s')", tmp);

    /* Set localtime here for current XenD (both PV & HVM) */
    if (def->clock.offset == VIR_DOMAIN_CLOCK_OFFSET_LOCALTIME) {
        if (def->clock.data.timezone) {
            virXendError(VIR_ERR_CONFIG_UNSUPPORTED,
                         "%s", _("configurable timezones are not supported"));
            goto error;
        }

        virBufferAddLit(&buf, "(localtime 1)");
    } else if (def->clock.offset != VIR_DOMAIN_CLOCK_OFFSET_UTC) {
        virXendError(VIR_ERR_CONFIG_UNSUPPORTED,
                     _("unsupported clock offset '%s'"),
                     virDomainClockOffsetTypeToString(def->clock.offset));
        goto error;
    }

    if (!def->os.bootloader) {
        if (STREQ(def->os.type, "hvm"))
            hvm = 1;

        if (hvm)
            virBufferAddLit(&buf, "(image (hvm ");
        else
            virBufferAddLit(&buf, "(image (linux ");

        if (hvm &&
            def->os.loader == NULL) {
            virXendError(VIR_ERR_INTERNAL_ERROR,
                         "%s",_("no HVM domain loader"));
            goto error;
        }

        if (def->os.kernel)
            virBufferEscapeSexpr(&buf, "(kernel '%s')", def->os.kernel);
        if (def->os.initrd)
            virBufferEscapeSexpr(&buf, "(ramdisk '%s')", def->os.initrd);
        if (def->os.root)
            virBufferEscapeSexpr(&buf, "(root '%s')", def->os.root);
        if (def->os.cmdline)
            virBufferEscapeSexpr(&buf, "(args '%s')", def->os.cmdline);

        if (hvm) {
            char bootorder[VIR_DOMAIN_BOOT_LAST+1];
            if (def->os.kernel)
                virBufferEscapeSexpr(&buf, "(loader '%s')", def->os.loader);
            else
                virBufferEscapeSexpr(&buf, "(kernel '%s')", def->os.loader);

            virBufferVSprintf(&buf, "(vcpus %u)", def->maxvcpus);
            if (def->vcpus < def->maxvcpus)
                virBufferVSprintf(&buf, "(vcpu_avail %lu)",
                                  (1UL << def->vcpus) - 1);

            for (i = 0 ; i < def->os.nBootDevs ; i++) {
                switch (def->os.bootDevs[i]) {
                case VIR_DOMAIN_BOOT_FLOPPY:
                    bootorder[i] = 'a';
                    break;
                default:
                case VIR_DOMAIN_BOOT_DISK:
                    bootorder[i] = 'c';
                    break;
                case VIR_DOMAIN_BOOT_CDROM:
                    bootorder[i] = 'd';
                    break;
                case VIR_DOMAIN_BOOT_NET:
                    bootorder[i] = 'n';
                    break;
                }
            }
            if (def->os.nBootDevs == 0) {
                bootorder[0] = 'c';
                bootorder[1] = '\0';
            } else {
                bootorder[def->os.nBootDevs] = '\0';
            }
            virBufferVSprintf(&buf, "(boot %s)", bootorder);

            /* some disk devices are defined here */
            for (i = 0 ; i < def->ndisks ; i++) {
                switch (def->disks[i]->device) {
                case VIR_DOMAIN_DISK_DEVICE_CDROM:
                    /* Only xend <= 3.0.2 wants cdrom config here */
                    if (xendConfigVersion != 1)
                        break;
                    if (!STREQ(def->disks[i]->dst, "hdc") ||
                        def->disks[i]->src == NULL)
                        break;

                    virBufferEscapeSexpr(&buf, "(cdrom '%s')",
                                         def->disks[i]->src);
                    break;

                case VIR_DOMAIN_DISK_DEVICE_FLOPPY:
                    /* all xend versions define floppies here */
                    virBufferEscapeSexpr(&buf, "(%s ", def->disks[i]->dst);
                    virBufferEscapeSexpr(&buf, "'%s')", def->disks[i]->src);
                    break;

                default:
                    break;
                }
            }

            if (def->features & (1 << VIR_DOMAIN_FEATURE_ACPI))
                virBufferAddLit(&buf, "(acpi 1)");
            if (def->features & (1 << VIR_DOMAIN_FEATURE_APIC))
                virBufferAddLit(&buf, "(apic 1)");
            if (def->features & (1 << VIR_DOMAIN_FEATURE_PAE))
                virBufferAddLit(&buf, "(pae 1)");
            if (def->features & (1 << VIR_DOMAIN_FEATURE_HAP))
                virBufferAddLit(&buf, "(hap 1)");

            virBufferAddLit(&buf, "(usb 1)");

            for (i = 0 ; i < def->ninputs ; i++)
                if (xenDaemonFormatSxprInput(def->inputs[i], &buf) < 0)
                    goto error;

            if (def->parallels) {
                virBufferAddLit(&buf, "(parallel ");
                if (xenDaemonFormatSxprChr(def->parallels[0], &buf) < 0)
                    goto error;
                virBufferAddLit(&buf, ")");
            } else {
                virBufferAddLit(&buf, "(parallel none)");
            }
            if (def->serials) {
                virBufferAddLit(&buf, "(serial ");
                if (xenDaemonFormatSxprChr(def->serials[0], &buf) < 0)
                    goto error;
                virBufferAddLit(&buf, ")");
            } else {
                virBufferAddLit(&buf, "(serial none)");
            }

            /* Set localtime here to keep old XenD happy for HVM */
            if (def->clock.offset == VIR_DOMAIN_CLOCK_OFFSET_LOCALTIME)
                virBufferAddLit(&buf, "(localtime 1)");

            if (def->sounds) {
                virBufferAddLit(&buf, "(soundhw '");
                if (xenDaemonFormatSxprSound(def, &buf) < 0)
                    goto error;
                virBufferAddLit(&buf, "')");
            }
        }

        /* get the device emulation model */
        if (def->emulator && (hvm || xendConfigVersion >= 3))
            virBufferEscapeSexpr(&buf, "(device_model '%s')", def->emulator);


        /* PV graphics for xen <= 3.0.4, or HVM graphics for xen <= 3.1.0 */
        if ((!hvm && xendConfigVersion < XEND_CONFIG_MIN_VERS_PVFB_NEWCONF) ||
            (hvm && xendConfigVersion < 4)) {
            if ((def->ngraphics == 1) &&
                xenDaemonFormatSxprGraphicsOld(def->graphics[0],
                                               &buf, xendConfigVersion) < 0)
                goto error;
        }

        virBufferAddLit(&buf, "))");
    }

    for (i = 0 ; i < def->ndisks ; i++)
        if (xenDaemonFormatSxprDisk(conn, def->disks[i],
                                    &buf, hvm, xendConfigVersion, 0) < 0)
            goto error;

    for (i = 0 ; i < def->nnets ; i++)
        if (xenDaemonFormatSxprNet(conn, def->nets[i],
                                   &buf, hvm, xendConfigVersion, 0) < 0)
            goto error;

    if (xenDaemonFormatSxprAllPCI(def, &buf) < 0)
        goto error;

    /* New style PV graphics config xen >= 3.0.4,
     * or HVM graphics config xen >= 3.0.5 */
    if ((xendConfigVersion >= XEND_CONFIG_MIN_VERS_PVFB_NEWCONF && !hvm) ||
        (xendConfigVersion >= 4 && hvm)) {
        if ((def->ngraphics == 1) &&
            xenDaemonFormatSxprGraphicsNew(def->graphics[0], &buf) < 0)
            goto error;
    }

    virBufferAddLit(&buf, ")"); /* closes (vm */

    if (virBufferError(&buf)) {
        virReportOOMError();
        goto error;
    }

    bufout = virBufferContentAndReset(&buf);
    DEBUG("Formatted sexpr: \n%s", bufout);
    return bufout;

error:
    virBufferFreeAndReset(&buf);
    return NULL;
}


/**
 * virDomainXMLDevID:
 * @domain: pointer to domain object
 * @dev: pointer to device config object
 * @class: Xen device class "vbd" or "vif" (OUT)
 * @ref: Xen device reference (OUT)
 *
 * Set class according to XML root, and:
 *  - if disk, copy in ref the target name from description
 *  - if network, get MAC address from description, scan XenStore and
 *    copy in ref the corresponding vif number.
 *  - if pci, get BDF from description, scan XenStore and
 *    copy in ref the corresponding dev number.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
static int
virDomainXMLDevID(virDomainPtr domain,
                  virDomainDeviceDefPtr dev,
                  char *class,
                  char *ref,
                  int ref_len)
{
    xenUnifiedPrivatePtr priv = domain->conn->privateData;
    char *xref;
    char *tmp;

    if (dev->type == VIR_DOMAIN_DEVICE_DISK) {
        if (dev->data.disk->driverName &&
            STREQ(dev->data.disk->driverName, "tap"))
            strcpy(class, "tap");
        else if (dev->data.disk->driverName &&
            STREQ(dev->data.disk->driverName, "tap2"))
            strcpy(class, "tap2");
        else
            strcpy(class, "vbd");

        if (dev->data.disk->dst == NULL)
            return -1;
        xenUnifiedLock(priv);
        xref = xenStoreDomainGetDiskID(domain->conn, domain->id,
                                       dev->data.disk->dst);
        xenUnifiedUnlock(priv);
        if (xref == NULL)
            return -1;

        tmp = virStrcpy(ref, xref, ref_len);
        VIR_FREE(xref);
        if (tmp == NULL)
            return -1;
    } else if (dev->type == VIR_DOMAIN_DEVICE_NET) {
        char mac[30];
        virDomainNetDefPtr def = dev->data.net;
        snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                 def->mac[0], def->mac[1], def->mac[2],
                 def->mac[3], def->mac[4], def->mac[5]);

        strcpy(class, "vif");

        xenUnifiedLock(priv);
        xref = xenStoreDomainGetNetworkID(domain->conn, domain->id,
                                          mac);
        xenUnifiedUnlock(priv);
        if (xref == NULL)
            return -1;

        tmp = virStrcpy(ref, xref, ref_len);
        VIR_FREE(xref);
        if (tmp == NULL)
            return -1;
    } else if (dev->type == VIR_DOMAIN_DEVICE_HOSTDEV &&
               dev->data.hostdev->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS &&
               dev->data.hostdev->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI) {
        char *bdf;
        virDomainHostdevDefPtr def = dev->data.hostdev;

        if (virAsprintf(&bdf, "%04x:%02x:%02x.%0x",
                        def->source.subsys.u.pci.domain,
                        def->source.subsys.u.pci.bus,
                        def->source.subsys.u.pci.slot,
                        def->source.subsys.u.pci.function) < 0) {
            virReportOOMError();
            return -1;
        }

        strcpy(class, "pci");

        xenUnifiedLock(priv);
        xref = xenStoreDomainGetPCIID(domain->conn, domain->id, bdf);
        xenUnifiedUnlock(priv);
        VIR_FREE(bdf);
        if (xref == NULL)
            return -1;

        tmp = virStrcpy(ref, xref, ref_len);
        VIR_FREE(xref);
        if (tmp == NULL)
            return -1;
    } else {
        virXendError(VIR_ERR_NO_SUPPORT,
                     "%s", _("hotplug of device type not supported"));
        return -1;
    }

    return 0;
}
