/*
 * xend_internal.c: access to Xen though the Xen Daemon interface
 *
 * Copyright (C) 2005
 *
 *      Anthony Liguori <aliguori@us.ibm.com>
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

#include "xend_internal.h"
#include "driver.h"
#include "util.h"
#include "sexpr.h"
#include "buf.h"
#include "uuid.h"
#include "xen_unified.h"
#include "xen_internal.h" /* for DOM0_INTERFACE_VERSION */
#include "xs_internal.h" /* To extract VNC port & Serial console TTY */
#include "memory.h"

/* required for cpumap_t */
#include <xen/dom0_ops.h>

#define DEBUG(fmt,...) VIR_DEBUG(__FILE__, fmt,__VA_ARGS__)
#define DEBUG0(msg) VIR_DEBUG(__FILE__, "%s", msg)

#ifndef PROXY

/*
 * The number of Xen scheduler parameters
 */
#define XEN_SCHED_SEDF_NPARAM   6
#define XEN_SCHED_CRED_NPARAM   2

#endif /* PROXY */

/**
 * xend_connection_type:
 *
 * The connection to the Xen Daemon can be done either though a normal TCP
 * socket or a local domain direct connection.
 */
enum xend_connection_type {
    XEND_DOMAIN,
    XEND_TCP,
};

/**
 * xend:
 *
 * Structure associated to a connection to a Xen daemon
 */
struct xend {
    int len;
    int type;
    struct sockaddr *addr;
    struct sockaddr_un addr_un;
    struct sockaddr_in addr_in;
};


#ifndef PROXY
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
virDomainXMLDevID(virDomainPtr domain,
                  virDomainDeviceDefPtr dev,
                  char *class,
                  char *ref,
                  int ref_len);
#endif

static void virXendError(virConnectPtr conn, virErrorNumber error,
                         const char *fmt, ...)
    ATTRIBUTE_FORMAT(printf,3,4);

#define MAX_ERROR_MESSAGE_LEN 1024

/**
 * virXendError:
 * @conn: the connection if available
 * @error: the error number
 * @fmt: format string followed by variable args
 *
 * Handle an error at the xend daemon interface
 */
static void
virXendError(virConnectPtr conn, virErrorNumber error,
             const char *fmt, ...)
{
    va_list args;
    char msg[MAX_ERROR_MESSAGE_LEN];
    const char *msg2;

    if (fmt) {
        va_start (args, fmt);
        vsnprintf (msg, sizeof (msg), fmt, args);
        va_end (args);
    } else {
        msg[0] = '\0';
    }

    msg2 = __virErrorMsg (error, fmt ? msg : NULL);
    __virRaiseError(conn, NULL, NULL, VIR_FROM_XEND, error, VIR_ERR_ERROR,
                    msg2, msg, NULL, 0, 0, msg2, msg);
}

/**
 * virXendErrorInt:
 * @conn: the connection if available
 * @error: the error number
 * @val: extra integer information
 *
 * Handle an error at the xend daemon interface
 */
static void
virXendErrorInt(virConnectPtr conn, virErrorNumber error, int val)
{
    const char *errmsg;

    if (error == VIR_ERR_OK)
        return;

    errmsg = __virErrorMsg(error, NULL);
    __virRaiseError(conn, NULL, NULL, VIR_FROM_XEND, error, VIR_ERR_ERROR,
                    errmsg, NULL, NULL, val, 0, errmsg, val);
}

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
    int serrno;
    int no_slow_start = 1;
    xenUnifiedPrivatePtr priv = (xenUnifiedPrivatePtr) xend->privateData;

    s = socket(priv->type, SOCK_STREAM, 0);
    if (s == -1) {
        virXendError(xend, VIR_ERR_INTERNAL_ERROR,
                     _("failed to create a socket"));
        return -1;
    }

    /*
     * try to desactivate slow-start
     */
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (void *)&no_slow_start,
               sizeof(no_slow_start));


    if (connect(s, priv->addr, priv->len) == -1) {
        serrno = errno;
        close(s);
        errno = serrno;
        s = -1;

        /*
         * Connecting to XenD as root is mandatory, so log this error
         */
        if (getuid() == 0) {
            virXendError(xend, VIR_ERR_INTERNAL_ERROR,
                         _("failed to connect to xend"));
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
wr_sync(virConnectPtr xend, int fd, void *buffer, size_t size, int do_read)
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
                virXendError(xend, VIR_ERR_INTERNAL_ERROR,
                             _("failed to read from Xen Daemon"));
            else
                virXendError(xend, VIR_ERR_INTERNAL_ERROR,
                             _("failed to read from Xen Daemon"));

            return (-1);
        }

        offset += len;
    }

    return offset;
}

/**
 * sread:
 * @xend: the xend connection object
 * @fd:  the file descriptor
 * @buffer: the I/O buffer
 * @size: the size of the I/O
 *
 * Internal routine to do a synchronous read
 *
 * Returns the number of bytes read, or -1 in case of error
 */
static ssize_t
sread(virConnectPtr xend, int fd, void *buffer, size_t size)
{
    return wr_sync(xend, fd, buffer, size, 1);
}

/**
 * swrite:
 * @xend: the xend connection object
 * @fd:  the file descriptor
 * @buffer: the I/O buffer
 * @size: the size of the I/O
 *
 * Internal routine to do a synchronous write
 *
 * Returns the number of bytes written, or -1 in case of error
 */
static ssize_t
swrite(virConnectPtr xend, int fd, const void *buffer, size_t size)
{
    return wr_sync(xend, fd, (void *) buffer, size, 0);
}

/**
 * swrites:
 * @xend: the xend connection object
 * @fd:  the file descriptor
 * @string: the string to write
 *
 * Internal routine to do a synchronous write of a string
 *
 * Returns the number of bytes written, or -1 in case of error
 */
static ssize_t
swrites(virConnectPtr xend, int fd, const char *string)
{
    return swrite(xend, fd, string, strlen(string));
}

/**
 * sreads:
 * @xend: the xend connection object
 * @fd:  the file descriptor
 * @buffer: the I/O buffer
 * @n_buffer: the size of the I/O buffer
 *
 * Internal routine to do a synchronous read of a line
 *
 * Returns the number of bytes read, or -1 in case of error
 */
static ssize_t
sreads(virConnectPtr xend, int fd, char *buffer, size_t n_buffer)
{
    size_t offset;

    if (n_buffer < 1)
        return (-1);

    for (offset = 0; offset < (n_buffer - 1); offset++) {
        ssize_t ret;

        ret = sread(xend, fd, buffer + offset, 1);
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
 * @xend: the xend connection object
 * @fd: the file descriptor
 * @content: the buffer to store the content
 * @n_content: the size of the buffer
 *
 * Read the HTTP response from a Xen Daemon request.
 *
 * Returns the HTTP return code.
 */
static int
xend_req(virConnectPtr xend, int fd, char *content, size_t n_content)
{
    char buffer[4096];
    int content_length = -1;
    int retcode = 0;

    while (sreads(xend, fd, buffer, sizeof(buffer)) > 0) {
        if (STREQ(buffer, "\r\n"))
            break;

        if (istartswith(buffer, "Content-Length: "))
            content_length = atoi(buffer + 16);
        else if (istartswith(buffer, "HTTP/1.1 "))
            retcode = atoi(buffer + 9);
    }

    if (content_length > -1) {
        ssize_t ret;

        if ((unsigned int) content_length > (n_content + 1))
            content_length = n_content - 1;

        ret = sread(xend, fd, content, content_length);
        if (ret < 0)
            return -1;

        content[ret] = 0;
    } else {
        content[0] = 0;
    }

    return retcode;
}

/**
 * xend_get:
 * @xend: pointer to the Xen Daemon structure
 * @path: the path used for the HTTP request
 * @content: the buffer to store the content
 * @n_content: the size of the buffer
 *
 * Do an HTTP GET RPC with the Xen Daemon
 *
 * Returns the HTTP return code or -1 in case or error.
 */
static int
xend_get(virConnectPtr xend, const char *path,
         char *content, size_t n_content)
{
    int ret;
    int s = do_connect(xend);

    if (s == -1)
        return s;

    swrites(xend, s, "GET ");
    swrites(xend, s, path);
    swrites(xend, s, " HTTP/1.1\r\n");

    swrites(xend, s,
            "Host: localhost:8000\r\n"
            "Accept-Encoding: identity\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n" "\r\n");

    ret = xend_req(xend, s, content, n_content);
    close(s);

    if (((ret < 0) || (ret >= 300)) &&
        ((ret != 404) || (!STRPREFIX(path, "/xend/domain/")))) {
        virXendError(xend, VIR_ERR_GET_FAILED,
                     _("xend_get: error from xen daemon: %s"), content);
    }

    return ret;
}

#ifndef PROXY
/**
 * xend_post:
 * @xend: pointer to the Xen Daemon structure
 * @path: the path used for the HTTP request
 * @ops: the information sent for the POST
 * @content: the buffer to store the content
 * @n_content: the size of the buffer
 *
 * Do an HTTP POST RPC with the Xen Daemon, this usually makes changes at the
 * Xen level.
 *
 * Returns the HTTP return code or -1 in case or error.
 */
static int
xend_post(virConnectPtr xend, const char *path, const char *ops,
          char *content, size_t n_content)
{
    char buffer[100];
    int ret;
    int s = do_connect(xend);

    if (s == -1)
        return s;

    swrites(xend, s, "POST ");
    swrites(xend, s, path);
    swrites(xend, s, " HTTP/1.1\r\n");

    swrites(xend, s,
            "Host: localhost:8000\r\n"
            "Accept-Encoding: identity\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: ");
    snprintf(buffer, sizeof(buffer), "%d", (int) strlen(ops));
    swrites(xend ,s, buffer);
    swrites(xend, s, "\r\n\r\n");
    swrites(xend, s, ops);

    ret = xend_req(xend, s, content, n_content);
    close(s);

    if ((ret < 0) || (ret >= 300)) {
        virXendError(xend, VIR_ERR_POST_FAILED,
                     _("xend_post: error from xen daemon: %s"), content);
    } else if ((ret == 202) && (strstr(content, "failed") != NULL)) {
        virXendError(xend, VIR_ERR_POST_FAILED,
                     _("xend_post: error from xen daemon: %s"), content);
        ret = -1;
    } else if (((ret >= 200) && (ret <= 202)) && (strstr(content, "xend.err") != NULL)) {
        /* This is to catch case of things like 'virsh dump Domain-0 foo'
         * which returns a success code, but the word 'xend.err'
         * in body to indicate error :-(
         */
        virXendError(xend, VIR_ERR_POST_FAILED,
                     _("xend_post: error from xen daemon: %s"), content);
        ret = -1;
    }

    return ret;
}
#endif /* ! PROXY */


/**
 * http2unix:
 * @xend: the xend connection object
 * @ret: the http return code
 *
 * Convert the HTTP return code to 0/-1 and set errno if needed
 *
 * Return -1 in case of error code 0 otherwise
 */
static int
http2unix(virConnectPtr xend, int ret)
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
            virXendErrorInt(xend, VIR_ERR_HTTP_ERROR, ret);
            errno = EINVAL;
            break;
    }
    return -1;
}

#ifndef PROXY
/**
 * xend_op_ext:
 * @xend: pointer to the Xen Daemon structure
 * @path: path for the object
 * @error: buffer for the error output
 * @n_error: size of @error
 * @key: the key for the operation
 * @ap: input values to pass to the operation
 *
 * internal routine to run a POST RPC operation to the Xen Daemon
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
static int
xend_op_ext(virConnectPtr xend, const char *path, char *error,
            size_t n_error, const char *key, va_list ap)
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
        virXendError(NULL, VIR_ERR_NO_MEMORY, _("allocate buffer"));
        return -1;
    }

    content = virBufferContentAndReset(&buf);
    ret = http2unix(xend, xend_post(xend, path, content, error, n_error));
    VIR_FREE(content);

    return ret;
}


/**
 * xend_op:
 * @xend: pointer to the Xen Daemon structure
 * @name: the domain name target of this operation
 * @error: buffer for the error output
 * @n_error: size of @error
 * @key: the key for the operation
 * @ap: input values to pass to the operation
 * @...: input values to pass to the operation
 *
 * internal routine to run a POST RPC operation to the Xen Daemon targetting
 * a given domain.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
static int
xend_op(virConnectPtr xend, const char *name, const char *key, ...)
{
    char buffer[1024];
    char error[1024];
    va_list ap;
    int ret;

    snprintf(buffer, sizeof(buffer), "/xend/domain/%s", name);

    va_start(ap, key);
    ret = xend_op_ext(xend, buffer, error, sizeof(error), key, ap);
    va_end(ap);

    return ret;
}

#endif /* ! PROXY */

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
  ATTRIBUTE_FORMAT(printf,2,3);

static struct sexpr *
sexpr_get(virConnectPtr xend, const char *fmt, ...)
{
    char buffer[4096];
    char path[1024];
    va_list ap;
    int ret;

    va_start(ap, fmt);
    vsnprintf(path, sizeof(path), fmt, ap);
    va_end(ap);

    ret = xend_get(xend, path, buffer, sizeof(buffer));
    ret = http2unix(xend ,ret);
    if (ret == -1)
        return NULL;

    return string2sexpr(buffer);
}

/**
 * sexpr_int:
 * @sexpr: an S-Expression
 * @name: the name for the value
 *
 * convenience function to lookup an int value in the S-Expression
 *
 * Returns the value found or 0 if not found (but may not be an error)
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


#ifndef PROXY
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
        virXendError(NULL, VIR_ERR_NO_MEMORY, _("allocate new buffer"));
        return (NULL);
    }
    ptr = buffer;
    for (i = 0; i < len; i++) {
        switch (string[i]) {
            case ' ':
            case '\n':
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
#endif /* ! PROXY */

/* Applicable sound models */
static const char *const sound_models[] = { "sb16", "es1370" };

/**
 * is_sound_model_valid:
 * @model : model string to check against whitelist
 *
 * checks passed model string against whitelist of acceptable models
 *
 * Returns 0 if invalid, 1 otherwise
 */
int is_sound_model_valid(const char *model) {
    int i;

    for (i = 0; i < sizeof(sound_models)/sizeof(*sound_models); ++i) {
        if (STREQ(model, sound_models[i])) {
            return 1;
        }
    }
    return 0;
}

/**
 * is_sound_model_conflict:
 * @model : model string to look for duplicates of
 * @soundstr : soundhw string for the form m1,m2,m3 ...
 *
 * Returns 0 if no conflict, 1 otherwise
 */
int is_sound_model_conflict(const char *model, const char *soundstr) {

    char *dupe;
    char *cur = (char *) soundstr;
    while ((dupe = strstr(cur, model))) {
        if (( (dupe == cur) ||                     // (Start of line |
              (*(dupe - 1) == ',') ) &&            //  Preceded by comma) &
            ( (dupe[strlen(model)] == ',') ||      // (Ends with comma |
               (dupe[strlen(model)] == '\0') ))    //  Ends whole string)
            return 1;
        else
            cur = dupe + strlen(model);
    }
    return 0;
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
    xenUnifiedPrivatePtr priv = (xenUnifiedPrivatePtr) conn->privateData;

    if ((conn == NULL) || (path == NULL))
        return (-1);

    addr = &priv->addr_un;
    addr->sun_family = AF_UNIX;
    memset(addr->sun_path, 0, sizeof(addr->sun_path));
    strncpy(addr->sun_path, path, sizeof(addr->sun_path));

    priv->len = sizeof(addr->sun_family) + strlen(addr->sun_path);
    if ((unsigned int) priv->len > sizeof(addr->sun_path))
        priv->len = sizeof(addr->sun_path);

    priv->addr = (struct sockaddr *) addr;
    priv->type = PF_UNIX;

    return (0);
}

#ifndef PROXY
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
xenDaemonOpen_tcp(virConnectPtr conn, const char *host, int port)
{
    struct in_addr ip;
    struct hostent *pent;
    xenUnifiedPrivatePtr priv;

    if ((conn == NULL) || (host == NULL) || (port <= 0))
        return (-1);

    priv = (xenUnifiedPrivatePtr) conn->privateData;

    pent = gethostbyname(host);
    if (pent == NULL) {
        if (inet_aton(host, &ip) == 0) {
            virXendError(NULL, VIR_ERR_UNKNOWN_HOST,
                         _("gethostbyname failed: %s"), host);
            errno = ESRCH;
            return (-1);
        }
    } else {
        memcpy(&ip, pent->h_addr_list[0], sizeof(ip));
    }

    priv->len = sizeof(struct sockaddr_in);
    priv->addr = (struct sockaddr *) &priv->addr_in;
    priv->type = PF_INET;

    priv->addr_in.sin_family = AF_INET;
    priv->addr_in.sin_port = htons(port);
    memcpy(&priv->addr_in.sin_addr, &ip, sizeof(ip));

    return (0);
}


/**
 * xend_wait_for_devices:
 * @xend: pointer to the Xem Daemon block
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


#endif /* PROXY */


/**
 * xenDaemonListDomainsOld:
 * @xend: pointer to the Xem Daemon block
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

    if (VIR_ALLOC_N(ptr, count + 1 + extra) < 0)
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

#ifndef PROXY
/**
 * xenDaemonDomainCreateLinux:
 * @xend: A xend instance
 * @sexpr: An S-Expr description of the domain.
 *
 * This method will create a domain based the passed in description.  The
 * domain will be paused after creation and must be unpaused with
 * xenDaemonResumeDomain() to begin execution.
 * This method may be deprecated once switching to XML-RPC based communcations
 * with xend.
 *
 * Returns 0 for success, -1 (with errno) on error
 */

int
xenDaemonDomainCreateLinux(virConnectPtr xend, const char *sexpr)
{
    int ret, serrno;
    char *ptr;

    ptr = urlencode(sexpr);
    if (ptr == NULL) {
        /* this should be caught at the interface but ... */
        virXendError(xend, VIR_ERR_INTERNAL_ERROR,
                     _("failed to urlencode the create S-Expr"));
        return (-1);
    }

    ret = xend_op(xend, "", "op", "create", "config", ptr, NULL);

    serrno = errno;
    VIR_FREE(ptr);
    errno = serrno;

    return ret;
}
#endif /* ! PROXY */

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
        virXendError(xend, VIR_ERR_INTERNAL_ERROR,
                     _("domain information incomplete, missing domid"));
        goto error;
    }
    ret = strtol(value, NULL, 0);
    if ((ret == 0) && (value[0] != '0')) {
        virXendError(xend, VIR_ERR_INTERNAL_ERROR,
                     _("domain information incorrect domid not numeric"));
        ret = -1;
    } else if (uuid != NULL) {
        if (sexpr_uuid(uuid, root, "domain/uuid") < 0) {
            virXendError(xend, VIR_ERR_INTERNAL_ERROR,
                         _("domain information incomplete, missing uuid"));
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
      virXendError(xend, VIR_ERR_INTERNAL_ERROR,
                   _("domain information incomplete, missing name"));
      goto error;
    }
    if (domname)
      *domname = strdup(name);

    if (sexpr_uuid(uuid, root, "domain/uuid") < 0) {
      virXendError(xend, VIR_ERR_INTERNAL_ERROR,
                   _("domain information incomplete, missing uuid"));
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


#ifndef PROXY
static int
xend_detect_config_version(virConnectPtr conn) {
    struct sexpr *root;
    const char *value;
    xenUnifiedPrivatePtr priv;

    if (!VIR_IS_CONNECT(conn)) {
        virXendError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
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

#endif /* PROXY */

/*****************************************************************
 ******
 ****** Parsing of SEXPR into virDomainDef objects
 ******
 *****************************************************************/

/**
 * xenDaemonParseSxprOS
 * @xend: the xend connection object
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
xenDaemonParseSxprOS(virConnectPtr xend,
                     const struct sexpr *node,
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
                virXendError(xend, VIR_ERR_INTERNAL_ERROR,
                             _("domain information incomplete, missing HVM loader"));
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
        virXendError(xend, VIR_ERR_INTERNAL_ERROR,
                     _("domain information incomplete, missing kernel & bootloader"));
        return -1;
    }

    return 0;

no_memory:
    virXendError(xend, VIR_ERR_NO_MEMORY, NULL);
    return -1;
}


int
xend_parse_sexp_desc_char(virConnectPtr conn,
                          virBufferPtr buf,
                          const char *devtype,
                          int portNum,
                          const char *value,
                          const char *tty)
{
    const char *type;
    int telnet = 0;
    char *bindPort = NULL;
    char *bindHost = NULL;
    char *connectPort = NULL;
    char *connectHost = NULL;
    char *path = NULL;
    int ret = -1;

    if (value[0] == '/') {
        type = "dev";
    } else if (STRPREFIX(value, "null")) {
        type = "null";
        value = NULL;
    } else if (STRPREFIX(value, "vc")) {
        type = "vc";
        value = NULL;
    } else if (STRPREFIX(value, "pty")) {
        type = "pty";
        value = NULL;
    } else if (STRPREFIX(value, "stdio")) {
        type = "stdio";
        value = NULL;
    } else if (STRPREFIX(value, "file:")) {
        type = "file";
        value += sizeof("file:")-1;
    } else if (STRPREFIX(value, "pipe:")) {
        type = "pipe";
        value += sizeof("pipe:")-1;
    } else if (STRPREFIX(value, "tcp:")) {
        type = "tcp";
        value += sizeof("tcp:")-1;
    } else if (STRPREFIX(value, "telnet:")) {
        type = "tcp";
        value += sizeof("telnet:")-1;
        telnet = 1;
    } else if (STRPREFIX(value, "udp:")) {
        type = "udp";
        value += sizeof("udp:")-1;
    } else if (STRPREFIX(value, "unix:")) {
        type = "unix";
        value += sizeof("unix:")-1;
    } else {
        virXendError(conn, VIR_ERR_INTERNAL_ERROR,
                     _("Unknown char device type"));
        return -1;
    }

    /* Compat with legacy  <console tty='/dev/pts/5'/> syntax */
    if (STREQ(devtype, "console") &&
        STREQ(type, "pty") &&
        tty != NULL) {
        virBufferVSprintf(buf, "    <%s type='%s' tty='%s'>\n",
                          devtype, type, tty);
    } else {
        virBufferVSprintf(buf, "    <%s type='%s'>\n",
                          devtype, type);
    }

    if (STREQ(type, "null") ||
        STREQ(type, "vc") ||
        STREQ(type, "stdio")) {
        /* no source needed */
    } else if (STREQ(type, "pty")) {
        if (tty)
            virBufferVSprintf(buf, "      <source path='%s'/>\n",
                              tty);
    } else if (STREQ(type, "file") ||
               STREQ(type, "pipe")) {
        virBufferVSprintf(buf, "      <source path='%s'/>\n",
                          value);
    } else if (STREQ(type, "tcp")) {
        const char *offset = strchr(value, ':');
        const char *offset2;
        const char *mode, *protocol;

        if (offset == NULL) {
            virXendError(conn, VIR_ERR_INTERNAL_ERROR,
                         _("malformed char device string"));
            goto error;
        }

        if (offset != value &&
            (bindHost = strndup(value, offset - value)) == NULL)
            goto no_memory;

        offset2 = strchr(offset, ',');
        if (offset2 == NULL)
            bindPort = strdup(offset+1);
        else
            bindPort = strndup(offset+1, offset2-(offset+1));
        if (bindPort == NULL)
            goto no_memory;

        if (offset2 && strstr(offset2, ",listen"))
            mode = "bind";
        else
            mode = "connect";
        protocol = telnet ? "telnet":"raw";

        if (bindHost) {
            virBufferVSprintf(buf,
                              "      <source mode='%s' host='%s' service='%s'/>\n",
                              mode, bindHost, bindPort);
        } else {
            virBufferVSprintf(buf,
                              "      <source mode='%s' service='%s'/>\n",
                              mode, bindPort);
        }
        virBufferVSprintf(buf,
                          "      <protocol type='%s'/>\n",
                          protocol);
    } else if (STREQ(type, "udp")) {
        const char *offset = strchr(value, ':');
        const char *offset2, *offset3;

        if (offset == NULL) {
            virXendError(conn, VIR_ERR_INTERNAL_ERROR,
                         _("malformed char device string"));
            goto error;
        }

        if (offset != value &&
            (connectHost = strndup(value, offset - value)) == NULL)
            goto no_memory;

        offset2 = strchr(offset, '@');
        if (offset2 != NULL) {
            if ((connectPort = strndup(offset + 1, offset2-(offset+1))) == NULL)
                goto no_memory;

            offset3 = strchr(offset2, ':');
            if (offset3 == NULL) {
                virXendError(conn, VIR_ERR_INTERNAL_ERROR,
                             _("malformed char device string"));
                goto error;
            }

            if (offset3 > (offset2 + 1) &&
                (bindHost = strndup(offset2 + 1, offset3 - (offset2+1))) == NULL)
                goto no_memory;

            if ((bindPort = strdup(offset3 + 1)) == NULL)
                goto no_memory;
        } else {
            if ((connectPort = strdup(offset + 1)) == NULL)
                goto no_memory;
        }

        if (connectPort) {
            if (connectHost) {
                virBufferVSprintf(buf,
                                  "      <source mode='connect' host='%s' service='%s'/>\n",
                                  connectHost, connectPort);
            } else {
                virBufferVSprintf(buf,
                                  "      <source mode='connect' service='%s'/>\n",
                                  connectPort);
            }
        }
        if (bindPort) {
            if (bindHost) {
                virBufferVSprintf(buf,
                                  "      <source mode='bind' host='%s' service='%s'/>\n",
                                  bindHost, bindPort);
            } else {
                virBufferVSprintf(buf,
                                  "      <source mode='bind' service='%s'/>\n",
                                  bindPort);
            }
        }

    } else if (STREQ(type, "unix")) {
        const char *offset = strchr(value, ',');
        int dolisten = 0;
        if (offset)
            path = strndup(value, (offset - value));
        else
            path = strdup(value);
        if (path == NULL)
            goto no_memory;

        if (offset != NULL &&
            strstr(offset, ",listen") != NULL)
            dolisten = 1;

        virBufferVSprintf(buf, "      <source mode='%s' path='%s'/>\n",
                          dolisten ? "bind" : "connect", path);
    }

    virBufferVSprintf(buf, "      <target port='%d'/>\n",
                      portNum);

    virBufferVSprintf(buf, "    </%s>\n",
                      devtype);

    ret = 0;

    if (ret == -1) {
no_memory:
        virXendError(conn, VIR_ERR_NO_MEMORY,
                     _("no memory for char device config"));
    }

error:

    VIR_FREE(path);
    VIR_FREE(bindHost);
    VIR_FREE(bindPort);
    VIR_FREE(connectHost);
    VIR_FREE(connectPort);

    return ret;
}

virDomainChrDefPtr
xenDaemonParseSxprChar(virConnectPtr conn,
                       const char *value,
                       const char *tty)
{
    char prefix[10];
    char *tmp;
    virDomainChrDefPtr def;

    if (VIR_ALLOC(def) < 0) {
        virXendError(conn, VIR_ERR_NO_MEMORY, NULL);
        return NULL;
    }

    strncpy(prefix, value, sizeof(prefix)-1);
    NUL_TERMINATE(prefix);

    if (value[0] == '/') {
        def->type = VIR_DOMAIN_CHR_TYPE_DEV;
    } else {
        if ((tmp = strchr(prefix, ':')) != NULL) {
            *tmp = '\0';
            value += (tmp - prefix) + 1;
        }

        if (STREQ(prefix, "telnet")) {
            def->type = VIR_DOMAIN_CHR_TYPE_TCP;
            def->data.tcp.protocol = VIR_DOMAIN_CHR_TCP_PROTOCOL_TELNET;
        } else {
            if ((def->type = virDomainChrTypeFromString(prefix)) < 0) {
                virXendError(conn, VIR_ERR_INTERNAL_ERROR,
                             _("unknown chr device type '%s'"), prefix);
                goto error;
            }
        }
    }

    /* Compat with legacy  <console tty='/dev/pts/5'/> syntax */
    switch (def->type) {
    case VIR_DOMAIN_CHR_TYPE_PTY:
        if (tty != NULL &&
            !(def->data.file.path = strdup(tty)))
            goto no_memory;
        break;

    case VIR_DOMAIN_CHR_TYPE_FILE:
    case VIR_DOMAIN_CHR_TYPE_PIPE:
        if (!(def->data.file.path = strdup(value)))
            goto no_memory;
        break;

    case VIR_DOMAIN_CHR_TYPE_TCP:
    {
        const char *offset = strchr(value, ':');
        const char *offset2;

        if (offset == NULL) {
            virXendError(conn, VIR_ERR_INTERNAL_ERROR,
                         _("malformed char device string"));
            goto error;
        }

        if (offset != value &&
            (def->data.tcp.host = strndup(value, offset - value)) == NULL)
            goto no_memory;

        offset2 = strchr(offset, ',');
        if (offset2 == NULL)
            def->data.tcp.service = strdup(offset+1);
        else
            def->data.tcp.service = strndup(offset+1, offset2-(offset+1));
        if (def->data.tcp.service == NULL)
            goto no_memory;

        if (offset2 && strstr(offset2, ",listen"))
            def->data.tcp.listen = 1;
    }
    break;

    case VIR_DOMAIN_CHR_TYPE_UDP:
    {
        const char *offset = strchr(value, ':');
        const char *offset2, *offset3;

        if (offset == NULL) {
            virXendError(conn, VIR_ERR_INTERNAL_ERROR,
                         _("malformed char device string"));
            goto error;
        }

        if (offset != value &&
            (def->data.udp.connectHost = strndup(value, offset - value)) == NULL)
            goto no_memory;

        offset2 = strchr(offset, '@');
        if (offset2 != NULL) {
            if ((def->data.udp.connectService = strndup(offset + 1, offset2-(offset+1))) == NULL)
                goto no_memory;

            offset3 = strchr(offset2, ':');
            if (offset3 == NULL) {
                virXendError(conn, VIR_ERR_INTERNAL_ERROR,
                             _("malformed char device string"));
                goto error;
            }

            if (offset3 > (offset2 + 1) &&
                (def->data.udp.bindHost = strndup(offset2 + 1, offset3 - (offset2+1))) == NULL)
                goto no_memory;

            if ((def->data.udp.bindService = strdup(offset3 + 1)) == NULL)
                goto no_memory;
        } else {
            if ((def->data.udp.connectService = strdup(offset + 1)) == NULL)
                goto no_memory;
        }
    }
    break;

    case VIR_DOMAIN_CHR_TYPE_UNIX:
    {
        const char *offset = strchr(value, ',');
        if (offset)
            def->data.nix.path = strndup(value, (offset - value));
        else
            def->data.nix.path = strdup(value);
        if (def->data.nix.path == NULL)
            goto no_memory;

        if (offset != NULL &&
            strstr(offset, ",listen") != NULL)
            def->data.nix.listen = 1;
    }
    break;
    }

    return def;

no_memory:
    virXendError(conn, VIR_ERR_NO_MEMORY, NULL);
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
xenDaemonParseSxprDisks(virConnectPtr conn,
                        virDomainDefPtr def,
                        const struct sexpr *root,
                        int hvm,
                        int xendConfigVersion)
{
    const struct sexpr *cur, *node;
    virDomainDiskDefPtr disk = NULL, prev = def->disks;

    for (cur = root; cur->kind == SEXPR_CONS; cur = cur->u.s.cdr) {
        node = cur->u.s.car;
        /* Normally disks are in a (device (vbd ...)) block
           but blktap disks ended up in a differently named
           (device (tap ....)) block.... */
        if (sexpr_lookup(node, "device/vbd") ||
            sexpr_lookup(node, "device/tap")) {
            char *offset;
            const char *src = NULL;
            const char *dst = NULL;
            const char *mode = NULL;

            /* Again dealing with (vbd...) vs (tap ...) differences */
            if (sexpr_lookup(node, "device/vbd")) {
                src = sexpr_node(node, "device/vbd/uname");
                dst = sexpr_node(node, "device/vbd/dev");
                mode = sexpr_node(node, "device/vbd/mode");
            } else {
                src = sexpr_node(node, "device/tap/uname");
                dst = sexpr_node(node, "device/tap/dev");
                mode = sexpr_node(node, "device/tap/mode");
            }

            if (VIR_ALLOC(disk) < 0)
                goto no_memory;

            if (dst == NULL) {
                virXendError(conn, VIR_ERR_INTERNAL_ERROR,
                             _("domain information incomplete, vbd has no dev"));
                goto error;
            }

            if (src == NULL) {
                /* There is a case without the uname to the CD-ROM device */
                offset = strchr(dst, ':');
                if (!offset ||
                    !hvm ||
                    STRNEQ(offset, ":cdrom")) {
                    virXendError(conn, VIR_ERR_INTERNAL_ERROR,
                                 _("domain information incomplete, vbd has no src"));
                    goto error;
                }
            }

            if (src != NULL) {
                offset = strchr(src, ':');
                if (!offset) {
                    virXendError(conn, VIR_ERR_INTERNAL_ERROR,
                                 _("cannot parse vbd filename, missing driver name"));
                    goto error;
                }

                if (VIR_ALLOC_N(disk->driverName, (offset-src)+1) < 0)
                    goto no_memory;
                strncpy(disk->driverName, src, (offset-src));
                disk->driverName[offset-src] = '\0';

                src = offset + 1;

                if (STREQ (disk->driverName, "tap")) {
                    offset = strchr(src, ':');
                    if (!offset) {
                        virXendError(conn, VIR_ERR_INTERNAL_ERROR,
                                     _("cannot parse vbd filename, missing driver type"));
                        goto error;
                    }

                    if (VIR_ALLOC_N(disk->driverType, (offset-src)+1)< 0)
                        goto no_memory;
                    strncpy(disk->driverType, src, (offset-src));
                    disk->driverType[offset-src] = '\0';

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

            if (prev)
                prev->next = disk;
            else
                def->disks = disk;

            prev = disk;
            disk = NULL;
        }
    }

    return 0;

no_memory:
    virXendError(conn, VIR_ERR_NO_MEMORY, NULL);

error:
    virDomainDiskDefFree(disk);
    return -1;
}


static int
xenDaemonParseSxprNets(virConnectPtr conn,
                       virDomainDefPtr def,
                       const struct sexpr *root)
{
    virDomainNetDefPtr net = NULL, prev = def->nets;
    const struct sexpr *cur, *node;
    const char *tmp;
    int vif_index = 0;

    for (cur = root; cur->kind == SEXPR_CONS; cur = cur->u.s.cdr) {
        node = cur->u.s.car;
        if (sexpr_lookup(node, "device/vif")) {
            const char *tmp2, *model;
            char buf[50];
            tmp2 = sexpr_node(node, "device/vif/script");
            tmp = sexpr_node(node, "device/vif/bridge");
            model = sexpr_node(node, "device/vif/model");

            if (VIR_ALLOC(net) < 0)
                goto no_memory;

            if ((tmp2 && strstr(tmp2, "bridge")) || tmp) {
                net->type = VIR_DOMAIN_NET_TYPE_BRIDGE;
                /* XXX virtual network reverse resolve */

                if (tmp &&
                    !(net->data.bridge.brname = strdup(tmp)))
                    goto no_memory;
            } else {
                net->type = VIR_DOMAIN_NET_TYPE_ETHERNET;
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
                unsigned int mac[6];
                if (sscanf(tmp, "%02x:%02x:%02x:%02x:%02x:%02x",
                           (unsigned int*)&mac[0],
                           (unsigned int*)&mac[1],
                           (unsigned int*)&mac[2],
                           (unsigned int*)&mac[3],
                           (unsigned int*)&mac[4],
                           (unsigned int*)&mac[5]) != 6) {
                    virXendError(conn, VIR_ERR_INTERNAL_ERROR,
                                 _("malformed mac address '%s'"),
                                 tmp);
                    goto cleanup;
                }
                net->mac[0] = mac[0];
                net->mac[1] = mac[1];
                net->mac[2] = mac[2];
                net->mac[3] = mac[3];
                net->mac[4] = mac[4];
                net->mac[5] = mac[5];
            }

            tmp = sexpr_node(node, "device/vif/ip");
            if (tmp &&
                !(net->data.ethernet.ipaddr = strdup(tmp)))
                goto no_memory;

            if (tmp2 &&
                net->type == VIR_DOMAIN_NET_TYPE_ETHERNET &&
                !(net->data.ethernet.script = strdup(tmp2)))
                goto no_memory;

            if (model &&
                !(net->model = strdup(model)))
                goto no_memory;

            if (prev)
                prev->next = net;
            else
                def->nets = net;
            vif_index++;
        }
    }

    return 0;

no_memory:
    virXendError(conn, VIR_ERR_NO_MEMORY, NULL);
cleanup:
    virDomainNetDefFree(net);
    return -1;
}


int
xenDaemonParseSxprSound(virConnectPtr conn,
                        virDomainDefPtr def,
                        const char *str)
{
    if (STREQ(str, "all")) {
        int i;
        virDomainSoundDefPtr prev = NULL;
        for (i = 0 ; i < VIR_DOMAIN_SOUND_MODEL_LAST ; i++) {
            virDomainSoundDefPtr sound;
            if (VIR_ALLOC(sound) < 0)
                goto no_memory;
            sound->model = i;
            if (prev)
                prev->next = sound;
            else
                def->sounds = sound;
            prev = sound;
        }
    } else {
        char model[10];
        const char *offset = str, *offset2;
        virDomainSoundDefPtr prev = NULL;
        do {
            int len;
            virDomainSoundDefPtr sound;
            offset2 = strchr(offset, ',');
            if (offset2)
                len = (offset2 - offset);
            else
                len = strlen(offset);
            if (len > (sizeof(model)-1)) {
                virXendError(conn, VIR_ERR_INTERNAL_ERROR,
                                 _("unexpected sound model %s"), offset);
                goto error;
            }
            strncpy(model, offset, len);
            model[len] = '\0';

            if (VIR_ALLOC(sound) < 0)
                goto no_memory;

            if ((sound->model = virDomainSoundModelTypeFromString(model)) < 0) {
                VIR_FREE(sound);
                goto error;
            }

            if (prev)
                prev->next = sound;
            else
                def->sounds = sound;
            prev = sound;
            offset = offset2 ? offset2 + 1 : NULL;
        } while (offset);
    }

    return 0;

no_memory:
    virXendError(conn, VIR_ERR_NO_MEMORY, NULL);
error:
    return -1;
}


static int
xenDaemonParseSxprUSB(virConnectPtr conn,
                      virDomainDefPtr def,
                      const struct sexpr *root)
{
    virDomainInputDefPtr prev = def->inputs;
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

                    if (prev)
                        prev->next = input;
                    else
                        def->inputs = input;
                    prev = input;
                } else {
                    /* XXX Handle other non-input USB devices later */
                }
            }
        }
    }
    return 0;

no_memory:
    virXendError(conn, VIR_ERR_NO_MEMORY, NULL);
    return -1;
}

static int
xenDaemonParseSxprGraphicsOld(virConnectPtr conn,
                              virDomainDefPtr def,
                              const struct sexpr *root,
                              int hvm,
                              int xendConfigVersion)
{
    const char *tmp;
    virDomainGraphicsDefPtr graphics = NULL;

    if ((tmp = sexpr_fmt_node(root, "domain/image/%s/vnc", hvm ? "hvm" : "linux")) &&
        tmp[0] == '1') {
        /* Graphics device (HVM, or old (pre-3.0.4) style PV VNC config) */
        int port = xenStoreDomainGetVNCPort(conn, def->id);
        const char *listenAddr = sexpr_fmt_node(root, "domain/image/%s/vnclisten", hvm ? "hvm" : "linux");
        const char *vncPasswd = sexpr_fmt_node(root, "domain/image/%s/vncpasswd", hvm ? "hvm" : "linux");
        const char *keymap = sexpr_fmt_node(root, "domain/image/%s/keymap", hvm ? "hvm" : "linux");
        const char *unused = sexpr_fmt_node(root, "domain/image/%s/vncunused", hvm ? "hvm" : "linux");

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
            !(graphics->data.vnc.passwd = strdup(vncPasswd)))
            goto no_memory;

        if (keymap &&
            !(graphics->data.vnc.keymap = strdup(keymap)))
            goto no_memory;

        def->graphics = graphics;
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

        def->graphics = graphics;
    }

    return 0;

no_memory:
    virXendError(conn, VIR_ERR_NO_MEMORY, NULL);
    virDomainGraphicsDefFree(graphics);
    return -1;
}


static int
xenDaemonParseSxprGraphicsNew(virConnectPtr conn,
                              virDomainDefPtr def,
                              const struct sexpr *root)
{
    virDomainGraphicsDefPtr graphics = NULL;
    const struct sexpr *cur, *node;
    const char *tmp;

    /* append network devices and framebuffer */
    for (cur = root; cur->kind == SEXPR_CONS; cur = cur->u.s.cdr) {
        node = cur->u.s.car;
        if (sexpr_lookup(node, "device/vfb")) {
            /* New style graphics config for PV guests in >= 3.0.4,
             * or for HVM guests in >= 3.0.5 */
            tmp = sexpr_node(node, "device/vfb/type");

            if (VIR_ALLOC(graphics) < 0)
                goto no_memory;

            if ((graphics->type = virDomainGraphicsTypeFromString(tmp)) < 0) {
                virXendError(conn, VIR_ERR_INTERNAL_ERROR,
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
                int port = xenStoreDomainGetVNCPort(conn, def->id);
                if (port == -1) {
                    // Didn't find port entry in xenstore
                    port = sexpr_int(node, "device/vfb/vncdisplay");
                }
                const char *listenAddr = sexpr_node(node, "device/vfb/vnclisten");
                const char *vncPasswd = sexpr_node(node, "device/vfb/vncpasswd");;
                const char *keymap = sexpr_node(node, "device/vfb/keymap");
                const char *unused = sexpr_node(node, "device/vfb/vncunused");

                if ((unused && STREQ(unused, "1")) || port == -1) {
                    graphics->data.vnc.autoport = 1;
                    port = -1;
                }

                if (port >= 0 && port < 5900)
                    port += 5900;
                graphics->data.vnc.port = port;

                if (listenAddr &&
                    !(graphics->data.vnc.listenAddr = strdup(listenAddr)))
                    goto no_memory;

                if (vncPasswd &&
                    !(graphics->data.vnc.passwd = strdup(vncPasswd)))
                    goto no_memory;

                if (keymap &&
                    !(graphics->data.vnc.keymap = strdup(keymap)))
                    goto no_memory;
            }

            def->graphics = graphics;
            break;
        }
    }

    return 0;

no_memory:
    virXendError(conn, VIR_ERR_NO_MEMORY, NULL);
error:
    virDomainGraphicsDefFree(graphics);
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
    const char *tmp;
    virDomainDefPtr def;
    int hvm = 0;
    char *tty = NULL;

    if (VIR_ALLOC(def) < 0)
        goto no_memory;

    tmp = sexpr_node(root, "domain/domid");
    if (tmp == NULL && xendConfigVersion < 3) { /* Old XenD, domid was mandatory */
        virXendError(conn, VIR_ERR_INTERNAL_ERROR,
                     _("domain information incomplete, missing id"));
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
        virXendError(conn, VIR_ERR_INTERNAL_ERROR,
                     _("domain information incomplete, missing name"));
        goto error;
    }

    tmp = sexpr_node(root, "domain/uuid");
    if (tmp == NULL) {
        virXendError(conn, VIR_ERR_INTERNAL_ERROR,
                     _("domain information incomplete, missing name"));
        goto error;
    }
    virUUIDParse(tmp, def->uuid);

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
            if (xenDaemonParseSxprOS(conn, root, def, hvm) < 0)
                goto error;
        }
    }

    def->maxmem = (unsigned long) (sexpr_u64(root, "domain/maxmem") << 10);
    def->memory = (unsigned long) (sexpr_u64(root, "domain/memory") << 10);
    if (def->memory > def->maxmem)
        def->maxmem = def->memory;

    if (cpus != NULL) {
        if (virDomainCpuSetParse(conn, &cpus,
                                 0, def->cpumask,
                                 def->cpumasklen) < 0)
            goto error;
    }
    def->vcpus = sexpr_int(root, "domain/vcpus");

    tmp = sexpr_node(root, "domain/on_poweroff");
    if (tmp != NULL) {
        if ((def->onPoweroff = virDomainLifecycleTypeFromString(tmp)) < 0) {
            virXendError(conn, VIR_ERR_INTERNAL_ERROR,
                         _("unknown lifecycle type %s"), tmp);
            goto error;
        }
    } else
        def->onPoweroff = VIR_DOMAIN_LIFECYCLE_DESTROY;

    tmp = sexpr_node(root, "domain/on_reboot");
    if (tmp != NULL) {
        if ((def->onReboot = virDomainLifecycleTypeFromString(tmp)) < 0) {
            virXendError(conn, VIR_ERR_INTERNAL_ERROR,
                         _("unknown lifecycle type %s"), tmp);
            goto error;
        }
    } else
        def->onReboot = VIR_DOMAIN_LIFECYCLE_RESTART;

    tmp = sexpr_node(root, "domain/on_crash");
    if (tmp != NULL) {
        if ((def->onCrash = virDomainLifecycleTypeFromString(tmp)) < 0) {
            virXendError(conn, VIR_ERR_INTERNAL_ERROR,
                         _("unknown lifecycle type %s"), tmp);
            goto error;
        }
    } else
        def->onCrash = VIR_DOMAIN_LIFECYCLE_DESTROY;


    if (hvm) {
        if (sexpr_int(root, "domain/image/hvm/acpi"))
            def->features |= (1 << VIR_DOMAIN_FEATURE_ACPI);
        if (sexpr_int(root, "domain/image/hvm/apic"))
            def->features |= (1 << VIR_DOMAIN_FEATURE_APIC);
        if (sexpr_int(root, "domain/image/hvm/pae"))
            def->features |= (1 << VIR_DOMAIN_FEATURE_PAE);

        if (sexpr_int(root, "domain/image/hvm/localtime"))
            def->localtime = 1;
    }

    if (sexpr_node_copy(root, hvm ?
                        "domain/image/hvm/device_model" :
                        "domain/image/linux/device_model",
                        &def->emulator) < 0)
        goto no_memory;

    /* append block devices */
    if (xenDaemonParseSxprDisks(conn, def, root, hvm, xendConfigVersion) < 0)
        goto error;

    if (xenDaemonParseSxprNets(conn, def, root) < 0)
        goto error;

    /* New style graphics device config */
    if (xenDaemonParseSxprGraphicsNew(conn, def, root) < 0)
        goto error;

    /* Graphics device (HVM <= 3.0.4, or PV <= 3.0.3) vnc config */
    if (!def->graphics &&
        xenDaemonParseSxprGraphicsOld(conn, def, root, hvm, xendConfigVersion) < 0)
        goto error;


    /* Old style cdrom config from Xen <= 3.0.2 */
    if (hvm &&
        xendConfigVersion == 1) {
        tmp = sexpr_node(root, "domain/image/hvm/cdrom");
        if ((tmp != NULL) && (tmp[0] != 0)) {
            virDomainDiskDefPtr disk, prev;
            if (VIR_ALLOC(disk) < 0)
                goto no_memory;
            if (!(disk->src = strdup(tmp))) {
                VIR_FREE(disk);
                goto no_memory;
            }
            disk->type = VIR_DOMAIN_DISK_TYPE_FILE;
            disk->device = VIR_DOMAIN_DISK_DEVICE_CDROM;
            if (!(disk->dst = strdup("hdc"))) {
                VIR_FREE(disk);
                goto no_memory;
            }
            if (!(disk->driverName = strdup("file"))) {
                VIR_FREE(disk);
                goto no_memory;
            }
            disk->bus = VIR_DOMAIN_DISK_BUS_IDE;
            disk->readonly = 1;

            prev = def->disks;
            while (prev && prev->next) {
                prev = prev->next;
            }
            if (prev)
                prev->next = disk;
            else
                def->disks = disk;
        }
    }


    /* Floppy disk config */
    if (hvm) {
        const char *const fds[] = { "fda", "fdb" };
        int i;
        for (i = 0 ; i < sizeof(fds)/sizeof(fds[0]) ; i++) {
            tmp = sexpr_fmt_node(root, "domain/image/hvm/%s", fds[i]);
            if ((tmp != NULL) && (tmp[0] != 0)) {
                virDomainDiskDefPtr disk, prev;
                if (VIR_ALLOC(disk) < 0)
                    goto no_memory;
                if (!(disk->src = strdup(tmp))) {
                    VIR_FREE(disk);
                    goto no_memory;
                }
                disk->type = VIR_DOMAIN_DISK_TYPE_FILE;
                disk->device = VIR_DOMAIN_DISK_DEVICE_FLOPPY;
                if (!(disk->dst = strdup(fds[i]))) {
                    VIR_FREE(disk);
                    goto no_memory;
                }
                if (!(disk->driverName = strdup("file"))) {
                    VIR_FREE(disk);
                    goto no_memory;
                }
                disk->bus = VIR_DOMAIN_DISK_BUS_FDC;

                prev = def->disks;
                while (prev && prev->next) {
                    prev = prev->next;
                }
                if (prev)
                    prev->next = disk;
                else
                    def->disks = disk;
            }
        }
    }

    /* in case of HVM we have USB device emulation */
    if (hvm &&
        xenDaemonParseSxprUSB(conn, def, root) < 0)
        goto error;

    /* Character device config */
    tty = xenStoreDomainGetConsolePath(conn, def->id);
    if (hvm) {
        tmp = sexpr_node(root, "domain/image/hvm/serial");
        if (tmp && STRNEQ(tmp, "none")) {
            if ((def->serials = xenDaemonParseSxprChar(conn, tmp, tty)) == NULL)
                goto error;
        }
        tmp = sexpr_node(root, "domain/image/hvm/parallel");
        if (tmp && STRNEQ(tmp, "none")) {
            /* XXX does XenD stuff parallel port tty info into xenstore somewhere ? */
            if ((def->parallels = xenDaemonParseSxprChar(conn, tmp, NULL)) == NULL)
                goto error;
        }
    } else {
        /* Fake a paravirt console, since that's not in the sexpr */
        if (!(def->console = xenDaemonParseSxprChar(conn, "pty", tty)))
            goto error;
    }
    VIR_FREE(tty);


    /* Sound device config */
    if (hvm &&
        (tmp = sexpr_node(root, "domain/image/hvm/soundhw")) != NULL &&
        *tmp) {
        if (xenDaemonParseSxprSound(conn, def, tmp) < 0)
            goto error;
    }

    return def;

no_memory:
    virXendError(conn, VIR_ERR_NO_MEMORY, NULL);
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
    info->nrVirtCpu = sexpr_int(root, "domain/vcpus");
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
        /* Should already be fine, but for further sanity make
         * sure we have at least one socket
         */
        if (info->sockets == 0)
            info->sockets = 1;
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
 * Returns 0 in case of success, -1 in case of error
 */
static int
sexpr_to_xend_topology(virConnectPtr conn,
                       const struct sexpr *root,
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
    if (nodeToCpu == NULL) {
        virXendError(conn, VIR_ERR_INTERNAL_ERROR,
                     _("failed to parse topology information"));
        return -1;
    }

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
            nb_cpus = virDomainCpuSetParse(conn, &cur, 'n', cpuset, numCpus);
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
    virXendError(conn, VIR_ERR_XEN_CALL, _("topology syntax error"));
  error:
    VIR_FREE(cpuNums);
    VIR_FREE(cpuset);

    return (-1);

  memory_error:
    VIR_FREE(cpuNums);
    VIR_FREE(cpuset);
    virXendError(conn, VIR_ERR_NO_MEMORY, _("allocate buffer"));
    return (-1);
}


#ifndef PROXY
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
    virXendError(conn, VIR_ERR_INTERNAL_ERROR,
                 _("failed to parse Xend domain information"));
    if (ret != NULL)
        virUnrefDomain(ret);
    return(NULL);
}
#endif /* !PROXY */

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
#ifndef PROXY
/**
 * xenDaemonOpen:
 * @conn: an existing virtual connection block
 * @name: optional argument to select a connection type
 * @flags: combination of virDrvOpenFlag(s)
 *
 * Creates a localhost Xen Daemon connection
 * Note: this doesn't try to check if the connection actually works
 *
 * Returns 0 in case of success, -1 in case of error.
 */
int
xenDaemonOpen(virConnectPtr conn,
              xmlURIPtr uri,
              virConnectAuthPtr auth ATTRIBUTE_UNUSED,
              int flags ATTRIBUTE_UNUSED)
{
    int ret;

    /* Switch on the scheme, which we expect to be NULL (file),
     * "http" or "xen".
     */
    if (uri->scheme == NULL) {
        /* It should be a file access */
        if (uri->path == NULL) {
            virXendError(NULL, VIR_ERR_NO_CONNECT, __FUNCTION__);
            goto failed;
        }
        ret = xenDaemonOpen_unix(conn, uri->path);
        if (ret < 0)
            goto failed;

        ret = xend_detect_config_version(conn);
        if (ret == -1)
            goto failed;
    }
    else if (STRCASEEQ (uri->scheme, "xen")) {
        /*
         * try first to open the unix socket
         */
        ret = xenDaemonOpen_unix(conn, "/var/lib/xend/xend-socket");
        if (ret < 0)
            goto try_http;
        ret = xend_detect_config_version(conn);
        if (ret != -1)
            goto done;

    try_http:
        /*
         * try though http on port 8000
         */
        ret = xenDaemonOpen_tcp(conn, "localhost", 8000);
        if (ret < 0)
            goto failed;
        ret = xend_detect_config_version(conn);
        if (ret == -1)
            goto failed;
    } else if (STRCASEEQ (uri->scheme, "http")) {
        ret = xenDaemonOpen_tcp(conn, uri->server, uri->port);
        if (ret < 0)
            goto failed;
        ret = xend_detect_config_version(conn);
        if (ret == -1)
            goto failed;
    } else {
        virXendError(NULL, VIR_ERR_NO_CONNECT, __FUNCTION__);
        goto failed;
    }

 done:
    return(ret);

failed:
    return(-1);
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
        virXendError((domain ? domain->conn : NULL), VIR_ERR_INVALID_ARG,
                     __FUNCTION__);
        return(-1);
    }
    if (domain->id < 0)
        return(-1);
    return xend_op(domain->conn, domain->name, "op", "pause", NULL);
}

/**
 * xenDaemonDomainResume:
 * @xend: pointer to the Xem Daemon block
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
        virXendError((domain ? domain->conn : NULL), VIR_ERR_INVALID_ARG,
                     __FUNCTION__);
        return(-1);
    }
    if (domain->id < 0)
        return(-1);
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
        virXendError((domain ? domain->conn : NULL), VIR_ERR_INVALID_ARG,
                     __FUNCTION__);
        return(-1);
    }
    if (domain->id < 0)
        return(-1);
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
        virXendError((domain ? domain->conn : NULL), VIR_ERR_INVALID_ARG,
                     __FUNCTION__);
        return(-1);
    }
    if (domain->id < 0)
        return(-1);
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
        virXendError((domain ? domain->conn : NULL), VIR_ERR_INVALID_ARG,
                     __FUNCTION__);
        return(-1);
    }
    if (domain->id < 0)
        return(-1);
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
        virXendError((domain ? domain->conn : NULL), VIR_ERR_INVALID_ARG,
                     __FUNCTION__);
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
        (filename == NULL) || (domain->id < 0)) {
        virXendError((domain ? domain->conn : NULL), VIR_ERR_INVALID_ARG,
                     __FUNCTION__);
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
        virXendError((domain ? domain->conn : NULL), VIR_ERR_INVALID_ARG,
                     __FUNCTION__);
        return(-1);
    }
    if (domain->id < 0)
        return(-1);
    return xend_op(domain->conn, domain->name, "op", "dump", "file", filename,
                   "live", "0", "crash", "0", NULL);
}

/**
 * xenDaemonDomainRestore:
 * @conn: pointer to the Xem Daemon block
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
        virXendError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }
    return xend_op(conn, "", "op", "restore", "file", filename, NULL);
}
#endif /* !PROXY */

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
        virXendError((domain ? domain->conn : NULL), VIR_ERR_INVALID_ARG,
                     __FUNCTION__);
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

#ifndef PROXY
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
        virXendError((domain ? domain->conn : NULL), VIR_ERR_INVALID_ARG,
                     __FUNCTION__);
        return(-1);
    }

    priv = (xenUnifiedPrivatePtr) domain->conn->privateData;

    if (domain->id < 0 && priv->xendConfigVersion < 3)
        return(-1);

    snprintf(buf, sizeof(buf), "%lu", memory >> 10);
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
        virXendError((domain ? domain->conn : NULL), VIR_ERR_INVALID_ARG,
                     __FUNCTION__);
        return(-1);
    }

    priv = (xenUnifiedPrivatePtr) domain->conn->privateData;

    if (domain->id < 0 && priv->xendConfigVersion < 3)
        return(-1);

    snprintf(buf, sizeof(buf), "%lu", memory >> 10);
    return xend_op(domain->conn, domain->name, "op", "mem_target_set",
                   "target", buf, NULL);
}

#endif /* ! PROXY */

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
        virXendError (conn, VIR_ERR_XEN_CALL,
                      _("xenDaemonDomainFetch failed to"
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


#ifndef PROXY
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
        virXendError((domain ? domain->conn : NULL), VIR_ERR_INVALID_ARG,
                     __FUNCTION__);
        return(NULL);
    }
    priv = (xenUnifiedPrivatePtr) domain->conn->privateData;

    if (domain->id < 0 && priv->xendConfigVersion < 3) {
        // fall-through to the next driver to handle
        return(NULL);
    }

    if (!(def = xenDaemonDomainFetch(domain->conn,
                                     domain->id,
                                     domain->name,
                                     cpus)))
        return(NULL);

    xml = virDomainDefFormat(domain->conn, def, flags);

    virDomainDefFree(def);

    return xml;
}
#endif /* !PROXY */

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
        virXendError((domain ? domain->conn : NULL), VIR_ERR_INVALID_ARG,
                     __FUNCTION__);
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

#ifndef PROXY
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
        virXendError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
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
#endif /* ! PROXY */

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
        virXendError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }
    if (info == NULL) {
        virXendError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
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
        virXendError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }

    if (caps == NULL) {
        virXendError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }

    root = sexpr_get(conn, "/xend/node/");
    if (root == NULL) {
        return (-1);
    }

    ret = sexpr_to_xend_topology(conn, root, caps);
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
        virXendError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }
    if (hvVer == NULL) {
        virXendError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
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

#ifndef PROXY
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
static int
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
static int
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
#endif /* ! PROXY */

#ifndef PROXY
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
    if (ret == NULL) return NULL;

    ret->id = id;
    VIR_FREE(name);
    return (ret);

 error:
    VIR_FREE(name);
    return (NULL);
}

/**
 * xenDaemonDomainSetVcpus:
 * @domain: pointer to domain object
 * @nvcpus: the new number of virtual CPUs for this domain
 *
 * Dynamically change the number of virtual CPUs used by the domain.
 *
 * Returns 0 for success; -1 (with errno) on error
 */
int
xenDaemonDomainSetVcpus(virDomainPtr domain, unsigned int vcpus)
{
    char buf[VIR_UUID_BUFLEN];
    xenUnifiedPrivatePtr priv;

    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)
     || (vcpus < 1)) {
        virXendError((domain ? domain->conn : NULL), VIR_ERR_INVALID_ARG,
                     __FUNCTION__);
        return (-1);
    }

    priv = (xenUnifiedPrivatePtr) domain->conn->privateData;

    if (domain->id < 0 && priv->xendConfigVersion < 3)
        return(-1);

    snprintf(buf, sizeof(buf), "%d", vcpus);
    return(xend_op(domain->conn, domain->name, "op", "set_vcpus", "vcpus",
                   buf, NULL));
}

/**
 * xenDaemonDomainPinCpu:
 * @domain: pointer to domain object
 * @vcpu: virtual CPU number
 * @cpumap: pointer to a bit map of real CPUs (in 8-bit bytes)
 * @maplen: length of cpumap in bytes
 *
 * Dynamically change the real CPUs which can be allocated to a virtual CPU.
 *
 * Returns 0 for success; -1 (with errno) on error
 */
int
xenDaemonDomainPinVcpu(virDomainPtr domain, unsigned int vcpu,
                     unsigned char *cpumap, int maplen)
{
    char buf[VIR_UUID_BUFLEN], mapstr[sizeof(cpumap_t) * 64] = "[";
    int i, j;

    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)
     || (cpumap == NULL) || (maplen < 1) || (maplen > (int)sizeof(cpumap_t))) {
        virXendError((domain ? domain->conn : NULL), VIR_ERR_INVALID_ARG,
                     __FUNCTION__);
        return (-1);
    }
    if (domain->id < 0)
        return(-1);

    /* from bit map, build character string of mapped CPU numbers */
    for (i = 0; i < maplen; i++) for (j = 0; j < 8; j++)
     if (cpumap[i] & (1 << j)) {
        snprintf(buf, sizeof(buf), "%d,", (8 * i) + j);
        strcat(mapstr, buf);
    }
    mapstr[strlen(mapstr) - 1] = ']';
    snprintf(buf, sizeof(buf), "%d", vcpu);
    return(xend_op(domain->conn, domain->name, "op", "pincpu", "vcpu", buf,
                  "cpumap", mapstr, NULL));
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
        virXendError((domain ? domain->conn : NULL), VIR_ERR_INVALID_ARG,
                     __FUNCTION__);
        return (-1);
    }
    if (cpumaps != NULL && maplen < 1) {
        virXendError((domain ? domain->conn : NULL), VIR_ERR_INVALID_ARG,
                     __FUNCTION__);
        return (-1);
    }
    if (domain->id < 0)
        return(-1);

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
        name = domname ? strdup(domname) : NULL;
        sexpr_free(root);
    }

    if (name == NULL)
        return (NULL);

    ret = virGetDomain(conn, name, uuid);
    if (ret == NULL) return NULL;

    ret->id = id;
    VIR_FREE(name);
    return (ret);
}

/**
 * xenDaemonCreateLinux:
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
xenDaemonCreateLinux(virConnectPtr conn, const char *xmlDesc,
                     unsigned int flags ATTRIBUTE_UNUSED)
{
    int ret;
    char *sexpr;
    virDomainPtr dom = NULL;
    xenUnifiedPrivatePtr priv;
    virDomainDefPtr def;

    priv = (xenUnifiedPrivatePtr) conn->privateData;

    if (!(def = virDomainDefParseString(conn,
                                        priv->caps,
                                        xmlDesc)))
        return (NULL);

    if (!(sexpr = xenDaemonFormatSxpr(conn, def, priv->xendConfigVersion))) {
        virXendError(conn, VIR_ERR_XML_ERROR,
                     "%s", _("failed to build sexpr"));
        virDomainDefFree(def);
        return (NULL);
    }

    ret = xenDaemonDomainCreateLinux(conn, sexpr);
    VIR_FREE(sexpr);
    if (ret != 0) {
        goto error;
    }

    /* This comes before wait_for_devices, to ensure that latter
       cleanup will destroy the domain upon failure */
    if (!(dom = virDomainLookupByName(conn, def->name)))
        goto error;

    if ((ret = xend_wait_for_devices(conn, def->name)) < 0)
        goto error;

    if ((ret = xenDaemonDomainResume(dom)) < 0)
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
 * xenDaemonAttachDevice:
 * @domain: pointer to domain object
 * @xml: pointer to XML description of device
 *
 * Create a virtual device attachment to backend.
 * XML description is translated into S-expression.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
static int
xenDaemonAttachDevice(virDomainPtr domain, const char *xml)
{
    xenUnifiedPrivatePtr priv;
    char *sexpr = NULL;
    int ret = -1;
    virDomainDeviceDefPtr dev = NULL;
    virDomainDefPtr def = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char class[8], ref[80];

    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)) {
        virXendError((domain ? domain->conn : NULL), VIR_ERR_INVALID_ARG,
                     __FUNCTION__);
        return -1;
    }

    priv = (xenUnifiedPrivatePtr) domain->conn->privateData;

    /*
     * on older Xen without the inactive guests management
     * avoid doing this on inactive guests
     */
    if ((domain->id < 0) && (priv->xendConfigVersion < 3))
        return -1;

    if (!(def = xenDaemonDomainFetch(domain->conn,
                                     domain->id,
                                     domain->name,
                                     NULL)))
        goto cleanup;

    if (!(dev = virDomainDeviceDefParse(domain->conn, def, xml)))
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

    case VIR_DOMAIN_DEVICE_NET:
        if (xenDaemonFormatSxprNet(domain->conn,
                                   dev->data.net,
                                   &buf,
                                   STREQ(def->os.type, "hvm") ? 1 : 0,
                                   priv->xendConfigVersion, 1) < 0)
            goto cleanup;
        break;

    default:
        virXendError(domain->conn, VIR_ERR_NO_SUPPORT, "%s",
                     _("unsupported device type"));
        goto cleanup;
    }

    sexpr = virBufferContentAndReset(&buf);

    if (virDomainXMLDevID(domain, dev, class, ref, sizeof(ref))) {
        /* device doesn't exist, define it */
        ret = xend_op(domain->conn, domain->name, "op", "device_create",
                      "config", sexpr, NULL);
    }
    else {
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
 * xenDaemonDetachDevice:
 * @domain: pointer to domain object
 * @xml: pointer to XML description of device
 *
 * Destroy a virtual device attachment to backend.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
static int
xenDaemonDetachDevice(virDomainPtr domain, const char *xml)
{
    xenUnifiedPrivatePtr priv;
    char class[8], ref[80];
    virDomainDeviceDefPtr dev = NULL;
    virDomainDefPtr def = NULL;
    int ret = -1;

    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)) {
        virXendError((domain ? domain->conn : NULL), VIR_ERR_INVALID_ARG,
                     __FUNCTION__);
        return (-1);
    }

    priv = (xenUnifiedPrivatePtr) domain->conn->privateData;

    /*
     * on older Xen without the inactive guests management
     * avoid doing this on inactive guests
     */
    if ((domain->id < 0) && (priv->xendConfigVersion < 3))
        return -1;

    if (!(def = xenDaemonDomainFetch(domain->conn,
                                     domain->id,
                                     domain->name,
                                     NULL)))
        goto cleanup;

    if (!(dev = virDomainDeviceDefParse(domain->conn, def, xml)))
        goto cleanup;

    if (virDomainXMLDevID(domain, dev, class, ref, sizeof(ref)))
        goto cleanup;

    ret = xend_op(domain->conn, domain->name, "op", "device_destroy",
                  "type", class, "dev", ref, "force", "0", "rm_cfg", "1", NULL);

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
        virXendError((domain ? domain->conn : NULL), VIR_ERR_INVALID_ARG,
                     __FUNCTION__);
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
        virXendError (domain->conn, VIR_ERR_XEN_CALL,
                      _("xenDaemonGetAutostart failed to find this domain"));
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
    const char *autostr;
    char buf[4096];
    int ret = -1;
    xenUnifiedPrivatePtr priv;

    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)) {
        virXendError((domain ? domain->conn : NULL), VIR_ERR_INTERNAL_ERROR,
                     __FUNCTION__);
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
        virXendError (domain->conn, VIR_ERR_XEN_CALL,
                      _("xenDaemonSetAutostart failed to find this domain"));
        return (-1);
    }

    autostr = sexpr_node(root, "domain/on_xend_start");
    if (autostr) {
        if (!STREQ(autostr, "ignore") && !STREQ(autostr, "start")) {
            virXendError(domain->conn, VIR_ERR_INTERNAL_ERROR,
                         _("unexpected value from on_xend_start"));
            goto error;
        }

        // Change the autostart value in place, then define the new sexpr
        autonode = sexpr_lookup(root, "domain/on_xend_start");
        VIR_FREE(autonode->u.s.car->u.value);
        autonode->u.s.car->u.value = (autostart ? strdup("start")
                                                : strdup("ignore"));
        if (!(autonode->u.s.car->u.value)) {
            virXendError(domain->conn, VIR_ERR_INTERNAL_ERROR,
                         _("no memory"));
            goto error;
        }

        if (sexpr2string(root, buf, sizeof(buf)) == 0) {
            virXendError(domain->conn, VIR_ERR_INTERNAL_ERROR,
                         _("sexpr2string failed"));
            goto error;
        }
        if (xend_op(domain->conn, "", "op", "new", "config", buf, NULL) != 0) {
            virXendError(domain->conn, VIR_ERR_XEN_CALL,
                         _("Failed to redefine sexpr"));
            goto error;
        }
    } else {
        virXendError(domain->conn, VIR_ERR_INTERNAL_ERROR,
                     _("on_xend_start not present in sexpr"));
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
    int r;
    char hostname [HOST_NAME_MAX+1];

    /* If uri_in is NULL, get the current hostname as a best guess
     * of how the source host should connect to us.  Note that caller
     * deallocates this string.
     */
    if (uri_in == NULL) {
        r = gethostname (hostname, HOST_NAME_MAX+1);
        if (r == -1) {
            virXendError (dconn, VIR_ERR_SYSTEM_ERROR,
                          _("gethostname failed: %s"), strerror (errno));
            return -1;
        }
        *uri_out = strdup (hostname);
        if (*uri_out == NULL) {
            virXendError (dconn, VIR_ERR_SYSTEM_ERROR,
                          _("failed to strdup hostname: %s"), strerror (errno));
            return -1;
        }
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
    virConnectPtr conn = domain->conn;
    /* NB: Passing port=0 to xend means it ignores
     * the port.  However this is somewhat specific to
     * the internals of the xend Python code. (XXX).
     */
    char port[16] = "0";
    char live[2] = "0";
    int ret;
    char *p, *hostname = NULL;

    /* Xen doesn't support renaming domains during migration. */
    if (dname) {
        virXendError (conn, VIR_ERR_NO_SUPPORT,
                      _("xenDaemonDomainMigrate: Xen does not support"
                        " renaming domains during migration"));
        return -1;
    }

    /* Xen (at least up to 3.1.0) takes a resource parameter but
     * ignores it.
     */
    if (bandwidth) {
        virXendError (conn, VIR_ERR_NO_SUPPORT,
                      _("xenDaemonDomainMigrate: Xen does not support"
                        " bandwidth limits during migration"));
        return -1;
    }

    /* Check the flags. */
    if ((flags & VIR_MIGRATE_LIVE)) {
        strcpy (live, "1");
        flags &= ~VIR_MIGRATE_LIVE;
    }
    if (flags != 0) {
        virXendError (conn, VIR_ERR_NO_SUPPORT,
                      _("xenDaemonDomainMigrate: unsupported flag"));
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
            virXendError (conn, VIR_ERR_INVALID_ARG,
                          _("xenDaemonDomainMigrate: invalid URI"));
            return -1;
        }
        if (uriptr->scheme && STRCASENEQ (uriptr->scheme, "xenmigr")) {
            virXendError (conn, VIR_ERR_INVALID_ARG,
                          _("xenDaemonDomainMigrate: only xenmigr://"
                            " migrations are supported by Xen"));
            xmlFreeURI (uriptr);
            return -1;
        }
        if (!uriptr->server) {
            virXendError (conn, VIR_ERR_INVALID_ARG,
                          _("xenDaemonDomainMigrate: a hostname must be"
                            " specified in the URI"));
            xmlFreeURI (uriptr);
            return -1;
        }
        hostname = strdup (uriptr->server);
        if (!hostname) {
            virXendError (conn, VIR_ERR_NO_MEMORY, _("strdup failed"));
            xmlFreeURI (uriptr);
            return -1;
        }
        if (uriptr->port)
            snprintf (port, sizeof port, "%d", uriptr->port);
        xmlFreeURI (uriptr);
    }
    else if ((p = strrchr (uri, ':')) != NULL) { /* "hostname:port" */
        int port_nr, n;

        if (sscanf (p+1, "%d", &port_nr) != 1) {
            virXendError (conn, VIR_ERR_INVALID_ARG,
                          _("xenDaemonDomainMigrate: invalid port number"));
            return -1;
        }
        snprintf (port, sizeof port, "%d", port_nr);

        /* Get the hostname. */
        n = p - uri; /* n = Length of hostname in bytes. */
        hostname = strdup (uri);
        if (!hostname) {
            virXendError (conn, VIR_ERR_NO_MEMORY, _("strdup failed"));
            return -1;
        }
        hostname[n] = '\0';
    }
    else {                      /* "hostname" (or IP address) */
        hostname = strdup (uri);
        if (!hostname) {
            virXendError (conn, VIR_ERR_NO_MEMORY, _("strdup failed"));
            return -1;
        }
    }

    DEBUG("hostname = %s, port = %s", hostname, port);

    /* Make the call. */
    ret = xend_op (domain->conn, domain->name,
                   "op", "migrate",
                   "destination", hostname,
                   "live", live,
                   "port", port,
                   "resource", "0", /* required, xend ignores it */
                   NULL);
    VIR_FREE (hostname);

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

    if (!(def = virDomainDefParseString(conn, priv->caps, xmlDesc))) {
        virXendError(conn, VIR_ERR_XML_ERROR,
                     _("failed to parse domain description"));
        return (NULL);
    }

    if (!(sexpr = xenDaemonFormatSxpr(conn, def, priv->xendConfigVersion))) {
        virXendError(conn, VIR_ERR_XML_ERROR,
                     _("failed to build sexpr"));
        goto error;
    }

    DEBUG("Defining w/ sexpr: \n%s", sexpr);

    ret = xend_op(conn, "", "op", "new", "config", sexpr, NULL);
    VIR_FREE(sexpr);
    if (ret != 0) {
        virXendError(conn, VIR_ERR_XEN_CALL,
                     _("Failed to create inactive domain %s\n"), def->name);
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

    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)) {
        virXendError((domain ? domain->conn : NULL), VIR_ERR_INVALID_ARG,
                     __FUNCTION__);
        return(-1);
    }

    priv = (xenUnifiedPrivatePtr) domain->conn->privateData;

    if (priv->xendConfigVersion < 3)
        return(-1);

    return xend_op(domain->conn, domain->name, "op", "start", NULL);
}

int xenDaemonDomainUndefine(virDomainPtr domain)
{
    xenUnifiedPrivatePtr priv;

    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)) {
        virXendError((domain ? domain->conn : NULL), VIR_ERR_INVALID_ARG,
                     __FUNCTION__);
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
    int ret = -1;
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

        names[ret++] = strdup(node->u.value);
        if (ret >= maxnames)
            break;
    }

error:
    sexpr_free(root);
    return(ret);
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
        virXendError((domain ? domain->conn : NULL), VIR_ERR_INVALID_ARG,
                     __FUNCTION__);
        return NULL;
    }

    /* Support only xendConfigVersion >=4 */
    priv = (xenUnifiedPrivatePtr) domain->conn->privateData;
    if (priv->xendConfigVersion < 4) {
        virXendError (domain->conn, VIR_ERR_NO_SUPPORT,
                      _("unsupported in xendConfigVersion < 4"));
        return NULL;
    }

    root = sexpr_get(domain->conn, "/xend/node/");
    if (root == NULL)
        return NULL;

    /* get xen_scheduler from xend/node */
    ret = sexpr_node(root, "node/xen_scheduler");
    if (ret == NULL){
        virXendError(domain->conn, VIR_ERR_INTERNAL_ERROR,
                     _("node information incomplete, missing scheduler name"));
        goto error;
    }
    if (STREQ (ret, "credit")) {
        schedulertype = strdup("credit");
        if (schedulertype == NULL){
            virXendError(domain->conn, VIR_ERR_SYSTEM_ERROR, _("strdup failed"));
            goto error;
        }
        *nparams = XEN_SCHED_CRED_NPARAM;
    } else if (STREQ (ret, "sedf")) {
        schedulertype = strdup("sedf");
        if (schedulertype == NULL){
            virXendError(domain->conn, VIR_ERR_SYSTEM_ERROR, _("strdup failed"));
            goto error;
        }
        *nparams = XEN_SCHED_SEDF_NPARAM;
    } else {
        virXendError(domain->conn, VIR_ERR_INTERNAL_ERROR, _("Unknown scheduler"));
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
        virXendError((domain ? domain->conn : NULL), VIR_ERR_INVALID_ARG,
                     __FUNCTION__);
        return (-1);
    }

    /* Support only xendConfigVersion >=4 */
    priv = (xenUnifiedPrivatePtr) domain->conn->privateData;
    if (priv->xendConfigVersion < 4) {
        virXendError (domain->conn, VIR_ERR_NO_SUPPORT,
                      _("unsupported in xendConfigVersion < 4"));
        return (-1);
    }

    /* look up the information by domain name */
    root = sexpr_get(domain->conn, "/xend/domain/%s?detail=1", domain->name);
    if (root == NULL)
        return (-1);

    /* get the scheduler type */
    sched_type = xenDaemonGetSchedulerType(domain, &sched_nparam);
    if (sched_type == NULL) {
        virXendError(domain->conn, VIR_ERR_INTERNAL_ERROR,
                     _("Failed to get a scheduler name"));
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
                virXendError(domain->conn, VIR_ERR_INTERNAL_ERROR,
                        _("domain information incomplete, missing cpu_weight"));
                goto error;
            }
            if (sexpr_node(root, "domain/cpu_cap") == NULL) {
                virXendError(domain->conn, VIR_ERR_INTERNAL_ERROR,
                        _("domain information incomplete, missing cpu_cap"));
                goto error;
            }

            strncpy (params[0].field, str_weight, VIR_DOMAIN_SCHED_FIELD_LENGTH);
            params[0].field[VIR_DOMAIN_SCHED_FIELD_LENGTH-1] = '\0';
            params[0].type = VIR_DOMAIN_SCHED_FIELD_UINT;
            params[0].value.ui = sexpr_int(root, "domain/cpu_weight");

            strncpy (params[1].field, str_cap, VIR_DOMAIN_SCHED_FIELD_LENGTH);
            params[1].field[VIR_DOMAIN_SCHED_FIELD_LENGTH-1] = '\0';
            params[1].type = VIR_DOMAIN_SCHED_FIELD_UINT;
            params[1].value.ui = sexpr_int(root, "domain/cpu_cap");
            *nparams = XEN_SCHED_CRED_NPARAM;
            ret = 0;
            break;
        default:
            virXendError(domain->conn, VIR_ERR_INTERNAL_ERROR, _("Unknown scheduler"));
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
        virXendError((domain ? domain->conn : NULL), VIR_ERR_INVALID_ARG,
                     __FUNCTION__);
        return (-1);
    }

    /* Support only xendConfigVersion >=4 and active domains */
    priv = (xenUnifiedPrivatePtr) domain->conn->privateData;
    if (priv->xendConfigVersion < 4) {
        virXendError (domain->conn, VIR_ERR_NO_SUPPORT,
                      _("unsupported in xendConfigVersion < 4"));
        return (-1);
    }

    /* look up the information by domain name */
    root = sexpr_get(domain->conn, "/xend/domain/%s?detail=1", domain->name);
    if (root == NULL)
        return (-1);

    /* get the scheduler type */
    sched_type = xenDaemonGetSchedulerType(domain, &sched_nparam);
    if (sched_type == NULL) {
        virXendError(domain->conn, VIR_ERR_INTERNAL_ERROR,
                     _("Failed to get a scheduler name"));
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
                    virXendError(domain->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
                    goto error;
                }
            }

            /* if not get the scheduler parameter, set the current setting */
            if (strlen(buf_weight) == 0) {
                weight = sexpr_node(root, "domain/cpu_weight");
                if (weight == NULL) {
                    virXendError(domain->conn, VIR_ERR_INTERNAL_ERROR,
                                _("domain information incomplete, missing cpu_weight"));
                    goto error;
                }
                snprintf(buf_weight, sizeof(buf_weight), "%s", weight);
            }
            if (strlen(buf_cap) == 0) {
                cap = sexpr_node(root, "domain/cpu_cap");
                if (cap == NULL) {
                    virXendError(domain->conn, VIR_ERR_INTERNAL_ERROR,
                                _("domain information incomplete, missing cpu_cap"));
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
            virXendError(domain->conn, VIR_ERR_INTERNAL_ERROR, _("Unknown scheduler"));
            goto error;
    }

error:
    sexpr_free(root);
    VIR_FREE(sched_type);
    return (ret);
}

/**
 * xenDaemonDomainBlockPeek:
 * @dom: domain object
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
    int found = 0;
    virDomainDefPtr def;
    virDomainDiskDefPtr disk;

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
        virXendError (domain->conn, VIR_ERR_NO_SUPPORT,
                      _("domainBlockPeek is not supported for dom0"));
        return -1;
    }

    if (!root) {
        virXendError (domain->conn, VIR_ERR_XEN_CALL, __FUNCTION__);
        return -1;
    }

    if (!(def = xenDaemonParseSxpr(domain->conn, root, priv->xendConfigVersion, NULL)))
        goto cleanup;

    disk = def->disks;
    while (disk) {
        if (disk->src &&
            STREQ(disk->src, path)) {
            found = 1;
            break;
        }
        disk = disk->next;
    }
    if (!found) {
        virXendError (domain->conn, VIR_ERR_INVALID_ARG,
                      _("%s: invalid path"), path);
        goto cleanup;
    }

    /* The path is correct, now try to open it and get its size. */
    fd = open (path, O_RDONLY);
    if (fd == -1) {
        virXendError (domain->conn, VIR_ERR_SYSTEM_ERROR,
                      _("failed to open for reading: %s: %s"),
                      path, strerror (errno));
        goto cleanup;
    }

    /* Seek and read. */
    /* NB. Because we configure with AC_SYS_LARGEFILE, off_t should
     * be 64 bits on all platforms.
     */
    if (lseek (fd, offset, SEEK_SET) == (off_t) -1 ||
        saferead (fd, buffer, size) == (ssize_t) -1) {
        virXendError (domain->conn, VIR_ERR_SYSTEM_ERROR,
                      _("failed to lseek or read from file: %s: %s"),
                      path, strerror (errno));
        goto cleanup;
    }

    ret = 0;
 cleanup:
    if (fd >= 0) close (fd);
    sexpr_free(root);
    virDomainDefFree(def);
    return ret;
}

struct xenUnifiedDriver xenDaemonDriver = {
    xenDaemonOpen,               /* open */
    xenDaemonClose,              /* close */
    xenDaemonGetVersion,         /* version */
    NULL,                        /* hostname */
    NULL,                        /* URI */
    xenDaemonNodeGetInfo,        /* nodeGetInfo */
    NULL,                        /* getCapabilities */
    xenDaemonListDomains,        /* listDomains */
    xenDaemonNumOfDomains,       /* numOfDomains */
    xenDaemonCreateLinux,        /* domainCreateLinux */
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
    xenDaemonDomainSetVcpus,     /* domainSetVcpus */
    xenDaemonDomainPinVcpu,      /* domainPinVcpu */
    xenDaemonDomainGetVcpus,     /* domainGetVcpus */
    NULL,                        /* domainGetMaxVcpus */
    xenDaemonListDefinedDomains, /* listDefinedDomains */
    xenDaemonNumOfDefinedDomains,/* numOfDefinedDomains */
    xenDaemonDomainCreate,       /* domainCreate */
    xenDaemonDomainDefineXML,    /* domainDefineXML */
    xenDaemonDomainUndefine,     /* domainUndefine */
    xenDaemonAttachDevice,       /* domainAttachDevice */
    xenDaemonDetachDevice,       /* domainDetachDevice */
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
xenDaemonFormatSxprGraphicsNew(virConnectPtr conn,
                               virDomainGraphicsDefPtr def,
                               virBufferPtr buf)
{
    if (def->type != VIR_DOMAIN_GRAPHICS_TYPE_SDL &&
        def->type != VIR_DOMAIN_GRAPHICS_TYPE_VNC) {
        virXendError(conn, VIR_ERR_INTERNAL_ERROR,
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
        if (def->data.vnc.passwd)
            virBufferVSprintf(buf, "(vncpasswd '%s')", def->data.vnc.passwd);
        if (def->data.vnc.keymap)
            virBufferVSprintf(buf, "(keymap '%s')", def->data.vnc.keymap);
    }

    virBufferAddLit(buf, "))");

    return 0;
}


static int
xenDaemonFormatSxprGraphicsOld(virConnectPtr conn,
                               virDomainGraphicsDefPtr def,
                               virBufferPtr buf,
                               int xendConfigVersion)
{
    if (def->type != VIR_DOMAIN_GRAPHICS_TYPE_SDL &&
        def->type != VIR_DOMAIN_GRAPHICS_TYPE_VNC) {
        virXendError(conn, VIR_ERR_INTERNAL_ERROR,
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
            if (def->data.vnc.passwd)
                virBufferVSprintf(buf, "(vncpasswd '%s')", def->data.vnc.passwd);
            if (def->data.vnc.keymap)
                virBufferVSprintf(buf, "(keymap '%s')", def->data.vnc.keymap);

        }
    }

    return 0;
}

int
xenDaemonFormatSxprChr(virConnectPtr conn,
                       virDomainChrDefPtr def,
                       virBufferPtr buf)
{
    const char *type = virDomainChrTypeToString(def->type);

    if (!type) {
        virXendError(conn, VIR_ERR_INTERNAL_ERROR,
                     _("unexpected chr device type"));
        return -1;
    }

    switch (def->type) {
    case VIR_DOMAIN_CHR_TYPE_NULL:
    case VIR_DOMAIN_CHR_TYPE_STDIO:
    case VIR_DOMAIN_CHR_TYPE_VC:
    case VIR_DOMAIN_CHR_TYPE_PTY:
        virBufferVSprintf(buf, "%s", type);
        break;

    case VIR_DOMAIN_CHR_TYPE_FILE:
    case VIR_DOMAIN_CHR_TYPE_PIPE:
        virBufferVSprintf(buf, "%s:%s", type, def->data.file.path);
        break;

    case VIR_DOMAIN_CHR_TYPE_DEV:
        virBufferVSprintf(buf, "%s", def->data.file.path);
        break;

    case VIR_DOMAIN_CHR_TYPE_TCP:
        virBufferVSprintf(buf, "%s:%s:%s%s",
                          (def->data.tcp.protocol == VIR_DOMAIN_CHR_TCP_PROTOCOL_RAW ?
                           "tcp" : "telnet"),
                          (def->data.tcp.host ? def->data.tcp.host : ""),
                          (def->data.tcp.service ? def->data.tcp.service : ""),
                          (def->data.tcp.listen ? ",listen" : ""));
        break;

    case VIR_DOMAIN_CHR_TYPE_UDP:
        virBufferVSprintf(buf, "%s:%s:%s@%s:%s", type,
                          (def->data.udp.connectHost ? def->data.udp.connectHost : ""),
                          (def->data.udp.connectService ? def->data.udp.connectService : ""),
                          (def->data.udp.bindHost ? def->data.udp.bindHost : ""),
                          (def->data.udp.bindService ? def->data.udp.bindService : ""));
        break;

    case VIR_DOMAIN_CHR_TYPE_UNIX:
        virBufferVSprintf(buf, "%s:%s%s", type,
                          def->data.nix.path,
                          def->data.nix.listen ? ",listen" : "");
        break;
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
        def->device == VIR_DOMAIN_DISK_DEVICE_FLOPPY)
        return 0;

    /* Xend <= 3.0.2 doesn't include cdrom config here */
    if (hvm &&
        def->device == VIR_DOMAIN_DISK_DEVICE_CDROM &&
        xendConfigVersion == 1)
        return 0;

    if (!isAttach)
        virBufferAddLit(buf, "(device ");

    /* Normally disks are in a (device (vbd ...)) block
     * but blktap disks ended up in a differently named
     * (device (tap ....)) block.... */
    if (def->driverName &&
        STREQ(def->driverName, "tap")) {
        virBufferAddLit(buf, "(tap ");
    } else {
        virBufferAddLit(buf, "(vbd ");
    }

    if (hvm) {
        /* Xend <= 3.0.2 wants a ioemu: prefix on devices for HVM */
        if (xendConfigVersion == 1)
            virBufferVSprintf(buf, "(dev 'ioemu:%s')", def->dst);
        else                    /* But newer does not */
            virBufferVSprintf(buf, "(dev '%s:%s')", def->dst,
                              def->device == VIR_DOMAIN_DISK_DEVICE_CDROM ?
                              "cdrom" : "disk");
    } else {
        virBufferVSprintf(buf, "(dev '%s')", def->dst);
    }

    if (def->src) {
        if (def->driverName) {
            if (STREQ(def->driverName, "tap")) {
                virBufferVSprintf(buf, "(uname '%s:%s:%s')",
                                  def->driverName,
                                  def->driverType ? def->driverType : "aio",
                                  def->src);
            } else {
                virBufferVSprintf(buf, "(uname '%s:%s')",
                                  def->driverName,
                                  def->src);
            }
        } else {
            if (def->type == VIR_DOMAIN_DISK_TYPE_FILE) {
                virBufferVSprintf(buf, "(uname 'file:%s')", def->src);
            } else {
                if (def->src[0] == '/')
                    virBufferVSprintf(buf, "(uname 'phy:%s')", def->src);
                else
                    virBufferVSprintf(buf, "(uname 'phy:/dev/%s')", def->src);
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
    if (def->type != VIR_DOMAIN_NET_TYPE_BRIDGE &&
        def->type != VIR_DOMAIN_NET_TYPE_NETWORK &&
        def->type != VIR_DOMAIN_NET_TYPE_ETHERNET) {
        virXendError(conn, VIR_ERR_INTERNAL_ERROR,
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
        virBufferVSprintf(buf, "(bridge '%s')", def->data.bridge.brname);
        virBufferAddLit(buf, "(script 'vif-bridge')");
        break;

    case VIR_DOMAIN_NET_TYPE_NETWORK:
    {
        virNetworkPtr network =
            virNetworkLookupByName(conn, def->data.network.name);
        char *bridge;

        if (!network) {
            virXendError(conn, VIR_ERR_NO_SOURCE, "%s",
                         def->data.network.name);
            return -1;
        }

        bridge = virNetworkGetBridgeName(network);
        virNetworkFree(network);
        if (!bridge) {
            virXendError(conn, VIR_ERR_NO_SOURCE, "%s",
                         def->data.network.name);
            return -1;
        }
        virBufferVSprintf(buf, "(bridge '%s')", bridge);
        virBufferAddLit(buf, "(script 'vif-bridge')");
        VIR_FREE(bridge);
    }
    break;

    case VIR_DOMAIN_NET_TYPE_ETHERNET:
        if (def->data.ethernet.script)
            virBufferVSprintf(buf, "(script '%s')", def->data.ethernet.script);
        if (def->data.ethernet.ipaddr != NULL)
            virBufferVSprintf(buf, "(ip '%s')", def->data.ethernet.ipaddr);
        break;
    }

    if (def->ifname != NULL &&
        !STRPREFIX(def->ifname, "vif"))
        virBufferVSprintf(buf, "(vifname '%s')", def->ifname);

    if (def->model != NULL)
        virBufferVSprintf(buf, "(model '%s')", def->model);

    /*
     * apparently (type ioemu) breaks paravirt drivers on HVM so skip this
     * from Xen 3.1.0
     */
    if ((hvm) && (xendConfigVersion < 4))
        virBufferAddLit(buf, "(type ioemu)");

    if (!isAttach)
        virBufferAddLit(buf, ")");

    virBufferAddLit(buf, ")");

    return 0;
}

int
xenDaemonFormatSxprSound(virConnectPtr conn,
                         virDomainSoundDefPtr sound,
                         virBufferPtr buf)
{
    const char *str;
    virDomainSoundDefPtr prev = NULL;

    while (sound) {
        if (!(str = virDomainSoundModelTypeToString(sound->model))) {
            virXendError(conn, VIR_ERR_INTERNAL_ERROR,
                         _("unexpected sound model %d"), sound->model);
            return -1;
        }
        virBufferVSprintf(buf, "%s%s", prev ? "," : "", str);
        prev = sound;
        sound = sound->next;
    }

    return 0;
}


static int
xenDaemonFormatSxprInput(virConnectPtr conn,
                         virDomainInputDefPtr input,
                         virBufferPtr buf)
{
    if (input->bus != VIR_DOMAIN_INPUT_BUS_USB)
        return 0;

    if (input->type != VIR_DOMAIN_INPUT_TYPE_MOUSE &&
        input->type != VIR_DOMAIN_INPUT_TYPE_TABLET) {
        virXendError(conn, VIR_ERR_INTERNAL_ERROR,
                     _("unexpected input type %d"), input->type);
        return -1;
    }

    virBufferVSprintf(buf, "(usbdevice %s)",
                      input->type == VIR_DOMAIN_INPUT_TYPE_MOUSE ?
                      "mouse" : "tablet");

    return 0;
}


/**
 * xenDaemonFormatSxpr:
 * @conn: pointer to the hypervisor connection
 * @def: domain config definition
 * @xendConfigVersion: xend configuration file format
 *
 * Generate an SEXPR representing the domain configuration.
 *
 * Returns the 0 terminatedi S-Expr string or NULL in case of error.
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
    int hvm = 0, i;
    virDomainNetDefPtr net;
    virDomainDiskDefPtr disk;
    virDomainInputDefPtr input;

    virBufferAddLit(&buf, "(vm ");
    virBufferVSprintf(&buf, "(name '%s')", def->name);
    virBufferVSprintf(&buf, "(memory %lu)(maxmem %lu)",
                      def->memory/1024, def->maxmem/1024);
    virBufferVSprintf(&buf, "(vcpus %lu)", def->vcpus);

    if (def->cpumask) {
        char *ranges = virDomainCpuSetFormat(conn, def->cpumask, def->cpumasklen);
        if (ranges == NULL)
            goto error;
        virBufferVSprintf(&buf, "(cpus '%s')", ranges);
        VIR_FREE(ranges);
    }

    virUUIDFormat(def->uuid, uuidstr);
    virBufferVSprintf(&buf, "(uuid '%s')", uuidstr);

    if (def->os.bootloader) {
        if (def->os.bootloader[0])
            virBufferVSprintf(&buf, "(bootloader '%s')", def->os.bootloader);
        else
            virBufferAddLit(&buf, "(bootloader)");

        if (def->os.bootloaderArgs)
            virBufferVSprintf(&buf, "(bootloader_args '%s')", def->os.bootloaderArgs);
    }

    if (!(tmp = virDomainLifecycleTypeToString(def->onPoweroff))) {
        virXendError(conn, VIR_ERR_INTERNAL_ERROR,
                     _("unexpected lifecycle value %d"), def->onPoweroff);
        goto error;
    }
    virBufferVSprintf(&buf, "(on_poweroff '%s')", tmp);

    if (!(tmp = virDomainLifecycleTypeToString(def->onReboot))) {
        virXendError(conn, VIR_ERR_INTERNAL_ERROR,
                     _("unexpected lifecycle value %d"), def->onReboot);
        goto error;
    }
    virBufferVSprintf(&buf, "(on_reboot '%s')", tmp);

    if (!(tmp = virDomainLifecycleTypeToString(def->onCrash))) {
        virXendError(conn, VIR_ERR_INTERNAL_ERROR,
                     _("unexpected lifecycle value %d"), def->onCrash);
        goto error;
    }
    virBufferVSprintf(&buf, "(on_crash '%s')", tmp);

    if (!def->os.bootloader) {
        if (STREQ(def->os.type, "hvm"))
            hvm = 1;

        if (hvm)
            virBufferAddLit(&buf, "(image (hvm ");
        else
            virBufferAddLit(&buf, "(image (linux ");

        if (hvm &&
            def->os.loader == NULL) {
            virXendError(conn, VIR_ERR_INTERNAL_ERROR,
                         "%s",_("no HVM domain loader"));
            goto error;
        }

        if (def->os.kernel)
            virBufferVSprintf(&buf, "(kernel '%s')", def->os.kernel);
        if (def->os.initrd)
            virBufferVSprintf(&buf, "(ramdisk '%s')", def->os.initrd);
        if (def->os.root)
            virBufferVSprintf(&buf, "(root '%s')", def->os.root);
        if (def->os.cmdline)
            virBufferVSprintf(&buf, "(args '%s')", def->os.cmdline);

        if (hvm) {
            char bootorder[VIR_DOMAIN_BOOT_LAST+1];
            if (def->os.kernel)
                virBufferVSprintf(&buf, "(loader '%s')", def->os.loader);
            else
                virBufferVSprintf(&buf, "(kernel '%s')", def->os.loader);

            virBufferVSprintf(&buf, "(vcpus %lu)", def->vcpus);

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

            /* get the cdrom device file */
            /* Only XenD <= 3.0.2 wants cdrom config here */
            if (xendConfigVersion == 1) {
                disk = def->disks;
                while (disk) {
                    if (disk->type == VIR_DOMAIN_DISK_DEVICE_CDROM &&
                        STREQ(disk->dst, "hdc") &&
                        disk->src) {
                        virBufferVSprintf(&buf, "(cdrom '%s')",
                                          disk->src);
                        break;
                    }
                    disk = disk->next;
                }
            }

            if (def->features & (1 << VIR_DOMAIN_FEATURE_ACPI))
                virBufferAddLit(&buf, "(acpi 1)");
            if (def->features & (1 << VIR_DOMAIN_FEATURE_APIC))
                virBufferAddLit(&buf, "(apic 1)");
            if (def->features & (1 << VIR_DOMAIN_FEATURE_PAE))
                virBufferAddLit(&buf, "(pae 1)");

            virBufferAddLit(&buf, "(usb 1)");

            input = def->inputs;
            while (input) {
                if (xenDaemonFormatSxprInput(conn, input, &buf) < 0)
                    goto error;
                input = input->next;
            }

            if (def->parallels) {
                virBufferAddLit(&buf, "(parallel ");
                if (xenDaemonFormatSxprChr(conn, def->parallels, &buf) < 0)
                    goto error;
                virBufferAddLit(&buf, ")");
            } else {
                virBufferAddLit(&buf, "(parallel none)");
            }
            if (def->serials) {
                virBufferAddLit(&buf, "(serial ");
                if (xenDaemonFormatSxprChr(conn, def->serials, &buf) < 0)
                    goto error;
                virBufferAddLit(&buf, ")");
            } else {
                virBufferAddLit(&buf, "(serial none)");
            }

            if (def->localtime)
                virBufferAddLit(&buf, "(localtime 1)");

            if (def->sounds) {
                virBufferAddLit(&buf, "(soundhw '");
                if (xenDaemonFormatSxprSound(conn, def->sounds, &buf) < 0)
                    goto error;
                virBufferAddLit(&buf, "')");
            }
        }

        /* get the device emulation model */
        if (def->emulator && (hvm || xendConfigVersion >= 3))
            virBufferVSprintf(&buf, "(device_model '%s')", def->emulator);


        /* PV graphics for xen <= 3.0.4, or HVM graphics for xen <= 3.1.0 */
        if ((!hvm && xendConfigVersion < 3) ||
            (hvm && xendConfigVersion < 4)) {
            if (def->graphics &&
                xenDaemonFormatSxprGraphicsOld(conn, def->graphics, &buf, xendConfigVersion) < 0)
                goto error;
        }

        virBufferAddLit(&buf, "))");
    }

    disk = def->disks;
    while (disk) {
        if (xenDaemonFormatSxprDisk(conn, disk, &buf, hvm, xendConfigVersion, 0) < 0)
            goto error;
        disk = disk->next;
    }

    net = def->nets;
    while (net) {
        if (xenDaemonFormatSxprNet(conn, net, &buf, hvm, xendConfigVersion, 0) < 0)
            goto error;
        net = net->next;
    }

    /* New style PV graphics config xen >= 3.0.4,
     * or HVM graphics config xen >= 3.0.5 */
    if ((xendConfigVersion >= 3 && !hvm) ||
        (xendConfigVersion >= 4 && hvm)) {
        if (def->graphics &&
            xenDaemonFormatSxprGraphicsNew(conn, def->graphics, &buf) < 0)
            goto error;
    }

    virBufferAddLit(&buf, ")"); /* closes (vm */

    return virBufferContentAndReset(&buf);

error:
    tmp = virBufferContentAndReset(&buf);
    VIR_FREE(tmp);
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
    char *xref;

    if (dev->type == VIR_DOMAIN_DEVICE_DISK) {
        strcpy(class, "vbd");
        if (dev->data.disk->dst == NULL)
            return -1;
        xref = xenStoreDomainGetDiskID(domain->conn, domain->id,
                                       dev->data.disk->dst);
        if (xref == NULL)
            return -1;

        strncpy(ref, xref, ref_len);
        free(xref);
        ref[ref_len - 1] = '\0';
    } else if (dev->type == VIR_DOMAIN_DEVICE_NET) {
        char mac[30];
        virDomainNetDefPtr def = dev->data.net;
        snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                 def->mac[0], def->mac[1], def->mac[2],
                 def->mac[3], def->mac[4], def->mac[5]);

        strcpy(class, "vif");

        xref = xenStoreDomainGetNetworkID(domain->conn, domain->id,
                                          mac);
        if (xref == NULL)
            return -1;

        strncpy(ref, xref, ref_len);
        free(xref);
        ref[ref_len - 1] = '\0';
    } else {
        virXendError(NULL, VIR_ERR_NO_SUPPORT,
                     _("hotplug of device type not supported"));
        return -1;
    }

    return 0;
}

#endif /* ! PROXY */
