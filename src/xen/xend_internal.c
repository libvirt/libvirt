/*
 * xend_internal.c: access to Xen though the Xen Daemon interface
 *
 * Copyright (C) 2010-2014 Red Hat, Inc.
 * Copyright (C) 2005 Anthony Liguori <aliguori@us.ibm.com>
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
#include <math.h>
#include <stdarg.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>

#include "virerror.h"
#include "virlog.h"
#include "datatypes.h"
#include "xend_internal.h"
#include "driver.h"
#include "virsexpr.h"
#include "xen_sxpr.h"
#include "virbuffer.h"
#include "viruuid.h"
#include "xen_driver.h"
#include "xen_hypervisor.h"
#include "xs_internal.h" /* To extract VNC port & Serial console TTY */
#include "viralloc.h"
#include "count-one-bits.h"
#include "virfile.h"
#include "viruri.h"
#include "device_conf.h"
#include "virstring.h"

/* required for cpumap_t */
#include <xen/dom0_ops.h>

#define VIR_FROM_THIS VIR_FROM_XEND

VIR_LOG_INIT("xen.xend_internal");

/*
 * The number of Xen scheduler parameters
 */

#define XEND_RCV_BUF_MAX_LEN (256 * 1024)

static int
virDomainXMLDevID(virConnectPtr conn, virDomainDefPtr domain,
                  virDomainDeviceDefPtr dev, char *class,
                  char *ref, int ref_len);

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
    xenUnifiedPrivatePtr priv = xend->privateData;

    s = socket(priv->addrfamily, SOCK_STREAM, priv->addrprotocol);
    if (s == -1) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("failed to create a socket"));
        return -1;
    }

    /*
     * try to deactivate slow-start
     */
    ignore_value(setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (void *)&no_slow_start,
                            sizeof(no_slow_start)));

    if (connect(s, (struct sockaddr *)&priv->addr, priv->addrlen) == -1) {
        VIR_FORCE_CLOSE(s); /* preserves errno */

        /*
         * Connecting to XenD when privileged is mandatory, so log this
         * error
         */
        if (xenHavePrivilege()) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
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
        if ((len == -1) && ((errno == EAGAIN) || (errno == EINTR)))
            continue;

        /* eof */
        if (len == 0)
            break;

        /* unrecoverable error */
        if (len == -1) {
            if (do_read)
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               "%s", _("failed to read from Xen Daemon"));
            else
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               "%s", _("failed to write to Xen Daemon"));

            return -1;
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
        return -1;

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
static int ATTRIBUTE_NONNULL(2)
xend_req(int fd, char **content)
{
    char *buffer;
    size_t buffer_size = 4096;
    int content_length = 0;
    int retcode = 0;
    char *end_ptr;

    if (VIR_ALLOC_N(buffer, buffer_size) < 0)
        return -1;

    while (sreads(fd, buffer, buffer_size) > 0) {
        if (STREQ(buffer, "\r\n"))
            break;

        if (istartswith(buffer, "Content-Length: ")) {
            if (virStrToLong_i(buffer + 16, &end_ptr, 10, &content_length) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("failed to parse Xend response content length"));
                return -1;
            }
        } else if (istartswith(buffer, "HTTP/1.1 ")) {
            if (virStrToLong_i(buffer + 9, &end_ptr, 10, &retcode) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("failed to parse Xend response return code"));
                return -1;
            }
        }
    }

    VIR_FREE(buffer);

    if (content_length > 0) {
        ssize_t ret;

        if (content_length > XEND_RCV_BUF_MAX_LEN) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Xend returned HTTP Content-Length of %d, "
                             "which exceeds maximum of %d"),
                           content_length,
                           XEND_RCV_BUF_MAX_LEN);
            return -1;
        }

        /* Allocate one byte beyond the end of the largest buffer we will read.
           Combined with the fact that VIR_ALLOC_N zeros the returned buffer,
           this guarantees that "content" will always be NUL-terminated. */
        if (VIR_ALLOC_N(*content, content_length + 1) < 0)
            return -1;

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
xend_get(virConnectPtr xend, const char *path, char **content)
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

    if (ret < 0)
        return ret;

    if ((ret >= 300) && ((ret != 404) || (!STRPREFIX(path, "/xend/domain/")))) {
        virReportError(VIR_ERR_GET_FAILED,
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
        virReportError(VIR_ERR_POST_FAILED,
                       _("xend_post: error from xen daemon: %s"), err_buf);
    } else if ((ret == 202) && err_buf && (strstr(err_buf, "failed") != NULL)) {
        virReportError(VIR_ERR_POST_FAILED,
                       _("xend_post: error from xen daemon: %s"), err_buf);
        ret = -1;
    } else if (((ret >= 200) && (ret <= 202)) && err_buf &&
               (strstr(err_buf, "xend.err") != NULL)) {
        /* This is to catch case of things like 'virsh dump Domain-0 foo'
         * which returns a success code, but the word 'xend.err'
         * in body to indicate error :-(
         */
        virReportError(VIR_ERR_POST_FAILED,
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
            virReportError(VIR_ERR_HTTP_ERROR,
                           _("Unexpected HTTP error code %d"), ret);
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

        virBufferURIEncodeString(&buf, k);
        virBufferAddChar(&buf, '=');
        virBufferURIEncodeString(&buf, v);
        k = va_arg(ap, const char *);

        if (k)
            virBufferAddChar(&buf, '&');
    }

    if (virBufferCheckError(&buf) < 0)
        return -1;

    content = virBufferContentAndReset(&buf);
    VIR_DEBUG("xend op: %s", content);
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
 * internal routine to run a POST RPC operation to the Xen Daemon targeting
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
  ATTRIBUTE_FMT_PRINTF(2, 3);

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
 * sexpr_uuid:
 * @ptr: where to store the UUID, incremented
 * @sexpr: an S-Expression
 * @name: the name for the value
 *
 * convenience function to lookup a UUID value from the S-Expression
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
    xenUnifiedPrivatePtr priv = conn->privateData;

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

    return 0;
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
    xenUnifiedPrivatePtr priv = conn->privateData;
    struct addrinfo *res, *r;
    struct addrinfo hints;
    int saved_errno = EINVAL;
    int ret;

    priv->addrlen = 0;
    memset(&priv->addr, 0, sizeof(priv->addr));

    /* http://people.redhat.com/drepper/userapi-ipv6.html */
    memset (&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_ADDRCONFIG;

    ret = getaddrinfo (host, port, &hints, &res);
    if (ret != 0) {
        virReportError(VIR_ERR_UNKNOWN_HOST,
                       _("unable to resolve hostname '%s': %s"),
                       host, gai_strerror (ret));
        return -1;
    }

    /* Try to connect to each returned address in turn. */
    for (r = res; r; r = r->ai_next) {
        int sock;

        sock = socket(r->ai_family, SOCK_STREAM, r->ai_protocol);
        if (sock == -1) {
            saved_errno = errno;
            continue;
        }

        if (connect(sock, r->ai_addr, r->ai_addrlen) == -1) {
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

    freeaddrinfo(res);

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
    struct sexpr *root = NULL;
    char **ret = NULL;
    int count = 0;
    size_t i;
    struct sexpr *_for_i, *node;

    root = sexpr_get(xend, "/xend/domain");
    if (root == NULL)
        goto error;

    for (_for_i = root, node = root->u.s.car; _for_i->kind == SEXPR_CONS;
         _for_i = _for_i->u.s.cdr, node = _for_i->u.s.car) {
        if (node->kind != SEXPR_VALUE)
            continue;
        count++;
    }

    if (VIR_ALLOC_N(ret, count + 1) < 0)
        goto error;

    i = 0;
    for (_for_i = root, node = root->u.s.car; _for_i->kind == SEXPR_CONS;
         _for_i = _for_i->u.s.cdr, node = _for_i->u.s.car) {
        if (node->kind != SEXPR_VALUE)
            continue;
        if (VIR_STRDUP(ret[i], node->u.value) < 0)
            goto no_memory;
        i++;
    }

    ret[i] = NULL;

 error:
    sexpr_free(root);
    return ret;

 no_memory:
    for (i = 0; i < count; i++)
        VIR_FREE(ret[i]);
    VIR_FREE(ret);
    goto error;
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
    int ret;

    ret = xend_op(xend, "", "op", "create", "config", sexpr, NULL);

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
xenDaemonDomainLookupByName_ids(virConnectPtr xend,
                                const char *domname,
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
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("domain information incomplete, missing domid"));
        goto error;
    } else if (virStrToLong_i(value, NULL, 0, &ret) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("domain information incorrect domid not numeric"));
        ret = -1;
    } else if (uuid != NULL) {
        if (sexpr_uuid(uuid, root, "domain/uuid") < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("domain information incomplete, missing uuid"));
        }
    }

 error:
    sexpr_free(root);
    return ret;
}


/**
 * sexpr_to_xend_domain_state:
 * @root: an S-Expression describing a domain
 *
 * Internal routine getting the domain's state from the domain root provided.
 *
 * Returns domain's state.
 */
static int
ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2)
sexpr_to_xend_domain_state(virDomainDefPtr def, const struct sexpr *root)
{
    const char *flags;
    int state = VIR_DOMAIN_NOSTATE;

    if ((flags = sexpr_node(root, "domain/state"))) {
        if (strchr(flags, 'c'))
            state = VIR_DOMAIN_CRASHED;
        else if (strchr(flags, 's'))
            state = VIR_DOMAIN_SHUTOFF;
        else if (strchr(flags, 'd'))
            state = VIR_DOMAIN_SHUTDOWN;
        else if (strchr(flags, 'p'))
            state = VIR_DOMAIN_PAUSED;
        else if (strchr(flags, 'b'))
            state = VIR_DOMAIN_BLOCKED;
        else if (strchr(flags, 'r'))
            state = VIR_DOMAIN_RUNNING;
    } else if (def->id < 0 || sexpr_int(root, "domain/status") == 0) {
        /* As far as I can see the domain->id is a bad sign for checking
         * inactive domains as this is inaccurate after the domain has
         * been running once. However domain/status from xend seems to
         * be always present and 0 for inactive domains.
         * (keeping the check for id < 0 to be extra safe about backward
         * compatibility)
         */
        state = VIR_DOMAIN_SHUTOFF;
    }

    return state;
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
sexpr_to_xend_domain_info(virDomainDefPtr def,
                          const struct sexpr *root,
                          virDomainInfoPtr info)
{
    int vcpus;

    info->state = sexpr_to_xend_domain_state(def, root);
    info->memory = sexpr_u64(root, "domain/memory") << 10;
    info->maxMem = sexpr_u64(root, "domain/maxmem") << 10;
    info->cpuTime = sexpr_float(root, "domain/cpu_time") * 1000000000;

    vcpus = sexpr_int(root, "domain/vcpus");
    info->nrVirtCpu = count_one_bits_l(sexpr_u64(root, "domain/vcpu_avail"));
    if (!info->nrVirtCpu || vcpus < info->nrVirtCpu)
        info->nrVirtCpu = vcpus;

    return 0;
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
            return -1;
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

    return 0;
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
sexpr_to_xend_topology(const struct sexpr *root, virCapsPtr caps)
{
    const char *nodeToCpu;
    const char *cur;
    virCapsHostNUMACellCPUPtr cpuInfo = NULL;
    int cell, cpu, nb_cpus = 0;
    int n = 0;
    int numCpus;

    nodeToCpu = sexpr_node(root, "node/node_to_cpu");
    if (nodeToCpu == NULL)
        return 0;               /* no NUMA support */

    numCpus = sexpr_int(root, "node/nr_cpus");


    cur = nodeToCpu;
    while (*cur != 0) {
        virBitmapPtr cpuset = NULL;
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
        virSkipSpacesAndBackslash(&cur);
        if (*cur != ':')
            goto parse_error;
        cur++;
        virSkipSpacesAndBackslash(&cur);
        if (STRPREFIX(cur, "no cpus")) {
            nb_cpus = 0;
            if (!(cpuset = virBitmapNew(numCpus)))
                goto error;
        } else {
            if (virBitmapParseSeparator(cur, 'n', &cpuset, numCpus) < 0)
                goto error;

            nb_cpus = virBitmapCountBits(cpuset);
        }

        if (VIR_ALLOC_N(cpuInfo, numCpus) < 0) {
            virBitmapFree(cpuset);
            goto error;
        }

        for (n = 0, cpu = 0; cpu < numCpus; cpu++) {
            if (virBitmapIsBitSet(cpuset, cpu))
                cpuInfo[n++].id = cpu;
        }
        virBitmapFree(cpuset);

        if (virCapabilitiesAddHostNUMACell(caps, cell, 0,
                                           nb_cpus, cpuInfo,
                                           0, NULL,
                                           0, NULL) < 0)
            goto error;
        cpuInfo = NULL;
    }

    return 0;

 parse_error:
    virReportError(VIR_ERR_XEN_CALL, "%s", _("topology syntax error"));
 error:
    if (nb_cpus > 0)
        virCapabilitiesClearHostNUMACellCPUTopology(cpuInfo, nb_cpus);
    VIR_FREE(cpuInfo);
    return -1;
}


/**
 * sexpr_to_domain:
 * @conn: an existing virtual connection block
 * @root: an S-Expression describing a domain
 *
 * Internal routine returning the associated virDomainPtr for this domain
 *
 * Returns the domain def pointer or NULL in case of error.
 */
static virDomainDefPtr
sexpr_to_domain(virConnectPtr conn ATTRIBUTE_UNUSED, const struct sexpr *root)
{
    virDomainDefPtr ret = NULL;
    unsigned char uuid[VIR_UUID_BUFLEN];
    const char *name;
    int id = -1;

    if (sexpr_uuid(uuid, root, "domain/uuid") < 0)
        goto error;
    name = sexpr_node(root, "domain/name");
    if (name == NULL)
        goto error;

    if (sexpr_node(root, "domain/domid"))
        id = sexpr_int(root, "domain/domid");

    return virDomainDefNewFull(name, uuid, id);

 error:
    virReportError(VIR_ERR_INTERNAL_ERROR,
                   "%s", _("failed to parse Xend domain information"));
    virObjectUnref(ret);
    return NULL;
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
int
xenDaemonOpen(virConnectPtr conn,
              virConnectAuthPtr auth ATTRIBUTE_UNUSED,
              unsigned int flags)
{
    char *port = NULL;
    int ret = -1;

    virCheckFlags(VIR_CONNECT_RO, -1);

    /* Switch on the scheme, which we expect to be NULL (file),
     * "http" or "xen".
     */
    if (conn->uri->scheme == NULL) {
        /* It should be a file access */
        if (conn->uri->path == NULL) {
            virReportError(VIR_ERR_NO_CONNECT, __FUNCTION__);
            goto failed;
        }
        if (xenDaemonOpen_unix(conn, conn->uri->path) < 0)
            goto failed;
    } else if (STRCASEEQ(conn->uri->scheme, "xen")) {
        /*
         * try first to open the unix socket
         */
        if (xenDaemonOpen_unix(conn, "/var/lib/xend/xend-socket") == 0)
            goto done;

        /*
         * try though http on port 8000
         */
        if (xenDaemonOpen_tcp(conn, "localhost", "8000") < 0)
            goto failed;
    } else if (STRCASEEQ(conn->uri->scheme, "http")) {
        if (conn->uri->port &&
            virAsprintf(&port, "%d", conn->uri->port) == -1)
            goto failed;

        if (xenDaemonOpen_tcp(conn,
                              conn->uri->server ? conn->uri->server : "localhost",
                              port ? port : "8000") < 0)
            goto failed;
    } else {
        virReportError(VIR_ERR_NO_CONNECT, __FUNCTION__);
        goto failed;
    }

 done:
    ret = 0;

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
 * @conn: the connection object
 * @def: the domain to suspend
 *
 * Pause the domain, the domain is not scheduled anymore though its resources
 * are preserved. Use xenDaemonDomainResume() to resume execution.
 *
 * Returns 0 in case of success, -1 (with errno) in case of error.
 */
int
xenDaemonDomainSuspend(virConnectPtr conn, virDomainDefPtr def)
{
    if (def->id < 0) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("Domain %s isn't running."), def->name);
        return -1;
    }

    return xend_op(conn, def->name, "op", "pause", NULL);
}

/**
 * xenDaemonDomainResume:
 * @conn: the connection object
 * @def: the domain to resume
 *
 * Resume the domain after xenDaemonDomainSuspend() has been called
 *
 * Returns 0 in case of success, -1 (with errno) in case of error.
 */
int
xenDaemonDomainResume(virConnectPtr conn, virDomainDefPtr def)
{
    if (def->id < 0) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("Domain %s isn't running."), def->name);
        return -1;
    }

    return xend_op(conn, def->name, "op", "unpause", NULL);
}

/**
 * xenDaemonDomainShutdown:
 * @conn: the connection object
 * @def: the domain to shutdown
 *
 * Shutdown the domain, the OS is requested to properly shutdown
 * and the domain may ignore it.  It will return immediately
 * after queuing the request.
 *
 * Returns 0 in case of success, -1 (with errno) in case of error.
 */
int
xenDaemonDomainShutdown(virConnectPtr conn, virDomainDefPtr def)
{
    if (def->id < 0) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("Domain %s isn't running."), def->name);
        return -1;
    }

    return xend_op(conn, def->name, "op", "shutdown", "reason", "poweroff", NULL);
}

/**
 * xenDaemonDomainReboot:
 * @conn: the connection object
 * @def: the domain to reboot
 *
 * Reboot the domain, the OS is requested to properly shutdown
 * and restart but the domain may ignore it.  It will return immediately
 * after queuing the request.
 *
 * Returns 0 in case of success, -1 (with errno) in case of error.
 */
int
xenDaemonDomainReboot(virConnectPtr conn, virDomainDefPtr def)
{
    if (def->id < 0) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("Domain %s isn't running."), def->name);
        return -1;
    }

    return xend_op(conn, def->name, "op", "shutdown", "reason", "reboot", NULL);
}

/**
 * xenDaemonDomainDestroy:
 * @conn: the connection object
 * @def: the domain to destroy
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
xenDaemonDomainDestroy(virConnectPtr conn, virDomainDefPtr def)
{
    if (def->id < 0) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("Domain %s isn't running."), def->name);
        return -1;
    }

    return xend_op(conn, def->name, "op", "destroy", NULL);
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
char *
xenDaemonDomainGetOSType(virConnectPtr conn,
                         virDomainDefPtr def)
{
    char *type;
    struct sexpr *root;

    /* can we ask for a subset ? worth it ? */
    root = sexpr_get(conn, "/xend/domain/%s?detail=1", def->name);
    if (root == NULL)
        return NULL;

    ignore_value(VIR_STRDUP(type,
                            sexpr_lookup(root, "domain/image/hvm") ? "hvm" : "linux"));

    sexpr_free(root);

    return type;
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
xenDaemonDomainSave(virConnectPtr conn,
                    virDomainDefPtr def,
                    const char *filename)
{
    if (def->id < 0) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("Domain %s isn't running."), def->name);
        return -1;
    }

    /* We can't save the state of Domain-0, that would mean stopping it too */
    if (def->id == 0) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Cannot save host domain"));
        return -1;
    }

    return xend_op(conn, def->name, "op", "save", "file", filename, NULL);
}

/**
 * xenDaemonDomainCoreDump:
 * @conn: the connection object
 * @def: domain configuration
 * @filename: path for the output file
 * @flags: extra flags, currently unused
 *
 * This method will dump the core of a domain on a given file for analysis.
 * Note that for remote Xen Daemon the file path will be interpreted in
 * the remote host.
 *
 * Returns 0 in case of success, -1 in case of error.
 */
int
xenDaemonDomainCoreDump(virConnectPtr conn,
                        virDomainDefPtr def,
                        const char *filename,
                        unsigned int flags)
{
    virCheckFlags(VIR_DUMP_LIVE | VIR_DUMP_CRASH, -1);

    if (def->id < 0) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("Domain %s isn't running."), def->name);
        return -1;
    }

    return xend_op(conn, def->name,
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
unsigned long long
xenDaemonDomainGetMaxMemory(virConnectPtr conn, virDomainDefPtr def)
{
    unsigned long long ret = 0;
    struct sexpr *root;

    /* can we ask for a subset ? worth it ? */
    root = sexpr_get(conn, "/xend/domain/%s?detail=1", def->name);
    if (root == NULL)
        return 0;

    ret = sexpr_u64(root, "domain/memory") << 10;
    sexpr_free(root);

    return ret;
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
xenDaemonDomainSetMaxMemory(virConnectPtr conn,
                            virDomainDefPtr def,
                            unsigned long memory)
{
    char buf[1024];

    snprintf(buf, sizeof(buf), "%lu", VIR_DIV_UP(memory, 1024));
    return xend_op(conn, def->name, "op", "maxmem_set", "memory",
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
xenDaemonDomainSetMemory(virConnectPtr conn,
                         virDomainDefPtr def,
                         unsigned long memory)
{
    char buf[1024];

    snprintf(buf, sizeof(buf), "%lu", VIR_DIV_UP(memory, 1024));
    return xend_op(conn, def->name, "op", "mem_target_set",
                   "target", buf, NULL);
}


virDomainDefPtr
xenDaemonDomainFetch(virConnectPtr conn, int domid, const char *name,
                     const char *cpus)
{
    struct sexpr *root;
    xenUnifiedPrivatePtr priv = conn->privateData;
    virDomainDefPtr def = NULL;
    int id;
    char * tty;
    int vncport;

    if (name)
        root = sexpr_get(conn, "/xend/domain/%s?detail=1", name);
    else
        root = sexpr_get(conn, "/xend/domain/%d?detail=1", domid);
    if (root == NULL)
        return NULL;

    if (xenGetDomIdFromSxpr(root, &id) < 0)
        goto cleanup;
    xenUnifiedLock(priv);
    if (sexpr_lookup(root, "domain/image/hvm"))
        tty = xenStoreDomainGetSerialConsolePath(conn, id);
    else
        tty = xenStoreDomainGetConsolePath(conn, id);
    vncport = xenStoreDomainGetVNCPort(conn, id);
    xenUnifiedUnlock(priv);
    if (!(def = xenParseSxpr(root,
                             cpus,
                             tty,
                             vncport,
                             priv->caps,
                             priv->xmlopt)))
        goto cleanup;

 cleanup:
    sexpr_free(root);

    return def;
}


/**
 * xenDaemonDomainGetXMLDesc:
 * @domain: a domain object
 * @cpus: list of cpu the domain is pinned to.
 *
 * Get the XML description of the domain as a structure.
 *
 * Returns a virDomainDefPtr instance, or NULL in case of error.
 */
virDomainDefPtr
xenDaemonDomainGetXMLDesc(virConnectPtr conn,
                          virDomainDefPtr minidef,
                          const char *cpus)
{
    return xenDaemonDomainFetch(conn,
                                minidef->id,
                                minidef->name,
                                cpus);
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
xenDaemonDomainGetInfo(virConnectPtr conn,
                       virDomainDefPtr def,
                       virDomainInfoPtr info)
{
    struct sexpr *root;
    int ret;

    root = sexpr_get(conn, "/xend/domain/%s?detail=1", def->name);
    if (root == NULL)
        return -1;

    ret = sexpr_to_xend_domain_info(def, root, info);
    sexpr_free(root);
    return ret;
}


/**
 * xenDaemonDomainGetState:
 * @domain: a domain object
 * @state: returned domain's state
 * @reason: returned reason for the state
 *
 * This method looks up domain state and reason.
 *
 * Returns 0 in case of success, -1 in case of error
 */
int
xenDaemonDomainGetState(virConnectPtr conn,
                        virDomainDefPtr def,
                        int *state,
                        int *reason)
{
    struct sexpr *root;

    root = sexpr_get(conn, "/xend/domain/%s?detail=1", def->name);
    if (!root)
        return -1;

    *state = sexpr_to_xend_domain_state(def, root);
    if (reason)
        *reason = 0;

    sexpr_free(root);
    return 0;
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
 * Returns domain def pointer on success; NULL on error
 */
virDomainDefPtr
xenDaemonLookupByName(virConnectPtr conn, const char *domname)
{
    struct sexpr *root;
    virDomainDefPtr ret = NULL;

    root = sexpr_get(conn, "/xend/domain/%s?detail=1", domname);
    if (root == NULL)
        goto error;

    ret = sexpr_to_domain(conn, root);

 error:
    sexpr_free(root);
    return ret;
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
xenDaemonNodeGetInfo(virConnectPtr conn, virNodeInfoPtr info)
{
    int ret = -1;
    struct sexpr *root;

    root = sexpr_get(conn, "/xend/node/");
    if (root == NULL)
        return -1;

    ret = sexpr_to_xend_node_info(root, info);
    sexpr_free(root);
    return ret;
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
xenDaemonNodeGetTopology(virConnectPtr conn, virCapsPtr caps)
{
    int ret = -1;
    struct sexpr *root;

    root = sexpr_get(conn, "/xend/node/");
    if (root == NULL)
        return -1;

    ret = sexpr_to_xend_topology(root, caps);
    sexpr_free(root);
    return ret;
}


/**
 * xenDaemonDomainSetVcpusFlags:
 * @conn: the connection object
 * @def: domain configuration
 * @nvcpus: the new number of virtual CPUs for this domain
 * @flags: bitwise-ORd from virDomainVcpuFlags
 *
 * Change virtual CPUs allocation of domain according to flags.
 *
 * Returns 0 on success, -1 if an error message was issued
 */
int
xenDaemonDomainSetVcpusFlags(virConnectPtr conn,
                             virDomainDefPtr def,
                             unsigned int vcpus,
                             unsigned int flags)
{
    char buf[VIR_UUID_BUFLEN];
    int max;

    virCheckFlags(VIR_DOMAIN_VCPU_LIVE |
                  VIR_DOMAIN_VCPU_CONFIG |
                  VIR_DOMAIN_VCPU_MAXIMUM, -1);

    if (vcpus < 1) {
        virReportError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        return -1;
    }

    if (def->id < 0) {
        if (flags & VIR_DOMAIN_VCPU_LIVE) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("domain not running"));
            return -1;
        }
    } else {
        if ((flags & (VIR_DOMAIN_VCPU_LIVE | VIR_DOMAIN_VCPU_CONFIG)) !=
            (VIR_DOMAIN_VCPU_LIVE | VIR_DOMAIN_VCPU_CONFIG)) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("Xend only supports modifying both live and "
                             "persistent config"));
        }
    }

    /* Unfortunately, xend_op does not validate whether this exceeds
     * the maximum.  */
    flags |= VIR_DOMAIN_VCPU_MAXIMUM;
    if ((max = xenDaemonDomainGetVcpusFlags(conn, def, flags)) < 0) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("could not determine max vcpus for the domain"));
        return -1;
    }
    if (vcpus > max) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("requested vcpus is greater than max allowable"
                         " vcpus for the domain: %d > %d"), vcpus, max);
        return -1;
    }

    snprintf(buf, sizeof(buf), "%d", vcpus);
    return xend_op(conn, def->name, "op", "set_vcpus", "vcpus",
                   buf, NULL);
}

/**
 * xenDaemonDomainPinCpu:
 * @conn: the connection object
 * @minidef: minimal domain configuration
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
xenDaemonDomainPinVcpu(virConnectPtr conn,
                       virDomainDefPtr minidef,
                       unsigned int vcpu,
                       unsigned char *cpumap,
                       int maplen)
{
    char buf[VIR_UUID_BUFLEN], mapstr[sizeof(cpumap_t) * 64];
    size_t i, j;

    if (maplen > (int)sizeof(cpumap_t)) {
        virReportError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        return -1;
    }

    mapstr[0] = 0;
    /* from bit map, build character string of mapped CPU numbers */
    for (i = 0; i < maplen; i++) for (j = 0; j < 8; j++)
     if (cpumap[i] & (1 << j)) {
        snprintf(buf, sizeof(buf), "%zu,", (8 * i) + j);
        strcat(mapstr, buf);
    }
    mapstr[strlen(mapstr) - 1] = 0;

    snprintf(buf, sizeof(buf), "%d", vcpu);

    return xend_op(conn, minidef->name, "op", "pincpu", "vcpu", buf,
                   "cpumap", mapstr, NULL);

}

/**
 * xenDaemonDomainGetVcpusFlags:
 * @conn: the connection object
 * @def: domain configuration
 * @flags: bitwise-ORd from virDomainVcpuFlags
 *
 * Extract information about virtual CPUs of domain according to flags.
 *
 * Returns the number of vcpus on success, -1 if an error message was
 * issued

 */
int
xenDaemonDomainGetVcpusFlags(virConnectPtr conn,
                             virDomainDefPtr def,
                             unsigned int flags)
{
    struct sexpr *root;
    int ret;

    virCheckFlags(VIR_DOMAIN_VCPU_LIVE |
                  VIR_DOMAIN_VCPU_CONFIG |
                  VIR_DOMAIN_VCPU_MAXIMUM, -1);

    if (def->id < 0 && (flags & VIR_DOMAIN_VCPU_LIVE)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("domain not active"));
        return -1;
    }

    root = sexpr_get(conn, "/xend/domain/%s?detail=1", def->name);
    if (root == NULL)
        return -1;

    ret = sexpr_int(root, "domain/vcpus");
    if (!(flags & VIR_DOMAIN_VCPU_MAXIMUM)) {
        int vcpus = count_one_bits_l(sexpr_u64(root, "domain/vcpu_avail"));
        if (vcpus)
            ret = MIN(vcpus, ret);
    }
    if (!ret)
        ret = -1;
    sexpr_free(root);
    return ret;
}

/**
 * virDomainGetVcpus:
 * @conn: the connection object
 * @def: domain configuration
 * @info: pointer to an array of virVcpuInfo structures (OUT)
 * @maxinfo: number of structures in info array
 * @cpumaps: pointer to a bit map of real CPUs for all vcpus of this domain (in 8-bit bytes) (OUT)
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
xenDaemonDomainGetVcpus(virConnectPtr conn,
                        virDomainDefPtr def,
                        virVcpuInfoPtr info,
                        int maxinfo,
                        unsigned char *cpumaps,
                        int maplen)
{
    struct sexpr *root, *s, *t;
    virVcpuInfoPtr ipt = info;
    int nbinfo = 0, oln;
    unsigned char *cpumap;
    int vcpu, cpu;

    root = sexpr_get(conn, "/xend/domain/%s?op=vcpuinfo", def->name);
    if (root == NULL)
        return -1;

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
    return nbinfo;
}

/**
 * xenDaemonLookupByUUID:
 * @conn: pointer to the hypervisor connection
 * @uuid: the raw UUID for the domain
 *
 * Try to lookup a domain on xend based on its UUID.
 *
 * Returns domain def pointer on success; NULL on error
 */
virDomainDefPtr
xenDaemonLookupByUUID(virConnectPtr conn, const unsigned char *uuid)
{
    virDomainDefPtr ret;
    char *name = NULL;
    int id = -1;
    char *domname = NULL;
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    struct sexpr *root = NULL;

    virUUIDFormat(uuid, uuidstr);
    root = sexpr_get(conn, "/xend/domain/%s?detail=1", uuidstr);
    if (root == NULL)
        return NULL;
    domname = (char*)sexpr_node(root, "domain/name");
    if (sexpr_node(root, "domain/domid")) /* only active domains have domid */
        id = sexpr_int(root, "domain/domid");
    else
        id = -1;

    ignore_value(VIR_STRDUP(name, domname));

    sexpr_free(root);

    if (name == NULL)
        return NULL;

    ret = virDomainDefNewFull(name, uuid, id);

    VIR_FREE(name);
    return ret;
}

/**
 * xenDaemonCreateXML:
 * @conn: pointer to the hypervisor connection
 * @def: domain configuration
 * @flags: an optional set of virDomainFlags
 *
 * Launch a new Linux guest domain, based on an XML description similar
 * to the one returned by virDomainGetXMLDesc()
 * This function may requires privileged access to the hypervisor.
 *
 * Returns a new domain object or NULL in case of failure
 */
int
xenDaemonCreateXML(virConnectPtr conn, virDomainDefPtr def)
{
    int ret;
    char *sexpr;
    const char *tmp;
    struct sexpr *root;

    if (def->id != -1) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("Domain %s is already running"),
                       def->name);
        return -1;
    }

    if (!(sexpr = xenFormatSxpr(conn, def)))
        return -1;

    ret = xenDaemonDomainCreateXML(conn, sexpr);
    VIR_FREE(sexpr);
    if (ret != 0)
        goto error;

    /* This comes before wait_for_devices, to ensure that latter
       cleanup will destroy the domain upon failure */
    root = sexpr_get(conn, "/xend/domain/%s?detail=1", def->name);
    if (root == NULL)
        goto error;

    tmp = sexpr_node(root, "domain/domid");
    if (!tmp) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Domain %s did not start"),
                       def->name);
        goto error;
    }
    if (tmp)
        def->id = sexpr_int(root, "domain/domid");

    if (xend_wait_for_devices(conn, def->name) < 0)
        goto error;

    if (xenDaemonDomainResume(conn, def) < 0)
        goto error;

    return 0;

 error:
    /* Make sure we don't leave a still-born domain around */
    if (def->id != -1)
        xenDaemonDomainDestroy(conn, def);
    return -1;
}

/**
 * xenDaemonAttachDeviceFlags:
 * @conn: the connection object
 * @minidef: domain configuration
 * @xml: pointer to XML description of device
 * @flags: an OR'ed set of virDomainDeviceModifyFlags
 *
 * Create a virtual device attachment to backend.
 * XML description is translated into S-expression.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
int
xenDaemonAttachDeviceFlags(virConnectPtr conn,
                           virDomainDefPtr minidef,
                           const char *xml,
                           unsigned int flags)
{
    xenUnifiedPrivatePtr priv = conn->privateData;
    char *sexpr = NULL;
    int ret = -1;
    virDomainDeviceDefPtr dev = NULL;
    virDomainDefPtr def = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char class[8], ref[80];
    char *target = NULL;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE | VIR_DOMAIN_AFFECT_CONFIG, -1);

    if (minidef->id < 0) {
        /* Cannot modify live config if domain is inactive */
        if (flags & VIR_DOMAIN_DEVICE_MODIFY_LIVE) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("Cannot modify live config if domain is inactive"));
            return -1;
        }
    } else {
        /* Xen only supports modifying both live and persistent config */
        if (flags != (VIR_DOMAIN_DEVICE_MODIFY_LIVE |
                      VIR_DOMAIN_DEVICE_MODIFY_CONFIG)) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("Xend only supports modifying both live and "
                             "persistent config"));
            return -1;
        }
    }

    if (!(def = xenDaemonDomainFetch(conn,
                                     minidef->id,
                                     minidef->name,
                                     NULL)))
        goto cleanup;

    if (!(dev = virDomainDeviceDefParse(xml, def, priv->caps, priv->xmlopt,
                                        VIR_DOMAIN_DEF_PARSE_INACTIVE)))
        goto cleanup;


    switch (dev->type) {
    case VIR_DOMAIN_DEVICE_DISK:
        if (xenFormatSxprDisk(dev->data.disk,
                              &buf,
                              def->os.type == VIR_DOMAIN_OSTYPE_HVM ? 1 : 0,
                              1) < 0)
            goto cleanup;

        if (dev->data.disk->device != VIR_DOMAIN_DISK_DEVICE_CDROM &&
            VIR_STRDUP(target, dev->data.disk->dst) < 0)
            goto cleanup;
        break;

    case VIR_DOMAIN_DEVICE_NET:
        if (xenFormatSxprNet(conn,
                             dev->data.net,
                             &buf,
                             def->os.type == VIR_DOMAIN_OSTYPE_HVM ? 1 : 0,
                             1) < 0)
            goto cleanup;

        char macStr[VIR_MAC_STRING_BUFLEN];
        virMacAddrFormat(&dev->data.net->mac, macStr);

        if (VIR_STRDUP(target, macStr) < 0)
            goto cleanup;
        break;

    case VIR_DOMAIN_DEVICE_HOSTDEV:
        if (dev->data.hostdev->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS &&
            dev->data.hostdev->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI) {
            if (xenFormatSxprOnePCI(dev->data.hostdev, &buf, 0) < 0)
                goto cleanup;

            virPCIDeviceAddress PCIAddr;

            PCIAddr = dev->data.hostdev->source.subsys.u.pci.addr;
            if (virAsprintf(&target, "PCI device: %.4x:%.2x:%.2x",
                            PCIAddr.domain, PCIAddr.bus, PCIAddr.slot) < 0)
                goto cleanup;
        } else {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("unsupported device type"));
            goto cleanup;
        }
        break;

    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("unsupported device type"));
        goto cleanup;
    }

    sexpr = virBufferContentAndReset(&buf);

    if (virDomainXMLDevID(conn, minidef, dev, class, ref, sizeof(ref))) {
        /* device doesn't exist, define it */
        ret = xend_op(conn, def->name, "op", "device_create",
                      "config", sexpr, NULL);
    } else {
        if (dev->data.disk->device != VIR_DOMAIN_DISK_DEVICE_CDROM) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("target '%s' already exists"), target);
        } else {
            /* device exists, attempt to modify it */
            ret = xend_op(conn, minidef->name, "op", "device_configure",
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
 * @conn: the connection object
 * @minidef: domain configuration
 * @xml: pointer to XML description of device
 * @flags: an OR'ed set of virDomainDeviceModifyFlags
 *
 * Create a virtual device attachment to backend.
 * XML description is translated into S-expression.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
int
xenDaemonUpdateDeviceFlags(virConnectPtr conn,
                           virDomainDefPtr minidef,
                           const char *xml,
                           unsigned int flags)
{
    xenUnifiedPrivatePtr priv = conn->privateData;
    char *sexpr = NULL;
    int ret = -1;
    virDomainDeviceDefPtr dev = NULL;
    virDomainDefPtr def = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char class[8], ref[80];

    virCheckFlags(VIR_DOMAIN_DEVICE_MODIFY_LIVE |
                  VIR_DOMAIN_DEVICE_MODIFY_CONFIG, -1);

    if (minidef->id < 0) {
        /* Cannot modify live config if domain is inactive */
        if (flags & VIR_DOMAIN_DEVICE_MODIFY_LIVE) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("Cannot modify live config if domain is inactive"));
            return -1;
        }
    } else {
        /* Xen only supports modifying both live and persistent config */
        if (flags != (VIR_DOMAIN_DEVICE_MODIFY_LIVE |
                      VIR_DOMAIN_DEVICE_MODIFY_CONFIG)) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("Xend only supports modifying both live and "
                             "persistent config"));
            return -1;
        }
    }

    if (!(def = xenDaemonDomainFetch(conn,
                                     minidef->id,
                                     minidef->name,
                                     NULL)))
        goto cleanup;

    if (!(dev = virDomainDeviceDefParse(xml, def, priv->caps, priv->xmlopt,
                                        VIR_DOMAIN_DEF_PARSE_INACTIVE)))
        goto cleanup;


    switch (dev->type) {
    case VIR_DOMAIN_DEVICE_DISK:
        if (xenFormatSxprDisk(dev->data.disk,
                              &buf,
                              def->os.type == VIR_DOMAIN_OSTYPE_HVM ? 1 : 0,
                              1) < 0)
            goto cleanup;
        break;

    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("unsupported device type"));
        goto cleanup;
    }

    sexpr = virBufferContentAndReset(&buf);

    if (virDomainXMLDevID(conn, minidef, dev, class, ref, sizeof(ref))) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("requested device does not exist"));
        goto cleanup;
    } else {
        /* device exists, attempt to modify it */
        ret = xend_op(conn, minidef->name, "op", "device_configure",
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
 * @conn: the connection object
 * @minidef: domain configuration
 * @xml: pointer to XML description of device
 * @flags: an OR'ed set of virDomainDeviceModifyFlags
 *
 * Destroy a virtual device attachment to backend.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
int
xenDaemonDetachDeviceFlags(virConnectPtr conn,
                           virDomainDefPtr minidef,
                           const char *xml,
                           unsigned int flags)
{
    xenUnifiedPrivatePtr priv = conn->privateData;
    char class[8], ref[80];
    virDomainDeviceDefPtr dev = NULL;
    virDomainDefPtr def = NULL;
    int ret = -1;
    char *xendev = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE | VIR_DOMAIN_AFFECT_CONFIG, -1);

    if (minidef->id < 0) {
        /* Cannot modify live config if domain is inactive */
        if (flags & VIR_DOMAIN_DEVICE_MODIFY_LIVE) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("Cannot modify live config if domain is inactive"));
            return -1;
        }
    } else {
        /* Xen only supports modifying both live and persistent config */
        if (flags != (VIR_DOMAIN_DEVICE_MODIFY_LIVE |
                      VIR_DOMAIN_DEVICE_MODIFY_CONFIG)) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("Xend only supports modifying both live and "
                             "persistent config"));
            return -1;
        }
    }

    if (!(def = xenDaemonDomainFetch(conn,
                                     minidef->id,
                                     minidef->name,
                                     NULL)))
        goto cleanup;

    if (!(dev = virDomainDeviceDefParse(xml, def, priv->caps, priv->xmlopt,
                                        VIR_DOMAIN_DEF_PARSE_INACTIVE |
                                        VIR_DOMAIN_DEF_PARSE_SKIP_VALIDATE)))
        goto cleanup;

    if (virDomainXMLDevID(conn, minidef, dev, class, ref, sizeof(ref)))
        goto cleanup;

    if (dev->type == VIR_DOMAIN_DEVICE_HOSTDEV) {
        if (dev->data.hostdev->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS &&
            dev->data.hostdev->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI) {
            if (xenFormatSxprOnePCI(dev->data.hostdev, &buf, 1) < 0)
                goto cleanup;
        } else {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("unsupported device type"));
            goto cleanup;
        }
        xendev = virBufferContentAndReset(&buf);
        ret = xend_op(conn, minidef->name, "op", "device_configure",
                      "config", xendev, "dev", ref, NULL);
        VIR_FREE(xendev);
    } else {
        ret = xend_op(conn, minidef->name, "op", "device_destroy",
                      "type", class, "dev", ref, "force", "0", "rm_cfg", "1",
                      NULL);
    }

 cleanup:
    virDomainDefFree(def);
    virDomainDeviceDefFree(dev);

    return ret;
}

int
xenDaemonDomainGetAutostart(virConnectPtr conn,
                            virDomainDefPtr def,
                            int *autostart)
{
    struct sexpr *root;
    const char *tmp;

    root = sexpr_get(conn, "/xend/domain/%s?detail=1", def->name);
    if (root == NULL) {
        virReportError(VIR_ERR_XEN_CALL,
                       "%s", _("xenDaemonGetAutostart failed to find this domain"));
        return -1;
    }

    *autostart = 0;

    tmp = sexpr_node(root, "domain/on_xend_start");
    if (tmp && STREQ(tmp, "start"))
        *autostart = 1;

    sexpr_free(root);
    return 0;
}

int
xenDaemonDomainSetAutostart(virConnectPtr conn,
                            virDomainDefPtr def,
                            int autostart)
{
    struct sexpr *root, *autonode;
    virBuffer buffer = VIR_BUFFER_INITIALIZER;
    char *content = NULL;
    int ret = -1;

    root = sexpr_get(conn, "/xend/domain/%s?detail=1", def->name);
    if (root == NULL) {
        virReportError(VIR_ERR_XEN_CALL,
                       "%s", _("xenDaemonSetAutostart failed to find this domain"));
        return -1;
    }

    autonode = sexpr_lookup(root, "domain/on_xend_start");
    if (autonode) {
        const char *val = (autonode->u.s.car->kind == SEXPR_VALUE
                           ? autonode->u.s.car->u.value : NULL);
        if (!val || (STRNEQ(val, "ignore") && STRNEQ(val, "start"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("unexpected value from on_xend_start"));
            goto error;
        }

        /* Change the autostart value in place, then define the new sexpr */
        VIR_FREE(autonode->u.s.car->u.value);
        if (VIR_STRDUP(autonode->u.s.car->u.value,
                       autostart ? "start" : "ignore") < 0)
            goto error;

        if (sexpr2string(root, &buffer) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("sexpr2string failed"));
            goto error;
        }

        if (virBufferCheckError(&buffer) < 0)
            goto error;

        content = virBufferContentAndReset(&buffer);

        if (xend_op(conn, "", "op", "new", "config", content, NULL) != 0) {
            virReportError(VIR_ERR_XEN_CALL,
                           "%s", _("Failed to redefine sexpr"));
            goto error;
        }
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("on_xend_start not present in sexpr"));
        goto error;
    }

    ret = 0;
 error:
    virBufferFreeAndReset(&buffer);
    VIR_FREE(content);
    sexpr_free(root);
    return ret;
}

int
xenDaemonDomainMigratePrepare(virConnectPtr dconn ATTRIBUTE_UNUSED,
                              char **cookie ATTRIBUTE_UNUSED,
                              int *cookielen ATTRIBUTE_UNUSED,
                              const char *uri_in,
                              char **uri_out,
                              unsigned long flags,
                              const char *dname ATTRIBUTE_UNUSED,
                              unsigned long resource ATTRIBUTE_UNUSED)
{
    virCheckFlags(XEN_MIGRATION_FLAGS, -1);

    /* If uri_in is NULL, get the current hostname as a best guess
     * of how the source host should connect to us.  Note that caller
     * deallocates this string.
     */
    if (uri_in == NULL) {
        *uri_out = virGetHostname();
        if (*uri_out == NULL)
            return -1;
    }

    return 0;
}

int
xenDaemonDomainMigratePerform(virConnectPtr conn,
                              virDomainDefPtr def,
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

    virCheckFlags(XEN_MIGRATION_FLAGS, -1);

    /* Xen doesn't support renaming domains during migration. */
    if (dname) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("xenDaemonDomainMigrate: Xen does not support"
                               " renaming domains during migration"));
        return -1;
    }

    /* Xen (at least up to 3.1.0) takes a resource parameter but
     * ignores it.
     */
    if (bandwidth) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("xenDaemonDomainMigrate: Xen does not support"
                               " bandwidth limits during migration"));
        return -1;
    }

    /*
     * Check the flags.
     */
    if ((flags & VIR_MIGRATE_LIVE)) {
        strcpy(live, "1");
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
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("xenDaemonDomainMigrate: xend cannot migrate paused domains"));
        return -1;
    }

    /* XXX we could easily do tunnelled & peer2peer migration too
       if we want to. support these... */
    if (flags != 0) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("xenDaemonDomainMigrate: unsupported flag"));
        return -1;
    }

    /* Set hostname and port.
     *
     * URI is non-NULL (guaranteed by caller).  We expect either
     * "hostname", "hostname:port" or "xenmigr://hostname[:port]/".
     */
    if (strstr(uri, "//")) {   /* Full URI. */
        virURIPtr uriptr;
        if (!(uriptr = virURIParse(uri)))
            return -1;

        if (uriptr->scheme && STRCASENEQ(uriptr->scheme, "xenmigr")) {
            virReportError(VIR_ERR_INVALID_ARG,
                           "%s", _("xenDaemonDomainMigrate: only xenmigr://"
                                   " migrations are supported by Xen"));
            virURIFree(uriptr);
            return -1;
        }
        if (!uriptr->server) {
            virReportError(VIR_ERR_INVALID_ARG,
                           "%s", _("xenDaemonDomainMigrate: a hostname must be"
                                   " specified in the URI"));
            virURIFree(uriptr);
            return -1;
        }
        if (VIR_STRDUP(hostname, uriptr->server) < 0) {
            virURIFree(uriptr);
            return -1;
        }
        if (uriptr->port)
            snprintf(port, sizeof(port), "%d", uriptr->port);
        virURIFree(uriptr);
    } else if ((p = strrchr(uri, ':')) != NULL) { /* "hostname:port" */
        int port_nr, n;

        if (virStrToLong_i(p+1, NULL, 10, &port_nr) < 0) {
            virReportError(VIR_ERR_INVALID_ARG,
                           "%s", _("xenDaemonDomainMigrate: invalid port number"));
            return -1;
        }
        snprintf(port, sizeof(port), "%d", port_nr);

        /* Get the hostname. */
        n = p - uri; /* n = Length of hostname in bytes. */
        if (VIR_STRDUP(hostname, uri) < 0)
            return -1;
        hostname[n] = '\0';
    } else {                      /* "hostname" (or IP address) */
        if (VIR_STRDUP(hostname, uri) < 0)
            return -1;
    }

    VIR_DEBUG("hostname = %s, port = %s", hostname, port);

    /* Make the call.
     * NB:  xend will fail the operation if any parameters are
     * missing but happily accept unknown parameters.  This works
     * to our advantage since all parameters supported and required
     * by current xend can be included without breaking older xend.
     */
    ret = xend_op(conn, def->name,
                  "op", "migrate",
                  "destination", hostname,
                  "live", live,
                  "port", port,
                  "node", "-1", /* xen-unstable c/s 17753 */
                  "ssl", "0", /* xen-unstable c/s 17709 */
                  "change_home_server", "0", /* xen-unstable c/s 20326 */
                  "resource", "0", /* removed by xen-unstable c/s 17553 */
                  NULL);
    VIR_FREE(hostname);

    if (ret == 0 && undefined_source)
        xenDaemonDomainUndefine(conn, def);

    VIR_DEBUG("migration done");

    return ret;
}

int
xenDaemonDomainDefineXML(virConnectPtr conn, virDomainDefPtr def)
{
    int ret = -1;
    char *sexpr;

    if (!(sexpr = xenFormatSxpr(conn, def))) {
        virReportError(VIR_ERR_XML_ERROR,
                       "%s", _("failed to build sexpr"));
        goto cleanup;
    }

    ret = xend_op(conn, "", "op", "new", "config", sexpr, NULL);
    VIR_FREE(sexpr);
    if (ret != 0) {
        virReportError(VIR_ERR_XEN_CALL,
                       _("Failed to create inactive domain %s"), def->name);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    return ret;
}

int
xenDaemonDomainCreate(virConnectPtr conn,
                      virDomainDefPtr def)
{
    int ret;

    ret = xend_op(conn, def->name, "op", "start", NULL);

    if (ret == 0) {
        int id = xenDaemonDomainLookupByName_ids(conn, def->name,
                                                 def->uuid);
        if (id > 0)
            def->id = id;
    }

    return ret;
}

int
xenDaemonDomainUndefine(virConnectPtr conn, virDomainDefPtr def)
{
    return xend_op(conn, def->name, "op", "delete", NULL);
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
xenDaemonNumOfDefinedDomains(virConnectPtr conn)
{
    struct sexpr *root = NULL;
    int ret = -1;
    struct sexpr *_for_i, *node;

    root = sexpr_get(conn, "/xend/domain?state=halted");
    if (root == NULL)
        goto error;

    ret = 0;

    /* coverity[copy_paste_error] */
    for (_for_i = root, node = root->u.s.car; _for_i->kind == SEXPR_CONS;
         _for_i = _for_i->u.s.cdr, node = _for_i->u.s.car) {
        if (node->kind != SEXPR_VALUE)
            continue;
        ret++;
    }

 error:
    sexpr_free(root);
    return ret;
}

int
xenDaemonListDefinedDomains(virConnectPtr conn,
                            char **const names,
                            int maxnames)
{
    struct sexpr *root = NULL;
    size_t i;
    int ret = 0;
    struct sexpr *_for_i, *node;

    if (maxnames == 0)
        return 0;

    root = sexpr_get(conn, "/xend/domain?state=halted");
    if (root == NULL)
        goto error;

    /* coverity[copy_paste_error] */
    for (_for_i = root, node = root->u.s.car; _for_i->kind == SEXPR_CONS;
         _for_i = _for_i->u.s.cdr, node = _for_i->u.s.car) {
        if (node->kind != SEXPR_VALUE)
            continue;

        if (VIR_STRDUP(names[ret++], node->u.value) < 0)
            goto error;

        if (ret >= maxnames)
            break;
    }

 cleanup:
    sexpr_free(root);
    return ret;

 error:
    for (i = 0; i < ret; ++i)
        VIR_FREE(names[i]);

    ret = -1;
    goto cleanup;
}

/**
 * xenDaemonGetSchedulerType:
 * @conn: the hypervisor connection
 * @nparams: give a number of scheduler parameters
 *
 * Get the scheduler type of Xen
 *
 * Returns a scheduler name (credit or sedf) which must be freed by the
 * caller or NULL in case of failure
 */
char *
xenDaemonGetSchedulerType(virConnectPtr conn,
                          int *nparams)
{
    struct sexpr *root;
    const char *ret = NULL;
    char *schedulertype = NULL;

    root = sexpr_get(conn, "/xend/node/");
    if (root == NULL)
        return NULL;

    /* get xen_scheduler from xend/node */
    ret = sexpr_node(root, "node/xen_scheduler");
    if (ret == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("node information incomplete, missing scheduler name"));
        goto error;
    }
    if (STREQ(ret, "credit")) {
        if (VIR_STRDUP(schedulertype, "credit") < 0)
            goto error;
        if (nparams)
            *nparams = XEN_SCHED_CRED_NPARAM;
    } else if (STREQ(ret, "sedf")) {
        if (VIR_STRDUP(schedulertype, "sedf") < 0)
            goto error;
        if (nparams)
            *nparams = XEN_SCHED_SEDF_NPARAM;
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Unknown scheduler"));
        goto error;
    }

 error:
    sexpr_free(root);
    return schedulertype;

}

/**
 * xenDaemonGetSchedulerParameters:
 * @conn: the hypervisor connection
 * @def: domain configuration
 * @params: pointer to scheduler parameters
 *          This memory area must be allocated by the caller
 * @nparams: a number of scheduler parameters which should be same as a
 *           given number from xenDaemonGetSchedulerType()
 *
 * Get the scheduler parameters
 *
 * Returns 0 or -1 in case of failure
 */
int
xenDaemonGetSchedulerParameters(virConnectPtr conn,
                                virDomainDefPtr def,
                                virTypedParameterPtr params,
                                int *nparams)
{
    struct sexpr *root;
    char *sched_type = NULL;
    int sched_nparam = 0;
    int ret = -1;

    /* look up the information by domain name */
    root = sexpr_get(conn, "/xend/domain/%s?detail=1", def->name);
    if (root == NULL)
        return -1;

    /* get the scheduler type */
    sched_type = xenDaemonGetSchedulerType(conn, &sched_nparam);
    if (sched_type == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("Failed to get a scheduler name"));
        goto error;
    }

    switch (sched_nparam) {
        case XEN_SCHED_SEDF_NPARAM:
            if (*nparams < XEN_SCHED_SEDF_NPARAM) {
                virReportError(VIR_ERR_INVALID_ARG,
                               "%s", _("Invalid parameter count"));
                goto error;
            }

            /* TODO: Implement for Xen/SEDF */
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("SEDF schedular parameters not supported"));
            goto error;
        case XEN_SCHED_CRED_NPARAM:
            /* get cpu_weight/cpu_cap from xend/domain */
            if (sexpr_node(root, "domain/cpu_weight") == NULL) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               "%s", _("domain information incomplete, missing cpu_weight"));
                goto error;
            }
            if (sexpr_node(root, "domain/cpu_cap") == NULL) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               "%s", _("domain information incomplete, missing cpu_cap"));
                goto error;
            }

            if (virStrcpyStatic(params[0].field,
                                VIR_DOMAIN_SCHEDULER_WEIGHT) == NULL) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Weight %s too big for destination"),
                               VIR_DOMAIN_SCHEDULER_WEIGHT);
                goto error;
            }
            params[0].type = VIR_TYPED_PARAM_UINT;
            params[0].value.ui = sexpr_int(root, "domain/cpu_weight");

            if (*nparams > 1) {
                if (virStrcpyStatic(params[1].field,
                                    VIR_DOMAIN_SCHEDULER_CAP) == NULL) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("Cap %s too big for destination"),
                                   VIR_DOMAIN_SCHEDULER_CAP);
                    goto error;
                }
                params[1].type = VIR_TYPED_PARAM_UINT;
                params[1].value.ui = sexpr_int(root, "domain/cpu_cap");
            }

            if (*nparams > XEN_SCHED_CRED_NPARAM)
                *nparams = XEN_SCHED_CRED_NPARAM;
            ret = 0;
            break;
        default:
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Unknown scheduler"));
            goto error;
    }

 error:
    sexpr_free(root);
    VIR_FREE(sched_type);
    return ret;
}

/**
 * xenDaemonSetSchedulerParameters:
 * @conn: the hypervisor connection
 * @def: domain configuration
 * @params: pointer to scheduler parameters
 * @nparams: a number of scheduler setting parameters
 *
 * Set the scheduler parameters
 *
 * Returns 0 or -1 in case of failure
 */
int
xenDaemonSetSchedulerParameters(virConnectPtr conn,
                                virDomainDefPtr def,
                                virTypedParameterPtr params,
                                int nparams)
{
    struct sexpr *root;
    char *sched_type = NULL;
    size_t i;
    int sched_nparam = 0;
    int ret = -1;

    /* look up the information by domain name */
    root = sexpr_get(conn, "/xend/domain/%s?detail=1", def->name);
    if (root == NULL)
        return -1;

    /* get the scheduler type */
    sched_type = xenDaemonGetSchedulerType(conn, &sched_nparam);
    if (sched_type == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("Failed to get a scheduler name"));
        goto error;
    }

    switch (sched_nparam) {
        case XEN_SCHED_SEDF_NPARAM:
            /* TODO: Implement for Xen/SEDF */
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("SEDF schedular parameters not supported"));
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
                if (STREQ(params[i].field, VIR_DOMAIN_SCHEDULER_WEIGHT) &&
                    params[i].type == VIR_TYPED_PARAM_UINT) {
                    snprintf(buf_weight, sizeof(buf_weight), "%u", params[i].value.ui);
                } else if (STREQ(params[i].field, VIR_DOMAIN_SCHEDULER_CAP) &&
                    params[i].type == VIR_TYPED_PARAM_UINT) {
                    snprintf(buf_cap, sizeof(buf_cap), "%u", params[i].value.ui);
                } else {
                    virReportError(VIR_ERR_INVALID_ARG, __FUNCTION__);
                    goto error;
                }
            }

            /* if not get the scheduler parameter, set the current setting */
            if (strlen(buf_weight) == 0) {
                weight = sexpr_node(root, "domain/cpu_weight");
                if (weight == NULL) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   "%s", _("domain information incomplete, missing cpu_weight"));
                    goto error;
                }
                snprintf(buf_weight, sizeof(buf_weight), "%s", weight);
            }
            if (strlen(buf_cap) == 0) {
                cap = sexpr_node(root, "domain/cpu_cap");
                if (cap == NULL) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   "%s", _("domain information incomplete, missing cpu_cap"));
                    goto error;
                }
                snprintf(buf_cap, sizeof(buf_cap), "%s", cap);
            }

            ret = xend_op(conn, def->name, "op",
                          "domain_sched_credit_set", "weight", buf_weight,
                          "cap", buf_cap, NULL);
            break;
        }
        default:
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Unknown scheduler"));
            goto error;
    }

 error:
    sexpr_free(root);
    VIR_FREE(sched_type);
    return ret;
}

/**
 * xenDaemonDomainBlockPeek:
 * @conn: the hypervisor connection
 * @minidef: minimal domain configuration
 * @path: path to the file or device
 * @offset: offset
 * @size: size
 * @buffer: return buffer
 *
 * Returns 0 if successful, -1 if error
 */
int
xenDaemonDomainBlockPeek(virConnectPtr conn,
                         virDomainDefPtr minidef,
                         const char *path,
                         unsigned long long offset,
                         size_t size,
                         void *buffer)
{
    xenUnifiedPrivatePtr priv = conn->privateData;
    struct sexpr *root = NULL;
    int fd = -1, ret = -1;
    virDomainDefPtr def = NULL;
    int id;
    char * tty;
    int vncport;
    const char *actual;

    /* Security check: The path must correspond to a block device. */
    if (minidef->id > 0) {
        root = sexpr_get(conn, "/xend/domain/%d?detail=1",
                         minidef->id);
    } else if (minidef->id < 0) {
        root = sexpr_get(conn, "/xend/domain/%s?detail=1",
                         minidef->name);
    } else {
        /* This call always fails for dom0. */
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domainBlockPeek is not supported for dom0"));
        return -1;
    }

    if (!root) {
        virReportError(VIR_ERR_XEN_CALL, __FUNCTION__);
        return -1;
    }

    if (xenGetDomIdFromSxpr(root, &id) < 0)
        goto cleanup;
    xenUnifiedLock(priv);
    tty = xenStoreDomainGetConsolePath(conn, id);
    vncport = xenStoreDomainGetVNCPort(conn, id);
    xenUnifiedUnlock(priv);

    if (!(def = xenParseSxpr(root, NULL, tty, vncport,
                             priv->caps, priv->xmlopt)))
        goto cleanup;

    if (!(actual = virDomainDiskPathByName(def, path))) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("%s: invalid path"), path);
        goto cleanup;
    }
    path = actual;

    /* The path is correct, now try to open it and get its size. */
    fd = open(path, O_RDONLY);
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
    if (lseek(fd, offset, SEEK_SET) == (off_t) -1 ||
        saferead(fd, buffer, size) == (ssize_t) -1) {
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


/**
 * virDomainXMLDevID:
 * @conn: the hypervisor connection
 * @minidef: minimal domain configuration
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
virDomainXMLDevID(virConnectPtr conn,
                  virDomainDefPtr def,
                  virDomainDeviceDefPtr dev,
                  char *class,
                  char *ref,
                  int ref_len)
{
    xenUnifiedPrivatePtr priv = conn->privateData;
    char *xref;
    char *tmp;

    if (dev->type == VIR_DOMAIN_DEVICE_DISK) {
        const char *driver = virDomainDiskGetDriver(dev->data.disk);

        if (STREQ_NULLABLE(driver, "tap") || STREQ_NULLABLE(driver, "tap2"))
            strcpy(class, driver);
        else
            strcpy(class, "vbd");

        if (dev->data.disk->dst == NULL)
            return -1;
        xenUnifiedLock(priv);
        xref = xenStoreDomainGetDiskID(conn, def->id,
                                       dev->data.disk->dst);
        xenUnifiedUnlock(priv);
        if (xref == NULL)
            return -1;

        tmp = virStrcpy(ref, xref, ref_len);
        VIR_FREE(xref);
        if (tmp == NULL)
            return -1;
    } else if (dev->type == VIR_DOMAIN_DEVICE_NET) {
        char mac[VIR_MAC_STRING_BUFLEN];
        virDomainNetDefPtr netdef = dev->data.net;
        virMacAddrFormat(&netdef->mac, mac);

        strcpy(class, "vif");

        xenUnifiedLock(priv);
        xref = xenStoreDomainGetNetworkID(conn, def->id, mac);
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
        virDomainHostdevDefPtr hostdef = dev->data.hostdev;

        if (virAsprintf(&bdf, "%04x:%02x:%02x.%0x",
                        hostdef->source.subsys.u.pci.addr.domain,
                        hostdef->source.subsys.u.pci.addr.bus,
                        hostdef->source.subsys.u.pci.addr.slot,
                        hostdef->source.subsys.u.pci.addr.function) < 0)
            return -1;

        strcpy(class, "pci");

        xenUnifiedLock(priv);
        xref = xenStoreDomainGetPCIID(conn, def->id, bdf);
        xenUnifiedUnlock(priv);
        VIR_FREE(bdf);
        if (xref == NULL)
            return -1;

        tmp = virStrcpy(ref, xref, ref_len);
        VIR_FREE(xref);
        if (tmp == NULL)
            return -1;
    } else {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("hotplug of device type not supported"));
        return -1;
    }

    return 0;
}
