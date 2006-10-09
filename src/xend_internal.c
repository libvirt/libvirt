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

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/errno.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <math.h>
#include <stdarg.h>
#include <malloc.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <libxml/uri.h>

#include "libvirt/libvirt.h"
#include "driver.h"
#include "internal.h"
#include "sexpr.h"
#include "xml.h"
#include "xend_internal.h"
#include "xen_internal.h" /* for DOM0_INTERFACE_VERSION */
#include "xs_internal.h" /* To extract VNC port & Serial console TTY */

#ifndef PROXY
static const char * xenDaemonGetType(virConnectPtr conn);
static int xenDaemonListDomains(virConnectPtr conn, int *ids, int maxids);
static int xenDaemonNumOfDomains(virConnectPtr conn);
static virDomainPtr xenDaemonLookupByID(virConnectPtr conn, int id);
static virDomainPtr xenDaemonLookupByUUID(virConnectPtr conn,
                                          const unsigned char *uuid);
static virDomainPtr xenDaemonCreateLinux(virConnectPtr conn,
                                         const char *xmlDesc,
					 unsigned int flags);
#endif /* PROXY */

#ifndef PROXY
static virDriver xenDaemonDriver = {
    VIR_DRV_XEN_DAEMON,
    "XenDaemon",
    (DOM0_INTERFACE_VERSION >> 24) * 1000000 +
    ((DOM0_INTERFACE_VERSION >> 16) & 0xFF) * 1000 +
    (DOM0_INTERFACE_VERSION & 0xFFFF),
    NULL, /* init */
    xenDaemonOpen, /* open */
    xenDaemonClose, /* close */
    xenDaemonGetType, /* type */
    xenDaemonGetVersion, /* version */
    xenDaemonNodeGetInfo, /* nodeGetInfo */
    xenDaemonListDomains, /* listDomains */
    xenDaemonNumOfDomains, /* numOfDomains */
    xenDaemonCreateLinux, /* domainCreateLinux */
    xenDaemonLookupByID, /* domainLookupByID */
    xenDaemonLookupByUUID, /* domainLookupByUUID */
    xenDaemonDomainLookupByName, /* domainLookupByName */
    xenDaemonDomainSuspend, /* domainSuspend */
    xenDaemonDomainResume, /* domainResume */
    xenDaemonDomainShutdown, /* domainShutdown */
    xenDaemonDomainReboot, /* domainReboot */
    xenDaemonDomainDestroy, /* domainDestroy */
    NULL, /* domainFree */
    NULL, /* domainGetName */
    NULL, /* domainGetID */
    NULL, /* domainGetUUID */
    NULL, /* domainGetOSType */
    xenDaemonDomainGetMaxMemory, /* domainGetMaxMemory */
    xenDaemonDomainSetMaxMemory, /* domainSetMaxMemory */
    xenDaemonDomainSetMemory, /* domainMaxMemory */
    xenDaemonDomainGetInfo, /* domainGetInfo */
    xenDaemonDomainSave, /* domainSave */
    xenDaemonDomainRestore, /* domainRestore */
    xenDaemonDomainSetVcpus, /* domainSetVcpus */
    xenDaemonDomainPinVcpu, /* domainPinVcpu */
    xenDaemonDomainGetVcpus, /* domainGetVcpus */
    xenDaemonDomainDumpXML, /* domainDumpXML */
    NULL, /* listDefinedDomains */
    NULL, /* numOfDefinedDomains */
    NULL, /* domainCreate */
    NULL, /* domainDefineXML */
    NULL, /* domainUndefine */
};

/**
 * xenDaemonRegister:
 *
 * Registers the xenDaemon driver
 */
void xenDaemonRegister(void)
{
    virRegisterDriver(&xenDaemonDriver);
}
#endif /* !PROXY */

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


/**
 * virXendError:
 * @conn: the connection if available
 * @error: the error noumber
 * @info: extra information string
 *
 * Handle an error at the xend daemon interface
 */
static void
virXendError(virConnectPtr conn, virErrorNumber error, const char *info)
{
    const char *errmsg;

    if (error == VIR_ERR_OK)
        return;

    errmsg = __virErrorMsg(error, info);
    __virRaiseError(conn, NULL, VIR_FROM_XEND, error, VIR_ERR_ERROR,
                    errmsg, info, NULL, 0, 0, errmsg, info);
}

/**
 * virXendErrorInt:
 * @conn: the connection if available
 * @error: the error noumber
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
    __virRaiseError(conn, NULL, VIR_FROM_XEND, error, VIR_ERR_ERROR,
                    errmsg, NULL, NULL, val, 0, errmsg, val);
}


#define foreach(iterator, start) \
       	for (_for_i = (start), *iterator = (start)->car; \
             _for_i->kind == SEXPR_CONS; \
             _for_i = _for_i->cdr, iterator = _for_i->car)

#define foreach_node(iterator, start, path) \
        foreach(iterator, start) \
            if (sexpr_lookup(iterator, path))

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

    s = socket(xend->type, SOCK_STREAM, 0);
    if (s == -1) {
        virXendError(xend, VIR_ERR_INTERNAL_ERROR,
                     "failed to create a socket");
        return -1;
    }

    /*
     * try to desactivate slow-start
     */
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (void *)&no_slow_start,
               sizeof(no_slow_start));


    if (connect(s, xend->addr, xend->len) == -1) {
        serrno = errno;
        close(s);
        errno = serrno;
        s = -1;
    }

    return s;
}

/**
 * wr_sync:
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
                virXendError(NULL, VIR_ERR_INTERNAL_ERROR,
                             _("failed to read from Xen Daemon"));
            else
                virXendError(NULL, VIR_ERR_INTERNAL_ERROR,
                             _("failed to read from Xen Daemon"));

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
    return (strncasecmp(haystack, needle, strlen(needle)) == 0);
}


/**
 * xend_req:
 * @fd: the file descriptor
 * @content: the buffer to store the content
 * @n_content: the size of the buffer
 *
 * Read the HTTP response from a Xen Daemon request.
 *
 * Returns the HTTP return code.
 */
static int
xend_req(int fd, char *content, size_t n_content)
{
    char buffer[4096];
    int content_length = -1;
    int retcode = 0;

    while (sreads(fd, buffer, sizeof(buffer)) > 0) {
        if (strcmp(buffer, "\r\n") == 0)
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

        ret = sread(fd, content, content_length);
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

    swrites(s, "GET ");
    swrites(s, path);
    swrites(s, " HTTP/1.1\r\n");

    swrites(s,
            "Host: localhost:8000\r\n"
            "Accept-Encoding: identity\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n" "\r\n");

    ret = xend_req(s, content, n_content);
    close(s);

    if ((ret < 0) || (ret >= 300)) {
        virXendError(NULL, VIR_ERR_GET_FAILED, content);
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

    ret = xend_req(s, content, n_content);
    close(s);

    if ((ret < 0) || (ret >= 300)) {
        virXendError(NULL, VIR_ERR_POST_FAILED, content);
    } else if ((ret = 202) && (strstr(content, "failed") != NULL)) {
        virXendError(NULL, VIR_ERR_POST_FAILED, content);
        ret = -1;
    }

    return ret;
}
#endif /* ! PROXY */


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
            virXendErrorInt(NULL, VIR_ERR_HTTP_ERROR, ret);
            errno = EINVAL;
            break;
    }
    return -1;
}

#ifndef PROXY
/**
 * xend_op_ext2:
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
xend_op_ext2(virConnectPtr xend, const char *path, char *error,
             size_t n_error, const char *key, va_list ap)
{
    char ops[1024];
    const char *k = key, *v;
    int offset = 0;

    while (k) {
        v = va_arg(ap, const char *);

        offset += snprintf(ops + offset, sizeof(ops) - offset, "%s", k);
        offset += snprintf(ops + offset, sizeof(ops) - offset, "%s", "=");
        offset += snprintf(ops + offset, sizeof(ops) - offset, "%s", v);
        k = va_arg(ap, const char *);

        if (k)
            offset += snprintf(ops + offset,
                               sizeof(ops) - offset, "%s", "&");
    }

    return http2unix(xend_post(xend, path, ops, error, n_error));
}


/**
 * xend_node_op:
 * @xend: pointer to the Xen Daemon structure
 * @path: path for the object
 * @key: the key for the operation
 * @...: input values to pass to the operation
 *
 * internal routine to run a POST RPC operation to the Xen Daemon
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
static int
xend_node_op(virConnectPtr xend, const char *path, const char *key, ...)
{
    va_list ap;
    int ret;
    char error[1024];

    va_start(ap, key);
    ret = xend_op_ext2(xend, path, error, sizeof(error), key, ap);
    va_end(ap);

    return ret;
}


/**
 * xend_node_op:
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
xend_op_ext(virConnectPtr xend, const char *name, char *error,
            size_t n_error, const char *key, ...)
{
    char buffer[1024];
    va_list ap;
    int ret;

    snprintf(buffer, sizeof(buffer), "/xend/domain/%s", name);

    va_start(ap, key);
    ret = xend_op_ext2(xend, buffer, error, n_error, key, ap);
    va_end(ap);

    return ret;
}

#define xend_op(xend, name, key, ...) ({char error[1024]; xend_op_ext(xend, name, error, sizeof(error), key, __VA_ARGS__);})
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
    ret = http2unix(ret);
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
sexpr_int(struct sexpr *sexpr, const char *name)
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
sexpr_float(struct sexpr *sexpr, const char *name)
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
sexpr_u64(struct sexpr *sexpr, const char *name)
{
    const char *value = sexpr_node(sexpr, name);

    if (value) {
        return strtoll(value, NULL, 0);
    }
    return 0;
}

static int
sexpr_strlen(struct sexpr *sexpr, const char *path)
{
    const char *r = sexpr_node(sexpr, path);

    return r ? (strlen(r) + 1) : 0;
}

static const char *
sexpr_strcpy(char **ptr, struct sexpr *node, const char *path)
{
    const char *ret = sexpr_node(node, path);

    if (ret) {
        strcpy(*ptr, ret);
        ret = *ptr;
        *ptr += (strlen(ret) + 1);
    }
    return ret;
}


/**
 * sexpr_node_system:
 * @sexpr: an S-Expression
 * @name: the name for the value
 *
 * convenience function to lookup a value describing the kind of system
 * from the S-Expression
 *
 * Returns the value found or 0 if not found (but may not be an error)
 */
static enum xend_node_system
sexpr_node_system(struct sexpr *node, const char *path)
{
    const char *syst = sexpr_node(node, path);

    if (syst) {
        if (strcmp(syst, "Linux") == 0) {
            return XEND_SYSTEM_LINUX;
        }
    }

    return XEND_DEFAULT;
}

/**
 * sexpr_uuid:
 * @ptr: where to store the UUID, incremented
 * @sexpr: an S-Expression
 * @name: the name for the value
 *
 * convenience function to lookup an UUID value from the S-Expression
 *
 * Returns a pointer to the stored UUID or NULL in case of error.
 */
static unsigned char *
sexpr_uuid(char **ptr, struct sexpr *node, const char *path)
{
    const char *r = sexpr_node(node, path);
    return virParseUUID(ptr, r);
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
    char *buffer = malloc(len * 3 + 1);
    char *ptr = buffer;
    size_t i;

    if (buffer == NULL)
        return (NULL);
    for (i = 0; i < len; i++) {
        switch (string[i]) {
            case ' ':
            case '\n':
                sprintf(ptr, "%%%02x", string[i]);
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

    if ((conn == NULL) || (path == NULL))
        return (-1);

    addr = &conn->addr_un;
    addr->sun_family = AF_UNIX;
    memset(addr->sun_path, 0, sizeof(addr->sun_path));
    strncpy(addr->sun_path, path, sizeof(addr->sun_path));

    conn->len = sizeof(addr->sun_family) + strlen(addr->sun_path);
    if ((unsigned int) conn->len > sizeof(addr->sun_path))
        conn->len = sizeof(addr->sun_path);

    conn->addr = (struct sockaddr *) addr;
    conn->type = PF_UNIX;

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
int
xenDaemonOpen_tcp(virConnectPtr conn, const char *host, int port)
{
    struct in_addr ip;
    struct hostent *pent;

    if ((conn == NULL) || (host == NULL) || (port <= 0))
        return (-1);

    pent = gethostbyname(host);
    if (pent == NULL) {
        if (inet_aton(host, &ip) == 0) {
            virXendError(conn, VIR_ERR_UNKNOWN_HOST, host);
            errno = ESRCH;
            return (-1);
        }
    } else {
        memcpy(&ip, pent->h_addr_list[0], sizeof(ip));
    }

    conn->len = sizeof(struct sockaddr_in);
    conn->addr = (struct sockaddr *) &conn->addr_in;
    conn->type = PF_INET;

    conn->addr_in.sin_family = AF_INET;
    conn->addr_in.sin_port = htons(port);
    memcpy(&conn->addr_in.sin_addr, &ip, sizeof(ip));

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


/**
 * xend_rename:
 * @xend: pointer to the Xem Daemon block
 * @old: old name for the domain
 * @new: new name for the domain
 *
 * Rename the domain
 *
 * Returns 0 in case of success, -1 (with errno) in case of error.
 */
int
xend_rename(virConnectPtr xend, const char *old, const char *new)
{
    if ((xend == NULL) || (old == NULL) || (new == NULL)) {
        /* this should be caught at the interface but ... */
        virXendError(xend, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }
    return xend_op(xend, old, "op", "rename", "name", new, NULL);
}


/**
 * xend_sysrq:
 * @xend: pointer to the Xem Daemon block
 * @name: name for the domain
 * @key: the SysReq key
 *
 * Send a SysReq key which is used to debug Linux kernels running in the domain
 *
 * Returns 0 in case of success, -1 (with errno) in case of error.
 */
int
xend_sysrq(virConnectPtr xend, const char *name, const char *key)
{
    if ((xend == NULL) || (name == NULL) || (key == NULL)) {
        /* this should be caught at the interface but ... */
        virXendError(xend, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }
    return xend_op(xend, name, "op", "sysrq", "key", key, NULL);
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

    for (_for_i = root, node = root->car; _for_i->kind == SEXPR_CONS;
         _for_i = _for_i->cdr, node = _for_i->car) {
        if (node->kind != SEXPR_VALUE)
            continue;
        extra += strlen(node->value) + 1;
        count++;
    }

    ptr = malloc((count + 1) * sizeof(char *) + extra);
    if (ptr == NULL)
        goto error;

    ret = (char **) ptr;
    ptr += sizeof(char *) * (count + 1);

    i = 0;
    for (_for_i = root, node = root->car; _for_i->kind == SEXPR_CONS;
         _for_i = _for_i->cdr, node = _for_i->car) {
        if (node->kind != SEXPR_VALUE)
            continue;
        ret[i] = ptr;
        strcpy(ptr, node->value);
        ptr += strlen(node->value) + 1;
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
    free(ptr);
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
        memset(uuid, 0, 16);
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
        char **ptr = (char **) &uuid;

        if (sexpr_uuid(ptr, root, "domain/uuid") == NULL) {
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
    char *dst_uuid;
    struct sexpr *root;

    memset(uuid, 0, 16);

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

    dst_uuid = (char *)&uuid[0];
    if (sexpr_uuid(&dst_uuid, root, "domain/uuid") == NULL) {
      virXendError(xend, VIR_ERR_INTERNAL_ERROR,
                   _("domain information incomplete, missing uuid"));
      goto error;
    }

    sexpr_free(root);
    return (0);

error:
    sexpr_free(root);
    if (domname && *domname) {
      free(*domname);
      *domname = NULL;
    }
    return (-1);
}

/**
 * xend_get_node:
 * @xend: A xend instance
 *
 * This method returns information about the physical host
 * machine running Xen.
 *
 * Returns node info on success; NULL (with errno) on error
 */
struct xend_node *
xend_get_node(virConnectPtr xend)
{
    struct sexpr *root;
    struct xend_node *node = NULL;
    size_t size;
    char *ptr;

    root = sexpr_get(xend, "/xend/node/");
    if (root == NULL)
        goto error;

    size = sizeof(struct xend_node);
    size += sexpr_strlen(root, "node/host");
    size += sexpr_strlen(root, "node/release");
    size += sexpr_strlen(root, "node/version");
    size += sexpr_strlen(root, "node/machine");
    size += sexpr_strlen(root, "node/hw_caps");
    size += sexpr_strlen(root, "node/xen_caps");
    size += sexpr_strlen(root, "node/platform_params");
    size += sexpr_strlen(root, "node/xen_changeset");
    size += sexpr_strlen(root, "node/cc_compiler");
    size += sexpr_strlen(root, "node/cc_compile_by");
    size += sexpr_strlen(root, "node/cc_compile_domain");
    size += sexpr_strlen(root, "node/cc_compile_date");

    ptr = malloc(size);
    if (ptr == NULL)
        goto error;

    node = (struct xend_node *) ptr;
    ptr += sizeof(struct xend_node);

    node->system = sexpr_node_system(root, "node/system");
    node->host = sexpr_strcpy(&ptr, root, "node/host");
    node->release = sexpr_strcpy(&ptr, root, "node/release");
    node->version = sexpr_strcpy(&ptr, root, "node/version");
    node->machine = sexpr_strcpy(&ptr, root, "node/machine");
    node->nr_cpus = sexpr_int(root, "node/nr_cpus");
    node->nr_nodes = sexpr_int(root, "node/nr_nodes");
    node->sockets_per_node = sexpr_int(root, "node/sockets_per_node");
    node->cores_per_socket = sexpr_int(root, "node/cores_per_socket");
    node->threads_per_core = sexpr_int(root, "node/threads_per_core");
    node->cpu_mhz = sexpr_int(root, "node/cpu_mhz");
    node->hw_caps = sexpr_strcpy(&ptr, root, "node/hw_caps");
    node->total_memory = sexpr_u64(root, "node/total_memory") << 12;
    node->free_memory = sexpr_u64(root, "node/free_memory") << 12;
    node->xen_major = sexpr_int(root, "node/xen_major");
    node->xen_minor = sexpr_int(root, "node/xen_minor");
    {
        const char *tmp;

        tmp = sexpr_node(root, "node/xen_extra");
        if (tmp) {
            if (*tmp == '.')
                tmp++;
            node->xen_extra = atoi(tmp);
        } else {
            node->xen_extra = 0;
        }
    }
    node->xen_caps = sexpr_strcpy(&ptr, root, "node/xen_caps");
    node->platform_params =
        sexpr_strcpy(&ptr, root, "node/platform_params");
    node->xen_changeset = sexpr_strcpy(&ptr, root, "node/xen_changeset");
    node->cc_compiler = sexpr_strcpy(&ptr, root, "node/cc_compiler");
    node->cc_compile_by = sexpr_strcpy(&ptr, root, "node/cc_compile_by");
    node->cc_compile_domain =
        sexpr_strcpy(&ptr, root, "node/cc_compile_domain");
    node->cc_compile_date =
        sexpr_strcpy(&ptr, root, "node/cc_compile_date");

  error:
    sexpr_free(root);
    return node;
}

static int
xend_get_config_version(virConnectPtr conn) {
    struct sexpr *root;
    const char *value;

    if (!VIR_IS_CONNECT(conn)) {
        virXendError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }

    root = sexpr_get(conn, "/xend/node/");
    if (root == NULL)
        return (-1);

    value = sexpr_node(root, "node/xend_config_format");

    if (value) {
        int version = strtol(value, NULL, 10);
        sexpr_free(root);
        return version;
    } 

    sexpr_free(root);

    /* Xen prior to 3.0.3 did not have the xend_config_format
       field, and is implicitly version 1. */
    return 1;
}


#ifndef PROXY
/**
 * xend_node_shutdown:
 * @xend: A xend instance
 *
 * This method shuts down the physical machine running Xen.
 *
 * Returns 0 on success; -1 (with errno) on error
 */
int
xend_node_shutdown(virConnectPtr xend)
{
    return xend_node_op(xend, "/xend/node/", "op", "halt", NULL);
}

/**
 * xend_node_restart:
 * @xend: A xend instance
 *
 * This method restarts the physical machine running Xen.
 *
 * Returns 0 on success; -1 (with errno) on error
 */
int
xend_node_restart(virConnectPtr xend)
{
    return xend_node_op(xend, "/xend/node/", "op", "restart", NULL);
}


/**
 * xend_dmesg:
 * @xend: A xend instance
 * @buffer: A buffer to hold the messages
 * @n_buffer: Size of buffer (including null terminator)
 *
 * This function will place the debugging messages from the
 * hypervisor into a buffer with a null terminator.
 *
 * Returns 0 on success; -1 (with errno) on error
 */
int
xend_dmesg(virConnectPtr xend, char *buffer, size_t n_buffer)
{
    return http2unix(xend_get(xend, "/xend/node/dmesg", buffer, n_buffer));
}

/**
 * xend_dmesg_clear:
 * @xend: A xend instance
 *
 * This function will clear the debugging message ring queue
 * in the hypervisor.
 *
 * Returns 0 on success; -1 (with errno) on error
 */
int
xend_dmesg_clear(virConnectPtr xend)
{
    return xend_node_op(xend, "/xend/node/dmesg", "op", "clear", NULL);
}

/**
 * xend_log:
 * @xend: A xend instance
 * @buffer: The buffer to hold the messages
 * @n_buffer: Size of buffer (including null terminator)
 *
 * This function will place the Xend debugging messages into
 * a buffer with a null terminator.
 *
 * Returns 0 on success; -1 (with errno) on error
 */
int
xend_log(virConnectPtr xend, char *buffer, size_t n_buffer)
{
    return http2unix(xend_get(xend, "/xend/node/log", buffer, n_buffer));
}
#endif /* PROXY */

/*****************************************************************
 ******
 ******
 ******
 ******
             Needed helper code
 ******
 ******
 ******
 ******
 *****************************************************************/

/**
 * xend_parse_sexp_desc_os:
 * @node: the root of the parsed S-Expression
 * @buf: output buffer object
 * @hvm: true or 1 if no contains HVM S-Expression 
 *
 * Parse the xend sexp for description of os and append it to buf.
 *
 * Returns 0 in case of success and -1 in case of error
 */
static int
xend_parse_sexp_desc_os(struct sexpr *node, virBufferPtr buf, int hvm)
{
    const char *tmp;

    if (node == NULL || buf == NULL) {
       return(-1);
    }
    
    virBufferAdd(buf, "  <os>\n", 7);
    if (hvm) {
        virBufferVSprintf(buf, "    <type>hvm</type>\n");
        tmp = sexpr_node(node, "domain/image/hvm/kernel");
        if (tmp == NULL) {
            virXendError(NULL, VIR_ERR_INTERNAL_ERROR,
                         _("domain information incomplete, missing kernel"));
            return(-1);
	}
        virBufferVSprintf(buf, "    <loader>%s</loader>\n", tmp);
        tmp = sexpr_node(node, "domain/image/hvm/boot");
        if ((tmp != NULL) && (tmp[0] != 0)) {
           if (tmp[0] == 'a')
               /* XXX no way to deal with boot from 2nd floppy */
               virBufferAdd(buf, "    <boot dev='fd'/>\n", 21 );
           else if (tmp[0] == 'c')
	   /*
            * Don't know what to put here.  Say the vm has been given 3
            * disks - hda, hdb, hdc.  How does one identify the boot disk?
                * We're going to assume that first disk is the boot disk since
                * this is most common practice
	    */
               virBufferAdd(buf, "    <boot dev='hd'/>\n", 21 );
           else if (strcmp(tmp, "d") == 0)
               virBufferAdd(buf, "    <boot dev='cdrom'/>\n", 24 );
        }
    } else {
        virBufferVSprintf(buf, "    <type>linux</type>\n");
        tmp = sexpr_node(node, "domain/image/linux/kernel");
        if (tmp == NULL) {
            virXendError(NULL, VIR_ERR_INTERNAL_ERROR,
                         _("domain information incomplete, missing kernel"));
            return(-1);
	}
        virBufferVSprintf(buf, "    <kernel>%s</kernel>\n", tmp);
        tmp = sexpr_node(node, "domain/image/linux/ramdisk");
        if ((tmp != NULL) && (tmp[0] != 0))
           virBufferVSprintf(buf, "    <initrd>%s</initrd>\n", tmp);
        tmp = sexpr_node(node, "domain/image/linux/root");
        if ((tmp != NULL) && (tmp[0] != 0))
           virBufferVSprintf(buf, "    <root>%s</root>\n", tmp);
        tmp = sexpr_node(node, "domain/image/linux/args");
        if ((tmp != NULL) && (tmp[0] != 0))
           virBufferVSprintf(buf, "    <cmdline>%s</cmdline>\n", tmp);
    }

    virBufferAdd(buf, "  </os>\n", 8);
    return(0);
}

/**
 * xend_parse_sexp_desc:
 * @conn: the connection associated with the XML
 * @root: the root of the parsed S-Expression
 *
 * Parse the xend sexp description and turn it into the XML format similar
 * to the one unsed for creation.
 *
 * Returns the 0 terminated XML string or NULL in case of error.
 *         the caller must free() the returned value.
 */
static char *
xend_parse_sexp_desc(virConnectPtr conn, struct sexpr *root, int xendConfigVersion)
{
    char *ret;
    struct sexpr *cur, *node;
    const char *tmp;
    char *tty;
    virBuffer buf;
    int hvm = 0;
    int domid = -1;

    if (root == NULL) {
        /* ERROR */
        return (NULL);
    }
    ret = malloc(4000);
    if (ret == NULL)
        return (NULL);
    buf.content = ret;
    buf.size = 4000;
    buf.use = 0;

    domid = sexpr_int(root, "domain/domid");
    virBufferVSprintf(&buf, "<domain type='xen' id='%d'>\n", domid);

    tmp = sexpr_node(root, "domain/name");
    if (tmp == NULL) {
        virXendError(conn, VIR_ERR_INTERNAL_ERROR,
                     _("domain information incomplete, missing name"));
        goto error;
    }
    virBufferVSprintf(&buf, "  <name>%s</name>\n", tmp);
    tmp = sexpr_node(root, "domain/uuid");
    if (tmp != NULL) {
        char compact[33];
	int i, j;
	for (i = 0, j = 0;(i < 32) && (tmp[j] != 0);j++) {
	    if (((tmp[j] >= '0') && (tmp[j] <= '9')) ||
	        ((tmp[j] >= 'a') && (tmp[j] <= 'f'))) {
            compact[i++] = tmp[j];
        } else if ((tmp[j] >= 'A') && (tmp[j] <= 'F')) {
	        compact[i++] = tmp[j] + 'a' - 'A';
        }
	}
	compact[i] = 0;
	if (i > 0)
	    virBufferVSprintf(&buf, "  <uuid>%s</uuid>\n", compact);
    }
    tmp = sexpr_node(root, "domain/bootloader");
    if (tmp != NULL)
        virBufferVSprintf(&buf, "  <bootloader>%s</bootloader>\n", tmp);

    if (sexpr_lookup(root, "domain/image")) {
        hvm = sexpr_lookup(root, "domain/image/hvm") ? 1 : 0;
        xend_parse_sexp_desc_os(root, &buf, hvm);
    }

    virBufferVSprintf(&buf, "  <memory>%d</memory>\n",
                      (int) (sexpr_u64(root, "domain/maxmem") << 10));
    virBufferVSprintf(&buf, "  <vcpu>%d</vcpu>\n",
                      sexpr_int(root, "domain/vcpus"));
    tmp = sexpr_node(root, "domain/on_poweroff");
    if (tmp != NULL)
        virBufferVSprintf(&buf, "  <on_poweroff>%s</on_poweroff>\n", tmp);
    tmp = sexpr_node(root, "domain/on_reboot");
    if (tmp != NULL)
        virBufferVSprintf(&buf, "  <on_reboot>%s</on_reboot>\n", tmp);
    tmp = sexpr_node(root, "domain/on_crash");
    if (tmp != NULL)
        virBufferVSprintf(&buf, "  <on_crash>%s</on_crash>\n", tmp);

    if (hvm) {
        virBufferAdd(&buf, "  <features>\n", 13);
        if (sexpr_int(root, "domain/image/hvm/acpi"))
            virBufferAdd(&buf, "    <acpi/>\n", 12);
        if (sexpr_int(root, "domain/image/hvm/apic"))
            virBufferAdd(&buf, "    <apic/>\n", 12);
        if (sexpr_int(root, "domain/image/hvm/pae"))
            virBufferAdd(&buf, "    <pae/>\n", 11);
        virBufferAdd(&buf, "  </features>\n", 14);
    }

    virBufferAdd(&buf, "  <devices>\n", 12);

    /* in case of HVM we have devices emulation */
    tmp = sexpr_node(root, "domain/image/hvm/device_model");
    if ((tmp != NULL) && (tmp[0] != 0))
        virBufferVSprintf(&buf, "    <emulator>%s</emulator>\n", tmp);

    for (cur = root; cur->kind == SEXPR_CONS; cur = cur->cdr) {
        node = cur->car;
        /* Normally disks are in a (device (vbd ...)) block
           but blktap disks ended up in a differently named
           (device (tap ....)) block.... */
        if (sexpr_lookup(node, "device/vbd") ||
            sexpr_lookup(node, "device/tap")) {
            char *offset;
            int isBlock = 0;
            int cdrom = 0;
            char *drvName = NULL;
            char *drvType = NULL;
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

            if (src == NULL) {
                virXendError(conn, VIR_ERR_INTERNAL_ERROR,
                             _("domain information incomplete, vbd has no src"));
                goto bad_parse;
            }

            if (dst == NULL) {
                virXendError(conn, VIR_ERR_INTERNAL_ERROR,
                             _("domain information incomplete, vbd has no dev"));
                goto bad_parse;
            }


            offset = strchr(src, ':');
            if (!offset) {
                virXendError(conn, VIR_ERR_INTERNAL_ERROR,
                             _("cannot parse vbd filename, missing driver name"));
                goto bad_parse;
            }

            drvName = malloc((offset-src)+1);
            if (!drvName) {
                virXendError(conn, VIR_ERR_NO_MEMORY,
                             _("allocate new buffer"));
                goto bad_parse;
            }
            strncpy(drvName, src, (offset-src));
            drvName[offset-src] = '\0';

            src = offset + 1;

            if (!strcmp(drvName, "tap")) {
                offset = strchr(src, ':');
                if (!offset) {
                    virXendError(conn, VIR_ERR_INTERNAL_ERROR,
                                 _("cannot parse vbd filename, missing driver type"));
                    goto bad_parse;
                }

                drvType = malloc((offset-src)+1);
                if (!drvType) {
                    virXendError(conn, VIR_ERR_NO_MEMORY,
                                 _("allocate new buffer"));
                    goto bad_parse;
                }
                strncpy(drvType, src, (offset-src));
                drvType[offset-src] = '\0';
                src = offset + 1;
                /* Its possible to use blktap driver for block devs
                   too, but kinda pointless because blkback is better,
                   so we assume common case here. If blktap becomes
                   omnipotent, we can revisit this, perhaps stat()'ing
                   the src file in question */
                isBlock = 0;
            } else if (!strcmp(drvName, "phy")) {
                isBlock = 1;
            } else if (!strcmp(drvName, "file")) {
                isBlock = 0;
            }

            if (!strncmp(dst, "ioemu:", 6))
                dst += 6;

            /* New style disk config from Xen >= 3.0.3 */
            if (xendConfigVersion > 1) {
                offset = rindex(dst, ':');
                if (offset) {
                    if (!strcmp(offset, ":cdrom")) {
                        cdrom = 1;
                    } else if (!strcmp(offset, ":disk")) {
                        /* The default anyway */
                    } else {
                        /* Unknown, lets pretend its a disk too */
                    }
                    offset[0] = '\0';
                }
            }

            virBufferVSprintf(&buf, "    <disk type='%s' device='%s'>\n",
                              isBlock ? "block" : "file",
                              cdrom ? "cdrom" : "disk");
            if (drvType) {
                virBufferVSprintf(&buf, "      <driver name='%s' type='%s'/>\n", drvName, drvType);
            } else {
                virBufferVSprintf(&buf, "      <driver name='%s'/>\n", drvName);
            }
            if (isBlock) {
                virBufferVSprintf(&buf, "      <source dev='%s'/>\n", src);
            } else {
                virBufferVSprintf(&buf, "      <source file='%s'/>\n", src);
            }
            virBufferVSprintf(&buf, "      <target dev='%s'/>\n", dst);


            /* XXX should we force mode == r, if cdrom==1, or assume
               xend has already done this ? */
            if ((mode != NULL) && (!strcmp(mode, "r")))
                virBufferVSprintf(&buf, "      <readonly/>\n");
            virBufferAdd(&buf, "    </disk>\n", 12);

            bad_parse:
            if (drvName)
                free(drvName);
            if (drvType)
                free(drvType);
        } else if (sexpr_lookup(node, "device/vif")) {
            const char *tmp2;

            tmp = sexpr_node(node, "device/vif/bridge");
            tmp2 = sexpr_node(node, "device/vif/script");
            if ((tmp != NULL) || (strstr(tmp2, "bridge"))) {
                virBufferVSprintf(&buf, "    <interface type='bridge'>\n");
                if (tmp != NULL)
                    virBufferVSprintf(&buf, "      <source bridge='%s'/>\n",
                                      tmp);
                tmp = sexpr_node(node, "device/vif/vifname");
                if (tmp != NULL)
                    virBufferVSprintf(&buf, "      <target dev='%s'/>\n",
                                      tmp);
                tmp = sexpr_node(node, "device/vif/mac");
                if (tmp != NULL)
                    virBufferVSprintf(&buf, "      <mac address='%s'/>\n",
                                      tmp);
                tmp = sexpr_node(node, "device/vif/ip");
                if (tmp != NULL)
                    virBufferVSprintf(&buf, "      <ip address='%s'/>\n",
                                      tmp);
                if (tmp2 != NULL)
                    virBufferVSprintf(&buf, "      <script path='%s'/>\n",
                                      tmp2);
                virBufferAdd(&buf, "    </interface>\n", 17);
            } else {
                char serial[1000];

                TODO sexpr2string(node, serial, 1000);
                virBufferVSprintf(&buf, "<!-- Failed to parse vif: %s -->\n",
                                  serial);
            }
        }
    }

    if (hvm) {
        tmp = sexpr_node(root, "domain/image/hvm/fda");
        if ((tmp != NULL) && (tmp[0] != 0)) {
            virBufferAdd(&buf, "    <disk type='file' device='floppy'>\n", 39);
            virBufferVSprintf(&buf, "      <source file='%s'/>\n", tmp);
            virBufferAdd(&buf, "      <target dev='fda'/>\n", 26);
            virBufferAdd(&buf, "    </disk>\n", 12);
        }
        tmp = sexpr_node(root, "domain/image/hvm/fdb");
        if ((tmp != NULL) && (tmp[0] != 0)) {
            virBufferAdd(&buf, "    <disk type='file' device='floppy'>\n", 39);
            virBufferVSprintf(&buf, "      <source file='%s'/>\n", tmp);
            virBufferAdd(&buf, "      <target dev='fdb'/>\n", 26);
            virBufferAdd(&buf, "    </disk>\n", 12);
        }

        /* Old style cdrom config from Xen <= 3.0.2 */
        if (xendConfigVersion == 1) {
            tmp = sexpr_node(root, "domain/image/hvm/cdrom");
            if ((tmp != NULL) && (tmp[0] != 0)) {
                virBufferAdd(&buf, "    <disk type='file' device='cdrom'>\n", 38);
                virBufferAdd(&buf, "      <driver name='file'/>\n", 28);
                virBufferVSprintf(&buf, "      <source file='%s'/>\n", tmp);
                virBufferAdd(&buf, "      <target dev='hdc'/>\n", 26);
                virBufferAdd(&buf, "      <readonly/>\n", 18);
                virBufferAdd(&buf, "    </disk>\n", 12);
            }
        }
    }

    /* Graphics device */
    tmp = sexpr_fmt_node(root, "domain/image/%s/vnc", hvm ? "hvm" : "linux");
    if (tmp != NULL) {
        if (tmp[0] == '1') {
            int port = xenStoreDomainGetVNCPort(conn, domid);
            if (port == -1)
                port = 5900 + domid;
            virBufferVSprintf(&buf, "    <graphics type='vnc' port='%d'/>\n", port);
        }
    }

    tmp = sexpr_fmt_node(root, "domain/image/%s/sdl", hvm ? "hvm" : "linux");
    if (tmp != NULL) {
        if (tmp[0] == '1')
            virBufferAdd(&buf, "    <graphics type='sdl'/>\n", 27 );
    }

    tty = xenStoreDomainGetConsolePath(conn, domid);
    if (tty) {
        virBufferVSprintf(&buf, "    <console tty='%s'/>\n", tty);
        free(tty);
    }

    virBufferAdd(&buf, "  </devices>\n", 13);
    virBufferAdd(&buf, "</domain>\n", 10);

    buf.content[buf.use] = 0;
    return (ret);

  error:
    if (ret != NULL)
        free(ret);
    return (NULL);
}

char *
xend_parse_domain_sexp(virConnectPtr conn, char *sexpr, int xendConfigVersion) {
  struct sexpr *root = string2sexpr(sexpr);
  char *data;

  if (!root)
      return NULL;

  data = xend_parse_sexp_desc(conn, root, xendConfigVersion);

  sexpr_free(root);

  return data;
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
sexpr_to_xend_domain_info(struct sexpr *root, virDomainInfoPtr info)
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
            info->state = VIR_DOMAIN_SHUTDOWN;
        else if (strchr(flags, 'd'))
            info->state = VIR_DOMAIN_SHUTOFF;
        else if (strchr(flags, 'p'))
            info->state = VIR_DOMAIN_PAUSED;
        else if (strchr(flags, 'b'))
            info->state = VIR_DOMAIN_BLOCKED;
        else if (strchr(flags, 'r'))
            info->state = VIR_DOMAIN_RUNNING;
    } else {
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
sexpr_to_xend_node_info(struct sexpr *root, virNodeInfoPtr info)
{
    const char *machine;


    if ((root == NULL) || (info == NULL))
        return (-1);

    machine = sexpr_node(root, "node/machine");
    if (machine == NULL)
        info->model[0] = 0;
    else {
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
    return (0);
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
sexpr_to_domain(virConnectPtr conn, struct sexpr *root)
{
    virDomainPtr ret = NULL;
    char *dst_uuid = NULL;
    char uuid[16];
    const char *name;

    if ((conn == NULL) || (root == NULL))
        return(NULL);

    dst_uuid = (char *) &uuid[0];
    if (sexpr_uuid(&dst_uuid, root, "domain/uuid") == NULL)
        goto error;
    name = sexpr_node(root, "domain/name");
    if (name == NULL)
        goto error;

    ret = virGetDomain(conn, name, (const unsigned char *) &uuid[0]);
    if (ret == NULL) {
        virXendError(conn, VIR_ERR_NO_MEMORY, _("allocating domain"));
	return(NULL);
    }
    ret->handle = sexpr_int(root, "domain/domid");
    if (ret->handle < 0)
        goto error;

    return (ret);

error:
    virXendError(conn, VIR_ERR_INTERNAL_ERROR,
                 _("failed to parse Xend domain information"));
    if (ret != NULL)
        virFreeDomain(conn, ret);
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
xenDaemonOpen(virConnectPtr conn, const char *name, int flags)
{
    xmlURIPtr uri = NULL;
    int ret;
    unsigned long version;

    if ((name == NULL) || (name[0] == 0) || (!strcasecmp(name, "xen"))) {
	/*
	 * try first to open the unix socket
	 */
	ret = xenDaemonOpen_unix(conn, "/var/lib/xend/xend-socket");
	if (ret < 0)
	    goto try_http;
	ret = xenDaemonGetVersion(conn, &version);
	if (ret == 0)
	    goto done;

try_http:
        /*
	 * try though http on port 8000
	 */
	ret = xenDaemonOpen_tcp(conn, "localhost", 8000);
	if (ret < 0)
	    goto failed;
	ret = xenDaemonGetVersion(conn, &version);
	if (ret < 0)
	    goto failed;
    } else {
        /*
	 * We were given a connection name, expected to be an URL
	 */
	uri = xmlParseURI(name);
	if (uri == NULL) {
	    if (!(flags & VIR_DRV_OPEN_QUIET))
		virXendError(conn, VIR_ERR_NO_SUPPORT, name);
	    goto failed;
	}

	if (uri->scheme == NULL) {
	    /* It should be a file access */
	    if (uri->path == NULL) {
		if (!(flags & VIR_DRV_OPEN_QUIET))
		    virXendError(conn, VIR_ERR_NO_SUPPORT, name);
	        goto failed;
	    }
	    ret = xenDaemonOpen_unix(conn, uri->path);
	    if (ret < 0)
	        goto failed;

	    ret = xenDaemonGetVersion(conn, &version);
	    if (ret < 0)
		goto failed;
	} else if (!strcasecmp(uri->scheme, "http")) {
	    ret = xenDaemonOpen_tcp(conn, uri->server, uri->port);
            if (ret < 0)
	        goto failed;
	    ret = xenDaemonGetVersion(conn, &version);
	    if (ret < 0)
	        goto failed;
	} else {
	    if (!(flags & VIR_DRV_OPEN_QUIET))
		virXendError(conn, VIR_ERR_NO_SUPPORT, name);
	    goto failed;
	}
    }

done:
    if (uri != NULL)
        xmlFreeURI(uri);
    return(ret);
failed:
    if (uri != NULL)
        xmlFreeURI(uri);
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
 * Returns 0 in case of succes, -1 in case of error
 */
int
xenDaemonClose(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    return(0);
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
    return xend_op(domain->conn, domain->name, "op", "shutdown", "reason", "halt", NULL);
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
    return xend_op(domain->conn, domain->name, "op", "destroy", NULL);
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
        virXendError((domain ? domain->conn : NULL), VIR_ERR_INVALID_ARG,
	             __FUNCTION__);
        return(-1);
    }
    return xend_op(domain->conn, domain->name, "op", "save", "file", filename, NULL);
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

    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)) {
        virXendError((domain ? domain->conn : NULL), VIR_ERR_INVALID_ARG,
	             __FUNCTION__);
        return(-1);
    }

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

    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)) {
        virXendError((domain ? domain->conn : NULL), VIR_ERR_INVALID_ARG,
	             __FUNCTION__);
        return(-1);
    }
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

    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)) {
        virXendError((domain ? domain->conn : NULL), VIR_ERR_INVALID_ARG,
	             __FUNCTION__);
        return(-1);
    }
    snprintf(buf, sizeof(buf), "%lu", memory >> 10);
    return xend_op(domain->conn, domain->name, "op", "mem_target_set",
                   "target", buf, NULL);
}

#endif /* ! PROXY */

char *
xenDaemonDomainDumpXMLByID(virConnectPtr conn, int domid)
{
    char *ret = NULL;
    struct sexpr *root;
    int xendConfigVersion;

    root = sexpr_get(conn, "/xend/domain/%d?detail=1", domid);
    if (root == NULL)
        return (NULL);

    if ((xendConfigVersion = xend_get_config_version(conn)) < 0) {
        virXendError(conn, VIR_ERR_INTERNAL_ERROR, "cannot determine xend config version");
        return (NULL);
    }

    ret = xend_parse_sexp_desc(conn, root, xendConfigVersion);
    sexpr_free(root);

    return (ret);
}


#ifndef PROXY
/**
 * xenDaemonDomainDumpXML:
 * @domain: a domain object
 *
 * Provide an XML description of the domain.
 *
 * Returns a 0 terminated UTF-8 encoded XML instance, or NULL in case of error.
 *         the caller must free() the returned value.
 */
char *
xenDaemonDomainDumpXML(virDomainPtr domain, int flags ATTRIBUTE_UNUSED)
{
    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)) {
        virXendError((domain ? domain->conn : NULL), VIR_ERR_INVALID_ARG,
	             __FUNCTION__);
        return(NULL);
    }

    return xenDaemonDomainDumpXMLByID(domain->conn, domain->handle);
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

    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL) ||
        (info == NULL)) {
        virXendError((domain ? domain->conn : NULL), VIR_ERR_INVALID_ARG,
	             __FUNCTION__);
        return(-1);
    }


    root = sexpr_get(domain->conn, "/xend/domain/%s?detail=1", domain->name);
    if (root == NULL)
        return (-1);

    ret = sexpr_to_xend_domain_info(root, info);
    sexpr_free(root);
    return (ret);
}

#ifndef PROXY
/**
 * xenDaemonDomainLookupByName:
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
xenDaemonDomainLookupByName(virConnectPtr conn, const char *domname)
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

#ifndef PROXY
/**
 * xenDaemonGetType:
 * @conn: pointer to the Xen Daemon block
 *
 * Get the version level of the Hypervisor running.
 *
 * Returns -1 in case of error, 0 otherwise. if the version can't be
 *    extracted by lack of capacities returns 0 and @hvVer is 0, otherwise
 *    @hvVer value is major * 1,000,000 + minor * 1,000 + release
 */
static const char *
xenDaemonGetType(virConnectPtr conn)
{
    if (!VIR_IS_CONNECT(conn)) {
        virXendError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    return("XenDaemon");
}
#endif /* ! PROXY */

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
    const char *extra;
    int major, minor, release = 0;
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
    extra = sexpr_node(root, "node/xen_extra");
    if (extra != NULL) {
	while (*extra != 0) {
	    if ((*extra >= '0') && (*extra <= '9'))
		release = release * 10 + (*extra - '0');
	    extra++;
	}
    }
    sexpr_free(root);
    version = major * 1000000 + minor * 1000 + release;
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

    if ((ids == NULL) || (maxids <= 0))
        goto error;
    root = sexpr_get(conn, "/xend/domain");
    if (root == NULL)
        goto error;

    ret = 0;

    for (_for_i = root, node = root->car; _for_i->kind == SEXPR_CONS;
         _for_i = _for_i->cdr, node = _for_i->car) {
        if (node->kind != SEXPR_VALUE)
            continue;
        id = xenDaemonDomainLookupByName_ids(conn, node->value, NULL);
        if (id >= 0)
	    ids[ret++] = (int) id;
    }

error:
    if (root != NULL)
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

    for (_for_i = root, node = root->car; _for_i->kind == SEXPR_CONS;
         _for_i = _for_i->cdr, node = _for_i->car) {
        if (node->kind != SEXPR_VALUE)
            continue;
	ret++;
    }

error:
    if (root != NULL)
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
static virDomainPtr
xenDaemonLookupByID(virConnectPtr conn, int id) {
    char *name = NULL;
    unsigned char uuid[16];
    virDomainPtr ret;

    if (xenDaemonDomainLookupByID(conn, id, &name, uuid) < 0) {
        goto error;
    }

    ret = virGetDomain(conn, name, uuid);
    if (ret == NULL) {
        virXendError(conn, VIR_ERR_NO_MEMORY, _("allocating domain"));
        goto error;
    }
    ret->handle = id;
    free(name);
    return (ret);

 error:
    if (name != NULL)
      free(name);
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
    char buf[16];

    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)
     || (vcpus < 1)) {
        virXendError((domain ? domain->conn : NULL), VIR_ERR_INVALID_ARG,
	             __FUNCTION__);
        return (-1);
    }
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
    char buf[16], mapstr[sizeof(cpumap_t) * 64] = "[";
    int i, j;

    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)
     || (cpumap == NULL) || (maplen < 1) || (maplen > (int)sizeof(cpumap_t))) {
        virXendError((domain ? domain->conn : NULL), VIR_ERR_INVALID_ARG,
	             __FUNCTION__);
        return (-1);
    }

    /* from bit map, build character string of mapped CPU numbers */
    for (i = 0; i < maplen; i++) for (j = 0; j < 8; j++)
     if (cpumap[i] & (1 << j)) {
        sprintf(buf, "%d,", (8 * i) + j);
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
 *	If cpumaps is NULL, then no cupmap information is returned by the API.
 *	It's assumed there is <maxinfo> cpumap in cpumaps array.
 *	The memory allocated to cpumaps must be (maxinfo * maplen) bytes
 *	(ie: calloc(maxinfo, maplen)).
 *	One cpumap inside cpumaps has the format described in virDomainPinVcpu() API.
 * @maplen: number of bytes in one cpumap, from 1 up to size of CPU map in
 *	underlying virtualization system (Xen...).
 * 
 * Extract information about virtual CPUs of domain, store it in info array
 * and also in cpumaps if this pointer is'nt NULL.
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
    root = sexpr_get(domain->conn, "/xend/domain/%s?op=vcpuinfo", domain->name);
    if (root == NULL)
        return (-1);

    if (cpumaps != NULL)
        memset(cpumaps, 0, maxinfo * maplen);

    /* scan the sexprs from "(vcpu (number x)...)" and get parameter values */
    for (s = root; s->kind == SEXPR_CONS; s = s->cdr) {
        if ((s->car->kind == SEXPR_CONS) &&
            (s->car->car->kind == SEXPR_VALUE) &&
            !strcmp(s->car->car->value, "vcpu")) {
            t = s->car;
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
                for (t = t->cdr; t->kind == SEXPR_CONS; t = t->cdr)
                    if ((t->car->kind == SEXPR_CONS) &&
                        (t->car->car->kind == SEXPR_VALUE) &&
                        !strcmp(t->car->car->value, "cpumap") &&
                        (t->car->cdr->kind == SEXPR_CONS)) {
                        for (t = t->car->cdr->car; t->kind == SEXPR_CONS; t = t->cdr)
                            if (t->car->kind == SEXPR_VALUE) {
                                cpu = strtol(t->car->value, NULL, 0);
                                if (cpu >= 0 && (VIR_CPU_MAPLEN(cpu+1) <= maplen)) {
                                    VIR_USE_CPU(cpumap, cpu);
                                }
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
static virDomainPtr
xenDaemonLookupByUUID(virConnectPtr conn, const unsigned char *uuid)
{
    virDomainPtr ret;
    char *name = NULL;
    char **names;
    char **tmp;
    unsigned char ident[16];
    int id = -1;

    names = xenDaemonListDomainsOld(conn);
    tmp = names;

    if (names == NULL) {
        TODO                    /* try to fallback to xenstore lookup */
            return (NULL);
    }
    while (*tmp != NULL) {
        id = xenDaemonDomainLookupByName_ids(conn, *tmp, &ident[0]);
        if (id >= 0) {
            if (!memcmp(uuid, ident, 16)) {
                name = strdup(*tmp);
                break;
            }
        }
        tmp++;
    }
    free(names);

    if (name == NULL)
        goto error;

    ret = virGetDomain(conn, name, uuid);
    if (ret == NULL) {
      virXendError(conn, VIR_ERR_NO_MEMORY, _("allocating domain"));
        goto error;
    }
    ret->handle = id;
    if (name != NULL)
        free(name);
    return (ret);

error:
    if (name != NULL)
        free(name);
    return (NULL);
}

/**
 * xenDaemonCreateLinux:
 * @conn: pointer to the hypervisor connection
 * @xmlDesc: an XML description of the domain
 * @flags: an optional set of virDomainFlags
 *
 * Launch a new Linux guest domain, based on an XML description similar
 * to the one returned by virDomainGetXMLDesc()
 * This function may requires priviledged access to the hypervisor.
 * 
 * Returns a new domain object or NULL in case of failure
 */
static virDomainPtr
xenDaemonCreateLinux(virConnectPtr conn, const char *xmlDesc,
                     unsigned int flags ATTRIBUTE_UNUSED)
{
    int ret;
    char *sexpr;
    char *name = NULL;
    virDomainPtr dom;
    int xendConfigVersion;

    if (!VIR_IS_CONNECT(conn)) {
        virXendError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (xmlDesc == NULL) {
        virXendError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (NULL);
    }

    if ((xendConfigVersion = xend_get_config_version(conn)) < 0) {
        virXendError(conn, VIR_ERR_INTERNAL_ERROR, "cannot determine xend config version");
        return (NULL);
    }

    sexpr = virDomainParseXMLDesc(xmlDesc, &name, xendConfigVersion);
    if ((sexpr == NULL) || (name == NULL)) {
        virXendError(conn, VIR_ERR_XML_ERROR, "Failed to parse the XML domain description");
        if (sexpr != NULL)
            free(sexpr);
        if (name != NULL)
            free(name);

        return (NULL);
    }

    ret = xenDaemonDomainCreateLinux(conn, sexpr);
    free(sexpr);
    if (ret != 0) {
        fprintf(stderr, _("Failed to create domain %s\n"), name);
        goto error;
    }

    ret = xend_wait_for_devices(conn, name);
    if (ret != 0) {
        fprintf(stderr, _("Failed to get devices for domain %s\n"), name);
        goto error;
    }

    dom = virDomainLookupByName(conn, name);
    if (dom == NULL) {
        goto error;
    }

    ret = xenDaemonDomainResume(dom);
    if (ret != 0) {
        fprintf(stderr, _("Failed to resume new domain %s\n"), name);
        xenDaemonDomainDestroy(dom);
        goto error;
    }

    dom = virDomainLookupByName(conn, name);
    free(name);

    return (dom);
  error:
    if (name != NULL)
        free(name);
    return (NULL);
}
#endif /* ! PROXY */

/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
