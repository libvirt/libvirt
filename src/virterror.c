/*
 * virterror.c: implements error handling and reporting code for libvirt
 *
 * Copy:  Copyright (C) 2006, 2008 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Author: Daniel Veillard <veillard@redhat.com>
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "virterror_internal.h"
#include "datatypes.h"

virError virLastErr =       /* the last error */
  { .code = 0, .domain = 0, .message = NULL, .level = VIR_ERR_NONE,
    .conn = NULL, .dom = NULL, .str1 = NULL, .str2 = NULL, .str3 = NULL,
    .int1 = 0, .int2 = 0, .net = NULL };
virErrorFunc virErrorHandler = NULL;     /* global error handler */
void *virUserData = NULL;        /* associated data */

/*
 * Macro used to format the message as a string in virRaiseError
 * and borrowed from libxml2.
 */
#define VIR_GET_VAR_STR(msg, str) {				\
    int       size, prev_size = -1;				\
    int       chars;						\
    char      *larger;						\
    va_list   ap;						\
                                                                \
    str = (char *) malloc(150);					\
    if (str != NULL) {						\
                                                                \
    size = 150;							\
                                                                \
    while (1) {							\
        va_start(ap, msg);					\
        chars = vsnprintf(str, size, msg, ap);			\
        va_end(ap);						\
        if ((chars > -1) && (chars < size)) {			\
            if (prev_size == chars) {				\
                break;						\
            } else {						\
                prev_size = chars;				\
            }							\
        }							\
        if (chars > -1)						\
            size += chars + 1;					\
        else							\
            size += 100;					\
        if ((larger = (char *) realloc(str, size)) == NULL) {	\
            break;						\
        }							\
        str = larger;						\
    }}								\
}

/*
 * virGetLastError:
 *
 * Provide a pointer to the last error caught at the library level
 * Simpler but may not be suitable for multithreaded accesses, in which
 * case use virCopyLastError()
 *
 * Returns a pointer to the last error or NULL if none occurred.
 */
virErrorPtr
virGetLastError(void)
{
    if (virLastErr.code == VIR_ERR_OK)
        return (NULL);
    return (&virLastErr);
}

/*
 * virCopyLastError:
 * @to: target to receive the copy
 *
 * Copy the content of the last error caught at the library level
 * One will need to free the result with virResetError()
 *
 * Returns 0 if no error was found and the error code otherwise and -1 in case
 *         of parameter error.
 */
int
virCopyLastError(virErrorPtr to)
{
    if (to == NULL)
        return (-1);
    if (virLastErr.code == VIR_ERR_OK)
        return (0);
    memcpy(to, &virLastErr, sizeof(virError));
    return (virLastErr.code);
}

/**
 * virResetError:
 * @err: pointer to the virError to clean up
 *
 * Reset the error being pointed to
 */
void
virResetError(virErrorPtr err)
{
    if (err == NULL)
        return;
    free(err->message);
    free(err->str1);
    free(err->str2);
    free(err->str3);
    memset(err, 0, sizeof(virError));
}

/**
 * virResetLastError:
 *
 * Reset the last error caught at the library level.
 */
void
virResetLastError(void)
{
    virResetError(&virLastErr);
}

/**
 * virConnGetLastError:
 * @conn: pointer to the hypervisor connection
 *
 * Provide a pointer to the last error caught on that connection
 * Simpler but may not be suitable for multithreaded accesses, in which
 * case use virConnCopyLastError()
 *
 * Returns a pointer to the last error or NULL if none occurred.
 */
virErrorPtr
virConnGetLastError(virConnectPtr conn)
{
    if (conn == NULL)
        return (NULL);
    return (&conn->err);
}

/**
 * virConnCopyLastError:
 * @conn: pointer to the hypervisor connection
 * @to: target to receive the copy
 *
 * Copy the content of the last error caught on that connection
 * One will need to free the result with virResetError()
 *
 * Returns 0 if no error was found and the error code otherwise and -1 in case
 *         of parameter error.
 */
int
virConnCopyLastError(virConnectPtr conn, virErrorPtr to)
{
    if (conn == NULL)
        return (-1);
    if (to == NULL)
        return (-1);
    if (conn->err.code == VIR_ERR_OK)
        return (0);
    memcpy(to, &conn->err, sizeof(virError));
    return (conn->err.code);
}

/**
 * virConnResetLastError:
 * @conn: pointer to the hypervisor connection
 *
 * Reset the last error caught on that connection
 */
void
virConnResetLastError(virConnectPtr conn)
{
    if (conn == NULL)
        return;
    virResetError(&conn->err);
}

/**
 * virSetErrorFunc:
 * @userData: pointer to the user data provided in the handler callback
 * @handler: the function to get called in case of error or NULL
 *
 * Set a library global error handling function, if @handler is NULL,
 * it will reset to default printing on stderr. The error raised there
 * are those for which no handler at the connection level could caught.
 */
void
virSetErrorFunc(void *userData, virErrorFunc handler)
{
    virErrorHandler = handler;
    virUserData = userData;
}

/**
 * virConnSetErrorFunc:
 * @conn: pointer to the hypervisor connection
 * @userData: pointer to the user data provided in the handler callback
 * @handler: the function to get called in case of error or NULL
 *
 * Set a connection error handling function, if @handler is NULL
 * it will reset to default which is to pass error back to the global
 * library handler.
 */
void
virConnSetErrorFunc(virConnectPtr conn, void *userData,
                    virErrorFunc handler)
{
    if (conn == NULL)
        return;
    conn->handler = handler;
    conn->userData = userData;
}

/**
 * virDefaultErrorFunc:
 * @err: pointer to the error.
 *
 * Default routine reporting an error to stderr.
 */
void
virDefaultErrorFunc(virErrorPtr err)
{
    const char *lvl = "", *dom = "", *domain = "", *network = "";
    int len;

    if ((err == NULL) || (err->code == VIR_ERR_OK))
        return;
    switch (err->level) {
        case VIR_ERR_NONE:
            lvl = "";
            break;
        case VIR_ERR_WARNING:
            lvl = _("warning");
            break;
        case VIR_ERR_ERROR:
            lvl = _("error");
            break;
    }
    switch (err->domain) {
        case VIR_FROM_NONE:
            dom = "";
            break;
        case VIR_FROM_XEN:
            dom = "Xen ";
            break;
        case VIR_FROM_XML:
            dom = "XML ";
            break;
        case VIR_FROM_XEND:
            dom = "Xen Daemon ";
            break;
        case VIR_FROM_XENSTORE:
            dom = "Xen Store ";
            break;
        case VIR_FROM_XEN_INOTIFY:
            dom = "Xen Inotify ";
            break;
        case VIR_FROM_DOM:
            dom = "Domain ";
            break;
        case VIR_FROM_RPC:
            dom = "XML-RPC ";
            break;
        case VIR_FROM_QEMU:
            dom = "QEMU ";
            break;
        case VIR_FROM_NET:
            dom = "Network ";
            break;
        case VIR_FROM_TEST:
            dom = "Test ";
            break;
        case VIR_FROM_REMOTE:
            dom = "Remote ";
            break;
        case VIR_FROM_SEXPR:
            dom = "S-Expr ";
            break;
        case VIR_FROM_PROXY:
            dom = "PROXY ";
            break;
        case VIR_FROM_CONF:
            dom = "Config ";
            break;
        case VIR_FROM_OPENVZ:
            dom = "OpenVZ ";
            break;
        case VIR_FROM_XENXM:
            dom = "Xen XM ";
            break;
        case VIR_FROM_STATS_LINUX:
            dom = "Linux Stats ";
            break;
        case VIR_FROM_LXC:
            dom = "Linux Container ";
            break;
        case VIR_FROM_STORAGE:
            dom = "Storage ";
            break;
        case VIR_FROM_NETWORK:
            dom = "Network Config ";
            break;
        case VIR_FROM_DOMAIN:
            dom = "Domain Config ";
            break;
        case VIR_FROM_NODEDEV:
            dom = "Node Device ";
            break;
        case VIR_FROM_UML:
            dom = "UML ";
            break;
    }
    if ((err->dom != NULL) && (err->code != VIR_ERR_INVALID_DOMAIN)) {
        domain = err->dom->name;
    } else if ((err->net != NULL) && (err->code != VIR_ERR_INVALID_NETWORK)) {
        network = err->net->name;
    }
    len = strlen(err->message);
    if ((err->domain == VIR_FROM_XML) && (err->code == VIR_ERR_XML_DETAIL) &&
        (err->int1 != 0))
        fprintf(stderr, "libvir: %s%s %s%s: line %d: %s",
                dom, lvl, domain, network, err->int1, err->message);
    else if ((len == 0) || (err->message[len - 1] != '\n'))
        fprintf(stderr, "libvir: %s%s %s%s: %s\n",
                dom, lvl, domain, network, err->message);
    else
        fprintf(stderr, "libvir: %s%s %s%s: %s",
                dom, lvl, domain, network, err->message);
}

/**
 * virRaiseError:
 * @conn: the connection to the hypervisor if available
 * @dom: the domain if available
 * @net: the network if available
 * @domain: the virErrorDomain indicating where it's coming from
 * @code: the virErrorNumber code for the error
 * @level: the virErrorLevel for the error
 * @str1: extra string info
 * @str2: extra string info
 * @str3: extra string info
 * @int1: extra int info
 * @int2: extra int info
 * @msg:  the message to display/transmit
 * @...:  extra parameters for the message display
 *
 * Internal routine called when an error is detected. It will raise it
 * immediately if a callback is found and store it for later handling.
 */
void
virRaiseError(virConnectPtr conn, virDomainPtr dom, virNetworkPtr net,
              int domain, int code, virErrorLevel level,
              const char *str1, const char *str2, const char *str3,
              int int1, int int2, const char *msg, ...)
{
    virErrorPtr to = &virLastErr;
    void *userData = virUserData;
    virErrorFunc handler = virErrorHandler;
    char *str;

    if (code == VIR_ERR_OK)
        return;

    /*
     * try to find the best place to save and report the error
     */
    if (conn != NULL) {
        to = &conn->err;
        if (conn->handler != NULL) {
            handler = conn->handler;
            userData = conn->userData;
        }
    }

    /*
     * formats the message
     */
    if (msg == NULL) {
        str = strdup(_("No error message provided"));
    } else {
        VIR_GET_VAR_STR(msg, str);
    }

    /*
     * Save the information about the error
     */
    virResetError(to);
    to->conn = conn;
    to->dom = dom;
    to->net = net;
    to->domain = domain;
    to->code = code;
    to->message = str;
    to->level = level;
    if (str1 != NULL)
        to->str1 = strdup(str1);
    if (str2 != NULL)
        to->str2 = strdup(str2);
    if (str3 != NULL)
        to->str3 = strdup(str3);
    to->int1 = int1;
    to->int2 = int2;

    /*
     * now, report it
     */
    if (handler != NULL) {
        handler(userData, to);
    } else {
        virDefaultErrorFunc(to);
    }
}

/**
 * virErrorMsg:
 * @error: the virErrorNumber
 * @info: usually the first parameter string
 *
 * Internal routine to get the message associated to an error raised
 * from the library
 *
 * Returns the constant string associated to @error
 */
const char *
virErrorMsg(virErrorNumber error, const char *info)
{
    const char *errmsg = NULL;

    switch (error) {
        case VIR_ERR_OK:
            return (NULL);
        case VIR_ERR_INTERNAL_ERROR:
            if (info != NULL)
              errmsg = _("internal error %s");
            else
              errmsg = _("internal error");
            break;
        case VIR_ERR_NO_MEMORY:
            errmsg = _("out of memory");
            break;
        case VIR_ERR_NO_SUPPORT:
            if (info == NULL)
                errmsg = _("this function is not supported by the hypervisor");
            else
                errmsg = _("this function is not supported by the hypervisor: %s");
            break;
        case VIR_ERR_NO_CONNECT:
            if (info == NULL)
                errmsg = _("could not connect to hypervisor");
            else
                errmsg = _("could not connect to %s");
            break;
        case VIR_ERR_INVALID_CONN:
            if (info == NULL)
                errmsg = _("invalid connection pointer in");
            else
                errmsg = _("invalid connection pointer in %s");
            break;
        case VIR_ERR_INVALID_DOMAIN:
            if (info == NULL)
                errmsg = _("invalid domain pointer in");
            else
                errmsg = _("invalid domain pointer in %s");
            break;
        case VIR_ERR_INVALID_ARG:
            if (info == NULL)
                errmsg = _("invalid argument in");
            else
                errmsg = _("invalid argument in %s");
            break;
        case VIR_ERR_OPERATION_FAILED:
            if (info != NULL)
                errmsg = _("operation failed: %s");
            else
                errmsg = _("operation failed");
            break;
        case VIR_ERR_GET_FAILED:
            if (info != NULL)
                errmsg = _("GET operation failed: %s");
            else
                errmsg = _("GET operation failed");
            break;
        case VIR_ERR_POST_FAILED:
            if (info != NULL)
                errmsg = _("POST operation failed: %s");
            else
                errmsg = _("POST operation failed");
            break;
        case VIR_ERR_HTTP_ERROR:
            errmsg = _("got unknown HTTP error code %d");
            break;
        case VIR_ERR_UNKNOWN_HOST:
            if (info != NULL)
                errmsg = _("unknown host %s");
            else
                errmsg = _("unknown host");
            break;
        case VIR_ERR_SEXPR_SERIAL:
            if (info != NULL)
                errmsg = _("failed to serialize S-Expr: %s");
            else
                errmsg = _("failed to serialize S-Expr");
            break;
        case VIR_ERR_NO_XEN:
            if (info == NULL)
                errmsg = _("could not use Xen hypervisor entry");
            else
                errmsg = _("could not use Xen hypervisor entry %s");
            break;
        case VIR_ERR_NO_XENSTORE:
            if (info == NULL)
                errmsg = _("could not connect to Xen Store");
            else
                errmsg = _("could not connect to Xen Store %s");
            break;
        case VIR_ERR_XEN_CALL:
            errmsg = _("failed Xen syscall %s");
            break;
        case VIR_ERR_OS_TYPE:
            if (info == NULL)
                errmsg = _("unknown OS type");
            else
                errmsg = _("unknown OS type %s");
            break;
        case VIR_ERR_NO_KERNEL:
            errmsg = _("missing kernel information");
            break;
        case VIR_ERR_NO_ROOT:
            if (info == NULL)
                errmsg = _("missing root device information");
            else
                errmsg = _("missing root device information in %s");
            break;
        case VIR_ERR_NO_SOURCE:
            if (info == NULL)
                errmsg = _("missing source information for device");
            else
                errmsg = _("missing source information for device %s");
            break;
        case VIR_ERR_NO_TARGET:
            if (info == NULL)
                errmsg = _("missing target information for device");
            else
                errmsg = _("missing target information for device %s");
            break;
        case VIR_ERR_NO_NAME:
            if (info == NULL)
                errmsg = _("missing domain name information");
            else
                errmsg = _("missing domain name information in %s");
            break;
        case VIR_ERR_NO_OS:
            if (info == NULL)
                errmsg = _("missing operating system information");
            else
                errmsg = _("missing operating system information for %s");
            break;
        case VIR_ERR_NO_DEVICE:
            if (info == NULL)
                errmsg = _("missing devices information");
            else
                errmsg = _("missing devices information for %s");
            break;
        case VIR_ERR_DRIVER_FULL:
            if (info == NULL)
                errmsg = _("too many drivers registered");
            else
                errmsg = _("too many drivers registered in %s");
            break;
        case VIR_ERR_CALL_FAILED: /* DEPRECATED, use VIR_ERR_NO_SUPPORT */
            if (info == NULL)
                errmsg = _("library call failed, possibly not supported");
            else
                errmsg = _("library call %s failed, possibly not supported");
            break;
        case VIR_ERR_XML_ERROR:
            if (info == NULL)
                errmsg = _("XML description not well formed or invalid");
            else
                errmsg = _("XML description for %s is not well formed or invalid");
            break;
        case VIR_ERR_DOM_EXIST:
            if (info == NULL)
                errmsg = _("this domain exists already");
            else
                errmsg = _("domain %s exists already");
            break;
        case VIR_ERR_OPERATION_DENIED:
            if (info == NULL)
                errmsg = _("operation forbidden for read only access");
            else
                errmsg = _("operation %s forbidden for read only access");
            break;
        case VIR_ERR_OPEN_FAILED:
            if (info == NULL)
                errmsg = _("failed to open configuration file for reading");
            else
                errmsg = _("failed to open %s for reading");
            break;
        case VIR_ERR_READ_FAILED:
            if (info == NULL)
                errmsg = _("failed to read configuration file");
            else
                errmsg = _("failed to read configuration file %s");
            break;
        case VIR_ERR_PARSE_FAILED:
            if (info == NULL)
                errmsg = _("failed to parse configuration file");
            else
                errmsg = _("failed to parse configuration file %s");
            break;
        case VIR_ERR_CONF_SYNTAX:
            if (info == NULL)
                errmsg = _("configuration file syntax error");
            else
                errmsg = _("configuration file syntax error: %s");
            break;
        case VIR_ERR_WRITE_FAILED:
            if (info == NULL)
                errmsg = _("failed to write configuration file");
            else
                errmsg = _("failed to write configuration file: %s");
            break;
        case VIR_ERR_XML_DETAIL:
            if (info == NULL)
                errmsg = _("parser error");
            else
                errmsg = "%s";
            break;
        case VIR_ERR_INVALID_NETWORK:
            if (info == NULL)
                errmsg = _("invalid network pointer in");
            else
                errmsg = _("invalid network pointer in %s");
            break;
        case VIR_ERR_NETWORK_EXIST:
            if (info == NULL)
                errmsg = _("this network exists already");
            else
                errmsg = _("network %s exists already");
            break;
        case VIR_ERR_SYSTEM_ERROR:
            if (info == NULL)
                errmsg = _("system call error");
            else
                errmsg = "%s";
            break;
        case VIR_ERR_RPC:
            if (info == NULL)
                errmsg = _("RPC error");
            else
                errmsg = "%s";
            break;
        case VIR_ERR_GNUTLS_ERROR:
            if (info == NULL)
                errmsg = _("GNUTLS call error");
            else
                errmsg = "%s";
            break;
        case VIR_WAR_NO_NETWORK:
            if (info == NULL)
                errmsg = _("Failed to find the network");
            else
                errmsg = _("Failed to find the network: %s");
            break;
        case VIR_ERR_NO_DOMAIN:
            if (info == NULL)
                errmsg = _("Domain not found");
            else
                errmsg = _("Domain not found: %s");
            break;
        case VIR_ERR_NO_NETWORK:
            if (info == NULL)
                errmsg = _("Network not found");
            else
                errmsg = _("Network not found: %s");
            break;
    case VIR_ERR_INVALID_MAC:
            if (info == NULL)
                errmsg = _("invalid MAC address");
            else
                errmsg = _("invalid MAC address: %s");
            break;
    case VIR_ERR_AUTH_FAILED:
            if (info == NULL)
                errmsg = _("authentication failed");
            else
                errmsg = _("authentication failed: %s");
            break;
        case VIR_ERR_NO_STORAGE_POOL:
                if (info == NULL)
                        errmsg = _("Storage pool not found");
                else
                        errmsg = _("Storage pool not found: %s");
                break;
        case VIR_ERR_NO_STORAGE_VOL:
                if (info == NULL)
                        errmsg = _("Storage volume not found");
                else
                        errmsg = _("Storage volume not found: %s");
                break;
        case VIR_ERR_INVALID_STORAGE_POOL:
                if (info == NULL)
                        errmsg = _("invalid storage pool pointer in");
                else
                        errmsg = _("invalid storage pool pointer in %s");
                break;
        case VIR_ERR_INVALID_STORAGE_VOL:
                if (info == NULL)
                        errmsg = _("invalid storage volume pointer in");
                else
                        errmsg = _("invalid storage volume pointer in %s");
                break;
        case VIR_WAR_NO_STORAGE:
                if (info == NULL)
                        errmsg = _("Failed to find a storage driver");
                else
                        errmsg = _("Failed to find a storage driver: %s");
                break;
        case VIR_WAR_NO_NODE:
                if (info == NULL)
                        errmsg = _("Failed to find a node driver");
                else
                        errmsg = _("Failed to find a node driver: %s");
                break;
        case VIR_ERR_INVALID_NODE_DEVICE:
                if (info == NULL)
                        errmsg = _("invalid node device pointer");
                else
                        errmsg = _("invalid node device pointer in %s");
                break;
        case VIR_ERR_NO_NODE_DEVICE:
                if (info == NULL)
                        errmsg = _("Node device not found");
                else
                        errmsg = _("Node device not found: %s");
                break;
    }
    return (errmsg);
}

/**
 * virReportErrorHelper:
 *
 * @conn: the connection to the hypervisor if available
 * @domcode: the virErrorDomain indicating where it's coming from
 * @errcode: the virErrorNumber code for the error
 * @filename: Source file error is dispatched from
 * @funcname: Function error is dispatched from
 * @linenr: Line number error is dispatched from
 * @fmt:  the format string
 * @...:  extra parameters for the message display
 *
 * Helper function to do most of the grunt work for individual driver
 * ReportError
 */
void virReportErrorHelper(virConnectPtr conn, int domcode, int errcode,
                          const char *filename ATTRIBUTE_UNUSED,
                          const char *funcname ATTRIBUTE_UNUSED,
                          long long linenr ATTRIBUTE_UNUSED,
                          const char *fmt, ...)
{
    va_list args;
    char errorMessage[1024];
    const char *virerr;

    if (fmt) {
        va_start(args, fmt);
        vsnprintf(errorMessage, sizeof(errorMessage)-1, fmt, args);
        va_end(args);
    } else {
        errorMessage[0] = '\0';
    }

    virerr = virErrorMsg(errcode, (errorMessage[0] ? errorMessage : NULL));
    virRaiseError(conn, NULL, NULL, domcode, errcode, VIR_ERR_ERROR,
                  virerr, errorMessage, NULL, -1, -1, virerr, errorMessage);

}
