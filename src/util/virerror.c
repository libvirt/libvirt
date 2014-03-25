/*
 * virerror.c: error handling and reporting code for libvirt
 *
 * Copyright (C) 2006, 2008-2014 Red Hat, Inc.
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
 *
 * Author: Daniel Veillard <veillard@redhat.com>
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "virerror.h"
#include "datatypes.h"
#include "virlog.h"
#include "viralloc.h"
#include "virthread.h"
#include "virutil.h"
#include "virstring.h"

VIR_LOG_INIT("util.error");

virThreadLocal virLastErr;

virErrorFunc virErrorHandler = NULL;     /* global error handler */
void *virUserData = NULL;        /* associated data */
virErrorLogPriorityFunc virErrorLogPriorityFilter = NULL;

static virLogPriority virErrorLevelPriority(virErrorLevel level)
{
    switch (level) {
        case VIR_ERR_NONE:
            return VIR_LOG_INFO;
        case VIR_ERR_WARNING:
            return VIR_LOG_WARN;
        case VIR_ERR_ERROR:
            return VIR_LOG_ERROR;
    }
    return VIR_LOG_ERROR;
}


VIR_ENUM_DECL(virErrorDomain)
VIR_ENUM_IMPL(virErrorDomain, VIR_ERR_DOMAIN_LAST,
              "", /* 0 */
              "Xen Driver",
              "Xen Daemon",
              "Xen Store",
              "S-Expression",

              "XML Util", /* 5 */
              "Domain",
              "XML-RPC",
              "Proxy Daemon",
              "Config File",

              "QEMU Driver", /* 10 */
              "Network",
              "Test Driver",
              "Remote Driver",
              "OpenVZ Driver",

              "Xen XM Driver", /* 15 */
              "Linux Statistics",
              "LXC Driver",
              "Storage Driver",
              "Network Driver",

              "Domain Config", /* 20 */
              "User Mode Linux Driver",
              "Node Device Driver",
              "Xen Inotify Driver",
              "Security Driver",

              "VirtualBox Driver", /* 25 */
              "Network Interface Driver",
              "Open Nebula Driver",
              "ESX Driver",
              "Power Hypervisor Driver",

              "Secrets Driver", /* 30 */
              "CPU Driver",
              "XenAPI Driver",
              "Network Filter Driver",
              "Lifecycle Hook",

              "Domain Snapshot", /* 35 */
              "Audit Utils",
              "Sysinfo Utils",
              "I/O Stream Utils",
              "VMWare Driver",

              "Event Loop", /* 40 */
              "Xen Light Driver",
              "Lock Driver",
              "Hyper-V Driver",
              "Capabilities Utils",

              "URI Utils", /* 45 */
              "Authentication Utils",
              "DBus Utils",
              "Parallels Cloud Server",
              "Device Config",

              "SSH transport layer", /* 50 */
              "Lock Space",
              "Init control",
              "Identity",
              "Cgroup",

              "Access Manager", /* 55 */
              "Systemd",
              "Bhyve",
              "Crypto",
    )


/*
 * Internal helper that is called when a thread exits, to
 * release the error object stored in the thread local
 */
static void
virLastErrFreeData(void *data)
{
    virErrorPtr err = data;
    if (!err)
        return;
    virResetError(err);
    VIR_FREE(err);
}


/**
 * virErrorInitialize:
 *
 * Initialize the error data (per thread)
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
int
virErrorInitialize(void)
{
    return virThreadLocalInit(&virLastErr, virLastErrFreeData);
}


/*
 * Internal helper to ensure a generic error code is stored
 * in case where API returns failure, but forgot to set an
 * error
 */
static void
virErrorGenericFailure(virErrorPtr err)
{
    err->code = VIR_ERR_INTERNAL_ERROR;
    err->domain = VIR_FROM_NONE;
    err->level = VIR_ERR_ERROR;
    ignore_value(VIR_STRDUP_QUIET(err->message,
                                  _("An error occurred, but the cause is unknown")));
}


/*
 * Internal helper to perform a deep copy of an error
 */
static int
virCopyError(virErrorPtr from,
             virErrorPtr to)
{
    int ret = 0;
    if (!to)
        return 0;
    virResetError(to);
    if (!from)
        return 0;
    to->code = from->code;
    to->domain = from->domain;
    to->level = from->level;
    if (VIR_STRDUP_QUIET(to->message, from->message) < 0)
        ret = -1;
    if (VIR_STRDUP_QUIET(to->str1, from->str1) < 0)
        ret = -1;
    if (VIR_STRDUP_QUIET(to->str2, from->str2) < 0)
        ret = -1;
    if (VIR_STRDUP_QUIET(to->str3, from->str3) < 0)
        ret = -1;
    to->int1 = from->int1;
    to->int2 = from->int2;
    /*
     * Deliberately not setting 'conn', 'dom', 'net' references
     */
    return ret;
}

static virErrorPtr
virLastErrorObject(void)
{
    virErrorPtr err;
    err = virThreadLocalGet(&virLastErr);
    if (!err) {
        if (VIR_ALLOC_QUIET(err) < 0)
            return NULL;
        if (virThreadLocalSet(&virLastErr, err) < 0)
            VIR_FREE(err);
    }
    return err;
}


/**
 * virGetLastError:
 *
 * Provide a pointer to the last error caught at the library level
 *
 * The error object is kept in thread local storage, so separate
 * threads can safely access this concurrently.
 *
 * Returns a pointer to the last error or NULL if none occurred.
 */
virErrorPtr
virGetLastError(void)
{
    virErrorPtr err = virLastErrorObject();
    if (!err || err->code == VIR_ERR_OK)
        return NULL;
    return err;
}


/**
 * virGetLastErrorMessage:
 *
 * Get the most recent error message
 *
 * Returns the most recent error message string in this
 * thread, or a generic message if none is set
 */
const char *
virGetLastErrorMessage(void)
{
    virErrorPtr err = virLastErrorObject();
    if (!err || err->code == VIR_ERR_OK)
        return _("no error");
    if (err->message == NULL)
        return _("unknown error");
    return err->message;
}


/**
 * virSetError:
 * @newerr: previously saved error object
 *
 * Set the current error from a previously saved error object
 *
 * Can be used to re-set an old error, which may have been squashed by
 * other functions (like cleanup routines).
 *
 * Returns 0 on success, -1 on failure.  Leaves errno unchanged.
 */
int
virSetError(virErrorPtr newerr)
{
    virErrorPtr err;
    int saved_errno = errno;
    int ret = -1;

    err = virLastErrorObject();
    if (!err)
        goto cleanup;

    virResetError(err);
    ret = virCopyError(newerr, err);
 cleanup:
    errno = saved_errno;
    return ret;
}

/**
 * virCopyLastError:
 * @to: target to receive the copy
 *
 * Copy the content of the last error caught at the library level
 *
 * The error object is kept in thread local storage, so separate
 * threads can safely access this concurrently.
 *
 * One will need to free the result with virResetError()
 *
 * Returns 0 if no error was found and the error code otherwise and -1 in case
 *         of parameter error.
 */
int
virCopyLastError(virErrorPtr to)
{
    virErrorPtr err = virLastErrorObject();
    /* We can't guarantee caller has initialized it to zero */
    memset(to, 0, sizeof(*to));
    if (err)
        virCopyError(err, to);
    else
        virResetError(to);
    return to->code;
}

/**
 * virSaveLastError:
 *
 * Save the last error into a new error object.  On success, errno is
 * unchanged; on failure, errno is ENOMEM.
 *
 * Returns a pointer to the copied error or NULL if allocation failed.
 * It is the caller's responsibility to free the error with
 * virFreeError().
 */
virErrorPtr
virSaveLastError(void)
{
    virErrorPtr to;
    int saved_errno = errno;

    if (VIR_ALLOC_QUIET(to) < 0)
        return NULL;

    virCopyLastError(to);
    errno = saved_errno;
    return to;
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
    VIR_FREE(err->message);
    VIR_FREE(err->str1);
    VIR_FREE(err->str2);
    VIR_FREE(err->str3);
    memset(err, 0, sizeof(virError));
}

/**
 * virFreeError:
 * @err: error to free
 *
 * Resets and frees the given error.
 */
void
virFreeError(virErrorPtr err)
{
    virResetError(err);
    VIR_FREE(err);
}

/**
 * virResetLastError:
 *
 * Reset the last error caught at the library level.
 *
 * The error object is kept in thread local storage, so separate
 * threads can safely access this concurrently, only resetting
 * their own error object.
 */
void
virResetLastError(void)
{
    virErrorPtr err = virLastErrorObject();
    if (err)
        virResetError(err);
}

/**
 * virConnGetLastError:
 * @conn: pointer to the hypervisor connection
 *
 * Provide a pointer to the last error caught on that connection
 *
 * This method is not protected against access from multiple
 * threads. In a multi-threaded application, always use the
 * global virGetLastError() API which is backed by thread
 * local storage.
 *
 * If the connection object was discovered to be invalid by
 * an API call, then the error will be reported against the
 * global error object.
 *
 * Since 0.6.0, all errors reported in the per-connection object
 * are also duplicated in the global error object. As such an
 * application can always use virGetLastError(). This method
 * remains for backwards compatibility.
 *
 * Returns a pointer to the last error or NULL if none occurred.
 */
virErrorPtr
virConnGetLastError(virConnectPtr conn)
{
    if (conn == NULL)
        return NULL;
    return &conn->err;
}

/**
 * virConnCopyLastError:
 * @conn: pointer to the hypervisor connection
 * @to: target to receive the copy
 *
 * Copy the content of the last error caught on that connection
 *
 * This method is not protected against access from multiple
 * threads. In a multi-threaded application, always use the
 * global virGetLastError() API which is backed by thread
 * local storage.
 *
 * If the connection object was discovered to be invalid by
 * an API call, then the error will be reported against the
 * global error object.
 *
 * Since 0.6.0, all errors reported in the per-connection object
 * are also duplicated in the global error object. As such an
 * application can always use virGetLastError(). This method
 * remains for backwards compatibility.
 *
 * One will need to free the result with virResetError()
 *
 * Returns 0 if no error was found and the error code otherwise and -1 in case
 *         of parameter error.
 */
int
virConnCopyLastError(virConnectPtr conn, virErrorPtr to)
{
    /* We can't guarantee caller has initialized it to zero */
    memset(to, 0, sizeof(*to));

    if (conn == NULL)
        return -1;
    virMutexLock(&conn->lock);
    if (conn->err.code == VIR_ERR_OK)
        virResetError(to);
    else
        virCopyError(&conn->err, to);
    virMutexUnlock(&conn->lock);
    return to->code;
}

/**
 * virConnResetLastError:
 * @conn: pointer to the hypervisor connection
 *
 * The error object is kept in thread local storage, so separate
 * threads can safely access this concurrently.
 *
 * Reset the last error caught on that connection
 */
void
virConnResetLastError(virConnectPtr conn)
{
    if (conn == NULL)
        return;
    virMutexLock(&conn->lock);
    virResetError(&conn->err);
    virMutexUnlock(&conn->lock);
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
    virMutexLock(&conn->lock);
    conn->handler = handler;
    conn->userData = userData;
    virMutexUnlock(&conn->lock);
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
    dom = virErrorDomainTypeToString(err->domain);
    if (!dom)
        dom = "Unknown";
    if ((err->dom != NULL) && (err->code != VIR_ERR_INVALID_DOMAIN)) {
        domain = err->dom->name;
    } else if ((err->net != NULL) && (err->code != VIR_ERR_INVALID_NETWORK)) {
        network = err->net->name;
    }
    len = strlen(err->message);
    if ((err->domain == VIR_FROM_XML) && (err->code == VIR_ERR_XML_DETAIL) &&
        (err->int1 != 0))
        fprintf(stderr, "libvirt: %s %s %s%s: line %d: %s",
                dom, lvl, domain, network, err->int1, err->message);
    else if ((len == 0) || (err->message[len - 1] != '\n'))
        fprintf(stderr, "libvirt: %s %s %s%s: %s\n",
                dom, lvl, domain, network, err->message);
    else
        fprintf(stderr, "libvirt: %s %s %s%s: %s",
                dom, lvl, domain, network, err->message);
}

/**
 * virDispatchError:
 * @conn: pointer to the hypervisor connection
 *
 * Internal helper to do final stage of error
 * reporting in public APIs.
 *
 *  - Copy the global error to per-connection error if needed
 *  - Set a generic error message if none is already set
 *  - Invoke the error callback functions
 */
void
virDispatchError(virConnectPtr conn)
{
    virErrorPtr err = virLastErrorObject();
    virErrorFunc handler = virErrorHandler;
    void *userData = virUserData;

    /* Can only happen on OOM.  */
    if (!err)
        return;

    /* Set a generic error message if none is already set */
    if (err->code == VIR_ERR_OK)
        virErrorGenericFailure(err);

    /* Copy the global error to per-connection error if needed */
    if (conn) {
        virMutexLock(&conn->lock);
        virCopyError(err, &conn->err);

        if (conn->handler != NULL) {
            handler = conn->handler;
            userData = conn->userData;
        }
        virMutexUnlock(&conn->lock);
    }

    /* Invoke the error callback functions */
    if (handler != NULL) {
        (handler)(userData, err);
    } else {
        virDefaultErrorFunc(err);
    }
}



/**
 * virRaiseErrorFull:
 * @filename: filename where error was raised
 * @funcname: function name where error was raised
 * @linenr: line number where error was raised
 * @domain: the virErrorDomain indicating where it's coming from
 * @code: the virErrorNumber code for the error
 * @level: the virErrorLevel for the error
 * @str1: extra string info
 * @str2: extra string info
 * @str3: extra string info
 * @int1: extra int info
 * @int2: extra int info
 * @fmt:  the message to display/transmit
 * @...:  extra parameters for the message display
 *
 * Internal routine called when an error is detected. It will raise it
 * immediately if a callback is found and store it for later handling.
 */
void
virRaiseErrorFull(const char *filename ATTRIBUTE_UNUSED,
                  const char *funcname,
                  size_t linenr,
                  int domain,
                  int code,
                  virErrorLevel level,
                  const char *str1,
                  const char *str2,
                  const char *str3,
                  int int1,
                  int int2,
                  const char *fmt, ...)
{
    int save_errno = errno;
    virErrorPtr to;
    char *str;
    int priority;
    virLogMetadata meta[] = {
        { .key = "LIBVIRT_DOMAIN", .s = NULL, .iv = domain },
        { .key = "LIBVIRT_CODE", .s = NULL, .iv = code },
        { .key = NULL },
    };

    /*
     * All errors are recorded in thread local storage
     * For compatibility, public API calls will copy them
     * to the per-connection error object when necessary
     */
    to = virLastErrorObject();
    if (!to) {
        errno = save_errno;
        return; /* Hit OOM allocating thread error object, sod all we can do now */
    }

    virResetError(to);

    if (code == VIR_ERR_OK) {
        errno = save_errno;
        return;
    }

    /*
     * formats the message; drop message on OOM situations
     */
    if (fmt == NULL) {
        ignore_value(VIR_STRDUP_QUIET(str, _("No error message provided")));
    } else {
        va_list ap;
        va_start(ap, fmt);
        ignore_value(virVasprintfQuiet(&str, fmt, ap));
        va_end(ap);
    }

    /*
     * Save the information about the error
     */
    /*
     * Deliberately not setting conn, dom & net fields since
     * they're utterly unsafe
     */
    to->domain = domain;
    to->code = code;
    to->message = str;
    to->level = level;
    ignore_value(VIR_STRDUP_QUIET(to->str1, str1));
    ignore_value(VIR_STRDUP_QUIET(to->str2, str2));
    ignore_value(VIR_STRDUP_QUIET(to->str3, str3));
    to->int1 = int1;
    to->int2 = int2;

    /*
     * Hook up the error or warning to the logging facility
     */
    priority = virErrorLevelPriority(level);
    if (virErrorLogPriorityFilter)
        priority = virErrorLogPriorityFilter(to, priority);

    /* We don't want to pollute stderr if no logging outputs
     * are explicitly requested by the user, since the default
     * error function already pollutes stderr and most apps
     * hate & thus disable that too. If the daemon has set
     * a priority filter though, we should always forward
     * all errors to the logging code.
     */
    if (virLogGetNbOutputs() > 0 ||
        virErrorLogPriorityFilter)
        virLogMessage(&virLogSelf,
                      priority,
                      filename, linenr, funcname,
                      meta, "%s", str);

    errno = save_errno;
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
static const char *
virErrorMsg(virErrorNumber error, const char *info)
{
    const char *errmsg = NULL;

    switch (error) {
        case VIR_ERR_OK:
            return NULL;
        case VIR_ERR_INTERNAL_ERROR:
            if (info != NULL)
              errmsg = _("internal error: %s");
            else
              errmsg = _("internal error");
            break;
        case VIR_ERR_NO_MEMORY:
            errmsg = _("out of memory");
            break;
        case VIR_ERR_NO_SUPPORT:
            if (info == NULL)
                errmsg = _("this function is not supported by the connection driver");
            else
                errmsg = _("this function is not supported by the connection driver: %s");
            break;
        case VIR_ERR_NO_CONNECT:
            if (info == NULL)
                errmsg = _("no connection driver available");
            else
                errmsg = _("no connection driver available for %s");
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
                errmsg = _("invalid argument");
            else
                errmsg = _("invalid argument: %s");
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
                errmsg = _("missing name information");
            else
                errmsg = _("missing name information in %s");
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
                errmsg = _("XML description is invalid or not well formed");
            else
                errmsg = _("XML error: %s");
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
                errmsg = _("operation forbidden: %s");
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
        case VIR_ERR_AUTH_CANCELLED:
            if (info == NULL)
                errmsg = _("authentication cancelled");
            else
                errmsg = _("authentication cancelled: %s");
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
        case VIR_ERR_STORAGE_VOL_EXIST:
            if (info == NULL)
                errmsg = _("this storage volume exists already");
            else
                errmsg = _("storage volume %s exists already");
            break;
        case VIR_ERR_STORAGE_PROBE_FAILED:
            if (info == NULL)
                errmsg = _("Storage pool probe failed");
            else
                errmsg = _("Storage pool probe failed: %s");
            break;
        case VIR_ERR_STORAGE_POOL_BUILT:
            if (info == NULL)
                errmsg = _("Storage pool already built");
            else
                errmsg = _("Storage pool already built: %s");
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
        case VIR_ERR_NO_SECURITY_MODEL:
            if (info == NULL)
                errmsg = _("Security model not found");
            else
                errmsg = _("Security model not found: %s");
            break;
        case VIR_ERR_OPERATION_INVALID:
            if (info == NULL)
                errmsg = _("Requested operation is not valid");
            else
                errmsg = _("Requested operation is not valid: %s");
            break;
        case VIR_WAR_NO_INTERFACE:
            if (info == NULL)
                errmsg = _("Failed to find the interface");
            else
                errmsg = _("Failed to find the interface: %s");
            break;
        case VIR_ERR_NO_INTERFACE:
            if (info == NULL)
                errmsg = _("Interface not found");
            else
                errmsg = _("Interface not found: %s");
            break;
        case VIR_ERR_INVALID_INTERFACE:
            if (info == NULL)
                errmsg = _("invalid interface pointer in");
            else
                errmsg = _("invalid interface pointer in %s");
            break;
        case VIR_ERR_MULTIPLE_INTERFACES:
            if (info == NULL)
                errmsg = _("multiple matching interfaces found");
            else
                errmsg = _("multiple matching interfaces found: %s");
            break;
        case VIR_WAR_NO_SECRET:
            if (info == NULL)
                errmsg = _("Failed to find a secret storage driver");
            else
                errmsg = _("Failed to find a secret storage driver: %s");
            break;
        case VIR_ERR_INVALID_SECRET:
            if (info == NULL)
                errmsg = _("Invalid secret");
            else
                errmsg = _("Invalid secret: %s");
            break;
        case VIR_ERR_NO_SECRET:
            if (info == NULL)
                errmsg = _("Secret not found");
            else
                errmsg = _("Secret not found: %s");
            break;
        case VIR_WAR_NO_NWFILTER:
            if (info == NULL)
                errmsg = _("Failed to start the nwfilter driver");
            else
                errmsg = _("Failed to start the nwfilter driver: %s");
            break;
        case VIR_ERR_INVALID_NWFILTER:
            if (info == NULL)
                errmsg = _("Invalid network filter");
            else
                errmsg = _("Invalid network filter: %s");
            break;
        case VIR_ERR_NO_NWFILTER:
            if (info == NULL)
                errmsg = _("Network filter not found");
            else
                errmsg = _("Network filter not found: %s");
            break;
        case VIR_ERR_BUILD_FIREWALL:
            if (info == NULL)
                errmsg = _("Error while building firewall");
            else
                errmsg = _("Error while building firewall: %s");
            break;
        case VIR_ERR_CONFIG_UNSUPPORTED:
            if (info == NULL)
                errmsg = _("unsupported configuration");
            else
                errmsg = _("unsupported configuration: %s");
            break;
        case VIR_ERR_OPERATION_TIMEOUT:
            if (info == NULL)
                errmsg = _("Timed out during operation");
            else
                errmsg = _("Timed out during operation: %s");
            break;
        case VIR_ERR_MIGRATE_PERSIST_FAILED:
            if (info == NULL)
                errmsg = _("Failed to make domain persistent after migration");
            else
                errmsg = _("Failed to make domain persistent after migration: %s");
            break;
        case VIR_ERR_HOOK_SCRIPT_FAILED:
            if (info == NULL)
                errmsg = _("Hook script execution failed");
            else
                errmsg = _("Hook script execution failed: %s");
            break;
        case VIR_ERR_INVALID_DOMAIN_SNAPSHOT:
            if (info == NULL)
                errmsg = _("Invalid snapshot");
            else
                errmsg = _("Invalid snapshot: %s");
            break;
        case VIR_ERR_NO_DOMAIN_SNAPSHOT:
            if (info == NULL)
                errmsg = _("Domain snapshot not found");
            else
                errmsg = _("Domain snapshot not found: %s");
            break;
        case VIR_ERR_INVALID_STREAM:
            if (info == NULL)
                errmsg = _("invalid stream pointer");
            else
                errmsg = _("invalid stream pointer in %s");
            break;
        case VIR_ERR_ARGUMENT_UNSUPPORTED:
            if (info == NULL)
                errmsg = _("argument unsupported");
            else
                errmsg = _("argument unsupported: %s");
            break;
        case VIR_ERR_SNAPSHOT_REVERT_RISKY:
            if (info == NULL)
                errmsg = _("revert requires force");
            else
                errmsg = _("revert requires force: %s");
            break;
        case VIR_ERR_OPERATION_ABORTED:
            if (info == NULL)
                errmsg = _("operation aborted");
            else
                errmsg = _("operation aborted: %s");
            break;
        case VIR_ERR_NO_DOMAIN_METADATA:
            if (info == NULL)
                errmsg = _("metadata not found");
            else
                errmsg = _("metadata not found: %s");
            break;
        case VIR_ERR_MIGRATE_UNSAFE:
            if (!info)
                errmsg = _("Unsafe migration");
            else
                errmsg = _("Unsafe migration: %s");
            break;
        case VIR_ERR_OVERFLOW:
            if (!info)
                errmsg = _("numerical overflow");
            else
                errmsg = _("numerical overflow: %s");
            break;
        case VIR_ERR_BLOCK_COPY_ACTIVE:
            if (!info)
                errmsg = _("block copy still active");
            else
                errmsg = _("block copy still active: %s");
            break;
        case VIR_ERR_OPERATION_UNSUPPORTED:
            if (!info)
                errmsg = _("Operation not supported");
            else
                errmsg = _("Operation not supported: %s");
            break;
        case VIR_ERR_SSH:
            if (info == NULL)
                errmsg = _("SSH transport error");
            else
                errmsg = _("SSH transport error: %s");
            break;
        case VIR_ERR_AGENT_UNRESPONSIVE:
            if (info == NULL)
                errmsg = _("Guest agent is not responding");
            else
                errmsg = _("Guest agent is not responding: %s");
            break;
        case VIR_ERR_RESOURCE_BUSY:
            if (info == NULL)
                errmsg = _("resource busy");
            else
                errmsg = _("resource busy %s");
            break;
        case VIR_ERR_ACCESS_DENIED:
            if (info == NULL)
                errmsg = _("access denied");
            else
                errmsg = _("access denied: %s");
            break;
        case VIR_ERR_DBUS_SERVICE:
            if (info == NULL)
                errmsg = _("error from service");
            else
                errmsg = _("error from service: %s");
            break;
    }
    return errmsg;
}

/**
 * virReportErrorHelper:
 *
 * @domcode: the virErrorDomain indicating where it's coming from
 * @errorcode: the virErrorNumber code for the error
 * @filename: Source file error is dispatched from
 * @funcname: Function error is dispatched from
 * @linenr: Line number error is dispatched from
 * @fmt:  the format string
 * @...:  extra parameters for the message display
 *
 * Helper function to do most of the grunt work for individual driver
 * ReportError
 */
void virReportErrorHelper(int domcode,
                          int errorcode,
                          const char *filename,
                          const char *funcname,
                          size_t linenr,
                          const char *fmt, ...)
{
    int save_errno = errno;
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

    virerr = virErrorMsg(errorcode, (errorMessage[0] ? errorMessage : NULL));
    virRaiseErrorFull(filename, funcname, linenr,
                      domcode, errorcode, VIR_ERR_ERROR,
                      virerr, errorMessage, NULL,
                      -1, -1, virerr, errorMessage);
    errno = save_errno;
}

/**
 * virStrerror:
 * @theerrno: the errno value
 * @errBuf: the buffer to save the error to
 * @errBufLen: the buffer length
 *
 * Generate an error string for the given errno
 *
 * Returns a pointer to the error string, possibly indicating that the
 *         error is unknown
 */
const char *virStrerror(int theerrno, char *errBuf, size_t errBufLen)
{
    int save_errno = errno;
    const char *ret;

    strerror_r(theerrno, errBuf, errBufLen);
    ret = errBuf;
    errno = save_errno;
    return ret;
}

/**
 * virReportSystemErrorFull:
 * @domcode: the virErrorDomain indicating where it's coming from
 * @theerrno: an errno number
 * @filename: filename where error was raised
 * @funcname: function name where error was raised
 * @linenr: line number where error was raised
 * @fmt:  the message to display/transmit
 * @...:  extra parameters for the message display
 *
 * Convenience internal routine called when a system error is detected.
 */
void virReportSystemErrorFull(int domcode,
                              int theerrno,
                              const char *filename,
                              const char *funcname,
                              size_t linenr,
                              const char *fmt, ...)
{
    int save_errno = errno;
    char strerror_buf[1024];
    char msgDetailBuf[1024];

    const char *errnoDetail = virStrerror(theerrno, strerror_buf,
                                          sizeof(strerror_buf));
    const char *msg = virErrorMsg(VIR_ERR_SYSTEM_ERROR, fmt);
    const char *msgDetail = NULL;

    if (fmt) {
        va_list args;
        int n;

        va_start(args, fmt);
        n = vsnprintf(msgDetailBuf, sizeof(msgDetailBuf), fmt, args);
        va_end(args);

        size_t len = strlen(errnoDetail);
        if (0 <= n && n + 2 + len < sizeof(msgDetailBuf)) {
          char *p = msgDetailBuf + n;
          stpcpy(stpcpy(p, ": "), errnoDetail);
          msgDetail = msgDetailBuf;
        }
    }

    if (!msgDetail)
        msgDetail = errnoDetail;

    virRaiseErrorFull(filename, funcname, linenr,
                      domcode, VIR_ERR_SYSTEM_ERROR, VIR_ERR_ERROR,
                      msg, msgDetail, NULL, theerrno, -1, msg, msgDetail);
    errno = save_errno;
}

/**
 * virReportOOMErrorFull:
 * @domcode: the virErrorDomain indicating where it's coming from
 * @filename: filename where error was raised
 * @funcname: function name where error was raised
 * @linenr: line number where error was raised
 *
 * Convenience internal routine called when an out of memory error is
 * detected
 */
void virReportOOMErrorFull(int domcode,
                           const char *filename,
                           const char *funcname,
                           size_t linenr)
{
    const char *virerr;

    virerr = virErrorMsg(VIR_ERR_NO_MEMORY, NULL);
    virRaiseErrorFull(filename, funcname, linenr,
                      domcode, VIR_ERR_NO_MEMORY, VIR_ERR_ERROR,
                      virerr, NULL, NULL, -1, -1, virerr, NULL);
}

/**
 * virSetErrorLogPriorityFunc:
 * @func: function to install
 *
 * Install a function used to filter error logging based on error priority.
 */
void virSetErrorLogPriorityFunc(virErrorLogPriorityFunc func)
{
    virErrorLogPriorityFilter = func;
}


/**
 * virErrorSetErrnoFromLastError:
 *
 * If the last error had a code of VIR_ERR_SYSTEM_ERROR
 * then set errno to the value saved in the error object.
 *
 * If the last error had a code of VIR_ERR_NO_MEMORY
 * then set errno to ENOMEM
 *
 * Otherwise set errno to EIO.
 */
void virErrorSetErrnoFromLastError(void)
{
    virErrorPtr err = virGetLastError();
    if (err && err->code == VIR_ERR_SYSTEM_ERROR) {
        errno = err->int1;
    } else if (err && err->code == VIR_ERR_NO_MEMORY) {
        errno = ENOMEM;
    } else {
        errno = EIO;
    }
}


/**
 * virLastErrorIsSystemErrno:
 * @errnum: the errno value
 *
 * Check if the last error reported is a system
 * error with the specific errno value.
 *
 * If @errnum is zero, any system error will pass.
 *
 * Returns true if the last error was a system error with errno == @errnum
 */
bool virLastErrorIsSystemErrno(int errnum)
{
    virErrorPtr err = virGetLastError();
    if (!err)
        return false;
    if (err->code != VIR_ERR_SYSTEM_ERROR)
        return false;
    if (errnum != 0 && err->int1 != errnum)
        return false;
    return true;
}
