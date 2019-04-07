/*
 * virerror.c: error handling and reporting code for libvirt
 *
 * Copyright (C) 2006-2019 Red Hat, Inc.
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

#include <stdarg.h>

#include "virerror.h"
#include "datatypes.h"
#include "virlog.h"
#include "virthread.h"
#include "virutil.h"
#include "virstring.h"

#define LIBVIRT_VIRERRORPRIV_H_ALLOW
#include "virerrorpriv.h"
#undef LIBVIRT_VIRERRORPRIV_H_ALLOW

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


VIR_ENUM_DECL(virErrorDomain);
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
              "VMware Driver",

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
              "Firewall",

              "Polkit", /* 60 */
              "Thread jobs",
              "Admin Interface",
              "Log Manager",
              "Xen XL Config",

              "Perf", /* 65 */
              "Libssh transport layer",
              "Resource control",
              "FirewallD",
              "Domain Checkpoint",
);


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


virErrorPtr
virErrorCopyNew(virErrorPtr err)
{
    virErrorPtr ret;

    if (VIR_ALLOC_QUIET(ret) < 0)
        return NULL;

    if (virCopyError(err, ret) < 0)
        VIR_FREE(ret);

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
 * virGetLastErrorCode:
 *
 * Get the most recent error code (enum virErrorNumber).
 *
 * Returns the most recent error code, or VIR_ERR_OK if none is set.
 */
int
virGetLastErrorCode(void)
{
    virErrorPtr err = virLastErrorObject();
    if (!err)
        return VIR_ERR_OK;
    return err->code;
}


/**
 * virGetLastErrorDomain:
 *
 * Get the most recent error domain (enum virErrorDomain).
 *
 * Returns a numerical value of the most recent error's origin, or VIR_FROM_NONE
 * if none is set.
 */
int
virGetLastErrorDomain(void)
{
    virErrorPtr err = virLastErrorObject();
    if (!err)
        return VIR_FROM_NONE;
    return err->domain;
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
    if (err && err->code == VIR_ERR_OK)
        return _("no error");
    if (!err || !err->message)
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
 * Returns error code or -1 in case of parameter error.
 */
int
virCopyLastError(virErrorPtr to)
{
    virErrorPtr err = virLastErrorObject();

    if (!to)
        return -1;

    /* We can't guarantee caller has initialized it to zero */
    memset(to, 0, sizeof(*to));
    if (err) {
        virCopyError(err, to);
    } else {
        virResetError(to);
        to->code = VIR_ERR_NO_MEMORY;
        to->domain = VIR_FROM_NONE;
        to->level = VIR_ERR_ERROR;
    }
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
 * virErrorPreserveLast:
 * @saveerr: pointer to virErrorPtr for storing last error object
 *
 * Preserves the currently set last error (for the thread) into @saveerr so that
 * it can be restored via virErrorRestore(). @saveerr must be passed to
 * virErrorRestore()
 */
void
virErrorPreserveLast(virErrorPtr *saveerr)
{
    int saved_errno = errno;
    virErrorPtr lasterr = virGetLastError();

    *saveerr = NULL;

    if (lasterr)
        *saveerr = virErrorCopyNew(lasterr);

    errno = saved_errno;
}


/**
 * virErrorRestore:
 * @savederr: error object holding saved error
 *
 * Restores the error passed via @savederr and clears associated memory.
 */
void
virErrorRestore(virErrorPtr *savederr)
{
    int saved_errno = errno;

    if (!*savederr)
        return;

    virSetError(*savederr);
    virFreeError(*savederr);
    *savederr = NULL;
    errno = saved_errno;
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
    virObjectLock(conn);
    if (conn->err.code == VIR_ERR_OK)
        virResetError(to);
    else
        virCopyError(&conn->err, to);
    virObjectUnlock(conn);
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
    virObjectLock(conn);
    virResetError(&conn->err);
    virObjectUnlock(conn);
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
    virObjectLock(conn);
    conn->handler = handler;
    conn->userData = userData;
    virObjectUnlock(conn);
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
        virObjectLock(conn);
        virCopyError(err, &conn->err);

        if (conn->handler != NULL) {
            handler = conn->handler;
            userData = conn->userData;
        }
        virObjectUnlock(conn);
    }

    /* Invoke the error callback functions */
    if (handler != NULL) {
        (handler)(userData, err);
    } else {
        virDefaultErrorFunc(err);
    }
}


/*
 * Reports an error through the logging subsystem
 */
static
void virRaiseErrorLog(const char *filename,
                      const char *funcname,
                      size_t linenr,
                      virErrorPtr err,
                      virLogMetadata *meta)
{
    int priority;

    /*
     * Hook up the error or warning to the logging facility
     */
    priority = virErrorLevelPriority(err->level);
    if (virErrorLogPriorityFilter)
        priority = virErrorLogPriorityFilter(err, priority);

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
                      meta, "%s", err->message);
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
virRaiseErrorFull(const char *filename,
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

    virRaiseErrorLog(filename, funcname, linenr,
                     to, meta);

    errno = save_errno;
}


/**
 * virRaiseErrorObject:
 * @filename: filename where error was raised
 * @funcname: function name where error was raised
 * @linenr: line number where error was raised
 * @newerr: the error object to report
 *
 * Sets the thread local error object to be a copy of
 * @newerr and logs the error
 *
 * This is like virRaiseErrorFull, except that it accepts the
 * error information via a pre-filled virErrorPtr object
 *
 * This is like virSetError, except that it will trigger the
 * logging callbacks.
 *
 * The caller must clear the @newerr instance afterwards, since
 * it will be copied into the thread local error.
 */
void virRaiseErrorObject(const char *filename,
                         const char *funcname,
                         size_t linenr,
                         virErrorPtr newerr)
{
    int saved_errno = errno;
    virErrorPtr err;
    virLogMetadata meta[] = {
        { .key = "LIBVIRT_DOMAIN", .s = NULL, .iv = newerr->domain },
        { .key = "LIBVIRT_CODE", .s = NULL, .iv = newerr->code },
        { .key = NULL },
    };

    err = virLastErrorObject();
    if (!err)
        goto cleanup;

    virResetError(err);
    virCopyError(newerr, err);
    virRaiseErrorLog(filename, funcname, linenr,
                     err, meta);
 cleanup:
    errno = saved_errno;
}


typedef struct {
    const char *msg;
    const char *msginfo;
} virErrorMsgTuple;


const virErrorMsgTuple virErrorMsgStrings[VIR_ERR_NUMBER_LAST] = {
    [VIR_ERR_OK] = { NULL, NULL },
    [VIR_ERR_INTERNAL_ERROR] = {
        N_("internal error"),
        N_("internal error: %s") },
    [VIR_ERR_NO_MEMORY] = {
        N_("out of memory"),
        N_("out of memory: %s") },
    [VIR_ERR_NO_SUPPORT] = {
        N_("this function is not supported by the connection driver"),
        N_("this function is not supported by the connection driver: %s") },
    [VIR_ERR_UNKNOWN_HOST] = {
        N_("unknown host"),
        N_("unknown host %s") },
    [VIR_ERR_NO_CONNECT] = {
        N_("no connection driver available"),
        N_("no connection driver available for %s") },
    [VIR_ERR_INVALID_CONN] = {
        N_("invalid connection pointer in"),
        N_("invalid connection pointer in %s") },
    [VIR_ERR_INVALID_DOMAIN] = {
        N_("invalid domain pointer in"),
        N_("invalid domain pointer in %s") },
    [VIR_ERR_INVALID_ARG] = {
        N_("invalid argument"),
        N_("invalid argument: %s") },
    [VIR_ERR_OPERATION_FAILED] = {
        N_("operation failed"),
        N_("operation failed: %s") },
    [VIR_ERR_GET_FAILED] = {
        N_("GET operation failed"),
        N_("GET operation failed: %s") },
    [VIR_ERR_POST_FAILED] = {
        N_("POST operation failed"),
        N_("POST operation failed: %s") },
    [VIR_ERR_HTTP_ERROR] = {
        N_("got unknown HTTP error code"),
        N_("got unknown HTTP error code %s") },
    [VIR_ERR_SEXPR_SERIAL] = {
        N_("failed to serialize S-Expr"),
        N_("failed to serialize S-Expr: %s") },
    [VIR_ERR_NO_XEN] = {
        N_("could not use Xen hypervisor entry"),
        N_("could not use Xen hypervisor entry %s") },
    [VIR_ERR_XEN_CALL] = {
        N_("failed Xen syscall"),
        N_("failed Xen syscall %s") },
    [VIR_ERR_OS_TYPE] = {
        N_("unknown OS type"),
        N_("unknown OS type %s") },
    [VIR_ERR_NO_KERNEL] = {
        N_("missing kernel information"),
        N_("missing kernel information: %s") },
    [VIR_ERR_NO_ROOT] = {
        N_("missing root device information"),
        N_("missing root device information in %s") },
    [VIR_ERR_NO_SOURCE] = {
        N_("missing source information for device"),
        N_("missing source information for device %s") },
    [VIR_ERR_NO_TARGET] = {
        N_("missing target information for device"),
        N_("missing target information for device %s") },
    [VIR_ERR_NO_NAME] = {
        N_("missing name information"),
        N_("missing name information in %s") },
    [VIR_ERR_NO_OS] = {
        N_("missing operating system information"),
        N_("missing operating system information for %s") },
    [VIR_ERR_NO_DEVICE] = {
        N_("missing devices information"),
        N_("missing devices information for %s") },
    [VIR_ERR_NO_XENSTORE] = {
        N_("could not connect to Xen Store"),
        N_("could not connect to Xen Store %s") },
    [VIR_ERR_DRIVER_FULL] = {
        N_("too many drivers registered"),
        N_("too many drivers registered in %s") },
    [VIR_ERR_CALL_FAILED] = {
        N_("library call failed"),
        N_("library call failed: %s") },
    [VIR_ERR_XML_ERROR] = {
        N_("XML description is invalid or not well formed"),
        N_("XML error: %s") },
    [VIR_ERR_DOM_EXIST] = {
        N_("this domain exists already"),
        N_("domain %s exists already") },
    [VIR_ERR_OPERATION_DENIED] = {
        N_("operation forbidden for read only access"),
        N_("operation forbidden: %s") },
    [VIR_ERR_OPEN_FAILED] = {
        N_("failed to open configuration file"),
        N_("failed to open configuration file %s") },
    [VIR_ERR_READ_FAILED] = {
        N_("failed to read configuration file"),
        N_("failed to read configuration file %s") },
    [VIR_ERR_PARSE_FAILED] = {
        N_("failed to parse configuration file"),
        N_("failed to parse configuration file %s") },
    [VIR_ERR_CONF_SYNTAX] = {
        N_("configuration file syntax error"),
        N_("configuration file syntax error: %s") },
    [VIR_ERR_WRITE_FAILED] = {
        N_("failed to write configuration file"),
        N_("failed to write configuration file: %s") },
    [VIR_ERR_XML_DETAIL] = {
        N_("parser error"),
        "%s" },
    [VIR_ERR_INVALID_NETWORK] = {
        N_("invalid network pointer in"),
        N_("invalid network pointer in %s") },
    [VIR_ERR_NETWORK_EXIST] = {
        N_("this network exists already"),
        N_("network %s exists already") },
    [VIR_ERR_SYSTEM_ERROR] = {
        N_("system call error"),
        "%s" },
    [VIR_ERR_RPC] = {
        N_("RPC error"),
        "%s" },
    [VIR_ERR_GNUTLS_ERROR] = {
        N_("GNUTLS call error"),
        "%s" },
    [VIR_WAR_NO_NETWORK] = {
        N_("Failed to find the network"),
        N_("Failed to find the network: %s") },
    [VIR_ERR_NO_DOMAIN] = {
        N_("Domain not found"),
        N_("Domain not found: %s") },
    [VIR_ERR_NO_NETWORK] = {
        N_("Network not found"),
        N_("Network not found: %s") },
    [VIR_ERR_INVALID_MAC] = {
        N_("invalid MAC address"),
        N_("invalid MAC address: %s") },
    [VIR_ERR_AUTH_FAILED] = {
        N_("authentication failed"),
        N_("authentication failed: %s") },
    [VIR_ERR_INVALID_STORAGE_POOL] = {
        N_("invalid storage pool pointer in"),
        N_("invalid storage pool pointer in %s") },
    [VIR_ERR_INVALID_STORAGE_VOL] = {
        N_("invalid storage volume pointer in"),
        N_("invalid storage volume pointer in %s") },
    [VIR_WAR_NO_STORAGE] = {
        N_("Failed to find a storage driver"),
        N_("Failed to find a storage driver: %s") },
    [VIR_ERR_NO_STORAGE_POOL] = {
        N_("Storage pool not found"),
        N_("Storage pool not found: %s") },
    [VIR_ERR_NO_STORAGE_VOL] = {
        N_("Storage volume not found"),
        N_("Storage volume not found: %s") },
    [VIR_WAR_NO_NODE] = {
        N_("Failed to find a node driver"),
        N_("Failed to find a node driver: %s") },
    [VIR_ERR_INVALID_NODE_DEVICE] = {
        N_("invalid node device pointer"),
        N_("invalid node device pointer in %s") },
    [VIR_ERR_NO_NODE_DEVICE] = {
        N_("Node device not found"),
        N_("Node device not found: %s") },
    [VIR_ERR_NO_SECURITY_MODEL] = {
        N_("Security model not found"),
        N_("Security model not found: %s") },
    [VIR_ERR_OPERATION_INVALID] = {
        N_("Requested operation is not valid"),
        N_("Requested operation is not valid: %s") },
    [VIR_WAR_NO_INTERFACE] = {
        N_("Failed to find the interface"),
        N_("Failed to find the interface: %s") },
    [VIR_ERR_NO_INTERFACE] = {
        N_("Interface not found"),
        N_("Interface not found: %s") },
    [VIR_ERR_INVALID_INTERFACE] = {
        N_("invalid interface pointer in"),
        N_("invalid interface pointer in %s") },
    [VIR_ERR_MULTIPLE_INTERFACES] = {
        N_("multiple matching interfaces found"),
        N_("multiple matching interfaces found: %s") },
    [VIR_WAR_NO_NWFILTER] = {
        N_("Failed to start the nwfilter driver"),
        N_("Failed to start the nwfilter driver: %s") },
    [VIR_ERR_INVALID_NWFILTER] = {
        N_("Invalid network filter"),
        N_("Invalid network filter: %s") },
    [VIR_ERR_NO_NWFILTER] = {
        N_("Network filter not found"),
        N_("Network filter not found: %s") },
    [VIR_ERR_BUILD_FIREWALL] = {
        N_("Error while building firewall"),
        N_("Error while building firewall: %s") },
    [VIR_WAR_NO_SECRET] = {
        N_("Failed to find a secret storage driver"),
        N_("Failed to find a secret storage driver: %s") },
    [VIR_ERR_INVALID_SECRET] = {
        N_("Invalid secret"),
        N_("Invalid secret: %s") },
    [VIR_ERR_NO_SECRET] = {
        N_("Secret not found"),
        N_("Secret not found: %s") },
    [VIR_ERR_CONFIG_UNSUPPORTED] = {
        N_("unsupported configuration"),
        N_("unsupported configuration: %s") },
    [VIR_ERR_OPERATION_TIMEOUT] = {
        N_("Timed out during operation"),
        N_("Timed out during operation: %s") },
    [VIR_ERR_MIGRATE_PERSIST_FAILED] = {
        N_("Failed to make domain persistent after migration"),
        N_("Failed to make domain persistent after migration: %s") },
    [VIR_ERR_HOOK_SCRIPT_FAILED] = {
        N_("Hook script execution failed"),
        N_("Hook script execution failed: %s") },
    [VIR_ERR_INVALID_DOMAIN_SNAPSHOT] = {
        N_("Invalid domain snapshot"),
        N_("Invalid domain snapshot: %s") },
    [VIR_ERR_NO_DOMAIN_SNAPSHOT] = {
        N_("Domain snapshot not found"),
        N_("Domain snapshot not found: %s") },
    [VIR_ERR_INVALID_STREAM] = {
        N_("invalid stream pointer"),
        N_("invalid stream pointer in %s") },
    [VIR_ERR_ARGUMENT_UNSUPPORTED] = {
        N_("argument unsupported"),
        N_("argument unsupported: %s") },
    [VIR_ERR_STORAGE_PROBE_FAILED] = {
        N_("Storage pool probe failed"),
        N_("Storage pool probe failed: %s") },
    [VIR_ERR_STORAGE_POOL_BUILT] = {
        N_("Storage pool already built"),
        N_("Storage pool already built: %s") },
    [VIR_ERR_SNAPSHOT_REVERT_RISKY] = {
        N_("revert requires force"),
        N_("revert requires force: %s") },
    [VIR_ERR_OPERATION_ABORTED] = {
        N_("operation aborted"),
        N_("operation aborted: %s") },
    [VIR_ERR_AUTH_CANCELLED] = {
        N_("authentication cancelled"),
        N_("authentication cancelled: %s") },
    [VIR_ERR_NO_DOMAIN_METADATA] = {
        N_("metadata not found"),
        N_("metadata not found: %s") },
    [VIR_ERR_MIGRATE_UNSAFE] = {
        N_("Unsafe migration"),
        N_("Unsafe migration: %s") },
    [VIR_ERR_OVERFLOW] = {
        N_("numerical overflow"),
        N_("numerical overflow: %s") },
    [VIR_ERR_BLOCK_COPY_ACTIVE] = {
        N_("block copy still active"),
        N_("block copy still active: %s") },
    [VIR_ERR_OPERATION_UNSUPPORTED] = {
        N_("Operation not supported"),
        N_("Operation not supported: %s") },
    [VIR_ERR_SSH] = {
        N_("SSH transport error"),
        N_("SSH transport error: %s") },
    [VIR_ERR_AGENT_UNRESPONSIVE] = {
        N_("Guest agent is not responding"),
        N_("Guest agent is not responding: %s") },
    [VIR_ERR_RESOURCE_BUSY] = {
        N_("resource busy"),
        N_("resource busy: %s") },
    [VIR_ERR_ACCESS_DENIED] = {
        N_("access denied"),
        N_("access denied: %s") },
    [VIR_ERR_DBUS_SERVICE] = {
        N_("error from service"),
        N_("error from service: %s") },
    [VIR_ERR_STORAGE_VOL_EXIST] = {
        N_("this storage volume exists already"),
        N_("storage volume %s exists already") },
    [VIR_ERR_CPU_INCOMPATIBLE] = {
        N_("the CPU is incompatible with host CPU"),
        N_("the CPU is incompatible with host CPU: %s") },
    [VIR_ERR_XML_INVALID_SCHEMA] = {
        N_("XML document failed to validate against schema"),
        N_("XML document failed to validate against schema: %s") },
    [VIR_ERR_MIGRATE_FINISH_OK] = {
        N_("migration successfully aborted"),
        N_("migration successfully aborted: %s") },
    [VIR_ERR_AUTH_UNAVAILABLE] = {
        N_("authentication unavailable"),
        N_("authentication unavailable: %s") },
    [VIR_ERR_NO_SERVER] = {
        N_("Server not found"),
        N_("Server not found: %s") },
    [VIR_ERR_NO_CLIENT] = {
        N_("Client not found"),
        N_("Client not found: %s") },
    [VIR_ERR_AGENT_UNSYNCED] = {
        N_("guest agent replied with wrong id to guest-sync command"),
        N_("guest agent replied with wrong id to guest-sync command: %s") },
    [VIR_ERR_LIBSSH] = {
        N_("libssh transport error"),
        N_("libssh transport error: %s") },
    [VIR_ERR_DEVICE_MISSING] = {
        N_("device not found"),
        N_("device not found: %s") },
    [VIR_ERR_INVALID_NWFILTER_BINDING] = {
        N_("Invalid network filter binding"),
        N_("Invalid network filter binding: %s") },
    [VIR_ERR_NO_NWFILTER_BINDING] = {
        N_("Network filter binding not found"),
        N_("Network filter binding not found: %s") },
    [VIR_ERR_INVALID_DOMAIN_CHECKPOINT] = {
        N_("Invalid domain checkpoint"),
        N_("Invalid domain checkpoint: %s") },
    [VIR_ERR_NO_DOMAIN_CHECKPOINT] = {
        N_("Domain checkpoint not found"),
        N_("Domain checkpoint not found: %s") },
    [VIR_ERR_NO_DOMAIN_BACKUP] = {
        N_("Domain backup job id not found"),
        N_("Domain backup job id not found: %s") },
};


/**
 * virErrorMsg:
 * @error: the virErrorNumber
 * @info: additional info string
 *
 * Internal routine to get the message associated to @error raised
 * from the library.
 *
 * Returns a *printf format string which describes @error. The returned string
 * contains exactly one '%s' modifier if @info is non-NULL, or no modifiers at
 * all if @info is NULL. If @error is invalid NULL is returned.
 */
const char *
virErrorMsg(virErrorNumber error, const char *info)
{
    if (error >= VIR_ERR_NUMBER_LAST)
        return NULL;

    if (info)
        return _(virErrorMsgStrings[error].msginfo);
    else
        return _(virErrorMsgStrings[error].msg);
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
    char errorMessage[VIR_ERROR_MAX_LENGTH];
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
    char strerror_buf[VIR_ERROR_MAX_LENGTH];
    char msgDetailBuf[VIR_ERROR_MAX_LENGTH];

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
