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
#include "viralloc.h"
#include "virlog.h"
#include "virthread.h"
#include "virbuffer.h"

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
VIR_ENUM_IMPL(virErrorDomain,
              VIR_ERR_DOMAIN_LAST,
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

              "TPM", /* 70 */
              "BPF",
              "Cloud-Hypervisor Driver",
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
    g_free(err);
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
    err->message = g_strdup(_("An error occurred, but the cause is unknown"));
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
    to->message = g_strdup(from->message);
    to->str1 = g_strdup(from->str1);
    to->str2 = g_strdup(from->str2);
    to->str3 = g_strdup(from->str3);
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
    virErrorPtr ret = g_new0(virError, 1);
    virCopyError(err, ret);
    return ret;
}


static virErrorPtr
virLastErrorObject(void)
{
    virErrorPtr err;
    err = virThreadLocalGet(&virLastErr);
    if (!err) {
        err = g_new0(virError, 1);
        if (virThreadLocalSet(&virLastErr, err) < 0)
            g_clear_pointer(&err, g_free);
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
 *
 * Since: 0.1.0
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
 *
 * Since: 4.5.0
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
 *
 * Since: 4.5.0
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
 *
 * Since: 1.0.6
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
 *
 * Since: 0.1.0
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
 *
 * Since: 0.6.1
 */
virErrorPtr
virSaveLastError(void)
{
    virErrorPtr to;
    int saved_errno = errno;

    to = g_new0(virError, 1);

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
    g_clear_pointer(savederr, virFreeError);
    errno = saved_errno;
}


/**
 * virResetError:
 * @err: pointer to the virError to clean up
 *
 * Reset the error being pointed to
 *
 * Since: 0.1.0
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
 *
 * Since: 0.6.1
 */
void
virFreeError(virErrorPtr err)
{
    virResetError(err);
    g_free(err);
}

/**
 * virResetLastError:
 *
 * Reset the last error caught at the library level.
 *
 * The error object is kept in thread local storage, so separate
 * threads can safely access this concurrently, only resetting
 * their own error object.
 *
 * Since: 0.1.0
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
 *
 * Since: 0.1.0
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
 *
 * Since: 0.1.0
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
 *
 * Since: 0.1.0
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
 *
 * Since: 0.1.0
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
 *
 * Since: 0.1.0
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
 *
 * Since: 0.1.0
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
     * Similarly when debug priority is the default we want to log the error.
     */
    if (virLogGetNbOutputs() > 0 ||
        virErrorLogPriorityFilter ||
        virLogGetDefaultPriority() == VIR_LOG_DEBUG)
        virLogMessage(&virLogSelf,
                      priority,
                      filename, linenr, funcname,
                      meta, "%s", err->message);
}


/**
 * virRaiseErrorInternal:
 *
 * Internal helper to assign and raise error. Note that @msgarg, @str1arg,
 * @str2arg and @str3arg if non-NULL must be heap-allocated strings and are
 * stolen and freed by this function.
 */
static void
virRaiseErrorInternal(const char *filename,
                      const char *funcname,
                      size_t linenr,
                      int domain,
                      int code,
                      virErrorLevel level,
                      char *msgarg,
                      char *str1arg,
                      char *str2arg,
                      char *str3arg,
                      int int1,
                      int int2)
{
    g_autofree char *msg = msgarg;
    g_autofree char *str1 = str1arg;
    g_autofree char *str2 = str2arg;
    g_autofree char *str3 = str3arg;
    virErrorPtr to;
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
    if (!(to = virLastErrorObject()))
        return;

    virResetError(to);

    if (code == VIR_ERR_OK)
        return;

    if (!msg)
        msg = g_strdup(_("No error message provided"));

    /* Deliberately not setting conn, dom & net fields since
     * they are utterly unsafe. */
    to->domain = domain;
    to->code = code;
    to->message = g_steal_pointer(&msg);
    to->level = level;
    to->str1 = g_steal_pointer(&str1);
    to->str2 = g_steal_pointer(&str2);
    to->str3 = g_steal_pointer(&str3);
    to->int1 = int1;
    to->int2 = int2;

    virRaiseErrorLog(filename, funcname, linenr, to, meta);
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
    char *msg = NULL;

    if (fmt) {
        va_list ap;

        va_start(ap, fmt);
        msg = g_strdup_vprintf(fmt, ap);
        va_end(ap);
    }

    virRaiseErrorInternal(filename, funcname, linenr,
                          domain, code, level,
                          msg, g_strdup(str1), g_strdup(str2), g_strdup(str3),
                          int1, int2);

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


static const virErrorMsgTuple virErrorMsgStrings[] = {
    [VIR_ERR_OK] = { NULL, NULL },
    [VIR_ERR_INTERNAL_ERROR] = {
        N_("internal error"),
        N_("internal error: %1$s") },
    [VIR_ERR_NO_MEMORY] = {
        N_("out of memory"),
        N_("out of memory: %1$s") },
    [VIR_ERR_NO_SUPPORT] = {
        N_("this function is not supported by the connection driver"),
        N_("this function is not supported by the connection driver: %1$s") },
    [VIR_ERR_UNKNOWN_HOST] = {
        N_("unknown host"),
        N_("unknown host %1$s") },
    [VIR_ERR_NO_CONNECT] = {
        N_("no connection driver available"),
        N_("no connection driver available for %1$s") },
    [VIR_ERR_INVALID_CONN] = {
        N_("invalid connection pointer in"),
        N_("invalid connection pointer in %1$s") },
    [VIR_ERR_INVALID_DOMAIN] = {
        N_("invalid domain pointer in"),
        N_("invalid domain pointer in %1$s") },
    [VIR_ERR_INVALID_ARG] = {
        N_("invalid argument"),
        N_("invalid argument: %1$s") },
    [VIR_ERR_OPERATION_FAILED] = {
        N_("operation failed"),
        N_("operation failed: %1$s") },
    [VIR_ERR_GET_FAILED] = {
        N_("GET operation failed"),
        N_("GET operation failed: %1$s") },
    [VIR_ERR_POST_FAILED] = {
        N_("POST operation failed"),
        N_("POST operation failed: %1$s") },
    [VIR_ERR_HTTP_ERROR] = {
        N_("got unknown HTTP error code"),
        N_("got unknown HTTP error code %1$s") },
    [VIR_ERR_SEXPR_SERIAL] = {
        N_("failed to serialize S-Expr"),
        N_("failed to serialize S-Expr: %1$s") },
    [VIR_ERR_NO_XEN] = {
        N_("could not use Xen hypervisor entry"),
        N_("could not use Xen hypervisor entry %1$s") },
    [VIR_ERR_XEN_CALL] = {
        N_("failed Xen syscall"),
        N_("failed Xen syscall %1$s") },
    [VIR_ERR_OS_TYPE] = {
        N_("unknown OS type"),
        N_("unknown OS type %1$s") },
    [VIR_ERR_NO_KERNEL] = {
        N_("missing kernel information"),
        N_("missing kernel information: %1$s") },
    [VIR_ERR_NO_ROOT] = {
        N_("missing root device information"),
        N_("missing root device information in %1$s") },
    [VIR_ERR_NO_SOURCE] = {
        N_("missing source information for device"),
        N_("missing source information for device %1$s") },
    [VIR_ERR_NO_TARGET] = {
        N_("missing target information for device"),
        N_("missing target information for device %1$s") },
    [VIR_ERR_NO_NAME] = {
        N_("missing name information"),
        N_("missing name information in %1$s") },
    [VIR_ERR_NO_OS] = {
        N_("missing operating system information"),
        N_("missing operating system information for %1$s") },
    [VIR_ERR_NO_DEVICE] = {
        N_("missing devices information"),
        N_("missing devices information for %1$s") },
    [VIR_ERR_NO_XENSTORE] = {
        N_("could not connect to Xen Store"),
        N_("could not connect to Xen Store %1$s") },
    [VIR_ERR_DRIVER_FULL] = {
        N_("too many drivers registered"),
        N_("too many drivers registered in %1$s") },
    [VIR_ERR_CALL_FAILED] = {
        N_("library call failed"),
        N_("library call failed: %1$s") },
    [VIR_ERR_XML_ERROR] = {
        N_("XML description is invalid or not well formed"),
        N_("XML error: %1$s") },
    [VIR_ERR_DOM_EXIST] = {
        N_("this domain exists already"),
        N_("domain %1$s exists already") },
    [VIR_ERR_OPERATION_DENIED] = {
        N_("operation forbidden for read only access"),
        N_("operation forbidden: %1$s") },
    [VIR_ERR_OPEN_FAILED] = {
        N_("failed to open configuration file"),
        N_("failed to open configuration file %1$s") },
    [VIR_ERR_READ_FAILED] = {
        N_("failed to read configuration file"),
        N_("failed to read configuration file %1$s") },
    [VIR_ERR_PARSE_FAILED] = {
        N_("failed to parse configuration file"),
        N_("failed to parse configuration file %1$s") },
    [VIR_ERR_CONF_SYNTAX] = {
        N_("configuration file syntax error"),
        N_("configuration file syntax error: %1$s") },
    [VIR_ERR_WRITE_FAILED] = {
        N_("failed to write configuration file"),
        N_("failed to write configuration file: %1$s") },
    [VIR_ERR_XML_DETAIL] = {
        N_("parser error"),
        "%s" },
    [VIR_ERR_INVALID_NETWORK] = {
        N_("invalid network pointer in"),
        N_("invalid network pointer in %1$s") },
    [VIR_ERR_NETWORK_EXIST] = {
        N_("this network exists already"),
        N_("network %1$s exists already") },
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
        N_("Failed to find the network: %1$s") },
    [VIR_ERR_NO_DOMAIN] = {
        N_("Domain not found"),
        N_("Domain not found: %1$s") },
    [VIR_ERR_NO_NETWORK] = {
        N_("Network not found"),
        N_("Network not found: %1$s") },
    [VIR_ERR_INVALID_MAC] = {
        N_("invalid MAC address"),
        N_("invalid MAC address: %1$s") },
    [VIR_ERR_AUTH_FAILED] = {
        N_("authentication failed"),
        N_("authentication failed: %1$s") },
    [VIR_ERR_INVALID_STORAGE_POOL] = {
        N_("invalid storage pool pointer in"),
        N_("invalid storage pool pointer in %1$s") },
    [VIR_ERR_INVALID_STORAGE_VOL] = {
        N_("invalid storage volume pointer in"),
        N_("invalid storage volume pointer in %1$s") },
    [VIR_WAR_NO_STORAGE] = {
        N_("Failed to find a storage driver"),
        N_("Failed to find a storage driver: %1$s") },
    [VIR_ERR_NO_STORAGE_POOL] = {
        N_("Storage pool not found"),
        N_("Storage pool not found: %1$s") },
    [VIR_ERR_NO_STORAGE_VOL] = {
        N_("Storage volume not found"),
        N_("Storage volume not found: %1$s") },
    [VIR_WAR_NO_NODE] = {
        N_("Failed to find a node driver"),
        N_("Failed to find a node driver: %1$s") },
    [VIR_ERR_INVALID_NODE_DEVICE] = {
        N_("invalid node device pointer"),
        N_("invalid node device pointer in %1$s") },
    [VIR_ERR_NO_NODE_DEVICE] = {
        N_("Node device not found"),
        N_("Node device not found: %1$s") },
    [VIR_ERR_NO_SECURITY_MODEL] = {
        N_("Security model not found"),
        N_("Security model not found: %1$s") },
    [VIR_ERR_OPERATION_INVALID] = {
        N_("Requested operation is not valid"),
        N_("Requested operation is not valid: %1$s") },
    [VIR_WAR_NO_INTERFACE] = {
        N_("Failed to find the interface"),
        N_("Failed to find the interface: %1$s") },
    [VIR_ERR_NO_INTERFACE] = {
        N_("Interface not found"),
        N_("Interface not found: %1$s") },
    [VIR_ERR_INVALID_INTERFACE] = {
        N_("invalid interface pointer in"),
        N_("invalid interface pointer in %1$s") },
    [VIR_ERR_MULTIPLE_INTERFACES] = {
        N_("multiple matching interfaces found"),
        N_("multiple matching interfaces found: %1$s") },
    [VIR_WAR_NO_NWFILTER] = {
        N_("Failed to start the nwfilter driver"),
        N_("Failed to start the nwfilter driver: %1$s") },
    [VIR_ERR_INVALID_NWFILTER] = {
        N_("Invalid network filter"),
        N_("Invalid network filter: %1$s") },
    [VIR_ERR_NO_NWFILTER] = {
        N_("Network filter not found"),
        N_("Network filter not found: %1$s") },
    [VIR_ERR_BUILD_FIREWALL] = {
        N_("Error while building firewall"),
        N_("Error while building firewall: %1$s") },
    [VIR_WAR_NO_SECRET] = {
        N_("Failed to find a secret storage driver"),
        N_("Failed to find a secret storage driver: %1$s") },
    [VIR_ERR_INVALID_SECRET] = {
        N_("Invalid secret"),
        N_("Invalid secret: %1$s") },
    [VIR_ERR_NO_SECRET] = {
        N_("Secret not found"),
        N_("Secret not found: %1$s") },
    [VIR_ERR_CONFIG_UNSUPPORTED] = {
        N_("unsupported configuration"),
        N_("unsupported configuration: %1$s") },
    [VIR_ERR_OPERATION_TIMEOUT] = {
        N_("Timed out during operation"),
        N_("Timed out during operation: %1$s") },
    [VIR_ERR_MIGRATE_PERSIST_FAILED] = {
        N_("Failed to make domain persistent after migration"),
        N_("Failed to make domain persistent after migration: %1$s") },
    [VIR_ERR_HOOK_SCRIPT_FAILED] = {
        N_("Hook script execution failed"),
        N_("Hook script execution failed: %1$s") },
    [VIR_ERR_INVALID_DOMAIN_SNAPSHOT] = {
        N_("Invalid domain snapshot"),
        N_("Invalid domain snapshot: %1$s") },
    [VIR_ERR_NO_DOMAIN_SNAPSHOT] = {
        N_("Domain snapshot not found"),
        N_("Domain snapshot not found: %1$s") },
    [VIR_ERR_INVALID_STREAM] = {
        N_("invalid stream pointer"),
        N_("invalid stream pointer in %1$s") },
    [VIR_ERR_ARGUMENT_UNSUPPORTED] = {
        N_("argument unsupported"),
        N_("argument unsupported: %1$s") },
    [VIR_ERR_STORAGE_PROBE_FAILED] = {
        N_("Storage pool probe failed"),
        N_("Storage pool probe failed: %1$s") },
    [VIR_ERR_STORAGE_POOL_BUILT] = {
        N_("Storage pool already built"),
        N_("Storage pool already built: %1$s") },
    [VIR_ERR_SNAPSHOT_REVERT_RISKY] = {
        N_("revert requires force"),
        N_("revert requires force: %1$s") },
    [VIR_ERR_OPERATION_ABORTED] = {
        N_("operation aborted"),
        N_("operation aborted: %1$s") },
    [VIR_ERR_AUTH_CANCELLED] = {
        N_("authentication cancelled"),
        N_("authentication cancelled: %1$s") },
    [VIR_ERR_NO_DOMAIN_METADATA] = {
        N_("metadata not found"),
        N_("metadata not found: %1$s") },
    [VIR_ERR_MIGRATE_UNSAFE] = {
        N_("Unsafe migration"),
        N_("Unsafe migration: %1$s") },
    [VIR_ERR_OVERFLOW] = {
        N_("numerical overflow"),
        N_("numerical overflow: %1$s") },
    [VIR_ERR_BLOCK_COPY_ACTIVE] = {
        N_("block copy still active"),
        N_("block copy still active: %1$s") },
    [VIR_ERR_OPERATION_UNSUPPORTED] = {
        N_("Operation not supported"),
        N_("Operation not supported: %1$s") },
    [VIR_ERR_SSH] = {
        N_("SSH transport error"),
        N_("SSH transport error: %1$s") },
    [VIR_ERR_AGENT_UNRESPONSIVE] = {
        N_("Guest agent is not responding"),
        N_("Guest agent is not responding: %1$s") },
    [VIR_ERR_RESOURCE_BUSY] = {
        N_("resource busy"),
        N_("resource busy: %1$s") },
    [VIR_ERR_ACCESS_DENIED] = {
        N_("access denied"),
        N_("access denied: %1$s") },
    [VIR_ERR_DBUS_SERVICE] = {
        N_("error from service"),
        N_("error from service: %1$s") },
    [VIR_ERR_STORAGE_VOL_EXIST] = {
        N_("this storage volume exists already"),
        N_("storage volume %1$s exists already") },
    [VIR_ERR_CPU_INCOMPATIBLE] = {
        N_("the CPU is incompatible with host CPU"),
        N_("the CPU is incompatible with host CPU: %1$s") },
    [VIR_ERR_XML_INVALID_SCHEMA] = {
        N_("XML document failed to validate against schema"),
        N_("XML document failed to validate against schema: %1$s") },
    [VIR_ERR_MIGRATE_FINISH_OK] = {
        N_("migration successfully aborted"),
        N_("migration successfully aborted: %1$s") },
    [VIR_ERR_AUTH_UNAVAILABLE] = {
        N_("authentication unavailable"),
        N_("authentication unavailable: %1$s") },
    [VIR_ERR_NO_SERVER] = {
        N_("Server not found"),
        N_("Server not found: %1$s") },
    [VIR_ERR_NO_CLIENT] = {
        N_("Client not found"),
        N_("Client not found: %1$s") },
    [VIR_ERR_AGENT_UNSYNCED] = {
        N_("guest agent replied with wrong id to guest-sync command"),
        N_("guest agent replied with wrong id to guest-sync command: %1$s") },
    [VIR_ERR_LIBSSH] = {
        N_("libssh transport error"),
        N_("libssh transport error: %1$s") },
    [VIR_ERR_DEVICE_MISSING] = {
        N_("device not found"),
        N_("device not found: %1$s") },
    [VIR_ERR_INVALID_NWFILTER_BINDING] = {
        N_("Invalid network filter binding"),
        N_("Invalid network filter binding: %1$s") },
    [VIR_ERR_NO_NWFILTER_BINDING] = {
        N_("Network filter binding not found"),
        N_("Network filter binding not found: %1$s") },
    [VIR_ERR_INVALID_DOMAIN_CHECKPOINT] = {
        N_("Invalid domain checkpoint"),
        N_("Invalid domain checkpoint: %1$s") },
    [VIR_ERR_NO_DOMAIN_CHECKPOINT] = {
        N_("Domain checkpoint not found"),
        N_("Domain checkpoint not found: %1$s") },
    [VIR_ERR_NO_DOMAIN_BACKUP] = {
        N_("Domain backup job id not found"),
        N_("Domain backup job id not found: %1$s") },
    [VIR_ERR_INVALID_NETWORK_PORT] = {
        N_("Invalid network port pointer"),
        N_("Invalid network port pointer: %1$s") },
    [VIR_ERR_NETWORK_PORT_EXIST] = {
        N_("this network port exists already"),
        N_("network port %1$s exists already") },
    [VIR_ERR_NO_NETWORK_PORT] = {
        N_("network port not found"),
        N_("network port not found: %1$s") },
    [VIR_ERR_NO_HOSTNAME] = {
        N_("no hostname found"),
        N_("no hostname found: %1$s") },
    [VIR_ERR_CHECKPOINT_INCONSISTENT] = {
        N_("checkpoint inconsistent"),
        N_("checkpoint inconsistent: %1$s") },
    [VIR_ERR_MULTIPLE_DOMAINS] = {
        N_("multiple matching domains found"),
        N_("multiple matching domains found: %1$s") },
    [VIR_ERR_NO_NETWORK_METADATA] = {
        N_("metadata not found"),
        N_("metadata not found: %1$s") },
};

G_STATIC_ASSERT(G_N_ELEMENTS(virErrorMsgStrings) == VIR_ERR_NUMBER_LAST);


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
    char *detail = NULL;
    char *errormsg = NULL;
    char *fullmsg = NULL;

    if (fmt) {
        va_list args;

        va_start(args, fmt);
        detail = g_strdup_vprintf(fmt, args);
        va_end(args);
    }

    errormsg = g_strdup(virErrorMsg(errorcode, detail));

    if (errormsg) {
        if (detail)
            fullmsg = g_strdup_printf(errormsg, detail);
        else
            fullmsg = g_strdup(errormsg);
    }

    virRaiseErrorInternal(filename, funcname, linenr,
                          domcode, errorcode, VIR_ERR_ERROR,
                          fullmsg, errormsg, detail, NULL, -1, -1);

    errno = save_errno;
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
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char *detail = NULL;
    char *errormsg = NULL;
    char *fullmsg = NULL;

    if (fmt) {
        va_list args;

        va_start(args, fmt);
        virBufferVasprintf(&buf, fmt, args);
        va_end(args);

        virBufferAddLit(&buf, ": ");
    }

    virBufferAdd(&buf, g_strerror(theerrno), -1);

    detail = virBufferContentAndReset(&buf);
    errormsg = g_strdup(virErrorMsg(VIR_ERR_SYSTEM_ERROR, detail));
    fullmsg = g_strdup_printf(errormsg, detail);

    virRaiseErrorInternal(filename, funcname, linenr,
                          domcode, VIR_ERR_SYSTEM_ERROR, VIR_ERR_ERROR,
                          fullmsg, errormsg, detail, NULL, theerrno, -1);
    errno = save_errno;
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


/**
 * virLastErrorPrefixMessage:
 * @fmt: printf-style formatting string
 * @...: Arguments for @fmt
 *
 * Prefixes last error reported with message formatted from @fmt. This is useful
 * if the low level error message does not convey enough information to describe
 * the problem.
 */
void
virLastErrorPrefixMessage(const char *fmt, ...)
{
    int save_errno = errno;
    virErrorPtr err = virGetLastError();
    g_autofree char *fmtmsg = NULL;
    g_autofree char *newmsg = NULL;
    va_list args;

    if (!err)
        return;

    va_start(args, fmt);
    fmtmsg = g_strdup_vprintf(fmt, args);
    va_end(args);

    newmsg = g_strdup_printf("%s: %s", fmtmsg, err->message);

    VIR_FREE(err->message);
    err->message = g_steal_pointer(&newmsg);

    errno = save_errno;
}
