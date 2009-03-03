/*
 * virterror.c: implements error handling and reporting code for libvirt
 *
 * Copy:  Copyright (C) 2006, 2008, 2009 Red Hat, Inc.
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
#include "logging.h"
#include "memory.h"
#include "threads.h"
#include "util.h"

virThreadLocal virLastErr;

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

static virLogPriority virErrorLevelPriority(virErrorLevel level) {
    switch (level) {
        case VIR_ERR_NONE:
            return(VIR_LOG_INFO);
        case VIR_ERR_WARNING:
            return(VIR_LOG_WARN);
        case VIR_ERR_ERROR:
            return(VIR_LOG_ERROR);
    }
    return(VIR_LOG_ERROR);
}

static const char *virErrorDomainName(virErrorDomain domain) {
    const char *dom = "unknown";
    switch (domain) {
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
        case VIR_FROM_SECURITY:
            dom = "Security Labeling ";
            break;
    }
    return(dom);
}


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
    err->message = strdup(_("Unknown failure"));
}


/*
 * Internal helper to perform a deep copy of the an error
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
    if (from->message && !(to->message = strdup(from->message)))
        ret = -1;
    if (from->str1 && !(to->str1 = strdup(from->str1)))
        ret = -1;
    if (from->str2 && !(to->str2 = strdup(from->str2)))
        ret = -1;
    if (from->str3 && !(to->str3 = strdup(from->str3)))
        ret = -1;
    to->int1 = from->int1;
    to->int2 = from->int2;
    /*
     * Delibrately not setting 'conn', 'dom', 'net' references
     */
    return ret;
}

static virErrorPtr
virLastErrorObject(void)
{
    virErrorPtr err;
    err = virThreadLocalGet(&virLastErr);
    if (!err) {
        if (VIR_ALLOC(err) < 0)
            return NULL;
        virThreadLocalSet(&virLastErr, err);
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
    /* We can't guarentee caller has initialized it to zero */
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
 * Save the last error into a new error object.
 *
 * Returns a pointer to the copied error or NULL if allocation failed.
 * It is the caller's responsibility to free the error with
 * virFreeError().
 */
virErrorPtr
virSaveLastError(void)
{
    virErrorPtr to;

    if (VIR_ALLOC(to) < 0)
        return NULL;

    virCopyLastError(to);
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
    free(err->message);
    free(err->str1);
    free(err->str2);
    free(err->str3);
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
 * remains for backwards compatability.
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
 * remains for backwards compatability.
 *
 * One will need to free the result with virResetError()
 *
 * Returns 0 if no error was found and the error code otherwise and -1 in case
 *         of parameter error.
 */
int
virConnCopyLastError(virConnectPtr conn, virErrorPtr to)
{
    /* We can't guarentee caller has initialized it to zero */
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
    dom = virErrorDomainName(err->domain);
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

/*
 * Internal helper to ensure the global error object
 * is initialized with a generic message if not already
 * set.
 */
void
virSetGlobalError(void)
{
    virErrorPtr err = virLastErrorObject();

    if (err && err->code == VIR_ERR_OK)
        virErrorGenericFailure(err);
}

/*
 * Internal helper to ensure the connection error object
 * is initialized from the global object.
 */
void
virSetConnError(virConnectPtr conn)
{
    virErrorPtr err = virLastErrorObject();

    if (err && err->code == VIR_ERR_OK)
        virErrorGenericFailure(err);

    if (conn) {
        virMutexLock(&conn->lock);
        if (err)
            virCopyError(err, &conn->err);
        else
            virErrorGenericFailure(&conn->err);
        virMutexUnlock(&conn->lock);
    }
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
virRaiseError(virConnectPtr conn,
              virDomainPtr dom ATTRIBUTE_UNUSED,
              virNetworkPtr net ATTRIBUTE_UNUSED,
              int domain, int code, virErrorLevel level,
              const char *str1, const char *str2, const char *str3,
              int int1, int int2, const char *msg, ...)
{
    virErrorPtr to;
    void *userData = virUserData;
    virErrorFunc handler = virErrorHandler;
    char *str;

    /*
     * All errors are recorded in thread local storage
     * For compatability, public API calls will copy them
     * to the per-connection error object when neccessary
     */
    to = virLastErrorObject();
    if (!to)
        return; /* Hit OOM allocating thread error object, sod all we can do now */

    virResetError(to);

    if (code == VIR_ERR_OK)
        return;

    /*
     * try to find the best place to save and report the error
     */
    if (conn != NULL) {
        virMutexLock(&conn->lock);
        if (conn->handler != NULL) {
            handler = conn->handler;
            userData = conn->userData;
        }
        virMutexUnlock(&conn->lock);
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
     * Hook up the error or warning to the logging facility
     * TODO: pass function name and lineno
     */
    virLogMessage(virErrorDomainName(domain), virErrorLevelPriority(level),
                  NULL, 0, 1, "%s", str);

    /*
     * Save the information about the error
     */
    virResetError(to);
    /*
     * Delibrately not setting conn, dom & net fields since
     * they're utterly unsafe
     */
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
        case VIR_ERR_NO_SECURITY_MODEL:
            if (info == NULL)
                    errmsg = _("Security model not found");
            else
                    errmsg = _("Security model not found: %s");
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
                          size_t linenr ATTRIBUTE_UNUSED,
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

const char *virStrerror(int theerrno, char *errBuf, size_t errBufLen)
{
#ifdef HAVE_STRERROR_R
# ifdef __USE_GNU
    /* Annoying linux specific API contract */
    return strerror_r(theerrno, errBuf, errBufLen);
# else
    strerror_r(theerrno, errBuf, errBufLen);
    return errBuf;
# endif
#else
    /* Mingw lacks strerror_r() and its strerror() is definitely not
     * threadsafe, so safest option is to just print the raw errno
     * value - we can at least reliably & safely look it up in the
     * header files for debug purposes
     */
    int n = snprintf(errBuf, errBufLen, "errno=%d", theerrno);
    return (0 < n && n < errBufLen
            ? errBuf : _("internal error: buffer too small"));
#endif
}

void virReportSystemErrorFull(virConnectPtr conn,
                              int domcode,
                              int theerrno,
                              const char *filename ATTRIBUTE_UNUSED,
                              const char *funcname ATTRIBUTE_UNUSED,
                              size_t linenr ATTRIBUTE_UNUSED,
                              const char *fmt, ...)
{
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

        size_t len = strlen (msgDetailBuf);
        if (0 <= n && n + 2 + len < sizeof (msgDetailBuf)) {
          char *p = msgDetailBuf + n;
          stpcpy (stpcpy (p, ": "), errnoDetail);
          msgDetail = msgDetailBuf;
        }
    }

    if (!msgDetail)
        msgDetail = errnoDetail;

    virRaiseError(conn, NULL, NULL, domcode, VIR_ERR_SYSTEM_ERROR, VIR_ERR_ERROR,
                  msg, msgDetail, NULL, -1, -1, msg, msgDetail);
}

void virReportOOMErrorFull(virConnectPtr conn,
                           int domcode,
                           const char *filename ATTRIBUTE_UNUSED,
                           const char *funcname ATTRIBUTE_UNUSED,
                           size_t linenr ATTRIBUTE_UNUSED)
{
    const char *virerr;

    virerr = virErrorMsg(VIR_ERR_NO_MEMORY, NULL);
    virRaiseError(conn, NULL, NULL, domcode, VIR_ERR_NO_MEMORY, VIR_ERR_ERROR,
                  virerr, NULL, NULL, -1, -1, virerr, NULL);
}
