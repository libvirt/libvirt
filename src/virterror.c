/*
 * virterror.c: implements error handling and reporting code for libvirt
 *
 * Copy:  Copyright (C) 2006 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Author: Daniel Veillard <veillard@redhat.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "libvirt.h"
#include "virterror.h"
#include "internal.h"

static virError     lastErr = 		/* the last error */
{ 0, 0, NULL, VIR_ERR_NONE, NULL, NULL, NULL, NULL, NULL, 0, 0};
static virErrorFunc virErrorHandler = NULL;/* global error handlet */
static void        *virUserData = NULL;	/* associated data */

/*
 * Macro used to format the message as a string in __virRaiseError
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
 * Returns a pointer to the last error or NULL if none occured.
 */
virErrorPtr
virGetLastError(void) {
    if (lastErr.code == VIR_ERR_OK)
        return(NULL);
    return(&lastErr);
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
virCopyLastError(virErrorPtr to) {
    if (to == NULL)
        return(-1);
    if (lastErr.code == VIR_ERR_OK)
        return(0);
    memcpy(to, &lastErr, sizeof(virError));
    return(lastErr.code);
}

/**
 * virResetError:
 * @err: pointer to the virError to clean up
 * 
 * Reset the error being pointed to
 */
void
virResetError(virErrorPtr err) {
    if (err == NULL)
        return;
    if (err->message != NULL)
        free(err->message);
    if (err->str1 != NULL)
        free(err->str1);
    if (err->str2 != NULL)
        free(err->str2);
    if (err->str3 != NULL)
        free(err->str3);
    memset(err, 0, sizeof(virError));
}

/**
 * virResetLastError:
 * 
 * Reset the last error caught at the library level.
 */
void
virResetLastError(void) {
    virResetError(&lastErr);
}

/**
 * virConnGetLastError:
 * @conn: pointer to the hypervisor connection
 *
 * Provide a pointer to the last error caught on that connection
 * Simpler but may not be suitable for multithreaded accesses, in which
 * case use virConnCopyLastError()
 *
 * Returns a pointer to the last error or NULL if none occured.
 */
virErrorPtr
virConnGetLastError(virConnectPtr conn) {
    if (conn == NULL)
	return(NULL);
    return(&conn->err);
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
virConnCopyLastError(virConnectPtr conn, virErrorPtr to) {
    if (conn == NULL)
	return(-1);
    if (to == NULL)
        return(-1);
    if (conn->err.code == VIR_ERR_OK)
        return(0);
    memcpy(to, &conn->err, sizeof(virError));
    return(conn->err.code);
}

/**
 * virConnResetLastError:
 * @conn: pointer to the hypervisor connection
 *
 * Reset the last error caught on that connection
 */
void
virConnResetLastError(virConnectPtr conn) {
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
virSetErrorFunc(void *userData, virErrorFunc handler) {
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
virConnSetErrorFunc(virConnectPtr conn, void *userData, virErrorFunc handler) {
    if (conn == NULL)
        return;
    conn->handler = handler;
    conn->userData = userData;
}

/**
 * virReportError:
 * @err: pointer to the error.
 *
 * Internal routine reporting an error to stderr.
 */
static void
virReportError(virErrorPtr err) {
    const char *lvl = "", *dom = "", *domain = "";
    int len;

    if ((err == NULL) || (err->code == VIR_ERR_OK))
        return;
    switch (err->level) {
        case VIR_ERR_NONE:
	    lvl = "";
	    break;
        case VIR_ERR_WARNING:
	    lvl = "warning";
	    break;
        case VIR_ERR_ERROR:
	    lvl = "error";
	    break;
    } 
    switch (err->domain) {
        case VIR_FROM_NONE:
	    dom = "";
	    break;
        case VIR_FROM_XEN:
	    dom = "Xen ";
	    break;
        case VIR_FROM_XEND:
	    dom = "Xen Daemon ";
	    break;
        case VIR_FROM_DOM:
	    dom = "Domain ";
	    break;
    }
    if ((err->dom != NULL) && (err->code != VIR_ERR_INVALID_DOMAIN)) {
        domain = err->dom->name;
    }
    len = strlen(err->message);
    if ((len == 0) || (err->message[len - 1] != '\n'))
	fprintf(stderr, "libvir: %s%s %s: %s\n",
	        dom, lvl, domain, err->message);
    else 
	fprintf(stderr, "libvir: %s%s %s: %s",
	        dom, lvl, domain, err->message);
}

/**
 * __virRaiseError:
 * @conn: the connection to the hypervisor if available
 * @dom: the domain if available
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
__virRaiseError(virConnectPtr conn, virDomainPtr dom,
                int domain, int code, virErrorLevel level,
                const char *str1, const char *str2, const char *str3,
		int int1, int int2, const char *msg, ...) {
    virErrorPtr to = &lastErr;
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
        str = strdup("No error message provided");
    } else {
        VIR_GET_VAR_STR(msg, str);
    }

    /*
     * Save the information about the error
     */
    virResetError(to);
    to->conn = conn;
    to->dom = dom;
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
        virReportError(to);
    }
}

/**
 * __virErrorMsg:
 * @error: the virErrorNumber
 * @info: usually the first paprameter string
 *
 * Internal routine to get the message associated to an error raised
 * from the library
 *
 * Returns the constant string associated to @error
 */
const char *
__virErrorMsg(virErrorNumber error, const char *info) {
    const char *errmsg = NULL;

    switch (error) {
        case VIR_ERR_OK:
	    return(NULL);
	case VIR_ERR_INTERNAL_ERROR:
	    if (info != NULL)
		errmsg = "internal error %s";
	    else
	        errmsg = "internal error";
	    break;
	case VIR_ERR_NO_MEMORY:
	    errmsg = "out of memory";
	    break;
	case VIR_ERR_NO_SUPPORT:
	    errmsg = "no support for hypervisor %s";
	    break;
	case VIR_ERR_NO_CONNECT:
	    if (info == NULL)
	        errmsg = "could not connect to hypervisor";
	    else
	        errmsg = "could not connect to %s";
	    break;
	case VIR_ERR_INVALID_CONN:
	    errmsg = "invalid connection pointer in";
	    break;
	case VIR_ERR_INVALID_DOMAIN:
	    errmsg = "invalid domain pointer in";
	    break;
	case VIR_ERR_INVALID_ARG:
	    errmsg = "invalid domain pointer in";
	    break;
	case VIR_ERR_OPERATION_FAILED:
	    if (info != NULL)
	        errmsg = "operation failed: %s";
	    else
	        errmsg = "operation failed";
	    break;
	case VIR_ERR_GET_FAILED:
	    if (info != NULL)
	        errmsg = "GET operation failed: %s";
	    else
	        errmsg = "GET operation failed";
	    break;
	case VIR_ERR_POST_FAILED:
	    if (info != NULL)
	        errmsg = "POST operation failed: %s";
	    else
	        errmsg = "POST operation failed";
	    break;
	case VIR_ERR_HTTP_ERROR:
	    errmsg = "got unknown HTTP error code %d";
	    break;
	case VIR_ERR_UNKNOWN_HOST:
	    errmsg = "Unknown host %s";
	    break;
    }
    return(errmsg);
}

