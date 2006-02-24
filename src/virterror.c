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
#include "libvirt.h"
#include "virterror.h"
#include "internal.h"

static virError     lastErr = 		/* the last error */
{ 0, 0, NULL, VIR_ERR_NONE, NULL, NULL, NULL, NULL, NULL, 0, 0};
static virErrorFunc virErrorHandler = NULL;/* global error handlet */
static void        *virUserData = NULL;	/* associated data */

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

