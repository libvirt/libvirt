/*
 * virterror.h: internal error handling
 *
 * Copyright (C) 2006-2009 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 */

#ifndef __VIRT_ERROR_H_
#define __VIRT_ERROR_H_

#include "internal.h"

extern virErrorFunc virErrorHandler;
extern void *virUserData;

/************************************************************************
 *									*
 *		API for error handling					*
 *									*
 ************************************************************************/
int virErrorInitialize(void);
void virRaiseError(virConnectPtr conn,
                   virDomainPtr dom,
                   virNetworkPtr net,
                   int domain,
                   int code,
                   virErrorLevel level,
                   const char *str1,
                   const char *str2,
                   const char *str3,
                   int int1, int int2, const char *msg, ...)
  ATTRIBUTE_FORMAT(printf, 12, 13);
const char *virErrorMsg(virErrorNumber error, const char *info);
void virReportErrorHelper(virConnectPtr conn, int domcode, int errcode,
                          const char *filename ATTRIBUTE_UNUSED,
                          const char *funcname ATTRIBUTE_UNUSED,
                          size_t linenr ATTRIBUTE_UNUSED,
                          const char *fmt, ...)
  ATTRIBUTE_FORMAT(printf, 7, 8);

void virReportSystemErrorFull(virConnectPtr conn,
                              int domcode,
                              int theerrno,
                              const char *filename,
                              const char *funcname,
                              size_t linenr,
                              const char *fmt, ...)
    ATTRIBUTE_FORMAT(printf, 7, 8);

#define virReportSystemError(conn, theerrno, fmt,...)             \
    virReportSystemErrorFull((conn),                              \
                             VIR_FROM_THIS,                       \
                             (theerrno),                          \
                             __FILE__, __FUNCTION__, __LINE__,    \
                             (fmt), __VA_ARGS__)

void virReportOOMErrorFull(virConnectPtr conn,
                           int domcode,
                           const char *filename,
                           const char *funcname,
                           size_t linenr);

#define virReportOOMError(conn)                         \
    virReportOOMErrorFull((conn), VIR_FROM_THIS,        \
                     __FILE__, __FUNCTION__, __LINE__)


void virSetGlobalError(void);
void virSetConnError(virConnectPtr conn);
const char *virStrerror(int theerrno, char *errBuf, size_t errBufLen);

#endif
