/*
 * virerror.h: error handling and reporting code for libvirt
 *
 * Copyright (C) 2006-2014 Red Hat, Inc.
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
 */

#ifndef __VIRT_ERROR_H_
# define __VIRT_ERROR_H_

# include "internal.h"

extern virErrorFunc virErrorHandler;
extern void *virUserData;

/************************************************************************
 *									*
 *		API for error handling					*
 *									*
 ************************************************************************/
int virErrorInitialize(void);
void virRaiseErrorFull(const char *filename,
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
    ATTRIBUTE_FMT_PRINTF(12, 13);

void virReportErrorHelper(int domcode, int errcode,
                          const char *filename,
                          const char *funcname,
                          size_t linenr,
                          const char *fmt, ...)
  ATTRIBUTE_FMT_PRINTF(6, 7);

void virReportSystemErrorFull(int domcode,
                              int theerrno,
                              const char *filename,
                              const char *funcname,
                              size_t linenr,
                              const char *fmt, ...)
    ATTRIBUTE_FMT_PRINTF(6, 7);

# define virReportSystemError(theerrno, fmt,...)                   \
    virReportSystemErrorFull(VIR_FROM_THIS,                       \
                             (theerrno),                          \
                             __FILE__, __FUNCTION__, __LINE__,    \
                             (fmt), __VA_ARGS__)

# define virReportInvalidNullArg(argname)                            \
    virRaiseErrorFull(__FILE__, __FUNCTION__, __LINE__,              \
                      VIR_FROM_THIS,                                 \
                      VIR_ERR_INVALID_ARG,                           \
                      VIR_ERR_ERROR,                                 \
                      __FUNCTION__,                                  \
                      #argname,                                      \
                      NULL,                                          \
                      0, 0,                                          \
                      _("%s in %s must be NULL"),                    \
                      #argname, __FUNCTION__)
# define virReportInvalidNonNullArg(argname)                         \
    virRaiseErrorFull(__FILE__, __FUNCTION__, __LINE__,              \
                      VIR_FROM_THIS,                                 \
                      VIR_ERR_INVALID_ARG,                           \
                      VIR_ERR_ERROR,                                 \
                      __FUNCTION__,                                  \
                      #argname,                                      \
                      NULL,                                          \
                      0, 0,                                          \
                      _("%s in %s must not be NULL"),                \
                      #argname, __FUNCTION__)
# define virReportInvalidPositiveArg(argname)                        \
    virRaiseErrorFull(__FILE__, __FUNCTION__, __LINE__,              \
                      VIR_FROM_THIS,                                 \
                      VIR_ERR_INVALID_ARG,                           \
                      VIR_ERR_ERROR,                                 \
                      __FUNCTION__,                                  \
                      #argname,                                      \
                      NULL,                                          \
                      0, 0,                                          \
                      _("%s in %s must greater than zero"),          \
                      #argname, __FUNCTION__)
# define virReportInvalidNonZeroArg(argname)                         \
    virRaiseErrorFull(__FILE__, __FUNCTION__, __LINE__,              \
                      VIR_FROM_THIS,                                 \
                      VIR_ERR_INVALID_ARG,                           \
                      VIR_ERR_ERROR,                                 \
                      __FUNCTION__,                                  \
                      #argname,                                      \
                      NULL,                                          \
                      0, 0,                                          \
                      _("%s in %s must not be zero"),                \
                      #argname, __FUNCTION__)
# define virReportInvalidZeroArg(argname)                            \
    virRaiseErrorFull(__FILE__, __FUNCTION__, __LINE__,              \
                      VIR_FROM_THIS,                                 \
                      VIR_ERR_INVALID_ARG,                           \
                      VIR_ERR_ERROR,                                 \
                      __FUNCTION__,                                  \
                      #argname,                                      \
                      NULL,                                          \
                      0, 0,                                          \
                      _("%s in %s must be zero"),                    \
                      #argname, __FUNCTION__)
# define virReportInvalidNonNegativeArg(argname)                     \
    virRaiseErrorFull(__FILE__, __FUNCTION__, __LINE__,              \
                      VIR_FROM_THIS,                                 \
                      VIR_ERR_INVALID_ARG,                           \
                      VIR_ERR_ERROR,                                 \
                      __FUNCTION__,                                  \
                      #argname,                                      \
                      NULL,                                          \
                      0, 0,                                          \
                      _("%s in %s must be zero or greater"),         \
                      #argname, __FUNCTION__)
# define virReportInvalidArg(argname, fmt, ...)                      \
    virRaiseErrorFull(__FILE__, __FUNCTION__, __LINE__,              \
                      VIR_FROM_THIS,                                 \
                      VIR_ERR_INVALID_ARG,                           \
                      VIR_ERR_ERROR,                                 \
                      __FUNCTION__,                                  \
                      #argname,                                      \
                      NULL,                                          \
                      0, 0,                                          \
                      (fmt), __VA_ARGS__)

# define virReportDBusServiceError(message, name)                    \
    virRaiseErrorFull(__FILE__, __FUNCTION__, __LINE__,              \
                      VIR_FROM_THIS,                                 \
                      VIR_ERR_DBUS_SERVICE,                          \
                      VIR_ERR_ERROR,                                 \
                      __FUNCTION__,                                  \
                      name,                                          \
                      NULL,                                          \
                      0, 0,                                          \
                      "%s", message);

# define virReportUnsupportedError()                                    \
    virReportErrorHelper(VIR_FROM_THIS, VIR_ERR_NO_SUPPORT,             \
                         __FILE__, __FUNCTION__, __LINE__, __FUNCTION__)
# define virReportRestrictedError(...)                                  \
    virReportErrorHelper(VIR_FROM_THIS, VIR_ERR_OPERATION_DENIED,       \
                         __FILE__, __FUNCTION__, __LINE__, __VA_ARGS__)


void virReportOOMErrorFull(int domcode,
                           const char *filename,
                           const char *funcname,
                           size_t linenr);

# define virReportOOMError() \
    virReportOOMErrorFull(VIR_FROM_THIS, __FILE__, __FUNCTION__, __LINE__)

# define virReportError(code, ...)                                   \
    virReportErrorHelper(VIR_FROM_THIS, code, __FILE__,              \
                         __FUNCTION__, __LINE__, __VA_ARGS__)

int virSetError(virErrorPtr newerr);
void virDispatchError(virConnectPtr conn);
const char *virStrerror(int theerrno, char *errBuf, size_t errBufLen);

typedef int (*virErrorLogPriorityFunc)(virErrorPtr, int);
void virSetErrorLogPriorityFunc(virErrorLogPriorityFunc func);

void virErrorSetErrnoFromLastError(void);

bool virLastErrorIsSystemErrno(int errnum);

#endif
