/*
 * virbuffer.h: buffers for libvirt
 *
 * Copyright (C) 2005-2008, 2011-2014 Red Hat, Inc.
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

#pragma once

#include <stdarg.h>

#include "internal.h"
#include "virautoclean.h"


/**
 * virBuffer:
 *
 * A buffer structure.
 */
typedef struct _virBuffer virBuffer;
typedef virBuffer *virBufferPtr;

#define VIR_BUFFER_INITIALIZER { 0, 0, 0, 0, NULL }

struct _virBuffer {
    size_t size;
    size_t use;
    int error; /* errno value, or -1 for usage error */
    int indent;
    char *content;
};

const char *virBufferCurrentContent(virBufferPtr buf);
char *virBufferContentAndReset(virBufferPtr buf);
void virBufferFreeAndReset(virBufferPtr buf);
int virBufferError(const virBuffer *buf);
int virBufferCheckErrorInternal(const virBuffer *buf,
                                int domcode,
                                const char *filename,
                                const char *funcname,
                                size_t linenr)
    ATTRIBUTE_NONNULL(1);

VIR_DEFINE_AUTOCLEAN_FUNC(virBuffer, virBufferFreeAndReset);

/**
 * virBufferCheckError
 *
 * Checks if the buffer is in error state and reports an error.
 *
 * Returns 0 if no error has occurred, otherwise an error is reported
 * and -1 is returned.
 */
#define virBufferCheckError(buf) \
    virBufferCheckErrorInternal(buf, VIR_FROM_THIS, __FILE__, __FUNCTION__, \
    __LINE__)
size_t virBufferUse(const virBuffer *buf);
void virBufferAdd(virBufferPtr buf, const char *str, int len);
void virBufferAddBuffer(virBufferPtr buf, virBufferPtr toadd);
void virBufferAddChar(virBufferPtr buf, char c);
void virBufferAsprintf(virBufferPtr buf, const char *format, ...)
  ATTRIBUTE_FMT_PRINTF(2, 3);
void virBufferVasprintf(virBufferPtr buf, const char *format, va_list ap)
  ATTRIBUTE_FMT_PRINTF(2, 0);
void virBufferStrcat(virBufferPtr buf, ...)
  G_GNUC_NULL_TERMINATED;
void virBufferStrcatVArgs(virBufferPtr buf, va_list ap);

void virBufferEscape(virBufferPtr buf, char escape, const char *toescape,
                     const char *format, const char *str);
void virBufferEscapeString(virBufferPtr buf, const char *format,
                           const char *str);
void virBufferEscapeSexpr(virBufferPtr buf, const char *format,
                          const char *str);
void virBufferEscapeRegex(virBufferPtr buf,
                          const char *format,
                          const char *str);
void virBufferEscapeSQL(virBufferPtr buf,
                        const char *format,
                        const char *str);
void virBufferEscapeShell(virBufferPtr buf, const char *str);
void virBufferURIEncodeString(virBufferPtr buf, const char *str);

#define virBufferAddLit(buf_, literal_string_) \
    virBufferAdd(buf_, "" literal_string_ "", sizeof(literal_string_) - 1)

void virBufferAdjustIndent(virBufferPtr buf, int indent);
void virBufferSetIndent(virBufferPtr, int indent);

/**
 * virBufferSetChildIndent
 *
 * Gets the parent indentation, increments it by 2 and sets it to
 * child buffer.
 */
#define virBufferSetChildIndent(childBuf_, parentBuf_) \
    virBufferSetIndent(childBuf_, virBufferGetIndent(parentBuf_, false) + 2)

int virBufferGetIndent(const virBuffer *buf, bool dynamic);

void virBufferTrim(virBufferPtr buf, const char *trim, int len);
void virBufferAddStr(virBufferPtr buf, const char *str);
