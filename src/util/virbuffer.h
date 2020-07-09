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


/**
 * virBuffer:
 *
 * A buffer structure.
 */
typedef struct _virBuffer virBuffer;
typedef virBuffer *virBufferPtr;

#define VIR_BUFFER_INITIALIZER { NULL, 0 }

/**
 * VIR_BUFFER_INIT_CHILD:
 * @parentbuf: parent buffer for XML element formatting
 *
 * Initialize a virBuffer structure and set up the indentation level for
 * formatting XML subelements of @parentbuf.
 */
#define VIR_BUFFER_INIT_CHILD(parentbuf) { NULL, (parentbuf)->indent + 2 }

struct _virBuffer {
    GString *str;
    int indent;
};

const char *virBufferCurrentContent(virBufferPtr buf);
char *virBufferContentAndReset(virBufferPtr buf);
void virBufferFreeAndReset(virBufferPtr buf);

G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(virBuffer, virBufferFreeAndReset);

size_t virBufferUse(const virBuffer *buf);
void virBufferAdd(virBufferPtr buf, const char *str, int len);
void virBufferAddBuffer(virBufferPtr buf, virBufferPtr toadd);
void virBufferAddChar(virBufferPtr buf, char c);
void virBufferAsprintf(virBufferPtr buf, const char *format, ...)
  G_GNUC_PRINTF(2, 3);
void virBufferVasprintf(virBufferPtr buf, const char *format, va_list ap)
  G_GNUC_PRINTF(2, 0);
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

size_t virBufferGetIndent(const virBuffer *buf);
size_t virBufferGetEffectiveIndent(const virBuffer *buf);

void virBufferTrim(virBufferPtr buf, const char *trim);
void virBufferTrimChars(virBufferPtr buf, const char *trim);
void virBufferTrimLen(virBufferPtr buf, int len);
void virBufferAddStr(virBufferPtr buf, const char *str);
