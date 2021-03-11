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

const char *virBufferCurrentContent(virBuffer *buf);
char *virBufferContentAndReset(virBuffer *buf);
void virBufferFreeAndReset(virBuffer *buf);

G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(virBuffer, virBufferFreeAndReset);

size_t virBufferUse(const virBuffer *buf);
void virBufferAdd(virBuffer *buf, const char *str, int len);
void virBufferAddBuffer(virBuffer *buf, virBuffer *toadd);
void virBufferAddChar(virBuffer *buf, char c);
void virBufferAsprintf(virBuffer *buf, const char *format, ...)
  G_GNUC_PRINTF(2, 3);
void virBufferVasprintf(virBuffer *buf, const char *format, va_list ap)
  G_GNUC_PRINTF(2, 0);
void virBufferStrcat(virBuffer *buf, ...)
  G_GNUC_NULL_TERMINATED;
void virBufferStrcatVArgs(virBuffer *buf, va_list ap);

void virBufferEscape(virBuffer *buf, char escape, const char *toescape,
                     const char *format, const char *str);
void virBufferEscapeString(virBuffer *buf, const char *format,
                           const char *str);
void virBufferEscapeSexpr(virBuffer *buf, const char *format,
                          const char *str);
void virBufferEscapeRegex(virBuffer *buf,
                          const char *format,
                          const char *str);
void virBufferEscapeSQL(virBuffer *buf,
                        const char *format,
                        const char *str);
void virBufferEscapeShell(virBuffer *buf, const char *str);
void virBufferURIEncodeString(virBuffer *buf, const char *str);

#define virBufferAddLit(buf_, literal_string_) \
    virBufferAdd(buf_, "" literal_string_ "", sizeof(literal_string_) - 1)

void virBufferAdjustIndent(virBuffer *buf, int indent);
void virBufferSetIndent(virBuffer *, int indent);

size_t virBufferGetIndent(const virBuffer *buf);
size_t virBufferGetEffectiveIndent(const virBuffer *buf);

void virBufferTrim(virBuffer *buf, const char *trim);
void virBufferTrimChars(virBuffer *buf, const char *trim);
void virBufferTrimLen(virBuffer *buf, int len);
void virBufferAddStr(virBuffer *buf, const char *str);
