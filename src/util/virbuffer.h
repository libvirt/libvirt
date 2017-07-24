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
 *
 * Daniel Veillard <veillard@redhat.com>
 */

#ifndef __VIR_BUFFER_H__
# define __VIR_BUFFER_H__

# include "internal.h"

# include <stdarg.h>

/**
 * virBuffer:
 *
 * A buffer structure.
 */
typedef struct _virBuffer virBuffer;
typedef virBuffer *virBufferPtr;

# ifndef __VIR_BUFFER_C__
#  define VIR_BUFFER_INITIALIZER { 0, 0, 0, 0, NULL }

/* This struct must be kept in sync with the real struct
   in the buf.c impl file */
struct _virBuffer {
    unsigned int a;
    unsigned int b;
    unsigned int c;
    int d;
    char *e;
};
# endif

const char *virBufferCurrentContent(virBufferPtr buf);
char *virBufferContentAndReset(virBufferPtr buf);
void virBufferFreeAndReset(virBufferPtr buf);
int virBufferError(const virBuffer *buf);
int virBufferCheckErrorInternal(const virBuffer *buf,
                                int domcode,
                                const char *filename,
                                const char *funcname,
                                size_t linenr)
    ATTRIBUTE_RETURN_CHECK ATTRIBUTE_NONNULL(1);
/**
 * virBufferCheckError
 *
 * Checks if the buffer is in error state and reports an error.
 *
 * Returns 0 if no error has occurred, otherwise an error is reported
 * and -1 is returned.
 */
# define virBufferCheckError(buf) \
    virBufferCheckErrorInternal(buf, VIR_FROM_THIS, __FILE__, __FUNCTION__, \
    __LINE__)
unsigned int virBufferUse(const virBuffer *buf);
void virBufferAdd(virBufferPtr buf, const char *str, int len);
void virBufferAddBuffer(virBufferPtr buf, virBufferPtr toadd);
void virBufferAddChar(virBufferPtr buf, char c);
void virBufferAsprintf(virBufferPtr buf, const char *format, ...)
  ATTRIBUTE_FMT_PRINTF(2, 3);
void virBufferVasprintf(virBufferPtr buf, const char *format, va_list ap)
  ATTRIBUTE_FMT_PRINTF(2, 0);
void virBufferStrcat(virBufferPtr buf, ...)
  ATTRIBUTE_SENTINEL;
void virBufferStrcatVArgs(virBufferPtr buf, va_list ap);

void virBufferEscape(virBufferPtr buf, char escape, const char *toescape,
                     const char *format, const char *str);
void virBufferEscapeN(virBufferPtr buf, const char *format,
                      const char *str, ...);
void virBufferEscapeString(virBufferPtr buf, const char *format,
                           const char *str);
void virBufferEscapeSexpr(virBufferPtr buf, const char *format,
                          const char *str);
void virBufferEscapeRegex(virBufferPtr buf,
                          const char *format,
                          const char *str);
void virBufferEscapeShell(virBufferPtr buf, const char *str);
void virBufferURIEncodeString(virBufferPtr buf, const char *str);

# define virBufferAddLit(buf_, literal_string_) \
    virBufferAdd(buf_, "" literal_string_ "", sizeof(literal_string_) - 1)

void virBufferAdjustIndent(virBufferPtr buf, int indent);
void virBufferSetIndent(virBufferPtr, int indent);

int virBufferGetIndent(const virBuffer *buf, bool dynamic);

void virBufferTrim(virBufferPtr buf, const char *trim, int len);
void virBufferAddStr(virBufferPtr buf, const char *str);

#endif /* __VIR_BUFFER_H__ */
