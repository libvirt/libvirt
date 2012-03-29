/*
 * buf.h: buffers for libvirt
 *
 * Copyright (C) 2005-2008, 2011, 2012 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
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

char *virBufferContentAndReset(virBufferPtr buf);
void virBufferFreeAndReset(virBufferPtr buf);
int virBufferError(const virBufferPtr buf);
unsigned int virBufferUse(const virBufferPtr buf);
void virBufferAdd(virBufferPtr buf, const char *str, int len);
void virBufferAddChar(virBufferPtr buf, char c);
void virBufferAsprintf(virBufferPtr buf, const char *format, ...)
  ATTRIBUTE_FMT_PRINTF(2, 3);
void virBufferVasprintf(virBufferPtr buf, const char *format, va_list ap)
  ATTRIBUTE_FMT_PRINTF(2, 0);
void virBufferStrcat(virBufferPtr buf, ...)
  ATTRIBUTE_SENTINEL;
void virBufferEscape(virBufferPtr buf, char escape, const char *toescape,
                     const char *format, const char *str);
void virBufferEscapeString(virBufferPtr buf, const char *format,
                           const char *str);
void virBufferEscapeSexpr(virBufferPtr buf, const char *format,
                          const char *str);
void virBufferEscapeShell(virBufferPtr buf, const char *str);
void virBufferURIEncodeString(virBufferPtr buf, const char *str);

# define virBufferAddLit(buf_, literal_string_) \
    virBufferAdd(buf_, "" literal_string_ "", sizeof(literal_string_) - 1)

void virBufferAdjustIndent(virBufferPtr buf, int indent);
int virBufferGetIndent(const virBufferPtr buf, bool dynamic);

#endif /* __VIR_BUFFER_H__ */
