/*
 * buf.h: buffers for libvirt
 *
 * Copyright (C) 2005-2008 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Daniel Veillard <veillard@redhat.com>
 */

#ifndef __VIR_BUFFER_H__
#define __VIR_BUFFER_H__

#include "internal.h"

/**
 * virBuffer:
 *
 * A buffer structure.
 */
typedef struct _virBuffer virBuffer;
typedef virBuffer *virBufferPtr;

#ifndef __VIR_BUFFER_C__
#define VIR_BUFFER_INITIALIZER { 0, 0, 0, NULL }

/* This struct must be kept in syn with the real struct
   in the buf.c impl file */
struct _virBuffer {
    unsigned int a;
    unsigned int b;
    unsigned int c;
    char *d;
};
#endif

char *__virBufferContentAndReset(const virBufferPtr buf);
int __virBufferError(const virBufferPtr buf);
unsigned int virBufferUse(const virBufferPtr buf);
void __virBufferAdd(const virBufferPtr buf, const char *str, int len);
void __virBufferAddChar(const virBufferPtr buf, char c);
void __virBufferVSprintf(const virBufferPtr buf, const char *format, ...)
  ATTRIBUTE_FORMAT(printf, 2, 3);
void virBufferStrcat(const virBufferPtr buf, ...);
void virBufferEscapeString(const virBufferPtr buf, const char *format, const char *str);
void virBufferURIEncodeString (const virBufferPtr buf, const char *str);

#define virBufferAddLit(buf_, literal_string_) \
  __virBufferAdd (buf_, "" literal_string_ "", sizeof literal_string_ - 1)

#define virBufferAdd(b,s,l) __virBufferAdd((b),(s),(l))
#define virBufferAddChar(b,c) __virBufferAddChar((b),(c))
#define virBufferVSprintf(b,f,...) __virBufferVSprintf((b),(f), __VA_ARGS__)

#define virBufferContentAndReset(b) __virBufferContentAndReset((b))
#define virBufferError(b) __virBufferError((b))

#endif /* __VIR_BUFFER_H__ */
