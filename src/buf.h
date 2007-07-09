/*
 * buf.h: buffers for libvirt
 *
 * Copyright (C) 2005-2007 Red Hat, Inc.
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
struct _virBuffer {
    char *content;          /* The buffer content UTF8 */
    unsigned int use;       /* The buffer size used */
    unsigned int size;      /* The buffer size */
};

virBufferPtr virBufferNew(unsigned int size);
void virBufferFree(virBufferPtr buf);
char *virBufferContentAndFree(virBufferPtr buf);
int virBufferAdd(virBufferPtr buf, const char *str, int len);
int virBufferVSprintf(virBufferPtr buf, const char *format, ...)
  ATTRIBUTE_FORMAT(printf, 2, 3);
int virBufferStrcat(virBufferPtr buf, ...);
int virBufferEscapeString(virBufferPtr buf, const char *format, const char *str);

#endif /* __VIR_BUFFER_H__ */
