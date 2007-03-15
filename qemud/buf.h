/*
 * buf.h: buffers for qemud
 *
 * Copyright (C) 2005 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Daniel Veillard <veillard@redhat.com>
 */

#ifndef __QEMUD_BUF_H__
#define __QEMUD_BUF_H__

#include "internal.h"

/**
 * buffer:
 *
 * A buffer structure.
 */
typedef struct _buffer buffer;
typedef buffer *bufferPtr;
struct _buffer {
    char *content;          /* The buffer content UTF8 */
    unsigned int use;       /* The buffer size used */
    unsigned int size;      /* The buffer size */
};

bufferPtr bufferNew(unsigned int size);
void bufferFree(bufferPtr buf);
char *bufferContentAndFree(bufferPtr buf);
int bufferAdd(bufferPtr buf, const char *str, int len);
int bufferVSprintf(bufferPtr buf, const char *format, ...)
  ATTRIBUTE_FORMAT(printf, 2, 3);
int bufferStrcat(bufferPtr buf, ...);

#endif                          /* __QEMUD_BUF_H__ */
