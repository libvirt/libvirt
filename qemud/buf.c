/*
 * buf.c: buffers for qemud
 *
 * Copyright (C) 2005 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Daniel Veillard <veillard@redhat.com>
 */

#include "libvirt/libvirt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "buf.h"

/**
 * bufferGrow:
 * @buf:  the buffer
 * @len:  the minimum free size to allocate on top of existing used space
 *
 * Grow the available space of a buffer to at least @len bytes.
 *
 * Returns the new available space or -1 in case of error
 */
static int
bufferGrow(bufferPtr buf, unsigned int len)
{
    int size;
    char *newbuf;

    if (buf == NULL)
        return (-1);
    if (len + buf->use < buf->size)
        return (0);

    size = buf->use + len + 1000;

    newbuf = (char *) realloc(buf->content, size);
    if (newbuf == NULL) return -1;
    buf->content = newbuf;
    buf->size = size;
    return (buf->size - buf->use);
}

/**
 * bufferAdd:
 * @buf:  the buffer to dump
 * @str:  the string
 * @len:  the number of bytes to add
 *
 * Add a string range to an XML buffer. if len == -1, the length of
 * str is recomputed to the full string.
 *
 * Returns 0 successful, -1 in case of internal or API error.
 */
int
bufferAdd(bufferPtr buf, const char *str, int len)
{
    unsigned int needSize;

    if ((str == NULL) || (buf == NULL)) {
        return -1;
    }
    if (len == 0)
        return 0;

    if (len < 0)
        len = strlen(str);

    needSize = buf->use + len + 2;
    if (needSize > buf->size) {
        if (!bufferGrow(buf, needSize - buf->use)) {
            return (-1);
        }
    }
    /* XXX: memmove() is 2x slower than memcpy(), do we really need it? */
    memmove(&buf->content[buf->use], str, len);
    buf->use += len;
    buf->content[buf->use] = 0;
    return (0);
}

bufferPtr
bufferNew(unsigned int size)
{
    bufferPtr buf;

    if (!(buf = malloc(sizeof(*buf)))) return NULL;
    if (size && (buf->content = malloc(size))==NULL) {
        free(buf);
        return NULL;
    }
    buf->size = size;
    buf->use = 0;

    return buf;
}

void
bufferFree(bufferPtr buf)
{
    if (buf) {
        if (buf->content)
            free(buf->content);
        free(buf);
    }
}

/**
 * bufferContentAndFree:
 * @buf: Buffer
 *
 * Return the content from the buffer and free (only) the buffer structure.
 */
char *
bufferContentAndFree (bufferPtr buf)
{
    char *content = buf->content;

    free (buf);
    return content;
}

/**
 * bufferVSprintf:
 * @buf:  the buffer to dump
 * @format:  the format
 * @argptr:  the variable list of arguments
 *
 * Do a formatted print to an XML buffer.
 *
 * Returns 0 successful, -1 in case of internal or API error.
 */
int
bufferVSprintf(bufferPtr buf, const char *format, ...)
{
    int size, count;
    va_list locarg, argptr;

    if ((format == NULL) || (buf == NULL)) {
        return (-1);
    }
    size = buf->size - buf->use - 1;
    va_start(argptr, format);
    va_copy(locarg, argptr);
    while (((count = vsnprintf(&buf->content[buf->use], size, format,
                               locarg)) < 0) || (count >= size - 1)) {
        buf->content[buf->use] = 0;
        va_end(locarg);
        if (bufferGrow(buf, 1000) < 0) {
            return (-1);
        }
        size = buf->size - buf->use - 1;
        va_copy(locarg, argptr);
    }
    va_end(locarg);
    buf->use += count;
    buf->content[buf->use] = 0;
    return (0);
}

/**
 * bufferStrcat:
 * @buf:  the buffer to dump
 * @argptr:  the variable list of strings, the last argument must be NULL
 *
 * Concatenate strings to an XML buffer.
 *
 * Returns 0 successful, -1 in case of internal or API error.
 */
int
bufferStrcat(bufferPtr buf, ...)
{
    va_list ap;
    char *str;

    va_start(ap, buf);

    while ((str = va_arg(ap, char *)) != NULL) {
        unsigned int len = strlen(str);
        unsigned int needSize = buf->use + len + 2;

        if (needSize > buf->size) {
            if (!bufferGrow(buf, needSize - buf->use))
                return -1;
        }
        memcpy(&buf->content[buf->use], str, len);
        buf->use += len;
        buf->content[buf->use] = 0;
    }
    va_end(ap);
    return 0;
}

/*
 * vim: set tabstop=4:
 * vim: set shiftwidth=4:
 * vim: set expandtab:
 */
/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
