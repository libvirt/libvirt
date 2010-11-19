/*
 * buf.c: buffers for libvirt
 *
 * Copyright (C) 2005-2008, 2010 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Daniel Veillard <veillard@redhat.com>
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "c-ctype.h"

#define __VIR_BUFFER_C__

#include "buf.h"
#include "memory.h"


/* If adding more fields, ensure to edit buf.h to match
   the number of fields */
struct _virBuffer {
    unsigned int size;
    unsigned int use;
    unsigned int error;
    char *content;
};

/**
 * virBufferFail
 * @buf: the buffer
 *
 * Mark the buffer has having failed a memory allocation,
 * freeing the content and setting the error flag.
 */
static void
virBufferNoMemory(const virBufferPtr buf)
{
    VIR_FREE(buf->content);
    buf->size = 0;
    buf->use = 0;
    buf->error = 1;
}

/**
 * virBufferGrow:
 * @buf:  the buffer
 * @len:  the minimum free size to allocate on top of existing used space
 *
 * Grow the available space of a buffer to at least @len bytes.
 *
 * Returns zero on success or -1 on error
 */
static int
virBufferGrow(virBufferPtr buf, unsigned int len)
{
    int size;

    if (buf->error)
        return -1;

    if ((len + buf->use) < buf->size)
        return 0;

    size = buf->use + len + 1000;

    if (VIR_REALLOC_N(buf->content, size) < 0) {
        virBufferNoMemory(buf);
        return -1;
    }
    buf->size = size;
    return 0;
}

/**
 * virBufferAdd:
 * @buf:  the buffer to add to
 * @str:  the string
 * @len:  the number of bytes to add
 *
 * Add a string range to an XML buffer. if len == -1, the length of
 * str is recomputed to the full string.
 *
 */
void
virBufferAdd(const virBufferPtr buf, const char *str, int len)
{
    unsigned int needSize;

    if ((str == NULL) || (buf == NULL) || (len == 0))
        return;

    if (buf->error)
        return;

    if (len < 0)
        len = strlen(str);

    needSize = buf->use + len + 2;
    if (needSize > buf->size &&
        virBufferGrow(buf, needSize - buf->use) < 0)
        return;

    memcpy (&buf->content[buf->use], str, len);
    buf->use += len;
    buf->content[buf->use] = '\0';
}

/**
 * virBufferAddChar:
 * @buf: the buffer to add to
 * @c: the character to add
 *
 * Add a single character 'c' to a buffer.
 *
 */
void
virBufferAddChar (virBufferPtr buf, char c)
{
    unsigned int needSize;

    if (buf == NULL)
        return;

    if (buf->error)
        return;

    needSize = buf->use + 2;
    if (needSize > buf->size &&
        virBufferGrow (buf, needSize - buf->use) < 0)
        return;

    buf->content[buf->use++] = c;
    buf->content[buf->use] = '\0';
}

/**
 * virBufferContentAndReset:
 * @buf: Buffer
 *
 * Get the content from the buffer and free (only) the buffer structure.
 * The caller owns the returned string & should free it when no longer
 * required. The buffer object is reset to its initial state.
 *
 * Returns the buffer content or NULL in case of error.
 */
char *
virBufferContentAndReset(const virBufferPtr buf)
{
    char *str;
    if (buf == NULL)
        return NULL;

    if (buf->error) {
        memset(buf, 0, sizeof(*buf));
        return NULL;
    }

    str = buf->content;
    memset(buf, 0, sizeof(*buf));
    return str;
}

/**
 * virBufferFreeAndReset:
 * @buf: the buffer to free and reset
 *
 * Frees the buffer content and resets the buffer structure.
 */
void virBufferFreeAndReset(const virBufferPtr buf)
{
    char *str = virBufferContentAndReset(buf);

    VIR_FREE(str);
}

/**
 * virBufferError:
 * @buf: the buffer
 *
 * Check to see if the buffer is in an error state due
 * to failed memory allocation
 *
 * Return true if in error, 0 if normal
 */
int
virBufferError(const virBufferPtr buf)
{
    if (buf == NULL)
        return 1;

    return buf->error;
}

/**
 * virBufferUse:
 * @buf: the usage of the string in the buffer
 *
 * Return the string usage in bytes
 */
unsigned int
virBufferUse(const virBufferPtr buf)
{
    if (buf == NULL)
        return 0;

    return buf->use;
}

/**
 * virBufferVSprintf:
 * @buf:  the buffer to dump
 * @format:  the format
 * @...:  the variable list of arguments
 *
 * Do a formatted print to an XML buffer.
 */
void
virBufferVSprintf(const virBufferPtr buf, const char *format, ...)
{
    int size, count, grow_size;
    va_list argptr;

    if ((format == NULL) || (buf == NULL))
        return;

    if (buf->error)
        return;

    if (buf->size == 0 &&
        virBufferGrow(buf, 100) < 0)
        return;

    va_start(argptr, format);

    size = buf->size - buf->use;
    if ((count = vsnprintf(&buf->content[buf->use],
                           size, format, argptr)) < 0) {
        buf->error = 1;
        goto err;
    }

    /* Grow buffer if necessary and retry */
    if (count >= size) {
        buf->content[buf->use] = 0;
        va_end(argptr);
        va_start(argptr, format);

        grow_size = (count + 1 > 1000) ? count + 1 : 1000;
        if (virBufferGrow(buf, grow_size) < 0) {
            goto err;
        }

        size = buf->size - buf->use;
        if ((count = vsnprintf(&buf->content[buf->use],
                               size, format, argptr)) < 0) {
            buf->error = 1;
            goto err;
        }
    }
    buf->use += count;

err:
    va_end(argptr);
    return;
}

/**
 * virBufferEscapeString:
 * @buf:  the buffer to dump
 * @format: a printf like format string but with only one %s parameter
 * @str:  the string argument which need to be escaped
 *
 * Do a formatted print with a single string to an XML buffer. The string
 * is escaped to avoid generating a not well-formed XML instance.
 */
void
virBufferEscapeString(const virBufferPtr buf, const char *format, const char *str)
{
    int len;
    char *escaped, *out;
    const char *cur;

    if ((format == NULL) || (buf == NULL) || (str == NULL))
        return;

    if (buf->error)
        return;

    len = strlen(str);
    if (strcspn(str, "<>&'\"") == len) {
        virBufferVSprintf(buf, format, str);
        return;
    }

    if (VIR_ALLOC_N(escaped, 6 * len + 1) < 0) {
        virBufferNoMemory(buf);
        return;
    }

    cur = str;
    out = escaped;
    while (*cur != 0) {
        if (*cur == '<') {
            *out++ = '&';
            *out++ = 'l';
            *out++ = 't';
            *out++ = ';';
        } else if (*cur == '>') {
            *out++ = '&';
            *out++ = 'g';
            *out++ = 't';
            *out++ = ';';
        } else if (*cur == '&') {
            *out++ = '&';
            *out++ = 'a';
            *out++ = 'm';
            *out++ = 'p';
            *out++ = ';';
        } else if (*cur == '"') {
            *out++ = '&';
            *out++ = 'q';
            *out++ = 'u';
            *out++ = 'o';
            *out++ = 't';
            *out++ = ';';
        } else if (*cur == '\'') {
            *out++ = '&';
            *out++ = 'a';
            *out++ = 'p';
            *out++ = 'o';
            *out++ = 's';
            *out++ = ';';
        } else if (((unsigned char)*cur >= 0x20) || (*cur == '\n') || (*cur == '\t') ||
                   (*cur == '\r')) {
            /*
             * default case, just copy !
             * Note that character over 0x80 are likely to give problem
             * with UTF-8 XML, but since our string don't have an encoding
             * it's hard to handle properly we have to assume it's UTF-8 too
             */
            *out++ = *cur;
        }
        cur++;
    }
    *out = 0;

    virBufferVSprintf(buf, format, escaped);
    VIR_FREE(escaped);
}

/**
 * virBufferEscapeSexpr:
 * @buf:  the buffer to dump
 * @format: a printf like format string but with only one %s parameter
 * @str:  the string argument which need to be escaped
 *
 * Do a formatted print with a single string to an sexpr buffer. The string
 * is escaped to avoid generating a sexpr that xen will choke on. This
 * doesn't fully escape the sexpr, just enough for our code to work.
 */
void
virBufferEscapeSexpr(const virBufferPtr buf,
                     const char *format,
                     const char *str)
{
    int len;
    char *escaped, *out;
    const char *cur;

    if ((format == NULL) || (buf == NULL) || (str == NULL))
        return;

    if (buf->error)
        return;

    len = strlen(str);
    if (strcspn(str, "\\'") == len) {
        virBufferVSprintf(buf, format, str);
        return;
    }

    if (VIR_ALLOC_N(escaped, 2 * len + 1) < 0) {
        virBufferNoMemory(buf);
        return;
    }

    cur = str;
    out = escaped;
    while (*cur != 0) {
        switch (*cur) {
        case '\\':
        case '\'':
            *out++ = '\\';
            /* fallthrough */
        default:
            *out++ = *cur;
        }
        cur++;
    }
    *out = 0;

    virBufferVSprintf(buf, format, escaped);
    VIR_FREE(escaped);
}

/**
 * virBufferURIEncodeString:
 * @buf:  the buffer to append to
 * @str:  the string argument which will be URI-encoded
 *
 * Append the string to the buffer.  The string will be URI-encoded
 * during the append (ie any non alpha-numeric characters are replaced
 * with '%xx' hex sequences).
 */
void
virBufferURIEncodeString (virBufferPtr buf, const char *str)
{
    int grow_size = 0;
    const char *p;
    unsigned char uc;
    const char *hex = "0123456789abcdef";

    if ((buf == NULL) || (str == NULL))
        return;

    if (buf->error)
        return;

    for (p = str; *p; ++p) {
        if (c_isalnum(*p))
            grow_size++;
        else
            grow_size += 3; /* %ab */
    }

    if (virBufferGrow (buf, grow_size) < 0)
        return;

    for (p = str; *p; ++p) {
        if (c_isalnum(*p))
            buf->content[buf->use++] = *p;
        else {
            uc = (unsigned char) *p;
            buf->content[buf->use++] = '%';
            buf->content[buf->use++] = hex[uc >> 4];
            buf->content[buf->use++] = hex[uc & 0xf];
        }
    }

    buf->content[buf->use] = '\0';
}

/**
 * virBufferStrcat:
 * @buf:  the buffer to dump
 * @...:  the variable list of strings, the last argument must be NULL
 *
 * Concatenate strings to an XML buffer.
 */
void
virBufferStrcat(virBufferPtr buf, ...)
{
    va_list ap;
    char *str;

    if (buf->error)
        return;

    va_start(ap, buf);

    while ((str = va_arg(ap, char *)) != NULL) {
        unsigned int len = strlen(str);
        unsigned int needSize = buf->use + len + 2;

        if (needSize > buf->size) {
            if (virBufferGrow(buf, needSize - buf->use) < 0)
                break;
        }
        memcpy(&buf->content[buf->use], str, len);
        buf->use += len;
        buf->content[buf->use] = 0;
    }
    va_end(ap);
}
