/*
 * buf.c: buffers for libvirt
 *
 * Copyright (C) 2005-2007 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Daniel Veillard <veillard@redhat.com>
 */

#include <config.h>

#include "libvirt/libvirt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>

#include "buf.h"

/**
 * virBufferGrow:
 * @buf:  the buffer
 * @len:  the minimum free size to allocate on top of existing used space
 *
 * Grow the available space of a buffer to at least @len bytes.
 *
 * Returns the new available space or -1 in case of error
 */
static int
virBufferGrow(virBufferPtr buf, unsigned int len)
{
    int size;
    char *newbuf;

    if (buf == NULL)
        return (-1);
    if (len + buf->use < buf->size)
        return (0);

    size = buf->use + len + 1000;

    newbuf = realloc(buf->content, size);
    if (newbuf == NULL) return -1;
    buf->content = newbuf;
    buf->size = size;
    return (buf->size - buf->use);
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
 * Returns 0 successful, -1 in case of internal or API error.
 */
int
__virBufferAdd(virBufferPtr buf, const char *str, int len)
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
        if (!virBufferGrow(buf, needSize - buf->use)) {
            return (-1);
        }
    }

    memcpy (&buf->content[buf->use], str, len);
    buf->use += len;
    buf->content[buf->use] = 0;
    return (0);
}

/**
 * virBufferAddChar:
 * @buf: the buffer to add to
 * @c: the character to add
 *
 * Add a single character 'c' to a buffer.
 *
 * Returns 0 if successful, -1 in the case of error.
 */
int
__virBufferAddChar (virBufferPtr buf, char c)
{
    unsigned int needSize;

    if (buf == NULL)
        return -1;

    needSize = buf->use + 2;
    if (needSize > buf->size)
        if (!virBufferGrow (buf, needSize - buf->use))
            return -1;

    buf->content[buf->use++] = c;
    buf->content[buf->use] = 0;

    return 0;
}

/**
 * virBufferNew:
 * @size:  creation size in bytes
 *
 * Creates a new buffer
 *
 * Returns a pointer to the buffer or NULL in case of error
 */
virBufferPtr
virBufferNew(unsigned int size)
{
    virBufferPtr buf;

    if (!(buf = malloc(sizeof(*buf)))) return NULL;
    if (size && (buf->content = malloc(size))==NULL) {
        free(buf);
        return NULL;
    }
    buf->size = size;
    buf->use = 0;

    return buf;
}

/**
 * virBufferFree:
 * @buf: the buffer to deallocate
 *
 * Free the set of resources used by a buffer.
 */

void
virBufferFree(virBufferPtr buf)
{
    if (buf) {
        free(buf->content);
        free(buf);
    }
}

/**
 * virBufferContentAndFree:
 * @buf: Buffer
 *
 * Get the content from the buffer and free (only) the buffer structure.
 *
 * Returns the buffer content or NULL in case of error.
 */
char *
virBufferContentAndFree (virBufferPtr buf)
{
    char *content;

    if (buf == NULL)
        return(NULL);

    content = buf->content;
    if (content != NULL)
        content[buf->use] = 0;

    free (buf);
    return(content);
}

/**
 * virBufferVSprintf:
 * @buf:  the buffer to dump
 * @format:  the format
 * @...:  the variable list of arguments
 *
 * Do a formatted print to an XML buffer.
 *
 * Returns 0 successful, -1 in case of internal or API error.
 */
int
__virBufferVSprintf(virBufferPtr buf, const char *format, ...)
{
    int size, count, grow_size;
    va_list locarg, argptr;

    if ((format == NULL) || (buf == NULL)) {
        return (-1);
    }

    if (buf->size == 0 &&
        virBufferGrow(buf, 100) < 0)
        return -1;

    size = buf->size - buf->use - 1;
    va_start(argptr, format);
    va_copy(locarg, argptr);
    while (((count = vsnprintf(&buf->content[buf->use], size, format,
                               locarg)) < 0) || (count >= size - 1)) {
        buf->content[buf->use] = 0;
        va_end(locarg);
        grow_size = (count > 1000) ? count : 1000;
        if (virBufferGrow(buf, grow_size) < 0) {
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
 * virBufferEscapeString:
 * @buf:  the buffer to dump
 * @format: a printf like format string but with only one %s parameter
 * @str:  the string argument which need to be escaped
 *
 * Do a formatted print with a single string to an XML buffer. The string
 * is escaped to avoid generating a not well-formed XML instance.
 *
 * Returns 0 successful, -1 in case of internal or API error.
 */
int
virBufferEscapeString(virBufferPtr buf, const char *format, const char *str)
{
    int size, count, len, grow_size;
    char *escaped, *out;
    const char *cur;

    if ((format == NULL) || (buf == NULL) || (str == NULL)) {
        return (-1);
    }

    len = strlen(str);
    escaped = malloc(5 * len + 1);
    if (escaped == NULL) {
        return (-1);
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
	} else if ((*cur >= 0x20) || (*cur == '\n') || (*cur == '\t') ||
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

    size = buf->size - buf->use - 1;
    while (((count = snprintf(&buf->content[buf->use], size, format,
                              (char *)escaped)) < 0) || (count >= size - 1)) {
        buf->content[buf->use] = 0;
        grow_size = (count > 1000) ? count : 1000;
        if (virBufferGrow(buf, grow_size) < 0) {
	    free(escaped);
            return (-1);
        }
        size = buf->size - buf->use - 1;
    }
    buf->use += count;
    buf->content[buf->use] = 0;
    free(escaped);
    return (0);
}

/**
 * virBufferURIEncodeString:
 * @buf:  the buffer to append to
 * @str:  the string argument which will be URI-encoded
 *
 * Append the string to the buffer.  The string will be URI-encoded
 * during the append (ie any non alpha-numeric characters are replaced
 * with '%xx' hex sequences).
 *
 * Returns 0 successful, -1 in case of internal or API error.
 */
int
virBufferURIEncodeString (virBufferPtr buf, const char *str)
{
    int grow_size = 0;
    const char *p;
    unsigned char uc;
    const char *hex = "0123456789abcdef";

    for (p = str; *p; ++p) {
        /* This may not work on EBCDIC. */
        if ((*p >= 'a' && *p <= 'z') ||
            (*p >= 'A' && *p <= 'Z') ||
            (*p >= '0' && *p <= '9'))
            grow_size++;
        else
            grow_size += 3; /* %ab */
    }

    if (virBufferGrow (buf, grow_size) == -1)
        return -1;

    for (p = str; *p; ++p) {
        /* This may not work on EBCDIC. */
        if ((*p >= 'a' && *p <= 'z') ||
            (*p >= 'A' && *p <= 'Z') ||
            (*p >= '0' && *p <= '9'))
            buf->content[buf->use++] = *p;
        else {
            uc = (unsigned char) *p;
            buf->content[buf->use++] = '%';
            buf->content[buf->use++] = hex[uc >> 4];
            buf->content[buf->use++] = hex[uc & 0xf];
        }
    }

    buf->content[buf->use] = '\0';
    return 0;
}

/**
 * virBufferStrcat:
 * @buf:  the buffer to dump
 * @...:  the variable list of strings, the last argument must be NULL
 *
 * Concatenate strings to an XML buffer.
 *
 * Returns 0 successful, -1 in case of internal or API error.
 */
int
virBufferStrcat(virBufferPtr buf, ...)
{
    va_list ap;
    char *str;

    va_start(ap, buf);

    while ((str = va_arg(ap, char *)) != NULL) {
        unsigned int len = strlen(str);
        unsigned int needSize = buf->use + len + 2;

        if (needSize > buf->size) {
            if (!virBufferGrow(buf, needSize - buf->use))
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
