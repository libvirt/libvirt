/*
 * virbuffer.c: buffers for libvirt
 *
 * Copyright (C) 2005-2008, 2010-2015 Red Hat, Inc.
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

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "c-ctype.h"

#define __VIR_BUFFER_C__

#include "virbuffer.h"
#include "viralloc.h"
#include "virerror.h"
#include "virstring.h"


/* If adding more fields, ensure to edit buf.h to match
   the number of fields */
struct _virBuffer {
    unsigned int size;
    unsigned int use;
    unsigned int error; /* errno value, or -1 for usage error */
    int indent;
    char *content;
};

/**
 * virBufferFail
 * @buf: the buffer
 * @error: which error occurred (errno value, or -1 for usage)
 *
 * Mark the buffer as failed, free the content and set the error flag.
 */
static void
virBufferSetError(virBufferPtr buf, int error)
{
    VIR_FREE(buf->content);
    buf->size = 0;
    buf->use = 0;
    buf->indent = 0;
    buf->error = error;
}

/**
 * virBufferAdjustIndent:
 * @buf: the buffer
 * @indent: adjustment to make
 *
 * Alter the auto-indent value by adding indent (positive to increase,
 * negative to decrease).  Automatic indentation is performed by all
 * additive functions when the existing buffer is empty or ends with a
 * newline (however, note that no indentation is added after newlines
 * embedded in an appended string).  If @indent would cause overflow,
 * the buffer error indicator is set.
 */
void
virBufferAdjustIndent(virBufferPtr buf, int indent)
{
    if (!buf || buf->error)
        return;
    if (indent > 0 ? INT_MAX - indent < buf->indent
        : buf->indent < -indent) {
        virBufferSetError(buf, -1);
        return;
    }
    buf->indent += indent;
}


/**
 * virBufferSetIndent:
 * @buf: the buffer
 * @indent: new indentation size.
 *
 * Set the auto-indent value to @indent. See virBufferAdjustIndent on how auto
 * indentation is applied.
 */
void
virBufferSetIndent(virBufferPtr buf, int indent)
{
    if (!buf || buf->error)
        return;

    buf->indent = indent;
}


/**
 * virBufferGetIndent:
 * @buf: the buffer
 * @dynamic: if false, return set value; if true, return 0 unless next
 * append would be affected by auto-indent
 *
 * Return the current auto-indent value, or -1 if there has been an error.
 */
int
virBufferGetIndent(const virBuffer *buf, bool dynamic)
{
    if (!buf || buf->error)
        return -1;
    if (dynamic && buf->use && buf->content[buf->use - 1] != '\n')
        return 0;
    return buf->indent;
}

/**
 * virBufferGrow:
 * @buf: the buffer
 * @len: the minimum free size to allocate on top of existing used space
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

    if (VIR_REALLOC_N_QUIET(buf->content, size) < 0) {
        virBufferSetError(buf, errno);
        return -1;
    }
    buf->size = size;
    return 0;
}

/**
 * virBufferAdd:
 * @buf: the buffer to append to
 * @str: the string
 * @len: the number of bytes to add, or -1
 *
 * Add a string range to an XML buffer. If @len == -1, the length of
 * str is recomputed to the full string.  Auto indentation may be applied.
 *
 */
void
virBufferAdd(virBufferPtr buf, const char *str, int len)
{
    unsigned int needSize;
    int indent;

    if (!str || !buf || (len == 0 && buf->indent == 0))
        return;

    indent = virBufferGetIndent(buf, true);
    if (indent < 0)
        return;

    if (len < 0)
        len = strlen(str);

    needSize = buf->use + indent + len + 2;
    if (virBufferGrow(buf, needSize - buf->use) < 0)
        return;

    memset(&buf->content[buf->use], ' ', indent);
    memcpy(&buf->content[buf->use + indent], str, len);
    buf->use += indent + len;
    buf->content[buf->use] = '\0';
}

/**
 * virBufferAddBuffer:
 * @buf: the buffer to append to
 * @toadd: the buffer to append
 *
 * Add a buffer into another buffer without need to go through:
 * virBufferContentAndReset(), virBufferAdd(). Auto indentation
 * is (intentionally) NOT applied!
 *
 * The @toadd virBuffer is consumed and cleared.
 */
void
virBufferAddBuffer(virBufferPtr buf, virBufferPtr toadd)
{
    if (!toadd)
        return;

    if (!buf)
        goto done;

    if (buf->error || toadd->error) {
        if (!buf->error)
            buf->error = toadd->error;
        goto done;
    }

    if (virBufferGrow(buf, toadd->use) < 0)
        goto done;

    memcpy(&buf->content[buf->use], toadd->content, toadd->use);
    buf->use += toadd->use;
    buf->content[buf->use] = '\0';

 done:
    virBufferFreeAndReset(toadd);
}

/**
 * virBufferAddChar:
 * @buf: the buffer to append to
 * @c: the character to add
 *
 * Add a single character 'c' to a buffer.  Auto indentation may be applied.
 *
 */
void
virBufferAddChar(virBufferPtr buf, char c)
{
    virBufferAdd(buf, &c, 1);
}

/**
 * virBufferCurrentContent:
 * @buf: Buffer
 *
 * Get the current content from the buffer.  The content is only valid
 * until the next operation on @buf, and an empty string is returned if
 * no content is present yet.
 *
 * Returns the buffer content or NULL in case of error.
 */
const char *
virBufferCurrentContent(virBufferPtr buf)
{
    if (!buf || buf->error)
        return NULL;
    return buf->use ? buf->content : "";
}

/**
 * virBufferContentAndReset:
 * @buf: Buffer
 *
 * Get the content from the buffer and free (only) the buffer structure.
 * The caller owns the returned string & should free it when no longer
 * required. The buffer object is reset to its initial state.  This
 * interface intentionally returns NULL instead of an empty string if
 * there is no content.
 *
 * Returns the buffer content or NULL in case of error.
 */
char *
virBufferContentAndReset(virBufferPtr buf)
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
void virBufferFreeAndReset(virBufferPtr buf)
{
    char *str = virBufferContentAndReset(buf);

    VIR_FREE(str);
}

/**
 * virBufferError:
 * @buf: the buffer
 *
 * Check to see if the buffer is in an error state due
 * to failed memory allocation or usage error
 *
 * Return positive errno value or -1 on usage error, 0 if normal
 */
int
virBufferError(const virBuffer *buf)
{
    if (buf == NULL)
        return -1;

    return buf->error;
}

/**
 * virBufferCheckErrorInternal:
 * @buf: the buffer
 *
 * Report an error if the buffer is in an error state.
 *
 * Return -1 if an error has been reported, 0 otherwise.
 */
int
virBufferCheckErrorInternal(const virBuffer *buf,
                            int domcode,
                            const char *filename,
                            const char *funcname,
                            size_t linenr)
{
    if (buf->error == 0)
        return 0;

    if (buf->error == ENOMEM) {
        virReportOOMErrorFull(domcode, filename, funcname, linenr);
        errno = ENOMEM;
    } else {
        virReportErrorHelper(domcode, VIR_ERR_INTERNAL_ERROR, filename,
                             funcname, linenr, "%s",
                             _("Invalid buffer API usage"));
        errno = EINVAL;
    }
    return -1;
}

/**
 * virBufferUse:
 * @buf: the usage of the string in the buffer
 *
 * Return the string usage in bytes
 */
unsigned int
virBufferUse(const virBuffer *buf)
{
    if (buf == NULL)
        return 0;

    return buf->use;
}

/**
 * virBufferAsprintf:
 * @buf: the buffer to append to
 * @format: the format
 * @...: the variable list of arguments
 *
 * Do a formatted print to an XML buffer.  Auto indentation may be applied.
 */
void
virBufferAsprintf(virBufferPtr buf, const char *format, ...)
{
    va_list argptr;
    va_start(argptr, format);
    virBufferVasprintf(buf, format, argptr);
    va_end(argptr);
}

/**
 * virBufferVasprintf:
 * @buf: the buffer to append to
 * @format: the format
 * @argptr: the variable list of arguments
 *
 * Do a formatted print to an XML buffer.  Auto indentation may be applied.
 */
void
virBufferVasprintf(virBufferPtr buf, const char *format, va_list argptr)
{
    int size, count, grow_size;
    va_list copy;

    if ((format == NULL) || (buf == NULL))
        return;

    if (buf->error)
        return;

    virBufferAddLit(buf, ""); /* auto-indent */

    if (buf->size == 0 &&
        virBufferGrow(buf, 100) < 0)
        return;

    va_copy(copy, argptr);

    size = buf->size - buf->use;
    if ((count = vsnprintf(&buf->content[buf->use],
                           size, format, copy)) < 0) {
        virBufferSetError(buf, errno);
        va_end(copy);
        return;
    }
    va_end(copy);

    /* Grow buffer if necessary and retry */
    if (count >= size) {
        buf->content[buf->use] = 0;

        grow_size = (count + 1 > 1000) ? count + 1 : 1000;
        if (virBufferGrow(buf, grow_size) < 0)
            return;

        size = buf->size - buf->use;
        if ((count = vsnprintf(&buf->content[buf->use],
                               size, format, argptr)) < 0) {
            virBufferSetError(buf, errno);
            return;
        }
    }
    buf->use += count;
}


VIR_WARNINGS_NO_WLOGICALOP_STRCHR


/**
 * virBufferEscapeString:
 * @buf: the buffer to append to
 * @format: a printf like format string but with only one %s parameter
 * @str: the string argument which needs to be escaped
 *
 * Do a formatted print with a single string to an XML buffer. The
 * string is escaped for use in XML.  If @str is NULL, nothing is
 * added (not even the rest of @format).  Auto indentation may be
 * applied.
 */
void
virBufferEscapeString(virBufferPtr buf, const char *format, const char *str)
{
    int len;
    char *escaped, *out;
    const char *cur;
    const char forbidden_characters[] = {
        0x01,   0x02,   0x03,   0x04,   0x05,   0x06,   0x07,   0x08,
        /*\t*/  /*\n*/  0x0B,   0x0C,   /*\r*/  0x0E,   0x0F,   0x10,
        0x11,   0x12,   0x13,   0x14,   0x15,   0x16,   0x17,   0x18,
        0x19,   '"',    '&',    '\'',   '<',    '>',
        '\0'
    };

    if ((format == NULL) || (buf == NULL) || (str == NULL))
        return;

    if (buf->error)
        return;

    len = strlen(str);
    if (strcspn(str, forbidden_characters) == len) {
        virBufferAsprintf(buf, format, str);
        return;
    }

    if (xalloc_oversized(6, len) ||
        VIR_ALLOC_N_QUIET(escaped, 6 * len + 1) < 0) {
        virBufferSetError(buf, errno);
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
        } else if (!strchr(forbidden_characters, *cur)) {
            /*
             * default case, just copy !
             * Note that character over 0x80 are likely to give problem
             * with UTF-8 XML, but since our string don't have an encoding
             * it's hard to handle properly we have to assume it's UTF-8 too
             */
            *out++ = *cur;
        } else {
            /* silently ignore control characters */
        }
        cur++;
    }
    *out = 0;

    virBufferAsprintf(buf, format, escaped);
    VIR_FREE(escaped);
}

/**
 * virBufferEscapeSexpr:
 * @buf: the buffer to append to
 * @format: a printf like format string but with only one %s parameter
 * @str: the string argument which needs to be escaped
 *
 * Do a formatted print with a single string to an sexpr buffer. The
 * string is escaped to avoid generating a sexpr that xen will choke
 * on. This doesn't fully escape the sexpr, just enough for our code
 * to work.  Auto indentation may be applied.
 */
void
virBufferEscapeSexpr(virBufferPtr buf,
                     const char *format,
                     const char *str)
{
    virBufferEscape(buf, '\\', "\\'", format, str);
}

/**
 * virBufferEscapeRegex:
 * @buf: the buffer to append to
 * @format: a printf like format string but with only one %s parameter
 * @str: the string argument which needs to be escaped
 *
 * Do a formatted print with a single string to a buffer.  The @str is
 * escaped to avoid using POSIX extended regular expression meta-characters.
 * Escaping is not applied to characters specified in @format. Auto
 * indentation may be applied.
 */
void
virBufferEscapeRegex(virBufferPtr buf,
                     const char *format,
                     const char *str)
{
    virBufferEscape(buf, '\\', "^$.|?*+()[]{}\\", format, str);
}

/**
 * virBufferEscape:
 * @buf: the buffer to append to
 * @escape: the escape character to inject
 * @toescape: NUL-terminated list of characters to escape
 * @format: a printf like format string but with only one %s parameter
 * @str: the string argument which needs to be escaped
 *
 * Do a formatted print with a single string to a buffer.  Any characters
 * in the provided list that are contained in @str are escaped with the
 * given escape.  Escaping is not applied to characters specified in @format.
 * Auto indentation may be applied.
 */
void
virBufferEscape(virBufferPtr buf, char escape, const char *toescape,
                const char *format, const char *str)
{
    int len;
    char *escaped, *out;
    const char *cur;

    if ((format == NULL) || (buf == NULL) || (str == NULL))
        return;

    if (buf->error)
        return;

    len = strlen(str);
    if (strcspn(str, toescape) == len) {
        virBufferAsprintf(buf, format, str);
        return;
    }

    if (xalloc_oversized(2, len) ||
        VIR_ALLOC_N_QUIET(escaped, 2 * len + 1) < 0) {
        virBufferSetError(buf, errno);
        return;
    }

    cur = str;
    out = escaped;
    while (*cur != 0) {
        if (strchr(toescape, *cur))
            *out++ = escape;
        *out++ = *cur;
        cur++;
    }
    *out = 0;

    virBufferAsprintf(buf, format, escaped);
    VIR_FREE(escaped);
}


struct _virBufferEscapePair {
    char escape;
    char *toescape;
};


/**
 * virBufferEscapeN:
 * @buf: the buffer to append to
 * @format: a printf like format string but with only one %s parameter
 * @str: the string argument which needs to be escaped
 * @...: the variable list of escape pairs
 *
 * The variable list of arguments @... must be composed of
 * 'char escape, char *toescape' pairs followed by NULL.
 *
 * This has the same functionality as virBufferEscape with the extension
 * that allows to specify multiple pairs of chars that needs to be escaped.
 */
void
virBufferEscapeN(virBufferPtr buf,
                 const char *format,
                 const char *str,
                 ...)
{
    int len;
    size_t i;
    char *escaped = NULL;
    char *out;
    const char *cur;
    struct _virBufferEscapePair escapeItem;
    struct _virBufferEscapePair *escapeList = NULL;
    size_t nescapeList = 0;
    va_list ap;

    if ((format == NULL) || (buf == NULL) || (str == NULL))
        return;

    if (buf->error)
        return;

    len = strlen(str);

    va_start(ap, str);

    while ((escapeItem.escape = va_arg(ap, int))) {
        if (!(escapeItem.toescape = va_arg(ap, char *))) {
            virBufferSetError(buf, errno);
            goto cleanup;
        }

        if (strcspn(str, escapeItem.toescape) == len)
            continue;

        if (VIR_APPEND_ELEMENT_QUIET(escapeList, nescapeList, escapeItem) < 0) {
            virBufferSetError(buf, errno);
            goto cleanup;
        }
    }

    if (nescapeList == 0) {
        virBufferAsprintf(buf, format, str);
        goto cleanup;
    }

    if (xalloc_oversized(2, len) ||
        VIR_ALLOC_N_QUIET(escaped, 2 * len + 1) < 0) {
        virBufferSetError(buf, errno);
        goto cleanup;
    }

    cur = str;
    out = escaped;
    while (*cur != 0) {
        for (i = 0; i < nescapeList; i++) {
            if (strchr(escapeList[i].toescape, *cur)) {
                *out++ = escapeList[i].escape;
                break;
            }
        }
        *out++ = *cur;
        cur++;
    }
    *out = 0;

    virBufferAsprintf(buf, format, escaped);

 cleanup:
    va_end(ap);
    VIR_FREE(escapeList);
    VIR_FREE(escaped);
}


/**
 * virBufferURIEncodeString:
 * @buf: the buffer to append to
 * @str: the string argument which will be URI-encoded
 *
 * Append the string to the buffer.  The string will be URI-encoded
 * during the append (ie any non alpha-numeric characters are replaced
 * with '%xx' hex sequences).  Auto indentation may be applied.
 */
void
virBufferURIEncodeString(virBufferPtr buf, const char *str)
{
    int grow_size = 0;
    const char *p;
    unsigned char uc;
    const char *hex = "0123456789abcdef";

    if ((buf == NULL) || (str == NULL))
        return;

    if (buf->error)
        return;

    virBufferAddLit(buf, ""); /* auto-indent */

    for (p = str; *p; ++p) {
        if (c_isalnum(*p))
            grow_size++;
        else
            grow_size += 3; /* %ab */
    }

    if (virBufferGrow(buf, grow_size) < 0)
        return;

    for (p = str; *p; ++p) {
        if (c_isalnum(*p)) {
            buf->content[buf->use++] = *p;
        } else {
            uc = (unsigned char) *p;
            buf->content[buf->use++] = '%';
            buf->content[buf->use++] = hex[uc >> 4];
            buf->content[buf->use++] = hex[uc & 0xf];
        }
    }

    buf->content[buf->use] = '\0';
}

/**
 * virBufferEscapeShell:
 * @buf: the buffer to append to
 * @str: an unquoted string
 *
 * Quotes a string so that the shell (/bin/sh) will interpret the
 * quoted string to mean str.  Auto indentation may be applied.
 */
void
virBufferEscapeShell(virBufferPtr buf, const char *str)
{
    int len;
    char *escaped, *out;
    const char *cur;

    if ((buf == NULL) || (str == NULL))
        return;

    if (buf->error)
        return;

    /* Only quote if str includes shell metacharacters. */
    if (*str && !strpbrk(str, "\r\t\n !\"#$&'()*;<>?[\\]^`{|}~")) {
        virBufferAdd(buf, str, -1);
        return;
    }

    if (*str) {
        len = strlen(str);
        if (xalloc_oversized(4, len) ||
            VIR_ALLOC_N_QUIET(escaped, 4 * len + 3) < 0) {
            virBufferSetError(buf, errno);
            return;
        }
    } else {
        virBufferAddLit(buf, "''");
        return;
    }

    cur = str;
    out = escaped;

    *out++ = '\'';
    while (*cur != 0) {
        if (*cur == '\'') {
            *out++ = '\'';
            /* Replace literal ' with a close ', a \', and a open ' */
            *out++ = '\\';
            *out++ = '\'';
        }
        *out++ = *cur++;
    }
    *out++ = '\'';
    *out = 0;

    virBufferAdd(buf, escaped, -1);
    VIR_FREE(escaped);
}

/**
 * virBufferStrcatVArgs:
 * @buf: the buffer to append to
 * @ap: variable argument structure
 *
 * See virBufferStrcat.
 */
void
virBufferStrcatVArgs(virBufferPtr buf,
                     va_list ap)
{
    char *str;

    if (buf->error)
        return;

    while ((str = va_arg(ap, char *)) != NULL)
        virBufferAdd(buf, str, -1);
}

/**
 * virBufferStrcat:
 * @buf: the buffer to append to
 * @...: the variable list of strings, the last argument must be NULL
 *
 * Concatenate strings to an XML buffer.  Auto indentation may be applied
 * after each string argument.
 */
void
virBufferStrcat(virBufferPtr buf, ...)
{
    va_list ap;

    va_start(ap, buf);
    virBufferStrcatVArgs(buf, ap);
    va_end(ap);
}

/**
 * virBufferTrim:
 * @buf: the buffer to trim
 * @str: the optional string, to force an exact trim
 * @len: the number of bytes to trim, or -1 to use @str
 *
 * Trim the tail of a buffer.  If @str is provided, the trim only occurs
 * if the current tail of the buffer matches @str; a non-negative @len
 * further limits how much of the tail is trimmed.  If @str is NULL, then
 * @len must be non-negative.
 *
 * Sets error to -1 (usage) if str is NULL and len is less than zero.
 */
void
virBufferTrim(virBufferPtr buf, const char *str, int len)
{
    size_t len2 = 0;

    if (!buf || buf->error)
        return;
    if (!str && len < 0) {
        virBufferSetError(buf, -1);
        return;
    }

    if (len > 0 && len > buf->use)
        return;
    if (str) {
        len2 = strlen(str);
        if (len2 > buf->use ||
            memcmp(&buf->content[buf->use - len2], str, len2) != 0)
            return;
    }
    buf->use -= len < 0 ? len2 : len;
    buf->content[buf->use] = '\0';
}


/**
 * virBufferAddStr:
 * @buf: the buffer to append to
 * @str: string to append
 *
 * Appends @str to @buffer. Applies autoindentation on the separate lines of
 * @str.
 */
void
virBufferAddStr(virBufferPtr buf,
                const char *str)
{
    const char *end;

    if (!buf || !str || buf->error)
        return;

    while (*str) {
        if ((end = strchr(str, '\n'))) {
            virBufferAdd(buf, str, (end - str) + 1);
            str = end + 1;
        } else {
            virBufferAdd(buf, str, -1);
            break;
        }
    }
}
