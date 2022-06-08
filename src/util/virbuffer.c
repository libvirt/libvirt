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
 */

#include <config.h>

#include <stdarg.h>

#include "virbuffer.h"

#define VIR_FROM_THIS VIR_FROM_NONE

/**
 * virBufferAdjustIndent:
 * @buf: the buffer
 * @indent: adjustment to make
 *
 * Alter the auto-indent value by adding indent (positive to increase,
 * negative to decrease).  Automatic indentation is performed by all
 * additive functions when the existing buffer is empty or ends with a
 * newline (however, note that no indentation is added after newlines
 * embedded in an appended string).  If @indent would cause overflow, the
 * indentation level is truncated.
 */
void
virBufferAdjustIndent(virBuffer *buf, int indent)
{
    if (!buf)
        return;

    if (indent > 0) {
        if (INT_MAX - indent < buf->indent) {
            buf->indent = INT_MAX;
            return;
        }
    } else {
        if (buf->indent < -indent) {
            buf->indent = 0;
            return;
        }
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
virBufferSetIndent(virBuffer *buf, int indent)
{
    if (!buf)
        return;

    buf->indent = indent;
}


/**
 * virBufferGetIndent:
 * @buf: the buffer
 *
 * Return the current auto-indent setting of @buf.
 */
size_t
virBufferGetIndent(const virBuffer *buf)
{
    return buf->indent;
}


/**
 * virBufferGetEffectiveIndent:
 * @buf: the buffer
 *
 * Returns the number of spaces that need to be appended to @buf to honour
 * auto-indentation.
 */
size_t
virBufferGetEffectiveIndent(const virBuffer *buf)
{
    if (buf->str && buf->str->len && buf->str->str[buf->str->len - 1] != '\n')
        return 0;

    return buf->indent;
}


/**
 * virBufferInitialize
 * @buf: the buffer
 *
 * Ensures that the internal GString container is allocated.
 */
static void
virBufferInitialize(virBuffer *buf)
{
    if (!buf->str)
        buf->str = g_string_new(NULL);
}


static void
virBufferApplyIndent(virBuffer *buf)
{
    const char space[] = "                               ";
    size_t spacesz = sizeof(space) - 1;
    size_t toindent = virBufferGetEffectiveIndent(buf);

    if (toindent == 0)
        return;

    while (toindent > spacesz) {
        g_string_append_len(buf->str, space, spacesz);
        toindent -= spacesz;
    }

    g_string_append_len(buf->str, space, toindent);
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
virBufferAdd(virBuffer *buf, const char *str, int len)
{
    if (!str || !buf)
        return;

    virBufferInitialize(buf);
    virBufferApplyIndent(buf);

    if (len < 0)
        g_string_append(buf->str, str);
    else
        g_string_append_len(buf->str, str, len);
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
virBufferAddBuffer(virBuffer *buf, virBuffer *toadd)
{
    if (!toadd || !toadd->str)
        return;

    if (buf) {
        virBufferInitialize(buf);
        g_string_append_len(buf->str, toadd->str->str, toadd->str->len);
    }

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
virBufferAddChar(virBuffer *buf, char c)
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
virBufferCurrentContent(virBuffer *buf)
{
    if (!buf)
        return NULL;

    if (!buf->str ||
        buf->str->len == 0)
        return "";

    return buf->str->str;
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
virBufferContentAndReset(virBuffer *buf)
{
    char *str = NULL;

    if (!buf)
        return NULL;

    if (buf->str)
        str = g_string_free(buf->str, false);

    memset(buf, 0, sizeof(*buf));
    return str;
}

/**
 * virBufferFreeAndReset:
 * @buf: the buffer to free and reset
 *
 * Frees the buffer content and resets the buffer structure.
 */
void virBufferFreeAndReset(virBuffer *buf)
{
    if (!buf)
        return;

    if (buf->str)
        g_string_free(buf->str, true);

    memset(buf, 0, sizeof(*buf));
}

/**
 * virBufferUse:
 * @buf: the usage of the string in the buffer
 *
 * Return the string usage in bytes
 */
size_t
virBufferUse(const virBuffer *buf)
{
    if (!buf || !buf->str)
        return 0;

    return buf->str->len;
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
virBufferAsprintf(virBuffer *buf, const char *format, ...)
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
virBufferVasprintf(virBuffer *buf, const char *format, va_list argptr)
{
    if ((format == NULL) || (buf == NULL))
        return;

    virBufferInitialize(buf);
    virBufferApplyIndent(buf);

    g_string_append_vprintf(buf->str, format, argptr);
}


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
virBufferEscapeString(virBuffer *buf, const char *format, const char *str)
{
    int len;
    g_autofree char *escaped = NULL;
    char *out;
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

    len = strlen(str);
    if (strcspn(str, forbidden_characters) == len) {
        virBufferAsprintf(buf, format, str);
        return;
    }

    escaped = g_malloc0_n(len + 1, 6);

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
virBufferEscapeSexpr(virBuffer *buf,
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
virBufferEscapeRegex(virBuffer *buf,
                     const char *format,
                     const char *str)
{
    virBufferEscape(buf, '\\', "^$.|?*+()[]{}\\", format, str);
}


/**
 * virBufferEscapeSQL:
 * @buf: the buffer to append to
 * @format: a printf like format string but with only one %s parameter
 * @str: the string argument which needs to be escaped
 *
 * Do a formatted print with a single string to a buffer.  The @str is
 * escaped to prevent SQL injection (format is expected to contain \"%s\").
 * Auto indentation may be applied.
 */
void
virBufferEscapeSQL(virBuffer *buf,
                   const char *format,
                   const char *str)
{
    virBufferEscape(buf, '\\', "'\"\\", format, str);
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
virBufferEscape(virBuffer *buf, char escape, const char *toescape,
                const char *format, const char *str)
{
    int len;
    g_autofree char *escaped = NULL;
    char *out;
    const char *cur;

    if ((format == NULL) || (buf == NULL) || (str == NULL))
        return;

    len = strlen(str);
    if (strcspn(str, toescape) == len) {
        virBufferAsprintf(buf, format, str);
        return;
    }

    escaped = g_malloc0_n(len + 1, 2);

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
}


/**
 * virBufferURIEncodeString:
 * @buf: the buffer to append to
 * @str: the string argument which will be URI-encoded
 *
 * Append the string to the buffer.  The string will be URI-encoded
 * during the append (ie any non alphanumeric characters are replaced
 * with '%xx' hex sequences).  Auto indentation may be applied.
 */
void
virBufferURIEncodeString(virBuffer *buf, const char *str)
{
    if ((buf == NULL) || (str == NULL))
        return;

    virBufferInitialize(buf);
    virBufferApplyIndent(buf);

    g_string_append_uri_escaped(buf->str, str, NULL, false);
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
virBufferEscapeShell(virBuffer *buf, const char *str)
{
    g_autofree char *escaped = NULL;
    char *out;
    const char *cur;

    if ((buf == NULL) || (str == NULL))
        return;

    if (!*str) {
        virBufferAddLit(buf, "''");
        return;
    }

    /* Only quote if str includes shell metacharacters. */
    if (!strpbrk(str, "\r\t\n !\"#$&'()*;<>?[\\]^`{|}~")) {
        virBufferAdd(buf, str, -1);
        return;
    }

    escaped = g_malloc0_n(strlen(str) + 1, 4);

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
}

/**
 * virBufferStrcatVArgs:
 * @buf: the buffer to append to
 * @ap: variable argument structure
 *
 * See virBufferStrcat.
 */
void
virBufferStrcatVArgs(virBuffer *buf,
                     va_list ap)
{
    char *str;

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
virBufferStrcat(virBuffer *buf, ...)
{
    va_list ap;

    if (!buf)
        return;

    va_start(ap, buf);
    virBufferStrcatVArgs(buf, ap);
    va_end(ap);
}

/**
 * virBufferTrim:
 * @buf: the buffer to trim
 * @str: the string to be trimmed from the tail
 *
 * Trim the supplied string from the tail of the buffer.
 */
void
virBufferTrim(virBuffer *buf, const char *str)
{
    size_t len = 0;

    if (!buf || !buf->str)
        return;

    if (!str)
        return;

    len = strlen(str);

    if (len > buf->str->len ||
        memcmp(&buf->str->str[buf->str->len - len], str, len) != 0)
        return;

    g_string_truncate(buf->str, buf->str->len - len);
}

/**
 * virBufferTrimChars:
 * @buf: the buffer to trim
 * @trim: the characters to be trimmed
 *
 * Trim the tail of the buffer. The longest string that can be formed with
 * the characters from @trim is trimmed.
 */
void
virBufferTrimChars(virBuffer *buf, const char *trim)
{
    ssize_t i;

    if (!buf || !buf->str)
        return;

    if (!trim)
        return;

    for (i = buf->str->len - 1; i > 0; i--) {
        if (!strchr(trim, buf->str->str[i]))
            break;
    }

    g_string_truncate(buf->str, i + 1);
}

/**
 * virBufferTrimLen:
 * @buf: the buffer to trim
 * @len: the number of bytes to trim
 *
 * Trim the tail of a buffer.
 */
void
virBufferTrimLen(virBuffer *buf, int len)
{
    if (!buf || !buf->str)
        return;

    if (len > buf->str->len)
        return;

    g_string_truncate(buf->str, buf->str->len - len);
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
virBufferAddStr(virBuffer *buf,
                const char *str)
{
    const char *end;

    if (!buf || !str)
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
