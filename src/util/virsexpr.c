/*
 * virsexpr.c : S-Expression routines to communicate with the Xen Daemon
 *
 * Copyright (C) 2010-2011 Red Hat, Inc.
 * Copyright (C) 2005 Anthony Liguori <aliguori@us.ibm.com>
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
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "c-ctype.h"
#include <errno.h>

#include "virerror.h"
#include "virsexpr.h"
#include "viralloc.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_SEXPR


/**
 * sexpr_new:
 *
 * Create a new S-Expression
 *
 * Returns the new node or NULL in case of memory allocation error
 */
static struct sexpr *
sexpr_new(void)
{
    struct sexpr *ret;

    if (VIR_ALLOC(ret) < 0)
        return NULL;
    ret->kind = SEXPR_NIL;
    return ret;
}

/**
 * sexpr_free:
 * @sexpr: the S-Expression pointer
 *
 * Free an S-Expression
 */
void
sexpr_free(struct sexpr *sexpr)
{
    int serrno = errno;

    if (sexpr == NULL) {
        return;
    }

    switch (sexpr->kind) {
        case SEXPR_CONS:
            sexpr_free(sexpr->u.s.car);
            sexpr_free(sexpr->u.s.cdr);
            break;
        case SEXPR_VALUE:
            VIR_FREE(sexpr->u.value);
            break;
        case SEXPR_NIL:
            break;
    }

    VIR_FREE(sexpr);

    errno = serrno;
}

/**
 * sexpr_nil:
 *
 * Provide a NIL S-Expression (the pointer is not shared so NIL equality
 * testing won't work at the pointer level).
 *
 * Returns a new NIL S-Expression of NULL in case of error.
 */
struct sexpr *
sexpr_nil(void)
{
    return sexpr_new();
}

/**
 * sexpr_string:
 * @str:  the input string, assumed to be UTF-8
 * @len:  the length in bytes of the input
 *
 * Parse the input S-Expression and return a pointer to the result
 *
 * Returns the S-Expression pointer or NULL in case of error
 */
struct sexpr *
sexpr_string(const char *str, ssize_t len)
{
    struct sexpr *ret = sexpr_new();

    if (ret == NULL)
        return ret;
    ret->kind = SEXPR_VALUE;

    if (VIR_STRNDUP(ret->u.value, str, len) < 0)
        VIR_FREE(ret);

    return ret;
}

/**
 * sexpr_cons:
 * @car: the left operand
 * @cdr: the right operand
 *
 * Implement the CONS operation assembling 2 existing S-Expressions.
 * Note that in case of error the input data are not freed.
 *
 * Returns the resulting S-Expression pointer or NULL in case of error.
 */
struct sexpr *
sexpr_cons(const struct sexpr *car, const struct sexpr *cdr)
{
    struct sexpr *ret = sexpr_new();

    if (ret == NULL)
        return ret;
    ret->kind = SEXPR_CONS;
    ret->u.s.car = (struct sexpr *) car;
    ret->u.s.cdr = (struct sexpr *) cdr;

    return ret;
}

/**
 * append:
 * @lst: an existing list
 * @value: the value
 *
 * Internal operation appending a value at the end of an existing list
 */
static int
append(struct sexpr *lst, const struct sexpr *value)
{
    struct sexpr *nil = sexpr_nil();

    if (nil == NULL)
        return -1;

    while (lst->kind != SEXPR_NIL) {
        lst = lst->u.s.cdr;
    }

    lst->kind = SEXPR_CONS;
    lst->u.s.car = (struct sexpr *) value;
    lst->u.s.cdr = nil;

    return 0;
}

/**
 * @lst: an existing list
 * @value: the value
 *
 * Append a value at the end of an existing list
 *
 * Returns lst or NULL in case of error
 */
struct sexpr *
sexpr_append(struct sexpr *lst, const struct sexpr *value)
{
    if (lst == NULL)
        return NULL;
    if (value == NULL)
        return lst;
    if (append(lst, value) < 0)
        return NULL;
    return lst;
}

/**
 * sexpr2string:
 * @sexpr: an S-Expression pointer
 * @buffer: the output buffer
 *
 * Serialize the S-Expression in the buffer.
 *
 * Returns 0 on success, -1 on error.
 */
int
sexpr2string(const struct sexpr *sexpr, virBufferPtr buffer)
{
    if ((sexpr == NULL) || (buffer == NULL))
        return -1;

    switch (sexpr->kind) {
    case SEXPR_CONS:
        virBufferAddChar(buffer, '(');

        if (sexpr2string(sexpr->u.s.car, buffer) < 0)
            return -1;

        while (sexpr->u.s.cdr->kind != SEXPR_NIL) {
            sexpr = sexpr->u.s.cdr;

            virBufferAddChar(buffer, ' ');

            if (sexpr2string(sexpr->u.s.car, buffer) < 0)
                return -1;
        }

        virBufferAddChar(buffer, ')');
        break;
    case SEXPR_VALUE:
        if (strchr(sexpr->u.value, ' ') ||
            strchr(sexpr->u.value, ')') ||
            strchr(sexpr->u.value, '('))
            virBufferAsprintf(buffer, "'%s'", sexpr->u.value);
        else
            virBufferAdd(buffer, sexpr->u.value, -1);

        break;
    case SEXPR_NIL:
        virBufferAddLit(buffer, "()");
        break;
    default:
        virReportError(VIR_ERR_SEXPR_SERIAL,
                       _("unknown s-expression kind %d"), sexpr->kind);
        return -1;
    }

    return 0;
}

#define IS_SPACE(c) ((c == 0x20) || (c == 0x9) || (c == 0xD) || (c == 0xA))

static const char *
trim(const char *string)
{
    while (IS_SPACE(*string))
        string++;
    return string;
}

/**
 * _string2sexpr:
 * @buffer: a zero terminated buffer containing an S-Expression in UTF-8
 * @end: pointer to an index in the buffer for the already parsed bytes
 *
 * Internal routine implementing the parse of S-Expression
 * Note that failure in this function is catastrophic.  If it returns
 * NULL, you've leaked memory and you're currently OOM.  It will always
 * parse an SEXPR given a buffer
 *
 * Returns a pointer to the resulting parsed S-Expression, or NULL in case of
 *         hard error.
 */
static struct sexpr *
_string2sexpr(const char *buffer, size_t * end)
{
    const char *ptr = buffer + *end;
    struct sexpr *ret = sexpr_new();

    if (ret == NULL)
        return NULL;

    ptr = trim(ptr);

    if (ptr[0] == '(') {
        ret->kind = SEXPR_NIL;

        ptr = trim(ptr + 1);
        while (*ptr && *ptr != ')') {
            struct sexpr *tmp;
            size_t tmp_len = 0;

            tmp = _string2sexpr(ptr, &tmp_len);
            if (tmp == NULL)
                goto error;
            if (append(ret, tmp) < 0) {
                sexpr_free(tmp);
                goto error;
            }
            ptr = trim(ptr + tmp_len);
        }

        if (*ptr == ')') {
            ptr++;
        }
    } else {
        const char *start;

        if (*ptr == '\'') {
            ptr++;
            start = ptr;

            while (*ptr && *ptr != '\'') {
                if (*ptr == '\\' && ptr[1])
                    ptr++;
                ptr++;
            }

            if (VIR_STRNDUP(ret->u.value, start, ptr - start) < 0)
                goto error;

            if (*ptr == '\'')
                ptr++;
        } else {
            start = ptr;

            while (*ptr && !c_isspace(*ptr)
                   && *ptr != ')' && *ptr != '(') {
                ptr++;
            }

            if (VIR_STRNDUP(ret->u.value, start, ptr - start) < 0)
                goto error;
        }

        ret->kind = SEXPR_VALUE;
        if (ret->u.value == NULL)
            goto error;
    }

    *end = ptr - buffer;

    return ret;

 error:
    sexpr_free(ret);
    return NULL;
}

/**
 * string2sexpr:
 * @buffer: a zero terminated buffer containing an S-Expression in UTF-8
 *
 * Parse the S-Expression in the buffer.
 * Note that failure in this function is catastrophic.  If it returns
 * NULL, you've leaked memory and you're currently OOM.  It will always
 * parse an SEXPR given a buffer
 *
 * Returns a pointer to the resulting parsed S-Expression, or NULL in case of
 *         hard error.
 */
struct sexpr *
string2sexpr(const char *buffer)
{
    size_t dummy = 0;

    return _string2sexpr(buffer, &dummy);
}


/**
 * sexpr_lookup_key:
 * @sexpr: a pointer to a parsed S-Expression
 * @node: a path for the sub expression to lookup in the S-Expression
 *
 * Search a sub expression in the S-Expression based on its path
 * Returns the key node, rather than the data node.
 * NOTE: path are limited to 4096 bytes.
 *
 * Returns the pointer to the sub expression or NULL if not found.
 */
static struct sexpr *
sexpr_lookup_key(const struct sexpr *sexpr, const char *node)
{
    struct sexpr *result = NULL;
    char *buffer, *ptr, *token;

    if ((node == NULL) || (sexpr == NULL))
        return NULL;

    if (VIR_STRDUP(buffer, node) < 0)
        return NULL;

    ptr = buffer;
    token = strsep(&ptr, "/");

    if (sexpr->kind != SEXPR_CONS || sexpr->u.s.car->kind != SEXPR_VALUE) {
        goto cleanup;
    }

    if (STRNEQ(sexpr->u.s.car->u.value, token)) {
        goto cleanup;
    }

    for (token = strsep(&ptr, "/"); token; token = strsep(&ptr, "/")) {
        const struct sexpr *i;

        sexpr = sexpr->u.s.cdr;
        for (i = sexpr; i->kind != SEXPR_NIL; i = i->u.s.cdr) {
            if (i->kind != SEXPR_CONS ||
                i->u.s.car->kind != SEXPR_CONS ||
                i->u.s.car->u.s.car->kind != SEXPR_VALUE) {
                continue;
            }

            if (STREQ(i->u.s.car->u.s.car->u.value, token)) {
                sexpr = i->u.s.car;
                break;
            }
        }

        if (i->kind == SEXPR_NIL) {
            break;
        }
    }

    if (token != NULL) {
        goto cleanup;
    }

    result = (struct sexpr *) sexpr;

 cleanup:
    VIR_FREE(buffer);

    return result;
}

/**
 * sexpr_lookup:
 * @sexpr: a pointer to a parsed S-Expression
 * @node: a path for the sub expression to lookup in the S-Expression
 *
 * Search a sub expression in the S-Expression based on its path.
 * NOTE: path are limited to 4096 bytes.
 *
 * Returns the pointer to the sub expression or NULL if not found.
 */
struct sexpr *
sexpr_lookup(const struct sexpr *sexpr, const char *node)
{
    struct sexpr *s = sexpr_lookup_key(sexpr, node);

    if (s == NULL)
        return NULL;

    if (s->kind != SEXPR_CONS || s->u.s.cdr->kind != SEXPR_CONS)
        return NULL;

    return s->u.s.cdr;
}

/**
 * sexpr_has:
 * @sexpr: a pointer to a parsed S-Expression
 * @node: a path for the sub expression to lookup in the S-Expression
 *
 * Search a sub expression in the S-Expression based on its path.
 * NOTE: path are limited to 4096 bytes.
 * NB, even if the key was found sexpr_lookup may return NULL if
 * the corresponding value was empty
 *
 * Returns true if the key was found, false otherwise
 */
int
sexpr_has(const struct sexpr *sexpr, const char *node)
{
    struct sexpr *s = sexpr_lookup_key(sexpr, node);

    if (s == NULL)
        return 0;

    if (s->kind != SEXPR_CONS)
        return 0;

    return 1;
}

/**
 * sexpr_node:
 * @sexpr: a pointer to a parsed S-Expression
 * @node: a path for the node to lookup in the S-Expression
 *
 * Search a node value in the S-Expression based on its path
 * NOTE: path are limited to 4096 bytes.
 *
 * Returns the value of the node or NULL if not found.
 */
const char *
sexpr_node(const struct sexpr *sexpr, const char *node)
{
    struct sexpr *n = sexpr_lookup(sexpr, node);

    return (n && n->u.s.car->kind == SEXPR_VALUE) ? n->u.s.car->u.value : NULL;
}

int sexpr_node_copy(const struct sexpr *sexpr, const char *node, char **dst)
{
    const char *val = sexpr_node(sexpr, node);

    if (val && *val)
        return VIR_STRDUP(*dst, val) < 0 ? -1 : 0;

    *dst = NULL;
    return 0;
}


/**
 * sexpr_fmt_node:
 * @sexpr: a pointer to a parsed S-Expression
 * @fmt: a path for the node to lookup in the S-Expression
 * @... extra data to build the path
 *
 * Search a node value in the S-Expression based on its path
 *
 * Returns the value of the node or NULL if not found.
 */
const char *
sexpr_fmt_node(const struct sexpr *sexpr, const char *fmt, ...)
{
    int result;
    va_list ap;
    char *node;
    const char *value;

    va_start(ap, fmt);
    result = virVasprintf(&node, fmt, ap);
    va_end(ap);

    if (result < 0) {
        return NULL;
    }

    value = sexpr_node(sexpr, node);

    VIR_FREE(node);

    return value;
}

/**
 * sexpr_int:
 * @sexpr: an S-Expression
 * @name: the name for the value
 *
 * convenience function to lookup an int value in the S-Expression
 *
 * Returns the value found or 0 if not found (but may not be an error).
 * This function suffers from the flaw that zero is both a correct
 * return value and an error indicator: careful!
 */
int
sexpr_int(const struct sexpr *sexpr, const char *name)
{
    const char *value = sexpr_node(sexpr, name);

    if (value) {
        return strtol(value, NULL, 0);
    }
    return 0;
}


/**
 * sexpr_float:
 * @sexpr: an S-Expression
 * @name: the name for the value
 *
 * convenience function to lookup a float value in the S-Expression
 *
 * Returns the value found or 0 if not found (but may not be an error)
 */
double
sexpr_float(const struct sexpr *sexpr, const char *name)
{
    const char *value = sexpr_node(sexpr, name);

    if (value) {
        return strtod(value, NULL);
    }
    return 0;
}

/**
 * sexpr_u64:
 * @sexpr: an S-Expression
 * @name: the name for the value
 *
 * convenience function to lookup a 64bits unsigned int value in the
 * S-Expression
 *
 * Returns the value found or 0 if not found (but may not be an error)
 */
uint64_t
sexpr_u64(const struct sexpr *sexpr, const char *name)
{
    const char *value = sexpr_node(sexpr, name);

    if (value) {
        return strtoll(value, NULL, 0);
    }
    return 0;
}
