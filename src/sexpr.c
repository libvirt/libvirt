/*
 * sexpr.c : S-Expression routines to communicate with the Xen Daemon
 *
 * Copyright (C) 2005
 *
 *      Anthony Liguori <aliguori@us.ibm.com>
 *
 *  This file is subject to the terms and conditions of the GNU Lesser General
 *  Public License. See the file COPYING.LIB in the main directory of this
 *  archive for more details.
 */

#define _GNU_SOURCE /* for strndup */

#include "sexpr.h"
#include "internal.h"

#include <malloc.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>

/**
 * virSexprError:
 * @conn: the connection if available
 * @error: the error noumber
 * @info: extra information string
 *
 * Handle an error in the S-Expression code
 */
static void
virSexprError(virErrorNumber error, const char *info)
{
    const char *errmsg;

    if (error == VIR_ERR_OK)
        return;

    errmsg = __virErrorMsg(error, info);
    __virRaiseError(NULL, NULL, NULL, VIR_FROM_SEXPR, error, VIR_ERR_ERROR,
                    errmsg, info, NULL, 0, 0, errmsg, info);
}

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

    ret = (struct sexpr *) malloc(sizeof(*ret));
    if (ret == NULL) {
        virSexprError(VIR_ERR_NO_MEMORY, _("failed to allocate a node"));
        return (NULL);
    }
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
            free(sexpr->u.value);
            break;
        case SEXPR_NIL:
            break;
    }

    free(sexpr);

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
    if (len > 0) {
        ret->u.value = strndup(str, len);
    } else {
        ret->u.value = strdup(str);
    }

    if (ret->u.value == NULL) {
        return NULL;
    }

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
sexpr_cons(struct sexpr *car, struct sexpr *cdr)
{
    struct sexpr *ret = sexpr_new();

    if (ret == NULL)
        return ret;
    ret->kind = SEXPR_CONS;
    ret->u.s.car = car;
    ret->u.s.cdr = cdr;

    return ret;
}

/**
 * append:
 * @lst: an existing list
 * @value: the value
 *
 * Internal operation appending a value at the end of an existing list
 */
static void
append(struct sexpr *lst, struct sexpr *value)
{
    while (lst->kind != SEXPR_NIL) {
        lst = lst->u.s.cdr;
    }

    lst->kind = SEXPR_CONS;
    lst->u.s.car = value;
    lst->u.s.cdr = sexpr_nil();
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
sexpr_append(struct sexpr *lst, struct sexpr *value)
{
    if (lst == NULL)
        return (NULL);
    if (value == NULL)
        return (lst);
    append(lst, value);
    return (lst);
}

/**
 * sexpr2string:
 * @sexpr: an S-Expression pointer
 * @buffer: the output buffer
 * @n_buffer: the size of the buffer in bytes
 *
 * Serialize the S-Expression in the buffer.
 * Note that the output may be truncated if @n_buffer is too small
 * resulting in an unparseable value.
 *
 * Returns the number of bytes used by the serialization in the buffer or
 *         0 in case of error.
 */
size_t
sexpr2string(struct sexpr * sexpr, char *buffer, size_t n_buffer)
{
    size_t ret = 0, tmp;

    if ((sexpr == NULL) || (buffer == NULL) || (n_buffer <= 0))
        return (0);

    switch (sexpr->kind) {
        case SEXPR_CONS:
            tmp = snprintf(buffer + ret, n_buffer - ret, "(");
            if (tmp == 0)
                goto error;
            ret += tmp;
            tmp = sexpr2string(sexpr->u.s.car, buffer + ret, n_buffer - ret);
            if (tmp == 0)
                goto error;
            ret += tmp;
            while (sexpr->u.s.cdr->kind != SEXPR_NIL) {
                sexpr = sexpr->u.s.cdr;
                tmp = snprintf(buffer + ret, n_buffer - ret, " ");
                if (tmp == 0)
                    goto error;
                ret += tmp;
                tmp =
                    sexpr2string(sexpr->u.s.car, buffer + ret, n_buffer - ret);
                if (tmp == 0)
                    goto error;
                ret += tmp;
            }
            tmp = snprintf(buffer + ret, n_buffer - ret, ")");
            if (tmp == 0)
                goto error;
            ret += tmp;
            break;
        case SEXPR_VALUE:
            if (strchr(sexpr->u.value, ' '))
                tmp = snprintf(buffer + ret, n_buffer - ret, "'%s'",
                               sexpr->u.value);
            else
                tmp = snprintf(buffer + ret, n_buffer - ret, "%s",
                               sexpr->u.value);
            if (tmp == 0)
                goto error;
            ret += tmp;
            break;
        case SEXPR_NIL:
            break;
        default:
            goto error;
    }

    return (ret);
  error:
    buffer[n_buffer - 1] = 0;
    virSexprError(VIR_ERR_SEXPR_SERIAL, buffer);
    return (0);
}

#define IS_SPACE(c) ((c == 0x20) || (c == 0x9) || (c == 0xD) || (c == 0xA))

static const char *
trim(const char *string)
{
    while (IS_SPACE(*string))
        string++;
    return (string);
}

/**
 * _string2sexpr:
 * @buffer: a zero terminated buffer containing an S-Expression in UTF-8
 * @end: pointer to an index in the buffer for the already parsed bytes
 *
 * Internal routine implementing the parse of S-Expression
 * Note that failure in this function is catrosphic.  If it returns
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
                return NULL;
            append(ret, tmp);
#if 0
            if (0) {
                char buf[4096];

                sexpr2string(ret, buf, sizeof(buf));
                printf("%s\n", buffer);
            }
#endif
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

            ret->u.value = strndup(start, ptr - start);
            if (ret->u.value == NULL) {
                virSexprError(VIR_ERR_NO_MEMORY,
                              _("failed to copy a string"));
            }

            if (*ptr == '\'')
                ptr++;
        } else {
            start = ptr;

            while (*ptr && !isspace(*ptr) && *ptr != ')' && *ptr != '(') {
                ptr++;
            }

            ret->u.value = strndup(start, ptr - start);
            if (ret->u.value == NULL) {
                virSexprError(VIR_ERR_NO_MEMORY,
                              _("failed to copy a string"));
            }
        }

        ret->kind = SEXPR_VALUE;
        if (ret->u.value == NULL)
            goto error;
    }

    *end = ptr - buffer;

    return ret;

  error:
    sexpr_free(ret);
    return (NULL);
}

/**
 * string2sexpr:
 * @buffer: a zero terminated buffer containing an S-Expression in UTF-8
 *
 * Parse the S-Expression in the buffer.
 * Note that failure in this function is catrosphic.  If it returns
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
sexpr_lookup_key(struct sexpr *sexpr, const char *node)
{
    char buffer[4096], *ptr, *token;

    if ((node == NULL) || (sexpr == NULL))
        return (NULL);

    snprintf(buffer, sizeof(buffer), "%s", node);

    ptr = buffer;
    token = strsep(&ptr, "/");

    if (sexpr->kind != SEXPR_CONS || sexpr->u.s.car->kind != SEXPR_VALUE) {
        return NULL;
    }

    if (strcmp(sexpr->u.s.car->u.value, token) != 0) {
        return NULL;
    }

    for (token = strsep(&ptr, "/"); token; token = strsep(&ptr, "/")) {
        struct sexpr *i;

        if (token == NULL)
            continue;

        sexpr = sexpr->u.s.cdr;
        for (i = sexpr; i->kind != SEXPR_NIL; i = i->u.s.cdr) {
            if (i->kind != SEXPR_CONS ||
                i->u.s.car->kind != SEXPR_CONS ||
                i->u.s.car->u.s.car->kind != SEXPR_VALUE) {
                continue;
            }

            if (strcmp(i->u.s.car->u.s.car->u.value, token) == 0) {
                sexpr = i->u.s.car;
                break;
            }
        }

        if (i->kind == SEXPR_NIL) {
            break;
        }
    }

    if (token != NULL) {
        return NULL;
    }

    return sexpr;
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
sexpr_lookup(struct sexpr *sexpr, const char *node)
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
sexpr_has(struct sexpr *sexpr, const char *node)
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
sexpr_node(struct sexpr *sexpr, const char *node)
{
    struct sexpr *n = sexpr_lookup(sexpr, node);

    return (n && n->u.s.car->kind == SEXPR_VALUE) ? n->u.s.car->u.value : NULL;
}

/**
 * sexpr_fmt_node:
 * @sexpr: a pointer to a parsed S-Expression
 * @fmt: a path for the node to lookup in the S-Expression
 * @... extra data to build the path
 *
 * Search a node value in the S-Expression based on its path
 * NOTE: path are limited to 4096 bytes.
 *
 * Returns the value of the node or NULL if not found.
 */
const char *
sexpr_fmt_node(struct sexpr *sexpr, const char *fmt, ...)
{
    va_list ap;
    char node[4096];

    va_start(ap, fmt);
    vsnprintf(node, sizeof(node), fmt, ap);
    va_end(ap);

    return sexpr_node(sexpr, node);
}
