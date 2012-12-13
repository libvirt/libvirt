/*
 * virsexpr.h : S-Expression interfaces needed to communicate with the Xen Daemon
 *
 * Copyright (C) 2012 Red Hat, Inc.
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

#ifndef _LIBVIR_SEXPR_H_
# define _LIBVIR_SEXPR_H_

# include "internal.h"
# include "virbuffer.h"

enum sexpr_type {
    SEXPR_NIL,
    SEXPR_CONS,
    SEXPR_VALUE,
};

struct sexpr {
    enum sexpr_type kind;
    union {
        struct {
            struct sexpr *car;
            struct sexpr *cdr;
        } s;
        char *value;
    } u;
};

/* conversion to/from strings */
int sexpr2string(const struct sexpr *sexpr, virBufferPtr buffer);
struct sexpr *string2sexpr(const char *buffer);

/* constructors and destructors */
struct sexpr *sexpr_nil(void);
struct sexpr *sexpr_string(const char *str, ssize_t len);
struct sexpr *sexpr_cons(const struct sexpr *car, const struct sexpr *cdr);
struct sexpr *sexpr_append(struct sexpr *lst, const struct sexpr *item);
void sexpr_free(struct sexpr *sexpr);

/* lookup in S-Expressions */
const char *sexpr_node(const struct sexpr *sexpr, const char *node);
int sexpr_node_copy(const struct sexpr *sexpr, const char *node, char **dst);
const char *sexpr_fmt_node(const struct sexpr *sexpr, const char *fmt, ...)
  ATTRIBUTE_FMT_PRINTF(2,3);
struct sexpr *sexpr_lookup(const struct sexpr *sexpr, const char *node);
int sexpr_has(const struct sexpr *sexpr, const char *node);

int sexpr_int(const struct sexpr *sexpr, const char *name);
double sexpr_float(const struct sexpr *sexpr, const char *name);
uint64_t sexpr_u64(const struct sexpr *sexpr, const char *name);

#endif
