/*
 * sexpr.h : S-Expression interfaces needed to communicate with the Xen Daemon
 *
 * Copyright (C) 2005
 *
 *      Anthony Liguori <aliguori@us.ibm.com>
 *
 *  This file is subject to the terms and conditions of the GNU Lesser General
 *  Public License. See the file COPYING.LIB in the main directory of this
 *  archive for more details.
 */

#ifndef _LIBVIR_SEXPR_H_
#define _LIBVIR_SEXPR_H_

#include "internal.h"

#include <sys/types.h>

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
        };
        char *value;
    };
};

/* conversion to/from strings */
size_t sexpr2string(struct sexpr *sexpr, char *buffer, size_t n_buffer);
struct sexpr *string2sexpr(const char *buffer);

/* constructors and destructors */
struct sexpr *sexpr_nil(void);
struct sexpr *sexpr_string(const char *str, ssize_t len);
struct sexpr *sexpr_cons(struct sexpr *car, struct sexpr *cdr);
struct sexpr *sexpr_append(struct sexpr *lst, struct sexpr *item);
void sexpr_free(struct sexpr *sexpr);

/* lookup in S-Expressions */
const char *sexpr_node(struct sexpr *sexpr, const char *node);
const char *sexpr_fmt_node(struct sexpr *sexpr, const char *fmt, ...)
  ATTRIBUTE_FORMAT(printf,2,3);
struct sexpr *sexpr_lookup(struct sexpr *sexpr, const char *node);
#endif
