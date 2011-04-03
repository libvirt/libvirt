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
# define _LIBVIR_SEXPR_H_

# include "internal.h"
# include "buf.h"

# include <sys/types.h>
# include <stdint.h>

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
