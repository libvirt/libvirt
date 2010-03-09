/* Copyright (C) 2007 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Authors:
 *    Richard W.M. Jones <rjones@redhat.com>
 *
 * Utility functions to help parse and assemble query strings.
 */

#ifndef _QPARAMS_H_
# define _QPARAMS_H_

/* Single web service query parameter 'name=value'. */
struct qparam {
  char *name;			/* Name (unescaped). */
  char *value;			/* Value (unescaped). */
  int ignore;			/* Ignore this field in qparam_get_query */
};

/* Set of parameters. */
struct qparam_set {
  int n;			/* number of parameters used */
  int alloc;			/* allocated space */
  struct qparam *p;		/* array of parameters */
};

/* New parameter set. */
extern struct qparam_set *new_qparam_set (int init_alloc, ...)
    ATTRIBUTE_SENTINEL;

/* Appending parameters. */
extern int append_qparams (struct qparam_set *ps, ...)
    ATTRIBUTE_SENTINEL;
extern int append_qparam (struct qparam_set *ps,
                          const char *name, const char *value);

/* Get a query string ("name=value&name=value&...") */
extern char *qparam_get_query (const struct qparam_set *ps);

/* Parse a query string into a parameter set. */
extern struct qparam_set *qparam_query_parse (const char *query);

extern void free_qparam_set (struct qparam_set *ps);

#endif /* _QPARAMS_H_ */
