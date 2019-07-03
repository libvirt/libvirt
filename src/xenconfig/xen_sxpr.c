/*
 * xen_sxpr.c: Xen SEXPR parsing functions
 *
 * Copyright (C) 2010-2016 Red Hat, Inc.
 * Copyright (C) 2011 Univention GmbH
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
 */

#include <config.h>

#include "internal.h"
#include "virerror.h"
#include "virconf.h"
#include "viralloc.h"
#include "viruuid.h"
#include "virlog.h"
#include "count-one-bits.h"
#include "xenxs_private.h"
#include "xen_sxpr.h"
#include "virstoragefile.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_SEXPR

VIR_LOG_INIT("xenconfig.xen_sxpr");

/* Get a domain id from a S-expression string */
int xenGetDomIdFromSxprString(const char *sexpr, int *id)
{
    struct sexpr *root = string2sexpr(sexpr);
    int ret;

    *id = -1;

    if (!root)
        return -1;

    ret = xenGetDomIdFromSxpr(root, id);
    sexpr_free(root);
    return ret;
}

/* Get a domain id from a S-expression */
int xenGetDomIdFromSxpr(const struct sexpr *root, int *id)
{
    const char * tmp = sexpr_node(root, "domain/domid");

    *id = tmp ? sexpr_int(root, "domain/domid") : -1;
    return 0;
}
