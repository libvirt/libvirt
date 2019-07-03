/*
 * xen_sxpr.h: Xen SEXPR parsing functions
 *
 * Copyright (C) 2006-2008, 2010, 2012 Red Hat, Inc.
 * Copyright (C) 2011 Univention GmbH
 * Copyright (C) 2005,2006
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

#pragma once

#include "internal.h"
#include "virconf.h"
#include "domain_conf.h"
#include "virsexpr.h"

/* helper functions to get the dom id from a sexpr */
int xenGetDomIdFromSxprString(const char *sexpr, int *id);
int xenGetDomIdFromSxpr(const struct sexpr *root, int *id);

virDomainChrDefPtr xenParseSxprChar(const char *value, const char *tty);

int xenParseSxprVifRate(const char *rate, unsigned long long *kbytes_per_sec);
