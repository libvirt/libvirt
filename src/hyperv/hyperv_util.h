
/*
 * hyperv_util.h: utility functions for the Microsoft Hyper-V driver
 *
 * Copyright (C) 2011 Matthias Bolte <matthias.bolte@googlemail.com>
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
 */

#ifndef __HYPERV_UTIL_H__
# define __HYPERV_UTIL_H__

# include "internal.h"
# include "viruri.h"

typedef struct _hypervParsedUri hypervParsedUri;

struct _hypervParsedUri {
    char *transport;
};

int hypervParseUri(hypervParsedUri **parsedUri, virURIPtr uri);

void hypervFreeParsedUri(hypervParsedUri **parsedUri);

#endif /* __HYPERV_UTIL_H__ */
