/*
 * viruri.h: internal definitions used for URI parsing.
 *
 * Copyright (C) 2012 Red Hat, Inc.
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

#ifndef __VIR_URI_H__
# define __VIR_URI_H__

# include <libxml/uri.h>

# include "internal.h"
# include "virconf.h"

typedef struct _virURI virURI;
typedef virURI *virURIPtr;

typedef struct _virURIParam virURIParam;
typedef virURIParam *virURIParamPtr;

struct _virURIParam {
    char *name;  /* Name (unescaped). */
    char *value; /* Value (unescaped). */
    bool ignore; /* Ignore this field in virURIFormatParams */
};

struct _virURI {
    char *scheme;       /* the URI scheme */
    char *server;       /* the server part */
    char *user;         /* the user part */
    unsigned int port;  /* the port number */
    char *path;         /* the path string */
    char *query;        /* the query string */
    char *fragment;     /* the fragment string */

    size_t paramsCount;
    size_t paramsAlloc;
    virURIParamPtr params;
};

virURIPtr virURIParse(const char *uri)
    ATTRIBUTE_NONNULL(1);
char *virURIFormat(virURIPtr uri)
    ATTRIBUTE_NONNULL(1);

char *virURIFormatParams(virURIPtr uri);

void virURIFree(virURIPtr uri);
int virURIResolveAlias(virConfPtr conf, const char *alias, char **uri);

# define VIR_URI_SERVER(uri) ((uri) && (uri)->server ? (uri)->server : "localhost")

#endif /* __VIR_URI_H__ */
