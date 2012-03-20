/*
 * viruri.h: internal definitions used for URI parsing.
 *
 * Copyright (C) 2012 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 */

#ifndef __VIR_URI_H__
# define __VIR_URI_H__

# include <libxml/uri.h>

# include "internal.h"

typedef xmlURI    virURI;
typedef xmlURIPtr virURIPtr;

virURIPtr virURIParse(const char *uri)
    ATTRIBUTE_NONNULL(1);
char *virURIFormat(virURIPtr uri)
    ATTRIBUTE_NONNULL(1);

void virURIFree(virURIPtr uri);

#endif /* __VIR_URI_H__ */
