/**
 * virsavecookie.h: Save cookie handling
 *
 * Copyright (C) 2017 Red Hat, Inc.
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
#ifndef __VIR_SAVE_COOKIE_H__
# define __VIR_SAVE_COOKIE_H__

# include <libxml/xpath.h>

# include "internal.h"
# include "virobject.h"
# include "virbuffer.h"


typedef int (*virSaveCookieParseFunc)(xmlXPathContextPtr ctxt,
                                      virObjectPtr *obj);
typedef int (*virSaveCookieFormatFunc)(virBufferPtr buf,
                                       virObjectPtr obj);

typedef struct _virSaveCookieCallbacks virSaveCookieCallbacks;
typedef virSaveCookieCallbacks *virSaveCookieCallbacksPtr;
struct _virSaveCookieCallbacks {
    virSaveCookieParseFunc parse;
    virSaveCookieFormatFunc format;
};


int
virSaveCookieParse(xmlXPathContextPtr ctxt,
                   virObjectPtr *obj,
                   virSaveCookieCallbacksPtr saveCookie);

int
virSaveCookieParseString(const char *xml,
                         virObjectPtr *obj,
                         virSaveCookieCallbacksPtr saveCookie);

int
virSaveCookieFormatBuf(virBufferPtr buf,
                       virObjectPtr obj,
                       virSaveCookieCallbacksPtr saveCookie);

char *
virSaveCookieFormat(virObjectPtr obj,
                    virSaveCookieCallbacksPtr saveCookie);

#endif /*__VIR_SAVE_COOKIE_H__ */
