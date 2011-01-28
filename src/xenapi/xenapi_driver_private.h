/*
 * xenapi_driver_private.h: Xen API driver's private header file.
 * Copyright (C) 2009, 2010 Citrix Ltd.
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
 * Author: Sharadha Prabhakar <sharadha.prabhakar@citrix.com>
 */


#ifndef __VIR_XENAPI_H__
# define __VIR_XENAPI_H__

# include <libxml/tree.h>
# include <xen/api/xen_common.h>
# include "virterror_internal.h"

/*# define PRINT_XML*/
# define VIR_FROM_THIS VIR_FROM_XENAPI
# define LIBVIRT_MODELNAME_LEN  (32)
# define xenapiSessionErrorHandler(conn, errNum, buf) \
    xenapiSessionErrorHandle(conn, errNum, buf, \
                             __FILE__, __FUNCTION__, __LINE__)

void
xenapiSessionErrorHandle(virConnectPtr conn, virErrorNumber errNum,
                         const char *buf, const char *filename,
                         const char *func, size_t lineno);

typedef struct
{
    xen_result_func func;
    void *handle;
} xen_comms;


int
call_func(const void *data, size_t len, void *user_handle,
          void *result_handle, xen_result_func result_func);
size_t
write_func(void *ptr, size_t size, size_t nmemb, void *comms);

/* xenAPI driver's private data structure */
struct _xenapiPrivate {
    xen_session *session;
    char *url;
    int noVerify;
    virCapsPtr caps;
};

#endif /* __VIR_XENAPI_H__ */
