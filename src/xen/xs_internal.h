/*
 * xs_internal.h: internal API for access to XenStore
 *
 * Copyright (C) 2006, 2010-2012 Red Hat, Inc.
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
 *
 * Daniel Veillard <veillard@redhat.com>
 */

#ifndef __VIR_XS_INTERNAL_H__
# define __VIR_XS_INTERNAL_H__

# include "internal.h"
# include "driver.h"

int		xenStoreOpen		(virConnectPtr conn,
                                         virConnectAuthPtr auth,
                                         unsigned int flags);
int		xenStoreClose		(virConnectPtr conn);
int		xenStoreNumOfDomains	(virConnectPtr conn);
int		xenStoreListDomains	(virConnectPtr conn,
                                         int *ids,
                                         int maxids);

int             xenStoreDomainGetVNCPort(virConnectPtr conn,
                                         int domid);
char *          xenStoreDomainGetConsolePath(virConnectPtr conn,
                                         int domid);
char *          xenStoreDomainGetSerialConsolePath(virConnectPtr conn,
                                         int domid);
char *		xenStoreDomainGetNetworkID(virConnectPtr conn,
                                         int id,
                                         const char *mac);
char *		xenStoreDomainGetDiskID(virConnectPtr conn,
                                         int id,
                                         const char *dev);
char *		xenStoreDomainGetPCIID(virConnectPtr conn,
                                   int domid,
                                   const char *bdf);
char *          xenStoreDomainGetName(virConnectPtr conn,
                                      int id);
int             xenStoreDomainGetUUID(virConnectPtr conn,
                                      int id,
                                      unsigned char *uuid);

typedef int (*xenStoreWatchCallback)(virConnectPtr conn,
                                     const char *path,
                                     const char *token,
                                     void *opaque);

struct _xenStoreWatch {
    char *path;
    char *token;
    xenStoreWatchCallback cb;
    void *opaque;
};
typedef struct _xenStoreWatch xenStoreWatch;
typedef xenStoreWatch *xenStoreWatchPtr;

struct _xenStoreWatchList {
    size_t count;
    xenStoreWatchPtr *watches;
};
typedef struct _xenStoreWatchList xenStoreWatchList;
typedef xenStoreWatchList *xenStoreWatchListPtr;


int             xenStoreAddWatch(virConnectPtr conn,
                                 const char *path,
                                 const char *token,
                                 xenStoreWatchCallback cb,
                                 void *opaque);
int             xenStoreRemoveWatch(virConnectPtr conn,
                                    const char *path,
                                    const char *token);

/* domain events */
int xenStoreDomainIntroduced(virConnectPtr conn,
                             const char *path,
                             const char *token,
                             void *opaque);
int xenStoreDomainReleased(virConnectPtr conn,
                            const char *path,
                            const char *token,
                            void *opaque);

int xenStoreDomainEventEmitted(virDomainEventType evt);
#endif /* __VIR_XS_INTERNAL_H__ */
