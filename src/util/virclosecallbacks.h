/*
 * virclosecallbacks.h: Connection close callbacks routines
 *
 * Copyright (C) 2013 Red Hat, Inc.
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
 * Authors:
 *      Daniel P. Berrange <berrange@redhat.com>
 *      Michal Privoznik <mprivozn@redhat.com>
 */

#ifndef __VIR_CLOSE_CALLBACKS__
# define __VIR_CLOSE_CALLBACKS__

# include "conf/virdomainobjlist.h"

typedef struct _virCloseCallbacks virCloseCallbacks;
typedef virCloseCallbacks *virCloseCallbacksPtr;

typedef virDomainObjPtr (*virCloseCallback)(virDomainObjPtr vm,
                                            virConnectPtr conn,
                                            void *opaque);
virCloseCallbacksPtr virCloseCallbacksNew(void);
int virCloseCallbacksSet(virCloseCallbacksPtr closeCallbacks,
                         virDomainObjPtr vm,
                         virConnectPtr conn,
                         virCloseCallback cb);
int virCloseCallbacksUnset(virCloseCallbacksPtr closeCallbacks,
                           virDomainObjPtr vm,
                           virCloseCallback cb);
virCloseCallback
virCloseCallbacksGet(virCloseCallbacksPtr closeCallbacks,
                     virDomainObjPtr vm,
                     virConnectPtr conn);
virConnectPtr
virCloseCallbacksGetConn(virCloseCallbacksPtr closeCallbacks,
                         virDomainObjPtr vm);
void
virCloseCallbacksRun(virCloseCallbacksPtr closeCallbacks,
                     virConnectPtr conn,
                     virDomainObjListPtr domains,
                     void *opaque);
#endif /* __VIR_CLOSE_CALLBACKS__ */
