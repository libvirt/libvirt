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
 */

#ifndef LIBVIRT_VIRCLOSECALLBACKS_H
# define LIBVIRT_VIRCLOSECALLBACKS_H

# include "conf/virdomainobjlist.h"

typedef struct _virCloseCallbacks virCloseCallbacks;
typedef virCloseCallbacks *virCloseCallbacksPtr;

typedef void (*virCloseCallback)(virDomainObjPtr vm,
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
#endif /* LIBVIRT_VIRCLOSECALLBACKS_H */
