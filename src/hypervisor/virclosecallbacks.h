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

#pragma once

#include "conf/virdomainobjlist.h"

typedef struct _virCloseCallbacks virCloseCallbacks;

typedef void (*virCloseCallback)(virDomainObj *vm,
                                 virConnectPtr conn);

virCloseCallbacks *
virCloseCallbacksNew(void);

int
virCloseCallbacksSet(virCloseCallbacks *closeCallbacks,
                     virDomainObj *vm,
                     virConnectPtr conn,
                     virCloseCallback cb);
int
virCloseCallbacksUnset(virCloseCallbacks *closeCallbacks,
                       virDomainObj *vm,
                       virCloseCallback cb);

virCloseCallback
virCloseCallbacksGet(virCloseCallbacks *closeCallbacks,
                     virDomainObj *vm,
                     virConnectPtr conn);
virConnectPtr
virCloseCallbacksGetConn(virCloseCallbacks *closeCallbacks,
                         virDomainObj *vm);

void
virCloseCallbacksRun(virCloseCallbacks *closeCallbacks,
                     virConnectPtr conn,
                     virDomainObjList *domains);
