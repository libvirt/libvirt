/*
 * network_event.h: network event queue processing helpers
 *
 * Copyright (C) 2014 Red Hat, Inc.
 * Copyright (C) 2013 SUSE LINUX Products GmbH, Nuernberg, Germany.
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
 * Author: Cedric Bosdonnat
 */

#include "internal.h"
#include "object_event.h"
#include "object_event_private.h"

#ifndef __NETWORK_EVENT_H__
# define __NETWORK_EVENT_H__

int
virNetworkEventStateRegisterID(virConnectPtr conn,
                               virObjectEventStatePtr state,
                               virNetworkPtr net,
                               int eventID,
                               virConnectNetworkEventGenericCallback cb,
                               void *opaque,
                               virFreeCallback freecb,
                               int *callbackID)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(5)
    ATTRIBUTE_NONNULL(8);

int
virNetworkEventStateRegisterClient(virConnectPtr conn,
                                   virObjectEventStatePtr state,
                                   virNetworkPtr net,
                                   int eventID,
                                   virConnectNetworkEventGenericCallback cb,
                                   void *opaque,
                                   virFreeCallback freecb,
                                   int *callbackID)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(5)
    ATTRIBUTE_NONNULL(8);

virObjectEventPtr
virNetworkEventLifecycleNew(const char *name,
                            const unsigned char *uuid,
                            int type,
                            int detail);

#endif
