/*
 * storage_event.h: storage event queue processing helpers
 *
 * Copyright (C) 2010-2014 Red Hat, Inc.
 * Copyright (C) 2008 VirtualIron
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
*/

#ifndef LIBVIRT_STORAGE_EVENT_H
# define LIBVIRT_STORAGE_EVENT_H

# include "internal.h"
# include "object_event.h"
# include "object_event_private.h"

int
virStoragePoolEventStateRegisterID(virConnectPtr conn,
                                   virObjectEventStatePtr state,
                                   virStoragePoolPtr pool,
                                   int eventID,
                                   virConnectStoragePoolEventGenericCallback cb,
                                   void *opaque,
                                   virFreeCallback freecb,
                                   int *callbackID)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(5)
    ATTRIBUTE_NONNULL(8);

int
virStoragePoolEventStateRegisterClient(virConnectPtr conn,
                                   virObjectEventStatePtr state,
                                   virStoragePoolPtr pool,
                                   int eventID,
                                   virConnectStoragePoolEventGenericCallback cb,
                                   void *opaque,
                                   virFreeCallback freecb,
                                   int *callbackID)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(5)
    ATTRIBUTE_NONNULL(8);

virObjectEventPtr
virStoragePoolEventLifecycleNew(const char *name,
                                const unsigned char *uuid,
                                int type,
                                int detail);

virObjectEventPtr
virStoragePoolEventRefreshNew(const char *name,
                              const unsigned char *uuid);

#endif /* LIBVIRT_STORAGE_EVENT_H */
