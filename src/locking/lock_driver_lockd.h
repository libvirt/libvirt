/*
 * lock_driver_lockd.h: Locking for domain lifecycle operations
 *
 * Copyright (C) 2010-2011 Red Hat, Inc.
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
 */

#ifndef __VIR_LOCK_DRIVER_LOCKD_H__
# define __VIR_LOCK_DRIVER_LOCKD_H__

enum virLockSpaceProtocolAcquireResourceFlags {
        VIR_LOCK_SPACE_PROTOCOL_ACQUIRE_RESOURCE_SHARED = 1,
        VIR_LOCK_SPACE_PROTOCOL_ACQUIRE_RESOURCE_AUTOCREATE = 2,
};

#endif /* __VIR_LOCK_DRIVER_LOCKD_H__ */
