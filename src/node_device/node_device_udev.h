/*
 * node_device_udev.h: node device enumeration - libudev implementation
 *
 * Copyright (C) 2009-2010 Red Hat, Inc.
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
 * Author: Dave Allan <dallan@redhat.com>
 */

#include <libudev.h>
#include <stdint.h>

typedef struct _udevPrivate udevPrivate;

#define SYSFS_DATA_SIZE 4096
#define DRV_STATE_UDEV_MONITOR(ds) (((udevPrivate *)((ds)->privateData))->udev_monitor)
#define DMI_DEVPATH "/sys/devices/virtual/dmi/id"
#define DMI_DEVPATH_FALLBACK "/sys/class/dmi/id"
#define PROPERTY_FOUND 0
#define PROPERTY_MISSING 1
#define PROPERTY_ERROR -1
