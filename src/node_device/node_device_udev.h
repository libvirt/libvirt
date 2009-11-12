/*
 * node_device_udev.h: node device enumeration - libudev implementation
 *
 * Copyright (C) 2009 Red Hat
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
 * Author: Dave Allan <dallan@redhat.com>
 */

#include <libudev.h>
#include <stdint.h>

#define SYSFS_DATA_SIZE 4096
#define DRV_STATE_UDEV_MONITOR(ds) ((struct udev_monitor *)((ds)->privateData))
#define DMI_DEVPATH "/sys/devices/virtual/dmi/id"
#define PROPERTY_FOUND 0
#define PROPERTY_MISSING 1
#define PROPERTY_ERROR -1
