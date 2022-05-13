/*
 * virccw.h: helper APIs for managing host CCW devices
 *
 * Copyright (C) 2022 IBM Corporation
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

#include "internal.h"

#define VIR_CCW_DEVICE_MAX_CSSID    254
#define VIR_CCW_DEVICE_MAX_SSID       3
#define VIR_CCW_DEVICE_MAX_DEVNO  65535
#define VIR_CCW_DEVICE_ADDRESS_FMT "%x.%x.%04x"

typedef struct _virCCWDeviceAddress virCCWDeviceAddress;
struct _virCCWDeviceAddress {
    unsigned int cssid;
    unsigned int ssid;
    unsigned int devno;
    bool         assigned;
};

bool virCCWDeviceAddressIsValid(virCCWDeviceAddress *addr);
bool virCCWDeviceAddressEqual(virCCWDeviceAddress *addr1,
                              virCCWDeviceAddress *addr2);

char* virCCWDeviceAddressAsString(virCCWDeviceAddress *addr)
    ATTRIBUTE_NONNULL(1);
virCCWDeviceAddress *virCCWDeviceAddressFromString(const char *address)
    ATTRIBUTE_NONNULL(1);

int virCCWDeviceAddressIncrement(virCCWDeviceAddress *addr);

int virCCWDeviceAddressParseFromString(const char *address,
                                       unsigned int *cssid,
                                       unsigned int *ssid,
                                       unsigned int *devno);
