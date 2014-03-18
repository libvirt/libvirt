/*
 * interface_driver.c: loads the appropriate backend
 *
 * Copyright (C) 2014 Red Hat, Inc.
 * Copyright (C) 2012 Doug Goldstein <cardoe@cardoe.com>
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
 * License along with this library;  If not, see
 * <http://www.gnu.org/licenses/>.
 */
#include <config.h>

#include "interface_driver.h"

int
interfaceRegister(void)
{
#ifdef WITH_NETCF
    /* Attempt to load the netcf based backend first */
    if (netcfIfaceRegister() == 0)
        return 0;
#endif /* WITH_NETCF */
#if WITH_UDEV
    /* If there's no netcf or it failed to load, register the udev backend */
    if (udevIfaceRegister() == 0)
        return 0;
#endif /* WITH_UDEV */
    return -1;
}
