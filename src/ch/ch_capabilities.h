/*
 * Copyright Microsoft Corp. 2023
 *
 * ch_capabilities.h: CH capabilities
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
#include "virbitmap.h"


typedef enum {
    /* 0 */
    CH_KERNEL_API_DEPRCATED, /* Use `payload` in place of `kernel` api */
    CH_SERIAL_CONSOLE_IN_PARALLEL, /* Serial and Console ports can work in parallel */
    CH_MULTIFD_IN_ADDNET, /* Cloud-hypervisor can accept multiple FDs in add-net api */
    CH_SOCKET_BACKEND_SERIAL_PORT, /* Support Unix socket as a backend for a serial port */

    CH_CAPS_LAST /* this must always be the last item */
} virCHCapsFlags;

virBitmap *
virCHCapsInitCHVersionCaps(int version);
