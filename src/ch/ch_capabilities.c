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

#include <config.h>
#include "ch_capabilities.h"

static void
virCHCapsSet(virBitmap *chCaps,
               virCHCapsFlags flag)
{
    ignore_value(virBitmapSetBit(chCaps, flag));
}

/**
 * virCHCapsInitCHVersionCaps:
 *
 * Set all CH capabilities based on version of CH.
 */
virBitmap *
virCHCapsInitCHVersionCaps(int version)
{
    g_autoptr(virBitmap) chCaps = NULL;
    chCaps = virBitmapNew(CH_CAPS_LAST);

    /* Version 28 deprecated kernel API:
     * https://github.com/cloud-hypervisor/cloud-hypervisor/releases/tag/v28.0
     */
    if (version >= 28000000)
        virCHCapsSet(chCaps, CH_KERNEL_API_DEPRCATED);


    /* Starting Version 18, serial and console can be used in parallel */
    if (version >= 18000000)
        virCHCapsSet(chCaps, CH_SERIAL_CONSOLE_IN_PARALLEL);

    /* Starting Version 22, add-net api can accept multiple FDs in the request
     * This is required to be able to configure queues for virtio-net devices
     * from libvirt.
     * This capability will be used to gate networking support for ch guests.
     * https://github.com/cloud-hypervisor/cloud-hypervisor/releases/tag/v22.0
     */
    if (version >= 22000000)
        virCHCapsSet(chCaps, CH_MULTIFD_IN_ADDNET);

    /* Starting v36, Cloud-Hypervisor accepts Unix Socket as a backend for
     * guest's serial port.
     * https://github.com/cloud-hypervisor/cloud-hypervisor/releases/tag/v36.0 */
    if (version >= 36000000)
        virCHCapsSet(chCaps, CH_SOCKET_BACKEND_SERIAL_PORT);

    return g_steal_pointer(&chCaps);

}
