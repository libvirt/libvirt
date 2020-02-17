/*
 * domain_driver.c: general functions shared between hypervisor drivers
 *
 * Copyright IBM Corp. 2020
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

#include "domain_driver.h"
#include "viralloc.h"

#define VIR_FROM_THIS VIR_FROM_DOMAIN


/* Modify dest_array to reflect all blkio device changes described in
 * src_array.  */
int
virDomainDriverMergeBlkioDevice(virBlkioDevicePtr *dest_array,
                                size_t *dest_size,
                                virBlkioDevicePtr src_array,
                                size_t src_size,
                                const char *type)
{
    size_t i, j;
    virBlkioDevicePtr dest, src;

    for (i = 0; i < src_size; i++) {
        bool found = false;

        src = &src_array[i];
        for (j = 0; j < *dest_size; j++) {
            dest = &(*dest_array)[j];
            if (STREQ(src->path, dest->path)) {
                found = true;

                if (STREQ(type, VIR_DOMAIN_BLKIO_DEVICE_WEIGHT)) {
                    dest->weight = src->weight;
                } else if (STREQ(type, VIR_DOMAIN_BLKIO_DEVICE_READ_IOPS)) {
                    dest->riops = src->riops;
                } else if (STREQ(type, VIR_DOMAIN_BLKIO_DEVICE_WRITE_IOPS)) {
                    dest->wiops = src->wiops;
                } else if (STREQ(type, VIR_DOMAIN_BLKIO_DEVICE_READ_BPS)) {
                    dest->rbps = src->rbps;
                } else if (STREQ(type, VIR_DOMAIN_BLKIO_DEVICE_WRITE_BPS)) {
                    dest->wbps = src->wbps;
                } else {
                    virReportError(VIR_ERR_INVALID_ARG, _("Unknown parameter %s"),
                                   type);
                    return -1;
                }
                break;
            }
        }
        if (!found) {
            if (!src->weight && !src->riops && !src->wiops && !src->rbps && !src->wbps)
                continue;
            if (VIR_EXPAND_N(*dest_array, *dest_size, 1) < 0)
                return -1;
            dest = &(*dest_array)[*dest_size - 1];

            if (STREQ(type, VIR_DOMAIN_BLKIO_DEVICE_WEIGHT)) {
                dest->weight = src->weight;
            } else if (STREQ(type, VIR_DOMAIN_BLKIO_DEVICE_READ_IOPS)) {
                dest->riops = src->riops;
            } else if (STREQ(type, VIR_DOMAIN_BLKIO_DEVICE_WRITE_IOPS)) {
                dest->wiops = src->wiops;
            } else if (STREQ(type, VIR_DOMAIN_BLKIO_DEVICE_READ_BPS)) {
                dest->rbps = src->rbps;
            } else if (STREQ(type, VIR_DOMAIN_BLKIO_DEVICE_WRITE_BPS)) {
                dest->wbps = src->wbps;
            } else {
                *dest_size = *dest_size - 1;
                return -1;
            }

            dest->path = src->path;
            src->path = NULL;
        }
    }

    return 0;
}
