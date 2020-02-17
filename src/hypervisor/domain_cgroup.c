/*
 * domain_cgroup.c: cgroup functions shared between hypervisor drivers
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

#include "domain_cgroup.h"


int
virDomainCgroupSetupBlkio(virCgroupPtr cgroup, virDomainBlkiotune blkio)
{
    size_t i;

    if (blkio.weight != 0 &&
        virCgroupSetBlkioWeight(cgroup, blkio.weight) < 0)
        return -1;

    if (blkio.ndevices) {
        for (i = 0; i < blkio.ndevices; i++) {
            virBlkioDevicePtr dev = &blkio.devices[i];

            if (dev->weight &&
                virCgroupSetupBlkioDeviceWeight(cgroup, dev->path,
                                                &dev->weight) < 0)
                return -1;

            if (dev->riops &&
                virCgroupSetupBlkioDeviceReadIops(cgroup, dev->path,
                                                  &dev->riops) < 0)
                return -1;

            if (dev->wiops &&
                virCgroupSetupBlkioDeviceWriteIops(cgroup, dev->path,
                                                   &dev->wiops) < 0)
                return -1;

            if (dev->rbps &&
                virCgroupSetupBlkioDeviceReadBps(cgroup, dev->path,
                                                 &dev->rbps) < 0)
                return -1;

            if (dev->wbps &&
                virCgroupSetupBlkioDeviceWriteBps(cgroup, dev->path,
                                                  &dev->wbps) < 0)
                return -1;
        }
    }

    return 0;
}
