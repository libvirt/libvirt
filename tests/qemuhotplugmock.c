/*
 * Copyright (C) 2019 IBM Corporation
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

#include "qemu/qemu_hotplug.h"
#include "conf/domain_conf.h"

unsigned long long
qemuDomainGetUnplugTimeout(virDomainObjPtr vm G_GNUC_UNUSED)
{
    /* Wait only 100ms for DEVICE_DELETED event. Give a greater
     * timeout in case of PSeries guest to be consistent with the
     * original logic. */
    if (qemuDomainIsPSeries(vm->def))
        return 200;
    return 100;
}
