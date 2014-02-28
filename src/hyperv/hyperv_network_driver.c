/*
 * hyperv_network_driver.c: network driver functions for managing
 *                          Microsoft Hyper-V host networks
 *
 * Copyright (C) 2011 Matthias Bolte <matthias.bolte@googlemail.com>
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

#include <config.h>

#include "internal.h"
#include "virerror.h"
#include "datatypes.h"
#include "viralloc.h"
#include "viruuid.h"
#include "hyperv_network_driver.h"

#define VIR_FROM_THIS VIR_FROM_HYPERV



static virDrvOpenStatus
hypervNetworkOpen(virConnectPtr conn,
                  virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                  unsigned int flags)
{
    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    if (conn->driver->no != VIR_DRV_HYPERV) {
        return VIR_DRV_OPEN_DECLINED;
    }

    conn->networkPrivateData = conn->privateData;

    return VIR_DRV_OPEN_SUCCESS;
}



static int
hypervNetworkClose(virConnectPtr conn)
{
    conn->networkPrivateData = NULL;

    return 0;
}



static virNetworkDriver hypervNetworkDriver = {
    .name = "Hyper-V",
    .networkOpen = hypervNetworkOpen, /* 0.9.5 */
    .networkClose = hypervNetworkClose, /* 0.9.5 */
};



int
hypervNetworkRegister(void)
{
    return virRegisterNetworkDriver(&hypervNetworkDriver);
}
