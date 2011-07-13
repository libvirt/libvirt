
/*
 * hyperv_nwfilter_driver.c: nwfilter driver functions for managing
 *                           Microsoft Hyper-V firewall rules
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 */

#include <config.h>

#include "internal.h"
#include "virterror_internal.h"
#include "datatypes.h"
#include "util.h"
#include "memory.h"
#include "logging.h"
#include "uuid.h"
#include "hyperv_nwfilter_driver.h"

#define VIR_FROM_THIS VIR_FROM_HYPERV



static virDrvOpenStatus
hypervNWFilterOpen(virConnectPtr conn,
                   virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                   unsigned int flags)
{
    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    if (conn->driver->no != VIR_DRV_HYPERV) {
        return VIR_DRV_OPEN_DECLINED;
    }

    conn->nwfilterPrivateData = conn->privateData;

    return VIR_DRV_OPEN_SUCCESS;
}



static int
hypervNWFilterClose(virConnectPtr conn)
{
    conn->nwfilterPrivateData = NULL;

    return 0;
}



static virNWFilterDriver hypervNWFilterDriver = {
    .name = "Hyper-V",
    .open = hypervNWFilterOpen, /* 0.9.5 */
    .close = hypervNWFilterClose, /* 0.9.5 */
};



int
hypervNWFilterRegister(void)
{
    return virRegisterNWFilterDriver(&hypervNWFilterDriver);
}
