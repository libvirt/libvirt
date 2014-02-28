/*
 * esx_secret_driver.c: secret driver functions for VMware ESX secret manipulation
 *
 * Copyright (C) 2010-2011 Red Hat, Inc.
 * Copyright (C) 2010 Matthias Bolte <matthias.bolte@googlemail.com>
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
#include "viralloc.h"
#include "viruuid.h"
#include "esx_private.h"
#include "esx_secret_driver.h"
#include "esx_vi.h"
#include "esx_vi_methods.h"
#include "esx_util.h"

#define VIR_FROM_THIS VIR_FROM_ESX



static virDrvOpenStatus
esxSecretOpen(virConnectPtr conn, virConnectAuthPtr auth ATTRIBUTE_UNUSED,
              unsigned int flags)
{
    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    if (conn->driver->no != VIR_DRV_ESX) {
        return VIR_DRV_OPEN_DECLINED;
    }

    conn->secretPrivateData = conn->privateData;

    return VIR_DRV_OPEN_SUCCESS;
}



static int
esxSecretClose(virConnectPtr conn)
{
    conn->secretPrivateData = NULL;

    return 0;
}



static virSecretDriver esxSecretDriver = {
    .name = "ESX",
    .secretOpen = esxSecretOpen, /* 0.7.6 */
    .secretClose = esxSecretClose, /* 0.7.6 */
};



int
esxSecretRegister(void)
{
    return virRegisterSecretDriver(&esxSecretDriver);
}
