
/*
 * hyperv_driver.c: core driver functions for managing Microsoft Hyper-V hosts
 *
 * Copyright (C) 2011 Matthias Bolte <matthias.bolte@googlemail.com>
 * Copyright (C) 2009 Michael Sievers <msievers83@googlemail.com>
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
#include "datatypes.h"
#include "domain_conf.h"
#include "authhelper.h"
#include "util.h"
#include "memory.h"
#include "logging.h"
#include "uuid.h"
#include "hyperv_driver.h"
#include "hyperv_interface_driver.h"
#include "hyperv_network_driver.h"
#include "hyperv_storage_driver.h"
#include "hyperv_device_monitor.h"
#include "hyperv_secret_driver.h"
#include "hyperv_nwfilter_driver.h"
#include "hyperv_private.h"

#define VIR_FROM_THIS VIR_FROM_HYPERV



static virDrvOpenStatus
hypervOpen(virConnectPtr conn, virConnectAuthPtr auth, unsigned int flags)
{
    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    /* Decline if the URI is NULL or the scheme is not hyperv */
    if (conn->uri == NULL || conn->uri->scheme == NULL ||
        STRCASENEQ(conn->uri->scheme, "hyperv")) {
        return VIR_DRV_OPEN_DECLINED;
    }

    /* Require server part */
    if (conn->uri->server == NULL) {
        HYPERV_ERROR(VIR_ERR_INVALID_ARG, "%s",
                     _("URI is missing the server part"));
        return VIR_DRV_OPEN_ERROR;
    }

    /* Require auth */
    if (auth == NULL || auth->cb == NULL) {
        HYPERV_ERROR(VIR_ERR_INVALID_ARG, "%s",
                     _("Missing or invalid auth pointer"));
        return VIR_DRV_OPEN_ERROR;
    }

    return VIR_DRV_OPEN_SUCCESS;
}



static int
hypervClose(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    return 0;
}



static virDriver hypervDriver = {
    .no = VIR_DRV_HYPERV,
    .name = "Hyper-V",
    .open = hypervOpen, /* 0.9.5 */
    .close = hypervClose, /* 0.9.5 */
};



int
hypervRegister(void)
{
    if (virRegisterDriver(&hypervDriver) < 0 ||
        hypervInterfaceRegister() < 0 ||
        hypervNetworkRegister() < 0 ||
        hypervStorageRegister() < 0 ||
        hypervDeviceRegister() < 0 ||
        hypervSecretRegister() < 0 ||
        hypervNWFilterRegister() < 0) {
        return -1;
    }

    return 0;
}
