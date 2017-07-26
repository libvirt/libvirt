/** @file vbox_driver.c
 * Core driver methods for managing VirtualBox VM's
 */

/*
 * Copyright (C) 2010-2014 Red Hat, Inc.
 * Copyright (C) 2008-2009 Sun Microsystems, Inc.
 *
 * This file is part of a free software library; you can redistribute
 * it and/or modify it under the terms of the GNU Lesser General
 * Public License version 2.1 as published by the Free Software
 * Foundation and shipped in the "COPYING.LESSER" file with this library.
 * The library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY of any kind.
 *
 * Sun LGPL Disclaimer: For the avoidance of doubt, except that if
 * any license choice other than GPL or LGPL is available it will
 * apply instead, Sun elects to use only the Lesser General Public
 * License version 2.1 (LGPLv2) at this time for any software where
 * a choice of LGPL license versions is made available with the
 * language indicating that LGPLv2 or any later version may be used,
 * or where a choice of which version of the LGPL is applied is
 * otherwise unspecified.
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa
 * Clara, CA 95054 USA or visit http://www.sun.com if you need
 * additional information or have any questions.
 */

#include <config.h>

#include <unistd.h>

#include "internal.h"

#include "datatypes.h"
#include "virlog.h"
#include "vbox_driver.h"
#include "vbox_glue.h"
#include "virerror.h"
#include "virutil.h"
#include "domain_event.h"
#include "domain_conf.h"

#include "vbox_get_driver.h"

#define VIR_FROM_THIS VIR_FROM_VBOX

VIR_LOG_INIT("vbox.vbox_driver");

#if defined(VBOX_DRIVER)
static virDrvOpenStatus dummyConnectOpen(virConnectPtr conn,
                                         virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                                         virConfPtr conf ATTRIBUTE_UNUSED,
                                         unsigned int flags)
{
    uid_t uid = geteuid();

    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    if (conn->uri == NULL ||
        conn->uri->scheme == NULL ||
        STRNEQ(conn->uri->scheme, "vbox") ||
        conn->uri->server != NULL)
        return VIR_DRV_OPEN_DECLINED;

    if (conn->uri->path == NULL || STREQ(conn->uri->path, "")) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("no VirtualBox driver path specified (try vbox:///session)"));
        return VIR_DRV_OPEN_ERROR;
    }

    if (uid != 0) {
        if (STRNEQ(conn->uri->path, "/session")) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unknown driver path '%s' specified (try vbox:///session)"), conn->uri->path);
            return VIR_DRV_OPEN_ERROR;
        }
    } else { /* root */
        if (STRNEQ(conn->uri->path, "/system") &&
            STRNEQ(conn->uri->path, "/session")) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unknown driver path '%s' specified (try vbox:///system)"), conn->uri->path);
            return VIR_DRV_OPEN_ERROR;
        }
    }

    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("unable to initialize VirtualBox driver API"));
    return VIR_DRV_OPEN_ERROR;
}

static virHypervisorDriver vboxDriverDummy = {
    "VBOX",
    .connectOpen = dummyConnectOpen, /* 0.6.3 */
};

static virConnectDriver vboxConnectDriver;

int vboxRegister(void)
{
    uint32_t uVersion;

    if (VBoxCGlueInit(&uVersion) == 0)
        vboxConnectDriver.hypervisorDriver = vboxGetHypervisorDriver(uVersion);

    if (vboxConnectDriver.hypervisorDriver) {
        vboxConnectDriver.networkDriver = vboxGetNetworkDriver(uVersion);
        vboxConnectDriver.storageDriver = vboxGetStorageDriver(uVersion);
    } else {
        vboxConnectDriver.hypervisorDriver = &vboxDriverDummy;
    }

    if (virRegisterConnectDriver(&vboxConnectDriver,
                                 false) < 0)
        return -1;

    return 0;
}
#endif
