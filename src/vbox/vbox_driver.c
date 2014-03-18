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

#define VIR_FROM_THIS VIR_FROM_VBOX

VIR_LOG_INIT("vbox.vbox_driver");

extern virDriver vbox22Driver;
extern virNetworkDriver vbox22NetworkDriver;
extern virStorageDriver vbox22StorageDriver;
extern virDriver vbox30Driver;
extern virNetworkDriver vbox30NetworkDriver;
extern virStorageDriver vbox30StorageDriver;
extern virDriver vbox31Driver;
extern virNetworkDriver vbox31NetworkDriver;
extern virStorageDriver vbox31StorageDriver;
extern virDriver vbox32Driver;
extern virNetworkDriver vbox32NetworkDriver;
extern virStorageDriver vbox32StorageDriver;
extern virDriver vbox40Driver;
extern virNetworkDriver vbox40NetworkDriver;
extern virStorageDriver vbox40StorageDriver;
extern virDriver vbox41Driver;
extern virNetworkDriver vbox41NetworkDriver;
extern virStorageDriver vbox41StorageDriver;
extern virDriver vbox42Driver;
extern virNetworkDriver vbox42NetworkDriver;
extern virStorageDriver vbox42StorageDriver;
extern virDriver vbox42_20Driver;
extern virNetworkDriver vbox42_20NetworkDriver;
extern virStorageDriver vbox42_20StorageDriver;
extern virDriver vbox43Driver;
extern virNetworkDriver vbox43NetworkDriver;
extern virStorageDriver vbox43StorageDriver;
extern virDriver vbox43_4Driver;
extern virNetworkDriver vbox43_4NetworkDriver;
extern virStorageDriver vbox43_4StorageDriver;

static virDriver vboxDriverDummy;

#define VIR_FROM_THIS VIR_FROM_VBOX

int vboxRegister(void)
{
    virDriverPtr        driver;
    virNetworkDriverPtr networkDriver;
    virStorageDriverPtr storageDriver;
    uint32_t            uVersion;

    /*
     * If the glue layer does not initialize, we register a driver
     * with a dummy open method, so we can report nicer errors
     * if the user requests a vbox:// URI which we know will
     * never work
     */
    driver        = &vboxDriverDummy;
    networkDriver = &vbox22NetworkDriver;
    storageDriver = &vbox22StorageDriver;

    /* Init the glue and get the API version. */
    if (VBoxCGlueInit(&uVersion) == 0) {
        VIR_DEBUG("VBoxCGlueInit found API version: %d.%d.%d (%u)",
              uVersion / 1000000,
              uVersion % 1000000 / 1000,
              uVersion % 1000,
              uVersion);

        /* Select driver implementation based on version.
         * Note that the VirtualBox development usually happens at build
         * number 51, thus the version ranges in the if statements below.
         */
        if (uVersion >= 2001052 && uVersion < 2002051) {
            VIR_DEBUG("VirtualBox API version: 2.2");
            driver        = &vbox22Driver;
            networkDriver = &vbox22NetworkDriver;
            storageDriver = &vbox22StorageDriver;
        } else if (uVersion >= 2002051 && uVersion < 3000051) {
            VIR_DEBUG("VirtualBox API version: 3.0");
            driver        = &vbox30Driver;
            networkDriver = &vbox30NetworkDriver;
            storageDriver = &vbox30StorageDriver;
        } else if (uVersion >= 3000051 && uVersion < 3001051) {
            VIR_DEBUG("VirtualBox API version: 3.1");
            driver        = &vbox31Driver;
            networkDriver = &vbox31NetworkDriver;
            storageDriver = &vbox31StorageDriver;
        } else if (uVersion >= 3001051 && uVersion < 3002051) {
            VIR_DEBUG("VirtualBox API version: 3.2");
            driver        = &vbox32Driver;
            networkDriver = &vbox32NetworkDriver;
            storageDriver = &vbox32StorageDriver;
        } else if (uVersion >= 3002051 && uVersion < 4000051) {
            VIR_DEBUG("VirtualBox API version: 4.0");
            driver        = &vbox40Driver;
            networkDriver = &vbox40NetworkDriver;
            storageDriver = &vbox40StorageDriver;
        } else if (uVersion >= 4000051 && uVersion < 4001051) {
            VIR_DEBUG("VirtualBox API version: 4.1");
            driver        = &vbox41Driver;
            networkDriver = &vbox41NetworkDriver;
            storageDriver = &vbox41StorageDriver;
        } else if (uVersion >= 4001051 && uVersion < 4002020) {
            VIR_DEBUG("VirtualBox API version: 4.2");
            driver        = &vbox42Driver;
            networkDriver = &vbox42NetworkDriver;
            storageDriver = &vbox42StorageDriver;
        } else if (uVersion >= 4002020 && uVersion < 4002051) {
           VIR_DEBUG("VirtualBox API version: 4.2.20 or higher");
           driver         = &vbox42_20Driver;
           networkDriver  = &vbox42_20NetworkDriver;
           storageDriver  = &vbox42_20StorageDriver;
        } else if (uVersion >= 4002051 && uVersion < 4003004) {
            VIR_DEBUG("VirtualBox API version: 4.3");
            driver        = &vbox43Driver;
            networkDriver = &vbox43NetworkDriver;
            storageDriver = &vbox43StorageDriver;
        } else if (uVersion >= 4003004 && uVersion < 4003051) {
            VIR_DEBUG("VirtualBox API version: 4.3.4 or higher");
            driver        = &vbox43_4Driver;
            networkDriver = &vbox43_4NetworkDriver;
            storageDriver = &vbox43_4StorageDriver;
        } else {
            VIR_DEBUG("Unsupported VirtualBox API version: %u", uVersion);
        }
    } else {
        VIR_DEBUG("VBoxCGlueInit failed, using dummy driver");
    }

    if (virRegisterDriver(driver) < 0)
        return -1;
    if (virRegisterNetworkDriver(networkDriver) < 0)
        return -1;
    if (virRegisterStorageDriver(storageDriver) < 0)
        return -1;

    return 0;
}

static virDrvOpenStatus vboxConnectOpen(virConnectPtr conn,
                                        virConnectAuthPtr auth ATTRIBUTE_UNUSED,
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

static virDriver vboxDriverDummy = {
    VIR_DRV_VBOX,
    "VBOX",
    .connectOpen = vboxConnectOpen,
};
