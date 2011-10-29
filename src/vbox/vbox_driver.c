/** @file vbox_driver.c
 * Core driver methods for managing VirtualBox VM's
 */

/*
 * Copyright (C) 2010-2011 Red Hat, Inc.
 * Copyright (C) 2008-2009 Sun Microsystems, Inc.
 *
 * This file is part of a free software library; you can redistribute
 * it and/or modify it under the terms of the GNU Lesser General
 * Public License version 2.1 as published by the Free Software
 * Foundation and shipped in the "COPYING" file with this library.
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

#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>

#include "internal.h"

#include "datatypes.h"
#include "logging.h"
#include "vbox_driver.h"
#include "vbox_glue.h"
#include "virterror_internal.h"
#include "util.h"

#define VIR_FROM_THIS VIR_FROM_VBOX


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

static virDriver vboxDriverDummy;

#define VIR_FROM_THIS VIR_FROM_VBOX

#define vboxError(code, ...) \
        virReportErrorHelper(VIR_FROM_VBOX, code, __FILE__, \
                             __FUNCTION__, __LINE__, __VA_ARGS__)

int vboxRegister(void) {
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

static virDrvOpenStatus vboxOpenDummy(virConnectPtr conn,
                                      virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                                      unsigned int flags)
{
    uid_t uid = getuid();

    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    if (conn->uri == NULL ||
        conn->uri->scheme == NULL ||
        STRNEQ (conn->uri->scheme, "vbox") ||
        conn->uri->server != NULL)
        return VIR_DRV_OPEN_DECLINED;

    if (conn->uri->path == NULL || STREQ(conn->uri->path, "")) {
        vboxError(VIR_ERR_INTERNAL_ERROR, "%s",
                  _("no VirtualBox driver path specified (try vbox:///session)"));
        return VIR_DRV_OPEN_ERROR;
    }

    if (uid != 0) {
        if (STRNEQ (conn->uri->path, "/session")) {
            vboxError(VIR_ERR_INTERNAL_ERROR,
                      _("unknown driver path '%s' specified (try vbox:///session)"), conn->uri->path);
            return VIR_DRV_OPEN_ERROR;
        }
    } else { /* root */
        if (STRNEQ (conn->uri->path, "/system") &&
            STRNEQ (conn->uri->path, "/session")) {
            vboxError(VIR_ERR_INTERNAL_ERROR,
                      _("unknown driver path '%s' specified (try vbox:///system)"), conn->uri->path);
            return VIR_DRV_OPEN_ERROR;
        }
    }

    vboxError(VIR_ERR_INTERNAL_ERROR, "%s",
              _("unable to initialize VirtualBox driver API"));
    return VIR_DRV_OPEN_ERROR;
}

static virDriver vboxDriverDummy = {
    VIR_DRV_VBOX,
    "VBOX",
    .open = vboxOpenDummy,
};
