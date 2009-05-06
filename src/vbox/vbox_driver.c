/** @file vbox_driver.c
 * Core driver methods for managing VirtualBox VM's
 */

/*
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

#include "internal.h"

#include "datatypes.h"
#include "logging.h"
#include "vbox_driver.h"
#include "vbox_XPCOMCGlue.h"

#define VIR_FROM_THIS VIR_FROM_VBOX


extern virDriver vbox22Driver;
#if 0
extern virDriver vbox25Driver;
#endif


int vboxRegister(void) {
    virDriverPtr        driver;
    uint32_t            uVersion;

    /* vboxRegister() shouldn't fail as that will render libvirt unless.
     * So, we use the v2.2 driver as a fallback/dummy.
     */
    driver        = &vbox22Driver;

    /* Init the glue and get the API version. */
    if (VBoxCGlueInit() == 0) {
        uVersion = g_pVBoxFuncs->pfnGetVersion();
        DEBUG("VBoxCGlueInit found API version: %d.%d.%d (%u)",
              uVersion / 1000000,
              uVersion % 1000000 / 1000,
              uVersion % 1000,
              uVersion);

        /* Select driver implementation based on version.
         * Note that the VirtualBox development usually happens at build
         * number 51, thus the version ranges in the if statements below.
         */
        if (uVersion >= 2001052 && uVersion < 2002051) {
            DEBUG0("VirtualBox API version: 2.2");
            driver        = &vbox22Driver;
#if 0
        } else if (uVersion >= 2002051 && uVersion < 2005051) {
            DEBUG0("VirtualBox API version: 2.5");
            driver        = &vbox25Driver;
#endif
        } else {
            DEBUG0("Unsupport VirtualBox API version");
        }

    } else {
        DEBUG0("VBoxCGlueInit failed");
    }

    if (virRegisterDriver(driver) < 0)
        return -1;

    return 0;
}
