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
extern virDriver vbox25Driver;

int errorval = 0;

int vboxRegister(void) {
    virDriver *driver;
    uint32_t uVersion = 0;
    uint32_t major    = 0;
    uint32_t minor    = 0;
    uint32_t intVer   = 0;
    uint32_t build    = 0;

    if (VBoxCGlueInit() != 0)
        errorval = -1;

    if (errorval != -1) {

        uVersion = g_pVBoxFuncs->pfnGetVersion();

        major  = uVersion / 1000000;
        intVer = uVersion % 1000000;
        minor  = intVer / 1000;
        build  = intVer % 1000;

        DEBUG("VBoxCGlueInit worked for version: %d.%d.%d", major, minor, build);
    } else {
        DEBUG("VBoxCGlueInit failed: %d.%d.%d, errorval=%d", major, minor, build, errorval);
    }
    /* select driver implementation based on version.
     * here returning -1 as initially thought is not
     * possible as that doesn't even allow libvirt to
     * load and thus drop to safe version which is
     * v2.2, but dont return -1 unless until it is
     * really bad like can't register the driver
     * itself using virRegisterDriver()
     */
    if (errorval == -1) {
        /* If initialization fails then always drop
         * back to the intial version i.e V2.2
         */
        driver = &vbox22Driver;
    } else if ( ((major == 2) && (minor == 1) && (build > 51)) ||
                ((major == 2) && (minor == 2)) ) {
        /* currently the OSE edition is still stuck at 2.1.52
         * while the beta is at 2.2 so check for both currently*/
        driver = &vbox22Driver;
    } else {
        /* Always drop to some default if none of the above
         * cases are matched, else virRegisterDriver() will fail
         * and cause the whole of libvirt to be non-operative.
         */
        driver = &vbox22Driver;
    }
    /** @todo r=bird:
     *   1. What about if (uVersion > 2001051 && uVersion <= 2002999)
     *      instead of the complicated stuff above?
     */



    if (virRegisterDriver(driver) < 0)
        return -1;

    return 0;
}
