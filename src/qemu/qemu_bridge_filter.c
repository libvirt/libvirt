/*
 * Copyright (C) 2009 IBM Corp.
 * Copyright (C) 2007-2009 Red Hat, Inc.
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
 * Authors:
 *     Gerhard Stenzel <gerhard.stenzel@de.ibm.com>
 */

#include <config.h>

#include "virebtables.h"
#include "qemu_conf.h"
#include "qemu_driver.h"
#include "virerror.h"
#include "virlog.h"

#include "qemu_bridge_filter.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

int
networkAddEbtablesRules(virQEMUDriverPtr driver) {
    int err;

    /* Set forward policy to DROP */
    if ((err = ebtablesAddForwardPolicyReject(driver->ebtables))) {
        virReportSystemError(err,
         _("failed to add ebtables rule to set default policy to drop on '%s'"),
                             __FILE__);
        return err;
    }

    return 0;
}


int
networkDisableAllFrames(virQEMUDriverPtr driver) {
    int err;

    /* add default rules */
    if ((err = networkAddEbtablesRules(driver))) {
        virReportSystemError(err,
                             _("cannot filter mac addresses on bridge '%s'"),
                             __FILE__);
        return err;
    }
    return 0;
}

int
networkAllowMacOnPort(virQEMUDriverPtr driver,
                      const char * ifname,
                      const virMacAddrPtr mac) {

    int err;

    /* allow this combination of macaddr and ifname */
    ebtablesContext * ebtablescontext = driver->ebtables;
    if ((err = ebtablesAddForwardAllowIn(ebtablescontext,
                                         ifname,
                                         mac))) {
        virReportSystemError(err,
                     _("failed to add ebtables rule to allow routing to '%s'"),
                             ifname);
    }

    return 0;
}


int
networkDisallowMacOnPort(virQEMUDriverPtr driver,
                         const char * ifname,
                         const virMacAddrPtr mac) {

    int err;

    /* disallow this combination of macaddr and ifname */
    ebtablesContext * ebtablescontext = driver->ebtables;
    if ((err = ebtablesRemoveForwardAllowIn(ebtablescontext,
                                         ifname,
                                         mac))) {
        virReportSystemError(err,
                     _("failed to add ebtables rule to allow routing to '%s'"),
                             ifname);
    }

    return 0;
}
