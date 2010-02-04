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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Authors:
 *     Gerhard Stenzel <gerhard.stenzel@de.ibm.com>
 */

#include <config.h>

#include "ebtables.h"
#include "qemu_conf.h"
#include "qemu_driver.h"
#include "util.h"
#include "virterror_internal.h"
#include "logging.h"

#include "qemu_bridge_filter.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

int
networkAddEbtablesRules(struct qemud_driver *driver) {
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
networkDisableAllFrames(struct qemud_driver *driver) {
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
networkAllowMacOnPort(struct qemud_driver *driver,
                      const char * ifname,
                      const unsigned char * mac) {

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
networkDisallowMacOnPort(struct qemud_driver *driver,
                         const char * ifname,
                         const unsigned char * mac) {

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
