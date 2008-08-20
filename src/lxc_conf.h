/*
 * Copyright IBM Corp. 2008
 *
 * lxc_conf.h: header file for linux container config functions
 *
 * Authors:
 *  David L. Leskovec <dlesko at linux.vnet.ibm.com>
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#ifndef LXC_CONF_H
#define LXC_CONF_H

#include <config.h>

#include "internal.h"
#include "domain_conf.h"
#include "capabilities.h"

#define LXC_CONFIG_DIR SYSCONF_DIR "/libvirt/lxc"
#define LXC_STATE_DIR LOCAL_STATE_DIR "/run/libvirt/lxc"
#define LXC_LOG_DIR LOCAL_STATE_DIR "/log/libvirt/lxc"

typedef struct __lxc_driver lxc_driver_t;
struct __lxc_driver {
    virCapsPtr caps;

    virDomainObjPtr domains;
    char *configDir;
    char *autostartDir;
    char *stateDir;
    char *logDir;
    int have_netns;
};

int lxcLoadDriverConfig(lxc_driver_t *driver);
virCapsPtr lxcCapsInit(void);

void lxcError(virConnectPtr conn,
              virDomainPtr dom,
              int code, const char *fmt, ...)
    ATTRIBUTE_FORMAT(printf,4,5);

#endif /* LXC_CONF_H */

