/*
 * bhyve_utils.h: bhyve utils
 *
 * Copyright (C) 2014 Roman Bogorodskiy
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

#ifndef __BHYVE_UTILS_H__
# define __BHYVE_UTILS_H__

# include "driver.h"
# include "domain_conf.h"
# include "configmake.h"
# include "virthread.h"
# include "virclosecallbacks.h"

# define BHYVE_AUTOSTART_DIR    SYSCONFDIR "/libvirt/bhyve/autostart"
# define BHYVE_CONFIG_DIR       SYSCONFDIR "/libvirt/bhyve"
# define BHYVE_STATE_DIR        LOCALSTATEDIR "/run/libvirt/bhyve"
# define BHYVE_LOG_DIR          LOCALSTATEDIR "/log/libvirt/bhyve"

struct _bhyveConn {
    virMutex lock;
    virDomainObjListPtr domains;
    virCapsPtr caps;
    virDomainXMLOptionPtr xmlopt;
    char *pidfile;

    virCloseCallbacksPtr closeCallbacks;
};

typedef struct _bhyveConn bhyveConn;
typedef struct _bhyveConn *bhyveConnPtr;

void bhyveDriverLock(bhyveConnPtr driver);
void bhyveDriverUnlock(bhyveConnPtr driver);

#endif /* __BHYVE_UTILS_H__ */
