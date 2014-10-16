/*
 * driver.h: description of the set of interfaces provided by a
 *           entry point to the virtualization engine
 *
 * Copyright (C) 2006-2014 Red Hat, Inc.
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
 */

#ifndef __VIR_DRIVER_H__
# define __VIR_DRIVER_H__

# include <unistd.h>

# include "internal.h"
# include "libvirt_internal.h"
# include "viruri.h"
/*
 * List of registered drivers numbers
 */
typedef enum {
    VIR_DRV_XEN_UNIFIED = 1,
    VIR_DRV_TEST = 2,
    VIR_DRV_QEMU = 3,
    VIR_DRV_REMOTE = 4,
    VIR_DRV_OPENVZ = 5,
    VIR_DRV_LXC = 6,
    VIR_DRV_UML = 7,
    VIR_DRV_VBOX = 8,
    VIR_DRV_ONE = 9,
    VIR_DRV_ESX = 10,
    VIR_DRV_PHYP = 11,
    VIR_DRV_XENAPI = 12,
    VIR_DRV_VMWARE = 13,
    VIR_DRV_LIBXL = 14,
    VIR_DRV_HYPERV = 15,
    VIR_DRV_PARALLELS = 16,
    VIR_DRV_BHYVE = 17,
} virDrvNo;


/* Status codes returned from driver open call. */
typedef enum {
    /* Opened successfully. */
    VIR_DRV_OPEN_SUCCESS = 0,

    /* 'name' is not for us. */
    VIR_DRV_OPEN_DECLINED = -1,

    /* 'name' is for us, but there was some error.  virConnectOpen will
     * return an error rather than continue probing the other drivers.
     */
    VIR_DRV_OPEN_ERROR = -2,
} virDrvOpenStatus;


/* Internal feature-detection macro.  Don't call drv->supports_feature
 * directly if you don't have to, because it may be NULL, use this macro
 * instead.
 *
 * Note that this treats a possible error returned by drv->supports_feature
 * the same as not supported. If you care about the error, call
 * drv->supports_feature directly.
 *
 * Returns:
 *   != 0  Feature is supported.
 *   0     Feature is not supported.
 */
# define VIR_DRV_SUPPORTS_FEATURE(drv, conn, feature)                   \
    ((drv)->connectSupportsFeature ?                                    \
        (drv)->connectSupportsFeature((conn), (feature)) > 0 : 0)


# define __VIR_DRIVER_H_INCLUDES___

# include "driver-hypervisor.h"
# include "driver-interface.h"
# include "driver-network.h"
# include "driver-nodedev.h"
# include "driver-nwfilter.h"
# include "driver-secret.h"
# ifdef WITH_LIBVIRTD
#  include "driver-state.h"
# endif
# include "driver-stream.h"
# include "driver-storage.h"

# undef __VIR_DRIVER_H_INCLUDES___

int virRegisterHypervisorDriver(virHypervisorDriverPtr) ATTRIBUTE_RETURN_CHECK;
int virRegisterNetworkDriver(virNetworkDriverPtr) ATTRIBUTE_RETURN_CHECK;
int virRegisterInterfaceDriver(virInterfaceDriverPtr) ATTRIBUTE_RETURN_CHECK;
int virRegisterNetworkDriver(virNetworkDriverPtr) ATTRIBUTE_RETURN_CHECK;
int virRegisterNodeDeviceDriver(virNodeDeviceDriverPtr) ATTRIBUTE_RETURN_CHECK;
int virRegisterNWFilterDriver(virNWFilterDriverPtr) ATTRIBUTE_RETURN_CHECK;
int virRegisterSecretDriver(virSecretDriverPtr) ATTRIBUTE_RETURN_CHECK;
# ifdef WITH_LIBVIRTD
int virRegisterStateDriver(virStateDriverPtr) ATTRIBUTE_RETURN_CHECK;
# endif
int virRegisterStorageDriver(virStorageDriverPtr) ATTRIBUTE_RETURN_CHECK;

void *virDriverLoadModule(const char *name);

#endif /* __VIR_DRIVER_H__ */
