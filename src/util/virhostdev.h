/* virhostdev.h: hostdev management
 *
 * Copyright (C) 2006-2007, 2009-2013 Red Hat, Inc.
 * Copyright (C) 2006 Daniel P. Berrange
 * Copyright (C) 2014 SUSE LINUX Products GmbH, Nuernberg, Germany.
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
 * Author: Daniel P. Berrange <berrange@redhat.com>
 * Author: Chunyan Liu <cyliu@suse.com>
 */

#ifndef __VIR_HOSTDEV_H__
# define __VIR_HOSTDEV_H__

# include "internal.h"

# include "virpci.h"
# include "virusb.h"
# include "virscsi.h"
# include "domain_conf.h"

typedef enum {
    VIR_HOSTDEV_STRICT_ACS_CHECK     = (1 << 0), /* strict acs check */
    VIR_HOSTDEV_COLD_BOOT            = (1 << 1), /* cold boot */
} virHostdevFlag;


typedef struct _virHostdevManager virHostdevManager;
typedef virHostdevManager *virHostdevManagerPtr;
struct _virHostdevManager {
    char *stateDir;

    virPCIDeviceListPtr activePciHostdevs;
    virPCIDeviceListPtr inactivePciHostdevs;
    virUSBDeviceListPtr activeUsbHostdevs;
    virSCSIDeviceListPtr activeScsiHostdevs;
};

virHostdevManagerPtr virHostdevManagerGetDefault(void);
int
virHostdevPreparePCIDevices(virHostdevManagerPtr hostdev_mgr,
                            const char *drv_name,
                            const char *dom_name,
                            const unsigned char *uuid,
                            virDomainHostdevDefPtr *hostdevs,
                            int nhostdevs,
                            unsigned int flags);
int
virHostdevPrepareUSBDevices(virHostdevManagerPtr hostdev_mgr,
                            const char *drv_name,
                            const char *dom_name,
                            virDomainHostdevDefPtr *hostdevs,
                            int nhostdevs,
                            unsigned int flags);
int
virHostdevPrepareSCSIDevices(virHostdevManagerPtr hostdev_mgr,
                             const char *drv_name,
                             const char *dom_name,
                             virDomainHostdevDefPtr *hostdevs,
                             int nhostdevs);
void
virHostdevReAttachPCIDevices(virHostdevManagerPtr hostdev_mgr,
                             const char *drv_name,
                             const char *dom_name,
                             virDomainHostdevDefPtr *hostdevs,
                             int nhostdevs,
                             char *oldStateDir);
void
virHostdevReAttachUsbHostdevs(virHostdevManagerPtr hostdev_mgr,
                              const char *drv_name,
                              const char *dom_name,
                              virDomainHostdevDefPtr *hostdevs,
                              int nhostdevs);
void
virHostdevReAttachScsiHostdevs(virHostdevManagerPtr hostdev_mgr,
                               const char *drv_name,
                               const char *dom_name,
                               virDomainHostdevDefPtr *hostdevs,
                               int nhostdevs);
int
virHostdevUpdateActivePciHostdevs(virHostdevManagerPtr mgr,
                                  const char *drv_name,
                                  virDomainDefPtr def);
int
virHostdevUpdateActiveUsbHostdevs(virHostdevManagerPtr mgr,
                                  const char *drv_name,
                                  virDomainDefPtr def);
int
virHostdevUpdateActiveScsiHostdevs(virHostdevManagerPtr mgr,
                                   const char *drv_name,
                                   virDomainDefPtr def);

/* functions used by NodeDevDetach/Reattach/Reset */
int virHostdevPciNodeDeviceDetach(virHostdevManagerPtr mgr,
                                  virPCIDevicePtr pci);
int virHostdevPciNodeDeviceReAttach(virHostdevManagerPtr mgr,
                                    virPCIDevicePtr pci);
int virHostdevPciNodeDeviceReset(virHostdevManagerPtr mgr,
                                 virPCIDevicePtr pci);

#endif /* __VIR_HOSTDEV_H__ */
