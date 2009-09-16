/*
 * Copyright (C) 2009 Red Hat, Inc.
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
 *     Mark McLoughlin <markmc@redhat.com>
 */

#ifndef __VIR_PCI_H__
#define __VIR_PCI_H__

#include "internal.h"

typedef struct _pciDevice pciDevice;

typedef struct {
    unsigned count;
    pciDevice **devs;
} pciDeviceList;

pciDevice *pciGetDevice      (virConnectPtr  conn,
                              unsigned       domain,
                              unsigned       bus,
                              unsigned       slot,
                              unsigned       function);
void       pciFreeDevice     (virConnectPtr  conn,
                              pciDevice     *dev);
int        pciDettachDevice  (virConnectPtr  conn,
                              pciDevice     *dev);
int        pciReAttachDevice (virConnectPtr  conn,
                              pciDevice     *dev);
int        pciResetDevice    (virConnectPtr  conn,
                              pciDevice     *dev,
                              pciDeviceList *activeDevs);
void      pciDeviceSetManaged(pciDevice     *dev,
                              unsigned       managed);
unsigned  pciDeviceGetManaged(pciDevice     *dev);

pciDeviceList *pciDeviceListNew  (virConnectPtr conn);
void           pciDeviceListFree (virConnectPtr conn,
                                  pciDeviceList *list);
int            pciDeviceListAdd  (virConnectPtr conn,
                                  pciDeviceList *list,
                                  pciDevice *dev);
void           pciDeviceListDel  (virConnectPtr conn,
                                  pciDeviceList *list,
                                  pciDevice *dev);
pciDevice *    pciDeviceListFind (pciDeviceList *list,
                                  pciDevice *dev);

/*
 * Callback that will be invoked once for each file
 * associated with / used for PCI host device access.
 *
 * Should return 0 if successfully processed, or
 * -1 to indicate error and abort iteration
 */
typedef int (*pciDeviceFileActor)(virConnectPtr conn, pciDevice *dev,
                                  const char *path, void *opaque);

int pciDeviceFileIterate(virConnectPtr conn,
                         pciDevice *dev,
                         pciDeviceFileActor actor,
                         void *opaque);

#endif /* __VIR_PCI_H__ */
