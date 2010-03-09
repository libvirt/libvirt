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
# define __VIR_PCI_H__

# include "internal.h"

typedef struct _pciDevice pciDevice;
typedef struct _pciDeviceList pciDeviceList;

pciDevice *pciGetDevice      (unsigned       domain,
                              unsigned       bus,
                              unsigned       slot,
                              unsigned       function);
void       pciFreeDevice     (pciDevice     *dev);
int        pciDettachDevice  (pciDevice     *dev);
int        pciReAttachDevice (pciDevice     *dev);
int        pciResetDevice    (pciDevice     *dev,
                              pciDeviceList *activeDevs);
void      pciDeviceSetManaged(pciDevice     *dev,
                              unsigned       managed);
unsigned  pciDeviceGetManaged(pciDevice     *dev);

pciDeviceList *pciDeviceListNew  (void);
void           pciDeviceListFree (pciDeviceList *list);
int            pciDeviceListAdd  (pciDeviceList *list,
                                  pciDevice *dev);
pciDevice *    pciDeviceListGet (pciDeviceList *list,
                                 int idx);
int            pciDeviceListCount (pciDeviceList *list);
pciDevice *    pciDeviceListSteal (pciDeviceList *list,
                                   pciDevice *dev);
void           pciDeviceListDel  (pciDeviceList *list,
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
typedef int (*pciDeviceFileActor)(pciDevice *dev,
                                  const char *path, void *opaque);

int pciDeviceFileIterate(pciDevice *dev,
                         pciDeviceFileActor actor,
                         void *opaque);

int pciDeviceIsAssignable(pciDevice *dev,
                          int strict_acs_check);
int pciWaitForDeviceCleanup(pciDevice *dev, const char *matcher);

#endif /* __VIR_PCI_H__ */
