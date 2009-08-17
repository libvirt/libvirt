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

#include <config.h>
#include "internal.h"

typedef struct _pciDevice pciDevice;

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
                              pciDevice     *dev);

#endif /* __VIR_PCI_H__ */
