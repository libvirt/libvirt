/*
 * Copyright (C) 2015 Midokura Sarl.

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
 *     Antoni Segura Puimedon <toni@midokura.com>
 */

#ifndef __VIR_NETDEV_MIDONET_H__
# define __VIR_NETDEV_MIDONET_H__

# include "internal.h"
# include "virnetdevvportprofile.h"


int virNetDevMidonetBindPort(const char *ifname,
                             virNetDevVPortProfilePtr virtualport)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;

int virNetDevMidonetUnbindPort(virNetDevVPortProfilePtr virtualport)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;

#endif /* __VIR_NETDEV_MIDONET_H__ */
