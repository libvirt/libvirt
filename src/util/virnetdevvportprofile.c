/*
 * Copyright (C) 2009-2011 Red Hat, Inc.
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
 *     Stefan Berger <stefanb@us.ibm.com>
 *     Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include "virnetdevvportprofile.h"

bool
virNetDevVPortProfileEqual(virNetDevVPortProfilePtr a, virNetDevVPortProfilePtr b)
{
    /* NULL resistant */
    if (!a && !b)
        return true;

    if (!a || !b)
        return false;

    if (a->virtPortType != b->virtPortType)
        return false;

    switch (a->virtPortType) {
    case VIR_NETDEV_VPORT_PROFILE_NONE:
        break;

    case VIR_NETDEV_VPORT_PROFILE_8021QBG:
        if (a->u.virtPort8021Qbg.managerID != b->u.virtPort8021Qbg.managerID ||
            a->u.virtPort8021Qbg.typeID != b->u.virtPort8021Qbg.typeID ||
            a->u.virtPort8021Qbg.typeIDVersion != b->u.virtPort8021Qbg.typeIDVersion ||
            memcmp(a->u.virtPort8021Qbg.instanceID, b->u.virtPort8021Qbg.instanceID, VIR_UUID_BUFLEN) != 0)
            return false;
        break;

    case VIR_NETDEV_VPORT_PROFILE_8021QBH:
        if (STRNEQ(a->u.virtPort8021Qbh.profileID, b->u.virtPort8021Qbh.profileID))
            return false;
        break;

    default:
        break;
    }

    return true;
}
