/*
 * Copyright (C) 2009-2013 Red Hat, Inc.
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

#ifndef LIBVIRT_VIRNETDEVVLAN_H
# define LIBVIRT_VIRNETDEVVLAN_H

# include <virutil.h>

# include "viralloc.h"

typedef enum {
    VIR_NATIVE_VLAN_MODE_DEFAULT = 0,
    VIR_NATIVE_VLAN_MODE_TAGGED,
    VIR_NATIVE_VLAN_MODE_UNTAGGED,

    VIR_NATIVE_VLAN_MODE_LAST
} virNativeVlanMode;

VIR_ENUM_DECL(virNativeVlanMode);

typedef struct _virNetDevVlan virNetDevVlan;
typedef virNetDevVlan *virNetDevVlanPtr;
struct _virNetDevVlan {
    bool trunk;        /* true if this is a trunk */
    int nTags;          /* number of tags in array */
    unsigned int *tag; /* pointer to array of tags */
    int nativeMode;    /* enum virNativeVlanMode */
    unsigned int nativeTag;
};

void virNetDevVlanClear(virNetDevVlanPtr vlan);
void virNetDevVlanFree(virNetDevVlanPtr vlan);
int virNetDevVlanEqual(const virNetDevVlan *a, const virNetDevVlan *b);
int virNetDevVlanCopy(virNetDevVlanPtr dst, const virNetDevVlan *src);

VIR_DEFINE_AUTOPTR_FUNC(virNetDevVlan, virNetDevVlanFree);

#endif /* LIBVIRT_VIRNETDEVVLAN_H */
