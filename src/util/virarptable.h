/*
 * virarptable.h Linux ARP table handling
 *
 * Copyright (C) 2018 Chen Hanxiao
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
 * Authors:
 *     Chen Hanxiao <chenhanxiao@gmail.com>
 */

#ifndef __VIR_ARPTABLE_H__
# define __VIR_ARPTABLE_H__

# include "internal.h"

typedef struct _virArpTableEntry virArpTableEntry;
typedef virArpTableEntry *virArpTableEntryPtr;
typedef struct _virArpTable virArpTable;
typedef virArpTable *virArpTablePtr;

struct _virArpTableEntry{
    char *ipaddr;
    char *mac;
};

struct _virArpTable {
    int n;
    virArpTableEntryPtr t;
};

virArpTablePtr virArpTableGet(void);
void virArpTableFree(virArpTablePtr table);

#endif /* __VIR_ARPTABLE_H__ */
