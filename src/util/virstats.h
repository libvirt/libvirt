/*
 * virstats.h: Block and network stats.
 *
 * Copyright (C) 2007 Red Hat, Inc.
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
 * Richard W.M. Jones <rjones@redhat.com>
 */

#ifndef __STATS_LINUX_H__
# define __STATS_LINUX_H__

# include "internal.h"

int virNetDevTapInterfaceStats(const char *ifname,
                               virDomainInterfaceStatsPtr stats)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;

#endif /* __STATS_LINUX_H__ */
