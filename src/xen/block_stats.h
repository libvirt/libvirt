/*
 * Linux block and network stats.
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

#ifndef __BLOCK_STATS_H__
# define __BLOCK_STATS_H__

# ifdef __linux__

#  include "xen_driver.h"

extern int xenLinuxDomainBlockStats (xenUnifiedPrivatePtr priv,
                                     virDomainDefPtr def, const char *path,
                                     virDomainBlockStatsPtr stats);

extern int xenLinuxDomainDeviceID(int domid, const char *dev);

# endif /* __linux__ */

#endif /* __STATS_LINUX_H__ */
