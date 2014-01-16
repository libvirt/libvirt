/*
 * nodeinfopriv.h: internal APIs for testing nodeinfo code
 *
 * Copyright (C) 2014 Red Hat, Inc.
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
 */

#ifndef __NODEINFO_PRIV_H__
# define __NODEINFO_PRIV_H__

# include "nodeinfo.h"

# ifdef __linux__
int linuxNodeInfoCPUPopulate(FILE *cpuinfo,
                             const char *sysfs_dir,
                             virNodeInfoPtr nodeinfo);

int linuxNodeGetCPUStats(FILE *procstat,
                         int cpuNum,
                         virNodeCPUStatsPtr params,
                         int *nparams);
# endif

#endif /* __NODEINFO_PRIV_H__ */
