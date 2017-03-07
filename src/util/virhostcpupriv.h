/*
 * virhostcpupriv.h: helper APIs for host CPU info
 *
 * Copyright (C) 2014-2016 Red Hat, Inc.
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

#ifndef __VIR_HOSTCPU_PRIV_H__
# define __VIR_HOSTCPU_PRIV_H__

# include "virhostcpu.h"

# ifdef __linux__
int virHostCPUGetInfoPopulateLinux(FILE *cpuinfo,
                                   virArch arch,
                                   unsigned int *cpus,
                                   unsigned int *mhz,
                                   unsigned int *nodes,
                                   unsigned int *sockets,
                                   unsigned int *cores,
                                   unsigned int *threads);

int virHostCPUGetStatsLinux(FILE *procstat,
                            int cpuNum,
                            virNodeCPUStatsPtr params,
                            int *nparams);
# endif

#endif /* __VIR_HOSTCPU_PRIV_H__ */
