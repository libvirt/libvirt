/*
 * Linux block and network stats.
 *
 * Copyright (C) 2007 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Richard W.M. Jones <rjones@redhat.com>
 */

#ifndef __STATS_LINUX_H__
#define __STATS_LINUX_H__

#ifdef __linux__

#include "xen_unified.h"

extern int xenLinuxDomainBlockStats (xenUnifiedPrivatePtr priv,
                                     virDomainPtr dom, const char *path,
                                     struct _virDomainBlockStats *stats);
extern int linuxDomainInterfaceStats (virConnectPtr conn, const char *path,
                                      struct _virDomainInterfaceStats *stats);

extern int xenLinuxDomainDeviceID(virConnectPtr conn, int domid, const char *dev);

#endif /* __linux__ */

#endif /* __STATS_LINUX_H__ */
