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
/*
 * vim: set tabstop=4:
 * vim: set shiftwidth=4:
 * vim: set expandtab:
 */
/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
