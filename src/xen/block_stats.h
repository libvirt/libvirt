/*
 * Linux block and network stats.
 *
 * Copyright (C) 2007 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Richard W.M. Jones <rjones@redhat.com>
 */

#ifndef __BLOCK_STATS_H__
# define __BLOCK_STATS_H__

# ifdef __linux__

#  include "xen_driver.h"

extern int xenLinuxDomainBlockStats (xenUnifiedPrivatePtr priv,
                                     virDomainPtr dom, const char *path,
                                     struct _virDomainBlockStats *stats);

extern int xenLinuxDomainDeviceID(int domid, const char *dev);

# endif /* __linux__ */

#endif /* __STATS_LINUX_H__ */
