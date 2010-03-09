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
# define __STATS_LINUX_H__

# ifdef __linux__

#  include "internal.h"

extern int linuxDomainInterfaceStats(const char *path,
                                     struct _virDomainInterfaceStats *stats);

# endif /* __linux__ */

#endif /* __STATS_LINUX_H__ */
