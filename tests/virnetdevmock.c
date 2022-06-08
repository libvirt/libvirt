/*
 * Copyright (C) 2015 Red Hat, Inc.
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

#include <config.h>

#ifdef __linux__
# include "internal.h"
# include "virnetdev.h"

# define NET_DEV_TEST_DATA_PREFIX abs_srcdir "/virnetdevtestdata/sys/class/net"

int
virNetDevSysfsFile(char **pf_sysfs_device_link,
                   const char *ifname,
                   const char *file)
{
    *pf_sysfs_device_link = g_strdup_printf("%s/%s/%s",
                                            NET_DEV_TEST_DATA_PREFIX, ifname, file);
    return 0;
}
#else
/* Nothing to override on non-__linux__ platforms */
#endif
