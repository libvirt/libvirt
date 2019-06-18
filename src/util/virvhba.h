/*
 * virvhba.h: Generic vHBA management utility functions
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

#pragma once

#include "internal.h"

enum {
    VPORT_CREATE,
    VPORT_DELETE,
};

bool
virVHBAPathExists(const char *sysfs_prefix, int host);

bool
virVHBAIsVportCapable(const char *sysfs_prefix, int host);

char *
virVHBAGetConfig(const char *sysfs_prefix,
                 int host,
                 const char *entry)
    ATTRIBUTE_NONNULL(3);

char *
virVHBAFindVportHost(const char *sysfs_prefix);

int
virVHBAManageVport(const int parent_host,
                   const char *wwpn,
                   const char *wwnn,
                   int operation)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);

char *
virVHBAGetHostByWWN(const char *sysfs_prefix,
                    const char *wwnn,
                    const char *wwpn)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);

char *
virVHBAGetHostByFabricWWN(const char *sysfs_prefix,
                          const char *fabric_wwn)
    ATTRIBUTE_NONNULL(2);
