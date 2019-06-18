/*
 * virscsihost.h: Generic scsi_host management utility functions
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

int virSCSIHostGetUniqueId(const char *sysfs_prefix, int host);

char *virSCSIHostFindByPCI(const char *sysfs_prefix,
                           const char *parentaddr,
                           unsigned int unique_id);

int virSCSIHostGetNumber(const char *adapter_name,
                         unsigned int *result)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

char *virSCSIHostGetNameByParentaddr(unsigned int domain,
                                     unsigned int bus,
                                     unsigned int slot,
                                     unsigned int function,
                                     unsigned int unique_id);
