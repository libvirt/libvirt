/*
 * ch_alias.c: CH device alias handling
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

#include "virutil.h"

#include "ch_alias.h"

#define VIR_FROM_THIS VIR_FROM_CH

int chAssignDeviceDiskAlias(virDomainDiskDef *disk)
{
    const char *prefix = virDomainDiskBusTypeToString(disk->bus);
    int idx = -1;

    if (disk->info.alias) {
        return 0;
    }

    idx = virDiskNameToIndex(disk->dst);

    if (idx < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not get index of disk '%1$s'"),
                       disk->dst);
        return -1;
    }

    disk->info.alias = g_strdup_printf("%s-disk%d", prefix, idx);

    return 0;
}

int chAssignDeviceAliases(virDomainDef *def)
{
    size_t i;

    for (i = 0; i < def->ndisks; i++) {
        if (chAssignDeviceDiskAlias(def->disks[i]) < 0)
            return -1;
    }

    /* TODO: handle other devices */

    return 0;
}
