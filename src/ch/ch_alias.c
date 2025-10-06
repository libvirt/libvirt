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

#include "virstring.h"
#include "virutil.h"

#include "ch_alias.h"

#define VIR_FROM_THIS VIR_FROM_CH
#define CH_NET_ID_PREFIX "net"

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

/**
 * Extract the index number of some device alias
 */
static
int chDomainDeviceAliasIndex(const virDomainDeviceInfo *info,
                             const char *prefix)
{
    int idx;

    if (!info->alias)
        return -1;
    if (!STRPREFIX(info->alias, prefix))
        return -1;

    if (virStrToLong_i(info->alias + strlen(prefix), NULL, 10, &idx) < 0)
        return -1;

    return idx;
}

void chAssignDeviceNetAlias(virDomainDef *def, virDomainNetDef *net)
{
    size_t idx = 0;
    size_t i;

    if (net->info.alias) {
        return;
    }

    for (i = 0; i < def->nnets; i++) {
        int thisidx;

        if ((thisidx = chDomainDeviceAliasIndex(&def->nets[i]->info, CH_NET_ID_PREFIX)) < 0)
            continue;
        if (thisidx >= idx)
            idx = thisidx + 1;
    }

    net->info.alias = g_strdup_printf("%s%lu", CH_NET_ID_PREFIX, idx);
}

int chAssignDeviceAliases(virDomainDef *def)
{
    size_t i;

    for (i = 0; i < def->ndisks; i++) {
        if (chAssignDeviceDiskAlias(def->disks[i]) < 0)
            return -1;
    }

    for (i = 0; i < def->nnets; i++) {
        chAssignDeviceNetAlias(def, def->nets[i]);
    }

    /* TODO: handle other devices */

    return 0;
}
