/*
 * ch_hotplug.c: CH device hotplug handling
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

#include "ch_hotplug.h"

#define VIR_FROM_THIS VIR_FROM_CH

int
chDomainAttachDeviceLiveAndUpdateConfig(virDomainObj *vm G_GNUC_UNUSED,
                                        virCHDriver *driver G_GNUC_UNUSED,
                                        const char *xml G_GNUC_UNUSED,
                                        unsigned int flags)
{
    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

    return -1;
}
