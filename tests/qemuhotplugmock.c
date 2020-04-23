/*
 * Copyright (C) 2019 IBM Corporation
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

#include "qemu/qemu_hotplug.h"
#include "qemu/qemu_process.h"
#include "conf/domain_conf.h"
#include "virdevmapper.h"
#include "virutil.h"
#include "virmock.h"

static int (*real_virGetDeviceID)(const char *path, int *maj, int *min);
static bool (*real_virFileExists)(const char *path);

static void
init_syms(void)
{
    if (real_virFileExists)
        return;

    VIR_MOCK_REAL_INIT(virGetDeviceID);
    VIR_MOCK_REAL_INIT(virFileExists);
}

unsigned long long
qemuDomainGetUnplugTimeout(virDomainObjPtr vm)
{
    /* Wait only 100ms for DEVICE_DELETED event. Give a greater
     * timeout in case of PSeries guest to be consistent with the
     * original logic. */
    if (qemuDomainIsPSeries(vm->def))
        return 20;
    return 10;
}


int
virDevMapperGetTargets(const char *path,
                       char ***devPaths)
{
    *devPaths = NULL;

    if (STREQ(path, "/dev/mapper/virt")) {
        *devPaths = g_new(char *, 4);
        (*devPaths)[0] = g_strdup("/dev/block/8:0");  /* /dev/sda */
        (*devPaths)[1] = g_strdup("/dev/block/8:16"); /* /dev/sdb */
        (*devPaths)[2] = g_strdup("/dev/block/8:32"); /* /dev/sdc */
        (*devPaths)[3] = NULL;
    }

    return 0;
}


int
virGetDeviceID(const char *path, int *maj, int *min)
{
    init_syms();

    if (STREQ(path, "/dev/mapper/virt")) {
        *maj = 254;
        *min = 0;
        return 0;
    }

    return real_virGetDeviceID(path, maj, min);
}


bool
virFileExists(const char *path)
{
    init_syms();

    if (STREQ(path, "/dev/mapper/virt"))
        return true;

    return real_virFileExists(path);
}


int
qemuProcessStartManagedPRDaemon(virDomainObjPtr vm G_GNUC_UNUSED)
{
    return 0;
}


void
qemuProcessKillManagedPRDaemon(virDomainObjPtr vm G_GNUC_UNUSED)
{
}
