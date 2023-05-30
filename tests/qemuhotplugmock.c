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

#include "qemu/qemu_command.h"
#include "qemu/qemu_hotplug.h"
#include "qemu/qemu_process.h"
#include "testutilsqemu.h"
#include "conf/domain_conf.h"
#include "virdevmapper.h"
#include "virmock.h"
#include <fcntl.h>

#define LIBVIRT_QEMU_MONITOR_PRIV_H_ALLOW
#include "qemu/qemu_monitor_priv.h"

static bool (*real_virFileExists)(const char *path);

static void
init_syms(void)
{
    if (real_virFileExists)
        return;

    VIR_MOCK_REAL_INIT(virFileExists);
}

unsigned long long
qemuDomainGetUnplugTimeout(virDomainObj *vm)
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
                       GSList **devPaths)
{
    *devPaths = NULL;

    if (STREQ(path, "/dev/mapper/virt")) {
        *devPaths = g_slist_prepend(*devPaths, g_strdup("/dev/block/8:32")); /* /dev/sdc */
        *devPaths = g_slist_prepend(*devPaths, g_strdup("/dev/block/8:16")); /* /dev/sdb */
        *devPaths = g_slist_prepend(*devPaths, g_strdup("/dev/block/8:0")); /* /dev/sda */
    }

    return 0;
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
qemuProcessStartManagedPRDaemon(virDomainObj *vm G_GNUC_UNUSED)
{
    return 0;
}


void
qemuProcessKillManagedPRDaemon(virDomainObj *vm G_GNUC_UNUSED)
{
}

int
qemuVDPAConnect(const char *devicepath G_GNUC_UNUSED)
{
    /* need a valid fd or sendmsg won't work. Just open /dev/null */
    return open("/dev/null", O_RDONLY);
}


int
qemuProcessPrepareHostBackendChardevHotplug(virDomainObj *vm,
                                            virDomainDeviceDef *dev)
{
    return qemuDomainDeviceBackendChardevForeachOne(dev,
                                                    testQemuPrepareHostBackendChardevOne,
                                                    vm);
}


/* we don't really want to send fake FDs across the monitor */
int
qemuMonitorIOWriteWithFD(qemuMonitor *mon,
                         const char *data,
                         size_t len,
                         int fd G_GNUC_UNUSED)
{
    return write(mon->fd, data, len); /* sc_avoid_write */
}
