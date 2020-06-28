/*
 * jailhouse_driver.h: Libvirt driver for Jailhouse hypervisor
 *
 * Copyright (C) 2020 Prakhar Bansal
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

#include <linux/types.h>

#include "jailhouse_api.h"

int jailhouseRegister(void);

#define JAILHOUSE_CONFIG_FILE SYSCONFDIR "/libvirt/jailhouse/jailhouse.conf"
#define JAILHOUSE_STATE_DIR RUNSTATEDIR "/libvirt/jailhouse"

#define JAILHOUSE_DEV "/dev/jailhouse"

#define JAILHOUSE_SYSFS_DEV "/sys/devices/jailhouse/"

typedef struct _virJailhouseDriver virJailhouseDriver;
typedef virJailhouseDriver *virJailhouseDriverPtr;

typedef struct _virJailhouseDriverConfig virJailhouseDriverConfig;
typedef virJailhouseDriverConfig *virJailhouseDriverConfigPtr;

struct _virJailhouseDriverConfig {
    virObject parent;

    char *stateDir;

    // File path of the jailhouse system configuration
    // for jailhouse enable/disable.
    char *sys_config_file_path;

    // Config directory where all jailhouse cell configurations
    // are stored.
    char *cell_config_dir;
};

struct _virJailhouseDriver {
    virMutex lock;

    // Jailhouse configuration read from the jailhouse.conf
    virJailhouseDriverConfigPtr config;

    /* pid file FD, ensures two copies of the driver can't use the same root */
    int lockFD;

    // All the cells created during connect open on the hypervisor.
    virJailhouseCellInfoPtr *cell_info_list;
};

struct _jailhouseCell {
    __s32 id;
    char *state;
    char *cpus_assigned_list;
    char *cpus_failed_list;
};
