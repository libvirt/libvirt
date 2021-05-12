/*
 * Copyright Intel Corp. 2020-2021
 *
 * ch_monitor.h: header file for managing Cloud-Hypervisor interactions
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

#include <curl/curl.h>

#include "virobject.h"
#include "domain_conf.h"

#define URL_ROOT "http://localhost/api/v1"
#define URL_VMM_SHUTDOWN "vmm.shutdown"
#define URL_VM_CREATE "vm.create"
#define URL_VM_DELETE "vm.delete"
#define URL_VM_BOOT "vm.boot"
#define URL_VM_SHUTDOWN "vm.shutdown"
#define URL_VM_REBOOT "vm.reboot"
#define URL_VM_Suspend "vm.pause"
#define URL_VM_RESUME "vm.resume"

typedef struct _virCHMonitor virCHMonitor;

struct _virCHMonitor {
    virObjectLockable parent;

    CURL *handle;

    char *socketpath;

    pid_t pid;

    virDomainObj *vm;
};

virCHMonitor *virCHMonitorNew(virDomainObj *vm, const char *socketdir);
void virCHMonitorClose(virCHMonitor *mon);

int virCHMonitorCreateVM(virCHMonitor *mon);
int virCHMonitorBootVM(virCHMonitor *mon);
int virCHMonitorShutdownVM(virCHMonitor *mon);
int virCHMonitorRebootVM(virCHMonitor *mon);
int virCHMonitorSuspendVM(virCHMonitor *mon);
int virCHMonitorResumeVM(virCHMonitor *mon);
