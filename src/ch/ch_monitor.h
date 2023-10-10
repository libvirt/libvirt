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
#include "virjson.h"
#include "domain_conf.h"
#include "ch_conf.h"

#define URL_ROOT "http://localhost/api/v1"
#define URL_VMM_SHUTDOWN "vmm.shutdown"
#define URL_VM_CREATE "vm.create"
#define URL_VM_DELETE "vm.delete"
#define URL_VM_BOOT "vm.boot"
#define URL_VM_SHUTDOWN "vm.shutdown"
#define URL_VM_REBOOT "vm.reboot"
#define URL_VM_Suspend "vm.pause"
#define URL_VM_RESUME "vm.resume"
#define URL_VM_INFO "vm.info"

#define VIRCH_THREAD_NAME_LEN   16

typedef enum {
    virCHThreadTypeEmulator,
    virCHThreadTypeVcpu,
    virCHThreadTypeIO,
    virCHThreadTypeMax
} virCHThreadType;

typedef struct _virCHMonitorCPUInfo virCHMonitorCPUInfo;

struct _virCHMonitorCPUInfo {
    int cpuid;
    pid_t tid;

    bool online;
};

typedef struct _virCHMonitorEmuThreadInfo virCHMonitorEmuThreadInfo;

struct _virCHMonitorEmuThreadInfo {
    char    thrName[VIRCH_THREAD_NAME_LEN];
    pid_t   tid;
};

typedef struct _virCHMonitorIOThreadInfo virCHMonitorIOThreadInfo;

struct _virCHMonitorIOThreadInfo {
    char    thrName[VIRCH_THREAD_NAME_LEN];
    pid_t   tid;
};

typedef struct _virCHMonitorThreadInfo virCHMonitorThreadInfo;

struct _virCHMonitorThreadInfo {
    virCHThreadType type;

    union {
        virCHMonitorCPUInfo vcpuInfo;
        virCHMonitorEmuThreadInfo emuInfo;
        virCHMonitorIOThreadInfo ioInfo;
    };
};

typedef struct _virCHMonitor virCHMonitor;

struct _virCHMonitor {
    virObjectLockable parent;

    CURL *handle;

    char *socketpath;

    pid_t pid;

    virDomainObj *vm;

    size_t nthreads;
    virCHMonitorThreadInfo *threads;
};

virCHMonitor *virCHMonitorNew(virDomainObj *vm, const char *socketdir);
void virCHMonitorClose(virCHMonitor *mon);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(virCHMonitor, virCHMonitorClose);


int virCHMonitorCreateVM(virCHDriver *driver,
                         virCHMonitor *mon,
                         size_t *nnicindexes,
                         int **nicindexes);
int virCHMonitorBootVM(virCHMonitor *mon);
int virCHMonitorShutdownVM(virCHMonitor *mon);
int virCHMonitorRebootVM(virCHMonitor *mon);
int virCHMonitorSuspendVM(virCHMonitor *mon);
int virCHMonitorResumeVM(virCHMonitor *mon);
int virCHMonitorGetInfo(virCHMonitor *mon, virJSONValue **info);

void virCHMonitorCPUInfoFree(virCHMonitorCPUInfo *cpus);
int virCHMonitorGetCPUInfo(virCHMonitor *mon,
                           virCHMonitorCPUInfo **vcpus,
                           size_t maxvcpus);
size_t virCHMonitorGetThreadInfo(virCHMonitor *mon, bool refresh,
                                 virCHMonitorThreadInfo **threads);
int virCHMonitorGetIOThreads(virCHMonitor *mon,
                             virDomainIOThreadInfo ***iothreads);
