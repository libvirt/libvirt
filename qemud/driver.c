/*
 * driver.c: core driver methods for managing qemu guests
 *
 * Copyright (C) 2006, 2007 Red Hat, Inc.
 * Copyright (C) 2006 Daniel P. Berrange
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <sys/types.h>
#include <sys/poll.h>
#include <dirent.h>
#include <limits.h>
#include <string.h>
#include <stdio.h>
#include <strings.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <libvirt/virterror.h>

#include "internal.h"
#include "driver.h"
#include "config.h"

void qemudReportError(struct qemud_server *server,
                      int code, const char *fmt, ...) {
    va_list args;
    server->errorCode = code;
    if (fmt) {
        va_start(args, fmt);
        vsnprintf(server->errorMessage, QEMUD_MAX_ERROR_LEN-1, fmt, args);
        va_end(args);
    } else {
        server->errorMessage[0] = '\0';
    }
}

int qemudMonitorCommand(struct qemud_server *server ATTRIBUTE_UNUSED,
                        struct qemud_vm *vm,
                        const char *cmd,
                        char **reply) {
    int size = 0;
    char *buf = NULL;
    if (write(vm->monitor, cmd, strlen(cmd)) < 0) {
        return -1;
    }

    *reply = NULL;

    for (;;) {
        struct pollfd fd = { vm->monitor, POLLIN | POLLERR | POLLHUP, 0 };
        char *tmp;

        /* Read all the data QEMU has sent thus far */
        for (;;) {
            char data[1024];
            int got = read(vm->monitor, data, sizeof(data));
            if (got < 0) {
                if (errno == EINTR)
                    continue;
                if (errno == EAGAIN)
                    break;

                free(buf);
                return -1;
            }
            if (!(buf = realloc(buf, size+got+1)))
                return -1;
            memmove(buf+size, data, got);
            buf[size+got] = '\0';
            size += got;
        }
        if (buf)
            QEMUD_DEBUG("Mon [%s]\n", buf);
        /* Look for QEMU prompt to indicate completion */
        if (buf && ((tmp = strstr(buf, "\n(qemu)")) != NULL)) {
            tmp[0] = '\0';
            break;
        }
    pollagain:
        /* Need to wait for more data */
        if (poll(&fd, 1, -1) < 0) {
            if (errno == EINTR)
                goto pollagain;

            free(buf);
            return -1;
        }
    }

    *reply = buf;
    return 0;
}

int qemudGetMemInfo(unsigned int *memory) {
    FILE *meminfo = fopen("/proc/meminfo", "r");
    char line[1024];

    *memory = 0;

    if (!meminfo) {
        return -1;
    }

    /* XXX NUMA and hyperthreads ? */
    while (fgets(line, sizeof(line), meminfo) != NULL) {
        if (!strncmp(line, "MemTotal:", 9)) {
            *memory = (unsigned int)strtol(line + 10, NULL, 10);
        }
    }
    fclose(meminfo);
    return 0;
}

int qemudGetCPUInfo(unsigned int *cpus, unsigned int *mhz,
                    unsigned int *nodes, unsigned int *sockets,
                    unsigned int *cores, unsigned int *threads) {
    FILE *cpuinfo = fopen("/proc/cpuinfo", "r");
    char line[1024];

    *cpus = 0;
    *mhz = 0;
    *nodes = *sockets = *cores = *threads = 1;

    if (!cpuinfo) {
        return -1;
    }

    /* XXX NUMA and hyperthreads ? */
    while (fgets(line, sizeof(line), cpuinfo) != NULL) {
        if (!strncmp(line, "processor\t", 10)) { /* aka a single logical CPU */
            (*cpus)++;
        } else if (!strncmp(line, "cpu MHz\t", 8)) {
            char *offset = index(line, ':');
            if (!offset)
                continue;
            offset++;
            if (!*offset)
                continue;
            *mhz = (unsigned int)strtol(offset, NULL, 10);
        } else if (!strncmp(line, "physical id\t", 12)) { /* aka socket */
            unsigned int id;
            char *offset = index(line, ':');
            if (!offset)
                continue;
            offset++;
            if (!*offset)
                continue;
            id = (unsigned int)strtol(offset, NULL, 10);
            if ((id+1) > *sockets)
                *sockets = (id + 1);
        } else if (!strncmp(line, "cpu cores\t", 9)) { /* aka cores */
            unsigned int id;
            char *offset = index(line, ':');
            if (!offset)
                continue;
            offset++;
            if (!*offset)
                continue;
            id = (unsigned int)strtol(offset, NULL, 10);
            if (id > *cores)
                *cores = id;
        }
    }
    fclose(cpuinfo);

    return 0;
}

static int qemudGetProcessInfo(unsigned long long *cpuTime, int pid) {
    char proc[PATH_MAX];
    FILE *pidinfo;
    unsigned long usertime, systime;

    if (snprintf(proc, sizeof(proc), "/proc/%d/stat", pid) >= (int)sizeof(proc)) {
        return -1;
    }

    if (!(pidinfo = fopen(proc, "r"))) {
        /*printf("cannnot read pid info");*/
        /* VM probably shut down, so fake 0 */
        *cpuTime = 0;
        return 0;
    }

    if (fscanf(pidinfo, "%*d %*s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu %lu", &usertime, &systime) != 2) {
        QEMUD_DEBUG("not enough arg\n");
        return -1;
    }

    /* We got jiffies
     * We want nanoseconds
     * _SC_CLK_TCK is jiffies per second
     * So calulate thus....
     */
    *cpuTime = 1000 * 1000 * 1000 * (usertime + systime) / sysconf(_SC_CLK_TCK);

    QEMUD_DEBUG("Got %lu %lu %lld\n", usertime, systime, *cpuTime);

    fclose(pidinfo);

    return 0;
}

struct qemud_vm *qemudFindVMByID(const struct qemud_server *server, int id) {
    struct qemud_vm *vm = server->activevms;

    while (vm) {
        if (vm->def.id == id)
            return vm;
        vm = vm->next;
    }

    return NULL;
}

struct qemud_vm *qemudFindVMByUUID(const struct qemud_server *server,
                                   const unsigned char *uuid) {
    struct qemud_vm *vm = server->activevms;

    while (vm) {
        if (!memcmp(vm->def.uuid, uuid, QEMUD_UUID_RAW_LEN))
            return vm;
        vm = vm->next;
    }

    vm = server->inactivevms;
    while (vm) {
        if (!memcmp(vm->def.uuid, uuid, QEMUD_UUID_RAW_LEN))
            return vm;
        vm = vm->next;
    }

    return NULL;
}

struct qemud_vm *qemudFindVMByName(const struct qemud_server *server,
                                   const char *name) {
    struct qemud_vm *vm = server->activevms;

    while (vm) {
        if (!strcmp(vm->def.name, name))
            return vm;
        vm = vm->next;
    }

    vm = server->inactivevms;
    while (vm) {
        if (!strcmp(vm->def.name, name))
            return vm;
        vm = vm->next;
    }

    return NULL;
}

int qemudGetVersion(struct qemud_server *server) {
    return server->qemuVersion;
}

int qemudListDomains(struct qemud_server *server, int *ids, int nids) {
    struct qemud_vm *vm = server->activevms;
    int got = 0;
    while (vm && got < nids) {
        ids[got] = vm->def.id;
        vm = vm->next;
        got++;
    }
    return got;
}
int qemudNumDomains(struct qemud_server *server) {
    return server->nactivevms;
}
struct qemud_vm *qemudDomainCreate(struct qemud_server *server, const char *xml) {
    struct qemud_vm *vm;

    if (!(vm = qemudLoadConfigXML(server, NULL, xml, 0))) {
        return NULL;
    }

    if (qemudStartVMDaemon(server, vm) < 0) {
        qemudFreeVM(vm);
        return NULL;
    }

    vm->next = server->activevms;
    server->activevms = vm;
    server->nactivevms++;
    server->nvmfds += 2;

    return vm;
}


int qemudDomainSuspend(struct qemud_server *server, int id) {
    char *info;
    struct qemud_vm *vm = qemudFindVMByID(server, id);
    if (!vm) {
        qemudReportError(server, VIR_ERR_INVALID_DOMAIN, "no domain with matching id %d", id);
        return -1;
    }
    if (vm->pid == -1) {
        qemudReportError(server, VIR_ERR_OPERATION_FAILED, "domain is not running");
        return -1;
    }

    if (qemudMonitorCommand(server, vm, "stop\n", &info) < 0) {
        qemudReportError(server, VIR_ERR_OPERATION_FAILED, "suspend operation failed");
        return -1;
    }
    printf("Reply %s\n", info);
    free(info);
    return 0;
}


int qemudDomainResume(struct qemud_server *server, int id) {
    char *info;
    struct qemud_vm *vm = qemudFindVMByID(server, id);
    if (!vm) {
        qemudReportError(server, VIR_ERR_INVALID_DOMAIN, "no domain with matching id %d", id);
        return -1;
    }
    if (vm->pid == -1) {
        qemudReportError(server, VIR_ERR_OPERATION_FAILED, "domain is not running");
        return -1;
    }
    if (qemudMonitorCommand(server, vm, "cont\n", &info) < 0) {
        qemudReportError(server, VIR_ERR_OPERATION_FAILED, "resume operation failed");
        return -1;
    }
    printf("Reply %s\n", info);
    free(info);
    return -1;
}


int qemudDomainDestroy(struct qemud_server *server, int id) {
    struct qemud_vm *vm = qemudFindVMByID(server, id);
    if (!vm) {
        qemudReportError(server, VIR_ERR_INVALID_DOMAIN, "no domain with matching id %d", id);
        return -1;
    }
    if (vm->pid == -1) {
        qemudReportError(server, VIR_ERR_OPERATION_FAILED, "domain is not running");
        return -1;
    }

    if (qemudShutdownVMDaemon(server, vm) < 0)
        return -1;
    return 0;
}


int qemudDomainGetInfo(struct qemud_server *server, const unsigned char *uuid,
                       int *runstate,
                       unsigned long long *cputime,
                       unsigned long *maxmem,
                       unsigned long *memory,
                       unsigned int *nrVirtCpu) {
    struct qemud_vm *vm = qemudFindVMByUUID(server, uuid);
    if (!vm) {
        qemudReportError(server, VIR_ERR_INVALID_DOMAIN, "no domain with matching uuid");
        return -1;
    }

    if (vm->pid == -1) {
        *runstate = QEMUD_STATE_STOPPED;
    } else {
        /* XXX in future need to add PAUSED */
        *runstate = QEMUD_STATE_RUNNING;
    }

    if (vm->pid == -1) {
        *cputime = 0;
    } else {
        if (qemudGetProcessInfo(cputime, vm->pid) < 0) {
            qemudReportError(server, VIR_ERR_OPERATION_FAILED, "cannot read cputime for domain");
            return -1;
        }
    }

    *maxmem = vm->def.maxmem;
    *memory = vm->def.memory;
    *nrVirtCpu = vm->def.vcpus;
    return 0;
}


int qemudDomainSave(struct qemud_server *server, int id,
                    const char *path ATTRIBUTE_UNUSED) {
    struct qemud_vm *vm = qemudFindVMByID(server, id);
    if (!vm) {
        qemudReportError(server, VIR_ERR_INVALID_DOMAIN, "no domain with matching id %d", id);
        return -1;
    }
    if (vm->pid == -1) {
        qemudReportError(server, VIR_ERR_OPERATION_FAILED, "domain is not running");
        return -1;
    }
    qemudReportError(server, VIR_ERR_OPERATION_FAILED, "save is not supported");
    return -1;
}


int qemudDomainRestore(struct qemud_server *server,
                       const char *path ATTRIBUTE_UNUSED) {
    qemudReportError(server, VIR_ERR_OPERATION_FAILED, "restore is not supported");
    return -1;
}


int qemudDomainDumpXML(struct qemud_server *server, const unsigned char *uuid, char *xml, int xmllen) {
    struct qemud_vm *vm = qemudFindVMByUUID(server, uuid);
    char *vmxml;
    if (!vm) {
        qemudReportError(server, VIR_ERR_INVALID_DOMAIN, "no domain with matching uuid");
        return -1;
    }

    vmxml = qemudGenerateXML(server, vm);
    if (!vmxml)
        return -1;

    strncpy(xml, vmxml, xmllen);
    xml[xmllen-1] = '\0';

    return 0;
}


int qemudListDefinedDomains(struct qemud_server *server, char *const*names, int nnames) {
    struct qemud_vm *vm = server->inactivevms;
    int got = 0;
    while (vm && got < nnames) {
        strncpy(names[got], vm->def.name, QEMUD_MAX_NAME_LEN-1);
        names[got][QEMUD_MAX_NAME_LEN-1] = '\0';
        vm = vm->next;
        got++;
    }
    return got;
}


int qemudNumDefinedDomains(struct qemud_server *server) {
    return server->ninactivevms;
}


int qemudDomainStart(struct qemud_server *server, struct qemud_vm *vm) {
    struct qemud_vm *prev = NULL, *curr = server->inactivevms;
    if (qemudStartVMDaemon(server, vm) < 0) {
        return 1;
    }

    while (curr) {
        if (curr == vm) {
            if (prev)
                prev->next = curr->next;
            else
                server->inactivevms = curr->next;
            server->ninactivevms--;
            break;
        }
        prev = curr;
        curr = curr->next;
    }

    vm->next = server->activevms;
    server->activevms = vm;
    server->nactivevms++;
    server->nvmfds += 2;

    return 0;
}


struct qemud_vm *qemudDomainDefine(struct qemud_server *server, const char *xml) {
    struct qemud_vm *vm;

    if (!(vm = qemudLoadConfigXML(server, NULL, xml, 1))) {
        return NULL;
    }

    vm->next = server->inactivevms;
    server->inactivevms = vm;
    server->ninactivevms++;

    return vm;
}

int qemudDomainUndefine(struct qemud_server *server, const unsigned char *uuid) {
    struct qemud_vm *vm = qemudFindVMByUUID(server, uuid);
    struct qemud_vm *prev = NULL, *curr = server->inactivevms;

    if (!vm) {
        qemudReportError(server, VIR_ERR_INVALID_DOMAIN, "no domain with matching uuid");
        return -1;
    }

    if (vm->pid != -1) {
        qemudReportError(server, VIR_ERR_INTERNAL_ERROR, "cannot delete active domain");
        return -1;
    }

    if (qemudDeleteConfigXML(server, vm) < 0)
        return -1;

    while (curr) {
        if (curr == vm) {
            if (prev) {
                prev->next = curr->next;
            } else {
                server->inactivevms = curr->next;
            }
            server->ninactivevms--;
            break;
        }

        prev = curr;
        curr = curr->next;
    }

    qemudFreeVM(vm);

    return 0;
}


/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
