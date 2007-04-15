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

#include <config.h>

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
#include "conf.h"

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

            if (got == 0) {
                if (buf)
                    free(buf);
                return -1;
            }
            if (got < 0) {
                if (errno == EINTR)
                    continue;
                if (errno == EAGAIN)
                    break;

                if (buf)
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
            qemudDebug("Mon [%s]", buf);
        /* Look for QEMU prompt to indicate completion */
        if (buf && ((tmp = strstr(buf, "\n(qemu) ")) != NULL)) {
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
    unsigned long long usertime, systime;

    if (snprintf(proc, sizeof(proc), "/proc/%d/stat", pid) >= (int)sizeof(proc)) {
        return -1;
    }

    if (!(pidinfo = fopen(proc, "r"))) {
        /*printf("cannnot read pid info");*/
        /* VM probably shut down, so fake 0 */
        *cpuTime = 0;
        return 0;
    }

    if (fscanf(pidinfo, "%*d %*s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %llu %llu", &usertime, &systime) != 2) {
        qemudDebug("not enough arg");
        return -1;
    }

    /* We got jiffies
     * We want nanoseconds
     * _SC_CLK_TCK is jiffies per second
     * So calulate thus....
     */
    *cpuTime = 1000ull * 1000ull * 1000ull * (usertime + systime) / (unsigned long long)sysconf(_SC_CLK_TCK);

    qemudDebug("Got %llu %llu %llu", usertime, systime, *cpuTime);

    fclose(pidinfo);

    return 0;
}

struct qemud_vm *qemudFindVMByID(const struct qemud_server *server, int id) {
    struct qemud_vm *vm = server->vms;

    while (vm) {
        if (qemudIsActiveVM(vm) && vm->id == id)
            return vm;
        vm = vm->next;
    }

    return NULL;
}

struct qemud_vm *qemudFindVMByUUID(const struct qemud_server *server,
                                   const unsigned char *uuid) {
    struct qemud_vm *vm = server->vms;

    while (vm) {
        if (!memcmp(vm->def->uuid, uuid, QEMUD_UUID_RAW_LEN))
            return vm;
        vm = vm->next;
    }

    return NULL;
}

struct qemud_vm *qemudFindVMByName(const struct qemud_server *server,
                                   const char *name) {
    struct qemud_vm *vm = server->vms;

    while (vm) {
        if (!strcmp(vm->def->name, name))
            return vm;
        vm = vm->next;
    }

    return NULL;
}

int qemudGetVersion(struct qemud_server *server) {
    if (qemudExtractVersion(server) < 0)
        return -1;

    return server->qemuVersion;
}

int qemudListDomains(struct qemud_server *server, int *ids, int nids) {
    struct qemud_vm *vm = server->vms;
    int got = 0;
    while (vm && got < nids) {
        if (qemudIsActiveVM(vm)) {
            ids[got] = vm->id;
            got++;
        }
        vm = vm->next;
    }
    return got;
}
int qemudNumDomains(struct qemud_server *server) {
    return server->nactivevms;
}
struct qemud_vm *qemudDomainCreate(struct qemud_server *server, const char *xml) {

    struct qemud_vm_def *def;
    struct qemud_vm *vm;

    if (!(def = qemudParseVMDef(server, xml, NULL)))
        return NULL;

    if (!(vm = qemudAssignVMDef(server, def))) {
        qemudFreeVMDef(def);
        return NULL;
    }

    if (qemudStartVMDaemon(server, vm) < 0) {
        qemudRemoveInactiveVM(server, vm);
        return NULL;
    }

    return vm;
}


int qemudDomainSuspend(struct qemud_server *server, int id) {
    char *info;
    struct qemud_vm *vm = qemudFindVMByID(server, id);
    if (!vm) {
        qemudReportError(server, VIR_ERR_INVALID_DOMAIN, "no domain with matching id %d", id);
        return -1;
    }
    if (!qemudIsActiveVM(vm)) {
        qemudReportError(server, VIR_ERR_OPERATION_FAILED, "domain is not running");
        return -1;
    }
    if (vm->state == QEMUD_STATE_PAUSED)
        return 0;

    if (qemudMonitorCommand(server, vm, "stop\n", &info) < 0) {
        qemudReportError(server, VIR_ERR_OPERATION_FAILED, "suspend operation failed");
        return -1;
    }
    vm->state = QEMUD_STATE_PAUSED;
    qemudDebug("Reply %s", info);
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
    if (!qemudIsActiveVM(vm)) {
        qemudReportError(server, VIR_ERR_OPERATION_FAILED, "domain is not running");
        return -1;
    }
    if (vm->state == QEMUD_STATE_RUNNING)
        return 0;
    if (qemudMonitorCommand(server, vm, "cont\n", &info) < 0) {
        qemudReportError(server, VIR_ERR_OPERATION_FAILED, "resume operation failed");
        return -1;
    }
    vm->state = QEMUD_STATE_RUNNING;
    qemudDebug("Reply %s", info);
    free(info);
    return 0;
}


int qemudDomainDestroy(struct qemud_server *server, int id) {
    struct qemud_vm *vm = qemudFindVMByID(server, id);

    if (!vm) {
        qemudReportError(server, VIR_ERR_INVALID_DOMAIN,
                         "no domain with matching id %d", id);
        return -1;
    }

    return qemudShutdownVMDaemon(server, vm);
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

    *runstate = vm->state;

    if (!qemudIsActiveVM(vm)) {
        *cputime = 0;
    } else {
        if (qemudGetProcessInfo(cputime, vm->pid) < 0) {
            qemudReportError(server, VIR_ERR_OPERATION_FAILED, "cannot read cputime for domain");
            return -1;
        }
    }

    *maxmem = vm->def->maxmem;
    *memory = vm->def->memory;
    *nrVirtCpu = vm->def->vcpus;
    return 0;
}


int qemudDomainSave(struct qemud_server *server, int id,
                    const char *path ATTRIBUTE_UNUSED) {
    struct qemud_vm *vm = qemudFindVMByID(server, id);
    if (!vm) {
        qemudReportError(server, VIR_ERR_INVALID_DOMAIN, "no domain with matching id %d", id);
        return -1;
    }
    if (!qemudIsActiveVM(vm)) {
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

    vmxml = qemudGenerateXML(server, vm, vm->def, 1);
    if (!vmxml)
        return -1;

    strncpy(xml, vmxml, xmllen);
    xml[xmllen-1] = '\0';

    free(vmxml);

    return 0;
}


int qemudListDefinedDomains(struct qemud_server *server, char *const*names, int nnames) {
    struct qemud_vm *vm = server->vms;
    int got = 0;
    while (vm && got < nnames) {
        if (!qemudIsActiveVM(vm)) {
            strncpy(names[got], vm->def->name, QEMUD_MAX_NAME_LEN-1);
            names[got][QEMUD_MAX_NAME_LEN-1] = '\0';
            got++;
        }
        vm = vm->next;
    }
    return got;
}


int qemudNumDefinedDomains(struct qemud_server *server) {
    return server->ninactivevms;
}


struct qemud_vm *qemudDomainStart(struct qemud_server *server, const unsigned char *uuid) {
    struct qemud_vm *vm = qemudFindVMByUUID(server, uuid);

    if (!vm) {
        qemudReportError(server, VIR_ERR_INVALID_DOMAIN,
                         "no domain with matching uuid");
        return NULL;
    }

    return qemudStartVMDaemon(server, vm) < 0 ? NULL : vm;
}


struct qemud_vm *qemudDomainDefine(struct qemud_server *server, const char *xml) {
    struct qemud_vm_def *def;
    struct qemud_vm *vm;

    if (!(def = qemudParseVMDef(server, xml, NULL)))
        return NULL;

    if (!(vm = qemudAssignVMDef(server, def))) {
        qemudFreeVMDef(def);
        return NULL;
    }

    if (qemudSaveVMDef(server, vm, def) < 0) {
        qemudRemoveInactiveVM(server, vm);
        return NULL;
    }

    return vm;
}

int qemudDomainUndefine(struct qemud_server *server, const unsigned char *uuid) {
    struct qemud_vm *vm = qemudFindVMByUUID(server, uuid);

    if (!vm) {
        qemudReportError(server, VIR_ERR_INVALID_DOMAIN, "no domain with matching uuid");
        return -1;
    }

    if (qemudIsActiveVM(vm)) {
        qemudReportError(server, VIR_ERR_INTERNAL_ERROR, "cannot delete active domain");
        return -1;
    }

    if (qemudDeleteConfig(server, vm->configFile, vm->def->name) < 0)
        return -1;

    if (unlink(vm->autostartLink) < 0 && errno != ENOENT && errno != ENOTDIR)
        qemudLog(QEMUD_WARN, "Failed to delete autostart link '%s': %s",
                 vm->autostartLink, strerror(errno));

    vm->configFile[0] = '\0';
    vm->autostartLink[0] = '\0';

    qemudRemoveInactiveVM(server, vm);

    return 0;
}

int qemudDomainGetAutostart(struct qemud_server *server,
                             const unsigned char *uuid,
                             int *autostart) {
    struct qemud_vm *vm = qemudFindVMByUUID(server, uuid);

    if (!vm) {
        qemudReportError(server, VIR_ERR_INVALID_DOMAIN, "no domain with matching uuid");
        return -1;
    }

    *autostart = vm->autostart;

    return 0;
}

int qemudDomainSetAutostart(struct qemud_server *server,
                             const unsigned char *uuid,
                             int autostart) {
    struct qemud_vm *vm = qemudFindVMByUUID(server, uuid);

    if (!vm) {
        qemudReportError(server, VIR_ERR_INVALID_DOMAIN, "no domain with matching uuid");
        return -1;
    }

    autostart = (autostart != 0);

    if (vm->autostart == autostart)
        return 0;

    if (autostart) {
        int err;

        if ((err = qemudEnsureDir(server->autostartDir))) {
            qemudReportError(server, VIR_ERR_INTERNAL_ERROR,
                             "cannot create autostart directory %s: %s",
                             server->autostartDir, strerror(err));
            return -1;
        }

        if (symlink(vm->configFile, vm->autostartLink) < 0) {
            qemudReportError(server, VIR_ERR_INTERNAL_ERROR,
                             "Failed to create symlink '%s' to '%s': %s",
                             vm->autostartLink, vm->configFile, strerror(errno));
            return -1;
        }
    } else {
        if (unlink(vm->autostartLink) < 0 && errno != ENOENT && errno != ENOTDIR) {
            qemudReportError(server, VIR_ERR_INTERNAL_ERROR,
                             "Failed to delete symlink '%s': %s",
                             vm->autostartLink, strerror(errno));
            return -1;
        }
    }

    vm->autostart = autostart;

    return 0;
}

struct qemud_network *qemudFindNetworkByUUID(const struct qemud_server *server,
                                             const unsigned char *uuid) {
    struct qemud_network *network = server->networks;

    while (network) {
        if (!memcmp(network->def->uuid, uuid, QEMUD_UUID_RAW_LEN))
            return network;
        network = network->next;
    }

    return NULL;
}

struct qemud_network *qemudFindNetworkByName(const struct qemud_server *server,
                                             const char *name) {
    struct qemud_network *network = server->networks;

    while (network) {
        if (!strcmp(network->def->name, name))
            return network;
        network = network->next;
    }

    return NULL;
}

int qemudNumNetworks(struct qemud_server *server) {
    return server->nactivenetworks;
}

int qemudListNetworks(struct qemud_server *server, char *const*names, int nnames) {
    struct qemud_network *network = server->networks;
    int got = 0;
    while (network && got < nnames) {
        if (qemudIsActiveNetwork(network)) {
            strncpy(names[got], network->def->name, QEMUD_MAX_NAME_LEN-1);
            names[got][QEMUD_MAX_NAME_LEN-1] = '\0';
            got++;
        }
        network = network->next;
    }
    return got;
}

int qemudNumDefinedNetworks(struct qemud_server *server) {
    return server->ninactivenetworks;
}

int qemudListDefinedNetworks(struct qemud_server *server, char *const*names, int nnames) {
    struct qemud_network *network = server->networks;
    int got = 0;
    while (network && got < nnames) {
        if (!qemudIsActiveNetwork(network)) {
            strncpy(names[got], network->def->name, QEMUD_MAX_NAME_LEN-1);
            names[got][QEMUD_MAX_NAME_LEN-1] = '\0';
            got++;
        }
        network = network->next;
    }
    return got;
}

struct qemud_network *qemudNetworkCreate(struct qemud_server *server, const char *xml) {
    struct qemud_network_def *def;
    struct qemud_network *network;

    if (!(def = qemudParseNetworkDef(server, xml, NULL)))
        return NULL;

    if (!(network = qemudAssignNetworkDef(server, def))) {
        qemudFreeNetworkDef(def);
        return NULL;
    }

    if (qemudStartNetworkDaemon(server, network) < 0) {
        qemudRemoveInactiveNetwork(server, network);
        return NULL;
    }

    return network;
}

struct qemud_network *qemudNetworkDefine(struct qemud_server *server, const char *xml) {
    struct qemud_network_def *def;
    struct qemud_network *network;

    if (!(def = qemudParseNetworkDef(server, xml, NULL)))
        return NULL;

    if (!(network = qemudAssignNetworkDef(server, def))) {
        qemudFreeNetworkDef(def);
        return NULL;
    }

    if (qemudSaveNetworkDef(server, network, def) < 0) {
        qemudRemoveInactiveNetwork(server, network);
        return NULL;
    }

    return network;
}

int qemudNetworkUndefine(struct qemud_server *server, const unsigned char *uuid) {
    struct qemud_network *network = qemudFindNetworkByUUID(server, uuid);

    if (!network) {
        qemudReportError(server, VIR_ERR_INVALID_DOMAIN, "no network with matching uuid");
        return -1;
    }

    if (qemudDeleteConfig(server, network->configFile, network->def->name) < 0)
        return -1;

    if (unlink(network->autostartLink) < 0 && errno != ENOENT && errno != ENOTDIR)
        qemudLog(QEMUD_WARN, "Failed to delete autostart link '%s': %s",
                 network->autostartLink, strerror(errno));

    network->configFile[0] = '\0';
    network->autostartLink[0] = '\0';

    qemudRemoveInactiveNetwork(server, network);

    return 0;
}

struct qemud_network *qemudNetworkStart(struct qemud_server *server, const unsigned char *uuid) {
    struct qemud_network *network = qemudFindNetworkByUUID(server, uuid);

    if (!network) {
        qemudReportError(server, VIR_ERR_INVALID_NETWORK,
                         "no network with matching uuid");
        return NULL;
    }

    return qemudStartNetworkDaemon(server, network) < 0 ? NULL : network;
}

int qemudNetworkDestroy(struct qemud_server *server, const unsigned char *uuid) {
    struct qemud_network *network = qemudFindNetworkByUUID(server, uuid);

    if (!network) {
        qemudReportError(server, VIR_ERR_INVALID_NETWORK,
                         "no network with matching uuid");
        return -1;
    }

    return qemudShutdownNetworkDaemon(server, network);
}

int qemudNetworkDumpXML(struct qemud_server *server, const unsigned char *uuid, char *xml, int xmllen) {
    struct qemud_network *network = qemudFindNetworkByUUID(server, uuid);
    char *networkxml;
    if (!network) {
        qemudReportError(server, VIR_ERR_INVALID_NETWORK, "no network with matching uuid");
        return -1;
    }

    networkxml = qemudGenerateNetworkXML(server, network, network->def);
    if (!networkxml)
        return -1;

    strncpy(xml, networkxml, xmllen);
    xml[xmllen-1] = '\0';

    free(networkxml);

    return 0;
}

int qemudNetworkGetBridgeName(struct qemud_server *server, const unsigned char *uuid, char *ifname, int ifnamelen) {
    struct qemud_network *network = qemudFindNetworkByUUID(server, uuid);

    if (!network) {
        qemudReportError(server, VIR_ERR_INVALID_NETWORK, "no network with matching id");
        return -1;
    }

    strncpy(ifname, network->bridge, ifnamelen);
    ifname[ifnamelen-1] = '\0';

    return 0;
}

int qemudNetworkGetAutostart(struct qemud_server *server,
                             const unsigned char *uuid,
                             int *autostart) {
    struct qemud_network *network = qemudFindNetworkByUUID(server, uuid);

    if (!network) {
        qemudReportError(server, VIR_ERR_INVALID_NETWORK, "no network with matching uuid");
        return -1;
    }

    *autostart = network->autostart;

    return 0;
}

int qemudNetworkSetAutostart(struct qemud_server *server,
                             const unsigned char *uuid,
                             int autostart) {
    struct qemud_network *network = qemudFindNetworkByUUID(server, uuid);

    if (!network) {
        qemudReportError(server, VIR_ERR_INVALID_NETWORK, "no network with matching uuid");
        return -1;
    }

    autostart = (autostart != 0);

    if (network->autostart == autostart)
        return 0;

    if (autostart) {
        int err;

        if ((err = qemudEnsureDir(server->networkAutostartDir))) {
            qemudReportError(server, VIR_ERR_INTERNAL_ERROR,
                             "cannot create autostart directory %s: %s",
                             server->networkAutostartDir, strerror(err));
            return -1;
        }

        if (symlink(network->configFile, network->autostartLink) < 0) {
            qemudReportError(server, VIR_ERR_INTERNAL_ERROR,
                             "Failed to create symlink '%s' to '%s': %s",
                             network->autostartLink, network->configFile, strerror(errno));
            return -1;
        }
    } else {
        if (unlink(network->autostartLink) < 0 && errno != ENOENT && errno != ENOTDIR) {
            qemudReportError(server, VIR_ERR_INTERNAL_ERROR,
                             "Failed to delete symlink '%s': %s",
                             network->autostartLink, strerror(errno));
            return -1;
        }
    }

    network->autostart = autostart;

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
