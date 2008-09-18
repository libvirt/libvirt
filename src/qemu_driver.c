/*
 * driver.c: core driver methods for managing qemu guests
 *
 * Copyright (C) 2006, 2007, 2008 Red Hat, Inc.
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
#include <sys/utsname.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <paths.h>
#include <pwd.h>
#include <stdio.h>
#include <sys/wait.h>
#include <sys/ioctl.h>

#if HAVE_NUMACTL
#include <numa.h>
#endif

#if HAVE_SCHED_H
#include <sched.h>
#endif

#include "qemu_driver.h"
#include "qemu_conf.h"
#include "c-ctype.h"
#include "event.h"
#include "buf.h"
#include "util.h"
#include "nodeinfo.h"
#include "stats_linux.h"
#include "capabilities.h"
#include "memory.h"
#include "uuid.h"
#include "domain_conf.h"

/* For storing short-lived temporary files. */
#define TEMPDIR LOCAL_STATE_DIR "/cache/libvirt"

#ifdef WITH_LIBVIRTD
static int qemudShutdown(void);
#endif

/* qemudDebug statements should be changed to use this macro instead. */
#define DEBUG(fmt,...) VIR_DEBUG(__FILE__, fmt, __VA_ARGS__)
#define DEBUG0(msg) VIR_DEBUG(__FILE__, "%s", msg)

#define qemudLog(level, msg...) fprintf(stderr, msg)

static int qemudSetCloseExec(int fd) {
    int flags;
    if ((flags = fcntl(fd, F_GETFD)) < 0)
        goto error;
    flags |= FD_CLOEXEC;
    if ((fcntl(fd, F_SETFD, flags)) < 0)
        goto error;
    return 0;
 error:
    qemudLog(QEMUD_ERR,
             "%s", _("Failed to set close-on-exec file descriptor flag\n"));
    return -1;
}


static int qemudSetNonBlock(int fd) {
    int flags;
    if ((flags = fcntl(fd, F_GETFL)) < 0)
        goto error;
    flags |= O_NONBLOCK;
    if ((fcntl(fd, F_SETFL, flags)) < 0)
        goto error;
    return 0;
 error:
    qemudLog(QEMUD_ERR,
             "%s", _("Failed to set non-blocking file descriptor flag\n"));
    return -1;
}


static void qemudDispatchVMEvent(int fd, int events, void *opaque);
static int qemudStartVMDaemon(virConnectPtr conn,
                              struct qemud_driver *driver,
                              virDomainObjPtr vm,
                              const char *migrateFrom);

static void qemudShutdownVMDaemon(virConnectPtr conn,
                                  struct qemud_driver *driver,
                                  virDomainObjPtr vm);

static int qemudStartNetworkDaemon(virConnectPtr conn,
                                   struct qemud_driver *driver,
                                   virNetworkObjPtr network);

static int qemudShutdownNetworkDaemon(virConnectPtr conn,
                                      struct qemud_driver *driver,
                                      virNetworkObjPtr network);

static int qemudDomainGetMaxVcpus(virDomainPtr dom);
static int qemudMonitorCommand (const struct qemud_driver *driver,
                                const virDomainObjPtr vm,
                                const char *cmd,
                                char **reply);

static struct qemud_driver *qemu_driver = NULL;


static
void qemudAutostartConfigs(struct qemud_driver *driver) {
    virNetworkObjPtr network;
    virDomainObjPtr vm;

    network = driver->networks;
    while (network != NULL) {
        virNetworkObjPtr next = network->next;

        if (network->autostart &&
            !virNetworkIsActive(network) &&
            qemudStartNetworkDaemon(NULL, driver, network) < 0) {
            virErrorPtr err = virGetLastError();
            qemudLog(QEMUD_ERR, _("Failed to autostart network '%s': %s\n"),
                     network->def->name, err->message);
        }

        network = next;
    }

    vm = driver->domains;
    while (vm != NULL) {
        virDomainObjPtr next = vm->next;

        if (vm->autostart &&
            !virDomainIsActive(vm) &&
            qemudStartVMDaemon(NULL, driver, vm, NULL) < 0) {
            virErrorPtr err = virGetLastError();
            qemudLog(QEMUD_ERR, _("Failed to autostart VM '%s': %s\n"),
                     vm->def->name, err->message);
        }

        vm = next;
    }
}

#ifdef WITH_LIBVIRTD
/**
 * qemudStartup:
 *
 * Initialization function for the QEmu daemon
 */
static int
qemudStartup(void) {
    uid_t uid = geteuid();
    struct passwd *pw;
    char *base = NULL;
    char driverConf[PATH_MAX];

    if (VIR_ALLOC(qemu_driver) < 0)
        return -1;

    /* Don't have a dom0 so start from 1 */
    qemu_driver->nextvmid = 1;

    if (!uid) {
        if (asprintf(&qemu_driver->logDir,
                     "%s/log/libvirt/qemu", LOCAL_STATE_DIR) == -1)
            goto out_of_memory;

        if ((base = strdup (SYSCONF_DIR "/libvirt")) == NULL)
            goto out_of_memory;
    } else {
        if (!(pw = getpwuid(uid))) {
            qemudLog(QEMUD_ERR, _("Failed to find user record for uid '%d': %s\n"),
                     uid, strerror(errno));
            goto out_of_memory;
        }

        if (asprintf(&qemu_driver->logDir,
                     "%s/.libvirt/qemu/log", pw->pw_dir) == -1)
            goto out_of_memory;

        if (asprintf (&base, "%s/.libvirt", pw->pw_dir) == -1) {
            qemudLog (QEMUD_ERR,
                      "%s", _("out of memory in asprintf\n"));
            goto out_of_memory;
        }
    }

    /* Configuration paths are either ~/.libvirt/qemu/... (session) or
     * /etc/libvirt/qemu/... (system).
     */
    if (snprintf (driverConf, sizeof(driverConf), "%s/qemu.conf", base) == -1)
        goto out_of_memory;
    driverConf[sizeof(driverConf)-1] = '\0';

    if (asprintf (&qemu_driver->configDir, "%s/qemu", base) == -1)
        goto out_of_memory;

    if (asprintf (&qemu_driver->autostartDir, "%s/qemu/autostart", base) == -1)
        goto out_of_memory;

    if (asprintf (&qemu_driver->networkConfigDir, "%s/qemu/networks", base) == -1)
        goto out_of_memory;

    if (asprintf (&qemu_driver->networkAutostartDir, "%s/qemu/networks/autostart",
                  base) == -1)
        goto out_of_memory;

    VIR_FREE(base);

    if ((qemu_driver->caps = qemudCapsInit()) == NULL)
        goto out_of_memory;

    if (qemudLoadDriverConfig(qemu_driver, driverConf) < 0) {
        qemudShutdown();
        return -1;
    }

    if (virDomainLoadAllConfigs(NULL,
                                qemu_driver->caps,
                                &qemu_driver->domains,
                                qemu_driver->configDir,
                                qemu_driver->autostartDir) < 0) {
        qemudShutdown();
        return -1;
    }
    if (virNetworkLoadAllConfigs(NULL,
                                 &qemu_driver->networks,
                                 qemu_driver->networkConfigDir,
                                 qemu_driver->networkAutostartDir) < 0) {
        qemudShutdown();
        return -1;
    }
    qemudAutostartConfigs(qemu_driver);

    return 0;

 out_of_memory:
    qemudLog (QEMUD_ERR,
              "%s", _("qemudStartup: out of memory\n"));
    VIR_FREE(base);
    VIR_FREE(qemu_driver);
    return -1;
}

/**
 * qemudReload:
 *
 * Function to restart the QEmu daemon, it will recheck the configuration
 * files and update its state and the networking
 */
static int
qemudReload(void) {
    virDomainLoadAllConfigs(NULL,
                            qemu_driver->caps,
                            &qemu_driver->domains,
                            qemu_driver->configDir,
                            qemu_driver->autostartDir);

    virNetworkLoadAllConfigs(NULL,
                             &qemu_driver->networks,
                             qemu_driver->networkConfigDir,
                             qemu_driver->networkAutostartDir);

     if (qemu_driver->iptables) {
        qemudLog(QEMUD_INFO,
                 "%s", _("Reloading iptables rules\n"));
        iptablesReloadRules(qemu_driver->iptables);
    }

    qemudAutostartConfigs(qemu_driver);

    return 0;
}

/**
 * qemudActive:
 *
 * Checks if the QEmu daemon is active, i.e. has an active domain or
 * an active network
 *
 * Returns 1 if active, 0 otherwise
 */
static int
qemudActive(void) {
    virDomainObjPtr dom = qemu_driver->domains;
    virNetworkObjPtr net = qemu_driver->networks;

    while (dom) {
        if (virDomainIsActive(dom))
            return 1;
        dom = dom->next;
    }

    while (net) {
        if (virNetworkIsActive(net))
            return 1;
        net = net->next;
    }

    /* Otherwise we're happy to deal with a shutdown */
    return 0;
}

/**
 * qemudShutdown:
 *
 * Shutdown the QEmu daemon, it will stop all active domains and networks
 */
static int
qemudShutdown(void) {
    virDomainObjPtr vm;
    virNetworkObjPtr network;

    if (!qemu_driver)
        return -1;

    virCapabilitiesFree(qemu_driver->caps);

    /* shutdown active VMs */
    vm = qemu_driver->domains;
    while (vm) {
        virDomainObjPtr next = vm->next;
        if (virDomainIsActive(vm))
            qemudShutdownVMDaemon(NULL, qemu_driver, vm);
        if (!vm->persistent)
            virDomainRemoveInactive(&qemu_driver->domains,
                                    vm);
        vm = next;
    }

    /* free inactive VMs */
    vm = qemu_driver->domains;
    while (vm) {
        virDomainObjPtr next = vm->next;
        virDomainObjFree(vm);
        vm = next;
    }
    qemu_driver->domains = NULL;

    /* shutdown active networks */
    network = qemu_driver->networks;
    while (network) {
        virNetworkObjPtr next = network->next;
        if (virNetworkIsActive(network))
            qemudShutdownNetworkDaemon(NULL, qemu_driver, network);
        network = next;
    }

    /* free inactive networks */
    network = qemu_driver->networks;
    while (network) {
        virNetworkObjPtr next = network->next;
        virNetworkObjFree(network);
        network = next;
    }
    qemu_driver->networks = NULL;

    VIR_FREE(qemu_driver->logDir);
    VIR_FREE(qemu_driver->configDir);
    VIR_FREE(qemu_driver->autostartDir);
    VIR_FREE(qemu_driver->networkConfigDir);
    VIR_FREE(qemu_driver->networkAutostartDir);
    VIR_FREE(qemu_driver->vncTLSx509certdir);

    if (qemu_driver->brctl)
        brShutdown(qemu_driver->brctl);
    if (qemu_driver->iptables)
        iptablesContextFree(qemu_driver->iptables);

    VIR_FREE(qemu_driver);

    return 0;
}
#endif

/* Return -1 for error, 1 to continue reading and 0 for success */
typedef int qemudHandlerMonitorOutput(virConnectPtr conn,
                                      struct qemud_driver *driver,
                                      virDomainObjPtr vm,
                                      const char *output,
                                      int fd);

static int
qemudReadMonitorOutput(virConnectPtr conn,
                       struct qemud_driver *driver,
                       virDomainObjPtr vm,
                       int fd,
                       char *buf,
                       int buflen,
                       qemudHandlerMonitorOutput func,
                       const char *what)
{
#define MONITOR_TIMEOUT 3000
    int got = 0;
    buf[0] = '\0';

   /* Consume & discard the initial greeting */
    while (got < (buflen-1)) {
        int ret;

        ret = read(fd, buf+got, buflen-got-1);
        if (ret == 0) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             _("QEMU quit during %s startup\n%s"), what, buf);
            return -1;
        }
        if (ret < 0) {
            struct pollfd pfd = { .fd = fd, .events = POLLIN };
            if (errno == EINTR)
                continue;

            if (errno != EAGAIN) {
                qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                                 _("Failure while reading %s startup output: %s"),
                                 what, strerror(errno));
                return -1;
            }

            ret = poll(&pfd, 1, MONITOR_TIMEOUT);
            if (ret == 0) {
                qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                                 _("Timed out while reading %s startup output"), what);
                return -1;
            } else if (ret == -1) {
                if (errno != EINTR) {
                    qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                                     _("Failure while reading %s startup output: %s"),
                                     what, strerror(errno));
                    return -1;
                }
            } else {
                /* Make sure we continue loop & read any further data
                   available before dealing with EOF */
                if (pfd.revents & (POLLIN | POLLHUP))
                    continue;

                qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                                 _("Failure while reading %s startup output"), what);
                return -1;
            }
        } else {
            got += ret;
            buf[got] = '\0';
            if ((ret = func(conn, driver, vm, buf, fd)) != 1)
                return ret;
        }
    }

    qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                     _("Out of space while reading %s startup output"), what);
    return -1;

#undef MONITOR_TIMEOUT
}

static int
qemudCheckMonitorPrompt(virConnectPtr conn ATTRIBUTE_UNUSED,
                        struct qemud_driver *driver ATTRIBUTE_UNUSED,
                        virDomainObjPtr vm,
                        const char *output,
                        int fd)
{
    if (strstr(output, "(qemu) ") == NULL)
        return 1; /* keep reading */

    vm->monitor = fd;

    return 0;
}

static int qemudOpenMonitor(virConnectPtr conn,
                            struct qemud_driver *driver,
                            virDomainObjPtr vm,
                            const char *monitor) {
    int monfd;
    char buf[1024];
    int ret = -1;

    if ((monfd = open(monitor, O_RDWR)) < 0) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("Unable to open monitor path %s"), monitor);
        return -1;
    }
    if (qemudSetCloseExec(monfd) < 0) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("Unable to set monitor close-on-exec flag"));
        goto error;
    }
    if (qemudSetNonBlock(monfd) < 0) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("Unable to put monitor into non-blocking mode"));
        goto error;
    }

    ret = qemudReadMonitorOutput(conn,
                                 driver, vm, monfd,
                                 buf, sizeof(buf),
                                 qemudCheckMonitorPrompt,
                                 "monitor");

    /* Keep monitor open upon success */
    if (ret == 0)
        return ret;

 error:
    close(monfd);
    return ret;
}

static int qemudExtractMonitorPath(virConnectPtr conn,
                                   const char *haystack,
                                   size_t *offset,
                                   char **path) {
    static const char needle[] = "char device redirected to";
    char *tmp, *dev;

    VIR_FREE(*path);
    /* First look for our magic string */
    if (!(tmp = strstr(haystack + *offset, needle))) {
        return 1;
    }
    tmp += sizeof(needle);
    dev = tmp;

    /*
     * And look for first whitespace character and nul terminate
     * to mark end of the pty path
     */
    while (*tmp) {
        if (c_isspace(*tmp)) {
            if (VIR_ALLOC_N(*path, (tmp-dev)+1) < 0) {
                qemudReportError(conn, NULL, NULL,
                                 VIR_ERR_NO_MEMORY, NULL);
                return -1;
            }
            strncpy(*path, dev, (tmp-dev));
            (*path)[(tmp-dev)] = '\0';
            /* ... now further update offset till we get EOL */
            *offset += tmp - haystack;
            return 0;
        }
        tmp++;
    }

    /*
     * We found a path, but didn't find any whitespace,
     * so it must be still incomplete - we should at
     * least see a \n - indicate that we want to carry
     * on trying again
     */
    return 1;
}

static int
qemudFindCharDevicePTYs(virConnectPtr conn,
                        struct qemud_driver *driver,
                        virDomainObjPtr vm,
                        const char *output,
                        int fd ATTRIBUTE_UNUSED)
{
    char *monitor = NULL;
    size_t offset = 0;
    virDomainChrDefPtr chr;
    int ret;

    /* The order in which QEMU prints out the PTY paths is
       the order in which it procsses its monitor, serial
       and parallel device args. This code must match that
       ordering.... */

    /* So first comes the monitor device */
    if ((ret = qemudExtractMonitorPath(conn, output, &offset, &monitor)) != 0)
        goto cleanup;

    /* then the serial devices */
    chr = vm->def->serials;
    while (chr) {
        if (chr->type == VIR_DOMAIN_CHR_TYPE_PTY) {
            if ((ret = qemudExtractMonitorPath(conn, output, &offset,
                                               &chr->data.file.path)) != 0)
                goto cleanup;
        }
        chr = chr->next;
    }

    /* and finally the parallel devices */
    chr = vm->def->parallels;
    while (chr) {
        if (chr->type == VIR_DOMAIN_CHR_TYPE_PTY) {
            if ((ret = qemudExtractMonitorPath(conn, output, &offset,
                                               &chr->data.file.path)) != 0)
                goto cleanup;
        }
        chr = chr->next;
    }

    /* Got them all, so now open the monitor console */
    ret = qemudOpenMonitor(conn, driver, vm, monitor);

cleanup:
    VIR_FREE(monitor);
    return ret;
}

static int qemudWaitForMonitor(virConnectPtr conn,
                               struct qemud_driver *driver,
                               virDomainObjPtr vm) {
    char buf[1024]; /* Plenty of space to get startup greeting */
    int ret = qemudReadMonitorOutput(conn,
                                     driver, vm, vm->stderr_fd,
                                     buf, sizeof(buf),
                                     qemudFindCharDevicePTYs,
                                     "console");

    buf[sizeof(buf)-1] = '\0';

    if (safewrite(vm->logfile, buf, strlen(buf)) < 0) {
        /* Log, but ignore failures to write logfile for VM */
        qemudLog(QEMUD_WARN, _("Unable to log VM console data: %s\n"),
                 strerror(errno));
    }
    return ret;
}

static int
qemudDetectVcpuPIDs(virConnectPtr conn,
                    struct qemud_driver *driver,
                    virDomainObjPtr vm) {
    char *qemucpus = NULL;
    char *line;
    int lastVcpu = -1;

    /* Only KVM has seperate threads for CPUs,
       others just use main QEMU process for CPU */
    if (vm->def->virtType != VIR_DOMAIN_VIRT_KVM)
        vm->nvcpupids = 1;
    else
        vm->nvcpupids = vm->def->vcpus;

    if (VIR_ALLOC_N(vm->vcpupids, vm->nvcpupids) < 0) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_NO_MEMORY,
                         "%s", _("allocate cpumap"));
        return -1;
    }

    if (vm->def->virtType != VIR_DOMAIN_VIRT_KVM) {
        vm->vcpupids[0] = vm->pid;
        return 0;
    }

    if (qemudMonitorCommand(driver, vm, "info cpus", &qemucpus) < 0) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("cannot run monitor command to fetch CPU thread info"));
        VIR_FREE(vm->vcpupids);
        vm->nvcpupids = 0;
        return -1;
    }

    /*
     * This is the gross format we're about to parse :-{
     *
     * (qemu) info cpus
     * * CPU #0: pc=0x00000000000f0c4a thread_id=30019
     *   CPU #1: pc=0x00000000fffffff0 thread_id=30020
     *   CPU #2: pc=0x00000000fffffff0 thread_id=30021
     *
     */
    line = qemucpus;
    do {
        char *offset = strchr(line, '#');
        char *end = NULL;
        int vcpu = 0, tid = 0;

        /* See if we're all done */
        if (offset == NULL)
            break;

        /* Extract VCPU number */
        if (virStrToLong_i(offset + 1, &end, 10, &vcpu) < 0)
            goto error;
        if (end == NULL || *end != ':')
            goto error;

        /* Extract host Thread ID */
        if ((offset = strstr(line, "thread_id=")) == NULL)
            goto error;
        if (virStrToLong_i(offset + strlen("thread_id="), &end, 10, &tid) < 0)
            goto error;
        if (end == NULL || !c_isspace(*end))
            goto error;

        /* Validate the VCPU is in expected range & order */
        if (vcpu > vm->nvcpupids ||
            vcpu != (lastVcpu + 1))
            goto error;

        lastVcpu = vcpu;
        vm->vcpupids[vcpu] = tid;

        /* Skip to next data line */
        line = strchr(offset, '\r');
        if (line == NULL)
            line = strchr(offset, '\n');
    } while (line != NULL);

    /* Validate we got data for all VCPUs we expected */
    if (lastVcpu != (vm->def->vcpus - 1))
        goto error;

    VIR_FREE(qemucpus);
    return 0;

error:
    VIR_FREE(vm->vcpupids);
    vm->nvcpupids = 0;
    VIR_FREE(qemucpus);

    /* Explicitly return success, not error. Older KVM does
       not have vCPU -> Thread mapping info and we don't
       want to break its use. This merely disables ability
       to pin vCPUS with libvirt */
    return 0;
}

static int
qemudInitCpus(virConnectPtr conn,
              struct qemud_driver *driver,
              virDomainObjPtr vm) {
    char *info = NULL;
#if HAVE_SCHED_GETAFFINITY
    cpu_set_t mask;
    int i, maxcpu = QEMUD_CPUMASK_LEN;
    virNodeInfo nodeinfo;

    if (virNodeInfoPopulate(conn, &nodeinfo) < 0)
        return -1;

    /* setaffinity fails if you set bits for CPUs which
     * aren't present, so we have to limit ourselves */
    if (maxcpu > nodeinfo.cpus)
        maxcpu = nodeinfo.cpus;

    CPU_ZERO(&mask);
    if (vm->def->cpumask) {
        for (i = 0 ; i < maxcpu ; i++)
            if (vm->def->cpumask[i])
                CPU_SET(i, &mask);
    } else {
        for (i = 0 ; i < maxcpu ; i++)
            CPU_SET(i, &mask);
    }

    for (i = 0 ; i < vm->nvcpupids ; i++) {
        if (sched_setaffinity(vm->vcpupids[i],
                              sizeof(mask), &mask) < 0) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             _("failed to set CPU affinity %s"),
                             strerror(errno));
            return -1;
        }
    }
#endif /* HAVE_SCHED_GETAFFINITY */

    /* Allow the CPUS to start executing */
    if (qemudMonitorCommand(driver, vm, "cont", &info) < 0) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("resume operation failed"));
        return -1;
    }
    VIR_FREE(info);

    return 0;
}


static int qemudNextFreeVNCPort(struct qemud_driver *driver ATTRIBUTE_UNUSED) {
    int i;

    for (i = 5900 ; i < 6000 ; i++) {
        int fd;
        int reuse = 1;
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(i);
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        fd = socket(PF_INET, SOCK_STREAM, 0);
        if (fd < 0)
            return -1;

        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void*)&reuse, sizeof(reuse)) < 0) {
            close(fd);
            break;
        }

        if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            /* Not in use, lets grab it */
            close(fd);
            return i;
        }
        close(fd);

        if (errno == EADDRINUSE) {
            /* In use, try next */
            continue;
        }
        /* Some other bad failure, get out.. */
        break;
    }
    return -1;
}

static int qemudStartVMDaemon(virConnectPtr conn,
                              struct qemud_driver *driver,
                              virDomainObjPtr vm,
                              const char *migrateFrom) {
    const char **argv = NULL, **tmp;
    int i, ret;
    char logfile[PATH_MAX];
    struct stat sb;
    int *tapfds = NULL;
    int ntapfds = 0;
    unsigned int qemuCmdFlags;
    fd_set keepfd;
    const char *emulator;

    FD_ZERO(&keepfd);

    if (virDomainIsActive(vm)) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("VM is already active"));
        return -1;
    }

    if (vm->def->graphics &&
        vm->def->graphics->type == VIR_DOMAIN_GRAPHICS_TYPE_VNC &&
        vm->def->graphics->data.vnc.autoport) {
        int port = qemudNextFreeVNCPort(driver);
        if (port < 0) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("Unable to find an unused VNC port"));
            return -1;
        }
        vm->def->graphics->data.vnc.port = port;
    }

    if ((strlen(driver->logDir) + /* path */
         1 + /* Separator */
         strlen(vm->def->name) + /* basename */
         4 + /* suffix .log */
         1 /* NULL */) > PATH_MAX) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("config file path too long: %s/%s.log"),
                         driver->logDir, vm->def->name);
        return -1;
    }
    strcpy(logfile, driver->logDir);
    strcat(logfile, "/");
    strcat(logfile, vm->def->name);
    strcat(logfile, ".log");

    if (virFileMakePath(driver->logDir) < 0) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("cannot create log directory %s: %s"),
                         driver->logDir, strerror(errno));
        return -1;
    }

    if ((vm->logfile = open(logfile, O_CREAT | O_TRUNC | O_WRONLY,
                            S_IRUSR | S_IWUSR)) < 0) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("failed to create logfile %s: %s"),
                         logfile, strerror(errno));
        return -1;
    }
    if (qemudSetCloseExec(vm->logfile) < 0) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("Unable to set VM logfile close-on-exec flag %s"),
                         strerror(errno));
        close(vm->logfile);
        vm->logfile = -1;
        return -1;
    }

    emulator = vm->def->emulator;
    if (!emulator)
        emulator = virDomainDefDefaultEmulator(conn, vm->def, driver->caps);
    if (!emulator)
        return -1;

    /* Make sure the binary we are about to try exec'ing exists.
     * Technically we could catch the exec() failure, but that's
     * in a sub-process so its hard to feed back a useful error
     */
    if (stat(emulator, &sb) < 0) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("Cannot find QEMU binary %s: %s"),
                         emulator,
                         strerror(errno));
        return -1;
    }

    if (qemudExtractVersionInfo(emulator,
                                NULL,
                                &qemuCmdFlags) < 0) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("Cannot determine QEMU argv syntax %s"),
                         emulator);
        return -1;
    }

    if (qemudBuildCommandLine(conn, driver, vm,
                              qemuCmdFlags, &argv,
                              &tapfds, &ntapfds, migrateFrom) < 0) {
        close(vm->logfile);
        vm->logfile = -1;
        return -1;
    }

    tmp = argv;
    while (*tmp) {
        if (safewrite(vm->logfile, *tmp, strlen(*tmp)) < 0)
            qemudLog(QEMUD_WARN, _("Unable to write argv to logfile %d: %s\n"),
                     errno, strerror(errno));
        if (safewrite(vm->logfile, " ", 1) < 0)
            qemudLog(QEMUD_WARN, _("Unable to write argv to logfile %d: %s\n"),
                     errno, strerror(errno));
        tmp++;
    }
    if (safewrite(vm->logfile, "\n", 1) < 0)
        qemudLog(QEMUD_WARN, _("Unable to write argv to logfile %d: %s\n"),
                 errno, strerror(errno));

    vm->stdout_fd = -1;
    vm->stderr_fd = -1;

    for (i = 0 ; i < ntapfds ; i++)
        FD_SET(tapfds[i], &keepfd);

    ret = virExec(conn, argv, NULL, &keepfd, &vm->pid,
                  vm->stdin_fd, &vm->stdout_fd, &vm->stderr_fd,
                  VIR_EXEC_NONBLOCK);
    if (ret == 0) {
        vm->def->id = driver->nextvmid++;
        vm->state = migrateFrom ? VIR_DOMAIN_PAUSED : VIR_DOMAIN_RUNNING;
    }

    for (i = 0 ; argv[i] ; i++)
        VIR_FREE(argv[i]);
    VIR_FREE(argv);

    if (tapfds) {
        for (i = 0 ; i < ntapfds ; i++) {
            close(tapfds[i]);
        }
        VIR_FREE(tapfds);
    }

    if (ret == 0) {
        if ((virEventAddHandle(vm->stdout_fd,
                               POLLIN | POLLERR | POLLHUP,
                               qemudDispatchVMEvent,
                               driver) < 0) ||
            (virEventAddHandle(vm->stderr_fd,
                               POLLIN | POLLERR | POLLHUP,
                               qemudDispatchVMEvent,
                               driver) < 0) ||
            (qemudWaitForMonitor(conn, driver, vm) < 0) ||
            (qemudDetectVcpuPIDs(conn, driver, vm) < 0) ||
            (qemudInitCpus(conn, driver, vm) < 0)) {
            qemudShutdownVMDaemon(conn, driver, vm);
            return -1;
        }
    }

    return ret;
}

static int qemudVMData(struct qemud_driver *driver ATTRIBUTE_UNUSED,
                       virDomainObjPtr vm, int fd) {
    char buf[4096];
    if (vm->pid < 0)
        return 0;

    for (;;) {
        int ret = read(fd, buf, sizeof(buf)-1);
        if (ret < 0) {
            if (errno == EAGAIN)
                return 0;
            return -1;
        }
        if (ret == 0) {
            return 0;
        }
        buf[ret] = '\0';

        if (safewrite(vm->logfile, buf, ret) < 0) {
            /* Log, but ignore failures to write logfile for VM */
            qemudLog(QEMUD_WARN, _("Unable to log VM console data: %s\n"),
                     strerror(errno));
        }
    }
}


static void qemudShutdownVMDaemon(virConnectPtr conn ATTRIBUTE_UNUSED,
                                  struct qemud_driver *driver, virDomainObjPtr vm) {
    if (!virDomainIsActive(vm))
        return;

    qemudLog(QEMUD_INFO, _("Shutting down VM '%s'\n"), vm->def->name);

    kill(vm->pid, SIGTERM);

    qemudVMData(driver, vm, vm->stdout_fd);
    qemudVMData(driver, vm, vm->stderr_fd);

    virEventRemoveHandle(vm->stdout_fd);
    virEventRemoveHandle(vm->stderr_fd);

    if (close(vm->logfile) < 0)
        qemudLog(QEMUD_WARN, _("Unable to close logfile %d: %s\n"),
                 errno, strerror(errno));
    close(vm->stdout_fd);
    close(vm->stderr_fd);
    if (vm->monitor != -1)
        close(vm->monitor);
    vm->logfile = -1;
    vm->stdout_fd = -1;
    vm->stderr_fd = -1;
    vm->monitor = -1;

    if (waitpid(vm->pid, NULL, WNOHANG) != vm->pid) {
        kill(vm->pid, SIGKILL);
        if (waitpid(vm->pid, NULL, 0) != vm->pid) {
            qemudLog(QEMUD_WARN,
                     "%s", _("Got unexpected pid, damn\n"));
        }
    }

    vm->pid = -1;
    vm->def->id = -1;
    vm->state = VIR_DOMAIN_SHUTOFF;
    VIR_FREE(vm->vcpupids);
    vm->nvcpupids = 0;

    if (vm->newDef) {
        virDomainDefFree(vm->def);
        vm->def = vm->newDef;
        vm->def->id = -1;
        vm->newDef = NULL;
    }
}

static int qemudDispatchVMLog(struct qemud_driver *driver, virDomainObjPtr vm, int fd) {
    if (qemudVMData(driver, vm, fd) < 0) {
        qemudShutdownVMDaemon(NULL, driver, vm);
        if (!vm->persistent)
            virDomainRemoveInactive(&driver->domains,
                                    vm);
    }
    return 0;
}

static int qemudDispatchVMFailure(struct qemud_driver *driver, virDomainObjPtr vm,
                                  int fd ATTRIBUTE_UNUSED) {
    qemudShutdownVMDaemon(NULL, driver, vm);
    if (!vm->persistent)
        virDomainRemoveInactive(&driver->domains,
                                vm);
    return 0;
}

static int
qemudBuildDnsmasqArgv(virConnectPtr conn,
                      virNetworkObjPtr network,
                      const char ***argv) {
    int i, len, r;
    char buf[PATH_MAX];

    len =
        1 + /* dnsmasq */
        1 + /* --keep-in-foreground */
        1 + /* --strict-order */
        1 + /* --bind-interfaces */
        (network->def->domain?2:0) + /* --domain name */
        2 + /* --pid-file "" */
        2 + /* --conf-file "" */
        /*2 + *//* --interface virbr0 */
        2 + /* --except-interface lo */
        2 + /* --listen-address 10.0.0.1 */
        1 + /* --dhcp-leasefile=path */
        (2 * network->def->nranges) + /* --dhcp-range 10.0.0.2,10.0.0.254 */
        /*  --dhcp-host 01:23:45:67:89:0a,hostname,10.0.0.3 */
        (2 * network->def->nhosts) +
        1;  /* NULL */

    if (VIR_ALLOC_N(*argv, len) < 0)
        goto no_memory;

#define APPEND_ARG(v, n, s) do {     \
        if (!((v)[(n)] = strdup(s))) \
            goto no_memory;          \
    } while (0)

    i = 0;

    APPEND_ARG(*argv, i++, DNSMASQ);

    APPEND_ARG(*argv, i++, "--keep-in-foreground");
    /*
     * Needed to ensure dnsmasq uses same algorithm for processing
     * multiple namedriver entries in /etc/resolv.conf as GLibC.
     */
    APPEND_ARG(*argv, i++, "--strict-order");
    APPEND_ARG(*argv, i++, "--bind-interfaces");

    if (network->def->domain) {
       APPEND_ARG(*argv, i++, "--domain");
       APPEND_ARG(*argv, i++, network->def->domain);
    }

    APPEND_ARG(*argv, i++, "--pid-file");
    APPEND_ARG(*argv, i++, "");

    APPEND_ARG(*argv, i++, "--conf-file");
    APPEND_ARG(*argv, i++, "");

    /*
     * XXX does not actually work, due to some kind of
     * race condition setting up ipv6 addresses on the
     * interface. A sleep(10) makes it work, but that's
     * clearly not practical
     *
     * APPEND_ARG(*argv, i++, "--interface");
     * APPEND_ARG(*argv, i++, network->def->bridge);
     */
    APPEND_ARG(*argv, i++, "--listen-address");
    APPEND_ARG(*argv, i++, network->def->ipAddress);

    APPEND_ARG(*argv, i++, "--except-interface");
    APPEND_ARG(*argv, i++, "lo");

    /*
     * NB, dnsmasq command line arg bug means we need to
     * use a single arg '--dhcp-leasefile=path' rather than
     * two separate args in '--dhcp-leasefile path' style
     */
    snprintf(buf, sizeof(buf), "--dhcp-leasefile=%s/lib/libvirt/dhcp-%s.leases",
             LOCAL_STATE_DIR, network->def->name);
    APPEND_ARG(*argv, i++, buf);

    for (r = 0 ; r < network->def->nranges ; r++) {
        snprintf(buf, sizeof(buf), "%s,%s",
                 network->def->ranges[r].start,
                 network->def->ranges[r].end);

        APPEND_ARG(*argv, i++, "--dhcp-range");
        APPEND_ARG(*argv, i++, buf);
    }

    for (r = 0 ; r < network->def->nhosts ; r++) {
        virNetworkDHCPHostDefPtr host = &(network->def->hosts[r]);
        if ((host->mac) && (host->name)) {
            snprintf(buf, sizeof(buf), "%s,%s,%s",
                     host->mac, host->name, host->ip);
        } else if (host->mac) {
            snprintf(buf, sizeof(buf), "%s,%s",
                     host->mac, host->ip);
        } else if (host->name) {
            snprintf(buf, sizeof(buf), "%s,%s",
                     host->name, host->ip);
        } else
            continue;

        APPEND_ARG(*argv, i++, "--dhcp-host");
        APPEND_ARG(*argv, i++, buf);
    }

#undef APPEND_ARG

    return 0;

 no_memory:
    if (argv) {
        for (i = 0; (*argv)[i]; i++)
            VIR_FREE((*argv)[i]);
        VIR_FREE(*argv);
    }
    qemudReportError(conn, NULL, NULL, VIR_ERR_NO_MEMORY,
                     "%s", _("failed to allocate space for dnsmasq argv"));
    return -1;
}


static int
dhcpStartDhcpDaemon(virConnectPtr conn,
                    virNetworkObjPtr network)
{
    const char **argv;
    int ret, i;

    if (network->def->ipAddress == NULL) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("cannot start dhcp daemon without IP address for server"));
        return -1;
    }

    argv = NULL;
    if (qemudBuildDnsmasqArgv(conn, network, &argv) < 0)
        return -1;

    ret = virExec(conn, argv, NULL, NULL,
                  &network->dnsmasqPid, -1, NULL, NULL, VIR_EXEC_NONBLOCK);

    for (i = 0; argv[i]; i++)
        VIR_FREE(argv[i]);
    VIR_FREE(argv);

    return ret;
}

static int
qemudAddMasqueradingIptablesRules(virConnectPtr conn,
                      struct qemud_driver *driver,
                      virNetworkObjPtr network) {
    int err;
    /* allow forwarding packets from the bridge interface */
    if ((err = iptablesAddForwardAllowOut(driver->iptables,
                                          network->def->network,
                                          network->def->bridge,
                                          network->def->forwardDev))) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("failed to add iptables rule to allow forwarding from '%s' : %s\n"),
                         network->def->bridge, strerror(err));
        goto masqerr1;
    }

    /* allow forwarding packets to the bridge interface if they are part of an existing connection */
    if ((err = iptablesAddForwardAllowRelatedIn(driver->iptables,
                                         network->def->network,
                                         network->def->bridge,
                                         network->def->forwardDev))) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("failed to add iptables rule to allow forwarding to '%s' : %s\n"),
                         network->def->bridge, strerror(err));
        goto masqerr2;
    }

    /* enable masquerading */
    if ((err = iptablesAddForwardMasquerade(driver->iptables,
                                            network->def->network,
                                            network->def->forwardDev))) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("failed to add iptables rule to enable masquerading : %s\n"),
                         strerror(err));
        goto masqerr3;
    }

    return 1;

 masqerr3:
    iptablesRemoveForwardAllowRelatedIn(driver->iptables,
                                 network->def->network,
                                 network->def->bridge,
                                 network->def->forwardDev);
 masqerr2:
    iptablesRemoveForwardAllowOut(driver->iptables,
                                  network->def->network,
                                  network->def->bridge,
                                  network->def->forwardDev);
 masqerr1:
    return 0;
}

static int
qemudAddRoutingIptablesRules(virConnectPtr conn,
                      struct qemud_driver *driver,
                      virNetworkObjPtr network) {
    int err;
    /* allow routing packets from the bridge interface */
    if ((err = iptablesAddForwardAllowOut(driver->iptables,
                                          network->def->network,
                                          network->def->bridge,
                                          network->def->forwardDev))) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("failed to add iptables rule to allow routing from '%s' : %s\n"),
                         network->def->bridge, strerror(err));
        goto routeerr1;
    }

    /* allow routing packets to the bridge interface */
    if ((err = iptablesAddForwardAllowIn(driver->iptables,
                                         network->def->network,
                                         network->def->bridge,
                                         network->def->forwardDev))) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("failed to add iptables rule to allow routing to '%s' : %s\n"),
                         network->def->bridge, strerror(err));
        goto routeerr2;
    }

    return 1;


 routeerr2:
    iptablesRemoveForwardAllowOut(driver->iptables,
                                  network->def->network,
                                  network->def->bridge,
                                  network->def->forwardDev);
 routeerr1:
    return 0;
}

static int
qemudAddIptablesRules(virConnectPtr conn,
                      struct qemud_driver *driver,
                      virNetworkObjPtr network) {
    int err;

    if (!driver->iptables && !(driver->iptables = iptablesContextNew())) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_NO_MEMORY,
                     "%s", _("failed to allocate space for IP tables support"));
        return 0;
    }


    /* allow DHCP requests through to dnsmasq */
    if ((err = iptablesAddTcpInput(driver->iptables, network->def->bridge, 67))) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("failed to add iptables rule to allow DHCP requests from '%s' : %s"),
                         network->def->bridge, strerror(err));
        goto err1;
    }

    if ((err = iptablesAddUdpInput(driver->iptables, network->def->bridge, 67))) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("failed to add iptables rule to allow DHCP requests from '%s' : %s"),
                         network->def->bridge, strerror(err));
        goto err2;
    }

    /* allow DNS requests through to dnsmasq */
    if ((err = iptablesAddTcpInput(driver->iptables, network->def->bridge, 53))) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("failed to add iptables rule to allow DNS requests from '%s' : %s"),
                         network->def->bridge, strerror(err));
        goto err3;
    }

    if ((err = iptablesAddUdpInput(driver->iptables, network->def->bridge, 53))) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("failed to add iptables rule to allow DNS requests from '%s' : %s"),
                         network->def->bridge, strerror(err));
        goto err4;
    }


    /* Catch all rules to block forwarding to/from bridges */

    if ((err = iptablesAddForwardRejectOut(driver->iptables, network->def->bridge))) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("failed to add iptables rule to block outbound traffic from '%s' : %s"),
                         network->def->bridge, strerror(err));
        goto err5;
    }

    if ((err = iptablesAddForwardRejectIn(driver->iptables, network->def->bridge))) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("failed to add iptables rule to block inbound traffic to '%s' : %s"),
                         network->def->bridge, strerror(err));
        goto err6;
    }

    /* Allow traffic between guests on the same bridge */
    if ((err = iptablesAddForwardAllowCross(driver->iptables, network->def->bridge))) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("failed to add iptables rule to allow cross bridge traffic on '%s' : %s"),
                         network->def->bridge, strerror(err));
        goto err7;
    }


    /* If masquerading is enabled, set up the rules*/
    if (network->def->forwardType == VIR_NETWORK_FORWARD_NAT &&
        !qemudAddMasqueradingIptablesRules(conn, driver, network))
        goto err8;
    /* else if routing is enabled, set up the rules*/
    else if (network->def->forwardType == VIR_NETWORK_FORWARD_ROUTE &&
             !qemudAddRoutingIptablesRules(conn, driver, network))
        goto err8;

    iptablesSaveRules(driver->iptables);

    return 1;

 err8:
    iptablesRemoveForwardAllowCross(driver->iptables,
                                    network->def->bridge);
 err7:
    iptablesRemoveForwardRejectIn(driver->iptables,
                                  network->def->bridge);
 err6:
    iptablesRemoveForwardRejectOut(driver->iptables,
                                   network->def->bridge);
 err5:
    iptablesRemoveUdpInput(driver->iptables, network->def->bridge, 53);
 err4:
    iptablesRemoveTcpInput(driver->iptables, network->def->bridge, 53);
 err3:
    iptablesRemoveUdpInput(driver->iptables, network->def->bridge, 67);
 err2:
    iptablesRemoveTcpInput(driver->iptables, network->def->bridge, 67);
 err1:
    return 0;
}

static void
qemudRemoveIptablesRules(struct qemud_driver *driver,
                         virNetworkObjPtr network) {
    if (network->def->forwardType != VIR_NETWORK_FORWARD_NONE) {
        iptablesRemoveForwardMasquerade(driver->iptables,
                                        network->def->network,
                                        network->def->forwardDev);

        if (network->def->forwardType == VIR_NETWORK_FORWARD_NAT)
            iptablesRemoveForwardAllowRelatedIn(driver->iptables,
                                                network->def->network,
                                                network->def->bridge,
                                                network->def->forwardDev);
        else if (network->def->forwardType == VIR_NETWORK_FORWARD_ROUTE)
            iptablesRemoveForwardAllowIn(driver->iptables,
                                         network->def->network,
                                         network->def->bridge,
                                         network->def->forwardDev);

        iptablesRemoveForwardAllowOut(driver->iptables,
                                      network->def->network,
                                      network->def->bridge,
                                      network->def->forwardDev);
    }
    iptablesRemoveForwardAllowCross(driver->iptables, network->def->bridge);
    iptablesRemoveForwardRejectIn(driver->iptables, network->def->bridge);
    iptablesRemoveForwardRejectOut(driver->iptables, network->def->bridge);
    iptablesRemoveUdpInput(driver->iptables, network->def->bridge, 53);
    iptablesRemoveTcpInput(driver->iptables, network->def->bridge, 53);
    iptablesRemoveUdpInput(driver->iptables, network->def->bridge, 67);
    iptablesRemoveTcpInput(driver->iptables, network->def->bridge, 67);
    iptablesSaveRules(driver->iptables);
}

static int
qemudEnableIpForwarding(void)
{
#define PROC_IP_FORWARD "/proc/sys/net/ipv4/ip_forward"

    int fd, ret;

    if ((fd = open(PROC_IP_FORWARD, O_WRONLY|O_TRUNC)) == -1)
        return 0;

    if (safewrite(fd, "1\n", 2) < 0)
        ret = 0;

    close (fd);

    return 1;

#undef PROC_IP_FORWARD
}

static int qemudStartNetworkDaemon(virConnectPtr conn,
                                   struct qemud_driver *driver,
                                   virNetworkObjPtr network) {
    int err;

    if (virNetworkIsActive(network)) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("network is already active"));
        return -1;
    }

    if (!driver->brctl && (err = brInit(&driver->brctl))) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("cannot initialize bridge support: %s"), strerror(err));
        return -1;
    }

    if ((err = brAddBridge(driver->brctl, &network->def->bridge))) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("cannot create bridge '%s' : %s"),
                         network->def->bridge, strerror(err));
        return -1;
    }


    if (brSetForwardDelay(driver->brctl, network->def->bridge, network->def->delay) < 0)
        goto err_delbr;

    if (brSetEnableSTP(driver->brctl, network->def->bridge, network->def->stp ? 1 : 0) < 0)
        goto err_delbr;

    if (network->def->ipAddress &&
        (err = brSetInetAddress(driver->brctl, network->def->bridge, network->def->ipAddress))) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("cannot set IP address on bridge '%s' to '%s' : %s"),
                         network->def->bridge, network->def->ipAddress, strerror(err));
        goto err_delbr;
    }

    if (network->def->netmask &&
        (err = brSetInetNetmask(driver->brctl, network->def->bridge, network->def->netmask))) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("cannot set netmask on bridge '%s' to '%s' : %s"),
                         network->def->bridge, network->def->netmask, strerror(err));
        goto err_delbr;
    }

    if (network->def->ipAddress &&
        (err = brSetInterfaceUp(driver->brctl, network->def->bridge, 1))) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("failed to bring the bridge '%s' up : %s"),
                         network->def->bridge, strerror(err));
        goto err_delbr;
    }

    if (!qemudAddIptablesRules(conn, driver, network))
        goto err_delbr1;

    if (network->def->forwardType != VIR_NETWORK_FORWARD_NONE &&
        !qemudEnableIpForwarding()) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("failed to enable IP forwarding : %s"), strerror(err));
        goto err_delbr2;
    }

    if (network->def->nranges &&
        dhcpStartDhcpDaemon(conn, network) < 0)
        goto err_delbr2;

    network->active = 1;

    return 0;

 err_delbr2:
    qemudRemoveIptablesRules(driver, network);

 err_delbr1:
    if (network->def->ipAddress &&
        (err = brSetInterfaceUp(driver->brctl, network->def->bridge, 0))) {
        qemudLog(QEMUD_WARN, _("Failed to bring down bridge '%s' : %s\n"),
                 network->def->bridge, strerror(err));
    }

 err_delbr:
    if ((err = brDeleteBridge(driver->brctl, network->def->bridge))) {
        qemudLog(QEMUD_WARN, _("Failed to delete bridge '%s' : %s\n"),
                 network->def->bridge, strerror(err));
    }

    return -1;
}


static int qemudShutdownNetworkDaemon(virConnectPtr conn ATTRIBUTE_UNUSED,
                                      struct qemud_driver *driver,
                                      virNetworkObjPtr network) {
    int err;

    qemudLog(QEMUD_INFO, _("Shutting down network '%s'\n"), network->def->name);

    if (!virNetworkIsActive(network))
        return 0;

    if (network->dnsmasqPid > 0)
        kill(network->dnsmasqPid, SIGTERM);

    qemudRemoveIptablesRules(driver, network);

    if (network->def->ipAddress &&
        (err = brSetInterfaceUp(driver->brctl, network->def->bridge, 0))) {
        qemudLog(QEMUD_WARN, _("Failed to bring down bridge '%s' : %s\n"),
                 network->def->bridge, strerror(err));
    }

    if ((err = brDeleteBridge(driver->brctl, network->def->bridge))) {
        qemudLog(QEMUD_WARN, _("Failed to delete bridge '%s' : %s\n"),
                 network->def->bridge, strerror(err));
    }

    if (network->dnsmasqPid > 0 &&
        waitpid(network->dnsmasqPid, NULL, WNOHANG) != network->dnsmasqPid) {
        kill(network->dnsmasqPid, SIGKILL);
        if (waitpid(network->dnsmasqPid, NULL, 0) != network->dnsmasqPid)
            qemudLog(QEMUD_WARN,
                     "%s", _("Got unexpected pid for dnsmasq\n"));
    }

    network->dnsmasqPid = -1;
    network->active = 0;

    if (network->newDef) {
        virNetworkDefFree(network->def);
        network->def = network->newDef;
        network->newDef = NULL;
    }

    if (!network->configFile)
        virNetworkRemoveInactive(&driver->networks,
                                 network);

    return 0;
}


static void qemudDispatchVMEvent(int fd, int events, void *opaque) {
    struct qemud_driver *driver = (struct qemud_driver *)opaque;
    virDomainObjPtr vm = driver->domains;

    while (vm) {
        if (virDomainIsActive(vm) &&
            (vm->stdout_fd == fd ||
             vm->stderr_fd == fd))
            break;

        vm = vm->next;
    }

    if (!vm)
        return;

    if (events == POLLIN)
        qemudDispatchVMLog(driver, vm, fd);
    else
        qemudDispatchVMFailure(driver, vm, fd);
}

static int
qemudMonitorCommand (const struct qemud_driver *driver ATTRIBUTE_UNUSED,
                     const virDomainObjPtr vm,
                     const char *cmd,
                     char **reply) {
    int size = 0;
    char *buf = NULL;
    size_t cmdlen = strlen(cmd);

    if (safewrite(vm->monitor, cmd, cmdlen) != cmdlen)
        return -1;
    if (safewrite(vm->monitor, "\r", 1) != 1)
        return -1;

    *reply = NULL;

    for (;;) {
        struct pollfd fd = { vm->monitor, POLLIN | POLLERR | POLLHUP, 0 };
        char *tmp;

        /* Read all the data QEMU has sent thus far */
        for (;;) {
            char data[1024];
            int got = read(vm->monitor, data, sizeof(data));

            if (got == 0)
                goto error;
            if (got < 0) {
                if (errno == EINTR)
                    continue;
                if (errno == EAGAIN)
                    break;
                goto error;
            }
            if (VIR_REALLOC_N(buf, size+got+1) < 0)
                goto error;

            memmove(buf+size, data, got);
            buf[size+got] = '\0';
            size += got;
        }

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
            goto error;
        }
    }

    /* Log, but ignore failures to write logfile for VM */
    if (safewrite(vm->logfile, buf, strlen(buf)) < 0)
        qemudLog(QEMUD_WARN, _("Unable to log VM console data: %s\n"),
                 strerror(errno));

    *reply = buf;
    return 0;

 error:
    if (buf) {
        /* Log, but ignore failures to write logfile for VM */
        if (safewrite(vm->logfile, buf, strlen(buf)) < 0)
            qemudLog(QEMUD_WARN, _("Unable to log VM console data: %s\n"),
                     strerror(errno));
        VIR_FREE(buf);
    }
    return -1;
}

/**
 * qemudProbe:
 *
 * Probe for the availability of the qemu driver, assume the
 * presence of QEmu emulation if the binaries are installed
 */
static const char *qemudProbe(void)
{
    if ((virFileExists("/usr/bin/qemu")) ||
        (virFileExists("/usr/bin/qemu-kvm")) ||
        (virFileExists("/usr/bin/xenner"))) {
        if (getuid() == 0) {
            return("qemu:///system");
        } else {
            return("qemu:///session");
        }
    }
    return(NULL);
}

static virDrvOpenStatus qemudOpen(virConnectPtr conn,
                                  xmlURIPtr uri,
                                  virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                                  int flags ATTRIBUTE_UNUSED) {
    uid_t uid = getuid();

    if (qemu_driver == NULL)
        goto decline;

    if (uri == NULL || uri->scheme == NULL || uri->path == NULL)
        goto decline;

    if (STRNEQ (uri->scheme, "qemu"))
        goto decline;

    if (uid != 0) {
        if (STRNEQ (uri->path, "/session"))
            goto decline;
    } else { /* root */
        if (STRNEQ (uri->path, "/system") &&
            STRNEQ (uri->path, "/session"))
            goto decline;
    }

    conn->privateData = qemu_driver;

    return VIR_DRV_OPEN_SUCCESS;

 decline:
    return VIR_DRV_OPEN_DECLINED;
}

static int qemudClose(virConnectPtr conn) {
    /*struct qemud_driver *driver = (struct qemud_driver *)conn->privateData;*/

    conn->privateData = NULL;

    return 0;
}

static const char *qemudGetType(virConnectPtr conn ATTRIBUTE_UNUSED) {
    return "QEMU";
}


static int kvmGetMaxVCPUs(void) {
    int maxvcpus = 1;

    int r, fd;

    fd = open(KVM_DEVICE, O_RDONLY);
    if (fd < 0) {
        qemudLog(QEMUD_WARN, _("Unable to open %s: %s\n"), KVM_DEVICE, strerror(errno));
        return maxvcpus;
    }

    r = ioctl(fd, KVM_CHECK_EXTENSION, KVM_CAP_NR_VCPUS);
    if (r > 0)
        maxvcpus = r;

    close(fd);
    return maxvcpus;
}


static int qemudGetMaxVCPUs(virConnectPtr conn, const char *type) {
    if (!type)
        return 16;

    if (STRCASEEQ(type, "qemu"))
        return 16;

    /* XXX future KVM will support SMP. Need to probe
       kernel to figure out KVM module version i guess */
    if (STRCASEEQ(type, "kvm"))
        return kvmGetMaxVCPUs();

    if (STRCASEEQ(type, "kqemu"))
        return 1;

    qemudReportError(conn, NULL, NULL, VIR_ERR_INVALID_ARG,
                     _("unknown type '%s'"), type);
    return -1;
}

static int qemudGetNodeInfo(virConnectPtr conn,
                            virNodeInfoPtr nodeinfo) {
    return virNodeInfoPopulate(conn, nodeinfo);
}


static char *qemudGetCapabilities(virConnectPtr conn) {
    struct qemud_driver *driver = (struct qemud_driver *)conn->privateData;
    char *xml;

    if ((xml = virCapabilitiesFormatXML(driver->caps)) == NULL) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_NO_MEMORY,
                 "%s", _("failed to allocate space for capabilities support"));
        return NULL;
    }

    return xml;
}


#if HAVE_NUMACTL
static int
qemudNodeGetCellsFreeMemory(virConnectPtr conn,
                            unsigned long long *freeMems,
                            int startCell,
                            int maxCells)
{
    int n, lastCell, numCells;

    if (numa_available() < 0) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_NO_SUPPORT,
                         "%s", _("NUMA not supported on this host"));
        return -1;
    }
    lastCell = startCell + maxCells - 1;
    if (lastCell > numa_max_node())
        lastCell = numa_max_node();

    for (numCells = 0, n = startCell ; n <= lastCell ; n++) {
        long long mem;
        if (numa_node_size64(n, &mem) < 0) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("Failed to query NUMA free memory"));
            return -1;
        }
        freeMems[numCells++] = mem;
    }
    return numCells;
}

static unsigned long long
qemudNodeGetFreeMemory (virConnectPtr conn)
{
    unsigned long long freeMem = 0;
    int n;
    if (numa_available() < 0) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_NO_SUPPORT,
                         "%s", _("NUMA not supported on this host"));
        return -1;
    }

    for (n = 0 ; n <= numa_max_node() ; n++) {
        long long mem;
        if (numa_node_size64(n, &mem) < 0) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("Failed to query NUMA free memory"));
            return -1;
        }
        freeMem += mem;
    }

    return freeMem;
}

#endif

static int qemudGetProcessInfo(unsigned long long *cpuTime, int pid) {
    char proc[PATH_MAX];
    FILE *pidinfo;
    unsigned long long usertime, systime;

    if (snprintf(proc, sizeof(proc), "/proc/%d/stat", pid) >= (int)sizeof(proc)) {
        return -1;
    }

    if (!(pidinfo = fopen(proc, "r"))) {
        /*printf("cannot read pid info");*/
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


static virDomainPtr qemudDomainLookupByID(virConnectPtr conn,
                                          int id) {
    struct qemud_driver *driver = (struct qemud_driver *)conn->privateData;
    virDomainObjPtr vm = virDomainFindByID(driver->domains, id);
    virDomainPtr dom;

    if (!vm) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_NO_DOMAIN, NULL);
        return NULL;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom) dom->id = vm->def->id;
    return dom;
}
static virDomainPtr qemudDomainLookupByUUID(virConnectPtr conn,
                                            const unsigned char *uuid) {
    struct qemud_driver *driver = (struct qemud_driver *)conn->privateData;
    virDomainObjPtr vm = virDomainFindByUUID(driver->domains, uuid);
    virDomainPtr dom;

    if (!vm) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_NO_DOMAIN, NULL);
        return NULL;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom) dom->id = vm->def->id;
    return dom;
}
static virDomainPtr qemudDomainLookupByName(virConnectPtr conn,
                                            const char *name) {
    struct qemud_driver *driver = (struct qemud_driver *)conn->privateData;
    virDomainObjPtr vm = virDomainFindByName(driver->domains, name);
    virDomainPtr dom;

    if (!vm) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_NO_DOMAIN, NULL);
        return NULL;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom) dom->id = vm->def->id;
    return dom;
}

static int qemudGetVersion(virConnectPtr conn, unsigned long *version) {
    struct qemud_driver *driver = (struct qemud_driver *)conn->privateData;
    if (qemudExtractVersion(conn, driver) < 0)
        return -1;

    *version = qemu_driver->qemuVersion;
    return 0;
}

static char *
qemudGetHostname (virConnectPtr conn)
{
    int r;
    char hostname[HOST_NAME_MAX+1], *str;

    r = gethostname (hostname, HOST_NAME_MAX+1);
    if (r == -1) {
        qemudReportError (conn, NULL, NULL, VIR_ERR_SYSTEM_ERROR,
                          "%s", strerror (errno));
        return NULL;
    }
    /* Caller frees this string. */
    str = strdup (hostname);
    if (str == NULL) {
        qemudReportError (conn, NULL, NULL, VIR_ERR_SYSTEM_ERROR,
                         "%s", strerror (errno));
        return NULL;
    }
    return str;
}

static int qemudListDomains(virConnectPtr conn, int *ids, int nids) {
    struct qemud_driver *driver = (struct qemud_driver *)conn->privateData;
    virDomainObjPtr vm = driver->domains;
    int got = 0;
    while (vm && got < nids) {
        if (virDomainIsActive(vm)) {
            ids[got] = vm->def->id;
            got++;
        }
        vm = vm->next;
    }
    return got;
}
static int qemudNumDomains(virConnectPtr conn) {
    struct qemud_driver *driver = (struct qemud_driver *)conn->privateData;
    int n = 0;
    virDomainObjPtr dom = driver->domains;
    while (dom) {
        if (virDomainIsActive(dom))
            n++;
        dom = dom->next;
    }
    return n;
}
static virDomainPtr qemudDomainCreate(virConnectPtr conn, const char *xml,
                                      unsigned int flags ATTRIBUTE_UNUSED) {
    virDomainDefPtr def;
    virDomainObjPtr vm;
    virDomainPtr dom;
    struct qemud_driver *driver = (struct qemud_driver *)conn->privateData;

    if (!(def = virDomainDefParseString(conn, driver->caps, xml)))
        return NULL;

    vm = virDomainFindByName(driver->domains, def->name);
    if (vm) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         _("domain '%s' is already defined"),
                         def->name);
        virDomainDefFree(def);
        return NULL;
    }
    vm = virDomainFindByUUID(driver->domains, def->uuid);
    if (vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];

        virUUIDFormat(def->uuid, uuidstr);
        qemudReportError(conn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         _("domain with uuid '%s' is already defined"),
                         uuidstr);
        virDomainDefFree(def);
        return NULL;
    }

    if (!(vm = virDomainAssignDef(conn,
                                  &driver->domains,
                                  def))) {
        virDomainDefFree(def);
        return NULL;
    }

    if (qemudStartVMDaemon(conn, driver, vm, NULL) < 0) {
        virDomainRemoveInactive(&driver->domains,
                                vm);
        return NULL;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom) dom->id = vm->def->id;
    return dom;
}


static int qemudDomainSuspend(virDomainPtr dom) {
    struct qemud_driver *driver = (struct qemud_driver *)dom->conn->privateData;
    char *info;
    virDomainObjPtr vm = virDomainFindByID(driver->domains, dom->id);
    if (!vm) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN, _("no domain with matching id %d"), dom->id);
        return -1;
    }
    if (!virDomainIsActive(vm)) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("domain is not running"));
        return -1;
    }
    if (vm->state == VIR_DOMAIN_PAUSED)
        return 0;

    if (qemudMonitorCommand(driver, vm, "stop", &info) < 0) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("suspend operation failed"));
        return -1;
    }
    vm->state = VIR_DOMAIN_PAUSED;
    qemudDebug("Reply %s", info);
    VIR_FREE(info);
    return 0;
}


static int qemudDomainResume(virDomainPtr dom) {
    struct qemud_driver *driver = (struct qemud_driver *)dom->conn->privateData;
    char *info;
    virDomainObjPtr vm = virDomainFindByID(driver->domains, dom->id);
    if (!vm) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         _("no domain with matching id %d"), dom->id);
        return -1;
    }
    if (!virDomainIsActive(vm)) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("domain is not running"));
        return -1;
    }
    if (vm->state == VIR_DOMAIN_RUNNING)
        return 0;
    if (qemudMonitorCommand(driver, vm, "cont", &info) < 0) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("resume operation failed"));
        return -1;
    }
    vm->state = VIR_DOMAIN_RUNNING;
    qemudDebug("Reply %s", info);
    VIR_FREE(info);
    return 0;
}


static int qemudDomainShutdown(virDomainPtr dom) {
    struct qemud_driver *driver = (struct qemud_driver *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByID(driver->domains, dom->id);
    char* info;

    if (!vm) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         _("no domain with matching id %d"), dom->id);
        return -1;
    }

    if (qemudMonitorCommand(driver, vm, "system_powerdown", &info) < 0) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("shutdown operation failed"));
        return -1;
    }
    return 0;

}


static int qemudDomainDestroy(virDomainPtr dom) {
    struct qemud_driver *driver = (struct qemud_driver *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByID(driver->domains, dom->id);

    if (!vm) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         _("no domain with matching id %d"), dom->id);
        return -1;
    }

    qemudShutdownVMDaemon(dom->conn, driver, vm);
    if (!vm->persistent)
        virDomainRemoveInactive(&driver->domains,
                                vm);

    return 0;
}


static char *qemudDomainGetOSType(virDomainPtr dom) {
    struct qemud_driver *driver = (struct qemud_driver *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByUUID(driver->domains, dom->uuid);
    char *type;

    if (!vm) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         "%s", _("no domain with matching uuid"));
        return NULL;
    }

    if (!(type = strdup(vm->def->os.type))) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_NO_MEMORY,
                         "%s", _("failed to allocate space for ostype"));
        return NULL;
    }
    return type;
}

/* Returns max memory in kb, 0 if error */
static unsigned long qemudDomainGetMaxMemory(virDomainPtr dom) {
    struct qemud_driver *driver = (struct qemud_driver *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByUUID(driver->domains, dom->uuid);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];

        virUUIDFormat(dom->uuid, uuidstr);
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         _("no domain with matching uuid '%s'"), uuidstr);
        return 0;
    }

    return vm->def->maxmem;
}

static int qemudDomainSetMaxMemory(virDomainPtr dom, unsigned long newmax) {
    struct qemud_driver *driver = (struct qemud_driver *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByUUID(driver->domains, dom->uuid);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];

        virUUIDFormat(dom->uuid, uuidstr);
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         _("no domain with matching uuid '%s'"), uuidstr);
        return -1;
    }

    if (newmax < vm->def->memory) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_ARG,
                         "%s", _("cannot set max memory lower than current memory"));
        return -1;
    }

    vm->def->maxmem = newmax;
    return 0;
}

static int qemudDomainSetMemory(virDomainPtr dom, unsigned long newmem) {
    struct qemud_driver *driver = (struct qemud_driver *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByUUID(driver->domains, dom->uuid);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];

        virUUIDFormat(dom->uuid, uuidstr);
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         _("no domain with matching uuid '%s'"), uuidstr);
        return -1;
    }

    if (virDomainIsActive(vm)) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_NO_SUPPORT,
                         "%s", _("cannot set memory of an active domain"));
        return -1;
    }

    if (newmem > vm->def->maxmem) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_ARG,
                         "%s", _("cannot set memory higher than max memory"));
        return -1;
    }

    vm->def->memory = newmem;
    return 0;
}

static int qemudDomainGetInfo(virDomainPtr dom,
                              virDomainInfoPtr info) {
    struct qemud_driver *driver = (struct qemud_driver *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByUUID(driver->domains, dom->uuid);
    if (!vm) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         "%s", _("no domain with matching uuid"));
        return -1;
    }

    info->state = vm->state;

    if (!virDomainIsActive(vm)) {
        info->cpuTime = 0;
    } else {
        if (qemudGetProcessInfo(&(info->cpuTime), vm->pid) < 0) {
            qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED, ("cannot read cputime for domain"));
            return -1;
        }
    }

    info->maxMem = vm->def->maxmem;
    info->memory = vm->def->memory;
    info->nrVirtCpu = vm->def->vcpus;
    return 0;
}


static char *qemudEscape(const char *in, int shell)
{
    int len = 0;
    int i, j;
    char *out;

    /* To pass through the QEMU monitor, we need to use escape
       sequences: \r, \n, \", \\

       To pass through both QEMU + the shell, we need to escape
       the single character ' as the five characters '\\''
    */

    for (i = 0; in[i] != '\0'; i++) {
        switch(in[i]) {
        case '\r':
        case '\n':
        case '"':
        case '\\':
            len += 2;
            break;
        case '\'':
            if (shell)
                len += 5;
            else
                len += 1;
            break;
        default:
            len += 1;
            break;
        }
    }

    if (VIR_ALLOC_N(out, len + 1) < 0)
        return NULL;

    for (i = j = 0; in[i] != '\0'; i++) {
        switch(in[i]) {
        case '\r':
            out[j++] = '\\';
            out[j++] = 'r';
            break;
        case '\n':
            out[j++] = '\\';
            out[j++] = 'n';
            break;
        case '"':
        case '\\':
            out[j++] = '\\';
            out[j++] = in[i];
            break;
        case '\'':
            if (shell) {
                out[j++] = '\'';
                out[j++] = '\\';
                out[j++] = '\\';
                out[j++] = '\'';
                out[j++] = '\'';
            } else {
                out[j++] = in[i];
            }
            break;
        default:
            out[j++] = in[i];
            break;
        }
    }
    out[j] = '\0';

    return out;
}

static char *qemudEscapeMonitorArg(const char *in)
{
    return qemudEscape(in, 0);
}

static char *qemudEscapeShellArg(const char *in)
{
    return qemudEscape(in, 1);
}

#define QEMUD_SAVE_MAGIC "LibvirtQemudSave"
#define QEMUD_SAVE_VERSION 1

struct qemud_save_header {
    char magic[sizeof(QEMUD_SAVE_MAGIC)-1];
    int version;
    int xml_len;
    int was_running;
    int unused[16];
};

static int qemudDomainSave(virDomainPtr dom,
                           const char *path) {
    struct qemud_driver *driver = (struct qemud_driver *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByID(driver->domains, dom->id);
    char *command, *info;
    int fd;
    char *safe_path;
    char *xml;
    struct qemud_save_header header;

    memset(&header, 0, sizeof(header));
    memcpy(header.magic, QEMUD_SAVE_MAGIC, sizeof(header.magic));
    header.version = QEMUD_SAVE_VERSION;

    if (!vm) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         _("no domain with matching id %d"), dom->id);
        return -1;
    }

    if (!virDomainIsActive(vm)) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("domain is not running"));
        return -1;
    }

    /* Pause */
    if (vm->state == VIR_DOMAIN_RUNNING) {
        header.was_running = 1;
        if (qemudDomainSuspend(dom) != 0) {
            qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                             "%s", _("failed to pause domain"));
            return -1;
        }
    }

    /* Get XML for the domain */
    xml = virDomainDefFormat(dom->conn, vm->def, VIR_DOMAIN_XML_SECURE);
    if (!xml) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("failed to get domain xml"));
        return -1;
    }
    header.xml_len = strlen(xml) + 1;

    /* Write header to file, followed by XML */
    if ((fd = open(path, O_CREAT|O_TRUNC|O_WRONLY, S_IRUSR|S_IWUSR)) < 0) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                         _("failed to create '%s'"), path);
        VIR_FREE(xml);
        return -1;
    }

    if (safewrite(fd, &header, sizeof(header)) != sizeof(header)) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("failed to write save header"));
        close(fd);
        VIR_FREE(xml);
        return -1;
    }

    if (safewrite(fd, xml, header.xml_len) != header.xml_len) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("failed to write xml"));
        close(fd);
        VIR_FREE(xml);
        return -1;
    }

    close(fd);
    VIR_FREE(xml);

    /* Migrate to file */
    safe_path = qemudEscapeShellArg(path);
    if (!safe_path) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("out of memory"));
        return -1;
    }
    if (asprintf (&command, "migrate \"exec:"
                  "dd of='%s' oflag=append conv=notrunc 2>/dev/null"
                  "\"", safe_path) == -1) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("out of memory"));
        VIR_FREE(safe_path);
        return -1;
    }
    free(safe_path);

    if (qemudMonitorCommand(driver, vm, command, &info) < 0) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("migrate operation failed"));
        VIR_FREE(command);
        return -1;
    }

    DEBUG ("migrate reply: %s", info);

    /* If the command isn't supported then qemu prints:
     * unknown command: migrate" */
    if (strstr(info, "unknown command:")) {
        qemudReportError (dom->conn, dom, NULL, VIR_ERR_NO_SUPPORT,
                          "%s",
                          _("'migrate' not supported by this qemu"));
        VIR_FREE(info);
        VIR_FREE(command);
        return -1;
    }

    VIR_FREE(info);
    VIR_FREE(command);

    /* Shut it down */
    qemudShutdownVMDaemon(dom->conn, driver, vm);
    if (!vm->persistent)
        virDomainRemoveInactive(&driver->domains,
                                vm);

    return 0;
}


static int qemudDomainSetVcpus(virDomainPtr dom, unsigned int nvcpus) {
    const struct qemud_driver *driver = (struct qemud_driver *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByUUID(driver->domains, dom->uuid);
    int max;

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];

        virUUIDFormat(dom->uuid, uuidstr);
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         _("no domain with matching uuid '%s'"), uuidstr);
        return -1;
    }

    if (virDomainIsActive(vm)) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_NO_SUPPORT, "%s",
                         _("cannot change vcpu count of an active domain"));
        return -1;
    }

    if ((max = qemudDomainGetMaxVcpus(dom)) < 0) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INTERNAL_ERROR, "%s",
                         _("could not determine max vcpus for the domain"));
        return -1;
    }

    if (nvcpus > max) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_ARG,
                         _("requested vcpus is greater than max allowable"
                           " vcpus for the domain: %d > %d"), nvcpus, max);
        return -1;
    }

    vm->def->vcpus = nvcpus;
    return 0;
}


#if HAVE_SCHED_GETAFFINITY
static int
qemudDomainPinVcpu(virDomainPtr dom,
                   unsigned int vcpu,
                   unsigned char *cpumap,
                   int maplen) {
    struct qemud_driver *driver = (struct qemud_driver *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByUUID(driver->domains, dom->uuid);
    cpu_set_t mask;
    int i, maxcpu;
    virNodeInfo nodeinfo;

    if (!virDomainIsActive(vm)) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_ARG,
                         "%s",_("cannot pin vcpus on an inactive domain"));
        return -1;
    }

    if (vcpu > (vm->nvcpupids-1)) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_ARG,
                         _("vcpu number out of range %d > %d"),
                         vcpu, vm->nvcpupids);
        return -1;
    }

    if (virNodeInfoPopulate(dom->conn, &nodeinfo) < 0)
        return -1;

    maxcpu = maplen * 8;
    if (maxcpu > nodeinfo.cpus)
        maxcpu = nodeinfo.cpus;

    CPU_ZERO(&mask);
    for (i = 0 ; i < maxcpu ; i++) {
        if ((cpumap[i/8] >> (i % 8)) & 1)
            CPU_SET(i, &mask);
    }

    if (vm->vcpupids != NULL) {
        if (sched_setaffinity(vm->vcpupids[vcpu], sizeof(mask), &mask) < 0) {
            qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_ARG,
                             _("cannot set affinity: %s"), strerror(errno));
            return -1;
        }
    } else {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_NO_SUPPORT,
                         "%s", _("cpu affinity is not supported"));
        return -1;
    }

    return 0;
}

static int
qemudDomainGetVcpus(virDomainPtr dom,
                    virVcpuInfoPtr info,
                    int maxinfo,
                    unsigned char *cpumaps,
                    int maplen) {
    struct qemud_driver *driver = (struct qemud_driver *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByUUID(driver->domains, dom->uuid);
    virNodeInfo nodeinfo;
    int i, v, maxcpu;

    if (!virDomainIsActive(vm)) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_ARG,
                         "%s",_("cannot pin vcpus on an inactive domain"));
        return -1;
    }

    if (virNodeInfoPopulate(dom->conn, &nodeinfo) < 0)
        return -1;

    maxcpu = maplen * 8;
    if (maxcpu > nodeinfo.cpus)
        maxcpu = nodeinfo.cpus;

    /* Clamp to actual number of vcpus */
    if (maxinfo > vm->nvcpupids)
        maxinfo = vm->nvcpupids;

    if (maxinfo < 1)
        return 0;

    if (info != NULL) {
        memset(info, 0, sizeof(*info) * maxinfo);
        for (i = 0 ; i < maxinfo ; i++) {
            info[i].number = i;
            info[i].state = VIR_VCPU_RUNNING;
            /* XXX cpu time, current pCPU mapping */
        }
    }

    if (cpumaps != NULL) {
        memset(cpumaps, 0, maplen * maxinfo);
        if (vm->vcpupids != NULL) {
            for (v = 0 ; v < maxinfo ; v++) {
                cpu_set_t mask;
                unsigned char *cpumap = VIR_GET_CPUMAP(cpumaps, maplen, v);
                CPU_ZERO(&mask);

                if (sched_getaffinity(vm->vcpupids[v], sizeof(mask), &mask) < 0) {
                    qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_ARG,
                                     _("cannot get affinity: %s"), strerror(errno));
                    return -1;
                }

                for (i = 0 ; i < maxcpu ; i++)
                    if (CPU_ISSET(i, &mask))
                        VIR_USE_CPU(cpumap, i);
            }
        } else {
            qemudReportError(dom->conn, dom, NULL, VIR_ERR_NO_SUPPORT,
                             "%s", _("cpu affinity is not available"));
            return -1;
        }
    }

    return maxinfo;
}
#endif /* HAVE_SCHED_GETAFFINITY */


static int qemudDomainGetMaxVcpus(virDomainPtr dom) {
    struct qemud_driver *driver = (struct qemud_driver *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByUUID(driver->domains, dom->uuid);
    const char *type;
    int ret;

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];

        virUUIDFormat(dom->uuid, uuidstr);
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         _("no domain with matching uuid '%s'"), uuidstr);
        return -1;
    }

    if (!(type = virDomainVirtTypeToString(vm->def->virtType))) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("unknown virt type in domain definition '%d'"),
                         vm->def->virtType);
        return -1;
    }

    if ((ret = qemudGetMaxVCPUs(dom->conn, type)) < 0) {
        return -1;
    }

    return ret;
}


static int qemudDomainRestore(virConnectPtr conn,
                       const char *path) {
    struct qemud_driver *driver = (struct qemud_driver *)conn->privateData;
    virDomainDefPtr def;
    virDomainObjPtr vm;
    int fd;
    int ret;
    char *xml;
    struct qemud_save_header header;

    /* Verify the header and read the XML */
    if ((fd = open(path, O_RDONLY)) < 0) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("cannot read domain image"));
        return -1;
    }

    if (saferead(fd, &header, sizeof(header)) != sizeof(header)) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("failed to read qemu header"));
        close(fd);
        return -1;
    }

    if (memcmp(header.magic, QEMUD_SAVE_MAGIC, sizeof(header.magic)) != 0) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("image magic is incorrect"));
        close(fd);
        return -1;
    }

    if (header.version > QEMUD_SAVE_VERSION) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         _("image version is not supported (%d > %d)"),
                         header.version, QEMUD_SAVE_VERSION);
        close(fd);
        return -1;
    }

    if (VIR_ALLOC_N(xml, header.xml_len) < 0) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("out of memory"));
        close(fd);
        return -1;
    }

    if (saferead(fd, xml, header.xml_len) != header.xml_len) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("failed to read XML"));
        close(fd);
        VIR_FREE(xml);
        return -1;
    }

    /* Create a domain from this XML */
    if (!(def = virDomainDefParseString(conn, driver->caps, xml))) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("failed to parse XML"));
        close(fd);
        VIR_FREE(xml);
        return -1;
    }
    VIR_FREE(xml);

    /* Ensure the name and UUID don't already exist in an active VM */
    vm = virDomainFindByUUID(driver->domains, def->uuid);
    if (!vm)
        vm = virDomainFindByName(driver->domains, def->name);
    if (vm && virDomainIsActive(vm)) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         _("domain is already active as '%s'"), vm->def->name);
        close(fd);
        return -1;
    }

    if (!(vm = virDomainAssignDef(conn,
                                  &driver->domains,
                                  def))) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("failed to assign new VM"));
        virDomainDefFree(def);
        close(fd);
        return -1;
    }

    /* Set the migration source and start it up. */
    vm->stdin_fd = fd;
    ret = qemudStartVMDaemon(conn, driver, vm, "stdio");
    close(fd);
    vm->stdin_fd = -1;
    if (ret < 0) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("failed to start VM"));
        if (!vm->persistent)
            virDomainRemoveInactive(&driver->domains,
                                    vm);
        return -1;
    }

    /* If it was running before, resume it now. */
    if (header.was_running) {
        char *info;
        if (qemudMonitorCommand(driver, vm, "cont", &info) < 0) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                             "%s", _("failed to resume domain"));
            return -1;
        }
        VIR_FREE(info);
        vm->state = VIR_DOMAIN_RUNNING;
    }

    return 0;
}


static char *qemudDomainDumpXML(virDomainPtr dom,
                                int flags ATTRIBUTE_UNUSED) {
    struct qemud_driver *driver = (struct qemud_driver *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByUUID(driver->domains, dom->uuid);
    if (!vm) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         "%s", _("no domain with matching uuid"));
        return NULL;
    }

    return virDomainDefFormat(dom->conn,
                              (flags & VIR_DOMAIN_XML_INACTIVE) && vm->newDef ?
                              vm->newDef : vm->def,
                              flags);
}


static int qemudListDefinedDomains(virConnectPtr conn,
                            char **const names, int nnames) {
    struct qemud_driver *driver = (struct qemud_driver *)conn->privateData;
    virDomainObjPtr vm = driver->domains;
    int got = 0, i;
    while (vm && got < nnames) {
        if (!virDomainIsActive(vm)) {
            if (!(names[got] = strdup(vm->def->name))) {
                qemudReportError(conn, NULL, NULL, VIR_ERR_NO_MEMORY,
                     "%s", _("failed to allocate space for VM name string"));
                goto cleanup;
            }
            got++;
        }
        vm = vm->next;
    }
    return got;

 cleanup:
    for (i = 0 ; i < got ; i++)
        VIR_FREE(names[i]);
    return -1;
}


static int qemudNumDefinedDomains(virConnectPtr conn) {
    struct qemud_driver *driver = (struct qemud_driver *)conn->privateData;
    int n = 0;
    virDomainObjPtr dom = driver->domains;
    while (dom) {
        if (!virDomainIsActive(dom))
            n++;
        dom = dom->next;
    }
    return n;
}


static int qemudDomainStart(virDomainPtr dom) {
    struct qemud_driver *driver = (struct qemud_driver *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByUUID(driver->domains, dom->uuid);

    if (!vm) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         "%s", _("no domain with matching uuid"));
        return -1;
    }

    return qemudStartVMDaemon(dom->conn, driver, vm, NULL);
}


static virDomainPtr qemudDomainDefine(virConnectPtr conn, const char *xml) {
    struct qemud_driver *driver = (struct qemud_driver *)conn->privateData;
    virDomainDefPtr def;
    virDomainObjPtr vm;
    virDomainPtr dom;

    if (!(def = virDomainDefParseString(conn, driver->caps, xml)))
        return NULL;

    if (!(vm = virDomainAssignDef(conn,
                                  &driver->domains,
                                  def))) {
        virDomainDefFree(def);
        return NULL;
    }
    vm->persistent = 1;

    if (virDomainSaveConfig(conn,
                            driver->configDir,
                            vm->newDef ? vm->newDef : vm->def) < 0) {
        virDomainRemoveInactive(&driver->domains,
                                vm);
        return NULL;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom) dom->id = vm->def->id;
    return dom;
}

static int qemudDomainUndefine(virDomainPtr dom) {
    struct qemud_driver *driver = (struct qemud_driver *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByUUID(driver->domains, dom->uuid);

    if (!vm) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         "%s", _("no domain with matching uuid"));
        return -1;
    }

    if (virDomainIsActive(vm)) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("cannot delete active domain"));
        return -1;
    }

    if (!vm->persistent) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("cannot undefine transient domain"));
        return -1;
    }

    if (virDomainDeleteConfig(dom->conn, driver->configDir, driver->autostartDir, vm) < 0)
        return -1;

    virDomainRemoveInactive(&driver->domains,
                            vm);

    return 0;
}

/* Return the disks name for use in monitor commands */
static char *qemudDiskDeviceName(virDomainPtr dom,
                                 virDomainDiskDefPtr disk) {

    int busid, devid;
    int ret;
    char *devname;

    if (virDiskNameToBusDeviceIndex(disk, &busid, &devid) < 0) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("cannot convert disk '%s' to bus/device index"),
                         disk->dst);
        return NULL;
    }

    switch (disk->bus) {
        case VIR_DOMAIN_DISK_BUS_IDE:
            ret = asprintf(&devname, "ide%d-cd%d", busid, devid);
            break;
        case VIR_DOMAIN_DISK_BUS_SCSI:
            ret = asprintf(&devname, "scsi%d-cd%d", busid, devid);
            break;
        case VIR_DOMAIN_DISK_BUS_FDC:
            ret = asprintf(&devname, "floppy%d", devid);
            break;
        case VIR_DOMAIN_DISK_BUS_VIRTIO:
            ret = asprintf(&devname, "virtio%d", devid);
            break;
        default:
            qemudReportError(dom->conn, dom, NULL, VIR_ERR_NO_SUPPORT,
                             _("Unsupported disk name mapping for bus '%s'"),
                             virDomainDiskBusTypeToString(disk->bus));
            return NULL;
    }

    if (ret == -1) {
        qemudReportError(dom->conn, NULL, NULL, VIR_ERR_NO_MEMORY, NULL);
        return NULL;
    }

    return devname;
}

static int qemudDomainChangeEjectableMedia(virDomainPtr dom,
                                           virDomainDeviceDefPtr dev)
{
    struct qemud_driver *driver = (struct qemud_driver *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByUUID(driver->domains, dom->uuid);
    virDomainDiskDefPtr origdisk, newdisk;
    char *cmd, *reply, *safe_path;
    char *devname = NULL;
    unsigned int qemuCmdFlags;

    if (!vm) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         "%s", _("no domain with matching uuid"));
        return -1;
    }

    newdisk = dev->data.disk;
    origdisk = vm->def->disks;
    while (origdisk) {
        if (origdisk->bus == newdisk->bus &&
            STREQ(origdisk->dst, newdisk->dst))
            break;
        origdisk = origdisk->next;
    }

    if (!origdisk) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("No device with bus '%s' and target '%s'"),
                         virDomainDiskBusTypeToString(newdisk->bus),
                         newdisk->dst);
        return -1;
    }

    if (qemudExtractVersionInfo(vm->def->emulator,
                                NULL,
                                &qemuCmdFlags) < 0) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("Cannot determine QEMU argv syntax %s"),
                         vm->def->emulator);
        return -1;
    }

    if (qemuCmdFlags & QEMUD_CMD_FLAG_DRIVE) {
        if (!(devname = qemudDiskDeviceName(dom, newdisk)))
            return -1;
    } else {
        /* Back compat for no -drive option */
        if (newdisk->device == VIR_DOMAIN_DISK_DEVICE_FLOPPY)
            devname = strdup(newdisk->dst);
        else if (newdisk->device == VIR_DOMAIN_DISK_DEVICE_CDROM &&
                 STREQ(newdisk->dst, "hdc"))
            devname = strdup("cdrom");
        else {
            qemudReportError(dom->conn, dom, NULL, VIR_ERR_INTERNAL_ERROR,
                             _("Emulator version does not support removable "
                               "media for device '%s' and target '%s'"),
                               virDomainDiskDeviceTypeToString(newdisk->device),
                               newdisk->dst);
            return -1;
        }

        if (!devname) {
            qemudReportError(dom->conn, NULL, NULL, VIR_ERR_NO_MEMORY, NULL);
            return -1;
        }
    }

    if (newdisk->src) {
        safe_path = qemudEscapeMonitorArg(newdisk->src);
        if (!safe_path) {
            qemudReportError(dom->conn, dom, NULL, VIR_ERR_NO_MEMORY, NULL);
            VIR_FREE(devname);
            return -1;
        }
        if (asprintf (&cmd, "change %s \"%s\"", devname, safe_path) == -1) {
            qemudReportError(dom->conn, dom, NULL, VIR_ERR_NO_MEMORY, NULL);
            VIR_FREE(safe_path);
            VIR_FREE(devname);
            return -1;
        }
        VIR_FREE(safe_path);

    } else if (asprintf(&cmd, "eject %s", devname) == -1) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_NO_MEMORY, NULL);
        VIR_FREE(devname);
        return -1;
    }
    VIR_FREE(devname);

    if (qemudMonitorCommand(driver, vm, cmd, &reply) < 0) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("cannot change cdrom media"));
        VIR_FREE(cmd);
        return -1;
    }

    /* If the command failed qemu prints:
     * device not found, device is locked ...
     * No message is printed on success it seems */
    DEBUG ("ejectable media change reply: %s", reply);
    if (strstr(reply, "\ndevice ")) {
        qemudReportError (dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                          "%s", _("changing cdrom media failed"));
        VIR_FREE(reply);
        VIR_FREE(cmd);
        return -1;
    }
    VIR_FREE(reply);
    VIR_FREE(cmd);

    VIR_FREE(origdisk->src);
    origdisk->src = newdisk->src;
    newdisk->src = NULL;
    origdisk->type = newdisk->type;
    return 0;
}


static int qemudDomainAttachUsbMassstorageDevice(virDomainPtr dom, virDomainDeviceDefPtr dev)
{
    struct qemud_driver *driver = (struct qemud_driver *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByUUID(driver->domains, dom->uuid);
    int ret;
    char *cmd, *reply;
    virDomainDiskDefPtr *dest, *prev, ptr;

    if (!vm) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         "%s", _("no domain with matching uuid"));
        return -1;
    }

    /* Find spot in domain definition where we will put the disk */
    ptr = vm->def->disks;
    prev = &(vm->def->disks);
    while (ptr) {
        if (STREQ(dev->data.disk->dst, ptr->dst)) {
            qemudReportError(dom->conn, dom, NULL, VIR_ERR_INTERNAL_ERROR,
                             _("duplicate disk target '%s'"),
                             dev->data.disk->dst);
            return -1;
        }
        if (virDomainDiskCompare(dev->data.disk, ptr) < 0) {
            dest = &(ptr);
            break;
        }
        prev = &(ptr->next);
        ptr = ptr->next;
    }

    if (!ptr) {
        dest = prev;
    }

    ret = asprintf(&cmd, "usb_add disk:%s", dev->data.disk->src);
    if (ret == -1) {
        qemudReportError(dom->conn, NULL, NULL, VIR_ERR_NO_MEMORY, NULL);
        return ret;
    }

    if (qemudMonitorCommand(driver, vm, cmd, &reply) < 0) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("cannot attach usb disk"));
        VIR_FREE(cmd);
        return -1;
    }

    DEBUG ("attach_usb reply: %s", reply);
    /* If the command failed qemu prints:
     * Could not add ... */
    if (strstr(reply, "Could not add ")) {
        qemudReportError (dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                          "%s",
                          _("adding usb disk failed"));
        VIR_FREE(reply);
        VIR_FREE(cmd);
        return -1;
    }

    /* Actually update the xml */
    dev->data.disk->next = *dest;
    *prev = dev->data.disk;

    VIR_FREE(reply);
    VIR_FREE(cmd);
    return 0;
}

static int qemudDomainAttachHostDevice(virDomainPtr dom, virDomainDeviceDefPtr dev)
{
    struct qemud_driver *driver = (struct qemud_driver *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByUUID(driver->domains, dom->uuid);
    int ret;
    char *cmd, *reply;

    if (!vm) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         "%s", _("no domain with matching uuid"));
        return -1;
    }

    if (dev->data.hostdev->source.subsys.usb.vendor) {
        ret = asprintf(&cmd, "usb_add host:%.4x:%.4x",
                       dev->data.hostdev->source.subsys.usb.vendor,
                       dev->data.hostdev->source.subsys.usb.product);
    } else {
        ret = asprintf(&cmd, "usb_add host:%.3d.%.3d",
                       dev->data.hostdev->source.subsys.usb.bus,
                       dev->data.hostdev->source.subsys.usb.device);
    }
    if (ret == -1) {
        qemudReportError(dom->conn, NULL, NULL, VIR_ERR_NO_MEMORY, NULL);
        return -1;
    }

    if (qemudMonitorCommand(driver, vm, cmd, &reply) < 0) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("cannot attach usb device"));
        VIR_FREE(cmd);
        return -1;
    }

    DEBUG ("attach_usb reply: %s", reply);
    /* If the command failed qemu prints:
     * Could not add ... */
    if (strstr(reply, "Could not add ")) {
        qemudReportError (dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                          "%s",
                          _("adding usb device failed"));
        VIR_FREE(reply);
        VIR_FREE(cmd);
        return -1;
    }

    /* Update xml */
    dev->data.hostdev->next = vm->def->hostdevs;
    vm->def->hostdevs = dev->data.hostdev;

    VIR_FREE(reply);
    VIR_FREE(cmd);
    return 0;
}

static int qemudDomainAttachDevice(virDomainPtr dom,
                                   const char *xml) {
    struct qemud_driver *driver = (struct qemud_driver *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByUUID(driver->domains, dom->uuid);
    virDomainDeviceDefPtr dev;
    int ret = 0;

    if (!vm) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         "%s", _("no domain with matching uuid"));
        return -1;
    }

    if (!virDomainIsActive(vm)) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("cannot attach device on inactive domain"));
        return -1;
    }

    dev = virDomainDeviceDefParse(dom->conn, vm->def, xml);
    if (dev == NULL) {
        return -1;
    }

    if (dev->type == VIR_DOMAIN_DEVICE_DISK &&
        (dev->data.disk->device == VIR_DOMAIN_DISK_DEVICE_CDROM ||
         dev->data.disk->device == VIR_DOMAIN_DISK_DEVICE_FLOPPY)) {
                ret = qemudDomainChangeEjectableMedia(dom, dev);
    } else if (dev->type == VIR_DOMAIN_DEVICE_DISK &&
        dev->data.disk->device == VIR_DOMAIN_DISK_DEVICE_DISK &&
        dev->data.disk->bus == VIR_DOMAIN_DISK_BUS_USB) {
                ret = qemudDomainAttachUsbMassstorageDevice(dom, dev);
    } else if (dev->type == VIR_DOMAIN_DEVICE_HOSTDEV &&
        dev->data.hostdev->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS &&
        dev->data.hostdev->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB) {
                ret = qemudDomainAttachHostDevice(dom, dev);
    } else {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_NO_SUPPORT,
                         "%s", _("this device type cannot be attached"));
        ret = -1;
    }

    VIR_FREE(dev);
    return ret;
}

static int qemudDomainGetAutostart(virDomainPtr dom,
                            int *autostart) {
    struct qemud_driver *driver = (struct qemud_driver *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByUUID(driver->domains, dom->uuid);

    if (!vm) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         "%s", _("no domain with matching uuid"));
        return -1;
    }

    *autostart = vm->autostart;

    return 0;
}

static int qemudDomainSetAutostart(virDomainPtr dom,
                                   int autostart) {
    struct qemud_driver *driver = (struct qemud_driver *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByUUID(driver->domains, dom->uuid);
    char *configFile = NULL, *autostartLink = NULL;
    int ret = -1;

    if (!vm) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         "%s", _("no domain with matching uuid"));
        return -1;
    }

    if (!vm->persistent) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("cannot set autostart for transient domain"));
        return -1;
    }

    autostart = (autostart != 0);

    if (vm->autostart == autostart)
        return 0;

    if ((configFile = virDomainConfigFile(dom->conn, driver->configDir, vm->def->name)) == NULL)
        goto cleanup;
    if ((autostartLink = virDomainConfigFile(dom->conn, driver->autostartDir, vm->def->name)) == NULL)
        goto cleanup;

    if (autostart) {
        int err;

        if ((err = virFileMakePath(driver->autostartDir))) {
            qemudReportError(dom->conn, dom, NULL, VIR_ERR_INTERNAL_ERROR,
                             _("cannot create autostart directory %s: %s"),
                             driver->autostartDir, strerror(err));
            goto cleanup;
        }

        if (symlink(configFile, autostartLink) < 0) {
            qemudReportError(dom->conn, dom, NULL, VIR_ERR_INTERNAL_ERROR,
                             _("Failed to create symlink '%s to '%s': %s"),
                             autostartLink, configFile, strerror(errno));
            goto cleanup;
        }
    } else {
        if (unlink(autostartLink) < 0 && errno != ENOENT && errno != ENOTDIR) {
            qemudReportError(dom->conn, dom, NULL, VIR_ERR_INTERNAL_ERROR,
                             _("Failed to delete symlink '%s': %s"),
                             autostartLink, strerror(errno));
            goto cleanup;
        }
    }

    vm->autostart = autostart;
    ret = 0;

cleanup:
    VIR_FREE(configFile);
    VIR_FREE(autostartLink);

    return ret;
}

/* This uses the 'info blockstats' monitor command which was
 * integrated into both qemu & kvm in late 2007.  If the command is
 * not supported we detect this and return the appropriate error.
 */
static int
qemudDomainBlockStats (virDomainPtr dom,
                       const char *path,
                       struct _virDomainBlockStats *stats)
{
    const struct qemud_driver *driver =
        (struct qemud_driver *)dom->conn->privateData;
    char *dummy, *info;
    const char *p, *eol;
    char qemu_dev_name[32];
    size_t len;
    const virDomainObjPtr vm = virDomainFindByID(driver->domains, dom->id);

    if (!vm) {
        qemudReportError (dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                          _("no domain with matching id %d"), dom->id);
        return -1;
    }
    if (!virDomainIsActive (vm)) {
        qemudReportError (dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                          "%s", _("domain is not running"));
        return -1;
    }

    /*
     * QEMU internal block device names are different from the device
     * names we use in libvirt, so we need to map between them:
     *
     *   hd[a-]   to  ide0-hd[0-]
     *   cdrom    to  ide1-cd0
     *   fd[a-]   to  floppy[0-]
     */
    if (STRPREFIX (path, "hd") && c_islower(path[2]))
        snprintf (qemu_dev_name, sizeof (qemu_dev_name),
                  "ide0-hd%d", path[2] - 'a');
    else if (STREQ (path, "cdrom"))
        strcpy (qemu_dev_name, "ide1-cd0");
    else if (STRPREFIX (path, "fd") && c_islower(path[2]))
        snprintf (qemu_dev_name, sizeof (qemu_dev_name),
                  "floppy%d", path[2] - 'a');
    else {
        qemudReportError (dom->conn, dom, NULL, VIR_ERR_INVALID_ARG,
                          _("invalid path: %s"), path);
        return -1;
    }

    len = strlen (qemu_dev_name);

    if (qemudMonitorCommand (driver, vm, "info blockstats", &info) < 0) {
        qemudReportError (dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                          "%s", _("'info blockstats' command failed"));
        return -1;
    }

    DEBUG ("info blockstats reply: %s", info);

    /* If the command isn't supported then qemu prints the supported
     * info commands, so the output starts "info ".  Since this is
     * unlikely to be the name of a block device, we can use this
     * to detect if qemu supports the command.
     */
    if (STRPREFIX (info, "info ")) {
        free (info);
        qemudReportError (dom->conn, dom, NULL, VIR_ERR_NO_SUPPORT,
                          "%s",
                          _("'info blockstats' not supported by this qemu"));
        return -1;
    }

    stats->rd_req = -1;
    stats->rd_bytes = -1;
    stats->wr_req = -1;
    stats->wr_bytes = -1;
    stats->errs = -1;

    /* The output format for both qemu & KVM is:
     *   blockdevice: rd_bytes=% wr_bytes=% rd_operations=% wr_operations=%
     *   (repeated for each block device)
     * where '%' is a 64 bit number.
     */
    p = info;

    while (*p) {
        if (STREQLEN (p, qemu_dev_name, len)
            && p[len] == ':' && p[len+1] == ' ') {

            eol = strchr (p, '\n');
            if (!eol)
                eol = p + strlen (p);

            p += len+2;         /* Skip to first label. */

            while (*p) {
                if (STRPREFIX (p, "rd_bytes=")) {
                    p += 9;
                    if (virStrToLong_ll (p, &dummy, 10, &stats->rd_bytes) == -1)
                        DEBUG ("error reading rd_bytes: %s", p);
                } else if (STRPREFIX (p, "wr_bytes=")) {
                    p += 9;
                    if (virStrToLong_ll (p, &dummy, 10, &stats->wr_bytes) == -1)
                        DEBUG ("error reading wr_bytes: %s", p);
                } else if (STRPREFIX (p, "rd_operations=")) {
                    p += 14;
                    if (virStrToLong_ll (p, &dummy, 10, &stats->rd_req) == -1)
                        DEBUG ("error reading rd_req: %s", p);
                } else if (STRPREFIX (p, "wr_operations=")) {
                    p += 14;
                    if (virStrToLong_ll (p, &dummy, 10, &stats->wr_req) == -1)
                        DEBUG ("error reading wr_req: %s", p);
                } else
                    DEBUG ("unknown block stat near %s", p);

                /* Skip to next label. */
                p = strchr (p, ' ');
                if (!p || p >= eol) break;
                p++;
            }

            goto done;
        }

        /* Skip to next line. */
        p = strchr (p, '\n');
        if (!p) break;
        p++;
    }

    /* If we reach here then the device was not found. */
    free (info);
    qemudReportError (dom->conn, dom, NULL, VIR_ERR_INVALID_ARG,
                      _("device not found: %s (%s)"), path, qemu_dev_name);
    return -1;

 done:
    free (info);
    return 0;
}

static int
qemudDomainInterfaceStats (virDomainPtr dom,
                           const char *path,
                           struct _virDomainInterfaceStats *stats)
{
#ifdef __linux__
    struct qemud_driver *driver = (struct qemud_driver *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByID(driver->domains, dom->id);
    virDomainNetDefPtr net;

    if (!vm) {
        qemudReportError (dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                          _("no domain with matching id %d"), dom->id);
        return -1;
    }

    if (!virDomainIsActive(vm)) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("domain is not running"));
        return -1;
    }

    if (!path || path[0] == '\0') {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_ARG,
                         "%s", _("NULL or empty path"));
        return -1;
    }

    /* Check the path is one of the domain's network interfaces. */
    for (net = vm->def->nets; net; net = net->next) {
        if (net->ifname && STREQ (net->ifname, path))
            goto ok;
    }

    qemudReportError (dom->conn, dom, NULL, VIR_ERR_INVALID_ARG,
                      _("invalid path, '%s' is not a known interface"), path);
    return -1;
 ok:

    return linuxDomainInterfaceStats (dom->conn, path, stats);
#else
    qemudReportError (dom->conn, dom, NULL, VIR_ERR_NO_SUPPORT,
                      "%s", __FUNCTION__);
    return -1;
#endif
}

static int
qemudDomainBlockPeek (virDomainPtr dom,
                      const char *path,
                      unsigned long long offset, size_t size,
                      void *buffer,
                      unsigned int flags ATTRIBUTE_UNUSED)
{
    struct qemud_driver *driver = (struct qemud_driver *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByUUID(driver->domains, dom->uuid);
    virDomainDiskDefPtr disk;
    int fd, ret = -1;

    if (!vm) {
        qemudReportError (dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                          _("no domain with matching uuid"));
        return -1;
    }

    if (!path || path[0] == '\0') {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_ARG,
                         _("NULL or empty path"));
        return -1;
    }

    /* Check the path belongs to this domain. */
    for (disk = vm->def->disks ; disk != NULL ; disk = disk->next) {
        if (disk->src != NULL &&
            STREQ (disk->src, path)) goto found;
    }
    qemudReportError (dom->conn, dom, NULL, VIR_ERR_INVALID_ARG,
                      _("invalid path"));
    return -1;

found:
    /* The path is correct, now try to open it and get its size. */
    fd = open (path, O_RDONLY);
    if (fd == -1) {
        qemudReportError (dom->conn, dom, NULL, VIR_ERR_SYSTEM_ERROR,
                          "%s", strerror (errno));
        goto done;
    }

    /* Seek and read. */
    /* NB. Because we configure with AC_SYS_LARGEFILE, off_t should
     * be 64 bits on all platforms.
     */
    if (lseek (fd, offset, SEEK_SET) == (off_t) -1 ||
        saferead (fd, buffer, size) == (ssize_t) -1) {
        qemudReportError (dom->conn, dom, NULL, VIR_ERR_SYSTEM_ERROR,
                          "%s", strerror (errno));
        goto done;
    }

    ret = 0;
 done:
    if (fd >= 0) close (fd);
    return ret;
}

static int
qemudDomainMemoryPeek (virDomainPtr dom,
                       unsigned long long offset, size_t size,
                       void *buffer,
                       unsigned int flags)
{
    struct qemud_driver *driver = (struct qemud_driver *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByID(driver->domains, dom->id);
    char cmd[256], *info;
    char tmp[] = TEMPDIR "/qemu.mem.XXXXXX";
    int fd = -1, ret = -1;

    if (flags != VIR_MEMORY_VIRTUAL) {
        qemudReportError (dom->conn, dom, NULL, VIR_ERR_INVALID_ARG,
                          _("QEMU driver only supports virtual memory addrs"));
        return -1;
    }

    if (!vm) {
        qemudReportError (dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                          _("no domain with matching id %d"), dom->id);
        return -1;
    }

    if (!virDomainIsActive(vm)) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("domain is not running"));
        return -1;
    }

    /* Create a temporary filename. */
    if ((fd = mkstemp (tmp)) == -1) {
        qemudReportError (dom->conn, dom, NULL, VIR_ERR_SYSTEM_ERROR,
                          "%s", strerror (errno));
        return -1;
    }

    /* Issue the memsave command. */
    snprintf (cmd, sizeof cmd, "memsave %llu %zi \"%s\"", offset, size, tmp);
    if (qemudMonitorCommand (driver, vm, cmd, &info) < 0) {
        qemudReportError (dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                          "%s", _("'memsave' command failed"));
        goto done;
    }

    DEBUG ("memsave reply: %s", info);
    free (info);

    /* Read the memory file into buffer. */
    if (saferead (fd, buffer, size) == (ssize_t) -1) {
        qemudReportError (dom->conn, dom, NULL, VIR_ERR_SYSTEM_ERROR,
                          "%s", strerror (errno));
        goto done;
    }

    ret = 0;
done:
    if (fd >= 0) close (fd);
    unlink (tmp);
    return ret;
}

static virNetworkPtr qemudNetworkLookupByUUID(virConnectPtr conn ATTRIBUTE_UNUSED,
                                              const unsigned char *uuid) {
    struct qemud_driver *driver = (struct qemud_driver *)conn->networkPrivateData;
    virNetworkObjPtr network = virNetworkFindByUUID(driver->networks, uuid);
    virNetworkPtr net;

    if (!network) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_NO_NETWORK,
                         "%s", _("no network with matching uuid"));
        return NULL;
    }

    net = virGetNetwork(conn, network->def->name, network->def->uuid);
    return net;
}
static virNetworkPtr qemudNetworkLookupByName(virConnectPtr conn ATTRIBUTE_UNUSED,
                                              const char *name) {
    struct qemud_driver *driver = (struct qemud_driver *)conn->networkPrivateData;
    virNetworkObjPtr network = virNetworkFindByName(driver->networks, name);
    virNetworkPtr net;

    if (!network) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_NO_NETWORK,
                         "%s", _("no network with matching name"));
        return NULL;
    }

    net = virGetNetwork(conn, network->def->name, network->def->uuid);
    return net;
}

static virDrvOpenStatus qemudOpenNetwork(virConnectPtr conn,
                                         xmlURIPtr uri ATTRIBUTE_UNUSED,
                                         virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                                         int flags ATTRIBUTE_UNUSED) {
    if (!qemu_driver)
        return VIR_DRV_OPEN_DECLINED;

    conn->networkPrivateData = qemu_driver;
    return VIR_DRV_OPEN_SUCCESS;
}

static int qemudCloseNetwork(virConnectPtr conn) {
    conn->networkPrivateData = NULL;
    return 0;
}

static int qemudNumNetworks(virConnectPtr conn) {
    int nactive = 0;
    struct qemud_driver *driver = (struct qemud_driver *)conn->networkPrivateData;
    virNetworkObjPtr net = driver->networks;
    while (net) {
        if (virNetworkIsActive(net))
            nactive++;
        net = net->next;
    }
    return nactive;
}

static int qemudListNetworks(virConnectPtr conn, char **const names, int nnames) {
    struct qemud_driver *driver = (struct qemud_driver *)conn->networkPrivateData;
    virNetworkObjPtr network = driver->networks;
    int got = 0, i;
    while (network && got < nnames) {
        if (virNetworkIsActive(network)) {
            if (!(names[got] = strdup(network->def->name))) {
                qemudReportError(conn, NULL, NULL, VIR_ERR_NO_MEMORY,
                     "%s", _("failed to allocate space for VM name string"));
                goto cleanup;
            }
            got++;
        }
        network = network->next;
    }
    return got;

 cleanup:
    for (i = 0 ; i < got ; i++)
        VIR_FREE(names[i]);
    return -1;
}

static int qemudNumDefinedNetworks(virConnectPtr conn) {
    int ninactive = 0;
    struct qemud_driver *driver = (struct qemud_driver *)conn->networkPrivateData;
    virNetworkObjPtr net = driver->networks;
    while (net) {
        if (!virNetworkIsActive(net))
            ninactive++;
        net = net->next;
    }
    return ninactive;
}

static int qemudListDefinedNetworks(virConnectPtr conn, char **const names, int nnames) {
    struct qemud_driver *driver = (struct qemud_driver *)conn->networkPrivateData;
    virNetworkObjPtr network = driver->networks;
    int got = 0, i;
    while (network && got < nnames) {
        if (!virNetworkIsActive(network)) {
            if (!(names[got] = strdup(network->def->name))) {
                qemudReportError(conn, NULL, NULL, VIR_ERR_NO_MEMORY,
                     "%s", _("failed to allocate space for VM name string"));
                goto cleanup;
            }
            got++;
        }
        network = network->next;
    }
    return got;

 cleanup:
    for (i = 0 ; i < got ; i++)
        VIR_FREE(names[i]);
    return -1;
}

static virNetworkPtr qemudNetworkCreate(virConnectPtr conn, const char *xml) {
 struct qemud_driver *driver = (struct qemud_driver *)conn->networkPrivateData;
    virNetworkDefPtr def;
    virNetworkObjPtr network;
    virNetworkPtr net;

    if (!(def = virNetworkDefParseString(conn, xml)))
        return NULL;

    if (!(network = virNetworkAssignDef(conn,
                                        &driver->networks,
                                        def))) {
        virNetworkDefFree(def);
        return NULL;
    }

    if (qemudStartNetworkDaemon(conn, driver, network) < 0) {
        virNetworkRemoveInactive(&driver->networks,
                                 network);
        return NULL;
    }

    net = virGetNetwork(conn, network->def->name, network->def->uuid);
    return net;
}

static virNetworkPtr qemudNetworkDefine(virConnectPtr conn, const char *xml) {
    struct qemud_driver *driver = (struct qemud_driver *)conn->networkPrivateData;
    virNetworkDefPtr def;
    virNetworkObjPtr network;

    if (!(def = virNetworkDefParseString(conn, xml)))
        return NULL;

    if (!(network = virNetworkAssignDef(conn,
                                        &driver->networks,
                                        def))) {
        virNetworkDefFree(def);
        return NULL;
    }

    if (virNetworkSaveConfig(conn,
                             driver->networkConfigDir,
                             driver->networkAutostartDir,
                             network) < 0) {
        virNetworkRemoveInactive(&driver->networks,
                                 network);
        return NULL;
    }

    return virGetNetwork(conn, network->def->name, network->def->uuid);
}

static int qemudNetworkUndefine(virNetworkPtr net) {
    struct qemud_driver *driver = (struct qemud_driver *)net->conn->networkPrivateData;
    virNetworkObjPtr network = virNetworkFindByUUID(driver->networks, net->uuid);

    if (!network) {
        qemudReportError(net->conn, NULL, net, VIR_ERR_INVALID_DOMAIN,
                         "%s", _("no network with matching uuid"));
        return -1;
    }

    if (virNetworkIsActive(network)) {
        qemudReportError(net->conn, NULL, net, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("network is still active"));
        return -1;
    }

    if (virNetworkDeleteConfig(net->conn, network) < 0)
        return -1;

    virNetworkRemoveInactive(&driver->networks,
                             network);

    return 0;
}

static int qemudNetworkStart(virNetworkPtr net) {
    struct qemud_driver *driver = (struct qemud_driver *)net->conn->networkPrivateData;
    virNetworkObjPtr network = virNetworkFindByUUID(driver->networks, net->uuid);

    if (!network) {
        qemudReportError(net->conn, NULL, net, VIR_ERR_INVALID_NETWORK,
                         "%s", _("no network with matching uuid"));
        return -1;
    }

    return qemudStartNetworkDaemon(net->conn, driver, network);
}

static int qemudNetworkDestroy(virNetworkPtr net) {
    struct qemud_driver *driver = (struct qemud_driver *)net->conn->networkPrivateData;
    virNetworkObjPtr network = virNetworkFindByUUID(driver->networks, net->uuid);
    int ret;

    if (!network) {
        qemudReportError(net->conn, NULL, net, VIR_ERR_INVALID_NETWORK,
                         "%s", _("no network with matching uuid"));
        return -1;
    }

    ret = qemudShutdownNetworkDaemon(net->conn, driver, network);

    return ret;
}

static char *qemudNetworkDumpXML(virNetworkPtr net, int flags ATTRIBUTE_UNUSED) {
    struct qemud_driver *driver = (struct qemud_driver *)net->conn->networkPrivateData;
    virNetworkObjPtr network = virNetworkFindByUUID(driver->networks, net->uuid);

    if (!network) {
        qemudReportError(net->conn, NULL, net, VIR_ERR_INVALID_NETWORK,
                         "%s", _("no network with matching uuid"));
        return NULL;
    }

    return virNetworkDefFormat(net->conn, network->def);
}

static char *qemudNetworkGetBridgeName(virNetworkPtr net) {
    struct qemud_driver *driver = (struct qemud_driver *)net->conn->networkPrivateData;
    virNetworkObjPtr network = virNetworkFindByUUID(driver->networks, net->uuid);
    char *bridge;
    if (!network) {
        qemudReportError(net->conn, NULL, net, VIR_ERR_INVALID_NETWORK,
                         "%s", _("no network with matching id"));
        return NULL;
    }

    bridge = strdup(network->def->bridge);
    if (!bridge) {
        qemudReportError(net->conn, NULL, net, VIR_ERR_NO_MEMORY,
                 "%s", _("failed to allocate space for network bridge string"));
        return NULL;
    }
    return bridge;
}

static int qemudNetworkGetAutostart(virNetworkPtr net,
                             int *autostart) {
    struct qemud_driver *driver = (struct qemud_driver *)net->conn->networkPrivateData;
    virNetworkObjPtr network = virNetworkFindByUUID(driver->networks, net->uuid);

    if (!network) {
        qemudReportError(net->conn, NULL, net, VIR_ERR_INVALID_NETWORK,
                         "%s", _("no network with matching uuid"));
        return -1;
    }

    *autostart = network->autostart;

    return 0;
}

static int qemudNetworkSetAutostart(virNetworkPtr net,
                             int autostart) {
    struct qemud_driver *driver = (struct qemud_driver *)net->conn->networkPrivateData;
    virNetworkObjPtr network = virNetworkFindByUUID(driver->networks, net->uuid);

    if (!network) {
        qemudReportError(net->conn, NULL, net, VIR_ERR_INVALID_NETWORK,
                         "%s", _("no network with matching uuid"));
        return -1;
    }

    autostart = (autostart != 0);

    if (network->autostart == autostart)
        return 0;

    if (autostart) {
        int err;

        if ((err = virFileMakePath(driver->networkAutostartDir))) {
            qemudReportError(net->conn, NULL, net, VIR_ERR_INTERNAL_ERROR,
                             _("cannot create autostart directory %s: %s"),
                             driver->networkAutostartDir, strerror(err));
            return -1;
        }

        if (symlink(network->configFile, network->autostartLink) < 0) {
            qemudReportError(net->conn, NULL, net, VIR_ERR_INTERNAL_ERROR,
                             _("Failed to create symlink '%s' to '%s': %s"),
                             network->autostartLink, network->configFile, strerror(errno));
            return -1;
        }
    } else {
        if (unlink(network->autostartLink) < 0 && errno != ENOENT && errno != ENOTDIR) {
            qemudReportError(net->conn, NULL, net, VIR_ERR_INTERNAL_ERROR,
                             _("Failed to delete symlink '%s': %s"),
                             network->autostartLink, strerror(errno));
            return -1;
        }
    }

    network->autostart = autostart;

    return 0;
}

static virDriver qemuDriver = {
    VIR_DRV_QEMU,
    "QEMU",
    LIBVIR_VERSION_NUMBER,
    qemudProbe, /* probe */
    qemudOpen, /* open */
    qemudClose, /* close */
    NULL, /* supports_feature */
    qemudGetType, /* type */
    qemudGetVersion, /* version */
    qemudGetHostname, /* hostname */
    NULL, /* URI  */
    qemudGetMaxVCPUs, /* getMaxVcpus */
    qemudGetNodeInfo, /* nodeGetInfo */
    qemudGetCapabilities, /* getCapabilities */
    qemudListDomains, /* listDomains */
    qemudNumDomains, /* numOfDomains */
    qemudDomainCreate, /* domainCreateLinux */
    qemudDomainLookupByID, /* domainLookupByID */
    qemudDomainLookupByUUID, /* domainLookupByUUID */
    qemudDomainLookupByName, /* domainLookupByName */
    qemudDomainSuspend, /* domainSuspend */
    qemudDomainResume, /* domainResume */
    qemudDomainShutdown, /* domainShutdown */
    NULL, /* domainReboot */
    qemudDomainDestroy, /* domainDestroy */
    qemudDomainGetOSType, /* domainGetOSType */
    qemudDomainGetMaxMemory, /* domainGetMaxMemory */
    qemudDomainSetMaxMemory, /* domainSetMaxMemory */
    qemudDomainSetMemory, /* domainSetMemory */
    qemudDomainGetInfo, /* domainGetInfo */
    qemudDomainSave, /* domainSave */
    qemudDomainRestore, /* domainRestore */
    NULL, /* domainCoreDump */
    qemudDomainSetVcpus, /* domainSetVcpus */
#if HAVE_SCHED_GETAFFINITY
    qemudDomainPinVcpu, /* domainPinVcpu */
    qemudDomainGetVcpus, /* domainGetVcpus */
#else
    NULL, /* domainPinVcpu */
    NULL, /* domainGetVcpus */
#endif
    qemudDomainGetMaxVcpus, /* domainGetMaxVcpus */
    qemudDomainDumpXML, /* domainDumpXML */
    qemudListDefinedDomains, /* listDomains */
    qemudNumDefinedDomains, /* numOfDomains */
    qemudDomainStart, /* domainCreate */
    qemudDomainDefine, /* domainDefineXML */
    qemudDomainUndefine, /* domainUndefine */
    qemudDomainAttachDevice, /* domainAttachDevice */
    NULL, /* domainDetachDevice */
    qemudDomainGetAutostart, /* domainGetAutostart */
    qemudDomainSetAutostart, /* domainSetAutostart */
    NULL, /* domainGetSchedulerType */
    NULL, /* domainGetSchedulerParameters */
    NULL, /* domainSetSchedulerParameters */
    NULL, /* domainMigratePrepare */
    NULL, /* domainMigratePerform */
    NULL, /* domainMigrateFinish */
    qemudDomainBlockStats, /* domainBlockStats */
    qemudDomainInterfaceStats, /* domainInterfaceStats */
    qemudDomainBlockPeek, /* domainBlockPeek */
    qemudDomainMemoryPeek, /* domainMemoryPeek */
#if HAVE_NUMACTL
    qemudNodeGetCellsFreeMemory, /* nodeGetCellsFreeMemory */
    qemudNodeGetFreeMemory,  /* getFreeMemory */
#else
    NULL, /* nodeGetCellsFreeMemory */
    NULL, /* getFreeMemory */
#endif
};

static virNetworkDriver qemuNetworkDriver = {
    "QEMU",
    qemudOpenNetwork, /* open */
    qemudCloseNetwork, /* close */
    qemudNumNetworks, /* numOfNetworks */
    qemudListNetworks, /* listNetworks */
    qemudNumDefinedNetworks, /* numOfDefinedNetworks */
    qemudListDefinedNetworks, /* listDefinedNetworks */
    qemudNetworkLookupByUUID, /* networkLookupByUUID */
    qemudNetworkLookupByName, /* networkLookupByName */
    qemudNetworkCreate, /* networkCreateXML */
    qemudNetworkDefine, /* networkDefineXML */
    qemudNetworkUndefine, /* networkUndefine */
    qemudNetworkStart, /* networkCreate */
    qemudNetworkDestroy, /* networkDestroy */
    qemudNetworkDumpXML, /* networkDumpXML */
    qemudNetworkGetBridgeName, /* networkGetBridgeName */
    qemudNetworkGetAutostart, /* networkGetAutostart */
    qemudNetworkSetAutostart, /* networkSetAutostart */
};

#ifdef WITH_LIBVIRTD
static virStateDriver qemuStateDriver = {
    qemudStartup,
    qemudShutdown,
    qemudReload,
    qemudActive,
    NULL
};
#endif

int qemudRegister(void) {
    virRegisterDriver(&qemuDriver);
    virRegisterNetworkDriver(&qemuNetworkDriver);
#ifdef WITH_LIBVIRTD
    virRegisterStateDriver(&qemuStateDriver);
#endif
    return 0;
}

