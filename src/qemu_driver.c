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
#define NUMA_VERSION1_COMPATIBILITY 1
#include <numa.h>
#endif

#if HAVE_SCHED_H
#include <sched.h>
#endif

#include "virterror_internal.h"
#include "logging.h"
#include "datatypes.h"
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

static int qemudShutdown(void);

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


static void qemudDomainEventDispatch (struct qemud_driver *driver,
                                      virDomainObjPtr vm,
                                      int event,
                                      int detail);

static void qemudDispatchVMEvent(int watch,
                                 int fd,
                                 int events,
                                 void *opaque);

static int qemudStartVMDaemon(virConnectPtr conn,
                              struct qemud_driver *driver,
                              virDomainObjPtr vm,
                              const char *migrateFrom);

static void qemudShutdownVMDaemon(virConnectPtr conn,
                                  struct qemud_driver *driver,
                                  virDomainObjPtr vm);

static int qemudDomainGetMaxVcpus(virDomainPtr dom);

static int qemudMonitorCommand (const struct qemud_driver *driver,
                                const virDomainObjPtr vm,
                                const char *cmd,
                                char **reply);

static struct qemud_driver *qemu_driver = NULL;


static void
qemudAutostartConfigs(struct qemud_driver *driver) {
    unsigned int i;

    for (i = 0 ; i < driver->domains.count ; i++) {
        virDomainObjPtr vm = driver->domains.objs[i];
        if (vm->autostart &&
            !virDomainIsActive(vm)) {
            int ret = qemudStartVMDaemon(NULL, driver, vm, NULL);
            if (ret < 0) {
                virErrorPtr err = virGetLastError();
                qemudLog(QEMUD_ERR, _("Failed to autostart VM '%s': %s\n"),
                         vm->def->name,
                         err ? err->message : NULL);
            } else {
                qemudDomainEventDispatch(driver, vm, VIR_DOMAIN_EVENT_STARTED,
                                         VIR_DOMAIN_EVENT_STARTED_BOOTED);
            }
        }
    }
}

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

    /* Init callback list */
    if(VIR_ALLOC(qemu_driver->domainEventCallbacks) < 0)
        return -1;

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
            goto out_nouid;
        }

        if (asprintf(&qemu_driver->logDir,
                     "%s/.libvirt/qemu/log", pw->pw_dir) == -1)
            goto out_of_memory;

        if (asprintf (&base, "%s/.libvirt", pw->pw_dir) == -1)
            goto out_of_memory;
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
                                qemu_driver->autostartDir,
                                NULL, NULL) < 0) {
        qemudShutdown();
        return -1;
    }
    qemudAutostartConfigs(qemu_driver);

    return 0;

 out_of_memory:
    qemudLog (QEMUD_ERR,
              "%s", _("qemudStartup: out of memory\n"));
 out_nouid:
    VIR_FREE(base);
    VIR_FREE(qemu_driver);
    return -1;
}

static void qemudNotifyLoadDomain(virDomainObjPtr vm, int newVM, void *opaque)
{
    struct qemud_driver *driver = opaque;

    if (newVM)
        qemudDomainEventDispatch(driver, vm,
                                 VIR_DOMAIN_EVENT_DEFINED,
                                 VIR_DOMAIN_EVENT_DEFINED_ADDED);
}

/**
 * qemudReload:
 *
 * Function to restart the QEmu daemon, it will recheck the configuration
 * files and update its state and the networking
 */
static int
qemudReload(void) {
    if (!qemu_driver)
        return 0;

    virDomainLoadAllConfigs(NULL,
                            qemu_driver->caps,
                            &qemu_driver->domains,
                            qemu_driver->configDir,
                            qemu_driver->autostartDir,
                            qemudNotifyLoadDomain, qemu_driver);

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
    unsigned int i;

    if (!qemu_driver)
        return 0;

    for (i = 0 ; i < qemu_driver->domains.count ; i++)
        if (virDomainIsActive(qemu_driver->domains.objs[i]))
            return 1;

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
    unsigned int i;

    if (!qemu_driver)
        return -1;

    virCapabilitiesFree(qemu_driver->caps);

    /* shutdown active VMs */
    for (i = 0 ; i < qemu_driver->domains.count ; i++) {
        virDomainObjPtr dom = qemu_driver->domains.objs[i];
        if (virDomainIsActive(dom))
            qemudShutdownVMDaemon(NULL, qemu_driver, dom);
        if (!dom->persistent)
            virDomainRemoveInactive(&qemu_driver->domains,
                                    dom);
    }

    virDomainObjListFree(&qemu_driver->domains);

    VIR_FREE(qemu_driver->logDir);
    VIR_FREE(qemu_driver->configDir);
    VIR_FREE(qemu_driver->autostartDir);
    VIR_FREE(qemu_driver->vncTLSx509certdir);
    VIR_FREE(qemu_driver->vncListen);

    /* Free domain callback list */
    virDomainEventCallbackListFree(qemu_driver->domainEventCallbacks);

    if (qemu_driver->brctl)
        brShutdown(qemu_driver->brctl);

    VIR_FREE(qemu_driver);

    return 0;
}

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
                       const char *what,
                       int timeout)
{
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

            ret = poll(&pfd, 1, timeout);
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
                                 "monitor", 10000);

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
            *offset = tmp - haystack;
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
    int ret, i;

    /* The order in which QEMU prints out the PTY paths is
       the order in which it procsses its monitor, serial
       and parallel device args. This code must match that
       ordering.... */

    /* So first comes the monitor device */
    if ((ret = qemudExtractMonitorPath(conn, output, &offset, &monitor)) != 0)
        goto cleanup;

    /* then the serial devices */
    for (i = 0 ; i < vm->def->nserials ; i++) {
        virDomainChrDefPtr chr = vm->def->serials[i];
        if (chr->type == VIR_DOMAIN_CHR_TYPE_PTY) {
            if ((ret = qemudExtractMonitorPath(conn, output, &offset,
                                               &chr->data.file.path)) != 0)
                goto cleanup;
        }
    }

    /* and finally the parallel devices */
    for (i = 0 ; i < vm->def->nparallels ; i++) {
        virDomainChrDefPtr chr = vm->def->parallels[i];
        if (chr->type == VIR_DOMAIN_CHR_TYPE_PTY) {
            if ((ret = qemudExtractMonitorPath(conn, output, &offset,
                                               &chr->data.file.path)) != 0)
                goto cleanup;
        }
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
                                     "console", 3000);

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
              virDomainObjPtr vm,
              const char *migrateFrom) {
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

    if (migrateFrom == NULL) {
        /* Allow the CPUS to start executing */
        if (qemudMonitorCommand(driver, vm, "cont", &info) < 0) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("resume operation failed"));
            return -1;
        }
        VIR_FREE(info);
    }

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

static virDomainPtr qemudDomainLookupByName(virConnectPtr conn,
                                            const char *name);

static int qemudStartVMDaemon(virConnectPtr conn,
                              struct qemud_driver *driver,
                              virDomainObjPtr vm,
                              const char *migrateFrom) {
    const char **argv = NULL, **tmp;
    const char **progenv = NULL;
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

    vm->def->id = driver->nextvmid++;
    if (qemudBuildCommandLine(conn, driver, vm,
                              qemuCmdFlags, &argv, &progenv,
                              &tapfds, &ntapfds, migrateFrom) < 0) {
        close(vm->logfile);
        vm->def->id = -1;
        vm->logfile = -1;
        return -1;
    }

    tmp = progenv;
    while (*tmp) {
        if (safewrite(vm->logfile, *tmp, strlen(*tmp)) < 0)
            qemudLog(QEMUD_WARN, _("Unable to write envv to logfile %d: %s\n"),
                     errno, strerror(errno));
        if (safewrite(vm->logfile, " ", 1) < 0)
            qemudLog(QEMUD_WARN, _("Unable to write envv to logfile %d: %s\n"),
                     errno, strerror(errno));
        tmp++;
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

    ret = virExec(conn, argv, progenv, &keepfd, &vm->pid,
                  vm->stdin_fd, &vm->stdout_fd, &vm->stderr_fd,
                  VIR_EXEC_NONBLOCK);
    if (ret == 0)
        vm->state = migrateFrom ? VIR_DOMAIN_PAUSED : VIR_DOMAIN_RUNNING;
    else
        vm->def->id = -1;

    for (i = 0 ; argv[i] ; i++)
        VIR_FREE(argv[i]);
    VIR_FREE(argv);

    for (i = 0 ; progenv[i] ; i++)
        VIR_FREE(progenv[i]);
    VIR_FREE(progenv);

    if (tapfds) {
        for (i = 0 ; i < ntapfds ; i++) {
            close(tapfds[i]);
        }
        VIR_FREE(tapfds);
    }

    if (ret == 0) {
        if (((vm->stdout_watch = virEventAddHandle(vm->stdout_fd,
                                                   VIR_EVENT_HANDLE_READABLE |
                                                   VIR_EVENT_HANDLE_ERROR |
                                                   VIR_EVENT_HANDLE_HANGUP,
                                                   qemudDispatchVMEvent,
                                                   driver, NULL)) < 0) ||
            ((vm->stderr_watch = virEventAddHandle(vm->stderr_fd,
                                                   VIR_EVENT_HANDLE_READABLE |
                                                   VIR_EVENT_HANDLE_ERROR |
                                                   VIR_EVENT_HANDLE_HANGUP,
                                                   qemudDispatchVMEvent,
                                                   driver, NULL)) < 0) ||
            (qemudWaitForMonitor(conn, driver, vm) < 0) ||
            (qemudDetectVcpuPIDs(conn, driver, vm) < 0) ||
            (qemudInitCpus(conn, driver, vm, migrateFrom) < 0)) {
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

    virEventRemoveHandle(vm->stdout_watch);
    virEventRemoveHandle(vm->stderr_watch);

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
        qemudDomainEventDispatch(driver, vm,
                                 VIR_DOMAIN_EVENT_STOPPED,
                                 VIR_DOMAIN_EVENT_STOPPED_FAILED);
        if (!vm->persistent)
            virDomainRemoveInactive(&driver->domains,
                                    vm);
    }
    return 0;
}

static int qemudDispatchVMFailure(struct qemud_driver *driver, virDomainObjPtr vm,
                                  int fd ATTRIBUTE_UNUSED) {
    qemudShutdownVMDaemon(NULL, driver, vm);
    qemudDomainEventDispatch(driver, vm,
                             VIR_DOMAIN_EVENT_STOPPED,
                             VIR_DOMAIN_EVENT_STOPPED_SHUTDOWN);
    if (!vm->persistent)
        virDomainRemoveInactive(&driver->domains,
                                vm);
    return 0;
}


static void
qemudDispatchVMEvent(int watch, int fd, int events, void *opaque) {
    struct qemud_driver *driver = (struct qemud_driver *)opaque;
    virDomainObjPtr vm = NULL;
    unsigned int i;

    for (i = 0 ; i < driver->domains.count ; i++) {
        if (virDomainIsActive(driver->domains.objs[i]) &&
            (driver->domains.objs[i]->stdout_watch == watch ||
             driver->domains.objs[i]->stderr_watch == watch)) {
            vm = driver->domains.objs[i];
            break;
        }
    }

    if (!vm)
        return;

    if (vm->stdout_fd != fd &&
        vm->stderr_fd != fd) {
        qemudDispatchVMFailure(driver, vm, fd);
        return;
    }

    if (events == VIR_EVENT_HANDLE_READABLE)
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
static int qemudProbe(void)
{
    if ((virFileExists("/usr/bin/qemu")) ||
        (virFileExists("/usr/bin/qemu-kvm")) ||
        (virFileExists("/usr/bin/kvm")) ||
        (virFileExists("/usr/bin/xenner")))
        return 1;

    return 0;
}

static virDrvOpenStatus qemudOpen(virConnectPtr conn,
                                  virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                                  int flags ATTRIBUTE_UNUSED) {
    uid_t uid = getuid();

    if (qemu_driver == NULL)
        goto decline;

    if (!qemudProbe())
        goto decline;

    if (conn->uri == NULL) {
        conn->uri = xmlParseURI(uid ? "qemu:///session" : "qemu:///system");
        if (!conn->uri) {
            qemudReportError(conn, NULL, NULL, VIR_ERR_NO_MEMORY,NULL);
            return VIR_DRV_OPEN_ERROR;
        }
    } else if (conn->uri->scheme == NULL ||
               conn->uri->path == NULL)
        goto decline;

    if (STRNEQ (conn->uri->scheme, "qemu"))
        goto decline;

    if (uid != 0) {
        if (STRNEQ (conn->uri->path, "/session"))
            goto decline;
    } else { /* root */
        if (STRNEQ (conn->uri->path, "/system") &&
            STRNEQ (conn->uri->path, "/session"))
            goto decline;
    }

    conn->privateData = qemu_driver;

    return VIR_DRV_OPEN_SUCCESS;

 decline:
    return VIR_DRV_OPEN_DECLINED;
}

static int qemudClose(virConnectPtr conn) {
    struct qemud_driver *driver = (struct qemud_driver *)conn->privateData;

    /* Get rid of callbacks registered for this conn */
    virDomainEventCallbackListRemoveConn(conn, driver->domainEventCallbacks);

    conn->privateData = NULL;

    return 0;
}

/* Which features are supported by this driver? */
static int
qemudSupportsFeature (virConnectPtr conn ATTRIBUTE_UNUSED, int feature)
{
    switch (feature) {
    case VIR_DRV_FEATURE_MIGRATION_V2: return 1;
    default: return 0;
    }
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
    virDomainObjPtr vm = virDomainFindByID(&driver->domains, id);
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
    virDomainObjPtr vm = virDomainFindByUUID(&driver->domains, uuid);
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
    virDomainObjPtr vm = virDomainFindByName(&driver->domains, name);
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
    int got = 0, i;

    for (i = 0 ; i < driver->domains.count && got < nids ; i++)
        if (virDomainIsActive(driver->domains.objs[i]))
            ids[got++] = driver->domains.objs[i]->def->id;

    return got;
}
static int qemudNumDomains(virConnectPtr conn) {
    struct qemud_driver *driver = (struct qemud_driver *)conn->privateData;
    int n = 0, i;

    for (i = 0 ; i < driver->domains.count ; i++)
        if (virDomainIsActive(driver->domains.objs[i]))
            n++;

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

    vm = virDomainFindByName(&driver->domains, def->name);
    if (vm) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         _("domain '%s' is already defined"),
                         def->name);
        virDomainDefFree(def);
        return NULL;
    }
    vm = virDomainFindByUUID(&driver->domains, def->uuid);
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
    qemudDomainEventDispatch(driver, vm,
                             VIR_DOMAIN_EVENT_STARTED,
                             VIR_DOMAIN_EVENT_STARTED_BOOTED);

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom) dom->id = vm->def->id;
    return dom;
}


static int qemudDomainSuspend(virDomainPtr dom) {
    struct qemud_driver *driver = (struct qemud_driver *)dom->conn->privateData;
    char *info;
    virDomainObjPtr vm = virDomainFindByID(&driver->domains, dom->id);
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
    qemudDomainEventDispatch(driver, vm,
                             VIR_DOMAIN_EVENT_SUSPENDED,
                             VIR_DOMAIN_EVENT_SUSPENDED_PAUSED);
    VIR_FREE(info);
    return 0;
}


static int qemudDomainResume(virDomainPtr dom) {
    struct qemud_driver *driver = (struct qemud_driver *)dom->conn->privateData;
    char *info;
    virDomainObjPtr vm = virDomainFindByID(&driver->domains, dom->id);
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
    qemudDomainEventDispatch(driver, vm,
                             VIR_DOMAIN_EVENT_RESUMED,
                             VIR_DOMAIN_EVENT_RESUMED_UNPAUSED);
    VIR_FREE(info);
    return 0;
}


static int qemudDomainShutdown(virDomainPtr dom) {
    struct qemud_driver *driver = (struct qemud_driver *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByID(&driver->domains, dom->id);
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
    VIR_FREE(info);
    return 0;

}


static int qemudDomainDestroy(virDomainPtr dom) {
    struct qemud_driver *driver = (struct qemud_driver *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByID(&driver->domains, dom->id);

    if (!vm) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         _("no domain with matching id %d"), dom->id);
        return -1;
    }

    qemudShutdownVMDaemon(dom->conn, driver, vm);
    qemudDomainEventDispatch(driver, vm,
                             VIR_DOMAIN_EVENT_STOPPED,
                             VIR_DOMAIN_EVENT_STOPPED_DESTROYED);
    if (!vm->persistent)
        virDomainRemoveInactive(&driver->domains,
                                vm);
    return 0;
}


static char *qemudDomainGetOSType(virDomainPtr dom) {
    struct qemud_driver *driver = (struct qemud_driver *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByUUID(&driver->domains, dom->uuid);
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
    virDomainObjPtr vm = virDomainFindByUUID(&driver->domains, dom->uuid);

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
    virDomainObjPtr vm = virDomainFindByUUID(&driver->domains, dom->uuid);

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
    virDomainObjPtr vm = virDomainFindByUUID(&driver->domains, dom->uuid);

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
    virDomainObjPtr vm = virDomainFindByUUID(&driver->domains, dom->uuid);
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
    virDomainObjPtr vm = virDomainFindByID(&driver->domains, dom->id);
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
    qemudDomainEventDispatch(driver, vm,
                             VIR_DOMAIN_EVENT_STOPPED,
                             VIR_DOMAIN_EVENT_STOPPED_SAVED);
    if (!vm->persistent)
        virDomainRemoveInactive(&driver->domains,
                                vm);
    return 0;
}


static int qemudDomainSetVcpus(virDomainPtr dom, unsigned int nvcpus) {
    struct qemud_driver *driver = (struct qemud_driver *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByUUID(&driver->domains, dom->uuid);
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
    virDomainObjPtr vm = virDomainFindByUUID(&driver->domains, dom->uuid);
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
    virDomainObjPtr vm = virDomainFindByUUID(&driver->domains, dom->uuid);
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
    virDomainObjPtr vm = virDomainFindByUUID(&driver->domains, dom->uuid);
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
    vm = virDomainFindByUUID(&driver->domains, def->uuid);
    if (!vm)
        vm = virDomainFindByName(&driver->domains, def->name);
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

    qemudDomainEventDispatch(driver, vm,
                             VIR_DOMAIN_EVENT_STARTED,
                             VIR_DOMAIN_EVENT_STARTED_RESTORED);

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
    virDomainObjPtr vm = virDomainFindByUUID(&driver->domains, dom->uuid);
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
    int got = 0, i;

    for (i = 0 ; i < driver->domains.count && got < nnames ; i++) {
        if (!virDomainIsActive(driver->domains.objs[i])) {
            if (!(names[got++] = strdup(driver->domains.objs[i]->def->name))) {
                qemudReportError(conn, NULL, NULL, VIR_ERR_NO_MEMORY,
                                 "%s", _("failed to allocate space for VM name string"));
                goto cleanup;
            }
        }
    }

    return got;

 cleanup:
    for (i = 0 ; i < got ; i++)
        VIR_FREE(names[i]);
    return -1;
}

static int qemudNumDefinedDomains(virConnectPtr conn) {
    struct qemud_driver *driver = (struct qemud_driver *)conn->privateData;
    int n = 0, i;

    for (i = 0 ; i < driver->domains.count ; i++)
        if (!virDomainIsActive(driver->domains.objs[i]))
            n++;

    return n;
}


static int qemudDomainStart(virDomainPtr dom) {
    struct qemud_driver *driver = (struct qemud_driver *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    int ret;

    if (!vm) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         "%s", _("no domain with matching uuid"));
        return -1;
    }

    ret = qemudStartVMDaemon(dom->conn, driver, vm, NULL);
    if (ret < 0)
        return ret;
    qemudDomainEventDispatch(driver, vm,
                             VIR_DOMAIN_EVENT_STARTED,
                             VIR_DOMAIN_EVENT_STARTED_BOOTED);
    return 0;
}


static virDomainPtr qemudDomainDefine(virConnectPtr conn, const char *xml) {
    struct qemud_driver *driver = (struct qemud_driver *)conn->privateData;
    virDomainDefPtr def;
    virDomainObjPtr vm;
    virDomainPtr dom;
    int newVM = 1;

    if (!(def = virDomainDefParseString(conn, driver->caps, xml)))
        return NULL;

    vm = virDomainFindByName(&driver->domains, def->name);
    if (vm)
        newVM = 0;

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

    qemudDomainEventDispatch(driver, vm,
                             VIR_DOMAIN_EVENT_DEFINED,
                             newVM ?
                             VIR_DOMAIN_EVENT_DEFINED_ADDED :
                             VIR_DOMAIN_EVENT_DEFINED_UPDATED);

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom) dom->id = vm->def->id;
    return dom;
}

static int qemudDomainUndefine(virDomainPtr dom) {
    struct qemud_driver *driver = (struct qemud_driver *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByUUID(&driver->domains, dom->uuid);

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

    qemudDomainEventDispatch(driver, vm,
                             VIR_DOMAIN_EVENT_UNDEFINED,
                             VIR_DOMAIN_EVENT_UNDEFINED_REMOVED);

    virDomainRemoveInactive(&driver->domains,
                            vm);

    return 0;
}

/* Return the disks name for use in monitor commands */
static char *qemudDiskDeviceName(const virDomainPtr dom,
                                 const virDomainDiskDefPtr disk) {

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
            if (disk->device== VIR_DOMAIN_DISK_DEVICE_DISK)
                ret = asprintf(&devname, "ide%d-hd%d", busid, devid);
            else
                ret = asprintf(&devname, "ide%d-cd%d", busid, devid);
            break;
        case VIR_DOMAIN_DISK_BUS_SCSI:
            if (disk->device == VIR_DOMAIN_DISK_DEVICE_DISK)
                ret = asprintf(&devname, "scsi%d-hd%d", busid, devid);
            else
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
    virDomainObjPtr vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    virDomainDiskDefPtr origdisk = NULL, newdisk;
    char *cmd, *reply, *safe_path;
    char *devname = NULL;
    unsigned int qemuCmdFlags;
    int i;

    if (!vm) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         "%s", _("no domain with matching uuid"));
        return -1;
    }

    origdisk = NULL;
    newdisk = dev->data.disk;
    for (i = 0 ; i < vm->def->ndisks ; i++) {
        if (vm->def->disks[i]->bus == newdisk->bus &&
            STREQ(vm->def->disks[i]->dst, newdisk->dst)) {
            origdisk = vm->def->disks[i];
            break;
        }
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

static int qemudDomainAttachPciDiskDevice(virDomainPtr dom, virDomainDeviceDefPtr dev)
{
    struct qemud_driver *driver = (struct qemud_driver *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    int ret, i;
    char *cmd, *reply, *s;
    char *safe_path;
    const char* type = virDomainDiskBusTypeToString(dev->data.disk->bus);

    if (!vm) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         "%s", _("no domain with matching uuid"));
        return -1;
    }

    for (i = 0 ; i < vm->def->ndisks ; i++) {
        if (STREQ(vm->def->disks[i]->dst, dev->data.disk->dst)) {
            qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                           _("target %s already exists"), dev->data.disk->dst);
            return -1;
        }
    }

    if (VIR_REALLOC_N(vm->def->disks, vm->def->ndisks+1) < 0) {
        qemudReportError(dom->conn, NULL, NULL, VIR_ERR_NO_MEMORY, NULL);
        return -1;
    }

    safe_path = qemudEscapeMonitorArg(dev->data.disk->src);
    if (!safe_path) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("out of memory"));
        return -1;
    }

    ret = asprintf(&cmd, "pci_add 0 storage file=%s,if=%s",
                         safe_path, type);
    VIR_FREE(safe_path);
    if (ret == -1) {
        qemudReportError(dom->conn, NULL, NULL, VIR_ERR_NO_MEMORY, NULL);
        return ret;
    }

    if (qemudMonitorCommand(driver, vm, cmd, &reply) < 0) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                         _("cannot attach %s disk"), type);
        VIR_FREE(cmd);
        return -1;
    }

    DEBUG ("pci_add reply: %s", reply);
    /* If the command succeeds qemu prints:
     * OK bus 0... */
#define PCI_ATTACH_OK_MSG "OK bus 0, slot "
    if ((s=strstr(reply, PCI_ATTACH_OK_MSG))) {
        char* dummy = s;
        s += strlen(PCI_ATTACH_OK_MSG);

        if (virStrToLong_i ((const char*)s, &dummy, 10, &dev->data.disk->slotnum) == -1)
            qemudLog(QEMUD_WARN, "%s", _("Unable to parse slot number\n"));
    } else {
        qemudReportError (dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                          _("adding %s disk failed"), type);
        VIR_FREE(reply);
        VIR_FREE(cmd);
        return -1;
    }

    vm->def->disks[vm->def->ndisks++] = dev->data.disk;
    qsort(vm->def->disks, vm->def->ndisks, sizeof(*vm->def->disks),
          virDomainDiskQSort);

    VIR_FREE(reply);
    VIR_FREE(cmd);
    return 0;
}

static int qemudDomainAttachUsbMassstorageDevice(virDomainPtr dom, virDomainDeviceDefPtr dev)
{
    struct qemud_driver *driver = (struct qemud_driver *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    int ret, i;
    char *safe_path;
    char *cmd, *reply;

    if (!vm) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         "%s", _("no domain with matching uuid"));
        return -1;
    }

    for (i = 0 ; i < vm->def->ndisks ; i++) {
        if (STREQ(vm->def->disks[i]->dst, dev->data.disk->dst)) {
            qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                           _("target %s already exists"), dev->data.disk->dst);
            return -1;
        }
    }

    if (VIR_REALLOC_N(vm->def->disks, vm->def->ndisks+1) < 0) {
        qemudReportError(dom->conn, NULL, NULL, VIR_ERR_NO_MEMORY, NULL);
        return -1;
    }

    safe_path = qemudEscapeMonitorArg(dev->data.disk->src);
    if (!safe_path) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("out of memory"));
        return -1;
    }

    ret = asprintf(&cmd, "usb_add disk:%s", safe_path);
    VIR_FREE(safe_path);
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

    vm->def->disks[vm->def->ndisks++] = dev->data.disk;
    qsort(vm->def->disks, vm->def->ndisks, sizeof(*vm->def->disks),
          virDomainDiskQSort);

    VIR_FREE(reply);
    VIR_FREE(cmd);
    return 0;
}

static int qemudDomainAttachHostDevice(virDomainPtr dom, virDomainDeviceDefPtr dev)
{
    struct qemud_driver *driver = (struct qemud_driver *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    int ret;
    char *cmd, *reply;

    if (!vm) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         "%s", _("no domain with matching uuid"));
        return -1;
    }
    if (VIR_REALLOC_N(vm->def->hostdevs, vm->def->nhostdevs+1) < 0) {
        qemudReportError(dom->conn, NULL, NULL, VIR_ERR_NO_MEMORY, NULL);
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

    vm->def->hostdevs[vm->def->nhostdevs++] = dev->data.hostdev;

    VIR_FREE(reply);
    VIR_FREE(cmd);
    return 0;
}

static int qemudDomainAttachDevice(virDomainPtr dom,
                                   const char *xml) {
    struct qemud_driver *driver = (struct qemud_driver *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    virDomainDeviceDefPtr dev;
    int ret = 0, supported = 0;

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

    dev = virDomainDeviceDefParse(dom->conn,
                                  driver->caps,
                                  vm->def, xml);
    if (dev == NULL) {
        return -1;
    }

    if (dev->type == VIR_DOMAIN_DEVICE_DISK) {
        switch (dev->data.disk->device) {
            case VIR_DOMAIN_DISK_DEVICE_CDROM:
            case VIR_DOMAIN_DISK_DEVICE_FLOPPY:
                supported = 1;
                ret = qemudDomainChangeEjectableMedia(dom, dev);
                break;
            case VIR_DOMAIN_DISK_DEVICE_DISK:
                if (dev->data.disk->bus == VIR_DOMAIN_DISK_BUS_USB) {
                    supported = 1;
                    ret = qemudDomainAttachUsbMassstorageDevice(dom, dev);
                } else if (dev->data.disk->bus == VIR_DOMAIN_DISK_BUS_SCSI ||
                           dev->data.disk->bus == VIR_DOMAIN_DISK_BUS_VIRTIO) {
                    supported = 1;
                    ret = qemudDomainAttachPciDiskDevice(dom, dev);
                }
                break;
        }
    } else if (dev->type == VIR_DOMAIN_DEVICE_HOSTDEV &&
        dev->data.hostdev->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS &&
        dev->data.hostdev->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB) {
                supported = 1;
                ret = qemudDomainAttachHostDevice(dom, dev);
    }

    if (!supported) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_NO_SUPPORT,
                         "%s", _("this device type cannot be attached"));
        ret = -1;
    }

    VIR_FREE(dev);
    return ret;
}

static int qemudDomainDetachPciDiskDevice(virDomainPtr dom, virDomainDeviceDefPtr dev)
{
    struct qemud_driver *driver = (struct qemud_driver *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    int i, ret = -1;
    char *cmd, *reply;
    virDomainDiskDefPtr detach = NULL;

    if (!vm) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         "%s", _("no domain with matching uuid"));
        return -1;
    }

    for (i = 0 ; i < vm->def->ndisks ; i++) {
        if (STREQ(vm->def->disks[i]->dst, dev->data.disk->dst)) {
            detach = vm->def->disks[i];
            break;
        }
    }

    if (!detach) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                         _("disk %s not found"), dev->data.disk->dst);
        return -1;
    }

    if (detach->slotnum < 1) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                         _("disk %s cannot be detached - invalid slot number %d"),
                           detach->dst, detach->slotnum);
        return -1;
    }

    ret = asprintf(&cmd, "pci_del 0 %d", detach->slotnum);
    if (ret == -1) {
        qemudReportError(dom->conn, NULL, NULL, VIR_ERR_NO_MEMORY, NULL);
        return ret;
    }

    if (qemudMonitorCommand(driver, vm, cmd, &reply) < 0) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                          _("failed to execute detach disk %s command"), detach->dst);
        VIR_FREE(cmd);
        return -1;
    }

    DEBUG ("pci_del reply: %s", reply);
    /* If the command fails due to a wrong slot qemu prints: invalid slot,
     * nothing is printed on success */
    if (strstr(reply, "invalid slot")) {
        qemudReportError (dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                          _("failed to detach disk %s: invalid slot %d"),
                            detach->dst, detach->slotnum);
        ret = -1;
        goto out;
    }

    if (vm->def->ndisks > 1) {
        vm->def->disks[i] = vm->def->disks[--vm->def->ndisks];
        if (VIR_REALLOC_N(vm->def->disks, vm->def->ndisks) < 0) {
            qemudReportError(dom->conn, NULL, NULL, VIR_ERR_NO_MEMORY, NULL);
            ret = -1;
            goto out;
        }
        qsort(vm->def->disks, vm->def->ndisks, sizeof(*vm->def->disks),
              virDomainDiskQSort);
    } else {
        VIR_FREE(vm->def->disks[0]);
        vm->def->ndisks = 0;
    }
    ret = 0;
out:
    VIR_FREE(reply);
    VIR_FREE(cmd);
    return ret;
}

static int qemudDomainDetachDevice(virDomainPtr dom,
                                   const char *xml) {
    struct qemud_driver *driver = (struct qemud_driver *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByUUID(&driver->domains, dom->uuid);
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

    dev = virDomainDeviceDefParse(dom->conn, driver->caps, vm->def, xml);
    if (dev == NULL) {
        return -1;
    }

    if (dev->type == VIR_DOMAIN_DEVICE_DISK &&
        dev->data.disk->device == VIR_DOMAIN_DISK_DEVICE_DISK &&
        (dev->data.disk->bus == VIR_DOMAIN_DISK_BUS_SCSI ||
         dev->data.disk->bus == VIR_DOMAIN_DISK_BUS_VIRTIO))
                    ret = qemudDomainDetachPciDiskDevice(dom, dev);
    else {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_NO_SUPPORT,
                         "%s", _("only SCSI or virtio disk device can be detached dynamically"));
        ret = -1;
    }

    VIR_FREE(dev);
    return ret;
}

static int qemudDomainGetAutostart(virDomainPtr dom,
                            int *autostart) {
    struct qemud_driver *driver = (struct qemud_driver *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByUUID(&driver->domains, dom->uuid);

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
    virDomainObjPtr vm = virDomainFindByUUID(&driver->domains, dom->uuid);
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
    struct qemud_driver *driver =
        (struct qemud_driver *)dom->conn->privateData;
    char *dummy, *info = NULL;
    const char *p, *eol;
    const char *qemu_dev_name = NULL;
    size_t len;
    int i, ret = -1;
    const virDomainObjPtr vm = virDomainFindByID(&driver->domains, dom->id);
    virDomainDiskDefPtr disk = NULL;

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

    for (i = 0 ; i < vm->def->ndisks ; i++) {
        if (STREQ(path, vm->def->disks[i]->dst)) {
            disk = vm->def->disks[i];
            break;
        }
    }

    if (!disk) {
        qemudReportError (dom->conn, dom, NULL, VIR_ERR_INVALID_ARG,
                          _("invalid path: %s"), path);
        return -1;
    }

    qemu_dev_name = qemudDiskDeviceName(dom, disk);
    if (!qemu_dev_name)
        return -1;
    len = strlen (qemu_dev_name);

    if (qemudMonitorCommand (driver, vm, "info blockstats", &info) < 0) {
        qemudReportError (dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                          "%s", _("'info blockstats' command failed"));
        goto out;
    }
    DEBUG ("info blockstats reply: %s", info);

    /* If the command isn't supported then qemu prints the supported
     * info commands, so the output starts "info ".  Since this is
     * unlikely to be the name of a block device, we can use this
     * to detect if qemu supports the command.
     */
    if (STRPREFIX (info, "info ")) {
        qemudReportError (dom->conn, dom, NULL, VIR_ERR_NO_SUPPORT,
                          "%s",
                          _("'info blockstats' not supported by this qemu"));
        goto out;
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
            ret = 0;
            goto out;
        }

        /* Skip to next line. */
        p = strchr (p, '\n');
        if (!p) break;
        p++;
    }

    /* If we reach here then the device was not found. */
    qemudReportError (dom->conn, dom, NULL, VIR_ERR_INVALID_ARG,
                      _("device not found: %s (%s)"), path, qemu_dev_name);
 out:
    VIR_FREE(qemu_dev_name);
    VIR_FREE(info);
    return ret;
}

static int
qemudDomainInterfaceStats (virDomainPtr dom,
                           const char *path,
                           struct _virDomainInterfaceStats *stats)
{
#ifdef __linux__
    struct qemud_driver *driver = (struct qemud_driver *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByID(&driver->domains, dom->id);
    int i;

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
    for (i = 0 ; i < vm->def->nnets ; i++) {
        if (vm->def->nets[i]->ifname &&
            STREQ (vm->def->nets[i]->ifname, path))
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
    virDomainObjPtr vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    int fd, ret = -1, i;

    if (!vm) {
        qemudReportError (dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                          "%s", _("no domain with matching uuid"));
        return -1;
    }

    if (!path || path[0] == '\0') {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_ARG,
                         "%s", _("NULL or empty path"));
        return -1;
    }

    /* Check the path belongs to this domain. */
    for (i = 0 ; i < vm->def->ndisks ; i++) {
        if (vm->def->disks[i]->src != NULL &&
            STREQ (vm->def->disks[i]->src, path))
            goto found;
    }
    qemudReportError (dom->conn, dom, NULL, VIR_ERR_INVALID_ARG,
                      "%s", _("invalid path"));
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
    virDomainObjPtr vm = virDomainFindByID(&driver->domains, dom->id);
    char cmd[256], *info;
    char tmp[] = TEMPDIR "/qemu.mem.XXXXXX";
    int fd = -1, ret = -1;

    if (flags != VIR_MEMORY_VIRTUAL) {
        qemudReportError (dom->conn, dom, NULL, VIR_ERR_INVALID_ARG,
                          "%s", _("QEMU driver only supports virtual memory addrs"));
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


static int
qemudDomainEventRegister (virConnectPtr conn,
                          void *callback,
                          void *opaque,
                          virFreeCallback freecb)
{
    struct qemud_driver *driver = (struct qemud_driver *)conn->privateData;

    return virDomainEventCallbackListAdd(conn, driver->domainEventCallbacks,
                                         callback, opaque, freecb);
}

static int
qemudDomainEventDeregister (virConnectPtr conn,
                            void *callback)
{
    struct qemud_driver *driver = (struct qemud_driver *)conn->privateData;

    return virDomainEventCallbackListRemove(conn, driver->domainEventCallbacks,
                                            callback);
}

static void qemudDomainEventDispatch (struct qemud_driver *driver,
                                      virDomainObjPtr vm,
                                      int event,
                                      int detail)
{
    int i;
    virDomainEventCallbackListPtr cbList;

    cbList = driver->domainEventCallbacks;

    for(i=0 ; i < cbList->count ; i++) {
        if(cbList->callbacks[i] && cbList->callbacks[i]->cb) {
            virConnectPtr conn = cbList->callbacks[i]->conn;
            virDomainPtr dom = virGetDomain(conn, vm->def->name,
                                            vm->def->uuid);
            if (dom) {
                dom->id = virDomainIsActive(vm) ? vm->def->id : -1;
                DEBUG("Dispatching callback %p %p event %d detail %d",
                      cbList->callbacks[i],
                      cbList->callbacks[i]->cb, event, detail);
                cbList->callbacks[i]->cb(cbList->callbacks[i]->conn,
                                         dom, event, detail,
                                         cbList->callbacks[i]->opaque);
                virDomainFree(dom);
            }
        }
    }

}

/* Migration support. */

/* Prepare is the first step, and it runs on the destination host.
 *
 * This starts an empty VM listening on a TCP port.
 */
static int
qemudDomainMigratePrepare2 (virConnectPtr dconn,
                            char **cookie ATTRIBUTE_UNUSED,
                            int *cookielen ATTRIBUTE_UNUSED,
                            const char *uri_in,
                            char **uri_out,
                            unsigned long flags ATTRIBUTE_UNUSED,
                            const char *dname,
                            unsigned long resource ATTRIBUTE_UNUSED,
                            const char *dom_xml)
{
    static int port = 0;
    struct qemud_driver *driver = (struct qemud_driver *)dconn->privateData;
    virDomainDefPtr def;
    virDomainObjPtr vm = NULL;
    int this_port;
    char hostname [HOST_NAME_MAX+1];
    char migrateFrom [64];
    const char *p;

    if (!dom_xml) {
        qemudReportError (dconn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                          "%s", _("no domain XML passed"));
        return -1;
    }

    /* The URI passed in may be NULL or a string "tcp://somehostname:port".
     *
     * If the URI passed in is NULL then we allocate a port number
     * from our pool of port numbers and return a URI of
     * "tcp://ourhostname:port".
     *
     * If the URI passed in is not NULL then we try to parse out the
     * port number and use that (note that the hostname is assumed
     * to be a correct hostname which refers to the target machine).
     */
    if (uri_in == NULL) {
        this_port = QEMUD_MIGRATION_FIRST_PORT + port++;
        if (port == QEMUD_MIGRATION_NUM_PORTS) port = 0;

        /* Get hostname */
        if (gethostname (hostname, HOST_NAME_MAX+1) == -1) {
            qemudReportError (dconn, NULL, NULL, VIR_ERR_SYSTEM_ERROR,
                              "%s", strerror (errno));
            return -1;
        }

        /* Caller frees */
        if (asprintf(uri_out, "tcp:%s:%d", hostname, this_port) < 0) {
            qemudReportError (dconn, NULL, NULL, VIR_ERR_NO_MEMORY,
                              "%s", strerror (errno));
            return -1;
        }
    } else {
        /* Check the URI starts with "tcp:".  We will escape the
         * URI when passing it to the qemu monitor, so bad
         * characters in hostname part don't matter.
         */
        if (!STREQLEN (uri_in, "tcp:", 6)) {
            qemudReportError (dconn, NULL, NULL, VIR_ERR_INVALID_ARG,
                  "%s", _("only tcp URIs are supported for KVM migrations"));
            return -1;
        }

        /* Get the port number. */
        p = strrchr (uri_in, ':');
        p++; /* definitely has a ':' in it, see above */
        this_port = virParseNumber (&p);
        if (this_port == -1 || p-uri_in != strlen (uri_in)) {
            qemudReportError (dconn, NULL, NULL, VIR_ERR_INVALID_ARG,
                              "%s", _("URI did not have ':port' at the end"));
            return -1;
        }
    }

    /* Parse the domain XML. */
    if (!(def = virDomainDefParseString(dconn, driver->caps, dom_xml))) {
        qemudReportError (dconn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                          "%s", _("failed to parse XML"));
        return -1;
    }

    /* Target domain name, maybe renamed. */
    dname = dname ? dname : def->name;

#if 1
    /* Ensure the name and UUID don't already exist in an active VM */
    vm = virDomainFindByUUID(&driver->domains, def->uuid);
#else
    /* For TESTING ONLY you can change #if 1 -> #if 0 above and use
     * this code which lets you do localhost migrations.  You must still
     * supply a fresh 'dname' but this code assigns a random UUID.
     */
    if (virUUIDGenerate (def->uuid) == -1) {
        qemudReportError (dconn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
            _("could not generate random UUID"));
    }
#endif

    if (!vm) vm = virDomainFindByName(&driver->domains, dname);
    if (vm) {
        if (virDomainIsActive(vm)) {
            qemudReportError (dconn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                              _("domain with the same name or UUID already exists as '%s'"),
                              vm->def->name);
            virDomainDefFree(def);
            return -1;
        }
    }

    if (!(vm = virDomainAssignDef(dconn,
                                  &driver->domains,
                                  def))) {
        qemudReportError (dconn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                          "%s", _("failed to assign new VM"));
        virDomainDefFree(def);
        return -1;
    }

    /* Domain starts inactive, even if the domain XML had an id field. */
    vm->def->id = -1;

    /* Start the QEMU daemon, with the same command-line arguments plus
     * -incoming tcp:0.0.0.0:port
     */
    snprintf (migrateFrom, sizeof (migrateFrom), "tcp:0.0.0.0:%d", this_port);
    if (qemudStartVMDaemon (dconn, driver, vm, migrateFrom) < 0) {
        qemudReportError (dconn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                          "%s", _("failed to start listening VM"));
        if (!vm->persistent)
            virDomainRemoveInactive(&driver->domains, vm);

        return -1;
    }
    qemudDomainEventDispatch(driver, vm,
                             VIR_DOMAIN_EVENT_STARTED,
                             VIR_DOMAIN_EVENT_STARTED_MIGRATED);

    return 0;
}

/* Perform is the second step, and it runs on the source host. */
static int
qemudDomainMigratePerform (virDomainPtr dom,
                           const char *cookie ATTRIBUTE_UNUSED,
                           int cookielen ATTRIBUTE_UNUSED,
                           const char *uri,
                           unsigned long flags ATTRIBUTE_UNUSED,
                           const char *dname ATTRIBUTE_UNUSED,
                           unsigned long resource)
{
    struct qemud_driver *driver = (struct qemud_driver *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByID(&driver->domains, dom->id);
    char *safe_uri;
    char cmd[HOST_NAME_MAX+50];
    char *info;

    if (!vm) {
        qemudReportError (dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                          _("no domain with matching id %d"), dom->id);
        return -1;
    }

    if (!virDomainIsActive(vm)) {
        qemudReportError (dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                          "%s", _("domain is not running"));
        return -1;
    }

    if (!(flags & VIR_MIGRATE_LIVE)) {
        /* Pause domain for non-live migration */
        snprintf(cmd, sizeof cmd, "%s", "stop");
        qemudMonitorCommand (driver, vm, cmd, &info);
        DEBUG ("stop reply: %s", info);
        VIR_FREE(info);

        qemudDomainEventDispatch(driver, vm,
                                 VIR_DOMAIN_EVENT_SUSPENDED,
                                 VIR_DOMAIN_EVENT_SUSPENDED_MIGRATED);
    }

    if (resource > 0) {
        /* Issue migrate_set_speed command.  Don't worry if it fails. */
        snprintf (cmd, sizeof cmd, "migrate_set_speed %lum", resource);
        qemudMonitorCommand (driver, vm, cmd, &info);

        DEBUG ("migrate_set_speed reply: %s", info);
        VIR_FREE (info);
    }

    /* Issue the migrate command. */
    safe_uri = qemudEscapeMonitorArg (uri);
    if (!safe_uri) {
        qemudReportError (dom->conn, dom, NULL, VIR_ERR_SYSTEM_ERROR,
                          "%s", strerror (errno));
        return -1;
    }
    snprintf (cmd, sizeof cmd, "migrate \"%s\"", safe_uri);
    VIR_FREE (safe_uri);

    if (qemudMonitorCommand (driver, vm, cmd, &info) < 0) {
        qemudReportError (dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                          "%s", _("migrate operation failed"));
        return -1;
    }

    DEBUG ("migrate reply: %s", info);

    /* Now check for "fail" in the output string */
    if (strstr(info, "fail") != NULL) {
        qemudReportError (dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                          _("migrate failed: %s"), info);
        VIR_FREE(info);
        return -1;
    }

    VIR_FREE (info);

    /* Clean up the source domain. */
    qemudShutdownVMDaemon (dom->conn, driver, vm);
    qemudDomainEventDispatch(driver, vm,
                             VIR_DOMAIN_EVENT_STOPPED,
                             VIR_DOMAIN_EVENT_STOPPED_MIGRATED);
    if (!vm->persistent)
        virDomainRemoveInactive(&driver->domains, vm);

    return 0;
}

/* Finish is the third and final step, and it runs on the destination host. */
static virDomainPtr
qemudDomainMigrateFinish2 (virConnectPtr dconn,
                           const char *dname,
                           const char *cookie ATTRIBUTE_UNUSED,
                           int cookielen ATTRIBUTE_UNUSED,
                           const char *uri ATTRIBUTE_UNUSED,
                           unsigned long flags ATTRIBUTE_UNUSED,
                           int retcode)
{
    struct qemud_driver *driver = (struct qemud_driver *)dconn->privateData;
    virDomainObjPtr vm = virDomainFindByName(&driver->domains, dname);
    virDomainPtr dom;
    char *info = NULL;

    if (!vm) {
        qemudReportError (dconn, NULL, NULL, VIR_ERR_INVALID_DOMAIN,
                          _("no domain with matching name %s"), dname);
        return NULL;
    }

    /* Did the migration go as planned?  If yes, return the domain
     * object, but if no, clean up the empty qemu process.
     */
    if (retcode == 0) {
        dom = virGetDomain (dconn, vm->def->name, vm->def->uuid);
        VIR_FREE(info);
        vm->state = VIR_DOMAIN_RUNNING;
        qemudDomainEventDispatch(driver, vm,
                                 VIR_DOMAIN_EVENT_RESUMED,
                                 VIR_DOMAIN_EVENT_RESUMED_MIGRATED);
        return dom;
    } else {
        qemudShutdownVMDaemon (dconn, driver, vm);
        qemudDomainEventDispatch(driver, vm,
                                 VIR_DOMAIN_EVENT_STOPPED,
                                 VIR_DOMAIN_EVENT_STOPPED_FAILED);
        if (!vm->persistent)
            virDomainRemoveInactive(&driver->domains, vm);
        return NULL;
    }
}

static virDriver qemuDriver = {
    VIR_DRV_QEMU,
    "QEMU",
    qemudOpen, /* open */
    qemudClose, /* close */
    qemudSupportsFeature, /* supports_feature */
    qemudGetType, /* type */
    qemudGetVersion, /* version */
    qemudGetHostname, /* hostname */
    NULL, /* URI  */
    qemudGetMaxVCPUs, /* getMaxVcpus */
    qemudGetNodeInfo, /* nodeGetInfo */
    qemudGetCapabilities, /* getCapabilities */
    qemudListDomains, /* listDomains */
    qemudNumDomains, /* numOfDomains */
    qemudDomainCreate, /* domainCreateXML */
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
    qemudDomainDetachDevice, /* domainDetachDevice */
    qemudDomainGetAutostart, /* domainGetAutostart */
    qemudDomainSetAutostart, /* domainSetAutostart */
    NULL, /* domainGetSchedulerType */
    NULL, /* domainGetSchedulerParameters */
    NULL, /* domainSetSchedulerParameters */
    NULL, /* domainMigratePrepare (v1) */
    qemudDomainMigratePerform, /* domainMigratePerform */
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
    qemudDomainEventRegister, /* domainEventRegister */
    qemudDomainEventDeregister, /* domainEventDeregister */
    qemudDomainMigratePrepare2, /* domainMigratePrepare2 */
    qemudDomainMigrateFinish2, /* domainMigrateFinish2 */
};


static virStateDriver qemuStateDriver = {
    .initialize = qemudStartup,
    .cleanup = qemudShutdown,
    .reload = qemudReload,
    .active = qemudActive,
};

int qemuRegister(void) {
    virRegisterDriver(&qemuDriver);
    virRegisterStateDriver(&qemuStateDriver);
    return 0;
}

