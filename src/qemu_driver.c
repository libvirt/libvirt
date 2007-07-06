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

#define _GNU_SOURCE /* for asprintf */

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
#include <ctype.h>
#include <pwd.h>
#include <stdio.h>
#include <sys/wait.h>

#include <libvirt/virterror.h>

#include "event.h"
#include "buf.h"
#include "qemu_driver.h"
#include "qemu_conf.h"

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
    qemudLog(QEMUD_ERR, "Failed to set close-on-exec file descriptor flag");
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
    qemudLog(QEMUD_ERR, "Failed to set non-blocking file descriptor flag");
    return -1;
}


static void qemudDispatchVMEvent(int fd, int events, void *opaque);
static int qemudStartVMDaemon(struct qemud_driver *driver,
                       struct qemud_vm *vm);

static int qemudShutdownVMDaemon(struct qemud_driver *driver,
                          struct qemud_vm *vm);

static int qemudStartNetworkDaemon(struct qemud_driver *driver,
                            struct qemud_network *network);

static int qemudShutdownNetworkDaemon(struct qemud_driver *driver,
                               struct qemud_network *network);

struct qemud_driver *qemu_driver = NULL;


static
void qemudAutostartConfigs(struct qemud_driver *driver) {
    struct qemud_network *network;
    struct qemud_vm *vm;

    network = driver->networks;
    while (network != NULL) {
        struct qemud_network *next = network->next;

        if (network->autostart &&
            !qemudIsActiveNetwork(network) &&
            qemudStartNetworkDaemon(driver, network) < 0) {
            virErrorPtr err = virGetLastError();
            qemudLog(QEMUD_ERR, "Failed to autostart network '%s': %s",
                     network->def->name, err->message);
        }

        network = next;
    }

    vm = driver->vms;
    while (vm != NULL) {
        struct qemud_vm *next = vm->next;

        if (vm->autostart &&
            !qemudIsActiveVM(vm) &&
            qemudStartVMDaemon(driver, vm) < 0) {
            virErrorPtr err = virGetLastError();
            qemudLog(QEMUD_ERR, "Failed to autostart VM '%s': %s",
                     vm->def->name, err->message);
        }

        vm = next;
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

    if (!(qemu_driver = calloc(1, sizeof(struct qemud_driver)))) {
        return -1;
    }

    /* Don't have a dom0 so start from 1 */
    qemu_driver->nextvmid = 1;

    if (!uid) {
        if (snprintf(qemu_driver->logDir, PATH_MAX, "%s/log/libvirt/qemu", LOCAL_STATE_DIR) >= PATH_MAX)
            goto snprintf_error;

        if ((base = strdup (SYSCONF_DIR "/libvirt/qemu")) == NULL)
            goto out_of_memory;
    } else {
        if (!(pw = getpwuid(uid))) {
            qemudLog(QEMUD_ERR, "Failed to find user record for uid '%d': %s",
                     uid, strerror(errno));
            goto out_of_memory;
        }

        if (snprintf(qemu_driver->logDir, PATH_MAX, "%s/.libvirt/qemu/log", pw->pw_dir) >= PATH_MAX)
            goto snprintf_error;

        if (asprintf (&base, "%s/.libvirt/qemu", pw->pw_dir) == -1) {
            qemudLog (QEMUD_ERR, "out of memory in asprintf");
            goto out_of_memory;
        }
    }

    /* Configuration paths are either ~/.libvirt/qemu/... (session) or
     * /etc/libvirt/qemu/... (system).
     */
    if (asprintf (&qemu_driver->configDir, "%s", base) == -1)
        goto out_of_memory;

    if (asprintf (&qemu_driver->autostartDir, "%s/autostart", base) == -1)
        goto out_of_memory;

    if (asprintf (&qemu_driver->networkConfigDir, "%s/networks", base) == -1)
        goto out_of_memory;

    if (asprintf (&qemu_driver->networkAutostartDir, "%s/networks/autostart",
                  base) == -1)
        goto out_of_memory;

    if (qemudScanConfigs(qemu_driver) < 0)
        qemudShutdown();
    qemudAutostartConfigs(qemu_driver);

    return 0;

 snprintf_error:
    qemudLog(QEMUD_ERR, "Resulting path to long for buffer in qemudInitPaths()");
    return -1;

 out_of_memory:
    qemudLog (QEMUD_ERR, "qemudStartup: out of memory");
    if (base) free (base);
    free(qemu_driver);
    qemu_driver = NULL;
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
    qemudScanConfigs(qemu_driver);

     if (qemu_driver->iptables) {
        qemudLog(QEMUD_INFO, "Reloading iptables rules");
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
    /* If we've any active networks or guests, then we
     * mark this driver as active
     */
    if (qemu_driver->nactivenetworks &&
        qemu_driver->nactivevms)
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
    struct qemud_vm *vm;
    struct qemud_network *network;

    if (!qemu_driver)
        return -1;

    /* shutdown active VMs */
    vm = qemu_driver->vms;
    while (vm) {
        struct qemud_vm *next = vm->next;
        if (qemudIsActiveVM(vm))
            qemudShutdownVMDaemon(qemu_driver, vm);
        vm = next;
    }
    
    /* free inactive VMs */
    vm = qemu_driver->vms;
    while (vm) {
        struct qemud_vm *next = vm->next;
        qemudFreeVM(vm);
        vm = next;
    }
    qemu_driver->vms = NULL;
    qemu_driver->nactivevms = 0;
    qemu_driver->ninactivevms = 0;

    /* shutdown active networks */
    network = qemu_driver->networks;
    while (network) {
        struct qemud_network *next = network->next;
        if (qemudIsActiveNetwork(network))
            qemudShutdownNetworkDaemon(qemu_driver, network);
        network = next;
    }
    
    /* free inactive networks */
    network = qemu_driver->networks;
    while (network) {
        struct qemud_network *next = network->next;
        qemudFreeNetwork(network);
        network = next;
    }
    qemu_driver->networks = NULL;
    qemu_driver->nactivenetworks = 0;
    qemu_driver->ninactivenetworks = 0;

    if (qemu_driver->configDir)
        free(qemu_driver->configDir);
    if (qemu_driver->autostartDir)
        free(qemu_driver->autostartDir);
    if (qemu_driver->networkConfigDir)
        free(qemu_driver->networkConfigDir);
    if (qemu_driver->networkAutostartDir)
        free(qemu_driver->networkAutostartDir);

    if (qemu_driver->brctl)
        brShutdown(qemu_driver->brctl);
    if (qemu_driver->iptables)
        iptablesContextFree(qemu_driver->iptables);

    free(qemu_driver);
    qemu_driver = NULL;

    return 0;
}

static int
qemudExec(char **argv,
          int *retpid, int *outfd, int *errfd) {
    int pid, null;
    int pipeout[2] = {-1,-1};
    int pipeerr[2] = {-1,-1};

    if ((null = open(_PATH_DEVNULL, O_RDONLY)) < 0) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR, "cannot open %s : %s",
                         _PATH_DEVNULL, strerror(errno));
        goto cleanup;
    }

    if ((outfd != NULL && pipe(pipeout) < 0) ||
        (errfd != NULL && pipe(pipeerr) < 0)) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR, "cannot create pipe : %s",
                         strerror(errno));
        goto cleanup;
    }

    if ((pid = fork()) < 0) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR, "cannot fork child process : %s",
                         strerror(errno));
        goto cleanup;
    }

    if (pid) { /* parent */
        close(null);
        if (outfd) {
            close(pipeout[1]);
            qemudSetNonBlock(pipeout[0]);
            qemudSetCloseExec(pipeout[0]);
            *outfd = pipeout[0];
        }
        if (errfd) {
            close(pipeerr[1]);
            qemudSetNonBlock(pipeerr[0]);
            qemudSetCloseExec(pipeerr[0]);
            *errfd = pipeerr[0];
        }
        *retpid = pid;
        return 0;
    }

    /* child */

    if (pipeout[0] > 0 && close(pipeout[0]) < 0)
        _exit(1);
    if (pipeerr[0] > 0 && close(pipeerr[0]) < 0)
        _exit(1);

    if (dup2(null, STDIN_FILENO) < 0)
        _exit(1);
    if (dup2(pipeout[1] > 0 ? pipeout[1] : null, STDOUT_FILENO) < 0)
        _exit(1);
    if (dup2(pipeerr[1] > 0 ? pipeerr[1] : null, STDERR_FILENO) < 0)
        _exit(1);

    close(null);
    if (pipeout[1] > 0)
        close(pipeout[1]);
    if (pipeerr[1] > 0)
        close(pipeerr[1]);

    execvp(argv[0], argv);

    _exit(1);

    return 0;

 cleanup:
    if (pipeerr[0] > 0)
        close(pipeerr[0]);
    if (pipeerr[1] > 0)
        close(pipeerr[1]);
    if (pipeout[0] > 0)
        close(pipeout[0]);
    if (pipeout[1] > 0)
        close(pipeout[1]);
    if (null > 0)
        close(null);
    return -1;
}

/* Return -1 for error, 1 to continue reading and 0 for success */
typedef int qemudHandlerMonitorOutput(struct qemud_driver *driver,
                                      struct qemud_vm *vm,
                                      const char *output,
                                      int fd);

static int
qemudReadMonitorOutput(struct qemud_driver *driver,
                       struct qemud_vm *vm,
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
            qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             "QEMU quit during %s startup\n%s", what, buf);
            return -1;
        }
        if (ret < 0) {
            struct pollfd pfd = { .fd = fd, .events = POLLIN };
            if (errno == EINTR)
                continue;

            if (errno != EAGAIN) {
                qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                                 "Failure while reading %s startup output: %s",
                                 what, strerror(errno));
                return -1;
            }

            ret = poll(&pfd, 1, MONITOR_TIMEOUT);
            if (ret == 0) {
                qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                                 "Timed out while reading %s startup output", what);
                return -1;
            } else if (ret == -1) {
                if (errno != EINTR) {
                    qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                                     "Failure while reading %s startup output: %s",
                                     what, strerror(errno));
                    return -1;
                }
            } else {
                /* Make sure we continue loop & read any further data
                   available before dealing with EOF */
                if (pfd.revents & (POLLIN | POLLHUP))
                    continue;

                qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                                 "Failure while reading %s startup output", what);
                return -1;
            }
        } else {
            got += ret;
            buf[got] = '\0';
            if ((ret = func(driver, vm, buf, fd)) != 1)
                return ret;
        }
    }

    qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                     "Out of space while reading %s startup output", what);
    return -1;

#undef MONITOR_TIMEOUT
}

static int
qemudCheckMonitorPrompt(struct qemud_driver *driver ATTRIBUTE_UNUSED,
                        struct qemud_vm *vm,
                        const char *output,
                        int fd)
{
    if (strstr(output, "(qemu) ") == NULL)
        return 1; /* keep reading */

    vm->monitor = fd;

    return 0;
}

static int qemudOpenMonitor(struct qemud_driver *driver, struct qemud_vm *vm, const char *monitor) {
    int monfd;
    char buf[1024];
    int ret = -1;

    if (!(monfd = open(monitor, O_RDWR))) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "Unable to open monitor path %s", monitor);
        return -1;
    }
    if (qemudSetCloseExec(monfd) < 0) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "Unable to set monitor close-on-exec flag");
        goto error;
    }
    if (qemudSetNonBlock(monfd) < 0) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "Unable to put monitor into non-blocking mode");
        goto error;
    }

    ret = qemudReadMonitorOutput(driver, vm, monfd,
                                 buf, sizeof(buf),
                                 qemudCheckMonitorPrompt,
                                 "monitor");
 error:
    close(monfd);
    return ret;
}

static int qemudExtractMonitorPath(const char *haystack, char *path, int pathmax) {
    static const char needle[] = "char device redirected to";
    char *tmp;

    if (!(tmp = strstr(haystack, needle)))
        return -1;

    strncpy(path, tmp+sizeof(needle), pathmax-1);
    path[pathmax-1] = '\0';

    while (*path) {
        /*
         * The monitor path ends at first whitespace char
         * so lets search for it & NULL terminate it there
         */
        if (isspace(*path)) {
            *path = '\0';
            return 0;
        }
        path++;
    }

    /*
     * We found a path, but didn't find any whitespace,
     * so it must be still incomplete - we should at
     * least see a \n
     */
    return -1;
}

static int
qemudOpenMonitorPath(struct qemud_driver *driver,
                     struct qemud_vm *vm,
                     const char *output,
                     int fd ATTRIBUTE_UNUSED)
{
    char monitor[PATH_MAX];

    if (qemudExtractMonitorPath(output, monitor, sizeof(monitor)) < 0)
        return 1; /* keep reading */

    return qemudOpenMonitor(driver, vm, monitor);
}

static int qemudWaitForMonitor(struct qemud_driver *driver, struct qemud_vm *vm) {
    char buf[1024]; /* Plenty of space to get startup greeting */
    int ret = qemudReadMonitorOutput(driver, vm, vm->stderr,
                                     buf, sizeof(buf),
                                     qemudOpenMonitorPath,
                                     "console");

    buf[sizeof(buf)-1] = '\0';
 retry:
    if (write(vm->logfile, buf, strlen(buf)) < 0) {
        /* Log, but ignore failures to write logfile for VM */
        if (errno == EINTR)
            goto retry;
        qemudLog(QEMUD_WARN, "Unable to log VM console data: %s",
                 strerror(errno));
    }

    return ret;
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

static int qemudStartVMDaemon(struct qemud_driver *driver,
                       struct qemud_vm *vm) {
    char **argv = NULL, **tmp;
    int i;
    char logfile[PATH_MAX];

    if (qemudIsActiveVM(vm)) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "VM is already active");
        return -1;
    }

    if (vm->def->vncPort < 0) {
        int port = qemudNextFreeVNCPort(driver);
        if (port < 0) {
            qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             "Unable to find an unused VNC port");
            return -1;
        }
        vm->def->vncActivePort = port;
    } else
        vm->def->vncActivePort = vm->def->vncPort;

    if ((strlen(driver->logDir) + /* path */
         1 + /* Separator */
         strlen(vm->def->name) + /* basename */
         4 + /* suffix .log */
         1 /* NULL */) > PATH_MAX) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "config file path too long: %s/%s.log",
                         driver->logDir, vm->def->name);
        return -1;
    }
    strcpy(logfile, driver->logDir);
    strcat(logfile, "/");
    strcat(logfile, vm->def->name);
    strcat(logfile, ".log");

    if (qemudEnsureDir(driver->logDir) < 0) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "cannot create log directory %s: %s",
                         driver->logDir, strerror(errno));
        return -1;
    }

    if ((vm->logfile = open(logfile, O_CREAT | O_TRUNC | O_WRONLY,
                            S_IRUSR | S_IWUSR)) < 0) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "failed to create logfile %s: %s",
                         logfile, strerror(errno));
        return -1;
    }

    if (qemudBuildCommandLine(driver, vm, &argv) < 0) {
        close(vm->logfile);
        vm->logfile = -1;
        return -1;
    }

    tmp = argv;
    while (*tmp) {
        if (write(vm->logfile, *tmp, strlen(*tmp)) < 0)
            qemudLog(QEMUD_WARN, "Unable to write argv to logfile %d: %s",
                     errno, strerror(errno));
        if (write(vm->logfile, " ", 1) < 0)
            qemudLog(QEMUD_WARN, "Unable to write argv to logfile %d: %s",
                     errno, strerror(errno));
        tmp++;
    }
    if (write(vm->logfile, "\n", 1) < 0)
        qemudLog(QEMUD_WARN, "Unable to write argv to logfile %d: %s",
                 errno, strerror(errno));

    if (qemudExec(argv, &vm->pid, &vm->stdout, &vm->stderr) == 0) {
        vm->id = driver->nextvmid++;
        vm->state = VIR_DOMAIN_RUNNING;

        driver->ninactivevms--;
        driver->nactivevms++;
    }

    for (i = 0 ; argv[i] ; i++)
        free(argv[i]);
    free(argv);

    if (vm->tapfds) {
        for (i = 0; vm->tapfds[i] != -1; i++) {
            close(vm->tapfds[i]);
            vm->tapfds[i] = -1;
        }
        free(vm->tapfds);
        vm->tapfds = NULL;
        vm->ntapfds = 0;
    }

    if (virEventAddHandle(vm->stdout,
                          POLLIN | POLLERR | POLLHUP,
                          qemudDispatchVMEvent,
                          driver) < 0) {
        qemudShutdownVMDaemon(driver, vm);
        return -1;
    }

    if (virEventAddHandle(vm->stderr,
                          POLLIN | POLLERR | POLLHUP,
                          qemudDispatchVMEvent,
                          driver) < 0) {
        qemudShutdownVMDaemon(driver, vm);
        return -1;
    }


    if (qemudWaitForMonitor(driver, vm) < 0) {
        qemudShutdownVMDaemon(driver, vm);
        return -1;
    }

    return 0;
}

static int qemudVMData(struct qemud_driver *driver ATTRIBUTE_UNUSED,
                       struct qemud_vm *vm, int fd) {
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

    retry:
        if (write(vm->logfile, buf, ret) < 0) {
            /* Log, but ignore failures to write logfile for VM */
            if (errno == EINTR)
                goto retry;
            qemudLog(QEMUD_WARN, "Unable to log VM console data: %s",
                     strerror(errno));
        }
    }

    qemudAutostartConfigs(qemu_driver);
}


static int qemudShutdownVMDaemon(struct qemud_driver *driver, struct qemud_vm *vm) {
    if (!qemudIsActiveVM(vm))
        return 0;

    qemudLog(QEMUD_INFO, "Shutting down VM '%s'", vm->def->name);

    kill(vm->pid, SIGTERM);

    qemudVMData(driver, vm, vm->stdout);
    qemudVMData(driver, vm, vm->stderr);

    virEventRemoveHandle(vm->stdout);
    virEventRemoveHandle(vm->stderr);

    if (close(vm->logfile) < 0)
        qemudLog(QEMUD_WARN, "Unable to close logfile %d: %s", errno, strerror(errno));
    close(vm->stdout);
    close(vm->stderr);
    if (vm->monitor != -1)
        close(vm->monitor);
    vm->logfile = -1;
    vm->stdout = -1;
    vm->stderr = -1;
    vm->monitor = -1;

    if (waitpid(vm->pid, NULL, WNOHANG) != vm->pid) {
        kill(vm->pid, SIGKILL);
        if (waitpid(vm->pid, NULL, 0) != vm->pid) {
            qemudLog(QEMUD_WARN, "Got unexpected pid, damn");
        }
    }

    vm->pid = -1;
    vm->id = -1;
    vm->state = VIR_DOMAIN_SHUTOFF;

    if (vm->newDef) {
        qemudFreeVMDef(vm->def);
        vm->def = vm->newDef;
        vm->newDef = NULL;
    }

    driver->nactivevms--;
    driver->ninactivevms++;

    if (!vm->configFile[0])
        qemudRemoveInactiveVM(driver, vm);

    return 0;
}

static int qemudDispatchVMLog(struct qemud_driver *driver, struct qemud_vm *vm, int fd) {
    if (qemudVMData(driver, vm, fd) < 0)
        if (qemudShutdownVMDaemon(driver, vm) < 0)
            return -1;
    return 0;
}

static int qemudDispatchVMFailure(struct qemud_driver *driver, struct qemud_vm *vm,
                                  int fd ATTRIBUTE_UNUSED) {
    if (qemudShutdownVMDaemon(driver, vm) < 0)
        return -1;
    return 0;
}

static int
qemudBuildDnsmasqArgv(struct qemud_network *network,
                      char ***argv) {
    int i, len;
    char buf[PATH_MAX];
    struct qemud_dhcp_range_def *range;

    len =
        1 + /* dnsmasq */
        1 + /* --keep-in-foreground */
        1 + /* --strict-order */
        1 + /* --bind-interfaces */
        2 + /* --pid-file "" */
        2 + /* --conf-file "" */
        /*2 + *//* --interface virbr0 */
        2 + /* --except-interface lo */
        2 + /* --listen-address 10.0.0.1 */
        1 + /* --dhcp-leasefile=path */
        (2 * network->def->nranges) + /* --dhcp-range 10.0.0.2,10.0.0.254 */
        1;  /* NULL */

    if (!(*argv = calloc(len, sizeof(char *))))
        goto no_memory;

#define APPEND_ARG(v, n, s) do {     \
        if (!((v)[(n)] = strdup(s))) \
            goto no_memory;          \
    } while (0)

    i = 0;

    APPEND_ARG(*argv, i++, "dnsmasq");

    APPEND_ARG(*argv, i++, "--keep-in-foreground");
    /*
     * Needed to ensure dnsmasq uses same algorithm for processing
     * multiple namedriver entries in /etc/resolv.conf as GLibC.
     */
    APPEND_ARG(*argv, i++, "--strict-order");
    APPEND_ARG(*argv, i++, "--bind-interfaces");

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

    range = network->def->ranges;
    while (range) {
        snprintf(buf, sizeof(buf), "%s,%s",
                 range->start, range->end);

        APPEND_ARG(*argv, i++, "--dhcp-range");
        APPEND_ARG(*argv, i++, buf);

        range = range->next;
    }

#undef APPEND_ARG

    return 0;

 no_memory:
    if (argv) {
        for (i = 0; (*argv)[i]; i++)
            free((*argv)[i]);
        free(*argv);
    }
    qemudReportError(NULL, NULL, NULL, VIR_ERR_NO_MEMORY, "dnsmasq argv");
    return -1;
}


static int
dhcpStartDhcpDaemon(struct qemud_network *network)
{
    char **argv;
    int ret, i;

    if (network->def->ipAddress[0] == '\0') {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "cannot start dhcp daemon without IP address for server");
        return -1;
    }

    argv = NULL;
    if (qemudBuildDnsmasqArgv(network, &argv) < 0)
        return -1;

    ret = qemudExec(argv, &network->dnsmasqPid, NULL, NULL);

    for (i = 0; argv[i]; i++)
        free(argv[i]);
    free(argv);

    return ret;
}

static int
qemudAddIptablesRules(struct qemud_driver *driver,
                      struct qemud_network *network) {
    int err;

    if (!driver->iptables && !(driver->iptables = iptablesContextNew())) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_NO_MEMORY, "iptables support");
        return 1;
    }


    /* allow DHCP requests through to dnsmasq */
    if ((err = iptablesAddTcpInput(driver->iptables, network->bridge, 67))) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "failed to add iptables rule to allow DHCP requests from '%s' : %s\n",
                         network->bridge, strerror(err));
        goto err1;
    }

    if ((err = iptablesAddUdpInput(driver->iptables, network->bridge, 67))) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "failed to add iptables rule to allow DHCP requests from '%s' : %s\n",
                         network->bridge, strerror(err));
        goto err2;
    }

    /* allow DNS requests through to dnsmasq */
    if ((err = iptablesAddTcpInput(driver->iptables, network->bridge, 53))) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "failed to add iptables rule to allow DNS requests from '%s' : %s\n",
                         network->bridge, strerror(err));
        goto err3;
    }

    if ((err = iptablesAddUdpInput(driver->iptables, network->bridge, 53))) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "failed to add iptables rule to allow DNS requests from '%s' : %s\n",
                         network->bridge, strerror(err));
        goto err4;
    }


    /* Catch all rules to block forwarding to/from bridges */

    if ((err = iptablesAddForwardRejectOut(driver->iptables, network->bridge))) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "failed to add iptables rule to block outbound traffic from '%s' : %s\n",
                         network->bridge, strerror(err));
        goto err5;
    }

    if ((err = iptablesAddForwardRejectIn(driver->iptables, network->bridge))) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "failed to add iptables rule to block inbound traffic to '%s' : %s\n",
                         network->bridge, strerror(err));
        goto err6;
    }

    /* Allow traffic between guests on the same bridge */
    if ((err = iptablesAddForwardAllowCross(driver->iptables, network->bridge))) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "failed to add iptables rule to allow cross bridge traffic on '%s' : %s\n",
                         network->bridge, strerror(err));
        goto err7;
    }


    /* The remaining rules are only needed for IP forwarding */
    if (!network->def->forward)
        return 1;

    /* allow forwarding packets from the bridge interface */
    if ((err = iptablesAddForwardAllowOut(driver->iptables,
                                          network->def->network,
                                          network->bridge,
                                          network->def->forwardDev))) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "failed to add iptables rule to allow forwarding from '%s' : %s\n",
                         network->bridge, strerror(err));
        goto err8;
    }

    /* allow forwarding packets to the bridge interface if they are part of an existing connection */
    if ((err = iptablesAddForwardAllowIn(driver->iptables,
                                         network->def->network,
                                         network->bridge,
                                         network->def->forwardDev))) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "failed to add iptables rule to allow forwarding to '%s' : %s\n",
                         network->bridge, strerror(err));
        goto err9;
    }

    /* enable masquerading */
    if ((err = iptablesAddForwardMasquerade(driver->iptables,
                                            network->def->network,
                                            network->def->forwardDev))) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "failed to add iptables rule to enable masquerading : %s\n",
                         strerror(err));
        goto err10;
    }

    return 1;

 err10:
    iptablesRemoveForwardAllowIn(driver->iptables,
                                 network->def->network,
                                 network->bridge,
                                 network->def->forwardDev);
 err9:
    iptablesRemoveForwardAllowOut(driver->iptables,
                                  network->def->network,
                                  network->bridge,
                                  network->def->forwardDev);
 err8:
    iptablesRemoveForwardAllowCross(driver->iptables,
                                    network->bridge);
 err7:
    iptablesRemoveForwardRejectIn(driver->iptables,
                                  network->bridge);
 err6:
    iptablesRemoveForwardRejectOut(driver->iptables,
                                   network->bridge);
 err5:
    iptablesRemoveUdpInput(driver->iptables, network->bridge, 53);
 err4:
    iptablesRemoveTcpInput(driver->iptables, network->bridge, 53);
 err3:
    iptablesRemoveUdpInput(driver->iptables, network->bridge, 67);
 err2:
    iptablesRemoveTcpInput(driver->iptables, network->bridge, 67);
 err1:
    return 0;
}

static void
qemudRemoveIptablesRules(struct qemud_driver *driver,
                         struct qemud_network *network) {
    if (network->def->forward) {
        iptablesRemoveForwardMasquerade(driver->iptables,
                                     network->def->network,
                                     network->def->forwardDev);
        iptablesRemoveForwardAllowIn(driver->iptables,
                                   network->def->network,
                                   network->bridge,
                                   network->def->forwardDev);
        iptablesRemoveForwardAllowOut(driver->iptables,
                                      network->def->network,
                                      network->bridge,
                                      network->def->forwardDev);
    }
    iptablesRemoveForwardAllowCross(driver->iptables, network->bridge);
    iptablesRemoveForwardRejectIn(driver->iptables, network->bridge);
    iptablesRemoveForwardRejectOut(driver->iptables, network->bridge);
    iptablesRemoveUdpInput(driver->iptables, network->bridge, 53);
    iptablesRemoveTcpInput(driver->iptables, network->bridge, 53);
    iptablesRemoveUdpInput(driver->iptables, network->bridge, 67);
    iptablesRemoveTcpInput(driver->iptables, network->bridge, 67);
}

static int
qemudEnableIpForwarding(void)
{
#define PROC_IP_FORWARD "/proc/sys/net/ipv4/ip_forward"

    int fd, ret;

    if ((fd = open(PROC_IP_FORWARD, O_WRONLY|O_TRUNC)) == -1)
        return 0;

    if (write(fd, "1\n", 2) < 0)
        ret = 0;

    close (fd);

    return 1;

#undef PROC_IP_FORWARD
}

static int qemudStartNetworkDaemon(struct qemud_driver *driver,
                            struct qemud_network *network) {
    const char *name;
    int err;

    if (qemudIsActiveNetwork(network)) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "network is already active");
        return -1;
    }

    if (!driver->brctl && (err = brInit(&driver->brctl))) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "cannot initialize bridge support: %s", strerror(err));
        return -1;
    }

    if (network->def->bridge[0] == '\0' ||
        strchr(network->def->bridge, '%')) {
        name = "vnet%d";
    } else {
        name = network->def->bridge;
    }

    if ((err = brAddBridge(driver->brctl, name, network->bridge, sizeof(network->bridge)))) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "cannot create bridge '%s' : %s", name, strerror(err));
        return -1;
    }


    if (network->def->forwardDelay &&
        (err = brSetForwardDelay(driver->brctl, network->bridge, network->def->forwardDelay))) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "failed to set bridge forward delay to %d\n",
                         network->def->forwardDelay);
        goto err_delbr;
    }

    if ((err = brSetForwardDelay(driver->brctl, network->bridge, network->def->disableSTP ? 0 : 1))) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "failed to set bridge STP to %s\n",
                         network->def->disableSTP ? "off" : "on");
        goto err_delbr;
    }

    if (network->def->ipAddress[0] &&
        (err = brSetInetAddress(driver->brctl, network->bridge, network->def->ipAddress))) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "cannot set IP address on bridge '%s' to '%s' : %s\n",
                         network->bridge, network->def->ipAddress, strerror(err));
        goto err_delbr;
    }

    if (network->def->netmask[0] &&
        (err = brSetInetNetmask(driver->brctl, network->bridge, network->def->netmask))) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "cannot set netmask on bridge '%s' to '%s' : %s\n",
                         network->bridge, network->def->netmask, strerror(err));
        goto err_delbr;
    }

    if (network->def->ipAddress[0] &&
        (err = brSetInterfaceUp(driver->brctl, network->bridge, 1))) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "failed to bring the bridge '%s' up : %s\n",
                         network->bridge, strerror(err));
        goto err_delbr;
    }

    if (!qemudAddIptablesRules(driver, network))
        goto err_delbr1;

    if (network->def->forward &&
        !qemudEnableIpForwarding()) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "failed to enable IP forwarding : %s\n", strerror(err));
        goto err_delbr2;
    }

    if (network->def->ranges &&
        dhcpStartDhcpDaemon(network) < 0)
        goto err_delbr2;

    network->active = 1;

    driver->ninactivenetworks--;
    driver->nactivenetworks++;

    return 0;

 err_delbr2:
    qemudRemoveIptablesRules(driver, network);

 err_delbr1:
    if (network->def->ipAddress[0] &&
        (err = brSetInterfaceUp(driver->brctl, network->bridge, 0))) {
        qemudLog(QEMUD_WARN, "Failed to bring down bridge '%s' : %s",
                 network->bridge, strerror(err));
    }

 err_delbr:
    if ((err = brDeleteBridge(driver->brctl, network->bridge))) {
        qemudLog(QEMUD_WARN, "Failed to delete bridge '%s' : %s\n",
                 network->bridge, strerror(err));
    }

    return -1;
}


static int qemudShutdownNetworkDaemon(struct qemud_driver *driver,
                               struct qemud_network *network) {
    int err;

    qemudLog(QEMUD_INFO, "Shutting down network '%s'", network->def->name);

    if (!qemudIsActiveNetwork(network))
        return 0;

    if (network->dnsmasqPid > 0)
        kill(network->dnsmasqPid, SIGTERM);

    qemudRemoveIptablesRules(driver, network);

    if (network->def->ipAddress[0] &&
        (err = brSetInterfaceUp(driver->brctl, network->bridge, 0))) {
        qemudLog(QEMUD_WARN, "Failed to bring down bridge '%s' : %s\n",
                 network->bridge, strerror(err));
    }

    if ((err = brDeleteBridge(driver->brctl, network->bridge))) {
        qemudLog(QEMUD_WARN, "Failed to delete bridge '%s' : %s\n",
                 network->bridge, strerror(err));
    }

    if (network->dnsmasqPid > 0 &&
        waitpid(network->dnsmasqPid, NULL, WNOHANG) != network->dnsmasqPid) {
        kill(network->dnsmasqPid, SIGKILL);
        if (waitpid(network->dnsmasqPid, NULL, 0) != network->dnsmasqPid)
            qemudLog(QEMUD_WARN, "Got unexpected pid for dnsmasq\n");
    }

    network->bridge[0] = '\0';
    network->dnsmasqPid = -1;
    network->active = 0;

    if (network->newDef) {
        qemudFreeNetworkDef(network->def);
        network->def = network->newDef;
        network->newDef = NULL;
    }

    driver->nactivenetworks--;
    driver->ninactivenetworks++;

    if (!network->configFile[0])
        qemudRemoveInactiveNetwork(driver, network);

    return 0;
}


static void qemudDispatchVMEvent(int fd, int events, void *opaque) {
    struct qemud_driver *driver = (struct qemud_driver *)opaque;
    struct qemud_vm *vm = driver->vms;

    while (vm) {
        if (qemudIsActiveVM(vm) &&
            (vm->stdout == fd ||
             vm->stderr == fd))
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

static int qemudMonitorCommand(struct qemud_driver *driver ATTRIBUTE_UNUSED,
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
            char *b;

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
            if (!(b = realloc(buf, size+got+1))) {
                free(buf);
                return -1;
            }
            buf = b;
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


static int qemudGetMemInfo(unsigned long *memory) {
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

static int qemudGetCPUInfo(unsigned int *cpus, unsigned int *mhz,
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
            char *offset = strchr(line, ':');
            if (!offset)
                continue;
            offset++;
            if (!*offset)
                continue;
            *mhz = (unsigned int)strtol(offset, NULL, 10);
        } else if (!strncmp(line, "physical id\t", 12)) { /* aka socket */
            unsigned int id;
            char *offset = strchr(line, ':');
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
            char *offset = strchr(line, ':');
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

static virDrvOpenStatus qemudOpen(virConnectPtr conn,
                           const char *name,
                           int flags ATTRIBUTE_UNUSED) {
    uid_t uid = getuid();

    if (qemu_driver == NULL)
        return VIR_DRV_OPEN_DECLINED;

    if (uid) {
        if (strcmp(name, "qemu:///session"))
            return VIR_DRV_OPEN_DECLINED;
    } else {
        if (strcmp(name, "qemu:///system") &&
            strcmp(name, "qemu:///session"))
            return VIR_DRV_OPEN_DECLINED;
    }

    conn->privateData = qemu_driver;

    return VIR_DRV_OPEN_SUCCESS;
}

static int qemudClose(virConnectPtr conn) {
    /*struct qemud_driver *driver = (struct qemud_driver *)conn->privateData;*/

    conn->privateData = NULL;

    return 0;
}

static const char *qemudGetType(virConnectPtr conn ATTRIBUTE_UNUSED) {
    return "QEMU";
}

static int qemudGetMaxVCPUs(virConnectPtr conn ATTRIBUTE_UNUSED,
                            const char *type) {
    if (!type)
        return 16;

    if (!strcmp(type, "qemu"))
        return 16;

    /* XXX future KVM will support SMP. Need to probe
       kernel to figure out KVM module version i guess */
    if (!strcmp(type, "kvm"))
        return 1;

    if (!strcmp(type, "kqemu"))
        return 1;
    return -1;
}

static int qemudGetNodeInfo(virConnectPtr conn ATTRIBUTE_UNUSED,
                     virNodeInfoPtr node) {
    struct utsname info;

    if (uname(&info) < 0)
        return -1;

    strncpy(node->model, info.machine, sizeof(node->model)-1);
    node->model[sizeof(node->model)-1] = '\0';

    if (qemudGetMemInfo(&(node->memory)) < 0)
        return -1;

    if (qemudGetCPUInfo(&(node->cpus), &(node->mhz), &(node->nodes),
                        &(node->sockets), &(node->cores), &(node->threads)) < 0)
        return -1;
    return 0;
}

static char *qemudGetCapabilities(virConnectPtr conn ATTRIBUTE_UNUSED) {
    struct utsname utsname;
    int i, j, r;
    int have_kqemu = 0;
    int have_kvm = 0;
    virBufferPtr xml;

    /* Really, this never fails - look at the man-page. */
    uname (&utsname);

    have_kqemu = access ("/dev/kqemu", F_OK) == 0;
    have_kvm = access ("/dev/kvm", F_OK) == 0;

    /* Construct the XML. */
    xml = virBufferNew (1024);
    if (!xml) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_NO_MEMORY, NULL);
        return NULL;
    }

    r = virBufferVSprintf (xml,
                        "\
<capabilities>\n\
  <host>\n\
    <cpu>\n\
      <arch>%s</arch>\n\
    </cpu>\n\
  </host>\n",
                        utsname.machine);
    if (r == -1) {
    vir_buffer_failed:
        virBufferFree (xml);
        qemudReportError(conn, NULL, NULL, VIR_ERR_NO_MEMORY, NULL);
        return NULL;
    }

    i = -1;
    if (strcmp (utsname.machine, "i686") == 0) i = 0;
    else if (strcmp (utsname.machine, "x86_64") == 0) i = 1;
    if (i >= 0) {
        /* For the default (PC-like) guest, qemudArchs[0] or [1]. */
        r = virBufferVSprintf (xml,
                            "\
\n\
  <guest>\n\
    <os_type>hvm</os_type>\n\
    <arch name=\"%s\">\n\
      <wordsize>%d</wordsize>\n\
      <emulator>/usr/bin/%s</emulator>\n\
      <domain type=\"qemu\"/>\n",
                            qemudArchs[i].arch,
                            qemudArchs[i].wordsize,
                            qemudArchs[i].binary);
        if (r == -1) goto vir_buffer_failed;

        for (j = 0; qemudArchs[i].machines[j]; ++j) {
            r = virBufferVSprintf (xml,
                                "\
      <machine>%s</machine>\n",
                                qemudArchs[i].machines[j]);
            if (r == -1) goto vir_buffer_failed;
        }

        if (have_kqemu) {
            r = virBufferAdd (xml,
                           "\
      <domain type=\"kqemu\"/>\n", -1);
            if (r == -1) goto vir_buffer_failed;
        }
        if (have_kvm) {
            r = virBufferAdd (xml,
                           "\
      <domain type=\"kvm\">\n\
        <emulator>/usr/bin/qemu-kvm</emulator>\n\
      </domain>\n", -1);
            if (r == -1) goto vir_buffer_failed;
        }
        r = virBufferAdd (xml,
                       "\
    </arch>\n\
  </guest>\n", -1);
        if (r == -1) goto vir_buffer_failed;

        /* The "other" PC architecture needs emulation. */
        i = i ^ 1;
        r = virBufferVSprintf (xml,
                            "\
\n\
  <guest>\n\
    <os_type>hvm</os_type>\n\
    <arch name=\"%s\">\n\
      <wordsize>%d</wordsize>\n\
      <emulator>/usr/bin/%s</emulator>\n\
      <domain type=\"qemu\"/>\n",
                            qemudArchs[i].arch,
                            qemudArchs[i].wordsize,
                            qemudArchs[i].binary);
        if (r == -1) goto vir_buffer_failed;
        for (j = 0; qemudArchs[i].machines[j]; ++j) {
            r = virBufferVSprintf (xml,
                                "\
      <machine>%s</machine>\n",
                                qemudArchs[i].machines[j]);
            if (r == -1) goto vir_buffer_failed;
        }
        r = virBufferAdd (xml,
                       "\
    </arch>\n\
  </guest>\n", -1);
        if (r == -1) goto vir_buffer_failed;
    }

    /* The non-PC architectures, qemudArchs[>=2]. */
    for (i = 2; qemudArchs[i].arch; ++i) {
        r = virBufferVSprintf (xml,
                            "\
\n\
  <guest>\n\
    <os_type>hvm</os_type>\n\
    <arch name=\"%s\">\n\
      <wordsize>%d</wordsize>\n\
      <emulator>/usr/bin/%s</emulator>\n\
      <domain type=\"qemu\"/>\n",
                            qemudArchs[i].arch,
                            qemudArchs[i].wordsize,
                            qemudArchs[i].binary);
        if (r == -1) goto vir_buffer_failed;
        for (j = 0; qemudArchs[i].machines[j]; ++j) {
            r = virBufferVSprintf (xml,
                                "\
      <machine>%s</machine>\n",
                                qemudArchs[i].machines[j]);
            if (r == -1) goto vir_buffer_failed;
        }
        r = virBufferAdd (xml,
                       "\
    </arch>\n\
  </guest>\n", -1);
        if (r == -1) goto vir_buffer_failed;
    }

    /* Finish off. */
    r = virBufferAdd (xml,
                      "\
</capabilities>\n", -1);
    if (r == -1) goto vir_buffer_failed;

    return virBufferContentAndFree(xml);
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


static virDomainPtr qemudDomainLookupByID(virConnectPtr conn,
                                   int id) {
    struct qemud_driver *driver = (struct qemud_driver *)conn->privateData;
    struct qemud_vm *vm = qemudFindVMByID(driver, id);
    virDomainPtr dom;

    if (!vm) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_NO_DOMAIN, NULL);
        return NULL;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom) dom->id = vm->id;
    return dom;
}
static virDomainPtr qemudDomainLookupByUUID(virConnectPtr conn,
                                     const unsigned char *uuid) {
    struct qemud_driver *driver = (struct qemud_driver *)conn->privateData;
    struct qemud_vm *vm = qemudFindVMByUUID(driver, uuid);
    virDomainPtr dom;

    if (!vm) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_NO_DOMAIN, NULL);
        return NULL;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom) dom->id = vm->id;
    return dom;
}
static virDomainPtr qemudDomainLookupByName(virConnectPtr conn,
                                     const char *name) {
    struct qemud_driver *driver = (struct qemud_driver *)conn->privateData;
    struct qemud_vm *vm = qemudFindVMByName(driver, name);
    virDomainPtr dom;

    if (!vm) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_NO_DOMAIN, NULL);
        return NULL;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom) dom->id = vm->id;
    return dom;
}

static int qemudGetVersion(virConnectPtr conn, unsigned long *version) {
    struct qemud_driver *driver = (struct qemud_driver *)conn->privateData;
    if (qemudExtractVersion(driver) < 0)
        return -1;

    *version = qemu_driver->qemuVersion;
    return 0;
}

static int qemudListDomains(virConnectPtr conn, int *ids, int nids) {
    struct qemud_driver *driver = (struct qemud_driver *)conn->privateData;
    struct qemud_vm *vm = driver->vms;
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
static int qemudNumDomains(virConnectPtr conn) {
    struct qemud_driver *driver = (struct qemud_driver *)conn->privateData;
    return driver->nactivevms;
}
static virDomainPtr qemudDomainCreate(virConnectPtr conn, const char *xml,
                               unsigned int flags ATTRIBUTE_UNUSED) {
    struct qemud_vm_def *def;
    struct qemud_vm *vm;
    virDomainPtr dom;
    struct qemud_driver *driver = (struct qemud_driver *)conn->privateData;

    if (!(def = qemudParseVMDef(driver, xml, NULL)))
        return NULL;

    if (!(vm = qemudAssignVMDef(driver, def))) {
        qemudFreeVMDef(def);
        return NULL;
    }

    if (qemudStartVMDaemon(driver, vm) < 0) {
        qemudRemoveInactiveVM(driver, vm);
        return NULL;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom) dom->id = vm->id;
    return dom;
}


static int qemudDomainSuspend(virDomainPtr dom) {
    struct qemud_driver *driver = (struct qemud_driver *)dom->conn->privateData;
    char *info;
    struct qemud_vm *vm = qemudFindVMByID(driver, dom->id);
    if (!vm) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN, "no domain with matching id %d", dom->id);
        return -1;
    }
    if (!qemudIsActiveVM(vm)) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED, "domain is not running");
        return -1;
    }
    if (vm->state == VIR_DOMAIN_PAUSED)
        return 0;

    if (qemudMonitorCommand(driver, vm, "stop\n", &info) < 0) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED, "suspend operation failed");
        return -1;
    }
    vm->state = VIR_DOMAIN_PAUSED;
    qemudDebug("Reply %s", info);
    free(info);
    return 0;
}


static int qemudDomainResume(virDomainPtr dom) {
    struct qemud_driver *driver = (struct qemud_driver *)dom->conn->privateData;
    char *info;
    struct qemud_vm *vm = qemudFindVMByID(driver, dom->id);
    if (!vm) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN, "no domain with matching id %d", dom->id);
        return -1;
    }
    if (!qemudIsActiveVM(vm)) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED, "domain is not running");
        return -1;
    }
    if (vm->state == VIR_DOMAIN_RUNNING)
        return 0;
    if (qemudMonitorCommand(driver, vm, "cont\n", &info) < 0) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED, "resume operation failed");
        return -1;
    }
    vm->state = VIR_DOMAIN_RUNNING;
    qemudDebug("Reply %s", info);
    free(info);
    return 0;
}


static int qemudDomainDestroy(virDomainPtr dom) {
    struct qemud_driver *driver = (struct qemud_driver *)dom->conn->privateData;
    struct qemud_vm *vm = qemudFindVMByID(driver, dom->id);
    int ret;

    if (!vm) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         "no domain with matching id %d", dom->id);
        return -1;
    }

    ret = qemudShutdownVMDaemon(driver, vm);
    virFreeDomain(dom->conn, dom);
    return ret;
}


static char *qemudDomainGetOSType(virDomainPtr dom) {
    struct qemud_driver *driver = (struct qemud_driver *)dom->conn->privateData;
    struct qemud_vm *vm = qemudFindVMByUUID(driver, dom->uuid);
    char *type;

    if (!vm) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         "no domain with matching uuid");
        return NULL;
    }

    if (!(type = strdup(vm->def->os.type))) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_NO_MEMORY, "ostype");
        return NULL;
    }
    return type;
}

static int qemudDomainGetInfo(virDomainPtr dom,
                       virDomainInfoPtr info) {
    struct qemud_driver *driver = (struct qemud_driver *)dom->conn->privateData;
    struct qemud_vm *vm = qemudFindVMByUUID(driver, dom->uuid);
    if (!vm) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN, "no domain with matching uuid");
        return -1;
    }

    info->state = vm->state;

    if (!qemudIsActiveVM(vm)) {
        info->cpuTime = 0;
    } else {
        if (qemudGetProcessInfo(&(info->cpuTime), vm->pid) < 0) {
            qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED, "cannot read cputime for domain");
            return -1;
        }
    }

    info->maxMem = vm->def->maxmem;
    info->memory = vm->def->memory;
    info->nrVirtCpu = vm->def->vcpus;
    return 0;
}


static int qemudDomainSave(virDomainPtr dom,
                    const char *path ATTRIBUTE_UNUSED) {
    struct qemud_driver *driver = (struct qemud_driver *)dom->conn->privateData;
    struct qemud_vm *vm = qemudFindVMByID(driver, dom->id);
    if (!vm) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN, "no domain with matching id %d", dom->id);
        return -1;
    }
    if (!qemudIsActiveVM(vm)) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED, "domain is not running");
        return -1;
    }
    qemudReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED, "save is not supported");
    return -1;
}


static int qemudDomainRestore(virConnectPtr conn,
                       const char *path ATTRIBUTE_UNUSED) {
    /*struct qemud_driver *driver = (struct qemud_driver *)conn->privateData;*/
    qemudReportError(conn, NULL, NULL, VIR_ERR_OPERATION_FAILED, "restore is not supported");
    return -1;
}


static char *qemudDomainDumpXML(virDomainPtr dom,
                         int flags ATTRIBUTE_UNUSED) {
    struct qemud_driver *driver = (struct qemud_driver *)dom->conn->privateData;
    struct qemud_vm *vm = qemudFindVMByUUID(driver, dom->uuid);
    if (!vm) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN, "no domain with matching uuid");
        return NULL;
    }

    return qemudGenerateXML(driver, vm, vm->def, 1);
}


static int qemudListDefinedDomains(virConnectPtr conn,
                            char **const names, int nnames) {
    struct qemud_driver *driver = (struct qemud_driver *)conn->privateData;
    struct qemud_vm *vm = driver->vms;
    int got = 0, i;
    while (vm && got < nnames) {
        if (!qemudIsActiveVM(vm)) {
            if (!(names[got] = strdup(vm->def->name))) {
                qemudReportError(conn, NULL, NULL, VIR_ERR_NO_MEMORY, "names");
                goto cleanup;
            }
            got++;
        }
        vm = vm->next;
    }
    return got;

 cleanup:
    for (i = 0 ; i < got ; i++)
        free(names[i]);
    return -1;
}


static int qemudNumDefinedDomains(virConnectPtr conn) {
    struct qemud_driver *driver = (struct qemud_driver *)conn->privateData;
    return driver->ninactivevms;
}


static int qemudDomainStart(virDomainPtr dom) {
    struct qemud_driver *driver = (struct qemud_driver *)dom->conn->privateData;
    struct qemud_vm *vm = qemudFindVMByUUID(driver, dom->uuid);

    if (!vm) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         "no domain with matching uuid");
        return -1;
    }

    return qemudStartVMDaemon(driver, vm);
}


static virDomainPtr qemudDomainDefine(virConnectPtr conn, const char *xml) {
    struct qemud_driver *driver = (struct qemud_driver *)conn->privateData;
    struct qemud_vm_def *def;
    struct qemud_vm *vm;
    virDomainPtr dom;

    if (!(def = qemudParseVMDef(driver, xml, NULL)))
        return NULL;

    if (!(vm = qemudAssignVMDef(driver, def))) {
        qemudFreeVMDef(def);
        return NULL;
    }

    if (qemudSaveVMDef(driver, vm, def) < 0) {
        qemudRemoveInactiveVM(driver, vm);
        return NULL;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom) dom->id = vm->id;
    return dom;
}

static int qemudDomainUndefine(virDomainPtr dom) {
    struct qemud_driver *driver = (struct qemud_driver *)dom->conn->privateData;
    struct qemud_vm *vm = qemudFindVMByUUID(driver, dom->uuid);

    if (!vm) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN, "no domain with matching uuid");
        return -1;
    }

    if (qemudIsActiveVM(vm)) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INTERNAL_ERROR, "cannot delete active domain");
        return -1;
    }

    if (qemudDeleteConfig(driver, vm->configFile, vm->def->name) < 0)
        return -1;

    if (unlink(vm->autostartLink) < 0 && errno != ENOENT && errno != ENOTDIR)
        qemudLog(QEMUD_WARN, "Failed to delete autostart link '%s': %s",
                 vm->autostartLink, strerror(errno));

    vm->configFile[0] = '\0';
    vm->autostartLink[0] = '\0';

    qemudRemoveInactiveVM(driver, vm);

    return 0;
}

static int qemudDomainGetAutostart(virDomainPtr dom,
                            int *autostart) {
    struct qemud_driver *driver = (struct qemud_driver *)dom->conn->privateData;
    struct qemud_vm *vm = qemudFindVMByUUID(driver, dom->uuid);

    if (!vm) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN, "no domain with matching uuid");
        return -1;
    }

    *autostart = vm->autostart;

    return 0;
}

static int qemudDomainSetAutostart(virDomainPtr dom,
                            int autostart) {
    struct qemud_driver *driver = (struct qemud_driver *)dom->conn->privateData;
    struct qemud_vm *vm = qemudFindVMByUUID(driver, dom->uuid);

    if (!vm) {
        qemudReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN, "no domain with matching uuid");
        return -1;
    }

    autostart = (autostart != 0);

    if (vm->autostart == autostart)
        return 0;

    if (autostart) {
        int err;

        if ((err = qemudEnsureDir(driver->autostartDir))) {
            qemudReportError(dom->conn, dom, NULL, VIR_ERR_INTERNAL_ERROR,
                             "cannot create autostart directory %s: %s",
                             driver->autostartDir, strerror(err));
            return -1;
        }

        if (symlink(vm->configFile, vm->autostartLink) < 0) {
            qemudReportError(dom->conn, dom, NULL, VIR_ERR_INTERNAL_ERROR,
                             "Failed to create symlink '%s' to '%s': %s",
                             vm->autostartLink, vm->configFile, strerror(errno));
            return -1;
        }
    } else {
        if (unlink(vm->autostartLink) < 0 && errno != ENOENT && errno != ENOTDIR) {
            qemudReportError(dom->conn, dom, NULL, VIR_ERR_INTERNAL_ERROR,
                             "Failed to delete symlink '%s': %s",
                             vm->autostartLink, strerror(errno));
            return -1;
        }
    }

    vm->autostart = autostart;

    return 0;
}

static virNetworkPtr qemudNetworkLookupByUUID(virConnectPtr conn ATTRIBUTE_UNUSED,
                                     const unsigned char *uuid) {
    struct qemud_driver *driver = (struct qemud_driver *)conn->networkPrivateData;
    struct qemud_network *network = qemudFindNetworkByUUID(driver, uuid);
    virNetworkPtr net;

    if (!network) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_NO_NETWORK, "no network with matching uuid");
        return NULL;
    }

    net = virGetNetwork(conn, network->def->name, network->def->uuid);
    return net;
}
static virNetworkPtr qemudNetworkLookupByName(virConnectPtr conn ATTRIBUTE_UNUSED,
                                     const char *name) {
    struct qemud_driver *driver = (struct qemud_driver *)conn->networkPrivateData;
    struct qemud_network *network = qemudFindNetworkByName(driver, name);
    virNetworkPtr net;

    if (!network) {
        qemudReportError(conn, NULL, NULL, VIR_ERR_NO_NETWORK, "no network with matching name");
        return NULL;
    }

    net = virGetNetwork(conn, network->def->name, network->def->uuid);
    return net;
}

static virDrvOpenStatus qemudOpenNetwork(virConnectPtr conn,
                                         const char *name ATTRIBUTE_UNUSED,
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
    struct qemud_driver *driver = (struct qemud_driver *)conn->networkPrivateData;
    return driver->nactivenetworks;
}

static int qemudListNetworks(virConnectPtr conn, char **const names, int nnames) {
    struct qemud_driver *driver = (struct qemud_driver *)conn->networkPrivateData;
    struct qemud_network *network = driver->networks;
    int got = 0, i;
    while (network && got < nnames) {
        if (qemudIsActiveNetwork(network)) {
            if (!(names[got] = strdup(network->def->name))) {
                qemudReportError(conn, NULL, NULL, VIR_ERR_NO_MEMORY, "names");
                goto cleanup;
            }
            got++;
        }
        network = network->next;
    }
    return got;

 cleanup:
    for (i = 0 ; i < got ; i++)
        free(names[i]);
    return -1;
}

static int qemudNumDefinedNetworks(virConnectPtr conn) {
    struct qemud_driver *driver = (struct qemud_driver *)conn->networkPrivateData;
    return driver->ninactivenetworks;
}

static int qemudListDefinedNetworks(virConnectPtr conn, char **const names, int nnames) {
    struct qemud_driver *driver = (struct qemud_driver *)conn->networkPrivateData;
    struct qemud_network *network = driver->networks;
    int got = 0, i;
    while (network && got < nnames) {
        if (!qemudIsActiveNetwork(network)) {
            if (!(names[got] = strdup(network->def->name))) {
                qemudReportError(conn, NULL, NULL, VIR_ERR_NO_MEMORY, "names");
                goto cleanup;
            }
            got++;
        }
        network = network->next;
    }
    return got;

 cleanup:
    for (i = 0 ; i < got ; i++)
        free(names[i]);
    return -1;
}

static virNetworkPtr qemudNetworkCreate(virConnectPtr conn, const char *xml) {
    struct qemud_driver *driver = (struct qemud_driver *)conn->networkPrivateData;
    struct qemud_network_def *def;
    struct qemud_network *network;
    virNetworkPtr net;

    if (!(def = qemudParseNetworkDef(driver, xml, NULL)))
        return NULL;

    if (!(network = qemudAssignNetworkDef(driver, def))) {
        qemudFreeNetworkDef(def);
        return NULL;
    }

    if (qemudStartNetworkDaemon(driver, network) < 0) {
        qemudRemoveInactiveNetwork(driver, network);
        return NULL;
    }

    net = virGetNetwork(conn, network->def->name, network->def->uuid);
    return net;
}

static virNetworkPtr qemudNetworkDefine(virConnectPtr conn, const char *xml) {
    struct qemud_driver *driver = (struct qemud_driver *)conn->networkPrivateData;
    struct qemud_network_def *def;
    struct qemud_network *network;
    virNetworkPtr net;

    if (!(def = qemudParseNetworkDef(driver, xml, NULL)))
        return NULL;

    if (!(network = qemudAssignNetworkDef(driver, def))) {
        qemudFreeNetworkDef(def);
        return NULL;
    }

    if (qemudSaveNetworkDef(driver, network, def) < 0) {
        qemudRemoveInactiveNetwork(driver, network);
        return NULL;
    }

    net = virGetNetwork(conn, network->def->name, network->def->uuid);
    return net;
}

static int qemudNetworkUndefine(virNetworkPtr net) {
    struct qemud_driver *driver = (struct qemud_driver *)net->conn->networkPrivateData;
    struct qemud_network *network = qemudFindNetworkByUUID(driver, net->uuid);

    if (!network) {
        qemudReportError(net->conn, NULL, net, VIR_ERR_INVALID_DOMAIN, "no network with matching uuid");
        return -1;
    }

    if (qemudDeleteConfig(driver, network->configFile, network->def->name) < 0)
        return -1;

    if (unlink(network->autostartLink) < 0 && errno != ENOENT && errno != ENOTDIR)
        qemudLog(QEMUD_WARN, "Failed to delete autostart link '%s': %s",
                 network->autostartLink, strerror(errno));

    network->configFile[0] = '\0';
    network->autostartLink[0] = '\0';

    qemudRemoveInactiveNetwork(driver, network);

    return 0;
}

static int qemudNetworkStart(virNetworkPtr net) {
    struct qemud_driver *driver = (struct qemud_driver *)net->conn->networkPrivateData;
    struct qemud_network *network = qemudFindNetworkByUUID(driver, net->uuid);

    if (!network) {
        qemudReportError(net->conn, NULL, net, VIR_ERR_INVALID_NETWORK,
                         "no network with matching uuid");
        return -1;
    }

    return qemudStartNetworkDaemon(driver, network);
}

static int qemudNetworkDestroy(virNetworkPtr net) {
    struct qemud_driver *driver = (struct qemud_driver *)net->conn->networkPrivateData;
    struct qemud_network *network = qemudFindNetworkByUUID(driver, net->uuid);
    int ret;

    if (!network) {
        qemudReportError(net->conn, NULL, net, VIR_ERR_INVALID_NETWORK,
                         "no network with matching uuid");
        return -1;
    }

    ret = qemudShutdownNetworkDaemon(driver, network);

    virFreeNetwork(net->conn, net);

    return ret;
}

static char *qemudNetworkDumpXML(virNetworkPtr net, int flags ATTRIBUTE_UNUSED) {
    struct qemud_driver *driver = (struct qemud_driver *)net->conn->networkPrivateData;
    struct qemud_network *network = qemudFindNetworkByUUID(driver, net->uuid);

    if (!network) {
        qemudReportError(net->conn, NULL, net, VIR_ERR_INVALID_NETWORK,
                         "no network with matching uuid");
        return NULL;
    }

    return qemudGenerateNetworkXML(driver, network, network->def);
}

static char *qemudNetworkGetBridgeName(virNetworkPtr net) {
    struct qemud_driver *driver = (struct qemud_driver *)net->conn->networkPrivateData;
    struct qemud_network *network = qemudFindNetworkByUUID(driver, net->uuid);
    char *bridge;
    if (!network) {
        qemudReportError(net->conn, NULL, net, VIR_ERR_INVALID_NETWORK, "no network with matching id");
        return NULL;
    }

    bridge = strdup(network->bridge);
    if (!bridge) {
        qemudReportError(net->conn, NULL, net, VIR_ERR_NO_MEMORY, "bridge");
        return NULL;
    }
    return bridge;
}

static int qemudNetworkGetAutostart(virNetworkPtr net,
                             int *autostart) {
    struct qemud_driver *driver = (struct qemud_driver *)net->conn->networkPrivateData;
    struct qemud_network *network = qemudFindNetworkByUUID(driver, net->uuid);

    if (!network) {
        qemudReportError(net->conn, NULL, net, VIR_ERR_INVALID_NETWORK, "no network with matching uuid");
        return -1;
    }

    *autostart = network->autostart;

    return 0;
}

static int qemudNetworkSetAutostart(virNetworkPtr net,
                             int autostart) {
    struct qemud_driver *driver = (struct qemud_driver *)net->conn->networkPrivateData;
    struct qemud_network *network = qemudFindNetworkByUUID(driver, net->uuid);

    if (!network) {
        qemudReportError(net->conn, NULL, net, VIR_ERR_INVALID_NETWORK, "no network with matching uuid");
        return -1;
    }

    autostart = (autostart != 0);

    if (network->autostart == autostart)
        return 0;

    if (autostart) {
        int err;

        if ((err = qemudEnsureDir(driver->networkAutostartDir))) {
            qemudReportError(net->conn, NULL, net, VIR_ERR_INTERNAL_ERROR,
                             "cannot create autostart directory %s: %s",
                             driver->networkAutostartDir, strerror(err));
            return -1;
        }

        if (symlink(network->configFile, network->autostartLink) < 0) {
            qemudReportError(net->conn, NULL, net, VIR_ERR_INTERNAL_ERROR,
                             "Failed to create symlink '%s' to '%s': %s",
                             network->autostartLink, network->configFile, strerror(errno));
            return -1;
        }
    } else {
        if (unlink(network->autostartLink) < 0 && errno != ENOENT && errno != ENOTDIR) {
            qemudReportError(net->conn, NULL, net, VIR_ERR_INTERNAL_ERROR,
                             "Failed to delete symlink '%s': %s",
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
    qemudOpen, /* open */
    qemudClose, /* close */
    qemudGetType, /* type */
    qemudGetVersion, /* version */
    NULL, /* hostname */
    NULL, /* uri */
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
    qemudDomainDestroy, /* domainShutdown */
    NULL, /* domainReboot */
    qemudDomainDestroy, /* domainDestroy */
    qemudDomainGetOSType, /* domainGetOSType */
    NULL, /* domainGetMaxMemory */
    NULL, /* domainSetMaxMemory */
    NULL, /* domainSetMemory */
    qemudDomainGetInfo, /* domainGetInfo */
    qemudDomainSave, /* domainSave */
    qemudDomainRestore, /* domainRestore */
    NULL, /* domainCoreDump */
    NULL, /* domainSetVcpus */
    NULL, /* domainPinVcpu */
    NULL, /* domainGetVcpus */
    NULL, /* domainGetMaxVcpus */
    qemudDomainDumpXML, /* domainDumpXML */
    qemudListDefinedDomains, /* listDomains */
    qemudNumDefinedDomains, /* numOfDomains */
    qemudDomainStart, /* domainCreate */
    qemudDomainDefine, /* domainDefineXML */
    qemudDomainUndefine, /* domainUndefine */
    NULL, /* domainAttachDevice */
    NULL, /* domainDetachDevice */
    qemudDomainGetAutostart, /* domainGetAutostart */
    qemudDomainSetAutostart, /* domainSetAutostart */
    NULL, /* domainGetSchedulerType */
    NULL, /* domainGetSchedulerParameters */
    NULL, /* domainSetSchedulerParameters */
};

static virNetworkDriver qemuNetworkDriver = {
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

static virStateDriver qemuStateDriver = {
    qemudStartup,
    qemudShutdown,
    qemudReload,
    qemudActive,
};

int qemudRegister(void) {
    virRegisterDriver(&qemuDriver);
    virRegisterNetworkDriver(&qemuNetworkDriver);
    virRegisterStateDriver(&qemuStateDriver);
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
