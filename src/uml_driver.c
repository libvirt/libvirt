/*
 * uml_driver.c: core driver methods for managing UML guests
 *
 * Copyright (C) 2006, 2007, 2008 Red Hat, Inc.
 * Copyright (C) 2006-2008 Daniel P. Berrange
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
#include <sys/inotify.h>

#if HAVE_NUMACTL
#define NUMA_VERSION1_COMPATIBILITY 1
#include <numa.h>
#endif

#include "uml_driver.h"
#include "uml_conf.h"
#include "event.h"
#include "buf.h"
#include "util.h"
#include "nodeinfo.h"
#include "stats_linux.h"
#include "capabilities.h"
#include "memory.h"
#include "uuid.h"
#include "domain_conf.h"
#include "datatypes.h"

/* For storing short-lived temporary files. */
#define TEMPDIR LOCAL_STATE_DIR "/cache/libvirt"

static int umlShutdown(void);

/* umlDebug statements should be changed to use this macro instead. */
#define DEBUG(fmt,...) VIR_DEBUG(__FILE__, fmt, __VA_ARGS__)
#define DEBUG0(msg) VIR_DEBUG(__FILE__, "%s", msg)

#define umlLog(level, msg...) fprintf(stderr, msg)


static int umlOpenMonitor(virConnectPtr conn,
                          struct uml_driver *driver,
                          virDomainObjPtr vm);
static int umlReadPidFile(virConnectPtr conn,
                          struct uml_driver *driver,
                          virDomainObjPtr vm);

static int umlSetCloseExec(int fd) {
    int flags;
    if ((flags = fcntl(fd, F_GETFD)) < 0)
        goto error;
    flags |= FD_CLOEXEC;
    if ((fcntl(fd, F_SETFD, flags)) < 0)
        goto error;
    return 0;
 error:
    umlLog(UML_ERR,
             "%s", _("Failed to set close-on-exec file descriptor flag\n"));
    return -1;
}

static int umlStartVMDaemon(virConnectPtr conn,
                            struct uml_driver *driver,
                            virDomainObjPtr vm);

static void umlShutdownVMDaemon(virConnectPtr conn,
                                struct uml_driver *driver,
                                virDomainObjPtr vm);


static int umlMonitorCommand (virConnectPtr conn,
                              const struct uml_driver *driver,
                              const virDomainObjPtr vm,
                              const char *cmd,
                              char **reply);

static struct uml_driver *uml_driver = NULL;


static void
umlAutostartConfigs(struct uml_driver *driver) {
    unsigned int i;

    for (i = 0 ; i < driver->domains.count ; i++) {
        if (driver->domains.objs[i]->autostart &&
            !virDomainIsActive(driver->domains.objs[i]) &&
            umlStartVMDaemon(NULL, driver, driver->domains.objs[i]) < 0) {
            virErrorPtr err = virGetLastError();
            umlLog(UML_ERR, _("Failed to autostart VM '%s': %s\n"),
                     driver->domains.objs[i]->def->name, err->message);
        }
    }
}


static int
umlIdentifyOneChrPTY(virConnectPtr conn,
                     struct uml_driver *driver,
                     virDomainObjPtr dom,
                     virDomainChrDefPtr def,
                     const char *dev)
{
    char *cmd;
    char *res = NULL;
    int retries = 0;
    if (asprintf(&cmd, "config %s%d", dev, def->dstPort) < 0) {
        umlReportError(conn, NULL, NULL, VIR_ERR_NO_MEMORY, NULL);
        return -1;
    }
requery:
    umlMonitorCommand(NULL, driver, dom, cmd, &res);

    if (STRPREFIX(res, "pts:")) {
        VIR_FREE(def->data.file.path);
        if ((def->data.file.path = strdup(res + 4)) == NULL) {
            umlReportError(conn, NULL, NULL, VIR_ERR_NO_MEMORY, NULL);
            VIR_FREE(res);
            VIR_FREE(cmd);
            return -1;
        }
    } else if (STRPREFIX(res, "pts")) {
        /* It can take a while to startup, so retry for
           upto 5 seconds */
        /* XXX should do this in a better non-blocking
           way somehow ...perhaps register a timer */
        if (retries++ < 50) {
            usleep(1000*10);
            goto requery;
        }
    }

    VIR_FREE(cmd);
    VIR_FREE(res);
    return 0;
}

static int
umlIdentifyChrPTY(virConnectPtr conn,
                  struct uml_driver *driver,
                  virDomainObjPtr dom)
{
    int i;

    if (dom->def->console &&
        dom->def->console->type == VIR_DOMAIN_CHR_TYPE_PTY)
        if (umlIdentifyOneChrPTY(conn, driver, dom,
                                 dom->def->console, "con") < 0)
            return -1;

    for (i = 0 ; i < dom->def->nserials; i++)
        if (dom->def->serials[i]->type == VIR_DOMAIN_CHR_TYPE_PTY &&
            umlIdentifyOneChrPTY(conn, driver, dom,
                                 dom->def->serials[i], "ssl") < 0)
            return -1;

    return 0;
}

static void
umlInotifyEvent(int watch,
                int fd,
                int events ATTRIBUTE_UNUSED,
                void *data)
{
    char buf[1024];
    struct inotify_event *e;
    int got;
    char *tmp, *name;
    struct uml_driver *driver = data;
    virDomainObjPtr dom;

    if (watch != driver->inotifyWatch)
        return;

reread:
    got = read(fd, buf, sizeof(buf));
    if (got == -1) {
        if (errno == EINTR)
            goto reread;
        return;
    }

    tmp = buf;
    while (got) {
        if (got < sizeof(struct inotify_event))
            return; /* bad */

        e = (struct inotify_event *)tmp;
        tmp += sizeof(struct inotify_event);
        got -= sizeof(struct inotify_event);

        if (got < e->len)
            return;

        tmp += e->len;
        got -= e->len;

        name = (char *)&(e->name);

        dom = virDomainFindByName(&driver->domains, name);

        if (!dom) {
            continue;
        }

        if (e->mask & IN_DELETE) {
            if (!virDomainIsActive(dom)) {
                continue;
            }

            dom->def->id = -1;
            dom->pid = -1;
            if (dom->newDef) {
                virDomainDefFree(dom->def);
                dom->def = dom->newDef;
            }
            dom->state = VIR_DOMAIN_SHUTOFF;
        } else if (e->mask & (IN_CREATE | IN_MODIFY)) {
            if (virDomainIsActive(dom)) {
                continue;
            }

            if (umlReadPidFile(NULL, driver, dom) < 0) {
                continue;
            }

            dom->def->id = driver->nextvmid++;
            dom->state = VIR_DOMAIN_RUNNING;

            if (umlOpenMonitor(NULL, driver, dom) < 0)
                umlShutdownVMDaemon(NULL, driver, dom);

            if (umlIdentifyChrPTY(NULL, driver, dom) < 0)
                umlShutdownVMDaemon(NULL, driver, dom);
        }
    }
}

/**
 * umlStartup:
 *
 * Initialization function for the Uml daemon
 */
static int
umlStartup(void) {
    uid_t uid = geteuid();
    struct passwd *pw;
    char *base = NULL;
    char driverConf[PATH_MAX];

    if (VIR_ALLOC(uml_driver) < 0)
        return -1;

    /* Don't have a dom0 so start from 1 */
    uml_driver->nextvmid = 1;

    if (!(pw = getpwuid(uid))) {
        umlLog(UML_ERR, _("Failed to find user record for uid '%d': %s\n"),
               uid, strerror(errno));
        goto out_nouid;
    }

    if (!uid) {
        if (asprintf(&uml_driver->logDir,
                     "%s/log/libvirt/uml", LOCAL_STATE_DIR) == -1)
            goto out_of_memory;

        if ((base = strdup (SYSCONF_DIR "/libvirt")) == NULL)
            goto out_of_memory;
    } else {
        if (asprintf(&uml_driver->logDir,
                     "%s/.libvirt/uml/log", pw->pw_dir) == -1)
            goto out_of_memory;

        if (asprintf (&base, "%s/.libvirt", pw->pw_dir) == -1)
            goto out_of_memory;
    }

    if (asprintf (&uml_driver->monitorDir,
                  "%s/.uml", pw->pw_dir) == -1)
        goto out_of_memory;

    /* Configuration paths are either ~/.libvirt/uml/... (session) or
     * /etc/libvirt/uml/... (system).
     */
    if (snprintf (driverConf, sizeof(driverConf), "%s/uml.conf", base) == -1)
        goto out_of_memory;
    driverConf[sizeof(driverConf)-1] = '\0';

    if (asprintf (&uml_driver->configDir, "%s/uml", base) == -1)
        goto out_of_memory;

    if (asprintf (&uml_driver->autostartDir, "%s/uml/autostart", base) == -1)
        goto out_of_memory;

    VIR_FREE(base);

    if ((uml_driver->caps = umlCapsInit()) == NULL)
        goto out_of_memory;


    if ((uml_driver->inotifyFD = inotify_init()) < 0) {
        umlLog(UML_ERR, "%s", _("cannot initialize inotify"));
        goto out_nouid;
    }

    if (virFileMakePath(uml_driver->monitorDir) < 0) {
        umlLog(UML_ERR, _("Failed to create monitor directory %s: %s"),
               uml_driver->monitorDir, strerror(errno));
        umlShutdown();
        return -1;
    }

    if (inotify_add_watch(uml_driver->inotifyFD,
                          uml_driver->monitorDir,
                          IN_CREATE | IN_MODIFY | IN_DELETE) < 0) {
        umlShutdown();
        return -1;
    }

    if ((uml_driver->inotifyWatch =
         virEventAddHandle(uml_driver->inotifyFD, POLLIN,
                           umlInotifyEvent, uml_driver, NULL)) < 0) {
        umlShutdown();
        return -1;
    }

    if (virDomainLoadAllConfigs(NULL,
                                uml_driver->caps,
                                &uml_driver->domains,
                                uml_driver->configDir,
                                uml_driver->autostartDir,
                                NULL, NULL) < 0) {
        umlShutdown();
        return -1;
    }
    umlAutostartConfigs(uml_driver);

    return 0;

 out_of_memory:
    umlLog (UML_ERR,
              "%s", _("umlStartup: out of memory\n"));
 out_nouid:
    VIR_FREE(base);
    VIR_FREE(uml_driver);
    return -1;
}

/**
 * umlReload:
 *
 * Function to restart the Uml daemon, it will recheck the configuration
 * files and update its state and the networking
 */
static int
umlReload(void) {
    if (!uml_driver)
        return 0;

    virDomainLoadAllConfigs(NULL,
                            uml_driver->caps,
                            &uml_driver->domains,
                            uml_driver->configDir,
                            uml_driver->autostartDir,
                            NULL, NULL);

    umlAutostartConfigs(uml_driver);

    return 0;
}

/**
 * umlActive:
 *
 * Checks if the Uml daemon is active, i.e. has an active domain or
 * an active network
 *
 * Returns 1 if active, 0 otherwise
 */
static int
umlActive(void) {
    unsigned int i;

    if (!uml_driver)
        return 0;

    for (i = 0 ; i < uml_driver->domains.count ; i++)
        if (virDomainIsActive(uml_driver->domains.objs[i]))
            return 1;

    /* Otherwise we're happy to deal with a shutdown */
    return 0;
}

/**
 * umlShutdown:
 *
 * Shutdown the Uml daemon, it will stop all active domains and networks
 */
static int
umlShutdown(void) {
    unsigned int i;

    if (!uml_driver)
        return -1;

    virEventRemoveHandle(uml_driver->inotifyWatch);
    close(uml_driver->inotifyFD);
    virCapabilitiesFree(uml_driver->caps);

    /* shutdown active VMs */
    for (i = 0 ; i < uml_driver->domains.count ; i++) {
        virDomainObjPtr dom = uml_driver->domains.objs[i];
        if (virDomainIsActive(dom))
            umlShutdownVMDaemon(NULL, uml_driver, dom);
        if (!dom->persistent)
            virDomainRemoveInactive(&uml_driver->domains,
                                    dom);
    }

    virDomainObjListFree(&uml_driver->domains);

    VIR_FREE(uml_driver->logDir);
    VIR_FREE(uml_driver->configDir);
    VIR_FREE(uml_driver->autostartDir);
    VIR_FREE(uml_driver->monitorDir);

    if (uml_driver->brctl)
        brShutdown(uml_driver->brctl);

    VIR_FREE(uml_driver);

    return 0;
}


static int umlReadPidFile(virConnectPtr conn,
                          struct uml_driver *driver,
                          virDomainObjPtr vm)
{
    int rc = -1;
    FILE *file;
    char *pidfile = NULL;
    int retries = 0;

    vm->pid = -1;
    if (asprintf(&pidfile, "%s/%s/pid",
                 driver->monitorDir, vm->def->name) < 0) {
        umlReportError(conn, NULL, NULL, VIR_ERR_NO_MEMORY, NULL);
        return -1;
    }

reopen:
    if (!(file = fopen(pidfile, "r"))) {
        if (errno == ENOENT &&
            retries++ < 50) {
            usleep(1000 * 100);
            goto reopen;
        }
        goto cleanup;
    }

    if (fscanf(file, "%d", &vm->pid) != 1) {
        errno = EINVAL;
        goto cleanup;
    }

    if (fclose(file) < 0)
        goto cleanup;

    rc = 0;

 cleanup:
    if (rc != 0)
        umlReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                       _("failed to read pid: %s: %s"),
                       pidfile, strerror(errno));
    VIR_FREE(pidfile);
    return rc;
}

static int umlMonitorAddress(virConnectPtr conn,
                             const struct uml_driver *driver,
                             virDomainObjPtr vm,
                             struct sockaddr_un *addr) {
    char *sockname;

    if (asprintf(&sockname, "%s/%s/mconsole",
                 driver->monitorDir, vm->def->name) < 0) {
        umlReportError(conn, NULL, NULL, VIR_ERR_NO_MEMORY, NULL);
        return -1;
    }

    memset(addr, 0, sizeof *addr);
    addr->sun_family = AF_UNIX;
    strncpy(addr->sun_path, sockname, sizeof(addr->sun_path)-1);
    NUL_TERMINATE(addr->sun_path);
    VIR_FREE(sockname);
    return 0;
}

static int umlOpenMonitor(virConnectPtr conn,
                          struct uml_driver *driver,
                          virDomainObjPtr vm) {
    struct sockaddr_un addr;
    struct stat sb;
    int retries = 0;

    if (umlMonitorAddress(conn, driver, vm, &addr) < 0)
        return -1;

restat:
    if (stat(addr.sun_path, &sb) < 0) {
        if (errno == ENOENT &&
            retries < 50) {
            usleep(1000 * 100);
            goto restat;
        }
        return -1;
    }

    if ((vm->monitor = socket(PF_UNIX, SOCK_DGRAM, 0)) < 0) {
        umlReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                       _("cannot open socket %s"), strerror(errno));
        return -1;
    }

    memset(addr.sun_path, 0, sizeof addr.sun_path);
    sprintf(addr.sun_path + 1, "%u", getpid());
    if (bind(vm->monitor, (struct sockaddr *)&addr, sizeof addr) < 0) {
        umlReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                       _("cannot bind socket %s"), strerror(errno));
        close(vm->monitor);
        vm->monitor = -1;
        return -1;
    }

    return 0;
}


#define MONITOR_MAGIC 0xcafebabe
#define MONITOR_BUFLEN 512
#define MONITOR_VERSION 2

struct monitor_request {
    uint32_t magic;
    uint32_t version;
    uint32_t length;
    char data[MONITOR_BUFLEN];
};

struct monitor_response {
    uint32_t error;
    uint32_t extra;
    uint32_t length;
    char data[MONITOR_BUFLEN];
};


static int umlMonitorCommand(virConnectPtr conn,
                             const struct uml_driver *driver,
                             const virDomainObjPtr vm,
                             const char *cmd,
                             char **reply)
{
    struct monitor_request req;
    struct monitor_response res;
    char *retdata = NULL;
    int retlen = 0, ret = 0;
    struct sockaddr_un addr;
    unsigned int addrlen;

    *reply = NULL;

    if (umlMonitorAddress(conn, driver, vm, &addr) < 0)
        return -1;

    memset(&req, 0, sizeof(req));
    req.magic = MONITOR_MAGIC;
    req.version = MONITOR_VERSION;
    req.length = strlen(cmd);
    if (req.length > (MONITOR_BUFLEN-1)) {
        umlReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                       _("cannot send too long command %s: %s"),
                       cmd, strerror(EINVAL));
        return -1;
    }
    strncpy(req.data, cmd, req.length);
    req.data[req.length] = '\0';

    if (sendto(vm->monitor, &req, sizeof req, 0,
               (struct sockaddr *)&addr, sizeof addr) != (sizeof req)) {
        umlReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                       _("cannot send command %s: %s"),
                       cmd, strerror(errno));
        return -1;
    }

    do {
        addrlen = sizeof(addr);
        if (recvfrom(vm->monitor, &res, sizeof res, 0,
                     (struct sockaddr *)&addr, &addrlen) < 0) {
            umlReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                           _("cannot read reply %s: %s"),
                           cmd, strerror(errno));
            goto error;
        }

        if (VIR_REALLOC_N(retdata, retlen + res.length) < 0) {
            umlReportError(conn, NULL, NULL,
                           VIR_ERR_NO_MEMORY, NULL);
            goto error;
        }
        memcpy(retdata + retlen, res.data, res.length);
        retlen += res.length - 1;
        retdata[retlen] = '\0';

        if (res.error)
            ret = -1;

    } while (res.extra);

    *reply = retdata;

    return ret;

error:
    VIR_FREE(retdata);
    return -1;
}


static int umlStartVMDaemon(virConnectPtr conn,
                            struct uml_driver *driver,
                            virDomainObjPtr vm) {
    const char **argv = NULL, **tmp;
    const char **progenv = NULL;
    int i, ret, pid;
    char *logfile;
    int logfd = -1;
    struct stat sb;
    int *tapfds = NULL;
    int ntapfds = 0;
    fd_set keepfd;

    FD_ZERO(&keepfd);

    if (virDomainIsActive(vm)) {
        umlReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("VM is already active"));
        return -1;
    }

    if (!vm->def->os.kernel) {
        umlReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                       "%s", _("no kernel specified"));
        return -1;
    }
    /* Make sure the binary we are about to try exec'ing exists.
     * Technically we could catch the exec() failure, but that's
     * in a sub-process so its hard to feed back a useful error
     */
    if (stat(vm->def->os.kernel, &sb) < 0) {
        umlReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                       _("Cannot find UML kernel %s: %s"),
                       vm->def->os.kernel, strerror(errno));
        return -1;
    }

    if (virFileMakePath(driver->logDir) < 0) {
        umlReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                       _("cannot create log directory %s"),
                       driver->logDir);
        return -1;
    }

    if (asprintf(&logfile, "%s/%s.log",
                 driver->logDir, vm->def->name) < 0) {
        umlReportError(conn, NULL, NULL, VIR_ERR_NO_MEMORY, NULL);
        return -1;
    }

    if ((logfd = open(logfile, O_CREAT | O_TRUNC | O_WRONLY,
                      S_IRUSR | S_IWUSR)) < 0) {
        umlReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                       _("failed to create logfile %s: %s"),
                       logfile, strerror(errno));
        VIR_FREE(logfile);
        return -1;
    }
    VIR_FREE(logfile);

    if (umlSetCloseExec(logfd) < 0) {
        umlReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                       _("Unable to set VM logfile close-on-exec flag %s"),
                       strerror(errno));
        close(logfd);
        return -1;
    }

    if (umlBuildCommandLine(conn, driver, vm,
                            &argv, &progenv,
                            &tapfds, &ntapfds) < 0) {
        close(logfd);
        return -1;
    }

    tmp = progenv;
    while (*tmp) {
        if (safewrite(logfd, *tmp, strlen(*tmp)) < 0)
            umlLog(UML_WARN, _("Unable to write envv to logfile %d: %s\n"),
                   errno, strerror(errno));
        if (safewrite(logfd, " ", 1) < 0)
            umlLog(UML_WARN, _("Unable to write envv to logfile %d: %s\n"),
                   errno, strerror(errno));
        tmp++;
    }
    tmp = argv;
    while (*tmp) {
        if (safewrite(logfd, *tmp, strlen(*tmp)) < 0)
            umlLog(UML_WARN, _("Unable to write argv to logfile %d: %s\n"),
                   errno, strerror(errno));
        if (safewrite(logfd, " ", 1) < 0)
            umlLog(UML_WARN, _("Unable to write argv to logfile %d: %s\n"),
                   errno, strerror(errno));
        tmp++;
    }
    if (safewrite(logfd, "\n", 1) < 0)
        umlLog(UML_WARN, _("Unable to write argv to logfile %d: %s\n"),
                 errno, strerror(errno));

    vm->monitor = -1;
    vm->stdin_fd = -1;
    vm->stdout_fd = vm->stderr_fd = logfd;

    for (i = 0 ; i < ntapfds ; i++)
        FD_SET(tapfds[i], &keepfd);

    ret = virExec(conn, argv, progenv, &keepfd, &pid,
                  vm->stdin_fd, &vm->stdout_fd, &vm->stderr_fd,
                  VIR_EXEC_DAEMON);
    close(logfd);

    /* Cleanup intermediate proces */
    if (waitpid(pid, NULL, 0) != pid)
        umlLog(UML_WARN, _("failed to wait on process: %d: %s\n"),
               pid, strerror(errno));

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

    /* NB we don't mark it running here - we do that async
       with inotify */

    return ret;
}

static void umlShutdownVMDaemon(virConnectPtr conn ATTRIBUTE_UNUSED,
                                struct uml_driver *driver ATTRIBUTE_UNUSED,
                                virDomainObjPtr vm)
{
    int ret;
    if (!virDomainIsActive(vm) ||
        vm->pid <= 1)
        return;


    kill(vm->pid, SIGTERM);

    if (vm->monitor != -1)
        close(vm->monitor);
    vm->monitor = -1;

    if ((ret = waitpid(vm->pid, NULL, 0)) != vm->pid) {
        umlLog(UML_WARN,
               _("Got unexpected pid %d != %d\n"),
               ret, vm->pid);
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


static virDrvOpenStatus umlOpen(virConnectPtr conn,
                                virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                                int flags ATTRIBUTE_UNUSED) {
    uid_t uid = getuid();

    if (uml_driver == NULL)
        goto decline;

    if (conn->uri != NULL) {
        if (conn->uri->scheme == NULL || conn->uri->path == NULL)
            goto decline;

        if (STRNEQ (conn->uri->scheme, "uml"))
            goto decline;

        if (uid != 0) {
            if (STRNEQ (conn->uri->path, "/session"))
                goto decline;
        } else { /* root */
            if (STRNEQ (conn->uri->path, "/system") &&
                STRNEQ (conn->uri->path, "/session"))
                goto decline;
        }
    } else {
        conn->uri = xmlParseURI(uid ? "uml:///session" : "uml:///system");
        if (!conn->uri) {
            umlReportError(conn, NULL, NULL, VIR_ERR_NO_MEMORY,NULL);
            return VIR_DRV_OPEN_ERROR;
        }
    }

    conn->privateData = uml_driver;

    return VIR_DRV_OPEN_SUCCESS;

 decline:
    return VIR_DRV_OPEN_DECLINED;
}

static int umlClose(virConnectPtr conn) {
    /*struct uml_driver *driver = (struct uml_driver *)conn->privateData;*/

    conn->privateData = NULL;

    return 0;
}

static const char *umlGetType(virConnectPtr conn ATTRIBUTE_UNUSED) {
    return "UML";
}

static int umlGetNodeInfo(virConnectPtr conn,
                          virNodeInfoPtr nodeinfo) {
    return virNodeInfoPopulate(conn, nodeinfo);
}


static char *umlGetCapabilities(virConnectPtr conn) {
    struct uml_driver *driver = (struct uml_driver *)conn->privateData;
    char *xml;

    if ((xml = virCapabilitiesFormatXML(driver->caps)) == NULL) {
        umlReportError(conn, NULL, NULL, VIR_ERR_NO_MEMORY,
                 "%s", _("failed to allocate space for capabilities support"));
        return NULL;
    }

    return xml;
}


#if HAVE_NUMACTL
static int
umlNodeGetCellsFreeMemory(virConnectPtr conn,
                            unsigned long long *freeMems,
                            int startCell,
                            int maxCells)
{
    int n, lastCell, numCells;

    if (numa_available() < 0) {
        umlReportError(conn, NULL, NULL, VIR_ERR_NO_SUPPORT,
                         "%s", _("NUMA not supported on this host"));
        return -1;
    }
    lastCell = startCell + maxCells - 1;
    if (lastCell > numa_max_node())
        lastCell = numa_max_node();

    for (numCells = 0, n = startCell ; n <= lastCell ; n++) {
        long long mem;
        if (numa_node_size64(n, &mem) < 0) {
            umlReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("Failed to query NUMA free memory"));
            return -1;
        }
        freeMems[numCells++] = mem;
    }
    return numCells;
}

static unsigned long long
umlNodeGetFreeMemory (virConnectPtr conn)
{
    unsigned long long freeMem = 0;
    int n;
    if (numa_available() < 0) {
        umlReportError(conn, NULL, NULL, VIR_ERR_NO_SUPPORT,
                         "%s", _("NUMA not supported on this host"));
        return -1;
    }

    for (n = 0 ; n <= numa_max_node() ; n++) {
        long long mem;
        if (numa_node_size64(n, &mem) < 0) {
            umlReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("Failed to query NUMA free memory"));
            return -1;
        }
        freeMem += mem;
    }

    return freeMem;
}

#endif

static int umlGetProcessInfo(unsigned long long *cpuTime, int pid) {
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
        umlDebug("not enough arg");
        return -1;
    }

    /* We got jiffies
     * We want nanoseconds
     * _SC_CLK_TCK is jiffies per second
     * So calulate thus....
     */
    *cpuTime = 1000ull * 1000ull * 1000ull * (usertime + systime) / (unsigned long long)sysconf(_SC_CLK_TCK);

    umlDebug("Got %llu %llu %llu", usertime, systime, *cpuTime);

    fclose(pidinfo);

    return 0;
}


static virDomainPtr umlDomainLookupByID(virConnectPtr conn,
                                          int id) {
    struct uml_driver *driver = (struct uml_driver *)conn->privateData;
    virDomainObjPtr vm = virDomainFindByID(&driver->domains, id);
    virDomainPtr dom;

    if (!vm) {
        umlReportError(conn, NULL, NULL, VIR_ERR_NO_DOMAIN, NULL);
        return NULL;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom) dom->id = vm->def->id;
    return dom;
}
static virDomainPtr umlDomainLookupByUUID(virConnectPtr conn,
                                            const unsigned char *uuid) {
    struct uml_driver *driver = (struct uml_driver *)conn->privateData;
    virDomainObjPtr vm = virDomainFindByUUID(&driver->domains, uuid);
    virDomainPtr dom;

    if (!vm) {
        umlReportError(conn, NULL, NULL, VIR_ERR_NO_DOMAIN, NULL);
        return NULL;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom) dom->id = vm->def->id;
    return dom;
}
static virDomainPtr umlDomainLookupByName(virConnectPtr conn,
                                            const char *name) {
    struct uml_driver *driver = (struct uml_driver *)conn->privateData;
    virDomainObjPtr vm = virDomainFindByName(&driver->domains, name);
    virDomainPtr dom;

    if (!vm) {
        umlReportError(conn, NULL, NULL, VIR_ERR_NO_DOMAIN, NULL);
        return NULL;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom) dom->id = vm->def->id;
    return dom;
}

static int umlGetVersion(virConnectPtr conn, unsigned long *version) {
    struct utsname ut;
    int major, minor, micro;

    uname(&ut);

    if (sscanf(ut.release, "%u.%u.%u",
               &major, &minor, &micro) != 3) {
        umlReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                       _("cannot parse version %s"), ut.release);
        return -1;
    }

    *version = uml_driver->umlVersion;
    return 0;
}

static char *
umlGetHostname (virConnectPtr conn)
{
    int r;
    char hostname[HOST_NAME_MAX+1], *str;

    r = gethostname (hostname, HOST_NAME_MAX+1);
    if (r == -1) {
        umlReportError (conn, NULL, NULL, VIR_ERR_SYSTEM_ERROR,
                          "%s", strerror (errno));
        return NULL;
    }
    /* Caller frees this string. */
    str = strdup (hostname);
    if (str == NULL) {
        umlReportError (conn, NULL, NULL, VIR_ERR_SYSTEM_ERROR,
                         "%s", strerror (errno));
        return NULL;
    }
    return str;
}

static int umlListDomains(virConnectPtr conn, int *ids, int nids) {
    struct uml_driver *driver = (struct uml_driver *)conn->privateData;
    int got = 0, i;

    for (i = 0 ; i < driver->domains.count && got < nids ; i++)
        if (virDomainIsActive(driver->domains.objs[i]))
            ids[got++] = driver->domains.objs[i]->def->id;

    return got;
}
static int umlNumDomains(virConnectPtr conn) {
    struct uml_driver *driver = (struct uml_driver *)conn->privateData;
    int n = 0, i;

    for (i = 0 ; i < driver->domains.count ; i++)
        if (virDomainIsActive(driver->domains.objs[i]))
            n++;

    return n;
}
static virDomainPtr umlDomainCreate(virConnectPtr conn, const char *xml,
                                      unsigned int flags ATTRIBUTE_UNUSED) {
    virDomainDefPtr def;
    virDomainObjPtr vm;
    virDomainPtr dom;
    struct uml_driver *driver = (struct uml_driver *)conn->privateData;

    if (!(def = virDomainDefParseString(conn, driver->caps, xml)))
        return NULL;

    vm = virDomainFindByName(&driver->domains, def->name);
    if (vm) {
        umlReportError(conn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
                         _("domain '%s' is already defined"),
                         def->name);
        virDomainDefFree(def);
        return NULL;
    }
    vm = virDomainFindByUUID(&driver->domains, def->uuid);
    if (vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];

        virUUIDFormat(def->uuid, uuidstr);
        umlReportError(conn, NULL, NULL, VIR_ERR_OPERATION_FAILED,
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

    if (umlStartVMDaemon(conn, driver, vm) < 0) {
        virDomainRemoveInactive(&driver->domains,
                                vm);
        return NULL;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom) dom->id = vm->def->id;
    return dom;
}


static int umlDomainShutdown(virDomainPtr dom) {
    struct uml_driver *driver = (struct uml_driver *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByID(&driver->domains, dom->id);
    char *info = NULL;

    if (!vm) {
        umlReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         _("no domain with matching id %d"), dom->id);
        return -1;
    }

#if 0
    if (umlMonitorCommand(driver, vm, "system_powerdown", &info) < 0) {
        umlReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("shutdown operation failed"));
        return -1;
    }
#endif
    VIR_FREE(info);
    return 0;

}


static int umlDomainDestroy(virDomainPtr dom) {
    struct uml_driver *driver = (struct uml_driver *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByID(&driver->domains, dom->id);

    if (!vm) {
        umlReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         _("no domain with matching id %d"), dom->id);
        return -1;
    }

    umlShutdownVMDaemon(dom->conn, driver, vm);
    if (!vm->persistent)
        virDomainRemoveInactive(&driver->domains,
                                vm);

    return 0;
}


static char *umlDomainGetOSType(virDomainPtr dom) {
    struct uml_driver *driver = (struct uml_driver *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    char *type;

    if (!vm) {
        umlReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         "%s", _("no domain with matching uuid"));
        return NULL;
    }

    if (!(type = strdup(vm->def->os.type))) {
        umlReportError(dom->conn, dom, NULL, VIR_ERR_NO_MEMORY,
                         "%s", _("failed to allocate space for ostype"));
        return NULL;
    }
    return type;
}

/* Returns max memory in kb, 0 if error */
static unsigned long umlDomainGetMaxMemory(virDomainPtr dom) {
    struct uml_driver *driver = (struct uml_driver *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByUUID(&driver->domains, dom->uuid);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];

        virUUIDFormat(dom->uuid, uuidstr);
        umlReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         _("no domain with matching uuid '%s'"), uuidstr);
        return 0;
    }

    return vm->def->maxmem;
}

static int umlDomainSetMaxMemory(virDomainPtr dom, unsigned long newmax) {
    struct uml_driver *driver = (struct uml_driver *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByUUID(&driver->domains, dom->uuid);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];

        virUUIDFormat(dom->uuid, uuidstr);
        umlReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         _("no domain with matching uuid '%s'"), uuidstr);
        return -1;
    }

    if (newmax < vm->def->memory) {
        umlReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_ARG,
                         "%s", _("cannot set max memory lower than current memory"));
        return -1;
    }

    vm->def->maxmem = newmax;
    return 0;
}

static int umlDomainSetMemory(virDomainPtr dom, unsigned long newmem) {
    struct uml_driver *driver = (struct uml_driver *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByUUID(&driver->domains, dom->uuid);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];

        virUUIDFormat(dom->uuid, uuidstr);
        umlReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         _("no domain with matching uuid '%s'"), uuidstr);
        return -1;
    }

    if (virDomainIsActive(vm)) {
        umlReportError(dom->conn, dom, NULL, VIR_ERR_NO_SUPPORT,
                         "%s", _("cannot set memory of an active domain"));
        return -1;
    }

    if (newmem > vm->def->maxmem) {
        umlReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_ARG,
                         "%s", _("cannot set memory higher than max memory"));
        return -1;
    }

    vm->def->memory = newmem;
    return 0;
}

static int umlDomainGetInfo(virDomainPtr dom,
                              virDomainInfoPtr info) {
    struct uml_driver *driver = (struct uml_driver *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    if (!vm) {
        umlReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         "%s", _("no domain with matching uuid"));
        return -1;
    }

    info->state = vm->state;

    if (!virDomainIsActive(vm)) {
        info->cpuTime = 0;
    } else {
        if (umlGetProcessInfo(&(info->cpuTime), vm->pid) < 0) {
            umlReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED, ("cannot read cputime for domain"));
            return -1;
        }
    }

    info->maxMem = vm->def->maxmem;
    info->memory = vm->def->memory;
    info->nrVirtCpu = vm->def->vcpus;
    return 0;
}


static char *umlDomainDumpXML(virDomainPtr dom,
                                int flags ATTRIBUTE_UNUSED) {
    struct uml_driver *driver = (struct uml_driver *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    if (!vm) {
        umlReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         "%s", _("no domain with matching uuid"));
        return NULL;
    }

    return virDomainDefFormat(dom->conn,
                              (flags & VIR_DOMAIN_XML_INACTIVE) && vm->newDef ?
                              vm->newDef : vm->def,
                              flags);
}


static int umlListDefinedDomains(virConnectPtr conn,
                            char **const names, int nnames) {
    struct uml_driver *driver = (struct uml_driver *)conn->privateData;
    int got = 0, i;

    for (i = 0 ; i < driver->domains.count && got < nnames ; i++) {
        if (!virDomainIsActive(driver->domains.objs[i])) {
            if (!(names[got++] = strdup(driver->domains.objs[i]->def->name))) {
                umlReportError(conn, NULL, NULL, VIR_ERR_NO_MEMORY,
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

static int umlNumDefinedDomains(virConnectPtr conn) {
    struct uml_driver *driver = (struct uml_driver *)conn->privateData;
    int n = 0, i;

    for (i = 0 ; i < driver->domains.count ; i++)
        if (!virDomainIsActive(driver->domains.objs[i]))
            n++;

    return n;
}


static int umlDomainStart(virDomainPtr dom) {
    struct uml_driver *driver = (struct uml_driver *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByUUID(&driver->domains, dom->uuid);

    if (!vm) {
        umlReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         "%s", _("no domain with matching uuid"));
        return -1;
    }

    return umlStartVMDaemon(dom->conn, driver, vm);
}


static virDomainPtr umlDomainDefine(virConnectPtr conn, const char *xml) {
    struct uml_driver *driver = (struct uml_driver *)conn->privateData;
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

static int umlDomainUndefine(virDomainPtr dom) {
    struct uml_driver *driver = (struct uml_driver *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByUUID(&driver->domains, dom->uuid);

    if (!vm) {
        umlReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         "%s", _("no domain with matching uuid"));
        return -1;
    }

    if (virDomainIsActive(vm)) {
        umlReportError(dom->conn, dom, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("cannot delete active domain"));
        return -1;
    }

    if (!vm->persistent) {
        umlReportError(dom->conn, dom, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("cannot undefine transient domain"));
        return -1;
    }

    if (virDomainDeleteConfig(dom->conn, driver->configDir, driver->autostartDir, vm) < 0)
        return -1;

    virDomainRemoveInactive(&driver->domains,
                            vm);

    return 0;
}



static int umlDomainGetAutostart(virDomainPtr dom,
                            int *autostart) {
    struct uml_driver *driver = (struct uml_driver *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByUUID(&driver->domains, dom->uuid);

    if (!vm) {
        umlReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         "%s", _("no domain with matching uuid"));
        return -1;
    }

    *autostart = vm->autostart;

    return 0;
}

static int umlDomainSetAutostart(virDomainPtr dom,
                                   int autostart) {
    struct uml_driver *driver = (struct uml_driver *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    char *configFile = NULL, *autostartLink = NULL;
    int ret = -1;

    if (!vm) {
        umlReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         "%s", _("no domain with matching uuid"));
        return -1;
    }

    if (!vm->persistent) {
        umlReportError(dom->conn, dom, NULL, VIR_ERR_INTERNAL_ERROR,
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
            umlReportError(dom->conn, dom, NULL, VIR_ERR_INTERNAL_ERROR,
                             _("cannot create autostart directory %s: %s"),
                             driver->autostartDir, strerror(err));
            goto cleanup;
        }

        if (symlink(configFile, autostartLink) < 0) {
            umlReportError(dom->conn, dom, NULL, VIR_ERR_INTERNAL_ERROR,
                             _("Failed to create symlink '%s to '%s': %s"),
                             autostartLink, configFile, strerror(errno));
            goto cleanup;
        }
    } else {
        if (unlink(autostartLink) < 0 && errno != ENOENT && errno != ENOTDIR) {
            umlReportError(dom->conn, dom, NULL, VIR_ERR_INTERNAL_ERROR,
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


static int
umlDomainBlockPeek (virDomainPtr dom,
                      const char *path,
                      unsigned long long offset, size_t size,
                      void *buffer,
                      unsigned int flags ATTRIBUTE_UNUSED)
{
    struct uml_driver *driver = (struct uml_driver *)dom->conn->privateData;
    virDomainObjPtr vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    int fd, ret = -1, i;

    if (!vm) {
        umlReportError (dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                          _("no domain with matching uuid"));
        return -1;
    }

    if (!path || path[0] == '\0') {
        umlReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_ARG,
                         _("NULL or empty path"));
        return -1;
    }

    /* Check the path belongs to this domain. */
    for (i = 0 ; i < vm->def->ndisks ; i++) {
        if (vm->def->disks[i]->src != NULL &&
            STREQ (vm->def->disks[i]->src, path))
            goto found;
    }
    umlReportError (dom->conn, dom, NULL, VIR_ERR_INVALID_ARG,
                      _("invalid path"));
    return -1;

found:
    /* The path is correct, now try to open it and get its size. */
    fd = open (path, O_RDONLY);
    if (fd == -1) {
        umlReportError (dom->conn, dom, NULL, VIR_ERR_SYSTEM_ERROR,
                          "%s", strerror (errno));
        goto done;
    }

    /* Seek and read. */
    /* NB. Because we configure with AC_SYS_LARGEFILE, off_t should
     * be 64 bits on all platforms.
     */
    if (lseek (fd, offset, SEEK_SET) == (off_t) -1 ||
        saferead (fd, buffer, size) == (ssize_t) -1) {
        umlReportError (dom->conn, dom, NULL, VIR_ERR_SYSTEM_ERROR,
                          "%s", strerror (errno));
        goto done;
    }

    ret = 0;
 done:
    if (fd >= 0) close (fd);
    return ret;
}



static virDriver umlDriver = {
    VIR_DRV_UML,
    "UML",
    umlOpen, /* open */
    umlClose, /* close */
    NULL, /* supports_feature */
    umlGetType, /* type */
    umlGetVersion, /* version */
    umlGetHostname, /* hostname */
    NULL, /* URI  */
    NULL, /* getMaxVcpus */
    umlGetNodeInfo, /* nodeGetInfo */
    umlGetCapabilities, /* getCapabilities */
    umlListDomains, /* listDomains */
    umlNumDomains, /* numOfDomains */
    umlDomainCreate, /* domainCreateXML */
    umlDomainLookupByID, /* domainLookupByID */
    umlDomainLookupByUUID, /* domainLookupByUUID */
    umlDomainLookupByName, /* domainLookupByName */
    NULL, /* domainSuspend */
    NULL, /* domainResume */
    umlDomainShutdown, /* domainShutdown */
    NULL, /* domainReboot */
    umlDomainDestroy, /* domainDestroy */
    umlDomainGetOSType, /* domainGetOSType */
    umlDomainGetMaxMemory, /* domainGetMaxMemory */
    umlDomainSetMaxMemory, /* domainSetMaxMemory */
    umlDomainSetMemory, /* domainSetMemory */
    umlDomainGetInfo, /* domainGetInfo */
    NULL, /* domainSave */
    NULL, /* domainRestore */
    NULL, /* domainCoreDump */
    NULL, /* domainSetVcpus */
    NULL, /* domainPinVcpu */
    NULL, /* domainGetVcpus */
    NULL, /* domainGetMaxVcpus */
    umlDomainDumpXML, /* domainDumpXML */
    umlListDefinedDomains, /* listDomains */
    umlNumDefinedDomains, /* numOfDomains */
    umlDomainStart, /* domainCreate */
    umlDomainDefine, /* domainDefineXML */
    umlDomainUndefine, /* domainUndefine */
    NULL, /* domainAttachDevice */
    NULL, /* domainDetachDevice */
    umlDomainGetAutostart, /* domainGetAutostart */
    umlDomainSetAutostart, /* domainSetAutostart */
    NULL, /* domainGetSchedulerType */
    NULL, /* domainGetSchedulerParameters */
    NULL, /* domainSetSchedulerParameters */
    NULL, /* domainMigratePrepare */
    NULL, /* domainMigratePerform */
    NULL, /* domainMigrateFinish */
    NULL, /* domainBlockStats */
    NULL, /* domainInterfaceStats */
    umlDomainBlockPeek, /* domainBlockPeek */
    NULL, /* domainMemoryPeek */
#if HAVE_NUMACTL
    umlNodeGetCellsFreeMemory, /* nodeGetCellsFreeMemory */
    umlNodeGetFreeMemory,  /* getFreeMemory */
#else
    NULL, /* nodeGetCellsFreeMemory */
    NULL, /* getFreeMemory */
#endif
    NULL, /* domainEventRegister */
    NULL, /* domainEventUnregister */
    NULL, /* domainMigratePrepare2 */
    NULL, /* domainMigrateFinish2 */
};


static virStateDriver umlStateDriver = {
    .initialize = umlStartup,
    .cleanup = umlShutdown,
    .reload = umlReload,
    .active = umlActive,
};

int umlRegister(void) {
    virRegisterDriver(&umlDriver);
    virRegisterStateDriver(&umlStateDriver);
    return 0;
}
