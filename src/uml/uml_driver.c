/*
 * uml_driver.c: core driver methods for managing UML guests
 *
 * Copyright (C) 2006, 2007, 2008, 2009 Red Hat, Inc.
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
#include <sys/un.h>

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
#include "logging.h"

#define VIR_FROM_THIS VIR_FROM_UML

/* For storing short-lived temporary files. */
#define TEMPDIR LOCAL_STATE_DIR "/cache/libvirt"

typedef struct _umlDomainObjPrivate umlDomainObjPrivate;
typedef umlDomainObjPrivate *umlDomainObjPrivatePtr;
struct _umlDomainObjPrivate {
    int monitor;
    int monitorWatch;
};


static int umlShutdown(void);

static void *umlDomainObjPrivateAlloc(void)
{
    umlDomainObjPrivatePtr priv;

    if (VIR_ALLOC(priv) < 0)
        return NULL;

    priv->monitor = -1;
    priv->monitorWatch = -1;

    return priv;
}

static void umlDomainObjPrivateFree(void *data)
{
    umlDomainObjPrivatePtr priv = data;

    VIR_FREE(priv);
}


static void umlDriverLock(struct uml_driver *driver)
{
    virMutexLock(&driver->lock);
}
static void umlDriverUnlock(struct uml_driver *driver)
{
    virMutexUnlock(&driver->lock);
}


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
    VIR_ERROR0(_("Failed to set close-on-exec file descriptor flag"));
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

struct umlAutostartData {
    struct uml_driver *driver;
    virConnectPtr conn;
};

static void
umlAutostartDomain(void *payload, const char *name ATTRIBUTE_UNUSED, void *opaque)
{
    virDomainObjPtr vm = payload;
    const struct umlAutostartData *data = opaque;

    virDomainObjLock(vm);
    if (vm->autostart &&
        !virDomainObjIsActive(vm)) {
        virResetLastError();
        if (umlStartVMDaemon(data->conn, data->driver, vm) < 0) {
            virErrorPtr err = virGetLastError();
            VIR_ERROR(_("Failed to autostart VM '%s': %s"),
                      vm->def->name, err->message);
        }
    }
    virDomainObjUnlock(vm);
}

static void
umlAutostartConfigs(struct uml_driver *driver) {
    /* XXX: Figure out a better way todo this. The domain
     * startup code needs a connection handle in order
     * to lookup the bridge associated with a virtual
     * network
     */
    virConnectPtr conn = virConnectOpen(driver->privileged ?
                                        "uml:///system" :
                                        "uml:///session");
    /* Ignoring NULL conn which is mostly harmless here */

    struct umlAutostartData data = { driver, conn };

    virHashForEach(driver->domains.objs, umlAutostartDomain, &data);

    if (conn)
        virConnectClose(conn);
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
    if (virAsprintf(&cmd, "config %s%d", dev, def->target.port) < 0) {
        virReportOOMError(conn);
        return -1;
    }
requery:
    if (umlMonitorCommand(NULL, driver, dom, cmd, &res) < 0)
        return -1;

    if (res && STRPREFIX(res, "pts:")) {
        VIR_FREE(def->data.file.path);
        if ((def->data.file.path = strdup(res + 4)) == NULL) {
            virReportOOMError(conn);
            VIR_FREE(res);
            VIR_FREE(cmd);
            return -1;
        }
    } else if (!res || STRPREFIX(res, "pts")) {
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

    umlDriverLock(driver);
    if (watch != driver->inotifyWatch)
        goto cleanup;

reread:
    got = read(fd, buf, sizeof(buf));
    if (got == -1) {
        if (errno == EINTR)
            goto reread;
        goto cleanup;
    }

    tmp = buf;
    while (got) {
        if (got < sizeof(struct inotify_event))
            goto cleanup; /* bad */

        e = (struct inotify_event *)tmp;
        tmp += sizeof(struct inotify_event);
        got -= sizeof(struct inotify_event);

        if (got < e->len)
            goto cleanup;

        tmp += e->len;
        got -= e->len;

        name = (char *)&(e->name);

        dom = virDomainFindByName(&driver->domains, name);

        if (!dom) {
            continue;
        }

        if (e->mask & IN_DELETE) {
            VIR_DEBUG("Got inotify domain shutdown '%s'", name);
            if (!virDomainObjIsActive(dom)) {
                virDomainObjUnlock(dom);
                continue;
            }

            umlShutdownVMDaemon(NULL, driver, dom);
        } else if (e->mask & (IN_CREATE | IN_MODIFY)) {
            VIR_DEBUG("Got inotify domain startup '%s'", name);
            if (virDomainObjIsActive(dom)) {
                virDomainObjUnlock(dom);
                continue;
            }

            if (umlReadPidFile(NULL, driver, dom) < 0) {
                virDomainObjUnlock(dom);
                continue;
            }

            dom->def->id = driver->nextvmid++;
            dom->state = VIR_DOMAIN_RUNNING;

            if (umlOpenMonitor(NULL, driver, dom) < 0) {
                VIR_WARN0("Could not open monitor for new domain");
                umlShutdownVMDaemon(NULL, driver, dom);
            } else if (umlIdentifyChrPTY(NULL, driver, dom) < 0) {
                VIR_WARN0("Could not identify charater devices for new domain");
                umlShutdownVMDaemon(NULL, driver, dom);
            }
        }
        virDomainObjUnlock(dom);
    }

cleanup:
    umlDriverUnlock(driver);
}

/**
 * umlStartup:
 *
 * Initialization function for the Uml daemon
 */
static int
umlStartup(int privileged) {
    uid_t uid = geteuid();
    char *base = NULL;
    char driverConf[PATH_MAX];
    char *userdir = NULL;

    if (VIR_ALLOC(uml_driver) < 0)
        return -1;

    uml_driver->privileged = privileged;

    if (virMutexInit(&uml_driver->lock) < 0) {
        VIR_FREE(uml_driver);
        return -1;
    }
    umlDriverLock(uml_driver);

    /* Don't have a dom0 so start from 1 */
    uml_driver->nextvmid = 1;
    uml_driver->inotifyWatch = -1;

    if (virDomainObjListInit(&uml_driver->domains) < 0)
        goto error;

    userdir = virGetUserDirectory(NULL, uid);
    if (!userdir)
        goto error;

    if (privileged) {
        if (virAsprintf(&uml_driver->logDir,
                        "%s/log/libvirt/uml", LOCAL_STATE_DIR) == -1)
            goto out_of_memory;

        if ((base = strdup (SYSCONF_DIR "/libvirt")) == NULL)
            goto out_of_memory;
    } else {

        if (virAsprintf(&uml_driver->logDir,
                        "%s/.libvirt/uml/log", userdir) == -1)
            goto out_of_memory;

        if (virAsprintf(&base, "%s/.libvirt", userdir) == -1)
            goto out_of_memory;
    }

    if (virAsprintf(&uml_driver->monitorDir,
                    "%s/.uml", userdir) == -1)
        goto out_of_memory;

    /* Configuration paths are either ~/.libvirt/uml/... (session) or
     * /etc/libvirt/uml/... (system).
     */
    if (snprintf (driverConf, sizeof(driverConf), "%s/uml.conf", base) == -1)
        goto out_of_memory;
    driverConf[sizeof(driverConf)-1] = '\0';

    if (virAsprintf(&uml_driver->configDir, "%s/uml", base) == -1)
        goto out_of_memory;

    if (virAsprintf(&uml_driver->autostartDir, "%s/uml/autostart", base) == -1)
        goto out_of_memory;

    VIR_FREE(base);

    if ((uml_driver->caps = umlCapsInit()) == NULL)
        goto out_of_memory;

    uml_driver->caps->privateDataAllocFunc = umlDomainObjPrivateAlloc;
    uml_driver->caps->privateDataFreeFunc = umlDomainObjPrivateFree;

    if ((uml_driver->inotifyFD = inotify_init()) < 0) {
        VIR_ERROR0(_("cannot initialize inotify"));
        goto error;
    }

    if (virFileMakePath(uml_driver->monitorDir) != 0) {
        char ebuf[1024];
        VIR_ERROR(_("Failed to create monitor directory %s: %s"),
               uml_driver->monitorDir, virStrerror(errno, ebuf, sizeof ebuf));
        goto error;
    }

    VIR_INFO("Adding inotify watch on %s", uml_driver->monitorDir);
    if (inotify_add_watch(uml_driver->inotifyFD,
                          uml_driver->monitorDir,
                          IN_CREATE | IN_MODIFY | IN_DELETE) < 0) {
        goto error;
    }

    if ((uml_driver->inotifyWatch =
         virEventAddHandle(uml_driver->inotifyFD, POLLIN,
                           umlInotifyEvent, uml_driver, NULL)) < 0)
        goto error;

    if (virDomainLoadAllConfigs(NULL,
                                uml_driver->caps,
                                &uml_driver->domains,
                                uml_driver->configDir,
                                uml_driver->autostartDir,
                                0, NULL, NULL) < 0)
        goto error;

    umlAutostartConfigs(uml_driver);

    umlDriverUnlock(uml_driver);
    VIR_FREE(userdir);

    return 0;

out_of_memory:
    VIR_ERROR0(_("umlStartup: out of memory"));

error:
    VIR_FREE(userdir);
    VIR_FREE(base);
    umlDriverUnlock(uml_driver);
    umlShutdown();
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

    umlDriverLock(uml_driver);
    virDomainLoadAllConfigs(NULL,
                            uml_driver->caps,
                            &uml_driver->domains,
                            uml_driver->configDir,
                            uml_driver->autostartDir,
                            0, NULL, NULL);

    umlAutostartConfigs(uml_driver);
    umlDriverUnlock(uml_driver);

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
    int active = 0;

    if (!uml_driver)
        return 0;

    umlDriverLock(uml_driver);
    active = virDomainObjListNumOfDomains(&uml_driver->domains, 1);
    umlDriverUnlock(uml_driver);

    return active;
}

static void
umlShutdownOneVM(void *payload, const char *name ATTRIBUTE_UNUSED, void *opaque)
{
    virDomainObjPtr dom = payload;
    struct uml_driver *driver = opaque;

    virDomainObjLock(dom);
    if (virDomainObjIsActive(dom))
        umlShutdownVMDaemon(NULL, driver, dom);
    virDomainObjUnlock(dom);
}

/**
 * umlShutdown:
 *
 * Shutdown the Uml daemon, it will stop all active domains and networks
 */
static int
umlShutdown(void) {
    if (!uml_driver)
        return -1;

    umlDriverLock(uml_driver);
    if (uml_driver->inotifyWatch != -1)
        virEventRemoveHandle(uml_driver->inotifyWatch);
    close(uml_driver->inotifyFD);
    virCapabilitiesFree(uml_driver->caps);

    /* shutdown active VMs
     * XXX allow them to stay around & reconnect */
    virHashForEach(uml_driver->domains.objs, umlShutdownOneVM, uml_driver);

    virDomainObjListDeinit(&uml_driver->domains);

    VIR_FREE(uml_driver->logDir);
    VIR_FREE(uml_driver->configDir);
    VIR_FREE(uml_driver->autostartDir);
    VIR_FREE(uml_driver->monitorDir);

    if (uml_driver->brctl)
        brShutdown(uml_driver->brctl);

    umlDriverUnlock(uml_driver);
    virMutexDestroy(&uml_driver->lock);
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
    if (virAsprintf(&pidfile, "%s/%s/pid",
                    driver->monitorDir, vm->def->name) < 0) {
        virReportOOMError(conn);
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
        fclose(file);
        goto cleanup;
    }

    if (fclose(file) < 0)
        goto cleanup;

    rc = 0;

 cleanup:
    if (rc != 0)
        virReportSystemError(conn, errno,
                             _("failed to read pid: %s"),
                             pidfile);
    VIR_FREE(pidfile);
    return rc;
}

static int umlMonitorAddress(virConnectPtr conn,
                             const struct uml_driver *driver,
                             virDomainObjPtr vm,
                             struct sockaddr_un *addr) {
    char *sockname;
    int retval = 0;

    if (virAsprintf(&sockname, "%s/%s/mconsole",
                    driver->monitorDir, vm->def->name) < 0) {
        virReportOOMError(conn);
        return -1;
    }

    memset(addr, 0, sizeof *addr);
    addr->sun_family = AF_UNIX;
    if (virStrcpyStatic(addr->sun_path, sockname) == NULL) {
        umlReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                       _("Unix path %s too long for destination"), sockname);
        retval = -1;
    }
    VIR_FREE(sockname);
    return retval;
}

static int umlOpenMonitor(virConnectPtr conn,
                          struct uml_driver *driver,
                          virDomainObjPtr vm) {
    struct sockaddr_un addr;
    struct stat sb;
    int retries = 0;
    umlDomainObjPrivatePtr priv = vm->privateData;

    if (umlMonitorAddress(conn, driver, vm, &addr) < 0)
        return -1;

    VIR_DEBUG("Dest address for monitor is '%s'", addr.sun_path);
restat:
    if (stat(addr.sun_path, &sb) < 0) {
        if (errno == ENOENT &&
            retries++ < 50) {
            usleep(1000 * 100);
            goto restat;
        }
        return -1;
    }

    if ((priv->monitor = socket(PF_UNIX, SOCK_DGRAM, 0)) < 0) {
        virReportSystemError(conn, errno,
                             "%s", _("cannot open socket"));
        return -1;
    }

    memset(addr.sun_path, 0, sizeof addr.sun_path);
    sprintf(addr.sun_path + 1, "libvirt-uml-%u", vm->pid);
    VIR_DEBUG("Reply address for monitor is '%s'", addr.sun_path+1);
    if (bind(priv->monitor, (struct sockaddr *)&addr, sizeof addr) < 0) {
        virReportSystemError(conn, errno,
                             "%s", _("cannot bind socket"));
        close(priv->monitor);
        priv->monitor = -1;
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
    umlDomainObjPrivatePtr priv = vm->privateData;

    VIR_DEBUG("Run command '%s'", cmd);

    *reply = NULL;

    if (umlMonitorAddress(conn, driver, vm, &addr) < 0)
        return -1;

    memset(&req, 0, sizeof(req));
    req.magic = MONITOR_MAGIC;
    req.version = MONITOR_VERSION;
    req.length = strlen(cmd);
    if (req.length > (MONITOR_BUFLEN-1)) {
        virReportSystemError(conn, EINVAL,
                             _("cannot send too long command %s (%d bytes)"),
                             cmd, req.length);
        return -1;
    }
    if (virStrcpyStatic(req.data, cmd) == NULL) {
        umlReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                       _("Command %s too long for destination"), cmd);
        return -1;
    }

    if (sendto(priv->monitor, &req, sizeof req, 0,
               (struct sockaddr *)&addr, sizeof addr) != (sizeof req)) {
        virReportSystemError(conn, errno,
                             _("cannot send command %s"),
                             cmd);
        return -1;
    }

    do {
        addrlen = sizeof(addr);
        if (recvfrom(priv->monitor, &res, sizeof res, 0,
                     (struct sockaddr *)&addr, &addrlen) < 0) {
            virReportSystemError(conn, errno,
                                 _("cannot read reply %s"),
                                 cmd);
            goto error;
        }

        if (VIR_REALLOC_N(retdata, retlen + res.length) < 0) {
            virReportOOMError(conn);
            goto error;
        }
        memcpy(retdata + retlen, res.data, res.length);
        retlen += res.length - 1;
        retdata[retlen] = '\0';

        if (res.error)
            ret = -1;

    } while (res.extra);

    VIR_DEBUG("Command reply is '%s'", NULLSTR(retdata));

    *reply = retdata;

    return ret;

error:
    VIR_FREE(retdata);
    return -1;
}


static int umlCleanupTapDevices(virConnectPtr conn ATTRIBUTE_UNUSED,
                                virDomainObjPtr vm) {
    int i;
    int err;
    int ret = 0;
    brControl *brctl = NULL;
    VIR_ERROR0("Cleanup tap");
    if (brInit(&brctl) < 0)
        return -1;

    for (i = 0 ; i < vm->def->nnets ; i++) {
        virDomainNetDefPtr def = vm->def->nets[i];

        if (def->type != VIR_DOMAIN_NET_TYPE_BRIDGE &&
            def->type != VIR_DOMAIN_NET_TYPE_NETWORK)
            continue;

        VIR_ERROR("Cleanup '%s'", def->ifname);
        err = brDeleteTap(brctl, def->ifname);
        if (err) {
            VIR_ERROR("Cleanup failed %d", err);
            ret = -1;
        }
    }
    VIR_ERROR0("Cleanup tap done");
    brShutdown(brctl);
    return ret;
}

static int umlStartVMDaemon(virConnectPtr conn,
                            struct uml_driver *driver,
                            virDomainObjPtr vm) {
    const char **argv = NULL, **tmp;
    const char **progenv = NULL;
    int i, ret;
    pid_t pid;
    char *logfile;
    int logfd = -1;
    struct stat sb;
    fd_set keepfd;
    char ebuf[1024];
    umlDomainObjPrivatePtr priv = vm->privateData;

    FD_ZERO(&keepfd);

    if (virDomainObjIsActive(vm)) {
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
        virReportSystemError(conn, errno,
                             _("Cannot find UML kernel %s"),
                             vm->def->os.kernel);
        return -1;
    }

    if (virFileMakePath(driver->logDir) != 0) {
        virReportSystemError(conn, errno,
                             _("cannot create log directory %s"),
                             driver->logDir);
        return -1;
    }

    if (virAsprintf(&logfile, "%s/%s.log",
                    driver->logDir, vm->def->name) < 0) {
        virReportOOMError(conn);
        return -1;
    }

    if ((logfd = open(logfile, O_CREAT | O_TRUNC | O_WRONLY,
                      S_IRUSR | S_IWUSR)) < 0) {
        virReportSystemError(conn, errno,
                             _("failed to create logfile %s"),
                             logfile);
        VIR_FREE(logfile);
        return -1;
    }
    VIR_FREE(logfile);

    if (umlSetCloseExec(logfd) < 0) {
        virReportSystemError(conn, errno,
                             "%s", _("Unable to set VM logfile close-on-exec flag"));
        close(logfd);
        return -1;
    }

    if (umlBuildCommandLine(conn, driver, vm,
                            &argv, &progenv) < 0) {
        close(logfd);
        umlCleanupTapDevices(conn, vm);
        return -1;
    }

    tmp = progenv;
    while (*tmp) {
        if (safewrite(logfd, *tmp, strlen(*tmp)) < 0)
            VIR_WARN(_("Unable to write envv to logfile: %s"),
                   virStrerror(errno, ebuf, sizeof ebuf));
        if (safewrite(logfd, " ", 1) < 0)
            VIR_WARN(_("Unable to write envv to logfile: %s"),
                   virStrerror(errno, ebuf, sizeof ebuf));
        tmp++;
    }
    tmp = argv;
    while (*tmp) {
        if (safewrite(logfd, *tmp, strlen(*tmp)) < 0)
            VIR_WARN(_("Unable to write argv to logfile: %s"),
                   virStrerror(errno, ebuf, sizeof ebuf));
        if (safewrite(logfd, " ", 1) < 0)
            VIR_WARN(_("Unable to write argv to logfile: %s"),
                   virStrerror(errno, ebuf, sizeof ebuf));
        tmp++;
    }
    if (safewrite(logfd, "\n", 1) < 0)
        VIR_WARN(_("Unable to write argv to logfile: %s"),
                 virStrerror(errno, ebuf, sizeof ebuf));

    priv->monitor = -1;

    ret = virExecDaemonize(conn, argv, progenv, &keepfd, &pid,
                           -1, &logfd, &logfd,
                           VIR_EXEC_CLEAR_CAPS,
                           NULL, NULL, NULL);
    close(logfd);

    for (i = 0 ; argv[i] ; i++)
        VIR_FREE(argv[i]);
    VIR_FREE(argv);

    for (i = 0 ; progenv[i] ; i++)
        VIR_FREE(progenv[i]);
    VIR_FREE(progenv);

    if (ret < 0)
        umlCleanupTapDevices(conn, vm);

    /* NB we don't mark it running here - we do that async
       with inotify */
    /* XXX what if someone else tries to start it again
       before we get the inotification ? Sounds like
       trouble.... */

    return ret;
}

static void umlShutdownVMDaemon(virConnectPtr conn ATTRIBUTE_UNUSED,
                                struct uml_driver *driver ATTRIBUTE_UNUSED,
                                virDomainObjPtr vm)
{
    int ret;
    umlDomainObjPrivatePtr priv = vm->privateData;

    if (!virDomainObjIsActive(vm))
        return;

    virKillProcess(vm->pid, SIGTERM);

    if (priv->monitor != -1)
        close(priv->monitor);
    priv->monitor = -1;

    if ((ret = waitpid(vm->pid, NULL, 0)) != vm->pid) {
        VIR_WARN(_("Got unexpected pid %d != %d"),
               ret, vm->pid);
    }

    vm->pid = -1;
    vm->def->id = -1;
    vm->state = VIR_DOMAIN_SHUTOFF;

    umlCleanupTapDevices(conn, vm);

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
    if (conn->uri == NULL) {
        if (uml_driver == NULL)
            return VIR_DRV_OPEN_DECLINED;

        conn->uri = xmlParseURI(uml_driver->privileged ?
                                "uml:///system" :
                                "uml:///session");
        if (!conn->uri) {
            virReportOOMError(conn);
            return VIR_DRV_OPEN_ERROR;
        }
    } else {
        if (conn->uri->scheme == NULL ||
            STRNEQ (conn->uri->scheme, "uml"))
            return VIR_DRV_OPEN_DECLINED;

        /* Allow remote driver to deal with URIs with hostname server */
        if (conn->uri->server != NULL)
            return VIR_DRV_OPEN_DECLINED;


        /* Check path and tell them correct path if they made a mistake */
        if (uml_driver->privileged) {
            if (STRNEQ (conn->uri->path, "/system") &&
                STRNEQ (conn->uri->path, "/session")) {
                umlReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                               _("unexpected UML URI path '%s', try uml:///system"),
                               conn->uri->path);
                return VIR_DRV_OPEN_ERROR;
            }
        } else {
            if (STRNEQ (conn->uri->path, "/session")) {
                umlReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                               _("unexpected UML URI path '%s', try uml:///session"),
                               conn->uri->path);
                return VIR_DRV_OPEN_ERROR;
            }
        }

        /* URI was good, but driver isn't active */
        if (uml_driver == NULL) {
            umlReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR, "%s",
                           _("uml state driver is not active"));
            return VIR_DRV_OPEN_ERROR;
        }
    }

    conn->privateData = uml_driver;

    return VIR_DRV_OPEN_SUCCESS;
}

static int umlClose(virConnectPtr conn) {
    /*struct uml_driver *driver = conn->privateData;*/

    conn->privateData = NULL;

    return 0;
}

static const char *umlGetType(virConnectPtr conn ATTRIBUTE_UNUSED) {
    return "UML";
}


static int umlIsSecure(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    /* Trivially secure, since always inside the daemon */
    return 1;
}


static int umlIsEncrypted(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    /* Not encrypted, but remote driver takes care of that */
    return 0;
}


static char *umlGetCapabilities(virConnectPtr conn) {
    struct uml_driver *driver = (struct uml_driver *)conn->privateData;
    char *xml;

    umlDriverLock(driver);
    if ((xml = virCapabilitiesFormatXML(driver->caps)) == NULL)
        virReportOOMError(conn);
    umlDriverUnlock(driver);

    return xml;
}



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
        fclose(pidinfo);
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
    virDomainObjPtr vm;
    virDomainPtr dom = NULL;

    umlDriverLock(driver);
    vm = virDomainFindByID(&driver->domains, id);
    umlDriverUnlock(driver);

    if (!vm) {
        umlReportError(conn, NULL, NULL, VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom) dom->id = vm->def->id;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return dom;
}

static virDomainPtr umlDomainLookupByUUID(virConnectPtr conn,
                                            const unsigned char *uuid) {
    struct uml_driver *driver = (struct uml_driver *)conn->privateData;
    virDomainObjPtr vm;
    virDomainPtr dom = NULL;

    umlDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, uuid);
    umlDriverUnlock(driver);

    if (!vm) {
        umlReportError(conn, NULL, NULL, VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom) dom->id = vm->def->id;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return dom;
}

static virDomainPtr umlDomainLookupByName(virConnectPtr conn,
                                            const char *name) {
    struct uml_driver *driver = (struct uml_driver *)conn->privateData;
    virDomainObjPtr vm;
    virDomainPtr dom = NULL;

    umlDriverLock(driver);
    vm = virDomainFindByName(&driver->domains, name);
    umlDriverUnlock(driver);

    if (!vm) {
        umlReportError(conn, NULL, NULL, VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom) dom->id = vm->def->id;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return dom;
}


static int umlDomainIsActive(virDomainPtr dom)
{
    struct uml_driver *driver = dom->conn->privateData;
    virDomainObjPtr obj;
    int ret = -1;

    umlDriverLock(driver);
    obj = virDomainFindByUUID(&driver->domains, dom->uuid);
    umlDriverUnlock(driver);
    if (!obj) {
        umlReportError(dom->conn, NULL, NULL, VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }
    ret = virDomainObjIsActive(obj);

cleanup:
    if (obj)
        virDomainObjUnlock(obj);
    return ret;
}


static int umlDomainIsPersistent(virDomainPtr dom)
{
    struct uml_driver *driver = dom->conn->privateData;
    virDomainObjPtr obj;
    int ret = -1;

    umlDriverLock(driver);
    obj = virDomainFindByUUID(&driver->domains, dom->uuid);
    umlDriverUnlock(driver);
    if (!obj) {
        umlReportError(dom->conn, NULL, NULL, VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }
    ret = obj->persistent;

cleanup:
    if (obj)
        virDomainObjUnlock(obj);
    return ret;
}


static int umlGetVersion(virConnectPtr conn, unsigned long *version) {
    struct uml_driver *driver = conn->privateData;
    struct utsname ut;
    int major, minor, micro;
    int ret = -1;

    uname(&ut);

    umlDriverLock(driver);
    if (sscanf(ut.release, "%u.%u.%u",
               &major, &minor, &micro) != 3) {
        umlReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                       _("cannot parse version %s"), ut.release);
        goto cleanup;
    }

    *version = driver->umlVersion;
    ret = 0;

cleanup:
    umlDriverUnlock(driver);
    return ret;
}

static int umlListDomains(virConnectPtr conn, int *ids, int nids) {
    struct uml_driver *driver = conn->privateData;
    int n;

    umlDriverLock(driver);
    n = virDomainObjListGetActiveIDs(&driver->domains, ids, nids);
    umlDriverUnlock(driver);

    return n;
}
static int umlNumDomains(virConnectPtr conn) {
    struct uml_driver *driver = conn->privateData;
    int n;

    umlDriverLock(driver);
    n = virDomainObjListNumOfDomains(&driver->domains, 1);
    umlDriverUnlock(driver);

    return n;
}
static virDomainPtr umlDomainCreate(virConnectPtr conn, const char *xml,
                                      unsigned int flags ATTRIBUTE_UNUSED) {
    struct uml_driver *driver = conn->privateData;
    virDomainDefPtr def;
    virDomainObjPtr vm = NULL;
    virDomainPtr dom = NULL;

    umlDriverLock(driver);
    if (!(def = virDomainDefParseString(conn, driver->caps, xml,
                                        VIR_DOMAIN_XML_INACTIVE)))
        goto cleanup;

    if (virDomainObjIsDuplicate(&driver->domains, def, 1) < 0)
        goto cleanup;

    if (!(vm = virDomainAssignDef(conn,
                                  driver->caps,
                                  &driver->domains,
                                  def)))
        goto cleanup;
    def = NULL;

    if (umlStartVMDaemon(conn, driver, vm) < 0) {
        virDomainRemoveInactive(&driver->domains,
                                vm);
        vm = NULL;
        goto cleanup;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom) dom->id = vm->def->id;

cleanup:
    virDomainDefFree(def);
    if (vm)
        virDomainObjUnlock(vm);
    umlDriverUnlock(driver);
    return dom;
}


static int umlDomainShutdown(virDomainPtr dom) {
    struct uml_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    char *info = NULL;
    int ret = -1;

    umlDriverLock(driver);
    vm = virDomainFindByID(&driver->domains, dom->id);
    umlDriverUnlock(driver);
    if (!vm) {
        umlReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         _("no domain with matching id %d"), dom->id);
        goto cleanup;
    }

#if 0
    if (umlMonitorCommand(driver, vm, "system_powerdown", &info) < 0) {
        umlReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                         "%s", _("shutdown operation failed"));
        goto cleanup;
    }
    ret = 0;
#endif

cleanup:
    VIR_FREE(info);
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}


static int umlDomainDestroy(virDomainPtr dom) {
    struct uml_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;

    umlDriverLock(driver);
    vm = virDomainFindByID(&driver->domains, dom->id);
    if (!vm) {
        umlReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         _("no domain with matching id %d"), dom->id);
        goto cleanup;
    }

    umlShutdownVMDaemon(dom->conn, driver, vm);
    if (!vm->persistent) {
        virDomainRemoveInactive(&driver->domains,
                                vm);
        vm = NULL;
    }
    ret = 0;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    umlDriverUnlock(driver);
    return ret;
}


static char *umlDomainGetOSType(virDomainPtr dom) {
    struct uml_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    char *type = NULL;

    umlDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    umlDriverUnlock(driver);
    if (!vm) {
        umlReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         "%s", _("no domain with matching uuid"));
        goto cleanup;
    }

    if (!(type = strdup(vm->def->os.type)))
        virReportOOMError(dom->conn);

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return type;
}

/* Returns max memory in kb, 0 if error */
static unsigned long umlDomainGetMaxMemory(virDomainPtr dom) {
    struct uml_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    unsigned long ret = 0;

    umlDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    umlDriverUnlock(driver);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];

        virUUIDFormat(dom->uuid, uuidstr);
        umlReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                       _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }
    ret = vm->def->maxmem;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}

static int umlDomainSetMaxMemory(virDomainPtr dom, unsigned long newmax) {
    struct uml_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;

    umlDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    umlDriverUnlock(driver);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];

        virUUIDFormat(dom->uuid, uuidstr);
        umlReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (newmax < vm->def->memory) {
        umlReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_ARG,
                         "%s", _("cannot set max memory lower than current memory"));
        goto cleanup;
    }

    vm->def->maxmem = newmax;
    ret = 0;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}

static int umlDomainSetMemory(virDomainPtr dom, unsigned long newmem) {
    struct uml_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;

    umlDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    umlDriverUnlock(driver);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];

        virUUIDFormat(dom->uuid, uuidstr);
        umlReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (virDomainObjIsActive(vm)) {
        umlReportError(dom->conn, dom, NULL, VIR_ERR_NO_SUPPORT,
                         "%s", _("cannot set memory of an active domain"));
        goto cleanup;
    }

    if (newmem > vm->def->maxmem) {
        umlReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_ARG,
                         "%s", _("cannot set memory higher than max memory"));
        goto cleanup;
    }

    vm->def->memory = newmem;
    ret = 0;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}

static int umlDomainGetInfo(virDomainPtr dom,
                              virDomainInfoPtr info) {
    struct uml_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;

    umlDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    umlDriverUnlock(driver);

    if (!vm) {
        umlReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                       "%s", _("no domain with matching uuid"));
        goto cleanup;
    }

    info->state = vm->state;

    if (!virDomainObjIsActive(vm)) {
        info->cpuTime = 0;
    } else {
        if (umlGetProcessInfo(&(info->cpuTime), vm->pid) < 0) {
            umlReportError(dom->conn, dom, NULL, VIR_ERR_OPERATION_FAILED,
                           "%s", _("cannot read cputime for domain"));
            goto cleanup;
        }
    }

    info->maxMem = vm->def->maxmem;
    info->memory = vm->def->memory;
    info->nrVirtCpu = vm->def->vcpus;
    ret = 0;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}


static char *umlDomainDumpXML(virDomainPtr dom,
                                int flags ATTRIBUTE_UNUSED) {
    struct uml_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    char *ret = NULL;

    umlDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    umlDriverUnlock(driver);

    if (!vm) {
        umlReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         "%s", _("no domain with matching uuid"));
        goto cleanup;
    }

    ret = virDomainDefFormat(dom->conn,
                             (flags & VIR_DOMAIN_XML_INACTIVE) && vm->newDef ?
                             vm->newDef : vm->def,
                             flags);

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}


static int umlListDefinedDomains(virConnectPtr conn,
                            char **const names, int nnames) {
    struct uml_driver *driver = conn->privateData;
    int n;

    umlDriverLock(driver);
    n = virDomainObjListGetInactiveNames(&driver->domains, names, nnames);
    umlDriverUnlock(driver);

    return n;
}

static int umlNumDefinedDomains(virConnectPtr conn) {
    struct uml_driver *driver = conn->privateData;
    int n;

    umlDriverLock(driver);
    n = virDomainObjListNumOfDomains(&driver->domains, 0);
    umlDriverUnlock(driver);

    return n;
}


static int umlDomainStart(virDomainPtr dom) {
    struct uml_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;

    umlDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);

    if (!vm) {
        umlReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         "%s", _("no domain with matching uuid"));
        goto cleanup;
    }

    ret = umlStartVMDaemon(dom->conn, driver, vm);

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    umlDriverUnlock(driver);
    return ret;
}


static virDomainPtr umlDomainDefine(virConnectPtr conn, const char *xml) {
    struct uml_driver *driver = conn->privateData;
    virDomainDefPtr def;
    virDomainObjPtr vm = NULL;
    virDomainPtr dom = NULL;

    umlDriverLock(driver);
    if (!(def = virDomainDefParseString(conn, driver->caps, xml,
                                        VIR_DOMAIN_XML_INACTIVE)))
        goto cleanup;

    if (virDomainObjIsDuplicate(&driver->domains, def, 0) < 0)
        goto cleanup;

    if (!(vm = virDomainAssignDef(conn,
                                  driver->caps,
                                  &driver->domains,
                                  def)))
        goto cleanup;
    def = NULL;
    vm->persistent = 1;

    if (virDomainSaveConfig(conn,
                            driver->configDir,
                            vm->newDef ? vm->newDef : vm->def) < 0) {
        virDomainRemoveInactive(&driver->domains,
                                vm);
        vm = NULL;
        goto cleanup;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom) dom->id = vm->def->id;

cleanup:
    virDomainDefFree(def);
    if (vm)
        virDomainObjUnlock(vm);
    umlDriverUnlock(driver);
    return dom;
}

static int umlDomainUndefine(virDomainPtr dom) {
    struct uml_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;

    umlDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    if (!vm) {
        umlReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         "%s", _("no domain with matching uuid"));
        goto cleanup;
    }

    if (virDomainObjIsActive(vm)) {
        umlReportError(dom->conn, dom, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("cannot delete active domain"));
        goto cleanup;
    }

    if (!vm->persistent) {
        umlReportError(dom->conn, dom, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("cannot undefine transient domain"));
        goto cleanup;
    }

    if (virDomainDeleteConfig(dom->conn, driver->configDir, driver->autostartDir, vm) < 0)
        goto cleanup;

    virDomainRemoveInactive(&driver->domains,
                            vm);
    vm = NULL;
    ret = 0;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    umlDriverUnlock(driver);
    return ret;
}



static int umlDomainGetAutostart(virDomainPtr dom,
                            int *autostart) {
    struct uml_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;

    umlDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);

    if (!vm) {
        umlReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         "%s", _("no domain with matching uuid"));
        goto cleanup;
    }

    *autostart = vm->autostart;
    ret = 0;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    umlDriverUnlock(driver);
    return ret;
}

static int umlDomainSetAutostart(virDomainPtr dom,
                                   int autostart) {
    struct uml_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    char *configFile = NULL, *autostartLink = NULL;
    int ret = -1;

    umlDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);

    if (!vm) {
        umlReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                         "%s", _("no domain with matching uuid"));
        goto cleanup;
    }

    if (!vm->persistent) {
        umlReportError(dom->conn, dom, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("cannot set autostart for transient domain"));
        goto cleanup;
    }

    autostart = (autostart != 0);

    if (vm->autostart != autostart) {
        if ((configFile = virDomainConfigFile(dom->conn, driver->configDir, vm->def->name)) == NULL)
            goto cleanup;
        if ((autostartLink = virDomainConfigFile(dom->conn, driver->autostartDir, vm->def->name)) == NULL)
            goto cleanup;

        if (autostart) {
            int err;

            if ((err = virFileMakePath(driver->autostartDir))) {
                virReportSystemError(dom->conn, err,
                                     _("cannot create autostart directory %s"),
                                     driver->autostartDir);
                goto cleanup;
            }

            if (symlink(configFile, autostartLink) < 0) {
                virReportSystemError(dom->conn, errno,
                                     _("Failed to create symlink '%s to '%s'"),
                                     autostartLink, configFile);
                goto cleanup;
            }
        } else {
            if (unlink(autostartLink) < 0 && errno != ENOENT && errno != ENOTDIR) {
                virReportSystemError(dom->conn, errno,
                                     _("Failed to delete symlink '%s'"),
                                     autostartLink);
                goto cleanup;
            }
        }

        vm->autostart = autostart;
    }
    ret = 0;

cleanup:
    VIR_FREE(configFile);
    VIR_FREE(autostartLink);
    if (vm)
        virDomainObjUnlock(vm);
    umlDriverUnlock(driver);
    return ret;
}


static int
umlDomainBlockPeek (virDomainPtr dom,
                      const char *path,
                      unsigned long long offset, size_t size,
                      void *buffer,
                      unsigned int flags ATTRIBUTE_UNUSED)
{
    struct uml_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int fd = -1, ret = -1, i;

    umlDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    umlDriverUnlock(driver);

    if (!vm) {
        umlReportError (dom->conn, dom, NULL, VIR_ERR_INVALID_DOMAIN,
                        "%s", _("no domain with matching uuid"));
        goto cleanup;
    }

    if (!path || path[0] == '\0') {
        umlReportError(dom->conn, dom, NULL, VIR_ERR_INVALID_ARG,
                       "%s", _("NULL or empty path"));
        goto cleanup;
    }

    /* Check the path belongs to this domain. */
    for (i = 0 ; i < vm->def->ndisks ; i++) {
        if (vm->def->disks[i]->src != NULL &&
            STREQ (vm->def->disks[i]->src, path)) {
            ret = 0;
            break;
        }
    }

    if (ret == 0) {
        ret = -1;
        /* The path is correct, now try to open it and get its size. */
        fd = open (path, O_RDONLY);
        if (fd == -1) {
            virReportSystemError(dom->conn, errno,
                                 _("cannot open %s"), path);
            goto cleanup;
        }

        /* Seek and read. */
        /* NB. Because we configure with AC_SYS_LARGEFILE, off_t should
         * be 64 bits on all platforms.
         */
        if (lseek (fd, offset, SEEK_SET) == (off_t) -1 ||
            saferead (fd, buffer, size) == (ssize_t) -1) {
            virReportSystemError(dom->conn, errno,
                                 _("cannot read %s"), path);
            goto cleanup;
        }

        ret = 0;
    } else {
        umlReportError (dom->conn, dom, NULL, VIR_ERR_INVALID_ARG,
                        "%s", _("invalid path"));
    }

cleanup:
    if (fd >= 0) close (fd);
    if (vm)
        virDomainObjUnlock(vm);
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
    NULL, /* libvirtVersion (impl. in libvirt.c) */
    virGetHostname, /* getHostname */
    NULL, /* getMaxVcpus */
    nodeGetInfo, /* nodeGetInfo */
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
    NULL, /* domainGetSecurityLabel */
    NULL, /* nodeGetSecurityModel */
    umlDomainDumpXML, /* domainDumpXML */
    NULL, /* domainXMLFromNative */
    NULL, /* domainXMLToNative */
    umlListDefinedDomains, /* listDefinedDomains */
    umlNumDefinedDomains, /* numOfDefinedDomains */
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
    NULL, /* domainMemoryStats */
    umlDomainBlockPeek, /* domainBlockPeek */
    NULL, /* domainMemoryPeek */
    nodeGetCellsFreeMemory, /* nodeGetCellsFreeMemory */
    nodeGetFreeMemory,  /* getFreeMemory */
    NULL, /* domainEventRegister */
    NULL, /* domainEventDeregister */
    NULL, /* domainMigratePrepare2 */
    NULL, /* domainMigrateFinish2 */
    NULL, /* nodeDeviceDettach */
    NULL, /* nodeDeviceReAttach */
    NULL, /* nodeDeviceReset */
    NULL, /* domainMigratePrepareTunnel */
    umlIsEncrypted,
    umlIsSecure,
    umlDomainIsActive,
    umlDomainIsPersistent,
    NULL, /* cpuCompare */
};


static virStateDriver umlStateDriver = {
    .name = "UML",
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
