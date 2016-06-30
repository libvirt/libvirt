/*
 * bhyve_process.c: bhyve process management
 *
 * Copyright (C) 2014 Roman Bogorodskiy
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
 *
 */

#include <config.h>

#include <fcntl.h>
#include <kvm.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_tap.h>

#include "bhyve_device.h"
#include "bhyve_driver.h"
#include "bhyve_command.h"
#include "bhyve_monitor.h"
#include "bhyve_process.h"
#include "datatypes.h"
#include "virerror.h"
#include "virlog.h"
#include "virfile.h"
#include "viralloc.h"
#include "vircommand.h"
#include "virstring.h"
#include "virpidfile.h"
#include "virprocess.h"
#include "virnetdev.h"
#include "virnetdevbridge.h"
#include "virnetdevtap.h"

#define VIR_FROM_THIS	VIR_FROM_BHYVE

VIR_LOG_INIT("bhyve.bhyve_process");

static virDomainObjPtr
bhyveProcessAutoDestroy(virDomainObjPtr vm,
                        virConnectPtr conn ATTRIBUTE_UNUSED,
                        void *opaque)
{
    bhyveConnPtr driver = opaque;

    virBhyveProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_DESTROYED);

    if (!vm->persistent) {
        virDomainObjListRemove(driver->domains, vm);
        vm = NULL;
    }

    return vm;
}

static void
bhyveNetCleanup(virDomainObjPtr vm)
{
    size_t i;

    for (i = 0; i < vm->def->nnets; i++) {
        virDomainNetDefPtr net = vm->def->nets[i];
        virDomainNetType actualType = virDomainNetGetActualType(net);

        if (actualType == VIR_DOMAIN_NET_TYPE_BRIDGE) {
            if (net->ifname) {
                ignore_value(virNetDevBridgeRemovePort(
                                virDomainNetGetActualBridgeName(net),
                                net->ifname));
                ignore_value(virNetDevTapDelete(net->ifname, NULL));
            }
        }
    }
}

static int
virBhyveFormatDevMapFile(const char *vm_name, char **fn_out)
{

    return virAsprintf(fn_out, "%s/grub_bhyve-%s-device.map", BHYVE_STATE_DIR,
                       vm_name);
}

int
virBhyveProcessStart(virConnectPtr conn,
                     bhyveConnPtr driver,
                     virDomainObjPtr vm,
                     virDomainRunningReason reason,
                     unsigned int flags)
{
    char *devmap_file = NULL;
    char *devicemap = NULL;
    char *logfile = NULL;
    int logfd = -1;
    off_t pos = -1;
    char ebuf[1024];
    virCommandPtr cmd = NULL;
    virCommandPtr load_cmd = NULL;
    bhyveConnPtr privconn = conn->privateData;
    bhyveDomainObjPrivatePtr priv = vm->privateData;
    int ret = -1, rc;
    virCapsPtr caps = NULL;

    if (virAsprintf(&logfile, "%s/%s.log",
                    BHYVE_LOG_DIR, vm->def->name) < 0)
       return -1;

    caps = bhyveDriverGetCapabilities(privconn);
    if (!caps)
        goto cleanup;

    if ((logfd = open(logfile, O_WRONLY | O_APPEND | O_CREAT,
                      S_IRUSR | S_IWUSR)) < 0) {
        virReportSystemError(errno,
                             _("Failed to open '%s'"),
                             logfile);
        goto cleanup;
    }

    VIR_FREE(privconn->pidfile);
    if (!(privconn->pidfile = virPidFileBuildPath(BHYVE_STATE_DIR,
                                                  vm->def->name))) {
        virReportSystemError(errno,
                             "%s", _("Failed to build pidfile path"));
        goto cleanup;
    }

    if (unlink(privconn->pidfile) < 0 &&
        errno != ENOENT) {
        virReportSystemError(errno,
                             _("Cannot remove state PID file %s"),
                             privconn->pidfile);
        goto cleanup;
    }

    if (bhyveDomainAssignAddresses(vm->def, NULL) < 0)
        goto cleanup;

    /* Call bhyve to start the VM */
    if (!(cmd = virBhyveProcessBuildBhyveCmd(conn,
                                             vm->def,
                                             false)))
        goto cleanup;

    virCommandSetOutputFD(cmd, &logfd);
    virCommandSetErrorFD(cmd, &logfd);
    virCommandWriteArgLog(cmd, logfd);
    virCommandSetPidFile(cmd, privconn->pidfile);
    virCommandDaemonize(cmd);

    if (vm->def->os.loader == NULL) {
        /* Now bhyve command is constructed, meaning the
         * domain is ready to be started, so we can build
         * and execute bhyveload command */

        rc = virBhyveFormatDevMapFile(vm->def->name, &devmap_file);
        if (rc < 0)
            goto cleanup;

        if (!(load_cmd = virBhyveProcessBuildLoadCmd(conn, vm->def, devmap_file,
                                                     &devicemap)))
            goto cleanup;
        virCommandSetOutputFD(load_cmd, &logfd);
        virCommandSetErrorFD(load_cmd, &logfd);

        if (devicemap != NULL) {
            rc = virFileWriteStr(devmap_file, devicemap, 0644);
            if (rc) {
                virReportSystemError(errno,
                                     _("Cannot write device.map '%s'"),
                                     devmap_file);
                goto cleanup;
            }
        }

        /* Log generated command line */
        virCommandWriteArgLog(load_cmd, logfd);
        if ((pos = lseek(logfd, 0, SEEK_END)) < 0)
            VIR_WARN("Unable to seek to end of logfile: %s",
                     virStrerror(errno, ebuf, sizeof(ebuf)));

        VIR_DEBUG("Loading domain '%s'", vm->def->name);
        if (virCommandRun(load_cmd, NULL) < 0)
            goto cleanup;
    }

    /* Now we can start the domain */
    VIR_DEBUG("Starting domain '%s'", vm->def->name);
    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    if (virPidFileReadPath(privconn->pidfile, &vm->pid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Domain %s didn't show up"), vm->def->name);
        goto cleanup;
    }

    if (flags & VIR_BHYVE_PROCESS_START_AUTODESTROY &&
        virCloseCallbacksSet(driver->closeCallbacks, vm,
                             conn, bhyveProcessAutoDestroy) < 0)
        goto cleanup;

    vm->def->id = vm->pid;
    virDomainObjSetState(vm, VIR_DOMAIN_RUNNING, reason);
    priv->mon = bhyveMonitorOpen(vm, driver);

    if (virDomainSaveStatus(driver->xmlopt,
                            BHYVE_STATE_DIR,
                            vm, caps) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virObjectUnref(caps);
    if (devicemap != NULL) {
        rc = unlink(devmap_file);
        if (rc < 0 && errno != ENOENT)
            virReportSystemError(errno, _("cannot unlink file '%s'"),
                                 devmap_file);
        VIR_FREE(devicemap);
    }
    VIR_FREE(devmap_file);

    if (ret < 0) {
        int exitstatus; /* Needed to avoid logging non-zero status */
        virCommandPtr destroy_cmd;
        if ((destroy_cmd = virBhyveProcessBuildDestroyCmd(driver,
                                                          vm->def)) != NULL) {
            virCommandSetOutputFD(load_cmd, &logfd);
            virCommandSetErrorFD(load_cmd, &logfd);
            ignore_value(virCommandRun(destroy_cmd, &exitstatus));
            virCommandFree(destroy_cmd);
        }

        bhyveNetCleanup(vm);
    }

    virCommandFree(load_cmd);
    virCommandFree(cmd);
    VIR_FREE(logfile);
    VIR_FORCE_CLOSE(logfd);
    return ret;
}

int
virBhyveProcessStop(bhyveConnPtr driver,
                    virDomainObjPtr vm,
                    virDomainShutoffReason reason)
{
    int ret = -1;
    virCommandPtr cmd = NULL;
    bhyveDomainObjPrivatePtr priv = vm->privateData;

    if (!virDomainObjIsActive(vm)) {
        VIR_DEBUG("VM '%s' not active", vm->def->name);
        return 0;
    }

    if (vm->pid <= 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid PID %d for VM"),
                       (int)vm->pid);
        return -1;
    }

    if (!(cmd = virBhyveProcessBuildDestroyCmd(driver, vm->def)))
        return -1;

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    if ((priv != NULL) && (priv->mon != NULL))
         bhyveMonitorClose(priv->mon);

    /* Cleanup network interfaces */
    bhyveNetCleanup(vm);

    ret = 0;

    virCloseCallbacksUnset(driver->closeCallbacks, vm,
                           bhyveProcessAutoDestroy);

    virDomainObjSetState(vm, VIR_DOMAIN_SHUTOFF, reason);
    vm->pid = -1;
    vm->def->id = -1;

 cleanup:
    virCommandFree(cmd);

    virPidFileDelete(BHYVE_STATE_DIR, vm->def->name);
    virDomainDeleteConfig(BHYVE_STATE_DIR, NULL, vm);

    return ret;
}

int
virBhyveProcessShutdown(virDomainObjPtr vm)
{
    if (vm->pid <= 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid PID %d for VM"),
                       (int)vm->pid);
        return -1;
    }

    /* Bhyve tries to perform ACPI shutdown when it receives
     * SIGTERM signal. So we just issue SIGTERM here and rely
     * on the bhyve monitor to clean things up if process disappears.
     */
    if (virProcessKill(vm->pid, SIGTERM) != 0) {
        VIR_WARN("Failed to terminate bhyve process for VM '%s': %s",
                 vm->def->name, virGetLastErrorMessage());
        return -1;
    }

    return 0;
}

int
virBhyveGetDomainTotalCpuStats(virDomainObjPtr vm,
                               unsigned long long *cpustats)
{
    struct kinfo_proc *kp;
    kvm_t *kd;
    char errbuf[_POSIX2_LINE_MAX];
    int nprocs;
    int ret = -1;

    if ((kd = kvm_openfiles(NULL, NULL, NULL, O_RDONLY, errbuf)) == NULL) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("Unable to get kvm descriptor: %s"),
                       errbuf);
        return -1;

    }

    kp = kvm_getprocs(kd, KERN_PROC_PID, vm->pid, &nprocs);
    if (kp == NULL || nprocs != 1) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("Unable to obtain information about pid: %d"),
                       (int)vm->pid);
        goto cleanup;
    }

    *cpustats = kp->ki_runtime * 1000ull;

    ret = 0;

 cleanup:
    kvm_close(kd);

    return ret;
}

struct bhyveProcessReconnectData {
    bhyveConnPtr driver;
    kvm_t *kd;
};

static int
virBhyveProcessReconnect(virDomainObjPtr vm,
                         void *opaque)
{
    struct bhyveProcessReconnectData *data = opaque;
    struct kinfo_proc *kp;
    int nprocs;
    char **proc_argv;
    char *expected_proctitle = NULL;
    bhyveDomainObjPrivatePtr priv = vm->privateData;
    int ret = -1;
    virCapsPtr caps = NULL;

    if (!virDomainObjIsActive(vm))
        return 0;

    if (!vm->pid)
        return 0;

    caps = bhyveDriverGetCapabilities(data->driver);
    if (!caps)
        return -1;

    virObjectLock(vm);

    kp = kvm_getprocs(data->kd, KERN_PROC_PID, vm->pid, &nprocs);
    if (kp == NULL || nprocs != 1)
        goto cleanup;

    if (virAsprintf(&expected_proctitle, "bhyve: %s", vm->def->name) < 0)
        goto cleanup;

    proc_argv = kvm_getargv(data->kd, kp, 0);
    if (proc_argv && proc_argv[0]) {
         if (STREQ(expected_proctitle, proc_argv[0])) {
             ret = 0;
             priv->mon = bhyveMonitorOpen(vm, data->driver);
         }
    }

 cleanup:
    if (ret < 0) {
        /* If VM is reported to be in active state, but we cannot find
         * its PID, then we clear information about the PID and
         * set state to 'shutdown' */
        vm->pid = 0;
        vm->def->id = -1;
        virDomainObjSetState(vm, VIR_DOMAIN_SHUTOFF,
                             VIR_DOMAIN_SHUTOFF_UNKNOWN);
        ignore_value(virDomainSaveStatus(data->driver->xmlopt,
                                         BHYVE_STATE_DIR,
                                         vm, caps));
    }

    virObjectUnref(caps);
    virObjectUnlock(vm);
    VIR_FREE(expected_proctitle);

    return ret;
}

void
virBhyveProcessReconnectAll(bhyveConnPtr driver)
{
    kvm_t *kd;
    struct bhyveProcessReconnectData data;
    char errbuf[_POSIX2_LINE_MAX];

    if ((kd = kvm_openfiles(NULL, NULL, NULL, O_RDONLY, errbuf)) == NULL) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("Unable to get kvm descriptor: %s"),
                       errbuf);
        return;

    }

    data.driver = driver;
    data.kd = kd;

    virDomainObjListForEach(driver->domains, virBhyveProcessReconnect, &data);

    kvm_close(kd);
}
