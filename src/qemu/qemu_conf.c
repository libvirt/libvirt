/*
 * qemu_conf.c: QEMU configuration management
 *
 * Copyright (C) 2006, 2007, 2008, 2009, 2010 Red Hat, Inc.
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

#include <dirent.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <sys/utsname.h>
#include <mntent.h>

#include "virterror_internal.h"
#include "qemu_conf.h"
#include "qemu_capabilities.h"
#include "qemu_bridge_filter.h"
#include "uuid.h"
#include "buf.h"
#include "conf.h"
#include "util.h"
#include "memory.h"
#include "verify.h"
#include "datatypes.h"
#include "xml.h"
#include "nodeinfo.h"
#include "logging.h"
#include "network.h"
#include "macvtap.h"
#include "cpu/cpu.h"
#include "domain_nwfilter.h"
#include "files.h"
#include "configmake.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

void qemuDriverLock(struct qemud_driver *driver)
{
    virMutexLock(&driver->lock);
}
void qemuDriverUnlock(struct qemud_driver *driver)
{
    virMutexUnlock(&driver->lock);
}


int qemudLoadDriverConfig(struct qemud_driver *driver,
                          const char *filename) {
    virConfPtr conf;
    virConfValuePtr p;
    char *user;
    char *group;
    int i;

    /* Setup critical defaults */
    driver->dynamicOwnership = 1;
    driver->clearEmulatorCapabilities = 1;

    if (!(driver->vncListen = strdup("127.0.0.1"))) {
        virReportOOMError();
        return -1;
    }
    if (!(driver->vncTLSx509certdir = strdup(SYSCONFDIR "/pki/libvirt-vnc"))) {
        virReportOOMError();
        return -1;
    }

    if (!(driver->spiceListen = strdup("127.0.0.1"))) {
        virReportOOMError();
        return -1;
    }
    if (!(driver->spiceTLSx509certdir
          = strdup(SYSCONFDIR "/pki/libvirt-spice"))) {
        virReportOOMError();
        return -1;
    }

#if defined HAVE_MNTENT_H && defined HAVE_GETMNTENT_R
    /* For privileged driver, try and find hugepage mount automatically.
     * Non-privileged driver requires admin to create a dir for the
     * user, chown it, and then let user configure it manually */
    if (driver->privileged &&
        !(driver->hugetlbfs_mount = virFileFindMountPoint("hugetlbfs"))) {
        if (errno != ENOENT) {
            virReportSystemError(errno, "%s",
                                 _("unable to find hugetlbfs mountpoint"));
            return -1;
        }
    }
#endif


    /* Just check the file is readable before opening it, otherwise
     * libvirt emits an error.
     */
    if (access (filename, R_OK) == -1) {
        VIR_INFO("Could not read qemu config file %s", filename);
        return 0;
    }

    conf = virConfReadFile (filename, 0);
    if (!conf) {
        return -1;
    }


#define CHECK_TYPE(name,typ) if (p && p->type != (typ)) {               \
        qemuReportError(VIR_ERR_INTERNAL_ERROR,                         \
                        "%s: %s: expected type " #typ,                  \
                        filename, (name));                              \
        virConfFree(conf);                                              \
        return -1;                                                      \
    }

    p = virConfGetValue (conf, "vnc_auto_unix_socket");
    CHECK_TYPE ("vnc_auto_unix_socket", VIR_CONF_LONG);
    if (p) driver->vncAutoUnixSocket = p->l;

    p = virConfGetValue (conf, "vnc_tls");
    CHECK_TYPE ("vnc_tls", VIR_CONF_LONG);
    if (p) driver->vncTLS = p->l;

    p = virConfGetValue (conf, "vnc_tls_x509_verify");
    CHECK_TYPE ("vnc_tls_x509_verify", VIR_CONF_LONG);
    if (p) driver->vncTLSx509verify = p->l;

    p = virConfGetValue (conf, "vnc_tls_x509_cert_dir");
    CHECK_TYPE ("vnc_tls_x509_cert_dir", VIR_CONF_STRING);
    if (p && p->str) {
        VIR_FREE(driver->vncTLSx509certdir);
        if (!(driver->vncTLSx509certdir = strdup(p->str))) {
            virReportOOMError();
            virConfFree(conf);
            return -1;
        }
    }

    p = virConfGetValue (conf, "vnc_listen");
    CHECK_TYPE ("vnc_listen", VIR_CONF_STRING);
    if (p && p->str) {
        VIR_FREE(driver->vncListen);
        if (!(driver->vncListen = strdup(p->str))) {
            virReportOOMError();
            virConfFree(conf);
            return -1;
        }
    }

    p = virConfGetValue (conf, "vnc_password");
    CHECK_TYPE ("vnc_password", VIR_CONF_STRING);
    if (p && p->str) {
        VIR_FREE(driver->vncPassword);
        if (!(driver->vncPassword = strdup(p->str))) {
            virReportOOMError();
            virConfFree(conf);
            return -1;
        }
    }

    p = virConfGetValue (conf, "security_driver");
    CHECK_TYPE ("security_driver", VIR_CONF_STRING);
    if (p && p->str) {
        if (!(driver->securityDriverName = strdup(p->str))) {
            virReportOOMError();
            virConfFree(conf);
            return -1;
        }
    }

    p = virConfGetValue (conf, "vnc_sasl");
    CHECK_TYPE ("vnc_sasl", VIR_CONF_LONG);
    if (p) driver->vncSASL = p->l;

    p = virConfGetValue (conf, "vnc_sasl_dir");
    CHECK_TYPE ("vnc_sasl_dir", VIR_CONF_STRING);
    if (p && p->str) {
        VIR_FREE(driver->vncSASLdir);
        if (!(driver->vncSASLdir = strdup(p->str))) {
            virReportOOMError();
            virConfFree(conf);
            return -1;
        }
    }

    p = virConfGetValue (conf, "spice_tls");
    CHECK_TYPE ("spice_tls", VIR_CONF_LONG);
    if (p) driver->spiceTLS = p->l;

    p = virConfGetValue (conf, "spice_tls_x509_cert_dir");
    CHECK_TYPE ("spice_tls_x509_cert_dir", VIR_CONF_STRING);
    if (p && p->str) {
        VIR_FREE(driver->spiceTLSx509certdir);
        if (!(driver->spiceTLSx509certdir = strdup(p->str))) {
            virReportOOMError();
            virConfFree(conf);
            return -1;
        }
    }

    p = virConfGetValue (conf, "spice_listen");
    CHECK_TYPE ("spice_listen", VIR_CONF_STRING);
    if (p && p->str) {
        VIR_FREE(driver->spiceListen);
        if (!(driver->spiceListen = strdup(p->str))) {
            virReportOOMError();
            virConfFree(conf);
            return -1;
        }
    }

    p = virConfGetValue (conf, "spice_password");
    CHECK_TYPE ("spice_password", VIR_CONF_STRING);
    if (p && p->str) {
        VIR_FREE(driver->spicePassword);
        if (!(driver->spicePassword = strdup(p->str))) {
            virReportOOMError();
            virConfFree(conf);
            return -1;
        }
    }

    p = virConfGetValue (conf, "user");
    CHECK_TYPE ("user", VIR_CONF_STRING);
    if (!(user = strdup(p && p->str ? p->str : QEMU_USER))) {
        virReportOOMError();
        virConfFree(conf);
        return -1;
    }
    if (virGetUserID(user, &driver->user) < 0) {
        VIR_FREE(user);
        virConfFree(conf);
        return -1;
    }
    VIR_FREE(user);


    p = virConfGetValue (conf, "group");
    CHECK_TYPE ("group", VIR_CONF_STRING);
    if (!(group = strdup(p && p->str ? p->str : QEMU_GROUP))) {
        virReportOOMError();
        virConfFree(conf);
        return -1;
    }
    if (virGetGroupID(group, &driver->group) < 0) {
        VIR_FREE(group);
        virConfFree(conf);
        return -1;
    }
    VIR_FREE(group);


    p = virConfGetValue (conf, "dynamic_ownership");
    CHECK_TYPE ("dynamic_ownership", VIR_CONF_LONG);
    if (p) driver->dynamicOwnership = p->l;


    p = virConfGetValue (conf, "cgroup_controllers");
    CHECK_TYPE ("cgroup_controllers", VIR_CONF_LIST);
    if (p) {
        virConfValuePtr pp;
        for (i = 0, pp = p->list; pp; ++i, pp = pp->next) {
            int ctl;
            if (pp->type != VIR_CONF_STRING) {
                VIR_ERROR0(_("cgroup_controllers must be a list of strings"));
                virConfFree(conf);
                return -1;
            }
            ctl = virCgroupControllerTypeFromString(pp->str);
            if (ctl < 0) {
                VIR_ERROR(_("Unknown cgroup controller '%s'"), pp->str);
                virConfFree(conf);
                return -1;
            }
            driver->cgroupControllers |= (1 << ctl);
        }
    } else {
        driver->cgroupControllers =
            (1 << VIR_CGROUP_CONTROLLER_CPU) |
            (1 << VIR_CGROUP_CONTROLLER_DEVICES) |
            (1 << VIR_CGROUP_CONTROLLER_MEMORY) |
            (1 << VIR_CGROUP_CONTROLLER_BLKIO);
    }
    for (i = 0 ; i < VIR_CGROUP_CONTROLLER_LAST ; i++) {
        if (driver->cgroupControllers & (1 << i)) {
            VIR_INFO("Configured cgroup controller '%s'",
                     virCgroupControllerTypeToString(i));
        }
    }

    p = virConfGetValue (conf, "cgroup_device_acl");
    CHECK_TYPE ("cgroup_device_acl", VIR_CONF_LIST);
    if (p) {
        int len = 0;
        virConfValuePtr pp;
        for (pp = p->list; pp; pp = pp->next)
            len++;
        if (VIR_ALLOC_N(driver->cgroupDeviceACL, 1+len) < 0) {
            virReportOOMError();
            virConfFree(conf);
            return -1;
        }
        for (i = 0, pp = p->list; pp; ++i, pp = pp->next) {
            if (pp->type != VIR_CONF_STRING) {
                VIR_ERROR0(_("cgroup_device_acl must be a list of strings"));
                virConfFree(conf);
                return -1;
            }
            driver->cgroupDeviceACL[i] = strdup (pp->str);
            if (driver->cgroupDeviceACL[i] == NULL) {
                virReportOOMError();
                virConfFree(conf);
                return -1;
            }

        }
        driver->cgroupDeviceACL[i] = NULL;
    }

    p = virConfGetValue (conf, "save_image_format");
    CHECK_TYPE ("save_image_format", VIR_CONF_STRING);
    if (p && p->str) {
        VIR_FREE(driver->saveImageFormat);
        if (!(driver->saveImageFormat = strdup(p->str))) {
            virReportOOMError();
            virConfFree(conf);
            return -1;
        }
    }

    p = virConfGetValue (conf, "dump_image_format");
    CHECK_TYPE ("dump_image_format", VIR_CONF_STRING);
    if (p && p->str) {
        VIR_FREE(driver->dumpImageFormat);
        if (!(driver->dumpImageFormat = strdup(p->str))) {
            virReportOOMError();
            virConfFree(conf);
            return -1;
        }
    }

    p = virConfGetValue (conf, "auto_dump_path");
    CHECK_TYPE ("auto_dump_path", VIR_CONF_STRING);
    if (p && p->str) {
        VIR_FREE(driver->autoDumpPath);
        if (!(driver->autoDumpPath = strdup(p->str))) {
            virReportOOMError();
            virConfFree(conf);
            return -1;
        }
    }

     p = virConfGetValue (conf, "hugetlbfs_mount");
     CHECK_TYPE ("hugetlbfs_mount", VIR_CONF_STRING);
     if (p && p->str) {
         VIR_FREE(driver->hugetlbfs_mount);
         if (!(driver->hugetlbfs_mount = strdup(p->str))) {
             virReportOOMError();
             virConfFree(conf);
             return -1;
         }
     }

    p = virConfGetValue (conf, "mac_filter");
    CHECK_TYPE ("mac_filter", VIR_CONF_LONG);
    if (p && p->l) {
        driver->macFilter = p->l;
        if (!(driver->ebtables = ebtablesContextNew("qemu"))) {
            driver->macFilter = 0;
            virReportSystemError(errno,
                                 _("failed to enable mac filter in '%s'"),
                                 __FILE__);
        }

        if ((errno = networkDisableAllFrames(driver))) {
            virReportSystemError(errno,
                         _("failed to add rule to drop all frames in '%s'"),
                                 __FILE__);
        }
    }

    p = virConfGetValue (conf, "relaxed_acs_check");
    CHECK_TYPE ("relaxed_acs_check", VIR_CONF_LONG);
    if (p) driver->relaxedACS = p->l;

    p = virConfGetValue (conf, "vnc_allow_host_audio");
    CHECK_TYPE ("vnc_allow_host_audio", VIR_CONF_LONG);
    if (p) driver->vncAllowHostAudio = p->l;

    p = virConfGetValue (conf, "clear_emulator_capabilities");
    CHECK_TYPE ("clear_emulator_capabilities", VIR_CONF_LONG);
    if (p) driver->clearEmulatorCapabilities = p->l;

    p = virConfGetValue (conf, "allow_disk_format_probing");
    CHECK_TYPE ("allow_disk_format_probing", VIR_CONF_LONG);
    if (p) driver->allowDiskFormatProbing = p->l;

    p = virConfGetValue (conf, "set_process_name");
    CHECK_TYPE ("set_process_name", VIR_CONF_LONG);
    if (p) driver->setProcessName = p->l;

    p = virConfGetValue(conf, "max_processes");
    CHECK_TYPE("max_processes", VIR_CONF_LONG);
    if (p) driver->maxProcesses = p->l;

    virConfFree (conf);
    return 0;
}
