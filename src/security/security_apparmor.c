/*
 * AppArmor security driver for libvirt
 *
 * Copyright (C) 2011-2014 Red Hat, Inc.
 * Copyright (C) 2009-2010 Canonical Ltd.
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
 * Author:
 *   Jamie Strandboge <jamie@canonical.com>
 *   Based on security_selinux.c by James Morris <jmorris@namei.org>
 *
 * AppArmor security driver.
 */

#include <config.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/apparmor.h>
#include <errno.h>
#include <unistd.h>
#include <wait.h>

#include "internal.h"

#include "security_apparmor.h"
#include "viralloc.h"
#include "virerror.h"
#include "datatypes.h"
#include "viruuid.h"
#include "virpci.h"
#include "virusb.h"
#include "virscsivhost.h"
#include "virfile.h"
#include "configmake.h"
#include "vircommand.h"
#include "virlog.h"
#include "virstring.h"
#include "virscsi.h"

#define VIR_FROM_THIS VIR_FROM_SECURITY

VIR_LOG_INIT("security.security_apparmor");

#define SECURITY_APPARMOR_VOID_DOI      "0"
#define SECURITY_APPARMOR_NAME          "apparmor"
#define VIRT_AA_HELPER LIBEXECDIR "/virt-aa-helper"

/* Data structure to pass to *FileIterate so we have everything we need */
struct SDPDOP {
    virSecurityManagerPtr mgr;
    virDomainDefPtr def;
};

/*
 * profile_status returns '-2' on error, '-1' if not loaded, '0' if loaded
 *
 * If check_enforcing is set to '1', then returns '-2' on error, '-1' if
 * not loaded, '0' if loaded in complain mode, and '1' if loaded in
 * enforcing mode.
 */
static int
profile_status(const char *str, const int check_enforcing)
{
    char *content = NULL;
    char *tmp = NULL;
    char *etmp = NULL;
    int rc = -2;

    /* create string that is '<str> \0' for accurate matching */
    if (virAsprintf(&tmp, "%s ", str) == -1)
        return rc;

    if (check_enforcing != 0) {
        /* create string that is '<str> (enforce)\0' for accurate matching */
        if (virAsprintf(&etmp, "%s (enforce)", str) == -1) {
            VIR_FREE(tmp);
            return rc;
        }
    }

    if (virFileReadAll(APPARMOR_PROFILES_PATH, MAX_FILE_LEN, &content) < 0) {
        virReportSystemError(errno,
                             _("Failed to read AppArmor profiles list "
                             "\'%s\'"), APPARMOR_PROFILES_PATH);
        goto cleanup;
    }

    if (strstr(content, tmp) != NULL)
        rc = 0;
    else
        rc = -1; /* return -1 if not loaded */
    if (check_enforcing != 0) {
        if (rc == 0 && strstr(content, etmp) != NULL)
            rc = 1;                 /* return '1' if loaded and enforcing */
    }

    VIR_FREE(content);
 cleanup:
    VIR_FREE(tmp);
    VIR_FREE(etmp);

    return rc;
}

static int
profile_loaded(const char *str)
{
    return profile_status(str, 0);
}

/*
 * profile_status_file returns '-1' on error, '0' if file on disk is in
 * complain mode and '1' if file on disk is in enforcing mode
 */
static int
profile_status_file(const char *str)
{
    char *profile = NULL;
    char *content = NULL;
    char *tmp = NULL;
    int rc = -1;
    int len;

    if (virAsprintf(&profile, "%s/%s", APPARMOR_DIR "/libvirt", str) == -1)
        return rc;

    if (!virFileExists(profile))
        goto failed;

    if ((len = virFileReadAll(profile, MAX_FILE_LEN, &content)) < 0) {
        virReportSystemError(errno,
                             _("Failed to read \'%s\'"), profile);
        goto failed;
    }

    /* create string that is ' <str> flags=(complain)\0' */
    if (virAsprintf(&tmp, " %s flags=(complain)", str) == -1)
        goto failed;

    if (strstr(content, tmp) != NULL)
        rc = 0;
    else
        rc = 1;

 failed:
    VIR_FREE(tmp);
    VIR_FREE(profile);
    VIR_FREE(content);

    return rc;
}

/*
 * load (add) a profile. Will create one if necessary
 */
static int
load_profile(virSecurityManagerPtr mgr,
             const char *profile,
             virDomainDefPtr def,
             const char *fn,
             bool append)
{
    int rc = -1;
    bool create = true;
    char *xml = NULL;
    virCommandPtr cmd = NULL;
    const char *probe = virSecurityManagerGetAllowDiskFormatProbing(mgr)
        ? "1" : "0";

    xml = virDomainDefFormat(def, NULL, VIR_DOMAIN_DEF_FORMAT_SECURE);
    if (!xml)
        goto cleanup;

    if (profile_status_file(profile) >= 0)
        create = false;

    cmd = virCommandNewArgList(VIRT_AA_HELPER, "-p", probe,
                               create ? "-c" : "-r",
                               "-u", profile, NULL);
    if (!create && fn) {
        if (append) {
            virCommandAddArgList(cmd, "-F", fn, NULL);
        } else {
            virCommandAddArgList(cmd, "-f", fn, NULL);
        }
    }

    virCommandAddEnvFormat(cmd,
                           "LIBVIRT_LOG_OUTPUTS=%d:stderr",
                           virLogGetDefaultPriority());

    virCommandSetInputBuffer(cmd, xml);
    rc = virCommandRun(cmd, NULL);

 cleanup:
    VIR_FREE(xml);
    virCommandFree(cmd);

    return rc;
}

static int
remove_profile(const char *profile)
{
    int rc = -1;
    const char * const argv[] = {
        VIRT_AA_HELPER, "-R", "-u", profile, NULL
    };

    if (virRun(argv, NULL) == 0)
        rc = 0;

    return rc;
}

static char *
get_profile_name(virDomainDefPtr def)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    char *name = NULL;

    virUUIDFormat(def->uuid, uuidstr);
    if (virAsprintf(&name, "%s%s", AA_PREFIX, uuidstr) < 0)
        return NULL;

    return name;
}

/* returns -1 on error or profile for libvirtd is unconfined, 0 if complain
 * mode and 1 if enforcing. This is required because at present you cannot
 * aa_change_profile() from a process that is unconfined.
 */
static int
use_apparmor(void)
{
    int rc = -1;
    char *libvirt_daemon = NULL;

    if (virFileResolveLink("/proc/self/exe", &libvirt_daemon) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("could not find libvirtd"));
        return rc;
    }

    /* If libvirt_lxc is calling us, then consider apparmor is used
     * and enforced. */
    if (strstr(libvirt_daemon, "libvirt_lxc"))
        return 1;

    if (access(APPARMOR_PROFILES_PATH, R_OK) != 0)
        goto cleanup;

    rc = profile_status(libvirt_daemon, 1);
    /* Error or unconfined should all result in -1*/
    if (rc < 0)
        rc = -1;

 cleanup:
    VIR_FREE(libvirt_daemon);
    return rc;
}

/* reload the profile, adding read/write file specified by fn if it is not
 * NULL.
 */
static int
reload_profile(virSecurityManagerPtr mgr,
               virDomainDefPtr def,
               const char *fn,
               bool append)
{
    int rc = -1;
    char *profile_name = NULL;
    virSecurityLabelDefPtr secdef = virDomainDefGetSecurityLabelDef(
                                                def, SECURITY_APPARMOR_NAME);

    if (!secdef || !secdef->relabel)
        return 0;

    if ((profile_name = get_profile_name(def)) == NULL)
        return rc;

    /* Update the profile only if it is loaded */
    if (profile_loaded(secdef->imagelabel) >= 0) {
        if (load_profile(mgr, secdef->imagelabel, def, fn, append) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot update AppArmor profile "
                             "\'%s\'"),
                           secdef->imagelabel);
            goto cleanup;
        }
    }

    rc = 0;
 cleanup:
    VIR_FREE(profile_name);

    return rc;
}

static int
AppArmorSetSecurityHostdevLabelHelper(const char *file, void *opaque)
{
    struct SDPDOP *ptr = opaque;
    virDomainDefPtr def = ptr->def;

    return reload_profile(ptr->mgr, def, file, true);
}

static int
AppArmorSetSecurityUSBLabel(virUSBDevicePtr dev ATTRIBUTE_UNUSED,
                            const char *file, void *opaque)
{
    return AppArmorSetSecurityHostdevLabelHelper(file, opaque);
}

static int
AppArmorSetSecurityPCILabel(virPCIDevicePtr dev ATTRIBUTE_UNUSED,
                            const char *file, void *opaque)
{
    return AppArmorSetSecurityHostdevLabelHelper(file, opaque);
}

static int
AppArmorSetSecuritySCSILabel(virSCSIDevicePtr dev ATTRIBUTE_UNUSED,
                             const char *file, void *opaque)
{
    return AppArmorSetSecurityHostdevLabelHelper(file, opaque);
}

static int
AppArmorSetSecurityHostLabel(virSCSIVHostDevicePtr dev ATTRIBUTE_UNUSED,
                             const char *file, void *opaque)
{
    return AppArmorSetSecurityHostdevLabelHelper(file, opaque);
}

/* Called on libvirtd startup to see if AppArmor is available */
static int
AppArmorSecurityManagerProbe(const char *virtDriver ATTRIBUTE_UNUSED)
{
    char *template_qemu = NULL;
    char *template_lxc = NULL;
    int rc = SECURITY_DRIVER_DISABLE;

    if (use_apparmor() < 0)
        return rc;

    /* see if template file exists */
    if (virAsprintf(&template_qemu, "%s/TEMPLATE.qemu",
                               APPARMOR_DIR "/libvirt") == -1)
        return rc;

    if (virAsprintf(&template_lxc, "%s/TEMPLATE.lxc",
                               APPARMOR_DIR "/libvirt") == -1)
        goto cleanup;

    if (!virFileExists(template_qemu)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("template \'%s\' does not exist"), template_qemu);
        goto cleanup;
    }
    if (!virFileExists(template_lxc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("template \'%s\' does not exist"), template_lxc);
        goto cleanup;
    }
    rc = SECURITY_DRIVER_ENABLE;

 cleanup:
    VIR_FREE(template_qemu);
    VIR_FREE(template_lxc);

    return rc;
}

/* Security driver initialization. DOI is for 'Domain of Interpretation' and is
 * currently not used.
 */
static int
AppArmorSecurityManagerOpen(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED)
{
    return 0;
}

static int
AppArmorSecurityManagerClose(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED)
{
    return 0;
}

static const char *
AppArmorSecurityManagerGetModel(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED)
{
    return SECURITY_APPARMOR_NAME;
}

static const char *
AppArmorSecurityManagerGetDOI(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED)
{
    return SECURITY_APPARMOR_VOID_DOI;
}


/* Currently called in qemudStartVMDaemon to setup a 'label'. We look for and
 * use a profile based on the UUID, otherwise create one based on a template.
 * Keep in mind that this is called on 'start' with RestoreSecurityLabel being
 * called on shutdown.
*/
static int
AppArmorGenSecurityLabel(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                         virDomainDefPtr def)
{
    int rc = -1;
    char *profile_name = NULL;
    virSecurityLabelDefPtr secdef = virDomainDefGetSecurityLabelDef(def,
                                                SECURITY_APPARMOR_NAME);

    if (!secdef)
        return 0;

    if ((secdef->type == VIR_DOMAIN_SECLABEL_STATIC) ||
        (secdef->type == VIR_DOMAIN_SECLABEL_NONE))
        return 0;

    if (secdef->baselabel) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       "%s", _("Cannot set a base label with AppArmour"));
        return rc;
    }

    if (secdef->label || secdef->imagelabel) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s",
                       _("security label already defined for VM"));
        return rc;
    }

    if ((profile_name = get_profile_name(def)) == NULL)
        return rc;

    if (VIR_STRDUP(secdef->label, profile_name) < 0)
        goto cleanup;

    /* set imagelabel the same as label (but we won't use it) */
    if (VIR_STRDUP(secdef->imagelabel, profile_name) < 0)
        goto err;

    if (!secdef->model && VIR_STRDUP(secdef->model, SECURITY_APPARMOR_NAME) < 0)
        goto err;

    /* Now that we have a label, load the profile into the kernel. */
    if (load_profile(mgr, secdef->label, def, NULL, false) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot load AppArmor profile "
                       "\'%s\'"), secdef->label);
        goto err;
    }

    rc = 0;
    goto cleanup;

 err:
    VIR_FREE(secdef->label);
    VIR_FREE(secdef->imagelabel);
    VIR_FREE(secdef->model);

 cleanup:
    VIR_FREE(profile_name);

    return rc;
}

static int
AppArmorSetSecurityAllLabel(virSecurityManagerPtr mgr,
                            virDomainDefPtr def, const char *stdin_path)
{
    virSecurityLabelDefPtr secdef = virDomainDefGetSecurityLabelDef(def,
                                                    SECURITY_APPARMOR_NAME);
    if (!secdef || !secdef->relabel)
        return 0;

    /* Reload the profile if stdin_path is specified. Note that
       GenSecurityLabel() will have already been run. */
    if (stdin_path)
        return reload_profile(mgr, def, stdin_path, true);

    return 0;
}

/* Seen with 'virsh dominfo <vm>'. This function only called if the VM is
 * running.
 */
static int
AppArmorGetSecurityProcessLabel(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                                virDomainDefPtr def,
                                pid_t pid ATTRIBUTE_UNUSED,
                                virSecurityLabelPtr sec)
{
    int rc = -1;
    int status;
    char *profile_name = NULL;

    if ((profile_name = get_profile_name(def)) == NULL)
        return rc;

    status = profile_status(profile_name, 1);
    if (status < -1) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("error getting profile status"));
        goto cleanup;
    } else if (status == -1) {
        profile_name[0] = '\0';
    }

    if (virStrcpy(sec->label, profile_name,
        VIR_SECURITY_LABEL_BUFLEN) == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("error copying profile name"));
        goto cleanup;
    }

    sec->enforcing = status == 1;
    rc = 0;

 cleanup:
    VIR_FREE(profile_name);

    return rc;
}

/* Called on VM shutdown and destroy. See AppArmorGenSecurityLabel (above) for
 * more details. Currently called via qemudShutdownVMDaemon.
 */
static int
AppArmorReleaseSecurityLabel(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                             virDomainDefPtr def)
{
    virSecurityLabelDefPtr secdef = virDomainDefGetSecurityLabelDef(def,
                                                        SECURITY_APPARMOR_NAME);
    if (secdef) {
        VIR_FREE(secdef->model);
        VIR_FREE(secdef->label);
        VIR_FREE(secdef->imagelabel);
    }

    return 0;
}


static int
AppArmorRestoreSecurityAllLabel(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                                virDomainDefPtr def,
                                bool migrated ATTRIBUTE_UNUSED)
{
    int rc = 0;
    virSecurityLabelDefPtr secdef =
        virDomainDefGetSecurityLabelDef(def, SECURITY_APPARMOR_NAME);

    if (!secdef)
        return 0;

    if (secdef->type == VIR_DOMAIN_SECLABEL_DYNAMIC) {
        if ((rc = remove_profile(secdef->label)) != 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("could not remove profile for \'%s\'"),
                           secdef->label);
        }
    }
    return rc;
}

/* Called via virCommand hook. Output goes to
 * LOCALSTATEDIR/log/libvirt/qemu/<vm name>.log
 */
static int
AppArmorSetSecurityProcessLabel(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                                virDomainDefPtr def)
{
    int rc = -1;
    char *profile_name = NULL;
    virSecurityLabelDefPtr secdef =
        virDomainDefGetSecurityLabelDef(def, SECURITY_APPARMOR_NAME);

    if (!secdef || !secdef->label)
        return 0;

    if ((profile_name = get_profile_name(def)) == NULL)
        return rc;

    if (STRNEQ(SECURITY_APPARMOR_NAME, secdef->model)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("security label driver mismatch: "
                         "\'%s\' model configured for domain, but "
                         "hypervisor driver is \'%s\'."),
                       secdef->model, SECURITY_APPARMOR_NAME);
        if (use_apparmor() > 0)
            goto cleanup;
    }

    VIR_DEBUG("Changing AppArmor profile to %s", profile_name);
    if (aa_change_profile(profile_name) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("error calling aa_change_profile()"));
        goto cleanup;
    }
    rc = 0;

 cleanup:
    VIR_FREE(profile_name);

    return rc;
}

/* Called directly by API user prior to virCommandRun().
 * virCommandRun() will then call aa_change_profile() (if a
 * cmd->appArmorProfile has been set) *after forking the child
 * process*.
 */
static int
AppArmorSetSecurityChildProcessLabel(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                                     virDomainDefPtr def,
                                     virCommandPtr cmd)
{
    int rc = -1;
    char *profile_name = NULL;
    char *cmd_str = NULL;
    virSecurityLabelDefPtr secdef =
        virDomainDefGetSecurityLabelDef(def, SECURITY_APPARMOR_NAME);

    if (!secdef || !secdef->label)
        return 0;

    if (STRNEQ(SECURITY_APPARMOR_NAME, secdef->model)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("security label driver mismatch: "
                         "\'%s\' model configured for domain, but "
                         "hypervisor driver is \'%s\'."),
                       secdef->model, SECURITY_APPARMOR_NAME);
        if (use_apparmor() > 0)
            goto cleanup;
    }

    if ((profile_name = get_profile_name(def)) == NULL)
        goto cleanup;

    cmd_str = virCommandToString(cmd);
    VIR_DEBUG("Changing AppArmor profile to %s on %s", profile_name, cmd_str);
    virCommandSetAppArmorProfile(cmd, profile_name);
    rc = 0;

 cleanup:
    VIR_FREE(profile_name);
    VIR_FREE(cmd_str);
    return rc;
}

static int
AppArmorSetSecurityDaemonSocketLabel(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                                     virDomainDefPtr vm ATTRIBUTE_UNUSED)
{
    return 0;
}

static int
AppArmorSetSecuritySocketLabel(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                               virDomainDefPtr def ATTRIBUTE_UNUSED)
{
    return 0;
}

static int
AppArmorClearSecuritySocketLabel(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                                 virDomainDefPtr def ATTRIBUTE_UNUSED)
{
    return 0;
}


/* Called when hotplugging */
static int
AppArmorRestoreSecurityImageLabel(virSecurityManagerPtr mgr,
                                  virDomainDefPtr def,
                                  virStorageSourcePtr src)
{
    if (!virStorageSourceIsLocalStorage(src))
        return 0;

    return reload_profile(mgr, def, NULL, false);
}

static int
AppArmorRestoreSecurityDiskLabel(virSecurityManagerPtr mgr,
                                 virDomainDefPtr def,
                                 virDomainDiskDefPtr disk)
{
    return AppArmorRestoreSecurityImageLabel(mgr, def, disk->src);
}

/* Called when hotplugging */
static int
AppArmorSetSecurityImageLabel(virSecurityManagerPtr mgr,
                              virDomainDefPtr def,
                              virStorageSourcePtr src)
{
    int rc = -1;
    char *profile_name = NULL;
    virSecurityLabelDefPtr secdef;

    if (!src->path || !virStorageSourceIsLocalStorage(src))
        return 0;

    secdef = virDomainDefGetSecurityLabelDef(def, SECURITY_APPARMOR_NAME);
    if (!secdef || !secdef->relabel)
        return 0;

    if (secdef->imagelabel) {
        /* if the device doesn't exist, error out */
        if (!virFileExists(src->path)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("\'%s\' does not exist"),
                           src->path);
            return -1;
        }

        if ((profile_name = get_profile_name(def)) == NULL)
            return -1;

        /* update the profile only if it is loaded */
        if (profile_loaded(secdef->imagelabel) >= 0) {
            if (load_profile(mgr, secdef->imagelabel, def,
                             src->path, false) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("cannot update AppArmor profile "
                                 "\'%s\'"),
                               secdef->imagelabel);
                goto cleanup;
            }
        }
    }
    rc = 0;

 cleanup:
    VIR_FREE(profile_name);

    return rc;
}

static int
AppArmorSetSecurityDiskLabel(virSecurityManagerPtr mgr,
                             virDomainDefPtr def,
                             virDomainDiskDefPtr disk)
{
    return AppArmorSetSecurityImageLabel(mgr, def, disk->src);
}

static int
AppArmorSecurityVerify(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                       virDomainDefPtr def)
{
    virSecurityLabelDefPtr secdef =
        virDomainDefGetSecurityLabelDef(def, SECURITY_APPARMOR_NAME);

    if (!secdef)
        return 0;

    if (secdef->type == VIR_DOMAIN_SECLABEL_STATIC) {
        if (use_apparmor() < 0 || profile_status(secdef->label, 0) < 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Invalid security label \'%s\'"),
                           secdef->label);
            return -1;
        }
    }
    return 0;
}

static int
AppArmorReserveSecurityLabel(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                             virDomainDefPtr def ATTRIBUTE_UNUSED,
                             pid_t pid ATTRIBUTE_UNUSED)
{
    /* NOOP. Nothing to reserve with AppArmor */
    return 0;
}

static int
AppArmorSetSecurityHostdevLabel(virSecurityManagerPtr mgr,
                                virDomainDefPtr def,
                                virDomainHostdevDefPtr dev,
                                const char *vroot)
{
    struct SDPDOP *ptr;
    int ret = -1;
    virSecurityLabelDefPtr secdef =
        virDomainDefGetSecurityLabelDef(def, SECURITY_APPARMOR_NAME);
    virDomainHostdevSubsysUSBPtr usbsrc = &dev->source.subsys.u.usb;
    virDomainHostdevSubsysPCIPtr pcisrc = &dev->source.subsys.u.pci;
    virDomainHostdevSubsysSCSIPtr scsisrc = &dev->source.subsys.u.scsi;
    virDomainHostdevSubsysSCSIVHostPtr hostsrc = &dev->source.subsys.u.scsi_host;

    if (!secdef || !secdef->relabel)
        return 0;

    if (dev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
        return 0;

    /* Like AppArmorRestoreSecurityImageLabel() for a networked disk,
     * do nothing for an iSCSI hostdev
     */
    if (dev->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI &&
        scsisrc->protocol == VIR_DOMAIN_HOSTDEV_SCSI_PROTOCOL_TYPE_ISCSI)
        return 0;

    if (profile_loaded(secdef->imagelabel) < 0)
        return 0;

    if (VIR_ALLOC(ptr) < 0)
        return -1;
    ptr->mgr = mgr;
    ptr->def = def;

    switch ((virDomainHostdevSubsysType) dev->source.subsys.type) {
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB: {
        virUSBDevicePtr usb =
            virUSBDeviceNew(usbsrc->bus, usbsrc->device, vroot);
        if (!usb)
            goto done;

        ret = virUSBDeviceFileIterate(usb, AppArmorSetSecurityUSBLabel, ptr);
        virUSBDeviceFree(usb);
        break;
    }

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI: {
        virPCIDevicePtr pci =
            virPCIDeviceNew(pcisrc->addr.domain, pcisrc->addr.bus,
                            pcisrc->addr.slot, pcisrc->addr.function);

        if (!pci)
            goto done;

        if (pcisrc->backend == VIR_DOMAIN_HOSTDEV_PCI_BACKEND_VFIO) {
            char *vfioGroupDev = virPCIDeviceGetIOMMUGroupDev(pci);

            if (!vfioGroupDev) {
                virPCIDeviceFree(pci);
                goto done;
            }
            ret = AppArmorSetSecurityPCILabel(pci, vfioGroupDev, ptr);
            VIR_FREE(vfioGroupDev);
        } else {
            ret = virPCIDeviceFileIterate(pci, AppArmorSetSecurityPCILabel, ptr);
        }
        virPCIDeviceFree(pci);
        break;
    }

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI: {
        virDomainHostdevSubsysSCSIHostPtr scsihostsrc = &scsisrc->u.host;
        virSCSIDevicePtr scsi =
            virSCSIDeviceNew(NULL,
                             scsihostsrc->adapter, scsihostsrc->bus,
                             scsihostsrc->target, scsihostsrc->unit,
                             dev->readonly, dev->shareable);

         if (!scsi)
             goto done;

        ret = virSCSIDeviceFileIterate(scsi, AppArmorSetSecuritySCSILabel, ptr);
        virSCSIDeviceFree(scsi);

        break;
    }

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI_HOST: {
        virSCSIVHostDevicePtr host = virSCSIVHostDeviceNew(hostsrc->wwpn);

        if (!host)
            goto done;

        ret = virSCSIVHostDeviceFileIterate(host,
                                            AppArmorSetSecurityHostLabel,
                                            ptr);
        virSCSIVHostDeviceFree(host);
        break;
    }

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_MDEV:
        break;

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_LAST:
        ret = 0;
        break;
    }

 done:
    VIR_FREE(ptr);
    return ret;
}


static int
AppArmorRestoreSecurityHostdevLabel(virSecurityManagerPtr mgr,
                                    virDomainDefPtr def,
                                    virDomainHostdevDefPtr dev ATTRIBUTE_UNUSED,
                                    const char *vroot ATTRIBUTE_UNUSED)

{
    virSecurityLabelDefPtr secdef =
        virDomainDefGetSecurityLabelDef(def, SECURITY_APPARMOR_NAME);

    if (!secdef || !secdef->relabel)
        return 0;

    return reload_profile(mgr, def, NULL, false);
}

static int
AppArmorSetSavedStateLabel(virSecurityManagerPtr mgr,
                           virDomainDefPtr def,
                           const char *savefile)
{
    return reload_profile(mgr, def, savefile, true);
}


static int
AppArmorRestoreSavedStateLabel(virSecurityManagerPtr mgr,
                               virDomainDefPtr def,
                               const char *savefile ATTRIBUTE_UNUSED)
{
    return reload_profile(mgr, def, NULL, false);
}

static int
AppArmorSetFDLabel(virSecurityManagerPtr mgr,
                   virDomainDefPtr def,
                   int fd)
{
    int rc = -1;
    char *proc = NULL;
    char *fd_path = NULL;

    virSecurityLabelDefPtr secdef =
        virDomainDefGetSecurityLabelDef(def, SECURITY_APPARMOR_NAME);

    if (!secdef || !secdef->imagelabel)
        return 0;

    if (virAsprintf(&proc, "/proc/self/fd/%d", fd) == -1)
        return rc;

    if (virFileResolveLink(proc, &fd_path) < 0) {
        /* it's a deleted file, presumably.  Ignore? */
        VIR_WARN("could not find path for descriptor %s, skipping", proc);
        return 0;
    }

    return reload_profile(mgr, def, fd_path, true);
}

static char *
AppArmorGetMountOptions(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                        virDomainDefPtr vm ATTRIBUTE_UNUSED)
{
    char *opts;

    ignore_value(VIR_STRDUP(opts, ""));
    return opts;
}

static const char *
AppArmorGetBaseLabel(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                     int virtType ATTRIBUTE_UNUSED)
{
    return NULL;
}

virSecurityDriver virAppArmorSecurityDriver = {
    .privateDataLen                     = 0,
    .name                               = SECURITY_APPARMOR_NAME,
    .probe                              = AppArmorSecurityManagerProbe,
    .open                               = AppArmorSecurityManagerOpen,
    .close                              = AppArmorSecurityManagerClose,

    .getModel                           = AppArmorSecurityManagerGetModel,
    .getDOI                             = AppArmorSecurityManagerGetDOI,

    .domainSecurityVerify               = AppArmorSecurityVerify,

    .domainSetSecurityDiskLabel         = AppArmorSetSecurityDiskLabel,
    .domainRestoreSecurityDiskLabel     = AppArmorRestoreSecurityDiskLabel,

    .domainSetSecurityImageLabel        = AppArmorSetSecurityImageLabel,
    .domainRestoreSecurityImageLabel    = AppArmorRestoreSecurityImageLabel,

    .domainSetSecurityDaemonSocketLabel = AppArmorSetSecurityDaemonSocketLabel,
    .domainSetSecuritySocketLabel       = AppArmorSetSecuritySocketLabel,
    .domainClearSecuritySocketLabel     = AppArmorClearSecuritySocketLabel,

    .domainGenSecurityLabel             = AppArmorGenSecurityLabel,
    .domainReserveSecurityLabel         = AppArmorReserveSecurityLabel,
    .domainReleaseSecurityLabel         = AppArmorReleaseSecurityLabel,

    .domainGetSecurityProcessLabel      = AppArmorGetSecurityProcessLabel,
    .domainSetSecurityProcessLabel      = AppArmorSetSecurityProcessLabel,
    .domainSetSecurityChildProcessLabel = AppArmorSetSecurityChildProcessLabel,

    .domainSetSecurityAllLabel          = AppArmorSetSecurityAllLabel,
    .domainRestoreSecurityAllLabel      = AppArmorRestoreSecurityAllLabel,

    .domainSetSecurityHostdevLabel      = AppArmorSetSecurityHostdevLabel,
    .domainRestoreSecurityHostdevLabel  = AppArmorRestoreSecurityHostdevLabel,

    .domainSetSavedStateLabel           = AppArmorSetSavedStateLabel,
    .domainRestoreSavedStateLabel       = AppArmorRestoreSavedStateLabel,

    .domainSetSecurityImageFDLabel      = AppArmorSetFDLabel,
    .domainSetSecurityTapFDLabel        = AppArmorSetFDLabel,

    .domainGetSecurityMountOptions      = AppArmorGetMountOptions,

    .getBaseLabel                       = AppArmorGetBaseLabel,
};
