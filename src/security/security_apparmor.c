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
 */

#include <config.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/apparmor.h>
#include <unistd.h>
#include <sys/wait.h>

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
#include "virmdev.h"

#define VIR_FROM_THIS VIR_FROM_SECURITY

VIR_LOG_INIT("security.security_apparmor");

#define SECURITY_APPARMOR_VOID_DOI      "0"
#define SECURITY_APPARMOR_NAME          "apparmor"
#define VIRT_AA_HELPER LIBEXECDIR "/virt-aa-helper"

/* Data structure to pass to *FileIterate so we have everything we need */
struct SDPDOP {
    virSecurityManager *mgr;
    virDomainDef *def;
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
    g_autofree char *content = NULL;
    g_autofree char *tmp = NULL;
    g_autofree char *etmp = NULL;
    int rc = -2;

    /* create string that is '<str> \0' for accurate matching */
    tmp = g_strdup_printf("%s ", str);

    if (check_enforcing != 0) {
        /* create string that is '<str> (enforce)\0' for accurate matching */
        etmp = g_strdup_printf("%s (enforce)", str);
    }

    if (virFileReadAll(APPARMOR_PROFILES_PATH, MAX_FILE_LEN, &content) < 0) {
        virReportSystemError(errno,
                             _("Failed to read AppArmor profiles list \'%1$s\'"),
                             APPARMOR_PROFILES_PATH);
        return -2;
    }

    if (strstr(content, tmp) != NULL)
        rc = 0;
    else
        rc = -1; /* return -1 if not loaded */
    if (check_enforcing != 0) {
        if (rc == 0 && strstr(content, etmp) != NULL)
            rc = 1;                 /* return '1' if loaded and enforcing */
    }

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

    profile = g_strdup_printf("%s/%s", APPARMOR_DIR "/libvirt", str);

    if (!virFileExists(profile))
        goto failed;

    if ((len = virFileReadAll(profile, MAX_FILE_LEN, &content)) < 0) {
        virReportSystemError(errno,
                             _("Failed to read \'%1$s\'"), profile);
        goto failed;
    }

    /* create string that is ' <str> flags=(complain)\0' */
    tmp = g_strdup_printf(" %s flags=(complain)", str);

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
load_profile(virSecurityManager *mgr G_GNUC_UNUSED,
             const char *profile,
             virDomainDef *def,
             const char *fn,
             bool append)
{
    bool create = true;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    g_autofree char *xml = NULL;
    g_autoptr(virCommand) cmd = NULL;

    if (virDomainDefFormatInternal(def, NULL, &buf,
                                   VIR_DOMAIN_DEF_FORMAT_SECURE |
                                   VIR_DOMAIN_DEF_FORMAT_VOLUME_TRANSLATED) < 0)
        return -1;

    xml = virBufferContentAndReset(&buf);

    if (profile_status_file(profile) >= 0)
        create = false;

    cmd = virCommandNewArgList(VIRT_AA_HELPER,
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
    return virCommandRun(cmd, NULL);
}

static int
remove_profile(const char *profile)
{
    g_autoptr(virCommand) cmd = virCommandNewArgList(VIRT_AA_HELPER, "-D", "-u",
                                                     profile, NULL);

    return virCommandRun(cmd, NULL);
}

static char *
get_profile_name(virDomainDef *def)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    virUUIDFormat(def->uuid, uuidstr);
    return g_strdup_printf("%s%s", AA_PREFIX, uuidstr);
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

    /* First check profile status using full binary path. If that fails
     * check using profile name.
     */
    rc = profile_status(libvirt_daemon, 1);
    if (rc < 0) {
        rc = profile_status("libvirtd", 1);
        /* Error or unconfined should all result in -1 */
        if (rc < 0)
            rc = -1;
    }

 cleanup:
    VIR_FREE(libvirt_daemon);
    return rc;
}

/* reload the profile, adding read/write file specified by fn if it is not
 * NULL.
 */
static int
reload_profile(virSecurityManager *mgr,
               virDomainDef *def,
               const char *fn,
               bool append)
{
    virSecurityLabelDef *secdef = virDomainDefGetSecurityLabelDef(
                                                def, SECURITY_APPARMOR_NAME);

    if (!secdef || !secdef->relabel)
        return 0;

    /* Update the profile only if it is loaded */
    if (profile_loaded(secdef->imagelabel) >= 0) {
        if (load_profile(mgr, secdef->imagelabel, def, fn, append) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot update AppArmor profile \'%1$s\'"),
                           secdef->imagelabel);
            return -1;
        }
    }
    return 0;
}

static int
AppArmorSetSecurityHostdevLabelHelper(const char *file, void *opaque)
{
    struct SDPDOP *ptr = opaque;
    virDomainDef *def = ptr->def;

    return reload_profile(ptr->mgr, def, file, true);
}

static int
AppArmorSetSecurityUSBLabel(virUSBDevice *dev G_GNUC_UNUSED,
                            const char *file, void *opaque)
{
    return AppArmorSetSecurityHostdevLabelHelper(file, opaque);
}

static int
AppArmorSetSecurityPCILabel(virPCIDevice *dev G_GNUC_UNUSED,
                            const char *file, void *opaque)
{
    return AppArmorSetSecurityHostdevLabelHelper(file, opaque);
}

static int
AppArmorSetSecuritySCSILabel(virSCSIDevice *dev G_GNUC_UNUSED,
                             const char *file, void *opaque)
{
    return AppArmorSetSecurityHostdevLabelHelper(file, opaque);
}

static int
AppArmorSetSecurityHostLabel(virSCSIVHostDevice *dev G_GNUC_UNUSED,
                             const char *file, void *opaque)
{
    return AppArmorSetSecurityHostdevLabelHelper(file, opaque);
}

/* Called on libvirtd startup to see if AppArmor is available */
static int
AppArmorSecurityManagerProbe(const char *virtDriver G_GNUC_UNUSED)
{
    g_autofree char *template_qemu = NULL;
    g_autofree char *template_lxc = NULL;

    if (use_apparmor() < 0)
        return SECURITY_DRIVER_DISABLE;

    /* see if template file exists */
    template_qemu = g_strdup_printf("%s/TEMPLATE.qemu", APPARMOR_DIR "/libvirt");
    template_lxc = g_strdup_printf("%s/TEMPLATE.lxc", APPARMOR_DIR "/libvirt");

    if (!virFileExists(template_qemu)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("template \'%1$s\' does not exist"), template_qemu);
        return SECURITY_DRIVER_DISABLE;
    }
    if (!virFileExists(template_lxc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("template \'%1$s\' does not exist"), template_lxc);
        return SECURITY_DRIVER_DISABLE;
    }

    return SECURITY_DRIVER_ENABLE;
}

/* Security driver initialization. DOI is for 'Domain of Interpretation' and is
 * currently not used.
 */
static int
AppArmorSecurityManagerOpen(virSecurityManager *mgr G_GNUC_UNUSED)
{
    return 0;
}

static int
AppArmorSecurityManagerClose(virSecurityManager *mgr G_GNUC_UNUSED)
{
    return 0;
}

static const char *
AppArmorSecurityManagerGetModel(virSecurityManager *mgr G_GNUC_UNUSED)
{
    return SECURITY_APPARMOR_NAME;
}

static const char *
AppArmorSecurityManagerGetDOI(virSecurityManager *mgr G_GNUC_UNUSED)
{
    return SECURITY_APPARMOR_VOID_DOI;
}


/* Currently called in qemudStartVMDaemon to setup a 'label'. We look for and
 * use a profile based on the UUID, otherwise create one based on a template.
 * Keep in mind that this is called on 'start' with RestoreSecurityLabel being
 * called on shutdown.
*/
static int
AppArmorGenSecurityLabel(virSecurityManager *mgr G_GNUC_UNUSED,
                         virDomainDef *def)
{
    g_autofree char *profile_name = NULL;
    virSecurityLabelDef *secdef = virDomainDefGetSecurityLabelDef(def,
                                                SECURITY_APPARMOR_NAME);

    if (!secdef)
        return 0;

    if ((secdef->type == VIR_DOMAIN_SECLABEL_STATIC) ||
        (secdef->type == VIR_DOMAIN_SECLABEL_NONE))
        return 0;

    if (secdef->baselabel) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       "%s", _("Cannot set a base label with AppArmour"));
        return -1;
    }

    if (secdef->label || secdef->imagelabel) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s",
                       _("security label already defined for VM"));
        return -1;
    }

    if ((profile_name = get_profile_name(def)) == NULL)
        return -1;

    secdef->label = g_strdup(profile_name);

    /* set imagelabel the same as label (but we won't use it) */
    secdef->imagelabel = g_strdup(profile_name);

    if (!secdef->model)
        secdef->model = g_strdup(SECURITY_APPARMOR_NAME);

    /* Now that we have a label, load the profile into the kernel. */
    if (load_profile(mgr, secdef->label, def, NULL, false) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot load AppArmor profile \'%1$s\'"),
                       secdef->label);
        goto err;
    }

    return 0;

 err:
    VIR_FREE(secdef->label);
    VIR_FREE(secdef->imagelabel);
    VIR_FREE(secdef->model);
    return -1;
}

static int
AppArmorSetSecurityAllLabel(virSecurityManager *mgr,
                            virDomainDef *def,
                            const char *incomingPath,
                            bool chardevStdioLogd G_GNUC_UNUSED,
                            bool migrated G_GNUC_UNUSED)
{
    virSecurityLabelDef *secdef = virDomainDefGetSecurityLabelDef(def,
                                                    SECURITY_APPARMOR_NAME);
    if (!secdef || !secdef->relabel)
        return 0;

    /* Reload the profile if incomingPath is specified. Note that
       GenSecurityLabel() will have already been run. */
    if (incomingPath)
        return reload_profile(mgr, def, incomingPath, true);

    return 0;
}

/* Seen with 'virsh dominfo <vm>'. This function only called if the VM is
 * running.
 */
static int
AppArmorGetSecurityProcessLabel(virSecurityManager *mgr G_GNUC_UNUSED,
                                virDomainDef *def,
                                pid_t pid G_GNUC_UNUSED,
                                virSecurityLabelPtr sec)
{
    int status;
    g_autofree char *profile_name = NULL;

    if ((profile_name = get_profile_name(def)) == NULL)
        return -1;

    status = profile_status(profile_name, 1);
    if (status < -1) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("error getting profile status"));
        return -1;
    } else if (status == -1) {
        sec->label[0] = '\0';
    } else {
        if (virStrcpy(sec->label, profile_name, VIR_SECURITY_LABEL_BUFLEN) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("error copying profile name"));
            return -1;
        }
    }

    sec->enforcing = status == 1;

    return 0;
}

/* Called on VM shutdown and destroy. See AppArmorGenSecurityLabel (above) for
 * more details. Currently called via qemudShutdownVMDaemon.
 */
static int
AppArmorReleaseSecurityLabel(virSecurityManager *mgr G_GNUC_UNUSED,
                             virDomainDef *def)
{
    virSecurityLabelDef *secdef = virDomainDefGetSecurityLabelDef(def,
                                                        SECURITY_APPARMOR_NAME);
    if (secdef) {
        VIR_FREE(secdef->model);
        VIR_FREE(secdef->label);
        VIR_FREE(secdef->imagelabel);
    }

    return 0;
}


static int
AppArmorRestoreSecurityAllLabel(virSecurityManager *mgr G_GNUC_UNUSED,
                                virDomainDef *def,
                                bool migrated G_GNUC_UNUSED,
                                bool chardevStdioLogd G_GNUC_UNUSED)
{
    int rc = 0;
    virSecurityLabelDef *secdef =
        virDomainDefGetSecurityLabelDef(def, SECURITY_APPARMOR_NAME);

    if (!secdef)
        return 0;

    if (secdef->type == VIR_DOMAIN_SECLABEL_DYNAMIC) {
        if ((rc = remove_profile(secdef->label)) != 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("could not remove profile for \'%1$s\'"),
                           secdef->label);
        }
    }
    return rc;
}

/* Called via virCommand hook. Output goes to
 * LOCALSTATEDIR/log/libvirt/qemu/<vm name>.log
 */
static int
AppArmorSetSecurityProcessLabel(virSecurityManager *mgr G_GNUC_UNUSED,
                                virDomainDef *def)
{
    g_autofree char *profile_name = NULL;
    virSecurityLabelDef *secdef =
        virDomainDefGetSecurityLabelDef(def, SECURITY_APPARMOR_NAME);

    if (!secdef || !secdef->label)
        return 0;

    if ((profile_name = get_profile_name(def)) == NULL)
        return -1;

    if (STRNEQ(SECURITY_APPARMOR_NAME, secdef->model)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("security label driver mismatch: \'%1$s\' model configured for domain, but hypervisor driver is \'%2$s\'."),
                       secdef->model, SECURITY_APPARMOR_NAME);
        if (use_apparmor() > 0)
            return -1;
    }

    VIR_DEBUG("Changing AppArmor profile to %s", profile_name);
    if (aa_change_profile(profile_name) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("error calling aa_change_profile()"));
        return -1;
    }

    return 0;
}

/* Called directly by API user prior to virCommandRun().
 * virCommandRun() will then call aa_change_profile() (if a
 * cmd->appArmorProfile has been set) *after forking the child
 * process*.
 */
static int
AppArmorSetSecurityChildProcessLabel(virSecurityManager *mgr G_GNUC_UNUSED,
                                     virDomainDef *def,
                                     bool useBinarySpecificLabel G_GNUC_UNUSED,
                                     virCommand *cmd)
{
    g_autofree char *profile_name = NULL;
    g_autofree char *cmd_str = NULL;
    virSecurityLabelDef *secdef =
        virDomainDefGetSecurityLabelDef(def, SECURITY_APPARMOR_NAME);

    if (!secdef || !secdef->label)
        return 0;

    if (STRNEQ(SECURITY_APPARMOR_NAME, secdef->model)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("security label driver mismatch: \'%1$s\' model configured for domain, but hypervisor driver is \'%2$s\'."),
                       secdef->model, SECURITY_APPARMOR_NAME);
        if (use_apparmor() > 0)
            return -1;
    }

    if ((profile_name = get_profile_name(def)) == NULL)
        return -1;

    cmd_str = virCommandToString(cmd, false);
    VIR_DEBUG("Changing AppArmor profile to %s on %s", profile_name, cmd_str);
    virCommandSetAppArmorProfile(cmd, profile_name);

    return 0;
}

static int
AppArmorSetSecurityDaemonSocketLabel(virSecurityManager *mgr G_GNUC_UNUSED,
                                     virDomainDef *vm G_GNUC_UNUSED)
{
    return 0;
}

static int
AppArmorSetSecuritySocketLabel(virSecurityManager *mgr G_GNUC_UNUSED,
                               virDomainDef *def G_GNUC_UNUSED)
{
    return 0;
}

static int
AppArmorClearSecuritySocketLabel(virSecurityManager *mgr G_GNUC_UNUSED,
                                 virDomainDef *def G_GNUC_UNUSED)
{
    return 0;
}


/* Called when hotplugging */
static int
AppArmorRestoreSecurityImageLabel(virSecurityManager *mgr,
                                  virDomainDef *def,
                                  virStorageSource *src,
                                  virSecurityDomainImageLabelFlags flags G_GNUC_UNUSED)
{
    if (!virStorageSourceIsLocalStorage(src))
        return 0;

    return reload_profile(mgr, def, NULL, false);
}


/* Called when hotplugging */
static int
AppArmorSetMemoryLabel(virSecurityManager *mgr,
                       virDomainDef *def,
                       virDomainMemoryDef *mem)
{
    const char *path = NULL;

    switch (mem->model) {
    case VIR_DOMAIN_MEMORY_MODEL_NVDIMM:
        path = mem->source.nvdimm.path;
        break;
    case VIR_DOMAIN_MEMORY_MODEL_VIRTIO_PMEM:
        path = mem->source.virtio_pmem.path;
        break;
    case VIR_DOMAIN_MEMORY_MODEL_NONE:
    case VIR_DOMAIN_MEMORY_MODEL_DIMM:
    case VIR_DOMAIN_MEMORY_MODEL_VIRTIO_MEM:
    case VIR_DOMAIN_MEMORY_MODEL_SGX_EPC:
    case VIR_DOMAIN_MEMORY_MODEL_LAST:
        break;
    }

    if (!path)
        return 0;

    if (!virFileExists(path)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("%1$s: \'%2$s\' does not exist"),
                       __func__, path);
        return -1;
    }
    return reload_profile(mgr, def, path, true);
}


static int
AppArmorRestoreMemoryLabel(virSecurityManager *mgr,
                           virDomainDef *def,
                           virDomainMemoryDef *mem G_GNUC_UNUSED)
{
    return reload_profile(mgr, def, NULL, false);
}

/* Called when hotplugging */
static int
AppArmorSetInputLabel(virSecurityManager *mgr,
                      virDomainDef *def,
                      virDomainInputDef *input)
{
    if (input == NULL)
        return 0;

    switch ((virDomainInputType)input->type) {
    case VIR_DOMAIN_INPUT_TYPE_PASSTHROUGH:
    case VIR_DOMAIN_INPUT_TYPE_EVDEV:
        if (input->source.evdev == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("%1$s: passthrough input device has no source"),
                           __func__);
            return -1;
        }
        if (!virFileExists(input->source.evdev)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("%1$s: \'%2$s\' does not exist"),
                           __func__, input->source.evdev);
            return -1;
        }
        return reload_profile(mgr, def, input->source.evdev, true);
        break;

    case VIR_DOMAIN_INPUT_TYPE_MOUSE:
    case VIR_DOMAIN_INPUT_TYPE_TABLET:
    case VIR_DOMAIN_INPUT_TYPE_KBD:
    case VIR_DOMAIN_INPUT_TYPE_LAST:
        break;
    }

    return 0;
}


static int
AppArmorRestoreInputLabel(virSecurityManager *mgr,
                          virDomainDef *def,
                          virDomainInputDef *input G_GNUC_UNUSED)
{
    return reload_profile(mgr, def, NULL, false);
}

/* Called when hotplugging */
static int
AppArmorSetSecurityImageLabelInternal(virSecurityManager *mgr,
                                      virDomainDef *def,
                                      virStorageSource *src)
{
    g_autofree char *vfioGroupDev = NULL;
    const char *path;

    if (src->type == VIR_STORAGE_TYPE_NVME) {
        const virStorageSourceNVMeDef *nvme = src->nvme;

        if (!(vfioGroupDev = virPCIDeviceAddressGetIOMMUGroupDev(&nvme->pciAddr)))
            return -1;

        path = vfioGroupDev;
    } else {
        if (!src->path || !virStorageSourceIsLocalStorage(src))
            return 0;

        path = src->path;
    }

    /* if the device doesn't exist, error out */
    if (!virFileExists(path)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("\'%1$s\' does not exist"),
                       path);
        return -1;
    }

    return reload_profile(mgr, def, path, true);
}

static int
AppArmorSetSecurityImageLabel(virSecurityManager *mgr,
                              virDomainDef *def,
                              virStorageSource *src,
                              virSecurityDomainImageLabelFlags flags G_GNUC_UNUSED)
{
    virSecurityLabelDef *secdef;
    virStorageSource *n;

    secdef = virDomainDefGetSecurityLabelDef(def, SECURITY_APPARMOR_NAME);
    if (!secdef || !secdef->relabel)
        return 0;

    if (!secdef->imagelabel)
        return 0;

    for (n = src; virStorageSourceIsBacking(n); n = n->backingStore) {
        if (AppArmorSetSecurityImageLabelInternal(mgr, def, n) < 0)
            return -1;
    }

    return 0;
}

static int
AppArmorSecurityVerify(virSecurityManager *mgr G_GNUC_UNUSED,
                       virDomainDef *def)
{
    virSecurityLabelDef *secdef =
        virDomainDefGetSecurityLabelDef(def, SECURITY_APPARMOR_NAME);

    if (!secdef)
        return 0;

    if (secdef->type == VIR_DOMAIN_SECLABEL_STATIC) {
        if (use_apparmor() < 0 || profile_status(secdef->label, 0) < 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Invalid security label \'%1$s\'"),
                           secdef->label);
            return -1;
        }
    }
    return 0;
}

static int
AppArmorReserveSecurityLabel(virSecurityManager *mgr G_GNUC_UNUSED,
                             virDomainDef *def G_GNUC_UNUSED,
                             pid_t pid G_GNUC_UNUSED)
{
    /* NOOP. Nothing to reserve with AppArmor */
    return 0;
}

static int
AppArmorSetSecurityHostdevLabel(virSecurityManager *mgr,
                                virDomainDef *def,
                                virDomainHostdevDef *dev,
                                const char *vroot)
{
    struct SDPDOP *ptr;
    int ret = -1;
    virSecurityLabelDef *secdef =
        virDomainDefGetSecurityLabelDef(def, SECURITY_APPARMOR_NAME);
    virDomainHostdevSubsysUSB *usbsrc = &dev->source.subsys.u.usb;
    virDomainHostdevSubsysPCI *pcisrc = &dev->source.subsys.u.pci;
    virDomainHostdevSubsysSCSI *scsisrc = &dev->source.subsys.u.scsi;
    virDomainHostdevSubsysSCSIVHost *hostsrc = &dev->source.subsys.u.scsi_host;
    virDomainHostdevSubsysMediatedDev *mdevsrc = &dev->source.subsys.u.mdev;

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

    ptr = g_new0(struct SDPDOP, 1);
    ptr->mgr = mgr;
    ptr->def = def;

    switch (dev->source.subsys.type) {
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB: {
        virUSBDevice *usb =
            virUSBDeviceNew(usbsrc->bus, usbsrc->device, vroot);
        if (!usb)
            goto done;

        ret = virUSBDeviceFileIterate(usb, AppArmorSetSecurityUSBLabel, ptr);
        virUSBDeviceFree(usb);
        break;
    }

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI: {
        virPCIDevice *pci =
            virPCIDeviceNew(&pcisrc->addr);

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
        virDomainHostdevSubsysSCSIHost *scsihostsrc = &scsisrc->u.host;
        virSCSIDevice *scsi =
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
        virSCSIVHostDevice *host = virSCSIVHostDeviceNew(hostsrc->wwpn);

        if (!host)
            goto done;

        ret = virSCSIVHostDeviceFileIterate(host,
                                            AppArmorSetSecurityHostLabel,
                                            ptr);
        virSCSIVHostDeviceFree(host);
        break;
    }

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_MDEV: {
        char *vfiodev = NULL;

        if (!(vfiodev = virMediatedDeviceGetIOMMUGroupDev(mdevsrc->uuidstr)))
            goto done;

        ret = AppArmorSetSecurityHostdevLabelHelper(vfiodev, ptr);

        VIR_FREE(vfiodev);
        break;
    }

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_LAST:
        ret = 0;
        break;
    }

 done:
    VIR_FREE(ptr);
    return ret;
}


static int
AppArmorRestoreSecurityHostdevLabel(virSecurityManager *mgr,
                                    virDomainDef *def,
                                    virDomainHostdevDef *dev G_GNUC_UNUSED,
                                    const char *vroot G_GNUC_UNUSED)

{
    virSecurityLabelDef *secdef =
        virDomainDefGetSecurityLabelDef(def, SECURITY_APPARMOR_NAME);

    if (!secdef || !secdef->relabel)
        return 0;

    return reload_profile(mgr, def, NULL, false);
}

static int
AppArmorSetChardevLabel(virSecurityManager *mgr,
                        virDomainDef *def,
                        virDomainChrSourceDef *dev_source,
                        bool chardevStdioLogd G_GNUC_UNUSED)
{
    char *in = NULL, *out = NULL;
    int ret = -1;
    virSecurityLabelDef *secdef;

    secdef = virDomainDefGetSecurityLabelDef(def, SECURITY_APPARMOR_NAME);
    if (!secdef)
        return 0;

    switch ((virDomainChrType)dev_source->type) {
    case VIR_DOMAIN_CHR_TYPE_DEV:
    case VIR_DOMAIN_CHR_TYPE_FILE:
    case VIR_DOMAIN_CHR_TYPE_UNIX:
    case VIR_DOMAIN_CHR_TYPE_PTY:
        ret = reload_profile(mgr, def, dev_source->data.file.path, true);
        break;

    case VIR_DOMAIN_CHR_TYPE_PIPE:
        in = g_strdup_printf("%s.in", dev_source->data.file.path);
        out = g_strdup_printf("%s.out", dev_source->data.file.path);
        if (virFileExists(in)) {
            if (reload_profile(mgr, def, in, true) < 0)
                goto done;
        }
        if (virFileExists(out)) {
            if (reload_profile(mgr, def, out, true) < 0)
                goto done;
        }
        ret = reload_profile(mgr, def, dev_source->data.file.path, true);
        break;

    case VIR_DOMAIN_CHR_TYPE_SPICEPORT:
    case VIR_DOMAIN_CHR_TYPE_NULL:
    case VIR_DOMAIN_CHR_TYPE_VC:
    case VIR_DOMAIN_CHR_TYPE_STDIO:
    case VIR_DOMAIN_CHR_TYPE_UDP:
    case VIR_DOMAIN_CHR_TYPE_TCP:
    case VIR_DOMAIN_CHR_TYPE_SPICEVMC:
    case VIR_DOMAIN_CHR_TYPE_NMDM:
    case VIR_DOMAIN_CHR_TYPE_QEMU_VDAGENT:
    case VIR_DOMAIN_CHR_TYPE_DBUS:
    case VIR_DOMAIN_CHR_TYPE_LAST:
        ret = 0;
        break;
    }

 done:
    VIR_FREE(in);
    VIR_FREE(out);
    return ret;
}

static int
AppArmorRestoreChardevLabel(virSecurityManager *mgr,
                            virDomainDef *def,
                            virDomainChrSourceDef *dev_source G_GNUC_UNUSED,
                            bool chardevStdioLogd G_GNUC_UNUSED)
{
    virSecurityLabelDef *secdef;

    secdef = virDomainDefGetSecurityLabelDef(def, SECURITY_APPARMOR_NAME);
    if (!secdef)
        return 0;

    return reload_profile(mgr, def, NULL, false);
}

static int
AppArmorSetNetdevLabel(virSecurityManager *mgr,
                       virDomainDef *def,
                       virDomainNetDef *net)
{
    int ret = -1;
    virSecurityLabelDef *secdef;
    virDomainChrSourceDef *dev_source;
    virDomainNetType actualType;

    secdef = virDomainDefGetSecurityLabelDef(def, SECURITY_APPARMOR_NAME);
    if (!secdef)
        return 0;

    actualType = virDomainNetGetActualType(net);
    if (actualType != VIR_DOMAIN_NET_TYPE_VHOSTUSER)
        return 0;

    dev_source = net->data.vhostuser;
    switch ((virDomainChrType)dev_source->type) {
    case VIR_DOMAIN_CHR_TYPE_UNIX:
        ret = reload_profile(mgr, def, dev_source->data.file.path, true);
        break;

    case VIR_DOMAIN_CHR_TYPE_DEV:
    case VIR_DOMAIN_CHR_TYPE_FILE:
    case VIR_DOMAIN_CHR_TYPE_PTY:
    case VIR_DOMAIN_CHR_TYPE_PIPE:
    case VIR_DOMAIN_CHR_TYPE_SPICEPORT:
    case VIR_DOMAIN_CHR_TYPE_NULL:
    case VIR_DOMAIN_CHR_TYPE_VC:
    case VIR_DOMAIN_CHR_TYPE_STDIO:
    case VIR_DOMAIN_CHR_TYPE_UDP:
    case VIR_DOMAIN_CHR_TYPE_TCP:
    case VIR_DOMAIN_CHR_TYPE_SPICEVMC:
    case VIR_DOMAIN_CHR_TYPE_NMDM:
    case VIR_DOMAIN_CHR_TYPE_QEMU_VDAGENT:
    case VIR_DOMAIN_CHR_TYPE_DBUS:
    case VIR_DOMAIN_CHR_TYPE_LAST:
        ret = 0;
        break;
    }

    return ret;
}

static int
AppArmorRestoreNetdevLabel(virSecurityManager *mgr,
                           virDomainDef *def,
                           virDomainNetDef *net G_GNUC_UNUSED)
{
    virSecurityLabelDef *secdef;

    secdef = virDomainDefGetSecurityLabelDef(def, SECURITY_APPARMOR_NAME);
    if (!secdef)
        return 0;

    return reload_profile(mgr, def, NULL, false);
}

static int
AppArmorSetPathLabel(virSecurityManager *mgr,
                           virDomainDef *def,
                           const char *path,
                           bool allowSubtree)
{
    int rc = -1;
    char *full_path = NULL;

    if (allowSubtree) {
        full_path = g_strdup_printf("%s/{,**}", path);
        rc = reload_profile(mgr, def, full_path, true);
        VIR_FREE(full_path);
    } else {
        rc = reload_profile(mgr, def, path, true);
    }

    return rc;
}

static int
AppArmorRestorePathLabel(virSecurityManager *mgr,
                         virDomainDef *def,
                         const char *path G_GNUC_UNUSED)
{
    return reload_profile(mgr, def, NULL, false);
}

static int
AppArmorSetFDLabel(virSecurityManager *mgr,
                   virDomainDef *def,
                   int fd)
{
    char *proc = NULL;
    char *fd_path = NULL;

    virSecurityLabelDef *secdef =
        virDomainDefGetSecurityLabelDef(def, SECURITY_APPARMOR_NAME);

    if (!secdef || !secdef->imagelabel)
        return 0;

    proc = g_strdup_printf("/proc/self/fd/%d", fd);

    if (virFileResolveLink(proc, &fd_path) < 0) {
        /* it's a deleted file, presumably.  Ignore? */
        VIR_WARN("could not find path for descriptor %s, skipping", proc);
        return 0;
    }

    return reload_profile(mgr, def, fd_path, true);
}

static char *
AppArmorGetMountOptions(virSecurityManager *mgr G_GNUC_UNUSED,
                        virDomainDef *vm G_GNUC_UNUSED)
{
    return g_strdup("");
}

static const char *
AppArmorGetBaseLabel(virSecurityManager *mgr G_GNUC_UNUSED,
                     int virtType G_GNUC_UNUSED)
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

    .domainSetSecurityImageLabel        = AppArmorSetSecurityImageLabel,
    .domainRestoreSecurityImageLabel    = AppArmorRestoreSecurityImageLabel,

    .domainSetSecurityMemoryLabel       = AppArmorSetMemoryLabel,
    .domainRestoreSecurityMemoryLabel   = AppArmorRestoreMemoryLabel,

    .domainSetSecurityInputLabel        = AppArmorSetInputLabel,
    .domainRestoreSecurityInputLabel    = AppArmorRestoreInputLabel,

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

    .domainSetPathLabel                 = AppArmorSetPathLabel,
    .domainRestorePathLabel             = AppArmorRestorePathLabel,

    .domainSetSecurityChardevLabel      = AppArmorSetChardevLabel,
    .domainRestoreSecurityChardevLabel  = AppArmorRestoreChardevLabel,

    .domainSetSecurityNetdevLabel       = AppArmorSetNetdevLabel,
    .domainRestoreSecurityNetdevLabel   = AppArmorRestoreNetdevLabel,

    .domainSetSecurityImageFDLabel      = AppArmorSetFDLabel,
    .domainSetSecurityTapFDLabel        = AppArmorSetFDLabel,

    .domainGetSecurityMountOptions      = AppArmorGetMountOptions,

    .getBaseLabel                       = AppArmorGetBaseLabel,
};
