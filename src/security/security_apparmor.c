
/*
 * AppArmor security driver for libvirt
 * Copyright (C) 2009 Canonical Ltd.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
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
#include <stdbool.h>

#include "internal.h"

#include "security_driver.h"
#include "security_apparmor.h"
#include "util.h"
#include "memory.h"
#include "virterror_internal.h"
#include "datatypes.h"
#include "uuid.h"

#define VIR_FROM_THIS VIR_FROM_SECURITY
#define SECURITY_APPARMOR_VOID_DOI      "0"
#define SECURITY_APPARMOR_NAME          "apparmor"
#define VIRT_AA_HELPER BINDIR "/virt-aa-helper"

/*
 * profile_status returns '-1' on error, '0' if loaded
 *
 * If check_enforcing is set to '1', then returns '-1' on error, '0' if
 * loaded in complain mode, and '1' if loaded in enforcing mode.
 */
static int
profile_status(const char *str, const int check_enforcing)
{
    char *content = NULL;
    char *tmp = NULL;
    char *etmp = NULL;
    int rc = -1;

    /* create string that is '<str> \0' for accurate matching */
    if (virAsprintf(&tmp, "%s ", str) == -1) {
        virReportOOMError(NULL);
        return rc;
    }

    if (check_enforcing != 0) {
        /* create string that is '<str> (enforce)\0' for accurate matching */
        if (virAsprintf(&etmp, "%s (enforce)", str) == -1) {
            VIR_FREE(tmp);
            virReportOOMError(NULL);
            return rc;
        }
    }

    if (virFileReadAll(APPARMOR_PROFILES_PATH, MAX_FILE_LEN, &content) < 0) {
        virReportSystemError(NULL, errno,
                             _("Failed to read AppArmor profiles list "
                             "\'%s\'"), APPARMOR_PROFILES_PATH);
        goto clean;
    }

    if (strstr(content, tmp) != NULL)
        rc = 0;
    if (check_enforcing != 0) {
        if (rc == 0 && strstr(content, etmp) != NULL)
            rc = 1;                 /* return '1' if loaded and enforcing */
    }

    VIR_FREE(content);
  clean:
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

    if (virAsprintf(&profile, "%s/%s", APPARMOR_DIR "/libvirt", str) == -1) {
        virReportOOMError(NULL);
        return rc;
    }

    if (!virFileExists(profile))
        goto failed;

    if ((len = virFileReadAll(profile, MAX_FILE_LEN, &content)) < 0) {
        virReportSystemError(NULL, errno,
                             _("Failed to read \'%s\'"), profile);
        goto failed;
    }

    /* create string that is ' <str> flags=(complain)\0' */
    if (virAsprintf(&tmp, " %s flags=(complain)", str) == -1) {
        virReportOOMError(NULL);
        goto failed;
    }

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
load_profile(virConnectPtr conn, const char *profile, virDomainObjPtr vm,
             virDomainDiskDefPtr disk)
{
    int rc = -1, status, ret;
    bool create = true;
    char *xml = NULL;
    int pipefd[2];
    pid_t child;

    if (pipe(pipefd) < -1) {
        virReportSystemError(conn, errno, "%s", _("unable to create pipe"));
        return rc;
    }

    xml = virDomainDefFormat(conn, vm->def, VIR_DOMAIN_XML_SECURE);
    if (!xml)
        goto clean;

    if (profile_status_file(profile) >= 0)
        create = false;

    if (create) {
        const char *const argv[] = {
            VIRT_AA_HELPER, "-c", "-u", profile, NULL
        };
        ret = virExec(conn, argv, NULL, NULL, &child,
                      pipefd[0], NULL, NULL, VIR_EXEC_CLEAR_CAPS);
    } else if (disk && disk->src) {
        const char *const argv[] = {
            VIRT_AA_HELPER, "-r", "-u", profile, "-f", disk->src, NULL
        };
        ret = virExec(conn, argv, NULL, NULL, &child,
                      pipefd[0], NULL, NULL, VIR_EXEC_CLEAR_CAPS);
    } else {
        const char *const argv[] = {
            VIRT_AA_HELPER, "-r", "-u", profile, NULL
        };
        ret = virExec(conn, argv, NULL, NULL, &child,
                      pipefd[0], NULL, NULL, VIR_EXEC_CLEAR_CAPS);
    }
    if (ret < 0)
        goto clean;

    /* parent continues here */
    if (safewrite(pipefd[1], xml, strlen(xml)) < 0) {
        virReportSystemError(conn, errno, "%s", _("unable to write to pipe"));
        goto clean;
    }
    close(pipefd[1]);
    rc = 0;

  rewait:
    if (waitpid(child, &status, 0) != child) {
        if (errno == EINTR)
            goto rewait;

        virSecurityReportError(conn, VIR_ERR_INTERNAL_ERROR,
                               _("Unexpected exit status from virt-aa-helper "
                               "%d pid %lu"),
                               WEXITSTATUS(status), (unsigned long)child);
        rc = -1;
    }

  clean:
    VIR_FREE(xml);

    if (pipefd[0] > 0)
        close(pipefd[0]);
    if (pipefd[1] > 0)
        close(pipefd[1]);

    return rc;
}

static int
remove_profile(const char *profile)
{
    int rc = -1;
    const char * const argv[] = {
        VIRT_AA_HELPER, "-R", "-u", profile, NULL
    };

    if (virRun(NULL, argv, NULL) == 0)
        rc = 0;

    return rc;
}

static char *
get_profile_name(virConnectPtr conn, virDomainObjPtr vm)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    char *name = NULL;

    virUUIDFormat(vm->def->uuid, uuidstr);
    if (virAsprintf(&name, "%s%s", AA_PREFIX, uuidstr) < 0) {
        virReportOOMError(conn);
        return NULL;
    }

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
        virSecurityReportError(NULL, VIR_ERR_INTERNAL_ERROR,
                               "%s", _("could not find libvirtd"));
        return rc;
    }

    if (access(APPARMOR_PROFILES_PATH, R_OK) != 0)
        goto cleanup;

    rc = profile_status(libvirt_daemon, 1);

cleanup:
    VIR_FREE(libvirt_daemon);
    return rc;
}

/* Called on libvirtd startup to see if AppArmor is available */
static int
AppArmorSecurityDriverProbe(void)
{
    char *template = NULL;
    int rc = SECURITY_DRIVER_DISABLE;

    if (use_apparmor() < 0)
        return rc;

    /* see if template file exists */
    if (virAsprintf(&template, "%s/TEMPLATE",
                               APPARMOR_DIR "/libvirt") == -1) {
        virReportOOMError(NULL);
        return rc;
    }

    if (!virFileExists(template)) {
        virSecurityReportError(NULL, VIR_ERR_INTERNAL_ERROR,
                               _("template \'%s\' does not exist"), template);
        goto clean;
    }
    rc = SECURITY_DRIVER_ENABLE;

  clean:
    VIR_FREE(template);

    return rc;
}

/* Security driver initialization. DOI is for 'Domain of Interpretation' and is
 * currently not used.
 */
static int
AppArmorSecurityDriverOpen(virConnectPtr conn, virSecurityDriverPtr drv)
{
    virSecurityDriverSetDOI(conn, drv, SECURITY_APPARMOR_VOID_DOI);
    return 0;
}

/* Currently called in qemudStartVMDaemon to setup a 'label'. We look for and
 * use a profile based on the UUID, otherwise create one based on a template.
 * Keep in mind that this is called on 'start' with RestoreSecurityLabel being
 * called on shutdown.
*/
static int
AppArmorGenSecurityLabel(virConnectPtr conn, virDomainObjPtr vm)
{
    int rc = -1;
    char *profile_name = NULL;

    if (vm->def->seclabel.type == VIR_DOMAIN_SECLABEL_STATIC)
        return 0;

    if ((vm->def->seclabel.label) ||
        (vm->def->seclabel.model) || (vm->def->seclabel.imagelabel)) {
        virSecurityReportError(conn, VIR_ERR_INTERNAL_ERROR,
                               "%s",
                               _("security label already defined for VM"));
        return rc;
    }

    if ((profile_name = get_profile_name(conn, vm)) == NULL)
        return rc;

    vm->def->seclabel.label = strndup(profile_name, strlen(profile_name));
    if (!vm->def->seclabel.label) {
        virReportOOMError(NULL);
        goto clean;
    }

    /* set imagelabel the same as label (but we won't use it) */
    vm->def->seclabel.imagelabel = strndup(profile_name,
                                           strlen(profile_name));
    if (!vm->def->seclabel.imagelabel) {
        virReportOOMError(NULL);
        goto err;
    }

    vm->def->seclabel.model = strdup(SECURITY_APPARMOR_NAME);
    if (!vm->def->seclabel.model) {
        virReportOOMError(conn);
        goto err;
    }

    rc = 0;
    goto clean;

  err:
    VIR_FREE(vm->def->seclabel.label);
    VIR_FREE(vm->def->seclabel.imagelabel);
    VIR_FREE(vm->def->seclabel.model);

  clean:
    VIR_FREE(profile_name);

    return rc;
}

static int
AppArmorSetSecurityAllLabel(virConnectPtr conn, virDomainObjPtr vm)
{
    if (vm->def->seclabel.type == VIR_DOMAIN_SECLABEL_STATIC)
        return 0;

    /* if the profile is not already loaded, then load one */
    if (profile_loaded(vm->def->seclabel.label) < 0) {
        if (load_profile(conn, vm->def->seclabel.label, vm, NULL) < 0) {
            virSecurityReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                   _("cannot generate AppArmor profile "
                                   "\'%s\'"), vm->def->seclabel.label);
            return -1;
        }
    }

    return 0;
}

/* Seen with 'virsh dominfo <vm>'. This function only called if the VM is
 * running.
 */
static int
AppArmorGetSecurityProcessLabel(virConnectPtr conn,
                                virDomainObjPtr vm, virSecurityLabelPtr sec)
{
    int rc = -1;
    char *profile_name = NULL;

    if ((profile_name = get_profile_name(conn, vm)) == NULL)
        return rc;

    if (virStrcpy(sec->label, profile_name,
        VIR_SECURITY_LABEL_BUFLEN) == NULL) {
        virSecurityReportError(conn, VIR_ERR_INTERNAL_ERROR,
                               "%s", _("error copying profile name"));
        goto clean;
    }

    if ((sec->enforcing = profile_status(profile_name, 1)) < 0) {
        virSecurityReportError(conn, VIR_ERR_INTERNAL_ERROR,
                               "%s", _("error calling profile_status()"));
        goto clean;
    }
    rc = 0;

  clean:
    VIR_FREE(profile_name);

    return rc;
}

/* Called on VM shutdown and destroy. See AppArmorGenSecurityLabel (above) for
 * more details. Currently called via qemudShutdownVMDaemon.
 */
static int
AppArmorReleaseSecurityLabel(virConnectPtr conn ATTRIBUTE_UNUSED, virDomainObjPtr vm)
{
    const virSecurityLabelDefPtr secdef = &vm->def->seclabel;

    VIR_FREE(secdef->model);
    VIR_FREE(secdef->label);
    VIR_FREE(secdef->imagelabel);

    return 0;
}


static int
AppArmorRestoreSecurityAllLabel(virConnectPtr conn, virDomainObjPtr vm)
{
    const virSecurityLabelDefPtr secdef = &vm->def->seclabel;
    int rc = 0;

    if (secdef->type == VIR_DOMAIN_SECLABEL_DYNAMIC) {
        if ((rc = remove_profile(secdef->label)) != 0) {
            virSecurityReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                   _("could not remove profile for \'%s\'"),
                                   secdef->label);
        }
    }
    return rc;
}

/* Called via virExecWithHook. Output goes to
 * LOCAL_STATE_DIR/log/libvirt/qemu/<vm name>.log
 */
static int
AppArmorSetSecurityProcessLabel(virConnectPtr conn,
                                virSecurityDriverPtr drv, virDomainObjPtr vm)
{
    const virSecurityLabelDefPtr secdef = &vm->def->seclabel;
    int rc = -1;
    char *profile_name = NULL;

    if ((profile_name = get_profile_name(conn, vm)) == NULL)
        return rc;

    if (STRNEQ(drv->name, secdef->model)) {
        virSecurityReportError(conn, VIR_ERR_INTERNAL_ERROR,
                               _("security label driver mismatch: "
                               "\'%s\' model configured for domain, but "
                               "hypervisor driver is \'%s\'."),
                               secdef->model, drv->name);
        if (use_apparmor() > 0)
            goto clean;
    }

    if (aa_change_profile(profile_name) < 0) {
        virSecurityReportError(conn, VIR_ERR_INTERNAL_ERROR,
                               _("error calling aa_change_profile()"));
        goto clean;
    }
    rc = 0;

  clean:
    VIR_FREE(profile_name);

    return rc;
}


/* Called when hotplugging */
static int
AppArmorRestoreSecurityImageLabel(virConnectPtr conn,
                                  virDomainObjPtr vm,
                                  virDomainDiskDefPtr disk ATTRIBUTE_UNUSED)
{
    const virSecurityLabelDefPtr secdef = &vm->def->seclabel;
    int rc = -1;
    char *profile_name = NULL;

    if (secdef->type == VIR_DOMAIN_SECLABEL_STATIC)
        return 0;

    if ((profile_name = get_profile_name(conn, vm)) == NULL)
        return rc;

    /* Update the profile only if it is loaded */
    if (profile_loaded(secdef->imagelabel) >= 0) {
        if (load_profile(conn, secdef->imagelabel, vm, NULL) < 0) {
            virSecurityReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                   _("cannot update AppArmor profile "
                                     "\'%s\'"),
                                   secdef->imagelabel);
            goto clean;
        }
    }

    rc = 0;
  clean:
    VIR_FREE(profile_name);

    return rc;
}

/* Called when hotplugging */
static int
AppArmorSetSecurityImageLabel(virConnectPtr conn,
                              virDomainObjPtr vm, virDomainDiskDefPtr disk)
{
    const virSecurityLabelDefPtr secdef = &vm->def->seclabel;
    int rc = -1;
    char *profile_name;

    if (secdef->type == VIR_DOMAIN_SECLABEL_STATIC)
        return 0;

    if (!disk->src)
        return 0;

    if (secdef->imagelabel) {
        /* if the device doesn't exist, error out */
        if (!virFileExists(disk->src)) {
            virSecurityReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                   _("\'%s\' does not exist"), disk->src);
            return rc;
        }

        if ((profile_name = get_profile_name(conn, vm)) == NULL)
            return rc;

        /* update the profile only if it is loaded */
        if (profile_loaded(secdef->imagelabel) >= 0) {
            if (load_profile(conn, secdef->imagelabel, vm, disk) < 0) {
                virSecurityReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                     _("cannot update AppArmor profile "
                                     "\'%s\'"),
                                     secdef->imagelabel);
                goto clean;
            }
        }
    }
    rc = 0;

  clean:
    VIR_FREE(profile_name);

    return rc;
}

static int
AppArmorSecurityVerify(virConnectPtr conn, virDomainDefPtr def)
{
    const virSecurityLabelDefPtr secdef = &def->seclabel;

    if (secdef->type == VIR_DOMAIN_SECLABEL_STATIC) {
        if (use_apparmor() < 0 || profile_status(secdef->label, 0) < 0) {
            virSecurityReportError(conn, VIR_ERR_XML_ERROR,
                                   _("Invalid security label \'%s\'"),
                                   secdef->label);
            return -1;
        }
    }
    return 0;
}

static int
AppArmorReserveSecurityLabel(virConnectPtr conn ATTRIBUTE_UNUSED,
                            virDomainObjPtr vm ATTRIBUTE_UNUSED)
{
    /* NOOP. Nothing to reserve with AppArmor */
    return 0;
}

static int
AppArmorSetSecurityHostdevLabel(virConnectPtr conn ATTRIBUTE_UNUSED,
                                virDomainObjPtr vm,
                                virDomainHostdevDefPtr dev ATTRIBUTE_UNUSED)

{
    const virSecurityLabelDefPtr secdef = &vm->def->seclabel;

    if (secdef->type == VIR_DOMAIN_SECLABEL_STATIC)
        return 0;

    /* TODO: call load_profile with an update vm->def */
    return 0;
}

static int
AppArmorRestoreSecurityHostdevLabel(virConnectPtr conn ATTRIBUTE_UNUSED,
                                    virDomainObjPtr vm,
                                    virDomainHostdevDefPtr dev ATTRIBUTE_UNUSED)

{
    const virSecurityLabelDefPtr secdef = &vm->def->seclabel;
    if (secdef->type == VIR_DOMAIN_SECLABEL_STATIC)
        return 0;

    /* TODO: call load_profile (needs virDomainObjPtr vm) */
    return 0;
}

virSecurityDriver virAppArmorSecurityDriver = {
    .name = SECURITY_APPARMOR_NAME,
    .probe = AppArmorSecurityDriverProbe,
    .open = AppArmorSecurityDriverOpen,
    .domainSecurityVerify = AppArmorSecurityVerify,
    .domainSetSecurityImageLabel = AppArmorSetSecurityImageLabel,
    .domainRestoreSecurityImageLabel = AppArmorRestoreSecurityImageLabel,
    .domainGenSecurityLabel = AppArmorGenSecurityLabel,
    .domainReserveSecurityLabel = AppArmorReserveSecurityLabel,
    .domainReleaseSecurityLabel = AppArmorReleaseSecurityLabel,
    .domainGetSecurityProcessLabel = AppArmorGetSecurityProcessLabel,
    .domainSetSecurityProcessLabel = AppArmorSetSecurityProcessLabel,
    .domainRestoreSecurityAllLabel = AppArmorRestoreSecurityAllLabel,
    .domainSetSecurityAllLabel = AppArmorSetSecurityAllLabel,
    .domainSetSecurityHostdevLabel = AppArmorSetSecurityHostdevLabel,
    .domainRestoreSecurityHostdevLabel = AppArmorRestoreSecurityHostdevLabel,
};
