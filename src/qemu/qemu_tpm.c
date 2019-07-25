/*
 * qemu_tpm.c: QEMU TPM support
 *
 * Copyright (C) 2018 IBM Corporation
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

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>

#include "qemu_extdevice.h"
#include "qemu_domain.h"
#include "qemu_security.h"

#include "conf/domain_conf.h"
#include "vircommand.h"
#include "viralloc.h"
#include "virkmod.h"
#include "virlog.h"
#include "virutil.h"
#include "viruuid.h"
#include "virfile.h"
#include "virstring.h"
#include "virpidfile.h"
#include "configmake.h"
#include "dirname.h"
#include "qemu_tpm.h"
#include "virtpm.h"
#include "secret_util.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("qemu.tpm");

/*
 * qemuTPMCreateEmulatorStoragePath
 *
 * @swtpmStorageDir: directory for swtpm persistent state
 * @uuid: The UUID of the VM for which to create the storage
 * @tpmversion: version of the TPM
 *
 * Create the swtpm's storage path
 */
static char *
qemuTPMCreateEmulatorStoragePath(const char *swtpmStorageDir,
                                 const char *uuidstr,
                                 virDomainTPMVersion tpmversion)
{
    char *path = NULL;
    const char *dir = "";

    switch (tpmversion) {
    case VIR_DOMAIN_TPM_VERSION_1_2:
        dir = "tpm1.2";
        break;
    case VIR_DOMAIN_TPM_VERSION_2_0:
        dir = "tpm2";
        break;
    case VIR_DOMAIN_TPM_VERSION_DEFAULT:
    case VIR_DOMAIN_TPM_VERSION_LAST:
        return NULL;
    }

    ignore_value(virAsprintf(&path, "%s/%s/%s", swtpmStorageDir, uuidstr,
                             dir));

    return path;
}


/*
 * virtTPMGetTPMStorageDir:
 *
 * @storagepath: directory for swtpm's persistent state
 *
 * Derive the 'TPMStorageDir' from the storagepath by searching
 * for the last '/'.
 */
static char *
qemuTPMGetTPMStorageDir(const char *storagepath)
{
    char *ret = mdir_name(storagepath);

    if (!ret)
        virReportOOMError();

    return ret;
}


/*
 * qemuTPMEmulatorInitStorage
 *
 * Initialize the TPM Emulator storage by creating its root directory,
 * which is typically found in /var/lib/libvirt/tpm.
 *
 */
static int
qemuTPMEmulatorInitStorage(const char *swtpmStorageDir)
{
    int rc = 0;

    /* allow others to cd into this dir */
    if (virFileMakePathWithMode(swtpmStorageDir, 0711) < 0) {
        virReportSystemError(errno,
                             _("Could not create TPM directory %s"),
                             swtpmStorageDir);
        rc = -1;
    }

    return rc;
}


/*
 * qemuTPMCreateEmulatorStorage
 *
 * @storagepath: directory for swtpm's persistent state
 * @created: a pointer to a bool that will be set to true if the
 *           storage was created because it did not exist yet
 * @swtpm_user: The uid that needs to be able to access the directory
 * @swtpm_group: The gid that needs to be able to access the directory
 *
 * Unless the storage path for the swtpm for the given VM
 * already exists, create it and make it accessible for the given userid.
 * Adapt ownership of the directory and all swtpm's state files there.
 */
static int
qemuTPMCreateEmulatorStorage(const char *storagepath,
                             bool *created,
                             uid_t swtpm_user,
                             gid_t swtpm_group)
{
    int ret = -1;
    char *swtpmStorageDir = qemuTPMGetTPMStorageDir(storagepath);

    if (!swtpmStorageDir)
        return -1;

    if (qemuTPMEmulatorInitStorage(swtpmStorageDir) < 0)
        goto cleanup;

    *created = false;

    if (!virFileExists(storagepath))
        *created = true;

    if (virDirCreate(storagepath, 0700, swtpm_user, swtpm_group,
                     VIR_DIR_CREATE_ALLOW_EXIST) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not create directory %s as %u:%d"),
                       storagepath, swtpm_user, swtpm_group);
        goto cleanup;
    }

    if (virFileChownFiles(storagepath, swtpm_user, swtpm_group) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    VIR_FREE(swtpmStorageDir);

    return ret;
}


static void
qemuTPMDeleteEmulatorStorage(virDomainTPMDefPtr tpm)
{
    char *path = qemuTPMGetTPMStorageDir(tpm->data.emulator.storagepath);

    if (path) {
        ignore_value(virFileDeleteTree(path));
        VIR_FREE(path);
    }
}


/*
 * qemuTPMCreateEmulatorSocket:
 *
 * @swtpmStateDir: the directory where to create the socket in
 * @shortName: short and unique name of the domain
 *
 * Create the Unix socket path from the given parameters
 */
static char *
qemuTPMCreateEmulatorSocket(const char *swtpmStateDir,
                            const char *shortName)
{
    char *path = NULL;

    ignore_value(virAsprintf(&path, "%s/%s-swtpm.sock", swtpmStateDir,
                             shortName));

    return path;
}


/*
 * qemuTPMEmulatorInitPaths:
 *
 * @tpm: TPM definition for an emulator type
 * @swtpmStorageDir: the general swtpm storage dir which is used as a base
 *                   directory for creating VM specific directories
 * @uuid: the UUID of the VM
 */
static int
qemuTPMEmulatorInitPaths(virDomainTPMDefPtr tpm,
                         const char *swtpmStorageDir,
                         const unsigned char *uuid)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    virUUIDFormat(uuid, uuidstr);

    if (!tpm->data.emulator.storagepath &&
        !(tpm->data.emulator.storagepath =
            qemuTPMCreateEmulatorStoragePath(swtpmStorageDir, uuidstr,
                                             tpm->version)))
        return -1;

    return 0;
}


/*
 * qemuTPMCreatePidFilename
 */
static char *
qemuTPMEmulatorCreatePidFilename(const char *swtpmStateDir,
                                 const char *shortName)
{
    char *pidfile = NULL;
    char *devicename = NULL;

    if (virAsprintf(&devicename, "%s-swtpm", shortName) < 0)
        return NULL;

    pidfile = virPidFileBuildPath(swtpmStateDir, devicename);

    VIR_FREE(devicename);

    return pidfile;
}


/*
 * qemuTPMEmulatorGetPid
 *
 * @swtpmStateDir: the directory where swtpm writes the pidfile into
 * @shortName: short name of the domain
 * @pid: pointer to pid
 *
 * Return -errno upon error, or zero on successful reading of the pidfile.
 * If the PID was not still alive, zero will be returned, and @pid will be
 * set to -1;
 */
static int
qemuTPMEmulatorGetPid(const char *swtpmStateDir,
                      const char *shortName,
                      pid_t *pid)
{
    int ret;
    VIR_AUTOFREE(char *) swtpm = virTPMGetSwtpm();
    char *pidfile = qemuTPMEmulatorCreatePidFilename(swtpmStateDir,
                                                     shortName);
    if (!pidfile)
        return -ENOMEM;

    ret = virPidFileReadPathIfAlive(pidfile, pid, swtpm);

    VIR_FREE(pidfile);

    return ret;
}


/*
 * qemuTPMEmulatorPrepareHost:
 *
 * @tpm: tpm definition
 * @logDir: directory where swtpm writes its logs into
 * @vmname: name of the VM
 * @swtpm_user: uid to run the swtpm with
 * @swtpm_group: gid to run the swtpm with
 * @swtpmStateDir: directory for swtpm's persistent state
 * @qemu_user: uid that qemu will run with; we share the socket file with it
 * @shortName: short and unique name of the domain
 *
 * Prepare the log directory for the swtpm and adjust ownership of it and the
 * log file we will be using. Prepare the state directory where we will share
 * the socket between tss and qemu users.
 */
static int
qemuTPMEmulatorPrepareHost(virDomainTPMDefPtr tpm,
                           const char *logDir,
                           const char *vmname,
                           uid_t swtpm_user,
                           gid_t swtpm_group,
                           const char *swtpmStateDir,
                           uid_t qemu_user,
                           const char *shortName)
{
    int ret = -1;

    if (virTPMEmulatorInit() < 0)
        return -1;

    /* create log dir ... allow 'tss' user to cd into it */
    if (virFileMakePathWithMode(logDir, 0711) < 0)
        return -1;

    /* ... and adjust ownership */
    if (virDirCreate(logDir, 0730, swtpm_user, swtpm_group,
                     VIR_DIR_CREATE_ALLOW_EXIST) < 0)
        goto cleanup;

    /* create logfile name ... */
    if (!tpm->data.emulator.logfile &&
        virAsprintf(&tpm->data.emulator.logfile, "%s/%s-swtpm.log",
                    logDir, vmname) < 0)
        goto cleanup;

    /* ... and make sure it can be accessed by swtpm_user */
    if (virFileExists(tpm->data.emulator.logfile) &&
        chown(tpm->data.emulator.logfile, swtpm_user, swtpm_group) < 0) {
        virReportSystemError(errno,
                             _("Could not chown on swtpm logfile %s"),
                             tpm->data.emulator.logfile);
        goto cleanup;
    }

    /*
      create our swtpm state dir ...
      - QEMU user needs to be able to access the socket there
      - swtpm group needs to be able to create files there
      - in privileged mode 0570 would be enough, for non-privileged mode
        we need 0770
    */
    if (virDirCreate(swtpmStateDir, 0770, qemu_user, swtpm_group,
                     VIR_DIR_CREATE_ALLOW_EXIST) < 0)
        goto cleanup;

    /* create the socket filename */
    if (!tpm->data.emulator.source.data.nix.path &&
        !(tpm->data.emulator.source.data.nix.path =
          qemuTPMCreateEmulatorSocket(swtpmStateDir, shortName)))
        goto cleanup;
    tpm->data.emulator.source.type = VIR_DOMAIN_CHR_TYPE_UNIX;

    ret = 0;

 cleanup:

    return ret;
}

/*
 * qemuTPMSetupEncryption
 *
 * @secretuuid: The UUID with the secret holding passphrase
 * @cmd: the virCommand to transfer the secret to
 *
 * Returns file descriptor representing the read-end of a pipe.
 * The passphrase can be read from this pipe. Returns < 0 in case
 * of error.
 *
 * This function reads the passphrase and writes it into the
 * write-end of a pipe so that the read-end of the pipe can be
 * passed to the emulator for reading the passphrase from.
 */
static int
qemuTPMSetupEncryption(const unsigned char *secretuuid,
                       virCommandPtr cmd)
{
    int ret = -1;
    int pipefd[2] = { -1, -1 };
    virConnectPtr conn;
    VIR_AUTOFREE(uint8_t *) secret = NULL;
    size_t secret_len;
    virSecretLookupTypeDef seclookupdef = {
         .type = VIR_SECRET_LOOKUP_TYPE_UUID,
    };

    conn = virGetConnectSecret();
    if (!conn)
        return -1;

    memcpy(seclookupdef.u.uuid, secretuuid, sizeof(seclookupdef.u.uuid));
    if (virSecretGetSecretString(conn, &seclookupdef,
                                 VIR_SECRET_USAGE_TYPE_VTPM,
                                 &secret, &secret_len) < 0)
        goto error;

    if (pipe(pipefd) == -1) {
        virReportSystemError(errno, "%s",
                             _("Unable to create pipe"));
        goto error;
    }

    if (virCommandSetSendBuffer(cmd, pipefd[1], secret, secret_len) < 0)
        goto error;

    secret = NULL;
    ret = pipefd[0];

 cleanup:
    virObjectUnref(conn);

    return ret;

 error:
    VIR_FORCE_CLOSE(pipefd[1]);
    VIR_FORCE_CLOSE(pipefd[0]);

    goto cleanup;
}

/*
 * qemuTPMEmulatorRunSetup
 *
 * @storagepath: path to the directory for TPM state
 * @vmname: the name of the VM
 * @vmuuid: the UUID of the VM
 * @privileged: whether we are running in privileged mode
 * @swtpm_user: The userid to switch to when setting up the TPM;
 *              typically this should be the uid of 'tss' or 'root'
 * @swtpm_group: The group id to switch to
 * @logfile: The file to write the log into; it must be writable
 *           for the user given by userid or 'tss'
 * @tpmversion: The version of the TPM, either a TPM 1.2 or TPM 2
 * @encryption: pointer to virStorageEncryption holding secret
 *
 * Setup the external swtpm by creating endorsement key and
 * certificates for it.
 */
static int
qemuTPMEmulatorRunSetup(const char *storagepath,
                        const char *vmname,
                        const unsigned char *vmuuid,
                        bool privileged,
                        uid_t swtpm_user,
                        gid_t swtpm_group,
                        const char *logfile,
                        const virDomainTPMVersion tpmversion,
                        const unsigned char *secretuuid)
{
    virCommandPtr cmd = NULL;
    int exitstatus;
    int ret = -1;
    char uuid[VIR_UUID_STRING_BUFLEN];
    char *vmid = NULL;
    VIR_AUTOFREE(char *)swtpm_setup = virTPMGetSwtpmSetup();
    VIR_AUTOCLOSE pwdfile_fd = -1;

    if (!swtpm_setup)
        return -1;

    if (!privileged && tpmversion == VIR_DOMAIN_TPM_VERSION_1_2)
        return virFileWriteStr(logfile,
                               _("Did not create EK and certificates since "
                                 "this requires privileged mode for a "
                                 "TPM 1.2\n"), 0600);

    cmd = virCommandNew(swtpm_setup);
    if (!cmd)
        goto cleanup;

    virUUIDFormat(vmuuid, uuid);
    if (virAsprintf(&vmid, "%s:%s", vmname, uuid) < 0)
        goto cleanup;

    virCommandSetUID(cmd, swtpm_user);
    virCommandSetGID(cmd, swtpm_group);

    switch (tpmversion) {
    case VIR_DOMAIN_TPM_VERSION_1_2:
        break;
    case VIR_DOMAIN_TPM_VERSION_2_0:
        virCommandAddArgList(cmd, "--tpm2", NULL);
        break;
    case VIR_DOMAIN_TPM_VERSION_DEFAULT:
    case VIR_DOMAIN_TPM_VERSION_LAST:
        break;
    }

    if (secretuuid) {
        if (!virTPMSwtpmSetupCapsGet(
                VIR_TPM_SWTPM_SETUP_FEATURE_CMDARG_PWDFILE_FD)) {
            virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED,
                _("%s does not support passing a passphrase using a file "
                  "descriptor"), virTPMGetSwtpmSetup());
            goto cleanup;
        }
        if ((pwdfile_fd = qemuTPMSetupEncryption(secretuuid, cmd)) < 0)
            goto cleanup;

        virCommandAddArg(cmd, "--pwdfile-fd");
        virCommandAddArgFormat(cmd, "%d", pwdfile_fd);
        virCommandAddArgList(cmd, "--cipher", "aes-256-cbc", NULL);
        virCommandPassFD(cmd, pwdfile_fd, VIR_COMMAND_PASS_FD_CLOSE_PARENT);
        pwdfile_fd = -1;
    }

    virCommandAddArgList(cmd,
                         "--tpm-state", storagepath,
                         "--vmid", vmid,
                         "--logfile", logfile,
                         "--createek",
                         "--create-ek-cert",
                         "--create-platform-cert",
                         "--lock-nvram",
                         "--not-overwrite",
                         NULL);

    virCommandClearCaps(cmd);

    if (virCommandRun(cmd, &exitstatus) < 0 || exitstatus != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not run '%s'. exitstatus: %d; "
                         "Check error log '%s' for details."),
                          swtpm_setup, exitstatus, logfile);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(vmid);
    virCommandFree(cmd);

    return ret;
}


/*
 * qemuTPMEmulatorBuildCommand:
 *
 * @tpm: TPM definition
 * @vmname: The name of the VM
 * @vmuuid: The UUID of the VM
 * @privileged: whether we are running in privileged mode
 * @swtpm_user: The uid for the swtpm to run as (drop privileges to from root)
 * @swtpm_group: The gid for the swtpm to run as
 * @swtpmStateDir: the directory where swtpm writes the pid file and creates the
 *                 Unix socket
 * @shortName: the short name of the VM
 *
 * Create the virCommand use for starting the emulator
 * Do some initializations on the way, such as creation of storage
 * and emulator setup.
 */
static virCommandPtr
qemuTPMEmulatorBuildCommand(virDomainTPMDefPtr tpm,
                            const char *vmname,
                            const unsigned char *vmuuid,
                            bool privileged,
                            uid_t swtpm_user,
                            gid_t swtpm_group,
                            const char *swtpmStateDir,
                            const char *shortName)
{
    virCommandPtr cmd = NULL;
    bool created = false;
    char *pidfile;
    VIR_AUTOFREE(char *) swtpm = virTPMGetSwtpm();
    VIR_AUTOCLOSE pwdfile_fd = -1;
    const unsigned char *secretuuid = NULL;

    if (!swtpm)
        return NULL;

    if (qemuTPMCreateEmulatorStorage(tpm->data.emulator.storagepath,
                                     &created, swtpm_user, swtpm_group) < 0)
        return NULL;

    if (tpm->data.emulator.hassecretuuid)
        secretuuid = tpm->data.emulator.secretuuid;

    if (created &&
        qemuTPMEmulatorRunSetup(tpm->data.emulator.storagepath, vmname, vmuuid,
                                privileged, swtpm_user, swtpm_group,
                                tpm->data.emulator.logfile, tpm->version,
                                secretuuid) < 0)
        goto error;

    unlink(tpm->data.emulator.source.data.nix.path);

    cmd = virCommandNew(swtpm);
    if (!cmd)
        goto error;

    virCommandClearCaps(cmd);

    virCommandAddArgList(cmd, "socket", "--daemon", "--ctrl", NULL);
    virCommandAddArgFormat(cmd, "type=unixio,path=%s,mode=0600",
                           tpm->data.emulator.source.data.nix.path);

    virCommandAddArg(cmd, "--tpmstate");
    virCommandAddArgFormat(cmd, "dir=%s,mode=0600",
                           tpm->data.emulator.storagepath);

    virCommandAddArg(cmd, "--log");
    virCommandAddArgFormat(cmd, "file=%s", tpm->data.emulator.logfile);

    virCommandSetUID(cmd, swtpm_user);
    virCommandSetGID(cmd, swtpm_group);

    switch (tpm->version) {
    case VIR_DOMAIN_TPM_VERSION_1_2:
        break;
    case VIR_DOMAIN_TPM_VERSION_2_0:
        virCommandAddArg(cmd, "--tpm2");
        break;
    case VIR_DOMAIN_TPM_VERSION_DEFAULT:
    case VIR_DOMAIN_TPM_VERSION_LAST:
        break;
    }

    if (!(pidfile = qemuTPMEmulatorCreatePidFilename(swtpmStateDir, shortName)))
        goto error;

    virCommandAddArg(cmd, "--pid");
    virCommandAddArgFormat(cmd, "file=%s", pidfile);
    VIR_FREE(pidfile);

    if (tpm->data.emulator.hassecretuuid) {
        if (!virTPMSwtpmCapsGet(VIR_TPM_SWTPM_FEATURE_CMDARG_PWD_FD)) {
            virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED,
                  _("%s does not support passing passphrase via file descriptor"),
                  virTPMGetSwtpm());
            goto error;
        }

        pwdfile_fd = qemuTPMSetupEncryption(tpm->data.emulator.secretuuid, cmd);
        if (pwdfile_fd)
            goto error;

        virCommandAddArg(cmd, "--key");
        virCommandAddArgFormat(cmd, "pwdfd=%d,mode=aes-256-cbc",
                               pwdfile_fd);
        virCommandPassFD(cmd, pwdfile_fd, VIR_COMMAND_PASS_FD_CLOSE_PARENT);
        pwdfile_fd = -1;
    }

    return cmd;

 error:
    if (created)
        qemuTPMDeleteEmulatorStorage(tpm);

    virCommandFree(cmd);

    return NULL;
}


/*
 * qemuTPMEmulatorStop
 * @swtpmStateDir: A directory where the socket is located
 * @shortName: short and unique name of the domain
 *
 * Gracefully stop the swptm
 */
static void
qemuTPMEmulatorStop(const char *swtpmStateDir,
                    const char *shortName)
{
    virCommandPtr cmd;
    char *pathname;
    char *errbuf = NULL;
    VIR_AUTOFREE(char *) swtpm_ioctl = virTPMGetSwtpmIoctl();

    if (!swtpm_ioctl)
        return;

    if (virTPMEmulatorInit() < 0)
        return;

    if (!(pathname = qemuTPMCreateEmulatorSocket(swtpmStateDir, shortName)))
        return;

    if (!virFileExists(pathname))
        goto cleanup;

    cmd = virCommandNew(swtpm_ioctl);
    if (!cmd)
        goto cleanup;

    virCommandAddArgList(cmd, "--unix", pathname, "-s", NULL);

    virCommandSetErrorBuffer(cmd, &errbuf);

    ignore_value(virCommandRun(cmd, NULL));

    virCommandFree(cmd);

    /* clean up the socket */
    unlink(pathname);

 cleanup:
    VIR_FREE(pathname);
    VIR_FREE(errbuf);
}


int
qemuExtTPMInitPaths(virQEMUDriverPtr driver,
                    virDomainDefPtr def)
{
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    int ret = 0;

    switch (def->tpm->type) {
    case VIR_DOMAIN_TPM_TYPE_EMULATOR:
        ret = qemuTPMEmulatorInitPaths(def->tpm, cfg->swtpmStorageDir,
                                       def->uuid);
        break;
    case VIR_DOMAIN_TPM_TYPE_PASSTHROUGH:
    case VIR_DOMAIN_TPM_TYPE_LAST:
        break;
    }

    virObjectUnref(cfg);

    return ret;
}


int
qemuExtTPMPrepareHost(virQEMUDriverPtr driver,
                      virDomainDefPtr def)
{
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    int ret = 0;
    char *shortName = NULL;

    switch (def->tpm->type) {
    case VIR_DOMAIN_TPM_TYPE_EMULATOR:
        shortName = virDomainDefGetShortName(def);
        if (!shortName)
            goto cleanup;

        ret = qemuTPMEmulatorPrepareHost(def->tpm, cfg->swtpmLogDir,
                                         def->name, cfg->swtpm_user,
                                         cfg->swtpm_group,
                                         cfg->swtpmStateDir, cfg->user,
                                         shortName);
        break;
    case VIR_DOMAIN_TPM_TYPE_PASSTHROUGH:
    case VIR_DOMAIN_TPM_TYPE_LAST:
        break;
    }

 cleanup:
    VIR_FREE(shortName);
    virObjectUnref(cfg);

    return ret;
}


void
qemuExtTPMCleanupHost(virDomainDefPtr def)
{
    switch (def->tpm->type) {
    case VIR_DOMAIN_TPM_TYPE_EMULATOR:
        qemuTPMDeleteEmulatorStorage(def->tpm);
        break;
    case VIR_DOMAIN_TPM_TYPE_PASSTHROUGH:
    case VIR_DOMAIN_TPM_TYPE_LAST:
        /* nothing to do */
        break;
    }
}


/*
 * qemuExtTPMStartEmulator:
 *
 * @driver: QEMU driver
 * @vm: the domain object
 * @logCtxt: log context
 *
 * Start the external TPM Emulator:
 * - have the command line built
 * - start the external TPM Emulator and sync with it before QEMU start
 */
static int
qemuExtTPMStartEmulator(virQEMUDriverPtr driver,
                        virDomainObjPtr vm,
                        qemuDomainLogContextPtr logCtxt)
{
    int ret = -1;
    virCommandPtr cmd = NULL;
    int exitstatus = 0;
    char *errbuf = NULL;
    virQEMUDriverConfigPtr cfg;
    virDomainTPMDefPtr tpm = vm->def->tpm;
    char *shortName = virDomainDefGetShortName(vm->def);
    int cmdret = 0, timeout, rc;
    pid_t pid;

    if (!shortName)
        return -1;

    cfg = virQEMUDriverGetConfig(driver);

    /* stop any left-over TPM emulator for this VM */
    qemuTPMEmulatorStop(cfg->swtpmStateDir, shortName);

    if (!(cmd = qemuTPMEmulatorBuildCommand(tpm, vm->def->name, vm->def->uuid,
                                            driver->privileged,
                                            cfg->swtpm_user,
                                            cfg->swtpm_group,
                                            cfg->swtpmStateDir, shortName)))
        goto cleanup;

    if (qemuExtDeviceLogCommand(logCtxt, cmd, "TPM Emulator") < 0)
        goto cleanup;

    virCommandSetErrorBuffer(cmd, &errbuf);

    if (qemuSecurityStartTPMEmulator(driver, vm, cmd,
                                     cfg->swtpm_user, cfg->swtpm_group,
                                     &exitstatus, &cmdret) < 0)
        goto cleanup;

    if (cmdret < 0 || exitstatus != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not start 'swtpm'. exitstatus: %d, "
                         "error: %s"), exitstatus, errbuf);
        goto cleanup;
    }

    /* check that the swtpm has written its pid into the file */
    timeout = 1000; /* ms */
    while (timeout > 0) {
        rc = qemuTPMEmulatorGetPid(cfg->swtpmStateDir, shortName, &pid);
        if (rc < 0) {
            timeout -= 50;
            usleep(50 * 1000);
            continue;
        }
        if (rc == 0 && pid == (pid_t)-1)
            goto error;
        break;
    }
    if (timeout <= 0)
        goto error;

    ret = 0;

 cleanup:
    VIR_FREE(shortName);
    VIR_FREE(errbuf);
    virCommandFree(cmd);

    virObjectUnref(cfg);

    return ret;

 error:
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("swtpm failed to start"));
    goto cleanup;
}


int
qemuExtTPMStart(virQEMUDriverPtr driver,
                virDomainObjPtr vm,
                qemuDomainLogContextPtr logCtxt)
{
    int ret = 0;
    virDomainTPMDefPtr tpm = vm->def->tpm;

    switch (tpm->type) {
    case VIR_DOMAIN_TPM_TYPE_EMULATOR:
        ret = qemuExtTPMStartEmulator(driver, vm, logCtxt);
        break;
    case VIR_DOMAIN_TPM_TYPE_PASSTHROUGH:
    case VIR_DOMAIN_TPM_TYPE_LAST:
        break;
    }

    return ret;
}


void
qemuExtTPMStop(virQEMUDriverPtr driver,
               virDomainObjPtr vm)
{
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    char *shortName = NULL;

    switch (vm->def->tpm->type) {
    case VIR_DOMAIN_TPM_TYPE_EMULATOR:
        shortName = virDomainDefGetShortName(vm->def);
        if (!shortName)
            goto cleanup;

        qemuTPMEmulatorStop(cfg->swtpmStateDir, shortName);
        qemuSecurityCleanupTPMEmulator(driver, vm);
        break;
    case VIR_DOMAIN_TPM_TYPE_PASSTHROUGH:
    case VIR_DOMAIN_TPM_TYPE_LAST:
        break;
    }

 cleanup:
    VIR_FREE(shortName);
    virObjectUnref(cfg);
}


int
qemuExtTPMSetupCgroup(virQEMUDriverPtr driver,
                      virDomainDefPtr def,
                      virCgroupPtr cgroup)
{
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    char *pidfile = NULL;
    char *shortName = NULL;
    int ret = -1, rc;
    pid_t pid;

    switch (def->tpm->type) {
    case VIR_DOMAIN_TPM_TYPE_EMULATOR:
        shortName = virDomainDefGetShortName(def);
        if (!shortName)
            goto cleanup;
        rc = qemuTPMEmulatorGetPid(cfg->swtpmStateDir, shortName, &pid);
        if (rc < 0 || (rc == 0 && pid == (pid_t)-1)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Could not get process id of swtpm"));
            goto cleanup;
        }
        if (virCgroupAddProcess(cgroup, pid) < 0)
            goto cleanup;
        break;
    case VIR_DOMAIN_TPM_TYPE_PASSTHROUGH:
    case VIR_DOMAIN_TPM_TYPE_LAST:
        break;
    }

    ret = 0;

 cleanup:
    VIR_FREE(pidfile);
    VIR_FREE(shortName);
    virObjectUnref(cfg);

    return ret;
}
