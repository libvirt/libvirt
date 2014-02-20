/*
 * storage_backend_iscsi.c: storage backend for iSCSI handling
 *
 * Copyright (C) 2007-2014 Red Hat, Inc.
 * Copyright (C) 2007-2008 Daniel P. Berrange
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
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include <dirent.h>
#include <sys/wait.h>
#include <string.h>
#include <stdio.h>
#include <regex.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include "datatypes.h"
#include "driver.h"
#include "virerror.h"
#include "storage_backend_scsi.h"
#include "storage_backend_iscsi.h"
#include "viralloc.h"
#include "virlog.h"
#include "virfile.h"
#include "vircommand.h"
#include "virobject.h"
#include "virrandom.h"
#include "virstring.h"
#include "viruuid.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE

#define ISCSI_DEFAULT_TARGET_PORT 3260

static char *
virStorageBackendISCSIPortal(virStoragePoolSourcePtr source)
{
    char *portal = NULL;

    if (source->nhost != 1) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Expected exactly 1 host for the storage pool"));
        return NULL;
    }

    if (source->hosts[0].port == 0)
        source->hosts[0].port = ISCSI_DEFAULT_TARGET_PORT;

    if (strchr(source->hosts[0].name, ':')) {
        ignore_value(virAsprintf(&portal, "[%s]:%d,1",
                                 source->hosts[0].name,
                                 source->hosts[0].port));
    } else {
        ignore_value(virAsprintf(&portal, "%s:%d,1",
                                 source->hosts[0].name,
                                 source->hosts[0].port));
    }

    return portal;
}


static int
virStorageBackendISCSIExtractSession(virStoragePoolObjPtr pool,
                                     char **const groups,
                                     void *data)
{
    char **session = data;

    if (STREQ(groups[1], pool->def->source.devices[0].path))
        return VIR_STRDUP(*session, groups[0]);
    return 0;
}

static char *
virStorageBackendISCSISession(virStoragePoolObjPtr pool,
                              int probe)
{
    /*
     * # iscsiadm --mode session
     * tcp: [1] 192.168.122.170:3260,1 demo-tgt-b
     * tcp: [2] 192.168.122.170:3260,1 demo-tgt-a
     *
     * Pull out 2nd and 4th fields
     */
    const char *regexes[] = {
        "^tcp:\\s+\\[(\\S+)\\]\\s+\\S+\\s+(\\S+).*$"
    };
    int vars[] = {
        2,
    };
    char *session = NULL;

    virCommandPtr cmd = virCommandNewArgList(ISCSIADM, "--mode", "session", NULL);

    if (virStorageBackendRunProgRegex(pool,
                                      cmd,
                                      1,
                                      regexes,
                                      vars,
                                      virStorageBackendISCSIExtractSession,
                                      &session, NULL) < 0)
        goto cleanup;

    if (session == NULL &&
        !probe) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("cannot find session"));
        goto cleanup;
    }

cleanup:
    virCommandFree(cmd);
    return session;
}


#define LINE_SIZE 4096

static int
virStorageBackendIQNFound(const char *initiatoriqn,
                          char **ifacename)
{
    int ret = IQN_MISSING, fd = -1;
    char ebuf[64];
    FILE *fp = NULL;
    char *line = NULL, *newline = NULL, *iqn = NULL, *token = NULL;
    virCommandPtr cmd = virCommandNewArgList(ISCSIADM,
                                             "--mode", "iface", NULL);

    if (VIR_ALLOC_N(line, LINE_SIZE) != 0) {
        ret = IQN_ERROR;
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not allocate memory for output of '%s'"),
                       ISCSIADM);
        goto out;
    }

    memset(line, 0, LINE_SIZE);

    virCommandSetOutputFD(cmd, &fd);
    if (virCommandRunAsync(cmd, NULL) < 0) {
        ret = IQN_ERROR;
        goto out;
    }

    if ((fp = VIR_FDOPEN(fd, "r")) == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to open stream for file descriptor "
                         "when reading output from '%s': '%s'"),
                       ISCSIADM, virStrerror(errno, ebuf, sizeof(ebuf)));
        ret = IQN_ERROR;
        goto out;
    }

    while (fgets(line, LINE_SIZE, fp) != NULL) {
        newline = strrchr(line, '\n');
        if (newline == NULL) {
            ret = IQN_ERROR;
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unexpected line > %d characters "
                             "when parsing output of '%s'"),
                           LINE_SIZE, ISCSIADM);
            goto out;
        }
        *newline = '\0';

        iqn = strrchr(line, ',');
        if (iqn == NULL) {
            continue;
        }
        iqn++;

        if (STREQ(iqn, initiatoriqn)) {
            token = strchr(line, ' ');
            if (!token) {
                ret = IQN_ERROR;
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Missing space when parsing output "
                                 "of '%s'"), ISCSIADM);
                goto out;
            }
            if (VIR_STRNDUP(*ifacename, line, token - line) < 0) {
                ret = IQN_ERROR;
                goto out;
            }
            VIR_DEBUG("Found interface '%s' with IQN '%s'", *ifacename, iqn);
            ret = IQN_FOUND;
            break;
        }
    }

    if (virCommandWait(cmd, NULL) < 0)
        ret = IQN_ERROR;

out:
    if (ret == IQN_MISSING) {
        VIR_DEBUG("Could not find interface with IQN '%s'", iqn);
    }

    VIR_FREE(line);
    VIR_FORCE_FCLOSE(fp);
    VIR_FORCE_CLOSE(fd);
    virCommandFree(cmd);

    return ret;
}


static int
virStorageBackendCreateIfaceIQN(const char *initiatoriqn,
                                char **ifacename)
{
    int ret = -1, exitstatus = -1;
    char *temp_ifacename;
    virCommandPtr cmd = NULL;

    if (virAsprintf(&temp_ifacename,
                    "libvirt-iface-%08llx",
                    (unsigned long long)virRandomBits(30)) < 0)
        return -1;

    VIR_DEBUG("Attempting to create interface '%s' with IQN '%s'",
              temp_ifacename, initiatoriqn);

    cmd = virCommandNewArgList(ISCSIADM,
                               "--mode", "iface",
                               "--interface", temp_ifacename,
                               "--op", "new",
                               NULL);
    /* Note that we ignore the exitstatus.  Older versions of iscsiadm
     * tools returned an exit status of > 0, even if they succeeded.
     * We will just rely on whether the interface got created
     * properly. */
    if (virCommandRun(cmd, &exitstatus) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to run command '%s' to create new iscsi interface"),
                       ISCSIADM);
        goto cleanup;
    }
    virCommandFree(cmd);

    cmd = virCommandNewArgList(ISCSIADM,
                               "--mode", "iface",
                               "--interface", temp_ifacename,
                               "--op", "update",
                               "--name", "iface.initiatorname",
                               "--value",
                               initiatoriqn,
                               NULL);
    /* Note that we ignore the exitstatus.  Older versions of iscsiadm tools
     * returned an exit status of > 0, even if they succeeded.  We will just
     * rely on whether iface file got updated properly. */
    if (virCommandRun(cmd, &exitstatus) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to run command '%s' to update iscsi interface with IQN '%s'"),
                       ISCSIADM, initiatoriqn);
        goto cleanup;
    }

    /* Check again to make sure the interface was created. */
    if (virStorageBackendIQNFound(initiatoriqn, ifacename) != IQN_FOUND) {
        VIR_DEBUG("Failed to find interface '%s' with IQN '%s' "
                  "after attempting to create it",
                  &temp_ifacename[0], initiatoriqn);
        goto cleanup;
    } else {
        VIR_DEBUG("Interface '%s' with IQN '%s' was created successfully",
                  *ifacename, initiatoriqn);
    }

    ret = 0;

cleanup:
    virCommandFree(cmd);
    VIR_FREE(temp_ifacename);
    if (ret != 0)
        VIR_FREE(*ifacename);
    return ret;
}



static int
virStorageBackendISCSIConnection(const char *portal,
                                 const char *initiatoriqn,
                                 const char *target,
                                 const char **extraargv)
{
    int ret = -1;
    const char *const baseargv[] = {
        ISCSIADM,
        "--mode", "node",
        "--portal", portal,
        "--targetname", target,
        NULL
    };
    virCommandPtr cmd;
    char *ifacename = NULL;

    cmd = virCommandNewArgs(baseargv);
    virCommandAddArgSet(cmd, extraargv);

    if (initiatoriqn) {
        switch (virStorageBackendIQNFound(initiatoriqn, &ifacename)) {
        case IQN_FOUND:
            VIR_DEBUG("ifacename: '%s'", ifacename);
            break;
        case IQN_MISSING:
            if (virStorageBackendCreateIfaceIQN(initiatoriqn,
                                                &ifacename) != 0) {
                goto cleanup;
            }
            break;
        case IQN_ERROR:
        default:
            goto cleanup;
        }
        virCommandAddArgList(cmd, "--interface", ifacename, NULL);
    }

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    ret = 0;

cleanup:
    virCommandFree(cmd);
    VIR_FREE(ifacename);

    return ret;
}

static int
virStorageBackendISCSIGetHostNumber(const char *sysfs_path,
                                    uint32_t *host)
{
    int retval = 0;
    DIR *sysdir = NULL;
    struct dirent *dirent = NULL;

    VIR_DEBUG("Finding host number from '%s'", sysfs_path);

    virFileWaitForDevices();

    sysdir = opendir(sysfs_path);

    if (sysdir == NULL) {
        virReportSystemError(errno,
                             _("Failed to opendir path '%s'"), sysfs_path);
        retval = -1;
        goto out;
    }

    while ((dirent = readdir(sysdir))) {
        if (STREQLEN(dirent->d_name, "target", strlen("target"))) {
            if (sscanf(dirent->d_name,
                       "target%u:", host) != 1) {
                VIR_DEBUG("Failed to parse target '%s'", dirent->d_name);
                retval = -1;
                break;
            }
        }
    }

    closedir(sysdir);
out:
    return retval;
}

static int
virStorageBackendISCSIFindLUs(virStoragePoolObjPtr pool,
                              const char *session)
{
    char *sysfs_path;
    int retval = 0;
    uint32_t host;

    if (virAsprintf(&sysfs_path,
                    "/sys/class/iscsi_session/session%s/device", session) < 0)
        return -1;

    if (virStorageBackendISCSIGetHostNumber(sysfs_path, &host) < 0) {
        virReportSystemError(errno,
                             _("Failed to get host number for iSCSI session "
                               "with path '%s'"),
                             sysfs_path);
        retval = -1;
    }

    if (virStorageBackendSCSIFindLUs(pool, host) < 0) {
        virReportSystemError(errno,
                             _("Failed to find LUs on host %u"), host);
        retval = -1;
    }

    VIR_FREE(sysfs_path);

    return retval;
}

static int
virStorageBackendISCSIRescanLUNs(virStoragePoolObjPtr pool ATTRIBUTE_UNUSED,
                                 const char *session)
{
    virCommandPtr cmd = virCommandNewArgList(ISCSIADM,
                                             "--mode", "session",
                                             "-r", session,
                                             "-R",
                                             NULL);
    int ret = virCommandRun(cmd, NULL);
    virCommandFree(cmd);
    return ret;
}

struct virStorageBackendISCSITargetList {
    size_t ntargets;
    char **targets;
};

static int
virStorageBackendISCSIGetTargets(virStoragePoolObjPtr pool ATTRIBUTE_UNUSED,
                                 char **const groups,
                                 void *data)
{
    struct virStorageBackendISCSITargetList *list = data;
    char *target;

    if (VIR_STRDUP(target, groups[1]) < 0)
        return -1;

    if (VIR_REALLOC_N(list->targets, list->ntargets + 1) < 0) {
        VIR_FREE(target);
        return -1;
    }

    list->targets[list->ntargets] = target;
    list->ntargets++;

    return 0;
}

static int
virStorageBackendISCSITargetAutologin(const char *portal,
                                      const char *initiatoriqn,
                                      const char *target,
                                      bool enable)
{
    const char *extraargv[] = { "--op", "update",
                                "--name", "node.startup",
                                "--value", enable ? "automatic" : "manual",
                                NULL };

    return virStorageBackendISCSIConnection(portal, initiatoriqn, target, extraargv);
}


static int
virStorageBackendISCSIScanTargets(const char *portal,
                                  const char *initiatoriqn,
                                  size_t *ntargetsret,
                                  char ***targetsret)
{
    /**
     *
     * The output of sendtargets is very simple, just two columns,
     * portal then target name
     *
     * 192.168.122.185:3260,1 iqn.2004-04.com:fedora14:iscsi.demo0.bf6d84
     * 192.168.122.185:3260,1 iqn.2004-04.com:fedora14:iscsi.demo1.bf6d84
     * 192.168.122.185:3260,1 iqn.2004-04.com:fedora14:iscsi.demo2.bf6d84
     * 192.168.122.185:3260,1 iqn.2004-04.com:fedora14:iscsi.demo3.bf6d84
     */
    const char *regexes[] = {
        "^\\s*(\\S+)\\s+(\\S+)\\s*$"
    };
    int vars[] = { 2 };
    struct virStorageBackendISCSITargetList list;
    size_t i;
    int ret = -1;
    virCommandPtr cmd = virCommandNewArgList(ISCSIADM,
                                             "--mode", "discovery",
                                             "--type", "sendtargets",
                                             "--portal", portal,
                                             NULL);

    memset(&list, 0, sizeof(list));

    if (virStorageBackendRunProgRegex(NULL, /* No pool for callback */
                                      cmd,
                                      1,
                                      regexes,
                                      vars,
                                      virStorageBackendISCSIGetTargets,
                                      &list, NULL) < 0)
        goto cleanup;

    for (i = 0; i < list.ntargets; i++) {
        /* We have to ignore failure, because we can't undo
         * the results of 'sendtargets', unless we go scrubbing
         * around in the dirt in /var/lib/iscsi.
         */
        if (virStorageBackendISCSITargetAutologin(portal,
                                                  initiatoriqn,
                                                  list.targets[i], false) < 0)
            VIR_WARN("Unable to disable auto-login on iSCSI target %s: %s",
                     portal, list.targets[i]);
    }

    if (ntargetsret && targetsret) {
        *ntargetsret = list.ntargets;
        *targetsret = list.targets;
    } else {
        for (i = 0; i < list.ntargets; i++) {
            VIR_FREE(list.targets[i]);
        }
        VIR_FREE(list.targets);
    }

    ret = 0;
cleanup:
    virCommandFree(cmd);
    return ret;
}


static char *
virStorageBackendISCSIFindPoolSources(virConnectPtr conn ATTRIBUTE_UNUSED,
                                      const char *srcSpec,
                                      unsigned int flags)
{
    virStoragePoolSourcePtr source = NULL;
    size_t ntargets = 0;
    char **targets = NULL;
    char *ret = NULL;
    size_t i;
    virStoragePoolSourceList list = {
        .type = VIR_STORAGE_POOL_ISCSI,
        .nsources = 0,
        .sources = NULL
    };
    char *portal = NULL;

    virCheckFlags(0, NULL);

    if (!srcSpec) {
        virReportError(VIR_ERR_INVALID_ARG,
                       "%s", _("hostname and device path "
                               "must be specified for iscsi sources"));
        return NULL;
    }

    if (!(source = virStoragePoolDefParseSourceString(srcSpec,
                                                      list.type)))
        return NULL;

    if (source->nhost != 1) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Expected exactly 1 host for the storage pool"));
        goto cleanup;
    }

    if (!(portal = virStorageBackendISCSIPortal(source)))
        goto cleanup;

    if (virStorageBackendISCSIScanTargets(portal,
                                          source->initiator.iqn,
                                          &ntargets, &targets) < 0)
        goto cleanup;

    if (VIR_ALLOC_N(list.sources, ntargets) < 0)
        goto cleanup;

    for (i = 0; i < ntargets; i++) {
        if (VIR_ALLOC_N(list.sources[i].devices, 1) < 0 ||
            VIR_ALLOC_N(list.sources[i].hosts, 1) < 0)
            goto cleanup;
        list.sources[i].nhost = 1;
        list.sources[i].hosts[0] = source->hosts[0];
        list.sources[i].initiator = source->initiator;
        list.sources[i].ndevice = 1;
        list.sources[i].devices[0].path = targets[i];
        list.nsources++;
    }

    if (!(ret = virStoragePoolSourceListFormat(&list)))
        goto cleanup;

cleanup:
    if (list.sources) {
        for (i = 0; i < ntargets; i++) {
            VIR_FREE(list.sources[i].hosts);
            VIR_FREE(list.sources[i].devices);
        }
        VIR_FREE(list.sources);
    }
    for (i = 0; i < ntargets; i++)
        VIR_FREE(targets[i]);
    VIR_FREE(targets);
    VIR_FREE(portal);
    virStoragePoolSourceFree(source);
    return ret;
}

static int
virStorageBackendISCSICheckPool(virConnectPtr conn ATTRIBUTE_UNUSED,
                                virStoragePoolObjPtr pool,
                                bool *isActive)
{
    char *session = NULL;
    int ret = -1;

    *isActive = false;

    if (pool->def->source.nhost != 1) {
         virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                        _("Expected exactly 1 host for the storage pool"));
        return -1;
    }

    if (pool->def->source.hosts[0].name == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("missing source host"));
        return -1;
    }

    if (pool->def->source.ndevice != 1 ||
        pool->def->source.devices[0].path == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("missing source device"));
        return -1;
    }

    if ((session = virStorageBackendISCSISession(pool, 1)) != NULL) {
        *isActive = true;
        VIR_FREE(session);
    }
    ret = 0;

    return ret;
}

static int
virStorageBackendISCSINodeUpdate(const char *portal,
                                 const char *target,
                                 const char *name,
                                 const char *value)
{
     virCommandPtr cmd = NULL;
     int status;
     int ret = -1;

     cmd = virCommandNewArgList(ISCSIADM,
                                "--mode", "node",
                                "--portal", portal,
                                "--target", target,
                                "--op", "update",
                                "--name", name,
                                "--value", value,
                                NULL);

    /* Ignore non-zero status.  */
    if (virCommandRun(cmd, &status) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to update '%s' of node mode for target '%s'"),
                       name, target);
        goto cleanup;
    }

    ret = 0;
cleanup:
    virCommandFree(cmd);
    return ret;
}

static int
virStorageBackendISCSISetAuth(const char *portal,
                              virConnectPtr conn,
                              virStoragePoolDefPtr def)
{
    virSecretPtr secret = NULL;
    unsigned char *secret_value = NULL;
    virStoragePoolAuthChap chap;
    int ret = -1;
    char uuidStr[VIR_UUID_STRING_BUFLEN];

    if (def->source.authType == VIR_STORAGE_POOL_AUTH_NONE)
        return 0;

    if (def->source.authType != VIR_STORAGE_POOL_AUTH_CHAP) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("iscsi pool only supports 'chap' auth type"));
        return -1;
    }

    if (!conn) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("iscsi 'chap' authentication not supported "
                         "for autostarted pools"));
        return -1;
    }

    chap = def->source.auth.chap;
    if (chap.secret.uuidUsable)
        secret = virSecretLookupByUUID(conn, chap.secret.uuid);
    else
        secret = virSecretLookupByUsage(conn, VIR_SECRET_USAGE_TYPE_ISCSI,
                                        chap.secret.usage);

    if (secret) {
        size_t secret_size;
        secret_value =
            conn->secretDriver->secretGetValue(secret, &secret_size, 0,
                                               VIR_SECRET_GET_VALUE_INTERNAL_CALL);
        if (!secret_value) {
            if (chap.secret.uuidUsable) {
                virUUIDFormat(chap.secret.uuid, uuidStr);
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("could not get the value of the secret "
                                 "for username %s using uuid '%s'"),
                                 chap.username, uuidStr);
            } else {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("could not get the value of the secret "
                                 "for username %s using usage value '%s'"),
                                 chap.username, chap.secret.usage);
            }
            goto cleanup;
        }
    } else {
        if (chap.secret.uuidUsable) {
            virUUIDFormat(chap.secret.uuid, uuidStr);
            virReportError(VIR_ERR_NO_SECRET,
                           _("no secret matches uuid '%s'"),
                           uuidStr);
        } else {
            virReportError(VIR_ERR_NO_SECRET,
                           _("no secret matches usage value '%s'"),
                           chap.secret.usage);
        }
        goto cleanup;
    }

    if (virStorageBackendISCSINodeUpdate(portal,
                                         def->source.devices[0].path,
                                         "node.session.auth.authmethod",
                                         "CHAP") < 0 ||
        virStorageBackendISCSINodeUpdate(portal,
                                         def->source.devices[0].path,
                                         "node.session.auth.username",
                                         chap.username) < 0 ||
        virStorageBackendISCSINodeUpdate(portal,
                                         def->source.devices[0].path,
                                         "node.session.auth.password",
                                         (const char *)secret_value) < 0)
        goto cleanup;

    ret = 0;

cleanup:
    virObjectUnref(secret);
    VIR_FREE(secret_value);
    return ret;
}

static int
virStorageBackendISCSIStartPool(virConnectPtr conn,
                                virStoragePoolObjPtr pool)
{
    char *portal = NULL;
    char *session = NULL;
    int ret = -1;
    const char *loginargv[] = { "--login", NULL };

    if (pool->def->source.nhost != 1) {
         virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                        _("Expected exactly 1 host for the storage pool"));
        return -1;
    }

    if (pool->def->source.hosts[0].name == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("missing source host"));
        return -1;
    }

    if (pool->def->source.ndevice != 1 ||
        pool->def->source.devices[0].path == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("missing source device"));
        return -1;
    }

    if ((session = virStorageBackendISCSISession(pool, 1)) == NULL) {
        if ((portal = virStorageBackendISCSIPortal(&pool->def->source)) == NULL)
            goto cleanup;
        /*
         * iscsiadm doesn't let you login to a target, unless you've
         * first issued a 'sendtargets' command to the portal :-(
         */
        if (virStorageBackendISCSIScanTargets(portal,
                                              pool->def->source.initiator.iqn,
                                              NULL, NULL) < 0)
            goto cleanup;

        if (virStorageBackendISCSISetAuth(portal, conn, pool->def) < 0)
            goto cleanup;

        if (virStorageBackendISCSIConnection(portal,
                                             pool->def->source.initiator.iqn,
                                             pool->def->source.devices[0].path,
                                             loginargv) < 0)
            goto cleanup;
    }
    ret = 0;

cleanup:
    VIR_FREE(portal);
    VIR_FREE(session);
    return ret;
}

static int
virStorageBackendISCSIRefreshPool(virConnectPtr conn ATTRIBUTE_UNUSED,
                                  virStoragePoolObjPtr pool)
{
    char *session = NULL;

    pool->def->allocation = pool->def->capacity = pool->def->available = 0;

    if ((session = virStorageBackendISCSISession(pool, 0)) == NULL)
        goto cleanup;
    if (virStorageBackendISCSIRescanLUNs(pool, session) < 0)
        goto cleanup;
    if (virStorageBackendISCSIFindLUs(pool, session) < 0)
        goto cleanup;
    VIR_FREE(session);

    return 0;

 cleanup:
    VIR_FREE(session);
    return -1;
}


static int
virStorageBackendISCSIStopPool(virConnectPtr conn ATTRIBUTE_UNUSED,
                               virStoragePoolObjPtr pool)
{
    const char *logoutargv[] = { "--logout", NULL };
    char *portal;
    int ret = -1;

    if ((portal = virStorageBackendISCSIPortal(&pool->def->source)) == NULL)
        return -1;

    if (virStorageBackendISCSIConnection(portal,
                                         pool->def->source.initiator.iqn,
                                         pool->def->source.devices[0].path,
                                         logoutargv) < 0)
        goto cleanup;
    ret = 0;

cleanup:
    VIR_FREE(portal);
    return ret;
}

virStorageBackend virStorageBackendISCSI = {
    .type = VIR_STORAGE_POOL_ISCSI,

    .checkPool = virStorageBackendISCSICheckPool,
    .startPool = virStorageBackendISCSIStartPool,
    .refreshPool = virStorageBackendISCSIRefreshPool,
    .stopPool = virStorageBackendISCSIStopPool,
    .findPoolSources = virStorageBackendISCSIFindPoolSources,
};
