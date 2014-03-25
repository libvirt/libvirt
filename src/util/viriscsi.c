/*
 * viriscsi.c: helper APIs for managing iSCSI
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
 */

#include <config.h>

#include <regex.h>
#include <stdio.h>

#include "viriscsi.h"

#include "viralloc.h"
#include "vircommand.h"
#include "virerror.h"
#include "virfile.h"
#include "virlog.h"
#include "virrandom.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.iscsi");


struct virISCSISessionData {
    char *session;
    const char *devpath;
};


static int
virISCSIExtractSession(char **const groups,
                       void *opaque)
{
    struct virISCSISessionData *data = opaque;

    if (STREQ(groups[1], data->devpath))
        return VIR_STRDUP(data->session, groups[0]);
    return 0;
}


char *
virISCSIGetSession(const char *devpath,
                   bool probe)
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
    struct virISCSISessionData cbdata = {
        .session = NULL,
        .devpath = devpath,
    };

    virCommandPtr cmd = virCommandNewArgList(ISCSIADM, "--mode", "session", NULL);

    if (virCommandRunRegex(cmd,
                           1,
                           regexes,
                           vars,
                           virISCSIExtractSession,
                           &cbdata, NULL) < 0)
        goto cleanup;

    if (cbdata.session == NULL && !probe) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("cannot find session"));
        goto cleanup;
    }

 cleanup:
    virCommandFree(cmd);
    return cbdata.session;
}



#define LINE_SIZE 4096
#define IQN_FOUND 1
#define IQN_MISSING 0
#define IQN_ERROR -1

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
virISCSIConnection(const char *portal,
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


int
virISCSIConnectionLogin(const char *portal,
                        const char *initiatoriqn,
                        const char *target)
{
    const char *extraargv[] = { "--login", NULL };
    return virISCSIConnection(portal, initiatoriqn, target, extraargv);
}


int
virISCSIConnectionLogout(const char *portal,
                         const char *initiatoriqn,
                         const char *target)
{
    const char *extraargv[] = { "--logout", NULL };
    return virISCSIConnection(portal, initiatoriqn, target, extraargv);
}


int
virISCSIRescanLUNs(const char *session)
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


struct virISCSITargetList {
    size_t ntargets;
    char **targets;
};


static int
virISCSIGetTargets(char **const groups,
                   void *data)
{
    struct virISCSITargetList *list = data;
    char *target;

    if (VIR_STRDUP(target, groups[1]) < 0)
        return -1;

    if (VIR_APPEND_ELEMENT(list->targets, list->ntargets, target) < 0) {
        VIR_FREE(target);
        return -1;
    }

    return 0;
}


static int
virISCSITargetAutologin(const char *portal,
                        const char *initiatoriqn,
                        const char *target,
                        bool enable)
{
    const char *extraargv[] = { "--op", "update",
                                "--name", "node.startup",
                                "--value", enable ? "automatic" : "manual",
                                NULL };

    return virISCSIConnection(portal, initiatoriqn, target, extraargv);
}


int
virISCSIScanTargets(const char *portal,
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
    struct virISCSITargetList list;
    size_t i;
    int ret = -1;
    virCommandPtr cmd = virCommandNewArgList(ISCSIADM,
                                             "--mode", "discovery",
                                             "--type", "sendtargets",
                                             "--portal", portal,
                                             NULL);

    memset(&list, 0, sizeof(list));

    if (virCommandRunRegex(cmd,
                           1,
                           regexes,
                           vars,
                           virISCSIGetTargets,
                           &list, NULL) < 0)
        goto cleanup;

    for (i = 0; i < list.ntargets; i++) {
        /* We have to ignore failure, because we can't undo
         * the results of 'sendtargets', unless we go scrubbing
         * around in the dirt in /var/lib/iscsi.
         */
        if (virISCSITargetAutologin(portal,
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


int
virISCSINodeUpdate(const char *portal,
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
