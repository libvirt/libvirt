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

#include "viriscsi.h"

#include "viralloc.h"
#include "vircommand.h"
#include "virerror.h"
#include "virlog.h"
#include "virrandom.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.iscsi");


static int
virISCSIScanTargetsInternal(const char *portal,
                            const char *ifacename,
                            bool persist,
                            size_t *ntargetsret,
                            char ***targetsret);


struct virISCSISessionData {
    char *session;
    const char *devpath;
};


static int
virISCSIExtractSession(char **const groups,
                       void *opaque)
{
    struct virISCSISessionData *data = opaque;

    if (!data->session &&
        STREQ(groups[1], data->devpath)) {
        data->session = g_strdup(groups[0]);
        return 0;
    }
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
    int exitstatus = 0;
    g_autofree char *error = NULL;

    g_autoptr(virCommand) cmd = virCommandNewArgList(ISCSIADM, "--mode",
                                                       "session", NULL);
    virCommandSetErrorBuffer(cmd, &error);

    if (virCommandRunRegex(cmd,
                           1,
                           regexes,
                           vars,
                           virISCSIExtractSession,
                           &cbdata, NULL, &exitstatus) < 0)
        return NULL;

    if (cbdata.session == NULL && !probe)
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot find iscsiadm session: %1$s"),
                       NULLSTR(error));

    return cbdata.session;
}



#define IQN_FOUND 1
#define IQN_MISSING 0
#define IQN_ERROR -1

static int
virStorageBackendIQNFound(const char *initiatoriqn,
                          char **ifacename)
{
    int ret = IQN_ERROR;
    char *line = NULL;
    g_autofree char *outbuf = NULL;
    g_autofree char *iface = NULL;
    g_autofree char *iqn = NULL;
    g_autoptr(virCommand) cmd = virCommandNewArgList(ISCSIADM,
                                                       "--mode", "iface", NULL);

    *ifacename = NULL;

    virCommandSetOutputBuffer(cmd, &outbuf);
    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    /* Example of data we are dealing with:
     * default tcp,<empty>,<empty>,<empty>,<empty>
     * iser iser,<empty>,<empty>,<empty>,<empty>
     * libvirt-iface-253db048 tcp,<empty>,<empty>,<empty>,iqn.2017-03.com.user:client
     */

    line = outbuf;
    while (line && *line) {
        char *current = line;
        char *newline;
        char *next;
        size_t i;

        if (!(newline = strchr(line, '\n')))
            break;

        *newline = '\0';

        VIR_FREE(iface);
        VIR_FREE(iqn);

        /* Find the first space, copy everything up to that point into
         * iface and move past it to continue processing */
        if (!(next = strchr(current, ' ')))
            goto error;

        iface = g_strndup(current, next - current);

        current = next + 1;

        /* There are five comma separated fields after iface and we only
         * care about the last one, so we need to skip four commas and
         * copy whatever's left into iqn */
        for (i = 0; i < 4; i++) {
            if (!(next = strchr(current, ',')))
                goto error;
            current = next + 1;
        }

        iqn = g_strdup(current);

        if (STREQ(iqn, initiatoriqn)) {
            *ifacename = g_steal_pointer(&iface);

            VIR_DEBUG("Found interface '%s' with IQN '%s'", *ifacename, iqn);
            break;
        }

        line = newline + 1;
    }

    ret = *ifacename ? IQN_FOUND : IQN_MISSING;

 cleanup:
    if (ret == IQN_MISSING)
        VIR_DEBUG("Could not find interface with IQN '%s'", iqn);

    return ret;

 error:
    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("malformed output of %1$s: %2$s"),
                   ISCSIADM, line);
    goto cleanup;
}


static int
virStorageBackendCreateIfaceIQN(const char *initiatoriqn,
                                char **ifacename)
{
    int exitstatus = -1;
    g_autofree char *iface_name = NULL;
    g_autofree char *temp_ifacename = NULL;
    g_autoptr(virCommand) newcmd = NULL;
    g_autoptr(virCommand) updatecmd = NULL;

    temp_ifacename = g_strdup_printf("libvirt-iface-%08llx",
                                     (unsigned long long)virRandomBits(32));

    VIR_DEBUG("Attempting to create interface '%s' with IQN '%s'",
              temp_ifacename, initiatoriqn);

    newcmd = virCommandNewArgList(ISCSIADM,
                                  "--mode", "iface",
                                  "--interface", temp_ifacename,
                                  "--op", "new",
                                  NULL);
    /* Note that we ignore the exitstatus.  Older versions of iscsiadm
     * tools returned an exit status of > 0, even if they succeeded.
     * We will just rely on whether the interface got created
     * properly. */
    if (virCommandRun(newcmd, &exitstatus) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to run command '%1$s' to create new iscsi interface"),
                       ISCSIADM);
        return -1;
    }

    updatecmd = virCommandNewArgList(ISCSIADM,
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
    if (virCommandRun(updatecmd, &exitstatus) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to run command '%1$s' to update iscsi interface with IQN '%2$s'"),
                       ISCSIADM, initiatoriqn);
        return -1;
    }

    /* Check again to make sure the interface was created. */
    if (virStorageBackendIQNFound(initiatoriqn, &iface_name) != IQN_FOUND) {
        VIR_DEBUG("Failed to find interface '%s' with IQN '%s' "
                  "after attempting to create it",
                  &temp_ifacename[0], initiatoriqn);
        return -1;
    } else {
        VIR_DEBUG("Interface '%s' with IQN '%s' was created successfully",
                  iface_name, initiatoriqn);
    }

    *ifacename = g_steal_pointer(&iface_name);

    return 0;
}


static int
virISCSIConnection(const char *portal,
                   const char *initiatoriqn,
                   const char *target,
                   const char **extraargv)
{
    const char *const baseargv[] = {
        ISCSIADM,
        "--mode", "node",
        "--portal", portal,
        "--targetname", target,
        NULL
    };
    g_autoptr(virCommand) cmd = NULL;
    g_autofree char *ifacename = NULL;

    cmd = virCommandNewArgs(baseargv);
    virCommandAddArgSet(cmd, extraargv);

    if (initiatoriqn) {
        switch (virStorageBackendIQNFound(initiatoriqn, &ifacename)) {
        case IQN_FOUND:
            VIR_DEBUG("ifacename: '%s'", ifacename);
            break;
        case IQN_MISSING:
            if (virStorageBackendCreateIfaceIQN(initiatoriqn, &ifacename) != 0)
                return -1;
            /*
             * iscsiadm doesn't let you send commands to the Interface IQN,
             * unless you've first issued a 'sendtargets' command to the
             * portal. Without the sendtargets all that is received is a
             * "iscsiadm: No records found". However, we must ensure that
             * the command is issued over interface name we invented above
             * and that targets are made persistent.
             */
            if (virISCSIScanTargetsInternal(portal, ifacename,
                                            true, NULL, NULL) < 0)
                return -1;

            break;
        case IQN_ERROR:
        default:
            return -1;
        }
        virCommandAddArgList(cmd, "--interface", ifacename, NULL);
    }

    if (virCommandRun(cmd, NULL) < 0)
        return -1;

    return 0;
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
    g_autoptr(virCommand) cmd = virCommandNewArgList(ISCSIADM,
                                                       "--mode", "session",
                                                       "-r", session,
                                                       "-R",
                                                       NULL);
    return virCommandRun(cmd, NULL);
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
    g_autofree char *target = NULL;

    target = g_strdup(groups[1]);

    VIR_APPEND_ELEMENT(list->targets, list->ntargets, target);

    return 0;
}


static int
virISCSIScanTargetsInternal(const char *portal,
                            const char *ifacename,
                            bool persist,
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
    struct virISCSITargetList list = { 0 };
    size_t i;
    g_autoptr(virCommand) cmd = virCommandNewArgList(ISCSIADM,
                                                       "--mode", "discovery",
                                                       "--type", "sendtargets",
                                                       "--portal", portal,
                                                       NULL);

    if (!persist) {
        virCommandAddArgList(cmd,
                             "--op", "nonpersistent",
                             NULL);
    }

    if (ifacename) {
        virCommandAddArgList(cmd,
                             "--interface", ifacename,
                             NULL);
    }

    if (virCommandRunRegex(cmd,
                           1,
                           regexes,
                           vars,
                           virISCSIGetTargets,
                           &list, NULL, NULL) < 0)
        return -1;

    if (ntargetsret && targetsret) {
        *ntargetsret = list.ntargets;
        *targetsret = list.targets;
    } else {
        for (i = 0; i < list.ntargets; i++)
            VIR_FREE(list.targets[i]);
        VIR_FREE(list.targets);
    }

    return 0;
}


/**
 * virISCSIScanTargets:
 * @portal: iSCSI portal
 * @initiatoriqn: Initiator IQN
 * @persists: whether scanned targets should be saved
 * @ntargets: number of items in @targetsret array
 * @targets: array of targets
 *
 * For given @portal issue sendtargets command. Optionally,
 * @initiatoriqn can be set to override default configuration.
 * The targets are stored into @targets array and the size of
 * the array is stored into @ntargets.
 *
 * If @persist is true, then targets returned by iSCSI portal are
 * made persistent on the host (their config is saved).
 *
 * Returns: 0 on success,
 *         -1 otherwise (with error reported)
 */
int
virISCSIScanTargets(const char *portal,
                    const char *initiatoriqn,
                    bool persist,
                    size_t *ntargets,
                    char ***targets)
{
    g_autofree char *ifacename = NULL;

    if (ntargets)
        *ntargets = 0;
    if (targets)
        *targets = NULL;

    if (initiatoriqn) {
        switch ((virStorageBackendIQNFound(initiatoriqn, &ifacename))) {
        case IQN_FOUND:
            break;

        case IQN_MISSING:
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("no iSCSI interface defined for IQN %1$s"),
                           initiatoriqn);
            G_GNUC_FALLTHROUGH;
        case IQN_ERROR:
        default:
            return -1;
        }
    }

    return virISCSIScanTargetsInternal(portal, ifacename,
                                       persist, ntargets, targets);
}


/*
 * virISCSINodeNew:
 * @portal: address for iSCSI target
 * @target: IQN and specific LUN target
 *
 * Usage of nonpersistent discovery in virISCSIScanTargets is useful primarily
 * only when the target IQN is not known; however, since we have the target IQN
 * usage of the "--op new" can be done. This avoids problems if "--op delete"
 * had been used wiping out the static nodes determined by the scanning of
 * all targets.
 *
 * NB: If an iSCSI node record is already created for this portal and
 * target, subsequent "--op new" commands do not return an error.
 *
 * Returns 0 on success, -1 w/ error message on error
 */
int
virISCSINodeNew(const char *portal,
                const char *target)
{
    g_autoptr(virCommand) cmd = NULL;
    int status;

    cmd = virCommandNewArgList(ISCSIADM,
                               "--mode", "node",
                               "--portal", portal,
                               "--targetname", target,
                               "--op", "new",
                               NULL);

    if (virCommandRun(cmd, &status) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed new node mode for target '%1$s'"),
                       target);
        return -1;
    }

    if (status != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("%1$s failed new mode for target '%2$s' with status '%3$d'"),
                       ISCSIADM, target, status);
        return -1;
    }

    return 0;
}


int
virISCSINodeUpdate(const char *portal,
                   const char *target,
                   const char *name,
                   const char *value)
{
    g_autoptr(virCommand) cmd = NULL;
    int status;

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
                       _("Failed to update '%1$s' of node mode for target '%2$s'"),
                       name, target);
        return -1;
    }

    return 0;
}
