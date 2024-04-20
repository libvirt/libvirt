/*
 * virfirewall.c: integration with firewalls
 *
 * Copyright (C) 2013-2015 Red Hat, Inc.
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

#include <stdarg.h>

#include "virfirewall.h"
#include "virfirewalld.h"
#include "viralloc.h"
#include "virerror.h"
#include "vircommand.h"
#include "virlog.h"
#include "virfile.h"
#include "virthread.h"

#define VIR_FROM_THIS VIR_FROM_FIREWALL

VIR_LOG_INIT("util.firewall");

VIR_ENUM_IMPL(virFirewallBackend,
              VIR_FIREWALL_BACKEND_LAST,
              "iptables");

typedef struct _virFirewallGroup virFirewallGroup;

VIR_ENUM_DECL(virFirewallLayerCommand);
VIR_ENUM_IMPL(virFirewallLayerCommand,
              VIR_FIREWALL_LAYER_LAST,
              EBTABLES,
              IPTABLES,
              IP6TABLES,
);

struct _virFirewallCmd {
    virFirewallLayer layer;

    virFirewallQueryCallback queryCB;
    void *queryOpaque;
    bool ignoreErrors;

    size_t argsAlloc;
    size_t argsLen;
    char **args;
};

struct _virFirewallGroup {
    unsigned int actionFlags;
    unsigned int rollbackFlags;

    size_t naction;
    virFirewallCmd **action;

    size_t nrollback;
    virFirewallCmd **rollback;

    bool addingRollback;
};


struct _virFirewall {
    int err;

    size_t ngroups;
    virFirewallGroup **groups;
    size_t currentGroup;
    virFirewallBackend backend;
};

static virMutex fwCmdLock = VIR_MUTEX_INITIALIZER;

static virFirewallGroup *
virFirewallGroupNew(void)
{
    return g_new0(virFirewallGroup, 1);
}


/**
 * virFirewallNew:
 *
 * Creates a new firewall ruleset for changing rules
 * of @layer. This should be followed by a call to
 * virFirewallStartTransaction before adding
 * any rules
 *
 * Returns the new firewall ruleset
 */
virFirewall *virFirewallNew(virFirewallBackend backend)
{
    virFirewall *firewall = g_new0(virFirewall, 1);

    firewall->backend = backend;
    return firewall;
}


virFirewallBackend
virFirewallGetBackend(virFirewall *firewall)
{
    return firewall->backend;
}


static void
virFirewallCmdFree(virFirewallCmd *fwCmd)
{
    size_t i;

    if (!fwCmd)
        return;

    for (i = 0; i < fwCmd->argsLen; i++)
        g_free(fwCmd->args[i]);
    g_free(fwCmd->args);
    g_free(fwCmd);
}


static void
virFirewallGroupFree(virFirewallGroup *group)
{
    size_t i;

    if (!group)
        return;

    for (i = 0; i < group->naction; i++)
        virFirewallCmdFree(group->action[i]);
    g_free(group->action);

    for (i = 0; i < group->nrollback; i++)
        virFirewallCmdFree(group->rollback[i]);
    g_free(group->rollback);

    g_free(group);
}


/**
 * virFirewallFree:
 *
 * Release all memory associated with the firewall
 * ruleset
 */
void virFirewallFree(virFirewall *firewall)
{
    size_t i;

    if (!firewall)
        return;

    for (i = 0; i < firewall->ngroups; i++)
        virFirewallGroupFree(firewall->groups[i]);
    g_free(firewall->groups);

    g_free(firewall);
}

#define VIR_FIREWALL_RETURN_IF_ERROR(firewall) \
    do { \
        if (!firewall || firewall->err) \
            return; \
    } while (0)

#define VIR_FIREWALL_CMD_RETURN_IF_ERROR(firewall, fwCmd)\
    do { \
        if (!firewall || firewall->err || !fwCmd) \
            return; \
    } while (0)

#define VIR_FIREWALL_RETURN_NULL_IF_ERROR(firewall) \
    do { \
        if (!firewall || firewall->err) \
            return NULL; \
    } while (0)

#define ADD_ARG(fwCmd, str) \
    do { \
        VIR_RESIZE_N(fwCmd->args, fwCmd->argsAlloc, fwCmd->argsLen, 1); \
        fwCmd->args[fwCmd->argsLen++] = g_strdup(str); \
    } while (0)


static virFirewallCmd *
virFirewallAddCmdFullV(virFirewall *firewall,
                       virFirewallLayer layer,
                       bool ignoreErrors,
                       bool isRollback,
                       virFirewallQueryCallback cb,
                       void *opaque,
                       va_list args)
{
    virFirewallGroup *group;
    virFirewallCmd *fwCmd;
    char *str;

    VIR_FIREWALL_RETURN_NULL_IF_ERROR(firewall);

    if (firewall->ngroups == 0) {
        firewall->err = EINVAL;
        return NULL;
    }
    group = firewall->groups[firewall->currentGroup];

    fwCmd = g_new0(virFirewallCmd, 1);
    fwCmd->layer = layer;

    while ((str = va_arg(args, char *)) != NULL)
        ADD_ARG(fwCmd, str);

    if (isRollback || group->addingRollback) {
        fwCmd->ignoreErrors = true; /* always ignore errors when rolling back */
        fwCmd->queryCB = NULL; /* rollback commands can't have a callback */
        fwCmd->queryOpaque = NULL;
        VIR_APPEND_ELEMENT_COPY(group->rollback, group->nrollback, fwCmd);
    } else {
        /* when not rolling back, ignore errors if this group (transaction)
         * was started with VIR_FIREWALL_TRANSACTION_IGNORE_ERRORS *or*
         * if this specific rule was created with ignoreErrors == true
         */
        fwCmd->ignoreErrors = ignoreErrors || (group->actionFlags & VIR_FIREWALL_TRANSACTION_IGNORE_ERRORS);
        fwCmd->queryCB = cb;
        fwCmd->queryOpaque = opaque;
        VIR_APPEND_ELEMENT_COPY(group->action, group->naction, fwCmd);
    }


    return fwCmd;
}


/**
 * virFirewallAddCmdFull:
 * @firewall: firewall ruleset to add to
 * @layer: the firewall layer to change
 * @ignoreErrors: true to ignore failure of the command
 * @cb: callback to invoke with result of query
 * @opaque: data passed into @cb
 * @...: NULL terminated list of strings for the rule
 *
 * Add any type of rule to the firewall ruleset. Any output
 * generated by the addition will be fed into the query
 * callback @cb. This callback is permitted to create new
 * rules by invoking the virFirewallAddCmd method, but
 * is not permitted to start new transactions.
 *
 * If @ignoreErrors is set to TRUE, then any failure of
 * the command is ignored. If it is set to FALSE, then
 * the behaviour upon failure is determined by the flags
 * set when the transaction was started.
 *
 * Returns the new rule
 */
virFirewallCmd *virFirewallAddCmdFull(virFirewall *firewall,
                                      virFirewallLayer layer,
                                      bool ignoreErrors,
                                      virFirewallQueryCallback cb,
                                      void *opaque,
                                      ...)
{
    virFirewallCmd *fwCmd;
    va_list args;
    va_start(args, opaque);
    fwCmd = virFirewallAddCmdFullV(firewall, layer, ignoreErrors, false, cb, opaque, args);
    va_end(args);
    return fwCmd;
}


/**
 * virFirewallAddRollbackCmd:
 * @firewall: firewall commands to add to
 * @layer: the firewall layer to change
 * @...: NULL terminated list of strings for the command
 *
 * Add a command to the current firewall command group "rollback".
 * Rollback commands always ignore errors and don't support any
 * callbacks.
 *
 * Returns the new Command
 */
virFirewallCmd *
virFirewallAddRollbackCmd(virFirewall *firewall,
                          virFirewallLayer layer,
                          ...)
{
    virFirewallCmd *fwCmd;
    va_list args;
    va_start(args, layer);
    fwCmd = virFirewallAddCmdFullV(firewall, layer, true, true, NULL, NULL, args);
    va_end(args);
    return fwCmd;
}


/**
 * virFirewallRemoveCmd:
 * @firewall: firewall ruleset to remove from
 * @rule: the rule to remove
 *
 * Remove a rule from the current transaction
 */
void virFirewallRemoveCmd(virFirewall *firewall,
                          virFirewallCmd *fwCmd)
{
    size_t i;
    virFirewallGroup *group;

    /* Explicitly not checking firewall->err too,
     * because if rule was partially created
     * before hitting error we must still remove
     * it to avoid leaking 'rule'
     */
    if (!firewall)
        return;

    if (firewall->ngroups == 0)
        return;
    group = firewall->groups[firewall->currentGroup];

    if (group->addingRollback) {
        for (i = 0; i < group->nrollback; i++) {
            if (group->rollback[i] == fwCmd) {
                VIR_DELETE_ELEMENT(group->rollback,
                                   i,
                                   group->nrollback);
                virFirewallCmdFree(fwCmd);
                break;
            }
        }
    } else {
        for (i = 0; i < group->naction; i++) {
            if (group->action[i] == fwCmd) {
                VIR_DELETE_ELEMENT(group->action,
                                   i,
                                   group->naction);
                virFirewallCmdFree(fwCmd);
                return;
            }
        }
    }
}


void virFirewallCmdAddArg(virFirewall *firewall,
                          virFirewallCmd *fwCmd,
                          const char *arg)
{
    VIR_FIREWALL_CMD_RETURN_IF_ERROR(firewall, fwCmd);

    ADD_ARG(fwCmd, arg);

    return;
}


void virFirewallCmdAddArgFormat(virFirewall *firewall,
                                virFirewallCmd *fwCmd,
                                const char *fmt, ...)
{
    g_autofree char *arg = NULL;
    va_list list;

    VIR_FIREWALL_CMD_RETURN_IF_ERROR(firewall, fwCmd);

    va_start(list, fmt);
    arg = g_strdup_vprintf(fmt, list);
    va_end(list);

    ADD_ARG(fwCmd, arg);

    return;
}


void virFirewallCmdAddArgSet(virFirewall *firewall,
                             virFirewallCmd *fwCmd,
                             const char *const *args)
{
    VIR_FIREWALL_CMD_RETURN_IF_ERROR(firewall, fwCmd);

    while (*args) {
        ADD_ARG(fwCmd, *args);
        args++;
    }

    return;
}


void virFirewallCmdAddArgList(virFirewall *firewall,
                              virFirewallCmd *fwCmd,
                              ...)
{
    va_list list;
    const char *str;

    VIR_FIREWALL_CMD_RETURN_IF_ERROR(firewall, fwCmd);

    va_start(list, fwCmd);

    while ((str = va_arg(list, char *)) != NULL)
        ADD_ARG(fwCmd, str);

    va_end(list);

    return;
}


size_t virFirewallCmdGetArgCount(virFirewallCmd *fwCmd)
{
    if (!fwCmd)
        return 0;
    return fwCmd->argsLen;
}


/**
 * virFirewallStartTransaction:
 * @firewall: the firewall ruleset
 * @flags: bitset of virFirewallTransactionFlags
 *
 * Start a new transaction with associated rollback
 * block.
 *
 * Should be followed by calls to add various rules to
 * the transaction. Then virFirwallStartRollback should
 * be used to provide rules to rollback upon transaction
 * failure
 */
void virFirewallStartTransaction(virFirewall *firewall,
                                 unsigned int flags)
{
    virFirewallGroup *group;

    VIR_FIREWALL_RETURN_IF_ERROR(firewall);

    group = virFirewallGroupNew();
    group->actionFlags = flags;

    VIR_EXPAND_N(firewall->groups, firewall->ngroups, 1);
    firewall->groups[firewall->ngroups - 1] = group;
    firewall->currentGroup = firewall->ngroups - 1;
}


/**
 * virFirewallTransactionGetFlags:
 * @firewall: the firewall to look at
 *
 * Returns the virFirewallTransactionFlags for the currently active
 * group (transaction) in @firewall.
 */
static virFirewallTransactionFlags G_GNUC_UNUSED
virFirewallTransactionGetFlags(virFirewall *firewall)
{
    return firewall->groups[firewall->currentGroup]->actionFlags;
}


/**
 * virFirewallBeginRollback:
 * @firewall: the firewall ruleset
 * @flags: bitset of virFirewallRollbackFlags
 *
 * Mark the beginning of a set of rules able to rollback
 * changes in this and all earlier transactions.
 *
 * Should be followed by calls to add various rules needed
 * to rollback state. Then virFirewallStartTransaction
 * should be used to indicate the beginning of the next
 * transactional ruleset.
 */
void virFirewallStartRollback(virFirewall *firewall,
                              unsigned int flags)
{
    virFirewallGroup *group;

    VIR_FIREWALL_RETURN_IF_ERROR(firewall);

    if (firewall->ngroups == 0) {
        firewall->err = EINVAL;
        return;
    }

    group = firewall->groups[firewall->ngroups-1];
    group->rollbackFlags = flags;
    group->addingRollback = true;
}


char *
virFirewallCmdToString(const char *cmd,
                       virFirewallCmd *fwCmd)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    size_t i;

    virBufferAdd(&buf, cmd, -1);
    for (i = 0; i < fwCmd->argsLen; i++) {
        virBufferAddLit(&buf, " ");
        virBufferAdd(&buf, fwCmd->args[i], -1);
    }

    return virBufferContentAndReset(&buf);
}


static int
virFirewallApplyCmdDirect(virFirewallCmd *fwCmd,
                           char **output)
{
    size_t i;
    const char *bin = virFirewallLayerCommandTypeToString(fwCmd->layer);
    g_autoptr(virCommand) cmd = NULL;
    g_autofree char *cmdStr = NULL;
    int status;
    g_autofree char *error = NULL;

    if (!bin) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unknown firewall layer %1$d"),
                       fwCmd->layer);
        return -1;
    }

    cmd = virCommandNewArgList(bin, NULL);

    /* lock to assure nobody else is messing with the tables while we are */
    switch (fwCmd->layer) {
    case VIR_FIREWALL_LAYER_ETHERNET:
        virCommandAddArg(cmd, "--concurrent");
        break;
    case VIR_FIREWALL_LAYER_IPV4:
    case VIR_FIREWALL_LAYER_IPV6:
        virCommandAddArg(cmd, "-w");
        break;
    case VIR_FIREWALL_LAYER_LAST:
        break;
    }

    for (i = 0; i < fwCmd->argsLen; i++)
        virCommandAddArg(cmd, fwCmd->args[i]);

    cmdStr = virCommandToString(cmd, false);
    VIR_INFO("Running firewall command '%s'", NULLSTR(cmdStr));

    virCommandSetOutputBuffer(cmd, output);
    virCommandSetErrorBuffer(cmd, &error);

    if (virCommandRun(cmd, &status) < 0)
        return -1;

    if (status != 0) {
        if (fwCmd->ignoreErrors) {
            VIR_DEBUG("Ignoring error running command");
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to run firewall command %1$s: %2$s"),
                           NULLSTR(cmdStr), NULLSTR(error));
            VIR_FREE(*output);
            return -1;
        }
    }

    return 0;
}


static int
virFirewallApplyCmd(virFirewall *firewall,
                    virFirewallCmd *fwCmd)
{
    g_autofree char *output = NULL;
    g_auto(GStrv) lines = NULL;

    if (fwCmd->argsLen == 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Can't apply empty firewall command"));
        return -1;
    }

    if (virFirewallApplyCmdDirect(fwCmd, &output) < 0)
        return -1;

    if (fwCmd->queryCB && output) {
        if (!(lines = g_strsplit(output, "\n", -1)))
            return -1;

        VIR_DEBUG("Invoking query %p with '%s'", fwCmd->queryCB, output);
        if (fwCmd->queryCB(firewall, fwCmd->layer, (const char *const *)lines, fwCmd->queryOpaque) < 0)
            return -1;

        if (firewall->err) {
            virReportSystemError(firewall->err, "%s",
                                 _("Unable to create firewall command"));
            return -1;
        }

    }

    return 0;
}

static int
virFirewallApplyGroup(virFirewall *firewall,
                      size_t idx)
{
    virFirewallGroup *group = firewall->groups[idx];

    size_t i;

    VIR_INFO("Starting transaction for firewall=%p group=%p flags=0x%x",
             firewall, group, group->actionFlags);
    firewall->currentGroup = idx;
    group->addingRollback = false;
    for (i = 0; i < group->naction; i++) {
        if (virFirewallApplyCmd(firewall, group->action[i]) < 0)
            return -1;
    }
    return 0;
}


static void
virFirewallRollbackGroup(virFirewall *firewall,
                         size_t idx)
{
    virFirewallGroup *group = firewall->groups[idx];
    size_t i;

    VIR_INFO("Starting rollback for group %p", group);
    firewall->currentGroup = idx;
    group->addingRollback = true;
    for (i = 0; i < group->nrollback; i++)
        ignore_value(virFirewallApplyCmd(firewall, group->rollback[i]));
}


int
virFirewallApply(virFirewall *firewall)
{
    size_t i, j;
    VIR_LOCK_GUARD lock = virLockGuardLock(&fwCmdLock);

    if (!firewall || firewall->err) {
        int err = EINVAL;

        if (firewall)
            err = firewall->err;

        virReportSystemError(err, "%s", _("Unable to create firewall command"));
        return -1;
    }

    VIR_DEBUG("Applying groups for %p", firewall);
    for (i = 0; i < firewall->ngroups; i++) {
        if (virFirewallApplyGroup(firewall, i) < 0) {
            size_t first = i;
            virErrorPtr saved_error;

            VIR_DEBUG("Rolling back groups up to %zu for %p", i, firewall);

            virErrorPreserveLast(&saved_error);

            /*
             * Look at any inheritance markers to figure out
             * what the first rollback group we need to apply is
             */
            for (j = 0; j < i; j++) {
                VIR_DEBUG("Checking inheritance of group %zu", i - j);
                if (firewall->groups[i - j]->rollbackFlags &
                    VIR_FIREWALL_ROLLBACK_INHERIT_PREVIOUS)
                    first = (i - j) - 1;
            }
            /*
             * Now apply all rollback groups in order
             */
            for (j = first; j <= i; j++) {
                VIR_DEBUG("Rolling back group %zu", j);
                virFirewallRollbackGroup(firewall, j);
            }

            virErrorRestore(&saved_error);
            VIR_DEBUG("Done rolling back groups for %p", firewall);
            return -1;
        }
    }
    VIR_DEBUG("Done applying groups for %p", firewall);

    return 0;
}
