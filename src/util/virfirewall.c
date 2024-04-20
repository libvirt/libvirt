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
              "iptables",
              "nftables");

VIR_ENUM_DECL(virFirewallLayer);
VIR_ENUM_IMPL(virFirewallLayer,
              VIR_FIREWALL_LAYER_LAST,
              "ethernet",
              "ipv4",
              "ipv6",
);

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

    char *name;
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


const char *
virFirewallGetName(virFirewall *firewall)
{
    return firewall->name;
}


void
virFirewallSetName(virFirewall *firewall,
                   const char *name)
{
    g_free(firewall->name);
    firewall->name = g_strdup(name);
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
    g_free(firewall->name);
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
static virFirewallTransactionFlags
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


#define VIR_IPTABLES_ARG_IS_CREATE(arg) \
    (STREQ(arg, "--insert") || STREQ(arg, "-I") || \
     STREQ(arg, "--append") || STREQ(arg, "-A"))


static int
virFirewallCmdIptablesApply(virFirewall *firewall,
                            virFirewallCmd *fwCmd,
                            char **output)
{
    const char *bin = virFirewallLayerCommandTypeToString(fwCmd->layer);
    bool checkRollback = (virFirewallTransactionGetFlags(firewall) &
                          VIR_FIREWALL_TRANSACTION_AUTO_ROLLBACK);
    bool needRollback = false;
    g_autoptr(virCommand) cmd = NULL;
    g_autofree char *cmdStr = NULL;
    g_autofree char *error = NULL;
    size_t i;
    int status;

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

    for (i = 0; i < fwCmd->argsLen; i++) {
        /* the -I/-A arg could be at any position in the list */
        if (checkRollback && VIR_IPTABLES_ARG_IS_CREATE(fwCmd->args[i]))
            needRollback = true;

        virCommandAddArg(cmd, fwCmd->args[i]);
    }

    cmdStr = virCommandToString(cmd, false);
    VIR_INFO("Running firewall command '%s'", NULLSTR(cmdStr));

    virCommandSetOutputBuffer(cmd, output);
    virCommandSetErrorBuffer(cmd, &error);

    if (virCommandRun(cmd, &status) < 0)
        return -1;

    if (status != 0) {
        /* the command failed, decide whether or not to report it */
        if (fwCmd->ignoreErrors) {
            VIR_DEBUG("Ignoring error running command");
            return 0;
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to run firewall command %1$s: %2$s"),
                           NULLSTR(cmdStr), NULLSTR(error));
            VIR_FREE(*output);
            return -1;
        }
    }

    /* the command was successful, see if we need to add a
     * rollback command
     */

    if (needRollback) {
        virFirewallCmd *rollback
            = virFirewallAddRollbackCmd(firewall, fwCmd->layer, NULL);
        g_autofree char *rollbackStr = NULL;

        for (i = 0; i < fwCmd->argsLen; i++) {
            /* iptables --delete wants the entire commandline that
             * was used for --insert but with s/insert/delete/
             */
            if (VIR_IPTABLES_ARG_IS_CREATE(fwCmd->args[i])) {
                virFirewallCmdAddArg(firewall, rollback, "--delete");
            } else {
                virFirewallCmdAddArg(firewall, rollback, fwCmd->args[i]);
            }
        }

        rollbackStr = virFirewallCmdToString(virFirewallLayerCommandTypeToString(fwCmd->layer),
                                             rollback);
        VIR_DEBUG("Recording Rollback command '%s'", NULLSTR(rollbackStr));
    }

    return 0;
}


#define VIR_NFTABLES_ARG_IS_CREATE(arg) \
    (STREQ(arg, "insert") || STREQ(arg, "add") || STREQ(arg, "create"))

static int
virFirewallCmdNftablesApply(virFirewall *firewall G_GNUC_UNUSED,
                            virFirewallCmd *fwCmd,
                             char **output)
{
    bool needRollback = false;
    size_t cmdIdx = 0;
    const char *objectType = NULL;
    g_autoptr(virCommand) cmd = NULL;
    g_autofree char *cmdStr = NULL;
    g_autofree char *error = NULL;
    size_t i;
    int status;

    cmd = virCommandNew(NFT);

    if ((virFirewallTransactionGetFlags(firewall) & VIR_FIREWALL_TRANSACTION_AUTO_ROLLBACK) &&
        fwCmd->argsLen > 1) {
        /* skip any leading options to get to command verb */
        for (i = 0; i < fwCmd->argsLen - 1; i++) {
            if (fwCmd->args[i][0] != '-')
                break;
        }

        if (i + 1 < fwCmd->argsLen &&
            VIR_NFTABLES_ARG_IS_CREATE(fwCmd->args[i])) {

            cmdIdx = i;
            objectType = fwCmd->args[i + 1];

            /* we currently only handle auto-rollback for rules,
             * chains, and tables, and those all can be "rolled
             * back" by a delete command using the handle that is
             * returned when "-ae" is added to the add/insert
             * command.
             */
            if (STREQ_NULLABLE(objectType, "rule") ||
                STREQ_NULLABLE(objectType, "chain") ||
                STREQ_NULLABLE(objectType, "table")) {

                needRollback = true;
                /* this option to nft instructs it to add the
                 * "handle" of the created object to stdout
                 */
                virCommandAddArg(cmd, "-ae");
            }
        }
    }

    for (i = 0; i < fwCmd->argsLen; i++)
        virCommandAddArg(cmd, fwCmd->args[i]);

    cmdStr = virCommandToString(cmd, false);
    VIR_INFO("Applying '%s'", NULLSTR(cmdStr));

    virCommandSetOutputBuffer(cmd, output);
    virCommandSetErrorBuffer(cmd, &error);

    if (virCommandRun(cmd, &status) < 0)
        return -1;

    if (status != 0) {
        if (STREQ_NULLABLE(fwCmd->args[0], "list")) {
            /* nft returns error status when the target of a "list"
             * command doesn't exist, but we always want to just have
             * an empty result, so this is not actually an error.
             */
        } else if (fwCmd->ignoreErrors) {
            VIR_DEBUG("Ignoring error running command");
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to apply firewall command '%1$s': %2$s"),
                           NULLSTR(cmdStr), NULLSTR(error));
            VIR_FREE(*output);
            return -1;
        }

        /* there was an error, so we won't be building any rollback command,
         * but the error should be ignored, so we return success
         */
        return 0;
    }

    if (needRollback) {
        virFirewallCmd *rollback = virFirewallAddRollbackCmd(firewall, fwCmd->layer, NULL);
        const char *handleStart = NULL;
        size_t handleLen = 0;
        g_autofree char *handleStr = NULL;
        g_autofree char *rollbackStr = NULL;

        /* Search for "# handle n" in stdout of the nft add command -
         * that is the handle of the table/rule/chain that will later
         * need to be deleted.
         */

        if ((handleStart = strstr(*output, "# handle "))) {
            handleStart += 9; /* move past "# handle " */
            handleLen = strspn(handleStart, "0123456789");
        }

        if (!handleLen) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("couldn't register rollback command - command '%1$s' had no valid handle in output ('%2$s')"),
                           NULLSTR(cmdStr), NULLSTR(*output));
            return -1;
        }

        handleStr = g_strdup_printf("%.*s", (int)handleLen, handleStart);

        /* The rollback command is created from the original command like this:
         *
         * 1) skip any leading options
         * 2) replace add/insert with delete
         * 3) keep the type of item being added (rule/chain/table)
         * 4) keep the class (ip/ip6/inet)
         * 5) for chain/rule, keep the table name
         * 6) for rule, keep the chain name
         * 7) add "handle n" where "n" is parsed from the
         *    stdout of the original nft command
         */
        virFirewallCmdAddArgList(firewall, rollback, "delete", objectType,
                                 fwCmd->args[cmdIdx + 2], /* ip/ip6/inet */
                                 NULL);

        if (STREQ_NULLABLE(objectType, "rule") ||
            STREQ_NULLABLE(objectType, "chain")) {
            /* include table name in command */
            virFirewallCmdAddArg(firewall, rollback, fwCmd->args[cmdIdx + 3]);
        }

        if (STREQ_NULLABLE(objectType, "rule")) {
            /* include chain name in command */
            virFirewallCmdAddArg(firewall, rollback, fwCmd->args[cmdIdx + 4]);
        }

        virFirewallCmdAddArgList(firewall, rollback, "handle", handleStr, NULL);

        rollbackStr = virFirewallCmdToString(NFT, rollback);
        VIR_DEBUG("Recording Rollback command '%s'", NULLSTR(rollbackStr));
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

    switch (virFirewallGetBackend(firewall)) {
    case VIR_FIREWALL_BACKEND_IPTABLES:
        if (virFirewallCmdIptablesApply(firewall, fwCmd, &output) < 0)
            return -1;
        break;

    case VIR_FIREWALL_BACKEND_NFTABLES:
        if (virFirewallCmdNftablesApply(firewall, fwCmd, &output) < 0)
            return -1;
        break;

    case VIR_FIREWALL_BACKEND_LAST:
    default:
        virReportEnumRangeError(virFirewallBackend,
                                virFirewallGetBackend(firewall));
        return -1;
    }

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


/**
 * virFirewallNewFromRollback:

 * @original: the original virFirewall object containing the rollback
 *            of interest
 * @fwRemoval: a firewall object that, when applied, will remove @original
 *
 * Copy the rollback rules from the current virFirewall object as a
 * new virFirewall. This virFirewall can then be saved to apply later
 * and counteract everything done by the original.
 *
 * Returns 0 on success, -1 on error
 */
int
virFirewallNewFromRollback(virFirewall *original,
                           virFirewall **fwRemoval)
{
    size_t g;
    g_autoptr(virFirewall) firewall = NULL;

    if (original->err) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("error in original firewall object"));
        return -1;
    }

    firewall = virFirewallNew(original->backend);

    /* add the rollback commands in reverse order of actions/groups of
     * what was applied in the original firewall.
     */
    for (g = original->ngroups; g > 0; g--) {
        size_t r;
        virFirewallGroup *group = original->groups[g - 1];

        if (group->nrollback == 0)
            continue;

        virFirewallStartTransaction(firewall, VIR_FIREWALL_TRANSACTION_IGNORE_ERRORS);

        for (r = group->nrollback; r > 0; r--) {
            size_t i;
            virFirewallCmd *origCmd = group->rollback[r - 1];
            virFirewallCmd *rbCmd = virFirewallAddCmd(firewall, origCmd->layer, NULL);

            for (i = 0; i < origCmd->argsLen; i++)
                ADD_ARG(rbCmd, origCmd->args[i]);
        }
    }

    if (firewall->ngroups == 0)
        VIR_DEBUG("original firewall object is empty");
    else
        *fwRemoval = g_steal_pointer(&firewall);

    return 0;
}


/* virFirewallGetFlagsFromNode:
 * @node: the xmlNode to check for an ignoreErrors attribute
 *
 * A short helper to get the setting of the ignorErrors attribute from
 * an xmlNode.  Returns -1 on error (with error reported), or the
 * VIR_FIREWALL_TRANSACTION_IGNORE_ERRORS bit set/reset according to
 * the value of the attribute.
 */
static int
virFirewallGetFlagsFromNode(xmlNodePtr node)
{
    virTristateBool ignoreErrors;

    if (virXMLPropTristateBool(node, "ignoreErrors", VIR_XML_PROP_NONE, &ignoreErrors) < 0)
        return -1;

    if (ignoreErrors == VIR_TRISTATE_BOOL_YES)
        return VIR_FIREWALL_TRANSACTION_IGNORE_ERRORS;
    return 0;
}


/**
 * virFirewallParseXML:
 * @firewall: pointer to virFirewall* to fill in with new virFirewall object
 *
 * Construct a new virFirewall object according to the XML in
 * xmlNodePtr.  Return 0 (and new object) on success, or -1 (with
 * error reported) on error.
 *
 * Example of <firewall> element XML:
 *
 * <firewall backend='iptables|nftables'>
 *   <group ignoreErrors='yes|no'>
 *     <action layer='ethernet|ipv4|ipv6' ignoreErrors='yes|no'>
 *       <args>
 *         <item>arg1</item>
 *         <item>arg2</item>
 *         ...
 *       </args>
 *     </action>
 *     <action ...>
 *       ...
       </action>
 *     ...
 *   </group>
 *   ...
 * </firewall>
 */
int
virFirewallParseXML(virFirewall **firewall,
                    xmlNodePtr node,
                    xmlXPathContextPtr ctxt)
{
    g_autoptr(virFirewall) newfw = NULL;
    virFirewallBackend backend;
    g_autofree xmlNodePtr *groupNodes = NULL;
    ssize_t ngroups;
    size_t g;
    VIR_XPATH_NODE_AUTORESTORE(ctxt);

    ctxt->node = node;

    if (virXMLPropEnum(node, "backend", virFirewallBackendTypeFromString,
                       VIR_XML_PROP_REQUIRED, &backend) < 0) {
        return -1;
    }

    newfw = virFirewallNew(backend);

    newfw->name = virXMLPropString(node, "name");

    ngroups = virXPathNodeSet("./group", ctxt, &groupNodes);
    if (ngroups < 0)
        return -1;

    for (g = 0; g < ngroups; g++) {
        int flags = 0;
        g_autofree xmlNodePtr *actionNodes = NULL;
        ssize_t nactions;
        size_t a;

        ctxt->node = groupNodes[g];
        nactions = virXPathNodeSet("./action", ctxt, &actionNodes);
        if (nactions < 0)
            return -1;
        if (nactions == 0)
            continue;

        if ((flags = virFirewallGetFlagsFromNode(groupNodes[g])) < 0)
            return -1;

        virFirewallStartTransaction(newfw, flags);

        for (a = 0; a < nactions; a++) {
            g_autofree xmlNodePtr *argsNodes = NULL;
            ssize_t nargs;
            size_t i;
            virFirewallLayer layer;
            virFirewallCmd *action;
            bool ignoreErrors;

            ctxt->node = actionNodes[a];

            if (!(ctxt->node = virXPathNode("./args", ctxt)))
                continue;

            if ((flags = virFirewallGetFlagsFromNode(actionNodes[a])) < 0)
                return -1;

            ignoreErrors = flags & VIR_FIREWALL_TRANSACTION_IGNORE_ERRORS;

            if (virXMLPropEnum(actionNodes[a], "layer",
                               virFirewallLayerTypeFromString,
                               VIR_XML_PROP_REQUIRED, &layer) < 0) {
                return -1;
            }

            nargs = virXPathNodeSet("./item", ctxt, &argsNodes);
            if (nargs < 0)
                return -1;
            if (nargs == 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Invalid firewall command has 0 arguments"));
                return -1;
            }

            action = virFirewallAddCmdFull(newfw, layer, ignoreErrors,
                                           NULL, NULL, NULL);
            for (i = 0; i < nargs; i++) {

                char *arg = virXMLNodeContentString(argsNodes[i]);
                if (!arg)
                    return -1;

                virFirewallCmdAddArg(newfw, action, arg);
            }
        }
    }

    *firewall = g_steal_pointer(&newfw);
    return 0;
}


/**
 * virFirewallFormat:
 * @buf: output buffer
 * @firewall: the virFirewall object to format as XML
 *
 * Format virFirewall object @firewall into @buf as XML.
 * Returns 0 on success, -1 on failure.
 *
 */
int
virFirewallFormat(virBuffer *buf,
                  virFirewall *firewall)
{
    size_t g;
    g_auto(virBuffer) attrBuf = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) childBuf = VIR_BUFFER_INIT_CHILD(buf);

    virBufferEscapeString(&attrBuf, " name='%s'", firewall->name);
    virBufferAsprintf(&attrBuf, " backend='%s'",
                      virFirewallBackendTypeToString(virFirewallGetBackend(firewall)));

    for (g = 0; g <  firewall->ngroups; g++) {
        virFirewallGroup *group = firewall->groups[g];
        bool groupIgnoreErrors  = (group->actionFlags &
                                   VIR_FIREWALL_TRANSACTION_IGNORE_ERRORS);
        size_t a;

        virBufferAddLit(&childBuf, "<group");
        if (groupIgnoreErrors)
            virBufferAddLit(&childBuf, " ignoreErrors='yes'");
        virBufferAddLit(&childBuf, ">\n");
        virBufferAdjustIndent(&childBuf, 2);

        for (a = 0; a < group->naction; a++) {
            virFirewallCmd *action = group->action[a];
            size_t i;

            virBufferAsprintf(&childBuf, "<action layer='%s'",
                              virFirewallLayerTypeToString(action->layer));
            /* if the entire group has ignoreErrors='yes', then it's
             * redundant to have it for an action of the group
            */
            if (action->ignoreErrors && !groupIgnoreErrors)
                virBufferAddLit(&childBuf, " ignoreErrors='yes'");
            virBufferAddLit(&childBuf, ">\n");

            virBufferAdjustIndent(&childBuf, 2);
            virBufferAddLit(&childBuf, "<args>\n");
            virBufferAdjustIndent(&childBuf, 2);
            for (i = 0; i < virFirewallCmdGetArgCount(action); i++)
                virBufferEscapeString(&childBuf, "<item>%s</item>\n", action->args[i]);
            virBufferAdjustIndent(&childBuf, -2);
            virBufferAddLit(&childBuf, "</args>\n");
            virBufferAdjustIndent(&childBuf, -2);
            virBufferAddLit(&childBuf, "</action>\n");
        }

        virBufferAdjustIndent(&childBuf, -2);
        virBufferAddLit(&childBuf, "</group>\n");
    }

    virXMLFormatElement(buf, "firewall", &attrBuf, &childBuf);
    return 0;
}
