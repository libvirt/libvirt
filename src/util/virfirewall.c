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

typedef struct _virFirewallGroup virFirewallGroup;

VIR_ENUM_DECL(virFirewallLayerCommand);
VIR_ENUM_IMPL(virFirewallLayerCommand,
              VIR_FIREWALL_LAYER_LAST,
              EBTABLES,
              IPTABLES,
              IP6TABLES,
);

struct _virFirewallRule {
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
    virFirewallRule **action;

    size_t nrollback;
    virFirewallRule **rollback;

    bool addingRollback;
};


struct _virFirewall {
    int err;

    size_t ngroups;
    virFirewallGroup **groups;
    size_t currentGroup;
};

static virMutex ruleLock = VIR_MUTEX_INITIALIZER;

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
virFirewall *virFirewallNew(void)
{
    virFirewall *firewall = g_new0(virFirewall, 1);

    return firewall;
}


static void
virFirewallRuleFree(virFirewallRule *rule)
{
    size_t i;

    if (!rule)
        return;

    for (i = 0; i < rule->argsLen; i++)
        g_free(rule->args[i]);
    g_free(rule->args);
    g_free(rule);
}


static void
virFirewallGroupFree(virFirewallGroup *group)
{
    size_t i;

    if (!group)
        return;

    for (i = 0; i < group->naction; i++)
        virFirewallRuleFree(group->action[i]);
    g_free(group->action);

    for (i = 0; i < group->nrollback; i++)
        virFirewallRuleFree(group->rollback[i]);
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

#define VIR_FIREWALL_RULE_RETURN_IF_ERROR(firewall, rule)\
    do { \
        if (!firewall || firewall->err || !rule) \
            return; \
    } while (0)

#define VIR_FIREWALL_RETURN_NULL_IF_ERROR(firewall) \
    do { \
        if (!firewall || firewall->err) \
            return NULL; \
    } while (0)

#define ADD_ARG(rule, str) \
    do { \
        VIR_RESIZE_N(rule->args, rule->argsAlloc, rule->argsLen, 1); \
        rule->args[rule->argsLen++] = g_strdup(str); \
    } while (0)

static virFirewallRule *
virFirewallAddRuleFullV(virFirewall *firewall,
                        virFirewallLayer layer,
                        bool ignoreErrors,
                        virFirewallQueryCallback cb,
                        void *opaque,
                        va_list args)
{
    virFirewallGroup *group;
    virFirewallRule *rule;
    char *str;

    VIR_FIREWALL_RETURN_NULL_IF_ERROR(firewall);

    if (firewall->ngroups == 0) {
        firewall->err = EINVAL;
        return NULL;
    }
    group = firewall->groups[firewall->currentGroup];


    rule = g_new0(virFirewallRule, 1);

    rule->layer = layer;
    rule->queryCB = cb;
    rule->queryOpaque = opaque;
    rule->ignoreErrors = ignoreErrors;

    switch (rule->layer) {
    case VIR_FIREWALL_LAYER_ETHERNET:
        ADD_ARG(rule, "--concurrent");
        break;
    case VIR_FIREWALL_LAYER_IPV4:
        ADD_ARG(rule, "-w");
        break;
    case VIR_FIREWALL_LAYER_IPV6:
        ADD_ARG(rule, "-w");
        break;
    case VIR_FIREWALL_LAYER_LAST:
        break;
    }

    while ((str = va_arg(args, char *)) != NULL)
        ADD_ARG(rule, str);

    if (group->addingRollback) {
        VIR_APPEND_ELEMENT_COPY(group->rollback, group->nrollback, rule);
    } else {
        VIR_APPEND_ELEMENT_COPY(group->action, group->naction, rule);
    }


    return rule;
}


/**
 * virFirewallAddRuleFull:
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
 * rules by invoking the virFirewallAddRule method, but
 * is not permitted to start new transactions.
 *
 * If @ignoreErrors is set to TRUE, then any failure of
 * the command is ignored. If it is set to FALSE, then
 * the behaviour upon failure is determined by the flags
 * set when the transaction was started.
 *
 * Returns the new rule
 */
virFirewallRule *virFirewallAddRuleFull(virFirewall *firewall,
                                          virFirewallLayer layer,
                                          bool ignoreErrors,
                                          virFirewallQueryCallback cb,
                                          void *opaque,
                                          ...)
{
    virFirewallRule *rule;
    va_list args;
    va_start(args, opaque);
    rule = virFirewallAddRuleFullV(firewall, layer, ignoreErrors, cb, opaque, args);
    va_end(args);
    return rule;
}


/**
 * virFirewallRemoveRule:
 * @firewall: firewall ruleset to remove from
 * @rule: the rule to remove
 *
 * Remove a rule from the current transaction
 */
void virFirewallRemoveRule(virFirewall *firewall,
                           virFirewallRule *rule)
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
            if (group->rollback[i] == rule) {
                VIR_DELETE_ELEMENT(group->rollback,
                                   i,
                                   group->nrollback);
                virFirewallRuleFree(rule);
                break;
            }
        }
    } else {
        for (i = 0; i < group->naction; i++) {
            if (group->action[i] == rule) {
                VIR_DELETE_ELEMENT(group->action,
                                   i,
                                   group->naction);
                virFirewallRuleFree(rule);
                return;
            }
        }
    }
}


void virFirewallRuleAddArg(virFirewall *firewall,
                           virFirewallRule *rule,
                           const char *arg)
{
    VIR_FIREWALL_RULE_RETURN_IF_ERROR(firewall, rule);

    ADD_ARG(rule, arg);

    return;
}


void virFirewallRuleAddArgFormat(virFirewall *firewall,
                                 virFirewallRule *rule,
                                 const char *fmt, ...)
{
    g_autofree char *arg = NULL;
    va_list list;

    VIR_FIREWALL_RULE_RETURN_IF_ERROR(firewall, rule);

    va_start(list, fmt);
    arg = g_strdup_vprintf(fmt, list);
    va_end(list);

    ADD_ARG(rule, arg);

    return;
}


void virFirewallRuleAddArgSet(virFirewall *firewall,
                              virFirewallRule *rule,
                              const char *const *args)
{
    VIR_FIREWALL_RULE_RETURN_IF_ERROR(firewall, rule);

    while (*args) {
        ADD_ARG(rule, *args);
        args++;
    }

    return;
}


void virFirewallRuleAddArgList(virFirewall *firewall,
                               virFirewallRule *rule,
                               ...)
{
    va_list list;
    const char *str;

    VIR_FIREWALL_RULE_RETURN_IF_ERROR(firewall, rule);

    va_start(list, rule);

    while ((str = va_arg(list, char *)) != NULL)
        ADD_ARG(rule, str);

    va_end(list);

    return;
}


size_t virFirewallRuleGetArgCount(virFirewallRule *rule)
{
    if (!rule)
        return 0;
    return rule->argsLen;
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
virFirewallRuleToString(const char *cmd,
                        virFirewallRule *rule)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    size_t i;

    virBufferAdd(&buf, cmd, -1);
    for (i = 0; i < rule->argsLen; i++) {
        virBufferAddLit(&buf, " ");
        virBufferAdd(&buf, rule->args[i], -1);
    }

    return virBufferContentAndReset(&buf);
}


static int
virFirewallApplyRuleDirect(virFirewallRule *rule,
                           bool ignoreErrors,
                           char **output)
{
    size_t i;
    const char *bin = virFirewallLayerCommandTypeToString(rule->layer);
    g_autoptr(virCommand) cmd = NULL;
    g_autofree char *cmdStr = NULL;
    int status;
    g_autofree char *error = NULL;

    if (!bin) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unknown firewall layer %1$d"),
                       rule->layer);
        return -1;
    }

    cmd = virCommandNewArgList(bin, NULL);

    for (i = 0; i < rule->argsLen; i++)
        virCommandAddArg(cmd, rule->args[i]);

    cmdStr = virCommandToString(cmd, false);
    VIR_INFO("Applying rule '%s'", NULLSTR(cmdStr));

    virCommandSetOutputBuffer(cmd, output);
    virCommandSetErrorBuffer(cmd, &error);

    if (virCommandRun(cmd, &status) < 0)
        return -1;

    if (status != 0) {
        if (ignoreErrors) {
            VIR_DEBUG("Ignoring error running command");
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to apply firewall rules %1$s: %2$s"),
                           NULLSTR(cmdStr), NULLSTR(error));
            VIR_FREE(*output);
            return -1;
        }
    }

    return 0;
}


static int
virFirewallApplyRule(virFirewall *firewall,
                     virFirewallRule *rule,
                     bool ignoreErrors)
{
    g_autofree char *output = NULL;
    g_auto(GStrv) lines = NULL;

    if (rule->ignoreErrors)
        ignoreErrors = rule->ignoreErrors;

    if (virFirewallApplyRuleDirect(rule, ignoreErrors, &output) < 0)
        return -1;

    if (rule->queryCB && output) {
        if (!(lines = g_strsplit(output, "\n", -1)))
            return -1;

        VIR_DEBUG("Invoking query %p with '%s'", rule->queryCB, output);
        if (rule->queryCB(firewall, rule->layer, (const char *const *)lines, rule->queryOpaque) < 0)
            return -1;

        if (firewall->err) {
            virReportSystemError(firewall->err, "%s",
                                 _("Unable to create rule"));
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
    bool ignoreErrors = (group->actionFlags & VIR_FIREWALL_TRANSACTION_IGNORE_ERRORS);
    size_t i;

    VIR_INFO("Starting transaction for firewall=%p group=%p flags=0x%x",
             firewall, group, group->actionFlags);
    firewall->currentGroup = idx;
    group->addingRollback = false;
    for (i = 0; i < group->naction; i++) {
        if (virFirewallApplyRule(firewall,
                                 group->action[i],
                                 ignoreErrors) < 0)
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
    for (i = 0; i < group->nrollback; i++) {
        ignore_value(virFirewallApplyRule(firewall,
                                          group->rollback[i],
                                          true));
    }
}


int
virFirewallApply(virFirewall *firewall)
{
    size_t i, j;
    VIR_LOCK_GUARD lock = virLockGuardLock(&ruleLock);

    if (!firewall || firewall->err) {
        int err = EINVAL;

        if (firewall)
            err = firewall->err;

        virReportSystemError(err, "%s", _("Unable to create rule"));
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
