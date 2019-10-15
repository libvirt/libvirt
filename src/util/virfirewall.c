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

#define LIBVIRT_VIRFIREWALLPRIV_H_ALLOW
#include "virfirewallpriv.h"
#include "virfirewalld.h"
#include "viralloc.h"
#include "virerror.h"
#include "virutil.h"
#include "virstring.h"
#include "vircommand.h"
#include "virlog.h"
#include "virfile.h"
#include "virthread.h"

#define VIR_FROM_THIS VIR_FROM_FIREWALL

VIR_LOG_INIT("util.firewall");

typedef struct _virFirewallGroup virFirewallGroup;
typedef virFirewallGroup *virFirewallGroupPtr;

VIR_ENUM_DECL(virFirewallLayerCommand);
VIR_ENUM_IMPL(virFirewallLayerCommand,
              VIR_FIREWALL_LAYER_LAST,
              EBTABLES_PATH,
              IPTABLES_PATH,
              IP6TABLES_PATH,
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
    virFirewallRulePtr *action;

    size_t nrollback;
    virFirewallRulePtr *rollback;

    bool addingRollback;
};


struct _virFirewall {
    int err;

    size_t ngroups;
    virFirewallGroupPtr *groups;
    size_t currentGroup;
};

static virFirewallBackend currentBackend = VIR_FIREWALL_BACKEND_AUTOMATIC;
static virMutex ruleLock = VIR_MUTEX_INITIALIZER;

static int
virFirewallValidateBackend(virFirewallBackend backend);

static int
virFirewallOnceInit(void)
{
    return virFirewallValidateBackend(currentBackend);
}

VIR_ONCE_GLOBAL_INIT(virFirewall);

static bool iptablesUseLock;
static bool ip6tablesUseLock;
static bool ebtablesUseLock;
static bool lockOverride; /* true to avoid lock probes */

void
virFirewallSetLockOverride(bool avoid)
{
    lockOverride = avoid;
}

static void
virFirewallCheckUpdateLock(bool *lockflag,
                           const char *const*args)
{
    int status; /* Ignore failed commands without logging them */
    VIR_AUTOPTR(virCommand) cmd = virCommandNewArgs(args);
    if (virCommandRun(cmd, &status) < 0 || status) {
        VIR_INFO("locking not supported by %s", args[0]);
    } else {
        VIR_INFO("using locking for %s", args[0]);
        *lockflag = true;
    }
}

static void
virFirewallCheckUpdateLocking(void)
{
    const char *iptablesArgs[] = {
        IPTABLES_PATH, "-w", "-L", "-n", NULL,
    };
    const char *ip6tablesArgs[] = {
        IP6TABLES_PATH, "-w", "-L", "-n", NULL,
    };
    const char *ebtablesArgs[] = {
        EBTABLES_PATH, "--concurrent", "-L", NULL,
    };
    if (lockOverride)
        return;
    virFirewallCheckUpdateLock(&iptablesUseLock,
                               iptablesArgs);
    virFirewallCheckUpdateLock(&ip6tablesUseLock,
                               ip6tablesArgs);
    virFirewallCheckUpdateLock(&ebtablesUseLock,
                               ebtablesArgs);
}

static int
virFirewallValidateBackend(virFirewallBackend backend)
{
    VIR_DEBUG("Validating backend %d", backend);
    if (backend == VIR_FIREWALL_BACKEND_AUTOMATIC ||
        backend == VIR_FIREWALL_BACKEND_FIREWALLD) {
        int rv = virFirewallDIsRegistered();

        VIR_DEBUG("Firewalld is registered ? %d", rv);
        if (rv < 0) {
            if (rv == -2) {
                if (backend == VIR_FIREWALL_BACKEND_FIREWALLD) {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("firewalld firewall backend requested, but service is not running"));
                    return -1;
                } else {
                    VIR_DEBUG("firewalld service not running, trying direct backend");
                    backend = VIR_FIREWALL_BACKEND_DIRECT;
                }
            } else {
                return -1;
            }
        } else {
            VIR_DEBUG("firewalld service running, using firewalld backend");
            backend = VIR_FIREWALL_BACKEND_FIREWALLD;
        }
    }

    if (backend == VIR_FIREWALL_BACKEND_DIRECT) {
        const char *commands[] = {
            IPTABLES_PATH, IP6TABLES_PATH, EBTABLES_PATH
        };
        size_t i;

        for (i = 0; i < G_N_ELEMENTS(commands); i++) {
            if (!virFileIsExecutable(commands[i])) {
                virReportSystemError(errno,
                                     _("direct firewall backend requested, but %s is not available"),
                                     commands[i]);
                return -1;
            }
        }
        VIR_DEBUG("found iptables/ip6tables/ebtables, using direct backend");
    }

    currentBackend = backend;

    virFirewallCheckUpdateLocking();

    return 0;
}

int
virFirewallSetBackend(virFirewallBackend backend)
{
    currentBackend = backend;

    if (virFirewallInitialize() < 0)
        return -1;

    return virFirewallValidateBackend(backend);
}

static virFirewallGroupPtr
virFirewallGroupNew(void)
{
    virFirewallGroupPtr group;

    if (VIR_ALLOC(group) < 0)
        return NULL;

    return group;
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
virFirewallPtr virFirewallNew(void)
{
    virFirewallPtr firewall;

    if (virFirewallInitialize() < 0)
        return NULL;

    if (VIR_ALLOC(firewall) < 0)
        return NULL;

    return firewall;
}


static void
virFirewallRuleFree(virFirewallRulePtr rule)
{
    size_t i;

    if (!rule)
        return;

    for (i = 0; i < rule->argsLen; i++)
        VIR_FREE(rule->args[i]);
    VIR_FREE(rule->args);
    VIR_FREE(rule);
}


static void
virFirewallGroupFree(virFirewallGroupPtr group)
{
    size_t i;

    if (!group)
        return;

    for (i = 0; i < group->naction; i++)
        virFirewallRuleFree(group->action[i]);
    VIR_FREE(group->action);

    for (i = 0; i < group->nrollback; i++)
        virFirewallRuleFree(group->rollback[i]);
    VIR_FREE(group->rollback);

    VIR_FREE(group);
}


/**
 * virFirewallFree:
 *
 * Release all memory associated with the firewall
 * ruleset
 */
void virFirewallFree(virFirewallPtr firewall)
{
    size_t i;

    if (!firewall)
        return;

    for (i = 0; i < firewall->ngroups; i++)
        virFirewallGroupFree(firewall->groups[i]);
    VIR_FREE(firewall->groups);

    VIR_FREE(firewall);
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
        if (VIR_RESIZE_N(rule->args, \
                         rule->argsAlloc, \
                         rule->argsLen, 1) < 0) \
            goto no_memory; \
 \
        if (VIR_STRDUP(rule->args[rule->argsLen++], str) < 0) \
            goto no_memory; \
    } while (0)

static virFirewallRulePtr
virFirewallAddRuleFullV(virFirewallPtr firewall,
                        virFirewallLayer layer,
                        bool ignoreErrors,
                        virFirewallQueryCallback cb,
                        void *opaque,
                        va_list args)
{
    virFirewallGroupPtr group;
    virFirewallRulePtr rule;
    char *str;

    VIR_FIREWALL_RETURN_NULL_IF_ERROR(firewall);

    if (firewall->ngroups == 0) {
        firewall->err = EINVAL;
        return NULL;
    }
    group = firewall->groups[firewall->currentGroup];


    if (VIR_ALLOC(rule) < 0)
        goto no_memory;

    rule->layer = layer;
    rule->queryCB = cb;
    rule->queryOpaque = opaque;
    rule->ignoreErrors = ignoreErrors;

    switch (rule->layer) {
    case VIR_FIREWALL_LAYER_ETHERNET:
        if (ebtablesUseLock)
            ADD_ARG(rule, "--concurrent");
        break;
    case VIR_FIREWALL_LAYER_IPV4:
        if (iptablesUseLock)
            ADD_ARG(rule, "-w");
        break;
    case VIR_FIREWALL_LAYER_IPV6:
        if (ip6tablesUseLock)
            ADD_ARG(rule, "-w");
        break;
    case VIR_FIREWALL_LAYER_LAST:
        break;
    }

    while ((str = va_arg(args, char *)) != NULL)
        ADD_ARG(rule, str);

    if (group->addingRollback) {
        if (VIR_APPEND_ELEMENT_COPY(group->rollback,
                                    group->nrollback,
                                    rule) < 0)
            goto no_memory;
    } else {
        if (VIR_APPEND_ELEMENT_COPY(group->action,
                                    group->naction,
                                    rule) < 0)
            goto no_memory;
    }


    return rule;

 no_memory:
    firewall->err = ENOMEM;
    virFirewallRuleFree(rule);
    return NULL;
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
virFirewallRulePtr virFirewallAddRuleFull(virFirewallPtr firewall,
                                          virFirewallLayer layer,
                                          bool ignoreErrors,
                                          virFirewallQueryCallback cb,
                                          void *opaque,
                                          ...)
{
    virFirewallRulePtr rule;
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
void virFirewallRemoveRule(virFirewallPtr firewall,
                           virFirewallRulePtr rule)
{
    size_t i;
    virFirewallGroupPtr group;

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


void virFirewallRuleAddArg(virFirewallPtr firewall,
                           virFirewallRulePtr rule,
                           const char *arg)
{
    VIR_FIREWALL_RULE_RETURN_IF_ERROR(firewall, rule);

    ADD_ARG(rule, arg);

    return;

 no_memory:
    firewall->err = ENOMEM;
}


void virFirewallRuleAddArgFormat(virFirewallPtr firewall,
                                 virFirewallRulePtr rule,
                                 const char *fmt, ...)
{
    VIR_AUTOFREE(char *) arg = NULL;
    va_list list;

    VIR_FIREWALL_RULE_RETURN_IF_ERROR(firewall, rule);

    va_start(list, fmt);

    if (virVasprintf(&arg, fmt, list) < 0)
        goto no_memory;

    ADD_ARG(rule, arg);

    va_end(list);

    return;

 no_memory:
    firewall->err = ENOMEM;
    va_end(list);
}


void virFirewallRuleAddArgSet(virFirewallPtr firewall,
                              virFirewallRulePtr rule,
                              const char *const *args)
{
    VIR_FIREWALL_RULE_RETURN_IF_ERROR(firewall, rule);

    while (*args) {
        ADD_ARG(rule, *args);
        args++;
    }

    return;

 no_memory:
    firewall->err = ENOMEM;
}


void virFirewallRuleAddArgList(virFirewallPtr firewall,
                               virFirewallRulePtr rule,
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

 no_memory:
    firewall->err = ENOMEM;
    va_end(list);
}


size_t virFirewallRuleGetArgCount(virFirewallRulePtr rule)
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
void virFirewallStartTransaction(virFirewallPtr firewall,
                                 unsigned int flags)
{
    virFirewallGroupPtr group;

    VIR_FIREWALL_RETURN_IF_ERROR(firewall);

    if (!(group = virFirewallGroupNew())) {
        firewall->err = ENOMEM;
        return;
    }
    group->actionFlags = flags;

    if (VIR_EXPAND_N(firewall->groups,
                     firewall->ngroups, 1) < 0) {
        firewall->err = ENOMEM;
        virFirewallGroupFree(group);
        return;
    }
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
void virFirewallStartRollback(virFirewallPtr firewall,
                              unsigned int flags)
{
    virFirewallGroupPtr group;

    VIR_FIREWALL_RETURN_IF_ERROR(firewall);

    if (firewall->ngroups == 0) {
        firewall->err = EINVAL;
        return;
    }

    group = firewall->groups[firewall->ngroups-1];
    group->rollbackFlags = flags;
    group->addingRollback = true;
}


static char *
virFirewallRuleToString(virFirewallRulePtr rule)
{
    const char *bin = virFirewallLayerCommandTypeToString(rule->layer);
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    size_t i;

    virBufferAdd(&buf, bin, -1);
    for (i = 0; i < rule->argsLen; i++) {
        virBufferAddLit(&buf, " ");
        virBufferAdd(&buf, rule->args[i], -1);
    }

    return virBufferContentAndReset(&buf);
}

static int
virFirewallApplyRuleDirect(virFirewallRulePtr rule,
                           bool ignoreErrors,
                           char **output)
{
    size_t i;
    const char *bin = virFirewallLayerCommandTypeToString(rule->layer);
    VIR_AUTOPTR(virCommand) cmd = NULL;
    int status;
    VIR_AUTOFREE(char *) error = NULL;

    if (!bin) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unknown firewall layer %d"),
                       rule->layer);
        return -1;
    }

    cmd = virCommandNewArgList(bin, NULL);

    for (i = 0; i < rule->argsLen; i++)
        virCommandAddArg(cmd, rule->args[i]);

    virCommandSetOutputBuffer(cmd, output);
    virCommandSetErrorBuffer(cmd, &error);

    if (virCommandRun(cmd, &status) < 0)
        return -1;

    if (status != 0) {
        if (ignoreErrors) {
            VIR_DEBUG("Ignoring error running command");
        } else {
            VIR_AUTOFREE(char *) args = virCommandToString(cmd, false);
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to apply firewall rules %s: %s"),
                           NULLSTR(args), NULLSTR(error));
            VIR_FREE(*output);
            return -1;
        }
    }

    return 0;
}


static int
virFirewallApplyRuleFirewallD(virFirewallRulePtr rule,
                              bool ignoreErrors,
                              char **output)
{
    /* wrapper necessary because virFirewallRule is a private struct */
    return virFirewallDApplyRule(rule->layer, rule->args, rule->argsLen, ignoreErrors, output);
}

static int
virFirewallApplyRule(virFirewallPtr firewall,
                     virFirewallRulePtr rule,
                     bool ignoreErrors)
{
    VIR_AUTOFREE(char *) output = NULL;
    VIR_AUTOFREE(char *) str = virFirewallRuleToString(rule);
    VIR_AUTOSTRINGLIST lines = NULL;
    VIR_INFO("Applying rule '%s'", NULLSTR(str));

    if (rule->ignoreErrors)
        ignoreErrors = rule->ignoreErrors;

    switch (currentBackend) {
    case VIR_FIREWALL_BACKEND_DIRECT:
        if (virFirewallApplyRuleDirect(rule, ignoreErrors, &output) < 0)
            return -1;
        break;
    case VIR_FIREWALL_BACKEND_FIREWALLD:
        if (virFirewallApplyRuleFirewallD(rule, ignoreErrors, &output) < 0)
            return -1;
        break;

    case VIR_FIREWALL_BACKEND_AUTOMATIC:
    case VIR_FIREWALL_BACKEND_LAST:
    default:
        virReportEnumRangeError(virFirewallBackend, currentBackend);
        return -1;
    }

    if (rule->queryCB && output) {
        if (!(lines = virStringSplit(output, "\n", -1)))
            return -1;

        VIR_DEBUG("Invoking query %p with '%s'", rule->queryCB, output);
        if (rule->queryCB(firewall, rule->layer, (const char *const *)lines, rule->queryOpaque) < 0)
            return -1;

        if (firewall->err == ENOMEM) {
            virReportOOMError();
            return -1;
        }
        if (firewall->err) {
            virReportSystemError(firewall->err, "%s",
                                 _("Unable to create rule"));
            return -1;
        }

    }

    return 0;
}

static int
virFirewallApplyGroup(virFirewallPtr firewall,
                      size_t idx)
{
    virFirewallGroupPtr group = firewall->groups[idx];
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
virFirewallRollbackGroup(virFirewallPtr firewall,
                         size_t idx)
{
    virFirewallGroupPtr group = firewall->groups[idx];
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
virFirewallApply(virFirewallPtr firewall)
{
    size_t i, j;
    int ret = -1;

    virMutexLock(&ruleLock);

    if (currentBackend == VIR_FIREWALL_BACKEND_AUTOMATIC) {
        /* a specific backend should have been set when the firewall
         * object was created. If not, it means none was found.
         */
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Failed to initialize a valid firewall backend"));
        goto cleanup;
    }
    if (!firewall || firewall->err == ENOMEM) {
        virReportOOMError();
        goto cleanup;
    }
    if (firewall->err) {
        virReportSystemError(firewall->err, "%s",
                             _("Unable to create rule"));
        goto cleanup;
    }

    VIR_DEBUG("Applying groups for %p", firewall);
    for (i = 0; i < firewall->ngroups; i++) {
        if (virFirewallApplyGroup(firewall, i) < 0) {
            VIR_DEBUG("Rolling back groups up to %zu for %p", i, firewall);
            size_t first = i;
            VIR_AUTOPTR(virError) saved_error = virSaveLastError();

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

            virSetError(saved_error);
            VIR_DEBUG("Done rolling back groups for %p", firewall);
            goto cleanup;
        }
    }
    VIR_DEBUG("Done applying groups for %p", firewall);

    ret = 0;
 cleanup:
    virMutexUnlock(&ruleLock);
    return ret;
}
