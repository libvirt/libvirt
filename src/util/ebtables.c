/*
 * Copyright (C) 2007-2010 Red Hat, Inc.
 * Copyright (C) 2009 IBM Corp.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * based on iptables.c
 * Authors:
 *     Gerhard Stenzel <gerhard.stenzel@de.ibm.com>
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#ifdef HAVE_PATHS_H
# include <paths.h>
#endif

#include "internal.h"
#include "ebtables.h"
#include "command.h"
#include "memory.h"
#include "virterror_internal.h"
#include "logging.h"

struct _ebtablesContext
{
    ebtRules *input_filter;
    ebtRules *forward_filter;
    ebtRules *nat_postrouting;
};

enum {
    ADD = 0,
    REMOVE,
    CREATE,
    POLICY,
    INSERT
};

static void
ebtRuleFree(ebtRule *rule)
{
    VIR_FREE(rule->rule);

    if (rule->argv) {
        int i = 0;
        while (rule->argv[i])
            VIR_FREE(rule->argv[i++]);
        VIR_FREE(rule->argv);
    }
}

static int
ebtRulesAppend(ebtRules *rules,
               char *rule,
               const char **argv,
               int command_idx)
{
    if (VIR_REALLOC_N(rules->rules, rules->nrules+1) < 0) {
        int i = 0;
        while (argv[i])
            VIR_FREE(argv[i++]);
        VIR_FREE(argv);
        return ENOMEM;
    }

    rules->rules[rules->nrules].rule        = rule;
    rules->rules[rules->nrules].argv        = argv;
    rules->rules[rules->nrules].command_idx = command_idx;

    rules->nrules++;

    return 0;
}

static int
ebtRulesRemove(ebtRules *rules,
               char *rule)
{
    int i;

    for (i = 0; i < rules->nrules; i++)
        if (STREQ(rules->rules[i].rule, rule))
            break;

    if (i >= rules->nrules)
        return EINVAL;

    ebtRuleFree(&rules->rules[i]);

    memmove(&rules->rules[i],
            &rules->rules[i+1],
            (rules->nrules - i - 1) * sizeof(ebtRule));

    rules->nrules--;

    return 0;
}

static void
ebtRulesFree(ebtRules *rules)
{
    int i;

    VIR_FREE(rules->table);
    VIR_FREE(rules->chain);

    if (rules->rules) {
        for (i = 0; i < rules->nrules; i++)
            ebtRuleFree(&rules->rules[i]);

        VIR_FREE(rules->rules);

        rules->nrules = 0;
    }

    VIR_FREE(rules);
}

static ebtRules *
ebtRulesNew(const char *table,
            const char *chain)
{
    ebtRules *rules;

    if (VIR_ALLOC(rules) < 0)
        return NULL;

    if (!(rules->table = strdup(table)))
        goto error;

    if (!(rules->chain = strdup(chain)))
        goto error;

    rules->rules = NULL;
    rules->nrules = 0;

    return rules;

 error:
    ebtRulesFree(rules);
    return NULL;
}

static int ATTRIBUTE_SENTINEL
ebtablesAddRemoveRule(ebtRules *rules, int action, const char *arg, ...)
{
    va_list args;
    int retval = ENOMEM;
    const char **argv;
    char *rule = NULL;
    const char *s;
    int n, command_idx;

    n = 1 + /* /sbin/ebtables  */
        2 + /*   --table foo   */
        2 + /*   --insert bar  */
        1;  /*   arg           */

    va_start(args, arg);
    while (va_arg(args, const char *))
        n++;

    va_end(args);

    if (VIR_ALLOC_N(argv, n + 1) < 0)
        goto error;

    n = 0;

    if (!(argv[n++] = strdup(EBTABLES_PATH)))
        goto error;

    command_idx = n;

    if(action == ADD || action == REMOVE) {
        if (!(argv[n++] = strdup("--insert")))
            goto error;

        if (!(argv[n++] = strdup(rules->chain)))
            goto error;
    }

    if (!(argv[n++] = strdup(arg)))
        goto error;

    va_start(args, arg);

    while ((s = va_arg(args, const char *))) {
        if (!(argv[n++] = strdup(s))) {
            va_end(args);
            goto error;
        }
    }

    va_end(args);

    if (!(rule = virArgvToString(&argv[command_idx])))
        goto error;

    if (action == REMOVE) {
        VIR_FREE(argv[command_idx]);
        if (!(argv[command_idx] = strdup("--delete")))
            goto error;
    }

    if (virRun(argv, NULL) < 0) {
        retval = errno;
        goto error;
    }

    if (action == ADD || action == CREATE || action == POLICY ||
        action == INSERT) {
        retval = ebtRulesAppend(rules, rule, argv, command_idx);
        rule = NULL;
        argv = NULL;
    } else {
        retval = ebtRulesRemove(rules, rule);
    }

 error:
    VIR_FREE(rule);

    if (argv) {
        n = 0;
        while (argv[n])
            VIR_FREE(argv[n++]);
        VIR_FREE(argv);
    }

    return retval;
}


/**
 * ebtablesContextNew:
 *
 * Create a new ebtable context
 *
 * Returns a pointer to the new structure or NULL in case of error
 */
ebtablesContext *
ebtablesContextNew(const char *driver)
{
    bool success = false;
    ebtablesContext *ctx = NULL;
    char *input_chain = NULL;
    char *forward_chain = NULL;
    char *nat_chain = NULL;

    if (VIR_ALLOC(ctx) < 0)
        return NULL;

    if (virAsprintf(&input_chain, "libvirt_%s_INPUT", driver) < 0 ||
        virAsprintf(&forward_chain, "libvirt_%s_FORWARD", driver) < 0 ||
        virAsprintf(&nat_chain, "libvirt_%s_POSTROUTING", driver) < 0) {
        goto cleanup;
    }

    if (!(ctx->input_filter = ebtRulesNew("filter", input_chain)))
        goto cleanup;

    if (!(ctx->forward_filter = ebtRulesNew("filter", forward_chain)))
        goto cleanup;

    if (!(ctx->nat_postrouting = ebtRulesNew("nat", nat_chain)))
        goto cleanup;

    success = true;

cleanup:
    VIR_FREE(input_chain);
    VIR_FREE(forward_chain);
    VIR_FREE(nat_chain);

    if (!success) {
        ebtablesContextFree(ctx);
        ctx = NULL;
    }

    return ctx;
}

/**
 * ebtablesContextFree:
 * @ctx: pointer to the EB table context
 *
 * Free the resources associated with an EB table context
 */
void
ebtablesContextFree(ebtablesContext *ctx)
{
    if (!ctx)
        return;
    if (ctx->input_filter)
        ebtRulesFree(ctx->input_filter);
    if (ctx->forward_filter)
        ebtRulesFree(ctx->forward_filter);
    if (ctx->nat_postrouting)
        ebtRulesFree(ctx->nat_postrouting);
    VIR_FREE(ctx);
}

int
ebtablesAddForwardPolicyReject(ebtablesContext *ctx)
{
    return ebtablesForwardPolicyReject(ctx, ADD);
}


int
ebtablesRemoveForwardPolicyReject(ebtablesContext *ctx)
{
    return ebtablesForwardPolicyReject(ctx, REMOVE);
}

int
ebtablesForwardPolicyReject(ebtablesContext *ctx,
                            int action)
{
    /* create it, if it does not exist */
    if (action == ADD) {
        ebtablesAddRemoveRule(ctx->forward_filter,
                              CREATE,
                              "--new-chain", ctx->forward_filter->chain, NULL,
                              NULL);
        ebtablesAddRemoveRule(ctx->forward_filter,
                              INSERT,
                              "--insert", "FORWARD", "--jump",
                              ctx->forward_filter->chain, NULL);
    }

    return ebtablesAddRemoveRule(ctx->forward_filter,
                                 POLICY,
                                 "-P", ctx->forward_filter->chain, "DROP",
                                 NULL);
}

/*
 * Allow all traffic destined to the bridge, with a valid network address
 */
static int
ebtablesForwardAllowIn(ebtablesContext *ctx,
                       const char *iface,
                       const char *macaddr,
                       int action)
{
    return ebtablesAddRemoveRule(ctx->forward_filter,
                                     action,
                                     "--in-interface", iface,
                                     "--source", macaddr,
                                     "--jump", "ACCEPT",
                                     NULL);
}

/**
 * ebtablesAddForwardAllowIn:
 * @ctx: pointer to the EB table context
 * @iface: the output interface name
 * @physdev: the physical input device or NULL
 *
 * Add rules to the EB table context to allow the traffic on
 * @physdev device to be forwarded to interface @iface. This allows
 * the inbound traffic on a bridge.
 *
 * Returns 0 in case of success or an error code otherwise
 */
int
ebtablesAddForwardAllowIn(ebtablesContext *ctx,
                          const char *iface,
                          const unsigned char *mac)
{
    char *macaddr;

    if (virAsprintf(&macaddr,
                    "%02x:%02x:%02x:%02x:%02x:%02x",
                    mac[0], mac[1],
                    mac[2], mac[3],
                    mac[4], mac[5]) < 0) {
        return -1;
    }
    return ebtablesForwardAllowIn(ctx, iface, macaddr, ADD);
}

/**
 * ebtablesRemoveForwardAllowIn:
 * @ctx: pointer to the EB table context
 * @iface: the output interface name
 * @physdev: the physical input device or NULL
 *
 * Remove rules from the EB table context hence forbidding the traffic
 * on the @physdev device to be forwarded to interface @iface. This
 * stops the inbound traffic on a bridge.
 *
 * Returns 0 in case of success or an error code otherwise
 */
int
ebtablesRemoveForwardAllowIn(ebtablesContext *ctx,
                             const char *iface,
                             const unsigned char *mac)
{
    char *macaddr;

    if (virAsprintf(&macaddr,
                    "%02x:%02x:%02x:%02x:%02x:%02x",
                    mac[0], mac[1],
                    mac[2], mac[3],
                    mac[4], mac[5]) < 0) {
       return -1;
    }
    return ebtablesForwardAllowIn(ctx, iface, macaddr, REMOVE);
}
