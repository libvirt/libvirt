/*
 * Copyright (C) 2007 Red Hat, Inc.
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
 * Authors:
 *     Mark McLoughlin <markmc@redhat.com>
 */

#include "config.h"

#if WITH_QEMU

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

#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#ifdef HAVE_PATHS_H
#include <paths.h>
#endif

#include "internal.h"
#include "iptables.h"

#define qemudLog(level, msg...) fprintf(stderr, msg)

enum {
    ADD = 0,
    REMOVE
};

enum {
    WITH_ERRORS = 0,
    NO_ERRORS
};

typedef struct
{
    char  *rule;
    char **argv;
    int    flipflop;
} iptRule;

typedef struct
{
    char  *table;
    char  *chain;

    int      nrules;
    iptRule *rules;

#ifdef IPTABLES_DIR

    char   dir[PATH_MAX];
    char   path[PATH_MAX];

#endif /* IPTABLES_DIR */

} iptRules;

struct _iptablesContext
{
    iptRules *input_filter;
    iptRules *forward_filter;
    iptRules *nat_postrouting;
};

#ifdef IPTABLES_DIR
static int
writeRules(const char *path,
           const iptRules *rules,
           int nrules)
{
    char tmp[PATH_MAX];
    FILE *f;
    int istmp;
    int i;

    if (nrules == 0 && unlink(path) == 0)
        return 0;

    if (snprintf(tmp, PATH_MAX, "%s.new", path) >= PATH_MAX)
        return EINVAL;

    istmp = 1;

    if (!(f = fopen(tmp, "w"))) {
        istmp = 0;
        if (!(f = fopen(path, "w")))
            return errno;
    }

    for (i = 0; i < nrules; i++) {
        if (fputs(rules[i].rule, f) == EOF ||
            fputc('\n', f) == EOF) {
            fclose(f);
            if (istmp)
                unlink(tmp);
            return errno;
        }
    }

    fclose(f);

    if (istmp && rename(tmp, path) < 0) {
        unlink(tmp);
        return errno;
    }

    if (istmp)
        unlink(tmp);

    return 0;
}

static int
ensureDir(const char *path)
{
    struct stat st;
    char parent[PATH_MAX];
    char *p;
    int err;

    if (stat(path, &st) >= 0)
        return 0;

    strncpy(parent, path, PATH_MAX);
    parent[PATH_MAX - 1] = '\0';

    if (!(p = strrchr(parent, '/')))
        return EINVAL;

    if (p == parent)
        return EPERM;

    *p = '\0';

    if ((err = ensureDir(parent)))
        return err;

    if (mkdir(path, 0700) < 0 && errno != EEXIST)
        return errno;

    return 0;
}

static int
buildDir(const char *table,
         char *path,
         int maxlen)
{
    if (snprintf(path, maxlen, IPTABLES_DIR "/%s", table) >= maxlen)
        return EINVAL;
    else
        return 0;
}

static int
buildPath(const char *table,
          const char *chain,
          char *path,
          int maxlen)
{
    if (snprintf(path, maxlen, IPTABLES_DIR "/%s/%s.chain", table, chain) >= maxlen)
        return EINVAL;
    else
        return 0;
}
#endif /* IPTABLES_DIR */

static void
iptRuleFree(iptRule *rule)
{
    if (rule->rule)
        free(rule->rule);
    rule->rule = NULL;

    if (rule->argv) {
        int i = 0;
        while (rule->argv[i])
            free(rule->argv[i++]);
        free(rule->argv);
        rule->argv = NULL;
    }
}

static int
iptRulesAppend(iptRules *rules,
               char *rule,
               char **argv,
               int flipflop)
{
    iptRule *r;

    if (!(r = realloc(rules->rules, sizeof(*r) * (rules->nrules+1)))) {
        int i = 0;
        while (argv[i])
            free(argv[i++]);
        free(argv);
        return ENOMEM;
    }

    rules->rules = r;

    rules->rules[rules->nrules].rule     = rule;
    rules->rules[rules->nrules].argv     = argv;
    rules->rules[rules->nrules].flipflop = flipflop;

    rules->nrules++;

#ifdef IPTABLES_DIR
    {
        int err;

        if ((err = ensureDir(rules->dir)))
            return err;

        if ((err = writeRules(rules->path, rules->rules, rules->nrules)))
            return err;
    }
#endif /* IPTABLES_DIR */

    return 0;
}

static int
iptRulesRemove(iptRules *rules,
               char *rule)
{
    int i;

    for (i = 0; i < rules->nrules; i++)
        if (!strcmp(rules->rules[i].rule, rule))
            break;

    if (i >= rules->nrules)
        return EINVAL;

    iptRuleFree(&rules->rules[i]);

    memmove(&rules->rules[i],
            &rules->rules[i+1],
            (rules->nrules - i - 1) * sizeof (iptRule));

    rules->nrules--;

#ifdef IPTABLES_DIR
    {
        int err;

        if ((err = writeRules(rules->path, rules->rules, rules->nrules)))
            return err;
    }
#endif /* IPTABLES_DIR */

    return 0;
}

static void
iptRulesFree(iptRules *rules)
{
    int i;

    if (rules->table) {
        free(rules->table);
        rules->table = NULL;
    }

    if (rules->chain) {
        free(rules->chain);
        rules->chain = NULL;
    }


    if (rules->rules) {
        for (i = 0; i < rules->nrules; i++)
            iptRuleFree(&rules->rules[i]);

        free(rules->rules);
        rules->rules = NULL;

        rules->nrules = 0;
    }

#ifdef IPTABLES_DIR
    rules->dir[0] = '\0';
    rules->path[0] = '\0';
#endif /* IPTABLES_DIR */

    free(rules);
}

static iptRules *
iptRulesNew(const char *table,
            const char *chain)
{
    iptRules *rules;

    if (!(rules = calloc(1, sizeof (*rules))))
        return NULL;

    if (!(rules->table = strdup(table)))
        goto error;

    if (!(rules->chain = strdup(chain)))
        goto error;

    rules->rules = NULL;
    rules->nrules = 0;

#ifdef IPTABLES_DIR
    if (buildDir(table, rules->dir, sizeof(rules->dir)))
        goto error;

    if (buildPath(table, chain, rules->path, sizeof(rules->path)))
        goto error;
#endif /* IPTABLES_DIR */

    return rules;

 error:
    iptRulesFree(rules);
    return NULL;
}

static int
iptablesSpawn(int errors, char * const *argv)
{
    pid_t pid, ret;
    int status;
    int null = -1;

    if (errors == NO_ERRORS && (null = open(_PATH_DEVNULL, O_RDONLY)) < 0)
        return errno;

    pid = fork();
    if (pid == -1) {
        if (errors == NO_ERRORS)
            close(null);
        return errno;
    }

    if (pid == 0) { /* child */
        if (errors == NO_ERRORS) {
            dup2(null, STDIN_FILENO);
            dup2(null, STDOUT_FILENO);
            dup2(null, STDERR_FILENO);
            close(null);
        }

        execvp(argv[0], argv);

        _exit (1);
    }

    if (errors == NO_ERRORS)
        close(null);

    while ((ret = waitpid(pid, &status, 0) == -1) && errno == EINTR);
    if (ret == -1)
        return errno;

    if (errors == NO_ERRORS)
        return 0;
    else
        return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : EINVAL;
}

static int
iptablesAddRemoveChain(iptRules *rules, int action)
{
    char **argv;
    int retval = ENOMEM;
    int n;

    n = 1 + /* /sbin/iptables    */
        2 + /*   --table foo     */
        2;  /*   --new-chain bar */

    if (!(argv = calloc(n + 1, sizeof(*argv))))
        goto error;

    n = 0;

    if (!(argv[n++] = strdup(IPTABLES_PATH)))
        goto error;

    if (!(argv[n++] = strdup("--table")))
        goto error;

    if (!(argv[n++] = strdup(rules->table)))
        goto error;

    if (!(argv[n++] = strdup(action == ADD ? "--new-chain" : "--delete-chain")))
        goto error;

    if (!(argv[n++] = strdup(rules->chain)))
        goto error;

    retval = iptablesSpawn(NO_ERRORS, argv);

 error:
    if (argv) {
        n = 0;
        while (argv[n])
            free(argv[n++]);
        free(argv);
    }

    return retval;
}

static int
iptablesAddRemoveRule(iptRules *rules, int action, const char *arg, ...)
{
    va_list args;
    int retval = ENOMEM;
    char **argv;
    char *rule = NULL, *p;
    const char *s;
    int n, rulelen, flipflop;

    n = 1 + /* /sbin/iptables  */
        2 + /*   --table foo   */
        2 + /*   --insert bar  */
        1;  /*   arg           */

    rulelen = strlen(arg) + 1;

    va_start(args, arg);
    while ((s = va_arg(args, const char *))) {
        n++;
        rulelen += strlen(s) + 1;
    }

    va_end(args);

    if (!(argv = calloc(n + 1, sizeof(*argv))))
        goto error;

    if (!(rule = (char *)malloc(rulelen)))
        goto error;

    n = 0;

    if (!(argv[n++] = strdup(IPTABLES_PATH)))
        goto error;

    if (!(argv[n++] = strdup("--table")))
        goto error;

    if (!(argv[n++] = strdup(rules->table)))
        goto error;

    flipflop = n;

    if (!(argv[n++] = strdup(action == ADD ? "--insert" : "--delete")))
        goto error;

    if (!(argv[n++] = strdup(rules->chain)))
        goto error;

    if (!(argv[n++] = strdup(arg)))
        goto error;

    p = strcpy(rule, arg);
    p += strlen(arg);

    va_start(args, arg);

    while ((s = va_arg(args, const char *))) {
        if (!(argv[n++] = strdup(s)))
            goto error;

        *(p++) = ' ';
        strcpy(p, s);
        p += strlen(s);
    }

    va_end(args);

    *p = '\0';

    if (action == ADD &&
        (retval = iptablesAddRemoveChain(rules, action)))
        goto error;

    if ((retval = iptablesSpawn(WITH_ERRORS, argv)))
        goto error;

    if (action == REMOVE &&
        (retval = iptablesAddRemoveChain(rules, action)))
        goto error;

    if (action == ADD) {
        retval = iptRulesAppend(rules, rule, argv, flipflop);
        rule = NULL;
        argv = NULL;
    } else {
        retval = iptRulesRemove(rules, rule);
    }

 error:
    if (rule)
        free(rule);

    if (argv) {
        n = 0;
        while (argv[n])
            free(argv[n++]);
        free(argv);
    }

    return retval;
}

/**
 * iptablesContextNew:
 *
 * Create a new IPtable context
 *
 * Returns a pointer to the new structure or NULL in case of error
 */
iptablesContext *
iptablesContextNew(void)
{
    iptablesContext *ctx;

    if (!(ctx = calloc(1, sizeof (*ctx))))
        return NULL;

    if (!(ctx->input_filter = iptRulesNew("filter", IPTABLES_PREFIX "INPUT")))
        goto error;

    if (!(ctx->forward_filter = iptRulesNew("filter", IPTABLES_PREFIX "FORWARD")))
        goto error;

    if (!(ctx->nat_postrouting = iptRulesNew("nat", IPTABLES_PREFIX "POSTROUTING")))
        goto error;

    return ctx;

 error:
    iptablesContextFree(ctx);
    return NULL;
}

/**
 * iptablesContextFree:
 * @ctx: pointer to the IP table context
 *
 * Free the ressources associated with an IP table context
 */
void
iptablesContextFree(iptablesContext *ctx)
{
    if (ctx->input_filter)
        iptRulesFree(ctx->input_filter);
    if (ctx->forward_filter)
        iptRulesFree(ctx->forward_filter);
    if (ctx->nat_postrouting)
        iptRulesFree(ctx->nat_postrouting);
    free(ctx);
}

static void
iptRulesReload(iptRules *rules)
{
    int i;
    int retval;

    for (i = 0; i < rules->nrules; i++) {
        iptRule *rule = &rules->rules[i];
        char *orig;

        orig = rule->argv[rule->flipflop];
        rule->argv[rule->flipflop] = (char *) "--delete";

        if ((retval = iptablesSpawn(WITH_ERRORS, rule->argv)))
            qemudLog(QEMUD_WARN, "Failed to remove iptables rule '%s' from chain '%s' in table '%s': %s",
                     rule->rule, rules->chain, rules->table, strerror(errno));

        rule->argv[rule->flipflop] = orig;
    }

    if ((retval = iptablesAddRemoveChain(rules, REMOVE)) ||
        (retval = iptablesAddRemoveChain(rules, ADD)))
        qemudLog(QEMUD_WARN, "Failed to re-create chain '%s' in table '%s': %s",
                 rules->chain, rules->table, strerror(retval));

    for (i = 0; i < rules->nrules; i++)
        if ((retval = iptablesSpawn(WITH_ERRORS, rules->rules[i].argv)))
            qemudLog(QEMUD_WARN, "Failed to add iptables rule '%s' to chain '%s' in table '%s': %s",
                     rules->rules[i].rule, rules->chain, rules->table, strerror(retval));
}

/**
 * iptablesReloadRules:
 * @ctx: pointer to the IP table context
 *
 * Reloads all the IP table rules associated to a context
 */
void
iptablesReloadRules(iptablesContext *ctx)
{
    iptRulesReload(ctx->input_filter);
    iptRulesReload(ctx->forward_filter);
    iptRulesReload(ctx->nat_postrouting);
}

static int
iptablesInput(iptablesContext *ctx,
              const char *iface,
              int port,
              int action,
              int tcp)
{
    char portstr[32];

    snprintf(portstr, sizeof(portstr), "%d", port);
    portstr[sizeof(portstr) - 1] = '\0';

    return iptablesAddRemoveRule(ctx->input_filter,
                                 action,
                                 "--in-interface", iface,
                                 "--protocol", tcp ? "tcp" : "udp",
                                 "--destination-port", portstr,
                                 "--jump", "ACCEPT",
                                 NULL);
}

/**
 * iptablesAddTcpInput:
 * @ctx: pointer to the IP table context
 * @iface: the interface name
 * @port: the TCP port to add
 *
 * Add an input to the IP table allowing access to the given @port on
 * the given @iface interface for TCP packets
 *
 * Returns 0 in case of success or an error code in case of error
 */

int
iptablesAddTcpInput(iptablesContext *ctx,
                    const char *iface,
                    int port)
{
    return iptablesInput(ctx, iface, port, ADD, 1);
}

/**
 * iptablesRemoveTcpInput:
 * @ctx: pointer to the IP table context
 * @iface: the interface name
 * @port: the TCP port to remove
 *
 * Removes an input from the IP table, hence forbiding access to the given
 * @port on the given @iface interface for TCP packets
 *
 * Returns 0 in case of success or an error code in case of error
 */
int
iptablesRemoveTcpInput(iptablesContext *ctx,
                       const char *iface,
                       int port)
{
    return iptablesInput(ctx, iface, port, REMOVE, 1);
}

/**
 * iptablesAddUdpInput:
 * @ctx: pointer to the IP table context
 * @iface: the interface name
 * @port: the UDP port to add
 *
 * Add an input to the IP table allowing access to the given @port on
 * the given @iface interface for UDP packets
 *
 * Returns 0 in case of success or an error code in case of error
 */

int
iptablesAddUdpInput(iptablesContext *ctx,
                    const char *iface,
                    int port)
{
    return iptablesInput(ctx, iface, port, ADD, 0);
}

/**
 * iptablesRemoveUdpInput:
 * @ctx: pointer to the IP table context
 * @iface: the interface name
 * @port: the UDP port to remove
 *
 * Removes an input from the IP table, hence forbiding access to the given
 * @port on the given @iface interface for UDP packets
 *
 * Returns 0 in case of success or an error code in case of error
 */
int
iptablesRemoveUdpInput(iptablesContext *ctx,
                       const char *iface,
                       int port)
{
    return iptablesInput(ctx, iface, port, REMOVE, 0);
}


/* Allow all traffic coming from the bridge, with a valid network address
 * to proceed to WAN
 */
static int
iptablesForwardAllowOut(iptablesContext *ctx,
                         const char *network,
                         const char *iface,
                         const char *physdev,
                         int action)
{
    if (physdev && physdev[0]) {
        return iptablesAddRemoveRule(ctx->forward_filter,
                                     action,
                                     "--source", network,
                                     "--in-interface", iface,
                                     "--out-interface", physdev,
                                     "--jump", "ACCEPT",
                                     NULL);
    } else {
        return iptablesAddRemoveRule(ctx->forward_filter,
                                     action,
                                     "--source", network,
                                     "--in-interface", iface,
                                     "--jump", "ACCEPT",
                                     NULL);
    }
}

/**
 * iptablesAddForwardAllowOut:
 * @ctx: pointer to the IP table context
 * @network: the source network name
 * @iface: the source interface name
 * @physdev: the physical output device
 * 
 * Add a rule to the IP table context to allow the traffic for the
 * network @network via interface @iface to be forwarded to
 * @physdev device. This allow the outbound traffic on a bridge.
 *
 * Returns 0 in case of success or an error code otherwise
 */
int
iptablesAddForwardAllowOut(iptablesContext *ctx,
                            const char *network,
                            const char *iface,
                            const char *physdev)
{
    return iptablesForwardAllowOut(ctx, network, iface, physdev, ADD);
}

/**
 * iptablesRemoveForwardAllowOut:
 * @ctx: pointer to the IP table context
 * @network: the source network name
 * @iface: the source interface name
 * @physdev: the physical output device
 * 
 * Remove a rule from the IP table context hence forbidding forwarding
 * of the traffic for the network @network via interface @iface
 * to the @physdev device output. This stops the outbound traffic on a bridge.
 *
 * Returns 0 in case of success or an error code otherwise
 */
int
iptablesRemoveForwardAllowOut(iptablesContext *ctx,
                               const char *network,
                               const char *iface,
                               const char *physdev)
{
    return iptablesForwardAllowOut(ctx, network, iface, physdev, REMOVE);
}


/* Allow all traffic destined to the bridge, with a valid network address
 * and associated with an existing connection
 */
static int
iptablesForwardAllowIn(iptablesContext *ctx,
                       const char *network,
                       const char *iface,
                       const char *physdev,
                       int action)
{
    if (physdev && physdev[0]) {
        return iptablesAddRemoveRule(ctx->forward_filter,
                                     action,
                                     "--destination", network,
                                     "--in-interface", physdev,
                                     "--out-interface", iface,
                                     "--match", "state",
                                     "--state", "ESTABLISHED,RELATED",
                                     "--jump", "ACCEPT",
                                     NULL);
    } else {
        return iptablesAddRemoveRule(ctx->forward_filter,
                                     action,
                                     "--destination", network,
                                     "--out-interface", iface,
                                     "--match", "state",
                                     "--state", "ESTABLISHED,RELATED",
                                     "--jump", "ACCEPT",
                                     NULL);
    }
}

/**
 * iptablesAddForwardAllowIn:
 * @ctx: pointer to the IP table context
 * @network: the source network name
 * @iface: the output interface name
 * @physdev: the physical input device or NULL
 * 
 * Add rules to the IP table context to allow the traffic for the
 * network @network on @physdev device to be forwarded to
 * interface @iface. This allow the inbound traffic on a bridge.
 *
 * Returns 0 in case of success or an error code otherwise
 */
int
iptablesAddForwardAllowIn(iptablesContext *ctx,
                          const char *network,
                          const char *iface,
                          const char *physdev)
{
    return iptablesForwardAllowIn(ctx, network, iface, physdev, ADD);
}

/**
 * iptablesRemoveForwardAllowIn:
 * @ctx: pointer to the IP table context
 * @network: the source network name
 * @iface: the output interface name
 * @physdev: the physical input device or NULL
 * 
 * Remove rules from the IP table context hence forbidding the traffic for
 * network @network on @physdev device to be forwarded to
 * interface @iface. This stops the inbound traffic on a bridge.
 *
 * Returns 0 in case of success or an error code otherwise
 */
int
iptablesRemoveForwardAllowIn(iptablesContext *ctx,
                             const char *network,
                             const char *iface,
                             const char *physdev)
{
    return iptablesForwardAllowIn(ctx, network, iface, physdev, REMOVE);
}


/* Allow all traffic between guests on the same bridge,
 * with a valid network address
 */
static int
iptablesForwardAllowCross(iptablesContext *ctx,
                          const char *iface,
                          int action)
{
    return iptablesAddRemoveRule(ctx->forward_filter,
                                 action,
                                 "--in-interface", iface,
                                 "--out-interface", iface,
                                 "--jump", "ACCEPT",
                                 NULL);
}

/**
 * iptablesAddForwardAllowCross:
 * @ctx: pointer to the IP table context
 * @iface: the input/output interface name
 *
 * Add rules to the IP table context to allow traffic to cross that
 * interface. It allows all traffic between guests on the same bridge
 * represented by that interface.
 *
 * Returns 0 in case of success or an error code otherwise
 */
int
iptablesAddForwardAllowCross(iptablesContext *ctx,
                             const char *iface) {
    return iptablesForwardAllowCross(ctx, iface, ADD);
}

/**
 * iptablesRemoveForwardAllowCross:
 * @ctx: pointer to the IP table context
 * @iface: the input/output interface name
 *
 * Remove rules to the IP table context to block traffic to cross that
 * interface. It forbids traffic between guests on the same bridge
 * represented by that interface.
 *
 * Returns 0 in case of success or an error code otherwise
 */
int
iptablesRemoveForwardAllowCross(iptablesContext *ctx,
                                const char *iface) {
    return iptablesForwardAllowCross(ctx, iface, REMOVE);
}


/* Drop all traffic trying to forward from the bridge.
 * ie the bridge is the in interface
 */
static int
iptablesForwardRejectOut(iptablesContext *ctx,
                         const char *iface,
                         int action)
{
    return iptablesAddRemoveRule(ctx->forward_filter,
                                     action,
                                     "--in-interface", iface,
                                     "--jump", "REJECT",
                                     NULL);
}

/**
 * iptablesAddForwardRejectOut:
 * @ctx: pointer to the IP table context
 * @iface: the output interface name
 *
 * Add rules to the IP table context to forbid all traffic to that
 * interface. It forbids forwarding from the bridge to that interface.
 *
 * Returns 0 in case of success or an error code otherwise
 */
int
iptablesAddForwardRejectOut(iptablesContext *ctx,
                            const char *iface)
{
    return iptablesForwardRejectOut(ctx, iface, ADD);
}

/**
 * iptablesRemoveForwardRejectOut:
 * @ctx: pointer to the IP table context
 * @iface: the output interface name
 *
 * Remove rules from the IP table context forbidding all traffic to that
 * interface. It reallow forwarding from the bridge to that interface.
 *
 * Returns 0 in case of success or an error code otherwise
 */
int
iptablesRemoveForwardRejectOut(iptablesContext *ctx,
                               const char *iface)
{
    return iptablesForwardRejectOut(ctx, iface, REMOVE);
}




/* Drop all traffic trying to forward to the bridge.
 * ie the bridge is the out interface
 */
static int
iptablesForwardRejectIn(iptablesContext *ctx,
                        const char *iface,
                        int action)
{
    return iptablesAddRemoveRule(ctx->forward_filter,
                                 action,
                                 "--out-interface", iface,
                                 "--jump", "REJECT",
                                 NULL);
}

/**
 * iptablesAddForwardRejectIn:
 * @ctx: pointer to the IP table context
 * @iface: the input interface name
 *
 * Add rules to the IP table context to forbid all traffic from that
 * interface. It forbids forwarding from that interface to the bridge.
 *
 * Returns 0 in case of success or an error code otherwise
 */
int
iptablesAddForwardRejectIn(iptablesContext *ctx,
                           const char *iface)
{
    return iptablesForwardRejectIn(ctx, iface, ADD);
}

/**
 * iptablesRemoveForwardRejectIn:
 * @ctx: pointer to the IP table context
 * @iface: the input interface name
 *
 * Remove rules from the IP table context forbidding all traffic from that
 * interface. It allows forwarding from that interface to the bridge.
 *
 * Returns 0 in case of success or an error code otherwise
 */
int
iptablesRemoveForwardRejectIn(iptablesContext *ctx,
                              const char *iface)
{
    return iptablesForwardRejectIn(ctx, iface, REMOVE);
}


/* Masquerade all traffic coming from the network associated
 * with the bridge
 */
static int
iptablesForwardMasquerade(iptablesContext *ctx,
                       const char *network,
                       const char *physdev,
                       int action)
{
    if (physdev && physdev[0]) {
        return iptablesAddRemoveRule(ctx->nat_postrouting,
                                     action,
                                     "--source", network,
                                     "--out-interface", physdev,
                                     "--jump", "MASQUERADE",
                                     NULL);
    } else {
        return iptablesAddRemoveRule(ctx->nat_postrouting,
                                     action,
                                     "--source", network,
                                     "--jump", "MASQUERADE",
                                     NULL);
    }
}

/**
 * iptablesAddForwardMasquerade:
 * @ctx: pointer to the IP table context
 * @network: the source network name
 * @physdev: the physical input device or NULL
 * 
 * Add rules to the IP table context to allow masquerading
 * network @network on @physdev. This allow the bridge to
 * masquerade for that network (on @physdev).
 *
 * Returns 0 in case of success or an error code otherwise
 */
int
iptablesAddForwardMasquerade(iptablesContext *ctx,
                             const char *network,
                             const char *physdev)
{
    return iptablesForwardMasquerade(ctx, network, physdev, ADD);
}

/**
 * iptablesRemoveForwardMasquerade:
 * @ctx: pointer to the IP table context
 * @network: the source network name
 * @physdev: the physical input device or NULL
 * 
 * Remove rules from the IP table context to stop masquerading
 * network @network on @physdev. This stops the bridge from
 * masquerading for that network (on @physdev).
 *
 * Returns 0 in case of success or an error code otherwise
 */
int
iptablesRemoveForwardMasquerade(iptablesContext *ctx,
                                const char *network,
                                const char *physdev)
{
    return iptablesForwardMasquerade(ctx, network, physdev, REMOVE);
}

#endif /* WITH_QEMU */

/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
