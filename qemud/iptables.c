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

#include <config.h>

#include "iptables.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <paths.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

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
    char  *table;
    char  *chain;

#ifdef IPTABLES_DIR

    char   dir[PATH_MAX];
    char   path[PATH_MAX];

    int    nrules;
    char **rules;

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
           char * const *rules,
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
        if (fputs(rules[i], f) == EOF ||
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

static int
iptRulesAppend(iptRules *rules,
               const char *rule)
{
    char **r;
    int err;

    if (!(r = (char **)realloc(rules->rules, sizeof(char *) * (rules->nrules+1))))
        return ENOMEM;

    rules->rules = r;

    if (!(rules->rules[rules->nrules] = strdup(rule)))
        return ENOMEM;

    rules->nrules++;

    if ((err = ensureDir(rules->dir)))
        return err;

    if ((err = writeRules(rules->path, rules->rules, rules->nrules)))
        return err;

    return 0;
}

static int
iptRulesRemove(iptRules *rules,
               const char *rule)
{
    int i;
    int err;

    for (i = 0; i < rules->nrules; i++)
        if (!strcmp(rules->rules[i], rule))
            break;

    if (i >= rules->nrules)
        return EINVAL;

    free(rules->rules[i]);

    memmove(&rules->rules[i],
            &rules->rules[i+1],
            (rules->nrules - i - 1) * sizeof (char *));

    rules->nrules--;

    if ((err = writeRules(rules->path, rules->rules, rules->nrules)))
        return err;

    return 0;
}
#endif /* IPTABLES_DIR */

static void
iptRulesFree(iptRules *rules)
{
    if (rules->table) {
        free(rules->table);
        rules->table = NULL;
    }

    if (rules->chain) {
        free(rules->chain);
        rules->chain = NULL;
    }

#ifdef IPTABLES_DIR
    {
        int i;

        rules->dir[0] = '\0';
        rules->path[0] = '\0';

        for (i = 0; i < rules->nrules; i++) {
            free(rules->rules[i]);
            rules->rules[i] = NULL;
        }

        rules->nrules = 0;

        if (rules->rules) {
            free(rules->rules);
            rules->rules = NULL;
        }
    }
#endif /* IPTABLES_DIR */

    free(rules);
}

static iptRules *
iptRulesNew(const char *table,
            const char *chain)
{
    iptRules *rules;

    if (!(rules = (iptRules *)malloc(sizeof (iptRules))))
        return NULL;

    memset (rules, 0, sizeof (iptRules));

    if (!(rules->table = strdup(table)))
        goto error;

    if (!(rules->chain = strdup(chain)))
        goto error;

#ifdef IPTABLES_DIR
    if (buildDir(table, rules->dir, sizeof(rules->dir)))
        goto error;

    if (buildPath(table, chain, rules->path, sizeof(rules->path)))
        goto error;

    rules->rules = NULL;
    rules->nrules = 0;
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

    if (!(argv = (char **)malloc(sizeof(char *) * (n+1))))
        goto error;

    memset(argv, 0, sizeof(char *) * (n + 1));

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
    int n, rulelen;

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

    if (!(argv = (char **)malloc(sizeof(char *) * (n + 1))))
        goto error;

    if (!(rule = (char *)malloc(rulelen)))
        goto error;

    memset(argv, 0, sizeof(char *) * (n + 1));

    n = 0;

    if (!(argv[n++] = strdup(IPTABLES_PATH)))
        goto error;

    if (!(argv[n++] = strdup("--table")))
        goto error;

    if (!(argv[n++] = strdup(rules->table)))
        goto error;

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

#ifdef IPTABLES_DIR
    if (action == ADD)
        retval = iptRulesAppend(rules, rule);
    else
        retval = iptRulesRemove(rules, rule);
#endif /* IPTABLES_DIR */

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

iptablesContext *
iptablesContextNew(void)
{
    iptablesContext *ctx;

    if (!(ctx = (iptablesContext *) malloc(sizeof (iptablesContext))))
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

void
iptablesContextFree(iptablesContext *ctx)
{
    iptRulesFree(ctx->input_filter);
    iptRulesFree(ctx->forward_filter);
    iptRulesFree(ctx->nat_postrouting);
    free(ctx);
}

static int
iptablesInput(iptablesContext *ctx,
              const char *iface,
              int port,
              int action,
              int tcp)
{
    char portstr[32];
    int ret;

    snprintf(portstr, sizeof(portstr), "%d", port);
    portstr[sizeof(portstr) - 1] = '\0';

    ret = iptablesAddRemoveRule(ctx->input_filter,
                                action,
                                "--in-interface", iface,
                                "--protocol", tcp ? "tcp" : "udp",
                                "--destination-port", portstr,
                                "--jump", "ACCEPT",
                                NULL);

    return ret;
}

int
iptablesAddTcpInput(iptablesContext *ctx,
                    const char *iface,
                    int port)
{
    return iptablesInput(ctx, iface, port, ADD, 1);
}

int
iptablesRemoveTcpInput(iptablesContext *ctx,
                       const char *iface,
                       int port)
{
    return iptablesInput(ctx, iface, port, REMOVE, 1);
}

int
iptablesAddUdpInput(iptablesContext *ctx,
                    const char *iface,
                    int port)
{
    return iptablesInput(ctx, iface, port, ADD, 0);
}

int
iptablesRemoveUdpInput(iptablesContext *ctx,
                       const char *iface,
                       int port)
{
    return iptablesInput(ctx, iface, port, REMOVE, 0);
}

static int
iptablesPhysdevForward(iptablesContext *ctx,
                       const char *iface,
                       int action)
{
    return iptablesAddRemoveRule(ctx->forward_filter,
                                 action,
                                 "--match", "physdev",
                                 "--physdev-in", iface,
                                 "--jump", "ACCEPT",
                                 NULL);
}

int
iptablesAddPhysdevForward(iptablesContext *ctx,
                          const char *iface)
{
    return iptablesPhysdevForward(ctx, iface, ADD);
}

int
iptablesRemovePhysdevForward(iptablesContext *ctx,
                             const char *iface)
{
    return iptablesPhysdevForward(ctx, iface, REMOVE);
}

static int
iptablesInterfaceForward(iptablesContext *ctx,
                         const char *iface,
                         int action)
{
    return iptablesAddRemoveRule(ctx->forward_filter,
                                 action,
                                 "--in-interface", iface,
                                 "--jump", "ACCEPT",
                                 NULL);
}

int
iptablesAddInterfaceForward(iptablesContext *ctx,
                            const char *iface)
{
    return iptablesInterfaceForward(ctx, iface, ADD);
}

int
iptablesRemoveInterfaceForward(iptablesContext *ctx,
                               const char *iface)
{
    return iptablesInterfaceForward(ctx, iface, REMOVE);
}

static int
iptablesStateForward(iptablesContext *ctx,
                     const char *iface,
                     int action)
{
    return iptablesAddRemoveRule(ctx->forward_filter,
                                 action,
                                 "--out-interface", iface,
                                 "--match", "state",
                                 "--state", "ESTABLISHED,RELATED",
                                 "--jump", "ACCEPT",
                                 NULL);
}

int
iptablesAddStateForward(iptablesContext *ctx,
                        const char *iface)
{
    return iptablesStateForward(ctx, iface, ADD);
}

int
iptablesRemoveStateForward(iptablesContext *ctx,
                           const char *iface)
{
    return iptablesStateForward(ctx, iface, REMOVE);
}

static int
iptablesNonBridgedMasq(iptablesContext *ctx,
                       int action)
{
    return iptablesAddRemoveRule(ctx->nat_postrouting,
                                 action,
                                 "--match", "physdev",
                                 "!", "--physdev-is-bridged",
                                 "--jump", "MASQUERADE",
                                 NULL);
}

int
iptablesAddNonBridgedMasq(iptablesContext *ctx)
{
    return iptablesNonBridgedMasq(ctx, ADD);
}

int
iptablesRemoveNonBridgedMasq(iptablesContext *ctx)
{
    return iptablesNonBridgedMasq(ctx, REMOVE);
}

/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
