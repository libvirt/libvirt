/*
 * virebtables.c: Helper APIs for managing ebtables
 *
 * Copyright (C) 2007-2014 Red Hat, Inc.
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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
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
#include "virebtables.h"
#include "vircommand.h"
#include "viralloc.h"
#include "virerror.h"
#include "virfile.h"
#include "virlog.h"
#include "virthread.h"
#include "virstring.h"
#include "virutil.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.ebtables");

#if HAVE_FIREWALLD
static char *firewall_cmd_path = NULL;

static int
virEbTablesOnceInit(void)
{
    firewall_cmd_path = virFindFileInPath("firewall-cmd");
    if (!firewall_cmd_path) {
        VIR_INFO("firewall-cmd not found on system. "
                 "firewalld support disabled for ebtables.");
    } else {
        virCommandPtr cmd = virCommandNew(firewall_cmd_path);

        virCommandAddArgList(cmd, "--state", NULL);
        if (virCommandRun(cmd, NULL) < 0) {
            VIR_INFO("firewall-cmd found but disabled for ebtables");
            VIR_FREE(firewall_cmd_path);
            firewall_cmd_path = NULL;
        } else {
            VIR_INFO("using firewalld for ebtables commands");
        }
        virCommandFree(cmd);
    }
    return 0;
}

VIR_ONCE_GLOBAL_INIT(virEbTables)

#endif

struct _ebtablesContext
{
    char *chain;
};

enum {
    ADD = 0,
    REMOVE,
};


static int ATTRIBUTE_SENTINEL
ebtablesAddRemoveRule(const char *arg, ...)
{
    va_list args;
    int retval = ENOMEM;
    char **argv;
    const char *s;
    int n;

    n = 1 + /* /sbin/ebtables  */
        2 + /*   --table foo   */
        2 + /*   --insert bar  */
        1;  /*   arg           */

#if HAVE_FIREWALLD
    virEbTablesInitialize();
    if (firewall_cmd_path)
        n += 3; /* --direct --passthrough eb */
#endif

    va_start(args, arg);
    while (va_arg(args, const char *))
        n++;

    va_end(args);

    if (VIR_ALLOC_N(argv, n + 1) < 0)
        goto error;

    n = 0;

#if HAVE_FIREWALLD
    if (firewall_cmd_path) {
        if (VIR_STRDUP(argv[n++], firewall_cmd_path) < 0)
            goto error;
        if (VIR_STRDUP(argv[n++], "--direct") < 0)
            goto error;
        if (VIR_STRDUP(argv[n++], "--passthrough") < 0)
            goto error;
        if (VIR_STRDUP(argv[n++], "eb") < 0)
            goto error;
    } else
#endif
    if (VIR_STRDUP(argv[n++], EBTABLES_PATH) < 0)
        goto error;

    if (VIR_STRDUP(argv[n++], arg) < 0)
        goto error;

    va_start(args, arg);

    while ((s = va_arg(args, const char *))) {
        if (VIR_STRDUP(argv[n++], s) < 0) {
            va_end(args);
            goto error;
        }
    }

    va_end(args);

    if (virRun((const char **)argv, NULL) < 0) {
        retval = errno;
        goto error;
    }

 error:
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
    ebtablesContext *ctx = NULL;

    if (VIR_ALLOC(ctx) < 0)
        return NULL;

    if (virAsprintf(&ctx->chain, "libvirt_%s_FORWARD", driver) < 0) {
        VIR_FREE(ctx);
        return NULL;
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
    VIR_FREE(ctx->chain);
    VIR_FREE(ctx);
}


int
ebtablesAddForwardPolicyReject(ebtablesContext *ctx)
{
    ebtablesAddRemoveRule("--new-chain", ctx->chain, NULL,
                          NULL);
    ebtablesAddRemoveRule("--insert", "FORWARD", "--jump",
                          ctx->chain, NULL);
    return ebtablesAddRemoveRule("-P", ctx->chain, "DROP",
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
    return ebtablesAddRemoveRule(action == ADD ? "--insert" : "--delete",
                                 ctx->chain,
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
                          const virMacAddr *mac)
{
    char macaddr[VIR_MAC_STRING_BUFLEN];

    virMacAddrFormat(mac, macaddr);
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
                             const virMacAddr *mac)
{
    char macaddr[VIR_MAC_STRING_BUFLEN];

    virMacAddrFormat(mac, macaddr);
    return ebtablesForwardAllowIn(ctx, iface, macaddr, REMOVE);
}
