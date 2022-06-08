/*
 * virkmod.c: helper APIs for managing kernel modules
 *
 * Copyright (C) 2014 Red Hat, Inc.
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
#include "viralloc.h"
#include "virkmod.h"
#include "vircommand.h"

static int
doModprobe(const char *opts, const char *module, char **outbuf, char **errbuf)
{
    g_autoptr(virCommand) cmd = NULL;

    cmd = virCommandNewArgList(MODPROBE, opts, NULL);
    if (module)
        virCommandAddArg(cmd, module);
    if (outbuf)
        virCommandSetOutputBuffer(cmd, outbuf);
    if (errbuf)
        virCommandSetErrorBuffer(cmd, errbuf);

    if (virCommandRun(cmd, NULL) < 0)
        return -1;

    return 0;
}

static int
doRmmod(const char *module, char **errbuf)
{
    g_autoptr(virCommand) cmd = NULL;

    cmd = virCommandNewArgList(RMMOD, module, NULL);
    virCommandSetErrorBuffer(cmd, errbuf);

    if (virCommandRun(cmd, NULL) < 0)
        return -1;

    return 0;
}


/**
 * virKModLoad:
 * @module: Name of the module to load
 *
 * Attempts to load a kernel module
 *
 * returns NULL in case of success and the error buffer output from the
 * virCommandRun() on failure.  The returned buffer must be VIR_FREE()
 * by the caller
 */
char *
virKModLoad(const char *module)
{
    char *errbuf = NULL;

    if (doModprobe("-b", module, NULL, &errbuf) < 0)
        return errbuf;

    VIR_FREE(errbuf);
    return NULL;
}


/**
 * virKModUnload:
 * @module: Name of the module to unload
 *
 * Remove or unload a module.
 *
 * NB: Do not use 'modprobe -r' here as that code will recursively
 * unload any modules that were dependencies of the one being removed
 * even if things still require them. e.g. it'll see the 'bridge'
 * module has refcount of 0 and remove it, even if there are bridges
 * created on the host
 *
 * returns NULL in case of success and the error buffer output from the
 * virCommandRun() on failure.  The returned buffer must be VIR_FREE()
 * by the caller
 */
char *
virKModUnload(const char *module)
{
    char *errbuf = NULL;

    if (doRmmod(module, &errbuf) < 0)
        return errbuf;

    VIR_FREE(errbuf);
    return NULL;
}


/**
 * virKModIsProhibited:
 * @module: Name of the module to check
 *
 * Determine if loading of @module is prohibited by admin
 * configuration.
 *
 * returns true when found prohibited, false otherwise.
 */
bool
virKModIsProhibited(const char *module)
{
    size_t i;
    g_autofree char *drvmatch = NULL;
    g_autofree char *outbuf = NULL;

    drvmatch = g_strdup_printf("blacklist %s\n", module);

    /* modprobe will convert all '-' into '_', so we need to as well */
    for (i = 0; i < drvmatch[i]; i++)
        if (drvmatch[i] == '-')
            drvmatch[i] = '_';

    if (doModprobe("-c", NULL, &outbuf, NULL) < 0)
        return false;

    if (strstr(outbuf, drvmatch))
        return true;

    return false;
}
