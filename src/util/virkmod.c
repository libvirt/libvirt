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
#include "virstring.h"

static int
doModprobe(const char *opts, const char *module, char **outbuf, char **errbuf)
{
    int ret = -1;
    virCommandPtr cmd = NULL;

    cmd = virCommandNew(MODPROBE);
    if (opts)
        virCommandAddArg(cmd, opts);
    if (module)
        virCommandAddArg(cmd, module);
    if (outbuf)
        virCommandSetOutputBuffer(cmd, outbuf);
    if (errbuf)
        virCommandSetErrorBuffer(cmd, errbuf);

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virCommandFree(cmd);
    return ret;
}

static int
doRmmod(const char *module, char **errbuf)
{
    int ret = -1;
    virCommandPtr cmd = NULL;

    cmd = virCommandNewArgList(RMMOD, module, NULL);
    virCommandSetErrorBuffer(cmd, errbuf);

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virCommandFree(cmd);
    return ret;
}

/**
 * virKModConfig:
 *
 * Get the current kernel module configuration
 *
 * Returns NULL on failure or a pointer to the output which
 * must be VIR_FREE()'d by the caller
 */
char *
virKModConfig(void)
{
    char *outbuf = NULL;

    if (doModprobe("-c", NULL, &outbuf, NULL) < 0)
        return NULL;

    return outbuf;
}


/**
 * virKModLoad:
 * @module: Name of the module to load
 * @useBlacklist: True if honoring blacklist
 *
 * Attempts to load a kernel module
 *
 * returns NULL in case of success and the error buffer output from the
 * virCommandRun() on failure.  The returned buffer must be VIR_FREE()
 * by the caller
 */
char *
virKModLoad(const char *module, bool useBlacklist)
{
    char *errbuf = NULL;

    if (doModprobe(useBlacklist ? "-b" : NULL, module, NULL, &errbuf) < 0)
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
 * unload any modules that were dependancies of the one being removed
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
 * virKModIsBlacklisted:
 * @module: Name of the module to check for on the blacklist
 *
 * Search the output of the configuration data for the module being
 * blacklisted.
 *
 * returns true when found blacklisted, false otherwise.
 */
bool
virKModIsBlacklisted(const char *module)
{
    bool retval = false;
    size_t i;
    char *drvblklst = NULL;
    char *outbuf = NULL;

    if (virAsprintfQuiet(&drvblklst, "blacklist %s\n", module) < 0)
        goto cleanup;

    /* modprobe will convert all '-' into '_', so we need to as well */
    for (i = 0; i < drvblklst[i]; i++)
        if (drvblklst[i] == '-')
            drvblklst[i] = '_';

    if (doModprobe("-c", NULL, &outbuf, NULL) < 0)
        goto cleanup;

    if (strstr(outbuf, drvblklst))
        retval = true;

 cleanup:
    VIR_FREE(drvblklst);
    VIR_FREE(outbuf);
    return retval;
}
