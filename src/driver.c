/*
 * driver.c: Helpers for loading drivers
 *
 * Copyright (C) 2006-2011 Red Hat, Inc.
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

#include <unistd.h>

#include "driver.h"
#include "viralloc.h"
#include "virlog.h"
#include "virutil.h"
#include "configmake.h"
#include "virstring.h"

VIR_LOG_INIT("driver");

#define DEFAULT_DRIVER_DIR LIBDIR "/libvirt/connection-driver"

#ifdef WITH_DRIVER_MODULES

/* XXX re-implment this for other OS, or use libtools helper lib ? */

# include <dlfcn.h>

static const char *moddir = NULL;

void
virDriverModuleInitialize(const char *defmoddir)
{
    const char *custommoddir = virGetEnvBlockSUID("LIBVIRT_DRIVER_DIR");
    if (custommoddir)
        moddir = custommoddir;
    else if (defmoddir)
        moddir = defmoddir;
    else
        moddir = DEFAULT_DRIVER_DIR;
    VIR_DEBUG("Module dir %s", moddir);
}

void *
virDriverLoadModule(const char *name)
{
    char *modfile = NULL, *regfunc = NULL;
    void *handle = NULL;
    int (*regsym)(void);

    if (moddir == NULL)
        virDriverModuleInitialize(NULL);

    VIR_DEBUG("Module load %s", name);

    if (virAsprintfQuiet(&modfile, "%s/libvirt_driver_%s.so", moddir, name) < 0)
        return NULL;

    if (access(modfile, R_OK) < 0) {
        VIR_WARN("Module %s not accessible", modfile);
        goto cleanup;
    }

    virUpdateSelfLastChanged(modfile);

    handle = dlopen(modfile, RTLD_NOW | RTLD_GLOBAL);
    if (!handle) {
        VIR_ERROR(_("failed to load module %s %s"), modfile, dlerror());
        goto cleanup;
    }

    if (virAsprintfQuiet(&regfunc, "%sRegister", name) < 0) {
        goto cleanup;
    }

    regsym = dlsym(handle, regfunc);
    if (!regsym) {
        VIR_ERROR(_("Missing module registration symbol %s"), regfunc);
        goto cleanup;
    }

    if ((*regsym)() < 0) {
        VIR_ERROR(_("Failed module registration %s"), regfunc);
        goto cleanup;
    }

    VIR_FREE(modfile);
    VIR_FREE(regfunc);
    return handle;

 cleanup:
    VIR_FREE(modfile);
    VIR_FREE(regfunc);
    if (handle)
        dlclose(handle);
    return NULL;
}


/* XXX unload modules, but we can't until we can unregister libvirt drivers */

#endif
