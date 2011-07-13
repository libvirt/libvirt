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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 */


#include <config.h>

#include <unistd.h>

#include "driver.h"
#include "memory.h"
#include "logging.h"
#include "util.h"
#include "configmake.h"

#define DEFAULT_DRIVER_DIR LIBDIR "/libvirt/connection-driver"

#ifdef WITH_DRIVER_MODULES

/* XXX re-implment this for other OS, or use libtools helper lib ? */

# include <dlfcn.h>

void *
virDriverLoadModule(const char *name)
{
    const char *moddir = getenv("LIBVIRT_DRIVER_DIR");
    char *modfile = NULL, *regfunc = NULL;
    void *handle = NULL;
    int (*regsym)(void);

    if (moddir == NULL)
        moddir = DEFAULT_DRIVER_DIR;

    VIR_DEBUG("Module load %s", name);

    if (virAsprintf(&modfile, "%s/libvirt_driver_%s.so", moddir, name) < 0)
        return NULL;

    if (access(modfile, R_OK) < 0) {
        VIR_WARN("Module %s not accessible", modfile);
        goto cleanup;
    }

    handle = dlopen(modfile, RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        VIR_ERROR(_("failed to load module %s %s"), modfile, dlerror());
        goto cleanup;
    }

    if (virAsprintf(&regfunc, "%sRegister", name) < 0) {
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
