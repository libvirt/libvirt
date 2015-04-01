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
#include <c-ctype.h>

#include "driver.h"
#include "viralloc.h"
#include "virfile.h"
#include "virlog.h"
#include "virutil.h"
#include "configmake.h"
#include "virstring.h"

VIR_LOG_INIT("driver");


#ifdef WITH_DRIVER_MODULES

/* XXX re-implment this for other OS, or use libtools helper lib ? */

# include <dlfcn.h>
# define DEFAULT_DRIVER_DIR LIBDIR "/libvirt/connection-driver"

void *
virDriverLoadModule(const char *name)
{
    char *modfile = NULL, *regfunc = NULL, *fixedname = NULL;
    char *tmp;
    void *handle = NULL;
    int (*regsym)(void);

    VIR_DEBUG("Module load %s", name);

    if (!(modfile = virFileFindResourceFull(name,
                                            "libvirt_driver_",
                                            ".so",
                                            abs_topbuilddir "/src/.libs",
                                            DEFAULT_DRIVER_DIR,
                                            "LIBVIRT_DRIVER_DIR")))
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

    if (VIR_STRDUP_QUIET(fixedname, name) < 0) {
        VIR_ERROR(_("out of memory"));
        goto cleanup;
    }

    /* convert something_like_this into somethingLikeThis */
    while ((tmp = strchr(fixedname, '_'))) {
        memmove(tmp, tmp + 1, strlen(tmp));
        *tmp = c_toupper(*tmp);
    }

    if (virAsprintfQuiet(&regfunc, "%sRegister", fixedname) < 0)
        goto cleanup;

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
    VIR_FREE(fixedname);
    return handle;

 cleanup:
    VIR_FREE(modfile);
    VIR_FREE(regfunc);
    VIR_FREE(fixedname);
    if (handle)
        dlclose(handle);
    return NULL;
}


/* XXX unload modules, but we can't until we can unregister libvirt drivers */

#endif
