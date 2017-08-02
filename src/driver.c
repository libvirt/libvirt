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
#include "virfile.h"
#include "virlog.h"
#include "configmake.h"

VIR_LOG_INIT("driver");


/* XXX re-implement this for other OS, or use libtools helper lib ? */
#define DEFAULT_DRIVER_DIR LIBDIR "/libvirt/connection-driver"

#ifdef HAVE_DLFCN_H
# include <dlfcn.h>


static void *
virDriverLoadModuleFile(const char *file)
{
    void *handle = NULL;

    VIR_DEBUG("Load module file '%s'", file);

    if (access(file, R_OK) < 0) {
        VIR_INFO("Module %s not accessible", file);
        return NULL;
    }

    virUpdateSelfLastChanged(file);

    if (!(handle = dlopen(file, RTLD_NOW | RTLD_GLOBAL)))
        VIR_ERROR(_("failed to load module %s %s"), file, dlerror());

    return handle;
}


static void *
virDriverLoadModuleFunc(void *handle,
                        const char *funcname)
{
    void *regsym;

    VIR_DEBUG("Lookup function '%s'", funcname);

    if (!(regsym = dlsym(handle, funcname)))
        VIR_ERROR(_("Missing module registration symbol %s"), funcname);

    return regsym;
}


/**
 * virDriverLoadModuleFull:
 * @path: filename of module to load
 * @regfunc: name of the function that registers the module
 * @handle: Returns handle of the loaded library if not NULL
 *
 * Loads a loadable module named @path and calls the
 * registration function @regfunc. If @handle is not NULL the handle is returned
 * in the variable. Otherwise the handle is leaked so that the module stays
 * loaded forever.
 *
 * The module is automatically looked up in the appropriate place (git or
 * installed directory).
 *
 * Returns 0 on success, 1 if the module was not found and -1 on any error.
 */
int
virDriverLoadModuleFull(const char *path,
                        const char *regfunc,
                        void **handle)
{
    void *rethandle = NULL;
    int (*regsym)(void);
    int ret = -1;

    if (!(rethandle = virDriverLoadModuleFile(path))) {
        ret = 1;
        goto cleanup;
    }

    if (!(regsym = virDriverLoadModuleFunc(rethandle, regfunc)))
        goto cleanup;

    if ((*regsym)() < 0) {
        VIR_ERROR(_("Failed module registration %s"), regfunc);
        goto cleanup;
    }

    if (handle)
        VIR_STEAL_PTR(*handle, rethandle);
    else
        rethandle = NULL;

    ret = 0;

 cleanup:
    if (rethandle)
        dlclose(rethandle);
    return ret;
}

#else /* ! HAVE_DLFCN_H */
int
virDriverLoadModuleFull(const char *path ATTRIBUTE_UNUSED,
                        const char *regfunc ATTRIBUTE_UNUSED,
                        void **handle)
{
    VIR_DEBUG("dlopen not available on this platform");
    if (handle)
        *handle = NULL;
    return -1;
}
#endif /* ! HAVE_DLFCN_H */


int
virDriverLoadModule(const char *name,
                    const char *regfunc)
{
    char *modfile = NULL;
    int ret;

    VIR_DEBUG("Module load %s", name);

    if (!(modfile = virFileFindResourceFull(name,
                                            "libvirt_driver_",
                                            ".so",
                                            abs_topbuilddir "/src/.libs",
                                            DEFAULT_DRIVER_DIR,
                                            "LIBVIRT_DRIVER_DIR")))
        return 1;

    ret = virDriverLoadModuleFull(modfile, regfunc, NULL);

    VIR_FREE(modfile);

    return ret;
}


/* XXX unload modules, but we can't until we can unregister libvirt drivers */
