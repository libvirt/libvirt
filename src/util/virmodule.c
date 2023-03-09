/*
 * virmodule.c: APIs for dlopen'ing extension modules
 *
 * Copyright (C) 2012-2018 Red Hat, Inc.
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
 * License along with this library;  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 */

#include <config.h>

#include "internal.h"
#include "virmodule.h"
#include "virerror.h"
#include "virfile.h"
#include "virlog.h"
#include "virutil.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.module");

#ifdef WITH_DLFCN_H
# include <dlfcn.h>

static void *
virModuleLoadFile(const char *file)
{
    void *handle = NULL;
    int flags = RTLD_NOW | RTLD_GLOBAL;

# ifdef RTLD_NODELETE
    flags |= RTLD_NODELETE;
# endif

    VIR_DEBUG("Load module file '%s'", file);

    virUpdateSelfLastChanged(file);

    if (!(handle = dlopen(file, flags))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to load module '%1$s': %2$s"), file, dlerror());
        return NULL;
    }

    return handle;
}


static void *
virModuleLoadFunc(void *handle,
                  const char *file,
                  const char *funcname)
{
    void *regsym;

    VIR_DEBUG("Lookup function '%s'", funcname);

    if (!(regsym = dlsym(handle, funcname))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to find symbol '%1$s' in module '%2$s': %3$s"),
                       funcname, file, dlerror());
        return NULL;
    }

    return regsym;
}


/**
 * virModuleLoad:
 * @path: filename of module to load
 * @regfunc: name of the function that registers the module
 * @required: true if module must exist on disk, false to silently skip
 *
 * Loads a loadable module named @path and calls the
 * registration function @regfunc. The module will never
 * be unloaded because unloading is not safe in a multi-threaded
 * application.
 *
 * The module is automatically looked up in the appropriate place (git or
 * installed directory).
 *
 * Returns 0 on success, 1 if the module was not found and -1 on any error.
 */
int
virModuleLoad(const char *path,
              const char *regfunc,
              bool required)
{
    void *rethandle = NULL;
    int (*regsym)(void);
    int ret = -1;

    if (!virFileExists(path)) {
        if (required) {
            virReportSystemError(errno,
                                 _("Failed to find module '%1$s'"), path);
            return -1;
        } else {
            VIR_INFO("Module '%s' does not exist", path);
            return 1;
        }
    }

    if (!(rethandle = virModuleLoadFile(path)))
        goto cleanup;

    if (!(regsym = virModuleLoadFunc(rethandle, path, regfunc)))
        goto cleanup;

    if ((*regsym)() < 0) {
        /* regsym() should report an error itself, but lets
         * just make sure */
        if (virGetLastErrorCode() == VIR_ERR_OK) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to execute symbol '%1$s' in module '%2$s'"),
                           regfunc, path);
        }
        goto cleanup;
    }

    rethandle = NULL;
    ret = 0;

 cleanup:
    if (rethandle)
        dlclose(rethandle);
    return ret;
}

#else /* ! WITH_DLFCN_H */
int
virModuleLoad(const char *path,
              const char *regfunc G_GNUC_UNUSED,
              bool required)
{
    VIR_DEBUG("dlopen not available on this platform");
    if (required) {
        virReportSystemError(ENOSYS,
                             _("Failed to find module '%1$s'"), path);
        return -1;
    } else {
        /* Since we have no dlopen(), but definition we have no
         * loadable modules on disk, so we can reasonably
         * return '1' instead of an error.
         */
        return 1;
    }
}
#endif /* ! WITH_DLFCN_H */
