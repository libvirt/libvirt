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
#include "virthread.h"
#include "configmake.h"

VIR_LOG_INIT("driver");

#define VIR_FROM_THIS VIR_FROM_NONE

/* XXX re-implement this for other OS, or use libtools helper lib ? */
#define DEFAULT_DRIVER_DIR LIBDIR "/libvirt/connection-driver"

#ifdef HAVE_DLFCN_H
# include <dlfcn.h>


static void *
virDriverLoadModuleFile(const char *file)
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
                       _("Failed to load module '%s': %s"), file, dlerror());
        return NULL;
    }

    return handle;
}


static void *
virDriverLoadModuleFunc(void *handle,
                        const char *file,
                        const char *funcname)
{
    void *regsym;

    VIR_DEBUG("Lookup function '%s'", funcname);

    if (!(regsym = dlsym(handle, funcname))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to find symbol '%s' in module '%s': %s"),
                       funcname, file, dlerror());
        return NULL;
    }

    return regsym;
}


/**
 * virDriverLoadModuleFull:
 * @path: filename of module to load
 * @regfunc: name of the function that registers the module
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
virDriverLoadModuleFull(const char *path,
                        const char *regfunc,
                        bool required)
{
    void *rethandle = NULL;
    int (*regsym)(void);
    int ret = -1;

    if (!virFileExists(path)) {
        if (required) {
            virReportSystemError(errno,
                                 _("Failed to find module '%s'"), path);
            return -1;
        } else {
            VIR_INFO("Module '%s' does not exist", path);
            return 1;
        }
    }

    if (!(rethandle = virDriverLoadModuleFile(path)))
        goto cleanup;

    if (!(regsym = virDriverLoadModuleFunc(rethandle, path, regfunc)))
        goto cleanup;

    if ((*regsym)() < 0) {
        /* regsym() should report an error itself, but lets
         * just make sure */
        virErrorPtr err = virGetLastError();
        if (err == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to execute symbol '%s' in module '%s'"),
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

#else /* ! HAVE_DLFCN_H */
int
virDriverLoadModuleFull(const char *path ATTRIBUTE_UNUSED,
                        const char *regfunc ATTRIBUTE_UNUSED,
                        bool required)
{
    VIR_DEBUG("dlopen not available on this platform");
    if (required) {
        virReportSystemError(ENOSYS,
                             _("Failed to find module '%s': %s"), path);
        return -1;
    } else {
        /* Since we have no dlopen(), but definition we have no
         * loadable modules on disk, so we can resaonably
         * return '1' instead of an error.
         */
        return 1;
    }
}
#endif /* ! HAVE_DLFCN_H */


int
virDriverLoadModule(const char *name,
                    const char *regfunc,
                    bool required)
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
        return -1;

    ret = virDriverLoadModuleFull(modfile, regfunc, required);

    VIR_FREE(modfile);

    return ret;
}


/* XXX unload modules, but we can't until we can unregister libvirt drivers */

virThreadLocal connectInterface;
virThreadLocal connectNetwork;
virThreadLocal connectNWFilter;
virThreadLocal connectNodeDev;
virThreadLocal connectSecret;
virThreadLocal connectStorage;

static int
virConnectCacheOnceInit(void)
{
    if (virThreadLocalInit(&connectInterface, NULL) < 0)
        return -1;
    if (virThreadLocalInit(&connectNetwork, NULL) < 0)
        return -1;
    if (virThreadLocalInit(&connectNWFilter, NULL) < 0)
        return -1;
    if (virThreadLocalInit(&connectNodeDev, NULL) < 0)
        return -1;
    if (virThreadLocalInit(&connectSecret, NULL) < 0)
        return -1;
    if (virThreadLocalInit(&connectStorage, NULL) < 0)
        return -1;
    return 0;
}

VIR_ONCE_GLOBAL_INIT(virConnectCache);

virConnectPtr virGetConnectInterface(void)
{
    virConnectPtr conn;

    if (virConnectCacheInitialize() < 0)
        return NULL;

    conn = virThreadLocalGet(&connectInterface);
    if (conn) {
        VIR_DEBUG("Return cached interface connection %p", conn);
        virObjectRef(conn);
    } else {
        conn = virConnectOpen(geteuid() == 0 ? "interface:///system" : "interface:///session");
        VIR_DEBUG("Opened new interface connection %p", conn);
    }
    return conn;
}

virConnectPtr virGetConnectNetwork(void)
{
    virConnectPtr conn;

    if (virConnectCacheInitialize() < 0)
        return NULL;

    conn = virThreadLocalGet(&connectNetwork);
    if (conn) {
        VIR_DEBUG("Return cached network connection %p", conn);
        virObjectRef(conn);
    } else {
        conn = virConnectOpen(geteuid() == 0 ? "network:///system" : "network:///session");
        VIR_DEBUG("Opened new network connection %p", conn);
    }
    return conn;
}

virConnectPtr virGetConnectNWFilter(void)
{
    virConnectPtr conn;

    if (virConnectCacheInitialize() < 0)
        return NULL;

    conn = virThreadLocalGet(&connectNWFilter);
    if (conn) {
        VIR_DEBUG("Return cached nwfilter connection %p", conn);
        virObjectRef(conn);
    } else {
        conn = virConnectOpen(geteuid() == 0 ? "nwfilter:///system" : "nwfilter:///session");
        VIR_DEBUG("Opened new nwfilter connection %p", conn);
    }
    return conn;
}

virConnectPtr virGetConnectNodeDev(void)
{
    virConnectPtr conn;

    if (virConnectCacheInitialize() < 0)
        return NULL;

    conn = virThreadLocalGet(&connectNodeDev);
    if (conn) {
        VIR_DEBUG("Return cached nodedev connection %p", conn);
        virObjectRef(conn);
    } else {
        conn = virConnectOpen(geteuid() == 0 ? "nodedev:///system" : "nodedev:///session");
        VIR_DEBUG("Opened new nodedev connection %p", conn);
    }
    return conn;
}

virConnectPtr virGetConnectSecret(void)
{
    virConnectPtr conn;

    if (virConnectCacheInitialize() < 0)
        return NULL;

    conn = virThreadLocalGet(&connectSecret);
    if (conn) {
        VIR_DEBUG("Return cached secret connection %p", conn);
        virObjectRef(conn);
    } else {
        conn = virConnectOpen(geteuid() == 0 ? "secret:///system" : "secret:///session");
        VIR_DEBUG("Opened new secret connection %p", conn);
    }
    return conn;
}

virConnectPtr virGetConnectStorage(void)
{
    virConnectPtr conn;

    if (virConnectCacheInitialize() < 0)
        return NULL;

    conn = virThreadLocalGet(&connectStorage);
    if (conn) {
        VIR_DEBUG("Return cached storage connection %p", conn);
        virObjectRef(conn);
    } else {
        conn = virConnectOpen(geteuid() == 0 ? "storage:///system" : "storage:///session");
        VIR_DEBUG("Opened new storage connection %p", conn);
    }
    return conn;
}


int
virSetConnectInterface(virConnectPtr conn)
{
    if (virConnectCacheInitialize() < 0)
        return -1;

    VIR_DEBUG("Override interface connection with %p", conn);
    return virThreadLocalSet(&connectInterface, conn);
}


int
virSetConnectNetwork(virConnectPtr conn)
{
    if (virConnectCacheInitialize() < 0)
        return -1;

    VIR_DEBUG("Override network connection with %p", conn);
    return virThreadLocalSet(&connectNetwork, conn);
}


int
virSetConnectNWFilter(virConnectPtr conn)
{
    if (virConnectCacheInitialize() < 0)
        return -1;

    VIR_DEBUG("Override nwfilter connection with %p", conn);
    return virThreadLocalSet(&connectNWFilter, conn);
}


int
virSetConnectNodeDev(virConnectPtr conn)
{
    if (virConnectCacheInitialize() < 0)
        return -1;

    VIR_DEBUG("Override nodedev connection with %p", conn);
    return virThreadLocalSet(&connectNodeDev, conn);
}


int
virSetConnectSecret(virConnectPtr conn)
{
    if (virConnectCacheInitialize() < 0)
        return -1;

    VIR_DEBUG("Override secret connection with %p", conn);
    return virThreadLocalSet(&connectSecret, conn);
}


int
virSetConnectStorage(virConnectPtr conn)
{
    if (virConnectCacheInitialize() < 0)
        return -1;

    VIR_DEBUG("Override storage connection with %p", conn);
    return virThreadLocalSet(&connectStorage, conn);
}
