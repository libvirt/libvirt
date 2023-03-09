/*
 * lock_manager.c: Implements the internal lock manager API
 *
 * Copyright (C) 2010-2011 Red Hat, Inc.
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

#include "lock_manager.h"
#include "lock_driver_nop.h"
#include "virerror.h"
#include "virfile.h"
#include "virlog.h"
#include "viralloc.h"
#include "viruuid.h"

#if WITH_DLFCN_H
# include <dlfcn.h>
#endif
#include <unistd.h>

#include "configmake.h"

#define VIR_FROM_THIS VIR_FROM_LOCKING

VIR_LOG_INIT("locking.lock_manager");

#define CHECK_DRIVER(field, errret) \
    if (!driver->field) { \
        virReportError(VIR_ERR_INTERNAL_ERROR, \
                     _("Missing '%1$s' field in lock manager driver"), \
                     #field); \
        return errret; \
    }

#define CHECK_MANAGER(field, errret) \
    if (!lock->driver->field) { \
        virReportError(VIR_ERR_INTERNAL_ERROR, \
                       _("Missing '%1$s' field in lock manager driver"), \
                       #field); \
        return errret; \
    }

struct _virLockManagerPlugin {
    char *name;
    virLockDriver *driver;
    void *handle;
    int refs;
};

static void virLockManagerLogParams(size_t nparams,
                                    virLockManagerParam *params)
{
    size_t i;
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    for (i = 0; i < nparams; i++) {
        switch (params[i].type) {
        case VIR_LOCK_MANAGER_PARAM_TYPE_INT:
            VIR_DEBUG("  key=%s type=int value=%d", params[i].key, params[i].value.iv);
            break;
        case VIR_LOCK_MANAGER_PARAM_TYPE_UINT:
            VIR_DEBUG("  key=%s type=uint value=%u", params[i].key, params[i].value.ui);
            break;
        case VIR_LOCK_MANAGER_PARAM_TYPE_LONG:
            VIR_DEBUG("  key=%s type=long value=%lld", params[i].key, params[i].value.l);
            break;
        case VIR_LOCK_MANAGER_PARAM_TYPE_ULONG:
            VIR_DEBUG("  key=%s type=ulong value=%llu", params[i].key, params[i].value.ul);
            break;
        case VIR_LOCK_MANAGER_PARAM_TYPE_DOUBLE:
            VIR_DEBUG("  key=%s type=double value=%lf", params[i].key, params[i].value.d);
            break;
        case VIR_LOCK_MANAGER_PARAM_TYPE_STRING:
            VIR_DEBUG("  key=%s type=string value=%s", params[i].key, params[i].value.str);
            break;
        case VIR_LOCK_MANAGER_PARAM_TYPE_CSTRING:
            VIR_DEBUG("  key=%s type=cstring value=%s", params[i].key, params[i].value.cstr);
            break;
        case VIR_LOCK_MANAGER_PARAM_TYPE_UUID:
            virUUIDFormat(params[i].value.uuid, uuidstr);
            VIR_DEBUG("  key=%s type=uuid value=%s", params[i].key, uuidstr);
            break;
        }
    }
}


/**
 * virLockManagerPluginNew:
 * @name: the name of the plugin
 * @flag: optional plugin flags
 *
 * Attempt to load the plugin $(libdir)/libvirt/lock-driver/@name.so
 * The plugin driver entry point will be resolved & invoked to obtain
 * the lock manager driver.
 *
 * Even if the loading of the plugin succeeded, this may still
 * return NULL if the plugin impl decided that we (libvirtd)
 * are too old to support a feature it requires
 *
 * Returns a plugin object, or NULL if loading failed.
 */
#if WITH_DLFCN_H
virLockManagerPlugin *virLockManagerPluginNew(const char *name,
                                                const char *driverName,
                                                const char *configDir,
                                                unsigned int flags)
{
    void *handle = NULL;
    virLockDriver *driver;
    virLockManagerPlugin *plugin = NULL;
    char *modfile = NULL;
    char *configFile = NULL;

    VIR_DEBUG("name=%s driverName=%s configDir=%s flags=0x%x",
              name, driverName, configDir, flags);

    configFile = g_strdup_printf("%s/%s-%s.conf", configDir, driverName, name);

    if (STREQ(name, "nop")) {
        driver = &virLockDriverNop;
    } else {
        if (!(modfile = virFileFindResourceFull(name,
                                                NULL,
                                                VIR_FILE_MODULE_EXT,
                                                abs_top_builddir "/src",
                                                LIBDIR "/libvirt/lock-driver",
                                                "LIBVIRT_LOCK_MANAGER_PLUGIN_DIR")))
            goto cleanup;

        VIR_DEBUG("Module load %s from %s", name, modfile);

        if (access(modfile, R_OK) < 0) {
            virReportSystemError(errno,
                                 _("Plugin %1$s not accessible"),
                                 modfile);
            goto cleanup;
        }

        handle = dlopen(modfile, RTLD_NOW | RTLD_LOCAL);
        if (!handle) {
            virReportError(VIR_ERR_SYSTEM_ERROR,
                           _("Failed to load plugin %1$s: %2$s"),
                           modfile, dlerror());
            goto cleanup;
        }

        if (!(driver = dlsym(handle, "virLockDriverImpl"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Missing plugin initialization symbol 'virLockDriverImpl'"));
            goto cleanup;
        }
    }

    if (driver->drvInit(VIR_LOCK_MANAGER_VERSION, configFile, flags) < 0)
        goto cleanup;

    plugin = g_new0(virLockManagerPlugin, 1);

    plugin->driver = driver;
    plugin->handle = handle;
    plugin->refs = 1;
    plugin->name = g_strdup(name);

    VIR_FREE(configFile);
    VIR_FREE(modfile);
    return plugin;

 cleanup:
    VIR_FREE(configFile);
    VIR_FREE(plugin);
    VIR_FREE(modfile);
    if (handle)
        dlclose(handle);
    return NULL;
}
#else /* !WITH_DLFCN_H */
virLockManagerPlugin *
virLockManagerPluginNew(const char *name G_GNUC_UNUSED,
                        const char *driverName G_GNUC_UNUSED,
                        const char *configDir G_GNUC_UNUSED,
                        unsigned int flags_unused G_GNUC_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("this platform is missing dlopen"));
    return NULL;
}
#endif /* !WITH_DLFCN_H */


/**
 * virLockManagerPluginRef:
 * @plugin: the plugin implementation to ref
 *
 * Acquires an additional reference on the plugin.
 */
void virLockManagerPluginRef(virLockManagerPlugin *plugin)
{
    plugin->refs++;
}


/**
 * virLockManagerPluginUnref:
 * @plugin: the plugin implementation to unref
 *
 * Releases a reference on the plugin. When the last reference
 * is released, it will attempt to unload the plugin from memory.
 * The plugin may refuse to allow unloading if this would
 * result in an unsafe scenario.
 *
 */
#if WITH_DLFCN_H
void virLockManagerPluginUnref(virLockManagerPlugin *plugin)
{
    if (!plugin)
        return;

    plugin->refs--;

    if (plugin->refs > 0)
        return;

    if (plugin->driver->drvDeinit() >= 0) {
        if (plugin->handle)
            dlclose(plugin->handle);
    } else {
        VIR_WARN("Unable to unload lock maanger plugin from memory");
        return;
    }

    g_free(plugin->name);
    g_free(plugin);
}
#else /* !WITH_DLFCN_H */
void virLockManagerPluginUnref(virLockManagerPlugin *plugin G_GNUC_UNUSED)
{
}
#endif /* !WITH_DLFCN_H */


const char *virLockManagerPluginGetName(virLockManagerPlugin *plugin)
{
    VIR_DEBUG("plugin=%p", plugin);

    return plugin->name;
}


bool virLockManagerPluginUsesState(virLockManagerPlugin *plugin)
{
    VIR_DEBUG("plugin=%p", plugin);

    return plugin->driver->flags & VIR_LOCK_MANAGER_USES_STATE;
}


virLockDriver *virLockManagerPluginGetDriver(virLockManagerPlugin *plugin)
{
    VIR_DEBUG("plugin=%p", plugin);

    return plugin->driver;
}

/**
 * virLockManagerNew:
 * @driver: the lock manager implementation to use
 * @type: the type of process to be supervised
 * @flags: bitwise-OR of virLockManagerNewFlags
 *
 * Create a new context to supervise a process, usually
 * a virtual machine.
 *
 * Returns a new lock manager context
 */
virLockManager *virLockManagerNew(virLockDriver *driver,
                                    unsigned int type,
                                    size_t nparams,
                                    virLockManagerParam *params,
                                    unsigned int flags)
{
    virLockManager *lock;
    VIR_DEBUG("driver=%p type=%u nparams=%zu params=%p flags=0x%x",
              driver, type, nparams, params, flags);
    virLockManagerLogParams(nparams, params);

    CHECK_DRIVER(drvNew, NULL);

    lock = g_new0(virLockManager, 1);

    lock->driver = driver;

    if (driver->drvNew(lock, type, nparams, params, flags) < 0) {
        VIR_FREE(lock);
        return NULL;
    }

    return lock;
}


int virLockManagerAddResource(virLockManager *lock,
                              unsigned int type,
                              const char *name,
                              size_t nparams,
                              virLockManagerParam *params,
                              unsigned int flags)
{
    VIR_DEBUG("lock=%p type=%u name=%s nparams=%zu params=%p flags=0x%x",
              lock, type, name, nparams, params, flags);
    virLockManagerLogParams(nparams, params);

    CHECK_MANAGER(drvAddResource, -1);

    return lock->driver->drvAddResource(lock,
                                        type, name,
                                        nparams, params,
                                        flags);
}

int virLockManagerAcquire(virLockManager *lock,
                          const char *state,
                          unsigned int flags,
                          virDomainLockFailureAction action,
                          int *fd)
{
    VIR_DEBUG("lock=%p state='%s' flags=0x%x action=%d fd=%p",
              lock, NULLSTR(state), flags, action, fd);

    CHECK_MANAGER(drvAcquire, -1);

    if (fd)
        *fd = -1;

    return lock->driver->drvAcquire(lock, state, flags, action, fd);
}


int virLockManagerRelease(virLockManager *lock,
                          char **state,
                          unsigned int flags)
{
    VIR_DEBUG("lock=%p state=%p flags=0x%x", lock, state, flags);

    CHECK_MANAGER(drvRelease, -1);

    return lock->driver->drvRelease(lock, state, flags);
}


int virLockManagerInquire(virLockManager *lock,
                          char **state,
                          unsigned int flags)
{
    VIR_DEBUG("lock=%p state=%p flags=0x%x", lock, state, flags);

    CHECK_MANAGER(drvInquire, -1);

    return lock->driver->drvInquire(lock, state, flags);
}


int virLockManagerFree(virLockManager *lock)
{
    VIR_DEBUG("lock=%p", lock);

    if (!lock)
        return 0;

    CHECK_MANAGER(drvFree, -1);

    lock->driver->drvFree(lock);

    g_free(lock);

    return 0;
}
