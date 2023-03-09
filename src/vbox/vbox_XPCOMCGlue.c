/** @file vbox_XPCOMCGlue.c
 * Glue code for dynamically linking to VBoxXPCOMC.
 */

/*
 * Copyright (C) 2008-2009 Sun Microsystems, Inc.
 *
 * This file is part of a free software library; you can redistribute
 * it and/or modify it under the terms of the GNU Lesser General
 * Public License version 2.1 as published by the Free Software
 * Foundation and shipped in the "COPYING.LESSER" file with this library.
 * The library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY of any kind.
 *
 * Sun LGPL Disclaimer: For the avoidance of doubt, except that if
 * any license choice other than GPL or LGPL is available it will
 * apply instead, Sun elects to use only the Lesser General Public
 * License version 2.1 (LGPLv2) at this time for any software where
 * a choice of LGPL license versions is made available with the
 * language indicating that LGPLv2 or any later version may be used,
 * or where a choice of which version of the LGPL is applied is
 * otherwise unspecified.
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa
 * Clara, CA 95054 USA or visit http://www.sun.com if you need
 * additional information or have any questions.
 */


#include <config.h>

#include <dlfcn.h>

#include "vbox_XPCOMCGlue.h"
#include "internal.h"
#include "viralloc.h"
#include "virlog.h"
#include "virfile.h"

#define VIR_FROM_THIS VIR_FROM_VBOX

VIR_LOG_INIT("vbox.vbox_XPCOMCGlue");

#if defined(__linux__) || defined(__linux_gnu__) || defined(__sun__) || \
    defined(__FreeBSD__) || defined(__OpenBSD__) || \
    defined(__FreeBSD_kernel__)
# define DYNLIB_NAME "VBoxXPCOMC.so"
#elif defined(__APPLE__)
# define DYNLIB_NAME "VBoxXPCOMC.dylib"
#elif defined(_MSC_VER) || defined(__OS2__)
# define DYNLIB_NAME "VBoxXPCOMC.dll"
#else
# error "Port me"
#endif


/** The dlopen handle for VBoxXPCOMC. */
static void *hVBoxXPCOMC;
/** Pointer to the VBoxXPCOMC function table. */
static PCVBOXXPCOM pVBoxFuncs_v2_2;
/** Pointer to VBoxGetXPCOMCFunctions for the loaded VBoxXPCOMC so/dylib/dll. */
PFNVBOXGETXPCOMCFUNCTIONS g_pfnGetFunctions = NULL;


/**
 * Try load VBoxXPCOMC.so/dylib/dll from the specified location and resolve all
 * the symbols we need.
 *
 * @returns 0 on success, -1 on failure and 1 if VBoxXPCOMC was not found.
 * @param   dir           The directory where to try load VBoxXPCOMC from. Can
 *                        be NULL.
 * @param   setAppHome    Whether to set the VBOX_APP_HOME env.var. or not.
 * @param   ignoreMissing Whether to ignore missing library or not.
 * @param   version       Version number of the loaded API.
 */
static int
tryLoadOne(const char *dir, bool setAppHome, bool ignoreMissing,
           unsigned int *version)
{
    int result = -1;
    char *name = NULL;
    PFNVBOXGETXPCOMCFUNCTIONS pfnGetFunctions;

    if (dir != NULL) {
        name = g_strdup_printf("%s/%s", dir, DYNLIB_NAME);

        if (!virFileExists(name)) {
            if (!ignoreMissing)
                VIR_ERROR(_("Library '%1$s' doesn't exist"), name);

            VIR_FREE(name);
            return -1;
        }
    } else {
        name = g_strdup(DYNLIB_NAME);
    }

    /*
     * Try load it by that name, setting the VBOX_APP_HOME first (for now).
     * Then resolve and call the function table getter.
     */
    if (setAppHome) {
        if (dir != NULL) {
            g_setenv("VBOX_APP_HOME", dir, TRUE);
        } else {
            g_unsetenv("VBOX_APP_HOME");
        }
    }

    hVBoxXPCOMC = dlopen(name, RTLD_NOW | RTLD_LOCAL);

    if (hVBoxXPCOMC == NULL) {
        /*
         * FIXME: Don't warn in this case as it currently breaks ninja test
         *        on systems without VirtualBox.
         */
        if (dir != NULL)
            VIR_WARN("Could not dlopen '%s': %s", name, dlerror());

        goto cleanup;
    }

    pfnGetFunctions = (PFNVBOXGETXPCOMCFUNCTIONS)
        dlsym(hVBoxXPCOMC, VBOX_GET_XPCOMC_FUNCTIONS_SYMBOL_NAME);

    if (pfnGetFunctions == NULL) {
        VIR_ERROR(_("Could not dlsym %1$s from '%2$s': %3$s"),
                  VBOX_GET_XPCOMC_FUNCTIONS_SYMBOL_NAME, name, dlerror());
        goto cleanup;
    }

    pVBoxFuncs_v2_2 = pfnGetFunctions(VBOX_XPCOMC_VERSION);

    if (pVBoxFuncs_v2_2 == NULL) {
        VIR_ERROR(_("Calling %1$s from '%2$s' failed"),
                  VBOX_GET_XPCOMC_FUNCTIONS_SYMBOL_NAME, name);
        goto cleanup;
    }

    *version = pVBoxFuncs_v2_2->pfnGetVersion();
    g_pfnGetFunctions = pfnGetFunctions;
    result = 0;

    if (dir != NULL) {
        VIR_DEBUG("Found %s in '%s'", DYNLIB_NAME, dir);
    } else {
        VIR_DEBUG("Found %s in dynamic linker search path", DYNLIB_NAME);
    }

 cleanup:
    if (hVBoxXPCOMC != NULL && result < 0) {
        g_clear_pointer(&hVBoxXPCOMC, dlclose);
    }

    VIR_FREE(name);

    return result;
}


/**
 * Tries to locate and load VBoxXPCOMC.so/dylib/dll, resolving all the related
 * function pointers.
 *
 * @returns 0 on success, -1 on failure.
 */
int
VBoxCGlueInit(unsigned int *version)
{
    size_t i;
    static const char *knownDirs[] = {
        "/usr/lib/virtualbox",
        "/usr/lib/virtualbox-ose",
        "/usr/lib64/virtualbox",
        "/usr/lib64/virtualbox-ose",
        "/usr/lib/VirtualBox",
        "/opt/virtualbox",
        "/opt/VirtualBox",
        "/opt/virtualbox/i386",
        "/opt/VirtualBox/i386",
        "/opt/virtualbox/amd64",
        "/opt/VirtualBox/amd64",
        "/usr/local/lib/virtualbox",
        "/usr/local/lib/VirtualBox",
        "/Applications/VirtualBox.app/Contents/MacOS"
    };
    const char *home = getenv("VBOX_APP_HOME");

    /* If the user specifies the location, try only that. */
    if (home != NULL) {
        if (tryLoadOne(home, false, false, version) < 0)
            return -1;
    }

    /* Try the additionally configured location. */
    if (VBOX_XPCOMC_DIR[0] != '\0') {
        if (tryLoadOne(VBOX_XPCOMC_DIR, true, true, version) >= 0)
            return 0;
    }

    /* Try the known locations. */
    for (i = 0; i < G_N_ELEMENTS(knownDirs); ++i) {
        if (tryLoadOne(knownDirs[i], true, true, version) >= 0)
            return 0;
    }

    /* Finally try the dynamic linker search path. */
    if (tryLoadOne(NULL, false, true, version) >= 0)
        return 0;

    /* No luck, return failure. */
    return -1;
}


/*
 * In XPCOM an array is represented by 1) a pointer to an array of pointers
 * that point to the items and 2) an unsigned int representing the number of
 * items in the array. When the items aren't needed anymore they are released
 * or freed according to their type.
 */

typedef nsresult (*ArrayGetter)(void *self, PRUint32 *count, void ***items);
typedef nsresult (*ArrayGetterWithPtrArg)(void *self, void *arg, PRUint32 *count, void ***items);
typedef nsresult (*ArrayGetterWithUintArg)(void *self, PRUint32 arg, PRUint32 *count, void ***items);

static nsresult
vboxArrayGetHelper(vboxArray *array, nsresult nsrc, void **items, PRUint32 count)
{
    array->items = NULL;
    array->count = 0;

    if (NS_FAILED(nsrc))
        return nsrc;

    array->items = items;
    array->count = count;

    return nsrc;
}

/*
 * Call the getter with self as first argument and fill the array with the
 * returned items.
 */
nsresult
vboxArrayGet(vboxArray *array, void *self, void *getter)
{
    nsresult nsrc;
    void **items = NULL;
    PRUint32 count = 0;

    nsrc = ((ArrayGetter)getter)(self, &count, &items);

    return vboxArrayGetHelper(array, nsrc, items, count);
}

/*
 * Call the getter with self as first argument and arg as second argument
 * and fill the array with the returned items.
 */
nsresult
vboxArrayGetWithPtrArg(vboxArray *array, void *self, void *getter, void *arg)
{
    nsresult nsrc;
    void **items = NULL;
    PRUint32 count = 0;

    nsrc = ((ArrayGetterWithPtrArg)getter)(self, arg, &count, &items);

    return vboxArrayGetHelper(array, nsrc, items, count);
}

/*
 * Call the getter with self as first argument and arg as second argument
 * and fill the array with the returned items.
 */
nsresult
vboxArrayGetWithUintArg(vboxArray *array, void *self, void *getter, PRUint32 arg)
{
    nsresult nsrc;
    void **items = NULL;
    PRUint32 count = 0;

    nsrc = ((ArrayGetterWithUintArg)getter)(self, arg, &count, &items);

    return vboxArrayGetHelper(array, nsrc, items, count);
}

/*
 * Release all items in the array and reset it.
 */
void
vboxArrayRelease(vboxArray *array)
{
    size_t i;
    nsISupports *supports;

    if (array->items == NULL)
        return;

    for (i = 0; i < array->count; ++i) {
        supports = array->items[i];

        if (supports != NULL)
            supports->vtbl->Release(supports);
    }

    pVBoxFuncs_v2_2->pfnComUnallocMem(array->items);

    array->items = NULL;
    array->count = 0;
}

/*
 * Unalloc all items in the array and reset it.
 */
void
vboxArrayUnalloc(vboxArray *array)
{
    size_t i;
    void *item;

    if (array->items == NULL)
        return;

    for (i = 0; i < array->count; ++i) {
        item = array->items[i];

        if (item != NULL)
            pVBoxFuncs_v2_2->pfnComUnallocMem(item);
    }

    pVBoxFuncs_v2_2->pfnComUnallocMem(array->items);

    array->items = NULL;
    array->count = 0;
}
