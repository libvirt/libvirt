/** @file vbox_XPCOMCGlue.c
 * Glue code for dynamically linking to VBoxXPCOMC.
 */

/*
 * Copyright (C) 2008-2009 Sun Microsystems, Inc.
 *
 * This file is part of a free software library; you can redistribute
 * it and/or modify it under the terms of the GNU Lesser General
 * Public License version 2.1 as published by the Free Software
 * Foundation and shipped in the "COPYING" file with this library.
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

/*******************************************************************************
*   Header Files                                                               *
*******************************************************************************/

#include <config.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>

#include "vbox_XPCOMCGlue.h"
#include "internal.h"
#include "memory.h"
#include "util.h"
#include "logging.h"
#include "virterror_internal.h"

#define VIR_FROM_THIS VIR_FROM_VBOX


/*******************************************************************************
*   Defined Constants And Macros                                               *
*******************************************************************************/
#if defined(__linux__) || defined(__linux_gnu__) || defined(__sun__) || defined(__FreeBSD__)
# define DYNLIB_NAME    "VBoxXPCOMC.so"
#elif defined(__APPLE__)
# define DYNLIB_NAME    "VBoxXPCOMC.dylib"
#elif defined(_MSC_VER) || defined(__OS2__)
# define DYNLIB_NAME    "VBoxXPCOMC.dll"
#else
# error "Port me"
#endif


/*******************************************************************************
*   Global Variables                                                           *
*******************************************************************************/
/** The dlopen handle for VBoxXPCOMC. */
void *g_hVBoxXPCOMC = NULL;
/** Pointer to the VBoxXPCOMC function table. */
PCVBOXXPCOM g_pVBoxFuncs = NULL;
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
 */
static int tryLoadOne(const char *dir, bool setAppHome, bool ignoreMissing)
{
    int result = -1;
    char *name = NULL;
    PFNVBOXGETXPCOMCFUNCTIONS pfnGetFunctions;

    if (dir != NULL) {
        if (virAsprintf(&name, "%s/%s", dir, DYNLIB_NAME) < 0) {
            virReportOOMError();
            return -1;
        }

        if (!virFileExists(name)) {
            if (!ignoreMissing) {
                VIR_ERROR(_("Libaray '%s' doesn't exist"), name);
            }

            return -1;
        }
    } else {
        name = strdup(DYNLIB_NAME);

        if (name == NULL) {
            virReportOOMError();
            return -1;
        }
    }

    /*
     * Try load it by that name, setting the VBOX_APP_HOME first (for now).
     * Then resolve and call the function table getter.
     */
    if (setAppHome) {
        if (dir != NULL) {
            setenv("VBOX_APP_HOME", dir, 1 /* always override */);
        } else {
            unsetenv("VBOX_APP_HOME");
        }
    }

    g_hVBoxXPCOMC = dlopen(name, RTLD_NOW | RTLD_LOCAL);

    if (g_hVBoxXPCOMC == NULL) {
        /*
         * FIXME: Don't warn in this case as it currently breaks make check
         *        on systems without VirtualBox.
         */
        if (dir != NULL) {
            VIR_WARN("Could not dlopen '%s': %s", name, dlerror());
        }

        goto cleanup;
    }

    pfnGetFunctions = (PFNVBOXGETXPCOMCFUNCTIONS)
        dlsym(g_hVBoxXPCOMC, VBOX_GET_XPCOMC_FUNCTIONS_SYMBOL_NAME);

    if (pfnGetFunctions == NULL) {
        VIR_ERROR(_("Could not dlsym %s from '%s': %s"),
                  VBOX_GET_XPCOMC_FUNCTIONS_SYMBOL_NAME, name, dlerror());
        goto cleanup;
    }

    g_pVBoxFuncs = pfnGetFunctions(VBOX_XPCOMC_VERSION);

    if (g_pVBoxFuncs == NULL) {
        VIR_ERROR(_("Calling %s from '%s' failed"),
                  VBOX_GET_XPCOMC_FUNCTIONS_SYMBOL_NAME, name);
        goto cleanup;
    }

    g_pfnGetFunctions = pfnGetFunctions;
    result = 0;

    if (dir != NULL) {
        VIR_DEBUG("Found %s in '%s'", DYNLIB_NAME, dir);
    } else {
        VIR_DEBUG("Found %s in dynamic linker search path", DYNLIB_NAME);
    }

cleanup:
    if (g_hVBoxXPCOMC != NULL && result < 0) {
        dlclose(g_hVBoxXPCOMC);
        g_hVBoxXPCOMC = NULL;
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
int VBoxCGlueInit(void)
{
    int i;
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
        if (tryLoadOne(home, false, false) < 0) {
            return -1;
        }
    }

    /* Try the additionally configured location. */
    if (VBOX_XPCOMC_DIR[0] != '\0') {
        if (tryLoadOne(VBOX_XPCOMC_DIR, true, true) >= 0) {
            return 0;
        }
    }

    /* Try the known locations. */
    for (i = 0; i < ARRAY_CARDINALITY(knownDirs); ++i) {
        if (tryLoadOne(knownDirs[i], true, true) >= 0) {
            return 0;
        }
    }

    /* Finally try the dynamic linker search path. */
    if (tryLoadOne(NULL, false, true) >= 0) {
        return 0;
    }

    /* No luck, return failure. */
    return -1;
}


/**
 * Terminate the C glue library.
 */
void VBoxCGlueTerm(void)
{
    if (g_hVBoxXPCOMC != NULL) {
#if 0 /* VBoxRT.so doesn't like being reloaded. See @bugref{3725}. */
        dlclose(g_hVBoxXPCOMC);
#endif
        g_hVBoxXPCOMC = NULL;
    }

    g_pVBoxFuncs = NULL;
    g_pfnGetFunctions = NULL;
}
