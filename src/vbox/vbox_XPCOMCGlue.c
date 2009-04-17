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
#ifdef LIBVIRT_VERSION
# include <config.h>
#endif /* LIBVIRT_VERSION */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dlfcn.h>

#include "vbox_XPCOMCGlue.h"


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
/** The last load error. */
PCVBOXXPCOM g_pVBoxFuncs = NULL;
/** Pointer to VBoxGetXPCOMCFunctions for the loaded VBoxXPCOMC so/dylib/dll. */
PFNVBOXGETXPCOMCFUNCTIONS g_pfnGetFunctions = NULL;


/**
 * Try load VBoxXPCOMC.so/dylib/dll from the specified location and resolve all
 * the symbols we need.
 *
 * @returns 0 on success, -1 on failure.
 * @param   pszHome         The director where to try load VBoxXPCOMC from. Can be NULL.
 * @param   fSetAppHome     Whether to set the VBOX_APP_HOME env.var. or not (boolean).
 */
static int tryLoadOne(const char *pszHome, int fSetAppHome)
{
    size_t      cchHome = pszHome ? strlen(pszHome) : 0;
    size_t      cbBufNeeded;
    char        szBuf[4096];
    int         rc = -1;

    /*
     * Construct the full name.
     */
    cbBufNeeded = cchHome + sizeof("/" DYNLIB_NAME);
    if (cbBufNeeded > sizeof(szBuf))
    {
        return -1;
    }
    if (cchHome)
    {
        memcpy(szBuf, pszHome, cchHome);
        szBuf[cchHome] = '/';
        cchHome++;
    }
    memcpy(&szBuf[cchHome], DYNLIB_NAME, sizeof(DYNLIB_NAME));

    /*
     * Try load it by that name, setting the VBOX_APP_HOME first (for now).
     * Then resolve and call the function table getter.
     */
    if (fSetAppHome)
    {
        if (pszHome)
            setenv("VBOX_APP_HOME", pszHome, 1 /* always override */);
        else
            unsetenv("VBOX_APP_HOME");
    }
    g_hVBoxXPCOMC = dlopen(szBuf, RTLD_NOW | RTLD_LOCAL);
    if (g_hVBoxXPCOMC)
    {
        PFNVBOXGETXPCOMCFUNCTIONS pfnGetFunctions;
        pfnGetFunctions = (PFNVBOXGETXPCOMCFUNCTIONS)
            dlsym(g_hVBoxXPCOMC, VBOX_GET_XPCOMC_FUNCTIONS_SYMBOL_NAME);
        if (pfnGetFunctions)
        {
            g_pVBoxFuncs = pfnGetFunctions(VBOX_XPCOMC_VERSION);
            if (g_pVBoxFuncs)
            {
                g_pfnGetFunctions = pfnGetFunctions;
                rc = 0;
            }
        }
        if (rc != 0)
        {
            dlclose(g_hVBoxXPCOMC);
            g_hVBoxXPCOMC = NULL;
        }
    }
    return rc;
}


/**
 * Tries to locate and load VBoxXPCOMC.so/dylib/dll, resolving all the related
 * function pointers.
 *
 * @returns 0 on success, -1 on failure.
 *
 * @remark  This should be considered moved into a separate glue library since
 *          its its going to be pretty much the same for any user of VBoxXPCOMC
 *          and it will just cause trouble to have duplicate versions of this
 *          source code all around the place.
 */
int VBoxCGlueInit(void)
{
    /*
     * If the user specifies the location, try only that.
     */
    const char *pszHome = getenv("VBOX_APP_HOME");
    if (pszHome)
        return tryLoadOne(pszHome, 0);

    /*
     * Try the known standard locations.
     */
#if defined(__gnu__linux__) || defined(__linux__)
    if (tryLoadOne("/opt/VirtualBox", 1) == 0)
        return 0;
    if (tryLoadOne("/usr/lib/virtualbox", 1) == 0)
        return 0;
#elif defined(__sun__)
    if (tryLoadOne("/opt/VirtualBox/amd64", 1) == 0)
        return 0;
    if (tryLoadOne("/opt/VirtualBox/i386", 1) == 0)
        return 0;
#elif defined(__APPLE__)
    if (tryLoadOne("/Application/VirtualBox.app/Contents/MacOS", 1) == 0)
        return 0;
#elif defined(__FreeBSD__)
    if (tryLoadOne("/usr/local/lib/virtualbox", 1) == 0)
        return 0;
#else
# error "port me"
#endif

    /*
     * Finally try the dynamic linker search path.
     */
    if (tryLoadOne(NULL, 1) == 0)
        return 0;

    /* No luck, return failure. */
    return -1;
}


/**
 * Terminate the C glue library.
 */
void VBoxCGlueTerm(void)
{
    if (g_hVBoxXPCOMC)
    {
#if 0 /* VBoxRT.so doesn't like being reloaded. See @bugref{3725}. */
        dlclose(g_hVBoxXPCOMC);
#endif
        g_hVBoxXPCOMC = NULL;
    }
    g_pVBoxFuncs = NULL;
    g_pfnGetFunctions = NULL;
}

