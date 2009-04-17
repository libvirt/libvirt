/** @file vbox_XPCOMCGlue.h
 * Glue for dynamically linking with VBoxXPCOMC.
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

#ifndef ___VBoxXPCOMC_cglue_h
#define ___VBoxXPCOMC_cglue_h

#include "vbox_CAPI_v2_2.h"

#ifdef __cplusplus
extern "C" {
#endif

/** The dlopen handle for VBoxXPCOMC. */
extern void *g_hVBoxXPCOMC;
/** The last load error. */
extern char g_szVBoxErrMsg[256];
/** Pointer to the VBoxXPCOMC function table.  */
extern PCVBOXXPCOM g_pVBoxFuncs;
/** Pointer to VBoxGetXPCOMCFunctions for the loaded VBoxXPCOMC so/dylib/dll. */
extern PFNVBOXGETXPCOMCFUNCTIONS g_pfnGetFunctions;


int VBoxCGlueInit(void);
void VBoxCGlueTerm(void);


#ifdef __cplusplus
}
#endif

#endif

