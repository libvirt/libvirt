/** @file vbox_V3_0.c
 * C file to include support for multiple versions of VirtualBox
 * at runtime.
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

/** The API Version */
#define VBOX_API_VERSION    3000000
/** Version specific prefix. */
#define NAME(name)  vbox30##name

#include "vbox_tmpl.c"
