/*
 * logging.h: internal logging and debugging
 *
 * Copyright (C) 2006-2008 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 */

#ifndef __VIRTLOG_H_
#define __VIRTLOG_H_

#include "internal.h"

/*
 * If configured with --enable-debug=yes then library calls
 * are printed to stderr for debugging or to an appropriate channel
 * defined at runtime of from the libvirt daemon configuration file
 */
#ifdef ENABLE_DEBUG
extern int debugFlag;
#define VIR_DEBUG(category, fmt,...)                                    \
    do { if (debugFlag) fprintf (stderr, "DEBUG: %s: %s (" fmt ")\n", category, __func__, __VA_ARGS__); } while (0)
#else
#define VIR_DEBUG(category, fmt,...) \
    do { } while (0)
#endif /* !ENABLE_DEBUG */

#define DEBUG(fmt,...) VIR_DEBUG(__FILE__, fmt, __VA_ARGS__)
#define DEBUG0(msg) VIR_DEBUG(__FILE__, "%s", msg)


#endif
