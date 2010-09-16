/*
 * cpu_map.h: internal functions for handling CPU mapping configuration
 *
 * Copyright (C) 2009 Red Hat, Inc.
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
 * Authors:
 *      Jiri Denemark <jdenemar@redhat.com>
 */

#ifndef __VIR_CPU_MAP_H__
# define __VIR_CPU_MAP_H__

# include "xml.h"


enum cpuMapElement {
    CPU_MAP_ELEMENT_VENDOR,
    CPU_MAP_ELEMENT_FEATURE,
    CPU_MAP_ELEMENT_MODEL,

    CPU_MAP_ELEMENT_LAST
};

VIR_ENUM_DECL(cpuMapElement)


typedef int
(*cpuMapLoadCallback)  (enum cpuMapElement element,
                        xmlXPathContextPtr ctxt,
                        void *data);

extern int
cpuMapLoad(const char *arch,
           cpuMapLoadCallback cb,
           void *data);

extern int
cpuMapOverride(const char *path);

#endif /* __VIR_CPU_MAP_H__ */
