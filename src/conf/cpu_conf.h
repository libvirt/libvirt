/*
 * cpu_conf.h: CPU XML handling
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

#ifndef __VIR_CPU_CONF_H__
# define __VIR_CPU_CONF_H__

# include "util.h"
# include "buf.h"
# ifndef PROXY
#  include "xml.h"
# endif

enum virCPUType {
    VIR_CPU_TYPE_HOST,
    VIR_CPU_TYPE_GUEST,
    VIR_CPU_TYPE_AUTO
};

enum virCPUMatch {
    VIR_CPU_MATCH_MINIMUM,
    VIR_CPU_MATCH_EXACT,
    VIR_CPU_MATCH_STRICT,

    VIR_CPU_MATCH_LAST
};

VIR_ENUM_DECL(virCPUMatch)

enum virCPUFeaturePolicy {
    VIR_CPU_FEATURE_FORCE,
    VIR_CPU_FEATURE_REQUIRE,
    VIR_CPU_FEATURE_OPTIONAL,
    VIR_CPU_FEATURE_DISABLE,
    VIR_CPU_FEATURE_FORBID,

    VIR_CPU_FEATURE_LAST
};

VIR_ENUM_DECL(virCPUFeaturePolicy)

typedef struct _virCPUFeatureDef virCPUFeatureDef;
typedef virCPUFeatureDef *virCPUFeatureDefPtr;
struct _virCPUFeatureDef {
    char *name;
    int policy;         /* enum virCPUFeaturePolicy */
};

typedef struct _virCPUDef virCPUDef;
typedef virCPUDef *virCPUDefPtr;
struct _virCPUDef {
    int type;           /* enum virCPUType */
    int match;          /* enum virCPUMatch */
    char *arch;
    char *model;
    char *vendor;
    unsigned int sockets;
    unsigned int cores;
    unsigned int threads;
    unsigned int nfeatures;
    virCPUFeatureDefPtr features;
};


void
virCPUDefFree(virCPUDefPtr def);

virCPUDefPtr
virCPUDefCopy(const virCPUDefPtr cpu);

# ifndef PROXY
virCPUDefPtr
virCPUDefParseXML(const xmlNodePtr node,
                  xmlXPathContextPtr ctxt,
                  enum virCPUType mode);
# endif

enum virCPUFormatFlags {
    VIR_CPU_FORMAT_EMBEDED  = (1 << 0)  /* embed into existing <cpu/> element
                                         * in host capabilities */
};


char *
virCPUDefFormat(virCPUDefPtr def,
                const char *indent,
                int flags);

int
virCPUDefFormatBuf(virBufferPtr buf,
                   virCPUDefPtr def,
                   const char *indent,
                   int flags);

int
virCPUDefAddFeature(virCPUDefPtr cpu,
                    const char *name,
                    int policy);

#endif /* __VIR_CPU_CONF_H__ */
