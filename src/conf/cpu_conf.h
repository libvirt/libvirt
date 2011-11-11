/*
 * cpu_conf.h: CPU XML handling
 *
 * Copyright (C) 2009-2011 Red Hat, Inc.
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
# include "xml.h"

enum virCPUType {
    VIR_CPU_TYPE_HOST,
    VIR_CPU_TYPE_GUEST,
    VIR_CPU_TYPE_AUTO,

    VIR_CPU_TYPE_LAST
};

VIR_ENUM_DECL(virCPU)

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

typedef struct _virCellDef virCellDef;
typedef virCellDef *virCellDefPtr;
struct _virCellDef {
   int cellid;
   char *cpumask;	/* CPUs that are part of this node */
   char *cpustr;	/* CPUs stored in string form for dumpxml */
   unsigned int mem;	/* Node memory in kB */
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
    size_t nfeatures;
    size_t nfeatures_max;
    virCPUFeatureDefPtr features;
    size_t ncells;
    size_t ncells_max;
    virCellDefPtr cells;
    unsigned int cells_cpus;
};


void
virCPUDefFree(virCPUDefPtr def);

virCPUDefPtr
virCPUDefCopy(const virCPUDefPtr cpu);

virCPUDefPtr
virCPUDefParseXML(const xmlNodePtr node,
                  xmlXPathContextPtr ctxt,
                  enum virCPUType mode);

bool
virCPUDefIsEqual(virCPUDefPtr src,
                 virCPUDefPtr dst);

char *
virCPUDefFormat(virCPUDefPtr def);

int
virCPUDefFormatBuf(virBufferPtr buf,
                   virCPUDefPtr def);
int
virCPUDefFormatBufFull(virBufferPtr buf,
                       virCPUDefPtr def);

int
virCPUDefAddFeature(virCPUDefPtr cpu,
                    const char *name,
                    int policy);

#endif /* __VIR_CPU_CONF_H__ */
