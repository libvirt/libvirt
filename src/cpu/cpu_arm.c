/*
 * cpu_arm.c: CPU driver for arm CPUs
 *
 * Copyright (C) 2013 Red Hat, Inc.
 * Copyright (C) Canonical Ltd. 2012
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
 */

#include <config.h>

#include "viralloc.h"
#include "cpu.h"
#include "cpu_map.h"
#include "virstring.h"
#include "virxml.h"

#define VIR_FROM_THIS VIR_FROM_CPU

static const virArch archs[] = {
    VIR_ARCH_ARMV6L,
    VIR_ARCH_ARMV7B,
    VIR_ARCH_ARMV7L,
    VIR_ARCH_AARCH64,
};

typedef struct _virCPUarmFeature virCPUarmFeature;
typedef virCPUarmFeature *virCPUarmFeaturePtr;
struct _virCPUarmFeature {
    char *name;
};

static virCPUarmFeaturePtr
virCPUarmFeatureNew(void)
{
    return g_new0(virCPUarmFeature, 1);
}

static void
virCPUarmFeatureFree(virCPUarmFeaturePtr feature)
{
    if (!feature)
        return;

    g_free(feature->name);

    g_free(feature);
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virCPUarmFeature, virCPUarmFeatureFree);

typedef struct _virCPUarmMap virCPUarmMap;
typedef virCPUarmMap *virCPUarmMapPtr;
struct _virCPUarmMap {
    GPtrArray *features;
};

static virCPUarmMapPtr
virCPUarmMapNew(void)
{
    virCPUarmMapPtr map;

    map = g_new0(virCPUarmMap, 1);

    map->features = g_ptr_array_new();
    g_ptr_array_set_free_func(map->features,
                              (GDestroyNotify) virCPUarmFeatureFree);

    return map;
}

static void
virCPUarmMapFree(virCPUarmMapPtr map)
{
    if (!map)
        return;

    g_ptr_array_free(map->features, TRUE);

    g_free(map);
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virCPUarmMap, virCPUarmMapFree);

static virCPUarmFeaturePtr
virCPUarmMapFeatureFind(virCPUarmMapPtr map,
                        const char *name)
{
    size_t i;

    for (i = 0; i < map->features->len; i++) {
        virCPUarmFeaturePtr feature = g_ptr_array_index(map->features, i);

        if (STREQ(feature->name, name))
            return feature;
    }

    return NULL;
}

static int
virCPUarmMapFeatureParse(xmlXPathContextPtr ctxt G_GNUC_UNUSED,
                         const char *name,
                         void *data)
{
    g_autoptr(virCPUarmFeature) feature = NULL;
    virCPUarmMapPtr map = data;

    if (virCPUarmMapFeatureFind(map, name)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("CPU feature %s already defined"), name);
        return -1;
    }

    feature = virCPUarmFeatureNew();
    feature->name = g_strdup(name);

    g_ptr_array_add(map->features, g_steal_pointer(&feature));

    return 0;
}

static virCPUarmMapPtr
virCPUarmLoadMap(void)
{
    g_autoptr(virCPUarmMap) map = NULL;

    map = virCPUarmMapNew();

    if (cpuMapLoad("arm", NULL, virCPUarmMapFeatureParse, NULL, map) < 0)
        return NULL;

    return g_steal_pointer(&map);
}

static virCPUarmMapPtr cpuMap;

int virCPUarmDriverOnceInit(void);
VIR_ONCE_GLOBAL_INIT(virCPUarmDriver);

int
virCPUarmDriverOnceInit(void)
{
    if (!(cpuMap = virCPUarmLoadMap()))
        return -1;

    return 0;
}

static virCPUarmMapPtr
virCPUarmGetMap(void)
{
    if (virCPUarmDriverInitialize() < 0)
        return NULL;

    return cpuMap;
}

static int
virCPUarmUpdate(virCPUDefPtr guest,
                const virCPUDef *host)
{
    int ret = -1;
    virCPUDefPtr updated = NULL;

    if (guest->mode != VIR_CPU_MODE_HOST_MODEL)
        return 0;

    if (!host) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("unknown host CPU model"));
        goto cleanup;
    }

    if (!(updated = virCPUDefCopyWithoutModel(guest)))
        goto cleanup;

    updated->mode = VIR_CPU_MODE_CUSTOM;
    if (virCPUDefCopyModel(updated, host, true) < 0)
        goto cleanup;

    virCPUDefStealModel(guest, updated, false);
    guest->mode = VIR_CPU_MODE_CUSTOM;
    guest->match = VIR_CPU_MATCH_EXACT;
    ret = 0;

 cleanup:
    virCPUDefFree(updated);
    return ret;
}


static virCPUDefPtr
virCPUarmBaseline(virCPUDefPtr *cpus,
                  unsigned int ncpus G_GNUC_UNUSED,
                  virDomainCapsCPUModelsPtr models G_GNUC_UNUSED,
                  const char **features G_GNUC_UNUSED,
                  bool migratable G_GNUC_UNUSED)
{
    virCPUDefPtr cpu = NULL;

    cpu = virCPUDefNew();

    cpu->model = g_strdup(cpus[0]->model);

    cpu->type = VIR_CPU_TYPE_GUEST;
    cpu->match = VIR_CPU_MATCH_EXACT;

    return cpu;
}

static virCPUCompareResult
virCPUarmCompare(virCPUDefPtr host G_GNUC_UNUSED,
                 virCPUDefPtr cpu G_GNUC_UNUSED,
                 bool failMessages G_GNUC_UNUSED)
{
    return VIR_CPU_COMPARE_IDENTICAL;
}

static int
virCPUarmValidateFeatures(virCPUDefPtr cpu)
{
    virCPUarmMapPtr map;
    size_t i;

    if (!(map = virCPUarmGetMap()))
        return -1;

    for (i = 0; i < cpu->nfeatures; i++) {
        virCPUFeatureDefPtr feature = &cpu->features[i];

        if (!virCPUarmMapFeatureFind(map, feature->name)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown CPU feature: %s"),
                           feature->name);
            return -1;
        }
    }

    return 0;
}

struct cpuArchDriver cpuDriverArm = {
    .name = "arm",
    .arch = archs,
    .narch = G_N_ELEMENTS(archs),
    .compare = virCPUarmCompare,
    .decode = NULL,
    .encode = NULL,
    .baseline = virCPUarmBaseline,
    .update = virCPUarmUpdate,
    .validateFeatures = virCPUarmValidateFeatures,
};
