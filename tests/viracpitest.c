/*
 * viracpitest.c: Test ACPI table parsing
 *
 * Copyright (C) 2023 Red Hat, Inc.
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
 *
 */

#include <config.h>

#define LIBVIRT_VIRACPIPRIV_H_ALLOW
#include "testutils.h"
#include "viracpi.h"
#include "viracpipriv.h"

#define VIR_FROM_THIS VIR_FROM_NONE

typedef struct testAarch64SMMUData testAarch64SMMUData;
struct testAarch64SMMUData {
    const char *filename;
    ssize_t nnodes;
    const virIORTNodeType *node_types;
};

static void
printBitmap(virBitmap *types)
{
    size_t i;

    for (i = 0; i < VIR_IORT_NODE_TYPE_LAST; i++) {
        if (virBitmapIsBitSet(types, i)) {
            fprintf(stderr, "%s\n", virIORTNodeTypeTypeToString(i));
        }
    }
}

static int
testAarch64SMMU(const void *opaque)
{
    const testAarch64SMMUData *data = opaque;
    g_autofree char *path = NULL;
    g_autofree virIORTNodeHeader *nodes = NULL;
    ssize_t nnodes = 0;

    path = g_strdup_printf("%s/viracpidata/%s",
                           abs_srcdir, data->filename);

    nnodes = virAcpiParseIORT(&nodes, path);

    if (nnodes != data->nnodes) {
        fprintf(stderr,
                "virAcpiParseIORT() returned wrong number of nodes: %zd, expected %zd\n",
                nnodes, data->nnodes);
        return -1;
    }

    if (nnodes > 0) {
        g_autoptr(virBitmap) typesSeen = virBitmapNew(VIR_IORT_NODE_TYPE_LAST);
        g_autoptr(virBitmap) typesExp = virBitmapNew(VIR_IORT_NODE_TYPE_LAST);
        size_t i = 0;

        for (i = 0; data->node_types[i] != VIR_IORT_NODE_TYPE_LAST; i++) {
            size_t type = data->node_types[i];

            ignore_value(virBitmapSetBit(typesExp, type));
        }

        for (i = 0; i < nnodes; i++) {
            virIORTNodeHeader *h = &nodes[i];

            ignore_value(virBitmapSetBit(typesSeen, h->type));
        }

        if (!virBitmapEqual(typesSeen, typesExp)) {
            fprintf(stderr, "node types mismatch.\n\nExpected:\n");
            printBitmap(typesExp);
            fprintf(stderr, "\nActual:\n");
            printBitmap(typesSeen);
            return -1;
        }
    }

    return 0;
}


static int
mymain(void)
{
    int ret = 0;

#define DO_TEST(filename, nnodes, ...) \
    do { \
        const virIORTNodeType node_types[] = { __VA_ARGS__, VIR_IORT_NODE_TYPE_LAST }; \
        const testAarch64SMMUData data = {filename, nnodes, node_types }; \
        if (virTestRun("aarch64 SMMU " filename, testAarch64SMMU, &data) < 0) \
            ret = -1; \
    } while (0)

    DO_TEST("IORT_empty", 0, VIR_IORT_NODE_TYPE_LAST);
    DO_TEST("IORT_virt_aarch64", 2,
            VIR_IORT_NODE_TYPE_ITS_GROUP,
            VIR_IORT_NODE_TYPE_ROOT_COMPLEX);
    DO_TEST("IORT_ampere", 36,
            VIR_IORT_NODE_TYPE_ITS_GROUP,
            VIR_IORT_NODE_TYPE_ROOT_COMPLEX,
            VIR_IORT_NODE_TYPE_SMMUV3);
    DO_TEST("IORT_gigabyte", 30,
            VIR_IORT_NODE_TYPE_ITS_GROUP,
            VIR_IORT_NODE_TYPE_ROOT_COMPLEX,
            VIR_IORT_NODE_TYPE_SMMUV1_OR_SMMUV2);
    DO_TEST("IORT_qualcomm", 69,
            VIR_IORT_NODE_TYPE_ITS_GROUP,
            VIR_IORT_NODE_TYPE_NAMED_COMPONENT,
            VIR_IORT_NODE_TYPE_ROOT_COMPLEX,
            VIR_IORT_NODE_TYPE_SMMUV3,
            VIR_IORT_NODE_TYPE_PMCG);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
