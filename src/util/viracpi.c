/*
 * viracpi.c: ACPI table(s) parser
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
 * License along with this library;  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#include <inttypes.h>
#include <fcntl.h>
#include <unistd.h>

#define LIBVIRT_VIRACPIPRIV_H_ALLOW
#include "internal.h"
#include "viracpi.h"
#include "viracpipriv.h"
#include "viralloc.h"
#include "virerror.h"
#include "virfile.h"
#include "virlog.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.acpi");

typedef struct virIORTHeader virIORTHeader;
struct virIORTHeader {
    uint32_t signature;
    uint32_t length;
    uint8_t revision;
    uint8_t checksum;
    char oem_id[6];
    char oem_table_id[8];
    char oem_revision[4];
    char creator_id[4];
    char creator_revision[4];
    /* Technically, the following are not part of header, but
     * they immediately follow the header and are in the table
     * exactly once. */
    uint32_t nnodes;
    uint32_t nodes_offset;
    /* Here follows reserved and padding fields. Ain't nobody's
     * interested in that. */
} ATTRIBUTE_PACKED;

VIR_ENUM_IMPL(virIORTNodeType,
              VIR_IORT_NODE_TYPE_LAST,
              "ITS Group",
              "Named Component",
              "Root Complex",
              "SMMUv1 or SMMUv2",
              "SMMUv3",
              "PMCG",
              "Memory range");


static int
virAcpiParseIORTNodeHeader(int fd,
                           const char *filename,
                           virIORTNodeHeader *nodeHeader)
{
    g_autofree char *nodeHeaderBuf = NULL;
    const char *typeStr = NULL;
    int nodeHeaderLen;

    nodeHeaderLen = virFileReadHeaderFD(fd, sizeof(*nodeHeader), &nodeHeaderBuf);
    if (nodeHeaderLen < 0) {
        virReportSystemError(errno,
                             _("cannot read node header '%1$s'"),
                             filename);
        return -1;
    }

    if (nodeHeaderLen != sizeof(*nodeHeader)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("IORT table node header ended early"));
        return -1;
    }

    memcpy(nodeHeader, nodeHeaderBuf, nodeHeaderLen);

    typeStr = virIORTNodeTypeTypeToString(nodeHeader->type);

    VIR_DEBUG("IORT node header: type = %" PRIu8 " (%s) len = %" PRIu16,
              nodeHeader->type, NULLSTR(typeStr), nodeHeader->len);

    /* Basic sanity check. While there's a type specific data
     * that follows the node header, the node length should be at
     * least size of header itself. */
    if (nodeHeader->len < sizeof(*nodeHeader)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("IORT table node type %1$s has invalid length: got %2$u, expected at least %3$zu"),
                       NULLSTR(typeStr), (unsigned int)nodeHeader->len, sizeof(*nodeHeader));
        return -1;
    }
    return 0;
}


static ssize_t
virAcpiParseIORTNodes(int fd,
                      const char *filename,
                      const virIORTHeader *header,
                      virIORTNodeHeader **nodesRet)
{
    g_autofree virIORTNodeHeader *nodes = NULL;
    size_t nnodes = 0;
    off_t pos;

    /* Firstly, reset position to the start of nodes. */
    if ((pos = lseek(fd, header->nodes_offset, SEEK_SET)) < 0) {
        virReportSystemError(errno,
                             _("cannot seek in '%1$s'"),
                             filename);
        return -1;
    }

    for (; pos < header->length;) {
        virIORTNodeHeader node;

        if (virAcpiParseIORTNodeHeader(fd, filename, &node) < 0)
            return -1;

        if ((pos = lseek(fd, pos + node.len, SEEK_SET)) < 0) {
            virReportSystemError(errno,
                                 _("cannot seek in '%1$s'"),
                                 filename);
            return -1;
        }

        VIR_APPEND_ELEMENT(nodes, nnodes, node);
    }

    *nodesRet = g_steal_pointer(&nodes);
    return nnodes;
}


ssize_t
virAcpiParseIORT(virIORTNodeHeader **nodesRet,
                 const char *filename)
{
    VIR_AUTOCLOSE fd = -1;
    g_autofree char *headerBuf = NULL;
    int headerLen;
    virIORTHeader header;

    if ((fd = open(filename, O_RDONLY)) < 0) {
        virReportSystemError(errno,
                             _("cannot open '%1$s'"),
                             filename);
        return -1;
    }

    headerLen = virFileReadHeaderFD(fd, sizeof(header), &headerBuf);
    if (headerLen < 0) {
        virReportSystemError(errno,
                             _("cannot read header '%1$s'"),
                             filename);
        return -1;
    }

    if (headerLen != sizeof(header)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("IORT table header ended early"));
        return -1;
    }

    memcpy(&header, headerBuf, headerLen);

    VIR_DEBUG("IORT header: len = %" PRIu32 " revision = %" PRIu8
              " nnodes = %" PRIu32 " OEM = %s",
              header.length, header.revision,
              header.nnodes, header.oem_id);

    return virAcpiParseIORTNodes(fd, filename, &header, nodesRet);
}


#define IORT_PATH "/sys/firmware/acpi/tables/IORT"

/**
 * virAcpiHasSMMU:
 *
 * Parse IORT table trying to find SMMU node entry.
 * Since IORT is ARM specific ACPI table, it doesn't make much
 * sense to call this function on other platforms and expect
 * sensible result.
 *
 * Returns: 0 if no SMMU node was found,
 *          1 if a SMMU node was found (i.e. host supports SMMU),
 *         -1 otherwise (with error reported).
 */
int
virAcpiHasSMMU(void)
{
    g_autofree virIORTNodeHeader *nodes = NULL;
    ssize_t nnodes = -1;
    size_t i;

    if ((nnodes = virAcpiParseIORT(&nodes, IORT_PATH)) < 0)
        return -1;

    for (i = 0; i < nnodes; i++) {
        if (nodes[i].type == VIR_IORT_NODE_TYPE_SMMUV1_OR_SMMUV2 ||
            nodes[i].type == VIR_IORT_NODE_TYPE_SMMUV3) {
            return 1;
        }
    }

    return 0;
}
