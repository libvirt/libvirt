/*
 * virpcivpdpriv.h: helper APIs for working with the PCI/PCIe VPD capability
 *
 * Copyright (C) 2021 Canonical Ltd.
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

#ifndef LIBVIRT_VIRPCIVPDPRIV_H_ALLOW
# error "virpcivpdpriv.h may only be included by virpcivpd.c or test suites"
#endif /* LIBVIRT_VIRPCIVPDPRIV_H_ALLOW */

#pragma once

#include "virpcivpd.h"

/*
 * PCI Local bus (2.2+, Appendix I) and PCIe 4.0+ (7.9.19 VPD Capability) define
 * the VPD capability structure (8 bytes in total) and VPD registers that can be used to access
 * VPD data including:
 * bit 31 of the first 32-bit DWORD: data transfer completion flag (between the VPD data register
 * and the VPD data storage hardware);
 * bits 30:16 of the first 32-bit DWORD: VPD address of the first VPD data byte to be accessed;
 * bits 31:0 of the second 32-bit DWORD: VPD data bytes with LSB being pointed to by the VPD address.
 *
 * Given that only 15 bits (30:16) are allocated for VPD address its mask is 0x7fff.
*/
#define PCI_VPD_ADDR_MASK 0x7FFF

/*
 * VPD data consists of small and large resource data types. Information within a resource type
 * consists of a 2-byte keyword, 1-byte length and data bytes (up to 255).
*/
#define PCI_VPD_MAX_FIELD_SIZE 255
#define PCI_VPD_LARGE_RESOURCE_FLAG 0x80
#define PCI_VPD_STRING_RESOURCE_FLAG 0x02
#define PCI_VPD_READ_ONLY_LARGE_RESOURCE_FLAG 0x10
#define PCI_VPD_READ_WRITE_LARGE_RESOURCE_FLAG 0x11
#define PCI_VPD_RESOURCE_END_TAG 0x0F
#define PCI_VPD_RESOURCE_END_VAL PCI_VPD_RESOURCE_END_TAG << 3

typedef enum {
    VIR_PCI_VPD_RESOURCE_FIELD_VALUE_FORMAT_TEXT = 1,
    VIR_PCI_VPD_RESOURCE_FIELD_VALUE_FORMAT_BINARY,
    VIR_PCI_VPD_RESOURCE_FIELD_VALUE_FORMAT_RESVD,
    VIR_PCI_VPD_RESOURCE_FIELD_VALUE_FORMAT_RDWR,
    VIR_PCI_VPD_RESOURCE_FIELD_VALUE_FORMAT_LAST
} virPCIVPDResourceFieldValueFormat;

virPCIVPDResourceFieldValueFormat virPCIVPDResourceGetFieldValueFormat(const char *value);

bool virPCIVPDResourceIsValidTextValue(const char *value);

gboolean
virPCIVPDResourceCustomCompareIndex(virPCIVPDResourceCustom *a, virPCIVPDResourceCustom *b);

bool
virPCIVPDResourceCustomUpsertValue(GPtrArray *arr, char index, const char *const value);

size_t
virPCIVPDReadVPDBytes(int vpdFileFd, uint8_t *buf, size_t count, off_t offset, uint8_t *csum);

bool virPCIVPDParseVPDLargeResourceFields(int vpdFileFd, uint16_t resPos, uint16_t resDataLen,
                                          bool readOnly, uint8_t *csum, virPCIVPDResource *res);

bool virPCIVPDParseVPDLargeResourceString(int vpdFileFd, uint16_t resPos, uint16_t resDataLen,
                                          uint8_t *csum, virPCIVPDResource *res);
