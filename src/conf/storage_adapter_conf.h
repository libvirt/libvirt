/*
 * storage_adapter_conf.h: helpers to handle storage pool adapter manipulation
 *                         (derived from storage_conf.h)
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

#pragma once

#include "virpci.h"
#include "virxml.h"
#include "virenum.h"


typedef enum {
    VIR_STORAGE_ADAPTER_TYPE_DEFAULT = 0,
    VIR_STORAGE_ADAPTER_TYPE_SCSI_HOST,
    VIR_STORAGE_ADAPTER_TYPE_FC_HOST,

    VIR_STORAGE_ADAPTER_TYPE_LAST,
} virStorageAdapterType;
VIR_ENUM_DECL(virStorageAdapter);

typedef struct _virStorageAdapterSCSIHost virStorageAdapterSCSIHost;
struct _virStorageAdapterSCSIHost {
    char *name;
    virPCIDeviceAddress parentaddr; /* host address */
    int unique_id;
    bool has_parent;
};

typedef struct _virStorageAdapterFCHost virStorageAdapterFCHost;
struct _virStorageAdapterFCHost {
    char *parent;
    char *parent_wwnn;
    char *parent_wwpn;
    char *parent_fabric_wwn;
    char *wwnn;
    char *wwpn;
    virTristateBool managed;
};

typedef struct _virStorageAdapter virStorageAdapter;
struct _virStorageAdapter {
    virStorageAdapterType type;

    union {
        virStorageAdapterSCSIHost scsi_host;
        virStorageAdapterFCHost fchost;
    } data;
};


void
virStorageAdapterClear(virStorageAdapter *adapter);

int
virStorageAdapterParseXML(virStorageAdapter *adapter,
                          xmlNodePtr node,
                          xmlXPathContextPtr ctxt);

int
virStorageAdapterValidate(virStorageAdapter *adapter);

void
virStorageAdapterFormat(virBuffer *buf,
                        virStorageAdapter *adapter);
