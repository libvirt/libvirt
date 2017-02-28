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

#ifndef __VIR_STORAGE_ADAPTER_CONF_H__
# define __VIR_STORAGE_ADAPTER_CONF_H__

# include "virpci.h"
# include "virxml.h"


typedef enum {
    VIR_STORAGE_ADAPTER_TYPE_DEFAULT = 0,
    VIR_STORAGE_ADAPTER_TYPE_SCSI_HOST,
    VIR_STORAGE_ADAPTER_TYPE_FC_HOST,

    VIR_STORAGE_ADAPTER_TYPE_LAST,
} virStorageAdapterType;
VIR_ENUM_DECL(virStorageAdapter)

typedef struct _virStorageAdapterSCSIHost virStorageAdapterSCSIHost;
typedef virStorageAdapterSCSIHost *virStorageAdapterSCSIHostPtr;
struct _virStorageAdapterSCSIHost {
    char *name;
    virPCIDeviceAddress parentaddr; /* host address */
    int unique_id;
    bool has_parent;
};

typedef struct _virStorageAdapterFCHost virStorageAdapterFCHost;
typedef virStorageAdapterFCHost *virStorageAdapterFCHostPtr;
struct _virStorageAdapterFCHost {
    char *parent;
    char *parent_wwnn;
    char *parent_wwpn;
    char *parent_fabric_wwn;
    char *wwnn;
    char *wwpn;
    int managed;        /* enum virTristateSwitch */
};

typedef struct _virStorageAdapter virStorageAdapter;
typedef virStorageAdapter *virStorageAdapterPtr;
struct _virStorageAdapter {
    int type; /* virStorageAdapterType */

    union {
        virStorageAdapterSCSIHost scsi_host;
        virStorageAdapterFCHost fchost;
    } data;
};


void
virStorageAdapterClear(virStorageAdapterPtr adapter);

int
virStorageAdapterParseXML(virStorageAdapterPtr adapter,
                          xmlNodePtr node,
                          xmlXPathContextPtr ctxt);

int
virStorageAdapterValidate(virStorageAdapterPtr adapter);

void
virStorageAdapterFormat(virBufferPtr buf,
                        virStorageAdapterPtr adapter);

#endif /* __VIR_STORAGE_ADAPTER_CONF_H__ */
