/*
 * qemu_block.h: helper functions for QEMU block subsystem
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

#ifndef __QEMU_BLOCK_H__
# define __QEMU_BLOCK_H__

# include "internal.h"

# include "qemu_conf.h"
# include "qemu_domain.h"

# include "virhash.h"
# include "virjson.h"

typedef struct qemuBlockNodeNameBackingChainData qemuBlockNodeNameBackingChainData;
typedef qemuBlockNodeNameBackingChainData *qemuBlockNodeNameBackingChainDataPtr;
struct qemuBlockNodeNameBackingChainData {
    char *qemufilename; /* name of the image from qemu */
    char *backingstore;
    char *nodeformat;   /* node name of the format layer */
    char *nodestorage;  /* node name of the storage backing the format node */

    char *nodebacking; /* node name of the backing file format layer */

    /* data necessary for detection of the node names from qemu */
    virJSONValuePtr *elems;
    size_t nelems;
};

virHashTablePtr
qemuBlockNodeNameGetBackingChain(virJSONValuePtr data);

int
qemuBlockNodeNamesDetect(virQEMUDriverPtr driver,
                         virDomainObjPtr vm,
                         qemuDomainAsyncJob asyncJob);

virHashTablePtr
qemuBlockGetNodeData(virJSONValuePtr data);

#endif /* __QEMU_BLOCK_H__ */
