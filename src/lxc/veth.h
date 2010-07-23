/*
 * veth.h: Interface to tools for managing veth pairs
 *
 * Copyright IBM Corp. 2008
 *
 * See COPYING.LIB for the License of this software
 *
 * Authors:
 *  David L. Leskovec <dlesko at linux.vnet.ibm.com>
 */

#ifndef VETH_H
# define VETH_H

# include <config.h>
# include "internal.h"

/* Function declarations */
int vethCreate(char* veth1, int veth1MaxLen, char* veth2,
               int veth2MaxLen)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(3);
int vethDelete(const char* veth)
    ATTRIBUTE_NONNULL(1);
int vethInterfaceUpOrDown(const char* veth, int upOrDown)
    ATTRIBUTE_NONNULL(1);
int moveInterfaceToNetNs(const char *iface, int pidInNs)
    ATTRIBUTE_NONNULL(1);
int setMacAddr(const char* iface, const char* macaddr)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);
int setInterfaceName(const char* iface, const char* new)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

#endif /* VETH_H */
