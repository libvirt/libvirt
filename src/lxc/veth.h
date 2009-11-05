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
#define VETH_H

#include <config.h>

/* Function declarations */
int vethCreate(char* veth1, int veth1MaxLen, char* veth2,
               int veth2MaxLen);
int vethDelete(const char* veth);
int vethInterfaceUpOrDown(const char* veth, int upOrDown);
int moveInterfaceToNetNs(const char *iface, int pidInNs);
int setMacAddr(const char* iface, const char* macaddr);
int setInterfaceName(const char* iface, const char* new);

#endif /* VETH_H */
