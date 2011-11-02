/*
 * veth.h: Interface to tools for managing veth pairs
 *
 * Copyright (C) 2010 Red Hat, Inc.
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
int virNetDevVethCreate(char **veth1, char **veth2)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;
int virNetDevVethDelete(const char *veth)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;
int virNetDevSetNamespace(const char *ifname, int pidInNs)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;
int virNetDevSetName(const char *ifname, const char *newifname)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;

#endif /* VETH_H */
