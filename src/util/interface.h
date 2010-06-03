/*
 * interface.h: interface helper APIs for libvirt
 *
 * Copyright (C) 2010 IBM Corporation, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Stefan Berger <stefanb@us.ibm.com>
 */
#ifndef __VIR_INTERFACE_H__
# define __VIR_INTERFACE_H__

# include "datatypes.h"

int ifaceGetFlags(const char *name, short *flags);
int ifaceIsUp(const char *name, bool *up);

int ifaceCtrl(const char *name, bool up);

static inline int ifaceUp(const char *name) {
    return ifaceCtrl(name, true);
}

static inline int ifaceDown(const char *name) {
    return ifaceCtrl(name, false);
}

int ifaceCheck(bool reportError, const char *ifname,
               const unsigned char *macaddr, int ifindex);

int ifaceGetIndex(bool reportError, const char *ifname, int *ifindex);

int ifaceGetVlanID(const char *vlanifname, int *vlanid);

#endif /* __VIR_INTERFACE_H__ */
