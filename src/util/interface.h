/*
 * interface.h: interface helper APIs for libvirt
 *
 * Copyright (C) 2011 Red Hat, Inc.
 * Copyright (C) 2010 IBM Corporation, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Stefan Berger <stefanb@us.ibm.com>
 */
#ifndef __VIR_INTERFACE_H__
# define __VIR_INTERFACE_H__

# include <stdint.h>

# if __linux__

#  include <sys/socket.h>
#  include <linux/netlink.h>

# else

struct nlattr;

# endif

# include "datatypes.h"
# include "virsocketaddr.h"

# define NET_SYSFS "/sys/class/net/"


int ifaceMacvtapLinkDump(bool nltarget_kernel, const char *ifname, int ifindex,
                         struct nlattr **tb, unsigned char **recvbuf,
                         uint32_t (*getPidFunc)(void));

int ifaceGetNthParent(int ifindex, const char *ifname, unsigned int nthParent,
                      int *parent_ifindex, char *parent_ifname,
                      unsigned int *nth)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(4) ATTRIBUTE_NONNULL(5)
    ATTRIBUTE_NONNULL(6);

int virNetDevIsVirtualFunction(const char *ifname)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;

int virNetDevGetVirtualFunctionIndex(const char *pfname, const char *vfname,
                                     int *vf_index)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    ATTRIBUTE_RETURN_CHECK;

int virNetDevGetPhysicalFunction(const char *ifname, char **pfname)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;

#endif /* __VIR_INTERFACE_H__ */
