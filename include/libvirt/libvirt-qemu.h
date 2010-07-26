/* -*- c -*-
 * libvirt-qemu.h:
 * Summary: qemu specific interfaces
 * Description: Provides the interfaces of the libvirt library to handle
 *              qemu specific methods
 *
 * Copy:  Copyright (C) 2010 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Author: Chris Lalancette <clalance@redhat.com>
 */

#ifndef __VIR_QEMU_H__
# define __VIR_QEMU_H__

# include "libvirt/libvirt.h"

# ifdef __cplusplus
extern "C" {
# endif

int virDomainQemuMonitorCommand(virDomainPtr domain, const char *cmd,
                                char **result, unsigned int flags);

# ifdef __cplusplus
}
# endif

#endif /* __VIR_QEMU_H__ */
