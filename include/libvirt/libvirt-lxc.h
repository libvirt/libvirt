/* -*- c -*-
 * libvirt-lxc.h: Interfaces specific for LXC driver
 * Summary: lxc specific interfaces
 * Description: Provides the interfaces of the libvirt library to handle
 *              LXC specific methods
 *
 * Copyright (C) 2012-2013 Red Hat, Inc.
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
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef __VIR_LXC_H__
# define __VIR_LXC_H__

# include <libvirt/libvirt.h>

# ifdef __cplusplus
extern "C" {
# endif

int virDomainLxcOpenNamespace(virDomainPtr domain,
                              int **fdlist,
                              unsigned int flags);

int virDomainLxcEnterNamespace(virDomainPtr domain,
                               unsigned int nfdlist,
                               int *fdlist,
                               unsigned int *noldfdlist,
                               int **oldfdlist,
                               unsigned int flags);
int virDomainLxcEnterSecurityLabel(virSecurityModelPtr model,
                                   virSecurityLabelPtr label,
                                   virSecurityLabelPtr oldlabel,
                                   unsigned int flags);

# ifdef __cplusplus
}
# endif

#endif /* __VIR_LXC_H__ */
