/* -*- c -*-
 * libvirt.h: Core interfaces for the libvirt library
 * Summary: core interfaces for the libvirt library
 * Description: Provides the interfaces of the libvirt library to handle
 *              virtualized domains
 *
 * Copyright (C) 2005-2019 Red Hat, Inc.
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

#ifndef LIBVIRT_H
# define LIBVIRT_H

# include <sys/types.h>

# ifdef __cplusplus
extern "C" {
# endif

# define __VIR_LIBVIRT_H_INCLUDES__
# include <libvirt/libvirt-common.h>
# include <libvirt/libvirt-host.h>
# include <libvirt/libvirt-domain.h>
# include <libvirt/libvirt-domain-checkpoint.h>
# include <libvirt/libvirt-domain-snapshot.h>
# include <libvirt/libvirt-event.h>
# include <libvirt/libvirt-interface.h>
# include <libvirt/libvirt-network.h>
# include <libvirt/libvirt-nodedev.h>
# include <libvirt/libvirt-nwfilter.h>
# include <libvirt/libvirt-secret.h>
# include <libvirt/libvirt-storage.h>
# include <libvirt/libvirt-stream.h>
# undef __VIR_LIBVIRT_H_INCLUDES__

# ifdef __cplusplus
}
# endif

#endif /* LIBVIRT_H */
