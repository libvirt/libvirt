/*
 * remote_driver.h: driver to provide access to libvirtd running
 *   on a remote machine
 *
 * Copyright (C) 2006-2007, 2010 Red Hat, Inc.
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

#ifndef LIBVIRT_REMOTE_DRIVER_H
# define LIBVIRT_REMOTE_DRIVER_H

# include "internal.h"
# include "configmake.h"

int remoteRegister (void);

unsigned long remoteVersion(void);

# define LIBVIRTD_LISTEN_ADDR NULL
# define LIBVIRTD_TLS_PORT "16514"
# define LIBVIRTD_TCP_PORT "16509"
# define LIBVIRTD_PRIV_UNIX_SOCKET LOCALSTATEDIR "/run/libvirt/libvirt-sock"
# define LIBVIRTD_PRIV_UNIX_SOCKET_RO LOCALSTATEDIR "/run/libvirt/libvirt-sock-ro"
# define LIBVIRTD_USER_UNIX_SOCKET "libvirt-sock"
# define LIBVIRTD_CONFIGURATION_FILE SYSCONFDIR "/libvirt/libvirtd.conf"

/* Defaults for PKI directory. */
# define LIBVIRT_PKI_DIR SYSCONFDIR "/pki"
# define LIBVIRT_CACERT LIBVIRT_PKI_DIR "/CA/cacert.pem"
# define LIBVIRT_CLIENTKEY LIBVIRT_PKI_DIR "/libvirt/private/clientkey.pem"
# define LIBVIRT_CLIENTCERT LIBVIRT_PKI_DIR "/libvirt/clientcert.pem"
# define LIBVIRT_SERVERKEY LIBVIRT_PKI_DIR "/libvirt/private/serverkey.pem"
# define LIBVIRT_SERVERCERT LIBVIRT_PKI_DIR "/libvirt/servercert.pem"


#endif /* LIBVIRT_REMOTE_DRIVER_H */
