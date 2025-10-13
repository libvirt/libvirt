/* packet-libvirt.h --- Libvirt packet dissector header file.
 *
 * Copyright (C) 2013 Yuto KAWAMURA(kawamuray) <kawamuray.dadada@gmail.com>
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

#pragma once

#ifdef WITH_WS_VERSION
# include <wireshark/ws_version.h>
#else
# include <wireshark/config.h>
# define WIRESHARK_VERSION_MAJOR VERSION_MAJOR
# define WIRESHARK_VERSION_MINOR VERSION_MINOR
# define WIRESHARK_VERSION_MICRO VERSION_MICRO
#endif

#define WIRESHARK_VERSION \
    ((WIRESHARK_VERSION_MAJOR * 1000 * 1000) + \
     (WIRESHARK_VERSION_MINOR * 1000) + \
     (WIRESHARK_VERSION_MICRO))

void proto_register_libvirt(void);
void proto_reg_handoff_libvirt(void);
