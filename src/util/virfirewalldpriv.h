/*
 * virfirewalldpriv.h: private APIs for firewalld
 *
 * Copyright (C) 2019 Red Hat, Inc.
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

#ifndef LIBVIRT_VIRFIREWALLDPRIV_H_ALLOW
# error "virfirewalldpriv.h may only be included by virfirewalld.c or test suites"
#endif /* LIBVIRT_VIRFIREWALLDPRIV_H_ALLOW */

#pragma once

#define VIR_FIREWALL_FIREWALLD_SERVICE "org.fedoraproject.FirewallD1"
