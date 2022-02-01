/*
 * virnetdevpriv.h: private virnetdev header for unit testing
 *
 * Copyright (C) 2021 Canonical Ltd.
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
 * License along with this library;  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifndef LIBVIRT_VIRNETDEVPRIV_H_ALLOW
# error "virnetdevpriv.h may only be included by virnetdev.c or test suites"
#endif /* LIBVIRT_VIRNETDEVPRIV_H_ALLOW */

#pragma once

#include "virnetdev.h"

int
virNetDevSendVfSetLinkRequest(const char *ifname,
                              int vfInfoType,
                              const void *payload,
                              const size_t payloadLen);

int
virNetDevSetVfVlan(const char *ifname,
                   int vf,
                   const int *vlanid);

int
virNetDevSetVfMac(const char *ifname,
                  int vf,
                  const virMacAddr *macaddr,
                  bool *allowRetry);

int
virNetDevSetVfConfig(const char *ifname,
                     int vf,
                     const virMacAddr *macaddr,
                     const int *vlanid,
                     bool *allowRetry);
