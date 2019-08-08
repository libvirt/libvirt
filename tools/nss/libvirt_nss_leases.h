/*
 * libvirt_nss_leases.h: Name Service Switch plugin lease file parser
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

#pragma once

#include <sys/types.h>

typedef struct {
    unsigned char addr[16];
    int af;
    long long expirytime;
} leaseAddress;

int
findLeases(const char *file,
           const char *name,
           char **macs,
           size_t nmacs,
           int af,
           time_t now,
           leaseAddress **addrs,
           size_t *naddrs,
           bool *found);
