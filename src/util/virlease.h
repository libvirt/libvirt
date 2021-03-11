/*
 * virlease.h: Leases file handling
 *
 * Copyright (C) 2014 Red Hat, Inc.
 * Copyright (C) 2014 Nehal J Wani
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
 */

#pragma once

#include "virjson.h"

int virLeaseReadCustomLeaseFile(virJSONValue *leases_array_new,
                                const char *custom_lease_file,
                                const char *ip_to_delete,
                                char **server_duid);

int virLeasePrintLeases(virJSONValue *leases_array_new,
                        const char *server_duid);


int virLeaseNew(virJSONValue **lease_ret,
                const char *mac,
                const char *clientid,
                const char *ip,
                const char *hostname,
                const char *iaid,
                const char *server_duid);
