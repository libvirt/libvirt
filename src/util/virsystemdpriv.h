/*
 * virsystemdpriv.h: Functions for testing virSystemd APIs
 *
 * Copyright (C) 2016 Red Hat, Inc.
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

#ifndef LIBVIRT_VIRSYSTEMDPRIV_H_ALLOW
# error "virsystemdpriv.h may only be included by virsystemd.c or test suites"
#endif /* LIBVIRT_VIRSYSTEMDPRIV_H_ALLOW */

#pragma once

#include "virsystemd.h"

void virSystemdHasMachinedResetCachedValue(void);
void virSystemdHasLogindResetCachedValue(void);
