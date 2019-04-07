/*
 * virkmod.h: helper APIs for managing kernel modprobe
 *
 * Copyright (C) 2014 Red Hat, Inc.
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

#ifndef LIBVIRT_VIRKMOD_H
# define LIBVIRT_VIRKMOD_H

# include "internal.h"

char *virKModConfig(void);
char *virKModLoad(const char *, bool)
    ATTRIBUTE_NONNULL(1);
char *virKModUnload(const char *)
    ATTRIBUTE_NONNULL(1);
bool virKModIsBlacklisted(const char *)
    ATTRIBUTE_NONNULL(1);
#endif /* LIBVIRT_VIRKMOD_H */
