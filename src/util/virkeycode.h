/*
 * virkeycode.h: keycodes definitions and declarations
 *
 * Copyright (c) 2011 Lai Jiangshan
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

#ifndef LIBVIRT_VIRKEYCODE_H
# define LIBVIRT_VIRKEYCODE_H

# include "virutil.h"

VIR_ENUM_DECL(virKeycodeSet);
int virKeycodeValueFromString(virKeycodeSet codeset, const char *keyname);
int virKeycodeValueTranslate(virKeycodeSet from_codeset,
                        virKeycodeSet to_offset,
                        int key_value);

#endif /* LIBVIRT_VIRKEYCODE_H */
