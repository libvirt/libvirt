/*
 * vbox_glue.h: glue to the VirtualBox API
 *
 * Copyright (C) 2010 Matthias Bolte <matthias.bolte@googlemail.com>
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

#ifndef LIBVIRT_VBOX_GLUE_H
# define LIBVIRT_VBOX_GLUE_H

# ifdef WIN32
#  include "vbox_MSCOMGlue.h"
# else
#  include "vbox_XPCOMCGlue.h"
# endif

#endif /* LIBVIRT_VBOX_GLUE_H */
