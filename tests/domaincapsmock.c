/*
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

#include <config.h>

#include "virhostcpu.h"
#ifdef WITH_LIBXL
# include "libxl/libxl_capabilities.h"
#endif

#ifdef WITH_LIBXL
bool
libxlCapsHasPVUSB(void)
{
    return true;
}
#endif

int
virHostCPUGetKVMMaxVCPUs(void)
{
    return INT_MAX;
}

unsigned int
virHostCPUGetMicrocodeVersion(virArch hostArch G_GNUC_UNUSED)
{
    return 0;
}
