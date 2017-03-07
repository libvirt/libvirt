/*
 * virsysfs.h: Helper functions for manipulating sysfs files
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
 * Author: Martin Kletzander <mkletzan@redhat.com>
 */

#ifndef __VIR_SYSFS_H__
# define __VIR_SYSFS_H__

# include "internal.h"
# include "virbitmap.h"

const char * virSysfsGetSystemPath(void);

int
virSysfsGetValueInt(const char *file,
                    int *value);

int
virSysfsGetValueString(const char *file,
                       char **value);

int
virSysfsGetValueBitmap(const char *file,
                       virBitmapPtr *value);

int
virSysfsGetCpuValueInt(unsigned int cpu,
                       const char *file,
                       int *value);
int
virSysfsGetCpuValueUint(unsigned int cpu,
                        const char *file,
                        unsigned int *value);

int
virSysfsGetCpuValueString(unsigned int cpu,
                          const char *file,
                          char **value);

int
virSysfsGetCpuValueBitmap(unsigned int cpu,
                          const char *file,
                          virBitmapPtr *value);

int
virSysfsGetNodeValueString(unsigned int node,
                           const char *file,
                           char **value);

int
virSysfsGetNodeValueBitmap(unsigned int cpu,
                           const char *file,
                           virBitmapPtr *value);

#endif /* __VIR_SYSFS_H__*/
