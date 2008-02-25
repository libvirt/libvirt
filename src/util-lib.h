/*
 * private utility functions
 *
 * Copyright (C) 2008 Red Hat, Inc.
 * See COPYING.LIB for the License of this software
 */

#ifndef __UTIL_LIB_H__
#define __UTIL_LIB_H__

#include <sys/types.h>

/*
 * To avoid a double definition of the function when compiling
 * programs using both util-lib and libvirt, like virsh
 */
#ifdef IN_LIBVIRT
#define saferead libvirt_saferead
#define safewrite libvirt_safewrite
#endif

int saferead(int fd, void *buf, size_t count);
ssize_t safewrite(int fd, const void *buf, size_t count);

#endif
