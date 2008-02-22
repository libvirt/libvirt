/*
 * private utility functions
 *
 * Copyright (C) 2008 Red Hat, Inc.
 * See COPYING.LIB for the License of this software
 */

#ifndef __UTIL_LIB_H__
#define __UTIL_LIB_H__

#include <sys/types.h>

int saferead(int fd, void *buf, size_t count);
ssize_t safewrite(int fd, const void *buf, size_t count);

#endif
