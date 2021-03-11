/*
 * Copyright (C) 2012 Fujitsu Limited.
 *
 * lxc_fuse.c: fuse filesystem support for libvirt lxc
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

#define FUSE_USE_VERSION 26

#if WITH_FUSE
# include <fuse.h>
#endif

#include "lxc_conf.h"

struct virLXCMeminfo {
    unsigned long long memtotal;
    unsigned long long memusage;
    unsigned long long cached;
    unsigned long long active_anon;
    unsigned long long inactive_anon;
    unsigned long long active_file;
    unsigned long long inactive_file;
    unsigned long long unevictable;
    unsigned long long swaptotal;
    unsigned long long swapusage;
};

struct virLXCFuse {
    virDomainDef *def;
    virThread thread;
    char *mountpoint;
    struct fuse *fuse;
    struct fuse_chan *ch;
    virMutex lock;
};
typedef struct virLXCFuse virLXCFuse;

int lxcSetupFuse(struct virLXCFuse **f, virDomainDef *def);
int lxcStartFuse(struct virLXCFuse *f);
void lxcFreeFuse(struct virLXCFuse **f);
