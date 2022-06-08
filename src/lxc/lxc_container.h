/*
 * Copyright IBM Corp. 2008
 *
 * lxc_container.h: Performs container setup tasks
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

#include "lxc_domain.h"
#include "security/security_manager.h"

#define LXC_DEV_MAJ_MEMORY  1
#define LXC_DEV_MIN_NULL    3
#define LXC_DEV_MIN_ZERO    5
#define LXC_DEV_MIN_FULL    7
#define LXC_DEV_MIN_RANDOM  8
#define LXC_DEV_MIN_URANDOM 9

#define LXC_DEV_MAJ_TTY     5
#define LXC_DEV_MIN_TTY     0
#define LXC_DEV_MIN_CONSOLE 1
#define LXC_DEV_MIN_PTMX    2

#define LXC_DEV_MAJ_PTY     136

#define LXC_DEV_MAJ_FUSE    10
#define LXC_DEV_MIN_FUSE    229

int lxcContainerSendContinue(int control);
int lxcContainerWaitForContinue(int control);

int lxcContainerStart(virDomainDef *def,
                      virSecurityManager *securityDriver,
                      size_t nveths,
                      char **veths,
                      size_t npassFDs,
                      int *passFDs,
                      int control,
                      int handshakefd,
                      int *nsInheritFDs,
                      size_t nttyPaths,
                      char **ttyPaths);

int lxcContainerSetupHostdevCapsMakePath(const char *dev);

virArch lxcContainerGetAlt32bitArch(virArch arch);

int lxcContainerChown(virDomainDef *def, const char *path);

bool lxcIsBasicMountLocation(const char *path);
