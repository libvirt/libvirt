/*
 * virsh-completer.h: virsh completer callbacks
 *
 * Copyright (C) 2017 Red Hat, Inc.
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

#include "virsh-completer-checkpoint.h"
#include "virsh-completer-domain.h"
#include "virsh-completer-host.h"
#include "virsh-completer-interface.h"
#include "virsh-completer-network.h"
#include "virsh-completer-nodedev.h"
#include "virsh-completer-nwfilter.h"
#include "virsh-completer-pool.h"
#include "virsh-completer-secret.h"
#include "virsh-completer-snapshot.h"
#include "virsh-completer-volume.h"

char **
virshEnumComplete(unsigned int last,
                  const char *(*intToStr)(int));

char **
virshCommaStringListComplete(const char *input,
                             const char **options);

char **
virshCompletePathLocalExisting(vshControl *ctl,
                               const vshCmd *cmd,
                               unsigned int completerflags);

char **
virshCompleteEmpty(vshControl *ctl,
                   const vshCmd *cmd,
                   unsigned int completerflags);
