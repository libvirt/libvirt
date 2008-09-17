/*
 * driver.h: core driver methods for managing qemu guests
 *
 * Copyright (C) 2006, 2007 Red Hat, Inc.
 * Copyright (C) 2006 Daniel P. Berrange
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */


#ifndef QEMUD_DRIVER_H
#define QEMUD_DRIVER_H

#include <config.h>

#include "internal.h"

#if HAVE_LINUX_KVM_H
#include <linux/kvm.h>
#endif

/* device for kvm ioctls */
#define KVM_DEVICE "/dev/kvm"

/* add definitions missing in older linux/kvm.h */
#ifndef KVMIO
#  define KVMIO 0xAE
#endif
#ifndef KVM_CHECK_EXTENSION
#  define KVM_CHECK_EXTENSION       _IO(KVMIO,   0x03)
#endif
#ifndef KVM_CAP_NR_VCPUS
#  define KVM_CAP_NR_VCPUS 9       /* returns max vcpus per vm */
#endif

int qemudRegister(void);

#endif /* QEMUD_DRIVER_H */
