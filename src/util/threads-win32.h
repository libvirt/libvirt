/*
 * threads-win32.h basic thread synchronization primitives
 *
 * Copyright (C) 2009, 2011-2012 Red Hat, Inc.
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
 */

#include "internal.h"

#ifdef HAVE_WINSOCK2_H
# include <winsock2.h>
#endif
#include <windows.h>

struct virMutex {
    HANDLE lock;
};

struct virCond {
    virMutex lock;
    unsigned int nwaiters;
    HANDLE *waiters;
};

struct virThread {
    HANDLE thread;
    bool joinable;
};

struct virThreadLocal {
    DWORD key;
};

struct virOnceControl {
    volatile long init; /* 0 at startup, > 0 if init has started */
    volatile long complete; /* 0 until first thread completes callback */
};

#define VIR_ONCE_CONTROL_INITIALIZER { 0, 0 }
