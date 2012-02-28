/*
 * hook.h: internal entry points needed for synchronous hooks support
 *
 * Copyright (C) 2010 Red Hat, Inc.
 * Copyright (C) 2010 Daniel Veillard
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
 * Author: Daniel Veillard <veillard@redhat.com>
 */

#ifndef __VIR_HOOKS_H__
# define __VIR_HOOKS_H__

# include "internal.h"
# include "util.h"

enum virHookDriverType {
    VIR_HOOK_DRIVER_DAEMON = 0,        /* Daemon related events */
    VIR_HOOK_DRIVER_QEMU,              /* QEmu domains related events */
    VIR_HOOK_DRIVER_LXC,               /* LXC domains related events */

    VIR_HOOK_DRIVER_LAST,
};

enum virHookDaemonOpType {
    VIR_HOOK_DAEMON_OP_START,          /* daemon is about to start */
    VIR_HOOK_DAEMON_OP_SHUTDOWN,       /* daemon is about to shutdown */
    VIR_HOOK_DAEMON_OP_RELOAD,         /* driver reload with SIGHUP */

    VIR_HOOK_DAEMON_OP_LAST,
};

enum virHookSubopType {
    VIR_HOOK_SUBOP_NONE,               /* no sub-operation */
    VIR_HOOK_SUBOP_BEGIN,              /* beginning of the operation */
    VIR_HOOK_SUBOP_END,                /* end of the operation */

    VIR_HOOK_SUBOP_LAST,
};

enum virHookQemuOpType {
    VIR_HOOK_QEMU_OP_START,            /* domain is about to start */
    VIR_HOOK_QEMU_OP_STOPPED,          /* domain has stopped */
    VIR_HOOK_QEMU_OP_PREPARE,          /* domain startup initiated */
    VIR_HOOK_QEMU_OP_RELEASE,          /* domain destruction is over */
    VIR_HOOK_QEMU_OP_MIGRATE,          /* domain is being migrated */

    VIR_HOOK_QEMU_OP_LAST,
};

enum virHookLxcOpType {
    VIR_HOOK_LXC_OP_START,            /* domain is about to start */
    VIR_HOOK_LXC_OP_STOPPED,          /* domain has stopped */

    VIR_HOOK_LXC_OP_LAST,
};

int virHookInitialize(void);

int virHookPresent(int driver);

int virHookCall(int driver, const char *id, int op, int sub_op,
                const char *extra, const char *input, char **output);

#endif /* __VIR_HOOKS_H__ */
