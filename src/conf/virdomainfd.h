/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#pragma once

#include "internal.h"

struct _virDomainFDTuple {
    GObject parent;
    int *fds;
    size_t nfds;
    int *testfds; /* populated by tests to ensure stable FDs */

    bool writable;
    bool tryRestoreLabel;

    /* connection this FD tuple is associated with for auto-closing */
    virConnect *conn;

    /* original selinux label when we relabel the image */
    char *selinuxLabel;
};
G_DECLARE_FINAL_TYPE(virDomainFDTuple, vir_domain_fd_tuple, VIR, DOMAIN_FD_TUPLE, GObject);

virDomainFDTuple *
virDomainFDTupleNew(void);
