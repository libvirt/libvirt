/*
 * libvirt-lxc.c: Interfaces for the libvirt library to handle lxc-specific
 *                 APIs.
 *
 * Copyright (C) 2012-2013 Red Hat, Inc.
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
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include "viralloc.h"
#include "virerror.h"
#include "virfile.h"
#include "virlog.h"
#include "virprocess.h"
#include "datatypes.h"
#ifdef WITH_SELINUX
# include <selinux/selinux.h>
#endif

#define VIR_FROM_THIS VIR_FROM_NONE

#define virLibConnError(conn, error, info)                               \
    virReportErrorHelper(VIR_FROM_NONE, error, NULL, __FUNCTION__,       \
                         __LINE__, info)

#define virLibDomainError(domain, error, info)                          \
    virReportErrorHelper(VIR_FROM_DOM, error, NULL, __FUNCTION__,       \
                         __LINE__, info)

/**
 * virDomainLxcOpenNamespace:
 * @domain: a domain object
 * @fdlist: pointer to an array to be filled with FDs
 * @flags: currently unused, pass 0
 *
 * This API is LXC specific, so it will only work with hypervisor
 * connections to the LXC driver.
 *
 * Open the namespaces associated with the container @domain.
 * The @fdlist array will be allocated to a suitable size,
 * and filled with file descriptors for the namespaces. It
 * is the caller's responsibility to close the file descriptors
 *
 * The returned file descriptors are intended to be used with
 * the setns() system call.
 *
 * Returns the number of opened file descriptors, or -1 on error
 */
int
virDomainLxcOpenNamespace(virDomainPtr domain,
                          int **fdlist,
                          unsigned int flags)
{
    virConnectPtr conn;

    VIR_DEBUG("domain=%p, fdlist=%p flags=%x",
              domain, fdlist, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    conn = domain->conn;

    virCheckNonNullArgGoto(fdlist, error);

    if (conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->driver->domainLxcOpenNamespace) {
        int ret;
        ret = conn->driver->domainLxcOpenNamespace(domain,
                                                   fdlist,
                                                   flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return -1;
}


/**
 * virDomainLxcEnterNamespace:
 * @domain: a domain object
 * @nfdlist: number of FDs in @fdlist
 * @fdlist: list of namespace file descriptors
 * @noldfdlist: filled with number of old FDs
 * @oldfdlist: pointer to hold list of old namespace file descriptors
 * @flags: currently unused, pass 0
 *
 * This API is LXC specific, so it will only work with hypervisor
 * connections to the LXC driver.
 *
 * Attaches the process to the namespaces associated
 * with the FDs in @fdlist
 *
 * If @oldfdlist is non-NULL, it will be populated with file
 * descriptors representing the old namespace. This allows
 * the caller to switch back to its current namespace later
 *
 * Returns 0 on success, -1 on error
 */
int
virDomainLxcEnterNamespace(virDomainPtr domain,
                           unsigned int nfdlist,
                           int *fdlist,
                           unsigned int *noldfdlist,
                           int **oldfdlist,
                           unsigned int flags)
{
    size_t i;

    virCheckFlagsGoto(0, error);

    if (noldfdlist && oldfdlist) {
        size_t nfds;
        if (virProcessGetNamespaces(getpid(),
                                    &nfds,
                                    oldfdlist) < 0)
            goto error;
        *noldfdlist = nfds;
    }

    if (virProcessSetNamespaces(nfdlist, fdlist) < 0) {
        if (oldfdlist && noldfdlist) {
            for (i = 0; i < *noldfdlist; i++) {
                VIR_FORCE_CLOSE((*oldfdlist)[i]);
            }
            VIR_FREE(*oldfdlist);
            *noldfdlist = 0;
        }
        goto error;
    }

    return 0;

error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainLxcEnterSecurityLabel:
 * @model: the security model to set
 * @label: the security label to apply
 * @oldlabel: filled with old security label
 * @flags: currently unused, pass 0
 *
 * This API is LXC specific, so it will only work with hypervisor
 * connections to the LXC driver.
 *
 * Attaches the process to the security label specified
 * by @label. @label is interpreted relative to @model
 * Depending on the security driver, this may
 * not take effect until the next call to exec().
 *
 * If @oldlabel is not NULL, it will be filled with info
 * about the current security label. This may let the
 * process be moved back to the previous label if no
 * exec() has yet been performed.
 *
 * Returns 0 on success, -1 on error
 */
int
virDomainLxcEnterSecurityLabel(virSecurityModelPtr model,
                               virSecurityLabelPtr label,
                               virSecurityLabelPtr oldlabel,
                               unsigned int flags)
{
    virCheckFlagsGoto(0, error);

    virCheckNonNullArgGoto(model, error);
    virCheckNonNullArgGoto(label, error);

    if (oldlabel)
        memset(oldlabel, 0, sizeof(*oldlabel));

    if (STREQ(model->model, "selinux")) {
#ifdef WITH_SELINUX
        if (oldlabel) {
            security_context_t ctx;

            if (getcon(&ctx) < 0) {
                virReportSystemError(errno,
                                     _("unable to get PID %d security context"),
                                     getpid());
                goto error;
            }

            if (strlen((char *) ctx) >= VIR_SECURITY_LABEL_BUFLEN) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("security label exceeds "
                                 "maximum length: %d"),
                               VIR_SECURITY_LABEL_BUFLEN - 1);
                freecon(ctx);
                goto error;
            }

            strcpy(oldlabel->label, (char *) ctx);
            freecon(ctx);

            if ((oldlabel->enforcing = security_getenforce()) < 0) {
                virReportSystemError(errno, "%s",
                                     _("error calling security_getenforce()"));
                goto error;
            }
        }

        if (setexeccon(label->label) < 0) {
            virReportSystemError(errno,
                            _("Cannot set context %s"),
                            label->label);
            goto error;
        }
#else
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("Support for SELinux is not enabled"));
        goto error;
#endif
    } else {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED,
                       _("Security model %s cannot be entered"),
                       model->model);
        goto error;
    }

    return 0;

error:
    virDispatchError(NULL);
    return -1;
}
