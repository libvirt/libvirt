/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include <config.h>

#include "virdomainfd.h"

#include "virfile.h"

G_DEFINE_TYPE(virDomainFDTuple, vir_domain_fd_tuple, G_TYPE_OBJECT);


static void
vir_domain_fd_tuple_init(virDomainFDTuple *fdt G_GNUC_UNUSED)
{
}


static void
virDomainFDTupleFinalize(GObject *object)
{
    virDomainFDTuple *fdt = VIR_DOMAIN_FD_TUPLE(object);
    size_t i;

    if (!fdt)
        return;

    for (i = 0; i < fdt->nfds; i++)
        VIR_FORCE_CLOSE(fdt->fds[i]);

    g_free(fdt->fds);
    g_free(fdt->testfds);
    g_free(fdt->selinuxLabel);
    G_OBJECT_CLASS(vir_domain_fd_tuple_parent_class)->finalize(object);
}


static void
vir_domain_fd_tuple_class_init(virDomainFDTupleClass *klass)
{
    GObjectClass *obj = G_OBJECT_CLASS(klass);

    obj->finalize = virDomainFDTupleFinalize;
}


virDomainFDTuple *
virDomainFDTupleNew(void)
{
    return g_object_new(vir_domain_fd_tuple_get_type(), NULL);
}
