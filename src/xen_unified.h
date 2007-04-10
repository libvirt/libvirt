/*
 * xen_unified.c: Unified Xen driver.
 *
 * Copyright (C) 2007 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Richard W.M. Jones <rjones@redhat.com>
 */

#ifndef __VIR_XEN_UNIFIED_H__
#define __VIR_XEN_UNIFIED_H__

#include "internal.h"

#ifdef __cplusplus
extern "C" {
#endif

extern int xenUnifiedRegister (void);

/* xenUnifiedPrivatePtr:
 *
 * Per-connection private data, stored in conn->privateData.  All Xen
 * low-level drivers access parts of this structure.
 */
struct _xenUnifiedPrivate {
#ifdef WITH_XEN
    int handle;			/* Xen hypervisor handle */

    int xendConfigVersion;      /* XenD config version */

    /* XXX This code is not IPv6 aware. */
    /* connection to xend */
    int type;                   /* PF_UNIX or PF_INET */
    int len;                    /* length of addr */
    struct sockaddr *addr;      /* type of address used */
    struct sockaddr_un addr_un; /* the unix address */
    struct sockaddr_in addr_in; /* the inet address */

    struct xs_handle *xshandle; /* handle to talk to the xenstore */
#endif /* WITH_XEN */

    int proxy;                  /* fd of proxy. */
};

typedef struct _xenUnifiedPrivate *xenUnifiedPrivatePtr;

#ifdef __cplusplus
}
#endif

#endif /* __VIR_XEN_UNIFIED_H__ */

/*
 * vim: set tabstop=4:
 * vim: set shiftwidth=4:
 * vim: set expandtab:
 */
/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
