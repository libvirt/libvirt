/*
 * libvirt_nss: Name Service Switch plugin
 *
 * The aim is to enable users and applications to translate
 * domain names into IP addresses. However, this is currently
 * available only for those domains which gets their IP addresses
 * from a libvirt managed network.
 *
 * Copyright (C) 2016 Red Hat, Inc.
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

#include <nss.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdlib.h>

#include "libvirt_nss_log.h"

#if !defined(LIBVIRT_NSS_GUEST)
# define NSS_NAME(s) _nss_libvirt_##s##_r
#else
# define NSS_NAME(s) _nss_libvirt_guest_##s##_r
#endif

#if !defined(g_autofree)
static inline void
generic_free(void *p)
{
    free(*((void **)p));
}
# define g_autofree __attribute__((cleanup(generic_free)))
#endif

#if !defined(g_steal_pointer)
static inline void *
g_steal_pointer(void *p)
{
    void **pp = (void **)p;
    void *ptr = *pp;

    *pp = NULL;
    return ptr;
}
# define g_steal_pointer(x) (__typeof__(*(x))) g_steal_pointer(x)
#endif


enum nss_status
NSS_NAME(gethostbyname)(const char *name, struct hostent *result,
                        char *buffer, size_t buflen, int *errnop,
                        int *herrnop);

enum nss_status
NSS_NAME(gethostbyname2)(const char *name, int af, struct hostent *result,
                         char *buffer, size_t buflen, int *errnop,
                         int *herrnop);

enum nss_status
NSS_NAME(gethostbyname3)(const char *name, int af, struct hostent *result,
                         char *buffer, size_t buflen, int *errnop,
                         int *herrnop, int32_t *ttlp, char **canonp);

#ifdef WITH_STRUCT_GAIH_ADDRTUPLE
enum nss_status
NSS_NAME(gethostbyname4)(const char *name, struct gaih_addrtuple **pat,
                         char *buffer, size_t buflen, int *errnop,
                         int *herrnop, int32_t *ttlp);
#endif /* WITH_STRUCT_GAIH_ADDRTUPLE */

#if defined(WITH_BSD_NSS)
ns_mtab*
nss_module_register(const char *name, unsigned int *size,
                    nss_module_unregister_fn *unregister);
#endif /* WITH_BSD_NSS */
