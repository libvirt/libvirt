/*
 * virsh-util.h: helpers for virsh
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

#ifndef VIRSH_UTIL_H
# define VIRSH_UTIL_H

# include "virsh.h"


virDomainPtr
virshLookupDomainBy(vshControl *ctl,
                    const char *name,
                    unsigned int flags);

virDomainPtr
virshCommandOptDomainBy(vshControl *ctl,
                        const vshCmd *cmd,
                        const char **name,
                        unsigned int flags);

virDomainPtr
virshCommandOptDomain(vshControl *ctl,
                      const vshCmd *cmd,
                      const char **name);

int
virshDomainState(vshControl *ctl,
                 virDomainPtr dom,
                 int *reason);

int
virshStreamSink(virStreamPtr st,
                const char *bytes,
                size_t nbytes,
                void *opaque);

#endif /* VIRSH_UTIL_H */
