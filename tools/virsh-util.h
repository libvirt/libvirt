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

# include <libxml/parser.h>
# include <libxml/xpath.h>

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

void
virshDomainFree(virDomainPtr dom);

void
virshDomainSnapshotFree(virDomainSnapshotPtr snap);

int
virshDomainState(vshControl *ctl,
                 virDomainPtr dom,
                 int *reason);

int
virshStreamSink(virStreamPtr st,
                const char *bytes,
                size_t nbytes,
                void *opaque);

typedef struct _virshStreamCallbackData virshStreamCallbackData;
typedef virshStreamCallbackData *virshStreamCallbackDataPtr;
struct _virshStreamCallbackData {
    vshControl *ctl;
    int fd;
};

int
virshStreamSource(virStreamPtr st,
                  char *bytes,
                  size_t nbytes,
                  void *opaque);

int
virshStreamSourceSkip(virStreamPtr st,
                      long long offset,
                      void *opaque);

int
virshStreamSkip(virStreamPtr st,
                long long offset,
                void *opaque);

int
virshStreamInData(virStreamPtr st,
                  int *inData,
                  long long *offset,
                  void *opaque);

int
virshDomainGetXMLFromDom(vshControl *ctl,
                         virDomainPtr dom,
                         unsigned int flags,
                         xmlDocPtr *xml,
                         xmlXPathContextPtr *ctxt)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(4)
    ATTRIBUTE_NONNULL(5) ATTRIBUTE_RETURN_CHECK;

int
virshDomainGetXML(vshControl *ctl,
                  const vshCmd *cmd,
                  unsigned int flags,
                  xmlDocPtr *xml,
                  xmlXPathContextPtr *ctxt)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(4)
    ATTRIBUTE_NONNULL(5) ATTRIBUTE_RETURN_CHECK;

#endif /* VIRSH_UTIL_H */
