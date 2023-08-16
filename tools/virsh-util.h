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

#pragma once

#include "virsh.h"

#include <libxml/parser.h>
#include <libxml/xpath.h>

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

typedef virDomain virshDomain;
void
virshDomainFree(virDomainPtr dom);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(virshDomain, virshDomainFree);

typedef virDomainCheckpoint virshDomainCheckpoint;
void
virshDomainCheckpointFree(virDomainCheckpointPtr chk);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(virshDomainCheckpoint, virshDomainCheckpointFree);

typedef virDomainSnapshot virshDomainSnapshot;
void
virshDomainSnapshotFree(virDomainSnapshotPtr snap);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(virshDomainSnapshot, virshDomainSnapshotFree);

typedef virInterface virshInterface;
void
virshInterfaceFree(virInterfacePtr iface);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(virshInterface, virshInterfaceFree);

typedef virNetwork virshNetwork;
void
virshNetworkFree(virNetworkPtr network);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(virshNetwork, virshNetworkFree);

typedef virNodeDevice virshNodeDevice;
void
virshNodeDeviceFree(virNodeDevicePtr device);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(virshNodeDevice, virshNodeDeviceFree);

typedef virNWFilter virshNWFilter;
void
virshNWFilterFree(virNWFilterPtr nwfilter);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(virshNWFilter, virshNWFilterFree);

typedef virSecret virshSecret;
void
virshSecretFree(virSecretPtr secret);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(virshSecret, virshSecretFree);

typedef virStoragePool virshStoragePool;
void
virshStoragePoolFree(virStoragePoolPtr pool);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(virshStoragePool, virshStoragePoolFree);

typedef virStorageVol virshStorageVol;
void
virshStorageVolFree(virStorageVolPtr vol);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(virshStorageVol, virshStorageVolFree);

typedef virStream virshStream;
void
virshStreamFree(virStreamPtr stream);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(virshStream, virshStreamFree);

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
struct _virshStreamCallbackData {
    vshControl *ctl;
    int fd;
    bool isBlock;
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
    ATTRIBUTE_NONNULL(5) G_GNUC_WARN_UNUSED_RESULT;

int
virshNetworkGetXMLFromNet(vshControl *ctl,
                          virNetworkPtr net,
                          unsigned int flags,
                          xmlDocPtr *xml,
                          xmlXPathContextPtr *ctxt)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(4)
    ATTRIBUTE_NONNULL(5) G_GNUC_WARN_UNUSED_RESULT;

int
virshDomainGetXML(vshControl *ctl,
                  const vshCmd *cmd,
                  unsigned int flags,
                  xmlDocPtr *xml,
                  xmlXPathContextPtr *ctxt)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(4)
    ATTRIBUTE_NONNULL(5) G_GNUC_WARN_UNUSED_RESULT;

VIR_ENUM_DECL(virshDomainBlockJob);

const char *
virshDomainBlockJobToString(int type);

bool
virshDumpXML(vshControl *ctl,
             const char *xml,
             const char *url,
             const char *xpath,
             bool wrap);
