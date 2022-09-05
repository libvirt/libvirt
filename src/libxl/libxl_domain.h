/*
 * libxl_domain.h: libxl domain object private state
 *
 * Copyright (C) 2011-2014 SUSE LINUX Products GmbH, Nuernberg, Germany.
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

#include <libxl.h>

#include "libxl_conf.h"
#include "virchrdev.h"
#include "virdomainjob.h"


typedef struct _libxlDomainObjPrivate libxlDomainObjPrivate;
struct _libxlDomainObjPrivate {
    /* console */
    virChrdevs *devs;
    libxl_evgen_domain_death *deathW;
    virThread *migrationDstReceiveThr;
    unsigned short migrationPort;
    char *lockState;
    bool lockProcessRunning;

    bool hookRun;  /* true if there was a hook run over this domain */
};


extern virDomainXMLPrivateDataCallbacks libxlDomainXMLPrivateDataCallbacks;
extern virDomainDefParserConfig libxlDomainDefParserConfig;
extern virXMLNamespace libxlDriverDomainXMLNamespace;
extern const struct libxl_event_hooks ev_hooks;

int
libxlDomainObjPrivateInitCtx(virDomainObj *vm);

int
libxlDomainJobGetTimeElapsed(virDomainJobObj *job,
                             unsigned long long *timeElapsed);

char *
libxlDomainManagedSavePath(libxlDriverPrivate *driver,
                           virDomainObj *vm);

int
libxlDomainSaveImageOpen(libxlDriverPrivate *driver,
                         const char *from,
                         virDomainDef **ret_def,
                         libxlSavefileHeader *ret_hdr)
    ATTRIBUTE_NONNULL(3) ATTRIBUTE_NONNULL(4);

int
libxlDomainHookRun(libxlDriverPrivate *driver,
                   virDomainDef *def,
                   unsigned int def_fmtflags,
                   int hookop,
                   int hooksubop,
                   char **output);

int
libxlDomainDestroyInternal(libxlDriverPrivate *driver,
                           virDomainObj *vm);

void
libxlDomainCleanup(libxlDriverPrivate *driver,
                   virDomainObj *vm);

void
libxlDomainEventHandler(void *data, libxl_event *event);

int
libxlDomainAutoCoreDump(libxlDriverPrivate *driver,
                        virDomainObj *vm);

int
libxlDomainStartNew(libxlDriverPrivate *driver,
                    virDomainObj *vm,
                    bool start_paused);

int
libxlDomainStartRestore(libxlDriverPrivate *driver,
                        virDomainObj *vm,
                        bool start_paused,
                        int restore_fd,
                        uint32_t restore_ver);

bool
libxlDomainDefCheckABIStability(libxlDriverPrivate *driver,
                                virDomainDef *src,
                                virDomainDef *dst);
