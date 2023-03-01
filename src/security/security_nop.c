/*
 * Copyright (C) 2010-2013 Red Hat, Inc.
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
 */

#include <config.h>

#include "security_nop.h"

#define VIR_FROM_THIS VIR_FROM_SECURITY

static virSecurityDriverStatus
virSecurityDriverProbeNop(const char *virtDriver G_GNUC_UNUSED)
{
    return SECURITY_DRIVER_ENABLE;
}

static int
virSecurityDriverOpenNop(virSecurityManager *mgr G_GNUC_UNUSED)
{
    return 0;
}

static int
virSecurityDriverCloseNop(virSecurityManager *mgr G_GNUC_UNUSED)
{
    return 0;
}

static const char *
virSecurityDriverGetModelNop(virSecurityManager *mgr G_GNUC_UNUSED)
{
    return "none";
}

static const char *
virSecurityDriverGetDOINop(virSecurityManager *mgr G_GNUC_UNUSED)
{
    return "0";
}

static int
virSecurityDomainSetDaemonSocketLabelNop(virSecurityManager *mgr G_GNUC_UNUSED,
                                         virDomainDef *vm G_GNUC_UNUSED)
{
    return 0;
}

static int
virSecurityDomainSetSocketLabelNop(virSecurityManager *mgr G_GNUC_UNUSED,
                                   virDomainDef *vm G_GNUC_UNUSED)
{
    return 0;
}

static int
virSecurityDomainClearSocketLabelNop(virSecurityManager *mgr G_GNUC_UNUSED,
                                     virDomainDef *vm G_GNUC_UNUSED)
{
    return 0;
}

static int
virSecurityDomainRestoreHostdevLabelNop(virSecurityManager *mgr G_GNUC_UNUSED,
                                        virDomainDef *vm G_GNUC_UNUSED,
                                        virDomainHostdevDef *dev G_GNUC_UNUSED,
                                        const char *vroot G_GNUC_UNUSED)
{
    return 0;
}

static int
virSecurityDomainSetHostdevLabelNop(virSecurityManager *mgr G_GNUC_UNUSED,
                                    virDomainDef *vm G_GNUC_UNUSED,
                                    virDomainHostdevDef *dev G_GNUC_UNUSED,
                                    const char *vroot G_GNUC_UNUSED)
{
    return 0;
}

static int
virSecurityDomainGenLabelNop(virSecurityManager *mgr G_GNUC_UNUSED,
                             virDomainDef *sec G_GNUC_UNUSED)
{
    return 0;
}

static int
virSecurityDomainReserveLabelNop(virSecurityManager *mgr G_GNUC_UNUSED,
                                 virDomainDef *sec G_GNUC_UNUSED,
                                 pid_t pid G_GNUC_UNUSED)
{
    return 0;
}

static int
virSecurityDomainReleaseLabelNop(virSecurityManager *mgr G_GNUC_UNUSED,
                                 virDomainDef *sec G_GNUC_UNUSED)
{
    return 0;
}

static int
virSecurityDomainSetAllLabelNop(virSecurityManager *mgr G_GNUC_UNUSED,
                                virDomainDef *sec G_GNUC_UNUSED,
                                const char *incomingPath G_GNUC_UNUSED,
                                bool chardevStdioLogd G_GNUC_UNUSED,
                                bool migrated G_GNUC_UNUSED)
{
    return 0;
}

static int
virSecurityDomainRestoreAllLabelNop(virSecurityManager *mgr G_GNUC_UNUSED,
                                    virDomainDef *vm G_GNUC_UNUSED,
                                    bool migrated G_GNUC_UNUSED,
                                    bool chardevStdioLogd G_GNUC_UNUSED)
{
    return 0;
}

static int
virSecurityDomainGetProcessLabelNop(virSecurityManager *mgr G_GNUC_UNUSED,
                                    virDomainDef *vm G_GNUC_UNUSED,
                                    pid_t pid G_GNUC_UNUSED,
                                    virSecurityLabelPtr sec G_GNUC_UNUSED)
{
    return 0;
}

static int
virSecurityDomainSetProcessLabelNop(virSecurityManager *mgr G_GNUC_UNUSED,
                                    virDomainDef *vm G_GNUC_UNUSED)
{
    return 0;
}

static int
virSecurityDomainSetChildProcessLabelNop(virSecurityManager *mgr G_GNUC_UNUSED,
                                         virDomainDef *vm G_GNUC_UNUSED,
                                         bool useBinarySpecificLabel G_GNUC_UNUSED,
                                         virCommand *cmd G_GNUC_UNUSED)
{
    return 0;
}

static int
virSecurityDomainVerifyNop(virSecurityManager *mgr G_GNUC_UNUSED,
                           virDomainDef *def G_GNUC_UNUSED)
{
    return 0;
}

static int
virSecurityDomainSetFDLabelNop(virSecurityManager *mgr G_GNUC_UNUSED,
                               virDomainDef *sec G_GNUC_UNUSED,
                               int fd G_GNUC_UNUSED)
{
    return 0;
}

static char *
virSecurityDomainGetMountOptionsNop(virSecurityManager *mgr G_GNUC_UNUSED,
                                    virDomainDef *vm G_GNUC_UNUSED)
{
    return g_strdup("");
}

static const char *
virSecurityGetBaseLabel(virSecurityManager *mgr G_GNUC_UNUSED,
                        int virtType G_GNUC_UNUSED)
{
    return NULL;
}

static int
virSecurityDomainRestoreImageLabelNop(virSecurityManager *mgr G_GNUC_UNUSED,
                                      virDomainDef *def G_GNUC_UNUSED,
                                      virStorageSource *src G_GNUC_UNUSED,
                                      virSecurityDomainImageLabelFlags flags G_GNUC_UNUSED)
{
    return 0;
}

static int
virSecurityDomainSetImageLabelNop(virSecurityManager *mgr G_GNUC_UNUSED,
                                  virDomainDef *def G_GNUC_UNUSED,
                                  virStorageSource *src G_GNUC_UNUSED,
                                  virSecurityDomainImageLabelFlags flags G_GNUC_UNUSED)
{
    return 0;
}

static int
virSecurityDomainMoveImageMetadataNop(virSecurityManager *mgr G_GNUC_UNUSED,
                                      pid_t pid G_GNUC_UNUSED,
                                      virStorageSource *src G_GNUC_UNUSED,
                                      virStorageSource *dst G_GNUC_UNUSED)
{
    return 0;
}

static int
virSecurityDomainSetMemoryLabelNop(virSecurityManager *mgr G_GNUC_UNUSED,
                                   virDomainDef *def G_GNUC_UNUSED,
                                   virDomainMemoryDef *mem G_GNUC_UNUSED)
{
    return 0;
}

static int
virSecurityDomainRestoreMemoryLabelNop(virSecurityManager *mgr G_GNUC_UNUSED,
                                       virDomainDef *def G_GNUC_UNUSED,
                                       virDomainMemoryDef *mem G_GNUC_UNUSED)
{
    return 0;
}

static int
virSecurityDomainInputLabelNop(virSecurityManager *mgr G_GNUC_UNUSED,
                               virDomainDef *def G_GNUC_UNUSED,
                               virDomainInputDef *input G_GNUC_UNUSED)
{
    return 0;
}

static int
virSecurityDomainSetChardevLabelNop(virSecurityManager *mgr G_GNUC_UNUSED,
                                    virDomainDef *def G_GNUC_UNUSED,
                                    virDomainChrSourceDef *dev_source G_GNUC_UNUSED,
                                    bool chardevStdioLogd G_GNUC_UNUSED)
{
    return 0;
}

static int
virSecurityDomainRestoreChardevLabelNop(virSecurityManager *mgr G_GNUC_UNUSED,
                                        virDomainDef *def G_GNUC_UNUSED,
                                        virDomainChrSourceDef *dev_source G_GNUC_UNUSED,
                                        bool chardevStdioLogd G_GNUC_UNUSED)
{
    return 0;
}

virSecurityDriver virSecurityDriverNop = {
    .privateDataLen                     = 0,
    .name                               = "none",
    .probe                              = virSecurityDriverProbeNop,
    .open                               = virSecurityDriverOpenNop,
    .close                              = virSecurityDriverCloseNop,

    .getModel                           = virSecurityDriverGetModelNop,
    .getDOI                             = virSecurityDriverGetDOINop,

    .domainSecurityVerify               = virSecurityDomainVerifyNop,

    .domainSetSecurityImageLabel        = virSecurityDomainSetImageLabelNop,
    .domainRestoreSecurityImageLabel    = virSecurityDomainRestoreImageLabelNop,
    .domainMoveImageMetadata            = virSecurityDomainMoveImageMetadataNop,

    .domainSetSecurityMemoryLabel       = virSecurityDomainSetMemoryLabelNop,
    .domainRestoreSecurityMemoryLabel   = virSecurityDomainRestoreMemoryLabelNop,

    .domainSetSecurityInputLabel        = virSecurityDomainInputLabelNop,
    .domainRestoreSecurityInputLabel    = virSecurityDomainInputLabelNop,

    .domainSetSecurityDaemonSocketLabel = virSecurityDomainSetDaemonSocketLabelNop,
    .domainSetSecuritySocketLabel       = virSecurityDomainSetSocketLabelNop,
    .domainClearSecuritySocketLabel     = virSecurityDomainClearSocketLabelNop,

    .domainGenSecurityLabel             = virSecurityDomainGenLabelNop,
    .domainReserveSecurityLabel         = virSecurityDomainReserveLabelNop,
    .domainReleaseSecurityLabel         = virSecurityDomainReleaseLabelNop,

    .domainGetSecurityProcessLabel      = virSecurityDomainGetProcessLabelNop,
    .domainSetSecurityProcessLabel      = virSecurityDomainSetProcessLabelNop,
    .domainSetSecurityChildProcessLabel = virSecurityDomainSetChildProcessLabelNop,

    .domainSetSecurityAllLabel          = virSecurityDomainSetAllLabelNop,
    .domainRestoreSecurityAllLabel      = virSecurityDomainRestoreAllLabelNop,

    .domainSetSecurityHostdevLabel      = virSecurityDomainSetHostdevLabelNop,
    .domainRestoreSecurityHostdevLabel  = virSecurityDomainRestoreHostdevLabelNop,

    .domainSetSecurityImageFDLabel      = virSecurityDomainSetFDLabelNop,
    .domainSetSecurityTapFDLabel        = virSecurityDomainSetFDLabelNop,

    .domainGetSecurityMountOptions      = virSecurityDomainGetMountOptionsNop,

    .getBaseLabel                       = virSecurityGetBaseLabel,

    .domainSetSecurityChardevLabel      = virSecurityDomainSetChardevLabelNop,
    .domainRestoreSecurityChardevLabel  = virSecurityDomainRestoreChardevLabelNop,
};
