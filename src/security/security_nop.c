/*
 * Copyright (C) 2010-2011 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 */

#include <config.h>

#include "security_nop.h"

static virSecurityDriverStatus virSecurityDriverProbeNop(void)
{
    return SECURITY_DRIVER_ENABLE;
}

static int virSecurityDriverOpenNop(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED)
{
    return 0;
}

static int virSecurityDriverCloseNop(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED)
{
    return 0;
}

static const char * virSecurityDriverGetModelNop(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED)
{
    return "none";
}

static const char * virSecurityDriverGetDOINop(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED)
{
    return "0";
}

static int virSecurityDomainRestoreImageLabelNop(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                                                 virDomainDefPtr vm ATTRIBUTE_UNUSED,
                                                 virDomainDiskDefPtr disk ATTRIBUTE_UNUSED)
{
    return 0;
}

static int virSecurityDomainSetDaemonSocketLabelNop(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                                                    virDomainDefPtr vm ATTRIBUTE_UNUSED)
{
    return 0;
}

static int virSecurityDomainSetSocketLabelNop(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                                              virDomainDefPtr vm ATTRIBUTE_UNUSED)
{
    return 0;
}

static int virSecurityDomainClearSocketLabelNop(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                                                virDomainDefPtr vm ATTRIBUTE_UNUSED)
{
    return 0;
}

static int virSecurityDomainSetImageLabelNop(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                                             virDomainDefPtr vm ATTRIBUTE_UNUSED,
                                             virDomainDiskDefPtr disk ATTRIBUTE_UNUSED)
{
    return 0;
}

static int virSecurityDomainRestoreHostdevLabelNop(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                                                   virDomainDefPtr vm ATTRIBUTE_UNUSED,
                                                   virDomainHostdevDefPtr dev ATTRIBUTE_UNUSED)
{
    return 0;
}

static int virSecurityDomainSetHostdevLabelNop(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                                               virDomainDefPtr vm ATTRIBUTE_UNUSED,
                                               virDomainHostdevDefPtr dev ATTRIBUTE_UNUSED)
{
    return 0;
}

static int virSecurityDomainSetSavedStateLabelNop(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                                                  virDomainDefPtr vm ATTRIBUTE_UNUSED,
                                                  const char *savefile ATTRIBUTE_UNUSED)
{
    return 0;
}
static int virSecurityDomainRestoreSavedStateLabelNop(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                                                      virDomainDefPtr vm ATTRIBUTE_UNUSED,
                                                      const char *savefile ATTRIBUTE_UNUSED)
{
    return 0;
}

static int virSecurityDomainGenLabelNop(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                                        virDomainDefPtr sec ATTRIBUTE_UNUSED)
{
    return 0;
}

static int virSecurityDomainReserveLabelNop(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                                            virDomainDefPtr sec ATTRIBUTE_UNUSED,
                                            pid_t pid ATTRIBUTE_UNUSED)
{
    return 0;
}

static int virSecurityDomainReleaseLabelNop(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                                            virDomainDefPtr sec ATTRIBUTE_UNUSED)
{
    return 0;
}

static int virSecurityDomainSetAllLabelNop(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                                           virDomainDefPtr sec ATTRIBUTE_UNUSED,
                                           const char *stdin_path ATTRIBUTE_UNUSED)
{
    return 0;
}

static int virSecurityDomainRestoreAllLabelNop(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                                               virDomainDefPtr vm ATTRIBUTE_UNUSED,
                                               int migrated ATTRIBUTE_UNUSED)
{
    return 0;
}
static int virSecurityDomainGetProcessLabelNop(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                                               virDomainDefPtr vm ATTRIBUTE_UNUSED,
                                               pid_t pid ATTRIBUTE_UNUSED,
                                               virSecurityLabelPtr sec ATTRIBUTE_UNUSED)
{
    return 0;
}

static int virSecurityDomainSetProcessLabelNop(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                                               virDomainDefPtr vm ATTRIBUTE_UNUSED)
{
    return 0;
}

static int virSecurityDomainVerifyNop(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                                      virDomainDefPtr def ATTRIBUTE_UNUSED)
{
    return 0;
}

static int virSecurityDomainSetFDLabelNop(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                                          virDomainDefPtr sec ATTRIBUTE_UNUSED,
                                          int fd ATTRIBUTE_UNUSED)
{
    return 0;
}

virSecurityDriver virSecurityDriverNop = {
    0,
    "none",
    virSecurityDriverProbeNop,
    virSecurityDriverOpenNop,
    virSecurityDriverCloseNop,

    virSecurityDriverGetModelNop,
    virSecurityDriverGetDOINop,

    virSecurityDomainVerifyNop,

    virSecurityDomainSetImageLabelNop,
    virSecurityDomainRestoreImageLabelNop,

    virSecurityDomainSetDaemonSocketLabelNop,
    virSecurityDomainSetSocketLabelNop,
    virSecurityDomainClearSocketLabelNop,

    virSecurityDomainGenLabelNop,
    virSecurityDomainReserveLabelNop,
    virSecurityDomainReleaseLabelNop,

    virSecurityDomainGetProcessLabelNop,
    virSecurityDomainSetProcessLabelNop,

    virSecurityDomainSetAllLabelNop,
    virSecurityDomainRestoreAllLabelNop,

    virSecurityDomainSetHostdevLabelNop,
    virSecurityDomainRestoreHostdevLabelNop,

    virSecurityDomainSetSavedStateLabelNop,
    virSecurityDomainRestoreSavedStateLabelNop,

    virSecurityDomainSetFDLabelNop,
};
