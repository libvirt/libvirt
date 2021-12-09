/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#pragma once

#include "domain_conf.h"
#include "qemu_capabilities.h"
#include "vircommand.h"

int
qemuChardevBuildCommandline(virCommand *cmd,
                            const virDomainChrSourceDef *dev,
                            const char *charAlias,
                            virQEMUCaps *qemuCaps);

int
qemuChardevGetBackendProps(const virDomainChrSourceDef *chr,
                           bool commandline,
                           const char *alias,
                           const char **backendType,
                           virJSONValue **props);
