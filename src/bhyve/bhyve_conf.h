/*
 * bhyve_conf.h: bhyve config file
 *
 * Copyright (C) 2017 Roman Bogorodskiy
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

#ifndef LIBVIRT_BHYVE_CONF_H
# define LIBVIRT_BHYVE_CONF_H

# include "bhyve_utils.h"

virBhyveDriverConfigPtr virBhyveDriverConfigNew(void);
virBhyveDriverConfigPtr virBhyveDriverGetConfig(bhyveConnPtr driver);
int virBhyveLoadDriverConfig(virBhyveDriverConfigPtr cfg,
                             const char *filename);

typedef struct _bhyveDomainCmdlineDef bhyveDomainCmdlineDef;
typedef bhyveDomainCmdlineDef *bhyveDomainCmdlineDefPtr;
struct _bhyveDomainCmdlineDef {
    size_t num_args;
    char **args;
};

void bhyveDomainCmdlineDefFree(bhyveDomainCmdlineDefPtr def);

#endif /* LIBVIRT_BHYVE_CONF_H */
