/*
 * bhyve_command.h: bhyve command generation
 *
 * Copyright (C) 2014 Roman Bogorodskiy
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

#ifndef __BHYVE_COMMAND_H__
# define __BHYVE_COMMAND_H__

# include "bhyve_utils.h"

# include "domain_conf.h"
# include "vircommand.h"

virCommandPtr virBhyveProcessBuildBhyveCmd(bhyveConnPtr,
                             virDomainObjPtr vm);

virCommandPtr
virBhyveProcessBuildDestroyCmd(bhyveConnPtr driver,
                               virDomainObjPtr vm);

virCommandPtr
virBhyveProcessBuildLoadCmd(bhyveConnPtr driver,
                            virDomainObjPtr vm);

#endif /* __BHYVE_COMMAND_H__ */
