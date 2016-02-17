/*
 * qemu_parse_command.h: QEMU command parser
 *
 * Copyright (C) 2006-2016 Red Hat, Inc.
 * Copyright (C) 2006 Daniel P. Berrange
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
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef __QEMU_PARSE_COMMAND_H__
# define __QEMU_PARSE_COMMAND_H__

# define QEMU_QXL_VGAMEM_DEFAULT 16 * 1024

/*
 * NB: def->name can be NULL upon return and the caller
 * *must* decide how to fill in a name in this case
 */
virDomainDefPtr qemuParseCommandLineString(virCapsPtr caps,
                                           virDomainXMLOptionPtr xmlopt,
                                           const char *args,
                                           char **pidfile,
                                           virDomainChrSourceDefPtr *monConfig,
                                           bool *monJSON);
virDomainDefPtr qemuParseCommandLinePid(virCapsPtr caps,
                                        virDomainXMLOptionPtr xmlopt,
                                        pid_t pid,
                                        char **pidfile,
                                        virDomainChrSourceDefPtr *monConfig,
                                        bool *monJSON);

int
qemuParseKeywords(const char *str,
                  char ***retkeywords,
                  char ***retvalues,
                  int *retnkeywords,
                  int allowEmptyValue);

#endif /* __QEMU_PARSE_COMMAND_H__*/
