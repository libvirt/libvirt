/*
 * snapshot_conf_priv.h: domain snapshot XML processing (private)
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

#ifndef LIBVIRT_SNAPSHOT_CONF_PRIV_H_ALLOW
# error "snapshot_conf_priv.h may only be included by snapshot_conf.c or test suites"
#endif /* LIBVIRT_SNAPSHOT_CONF_PRIV_H_ALLOW */

#pragma once

#include "snapshot_conf.h"

int
virDomainSnapshotDiskDefParseXML(xmlNodePtr node,
                                 xmlXPathContextPtr ctxt,
                                 virDomainSnapshotDiskDef *def,
                                 unsigned int flags,
                                 virDomainXMLOption *xmlopt);
