/*
 * hyperv_wsman.h: OpenWSMAN include and GLib auto-cleanup
 *
 * Copyright (C) 2021 Datto Inc
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

#pragma once

#include <wsman-api.h>

G_DEFINE_AUTO_CLEANUP_FREE_FUNC(WsXmlDocH, ws_xml_destroy_doc, NULL);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(client_opt_t, wsmc_options_destroy);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(filter_t, filter_destroy);
