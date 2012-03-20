/*
 * virauth.h: authentication related utility functions
 *
 * Copyright (C) 2010 Matthias Bolte <matthias.bolte@googlemail.com>
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

#ifndef __VIR_AUTH_H__
# define __VIR_AUTH_H__

# include "internal.h"

int virAuthGetConfigFilePath(virConnectPtr conn,
                             char **path);

char *virAuthGetUsername(virConnectPtr conn,
                         virConnectAuthPtr auth,
                         const char *servicename,
                         const char *defaultUsername,
                         const char *hostname);
char *virAuthGetPassword(virConnectPtr conn,
                         virConnectAuthPtr auth,
                         const char *servicename,
                         const char *username,
                         const char *hostname);

#endif /* __VIR_AUTH_H__ */
