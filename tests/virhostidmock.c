/*
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

#include <config.h>

#include "util/virutil.h"
#include "util/viruuid.h"

char *
virGetHostname(void)
{
    return g_strdup("hostname");
}


int
virGetHostUUID(unsigned char *uuid)
{
    /* uuidgen --sha1 --namespace @dns --name "hostname" */
    const char *fakeuuid = "4a802f00-4cba-5df6-9679-a08c4c5b577f";

    return virUUIDParse(fakeuuid, uuid);
}
