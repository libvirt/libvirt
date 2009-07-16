/* Copyright 2002-2009, Distributed Systems Architecture Group, Universidad
 * Complutense de Madrid (dsa-research.org)
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
 */

#ifndef ONE_CLIENT_H_
#define ONE_CLIENT_H_

#include <xmlrpc-c/base.h>
#include <xmlrpc-c/client.h>

struct _oneClient {
    xmlrpc_env env;
    const char *url;
    const char *session;
    char *error;
};

typedef struct _oneClient oneClient;
typedef oneClient *oneClientPtr;

void c_oneStart(void);

int c_oneDeploy(int vmid, int hid);

int c_oneMigrate(int vmid, int hid, int flag);

int c_oneAllocateTemplate(char* vm_template);

int c_oneAction(int vmid,char* action);

int c_oneShutdown(int vmid);

int c_oneSuspend(int vmid);

int c_oneStop(int vmid);

int c_oneResume(int vmid);

int c_oneCancel(int vmid);

int c_oneFinalize(int vmid);

int c_oneVmInfo(int vmid, char* ret_info,int leng);

void c_oneFree(void);


#endif /* ONE_CLIENT_H_ */
