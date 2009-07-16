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

#include <config.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include "one_client.h"

oneClient one_client;

void c_oneStart()
{
    xmlrpc_env_init(&one_client.env);
    xmlrpc_client_init2(&one_client.env, XMLRPC_CLIENT_NO_FLAGS,
        "OpenNebula API Client", "1.2", NULL, 0);

    one_client.error = 0;
    one_client.url = "http://localhost:2633/RPC2";
    one_client.session = "one-session";
};


int c_oneReturnCode(xmlrpc_value *resultP);

int c_oneReturnCode(xmlrpc_value *resultP)
{
    int return_code;
    char *return_string;

    xmlrpc_decompose_value(&one_client.env, resultP, "(bs)",
        &return_code, &return_string);

    if( return_code )
    {
        xmlrpc_DECREF(resultP);
        free(return_string);
        return 0;
    }
    else
    {
        free(one_client.error);

        one_client.error=return_string;
        return -1;
    }
}

int c_oneDeploy(int vmid, int hid)
{
    xmlrpc_value *resultP;

    resultP = xmlrpc_client_call(&one_client.env, one_client.url,
        "one.vmdeploy", "(sii)", one_client.session, (xmlrpc_int32)vmid,
        (xmlrpc_int32)hid);

    return c_oneReturnCode(resultP);
}

int c_oneMigrate(int vmid, int hid, int flag)
{
    xmlrpc_value *resultP;

    resultP = xmlrpc_client_call(&one_client.env, one_client.url,
        "one.vmmigrate", "(siib)", one_client.session, (xmlrpc_int32)vmid,
        (xmlrpc_int32)hid,
        (xmlrpc_bool)flag);

    return c_oneReturnCode(resultP);
}

int c_oneAllocateTemplate(char* vm_template)
{
    xmlrpc_value *resultP;
    xmlrpc_value *valueP;
    int return_code;
    char *return_string;
    int vmid;


    resultP = xmlrpc_client_call(&one_client.env, one_client.url,
        "one.vmallocate", "(ss)", one_client.session, vm_template);

    xmlrpc_array_read_item(&one_client.env, resultP, 0, &valueP);
    xmlrpc_read_bool(&one_client.env, valueP, &return_code);

    if( return_code )
    {
        xmlrpc_DECREF(valueP);
        xmlrpc_array_read_item(&one_client.env, resultP, 1, &valueP);
        xmlrpc_read_int(&one_client.env, valueP, &vmid);

        xmlrpc_DECREF(valueP);
        xmlrpc_DECREF(resultP);

        return vmid;
    }
    else
    {
        xmlrpc_DECREF(valueP);
        xmlrpc_array_read_item(&one_client.env, resultP, 1, &valueP);
        xmlrpc_read_string(&one_client.env, valueP,
            (const char **)&return_string);

        xmlrpc_DECREF(valueP);
        xmlrpc_DECREF(resultP);

        free(one_client.error);

        one_client.error=return_string;
        return -1;
    }
}

int c_oneAction(int vmid, char* action)
{
    xmlrpc_value *resultP;

    resultP = xmlrpc_client_call(&one_client.env, one_client.url,
        "one.vmaction", "(ssi)", one_client.session, action,
        (xmlrpc_int32)vmid);

    return c_oneReturnCode(resultP);
}

int c_oneShutdown(int vmid)
{
    return c_oneAction(vmid, (char *)"shutdown");
}

int c_oneSuspend(int vmid)
{
    return c_oneAction(vmid, (char *)"suspend");
}

int c_oneStop(int vmid)
{
    return c_oneAction(vmid, (char *)"stop");
}

int c_oneResume(int vmid)
{
    return c_oneAction(vmid, (char *)"resume");
}

int c_oneCancel(int vmid)
{
    return c_oneAction(vmid, (char *)"cancel");
}

int c_oneFinalize(int vmid)
{
    return c_oneAction(vmid, (char *)"finalize");
}

int c_oneVmInfo(int vmid, char* ret_info,int length)
{
    xmlrpc_value *resultP;
    int return_code;
    char *return_string;

    resultP = xmlrpc_client_call(&one_client.env, one_client.url,
        "one.vmget_info", "(si)", one_client.session, vmid);

    xmlrpc_decompose_value(&one_client.env, resultP, "(bs)",
        &return_code, &return_string);

    if( return_code )
    {
        strncpy(ret_info, return_string, length-1);
        ret_info[length-1] = '\0';

        xmlrpc_DECREF(resultP);
        free(return_string);

        return 0;
    }
    else
    {
        xmlrpc_DECREF(resultP);
        free(return_string);

        return -1;
    }
}

void c_oneFree()
{
    xmlrpc_env_clean(&one_client.env);
    xmlrpc_client_cleanup();
}
