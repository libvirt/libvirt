#include <config.h>

#include "internal.h"
#include "esx_vi.h"

int
esxVI_LookupDatastoreList(esxVI_Context *ctx G_GNUC_UNUSED,
                          esxVI_String *propertyNameList,
                          esxVI_ObjectContent **datastoreList)
{
    esxVI_String *tmp;

    for (tmp = propertyNameList; tmp; tmp = tmp->_next) {
        esxVI_ObjectContent *obj = NULL;
        esxVI_DynamicProperty *prop = NULL;

        if (STRNEQ(tmp->value, "summary.name"))
            continue;

        esxVI_ObjectContent_Alloc(&obj);

        esxVI_DynamicProperty_Alloc(&prop);
        prop->name = g_strdup("summary.name");

        esxVI_AnyType_Alloc(&prop->val);
        prop->val->type = esxVI_Type_String;
        prop->val->other = g_strdup("xsd:string");
        prop->val->value = g_strdup("datastore");
        prop->val->string = prop->val->value;
        esxVI_DynamicProperty_AppendToList(&obj->propSet, prop);

        esxVI_ObjectContent_AppendToList(datastoreList, obj);
    }

    return 0;
}


int
esxVI_LookupDatastoreHostMount(esxVI_Context *ctx G_GNUC_UNUSED,
                               esxVI_ManagedObjectReference *datastore G_GNUC_UNUSED,
                               esxVI_DatastoreHostMount **hostMount,
                               esxVI_Occurrence occurrence G_GNUC_UNUSED)
{
    esxVI_DatastoreHostMount *hm = NULL;

    esxVI_DatastoreHostMount_Alloc(&hm);
    esxVI_HostMountInfo_Alloc(&hm->mountInfo);
    hm->mountInfo->path = g_strdup("/non/existent");
    hm->mountInfo->accessMode = g_strdup("readWrite");
    hm->mountInfo->accessible = esxVI_Boolean_True;

    *hostMount = hm;
    return 0;
}


int
esxVI_LookupDatastoreByName(esxVI_Context *ctx G_GNUC_UNUSED,
                            const char *name,
                            esxVI_String *propertyNameList G_GNUC_UNUSED,
                            esxVI_ObjectContent **datastore,
                            esxVI_Occurrence occurrence G_GNUC_UNUSED)
{
    esxVI_ObjectContent *obj = NULL;

    if (STREQ(name, "missing") || STREQ(name, "ds")) {
        *datastore = NULL;
        return 0;
    }

    /* No need to return anything useful, empty object is fine. */
    esxVI_ObjectContent_Alloc(&obj);
    esxVI_ObjectContent_AppendToList(datastore, obj);

    return 0;
}
