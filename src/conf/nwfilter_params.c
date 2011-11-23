/*
 * nwfilter_params.c: parsing and data maintenance of filter parameters
 *
 * Copyright (C) 2011 Red Hat, Inc.
 * Copyright (C) 2010 IBM Corporation
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
 * Author: Stefan Berger <stefanb@us.ibm.com>
 */

#include <config.h>

#include "internal.h"

#include "memory.h"
#include "virterror_internal.h"
#include "datatypes.h"
#include "nwfilter_params.h"
#include "domain_conf.h"


#define VIR_FROM_THIS VIR_FROM_NWFILTER

static bool isValidVarValue(const char *value);


void
virNWFilterVarValueFree(virNWFilterVarValuePtr val)
{
    unsigned i;

    if (!val)
        return;

    switch (val->valType) {
    case NWFILTER_VALUE_TYPE_SIMPLE:
        VIR_FREE(val->u.simple.value);
        break;
    case NWFILTER_VALUE_TYPE_ARRAY:
        for (i = 0; i < val->u.array.nValues; i++)
            VIR_FREE(val->u.array.values[i]);
        VIR_FREE(val->u.array.values);
        break;
    case NWFILTER_VALUE_TYPE_LAST:
        break;
    }
    VIR_FREE(val);
}

virNWFilterVarValuePtr
virNWFilterVarValueCopy(const virNWFilterVarValuePtr val)
{
    virNWFilterVarValuePtr res;
    unsigned i;
    char *str;

    if (VIR_ALLOC(res) < 0) {
        virReportOOMError();
        return NULL;
    }
    res->valType = val->valType;

    switch (res->valType) {
    case NWFILTER_VALUE_TYPE_SIMPLE:
        if (val->u.simple.value) {
            res->u.simple.value = strdup(val->u.simple.value);
            if (!res->u.simple.value)
                goto err_exit;
        }
        break;
    case NWFILTER_VALUE_TYPE_ARRAY:
        if (VIR_ALLOC_N(res->u.array.values, val->u.array.nValues))
            goto err_exit;
        res->u.array.nValues = val->u.array.nValues;
        for (i = 0; i < val->u.array.nValues; i++) {
            str = strdup(val->u.array.values[i]);
            if (!str)
                goto err_exit;
            res->u.array.values[i] = str;
        }
        break;
    case NWFILTER_VALUE_TYPE_LAST:
        break;
    }

    return res;

err_exit:
    virReportOOMError();
    virNWFilterVarValueFree(res);
    return NULL;
}

virNWFilterVarValuePtr
virNWFilterVarValueCreateSimple(char *value)
{
    virNWFilterVarValuePtr val;

    if (!isValidVarValue(value)) {
        virNWFilterReportError(VIR_ERR_INVALID_ARG,
                               _("Variable value contains invalid character"));
        return NULL;
    }

    if (VIR_ALLOC(val) < 0) {
        virReportOOMError();
        return NULL;
    }

    val->valType = NWFILTER_VALUE_TYPE_SIMPLE;
    val->u.simple.value = value;

    return val;
}

virNWFilterVarValuePtr
virNWFilterVarValueCreateSimpleCopyValue(const char *value)
{
    char *val = strdup(value);

    if (!val) {
        virReportOOMError();
        return NULL;
    }
    return virNWFilterVarValueCreateSimple(val);
}

const char *
virNWFilterVarValueGetSimple(const virNWFilterVarValuePtr val)
{
    if (val->valType == NWFILTER_VALUE_TYPE_SIMPLE)
        return val->u.simple.value;
    return NULL;
}

const char *
virNWFilterVarValueGetNthValue(virNWFilterVarValuePtr val, unsigned int idx)
{
    const char *res = NULL;

    switch (val->valType) {
    case NWFILTER_VALUE_TYPE_SIMPLE:
        if (idx == 0)
            res = val->u.simple.value;
        break;
    case NWFILTER_VALUE_TYPE_ARRAY:
        if (idx < val->u.array.nValues)
            res = val->u.array.values[idx];
        break;
    case NWFILTER_VALUE_TYPE_LAST:
        break;
    }

    return res;
}

unsigned int
virNWFilterVarValueGetCardinality(const virNWFilterVarValuePtr val)
{
    switch (val->valType) {
    case NWFILTER_VALUE_TYPE_SIMPLE:
        return 1;
        break;
    case NWFILTER_VALUE_TYPE_ARRAY:
        return val->u.array.nValues;
        break;
    case NWFILTER_VALUE_TYPE_LAST:
        return 0;
    }
    return 0;
}

int
virNWFilterVarValueAddValue(virNWFilterVarValuePtr val, char *value)
{
    char *tmp;
    int rc = -1;

    switch (val->valType) {
    case NWFILTER_VALUE_TYPE_SIMPLE:
        /* switch to array */
        tmp = val->u.simple.value;
        if (VIR_ALLOC_N(val->u.array.values, 2) < 0) {
            val->u.simple.value = tmp;
            virReportOOMError();
            return -1;
        }
        val->valType = NWFILTER_VALUE_TYPE_ARRAY;
        val->u.array.nValues = 2;
        val->u.array.values[0] = tmp;
        val->u.array.values[1] = value;
        rc  = 0;
        break;

    case NWFILTER_VALUE_TYPE_ARRAY:
        if (VIR_EXPAND_N(val->u.array.values,
                         val->u.array.nValues, 1) < 0) {
            virReportOOMError();
            return -1;
        }
        val->u.array.values[val->u.array.nValues - 1] = value;
        rc = 0;
        break;

    case NWFILTER_VALUE_TYPE_LAST:
        break;
    }

    return rc;
}

static int
virNWFilterVarValueDelNthValue(virNWFilterVarValuePtr val, unsigned int pos)
{
    switch (val->valType) {
    case NWFILTER_VALUE_TYPE_SIMPLE:
        return -1;

    case NWFILTER_VALUE_TYPE_ARRAY:
        if (pos < val->u.array.nValues) {
            VIR_FREE(val->u.array.values[pos]);
            val->u.array.nValues--;

            if (pos < val->u.array.nValues)
                memmove(&val->u.array.values[pos],
                        &val->u.array.values[pos + 1],
                        sizeof(val->u.array.values[0]) *
                            (val->u.array.nValues - pos));
            return 0;
        }
        break;

    case NWFILTER_VALUE_TYPE_LAST:
        break;
    }

    return -1;
}

int
virNWFilterVarValueDelValue(virNWFilterVarValuePtr val, const char *value)
{
    unsigned int i;

    switch (val->valType) {
    case NWFILTER_VALUE_TYPE_SIMPLE:
        return -1;

    case NWFILTER_VALUE_TYPE_ARRAY:
        for (i = 0; i < val->u.array.nValues; i++)
            if (STREQ(value, val->u.array.values[i]))
                return virNWFilterVarValueDelNthValue(val, i);
        break;

    case NWFILTER_VALUE_TYPE_LAST:
        break;
    }

    return -1;
}

void
virNWFilterVarCombIterFree(virNWFilterVarCombIterPtr ci)
{
    unsigned int i;

    if (!ci)
        return;

    for (i = 0; i < ci->nIter; i++)
        VIR_FREE(ci->iter[i].varNames);

    VIR_FREE(ci);
}

static int
virNWFilterVarCombIterGetIndexByIterId(virNWFilterVarCombIterPtr ci,
                                       unsigned int iterId)
{
    unsigned int i;

    for (i = 0; i < ci->nIter; i++)
        if (ci->iter[i].iterId == iterId)
            return i;

    return -1;
}

static void
virNWFilterVarCombIterEntryInit(virNWFilterVarCombIterEntryPtr cie,
                                unsigned int iterId)
{
    memset(cie, 0, sizeof(*cie));
    cie->iterId = iterId;
}

static int
virNWFilterVarCombIterAddVariable(virNWFilterVarCombIterEntryPtr cie,
                                  virNWFilterHashTablePtr hash,
                                  const char *varName)
{
    virNWFilterVarValuePtr varValue;
    unsigned int cardinality;

    varValue = virHashLookup(hash->hashTable, varName);
    if (varValue == NULL) {
        virNWFilterReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Could not find value for variable '%s'"),
                               varName);
        return -1;
    }

    cardinality = virNWFilterVarValueGetCardinality(varValue);

    if (cie->nVarNames == 0) {
        cie->maxValue = cardinality - 1;
    } else {
        if (cie->maxValue != cardinality - 1) {
            virNWFilterReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("Cardinality of list items must be "
                                     "the same for processing them in "
                                     "parallel"));
            return -1;
        }
    }

    if (VIR_EXPAND_N(cie->varNames, cie->nVarNames, 1) < 0) {
        virReportOOMError();
        return -1;
    }

    cie->varNames[cie->nVarNames - 1] = varName;

    return 0;
}

/*
 * Create an iterator over the contents of the given variables. All variables
 * must have entries in the hash table.
 * The iterator that is created processes all given variables in parallel,
 * meaning it will access $ITEM1[0] and $ITEM2[0] then $ITEM1[1] and $ITEM2[1]
 * up to $ITEM1[n] and $ITEM2[n]. For this to work, the cardinality of all
 * processed lists must be the same.
 * The notation $ITEM1 and $ITEM2 (in one rule) therefore will always have to
 * process the items in parallel. This will be an implicit notation for
 * $ITEM1[@0] and $ITEM2[@0] to 'lock' the two together. Future notations of
 * $ITEM1[@1] and $ITEM2[@2] will make them be processed independently,
 * which then would cause all combinations of the items of the two lists to
 * be created.
 */
virNWFilterVarCombIterPtr
virNWFilterVarCombIterCreate(virNWFilterHashTablePtr hash,
                             char * const *vars, unsigned int nVars)
{
    virNWFilterVarCombIterPtr res;
    unsigned int i, iterId;
    int iterIndex;

    if (VIR_ALLOC_VAR(res, virNWFilterVarCombIterEntry, 1) < 0) {
        virReportOOMError();
        return NULL;
    }

    res->hashTable = hash;

    /* create the default iterator to support @0 */
    iterId = 0;

    res->nIter = 1;
    virNWFilterVarCombIterEntryInit(&res->iter[0], iterId);

    for (i = 0; i < nVars; i++) {

        /* currently always access @0 */
        iterId = 0;

        iterIndex = virNWFilterVarCombIterGetIndexByIterId(res, iterId);
        if (iterIndex < 0) {
            /* future: create new iterator. for now it's a bug */
            virNWFilterReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("Could not find iterator with id %u"),
                                   iterId);
            goto err_exit;
        }

        if (virNWFilterVarCombIterAddVariable(&res->iter[iterIndex],
                                              hash, vars[i]) < 0)
            goto err_exit;
    }

    return res;

err_exit:
    virNWFilterVarCombIterFree(res);
    return NULL;
}

virNWFilterVarCombIterPtr
virNWFilterVarCombIterNext(virNWFilterVarCombIterPtr ci)
{
    unsigned int i;

    for (i = 0; i < ci->nIter; i++) {
        ci->iter[i].curValue++;
        if (ci->iter[i].curValue <= ci->iter[i].maxValue)
            break;
        else
            ci->iter[i].curValue = 0;
    }

    if (ci->nIter == i) {
        virNWFilterVarCombIterFree(ci);
        return NULL;
    }

    return ci;
}

const char *
virNWFilterVarCombIterGetVarValue(virNWFilterVarCombIterPtr ci,
                                  const char *varName)
{
    unsigned int i;
    bool found = false;
    const char *res = NULL;
    virNWFilterVarValuePtr value;
    unsigned int iterIndex;

    /* currently always accessing iter @0 */
    iterIndex = 0;

    for (i = 0; i < ci->iter[iterIndex].nVarNames; i++) {
        if (STREQ(ci->iter[iterIndex].varNames[i], varName)) {
            found = true;
            break;
        }
    }

    if (!found) {
        virNWFilterReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Could not find variable '%s' in iterator"),
                               varName);
        return NULL;
    }

    value = virHashLookup(ci->hashTable->hashTable, varName);
    if (!value) {
        virNWFilterReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Could not find value for variable '%s'"),
                               varName);
        return NULL;
    }

    res = virNWFilterVarValueGetNthValue(value, ci->iter[iterIndex].curValue);
    if (!res) {
        virNWFilterReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Could not get nth (%u) value of "
                               "variable '%s'"),
                               ci->iter[iterIndex].curValue, varName);
        return NULL;
    }

    return res;
}

static void
hashDataFree(void *payload, const void *name ATTRIBUTE_UNUSED)
{
    virNWFilterVarValueFree(payload);
}


/**
 * virNWFilterHashTablePut:
 * @table: Pointer to a virNWFilterHashTable
 * @name: name of the key to enter
 * @val: The value associated with the key
 * @freeName: Whether the name must be freed on table destruction
 *
 * Returns 0 on success, 1 on failure.
 *
 * Put an entry into the hashmap replacing and freeing an existing entry
 * if one existed.
 */
int
virNWFilterHashTablePut(virNWFilterHashTablePtr table,
                        const char *name,
                        virNWFilterVarValuePtr val,
                        int copyName)
{
    if (!virHashLookup(table->hashTable, name)) {
        if (copyName) {
            name = strdup(name);
            if (!name)
                return 1;

            if (VIR_REALLOC_N(table->names, table->nNames + 1) < 0) {
                VIR_FREE(name);
                return 1;
            }
            table->names[table->nNames++] = (char *)name;
        }

        if (virHashAddEntry(table->hashTable, name, val) != 0) {
            if (copyName) {
                VIR_FREE(name);
                table->nNames--;
            }
            return 1;
        }
    } else {
        if (virHashUpdateEntry(table->hashTable, name, val) != 0) {
            return 1;
        }
    }
    return 0;
}


/**
 * virNWFilterHashTableFree:
 * @table: Pointer to virNWFilterHashTable
 *
 * Free a hashtable de-allocating memory for all its entries.
 *
 * All hash tables within the NWFilter driver must use this
 * function to deallocate and free their content.
 */
void
virNWFilterHashTableFree(virNWFilterHashTablePtr table)
{
    int i;
    if (!table)
        return;
    virHashFree(table->hashTable);

    for (i = 0; i < table->nNames; i++)
        VIR_FREE(table->names[i]);
    VIR_FREE(table->names);
    VIR_FREE(table);
}


virNWFilterHashTablePtr
virNWFilterHashTableCreate(int n) {
    virNWFilterHashTablePtr ret;

    if (VIR_ALLOC(ret) < 0) {
        virReportOOMError();
        return NULL;
    }
    ret->hashTable = virHashCreate(n, hashDataFree);
    if (!ret->hashTable) {
        VIR_FREE(ret);
        return NULL;
    }
    return ret;
}


void *
virNWFilterHashTableRemoveEntry(virNWFilterHashTablePtr ht,
                                const char *entry)
{
    int i;
    void *value = virHashSteal(ht->hashTable, entry);

    if (value) {
        for (i = 0; i < ht->nNames; i++) {
            if (STREQ(ht->names[i], entry)) {
                VIR_FREE(ht->names[i]);
                ht->names[i] = ht->names[--ht->nNames];
                ht->names[ht->nNames] = NULL;
                break;
            }
        }
    }
    return value;
}


struct addToTableStruct {
    virNWFilterHashTablePtr target;
    int errOccurred;
};


static void
addToTable(void *payload, const void *name, void *data)
{
    struct addToTableStruct *atts = (struct addToTableStruct *)data;
    virNWFilterVarValuePtr val;

    if (atts->errOccurred)
        return;

    val = virNWFilterVarValueCopy((virNWFilterVarValuePtr)payload);
    if (!val) {
        virReportOOMError();
        atts->errOccurred = 1;
        return;
    }

    if (virNWFilterHashTablePut(atts->target, (const char *)name, val, 1) != 0) {
        virNWFilterReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Could not put variable '%s' into hashmap"),
                               (const char *)name);
        atts->errOccurred = 1;
        virNWFilterVarValueFree(val);
    }
}


int
virNWFilterHashTablePutAll(virNWFilterHashTablePtr src,
                           virNWFilterHashTablePtr dest)
{
    struct addToTableStruct atts = {
        .target = dest,
        .errOccurred = 0,
    };

    virHashForEach(src->hashTable, addToTable, &atts);
    if (atts.errOccurred)
        goto err_exit;

    return 0;

err_exit:
    return 1;
}


static bool
isValidVarName(const char *var)
{
    return var[strspn(var, VALID_VARNAME)] == 0;
}


static bool
isValidVarValue(const char *value)
{
    return (value[strspn(value, VALID_VARVALUE)] == 0) && (strlen(value) != 0);
}

static virNWFilterVarValuePtr
virNWFilterParseVarValue(const char *val)
{
    return virNWFilterVarValueCreateSimpleCopyValue(val);
}

virNWFilterHashTablePtr
virNWFilterParseParamAttributes(xmlNodePtr cur)
{
    char *nam, *val;
    virNWFilterVarValuePtr value;

    virNWFilterHashTablePtr table = virNWFilterHashTableCreate(0);
    if (!table) {
        virReportOOMError();
        return NULL;
    }

    cur = cur->children;

    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE) {
            if (xmlStrEqual(cur->name, BAD_CAST "parameter")) {
                nam = virXMLPropString(cur, "name");
                val = virXMLPropString(cur, "value");
                value = NULL;
                if (nam != NULL && val != NULL) {
                    if (!isValidVarName(nam))
                        goto skip_entry;
                    if (!isValidVarValue(val))
                        goto skip_entry;
                    value = virHashLookup(table->hashTable, nam);
                    if (value) {
                        /* add value to existing value -> list */
                        if (virNWFilterVarValueAddValue(value, val) < 0) {
                            value = NULL;
                            goto err_exit;
                        }
                        val = NULL;
                    } else {
                        value = virNWFilterParseVarValue(val);
                        if (!value)
                            goto skip_entry;
                        if (virNWFilterHashTablePut(table, nam, value, 1))
                            goto err_exit;
                    }
                    value = NULL;
                }
skip_entry:
                virNWFilterVarValueFree(value);
                VIR_FREE(nam);
                VIR_FREE(val);
            }
        }
        cur = cur->next;
    }
    return table;

err_exit:
    VIR_FREE(nam);
    VIR_FREE(val);
    virNWFilterVarValueFree(value);
    virNWFilterHashTableFree(table);
    return NULL;
}


static int
virNWFilterFormatParameterNameSorter(const virHashKeyValuePairPtr a,
                                     const virHashKeyValuePairPtr b)
{
    return strcmp((const char *)a->key, (const char *)b->key);
}

int
virNWFilterFormatParamAttributes(virBufferPtr buf,
                                 virNWFilterHashTablePtr table,
                                 const char *filterref)
{
    virHashKeyValuePairPtr items;
    int i, j, card, numKeys;

    numKeys = virHashSize(table->hashTable);

    if (numKeys < 0) {
        virNWFilterReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("missing filter parameter table"));
        return -1;
    }

    items = virHashGetItems(table->hashTable,
                            virNWFilterFormatParameterNameSorter);
    if (!items)
        return -1;

    virBufferAsprintf(buf, "<filterref filter='%s'", filterref);
    if (numKeys) {
        virBufferAddLit(buf, ">\n");
        for (i = 0; i < numKeys; i++) {
            const virNWFilterVarValuePtr value =
                (const virNWFilterVarValuePtr)items[i].value;

            card = virNWFilterVarValueGetCardinality(value);

            for (j = 0; j < card; j++)
                virBufferAsprintf(buf,
                                  "  <parameter name='%s' value='%s'/>\n",
                                  (const char *)items[i].key,
                                  virNWFilterVarValueGetNthValue(value, j));

        }
        virBufferAddLit(buf, "</filterref>\n");
    } else {
        virBufferAddLit(buf, "/>\n");
    }

    VIR_FREE(items);

    return 0;
}
