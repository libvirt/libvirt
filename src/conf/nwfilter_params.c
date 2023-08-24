/*
 * nwfilter_params.c: parsing and data maintenance of filter parameters
 *
 * Copyright (C) 2011-2014 Red Hat, Inc.
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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#include "internal.h"

#include "viralloc.h"
#include "virerror.h"
#include "nwfilter_params.h"
#include "virlog.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NWFILTER

VIR_LOG_INIT("conf.nwfilter_params");

static bool isValidVarValue(const char *value);
static void virNWFilterVarAccessSetIntIterId(virNWFilterVarAccess *,
                                             unsigned int);
static unsigned int virNWFilterVarAccessGetIntIterId(const virNWFilterVarAccess *);

void
virNWFilterVarValueFree(virNWFilterVarValue *val)
{
    size_t i;

    if (!val)
        return;

    switch (val->valType) {
    case NWFILTER_VALUE_TYPE_SIMPLE:
        g_free(val->u.simple.value);
        break;
    case NWFILTER_VALUE_TYPE_ARRAY:
        for (i = 0; i < val->u.array.nValues; i++)
            g_free(val->u.array.values[i]);
        g_free(val->u.array.values);
        break;
    case NWFILTER_VALUE_TYPE_LAST:
        break;
    }
    g_free(val);
}

virNWFilterVarValue *
virNWFilterVarValueCopy(const virNWFilterVarValue *val)
{
    virNWFilterVarValue *res;
    size_t i;
    char *str;

    res = g_new0(virNWFilterVarValue, 1);
    res->valType = val->valType;

    switch (res->valType) {
    case NWFILTER_VALUE_TYPE_SIMPLE:
        res->u.simple.value = g_strdup(val->u.simple.value);
        break;
    case NWFILTER_VALUE_TYPE_ARRAY:
        res->u.array.values = g_new0(char *, val->u.array.nValues);
        res->u.array.nValues = val->u.array.nValues;
        for (i = 0; i < val->u.array.nValues; i++) {
            str = g_strdup(val->u.array.values[i]);
            res->u.array.values[i] = str;
        }
        break;
    case NWFILTER_VALUE_TYPE_LAST:
        break;
    }

    return res;
}

virNWFilterVarValue *
virNWFilterVarValueCreateSimple(char *value)
{
    virNWFilterVarValue *val;

    if (!isValidVarValue(value)) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Variable value contains invalid character"));
        return NULL;
    }

    val = g_new0(virNWFilterVarValue, 1);

    val->valType = NWFILTER_VALUE_TYPE_SIMPLE;
    val->u.simple.value = value;

    return val;
}

virNWFilterVarValue *
virNWFilterVarValueCreateSimpleCopyValue(const char *value)
{
    char *val;
    virNWFilterVarValue *ret;

    val = g_strdup(value);
    ret = virNWFilterVarValueCreateSimple(val);
    if (!ret)
        VIR_FREE(val);
    return ret;
}

const char *
virNWFilterVarValueGetSimple(const virNWFilterVarValue *val)
{
    if (val->valType == NWFILTER_VALUE_TYPE_SIMPLE)
        return val->u.simple.value;
    return NULL;
}

const char *
virNWFilterVarValueGetNthValue(const virNWFilterVarValue* val, unsigned int idx)
{
    const char *res = NULL;

    if (!val)
        return NULL;

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
virNWFilterVarValueGetCardinality(const virNWFilterVarValue *val)
{
    switch (val->valType) {
    case NWFILTER_VALUE_TYPE_SIMPLE:
        return 1;
    case NWFILTER_VALUE_TYPE_ARRAY:
        return val->u.array.nValues;
    case NWFILTER_VALUE_TYPE_LAST:
        return 0;
    }
    return 0;
}

bool
virNWFilterVarValueEqual(const virNWFilterVarValue *a,
                         const virNWFilterVarValue *b)
{
    unsigned int card;
    size_t i, j;
    const char *s;

    if (!a || !b)
        return false;

    card = virNWFilterVarValueGetCardinality(a);
    if (card != virNWFilterVarValueGetCardinality(b))
        return false;

    /* brute force O(n^2) comparison */
    for (i = 0; i < card; i++) {
        bool eq = false;

        s = virNWFilterVarValueGetNthValue(a, i);
        for (j = 0; j < card; j++) {
            if (STREQ_NULLABLE(s, virNWFilterVarValueGetNthValue(b, j))) {
                 eq = true;
                 break;
            }
        }
        if (!eq)
            return false;
    }
    return true;
}

int
virNWFilterVarValueAddValue(virNWFilterVarValue *val, char *value)
{
    char *tmp;
    int rc = -1;

    switch (val->valType) {
    case NWFILTER_VALUE_TYPE_SIMPLE:
        /* switch to array */
        tmp = val->u.simple.value;
        val->u.array.values = g_new0(char *, 2);
        val->valType = NWFILTER_VALUE_TYPE_ARRAY;
        val->u.array.nValues = 2;
        val->u.array.values[0] = tmp;
        val->u.array.values[1] = value;
        rc  = 0;
        break;

    case NWFILTER_VALUE_TYPE_ARRAY:
        VIR_EXPAND_N(val->u.array.values, val->u.array.nValues, 1);
        val->u.array.values[val->u.array.nValues - 1] = value;
        rc = 0;
        break;

    case NWFILTER_VALUE_TYPE_LAST:
        break;
    }

    return rc;
}


int
virNWFilterVarValueAddValueCopy(virNWFilterVarValue *val, const char *value)
{
    char *valdup;
    valdup = g_strdup(value);
    if (virNWFilterVarValueAddValue(val, valdup) < 0) {
        VIR_FREE(valdup);
        return -1;
    }
    return 0;
}


static int
virNWFilterVarValueDelNthValue(virNWFilterVarValue *val, unsigned int pos)
{
    switch (val->valType) {
    case NWFILTER_VALUE_TYPE_SIMPLE:
        return -1;

    case NWFILTER_VALUE_TYPE_ARRAY:
        if (pos < val->u.array.nValues) {
            VIR_FREE(val->u.array.values[pos]);
            VIR_DELETE_ELEMENT(val->u.array.values, pos, val->u.array.nValues);
            return 0;
        }
        break;

    case NWFILTER_VALUE_TYPE_LAST:
        break;
    }

    return -1;
}

int
virNWFilterVarValueDelValue(virNWFilterVarValue *val, const char *value)
{
    size_t i;

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
virNWFilterVarCombIterFree(virNWFilterVarCombIter *ci)
{
    size_t i;

    if (!ci)
        return;

    for (i = 0; i < ci->nIter; i++)
        g_free(ci->iter[i].varNames);

    g_free(ci->iter);

    g_free(ci);
}

static int
virNWFilterVarCombIterGetIndexByIterId(virNWFilterVarCombIter *ci,
                                       unsigned int iterId)
{
    size_t i;

    for (i = 0; i < ci->nIter; i++)
        if (ci->iter[i].iterId == iterId)
            return i;

    return -1;
}

static void
virNWFilterVarCombIterEntryInit(virNWFilterVarCombIterEntry *cie,
                                unsigned int iterId)
{
    memset(cie, 0, sizeof(*cie));
    cie->iterId = iterId;
}

static int
virNWFilterVarCombIterAddVariable(virNWFilterVarCombIterEntry *cie,
                                  GHashTable *hash,
                                  const virNWFilterVarAccess *varAccess)
{
    virNWFilterVarValue *varValue;
    unsigned int maxValue = 0, minValue = 0;
    const char *varName = virNWFilterVarAccessGetVarName(varAccess);

    varValue = virHashLookup(hash, varName);
    if (varValue == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not find value for variable '%1$s'"),
                       varName);
        return -1;
    }

    switch (virNWFilterVarAccessGetType(varAccess)) {
    case VIR_NWFILTER_VAR_ACCESS_ELEMENT:
        maxValue = virNWFilterVarAccessGetIndex(varAccess);
        minValue = maxValue;
        break;
    case VIR_NWFILTER_VAR_ACCESS_ITERATOR:
        maxValue = virNWFilterVarValueGetCardinality(varValue) - 1;
        minValue = 0;
        break;
    case VIR_NWFILTER_VAR_ACCESS_LAST:
        return -1;
    }

    if (cie->nVarNames == 0) {
        cie->maxValue = maxValue;
        cie->minValue = minValue;
        cie->curValue = minValue;
    } else {
        if (cie->maxValue != maxValue) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Cardinality of list items must be the same for processing them in parallel"));
            return -1;
        }
    }

    VIR_EXPAND_N(cie->varNames, cie->nVarNames, 1);
    cie->varNames[cie->nVarNames - 1] = varName;

    return 0;
}

/*
 * Test whether the iterator entry points to a distinguished set of entries
 * that have not been seen before at one of the previous iterations.
 *
 * The point of this function is to eliminate duplicates.
 * Example with two lists:
 *
 * list1 = [1,2,1]
 * list2 = [1,3,1]
 *
 * The 1st iteration would take the 1st items of each list -> 1,1
 * The 2nd iteration would take the 2nd items of each list -> 2,3
 * The 3rd iteration would take the 3rd items of each list -> 1,1 but
 * skip them since this pair has already been encountered in the 1st iteration
 */
static bool
virNWFilterVarCombIterEntryAreUniqueEntries(virNWFilterVarCombIterEntry *cie,
                                            GHashTable *hash)
{
    size_t i, j;
    virNWFilterVarValue *varValue;
    virNWFilterVarValue *tmp;
    const char *value;

    varValue = virHashLookup(hash, cie->varNames[0]);
    if (!varValue) {
        /* caller's error */
        VIR_ERROR(_("hash lookup resulted in NULL pointer"));
        return true;
    }

    value = virNWFilterVarValueGetNthValue(varValue, cie->curValue);
    if (!value) {
        VIR_ERROR(_("Lookup of value at index %1$u resulted in a NULL pointer"),
                  cie->curValue);
        return true;
    }

    for (i = 0; i < cie->curValue; i++) {
        if (STREQ(value, virNWFilterVarValueGetNthValue(varValue, i))) {
            bool isSame = true;
            for (j = 1; j < cie->nVarNames; j++) {
                tmp = virHashLookup(hash, cie->varNames[j]);
                if (!tmp) {
                    /* should never occur to step on a NULL here */
                    return true;
                }
                if (STRNEQ(virNWFilterVarValueGetNthValue(tmp, cie->curValue),
                           virNWFilterVarValueGetNthValue(tmp, i))) {
                    isSame = false;
                    break;
                }
            }
            if (isSame)
                return false;
        }
    }

    return true;
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
virNWFilterVarCombIter *
virNWFilterVarCombIterCreate(GHashTable *hash,
                             virNWFilterVarAccess **varAccess,
                             size_t nVarAccess)
{
    virNWFilterVarCombIter *res;
    size_t i;
    unsigned int iterId;
    int iterIndex = -1;
    unsigned int nextIntIterId = VIR_NWFILTER_MAX_ITERID + 1;

    res = g_new0(virNWFilterVarCombIter, 1);
    res->iter = g_new0(virNWFilterVarCombIterEntry, nVarAccess + 1);

    res->hashTable = hash;

    /* create the default iterator to support @0 */
    iterId = 0;

    res->nIter = 1;
    virNWFilterVarCombIterEntryInit(&res->iter[0], iterId);

    for (i = 0; i < nVarAccess; i++) {
        switch (virNWFilterVarAccessGetType(varAccess[i])) {
        case VIR_NWFILTER_VAR_ACCESS_ITERATOR:
            iterId = virNWFilterVarAccessGetIterId(varAccess[i]);
            iterIndex = virNWFilterVarCombIterGetIndexByIterId(res, iterId);
            if (iterIndex < 0) {
                iterIndex = res->nIter;
                virNWFilterVarCombIterEntryInit(&res->iter[iterIndex], iterId);
                res->nIter++;
            }
            break;
        case VIR_NWFILTER_VAR_ACCESS_ELEMENT:
            iterIndex = res->nIter;
            virNWFilterVarAccessSetIntIterId(varAccess[i], nextIntIterId);
            virNWFilterVarCombIterEntryInit(&res->iter[iterIndex],
                                            nextIntIterId);
            nextIntIterId++;
            res->nIter++;
            break;
        case VIR_NWFILTER_VAR_ACCESS_LAST:
            goto err_exit;
        }

        if (virNWFilterVarCombIterAddVariable(&res->iter[iterIndex],
                                              hash, varAccess[i]) < 0)
            goto err_exit;
    }

    return res;

 err_exit:
    virNWFilterVarCombIterFree(res);
    return NULL;
}

virNWFilterVarCombIter *
virNWFilterVarCombIterNext(virNWFilterVarCombIter *ci)
{
    size_t i;

    for (i = 0; i < ci->nIter; i++) {
 next:
        ci->iter[i].curValue++;
        if (ci->iter[i].curValue <= ci->iter[i].maxValue) {
            if (!virNWFilterVarCombIterEntryAreUniqueEntries(
                                              &ci->iter[i], ci->hashTable))
                goto next;
            break;
        } else {
            ci->iter[i].curValue = ci->iter[i].minValue;
        }
    }

    if (ci->nIter == i)
        return NULL;

    return ci;
}

const char *
virNWFilterVarCombIterGetVarValue(virNWFilterVarCombIter *ci,
                                  const virNWFilterVarAccess *vap)
{
    size_t i;
    unsigned int iterId;
    bool found = false;
    const char *res = NULL;
    virNWFilterVarValue *value;
    int iterIndex = -1;
    const char *varName = virNWFilterVarAccessGetVarName(vap);

    switch (virNWFilterVarAccessGetType(vap)) {
    case VIR_NWFILTER_VAR_ACCESS_ITERATOR:
        iterId = virNWFilterVarAccessGetIterId(vap);
        iterIndex = virNWFilterVarCombIterGetIndexByIterId(ci, iterId);
        if (iterIndex < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Could not get iterator index for iterator ID %1$u"),
                           iterId);
            return NULL;
        }
        break;
    case VIR_NWFILTER_VAR_ACCESS_ELEMENT:
        iterId = virNWFilterVarAccessGetIntIterId(vap);
        iterIndex = virNWFilterVarCombIterGetIndexByIterId(ci, iterId);
        if (iterIndex < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Could not get iterator index for (internal) iterator ID %1$u"),
                           iterId);
            return NULL;
        }
        break;
    case VIR_NWFILTER_VAR_ACCESS_LAST:
        return NULL;
    }

    for (i = 0; i < ci->iter[iterIndex].nVarNames; i++) {
        if (STREQ(ci->iter[iterIndex].varNames[i], varName)) {
            found = true;
            break;
        }
    }

    if (!found) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not find variable '%1$s' in iterator"),
                       varName);
        return NULL;
    }

    value = virHashLookup(ci->hashTable, varName);
    if (!value) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not find value for variable '%1$s'"),
                       varName);
        return NULL;
    }

    res = virNWFilterVarValueGetNthValue(value, ci->iter[iterIndex].curValue);
    if (!res) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not get nth (%1$u) value of variable '%2$s'"),
                       ci->iter[iterIndex].curValue, varName);
        return NULL;
    }

    return res;
}

void
virNWFilterVarValueHashFree(void *payload)
{
    virNWFilterVarValueFree(payload);
}


struct addToTableStruct {
    GHashTable *target;
    int errOccurred;
};


static int
addToTable(void *payload, const char *name, void *data)
{
    struct addToTableStruct *atts = (struct addToTableStruct *)data;
    virNWFilterVarValue *val;

    if (atts->errOccurred)
        return 0;

    val = virNWFilterVarValueCopy((virNWFilterVarValue *)payload);
    if (!val) {
        atts->errOccurred = 1;
        return 0;
    }

    if (virHashUpdateEntry(atts->target, (const char *)name, val) < 0) {
        atts->errOccurred = 1;
        virNWFilterVarValueFree(val);
    }

    return 0;
}


int
virNWFilterHashTablePutAll(GHashTable *src,
                           GHashTable *dest)
{
    struct addToTableStruct atts = {
        .target = dest,
        .errOccurred = 0,
    };

    virHashForEach(src, addToTable, &atts);
    if (atts.errOccurred)
        return -1;

    return 0;
}

/* The general purpose function virNWFilterVarValueEqual returns a
 * bool, but the comparison callback for virHashEqual (called below)
 * needs to return an int of 0 for == and non-0 for !=
 */
static int
virNWFilterVarValueCompare(const void *a, const void *b)
{
    return virNWFilterVarValueEqual((const virNWFilterVarValue *) a,
                                    (const virNWFilterVarValue *) b) ? 0 : 1;
}

bool
virNWFilterHashTableEqual(GHashTable *a,
                          GHashTable *b)
{
    return virHashEqual(a, b, virNWFilterVarValueCompare);
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

static virNWFilterVarValue *
virNWFilterParseVarValue(const char *val)
{
    return virNWFilterVarValueCreateSimpleCopyValue(val);
}

GHashTable *
virNWFilterParseParamAttributes(xmlNodePtr cur)
{
    g_autoptr(GHashTable) table = virHashNew(virNWFilterVarValueHashFree);

    for (cur = xmlFirstElementChild(cur); cur != NULL;
         cur = xmlNextElementSibling(cur)) {
        if (virXMLNodeNameEqual(cur, "parameter")) {
            g_autofree char *nam = virXMLPropString(cur, "name");
            g_autofree char *val = virXMLPropString(cur, "value");
            g_autoptr(virNWFilterVarValue) value = NULL;

            if (nam == NULL || !isValidVarName(nam) ||
                val == NULL || !isValidVarValue(val)) {
                continue;
            }

            if ((value = virHashLookup(table, nam))) {
                /* add value to existing value -> list */
                if (virNWFilterVarValueAddValue(g_steal_pointer(&value), val) < 0)
                    return NULL;
                val = NULL;
            } else if ((value = virNWFilterParseVarValue(val))) {
                if (virHashUpdateEntry(table, nam, value) < 0)
                    return NULL;
            }
            value = NULL;
        }
    }

    return g_steal_pointer(&table);
}


int
virNWFilterFormatParamAttributes(virBuffer *buf,
                                 GHashTable *table,
                                 const char *filterref)
{
    g_auto(virBuffer) attrBuf = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) childBuf = VIR_BUFFER_INIT_CHILD(buf);
    g_autofree virHashKeyValuePair *items = NULL;
    size_t i;
    size_t nitems;

    if (!(items = virHashGetItems(table, &nitems, true))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("missing filter parameter table"));
        return -1;
    }

    virBufferAsprintf(&attrBuf, " filter='%s'", filterref);

    for (i = 0; i < nitems; i++) {
        const virNWFilterVarValue *value = items[i].value;
        size_t npar = virNWFilterVarValueGetCardinality(value);
        size_t j;

        for (j = 0; j < npar; j++)
            virBufferAsprintf(&childBuf,
                              "<parameter name='%s' value='%s'/>\n",
                              (const char *)items[i].key,
                              virNWFilterVarValueGetNthValue(value, j));

    }

    virXMLFormatElement(buf, "filterref", &attrBuf, &childBuf);

    return 0;
}

void
virNWFilterVarAccessFree(virNWFilterVarAccess *varAccess)
{
    if (!varAccess)
        return;

    g_free(varAccess->varName);
    g_free(varAccess);
}

bool
virNWFilterVarAccessEqual(const virNWFilterVarAccess *a,
                          const virNWFilterVarAccess *b)
{
    if (a->accessType != b->accessType)
        return false;

    if (STRNEQ(a->varName, b->varName))
        return false;

    switch (a->accessType) {
    case VIR_NWFILTER_VAR_ACCESS_ELEMENT:
        return (a->u.index.idx == b->u.index.idx &&
                a->u.index.intIterId == b->u.index.intIterId);
    case VIR_NWFILTER_VAR_ACCESS_ITERATOR:
        return a->u.iterId == b->u.iterId;
    case VIR_NWFILTER_VAR_ACCESS_LAST:
        break;
    }
    return false;
}

/*
 * Parse a variable access like
 * IP, IP[@2], IP[3]
 */
virNWFilterVarAccess *
virNWFilterVarAccessParse(const char *varAccess)
{
    size_t idx, varNameLen;
    virNWFilterVarAccess *dest;
    const char *input = varAccess;

    dest = g_new0(virNWFilterVarAccess, 1);

    idx = strspn(input, VALID_VARNAME);

    if (input[idx] == '\0') {
        /* in the form 'IP', which is equivalent to IP[@0] */
        dest->varName = g_strndup(input, idx);
        dest->accessType = VIR_NWFILTER_VAR_ACCESS_ITERATOR;
        dest->u.iterId = 0;
        return dest;
    }

    if (input[idx] == '[') {
        char *end_ptr;
        unsigned int result;
        bool parseError = false;

        varNameLen = idx;

        dest->varName = g_strndup(input, varNameLen);

        input += idx + 1;
        virSkipSpaces(&input);

        if (*input == '@') {
            /* in the form 'IP[@<number>] -> iterator */
            dest->accessType = VIR_NWFILTER_VAR_ACCESS_ITERATOR;
            input++;
        } else {
            /* in the form 'IP[<number>] -> element */
            dest->accessType = VIR_NWFILTER_VAR_ACCESS_ELEMENT;
        }

        if (virStrToLong_ui(input, &end_ptr, 10, &result) < 0)
            parseError = true;
        if (!parseError) {
            input = end_ptr;
            virSkipSpaces(&input);
            if (*input != ']')
                parseError = true;
        }
        if (parseError) {
            if (dest->accessType == VIR_NWFILTER_VAR_ACCESS_ELEMENT)
                virReportError(VIR_ERR_INVALID_ARG, "%s",
                               _("Malformatted array index"));
            else
                virReportError(VIR_ERR_INVALID_ARG, "%s",
                               _("Malformatted iterator id"));
            goto err_exit;
        }

        switch (dest->accessType) {
        case VIR_NWFILTER_VAR_ACCESS_ELEMENT:
            dest->u.index.idx = result;
            dest->u.index.intIterId = ~0;
            break;
        case VIR_NWFILTER_VAR_ACCESS_ITERATOR:
            if (result > VIR_NWFILTER_MAX_ITERID) {
                virReportError(VIR_ERR_INVALID_ARG,
                               _("Iterator ID exceeds maximum ID of %1$u"),
                               VIR_NWFILTER_MAX_ITERID);
                goto err_exit;
            }
            dest->u.iterId = result;
            break;
        case VIR_NWFILTER_VAR_ACCESS_LAST:
            goto err_exit;
        }

        return dest;
    } else {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Malformatted variable"));
    }

 err_exit:
    virNWFilterVarAccessFree(dest);

    return NULL;
}

void
virNWFilterVarAccessPrint(virNWFilterVarAccess *vap, virBuffer *buf)
{
    virBufferAdd(buf, vap->varName, -1);
    switch (vap->accessType) {
    case VIR_NWFILTER_VAR_ACCESS_ELEMENT:
        virBufferAsprintf(buf, "[%u]", vap->u.index.idx);
        break;
    case VIR_NWFILTER_VAR_ACCESS_ITERATOR:
        if (vap->u.iterId != 0)
            virBufferAsprintf(buf, "[@%u]", vap->u.iterId);
        break;
    case VIR_NWFILTER_VAR_ACCESS_LAST:
        break;
    }
}

const char *
virNWFilterVarAccessGetVarName(const virNWFilterVarAccess *vap)
{
    return vap->varName;
}

virNWFilterVarAccessType
virNWFilterVarAccessGetType(const virNWFilterVarAccess *vap)
{
    return vap->accessType;
}

unsigned int
virNWFilterVarAccessGetIterId(const virNWFilterVarAccess *vap)
{
    return vap->u.iterId;
}

unsigned int
virNWFilterVarAccessGetIndex(const virNWFilterVarAccess *vap)
{
    return vap->u.index.idx;
}

static void
virNWFilterVarAccessSetIntIterId(virNWFilterVarAccess *vap,
                                 unsigned int intIterId)
{
    vap->u.index.intIterId = intIterId;
}

static unsigned int
virNWFilterVarAccessGetIntIterId(const virNWFilterVarAccess *vap)
{
    return vap->u.index.intIterId;
}

bool
virNWFilterVarAccessIsAvailable(const virNWFilterVarAccess *varAccess,
                                GHashTable *hash)
{
    const char *varName = virNWFilterVarAccessGetVarName(varAccess);
    const char *res;
    unsigned int idx;
    virNWFilterVarValue *varValue;

    varValue = virHashLookup(hash, varName);
    if (!varValue)
        return false;

    switch (virNWFilterVarAccessGetType(varAccess)) {
    case VIR_NWFILTER_VAR_ACCESS_ELEMENT:
        idx = virNWFilterVarAccessGetIndex(varAccess);
        res = virNWFilterVarValueGetNthValue(varValue, idx);
        if (res == NULL)
            return false;
        break;
    case VIR_NWFILTER_VAR_ACCESS_ITERATOR:
        break;
    case VIR_NWFILTER_VAR_ACCESS_LAST:
        return false;
    }

    return true;
}
