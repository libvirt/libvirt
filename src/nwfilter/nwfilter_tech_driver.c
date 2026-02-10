/*
 * nwfilter_tech_driver.c: common/shared functions used in nwfilter gentech drivers
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

#include "nwfilter_tech_driver.h"
#include "nwfilter_conf.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NWFILTER

int virNWFilterRuleInstSort(const void *a, const void *b)
{
    const virNWFilterRuleInst *insta = a;
    const virNWFilterRuleInst *instb = b;
    const char *root = virNWFilterChainSuffixTypeToString(
                                     VIR_NWFILTER_CHAINSUFFIX_ROOT);
    bool root_a = STREQ(insta->chainSuffix, root);
    bool root_b = STREQ(instb->chainSuffix, root);

    /* ensure root chain commands appear before all others since
       we will need them to create the child chains */
    if (root_a) {
        if (!root_b)
            return -1; /* a before b */
    } else if (root_b) {
        return 1; /* b before a */
    }

    /* priorities are limited to range [-1000, 1000] */
    return insta->priority - instb->priority;
}


int virNWFilterRuleInstSortPtr(const void *a,
                               const void *b,
                               void *opaque G_GNUC_UNUSED)
{
    virNWFilterRuleInst * const *insta = a;
    virNWFilterRuleInst * const *instb = b;
    return virNWFilterRuleInstSort(*insta, *instb);
}

int virNWFilterPrintVar(virNWFilterVarCombIter *vars,
                        char *buf, int bufsize,
                        nwItemDesc *item,
                        bool *done)
{
    *done = false;

    if ((item->flags & NWFILTER_ENTRY_ITEM_FLAG_HAS_VAR)) {
        const char *val;

        val = virNWFilterVarCombIterGetVarValue(vars, item->varAccess);
        if (!val) {
            /* error has been reported */
            return -1;
        }

        if (virStrcpy(buf, val, bufsize) < 0) {
            const char *varName;

            varName = virNWFilterVarAccessGetVarName(item->varAccess);
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Buffer too small to print variable '%1$s' into"),
                           varName);
            return -1;
        }

        *done = true;
    }
    return 0;
}

static int
_virNWFilterPrintDataType(virNWFilterVarCombIter *vars,
                          char *buf, int bufsize,
                          nwItemDesc *item,
                          bool asHex, bool directionIn)
{
    bool done;
    g_autofree char *data = NULL;
    uint8_t ctr;
    g_auto(virBuffer) vb = VIR_BUFFER_INITIALIZER;
    g_autofree char *flags = NULL;

    if (virNWFilterPrintVar(vars, buf, bufsize, item, &done) < 0)
        return -1;

    if (done)
        return 0;

    switch (item->datatype) {
    case DATATYPE_IPADDR:
        data = virSocketAddrFormat(&item->u.ipaddr);
        if (!data)
            return -1;
        if (g_snprintf(buf, bufsize, "%s", data) >= bufsize) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("buffer too small for IP address"));
            return -1;
        }
    break;

    case DATATYPE_IPV6ADDR:
        data = virSocketAddrFormat(&item->u.ipaddr);
        if (!data)
            return -1;

        if (g_snprintf(buf, bufsize, "%s", data) >= bufsize) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("buffer too small for IPv6 address"));
            return -1;
        }
    break;

    case DATATYPE_MACADDR:
    case DATATYPE_MACMASK:
        if (bufsize < VIR_MAC_STRING_BUFLEN) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Buffer too small for MAC address"));
            return -1;
        }

        virMacAddrFormat(&item->u.macaddr, buf);
    break;

    case DATATYPE_IPV6MASK:
    case DATATYPE_IPMASK:
        if (g_snprintf(buf, bufsize, "%d",
                       item->u.u8) >= bufsize) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Buffer too small for uint8 type"));
            return -1;
        }
    break;

    case DATATYPE_UINT32:
    case DATATYPE_UINT32_HEX:
        if (g_snprintf(buf, bufsize, asHex ? "0x%x" : "%u",
                       item->u.u32) >= bufsize) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Buffer too small for uint32 type"));
            return -1;
        }
    break;

    case DATATYPE_UINT16:
    case DATATYPE_UINT16_HEX:
        if (g_snprintf(buf, bufsize, asHex ? "0x%x" : "%d",
                       item->u.u16) >= bufsize) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Buffer too small for uint16 type"));
            return -1;
        }
    break;

    case DATATYPE_UINT8:
    case DATATYPE_UINT8_HEX:
        if (g_snprintf(buf, bufsize, asHex ? "0x%x" : "%d",
                       item->u.u8) >= bufsize) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Buffer too small for uint8 type"));
            return -1;
        }
    break;

    case DATATYPE_IPSETNAME:
        if (virStrcpy(buf, item->u.ipset.setname, bufsize) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Buffer to small for ipset name"));
            return -1;
        }
    break;

    case DATATYPE_IPSETFLAGS:
        for (ctr = 0; ctr < item->u.ipset.numFlags; ctr++) {
            if (ctr != 0)
                virBufferAddLit(&vb, ",");
            if ((item->u.ipset.flags & (1 << ctr))) {
                if (directionIn)
                    virBufferAddLit(&vb, "dst");
                else
                    virBufferAddLit(&vb, "src");
            } else {
                if (directionIn)
                    virBufferAddLit(&vb, "src");
                else
                    virBufferAddLit(&vb, "dst");
            }
        }

        flags = virBufferContentAndReset(&vb);

        if (virStrcpy(buf, flags, bufsize) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Buffer too small for IPSETFLAGS type"));
            return -1;
        }
    break;

    case DATATYPE_STRING:
    case DATATYPE_STRINGCOPY:
    case DATATYPE_BOOLEAN:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Cannot print data type %1$x"), item->datatype);
        return -1;
    case DATATYPE_LAST:
    default:
        virReportEnumRangeError(virNWFilterAttrDataType, item->datatype);
        return -1;
    }

    return 0;
}

int virNWFilterPrintDataType(virNWFilterVarCombIter *vars,
                             char *buf, int bufsize,
                             nwItemDesc *item)
{
    return _virNWFilterPrintDataType(vars, buf, bufsize, item, 0, 0);
}

int virNWFilterPrintDataTypeDirection(virNWFilterVarCombIter *vars,
                                      char *buf, int bufsize,
                                      nwItemDesc *item, bool directionIn)
{
    return _virNWFilterPrintDataType(vars, buf, bufsize, item, 0, directionIn);
}

int virNWFilterPrintDataTypeAsHex(virNWFilterVarCombIter *vars,
                                  char *buf, int bufsize,
                                  nwItemDesc *item)
{
    return _virNWFilterPrintDataType(vars, buf, bufsize, item, 1, 0);
}
