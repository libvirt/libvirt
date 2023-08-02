/*
 * virarptable.c Linux ARP table handling
 *
 * Copyright (C) 2018 Chen Hanxiao
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

#ifdef __linux__
# include <linux/rtnetlink.h>
#endif

#include "viralloc.h"
#include "virarptable.h"
#include "virerror.h"
#include "virlog.h"
#include "virnetlink.h"
#include "virsocketaddr.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.arptable");

#ifdef __linux__

# define NDA_RTA(r) \
    ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ndmsg))))


static int
parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
    memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
    VIR_WARNINGS_NO_CAST_ALIGN
    for (; RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
        VIR_WARNINGS_RESET
        if ((rta->rta_type <= max) && (!tb[rta->rta_type]))
            tb[rta->rta_type] = rta;
    }

    if (len)
        VIR_WARN("malformed netlink message: Deficit %d, rta_len=%d",
                 len, rta->rta_len);
    return 0;
}


virArpTable *
virArpTableGet(void)
{
    int num = 0;
    int msglen;
    g_autofree void *nlData = NULL;
    virArpTable *table = NULL;
    struct nlmsghdr* nh;
    struct rtattr * tb[NDA_MAX+1];

    msglen = virNetlinkGetNeighbor(&nlData, 0, 0);
    if (msglen < 0)
        return NULL;

    table = g_new0(virArpTable, 1);

    nh = (struct nlmsghdr*)nlData;

    VIR_WARNINGS_NO_CAST_ALIGN
    for (; NLMSG_OK(nh, msglen); nh = NLMSG_NEXT(nh, msglen)) {
        VIR_WARNINGS_RESET
        struct ndmsg *r = NLMSG_DATA(nh);
        int len = nh->nlmsg_len;
        void *addr;

        if ((len -= NLMSG_LENGTH(sizeof(*nh))) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("wrong nlmsg len"));
            goto cleanup;
        }

        if (r->ndm_family && (r->ndm_family != AF_INET))
            continue;

        /* catch stale and reachalbe arp entry only */
        if (r->ndm_state &&
            (!(r->ndm_state == NUD_STALE || r->ndm_state == NUD_REACHABLE)))
            continue;

        if (nh->nlmsg_type == NLMSG_DONE)
            return table;

        VIR_WARNINGS_NO_CAST_ALIGN
        parse_rtattr(tb, NDA_MAX, NDA_RTA(r),
                     nh->nlmsg_len - NLMSG_LENGTH(sizeof(*r)));
        VIR_WARNINGS_RESET

        if (tb[NDA_DST] == NULL || tb[NDA_LLADDR] == NULL)
            continue;

        if (tb[NDA_DST]) {
            g_autofree char *ipstr = NULL;
            virSocketAddr virAddr = { 0 };

            VIR_REALLOC_N(table->t, num + 1);
            table->n = num + 1;

            addr = RTA_DATA(tb[NDA_DST]);
            virAddr.len = sizeof(virAddr.data.inet4);
            virAddr.data.inet4.sin_family = AF_INET;
            virAddr.data.inet4.sin_addr = *(struct in_addr *)addr;
            ipstr = virSocketAddrFormat(&virAddr);

            table->t[num].ipaddr = g_strdup(ipstr);
        }

        if (tb[NDA_LLADDR]) {
            virMacAddr macaddr;
            char ifmac[VIR_MAC_STRING_BUFLEN];

            addr = RTA_DATA(tb[NDA_LLADDR]);
            memcpy(macaddr.addr, addr, VIR_MAC_BUFLEN);

            virMacAddrFormat(&macaddr, ifmac);

            table->t[num].mac = g_strdup(ifmac);

            num++;
        }
    }

    return table;

 cleanup:
    virArpTableFree(table);
    return NULL;
}

#else

virArpTable *
virArpTableGet(void)
{
    virReportError(VIR_ERR_NO_SUPPORT, "%s",
                   _("get arp table not implemented on this platform"));
    return NULL;
}

#endif /* __linux__ */

void
virArpTableFree(virArpTable *table)
{
    size_t i;

    if (!table)
        return;

    for (i = 0; i < table->n; i++) {
        g_free(table->t[i].ipaddr);
        g_free(table->t[i].mac);
    }
    g_free(table->t);
    g_free(table);
}
