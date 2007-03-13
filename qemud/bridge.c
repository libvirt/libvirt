/*
 * Copyright (C) 2007 Red Hat, Inc.
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
 * Authors:
 *     Mark McLoughlin <markmc@redhat.com>
 */

#include <config.h>

#include "bridge.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <linux/param.h>     /* HZ                 */
#include <linux/sockios.h>   /* SIOCBRADDBR etc.   */
#include <linux/if_bridge.h> /* SYSFS_BRIDGE_ATTR  */
#include <linux/if_tun.h>    /* IFF_TUN, IFF_NO_PI */

#include "internal.h"

#define MAX_BRIDGE_ID 256

#define JIFFIES_TO_MS(j) (((j)*1000)/HZ)
#define MS_TO_JIFFIES(ms) (((ms)*HZ)/1000)

struct _brControl {
    int fd;
};

int
brInit(brControl **ctlp)
{
    int fd;
    int flags;

    if (!ctlp || *ctlp)
        return EINVAL;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return errno;

    if ((flags = fcntl(fd, F_GETFD)) < 0 ||
        fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0) {
        int err = errno;
        close(fd);
        return err;
    }

    *ctlp = (brControl *)malloc(sizeof(struct _brControl));
    if (!*ctlp)
        return ENOMEM;

    (*ctlp)->fd = fd;

    return 0;
}

void
brShutdown(brControl *ctl)
{
    if (!ctl)
        return;

    close(ctl->fd);
    ctl->fd = 0;

    free(ctl);
}

int
brAddBridge(brControl *ctl,
            const char *nameOrFmt,
            char *name,
            int maxlen)
{
    int id, subst;

    if (!ctl || !ctl->fd || !nameOrFmt || !name)
        return EINVAL;

    if (maxlen >= BR_IFNAME_MAXLEN)
        maxlen = BR_IFNAME_MAXLEN;

    subst = id = 0;

    if (strstr(nameOrFmt, "%d"))
        subst = 1;

    do {
        char try[BR_IFNAME_MAXLEN];
        int len;

        if (subst) {
            len = snprintf(try, maxlen, nameOrFmt, id);
            if (len >= maxlen)
                return EADDRINUSE;
        } else {
            len = strlen(nameOrFmt);
            if (len >= maxlen - 1)
                return EINVAL;

            strncpy(try, nameOrFmt, len);
            try[len] = '\0';
        }

        if (ioctl(ctl->fd, SIOCBRADDBR, try) == 0) {
            strncpy(name, try, maxlen);
            return 0;
        }

        id++;
    } while (subst && id <= MAX_BRIDGE_ID);

    return errno;
}

int
brDeleteBridge(brControl *ctl,
               const char *name)
{
    if (!ctl || !ctl->fd || !name)
        return EINVAL;

    return ioctl(ctl->fd, SIOCBRDELBR, name) == 0 ? 0 : errno;
}

static int
brAddDelInterface(brControl *ctl,
                  int cmd,
                  const char *bridge,
                  const char *iface)
{
    struct ifreq ifr;
    int len;

    if (!ctl || !ctl->fd || !bridge || !iface)
        return EINVAL;

    if ((len = strlen(bridge)) >= BR_IFNAME_MAXLEN)
        return EINVAL;

    memset(&ifr, 0, sizeof(struct ifreq));

    strncpy(ifr.ifr_name, bridge, len);
    ifr.ifr_name[len] = '\0';

    if (!(ifr.ifr_ifindex = if_nametoindex(iface)))
        return ENODEV;

    return ioctl(ctl->fd, cmd, &ifr) == 0 ? 0 : errno;
}

int
brAddInterface(brControl *ctl,
               const char *bridge,
               const char *iface)
{
    return brAddDelInterface(ctl, SIOCBRADDIF, bridge, iface);
}

int
brDeleteInterface(brControl *ctl,
                  const char *bridge,
                  const char *iface)
{
    return brAddDelInterface(ctl, SIOCBRDELIF, bridge, iface);
}


int
brAddTap(brControl *ctl,
         const char *bridge,
         char *ifname,
         int maxlen,
         int *tapfd)
{
    int id, subst, fd;

    if (!ctl || !ctl->fd || !bridge || !ifname || !tapfd)
        return EINVAL;

    subst = id = 0;

    if (strstr(ifname, "%d"))
        subst = 1;

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0)
      return errno;

    do {
        struct ifreq try;
        int len;

        memset(&try, 0, sizeof(struct ifreq));

        try.ifr_flags = IFF_TAP|IFF_NO_PI;

        if (subst) {
            len = snprintf(try.ifr_name, maxlen, ifname, id);
            if (len >= maxlen) {
                errno = EADDRINUSE;
                goto error;
            }
        } else {
            len = strlen(ifname);
            if (len >= maxlen - 1) {
                errno = EINVAL;
                goto error;
            }

            strncpy(try.ifr_name, ifname, len);
            try.ifr_name[len] = '\0';
        }

        if (ioctl(fd, TUNSETIFF, &try) == 0) {
            if ((errno = brAddInterface(ctl, bridge, try.ifr_name)))
                goto error;
            if ((errno = brSetInterfaceUp(ctl, try.ifr_name, 1)))
                goto error;
            if (ifname)
                strncpy(ifname, try.ifr_name, maxlen);
            *tapfd = fd;
            return 0;
        }

        id++;
    } while (subst && id <= MAX_BRIDGE_ID);

 error:
    close(fd);

    return errno;
}

int
brSetInterfaceUp(brControl *ctl,
                 const char *ifname,
                 int up)
{
    struct ifreq ifr;
    int len;
    int flags;

    if (!ctl || !ifname)
        return EINVAL;

    if ((len = strlen(ifname)) >= BR_IFNAME_MAXLEN)
        return EINVAL;

    memset(&ifr, 0, sizeof(struct ifreq));

    strncpy(ifr.ifr_name, ifname, len);
    ifr.ifr_name[len] = '\0';

    if (ioctl(ctl->fd, SIOCGIFFLAGS, &ifr) < 0)
        return errno;

    flags = up ? (ifr.ifr_flags | IFF_UP) : (ifr.ifr_flags & ~IFF_UP);

    if (ifr.ifr_flags != flags) {
        ifr.ifr_flags = flags;

        if (ioctl(ctl->fd, SIOCSIFFLAGS, &ifr) < 0)
            return errno;
    }

    return 0;
}

int
brGetInterfaceUp(brControl *ctl,
                 const char *ifname,
                 int *up)
{
    struct ifreq ifr;
    int len;

    if (!ctl || !ifname)
        return EINVAL;

    if ((len = strlen(ifname)) >= BR_IFNAME_MAXLEN)
        return EINVAL;

    memset(&ifr, 0, sizeof(struct ifreq));

    strncpy(ifr.ifr_name, ifname, len);
    ifr.ifr_name[len] = '\0';

    if (ioctl(ctl->fd, SIOCGIFFLAGS, &ifr) < 0)
        return errno;

    *up = (ifr.ifr_flags & IFF_UP) ? 1 : 0;

    return 0;
}

static int
brSetInetAddr(brControl *ctl,
              const char *ifname,
              int cmd,
              const char *addr)
{
    struct ifreq ifr;
    struct in_addr inaddr;
    int len, ret;

    if (!ctl || !ctl->fd || !ifname || !addr)
        return EINVAL;

    if ((len = strlen(ifname)) >= BR_IFNAME_MAXLEN)
        return EINVAL;

    memset(&ifr, 0, sizeof(struct ifreq));

    strncpy(ifr.ifr_name, ifname, len);
    ifr.ifr_name[len] = '\0';

    if ((ret = inet_pton(AF_INET, addr, &inaddr)) < 0)
        return errno;
    else if (ret == 0)
        return EINVAL;

    ((struct sockaddr_in *)&ifr.ifr_data)->sin_family = AF_INET;
    ((struct sockaddr_in *)&ifr.ifr_data)->sin_addr   = inaddr;

    if (ioctl(ctl->fd, cmd, &ifr) < 0)
        return errno;

    return 0;
}

static int
brGetInetAddr(brControl *ctl,
              const char *ifname,
              int cmd,
              char *addr,
              int maxlen)
{
    struct ifreq ifr;
    struct in_addr *inaddr;
    int len;

    if (!ctl || !ctl->fd || !ifname || !addr)
        return EINVAL;

    if ((len = strlen(ifname)) >= BR_IFNAME_MAXLEN)
        return EINVAL;

    memset(&ifr, 0, sizeof(struct ifreq));

    strncpy(ifr.ifr_name, ifname, len);
    ifr.ifr_name[len] = '\0';

    if (ioctl(ctl->fd, cmd, &ifr) < 0)
        return errno;

    if (maxlen < BR_INET_ADDR_MAXLEN || ifr.ifr_addr.sa_family != AF_INET)
        return EFAULT;

    inaddr = &((struct sockaddr_in *)&ifr.ifr_data)->sin_addr;

    if (!inet_ntop(AF_INET, inaddr, addr, maxlen))
        return errno;

    return 0;
}

int
brSetInetAddress(brControl *ctl,
                 const char *ifname,
                 const char *addr)
{
    return brSetInetAddr(ctl, ifname, SIOCSIFADDR, addr);
}

int
brGetInetAddress(brControl *ctl,
                 const char *ifname,
                 char *addr,
                 int maxlen)
{
    return brGetInetAddr(ctl, ifname, SIOCGIFADDR, addr, maxlen);
}

int
brSetInetNetmask(brControl *ctl,
                 const char *ifname,
                 const char *addr)
{
    return brSetInetAddr(ctl, ifname, SIOCSIFNETMASK, addr);
}

int
brGetInetNetmask(brControl *ctl,
                 const char *ifname,
                 char *addr,
                 int maxlen)
{
    return brGetInetAddr(ctl, ifname, SIOCGIFNETMASK, addr, maxlen);
}

#ifdef ENABLE_BRIDGE_PARAMS

#include <sysfs/libsysfs.h>

static int
brSysfsPrep(struct sysfs_class_device **dev,
            struct sysfs_attribute **attr,
            const char *bridge,
            const char *attrname)
{
    *dev = NULL;
    *attr = NULL;

    if (!(*dev = sysfs_open_class_device("net", bridge)))
        return errno;

    if (!(*attr = sysfs_get_classdev_attr(*dev, attrname))) {
        int err = errno;

        sysfs_close_class_device(*dev);
        *dev = NULL;

        return err;
    }

    return 0;
}

static int
brSysfsWriteInt(struct sysfs_attribute *attr,
                int value)
{
    char buf[32];
    int len;

    len = snprintf(buf, sizeof(buf), "%d\n", value);

    if (len > (int)sizeof(buf))
        len = sizeof(buf); /* paranoia, shouldn't happen */

    return sysfs_write_attribute(attr, buf, len) == 0 ? 0 : errno;
}

int
brSetForwardDelay(brControl *ctl,
                  const char *bridge,
                  int delay)
{
    struct sysfs_class_device *dev;
    struct sysfs_attribute *attr;
    int err = 0;

    if (!ctl || !bridge)
        return EINVAL;

    if ((err = brSysfsPrep(&dev, &attr, bridge, SYSFS_BRIDGE_ATTR "/forward_delay")))
        return err;

    err = brSysfsWriteInt(attr, MS_TO_JIFFIES(delay));

    sysfs_close_class_device(dev);

    return err;
}

int
brGetForwardDelay(brControl *ctl,
                  const char *bridge,
                  int *delayp)
{
    struct sysfs_class_device *dev;
    struct sysfs_attribute *attr;
    int err = 0;

    if (!ctl || !bridge || !delayp)
        return EINVAL;

    if ((err = brSysfsPrep(&dev, &attr, bridge, SYSFS_BRIDGE_ATTR "/forward_delay")))
        return err;

    *delayp = strtoul(attr->value, NULL, 0);

    if (errno != ERANGE) {
        *delayp = JIFFIES_TO_MS(*delayp);
    } else {
        err = errno;
    }

    sysfs_close_class_device(dev);

    return err;
}

int
brSetEnableSTP(brControl *ctl,
               const char *bridge,
               int enable)
{
    struct sysfs_class_device *dev;
    struct sysfs_attribute *attr;
    int err = 0;

    if (!ctl || !bridge)
        return EINVAL;

    if ((err = brSysfsPrep(&dev, &attr, bridge, SYSFS_BRIDGE_ATTR "/stp_state")))
        return err;

    err = brSysfsWriteInt(attr, (enable == 0) ? 0 : 1);

    sysfs_close_class_device(dev);

    return err;
}

int
brGetEnableSTP(brControl *ctl,
               const char *bridge,
               int *enablep)
{
    struct sysfs_class_device *dev;
    struct sysfs_attribute *attr;
    int err = 0;

    if (!ctl || !bridge || !enablep)
        return EINVAL;

    if ((err = brSysfsPrep(&dev, &attr, bridge, SYSFS_BRIDGE_ATTR "/stp_state")))
        return err;

    *enablep = strtoul(attr->value, NULL, 0);

    if (errno != ERANGE) {
        *enablep = (*enablep == 0) ? 0 : 1;
    } else {
        err = errno;
    }

    sysfs_close_class_device(dev);

    return err;
}

#else /* ENABLE_BRIDGE_PARAMS */

int
brSetForwardDelay(brControl *ctl ATTRIBUTE_UNUSED,
                  const char *bridge ATTRIBUTE_UNUSED,
                  int delay ATTRIBUTE_UNUSED)
{
    return 0;
}

int
brGetForwardDelay(brControl *ctl ATTRIBUTE_UNUSED,
                  const char *bridge ATTRIBUTE_UNUSED,
                  int *delay ATTRIBUTE_UNUSED)
{
    return 0;
}

int
brSetEnableSTP(brControl *ctl ATTRIBUTE_UNUSED,
               const char *bridge ATTRIBUTE_UNUSED,
               int enable ATTRIBUTE_UNUSED)
{
    return 0;
}

int
brGetEnableSTP(brControl *ctl ATTRIBUTE_UNUSED,
               const char *bridge ATTRIBUTE_UNUSED,
               int *enable ATTRIBUTE_UNUSED)
{
    return 0;
}

#endif /* ENABLE_BRIDGE_PARAMS */

/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
