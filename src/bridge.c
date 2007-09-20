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
#include <paths.h>
#include <sys/wait.h>

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

/**
 * brInit:
 * @ctlp: pointer to bridge control return value
 *
 * Initialize a new bridge layer. In case of success
 * @ctlp will contain a pointer to the new bridge structure.
 *
 * Returns 0 in case of success, an error code otherwise.
 */
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
    if (!*ctlp) {
        close(fd);
        return ENOMEM;
    }

    (*ctlp)->fd = fd;

    return 0;
}

/**
 * brShutdown:
 * @ctl: pointer to a bridge control
 *
 * Shutdown the bridge layer and deallocate the associated structures
 */
void
brShutdown(brControl *ctl)
{
    if (!ctl)
        return;

    close(ctl->fd);
    ctl->fd = 0;

    free(ctl);
}

/**
 * brAddBridge:
 * @ctl: bridge control pointer
 * @nameOrFmt: the bridge name (or name template)
 * @name: pointer to @maxlen bytes to store the bridge name
 * @maxlen: size of @name array
 *
 * This function register a new bridge, @nameOrFmt can be either
 * a fixed name or a name template with '%d' for dynamic name allocation.
 * in either case the final name for the bridge will be stored in @name.
 *
 * Returns 0 in case of success or an errno code in case of failure.
 */
#ifdef SIOCBRADDBR
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
#else
int brAddBridge (brControl *ctl ATTRIBUTE_UNUSED,
                 const char *nameOrFmt ATTRIBUTE_UNUSED,
                 char *name ATTRIBUTE_UNUSED,
                 int maxlen ATTRIBUTE_UNUSED)
{
    return EINVAL;
}
#endif

/**
 * brDeleteBridge:
 * @ctl: bridge control pointer
 * @name: the bridge name
 *
 * Remove a bridge from the layer.
 *
 * Returns 0 in case of success or an errno code in case of failure.
 */
#ifdef SIOCBRDELBR
int
brDeleteBridge(brControl *ctl,
               const char *name)
{
    if (!ctl || !ctl->fd || !name)
        return EINVAL;

    return ioctl(ctl->fd, SIOCBRDELBR, name) == 0 ? 0 : errno;
}
#else
int
brDeleteBridge(brControl *ctl ATTRIBUTE_UNUSED,
               const char *name ATTRIBUTE_UNUSED)
{
    return EINVAL;
}
#endif

#if defined(SIOCBRADDIF) && defined(SIOCBRDELIF)
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
#endif

/**
 * brAddInterface:
 * @ctl: bridge control pointer
 * @bridge: the bridge name
 * @iface: the network interface name
 * 
 * Adds an interface to a bridge
 *
 * Returns 0 in case of success or an errno code in case of failure.
 */
#ifdef SIOCBRADDIF
int
brAddInterface(brControl *ctl,
               const char *bridge,
               const char *iface)
{
    return brAddDelInterface(ctl, SIOCBRADDIF, bridge, iface);
}
#else
int
brAddInterface(brControl *ctl ATTRIBUTE_UNUSED,
               const char *bridge ATTRIBUTE_UNUSED,
               const char *iface ATTRIBUTE_UNUSED)
{
    return EINVAL;
}
#endif

/**
 * brDeleteInterface:
 * @ctl: bridge control pointer
 * @bridge: the bridge name
 * @iface: the network interface name
 * 
 * Removes an interface from a bridge
 *
 * Returns 0 in case of success or an errno code in case of failure.
 */
#ifdef SIOCBRDELIF
int
brDeleteInterface(brControl *ctl,
                  const char *bridge,
                  const char *iface)
{
    return brAddDelInterface(ctl, SIOCBRDELIF, bridge, iface);
}
#else
int
brDeleteInterface(brControl *ctl ATTRIBUTE_UNUSED,
                  const char *bridge ATTRIBUTE_UNUSED,
                  const char *iface ATTRIBUTE_UNUSED)
{
    return EINVAL;
}
#endif

/**
 * brAddTap:
 * @ctl: bridge control pointer
 * @bridge: the bridge name
 * @ifname: the interface name (or name template)
 * @maxlen: size of @ifname array
 * @tapfd: file descriptor return value for the new tap device
 *
 * This function reates a new tap device on a bridge. @ifname can be either
 * a fixed name or a name template with '%d' for dynamic name allocation.
 * in either case the final name for the bridge will be stored in @ifname
 * and the associated file descriptor in @tapfd.
 *
 * Returns 0 in case of success or an errno code in case of failure.
 */
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

/**
 * brSetInterfaceUp:
 * @ctl: bridge control pointer
 * @ifname: the interface name
 * @up: 1 for up, 0 for down
 *
 * Function to control if an interface is activated (up, 1) or not (down, 0)
 *
 * Returns 0 in case of success or an errno code in case of failure.
 */
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

/**
 * brGetInterfaceUp:
 * @ctl: bridge control pointer
 * @ifname: the interface name
 * @up: where to store the status
 *
 * Function to query if an interface is activated (1) or not (0)
 *
 * Returns 0 in case of success or an errno code in case of failure.
 */
int
brGetInterfaceUp(brControl *ctl,
                 const char *ifname,
                 int *up)
{
    struct ifreq ifr;
    int len;

    if (!ctl || !ifname || !up)
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

/**
 * brSetInetAddress:
 * @ctl: bridge control pointer
 * @ifname: the interface name
 * @addr: the string representation of the IP adress
 *
 * Function to bind the interface to an IP address, it should handle
 * IPV4 and IPv6. The string for addr would be of the form
 * "ddd.ddd.ddd.ddd" assuming the common IPv4 format.
 *
 * Returns 0 in case of success or an errno code in case of failure.
 */

int
brSetInetAddress(brControl *ctl,
                 const char *ifname,
                 const char *addr)
{
    return brSetInetAddr(ctl, ifname, SIOCSIFADDR, addr);
}

/**
 * brGetInetAddress:
 * @ctl: bridge control pointer
 * @ifname: the interface name
 * @addr: the array for the string representation of the IP adress
 * @maxlen: size of @addr in bytes
 *
 * Function to get the IP address of an interface, it should handle
 * IPV4 and IPv6. The returned string for addr would be of the form
 * "ddd.ddd.ddd.ddd" assuming the common IPv4 format.
 *
 * Returns 0 in case of success or an errno code in case of failure.
 */

int
brGetInetAddress(brControl *ctl,
                 const char *ifname,
                 char *addr,
                 int maxlen)
{
    return brGetInetAddr(ctl, ifname, SIOCGIFADDR, addr, maxlen);
}

/**
 * brSetInetNetmask:
 * @ctl: bridge control pointer
 * @ifname: the interface name
 * @addr: the string representation of the netmask
 *
 * Function to set the netmask of an interface, it should handle
 * IPV4 and IPv6 forms. The string for addr would be of the form
 * "ddd.ddd.ddd.ddd" assuming the common IPv4 format.
 *
 * Returns 0 in case of success or an errno code in case of failure.
 */

int
brSetInetNetmask(brControl *ctl,
                 const char *ifname,
                 const char *addr)
{
    return brSetInetAddr(ctl, ifname, SIOCSIFNETMASK, addr);
}

/**
 * brGetInetNetmask:
 * @ctl: bridge control pointer
 * @ifname: the interface name
 * @addr: the array for the string representation of the netmask
 * @maxlen: size of @addr in bytes
 *
 * Function to get the netmask of an interface, it should handle
 * IPV4 and IPv6. The returned string for addr would be of the form
 * "ddd.ddd.ddd.ddd" assuming the common IPv4 format.
 *
 * Returns 0 in case of success or an errno code in case of failure.
 */

int
brGetInetNetmask(brControl *ctl,
                 const char *ifname,
                 char *addr,
                 int maxlen)
{
    return brGetInetAddr(ctl, ifname, SIOCGIFNETMASK, addr, maxlen);
}

static int
brctlSpawn(char * const *argv)
{
    pid_t pid, ret;
    int status;
    int null = -1;

    if ((null = open(_PATH_DEVNULL, O_RDONLY)) < 0)
        return errno;

    pid = fork();
    if (pid == -1) {
        int saved_errno = errno;
        close(null);
        return saved_errno;
    }

    if (pid == 0) { /* child */
        dup2(null, STDIN_FILENO);
        dup2(null, STDOUT_FILENO);
        dup2(null, STDERR_FILENO);
        close(null);

        execvp(argv[0], argv);

        _exit (1);
    }

    close(null);

    while ((ret = waitpid(pid, &status, 0) == -1) && errno == EINTR);
    if (ret == -1)
        return errno;

    return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : EINVAL;
}

/**
 * brSetForwardDelay:
 * @ctl: bridge control pointer
 * @bridge: the bridge name
 * @delay: delay in seconds
 *
 * Set the bridge forward delay
 *
 * Returns 0 in case of success or an errno code in case of failure.
 */
 
int
brSetForwardDelay(brControl *ctl ATTRIBUTE_UNUSED,
                  const char *bridge,
                  int delay)
{
    char **argv;
    int retval = ENOMEM;
    int n;
    char delayStr[30];

    n = 1 + /* brctl */
        1 + /* setfd */
        1 + /* brige name */
        1; /* value */

    snprintf(delayStr, sizeof(delayStr), "%d", delay);

    if (!(argv = (char **)calloc(n + 1, sizeof(char *))))
        goto error;

    n = 0;

    if (!(argv[n++] = strdup(BRCTL)))
        goto error;

    if (!(argv[n++] = strdup("setfd")))
        goto error;

    if (!(argv[n++] = strdup(bridge)))
        goto error;

    if (!(argv[n++] = strdup(delayStr)))
        goto error;

    argv[n++] = NULL;

    retval = brctlSpawn(argv);

 error:
    if (argv) {
        n = 0;
        while (argv[n])
            free(argv[n++]);
        free(argv);
    }

    return retval;
}

/**
 * brSetEnableSTP:
 * @ctl: bridge control pointer
 * @bridge: the bridge name
 * @enable: 1 to enable, 0 to disable
 *
 * Control whether the bridge participates in the spanning tree protocol,
 * in general don't disable it without good reasons.
 *
 * Returns 0 in case of success or an errno code in case of failure.
 */
int
brSetEnableSTP(brControl *ctl ATTRIBUTE_UNUSED,
               const char *bridge,
               int enable)
{
    char **argv;
    int retval = ENOMEM;
    int n;

    n = 1 + /* brctl */
        1 + /* setfd */
        1 + /* brige name */
        1;  /* value */

    if (!(argv = (char **)calloc(n + 1, sizeof(char *))))
        goto error;

    n = 0;

    if (!(argv[n++] = strdup(BRCTL)))
        goto error;

    if (!(argv[n++] = strdup("stp")))
        goto error;

    if (!(argv[n++] = strdup(bridge)))
        goto error;

    if (!(argv[n++] = strdup(enable ? "on" : "off")))
        goto error;

    argv[n++] = NULL;

    retval = brctlSpawn(argv);

 error:
    if (argv) {
        n = 0;
        while (argv[n])
            free(argv[n++]);
        free(argv);
    }

    return retval;
}

/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
