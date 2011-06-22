#ifndef __VIR_NETLINK_H__
# define __VIR_NETLINK_H__

# if __linux__

#  include <netlink/msg.h>

# else

struct nl_msg;

# endif /* __linux__ */

int nlComm(struct nl_msg *nl_msg,
           unsigned char **respbuf, unsigned int *respbuflen,
           int nl_pid);

#endif /* __VIR_NETLINK_H__ */
