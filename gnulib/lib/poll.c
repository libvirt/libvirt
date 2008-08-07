/* Emulation for poll(2)
   Contributed by Paolo Bonzini.

   Copyright 2001, 2002, 2003, 2006, 2007, 2008 Free Software Foundation, Inc.

   This file is part of gnulib.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as published by
   the Free Software Foundation; either version 2.1, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License along
   with this program; if not, write to the Free Software Foundation,
   Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.  */

#include <config.h>

#include <sys/types.h>
#include "poll.h"
#include <errno.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <unistd.h>

#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#ifdef HAVE_SYS_FILIO_H
#include <sys/filio.h>
#endif

#include <sys/time.h>
#include <time.h>

#ifndef INFTIM
#define INFTIM (-1)
#endif

/* BeOS does not have MSG_PEEK.  */
#ifndef MSG_PEEK
#define MSG_PEEK 0
#endif

int
poll (pfd, nfd, timeout)
     struct pollfd *pfd;
     nfds_t nfd;
     int timeout;
{
  fd_set rfds, wfds, efds;
  struct timeval tv;
  struct timeval *ptv;
  int maxfd, rc;
  nfds_t i;

#ifdef _SC_OPEN_MAX
  static int sc_open_max = -1;

  if (nfd < 0
      || (nfd > sc_open_max
          && (sc_open_max != -1
	      || nfd > (sc_open_max = sysconf (_SC_OPEN_MAX)))))
    {
      errno = EINVAL;
      return -1;
    }
#else /* !_SC_OPEN_MAX */
#ifdef OPEN_MAX
  if (nfd < 0 || nfd > OPEN_MAX)
    {
      errno = EINVAL;
      return -1;
    }
#endif /* OPEN_MAX -- else, no check is needed */
#endif /* !_SC_OPEN_MAX */

  /* EFAULT is not necessary to implement, but let's do it in the
     simplest case. */
  if (!pfd)
    {
      errno = EFAULT;
      return -1;
    }

  /* convert timeout number into a timeval structure */
  if (timeout == 0)
    {
      ptv = &tv;
      ptv->tv_sec = 0;
      ptv->tv_usec = 0;
    }
  else if (timeout > 0)
    {
      ptv = &tv;
      ptv->tv_sec = timeout / 1000;
      ptv->tv_usec = (timeout % 1000) * 1000;
    }
  else if (timeout == INFTIM)
    /* wait forever */
    ptv = NULL;
  else
    {
      errno = EINVAL;
      return -1;
    }

  /* create fd sets and determine max fd */
  maxfd = -1;
  FD_ZERO (&rfds);
  FD_ZERO (&wfds);
  FD_ZERO (&efds);
  for (i = 0; i < nfd; i++)
    {
      if (pfd[i].fd < 0)
	continue;

      if (pfd[i].events & (POLLIN | POLLRDNORM))
	FD_SET (pfd[i].fd, &rfds);

      /* see select(2): "the only exceptional condition detectable
         is out-of-band data received on a socket", hence we push
         POLLWRBAND events onto wfds instead of efds. */
      if (pfd[i].events & (POLLOUT | POLLWRNORM | POLLWRBAND))
	FD_SET (pfd[i].fd, &wfds);
      if (pfd[i].events & (POLLPRI | POLLRDBAND))
	FD_SET (pfd[i].fd, &efds);
      if (pfd[i].fd >= maxfd
	  && (pfd[i].events & (POLLIN | POLLOUT | POLLPRI
			       | POLLRDNORM | POLLRDBAND
			       | POLLWRNORM | POLLWRBAND)))
	{
	  maxfd = pfd[i].fd;

	  /* Windows use a linear array of sockets (of size FD_SETSIZE). The
	     descriptor value is not used to address the array.  */
#if defined __CYGWIN__ || (!defined _WIN32 && !defined __WIN32__)
	  if (maxfd > FD_SETSIZE)
	    {
	      errno = EOVERFLOW;
	      return -1;
	    }
#endif
	}
    }

  /* examine fd sets */
  rc = select (maxfd + 1, &rfds, &wfds, &efds, ptv);
  if (rc < 0)
    return rc;

  /* establish results */
  rc = 0;
  for (i = 0; i < nfd; i++)
    if (pfd[i].fd < 0)
      pfd[i].revents = 0;
    else
      {
	int happened = 0, sought = pfd[i].events;
	if (FD_ISSET (pfd[i].fd, &rfds))
	  {
	    int r;
	    int socket_errno;

#if defined __MACH__ && defined __APPLE__
	    /* There is a bug in Mac OS X that causes it to ignore MSG_PEEK
	       for some kinds of descriptors.  Detect if this descriptor is a
	       connected socket, a server socket, or something else using a
	       0-byte recv, and use ioctl(2) to detect POLLHUP.  */
	    r = recv (pfd[i].fd, NULL, 0, MSG_PEEK);
	    socket_errno = (r < 0) ? errno : 0;
	    if (r == 0 || socket_errno == ENOTSOCK)
	      ioctl(pfd[i].fd, FIONREAD, &r);
#else
	    char data[64];
	    r = recv (pfd[i].fd, data, sizeof (data), MSG_PEEK);
	    socket_errno = (r < 0) ? errno : 0;
#endif
	    if (r == 0)
	      happened |= POLLHUP;

	    /* If the event happened on an unconnected server socket,
	       that's fine. */
	    else if (r > 0 || ( /* (r == -1) && */ socket_errno == ENOTCONN))
	      happened |= (POLLIN | POLLRDNORM) & sought;

	    /* Distinguish hung-up sockets from other errors.  */
	    else if (socket_errno == ESHUTDOWN || socket_errno == ECONNRESET
		     || socket_errno == ECONNABORTED || socket_errno == ENETRESET)
	      happened |= POLLHUP;

	    else
	      happened |= POLLERR;
	  }

	if (FD_ISSET (pfd[i].fd, &wfds))
	  happened |= (POLLOUT | POLLWRNORM | POLLWRBAND) & sought;

	if (FD_ISSET (pfd[i].fd, &efds))
	  happened |= (POLLPRI | POLLRDBAND) & sought;

	if (happened)
	  {
	    pfd[i].revents = happened;
	    rc++;
	  }
      }

  return rc;
}
