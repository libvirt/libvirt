/* Test of poll() function.
   Copyright (C) 2008 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.  */

/* Written by Paolo Bonzini.  */

#include <config.h>

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/ioctl.h>
#include <errno.h>
#include "sockets.h"

#if (defined _WIN32 || defined __WIN32__) && ! defined __CYGWIN__
# define WIN32_NATIVE
#endif

#ifdef WIN32_NATIVE
#include <io.h>
#define pipe(x) _pipe(x, 256, O_BINARY)
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#ifndef SO_REUSEPORT
#define SO_REUSEPORT    SO_REUSEADDR
#endif

#define TEST_PORT	12345


/* Minimal testing infrastructure.  */

static int failures;

static void
failed (const char *reason)
{
  if (++failures > 1)
    printf ("  ");
  printf ("failed (%s)\n", reason);
}

static int
test (void (*fn) (void), const char *msg)
{
  failures = 0;
  printf ("%s... ", msg);
  fflush (stdout);
  fn ();

  if (!failures)
    printf ("passed\n");

  return failures;
}


/* Funny socket code.  */

static int
open_server_socket ()
{
  int s, x;
  struct sockaddr_in ia;

  s = socket (AF_INET, SOCK_STREAM, 0);

  memset (&ia, 0, sizeof (ia));
  ia.sin_family = AF_INET;
  inet_pton (AF_INET, "127.0.0.1", &ia.sin_addr);
  ia.sin_port = htons (TEST_PORT);
  if (bind (s, (struct sockaddr *) &ia, sizeof (ia)) < 0)
    {
      perror ("bind");
      exit (77);
    }

  x = 1;
  setsockopt (s, SOL_SOCKET, SO_REUSEPORT, &x, sizeof (x));

  if (listen (s, 1) < 0)
    {
      perror ("listen");
      exit (77);
    }

  return s;
}

static int
connect_to_socket (int blocking)
{
  int s;
  struct sockaddr_in ia;

  s = socket (AF_INET, SOCK_STREAM, 0);

  memset (&ia, 0, sizeof (ia));
  ia.sin_family = AF_INET;
  inet_pton (AF_INET, "127.0.0.1", &ia.sin_addr);
  ia.sin_port = htons (TEST_PORT);

  if (!blocking)
    {
#ifdef WIN32_NATIVE
      unsigned long iMode = 1;
      ioctl (s, FIONBIO, (char *) &iMode);

#elif defined F_GETFL
      int oldflags = fcntl (s, F_GETFL, NULL);

      if (!(oldflags & O_NONBLOCK))
        fcntl (s, F_SETFL, oldflags | O_NONBLOCK);
#endif
    }

  if (connect (s, (struct sockaddr *) &ia, sizeof (ia)) < 0
      && (blocking || errno != EINPROGRESS))
    {
      perror ("connect");
      exit (77);
    }

  return s;
}


/* A slightly more convenient interface to poll(2).  */

static int
poll1 (int fd, int ev, int time)
{
  struct pollfd pfd;
  int r;

  pfd.fd = fd;
  pfd.events = ev;
  pfd.revents = 0;
  r = poll (&pfd, 1, time);
  if (r < 0)
    return r;

  if (pfd.revents & ~(POLLHUP | POLLERR | POLLNVAL | ev))
    failed ("invalid flag combination (unrequested events)");

  return pfd.revents;
}

static int
poll1_nowait (int fd, int ev)
{
  return poll1 (fd, ev, 0);
}

static int
poll1_wait (int fd, int ev)
{
  return poll1 (fd, ev, -1);
}


/* Test poll(2) for TTYs.  */

#ifdef INTERACTIVE
static void
test_tty (void)
{
  if (poll1_nowait (0, POLLIN | POLLRDNORM) != 0)
    failed ("can read");
  if (poll1_nowait (0, POLLOUT) == 0)
    failed ("cannot write");

  if (poll1_wait (0, POLLIN | POLLRDNORM) == 0)
    failed ("return with infinite timeout");

  getchar ();
  if (poll1_nowait (0, POLLIN | POLLRDNORM) != 0)
    failed ("can read after getc");
}
#endif


/* Test poll(2) for unconnected nonblocking sockets.  */

static void
test_connect_first (void)
{
  int s = open_server_socket ();
  struct sockaddr_in ia;
  socklen_t addrlen;

  int c1, c2;

  if (poll1_nowait (s, POLLIN | POLLRDNORM | POLLRDBAND) != 0)
    failed ("can read, socket not connected");

  c1 = connect_to_socket (false);

  if (poll1_wait (s, POLLIN | POLLRDNORM | POLLRDBAND) != (POLLIN | POLLRDNORM))
    failed ("expecting POLLIN | POLLRDNORM on passive socket");
  if (poll1_nowait (s, POLLIN | POLLRDBAND) != POLLIN)
    failed ("expecting POLLIN on passive socket");
  if (poll1_nowait (s, POLLRDNORM | POLLRDBAND) != POLLRDNORM)
    failed ("expecting POLLRDNORM on passive socket");

  addrlen = sizeof (ia);
  c2 = accept (s, (struct sockaddr *) &ia, &addrlen);
  close (s);
  close (c1);
  close (c2);
}


/* Test poll(2) for unconnected blocking sockets.  */

static void
test_accept_first (void)
{
#ifndef WIN32_NATIVE
  int s = open_server_socket ();
  struct sockaddr_in ia;
  socklen_t addrlen;
  char buf[3];
  int c, pid;

  pid = fork ();
  if (pid < 0)
    return;

  if (pid == 0)
    {
      addrlen = sizeof (ia);
      c = accept (s, (struct sockaddr *) &ia, &addrlen);
      close (s);
      write (c, "foo", 3);
      read (c, buf, 3);
      shutdown (c, SHUT_RD);
      close (c);
      exit (0);
    }
  else
    {
      close (s);
      c = connect_to_socket (true);
      if (poll1_nowait (c, POLLOUT | POLLWRNORM | POLLRDBAND)
	  != (POLLOUT | POLLWRNORM))
        failed ("cannot write after blocking connect");
      write (c, "foo", 3);
      wait (&pid);
      if (poll1_wait (c, POLLIN) != POLLIN)
        failed ("cannot read data left in the socket by closed process");
      read (c, buf, 3);
      write (c, "foo", 3);
      if ((poll1_wait (c, POLLIN | POLLOUT) & (POLLHUP | POLLERR)) == 0)
        failed ("expecting POLLHUP after shutdown");
      close (c);
    }
#endif
}


/* Common code for pipes and connected sockets.  */

static void
test_pair (int rd, int wd)
{
  char buf[3];
  if (poll1_wait (wd, POLLIN | POLLRDNORM | POLLOUT | POLLWRNORM | POLLRDBAND)
      != (POLLOUT | POLLWRNORM))
    failed ("expecting POLLOUT | POLLWRNORM before writing");
  if (poll1_nowait (wd, POLLIN | POLLRDNORM | POLLOUT | POLLRDBAND) != POLLOUT)
    failed ("expecting POLLOUT before writing");
  if (poll1_nowait (wd, POLLIN | POLLRDNORM | POLLWRNORM | POLLRDBAND)
      != POLLWRNORM)
    failed ("expecting POLLWRNORM before writing");

  write (wd, "foo", 3);
  if (poll1_wait (rd, POLLIN | POLLRDNORM) != (POLLIN | POLLRDNORM))
    failed ("expecting POLLIN | POLLRDNORM after writing");
  if (poll1_nowait (rd, POLLIN) != POLLIN)
    failed ("expecting POLLIN after writing");
  if (poll1_nowait (rd, POLLRDNORM) != POLLRDNORM)
    failed ("expecting POLLRDNORM after writing");

  read (rd, buf, 3);
}


/* Test poll(2) on connected sockets.  */

static void
test_socket_pair (void)
{
  struct sockaddr_in ia;

  socklen_t addrlen = sizeof (ia);
  int s = open_server_socket ();
  int c1 = connect_to_socket (false);
  int c2 = accept (s, (struct sockaddr *) &ia, &addrlen);

  close (s);

  test_pair (c1, c2);
  close (c1);
  write (c2, "foo", 3);
  if ((poll1_nowait (c2, POLLIN | POLLOUT) & (POLLHUP | POLLERR)) == 0)
    failed ("expecting POLLHUP after shutdown");

  close (c2);
}


/* Test poll(2) on pipes.  */

static void
test_pipe (void)
{
  int fd[2];

  pipe (fd);
  test_pair (fd[0], fd[1]);
  close (fd[0]);
  if ((poll1_wait (fd[1], POLLIN | POLLOUT) & (POLLHUP | POLLERR)) == 0)
    failed ("expecting POLLHUP after shutdown");

  close (fd[1]);
}


/* Do them all.  */

int
main ()
{
  int result;

  gl_sockets_startup (SOCKETS_1_1);

#ifdef INTERACTIVE
  printf ("Please press Enter\n");
  test (test_tty, "TTY");
#endif

  result = test (test_connect_first, "Unconnected socket test");
  result += test (test_socket_pair, "Connected sockets test");
  result += test (test_accept_first, "General socket test with fork");
  result += test (test_pipe, "Pipe test");

  exit (result);
}
