.. role:: since

====================
LXC container driver
====================

.. contents::

The libvirt LXC driver manages "Linux Containers". At their simplest, containers
can just be thought of as a collection of processes, separated from the main
host processes via a set of resource namespaces and constrained via control
groups resource tunables. The libvirt LXC driver has no dependency on the LXC
userspace tools hosted on sourceforge.net. It directly utilizes the relevant
kernel features to build the container environment. This allows for sharing of
many libvirt technologies across both the QEMU/KVM and LXC drivers. In
particular sVirt for mandatory access control, auditing of operations,
integration with control groups and many other features.

Control groups Requirements
---------------------------

In order to control the resource usage of processes inside containers, the
libvirt LXC driver requires that certain cgroups controllers are mounted on the
host OS. The minimum required controllers are 'cpuacct', 'memory' and 'devices',
while recommended extra controllers are 'cpu', 'freezer' and 'blkio'. Libvirt
will not mount the cgroups filesystem itself, leaving this up to the init system
to take care of. Systemd will do the right thing in this respect, while for
other init systems the ``cgconfig`` init service will be required. For further
information, consult the general libvirt `cgroups
documentation <cgroups.html>`__.

Namespace requirements
----------------------

In order to separate processes inside a container from those in the primary
"host" OS environment, the libvirt LXC driver requires that certain kernel
namespaces are compiled in. Libvirt currently requires the 'mount', 'ipc',
'pid', and 'uts' namespaces to be available. If separate network interfaces are
desired, then the 'net' namespace is required. If the guest configuration
declares a `UID or GID mapping <formatdomain.html#container-boot>`__, the
'user' namespace will be enabled to apply these. **A suitably configured UID/GID
mapping is a pre-requisite to making containers secure, in the absence of sVirt
confinement.**

Default container setup
-----------------------

Command line arguments
~~~~~~~~~~~~~~~~~~~~~~

When the container "init" process is started, it will typically not be given any
command line arguments (eg the equivalent of the bootloader args visible in
``/proc/cmdline``). If any arguments are desired, then must be explicitly set in
the container XML configuration via one or more ``initarg`` elements. For
example, to run ``systemd --unit emergency.service`` would use the following XML

::

   <os>
     <type arch='x86_64'>exe</type>
     <init>/bin/systemd</init>
     <initarg>--unit</initarg>
     <initarg>emergency.service</initarg>
   </os>

Environment variables
~~~~~~~~~~~~~~~~~~~~~

When the container "init" process is started, it will be given several useful
environment variables. The following standard environment variables are mandated
by `systemd container
interface <https://www.freedesktop.org/wiki/Software/systemd/ContainerInterface>`__
to be provided by all container technologies on Linux.

``container``
   The fixed string ``libvirt-lxc`` to identify libvirt as the creator
``container_uuid``
   The UUID assigned to the container by libvirt
``PATH``
   The fixed string ``/bin:/usr/bin``
``TERM``
   The fixed string ``linux``
``HOME``
   The fixed string ``/``

In addition to the standard variables, the following libvirt specific
environment variables are also provided

``LIBVIRT_LXC_NAME``
   The name assigned to the container by libvirt
``LIBVIRT_LXC_UUID``
   The UUID assigned to the container by libvirt
``LIBVIRT_LXC_CMDLINE``
   The unparsed command line arguments specified in the container configuration.
   Use of this is discouraged, in favour of passing arguments directly to the
   container init process via the ``initarg`` config element.

Filesystem mounts
~~~~~~~~~~~~~~~~~

In the absence of any explicit configuration, the container will inherit the
host OS filesystem mounts. A number of mount points will be made read only, or
re-mounted with new instances to provide container specific data. The following
special mounts are setup by libvirt

-  ``/dev`` a new "tmpfs" pre-populated with authorized device nodes
-  ``/dev/pts`` a new private "devpts" instance for console devices
-  ``/sys`` the host "sysfs" instance remounted read-only
-  ``/proc`` a new instance of the "proc" filesystem
-  ``/proc/sys`` the host "/proc/sys" bind-mounted read-only
-  ``/sys/fs/selinux`` the host "selinux" instance remounted read-only
-  ``/sys/fs/cgroup/NNNN`` the host cgroups controllers bind-mounted to only
   expose the sub-tree associated with the container
-  ``/proc/meminfo`` a FUSE backed file reflecting memory limits of the
   container

Device nodes
~~~~~~~~~~~~

The container init process will be started with ``CAP_MKNOD`` capability removed
and blocked from re-acquiring it. As such it will not be able to create any
device nodes in ``/dev`` or anywhere else in its filesystems. Libvirt itself
will take care of pre-populating the ``/dev`` filesystem with any devices that
the container is authorized to use. The current devices that will be made
available to all containers are

-  ``/dev/zero``
-  ``/dev/null``
-  ``/dev/full``
-  ``/dev/random``
-  ``/dev/urandom``
-  ``/dev/stdin`` symlinked to ``/proc/self/fd/0``
-  ``/dev/stdout`` symlinked to ``/proc/self/fd/1``
-  ``/dev/stderr`` symlinked to ``/proc/self/fd/2``
-  ``/dev/fd`` symlinked to ``/proc/self/fd``
-  ``/dev/ptmx`` symlinked to ``/dev/pts/ptmx``
-  ``/dev/console`` symlinked to ``/dev/pts/0``

In addition, for every console defined in the guest configuration, a symlink
will be created from ``/dev/ttyN`` symlinked to the corresponding ``/dev/pts/M``
pseudo TTY device. The first console will be ``/dev/tty1``, with further
consoles numbered incrementally from there.

Since /dev/ttyN and /dev/console are linked to the pts devices. The tty device
of login program is pts device. The pam module securetty may prevent root user
from logging in container. If you want root user to log in container
successfully, add the pts device to the file /etc/securetty of container.

Further block or character devices will be made available to containers
depending on their configuration.

Security considerations
-----------------------

The libvirt LXC driver is fairly flexible in how it can be configured, and as
such does not enforce a requirement for strict security separation between a
container and the host. This allows it to be used in scenarios where only
resource control capabilities are important, and resource sharing is desired.
Applications wishing to ensure secure isolation between a container and the host
must ensure that they are writing a suitable configuration.

Network isolation
~~~~~~~~~~~~~~~~~

If the guest configuration does not list any network interfaces, the ``network``
namespace will not be activated, and thus the container will see all the host's
network interfaces. This will allow apps in the container to bind to/connect
from TCP/UDP addresses and ports from the host OS. It also allows applications
to access UNIX domain sockets associated with the host OS, which are in the
abstract namespace. If access to UNIX domains sockets in the abstract namespace
is not wanted, then applications should set the ``<privnet/>`` flag in the
``<features>....</features>`` element.

Filesystem isolation
~~~~~~~~~~~~~~~~~~~~

If the guest configuration does not list any filesystems, then the container
will be set up with a root filesystem that matches the host's root filesystem.
As noted earlier, only a few locations such as ``/dev``, ``/proc`` and ``/sys``
will be altered. This means that, in the absence of restrictions from sVirt, a
process running as user/group N:M inside the container will be able to access
almost exactly the same files as a process running as user/group N:M in the
host.

There are multiple options for restricting this. It is possible to simply map
the existing root filesystem through to the container in read-only mode.
Alternatively a completely separate root filesystem can be configured for the
guest. In both cases, further sub-mounts can be applied to customize the content
that is made visible. Note that in the absence of sVirt controls, it is still
possible for the root user in a container to unmount any sub-mounts applied. The
user namespace feature can also be used to restrict access to files based on the
UID/GID mappings.

Sharing the host filesystem tree, also allows applications to access UNIX
domains sockets associated with the host OS, which are in the filesystem
namespaces. It should be noted that a number of init systems including at least
``systemd`` and ``upstart`` have UNIX domain socket which are used to control
their operation. Thus, if the directory/filesystem holding their UNIX domain
socket is exposed to the container, it will be possible for a user in the
container to invoke operations on the init service in the same way it could if
outside the container. This also applies to other applications in the host which
use UNIX domain sockets in the filesystem, such as DBus, Libvirtd, and many
more. If this is not desired, then applications should either specify the
UID/GID mapping in the configuration to enable user namespaces and thus block
access to the UNIX domain socket based on permissions, or should ensure the
relevant directories have a bind mount to hide them. This is particularly
important for the ``/run`` or ``/var/run`` directories.

User and group isolation
~~~~~~~~~~~~~~~~~~~~~~~~

If the guest configuration does not list any ID mapping, then the user and group
IDs used inside the container will match those used outside the container. In
addition, the capabilities associated with a process in the container will infer
the same privileges they would for a process in the host. This has obvious
implications for security, since a root user inside the container will be able
to access any file owned by root that is visible to the container, and perform
more or less any privileged kernel operation. In the absence of additional
protection from sVirt, this means that the root user inside a container is
effectively as powerful as the root user in the host. There is no security
isolation of the root user.

The ID mapping facility was introduced to allow for stricter control over the
privileges of users inside the container. It allows apps to define rules such as
"user ID 0 in the container maps to user ID 1000 in the host". In addition the
privileges associated with capabilities are somewhat reduced so that they cannot
be used to escape from the container environment. A full description of user
namespaces is outside the scope of this document, however LWN has `a good
write-up on the topic <https://lwn.net/Articles/532593/>`__. From the libvirt
point of view, the key thing to remember is that defining an ID mapping for
users and groups in the container XML configuration causes libvirt to activate
the user namespace feature.

Location of configuration files
-------------------------------

The LXC driver comes with sane default values. However, during its
initialization it reads a configuration file which offers system administrator
to override some of that default. The file is located under
``/etc/libvirt/lxc.conf``

Systemd Socket Activation Integration
-------------------------------------

The libvirt LXC driver provides the ability to pass across pre-opened file
descriptors when starting LXC guests. This allows for libvirt LXC to support
systemd's `socket activation
capability <https://0pointer.de/blog/projects/socket-activated-containers.html>`__,
where an incoming client connection in the host OS will trigger the startup of a
container, which runs another copy of systemd which gets passed the server
socket, and then activates the actual service handler in the container.

Let us assume that you already have a LXC guest created, running a systemd
instance as PID 1 inside the container, which has an SSHD service configured.
The goal is to automatically activate the container when the first SSH
connection is made. The first step is to create a couple of unit files for the
host OS systemd instance. The ``/etc/systemd/system/mycontainer.service`` unit
file specifies how systemd will start the libvirt LXC container

::

   [Unit]
   Description=My little container

   [Service]
   ExecStart=/usr/bin/virsh -c lxc:///system start --pass-fds 3 mycontainer
   ExecStop=/usr/bin/virsh -c lxc:///system destroy mycontainer
   Type=oneshot
   RemainAfterExit=yes
   KillMode=none

The ``--pass-fds 3`` argument specifies that the file descriptor number 3 that
``virsh`` inherits from systemd, is to be passed into the container. Since
``virsh`` will exit immediately after starting the container, the
``RemainAfterExit`` and ``KillMode`` settings must be altered from their
defaults.

Next, the ``/etc/systemd/system/mycontainer.socket`` unit file is created to get
the host systemd to listen on port 23 for TCP connections. When this unit file
is activated by the first incoming connection, it will cause the
``mycontainer.service`` unit to be activated with the FD corresponding to the
listening TCP socket passed in as FD 3.

::

   [Unit]
   Description=The SSH socket of my little container

   [Socket]
   ListenStream=23

Port 23 was picked here so that the container doesn't conflict with the host's
SSH which is on the normal port 22. That's it in terms of host side
configuration.

Inside the container, the ``/etc/systemd/system/sshd.socket`` unit file must be
created

::

   [Unit]
   Description=SSH Socket for Per-Connection Servers

   [Socket]
   ListenStream=23
   Accept=yes

The ``ListenStream`` value listed in this unit file, must match the value used
in the host file. When systemd in the container receives the pre-opened FD from
libvirt during container startup, it looks at the ``ListenStream`` values to
figure out which FD to give to which service. The actual service to start is
defined by a correspondingly named ``/etc/systemd/system/sshd@.service``

::

   [Unit]
   Description=SSH Per-Connection Server for %I

   [Service]
   ExecStart=-/usr/sbin/sshd -i
   StandardInput=socket

Finally, make sure this SSH service is set to start on boot of the container, by
running the following command inside the container:

::

   # mkdir -p /etc/systemd/system/sockets.target.wants/
   # ln -s /etc/systemd/system/sshd.socket /etc/systemd/system/sockets.target.wants/

This example shows how to activate the container based on an incoming SSH
connection. If the container was also configured to have an httpd service, it
may be desirable to activate it upon either an httpd or a sshd connection
attempt. In this case, the ``mycontainer.socket`` file in the host would simply
list multiple socket ports. Inside the container a separate ``xxxxx.socket``
file would need to be created for each service, with a corresponding
``ListenStream`` value set.

Container security
------------------

sVirt SELinux
~~~~~~~~~~~~~

In the absence of the "user" namespace being used, containers cannot be
considered secure against exploits of the host OS. The sVirt SELinux driver
provides a way to secure containers even when the "user" namespace is not used.
The cost is that writing a policy to allow execution of arbitrary OS is not
practical. The SELinux sVirt policy is typically tailored to work with a simpler
application confinement use case, as provided by the "libvirt-sandbox" project.

Auditing
~~~~~~~~

The LXC driver is integrated with libvirt's auditing subsystem, which causes
audit messages to be logged whenever there is an operation performed against a
container which has impact on host resources. So for example, start/stop, device
hotplug will all log audit messages providing details about what action occurred
and any resources associated with it. There are the following 3 types of audit
messages

-  ``VIRT_MACHINE_ID`` - details of the SELinux process and image security
   labels assigned to the container.
-  ``VIRT_CONTROL`` - details of an action / operation performed against a
   container. There are the following types of operation

   -  ``op=start`` - a container has been started. Provides the machine name,
      uuid and PID of the ``libvirt_lxc`` controller process
   -  ``op=init`` - the init PID of the container has been started. Provides the
      machine name, uuid and PID of the ``libvirt_lxc`` controller process and
      PID of the init process (in the host PID namespace)
   -  ``op=stop`` - a container has been stopped. Provides the machine name,
      uuid

-  ``VIRT_RESOURCE`` - details of a host resource associated with a container
   action.

Device access
~~~~~~~~~~~~~

All containers are launched with the CAP_MKNOD capability cleared and removed
from the bounding set. Libvirt will ensure that the /dev filesystem is
pre-populated with all devices that a container is allowed to use. In addition,
the cgroup "device" controller is configured to block read/write/mknod from all
devices except those that a container is authorized to use.

Example configurations
----------------------

Example config version 1
~~~~~~~~~~~~~~~~~~~~~~~~

::

   <domain type='lxc'>
     <name>vm1</name>
     <memory>500000</memory>
     <os>
       <type>exe</type>
       <init>/bin/sh</init>
     </os>
     <vcpu>1</vcpu>
     <clock offset='utc'/>
     <on_poweroff>destroy</on_poweroff>
     <on_reboot>restart</on_reboot>
     <on_crash>destroy</on_crash>
     <devices>
       <emulator>/usr/libexec/libvirt_lxc</emulator>
       <interface type='network'>
         <source network='default'/>
       </interface>
       <console type='pty' />
     </devices>
   </domain>

In the <emulator> element, be sure you specify the correct path to libvirt_lxc,
if it does not live in /usr/libexec on your system.

The next example assumes there is a private root filesystem (perhaps
hand-crafted using busybox, or installed from media, debootstrap, whatever)
under /opt/vm-1-root:

::

   <domain type='lxc'>
     <name>vm1</name>
     <memory>32768</memory>
     <os>
       <type>exe</type>
       <init>/init</init>
     </os>
     <vcpu>1</vcpu>
     <clock offset='utc'/>
     <on_poweroff>destroy</on_poweroff>
     <on_reboot>restart</on_reboot>
     <on_crash>destroy</on_crash>
     <devices>
       <emulator>/usr/libexec/libvirt_lxc</emulator>
       <filesystem type='mount'>
         <source dir='/opt/vm-1-root'/>
         <target dir='/'/>
       </filesystem>
       <interface type='network'>
         <source network='default'/>
       </interface>
       <console type='pty' />
     </devices>
   </domain>

Altering the available capabilities
-----------------------------------

By default the libvirt LXC driver drops some capabilities among which CAP_MKNOD.
However :since:`since 1.2.6` libvirt can be told to keep or drop some
capabilities using a domain configuration like the following:

::

   ...
   <features>
     <capabilities policy='default'>
       <mknod state='on'/>
       <sys_chroot state='off'/>
     </capabilities>
   </features>
   ...

The capabilities children elements are named after the capabilities as defined
in ``man 7 capabilities``. An ``off`` state tells libvirt to drop the
capability, while an ``on`` state will force to keep the capability even though
this one is dropped by default.

The ``policy`` attribute can be one of ``default``, ``allow`` or ``deny``. It
defines the default rules for capabilities: either keep the default behavior
that is dropping a few selected capabilities, or keep all capabilities or drop
all capabilities. The interest of ``allow`` and ``deny`` is that they guarantee
that all capabilities will be kept (or removed) even if new ones are added
later.

The following example, drops all capabilities but CAP_MKNOD:

::

   ...
   <features>
     <capabilities policy='deny'>
       <mknod state='on'/>
     </capabilities>
   </features>
   ...

Note that allowing capabilities that are normally dropped by default can
seriously affect the security of the container and the host.

Inherit namespaces
------------------

Libvirt allows you to inherit the namespace from container/process just like lxc
tools or docker provides to share the network namespace. The following can be
used to share required namespaces. If we want to share only one then the other
namespaces can be ignored. The netns option is specific to sharenet. It can be
used in cases we want to use existing network namespace rather than creating new
network namespace for the container. In this case privnet option will be
ignored.

::

   <domain type='lxc' xmlns:lxc='http://libvirt.org/schemas/domain/lxc/1.0'>
   ...
   <lxc:namespace>
     <lxc:sharenet type='netns' value='red'/>
     <lxc:shareuts type='name' value='container1'/>
     <lxc:shareipc type='pid' value='12345'/>
   </lxc:namespace>
   </domain>

The use of namespace passthrough requires libvirt >= 1.2.19

Container usage / management
----------------------------

As with any libvirt virtualization driver, LXC containers can be managed via a
wide variety of libvirt based tools. At the lowest level the ``virsh`` command
can be used to perform many tasks, by passing the ``-c lxc:///system`` argument.
As an alternative to repeating the URI with every command, the
``LIBVIRT_DEFAULT_URI`` environment variable can be set to ``lxc:///system``.
The examples that follow outline some common operations with virsh and LXC. For
further details about usage of virsh consult its manual page.

Defining (saving) container configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``virsh define`` command takes an XML configuration document and loads it
into libvirt, saving the configuration on disk

::

   # virsh -c lxc:///system define myguest.xml

Viewing container configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``virsh dumpxml`` command can be used to view the current XML configuration
of a container. By default the XML output reflects the current state of the
container. If the container is running, it is possible to explicitly request the
persistent configuration, instead of the current live configuration using the
``--inactive`` flag

::

   # virsh -c lxc:///system dumpxml myguest

Starting containers
~~~~~~~~~~~~~~~~~~~

The ``virsh start`` command can be used to start a container from a previously
defined persistent configuration

::

   # virsh -c lxc:///system start myguest

It is also possible to start so called "transient" containers, which do not
require a persistent configuration to be saved by libvirt, using the
``virsh create`` command.

::

   # virsh -c lxc:///system create myguest.xml

Stopping containers
~~~~~~~~~~~~~~~~~~~

The ``virsh shutdown`` command can be used to request a graceful shutdown of the
container. By default this command will first attempt to send a message to the
init process via the ``/dev/initctl`` device node. If no such device node
exists, then it will send SIGTERM to PID 1 inside the container.

::

   # virsh -c lxc:///system shutdown myguest

If the container does not respond to the graceful shutdown request, it can be
forcibly stopped using the ``virsh destroy``

::

   # virsh -c lxc:///system destroy myguest

Rebooting a container
~~~~~~~~~~~~~~~~~~~~~

The ``virsh reboot`` command can be used to request a graceful shutdown of the
container. By default this command will first attempt to send a message to the
init process via the ``/dev/initctl`` device node. If no such device node
exists, then it will send SIGHUP to PID 1 inside the container.

::

   # virsh -c lxc:///system reboot myguest

Undefining (deleting) a container configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``virsh undefine`` command can be used to delete the persistent
configuration of a container. If the guest is currently running, this will turn
it into a "transient" guest.

::

   # virsh -c lxc:///system undefine myguest

Connecting to a container console
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``virsh console`` command can be used to connect to the text console
associated with a container.

::

   # virsh -c lxc:///system console myguest

If the container has been configured with multiple console devices, then the
``--devname`` argument can be used to choose the console to connect to. In LXC,
multiple consoles will be named as 'console0', 'console1', 'console2', etc.

::

   # virsh -c lxc:///system console myguest --devname console1

Running commands in a container
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``virsh lxc-enter-namespace`` command can be used to enter the namespaces
and security context of a container and then execute an arbitrary command.

::

   # virsh -c lxc:///system lxc-enter-namespace myguest -- /bin/ls -al /dev

Monitoring container utilization
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``virt-top`` command can be used to monitor the activity and resource
utilization of all containers on a host

::

   # virt-top -c lxc:///system

Converting LXC container configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``virsh domxml-from-native`` command can be used to convert most of the LXC
container configuration into a domain XML fragment

::

   # virsh -c lxc:///system domxml-from-native lxc-tools /var/lib/lxc/myguest/config

This conversion has some limitations due to the fact that the domxml-from-native
command output has to be independent of the host. Here are a few things to take
care of before converting:

-  Replace the fstab file referenced by lxc.mount by the corresponding
   lxc.mount.entry lines.
-  Replace all relative sizes of tmpfs mount entries to absolute sizes. Also
   make sure that tmpfs entries all have a size option (default is 50%).
-  Define lxc.cgroup.memory.limit_in_bytes to properly limit the memory
   available to the container. The conversion will use 64MiB as the default.
