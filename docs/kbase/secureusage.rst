=======================
Secure Usage of Libvirt
=======================

.. contents::

This page details information that application developers and
administrators of libvirt should be aware of when working with libvirt,
that may have a bearing on security of the system.

Disk image handling
===================

Disk image format probing
-------------------------

Historically there have been multiple flaws in QEMU and most projects
using QEMU, related to handling of disk formats. The problems occur when
a guest is given a virtual disk backed by raw disk format on the host.
If the management application on the host tries to auto-detect / probe
the disk format, it is vulnerable to a malicious guest which can write a
qcow2 file header into its raw disk. If the management application
subsequently probes the disk, it will see it as a 'qcow2' disk instead
of a 'raw' disk. Since 'qcow2' disks can have a copy on write backing
file, such flaw can be leveraged to read arbitrary files on the host.
The same type of flaw may occur if the management application allows
users to upload pre-created raw images.

**Recommendation:** never attempt to automatically detect the format of
a disk image based on file contents which are accessible to / originate
from an untrusted source.

Disk image backing files
------------------------

If a management application allows users to upload pre-created disk
images in non-raw formats, it can be tricked into giving the user access
to arbitrary host files via the copy-on-write backing file feature. This
is because the qcow2 disk format header contains a filename field which
can point to any location. It can also point to network protocols such
as NBD, HTTP, GlusterFS, RBD and more. This could allow for compromise
of almost arbitrary data accessible on the LAN/WAN.

**Recommendation:** always validate that a disk image originating from
an untrusted source has no backing file set. If a backing file is seen,
reject the image.

Disk image size validation
--------------------------

If an application allows users to upload pre-created disk images in
non-raw formats, it is essential to validate the logical disk image
size, rather than the physical disk image size. Non-raw disk images have
a grow-on-demand capability, so a user can provide a qcow2 image that
may be only 1 MB in size, but is configured to grow to many TB in size.

**Recommendation:** if receiving a non-raw disk image from an untrusted
source, validate the logical image size stored in the disk image
metadata against some finite limit.

Disk image data access
----------------------

If an untrusted disk image is ever mounted on the host OS by a
management application or administrator, this opens an avenue of attack
with which to potentially compromise the host kernel. Filesystem drivers
in OS kernels are often very complex code and thus may have bugs lurking
in them. With Linux, there are a large number of filesystem drivers,
many of which attract little security analysis attention. Linux will
helpfully probe filesystem formats if not told to use an explicit
format, allowing an attacker the ability to target specific weak
filesystem drivers. Even commonly used and widely audited filesystems
such as ``ext4`` have had `bugs lurking in
them <https://lwn.net/Articles/538898/>`__ undetected for years at a
time.

**Recommendation:** if there is a need to access the content of a disk
image, use a single-use throwaway virtual machine to access the data.
Never mount disk images on the host OS. Ideally make use of the
`libguestfs <https://libguestfs.org>`__ tools and APIs for accessing
disks

Guest migration network
=======================

Most hypervisors with support for guest migration between hosts make use
of one (or more) network connections. Typically the source host will
connect to some port on the target host to initiate the migration. There
may be separate connections for co-ordinating the migration,
transferring memory state and transferring storage. If the network over
which migration takes place is accessible the guest, or client
applications, there is potential for data leakage via packet
snooping/capture. It is also possible for a malicious guest or client to
make attempts to connect to the target host to trigger bogus migration
operations, or at least inflict a denial of service attack.

**Recommendations:** there are several things to consider when
performing migration

-  Use a specific address for establishing the migration connection
   which is accessible only to the virtualization hosts themselves, not
   libvirt clients or virtual guests. Most hypervisors allow the
   management application to provide the IP address of the target host
   as a way to determine which network migration takes place on. This is
   effectively the connect() socket address for the source host.
-  Use a specific address for listening for incoming migration
   connections which is accessible only to the virtualization hosts
   themselves, not libvirt clients or virtual guests. Most hypervisors
   allow the management application to configure the IP address on which
   the target host listens. This is the bind() socket address for the
   target host.
-  Use an encrypted migration protocol. Some hypervisors have support
   for encrypting the migration memory/storage data. In other cases it
   can be tunnelled over the libvirtd RPC protocol connections.

Storage encryption
==================

Virtual disk images will typically contain confidential data belonging
to the owner of the virtual machine. It is desirable to protect this
against data center administrators as much as possible. For example, a
rogue storage administrator may attempt to access disk contents directly
from a storage host, or a network administrator/attack may attempt to
snoop on data packets relating to storage access. Use of disk encryption
on the virtualization host can ensure that only the virtualization host
administrator can see the plain text contents of disk images.

**Recommendation:** make use of storage encryption to protect non-local
storage from attack by rogue network / storage administrators or
external attackers. This is particularly important if the storage
protocol itself does not offer any kind of encryption capabilities.
