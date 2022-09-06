=============================
QEMU command-line passthrough
=============================

.. contents::

Libvirt aims to provide explicit modelling of virtualization features in
the domain XML document schema. QEMU has a very broad range of features
and not all of these can be mapped to elements in the domain XML. Libvirt
would like to reduce the gap to QEMU, however, with finite resources there
will always be cases which aren't covered by the domain XML schema.


XML document additions
======================

To deal with the problem, libvirt introduced support for command-line
passthrough of QEMU arguments. This is achieved by supporting a custom
XML namespace, under which some QEMU driver specific elements are defined.

The canonical place to declare the namespace is on the top level ``<domain>``
element. At the very end of the document, arbitrary command-line arguments
can now be added, using the namespace prefix ``qemu:``

::

   <domain type='kvm' xmlns:qemu='http://libvirt.org/schemas/domain/qemu/1.0'>
     <name>QEMUGuest1</name>
     <uuid>c7a5fdbd-edaf-9455-926a-d65c16db1809</uuid>
     ...
     <qemu:commandline>
       <qemu:arg value='-newarg'/>
       <qemu:arg value='parameter'/>
       <qemu:env name='ID' value='wibble'/>
       <qemu:env name='BAR'/>
     </qemu:commandline>
   </domain>

Note that when an argument takes a value eg ``-newarg parameter``, the argument
and the value must be passed as separate ``<qemu:arg>`` entries.

Instead of declaring the XML namespace on the top level ``<domain>`` it is also
possible to declare it at time of use, which is more convenient for humans
writing the XML documents manually. So the following example is functionally
identical:

::

   <domain type='kvm'>
     <name>QEMUGuest1</name>
     <uuid>c7a5fdbd-edaf-9455-926a-d65c16db1809</uuid>
     ...
     <commandline xmlns="http://libvirt.org/schemas/domain/qemu/1.0">
       <arg value='-newarg'/>
       <arg value='parameter'/>
       <env name='ID' value='wibble'/>
       <env name='BAR'/>
     </commandline>
   </domain>

Note that when querying the XML from libvirt, it will have been translated into
the canonical syntax once more with the namespace on the top level element.

Security confinement / sandboxing
=================================

When libvirt launches a QEMU process it makes use of a number of security
technologies to confine QEMU and thus protect the host from malicious VM
breakouts.

When configuring security protection, however, libvirt generally needs to know
exactly which host resources the VM is permitted to access. It gets this
information from the domain XML document. This only works for elements in the
regular schema, the arguments used with command-line passthrough are completely
opaque to libvirt.

As a result, if command-line passthrough is used to expose a file on the host
to QEMU, the security protections will activate and either kill QEMU or deny it
access.

There are two strategies for dealing with this problem, either figure out what
steps are needed to grant QEMU access to the device, or disable the security
protections.  The former is harder, but more secure, while the latter is simple.

Granting access per VM
----------------------

* SELinux - the file on the host needs an SELinux label that will grant access
  to QEMU's ``svirt_t`` policy.

  - Read-only access - use the ``virt_content_t`` label
  - Shared, write access - use the ``svirt_image_t:s0`` label (ie no Multi-
    Category Security (MCS) value appended)
  - Exclusive, write access - use the ``svirt_image_t:s0:MCS`` label for the VM.
    The MCS is auto-generatd at boot time, so this may require re-configuring
    the VM to have a fixed MCS label

* Discretionary Access Control (DAC) - the file on the host needs to be
  readable/writable to the ``qemu`` user or ``qemu`` group. This can be done
  by changing the file ownership to ``qemu``, or relaxing the permissions to
  allow world read, or adding file ACLs to allow access to ``qemu``.

* Namespaces - a private ``mount`` namespace is used for QEMU by default
  which populates a new ``/dev`` with only the device nodes needed by QEMU.
  There is no way to augment the set of device nodes ahead of time.

* Seccomp - libvirt launches QEMU with its built-in seccomp policy enabled with
  ``obsolete=deny``, ``elevateprivileges=deny``, ``spawn=deny`` and
  ``resourcecontrol=deny`` settings active. There is no way to change this
  policy on a per VM basis.

* Cgroups - a custom cgroup is created per VM and this will either use the
  ``devices`` controller or an ``BPF`` rule to define an access control list
  for the set of device nodes.
  There is no way to change this policy on a per VM basis.

Disabling security protection per VM
------------------------------------

Some of the security protections can be disabled per-VM:

* SELinux - in the domain XML the ``<seclabel>`` model can be changed to
  ``none`` instead of ``selinux``, which will make the VM run unconfined.

* DAC - in the domain XML an ``<seclabel>`` element with the ``dac`` model can
  be added, configured with a user / group account of ``root`` to make QEMU run
  with full privileges.

* Namespaces - there is no way to disable this per VM.

* Seccomp - there is no way to disable this per VM.

* Cgroups - there is no way to disable this per VM.

Disabling security protection host-wide
---------------------------------------

As a last resort it is possible to disable security protection host wide which
will affect all virtual machines. These settings are all made in
``/etc/libvirt/qemu.conf``

* SELinux - set ``security_default_confied = 0`` to make QEMU run unconfined by
  default, while still allowing explicit opt-in to SELinux for VMs.

* DAC - set ``user = root`` and ``group = root`` to make QEMU run as the root
  account.

* SELinux, DAC - set ``security_driver = []`` to entirely disable both the
  SELinux and DAC security drivers.

* Namespaces - set ``namespaces = []`` to disable use of the ``mount``
  namespaces, causing QEMU to see the normal fully popualated ``dev``.

* Seccomp - set ``seccomp_sandbox = 0`` to disable use of the Seccomp sandboxing
  in QEMU.

* Cgroups - set ``cgroup_device_acl`` to include the desired device node, or
  ``cgroup_controllers = [...]`` to exclude the ``devices`` controller.

Private monunt namespace
----------------------------

As mentioned above, libvirt launches each QEMU process in its own ``mount``
namespace. It's recommended that all mount points are set up prior starting any
guest. For cases when that can't be assured, mount points in the namespace are
marked as slave so that mount events happening in the parent namespace are
propagated into this child namespace. But this may require an additional step:
mounts in the parent namespace need to be marked as shared (if the distribution
doesn't do that by default). This can be achieved by running the following
command before any guest is started:

::

  # mount --make-rshared /
