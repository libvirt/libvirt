=====================
Terminology and goals
=====================

To avoid ambiguity about the terms used, here are the definitions for some of
the specific concepts used in libvirt documentation:

-  a **node** is a single physical machine
-  an **hypervisor** is a layer of software allowing to virtualize a node in a
   set of virtual machines with possibly different configurations than the node
   itself
-  a **domain** is an instance of an operating system (or subsystem in the case
   of container virtualization) running on a virtualized machine provided by the
   hypervisor

Now we can define the goal of libvirt: **to provide a common and stable layer
sufficient to securely manage domains on a node, possibly remote**.

As a result, libvirt should provide all APIs needed to do the management, such
as: provision, create, modify, monitor, control, migrate and stop the domains -
within the limits of the support of the hypervisor for those operations. Not all
hypervisors provide the same operations; but if an operation is useful for
domain management of even one specific hypervisor it is worth providing in
libvirt. Multiple nodes may be accessed with libvirt simultaneously, but the
APIs are limited to single node operations. Node resource operations which are
needed for the management and provisioning of domains are also in the scope of
the libvirt API, such as interface setup, firewall rules, storage management and
general provisioning APIs. Libvirt will also provide the state monitoring APIs
needed to implement management policies, obviously checking domain state but
also exposing local node resource consumption.

This implies the following sub-goals:

-  All API can be carried remotely though secure APIs
-  While most API will be generic in term of hypervisor or Host OS, some API may
   be targeted to a single virtualization environment as long as the semantic
   for the operations from a domain management perspective is clear
-  the API should allow to do efficiently and cleanly all the operations needed
   to manage domains on a node, including resource provisioning and setup
-  the API will not try to provide high level virtualization policies or
   multi-nodes management features like load balancing, but the API should be
   sufficient so they can be implemented on top of libvirt
-  stability of the API is a big concern, libvirt should isolate applications
   from the frequent changes expected at the lower level of the virtualization
   framework
-  the node being managed may be on a different physical machine than the
   management program using libvirt, to this effect libvirt supports remote
   access, but should only do so by using secure protocols.
-  libvirt will provide APIs to enumerate, monitor and use the resources
   available on the managed node, including CPUs, memory, storage, networking,
   and NUMA partitions.

So libvirt is intended to be a building block for higher level management tools
and for applications focusing on virtualization of a single node (the only
exception being domain migration between node capabilities which involves more
than one node).
