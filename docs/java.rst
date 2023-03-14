=================
Java API bindings
=================

.. contents::

Presentation
------------

The Java bindings make use of `JNA <https://jna.dev.java.net/>`__ to expose the
C API in a Java friendly way. The bindings are based on work initiated by Toth
Istvan.

Getting it
----------

The latest versions of the libvirt Java bindings can be downloaded from:

-  `libvirt.org HTTP server <https://download.libvirt.org/java/>`__

A maven repository is located at https://download.libvirt.org/maven2/ which you
can use to include this in your maven projects.

GIT source repository
---------------------

The Java bindings code source is now maintained in a
`git <https://git-scm.com/>`__ repository available on
`gitlab.com <https://gitlab.com/libvirt/libvirt-java/>`__:

::

   git clone https://gitlab.com/libvirt/libvirt-java.git

Building
--------

The code is built using ant, and assumes that you have the jna jar installed.
Once you have downloaded the code you can build the code with

::


   % cd libvirt-java
   % ant build

Content
-------

The bindings are articulated around a few classes in the ``org/libvirt``
package, notably the ``Connect``, ``Domain`` and ``Network`` ones. Functions in
the `C API <html/index.html>`__ taking ``virConnectPtr``, ``virDomainPtr`` or
``virNetworkPtr`` as their first argument usually become methods for the
classes, their name is just stripped from the virConnect or virDomain(Get)
prefix and the first letter gets converted to lower case, for example the C
functions:

``int virConnectNumOfDomains (virConnectPtr conn);``

``int virDomainSetMaxMemory (virDomainPtr domain, unsigned long memory);``

become

``virConn.numOfDomains()``

``virDomain.setMaxMemory(long memory)``

There is of course some functions where the mapping is less direct and using
extra classes to map complex arguments. The
`Javadoc <https://libvirt.gitlab.io/libvirt-java/javadoc>`__ is available online
or as part of a separate libvirt-java-javadoc package.

So let's look at a simple example inspired from the ``test.java`` test found in
``src`` in the source tree:

::

   import org.libvirt.*;
   public class minitest {
       public static void main(String[] args) {
           Connect conn=null;
           try{
               conn = new Connect("test:///default", true);
           } catch (LibvirtException e) {
               System.out.println("exception caught:"+e);
               System.out.println(e.getError());
           }
           try{
               Domain testDomain=conn.domainLookupByName("test");
               System.out.println("Domain:" + testDomain.getName() + " id " +
                                  testDomain.getID() + " running " +
                                  testDomain.getOSType());
           } catch (LibvirtException e) {
               System.out.println("exception caught:"+e);
               System.out.println(e.getError());
           }
       }
   }

There is not much to comment about it, it really is a straight mapping from the
C API, the only points to notice are:

-  the import of the modules in the ``org.libvirt`` package
-  getting a connection to the hypervisor, in that case using the readonly
   access to the default test hypervisor.
-  getting an object representing the test domain using ``lookupByName``
-  if the domain is not found a LibvirtError exception will be raised
-  extracting and printing some information about the domain using various
   methods associated to the Domain class.

Maven
-----

Up until version 0.4.7 the Java bindings were available from the central maven
repository.

If you want to use 0.4.8 or higher, please add the following repository to your
pom.xml

::

   <repositories>
     <repository>
       <id>libvirt-org</id>
       <url>https://download.libvirt.org/maven2</url>
     </repository>
   </repositories>
