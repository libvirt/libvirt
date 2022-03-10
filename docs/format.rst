==========
XML Format
==========

Objects in the libvirt API are configured using XML documents to allow for ease
of extension in future releases. Each XML document has an associated Relax-NG
schema that can be used to validate documents prior to usage.

-  `Domains <formatdomain.html>`__
-  `Networks <formatnetwork.html>`__
-  `Network filtering <formatnwfilter.html>`__
-  `Network ports <formatnetworkport.html>`__
-  `Storage <formatstorage.html>`__
-  `Storage encryption <formatstorageencryption.html>`__
-  `Capabilities <formatcaps.html>`__
-  `Domain capabilities <formatdomaincaps.html>`__
-  `Storage Pool capabilities <formatstoragecaps.html>`__
-  `Node devices <formatnode.html>`__
-  `Secrets <formatsecret.html>`__
-  `Snapshots <formatsnapshot.html>`__
-  `Checkpoints <formatcheckpoint.html>`__
-  `Backup jobs <formatbackup.html>`__

Command line validation
-----------------------

The ``virt-xml-validate`` tool provides a simple command line for validating XML
documents prior to giving them to libvirt. It uses the locally installed RNG
schema documents. It will auto-detect which schema to use for validation based
on the name of the top level element in the input document. Thus it merely
requires the XML document filename to be passed on the command line

::

   $ virt-xml-validate /path/to/XML/file
