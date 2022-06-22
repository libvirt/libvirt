===================================
Contacting the project contributors
===================================

.. contents::

Security Issues
---------------

If you think that an issue with libvirt may have security implications, **please
do not** publicly report it in the bug tracker, mailing lists, or irc. Libvirt
has `a dedicated process for handling (potential) security
issues <securityprocess.html>`__ that should be used instead. So if your issue
has security implications, ignore the rest of this page and follow the `security
process <securityprocess.html>`__ instead.

Mailing lists
-------------

There are three mailing-lists:

**libvir-list@redhat.com** (for development)
   Archives
     https://listman.redhat.com/archives/libvir-list
   List info
     https://listman.redhat.com/mailman/listinfo/libvir-list

   This is a high volume mailing list. It is a place for discussions about the
   **development** of libvirt.
   Topics for discussion include:

   -  New features for libvirt
   -  Bug fixing of libvirt
   -  New hypervisor drivers
   -  Development of language bindings for libvirt API
   -  Testing and documentation of libvirt

**libvirt-users@redhat.com** (for users)
   Archives
     https://listman.redhat.com/archives/libvirt-users
   List info
     https://listman.redhat.com/mailman/listinfo/libvirt-users

   This is a moderate volume mailing list. It is a place for discussions
   involving libvirt **users**.
   Topics for discussion include:

   -  Usage of libvirt / virsh
   -  Administration of libvirt
   -  Deployment of libvirt with hypervisors
   -  Development of applications on top of / using the libvirt API(s)
   -  Any other topics along these lines

**libvirt-announce@redhat.com** (for release notices)
   Archives
     https://listman.redhat.com/archives/libvirt-announce
   List info
     https://listman.redhat.com/mailman/listinfo/libvirt-announce

   This is a low volume mailing list, with restricted posting, for announcements
   of new libvirt releases.
   Subscribe to just this if you want to be notified of new releases, without
   subscribing to either of the other mailing lists.

It is recommended but not required that you subscribe before posting to the user
and development lists. Posts from non-subscribers will be subject to manual
moderation delays. You can subscribe at the linked web pages above.

Patches with explanations and provided as attachments are really appreciated,
and should be directed to the development mailing list for review and
discussion. Wherever possible, please generate the patches by using
``git format-patch`` in a git repository clone. Further useful information
regarding developing libvirt and/or contributing is available on our
`Contributor Guidelines <hacking.html>`__ page.

IRC
---

Some of the libvirt developers may be found on IRC on the `OFTC
IRC <https://oftc.net>`__ network. Use the settings:

-  server: irc.oftc.net
-  port: 6697 (the usual IRC TLS port)
-  channel: #virt

NB There is no guarantee that someone will be watching or able to reply
promptly, so use the mailing-list if you don't get an answer on the IRC channel.
