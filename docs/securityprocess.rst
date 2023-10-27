================
Security Process
================

.. contents::

The libvirt project believes in responsible disclosure of security problems, to
allow vendors time to prepare and distribute patches for problems ahead of their
publication. This page describes how the process works and how to report
potential security issues.

Reporting security issues
-------------------------

In the event that a bug in libvirt is found which is believed to have
(potential) security implications there is a dedicated contact to which a bug
report / notification should be directed. Send an email with as many details of
the problem as possible (ideally with steps to reproduce) to the following email
address:

::

   security@lists.libvirt.org

NB. while this email address is backed by a mailing list, it is invitation only
and moderated for non-members. As such you will receive an auto-reply indicating
the report is held for moderation. Postings by non-members will be approved by a
moderator and the reporter copied on any replies.

Security notices
----------------

Information for all historical security issues is maintained in machine parsable
format in the `libvirt-security-notice GIT
repository <https://gitlab.com/libvirt/libvirt-security-notice>`__ and
`published online <https://security.libvirt.org>`__ in text, HTML and XML
formats. Security notices are published on the `libvirt-announce mailing
list <https://libvirt.org/contact.html#mailing-lists>`__ when any embargo is
lifted, or as soon as triaged if already public knowledge.

Security team
-------------

The libvirt security team is made up of a subset of the libvirt core development
team which covers the various distro maintainers of libvirt, along with
nominated security engineers representing the various vendors who distribute
libvirt. The team is responsible for analysing incoming reports from users to
identify whether a security problem exists and its severity. It then works to
produce a fix for all official stable branches of libvirt and coordinate embargo
dates between vendors to allow simultaneous release of the fix by all affected
parties.

If you are a security representative of a vendor distributing libvirt and would
like to join the security team, send an email to the afore-mentioned security
address. Typically an existing member of the security team will have to vouch
for your credentials before membership is approved. All members of the security
team are **required to respect the embargo policy** described below.

Publication embargo policy
--------------------------

The libvirt security team operates a policy of `responsible
disclosure <https://en.wikipedia.org/wiki/Responsible_disclosure>`__. As such
any security issue reported, that is not already publicly disclosed elsewhere,
will have an embargo date assigned. Members of the security team agree not to
publicly disclose any details of the security issue until the embargo date
expires.

The general aim of the team is to have embargo dates which are two weeks or less
in duration. If a problem is identified with a proposed patch for a security
issue, requiring further investigation and bug fixing, the embargo clock may be
restarted. In exceptional circumstances longer initial embargoes may be
negotiated by mutual agreement between members of the security team and other
relevant parties to the problem. Any such extended embargoes will aim to be at
most one month in duration.

CVE allocation
--------------

The libvirt security team will associate each security issue with a CVE number.
The CVE numbers will usually be allocated by one of the vendor security
engineers on the security team.

Branch fixing policy
--------------------

The security team will publish fixes for GIT master (which will become the next
major release). The distro maintainers will be responsible for backporting the
officially published fixes to other release branches where applicable.
