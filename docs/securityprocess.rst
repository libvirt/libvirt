================
Security Process
================

.. contents::

The libvirt project handles security disclosures with a lightweight process
whose aim is to minimize the overhead of triage and prioritize publication
of a patch that addresses the issue.

Reporting security issues
-------------------------

Security concerns should be reported as confidential issues in the
`libvirt project on GitLab <https://gitlab.com/libvirt/libvirt/-/work_items>`__,
or one of the other related projects under the
`libvirt namespace <https://gitlab.com/libvirt/>`__ if the issue does not
apply to the core project.

Ensure that the "**turn on confidentiality**" checkbox is selected prior to
submitting the issue, to restrict visibility to project maintainers only.

.. important::
   Only attach plain files, do not bundle files in archives (zip, tar, etc.)
   without prior request from a libvirt maintainer.

Maintainer(s) will analyse the reported disclosure and decide whether it
is to be classed as a security flaw or not. If not a security flaw, the
``confidential`` tag will be removed immediately. If a security flaw,
the maintainers will work to develop and test a patch. When a suitable
patch is considered ready to post to the mailing list or a merge request,
the ``confidential`` tag will be removed. Generally a CVE should be assigned
to a security issue before a patch is ready to be posted (see below).

.. note::
   Refer to the `bug reporting <bugs.html#use-of-automated-tools-ai-agents>`__
   page for the *expectations around the use of automated tools and AI agents*,
   **prior** to filing any security report.

Security notices
----------------

Information for all historical security issues is maintained in machine parsable
format in the `libvirt-security-notice GIT
repository <https://gitlab.com/libvirt/libvirt-security-notice>`__ and
`published online <https://security.libvirt.org>`__ in text, HTML and XML
formats. Security notices are published on the `libvirt-announce mailing
list <contact.html#mailing-lists>`__ when any embargo is
lifted, or as soon as triaged if already public knowledge.

Publication embargo policy
--------------------------

The libvirt project policy is to limit the time that a disclosure has the
"*confidential*" marker applied strictly to the minimum required to develop
and publish a suitable patch and allocate a CVE.

Given the widespread use of AI/LLM based agents for security auditing,
as well as ongoing use of traditional fuzzing and static analysis
tools, the libvirt maintainers consider that any disclosure originating
from automated tools is highly likely to be independently re-discovered,
potentially many times over in a very short timeframe.

Thus the libvirt maintainers will generally reject requests for arbitrary
embargoes unless high severity, extenuating circumstances can be
demonstrated.

If a patch for a confirmed security issue cannot be developed by a
maintainer in a reasonable time, the maintainers may choose to make
a disclosure public without having a patch available. This approach
should only be taken for issues judged to have low severity.

CVE allocation
--------------

If a reported disclosure is confirmed to be a security flaw, the
``CVE::Required`` label will be added.

When a CVE has been allocated, this label will be removed and replaced
by ``CVE::Assigned``.

The allocated CVE identifier will be included in the patch(es) that
are required to fix the issue. If multiple patches are involved, the
CVE must be included in the final patch in the series that closes the
last hole, but should also be included in any prior patches it the
series that are directly related.

Branch fixing policy
--------------------

The security team will publish fixes for GIT master (which will become the next
major release). The distro maintainers will be responsible for backporting the
officially published fixes to other release branches where applicable.
