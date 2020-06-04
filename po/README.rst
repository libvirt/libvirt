===========================
Libvirt Message Translation
===========================

.. image:: https://translate.fedoraproject.org/widgets/libvirt/-/libvirt/multi-auto.svg
     :target: https://translate.fedoraproject.org/engage/libvirt/
     :alt: Translation status

Libvirt translatable messages are maintained using the GNU Gettext tools and
file formats, in combination with the Fedora Weblate web service.

https://translate.fedoraproject.org/projects/libvirt/libvirt/

Source repository
=================

The libvirt GIT repository stores the master "libvirt.pot" file, which is to be
refreshed at time of feature freeze.

The "po" files stored in GIT have source locations removed in order to cut down
on storage size, by eliminating information already present in the "pot" file.
All files are stored with strings sorted in alphabetical order rather than
source location order, to minimize movement of strings when source locations
change.

The "po" files are to be EXCLUSIVELY UPDATED by merge requests sent from the
Fedora Weblate service. Other contributors MUST NEVER send changes which touch
the "po" file content, as that will create merge conflicts for Weblate. IOW any
bug fixes to translations should be made via the Weblate application UI.

After the "pot" file in libvirt GIT, Weblate will automatically run "msgmerge"
to update the "po" files itself and send back a merge request with the changes.

Translation updates made in the Weblate Web UI will be committed to its fork of
the GIT repo once a day. These commits will be submitted back to the master GIT
repo via merge requests. If a merge request from Weblate is already open,
commits will be added to this existing merge request. Weblate will take care of
rebasing whenever changes happen in Git master. In order to avoid having to do
translations merges 30 times a month, merge requests from Weblate will usually
be left open until feature freeze arrives. During the freeze period, they will
be accepted more promptly to ensure they make it into the new release.
