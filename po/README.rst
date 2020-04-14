===========================
Libvirt Message Translation
===========================

Libvirt translatable messages are maintained using the GNU Gettext tools and
file formats, in combination with the Zanata web service.

python-zanata-client is required in order to use make to pull/push translations
from/to Zanata server.


Source repository
=================

The libvirt GIT repository does NOT store the master "libvirt.pot" file, nor
does it store full "po" files for translations. The master "libvirt.pot" file
can be generated at any time using

::

  $ make libvirt.pot

The translations are kept in minimized files that are the same file format
as normal po files but with all redundant information stripped and messages
re-ordered. The key differences between the ".mini.po" files in GIT and the
full ".po" files are

* msgids with no current translation are omitted
* msgids are sorted in alphabetical order not source file order
* msgids with a msgstr marked "fuzzy" are discarded
* source file locations are omitted

The full po files can be created at any time using

::

  $ make update-po

This merges the "libvirt.pot" with the "$LANG.mini.po" for each language, to
create the "$LANG.po" files. These are included in the release archives created
by "make dist".

When a full po file is updated, changes can be propagated back into the
minimized po files using

::

  $ make update-mini-po

Note, however, that this is generally not something that should be run by
developers normally, as it is triggered by 'make pull-po' when refreshing
content from Zanata.


Zanata web service
==================

The translation of libvirt messages has been outsourced to the Fedora
translation team using the Zanata web service:

https://fedora.zanata.org/project/view/libvirt

As such, changes to translations will generally NOT be accepted as patches
directly to libvirt GIT. Any changes made to "$LANG.mini.po" files in libvirt
GIT will be overwritten and lost the next time content is imported from Zanata.

The master "libvirt.pot" file is periodically pushed to Zanata to provide the
translation team with content changes, using

::

  $ make push-pot

New translated text is then periodically pulled down from Zanata to update the
minimized po files, using

::

  $ make pull-po

Sometimes the translators make mistakes, most commonly with handling printf
format specifiers. The "pull-po" command re-generates the .gmo files to try to
identify such mistakes. If a mistake is made, the broken msgstr should be
deleted in the local "$LANG.mini.po" file, and the Zanata web interface used
to reject the translation so that the broken msgstr isn't pulled down next time.

After pulling down new content the diff should be examined to look for any
obvious mistakes that are not caught automatically. There have been bugs in
Zanata tools which caused messges to go missing, so pay particular attention to
diffs showing deletions where the msgid still exists in libvirt.pot
