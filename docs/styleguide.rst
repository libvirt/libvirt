=========================
Documentation style guide
=========================

.. contents::

The following documents some specific libvirt rules for writing docs in
reStructuredText

Table of contents
=================

Any document which uses headings and whose content is long enough to cause
scrolling when viewed in the browser must start with a table of contents.
This should be created using the default formatting:

::

   .. contents::


Whitespace
==========

Blocks should be indented with 3 spaces, and no tabs

Code blocks
===========

Code blocks should be created using

::

   This is regular text.

   ::

      This is a code block.

Headings
========

RST allows headings to be created simply by underlining with any punctuation
characters. Optionally the text may be overlined to.

For the sake of consistency, libvirt defines the following style requirement
which allows for 6 levels of headings

::

   =========
   Heading 1
   =========



   Heading 2
   =========



   Heading 3
   ---------



   Heading 4
   ~~~~~~~~~



   Heading 5
   .........



   Heading 6
   ^^^^^^^^^

Tables
======

Tables should be created using the ``list-table`` directive whenever
possible, as in

::

   .. list-table::
      :header-rows: 1

      * - Option
        - Description

      * - ``foo_enabled``
        - Whether or not ``foo`` should be enabled

      * - ``bar_user``
        - Which user to run ``bar`` as

Manual pages
============

RST documents created as manual pages must have the following structure

::

  ===========
  ::PROGRAM::
  ===========

  ---------------------------
  ...line line description...
  ---------------------------

  :Manual section: 8
  :Manual group: Virtualization Support

  .. contents::

  SYNOPSIS
  ========

  ``::PROGRAM::`` [*OPTION*]...

  DESCRIPTION
  ===========

  ...describe the tool / program ...

  OPTIONS
  =======

  ``-h``, ``--help``

  Display command line help usage then exit.

  ...and other args....

  FILES
  =====

  ...any files used that the user needs to know about. eg config
  files in particular...

  AUTHORS
  =======

  Please refer to the AUTHORS file distributed with libvirt.

  BUGS
  ====

  Please report all bugs you discover.  This should be done via either:

  #. the mailing list

   `https://libvirt.org/contact.html <https://libvirt.org/contact.html>`_

  #. the bug tracker

   `https://libvirt.org/bugs.html <https://libvirt.org/bugs.html>`_

  Alternatively, you may report bugs to your software distributor / vendor.


  COPYRIGHT
  =========

  Copyright (C) ::DATE:: ::ORIGINAL AUTHOR::, and the authors listed in the
  libvirt AUTHORS file.

  LICENSE
  =======

  ``::PROGRAM::`` is distributed under the terms of the GNU LGPL v2.1+.
  This is free software; see the source for copying conditions. There
  is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR
  PURPOSE

  SEE ALSO
  ========

  ...other man page links....
  `https://libvirt.org/ <https://libvirt.org/>`_
