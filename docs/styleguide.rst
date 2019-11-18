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
