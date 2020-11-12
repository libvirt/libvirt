=====================
Programming languages
=====================

The libvirt repository makes use of a large number of programming
languages. It is anticipated that in the future libvirt will adopt
use of other new languages. To reduce the overall burden on
developers, there is thus a general desire to phase out usage of
some of the existing languages.

The preferred languages at this time are:

-  C - for the main libvirt codebase. Dialect supported by
   GCC/Clang only.
-  Python - for supporting build scripts / tools. Code must run
   with both version 2.7 and 3.x at this time.

Languages that should not be used for any new contributions:

-  Perl - build scripts must be written in Python instead.
-  Shell - build scripts must be written in Python instead.
