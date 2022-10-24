==============
Best practices
==============

These are a few guidelines to keep in mind when submitting patches
to libvirt: following them will maximise the chance of your patches
being reviewed in a timely manner and being accepted into libvirt
with minimal back-and-forth.

-  Discuss any large changes on the mailing list first. Post
   patches early and listen to feedback.

-  In your commit message, make the summary line reasonably short
   (60 characters is typical), followed by a blank line, followed
   by any longer description of why your patch makes sense. If the
   patch fixes a regression, and you know what commit introduced
   the problem, mentioning that is useful. If the patch resolves
   an upstream bug reported in GitLab, or downstream bug, put
   "Resolves: $fullURL" of the bug. In both cases also summarize
   the issue rather than making all readers follow the link. You
   can use 'git shortlog -30' to get an idea of typical summary
   lines.

-  Split large changes into a series of smaller patches,
   self-contained if possible, with an explanation of each patch
   and an explanation of how the sequence of patches fits
   together. Moreover, please keep in mind that it's required to
   be able to compile cleanly (**including** ``ninja test``) after
   each patch. A feature does not have to work until the end of a
   series, but intermediate patches must compile and not cause
   test-suite failures (this is to preserve the usefulness of
   ``git bisect``, among other things).

There is more on this subject, including lots of links to
background reading on the subject, on `Richard Jones' guide to
working with open source
projects <https://people.redhat.com/rjones/how-to-supply-code-to-open-source-projects/>`__.
