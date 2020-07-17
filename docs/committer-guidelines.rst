====================
Committer guidelines
====================

The AUTHORS files indicates the list of people with commit access
right who can actually merge the patches.

The general rule for committing a patch is to make sure it has
been reviewed properly in the mailing-list first, usually if a
couple of people gave an ACK or +1 to a patch and nobody raised an
objection on the list it should be good to go. If the patch
touches a part of the code where you're not the main maintainer,
or where you do not have a very clear idea of how things work,
it's better to wait for a more authoritative feedback though.
Before committing, please also rebuild locally, run 'ninja test',
and make sure you don't raise errors.

An exception to 'review and approval on the list first' is fixing
failures to build:

-  if a recently committed patch breaks compilation on a platform
   or for a given driver, then it's fine to commit a minimal fix
   directly without getting the review feedback first
-  if ninja test breaks, if there is an obvious fix, it's fine to
   commit immediately. The patch should still be sent to the list
   (or tell what the fix was if trivial), and 'ninja test' should
   pass too, before committing anything
-  fixes for documentation and code comments can be managed in the
   same way, but still make sure they get reviewed if non-trivial.
-  (ir)regular pulls from other repositories or automated updates,
   such as the keycodemap submodule updates, pulling in new
   translations or updating the container images for the CI system
