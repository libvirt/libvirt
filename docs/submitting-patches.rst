==================
Submitting patches
==================

The simplest way to send patches is to use the
`git-publish <https://github.com/stefanha/git-publish>`__
tool. All libvirt-related repositories contain a config file
that tells git-publish to use the correct mailing list and
subject prefix.

If you are a first-time contributor, you may wish to read some
patch submission threads from the `mailing list archive
<contact.html#mailing-lists>`__ of the mailing list from the
``.gitpublish`` file.

Alternatively, you may send patches using ``git send-email``.

The usual workflow of libvirt developer is:

::

  $ git checkout master
  $ git pull
  $ git checkout -t origin -b workbranch
  (hack, committing any changes along the way)

More hints on compiling can be found `here <compiling.html>`__.
Make sure to express your agreement with the `Developer Certificate
of Origin <hacking.html#developer-certificate-of-origin>`__ by
adding a "Signed-off-by" line to every commit message.
When you want to post your patches:

::

  $ git pull --rebase
  (fix any conflicts)
  $ git send-email --cover-letter --no-chain-reply-to --annotate \
                   --confirm=always --to=devel@lists.libvirt.org master

For a single patch you can omit ``--cover-letter``, but a
series of two or more patches needs a cover letter.

Note that the ``git send-email`` subcommand may not be in the
main git package and using it may require installation of a
separate package, for example the "git-email" package in Fedora
and Debian.

Avoid using mail clients for sending patches, as most of them
will mangle the messages in some way, making them unusable for
our purposes. Gmail and other Web-based mail clients are
particularly bad at this.

If everything went well, your patch should show up on the
`devel list
archives <https://lists.libvirt.org/archives/list/devel@lists.libvirt.org/>`__ in a
matter of minutes; if you still can't find it on there after an
hour or so, you should double-check your setup. **Note that, if
you are not already a subscriber, your very first post to the
mailing list will be subject to moderation**, and it's not
uncommon for that to take around a day.

Please follow this as close as you can, especially the rebase
and ``git send-email`` part, as it makes life easier for other
developers to review your patch set.

One should avoid sending patches as attachments, but rather
send them in email body along with commit message. If a
developer is sending another version of the patch (e.g. to
address review comments), they are advised to note differences
to previous versions after the ``---`` line in the patch so
that it helps reviewers but doesn't become part of git history.
Moreover, such patch needs to be prefixed correctly with
``--subject-prefix=PATCHv2`` appended to
``git send-email`` (substitute ``v2`` with the
correct version if needed though).

Git Configuration
-----------------

If this is your first time using ``git send-email``, you will probably
need to setup your global git configuration, to point to your outgoing
SMTP server with something like:

::

  $ git config --global sendemail.smtpServer stmp.youremailprovider.net

If your email provider (often your employer) has configured a DMARC
policy for their domain, there are some additional settings that will
be required. Before doing this, check the DMARC policy with

::

  $ host -t txt _dmarc.$YOURDOMAIN.COM

If this returns no output, or contains ``p=none`` then no configuration
is required. If it reports ``p=quarantine`` or ``p=reject``, then the
libvirt lists will apply DMARC countermeasures to your email. To ensure
that git authorship is preserved add

::

  $ git config --global format.from "Your Name <your@email.com>"
  $ git config --global format.forceInBodyFrom true

This will force git to always add an additional line

::

   From: Your Name <your@email.com>

in the body of the patch, guaranteeing correct author records even
when the main ``From`` header is rewritten by mailman.

If you get tired of typing ``--to=devel@lists.libvirt.org`` all
the time, you can configure that to be automatically handled by
adding a local repository setting:

::

  $ git config sendemail.to devel@lists.libvirt.org

This last setting is not required if using ``git-publish`` to send
patches, as that auto-identifies the mailing list address from its
config file stored in git.

Review process
--------------

Reviewing patches may take a lot of effort with review bandwidth being limited
in open source projects. Here are a few rules to follow to streamline the
process:

 - **don't** contact individual maintainers/developers directly with your
   patches; reviewers are subscribed to the mailing list
 - **do** be patient; reviewers may be busy
 - **do** respond to reviewer's questions
 - **don't** ignore a suggestion from a reviewer; if you disagree discuss it on
   the list before sending a new version
 - **do** remind us of your patches on the list if they haven't gotten any
   attention for a prolonged period (>1 week) by replying to your patches with a
   "ping"
 - **do** test your patches before sending

Don't feel obliged to review whole patch series if you see any major problems
in any of the comprising patches - just point them out on the list.
