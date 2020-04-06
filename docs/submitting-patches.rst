==================
Submitting patches
==================

The simplest way to send patches is to use the
`git-publish <https://github.com/stefanha/git-publish>`__
tool. All libvirt-related repositories contain a config file
that tells git-publish to use the correct mailing list and
subject prefix.

Alternatively, you may send patches using ``git send-email``.

Also, for code motion patches, you may find that
``git diff --patience`` provides an easier-to-read
patch. However, the usual workflow of libvirt developer is:

::

  $ git checkout master
  $ git pull
  $ git checkout -t origin -b workbranch
  (hack, committing any changes along the way)

More hints on compiling can be found `here <compiling.html>`__.
When you want to post your patches:

::

  $ git pull --rebase
  (fix any conflicts)
  $ git send-email --cover-letter --no-chain-reply-to --annotate \
                   --confirm=always --to=libvir-list@redhat.com master

For a single patch you can omit ``--cover-letter``, but a
series of two or more patches needs a cover letter.

Note that the ``git send-email`` subcommand may not be in the
main git package and using it may require installation of a
separate package, for example the "git-email" package in Fedora
and Debian. If this is your first time using
``git send-email``, you might need to configure it to point it
to your SMTP server with something like:

::

  $ git config --global sendemail.smtpServer stmp.youremailprovider.net

If you get tired of typing ``--to=libvir-list@redhat.com`` all
the time, you can configure that to be automatically handled as
well:

::

  $ git config sendemail.to libvir-list@redhat.com

As a rule, patches should be sent to the mailing list only: all
developers are subscribed to libvir-list and read it regularly,
so **please don't CC individual developers** unless they've
explicitly asked you to.

Avoid using mail clients for sending patches, as most of them
will mangle the messages in some way, making them unusable for
our purposes. Gmail and other Web-based mail clients are
particularly bad at this.

If everything went well, your patch should show up on the
`libvir-list
archives <https://www.redhat.com/archives/libvir-list/>`__ in a
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
