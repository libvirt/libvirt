===============================
Repository infrastructure setup
===============================

GitLab Configuration
====================

The `GitLab organization <https://gitlab.com/libvirt>`_ hosts the master copy
of all the libvirt Git repositories.

When creating a new repository the following changes to the defaults are
required under the **Settings** page:

* **General**

  * **Naming, topics, avatar**

    * *Project avatar*: upload ``docs/logos/logo-square-256.png``

  * **Visibility, project features, permissions**

    * *Packages*: disabled

    * *Wiki*: disabled

    * *Snippets*: disabled

  * **Merge Requests**

    * *Merge method*: Fast-forward merge

    * *Merge options*: Enable 'delete source branch' option by default

    * *Merge checks*: Pipelines must succeed

  * **Merge request approvals**

    * *Any eligible user*: Num approvals required == 1

* **Integrations**

  * **Pipelines emails**

    * *Recipients*: ``ci@lists.libvirt.org``

* **Repository**

  * **Push rules**

    * *Do not allow users to remove git tags with git push*: enabled

    * *Commit message*:  ``Signed-off-by:``

    * *Branch name*: ``^(master|v.*-maint)$``

  * **Mirroring repositories**

    * *Git repository URL*: ``https://libvirtmirror@github.com/libvirt/$repo.git``

    * *Mirror direction*: push

    * *Password*:  see ``/root/libvirt-mirror-github-api-token.txt`` on ``libvirt.org``

  * **Protected branches**

    * *Branch*: ``master`` and ``v*-maint``

    * *Allowed to merge*: Developers + Maintainers

    * *Allowed to push*: None (or Developers + Maintainers if MRs not used)

    * *Require approval from code owners*: disabled

  * **Protected tags**

    * *Tag*: ``v*`` and any project specific tag formats like ``LIBVIRT_*`` or ``CVE*``

    * *Allowed to create*: Developers + Maintainers

* **CI/CD**

  * **Runners**

    * *Shared runners*: Enable shared runners

  * **Variables**

    * *Key*: ``CIRRUS_GITHUB_REPO``

      * *Value*: ``libvirt/$repo``

      * *Protect variable*: enabled

      * *Mask variable*: disabled

    * *Key*: ``CIRRUS_API_TOKEN``

      * No need to set this at the project level: it's already set for the
        libvirt organization and will be inherited from there.


GitHub configuration
====================

The `GitHub organization <https://github.com/libvirt>`_ hosts read-only
mirrors of all the libvirt Git repositories.

When creating a new repository the following changes to the defaults are
required under the **Settings** page:

* **Options**

  * **Features**

    * *Wikis*: disabled

    * *Sponsorships*: disabled

    * *Projects*: disabled

  * **Manage access**

    * Add the ``@committers`` team with the role "Write", which
      grants the ``libvirtmirror`` user access to sync from GitLab.

  * **Integrations**

    * Check for *Repo Lockdown*  (should be set automatically for all projects)

In the master git repository create a file `.github/lockdown.yml` to restrict
use of issue tracker and pull requests.


libvirt.org
===========

The `libvirt project server <https://libvirt.org>`_ hosts read-only mirrors of
all the libvirt Git repositories in the directory ``/data/git``.

When creating a new repository the following steps are required:

* Create repo with
  ::

     $ sudo su -
     # cd /data/git
     # mkdir $repo.git
     # cd $repo.git
     # git init --bare
     # touch export
     # touch git-daemon-export-ok
     # cd ..
     # chown -R gitmirror.gitmirror $repo.git
     # chmod -R g+w $repo.git
     # find -type d $repo.git | xargs chmod g+s

* Set the ``description`` and ``config`` files following other repos' example

* Setup mirroring
  ::

    $ sudo su - gitmirror
    # ./newrepo.sh /data/git/$repo.git
    # cd mirrors
    # $HOME/sync-one.sh $repo.git
