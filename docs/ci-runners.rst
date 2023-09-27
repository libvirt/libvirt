GitLab CI Custom (Specific) Runners
===================================

.. contents::

GitLab's CI allows additional machines to be added to the project's or group's
pool of runners (a runner is a machine running the GitLab's
`gitlab-runner <https://gitlab.com/gitlab-org/gitlab-runner/>`__ agent service).
Upon registering the runner the runner will then be ready accepting CI jobs
depending on the pipeline configuration. Unlike the shared runners provided
directly by GitLab's hosted SaaS specific runners are only used within the
project/group which they were registered to, so you don't need to worry about
forks burning CPU cycles on your precious HW resources.

Understandably, we respect your decision to keep your runners only visible to
your fork, but for the sake of the community we'd appreciate if you decided to
register your runner with the upstream libvirt project instead. As we're only
interested in running upstream test workloads (which you can even help
defining) maintenance and security of the HW is your own responsibility and so
we can promise to never ask for physical or remote access to the machine.

Machine Setup Howto
-------------------

The following sections will guide you through the necessary setup of your
specific GitLab runners.

gitlab-runner setup and registration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The gitlab-runner agent needs to be installed on each machine that is supposed
to run jobs. The association between a machine and a GitLab project
happens with a registration token.  To find the registration token for
your repository/project, navigate on GitLab's web UI to:

 * Settings (the gears-like icon at the bottom of the left hand side
   vertical toolbar), then
 * CI/CD, then
 * Runners, and click on the *Expand* button, then
 * Under *Set up a specific Runner manually*, look for the value under
   *And this registration token:*

Note that in order to register a runner with the upstream libvirt project
you'll need to work with the project maintainers to successfully register your
machine.

Following the `registration <https://docs.gitlab.com/runner/register/>`__
process, it's necessary to configure the runner tags, and optionally other
configurations on the GitLab UI.  Navigate to:

 * Settings (the gears like icon), then
 * CI/CD, then
 * Runners, and click on the *Expand* button, then
 * *Runners activated for this project*, then
 * Click on the *Edit* icon (next to the *Lock* Icon)

*Note: GitLab has changed the runner registration process deprecating the use of
registration tokens in future versions, so while the above process is still
applicable (though the settings are now a bit more hidden) at the time of writing
this note (09/2023), GitLab v18.0+ is planned to completely switch to a new
process (see the links below), deleting the use of registration tokens.*

 * https://gitlab.com/gitlab-org/gitlab/-/issues/380872
 * https://docs.gitlab.com/ee/ci/runners/new_creation_workflow.html
 * https://docs.gitlab.com/ee/ci/runners/runners_scope.html#create-a-shared-runner-with-a-runner-authentication-token

Don't forget to add a tag to your runner as these are used to route specific
jobs to specific runners, e.g. if a job in ``ci/integration.yml`` looked like
this ::

    centos-stream-9-tests:
    ...
    variables:
      # needed by libvirt-gitlab-executor
      DISTRO: centos-stream-9
      # can be overridden in forks to set a different runner tag
      LIBVIRT_CI_INTEGRATION_RUNNER_TAG: my-vm-host
    tags:
    - $LIBVIRT_CI_INTEGRATION_RUNNER_TAG

it would mean that the CentOS Stream 9 job would only be scheduled on runners
bearing the 'my-vm-host' tag.

Running integration tests
~~~~~~~~~~~~~~~~~~~~~~~~~

Libvirt's integration tests run in a nested virtualization environment. So, if
you wish to run integration tests on your bare-metal machine, you'll have to
make use of GitLab's
`custom executor <https://docs.gitlab.com/runner/executors/custom.html>`__
feature which allows you to provision any kind of environment for a workload to
run - in libvirt's case - a virtual machine. If you need any help with creating
VM template images ready to run libvirt's integration test suite, have a look
at the `libvirt-gitlab-executor <https://gitlab.com/libvirt/libvirt-custom-executor>`__
project which encapsulates provisioning, execution, and teardown of the
virtualized environments in a single tool.
