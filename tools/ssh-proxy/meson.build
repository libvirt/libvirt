if conf.has('WITH_SSH_PROXY')
  executable(
    'libvirt-ssh-proxy',
    [
      'ssh-proxy.c'
    ],
    dependencies: [
      src_dep,
    ],
    link_with: [
      libvirt_lib,
    ],
    install: true,
    install_dir: libexecdir,
    install_rpath: libvirt_rpath,
  )

  configure_file(
    input : '30-libvirt-ssh-proxy.conf.in',
    output: '@BASENAME@',
    configuration: tools_conf,
    install: true,
    install_dir : sshconfdir,
  )
endif
