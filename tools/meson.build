tools_inc_dir = include_directories('.')

tools_dep = declare_dependency(
  compile_args: coverage_flags,
  dependencies: [
    libxml_dep,
    glib_dep,
  ],
  include_directories: [
    libvirt_inc,
    src_inc_dir,
    util_inc_dir,
    top_inc_dir,
  ],
  link_args: (
    libvirt_relro
    + libvirt_no_indirect
    + libvirt_no_undefined
  ),
)

libvirt_shell_lib = static_library(
  'virt_shell',
  [
    'vsh.c',
    'vsh-table.c',
  ],
  dependencies: [
    tools_dep,
    readline_dep,
  ],
  link_with: [
    libvirt_lib,
  ],
  link_args: [
    coverage_flags,
  ],
)

if conf.has('WITH_HOST_VALIDATE')
  virt_host_validate_sources = [
    'virt-host-validate.c',
    'virt-host-validate-common.c',
  ]

  if conf.has('WITH_QEMU')
    virt_host_validate_sources += [
      'virt-host-validate-qemu.c',
    ]
  endif
  if conf.has('WITH_LXC')
    virt_host_validate_sources += [
      'virt-host-validate-lxc.c',
    ]
  endif
  if conf.has('WITH_BHYVE')
    virt_host_validate_sources += [
      'virt-host-validate-bhyve.c',
    ]
  endif
  if conf.has('WITH_CH')
    virt_host_validate_sources += [
      'virt-host-validate-ch.c',
    ]
  endif

  executable(
    'virt-host-validate',
    [
      virt_host_validate_sources,
    ],
    dependencies: [
      tools_dep,
    ],
    link_args: [
      coverage_flags,
    ],
    link_with: [
      libvirt_lib,
    ],
    install: true,
    install_dir: bindir,
    install_rpath: libvirt_rpath,
  )
endif

if conf.has('WITH_LOGIN_SHELL')
  # virt-login-shell will be setuid, and must not link to anything
  # except glibc. It will scrub the environment and then invoke the
  # real virt-login-shell-helper binary.
  executable(
    'virt-login-shell',
    [
      'virt-login-shell.c',
    ],
    include_directories: [
      top_inc_dir,
    ],
    install: true,
    install_dir: bindir,
  )

  executable(
    'virt-login-shell-helper',
    [
      'virt-login-shell-helper.c',
    ],
    dependencies: [
      tools_dep,
    ],
    link_args: [
      coverage_flags,
    ],
    link_with: [
      libvirt_lib,
      libvirt_lxc_lib,
    ],
    install: true,
    install_dir: libexecdir,
    install_rpath: libvirt_rpath,
  )

  install_data('virt-login-shell.conf', install_dir: sysconfdir / 'libvirt')
endif

if host_machine.system() == 'windows'
  # Before you edit virsh_win_icon.rc, please note the following
  # limitations of the resource file format:
  #
  # (1) '..' is not permitted in the icon filename field.
  # (2) '-' is not permitted in the icon filename field.
  # (3) Comments are not permitted in the file.
  #
  # Windows appears to choose the first <= 32x32 icon it finds
  # in the resource file.  Therefore you should list the available
  # icons from largest to smallest, and make sure that the 32x32
  # icon is the most legible.
  #
  # Windows .ICO is a special MS-only format.  GIMP and other
  # tools can write it.  However there are several variations,
  # and Windows seems to do its own colour quantization.  More
  # information is needed in this area.
  windres = import('windows')
  virsh_icon_res = windres.compile_resources(
    'virsh_win_icon.rc',
    depend_files: [
      'libvirt_win_icon_16x16.ico',
      'libvirt_win_icon_32x32.ico',
      'libvirt_win_icon_48x48.ico',
      'libvirt_win_icon_64x64.ico',
    ],
  )
else
  virsh_icon_res = []
endif

executable(
  'virsh',
  [
    'virsh.c',
    'virsh-backup.c',
    'virsh-checkpoint.c',
    'virsh-completer.c',
    'virsh-completer-domain.c',
    'virsh-completer-checkpoint.c',
    'virsh-completer-host.c',
    'virsh-completer-interface.c',
    'virsh-completer-network.c',
    'virsh-completer-nodedev.c',
    'virsh-completer-nwfilter.c',
    'virsh-completer-pool.c',
    'virsh-completer-secret.c',
    'virsh-completer-snapshot.c',
    'virsh-completer-volume.c',
    'virsh-console.c',
    'virsh-domain.c',
    'virsh-domain-event.c',
    'virsh-domain-monitor.c',
    'virsh-host.c',
    'virsh-interface.c',
    'virsh-network.c',
    'virsh-nodedev.c',
    'virsh-nwfilter.c',
    'virsh-pool.c',
    'virsh-secret.c',
    'virsh-snapshot.c',
    'virsh-util.c',
    'virsh-volume.c',
    virsh_icon_res,
  ],
  dependencies: [
    tools_dep,
    readline_dep,
    thread_dep,
    keycode_dep,
  ],
  link_args: [
    coverage_flags,
  ],
  link_with: [
    libvirt_lxc_lib,
    libvirt_qemu_lib,
    libvirt_shell_lib,
  ],
  install: true,
  install_dir: bindir,
  install_rpath: libvirt_rpath,
)

if conf.has('WITH_REMOTE')
  executable(
    'virt-admin',
    [
      'virt-admin.c',
      'virt-admin-completer.c',
    ],
    dependencies: [
      tools_dep,
      readline_dep,
    ],
    link_args: [
      coverage_flags,
    ],
    link_with: [
      libvirt_admin_lib,
      libvirt_shell_lib,
    ],
    install: true,
    install_dir: bindir,
    install_rpath: libvirt_rpath,
  )
endif

tools_conf = configuration_data({
  'PACKAGE': meson.project_name(),
  'VERSION': meson.project_version(),
  'bindir': bindir,
  'libexecdir': libexecdir,
  'localedir': localedir,
  'localstatedir': localstatedir,
  'sbindir': sbindir,
  'schemadir': pkgdatadir / 'schemas',
  'sysconfdir': sysconfdir,
  'initconfdir': initconfdir,
})

configure_file(
  input: 'virt-xml-validate.in',
  output: '@BASENAME@',
  configuration: tools_conf,
  install: true,
  install_dir: bindir,
  install_mode: 'rwxr-xr-x',
)

configure_file(
  input: 'virt-pki-validate.in',
  output: '@BASENAME@',
  configuration: tools_conf,
  install: true,
  install_dir: bindir,
  install_mode: 'rwxr-xr-x',
)

executable(
  'virt-pki-query-dn',
  [
    'virt-pki-query-dn.c',
  ],
  dependencies: [
    glib_dep,
    gnutls_dep,
  ],
  include_directories: [
    libvirt_inc,
    src_inc_dir,
    top_inc_dir,
    util_inc_dir,
  ],
  link_args: (
    libvirt_relro
    + libvirt_no_indirect
    + libvirt_no_undefined
  ),
  link_with: [
    libvirt_lib
  ],
  install: true,
  install_dir: bindir,
)

if conf.has('WITH_SANLOCK')
  configure_file(
    input: 'virt-sanlock-cleanup.in',
    output: '@BASENAME@',
    configuration: tools_conf,
    install: true,
    install_dir: sbindir,
    install_mode: 'rwxr-xr-x',
  )
endif

if conf.has('WITH_QEMU')
  install_data('virt-qemu-sev-validate',
               install_dir: bindir)
endif

if conf.has('WITH_LIBVIRTD')
  configure_file(
    input: 'libvirt-guests.sh.in',
    output: '@BASENAME@',
    configuration: tools_conf,
    install: true,
    install_dir: libexecdir,
    install_mode: 'rwxr-xr-x',
  )

  if init_script == 'systemd'
    configure_file(
      input: 'libvirt-guests.service.in',
      output: '@BASENAME@',
      configuration: tools_conf,
      install: true,
      install_dir: prefix / 'lib' / 'systemd' / 'system',
    )
  endif
endif

if conf.has('WITH_QEMU')
    install_data('virt-qemu-qmp-proxy',
                 install_dir: bindir)
endif

if bash_completion_dep.found()
  subdir('bash-completion')
endif

if conf.has('WITH_NSS')
  subdir('nss')
endif

if wireshark_dep.found()
  subdir('wireshark')
endif
