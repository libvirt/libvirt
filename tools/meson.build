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
    install_rpath: libdir,
  )
endif
