access_sources = [
  'viraccessperm.c',
  'viraccessmanager.c',
  'viraccessdrivernop.c',
  'viraccessdriverstack.c',
]

access_polkit_sources = [
  'viraccessdriverpolkit.c',
]

access_perm_h = files('viraccessperm.h')

remote_path = meson.project_source_root() / 'src' / 'remote'

access_gen_headers = []
access_gen_sources = []
access_gen_sym = []
access_gen_xml = []

foreach name : [ 'remote', 'qemu', 'lxc' ]
  if name == 'remote'
    header_file = 'viraccessapicheck.h'
    source_file = 'viraccessapicheck.c'
    syms_file = 'libvirt_access.syms'
  else
    header_file = 'viraccessapicheck@0@.h'.format(name)
    source_file = 'viraccessapicheck@0@.c'.format(name)
    syms_file = 'libvirt_access_@0@.syms'.format(name)
  endif
  protocol_file = remote_path / '@0@_protocol.x'.format(name)

  access_gen_headers += custom_target(
    header_file,
    input: protocol_file,
    output: header_file,
    command: [
      gendispatch_prog, '--mode=aclheader', name, name.to_upper(), '@INPUT@',
    ],
    capture: true,
  )

  access_gen_sources += custom_target(
    source_file,
    input: protocol_file,
    output: source_file,
    command: [
      gendispatch_prog, '--mode=aclbody', name, name.to_upper(),
       '@INPUT@', header_file,
    ],
    capture: true,
  )

  access_gen_sym += custom_target(
    syms_file,
    input: protocol_file,
    output: syms_file,
    capture: true,
    command: [
      gendispatch_prog, '--mode=aclsym', name, name.to_upper(), '@INPUT@',
    ]
  )
endforeach

if conf.has('WITH_POLKIT')
  access_sources += access_polkit_sources

  if conf.has('WITH_LIBVIRTD')
    custom_target(
      'org.libvirt.api.policy',
      input: access_perm_h,
      output: 'org.libvirt.api.policy',
      command: [ meson_python_prog, python3_prog, genpolkit_prog, '@INPUT@' ],
      capture: true,
      install: true,
      install_dir: datadir / 'polkit-1' / 'actions',
    )
  endif
endif

virt_access_lib = static_library(
  'virt_access',
  [
    access_sources,
    access_gen_headers,
    access_gen_sources,
  ],
  dependencies: [
    src_dep,
  ],
  include_directories: [
    conf_inc_dir,
  ]
)

libvirt_libs += virt_access_lib

access_inc_dir = include_directories('.')

# Used by others where generated headers are required
access_dep = declare_dependency(
  include_directories: access_inc_dir,
  sources: access_gen_headers,
)

generated_sym_files += access_gen_sym

if tests_enabled[0]
  test(
    'check-aclperms',
    python3_prog,
    args: [ check_aclperms_prog.full_path(), access_perm_h, files('viraccessperm.c') ],
    env: runutf8,
    suite: 'script'
  )
endif
