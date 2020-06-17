access_sources = [
  'viraccessperm.c',
  'viraccessmanager.c',
  'viraccessdrivernop.c',
  'viraccessdriverstack.c',
]

access_polkit_sources = [
  'viraccessdriverpolkit.c',
]

remote_path = meson.source_root() / 'src' / 'remote'

access_gen_headers = []
access_gen_sources = []

foreach name : [ 'remote', 'qemu', 'lxc' ]
  if name == 'remote'
    header_file = 'viraccessapicheck.h'
    source_file = 'viraccessapicheck.c'
  else
    header_file = 'viraccessapicheck@0@.h'.format(name)
    source_file = 'viraccessapicheck@0@.c'.format(name)
  endif
  protocol_file = remote_path / '@0@_protocol.x'.format(name)

  access_gen_headers += custom_target(
    header_file,
    output: header_file,
    command: [
      gendispatch_prog, '--mode=aclheader', name, name.to_upper(), protocol_file,
    ],
    capture: true,
  )

  access_gen_sources += custom_target(
    source_file,
    output: source_file,
    command: [
      gendispatch_prog, '--mode=aclbody', name, name.to_upper(),
      protocol_file, header_file,
    ],
    capture: true,
  )
endforeach

if conf.has('WITH_POLKIT')
  access_sources += access_polkit_sources
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

access_inc_dir = include_directories('.')

# Used by others where generated headers are required
access_dep = declare_dependency(
  include_directories: access_inc_dir,
  sources: access_gen_headers,
)
