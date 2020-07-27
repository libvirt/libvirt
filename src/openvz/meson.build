openvz_sources = [
  'openvz_conf.c',
  'openvz_driver.c',
  'openvz_util.c',
]

if conf.has('WITH_OPENVZ')
  openvz_lib = static_library(
    'virt_openvz',
    [
      openvz_sources,
    ],
    dependencies: [
      src_dep,
    ],
    include_directories: [
      conf_inc_dir,
    ],
  )

  libvirt_libs += openvz_lib
endif

if conf.has('WITH_OPENVZ')
  used_sym_files += 'libvirt_openvz.syms'
else
  sym_files += 'libvirt_openvz.syms'
endif
