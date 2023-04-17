esx_sources = [
  'esx_driver.c',
  'esx_interface_driver.c',
  'esx_network_driver.c',
  'esx_storage_driver.c',
  'esx_storage_backend_vmfs.c',
  'esx_storage_backend_iscsi.c',
  'esx_stream.c',
  'esx_util.c',
  'esx_vi.c',
  'esx_vi_methods.c',
  'esx_vi_types.c',
]

esx_gen_headers = custom_target(
  'virtesxgenheaders',
  input: [
    'esx_vi_generator.input',
  ],
  output: [
    'esx_vi.generated.h',
    'esx_vi_methods.generated.h',
    'esx_vi_types.generated.h',
    'esx_vi_types.generated.typedef',
    'esx_vi_types.generated.typeenum',
  ],
  command: [
    esx_vi_generator_prog,
    meson.project_source_root() / 'src',
    meson.project_build_root() / 'src',
    'header',
  ],
)

esx_gen_sources = custom_target(
  'virtesxgensources',
  input: [
    'esx_vi_generator.input',
  ],
  output: [
    'esx_vi.generated.c',
    'esx_vi_methods.generated.macro',
    'esx_vi_methods.generated.c',
    'esx_vi_types.generated.c',
    'esx_vi_types.generated.typefromstring',
    'esx_vi_types.generated.typetostring',
  ],
  command: [
    esx_vi_generator_prog,
    meson.project_source_root() / 'src',
    meson.project_build_root() / 'src',
    'source',
  ],
)

if conf.has('WITH_ESX')
  esx_lib = static_library(
    'virt_driver_esx',
    [
      esx_sources,
      esx_gen_headers[1],
      esx_gen_sources[1],
    ],
    dependencies: [
      curl_dep,
      src_dep,
    ],
    include_directories: [
      conf_inc_dir,
      vmx_inc_dir,
    ],
  )

  libvirt_libs += esx_lib
endif

if conf.has('WITH_ESX')
  used_sym_files += 'libvirt_esx.syms'
else
  sym_files += 'libvirt_esx.syms'
endif

esx_inc_dir = include_directories('.')

esx_dep = declare_dependency(
  include_directories: esx_inc_dir,
  sources: esx_gen_headers,
)
